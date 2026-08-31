#![forbid(unsafe_code)]

//! Bounded native HTTP/1.1-over-TLS transport for the EKS execution profile.
//!
//! This crate deliberately implements less than a general HTTP client. It has
//! one pinned socket destination, one DNS identity, explicit trust anchors,
//! no proxy, no redirect handling, no retry, and no connection reuse.

use std::{
    fmt,
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};

use accordlock_eks_profile::{CaTrustCommitment, CaTrustError, EksRouteProfile};
use accordlock_executor::{
    NativeEksResponse, NativeEksTransport, NativeGetRequest, NativePatchRequest,
    NativePreWriteAuthorization, TransportFailure,
};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
    client::Resumption,
    pki_types::{CertificateDer, ServerName},
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const USER_AGENT: &str = "accordlock-eks-transport/0.1";
const HTTP_11_ALPN: &[u8] = b"http/1.1";
const CHANNEL_COMMITMENT_DOMAIN: &[u8] = b"accordlock:v1:eks-tls-channel\0";
const MAX_PATH_BYTES: usize = 4 * 1024;
const MAX_BEARER_BYTES: usize = 64 * 1024;
const MAX_CHUNK_LINE_BYTES: usize = 128;
const MAX_HTTP_HEADERS: usize = 64;
const MIN_TIMEOUT: Duration = Duration::from_millis(1);
const MAX_TIMEOUT: Duration = Duration::from_mins(2);

/// Conservative default bounds for one Kubernetes API request and response.
pub const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
/// Default maximum HTTP response header section, including its final CRLF.
pub const DEFAULT_MAX_RESPONSE_HEADER_BYTES: usize = 32 * 1024;
/// Default maximum decoded Kubernetes API response body.
pub const DEFAULT_MAX_RESPONSE_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Trusted configuration for one fixed EKS API-server destination.
///
/// The socket is supplied rather than resolved inside this crate. `dns_name`
/// is nevertheless used as SNI, as the HTTP Host value, and as the `WebPKI`
/// certificate identity. The port in `socket_address` must equal `port`.
#[derive(Clone, PartialEq, Eq)]
pub struct EksEndpointConfig {
    route_profile: EksRouteProfile,
    ca_certificates_der: Vec<Vec<u8>>,
    connect_timeout: Duration,
    operation_timeout: Duration,
    max_request_body_bytes: usize,
    max_response_header_bytes: usize,
    max_response_body_bytes: usize,
}

impl fmt::Debug for EksEndpointConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EksEndpointConfig")
            .field("route_profile", &self.route_profile)
            .field("ca_certificate_count", &self.ca_certificates_der.len())
            .field("connect_timeout", &self.connect_timeout)
            .field("operation_timeout", &self.operation_timeout)
            .field("max_request_body_bytes", &self.max_request_body_bytes)
            .field("max_response_header_bytes", &self.max_response_header_bytes)
            .field("max_response_body_bytes", &self.max_response_body_bytes)
            .finish()
    }
}

impl EksEndpointConfig {
    /// Creates a destination with explicit DER-encoded CA certificates.
    ///
    /// DNS resolution is intentionally outside this constructor. The supplied
    /// socket address is the only address the transport will contact.
    #[must_use]
    pub fn new(route_profile: EksRouteProfile, ca_certificates_der: Vec<Vec<u8>>) -> Self {
        Self {
            route_profile,
            ca_certificates_der,
            connect_timeout: Duration::from_secs(5),
            operation_timeout: Duration::from_secs(15),
            max_request_body_bytes: DEFAULT_MAX_REQUEST_BODY_BYTES,
            max_response_header_bytes: DEFAULT_MAX_RESPONSE_HEADER_BYTES,
            max_response_body_bytes: DEFAULT_MAX_RESPONSE_BODY_BYTES,
        }
    }

    /// Replaces the TCP-connect and total per-request deadlines.
    #[must_use]
    pub const fn with_timeouts(
        mut self,
        connect_timeout: Duration,
        operation_timeout: Duration,
    ) -> Self {
        self.connect_timeout = connect_timeout;
        self.operation_timeout = operation_timeout;
        self
    }

    /// Replaces request-body, response-header, and response-body bounds.
    #[must_use]
    pub const fn with_size_limits(
        mut self,
        max_request_body_bytes: usize,
        max_response_header_bytes: usize,
        max_response_body_bytes: usize,
    ) -> Self {
        self.max_request_body_bytes = max_request_body_bytes;
        self.max_response_header_bytes = max_response_header_bytes;
        self.max_response_body_bytes = max_response_body_bytes;
        self
    }
}

/// Error returned before a usable transport can be constructed.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum TransportConfigError {
    #[error("explicit CA bundle is empty or exceeds its certificate-count bound")]
    InvalidCaBundleSize,
    #[error("an explicit CA certificate is empty, oversized, duplicated, or invalid DER")]
    InvalidCaCertificate,
    #[error("explicit CA bytes do not match the route profile CA commitment")]
    CaTrustCommitmentMismatch,
    #[error("a configured timeout is outside the supported range")]
    InvalidTimeout,
    #[error("a configured message-size limit is invalid")]
    InvalidSizeLimit,
    #[error("the selected rustls provider has no safe default protocol versions")]
    NoSafeTlsProtocolVersions,
}

/// A fixed-destination native EKS transport.
#[derive(Clone)]
pub struct FixedEksHttpsTransport {
    route_profile: EksRouteProfile,
    host_header: String,
    connect_timeout: Duration,
    operation_timeout: Duration,
    max_request_body_bytes: usize,
    response_limits: ResponseLimits,
    tls_config: Arc<ClientConfig>,
}

impl fmt::Debug for FixedEksHttpsTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixedEksHttpsTransport")
            .field("route_profile", &self.route_profile)
            .field("connect_timeout", &self.connect_timeout)
            .field("operation_timeout", &self.operation_timeout)
            .field("max_request_body_bytes", &self.max_request_body_bytes)
            .field("response_limits", &self.response_limits)
            .finish_non_exhaustive()
    }
}

impl FixedEksHttpsTransport {
    /// Validates configuration and builds an explicit rustls trust store.
    ///
    /// No platform or `WebPKI` public-root bundle is added.
    ///
    /// # Errors
    ///
    /// Returns [`TransportConfigError`] when any destination, trust, timeout,
    /// or size invariant is invalid.
    pub fn new(mut config: EksEndpointConfig) -> Result<Self, TransportConfigError> {
        validate_config(&config)?;
        config.ca_certificates_der.sort_unstable();
        let loaded_ca_commitment = ca_trust_commitment(&config.ca_certificates_der)?;
        if loaded_ca_commitment != config.route_profile.ca_trust_commitment() {
            return Err(TransportConfigError::CaTrustCommitmentMismatch);
        }
        let mut roots = RootCertStore::empty();
        for certificate in &config.ca_certificates_der {
            roots
                .add(CertificateDer::from(certificate.clone()))
                .map_err(|_| TransportConfigError::InvalidCaCertificate)?;
        }

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let builder = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| TransportConfigError::NoSafeTlsProtocolVersions)?;
        let mut tls_config = builder.with_root_certificates(roots).with_no_client_auth();
        tls_config.alpn_protocols = vec![HTTP_11_ALPN.to_vec()];
        tls_config.enable_sni = true;
        tls_config.enable_early_data = false;
        tls_config.resumption = Resumption::disabled();

        let host_header = if config.route_profile.port() == 443 {
            config.route_profile.dns_server_name().to_owned()
        } else {
            format!(
                "{}:{}",
                config.route_profile.dns_server_name(),
                config.route_profile.port()
            )
        };
        Ok(Self {
            route_profile: config.route_profile,
            host_header,
            connect_timeout: config.connect_timeout,
            operation_timeout: config.operation_timeout,
            max_request_body_bytes: config.max_request_body_bytes,
            response_limits: ResponseLimits {
                max_header_bytes: config.max_response_header_bytes,
                max_body_bytes: config.max_response_body_bytes,
            },
            tls_config: Arc::new(tls_config),
        })
    }

    fn validate_common_request(
        &self,
        api_server_identity: &str,
        path: &str,
        bearer: &[u8],
    ) -> Result<(), RequestError> {
        if api_server_identity != self.route_profile.api_server_identity() {
            return Err(RequestError::IdentityMismatch);
        }
        validate_path(path)?;
        validate_bearer(bearer)?;
        Ok(())
    }

    fn connect(&self, deadline: Deadline) -> Result<AuthenticatedStream, RequestError> {
        let connect_timeout = self.connect_timeout.min(deadline.remaining()?);
        let socket_target = self.route_profile.socket_target().socket_addr();
        let mut socket = TcpStream::connect_timeout(&socket_target, connect_timeout)
            .map_err(|_| RequestError::Connect)?;
        socket
            .set_nodelay(true)
            .map_err(|_| RequestError::SocketConfiguration)?;
        apply_socket_deadline(&socket, deadline)?;

        let server_name = ServerName::try_from(self.route_profile.dns_server_name().to_owned())
            .map_err(|_| RequestError::TlsConfiguration)?;
        let mut connection = ClientConnection::new(Arc::clone(&self.tls_config), server_name)
            .map_err(|_| RequestError::TlsConfiguration)?;
        while connection.is_handshaking() {
            apply_socket_deadline(&socket, deadline)?;
            let (read, written) = connection
                .complete_io(&mut socket)
                .map_err(|_| RequestError::TlsHandshake)?;
            if connection.is_handshaking() && read == 0 && written == 0 {
                return Err(RequestError::TlsHandshake);
            }
        }
        if connection.alpn_protocol() != Some(HTTP_11_ALPN) {
            return Err(RequestError::TlsAlpnMismatch);
        }
        if socket.peer_addr().map_err(|_| RequestError::Connect)? != socket_target {
            return Err(RequestError::ConnectedPeerMismatch);
        }
        let channel_authentication_commitment = channel_commitment(
            &connection,
            self.route_profile.api_server_identity(),
            self.route_profile.dns_server_name(),
            self.route_profile.port(),
            socket_target,
            *self.route_profile.ca_trust_commitment().as_bytes(),
        )?;
        Ok(AuthenticatedStream {
            stream: StreamOwned::new(connection, socket),
            channel_authentication_commitment,
        })
    }

    fn perform_get(&self, path: &str, bearer: &[u8]) -> Result<NativeEksResponse, RequestError> {
        let deadline = Deadline::new(self.operation_timeout);
        let mut authenticated = self.connect(deadline)?;
        let request_head = request_head(Method::Get, path, &self.host_header);
        write_all_deadline(&mut authenticated.stream, request_head.as_bytes(), deadline)?;
        write_all_deadline(&mut authenticated.stream, bearer, deadline)?;
        let request_tail = request_tail(None, 0);
        write_all_deadline(&mut authenticated.stream, request_tail.as_bytes(), deadline)?;
        flush_deadline(&mut authenticated.stream, deadline)?;

        let mut reader = DeadlineReader {
            stream: &mut authenticated.stream,
            deadline,
        };
        let parsed = read_http_response(&mut reader, self.response_limits)?;
        Ok(NativeEksResponse::new(
            parsed.status,
            self.route_profile.api_server_identity().to_owned(),
            authenticated.channel_authentication_commitment,
            parsed.body,
        ))
    }
}

impl NativeEksTransport for FixedEksHttpsTransport {
    fn route_profile(&self) -> &EksRouteProfile {
        &self.route_profile
    }

    fn operation_timeout_upper_bound(&self) -> Duration {
        self.operation_timeout
    }

    fn get_deployment(
        &self,
        request: NativeGetRequest<'_>,
    ) -> Result<NativeEksResponse, TransportFailure> {
        self.validate_common_request(
            request.api_server_identity(),
            request.path(),
            request.bearer(),
        )
        .and_then(|()| self.perform_get(request.path(), request.bearer()))
        .map_err(|error| TransportFailure::DefinitelyNotSent(error.safe_detail().to_owned()))
    }

    fn patch_deployment(
        &self,
        request: NativePatchRequest<'_>,
        immediately_before_first_write: NativePreWriteAuthorization<'_>,
    ) -> Result<NativeEksResponse, TransportFailure> {
        if let Err(error) = self.validate_common_request(
            request.api_server_identity(),
            request.path(),
            request.bearer(),
        ) {
            return Err(TransportFailure::DefinitelyNotSent(
                error.safe_detail().to_owned(),
            ));
        }
        if request.content_type() != "application/json-patch+json"
            || request.body().is_empty()
            || request.body().len() > self.max_request_body_bytes
            || request.provider_request_commitment() == [0; 32]
        {
            return Err(TransportFailure::DefinitelyNotSent(
                "PATCH request failed fixed-profile validation".to_owned(),
            ));
        }

        // `perform` completes configuration validation, TCP connect, TLS
        // handshake, DNS certificate verification, ALPN, peer pinning, and the
        // channel commitment before it emits HTTP application data. Its public
        // error type deliberately does not expose that internal phase. To keep
        // the executor's mutation classification sound, perform the pre-send
        // connection step here and then execute over that established channel.
        self.perform_patch_after_connect(&request, immediately_before_first_write)
    }
}

impl FixedEksHttpsTransport {
    fn perform_patch_after_connect(
        &self,
        request: &NativePatchRequest<'_>,
        immediately_before_first_write: NativePreWriteAuthorization<'_>,
    ) -> Result<NativeEksResponse, TransportFailure> {
        let deadline = Deadline::new(self.operation_timeout);
        let mut authenticated = self
            .connect(deadline)
            .map_err(|error| TransportFailure::DefinitelyNotSent(error.safe_detail().to_owned()))?;

        let request_head = request_head(Method::Patch, request.path(), &self.host_header);
        // TCP, TLS authentication, ALPN, peer pinning, and request
        // construction are complete. The one-shot executor guard is the send
        // linearization boundary and runs before any HTTP application byte.
        immediately_before_first_write.authorize()?;
        // From immediately before the first plaintext write onward, a caller
        // cannot prove non-delivery from a local I/O result. No retry occurs.
        let outcome = (|| -> Result<ParsedResponse, RequestError> {
            write_all_deadline(&mut authenticated.stream, request_head.as_bytes(), deadline)?;
            write_all_deadline(&mut authenticated.stream, request.bearer(), deadline)?;
            let tail = request_tail(Some(request.content_type()), request.body().len());
            write_all_deadline(&mut authenticated.stream, tail.as_bytes(), deadline)?;
            write_all_deadline(&mut authenticated.stream, request.body(), deadline)?;
            flush_deadline(&mut authenticated.stream, deadline)?;
            let mut reader = DeadlineReader {
                stream: &mut authenticated.stream,
                deadline,
            };
            read_http_response(&mut reader, self.response_limits)
        })();

        let parsed = outcome
            .map_err(|error| TransportFailure::OutcomeUnknown(error.safe_detail().to_owned()))?;
        Ok(NativeEksResponse::new(
            parsed.status,
            self.route_profile.api_server_identity().to_owned(),
            authenticated.channel_authentication_commitment,
            parsed.body,
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Method {
    Get,
    Patch,
}

impl Method {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Patch => "PATCH",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct ResponseLimits {
    max_header_bytes: usize,
    max_body_bytes: usize,
}

struct AuthenticatedStream {
    stream: StreamOwned<ClientConnection, TcpStream>,
    channel_authentication_commitment: [u8; 32],
}

impl fmt::Debug for AuthenticatedStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedStream")
            .field(
                "channel_authentication_commitment",
                &self.channel_authentication_commitment,
            )
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug)]
struct Deadline {
    at: Instant,
}

impl Deadline {
    fn new(timeout: Duration) -> Self {
        Self {
            at: Instant::now() + timeout,
        }
    }

    fn remaining(self) -> Result<Duration, RequestError> {
        self.at
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(RequestError::Deadline)
    }
}

struct DeadlineReader<'a> {
    stream: &'a mut StreamOwned<ClientConnection, TcpStream>,
    deadline: Deadline,
}

impl fmt::Debug for DeadlineReader<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeadlineReader")
            .finish_non_exhaustive()
    }
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let remaining = self.deadline.remaining().map_err(request_error_to_io)?;
        self.stream
            .sock
            .set_read_timeout(Some(remaining))
            .and_then(|()| self.stream.sock.set_write_timeout(Some(remaining)))?;
        self.stream.read(buffer)
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
enum RequestError {
    #[error("request identity mismatch")]
    IdentityMismatch,
    #[error("request path is outside the fixed Kubernetes path grammar")]
    InvalidPath,
    #[error("bearer is empty, oversized, or unsafe for an Authorization header")]
    InvalidBearer,
    #[error("TCP connection failed")]
    Connect,
    #[error("TCP socket configuration failed")]
    SocketConfiguration,
    #[error("TLS client configuration failed")]
    TlsConfiguration,
    #[error("TLS handshake or certificate verification failed")]
    TlsHandshake,
    #[error("TLS peer did not negotiate exactly HTTP/1.1 through ALPN")]
    TlsAlpnMismatch,
    #[error("connected socket differs from the fixed destination")]
    ConnectedPeerMismatch,
    #[error("authenticated TLS peer supplied no usable certificate binding")]
    MissingPeerBinding,
    #[error("request deadline expired")]
    Deadline,
    #[error("HTTP request write failed")]
    RequestWrite,
    #[error("HTTP response read failed")]
    ResponseRead,
    #[error("HTTP response framing is invalid or ambiguous")]
    InvalidHttpResponse,
    #[error("HTTP response exceeds a configured bound")]
    ResponseTooLarge,
}

impl RequestError {
    const fn safe_detail(self) -> &'static str {
        match self {
            Self::IdentityMismatch => "request identity mismatch",
            Self::InvalidPath => "request path failed validation",
            Self::InvalidBearer => "bearer failed validation",
            Self::Connect => "fixed-destination TCP connection failed",
            Self::SocketConfiguration => "socket deadline configuration failed",
            Self::TlsConfiguration => "TLS client configuration failed",
            Self::TlsHandshake => "TLS authentication failed",
            Self::TlsAlpnMismatch => "HTTP/1.1 ALPN was not negotiated",
            Self::ConnectedPeerMismatch => "connected peer differs from fixed destination",
            Self::MissingPeerBinding => "TLS peer binding is unavailable",
            Self::Deadline => "request deadline expired",
            Self::RequestWrite => "HTTP request write failed after dispatch began",
            Self::ResponseRead => "HTTP response was not read completely",
            Self::InvalidHttpResponse => "HTTP response framing was invalid or ambiguous",
            Self::ResponseTooLarge => "HTTP response exceeded a configured bound",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedResponse {
    status: u16,
    body: Vec<u8>,
}

fn validate_config(config: &EksEndpointConfig) -> Result<(), TransportConfigError> {
    let loaded_ca_commitment = ca_trust_commitment(&config.ca_certificates_der)?;
    if loaded_ca_commitment != config.route_profile.ca_trust_commitment() {
        return Err(TransportConfigError::CaTrustCommitmentMismatch);
    }
    if !valid_timeout(config.connect_timeout) || !valid_timeout(config.operation_timeout) {
        return Err(TransportConfigError::InvalidTimeout);
    }
    if config.connect_timeout > config.operation_timeout {
        return Err(TransportConfigError::InvalidTimeout);
    }
    if config.max_request_body_bytes == 0
        || config.max_request_body_bytes > 16 * 1024 * 1024
        || config.max_response_header_bytes < 1024
        || config.max_response_header_bytes > 256 * 1024
        || config.max_response_body_bytes == 0
        || config.max_response_body_bytes > 64 * 1024 * 1024
    {
        return Err(TransportConfigError::InvalidSizeLimit);
    }
    Ok(())
}

fn valid_timeout(timeout: Duration) -> bool {
    (MIN_TIMEOUT..=MAX_TIMEOUT).contains(&timeout)
}

fn validate_path(path: &str) -> Result<(), RequestError> {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || !path.starts_with('/')
        || path.contains('?')
        || path.contains('#')
        || !path
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'\\')
    {
        return Err(RequestError::InvalidPath);
    }
    let mut components = path.split('/');
    if components.next() != Some("")
        || components.next() != Some("apis")
        || components.next() != Some("apps")
        || components.next() != Some("v1")
        || components.next() != Some("namespaces")
        || !components.next().is_some_and(valid_dns_label)
        || components.next() != Some("deployments")
        || !components.next().is_some_and(valid_dns_subdomain)
        || components.next().is_some()
    {
        return Err(RequestError::InvalidPath);
    }
    Ok(())
}

fn valid_dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn valid_dns_subdomain(value: &str) -> bool {
    !value.is_empty() && value.len() <= 253 && value.split('.').all(valid_dns_label)
}

fn validate_bearer(bearer: &[u8]) -> Result<(), RequestError> {
    if bearer.is_empty()
        || bearer.len() > MAX_BEARER_BYTES
        || !bearer.iter().copied().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
        })
    {
        return Err(RequestError::InvalidBearer);
    }
    Ok(())
}

fn request_head(method: Method, path: &str, host_header: &str) -> String {
    format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: application/json\r\nAuthorization: Bearer ",
        method.as_str(),
        path,
        host_header,
        USER_AGENT
    )
}

fn request_tail(content_type: Option<&str>, body_length: usize) -> String {
    match content_type {
        Some(value) => format!(
            "\r\nContent-Type: {value}\r\nContent-Length: {body_length}\r\nConnection: close\r\n\r\n"
        ),
        None => "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
    }
}

fn apply_socket_deadline(socket: &TcpStream, deadline: Deadline) -> Result<(), RequestError> {
    let remaining = deadline.remaining()?;
    socket
        .set_read_timeout(Some(remaining))
        .and_then(|()| socket.set_write_timeout(Some(remaining)))
        .map_err(|_| RequestError::SocketConfiguration)
}

fn write_all_deadline(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    mut bytes: &[u8],
    deadline: Deadline,
) -> Result<(), RequestError> {
    while !bytes.is_empty() {
        apply_socket_deadline(&stream.sock, deadline)?;
        match stream.write(bytes) {
            Ok(0) => return Err(RequestError::RequestWrite),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(RequestError::RequestWrite),
        }
    }
    Ok(())
}

fn flush_deadline(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    deadline: Deadline,
) -> Result<(), RequestError> {
    apply_socket_deadline(&stream.sock, deadline)?;
    stream.flush().map_err(|_| RequestError::RequestWrite)
}

fn request_error_to_io(error: RequestError) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, error.safe_detail())
}

fn ca_trust_commitment(
    certificates: &[Vec<u8>],
) -> Result<CaTrustCommitment, TransportConfigError> {
    CaTrustCommitment::from_der_certificates(certificates).map_err(|error| match error {
        CaTrustError::InvalidCertificateCount => TransportConfigError::InvalidCaBundleSize,
        CaTrustError::InvalidCertificateSize
        | CaTrustError::DuplicateCertificate
        | CaTrustError::ZeroCommitment => TransportConfigError::InvalidCaCertificate,
    })
}

fn channel_commitment(
    connection: &ClientConnection,
    api_server_identity: &str,
    dns_name: &str,
    port: u16,
    socket_address: SocketAddr,
    ca_bundle_commitment: [u8; 32],
) -> Result<[u8; 32], RequestError> {
    let certificates = connection
        .peer_certificates()
        .filter(|chain| !chain.is_empty())
        .ok_or(RequestError::MissingPeerBinding)?;
    let protocol = connection
        .protocol_version()
        .ok_or(RequestError::MissingPeerBinding)?;
    let cipher_suite = connection
        .negotiated_cipher_suite()
        .ok_or(RequestError::MissingPeerBinding)?;
    let alpn = connection
        .alpn_protocol()
        .ok_or(RequestError::MissingPeerBinding)?;

    let mut hasher = Sha256::new();
    hasher.update(CHANNEL_COMMITMENT_DOMAIN);
    update_len_prefixed(&mut hasher, api_server_identity.as_bytes());
    update_len_prefixed(&mut hasher, dns_name.as_bytes());
    hasher.update(port.to_be_bytes());
    update_len_prefixed(&mut hasher, socket_address.to_string().as_bytes());
    hasher.update(ca_bundle_commitment);
    hasher.update(u16::from(protocol).to_be_bytes());
    hasher.update(u16::from(cipher_suite.suite()).to_be_bytes());
    update_len_prefixed(&mut hasher, alpn);
    for certificate in certificates {
        update_len_prefixed(&mut hasher, certificate.as_ref());
    }
    let result: [u8; 32] = hasher.finalize().into();
    if result == [0; 32] {
        return Err(RequestError::MissingPeerBinding);
    }
    Ok(result)
}

fn update_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}

fn read_http_response<R: Read>(
    reader: &mut R,
    limits: ResponseLimits,
) -> Result<ParsedResponse, RequestError> {
    let mut received = Vec::with_capacity(limits.max_header_bytes.min(8192));
    let header_end = loop {
        if let Some(index) = find_bytes(&received, b"\r\n\r\n") {
            let end = index + 4;
            if end > limits.max_header_bytes {
                return Err(RequestError::ResponseTooLarge);
            }
            break end;
        }
        if received.len() >= limits.max_header_bytes {
            return Err(RequestError::ResponseTooLarge);
        }
        read_more(reader, &mut received, limits.max_header_bytes + 8192)?;
    };

    let (status, framing) = parse_response_head(&received[..header_end])?;
    let initial_body = received.split_off(header_end);
    let body = match framing {
        BodyFraming::ContentLength(length) => {
            read_content_length_body(reader, initial_body, length, limits.max_body_bytes)?
        }
        BodyFraming::Chunked => read_chunked_body(
            reader,
            initial_body,
            limits.max_body_bytes,
            limits.max_header_bytes,
        )?,
    };
    Ok(ParsedResponse { status, body })
}

fn read_more<R: Read>(
    reader: &mut R,
    destination: &mut Vec<u8>,
    absolute_limit: usize,
) -> Result<(), RequestError> {
    let remaining = absolute_limit.saturating_sub(destination.len());
    if remaining == 0 {
        return Err(RequestError::ResponseTooLarge);
    }
    let mut buffer = [0_u8; 8192];
    let requested = remaining.min(buffer.len());
    let count = loop {
        match reader.read(&mut buffer[..requested]) {
            Ok(0) => return Err(RequestError::ResponseRead),
            Ok(count) => break count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(RequestError::ResponseRead),
        }
    };
    destination.extend_from_slice(&buffer[..count]);
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BodyFraming {
    ContentLength(usize),
    Chunked,
}

fn parse_response_head(bytes: &[u8]) -> Result<(u16, BodyFraming), RequestError> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HTTP_HEADERS];
    let mut response = httparse::Response::new(&mut headers);
    let parsed = response
        .parse(bytes)
        .map_err(|_| RequestError::InvalidHttpResponse)?;
    if parsed != httparse::Status::Complete(bytes.len()) || response.version != Some(1) {
        return Err(RequestError::InvalidHttpResponse);
    }
    let status = response.code.ok_or(RequestError::InvalidHttpResponse)?;
    if !(100..=599).contains(&status) || (100..200).contains(&status) {
        return Err(RequestError::InvalidHttpResponse);
    }

    let mut content_length = None;
    let mut transfer_encoding = None;
    let mut content_encoding = None;
    let mut trailer_declared = false;
    for header in response.headers {
        if !valid_header(header.name.as_bytes(), header.value) {
            return Err(RequestError::InvalidHttpResponse);
        }
        if header.name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(RequestError::InvalidHttpResponse);
            }
            content_length = Some(parse_content_length(header.value)?);
        } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
            if transfer_encoding.is_some() {
                return Err(RequestError::InvalidHttpResponse);
            }
            transfer_encoding = Some(header.value);
        } else if header.name.eq_ignore_ascii_case("content-encoding") {
            if content_encoding.is_some() {
                return Err(RequestError::InvalidHttpResponse);
            }
            content_encoding = Some(header.value);
        } else if header.name.eq_ignore_ascii_case("trailer") {
            trailer_declared = true;
        }
    }
    if content_encoding.is_some_and(|value| !value.eq_ignore_ascii_case(b"identity")) {
        return Err(RequestError::InvalidHttpResponse);
    }
    match (content_length, transfer_encoding) {
        (Some(length), None) => Ok((status, BodyFraming::ContentLength(length))),
        (None, Some(value)) if !trailer_declared && value.eq_ignore_ascii_case(b"chunked") => {
            Ok((status, BodyFraming::Chunked))
        }
        _ => Err(RequestError::InvalidHttpResponse),
    }
}

fn valid_header(name: &[u8], value: &[u8]) -> bool {
    !name.is_empty()
        && name.iter().copied().all(is_token_byte)
        && value
            .iter()
            .copied()
            .all(|byte| byte == b'\t' || (b' '..=b'~').contains(&byte))
}

const fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn parse_content_length(bytes: &[u8]) -> Result<usize, RequestError> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(RequestError::InvalidHttpResponse);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| RequestError::InvalidHttpResponse)?;
    text.parse::<usize>()
        .map_err(|_| RequestError::InvalidHttpResponse)
}

fn read_content_length_body<R: Read>(
    reader: &mut R,
    mut initial: Vec<u8>,
    length: usize,
    maximum: usize,
) -> Result<Vec<u8>, RequestError> {
    if length > maximum || initial.len() > length {
        return Err(RequestError::ResponseTooLarge);
    }
    initial.reserve(length.saturating_sub(initial.len()));
    while initial.len() < length {
        read_more(reader, &mut initial, length)?;
    }
    Ok(initial)
}

fn read_chunked_body<R: Read>(
    reader: &mut R,
    initial: Vec<u8>,
    max_body_bytes: usize,
    framing_allowance: usize,
) -> Result<Vec<u8>, RequestError> {
    let encoded_limit = max_body_bytes
        .checked_add(framing_allowance)
        .ok_or(RequestError::ResponseTooLarge)?;
    if initial.len() > encoded_limit {
        return Err(RequestError::ResponseTooLarge);
    }
    let mut source = ChunkSource {
        reader,
        encoded: initial,
        cursor: 0,
        encoded_limit,
    };
    let mut decoded = Vec::new();
    loop {
        let line = source.read_crlf_line(MAX_CHUNK_LINE_BYTES)?;
        let size = parse_chunk_size(&line)?;
        if size == 0 {
            if !source.read_crlf_line(MAX_CHUNK_LINE_BYTES)?.is_empty() {
                return Err(RequestError::InvalidHttpResponse);
            }
            if source.cursor != source.encoded.len() {
                return Err(RequestError::InvalidHttpResponse);
            }
            return Ok(decoded);
        }
        if size > max_body_bytes.saturating_sub(decoded.len()) {
            return Err(RequestError::ResponseTooLarge);
        }
        let chunk = source.read_exact_slice(size)?;
        decoded.extend_from_slice(chunk);
        if source.read_exact_slice(2)? != b"\r\n" {
            return Err(RequestError::InvalidHttpResponse);
        }
    }
}

struct ChunkSource<'a, R> {
    reader: &'a mut R,
    encoded: Vec<u8>,
    cursor: usize,
    encoded_limit: usize,
}

impl<R: Read> ChunkSource<'_, R> {
    fn fill_until(&mut self, needed: usize) -> Result<(), RequestError> {
        while self.encoded.len().saturating_sub(self.cursor) < needed {
            read_more(self.reader, &mut self.encoded, self.encoded_limit)?;
        }
        Ok(())
    }

    fn read_crlf_line(&mut self, maximum: usize) -> Result<Vec<u8>, RequestError> {
        loop {
            if let Some(relative) = find_bytes(&self.encoded[self.cursor..], b"\r\n") {
                if relative > maximum {
                    return Err(RequestError::InvalidHttpResponse);
                }
                let line = self.encoded[self.cursor..self.cursor + relative].to_vec();
                self.cursor += relative + 2;
                return Ok(line);
            }
            if self.encoded.len().saturating_sub(self.cursor) > maximum {
                return Err(RequestError::InvalidHttpResponse);
            }
            read_more(self.reader, &mut self.encoded, self.encoded_limit)?;
        }
    }

    fn read_exact_slice(&mut self, length: usize) -> Result<&[u8], RequestError> {
        self.fill_until(length)?;
        let start = self.cursor;
        self.cursor += length;
        Ok(&self.encoded[start..self.cursor])
    }
}

fn parse_chunk_size(bytes: &[u8]) -> Result<usize, RequestError> {
    if bytes.is_empty() || bytes.len() > 16 || !bytes.iter().all(u8::is_ascii_hexdigit) {
        return Err(RequestError::InvalidHttpResponse);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| RequestError::InvalidHttpResponse)?;
    usize::from_str_radix(text, 16).map_err(|_| RequestError::InvalidHttpResponse)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use accordlock_eks_profile::{EksRouteProfileInput, PinnedSocketTarget};
    use std::io::Cursor;

    fn route(certificates: &[Vec<u8>]) -> EksRouteProfile {
        EksRouteProfile::new(EksRouteProfileInput {
            cluster_trust_domain: "spiffe://example.test/eks/prod-a",
            cluster_identity: "eks://prod-a",
            api_server_identity: "urn:accordlock:api:prod-a",
            dns_server_name: "api.prod-a.eks.amazonaws.com",
            port: 443,
            socket_target: PinnedSocketTarget::new(SocketAddr::from(([192, 0, 2, 11], 443)))
                .unwrap(),
            ca_trust_commitment: CaTrustCommitment::from_der_certificates(certificates).unwrap(),
            namespace: "payments",
            deployment_name: "api",
            deployment_uid: "11111111-1111-4111-8111-111111111111",
            attempt_service_account_name: "accordlock-attempt",
            attempt_service_account_uid: "22222222-2222-4222-8222-222222222222",
            token_audience: "https://kubernetes.default.svc",
        })
        .unwrap()
    }

    fn limits() -> ResponseLimits {
        ResponseLimits {
            max_header_bytes: 1024,
            max_body_bytes: 64,
        }
    }

    fn decode(bytes: &[u8]) -> Result<ParsedResponse, RequestError> {
        read_http_response(&mut Cursor::new(bytes), limits())
    }

    #[test]
    fn parses_bounded_content_length_response() {
        let response = decode(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n{\"a\":1}",
        );
        assert_eq!(
            response,
            Ok(ParsedResponse {
                status: 200,
                body: br#"{"a":1}"#.to_vec(),
            })
        );
    }

    #[test]
    fn parses_strict_chunked_response() {
        let response = decode(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n{\"a\r\n3\r\n\":1\r\n1\r\n}\r\n0\r\n\r\n",
        );
        assert_eq!(response.map(|value| value.body), Ok(br#"{"a":1}"#.to_vec()));
    }

    #[test]
    fn rejects_content_length_and_transfer_encoding_ambiguity() {
        let result = decode(
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        );
        assert_eq!(result, Err(RequestError::InvalidHttpResponse));
    }

    #[test]
    fn rejects_duplicate_content_length_even_when_equal() {
        let result = decode(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(result, Err(RequestError::InvalidHttpResponse));
    }

    #[test]
    fn rejects_close_delimited_response() {
        let result = decode(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{}");
        assert_eq!(result, Err(RequestError::InvalidHttpResponse));
    }

    #[test]
    fn rejects_http_10_and_informational_responses() {
        assert_eq!(
            decode(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n"),
            Err(RequestError::InvalidHttpResponse)
        );
        assert_eq!(
            decode(b"HTTP/1.1 100 Continue\r\nContent-Length: 0\r\n\r\n"),
            Err(RequestError::InvalidHttpResponse)
        );
    }

    #[test]
    fn rejects_unsupported_content_encoding() {
        let result =
            decode(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(result, Err(RequestError::InvalidHttpResponse));
    }

    #[test]
    fn rejects_chunk_extensions_and_trailers() {
        assert_eq!(
            decode(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;x=y\r\na\r\n0\r\n\r\n"),
            Err(RequestError::InvalidHttpResponse)
        );
        assert_eq!(
            decode(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Foo\r\n\r\n0\r\n\r\n"
            ),
            Err(RequestError::InvalidHttpResponse)
        );
        assert_eq!(
            decode(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\ngarbage"),
            Err(RequestError::InvalidHttpResponse)
        );
    }

    #[test]
    fn rejects_oversized_decoded_body() {
        let body = vec![b'a'; 65];
        let mut response = b"HTTP/1.1 200 OK\r\nContent-Length: 65\r\n\r\n".to_vec();
        response.extend_from_slice(&body);
        assert_eq!(decode(&response), Err(RequestError::ResponseTooLarge));
    }

    #[test]
    fn rejects_truncated_and_overlong_content_length_bodies() {
        assert_eq!(
            decode(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{"),
            Err(RequestError::ResponseRead)
        );
        assert_eq!(
            decode(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n{}"),
            Err(RequestError::ResponseTooLarge)
        );
    }

    #[test]
    fn request_construction_never_formats_bearer() {
        let prefix = request_head(
            Method::Patch,
            "/apis/apps/v1/namespaces/n/deployments/d",
            "api.example.test",
        );
        let tail = request_tail(Some("application/json-patch+json"), 2);
        assert!(prefix.ends_with("Authorization: Bearer "));
        assert!(!prefix.contains("secret-token"));
        assert!(!tail.contains("secret-token"));
        assert!(tail.contains("Content-Length: 2"));
    }

    #[test]
    fn bearer_validation_rejects_header_injection() {
        assert_eq!(
            validate_bearer(b"token\r\nX-Evil: yes"),
            Err(RequestError::InvalidBearer)
        );
        assert_eq!(
            validate_bearer(b"token value"),
            Err(RequestError::InvalidBearer)
        );
        assert_eq!(validate_bearer(b"k8s-aws-v1.abc_DEF-123"), Ok(()));
    }

    #[test]
    fn path_validation_rejects_authority_query_and_fragment_injection() {
        assert_eq!(
            validate_path("https://evil.test/x"),
            Err(RequestError::InvalidPath)
        );
        assert_eq!(
            validate_path("/x?watch=true"),
            Err(RequestError::InvalidPath)
        );
        assert_eq!(validate_path("/x#fragment"), Err(RequestError::InvalidPath));
        assert_eq!(
            validate_path("/x\r\nHost: evil"),
            Err(RequestError::InvalidPath)
        );
        assert_eq!(
            validate_path("/apis/apps/v1/namespaces/n/deployments/d/scale"),
            Err(RequestError::InvalidPath)
        );
        assert_eq!(
            validate_path("/api/v1/namespaces/n/pods/p"),
            Err(RequestError::InvalidPath)
        );
        assert_eq!(
            validate_path("/apis/apps/v1/namespaces/n/deployments/d"),
            Ok(())
        );
    }

    #[test]
    fn config_debug_discloses_no_ca_bytes() {
        let certificates = vec![b"sensitive-ca-material".to_vec()];
        let config = EksEndpointConfig::new(route(&certificates), certificates);
        let debug = format!("{config:?}");
        assert!(!debug.contains("sensitive-ca-material"));
        assert!(debug.contains("ca_certificate_count"));
    }

    #[test]
    fn ca_bytes_must_exactly_match_route_commitment() {
        let expected = vec![b"expected-ca".to_vec()];
        let substituted = vec![b"substituted-ca".to_vec()];
        let config = EksEndpointConfig::new(route(&expected), substituted);
        assert_eq!(
            validate_config(&config),
            Err(TransportConfigError::CaTrustCommitmentMismatch)
        );
    }
}
