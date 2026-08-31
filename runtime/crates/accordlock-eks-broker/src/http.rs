use std::{
    fmt,
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};

use accordlock_eks_profile::{CaTrustCommitment, EksRouteProfile};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
    client::Resumption,
    pki_types::{CertificateDer, ServerName},
};
use sha2::{Digest as _, Sha256};

const HTTP_11_ALPN: &[u8] = b"http/1.1";
const USER_AGENT: &str = "accordlock-eks-broker/0.1";
const CHANNEL_DOMAIN: &[u8] = b"accordlock:v1:eks-broker-tls-channel\0";
const REQUEST_DOMAIN: &[u8] = b"accordlock:v1:eks-broker-http-request\0";
const MAX_HEADERS: usize = 64;
const MAX_CHUNK_LINE: usize = 128;

#[derive(Clone, Debug)]
pub(crate) struct EndpointMaterial {
    pub route_profile: EksRouteProfile,
    pub ca_certificates_der: Vec<Vec<u8>>,
    pub connect_timeout: Duration,
    pub operation_timeout: Duration,
    pub max_request_body_bytes: usize,
    pub max_response_header_bytes: usize,
    pub max_response_body_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HttpConfigError {
    InvalidCa,
    InvalidTlsProvider,
}

#[derive(Clone)]
pub(crate) struct FixedHttpsClient {
    route_profile: EksRouteProfile,
    host_header: String,
    connect_timeout: Duration,
    operation_timeout: Duration,
    max_request_body_bytes: usize,
    limits: ResponseLimits,
    tls: Arc<ClientConfig>,
}

impl fmt::Debug for FixedHttpsClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixedHttpsClient")
            .field("route_profile", &self.route_profile)
            .field("connect_timeout", &self.connect_timeout)
            .field("operation_timeout", &self.operation_timeout)
            .field("max_request_body_bytes", &self.max_request_body_bytes)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl FixedHttpsClient {
    pub(crate) fn new(mut material: EndpointMaterial) -> Result<Self, HttpConfigError> {
        material.ca_certificates_der.sort_unstable();
        if material.ca_certificates_der.is_empty()
            || material
                .ca_certificates_der
                .windows(2)
                .any(|pair| pair[0] == pair[1])
        {
            return Err(HttpConfigError::InvalidCa);
        }
        let ca_commitment = CaTrustCommitment::from_der_certificates(&material.ca_certificates_der)
            .map_err(|_| HttpConfigError::InvalidCa)?;
        if ca_commitment != material.route_profile.ca_trust_commitment() {
            return Err(HttpConfigError::InvalidCa);
        }
        let mut roots = RootCertStore::empty();
        for certificate in &material.ca_certificates_der {
            roots
                .add(CertificateDer::from(certificate.clone()))
                .map_err(|_| HttpConfigError::InvalidCa)?;
        }
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let builder = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| HttpConfigError::InvalidTlsProvider)?;
        let mut tls = builder.with_root_certificates(roots).with_no_client_auth();
        tls.alpn_protocols = vec![HTTP_11_ALPN.to_vec()];
        tls.enable_sni = true;
        tls.enable_early_data = false;
        tls.resumption = Resumption::disabled();
        let host_header = if material.route_profile.port() == 443 {
            material.route_profile.dns_server_name().to_owned()
        } else {
            format!(
                "{}:{}",
                material.route_profile.dns_server_name(),
                material.route_profile.port()
            )
        };
        Ok(Self {
            route_profile: material.route_profile,
            host_header,
            connect_timeout: material.connect_timeout,
            operation_timeout: material.operation_timeout,
            max_request_body_bytes: material.max_request_body_bytes,
            limits: ResponseLimits {
                max_header_bytes: material.max_response_header_bytes,
                max_body_bytes: material.max_response_body_bytes,
            },
            tls: Arc::new(tls),
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(route_profile: EksRouteProfile) -> Result<Self, HttpConfigError> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let builder = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| HttpConfigError::InvalidTlsProvider)?;
        let mut tls = builder
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        tls.alpn_protocols = vec![HTTP_11_ALPN.to_vec()];
        tls.enable_sni = true;
        tls.enable_early_data = false;
        tls.resumption = Resumption::disabled();
        Ok(Self {
            host_header: route_profile.dns_server_name().to_owned(),
            route_profile,
            connect_timeout: Duration::from_secs(1),
            operation_timeout: Duration::from_secs(1),
            max_request_body_bytes: 1024 * 1024,
            limits: ResponseLimits {
                max_header_bytes: 32 * 1024,
                max_body_bytes: 8 * 1024 * 1024,
            },
            tls: Arc::new(tls),
        })
    }

    pub(crate) const fn route_profile(&self) -> &EksRouteProfile {
        &self.route_profile
    }

    /// Trusted upper bound for the complete connect, TLS, write, and read
    /// operation performed by [`Self::exchange`].
    pub(crate) const fn operation_timeout_upper_bound(&self) -> Duration {
        self.operation_timeout
    }

    pub(crate) fn exchange<E, F>(
        &self,
        operation: WireOperation,
        path: &str,
        management_bearer: &[u8],
        content_type: Option<&str>,
        body: WireBody<'_>,
        immediately_before_first_write: F,
    ) -> Result<WireResponse, GuardedWireFailure<E>>
    where
        F: FnOnce() -> Result<(), E>,
    {
        let not_sent = |reason| GuardedWireFailure::Wire(WireFailure::DefinitelyNotSent(reason));
        validate_path(path).map_err(not_sent)?;
        validate_bearer(management_bearer).map_err(not_sent)?;
        let body_length = body
            .length()
            .ok_or_else(|| not_sent(WireReason::RequestTooLarge))?;
        if body_length > self.max_request_body_bytes
            || (operation.method() == "GET" && body_length != 0)
            || (operation.method() != "GET" && content_type != Some("application/json"))
        {
            return Err(not_sent(WireReason::RequestTooLarge));
        }
        let request_commitment = request_commitment(operation, path, content_type, body);
        let head = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: application/json\r\nAuthorization: Bearer ",
            operation.method(),
            path,
            self.host_header,
            USER_AGENT
        );
        let tail = match content_type {
            Some(value) => format!(
                "\r\nContent-Type: {value}\r\nContent-Length: {body_length}\r\nConnection: close\r\n\r\n"
            ),
            None => "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
        };

        let deadline = Deadline::new(self.operation_timeout);
        let mut authenticated = self.connect(deadline).map_err(not_sent)?;

        // This is the send linearization boundary. TCP, TLS authentication,
        // ALPN, peer pinning, and all request construction are complete, but
        // no HTTP application byte has been written. Dropping the stream on a
        // rejected guard therefore proves `DefinitelyNotSent`.
        immediately_before_first_write().map_err(GuardedWireFailure::GuardRejected)?;

        let result = (|| -> Result<ParsedResponse, WireReason> {
            write_all(&mut authenticated.stream, head.as_bytes(), deadline)?;
            write_all(&mut authenticated.stream, management_bearer, deadline)?;
            write_all(&mut authenticated.stream, tail.as_bytes(), deadline)?;
            for segment in body.segments() {
                write_all(&mut authenticated.stream, segment, deadline)?;
            }
            apply_deadline(&authenticated.stream.sock, deadline)?;
            authenticated
                .stream
                .flush()
                .map_err(|_| WireReason::RequestWrite)?;
            let mut reader = DeadlineReader {
                stream: &mut authenticated.stream,
                deadline,
            };
            read_response(&mut reader, self.limits)
        })();
        let parsed = result
            .map_err(WireFailure::OutcomeUnknown)
            .map_err(GuardedWireFailure::Wire)?;
        Ok(WireResponse {
            status: parsed.status,
            api_server_identity: self.route_profile.api_server_identity().to_owned(),
            channel_commitment: authenticated.channel_commitment,
            request_commitment,
            body: SensitiveBody(parsed.body),
        })
    }

    fn connect(&self, deadline: Deadline) -> Result<AuthenticatedStream, WireReason> {
        let timeout = self
            .connect_timeout
            .min(deadline.remaining().ok_or(WireReason::Deadline)?);
        let socket_target = self.route_profile.socket_target().socket_addr();
        let mut socket =
            TcpStream::connect_timeout(&socket_target, timeout).map_err(|_| WireReason::Connect)?;
        socket
            .set_nodelay(true)
            .map_err(|_| WireReason::SocketConfiguration)?;
        apply_deadline(&socket, deadline)?;
        let server_name = ServerName::try_from(self.route_profile.dns_server_name().to_owned())
            .map_err(|_| WireReason::TlsConfiguration)?;
        let mut connection = ClientConnection::new(Arc::clone(&self.tls), server_name)
            .map_err(|_| WireReason::TlsConfiguration)?;
        while connection.is_handshaking() {
            apply_deadline(&socket, deadline)?;
            let (read, written) = connection
                .complete_io(&mut socket)
                .map_err(|_| WireReason::TlsAuthentication)?;
            if connection.is_handshaking() && read == 0 && written == 0 {
                return Err(WireReason::TlsAuthentication);
            }
        }
        if connection.alpn_protocol() != Some(HTTP_11_ALPN) {
            return Err(WireReason::TlsAlpn);
        }
        if socket.peer_addr().map_err(|_| WireReason::Connect)? != socket_target {
            return Err(WireReason::PeerMismatch);
        }
        let channel_commitment = channel_commitment(
            &connection,
            self.route_profile.api_server_identity(),
            self.route_profile.dns_server_name(),
            self.route_profile.port(),
            socket_target,
            *self.route_profile.ca_trust_commitment().as_bytes(),
        )?;
        Ok(AuthenticatedStream {
            stream: StreamOwned::new(connection, socket),
            channel_commitment,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WireOperation {
    CreateSecret,
    GetSecret,
    CreateTokenRequest,
    CreateTokenReview,
    DeleteSecret,
}

impl WireOperation {
    const fn method(self) -> &'static str {
        match self {
            Self::GetSecret => "GET",
            Self::CreateSecret | Self::CreateTokenRequest | Self::CreateTokenReview => "POST",
            Self::DeleteSecret => "DELETE",
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::CreateSecret => 1,
            Self::GetSecret => 2,
            Self::CreateTokenRequest => 3,
            Self::CreateTokenReview => 4,
            Self::DeleteSecret => 5,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum WireBody<'a> {
    Empty,
    Bytes(&'a [u8]),
    TokenReview {
        prefix: &'a [u8],
        token: &'a [u8],
        suffix: &'a [u8],
    },
}

impl<'a> WireBody<'a> {
    fn length(self) -> Option<usize> {
        match self {
            Self::Empty => Some(0),
            Self::Bytes(bytes) => Some(bytes.len()),
            Self::TokenReview {
                prefix,
                token,
                suffix,
            } => prefix
                .len()
                .checked_add(token.len())?
                .checked_add(suffix.len()),
        }
    }

    fn segments(self) -> BodySegments<'a> {
        BodySegments {
            body: self,
            next: 0,
        }
    }
}

struct BodySegments<'a> {
    body: WireBody<'a>,
    next: u8,
}

impl<'a> Iterator for BodySegments<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let result = match (self.body, self.next) {
            (WireBody::Bytes(bytes), 0) => Some(bytes),
            (
                WireBody::TokenReview {
                    prefix,
                    token: _,
                    suffix: _,
                },
                0,
            ) => Some(prefix),
            (
                WireBody::TokenReview {
                    prefix: _,
                    token,
                    suffix: _,
                },
                1,
            ) => Some(token),
            (
                WireBody::TokenReview {
                    prefix: _,
                    token: _,
                    suffix,
                },
                2,
            ) => Some(suffix),
            _ => None,
        };
        self.next = self.next.saturating_add(1);
        result
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WireReason {
    InvalidPath,
    InvalidBearer,
    RequestTooLarge,
    Connect,
    SocketConfiguration,
    TlsConfiguration,
    TlsAuthentication,
    TlsAlpn,
    PeerMismatch,
    MissingPeerBinding,
    Deadline,
    RequestWrite,
    ResponseRead,
    InvalidResponse,
    ResponseTooLarge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WireFailure {
    DefinitelyNotSent(WireReason),
    OutcomeUnknown(WireReason),
}

/// Failure either at the post-TLS/pre-write authorization boundary or in the
/// fixed HTTP transport itself.
pub(crate) enum GuardedWireFailure<E> {
    GuardRejected(E),
    Wire(WireFailure),
}

pub(crate) struct WireResponse {
    pub status: u16,
    pub api_server_identity: String,
    pub channel_commitment: [u8; 32],
    pub request_commitment: [u8; 32],
    body: SensitiveBody,
}

impl fmt::Debug for WireResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WireResponse")
            .field("status", &self.status)
            .field("api_server_identity", &self.api_server_identity)
            .field("channel_commitment", &self.channel_commitment)
            .field("request_commitment", &self.request_commitment)
            .field("body_length", &self.body.0.len())
            .finish()
    }
}

impl WireResponse {
    pub(crate) fn body(&self) -> &[u8] {
        &self.body.0
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        operation: WireOperation,
        path: &str,
        content_type: Option<&str>,
        request_body: WireBody<'_>,
        status: u16,
        api_server_identity: String,
        response_body: Vec<u8>,
    ) -> Self {
        Self {
            status,
            api_server_identity,
            channel_commitment: [91; 32],
            request_commitment: request_commitment(operation, path, content_type, request_body),
            body: SensitiveBody(response_body),
        }
    }
}

struct SensitiveBody(Vec<u8>);

impl Drop for SensitiveBody {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Clone, Copy, Debug)]
struct ResponseLimits {
    max_header_bytes: usize,
    max_body_bytes: usize,
}

struct AuthenticatedStream {
    stream: StreamOwned<ClientConnection, TcpStream>,
    channel_commitment: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
struct Deadline(Instant);

impl Deadline {
    fn new(timeout: Duration) -> Self {
        Self(Instant::now() + timeout)
    }

    fn remaining(self) -> Option<Duration> {
        self.0
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
    }
}

struct DeadlineReader<'a> {
    stream: &'a mut StreamOwned<ClientConnection, TcpStream>,
    deadline: Deadline,
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let remaining = self.deadline.remaining().ok_or_else(|| {
            io::Error::new(io::ErrorKind::TimedOut, "broker operation deadline expired")
        })?;
        self.stream
            .sock
            .set_read_timeout(Some(remaining))
            .and_then(|()| self.stream.sock.set_write_timeout(Some(remaining)))?;
        self.stream.read(buffer)
    }
}

fn validate_path(path: &str) -> Result<(), WireReason> {
    if path.is_empty()
        || path.len() > 4096
        || !path.starts_with('/')
        || path.contains('#')
        || path
            .bytes()
            .any(|byte| !byte.is_ascii_graphic() || byte == b'\\')
    {
        return Err(WireReason::InvalidPath);
    }
    Ok(())
}

fn validate_bearer(bearer: &[u8]) -> Result<(), WireReason> {
    if bearer.is_empty()
        || bearer.len() > 64 * 1024
        || !bearer.iter().copied().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
        })
    {
        return Err(WireReason::InvalidBearer);
    }
    Ok(())
}

fn apply_deadline(socket: &TcpStream, deadline: Deadline) -> Result<(), WireReason> {
    let remaining = deadline.remaining().ok_or(WireReason::Deadline)?;
    socket
        .set_read_timeout(Some(remaining))
        .and_then(|()| socket.set_write_timeout(Some(remaining)))
        .map_err(|_| WireReason::SocketConfiguration)
}

fn write_all(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    mut bytes: &[u8],
    deadline: Deadline,
) -> Result<(), WireReason> {
    while !bytes.is_empty() {
        apply_deadline(&stream.sock, deadline)?;
        match stream.write(bytes) {
            Ok(0) => return Err(WireReason::RequestWrite),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(WireReason::RequestWrite),
        }
    }
    Ok(())
}

fn request_commitment(
    operation: WireOperation,
    path: &str,
    content_type: Option<&str>,
    body: WireBody<'_>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_DOMAIN);
    hasher.update([operation.tag()]);
    update_len(&mut hasher, operation.method().as_bytes());
    update_len(&mut hasher, path.as_bytes());
    match content_type {
        Some(value) => {
            hasher.update([1]);
            update_len(&mut hasher, value.as_bytes());
        }
        None => hasher.update([0]),
    }
    hasher.update(
        u64::try_from(body.length().unwrap_or(usize::MAX))
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for segment in body.segments() {
        hasher.update(segment);
    }
    hasher.finalize().into()
}

fn channel_commitment(
    connection: &ClientConnection,
    identity: &str,
    dns_name: &str,
    port: u16,
    socket: SocketAddr,
    ca_commitment: [u8; 32],
) -> Result<[u8; 32], WireReason> {
    let certificates = connection
        .peer_certificates()
        .filter(|chain| !chain.is_empty())
        .ok_or(WireReason::MissingPeerBinding)?;
    let protocol = connection
        .protocol_version()
        .ok_or(WireReason::MissingPeerBinding)?;
    let suite = connection
        .negotiated_cipher_suite()
        .ok_or(WireReason::MissingPeerBinding)?;
    let alpn = connection
        .alpn_protocol()
        .ok_or(WireReason::MissingPeerBinding)?;
    let mut hasher = Sha256::new();
    hasher.update(CHANNEL_DOMAIN);
    update_len(&mut hasher, identity.as_bytes());
    update_len(&mut hasher, dns_name.as_bytes());
    hasher.update(port.to_be_bytes());
    update_len(&mut hasher, socket.to_string().as_bytes());
    hasher.update(ca_commitment);
    hasher.update(u16::from(protocol).to_be_bytes());
    hasher.update(u16::from(suite.suite()).to_be_bytes());
    update_len(&mut hasher, alpn);
    for certificate in certificates {
        update_len(&mut hasher, certificate.as_ref());
    }
    let commitment: [u8; 32] = hasher.finalize().into();
    if commitment == [0; 32] {
        return Err(WireReason::MissingPeerBinding);
    }
    Ok(commitment)
}

fn update_len(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedResponse {
    status: u16,
    body: Vec<u8>,
}

fn read_response<R: Read>(
    reader: &mut R,
    limits: ResponseLimits,
) -> Result<ParsedResponse, WireReason> {
    let mut received = Vec::with_capacity(limits.max_header_bytes.min(8192));
    let header_end = loop {
        if let Some(index) = find(&received, b"\r\n\r\n") {
            let end = index + 4;
            if end > limits.max_header_bytes {
                return Err(WireReason::ResponseTooLarge);
            }
            break end;
        }
        if received.len() >= limits.max_header_bytes {
            return Err(WireReason::ResponseTooLarge);
        }
        read_more(reader, &mut received, limits.max_header_bytes + 8192)?;
    };
    let (status, framing) = parse_head(&received[..header_end])?;
    let initial = received.split_off(header_end);
    let body = match framing {
        Framing::ContentLength(length) => {
            read_content_length(reader, initial, length, limits.max_body_bytes)?
        }
        Framing::Chunked => read_chunked(
            reader,
            initial,
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
) -> Result<(), WireReason> {
    let remaining = absolute_limit.saturating_sub(destination.len());
    if remaining == 0 {
        return Err(WireReason::ResponseTooLarge);
    }
    let mut buffer = [0_u8; 8192];
    let requested = remaining.min(buffer.len());
    let count = loop {
        match reader.read(&mut buffer[..requested]) {
            Ok(0) => return Err(WireReason::ResponseRead),
            Ok(count) => break count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(WireReason::ResponseRead),
        }
    };
    destination.extend_from_slice(&buffer[..count]);
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Framing {
    ContentLength(usize),
    Chunked,
}

fn parse_head(bytes: &[u8]) -> Result<(u16, Framing), WireReason> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut response = httparse::Response::new(&mut headers);
    if response
        .parse(bytes)
        .map_err(|_| WireReason::InvalidResponse)?
        != httparse::Status::Complete(bytes.len())
        || response.version != Some(1)
    {
        return Err(WireReason::InvalidResponse);
    }
    let status = response.code.ok_or(WireReason::InvalidResponse)?;
    if !(200..=599).contains(&status) {
        return Err(WireReason::InvalidResponse);
    }
    let mut content_length = None;
    let mut transfer_encoding = None;
    let mut content_encoding = None;
    let mut trailer = false;
    for header in response.headers {
        if !valid_header(header.name.as_bytes(), header.value) {
            return Err(WireReason::InvalidResponse);
        }
        if header.name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(WireReason::InvalidResponse);
            }
            content_length = Some(parse_length(header.value)?);
        } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
            if transfer_encoding.is_some() {
                return Err(WireReason::InvalidResponse);
            }
            transfer_encoding = Some(header.value);
        } else if header.name.eq_ignore_ascii_case("content-encoding") {
            if content_encoding.is_some() {
                return Err(WireReason::InvalidResponse);
            }
            content_encoding = Some(header.value);
        } else if header.name.eq_ignore_ascii_case("trailer") {
            trailer = true;
        }
    }
    if content_encoding.is_some_and(|value| !value.eq_ignore_ascii_case(b"identity")) {
        return Err(WireReason::InvalidResponse);
    }
    match (content_length, transfer_encoding) {
        (Some(length), None) => Ok((status, Framing::ContentLength(length))),
        (None, Some(value)) if !trailer && value.eq_ignore_ascii_case(b"chunked") => {
            Ok((status, Framing::Chunked))
        }
        _ => Err(WireReason::InvalidResponse),
    }
}

fn valid_header(name: &[u8], value: &[u8]) -> bool {
    !name.is_empty()
        && name.iter().copied().all(|byte| {
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
        })
        && value
            .iter()
            .copied()
            .all(|byte| byte == b'\t' || (b' '..=b'~').contains(&byte))
}

fn parse_length(bytes: &[u8]) -> Result<usize, WireReason> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(WireReason::InvalidResponse);
    }
    std::str::from_utf8(bytes)
        .map_err(|_| WireReason::InvalidResponse)?
        .parse()
        .map_err(|_| WireReason::InvalidResponse)
}

fn read_content_length<R: Read>(
    reader: &mut R,
    mut initial: Vec<u8>,
    length: usize,
    maximum: usize,
) -> Result<Vec<u8>, WireReason> {
    if length > maximum || initial.len() > length {
        return Err(WireReason::ResponseTooLarge);
    }
    initial.reserve(length.saturating_sub(initial.len()));
    while initial.len() < length {
        read_more(reader, &mut initial, length)?;
    }
    Ok(initial)
}

fn read_chunked<R: Read>(
    reader: &mut R,
    initial: Vec<u8>,
    max_body: usize,
    allowance: usize,
) -> Result<Vec<u8>, WireReason> {
    let encoded_limit = max_body
        .checked_add(allowance)
        .ok_or(WireReason::ResponseTooLarge)?;
    let mut source = ChunkSource {
        reader,
        encoded: initial,
        cursor: 0,
        encoded_limit,
    };
    if source.encoded.len() > encoded_limit {
        return Err(WireReason::ResponseTooLarge);
    }
    let mut decoded = Vec::new();
    loop {
        let line = source.line()?;
        let size = chunk_size(&line)?;
        if size == 0 {
            if !source.line()?.is_empty() || source.cursor != source.encoded.len() {
                return Err(WireReason::InvalidResponse);
            }
            return Ok(decoded);
        }
        if size > max_body.saturating_sub(decoded.len()) {
            return Err(WireReason::ResponseTooLarge);
        }
        decoded.extend_from_slice(source.exact(size)?);
        if source.exact(2)? != b"\r\n" {
            return Err(WireReason::InvalidResponse);
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
    fn fill(&mut self, needed: usize) -> Result<(), WireReason> {
        while self.encoded.len().saturating_sub(self.cursor) < needed {
            read_more(self.reader, &mut self.encoded, self.encoded_limit)?;
        }
        Ok(())
    }

    fn line(&mut self) -> Result<Vec<u8>, WireReason> {
        loop {
            if let Some(relative) = find(&self.encoded[self.cursor..], b"\r\n") {
                if relative > MAX_CHUNK_LINE {
                    return Err(WireReason::InvalidResponse);
                }
                let line = self.encoded[self.cursor..self.cursor + relative].to_vec();
                self.cursor += relative + 2;
                return Ok(line);
            }
            if self.encoded.len().saturating_sub(self.cursor) > MAX_CHUNK_LINE {
                return Err(WireReason::InvalidResponse);
            }
            read_more(self.reader, &mut self.encoded, self.encoded_limit)?;
        }
    }

    fn exact(&mut self, length: usize) -> Result<&[u8], WireReason> {
        self.fill(length)?;
        let start = self.cursor;
        self.cursor += length;
        Ok(&self.encoded[start..self.cursor])
    }
}

fn chunk_size(bytes: &[u8]) -> Result<usize, WireReason> {
    if bytes.is_empty() || bytes.len() > 16 || !bytes.iter().all(u8::is_ascii_hexdigit) {
        return Err(WireReason::InvalidResponse);
    }
    usize::from_str_radix(
        std::str::from_utf8(bytes).map_err(|_| WireReason::InvalidResponse)?,
        16,
    )
    .map_err(|_| WireReason::InvalidResponse)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn limits() -> ResponseLimits {
        ResponseLimits {
            max_header_bytes: 1024,
            max_body_bytes: 64,
        }
    }

    #[test]
    fn codec_accepts_content_length_and_chunked() {
        let fixed = read_response(
            &mut Cursor::new(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\n{}"),
            limits(),
        );
        assert_eq!(fixed.map(|response| response.body), Ok(b"{}".to_vec()));
        let chunked = read_response(
            &mut Cursor::new(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
            ),
            limits(),
        );
        assert_eq!(chunked.map(|response| response.body), Ok(b"{}".to_vec()));
    }

    #[test]
    fn codec_rejects_ambiguous_or_unbounded_framing() {
        assert_eq!(
            read_response(
                &mut Cursor::new(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
                ),
                limits()
            ),
            Err(WireReason::InvalidResponse)
        );
        assert_eq!(
            read_response(
                &mut Cursor::new(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{}"),
                limits()
            ),
            Err(WireReason::InvalidResponse)
        );
    }

    #[test]
    fn segmented_token_review_body_does_not_own_token() {
        let token = b"header.payload.signature";
        let body = WireBody::TokenReview {
            prefix: b"{\"token\":\"",
            token,
            suffix: b"\"}",
        };
        assert_eq!(
            body.length(),
            Some(b"{\"token\":\"".len() + token.len() + b"\"}".len())
        );
        let collected: Vec<_> = body.segments().collect();
        assert_eq!(
            collected,
            vec![b"{\"token\":\"".as_slice(), token, b"\"}".as_slice()]
        );
    }
}
