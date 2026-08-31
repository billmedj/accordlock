//! One-shot public-WebPKI transport for the governed HTTPS broker.
//!
//! This is intentionally not a general HTTP client. It resolves only the
//! exact authority committed by [`HttpsEgressPolicy`], rejects every DNS
//! answer when any address is non-public, connects directly without proxies,
//! authenticates the original DNS name with rustls, sends one HTTP/1.1
//! request, follows no redirects, and reads one strictly framed response.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs as _},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use axum::http::Uri;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, StreamOwned, client::Resumption,
    pki_types::ServerName,
};
use thiserror::Error;
use zeroize::Zeroizing;

use super::{
    HttpsEgress, HttpsEgressError, HttpsEgressPolicy, HttpsEgressRequest, HttpsEgressResponse,
    HttpsHeader, HttpsMethod, HttpsPolicyError, MAX_BODY_BYTES, MAX_HEADER_COUNT,
    MAX_HEADER_VALUE_BYTES, MAX_RESPONSE_BYTES, MAX_TIMEOUT_SECONDS, MAX_URL_BYTES,
    PreparedHttpsRequest, REQUEST_HEADER_ALLOWLIST, RESPONSE_HEADER_ALLOWLIST, validate_domain,
    validate_headers,
};

const HTTPS_PORT: u16 = 443;
const HTTP_11_ALPN: &[u8] = b"http/1.1";
const MAX_HTTP_HEADERS: usize = 64;
const MAX_RESPONSE_HEADER_BYTES: usize = 32 * 1_024;
const MAX_REQUEST_HEADER_BYTES: usize = 16 * 1_024;
const MAX_CHUNK_LINE_BYTES: usize = 128;
const MAX_RESOLVED_ADDRESSES: usize = 32;
const MAX_ACTIVE_DNS_LOOKUPS: usize = 4;
const CONNECT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

static ACTIVE_DNS_LOOKUPS: AtomicUsize = AtomicUsize::new(0);

/// Failure to construct the public-root HTTPS egress transport.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum WebPkiHttpsEgressBuildError {
    #[error(transparent)]
    InvalidPolicy(#[from] HttpsPolicyError),
    #[error("the selected rustls provider has no safe default protocol versions")]
    NoSafeTlsProtocolVersions,
}

/// Direct, one-shot HTTPS transport for one exact bounded egress policy.
///
/// The transport owns no credential store, reads no proxy environment, keeps
/// no cookie jar or connection pool, and has no client certificate. Its
/// `Debug` representation deliberately omits domains and policy material.
#[derive(Clone)]
pub struct WebPkiHttpsEgress {
    policy: HttpsEgressPolicy,
    connector: Arc<dyn NetworkConnector>,
}

impl fmt::Debug for WebPkiHttpsEgress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebPkiHttpsEgress")
            .finish_non_exhaustive()
    }
}

impl WebPkiHttpsEgress {
    /// Builds a direct rustls client with the static Mozilla public-root set.
    ///
    /// TLS early data, session resumption, client authentication, proxies,
    /// connection reuse, redirects, decompression, cookies, and retries are
    /// absent by construction.
    ///
    /// # Errors
    ///
    /// Rejects an invalid egress policy or unavailable safe TLS defaults.
    pub fn new(policy: HttpsEgressPolicy) -> Result<Self, WebPkiHttpsEgressBuildError> {
        policy.validate()?;
        let connector = WebPkiConnector::new()?;
        Ok(Self {
            policy,
            connector: Arc::new(connector),
        })
    }

    #[cfg(test)]
    fn with_connector(
        policy: HttpsEgressPolicy,
        connector: Arc<dyn NetworkConnector>,
    ) -> Result<Self, WebPkiHttpsEgressBuildError> {
        policy.validate()?;
        Ok(Self { policy, connector })
    }
}

impl HttpsEgress for WebPkiHttpsEgress {
    fn policy(&self) -> HttpsEgressPolicy {
        self.policy.clone()
    }

    fn execute(
        &self,
        request: &HttpsEgressRequest,
    ) -> Result<HttpsEgressResponse, HttpsEgressError> {
        self.policy
            .validate()
            .map_err(|_| HttpsEgressError::Policy)?;
        let prepared = prepare_request(request).map_err(|()| HttpsEgressError::Policy)?;
        if !self.policy.authorizes(&prepared) {
            return Err(HttpsEgressError::Policy);
        }
        let encoded = encode_http_request(&prepared).map_err(|()| HttpsEgressError::Policy)?;
        let deadline = Deadline::new(Duration::from_secs(u64::from(prepared.timeout_seconds)))
            .map_err(|()| HttpsEgressError::Policy)?;
        let mut stream = self
            .connector
            .connect(&prepared.domain, deadline)
            .map_err(ConnectionFailure::into_egress_error)?;
        let parsed = exchange_http(
            stream.as_mut(),
            encoded.as_slice(),
            deadline,
            prepared.max_response_bytes,
            prepared.method,
        )
        .map_err(WireFailure::into_egress_error)?;
        if (300..=399).contains(&parsed.status) {
            return Err(HttpsEgressError::Redirect);
        }
        let body = String::from_utf8(parsed.body).map_err(|_| HttpsEgressError::InvalidResponse)?;
        Ok(HttpsEgressResponse {
            status: parsed.status,
            headers: parsed.headers,
            body,
            redirected: false,
        })
    }
}

fn prepare_request(request: &HttpsEgressRequest) -> Result<PreparedHttpsRequest, ()> {
    if request.url.is_empty() || request.url.len() > MAX_URL_BYTES {
        return Err(());
    }
    let uri = request.url.parse::<Uri>().map_err(|_| ())?;
    if uri.scheme_str() != Some("https") {
        return Err(());
    }
    let authority = uri.authority().ok_or(())?;
    if authority.as_str().contains('@') || authority.port_u16().is_some_and(|port| port != 443) {
        return Err(());
    }
    let domain = authority.host().to_owned();
    validate_domain(&domain).map_err(|_| ())?;
    if authority.as_str() != domain && authority.as_str() != format!("{domain}:443") {
        return Err(());
    }
    let target = uri
        .path_and_query()
        .map_or("/", axum::http::uri::PathAndQuery::as_str)
        .to_owned();
    if target.is_empty()
        || target.len() > MAX_URL_BYTES
        || !target.starts_with('/')
        || target.contains(['#', '\\'])
        || target.chars().any(char::is_control)
    {
        return Err(());
    }
    validate_headers(&request.headers, REQUEST_HEADER_ALLOWLIST).map_err(|_| ())?;
    if request.headers.len() > MAX_HEADER_COUNT
        || request.headers.iter().any(|header| {
            header.value.len() > MAX_HEADER_VALUE_BYTES
                || !header
                    .value
                    .bytes()
                    .all(|byte| (b' '..=b'~').contains(&byte))
        })
    {
        return Err(());
    }
    if request
        .body
        .as_ref()
        .is_some_and(|body| body.len() > MAX_BODY_BYTES)
        || (matches!(request.method, HttpsMethod::Get | HttpsMethod::Head)
            && request.body.is_some())
        || !(1..=MAX_TIMEOUT_SECONDS).contains(&request.timeout_seconds)
        || request.max_response_bytes == 0
        || request.max_response_bytes > MAX_RESPONSE_BYTES
    {
        return Err(());
    }
    Ok(PreparedHttpsRequest {
        method: request.method,
        url: request.url.clone(),
        domain,
        target,
        headers: request.headers.clone(),
        body: request.body.clone(),
        timeout_seconds: request.timeout_seconds,
        max_response_bytes: request.max_response_bytes,
    })
}

fn encode_http_request(request: &PreparedHttpsRequest) -> Result<Zeroizing<Vec<u8>>, ()> {
    let body = request.body.as_deref().unwrap_or_default().as_bytes();
    let mut encoded = Zeroizing::new(Vec::with_capacity(
        body.len().saturating_add(MAX_REQUEST_HEADER_BYTES),
    ));
    encoded.extend_from_slice(method_token(request.method));
    encoded.extend_from_slice(b" ");
    encoded.extend_from_slice(request.target.as_bytes());
    encoded.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    encoded.extend_from_slice(request.domain.as_bytes());
    encoded.extend_from_slice(b"\r\nAccept-Encoding: identity\r\n");
    for header in &request.headers {
        if !valid_header_name(header.name.as_bytes())
            || !header
                .value
                .bytes()
                .all(|byte| (b' '..=b'~').contains(&byte))
            || header.name.eq_ignore_ascii_case("host")
            || header.name.eq_ignore_ascii_case("content-length")
            || header.name.eq_ignore_ascii_case("connection")
            || header.name.eq_ignore_ascii_case("accept-encoding")
        {
            return Err(());
        }
        encoded.extend_from_slice(header.name.as_bytes());
        encoded.extend_from_slice(b": ");
        encoded.extend_from_slice(header.value.as_bytes());
        encoded.extend_from_slice(b"\r\n");
        if encoded.len() > MAX_REQUEST_HEADER_BYTES {
            return Err(());
        }
    }
    encoded.extend_from_slice(b"Content-Length: ");
    encoded.extend_from_slice(body.len().to_string().as_bytes());
    encoded.extend_from_slice(b"\r\nConnection: close\r\n\r\n");
    if encoded.len() > MAX_REQUEST_HEADER_BYTES {
        return Err(());
    }
    encoded.extend_from_slice(body);
    Ok(encoded)
}

const fn method_token(method: HttpsMethod) -> &'static [u8] {
    match method {
        HttpsMethod::Get => b"GET",
        HttpsMethod::Head => b"HEAD",
        HttpsMethod::Post => b"POST",
        HttpsMethod::Put => b"PUT",
        HttpsMethod::Patch => b"PATCH",
        HttpsMethod::Delete => b"DELETE",
    }
}

trait NetworkConnector: fmt::Debug + Send + Sync {
    fn connect(
        &self,
        authority: &str,
        deadline: Deadline,
    ) -> Result<Box<dyn TimedIo>, ConnectionFailure>;
}

#[derive(Clone)]
struct WebPkiConnector {
    tls_config: Arc<ClientConfig>,
}

impl fmt::Debug for WebPkiConnector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebPkiConnector")
            .finish_non_exhaustive()
    }
}

impl WebPkiConnector {
    fn new() -> Result<Self, WebPkiHttpsEgressBuildError> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let builder = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| WebPkiHttpsEgressBuildError::NoSafeTlsProtocolVersions)?;
        let mut tls_config = builder.with_root_certificates(roots).with_no_client_auth();
        tls_config.alpn_protocols = vec![HTTP_11_ALPN.to_vec()];
        tls_config.enable_sni = true;
        tls_config.enable_early_data = false;
        tls_config.resumption = Resumption::disabled();
        Ok(Self {
            tls_config: Arc::new(tls_config),
        })
    }
}

impl NetworkConnector for WebPkiConnector {
    fn connect(
        &self,
        authority: &str,
        deadline: Deadline,
    ) -> Result<Box<dyn TimedIo>, ConnectionFailure> {
        let addresses = resolve_public_addresses(authority, deadline)?;
        let mut socket_and_peer = None;
        for address in addresses {
            let remaining = deadline
                .remaining()
                .map_err(|()| ConnectionFailure::Timeout)?;
            let timeout = CONNECT_ATTEMPT_TIMEOUT.min(remaining);
            match TcpStream::connect_timeout(&address, timeout) {
                Ok(socket) => {
                    socket_and_peer = Some((socket, address));
                    break;
                }
                Err(error) if is_timeout(&error) => {
                    if deadline.remaining().is_err() {
                        return Err(ConnectionFailure::Timeout);
                    }
                }
                Err(_) => {}
            }
        }
        let (mut socket, selected_peer) = socket_and_peer.ok_or(ConnectionFailure::Connect)?;
        socket
            .set_nodelay(true)
            .map_err(|_| ConnectionFailure::Connect)?;
        apply_socket_deadline(&socket, deadline).map_err(|error| map_connection_io(&error))?;

        let server_name =
            ServerName::try_from(authority.to_owned()).map_err(|_| ConnectionFailure::Tls)?;
        let mut connection = ClientConnection::new(Arc::clone(&self.tls_config), server_name)
            .map_err(|_| ConnectionFailure::Tls)?;
        while connection.is_handshaking() {
            apply_socket_deadline(&socket, deadline).map_err(|error| map_connection_io(&error))?;
            match connection.complete_io(&mut socket) {
                Ok((0, 0)) if connection.is_handshaking() => {
                    return Err(ConnectionFailure::Tls);
                }
                Ok(_) => {}
                Err(error) if is_timeout(&error) => return Err(ConnectionFailure::Timeout),
                Err(_) => return Err(ConnectionFailure::Tls),
            }
        }
        if connection.alpn_protocol() != Some(HTTP_11_ALPN) {
            return Err(ConnectionFailure::Tls);
        }
        if socket.peer_addr().map_err(|_| ConnectionFailure::Connect)? != selected_peer {
            return Err(ConnectionFailure::Connect);
        }
        Ok(Box::new(StreamOwned::new(connection, socket)))
    }
}

#[derive(Clone, Copy, Debug)]
struct Deadline {
    at: Instant,
}

impl Deadline {
    fn new(timeout: Duration) -> Result<Self, ()> {
        Instant::now()
            .checked_add(timeout)
            .map(|at| Self { at })
            .ok_or(())
    }

    fn remaining(self) -> Result<Duration, ()> {
        self.at
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectionFailure {
    NameResolution,
    Connect,
    Tls,
    Timeout,
}

impl ConnectionFailure {
    const fn into_egress_error(self) -> HttpsEgressError {
        match self {
            Self::Tls => HttpsEgressError::Tls,
            Self::NameResolution | Self::Connect | Self::Timeout => HttpsEgressError::Transport,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WireFailure {
    Timeout,
    Protocol,
    ResponseTooLarge,
}

impl WireFailure {
    const fn into_egress_error(self) -> HttpsEgressError {
        match self {
            Self::Timeout => HttpsEgressError::Transport,
            Self::Protocol => HttpsEgressError::InvalidResponse,
            Self::ResponseTooLarge => HttpsEgressError::ResponseTooLarge,
        }
    }
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

fn map_connection_io(error: &io::Error) -> ConnectionFailure {
    if is_timeout(error) {
        ConnectionFailure::Timeout
    } else {
        ConnectionFailure::Connect
    }
}

fn map_wire_io(error: &io::Error) -> WireFailure {
    if is_timeout(error) {
        WireFailure::Timeout
    } else {
        WireFailure::Protocol
    }
}

fn apply_socket_deadline(socket: &TcpStream, deadline: Deadline) -> io::Result<()> {
    let remaining = deadline
        .remaining()
        .map_err(|()| io::Error::new(io::ErrorKind::TimedOut, "request deadline expired"))?;
    socket.set_read_timeout(Some(remaining))?;
    socket.set_write_timeout(Some(remaining))
}

trait TimedIo: Read + Write + Send {
    fn apply_deadline(&mut self, deadline: Deadline) -> io::Result<()>;
}

impl TimedIo for StreamOwned<ClientConnection, TcpStream> {
    fn apply_deadline(&mut self, deadline: Deadline) -> io::Result<()> {
        apply_socket_deadline(&self.sock, deadline)
    }
}

fn exchange_http<T: TimedIo + ?Sized>(
    stream: &mut T,
    request: &[u8],
    deadline: Deadline,
    max_response_body_bytes: usize,
    method: HttpsMethod,
) -> Result<ParsedResponse, WireFailure> {
    write_all_deadline(stream, request, deadline)?;
    stream
        .apply_deadline(deadline)
        .map_err(|error| map_wire_io(&error))?;
    stream.flush().map_err(|error| map_wire_io(&error))?;
    let mut reader = DeadlineReader { stream, deadline };
    read_http_response(
        &mut reader,
        ResponseLimits {
            max_header_bytes: MAX_RESPONSE_HEADER_BYTES,
            max_body_bytes: max_response_body_bytes,
        },
        method,
    )
}

fn write_all_deadline<T: TimedIo + ?Sized>(
    stream: &mut T,
    mut bytes: &[u8],
    deadline: Deadline,
) -> Result<(), WireFailure> {
    while !bytes.is_empty() {
        stream
            .apply_deadline(deadline)
            .map_err(|error| map_wire_io(&error))?;
        match stream.write(bytes) {
            Ok(0) => return Err(WireFailure::Protocol),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(map_wire_io(&error)),
        }
    }
    Ok(())
}

struct DeadlineReader<'a, T: ?Sized> {
    stream: &'a mut T,
    deadline: Deadline,
}

impl<T: ?Sized> fmt::Debug for DeadlineReader<'_, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeadlineReader")
            .finish_non_exhaustive()
    }
}

impl<T: TimedIo + ?Sized> Read for DeadlineReader<'_, T> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.apply_deadline(self.deadline)?;
        self.stream.read(buffer)
    }
}

fn resolve_public_addresses(
    authority: &str,
    deadline: Deadline,
) -> Result<Vec<SocketAddr>, ConnectionFailure> {
    acquire_dns_slot()?;
    let authority = authority.to_owned();
    let (sender, receiver) = mpsc::sync_channel(1);
    let spawn = thread::Builder::new()
        .name("accordlock-public-dns".to_owned())
        .spawn(move || {
            let _slot = DnsSlot;
            let result = resolve_now(&authority);
            let _ = sender.send(result);
        });
    if spawn.is_err() {
        ACTIVE_DNS_LOOKUPS.fetch_sub(1, Ordering::AcqRel);
        return Err(ConnectionFailure::NameResolution);
    }
    let remaining = deadline
        .remaining()
        .map_err(|()| ConnectionFailure::Timeout)?;
    match receiver.recv_timeout(remaining) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(ConnectionFailure::Timeout),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(ConnectionFailure::NameResolution),
    }
}

fn acquire_dns_slot() -> Result<(), ConnectionFailure> {
    ACTIVE_DNS_LOOKUPS
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
            (active < MAX_ACTIVE_DNS_LOOKUPS).then_some(active + 1)
        })
        .map(|_| ())
        .map_err(|_| ConnectionFailure::NameResolution)
}

struct DnsSlot;

impl Drop for DnsSlot {
    fn drop(&mut self) {
        ACTIVE_DNS_LOOKUPS.fetch_sub(1, Ordering::AcqRel);
    }
}

fn resolve_now(authority: &str) -> Result<Vec<SocketAddr>, ConnectionFailure> {
    let resolved = (authority, HTTPS_PORT)
        .to_socket_addrs()
        .map_err(|_| ConnectionFailure::NameResolution)?;
    validate_resolved_addresses(resolved)
}

fn validate_resolved_addresses(
    resolved: impl IntoIterator<Item = SocketAddr>,
) -> Result<Vec<SocketAddr>, ConnectionFailure> {
    let mut addresses = BTreeSet::new();
    for address in resolved {
        if addresses.len() >= MAX_RESOLVED_ADDRESSES || !is_public_address(address.ip()) {
            return Err(ConnectionFailure::NameResolution);
        }
        addresses.insert(address);
    }
    if addresses.is_empty() {
        return Err(ConnectionFailure::NameResolution);
    }
    Ok(addresses.into_iter().collect())
}

fn is_public_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_private()
        && !address.is_link_local()
        && !address.is_multicast()
        && !address.is_broadcast()
        && !address.is_documentation()
        && octets[0] != 0
        && !(octets[0] == 100 && (64..=127).contains(&octets[1]))
        && !(octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        && !(octets[0] == 198 && matches!(octets[1], 18 | 19))
        && octets[0] < 240
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    let octets = address.octets();
    if address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || (octets[0] & 0xfe) == 0xfc
        || (octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80)
        || (octets[0] == 0xfe && (octets[1] & 0xc0) == 0xc0)
        || octets[..4] == [0x20, 0x01, 0x0d, 0xb8]
        || octets[..4] == [0x20, 0x01, 0, 0]
        || octets[..6] == [0x20, 0x01, 0, 2, 0, 0]
        || (octets[0] == 0x20 && octets[1] == 0x02)
        || octets[..12] == [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0]
        || octets[..6] == [0, 0x64, 0xff, 0x9b, 0, 1]
        || octets[..8] == [1, 0, 0, 0, 0, 0, 0, 0]
    {
        return false;
    }
    !(octets[..12].iter().all(|byte| *byte == 0)
        || (octets[..10].iter().all(|byte| *byte == 0) && octets[10] == 0xff && octets[11] == 0xff))
}

#[derive(Clone, Copy, Debug)]
struct ResponseLimits {
    max_header_bytes: usize,
    max_body_bytes: usize,
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedResponse {
    status: u16,
    headers: Vec<HttpsHeader>,
    body: Vec<u8>,
}

fn read_http_response<R: Read>(
    reader: &mut R,
    limits: ResponseLimits,
    method: HttpsMethod,
) -> Result<ParsedResponse, WireFailure> {
    let mut received = Vec::with_capacity(limits.max_header_bytes.min(8_192));
    let header_end = loop {
        if let Some(index) = find_bytes(&received, b"\r\n\r\n") {
            let end = index + 4;
            if end > limits.max_header_bytes {
                return Err(WireFailure::ResponseTooLarge);
            }
            break end;
        }
        if received.len() >= limits.max_header_bytes {
            return Err(WireFailure::ResponseTooLarge);
        }
        read_more(
            reader,
            &mut received,
            limits.max_header_bytes.saturating_add(8_192),
        )?;
    };

    let head = parse_response_head(&received[..header_end], method)?;
    let initial_body = received.split_off(header_end);
    let body = match head.framing {
        BodyFraming::None => {
            if !initial_body.is_empty() && !(300..=399).contains(&head.status) {
                return Err(WireFailure::Protocol);
            }
            Vec::new()
        }
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
    Ok(ParsedResponse {
        status: head.status,
        headers: head.headers,
        body,
    })
}

fn read_more<R: Read>(
    reader: &mut R,
    destination: &mut Vec<u8>,
    absolute_limit: usize,
) -> Result<(), WireFailure> {
    let remaining = absolute_limit.saturating_sub(destination.len());
    if remaining == 0 {
        return Err(WireFailure::ResponseTooLarge);
    }
    let mut buffer = [0_u8; 8_192];
    let requested = remaining.min(buffer.len());
    let count = loop {
        match reader.read(&mut buffer[..requested]) {
            Ok(0) => return Err(WireFailure::Protocol),
            Ok(count) => break count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(map_wire_io(&error)),
        }
    };
    destination.extend_from_slice(&buffer[..count]);
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedResponseHead {
    status: u16,
    headers: Vec<HttpsHeader>,
    framing: BodyFraming,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BodyFraming {
    None,
    ContentLength(usize),
    Chunked,
}

fn parse_response_head(
    bytes: &[u8],
    method: HttpsMethod,
) -> Result<ParsedResponseHead, WireFailure> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HTTP_HEADERS];
    let mut response = httparse::Response::new(&mut headers);
    let parsed = response.parse(bytes).map_err(|_| WireFailure::Protocol)?;
    if parsed != httparse::Status::Complete(bytes.len()) || response.version != Some(1) {
        return Err(WireFailure::Protocol);
    }
    let status = response.code.ok_or(WireFailure::Protocol)?;
    if !(200..=599).contains(&status) {
        return Err(WireFailure::Protocol);
    }

    let mut content_length = None;
    let mut transfer_encoding = None;
    let mut content_encoding = None;
    let mut trailer_declared = false;
    let mut retained = BTreeMap::new();
    for header in response.headers {
        if !valid_header_name(header.name.as_bytes())
            || !header
                .value
                .iter()
                .copied()
                .all(|byte| (b' '..=b'~').contains(&byte))
        {
            return Err(WireFailure::Protocol);
        }
        let name = header.name.to_ascii_lowercase();
        if name == "content-length" {
            if content_length.is_some() {
                return Err(WireFailure::Protocol);
            }
            content_length = Some(parse_content_length(header.value)?);
        } else if name == "transfer-encoding" {
            if transfer_encoding.is_some() {
                return Err(WireFailure::Protocol);
            }
            transfer_encoding = Some(header.value);
        } else if name == "content-encoding" {
            if content_encoding.is_some() {
                return Err(WireFailure::Protocol);
            }
            content_encoding = Some(header.value);
        } else if name == "trailer" {
            trailer_declared = true;
        }
        if RESPONSE_HEADER_ALLOWLIST.contains(&name.as_str()) {
            let value = std::str::from_utf8(header.value)
                .map_err(|_| WireFailure::Protocol)?
                .to_owned();
            if value.len() > MAX_HEADER_VALUE_BYTES || retained.insert(name, value).is_some() {
                return Err(WireFailure::Protocol);
            }
        }
    }
    if content_length.is_some() && transfer_encoding.is_some() {
        return Err(WireFailure::Protocol);
    }
    if content_encoding.is_some_and(|value| !value.eq_ignore_ascii_case(b"identity")) {
        return Err(WireFailure::Protocol);
    }
    let no_body = method == HttpsMethod::Head || status == 204 || (300..=399).contains(&status);
    let framing = if no_body {
        if status == 204
            && (content_length.is_some_and(|length| length != 0) || transfer_encoding.is_some())
        {
            return Err(WireFailure::Protocol);
        }
        BodyFraming::None
    } else {
        match (content_length, transfer_encoding) {
            (Some(length), None) => BodyFraming::ContentLength(length),
            (None, Some(value)) if !trailer_declared && value.eq_ignore_ascii_case(b"chunked") => {
                BodyFraming::Chunked
            }
            _ => return Err(WireFailure::Protocol),
        }
    };
    let headers = retained
        .into_iter()
        .map(|(name, value)| HttpsHeader { name, value })
        .collect::<Vec<_>>();
    validate_headers(&headers, RESPONSE_HEADER_ALLOWLIST).map_err(|_| WireFailure::Protocol)?;
    Ok(ParsedResponseHead {
        status,
        headers,
        framing,
    })
}

const fn valid_header_name_byte(byte: u8) -> bool {
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

fn valid_header_name(name: &[u8]) -> bool {
    !name.is_empty() && name.iter().copied().all(valid_header_name_byte)
}

fn parse_content_length(bytes: &[u8]) -> Result<usize, WireFailure> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(WireFailure::Protocol);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| WireFailure::Protocol)?;
    text.parse::<usize>().map_err(|_| WireFailure::Protocol)
}

fn read_content_length_body<R: Read>(
    reader: &mut R,
    mut initial: Vec<u8>,
    length: usize,
    maximum: usize,
) -> Result<Vec<u8>, WireFailure> {
    if length > maximum {
        return Err(WireFailure::ResponseTooLarge);
    }
    if initial.len() > length {
        return Err(WireFailure::Protocol);
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
) -> Result<Vec<u8>, WireFailure> {
    let encoded_limit = max_body_bytes
        .checked_add(framing_allowance)
        .ok_or(WireFailure::ResponseTooLarge)?;
    if initial.len() > encoded_limit {
        return Err(WireFailure::ResponseTooLarge);
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
                return Err(WireFailure::Protocol);
            }
            if source.cursor != source.encoded.len() {
                return Err(WireFailure::Protocol);
            }
            return Ok(decoded);
        }
        if size > max_body_bytes.saturating_sub(decoded.len()) {
            return Err(WireFailure::ResponseTooLarge);
        }
        let chunk = source.read_exact_slice(size)?;
        decoded.extend_from_slice(chunk);
        if source.read_exact_slice(2)? != b"\r\n" {
            return Err(WireFailure::Protocol);
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
    fn fill_until(&mut self, needed: usize) -> Result<(), WireFailure> {
        while self.encoded.len().saturating_sub(self.cursor) < needed {
            read_more(self.reader, &mut self.encoded, self.encoded_limit)?;
        }
        Ok(())
    }

    fn read_crlf_line(&mut self, maximum: usize) -> Result<Vec<u8>, WireFailure> {
        loop {
            if let Some(relative) = find_bytes(&self.encoded[self.cursor..], b"\r\n") {
                if relative > maximum {
                    return Err(WireFailure::Protocol);
                }
                let start = self.cursor;
                let end = start + relative;
                self.cursor = end + 2;
                return Ok(self.encoded[start..end].to_vec());
            }
            if self.encoded.len().saturating_sub(self.cursor) > maximum {
                return Err(WireFailure::Protocol);
            }
            read_more(self.reader, &mut self.encoded, self.encoded_limit)?;
        }
    }

    fn read_exact_slice(&mut self, length: usize) -> Result<&[u8], WireFailure> {
        self.fill_until(length)?;
        let start = self.cursor;
        let end = start
            .checked_add(length)
            .ok_or(WireFailure::ResponseTooLarge)?;
        self.cursor = end;
        Ok(&self.encoded[start..end])
    }
}

fn parse_chunk_size(line: &[u8]) -> Result<usize, WireFailure> {
    if line.is_empty()
        || line.len() > 16
        || !line.iter().all(u8::is_ascii_hexdigit)
        || (line.len() > 1 && line[0] == b'0')
    {
        return Err(WireFailure::Protocol);
    }
    let text = std::str::from_utf8(line).map_err(|_| WireFailure::Protocol)?;
    usize::from_str_radix(text, 16).map_err(|_| WireFailure::Protocol)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use std::{
        io::Cursor,
        sync::{Arc, Mutex},
    };

    use super::*;

    #[derive(Debug)]
    struct ScriptedConnector {
        response: Vec<u8>,
        request: Arc<Mutex<Vec<u8>>>,
    }

    impl NetworkConnector for ScriptedConnector {
        fn connect(
            &self,
            _authority: &str,
            _deadline: Deadline,
        ) -> Result<Box<dyn TimedIo>, ConnectionFailure> {
            Ok(Box::new(ScriptedIo {
                response: Cursor::new(self.response.clone()),
                request: Arc::clone(&self.request),
            }))
        }
    }

    #[derive(Debug)]
    struct ScriptedIo {
        response: Cursor<Vec<u8>>,
        request: Arc<Mutex<Vec<u8>>>,
    }

    impl Read for ScriptedIo {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.response.read(buffer)
        }
    }

    impl Write for ScriptedIo {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            let mut request = self
                .request
                .lock()
                .map_err(|_| io::Error::other("scripted request lock failed"))?;
            request.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl TimedIo for ScriptedIo {
        fn apply_deadline(&mut self, _deadline: Deadline) -> io::Result<()> {
            Ok(())
        }
    }

    fn policy() -> Result<HttpsEgressPolicy, HttpsPolicyError> {
        HttpsEgressPolicy::new(
            "native-test-v1",
            ["api.example.com".to_owned()],
            [HttpsMethod::Get, HttpsMethod::Post],
            1_024,
            4_096,
        )
    }

    fn request(method: HttpsMethod, body: Option<String>) -> HttpsEgressRequest {
        HttpsEgressRequest {
            method,
            url: "https://api.example.com/v1/items?limit=1".to_owned(),
            headers: vec![HttpsHeader {
                name: "accept".to_owned(),
                value: "application/json".to_owned(),
            }],
            body,
            timeout_seconds: 2,
            max_response_bytes: 4_096,
        }
    }

    #[test]
    fn full_transport_uses_one_direct_canonical_request_without_ambient_credentials()
    -> Result<(), Box<dyn std::error::Error>> {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Request-Id: req-7\r\nContent-Length: 11\r\n\r\n{\"ok\":true}";
        let transport = WebPkiHttpsEgress::with_connector(
            policy()?,
            Arc::new(ScriptedConnector {
                response: response.to_vec(),
                request: Arc::clone(&captured),
            }),
        )?;

        let result = transport.execute(&request(HttpsMethod::Get, None))?;
        assert_eq!(result.status, 200);
        assert_eq!(result.body, "{\"ok\":true}");
        assert_eq!(result.headers[0].name, "content-length");
        assert_eq!(result.headers[1].name, "content-type");
        assert_eq!(result.headers[2].name, "x-request-id");
        let sent = captured
            .lock()
            .map_err(|_| "scripted request lock failed")?
            .clone();
        let sent = std::str::from_utf8(&sent)?;
        assert!(sent.starts_with("GET /v1/items?limit=1 HTTP/1.1\r\nHost: api.example.com\r\n"));
        assert!(sent.contains("\r\nAccept-Encoding: identity\r\n"));
        assert!(!sent.to_ascii_lowercase().contains("authorization"));
        assert!(!sent.to_ascii_lowercase().contains("cookie"));
        assert!(!sent.to_ascii_lowercase().contains("proxy"));
        Ok(())
    }

    #[test]
    fn policy_mismatch_is_refused_before_the_connector_runs()
    -> Result<(), Box<dyn std::error::Error>> {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let transport = WebPkiHttpsEgress::with_connector(
            policy()?,
            Arc::new(ScriptedConnector {
                response: Vec::new(),
                request: Arc::clone(&captured),
            }),
        )?;
        let mut outside = request(HttpsMethod::Get, None);
        outside.url = "https://sub.api.example.com/v1/items".to_owned();
        assert_eq!(transport.execute(&outside), Err(HttpsEgressError::Policy));
        assert!(
            captured
                .lock()
                .map_err(|_| "scripted request lock failed")?
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn redirect_is_terminal_and_never_followed() -> Result<(), Box<dyn std::error::Error>> {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let transport = WebPkiHttpsEgress::with_connector(
            policy()?,
            Arc::new(ScriptedConnector {
                response: b"HTTP/1.1 302 Found\r\nLocation: https://evil.example/\r\nContent-Length: 99\r\n\r\n"
                    .to_vec(),
                request: Arc::clone(&captured),
            }),
        )?;
        assert_eq!(
            transport.execute(&request(HttpsMethod::Get, None)),
            Err(HttpsEgressError::Redirect)
        );
        assert!(!captured.lock().map_err(|_| "lock failed")?.is_empty());
        Ok(())
    }

    #[test]
    fn chunked_body_is_decoded_but_trailers_and_compression_are_rejected() {
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let parsed = read_http_response(
            &mut Cursor::new(chunked),
            ResponseLimits {
                max_header_bytes: 1_024,
                max_body_bytes: 11,
            },
            HttpsMethod::Get,
        );
        assert!(parsed.is_ok_and(|response| response.body == b"hello world"));

        let trailer = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Test\r\n\r\n0\r\nX-Test: value\r\n\r\n";
        assert_eq!(
            read_http_response(
                &mut Cursor::new(trailer),
                ResponseLimits {
                    max_header_bytes: 1_024,
                    max_body_bytes: 32,
                },
                HttpsMethod::Get,
            ),
            Err(WireFailure::Protocol)
        );

        let compressed = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            read_http_response(
                &mut Cursor::new(compressed),
                ResponseLimits {
                    max_header_bytes: 1_024,
                    max_body_bytes: 32,
                },
                HttpsMethod::Get,
            ),
            Err(WireFailure::Protocol)
        );
    }

    #[test]
    fn response_bounds_and_ambiguous_framing_fail_closed() {
        let oversized = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(
            read_http_response(
                &mut Cursor::new(oversized),
                ResponseLimits {
                    max_header_bytes: 1_024,
                    max_body_bytes: 4,
                },
                HttpsMethod::Get,
            ),
            Err(WireFailure::ResponseTooLarge)
        );
        let smuggled =
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        assert_eq!(
            read_http_response(
                &mut Cursor::new(smuggled),
                ResponseLimits {
                    max_header_bytes: 1_024,
                    max_body_bytes: 4,
                },
                HttpsMethod::Get,
            ),
            Err(WireFailure::Protocol)
        );
    }

    #[test]
    fn public_dns_filter_rejects_mixed_or_non_public_answers() {
        assert_eq!(
            validate_resolved_addresses([
                SocketAddr::from(([1, 1, 1, 1], 443)),
                SocketAddr::from(([127, 0, 0, 1], 443)),
            ]),
            Err(ConnectionFailure::NameResolution)
        );
        assert!(validate_resolved_addresses([SocketAddr::from(([1, 1, 1, 1], 443))]).is_ok());
        assert!(!is_public_address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!is_public_address(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(!is_public_address(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!is_public_address(IpAddr::V6(
            Ipv4Addr::new(1, 1, 1, 1).to_ipv6_mapped()
        )));
        assert!(!is_public_address(IpAddr::V6(Ipv6Addr::new(
            0x0064, 0xff9b, 0, 0, 0, 0, 0x0a00, 1,
        ))));
        assert!(!is_public_address(IpAddr::V6(Ipv6Addr::new(
            0x2002, 0x0a00, 1, 0, 0, 0, 0, 1,
        ))));
        assert!(is_public_address(IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111,
        ))));
    }

    #[test]
    fn production_constructor_is_offline_and_debug_is_redacted()
    -> Result<(), Box<dyn std::error::Error>> {
        let transport = WebPkiHttpsEgress::new(policy()?)?;
        assert_eq!(format!("{transport:?}"), "WebPkiHttpsEgress { .. }");
        Ok(())
    }
}
