//! Native HTTPS transport for provider notification delivery.
//!
//! This is deliberately smaller than a general-purpose HTTP client. It can
//! contact only the four authorities already fixed by the outbound adapters,
//! uses the Mozilla `WebPKI` root set through rustls, sends one HTTP/1.1
//! request, follows no redirects, uses no proxy, and never retries.

use std::collections::BTreeSet;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs as _};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use rustls::{
    ClientConfig, ClientConnection, RootCertStore, StreamOwned, client::Resumption,
    pki_types::ServerName,
};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::ApprovalChannel;
use crate::ChannelDelivery;
use crate::transport::{
    BoundedHttpsTransport, DeliveryAttempt, DeliveryCredential, DeliveryEndpointConfig,
    DeliveryLimits, DeliveryTransportError, HttpsRequestProgress, HttpsTransportFailure,
    HttpsTransportFailureKind, OutboundHttpsResponse, PreparedHttpsRequest,
    dispatch_channel_delivery,
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

const SLACK_AUTHORITY: &str = "slack.com";
const TELEGRAM_AUTHORITY: &str = "api.telegram.org";
const WHATSAPP_AUTHORITY: &str = "graph.facebook.com";
const TEAMS_AUTHORITY: &str = "smba.trafficmanager.net";

static ACTIVE_DNS_LOOKUPS: AtomicUsize = AtomicUsize::new(0);

/// Failure to construct the fixed public-root HTTPS client.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum WebPkiHttpsClientError {
    #[error("the selected rustls provider has no safe default protocol versions")]
    NoSafeTlsProtocolVersions,
}

/// One-shot native HTTPS transport for the approved notification providers.
///
/// The transport owns no provider credentials and keeps no connection pool.
/// Each call resolves one fixed authority, authenticates it with the bundled
/// public `WebPKI` roots, sends exactly one request, and closes the connection.
/// Its `Debug` representation contains no request or credential data.
#[derive(Clone)]
pub struct WebPkiHttpsTransport {
    tls_config: Arc<ClientConfig>,
}

impl fmt::Debug for WebPkiHttpsTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebPkiHttpsTransport")
            .finish_non_exhaustive()
    }
}

impl WebPkiHttpsTransport {
    /// Builds a rustls client with the static Mozilla public-root set.
    ///
    /// TLS early data, session resumption, client authentication, proxies,
    /// connection reuse, and automatic redirects are disabled.
    ///
    /// # Errors
    ///
    /// Returns an error when rustls cannot select safe protocol versions for
    /// its configured cryptographic provider.
    pub fn new() -> Result<Self, WebPkiHttpsClientError> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let builder = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| WebPkiHttpsClientError::NoSafeTlsProtocolVersions)?;
        let mut tls_config = builder.with_root_certificates(roots).with_no_client_auth();
        tls_config.alpn_protocols = vec![HTTP_11_ALPN.to_vec()];
        tls_config.enable_sni = true;
        tls_config.enable_early_data = false;
        tls_config.resumption = Resumption::disabled();
        Ok(Self {
            tls_config: Arc::new(tls_config),
        })
    }

    /// Synchronously prepares, sends, and classifies one delivery.
    ///
    /// This is the narrow public entry point for a trusted runtime control
    /// method. It blocks for at most `limits.request_timeout()` and must run on
    /// a dedicated worker thread, never the desktop renderer or UI event loop.
    /// It performs no automatic retry; callers that need durable settlement
    /// should use [`crate::process_one_delivery`] with this transport instead.
    ///
    /// # Errors
    ///
    /// Returns a request preparation error for mismatched or invalid delivery
    /// material. Network and provider outcomes are returned as a secret-free
    /// [`DeliveryAttempt`], including ambiguous possibly-sent failures.
    pub fn dispatch_delivery(
        &mut self,
        delivery: &ChannelDelivery,
        endpoint: &DeliveryEndpointConfig,
        credential: &DeliveryCredential,
        limits: DeliveryLimits,
    ) -> Result<DeliveryAttempt, DeliveryTransportError> {
        dispatch_channel_delivery(delivery, endpoint, credential, limits, self)
    }

    fn connect(
        &self,
        endpoint: ResolvedEndpoint<'_>,
        deadline: Deadline,
    ) -> Result<StreamOwned<ClientConnection, TcpStream>, PreSendFailure> {
        let addresses = resolve_public_addresses(endpoint.authority, deadline)?;
        let mut socket_and_peer = None;
        for address in addresses {
            let remaining = deadline.remaining().map_err(|()| PreSendFailure::Timeout)?;
            let timeout = CONNECT_ATTEMPT_TIMEOUT.min(remaining);
            match TcpStream::connect_timeout(&address, timeout) {
                Ok(socket) => {
                    socket_and_peer = Some((socket, address));
                    break;
                }
                Err(error) if is_timeout(&error) => {
                    if deadline.remaining().is_err() {
                        return Err(PreSendFailure::Timeout);
                    }
                }
                Err(_) => {}
            }
        }
        let (mut socket, selected_peer) = socket_and_peer.ok_or(PreSendFailure::Connect)?;
        socket
            .set_nodelay(true)
            .map_err(|_| PreSendFailure::Connect)?;
        apply_socket_deadline(&socket, deadline).map_err(|error| map_pre_send_io(&error))?;

        let server_name =
            ServerName::try_from(endpoint.authority.to_owned()).map_err(|_| PreSendFailure::Tls)?;
        let mut connection = ClientConnection::new(Arc::clone(&self.tls_config), server_name)
            .map_err(|_| PreSendFailure::Tls)?;
        while connection.is_handshaking() {
            apply_socket_deadline(&socket, deadline).map_err(|error| map_pre_send_io(&error))?;
            match connection.complete_io(&mut socket) {
                Ok((0, 0)) if connection.is_handshaking() => {
                    return Err(PreSendFailure::Tls);
                }
                Ok(_) => {}
                Err(error) if is_timeout(&error) => return Err(PreSendFailure::Timeout),
                Err(_) => return Err(PreSendFailure::Tls),
            }
        }
        if connection.alpn_protocol() != Some(HTTP_11_ALPN) {
            return Err(PreSendFailure::Tls);
        }
        if socket.peer_addr().map_err(|_| PreSendFailure::Connect)? != selected_peer {
            return Err(PreSendFailure::Connect);
        }
        Ok(StreamOwned::new(connection, socket))
    }
}

impl BoundedHttpsTransport for WebPkiHttpsTransport {
    fn send(
        &mut self,
        request: &PreparedHttpsRequest,
    ) -> Result<OutboundHttpsResponse, HttpsTransportFailure> {
        let endpoint = parse_endpoint(request.channel(), request.expose_endpoint())
            .map_err(|()| pre_send(HttpsTransportFailureKind::Protocol))?;
        let encoded = encode_http_request(
            endpoint.path,
            endpoint.authority,
            request
                .headers()
                .iter()
                .map(|header| (header.name(), header.expose_value())),
            request.body(),
        )
        .map_err(|()| pre_send(HttpsTransportFailureKind::Protocol))?;
        let deadline = Deadline::new(request.limits().request_timeout());
        let mut stream = self
            .connect(endpoint, deadline)
            .map_err(PreSendFailure::into_transport_failure)?;

        exchange_http(
            &mut stream,
            encoded.as_slice(),
            deadline,
            request.limits().max_response_body_bytes(),
        )
        .map_err(WireFailure::into_transport_failure)
    }
}

#[derive(Clone, Copy, Debug)]
struct ResolvedEndpoint<'a> {
    authority: &'static str,
    path: &'a str,
}

fn parse_endpoint(channel: ApprovalChannel, endpoint: &str) -> Result<ResolvedEndpoint<'_>, ()> {
    let expected_authority = match channel {
        ApprovalChannel::Slack => SLACK_AUTHORITY,
        ApprovalChannel::Telegram => TELEGRAM_AUTHORITY,
        ApprovalChannel::WhatsApp => WHATSAPP_AUTHORITY,
        ApprovalChannel::MicrosoftTeams => TEAMS_AUTHORITY,
    };
    let rest = endpoint.strip_prefix("https://").ok_or(())?;
    let separator = rest.find('/').ok_or(())?;
    let (authority, path) = rest.split_at(separator);
    if authority != expected_authority
        || path.is_empty()
        || path.len() > crate::MAX_DELIVERY_ENDPOINT_BYTES
        || path.contains(['?', '#', '\\'])
        || !path.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err(());
    }
    Ok(ResolvedEndpoint {
        authority: expected_authority,
        path,
    })
}

fn encode_http_request<'a>(
    path: &str,
    authority: &str,
    headers: impl Iterator<Item = (&'a str, &'a str)>,
    body: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ()> {
    let mut encoded = Zeroizing::new(Vec::with_capacity(
        body.len().saturating_add(MAX_REQUEST_HEADER_BYTES),
    ));
    encoded.extend_from_slice(b"POST ");
    encoded.extend_from_slice(path.as_bytes());
    encoded.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    encoded.extend_from_slice(authority.as_bytes());
    encoded.extend_from_slice(b"\r\n");
    let mut header_bytes = encoded.len();
    for (name, value) in headers {
        if !valid_request_header(name.as_bytes(), value.as_bytes())
            || matches_ignore_ascii_case(name, &["host", "content-length", "connection"])
        {
            return Err(());
        }
        header_bytes = header_bytes
            .checked_add(name.len())
            .and_then(|total| total.checked_add(2))
            .and_then(|total| total.checked_add(value.len()))
            .and_then(|total| total.checked_add(2))
            .ok_or(())?;
        if header_bytes > MAX_REQUEST_HEADER_BYTES {
            return Err(());
        }
        encoded.extend_from_slice(name.as_bytes());
        encoded.extend_from_slice(b": ");
        encoded.extend_from_slice(value.as_bytes());
        encoded.extend_from_slice(b"\r\n");
    }
    let body_length = body.len().to_string();
    encoded.extend_from_slice(b"Content-Length: ");
    encoded.extend_from_slice(body_length.as_bytes());
    encoded.extend_from_slice(b"\r\nConnection: close\r\n\r\n");
    if encoded.len().saturating_sub(body.len()) > MAX_REQUEST_HEADER_BYTES {
        return Err(());
    }
    encoded.extend_from_slice(body);
    Ok(encoded)
}

fn matches_ignore_ascii_case(value: &str, forbidden: &[&str]) -> bool {
    forbidden
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
}

fn valid_request_header(name: &[u8], value: &[u8]) -> bool {
    !name.is_empty()
        && name.iter().copied().all(is_token_byte)
        && !value.is_empty()
        && value
            .iter()
            .copied()
            .all(|byte| (b' '..=b'~').contains(&byte))
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

    fn remaining(self) -> Result<Duration, ()> {
        self.at
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(())
    }
}

#[derive(Clone, Copy, Debug)]
enum PreSendFailure {
    NameResolution,
    Connect,
    Tls,
    Timeout,
}

impl PreSendFailure {
    const fn into_transport_failure(self) -> HttpsTransportFailure {
        let kind = match self {
            Self::NameResolution => HttpsTransportFailureKind::NameResolution,
            Self::Connect => HttpsTransportFailureKind::Connect,
            Self::Tls => HttpsTransportFailureKind::Tls,
            Self::Timeout => HttpsTransportFailureKind::Timeout,
        };
        pre_send(kind)
    }
}

const fn pre_send(kind: HttpsTransportFailureKind) -> HttpsTransportFailure {
    HttpsTransportFailure::new(kind, HttpsRequestProgress::NotSent)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WireFailure {
    Timeout,
    Protocol,
    ResponseTooLarge,
}

impl WireFailure {
    const fn into_transport_failure(self) -> HttpsTransportFailure {
        let kind = match self {
            Self::Timeout => HttpsTransportFailureKind::Timeout,
            Self::Protocol => HttpsTransportFailureKind::Protocol,
            Self::ResponseTooLarge => HttpsTransportFailureKind::ResponseTooLarge,
        };
        HttpsTransportFailure::new(kind, HttpsRequestProgress::MayHaveBeenSent)
    }
}

fn map_pre_send_io(error: &io::Error) -> PreSendFailure {
    if is_timeout(error) {
        PreSendFailure::Timeout
    } else {
        PreSendFailure::Connect
    }
}

fn map_wire_io(error: &io::Error) -> WireFailure {
    if is_timeout(error) {
        WireFailure::Timeout
    } else {
        WireFailure::Protocol
    }
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

fn apply_socket_deadline(socket: &TcpStream, deadline: Deadline) -> io::Result<()> {
    let remaining = deadline
        .remaining()
        .map_err(|()| io::Error::new(io::ErrorKind::TimedOut, "request deadline expired"))?;
    socket.set_read_timeout(Some(remaining))?;
    socket.set_write_timeout(Some(remaining))
}

trait TimedIo: Read + Write {
    fn apply_deadline(&mut self, deadline: Deadline) -> io::Result<()>;
}

impl TimedIo for StreamOwned<ClientConnection, TcpStream> {
    fn apply_deadline(&mut self, deadline: Deadline) -> io::Result<()> {
        apply_socket_deadline(&self.sock, deadline)
    }
}

fn exchange_http<T: TimedIo>(
    stream: &mut T,
    request: &[u8],
    deadline: Deadline,
    max_response_body_bytes: usize,
) -> Result<OutboundHttpsResponse, WireFailure> {
    write_all_deadline(stream, request, deadline)?;
    stream
        .apply_deadline(deadline)
        .map_err(|error| map_wire_io(&error))?;
    stream.flush().map_err(|error| map_wire_io(&error))?;
    let mut reader = DeadlineReader { stream, deadline };
    let response = read_http_response(
        &mut reader,
        ResponseLimits {
            max_header_bytes: MAX_RESPONSE_HEADER_BYTES,
            max_body_bytes: max_response_body_bytes,
        },
    )?;
    OutboundHttpsResponse::new(response.status, response.retry_after, response.body)
        .map_err(|_| WireFailure::Protocol)
}

fn write_all_deadline<T: TimedIo>(
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

struct DeadlineReader<'a, T> {
    stream: &'a mut T,
    deadline: Deadline,
}

impl<T> fmt::Debug for DeadlineReader<'_, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeadlineReader")
            .finish_non_exhaustive()
    }
}

impl<T: TimedIo> Read for DeadlineReader<'_, T> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.apply_deadline(self.deadline)?;
        self.stream.read(buffer)
    }
}

fn resolve_public_addresses(
    authority: &'static str,
    deadline: Deadline,
) -> Result<Vec<SocketAddr>, PreSendFailure> {
    acquire_dns_slot()?;
    let (sender, receiver) = mpsc::sync_channel(1);
    let spawn = thread::Builder::new()
        .name("accordlock-public-dns".to_owned())
        .spawn(move || {
            let _slot = DnsSlot;
            let result = resolve_now(authority);
            let _ = sender.send(result);
        });
    if spawn.is_err() {
        ACTIVE_DNS_LOOKUPS.fetch_sub(1, Ordering::AcqRel);
        return Err(PreSendFailure::NameResolution);
    }
    let remaining = deadline.remaining().map_err(|()| PreSendFailure::Timeout)?;
    match receiver.recv_timeout(remaining) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(PreSendFailure::Timeout),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(PreSendFailure::NameResolution),
    }
}

fn acquire_dns_slot() -> Result<(), PreSendFailure> {
    ACTIVE_DNS_LOOKUPS
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
            (active < MAX_ACTIVE_DNS_LOOKUPS).then_some(active + 1)
        })
        .map(|_| ())
        .map_err(|_| PreSendFailure::NameResolution)
}

struct DnsSlot;

impl Drop for DnsSlot {
    fn drop(&mut self) {
        ACTIVE_DNS_LOOKUPS.fetch_sub(1, Ordering::AcqRel);
    }
}

fn resolve_now(authority: &'static str) -> Result<Vec<SocketAddr>, PreSendFailure> {
    let resolved = (authority, HTTPS_PORT)
        .to_socket_addrs()
        .map_err(|_| PreSendFailure::NameResolution)?;
    let mut addresses = BTreeSet::new();
    for address in resolved {
        if addresses.len() >= MAX_RESOLVED_ADDRESSES || !is_public_address(address.ip()) {
            return Err(PreSendFailure::NameResolution);
        }
        addresses.insert(address);
    }
    if addresses.is_empty() {
        return Err(PreSendFailure::NameResolution);
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
        || octets[..4] == [0x20, 0x01, 0x0d, 0xb8]
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
    retry_after: Option<String>,
    body: Vec<u8>,
}

fn read_http_response<R: Read>(
    reader: &mut R,
    limits: ResponseLimits,
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

    let head = parse_response_head(&received[..header_end])?;
    let initial_body = received.split_off(header_end);
    let body = match head.framing {
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
        retry_after: head.retry_after,
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
    retry_after: Option<String>,
    framing: BodyFraming,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BodyFraming {
    ContentLength(usize),
    Chunked,
}

fn parse_response_head(bytes: &[u8]) -> Result<ParsedResponseHead, WireFailure> {
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
    let mut retry_after = None;
    let mut trailer_declared = false;
    for header in response.headers {
        if !valid_response_header(header.name.as_bytes(), header.value) {
            return Err(WireFailure::Protocol);
        }
        if header.name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(WireFailure::Protocol);
            }
            content_length = Some(parse_content_length(header.value)?);
        } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
            if transfer_encoding.is_some() {
                return Err(WireFailure::Protocol);
            }
            transfer_encoding = Some(header.value);
        } else if header.name.eq_ignore_ascii_case("content-encoding") {
            if content_encoding.is_some() {
                return Err(WireFailure::Protocol);
            }
            content_encoding = Some(header.value);
        } else if header.name.eq_ignore_ascii_case("retry-after") {
            if retry_after.is_some() || header.value.is_empty() || header.value.len() > 64 {
                return Err(WireFailure::Protocol);
            }
            retry_after = Some(
                std::str::from_utf8(header.value)
                    .map_err(|_| WireFailure::Protocol)?
                    .to_owned(),
            );
        } else if header.name.eq_ignore_ascii_case("trailer") {
            trailer_declared = true;
        }
    }
    if content_encoding.is_some_and(|value| !value.eq_ignore_ascii_case(b"identity")) {
        return Err(WireFailure::Protocol);
    }
    let framing = match (content_length, transfer_encoding) {
        (Some(length), None) => BodyFraming::ContentLength(length),
        (None, Some(value)) if !trailer_declared && value.eq_ignore_ascii_case(b"chunked") => {
            BodyFraming::Chunked
        }
        _ => return Err(WireFailure::Protocol),
    };
    Ok(ParsedResponseHead {
        status,
        retry_after,
        framing,
    })
}

fn valid_response_header(name: &[u8], value: &[u8]) -> bool {
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
    if length > maximum || initial.len() > length {
        return Err(WireFailure::ResponseTooLarge);
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
    use std::io::Cursor;

    use super::*;

    #[derive(Debug)]
    struct ScriptedIo {
        response: Cursor<Vec<u8>>,
        request: Vec<u8>,
        write_error: Option<io::ErrorKind>,
        deadline_error: Option<io::ErrorKind>,
    }

    impl ScriptedIo {
        fn response(bytes: &[u8]) -> Self {
            Self {
                response: Cursor::new(bytes.to_vec()),
                request: Vec::new(),
                write_error: None,
                deadline_error: None,
            }
        }
    }

    impl Read for ScriptedIo {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.response.read(buffer)
        }
    }

    impl Write for ScriptedIo {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if let Some(kind) = self.write_error.take() {
                return Err(io::Error::new(kind, "scripted write failure"));
            }
            self.request.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl TimedIo for ScriptedIo {
        fn apply_deadline(&mut self, _deadline: Deadline) -> io::Result<()> {
            if let Some(kind) = self.deadline_error.take() {
                return Err(io::Error::new(kind, "scripted deadline failure"));
            }
            Ok(())
        }
    }

    fn deadline() -> Deadline {
        Deadline::new(Duration::from_secs(2))
    }

    #[test]
    fn endpoint_parser_accepts_only_the_channel_authority() {
        let slack = parse_endpoint(
            ApprovalChannel::Slack,
            "https://slack.com/api/chat.postMessage",
        )
        .unwrap_or_else(|()| unreachable!());
        assert_eq!(slack.authority, SLACK_AUTHORITY);
        assert_eq!(slack.path, "/api/chat.postMessage");

        assert!(
            parse_endpoint(
                ApprovalChannel::Slack,
                "https://api.telegram.org/api/chat.postMessage"
            )
            .is_err()
        );
        assert!(
            parse_endpoint(
                ApprovalChannel::Slack,
                "https://slack.com:443/api/chat.postMessage"
            )
            .is_err()
        );
        assert!(
            parse_endpoint(
                ApprovalChannel::Slack,
                "https://slack.com/api/chat.postMessage?redirect=true"
            )
            .is_err()
        );
        assert!(
            parse_endpoint(
                ApprovalChannel::Slack,
                "https://user@slack.com/api/chat.postMessage"
            )
            .is_err()
        );
    }

    #[test]
    fn request_encoder_uses_origin_form_and_fixed_connection_close() {
        let encoded = encode_http_request(
            "/api/chat.postMessage",
            SLACK_AUTHORITY,
            [
                ("accept", "application/json"),
                ("authorization", "Bearer test-secret-value"),
            ]
            .into_iter(),
            br#"{"ok":true}"#,
        )
        .unwrap_or_else(|()| unreachable!());
        assert_eq!(
            encoded.as_slice(),
            b"POST /api/chat.postMessage HTTP/1.1\r\nHost: slack.com\r\naccept: application/json\r\nauthorization: Bearer test-secret-value\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}"
        );
        assert!(
            encode_http_request(
                "/api/chat.postMessage",
                SLACK_AUTHORITY,
                [("host", "attacker.invalid")].into_iter(),
                b"{}"
            )
            .is_err()
        );
        assert!(
            encode_http_request(
                "/api/chat.postMessage",
                SLACK_AUTHORITY,
                [("authorization", "Bearer safe\r\nX-Evil: yes")].into_iter(),
                b"{}"
            )
            .is_err()
        );
    }

    #[test]
    fn in_memory_exchange_sends_once_and_collects_a_bounded_response() {
        let body = br#"{"ok":true,"ts":"1"}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nRetry-After: 7\r\n\r\n{}",
            body.len(),
            std::str::from_utf8(body).unwrap_or_else(|_| unreachable!())
        );
        let mut io = ScriptedIo::response(response.as_bytes());
        let received = exchange_http(&mut io, b"request", deadline(), 1_024)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(io.request, b"request");
        assert_eq!(received.status_code(), 200);
        assert_eq!(received.body(), body);
    }

    #[test]
    fn chunked_response_is_decoded_without_accepting_trailers() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let parsed = read_http_response(
            &mut Cursor::new(response),
            ResponseLimits {
                max_header_bytes: 1_024,
                max_body_bytes: 11,
            },
        )
        .unwrap_or_else(|_| unreachable!());
        assert_eq!(parsed.body, b"hello world");

        let with_trailer = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Test\r\n\r\n0\r\nX-Test: value\r\n\r\n";
        assert_eq!(
            read_http_response(
                &mut Cursor::new(with_trailer),
                ResponseLimits {
                    max_header_bytes: 1_024,
                    max_body_bytes: 32,
                }
            ),
            Err(WireFailure::Protocol)
        );
    }

    #[test]
    fn response_size_and_framing_fail_closed() {
        let oversized = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(
            read_http_response(
                &mut Cursor::new(oversized),
                ResponseLimits {
                    max_header_bytes: 1_024,
                    max_body_bytes: 4,
                }
            ),
            Err(WireFailure::ResponseTooLarge)
        );

        let duplicate = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            read_http_response(
                &mut Cursor::new(duplicate),
                ResponseLimits {
                    max_header_bytes: 1_024,
                    max_body_bytes: 4,
                }
            ),
            Err(WireFailure::Protocol)
        );

        let compressed = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            read_http_response(
                &mut Cursor::new(compressed),
                ResponseLimits {
                    max_header_bytes: 1_024,
                    max_body_bytes: 4,
                }
            ),
            Err(WireFailure::Protocol)
        );
    }

    #[test]
    fn failures_after_the_write_boundary_are_never_reported_not_sent() {
        let mut io = ScriptedIo::response(b"");
        io.write_error = Some(io::ErrorKind::ConnectionReset);
        assert_eq!(
            exchange_http(&mut io, b"request", deadline(), 1_024).map(|_| ()),
            Err(WireFailure::Protocol)
        );
        let failure = WireFailure::Protocol.into_transport_failure();
        assert_eq!(failure.progress(), HttpsRequestProgress::MayHaveBeenSent);
        assert_eq!(failure.kind(), HttpsTransportFailureKind::Protocol);

        let before = PreSendFailure::Tls.into_transport_failure();
        assert_eq!(before.progress(), HttpsRequestProgress::NotSent);
        assert_eq!(before.kind(), HttpsTransportFailureKind::Tls);
    }

    #[test]
    fn timeout_classification_preserves_the_send_boundary() {
        let mut io = ScriptedIo::response(b"");
        io.deadline_error = Some(io::ErrorKind::TimedOut);
        assert_eq!(
            exchange_http(&mut io, b"request", deadline(), 1_024).map(|_| ()),
            Err(WireFailure::Timeout)
        );
        let failure = WireFailure::Timeout.into_transport_failure();
        assert_eq!(failure.progress(), HttpsRequestProgress::MayHaveBeenSent);
        assert_eq!(failure.kind(), HttpsTransportFailureKind::Timeout);

        let before = PreSendFailure::Timeout.into_transport_failure();
        assert_eq!(before.progress(), HttpsRequestProgress::NotSent);
        assert_eq!(before.kind(), HttpsTransportFailureKind::Timeout);
    }

    #[test]
    fn resolver_rejects_non_public_destinations() {
        assert!(!is_public_address(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!is_public_address(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(!is_public_address(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(!is_public_address(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!is_public_address(IpAddr::V6(Ipv6Addr::new(
            0xfc00, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(is_public_address(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(is_public_address(IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111
        ))));
    }

    #[test]
    fn public_client_debug_has_no_configuration_or_secret_surface() {
        let client = WebPkiHttpsTransport::new().unwrap_or_else(|_| unreachable!());
        assert_eq!(format!("{client:?}"), "WebPkiHttpsTransport { .. }");
    }
}
