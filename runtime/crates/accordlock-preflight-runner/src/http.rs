use std::{
    fmt,
    io::{Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs as _},
    sync::Arc,
    time::Duration,
};

use accordlock_protocol::Digest32;
use accordlock_provider_adapters::TransportFailure;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
    client::Resumption,
    pki_types::{CertificateDer, ServerName, TrustAnchor},
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

const HTTP_11_ALPN: &[u8] = b"http/1.1";
const MAX_HEADER_BYTES: usize = 32 * 1024;
const MAX_HEADERS: usize = 64;
const MAX_PATH_BYTES: usize = 4 * 1024;
const MAX_HEADER_VALUE_BYTES: usize = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_PUBLIC_ROOTS: usize = 4_096;
const MAX_TRUST_ANCHOR_FIELD_BYTES: usize = 128 * 1024;
const PUBLIC_ROOT_CORPUS_DOMAIN: &[u8] = b"accordlock:v1:webpki-root-corpus\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
}

impl HttpMethod {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

#[derive(Clone)]
pub struct FixedHttpsClient {
    authority: String,
    socket_override: Option<SocketAddr>,
    tls: Arc<ClientConfig>,
    trust_anchor_hash: Digest32,
}

impl fmt::Debug for FixedHttpsClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixedHttpsClient")
            .field("authority", &self.authority)
            .field("socket_override", &self.socket_override)
            .field("trust_anchor_hash", &self.trust_anchor_hash)
            .finish_non_exhaustive()
    }
}

impl FixedHttpsClient {
    pub fn new(
        authority: impl Into<String>,
        socket_override: Option<SocketAddr>,
        ca_certificates_der: &[Vec<u8>],
    ) -> Result<Self, TransportFailure> {
        let authority = authority.into();
        if !valid_authority(&authority) || ca_certificates_der.len() > 16 {
            return Err(TransportFailure::Route);
        }
        let mut roots = RootCertStore::empty();
        let trust_anchor_hash = if ca_certificates_der.is_empty() {
            let public_roots = webpki_roots::TLS_SERVER_ROOTS;
            let commitment = public_root_corpus_hash(public_roots)?;
            roots.extend(public_roots.iter().cloned());
            commitment
        } else {
            let mut canonical = ca_certificates_der.to_vec();
            canonical.sort_unstable();
            canonical.dedup();
            if canonical.len() != ca_certificates_der.len()
                || canonical
                    .iter()
                    .any(|certificate| certificate.is_empty() || certificate.len() > 128 * 1024)
            {
                return Err(TransportFailure::Integrity);
            }
            let mut hash = Sha256::new();
            hash.update(b"accordlock:v1:preflight-ca-bundle\0");
            for certificate in &canonical {
                roots
                    .add(CertificateDer::from(certificate.clone()))
                    .map_err(|_| TransportFailure::Integrity)?;
                hash.update(
                    u64::try_from(certificate.len())
                        .unwrap_or(u64::MAX)
                        .to_be_bytes(),
                );
                hash.update(certificate);
            }
            Digest32::from_bytes(hash.finalize().into())
        };
        if roots.is_empty() {
            return Err(TransportFailure::Integrity);
        }

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let builder = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| TransportFailure::Integrity)?;
        let mut tls = builder.with_root_certificates(roots).with_no_client_auth();
        tls.alpn_protocols = vec![HTTP_11_ALPN.to_vec()];
        tls.enable_sni = true;
        tls.enable_early_data = false;
        tls.resumption = Resumption::disabled();
        Ok(Self {
            authority,
            socket_override,
            tls: Arc::new(tls),
            trust_anchor_hash,
        })
    }

    #[must_use]
    pub const fn trust_anchor_hash(&self) -> Digest32 {
        self.trust_anchor_hash
    }

    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    pub fn send_json(
        &self,
        method: HttpMethod,
        path: &str,
        headers: &[(&str, String)],
        body: &[u8],
        maximum_response_bytes: usize,
    ) -> Result<HttpResponse, TransportFailure> {
        validate_request(path, headers, body, maximum_response_bytes)?;
        let socket_target = self.resolve_target()?;
        let mut socket =
            TcpStream::connect_timeout(&socket_target, CONNECT_TIMEOUT).map_err(map_io_failure)?;
        socket.set_nodelay(true).map_err(map_io_failure)?;
        socket
            .set_read_timeout(Some(OPERATION_TIMEOUT))
            .map_err(map_io_failure)?;
        socket
            .set_write_timeout(Some(OPERATION_TIMEOUT))
            .map_err(map_io_failure)?;
        if socket.peer_addr().map_err(map_io_failure)? != socket_target {
            return Err(TransportFailure::Route);
        }
        let server_name =
            ServerName::try_from(self.authority.clone()).map_err(|_| TransportFailure::Route)?;
        let mut connection = ClientConnection::new(Arc::clone(&self.tls), server_name)
            .map_err(|_| TransportFailure::Integrity)?;
        while connection.is_handshaking() {
            let (read, written) = connection
                .complete_io(&mut socket)
                .map_err(|_| TransportFailure::Authentication)?;
            if connection.is_handshaking() && read == 0 && written == 0 {
                return Err(TransportFailure::Authentication);
            }
        }
        if connection.alpn_protocol() != Some(HTTP_11_ALPN) {
            return Err(TransportFailure::Integrity);
        }

        let mut stream = StreamOwned::new(connection, socket);
        let mut request = Zeroizing::new(Vec::with_capacity(512 + body.len()));
        request.extend_from_slice(method.as_str().as_bytes());
        request.extend_from_slice(b" ");
        request.extend_from_slice(path.as_bytes());
        request.extend_from_slice(b" HTTP/1.1\r\nHost: ");
        request.extend_from_slice(self.authority.as_bytes());
        request.extend_from_slice(b"\r\nAccept: application/json\r\nConnection: close\r\n");
        for (name, value) in headers {
            request.extend_from_slice(name.as_bytes());
            request.extend_from_slice(b": ");
            request.extend_from_slice(value.as_bytes());
            request.extend_from_slice(b"\r\n");
        }
        request.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        request.extend_from_slice(body);
        stream.write_all(&request).map_err(map_io_failure)?;
        stream.flush().map_err(map_io_failure)?;
        read_response(&mut stream, maximum_response_bytes)
    }

    fn resolve_target(&self) -> Result<SocketAddr, TransportFailure> {
        if let Some(value) = self.socket_override {
            return Ok(value);
        }
        (self.authority.as_str(), 443)
            .to_socket_addrs()
            .map_err(|_| TransportFailure::Unavailable)?
            .next()
            .ok_or(TransportFailure::Unavailable)
    }
}

/// Commits to the exact trust-anchor material consumed by rustls.
///
/// A dependency version is not a trust-root identity: the same version label
/// can resolve to different locked data over the lifetime of a distribution.
/// This representation binds every field used by rustls. Entries are sorted
/// before hashing because a root store is a set; duplicate entries are
/// rejected so that the set has exactly one canonical representation.
fn public_root_corpus_hash(anchors: &[TrustAnchor<'_>]) -> Result<Digest32, TransportFailure> {
    if anchors.is_empty() || anchors.len() > MAX_PUBLIC_ROOTS {
        return Err(TransportFailure::Integrity);
    }

    let mut canonical = anchors
        .iter()
        .map(canonical_trust_anchor)
        .collect::<Result<Vec<_>, _>>()?;
    canonical.sort_unstable();
    if canonical.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(TransportFailure::Integrity);
    }

    let mut hash = Sha256::new();
    hash.update(PUBLIC_ROOT_CORPUS_DOMAIN);
    hash.update(
        u64::try_from(canonical.len())
            .map_err(|_| TransportFailure::Integrity)?
            .to_be_bytes(),
    );
    for anchor in canonical {
        update_length_prefixed(&mut hash, &anchor)?;
    }
    Ok(Digest32::from_bytes(hash.finalize().into()))
}

fn canonical_trust_anchor(anchor: &TrustAnchor<'_>) -> Result<Vec<u8>, TransportFailure> {
    let subject = anchor.subject.as_ref();
    let subject_public_key_info = anchor.subject_public_key_info.as_ref();
    if subject.is_empty()
        || subject.len() > MAX_TRUST_ANCHOR_FIELD_BYTES
        || subject_public_key_info.is_empty()
        || subject_public_key_info.len() > MAX_TRUST_ANCHOR_FIELD_BYTES
        || anchor
            .name_constraints
            .as_ref()
            .is_some_and(|value| value.as_ref().len() > MAX_TRUST_ANCHOR_FIELD_BYTES)
    {
        return Err(TransportFailure::Integrity);
    }

    let mut canonical = Vec::new();
    append_length_prefixed(&mut canonical, subject)?;
    append_length_prefixed(&mut canonical, subject_public_key_info)?;
    match &anchor.name_constraints {
        None => canonical.push(0),
        Some(value) => {
            canonical.push(1);
            append_length_prefixed(&mut canonical, value.as_ref())?;
        }
    }
    Ok(canonical)
}

fn append_length_prefixed(target: &mut Vec<u8>, value: &[u8]) -> Result<(), TransportFailure> {
    target.extend_from_slice(
        &u64::try_from(value.len())
            .map_err(|_| TransportFailure::Integrity)?
            .to_be_bytes(),
    );
    target.extend_from_slice(value);
    Ok(())
}

fn update_length_prefixed(hash: &mut Sha256, value: &[u8]) -> Result<(), TransportFailure> {
    hash.update(
        u64::try_from(value.len())
            .map_err(|_| TransportFailure::Integrity)?
            .to_be_bytes(),
    );
    hash.update(value);
    Ok(())
}

fn validate_request(
    path: &str,
    headers: &[(&str, String)],
    body: &[u8],
    maximum_response_bytes: usize,
) -> Result<(), TransportFailure> {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || !path.starts_with('/')
        || path.contains(['\r', '\n', ' ', '#'])
        || headers.len() > 32
        || body.len() > 1024 * 1024
        || !(2..=8 * 1024 * 1024).contains(&maximum_response_bytes)
    {
        return Err(TransportFailure::Route);
    }
    for (name, value) in headers {
        if name.is_empty()
            || name.len() > 128
            || *name != name.to_ascii_lowercase()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
            || value.is_empty()
            || value.len() > MAX_HEADER_VALUE_BYTES
            || value.contains(['\r', '\n'])
        {
            return Err(TransportFailure::Route);
        }
    }
    Ok(())
}

fn read_response(
    stream: &mut impl Read,
    maximum_response_bytes: usize,
) -> Result<HttpResponse, TransportFailure> {
    let maximum_wire_bytes = MAX_HEADER_BYTES
        .checked_add(maximum_response_bytes.saturating_mul(2))
        .and_then(|value| value.checked_add(4_096))
        .ok_or(TransportFailure::Integrity)?;
    let mut wire = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = stream.read(&mut buffer).map_err(map_io_failure)?;
        if read == 0 {
            break;
        }
        if wire.len().saturating_add(read) > maximum_wire_bytes {
            return Err(TransportFailure::Integrity);
        }
        wire.extend_from_slice(&buffer[..read]);
    }
    let header_end = find_header_end(&wire).ok_or(TransportFailure::Integrity)?;
    if header_end > MAX_HEADER_BYTES {
        return Err(TransportFailure::Integrity);
    }
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut parsed = httparse::Response::new(&mut headers);
    let status = match parsed.parse(&wire[..header_end]) {
        Ok(httparse::Status::Complete(_)) => parsed.code.ok_or(TransportFailure::Integrity)?,
        _ => return Err(TransportFailure::Integrity),
    };
    if (300..400).contains(&status) {
        return Err(TransportFailure::Route);
    }
    let mut content_length = None;
    let mut chunked = false;
    let mut content_type = None;
    for header in parsed.headers.iter() {
        let name = header.name.to_ascii_lowercase();
        let value = std::str::from_utf8(header.value).map_err(|_| TransportFailure::Integrity)?;
        match name.as_str() {
            "content-length" => {
                if content_length.is_some() {
                    return Err(TransportFailure::Integrity);
                }
                content_length = Some(
                    value
                        .parse::<usize>()
                        .map_err(|_| TransportFailure::Integrity)?,
                );
            }
            "transfer-encoding" => {
                if value.trim().eq_ignore_ascii_case("chunked") {
                    chunked = true;
                } else {
                    return Err(TransportFailure::Integrity);
                }
            }
            "content-type" => {
                if content_type.is_some() || value.len() > 256 {
                    return Err(TransportFailure::Integrity);
                }
                content_type = Some(value.to_owned());
            }
            _ => {}
        }
    }
    if chunked && content_length.is_some() {
        return Err(TransportFailure::Integrity);
    }
    let raw_body = &wire[header_end..];
    let body = if chunked {
        decode_chunked(raw_body, maximum_response_bytes)?
    } else if let Some(expected) = content_length {
        if expected != raw_body.len() || expected > maximum_response_bytes {
            return Err(TransportFailure::Integrity);
        }
        raw_body.to_vec()
    } else {
        if raw_body.len() > maximum_response_bytes {
            return Err(TransportFailure::Integrity);
        }
        raw_body.to_vec()
    };
    Ok(HttpResponse {
        status,
        content_type,
        body,
    })
}

fn decode_chunked(input: &[u8], maximum: usize) -> Result<Vec<u8>, TransportFailure> {
    let mut cursor = 0;
    let mut output = Vec::new();
    loop {
        let relative = input[cursor..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or(TransportFailure::Integrity)?;
        if relative > 128 {
            return Err(TransportFailure::Integrity);
        }
        let line = std::str::from_utf8(&input[cursor..cursor + relative])
            .map_err(|_| TransportFailure::Integrity)?;
        if line.contains(';') || line.is_empty() {
            return Err(TransportFailure::Integrity);
        }
        let size = usize::from_str_radix(line, 16).map_err(|_| TransportFailure::Integrity)?;
        cursor = cursor
            .checked_add(relative + 2)
            .ok_or(TransportFailure::Integrity)?;
        if size == 0 {
            if input.get(cursor..cursor + 2) != Some(b"\r\n") || cursor + 2 != input.len() {
                return Err(TransportFailure::Integrity);
            }
            return Ok(output);
        }
        let end = cursor
            .checked_add(size)
            .ok_or(TransportFailure::Integrity)?;
        if end.saturating_add(2) > input.len()
            || input.get(end..end + 2) != Some(b"\r\n")
            || output.len().saturating_add(size) > maximum
        {
            return Err(TransportFailure::Integrity);
        }
        output.extend_from_slice(&input[cursor..end]);
        cursor = end + 2;
    }
}

fn find_header_end(input: &[u8]) -> Option<usize> {
    input
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

#[allow(clippy::needless_pass_by_value)]
fn map_io_failure(error: std::io::Error) -> TransportFailure {
    if matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) {
        TransportFailure::Timeout
    } else {
        TransportFailure::Unavailable
    }
}

fn valid_authority(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value == value.to_ascii_lowercase()
        && !value.contains(['/', '@', '?', '#', ':'])
        && value.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

#[cfg(test)]
mod root_corpus_tests {
    use std::fmt::Debug;

    use rustls::pki_types::TrustAnchor;

    use super::{Digest32, TransportFailure, public_root_corpus_hash};

    fn must<T, E: Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("test fixture failed: {error:?}"))
    }

    fn anchor(
        subject: &[u8],
        subject_public_key_info: &[u8],
        name_constraints: Option<&[u8]>,
    ) -> TrustAnchor<'static> {
        TrustAnchor {
            subject: subject.to_vec().into(),
            subject_public_key_info: subject_public_key_info.to_vec().into(),
            name_constraints: name_constraints.map(|value| value.to_vec().into()),
        }
    }

    #[test]
    fn public_root_commitment_changes_when_any_trust_material_changes() {
        let baseline = must(public_root_corpus_hash(&[anchor(
            b"subject-a",
            b"public-key-a",
            Some(b"constraints-a"),
        )]));
        let changed_subject = must(public_root_corpus_hash(&[anchor(
            b"subject-b",
            b"public-key-a",
            Some(b"constraints-a"),
        )]));
        let changed_key = must(public_root_corpus_hash(&[anchor(
            b"subject-a",
            b"public-key-b",
            Some(b"constraints-a"),
        )]));
        let changed_constraints = must(public_root_corpus_hash(&[anchor(
            b"subject-a",
            b"public-key-a",
            Some(b"constraints-b"),
        )]));

        assert_ne!(baseline, changed_subject);
        assert_ne!(baseline, changed_key);
        assert_ne!(baseline, changed_constraints);
    }

    #[test]
    fn public_root_commitment_has_one_canonical_order() {
        let first = anchor(b"subject-a", b"public-key-a", None);
        let second = anchor(b"subject-b", b"public-key-b", Some(b"constraints-b"));
        let forward = must(public_root_corpus_hash(&[first.clone(), second.clone()]));
        let reverse = must(public_root_corpus_hash(&[second, first]));

        assert_eq!(forward, reverse);
    }

    #[test]
    fn public_root_commitment_rejects_duplicate_or_empty_corpora() {
        let duplicate = anchor(b"subject-a", b"public-key-a", None);
        assert!(matches!(
            public_root_corpus_hash(&[duplicate.clone(), duplicate]),
            Err(TransportFailure::Integrity)
        ));
        assert!(matches!(
            public_root_corpus_hash(&[]),
            Err(TransportFailure::Integrity)
        ));
    }

    #[test]
    fn public_root_commitment_distinguishes_absent_constraints_from_present_bytes() {
        let absent = must(public_root_corpus_hash(&[anchor(
            b"subject-a",
            b"public-key-a",
            None,
        )]));
        let present = must(public_root_corpus_hash(&[anchor(
            b"subject-a",
            b"public-key-a",
            Some(b"constraints-a"),
        )]));
        assert_ne!(absent, present);
    }

    #[test]
    fn bundled_public_roots_are_not_identified_by_a_version_label() {
        let actual = must(public_root_corpus_hash(webpki_roots::TLS_SERVER_ROOTS));
        let legacy_label = Digest32::sha256(b"accordlock:webpki-roots:1.0");
        assert_ne!(actual, legacy_label);
    }
}
