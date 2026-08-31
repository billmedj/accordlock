use std::{collections::BTreeSet, fmt};

use accordlock_connectors::SourceReadError;
use accordlock_protocol::Digest32;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub const PROVIDER_ADAPTER_SCHEMA_VERSION: u16 = 1;
pub const MAX_PROVIDER_RESPONSE_BYTES: usize = 256 * 1024;
pub const MIN_PROVIDER_RESPONSE_BYTES: usize = 2;
const MAX_AUTHORITY_BYTES: usize = 253;
const MAX_BASE_PATH_BYTES: usize = 128;
const MAX_ROUTE_SEGMENT_BYTES: usize = 128;
const MAX_PUBLIC_IDENTITY_BYTES: usize = 512;
const TRANSPORT_IDENTITY_DOMAIN: &[u8] = b"accordlock:v1:authenticated-transport-identity";

/// Public, credential-free identity of an authenticated transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedTransportIdentity {
    implementation_id: String,
    principal_id: String,
    credential_source_id: String,
    trust_anchor_hash: Digest32,
}

impl AuthenticatedTransportIdentity {
    /// Creates one bounded public transport identity.
    ///
    /// # Errors
    ///
    /// Rejects empty, noncanonical identity fields and an empty trust-anchor
    /// commitment.
    pub fn new(
        implementation_id: impl Into<String>,
        principal_id: impl Into<String>,
        credential_source_id: impl Into<String>,
        trust_anchor_hash: Digest32,
    ) -> Result<Self, AdapterConfigError> {
        let implementation_id = implementation_id.into();
        let principal_id = principal_id.into();
        let credential_source_id = credential_source_id.into();
        for (value, label) in [
            (&implementation_id, "transport implementation identity"),
            (&principal_id, "transport principal identity"),
            (
                &credential_source_id,
                "transport credential-source identity",
            ),
        ] {
            validate_public_identity(value, label)?;
        }
        if trust_anchor_hash == Digest32::from_bytes([0; 32]) {
            return Err(AdapterConfigError::Invalid("transport trust anchor"));
        }
        Ok(Self {
            implementation_id,
            principal_id,
            credential_source_id,
            trust_anchor_hash,
        })
    }

    /// Returns the canonical domain-separated public identity commitment.
    #[must_use]
    pub fn digest(&self) -> Digest32 {
        let mut hash = Sha256::new();
        commit_bytes(&mut hash, TRANSPORT_IDENTITY_DOMAIN);
        commit_bytes(&mut hash, self.implementation_id.as_bytes());
        commit_bytes(&mut hash, self.principal_id.as_bytes());
        commit_bytes(&mut hash, self.credential_source_id.as_bytes());
        hash.update(self.trust_anchor_hash.as_bytes());
        Digest32::from_bytes(hash.finalize().into())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReadMethod {
    Get,
    Post,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RedirectPolicy {
    Deny,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseMediaType {
    Json,
    Other,
}

/// An authenticated response whose body is always redacted from `Debug`.
pub struct AuthenticatedJsonResponse {
    status: u16,
    media_type: ResponseMediaType,
    body: Vec<u8>,
}

impl AuthenticatedJsonResponse {
    #[must_use]
    pub fn new(status: u16, media_type: ResponseMediaType, body: Vec<u8>) -> Self {
        Self {
            status,
            media_type,
            body,
        }
    }

    pub(crate) fn body_for(self, maximum_bytes: usize) -> Result<Vec<u8>, ProviderResponseError> {
        if self.status != 200 {
            return Err(ProviderResponseError::Status);
        }
        if self.media_type != ResponseMediaType::Json {
            return Err(ProviderResponseError::MediaType);
        }
        if !(MIN_PROVIDER_RESPONSE_BYTES..=maximum_bytes).contains(&self.body.len()) {
            return Err(ProviderResponseError::Size);
        }
        Ok(self.body)
    }
}

impl fmt::Debug for AuthenticatedJsonResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedJsonResponse")
            .field("status", &self.status)
            .field("media_type", &self.media_type)
            .field(
                "body",
                &format_args!("<redacted:{} bytes>", self.body.len()),
            )
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum TransportFailure {
    #[error("authenticated provider transport unavailable")]
    Unavailable,
    #[error("authenticated provider transport timed out")]
    Timeout,
    #[error("authenticated provider identity was rejected")]
    Authentication,
    #[error("authenticated provider response was not integrity protected")]
    Integrity,
    #[error("authenticated provider route was rejected")]
    Route,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AdapterConfigError {
    #[error("invalid provider adapter configuration: {0}")]
    Invalid(&'static str),
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(crate) enum ProviderResponseError {
    #[error("unexpected status")]
    Status,
    #[error("unexpected media type")]
    MediaType,
    #[error("response size outside configured bounds")]
    Size,
    #[error("malformed strict JSON")]
    Json,
    #[error("provider response binding mismatch")]
    Binding,
}

/// Fixed HTTPS authority and optional path prefix. User-info, schemes,
/// fragments and query strings are unrepresentable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpsEndpoint {
    authority: String,
    base_path: String,
}

impl HttpsEndpoint {
    /// Creates a fixed HTTPS endpoint.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical authorities and base paths.
    pub fn new(
        authority: impl Into<String>,
        base_path: impl Into<String>,
    ) -> Result<Self, AdapterConfigError> {
        let authority = authority.into();
        let base_path = base_path.into();
        validate_authority(&authority)?;
        validate_base_path(&base_path)?;
        Ok(Self {
            authority,
            base_path,
        })
    }

    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    #[must_use]
    pub fn base_path(&self) -> &str {
        &self.base_path
    }

    /// Returns the canonical HTTPS source prefix, always ending in `/`.
    #[must_use]
    pub fn source_uri_prefix(&self) -> String {
        if self.base_path == "/" {
            format!("https://{}/", self.authority)
        } else {
            format!("https://{}{}/", self.authority, self.base_path)
        }
    }

    pub(crate) fn path(&self, suffix: &str) -> Result<String, AdapterConfigError> {
        if !suffix.starts_with('/')
            || suffix.contains(['?', '#'])
            || suffix.chars().any(char::is_control)
        {
            return Err(AdapterConfigError::Invalid("route suffix"));
        }
        let mut value = self.base_path.clone();
        if value == "/" {
            value.clear();
        }
        value.push_str(suffix);
        if value.len() > 2_048 {
            return Err(AdapterConfigError::Invalid("route length"));
        }
        Ok(value)
    }

    pub(crate) fn source_uri(&self, path: &str) -> String {
        format!("https://{}{path}", self.authority)
    }
}

pub(crate) fn provider_identity_commitment(domain: &[u8], fields: &[&[u8]]) -> Digest32 {
    let mut hash = Sha256::new();
    commit_bytes(&mut hash, domain);
    for field in fields {
        commit_bytes(&mut hash, field);
    }
    Digest32::from_bytes(hash.finalize().into())
}

fn commit_bytes(hash: &mut Sha256, value: &[u8]) {
    hash.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hash.update(value);
}

fn validate_public_identity(value: &str, label: &'static str) -> Result<(), AdapterConfigError> {
    if value.is_empty()
        || value.len() > MAX_PUBLIC_IDENTITY_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(AdapterConfigError::Invalid(label));
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub(crate) struct ReadFailures {
    pub invalid_lookup: SourceReadError,
    pub transport: SourceReadError,
    pub invalid_response: SourceReadError,
}

impl ReadFailures {
    pub fn new() -> Result<Self, AdapterConfigError> {
        Ok(Self {
            invalid_lookup: make_read_error("invalid_provider_lookup")?,
            transport: make_read_error("provider_transport_failure")?,
            invalid_response: make_read_error("invalid_provider_response")?,
        })
    }
}

fn make_read_error(code: &'static str) -> Result<SourceReadError, AdapterConfigError> {
    SourceReadError::new(code).map_err(|_| AdapterConfigError::Invalid("source error code"))
}

pub(crate) fn validate_maximum_response_bytes(value: usize) -> Result<(), AdapterConfigError> {
    if !(MIN_PROVIDER_RESPONSE_BYTES..=MAX_PROVIDER_RESPONSE_BYTES).contains(&value) {
        return Err(AdapterConfigError::Invalid("maximum response bytes"));
    }
    Ok(())
}

pub(crate) fn validate_route_segment(
    value: &str,
    label: &'static str,
) -> Result<(), AdapterConfigError> {
    if value.is_empty()
        || value.len() > MAX_ROUTE_SEGMENT_BYTES
        || value.trim() != value
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || value == "."
        || value == ".."
    {
        return Err(AdapterConfigError::Invalid(label));
    }
    Ok(())
}

pub(crate) fn validate_commit_sha(value: &str) -> Result<(), ProviderResponseError> {
    if (value.len() == 40 || value.len() == 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ProviderResponseError::Binding)
    }
}

pub(crate) fn validate_positive_meta(
    request_id: Uuid,
    evidence_id: Uuid,
    observed_at: i64,
    source_sequence: u64,
) -> Result<(), ProviderResponseError> {
    if request_id.is_nil() || evidence_id.is_nil() || observed_at < 0 || source_sequence == 0 {
        return Err(ProviderResponseError::Binding);
    }
    Ok(())
}

pub(crate) fn parse_strict_json<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
) -> Result<T, ProviderResponseError> {
    let _: DuplicateRejectingJson =
        serde_json::from_slice(bytes).map_err(|_| ProviderResponseError::Json)?;
    serde_json::from_slice(bytes).map_err(|_| ProviderResponseError::Json)
}

pub(crate) fn split_lookup<'a>(
    value: &'a str,
    prefix: &[&str],
    tail_length: usize,
) -> Result<(Uuid, Vec<&'a str>), ProviderResponseError> {
    let parts = value.split('/').collect::<Vec<_>>();
    if parts.len() != prefix.len() + 1 + tail_length
        || !parts.iter().all(|part| !part.is_empty())
        || !parts
            .iter()
            .take(prefix.len())
            .zip(prefix)
            .all(|(actual, expected)| actual == expected)
    {
        return Err(ProviderResponseError::Binding);
    }
    let request_id =
        Uuid::parse_str(parts[prefix.len()]).map_err(|_| ProviderResponseError::Binding)?;
    if request_id.is_nil() || request_id.to_string() != parts[prefix.len()] {
        return Err(ProviderResponseError::Binding);
    }
    Ok((request_id, parts[prefix.len() + 1..].to_vec()))
}

fn validate_authority(value: &str) -> Result<(), AdapterConfigError> {
    if value.is_empty()
        || value.len() > MAX_AUTHORITY_BYTES
        || value != value.to_ascii_lowercase()
        || value.contains(['/', '@', '?', '#'])
        || value.starts_with('.')
        || value.ends_with('.')
        || value.split('.').any(|label| {
            label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(AdapterConfigError::Invalid("HTTPS authority"));
    }
    Ok(())
}

fn validate_base_path(value: &str) -> Result<(), AdapterConfigError> {
    if value.is_empty()
        || value.len() > MAX_BASE_PATH_BYTES
        || !value.starts_with('/')
        || (value.len() > 1 && value.ends_with('/'))
        || value.contains(['?', '#'])
        || value.chars().any(char::is_control)
        || value
            .split('/')
            .any(|segment| segment == "." || segment == "..")
    {
        return Err(AdapterConfigError::Invalid("HTTPS base path"));
    }
    Ok(())
}

#[derive(Debug)]
struct DuplicateRejectingJson;

impl<'de> Deserialize<'de> for DuplicateRejectingJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateRejectingVisitor)
    }
}

struct DuplicateRejectingVisitor;

impl<'de> Visitor<'de> for DuplicateRejectingVisitor {
    type Value = DuplicateRejectingJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJson)
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJson)
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJson)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJson)
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJson)
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJson)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJson)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJson)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        DuplicateRejectingJson::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<DuplicateRejectingJson>()?.is_some() {}
        Ok(DuplicateRejectingJson)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            let _: DuplicateRejectingJson = map.next_value()?;
        }
        Ok(DuplicateRejectingJson)
    }
}
