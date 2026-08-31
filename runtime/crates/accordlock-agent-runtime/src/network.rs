use std::{
    collections::BTreeSet,
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use accordlock_agent_protocol::Digest32;
use axum::http::Uri;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    ActionApprovalRequest, ActionDescriptor, ActionType, Ledger, LedgerError,
    canonical::canonical_json_bytes,
    ledger::{AuthorizationGrant, AuthorizationResult, ObservationResult},
    model::{
        TOOL_EXECUTION_SCHEMA_VERSION, ToolCallProposal, ToolExecutionObservation,
        WireExecutionOutcome,
    },
};

#[path = "network_https.rs"]
mod native_https;

pub use native_https::{WebPkiHttpsEgress, WebPkiHttpsEgressBuildError};

pub const HTTPS_EXECUTE_PATH: &str = "/api/v2/execution/network/authorize-and-execute";

const MAX_URL_BYTES: usize = 4 * 1024;
const MAX_HEADER_COUNT: usize = 32;
const MAX_HEADER_VALUE_BYTES: usize = 4 * 1024;
const MAX_BODY_BYTES: usize = 256 * 1024;
const MAX_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_TIMEOUT_SECONDS: u32 = 2 * 60;
const DEFAULT_TIMEOUT_SECONDS: u32 = 30;
const DEFAULT_RESPONSE_BYTES: u32 = 64 * 1024;
const HTTPS_PRESTATE_DOMAIN: &[u8] = b"accordlock:v2:https-prestate";
const HTTPS_POLICY_DOMAIN: &[u8] = b"accordlock:v2:https-egress-policy";

const REQUEST_HEADER_ALLOWLIST: &[&str] = &[
    "accept",
    "content-type",
    "idempotency-key",
    "if-match",
    "if-none-match",
    "user-agent",
];

const RESPONSE_HEADER_ALLOWLIST: &[&str] = &[
    "content-length",
    "content-type",
    "date",
    "etag",
    "last-modified",
    "location",
    "x-request-id",
];

/// Closed HTTP method profile understood by the native broker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpsMethod {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
}

/// One bounded, lowercase HTTP header.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpsHeader {
    pub name: String,
    pub value: String,
}

/// Fully validated request handed to a trusted HTTPS adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpsEgressRequest {
    pub method: HttpsMethod,
    pub url: String,
    pub headers: Vec<HttpsHeader>,
    pub body: Option<String>,
    pub timeout_seconds: u32,
    pub max_response_bytes: usize,
}

/// Bounded adapter response. Redirects must never be followed by the adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpsEgressResponse {
    pub status: u16,
    pub headers: Vec<HttpsHeader>,
    pub body: String,
    pub redirected: bool,
}

/// Immutable outbound policy supplied by the trusted egress implementation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpsEgressPolicy {
    schema_version: u16,
    policy_id: String,
    allowed_domains: BTreeSet<String>,
    allowed_methods: BTreeSet<HttpsMethod>,
    max_request_body_bytes: usize,
    max_response_bytes: usize,
}

impl HttpsEgressPolicy {
    /// Creates an exact-domain, exact-method outbound policy.
    ///
    /// # Errors
    ///
    /// Rejects empty/excessive sets, IP literals, localhost-like names, and
    /// limits outside the compile-time hard ceiling.
    pub fn new(
        policy_id: impl Into<String>,
        allowed_domains: impl IntoIterator<Item = String>,
        allowed_methods: impl IntoIterator<Item = HttpsMethod>,
        max_request_body_bytes: usize,
        max_response_bytes: usize,
    ) -> Result<Self, HttpsPolicyError> {
        let policy = Self {
            schema_version: 2,
            policy_id: policy_id.into(),
            allowed_domains: allowed_domains.into_iter().collect(),
            allowed_methods: allowed_methods.into_iter().collect(),
            max_request_body_bytes,
            max_response_bytes,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub(crate) fn validate(&self) -> Result<(), HttpsPolicyError> {
        if self.schema_version != 2
            || self.policy_id.is_empty()
            || self.policy_id.len() > 128
            || self.policy_id.trim() != self.policy_id
            || self.policy_id.chars().any(char::is_control)
            || self.allowed_domains.is_empty()
            || self.allowed_domains.len() > 256
            || self.allowed_methods.is_empty()
            || self.max_request_body_bytes > MAX_BODY_BYTES
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(HttpsPolicyError::InvalidPolicy);
        }
        if self
            .allowed_domains
            .iter()
            .any(|domain| validate_domain(domain).is_err())
        {
            return Err(HttpsPolicyError::InvalidDomain);
        }
        Ok(())
    }

    fn authorizes(&self, request: &PreparedHttpsRequest) -> bool {
        self.allowed_domains.contains(&request.domain)
            && self.allowed_methods.contains(&request.method)
            && request.body.as_ref().map_or(0, String::len) <= self.max_request_body_bytes
            && request.max_response_bytes <= self.max_response_bytes
    }

    fn digest(&self) -> Result<Digest32, HttpsPolicyError> {
        self.validate()?;
        domain_digest(HTTPS_POLICY_DOMAIN, self).map_err(|()| HttpsPolicyError::InvalidPolicy)
    }
}

/// Integration seam for a TLS-verifying, redirects-disabled client.
///
/// Implementations are trusted to enforce certificate validation, the supplied
/// timeout and streaming response bound. [`WebPkiHttpsEgress`] is the direct
/// public-root implementation. The runtime still installs no transport by
/// default, so its optional network endpoint fails closed rather than
/// simulating network success.
pub trait HttpsEgress: fmt::Debug + Send + Sync {
    fn policy(&self) -> HttpsEgressPolicy;

    /// Executes one already validated request without following redirects.
    ///
    /// # Errors
    ///
    /// Returns a typed policy, TLS, redirect, wire-profile, size, or transport
    /// failure. Implementations must not turn ambiguous transport state into a
    /// successful response.
    fn execute(
        &self,
        request: &HttpsEgressRequest,
    ) -> Result<HttpsEgressResponse, HttpsEgressError>;
}

pub(crate) type SharedHttpsEgress = Arc<dyn HttpsEgress>;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum HttpsEgressError {
    #[error("HTTPS transport did not produce a trustworthy terminal response")]
    Transport,
    #[error("HTTPS certificate verification failed")]
    Tls,
    #[error("HTTPS adapter rejected the request policy")]
    Policy,
    #[error("HTTPS redirect was refused")]
    Redirect,
    #[error("HTTPS response was outside the strict wire profile")]
    InvalidResponse,
    #[error("HTTPS response exceeded its committed byte limit")]
    ResponseTooLarge,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HttpsExecutionRequest {
    pub schema_version: u16,
    pub proposal: ToolCallProposal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum HttpsExecutionStatus {
    Succeeded,
    ExecutionUnknown,
    Denied,
    ApprovalRequired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HttpsResult {
    pub status: u16,
    pub headers: Vec<HttpsHeader>,
    pub body: String,
    pub body_sha256: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HttpsExecutionResponse {
    pub schema_version: u16,
    pub proposal_digest: String,
    pub status: HttpsExecutionStatus,
    pub reason_code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<HttpsResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_request: Option<ActionApprovalRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_request_hash: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum RedirectPolicy {
    Deny,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpsArguments {
    method: HttpsMethod,
    url: String,
    #[serde(default)]
    headers: Vec<HttpsHeader>,
    body: Option<String>,
    #[serde(default = "default_timeout_seconds")]
    timeout_seconds: u32,
    #[serde(default = "default_response_bytes")]
    max_response_bytes: u32,
    redirect_policy: RedirectPolicy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PreparedHttpsRequest {
    method: HttpsMethod,
    url: String,
    domain: String,
    target: String,
    headers: Vec<HttpsHeader>,
    body: Option<String>,
    timeout_seconds: u32,
    max_response_bytes: usize,
}

impl PreparedHttpsRequest {
    fn from_proposal(proposal: &ToolCallProposal) -> Result<Self, HttpsInputError> {
        if proposal.extension_id != "accordlock_network" || proposal.tool_name != "https_request" {
            return Err(HttpsInputError::UnsupportedTool);
        }
        let arguments: HttpsArguments = serde_json::from_value(proposal.arguments.clone())
            .map_err(|_| HttpsInputError::InvalidArguments)?;
        if arguments.url.is_empty() || arguments.url.len() > MAX_URL_BYTES {
            return Err(HttpsInputError::InvalidUrl);
        }
        let uri = arguments
            .url
            .parse::<Uri>()
            .map_err(|_| HttpsInputError::InvalidUrl)?;
        if uri.scheme_str() != Some("https") {
            return Err(HttpsInputError::HttpsRequired);
        }
        let authority = uri.authority().ok_or(HttpsInputError::InvalidUrl)?;
        if authority.as_str().contains('@') || authority.port_u16().is_some_and(|port| port != 443)
        {
            return Err(HttpsInputError::InvalidUrl);
        }
        let domain = authority.host().to_owned();
        validate_domain(&domain).map_err(|_| HttpsInputError::InvalidDomain)?;
        if authority.as_str() != domain && authority.as_str() != format!("{domain}:443") {
            return Err(HttpsInputError::InvalidUrl);
        }
        let target = uri
            .path_and_query()
            .map_or("/", axum::http::uri::PathAndQuery::as_str)
            .to_owned();
        if target.is_empty()
            || target.len() > MAX_URL_BYTES
            || !target.starts_with('/')
            || target.contains('#')
            || target.chars().any(char::is_control)
        {
            return Err(HttpsInputError::InvalidUrl);
        }
        validate_headers(&arguments.headers, REQUEST_HEADER_ALLOWLIST)?;
        if arguments
            .body
            .as_ref()
            .is_some_and(|body| body.len() > MAX_BODY_BYTES)
        {
            return Err(HttpsInputError::BodyTooLarge);
        }
        if matches!(arguments.method, HttpsMethod::Get | HttpsMethod::Head)
            && arguments.body.is_some()
        {
            return Err(HttpsInputError::BodyForbidden);
        }
        if !(1..=MAX_TIMEOUT_SECONDS).contains(&arguments.timeout_seconds) {
            return Err(HttpsInputError::InvalidTimeout);
        }
        let maximum = usize::try_from(arguments.max_response_bytes)
            .map_err(|_| HttpsInputError::InvalidResponseLimit)?;
        if maximum == 0 || maximum > MAX_RESPONSE_BYTES {
            return Err(HttpsInputError::InvalidResponseLimit);
        }
        let RedirectPolicy::Deny = arguments.redirect_policy;
        Ok(Self {
            method: arguments.method,
            url: arguments.url,
            domain,
            target,
            headers: arguments.headers,
            body: arguments.body,
            timeout_seconds: arguments.timeout_seconds,
            max_response_bytes: maximum,
        })
    }

    fn request(&self) -> HttpsEgressRequest {
        HttpsEgressRequest {
            method: self.method,
            url: self.url.clone(),
            headers: self.headers.clone(),
            body: self.body.clone(),
            timeout_seconds: self.timeout_seconds,
            max_response_bytes: self.max_response_bytes,
        }
    }

    fn prestate(&self, policy: &HttpsEgressPolicy) -> Result<HttpsPrestate, HttpsToolError> {
        Ok(HttpsPrestate {
            schema_version: 2,
            policy_hash: policy.digest().map_err(|_| HttpsToolError::PolicyChanged)?,
            domain: self.domain.clone(),
            method: self.method,
            target: self.target.clone(),
        })
    }

    fn action(&self) -> ActionDescriptor {
        ActionDescriptor {
            extension_id: "accordlock_network".to_owned(),
            tool_name: "https_request".to_owned(),
            relative_path: format!("{}{}", self.domain, self.target),
            action_type: ActionType::HttpsRequest,
            requested_bytes: u64::try_from(self.body.as_ref().map_or(0, String::len))
                .unwrap_or(u64::MAX),
            executable_path: None,
            executable_sha256: None,
        }
    }

    fn execute(
        &self,
        egress: &dyn HttpsEgress,
        expected_prestate: Digest32,
    ) -> Result<HttpsResult, HttpsToolError> {
        let policy = egress.policy();
        policy
            .validate()
            .map_err(|_| HttpsToolError::PolicyChanged)?;
        if !policy.authorizes(self) || self.prestate(&policy)?.digest()? != expected_prestate {
            return Err(HttpsToolError::PolicyChanged);
        }
        let response = egress
            .execute(&self.request())
            .map_err(|error| match error {
                HttpsEgressError::Policy => HttpsToolError::PolicyChanged,
                HttpsEgressError::Redirect => HttpsToolError::RedirectBlocked,
                HttpsEgressError::InvalidResponse => HttpsToolError::InvalidResponse,
                HttpsEgressError::ResponseTooLarge => HttpsToolError::ResponseTooLarge,
                HttpsEgressError::Transport | HttpsEgressError::Tls => {
                    HttpsToolError::ExecutionUnknown
                }
            })?;
        if response.redirected || (300..=399).contains(&response.status) {
            return Err(HttpsToolError::RedirectBlocked);
        }
        if !(200..=599).contains(&response.status) {
            return Err(HttpsToolError::InvalidResponse);
        }
        validate_headers(&response.headers, RESPONSE_HEADER_ALLOWLIST)
            .map_err(|_| HttpsToolError::InvalidResponse)?;
        if response.body.len() > self.max_response_bytes {
            return Err(HttpsToolError::ResponseTooLarge);
        }
        Ok(HttpsResult {
            status: response.status,
            headers: response.headers,
            body_sha256: format!(
                "sha256:{}",
                hex::encode(Sha256::digest(response.body.as_bytes()))
            ),
            body: response.body,
        })
    }
}

pub(crate) fn execute_governed(
    ledger: &Ledger,
    request: &HttpsExecutionRequest,
    egress: Option<&dyn HttpsEgress>,
    now: i64,
    grant_lifetime_seconds: i64,
) -> Result<HttpsExecutionResponse, GovernedHttpsError> {
    if request.schema_version != TOOL_EXECUTION_SCHEMA_VERSION {
        return Err(GovernedHttpsError::Input);
    }
    request
        .proposal
        .validate()
        .map_err(|_| GovernedHttpsError::Input)?;
    let proposal_digest = request
        .proposal
        .digest()
        .map_err(|_| GovernedHttpsError::Input)?;
    let operation = PreparedHttpsRequest::from_proposal(&request.proposal)
        .map_err(|_| GovernedHttpsError::Input)?;
    let Some(egress) = egress else {
        return Ok(denied_response(
            proposal_digest,
            "NETWORK_EGRESS_NOT_CONFIGURED",
            None,
        ));
    };
    let policy = egress.policy();
    policy.validate().map_err(|_| GovernedHttpsError::Input)?;
    if !policy.authorizes(&operation) {
        return Ok(denied_response(
            proposal_digest,
            "NETWORK_POLICY_DENIED",
            None,
        ));
    }
    let prestate_hash = operation
        .prestate(&policy)
        .and_then(|state| state.digest())
        .map_err(|_| GovernedHttpsError::Input)?;
    let approval_request =
        ledger.action_approval_request(&request.proposal, prestate_hash, operation.action())?;
    let _execution_scope = ledger.begin_execution_scope()?;
    match ledger.authorize_and_consume(
        &request.proposal,
        approval_request.as_ref(),
        None,
        now,
        grant_lifetime_seconds,
    )? {
        AuthorizationResult::Denied(reason_code) => Ok(denied_response(
            proposal_digest,
            reason_code,
            if reason_code == "ACTION_APPROVAL_REQUIRED" {
                approval_request
            } else {
                None
            },
        )),
        AuthorizationResult::Allowed(grant) => execute_authorized(
            ledger,
            egress,
            &operation,
            proposal_digest,
            prestate_hash,
            &grant,
        ),
    }
}

fn execute_authorized(
    ledger: &Ledger,
    egress: &dyn HttpsEgress,
    operation: &PreparedHttpsRequest,
    proposal_digest: String,
    prestate_hash: Digest32,
    grant: &AuthorizationGrant,
) -> Result<HttpsExecutionResponse, GovernedHttpsError> {
    if grant.proposal_digest != proposal_digest {
        return Err(GovernedHttpsError::ExecutionStateUnknown);
    }
    let authorization_id = grant.authorization_id.to_string();
    let request_hash = grant.request_hash.to_string();
    match operation.execute(egress, prestate_hash) {
        Ok(result) => {
            let digest = crate::canonical::goose_digest(&result)
                .map_err(|_| GovernedHttpsError::ExecutionStateUnknown)?;
            let record = observe(
                ledger,
                &authorization_id,
                &proposal_digest,
                &request_hash,
                WireExecutionOutcome::Succeeded,
                Some(digest.clone()),
                completion_time()?,
            )?;
            Ok(success_response(
                proposal_digest,
                authorization_id,
                request_hash,
                record,
                digest,
                result,
            ))
        }
        Err(error) => {
            let reason_code = error.reason_code();
            let evidence_digest =
                crate::canonical::goose_digest(&serde_json::json!({"reason_code": reason_code}))
                    .map_err(|_| GovernedHttpsError::ExecutionStateUnknown)?;
            let record = observe(
                ledger,
                &authorization_id,
                &proposal_digest,
                &request_hash,
                WireExecutionOutcome::ToolReportedError,
                Some(evidence_digest),
                completion_time()?,
            )?;
            Ok(execution_state_unknown_response(
                proposal_digest,
                authorization_id,
                request_hash,
                record,
                reason_code,
            ))
        }
    }
}

fn observe(
    ledger: &Ledger,
    authorization_id: &str,
    proposal_digest: &str,
    request_hash: &str,
    outcome: WireExecutionOutcome,
    result_digest: Option<String>,
    now: i64,
) -> Result<ObservationResult, GovernedHttpsError> {
    ledger
        .observe(
            &ToolExecutionObservation {
                schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
                authorization_id: authorization_id.to_owned(),
                proposal_digest: proposal_digest.to_owned(),
                request_hash: request_hash.to_owned(),
                outcome,
                result_digest,
            },
            now,
        )
        .map_err(|_| GovernedHttpsError::ExecutionStateUnknown)
}

fn completion_time() -> Result<i64, GovernedHttpsError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| GovernedHttpsError::ExecutionStateUnknown)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| GovernedHttpsError::ExecutionStateUnknown)
}

fn success_response(
    proposal_digest: String,
    authorization_id: String,
    request_hash: String,
    record: ObservationResult,
    result_sha256: String,
    result: HttpsResult,
) -> HttpsExecutionResponse {
    HttpsExecutionResponse {
        schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
        proposal_digest,
        status: HttpsExecutionStatus::Succeeded,
        reason_code: "EXECUTED",
        authorization_id: Some(authorization_id),
        request_hash: Some(request_hash),
        record_id: Some(record.record_id.to_string()),
        record_hash: Some(record.record_hash),
        result_sha256: Some(result_sha256),
        result: Some(result),
        approval_request: None,
        approval_request_hash: None,
    }
}

fn execution_state_unknown_response(
    proposal_digest: String,
    authorization_id: String,
    request_hash: String,
    record: ObservationResult,
    reason_code: &'static str,
) -> HttpsExecutionResponse {
    HttpsExecutionResponse {
        schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
        proposal_digest,
        status: HttpsExecutionStatus::ExecutionUnknown,
        reason_code,
        authorization_id: Some(authorization_id),
        request_hash: Some(request_hash),
        record_id: Some(record.record_id.to_string()),
        record_hash: Some(record.record_hash),
        result_sha256: None,
        result: None,
        approval_request: None,
        approval_request_hash: None,
    }
}

fn denied_response(
    proposal_digest: String,
    reason_code: &'static str,
    approval_request: Option<ActionApprovalRequest>,
) -> HttpsExecutionResponse {
    let approval_request_hash = approval_request
        .as_ref()
        .and_then(|context| context.digest().ok())
        .map(|digest| digest.to_string());
    HttpsExecutionResponse {
        schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
        proposal_digest,
        status: if approval_request_hash.is_some() && reason_code == "ACTION_APPROVAL_REQUIRED" {
            HttpsExecutionStatus::ApprovalRequired
        } else {
            HttpsExecutionStatus::Denied
        },
        reason_code,
        authorization_id: None,
        request_hash: None,
        record_id: None,
        record_hash: None,
        result_sha256: None,
        result: None,
        approval_request,
        approval_request_hash,
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct HttpsPrestate {
    schema_version: u16,
    policy_hash: Digest32,
    domain: String,
    method: HttpsMethod,
    target: String,
}

impl HttpsPrestate {
    fn digest(&self) -> Result<Digest32, HttpsToolError> {
        domain_digest(HTTPS_PRESTATE_DOMAIN, self)
            .map_err(|()| HttpsToolError::InvalidExecutionState)
    }
}

fn domain_digest<T: Serialize + ?Sized>(domain: &[u8], value: &T) -> Result<Digest32, ()> {
    let encoded = canonical_json_bytes(value).map_err(|_| ())?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(u64::try_from(encoded.len()).map_err(|_| ())?.to_be_bytes());
    hasher.update(encoded);
    Ok(Digest32::from_bytes(hasher.finalize().into()))
}

fn validate_domain(domain: &str) -> Result<(), HttpsPolicyError> {
    if domain.is_empty()
        || domain.len() > 253
        || domain != domain.to_ascii_lowercase()
        || domain.ends_with('.')
        || domain == "localhost"
        || domain.ends_with(".localhost")
        || domain.parse::<Ipv4Addr>().is_ok()
        || domain.parse::<Ipv6Addr>().is_ok()
    {
        return Err(HttpsPolicyError::InvalidDomain);
    }
    for label in domain.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(HttpsPolicyError::InvalidDomain);
        }
    }
    if !domain.contains('.') {
        return Err(HttpsPolicyError::InvalidDomain);
    }
    Ok(())
}

fn validate_headers(headers: &[HttpsHeader], allowlist: &[&str]) -> Result<(), HttpsInputError> {
    if headers.len() > MAX_HEADER_COUNT {
        return Err(HttpsInputError::InvalidHeaders);
    }
    let mut previous: Option<&str> = None;
    for header in headers {
        if !allowlist.contains(&header.name.as_str())
            || header.value.len() > MAX_HEADER_VALUE_BYTES
            || header.value.chars().any(char::is_control)
            || previous.is_some_and(|name| name >= header.name.as_str())
        {
            return Err(HttpsInputError::InvalidHeaders);
        }
        previous = Some(&header.name);
    }
    Ok(())
}

const fn default_timeout_seconds() -> u32 {
    DEFAULT_TIMEOUT_SECONDS
}

const fn default_response_bytes() -> u32 {
    DEFAULT_RESPONSE_BYTES
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum HttpsPolicyError {
    #[error("HTTPS egress policy is outside the strict profile")]
    InvalidPolicy,
    #[error("HTTPS egress policy contains an invalid domain")]
    InvalidDomain,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
enum HttpsInputError {
    #[error("HTTPS arguments are malformed")]
    InvalidArguments,
    #[error("only HTTPS URLs are accepted")]
    HttpsRequired,
    #[error("HTTPS URL is outside the strict profile")]
    InvalidUrl,
    #[error("HTTPS domain is outside the strict DNS profile")]
    InvalidDomain,
    #[error("HTTPS headers are not canonical or allowed")]
    InvalidHeaders,
    #[error("HTTPS body is too large")]
    BodyTooLarge,
    #[error("this HTTP method cannot carry a body")]
    BodyForbidden,
    #[error("HTTPS timeout is outside the bounded profile")]
    InvalidTimeout,
    #[error("HTTPS response limit is outside the bounded profile")]
    InvalidResponseLimit,
    #[error("tool is not brokered by the HTTPS profile")]
    UnsupportedTool,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
enum HttpsToolError {
    #[error("NETWORK_POLICY_CHANGED")]
    PolicyChanged,
    #[error("NETWORK_EXECUTION_UNKNOWN")]
    ExecutionUnknown,
    #[error("NETWORK_REDIRECT_BLOCKED")]
    RedirectBlocked,
    #[error("NETWORK_RESPONSE_INVALID")]
    InvalidResponse,
    #[error("NETWORK_RESPONSE_TOO_LARGE")]
    ResponseTooLarge,
    #[error("INVALID_EXECUTION_STATE")]
    InvalidExecutionState,
}

impl HttpsToolError {
    const fn reason_code(self) -> &'static str {
        match self {
            Self::PolicyChanged => "NETWORK_POLICY_CHANGED",
            Self::ExecutionUnknown => "NETWORK_EXECUTION_UNKNOWN",
            Self::RedirectBlocked => "NETWORK_REDIRECT_BLOCKED",
            Self::InvalidResponse => "NETWORK_RESPONSE_INVALID",
            Self::ResponseTooLarge => "NETWORK_RESPONSE_TOO_LARGE",
            Self::InvalidExecutionState => "INVALID_EXECUTION_STATE",
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum GovernedHttpsError {
    #[error("HTTPS execution request is invalid")]
    Input,
    #[error("HTTPS ledger is unavailable")]
    Ledger(#[from] LedgerError),
    #[error("HTTPS execution state is unknown")]
    ExecutionStateUnknown,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::{Value, json};

    use super::*;

    fn proposal(arguments: Value) -> ToolCallProposal {
        let arguments_sha256 = crate::canonical::goose_digest(&arguments).unwrap_or_default();
        ToolCallProposal {
            schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
            session_id: "session".to_owned(),
            run_id: "run".to_owned(),
            tool_call_id: "call".to_owned(),
            workspace_root: std::fs::canonicalize(".")
                .unwrap_or_else(|_| PathBuf::from("."))
                .to_string_lossy()
                .into_owned(),
            extension_id: "accordlock_network".to_owned(),
            tool_name: "https_request".to_owned(),
            arguments,
            arguments_sha256: arguments_sha256.clone(),
            agent_plan_checkpoint: crate::model::test_agent_plan_checkpoint(
                "session",
                "run",
                "call",
                "accordlock_network__https_request",
                &arguments_sha256,
                1,
            ),
        }
    }

    fn valid() -> Value {
        json!({
            "method": "GET",
            "url": "https://api.example.com/v1/status",
            "headers": [{"name": "accept", "value": "application/json"}],
            "body": null,
            "redirect_policy": "DENY"
        })
    }

    #[test]
    fn strict_https_contract_accepts_one_canonical_request() {
        let prepared = PreparedHttpsRequest::from_proposal(&proposal(valid()));
        assert!(prepared.is_ok());
    }

    #[test]
    fn reported_network_error_has_an_explicit_unknown_execution_status()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = execution_state_unknown_response(
            Digest32::sha256(b"proposal").to_string(),
            uuid::Uuid::from_u128(1).to_string(),
            Digest32::sha256(b"request").to_string(),
            ObservationResult {
                authorization_id: uuid::Uuid::from_u128(1),
                observation_digest: Digest32::sha256(b"observation").to_string(),
                record_id: uuid::Uuid::from_u128(2),
                record_hash: Digest32::sha256(b"record").to_string(),
            },
            "NETWORK_EXECUTION_UNKNOWN",
        );
        let wire = serde_json::to_value(response)?;

        assert_eq!(wire["status"], "EXECUTION_UNKNOWN");
        assert_eq!(wire["reason_code"], "NETWORK_EXECUTION_UNKNOWN");
        assert!(wire.get("result").is_none());
        Ok(())
    }

    #[test]
    fn http_ips_userinfo_redirects_and_unknown_fields_are_rejected() {
        for value in [
            json!({"method":"GET","url":"http://api.example.com/","body":null,"redirect_policy":"DENY"}),
            json!({"method":"GET","url":"https://127.0.0.1/","body":null,"redirect_policy":"DENY"}),
            json!({"method":"GET","url":"https://user@api.example.com/","body":null,"redirect_policy":"DENY"}),
            json!({"method":"GET","url":"https://api.example.com/","body":null,"redirect_policy":"FOLLOW"}),
            json!({"method":"GET","url":"https://api.example.com/","body":null,"redirect_policy":"DENY","proxy":"https://evil.example"}),
        ] {
            assert!(PreparedHttpsRequest::from_proposal(&proposal(value)).is_err());
        }
    }

    #[test]
    fn credentials_duplicate_headers_and_get_bodies_are_rejected() {
        for value in [
            json!({"method":"GET","url":"https://api.example.com/","headers":[{"name":"authorization","value":"secret"}],"body":null,"redirect_policy":"DENY"}),
            json!({"method":"GET","url":"https://api.example.com/","headers":[{"name":"accept","value":"a"},{"name":"accept","value":"b"}],"body":null,"redirect_policy":"DENY"}),
            json!({"method":"GET","url":"https://api.example.com/","body":"unexpected","redirect_policy":"DENY"}),
        ] {
            assert!(PreparedHttpsRequest::from_proposal(&proposal(value)).is_err());
        }
    }

    #[test]
    fn policy_is_exact_domain_not_suffix_or_wildcard() -> Result<(), HttpsPolicyError> {
        let policy = HttpsEgressPolicy::new(
            "test-policy",
            ["api.example.com".to_owned()],
            [HttpsMethod::Get],
            0,
            65536,
        )?;
        let allowed = PreparedHttpsRequest::from_proposal(&proposal(valid()))
            .map_err(|_| HttpsPolicyError::InvalidPolicy)?;
        assert!(policy.authorizes(&allowed));
        let mut other = valid();
        other["url"] = json!("https://sub.api.example.com/v1/status");
        let other = PreparedHttpsRequest::from_proposal(&proposal(other))
            .map_err(|_| HttpsPolicyError::InvalidPolicy)?;
        assert!(!policy.authorizes(&other));
        Ok(())
    }

    #[derive(Debug)]
    struct FailingEgress {
        policy: HttpsEgressPolicy,
        error: HttpsEgressError,
    }

    impl HttpsEgress for FailingEgress {
        fn policy(&self) -> HttpsEgressPolicy {
            self.policy.clone()
        }

        fn execute(
            &self,
            _request: &HttpsEgressRequest,
        ) -> Result<HttpsEgressResponse, HttpsEgressError> {
            Err(self.error)
        }
    }

    #[test]
    fn concrete_transport_failures_keep_stable_network_reason_codes()
    -> Result<(), Box<dyn std::error::Error>> {
        let operation = PreparedHttpsRequest::from_proposal(&proposal(valid()))
            .map_err(|_| "valid request was rejected")?;
        let policy = HttpsEgressPolicy::new(
            "test-policy",
            ["api.example.com".to_owned()],
            [HttpsMethod::Get],
            0,
            65_536,
        )?;
        let prestate = operation.prestate(&policy)?.digest()?;
        for (error, expected) in [
            (HttpsEgressError::Policy, HttpsToolError::PolicyChanged),
            (HttpsEgressError::Redirect, HttpsToolError::RedirectBlocked),
            (
                HttpsEgressError::InvalidResponse,
                HttpsToolError::InvalidResponse,
            ),
            (
                HttpsEgressError::ResponseTooLarge,
                HttpsToolError::ResponseTooLarge,
            ),
            (
                HttpsEgressError::Transport,
                HttpsToolError::ExecutionUnknown,
            ),
            (HttpsEgressError::Tls, HttpsToolError::ExecutionUnknown),
        ] {
            let egress = FailingEgress {
                policy: policy.clone(),
                error,
            };
            assert_eq!(operation.execute(&egress, prestate), Err(expected));
        }
        Ok(())
    }
}
