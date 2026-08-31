//! Approval-controlled, read-only HTTPS tool for the AccordLock distribution.
//!
//! The model can name an exact HTTPS URL and choose GET or HEAD. Goose does not
//! open a socket. It submits a normalized proposal to the trusted runtime, which
//! rechecks the configured exact-domain policy, obtains one-time approval,
//! performs WebPKI TLS without proxies or redirects, and records the result.

#![cfg_attr(not(feature = "accordlock-distribution"), allow(dead_code))]

use async_trait::async_trait;
use rmcp::model::{CallToolResult, ContentBlock};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

use super::accordlock_authorization::{
    canonical_json_bytes, sha256_digest, validate_authorization_id, validate_digest,
    validate_reason_code, PolicyEnforcementError, RuntimePolicyEnforcementPoint,
    ToolExecutionRequest, PROTOCOL_VERSION,
};
use super::accordlock_filesystem::ExecutionEvidence;

pub(super) const NETWORK_EXECUTE_PATH: &str = "/api/v2/execution/network/authorize-and-execute";
pub(super) const NETWORK_ENABLED_ENV: &str = "ACCORDLOCK_GOVERNED_NETWORK";
const MAX_NETWORK_RESPONSE_BYTES: usize = 384 * 1024;
const DEFAULT_TIMEOUT_SECONDS: u32 = 30;
const MAX_TIMEOUT_SECONDS: u32 = 120;
const DEFAULT_RESPONSE_BYTES: u32 = 64 * 1024;
const MAX_RESPONSE_BYTES: u32 = 256 * 1024;
const HTTP_COMPLETION_GRACE_SECONDS: u64 = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) enum BrokeredHttpsMethod {
    Get,
    Head,
}

fn default_method() -> BrokeredHttpsMethod {
    BrokeredHttpsMethod::Get
}

const fn default_timeout_seconds() -> u32 {
    DEFAULT_TIMEOUT_SECONDS
}

const fn default_response_bytes() -> u32 {
    DEFAULT_RESPONSE_BYTES
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct BrokeredHttpsArguments {
    /// Exact HTTPS URL on an administrator-configured domain.
    pub url: String,
    /// Read-only HTTP method. Defaults to GET.
    #[serde(default = "default_method")]
    pub method: BrokeredHttpsMethod,
    /// End-to-end request deadline in seconds.
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u32,
    /// Maximum response body bytes retained by the broker.
    #[serde(default = "default_response_bytes")]
    pub max_response_bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeHttpsArguments {
    method: BrokeredHttpsMethod,
    url: String,
    headers: Vec<HttpsHeader>,
    body: Option<String>,
    timeout_seconds: u32,
    max_response_bytes: u32,
    redirect_policy: RedirectPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpsHeader {
    name: String,
    value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum RedirectPolicy {
    Deny,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct NetworkExecutionRequest<'a> {
    schema_version: u16,
    proposal: &'a ToolExecutionRequest,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkExecutionResponse {
    schema_version: u16,
    proposal_digest: String,
    status: NetworkExecutionStatus,
    reason_code: String,
    authorization_id: Option<String>,
    request_hash: Option<String>,
    record_id: Option<String>,
    record_hash: Option<String>,
    result_sha256: Option<String>,
    result: Option<BrokeredHttpsResult>,
    approval_request: Option<Value>,
    approval_request_hash: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum NetworkExecutionStatus {
    Succeeded,
    ExecutionUnknown,
    Denied,
    ApprovalRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct BrokeredHttpsResult {
    pub status: u16,
    pub headers: Vec<BrokeredHttpsHeader>,
    pub body: String,
    pub body_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct BrokeredHttpsHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedNetworkOperation {
    arguments: RuntimeHttpsArguments,
}

#[derive(Debug, Clone)]
pub(super) enum BrokeredNetworkOutcome {
    Succeeded {
        result: BrokeredHttpsResult,
        result_sha256: String,
        evidence: ExecutionEvidence,
    },
}

impl BrokeredNetworkOutcome {
    pub(super) fn into_call_tool_result(self) -> CallToolResult {
        match self {
            Self::Succeeded {
                result,
                result_sha256,
                evidence,
            } => {
                let text = if result.body.is_empty() {
                    format!("HTTPS {} (empty response body)", result.status)
                } else {
                    result.body.clone()
                };
                let mut call_result = CallToolResult::success(vec![ContentBlock::text(text)]);
                call_result.structured_content = Some(json!({
                    "result": result,
                    "accordlock": {
                        "schemaVersion": PROTOCOL_VERSION,
                        "status": "SUCCEEDED",
                        "reasonCode": "EXECUTED",
                        "authorizationId": evidence.authorization_id,
                        "requestHash": evidence.request_hash,
                        "recordId": evidence.record_id,
                        "recordHash": evidence.record_hash,
                        "resultSha256": result_sha256,
                    }
                }));
                call_result
            }
        }
    }
}

#[async_trait]
pub(super) trait NetworkBroker: Send + Sync {
    fn enforces_boundary(&self) -> bool;
    fn derive_run_id(&self, session_id: &str) -> Result<String, PolicyEnforcementError>;
    async fn authorize_and_execute(
        &self,
        request: &ToolExecutionRequest,
    ) -> Result<BrokeredNetworkOutcome, PolicyEnforcementError>;
}

#[derive(Clone)]
struct RuntimeNetworkBroker {
    runtime: RuntimePolicyEnforcementPoint,
}

impl RuntimeNetworkBroker {
    fn from_environment() -> Result<Self, PolicyEnforcementError> {
        Ok(Self {
            runtime: RuntimePolicyEnforcementPoint::from_environment()?,
        })
    }
}

#[async_trait]
impl NetworkBroker for RuntimeNetworkBroker {
    fn enforces_boundary(&self) -> bool {
        true
    }

    fn derive_run_id(&self, session_id: &str) -> Result<String, PolicyEnforcementError> {
        self.runtime.derive_backend_run_id(session_id)
    }

    async fn authorize_and_execute(
        &self,
        request: &ToolExecutionRequest,
    ) -> Result<BrokeredNetworkOutcome, PolicyEnforcementError> {
        let operation = validate_execution_request(request)?;
        let expected_proposal_digest = request.digest()?;
        let envelope = NetworkExecutionRequest {
            schema_version: PROTOCOL_VERSION,
            proposal: request,
        };
        let response: NetworkExecutionResponse = self
            .runtime
            .post_json_bounded_with_timeout(
                NETWORK_EXECUTE_PATH,
                &envelope,
                MAX_NETWORK_RESPONSE_BYTES,
                Duration::from_secs(
                    u64::from(operation.arguments.timeout_seconds) + HTTP_COMPLETION_GRACE_SECONDS,
                ),
            )
            .await
            .map_err(|_| PolicyEnforcementError::ExecutionUnknown)?;
        validate_response(response, &operation, request, &expected_proposal_digest)
    }
}

struct UnavailableNetworkBroker;

#[async_trait]
impl NetworkBroker for UnavailableNetworkBroker {
    fn enforces_boundary(&self) -> bool {
        true
    }

    fn derive_run_id(&self, _session_id: &str) -> Result<String, PolicyEnforcementError> {
        Err(PolicyEnforcementError::RuntimeNotConfigured)
    }

    async fn authorize_and_execute(
        &self,
        _request: &ToolExecutionRequest,
    ) -> Result<BrokeredNetworkOutcome, PolicyEnforcementError> {
        Err(PolicyEnforcementError::RuntimeNotConfigured)
    }
}

pub(super) fn default_network_broker() -> Arc<dyn NetworkBroker> {
    #[cfg(feature = "accordlock-distribution")]
    {
        RuntimeNetworkBroker::from_environment()
            .map(|broker| Arc::new(broker) as Arc<dyn NetworkBroker>)
            .unwrap_or_else(|_| Arc::new(UnavailableNetworkBroker))
    }
    #[cfg(not(feature = "accordlock-distribution"))]
    {
        Arc::new(UnavailableNetworkBroker)
    }
}

pub(super) fn is_enabled() -> bool {
    cfg!(feature = "accordlock-distribution")
        && std::env::var_os(NETWORK_ENABLED_ENV).is_some_and(|value| value == "1")
}

pub(super) fn is_brokered(extension_id: &str, tool_name: &str) -> bool {
    extension_id == "developer" && tool_name == "https_request"
}

pub(super) fn normalize_tool_arguments(value: Value) -> Result<Value, PolicyEnforcementError> {
    let arguments: BrokeredHttpsArguments = serde_json::from_value(value)
        .map_err(|_| PolicyEnforcementError::InvalidField("arguments"))?;
    validate_url(&arguments.url)?;
    if !(1..=MAX_TIMEOUT_SECONDS).contains(&arguments.timeout_seconds)
        || !(1..=MAX_RESPONSE_BYTES).contains(&arguments.max_response_bytes)
    {
        return Err(PolicyEnforcementError::InvalidField("arguments"));
    }
    serde_json::to_value(RuntimeHttpsArguments {
        method: arguments.method,
        url: arguments.url,
        headers: Vec::new(),
        body: None,
        timeout_seconds: arguments.timeout_seconds,
        max_response_bytes: arguments.max_response_bytes,
        redirect_policy: RedirectPolicy::Deny,
    })
    .map_err(|_| PolicyEnforcementError::InvalidField("arguments"))
}

fn validate_execution_request(
    request: &ToolExecutionRequest,
) -> Result<ValidatedNetworkOperation, PolicyEnforcementError> {
    if request.extension_id != "accordlock_network" || request.tool_name != "https_request" {
        return Err(PolicyEnforcementError::InvalidField("tool_name"));
    }
    let arguments: RuntimeHttpsArguments = serde_json::from_value(request.arguments.clone())
        .map_err(|_| PolicyEnforcementError::InvalidField("arguments"))?;
    validate_url(&arguments.url)?;
    if !arguments.headers.is_empty()
        || arguments.body.is_some()
        || arguments.redirect_policy != RedirectPolicy::Deny
        || !(1..=MAX_TIMEOUT_SECONDS).contains(&arguments.timeout_seconds)
        || !(1..=MAX_RESPONSE_BYTES).contains(&arguments.max_response_bytes)
    {
        return Err(PolicyEnforcementError::InvalidField("arguments"));
    }
    Ok(ValidatedNetworkOperation { arguments })
}

fn validate_url(value: &str) -> Result<(), PolicyEnforcementError> {
    if value.is_empty()
        || value.len() > 4 * 1024
        || value.trim() != value
        || value.chars().any(char::is_control)
        || !value.starts_with("https://")
        || value.contains('#')
    {
        return Err(PolicyEnforcementError::InvalidField("url"));
    }
    let parsed = url::Url::parse(value).map_err(|_| PolicyEnforcementError::InvalidField("url"))?;
    let host = parsed
        .host_str()
        .ok_or(PolicyEnforcementError::InvalidField("url"))?;
    if parsed.scheme() != "https"
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.port().is_some_and(|port| port != 443)
        || host != host.to_ascii_lowercase()
        || !host.contains('.')
        || host == "localhost"
        || host.ends_with(".localhost")
        || host.parse::<std::net::IpAddr>().is_ok()
    {
        return Err(PolicyEnforcementError::InvalidField("url"));
    }
    Ok(())
}

fn validate_response(
    response: NetworkExecutionResponse,
    operation: &ValidatedNetworkOperation,
    request: &ToolExecutionRequest,
    expected_proposal_digest: &str,
) -> Result<BrokeredNetworkOutcome, PolicyEnforcementError> {
    if response.schema_version != PROTOCOL_VERSION
        || response.proposal_digest != expected_proposal_digest
        || validate_digest(&response.proposal_digest).is_err()
        || validate_reason_code(&response.reason_code).is_err()
    {
        return Err(PolicyEnforcementError::ExecutionUnknown);
    }
    match response.status {
        NetworkExecutionStatus::Succeeded => {
            if response.reason_code != "EXECUTED"
                || response.approval_request.is_some()
                || response.approval_request_hash.is_some()
            {
                return Err(PolicyEnforcementError::ExecutionUnknown);
            }
            let evidence = extract_evidence(&response)?;
            let result = response
                .result
                .ok_or(PolicyEnforcementError::ExecutionUnknown)?;
            let result_sha256 = response
                .result_sha256
                .ok_or(PolicyEnforcementError::ExecutionUnknown)?;
            let expected_result_sha256 = canonical_json_bytes(&result)
                .map(|bytes| sha256_digest(&bytes))
                .map_err(|_| PolicyEnforcementError::ExecutionUnknown)?;
            if validate_digest(&result_sha256).is_err()
                || result_sha256 != expected_result_sha256
                || !(200..=599).contains(&result.status)
                || result.body.len() > operation.arguments.max_response_bytes as usize
                || sha256_digest(result.body.as_bytes()) != result.body_sha256
                || validate_digest(&result.body_sha256).is_err()
                || !valid_response_headers(&result.headers)
            {
                return Err(PolicyEnforcementError::ExecutionUnknown);
            }
            Ok(BrokeredNetworkOutcome::Succeeded {
                result,
                result_sha256,
                evidence,
            })
        }
        NetworkExecutionStatus::ExecutionUnknown => {
            if !matches!(
                response.reason_code.as_str(),
                "NETWORK_EXECUTION_UNKNOWN"
                    | "NETWORK_RESPONSE_INVALID"
                    | "NETWORK_RESPONSE_TOO_LARGE"
            ) || response.approval_request.is_some()
                || response.approval_request_hash.is_some()
            {
                return Err(PolicyEnforcementError::ExecutionUnknown);
            }
            let _ = extract_evidence(&response)?;
            Err(PolicyEnforcementError::ExecutionUnknown)
        }
        NetworkExecutionStatus::Denied => {
            require_no_execution_evidence(&response)?;
            if !matches!(
                response.reason_code.as_str(),
                "NETWORK_EGRESS_NOT_CONFIGURED"
                    | "NETWORK_POLICY_CHANGED"
                    | "NETWORK_REDIRECT_BLOCKED"
                    | "UNKNOWN_SESSION"
                    | "SESSION_REVOKED"
                    | "SESSION_NOT_CURRENT"
                    | "SESSION_BINDING_MISMATCH"
                    | "CAPABILITY_NOT_APPROVED"
                    | "TOOL_CALL_REPLAY"
                    | "EXECUTION_CONTEXT_REQUIRED"
                    | "ACTION_APPROVAL_DENIED"
                    | "ACTION_APPROVAL_EXPIRED"
                    | "ACTION_APPROVAL_SCOPE_MISMATCH"
                    | "ACTION_APPROVAL_ALREADY_USED"
            ) || response.approval_request.is_some()
                || response.approval_request_hash.is_some()
            {
                return Err(PolicyEnforcementError::ExecutionUnknown);
            }
            Err(PolicyEnforcementError::Denied(response.reason_code))
        }
        NetworkExecutionStatus::ApprovalRequired => {
            require_no_execution_evidence(&response)?;
            let approval = response
                .approval_request
                .as_ref()
                .ok_or(PolicyEnforcementError::ExecutionUnknown)?;
            let supplied_hash = response
                .approval_request_hash
                .as_deref()
                .ok_or(PolicyEnforcementError::ExecutionUnknown)?;
            if response.reason_code != "ACTION_APPROVAL_REQUIRED"
                || validate_approval_request(
                    approval,
                    supplied_hash,
                    request,
                    expected_proposal_digest,
                )
                .is_err()
            {
                return Err(PolicyEnforcementError::ExecutionUnknown);
            }
            Err(PolicyEnforcementError::ApprovalRequired(
                response.reason_code,
            ))
        }
    }
}

fn validate_approval_request(
    value: &Value,
    supplied_hash: &str,
    request: &ToolExecutionRequest,
    proposal_digest: &str,
) -> Result<(), PolicyEnforcementError> {
    validate_digest(supplied_hash).map_err(|_| PolicyEnforcementError::ExecutionUnknown)?;
    let canonical =
        canonical_json_bytes(value).map_err(|_| PolicyEnforcementError::ExecutionUnknown)?;
    if domain_digest(b"accordlock:v2:action-approval-request", &canonical) != supplied_hash {
        return Err(PolicyEnforcementError::ExecutionUnknown);
    }
    let object = value
        .as_object()
        .ok_or(PolicyEnforcementError::ExecutionUnknown)?;
    let action = object
        .get("action")
        .and_then(Value::as_object)
        .ok_or(PolicyEnforcementError::ExecutionUnknown)?;
    if object.get("schema_version") != Some(&json!(2))
        || object.get("session_id") != Some(&json!(request.session_id))
        || object.get("run_id") != Some(&json!(request.run_id))
        || object.get("tool_call_id") != Some(&json!(request.tool_call_id))
        || object.get("proposal_digest") != Some(&json!(proposal_digest))
        || action.get("extension_id") != Some(&json!("accordlock_network"))
        || action.get("tool_name") != Some(&json!("https_request"))
        || action.get("action_type") != Some(&json!("HTTPS_REQUEST"))
        || action.get("relative_path") != Some(&json!(network_target(&request.arguments)?))
        || action.get("requested_bytes") != Some(&json!(0))
    {
        return Err(PolicyEnforcementError::ExecutionUnknown);
    }
    Ok(())
}

fn network_target(arguments: &Value) -> Result<String, PolicyEnforcementError> {
    let arguments: RuntimeHttpsArguments = serde_json::from_value(arguments.clone())
        .map_err(|_| PolicyEnforcementError::ExecutionUnknown)?;
    let parsed =
        url::Url::parse(&arguments.url).map_err(|_| PolicyEnforcementError::ExecutionUnknown)?;
    let host = parsed
        .host_str()
        .ok_or(PolicyEnforcementError::ExecutionUnknown)?;
    let mut target = parsed.path().to_owned();
    if let Some(query) = parsed.query() {
        target.push('?');
        target.push_str(query);
    }
    Ok(format!("{host}{target}"))
}

fn extract_evidence(
    response: &NetworkExecutionResponse,
) -> Result<ExecutionEvidence, PolicyEnforcementError> {
    let authorization_id = response
        .authorization_id
        .clone()
        .ok_or(PolicyEnforcementError::ExecutionUnknown)?;
    let request_hash = response
        .request_hash
        .clone()
        .ok_or(PolicyEnforcementError::ExecutionUnknown)?;
    let record_id = response
        .record_id
        .clone()
        .ok_or(PolicyEnforcementError::ExecutionUnknown)?;
    let record_hash = response
        .record_hash
        .clone()
        .ok_or(PolicyEnforcementError::ExecutionUnknown)?;
    validate_authorization_id(&authorization_id)
        .map_err(|_| PolicyEnforcementError::ExecutionUnknown)?;
    validate_authorization_id(&record_id).map_err(|_| PolicyEnforcementError::ExecutionUnknown)?;
    validate_digest(&request_hash).map_err(|_| PolicyEnforcementError::ExecutionUnknown)?;
    validate_digest(&record_hash).map_err(|_| PolicyEnforcementError::ExecutionUnknown)?;
    Ok(ExecutionEvidence {
        authorization_id,
        request_hash,
        record_id,
        record_hash,
    })
}

fn require_no_execution_evidence(
    response: &NetworkExecutionResponse,
) -> Result<(), PolicyEnforcementError> {
    if response.authorization_id.is_some()
        || response.request_hash.is_some()
        || response.record_id.is_some()
        || response.record_hash.is_some()
        || response.result_sha256.is_some()
        || response.result.is_some()
    {
        return Err(PolicyEnforcementError::ExecutionUnknown);
    }
    Ok(())
}

fn valid_response_headers(headers: &[BrokeredHttpsHeader]) -> bool {
    const ALLOWED: &[&str] = &[
        "content-length",
        "content-type",
        "date",
        "etag",
        "last-modified",
        "location",
        "x-request-id",
    ];
    headers.len() <= 32
        && headers.iter().enumerate().all(|(index, header)| {
            ALLOWED.contains(&header.name.as_str())
                && header.value.len() <= 4 * 1024
                && !header.value.chars().any(char::is_control)
                && (index == 0 || headers[index - 1].name < header.name)
        })
}

fn domain_digest(domain: &[u8], canonical: &[u8]) -> String {
    let mut input = Vec::with_capacity(domain.len() + 1 + 8 + canonical.len());
    input.extend_from_slice(domain);
    input.push(0);
    input.extend_from_slice(&(canonical.len() as u64).to_be_bytes());
    input.extend_from_slice(canonical);
    sha256_digest(&input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_a_minimal_get_without_headers_or_body() {
        let value = normalize_tool_arguments(json!({"url": "https://api.example.com/v1"})).unwrap();
        assert_eq!(value["method"], "GET");
        assert_eq!(value["headers"], json!([]));
        assert_eq!(value["body"], Value::Null);
        assert_eq!(value["redirect_policy"], "DENY");
    }

    #[test]
    fn rejects_credentials_local_targets_wildcards_and_write_methods() {
        for value in [
            json!({"url": "http://api.example.com"}),
            json!({"url": "https://user:pass@api.example.com"}),
            json!({"url": "https://localhost/status"}),
            json!({"url": "https://127.0.0.1/status"}),
            json!({"url": "https://*.example.com/status"}),
            json!({"url": "https://api.example.com", "method": "POST"}),
        ] {
            assert!(normalize_tool_arguments(value).is_err());
        }
    }

    #[test]
    fn response_headers_must_be_allowlisted_sorted_and_unique() {
        assert!(valid_response_headers(&[
            BrokeredHttpsHeader {
                name: "content-type".into(),
                value: "application/json".into()
            },
            BrokeredHttpsHeader {
                name: "etag".into(),
                value: "v1".into()
            },
        ]));
        assert!(!valid_response_headers(&[
            BrokeredHttpsHeader {
                name: "etag".into(),
                value: "v1".into()
            },
            BrokeredHttpsHeader {
                name: "content-type".into(),
                value: "application/json".into()
            },
        ]));
        assert!(!valid_response_headers(&[BrokeredHttpsHeader {
            name: "set-cookie".into(),
            value: "secret=1".into()
        },]));
    }
}
