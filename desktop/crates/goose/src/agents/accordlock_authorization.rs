//! Mandatory AccordLock policy enforcement boundary for protected tool calls.
//!
//! Model providers stop at the agent loop. This module sits later, immediately
//! before an MCP client can execute an action. The AccordLock distribution uses
//! a separate local runtime as the authority; a missing, malformed, or timed-out
//! runtime response is always a denial.

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use futures::StreamExt;
use hmac::{Hmac, Mac};
use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sha2_10::Sha256 as HmacSha256;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

pub(super) const PROTOCOL_VERSION: u16 = 3;
pub(super) const AGENT_PLAN_CHECKPOINT_SCHEMA_VERSION: u16 = 1;
const MAX_ARGUMENT_BYTES: usize = 256 * 1_024;
const MAX_PLAN_MATERIAL_BYTES: usize = 512 * 1_024;
const MAX_RUNTIME_RESPONSE_BYTES: usize = 65_536;
const MAX_IDENTIFIER_BYTES: usize = 512;
const MAX_REASON_CODE_BYTES: usize = 128;
const MIN_RUNTIME_TOKEN_BYTES: usize = 32;
const BACKEND_BINDING_SECRET_BYTES: usize = 32;
const BACKEND_BINDING_DOMAIN: &[u8] = b"accordlock.backend-run/v1";
const MAX_AUTHORIZATION_LIFETIME_SECONDS: i64 = 5 * 60;
const RUNTIME_TIMEOUT: Duration = Duration::from_secs(5);
const AUTHORIZE_PATH: &str = "/api/v2/authorization/tool-calls/authorize-and-consume";
const RECORD_PATH: &str = "/api/v2/execution/tool-observations/record";
const OBSERVATION_DIGEST_DOMAIN: &[u8] = b"accordlock:v2:agent-execution-observation";

pub const RUNTIME_URL_ENV: &str = "ACCORDLOCK_RUNTIME_URL";
pub const RUNTIME_TOKEN_ENV: &str = "ACCORDLOCK_RUNTIME_TOKEN";
pub const BACKEND_BINDING_SECRET_ENV: &str = "ACCORDLOCK_BACKEND_BINDING_SECRET";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PolicyEnforcementError {
    #[error("missing tool-call request identifier")]
    MissingRequestId,
    #[error("missing or invalid workspace binding")]
    InvalidWorkspace,
    #[error("tool-call field is invalid: {0}")]
    InvalidField(&'static str),
    #[error("tool arguments exceed the accepted bound")]
    ArgumentsTooLarge,
    #[error("agent plan checkpoint is missing or invalid")]
    InvalidAgentPlanCheckpoint,
    #[error("AccordLock runtime is not configured")]
    RuntimeNotConfigured,
    #[error("AccordLock backend binding is missing or invalid")]
    InvalidBackendBinding,
    #[error("AccordLock runtime endpoint is invalid")]
    InvalidRuntimeEndpoint,
    #[error("AccordLock runtime is unavailable")]
    RuntimeUnavailable,
    #[error("AccordLock runtime returned an invalid response")]
    InvalidRuntimeResponse,
    #[error("AccordLock execution authorization is not currently valid")]
    AuthorizationNotCurrent,
    #[error("AccordLock denied this exact tool call: {0}")]
    Denied(String),
    #[error("AccordLock requires approval for this exact tool call: {0}")]
    ApprovalRequired(String),
    #[error("the execution record could not be committed; execution status is unknown")]
    ExecutionUnknown,
}

/// Exact, provider-independent execution request sent to the trusted runtime.
///
/// Policy state and task authorization digests deliberately do not come from
/// Goose. The trusted runtime resolves them from its own session binding and
/// creates the authoritative `ExecutionRequest`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ToolExecutionRequest {
    pub schema_version: u16,
    pub session_id: String,
    pub run_id: String,
    pub tool_call_id: String,
    pub workspace_root: String,
    pub extension_id: String,
    pub tool_name: String,
    pub arguments: Value,
    pub arguments_sha256: String,
    pub agent_plan_checkpoint: AgentPlanCheckpoint,
}

pub(super) struct ToolExecutionRequestParams<'a> {
    pub(super) session_id: &'a str,
    pub(super) run_id: &'a str,
    pub(super) request_id: Option<&'a str>,
    pub(super) working_dir: Option<&'a Path>,
    pub(super) extension_id: &'a str,
    pub(super) tool_name: &'a str,
    pub(super) plan_tool_name: &'a str,
    pub(super) arguments: Value,
    pub(super) plan_checkpoint_input: Option<&'a AgentPlanCheckpointInput>,
}

/// Sanitized plan material captured from the assistant message that proposed
/// the tool call. This is internal dispatch state, not a runtime wire object.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentPlanCheckpointInput {
    pub session_id: String,
    pub tool_call_id: String,
    pub material: Value,
    pub material_sha256: String,
    pub recorded_at: i64,
}

/// Canonically committed, provider-independent plan checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AgentPlanCheckpoint {
    pub schema_version: u16,
    pub session_id: String,
    pub run_id: String,
    pub tool_call_id: String,
    pub material: Value,
    pub material_sha256: String,
    pub recorded_at: i64,
}

impl AgentPlanCheckpointInput {
    pub fn new(
        session_id: String,
        tool_call_id: String,
        material: Value,
        recorded_at: i64,
    ) -> Result<Self, PolicyEnforcementError> {
        validate_identifier(&session_id, "session_id")?;
        validate_identifier(&tool_call_id, "tool_call_id")?;
        if recorded_at <= 0 {
            return Err(PolicyEnforcementError::InvalidAgentPlanCheckpoint);
        }
        let material_bytes = canonical_json_bytes(&material)?;
        if material_bytes.len() > MAX_PLAN_MATERIAL_BYTES {
            return Err(PolicyEnforcementError::InvalidAgentPlanCheckpoint);
        }
        Ok(Self {
            session_id,
            tool_call_id,
            material,
            material_sha256: sha256_digest(&material_bytes),
            recorded_at,
        })
    }

    fn bind(
        &self,
        session_id: &str,
        run_id: &str,
        tool_call_id: &str,
        tool_name: &str,
        arguments_sha256: &str,
    ) -> Result<AgentPlanCheckpoint, PolicyEnforcementError> {
        if self.session_id != session_id || self.tool_call_id != tool_call_id {
            return Err(PolicyEnforcementError::InvalidAgentPlanCheckpoint);
        }
        validate_digest(run_id)?;
        let material_bytes = canonical_json_bytes(&self.material)?;
        if material_bytes.len() > MAX_PLAN_MATERIAL_BYTES
            || sha256_digest(&material_bytes) != self.material_sha256
        {
            return Err(PolicyEnforcementError::InvalidAgentPlanCheckpoint);
        }
        validate_plan_material(&self.material, tool_call_id, tool_name, arguments_sha256)?;
        Ok(AgentPlanCheckpoint {
            schema_version: AGENT_PLAN_CHECKPOINT_SCHEMA_VERSION,
            session_id: session_id.to_owned(),
            run_id: run_id.to_owned(),
            tool_call_id: tool_call_id.to_owned(),
            material: self.material.clone(),
            material_sha256: self.material_sha256.clone(),
            recorded_at: self.recorded_at,
        })
    }
}

impl ToolExecutionRequest {
    pub(super) fn new(
        params: ToolExecutionRequestParams<'_>,
    ) -> Result<Self, PolicyEnforcementError> {
        let ToolExecutionRequestParams {
            session_id,
            run_id,
            request_id,
            working_dir,
            extension_id,
            tool_name,
            plan_tool_name,
            arguments,
            plan_checkpoint_input,
        } = params;
        validate_identifier(session_id, "session_id")?;
        validate_digest(run_id).map_err(|_| PolicyEnforcementError::InvalidField("run_id"))?;
        let tool_call_id = request_id.ok_or(PolicyEnforcementError::MissingRequestId)?;
        validate_identifier(tool_call_id, "tool_call_id")?;
        validate_identifier(extension_id, "extension_id")?;
        validate_identifier(tool_name, "tool_name")?;
        validate_identifier(plan_tool_name, "plan_tool_name")?;

        let workspace = working_dir.ok_or(PolicyEnforcementError::InvalidWorkspace)?;
        let workspace = canonical_workspace(workspace)?;
        let canonical_arguments = canonical_json_bytes(&arguments)?;
        if canonical_arguments.len() > MAX_ARGUMENT_BYTES {
            return Err(PolicyEnforcementError::ArgumentsTooLarge);
        }
        let arguments_sha256 = sha256_digest(&canonical_arguments);
        let agent_plan_checkpoint = plan_checkpoint_input
            .ok_or(PolicyEnforcementError::InvalidAgentPlanCheckpoint)?
            .bind(
                session_id,
                run_id,
                tool_call_id,
                plan_tool_name,
                &arguments_sha256,
            )?;

        Ok(Self {
            schema_version: PROTOCOL_VERSION,
            session_id: session_id.to_owned(),
            run_id: run_id.to_owned(),
            tool_call_id: tool_call_id.to_owned(),
            workspace_root: workspace,
            extension_id: extension_id.to_owned(),
            tool_name: tool_name.to_owned(),
            arguments,
            arguments_sha256,
            agent_plan_checkpoint,
        })
    }

    pub fn digest(&self) -> Result<String, PolicyEnforcementError> {
        canonical_json_bytes(self).map(|bytes| sha256_digest(&bytes))
    }
}

fn validate_plan_material(
    material: &Value,
    tool_call_id: &str,
    tool_name: &str,
    arguments_sha256: &str,
) -> Result<(), PolicyEnforcementError> {
    let object = material
        .as_object()
        .ok_or(PolicyEnforcementError::InvalidAgentPlanCheckpoint)?;
    if object.len() != 2 || !object.contains_key("text") || !object.contains_key("tool_requests") {
        return Err(PolicyEnforcementError::InvalidAgentPlanCheckpoint);
    }
    let texts = object["text"]
        .as_array()
        .ok_or(PolicyEnforcementError::InvalidAgentPlanCheckpoint)?;
    if texts.iter().any(|value| value.as_str().is_none()) {
        return Err(PolicyEnforcementError::InvalidAgentPlanCheckpoint);
    }
    let requests = object["tool_requests"]
        .as_array()
        .ok_or(PolicyEnforcementError::InvalidAgentPlanCheckpoint)?;
    let mut identifiers = HashSet::with_capacity(requests.len());
    let mut target_matches = 0_usize;
    for request in requests {
        let request = request
            .as_object()
            .ok_or(PolicyEnforcementError::InvalidAgentPlanCheckpoint)?;
        if request.len() != 3
            || !request.contains_key("id")
            || !request.contains_key("name")
            || !request.contains_key("arguments_sha256")
        {
            return Err(PolicyEnforcementError::InvalidAgentPlanCheckpoint);
        }
        let id = request["id"]
            .as_str()
            .ok_or(PolicyEnforcementError::InvalidAgentPlanCheckpoint)?;
        let name = request["name"]
            .as_str()
            .ok_or(PolicyEnforcementError::InvalidAgentPlanCheckpoint)?;
        let digest = request["arguments_sha256"]
            .as_str()
            .ok_or(PolicyEnforcementError::InvalidAgentPlanCheckpoint)?;
        validate_identifier(id, "tool_call_id")?;
        validate_identifier(name, "tool_name")?;
        validate_digest(digest)?;
        if !identifiers.insert(id) {
            return Err(PolicyEnforcementError::InvalidAgentPlanCheckpoint);
        }
        if id == tool_call_id {
            if name != tool_name || digest != arguments_sha256 {
                return Err(PolicyEnforcementError::InvalidAgentPlanCheckpoint);
            }
            target_matches += 1;
        }
    }
    if target_matches != 1 {
        return Err(PolicyEnforcementError::InvalidAgentPlanCheckpoint);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionAuthorization {
    pub authorization_id: String,
    pub proposal_digest: String,
    pub request_hash: String,
    pub issued_at: i64,
    pub not_before: i64,
    pub expires_at: i64,
}

impl ExecutionAuthorization {
    pub fn ensure_current(&self, now: i64) -> Result<(), PolicyEnforcementError> {
        if self.issued_at < 0
            || self.not_before < self.issued_at
            || self.expires_at <= self.not_before
            || self.expires_at.saturating_sub(self.issued_at) > MAX_AUTHORIZATION_LIFETIME_SECONDS
            || now < self.not_before
            || now >= self.expires_at
        {
            return Err(PolicyEnforcementError::AuthorizationNotCurrent);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionOutcome {
    Succeeded,
    ToolReportedError,
    TransportError,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ToolExecutionObservation {
    pub schema_version: u16,
    pub authorization_id: String,
    pub proposal_digest: String,
    pub request_hash: String,
    pub outcome: ExecutionOutcome,
    pub result_digest: Option<String>,
}

impl ToolExecutionObservation {
    pub fn new(
        authorization: &ExecutionAuthorization,
        outcome: ExecutionOutcome,
        result: Option<&Value>,
    ) -> Result<Self, PolicyEnforcementError> {
        validate_authorization_id(&authorization.authorization_id)?;
        validate_digest(&authorization.proposal_digest)?;
        validate_digest(&authorization.request_hash)?;
        let result_digest = result
            .map(canonical_json_bytes)
            .transpose()?
            .map(|bytes| sha256_digest(&bytes));
        Ok(Self {
            schema_version: PROTOCOL_VERSION,
            authorization_id: authorization.authorization_id.clone(),
            proposal_digest: authorization.proposal_digest.clone(),
            request_hash: authorization.request_hash.clone(),
            outcome,
            result_digest,
        })
    }

    pub fn digest(&self) -> Result<String, PolicyEnforcementError> {
        canonical_json_bytes(self).map(|bytes| {
            let mut payload = Vec::with_capacity(OBSERVATION_DIGEST_DOMAIN.len() + 1 + bytes.len());
            payload.extend_from_slice(OBSERVATION_DIGEST_DOMAIN);
            payload.push(0);
            payload.extend_from_slice(&bytes);
            sha256_digest(&payload)
        })
    }
}

#[async_trait]
pub trait PolicyEnforcementPoint: Send + Sync {
    /// Upstream Goose builds keep their original behavior. AccordLock builds
    /// and tests return `true` and cannot reach an operation without a complete
    /// request.
    fn enforces_tool_policy(&self) -> bool {
        true
    }

    /// Derive the non-transferable task run binding immediately before a
    /// request is built. Implementations without backend authorization must fail.
    fn derive_run_id(&self, session_id: &str) -> Result<String, PolicyEnforcementError>;

    /// Authorize and atomically consume authority for this exact proposal.
    async fn authorize_and_consume(
        &self,
        request: &ToolExecutionRequest,
    ) -> Result<ExecutionAuthorization, PolicyEnforcementError>;

    /// Commit a post-execution record. Failure means execution is ambiguous,
    /// never a clean tool failure that an agent may safely retry.
    async fn record_execution(
        &self,
        record: &ToolExecutionObservation,
    ) -> Result<(), PolicyEnforcementError>;
}

/// Upstream compatibility only. This type is never selected by an
/// `accordlock-distribution` build.
#[derive(Default)]
#[cfg(not(feature = "accordlock-distribution"))]
struct UpstreamPassthroughPolicyEnforcementPoint;

#[async_trait]
#[cfg(not(feature = "accordlock-distribution"))]
impl PolicyEnforcementPoint for UpstreamPassthroughPolicyEnforcementPoint {
    fn enforces_tool_policy(&self) -> bool {
        false
    }

    fn derive_run_id(&self, _session_id: &str) -> Result<String, PolicyEnforcementError> {
        Err(PolicyEnforcementError::RuntimeNotConfigured)
    }

    async fn authorize_and_consume(
        &self,
        request: &ToolExecutionRequest,
    ) -> Result<ExecutionAuthorization, PolicyEnforcementError> {
        Ok(ExecutionAuthorization {
            authorization_id: "upstream-compatibility".to_owned(),
            proposal_digest: request.digest()?,
            request_hash: sha256_digest(b"upstream-compatibility"),
            issued_at: 0,
            not_before: 0,
            expires_at: i64::MAX,
        })
    }

    async fn record_execution(
        &self,
        _record: &ToolExecutionObservation,
    ) -> Result<(), PolicyEnforcementError> {
        Ok(())
    }
}

#[derive(Clone)]
struct BackendBindingKey([u8; BACKEND_BINDING_SECRET_BYTES]);

impl BackendBindingKey {
    fn parse(value: &str) -> Result<Self, PolicyEnforcementError> {
        // A canonical no-padding base64url encoding of 32 bytes is always 43
        // ASCII characters. Re-encoding rejects alternate representations.
        if value.len() != 43
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(PolicyEnforcementError::InvalidBackendBinding);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| PolicyEnforcementError::InvalidBackendBinding)?;
        if decoded.len() != BACKEND_BINDING_SECRET_BYTES
            || URL_SAFE_NO_PAD.encode(&decoded) != value
        {
            return Err(PolicyEnforcementError::InvalidBackendBinding);
        }

        let mut key = [0_u8; BACKEND_BINDING_SECRET_BYTES];
        key.copy_from_slice(&decoded);
        Ok(Self(key))
    }

    fn derive_run_id(&self, session_id: &str) -> Result<String, PolicyEnforcementError> {
        validate_identifier(session_id, "session_id")?;
        let session_bytes = session_id.as_bytes();
        let session_length = u32::try_from(session_bytes.len())
            .map_err(|_| PolicyEnforcementError::InvalidField("session_id"))?;
        let mut message =
            Vec::with_capacity(BACKEND_BINDING_DOMAIN.len() + 1 + 4 + session_bytes.len());
        message.extend_from_slice(BACKEND_BINDING_DOMAIN);
        message.push(0);
        message.extend_from_slice(&session_length.to_be_bytes());
        message.extend_from_slice(session_bytes);
        let mut mac = Hmac::<HmacSha256>::new_from_slice(&self.0)
            .map_err(|_| PolicyEnforcementError::InvalidBackendBinding)?;
        mac.update(&message);
        Ok(format_sha256_identifier(&mac.finalize().into_bytes()))
    }
}

#[cfg(test)]
pub(super) fn derive_backend_run_id(
    backend_binding_secret: &str,
    session_id: &str,
) -> Result<String, PolicyEnforcementError> {
    BackendBindingKey::parse(backend_binding_secret)?.derive_run_id(session_id)
}

fn format_sha256_identifier(digest: &[u8]) -> String {
    let mut value = String::with_capacity(71);
    value.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(value, "{byte:02x}");
    }
    value
}

#[derive(Clone)]
pub struct RuntimePolicyEnforcementPoint {
    client: Client,
    base_url: Url,
    bearer: String,
    backend_binding: BackendBindingKey,
}

impl RuntimePolicyEnforcementPoint {
    pub fn from_environment() -> Result<Self, PolicyEnforcementError> {
        let url = std::env::var(RUNTIME_URL_ENV)
            .map_err(|_| PolicyEnforcementError::RuntimeNotConfigured)?;
        let bearer = std::env::var(RUNTIME_TOKEN_ENV)
            .map_err(|_| PolicyEnforcementError::RuntimeNotConfigured)?;
        let backend_binding = std::env::var(BACKEND_BINDING_SECRET_ENV)
            .map_err(|_| PolicyEnforcementError::InvalidBackendBinding)?;
        Self::new(&url, bearer, &backend_binding)
    }

    pub fn new(
        url: &str,
        bearer: String,
        backend_binding_secret: &str,
    ) -> Result<Self, PolicyEnforcementError> {
        let base_url = validate_runtime_url(url)?;
        validate_runtime_token(&bearer)?;
        let backend_binding = BackendBindingKey::parse(backend_binding_secret)?;
        let client = Client::builder()
            .connect_timeout(RUNTIME_TIMEOUT)
            .timeout(RUNTIME_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| PolicyEnforcementError::RuntimeUnavailable)?;
        Ok(Self {
            client,
            base_url,
            bearer,
            backend_binding,
        })
    }

    pub(super) fn derive_backend_run_id(
        &self,
        session_id: &str,
    ) -> Result<String, PolicyEnforcementError> {
        self.backend_binding.derive_run_id(session_id)
    }

    async fn post_json<T, R>(&self, path: &str, body: &T) -> Result<R, PolicyEnforcementError>
    where
        T: Serialize + Sync,
        R: for<'de> Deserialize<'de>,
    {
        self.post_json_bounded(path, body, MAX_RUNTIME_RESPONSE_BYTES)
            .await
    }

    pub(super) async fn post_json_bounded<T, R>(
        &self,
        path: &str,
        body: &T,
        max_response_bytes: usize,
    ) -> Result<R, PolicyEnforcementError>
    where
        T: Serialize + Sync,
        R: for<'de> Deserialize<'de>,
    {
        self.post_json_bounded_with_timeout(path, body, max_response_bytes, RUNTIME_TIMEOUT)
            .await
    }

    pub(super) async fn post_json_bounded_with_timeout<T, R>(
        &self,
        path: &str,
        body: &T,
        max_response_bytes: usize,
        timeout: Duration,
    ) -> Result<R, PolicyEnforcementError>
    where
        T: Serialize + Sync,
        R: for<'de> Deserialize<'de>,
    {
        if timeout.is_zero() || timeout > Duration::from_secs(10 * 60) {
            return Err(PolicyEnforcementError::InvalidField("runtime_timeout"));
        }
        let endpoint = self
            .base_url
            .join(path)
            .map_err(|_| PolicyEnforcementError::InvalidRuntimeEndpoint)?;
        let response = self
            .client
            .post(endpoint)
            .bearer_auth(&self.bearer)
            .header("Cache-Control", "no-store")
            .json(body)
            .timeout(timeout)
            .send()
            .await
            .map_err(|_| PolicyEnforcementError::RuntimeUnavailable)?;

        if response.status() != StatusCode::OK {
            return Err(PolicyEnforcementError::RuntimeUnavailable);
        }
        if response
            .content_length()
            .is_some_and(|length| length > max_response_bytes as u64)
        {
            return Err(PolicyEnforcementError::InvalidRuntimeResponse);
        }

        let mut bytes = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| PolicyEnforcementError::RuntimeUnavailable)?;
            if bytes.len().saturating_add(chunk.len()) > max_response_bytes {
                return Err(PolicyEnforcementError::InvalidRuntimeResponse);
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| PolicyEnforcementError::InvalidRuntimeResponse)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeAuthorizationResponse {
    schema_version: u16,
    decision: RuntimeDecision,
    proposal_digest: String,
    request_hash: Option<String>,
    authorization_id: Option<String>,
    reason_code: String,
    issued_at: Option<i64>,
    not_before: Option<i64>,
    expires_at: Option<i64>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum RuntimeDecision {
    Allow,
    Deny,
    ApprovalRequired,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeToolExecutionObservationResponse {
    schema_version: u16,
    recorded: bool,
    authorization_id: String,
    observation_digest: String,
    record_id: String,
    record_hash: String,
}

#[async_trait]
impl PolicyEnforcementPoint for RuntimePolicyEnforcementPoint {
    fn derive_run_id(&self, session_id: &str) -> Result<String, PolicyEnforcementError> {
        self.derive_backend_run_id(session_id)
    }

    async fn authorize_and_consume(
        &self,
        request: &ToolExecutionRequest,
    ) -> Result<ExecutionAuthorization, PolicyEnforcementError> {
        let expected_digest = request.digest()?;
        let response: RuntimeAuthorizationResponse =
            self.post_json(AUTHORIZE_PATH, request).await?;
        if response.schema_version != PROTOCOL_VERSION
            || response.proposal_digest != expected_digest
            || validate_digest(&response.proposal_digest).is_err()
        {
            return Err(PolicyEnforcementError::InvalidRuntimeResponse);
        }
        match response.decision {
            RuntimeDecision::Allow => {
                if response.reason_code != "ALLOWED" {
                    return Err(PolicyEnforcementError::InvalidRuntimeResponse);
                }
                let authorization_id = response
                    .authorization_id
                    .ok_or(PolicyEnforcementError::InvalidRuntimeResponse)?;
                let request_hash = response
                    .request_hash
                    .ok_or(PolicyEnforcementError::InvalidRuntimeResponse)?;
                validate_authorization_id(&authorization_id)?;
                validate_digest(&request_hash)?;
                let issued_at = response
                    .issued_at
                    .ok_or(PolicyEnforcementError::InvalidRuntimeResponse)?;
                let not_before = response
                    .not_before
                    .ok_or(PolicyEnforcementError::InvalidRuntimeResponse)?;
                let expires_at = response
                    .expires_at
                    .ok_or(PolicyEnforcementError::InvalidRuntimeResponse)?;
                let authorization = ExecutionAuthorization {
                    authorization_id,
                    proposal_digest: response.proposal_digest,
                    request_hash,
                    issued_at,
                    not_before,
                    expires_at,
                };
                authorization
                    .ensure_current(chrono::Utc::now().timestamp())
                    .map_err(|_| PolicyEnforcementError::InvalidRuntimeResponse)?;
                Ok(authorization)
            }
            RuntimeDecision::Deny => {
                if response.authorization_id.is_some()
                    || response.request_hash.is_some()
                    || response.issued_at.is_some()
                    || response.not_before.is_some()
                    || response.expires_at.is_some()
                    || validate_reason_code(&response.reason_code).is_err()
                {
                    return Err(PolicyEnforcementError::InvalidRuntimeResponse);
                }
                Err(PolicyEnforcementError::Denied(response.reason_code))
            }
            RuntimeDecision::ApprovalRequired => {
                if response.authorization_id.is_some()
                    || response.request_hash.is_some()
                    || response.issued_at.is_some()
                    || response.not_before.is_some()
                    || response.expires_at.is_some()
                    || validate_reason_code(&response.reason_code).is_err()
                {
                    return Err(PolicyEnforcementError::InvalidRuntimeResponse);
                }
                Err(PolicyEnforcementError::ApprovalRequired(
                    response.reason_code,
                ))
            }
        }
    }

    async fn record_execution(
        &self,
        record: &ToolExecutionObservation,
    ) -> Result<(), PolicyEnforcementError> {
        let expected_digest = record.digest()?;
        let response: RuntimeToolExecutionObservationResponse =
            self.post_json(RECORD_PATH, record).await?;
        if response.schema_version != PROTOCOL_VERSION
            || !response.recorded
            || response.authorization_id != record.authorization_id
            || response.observation_digest != expected_digest
            || validate_digest(&response.observation_digest).is_err()
            || validate_authorization_id(&response.record_id).is_err()
            || validate_digest(&response.record_hash).is_err()
        {
            return Err(PolicyEnforcementError::ExecutionUnknown);
        }
        Ok(())
    }
}

#[cfg(feature = "accordlock-distribution")]
struct UnavailablePolicyEnforcementPoint;

#[async_trait]
#[cfg(feature = "accordlock-distribution")]
impl PolicyEnforcementPoint for UnavailablePolicyEnforcementPoint {
    fn derive_run_id(&self, _session_id: &str) -> Result<String, PolicyEnforcementError> {
        Err(PolicyEnforcementError::RuntimeNotConfigured)
    }

    async fn authorize_and_consume(
        &self,
        _request: &ToolExecutionRequest,
    ) -> Result<ExecutionAuthorization, PolicyEnforcementError> {
        Err(PolicyEnforcementError::RuntimeNotConfigured)
    }

    async fn record_execution(
        &self,
        _record: &ToolExecutionObservation,
    ) -> Result<(), PolicyEnforcementError> {
        Err(PolicyEnforcementError::ExecutionUnknown)
    }
}

pub fn default_policy_enforcement_point() -> Arc<dyn PolicyEnforcementPoint> {
    #[cfg(feature = "accordlock-distribution")]
    {
        RuntimePolicyEnforcementPoint::from_environment()
            .map(|point| Arc::new(point) as Arc<dyn PolicyEnforcementPoint>)
            .unwrap_or_else(|_| Arc::new(UnavailablePolicyEnforcementPoint))
    }
    #[cfg(not(feature = "accordlock-distribution"))]
    {
        Arc::new(UpstreamPassthroughPolicyEnforcementPoint)
    }
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), PolicyEnforcementError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        return Err(PolicyEnforcementError::InvalidField(field));
    }
    Ok(())
}

pub(super) fn validate_authorization_id(value: &str) -> Result<(), PolicyEnforcementError> {
    match uuid::Uuid::parse_str(value) {
        Ok(identifier) if !identifier.is_nil() => Ok(()),
        _ => Err(PolicyEnforcementError::InvalidRuntimeResponse),
    }
}

pub(super) fn validate_reason_code(value: &str) -> Result<(), PolicyEnforcementError> {
    if value.is_empty()
        || value.len() > MAX_REASON_CODE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(PolicyEnforcementError::InvalidRuntimeResponse);
    }
    Ok(())
}

fn validate_runtime_token(value: &str) -> Result<(), PolicyEnforcementError> {
    if value.len() < MIN_RUNTIME_TOKEN_BYTES
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(PolicyEnforcementError::InvalidField("runtime_token"));
    }
    Ok(())
}

pub(super) fn validate_digest(value: &str) -> Result<(), PolicyEnforcementError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(PolicyEnforcementError::InvalidRuntimeResponse);
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PolicyEnforcementError::InvalidRuntimeResponse);
    }
    Ok(())
}

fn canonical_workspace(path: &Path) -> Result<String, PolicyEnforcementError> {
    let canonical: PathBuf =
        std::fs::canonicalize(path).map_err(|_| PolicyEnforcementError::InvalidWorkspace)?;
    canonical
        .to_str()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or(PolicyEnforcementError::InvalidWorkspace)
}

pub(super) fn canonical_json_bytes<T: Serialize + ?Sized>(
    value: &T,
) -> Result<Vec<u8>, PolicyEnforcementError> {
    let value =
        serde_json::to_value(value).map_err(|_| PolicyEnforcementError::InvalidRuntimeResponse)?;
    let sorted = sort_json(value);
    serde_json::to_vec(&sorted).map_err(|_| PolicyEnforcementError::InvalidRuntimeResponse)
}

fn sort_json(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(sort_json).collect()),
        Value::Object(values) => {
            let mut entries: Vec<_> = values.into_iter().collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key, sort_json(value)))
                    .collect(),
            )
        }
        scalar => scalar,
    }
}

pub(super) fn sha256_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut value = String::with_capacity(71);
    value.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(value, "{byte:02x}");
    }
    value
}

fn validate_runtime_url(value: &str) -> Result<Url, PolicyEnforcementError> {
    let mut url = Url::parse(value).map_err(|_| PolicyEnforcementError::InvalidRuntimeEndpoint)?;
    if url.scheme() != "http"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port().is_none()
        || url.path() != "/"
    {
        return Err(PolicyEnforcementError::InvalidRuntimeEndpoint);
    }
    let is_loopback = url
        .host_str()
        .map(|host| host.trim_start_matches('[').trim_end_matches(']'))
        .and_then(|host| host.parse::<std::net::IpAddr>().ok())
        .is_some_and(|address| address.is_loopback());
    if !is_loopback {
        return Err(PolicyEnforcementError::InvalidRuntimeEndpoint);
    }
    url.set_path("/");
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ZERO_BINDING_SECRET: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn test_run_id(session_id: &str) -> String {
        derive_backend_run_id(ZERO_BINDING_SECRET, session_id).unwrap()
    }

    fn test_plan(
        session_id: &str,
        tool_call_id: &str,
        tool_name: &str,
        arguments: Value,
    ) -> AgentPlanCheckpointInput {
        let arguments_sha256 = sha256_digest(&canonical_json_bytes(&arguments).unwrap());
        AgentPlanCheckpointInput::new(
            session_id.to_owned(),
            tool_call_id.to_owned(),
            json!({
                "text": [],
                "tool_requests": [{
                    "id": tool_call_id,
                    "name": tool_name,
                    "arguments_sha256": arguments_sha256,
                }]
            }),
            1_800_000_000,
        )
        .unwrap()
    }

    #[test]
    fn backend_binding_matches_the_cross_language_vector() {
        assert_eq!(
            test_run_id("session-alpha"),
            "sha256:25afda2a41396a99b76fc018ceae13ee86304c4e235c798c3d87478c3b8f13ad"
        );
    }

    #[test]
    fn backend_binding_rejects_malformed_secrets_and_sessions() {
        for secret in [
            "",
            "short",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+",
        ] {
            assert_eq!(
                derive_backend_run_id(secret, "session").unwrap_err(),
                PolicyEnforcementError::InvalidBackendBinding
            );
        }
        assert_eq!(
            derive_backend_run_id(ZERO_BINDING_SECRET, "line\nbreak").unwrap_err(),
            PolicyEnforcementError::InvalidField("session_id")
        );
    }

    #[test]
    fn canonical_argument_hash_is_key_order_independent() {
        let dir = tempfile::tempdir().unwrap();
        let run_id = test_run_id("session");
        let first = ToolExecutionRequest::new(ToolExecutionRequestParams {
            session_id: "session",
            run_id: &run_id,
            request_id: Some("run"),
            working_dir: Some(dir.path()),
            extension_id: "developer",
            tool_name: "write",
            plan_tool_name: "write",
            arguments: json!({"b": 2, "a": {"d": 4, "c": 3}}),
            plan_checkpoint_input: Some(&test_plan(
                "session",
                "run",
                "write",
                json!({"b": 2, "a": {"d": 4, "c": 3}}),
            )),
        })
        .unwrap();
        let second = ToolExecutionRequest::new(ToolExecutionRequestParams {
            session_id: "session",
            run_id: &run_id,
            request_id: Some("run"),
            working_dir: Some(dir.path()),
            extension_id: "developer",
            tool_name: "write",
            plan_tool_name: "write",
            arguments: json!({"a": {"c": 3, "d": 4}, "b": 2}),
            plan_checkpoint_input: Some(&test_plan(
                "session",
                "run",
                "write",
                json!({"a": {"c": 3, "d": 4}, "b": 2}),
            )),
        })
        .unwrap();
        assert_eq!(first.arguments_sha256, second.arguments_sha256);
        assert_eq!(first.digest().unwrap(), second.digest().unwrap());
    }

    #[test]
    fn argument_mutation_changes_exact_binding() {
        let dir = tempfile::tempdir().unwrap();
        let run_id = test_run_id("session");
        let first = ToolExecutionRequest::new(ToolExecutionRequestParams {
            session_id: "session",
            run_id: &run_id,
            request_id: Some("run"),
            working_dir: Some(dir.path()),
            extension_id: "developer",
            tool_name: "write",
            plan_tool_name: "write",
            arguments: json!({"path": "a.txt", "content": "one"}),
            plan_checkpoint_input: Some(&test_plan(
                "session",
                "run",
                "write",
                json!({"path": "a.txt", "content": "one"}),
            )),
        })
        .unwrap();
        let second = ToolExecutionRequest::new(ToolExecutionRequestParams {
            session_id: "session",
            run_id: &run_id,
            request_id: Some("run"),
            working_dir: Some(dir.path()),
            extension_id: "developer",
            tool_name: "write",
            plan_tool_name: "write",
            arguments: json!({"path": "a.txt", "content": "two"}),
            plan_checkpoint_input: Some(&test_plan(
                "session",
                "run",
                "write",
                json!({"path": "a.txt", "content": "two"}),
            )),
        })
        .unwrap();
        assert_ne!(first.arguments_sha256, second.arguments_sha256);
        assert_ne!(first.digest().unwrap(), second.digest().unwrap());
    }

    #[test]
    fn missing_request_or_workspace_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let run_id = test_run_id("session");
        assert_eq!(
            ToolExecutionRequest::new(ToolExecutionRequestParams {
                session_id: "session",
                run_id: &run_id,
                request_id: None,
                working_dir: Some(dir.path()),
                extension_id: "ext",
                tool_name: "tool",
                plan_tool_name: "tool",
                arguments: json!({}),
                plan_checkpoint_input: Some(&test_plan("session", "unused", "tool", json!({}))),
            })
            .unwrap_err(),
            PolicyEnforcementError::MissingRequestId
        );
        assert_eq!(
            ToolExecutionRequest::new(ToolExecutionRequestParams {
                session_id: "session",
                run_id: &run_id,
                request_id: Some("run"),
                working_dir: None,
                extension_id: "ext",
                tool_name: "tool",
                plan_tool_name: "tool",
                arguments: json!({}),
                plan_checkpoint_input: Some(&test_plan("session", "run", "tool", json!({}))),
            })
            .unwrap_err(),
            PolicyEnforcementError::InvalidWorkspace
        );
    }

    #[test]
    fn runtime_endpoint_accepts_only_literal_loopback_http() {
        assert!(validate_runtime_url("http://127.0.0.1:43127").is_ok());
        assert!(validate_runtime_url("http://[::1]:43127").is_ok());
        assert!(validate_runtime_url("http://localhost:43127").is_err());
        assert!(validate_runtime_url("https://127.0.0.1:43127").is_err());
        assert!(validate_runtime_url("http://10.0.0.2:43127").is_err());
        assert!(validate_runtime_url("http://127.0.0.1:43127/other").is_err());
        assert!(validate_runtime_url("http://127.0.0.1:43127?token=leak").is_err());
    }

    #[test]
    fn runtime_capability_has_a_strict_nontrivial_profile() {
        assert!(validate_runtime_token("0123456789abcdef0123456789abcdef").is_ok());
        assert!(validate_runtime_token("short").is_err());
        assert!(validate_runtime_token("0123456789abcdef0123456789abcde ").is_err());
        assert!(validate_runtime_token("0123456789abcdef0123456789abcde ").is_err());
    }

    #[test]
    fn execution_record_commitment_binds_outcome_and_result() {
        let authorization = ExecutionAuthorization {
            authorization_id: uuid::Uuid::from_u128(1).to_string(),
            proposal_digest: sha256_digest(b"proposal"),
            request_hash: sha256_digest(b"intent"),
            issued_at: 1,
            not_before: 1,
            expires_at: 2,
        };
        let succeeded = ToolExecutionObservation::new(
            &authorization,
            ExecutionOutcome::Succeeded,
            Some(&json!({"ok": true})),
        )
        .unwrap();
        let failed = ToolExecutionObservation::new(
            &authorization,
            ExecutionOutcome::ToolReportedError,
            Some(&json!({"ok": true})),
        )
        .unwrap();
        let changed = ToolExecutionObservation::new(
            &authorization,
            ExecutionOutcome::Succeeded,
            Some(&json!({"ok": false})),
        )
        .unwrap();

        assert_ne!(succeeded.digest().unwrap(), failed.digest().unwrap());
        assert_ne!(succeeded.digest().unwrap(), changed.digest().unwrap());
    }

    #[test]
    fn authorization_window_is_short_lived_and_half_open() {
        let authorization = ExecutionAuthorization {
            authorization_id: uuid::Uuid::from_u128(1).to_string(),
            proposal_digest: sha256_digest(b"proposal"),
            request_hash: sha256_digest(b"intent"),
            issued_at: 10,
            not_before: 11,
            expires_at: 20,
        };
        assert!(authorization.ensure_current(10).is_err());
        assert!(authorization.ensure_current(11).is_ok());
        assert!(authorization.ensure_current(19).is_ok());
        assert!(authorization.ensure_current(20).is_err());
    }
}
