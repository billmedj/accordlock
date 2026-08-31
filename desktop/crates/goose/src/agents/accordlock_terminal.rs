//! Trusted terminal execution boundary for the AccordLock distribution.
//!
//! The model proposes a bounded direct argv invocation. Goose never resolves
//! or spawns that program: the trusted runtime binds `argv[0]` to an
//! administrator-configured executable, authorizes the exact request,
//! consumes single-use authorization, executes, and writes the execution record
//! in one request. An ambiguous response is always an unknown execution status.

#![cfg_attr(not(feature = "accordlock-distribution"), allow(dead_code))]

use async_trait::async_trait;
use rmcp::model::{CallToolResult, ContentBlock};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
#[cfg(test)]
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

#[cfg(test)]
use super::accordlock_authorization::ToolExecutionRequestParams;
use super::accordlock_authorization::{
    canonical_json_bytes, sha256_digest, validate_authorization_id, validate_digest,
    validate_reason_code, PolicyEnforcementError, RuntimePolicyEnforcementPoint,
    ToolExecutionRequest, PROTOCOL_VERSION,
};
use super::accordlock_filesystem::ExecutionEvidence;

pub(super) const TERMINAL_EXECUTE_PATH: &str = "/api/v2/execution/terminal/authorize-and-execute";
const ACTION_APPROVAL_SCHEMA_VERSION: u16 = 2;
// The runtime captures at most 256 KiB per byte stream. Older compatible
// runtimes may replace each one-byte environment value with the fourteen-byte
// `[REDACTED_ENV]` marker; eight MiB covers both maximally expanded streams,
// JSON framing, and the bounded execution-record/approval metadata.
const MAX_TERMINAL_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_RENDERED_OUTPUT_EXPANSION: usize = 14;
const MAX_ARG_COUNT: usize = 128;
const MAX_ARG_BYTES: usize = 4 * 1024;
const MAX_TOTAL_ARG_BYTES: usize = 64 * 1024;
const MAX_ENVIRONMENT_ENTRIES: usize = 16;
const MAX_ENVIRONMENT_VALUE_BYTES: usize = 256;
const MAX_RELATIVE_CWD_BYTES: usize = 4 * 1024;
const MAX_CWD_COMPONENTS: usize = 64;
const MAX_TIMEOUT_SECONDS: u32 = 5 * 60;
const DEFAULT_TIMEOUT_SECONDS: u32 = 60;
const MAX_OUTPUT_BYTES: u32 = 256 * 1024;
const DEFAULT_OUTPUT_BYTES: u32 = 64 * 1024;
const HTTP_COMPLETION_GRACE_SECONDS: u64 = 20;

const ALLOWED_ENVIRONMENT: &[&str] = &[
    "CARGO_TERM_COLOR",
    "CI",
    "LANG",
    "LC_ALL",
    "NODE_ENV",
    "NO_COLOR",
    "RUST_BACKTRACE",
    "TERM",
    "TZ",
];

const ACCORDLOCK_AUTHORITY_ENV_KEYS: &[&str] = &[
    "ACCORDLOCK_RUNTIME_URL",
    "ACCORDLOCK_RUNTIME_TOKEN",
    "ACCORDLOCK_BACKEND_BINDING_SECRET",
];

const BANNED_EXECUTABLE_ALIASES: &[&str] = &[
    "bash",
    "cmd",
    "cscript",
    "dash",
    "fish",
    "mshta",
    "powershell",
    "pwsh",
    "regsvr32",
    "rundll32",
    "sh",
    "wscript",
    "wsl",
    "zsh",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct BrokeredTerminalArguments {
    /// Configured program alias followed by literal arguments. No shell string.
    pub argv: Vec<String>,
    #[serde(default = "default_cwd")]
    pub cwd: String,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u32,
    #[serde(default = "default_output_bytes")]
    pub max_output_bytes: u32,
}

fn default_cwd() -> String {
    ".".to_owned()
}

const fn default_timeout_seconds() -> u32 {
    DEFAULT_TIMEOUT_SECONDS
}

const fn default_output_bytes() -> u32 {
    DEFAULT_OUTPUT_BYTES
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum BrokeredProcessOutcome {
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct BrokeredTerminalResult {
    pub program: String,
    pub exit_code: Option<i32>,
    pub outcome: BrokeredProcessOutcome,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub encoding_lossy: bool,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct BrokeredTerminalOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<BrokeredTerminalResult>,
    accordlock: AccordLockTerminalMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct AccordLockTerminalMetadata {
    schema_version: u16,
    status: String,
    reason_code: String,
    authorization_id: String,
    request_hash: String,
    record_id: String,
    record_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    result_sha256: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct TerminalExecutionRequest<'a> {
    schema_version: u16,
    proposal: &'a ToolExecutionRequest,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalExecutionResponse {
    schema_version: u16,
    proposal_digest: String,
    status: TerminalExecutionStatus,
    reason_code: String,
    authorization_id: Option<String>,
    request_hash: Option<String>,
    record_id: Option<String>,
    record_hash: Option<String>,
    result_sha256: Option<String>,
    result: Option<BrokeredTerminalResult>,
    approval_request: Option<ActionApprovalRequest>,
    approval_request_hash: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum TerminalExecutionStatus {
    Succeeded,
    ExecutionUnknown,
    Denied,
    ApprovalRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionApprovalRequest {
    schema_version: u16,
    task_id: String,
    session_id: String,
    run_id: String,
    tool_call_id: String,
    proposal_digest: String,
    task_policy_hash: String,
    prestate_hash: String,
    action: ActionRequest,
    task_requirement: TaskRequirement,
    transformation_step: TransformationStep,
    policy_decision: PolicyDecisionRecord,
    policy_decision_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionRequest {
    extension_id: String,
    tool_name: String,
    relative_path: String,
    action_type: ActionType,
    requested_bytes: u64,
    executable_path: String,
    executable_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ActionType {
    CreateFile,
    OverwriteFile,
    EditFile,
    ExecuteProcess,
    HttpsRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskRequirement {
    schema_version: u16,
    requirement_id: String,
    task_policy_hash: String,
    statement_hash: String,
    minimum_conformance_score_ppm: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransformationStep {
    schema_version: u16,
    step_id: String,
    task_policy_hash: String,
    sequence: u64,
    parent_step_hash: Option<String>,
    source_stage: TransformationStage,
    source_hash: String,
    target_stage: TransformationStage,
    target_hash: String,
    recorded_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum TransformationStage {
    Intention,
    Decision,
    Specification,
    Plan,
    Action,
    Execution,
    Observation,
    Result,
    Communication,
    Memory,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDecisionRecord {
    schema_version: u16,
    decision_id: String,
    task_policy_hash: String,
    action_hash: String,
    sequence: u64,
    previous_decision_hash: Option<String>,
    requirement_hashes: Vec<String>,
    transformation_step_hashes: Vec<String>,
    conformance_evaluation_hashes: Vec<String>,
    resource_request_hashes: Vec<String>,
    resource_quota_hashes: Vec<String>,
    resource_reservation_hashes: Vec<String>,
    baseline: PolicyDecision,
    decision: PolicyDecision,
    reasons: Vec<DecisionReason>,
    policy_epoch: u64,
    evaluated_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum PolicyDecision {
    AllowAutomatic,
    RequireApproval,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum DecisionReason {
    TaskConformanceThresholdMet,
    TaskConformanceEvidenceMissing,
    TaskConformanceIndeterminate,
    TaskConformanceThresholdIndeterminate,
    TaskConformanceThresholdNotMet,
    TaskRequirementViolation,
    ConformanceEvidenceBindingMismatch,
    ResourceQuotaMissing,
    ResourceReservationMissing,
    ResourceQuotaExceeded,
    ResourceBindingMismatch,
    ResourceReservationValid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedTerminalOperation {
    arguments: BrokeredTerminalArguments,
    requested_bytes: u64,
}

#[derive(Debug, Clone)]
pub(super) enum BrokeredTerminalOutcome {
    Succeeded {
        result: BrokeredTerminalResult,
        result_sha256: String,
        evidence: ExecutionEvidence,
    },
}

impl BrokeredTerminalOutcome {
    pub(super) fn into_call_tool_result(self) -> CallToolResult {
        match self {
            Self::Succeeded {
                result,
                result_sha256,
                evidence,
            } => {
                let mut text = result.stdout.clone();
                if !result.stderr.is_empty() {
                    if !text.is_empty() && !text.ends_with('\n') {
                        text.push('\n');
                    }
                    text.push_str(&result.stderr);
                }
                if text.is_empty() {
                    text = format!(
                        "{} exited with {}",
                        result.program,
                        result
                            .exit_code
                            .map_or_else(|| "no exit code".to_owned(), |code| code.to_string())
                    );
                }
                let is_error = result.outcome == BrokeredProcessOutcome::Failed;
                let mut call_result = if is_error {
                    CallToolResult::error(vec![ContentBlock::text(text)])
                } else {
                    CallToolResult::success(vec![ContentBlock::text(text)])
                };
                let output = BrokeredTerminalOutput {
                    result: Some(result),
                    accordlock: AccordLockTerminalMetadata {
                        schema_version: PROTOCOL_VERSION,
                        status: "SUCCEEDED".to_owned(),
                        reason_code: "EXECUTED".to_owned(),
                        authorization_id: evidence.authorization_id,
                        request_hash: evidence.request_hash,
                        record_id: evidence.record_id,
                        record_hash: evidence.record_hash,
                        result_sha256: Some(result_sha256),
                    },
                };
                call_result.structured_content = serde_json::to_value(output).ok();
                call_result
            }
        }
    }
}

#[async_trait]
pub(super) trait TerminalBroker: Send + Sync {
    fn enforces_boundary(&self) -> bool;

    fn derive_run_id(&self, session_id: &str) -> Result<String, PolicyEnforcementError>;

    async fn authorize_and_execute(
        &self,
        request: &ToolExecutionRequest,
    ) -> Result<BrokeredTerminalOutcome, PolicyEnforcementError>;
}

#[cfg(not(feature = "accordlock-distribution"))]
struct UpstreamTerminalBroker;

#[async_trait]
#[cfg(not(feature = "accordlock-distribution"))]
impl TerminalBroker for UpstreamTerminalBroker {
    fn enforces_boundary(&self) -> bool {
        false
    }

    fn derive_run_id(&self, _session_id: &str) -> Result<String, PolicyEnforcementError> {
        Err(PolicyEnforcementError::RuntimeNotConfigured)
    }

    async fn authorize_and_execute(
        &self,
        _request: &ToolExecutionRequest,
    ) -> Result<BrokeredTerminalOutcome, PolicyEnforcementError> {
        Err(PolicyEnforcementError::RuntimeNotConfigured)
    }
}

#[derive(Clone)]
struct RuntimeTerminalBroker {
    runtime: RuntimePolicyEnforcementPoint,
}

impl RuntimeTerminalBroker {
    fn from_environment() -> Result<Self, PolicyEnforcementError> {
        Ok(Self {
            runtime: RuntimePolicyEnforcementPoint::from_environment()?,
        })
    }

    #[cfg(test)]
    fn new(url: &str, bearer: String) -> Result<Self, PolicyEnforcementError> {
        Ok(Self {
            runtime: RuntimePolicyEnforcementPoint::new(
                url,
                bearer,
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            )?,
        })
    }
}

#[async_trait]
impl TerminalBroker for RuntimeTerminalBroker {
    fn enforces_boundary(&self) -> bool {
        true
    }

    fn derive_run_id(&self, session_id: &str) -> Result<String, PolicyEnforcementError> {
        self.runtime.derive_backend_run_id(session_id)
    }

    async fn authorize_and_execute(
        &self,
        execution_request: &ToolExecutionRequest,
    ) -> Result<BrokeredTerminalOutcome, PolicyEnforcementError> {
        let operation = validate_execution_request(execution_request)?;
        let expected_proposal_digest = execution_request.digest()?;
        let request = TerminalExecutionRequest {
            schema_version: PROTOCOL_VERSION,
            proposal: execution_request,
        };
        let request_timeout = terminal_http_timeout(&operation);
        let response: TerminalExecutionResponse = self
            .runtime
            .post_json_bounded_with_timeout(
                TERMINAL_EXECUTE_PATH,
                &request,
                MAX_TERMINAL_RESPONSE_BYTES,
                request_timeout,
            )
            .await
            .map_err(|_| PolicyEnforcementError::ExecutionUnknown)?;
        validate_response(
            response,
            &operation,
            execution_request,
            &expected_proposal_digest,
        )
    }
}

fn terminal_http_timeout(operation: &ValidatedTerminalOperation) -> Duration {
    Duration::from_secs(
        u64::from(operation.arguments.timeout_seconds) + HTTP_COMPLETION_GRACE_SECONDS,
    )
}

#[cfg(feature = "accordlock-distribution")]
struct UnavailableTerminalBroker;

#[async_trait]
#[cfg(feature = "accordlock-distribution")]
impl TerminalBroker for UnavailableTerminalBroker {
    fn enforces_boundary(&self) -> bool {
        true
    }

    fn derive_run_id(&self, _session_id: &str) -> Result<String, PolicyEnforcementError> {
        Err(PolicyEnforcementError::RuntimeNotConfigured)
    }

    async fn authorize_and_execute(
        &self,
        _request: &ToolExecutionRequest,
    ) -> Result<BrokeredTerminalOutcome, PolicyEnforcementError> {
        Err(PolicyEnforcementError::RuntimeNotConfigured)
    }
}

pub(super) fn default_terminal_broker() -> Arc<dyn TerminalBroker> {
    #[cfg(feature = "accordlock-distribution")]
    {
        RuntimeTerminalBroker::from_environment()
            .map(|broker| Arc::new(broker) as Arc<dyn TerminalBroker>)
            .unwrap_or_else(|_| Arc::new(UnavailableTerminalBroker))
    }
    #[cfg(not(feature = "accordlock-distribution"))]
    {
        Arc::new(UpstreamTerminalBroker)
    }
}

pub(super) fn is_brokered(extension_id: &str, tool_name: &str) -> bool {
    extension_id == "developer" && tool_name == "shell"
}

fn validate_execution_request(
    execution_request: &ToolExecutionRequest,
) -> Result<ValidatedTerminalOperation, PolicyEnforcementError> {
    if !is_brokered(
        &execution_request.extension_id,
        &execution_request.tool_name,
    ) {
        return Err(PolicyEnforcementError::InvalidField("tool_name"));
    }
    let arguments: BrokeredTerminalArguments =
        serde_json::from_value(execution_request.arguments.clone())
            .map_err(|_| PolicyEnforcementError::InvalidField("arguments"))?;
    validate_argv(&arguments.argv)?;
    validate_relative_cwd(&arguments.cwd)?;
    validate_environment(&arguments.env)?;
    if !(1..=MAX_TIMEOUT_SECONDS).contains(&arguments.timeout_seconds) {
        return Err(PolicyEnforcementError::InvalidField("timeout_seconds"));
    }
    if !(1..=MAX_OUTPUT_BYTES).contains(&arguments.max_output_bytes) {
        return Err(PolicyEnforcementError::InvalidField("max_output_bytes"));
    }
    let requested_bytes = arguments
        .argv
        .iter()
        .skip(1)
        .map(String::len)
        .chain(arguments.env.values().map(String::len))
        .try_fold(0_u64, |sum, size| {
            sum.checked_add(u64::try_from(size).ok()?)
        })
        .ok_or(PolicyEnforcementError::ArgumentsTooLarge)?;
    Ok(ValidatedTerminalOperation {
        arguments,
        requested_bytes,
    })
}

fn validate_argv(argv: &[String]) -> Result<(), PolicyEnforcementError> {
    if argv.is_empty() || argv.len() > MAX_ARG_COUNT || !valid_alias(&argv[0]) {
        return Err(PolicyEnforcementError::InvalidField("argv"));
    }
    let mut total = 0_usize;
    for argument in argv {
        if argument.len() > MAX_ARG_BYTES || argument.chars().any(char::is_control) {
            return Err(PolicyEnforcementError::InvalidField("argv"));
        }
        total = total
            .checked_add(argument.len())
            .ok_or(PolicyEnforcementError::ArgumentsTooLarge)?;
    }
    if total > MAX_TOTAL_ARG_BYTES {
        return Err(PolicyEnforcementError::ArgumentsTooLarge);
    }
    Ok(())
}

fn valid_alias(alias: &str) -> bool {
    !alias.is_empty()
        && alias.len() <= 64
        && alias == alias.to_ascii_lowercase()
        && alias.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
        && !BANNED_EXECUTABLE_ALIASES.contains(&alias)
}

fn validate_relative_cwd(cwd: &str) -> Result<(), PolicyEnforcementError> {
    if cwd == "." {
        return Ok(());
    }
    if cwd.is_empty()
        || cwd.len() > MAX_RELATIVE_CWD_BYTES
        || cwd.starts_with(['/', '\\'])
        || cwd.contains(['\\', ':'])
        || cwd.chars().any(char::is_control)
    {
        return Err(PolicyEnforcementError::InvalidField("cwd"));
    }
    let components = cwd.split('/').collect::<Vec<_>>();
    if components.len() > MAX_CWD_COMPONENTS
        || components.iter().any(|component| {
            component.is_empty()
                || matches!(*component, "." | "..")
                || component.ends_with(['.', ' '])
        })
    {
        return Err(PolicyEnforcementError::InvalidField("cwd"));
    }
    Ok(())
}

fn validate_environment(
    environment: &BTreeMap<String, String>,
) -> Result<(), PolicyEnforcementError> {
    if environment.len() > MAX_ENVIRONMENT_ENTRIES {
        return Err(PolicyEnforcementError::InvalidField("env"));
    }
    for (name, value) in environment {
        if ACCORDLOCK_AUTHORITY_ENV_KEYS
            .iter()
            .any(|secret| secret.eq_ignore_ascii_case(name))
            || !ALLOWED_ENVIRONMENT.contains(&name.as_str())
            || value.len() > MAX_ENVIRONMENT_VALUE_BYTES
            || !valid_environment_value(name, value)
        {
            return Err(PolicyEnforcementError::InvalidField("env"));
        }
    }
    Ok(())
}

fn valid_environment_value(name: &str, value: &str) -> bool {
    match name {
        "CI" => matches!(value, "1" | "true"),
        "NO_COLOR" => value == "1",
        "CARGO_TERM_COLOR" => matches!(value, "auto" | "always" | "never"),
        "NODE_ENV" => matches!(value, "development" | "production" | "test"),
        "RUST_BACKTRACE" => matches!(value, "0" | "1"),
        "TERM" => matches!(value, "dumb" | "xterm" | "xterm-256color"),
        "LANG" | "LC_ALL" => matches!(value, "C" | "C.UTF-8" | "en_US.UTF-8"),
        "TZ" => value == "UTC",
        _ => false,
    }
}

fn validate_response(
    response: TerminalExecutionResponse,
    operation: &ValidatedTerminalOperation,
    execution_request: &ToolExecutionRequest,
    expected_proposal_digest: &str,
) -> Result<BrokeredTerminalOutcome, PolicyEnforcementError> {
    if response.schema_version != PROTOCOL_VERSION
        || response.proposal_digest != expected_proposal_digest
        || validate_digest(&response.proposal_digest).is_err()
        || validate_reason_code(&response.reason_code).is_err()
    {
        return Err(PolicyEnforcementError::ExecutionUnknown);
    }

    match response.status {
        TerminalExecutionStatus::Succeeded => {
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
            validate_digest(&result_sha256)
                .map_err(|_| PolicyEnforcementError::ExecutionUnknown)?;
            let expected_result_sha256 = canonical_json_bytes(&result)
                .map(|bytes| sha256_digest(&bytes))
                .map_err(|_| PolicyEnforcementError::ExecutionUnknown)?;
            if result_sha256 != expected_result_sha256
                || result.program != operation.arguments.argv[0]
                || !valid_rendered_output_bound(
                    &result.stdout,
                    operation.arguments.max_output_bytes,
                )
                || !valid_rendered_output_bound(
                    &result.stderr,
                    operation.arguments.max_output_bytes,
                )
                || !valid_process_outcome(&result)
            {
                return Err(PolicyEnforcementError::ExecutionUnknown);
            }
            Ok(BrokeredTerminalOutcome::Succeeded {
                result,
                result_sha256,
                evidence,
            })
        }
        TerminalExecutionStatus::ExecutionUnknown => {
            if !valid_tool_error_reason(&response.reason_code)
                || response.result.is_some()
                || response.result_sha256.is_some()
                || response.approval_request.is_some()
                || response.approval_request_hash.is_some()
            {
                return Err(PolicyEnforcementError::ExecutionUnknown);
            }
            let _evidence = extract_evidence(&response)?;
            Err(PolicyEnforcementError::ExecutionUnknown)
        }
        TerminalExecutionStatus::Denied => {
            require_no_execution_evidence(&response)?;
            if !valid_denial_reason(&response.reason_code)
                || response.approval_request.is_some()
                || response.approval_request_hash.is_some()
            {
                return Err(PolicyEnforcementError::ExecutionUnknown);
            }
            Err(PolicyEnforcementError::Denied(response.reason_code))
        }
        TerminalExecutionStatus::ApprovalRequired => {
            require_no_execution_evidence(&response)?;
            if response.reason_code != "ACTION_APPROVAL_REQUIRED" {
                return Err(PolicyEnforcementError::ExecutionUnknown);
            }
            let approval_request = response
                .approval_request
                .as_ref()
                .ok_or(PolicyEnforcementError::ExecutionUnknown)?;
            let supplied_hash = response
                .approval_request_hash
                .as_deref()
                .ok_or(PolicyEnforcementError::ExecutionUnknown)?;
            validate_approval_request(
                approval_request,
                supplied_hash,
                operation,
                execution_request,
                expected_proposal_digest,
            )?;
            Err(PolicyEnforcementError::ApprovalRequired(
                response.reason_code,
            ))
        }
    }
}

fn valid_tool_error_reason(reason: &str) -> bool {
    matches!(
        reason,
        "WORKSPACE_UNAVAILABLE"
            | "WORKING_DIRECTORY_UNAVAILABLE"
            | "WORKING_DIRECTORY_ESCAPES_WORKSPACE"
            | "PROGRAM_UNAVAILABLE"
            | "PROGRAM_CHANGED"
            | "INVALID_EXECUTION_STATE"
            | "EXECUTION_STATE_CHANGED"
            | "SPAWN_FAILED"
            | "WAIT_FAILED"
            | "TIMED_OUT"
            | "OUTPUT_CAPTURE_FAILED"
    )
}

fn valid_denial_reason(reason: &str) -> bool {
    matches!(
        reason,
        "TERMINAL_PROGRAM_NOT_CONFIGURED"
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
    )
}

fn valid_process_outcome(result: &BrokeredTerminalResult) -> bool {
    match result.outcome {
        BrokeredProcessOutcome::Succeeded => result.exit_code == Some(0),
        BrokeredProcessOutcome::Failed => result.exit_code != Some(0),
    }
}

fn valid_rendered_output_bound(output: &str, captured_byte_limit: u32) -> bool {
    output.len() <= (captured_byte_limit as usize).saturating_mul(MAX_RENDERED_OUTPUT_EXPANSION)
}

fn extract_evidence(
    response: &TerminalExecutionResponse,
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
    response: &TerminalExecutionResponse,
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

fn validate_approval_request(
    approval_request: &ActionApprovalRequest,
    supplied_hash: &str,
    operation: &ValidatedTerminalOperation,
    execution_request: &ToolExecutionRequest,
    expected_proposal_digest: &str,
) -> Result<(), PolicyEnforcementError> {
    validate_digest(supplied_hash).map_err(|_| PolicyEnforcementError::ExecutionUnknown)?;
    let canonical = canonical_json_bytes(approval_request)
        .map_err(|_| PolicyEnforcementError::ExecutionUnknown)?;
    let computed_hash = domain_digest(b"accordlock:v2:action-approval-request", &canonical);
    if supplied_hash != computed_hash
        || approval_request.schema_version != ACTION_APPROVAL_SCHEMA_VERSION
        || !valid_uuid(&approval_request.task_id)
        || approval_request.session_id != execution_request.session_id
        || approval_request.run_id != execution_request.run_id
        || approval_request.tool_call_id != execution_request.tool_call_id
        || approval_request.proposal_digest != expected_proposal_digest
        || validate_digest(&approval_request.task_policy_hash).is_err()
        || validate_digest(&approval_request.prestate_hash).is_err()
        || validate_digest(&approval_request.policy_decision_hash).is_err()
        || approval_request.action.extension_id != execution_request.extension_id
        || approval_request.action.tool_name != execution_request.tool_name
        || approval_request.action.relative_path != operation.arguments.cwd
        || approval_request.action.action_type != ActionType::ExecuteProcess
        || approval_request.action.requested_bytes != operation.requested_bytes
        || !Path::new(&approval_request.action.executable_path).is_absolute()
        || validate_digest(&approval_request.action.executable_sha256).is_err()
    {
        return Err(PolicyEnforcementError::ExecutionUnknown);
    }
    validate_conformance_context(approval_request, expected_proposal_digest)
}

fn validate_conformance_context(
    approval_request: &ActionApprovalRequest,
    proposal_digest: &str,
) -> Result<(), PolicyEnforcementError> {
    let requirement = &approval_request.task_requirement;
    let step = &approval_request.transformation_step;
    let decision = &approval_request.policy_decision;
    let action_hash = action_binding_hash(
        proposal_digest,
        &approval_request.prestate_hash,
        &approval_request.action,
    )?;

    let all_digests_valid = [
        &requirement.task_policy_hash,
        &requirement.statement_hash,
        &step.task_policy_hash,
        &step.source_hash,
        &step.target_hash,
        &decision.task_policy_hash,
        &decision.action_hash,
    ]
    .into_iter()
    .all(|digest| validate_digest(digest).is_ok())
        && decision
            .requirement_hashes
            .iter()
            .chain(&decision.transformation_step_hashes)
            .chain(&decision.conformance_evaluation_hashes)
            .chain(&decision.resource_request_hashes)
            .chain(&decision.resource_quota_hashes)
            .chain(&decision.resource_reservation_hashes)
            .all(|digest| validate_digest(digest).is_ok());

    if !all_digests_valid
        || requirement.schema_version != 2
        || !valid_uuid(&requirement.requirement_id)
        || requirement.task_policy_hash != approval_request.task_policy_hash
        || requirement.minimum_conformance_score_ppm != 1_000_000
        || step.schema_version != 2
        || !valid_uuid(&step.step_id)
        || step.task_policy_hash != approval_request.task_policy_hash
        || step.sequence != 0
        || step.parent_step_hash.is_some()
        || step.source_stage != TransformationStage::Intention
        || step.source_hash != requirement.statement_hash
        || step.target_stage != TransformationStage::Action
        || step.target_hash != action_hash
        || step.recorded_at <= 0
        || decision.schema_version != 2
        || !valid_uuid(&decision.decision_id)
        || decision.task_policy_hash != approval_request.task_policy_hash
        || decision.action_hash != action_hash
        || decision.sequence != 0
        || decision.previous_decision_hash.is_some()
        || decision.requirement_hashes.len() != 1
        || decision.transformation_step_hashes.len() != 1
        || !decision.conformance_evaluation_hashes.is_empty()
        || !decision.resource_request_hashes.is_empty()
        || !decision.resource_quota_hashes.is_empty()
        || !decision.resource_reservation_hashes.is_empty()
        || decision.baseline != PolicyDecision::AllowAutomatic
        || decision.decision != PolicyDecision::RequireApproval
        || decision.reasons != [DecisionReason::TaskConformanceEvidenceMissing]
        || decision.policy_epoch == 0
        || decision.evaluated_at != step.recorded_at
    {
        return Err(PolicyEnforcementError::ExecutionUnknown);
    }
    Ok(())
}

fn action_binding_hash(
    proposal_digest: &str,
    prestate_hash: &str,
    action: &ActionRequest,
) -> Result<String, PolicyEnforcementError> {
    let binding = json!({
        "schema_version": 2,
        "proposal_digest": proposal_digest,
        "prestate_hash": prestate_hash,
        "action": action,
    });
    let canonical =
        canonical_json_bytes(&binding).map_err(|_| PolicyEnforcementError::ExecutionUnknown)?;
    Ok(domain_digest(b"accordlock:v2:action-binding", &canonical))
}

fn domain_digest(domain: &[u8], canonical: &[u8]) -> String {
    let mut input = Vec::with_capacity(domain.len() + 1 + 8 + canonical.len());
    input.extend_from_slice(domain);
    input.push(0);
    input.extend_from_slice(&(canonical.len() as u64).to_be_bytes());
    input.extend_from_slice(canonical);
    sha256_digest(&input)
}

fn valid_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value)
        .ok()
        .filter(|identifier| !identifier.is_nil() && identifier.to_string() == value)
        .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_request(arguments: Value) -> (tempfile::TempDir, ToolExecutionRequest) {
        let workspace = tempfile::tempdir().unwrap();
        let run_id = super::super::accordlock_authorization::derive_backend_run_id(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "session",
        )
        .unwrap();
        let arguments_sha256 = super::super::accordlock_authorization::sha256_digest(
            &super::super::accordlock_authorization::canonical_json_bytes(&arguments).unwrap(),
        );
        let plan = super::super::accordlock_authorization::AgentPlanCheckpointInput::new(
            "session".to_owned(),
            "call".to_owned(),
            json!({
                "text": [],
                "tool_requests": [{
                    "id": "call",
                    "name": "shell",
                    "arguments_sha256": arguments_sha256,
                }]
            }),
            1_800_000_000,
        )
        .unwrap();
        let request = ToolExecutionRequest::new(ToolExecutionRequestParams {
            session_id: "session",
            run_id: &run_id,
            request_id: Some("call"),
            working_dir: Some(workspace.path()),
            extension_id: "developer",
            tool_name: "shell",
            plan_tool_name: "shell",
            arguments,
            plan_checkpoint_input: Some(&plan),
        })
        .unwrap();
        (workspace, request)
    }

    fn valid_arguments() -> Value {
        json!({
            "argv": ["cargo", "test", "--lib"],
            "cwd": "crates/example",
            "env": {"CI": "1", "NO_COLOR": "1"},
            "timeout_seconds": 30,
            "max_output_bytes": 4096
        })
    }

    fn evidence_fields() -> ExecutionEvidence {
        ExecutionEvidence {
            authorization_id: uuid::Uuid::from_u128(1).to_string(),
            request_hash: sha256_digest(b"intent"),
            record_id: uuid::Uuid::from_u128(2).to_string(),
            record_hash: sha256_digest(b"record"),
        }
    }

    fn success_response(request: &ToolExecutionRequest) -> TerminalExecutionResponse {
        let result = BrokeredTerminalResult {
            program: "cargo".to_owned(),
            exit_code: Some(0),
            outcome: BrokeredProcessOutcome::Succeeded,
            stdout: "ok\n".to_owned(),
            stderr: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            encoding_lossy: false,
            duration_ms: 12,
        };
        let result_sha256 = canonical_json_bytes(&result)
            .map(|bytes| sha256_digest(&bytes))
            .unwrap();
        let evidence = evidence_fields();
        TerminalExecutionResponse {
            schema_version: PROTOCOL_VERSION,
            proposal_digest: request.digest().unwrap(),
            status: TerminalExecutionStatus::Succeeded,
            reason_code: "EXECUTED".to_owned(),
            authorization_id: Some(evidence.authorization_id),
            request_hash: Some(evidence.request_hash),
            record_id: Some(evidence.record_id),
            record_hash: Some(evidence.record_hash),
            result_sha256: Some(result_sha256),
            result: Some(result),
            approval_request: None,
            approval_request_hash: None,
        }
    }

    fn status_unknown_response(request: &ToolExecutionRequest) -> TerminalExecutionResponse {
        let evidence = evidence_fields();
        TerminalExecutionResponse {
            schema_version: PROTOCOL_VERSION,
            proposal_digest: request.digest().unwrap(),
            status: TerminalExecutionStatus::ExecutionUnknown,
            reason_code: "TIMED_OUT".to_owned(),
            authorization_id: Some(evidence.authorization_id),
            request_hash: Some(evidence.request_hash),
            record_id: Some(evidence.record_id),
            record_hash: Some(evidence.record_hash),
            result_sha256: None,
            result: None,
            approval_request: None,
            approval_request_hash: None,
        }
    }

    fn approval_request(
        request: &ToolExecutionRequest,
        operation: &ValidatedTerminalOperation,
    ) -> (ActionApprovalRequest, String) {
        let task_policy_hash = sha256_digest(b"task policy");
        let prestate_hash = sha256_digest(b"terminal prestate");
        let action = ActionRequest {
            extension_id: "developer".to_owned(),
            tool_name: "shell".to_owned(),
            relative_path: operation.arguments.cwd.clone(),
            action_type: ActionType::ExecuteProcess,
            requested_bytes: operation.requested_bytes,
            executable_path: std::env::current_exe()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            executable_sha256: sha256_digest(b"test executable"),
        };
        let action_hash =
            action_binding_hash(&request.digest().unwrap(), &prestate_hash, &action).unwrap();
        let recorded_at = 1_800_000_000;
        let approval_request = ActionApprovalRequest {
            schema_version: ACTION_APPROVAL_SCHEMA_VERSION,
            task_id: uuid::Uuid::from_u128(3).to_string(),
            session_id: request.session_id.clone(),
            run_id: request.run_id.clone(),
            tool_call_id: request.tool_call_id.clone(),
            proposal_digest: request.digest().unwrap(),
            task_policy_hash: task_policy_hash.clone(),
            prestate_hash,
            action,
            task_requirement: TaskRequirement {
                schema_version: 2,
                requirement_id: uuid::Uuid::from_u128(4).to_string(),
                task_policy_hash: task_policy_hash.clone(),
                statement_hash: sha256_digest(b"objective"),
                minimum_conformance_score_ppm: 1_000_000,
            },
            transformation_step: TransformationStep {
                schema_version: 2,
                step_id: uuid::Uuid::from_u128(5).to_string(),
                task_policy_hash: task_policy_hash.clone(),
                sequence: 0,
                parent_step_hash: None,
                source_stage: TransformationStage::Intention,
                source_hash: sha256_digest(b"objective"),
                target_stage: TransformationStage::Action,
                target_hash: action_hash.clone(),
                recorded_at,
            },
            policy_decision: PolicyDecisionRecord {
                schema_version: 2,
                decision_id: uuid::Uuid::from_u128(6).to_string(),
                task_policy_hash,
                action_hash,
                sequence: 0,
                previous_decision_hash: None,
                requirement_hashes: vec![sha256_digest(b"requirement")],
                transformation_step_hashes: vec![sha256_digest(b"transformation step")],
                conformance_evaluation_hashes: vec![],
                resource_request_hashes: vec![],
                resource_quota_hashes: vec![],
                resource_reservation_hashes: vec![],
                baseline: PolicyDecision::AllowAutomatic,
                decision: PolicyDecision::RequireApproval,
                reasons: vec![DecisionReason::TaskConformanceEvidenceMissing],
                policy_epoch: 1,
                evaluated_at: recorded_at,
            },
            policy_decision_hash: sha256_digest(b"opaque canonical policy decision"),
        };
        let canonical = canonical_json_bytes(&approval_request).unwrap();
        let hash = domain_digest(b"accordlock:v2:action-approval-request", &canonical);
        (approval_request, hash)
    }

    #[test]
    fn only_exact_developer_shell_is_brokered() {
        assert!(is_brokered("developer", "shell"));
        assert!(!is_brokered("developer", "write"));
        assert!(!is_brokered("external", "shell"));
    }

    #[test]
    fn direct_argv_contract_rejects_shell_strings_and_unknown_fields() {
        for arguments in [
            json!({"command": "cargo test"}),
            json!({"argv": ["cargo", "test"], "command": "cargo test"}),
            json!({"argv": ["cargo\nwhoami"]}),
            json!({"argv": ["../cargo"]}),
            json!({"argv": []}),
        ] {
            let (_workspace, request) = make_request(arguments);
            assert!(validate_execution_request(&request).is_err());
        }
        let (_workspace, request) = make_request(valid_arguments());
        assert!(validate_execution_request(&request).is_ok());
    }

    #[test]
    fn cwd_must_be_canonical_and_workspace_relative() {
        for cwd in [
            "../secret",
            "src/../secret",
            "/etc",
            "C:\\Windows",
            "src\\bin",
            "src//bin",
            "src./child",
            "dir/. /child",
        ] {
            let mut arguments = valid_arguments();
            arguments["cwd"] = json!(cwd);
            let (_workspace, request) = make_request(arguments);
            assert!(validate_execution_request(&request).is_err(), "{cwd}");
        }
    }

    #[test]
    fn environment_is_allowlisted_and_authority_is_never_forwardable() {
        for name in [
            "PATH",
            "HOME",
            "ACCORDLOCK_RUNTIME_URL",
            "accordlock_runtime_token",
            "ACCORDLOCK_BACKEND_BINDING_SECRET",
        ] {
            let mut arguments = valid_arguments();
            arguments["env"] = json!({name: "secret"});
            let (_workspace, request) = make_request(arguments);
            assert!(validate_execution_request(&request).is_err(), "{name}");
        }
    }

    #[test]
    fn bounds_are_enforced_before_the_runtime_request() {
        let cases = [
            json!({"argv": ["cargo"], "timeout_seconds": 0}),
            json!({"argv": ["cargo"], "timeout_seconds": 301}),
            json!({"argv": ["cargo"], "max_output_bytes": 0}),
            json!({"argv": ["cargo"], "max_output_bytes": 262145}),
        ];
        for arguments in cases {
            let (_workspace, request) = make_request(arguments);
            assert!(validate_execution_request(&request).is_err());
        }
    }

    #[test]
    fn rendered_output_bound_accepts_the_legacy_redaction_worst_case_only() {
        let maximum = MAX_OUTPUT_BYTES;
        let expanded = "x".repeat((maximum as usize).saturating_mul(MAX_RENDERED_OUTPUT_EXPANSION));
        assert!(valid_rendered_output_bound(&expanded, maximum));

        let one_byte_too_many = format!("{expanded}x");
        assert!(!valid_rendered_output_bound(&one_byte_too_many, maximum));
        assert!(MAX_TERMINAL_RESPONSE_BYTES >= 8 * 1024 * 1024);
    }

    #[test]
    fn success_is_bound_to_program_result_digest_and_execution_record() {
        let (_workspace, request) = make_request(valid_arguments());
        let operation = validate_execution_request(&request).unwrap();
        let proposal_digest = request.digest().unwrap();
        let response = success_response(&request);
        assert!(validate_response(response, &operation, &request, &proposal_digest).is_ok());

        let mut wrong_program = success_response(&request);
        wrong_program.result.as_mut().unwrap().program = "git".to_owned();
        let changed_result = wrong_program.result.as_ref().unwrap();
        wrong_program.result_sha256 = Some(
            canonical_json_bytes(changed_result)
                .map(|bytes| sha256_digest(&bytes))
                .unwrap(),
        );
        assert_eq!(
            validate_response(wrong_program, &operation, &request, &proposal_digest).unwrap_err(),
            PolicyEnforcementError::ExecutionUnknown
        );

        let mut missing_record = success_response(&request);
        missing_record.record_hash = None;
        assert_eq!(
            validate_response(missing_record, &operation, &request, &proposal_digest).unwrap_err(),
            PolicyEnforcementError::ExecutionUnknown
        );
    }

    #[test]
    fn action_approval_v2_is_hash_and_request_bound() {
        let (_workspace, request) = make_request(valid_arguments());
        let operation = validate_execution_request(&request).unwrap();
        let proposal_digest = request.digest().unwrap();
        let (approval_request, approval_request_hash) = approval_request(&request, &operation);
        let response = TerminalExecutionResponse {
            schema_version: PROTOCOL_VERSION,
            proposal_digest: proposal_digest.clone(),
            status: TerminalExecutionStatus::ApprovalRequired,
            reason_code: "ACTION_APPROVAL_REQUIRED".to_owned(),
            authorization_id: None,
            request_hash: None,
            record_id: None,
            record_hash: None,
            result_sha256: None,
            result: None,
            approval_request: Some(approval_request.clone()),
            approval_request_hash: Some(approval_request_hash),
        };
        assert_eq!(
            validate_response(response, &operation, &request, &proposal_digest).unwrap_err(),
            PolicyEnforcementError::ApprovalRequired("ACTION_APPROVAL_REQUIRED".to_owned())
        );

        let mut rebound = approval_request;
        rebound.action.relative_path = "other".to_owned();
        let rebound_hash = domain_digest(
            b"accordlock:v2:action-approval-request",
            &canonical_json_bytes(&rebound).unwrap(),
        );
        assert_eq!(
            validate_approval_request(
                &rebound,
                &rebound_hash,
                &operation,
                &request,
                &proposal_digest,
            )
            .unwrap_err(),
            PolicyEnforcementError::ExecutionUnknown
        );
    }

    #[test]
    fn unknown_execution_status_is_never_rendered_as_an_ordinary_tool_error() {
        let (_workspace, request) = make_request(valid_arguments());
        let operation = validate_execution_request(&request).unwrap();
        let proposal_digest = request.digest().unwrap();

        assert_eq!(
            validate_response(
                status_unknown_response(&request),
                &operation,
                &request,
                &proposal_digest,
            )
            .unwrap_err(),
            PolicyEnforcementError::ExecutionUnknown
        );
    }

    #[test]
    fn terminal_deadline_is_bounded_by_validated_process_timeout() {
        let mut arguments = valid_arguments();
        arguments["timeout_seconds"] = json!(MAX_TIMEOUT_SECONDS);
        let (_workspace, request) = make_request(arguments);
        let operation = validate_execution_request(&request).unwrap();

        assert_eq!(terminal_http_timeout(&operation), Duration::from_secs(320));

        let mut invalid = valid_arguments();
        invalid["timeout_seconds"] = json!(MAX_TIMEOUT_SECONDS + 1);
        let (_workspace, request) = make_request(invalid);
        assert!(validate_execution_request(&request).is_err());
    }

    #[tokio::test]
    async fn runtime_uses_only_the_atomic_terminal_endpoint() {
        use wiremock::matchers::{bearer_token, body_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (_workspace, request) = make_request(valid_arguments());
        let response = serde_json::to_value(success_response(&request)).unwrap();
        Mock::given(method("POST"))
            .and(path(TERMINAL_EXECUTE_PATH))
            .and(bearer_token("0123456789abcdef0123456789abcdef"))
            .and(body_json(json!({
                "schema_version": PROTOCOL_VERSION,
                "proposal": request.clone(),
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;

        let broker = RuntimeTerminalBroker::new(
            &format!("{}/", server.uri()),
            "0123456789abcdef0123456789abcdef".to_owned(),
        )
        .unwrap();
        let outcome = broker.authorize_and_execute(&request).await.unwrap();
        assert!(matches!(outcome, BrokeredTerminalOutcome::Succeeded { .. }));
    }

    #[tokio::test]
    async fn malformed_or_unknown_runtime_responses_fail_closed() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        for body in [
            json!({
                "schema_version": PROTOCOL_VERSION,
                "proposal_digest": sha256_digest(b"wrong"),
                "status": "SUCCEEDED",
                "reason_code": "EXECUTED",
                "unexpected": true
            }),
            json!({
                "schema_version": PROTOCOL_VERSION,
                "proposal_digest": sha256_digest(b"wrong"),
                "status": "FUTURE_STATUS",
                "reason_code": "EXECUTED"
            }),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path(TERMINAL_EXECUTE_PATH))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .expect(1)
                .mount(&server)
                .await;
            let (_workspace, request) = make_request(valid_arguments());
            let broker = RuntimeTerminalBroker::new(
                &format!("{}/", server.uri()),
                "0123456789abcdef0123456789abcdef".to_owned(),
            )
            .unwrap();
            assert_eq!(
                broker.authorize_and_execute(&request).await.unwrap_err(),
                PolicyEnforcementError::ExecutionUnknown
            );
        }
    }
}
