//! Trusted filesystem execution boundary for the AccordLock distribution.
//!
//! Goose may propose filesystem operations, but an AccordLock build never
//! performs them in-process. The runtime authorizes, consumes one-shot
//! authorization, executes the bounded operation, and persists its execution
//! record in one request. Any ambiguous response is treated as unknown status.

use async_trait::async_trait;
use rmcp::model::{CallToolResult, ContentBlock};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;

#[cfg(test)]
use super::accordlock_authorization::ToolExecutionRequestParams;
use super::accordlock_authorization::{
    canonical_json_bytes, sha256_digest, validate_authorization_id, validate_digest,
    validate_reason_code, PolicyEnforcementError, RuntimePolicyEnforcementPoint,
    ToolExecutionRequest, PROTOCOL_VERSION,
};

pub(super) const FILESYSTEM_EXECUTE_PATH: &str =
    "/api/v2/execution/filesystem/authorize-and-execute";
const MAX_FILESYSTEM_RESPONSE_BYTES: usize = 384 * 1024;
const MAX_BROKERED_CONTENT_BYTES: usize = 256 * 1024;
const MAX_RELATIVE_PATH_BYTES: usize = 4_096;
const MAX_PATH_SEGMENT_BYTES: usize = 255;
const MAX_PATH_SEGMENTS: usize = 64;
const MAX_READ_LINES: u32 = 10_000;
const MAX_TREE_DEPTH: u32 = 8;
const ACTION_APPROVAL_SCHEMA_VERSION: u16 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FilesystemRoute {
    Brokered,
    ForbiddenDirect,
    Unrelated,
}

pub(super) fn classify(extension_id: &str, tool_name: &str) -> FilesystemRoute {
    if extension_id != "developer" {
        return FilesystemRoute::Unrelated;
    }
    match tool_name {
        "read" | "write" | "edit" | "delete_file" | "tree" => FilesystemRoute::Brokered,
        "shell" | "read_image" => FilesystemRoute::ForbiddenDirect,
        _ => FilesystemRoute::Unrelated,
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct FilesystemExecutionRequest<'a> {
    schema_version: u16,
    proposal: &'a ToolExecutionRequest,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FilesystemExecutionResponse {
    schema_version: u16,
    proposal_digest: String,
    status: FilesystemExecutionStatus,
    reason_code: String,
    authorization_id: Option<String>,
    request_hash: Option<String>,
    record_id: Option<String>,
    record_hash: Option<String>,
    result_sha256: Option<String>,
    result: Option<BrokeredFilesystemResult>,
    approval_request: Option<Value>,
    approval_request_hash: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FilesystemApprovalRequest {
    schema_version: u16,
    task_id: String,
    session_id: String,
    run_id: String,
    tool_call_id: String,
    proposal_digest: String,
    task_policy_hash: String,
    prestate_hash: String,
    action: FilesystemApprovalAction,
    task_requirement: ApprovalTaskRequirement,
    transformation_step: ApprovalTransformationStep,
    policy_decision: ApprovalPolicyDecision,
    policy_decision_hash: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FilesystemApprovalAction {
    extension_id: String,
    tool_name: String,
    relative_path: String,
    action_type: ApprovalActionType,
    requested_bytes: u64,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ApprovalActionType {
    CreateFile,
    OverwriteFile,
    EditFile,
    DeleteFile,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ApprovalTaskRequirement {
    schema_version: u16,
    requirement_id: String,
    task_hash: String,
    statement_hash: String,
    minimum_score: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ApprovalTransformationStep {
    schema_version: u16,
    step_id: String,
    task_hash: String,
    sequence: u64,
    parent_step_hash: Option<String>,
    source_stage: ApprovalWorkflowStage,
    source_hash: String,
    target_stage: ApprovalWorkflowStage,
    target_hash: String,
    recorded_at: i64,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ApprovalWorkflowStage {
    Request,
    Action,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ApprovalPolicyDecision {
    schema_version: u16,
    decision_id: String,
    task_hash: String,
    action_hash: String,
    sequence: u64,
    parent_decision_hash: Option<String>,
    requirement_hashes: Vec<String>,
    transformation_step_hashes: Vec<String>,
    conformance_evaluation_hashes: Vec<String>,
    resource_request_hashes: Vec<String>,
    resource_quota_hashes: Vec<String>,
    resource_reservation_hashes: Vec<String>,
    baseline_decision: ApprovalEnforcementDecision,
    decision: ApprovalEnforcementDecision,
    reasons: Vec<ApprovalDecisionReason>,
    policy_epoch: u64,
    evaluated_at: i64,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ApprovalEnforcementDecision {
    Allow,
    RequireApproval,
    Deny,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ApprovalDecisionReason {
    ConformanceEvaluationMissing,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum FilesystemExecutionStatus {
    Succeeded,
    ToolError,
    ExecutionUnknown,
    Denied,
    ApprovalRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub(super) enum BrokeredFilesystemResult {
    Read {
        relative_path: String,
        content: String,
        content_sha256: String,
        truncated: bool,
    },
    Tree {
        relative_path: String,
        content: String,
        entries: u64,
        truncated: bool,
    },
    Write {
        relative_path: String,
        created: bool,
        bytes_written: u64,
        content_sha256: String,
    },
    Edit {
        relative_path: String,
        bytes_written: u64,
        content_sha256: String,
    },
    Delete {
        relative_path: String,
        recovery_id: String,
        recovery_path: String,
        original_bytes: u64,
        content_sha256: String,
    },
}

impl BrokeredFilesystemResult {
    fn relative_path(&self) -> &str {
        match self {
            Self::Read { relative_path, .. }
            | Self::Tree { relative_path, .. }
            | Self::Write { relative_path, .. }
            | Self::Edit { relative_path, .. }
            | Self::Delete { relative_path, .. } => relative_path,
        }
    }

    fn kind(&self) -> FilesystemOperationKind {
        match self {
            Self::Read { .. } => FilesystemOperationKind::Read,
            Self::Tree { .. } => FilesystemOperationKind::Tree,
            Self::Write { .. } => FilesystemOperationKind::Write,
            Self::Edit { .. } => FilesystemOperationKind::Edit,
            Self::Delete { .. } => FilesystemOperationKind::Delete,
        }
    }

    fn validate_content(&self) -> Result<(), PolicyEnforcementError> {
        match self {
            Self::Read {
                content,
                content_sha256,
                ..
            } => {
                if content.len() > MAX_BROKERED_CONTENT_BYTES
                    || sha256_digest(content.as_bytes()) != *content_sha256
                {
                    return Err(PolicyEnforcementError::InvalidRuntimeResponse);
                }
                validate_digest(content_sha256)
            }
            Self::Tree { content, .. } => {
                if content.len() > MAX_BROKERED_CONTENT_BYTES {
                    return Err(PolicyEnforcementError::InvalidRuntimeResponse);
                }
                Ok(())
            }
            Self::Write { content_sha256, .. } | Self::Edit { content_sha256, .. } => {
                validate_digest(content_sha256)
            }
            Self::Delete {
                recovery_id,
                recovery_path,
                content_sha256,
                ..
            } => {
                validate_authorization_id(recovery_id)?;
                validate_digest(content_sha256)?;
                if recovery_path != &format!(".accordlock/recovery/{recovery_id}/content") {
                    return Err(PolicyEnforcementError::InvalidRuntimeResponse);
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilesystemOperationKind {
    Read,
    Tree,
    Write,
    Edit,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedOperation {
    kind: FilesystemOperationKind,
    relative_path: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadArguments {
    path: String,
    line: Option<u32>,
    limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteArguments {
    path: String,
    content: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EditArguments {
    path: String,
    before: String,
    after: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteArguments {
    path: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TreeArguments {
    path: String,
    #[serde(default = "default_tree_depth")]
    depth: u32,
}

fn default_tree_depth() -> u32 {
    2
}

#[derive(Debug, Clone)]
pub(super) struct ExecutionEvidence {
    pub(super) authorization_id: String,
    pub(super) request_hash: String,
    pub(super) record_id: String,
    pub(super) record_hash: String,
}

#[derive(Debug, Clone)]
pub(super) enum BrokeredFilesystemOutcome {
    Succeeded {
        result: BrokeredFilesystemResult,
        result_sha256: String,
        evidence: ExecutionEvidence,
    },
    ToolError {
        reason_code: String,
        evidence: ExecutionEvidence,
    },
}

impl BrokeredFilesystemOutcome {
    pub(super) fn into_call_tool_result(self) -> CallToolResult {
        match self {
            Self::Succeeded {
                result,
                result_sha256,
                evidence,
            } => {
                let text = match &result {
                    BrokeredFilesystemResult::Read { content, .. }
                    | BrokeredFilesystemResult::Tree { content, .. } => content.clone(),
                    BrokeredFilesystemResult::Write {
                        relative_path,
                        created,
                        bytes_written,
                        ..
                    } => format!(
                        "{} {} ({} bytes)",
                        if *created { "Created" } else { "Wrote" },
                        relative_path,
                        bytes_written
                    ),
                    BrokeredFilesystemResult::Edit {
                        relative_path,
                        bytes_written,
                        ..
                    } => format!("Edited {relative_path} ({bytes_written} bytes)"),
                    BrokeredFilesystemResult::Delete {
                        relative_path,
                        recovery_path,
                        original_bytes,
                        ..
                    } => format!(
                        "Moved {relative_path} to recovery storage at {recovery_path} ({original_bytes} bytes)"
                    ),
                };
                let mut call_result = CallToolResult::success(vec![ContentBlock::text(text)]);
                call_result.structured_content = Some(execution_metadata(
                    &result,
                    &result_sha256,
                    &evidence,
                    "SUCCEEDED",
                    "EXECUTED",
                ));
                call_result
            }
            Self::ToolError {
                reason_code,
                evidence,
            } => {
                let mut call_result = CallToolResult::error(vec![ContentBlock::text(format!(
                    "AccordLock filesystem operation failed ({reason_code})."
                ))]);
                call_result.structured_content = Some(json!({
                    "accordlock": {
                        "schemaVersion": PROTOCOL_VERSION,
                        "status": "TOOL_ERROR",
                        "reasonCode": reason_code,
                        "authorizationId": evidence.authorization_id,
                        "requestHash": evidence.request_hash,
                        "recordId": evidence.record_id,
                        "recordHash": evidence.record_hash,
                    }
                }));
                call_result
            }
        }
    }
}

fn execution_metadata(
    result: &BrokeredFilesystemResult,
    result_sha256: &str,
    evidence: &ExecutionEvidence,
    status: &str,
    reason_code: &str,
) -> Value {
    json!({
        "accordlock": {
            "schemaVersion": PROTOCOL_VERSION,
            "status": status,
            "reasonCode": reason_code,
            "authorizationId": evidence.authorization_id,
            "requestHash": evidence.request_hash,
            "recordId": evidence.record_id,
            "recordHash": evidence.record_hash,
            "resultSha256": result_sha256,
            "operation": match result.kind() {
                FilesystemOperationKind::Read => "READ",
                FilesystemOperationKind::Tree => "TREE",
                FilesystemOperationKind::Write => "WRITE",
                FilesystemOperationKind::Edit => "EDIT",
                FilesystemOperationKind::Delete => "DELETE_FILE",
            },
            "relativePath": result.relative_path(),
        }
    })
}

#[async_trait]
pub(super) trait FilesystemBroker: Send + Sync {
    fn enforces_boundary(&self) -> bool;

    fn derive_run_id(&self, session_id: &str) -> Result<String, PolicyEnforcementError>;

    async fn authorize_and_execute(
        &self,
        request: &ToolExecutionRequest,
    ) -> Result<BrokeredFilesystemOutcome, PolicyEnforcementError>;
}

#[cfg(not(feature = "accordlock-distribution"))]
struct UpstreamFilesystemBroker;

#[async_trait]
#[cfg(not(feature = "accordlock-distribution"))]
impl FilesystemBroker for UpstreamFilesystemBroker {
    fn enforces_boundary(&self) -> bool {
        false
    }

    fn derive_run_id(&self, _session_id: &str) -> Result<String, PolicyEnforcementError> {
        Err(PolicyEnforcementError::RuntimeNotConfigured)
    }

    async fn authorize_and_execute(
        &self,
        _request: &ToolExecutionRequest,
    ) -> Result<BrokeredFilesystemOutcome, PolicyEnforcementError> {
        Err(PolicyEnforcementError::RuntimeNotConfigured)
    }
}

#[derive(Clone)]
struct RuntimeFilesystemBroker {
    runtime: RuntimePolicyEnforcementPoint,
}

impl RuntimeFilesystemBroker {
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
impl FilesystemBroker for RuntimeFilesystemBroker {
    fn enforces_boundary(&self) -> bool {
        true
    }

    fn derive_run_id(&self, session_id: &str) -> Result<String, PolicyEnforcementError> {
        self.runtime.derive_backend_run_id(session_id)
    }

    async fn authorize_and_execute(
        &self,
        execution_request: &ToolExecutionRequest,
    ) -> Result<BrokeredFilesystemOutcome, PolicyEnforcementError> {
        let operation = validate_execution_request(execution_request)?;
        let expected_proposal_digest = execution_request.digest()?;
        let request = FilesystemExecutionRequest {
            schema_version: PROTOCOL_VERSION,
            proposal: execution_request,
        };
        let response: FilesystemExecutionResponse = self
            .runtime
            .post_json_bounded(
                FILESYSTEM_EXECUTE_PATH,
                &request,
                MAX_FILESYSTEM_RESPONSE_BYTES,
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

#[cfg(feature = "accordlock-distribution")]
struct UnavailableFilesystemBroker;

#[async_trait]
#[cfg(feature = "accordlock-distribution")]
impl FilesystemBroker for UnavailableFilesystemBroker {
    fn enforces_boundary(&self) -> bool {
        true
    }

    fn derive_run_id(&self, _session_id: &str) -> Result<String, PolicyEnforcementError> {
        Err(PolicyEnforcementError::RuntimeNotConfigured)
    }

    async fn authorize_and_execute(
        &self,
        _request: &ToolExecutionRequest,
    ) -> Result<BrokeredFilesystemOutcome, PolicyEnforcementError> {
        Err(PolicyEnforcementError::RuntimeNotConfigured)
    }
}

pub(super) fn default_filesystem_broker() -> Arc<dyn FilesystemBroker> {
    #[cfg(feature = "accordlock-distribution")]
    {
        RuntimeFilesystemBroker::from_environment()
            .map(|broker| Arc::new(broker) as Arc<dyn FilesystemBroker>)
            .unwrap_or_else(|_| Arc::new(UnavailableFilesystemBroker))
    }
    #[cfg(not(feature = "accordlock-distribution"))]
    {
        Arc::new(UpstreamFilesystemBroker)
    }
}

fn validate_execution_request(
    execution_request: &ToolExecutionRequest,
) -> Result<ValidatedOperation, PolicyEnforcementError> {
    if execution_request.extension_id != "developer" {
        return Err(PolicyEnforcementError::InvalidField("extension_id"));
    }

    let (kind, path) = match execution_request.tool_name.as_str() {
        "read" => {
            let arguments: ReadArguments = parse_arguments(&execution_request.arguments)?;
            validate_relative_path(&arguments.path, false)?;
            if arguments.line == Some(0)
                || arguments.limit == Some(0)
                || arguments.limit.is_some_and(|limit| limit > MAX_READ_LINES)
            {
                return Err(PolicyEnforcementError::InvalidField("arguments"));
            }
            (FilesystemOperationKind::Read, arguments.path)
        }
        "write" => {
            let arguments: WriteArguments = parse_arguments(&execution_request.arguments)?;
            validate_relative_path(&arguments.path, false)?;
            if arguments.content.len() > MAX_BROKERED_CONTENT_BYTES {
                return Err(PolicyEnforcementError::ArgumentsTooLarge);
            }
            (FilesystemOperationKind::Write, arguments.path)
        }
        "edit" => {
            let arguments: EditArguments = parse_arguments(&execution_request.arguments)?;
            validate_relative_path(&arguments.path, false)?;
            if arguments.before.is_empty()
                || arguments.before.len().saturating_add(arguments.after.len())
                    > MAX_BROKERED_CONTENT_BYTES
            {
                return Err(PolicyEnforcementError::InvalidField("arguments"));
            }
            (FilesystemOperationKind::Edit, arguments.path)
        }
        "delete_file" => {
            let arguments: DeleteArguments = parse_arguments(&execution_request.arguments)?;
            validate_relative_path(&arguments.path, false)?;
            (FilesystemOperationKind::Delete, arguments.path)
        }
        "tree" => {
            let arguments: TreeArguments = parse_arguments(&execution_request.arguments)?;
            validate_relative_path(&arguments.path, true)?;
            if arguments.depth == 0 || arguments.depth > MAX_TREE_DEPTH {
                return Err(PolicyEnforcementError::InvalidField("arguments"));
            }
            (FilesystemOperationKind::Tree, arguments.path)
        }
        _ => return Err(PolicyEnforcementError::InvalidField("tool_name")),
    };

    Ok(ValidatedOperation {
        kind,
        relative_path: path,
    })
}

fn parse_arguments<T: for<'de> Deserialize<'de>>(
    value: &Value,
) -> Result<T, PolicyEnforcementError> {
    serde_json::from_value(value.clone())
        .map_err(|_| PolicyEnforcementError::InvalidField("arguments"))
}

fn validate_relative_path(
    path: &str,
    allow_workspace_root: bool,
) -> Result<(), PolicyEnforcementError> {
    if allow_workspace_root && path == "." {
        return Ok(());
    }
    if path.is_empty()
        || path.len() > MAX_RELATIVE_PATH_BYTES
        || path.trim() != path
        || path.starts_with(['/', '\\'])
        || path.contains('\\')
        || path.contains(':')
        || path.chars().any(char::is_control)
    {
        return Err(PolicyEnforcementError::InvalidField("path"));
    }

    let segments = path.split('/').collect::<Vec<_>>();
    if segments.len() > MAX_PATH_SEGMENTS
        || segments.iter().any(|segment| {
            segment.is_empty()
                || segment.len() > MAX_PATH_SEGMENT_BYTES
                || matches!(*segment, "." | "..")
                || segment.ends_with(['.', ' '])
                || is_reserved_windows_name(segment)
        })
    {
        return Err(PolicyEnforcementError::InvalidField("path"));
    }
    Ok(())
}

fn is_reserved_windows_name(segment: &str) -> bool {
    let basename = segment.split('.').next().unwrap_or(segment);
    let upper = basename.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || upper
            .strip_prefix("COM")
            .or_else(|| upper.strip_prefix("LPT"))
            .is_some_and(|suffix| {
                matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            })
}

fn validate_response(
    response: FilesystemExecutionResponse,
    operation: &ValidatedOperation,
    execution_request: &ToolExecutionRequest,
    expected_proposal_digest: &str,
) -> Result<BrokeredFilesystemOutcome, PolicyEnforcementError> {
    if response.schema_version != PROTOCOL_VERSION
        || response.proposal_digest != expected_proposal_digest
        || validate_digest(&response.proposal_digest).is_err()
        || validate_reason_code(&response.reason_code).is_err()
    {
        return Err(PolicyEnforcementError::ExecutionUnknown);
    }

    match response.status {
        FilesystemExecutionStatus::Succeeded => {
            if !matches!(response.reason_code.as_str(), "EXECUTED" | "RECONCILED")
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
                || result.kind() != operation.kind
                || result.relative_path() != operation.relative_path
                || result.validate_content().is_err()
                || matches!(
                    &result,
                    BrokeredFilesystemResult::Delete { recovery_id, .. }
                        if recovery_id != &evidence.authorization_id
                )
            {
                return Err(PolicyEnforcementError::ExecutionUnknown);
            }
            Ok(BrokeredFilesystemOutcome::Succeeded {
                result,
                result_sha256,
                evidence,
            })
        }
        FilesystemExecutionStatus::ToolError => {
            if response.result.is_some()
                || response.result_sha256.is_some()
                || response.approval_request.is_some()
                || response.approval_request_hash.is_some()
            {
                return Err(PolicyEnforcementError::ExecutionUnknown);
            }
            let evidence = extract_evidence(&response)?;
            Ok(BrokeredFilesystemOutcome::ToolError {
                reason_code: response.reason_code,
                evidence,
            })
        }
        FilesystemExecutionStatus::ExecutionUnknown => {
            if response.result.is_some()
                || response.result_sha256.is_some()
                || response.approval_request.is_some()
                || response.approval_request_hash.is_some()
            {
                return Err(PolicyEnforcementError::ExecutionUnknown);
            }
            let _evidence = extract_evidence(&response)?;
            Err(PolicyEnforcementError::ExecutionUnknown)
        }
        FilesystemExecutionStatus::Denied => {
            require_no_execution_evidence(&response)?;
            if response.approval_request.is_some() || response.approval_request_hash.is_some() {
                return Err(PolicyEnforcementError::ExecutionUnknown);
            }
            Err(PolicyEnforcementError::Denied(response.reason_code))
        }
        FilesystemExecutionStatus::ApprovalRequired => {
            require_no_execution_evidence(&response)?;
            let approval_request = response
                .approval_request
                .as_ref()
                .ok_or(PolicyEnforcementError::ExecutionUnknown)?;
            let approval_request_hash = response
                .approval_request_hash
                .as_deref()
                .ok_or(PolicyEnforcementError::ExecutionUnknown)?;
            if response.reason_code != "ACTION_APPROVAL_REQUIRED"
                || validate_approval_request(
                    approval_request,
                    approval_request_hash,
                    operation,
                    execution_request,
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

fn require_no_execution_evidence(
    response: &FilesystemExecutionResponse,
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
    value: &Value,
    supplied_hash: &str,
    operation: &ValidatedOperation,
    execution_request: &ToolExecutionRequest,
    proposal_digest: &str,
) -> Result<(), PolicyEnforcementError> {
    validate_nonzero_digest(supplied_hash)?;
    let canonical =
        canonical_json_bytes(value).map_err(|_| PolicyEnforcementError::ExecutionUnknown)?;
    if domain_digest(b"accordlock:v2:action-approval-request", &canonical) != supplied_hash {
        return Err(PolicyEnforcementError::ExecutionUnknown);
    }

    let approval: FilesystemApprovalRequest = serde_json::from_value(value.clone())
        .map_err(|_| PolicyEnforcementError::ExecutionUnknown)?;
    let expected_action_type = match operation.kind {
        FilesystemOperationKind::Write => matches!(
            approval.action.action_type,
            ApprovalActionType::CreateFile | ApprovalActionType::OverwriteFile
        ),
        FilesystemOperationKind::Edit => {
            approval.action.action_type == ApprovalActionType::EditFile
        }
        FilesystemOperationKind::Delete => {
            approval.action.action_type == ApprovalActionType::DeleteFile
        }
        FilesystemOperationKind::Read | FilesystemOperationKind::Tree => false,
    };
    let requested_bytes_match = match operation.kind {
        FilesystemOperationKind::Write => {
            parse_arguments::<WriteArguments>(&execution_request.arguments)
                .ok()
                .is_some_and(|arguments| {
                    approval.action.requested_bytes == arguments.content.len() as u64
                })
        }
        FilesystemOperationKind::Edit => {
            parse_arguments::<EditArguments>(&execution_request.arguments)
                .ok()
                .is_some_and(|arguments| {
                    approval.action.requested_bytes == arguments.after.len() as u64
                })
        }
        FilesystemOperationKind::Delete => true,
        FilesystemOperationKind::Read | FilesystemOperationKind::Tree => false,
    };
    let action_hash =
        approval_action_hash(proposal_digest, &approval.prestate_hash, &approval.action)?;
    let requirement = &approval.task_requirement;
    let step = &approval.transformation_step;
    let decision = &approval.policy_decision;
    let nested_digests_valid = [
        &approval.task_policy_hash,
        &approval.prestate_hash,
        &approval.policy_decision_hash,
        &requirement.task_hash,
        &requirement.statement_hash,
        &step.task_hash,
        &step.source_hash,
        &step.target_hash,
        &decision.task_hash,
        &decision.action_hash,
    ]
    .into_iter()
    .all(|digest| validate_nonzero_digest(digest).is_ok())
        && decision
            .requirement_hashes
            .iter()
            .chain(&decision.transformation_step_hashes)
            .chain(&decision.conformance_evaluation_hashes)
            .chain(&decision.resource_request_hashes)
            .chain(&decision.resource_quota_hashes)
            .chain(&decision.resource_reservation_hashes)
            .all(|digest| validate_nonzero_digest(digest).is_ok());
    let requirement_hash = approval_task_requirement_hash(requirement)?;
    let transformation_step_hash = approval_transformation_step_hash(step)?;
    let policy_decision_hash = approval_policy_decision_hash(decision)?;
    let expected_requirement_id = derived_approval_record_id(
        b"accordlock:v2:task-requirement-id",
        &approval.task_id,
        proposal_digest,
        &approval.prestate_hash,
        &action_hash,
        decision.policy_epoch,
        decision.evaluated_at,
    )?;
    let expected_step_id = derived_approval_record_id(
        b"accordlock:v2:transformation-step-id",
        &approval.task_id,
        proposal_digest,
        &approval.prestate_hash,
        &action_hash,
        decision.policy_epoch,
        decision.evaluated_at,
    )?;
    let expected_decision_id = derived_approval_record_id(
        b"accordlock:v2:policy-decision-id",
        &approval.task_id,
        proposal_digest,
        &approval.prestate_hash,
        &action_hash,
        decision.policy_epoch,
        decision.evaluated_at,
    )?;

    if approval.schema_version != ACTION_APPROVAL_SCHEMA_VERSION
        || !valid_non_nil_uuid(&approval.task_id)
        || approval.session_id != execution_request.session_id
        || approval.run_id != execution_request.run_id
        || approval.tool_call_id != execution_request.tool_call_id
        || approval.proposal_digest != proposal_digest
        || !nested_digests_valid
        || approval.action.extension_id != execution_request.extension_id
        || approval.action.tool_name != execution_request.tool_name
        || approval.action.relative_path != operation.relative_path
        || !expected_action_type
        || !requested_bytes_match
        || requirement.schema_version != 2
        || !valid_non_nil_uuid(&requirement.requirement_id)
        || requirement.requirement_id != expected_requirement_id
        || requirement.task_hash != approval.task_policy_hash
        || requirement.minimum_score != 1_000_000
        || step.schema_version != 2
        || !valid_non_nil_uuid(&step.step_id)
        || step.step_id != expected_step_id
        || step.task_hash != approval.task_policy_hash
        || step.sequence != 0
        || step.parent_step_hash.is_some()
        || step.source_stage != ApprovalWorkflowStage::Request
        || step.source_hash != requirement.statement_hash
        || step.target_stage != ApprovalWorkflowStage::Action
        || step.target_hash != action_hash
        || step.recorded_at <= 0
        || decision.schema_version != 2
        || !valid_non_nil_uuid(&decision.decision_id)
        || decision.decision_id != expected_decision_id
        || decision.task_hash != approval.task_policy_hash
        || decision.action_hash != action_hash
        || decision.sequence != 0
        || decision.parent_decision_hash.is_some()
        || decision.requirement_hashes.len() != 1
        || decision.requirement_hashes[0] != requirement_hash
        || decision.transformation_step_hashes.len() != 1
        || decision.transformation_step_hashes[0] != transformation_step_hash
        || !decision.conformance_evaluation_hashes.is_empty()
        || !decision.resource_request_hashes.is_empty()
        || !decision.resource_quota_hashes.is_empty()
        || !decision.resource_reservation_hashes.is_empty()
        || decision.baseline_decision != ApprovalEnforcementDecision::Allow
        || decision.decision != ApprovalEnforcementDecision::RequireApproval
        || decision.reasons != [ApprovalDecisionReason::ConformanceEvaluationMissing]
        || decision.policy_epoch == 0
        || decision.evaluated_at != step.recorded_at
        || approval.policy_decision_hash != policy_decision_hash
    {
        return Err(PolicyEnforcementError::ExecutionUnknown);
    }
    Ok(())
}

fn approval_action_hash(
    proposal_digest: &str,
    prestate_hash: &str,
    action: &FilesystemApprovalAction,
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

fn validate_nonzero_digest(value: &str) -> Result<(), PolicyEnforcementError> {
    validate_digest(value).map_err(|_| PolicyEnforcementError::ExecutionUnknown)?;
    if value == format!("sha256:{}", "0".repeat(64)) {
        return Err(PolicyEnforcementError::ExecutionUnknown);
    }
    Ok(())
}

fn valid_non_nil_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|uuid| !uuid.is_nil())
}

fn approval_task_requirement_hash(
    value: &ApprovalTaskRequirement,
) -> Result<String, PolicyEnforcementError> {
    let mut bytes = Vec::new();
    cbor_array(&mut bytes, 6);
    cbor_unsigned(&mut bytes, u64::from(value.schema_version));
    cbor_bytes(&mut bytes, uuid_bytes(&value.requirement_id)?.as_slice());
    cbor_bytes(&mut bytes, &digest_bytes(&value.task_hash)?);
    cbor_bytes(&mut bytes, &digest_bytes(&value.statement_hash)?);
    cbor_unsigned(&mut bytes, u64::from(value.minimum_score));
    cbor_text(&mut bytes, "accordlock:v2:task-requirement");
    Ok(sha256_digest(&bytes))
}

fn approval_transformation_step_hash(
    value: &ApprovalTransformationStep,
) -> Result<String, PolicyEnforcementError> {
    let mut bytes = Vec::new();
    cbor_array(&mut bytes, 11);
    cbor_unsigned(&mut bytes, u64::from(value.schema_version));
    cbor_bytes(&mut bytes, uuid_bytes(&value.step_id)?.as_slice());
    cbor_bytes(&mut bytes, &digest_bytes(&value.task_hash)?);
    cbor_unsigned(&mut bytes, value.sequence);
    cbor_optional_digest(&mut bytes, value.parent_step_hash.as_deref())?;
    cbor_unsigned(&mut bytes, approval_stage_code(value.source_stage));
    cbor_bytes(&mut bytes, &digest_bytes(&value.source_hash)?);
    cbor_unsigned(&mut bytes, approval_stage_code(value.target_stage));
    cbor_bytes(&mut bytes, &digest_bytes(&value.target_hash)?);
    cbor_integer(&mut bytes, value.recorded_at);
    cbor_text(&mut bytes, "accordlock:v2:transformation-step");
    Ok(sha256_digest(&bytes))
}

fn approval_policy_decision_hash(
    value: &ApprovalPolicyDecision,
) -> Result<String, PolicyEnforcementError> {
    let mut bytes = Vec::new();
    cbor_array(&mut bytes, 18);
    cbor_unsigned(&mut bytes, u64::from(value.schema_version));
    cbor_bytes(&mut bytes, uuid_bytes(&value.decision_id)?.as_slice());
    cbor_bytes(&mut bytes, &digest_bytes(&value.task_hash)?);
    cbor_bytes(&mut bytes, &digest_bytes(&value.action_hash)?);
    cbor_unsigned(&mut bytes, value.sequence);
    cbor_optional_digest(&mut bytes, value.parent_decision_hash.as_deref())?;
    for digests in [
        &value.requirement_hashes,
        &value.transformation_step_hashes,
        &value.conformance_evaluation_hashes,
        &value.resource_request_hashes,
        &value.resource_quota_hashes,
        &value.resource_reservation_hashes,
    ] {
        cbor_array(&mut bytes, digests.len() as u64);
        for digest in digests {
            cbor_bytes(&mut bytes, &digest_bytes(digest)?);
        }
    }
    cbor_unsigned(&mut bytes, approval_decision_code(value.baseline_decision));
    cbor_unsigned(&mut bytes, approval_decision_code(value.decision));
    cbor_array(&mut bytes, value.reasons.len() as u64);
    for reason in &value.reasons {
        cbor_unsigned(&mut bytes, approval_reason_code(*reason));
    }
    cbor_unsigned(&mut bytes, value.policy_epoch);
    cbor_integer(&mut bytes, value.evaluated_at);
    cbor_text(&mut bytes, "accordlock:v2:policy-decision");
    Ok(sha256_digest(&bytes))
}

fn derived_approval_record_id(
    domain: &[u8],
    task_id: &str,
    proposal_digest: &str,
    prestate_hash: &str,
    action_hash: &str,
    policy_epoch: u64,
    evaluated_at: i64,
) -> Result<String, PolicyEnforcementError> {
    let mut input = Vec::new();
    input.extend_from_slice(domain);
    input.push(0);
    input.extend_from_slice(&uuid_bytes(task_id)?);
    input.extend_from_slice(&digest_bytes(proposal_digest)?);
    input.extend_from_slice(&digest_bytes(prestate_hash)?);
    input.extend_from_slice(&digest_bytes(action_hash)?);
    input.extend_from_slice(&policy_epoch.to_be_bytes());
    input.extend_from_slice(&evaluated_at.to_be_bytes());
    let digest = digest_bytes(&sha256_digest(&input))?;
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    id[6] = (id[6] & 0x0f) | 0x40;
    id[8] = (id[8] & 0x3f) | 0x80;
    Ok(uuid::Uuid::from_bytes(id).to_string())
}

fn uuid_bytes(value: &str) -> Result<[u8; 16], PolicyEnforcementError> {
    let uuid =
        uuid::Uuid::parse_str(value).map_err(|_| PolicyEnforcementError::ExecutionUnknown)?;
    if uuid.is_nil() {
        return Err(PolicyEnforcementError::ExecutionUnknown);
    }
    Ok(*uuid.as_bytes())
}

fn digest_bytes(value: &str) -> Result<[u8; 32], PolicyEnforcementError> {
    validate_nonzero_digest(value)?;
    let hex = value
        .strip_prefix("sha256:")
        .ok_or(PolicyEnforcementError::ExecutionUnknown)?;
    let mut bytes = [0_u8; 32];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let text =
            std::str::from_utf8(chunk).map_err(|_| PolicyEnforcementError::ExecutionUnknown)?;
        bytes[index] =
            u8::from_str_radix(text, 16).map_err(|_| PolicyEnforcementError::ExecutionUnknown)?;
    }
    Ok(bytes)
}

fn approval_stage_code(value: ApprovalWorkflowStage) -> u64 {
    match value {
        ApprovalWorkflowStage::Request => 0,
        ApprovalWorkflowStage::Action => 4,
    }
}

fn approval_decision_code(value: ApprovalEnforcementDecision) -> u64 {
    match value {
        ApprovalEnforcementDecision::Allow => 0,
        ApprovalEnforcementDecision::RequireApproval => 1,
        ApprovalEnforcementDecision::Deny => 2,
    }
}

fn approval_reason_code(value: ApprovalDecisionReason) -> u64 {
    match value {
        ApprovalDecisionReason::ConformanceEvaluationMissing => 1,
    }
}

fn cbor_array(output: &mut Vec<u8>, length: u64) {
    cbor_head(output, 4, length);
}

fn cbor_bytes(output: &mut Vec<u8>, value: &[u8]) {
    cbor_head(output, 2, value.len() as u64);
    output.extend_from_slice(value);
}

fn cbor_text(output: &mut Vec<u8>, value: &str) {
    cbor_head(output, 3, value.len() as u64);
    output.extend_from_slice(value.as_bytes());
}

fn cbor_optional_digest(
    output: &mut Vec<u8>,
    value: Option<&str>,
) -> Result<(), PolicyEnforcementError> {
    if let Some(value) = value {
        cbor_bytes(output, &digest_bytes(value)?);
    } else {
        output.push(0xf6);
    }
    Ok(())
}

fn cbor_unsigned(output: &mut Vec<u8>, value: u64) {
    cbor_head(output, 0, value);
}

fn cbor_integer(output: &mut Vec<u8>, value: i64) {
    if value >= 0 {
        cbor_head(output, 0, value as u64);
    } else {
        cbor_head(output, 1, value.unsigned_abs() - 1);
    }
}

fn cbor_head(output: &mut Vec<u8>, major: u8, value: u64) {
    let prefix = major << 5;
    match value {
        0..=23 => output.push(prefix | value as u8),
        24..=0xff => output.extend_from_slice(&[prefix | 24, value as u8]),
        0x100..=0xffff => {
            output.push(prefix | 25);
            output.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(prefix | 26);
            output.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            output.push(prefix | 27);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn domain_digest(domain: &[u8], canonical: &[u8]) -> String {
    let mut input = Vec::with_capacity(domain.len() + 1 + 8 + canonical.len());
    input.extend_from_slice(domain);
    input.push(0);
    input.extend_from_slice(&(canonical.len() as u64).to_be_bytes());
    input.extend_from_slice(canonical);
    sha256_digest(&input)
}

fn extract_evidence(
    response: &FilesystemExecutionResponse,
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_request(
        tool_name: &str,
        arguments: Value,
    ) -> (tempfile::TempDir, ToolExecutionRequest) {
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
                    "name": tool_name,
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
            tool_name,
            plan_tool_name: tool_name,
            arguments,
            plan_checkpoint_input: Some(&plan),
        })
        .unwrap();
        (workspace, request)
    }

    fn approval_required_response(
        request: &ToolExecutionRequest,
        operation: &ValidatedOperation,
    ) -> FilesystemExecutionResponse {
        let proposal_digest = request.digest().unwrap();
        let task_policy_hash = sha256_digest(b"task policy");
        let prestate_hash = sha256_digest(b"prestate");
        let recorded_at = 1_800_000_000;
        let action = FilesystemApprovalAction {
            extension_id: "developer".to_owned(),
            tool_name: request.tool_name.clone(),
            relative_path: operation.relative_path.clone(),
            action_type: ApprovalActionType::CreateFile,
            requested_bytes: 5,
        };
        let action_hash = approval_action_hash(&proposal_digest, &prestate_hash, &action).unwrap();
        let task_id = uuid::Uuid::from_u128(3).to_string();
        let requirement_id = derived_approval_record_id(
            b"accordlock:v2:task-requirement-id",
            &task_id,
            &proposal_digest,
            &prestate_hash,
            &action_hash,
            1,
            recorded_at,
        )
        .unwrap();
        let step_id = derived_approval_record_id(
            b"accordlock:v2:transformation-step-id",
            &task_id,
            &proposal_digest,
            &prestate_hash,
            &action_hash,
            1,
            recorded_at,
        )
        .unwrap();
        let decision_id = derived_approval_record_id(
            b"accordlock:v2:policy-decision-id",
            &task_id,
            &proposal_digest,
            &prestate_hash,
            &action_hash,
            1,
            recorded_at,
        )
        .unwrap();
        let task_requirement = ApprovalTaskRequirement {
            schema_version: 2,
            requirement_id,
            task_hash: task_policy_hash.clone(),
            statement_hash: sha256_digest(b"objective"),
            minimum_score: 1_000_000,
        };
        let transformation_step = ApprovalTransformationStep {
            schema_version: 2,
            step_id,
            task_hash: task_policy_hash.clone(),
            sequence: 0,
            parent_step_hash: None,
            source_stage: ApprovalWorkflowStage::Request,
            source_hash: task_requirement.statement_hash.clone(),
            target_stage: ApprovalWorkflowStage::Action,
            target_hash: action_hash.clone(),
            recorded_at,
        };
        let policy_decision = ApprovalPolicyDecision {
            schema_version: 2,
            decision_id,
            task_hash: task_policy_hash.clone(),
            action_hash,
            sequence: 0,
            parent_decision_hash: None,
            requirement_hashes: vec![approval_task_requirement_hash(&task_requirement).unwrap()],
            transformation_step_hashes: vec![approval_transformation_step_hash(
                &transformation_step,
            )
            .unwrap()],
            conformance_evaluation_hashes: vec![],
            resource_request_hashes: vec![],
            resource_quota_hashes: vec![],
            resource_reservation_hashes: vec![],
            baseline_decision: ApprovalEnforcementDecision::Allow,
            decision: ApprovalEnforcementDecision::RequireApproval,
            reasons: vec![ApprovalDecisionReason::ConformanceEvaluationMissing],
            policy_epoch: 1,
            evaluated_at: recorded_at,
        };
        let policy_decision_hash = approval_policy_decision_hash(&policy_decision).unwrap();
        let approval_request = serde_json::to_value(FilesystemApprovalRequest {
            schema_version: ACTION_APPROVAL_SCHEMA_VERSION,
            task_id,
            session_id: request.session_id.clone(),
            run_id: request.run_id.clone(),
            tool_call_id: request.tool_call_id.clone(),
            proposal_digest: proposal_digest.clone(),
            task_policy_hash,
            prestate_hash,
            action,
            task_requirement,
            transformation_step,
            policy_decision,
            policy_decision_hash,
        })
        .unwrap();
        let approval_request_hash = domain_digest(
            b"accordlock:v2:action-approval-request",
            &canonical_json_bytes(&approval_request).unwrap(),
        );
        FilesystemExecutionResponse {
            schema_version: PROTOCOL_VERSION,
            proposal_digest: request.digest().unwrap(),
            status: FilesystemExecutionStatus::ApprovalRequired,
            reason_code: "ACTION_APPROVAL_REQUIRED".to_owned(),
            authorization_id: None,
            request_hash: None,
            record_id: None,
            record_hash: None,
            result_sha256: None,
            result: None,
            approval_request: Some(approval_request),
            approval_request_hash: Some(approval_request_hash),
        }
    }

    fn refresh_approval_request_hash(response: &mut FilesystemExecutionResponse) {
        let approval_request = response.approval_request.as_ref().unwrap();
        response.approval_request_hash = Some(domain_digest(
            b"accordlock:v2:action-approval-request",
            &canonical_json_bytes(approval_request).unwrap(),
        ));
    }

    #[test]
    fn filesystem_routes_are_explicit() {
        for tool in ["read", "write", "edit", "delete_file", "tree"] {
            assert_eq!(classify("developer", tool), FilesystemRoute::Brokered);
        }
        for tool in ["shell", "read_image"] {
            assert_eq!(
                classify("developer", tool),
                FilesystemRoute::ForbiddenDirect
            );
        }
        assert_eq!(classify("external", "write"), FilesystemRoute::Unrelated);
    }

    #[test]
    fn broker_accepts_only_portable_relative_paths() {
        for path in [
            "../secret",
            "src/../secret",
            "/etc/passwd",
            "C:\\secret",
            "\\\\server\\share",
            "file.txt:stream",
            "src//main.rs",
            "NUL.txt",
            "dir/. /file",
        ] {
            let (_workspace, request) =
                make_request("write", json!({"path": path, "content": "not written"}));
            assert!(validate_execution_request(&request).is_err(), "{path}");
        }

        let (_workspace, request) = make_request(
            "write",
            json!({"path": "src/main.rs", "content": "fn main() {}"}),
        );
        assert!(validate_execution_request(&request).is_ok());

        let (_workspace, request) = make_request("tree", json!({"path": ".", "depth": 2}));
        assert!(validate_execution_request(&request).is_ok());
    }

    #[test]
    fn broker_argument_shapes_are_closed_and_bounded() {
        let (_workspace, request) = make_request(
            "read",
            json!({"path": "src/main.rs", "line": 0, "limit": 1}),
        );
        assert!(validate_execution_request(&request).is_err());

        let (_workspace, request) =
            make_request("tree", json!({"path": ".", "depth": MAX_TREE_DEPTH + 1}));
        assert!(validate_execution_request(&request).is_err());

        let (_workspace, request) = make_request(
            "write",
            json!({"path": "safe.txt", "content": "x", "unexpected": true}),
        );
        assert!(validate_execution_request(&request).is_err());
    }

    #[test]
    fn approval_required_response_is_parsed_and_bound_to_the_exact_write() {
        let (_workspace, request) =
            make_request("write", json!({"path": "notes.txt", "content": "hello"}));
        let proposal_digest = request.digest().unwrap();
        let operation = validate_execution_request(&request).unwrap();
        let response = approval_required_response(&request, &operation);

        assert_eq!(
            validate_response(response.clone(), &operation, &request, &proposal_digest)
                .unwrap_err(),
            PolicyEnforcementError::ApprovalRequired("ACTION_APPROVAL_REQUIRED".to_owned())
        );

        let mut tampered = response;
        tampered.approval_request_hash = Some(sha256_digest(b"tampered"));
        assert_eq!(
            validate_response(tampered, &operation, &request, &proposal_digest).unwrap_err(),
            PolicyEnforcementError::ExecutionUnknown
        );
    }

    #[test]
    fn approval_required_response_rejects_empty_or_malformed_policy_records() {
        let (_workspace, request) =
            make_request("write", json!({"path": "notes.txt", "content": "hello"}));
        let proposal_digest = request.digest().unwrap();
        let operation = validate_execution_request(&request).unwrap();

        for pointer in [
            "/task_requirement",
            "/transformation_step",
            "/policy_decision",
        ] {
            let mut response = approval_required_response(&request, &operation);
            *response
                .approval_request
                .as_mut()
                .unwrap()
                .pointer_mut(pointer)
                .unwrap() = json!({});
            refresh_approval_request_hash(&mut response);
            assert_eq!(
                validate_response(response, &operation, &request, &proposal_digest).unwrap_err(),
                PolicyEnforcementError::ExecutionUnknown,
                "{pointer}"
            );
        }

        let mut response = approval_required_response(&request, &operation);
        response.approval_request.as_mut().unwrap()["task_requirement"]["unexpected"] = json!(true);
        refresh_approval_request_hash(&mut response);
        assert_eq!(
            validate_response(response, &operation, &request, &proposal_digest).unwrap_err(),
            PolicyEnforcementError::ExecutionUnknown
        );
    }

    #[test]
    fn approval_required_response_rejects_broken_policy_bindings_and_decision() {
        let (_workspace, request) =
            make_request("write", json!({"path": "notes.txt", "content": "hello"}));
        let proposal_digest = request.digest().unwrap();
        let operation = validate_execution_request(&request).unwrap();
        let mutations = [
            (
                "/transformation_step/target_hash",
                json!(sha256_digest(b"other action")),
            ),
            (
                "/policy_decision/action_hash",
                json!(sha256_digest(b"other action")),
            ),
            ("/policy_decision/decision", json!("ALLOW")),
            ("/policy_decision/reasons", json!(["REQUIREMENT_SATISFIED"])),
            ("/policy_decision/requirement_hashes", json!([])),
            (
                "/policy_decision/requirement_hashes",
                json!([sha256_digest(b"substituted requirement")]),
            ),
            (
                "/policy_decision/transformation_step_hashes",
                json!([sha256_digest(b"substituted transformation")]),
            ),
            (
                "/policy_decision_hash",
                json!(sha256_digest(b"substituted policy decision")),
            ),
            (
                "/task_requirement/requirement_id",
                json!(uuid::Uuid::from_u128(40).to_string()),
            ),
            (
                "/transformation_step/step_id",
                json!(uuid::Uuid::from_u128(50).to_string()),
            ),
            (
                "/policy_decision/decision_id",
                json!(uuid::Uuid::from_u128(60).to_string()),
            ),
            (
                "/policy_decision_hash",
                json!(format!("sha256:{}", "0".repeat(64))),
            ),
        ];

        for (pointer, replacement) in mutations {
            let mut response = approval_required_response(&request, &operation);
            *response
                .approval_request
                .as_mut()
                .unwrap()
                .pointer_mut(pointer)
                .unwrap() = replacement;
            refresh_approval_request_hash(&mut response);
            assert_eq!(
                validate_response(response, &operation, &request, &proposal_digest).unwrap_err(),
                PolicyEnforcementError::ExecutionUnknown,
                "{pointer}"
            );
        }
    }

    #[test]
    fn successful_response_is_bound_to_operation_path_and_result_digest() {
        let (_workspace, request) = make_request(
            "read",
            json!({"path": "src/main.rs", "line": null, "limit": null}),
        );
        let proposal_digest = request.digest().unwrap();
        let result = BrokeredFilesystemResult::Read {
            relative_path: "src/main.rs".to_owned(),
            content: "fn main() {}".to_owned(),
            content_sha256: sha256_digest(b"fn main() {}"),
            truncated: false,
        };
        let result_sha256 = canonical_json_bytes(&result)
            .map(|bytes| sha256_digest(&bytes))
            .unwrap();
        let response = FilesystemExecutionResponse {
            schema_version: PROTOCOL_VERSION,
            proposal_digest: proposal_digest.clone(),
            status: FilesystemExecutionStatus::Succeeded,
            reason_code: "EXECUTED".to_owned(),
            authorization_id: Some(uuid::Uuid::from_u128(1).to_string()),
            request_hash: Some(sha256_digest(b"intent")),
            record_id: Some(uuid::Uuid::from_u128(2).to_string()),
            record_hash: Some(sha256_digest(b"record")),
            result_sha256: Some(result_sha256),
            result: Some(result.clone()),
            approval_request: None,
            approval_request_hash: None,
        };
        let operation = validate_execution_request(&request).unwrap();
        assert!(
            validate_response(response.clone(), &operation, &request, &proposal_digest).is_ok()
        );

        let mut mismatched = response;
        mismatched.result = Some(BrokeredFilesystemResult::Read {
            relative_path: "other.rs".to_owned(),
            content: "fn main() {}".to_owned(),
            content_sha256: sha256_digest(b"fn main() {}"),
            truncated: false,
        });
        assert_eq!(
            validate_response(mismatched, &operation, &request, &proposal_digest).unwrap_err(),
            PolicyEnforcementError::ExecutionUnknown
        );
    }

    #[test]
    fn ambiguous_mutation_is_a_no_retry_policy_enforcement_error() {
        let (_workspace, request) =
            make_request("write", json!({"path": "notes.txt", "content": "hello"}));
        let proposal_digest = request.digest().unwrap();
        let operation = validate_execution_request(&request).unwrap();
        let response = FilesystemExecutionResponse {
            schema_version: PROTOCOL_VERSION,
            proposal_digest: proposal_digest.clone(),
            status: FilesystemExecutionStatus::ExecutionUnknown,
            reason_code: "IO_AMBIGUOUS".to_owned(),
            authorization_id: Some(uuid::Uuid::from_u128(1).to_string()),
            request_hash: Some(sha256_digest(b"intent")),
            record_id: Some(uuid::Uuid::from_u128(2).to_string()),
            record_hash: Some(sha256_digest(b"record")),
            result_sha256: None,
            result: None,
            approval_request: None,
            approval_request_hash: None,
        };

        assert!(matches!(
            validate_response(response, &operation, &request, &proposal_digest),
            Err(PolicyEnforcementError::ExecutionUnknown)
        ));
    }

    #[test]
    fn delete_result_is_bound_to_the_authorization_and_exact_recovery_path() {
        let (_workspace, request) = make_request("delete_file", json!({"path": "notes.txt"}));
        let proposal_digest = request.digest().unwrap();
        let operation = validate_execution_request(&request).unwrap();
        let authorization_id = uuid::Uuid::from_u128(1).to_string();
        let result = BrokeredFilesystemResult::Delete {
            relative_path: "notes.txt".to_owned(),
            recovery_id: authorization_id.clone(),
            recovery_path: format!(".accordlock/recovery/{authorization_id}/content"),
            original_bytes: 5,
            content_sha256: sha256_digest(b"hello"),
        };
        let result_sha256 = canonical_json_bytes(&result)
            .map(|bytes| sha256_digest(&bytes))
            .unwrap();
        let response = FilesystemExecutionResponse {
            schema_version: PROTOCOL_VERSION,
            proposal_digest: proposal_digest.clone(),
            status: FilesystemExecutionStatus::Succeeded,
            reason_code: "RECONCILED".to_owned(),
            authorization_id: Some(authorization_id),
            request_hash: Some(sha256_digest(b"intent")),
            record_id: Some(uuid::Uuid::from_u128(2).to_string()),
            record_hash: Some(sha256_digest(b"record")),
            result_sha256: Some(result_sha256),
            result: Some(result),
            approval_request: None,
            approval_request_hash: None,
        };
        assert!(
            validate_response(response.clone(), &operation, &request, &proposal_digest).is_ok()
        );

        let mut mismatched = response;
        if let Some(BrokeredFilesystemResult::Delete { recovery_id, .. }) = &mut mismatched.result {
            *recovery_id = uuid::Uuid::from_u128(3).to_string();
        }
        assert_eq!(
            validate_response(mismatched, &operation, &request, &proposal_digest).unwrap_err(),
            PolicyEnforcementError::ExecutionUnknown
        );
    }

    #[tokio::test]
    async fn runtime_broker_uses_combined_endpoint_and_accepts_a_recorded_result() {
        use wiremock::matchers::{bearer_token, body_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (_workspace, request) =
            make_request("write", json!({"path": "notes.txt", "content": "hello"}));
        let result = BrokeredFilesystemResult::Write {
            relative_path: "notes.txt".to_owned(),
            created: true,
            bytes_written: 5,
            content_sha256: sha256_digest(b"hello"),
        };
        let response = json!({
            "schema_version": PROTOCOL_VERSION,
            "proposal_digest": request.digest().unwrap(),
            "status": "SUCCEEDED",
            "reason_code": "EXECUTED",
            "authorization_id": uuid::Uuid::from_u128(1).to_string(),
            "request_hash": sha256_digest(b"intent"),
            "record_id": uuid::Uuid::from_u128(2).to_string(),
            "record_hash": sha256_digest(b"record"),
            "result_sha256": canonical_json_bytes(&result).map(|bytes| sha256_digest(&bytes)).unwrap(),
            "result": result,
        });
        Mock::given(method("POST"))
            .and(path(FILESYSTEM_EXECUTE_PATH))
            .and(bearer_token("0123456789abcdef0123456789abcdef"))
            .and(body_json(json!({
                "schema_version": PROTOCOL_VERSION,
                "proposal": request.clone(),
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;

        let broker = RuntimeFilesystemBroker::new(
            &format!("{}/", server.uri()),
            "0123456789abcdef0123456789abcdef".to_owned(),
        )
        .unwrap();
        let outcome = broker.authorize_and_execute(&request).await.unwrap();
        assert!(matches!(
            outcome,
            BrokeredFilesystemOutcome::Succeeded { .. }
        ));
    }
}
