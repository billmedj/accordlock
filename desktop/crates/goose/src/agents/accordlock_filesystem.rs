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
        validate_response(response, &operation, &expected_proposal_digest)
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
            if !matches!(response.reason_code.as_str(), "EXECUTED" | "RECONCILED") {
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
            if response.result.is_some() || response.result_sha256.is_some() {
                return Err(PolicyEnforcementError::ExecutionUnknown);
            }
            let evidence = extract_evidence(&response)?;
            Ok(BrokeredFilesystemOutcome::ToolError {
                reason_code: response.reason_code,
                evidence,
            })
        }
        FilesystemExecutionStatus::ExecutionUnknown => {
            if response.result.is_some() || response.result_sha256.is_some() {
                return Err(PolicyEnforcementError::ExecutionUnknown);
            }
            let _evidence = extract_evidence(&response)?;
            Err(PolicyEnforcementError::ExecutionUnknown)
        }
        FilesystemExecutionStatus::Denied | FilesystemExecutionStatus::ApprovalRequired => {
            if response.authorization_id.is_some()
                || response.request_hash.is_some()
                || response.record_id.is_some()
                || response.record_hash.is_some()
                || response.result_sha256.is_some()
                || response.result.is_some()
            {
                return Err(PolicyEnforcementError::ExecutionUnknown);
            }
            if response.status == FilesystemExecutionStatus::Denied {
                Err(PolicyEnforcementError::Denied(response.reason_code))
            } else {
                Err(PolicyEnforcementError::ApprovalRequired(
                    response.reason_code,
                ))
            }
        }
    }
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
        };
        let operation = validate_execution_request(&request).unwrap();
        assert!(validate_response(response.clone(), &operation, &proposal_digest).is_ok());

        let mut mismatched = response;
        mismatched.result = Some(BrokeredFilesystemResult::Read {
            relative_path: "other.rs".to_owned(),
            content: "fn main() {}".to_owned(),
            content_sha256: sha256_digest(b"fn main() {}"),
            truncated: false,
        });
        assert_eq!(
            validate_response(mismatched, &operation, &proposal_digest).unwrap_err(),
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
        };

        assert!(matches!(
            validate_response(response, &operation, &proposal_digest),
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
        };
        assert!(validate_response(response.clone(), &operation, &proposal_digest).is_ok());

        let mut mismatched = response;
        if let Some(BrokeredFilesystemResult::Delete { recovery_id, .. }) = &mut mismatched.result {
            *recovery_id = uuid::Uuid::from_u128(3).to_string();
        }
        assert_eq!(
            validate_response(mismatched, &operation, &proposal_digest).unwrap_err(),
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
