use std::{
    ffi::OsString,
    io::{self, Read as _, Seek as _, SeekFrom, Write as _},
    path::{Component, Path, PathBuf},
};

use accordlock_agent_protocol::Digest32;
use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unicode_general_category::{GeneralCategory, get_general_category};

use crate::{
    ActionApprovalRequest, ActionDescriptor, ActionType, Ledger, LedgerError,
    ledger::{AuthorizationGrant, AuthorizationResult, ObservationResult},
    model::{
        TOOL_EXECUTION_SCHEMA_VERSION, ToolCallProposal, ToolExecutionObservation,
        WireExecutionOutcome,
    },
    policy::AutomaticExecutionClass,
};

pub const FILESYSTEM_EXECUTE_PATH: &str = "/api/v2/execution/filesystem/authorize-and-execute";

const MAX_RELATIVE_PATH_BYTES: usize = 4 * 1024;
const MAX_PATH_COMPONENT_BYTES: usize = 255;
const MAX_PATH_COMPONENTS: usize = 64;
const MAX_FILE_BYTES: usize = 1024 * 1024;
const MAX_RESULT_CONTENT_BYTES: usize = 256 * 1024;
const MAX_TREE_DEPTH: u32 = 8;
const MAX_TREE_ENTRIES: usize = 2_000;
const FILESYSTEM_PRESTATE_DOMAIN: &[u8] = b"accordlock:v1:filesystem-prestate";
const RECOVERY_ROOT_COMPONENTS: [&str; 2] = [".accordlock", "recovery"];
const RECOVERY_CONTENT_NAME: &str = "content";

fn has_disallowed_unicode_path_character(value: &str) -> bool {
    value.chars().any(|character| {
        matches!(
            get_general_category(character),
            GeneralCategory::Format
                | GeneralCategory::LineSeparator
                | GeneralCategory::ParagraphSeparator
        )
    })
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FilesystemExecutionRequest {
    pub schema_version: u16,
    pub proposal: ToolCallProposal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum FilesystemExecutionStatus {
    Succeeded,
    ToolError,
    ExecutionUnknown,
    Denied,
    ApprovalRequired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum FilesystemResult {
    Read {
        relative_path: String,
        content: String,
        content_sha256: String,
        truncated: bool,
    },
    Tree {
        relative_path: String,
        content: String,
        entries: usize,
        truncated: bool,
    },
    Write {
        relative_path: String,
        created: bool,
        bytes_written: usize,
        content_sha256: String,
    },
    Edit {
        relative_path: String,
        bytes_written: usize,
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

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FilesystemExecutionResponse {
    pub schema_version: u16,
    pub proposal_digest: String,
    pub status: FilesystemExecutionStatus,
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
    pub result: Option<FilesystemResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_request: Option<ActionApprovalRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_request_hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PreparedFilesystemOperation {
    Read {
        path: ValidatedRelativePath,
        line: Option<u32>,
        limit: Option<u32>,
    },
    Tree {
        path: ValidatedRelativePath,
        depth: u32,
    },
    Write {
        path: ValidatedRelativePath,
        content: String,
    },
    Edit {
        path: ValidatedRelativePath,
        before: String,
        after: String,
    },
    Delete {
        path: ValidatedRelativePath,
    },
}

impl PreparedFilesystemOperation {
    pub(crate) fn from_proposal(proposal: &ToolCallProposal) -> Result<Self, FilesystemInputError> {
        if proposal.extension_id != "developer" {
            return Err(FilesystemInputError::UnsupportedTool);
        }
        match proposal.tool_name.as_str() {
            "read" => {
                let arguments = parse_arguments::<ReadArguments>(&proposal.arguments)?;
                if arguments.line == Some(0) || arguments.limit == Some(0) {
                    return Err(FilesystemInputError::InvalidRange);
                }
                Ok(Self::Read {
                    path: ValidatedRelativePath::new(&arguments.path, false)?,
                    line: arguments.line,
                    limit: arguments.limit,
                })
            }
            "tree" => {
                let arguments = parse_arguments::<TreeArguments>(&proposal.arguments)?;
                if !(1..=MAX_TREE_DEPTH).contains(&arguments.depth) {
                    return Err(FilesystemInputError::InvalidRange);
                }
                Ok(Self::Tree {
                    path: ValidatedRelativePath::new(&arguments.path, true)?,
                    depth: arguments.depth,
                })
            }
            "write" => {
                let arguments = parse_arguments::<WriteArguments>(&proposal.arguments)?;
                if arguments.content.len() > MAX_FILE_BYTES {
                    return Err(FilesystemInputError::ContentTooLarge);
                }
                Ok(Self::Write {
                    path: ValidatedRelativePath::new(&arguments.path, false)?,
                    content: arguments.content,
                })
            }
            "edit" => {
                let arguments = parse_arguments::<EditArguments>(&proposal.arguments)?;
                if arguments.before.is_empty()
                    || arguments.before.len() > MAX_FILE_BYTES
                    || arguments.after.len() > MAX_FILE_BYTES
                {
                    return Err(FilesystemInputError::ContentTooLarge);
                }
                Ok(Self::Edit {
                    path: ValidatedRelativePath::new(&arguments.path, false)?,
                    before: arguments.before,
                    after: arguments.after,
                })
            }
            "delete_file" => {
                let arguments = parse_arguments::<DeleteArguments>(&proposal.arguments)?;
                Ok(Self::Delete {
                    path: ValidatedRelativePath::new(&arguments.path, false)?,
                })
            }
            _ => Err(FilesystemInputError::UnsupportedTool),
        }
    }

    fn relative_path(&self) -> &ValidatedRelativePath {
        match self {
            Self::Read { path, .. }
            | Self::Tree { path, .. }
            | Self::Write { path, .. }
            | Self::Edit { path, .. }
            | Self::Delete { path } => path,
        }
    }

    fn may_mutate(&self) -> bool {
        matches!(
            self,
            Self::Write { .. } | Self::Edit { .. } | Self::Delete { .. }
        )
    }

    fn automatic_execution_class(&self) -> Option<AutomaticExecutionClass> {
        match self {
            Self::Read { .. } => Some(AutomaticExecutionClass::LocalFileRead),
            Self::Tree { .. } => Some(AutomaticExecutionClass::LocalDirectoryTree),
            Self::Write { .. } | Self::Edit { .. } | Self::Delete { .. } => None,
        }
    }

    fn mutation_approval_input(
        &self,
        workspace_root: &Path,
    ) -> Result<Option<(Digest32, ActionDescriptor)>, ToolError> {
        let workspace = open_workspace(workspace_root)?;
        match self {
            Self::Read { .. } | Self::Tree { .. } => Ok(None),
            Self::Write { path, content } => {
                let prestate = observe_prestate(&workspace, path, true)?;
                let action_type = if prestate.kind == PrestateKind::Absent {
                    ActionType::CreateFile
                } else {
                    ActionType::OverwriteFile
                };
                Ok(Some((
                    prestate.digest()?,
                    ActionDescriptor {
                        extension_id: "developer".to_owned(),
                        tool_name: "write".to_owned(),
                        relative_path: path.display.clone(),
                        action_type,
                        requested_bytes: u64::try_from(content.len())
                            .map_err(|_| ToolError::ContentTooLarge)?,
                        executable_path: None,
                        executable_sha256: None,
                    },
                )))
            }
            Self::Edit { path, after, .. } => {
                let prestate = observe_prestate(&workspace, path, false)?;
                Ok(Some((
                    prestate.digest()?,
                    ActionDescriptor {
                        extension_id: "developer".to_owned(),
                        tool_name: "edit".to_owned(),
                        relative_path: path.display.clone(),
                        action_type: ActionType::EditFile,
                        requested_bytes: u64::try_from(after.len())
                            .map_err(|_| ToolError::ContentTooLarge)?,
                        executable_path: None,
                        executable_sha256: None,
                    },
                )))
            }
            Self::Delete { path } => {
                let prestate = observe_prestate(&workspace, path, false)?;
                Ok(Some((
                    prestate.digest()?,
                    ActionDescriptor {
                        extension_id: "developer".to_owned(),
                        tool_name: "delete_file".to_owned(),
                        relative_path: path.display.clone(),
                        action_type: ActionType::DeleteFile,
                        requested_bytes: prestate.content_bytes,
                        executable_path: None,
                        executable_sha256: None,
                    },
                )))
            }
        }
    }

    pub(crate) fn execute(
        &self,
        workspace_root: &Path,
        expected_prestate_hash: Option<Digest32>,
        protected_paths: &[String],
        recovery_id: Option<&str>,
    ) -> Result<FilesystemResult, ToolError> {
        let workspace = open_workspace(workspace_root)?;
        match self {
            Self::Read { path, line, limit } => execute_read(&workspace, path, *line, *limit),
            Self::Tree { path, depth } => execute_tree(&workspace, path, *depth, protected_paths),
            Self::Write { path, content } => execute_write(
                &workspace,
                path,
                content,
                expected_prestate_hash.ok_or(ToolError::StateStale)?,
            ),
            Self::Edit {
                path,
                before,
                after,
            } => execute_edit(
                &workspace,
                path,
                before,
                after,
                expected_prestate_hash.ok_or(ToolError::StateStale)?,
            ),
            Self::Delete { path } => execute_delete(
                &workspace,
                path,
                expected_prestate_hash.ok_or(ToolError::StateStale)?,
                recovery_id.ok_or(ToolError::RecoveryUnavailable)?,
            ),
        }
    }

    fn reconcile_success(
        &self,
        workspace_root: &Path,
        expected_prestate_hash: Digest32,
        recovery_id: &str,
    ) -> Result<Option<FilesystemResult>, ToolError> {
        let workspace = open_workspace(workspace_root)?;
        match self {
            Self::Read { .. } | Self::Tree { .. } => Ok(None),
            Self::Write { path, content } => {
                let observed = observe_prestate(&workspace, path, true)?;
                let expected_content = Digest32::sha256(content.as_bytes());
                if observed.kind != PrestateKind::RegularFile
                    || observed.content_sha256 != Some(expected_content)
                    || observed.content_bytes != content.len() as u64
                {
                    return Ok(None);
                }
                Ok(Some(FilesystemResult::Write {
                    relative_path: path.display.clone(),
                    created: expected_prestate_hash == ObservedPrestate::absent().digest()?,
                    bytes_written: content.len(),
                    content_sha256: expected_content.to_string(),
                }))
            }
            Self::Edit {
                path,
                before,
                after,
            } => reconcile_edit_result(&workspace, path, before, after, expected_prestate_hash),
            Self::Delete { path } => {
                reconcile_delete_result(&workspace, path, expected_prestate_hash, recovery_id)
            }
        }
    }
}

pub(crate) fn execute_governed(
    ledger: &Ledger,
    request: &FilesystemExecutionRequest,
    now: i64,
    grant_lifetime_seconds: i64,
) -> Result<FilesystemExecutionResponse, GovernedFilesystemError> {
    if request.schema_version != TOOL_EXECUTION_SCHEMA_VERSION {
        return Err(GovernedFilesystemError::Input);
    }
    request
        .proposal
        .validate()
        .map_err(|_| GovernedFilesystemError::Input)?;
    let operation = PreparedFilesystemOperation::from_proposal(&request.proposal)
        .map_err(|_| GovernedFilesystemError::Input)?;
    let expected_proposal_digest = request
        .proposal
        .digest()
        .map_err(|_| GovernedFilesystemError::Input)?;
    let protected_paths = ledger.task_policy_protected_paths(&request.proposal)?;
    if is_protected_path(operation.relative_path().display.as_str(), &protected_paths) {
        return Ok(denied_response(
            expected_proposal_digest,
            "PROTECTED_PATH",
            None,
        ));
    }
    // Hold the authority barrier while checking for a durable prior attempt,
    // executing, reconciling, and recording the final outcome.
    let _execution_scope = ledger.begin_execution_scope()?;
    if operation.may_mutate()
        && let Some(attempt) = ledger.attempt_for_proposal(&request.proposal)?
    {
        return reconcile_existing_attempt(
            ledger,
            &request.proposal,
            &operation,
            expected_proposal_digest,
            &attempt,
            now,
        );
    }
    let approval_input = operation
        .mutation_approval_input(Path::new(&request.proposal.workspace_root))
        .map_err(|_| GovernedFilesystemError::Input)?;
    let expected_prestate_hash = approval_input.as_ref().map(|(hash, _)| *hash);
    let approval_request = match approval_input {
        Some((prestate_hash, action)) => {
            ledger.action_approval_request(&request.proposal, prestate_hash, action)?
        }
        None => None,
    };
    match ledger.authorize_and_consume(
        &request.proposal,
        approval_request.as_ref(),
        operation.automatic_execution_class(),
        now,
        grant_lifetime_seconds,
    )? {
        AuthorizationResult::Denied(reason_code) => Ok(denied_response(
            expected_proposal_digest,
            reason_code,
            if reason_code == "ACTION_APPROVAL_REQUIRED" {
                approval_request
            } else {
                None
            },
        )),
        AuthorizationResult::Allowed(grant) => execute_authorized_operation(
            ledger,
            &request.proposal,
            &operation,
            expected_proposal_digest,
            expected_prestate_hash,
            &protected_paths,
            &grant,
            now,
        ),
    }
}

pub(crate) fn validated_automatic_execution_class(
    proposal: &ToolCallProposal,
    protected_paths: &[String],
) -> Option<AutomaticExecutionClass> {
    let operation = PreparedFilesystemOperation::from_proposal(proposal).ok()?;
    let execution_class = operation.automatic_execution_class()?;
    if is_protected_path(operation.relative_path().display.as_str(), protected_paths) {
        return None;
    }
    Some(execution_class)
}

fn reconcile_existing_attempt(
    ledger: &Ledger,
    proposal: &ToolCallProposal,
    operation: &PreparedFilesystemOperation,
    expected_proposal_digest: String,
    attempt: &crate::ledger::ReconciliationAttempt,
    now: i64,
) -> Result<FilesystemExecutionResponse, GovernedFilesystemError> {
    if attempt.proposal_digest != expected_proposal_digest {
        return Err(GovernedFilesystemError::ExecutionStateUnknown);
    }
    if attempt.state == "EXECUTION_UNKNOWN" {
        return existing_unknown_response(expected_proposal_digest, attempt);
    }
    let prestate_hash = attempt
        .prestate_hash
        .ok_or(GovernedFilesystemError::ExecutionStateUnknown)?;
    let authorization_id = attempt.authorization_id.to_string();
    let request_hash = attempt.request_hash.to_string();
    let result = operation
        .reconcile_success(
            Path::new(&proposal.workspace_root),
            prestate_hash,
            &authorization_id,
        )
        .map_err(|_| GovernedFilesystemError::ExecutionStateUnknown)?;

    if attempt.state == "SUCCEEDED" {
        let result = result.ok_or(GovernedFilesystemError::ExecutionStateUnknown)?;
        let digest =
            result_digest(&result).map_err(|_| GovernedFilesystemError::ExecutionStateUnknown)?;
        return Ok(success_response(
            expected_proposal_digest,
            authorization_id,
            request_hash,
            completed_observation(attempt)?,
            digest,
            result,
            "RECONCILED",
        ));
    }
    if attempt.state != "IN_FLIGHT" {
        return Err(GovernedFilesystemError::ExecutionStateUnknown);
    }
    let Some(result) = result else {
        let observation = ToolExecutionObservation {
            schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
            authorization_id: authorization_id.clone(),
            proposal_digest: expected_proposal_digest.clone(),
            request_hash: request_hash.clone(),
            outcome: WireExecutionOutcome::TransportError,
            result_digest: None,
        };
        let record = ledger
            .observe(&observation, now)
            .map_err(|_| GovernedFilesystemError::ExecutionStateUnknown)?;
        return Ok(execution_state_unknown_response(
            expected_proposal_digest,
            authorization_id,
            request_hash,
            record,
            "POSTSTATE_NOT_CONFIRMED",
        ));
    };
    let digest =
        result_digest(&result).map_err(|_| GovernedFilesystemError::ExecutionStateUnknown)?;
    let observation = ToolExecutionObservation {
        schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
        authorization_id: authorization_id.clone(),
        proposal_digest: expected_proposal_digest.clone(),
        request_hash: request_hash.clone(),
        outcome: WireExecutionOutcome::Succeeded,
        result_digest: Some(digest.clone()),
    };
    let record = ledger
        .observe(&observation, now)
        .map_err(|_| GovernedFilesystemError::ExecutionStateUnknown)?;
    Ok(success_response(
        expected_proposal_digest,
        authorization_id,
        request_hash,
        record,
        digest,
        result,
        "RECONCILED",
    ))
}

fn completed_observation(
    attempt: &crate::ledger::ReconciliationAttempt,
) -> Result<ObservationResult, GovernedFilesystemError> {
    Ok(ObservationResult {
        authorization_id: attempt.authorization_id,
        observation_digest: attempt
            .observation_digest
            .clone()
            .ok_or(GovernedFilesystemError::ExecutionStateUnknown)?,
        record_id: attempt
            .record_id
            .ok_or(GovernedFilesystemError::ExecutionStateUnknown)?,
        record_hash: attempt
            .record_hash
            .clone()
            .ok_or(GovernedFilesystemError::ExecutionStateUnknown)?,
    })
}

fn existing_unknown_response(
    proposal_digest: String,
    attempt: &crate::ledger::ReconciliationAttempt,
) -> Result<FilesystemExecutionResponse, GovernedFilesystemError> {
    Ok(execution_state_unknown_response(
        proposal_digest,
        attempt.authorization_id.to_string(),
        attempt.request_hash.to_string(),
        completed_observation(attempt)?,
        "PRIOR_EXECUTION_UNKNOWN",
    ))
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn execute_authorized_operation(
    ledger: &Ledger,
    proposal: &ToolCallProposal,
    operation: &PreparedFilesystemOperation,
    expected_proposal_digest: String,
    expected_prestate_hash: Option<Digest32>,
    protected_paths: &[String],
    grant: &AuthorizationGrant,
    now: i64,
) -> Result<FilesystemExecutionResponse, GovernedFilesystemError> {
    if grant.proposal_digest != expected_proposal_digest {
        return Err(GovernedFilesystemError::ExecutionStateUnknown);
    }
    let authorization_id = grant.authorization_id.to_string();
    let request_hash = grant.request_hash.to_string();
    match operation.execute(
        Path::new(&proposal.workspace_root),
        expected_prestate_hash,
        protected_paths,
        Some(&authorization_id),
    ) {
        Ok(result) => {
            let digest = result_digest(&result)
                .map_err(|_| GovernedFilesystemError::ExecutionStateUnknown)?;
            let observation = ToolExecutionObservation {
                schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
                authorization_id: authorization_id.clone(),
                proposal_digest: expected_proposal_digest.clone(),
                request_hash: request_hash.clone(),
                outcome: WireExecutionOutcome::Succeeded,
                result_digest: Some(digest.clone()),
            };
            let record = ledger
                .observe(&observation, now)
                .map_err(|_| GovernedFilesystemError::ExecutionStateUnknown)?;
            Ok(success_response(
                expected_proposal_digest,
                authorization_id,
                request_hash,
                record,
                digest,
                result,
                "EXECUTED",
            ))
        }
        Err(error) => {
            if error == ToolError::IoAmbiguous && operation.may_mutate() {
                let prestate_hash =
                    expected_prestate_hash.ok_or(GovernedFilesystemError::ExecutionStateUnknown)?;
                if let Some(result) = operation
                    .reconcile_success(
                        Path::new(&proposal.workspace_root),
                        prestate_hash,
                        &authorization_id,
                    )
                    .map_err(|_| GovernedFilesystemError::ExecutionStateUnknown)?
                {
                    let digest = result_digest(&result)
                        .map_err(|_| GovernedFilesystemError::ExecutionStateUnknown)?;
                    let observation = ToolExecutionObservation {
                        schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
                        authorization_id: authorization_id.clone(),
                        proposal_digest: expected_proposal_digest.clone(),
                        request_hash: request_hash.clone(),
                        outcome: WireExecutionOutcome::Succeeded,
                        result_digest: Some(digest.clone()),
                    };
                    let record = ledger
                        .observe(&observation, now)
                        .map_err(|_| GovernedFilesystemError::ExecutionStateUnknown)?;
                    return Ok(success_response(
                        expected_proposal_digest,
                        authorization_id,
                        request_hash,
                        record,
                        digest,
                        result,
                        "RECONCILED",
                    ));
                }
            }
            let reason_code = error.reason_code();
            let evidence = serde_json::json!({ "reason_code": reason_code });
            let evidence_digest = crate::canonical::goose_digest(&evidence)
                .map_err(|_| GovernedFilesystemError::ExecutionStateUnknown)?;
            let observation = ToolExecutionObservation {
                schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
                authorization_id: authorization_id.clone(),
                proposal_digest: expected_proposal_digest.clone(),
                request_hash: request_hash.clone(),
                outcome: WireExecutionOutcome::ToolReportedError,
                result_digest: Some(evidence_digest),
            };
            let record = ledger
                .observe(&observation, now)
                .map_err(|_| GovernedFilesystemError::ExecutionStateUnknown)?;
            Ok(if operation.may_mutate() {
                execution_state_unknown_response(
                    expected_proposal_digest,
                    authorization_id,
                    request_hash,
                    record,
                    reason_code,
                )
            } else {
                tool_error_response(
                    expected_proposal_digest,
                    authorization_id,
                    request_hash,
                    record,
                    reason_code,
                )
            })
        }
    }
}

fn success_response(
    proposal_digest: String,
    authorization_id: String,
    request_hash: String,
    record: ObservationResult,
    result_sha256: String,
    result: FilesystemResult,
    reason_code: &'static str,
) -> FilesystemExecutionResponse {
    FilesystemExecutionResponse {
        schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
        proposal_digest,
        status: FilesystemExecutionStatus::Succeeded,
        reason_code,
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

fn tool_error_response(
    proposal_digest: String,
    authorization_id: String,
    request_hash: String,
    record: ObservationResult,
    reason_code: &'static str,
) -> FilesystemExecutionResponse {
    FilesystemExecutionResponse {
        schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
        proposal_digest,
        status: FilesystemExecutionStatus::ToolError,
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

fn execution_state_unknown_response(
    proposal_digest: String,
    authorization_id: String,
    request_hash: String,
    record: ObservationResult,
    reason_code: &'static str,
) -> FilesystemExecutionResponse {
    FilesystemExecutionResponse {
        schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
        proposal_digest,
        status: FilesystemExecutionStatus::ExecutionUnknown,
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
) -> FilesystemExecutionResponse {
    let approval_request_hash = approval_request
        .as_ref()
        .and_then(|context| context.digest().ok())
        .map(|digest| digest.to_string());
    let status = if approval_request_hash.is_some() && reason_code == "ACTION_APPROVAL_REQUIRED" {
        FilesystemExecutionStatus::ApprovalRequired
    } else {
        FilesystemExecutionStatus::Denied
    };
    FilesystemExecutionResponse {
        schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
        proposal_digest,
        status,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ValidatedRelativePath {
    path: PathBuf,
    display: String,
}

impl ValidatedRelativePath {
    fn new(value: &str, allow_root: bool) -> Result<Self, FilesystemInputError> {
        if allow_root && value == "." {
            return Ok(Self {
                path: PathBuf::new(),
                display: ".".to_owned(),
            });
        }
        if value.is_empty()
            || value.len() > MAX_RELATIVE_PATH_BYTES
            || value.starts_with('/')
            || value.contains('\\')
            || value.contains(':')
            || value.chars().any(char::is_control)
            || has_disallowed_unicode_path_character(value)
            || value.split('/').any(str::is_empty)
        {
            return Err(FilesystemInputError::InvalidPath);
        }

        let mut path = PathBuf::new();
        let mut normalized = Vec::new();
        for component in Path::new(value).components() {
            let Component::Normal(component) = component else {
                return Err(FilesystemInputError::InvalidPath);
            };
            let text = component
                .to_str()
                .ok_or(FilesystemInputError::InvalidPath)?;
            if !valid_component(text) {
                return Err(FilesystemInputError::InvalidPath);
            }
            normalized.push(text.to_owned());
            path.push(component);
        }
        if normalized.is_empty() || normalized.len() > MAX_PATH_COMPONENTS {
            return Err(FilesystemInputError::InvalidPath);
        }
        Ok(Self {
            path,
            display: normalized.join("/"),
        })
    }

    fn components(&self) -> Vec<OsString> {
        self.path
            .components()
            .filter_map(|component| match component {
                Component::Normal(value) => Some(value.to_os_string()),
                _ => None,
            })
            .collect()
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadArguments {
    path: String,
    line: Option<u32>,
    limit: Option<u32>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TreeArguments {
    path: String,
    #[serde(default = "default_tree_depth")]
    depth: u32,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteArguments {
    path: String,
    content: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EditArguments {
    path: String,
    before: String,
    after: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteArguments {
    path: String,
}

fn default_tree_depth() -> u32 {
    2
}

fn parse_arguments<T: for<'de> Deserialize<'de>>(value: &Value) -> Result<T, FilesystemInputError> {
    serde_json::from_value(value.clone()).map_err(|_| FilesystemInputError::InvalidArguments)
}

fn valid_component(component: &str) -> bool {
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.len() > MAX_PATH_COMPONENT_BYTES
        || component.ends_with([' ', '.'])
    {
        return false;
    }
    let stem = component.split('.').next().unwrap_or_default();
    let upper = stem.to_ascii_uppercase();
    !matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        && !(upper.len() == 4
            && (upper.starts_with("COM") || upper.starts_with("LPT"))
            && upper.as_bytes()[3].is_ascii_digit()
            && upper.as_bytes()[3] != b'0')
}

fn is_protected_path(relative_path: &str, protected_paths: &[String]) -> bool {
    let candidate = relative_path.replace('\\', "/").to_lowercase();
    if candidate != "."
        && protected_paths.iter().any(|protected| {
            candidate == *protected || candidate.starts_with(&format!("{protected}/"))
        })
    {
        return true;
    }
    candidate.split('/').any(|component| {
        matches!(
            component,
            ".git" | ".ssh" | ".aws" | ".kube" | ".accordlock" | ".goose"
        ) || component == ".env"
            || component.starts_with(".env.")
            || matches!(component, "id_rsa" | "id_ed25519")
            || has_protected_key_extension(component)
            || has_secret_stem(component, "credential")
            || has_secret_stem(component, "credentials")
            || has_secret_stem(component, "secret")
            || has_secret_stem(component, "secrets")
    })
}

fn has_protected_key_extension(component: &str) -> bool {
    Path::new(component)
        .extension()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("pem") || extension.eq_ignore_ascii_case("key")
        })
}

fn has_secret_stem(component: &str, stem: &str) -> bool {
    component == stem
        || component
            .strip_prefix(stem)
            .is_some_and(|suffix| suffix.starts_with(['.', '-', '_']))
}

fn open_workspace(workspace_root: &Path) -> Result<Dir, ToolError> {
    let metadata =
        std::fs::symlink_metadata(workspace_root).map_err(|_| ToolError::WorkspaceUnavailable)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(ToolError::WorkspaceChanged);
    }
    let directory = Dir::open_ambient_dir(workspace_root, ambient_authority())
        .map_err(|_| ToolError::WorkspaceUnavailable)?;
    let opened = directory
        .dir_metadata()
        .map_err(|_| ToolError::WorkspaceUnavailable)?;
    if !opened.is_dir() {
        return Err(ToolError::WorkspaceChanged);
    }
    let after =
        std::fs::symlink_metadata(workspace_root).map_err(|_| ToolError::WorkspaceChanged)?;
    if !after.is_dir() || after.file_type().is_symlink() {
        return Err(ToolError::WorkspaceChanged);
    }
    Ok(directory)
}

fn open_parent(
    workspace: &Dir,
    path: &ValidatedRelativePath,
    create_missing: bool,
) -> Result<(Dir, OsString), ToolError> {
    let mut components = path.components();
    let file_name = components.pop().ok_or(ToolError::InvalidPath)?;
    let mut current = workspace
        .try_clone()
        .map_err(|_| ToolError::WorkspaceUnavailable)?;
    for component in components {
        match current.open_dir_nofollow(&component) {
            Ok(next) => current = next,
            Err(error) if create_missing && error.kind() == io::ErrorKind::NotFound => {
                current
                    .create_dir(&component)
                    .map_err(|_| ToolError::IoAmbiguous)?;
                current = current
                    .open_dir_nofollow(&component)
                    .map_err(|_| ToolError::UnsafePath)?;
            }
            Err(_) => return Err(ToolError::UnsafePath),
        }
    }
    Ok((current, file_name))
}

fn nofollow_options(read: bool, write: bool) -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(read).write(write).follow(FollowSymlinks::No);
    options
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum PrestateKind {
    Absent,
    RegularFile,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct ObservedPrestate {
    schema_version: u16,
    kind: PrestateKind,
    content_sha256: Option<Digest32>,
    content_bytes: u64,
}

impl ObservedPrestate {
    fn absent() -> Self {
        Self {
            schema_version: 2,
            kind: PrestateKind::Absent,
            content_sha256: None,
            content_bytes: 0,
        }
    }

    fn digest(&self) -> Result<Digest32, ToolError> {
        let canonical =
            crate::canonical::canonical_json_bytes(self).map_err(|_| ToolError::IoAmbiguous)?;
        let mut hasher = Sha256::new();
        hasher.update(FILESYSTEM_PRESTATE_DOMAIN);
        hasher.update([0]);
        hasher.update(
            u64::try_from(canonical.len())
                .map_err(|_| ToolError::IoAmbiguous)?
                .to_be_bytes(),
        );
        hasher.update(canonical);
        Ok(Digest32::from_bytes(hasher.finalize().into()))
    }
}

fn open_existing_parent(
    workspace: &Dir,
    path: &ValidatedRelativePath,
) -> Result<Option<(Dir, OsString)>, ToolError> {
    let mut components = path.components();
    let file_name = components.pop().ok_or(ToolError::InvalidPath)?;
    let mut current = workspace
        .try_clone()
        .map_err(|_| ToolError::WorkspaceUnavailable)?;
    for component in components {
        match current.open_dir_nofollow(&component) {
            Ok(next) => current = next,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(ToolError::UnsafePath),
        }
    }
    Ok(Some((current, file_name)))
}

fn observe_prestate(
    workspace: &Dir,
    path: &ValidatedRelativePath,
    allow_absent: bool,
) -> Result<ObservedPrestate, ToolError> {
    let Some((parent, file_name)) = open_existing_parent(workspace, path)? else {
        return if allow_absent {
            Ok(ObservedPrestate::absent())
        } else {
            Err(ToolError::ReadFailed)
        };
    };
    match parent.symlink_metadata(&file_name) {
        Ok(metadata) if metadata.is_file() && !metadata.is_symlink() => {
            let mut file = parent
                .open_with(&file_name, &nofollow_options(true, false))
                .map_err(|_| ToolError::ReadFailed)?;
            observe_open_file(&mut file)
        }
        Ok(_) => Err(ToolError::UnsafePath),
        Err(error) if error.kind() == io::ErrorKind::NotFound && allow_absent => {
            Ok(ObservedPrestate::absent())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(ToolError::ReadFailed),
        Err(_) => Err(ToolError::IoAmbiguous),
    }
}

fn observe_open_file(file: &mut cap_std::fs::File) -> Result<ObservedPrestate, ToolError> {
    read_open_file(file).map(|(observed, _)| observed)
}

fn read_open_file(file: &mut cap_std::fs::File) -> Result<(ObservedPrestate, Vec<u8>), ToolError> {
    let metadata = file.metadata().map_err(|_| ToolError::ReadFailed)?;
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES as u64 {
        return Err(ToolError::ContentTooLarge);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| ToolError::ReadFailed)?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len()).map_err(|_| ToolError::ContentTooLarge)?,
    );
    file.read_to_end(&mut bytes)
        .map_err(|_| ToolError::ReadFailed)?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(ToolError::ContentTooLarge);
    }
    Ok((
        ObservedPrestate {
            schema_version: 2,
            kind: PrestateKind::RegularFile,
            content_sha256: Some(Digest32::sha256(&bytes)),
            content_bytes: u64::try_from(bytes.len()).map_err(|_| ToolError::ContentTooLarge)?,
        },
        bytes,
    ))
}

fn execute_read(
    workspace: &Dir,
    path: &ValidatedRelativePath,
    line: Option<u32>,
    limit: Option<u32>,
) -> Result<FilesystemResult, ToolError> {
    let (parent, file_name) = open_parent(workspace, path, false)?;
    let mut file = parent
        .open_with(&file_name, &nofollow_options(true, false))
        .map_err(|_| ToolError::ReadFailed)?;
    let metadata = file.metadata().map_err(|_| ToolError::ReadFailed)?;
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES as u64 {
        return Err(ToolError::ReadFailed);
    }
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|_| ToolError::ReadFailed)?;
    let selected = apply_line_window(&content, line, limit);
    let (content, truncated) = truncate_utf8(selected, MAX_RESULT_CONTENT_BYTES);
    let content_sha256 = sha256(content.as_bytes());
    Ok(FilesystemResult::Read {
        relative_path: path.display.clone(),
        content,
        content_sha256,
        truncated,
    })
}

fn execute_tree(
    workspace: &Dir,
    path: &ValidatedRelativePath,
    depth: u32,
    protected_paths: &[String],
) -> Result<FilesystemResult, ToolError> {
    let root = if path.path.as_os_str().is_empty() {
        workspace
            .try_clone()
            .map_err(|_| ToolError::WorkspaceUnavailable)?
    } else {
        open_directory(workspace, path)?
    };
    let mut state = TreeState::default();
    let policy_prefix = if path.display == "." {
        ""
    } else {
        path.display.as_str()
    };
    collect_tree(
        &root,
        "",
        policy_prefix,
        0,
        depth,
        protected_paths,
        &mut state,
    )?;
    let (content, content_truncated) =
        truncate_utf8(state.lines.join("\n"), MAX_RESULT_CONTENT_BYTES);
    Ok(FilesystemResult::Tree {
        relative_path: path.display.clone(),
        content,
        entries: state.entries,
        truncated: state.truncated || content_truncated,
    })
}

fn open_directory(workspace: &Dir, path: &ValidatedRelativePath) -> Result<Dir, ToolError> {
    let mut current = workspace
        .try_clone()
        .map_err(|_| ToolError::WorkspaceUnavailable)?;
    for component in path.components() {
        current = current
            .open_dir_nofollow(&component)
            .map_err(|_| ToolError::UnsafePath)?;
    }
    Ok(current)
}

#[derive(Default)]
struct TreeState {
    lines: Vec<String>,
    entries: usize,
    truncated: bool,
}

fn collect_tree(
    directory: &Dir,
    prefix: &str,
    policy_prefix: &str,
    level: u32,
    maximum_depth: u32,
    protected_paths: &[String],
    state: &mut TreeState,
) -> Result<(), ToolError> {
    if state.entries >= MAX_TREE_ENTRIES {
        state.truncated = true;
        return Ok(());
    }
    let entries = directory.entries().map_err(|_| ToolError::ReadFailed)?;
    let mut records = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| ToolError::ReadFailed)?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let file_type = entry.file_type().map_err(|_| ToolError::ReadFailed)?;
        records.push((name, file_type));
    }
    records.sort_by(|left, right| left.0.cmp(&right.0));

    for (name, file_type) in records {
        if state.entries >= MAX_TREE_ENTRIES {
            state.truncated = true;
            break;
        }
        let relative = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        let policy_relative = if policy_prefix.is_empty() {
            name.clone()
        } else {
            format!("{policy_prefix}/{name}")
        };
        if is_protected_path(&policy_relative, protected_paths) {
            state.lines.push(format!("{relative} [protected]"));
            state.entries += 1;
            continue;
        }
        if file_type.is_symlink() {
            state.lines.push(format!("{relative} [blocked-link]"));
            state.entries += 1;
            continue;
        }
        if file_type.is_dir() {
            state.lines.push(format!("{relative}/"));
            state.entries += 1;
            if level < maximum_depth {
                let child = directory
                    .open_dir_nofollow(&name)
                    .map_err(|_| ToolError::UnsafePath)?;
                collect_tree(
                    &child,
                    &relative,
                    &policy_relative,
                    level + 1,
                    maximum_depth,
                    protected_paths,
                    state,
                )?;
            }
        } else if file_type.is_file() {
            state.lines.push(relative);
            state.entries += 1;
        }
    }
    Ok(())
}

fn execute_write(
    workspace: &Dir,
    path: &ValidatedRelativePath,
    content: &str,
    expected_prestate_hash: Digest32,
) -> Result<FilesystemResult, ToolError> {
    let (parent, file_name) = open_parent(workspace, path, true)?;
    let exists = match parent.symlink_metadata(&file_name) {
        Ok(metadata) if metadata.is_file() && !metadata.is_symlink() => true,
        Ok(_) => return Err(ToolError::UnsafePath),
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(_) => return Err(ToolError::IoAmbiguous),
    };
    let mut file = if exists {
        let mut file = parent
            .open_with(&file_name, &nofollow_options(true, true))
            .map_err(|_| ToolError::IoAmbiguous)?;
        if observe_open_file(&mut file)?.digest()? != expected_prestate_hash {
            return Err(ToolError::StateStale);
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|_| ToolError::IoAmbiguous)?;
        file
    } else {
        if ObservedPrestate::absent().digest()? != expected_prestate_hash {
            return Err(ToolError::StateStale);
        }
        let mut options = nofollow_options(false, true);
        options.create_new(true);
        parent
            .open_with(&file_name, &options)
            .map_err(|_| ToolError::StateStale)?
    };
    if !file
        .metadata()
        .map_err(|_| ToolError::IoAmbiguous)?
        .is_file()
    {
        return Err(ToolError::UnsafePath);
    }
    file.write_all(content.as_bytes())
        .and_then(|()| file.set_len(content.len() as u64))
        .and_then(|()| file.sync_all())
        .map_err(|_| ToolError::IoAmbiguous)?;
    Ok(FilesystemResult::Write {
        relative_path: path.display.clone(),
        created: !exists,
        bytes_written: content.len(),
        content_sha256: sha256(content.as_bytes()),
    })
}

fn execute_edit(
    workspace: &Dir,
    path: &ValidatedRelativePath,
    before: &str,
    after: &str,
    expected_prestate_hash: Digest32,
) -> Result<FilesystemResult, ToolError> {
    let (parent, file_name) = open_parent(workspace, path, false)?;
    let mut file = parent
        .open_with(&file_name, &nofollow_options(true, true))
        .map_err(|_| ToolError::ReadFailed)?;
    let metadata = file.metadata().map_err(|_| ToolError::ReadFailed)?;
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES as u64 {
        return Err(ToolError::ReadFailed);
    }
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|_| ToolError::ReadFailed)?;
    let observed = ObservedPrestate {
        schema_version: 2,
        kind: PrestateKind::RegularFile,
        content_sha256: Some(Digest32::sha256(content.as_bytes())),
        content_bytes: u64::try_from(content.len()).map_err(|_| ToolError::ContentTooLarge)?,
    };
    if observed.digest()? != expected_prestate_hash {
        return Err(ToolError::StateStale);
    }
    let mut matches = content.match_indices(before);
    let Some((offset, _)) = matches.next() else {
        return Err(ToolError::NoUniqueMatch);
    };
    if matches.next().is_some() {
        return Err(ToolError::NoUniqueMatch);
    }
    let new_size = content
        .len()
        .saturating_sub(before.len())
        .saturating_add(after.len());
    if new_size > MAX_FILE_BYTES {
        return Err(ToolError::ContentTooLarge);
    }
    let mut replacement = String::with_capacity(new_size);
    replacement.push_str(&content[..offset]);
    replacement.push_str(after);
    replacement.push_str(&content[offset + before.len()..]);
    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.write_all(replacement.as_bytes()))
        .and_then(|()| file.set_len(replacement.len() as u64))
        .and_then(|()| file.sync_all())
        .map_err(|_| ToolError::IoAmbiguous)?;
    Ok(FilesystemResult::Edit {
        relative_path: path.display.clone(),
        bytes_written: replacement.len(),
        content_sha256: sha256(replacement.as_bytes()),
    })
}

fn execute_delete(
    workspace: &Dir,
    path: &ValidatedRelativePath,
    expected_prestate_hash: Digest32,
    recovery_id: &str,
) -> Result<FilesystemResult, ToolError> {
    uuid::Uuid::parse_str(recovery_id).map_err(|_| ToolError::RecoveryUnavailable)?;
    let (parent, file_name) = open_parent(workspace, path, false)?;
    let mut file = parent
        .open_with(&file_name, &nofollow_options(true, false))
        .map_err(|_| ToolError::ReadFailed)?;
    let observed = observe_open_file(&mut file)?;
    if observed.digest()? != expected_prestate_hash {
        return Err(ToolError::StateStale);
    }
    drop(file);

    let recovery_root = open_or_create_recovery_root(workspace)?;
    match recovery_root.create_dir(recovery_id) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            return Err(ToolError::RecoveryConflict);
        }
        Err(_) => return Err(ToolError::RecoveryUnavailable),
    }
    let recovery_directory = recovery_root
        .open_dir_nofollow(recovery_id)
        .map_err(|_| ToolError::RecoveryUnavailable)?;
    if recovery_directory
        .symlink_metadata(RECOVERY_CONTENT_NAME)
        .is_ok()
    {
        return Err(ToolError::RecoveryConflict);
    }

    if parent
        .rename(&file_name, &recovery_directory, RECOVERY_CONTENT_NAME)
        .is_err()
    {
        return reconcile_delete_result(workspace, path, expected_prestate_hash, recovery_id)?
            .ok_or(ToolError::IoAmbiguous);
    }
    reconcile_delete_result(workspace, path, expected_prestate_hash, recovery_id)?
        .ok_or(ToolError::IoAmbiguous)
}

fn open_or_create_recovery_root(workspace: &Dir) -> Result<Dir, ToolError> {
    let mut current = workspace
        .try_clone()
        .map_err(|_| ToolError::WorkspaceUnavailable)?;
    for component in RECOVERY_ROOT_COMPONENTS {
        current = match current.open_dir_nofollow(component) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match current.create_dir(component) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(_) => return Err(ToolError::RecoveryUnavailable),
                }
                current
                    .open_dir_nofollow(component)
                    .map_err(|_| ToolError::RecoveryUnavailable)?
            }
            Err(_) => return Err(ToolError::UnsafePath),
        };
    }
    Ok(current)
}

fn open_recovery_directory(workspace: &Dir, recovery_id: &str) -> Result<Option<Dir>, ToolError> {
    uuid::Uuid::parse_str(recovery_id).map_err(|_| ToolError::RecoveryUnavailable)?;
    let mut current = workspace
        .try_clone()
        .map_err(|_| ToolError::WorkspaceUnavailable)?;
    for component in RECOVERY_ROOT_COMPONENTS.into_iter().chain([recovery_id]) {
        current = match current.open_dir_nofollow(component) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(ToolError::UnsafePath),
        };
    }
    Ok(Some(current))
}

fn reconcile_delete_result(
    workspace: &Dir,
    path: &ValidatedRelativePath,
    expected_prestate_hash: Digest32,
    recovery_id: &str,
) -> Result<Option<FilesystemResult>, ToolError> {
    let source_state = observe_prestate(workspace, path, true)?;
    if source_state != ObservedPrestate::absent() {
        return Ok(None);
    }
    let Some(recovery_directory) = open_recovery_directory(workspace, recovery_id)? else {
        return Ok(None);
    };
    let metadata = match recovery_directory.symlink_metadata(RECOVERY_CONTENT_NAME) {
        Ok(metadata) if metadata.is_file() && !metadata.is_symlink() => metadata,
        Ok(_) => return Err(ToolError::UnsafePath),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(ToolError::IoAmbiguous),
    };
    if metadata.len() > MAX_FILE_BYTES as u64 {
        return Err(ToolError::ContentTooLarge);
    }
    let mut file = recovery_directory
        .open_with(RECOVERY_CONTENT_NAME, &nofollow_options(true, false))
        .map_err(|_| ToolError::IoAmbiguous)?;
    let recovered = observe_open_file(&mut file)?;
    if recovered.digest()? != expected_prestate_hash {
        return Ok(None);
    }
    let content_sha256 = recovered
        .content_sha256
        .ok_or(ToolError::IoAmbiguous)?
        .to_string();
    Ok(Some(FilesystemResult::Delete {
        relative_path: path.display.clone(),
        recovery_id: recovery_id.to_owned(),
        recovery_path: format!(
            "{}/{recovery_id}/{RECOVERY_CONTENT_NAME}",
            RECOVERY_ROOT_COMPONENTS.join("/")
        ),
        original_bytes: recovered.content_bytes,
        content_sha256,
    }))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DeleteRecoveryInspection {
    pub relative_path: String,
    pub content_sha256: String,
    pub original_bytes: u64,
    pub restored: bool,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(crate) enum FilesystemRecoveryError {
    #[error("recovery evidence is invalid")]
    InvalidEvidence,
    #[error("recovery state changed")]
    StateStale,
    #[error("recovery path is unsafe")]
    UnsafePath,
    #[error("recovery content failed verification")]
    IntegrityMismatch,
    #[error("recovery storage is unavailable")]
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeleteRecoveryState {
    Available,
    Copied,
    Restored,
}

fn recovery_content_prestate(
    recovery_directory: &Dir,
) -> Result<Option<ObservedPrestate>, FilesystemRecoveryError> {
    match recovery_directory.symlink_metadata(RECOVERY_CONTENT_NAME) {
        Ok(metadata) if metadata.is_file() && !metadata.is_symlink() => {}
        Ok(_) => return Err(FilesystemRecoveryError::UnsafePath),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(FilesystemRecoveryError::Unavailable),
    }
    let mut file = recovery_directory
        .open_with(RECOVERY_CONTENT_NAME, &nofollow_options(true, false))
        .map_err(|_| FilesystemRecoveryError::Unavailable)?;
    let observed = observe_open_file(&mut file).map_err(|error| match error {
        ToolError::UnsafePath => FilesystemRecoveryError::UnsafePath,
        ToolError::ContentTooLarge => FilesystemRecoveryError::IntegrityMismatch,
        _ => FilesystemRecoveryError::Unavailable,
    })?;
    Ok(Some(observed))
}

fn target_prestate(
    workspace: &Dir,
    path: &ValidatedRelativePath,
) -> Result<Option<ObservedPrestate>, FilesystemRecoveryError> {
    let Some((parent, file_name)) =
        open_existing_parent(workspace, path).map_err(|_| FilesystemRecoveryError::UnsafePath)?
    else {
        return Ok(None);
    };
    match parent.symlink_metadata(&file_name) {
        Ok(metadata) if metadata.is_file() && !metadata.is_symlink() => {
            let mut file = parent
                .open_with(&file_name, &nofollow_options(true, false))
                .map_err(|_| FilesystemRecoveryError::Unavailable)?;
            let observed = observe_open_file(&mut file).map_err(|error| match error {
                ToolError::UnsafePath => FilesystemRecoveryError::UnsafePath,
                ToolError::ContentTooLarge => FilesystemRecoveryError::StateStale,
                _ => FilesystemRecoveryError::Unavailable,
            })?;
            Ok(Some(observed))
        }
        Ok(_) => Err(FilesystemRecoveryError::UnsafePath),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(FilesystemRecoveryError::Unavailable),
    }
}

fn delete_recovery_state(
    evidence: &crate::ledger::DeletedFileRecoveryEvidence,
) -> Result<(DeleteRecoveryInspection, DeleteRecoveryState), FilesystemRecoveryError> {
    evidence
        .proposal
        .validate()
        .map_err(|_| FilesystemRecoveryError::InvalidEvidence)?;
    let operation = PreparedFilesystemOperation::from_proposal(&evidence.proposal)
        .map_err(|_| FilesystemRecoveryError::InvalidEvidence)?;
    let PreparedFilesystemOperation::Delete { path } = operation else {
        return Err(FilesystemRecoveryError::InvalidEvidence);
    };
    if evidence.authorization_id.is_nil() {
        return Err(FilesystemRecoveryError::InvalidEvidence);
    }
    let workspace = open_workspace(Path::new(&evidence.proposal.workspace_root)).map_err(
        |error| match error {
            ToolError::UnsafePath | ToolError::WorkspaceChanged => {
                FilesystemRecoveryError::UnsafePath
            }
            _ => FilesystemRecoveryError::Unavailable,
        },
    )?;
    let recovery_directory =
        open_recovery_directory(&workspace, evidence.authorization_id.to_string().as_str())
            .map_err(|error| match error {
                ToolError::UnsafePath => FilesystemRecoveryError::UnsafePath,
                _ => FilesystemRecoveryError::Unavailable,
            })?;
    let recovery = recovery_directory
        .as_ref()
        .map(recovery_content_prestate)
        .transpose()?
        .flatten();
    let target = target_prestate(&workspace, &path)?;

    let (original, state) = match (recovery, target) {
        (Some(recovered), None) => (recovered, DeleteRecoveryState::Available),
        (Some(recovered), Some(target)) if target == recovered => {
            (recovered, DeleteRecoveryState::Copied)
        }
        (None, Some(target)) => (target, DeleteRecoveryState::Restored),
        (None, None) => return Err(FilesystemRecoveryError::Unavailable),
        _ => return Err(FilesystemRecoveryError::StateStale),
    };
    if original.kind != PrestateKind::RegularFile
        || original
            .digest()
            .map_err(|_| FilesystemRecoveryError::InvalidEvidence)?
            != evidence.prestate_hash
    {
        return Err(FilesystemRecoveryError::IntegrityMismatch);
    }
    let content_sha256 = original
        .content_sha256
        .ok_or(FilesystemRecoveryError::IntegrityMismatch)?
        .to_string();
    let result = FilesystemResult::Delete {
        relative_path: path.display.clone(),
        recovery_id: evidence.authorization_id.to_string(),
        recovery_path: format!(
            "{}/{}/{RECOVERY_CONTENT_NAME}",
            RECOVERY_ROOT_COMPONENTS.join("/"),
            evidence.authorization_id
        ),
        original_bytes: original.content_bytes,
        content_sha256: content_sha256.clone(),
    };
    if result_digest(&result).map_err(|_| FilesystemRecoveryError::InvalidEvidence)?
        != evidence.result_digest
    {
        return Err(FilesystemRecoveryError::IntegrityMismatch);
    }
    Ok((
        DeleteRecoveryInspection {
            relative_path: path.display,
            content_sha256,
            original_bytes: original.content_bytes,
            restored: state != DeleteRecoveryState::Available,
        },
        state,
    ))
}

pub(crate) fn inspect_deleted_file_recovery(
    evidence: &crate::ledger::DeletedFileRecoveryEvidence,
) -> Result<DeleteRecoveryInspection, FilesystemRecoveryError> {
    delete_recovery_state(evidence).map(|(inspection, _)| inspection)
}

pub(crate) fn restore_deleted_file(
    evidence: &crate::ledger::DeletedFileRecoveryEvidence,
) -> Result<DeleteRecoveryInspection, FilesystemRecoveryError> {
    let (inspection, state) = delete_recovery_state(evidence)?;
    let PreparedFilesystemOperation::Delete { path } =
        PreparedFilesystemOperation::from_proposal(&evidence.proposal)
            .map_err(|_| FilesystemRecoveryError::InvalidEvidence)?
    else {
        return Err(FilesystemRecoveryError::InvalidEvidence);
    };
    let workspace = open_workspace(Path::new(&evidence.proposal.workspace_root))
        .map_err(|_| FilesystemRecoveryError::Unavailable)?;
    let (target_parent, target_name) =
        open_parent(&workspace, &path, false).map_err(|_| FilesystemRecoveryError::UnsafePath)?;

    if matches!(
        state,
        DeleteRecoveryState::Copied | DeleteRecoveryState::Restored
    ) {
        sync_verified_target(&target_parent, &target_name, &inspection)?;
        let (restored, final_state) = delete_recovery_state(evidence)?;
        if final_state != state || !restored.restored {
            return Err(FilesystemRecoveryError::StateStale);
        }
        return Ok(restored);
    }

    let recovery_directory =
        open_recovery_directory(&workspace, evidence.authorization_id.to_string().as_str())
            .map_err(|_| FilesystemRecoveryError::Unavailable)?
            .ok_or(FilesystemRecoveryError::Unavailable)?;
    let mut source = recovery_directory
        .open_with(RECOVERY_CONTENT_NAME, &nofollow_options(true, false))
        .map_err(|_| FilesystemRecoveryError::Unavailable)?;
    let (source_state, source_bytes) =
        read_open_file(&mut source).map_err(|error| match error {
            ToolError::UnsafePath => FilesystemRecoveryError::UnsafePath,
            ToolError::ContentTooLarge => FilesystemRecoveryError::IntegrityMismatch,
            _ => FilesystemRecoveryError::Unavailable,
        })?;
    if source_state
        .digest()
        .map_err(|_| FilesystemRecoveryError::InvalidEvidence)?
        != evidence.prestate_hash
    {
        return Err(FilesystemRecoveryError::IntegrityMismatch);
    }

    let mut options = nofollow_options(true, true);
    options.create_new(true);
    let mut target = target_parent
        .open_with(&target_name, &options)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                FilesystemRecoveryError::StateStale
            } else {
                FilesystemRecoveryError::Unavailable
            }
        })?;
    target
        .write_all(&source_bytes)
        .and_then(|()| target.set_len(source_bytes.len() as u64))
        .and_then(|()| target.sync_all())
        .map_err(|_| FilesystemRecoveryError::Unavailable)?;
    let target_state =
        observe_open_file(&mut target).map_err(|_| FilesystemRecoveryError::IntegrityMismatch)?;
    if target_state != source_state {
        return Err(FilesystemRecoveryError::IntegrityMismatch);
    }
    sync_directory(&target_parent)?;

    let (restored, final_state) = delete_recovery_state(evidence)?;
    if final_state != DeleteRecoveryState::Copied || !restored.restored {
        return Err(FilesystemRecoveryError::StateStale);
    }
    Ok(restored)
}

fn sync_verified_target(
    parent: &Dir,
    name: &OsString,
    expected: &DeleteRecoveryInspection,
) -> Result<(), FilesystemRecoveryError> {
    let mut target = parent
        .open_with(name, &nofollow_options(true, true))
        .map_err(|_| FilesystemRecoveryError::Unavailable)?;
    let observed =
        observe_open_file(&mut target).map_err(|_| FilesystemRecoveryError::IntegrityMismatch)?;
    if observed.kind != PrestateKind::RegularFile
        || observed.content_bytes != expected.original_bytes
        || observed.content_sha256.map(|value| value.to_string())
            != Some(expected.content_sha256.clone())
    {
        return Err(FilesystemRecoveryError::IntegrityMismatch);
    }
    target
        .sync_all()
        .map_err(|_| FilesystemRecoveryError::Unavailable)?;
    sync_directory(parent)
}

fn sync_directory(directory: &Dir) -> Result<(), FilesystemRecoveryError> {
    // Directory flushing is not portable across Windows, network shares, and
    // several Unix filesystems. Attempt it when supported; the verified
    // recovery blob is retained and every durable replay rechecks the target
    // when the platform rejects directory flushing.
    match directory
        .try_clone()
        .and_then(|clone| clone.into_std_file().sync_all())
    {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::PermissionDenied
                    | io::ErrorKind::Unsupported
                    | io::ErrorKind::InvalidInput
            ) =>
        {
            Ok(())
        }
        Err(_) => Err(FilesystemRecoveryError::Unavailable),
    }
}

fn reconcile_edit_result(
    workspace: &Dir,
    path: &ValidatedRelativePath,
    before: &str,
    after: &str,
    expected_prestate_hash: Digest32,
) -> Result<Option<FilesystemResult>, ToolError> {
    let (parent, file_name) = open_parent(workspace, path, false)?;
    let mut file = parent
        .open_with(&file_name, &nofollow_options(true, false))
        .map_err(|_| ToolError::ReadFailed)?;
    let metadata = file.metadata().map_err(|_| ToolError::ReadFailed)?;
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES as u64 {
        return Err(ToolError::ReadFailed);
    }
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|_| ToolError::ReadFailed)?;

    let mut matching_prestate_count = 0usize;
    for (offset, _) in content.match_indices(after) {
        let candidate_size = content
            .len()
            .saturating_sub(after.len())
            .saturating_add(before.len());
        if candidate_size > MAX_FILE_BYTES {
            continue;
        }
        let mut candidate = String::with_capacity(candidate_size);
        candidate.push_str(&content[..offset]);
        candidate.push_str(before);
        candidate.push_str(&content[offset + after.len()..]);
        let mut original_matches = candidate.match_indices(before);
        let exact_forward_match = matches!(original_matches.next(), Some((found, _)) if found == offset)
            && original_matches.next().is_none();
        if !exact_forward_match {
            continue;
        }
        let candidate_prestate = ObservedPrestate {
            schema_version: 2,
            kind: PrestateKind::RegularFile,
            content_sha256: Some(Digest32::sha256(candidate.as_bytes())),
            content_bytes: candidate.len() as u64,
        };
        if candidate_prestate.digest()? == expected_prestate_hash {
            matching_prestate_count += 1;
        }
    }
    if matching_prestate_count != 1 {
        return Ok(None);
    }
    Ok(Some(FilesystemResult::Edit {
        relative_path: path.display.clone(),
        bytes_written: content.len(),
        content_sha256: Digest32::sha256(content.as_bytes()).to_string(),
    }))
}

fn apply_line_window(content: &str, line: Option<u32>, limit: Option<u32>) -> String {
    if line.is_none() && limit.is_none() {
        return content.to_owned();
    }
    let lines = content.split_inclusive('\n').collect::<Vec<_>>();
    let start = line
        .map(|value| (value as usize).saturating_sub(1))
        .unwrap_or_default()
        .min(lines.len());
    let end = limit
        .map_or(lines.len(), |value| start.saturating_add(value as usize))
        .min(lines.len());
    lines[start..end].concat()
}

fn truncate_utf8(mut value: String, maximum: usize) -> (String, bool) {
    if value.len() <= maximum {
        return (value, false);
    }
    let mut boundary = maximum;
    while !value.is_char_boundary(boundary) {
        boundary = boundary.saturating_sub(1);
    }
    value.truncate(boundary);
    (value, true)
}

pub(crate) fn result_digest(result: &FilesystemResult) -> Result<String, FilesystemInputError> {
    crate::canonical::goose_digest(result).map_err(|_| FilesystemInputError::Canonical)
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[derive(Debug, Error)]
pub(crate) enum FilesystemInputError {
    #[error("filesystem arguments are malformed")]
    InvalidArguments,
    #[error("filesystem path is not a canonical relative path")]
    InvalidPath,
    #[error("filesystem content exceeds the bounded profile")]
    ContentTooLarge,
    #[error("filesystem range exceeds the bounded profile")]
    InvalidRange,
    #[error("tool is not brokered by the filesystem profile")]
    UnsupportedTool,
    #[error("filesystem result cannot be canonicalized")]
    Canonical,
}

#[derive(Debug, Error)]
pub(crate) enum GovernedFilesystemError {
    #[error("filesystem execution request is invalid")]
    Input,
    #[error("filesystem ledger is unavailable")]
    Ledger(#[from] LedgerError),
    #[error("filesystem execution state is unknown")]
    ExecutionStateUnknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(crate) enum ToolError {
    #[error("WORKSPACE_UNAVAILABLE")]
    WorkspaceUnavailable,
    #[error("WORKSPACE_CHANGED")]
    WorkspaceChanged,
    #[error("INVALID_PATH")]
    InvalidPath,
    #[error("UNSAFE_PATH")]
    UnsafePath,
    #[error("READ_FAILED")]
    ReadFailed,
    #[error("NO_UNIQUE_MATCH")]
    NoUniqueMatch,
    #[error("CONTENT_TOO_LARGE")]
    ContentTooLarge,
    #[error("IO_AMBIGUOUS")]
    IoAmbiguous,
    #[error("STATE_STALE")]
    StateStale,
    #[error("RECOVERY_UNAVAILABLE")]
    RecoveryUnavailable,
    #[error("RECOVERY_CONFLICT")]
    RecoveryConflict,
}

impl ToolError {
    pub(crate) const fn reason_code(self) -> &'static str {
        match self {
            Self::WorkspaceUnavailable => "WORKSPACE_UNAVAILABLE",
            Self::WorkspaceChanged => "WORKSPACE_CHANGED",
            Self::InvalidPath => "INVALID_PATH",
            Self::UnsafePath => "UNSAFE_PATH",
            Self::ReadFailed => "READ_FAILED",
            Self::NoUniqueMatch => "NO_UNIQUE_MATCH",
            Self::ContentTooLarge => "CONTENT_TOO_LARGE",
            Self::IoAmbiguous => "IO_AMBIGUOUS",
            Self::StateStale => "STATE_STALE",
            Self::RecoveryUnavailable => "RECOVERY_UNAVAILABLE",
            Self::RecoveryConflict => "RECOVERY_CONFLICT",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ActionApproval, ApprovalDecision, Capability, TaskPolicy,
        model::{ApprovedSession, TOOL_EXECUTION_SCHEMA_VERSION},
    };

    const TEST_NOW: i64 = 1_800_000_000;

    fn governed_fixture()
    -> Result<(tempfile::TempDir, std::path::PathBuf, Ledger), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let workspace = root.path().join("workspace");
        std::fs::create_dir(&workspace)?;
        let workspace = std::fs::canonicalize(workspace)?;
        let ledger = Ledger::open(&root.path().join("runtime.sqlite3"))?;
        let session = ApprovedSession::new_with_task_objective(
            uuid::Uuid::new_v4(),
            "filesystem-session",
            "filesystem-run",
            &workspace,
            1,
            "filesystem test objective",
            TaskPolicy::new(
                Digest32::sha256(b"filesystem test objective"),
                [],
                [".accordlock".to_owned()],
            )?,
            [
                Capability::new("developer", "delete_file"),
                Capability::new("developer", "edit"),
                Capability::new("developer", "write"),
            ],
            TEST_NOW - 10,
            TEST_NOW + 100_000,
        )?;
        ledger.approve_session(&session)?;
        Ok((root, workspace, ledger))
    }

    fn proposal(
        workspace: &Path,
        tool_call_id: &str,
        tool_name: &str,
        arguments: Value,
    ) -> Result<ToolCallProposal, Box<dyn std::error::Error>> {
        let arguments_sha256 = crate::canonical::goose_digest(&arguments)?;
        Ok(ToolCallProposal {
            schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
            session_id: "filesystem-session".to_owned(),
            run_id: "filesystem-run".to_owned(),
            tool_call_id: tool_call_id.to_owned(),
            workspace_root: workspace.to_string_lossy().into_owned(),
            extension_id: "developer".to_owned(),
            tool_name: tool_name.to_owned(),
            arguments,
            arguments_sha256: arguments_sha256.clone(),
            agent_plan_checkpoint: crate::model::test_agent_plan_checkpoint(
                "filesystem-session",
                "filesystem-run",
                tool_call_id,
                &format!("developer__{tool_name}"),
                &arguments_sha256,
                TEST_NOW - 1,
            ),
        })
    }

    fn request_approval(
        ledger: &Ledger,
        proposal: ToolCallProposal,
    ) -> Result<FilesystemExecutionRequest, Box<dyn std::error::Error>> {
        let request = FilesystemExecutionRequest {
            schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
            proposal,
        };
        let response = execute_governed(ledger, &request, TEST_NOW, 30)?;
        assert_eq!(response.status, FilesystemExecutionStatus::ApprovalRequired);
        let context = response
            .approval_request
            .ok_or("missing approval request")?;
        let approval = ActionApproval::for_context(
            &context,
            uuid::Uuid::new_v4(),
            ApprovalDecision::Approved,
            Digest32::sha256(b"approved exact filesystem operation"),
            TEST_NOW - 1,
            TEST_NOW + 60,
        )?;
        ledger.register_action_approval(&approval)?;
        Ok(request)
    }

    #[test]
    fn relative_path_profile_rejects_cross_platform_escape_forms() {
        for invalid in [
            "",
            ".",
            "..",
            "../secret",
            "a/../secret",
            "/secret",
            "a\\secret",
            "C:/secret",
            "a//b",
            "NUL",
            "COM1.txt",
            "trailing.",
            "trailing ",
        ] {
            assert!(
                ValidatedRelativePath::new(invalid, false).is_err(),
                "accepted {invalid:?}"
            );
        }
        let valid = ValidatedRelativePath::new("src/lib.rs", false);
        assert!(valid.is_ok());
    }

    #[test]
    fn v3_filesystem_envelope_accepts_only_the_proposal_key()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_root, workspace, _ledger) = governed_fixture()?;
        let valid_proposal = proposal(
            &workspace,
            "wire-contract",
            "write",
            serde_json::json!({"path": "notes.txt", "content": "hello"}),
        )?;
        let valid = serde_json::json!({
            "schema_version": TOOL_EXECUTION_SCHEMA_VERSION,
            "proposal": valid_proposal,
        });
        assert!(serde_json::from_value::<FilesystemExecutionRequest>(valid).is_ok());
        let stale = serde_json::json!({
            "schema_version": TOOL_EXECUTION_SCHEMA_VERSION,
            "execution_request": proposal(
                &workspace,
                "wire-contract-stale",
                "write",
                serde_json::json!({"path": "notes.txt", "content": "hello"}),
            )?,
        });
        assert!(serde_json::from_value::<FilesystemExecutionRequest>(stale).is_err());
        Ok(())
    }

    #[test]
    fn delete_file_moves_one_exact_regular_file_to_recovery_storage_and_replays_idempotently()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_root, workspace, ledger) = governed_fixture()?;
        std::fs::write(workspace.join("notes.txt"), "recover me")?;
        let request = request_approval(
            &ledger,
            proposal(
                &workspace,
                "delete-once",
                "delete_file",
                serde_json::json!({"path": "notes.txt"}),
            )?,
        )?;

        let executed = execute_governed(&ledger, &request, TEST_NOW, 30)?;
        assert_eq!(
            executed.status,
            FilesystemExecutionStatus::Succeeded,
            "{executed:?}"
        );
        assert_eq!(executed.reason_code, "EXECUTED");
        let delete_result = executed.result.clone().ok_or("missing delete result")?;
        let FilesystemResult::Delete {
            recovery_id,
            recovery_path,
            original_bytes,
            content_sha256,
            ..
        } = &delete_result
        else {
            return Err("unexpected delete result".into());
        };
        assert!(!workspace.join("notes.txt").exists());
        assert_eq!(*original_bytes, 10);
        assert_eq!(*content_sha256, Digest32::sha256(b"recover me").to_string());
        assert_eq!(
            std::fs::read_to_string(workspace.join(recovery_path))?,
            "recover me"
        );
        assert_eq!(
            executed.authorization_id.as_deref(),
            Some(recovery_id.as_str())
        );

        let replay = execute_governed(&ledger, &request, TEST_NOW + 1, 30)?;
        assert_eq!(replay.status, FilesystemExecutionStatus::Succeeded);
        assert_eq!(replay.reason_code, "RECONCILED");
        assert_eq!(replay.authorization_id, executed.authorization_id);
        assert_eq!(replay.record_id, executed.record_id);
        assert_eq!(replay.record_hash, executed.record_hash);
        assert_eq!(replay.result, executed.result);
        Ok(())
    }

    #[test]
    fn delete_file_rejects_directories_and_recursive_argument_substitution()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_root, workspace, ledger) = governed_fixture()?;
        std::fs::create_dir(workspace.join("directory"))?;
        let directory_request = FilesystemExecutionRequest {
            schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
            proposal: proposal(
                &workspace,
                "delete-directory",
                "delete_file",
                serde_json::json!({"path": "directory"}),
            )?,
        };
        assert!(execute_governed(&ledger, &directory_request, TEST_NOW, 30).is_err());
        assert!(workspace.join("directory").is_dir());

        let recursive = proposal(
            &workspace,
            "delete-recursive",
            "delete_file",
            serde_json::json!({"path": "directory", "recursive": true}),
        )?;
        assert!(PreparedFilesystemOperation::from_proposal(&recursive).is_err());
        assert!(workspace.join("directory").is_dir());
        Ok(())
    }

    fn execute_then_drop_record(
        ledger: &Ledger,
        request: &FilesystemExecutionRequest,
    ) -> Result<FilesystemResult, Box<dyn std::error::Error>> {
        let operation = PreparedFilesystemOperation::from_proposal(&request.proposal)?;
        let approval_input = operation
            .mutation_approval_input(Path::new(&request.proposal.workspace_root))?
            .ok_or("mutation approval input missing")?;
        let approval_request = ledger
            .action_approval_request(&request.proposal, approval_input.0, approval_input.1)?
            .ok_or("action approval request missing")?;
        let AuthorizationResult::Allowed(grant) = ledger.authorize_and_consume(
            &request.proposal,
            Some(&approval_request),
            None,
            TEST_NOW,
            30,
        )?
        else {
            return Err("authorized mutation was denied".into());
        };
        let protected_paths = ledger.task_policy_protected_paths(&request.proposal)?;
        Ok(operation.execute(
            Path::new(&request.proposal.workspace_root),
            Some(approval_input.0),
            &protected_paths,
            Some(&grant.authorization_id.to_string()),
        )?)
    }

    #[test]
    fn crash_after_mutation_is_reconciled_without_reexecution_for_write_edit_and_delete()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_root, workspace, ledger) = governed_fixture()?;

        let write = request_approval(
            &ledger,
            proposal(
                &workspace,
                "crash-write",
                "write",
                serde_json::json!({"path": "value.txt", "content": "first"}),
            )?,
        )?;
        assert!(matches!(
            execute_then_drop_record(&ledger, &write)?,
            FilesystemResult::Write { .. }
        ));
        let write_reconciled = execute_governed(&ledger, &write, TEST_NOW, 30)?;
        assert_eq!(
            write_reconciled.status,
            FilesystemExecutionStatus::Succeeded
        );
        assert_eq!(write_reconciled.reason_code, "RECONCILED");
        assert_eq!(
            std::fs::read_to_string(workspace.join("value.txt"))?,
            "first"
        );

        let edit = request_approval(
            &ledger,
            proposal(
                &workspace,
                "crash-edit",
                "edit",
                serde_json::json!({"path": "value.txt", "before": "first", "after": "second"}),
            )?,
        )?;
        assert!(matches!(
            execute_then_drop_record(&ledger, &edit)?,
            FilesystemResult::Edit { .. }
        ));
        let edit_reconciled = execute_governed(&ledger, &edit, TEST_NOW, 30)?;
        assert_eq!(edit_reconciled.status, FilesystemExecutionStatus::Succeeded);
        assert_eq!(edit_reconciled.reason_code, "RECONCILED");
        assert_eq!(
            std::fs::read_to_string(workspace.join("value.txt"))?,
            "second"
        );

        let delete = request_approval(
            &ledger,
            proposal(
                &workspace,
                "crash-delete",
                "delete_file",
                serde_json::json!({"path": "value.txt"}),
            )?,
        )?;
        let deleted = execute_then_drop_record(&ledger, &delete)?;
        assert!(matches!(deleted, FilesystemResult::Delete { .. }));
        let delete_reconciled = execute_governed(&ledger, &delete, TEST_NOW, 30)?;
        assert_eq!(
            delete_reconciled.status,
            FilesystemExecutionStatus::Succeeded
        );
        assert_eq!(delete_reconciled.reason_code, "RECONCILED");
        assert!(!workspace.join("value.txt").exists());

        let repeated = execute_governed(&ledger, &delete, TEST_NOW, 30)?;
        assert_eq!(repeated.status, FilesystemExecutionStatus::Succeeded);
        assert_eq!(
            repeated.authorization_id,
            delete_reconciled.authorization_id
        );
        assert_eq!(repeated.record_hash, delete_reconciled.record_hash);
        assert_eq!(repeated.result, delete_reconciled.result);
        Ok(())
    }

    #[test]
    fn five_hundred_normal_mutations_finish_with_determined_results()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_root, workspace, ledger) = governed_fixture()?;
        for index in 0..500usize {
            let file_index = index / 3;
            let path = format!("batch/item-{file_index}.txt");
            let (tool, arguments) = match index % 3 {
                0 => (
                    "write",
                    serde_json::json!({"path": path, "content": "before"}),
                ),
                1 => (
                    "edit",
                    serde_json::json!({"path": path, "before": "before", "after": "after"}),
                ),
                _ => ("delete_file", serde_json::json!({"path": path})),
            };
            let request = request_approval(
                &ledger,
                proposal(&workspace, &format!("batch-{index}"), tool, arguments)?,
            )?;
            let response = execute_governed(&ledger, &request, TEST_NOW, 30)?;
            assert_eq!(
                response.status,
                FilesystemExecutionStatus::Succeeded,
                "mutation {index} did not finish deterministically: {response:?}"
            );
            assert_eq!(response.reason_code, "EXECUTED");
        }
        Ok(())
    }

    #[test]
    fn relative_path_profile_rejects_unicode_format_and_separator_characters() {
        for invalid in [
            "src/soft\u{ad}hyphen.txt",
            "src/rtl\u{202e}override.txt",
            "src/zero\u{200d}width-joiner.txt",
            "src/isolate\u{2066}name.txt",
            "src/line\u{2028}separator.txt",
            "src/paragraph\u{2029}separator.txt",
            "src/tag\u{e0061}.txt",
        ] {
            assert!(
                ValidatedRelativePath::new(invalid, false).is_err(),
                "accepted Unicode-confusable path {invalid:?}"
            );
        }

        assert!(ValidatedRelativePath::new("src/合法-name.txt", false).is_ok());
    }

    #[test]
    fn broker_reads_writes_edits_and_lists_only_relative_files()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let workspace = open_workspace(temporary.path())?;
        let path = ValidatedRelativePath::new("src/lib.rs", false)?;
        let written = execute_write(
            &workspace,
            &path,
            "one\ntwo\n",
            ObservedPrestate::absent().digest()?,
        )?;
        assert!(matches!(
            written,
            FilesystemResult::Write { created: true, .. }
        ));

        let read = execute_read(&workspace, &path, Some(2), Some(1))?;
        assert!(matches!(read, FilesystemResult::Read { ref content, .. } if content == "two\n"));

        let edit_prestate = observe_prestate(&workspace, &path, false)?.digest()?;
        let edited = execute_edit(&workspace, &path, "two", "three", edit_prestate)?;
        assert!(matches!(edited, FilesystemResult::Edit { .. }));

        let root = ValidatedRelativePath::new(".", true)?;
        let tree = execute_tree(&workspace, &root, 2, &[])?;
        assert!(
            matches!(tree, FilesystemResult::Tree { ref content, entries: 2, .. } if content.contains("src/lib.rs"))
        );
        Ok(())
    }

    #[test]
    fn edit_requires_one_exact_match_without_touching_the_file()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        std::fs::write(temporary.path().join("value.txt"), "same same")?;
        let workspace = open_workspace(temporary.path())?;
        let path = ValidatedRelativePath::new("value.txt", false)?;
        let prestate = observe_prestate(&workspace, &path, false)?.digest()?;
        assert_eq!(
            execute_edit(&workspace, &path, "same", "changed", prestate),
            Err(ToolError::NoUniqueMatch)
        );
        assert_eq!(
            std::fs::read_to_string(temporary.path().join("value.txt"))?,
            "same same"
        );
        Ok(())
    }

    #[test]
    fn native_secret_profile_is_case_insensitive_and_matches_nested_paths() {
        for protected in [
            ".env",
            "nested/.ENV.production",
            "nested/.Git/config",
            "keys/ID_ED25519",
            "keys/service.PEM",
            "config/Credentials.json",
            "deep/Secrets-prod.yaml",
        ] {
            assert!(is_protected_path(protected, &[]), "missed {protected}");
        }
        assert!(!is_protected_path("src/secretary.rs", &[]));
        assert!(!is_protected_path("docs/public.pem.txt", &[]));
    }

    #[test]
    fn tree_marks_protected_entries_without_descending() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        std::fs::create_dir(temporary.path().join(".git"))?;
        std::fs::write(temporary.path().join(".git/config"), "secret")?;
        std::fs::create_dir(temporary.path().join("src"))?;
        std::fs::write(temporary.path().join("src/lib.rs"), "safe")?;
        let workspace = open_workspace(temporary.path())?;
        let root = ValidatedRelativePath::new(".", true)?;
        let result = execute_tree(&workspace, &root, 4, &[".git".to_owned()])?;
        assert!(matches!(
            result,
            FilesystemResult::Tree { content, .. }
                if content.contains(".git [protected]")
                    && !content.contains(".git/config")
                    && content.contains("src/lib.rs")
        ));
        Ok(())
    }

    #[test]
    fn changed_prestate_is_rejected_before_mutation() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let workspace = open_workspace(temporary.path())?;
        let path = ValidatedRelativePath::new("value.txt", false)?;
        let absent = ObservedPrestate::absent().digest()?;
        std::fs::write(temporary.path().join("value.txt"), "raced")?;
        assert_eq!(
            execute_write(&workspace, &path, "replacement", absent),
            Err(ToolError::StateStale)
        );
        assert_eq!(
            std::fs::read_to_string(temporary.path().join("value.txt"))?,
            "raced"
        );
        Ok(())
    }

    #[test]
    fn mutation_failures_are_never_reported_as_ordinary_retryable_tool_errors()
    -> Result<(), Box<dyn std::error::Error>> {
        let operation = PreparedFilesystemOperation::Write {
            path: ValidatedRelativePath::new("value.txt", false)?,
            content: "replacement".to_owned(),
        };
        assert!(operation.may_mutate());
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
            ToolError::IoAmbiguous.reason_code(),
        );

        assert_eq!(response.status, FilesystemExecutionStatus::ExecutionUnknown);
        assert_eq!(response.reason_code, "IO_AMBIGUOUS");
        assert!(response.result.is_none());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn broker_rejects_symlink_escape() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        std::fs::write(outside.path().join("secret.txt"), "secret")?;
        symlink(outside.path(), temporary.path().join("escape"))?;
        let workspace = open_workspace(temporary.path())?;
        let path = ValidatedRelativePath::new("escape/secret.txt", false)?;
        assert!(execute_read(&workspace, &path, None, None).is_err());
        Ok(())
    }
}
