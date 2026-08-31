use std::{
    io::{self, Read, Write},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    ActionApproval, ApprovedSession, Ledger, LedgerError, Runtime, SessionAuditPage,
    SessionAuditQuery, SessionRevocation,
    canonical::goose_digest,
    ledger::{ActionApprovalRegistration, ApprovalRegistration, RevocationRegistration},
    model::DESKTOP_PROTOCOL_SCHEMA_VERSION,
    recovery::{
        FileRestoreChallenge, FileRestoreCommitRequest, FileRestorePrepareOutcome,
        FileRestorePrepareRequest, FileRestoreRecord,
    },
};

/// Magic prefix for every binary control-channel frame.
pub const CONTROL_FRAME_MAGIC: [u8; 4] = *b"ALC1";
/// Schema version of request and response JSON inside control frames.
pub const CONTROL_CHANNEL_SCHEMA_VERSION: u16 = DESKTOP_PROTOCOL_SCHEMA_VERSION;
/// Maximum JSON payload accepted from the trusted Desktop parent.
pub const MAX_CONTROL_FRAME_BYTES: usize = 256 * 1_024;
const CONTROL_HEADER_BYTES: usize = 8;
const APPROVE_SESSION_METHOD: &str = "APPROVE_SESSION";
const REVOKE_SESSION_METHOD: &str = "REVOKE_SESSION";
const REGISTER_ACTION_APPROVAL_METHOD: &str = "REGISTER_ACTION_APPROVAL";
const PREPARE_FILE_RESTORE_METHOD: &str = "PREPARE_FILE_RESTORE";
const COMMIT_FILE_RESTORE_METHOD: &str = "COMMIT_FILE_RESTORE";
const GET_SESSION_AUDIT_METHOD: &str = "GET_SESSION_AUDIT";

/// Normal termination of the inherited control channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlChannelExit {
    /// Desktop closed its write end. The runtime must stop with its parent.
    ParentClosed,
}

/// Terminal framing or I/O failure. The channel is never resynchronized after
/// a corrupt header, oversized declaration, or truncated frame.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ControlChannelError {
    #[error("control channel input failed")]
    Input,
    #[error("control channel output failed")]
    Output,
    #[error("control channel frame header is invalid")]
    InvalidHeader,
    #[error("control channel frame exceeds the bounded profile")]
    FrameTooLarge,
    #[error("control channel frame is truncated")]
    TruncatedFrame,
    #[error("control channel response encoding failed")]
    Encoding,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlRequest {
    schema_version: u16,
    request_id: String,
    method: String,
    approved_session: Option<ApprovedSession>,
    session_revocation: Option<SessionRevocation>,
    action_approval: Option<ActionApproval>,
    file_restore_prepare: Option<FileRestorePrepareRequest>,
    file_restore_commit: Option<FileRestoreCommitRequest>,
    audit_query: Option<SessionAuditQuery>,
}

/// Narrow request shape accepted by a historical audit reader. Keeping this
/// separate from `ControlRequest` makes write-shaped fields a parse error
/// instead of silently ignoring them.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditControlRequest {
    schema_version: u16,
    request_id: String,
    method: String,
    audit_query: SessionAuditQuery,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ResponseStatus {
    Ack,
    Error,
}

#[derive(Debug, Serialize)]
struct ApprovalResponse {
    schema_version: u16,
    request_id: Option<String>,
    status: ResponseStatus,
    code: &'static str,
    approval_digest: Option<String>,
}

#[derive(Debug, Serialize)]
struct RevocationResponse {
    schema_version: u16,
    request_id: Option<String>,
    status: ResponseStatus,
    code: &'static str,
    revocation_digest: Option<String>,
    task_id: Option<Uuid>,
    session_id: Option<String>,
    run_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct ActionApprovalResponse {
    schema_version: u16,
    request_id: Option<String>,
    status: ResponseStatus,
    code: &'static str,
    approval_digest: Option<String>,
    approval_id: Option<Uuid>,
    proposal_digest: Option<String>,
    approval_request_hash: Option<String>,
}

#[derive(Debug, Serialize)]
struct FileRestoreResponse {
    schema_version: u16,
    request_id: Option<String>,
    status: ResponseStatus,
    code: &'static str,
    challenge_hash: Option<String>,
    challenge: Option<FileRestoreChallenge>,
    record_hash: Option<String>,
    record: Option<FileRestoreRecord>,
}

#[derive(Debug, Serialize)]
struct AuditResponse {
    schema_version: u16,
    request_id: Option<String>,
    status: ResponseStatus,
    code: &'static str,
    page: Option<SessionAuditPage>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum ControlResponse {
    Approval(ApprovalResponse),
    Revocation(RevocationResponse),
    ActionApproval(ActionApprovalResponse),
    FileRestore(Box<FileRestoreResponse>),
    Audit(Box<AuditResponse>),
}

/// Runs the private, inherited Desktop control channel until its input closes.
///
/// The stream starts immediately after the optional readiness line emitted by
/// the binary. Each direction uses the same exact frame:
/// `ALC1 || uint32_be(json_length) || json`. Frame-level corruption receives
/// one deterministic error response when possible and then closes the channel.
/// Request-level errors are recoverable and leave the channel synchronized.
///
/// # Errors
///
/// Returns a terminal framing, encoding, or I/O failure. Callers must stop the
/// HTTP planner surface when this capability channel is lost.
pub fn serve_control_channel<R, W>(
    runtime: &Runtime,
    mut input: R,
    mut output: W,
) -> Result<ControlChannelExit, ControlChannelError>
where
    R: Read,
    W: Write,
{
    loop {
        let body = match read_frame(&mut input) {
            Ok(Some(body)) => body,
            Ok(None) => return Ok(ControlChannelExit::ParentClosed),
            Err(FrameReadError::InvalidHeader) => {
                write_error(&mut output, None, "FRAME_HEADER_INVALID")?;
                return Err(ControlChannelError::InvalidHeader);
            }
            Err(FrameReadError::TooLarge) => {
                write_error(&mut output, None, "FRAME_TOO_LARGE")?;
                return Err(ControlChannelError::FrameTooLarge);
            }
            Err(FrameReadError::Truncated) => {
                write_error(&mut output, None, "FRAME_TRUNCATED")?;
                return Err(ControlChannelError::TruncatedFrame);
            }
            Err(FrameReadError::Input) => return Err(ControlChannelError::Input),
        };

        let response = process_request(runtime, &body);
        write_response(&mut output, &response)?;
    }
}

/// Runs a bounded, audit-only inherited channel over a read-only ledger.
///
/// Only `GET_SESSION_AUDIT` with the exact audit request shape is accepted.
/// There is no HTTP listener, task-authorization method, approval method, or
/// execution surface behind this channel. Callers should construct `ledger`
/// with [`Ledger::open_read_only`].
///
/// # Errors
///
/// Returns a terminal framing, encoding, or I/O failure. Request-level audit
/// errors are typed responses and leave the stream synchronized.
pub fn serve_audit_control_channel<R, W>(
    ledger: &Ledger,
    mut input: R,
    mut output: W,
) -> Result<ControlChannelExit, ControlChannelError>
where
    R: Read,
    W: Write,
{
    loop {
        let body = match read_frame(&mut input) {
            Ok(Some(body)) => body,
            Ok(None) => return Ok(ControlChannelExit::ParentClosed),
            Err(FrameReadError::InvalidHeader) => {
                write_audit_error(&mut output, None, "FRAME_HEADER_INVALID")?;
                return Err(ControlChannelError::InvalidHeader);
            }
            Err(FrameReadError::TooLarge) => {
                write_audit_error(&mut output, None, "FRAME_TOO_LARGE")?;
                return Err(ControlChannelError::FrameTooLarge);
            }
            Err(FrameReadError::Truncated) => {
                write_audit_error(&mut output, None, "FRAME_TRUNCATED")?;
                return Err(ControlChannelError::TruncatedFrame);
            }
            Err(FrameReadError::Input) => return Err(ControlChannelError::Input),
        };

        let response = process_audit_only_request(ledger, &body);
        write_response(&mut output, &response)?;
    }
}

fn process_audit_only_request(ledger: &Ledger, body: &[u8]) -> ControlResponse {
    let Ok(request) = serde_json::from_slice::<AuditControlRequest>(body) else {
        let request_id = serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|value| {
                value
                    .get("request_id")
                    .and_then(serde_json::Value::as_str)
                    .filter(|candidate| canonical_request_id(candidate))
                    .map(str::to_owned)
            });
        return audit_error_response(request_id.as_deref(), "MALFORMED_REQUEST");
    };
    let request_id = request.request_id.as_str();
    if !canonical_request_id(request_id) {
        return audit_error_response(None, "INVALID_REQUEST_ID");
    }
    if request.schema_version != DESKTOP_PROTOCOL_SCHEMA_VERSION {
        return audit_error_response(Some(request_id), "UNSUPPORTED_SCHEMA");
    }
    if request.method != GET_SESSION_AUDIT_METHOD {
        return audit_error_response(Some(request_id), "UNSUPPORTED_METHOD");
    }
    process_session_audit(ledger, request_id, &request.audit_query)
}

fn process_request(runtime: &Runtime, body: &[u8]) -> ControlResponse {
    let Ok(request) = serde_json::from_slice::<ControlRequest>(body) else {
        return malformed_request_response(body);
    };
    let request_id = request.request_id.as_str();
    if !canonical_request_id(request_id) {
        return method_error_response(request.method.as_str(), None, "INVALID_REQUEST_ID");
    }
    if request.schema_version != DESKTOP_PROTOCOL_SCHEMA_VERSION {
        return method_error_response(
            request.method.as_str(),
            Some(request_id),
            "UNSUPPORTED_SCHEMA",
        );
    }
    match request.method.as_str() {
        APPROVE_SESSION_METHOD => match (
            request.approved_session,
            request.session_revocation,
            request.action_approval,
            request.file_restore_prepare,
            request.file_restore_commit,
            request.audit_query,
        ) {
            (Some(approval), None, None, None, None, None) => {
                process_approval(runtime, request_id, &approval)
            }
            _ => error_response(Some(request_id), "MALFORMED_REQUEST"),
        },
        REVOKE_SESSION_METHOD => match (
            request.approved_session,
            request.session_revocation,
            request.action_approval,
            request.file_restore_prepare,
            request.file_restore_commit,
            request.audit_query,
        ) {
            (None, Some(revocation), None, None, None, None) => {
                process_revocation(runtime, request_id, &revocation)
            }
            _ => revocation_error_response(Some(request_id), "MALFORMED_REQUEST"),
        },
        REGISTER_ACTION_APPROVAL_METHOD => match (
            request.approved_session,
            request.session_revocation,
            request.action_approval,
            request.file_restore_prepare,
            request.file_restore_commit,
            request.audit_query,
        ) {
            (None, None, Some(approval), None, None, None) => {
                process_action_approval(runtime, request_id, &approval)
            }
            _ => action_approval_error_response(Some(request_id), "MALFORMED_REQUEST"),
        },
        PREPARE_FILE_RESTORE_METHOD => match (
            request.approved_session,
            request.session_revocation,
            request.action_approval,
            request.file_restore_prepare,
            request.file_restore_commit,
            request.audit_query,
        ) {
            (None, None, None, Some(prepare), None, None) => {
                process_file_restore_prepare(runtime, request_id, &prepare)
            }
            _ => file_restore_error_response(Some(request_id), "MALFORMED_REQUEST"),
        },
        COMMIT_FILE_RESTORE_METHOD => match (
            request.approved_session,
            request.session_revocation,
            request.action_approval,
            request.file_restore_prepare,
            request.file_restore_commit,
            request.audit_query,
        ) {
            (None, None, None, None, Some(commit), None) => {
                process_file_restore_commit(runtime, request_id, &commit)
            }
            _ => file_restore_error_response(Some(request_id), "MALFORMED_REQUEST"),
        },
        GET_SESSION_AUDIT_METHOD => match (
            request.approved_session,
            request.session_revocation,
            request.action_approval,
            request.file_restore_prepare,
            request.file_restore_commit,
            request.audit_query,
        ) {
            (None, None, None, None, None, Some(query)) => {
                process_session_audit(runtime.ledger(), request_id, &query)
            }
            _ => audit_error_response(Some(request_id), "MALFORMED_REQUEST"),
        },
        _ => error_response(Some(request_id), "UNSUPPORTED_METHOD"),
    }
}

fn malformed_request_response(body: &[u8]) -> ControlResponse {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return error_response(None, "MALFORMED_REQUEST");
    };
    let method = value.get("method").and_then(serde_json::Value::as_str);
    let request_id = value
        .get("request_id")
        .and_then(serde_json::Value::as_str)
        .filter(|value| canonical_request_id(value));
    method_error_response(method.unwrap_or_default(), request_id, "MALFORMED_REQUEST")
}

fn method_error_response(
    method: &str,
    request_id: Option<&str>,
    code: &'static str,
) -> ControlResponse {
    match method {
        PREPARE_FILE_RESTORE_METHOD | COMMIT_FILE_RESTORE_METHOD => {
            file_restore_error_response(request_id, code)
        }
        REVOKE_SESSION_METHOD => revocation_error_response(request_id, code),
        REGISTER_ACTION_APPROVAL_METHOD => action_approval_error_response(request_id, code),
        GET_SESSION_AUDIT_METHOD => audit_error_response(request_id, code),
        _ => error_response(request_id, code),
    }
}

fn trusted_now() -> Option<i64> {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    i64::try_from(seconds).ok()
}

fn process_session_audit(
    ledger: &Ledger,
    request_id: &str,
    query: &SessionAuditQuery,
) -> ControlResponse {
    match ledger.session_audit(query) {
        Ok(page) => ControlResponse::Audit(Box::new(AuditResponse {
            schema_version: DESKTOP_PROTOCOL_SCHEMA_VERSION,
            request_id: Some(request_id.to_owned()),
            status: ResponseStatus::Ack,
            code: "SESSION_AUDIT_READY",
            page: Some(page),
        })),
        Err(LedgerError::InvalidAuditQuery) => {
            audit_error_response(Some(request_id), "INVALID_AUDIT_QUERY")
        }
        Err(LedgerError::UnknownApproval) => {
            audit_error_response(Some(request_id), "UNKNOWN_SESSION")
        }
        Err(LedgerError::CorruptState) => {
            audit_error_response(Some(request_id), "AUDIT_STATE_CORRUPT")
        }
        Err(LedgerError::AuditSnapshotChanged) => {
            audit_error_response(Some(request_id), "AUDIT_SNAPSHOT_CHANGED")
        }
        Err(LedgerError::AuditHistoryTooLarge) => {
            audit_error_response(Some(request_id), "AUDIT_HISTORY_TOO_LARGE")
        }
        Err(LedgerError::AuditPageTooLarge) => {
            audit_error_response(Some(request_id), "AUDIT_PAGE_TOO_LARGE")
        }
        Err(_) => audit_error_response(Some(request_id), "LEDGER_UNAVAILABLE"),
    }
}

fn process_file_restore_prepare(
    runtime: &Runtime,
    request_id: &str,
    request: &FileRestorePrepareRequest,
) -> ControlResponse {
    let Some(now) = trusted_now() else {
        return file_restore_error_response(Some(request_id), "FILE_RESTORE_UNAVAILABLE");
    };
    match runtime.prepare_file_restore(request, now) {
        Ok(FileRestorePrepareOutcome::Prepared {
            challenge,
            challenge_hash,
            already_prepared,
        }) => ControlResponse::FileRestore(Box::new(FileRestoreResponse {
            schema_version: DESKTOP_PROTOCOL_SCHEMA_VERSION,
            request_id: Some(request_id.to_owned()),
            status: ResponseStatus::Ack,
            code: if already_prepared {
                "FILE_RESTORE_ALREADY_PREPARED"
            } else {
                "FILE_RESTORE_PREPARED"
            },
            challenge_hash: Some(challenge_hash),
            challenge: Some(challenge),
            record_hash: None,
            record: None,
        })),
        Ok(FileRestorePrepareOutcome::AlreadyCommitted {
            record,
            record_hash,
        }) => ControlResponse::FileRestore(Box::new(FileRestoreResponse {
            schema_version: DESKTOP_PROTOCOL_SCHEMA_VERSION,
            request_id: Some(request_id.to_owned()),
            status: ResponseStatus::Ack,
            code: "FILE_RESTORE_ALREADY_COMMITTED",
            challenge_hash: Some(record.challenge_hash.clone()),
            challenge: None,
            record_hash: Some(record_hash),
            record: Some(record),
        })),
        Err(error) => file_restore_error_response(Some(request_id), error.reason_code()),
    }
}

fn process_file_restore_commit(
    runtime: &Runtime,
    request_id: &str,
    request: &FileRestoreCommitRequest,
) -> ControlResponse {
    let Some(now) = trusted_now() else {
        return file_restore_error_response(Some(request_id), "FILE_RESTORE_UNAVAILABLE");
    };
    match runtime.commit_file_restore(request, now) {
        Ok(outcome) => ControlResponse::FileRestore(Box::new(FileRestoreResponse {
            schema_version: DESKTOP_PROTOCOL_SCHEMA_VERSION,
            request_id: Some(request_id.to_owned()),
            status: ResponseStatus::Ack,
            code: if outcome.already_committed {
                "FILE_RESTORE_ALREADY_COMMITTED"
            } else {
                "FILE_RESTORE_COMMITTED"
            },
            challenge_hash: Some(outcome.record.challenge_hash.clone()),
            challenge: None,
            record_hash: Some(outcome.record_hash),
            record: Some(outcome.record),
        })),
        Err(error) => file_restore_error_response(Some(request_id), error.reason_code()),
    }
}

fn process_action_approval(
    runtime: &Runtime,
    request_id: &str,
    approval: &ActionApproval,
) -> ControlResponse {
    if approval.validate().is_err() {
        return action_approval_error_response(Some(request_id), "INVALID_ACTION_APPROVAL");
    }
    let Ok(approval_digest) = goose_digest(approval) else {
        return action_approval_error_response(Some(request_id), "INVALID_ACTION_APPROVAL");
    };
    let result = runtime.register_action_approval(approval);
    let code = match result {
        Ok(ActionApprovalRegistration::Inserted) => "ACTION_APPROVAL_REGISTERED",
        Ok(ActionApprovalRegistration::AlreadyPresent) => "ACTION_APPROVAL_ALREADY_REGISTERED",
        Err(LedgerError::UnknownApproval) => {
            return action_approval_error_response(Some(request_id), "UNKNOWN_SESSION");
        }
        Err(LedgerError::ActionApprovalScopeMismatch) => {
            return action_approval_error_response(
                Some(request_id),
                "ACTION_APPROVAL_SCOPE_MISMATCH",
            );
        }
        Err(LedgerError::ConflictingActionApproval) => {
            return action_approval_error_response(Some(request_id), "ACTION_APPROVAL_CONFLICT");
        }
        Err(LedgerError::ActionApprovalBinding(_)) => {
            return action_approval_error_response(Some(request_id), "INVALID_ACTION_APPROVAL");
        }
        Err(_) => {
            return action_approval_error_response(Some(request_id), "LEDGER_UNAVAILABLE");
        }
    };
    ControlResponse::ActionApproval(ActionApprovalResponse {
        schema_version: DESKTOP_PROTOCOL_SCHEMA_VERSION,
        request_id: Some(request_id.to_owned()),
        status: ResponseStatus::Ack,
        code,
        approval_digest: Some(approval_digest),
        approval_id: Some(approval.approval_id),
        proposal_digest: Some(approval.proposal_digest.to_string()),
        approval_request_hash: Some(approval.approval_request_hash.to_string()),
    })
}

fn process_approval(
    runtime: &Runtime,
    request_id: &str,
    approved_session: &ApprovedSession,
) -> ControlResponse {
    if approved_session.validate().is_err() {
        return error_response(Some(request_id), "INVALID_APPROVAL");
    }
    let Ok(approval_digest) = goose_digest(approved_session) else {
        return error_response(Some(request_id), "INVALID_APPROVAL");
    };
    match runtime.register_session(approved_session) {
        Ok(ApprovalRegistration::Inserted) => ControlResponse::Approval(ApprovalResponse {
            schema_version: DESKTOP_PROTOCOL_SCHEMA_VERSION,
            request_id: Some(request_id.to_owned()),
            status: ResponseStatus::Ack,
            code: "SESSION_APPROVED",
            approval_digest: Some(approval_digest),
        }),
        Ok(ApprovalRegistration::AlreadyPresent) => ControlResponse::Approval(ApprovalResponse {
            schema_version: DESKTOP_PROTOCOL_SCHEMA_VERSION,
            request_id: Some(request_id.to_owned()),
            status: ResponseStatus::Ack,
            code: "SESSION_ALREADY_APPROVED",
            approval_digest: Some(approval_digest),
        }),
        Err(LedgerError::ConflictingApproval | LedgerError::DuplicateApproval) => {
            error_response(Some(request_id), "APPROVAL_CONFLICT")
        }
        Err(LedgerError::TaskBinding(_) | LedgerError::InvalidApproval) => {
            error_response(Some(request_id), "INVALID_APPROVAL")
        }
        Err(_) => error_response(Some(request_id), "LEDGER_UNAVAILABLE"),
    }
}

fn process_revocation(
    runtime: &Runtime,
    request_id: &str,
    revocation: &SessionRevocation,
) -> ControlResponse {
    if revocation.validate().is_err() {
        return revocation_error_response(Some(request_id), "INVALID_REVOCATION");
    }
    let Ok(revocation_digest) = goose_digest(revocation) else {
        return revocation_error_response(Some(request_id), "INVALID_REVOCATION");
    };
    let Some(revoked_at) = trusted_now() else {
        return revocation_error_response(Some(request_id), "LEDGER_UNAVAILABLE");
    };
    match runtime.revoke_session_at(revocation, revoked_at) {
        Ok(RevocationRegistration::Revoked) => {
            revocation_ack_response(request_id, "SESSION_REVOKED", revocation_digest, revocation)
        }
        Ok(RevocationRegistration::AlreadyRevoked) => revocation_ack_response(
            request_id,
            "SESSION_ALREADY_REVOKED",
            revocation_digest,
            revocation,
        ),
        Err(LedgerError::UnknownApproval) => {
            revocation_error_response(Some(request_id), "UNKNOWN_SESSION")
        }
        Err(LedgerError::RevocationBindingMismatch) => {
            revocation_error_response(Some(request_id), "REVOCATION_BINDING_MISMATCH")
        }
        Err(LedgerError::ConflictingRevocation) => {
            revocation_error_response(Some(request_id), "REVOCATION_CONFLICT")
        }
        Err(LedgerError::SessionRevocationBinding(_) | LedgerError::InvalidRevocation) => {
            revocation_error_response(Some(request_id), "INVALID_REVOCATION")
        }
        Err(LedgerError::InvalidTime | LedgerError::ClockRollback) => {
            revocation_error_response(Some(request_id), "INVALID_REVOCATION_TIME")
        }
        Err(_) => revocation_error_response(Some(request_id), "LEDGER_UNAVAILABLE"),
    }
}

fn revocation_ack_response(
    request_id: &str,
    code: &'static str,
    revocation_digest: String,
    revocation: &SessionRevocation,
) -> ControlResponse {
    ControlResponse::Revocation(RevocationResponse {
        schema_version: DESKTOP_PROTOCOL_SCHEMA_VERSION,
        request_id: Some(request_id.to_owned()),
        status: ResponseStatus::Ack,
        code,
        revocation_digest: Some(revocation_digest),
        task_id: Some(revocation.task_id),
        session_id: Some(revocation.session_id.clone()),
        run_id: Some(revocation.run_id.clone()),
    })
}

fn error_response(request_id: Option<&str>, code: &'static str) -> ControlResponse {
    ControlResponse::Approval(ApprovalResponse {
        schema_version: DESKTOP_PROTOCOL_SCHEMA_VERSION,
        request_id: request_id.map(str::to_owned),
        status: ResponseStatus::Error,
        code,
        approval_digest: None,
    })
}

fn revocation_error_response(request_id: Option<&str>, code: &'static str) -> ControlResponse {
    ControlResponse::Revocation(RevocationResponse {
        schema_version: DESKTOP_PROTOCOL_SCHEMA_VERSION,
        request_id: request_id.map(str::to_owned),
        status: ResponseStatus::Error,
        code,
        revocation_digest: None,
        task_id: None,
        session_id: None,
        run_id: None,
    })
}

fn action_approval_error_response(request_id: Option<&str>, code: &'static str) -> ControlResponse {
    ControlResponse::ActionApproval(ActionApprovalResponse {
        schema_version: DESKTOP_PROTOCOL_SCHEMA_VERSION,
        request_id: request_id.map(str::to_owned),
        status: ResponseStatus::Error,
        code,
        approval_digest: None,
        approval_id: None,
        proposal_digest: None,
        approval_request_hash: None,
    })
}

fn file_restore_error_response(request_id: Option<&str>, code: &'static str) -> ControlResponse {
    ControlResponse::FileRestore(Box::new(FileRestoreResponse {
        schema_version: DESKTOP_PROTOCOL_SCHEMA_VERSION,
        request_id: request_id.map(str::to_owned),
        status: ResponseStatus::Error,
        code,
        challenge_hash: None,
        challenge: None,
        record_hash: None,
        record: None,
    }))
}

fn audit_error_response(request_id: Option<&str>, code: &'static str) -> ControlResponse {
    ControlResponse::Audit(Box::new(AuditResponse {
        schema_version: DESKTOP_PROTOCOL_SCHEMA_VERSION,
        request_id: request_id.map(str::to_owned),
        status: ResponseStatus::Error,
        code,
        page: None,
    }))
}

fn canonical_request_id(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|parsed| !parsed.is_nil() && parsed.to_string() == value)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FrameReadError {
    Input,
    InvalidHeader,
    TooLarge,
    Truncated,
}

fn read_frame(input: &mut impl Read) -> Result<Option<Vec<u8>>, FrameReadError> {
    let mut header = [0_u8; CONTROL_HEADER_BYTES];
    if !read_exact_or_eof(input, &mut header)? {
        return Ok(None);
    }
    if header[..4] != CONTROL_FRAME_MAGIC {
        return Err(FrameReadError::InvalidHeader);
    }
    let length = u32::from_be_bytes(
        header[4..]
            .try_into()
            .map_err(|_| FrameReadError::InvalidHeader)?,
    ) as usize;
    if length > MAX_CONTROL_FRAME_BYTES {
        return Err(FrameReadError::TooLarge);
    }
    let mut body = vec![0_u8; length];
    read_exact_body(input, &mut body)?;
    Ok(Some(body))
}

fn read_exact_or_eof(input: &mut impl Read, target: &mut [u8]) -> Result<bool, FrameReadError> {
    let mut offset = 0;
    while offset < target.len() {
        match input.read(&mut target[offset..]) {
            Ok(0) if offset == 0 => return Ok(false),
            Ok(0) => return Err(FrameReadError::Truncated),
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(FrameReadError::Input),
        }
    }
    Ok(true)
}

fn read_exact_body(input: &mut impl Read, target: &mut [u8]) -> Result<(), FrameReadError> {
    let mut offset = 0;
    while offset < target.len() {
        match input.read(&mut target[offset..]) {
            Ok(0) => return Err(FrameReadError::Truncated),
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(FrameReadError::Input),
        }
    }
    Ok(())
}

fn write_error(
    output: &mut impl Write,
    request_id: Option<&str>,
    code: &'static str,
) -> Result<(), ControlChannelError> {
    write_response(output, &error_response(request_id, code))
}

fn write_audit_error(
    output: &mut impl Write,
    request_id: Option<&str>,
    code: &'static str,
) -> Result<(), ControlChannelError> {
    write_response(output, &audit_error_response(request_id, code))
}

fn write_response(
    output: &mut impl Write,
    response: &ControlResponse,
) -> Result<(), ControlChannelError> {
    let body = serde_json::to_vec(response).map_err(|_| ControlChannelError::Encoding)?;
    let length = u32::try_from(body.len()).map_err(|_| ControlChannelError::Encoding)?;
    if body.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(ControlChannelError::Encoding);
    }
    output
        .write_all(&CONTROL_FRAME_MAGIC)
        .map_err(|_| ControlChannelError::Output)?;
    output
        .write_all(&length.to_be_bytes())
        .map_err(|_| ControlChannelError::Output)?;
    output
        .write_all(&body)
        .map_err(|_| ControlChannelError::Output)?;
    output.flush().map_err(|_| ControlChannelError::Output)
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, path::PathBuf};

    use accordlock_agent_protocol::Digest32;
    use serde_json::{Value, json};
    use tempfile::TempDir;

    use super::*;
    use crate::{
        ActionApproval, ActionApprovalRequest, ActionDescriptor, ActionType, ApprovalDecision,
        Capability, Runtime, SessionRevocation, TOOL_EXECUTION_SCHEMA_VERSION, TaskPolicy,
        ToolCallProposal,
        canonical::goose_digest,
        filesystem::{
            FilesystemExecutionRequest, FilesystemExecutionStatus, FilesystemResult,
            execute_governed,
        },
        ledger::AuthorizationResult,
    };

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    struct Fixture {
        _root: TempDir,
        workspace: PathBuf,
        runtime: Runtime,
    }

    impl Fixture {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let root = tempfile::tempdir()?;
            let workspace = root.path().join("workspace");
            std::fs::create_dir(&workspace)?;
            let runtime = Runtime::open(&root.path().join("runtime.sqlite3"), TOKEN)?;
            Ok(Self {
                _root: root,
                workspace,
                runtime,
            })
        }

        fn approval(&self, session: &str, task: Uuid) -> ApprovedSession {
            ApprovedSession::new_with_task_objective(
                task,
                session,
                session,
                &self.workspace,
                7,
                "task-contract",
                TaskPolicy::new(
                    Digest32::sha256(b"task-contract"),
                    [],
                    [".accordlock".to_owned()],
                )
                .unwrap_or_else(|error| unreachable!("valid policy fixture: {error}")),
                [Capability::new("developer", "write")],
                100,
                200,
            )
            .unwrap_or_else(|error| unreachable!("valid fixture: {error}"))
        }
    }

    fn request(id: Uuid, approval: &ApprovedSession) -> Value {
        json!({
            "schema_version": DESKTOP_PROTOCOL_SCHEMA_VERSION,
            "request_id": id.to_string(),
            "method": "APPROVE_SESSION",
            "approved_session": approval,
        })
    }

    fn revocation_request(id: Uuid, revocation: &SessionRevocation) -> Value {
        json!({
            "schema_version": DESKTOP_PROTOCOL_SCHEMA_VERSION,
            "request_id": id.to_string(),
            "method": "REVOKE_SESSION",
            "session_revocation": revocation,
        })
    }

    fn action_approval_request(id: Uuid, approval: &ActionApproval) -> Value {
        json!({
            "schema_version": DESKTOP_PROTOCOL_SCHEMA_VERSION,
            "request_id": id.to_string(),
            "method": "REGISTER_ACTION_APPROVAL",
            "action_approval": approval,
        })
    }

    fn audit_request(id: Uuid, session_id: &str, offset: u32, limit: u16) -> Value {
        json!({
            "schema_version": DESKTOP_PROTOCOL_SCHEMA_VERSION,
            "request_id": id.to_string(),
            "method": GET_SESSION_AUDIT_METHOD,
            "audit_query": {
                "schema_version": DESKTOP_PROTOCOL_SCHEMA_VERSION,
                "session_id": session_id,
                "offset": offset,
                "limit": limit,
            },
        })
    }

    fn delete_for_restore(fixture: &Fixture) -> Result<Uuid, Box<dyn std::error::Error>> {
        let now = trusted_now().ok_or("trusted clock unavailable")?;
        std::fs::write(fixture.workspace.join("restore.txt"), b"control restore")?;
        let approved = ApprovedSession::new_with_task_objective(
            Uuid::new_v4(),
            "restore-control-session",
            "restore-control-run",
            &fixture.workspace,
            1,
            "restore control objective",
            TaskPolicy::new(
                Digest32::sha256(b"restore control objective"),
                [],
                [".accordlock".to_owned()],
            )?,
            [Capability::new("developer", "delete_file")],
            now - 10,
            now + 300,
        )?;
        fixture.runtime.approve_session(&approved)?;
        let arguments = json!({"path": "restore.txt"});
        let arguments_sha256 = goose_digest(&arguments)?;
        let proposal = ToolCallProposal {
            schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
            session_id: approved.session_id.clone(),
            run_id: approved.run_id.clone(),
            tool_call_id: "delete-for-control-restore".to_owned(),
            workspace_root: approved.workspace_root.clone(),
            extension_id: "developer".to_owned(),
            tool_name: "delete_file".to_owned(),
            arguments_sha256: arguments_sha256.clone(),
            arguments,
            agent_plan_checkpoint: crate::model::test_agent_plan_checkpoint(
                &approved.session_id,
                &approved.run_id,
                "delete-for-control-restore",
                "developer__delete_file",
                &arguments_sha256,
                now - 1,
            ),
        };
        let request = FilesystemExecutionRequest {
            schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
            proposal,
        };
        let approval_needed = execute_governed(fixture.runtime.ledger(), &request, now, 30)?;
        assert_eq!(
            approval_needed.status,
            FilesystemExecutionStatus::ApprovalRequired
        );
        let context = approval_needed
            .approval_request
            .ok_or("missing restore deletion approval")?;
        let approval = ActionApproval::for_context(
            &context,
            Uuid::new_v4(),
            ApprovalDecision::Approved,
            Digest32::sha256(b"control restore deletion approved"),
            now - 1,
            now + 60,
        )?;
        fixture.runtime.register_action_approval(&approval)?;
        let deleted = execute_governed(fixture.runtime.ledger(), &request, now, 30)?;
        assert_eq!(deleted.status, FilesystemExecutionStatus::Succeeded);
        let FilesystemResult::Delete { recovery_id, .. } =
            deleted.result.ok_or("missing delete result")?
        else {
            return Err("unexpected delete result".into());
        };
        Ok(Uuid::parse_str(&recovery_id)?)
    }

    fn prepare_file_restore_request(id: Uuid, recovery_id: Uuid) -> Value {
        json!({
            "schema_version": DESKTOP_PROTOCOL_SCHEMA_VERSION,
            "request_id": id.to_string(),
            "method": PREPARE_FILE_RESTORE_METHOD,
            "file_restore_prepare": {
                "schema_version": DESKTOP_PROTOCOL_SCHEMA_VERSION,
                "recovery_id": recovery_id.to_string(),
            },
        })
    }

    fn commit_file_restore_request(
        id: Uuid,
        restore_id: &str,
        recovery_id: Uuid,
        challenge_hash: &str,
    ) -> Value {
        json!({
            "schema_version": DESKTOP_PROTOCOL_SCHEMA_VERSION,
            "request_id": id.to_string(),
            "method": COMMIT_FILE_RESTORE_METHOD,
            "file_restore_commit": {
                "schema_version": DESKTOP_PROTOCOL_SCHEMA_VERSION,
                "restore_id": restore_id,
                "recovery_id": recovery_id.to_string(),
                "challenge_hash": challenge_hash,
            },
        })
    }

    fn frame(value: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(CONTROL_HEADER_BYTES + value.len());
        bytes.extend_from_slice(&CONTROL_FRAME_MAGIC);
        bytes.extend_from_slice(&u32::try_from(value.len()).unwrap_or_default().to_be_bytes());
        bytes.extend_from_slice(value);
        bytes
    }

    fn json_frame(value: &Value) -> Vec<u8> {
        frame(&serde_json::to_vec(value).unwrap_or_default())
    }

    fn responses(mut bytes: &[u8]) -> Vec<Value> {
        let mut values = Vec::new();
        while !bytes.is_empty() {
            assert!(bytes.len() >= CONTROL_HEADER_BYTES);
            assert_eq!(&bytes[..4], &CONTROL_FRAME_MAGIC);
            let length = u32::from_be_bytes(bytes[4..8].try_into().unwrap_or_default()) as usize;
            assert!(bytes.len() >= CONTROL_HEADER_BYTES + length);
            values.push(
                serde_json::from_slice(&bytes[8..8 + length])
                    .unwrap_or_else(|error| unreachable!("valid response: {error}")),
            );
            bytes = &bytes[8 + length..];
        }
        values
    }

    #[test]
    fn exact_retry_is_idempotent_and_conflict_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let task = Uuid::new_v4();
        let approval = fixture.approval("session-1", task);
        let session_conflict = fixture.approval("session-1", Uuid::new_v4());
        let task_conflict = fixture.approval("session-2", task);
        let mut input = json_frame(&request(Uuid::new_v4(), &approval));
        input.extend(json_frame(&request(Uuid::new_v4(), &approval)));
        input.extend(json_frame(&request(Uuid::new_v4(), &session_conflict)));
        input.extend(json_frame(&request(Uuid::new_v4(), &task_conflict)));
        let mut output = Vec::new();

        let exit = serve_control_channel(&fixture.runtime, Cursor::new(input), &mut output)?;

        assert_eq!(exit, ControlChannelExit::ParentClosed);
        let responses = responses(&output);
        assert_eq!(responses.len(), 4);
        assert_eq!(responses[0]["status"], "ACK");
        assert_eq!(responses[0]["code"], "SESSION_APPROVED");
        assert_eq!(responses[1]["status"], "ACK");
        assert_eq!(responses[1]["code"], "SESSION_ALREADY_APPROVED");
        assert_eq!(
            responses[0]["approval_digest"],
            responses[1]["approval_digest"]
        );
        assert_eq!(responses[2]["status"], "ERROR");
        assert_eq!(responses[2]["code"], "APPROVAL_CONFLICT");
        assert_eq!(responses[3]["status"], "ERROR");
        assert_eq!(responses[3]["code"], "APPROVAL_CONFLICT");
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn deleted_file_restore_control_contract_is_exact_private_and_idempotent()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let recovery_id = delete_for_restore(&fixture)?;
        let prepare_id = Uuid::new_v4();
        let retry_id = Uuid::new_v4();
        let mut prepare_input = json_frame(&prepare_file_restore_request(prepare_id, recovery_id));
        prepare_input.extend(json_frame(&prepare_file_restore_request(
            retry_id,
            recovery_id,
        )));
        let mut prepare_output = Vec::new();
        serve_control_channel(
            &fixture.runtime,
            Cursor::new(prepare_input),
            &mut prepare_output,
        )?;
        let prepared = responses(&prepare_output);
        assert_eq!(prepared.len(), 2);
        assert_eq!(
            prepared[0]["schema_version"],
            DESKTOP_PROTOCOL_SCHEMA_VERSION
        );
        assert_eq!(prepared[0]["request_id"], prepare_id.to_string());
        assert_eq!(prepared[0]["status"], "ACK");
        assert_eq!(prepared[0]["code"], "FILE_RESTORE_PREPARED");
        assert!(prepared[0]["challenge_hash"].as_str().is_some());
        assert!(prepared[0]["challenge"].is_object());
        assert!(prepared[0]["record_hash"].is_null());
        assert!(prepared[0]["record"].is_null());
        assert_eq!(prepared[1]["code"], "FILE_RESTORE_ALREADY_PREPARED");
        assert_eq!(prepared[1]["challenge_hash"], prepared[0]["challenge_hash"]);
        assert_eq!(prepared[1]["challenge"], prepared[0]["challenge"]);

        let restore_id = prepared[0]["challenge"]["restore_id"]
            .as_str()
            .ok_or("missing restore id")?;
        let challenge_hash = prepared[0]["challenge_hash"]
            .as_str()
            .ok_or("missing challenge hash")?;
        assert_eq!(
            prepared[0]["challenge"]["content_sha256"],
            Digest32::sha256(b"control restore").to_string()
        );

        let bad_id = Uuid::new_v4();
        let bad = commit_file_restore_request(
            bad_id,
            restore_id,
            recovery_id,
            &Digest32::sha256(b"wrong challenge").to_string(),
        );
        let mut bad_output = Vec::new();
        serve_control_channel(
            &fixture.runtime,
            Cursor::new(json_frame(&bad)),
            &mut bad_output,
        )?;
        let bad_response = responses(&bad_output);
        assert_eq!(bad_response[0]["status"], "ERROR");
        assert_eq!(bad_response[0]["code"], "FILE_RESTORE_CHALLENGE_MISMATCH");
        assert!(bad_response[0]["challenge_hash"].is_null());
        assert!(bad_response[0]["challenge"].is_null());
        assert!(bad_response[0]["record_hash"].is_null());
        assert!(bad_response[0]["record"].is_null());
        assert!(!fixture.workspace.join("restore.txt").exists());

        let commit_id = Uuid::new_v4();
        let commit_retry_id = Uuid::new_v4();
        let mut commit_input = json_frame(&commit_file_restore_request(
            commit_id,
            restore_id,
            recovery_id,
            challenge_hash,
        ));
        commit_input.extend(json_frame(&commit_file_restore_request(
            commit_retry_id,
            restore_id,
            recovery_id,
            challenge_hash,
        )));
        let mut commit_output = Vec::new();
        serve_control_channel(
            &fixture.runtime,
            Cursor::new(commit_input),
            &mut commit_output,
        )?;
        let committed = responses(&commit_output);
        assert_eq!(committed[0]["code"], "FILE_RESTORE_COMMITTED");
        assert_eq!(committed[0]["challenge_hash"], challenge_hash);
        assert!(committed[0]["challenge"].is_null());
        assert!(committed[0]["record_hash"].as_str().is_some());
        assert!(committed[0]["record"].is_object());
        assert_eq!(committed[1]["code"], "FILE_RESTORE_ALREADY_COMMITTED");
        assert_eq!(committed[1]["record_hash"], committed[0]["record_hash"]);
        assert_eq!(committed[1]["record"], committed[0]["record"]);
        assert_eq!(
            std::fs::read(fixture.workspace.join("restore.txt"))?,
            b"control restore"
        );

        let mut after_output = Vec::new();
        serve_control_channel(
            &fixture.runtime,
            Cursor::new(json_frame(&prepare_file_restore_request(
                Uuid::new_v4(),
                recovery_id,
            ))),
            &mut after_output,
        )?;
        let after = responses(&after_output);
        assert_eq!(after[0]["code"], "FILE_RESTORE_ALREADY_COMMITTED");
        assert_eq!(after[0]["record_hash"], committed[0]["record_hash"]);
        Ok(())
    }

    #[test]
    fn audit_is_private_bounded_and_uses_a_dedicated_response_shape()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let approved = fixture.approval("audit-session", Uuid::new_v4());
        let mut input = json_frame(&request(Uuid::new_v4(), &approved));
        input.extend(json_frame(&audit_request(
            Uuid::new_v4(),
            &approved.session_id,
            0,
            10,
        )));
        input.extend(json_frame(&audit_request(
            Uuid::new_v4(),
            "missing-session",
            0,
            10,
        )));
        let mut malformed = audit_request(Uuid::new_v4(), &approved.session_id, 0, 10);
        malformed["audit_query"]["include_raw_arguments"] = json!(true);
        input.extend(json_frame(&malformed));
        let mut output = Vec::new();

        serve_control_channel(&fixture.runtime, Cursor::new(input), &mut output)?;

        let responses = responses(&output);
        assert_eq!(responses[0]["code"], "SESSION_APPROVED");
        assert_eq!(responses[1]["code"], "SESSION_AUDIT_READY");
        assert_eq!(responses[1]["page"]["session_id"], approved.session_id);
        assert_eq!(responses[1]["page"]["total_events"], 1);
        assert_eq!(
            responses[1]["page"]["events"][0]["type"],
            "SESSION_APPROVED"
        );
        assert!(responses[1]["page"]["page_digest"].is_string());
        assert_eq!(responses[2]["code"], "UNKNOWN_SESSION");
        assert!(responses[2]["page"].is_null());
        assert_eq!(responses[3]["code"], "MALFORMED_REQUEST");
        assert!(responses[3]["page"].is_null());
        Ok(())
    }

    #[test]
    fn historical_audit_channel_accepts_only_exact_read_requests()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let approved = fixture.approval("historical-audit", Uuid::new_v4());
        fixture.runtime.approve_session(&approved)?;
        let mutation_id = Uuid::new_v4();
        let audit_id = Uuid::new_v4();
        let mut input = json_frame(&request(mutation_id, &approved));
        input.extend(json_frame(&audit_request(
            audit_id,
            &approved.session_id,
            0,
            10,
        )));
        let mut output = Vec::new();

        serve_audit_control_channel(fixture.runtime.ledger(), Cursor::new(input), &mut output)?;

        let responses = responses(&output);
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["request_id"], mutation_id.to_string());
        assert_eq!(responses[0]["status"], "ERROR");
        assert_eq!(responses[0]["code"], "MALFORMED_REQUEST");
        assert!(responses[0]["page"].is_null());
        assert_eq!(responses[1]["request_id"], audit_id.to_string());
        assert_eq!(responses[1]["status"], "ACK");
        assert_eq!(responses[1]["code"], "SESSION_AUDIT_READY");
        assert_eq!(
            responses[1]["page"]["task_id"],
            approved.task_id.to_string()
        );
        assert_eq!(responses[1]["page"]["session_id"], approved.session_id);
        assert_eq!(responses[1]["page"]["run_id"], approved.run_id);
        Ok(())
    }

    #[test]
    fn audit_snapshot_drift_is_a_typed_recoverable_response()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let approved = fixture.approval("audit-drift", Uuid::new_v4());
        fixture.runtime.approve_session(&approved)?;
        let denied_proposal =
            |tool_call_id: &str| -> Result<ToolCallProposal, Box<dyn std::error::Error>> {
                let arguments = json!({"path": "notes.txt"});
                let arguments_sha256 = goose_digest(&arguments)?;
                Ok(ToolCallProposal {
                    schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
                    session_id: approved.session_id.clone(),
                    run_id: approved.run_id.clone(),
                    tool_call_id: tool_call_id.to_owned(),
                    workspace_root: approved.workspace_root.clone(),
                    extension_id: "developer".to_owned(),
                    tool_name: "shell".to_owned(),
                    arguments_sha256: arguments_sha256.clone(),
                    arguments,
                    agent_plan_checkpoint: crate::model::test_agent_plan_checkpoint(
                        &approved.session_id,
                        &approved.run_id,
                        tool_call_id,
                        "developer__shell",
                        &arguments_sha256,
                        119,
                    ),
                })
            };
        assert!(matches!(
            fixture.runtime.ledger().authorize_and_consume(
                &denied_proposal("first-denial")?,
                None,
                None,
                120,
                30,
            )?,
            AuthorizationResult::Denied("CAPABILITY_NOT_APPROVED")
        ));

        let mut first_output = Vec::new();
        serve_control_channel(
            &fixture.runtime,
            Cursor::new(json_frame(&audit_request(
                Uuid::new_v4(),
                &approved.session_id,
                0,
                1,
            ))),
            &mut first_output,
        )?;
        let first = responses(&first_output);
        assert_eq!(first[0]["code"], "SESSION_AUDIT_READY");
        let snapshot_revision = first[0]["page"]["snapshot_revision"]
            .as_i64()
            .ok_or("missing snapshot revision")?;
        assert_eq!(first[0]["page"]["next_offset"], 1);

        assert!(matches!(
            fixture.runtime.ledger().authorize_and_consume(
                &denied_proposal("concurrent-denial")?,
                None,
                None,
                121,
                30,
            )?,
            AuthorizationResult::Denied("CAPABILITY_NOT_APPROVED")
        ));
        let mut continuation = audit_request(Uuid::new_v4(), &approved.session_id, 1, 1);
        continuation["audit_query"]["snapshot_revision"] = json!(snapshot_revision);
        let mut continuation_output = Vec::new();
        serve_control_channel(
            &fixture.runtime,
            Cursor::new(json_frame(&continuation)),
            &mut continuation_output,
        )?;
        let drift = responses(&continuation_output);
        assert_eq!(drift[0]["code"], "AUDIT_SNAPSHOT_CHANGED");
        assert!(drift[0]["page"].is_null());
        Ok(())
    }

    #[test]
    fn malformed_restore_payload_keeps_the_restore_response_shape()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let request_id = Uuid::new_v4();
        let request = json!({
            "schema_version": DESKTOP_PROTOCOL_SCHEMA_VERSION,
            "request_id": request_id.to_string(),
            "method": PREPARE_FILE_RESTORE_METHOD,
            "file_restore_prepare": {
                "schema_version": DESKTOP_PROTOCOL_SCHEMA_VERSION,
                "recovery_id": Uuid::new_v4().to_string(),
                "renderer_supplied_path": "outside-the-workspace.txt",
            },
        });
        let mut output = Vec::new();

        serve_control_channel(
            &fixture.runtime,
            Cursor::new(json_frame(&request)),
            &mut output,
        )?;

        let response = responses(&output);
        assert_eq!(response[0]["request_id"], request_id.to_string());
        assert_eq!(response[0]["status"], "ERROR");
        assert_eq!(response[0]["code"], "MALFORMED_REQUEST");
        assert!(response[0]["challenge_hash"].is_null());
        assert!(response[0]["challenge"].is_null());
        assert!(response[0]["record_hash"].is_null());
        assert!(response[0]["record"].is_null());
        assert!(response[0].get("approval_digest").is_none());
        Ok(())
    }

    #[test]
    fn action_approval_is_private_exact_idempotent_and_conflict_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let task = Uuid::new_v4();
        let approval = fixture.approval("session-1", task);
        fixture.runtime.approve_session(&approval)?;
        let context = ActionApprovalRequest::new(
            task,
            "session-1".to_owned(),
            "session-1".to_owned(),
            "call-1".to_owned(),
            Digest32::sha256(b"proposal"),
            approval.task_policy_hash,
            approval.task_policy.task_objective_hash,
            approval.policy_epoch,
            approval.approved_at,
            Digest32::sha256(b"prestate"),
            ActionDescriptor {
                extension_id: "developer".to_owned(),
                tool_name: "write".to_owned(),
                relative_path: "reviewed.txt".to_owned(),
                action_type: ActionType::CreateFile,
                requested_bytes: 8,
                executable_path: None,
                executable_sha256: None,
            },
        )?;
        let approval = ActionApproval::for_context(
            &context,
            Uuid::new_v4(),
            ApprovalDecision::Approved,
            Digest32::sha256(b"human-approval"),
            110,
            150,
        )?;
        let mut conflicting = approval.clone();
        conflicting.approval_id = Uuid::new_v4();
        conflicting.decision = ApprovalDecision::Denied;
        let mut input = json_frame(&action_approval_request(Uuid::new_v4(), &approval));
        input.extend(json_frame(&action_approval_request(
            Uuid::new_v4(),
            &approval,
        )));
        input.extend(json_frame(&action_approval_request(
            Uuid::new_v4(),
            &conflicting,
        )));
        let mut output = Vec::new();

        serve_control_channel(&fixture.runtime, Cursor::new(input), &mut output)?;
        let responses = responses(&output);
        assert_eq!(responses[0]["code"], "ACTION_APPROVAL_REGISTERED");
        assert_eq!(responses[1]["code"], "ACTION_APPROVAL_ALREADY_REGISTERED");
        assert_eq!(
            responses[0]["approval_id"],
            approval.approval_id.to_string()
        );
        assert_eq!(
            responses[0]["approval_request_hash"],
            approval.approval_request_hash.to_string()
        );
        assert_eq!(responses[2]["status"], "ERROR");
        assert_eq!(responses[2]["code"], "ACTION_APPROVAL_CONFLICT");
        Ok(())
    }

    #[test]
    fn revocation_is_exact_idempotent_durable_and_cannot_be_resurrected()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let task = Uuid::new_v4();
        let approval = fixture.approval("session-1", task);
        let revocation = SessionRevocation::new(task, "session-1", "session-1");
        let mut input = json_frame(&request(Uuid::new_v4(), &approval));
        input.extend(json_frame(&revocation_request(Uuid::new_v4(), &revocation)));
        input.extend(json_frame(&revocation_request(Uuid::new_v4(), &revocation)));
        input.extend(json_frame(&request(Uuid::new_v4(), &approval)));
        let mut output = Vec::new();

        serve_control_channel(&fixture.runtime, Cursor::new(input), &mut output)?;

        let responses = responses(&output);
        assert_eq!(responses.len(), 4);
        assert_eq!(responses[0]["code"], "SESSION_APPROVED");
        assert_eq!(responses[1]["code"], "SESSION_REVOKED");
        assert_eq!(responses[2]["code"], "SESSION_ALREADY_REVOKED");
        assert_eq!(responses[3]["code"], "SESSION_ALREADY_APPROVED");
        assert_eq!(
            responses[1]["revocation_digest"],
            goose_digest(&revocation)?
        );
        assert_eq!(
            responses[1]["revocation_digest"],
            responses[2]["revocation_digest"]
        );
        assert_eq!(responses[1]["task_id"], task.to_string());
        assert_eq!(responses[1]["session_id"], revocation.session_id);
        assert_eq!(responses[1]["run_id"], revocation.run_id);

        let arguments = json!({"path": "notes.txt"});
        let arguments_sha256 = goose_digest(&arguments)?;
        let proposal = ToolCallProposal {
            schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
            session_id: "session-1".to_owned(),
            run_id: "session-1".to_owned(),
            tool_call_id: "after-revocation".to_owned(),
            workspace_root: approval.workspace_root,
            extension_id: "developer".to_owned(),
            tool_name: "write".to_owned(),
            arguments_sha256: arguments_sha256.clone(),
            arguments,
            agent_plan_checkpoint: crate::model::test_agent_plan_checkpoint(
                "session-1",
                "session-1",
                "after-revocation",
                "developer__write",
                &arguments_sha256,
                149,
            ),
        };
        assert_eq!(
            fixture
                .runtime
                .ledger()
                .authorize_and_consume(&proposal, None, None, 150, 30)?,
            AuthorizationResult::Denied("SESSION_REVOKED")
        );
        Ok(())
    }

    #[test]
    fn revocation_rejects_unknown_partial_cross_bound_and_ambiguous_payloads()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let task = Uuid::new_v4();
        let approval = fixture.approval("session-1", task);
        let wrong_run = SessionRevocation::new(task, "session-1", "other-run");
        let cross_bound = SessionRevocation::new(Uuid::new_v4(), "session-1", "session-1");
        let unknown = SessionRevocation::new(Uuid::new_v4(), "unknown", "unknown");
        let mut ambiguous = request(Uuid::new_v4(), &approval);
        ambiguous["session_revocation"] =
            serde_json::to_value(SessionRevocation::new(task, "session-1", "session-1"))?;
        let mut input = json_frame(&request(Uuid::new_v4(), &approval));
        input.extend(json_frame(&revocation_request(Uuid::new_v4(), &wrong_run)));
        input.extend(json_frame(&revocation_request(
            Uuid::new_v4(),
            &cross_bound,
        )));
        input.extend(json_frame(&revocation_request(Uuid::new_v4(), &unknown)));
        input.extend(json_frame(&ambiguous));
        let mut output = Vec::new();

        serve_control_channel(&fixture.runtime, Cursor::new(input), &mut output)?;

        let responses = responses(&output);
        assert_eq!(responses[0]["code"], "SESSION_APPROVED");
        assert_eq!(responses[1]["code"], "REVOCATION_BINDING_MISMATCH");
        assert_eq!(responses[2]["code"], "REVOCATION_BINDING_MISMATCH");
        assert_eq!(responses[3]["code"], "UNKNOWN_SESSION");
        assert_eq!(responses[4]["code"], "MALFORMED_REQUEST");
        assert!(responses[1]["revocation_digest"].is_null());
        assert!(responses[1]["task_id"].is_null());
        Ok(())
    }

    #[test]
    fn malformed_request_is_recoverable_but_never_authoritative()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let approval = fixture.approval("session-1", Uuid::new_v4());
        let mut malformed = json_frame(&json!({
            "schema_version": DESKTOP_PROTOCOL_SCHEMA_VERSION,
            "unexpected": true
        }));
        malformed.extend(json_frame(&request(Uuid::new_v4(), &approval)));
        let mut output = Vec::new();

        serve_control_channel(&fixture.runtime, Cursor::new(malformed), &mut output)?;

        let responses = responses(&output);
        assert_eq!(responses[0]["code"], "MALFORMED_REQUEST");
        assert!(responses[0]["request_id"].is_null());
        assert_eq!(responses[1]["code"], "SESSION_APPROVED");
        Ok(())
    }

    #[test]
    fn oversized_frame_is_rejected_before_allocation() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let mut input = Vec::from(CONTROL_FRAME_MAGIC);
        input.extend_from_slice(
            &u32::try_from(MAX_CONTROL_FRAME_BYTES + 1)
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        let mut output = Vec::new();

        let error = match serve_control_channel(&fixture.runtime, Cursor::new(input), &mut output) {
            Err(error) => error,
            Ok(exit) => {
                return Err(format!("oversized frame unexpectedly returned {exit:?}").into());
            }
        };

        assert_eq!(error, ControlChannelError::FrameTooLarge);
        assert_eq!(responses(&output)[0]["code"], "FRAME_TOO_LARGE");
        Ok(())
    }

    #[test]
    fn corrupt_header_and_truncated_body_terminate_deterministically()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let mut bad_header = Vec::from(*b"NOPE");
        bad_header.extend_from_slice(&0_u32.to_be_bytes());
        let mut output = Vec::new();
        let error =
            match serve_control_channel(&fixture.runtime, Cursor::new(bad_header), &mut output) {
                Err(error) => error,
                Ok(exit) => return Err(format!("bad header unexpectedly returned {exit:?}").into()),
            };
        assert_eq!(error, ControlChannelError::InvalidHeader);
        assert_eq!(responses(&output)[0]["code"], "FRAME_HEADER_INVALID");

        let mut truncated = Vec::from(CONTROL_FRAME_MAGIC);
        truncated.extend_from_slice(&4_u32.to_be_bytes());
        truncated.extend_from_slice(b"{}");
        output.clear();
        let error =
            match serve_control_channel(&fixture.runtime, Cursor::new(truncated), &mut output) {
                Err(error) => error,
                Ok(exit) => {
                    return Err(format!("truncated frame unexpectedly returned {exit:?}").into());
                }
            };
        assert_eq!(error, ControlChannelError::TruncatedFrame);
        assert_eq!(responses(&output)[0]["code"], "FRAME_TRUNCATED");
        Ok(())
    }

    #[test]
    fn strict_request_profile_rejects_unknown_method_schema_and_identifier()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let approval = fixture.approval("session-1", Uuid::new_v4());
        let id = Uuid::new_v4();
        let mut wrong_schema = request(id, &approval);
        wrong_schema["schema_version"] = json!(1);
        let mut wrong_method = request(id, &approval);
        wrong_method["method"] = json!("DELETE_SESSION");
        let mut wrong_id = request(id, &approval);
        wrong_id["request_id"] = json!(id.to_string().to_uppercase());
        let mut input = json_frame(&wrong_schema);
        input.extend(json_frame(&wrong_method));
        input.extend(json_frame(&wrong_id));
        let mut output = Vec::new();

        serve_control_channel(&fixture.runtime, Cursor::new(input), &mut output)?;

        let responses = responses(&output);
        assert_eq!(responses[0]["code"], "UNSUPPORTED_SCHEMA");
        assert_eq!(responses[1]["code"], "UNSUPPORTED_METHOD");
        assert_eq!(responses[2]["code"], "INVALID_REQUEST_ID");
        Ok(())
    }
}
