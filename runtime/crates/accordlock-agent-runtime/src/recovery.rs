use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    canonical::domain_digest,
    filesystem::{
        DeleteRecoveryInspection, FilesystemRecoveryError, inspect_deleted_file_recovery,
        restore_deleted_file,
    },
    ledger::{DeletedFileRecoveryEvidence, Ledger, LedgerError},
    model::{DESKTOP_PROTOCOL_SCHEMA_VERSION, parse_digest},
};

/// V2 file-restore challenge digest domain, including its terminating NUL byte.
///
/// The stable digest preimage is exactly this byte string followed immediately
/// by the UTF-8 encoding of the recursively key-sorted, compact JSON challenge.
pub const FILE_RESTORE_CHALLENGE_DIGEST_DOMAIN: &[u8] = b"accordlock:v2:file-restore-challenge\0";

/// V2 file-restore record digest domain, including its terminating NUL byte.
///
/// The stable digest preimage is exactly this byte string followed immediately
/// by the UTF-8 encoding of the recursively key-sorted, compact JSON record.
pub const FILE_RESTORE_RECORD_DIGEST_DOMAIN: &[u8] = b"accordlock:v2:file-restore-record\0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRestorePrepareRequest {
    pub schema_version: u16,
    pub recovery_id: Uuid,
}

impl FileRestorePrepareRequest {
    pub(crate) fn validate(&self) -> Result<(), FileRestoreError> {
        if self.schema_version != DESKTOP_PROTOCOL_SCHEMA_VERSION || self.recovery_id.is_nil() {
            return Err(FileRestoreError::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRestoreCommitRequest {
    pub schema_version: u16,
    pub restore_id: Uuid,
    pub recovery_id: Uuid,
    pub challenge_hash: String,
}

impl FileRestoreCommitRequest {
    pub(crate) fn validate(&self) -> Result<(), FileRestoreError> {
        if self.schema_version != DESKTOP_PROTOCOL_SCHEMA_VERSION
            || self.restore_id.is_nil()
            || self.recovery_id.is_nil()
            || parse_digest(&self.challenge_hash).is_err()
        {
            return Err(FileRestoreError::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRestoreChallenge {
    pub schema_version: u16,
    pub restore_id: Uuid,
    pub recovery_id: Uuid,
    pub task_id: Uuid,
    pub session_id: String,
    pub run_id: String,
    pub original_record_id: Uuid,
    pub original_record_hash: String,
    pub workspace_root: String,
    pub relative_path: String,
    pub content_sha256: String,
    pub original_bytes: u64,
    pub prepared_at: i64,
}

impl FileRestoreChallenge {
    pub(crate) fn digest(&self) -> Result<String, FileRestoreError> {
        file_restore_challenge_digest(self)
    }

    pub(crate) fn validate(&self) -> Result<(), FileRestoreError> {
        if self.schema_version != DESKTOP_PROTOCOL_SCHEMA_VERSION
            || self.restore_id.is_nil()
            || self.recovery_id.is_nil()
            || self.task_id.is_nil()
            || self.original_record_id.is_nil()
            || self.session_id.is_empty()
            || self.run_id.is_empty()
            || self.workspace_root.is_empty()
            || self.relative_path.is_empty()
            || self.prepared_at < 0
            || parse_digest(&self.original_record_hash).is_err()
            || parse_digest(&self.content_sha256).is_err()
        {
            return Err(FileRestoreError::InvalidEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRestoreRecord {
    pub schema_version: u16,
    pub restore_id: Uuid,
    pub recovery_id: Uuid,
    pub challenge_hash: String,
    pub task_id: Uuid,
    pub session_id: String,
    pub run_id: String,
    pub original_record_id: Uuid,
    pub original_record_hash: String,
    pub workspace_root: String,
    pub relative_path: String,
    pub content_sha256: String,
    pub original_bytes: u64,
    pub completed_at: i64,
}

impl FileRestoreRecord {
    pub(crate) fn digest(&self) -> Result<String, FileRestoreError> {
        file_restore_record_digest(self)
    }

    pub(crate) fn validate(&self) -> Result<(), FileRestoreError> {
        if self.schema_version != DESKTOP_PROTOCOL_SCHEMA_VERSION
            || self.restore_id.is_nil()
            || self.recovery_id.is_nil()
            || self.task_id.is_nil()
            || self.original_record_id.is_nil()
            || self.session_id.is_empty()
            || self.run_id.is_empty()
            || self.workspace_root.is_empty()
            || self.relative_path.is_empty()
            || self.completed_at < 0
            || parse_digest(&self.challenge_hash).is_err()
            || parse_digest(&self.original_record_hash).is_err()
            || parse_digest(&self.content_sha256).is_err()
        {
            return Err(FileRestoreError::InvalidEvidence);
        }
        Ok(())
    }
}

/// Computes the stable v2 domain-separated digest of a file-restore challenge.
///
/// # Errors
///
/// Returns [`FileRestoreError::InvalidEvidence`] if the challenge cannot be
/// represented by the canonical JSON profile.
pub fn file_restore_challenge_digest(
    challenge: &FileRestoreChallenge,
) -> Result<String, FileRestoreError> {
    domain_digest(FILE_RESTORE_CHALLENGE_DIGEST_DOMAIN, challenge)
        .map_err(|_| FileRestoreError::InvalidEvidence)
}

/// Computes the stable v2 domain-separated digest of a completed restore record.
///
/// # Errors
///
/// Returns [`FileRestoreError::InvalidEvidence`] if the record cannot be
/// represented by the canonical JSON profile.
pub fn file_restore_record_digest(record: &FileRestoreRecord) -> Result<String, FileRestoreError> {
    domain_digest(FILE_RESTORE_RECORD_DIGEST_DOMAIN, record)
        .map_err(|_| FileRestoreError::InvalidEvidence)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StoredFileRestore {
    Prepared {
        challenge: FileRestoreChallenge,
        challenge_hash: String,
    },
    InFlight {
        challenge: FileRestoreChallenge,
        challenge_hash: String,
    },
    Committed {
        challenge: FileRestoreChallenge,
        challenge_hash: String,
        record: Box<FileRestoreRecord>,
        record_hash: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileRestorePrepareOutcome {
    Prepared {
        challenge: FileRestoreChallenge,
        challenge_hash: String,
        already_prepared: bool,
    },
    AlreadyCommitted {
        record: FileRestoreRecord,
        record_hash: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRestoreCommitOutcome {
    pub record: FileRestoreRecord,
    pub record_hash: String,
    pub already_committed: bool,
}

#[derive(Debug, Error)]
pub enum FileRestoreError {
    #[error("file restore request is invalid")]
    InvalidRequest,
    #[error("file restore evidence is invalid")]
    InvalidEvidence,
    #[error("file restore challenge does not match")]
    ChallengeMismatch,
    #[error("file restore is unknown")]
    UnknownRecovery,
    #[error("file restore state changed")]
    StateStale,
    #[error("file restore path is unsafe")]
    UnsafePath,
    #[error("file restore content failed verification")]
    IntegrityMismatch,
    #[error("file restore storage is unavailable")]
    Unavailable,
    #[error("file restore durable state is corrupt")]
    CorruptState,
}

impl FileRestoreError {
    pub(crate) const fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "INVALID_FILE_RESTORE_REQUEST",
            Self::InvalidEvidence => "INVALID_FILE_RESTORE_EVIDENCE",
            Self::ChallengeMismatch => "FILE_RESTORE_CHALLENGE_MISMATCH",
            Self::UnknownRecovery => "UNKNOWN_FILE_RECOVERY",
            Self::StateStale => "FILE_RESTORE_STATE_STALE",
            Self::UnsafePath => "FILE_RESTORE_UNSAFE_PATH",
            Self::IntegrityMismatch => "FILE_RESTORE_INTEGRITY_MISMATCH",
            Self::Unavailable => "FILE_RESTORE_UNAVAILABLE",
            Self::CorruptState => "FILE_RESTORE_STATE_CORRUPT",
        }
    }
}

impl From<LedgerError> for FileRestoreError {
    fn from(value: LedgerError) -> Self {
        match value {
            LedgerError::UnknownFileRecovery => Self::UnknownRecovery,
            LedgerError::FileRestoreChallengeMismatch => Self::ChallengeMismatch,
            LedgerError::CorruptState => Self::CorruptState,
            LedgerError::Unavailable => Self::Unavailable,
            _ => Self::InvalidEvidence,
        }
    }
}

impl From<FilesystemRecoveryError> for FileRestoreError {
    fn from(value: FilesystemRecoveryError) -> Self {
        match value {
            FilesystemRecoveryError::StateStale => Self::StateStale,
            FilesystemRecoveryError::UnsafePath => Self::UnsafePath,
            FilesystemRecoveryError::IntegrityMismatch => Self::IntegrityMismatch,
            FilesystemRecoveryError::Unavailable => Self::Unavailable,
            FilesystemRecoveryError::InvalidEvidence => Self::InvalidEvidence,
        }
    }
}

fn challenge_matches_evidence(
    challenge: &FileRestoreChallenge,
    evidence: &DeletedFileRecoveryEvidence,
    inspection: &DeleteRecoveryInspection,
) -> bool {
    challenge.schema_version == DESKTOP_PROTOCOL_SCHEMA_VERSION
        && challenge.recovery_id == evidence.authorization_id
        && challenge.task_id == evidence.task_id
        && challenge.session_id == evidence.proposal.session_id
        && challenge.run_id == evidence.proposal.run_id
        && challenge.original_record_id == evidence.record_id
        && challenge.original_record_hash == evidence.record_hash
        && challenge.workspace_root == evidence.proposal.workspace_root
        && challenge.relative_path == inspection.relative_path
        && challenge.content_sha256 == inspection.content_sha256
        && challenge.original_bytes == inspection.original_bytes
}

fn commit_matches_challenge(
    request: &FileRestoreCommitRequest,
    challenge: &FileRestoreChallenge,
    challenge_hash: &str,
) -> bool {
    request.restore_id == challenge.restore_id
        && request.recovery_id == challenge.recovery_id
        && request.challenge_hash == challenge_hash
        && challenge
            .digest()
            .is_ok_and(|value| value == challenge_hash)
}

pub(crate) fn record_matches_challenge(
    record: &FileRestoreRecord,
    challenge: &FileRestoreChallenge,
    challenge_hash: &str,
) -> bool {
    record.schema_version == challenge.schema_version
        && record.restore_id == challenge.restore_id
        && record.recovery_id == challenge.recovery_id
        && record.challenge_hash == challenge_hash
        && record.task_id == challenge.task_id
        && record.session_id == challenge.session_id
        && record.run_id == challenge.run_id
        && record.original_record_id == challenge.original_record_id
        && record.original_record_hash == challenge.original_record_hash
        && record.workspace_root == challenge.workspace_root
        && record.relative_path == challenge.relative_path
        && record.content_sha256 == challenge.content_sha256
        && record.original_bytes == challenge.original_bytes
        && record.completed_at >= challenge.prepared_at
}

pub(crate) fn prepare_file_restore(
    ledger: &Ledger,
    request: &FileRestorePrepareRequest,
    now: i64,
) -> Result<FileRestorePrepareOutcome, FileRestoreError> {
    request.validate()?;
    if now < 0 {
        return Err(FileRestoreError::InvalidRequest);
    }
    let _scope = ledger.begin_recovery_scope()?;
    let evidence = ledger.deleted_file_recovery_evidence(request.recovery_id)?;

    if let Some(stored) = ledger.file_restore(request.recovery_id)? {
        return match stored {
            StoredFileRestore::Committed {
                challenge,
                challenge_hash,
                record,
                record_hash,
            } => {
                let record = *record;
                challenge.validate()?;
                record.validate()?;
                if !commit_matches_challenge(
                    &FileRestoreCommitRequest {
                        schema_version: DESKTOP_PROTOCOL_SCHEMA_VERSION,
                        restore_id: challenge.restore_id,
                        recovery_id: challenge.recovery_id,
                        challenge_hash: challenge_hash.clone(),
                    },
                    &challenge,
                    &challenge_hash,
                ) || !record_matches_challenge(&record, &challenge, &challenge_hash)
                    || record.digest()? != record_hash
                {
                    return Err(FileRestoreError::CorruptState);
                }
                let inspection = inspect_deleted_file_recovery(&evidence)?;
                if !inspection.restored
                    || !challenge_matches_evidence(&challenge, &evidence, &inspection)
                {
                    return Err(FileRestoreError::StateStale);
                }
                Ok(FileRestorePrepareOutcome::AlreadyCommitted {
                    record,
                    record_hash,
                })
            }
            StoredFileRestore::Prepared {
                challenge,
                challenge_hash,
            }
            | StoredFileRestore::InFlight {
                challenge,
                challenge_hash,
            } => {
                challenge.validate()?;
                let inspection = inspect_deleted_file_recovery(&evidence)?;
                if !challenge_matches_evidence(&challenge, &evidence, &inspection)
                    || challenge.digest()? != challenge_hash
                {
                    return Err(FileRestoreError::CorruptState);
                }
                Ok(FileRestorePrepareOutcome::Prepared {
                    challenge,
                    challenge_hash,
                    already_prepared: true,
                })
            }
        };
    }

    let inspection = inspect_deleted_file_recovery(&evidence)?;
    if inspection.restored {
        return Err(FileRestoreError::InvalidEvidence);
    }
    let challenge = FileRestoreChallenge {
        schema_version: DESKTOP_PROTOCOL_SCHEMA_VERSION,
        restore_id: Uuid::new_v4(),
        recovery_id: evidence.authorization_id,
        task_id: evidence.task_id,
        session_id: evidence.proposal.session_id.clone(),
        run_id: evidence.proposal.run_id.clone(),
        original_record_id: evidence.record_id,
        original_record_hash: evidence.record_hash.clone(),
        workspace_root: evidence.proposal.workspace_root.clone(),
        relative_path: inspection.relative_path,
        content_sha256: inspection.content_sha256,
        original_bytes: inspection.original_bytes,
        prepared_at: now,
    };
    challenge.validate()?;
    let challenge_hash = challenge.digest()?;
    ledger.insert_file_restore(&challenge, &challenge_hash, now)?;
    Ok(FileRestorePrepareOutcome::Prepared {
        challenge,
        challenge_hash,
        already_prepared: false,
    })
}

pub(crate) fn commit_file_restore(
    ledger: &Ledger,
    request: &FileRestoreCommitRequest,
    now: i64,
) -> Result<FileRestoreCommitOutcome, FileRestoreError> {
    request.validate()?;
    if now < 0 {
        return Err(FileRestoreError::InvalidRequest);
    }
    let _scope = ledger.begin_recovery_scope()?;
    let evidence = ledger.deleted_file_recovery_evidence(request.recovery_id)?;
    let stored = ledger
        .file_restore(request.recovery_id)?
        .ok_or(FileRestoreError::UnknownRecovery)?;
    let (challenge, challenge_hash, in_flight) = match stored {
        StoredFileRestore::Committed {
            challenge,
            challenge_hash,
            record,
            record_hash,
        } => {
            let record = *record;
            if !commit_matches_challenge(request, &challenge, &challenge_hash) {
                return Err(FileRestoreError::ChallengeMismatch);
            }
            if !record_matches_challenge(&record, &challenge, &challenge_hash)
                || record.digest()? != record_hash
            {
                return Err(FileRestoreError::CorruptState);
            }
            let inspection = inspect_deleted_file_recovery(&evidence)?;
            if !inspection.restored
                || !challenge_matches_evidence(&challenge, &evidence, &inspection)
            {
                return Err(FileRestoreError::StateStale);
            }
            return Ok(FileRestoreCommitOutcome {
                record,
                record_hash,
                already_committed: true,
            });
        }
        StoredFileRestore::Prepared {
            challenge,
            challenge_hash,
        } => (challenge, challenge_hash, false),
        StoredFileRestore::InFlight {
            challenge,
            challenge_hash,
        } => (challenge, challenge_hash, true),
    };
    if !commit_matches_challenge(request, &challenge, &challenge_hash) {
        return Err(FileRestoreError::ChallengeMismatch);
    }

    if !in_flight {
        let before = inspect_deleted_file_recovery(&evidence)?;
        if before.restored || !challenge_matches_evidence(&challenge, &evidence, &before) {
            return Err(FileRestoreError::StateStale);
        }
        ledger.begin_file_restore(request, now)?;
    }

    let inspection = restore_deleted_file(&evidence)?;
    if !inspection.restored || !challenge_matches_evidence(&challenge, &evidence, &inspection) {
        return Err(FileRestoreError::StateStale);
    }
    let record = FileRestoreRecord {
        schema_version: DESKTOP_PROTOCOL_SCHEMA_VERSION,
        restore_id: challenge.restore_id,
        recovery_id: challenge.recovery_id,
        challenge_hash: challenge_hash.clone(),
        task_id: challenge.task_id,
        session_id: challenge.session_id.clone(),
        run_id: challenge.run_id.clone(),
        original_record_id: challenge.original_record_id,
        original_record_hash: challenge.original_record_hash.clone(),
        workspace_root: challenge.workspace_root.clone(),
        relative_path: challenge.relative_path.clone(),
        content_sha256: challenge.content_sha256.clone(),
        original_bytes: challenge.original_bytes,
        completed_at: now,
    };
    record.validate()?;
    let record_hash = record.digest()?;
    ledger.complete_file_restore(&record, &record_hash, now)?;
    Ok(FileRestoreCommitOutcome {
        record,
        record_hash,
        already_committed: false,
    })
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use accordlock_agent_protocol::Digest32;
    use serde_json::json;

    use super::*;
    use crate::{
        ActionApproval, ApprovalDecision, ApprovedSession, Capability, TaskPolicy,
        canonical::goose_digest,
        filesystem::{
            FilesystemExecutionRequest, FilesystemExecutionStatus, FilesystemResult,
            execute_governed,
        },
        model::{DESKTOP_PROTOCOL_SCHEMA_VERSION, TOOL_EXECUTION_SCHEMA_VERSION, ToolCallProposal},
    };

    const NOW: i64 = 1_800_000_000;

    struct DeletedFixture {
        _root: tempfile::TempDir,
        workspace: PathBuf,
        database: PathBuf,
        ledger: Ledger,
        recovery_id: Uuid,
        recovery_path: String,
    }

    fn proposal(
        workspace: &Path,
        tool_call_id: &str,
    ) -> Result<ToolCallProposal, Box<dyn std::error::Error>> {
        let arguments = json!({"path": "notes.txt"});
        let arguments_sha256 = goose_digest(&arguments)?;
        Ok(ToolCallProposal {
            schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
            session_id: "restore-session".to_owned(),
            run_id: "restore-run".to_owned(),
            tool_call_id: tool_call_id.to_owned(),
            workspace_root: workspace.to_string_lossy().into_owned(),
            extension_id: "developer".to_owned(),
            tool_name: "delete_file".to_owned(),
            arguments_sha256: arguments_sha256.clone(),
            arguments,
            agent_plan_checkpoint: crate::model::test_agent_plan_checkpoint(
                "restore-session",
                "restore-run",
                tool_call_id,
                "developer__delete_file",
                &arguments_sha256,
                NOW - 1,
            ),
        })
    }

    fn deleted_fixture() -> Result<DeletedFixture, Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let workspace = root.path().join("workspace");
        std::fs::create_dir(&workspace)?;
        let workspace = std::fs::canonicalize(workspace)?;
        std::fs::write(workspace.join("notes.txt"), b"recover exactly")?;
        let database = root.path().join("runtime.sqlite3");
        let ledger = Ledger::open(&database)?;
        let approved = ApprovedSession::new_with_task_objective(
            Uuid::new_v4(),
            "restore-session",
            "restore-run",
            &workspace,
            1,
            "restore objective",
            TaskPolicy::new(
                Digest32::sha256(b"restore objective"),
                [],
                [".accordlock".to_owned()],
            )?,
            [Capability::new("developer", "delete_file")],
            NOW - 10,
            NOW + 1_000,
        )?;
        ledger.approve_session(&approved)?;
        let request = FilesystemExecutionRequest {
            schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
            proposal: proposal(&workspace, "delete-for-restore")?,
        };
        let approval_needed = execute_governed(&ledger, &request, NOW, 30)?;
        assert_eq!(
            approval_needed.status,
            FilesystemExecutionStatus::ApprovalRequired
        );
        let context = approval_needed
            .approval_request
            .ok_or("missing action approval request")?;
        let action_approval = ActionApproval::for_context(
            &context,
            Uuid::new_v4(),
            ApprovalDecision::Approved,
            Digest32::sha256(b"human approved deletion"),
            NOW - 1,
            NOW + 60,
        )?;
        ledger.register_action_approval(&action_approval)?;
        let deleted = execute_governed(&ledger, &request, NOW, 30)?;
        assert_eq!(deleted.status, FilesystemExecutionStatus::Succeeded);
        let FilesystemResult::Delete {
            recovery_id,
            recovery_path,
            ..
        } = deleted.result.ok_or("missing deletion result")?
        else {
            return Err("unexpected deletion result".into());
        };
        Ok(DeletedFixture {
            _root: root,
            workspace,
            database,
            ledger,
            recovery_id: Uuid::parse_str(&recovery_id)?,
            recovery_path,
        })
    }

    fn prepare(
        fixture: &DeletedFixture,
    ) -> Result<(FileRestoreChallenge, String), Box<dyn std::error::Error>> {
        let outcome = prepare_file_restore(
            &fixture.ledger,
            &FileRestorePrepareRequest {
                schema_version: DESKTOP_PROTOCOL_SCHEMA_VERSION,
                recovery_id: fixture.recovery_id,
            },
            NOW + 1,
        )?;
        let FileRestorePrepareOutcome::Prepared {
            challenge,
            challenge_hash,
            ..
        } = outcome
        else {
            return Err("restore unexpectedly committed".into());
        };
        Ok((challenge, challenge_hash))
    }

    fn commit_request(
        challenge: &FileRestoreChallenge,
        challenge_hash: String,
    ) -> FileRestoreCommitRequest {
        FileRestoreCommitRequest {
            schema_version: DESKTOP_PROTOCOL_SCHEMA_VERSION,
            restore_id: challenge.restore_id,
            recovery_id: challenge.recovery_id,
            challenge_hash,
        }
    }

    fn require_restore_error<T>(
        result: Result<T, FileRestoreError>,
        message: &'static str,
    ) -> Result<FileRestoreError, Box<dyn std::error::Error>> {
        match result {
            Err(error) => Ok(error),
            Ok(_) => Err(std::io::Error::other(message).into()),
        }
    }

    #[test]
    fn v2_restore_hashes_match_the_cross_language_golden_vectors()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(DESKTOP_PROTOCOL_SCHEMA_VERSION, 2);
        assert_eq!(TOOL_EXECUTION_SCHEMA_VERSION, 3);
        let challenge = FileRestoreChallenge {
            schema_version: 2,
            restore_id: Uuid::parse_str("77777777-7777-4777-8777-777777777777")?,
            recovery_id: Uuid::parse_str("88888888-8888-4888-8888-888888888888")?,
            task_id: Uuid::parse_str("12345678-1234-4abc-8def-123456789abc")?,
            session_id: "session-1".to_owned(),
            run_id: "run-1".to_owned(),
            original_record_id: Uuid::parse_str("99999999-9999-4999-8999-999999999999")?,
            original_record_hash:
                "sha256:9999999999999999999999999999999999999999999999999999999999999999".to_owned(),
            workspace_root: "/srv/accordlock/project".to_owned(),
            relative_path: "docs/release.md".to_owned(),
            content_sha256:
                "sha256:8888888888888888888888888888888888888888888888888888888888888888".to_owned(),
            original_bytes: 42,
            prepared_at: 100,
        };
        let challenge_hash = file_restore_challenge_digest(&challenge)?;
        assert_eq!(
            challenge_hash,
            "sha256:40b527525edeff9a72cb2a2dcbe03acf1431c46bc751a9740e517f5c93afb095"
        );

        let record = FileRestoreRecord {
            schema_version: 2,
            restore_id: challenge.restore_id,
            recovery_id: challenge.recovery_id,
            challenge_hash,
            task_id: challenge.task_id,
            session_id: challenge.session_id,
            run_id: challenge.run_id,
            original_record_id: challenge.original_record_id,
            original_record_hash: challenge.original_record_hash,
            workspace_root: challenge.workspace_root,
            relative_path: challenge.relative_path,
            content_sha256: challenge.content_sha256,
            original_bytes: challenge.original_bytes,
            completed_at: 120,
        };
        assert_eq!(
            file_restore_record_digest(&record)?,
            "sha256:27d5f9cbf8b3fe864e66ed7fadc123f141e923a7607c3131d134be53fcf87d06"
        );
        Ok(())
    }

    #[test]
    fn exact_deleted_file_restore_is_durable_and_idempotent()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = deleted_fixture()?;
        let (challenge, challenge_hash) = prepare(&fixture)?;
        assert_eq!(challenge.relative_path, "notes.txt");
        assert_eq!(
            challenge.content_sha256,
            Digest32::sha256(b"recover exactly").to_string()
        );
        let repeated = prepare_file_restore(
            &fixture.ledger,
            &FileRestorePrepareRequest {
                schema_version: DESKTOP_PROTOCOL_SCHEMA_VERSION,
                recovery_id: fixture.recovery_id,
            },
            NOW + 2,
        )?;
        assert!(matches!(
            repeated,
            FileRestorePrepareOutcome::Prepared {
                already_prepared: true,
                ..
            }
        ));

        let request = commit_request(&challenge, challenge_hash);
        let committed = commit_file_restore(&fixture.ledger, &request, NOW + 3)?;
        assert!(!committed.already_committed);
        assert_eq!(
            std::fs::read(fixture.workspace.join("notes.txt"))?,
            b"recover exactly"
        );
        assert!(fixture.workspace.join(&fixture.recovery_path).exists());

        let replay = commit_file_restore(&fixture.ledger, &request, NOW + 4)?;
        assert!(replay.already_committed);
        assert_eq!(replay.record, committed.record);
        assert_eq!(replay.record_hash, committed.record_hash);

        drop(fixture.ledger);
        let reopened = Ledger::open(&fixture.database)?;
        let durable_replay = commit_file_restore(&reopened, &request, NOW + 5)?;
        assert!(durable_replay.already_committed);
        assert_eq!(durable_replay.record_hash, committed.record_hash);
        Ok(())
    }

    #[test]
    fn restore_never_overwrites_a_recreated_target() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = deleted_fixture()?;
        let (challenge, challenge_hash) = prepare(&fixture)?;
        std::fs::write(fixture.workspace.join("notes.txt"), b"newer work")?;

        let error = require_restore_error(
            commit_file_restore(
                &fixture.ledger,
                &commit_request(&challenge, challenge_hash),
                NOW + 2,
            ),
            "recreated target must block restore",
        )?;
        assert!(matches!(error, FileRestoreError::StateStale));
        assert_eq!(
            std::fs::read(fixture.workspace.join("notes.txt"))?,
            b"newer work"
        );
        assert_eq!(
            std::fs::read(fixture.workspace.join(&fixture.recovery_path))?,
            b"recover exactly"
        );
        Ok(())
    }

    #[test]
    fn tampered_recovery_content_fails_integrity_before_prepare()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = deleted_fixture()?;
        std::fs::write(
            fixture.workspace.join(&fixture.recovery_path),
            b"substituted",
        )?;
        let error = require_restore_error(
            prepare_file_restore(
                &fixture.ledger,
                &FileRestorePrepareRequest {
                    schema_version: DESKTOP_PROTOCOL_SCHEMA_VERSION,
                    recovery_id: fixture.recovery_id,
                },
                NOW + 1,
            ),
            "tampered recovery must fail",
        )?;
        assert!(matches!(error, FileRestoreError::IntegrityMismatch));
        assert!(!fixture.workspace.join("notes.txt").exists());
        Ok(())
    }

    #[test]
    fn in_flight_exact_copy_is_reconciled_without_overwrite()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = deleted_fixture()?;
        let (challenge, challenge_hash) = prepare(&fixture)?;
        let request = commit_request(&challenge, challenge_hash);
        fixture.ledger.begin_file_restore(&request, NOW + 2)?;
        std::fs::copy(
            fixture.workspace.join(&fixture.recovery_path),
            fixture.workspace.join("notes.txt"),
        )?;

        let committed = commit_file_restore(&fixture.ledger, &request, NOW + 3)?;
        assert!(!committed.already_committed);
        assert_eq!(
            std::fs::read(fixture.workspace.join("notes.txt"))?,
            b"recover exactly"
        );
        assert!(fixture.workspace.join(&fixture.recovery_path).exists());
        Ok(())
    }

    #[test]
    fn challenge_substitution_is_rejected_without_touching_files()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = deleted_fixture()?;
        let (challenge, _challenge_hash) = prepare(&fixture)?;
        let error = require_restore_error(
            commit_file_restore(
                &fixture.ledger,
                &commit_request(&challenge, Digest32::sha256(b"substitution").to_string()),
                NOW + 2,
            ),
            "substituted challenge must fail",
        )?;
        assert!(matches!(error, FileRestoreError::ChallengeMismatch));
        assert!(!fixture.workspace.join("notes.txt").exists());
        assert!(fixture.workspace.join(&fixture.recovery_path).exists());
        Ok(())
    }

    #[test]
    fn recovery_changed_after_prepare_is_refused_before_restore()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = deleted_fixture()?;
        let (challenge, challenge_hash) = prepare(&fixture)?;
        std::fs::write(
            fixture.workspace.join(&fixture.recovery_path),
            b"changed after review",
        )?;

        let error = require_restore_error(
            commit_file_restore(
                &fixture.ledger,
                &commit_request(&challenge, challenge_hash),
                NOW + 2,
            ),
            "changed recovery content must fail",
        )?;
        assert!(matches!(error, FileRestoreError::IntegrityMismatch));
        assert!(!fixture.workspace.join("notes.txt").exists());
        Ok(())
    }

    #[test]
    fn committed_replay_rechecks_the_live_target() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = deleted_fixture()?;
        let (challenge, challenge_hash) = prepare(&fixture)?;
        let request = commit_request(&challenge, challenge_hash);
        commit_file_restore(&fixture.ledger, &request, NOW + 2)?;
        std::fs::write(fixture.workspace.join("notes.txt"), b"changed later")?;

        let error = require_restore_error(
            commit_file_restore(&fixture.ledger, &request, NOW + 3),
            "durable success must not mask a changed live target",
        )?;
        assert!(matches!(error, FileRestoreError::StateStale));
        assert_eq!(
            std::fs::read(fixture.workspace.join("notes.txt"))?,
            b"changed later"
        );
        Ok(())
    }
}
