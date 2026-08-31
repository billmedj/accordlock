use std::{
    fmt,
    path::Path,
    sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::Duration,
};

use accordlock_agent_protocol::{
    AUTHORIZATION_DECISION_SCHEMA_VERSION, AuthorizationDecision, AuthorizationOutcome,
    EXECUTION_AUTHORIZATION_SCHEMA_VERSION, EXECUTION_RECORD_SCHEMA_VERSION,
    EXECUTION_REQUEST_SCHEMA_VERSION, ExecutionAuthorization, ExecutionOutcome, ExecutionRecord,
    ExecutionRequest, MAX_EXECUTION_DURATION_SECONDS,
};
use rusqlite::{
    Connection, ErrorCode, OpenFlags, OptionalExtension as _, Transaction, TransactionBehavior,
    params,
};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    canonical::{digest_bytes, goose_digest},
    execution_trace::CompletedExecutionEvidence,
    live_intent::PreExecutionLiveIntentBundle,
    model::{
        ApprovedSession, SessionRevocation, SessionRevocationError, TaskBindingError,
        ToolCallProposal, ToolExecutionObservation, WireExecutionOutcome, WireValidationError,
        parse_digest,
    },
    policy::{
        ActionApproval, ActionApprovalRequest, ActionDescriptor, ApprovalDecision,
        AuthorizationDenial, AutomaticActionEvaluation, AutomaticEvaluationInput,
        AutomaticExecutionClass, TaskPolicyError,
    },
    recovery::{
        FileRestoreChallenge, FileRestoreRecord, StoredFileRestore, record_matches_challenge,
    },
};

const SCHEMA_VERSION: i64 = 12;
const DATABASE_BUSY_TIMEOUT: Duration = Duration::from_secs(2);

const SCHEMA: &str = r"
BEGIN IMMEDIATE;
CREATE TABLE approved_sessions (
    session_id TEXT PRIMARY KEY NOT NULL,
    task_id TEXT NOT NULL UNIQUE,
    run_id TEXT NOT NULL,
    workspace_root TEXT NOT NULL,
    policy_epoch INTEGER NOT NULL CHECK (policy_epoch > 0),
    task_policy_hash TEXT NOT NULL,
    approved_at INTEGER NOT NULL CHECK (approved_at >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at > approved_at),
    approval_json TEXT NOT NULL
) STRICT;

CREATE TABLE approved_capabilities (
    session_id TEXT NOT NULL REFERENCES approved_sessions(session_id) ON DELETE RESTRICT,
    extension_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    PRIMARY KEY (session_id, extension_id, tool_name)
) STRICT;

CREATE TABLE revoked_sessions (
    session_id TEXT PRIMARY KEY NOT NULL
        REFERENCES approved_sessions(session_id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL UNIQUE,
    run_id TEXT NOT NULL,
    revocation_digest TEXT NOT NULL UNIQUE,
    revocation_json TEXT NOT NULL,
    revoked_at INTEGER NOT NULL CHECK (revoked_at >= 0)
) STRICT;

CREATE TABLE attempts (
    proposal_digest TEXT PRIMARY KEY NOT NULL,
    session_id TEXT NOT NULL REFERENCES approved_sessions(session_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL,
    tool_call_id TEXT NOT NULL,
    proposal_json TEXT NOT NULL,
    request_hash TEXT NOT NULL UNIQUE,
    request_json TEXT NOT NULL,
    authorization_decision_hash TEXT NOT NULL UNIQUE,
    decision_json TEXT NOT NULL,
    authorization_id TEXT NOT NULL UNIQUE,
    authorization_hash TEXT NOT NULL UNIQUE,
    authorization_json TEXT NOT NULL,
    consumed_at INTEGER NOT NULL CHECK (consumed_at >= 0),
    state TEXT NOT NULL CHECK (state IN ('IN_FLIGHT', 'SUCCEEDED', 'EXECUTION_UNKNOWN')),
    outcome TEXT,
    completed_at INTEGER,
    observation_digest TEXT UNIQUE,
    observation_json TEXT,
    record_id TEXT UNIQUE,
    record_hash TEXT UNIQUE,
    record_json TEXT,
    UNIQUE (session_id, run_id, tool_call_id)
) STRICT;

CREATE TABLE denied_proposals (
    denial_id INTEGER PRIMARY KEY,
    proposal_digest TEXT NOT NULL,
    session_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    tool_call_id TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    recorded_at INTEGER NOT NULL CHECK (recorded_at >= 0)
) STRICT;

CREATE INDEX denied_proposals_session_idx
    ON denied_proposals(session_id, recorded_at);

CREATE TABLE action_approvals (
    approval_id TEXT PRIMARY KEY NOT NULL,
    session_id TEXT NOT NULL REFERENCES approved_sessions(session_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL,
    tool_call_id TEXT NOT NULL,
    proposal_digest TEXT NOT NULL UNIQUE,
    task_policy_hash TEXT NOT NULL,
    prestate_hash TEXT NOT NULL,
    approval_request_hash TEXT NOT NULL UNIQUE,
    policy_decision_hash TEXT NOT NULL UNIQUE,
    decision TEXT NOT NULL CHECK (decision IN ('APPROVED', 'DENIED')),
    approval_evidence_hash TEXT NOT NULL,
    decided_at INTEGER NOT NULL CHECK (decided_at >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at > decided_at),
    consumed_at INTEGER,
    approval_json TEXT NOT NULL,
    UNIQUE (session_id, run_id, tool_call_id)
) STRICT;

CREATE TABLE file_restores (
    recovery_id TEXT PRIMARY KEY NOT NULL
        REFERENCES attempts(authorization_id) ON DELETE RESTRICT,
    restore_id TEXT NOT NULL UNIQUE,
    challenge_hash TEXT NOT NULL UNIQUE,
    challenge_json TEXT NOT NULL,
    prepared_at INTEGER NOT NULL CHECK (prepared_at >= 0),
    state TEXT NOT NULL CHECK (state IN ('PREPARED', 'IN_FLIGHT', 'SUCCEEDED')),
    completed_at INTEGER,
    record_hash TEXT UNIQUE,
    record_json TEXT,
    CHECK (
        (state IN ('PREPARED', 'IN_FLIGHT') AND completed_at IS NULL AND record_hash IS NULL AND record_json IS NULL)
        OR
        (state = 'SUCCEEDED' AND completed_at IS NOT NULL AND record_hash IS NOT NULL AND record_json IS NOT NULL)
    )
) STRICT;

CREATE TABLE runtime_meta (
    key TEXT PRIMARY KEY NOT NULL,
    integer_value INTEGER NOT NULL
) STRICT;

INSERT INTO runtime_meta(key, integer_value) VALUES ('clock_high_water', 0);
PRAGMA user_version = 7;
COMMIT;
";

const UPGRADE_V5_TO_V6: &str = r"
BEGIN IMMEDIATE;
CREATE TABLE file_restores (
    recovery_id TEXT PRIMARY KEY NOT NULL
        REFERENCES attempts(authorization_id) ON DELETE RESTRICT,
    restore_id TEXT NOT NULL UNIQUE,
    challenge_hash TEXT NOT NULL UNIQUE,
    challenge_json TEXT NOT NULL,
    prepared_at INTEGER NOT NULL CHECK (prepared_at >= 0),
    state TEXT NOT NULL CHECK (state IN ('PREPARED', 'IN_FLIGHT', 'SUCCEEDED')),
    completed_at INTEGER,
    record_hash TEXT UNIQUE,
    record_json TEXT,
    CHECK (
        (state IN ('PREPARED', 'IN_FLIGHT') AND completed_at IS NULL AND record_hash IS NULL AND record_json IS NULL)
        OR
        (state = 'SUCCEEDED' AND completed_at IS NOT NULL AND record_hash IS NOT NULL AND record_json IS NOT NULL)
    )
) STRICT;
PRAGMA user_version = 6;
COMMIT;
";

const UPGRADE_V6_TO_V7: &str = r"
BEGIN IMMEDIATE;
ALTER TABLE revoked_sessions
    ADD COLUMN revoked_at INTEGER NOT NULL DEFAULT 0 CHECK (revoked_at >= 0);
PRAGMA user_version = 7;
COMMIT;
";

const UPGRADE_V7_TO_V8: &str = r"
BEGIN IMMEDIATE;
INSERT INTO runtime_meta(key, integer_value) VALUES ('audit_revision', 1);

CREATE TRIGGER audit_revision_approved_sessions_insert
AFTER INSERT ON approved_sessions BEGIN
    UPDATE runtime_meta SET integer_value = integer_value + 1
        WHERE key = 'audit_revision' AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1 THEN RAISE(ABORT, 'audit revision is unavailable') END;
END;
CREATE TRIGGER audit_revision_approved_sessions_update
AFTER UPDATE ON approved_sessions BEGIN
    UPDATE runtime_meta SET integer_value = integer_value + 1
        WHERE key = 'audit_revision' AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1 THEN RAISE(ABORT, 'audit revision is unavailable') END;
END;
CREATE TRIGGER audit_revision_approved_sessions_delete
AFTER DELETE ON approved_sessions BEGIN
    UPDATE runtime_meta SET integer_value = integer_value + 1
        WHERE key = 'audit_revision' AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1 THEN RAISE(ABORT, 'audit revision is unavailable') END;
END;

CREATE TRIGGER audit_revision_approved_capabilities_insert
AFTER INSERT ON approved_capabilities BEGIN
    UPDATE runtime_meta SET integer_value = integer_value + 1
        WHERE key = 'audit_revision' AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1 THEN RAISE(ABORT, 'audit revision is unavailable') END;
END;
CREATE TRIGGER audit_revision_approved_capabilities_update
AFTER UPDATE ON approved_capabilities BEGIN
    UPDATE runtime_meta SET integer_value = integer_value + 1
        WHERE key = 'audit_revision' AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1 THEN RAISE(ABORT, 'audit revision is unavailable') END;
END;
CREATE TRIGGER audit_revision_approved_capabilities_delete
AFTER DELETE ON approved_capabilities BEGIN
    UPDATE runtime_meta SET integer_value = integer_value + 1
        WHERE key = 'audit_revision' AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1 THEN RAISE(ABORT, 'audit revision is unavailable') END;
END;

CREATE TRIGGER audit_revision_revoked_sessions_insert
AFTER INSERT ON revoked_sessions BEGIN
    UPDATE runtime_meta SET integer_value = integer_value + 1
        WHERE key = 'audit_revision' AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1 THEN RAISE(ABORT, 'audit revision is unavailable') END;
END;
CREATE TRIGGER audit_revision_revoked_sessions_update
AFTER UPDATE ON revoked_sessions BEGIN
    UPDATE runtime_meta SET integer_value = integer_value + 1
        WHERE key = 'audit_revision' AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1 THEN RAISE(ABORT, 'audit revision is unavailable') END;
END;
CREATE TRIGGER audit_revision_revoked_sessions_delete
AFTER DELETE ON revoked_sessions BEGIN
    UPDATE runtime_meta SET integer_value = integer_value + 1
        WHERE key = 'audit_revision' AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1 THEN RAISE(ABORT, 'audit revision is unavailable') END;
END;

CREATE TRIGGER audit_revision_attempts_insert
AFTER INSERT ON attempts BEGIN
    UPDATE runtime_meta SET integer_value = integer_value + 1
        WHERE key = 'audit_revision' AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1 THEN RAISE(ABORT, 'audit revision is unavailable') END;
END;
CREATE TRIGGER audit_revision_attempts_update
AFTER UPDATE ON attempts BEGIN
    UPDATE runtime_meta SET integer_value = integer_value + 1
        WHERE key = 'audit_revision' AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1 THEN RAISE(ABORT, 'audit revision is unavailable') END;
END;
CREATE TRIGGER audit_revision_attempts_delete
AFTER DELETE ON attempts BEGIN
    UPDATE runtime_meta SET integer_value = integer_value + 1
        WHERE key = 'audit_revision' AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1 THEN RAISE(ABORT, 'audit revision is unavailable') END;
END;

CREATE TRIGGER audit_revision_denied_proposals_insert
AFTER INSERT ON denied_proposals BEGIN
    UPDATE runtime_meta SET integer_value = integer_value + 1
        WHERE key = 'audit_revision' AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1 THEN RAISE(ABORT, 'audit revision is unavailable') END;
END;
CREATE TRIGGER audit_revision_denied_proposals_update
AFTER UPDATE ON denied_proposals BEGIN
    UPDATE runtime_meta SET integer_value = integer_value + 1
        WHERE key = 'audit_revision' AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1 THEN RAISE(ABORT, 'audit revision is unavailable') END;
END;
CREATE TRIGGER audit_revision_denied_proposals_delete
AFTER DELETE ON denied_proposals BEGIN
    UPDATE runtime_meta SET integer_value = integer_value + 1
        WHERE key = 'audit_revision' AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1 THEN RAISE(ABORT, 'audit revision is unavailable') END;
END;

CREATE TRIGGER audit_revision_action_approvals_insert
AFTER INSERT ON action_approvals BEGIN
    UPDATE runtime_meta SET integer_value = integer_value + 1
        WHERE key = 'audit_revision' AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1 THEN RAISE(ABORT, 'audit revision is unavailable') END;
END;
CREATE TRIGGER audit_revision_action_approvals_update
AFTER UPDATE ON action_approvals BEGIN
    UPDATE runtime_meta SET integer_value = integer_value + 1
        WHERE key = 'audit_revision' AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1 THEN RAISE(ABORT, 'audit revision is unavailable') END;
END;
CREATE TRIGGER audit_revision_action_approvals_delete
AFTER DELETE ON action_approvals BEGIN
    UPDATE runtime_meta SET integer_value = integer_value + 1
        WHERE key = 'audit_revision' AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1 THEN RAISE(ABORT, 'audit revision is unavailable') END;
END;

CREATE TRIGGER audit_revision_file_restores_insert
AFTER INSERT ON file_restores BEGIN
    UPDATE runtime_meta SET integer_value = integer_value + 1
        WHERE key = 'audit_revision' AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1 THEN RAISE(ABORT, 'audit revision is unavailable') END;
END;
CREATE TRIGGER audit_revision_file_restores_update
AFTER UPDATE ON file_restores BEGIN
    UPDATE runtime_meta SET integer_value = integer_value + 1
        WHERE key = 'audit_revision' AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1 THEN RAISE(ABORT, 'audit revision is unavailable') END;
END;
CREATE TRIGGER audit_revision_file_restores_delete
AFTER DELETE ON file_restores BEGIN
    UPDATE runtime_meta SET integer_value = integer_value + 1
        WHERE key = 'audit_revision' AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1 THEN RAISE(ABORT, 'audit revision is unavailable') END;
END;

CREATE INDEX action_approvals_audit_idx
    ON action_approvals(session_id, decided_at DESC, approval_id DESC);
CREATE INDEX attempts_started_audit_idx
    ON attempts(session_id, consumed_at DESC, authorization_id DESC);
CREATE INDEX attempts_completed_audit_idx
    ON attempts(session_id, completed_at DESC, authorization_id DESC)
    WHERE completed_at IS NOT NULL;
CREATE INDEX file_restores_audit_idx
    ON file_restores(prepared_at DESC, restore_id DESC);

PRAGMA user_version = 8;
COMMIT;
";

const UPGRADE_V8_TO_V9: &str = r"
BEGIN IMMEDIATE;
DROP TRIGGER IF EXISTS audit_revision_approved_sessions_insert;
DROP TRIGGER IF EXISTS audit_revision_approved_sessions_update;
DROP TRIGGER IF EXISTS audit_revision_approved_sessions_delete;
DROP TRIGGER IF EXISTS audit_revision_approved_capabilities_insert;
DROP TRIGGER IF EXISTS audit_revision_approved_capabilities_update;
DROP TRIGGER IF EXISTS audit_revision_approved_capabilities_delete;
DROP TRIGGER IF EXISTS audit_revision_revoked_sessions_insert;
DROP TRIGGER IF EXISTS audit_revision_revoked_sessions_update;
DROP TRIGGER IF EXISTS audit_revision_revoked_sessions_delete;
DROP TRIGGER IF EXISTS audit_revision_attempts_insert;
DROP TRIGGER IF EXISTS audit_revision_attempts_update;
DROP TRIGGER IF EXISTS audit_revision_attempts_delete;
DROP TRIGGER IF EXISTS audit_revision_denied_proposals_insert;
DROP TRIGGER IF EXISTS audit_revision_denied_proposals_update;
DROP TRIGGER IF EXISTS audit_revision_denied_proposals_delete;
DROP TRIGGER IF EXISTS audit_revision_action_approvals_insert;
DROP TRIGGER IF EXISTS audit_revision_action_approvals_update;
DROP TRIGGER IF EXISTS audit_revision_action_approvals_delete;
DROP TRIGGER IF EXISTS audit_revision_file_restores_insert;
DROP TRIGGER IF EXISTS audit_revision_file_restores_update;
DROP TRIGGER IF EXISTS audit_revision_file_restores_delete;

CREATE TABLE audit_session_revisions (
    session_id TEXT PRIMARY KEY NOT NULL,
    integer_value INTEGER NOT NULL
        CHECK (integer_value BETWEEN 1 AND 9007199254740991)
) STRICT;
INSERT INTO audit_session_revisions(session_id, integer_value)
    SELECT session_id, 1 FROM approved_sessions;

CREATE TRIGGER session_audit_revision_approved_sessions_insert
AFTER INSERT ON approved_sessions BEGIN
    SELECT CASE WHEN COALESCE((
        SELECT integer_value FROM audit_session_revisions WHERE session_id = NEW.session_id
    ), 0) >= 9007199254740991
        THEN RAISE(ABORT, 'session audit revision is unavailable') END;
    INSERT INTO audit_session_revisions(session_id, integer_value)
        VALUES (NEW.session_id, 1)
        ON CONFLICT(session_id) DO UPDATE SET integer_value = integer_value + 1;
END;
CREATE TRIGGER session_audit_revision_approved_sessions_update
AFTER UPDATE ON approved_sessions BEGIN
    UPDATE audit_session_revisions SET integer_value = integer_value + 1
        WHERE session_id = OLD.session_id AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1
        THEN RAISE(ABORT, 'session audit revision is unavailable') END;
    SELECT CASE WHEN NEW.session_id != OLD.session_id AND COALESCE((
        SELECT integer_value FROM audit_session_revisions WHERE session_id = NEW.session_id
    ), 0) >= 9007199254740991
        THEN RAISE(ABORT, 'session audit revision is unavailable') END;
    INSERT INTO audit_session_revisions(session_id, integer_value)
        SELECT NEW.session_id, 1 WHERE NEW.session_id != OLD.session_id
        ON CONFLICT(session_id) DO UPDATE SET integer_value = integer_value + 1;
END;
CREATE TRIGGER session_audit_revision_approved_sessions_delete
AFTER DELETE ON approved_sessions BEGIN
    UPDATE audit_session_revisions SET integer_value = integer_value + 1
        WHERE session_id = OLD.session_id AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1
        THEN RAISE(ABORT, 'session audit revision is unavailable') END;
END;

CREATE TRIGGER session_audit_revision_approved_capabilities_insert
AFTER INSERT ON approved_capabilities BEGIN
    UPDATE audit_session_revisions SET integer_value = integer_value + 1
        WHERE session_id = NEW.session_id AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1
        THEN RAISE(ABORT, 'session audit revision is unavailable') END;
END;
CREATE TRIGGER session_audit_revision_approved_capabilities_update
AFTER UPDATE ON approved_capabilities BEGIN
    UPDATE audit_session_revisions SET integer_value = integer_value + 1
        WHERE session_id = OLD.session_id AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1
        THEN RAISE(ABORT, 'session audit revision is unavailable') END;
    UPDATE audit_session_revisions SET integer_value = integer_value + 1
        WHERE NEW.session_id != OLD.session_id AND session_id = NEW.session_id
          AND integer_value < 9007199254740991;
    SELECT CASE WHEN NEW.session_id != OLD.session_id AND changes() != 1
        THEN RAISE(ABORT, 'session audit revision is unavailable') END;
END;
CREATE TRIGGER session_audit_revision_approved_capabilities_delete
AFTER DELETE ON approved_capabilities BEGIN
    UPDATE audit_session_revisions SET integer_value = integer_value + 1
        WHERE session_id = OLD.session_id AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1
        THEN RAISE(ABORT, 'session audit revision is unavailable') END;
END;

CREATE TRIGGER session_audit_revision_revoked_sessions_insert
AFTER INSERT ON revoked_sessions BEGIN
    UPDATE audit_session_revisions SET integer_value = integer_value + 1
        WHERE session_id = NEW.session_id AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1
        THEN RAISE(ABORT, 'session audit revision is unavailable') END;
END;
CREATE TRIGGER session_audit_revision_revoked_sessions_update
AFTER UPDATE ON revoked_sessions BEGIN
    UPDATE audit_session_revisions SET integer_value = integer_value + 1
        WHERE session_id = OLD.session_id AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1
        THEN RAISE(ABORT, 'session audit revision is unavailable') END;
    UPDATE audit_session_revisions SET integer_value = integer_value + 1
        WHERE NEW.session_id != OLD.session_id AND session_id = NEW.session_id
          AND integer_value < 9007199254740991;
    SELECT CASE WHEN NEW.session_id != OLD.session_id AND changes() != 1
        THEN RAISE(ABORT, 'session audit revision is unavailable') END;
END;
CREATE TRIGGER session_audit_revision_revoked_sessions_delete
AFTER DELETE ON revoked_sessions BEGIN
    UPDATE audit_session_revisions SET integer_value = integer_value + 1
        WHERE session_id = OLD.session_id AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1
        THEN RAISE(ABORT, 'session audit revision is unavailable') END;
END;

CREATE TRIGGER session_audit_revision_attempts_insert
AFTER INSERT ON attempts BEGIN
    UPDATE audit_session_revisions SET integer_value = integer_value + 1
        WHERE session_id = NEW.session_id AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1
        THEN RAISE(ABORT, 'session audit revision is unavailable') END;
END;
CREATE TRIGGER session_audit_revision_attempts_update
AFTER UPDATE ON attempts BEGIN
    UPDATE audit_session_revisions SET integer_value = integer_value + 1
        WHERE session_id = OLD.session_id AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1
        THEN RAISE(ABORT, 'session audit revision is unavailable') END;
    UPDATE audit_session_revisions SET integer_value = integer_value + 1
        WHERE NEW.session_id != OLD.session_id AND session_id = NEW.session_id
          AND integer_value < 9007199254740991;
    SELECT CASE WHEN NEW.session_id != OLD.session_id AND changes() != 1
        THEN RAISE(ABORT, 'session audit revision is unavailable') END;
END;
CREATE TRIGGER session_audit_revision_attempts_delete
AFTER DELETE ON attempts BEGIN
    UPDATE audit_session_revisions SET integer_value = integer_value + 1
        WHERE session_id = OLD.session_id AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1
        THEN RAISE(ABORT, 'session audit revision is unavailable') END;
END;

CREATE TRIGGER session_audit_revision_denied_proposals_insert
AFTER INSERT ON denied_proposals BEGIN
    UPDATE audit_session_revisions SET integer_value = integer_value + 1
        WHERE session_id = NEW.session_id AND integer_value < 9007199254740991;
    SELECT CASE WHEN EXISTS(
        SELECT 1 FROM audit_session_revisions WHERE session_id = NEW.session_id
    ) AND changes() != 1
        THEN RAISE(ABORT, 'session audit revision is unavailable') END;
END;
CREATE TRIGGER session_audit_revision_denied_proposals_update
AFTER UPDATE ON denied_proposals BEGIN
    UPDATE audit_session_revisions SET integer_value = integer_value + 1
        WHERE session_id = OLD.session_id AND integer_value < 9007199254740991;
    SELECT CASE WHEN EXISTS(
        SELECT 1 FROM audit_session_revisions WHERE session_id = OLD.session_id
    ) AND changes() != 1
        THEN RAISE(ABORT, 'session audit revision is unavailable') END;
    UPDATE audit_session_revisions SET integer_value = integer_value + 1
        WHERE NEW.session_id != OLD.session_id AND session_id = NEW.session_id
          AND integer_value < 9007199254740991;
    SELECT CASE WHEN NEW.session_id != OLD.session_id AND EXISTS(
        SELECT 1 FROM audit_session_revisions WHERE session_id = NEW.session_id
    ) AND changes() != 1
        THEN RAISE(ABORT, 'session audit revision is unavailable') END;
END;
CREATE TRIGGER session_audit_revision_denied_proposals_delete
AFTER DELETE ON denied_proposals BEGIN
    UPDATE audit_session_revisions SET integer_value = integer_value + 1
        WHERE session_id = OLD.session_id AND integer_value < 9007199254740991;
    SELECT CASE WHEN EXISTS(
        SELECT 1 FROM audit_session_revisions WHERE session_id = OLD.session_id
    ) AND changes() != 1
        THEN RAISE(ABORT, 'session audit revision is unavailable') END;
END;

CREATE TRIGGER session_audit_revision_action_approvals_insert
AFTER INSERT ON action_approvals BEGIN
    UPDATE audit_session_revisions SET integer_value = integer_value + 1
        WHERE session_id = NEW.session_id AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1
        THEN RAISE(ABORT, 'session audit revision is unavailable') END;
END;
CREATE TRIGGER session_audit_revision_action_approvals_update
AFTER UPDATE ON action_approvals BEGIN
    UPDATE audit_session_revisions SET integer_value = integer_value + 1
        WHERE session_id = OLD.session_id AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1
        THEN RAISE(ABORT, 'session audit revision is unavailable') END;
    UPDATE audit_session_revisions SET integer_value = integer_value + 1
        WHERE NEW.session_id != OLD.session_id AND session_id = NEW.session_id
          AND integer_value < 9007199254740991;
    SELECT CASE WHEN NEW.session_id != OLD.session_id AND changes() != 1
        THEN RAISE(ABORT, 'session audit revision is unavailable') END;
END;
CREATE TRIGGER session_audit_revision_action_approvals_delete
AFTER DELETE ON action_approvals BEGIN
    UPDATE audit_session_revisions SET integer_value = integer_value + 1
        WHERE session_id = OLD.session_id AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1
        THEN RAISE(ABORT, 'session audit revision is unavailable') END;
END;

CREATE TRIGGER session_audit_revision_file_restores_insert
AFTER INSERT ON file_restores BEGIN
    UPDATE audit_session_revisions SET integer_value = integer_value + 1
        WHERE session_id = (
            SELECT session_id FROM attempts WHERE authorization_id = NEW.recovery_id
        ) AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1
        THEN RAISE(ABORT, 'session audit revision is unavailable') END;
END;
CREATE TRIGGER session_audit_revision_file_restores_update
AFTER UPDATE ON file_restores BEGIN
    UPDATE audit_session_revisions SET integer_value = integer_value + 1
        WHERE session_id = (
            SELECT session_id FROM attempts WHERE authorization_id = OLD.recovery_id
        ) AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1
        THEN RAISE(ABORT, 'session audit revision is unavailable') END;
    UPDATE audit_session_revisions SET integer_value = integer_value + 1
        WHERE NEW.recovery_id != OLD.recovery_id AND session_id = (
            SELECT session_id FROM attempts WHERE authorization_id = NEW.recovery_id
        ) AND session_id != (
            SELECT session_id FROM attempts WHERE authorization_id = OLD.recovery_id
        ) AND integer_value < 9007199254740991;
    SELECT CASE WHEN NEW.recovery_id != OLD.recovery_id AND (
        SELECT session_id FROM attempts WHERE authorization_id = NEW.recovery_id
    ) != (
        SELECT session_id FROM attempts WHERE authorization_id = OLD.recovery_id
    ) AND changes() != 1
        THEN RAISE(ABORT, 'session audit revision is unavailable') END;
END;
CREATE TRIGGER session_audit_revision_file_restores_delete
AFTER DELETE ON file_restores BEGIN
    UPDATE audit_session_revisions SET integer_value = integer_value + 1
        WHERE session_id = (
            SELECT session_id FROM attempts WHERE authorization_id = OLD.recovery_id
        ) AND integer_value < 9007199254740991;
    SELECT CASE WHEN changes() != 1
        THEN RAISE(ABORT, 'session audit revision is unavailable') END;
END;

PRAGMA user_version = 9;
COMMIT;
";

const UPGRADE_V9_TO_V10: &str = r"
BEGIN IMMEDIATE;
ALTER TABLE attempts ADD COLUMN automatic_evaluation_json TEXT;
PRAGMA user_version = 10;
COMMIT;
";

const UPGRADE_V10_TO_V11: &str = r"
BEGIN IMMEDIATE;
ALTER TABLE attempts ADD COLUMN execution_trace_hash TEXT;
ALTER TABLE attempts ADD COLUMN execution_trace_json TEXT;
PRAGMA user_version = 11;
COMMIT;
";

const UPGRADE_V11_TO_V12: &str = r"
BEGIN IMMEDIATE;
ALTER TABLE attempts ADD COLUMN intent_pre_evaluation_hash TEXT;
ALTER TABLE attempts ADD COLUMN intent_pre_evaluation_json TEXT;
ALTER TABLE attempts ADD COLUMN intent_complete_evaluation_hash TEXT;
ALTER TABLE attempts ADD COLUMN intent_complete_evaluation_json TEXT;
PRAGMA user_version = 12;
COMMIT;
";

const SCHEMA_UPGRADES: &[(i64, &str)] = &[
    (5, UPGRADE_V5_TO_V6),
    (6, UPGRADE_V6_TO_V7),
    (7, UPGRADE_V7_TO_V8),
    (8, UPGRADE_V8_TO_V9),
    (9, UPGRADE_V9_TO_V10),
    (10, UPGRADE_V10_TO_V11),
    (11, UPGRADE_V11_TO_V12),
];

/// Durable `SQLite` ledger. A single connection is serialized because every
/// authority transition is short and uses `BEGIN IMMEDIATE`.
#[derive(Clone)]
pub struct Ledger {
    connection: Arc<Mutex<Connection>>,
    execution_barrier: Arc<RwLock<()>>,
}

impl fmt::Debug for Ledger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Ledger(SQLite, [REDACTED])")
    }
}

fn configure_ledger_connection(connection: &Connection) -> Result<i64, LedgerError> {
    connection
        .busy_timeout(DATABASE_BUSY_TIMEOUT)
        .map_err(|_| LedgerError::Unavailable)?;
    connection
        .execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA trusted_schema = OFF;
             PRAGMA secure_delete = ON;",
        )
        .map_err(|_| LedgerError::Unavailable)?;
    connection
        .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
        .map_err(|_| LedgerError::Unavailable)
}

fn migrate_ledger_schema(connection: &Connection, version: i64) -> Result<(), LedgerError> {
    let starting_version = match version {
        0 => {
            connection
                .execute_batch(SCHEMA)
                .map_err(|_| LedgerError::Unavailable)?;
            7
        }
        1..=4 => return Err(LedgerError::PreReleaseStateResetRequired),
        5..=SCHEMA_VERSION => version,
        _ => return Err(LedgerError::IncompatibleSchema),
    };
    for &(from_version, statements) in SCHEMA_UPGRADES {
        if from_version >= starting_version {
            connection
                .execute_batch(statements)
                .map_err(|_| LedgerError::Unavailable)?;
        }
    }
    Ok(())
}

impl Ledger {
    /// Opens or creates the durable ledger with WAL and full synchronization.
    ///
    /// # Errors
    ///
    /// Refuses empty paths, incompatible schemas, or unavailable `SQLite`.
    pub fn open(path: &Path) -> Result<Self, LedgerError> {
        if path.as_os_str().is_empty() {
            return Err(LedgerError::InvalidPath);
        }
        let connection = Connection::open(path).map_err(|_| LedgerError::Unavailable)?;
        let version = configure_ledger_connection(&connection)?;
        migrate_ledger_schema(&connection, version)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            execution_barrier: Arc::new(RwLock::new(())),
        })
    }

    /// Opens an existing ledger for bounded historical audit reads only.
    ///
    /// This path never creates or migrates a database. `SQLite` is opened with a
    /// read-only file descriptor and `query_only` is enabled before the schema
    /// version is inspected. Historical readers therefore cannot restore old
    /// execution authority or mutate audit state, even if their caller sends a
    /// write-shaped request by mistake.
    ///
    /// # Errors
    ///
    /// Refuses empty paths, missing databases, incompatible schemas, or any
    /// database that cannot be opened with the strict read-only profile.
    pub fn open_read_only(path: &Path) -> Result<Self, LedgerError> {
        if path.as_os_str().is_empty() || !path.is_file() {
            return Err(LedgerError::InvalidPath);
        }
        let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|_| LedgerError::Unavailable)?;
        connection
            .busy_timeout(DATABASE_BUSY_TIMEOUT)
            .map_err(|_| LedgerError::Unavailable)?;
        connection
            .execute_batch(
                "PRAGMA query_only = ON;
                 PRAGMA trusted_schema = OFF;
                 PRAGMA foreign_keys = ON;",
            )
            .map_err(|_| LedgerError::Unavailable)?;
        let query_only = connection
            .query_row("PRAGMA query_only", [], |row| row.get::<_, i64>(0))
            .map_err(|_| LedgerError::Unavailable)?;
        let version = connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .map_err(|_| LedgerError::Unavailable)?;
        if query_only != 1 {
            return Err(LedgerError::Unavailable);
        }
        if version != SCHEMA_VERSION {
            return Err(LedgerError::IncompatibleSchema);
        }
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            execution_barrier: Arc::new(RwLock::new(())),
        })
    }

    /// Installs one immutable approved Task Policy/session binding.
    /// Duplicate sessions and tasks are rejected rather than widened.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid binding, duplicate, or unavailable DB.
    pub fn approve_session(&self, approval: &ApprovedSession) -> Result<(), LedgerError> {
        approval.validate()?;
        let approval_json = serde_json::to_string(approval).map_err(|_| LedgerError::Encoding)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| LedgerError::Unavailable)?;
        let inserted = transaction.execute(
            "INSERT INTO approved_sessions (
                 session_id, task_id, run_id, workspace_root, policy_epoch,
                 task_policy_hash, approved_at, expires_at, approval_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                approval.session_id,
                approval.task_id.to_string(),
                approval.run_id,
                approval.workspace_root,
                i64::try_from(approval.policy_epoch).map_err(|_| LedgerError::InvalidApproval)?,
                approval.task_policy_hash.to_string(),
                approval.approved_at,
                approval.expires_at,
                approval_json,
            ],
        );
        if let Err(error) = inserted {
            if is_constraint(&error) {
                return Err(LedgerError::DuplicateApproval);
            }
            return Err(LedgerError::Unavailable);
        }
        for capability in &approval.capabilities {
            transaction
                .execute(
                    "INSERT INTO approved_capabilities(session_id, extension_id, tool_name)
                     VALUES (?1, ?2, ?3)",
                    params![
                        approval.session_id,
                        capability.extension_id,
                        capability.tool_name
                    ],
                )
                .map_err(|_| LedgerError::Unavailable)?;
        }
        transaction.commit().map_err(|_| LedgerError::Unavailable)
    }

    /// Installs an immutable approval, treating an exact retry as success.
    ///
    /// Reusing either the session identifier or task identifier for any
    /// different binding is a conflict; no existing authority is updated.
    /// This operation is intended for a trusted control-channel retry after an
    /// ambiguous transport failure.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid/conflicting binding or unavailable DB.
    pub fn register_session(
        &self,
        approval: &ApprovedSession,
    ) -> Result<ApprovalRegistration, LedgerError> {
        approval.validate()?;
        let approval_json = serde_json::to_string(approval).map_err(|_| LedgerError::Encoding)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| LedgerError::Unavailable)?;

        let existing = {
            let mut statement = transaction
                .prepare(
                    "SELECT approval_json FROM approved_sessions
                     WHERE session_id = ?1 OR task_id = ?2
                     ORDER BY session_id",
                )
                .map_err(|_| LedgerError::Unavailable)?;
            let rows = statement
                .query_map(
                    params![approval.session_id, approval.task_id.to_string()],
                    |row| row.get::<_, String>(0),
                )
                .map_err(|_| LedgerError::Unavailable)?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|_| LedgerError::Unavailable)?
        };
        if !existing.is_empty() {
            if existing.len() == 1 {
                let recorded: ApprovedSession =
                    serde_json::from_str(&existing[0]).map_err(|_| LedgerError::CorruptState)?;
                recorded.validate().map_err(|_| LedgerError::CorruptState)?;
                if recorded == *approval {
                    transaction.commit().map_err(|_| LedgerError::Unavailable)?;
                    return Ok(ApprovalRegistration::AlreadyPresent);
                }
            }
            return Err(LedgerError::ConflictingApproval);
        }

        transaction
            .execute(
                "INSERT INTO approved_sessions (
                     session_id, task_id, run_id, workspace_root, policy_epoch,
                     task_policy_hash, approved_at, expires_at, approval_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    approval.session_id,
                    approval.task_id.to_string(),
                    approval.run_id,
                    approval.workspace_root,
                    i64::try_from(approval.policy_epoch)
                        .map_err(|_| LedgerError::InvalidApproval)?,
                    approval.task_policy_hash.to_string(),
                    approval.approved_at,
                    approval.expires_at,
                    approval_json,
                ],
            )
            .map_err(|error| {
                if is_constraint(&error) {
                    LedgerError::ConflictingApproval
                } else {
                    LedgerError::Unavailable
                }
            })?;
        for capability in &approval.capabilities {
            transaction
                .execute(
                    "INSERT INTO approved_capabilities(session_id, extension_id, tool_name)
                     VALUES (?1, ?2, ?3)",
                    params![
                        approval.session_id,
                        capability.extension_id,
                        capability.tool_name
                    ],
                )
                .map_err(|_| LedgerError::Unavailable)?;
        }
        transaction.commit().map_err(|_| LedgerError::Unavailable)?;
        Ok(ApprovalRegistration::Inserted)
    }

    /// Installs one immutable, exact policy approval from the private control
    /// channel. An exact retry is idempotent; every policy conflict fails
    /// closed and no existing approval is widened or replaced.
    ///
    /// # Errors
    ///
    /// Rejects invalid, unknown, revoked, mismatched, conflicting, or
    /// unavailable durable state.
    pub fn register_action_approval(
        &self,
        approval: &ActionApproval,
    ) -> Result<ActionApprovalRegistration, LedgerError> {
        approval.validate()?;
        let approval_json = serde_json::to_string(approval).map_err(|_| LedgerError::Encoding)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| LedgerError::Unavailable)?;

        validate_action_approval_session(&transaction, approval)?;

        let existing = {
            let mut statement = transaction
                .prepare(
                    "SELECT approval_json FROM action_approvals
                     WHERE approval_id = ?1 OR proposal_digest = ?2
                        OR approval_request_hash = ?3
                        OR policy_decision_hash = ?4
                        OR (session_id = ?5 AND run_id = ?6 AND tool_call_id = ?7)
                     ORDER BY approval_id",
                )
                .map_err(|_| LedgerError::Unavailable)?;
            let rows = statement
                .query_map(
                    params![
                        approval.approval_id.to_string(),
                        approval.proposal_digest.to_string(),
                        approval.approval_request_hash.to_string(),
                        approval.policy_decision_hash.to_string(),
                        approval.session_id,
                        approval.run_id,
                        approval.tool_call_id,
                    ],
                    |row| row.get::<_, String>(0),
                )
                .map_err(|_| LedgerError::Unavailable)?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|_| LedgerError::Unavailable)?
        };
        if !existing.is_empty() {
            if existing.len() == 1 {
                let recorded: ActionApproval =
                    serde_json::from_str(&existing[0]).map_err(|_| LedgerError::CorruptState)?;
                recorded.validate().map_err(|_| LedgerError::CorruptState)?;
                if recorded == *approval {
                    transaction.commit().map_err(|_| LedgerError::Unavailable)?;
                    return Ok(ActionApprovalRegistration::AlreadyPresent);
                }
            }
            return Err(LedgerError::ConflictingActionApproval);
        }

        transaction
            .execute(
                "INSERT INTO action_approvals (
                     approval_id, session_id, run_id, tool_call_id, proposal_digest,
                     task_policy_hash, prestate_hash, approval_request_hash,
                     policy_decision_hash, decision, approval_evidence_hash, decided_at, expires_at,
                     consumed_at, approval_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, NULL, ?14)",
                params![
                    approval.approval_id.to_string(),
                    approval.session_id,
                    approval.run_id,
                    approval.tool_call_id,
                    approval.proposal_digest.to_string(),
                    approval.task_policy_hash.to_string(),
                    approval.prestate_hash.to_string(),
                    approval.approval_request_hash.to_string(),
                    approval.policy_decision_hash.to_string(),
                    match approval.decision {
                        ApprovalDecision::Approved => "APPROVED",
                        ApprovalDecision::Denied => "DENIED",
                    },
                    approval.approval_evidence_hash.to_string(),
                    approval.decided_at,
                    approval.expires_at,
                    approval_json,
                ],
            )
            .map_err(|error| {
                if is_constraint(&error) {
                    LedgerError::ConflictingActionApproval
                } else {
                    LedgerError::Unavailable
                }
            })?;
        transaction.commit().map_err(|_| LedgerError::Unavailable)?;
        Ok(ActionApprovalRegistration::Inserted)
    }

    pub(crate) fn action_approval_request(
        &self,
        proposal: &ToolCallProposal,
        prestate_hash: accordlock_agent_protocol::Digest32,
        action: ActionDescriptor,
    ) -> Result<Option<ActionApprovalRequest>, LedgerError> {
        proposal.validate()?;
        let proposal_digest = parse_digest(&proposal.digest()?)?;
        let connection = self.lock()?;
        let approval_json = connection
            .query_row(
                "SELECT approval_json FROM approved_sessions WHERE session_id = ?1",
                params![proposal.session_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| LedgerError::Unavailable)?;
        let Some(approval_json) = approval_json else {
            return Ok(None);
        };
        let approval: ApprovedSession =
            serde_json::from_str(&approval_json).map_err(|_| LedgerError::CorruptState)?;
        approval.validate().map_err(|_| LedgerError::CorruptState)?;
        if proposal.run_id != approval.run_id
            || proposal.workspace_root != approval.workspace_root
            || !approval.authorizes(&proposal.extension_id, &proposal.tool_name)
        {
            return Ok(None);
        }
        let context = ActionApprovalRequest::new(
            approval.task_id,
            proposal.session_id.clone(),
            proposal.run_id.clone(),
            proposal.tool_call_id.clone(),
            proposal_digest,
            approval.task_policy_hash,
            approval.task_policy.task_objective_hash,
            approval.policy_epoch,
            approval.approved_at,
            prestate_hash,
            action,
        )
        .map_err(|_| LedgerError::ActionApprovalScopeMismatch)?;
        Ok(Some(context))
    }

    pub(crate) fn task_policy_protected_paths(
        &self,
        proposal: &ToolCallProposal,
    ) -> Result<Vec<String>, LedgerError> {
        let connection = self.lock()?;
        let approval_json = connection
            .query_row(
                "SELECT approval_json FROM approved_sessions WHERE session_id = ?1",
                params![proposal.session_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| LedgerError::Unavailable)?;
        let Some(approval_json) = approval_json else {
            return Ok(Vec::new());
        };
        let approval: ApprovedSession =
            serde_json::from_str(&approval_json).map_err(|_| LedgerError::CorruptState)?;
        approval.validate().map_err(|_| LedgerError::CorruptState)?;
        if proposal.run_id != approval.run_id || proposal.workspace_root != approval.workspace_root
        {
            return Ok(Vec::new());
        }
        Ok(approval.task_policy.protected_paths)
    }

    /// Durably disables one exact approved task/session/run authority.
    ///
    /// The approval is retained for auditability. An exact retry is successful,
    /// while partial identities, cross-bound identities, and conflicting
    /// retries are rejected without changing the ledger.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid or unknown binding, any conflict, or an
    /// unavailable/corrupt ledger.
    pub fn revoke_session(
        &self,
        revocation: &SessionRevocation,
    ) -> Result<RevocationRegistration, LedgerError> {
        let revoked_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|value| i64::try_from(value.as_secs()).ok())
            .ok_or(LedgerError::InvalidTime)?;
        self.revoke_session_at(revocation, revoked_at)
    }

    /// Durably disables one exact authority and records trusted control-plane time.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid time or any revocation registration failure.
    pub fn revoke_session_at(
        &self,
        revocation: &SessionRevocation,
        revoked_at: i64,
    ) -> Result<RevocationRegistration, LedgerError> {
        revocation.validate()?;
        let revocation_digest =
            goose_digest(revocation).map_err(|_| LedgerError::InvalidRevocation)?;
        let revocation_json =
            serde_json::to_string(revocation).map_err(|_| LedgerError::Encoding)?;
        // A successful ACK is also a barrier: every brokered execution that held
        // authority before this transition has finished, and no later execution
        // can pass authorization using the revoked session.
        let _execution_barrier = self
            .execution_barrier
            .write()
            .map_err(|_| LedgerError::Unavailable)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| LedgerError::Unavailable)?;

        require_exact_revocation_binding(&transaction, revocation)?;
        let existing = recorded_revocations(&transaction, revocation)?;
        if !existing.is_empty() {
            if existing.len() == 1 {
                let recorded: SessionRevocation =
                    serde_json::from_str(&existing[0]).map_err(|_| LedgerError::CorruptState)?;
                recorded.validate().map_err(|_| LedgerError::CorruptState)?;
                if recorded == *revocation {
                    transaction.commit().map_err(|_| LedgerError::Unavailable)?;
                    return Ok(RevocationRegistration::AlreadyRevoked);
                }
            }
            return Err(LedgerError::ConflictingRevocation);
        }

        // Preserve exact retry idempotence above, even when the caller retries
        // with a stale clock value. A first revocation, however, must not
        // rewrite history by preceding either the approval or any event already
        // committed under this session authority.
        if revoked_at < 0
            || revoked_at < session_event_high_water(&transaction, &revocation.session_id)?
        {
            return Err(LedgerError::InvalidTime);
        }

        transaction
            .execute(
                "INSERT INTO revoked_sessions (
                     session_id, task_id, run_id, revocation_digest, revocation_json, revoked_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    revocation.session_id,
                    revocation.task_id.to_string(),
                    revocation.run_id,
                    revocation_digest,
                    revocation_json,
                    revoked_at,
                ],
            )
            .map_err(|error| {
                if is_constraint(&error) {
                    LedgerError::ConflictingRevocation
                } else {
                    LedgerError::Unavailable
                }
            })?;
        transaction.commit().map_err(|_| LedgerError::Unavailable)?;
        Ok(RevocationRegistration::Revoked)
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn authorize_and_consume(
        &self,
        proposal: &ToolCallProposal,
        approval_request: Option<&ActionApprovalRequest>,
        automatic_execution_class: Option<AutomaticExecutionClass>,
        now: i64,
        grant_lifetime_seconds: i64,
    ) -> Result<AuthorizationResult, LedgerError> {
        proposal.validate()?;
        if now < 0
            || !(1..=accordlock_agent_protocol::MAX_AUTHORIZATION_LIFETIME_SECONDS)
                .contains(&grant_lifetime_seconds)
        {
            return Err(LedgerError::InvalidTime);
        }
        let proposal_digest = proposal.digest()?;
        let proposal_json = serde_json::to_string(proposal).map_err(|_| LedgerError::Encoding)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| LedgerError::Unavailable)?;
        observe_clock(&transaction, now)?;

        let approval_json = transaction
            .query_row(
                "SELECT approval_json FROM approved_sessions WHERE session_id = ?1",
                params![proposal.session_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| LedgerError::Unavailable)?;
        let Some(approval_json) = approval_json else {
            return commit_denial(
                transaction,
                proposal,
                &proposal_digest,
                "UNKNOWN_SESSION",
                now,
            );
        };
        let approval: ApprovedSession =
            serde_json::from_str(&approval_json).map_err(|_| LedgerError::CorruptState)?;
        approval.validate().map_err(|_| LedgerError::CorruptState)?;

        let revoked = transaction
            .query_row(
                "SELECT 1 FROM revoked_sessions WHERE session_id = ?1",
                params![proposal.session_id],
                |_| Ok(()),
            )
            .optional()
            .map_err(|_| LedgerError::Unavailable)?
            .is_some();
        if revoked {
            return commit_denial(
                transaction,
                proposal,
                &proposal_digest,
                "SESSION_REVOKED",
                now,
            );
        }

        let reason = if now < approval.approved_at || now >= approval.expires_at {
            Some("SESSION_NOT_CURRENT")
        } else if proposal.run_id != approval.run_id
            || proposal.workspace_root != approval.workspace_root
        {
            Some("SESSION_BINDING_MISMATCH")
        } else if !approval.authorizes(&proposal.extension_id, &proposal.tool_name) {
            Some("CAPABILITY_NOT_APPROVED")
        } else {
            None
        };
        if let Some(reason) = reason {
            return commit_denial(transaction, proposal, &proposal_digest, reason, now);
        }

        // The live semantic chain is built from the trusted objective, the
        // exact provider-visible plan checkpoint, and this full proposal before
        // any one-shot authority is issued. A legacy session, substituted plan,
        // future checkpoint, or malformed evaluator context is a hard denial.
        let Ok(intent_pre_evaluation) =
            PreExecutionLiveIntentBundle::build_strict(&approval, proposal, now)
        else {
            return commit_denial(
                transaction,
                proposal,
                &proposal_digest,
                "INTENT_EVALUATION_INVALID",
                now,
            );
        };
        let intent_pre_evaluation_hash = intent_pre_evaluation
            .record
            .digest()
            .map_err(|_| LedgerError::Protocol)?;
        let intent_pre_evaluation_json =
            serde_json::to_string(&intent_pre_evaluation).map_err(|_| LedgerError::Encoding)?;

        let automatic = approval
            .task_policy
            .allows_automatic(&proposal.extension_id, &proposal.tool_name);
        let (
            authorization_outcome,
            decision_reason,
            approval_evidence_hash,
            policy_decision_hash,
            conformance_evaluation_hashes,
            automatic_evaluation_json,
        ) = if automatic {
            let Some(execution_class) = crate::filesystem::validated_automatic_execution_class(
                proposal,
                &approval.task_policy.protected_paths,
            ) else {
                return commit_denial(
                    transaction,
                    proposal,
                    &proposal_digest,
                    "CONFORMANCE_EVALUATION_INVALID",
                    now,
                );
            };
            if automatic_execution_class.is_some_and(|candidate| candidate != execution_class) {
                return commit_denial(
                    transaction,
                    proposal,
                    &proposal_digest,
                    "CONFORMANCE_SCOPE_MISMATCH",
                    now,
                );
            }
            let evaluation_input = AutomaticEvaluationInput {
                task_id: approval.task_id,
                session_id: &proposal.session_id,
                run_id: &proposal.run_id,
                tool_call_id: &proposal.tool_call_id,
                proposal_digest: parse_digest(&proposal_digest)?,
                extension_id: &proposal.extension_id,
                tool_name: &proposal.tool_name,
                task_policy: &approval.task_policy,
                task_policy_hash: approval.task_policy_hash,
                policy_epoch: approval.policy_epoch,
                evaluated_at: now,
            };
            let Ok(automatic_evaluation) =
                AutomaticActionEvaluation::new(evaluation_input, execution_class)
            else {
                return commit_denial(
                    transaction,
                    proposal,
                    &proposal_digest,
                    "CONFORMANCE_EVALUATION_INVALID",
                    now,
                );
            };
            let conformance_hash = automatic_evaluation
                .conformance_evaluation_hash()
                .map_err(|_| LedgerError::Protocol)?;
            let automatic_evaluation_json =
                serde_json::to_string(&automatic_evaluation).map_err(|_| LedgerError::Encoding)?;
            (
                AuthorizationOutcome::Allow,
                "POLICY_CONFORMANT",
                None,
                automatic_evaluation.policy_decision_hash,
                vec![conformance_hash],
                Some(automatic_evaluation_json),
            )
        } else {
            if automatic_execution_class.is_some() {
                return commit_denial(
                    transaction,
                    proposal,
                    &proposal_digest,
                    "CONFORMANCE_SCOPE_MISMATCH",
                    now,
                );
            }
            match resolve_action_approval(
                &transaction,
                &approval,
                proposal,
                &proposal_digest,
                approval_request,
                now,
            )? {
                Ok((evidence_hash, policy_decision_hash)) => (
                    AuthorizationOutcome::AllowAfterApproval,
                    "ACTION_APPROVAL_ACCEPTED",
                    Some(evidence_hash),
                    policy_decision_hash,
                    Vec::new(),
                    None,
                ),
                Err(denial) => {
                    return commit_denial(
                        transaction,
                        proposal,
                        &proposal_digest,
                        denial.reason_code(),
                        now,
                    );
                }
            }
        };

        let replayed = transaction
            .query_row(
                "SELECT 1 FROM attempts
                 WHERE session_id = ?1 AND run_id = ?2 AND tool_call_id = ?3",
                params![proposal.session_id, proposal.run_id, proposal.tool_call_id],
                |_| Ok(()),
            )
            .optional()
            .map_err(|_| LedgerError::Unavailable)?
            .is_some();
        if replayed {
            return commit_denial(
                transaction,
                proposal,
                &proposal_digest,
                "TOOL_CALL_REPLAY",
                now,
            );
        }

        let expires_at = now
            .checked_add(grant_lifetime_seconds)
            .ok_or(LedgerError::InvalidTime)?
            .min(approval.expires_at);
        if expires_at <= now {
            return commit_denial(
                transaction,
                proposal,
                &proposal_digest,
                "SESSION_NOT_CURRENT",
                now,
            );
        }
        let arguments_hash = proposal.arguments_digest()?;
        let request = ExecutionRequest {
            schema_version: EXECUTION_REQUEST_SCHEMA_VERSION,
            request_id: Uuid::new_v4(),
            session_id: proposal.session_id.clone(),
            run_id: proposal.run_id.clone(),
            tool_call_id: proposal.tool_call_id.clone(),
            workspace: proposal.workspace_root.clone(),
            extension: proposal.extension_id.clone(),
            tool: proposal.tool_name.clone(),
            canonical_args_hash: arguments_hash,
            policy_epoch: approval.policy_epoch,
            task_policy_hash: approval.task_policy_hash,
            created_at: now,
            expires_at,
        };
        let request_hash = request.digest().map_err(|_| LedgerError::Protocol)?;
        let decision = AuthorizationDecision {
            schema_version: AUTHORIZATION_DECISION_SCHEMA_VERSION,
            request_hash,
            session_id: request.session_id.clone(),
            run_id: request.run_id.clone(),
            tool_call_id: request.tool_call_id.clone(),
            workspace: request.workspace.clone(),
            extension: request.extension.clone(),
            tool: request.tool.clone(),
            canonical_args_hash: request.canonical_args_hash,
            policy_epoch: request.policy_epoch,
            task_policy_hash: request.task_policy_hash,
            policy_decision_hash,
            conformance_evaluation_hashes,
            intent_evaluation_hash: intent_pre_evaluation_hash,
            outcome: authorization_outcome,
            reason_code: decision_reason.to_owned(),
            approval_evidence_hash,
            decided_at: now,
            expires_at,
        };
        let authorization_decision_hash = decision.digest().map_err(|_| LedgerError::Protocol)?;
        let authorization = ExecutionAuthorization {
            schema_version: EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
            authorization_id: Uuid::new_v4(),
            request_hash,
            authorization_decision_hash,
            session_id: request.session_id.clone(),
            run_id: request.run_id.clone(),
            tool_call_id: request.tool_call_id.clone(),
            workspace: request.workspace.clone(),
            extension: request.extension.clone(),
            tool: request.tool.clone(),
            canonical_args_hash: request.canonical_args_hash,
            policy_epoch: request.policy_epoch,
            task_policy_hash: request.task_policy_hash,
            issued_at: now,
            not_before: now,
            expires_at,
        };
        authorization
            .verify_for(&request, &decision)
            .map_err(|_| LedgerError::Protocol)?;
        let authorization_hash = authorization.digest().map_err(|_| LedgerError::Protocol)?;
        let request_json = serde_json::to_string(&request).map_err(|_| LedgerError::Encoding)?;
        let decision_json = serde_json::to_string(&decision).map_err(|_| LedgerError::Encoding)?;
        let authorization_json =
            serde_json::to_string(&authorization).map_err(|_| LedgerError::Encoding)?;

        let inserted = transaction.execute(
            "INSERT INTO attempts (
                 proposal_digest, session_id, run_id, tool_call_id, proposal_json,
                 request_hash, request_json, authorization_decision_hash, decision_json,
                 automatic_evaluation_json,
                 intent_pre_evaluation_hash, intent_pre_evaluation_json,
                 authorization_id, authorization_hash, authorization_json, consumed_at, state
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, 'IN_FLIGHT')",
            params![
                proposal_digest,
                proposal.session_id,
                proposal.run_id,
                proposal.tool_call_id,
                proposal_json,
                request_hash.to_string(),
                request_json,
                authorization_decision_hash.to_string(),
                decision_json,
                automatic_evaluation_json,
                intent_pre_evaluation_hash.to_string(),
                intent_pre_evaluation_json,
                authorization.authorization_id.to_string(),
                authorization_hash.to_string(),
                authorization_json,
                now,
            ],
        );
        if let Err(error) = inserted {
            if is_constraint(&error) {
                return commit_denial(
                    transaction,
                    proposal,
                    &proposal_digest,
                    "TOOL_CALL_REPLAY",
                    now,
                );
            }
            return Err(LedgerError::Unavailable);
        }
        transaction.commit().map_err(|_| LedgerError::Unavailable)?;
        Ok(AuthorizationResult::Allowed(AuthorizationGrant {
            authorization_id: authorization.authorization_id,
            proposal_digest,
            request_hash,
            reason_code: decision_reason,
            issued_at: authorization.issued_at,
            not_before: authorization.not_before,
            expires_at: authorization.expires_at,
        }))
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn observe(
        &self,
        observation: &ToolExecutionObservation,
        now: i64,
    ) -> Result<ObservationResult, LedgerError> {
        observation.validate()?;
        if now < 0 {
            return Err(LedgerError::InvalidTime);
        }
        let observation_digest = observation.digest()?;
        let observation_json =
            serde_json::to_string(observation).map_err(|_| LedgerError::Encoding)?;
        let authorization_id = observation.authorization_id()?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| LedgerError::Unavailable)?;
        observe_clock(&transaction, now)?;

        let record = transaction
            .query_row(
                "SELECT proposal_digest, proposal_json, request_hash, request_json, decision_json,
                        authorization_json, intent_pre_evaluation_hash,
                        intent_pre_evaluation_json,
                        consumed_at, state, observation_digest, record_id, record_hash
                 FROM attempts WHERE authorization_id = ?1",
                params![authorization_id.to_string()],
                |row| {
                    Ok(ObservationRecord {
                        proposal_digest: row.get(0)?,
                        proposal_json: row.get(1)?,
                        request_hash: row.get(2)?,
                        request_json: row.get(3)?,
                        decision_json: row.get(4)?,
                        authorization_json: row.get(5)?,
                        intent_pre_evaluation_hash: row.get(6)?,
                        intent_pre_evaluation_json: row.get(7)?,
                        consumed_at: row.get(8)?,
                        state: row.get(9)?,
                        observation_digest: row.get(10)?,
                        record_id: row.get(11)?,
                        record_hash: row.get(12)?,
                    })
                },
            )
            .optional()
            .map_err(|_| LedgerError::Unavailable)?
            .ok_or(LedgerError::UnknownAuthorization)?;

        if record.state != "IN_FLIGHT" {
            if record.observation_digest.as_deref() == Some(&observation_digest) {
                transaction.commit().map_err(|_| LedgerError::Unavailable)?;
                return Ok(ObservationResult {
                    authorization_id,
                    observation_digest,
                    record_id: record
                        .record_id
                        .as_deref()
                        .ok_or(LedgerError::CorruptState)
                        .and_then(|value| {
                            Uuid::parse_str(value).map_err(|_| LedgerError::CorruptState)
                        })?,
                    record_hash: record.record_hash.ok_or(LedgerError::CorruptState)?,
                });
            }
            return Err(LedgerError::ConflictingObservation);
        }
        if observation.proposal_digest != record.proposal_digest
            || observation.request_hash != record.request_hash
        {
            return Err(LedgerError::ObservationBindingMismatch);
        }
        if now < record.consumed_at
            || now.saturating_sub(record.consumed_at) > MAX_EXECUTION_DURATION_SECONDS
        {
            return Err(LedgerError::ObservationWindowExpired);
        }

        let proposal: ToolCallProposal =
            serde_json::from_str(&record.proposal_json).map_err(|_| LedgerError::CorruptState)?;
        if proposal.digest().map_err(|_| LedgerError::CorruptState)? != record.proposal_digest {
            return Err(LedgerError::CorruptState);
        }
        let request: ExecutionRequest =
            serde_json::from_str(&record.request_json).map_err(|_| LedgerError::CorruptState)?;
        let decision: AuthorizationDecision =
            serde_json::from_str(&record.decision_json).map_err(|_| LedgerError::CorruptState)?;
        decision
            .verify_for_request(&request)
            .map_err(|_| LedgerError::CorruptState)?;
        let authorization: ExecutionAuthorization =
            serde_json::from_str(&record.authorization_json)
                .map_err(|_| LedgerError::CorruptState)?;
        authorization
            .verify_for(&request, &decision)
            .map_err(|_| LedgerError::CorruptState)?;
        let approved_json = transaction
            .query_row(
                "SELECT approval_json FROM approved_sessions WHERE session_id = ?1",
                params![authorization.session_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| LedgerError::Unavailable)?
            .ok_or(LedgerError::CorruptState)?;
        let approved: ApprovedSession =
            serde_json::from_str(&approved_json).map_err(|_| LedgerError::CorruptState)?;
        approved.validate().map_err(|_| LedgerError::CorruptState)?;
        if approved.session_id != authorization.session_id
            || approved.run_id != authorization.run_id
            || approved.task_policy_hash != authorization.task_policy_hash
            || approved.policy_epoch != authorization.policy_epoch
        {
            return Err(LedgerError::CorruptState);
        }
        let intent_pre_evaluation_hash = record
            .intent_pre_evaluation_hash
            .as_deref()
            .ok_or(LedgerError::CorruptState)?;
        let intent_pre_evaluation: PreExecutionLiveIntentBundle = serde_json::from_str(
            record
                .intent_pre_evaluation_json
                .as_deref()
                .ok_or(LedgerError::CorruptState)?,
        )
        .map_err(|_| LedgerError::CorruptState)?;
        intent_pre_evaluation
            .revalidate(&approved, &proposal)
            .map_err(|_| LedgerError::CorruptState)?;
        if intent_pre_evaluation
            .record
            .digest()
            .map_err(|_| LedgerError::CorruptState)?
            .to_string()
            != intent_pre_evaluation_hash
        {
            return Err(LedgerError::CorruptState);
        }
        let stored_intent_evaluation_hash =
            parse_digest(intent_pre_evaluation_hash).map_err(|_| LedgerError::CorruptState)?;
        if decision.intent_evaluation_hash != stored_intent_evaluation_hash {
            return Err(LedgerError::CorruptState);
        }
        let (outcome, state, outcome_label) = match observation.outcome {
            WireExecutionOutcome::Succeeded => {
                (ExecutionOutcome::Succeeded, "SUCCEEDED", "SUCCEEDED")
            }
            WireExecutionOutcome::ToolReportedError => (
                ExecutionOutcome::Indeterminate,
                "EXECUTION_UNKNOWN",
                "TOOL_REPORTED_ERROR",
            ),
            WireExecutionOutcome::TransportError => (
                ExecutionOutcome::Indeterminate,
                "EXECUTION_UNKNOWN",
                "TRANSPORT_ERROR",
            ),
        };
        let result_hash = match observation.result_digest.as_deref() {
            Some(value) => parse_digest(value)?,
            None => digest_bytes(b"accordlock:v2:agent-no-tool-result:transport-error"),
        };
        let authorization_hash = authorization
            .digest()
            .map_err(|_| LedgerError::CorruptState)?;
        let record = ExecutionRecord {
            schema_version: EXECUTION_RECORD_SCHEMA_VERSION,
            record_id: Uuid::new_v4(),
            authorization_id,
            request_hash: authorization.request_hash,
            authorization_hash,
            session_id: authorization.session_id.clone(),
            run_id: authorization.run_id.clone(),
            tool_call_id: authorization.tool_call_id.clone(),
            workspace: authorization.workspace.clone(),
            extension: authorization.extension.clone(),
            tool: authorization.tool.clone(),
            canonical_args_hash: authorization.canonical_args_hash,
            policy_epoch: authorization.policy_epoch,
            task_policy_hash: authorization.task_policy_hash,
            consumed_at: record.consumed_at,
            completed_at: now,
            outcome,
            result_hash,
        };
        record
            .verify_for(&request, &authorization)
            .map_err(|_| LedgerError::CorruptState)?;
        let record_hash = record.digest().map_err(|_| LedgerError::Protocol)?;
        let record_json = serde_json::to_string(&record).map_err(|_| LedgerError::Encoding)?;
        let execution_trace = CompletedExecutionEvidence::build(
            &approved,
            &proposal,
            &request,
            &decision,
            &authorization,
            &record,
        )
        .map_err(|_| LedgerError::Protocol)?;
        let execution_trace_hash = execution_trace
            .commitment()
            .map_err(|_| LedgerError::Protocol)?
            .to_string();
        let execution_trace_json =
            serde_json::to_string(&execution_trace).map_err(|_| LedgerError::Encoding)?;
        let intent_complete_evaluation = intent_pre_evaluation
            .append_result(&approved, &proposal, result_hash, now)
            .map_err(|_| LedgerError::Protocol)?;
        let intent_complete_evaluation_hash = intent_complete_evaluation
            .record
            .digest()
            .map_err(|_| LedgerError::Protocol)?
            .to_string();
        let intent_complete_evaluation_json = serde_json::to_string(&intent_complete_evaluation)
            .map_err(|_| LedgerError::Encoding)?;
        let updated = transaction
            .execute(
                "UPDATE attempts SET
                     state = ?1, outcome = ?2, completed_at = ?3,
                     observation_digest = ?4, observation_json = ?5,
                     record_id = ?6, record_hash = ?7, record_json = ?8,
                     execution_trace_hash = ?9, execution_trace_json = ?10,
                     intent_complete_evaluation_hash = ?11,
                     intent_complete_evaluation_json = ?12
                 WHERE authorization_id = ?13 AND state = 'IN_FLIGHT'",
                params![
                    state,
                    outcome_label,
                    now,
                    observation_digest,
                    observation_json,
                    record.record_id.to_string(),
                    record_hash.to_string(),
                    record_json,
                    execution_trace_hash,
                    execution_trace_json,
                    intent_complete_evaluation_hash,
                    intent_complete_evaluation_json,
                    authorization_id.to_string(),
                ],
            )
            .map_err(|error| {
                if is_constraint(&error) {
                    LedgerError::ConflictingObservation
                } else {
                    LedgerError::Unavailable
                }
            })?;
        if updated != 1 {
            return Err(LedgerError::ConflictingObservation);
        }
        transaction.commit().map_err(|_| LedgerError::Unavailable)?;
        Ok(ObservationResult {
            authorization_id,
            observation_digest,
            record_id: record.record_id,
            record_hash: record_hash.to_string(),
        })
    }

    /// Reads the non-secret terminal/in-flight summary used by Desktop UI.
    ///
    /// # Errors
    ///
    /// Returns unknown for an absent authorization and fail-closed on DB errors.
    pub fn attempt(&self, authorization_id: Uuid) -> Result<AttemptSnapshot, LedgerError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT proposal_digest, request_hash, state, outcome, consumed_at,
                        completed_at, record_id, record_hash
                 FROM attempts WHERE authorization_id = ?1",
                params![authorization_id.to_string()],
                |row| {
                    let record_id = row
                        .get::<_, Option<String>>(6)?
                        .map(|value| Uuid::parse_str(&value))
                        .transpose()
                        .map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                6,
                                rusqlite::types::Type::Text,
                                Box::new(error),
                            )
                        })?;
                    Ok(AttemptSnapshot {
                        authorization_id,
                        proposal_digest: row.get(0)?,
                        request_hash: row.get(1)?,
                        state: row.get(2)?,
                        outcome: row.get(3)?,
                        consumed_at: row.get(4)?,
                        completed_at: row.get(5)?,
                        record_id,
                        record_hash: row.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(|_| LedgerError::Unavailable)?
            .ok_or(LedgerError::UnknownAuthorization)
    }

    pub(crate) fn attempt_for_proposal(
        &self,
        proposal: &ToolCallProposal,
    ) -> Result<Option<ReconciliationAttempt>, LedgerError> {
        proposal.validate()?;
        let proposal_digest = proposal.digest()?;
        let connection = self.lock()?;
        let record = connection
            .query_row(
                "SELECT attempts.proposal_json, attempts.authorization_id,
                        attempts.request_hash, attempts.state,
                        attempts.observation_digest, attempts.record_id,
                        attempts.record_hash, action_approvals.prestate_hash
                 FROM attempts
                 LEFT JOIN action_approvals USING (proposal_digest)
                 WHERE attempts.proposal_digest = ?1",
                params![proposal_digest],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, Option<String>>(7)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| LedgerError::Unavailable)?;
        let Some((
            proposal_json,
            authorization_id,
            request_hash,
            state,
            observation_digest,
            record_id,
            record_hash,
            prestate_hash,
        )) = record
        else {
            return Ok(None);
        };
        let stored_proposal: ToolCallProposal =
            serde_json::from_str(&proposal_json).map_err(|_| LedgerError::CorruptState)?;
        if stored_proposal != *proposal {
            return Err(LedgerError::CorruptState);
        }
        let authorization_id =
            Uuid::parse_str(&authorization_id).map_err(|_| LedgerError::CorruptState)?;
        let request_hash = parse_digest(&request_hash)?;
        let record_id = record_id
            .map(|value| Uuid::parse_str(&value).map_err(|_| LedgerError::CorruptState))
            .transpose()?;
        let terminal_fields_are_complete =
            observation_digest.is_some() && record_id.is_some() && record_hash.is_some();
        if !matches!(
            state.as_str(),
            "IN_FLIGHT" | "SUCCEEDED" | "EXECUTION_UNKNOWN"
        ) || (state == "IN_FLIGHT"
            && (observation_digest.is_some() || record_id.is_some() || record_hash.is_some()))
            || (state != "IN_FLIGHT" && !terminal_fields_are_complete)
        {
            return Err(LedgerError::CorruptState);
        }
        if let Some(value) = observation_digest.as_deref() {
            parse_digest(value)?;
        }
        if let Some(value) = record_hash.as_deref() {
            parse_digest(value)?;
        }
        let prestate_hash = prestate_hash.as_deref().map(parse_digest).transpose()?;
        Ok(Some(ReconciliationAttempt {
            authorization_id,
            proposal_digest,
            request_hash,
            state,
            observation_digest,
            record_id,
            record_hash,
            prestate_hash,
        }))
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn deleted_file_recovery_evidence(
        &self,
        recovery_id: Uuid,
    ) -> Result<DeletedFileRecoveryEvidence, LedgerError> {
        if recovery_id.is_nil() {
            return Err(LedgerError::UnknownFileRecovery);
        }
        let connection = self.lock()?;
        let row = connection
            .query_row(
                "SELECT attempts.proposal_digest, attempts.proposal_json,
                        attempts.state, attempts.outcome, attempts.observation_json,
                        attempts.record_id, attempts.record_hash, attempts.record_json,
                        attempts.completed_at, action_approvals.prestate_hash,
                        action_approvals.approval_json, action_approvals.consumed_at,
                        approved_sessions.task_id, approved_sessions.approval_json
                 FROM attempts
                 JOIN action_approvals USING (proposal_digest)
                 JOIN approved_sessions USING (session_id)
                 WHERE attempts.authorization_id = ?1",
                params![recovery_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, Option<i64>>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, String>(10)?,
                        row.get::<_, Option<i64>>(11)?,
                        row.get::<_, String>(12)?,
                        row.get::<_, String>(13)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| LedgerError::Unavailable)?
            .ok_or(LedgerError::UnknownFileRecovery)?;
        let (
            proposal_digest,
            proposal_json,
            state,
            outcome,
            observation_json,
            record_id,
            record_hash,
            record_json,
            completed_at,
            prestate_hash,
            action_approval_json,
            approval_consumed_at,
            task_id,
            approved_session_json,
        ) = row;
        if state != "SUCCEEDED" || outcome.as_deref() != Some("SUCCEEDED") {
            return Err(LedgerError::UnknownFileRecovery);
        }
        let proposal: ToolCallProposal =
            serde_json::from_str(&proposal_json).map_err(|_| LedgerError::CorruptState)?;
        proposal.validate().map_err(|_| LedgerError::CorruptState)?;
        if proposal.extension_id != "developer"
            || proposal.tool_name != "delete_file"
            || proposal.digest()? != proposal_digest
        {
            return Err(LedgerError::UnknownFileRecovery);
        }
        let observation: ToolExecutionObservation = serde_json::from_str(
            observation_json
                .as_deref()
                .ok_or(LedgerError::CorruptState)?,
        )
        .map_err(|_| LedgerError::CorruptState)?;
        observation
            .validate()
            .map_err(|_| LedgerError::CorruptState)?;
        if observation.authorization_id()? != recovery_id
            || observation.proposal_digest != proposal_digest
            || observation.outcome != WireExecutionOutcome::Succeeded
        {
            return Err(LedgerError::CorruptState);
        }
        let result_digest = observation
            .result_digest
            .clone()
            .ok_or(LedgerError::CorruptState)?;
        parse_digest(&result_digest)?;

        let record: ExecutionRecord =
            serde_json::from_str(record_json.as_deref().ok_or(LedgerError::CorruptState)?)
                .map_err(|_| LedgerError::CorruptState)?;
        record.validate().map_err(|_| LedgerError::CorruptState)?;
        let parsed_record_id = record_id
            .as_deref()
            .ok_or(LedgerError::CorruptState)
            .and_then(|value| Uuid::parse_str(value).map_err(|_| LedgerError::CorruptState))?;
        let record_hash = record_hash.ok_or(LedgerError::CorruptState)?;
        if record.record_id != parsed_record_id
            || record.authorization_id != recovery_id
            || record.session_id != proposal.session_id
            || record.run_id != proposal.run_id
            || record.tool_call_id != proposal.tool_call_id
            || record.workspace != proposal.workspace_root
            || record.extension != proposal.extension_id
            || record.tool != proposal.tool_name
            || record.result_hash.to_string() != result_digest
            || record
                .digest()
                .map_err(|_| LedgerError::CorruptState)?
                .to_string()
                != record_hash
            || completed_at != Some(record.completed_at)
        {
            return Err(LedgerError::CorruptState);
        }

        let action_approval: ActionApproval =
            serde_json::from_str(&action_approval_json).map_err(|_| LedgerError::CorruptState)?;
        action_approval
            .validate()
            .map_err(|_| LedgerError::CorruptState)?;
        if action_approval.decision != ApprovalDecision::Approved
            || action_approval.proposal_digest.to_string() != proposal_digest
            || action_approval.session_id != proposal.session_id
            || action_approval.run_id != proposal.run_id
            || action_approval.tool_call_id != proposal.tool_call_id
            || action_approval.prestate_hash.to_string() != prestate_hash
            || approval_consumed_at.is_none()
        {
            return Err(LedgerError::CorruptState);
        }
        let approved_session: ApprovedSession =
            serde_json::from_str(&approved_session_json).map_err(|_| LedgerError::CorruptState)?;
        approved_session
            .validate()
            .map_err(|_| LedgerError::CorruptState)?;
        let task_id = Uuid::parse_str(&task_id).map_err(|_| LedgerError::CorruptState)?;
        if approved_session.task_id != task_id
            || approved_session.session_id != proposal.session_id
            || approved_session.run_id != proposal.run_id
            || approved_session.workspace_root != proposal.workspace_root
        {
            return Err(LedgerError::CorruptState);
        }

        Ok(DeletedFileRecoveryEvidence {
            authorization_id: recovery_id,
            task_id,
            proposal,
            prestate_hash: parse_digest(&prestate_hash)?,
            result_digest,
            record_id: parsed_record_id,
            record_hash,
        })
    }

    pub(crate) fn file_restore(
        &self,
        recovery_id: Uuid,
    ) -> Result<Option<StoredFileRestore>, LedgerError> {
        let connection = self.lock()?;
        let row = connection
            .query_row(
                "SELECT state, restore_id, challenge_hash, challenge_json, prepared_at,
                        record_hash, record_json
                  FROM file_restores WHERE recovery_id = ?1",
                params![recovery_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| LedgerError::Unavailable)?;
        let Some((
            state,
            restore_id,
            challenge_hash,
            challenge_json,
            prepared_at,
            record_hash,
            record_json,
        )) = row
        else {
            return Ok(None);
        };
        parse_digest(&challenge_hash)?;
        let challenge: FileRestoreChallenge =
            serde_json::from_str(&challenge_json).map_err(|_| LedgerError::CorruptState)?;
        challenge
            .validate()
            .map_err(|_| LedgerError::CorruptState)?;
        if challenge.recovery_id != recovery_id
            || restore_id != challenge.restore_id.to_string()
            || prepared_at != challenge.prepared_at
            || challenge.digest().map_err(|_| LedgerError::CorruptState)? != challenge_hash
        {
            return Err(LedgerError::CorruptState);
        }
        match (state.as_str(), record_hash, record_json) {
            ("PREPARED", None, None) => Ok(Some(StoredFileRestore::Prepared {
                challenge,
                challenge_hash,
            })),
            ("IN_FLIGHT", None, None) => Ok(Some(StoredFileRestore::InFlight {
                challenge,
                challenge_hash,
            })),
            ("SUCCEEDED", Some(record_hash), Some(record_json)) => {
                parse_digest(&record_hash)?;
                let record: FileRestoreRecord =
                    serde_json::from_str(&record_json).map_err(|_| LedgerError::CorruptState)?;
                record.validate().map_err(|_| LedgerError::CorruptState)?;
                if !record_matches_challenge(&record, &challenge, &challenge_hash)
                    || record.digest().map_err(|_| LedgerError::CorruptState)? != record_hash
                {
                    return Err(LedgerError::CorruptState);
                }
                Ok(Some(StoredFileRestore::Committed {
                    challenge,
                    challenge_hash,
                    record: Box::new(record),
                    record_hash,
                }))
            }
            _ => Err(LedgerError::CorruptState),
        }
    }

    pub(crate) fn insert_file_restore(
        &self,
        challenge: &FileRestoreChallenge,
        challenge_hash: &str,
        now: i64,
    ) -> Result<(), LedgerError> {
        challenge
            .validate()
            .map_err(|_| LedgerError::InvalidFileRestore)?;
        if challenge.prepared_at != now
            || challenge
                .digest()
                .map_err(|_| LedgerError::InvalidFileRestore)?
                != challenge_hash
        {
            return Err(LedgerError::InvalidFileRestore);
        }
        let challenge_json = serde_json::to_string(challenge).map_err(|_| LedgerError::Encoding)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| LedgerError::Unavailable)?;
        observe_clock(&transaction, now)?;
        transaction
            .execute(
                "INSERT INTO file_restores (
                     recovery_id, restore_id, challenge_hash, challenge_json, prepared_at, state
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 'PREPARED')",
                params![
                    challenge.recovery_id.to_string(),
                    challenge.restore_id.to_string(),
                    challenge_hash,
                    challenge_json,
                    now,
                ],
            )
            .map_err(|error| {
                if is_constraint(&error) {
                    LedgerError::ConflictingFileRestore
                } else {
                    LedgerError::Unavailable
                }
            })?;
        transaction.commit().map_err(|_| LedgerError::Unavailable)
    }

    pub(crate) fn complete_file_restore(
        &self,
        record: &FileRestoreRecord,
        record_hash: &str,
        now: i64,
    ) -> Result<(), LedgerError> {
        record
            .validate()
            .map_err(|_| LedgerError::InvalidFileRestore)?;
        if record.completed_at != now
            || record
                .digest()
                .map_err(|_| LedgerError::InvalidFileRestore)?
                != record_hash
        {
            return Err(LedgerError::InvalidFileRestore);
        }
        let record_json = serde_json::to_string(record).map_err(|_| LedgerError::Encoding)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| LedgerError::Unavailable)?;
        observe_clock(&transaction, now)?;
        let updated = transaction
            .execute(
                "UPDATE file_restores SET
                     state = 'SUCCEEDED', completed_at = ?1,
                     record_hash = ?2, record_json = ?3
                 WHERE recovery_id = ?4 AND restore_id = ?5
                   AND challenge_hash = ?6 AND state = 'IN_FLIGHT'",
                params![
                    now,
                    record_hash,
                    record_json,
                    record.recovery_id.to_string(),
                    record.restore_id.to_string(),
                    record.challenge_hash,
                ],
            )
            .map_err(|error| {
                if is_constraint(&error) {
                    LedgerError::ConflictingFileRestore
                } else {
                    LedgerError::Unavailable
                }
            })?;
        if updated != 1 {
            return Err(LedgerError::FileRestoreChallengeMismatch);
        }
        transaction.commit().map_err(|_| LedgerError::Unavailable)
    }

    pub(crate) fn begin_file_restore(
        &self,
        request: &crate::recovery::FileRestoreCommitRequest,
        now: i64,
    ) -> Result<(), LedgerError> {
        request
            .validate()
            .map_err(|_| LedgerError::InvalidFileRestore)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| LedgerError::Unavailable)?;
        observe_clock(&transaction, now)?;
        let updated = transaction
            .execute(
                "UPDATE file_restores SET state = 'IN_FLIGHT'
                 WHERE recovery_id = ?1 AND restore_id = ?2
                   AND challenge_hash = ?3 AND state = 'PREPARED'",
                params![
                    request.recovery_id.to_string(),
                    request.restore_id.to_string(),
                    request.challenge_hash,
                ],
            )
            .map_err(|_| LedgerError::Unavailable)?;
        if updated != 1 {
            return Err(LedgerError::FileRestoreChallengeMismatch);
        }
        transaction.commit().map_err(|_| LedgerError::Unavailable)
    }

    pub(crate) fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>, LedgerError> {
        self.connection.lock().map_err(|_| LedgerError::Unavailable)
    }

    pub(crate) fn begin_execution_scope(&self) -> Result<RwLockReadGuard<'_, ()>, LedgerError> {
        self.execution_barrier
            .read()
            .map_err(|_| LedgerError::Unavailable)
    }

    pub(crate) fn begin_recovery_scope(&self) -> Result<RwLockWriteGuard<'_, ()>, LedgerError> {
        self.execution_barrier
            .write()
            .map_err(|_| LedgerError::Unavailable)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptSnapshot {
    pub authorization_id: Uuid,
    pub proposal_digest: String,
    pub request_hash: String,
    pub state: String,
    pub outcome: Option<String>,
    pub consumed_at: i64,
    pub completed_at: Option<i64>,
    pub record_id: Option<Uuid>,
    pub record_hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReconciliationAttempt {
    pub authorization_id: Uuid,
    pub proposal_digest: String,
    pub request_hash: accordlock_agent_protocol::Digest32,
    pub state: String,
    pub observation_digest: Option<String>,
    pub record_id: Option<Uuid>,
    pub record_hash: Option<String>,
    pub prestate_hash: Option<accordlock_agent_protocol::Digest32>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeletedFileRecoveryEvidence {
    pub authorization_id: Uuid,
    pub task_id: Uuid,
    pub proposal: ToolCallProposal,
    pub prestate_hash: accordlock_agent_protocol::Digest32,
    pub result_digest: String,
    pub record_id: Uuid,
    pub record_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AuthorizationGrant {
    pub authorization_id: Uuid,
    pub proposal_digest: String,
    pub request_hash: accordlock_agent_protocol::Digest32,
    pub reason_code: &'static str,
    pub issued_at: i64,
    pub not_before: i64,
    pub expires_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AuthorizationResult {
    Allowed(AuthorizationGrant),
    Denied(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ObservationResult {
    pub authorization_id: Uuid,
    pub observation_digest: String,
    pub record_id: Uuid,
    pub record_hash: String,
}

/// Result of a trusted idempotent session-registration attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalRegistration {
    Inserted,
    AlreadyPresent,
}

/// Result of a trusted idempotent session-revocation attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevocationRegistration {
    Revoked,
    AlreadyRevoked,
}

/// Result of a trusted idempotent policy-approval registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionApprovalRegistration {
    Inserted,
    AlreadyPresent,
}

struct ObservationRecord {
    proposal_digest: String,
    proposal_json: String,
    request_hash: String,
    request_json: String,
    decision_json: String,
    authorization_json: String,
    intent_pre_evaluation_hash: Option<String>,
    intent_pre_evaluation_json: Option<String>,
    consumed_at: i64,
    state: String,
    observation_digest: Option<String>,
    record_id: Option<String>,
    record_hash: Option<String>,
}

fn validate_action_approval_session(
    transaction: &Transaction<'_>,
    action_approval: &ActionApproval,
) -> Result<(), LedgerError> {
    let session_json = transaction
        .query_row(
            "SELECT approval_json FROM approved_sessions WHERE session_id = ?1",
            params![action_approval.session_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| LedgerError::Unavailable)?
        .ok_or(LedgerError::UnknownApproval)?;
    let approved_session: ApprovedSession =
        serde_json::from_str(&session_json).map_err(|_| LedgerError::CorruptState)?;
    approved_session
        .validate()
        .map_err(|_| LedgerError::CorruptState)?;
    if approved_session.task_id != action_approval.task_id
        || approved_session.run_id != action_approval.run_id
        || approved_session.task_policy_hash != action_approval.task_policy_hash
        || action_approval.task_requirement.statement_hash
            != approved_session.task_policy.task_objective_hash
        || action_approval.policy_decision.policy_epoch != approved_session.policy_epoch
        || action_approval.policy_decision.evaluated_at != approved_session.approved_at
        || action_approval.transformation_step.recorded_at != approved_session.approved_at
        || action_approval.decided_at < approved_session.approved_at
        || action_approval.expires_at > approved_session.expires_at
    {
        return Err(LedgerError::ActionApprovalScopeMismatch);
    }
    let revoked = transaction
        .query_row(
            "SELECT 1 FROM revoked_sessions WHERE session_id = ?1",
            params![action_approval.session_id],
            |_| Ok(()),
        )
        .optional()
        .map_err(|_| LedgerError::Unavailable)?
        .is_some();
    if revoked {
        return Err(LedgerError::ActionApprovalScopeMismatch);
    }
    Ok(())
}

fn resolve_action_approval(
    transaction: &Transaction<'_>,
    approved_session: &ApprovedSession,
    proposal: &ToolCallProposal,
    proposal_digest: &str,
    approval_request: Option<&ActionApprovalRequest>,
    now: i64,
) -> Result<
    Result<
        (
            accordlock_agent_protocol::Digest32,
            accordlock_agent_protocol::Digest32,
        ),
        AuthorizationDenial,
    >,
    LedgerError,
> {
    let Some(context) = approval_request else {
        return Ok(Err(AuthorizationDenial::ExecutionContextRequired));
    };
    let Ok(context_hash) = context.digest() else {
        return Ok(Err(AuthorizationDenial::ApprovalScopeMismatch));
    };
    let expected_proposal_digest = parse_digest(proposal_digest)?;
    if context.task_id != approved_session.task_id
        || context.session_id != proposal.session_id
        || context.run_id != proposal.run_id
        || context.tool_call_id != proposal.tool_call_id
        || context.proposal_digest != expected_proposal_digest
        || context.task_policy_hash != approved_session.task_policy_hash
        || context.task_requirement.statement_hash
            != approved_session.task_policy.task_objective_hash
        || context.policy_decision.policy_epoch != approved_session.policy_epoch
        || context.policy_decision.evaluated_at != approved_session.approved_at
        || context.transformation_step.recorded_at != approved_session.approved_at
        || context.action.extension_id != proposal.extension_id
        || context.action.tool_name != proposal.tool_name
    {
        return Ok(Err(AuthorizationDenial::ApprovalScopeMismatch));
    }

    let record = transaction
        .query_row(
            "SELECT approval_json, consumed_at, policy_decision_hash FROM action_approvals
             WHERE session_id = ?1 AND run_id = ?2 AND tool_call_id = ?3",
            params![proposal.session_id, proposal.run_id, proposal.tool_call_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|_| LedgerError::Unavailable)?;
    let Some((approval_json, consumed_at, stored_policy_decision_hash)) = record else {
        return Ok(Err(AuthorizationDenial::ApprovalRequired));
    };
    let action_approval: ActionApproval =
        serde_json::from_str(&approval_json).map_err(|_| LedgerError::CorruptState)?;
    action_approval
        .validate()
        .map_err(|_| LedgerError::CorruptState)?;
    if action_approval.task_id != approved_session.task_id
        || action_approval.session_id != proposal.session_id
        || action_approval.run_id != proposal.run_id
        || action_approval.tool_call_id != proposal.tool_call_id
        || action_approval.proposal_digest != expected_proposal_digest
        || action_approval.task_policy_hash != approved_session.task_policy_hash
        || action_approval.prestate_hash != context.prestate_hash
        || action_approval.approval_request_hash != context_hash
        || action_approval.task_requirement != context.task_requirement
        || action_approval.transformation_step != context.transformation_step
        || action_approval.policy_decision != context.policy_decision
        || action_approval.policy_decision_hash != context.policy_decision_hash
        || parse_digest(&stored_policy_decision_hash)? != context.policy_decision_hash
    {
        return Ok(Err(AuthorizationDenial::ApprovalScopeMismatch));
    }
    if consumed_at.is_some() {
        return Ok(Err(AuthorizationDenial::ApprovalAlreadyUsed));
    }
    if action_approval.decided_at > now || now >= action_approval.expires_at {
        return Ok(Err(AuthorizationDenial::ApprovalExpired));
    }
    let updated = transaction
        .execute(
            "UPDATE action_approvals SET consumed_at = ?1
             WHERE approval_id = ?2 AND consumed_at IS NULL",
            params![now, action_approval.approval_id.to_string()],
        )
        .map_err(|_| LedgerError::Unavailable)?;
    if updated != 1 {
        return Ok(Err(AuthorizationDenial::ApprovalAlreadyUsed));
    }
    match action_approval.decision {
        ApprovalDecision::Approved => Ok(Ok((
            action_approval.approval_evidence_hash,
            action_approval.policy_decision_hash,
        ))),
        ApprovalDecision::Denied => Ok(Err(AuthorizationDenial::ApprovalDenied)),
    }
}

fn commit_denial(
    transaction: Transaction<'_>,
    proposal: &ToolCallProposal,
    proposal_digest: &str,
    reason: &'static str,
    now: i64,
) -> Result<AuthorizationResult, LedgerError> {
    transaction
        .execute(
            "INSERT INTO denied_proposals (
                 proposal_digest, session_id, run_id, tool_call_id, reason_code, recorded_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                proposal_digest,
                proposal.session_id,
                proposal.run_id,
                proposal.tool_call_id,
                reason,
                now,
            ],
        )
        .map_err(|_| LedgerError::Unavailable)?;
    transaction.commit().map_err(|_| LedgerError::Unavailable)?;
    Ok(AuthorizationResult::Denied(reason))
}

fn observe_clock(transaction: &Transaction<'_>, now: i64) -> Result<(), LedgerError> {
    let high_water = transaction
        .query_row(
            "SELECT integer_value FROM runtime_meta WHERE key = 'clock_high_water'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| LedgerError::CorruptState)?;
    if now < high_water {
        return Err(LedgerError::ClockRollback);
    }
    transaction
        .execute(
            "UPDATE runtime_meta SET integer_value = ?1 WHERE key = 'clock_high_water'",
            params![now],
        )
        .map_err(|_| LedgerError::Unavailable)?;
    Ok(())
}

fn require_exact_revocation_binding(
    transaction: &Transaction<'_>,
    revocation: &SessionRevocation,
) -> Result<(), LedgerError> {
    let mut statement = transaction
        .prepare(
            "SELECT task_id, session_id, run_id FROM approved_sessions
             WHERE session_id = ?1 OR task_id = ?2
             ORDER BY session_id",
        )
        .map_err(|_| LedgerError::Unavailable)?;
    let rows = statement
        .query_map(
            params![revocation.session_id, revocation.task_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .map_err(|_| LedgerError::Unavailable)?;
    let approved = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| LedgerError::Unavailable)?;
    if approved.is_empty() {
        return Err(LedgerError::UnknownApproval);
    }
    if approved.len() != 1
        || approved[0].0 != revocation.task_id.to_string()
        || approved[0].1 != revocation.session_id
        || approved[0].2 != revocation.run_id
    {
        return Err(LedgerError::RevocationBindingMismatch);
    }
    Ok(())
}

fn recorded_revocations(
    transaction: &Transaction<'_>,
    revocation: &SessionRevocation,
) -> Result<Vec<String>, LedgerError> {
    let mut statement = transaction
        .prepare(
            "SELECT revocation_json FROM revoked_sessions
             WHERE session_id = ?1 OR task_id = ?2
             ORDER BY session_id",
        )
        .map_err(|_| LedgerError::Unavailable)?;
    let rows = statement
        .query_map(
            params![revocation.session_id, revocation.task_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .map_err(|_| LedgerError::Unavailable)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|_| LedgerError::Unavailable)
}

fn session_event_high_water(
    transaction: &Transaction<'_>,
    session_id: &str,
) -> Result<i64, LedgerError> {
    transaction
        .query_row(
            "WITH session_events(event_at) AS (
                 SELECT approved_at FROM approved_sessions WHERE session_id = ?1
                 UNION ALL
                 SELECT decided_at FROM action_approvals WHERE session_id = ?1
                 UNION ALL
                 SELECT consumed_at FROM attempts WHERE session_id = ?1
                 UNION ALL
                 SELECT completed_at FROM attempts
                    WHERE session_id = ?1 AND completed_at IS NOT NULL
                 UNION ALL
                 SELECT recorded_at FROM denied_proposals WHERE session_id = ?1
                 UNION ALL
                 SELECT file_restores.prepared_at FROM file_restores
                    JOIN attempts ON attempts.authorization_id = file_restores.recovery_id
                    WHERE attempts.session_id = ?1
                 UNION ALL
                 SELECT file_restores.completed_at FROM file_restores
                    JOIN attempts ON attempts.authorization_id = file_restores.recovery_id
                    WHERE attempts.session_id = ?1
                      AND file_restores.completed_at IS NOT NULL
             )
             SELECT MAX(event_at) FROM session_events",
            params![session_id],
            |row| row.get::<_, Option<i64>>(0),
        )
        .map_err(|_| LedgerError::Unavailable)?
        .ok_or(LedgerError::CorruptState)
}

fn is_constraint(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(value, _)
            if value.code == ErrorCode::ConstraintViolation
    )
}

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("ledger path is invalid")]
    InvalidPath,
    #[error("ledger schema is incompatible")]
    IncompatibleSchema,
    #[error(
        "local alpha state predates the supported schema; export it if needed, then reset the local database"
    )]
    PreReleaseStateResetRequired,
    #[error("approved session is invalid")]
    InvalidApproval,
    #[error("approved session already exists")]
    DuplicateApproval,
    #[error("task or session identifier is already bound differently")]
    ConflictingApproval,
    #[error("task/session binding is invalid")]
    TaskBinding(#[from] TaskBindingError),
    #[error("session revocation binding is invalid")]
    SessionRevocationBinding(#[from] SessionRevocationError),
    #[error("session revocation is invalid")]
    InvalidRevocation,
    #[error("approved session is unknown")]
    UnknownApproval,
    #[error("session revocation does not match the approved authority")]
    RevocationBindingMismatch,
    #[error("a different session revocation is already committed")]
    ConflictingRevocation,
    #[error("policy approval binding is invalid")]
    ActionApprovalBinding(#[from] TaskPolicyError),
    #[error("policy approval does not match the approved authority")]
    ActionApprovalScopeMismatch,
    #[error("a different policy approval is already committed")]
    ConflictingActionApproval,
    #[error("wire request is invalid")]
    WireValidation,
    #[error("trusted time is invalid")]
    InvalidTime,
    #[error("trusted clock moved backwards")]
    ClockRollback,
    #[error("authorization is unknown")]
    UnknownAuthorization,
    #[error("observation does not match the consumed authorization")]
    ObservationBindingMismatch,
    #[error("a different observation is already committed")]
    ConflictingObservation,
    #[error("execution observation window has expired")]
    ObservationWindowExpired,
    #[error("file recovery is unknown")]
    UnknownFileRecovery,
    #[error("file restore record is invalid")]
    InvalidFileRestore,
    #[error("file restore challenge does not match")]
    FileRestoreChallengeMismatch,
    #[error("a different file restore is already committed")]
    ConflictingFileRestore,
    #[error("audit query is invalid")]
    InvalidAuditQuery,
    #[error("audit snapshot changed between pages")]
    AuditSnapshotChanged,
    #[error("audit history exceeds the supported local profile")]
    AuditHistoryTooLarge,
    #[error("one audit page cannot fit the private control frame")]
    AuditPageTooLarge,
    #[error("durable ledger state is corrupt")]
    CorruptState,
    #[error("protocol chain construction failed")]
    Protocol,
    #[error("durable record encoding failed")]
    Encoding,
    #[error("durable ledger is unavailable")]
    Unavailable,
}

impl From<WireValidationError> for LedgerError {
    fn from(_: WireValidationError) -> Self {
        Self::WireValidation
    }
}

#[cfg(test)]
mod tests {
    use accordlock_agent_protocol::Digest32;
    use serde_json::json;

    use super::*;
    use crate::{
        ActionApprovalRegistration, ActionType, ApprovalDecision, Capability,
        PreauthorizedCapability, SessionAuditQuery, TaskPolicy,
    };

    #[test]
    fn historical_ledger_is_queryable_but_cannot_restore_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let workspace = root.path().join("workspace");
        std::fs::create_dir(&workspace)?;
        let database = root.path().join("runtime.sqlite3");
        let writable = Ledger::open(&database)?;
        let approved = ApprovedSession::new(
            Uuid::new_v4(),
            "historical-session",
            "historical-run",
            &workspace,
            1,
            TaskPolicy::new(Digest32::sha256(b"historical objective"), [], [])?,
            [Capability::new("developer", "read")],
            100,
            200,
        )?;
        writable.approve_session(&approved)?;
        drop(writable);

        let historical = Ledger::open_read_only(&database)?;
        let page =
            historical.session_audit(&SessionAuditQuery::new(&approved.session_id, 0, 10))?;
        assert_eq!(page.task_id, approved.task_id);
        assert_eq!(page.session_id, approved.session_id);
        assert_eq!(page.run_id, approved.run_id);
        assert_eq!(page.total_events, 1);
        assert!(matches!(
            historical.approve_session(&ApprovedSession::new(
                Uuid::new_v4(),
                "forbidden-session",
                "forbidden-run",
                &workspace,
                1,
                TaskPolicy::new(Digest32::sha256(b"forbidden objective"), [], [])?,
                [Capability::new("developer", "read")],
                100,
                200,
            )?),
            Err(LedgerError::Unavailable)
        ));
        assert!(matches!(
            historical.session_audit(&SessionAuditQuery::new("forbidden-session", 0, 10)),
            Err(LedgerError::UnknownApproval)
        ));
        Ok(())
    }

    fn remove_v9_audit_artifacts(connection: &Connection) -> rusqlite::Result<()> {
        const TABLES: &[&str] = &[
            "approved_sessions",
            "approved_capabilities",
            "revoked_sessions",
            "attempts",
            "denied_proposals",
            "action_approvals",
            "file_restores",
        ];
        const OPERATIONS: &[&str] = &["insert", "update", "delete"];
        for table in TABLES {
            for operation in OPERATIONS {
                connection.execute_batch(&format!(
                    "DROP TRIGGER session_audit_revision_{table}_{operation};"
                ))?;
            }
        }
        connection.execute_batch("DROP TABLE audit_session_revisions;")
    }

    fn remove_v10_evaluation_artifacts(connection: &Connection) -> rusqlite::Result<()> {
        connection.execute_batch("ALTER TABLE attempts DROP COLUMN automatic_evaluation_json;")
    }

    fn remove_v11_execution_trace_artifacts(connection: &Connection) -> rusqlite::Result<()> {
        connection.execute_batch(
            "ALTER TABLE attempts DROP COLUMN execution_trace_hash;
             ALTER TABLE attempts DROP COLUMN execution_trace_json;",
        )
    }

    fn remove_v12_live_intent_artifacts(connection: &Connection) -> rusqlite::Result<()> {
        connection.execute_batch(
            "ALTER TABLE attempts DROP COLUMN intent_pre_evaluation_hash;
             ALTER TABLE attempts DROP COLUMN intent_pre_evaluation_json;
             ALTER TABLE attempts DROP COLUMN intent_complete_evaluation_hash;
             ALTER TABLE attempts DROP COLUMN intent_complete_evaluation_json;",
        )
    }

    fn remove_v8_audit_artifacts(connection: &Connection) -> rusqlite::Result<()> {
        const TRIGGERS: &[&str] = &[
            "audit_revision_approved_sessions_insert",
            "audit_revision_approved_sessions_update",
            "audit_revision_approved_sessions_delete",
            "audit_revision_approved_capabilities_insert",
            "audit_revision_approved_capabilities_update",
            "audit_revision_approved_capabilities_delete",
            "audit_revision_revoked_sessions_insert",
            "audit_revision_revoked_sessions_update",
            "audit_revision_revoked_sessions_delete",
            "audit_revision_attempts_insert",
            "audit_revision_attempts_update",
            "audit_revision_attempts_delete",
            "audit_revision_denied_proposals_insert",
            "audit_revision_denied_proposals_update",
            "audit_revision_denied_proposals_delete",
            "audit_revision_action_approvals_insert",
            "audit_revision_action_approvals_update",
            "audit_revision_action_approvals_delete",
            "audit_revision_file_restores_insert",
            "audit_revision_file_restores_update",
            "audit_revision_file_restores_delete",
        ];
        const INDEXES: &[&str] = &[
            "action_approvals_audit_idx",
            "attempts_started_audit_idx",
            "attempts_completed_audit_idx",
            "file_restores_audit_idx",
        ];
        for trigger in TRIGGERS {
            connection.execute_batch(&format!("DROP TRIGGER IF EXISTS {trigger};"))?;
        }
        for index in INDEXES {
            connection.execute_batch(&format!("DROP INDEX {index};"))?;
        }
        connection.execute("DELETE FROM runtime_meta WHERE key = 'audit_revision'", [])?;
        Ok(())
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one adversarial test keeps storage substitution and replay checks contiguous"
    )]
    fn policy_decision_is_stored_exactly_and_cannot_be_substituted_or_replayed()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let workspace = root.path().join("workspace");
        std::fs::create_dir(&workspace)?;
        let ledger = Ledger::open(&root.path().join("runtime.sqlite3"))?;
        let task_id = Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")?;
        let approval = ApprovedSession::new_with_task_objective(
            task_id,
            "session-1",
            "run-1",
            &workspace,
            19,
            "task objective",
            TaskPolicy::new(Digest32::sha256(b"task objective"), [], [])?,
            [Capability::new("developer", "write")],
            100,
            300,
        )?;
        ledger.approve_session(&approval)?;
        let arguments = json!({"content": "guarded", "path": "notes.txt"});
        let arguments_sha256 = goose_digest(&arguments)?;
        let proposal = ToolCallProposal {
            schema_version: crate::model::TOOL_EXECUTION_SCHEMA_VERSION,
            session_id: "session-1".to_owned(),
            run_id: "run-1".to_owned(),
            tool_call_id: "call-1".to_owned(),
            workspace_root: approval.workspace_root.clone(),
            extension_id: "developer".to_owned(),
            tool_name: "write".to_owned(),
            arguments_sha256: arguments_sha256.clone(),
            arguments,
            agent_plan_checkpoint: crate::model::test_agent_plan_checkpoint(
                "session-1",
                "run-1",
                "call-1",
                "developer__write",
                &arguments_sha256,
                119,
            ),
        };
        let context = ledger
            .action_approval_request(
                &proposal,
                Digest32::sha256(b"prestate"),
                ActionDescriptor {
                    extension_id: "developer".to_owned(),
                    tool_name: "write".to_owned(),
                    relative_path: "notes.txt".to_owned(),
                    action_type: ActionType::CreateFile,
                    requested_bytes: 7,
                    executable_path: None,
                    executable_sha256: None,
                },
            )?
            .ok_or("missing policy approval context")?;
        let action_approval = ActionApproval::for_context(
            &context,
            Uuid::parse_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")?,
            ApprovalDecision::Approved,
            Digest32::sha256(b"signed action approval"),
            110,
            180,
        )?;

        let mut substituted_hash = action_approval.clone();
        substituted_hash.policy_decision_hash = Digest32::sha256(b"substitution");
        assert!(matches!(
            ledger.register_action_approval(&substituted_hash),
            Err(LedgerError::ActionApprovalBinding(
                TaskPolicyError::InvalidEvaluationRecord
            ))
        ));
        assert_eq!(
            ledger.register_action_approval(&action_approval)?,
            ActionApprovalRegistration::Inserted
        );
        {
            let connection = ledger.lock()?;
            let stored_hash = connection.query_row(
                "SELECT policy_decision_hash FROM action_approvals WHERE approval_id = ?1",
                params![action_approval.approval_id.to_string()],
                |row| row.get::<_, String>(0),
            )?;
            assert_eq!(stored_hash, context.policy_decision_hash.to_string());
        }

        let AuthorizationResult::Allowed(grant) =
            ledger.authorize_and_consume(&proposal, Some(&context), None, 120, 30)?
        else {
            return Err("expected exact action authorization".into());
        };
        {
            let connection = ledger.lock()?;
            let (stored_hash, stored_json) = connection.query_row(
                "SELECT intent_pre_evaluation_hash, intent_pre_evaluation_json
                 FROM attempts WHERE authorization_id = ?1",
                params![grant.authorization_id.to_string()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )?;
            let stored: PreExecutionLiveIntentBundle = serde_json::from_str(&stored_json)?;
            stored.revalidate(&approval, &proposal)?;
            assert_eq!(stored.record.digest()?.to_string(), stored_hash);
        }
        let result_digest = Digest32::sha256(b"guarded write result");
        ledger.observe(
            &ToolExecutionObservation {
                schema_version: crate::model::TOOL_EXECUTION_SCHEMA_VERSION,
                authorization_id: grant.authorization_id.to_string(),
                proposal_digest: grant.proposal_digest.clone(),
                request_hash: grant.request_hash.to_string(),
                outcome: WireExecutionOutcome::Succeeded,
                result_digest: Some(result_digest.to_string()),
            },
            130,
        )?;
        {
            let connection = ledger.lock()?;
            let (stored_hash, stored_json) = connection.query_row(
                "SELECT intent_complete_evaluation_hash, intent_complete_evaluation_json
                 FROM attempts WHERE authorization_id = ?1",
                params![grant.authorization_id.to_string()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )?;
            let stored: crate::CompleteLiveIntentBundle = serde_json::from_str(&stored_json)?;
            stored.revalidate(&approval, &proposal, result_digest)?;
            assert_eq!(stored.record.digest()?.to_string(), stored_hash);
        }
        assert_eq!(
            ledger.authorize_and_consume(&proposal, Some(&context), None, 131, 30)?,
            AuthorizationResult::Denied("ACTION_APPROVAL_ALREADY_USED")
        );
        Ok(())
    }

    #[test]
    fn revocation_rejects_backdating_without_breaking_exact_retry_idempotence()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let workspace = root.path().join("workspace");
        std::fs::create_dir(&workspace)?;
        let ledger = Ledger::open(&root.path().join("runtime.sqlite3"))?;
        let task_id = Uuid::parse_str("cccccccc-cccc-4ccc-8ccc-cccccccccccc")?;
        let approval = ApprovedSession::new_with_task_objective(
            task_id,
            "session-revocation-clock",
            "run-revocation-clock",
            &workspace,
            1,
            "inspect the workspace",
            TaskPolicy::new(
                Digest32::sha256(b"inspect the workspace"),
                [PreauthorizedCapability::new("developer", "read")],
                [],
            )?,
            [Capability::new("developer", "read")],
            100,
            300,
        )?;
        ledger.approve_session(&approval)?;
        let revocation =
            SessionRevocation::new(task_id, "session-revocation-clock", "run-revocation-clock");

        assert!(matches!(
            ledger.revoke_session_at(&revocation, 99),
            Err(LedgerError::InvalidTime)
        ));

        let arguments = json!({"path": "notes.txt"});
        let arguments_sha256 = goose_digest(&arguments)?;
        let proposal = ToolCallProposal {
            schema_version: crate::model::TOOL_EXECUTION_SCHEMA_VERSION,
            session_id: approval.session_id.clone(),
            run_id: approval.run_id.clone(),
            tool_call_id: "read-before-revocation".to_owned(),
            workspace_root: approval.workspace_root.clone(),
            extension_id: "developer".to_owned(),
            tool_name: "read".to_owned(),
            arguments_sha256: arguments_sha256.clone(),
            arguments,
            agent_plan_checkpoint: crate::model::test_agent_plan_checkpoint(
                &approval.session_id,
                &approval.run_id,
                "read-before-revocation",
                "developer__read",
                &arguments_sha256,
                119,
            ),
        };
        assert!(matches!(
            ledger.authorize_and_consume(
                &proposal,
                None,
                Some(AutomaticExecutionClass::LocalFileRead),
                120,
                30,
            )?,
            AuthorizationResult::Allowed(_)
        ));
        assert!(matches!(
            ledger.revoke_session_at(&revocation, 119),
            Err(LedgerError::InvalidTime)
        ));
        {
            let connection = ledger.lock()?;
            let revocations = connection.query_row(
                "SELECT COUNT(*) FROM revoked_sessions WHERE session_id = ?1",
                params![approval.session_id],
                |row| row.get::<_, i64>(0),
            )?;
            assert_eq!(revocations, 0);
        }

        assert_eq!(
            ledger.revoke_session_at(&revocation, 120)?,
            RevocationRegistration::Revoked
        );
        assert_eq!(
            ledger.revoke_session_at(&revocation, -1)?,
            RevocationRegistration::AlreadyRevoked
        );
        Ok(())
    }

    #[test]
    fn pre_release_schema_versions_are_rejected_without_modification()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        for version in 1..=4 {
            let database = root.path().join(format!("runtime-v{version}.sqlite3"));
            let connection = Connection::open(&database)?;
            connection.execute_batch(&format!(
                "CREATE TABLE preserved_state (value TEXT NOT NULL);
                 INSERT INTO preserved_state(value) VALUES ('keep');
                 PRAGMA user_version = {version};"
            ))?;
            drop(connection);

            assert!(matches!(
                Ledger::open(&database),
                Err(LedgerError::PreReleaseStateResetRequired)
            ));

            let connection = Connection::open(&database)?;
            let retained_version =
                connection.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?;
            let retained_value =
                connection.query_row("SELECT value FROM preserved_state", [], |row| {
                    row.get::<_, String>(0)
                })?;
            assert_eq!(retained_version, version);
            assert_eq!(retained_value, "keep");
        }
        Ok(())
    }

    #[test]
    fn fresh_ledger_boots_at_current_schema() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let database = root.path().join("runtime.sqlite3");
        let ledger = Ledger::open(&database)?;
        let connection = ledger.lock()?;
        let version =
            connection.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?;
        let live_tables = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'table'
               AND name IN ('approved_sessions', 'attempts', 'action_approvals', 'file_restores')",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        let audit_revision = connection.query_row(
            "SELECT integer_value FROM runtime_meta WHERE key = 'audit_revision'",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        let audit_triggers = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'trigger' AND name LIKE 'audit_revision_%'",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        let session_audit_revisions =
            connection.query_row("SELECT COUNT(*) FROM audit_session_revisions", [], |row| {
                row.get::<_, i64>(0)
            })?;
        let session_audit_triggers = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'trigger' AND name LIKE 'session_audit_revision_%'",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        assert_eq!(version, SCHEMA_VERSION);
        assert_eq!(live_tables, 4);
        assert_eq!(audit_revision, 1);
        assert_eq!(audit_triggers, 0);
        assert_eq!(session_audit_revisions, 0);
        assert_eq!(session_audit_triggers, 21);
        Ok(())
    }

    #[test]
    fn schema_eleven_upgrade_adds_live_intent_evidence_without_losing_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let database = root.path().join("runtime-v11.sqlite3");
        let ledger = Ledger::open(&database)?;
        {
            let connection = ledger.lock()?;
            connection.execute_batch(
                "CREATE TABLE preserved_state (value TEXT NOT NULL);
                 INSERT INTO preserved_state(value) VALUES ('keep');",
            )?;
            remove_v12_live_intent_artifacts(&connection)?;
            connection.execute_batch("PRAGMA user_version = 11;")?;
        }
        drop(ledger);

        let upgraded = Ledger::open(&database)?;
        let connection = upgraded.lock()?;
        let version =
            connection.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?;
        let retained = connection.query_row("SELECT value FROM preserved_state", [], |row| {
            row.get::<_, String>(0)
        })?;
        let live_columns = connection.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('attempts')
             WHERE name IN (
                 'intent_pre_evaluation_hash', 'intent_pre_evaluation_json',
                 'intent_complete_evaluation_hash', 'intent_complete_evaluation_json'
             )",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        assert_eq!(version, SCHEMA_VERSION);
        assert_eq!(retained, "keep");
        assert_eq!(live_columns, 4);
        Ok(())
    }

    #[test]
    fn schema_seven_is_upgraded_additively_for_immutable_audit_snapshots()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let database = root.path().join("runtime-v7.sqlite3");
        let ledger = Ledger::open(&database)?;
        {
            let connection = ledger.lock()?;
            remove_v12_live_intent_artifacts(&connection)?;
            remove_v11_execution_trace_artifacts(&connection)?;
            remove_v10_evaluation_artifacts(&connection)?;
            remove_v9_audit_artifacts(&connection)?;
            remove_v8_audit_artifacts(&connection)?;
            connection.execute_batch(
                "CREATE TABLE preserved_state (value TEXT NOT NULL);
                 INSERT INTO preserved_state(value) VALUES ('keep');
                 PRAGMA user_version = 7;",
            )?;
        }
        drop(ledger);

        let upgraded = Ledger::open(&database)?;
        let connection = upgraded.lock()?;
        let version =
            connection.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?;
        let retained_value =
            connection.query_row("SELECT value FROM preserved_state", [], |row| {
                row.get::<_, String>(0)
            })?;
        let audit_revision = connection.query_row(
            "SELECT integer_value FROM runtime_meta WHERE key = 'audit_revision'",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        let session_audit_table = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'table' AND name = 'audit_session_revisions'",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        assert_eq!(version, SCHEMA_VERSION);
        assert_eq!(retained_value, "keep");
        assert_eq!(audit_revision, 1);
        assert_eq!(session_audit_table, 1);
        Ok(())
    }

    #[test]
    fn schema_eight_upgrade_seeds_and_advances_existing_session_revisions()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let workspace = root.path().join("workspace");
        std::fs::create_dir(&workspace)?;
        let database = root.path().join("runtime-v8.sqlite3");
        let ledger = Ledger::open(&database)?;
        let approval = ApprovedSession::new(
            Uuid::parse_str("dddddddd-dddd-4ddd-8ddd-dddddddddddd")?,
            "migrated-session",
            "migrated-run",
            &workspace,
            1,
            TaskPolicy::new(Digest32::sha256(b"migration objective"), [], [])?,
            [Capability::new("developer", "read")],
            100,
            300,
        )?;
        ledger.approve_session(&approval)?;
        {
            let connection = ledger.lock()?;
            remove_v12_live_intent_artifacts(&connection)?;
            remove_v11_execution_trace_artifacts(&connection)?;
            remove_v10_evaluation_artifacts(&connection)?;
            remove_v9_audit_artifacts(&connection)?;
            connection.execute_batch("PRAGMA user_version = 8;")?;
        }
        drop(ledger);

        let upgraded = Ledger::open(&database)?;
        let connection = upgraded.lock()?;
        let seeded = connection.query_row(
            "SELECT integer_value FROM audit_session_revisions WHERE session_id = ?1",
            params![approval.session_id],
            |row| row.get::<_, i64>(0),
        )?;
        assert_eq!(seeded, 1);
        connection.execute(
            "INSERT INTO denied_proposals (
                 proposal_digest, session_id, run_id, tool_call_id, reason_code, recorded_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                Digest32::sha256(b"migrated denial").to_string(),
                approval.session_id,
                approval.run_id,
                "migrated-call",
                "CAPABILITY_NOT_APPROVED",
                120_i64,
            ],
        )?;
        let advanced = connection.query_row(
            "SELECT integer_value FROM audit_session_revisions WHERE session_id = ?1",
            params![approval.session_id],
            |row| row.get::<_, i64>(0),
        )?;
        assert_eq!(advanced, 2);
        Ok(())
    }

    #[test]
    fn schema_five_is_upgraded_additively_for_file_restores()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let database = root.path().join("runtime-v5.sqlite3");
        let ledger = Ledger::open(&database)?;
        {
            let connection = ledger.lock()?;
            remove_v12_live_intent_artifacts(&connection)?;
            remove_v11_execution_trace_artifacts(&connection)?;
            remove_v10_evaluation_artifacts(&connection)?;
            remove_v9_audit_artifacts(&connection)?;
            remove_v8_audit_artifacts(&connection)?;
            connection.execute_batch(
                "CREATE TABLE preserved_state (value TEXT NOT NULL);
                 INSERT INTO preserved_state(value) VALUES ('keep');
                 DROP TABLE file_restores;
                 ALTER TABLE revoked_sessions DROP COLUMN revoked_at;
                 PRAGMA user_version = 5;",
            )?;
        }
        drop(ledger);

        let upgraded = Ledger::open(&database)?;
        let connection = upgraded.lock()?;
        let version =
            connection.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?;
        let retained_value =
            connection.query_row("SELECT value FROM preserved_state", [], |row| {
                row.get::<_, String>(0)
            })?;
        let restore_table = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'table' AND name = 'file_restores'",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        assert_eq!(version, SCHEMA_VERSION);
        assert_eq!(retained_value, "keep");
        assert_eq!(restore_table, 1);
        Ok(())
    }
}
