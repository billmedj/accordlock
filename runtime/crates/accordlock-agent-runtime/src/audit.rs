use accordlock_agent_protocol::{
    AuthorizationDecision, AuthorizationOutcome, ExecutionAuthorization, ExecutionOutcome,
    ExecutionRecord, ExecutionRequest, MAX_RUN_ID_BYTES, MAX_SESSION_ID_BYTES,
    MAX_TOOL_CALL_ID_BYTES,
};
use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    canonical::{digest_bytes, domain_digest, goose_digest},
    execution_trace::{
        CompletedExecutionEvidence, TaskControlProjection, TaskControlProvenance, TaskReviewStatus,
        TaskScopeStatus,
    },
    filesystem::{FilesystemResult, result_digest, validated_automatic_execution_class},
    ledger::{Ledger, LedgerError},
    live_intent::{CompleteLiveIntentBundle, IntentAssessment, PreExecutionLiveIntentBundle},
    model::{
        ApprovedSession, DESKTOP_PROTOCOL_SCHEMA_VERSION, MAX_CAPABILITIES, SessionRevocation,
        ToolCallProposal, ToolExecutionObservation, WireExecutionOutcome, parse_digest,
    },
    policy::{
        ActionApproval, ApprovalDecision, AutomaticActionEvaluation, AutomaticEvaluationInput,
    },
    recovery::{FileRestoreChallenge, FileRestoreRecord, record_matches_challenge},
};

#[cfg(test)]
use crate::model::TOOL_EXECUTION_SCHEMA_VERSION;

/// Maximum number of compact events returned through one private control frame.
pub const MAX_AUDIT_PAGE_EVENTS: u16 = 100;
/// Maximum encoded size of the page itself. The remaining 4 KiB is reserved for
/// the ALC1 response envelope and framing below the 256 KiB channel ceiling.
pub const MAX_AUDIT_PAGE_ENCODED_BYTES: usize = 252 * 1_024;
/// Current session-audit response profile. Queries remain on the stable wire profile.
pub const SESSION_AUDIT_PAGE_SCHEMA_VERSION: u16 = 6;
/// V6 session-audit page digest domain, including its terminating NUL byte.
pub const SESSION_AUDIT_PAGE_DIGEST_DOMAIN: &[u8] = b"accordlock:v6:session-audit-page\0";

const MAX_AUDIT_OFFSET: u32 = 100_000;
const MAX_AUDIT_TOTAL_EVENTS: u32 = MAX_AUDIT_OFFSET;
const MAX_SAFE_JSON_INTEGER: i64 = 9_007_199_254_740_991;
const MAX_AUDIT_RELATIVE_PATH_BYTES: usize = 4 * 1_024;
const MAX_AUDIT_SOURCE_ROW_BYTES: u64 = 1_024 * 1_024;
const MAX_AUDIT_PAGE_SOURCE_BYTES: u64 = 4 * 1_024 * 1_024;
const NO_TOOL_RESULT_PREIMAGE: &[u8] = b"accordlock:v2:agent-no-tool-result:transport-error";

/// Bounded query for one exact approved session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionAuditQuery {
    pub schema_version: u16,
    pub session_id: String,
    pub offset: u32,
    pub limit: u16,
    /// Omitted only for the first page. Every continuation must repeat the
    /// exact durable revision returned by that first page.
    #[serde(default)]
    pub snapshot_revision: Option<i64>,
}

impl SessionAuditQuery {
    #[must_use]
    pub fn new(session_id: impl Into<String>, offset: u32, limit: u16) -> Self {
        Self {
            schema_version: DESKTOP_PROTOCOL_SCHEMA_VERSION,
            session_id: session_id.into(),
            offset,
            limit,
            snapshot_revision: None,
        }
    }

    #[must_use]
    pub fn for_snapshot(
        session_id: impl Into<String>,
        offset: u32,
        limit: u16,
        snapshot_revision: i64,
    ) -> Self {
        Self {
            schema_version: DESKTOP_PROTOCOL_SCHEMA_VERSION,
            session_id: session_id.into(),
            offset,
            limit,
            snapshot_revision: Some(snapshot_revision),
        }
    }

    fn validate(&self) -> Result<(), LedgerError> {
        if self.schema_version != DESKTOP_PROTOCOL_SCHEMA_VERSION
            || !valid_audit_text(&self.session_id, MAX_SESSION_ID_BYTES)
            || self.offset > MAX_AUDIT_OFFSET
            || !(1..=MAX_AUDIT_PAGE_EVENTS).contains(&self.limit)
            || self
                .snapshot_revision
                .is_some_and(|value| !(0..=MAX_SAFE_JSON_INTEGER).contains(&value))
            || (self.offset > 0 && self.snapshot_revision.is_none())
        {
            return Err(LedgerError::InvalidAuditQuery);
        }
        Ok(())
    }
}

/// Compact, non-secret facts rendered by the Desktop audit timeline.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionAuditEvent {
    SessionApproved {
        event_id: String,
        recorded_at: i64,
        task_id: Uuid,
        run_id: String,
        workspace_root: String,
        policy_hash: String,
        expires_at: i64,
    },
    SessionRevoked {
        event_id: String,
        recorded_at: i64,
        task_id: Uuid,
        run_id: String,
        revocation_digest: String,
    },
    ActionDecision {
        event_id: String,
        recorded_at: i64,
        approval_id: Uuid,
        tool_call_id: String,
        proposal_digest: String,
        decision: ApprovalDecision,
        evidence_hash: String,
        consumed: bool,
    },
    ActionStarted {
        event_id: String,
        recorded_at: i64,
        authorization_id: Uuid,
        tool_call_id: String,
        extension_id: String,
        tool_name: String,
        proposal_digest: String,
        request_hash: String,
        conformance_evaluation_hashes: Vec<String>,
        task_scope_status: TaskScopeStatus,
        review_status: TaskReviewStatus,
        decision_reason_code: String,
        task_control_hash: String,
        task_control_provenance: String,
        intent_evaluation_hash: String,
        intent_assessment: IntentAssessment,
    },
    ActionCompleted {
        event_id: String,
        recorded_at: i64,
        authorization_id: Uuid,
        tool_call_id: String,
        outcome: String,
        state: String,
        record_hash: Option<String>,
        execution_lineage_hash: String,
        task_scope_status: TaskScopeStatus,
        review_status: TaskReviewStatus,
        decision_reason_code: String,
        task_control_hash: String,
        task_control_provenance: TaskControlProvenance,
        intent_pre_evaluation_hash: String,
        intent_complete_evaluation_hash: Option<String>,
        intent_pre_assessment: IntentAssessment,
        intent_complete_assessment: IntentAssessment,
    },
    ActionDenied {
        event_id: String,
        recorded_at: i64,
        denial_id: i64,
        attempted_run_id: String,
        tool_call_id: String,
        proposal_digest: String,
        reason_code: String,
    },
    RestorePrepared {
        event_id: String,
        recorded_at: i64,
        restore_id: Uuid,
        recovery_id: Uuid,
        relative_path: String,
        content_hash: String,
    },
    RestoreCompleted {
        event_id: String,
        recorded_at: i64,
        restore_id: Uuid,
        recovery_id: Uuid,
        relative_path: String,
        record_hash: String,
    },
}

impl SessionAuditEvent {
    const fn recorded_at(&self) -> i64 {
        match self {
            Self::SessionApproved { recorded_at, .. }
            | Self::SessionRevoked { recorded_at, .. }
            | Self::ActionDecision { recorded_at, .. }
            | Self::ActionStarted { recorded_at, .. }
            | Self::ActionCompleted { recorded_at, .. }
            | Self::ActionDenied { recorded_at, .. }
            | Self::RestorePrepared { recorded_at, .. }
            | Self::RestoreCompleted { recorded_at, .. } => *recorded_at,
        }
    }
}

/// One deterministic page from the durable execution log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SessionAuditPage {
    pub schema_version: u16,
    pub task_id: Uuid,
    pub session_id: String,
    pub run_id: String,
    pub offset: u32,
    pub next_offset: Option<u32>,
    pub total_events: u32,
    /// Durable revision captured by the first page and required by every
    /// continuation. It changes on every audit-relevant row mutation.
    pub snapshot_revision: i64,
    pub snapshot_at: i64,
    pub events: Vec<SessionAuditEvent>,
    pub page_digest: String,
}

const AUDIT_STATS_SQL: &str = r"
WITH audit_events(recorded_at) AS (
    SELECT approved_at FROM approved_sessions WHERE session_id = ?1
    UNION ALL
    SELECT revoked_at FROM revoked_sessions WHERE session_id = ?1
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
    SELECT file_restores.prepared_at
        FROM file_restores
        JOIN attempts ON attempts.authorization_id = file_restores.recovery_id
        WHERE attempts.session_id = ?1
    UNION ALL
    SELECT file_restores.completed_at
        FROM file_restores
        JOIN attempts ON attempts.authorization_id = file_restores.recovery_id
        WHERE attempts.session_id = ?1 AND file_restores.completed_at IS NOT NULL
), bounded_events(recorded_at) AS MATERIALIZED (
    SELECT recorded_at FROM audit_events LIMIT ?2
)
SELECT COUNT(*), MAX(recorded_at) FROM bounded_events
";

const AUDIT_PAGE_REFS_SQL: &str = r"
WITH audit_events(kind, source_id, recorded_at) AS (
    SELECT 'SESSION_APPROVED', session_id, approved_at
        FROM approved_sessions WHERE session_id = ?1
    UNION ALL
    SELECT 'SESSION_REVOKED', session_id, revoked_at
        FROM revoked_sessions WHERE session_id = ?1
    UNION ALL
    SELECT 'ACTION_DECISION', approval_id, decided_at
        FROM action_approvals WHERE session_id = ?1
    UNION ALL
    SELECT 'ACTION_STARTED', authorization_id, consumed_at
        FROM attempts WHERE session_id = ?1
    UNION ALL
    SELECT 'ACTION_COMPLETED', authorization_id, completed_at
        FROM attempts WHERE session_id = ?1 AND completed_at IS NOT NULL
    UNION ALL
    SELECT 'ACTION_DENIED', CAST(denial_id AS TEXT), recorded_at
        FROM denied_proposals WHERE session_id = ?1
    UNION ALL
    SELECT 'RESTORE_PREPARED', file_restores.restore_id, file_restores.prepared_at
        FROM file_restores
        JOIN attempts ON attempts.authorization_id = file_restores.recovery_id
        WHERE attempts.session_id = ?1
    UNION ALL
    SELECT 'RESTORE_COMPLETED', file_restores.restore_id, file_restores.completed_at
        FROM file_restores
        JOIN attempts ON attempts.authorization_id = file_restores.recovery_id
        WHERE attempts.session_id = ?1 AND file_restores.completed_at IS NOT NULL
)
SELECT kind, substr(source_id, 1, 513), recorded_at,
       length(CAST(source_id AS BLOB))
FROM audit_events
ORDER BY recorded_at DESC, kind DESC, substr(source_id, 1, 513) DESC
LIMIT ?2 OFFSET ?3
";

const APPROVAL_SOURCE_BYTES_SQL: &str = r"
SELECT length(CAST(task_id AS BLOB)) + length(CAST(run_id AS BLOB))
     + length(CAST(workspace_root AS BLOB)) + length(CAST(task_policy_hash AS BLOB))
     + length(CAST(approval_json AS BLOB))
FROM approved_sessions WHERE session_id = ?1
";

const REVOCATION_SOURCE_BYTES_SQL: &str = r"
SELECT length(CAST(task_id AS BLOB)) + length(CAST(run_id AS BLOB))
     + length(CAST(revocation_digest AS BLOB)) + length(CAST(revocation_json AS BLOB))
FROM revoked_sessions WHERE session_id = ?1
";

const ACTION_APPROVAL_SOURCE_BYTES_SQL: &str = r"
SELECT length(CAST(approval_id AS BLOB)) + length(CAST(session_id AS BLOB))
     + length(CAST(run_id AS BLOB)) + length(CAST(tool_call_id AS BLOB))
     + length(CAST(proposal_digest AS BLOB)) + length(CAST(task_policy_hash AS BLOB))
     + length(CAST(prestate_hash AS BLOB)) + length(CAST(approval_request_hash AS BLOB))
     + length(CAST(policy_decision_hash AS BLOB)) + length(CAST(decision AS BLOB))
     + length(CAST(approval_evidence_hash AS BLOB)) + length(CAST(approval_json AS BLOB))
FROM action_approvals WHERE approval_id = ?1
";

const ATTEMPT_SOURCE_BYTES_SQL: &str = r"
SELECT length(CAST(attempts.proposal_digest AS BLOB))
     + length(CAST(attempts.session_id AS BLOB)) + length(CAST(attempts.run_id AS BLOB))
     + length(CAST(attempts.tool_call_id AS BLOB))
     + length(CAST(attempts.proposal_json AS BLOB))
     + length(CAST(attempts.request_hash AS BLOB))
     + length(CAST(attempts.request_json AS BLOB))
     + length(CAST(attempts.authorization_decision_hash AS BLOB))
     + length(CAST(attempts.decision_json AS BLOB))
     + length(CAST(COALESCE(attempts.automatic_evaluation_json, '') AS BLOB))
     + length(CAST(COALESCE(attempts.intent_pre_evaluation_hash, '') AS BLOB))
     + length(CAST(COALESCE(attempts.intent_pre_evaluation_json, '') AS BLOB))
     + length(CAST(COALESCE(attempts.intent_complete_evaluation_hash, '') AS BLOB))
     + length(CAST(COALESCE(attempts.intent_complete_evaluation_json, '') AS BLOB))
     + length(CAST(attempts.authorization_id AS BLOB))
     + length(CAST(attempts.authorization_hash AS BLOB))
     + length(CAST(attempts.authorization_json AS BLOB))
     + length(CAST(attempts.state AS BLOB))
     + length(CAST(COALESCE(attempts.outcome, '') AS BLOB))
     + length(CAST(COALESCE(attempts.observation_digest, '') AS BLOB))
     + length(CAST(COALESCE(attempts.observation_json, '') AS BLOB))
     + length(CAST(COALESCE(attempts.record_id, '') AS BLOB))
     + length(CAST(COALESCE(attempts.record_hash, '') AS BLOB))
     + length(CAST(COALESCE(attempts.record_json, '') AS BLOB))
     + length(CAST(COALESCE(attempts.execution_trace_hash, '') AS BLOB))
     + length(CAST(COALESCE(attempts.execution_trace_json, '') AS BLOB))
     + COALESCE(length(CAST(action_approvals.approval_id AS BLOB)), 0)
     + COALESCE(length(CAST(action_approvals.session_id AS BLOB)), 0)
     + COALESCE(length(CAST(action_approvals.run_id AS BLOB)), 0)
     + COALESCE(length(CAST(action_approvals.tool_call_id AS BLOB)), 0)
     + COALESCE(length(CAST(action_approvals.proposal_digest AS BLOB)), 0)
     + COALESCE(length(CAST(action_approvals.task_policy_hash AS BLOB)), 0)
     + COALESCE(length(CAST(action_approvals.prestate_hash AS BLOB)), 0)
     + COALESCE(length(CAST(action_approvals.approval_request_hash AS BLOB)), 0)
     + COALESCE(length(CAST(action_approvals.policy_decision_hash AS BLOB)), 0)
     + COALESCE(length(CAST(action_approvals.decision AS BLOB)), 0)
     + COALESCE(length(CAST(action_approvals.approval_evidence_hash AS BLOB)), 0)
     + COALESCE(length(CAST(action_approvals.approval_json AS BLOB)), 0)
FROM attempts
LEFT JOIN action_approvals ON action_approvals.proposal_digest = attempts.proposal_digest
WHERE attempts.authorization_id = ?1
";

const DENIAL_SOURCE_BYTES_SQL: &str = r"
SELECT length(CAST(proposal_digest AS BLOB)) + length(CAST(session_id AS BLOB))
     + length(CAST(run_id AS BLOB)) + length(CAST(tool_call_id AS BLOB))
     + length(CAST(reason_code AS BLOB))
FROM denied_proposals WHERE CAST(denial_id AS TEXT) = ?1
";

const RESTORE_SOURCE_BYTES_SQL: &str = r"
SELECT length(CAST(file_restores.recovery_id AS BLOB))
     + length(CAST(file_restores.restore_id AS BLOB))
     + length(CAST(file_restores.challenge_hash AS BLOB))
     + length(CAST(file_restores.challenge_json AS BLOB))
     + length(CAST(file_restores.state AS BLOB))
     + length(CAST(COALESCE(file_restores.record_hash, '') AS BLOB))
     + length(CAST(COALESCE(file_restores.record_json, '') AS BLOB))
     + length(CAST(attempts.proposal_digest AS BLOB))
     + length(CAST(attempts.session_id AS BLOB)) + length(CAST(attempts.run_id AS BLOB))
     + length(CAST(attempts.tool_call_id AS BLOB))
     + length(CAST(attempts.proposal_json AS BLOB))
     + length(CAST(attempts.request_hash AS BLOB))
     + length(CAST(attempts.request_json AS BLOB))
     + length(CAST(attempts.authorization_decision_hash AS BLOB))
     + length(CAST(attempts.decision_json AS BLOB))
     + length(CAST(attempts.authorization_id AS BLOB))
     + length(CAST(attempts.authorization_hash AS BLOB))
     + length(CAST(attempts.authorization_json AS BLOB))
     + length(CAST(attempts.state AS BLOB))
     + length(CAST(COALESCE(attempts.outcome, '') AS BLOB))
     + length(CAST(COALESCE(attempts.observation_digest, '') AS BLOB))
     + length(CAST(COALESCE(attempts.observation_json, '') AS BLOB))
     + length(CAST(COALESCE(attempts.record_id, '') AS BLOB))
     + length(CAST(COALESCE(attempts.record_hash, '') AS BLOB))
     + length(CAST(COALESCE(attempts.record_json, '') AS BLOB))
     + COALESCE(length(CAST(action_approvals.approval_id AS BLOB)), 0)
     + COALESCE(length(CAST(action_approvals.session_id AS BLOB)), 0)
     + COALESCE(length(CAST(action_approvals.run_id AS BLOB)), 0)
     + COALESCE(length(CAST(action_approvals.tool_call_id AS BLOB)), 0)
     + COALESCE(length(CAST(action_approvals.proposal_digest AS BLOB)), 0)
     + COALESCE(length(CAST(action_approvals.task_policy_hash AS BLOB)), 0)
     + COALESCE(length(CAST(action_approvals.prestate_hash AS BLOB)), 0)
     + COALESCE(length(CAST(action_approvals.approval_request_hash AS BLOB)), 0)
     + COALESCE(length(CAST(action_approvals.policy_decision_hash AS BLOB)), 0)
     + COALESCE(length(CAST(action_approvals.decision AS BLOB)), 0)
     + COALESCE(length(CAST(action_approvals.approval_evidence_hash AS BLOB)), 0)
     + COALESCE(length(CAST(action_approvals.approval_json AS BLOB)), 0)
FROM file_restores
JOIN attempts ON attempts.authorization_id = file_restores.recovery_id
LEFT JOIN action_approvals ON action_approvals.proposal_digest = attempts.proposal_digest
WHERE file_restores.restore_id = ?1
";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuditEventKind {
    SessionApproved,
    SessionRevoked,
    ActionDecision,
    ActionStarted,
    ActionCompleted,
    ActionDenied,
    RestorePrepared,
    RestoreCompleted,
}

impl AuditEventKind {
    fn parse(value: &str) -> Result<Self, LedgerError> {
        match value {
            "SESSION_APPROVED" => Ok(Self::SessionApproved),
            "SESSION_REVOKED" => Ok(Self::SessionRevoked),
            "ACTION_DECISION" => Ok(Self::ActionDecision),
            "ACTION_STARTED" => Ok(Self::ActionStarted),
            "ACTION_COMPLETED" => Ok(Self::ActionCompleted),
            "ACTION_DENIED" => Ok(Self::ActionDenied),
            "RESTORE_PREPARED" => Ok(Self::RestorePrepared),
            "RESTORE_COMPLETED" => Ok(Self::RestoreCompleted),
            _ => Err(LedgerError::CorruptState),
        }
    }

    const fn max_source_id_bytes(self) -> usize {
        match self {
            Self::SessionApproved | Self::SessionRevoked => MAX_SESSION_ID_BYTES,
            Self::ActionDecision
            | Self::ActionStarted
            | Self::ActionCompleted
            | Self::RestorePrepared
            | Self::RestoreCompleted => 36,
            Self::ActionDenied => 16,
        }
    }
}

#[derive(Clone, Debug)]
struct AuditEventRef {
    kind: AuditEventKind,
    source_id: String,
    recorded_at: i64,
}

#[derive(Debug)]
struct StoredActionApprovalRow {
    approval_id: String,
    session_id: String,
    run_id: String,
    tool_call_id: String,
    proposal_digest: String,
    task_policy_hash: String,
    prestate_hash: String,
    approval_request_hash: String,
    policy_decision_hash: String,
    decision: String,
    approval_evidence_hash: String,
    decided_at: i64,
    expires_at: i64,
    consumed_at: Option<i64>,
    approval_json: String,
}

#[derive(Debug)]
struct StoredAttemptRow {
    proposal_digest: String,
    session_id: String,
    run_id: String,
    tool_call_id: String,
    proposal_json: String,
    request_hash: String,
    request_json: String,
    authorization_decision_hash: String,
    decision_json: String,
    automatic_evaluation_json: Option<String>,
    intent_pre_evaluation_hash: Option<String>,
    intent_pre_evaluation_json: Option<String>,
    intent_complete_evaluation_hash: Option<String>,
    intent_complete_evaluation_json: Option<String>,
    authorization_id: String,
    authorization_hash: String,
    authorization_json: String,
    consumed_at: i64,
    state: String,
    outcome: Option<String>,
    completed_at: Option<i64>,
    observation_digest: Option<String>,
    observation_json: Option<String>,
    record_id: Option<String>,
    record_hash: Option<String>,
    record_json: Option<String>,
    execution_trace_hash: Option<String>,
    execution_trace_json: Option<String>,
}

#[derive(Clone, Debug)]
struct VerifiedAttempt {
    proposal: ToolCallProposal,
    decision_outcome: AuthorizationOutcome,
    authorization_id: Uuid,
    request_hash: String,
    consumed_at: i64,
    state: String,
    outcome: Option<String>,
    completed_at: Option<i64>,
    record_hash: Option<String>,
    record: Option<ExecutionRecord>,
    execution_lineage_hash: Option<String>,
    task_control: TaskControlProjection,
    task_control_provenance: Option<TaskControlProvenance>,
    intent_pre_evaluation_hash: String,
    intent_complete_evaluation_hash: Option<String>,
    intent_pre_assessment: IntentAssessment,
    intent_complete_assessment: Option<IntentAssessment>,
}

#[derive(Debug)]
struct StoredRestoreRow {
    recovery_id: String,
    restore_id: String,
    challenge_hash: String,
    challenge_json: String,
    prepared_at: i64,
    state: String,
    completed_at: Option<i64>,
    record_hash: Option<String>,
    record_json: Option<String>,
}

impl Ledger {
    /// Reads one immutable, SQL-bounded audit page for one exact session.
    ///
    /// The first page captures a durable audit revision. A continuation whose
    /// revision no longer matches fails explicitly instead of silently shifting
    /// offset pagination. Only the selected rows are decoded, fully rebound,
    /// and hashed before they are projected.
    ///
    /// # Errors
    ///
    /// Rejects malformed queries, unknown sessions, snapshot drift, oversized
    /// histories/pages, corrupt records, and unavailable storage.
    pub fn session_audit(
        &self,
        query: &SessionAuditQuery,
    ) -> Result<SessionAuditPage, LedgerError> {
        query.validate()?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| LedgerError::Unavailable)?;

        preflight_approved_source(&transaction, &query.session_id)?;
        let approved = load_approved_session(&transaction, &query.session_id)?;
        let snapshot_revision = read_audit_revision(&transaction, &query.session_id)?;
        if query
            .snapshot_revision
            .is_some_and(|expected| expected != snapshot_revision)
        {
            return Err(LedgerError::AuditSnapshotChanged);
        }

        let (total_events, snapshot_at) = read_audit_stats(&transaction, &query.session_id)?;
        let references = read_audit_refs(&transaction, query)?;
        let mut events = Vec::with_capacity(references.len());
        let mut source_bytes = 0_u64;
        for reference in references {
            let row_bytes = audit_source_row_bytes(&transaction, &reference)?;
            let next_source_bytes = source_bytes
                .checked_add(row_bytes)
                .ok_or(LedgerError::AuditPageTooLarge)?;
            if next_source_bytes > MAX_AUDIT_PAGE_SOURCE_BYTES {
                break;
            }
            events.push(load_verified_event(&transaction, &approved, &reference)?);
            source_bytes = next_source_bytes;
        }
        validate_event_order(&events)?;

        let page = build_bounded_page(
            &approved,
            query.offset,
            total_events,
            snapshot_revision,
            snapshot_at,
            events,
        )?;
        transaction.commit().map_err(|_| LedgerError::Unavailable)?;
        Ok(page)
    }
}

fn read_audit_revision(connection: &Connection, session_id: &str) -> Result<i64, LedgerError> {
    let revision = connection
        .query_row(
            "SELECT integer_value FROM audit_session_revisions WHERE session_id = ?1",
            params![session_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| LedgerError::CorruptState)?;
    if !(0..=MAX_SAFE_JSON_INTEGER).contains(&revision) {
        return Err(LedgerError::CorruptState);
    }
    Ok(revision)
}

fn read_audit_stats(connection: &Connection, session_id: &str) -> Result<(u32, i64), LedgerError> {
    let (count, snapshot_at) = connection
        .query_row(
            AUDIT_STATS_SQL,
            params![session_id, i64::from(MAX_AUDIT_TOTAL_EVENTS) + 1],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?)),
        )
        .map_err(|_| LedgerError::Unavailable)?;
    let count = u32::try_from(count).map_err(|_| LedgerError::AuditHistoryTooLarge)?;
    if count == 0 || count > MAX_AUDIT_TOTAL_EVENTS {
        return Err(if count == 0 {
            LedgerError::CorruptState
        } else {
            LedgerError::AuditHistoryTooLarge
        });
    }
    let snapshot_at = snapshot_at.ok_or(LedgerError::CorruptState)?;
    if !(0..=MAX_SAFE_JSON_INTEGER).contains(&snapshot_at) {
        return Err(LedgerError::CorruptState);
    }
    Ok((count, snapshot_at))
}

fn read_audit_refs(
    connection: &Connection,
    query: &SessionAuditQuery,
) -> Result<Vec<AuditEventRef>, LedgerError> {
    let mut statement = connection
        .prepare(AUDIT_PAGE_REFS_SQL)
        .map_err(|_| LedgerError::Unavailable)?;
    let rows = statement
        .query_map(
            params![
                query.session_id,
                i64::from(query.limit),
                i64::from(query.offset)
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .map_err(|_| LedgerError::Unavailable)?;
    let mut references = Vec::with_capacity(usize::from(query.limit));
    for row in rows {
        let (kind, source_id, recorded_at, source_id_bytes) =
            row.map_err(|_| LedgerError::Unavailable)?;
        let kind = AuditEventKind::parse(&kind)?;
        if references.len() >= usize::from(query.limit)
            || !(0..=MAX_SAFE_JSON_INTEGER).contains(&recorded_at)
            || source_id_bytes <= 0
            || usize::try_from(source_id_bytes).ok() != Some(source_id.len())
            || source_id.len() > kind.max_source_id_bytes()
        {
            return Err(LedgerError::CorruptState);
        }
        references.push(AuditEventRef {
            kind,
            source_id,
            recorded_at,
        });
    }
    Ok(references)
}

fn audit_source_row_bytes(
    connection: &Connection,
    reference: &AuditEventRef,
) -> Result<u64, LedgerError> {
    let sql = match reference.kind {
        AuditEventKind::SessionApproved => APPROVAL_SOURCE_BYTES_SQL,
        AuditEventKind::SessionRevoked => REVOCATION_SOURCE_BYTES_SQL,
        AuditEventKind::ActionDecision => ACTION_APPROVAL_SOURCE_BYTES_SQL,
        AuditEventKind::ActionStarted | AuditEventKind::ActionCompleted => ATTEMPT_SOURCE_BYTES_SQL,
        AuditEventKind::ActionDenied => DENIAL_SOURCE_BYTES_SQL,
        AuditEventKind::RestorePrepared | AuditEventKind::RestoreCompleted => {
            RESTORE_SOURCE_BYTES_SQL
        }
    };
    let source_bytes = connection
        .query_row(sql, params![reference.source_id], |row| {
            row.get::<_, i64>(0)
        })
        .optional()
        .map_err(|_| LedgerError::Unavailable)?
        .ok_or(LedgerError::CorruptState)?;
    bounded_source_bytes(source_bytes)
}

fn preflight_approved_source(connection: &Connection, session_id: &str) -> Result<(), LedgerError> {
    let source_bytes = connection
        .query_row(APPROVAL_SOURCE_BYTES_SQL, params![session_id], |row| {
            row.get::<_, i64>(0)
        })
        .optional()
        .map_err(|_| LedgerError::Unavailable)?
        .ok_or(LedgerError::UnknownApproval)?;
    bounded_source_bytes(source_bytes).map(|_| ())
}

fn bounded_source_bytes(source_bytes: i64) -> Result<u64, LedgerError> {
    let source_bytes = u64::try_from(source_bytes).map_err(|_| LedgerError::CorruptState)?;
    if source_bytes == 0 || source_bytes > MAX_AUDIT_SOURCE_ROW_BYTES {
        return Err(LedgerError::CorruptState);
    }
    Ok(source_bytes)
}

fn load_verified_event(
    connection: &Connection,
    approved: &ApprovedSession,
    reference: &AuditEventRef,
) -> Result<SessionAuditEvent, LedgerError> {
    match reference.kind {
        AuditEventKind::SessionApproved => {
            if reference.source_id != approved.session_id
                || reference.recorded_at != approved.approved_at
            {
                return Err(LedgerError::CorruptState);
            }
            let digest = goose_digest(approved).map_err(|_| LedgerError::CorruptState)?;
            Ok(SessionAuditEvent::SessionApproved {
                event_id: format!("session-approved:{digest}"),
                recorded_at: approved.approved_at,
                task_id: approved.task_id,
                run_id: approved.run_id.clone(),
                workspace_root: approved.workspace_root.clone(),
                policy_hash: approved.task_policy_hash.to_string(),
                expires_at: approved.expires_at,
            })
        }
        AuditEventKind::SessionRevoked => load_verified_revocation(connection, approved, reference),
        AuditEventKind::ActionDecision => {
            load_verified_action_decision(connection, approved, reference)
        }
        AuditEventKind::ActionStarted | AuditEventKind::ActionCompleted => {
            load_verified_attempt_event(connection, approved, reference)
        }
        AuditEventKind::ActionDenied => load_verified_denial(connection, approved, reference),
        AuditEventKind::RestorePrepared | AuditEventKind::RestoreCompleted => {
            load_verified_restore_event(connection, approved, reference)
        }
    }
}

fn load_approved_session(
    connection: &Connection,
    session_id: &str,
) -> Result<ApprovedSession, LedgerError> {
    let row = connection
        .query_row(
            "SELECT task_id, run_id, workspace_root, policy_epoch, task_policy_hash,
                    approved_at, expires_at, approval_json
             FROM approved_sessions WHERE session_id = ?1",
            params![session_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, String>(7)?,
                ))
            },
        )
        .optional()
        .map_err(|_| LedgerError::Unavailable)?
        .ok_or(LedgerError::UnknownApproval)?;
    let approved: ApprovedSession =
        serde_json::from_str(&row.7).map_err(|_| LedgerError::CorruptState)?;
    approved
        .validate_durable()
        .map_err(|_| LedgerError::CorruptState)?;
    if approved.session_id != session_id
        || approved.task_id.to_string() != row.0
        || approved.run_id != row.1
        || approved.workspace_root != row.2
        || i64::try_from(approved.policy_epoch).ok() != Some(row.3)
        || approved.task_policy_hash.to_string() != row.4
        || approved.approved_at != row.5
        || approved.expires_at != row.6
        || !(0..=MAX_SAFE_JSON_INTEGER).contains(&approved.expires_at)
    {
        return Err(LedgerError::CorruptState);
    }

    let mut statement = connection
        .prepare(
            "SELECT substr(extension_id, 1, 257), length(CAST(extension_id AS BLOB)),
                    substr(tool_name, 1, 257), length(CAST(tool_name AS BLOB))
             FROM approved_capabilities
             WHERE session_id = ?1 ORDER BY extension_id, tool_name LIMIT ?2",
        )
        .map_err(|_| LedgerError::Unavailable)?;
    let capability_row_limit =
        i64::try_from(MAX_CAPABILITIES + 1).map_err(|_| LedgerError::CorruptState)?;
    let rows = statement
        .query_map(params![session_id, capability_row_limit], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(|_| LedgerError::Unavailable)?;
    let stored = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| LedgerError::Unavailable)?;
    if stored.len() > MAX_CAPABILITIES
        || stored
            .iter()
            .any(|(extension, extension_bytes, tool, tool_bytes)| {
                usize::try_from(*extension_bytes).ok() != Some(extension.len())
                    || usize::try_from(*tool_bytes).ok() != Some(tool.len())
                    || extension.len() > 256
                    || tool.len() > 256
            })
    {
        return Err(LedgerError::CorruptState);
    }
    let stored = stored
        .into_iter()
        .map(|(extension, _, tool, _)| (extension, tool))
        .collect::<Vec<_>>();
    let expected = approved
        .capabilities
        .iter()
        .map(|capability| {
            (
                capability.extension_id.clone(),
                capability.tool_name.clone(),
            )
        })
        .collect::<Vec<_>>();
    if stored != expected {
        return Err(LedgerError::CorruptState);
    }
    Ok(approved)
}

fn load_verified_revocation(
    connection: &Connection,
    approved: &ApprovedSession,
    reference: &AuditEventRef,
) -> Result<SessionAuditEvent, LedgerError> {
    let row = connection
        .query_row(
            "SELECT task_id, run_id, revocation_digest, revocation_json, revoked_at
             FROM revoked_sessions WHERE session_id = ?1",
            params![approved.session_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|_| LedgerError::Unavailable)?
        .ok_or(LedgerError::CorruptState)?;
    let revocation: SessionRevocation =
        serde_json::from_str(&row.3).map_err(|_| LedgerError::CorruptState)?;
    revocation
        .validate()
        .map_err(|_| LedgerError::CorruptState)?;
    if reference.source_id != approved.session_id
        || reference.recorded_at != row.4
        || row.0 != approved.task_id.to_string()
        || row.1 != approved.run_id
        || revocation.task_id != approved.task_id
        || revocation.session_id != approved.session_id
        || revocation.run_id != approved.run_id
        || goose_digest(&revocation).map_err(|_| LedgerError::CorruptState)? != row.2
    {
        return Err(LedgerError::CorruptState);
    }
    Ok(SessionAuditEvent::SessionRevoked {
        event_id: format!("session-revoked:{}", row.2),
        recorded_at: row.4,
        task_id: revocation.task_id,
        run_id: revocation.run_id,
        revocation_digest: row.2,
    })
}

fn load_verified_action_decision(
    connection: &Connection,
    approved: &ApprovedSession,
    reference: &AuditEventRef,
) -> Result<SessionAuditEvent, LedgerError> {
    let (record, consumed_at) = verify_action_approval(connection, approved, &reference.source_id)?;
    if reference.recorded_at != record.decided_at {
        return Err(LedgerError::CorruptState);
    }
    Ok(SessionAuditEvent::ActionDecision {
        event_id: format!("action-decision:{}", record.approval_id),
        recorded_at: record.decided_at,
        approval_id: record.approval_id,
        tool_call_id: record.tool_call_id,
        proposal_digest: record.proposal_digest.to_string(),
        decision: record.decision,
        evidence_hash: record.approval_evidence_hash.to_string(),
        consumed: consumed_at.is_some(),
    })
}

fn verify_action_approval(
    connection: &Connection,
    approved: &ApprovedSession,
    approval_id: &str,
) -> Result<(ActionApproval, Option<i64>), LedgerError> {
    let row = connection
        .query_row(
            "SELECT approval_id, session_id, run_id, tool_call_id, proposal_digest,
                    task_policy_hash, prestate_hash, approval_request_hash,
                    policy_decision_hash, decision, approval_evidence_hash,
                    decided_at, expires_at, consumed_at, approval_json
             FROM action_approvals WHERE approval_id = ?1 AND session_id = ?2",
            params![approval_id, approved.session_id],
            |row| {
                Ok(StoredActionApprovalRow {
                    approval_id: row.get(0)?,
                    session_id: row.get(1)?,
                    run_id: row.get(2)?,
                    tool_call_id: row.get(3)?,
                    proposal_digest: row.get(4)?,
                    task_policy_hash: row.get(5)?,
                    prestate_hash: row.get(6)?,
                    approval_request_hash: row.get(7)?,
                    policy_decision_hash: row.get(8)?,
                    decision: row.get(9)?,
                    approval_evidence_hash: row.get(10)?,
                    decided_at: row.get(11)?,
                    expires_at: row.get(12)?,
                    consumed_at: row.get(13)?,
                    approval_json: row.get(14)?,
                })
            },
        )
        .optional()
        .map_err(|_| LedgerError::Unavailable)?
        .ok_or(LedgerError::CorruptState)?;
    let record: ActionApproval =
        serde_json::from_str(&row.approval_json).map_err(|_| LedgerError::CorruptState)?;
    record.validate().map_err(|_| LedgerError::CorruptState)?;
    let expected_decision = match record.decision {
        ApprovalDecision::Approved => "APPROVED",
        ApprovalDecision::Denied => "DENIED",
    };
    if record.approval_id.to_string() != row.approval_id
        || record.approval_id.to_string() != approval_id
        || record.task_id != approved.task_id
        || record.session_id != row.session_id
        || record.session_id != approved.session_id
        || record.run_id != row.run_id
        || record.run_id != approved.run_id
        || record.tool_call_id != row.tool_call_id
        || record.proposal_digest.to_string() != row.proposal_digest
        || record.task_policy_hash.to_string() != row.task_policy_hash
        || record.task_policy_hash != approved.task_policy_hash
        || record.prestate_hash.to_string() != row.prestate_hash
        || record.approval_request_hash.to_string() != row.approval_request_hash
        || record.policy_decision_hash.to_string() != row.policy_decision_hash
        || expected_decision != row.decision
        || record.approval_evidence_hash.to_string() != row.approval_evidence_hash
        || record.decided_at != row.decided_at
        || record.expires_at != row.expires_at
        || record.decided_at < approved.approved_at
        || record.expires_at > approved.expires_at
        || record.task_requirement.statement_hash != approved.task_policy.task_objective_hash
        || record.policy_decision.policy_epoch != approved.policy_epoch
        || record.policy_decision.evaluated_at != approved.approved_at
        || record.transformation_step.recorded_at != approved.approved_at
        || row
            .consumed_at
            .is_some_and(|value| value < record.decided_at || value >= record.expires_at)
    {
        return Err(LedgerError::CorruptState);
    }
    Ok((record, row.consumed_at))
}

fn load_stored_attempt(
    connection: &Connection,
    approved: &ApprovedSession,
    authorization_id: &str,
) -> Result<StoredAttemptRow, LedgerError> {
    connection
        .query_row(
            "SELECT proposal_digest, session_id, run_id, tool_call_id, proposal_json,
                    request_hash, request_json, authorization_decision_hash, decision_json,
                    automatic_evaluation_json, intent_pre_evaluation_hash,
                    intent_pre_evaluation_json, intent_complete_evaluation_hash,
                    intent_complete_evaluation_json, authorization_id, authorization_hash,
                    authorization_json, consumed_at,
                    state, outcome, completed_at, observation_digest, observation_json,
                    record_id, record_hash, record_json,
                    execution_trace_hash, execution_trace_json
             FROM attempts WHERE authorization_id = ?1 AND session_id = ?2",
            params![authorization_id, approved.session_id],
            |row| {
                Ok(StoredAttemptRow {
                    proposal_digest: row.get(0)?,
                    session_id: row.get(1)?,
                    run_id: row.get(2)?,
                    tool_call_id: row.get(3)?,
                    proposal_json: row.get(4)?,
                    request_hash: row.get(5)?,
                    request_json: row.get(6)?,
                    authorization_decision_hash: row.get(7)?,
                    decision_json: row.get(8)?,
                    automatic_evaluation_json: row.get(9)?,
                    intent_pre_evaluation_hash: row.get(10)?,
                    intent_pre_evaluation_json: row.get(11)?,
                    intent_complete_evaluation_hash: row.get(12)?,
                    intent_complete_evaluation_json: row.get(13)?,
                    authorization_id: row.get(14)?,
                    authorization_hash: row.get(15)?,
                    authorization_json: row.get(16)?,
                    consumed_at: row.get(17)?,
                    state: row.get(18)?,
                    outcome: row.get(19)?,
                    completed_at: row.get(20)?,
                    observation_digest: row.get(21)?,
                    observation_json: row.get(22)?,
                    record_id: row.get(23)?,
                    record_hash: row.get(24)?,
                    record_json: row.get(25)?,
                    execution_trace_hash: row.get(26)?,
                    execution_trace_json: row.get(27)?,
                })
            },
        )
        .optional()
        .map_err(|_| LedgerError::Unavailable)?
        .ok_or(LedgerError::CorruptState)
}

fn verify_automatic_evaluation(
    row: &StoredAttemptRow,
    approved: &ApprovedSession,
    proposal: &ToolCallProposal,
    proposal_digest: &str,
    decision: &AuthorizationDecision,
) -> Result<(), LedgerError> {
    let automatic = approved
        .task_policy
        .allows_automatic(&proposal.extension_id, &proposal.tool_name);
    if !automatic {
        return if row.automatic_evaluation_json.is_none()
            && decision.conformance_evaluation_hashes.is_empty()
        {
            Ok(())
        } else {
            Err(LedgerError::CorruptState)
        };
    }

    let execution_class =
        validated_automatic_execution_class(proposal, &approved.task_policy.protected_paths)
            .ok_or(LedgerError::CorruptState)?;
    let evaluation: AutomaticActionEvaluation = serde_json::from_str(
        row.automatic_evaluation_json
            .as_deref()
            .ok_or(LedgerError::CorruptState)?,
    )
    .map_err(|_| LedgerError::CorruptState)?;
    let input = AutomaticEvaluationInput {
        task_id: approved.task_id,
        session_id: &proposal.session_id,
        run_id: &proposal.run_id,
        tool_call_id: &proposal.tool_call_id,
        proposal_digest: parse_digest(proposal_digest)?,
        extension_id: &proposal.extension_id,
        tool_name: &proposal.tool_name,
        task_policy: &approved.task_policy,
        task_policy_hash: approved.task_policy_hash,
        policy_epoch: approved.policy_epoch,
        evaluated_at: decision.decided_at,
    };
    evaluation
        .validate_for(input, execution_class)
        .map_err(|_| LedgerError::CorruptState)?;
    evaluation.digest().map_err(|_| LedgerError::CorruptState)?;
    let conformance_hash = evaluation
        .conformance_evaluation_hash()
        .map_err(|_| LedgerError::CorruptState)?;
    if decision.policy_decision_hash != evaluation.policy_decision_hash
        || decision.conformance_evaluation_hashes != [conformance_hash]
    {
        return Err(LedgerError::CorruptState);
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn verify_attempt(
    connection: &Connection,
    approved: &ApprovedSession,
    authorization_id: &str,
) -> Result<VerifiedAttempt, LedgerError> {
    let row = load_stored_attempt(connection, approved, authorization_id)?;
    let proposal: ToolCallProposal =
        serde_json::from_str(&row.proposal_json).map_err(|_| LedgerError::CorruptState)?;
    proposal.validate().map_err(|_| LedgerError::CorruptState)?;
    let proposal_digest = proposal.digest().map_err(|_| LedgerError::CorruptState)?;
    let request: ExecutionRequest =
        serde_json::from_str(&row.request_json).map_err(|_| LedgerError::CorruptState)?;
    request.validate().map_err(|_| LedgerError::CorruptState)?;
    let request_digest = request.digest().map_err(|_| LedgerError::CorruptState)?;
    let decision: AuthorizationDecision =
        serde_json::from_str(&row.decision_json).map_err(|_| LedgerError::CorruptState)?;
    decision.validate().map_err(|_| LedgerError::CorruptState)?;
    let decision_digest = decision.digest().map_err(|_| LedgerError::CorruptState)?;
    let authorization: ExecutionAuthorization =
        serde_json::from_str(&row.authorization_json).map_err(|_| LedgerError::CorruptState)?;
    authorization
        .verify_for(&request, &decision)
        .map_err(|_| LedgerError::CorruptState)?;
    let authorization_digest = authorization
        .digest()
        .map_err(|_| LedgerError::CorruptState)?;

    let expected_decision_reason = match decision.outcome {
        AuthorizationOutcome::Allow => "POLICY_CONFORMANT",
        AuthorizationOutcome::AllowAfterApproval => "ACTION_APPROVAL_ACCEPTED",
        AuthorizationOutcome::ApprovalRequired | AuthorizationOutcome::Deny => {
            return Err(LedgerError::CorruptState);
        }
    };
    let automatic = approved
        .task_policy
        .allows_automatic(&proposal.extension_id, &proposal.tool_name);
    verify_automatic_evaluation(&row, approved, &proposal, &proposal_digest, &decision)?;
    if row.proposal_digest != proposal_digest
        || row.session_id != proposal.session_id
        || row.run_id != proposal.run_id
        || row.tool_call_id != proposal.tool_call_id
        || proposal.session_id != approved.session_id
        || proposal.run_id != approved.run_id
        || proposal.workspace_root != approved.workspace_root
        || !approved.authorizes(&proposal.extension_id, &proposal.tool_name)
        || request_digest.to_string() != row.request_hash
        || request.session_id != proposal.session_id
        || request.run_id != proposal.run_id
        || request.tool_call_id != proposal.tool_call_id
        || request.workspace != proposal.workspace_root
        || request.extension != proposal.extension_id
        || request.tool != proposal.tool_name
        || request.canonical_args_hash
            != proposal
                .arguments_digest()
                .map_err(|_| LedgerError::CorruptState)?
        || request.policy_epoch != approved.policy_epoch
        || request.task_policy_hash != approved.task_policy_hash
        || request.created_at < approved.approved_at
        || request.expires_at > approved.expires_at
        || (decision.outcome == AuthorizationOutcome::Allow) != automatic
        || (decision.outcome == AuthorizationOutcome::AllowAfterApproval) == automatic
        || decision_digest.to_string() != row.authorization_decision_hash
        || decision.reason_code != expected_decision_reason
        || authorization.authorization_id.to_string() != row.authorization_id
        || authorization.authorization_id.to_string() != authorization_id
        || authorization_digest.to_string() != row.authorization_hash
        || row.consumed_at != request.created_at
        || row.consumed_at != decision.decided_at
        || row.consumed_at != authorization.issued_at
        || row.consumed_at != authorization.not_before
        || request.expires_at != decision.expires_at
        || request.expires_at != authorization.expires_at
    {
        return Err(LedgerError::CorruptState);
    }

    if decision.outcome == AuthorizationOutcome::AllowAfterApproval {
        let approval_id = connection
            .query_row(
                "SELECT approval_id FROM action_approvals
                 WHERE session_id = ?1 AND run_id = ?2 AND tool_call_id = ?3
                   AND proposal_digest = ?4",
                params![
                    approved.session_id,
                    approved.run_id,
                    proposal.tool_call_id,
                    proposal_digest
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| LedgerError::Unavailable)?
            .ok_or(LedgerError::CorruptState)?;
        let (action_approval, approval_consumed_at) =
            verify_action_approval(connection, approved, &approval_id)?;
        if action_approval.decision != ApprovalDecision::Approved
            || action_approval.proposal_digest.to_string() != proposal_digest
            || action_approval.tool_call_id != proposal.tool_call_id
            || action_approval.approval_evidence_hash
                != decision
                    .approval_evidence_hash
                    .ok_or(LedgerError::CorruptState)?
            || action_approval.policy_decision_hash != decision.policy_decision_hash
            || approval_consumed_at != Some(row.consumed_at)
        {
            return Err(LedgerError::CorruptState);
        }
    }

    let task_control =
        TaskControlProjection::from_decision(&decision).map_err(|_| LedgerError::CorruptState)?;
    let intent_pre_evaluation_hash = row
        .intent_pre_evaluation_hash
        .clone()
        .ok_or(LedgerError::CorruptState)?;
    let intent_pre_evaluation: PreExecutionLiveIntentBundle = serde_json::from_str(
        row.intent_pre_evaluation_json
            .as_deref()
            .ok_or(LedgerError::CorruptState)?,
    )
    .map_err(|_| LedgerError::CorruptState)?;
    intent_pre_evaluation
        .revalidate(approved, &proposal)
        .map_err(|_| LedgerError::CorruptState)?;
    if intent_pre_evaluation
        .record
        .digest()
        .map_err(|_| LedgerError::CorruptState)?
        .to_string()
        != intent_pre_evaluation_hash
        || decision.intent_evaluation_hash
            != parse_digest(&intent_pre_evaluation_hash).map_err(|_| LedgerError::CorruptState)?
    {
        return Err(LedgerError::CorruptState);
    }
    let intent_pre_assessment = intent_pre_evaluation
        .assessment()
        .map_err(|_| LedgerError::CorruptState)?;

    if row.state == "IN_FLIGHT" {
        if row.outcome.is_some()
            || row.completed_at.is_some()
            || row.observation_digest.is_some()
            || row.observation_json.is_some()
            || row.record_id.is_some()
            || row.record_hash.is_some()
            || row.record_json.is_some()
            || row.execution_trace_hash.is_some()
            || row.execution_trace_json.is_some()
            || row.intent_complete_evaluation_hash.is_some()
            || row.intent_complete_evaluation_json.is_some()
        {
            return Err(LedgerError::CorruptState);
        }
        return Ok(VerifiedAttempt {
            proposal,
            decision_outcome: decision.outcome,
            authorization_id: authorization.authorization_id,
            request_hash: row.request_hash,
            consumed_at: row.consumed_at,
            state: row.state,
            outcome: None,
            completed_at: None,
            record_hash: None,
            record: None,
            execution_lineage_hash: None,
            task_control,
            task_control_provenance: None,
            intent_pre_evaluation_hash,
            intent_complete_evaluation_hash: None,
            intent_pre_assessment,
            intent_complete_assessment: None,
        });
    }

    let completed_at = row.completed_at.ok_or(LedgerError::CorruptState)?;
    let outcome = row.outcome.clone().ok_or(LedgerError::CorruptState)?;
    let observation_digest = row
        .observation_digest
        .as_deref()
        .ok_or(LedgerError::CorruptState)?;
    let observation: ToolExecutionObservation = serde_json::from_str(
        row.observation_json
            .as_deref()
            .ok_or(LedgerError::CorruptState)?,
    )
    .map_err(|_| LedgerError::CorruptState)?;
    observation
        .validate()
        .map_err(|_| LedgerError::CorruptState)?;
    if observation
        .digest()
        .map_err(|_| LedgerError::CorruptState)?
        != observation_digest
        || observation
            .authorization_id()
            .map_err(|_| LedgerError::CorruptState)?
            != authorization.authorization_id
        || observation.proposal_digest != proposal_digest
        || observation.request_hash != row.request_hash
    {
        return Err(LedgerError::CorruptState);
    }

    let (expected_state, expected_outcome, expected_record_outcome, result_hash) =
        match observation.outcome {
            WireExecutionOutcome::Succeeded => (
                "SUCCEEDED",
                "SUCCEEDED",
                ExecutionOutcome::Succeeded,
                parse_digest(
                    observation
                        .result_digest
                        .as_deref()
                        .ok_or(LedgerError::CorruptState)?,
                )
                .map_err(|_| LedgerError::CorruptState)?,
            ),
            WireExecutionOutcome::ToolReportedError => (
                "EXECUTION_UNKNOWN",
                "TOOL_REPORTED_ERROR",
                ExecutionOutcome::Indeterminate,
                parse_digest(
                    observation
                        .result_digest
                        .as_deref()
                        .ok_or(LedgerError::CorruptState)?,
                )
                .map_err(|_| LedgerError::CorruptState)?,
            ),
            WireExecutionOutcome::TransportError => (
                "EXECUTION_UNKNOWN",
                "TRANSPORT_ERROR",
                ExecutionOutcome::Indeterminate,
                digest_bytes(NO_TOOL_RESULT_PREIMAGE),
            ),
        };
    let intent_complete_evaluation_hash = row
        .intent_complete_evaluation_hash
        .clone()
        .ok_or(LedgerError::CorruptState)?;
    let intent_complete_evaluation: CompleteLiveIntentBundle = serde_json::from_str(
        row.intent_complete_evaluation_json
            .as_deref()
            .ok_or(LedgerError::CorruptState)?,
    )
    .map_err(|_| LedgerError::CorruptState)?;
    intent_complete_evaluation
        .revalidate(approved, &proposal, result_hash)
        .map_err(|_| LedgerError::CorruptState)?;
    if intent_complete_evaluation
        .record
        .digest()
        .map_err(|_| LedgerError::CorruptState)?
        .to_string()
        != intent_complete_evaluation_hash
    {
        return Err(LedgerError::CorruptState);
    }
    let intent_complete_assessment = intent_complete_evaluation
        .assessment()
        .map_err(|_| LedgerError::CorruptState)?;
    let record_id = row.record_id.as_deref().ok_or(LedgerError::CorruptState)?;
    let record_hash = row.record_hash.clone().ok_or(LedgerError::CorruptState)?;
    let record: ExecutionRecord = serde_json::from_str(
        row.record_json
            .as_deref()
            .ok_or(LedgerError::CorruptState)?,
    )
    .map_err(|_| LedgerError::CorruptState)?;
    record
        .verify_for(&request, &authorization)
        .map_err(|_| LedgerError::CorruptState)?;
    if row.state != expected_state
        || outcome != expected_outcome
        || record.record_id.to_string() != record_id
        || record
            .digest()
            .map_err(|_| LedgerError::CorruptState)?
            .to_string()
            != record_hash
        || record.authorization_id != authorization.authorization_id
        || record.consumed_at != row.consumed_at
        || record.completed_at != completed_at
        || record.outcome != expected_record_outcome
        || record.result_hash != result_hash
    {
        return Err(LedgerError::CorruptState);
    }
    let execution_trace_hash = row
        .execution_trace_hash
        .clone()
        .ok_or(LedgerError::CorruptState)?;
    let execution_trace: CompletedExecutionEvidence = serde_json::from_str(
        row.execution_trace_json
            .as_deref()
            .ok_or(LedgerError::CorruptState)?,
    )
    .map_err(|_| LedgerError::CorruptState)?;
    execution_trace
        .validate_for(
            approved,
            &proposal,
            &request,
            &decision,
            &authorization,
            &record,
        )
        .map_err(|_| LedgerError::CorruptState)?;
    if execution_trace
        .commitment()
        .map_err(|_| LedgerError::CorruptState)?
        .to_string()
        != execution_trace_hash
    {
        return Err(LedgerError::CorruptState);
    }
    let execution_lineage_hash = execution_trace
        .execution_lineage_digest_for(
            approved,
            &proposal,
            &request,
            &decision,
            &authorization,
            &record,
        )
        .map_err(|_| LedgerError::CorruptState)?
        .to_string();
    let (completed_task_control, task_control_provenance) = execution_trace
        .task_control_for(&decision)
        .map_err(|_| LedgerError::CorruptState)?;
    if completed_task_control != task_control {
        return Err(LedgerError::CorruptState);
    }
    Ok(VerifiedAttempt {
        proposal,
        decision_outcome: decision.outcome,
        authorization_id: authorization.authorization_id,
        request_hash: row.request_hash,
        consumed_at: row.consumed_at,
        state: row.state,
        outcome: Some(outcome),
        completed_at: Some(completed_at),
        record_hash: Some(record_hash),
        record: Some(record),
        execution_lineage_hash: Some(execution_lineage_hash),
        task_control,
        task_control_provenance: Some(task_control_provenance),
        intent_pre_evaluation_hash,
        intent_complete_evaluation_hash: Some(intent_complete_evaluation_hash),
        intent_pre_assessment,
        intent_complete_assessment: Some(intent_complete_assessment),
    })
}

fn load_verified_attempt_event(
    connection: &Connection,
    approved: &ApprovedSession,
    reference: &AuditEventRef,
) -> Result<SessionAuditEvent, LedgerError> {
    let attempt = verify_attempt(connection, approved, &reference.source_id)?;
    let proposal_digest = attempt
        .proposal
        .digest()
        .map_err(|_| LedgerError::CorruptState)?;
    match reference.kind {
        AuditEventKind::ActionStarted if reference.recorded_at == attempt.consumed_at => {
            let task_control_hash = attempt
                .task_control
                .digest()
                .map_err(|_| LedgerError::CorruptState)?
                .to_string();
            Ok(SessionAuditEvent::ActionStarted {
                event_id: format!("action-started:{}", attempt.authorization_id),
                recorded_at: attempt.consumed_at,
                authorization_id: attempt.authorization_id,
                tool_call_id: attempt.proposal.tool_call_id,
                extension_id: attempt.proposal.extension_id,
                tool_name: attempt.proposal.tool_name,
                proposal_digest,
                request_hash: attempt.request_hash,
                conformance_evaluation_hashes: attempt
                    .task_control
                    .conformance_evaluation_hashes
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                task_scope_status: attempt.task_control.task_scope_status,
                review_status: attempt.task_control.review_status,
                decision_reason_code: attempt.task_control.decision_reason_code,
                task_control_hash,
                task_control_provenance: "DECISION_BOUND".to_owned(),
                intent_evaluation_hash: attempt.intent_pre_evaluation_hash,
                intent_assessment: attempt.intent_pre_assessment,
            })
        }
        AuditEventKind::ActionCompleted if Some(reference.recorded_at) == attempt.completed_at => {
            let task_control = attempt.task_control;
            let task_control_hash = task_control
                .digest()
                .map_err(|_| LedgerError::CorruptState)?
                .to_string();
            Ok(SessionAuditEvent::ActionCompleted {
                event_id: format!("action-completed:{}", attempt.authorization_id),
                recorded_at: reference.recorded_at,
                authorization_id: attempt.authorization_id,
                tool_call_id: attempt.proposal.tool_call_id,
                outcome: attempt.outcome.ok_or(LedgerError::CorruptState)?,
                state: attempt.state,
                record_hash: attempt.record_hash,
                execution_lineage_hash: attempt
                    .execution_lineage_hash
                    .ok_or(LedgerError::CorruptState)?,
                task_scope_status: task_control.task_scope_status,
                review_status: task_control.review_status,
                decision_reason_code: task_control.decision_reason_code,
                task_control_hash,
                task_control_provenance: attempt
                    .task_control_provenance
                    .ok_or(LedgerError::CorruptState)?,
                intent_pre_evaluation_hash: attempt.intent_pre_evaluation_hash,
                intent_complete_evaluation_hash: attempt.intent_complete_evaluation_hash,
                intent_pre_assessment: attempt.intent_pre_assessment,
                intent_complete_assessment: attempt
                    .intent_complete_assessment
                    .ok_or(LedgerError::CorruptState)?,
            })
        }
        _ => Err(LedgerError::CorruptState),
    }
}

fn load_verified_denial(
    connection: &Connection,
    approved: &ApprovedSession,
    reference: &AuditEventRef,
) -> Result<SessionAuditEvent, LedgerError> {
    let denial_id = reference
        .source_id
        .parse::<i64>()
        .map_err(|_| LedgerError::CorruptState)?;
    let row = connection
        .query_row(
            "SELECT proposal_digest, run_id, tool_call_id, reason_code, recorded_at
             FROM denied_proposals WHERE denial_id = ?1 AND session_id = ?2",
            params![denial_id, approved.session_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|_| LedgerError::Unavailable)?
        .ok_or(LedgerError::CorruptState)?;
    if denial_id <= 0
        || denial_id > MAX_SAFE_JSON_INTEGER
        || row.4 != reference.recorded_at
        || parse_digest(&row.0).is_err()
        || !valid_audit_text(&row.1, MAX_RUN_ID_BYTES)
        || !valid_audit_text(&row.2, MAX_TOOL_CALL_ID_BYTES)
        || !valid_denial_reason(&row.3)
    {
        return Err(LedgerError::CorruptState);
    }
    Ok(SessionAuditEvent::ActionDenied {
        event_id: format!("action-denied:{denial_id}"),
        recorded_at: row.4,
        denial_id,
        attempted_run_id: row.1,
        tool_call_id: row.2,
        proposal_digest: row.0,
        reason_code: row.3,
    })
}

fn load_stored_restore(
    connection: &Connection,
    approved: &ApprovedSession,
    restore_id: &str,
) -> Result<StoredRestoreRow, LedgerError> {
    connection
        .query_row(
            "SELECT file_restores.recovery_id, file_restores.restore_id,
                    file_restores.challenge_hash, file_restores.challenge_json,
                    file_restores.prepared_at, file_restores.state,
                    file_restores.completed_at, file_restores.record_hash,
                    file_restores.record_json
             FROM file_restores
             JOIN attempts ON attempts.authorization_id = file_restores.recovery_id
             WHERE file_restores.restore_id = ?1 AND attempts.session_id = ?2",
            params![restore_id, approved.session_id],
            |row| {
                Ok(StoredRestoreRow {
                    recovery_id: row.get(0)?,
                    restore_id: row.get(1)?,
                    challenge_hash: row.get(2)?,
                    challenge_json: row.get(3)?,
                    prepared_at: row.get(4)?,
                    state: row.get(5)?,
                    completed_at: row.get(6)?,
                    record_hash: row.get(7)?,
                    record_json: row.get(8)?,
                })
            },
        )
        .optional()
        .map_err(|_| LedgerError::Unavailable)?
        .ok_or(LedgerError::CorruptState)
}

fn verify_delete_recovery_attempt(
    connection: &Connection,
    approved: &ApprovedSession,
    recovery_id: Uuid,
    challenge: &FileRestoreChallenge,
) -> Result<(), LedgerError> {
    let recovery_attempt = verify_attempt(connection, approved, &recovery_id.to_string())?;
    let recovery_record = recovery_attempt
        .record
        .as_ref()
        .ok_or(LedgerError::CorruptState)?;
    if recovery_attempt.state != "SUCCEEDED"
        || recovery_attempt.outcome.as_deref() != Some("SUCCEEDED")
        || recovery_attempt.decision_outcome != AuthorizationOutcome::AllowAfterApproval
        || recovery_attempt.proposal.extension_id != "developer"
        || recovery_attempt.proposal.tool_name != "delete_file"
        || recovery_record.record_id != challenge.original_record_id
        || recovery_attempt.record_hash.as_deref() != Some(&challenge.original_record_hash)
        || challenge.prepared_at < recovery_record.completed_at
    {
        return Err(LedgerError::CorruptState);
    }
    let expected_delete_result = FilesystemResult::Delete {
        relative_path: challenge.relative_path.clone(),
        recovery_id: recovery_id.to_string(),
        recovery_path: format!(".accordlock/recovery/{recovery_id}/content"),
        original_bytes: challenge.original_bytes,
        content_sha256: challenge.content_sha256.clone(),
    };
    let expected_result_hash = parse_digest(
        &result_digest(&expected_delete_result).map_err(|_| LedgerError::CorruptState)?,
    )
    .map_err(|_| LedgerError::CorruptState)?;
    if recovery_record.result_hash != expected_result_hash {
        return Err(LedgerError::CorruptState);
    }
    Ok(())
}

fn load_verified_restore_event(
    connection: &Connection,
    approved: &ApprovedSession,
    reference: &AuditEventRef,
) -> Result<SessionAuditEvent, LedgerError> {
    let row = load_stored_restore(connection, approved, &reference.source_id)?;
    let recovery_id = Uuid::parse_str(&row.recovery_id).map_err(|_| LedgerError::CorruptState)?;
    let restore_id = Uuid::parse_str(&row.restore_id).map_err(|_| LedgerError::CorruptState)?;
    let challenge: FileRestoreChallenge =
        serde_json::from_str(&row.challenge_json).map_err(|_| LedgerError::CorruptState)?;
    challenge
        .validate()
        .map_err(|_| LedgerError::CorruptState)?;
    if restore_id.to_string() != row.restore_id
        || recovery_id.to_string() != row.recovery_id
        || challenge.restore_id != restore_id
        || challenge.recovery_id != recovery_id
        || challenge.task_id != approved.task_id
        || challenge.session_id != approved.session_id
        || challenge.run_id != approved.run_id
        || challenge.workspace_root != approved.workspace_root
        || challenge.prepared_at != row.prepared_at
        || challenge.digest().map_err(|_| LedgerError::CorruptState)? != row.challenge_hash
        || !valid_restore_relative_path(&challenge.relative_path)
    {
        return Err(LedgerError::CorruptState);
    }

    verify_delete_recovery_attempt(connection, approved, recovery_id, &challenge)?;

    let completed_record = match row.state.as_str() {
        "PREPARED" | "IN_FLIGHT"
            if row.completed_at.is_none()
                && row.record_hash.is_none()
                && row.record_json.is_none() =>
        {
            None
        }
        "SUCCEEDED" => {
            let completed_at = row.completed_at.ok_or(LedgerError::CorruptState)?;
            let record_hash = row
                .record_hash
                .as_deref()
                .ok_or(LedgerError::CorruptState)?;
            let record: FileRestoreRecord = serde_json::from_str(
                row.record_json
                    .as_deref()
                    .ok_or(LedgerError::CorruptState)?,
            )
            .map_err(|_| LedgerError::CorruptState)?;
            record.validate().map_err(|_| LedgerError::CorruptState)?;
            if record.completed_at != completed_at
                || !record_matches_challenge(&record, &challenge, &row.challenge_hash)
                || record.digest().map_err(|_| LedgerError::CorruptState)? != record_hash
            {
                return Err(LedgerError::CorruptState);
            }
            Some((record, record_hash.to_owned()))
        }
        _ => return Err(LedgerError::CorruptState),
    };

    match reference.kind {
        AuditEventKind::RestorePrepared if reference.recorded_at == challenge.prepared_at => {
            Ok(SessionAuditEvent::RestorePrepared {
                event_id: format!("restore-prepared:{}", challenge.restore_id),
                recorded_at: challenge.prepared_at,
                restore_id: challenge.restore_id,
                recovery_id: challenge.recovery_id,
                relative_path: challenge.relative_path,
                content_hash: challenge.content_sha256,
            })
        }
        AuditEventKind::RestoreCompleted => {
            let (record, record_hash) = completed_record.ok_or(LedgerError::CorruptState)?;
            if reference.recorded_at != record.completed_at {
                return Err(LedgerError::CorruptState);
            }
            Ok(SessionAuditEvent::RestoreCompleted {
                event_id: format!("restore-completed:{}", record.restore_id),
                recorded_at: record.completed_at,
                restore_id: record.restore_id,
                recovery_id: record.recovery_id,
                relative_path: record.relative_path,
                record_hash,
            })
        }
        _ => Err(LedgerError::CorruptState),
    }
}

fn build_bounded_page(
    approved: &ApprovedSession,
    offset: u32,
    total_events: u32,
    snapshot_revision: i64,
    snapshot_at: i64,
    mut events: Vec<SessionAuditEvent>,
) -> Result<SessionAuditPage, LedgerError> {
    loop {
        let returned = u32::try_from(events.len()).map_err(|_| LedgerError::Encoding)?;
        let cursor = offset.checked_add(returned).ok_or(LedgerError::Encoding)?;
        let next_offset = (cursor < total_events).then_some(cursor);
        if events.is_empty() && next_offset.is_some() {
            return Err(LedgerError::AuditPageTooLarge);
        }
        let page_digest = domain_digest(
            SESSION_AUDIT_PAGE_DIGEST_DOMAIN,
            &(
                SESSION_AUDIT_PAGE_SCHEMA_VERSION,
                approved.task_id,
                &approved.session_id,
                &approved.run_id,
                offset,
                next_offset,
                total_events,
                snapshot_revision,
                snapshot_at,
                &events,
            ),
        )
        .map_err(|_| LedgerError::Encoding)?;
        let page = SessionAuditPage {
            schema_version: SESSION_AUDIT_PAGE_SCHEMA_VERSION,
            task_id: approved.task_id,
            session_id: approved.session_id.clone(),
            run_id: approved.run_id.clone(),
            offset,
            next_offset,
            total_events,
            snapshot_revision,
            snapshot_at,
            events,
            page_digest,
        };
        let encoded = serde_json::to_vec(&page).map_err(|_| LedgerError::Encoding)?;
        if encoded.len() <= MAX_AUDIT_PAGE_ENCODED_BYTES {
            return Ok(page);
        }
        events = page.events;
        if events.pop().is_none() {
            return Err(LedgerError::AuditPageTooLarge);
        }
    }
}

fn validate_event_order(events: &[SessionAuditEvent]) -> Result<(), LedgerError> {
    for pair in events.windows(2) {
        let [left, right] = pair else {
            continue;
        };
        // The SQL query supplies the deterministic secondary key. Every
        // selected row is rebound below, so this independent check only needs
        // to ensure projected timestamps did not move across page positions.
        if right.recorded_at() > left.recorded_at() {
            return Err(LedgerError::CorruptState);
        }
    }
    Ok(())
}

fn valid_audit_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_restore_relative_path(value: &str) -> bool {
    valid_audit_text(value, MAX_AUDIT_RELATIVE_PATH_BYTES)
        && !value.starts_with('/')
        && !value.starts_with('\\')
        && !value.contains('\\')
        && !value.contains(':')
        && value
            .split('/')
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
}

fn valid_denial_reason(reason: &str) -> bool {
    matches!(
        reason,
        "UNKNOWN_SESSION"
            | "SESSION_REVOKED"
            | "SESSION_NOT_CURRENT"
            | "SESSION_BINDING_MISMATCH"
            | "CAPABILITY_NOT_APPROVED"
            | "EXECUTION_CONTEXT_REQUIRED"
            | "INTENT_EVALUATION_INVALID"
            | "ACTION_APPROVAL_REQUIRED"
            | "ACTION_APPROVAL_DENIED"
            | "ACTION_APPROVAL_EXPIRED"
            | "ACTION_APPROVAL_SCOPE_MISMATCH"
            | "ACTION_APPROVAL_ALREADY_USED"
            | "TOOL_CALL_REPLAY"
    )
}

#[cfg(test)]
mod tests {
    use accordlock_agent_protocol::Digest32;
    use accordlock_evaluation::{IntentEvaluationProfile, IntentFindingReason};
    use rusqlite::params;
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::{
        ActionDescriptor, ActionType, Capability, PreauthorizedCapability, TaskPolicy,
        filesystem::{
            FilesystemExecutionRequest, FilesystemExecutionStatus, FilesystemResult,
            execute_governed,
        },
        ledger::AuthorizationResult,
        policy::AutomaticExecutionClass,
        recovery::{FileRestorePrepareOutcome, FileRestorePrepareRequest, prepare_file_restore},
    };

    fn review_assessment(profile: IntentEvaluationProfile) -> IntentAssessment {
        IntentAssessment {
            schema_version: crate::INTENT_ASSESSMENT_SCHEMA_VERSION,
            profile,
            status: crate::IntentAssessmentStatus::ReviewRequired,
            evidence_count: 0,
            finding_reasons: vec![IntentFindingReason::MissingEvidence],
        }
    }

    struct Fixture {
        root: TempDir,
        database: std::path::PathBuf,
        ledger: Ledger,
        approved: ApprovedSession,
    }

    impl Fixture {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let root = tempfile::tempdir()?;
            let workspace = root.path().join("workspace");
            std::fs::create_dir(&workspace)?;
            let database = root.path().join("runtime.sqlite3");
            let ledger = Ledger::open(&database)?;
            let approved = ApprovedSession::new_with_task_objective(
                Uuid::parse_str("11111111-1111-4111-8111-111111111111")?,
                "audit-session",
                "audit-run",
                &workspace,
                7,
                "bounded audit objective",
                TaskPolicy::new(
                    Digest32::sha256(b"bounded audit objective"),
                    [PreauthorizedCapability::new("developer", "read")],
                    [".accordlock".to_owned()],
                )?,
                [
                    Capability::new("developer", "delete_file"),
                    Capability::new("developer", "read"),
                    Capability::new("developer", "write"),
                ],
                100,
                1_000,
            )?;
            ledger.approve_session(&approved)?;
            Ok(Self {
                root,
                database,
                ledger,
                approved,
            })
        }

        fn proposal(
            &self,
            call_id: &str,
            tool_name: &str,
        ) -> Result<ToolCallProposal, Box<dyn std::error::Error>> {
            let arguments = json!({"path": "do-not-project.txt"});
            Ok(ToolCallProposal {
                schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
                session_id: self.approved.session_id.clone(),
                run_id: self.approved.run_id.clone(),
                tool_call_id: call_id.to_owned(),
                workspace_root: self.approved.workspace_root.clone(),
                extension_id: "developer".to_owned(),
                tool_name: tool_name.to_owned(),
                arguments_sha256: goose_digest(&arguments)?,
                agent_plan_checkpoint: crate::model::test_agent_plan_checkpoint(
                    &self.approved.session_id,
                    &self.approved.run_id,
                    call_id,
                    &format!("developer__{tool_name}"),
                    &goose_digest(&arguments)?,
                    100,
                ),
                arguments,
            })
        }
    }

    #[test]
    fn audit_is_deterministic_bounded_and_never_projects_raw_arguments()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let allowed = fixture.proposal("read-call", "read")?;
        assert!(matches!(
            fixture.ledger.authorize_and_consume(
                &allowed,
                None,
                Some(AutomaticExecutionClass::LocalFileRead),
                120,
                30,
            )?,
            AuthorizationResult::Allowed(_)
        ));
        let denied = fixture.proposal("shell-call", "shell")?;
        assert_eq!(
            fixture
                .ledger
                .authorize_and_consume(&denied, None, None, 121, 30)?,
            AuthorizationResult::Denied("CAPABILITY_NOT_APPROVED")
        );
        fixture.ledger.revoke_session_at(
            &SessionRevocation::new(
                fixture.approved.task_id,
                &fixture.approved.session_id,
                &fixture.approved.run_id,
            ),
            130,
        )?;

        let first = fixture.ledger.session_audit(&SessionAuditQuery::new(
            &fixture.approved.session_id,
            0,
            MAX_AUDIT_PAGE_EVENTS,
        ))?;
        let repeated = fixture
            .ledger
            .session_audit(&SessionAuditQuery::for_snapshot(
                &fixture.approved.session_id,
                0,
                MAX_AUDIT_PAGE_EVENTS,
                first.snapshot_revision,
            ))?;
        assert_eq!(first, repeated);
        assert_eq!(first.total_events, 4);
        assert!(first.next_offset.is_none());
        assert!(serde_json::to_vec(&first)?.len() <= MAX_AUDIT_PAGE_ENCODED_BYTES);
        let encoded = serde_json::to_string(&first)?;
        assert!(!encoded.contains("do-not-project"));
        assert!(!encoded.contains("runtime_bearer"));
        Ok(())
    }

    #[test]
    fn post_revocation_denial_preserves_the_attempted_run_without_poisoning_audit()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        fixture.ledger.revoke_session_at(
            &SessionRevocation::new(
                fixture.approved.task_id,
                &fixture.approved.session_id,
                &fixture.approved.run_id,
            ),
            110,
        )?;
        let mut wrong_run = fixture.proposal("wrong-run-after-revocation", "read")?;
        wrong_run.run_id = "attempted-wrong-run".to_owned();
        wrong_run.agent_plan_checkpoint.run_id = wrong_run.run_id.clone();
        assert_eq!(
            fixture
                .ledger
                .authorize_and_consume(&wrong_run, None, None, 120, 30)?,
            AuthorizationResult::Denied("SESSION_REVOKED")
        );

        let page = fixture.ledger.session_audit(&SessionAuditQuery::new(
            &fixture.approved.session_id,
            0,
            MAX_AUDIT_PAGE_EVENTS,
        ))?;
        let attempted_run = page.events.iter().find_map(|event| match event {
            SessionAuditEvent::ActionDenied {
                attempted_run_id,
                reason_code,
                ..
            } if reason_code == "SESSION_REVOKED" => Some(attempted_run_id.as_str()),
            _ => None,
        });
        assert_eq!(attempted_run, Some("attempted-wrong-run"));
        Ok(())
    }

    #[test]
    fn unknown_session_denial_before_approval_remains_auditable()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let workspace = root.path().join("workspace");
        std::fs::create_dir(&workspace)?;
        let canonical_workspace = std::fs::canonicalize(&workspace)?;
        let ledger = Ledger::open(&root.path().join("runtime.sqlite3"))?;
        let arguments = json!({"path": "notes.txt"});
        let proposal = ToolCallProposal {
            schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
            session_id: "eventual-session".to_owned(),
            run_id: "attempted-before-approval".to_owned(),
            tool_call_id: "unknown-before-approval".to_owned(),
            workspace_root: canonical_workspace.to_string_lossy().into_owned(),
            extension_id: "developer".to_owned(),
            tool_name: "read".to_owned(),
            arguments_sha256: goose_digest(&arguments)?,
            agent_plan_checkpoint: crate::model::test_agent_plan_checkpoint(
                "eventual-session",
                "attempted-before-approval",
                "unknown-before-approval",
                "developer__read",
                &goose_digest(&arguments)?,
                90,
            ),
            arguments,
        };
        assert_eq!(
            ledger.authorize_and_consume(&proposal, None, None, 90, 30)?,
            AuthorizationResult::Denied("UNKNOWN_SESSION")
        );
        let approved = ApprovedSession::new(
            Uuid::parse_str("33333333-3333-4333-8333-333333333333")?,
            "eventual-session",
            "approved-run",
            &workspace,
            1,
            TaskPolicy::new(
                Digest32::sha256(b"eventual approval objective"),
                [PreauthorizedCapability::new("developer", "read")],
                [],
            )?,
            [Capability::new("developer", "read")],
            100,
            1_000,
        )?;
        ledger.approve_session(&approved)?;

        let page = ledger.session_audit(&SessionAuditQuery::new(
            &approved.session_id,
            0,
            MAX_AUDIT_PAGE_EVENTS,
        ))?;
        let attempted_run = page.events.iter().find_map(|event| match event {
            SessionAuditEvent::ActionDenied {
                attempted_run_id,
                reason_code,
                ..
            } if reason_code == "UNKNOWN_SESSION" => Some(attempted_run_id.as_str()),
            _ => None,
        });
        assert_eq!(attempted_run, Some("attempted-before-approval"));
        Ok(())
    }

    #[test]
    fn snapshot_revision_isolated_by_session_and_rejects_same_session_writers()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let workspace_b = fixture.root.path().join("workspace-b");
        std::fs::create_dir(&workspace_b)?;
        let approved_b = ApprovedSession::new(
            Uuid::parse_str("22222222-2222-4222-8222-222222222222")?,
            "audit-session-b",
            "audit-run-b",
            &workspace_b,
            1,
            TaskPolicy::new(
                Digest32::sha256(b"independent audit objective"),
                [PreauthorizedCapability::new("developer", "read")],
                [],
            )?,
            [Capability::new("developer", "read")],
            100,
            1_000,
        )?;
        fixture.ledger.approve_session(&approved_b)?;
        let denied = fixture.proposal("before-first-page", "shell")?;
        assert!(matches!(
            fixture
                .ledger
                .authorize_and_consume(&denied, None, None, 110, 30)?,
            AuthorizationResult::Denied("CAPABILITY_NOT_APPROVED")
        ));
        let first = fixture.ledger.session_audit(&SessionAuditQuery::new(
            &fixture.approved.session_id,
            0,
            1,
        ))?;
        assert_eq!(first.next_offset, Some(1));

        let writer = Connection::open(&fixture.database)?;
        writer.execute(
            "INSERT INTO denied_proposals (
                 proposal_digest, session_id, run_id, tool_call_id, reason_code, recorded_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                Digest32::sha256(b"other-session denial").to_string(),
                approved_b.session_id,
                approved_b.run_id,
                "other-session-call",
                "CAPABILITY_NOT_APPROVED",
                139_i64
            ],
        )?;
        let unaffected = fixture
            .ledger
            .session_audit(&SessionAuditQuery::for_snapshot(
                &fixture.approved.session_id,
                1,
                1,
                first.snapshot_revision,
            ))?;
        assert_eq!(unaffected.snapshot_revision, first.snapshot_revision);

        writer.execute(
            "INSERT INTO denied_proposals (
                 proposal_digest, session_id, run_id, tool_call_id, reason_code, recorded_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                Digest32::sha256(b"concurrent denial").to_string(),
                fixture.approved.session_id,
                fixture.approved.run_id,
                "concurrent-call",
                "CAPABILITY_NOT_APPROVED",
                140_i64
            ],
        )?;

        assert!(matches!(
            fixture
                .ledger
                .session_audit(&SessionAuditQuery::for_snapshot(
                    &fixture.approved.session_id,
                    1,
                    1,
                    first.snapshot_revision,
                )),
            Err(LedgerError::AuditSnapshotChanged)
        ));
        let restarted = fixture.ledger.session_audit(&SessionAuditQuery::new(
            &fixture.approved.session_id,
            0,
            1,
        ))?;
        assert!(restarted.snapshot_revision > first.snapshot_revision);
        assert_eq!(restarted.next_offset, Some(1));
        Ok(())
    }

    #[test]
    fn large_history_returns_only_the_sql_bounded_page() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let connection = Connection::open(&fixture.database)?;
        connection.execute(
            "WITH RECURSIVE counter(value) AS (
                 VALUES(1) UNION ALL SELECT value + 1 FROM counter WHERE value < 5000
             )
             INSERT INTO denied_proposals (
                 proposal_digest, session_id, run_id, tool_call_id, reason_code, recorded_at
             )
             SELECT ?1, ?2, ?3, 'bulk-' || value, 'CAPABILITY_NOT_APPROVED', 200 + value
             FROM counter",
            params![
                Digest32::sha256(b"bulk denial").to_string(),
                fixture.approved.session_id,
                fixture.approved.run_id
            ],
        )?;

        let page = fixture.ledger.session_audit(&SessionAuditQuery::new(
            &fixture.approved.session_id,
            0,
            7,
        ))?;
        assert_eq!(page.total_events, 5_001);
        assert_eq!(page.events.len(), 7);
        assert_eq!(page.next_offset, Some(7));
        assert!(serde_json::to_vec(&page)?.len() <= MAX_AUDIT_PAGE_ENCODED_BYTES);
        Ok(())
    }

    #[test]
    fn selected_attempt_rejects_a_valid_looking_but_wrong_stored_hash()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let proposal = fixture.proposal("corrupt-attempt", "read")?;
        let AuthorizationResult::Allowed(grant) = fixture.ledger.authorize_and_consume(
            &proposal,
            None,
            Some(AutomaticExecutionClass::LocalFileRead),
            120,
            30,
        )?
        else {
            return Err("automatic read was unexpectedly denied".into());
        };
        fixture.ledger.lock()?.execute(
            "UPDATE attempts SET request_hash = ?1 WHERE authorization_id = ?2",
            params![
                Digest32::sha256(b"wrong request").to_string(),
                grant.authorization_id.to_string()
            ],
        )?;
        assert!(matches!(
            fixture.ledger.session_audit(&SessionAuditQuery::new(
                &fixture.approved.session_id,
                0,
                10,
            )),
            Err(LedgerError::CorruptState)
        ));
        Ok(())
    }

    #[test]
    fn selected_attempt_rejects_a_substituted_stored_intent_evaluation_hash()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let proposal = fixture.proposal("corrupt-intent-evaluation", "read")?;
        let AuthorizationResult::Allowed(grant) = fixture.ledger.authorize_and_consume(
            &proposal,
            None,
            Some(AutomaticExecutionClass::LocalFileRead),
            120,
            30,
        )?
        else {
            return Err("automatic read was unexpectedly denied".into());
        };
        fixture.ledger.lock()?.execute(
            "UPDATE attempts SET intent_pre_evaluation_hash = ?1 WHERE authorization_id = ?2",
            params![
                Digest32::sha256(b"substituted stored intent evaluation").to_string(),
                grant.authorization_id.to_string()
            ],
        )?;
        assert!(matches!(
            fixture.ledger.session_audit(&SessionAuditQuery::new(
                &fixture.approved.session_id,
                0,
                10,
            )),
            Err(LedgerError::CorruptState)
        ));
        Ok(())
    }

    #[test]
    fn completed_action_exposes_and_revalidates_the_execution_lineage()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let proposal = fixture.proposal("trace-complete", "read")?;
        let AuthorizationResult::Allowed(grant) = fixture.ledger.authorize_and_consume(
            &proposal,
            None,
            Some(AutomaticExecutionClass::LocalFileRead),
            120,
            30,
        )?
        else {
            return Err("automatic read was unexpectedly denied".into());
        };
        fixture.ledger.observe(
            &ToolExecutionObservation {
                schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
                authorization_id: grant.authorization_id.to_string(),
                proposal_digest: grant.proposal_digest.clone(),
                request_hash: grant.request_hash.to_string(),
                outcome: WireExecutionOutcome::Succeeded,
                result_digest: Some(Digest32::sha256(b"bounded result").to_string()),
            },
            125,
        )?;

        let page = fixture.ledger.session_audit(&SessionAuditQuery::new(
            &fixture.approved.session_id,
            0,
            10,
        ))?;
        let task_projection = page
            .events
            .iter()
            .find_map(|event| match event {
                SessionAuditEvent::ActionCompleted {
                    execution_lineage_hash,
                    task_scope_status,
                    review_status,
                    decision_reason_code,
                    task_control_hash,
                    task_control_provenance,
                    ..
                } => Some((
                    execution_lineage_hash.clone(),
                    *task_scope_status,
                    *review_status,
                    decision_reason_code.clone(),
                    task_control_hash.clone(),
                    *task_control_provenance,
                )),
                _ => None,
            })
            .ok_or("completed action was not projected")?;
        assert!(task_projection.0.starts_with("sha256:"));
        assert_eq!(task_projection.1, TaskScopeStatus::WithinApprovedAccess);
        assert_eq!(task_projection.2, TaskReviewStatus::NotRequired);
        assert_eq!(task_projection.3, "POLICY_CONFORMANT");
        assert!(task_projection.4.starts_with("sha256:"));
        assert_eq!(task_projection.5, TaskControlProvenance::LineageBound);

        let connection = fixture.ledger.lock()?;
        let stored = connection.query_row(
            "SELECT execution_trace_json FROM attempts WHERE authorization_id = ?1",
            params![grant.authorization_id.to_string()],
            |row| row.get::<_, String>(0),
        )?;
        let mut substituted = serde_json::from_str::<serde_json::Value>(&stored)?;
        substituted["lineage"]["started_at"] = serde_json::Value::from(121);
        connection.execute(
            "UPDATE attempts SET execution_trace_json = ?1
             WHERE authorization_id = ?2",
            params![substituted.to_string(), grant.authorization_id.to_string()],
        )?;
        drop(connection);
        assert!(matches!(
            fixture.ledger.session_audit(&SessionAuditQuery::new(
                &fixture.approved.session_id,
                0,
                10,
            )),
            Err(LedgerError::CorruptState)
        ));
        Ok(())
    }

    #[test]
    fn legacy_completed_actions_expose_a_derived_execution_lineage_not_the_storage_commitment()
    -> Result<(), Box<dyn std::error::Error>> {
        for (legacy_schema, expected_provenance) in [
            (1_u16, TaskControlProvenance::Reconstructed),
            (2_u16, TaskControlProvenance::Embedded),
        ] {
            let fixture = Fixture::new()?;
            let proposal = fixture.proposal(&format!("legacy-lineage-{legacy_schema}"), "read")?;
            let AuthorizationResult::Allowed(grant) = fixture.ledger.authorize_and_consume(
                &proposal,
                None,
                Some(AutomaticExecutionClass::LocalFileRead),
                120,
                30,
            )?
            else {
                return Err("automatic read was unexpectedly denied".into());
            };
            fixture.ledger.observe(
                &ToolExecutionObservation {
                    schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
                    authorization_id: grant.authorization_id.to_string(),
                    proposal_digest: grant.proposal_digest,
                    request_hash: grant.request_hash.to_string(),
                    outcome: WireExecutionOutcome::Succeeded,
                    result_digest: Some(Digest32::sha256(b"legacy result").to_string()),
                },
                125,
            )?;

            let connection = fixture.ledger.lock()?;
            let (proposal_json, request_json, decision_json, authorization_json, record_json) =
                connection.query_row(
                    "SELECT proposal_json, request_json, decision_json,
                            authorization_json, record_json
                     FROM attempts WHERE authorization_id = ?1",
                    params![grant.authorization_id.to_string()],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                        ))
                    },
                )?;
            let stored_proposal: ToolCallProposal = serde_json::from_str(&proposal_json)?;
            let request: ExecutionRequest = serde_json::from_str(&request_json)?;
            let decision: AuthorizationDecision = serde_json::from_str(&decision_json)?;
            let authorization: ExecutionAuthorization = serde_json::from_str(&authorization_json)?;
            let record: ExecutionRecord = serde_json::from_str(&record_json)?;
            let legacy = CompletedExecutionEvidence::build_legacy_for_test(
                legacy_schema,
                &fixture.approved,
                &stored_proposal,
                &request,
                &decision,
                &authorization,
                &record,
            )?;
            let legacy_storage_commitment = legacy.commitment()?.to_string();
            let derived_lineage_hash = legacy
                .execution_lineage_digest_for(
                    &fixture.approved,
                    &stored_proposal,
                    &request,
                    &decision,
                    &authorization,
                    &record,
                )?
                .to_string();
            assert_ne!(legacy_storage_commitment, derived_lineage_hash);
            connection.execute(
                "UPDATE attempts
                 SET execution_trace_hash = ?1, execution_trace_json = ?2
                 WHERE authorization_id = ?3",
                params![
                    legacy_storage_commitment,
                    serde_json::to_string(&legacy)?,
                    grant.authorization_id.to_string(),
                ],
            )?;
            drop(connection);

            let page = fixture.ledger.session_audit(&SessionAuditQuery::new(
                &fixture.approved.session_id,
                0,
                10,
            ))?;
            let projected = page.events.iter().find_map(|event| match event {
                SessionAuditEvent::ActionCompleted {
                    execution_lineage_hash,
                    task_control_provenance,
                    ..
                } => Some((execution_lineage_hash, *task_control_provenance)),
                _ => None,
            });
            assert_eq!(
                projected,
                Some((&derived_lineage_hash, expected_provenance))
            );
        }
        Ok(())
    }

    #[test]
    fn reviewed_action_projects_the_exact_task_control() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let proposal = fixture.proposal("trace-reviewed", "write")?;
        let context = fixture
            .ledger
            .action_approval_request(
                &proposal,
                Digest32::sha256(b"reviewed prestate"),
                ActionDescriptor {
                    extension_id: "developer".to_owned(),
                    tool_name: "write".to_owned(),
                    relative_path: "reviewed.txt".to_owned(),
                    action_type: ActionType::CreateFile,
                    requested_bytes: 7,
                    executable_path: None,
                    executable_sha256: None,
                },
            )?
            .ok_or("missing action approval request")?;
        fixture
            .ledger
            .register_action_approval(&ActionApproval::for_context(
                &context,
                Uuid::parse_str("33333333-3333-4333-8333-333333333333")?,
                ApprovalDecision::Approved,
                Digest32::sha256(b"reviewed action evidence"),
                110,
                180,
            )?)?;
        let AuthorizationResult::Allowed(grant) =
            fixture
                .ledger
                .authorize_and_consume(&proposal, Some(&context), None, 120, 30)?
        else {
            return Err("reviewed action was unexpectedly denied".into());
        };
        fixture.ledger.observe(
            &ToolExecutionObservation {
                schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
                authorization_id: grant.authorization_id.to_string(),
                proposal_digest: grant.proposal_digest,
                request_hash: grant.request_hash.to_string(),
                outcome: WireExecutionOutcome::Succeeded,
                result_digest: Some(Digest32::sha256(b"reviewed result").to_string()),
            },
            125,
        )?;

        let page = fixture.ledger.session_audit(&SessionAuditQuery::new(
            &fixture.approved.session_id,
            0,
            10,
        ))?;
        let projection = page.events.iter().find_map(|event| match event {
            SessionAuditEvent::ActionCompleted {
                task_scope_status,
                review_status,
                decision_reason_code,
                task_control_provenance,
                ..
            } => Some((
                *task_scope_status,
                *review_status,
                decision_reason_code.as_str(),
                *task_control_provenance,
            )),
            _ => None,
        });
        assert_eq!(
            projection,
            Some((
                TaskScopeStatus::ReviewRequired,
                TaskReviewStatus::Approved,
                "ACTION_APPROVAL_ACCEPTED",
                TaskControlProvenance::LineageBound,
            ))
        );
        Ok(())
    }

    #[test]
    fn selected_attempt_rejects_substituted_automatic_evaluation_evidence()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let proposal = fixture.proposal("corrupt-automatic-evaluation", "read")?;
        let AuthorizationResult::Allowed(grant) = fixture.ledger.authorize_and_consume(
            &proposal,
            None,
            Some(AutomaticExecutionClass::LocalFileRead),
            120,
            30,
        )?
        else {
            return Err("automatic read was unexpectedly denied".into());
        };
        let connection = fixture.ledger.lock()?;
        let stored = connection.query_row(
            "SELECT automatic_evaluation_json FROM attempts WHERE authorization_id = ?1",
            params![grant.authorization_id.to_string()],
            |row| row.get::<_, String>(0),
        )?;
        let mut substituted = serde_json::from_str::<serde_json::Value>(&stored)?;
        substituted["conformance_evaluation"]["evidence_hash"] =
            serde_json::Value::String(Digest32::sha256(b"substituted evidence").to_string());
        connection.execute(
            "UPDATE attempts SET automatic_evaluation_json = ?1 WHERE authorization_id = ?2",
            params![substituted.to_string(), grant.authorization_id.to_string()],
        )?;
        drop(connection);

        assert!(matches!(
            fixture.ledger.session_audit(&SessionAuditQuery::new(
                &fixture.approved.session_id,
                0,
                MAX_AUDIT_PAGE_EVENTS,
            )),
            Err(LedgerError::CorruptState)
        ));
        Ok(())
    }

    #[test]
    fn selected_action_decision_rejects_scalar_json_divergence()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let proposal = fixture.proposal("corrupt-decision", "write")?;
        let context = fixture
            .ledger
            .action_approval_request(
                &proposal,
                Digest32::sha256(b"prestate"),
                ActionDescriptor {
                    extension_id: "developer".to_owned(),
                    tool_name: "write".to_owned(),
                    relative_path: "notes.txt".to_owned(),
                    action_type: ActionType::CreateFile,
                    requested_bytes: 1,
                    executable_path: None,
                    executable_sha256: None,
                },
            )?
            .ok_or("missing action approval request")?;
        let approval = ActionApproval::for_context(
            &context,
            Uuid::parse_str("22222222-2222-4222-8222-222222222222")?,
            ApprovalDecision::Approved,
            Digest32::sha256(b"human evidence"),
            110,
            180,
        )?;
        fixture.ledger.register_action_approval(&approval)?;
        fixture.ledger.lock()?.execute(
            "UPDATE action_approvals SET prestate_hash = ?1 WHERE approval_id = ?2",
            params![
                Digest32::sha256(b"wrong prestate").to_string(),
                approval.approval_id.to_string()
            ],
        )?;
        assert!(matches!(
            fixture.ledger.session_audit(&SessionAuditQuery::new(
                &fixture.approved.session_id,
                0,
                10,
            )),
            Err(LedgerError::CorruptState)
        ));
        Ok(())
    }

    #[test]
    fn selected_restore_rebinds_the_complete_delete_and_challenge_chain()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        std::fs::write(
            std::path::Path::new(&fixture.approved.workspace_root).join("notes.txt"),
            b"recover exactly",
        )?;
        let arguments = json!({"path": "notes.txt"});
        let request = FilesystemExecutionRequest {
            schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
            proposal: ToolCallProposal {
                schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
                session_id: fixture.approved.session_id.clone(),
                run_id: fixture.approved.run_id.clone(),
                tool_call_id: "delete-for-audit".to_owned(),
                workspace_root: fixture.approved.workspace_root.clone(),
                extension_id: "developer".to_owned(),
                tool_name: "delete_file".to_owned(),
                arguments_sha256: goose_digest(&arguments)?,
                agent_plan_checkpoint: crate::model::test_agent_plan_checkpoint(
                    &fixture.approved.session_id,
                    &fixture.approved.run_id,
                    "delete-for-audit",
                    "developer__delete_file",
                    &goose_digest(&arguments)?,
                    120,
                ),
                arguments,
            },
        };
        let approval_needed = execute_governed(&fixture.ledger, &request, 120, 30)?;
        assert_eq!(
            approval_needed.status,
            FilesystemExecutionStatus::ApprovalRequired
        );
        let context = approval_needed
            .approval_request
            .ok_or("missing deletion approval request")?;
        let approval = ActionApproval::for_context(
            &context,
            Uuid::parse_str("33333333-3333-4333-8333-333333333333")?,
            ApprovalDecision::Approved,
            Digest32::sha256(b"delete evidence"),
            119,
            180,
        )?;
        fixture.ledger.register_action_approval(&approval)?;
        let deleted = execute_governed(&fixture.ledger, &request, 120, 30)?;
        assert_eq!(deleted.status, FilesystemExecutionStatus::Succeeded);
        let FilesystemResult::Delete { recovery_id, .. } =
            deleted.result.ok_or("missing deletion result")?
        else {
            return Err("unexpected filesystem result".into());
        };
        let recovery_id = Uuid::parse_str(&recovery_id)?;
        let prepared = prepare_file_restore(
            &fixture.ledger,
            &FileRestorePrepareRequest {
                schema_version: DESKTOP_PROTOCOL_SCHEMA_VERSION,
                recovery_id,
            },
            121,
        )?;
        let FileRestorePrepareOutcome::Prepared { challenge, .. } = prepared else {
            return Err("restore unexpectedly committed".into());
        };

        let valid = fixture.ledger.session_audit(&SessionAuditQuery::new(
            &fixture.approved.session_id,
            0,
            20,
        ))?;
        assert!(valid.events.iter().any(|event| matches!(
            event,
            SessionAuditEvent::RestorePrepared { restore_id, .. }
                if *restore_id == challenge.restore_id
        )));

        fixture.ledger.lock()?.execute(
            "UPDATE file_restores SET challenge_hash = ?1 WHERE restore_id = ?2",
            params![
                Digest32::sha256(b"wrong restore challenge").to_string(),
                challenge.restore_id.to_string()
            ],
        )?;
        assert!(matches!(
            fixture.ledger.session_audit(&SessionAuditQuery::new(
                &fixture.approved.session_id,
                0,
                20,
            )),
            Err(LedgerError::CorruptState)
        ));
        Ok(())
    }

    #[test]
    fn page_builder_stays_below_the_control_frame_cap() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let long_path = format!("{}.txt", "a".repeat(MAX_AUDIT_RELATIVE_PATH_BYTES - 4));
        let events = (0..MAX_AUDIT_PAGE_EVENTS)
            .map(|index| SessionAuditEvent::RestorePrepared {
                event_id: format!("restore-prepared:{index:04}"),
                recorded_at: 500 - i64::from(index),
                restore_id: Uuid::new_v4(),
                recovery_id: Uuid::new_v4(),
                relative_path: long_path.clone(),
                content_hash: Digest32::sha256(index.to_string().as_bytes()).to_string(),
            })
            .collect();
        let page = build_bounded_page(
            &fixture.approved,
            0,
            u32::from(MAX_AUDIT_PAGE_EVENTS),
            7,
            500,
            events,
        )?;
        assert!(page.events.len() < usize::from(MAX_AUDIT_PAGE_EVENTS));
        assert!(page.next_offset.is_some());
        assert!(serde_json::to_vec(&page)?.len() <= MAX_AUDIT_PAGE_ENCODED_BYTES);
        let envelope = json!({
            "schema_version": DESKTOP_PROTOCOL_SCHEMA_VERSION,
            "request_id": "ffffffff-ffff-4fff-8fff-ffffffffffff",
            "status": "ACK",
            "code": "SESSION_AUDIT_READY",
            "page": page,
        });
        assert!(serde_json::to_vec(&envelope)?.len() <= crate::MAX_CONTROL_FRAME_BYTES);
        Ok(())
    }

    #[test]
    fn audit_queries_remain_on_the_desktop_v2_contract() {
        let query = SessionAuditQuery::new("audit-session", 0, 1);
        assert_eq!(DESKTOP_PROTOCOL_SCHEMA_VERSION, 2);
        assert_eq!(query.schema_version, DESKTOP_PROTOCOL_SCHEMA_VERSION);
    }

    #[test]
    fn continuation_requires_an_explicit_valid_snapshot_revision() {
        assert!(matches!(
            SessionAuditQuery::new("audit-session", 1, 1).validate(),
            Err(LedgerError::InvalidAuditQuery)
        ));
        assert!(matches!(
            SessionAuditQuery::for_snapshot("audit-session", 1, 1, -1).validate(),
            Err(LedgerError::InvalidAuditQuery)
        ));
    }

    #[test]
    fn source_byte_budget_truncates_before_decoding_an_unbounded_page()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let padding = " ".repeat(200_000);
        for index in 0..30 {
            let arguments = json!({"path": "notes.txt"});
            let proposal = ToolCallProposal {
                schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
                session_id: fixture.approved.session_id.clone(),
                run_id: fixture.approved.run_id.clone(),
                tool_call_id: format!("large-read-{index:02}"),
                workspace_root: fixture.approved.workspace_root.clone(),
                extension_id: "developer".to_owned(),
                tool_name: "read".to_owned(),
                arguments_sha256: goose_digest(&arguments)?,
                agent_plan_checkpoint: crate::model::test_agent_plan_checkpoint(
                    &fixture.approved.session_id,
                    &fixture.approved.run_id,
                    &format!("large-read-{index:02}"),
                    "developer__read",
                    &goose_digest(&arguments)?,
                    120 + index,
                ),
                arguments,
            };
            let AuthorizationResult::Allowed(grant) = fixture.ledger.authorize_and_consume(
                &proposal,
                None,
                Some(AutomaticExecutionClass::LocalFileRead),
                120 + index,
                30,
            )?
            else {
                return Err("automatic read was unexpectedly denied".into());
            };
            fixture.ledger.lock()?.execute(
                "UPDATE attempts
                 SET automatic_evaluation_json = automatic_evaluation_json || ?1
                 WHERE authorization_id = ?2",
                params![padding, grant.authorization_id.to_string()],
            )?;
        }

        let page = fixture.ledger.session_audit(&SessionAuditQuery::new(
            &fixture.approved.session_id,
            0,
            MAX_AUDIT_PAGE_EVENTS,
        ))?;
        assert!(page.events.len() < 31);
        assert!(!page.events.is_empty());
        assert_eq!(page.next_offset, Some(u32::try_from(page.events.len())?));
        assert!(serde_json::to_vec(&page)?.len() <= MAX_AUDIT_PAGE_ENCODED_BYTES);
        Ok(())
    }

    #[test]
    fn oversized_selected_source_row_fails_before_json_decode()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let proposal = fixture.proposal("oversized-source", "read")?;
        let AuthorizationResult::Allowed(grant) = fixture.ledger.authorize_and_consume(
            &proposal,
            None,
            Some(AutomaticExecutionClass::LocalFileRead),
            120,
            30,
        )?
        else {
            return Err("automatic read was unexpectedly denied".into());
        };
        fixture.ledger.lock()?.execute(
            "UPDATE attempts SET proposal_json = ?1 WHERE authorization_id = ?2",
            params![
                "x".repeat(usize::try_from(MAX_AUDIT_SOURCE_ROW_BYTES)? + 1),
                grant.authorization_id.to_string()
            ],
        )?;
        assert!(matches!(
            fixture.ledger.session_audit(&SessionAuditQuery::new(
                &fixture.approved.session_id,
                0,
                10,
            )),
            Err(LedgerError::CorruptState)
        ));
        Ok(())
    }

    #[test]
    fn durable_history_survives_a_detached_workspace() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let detached = std::path::Path::new(&fixture.approved.workspace_root)
            .with_file_name("detached-workspace");
        std::fs::rename(&fixture.approved.workspace_root, detached)?;
        let page = fixture.ledger.session_audit(&SessionAuditQuery::new(
            &fixture.approved.session_id,
            0,
            10,
        ))?;
        assert_eq!(page.total_events, 1);
        assert!(matches!(
            page.events.as_slice(),
            [SessionAuditEvent::SessionApproved { .. }]
        ));
        Ok(())
    }

    #[test]
    fn page_digest_matches_the_cross_language_golden_vector()
    -> Result<(), Box<dyn std::error::Error>> {
        let events = vec![SessionAuditEvent::ActionDenied {
            event_id: "action-denied:42".to_owned(),
            recorded_at: 119,
            denial_id: 42,
            attempted_run_id: "run-1".to_owned(),
            tool_call_id: "call-1".to_owned(),
            proposal_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            reason_code: "CAPABILITY_NOT_APPROVED".to_owned(),
        }];
        let digest = domain_digest(
            SESSION_AUDIT_PAGE_DIGEST_DOMAIN,
            &(
                SESSION_AUDIT_PAGE_SCHEMA_VERSION,
                Uuid::parse_str("12345678-1234-4abc-8def-123456789abc")?,
                "session-1",
                "run-1",
                0_u32,
                Some(1_u32),
                2_u32,
                17_i64,
                120_i64,
                &events,
            ),
        )?;
        assert_eq!(
            digest,
            "sha256:97700bb686a5841ffd3869397cbaf1085ecd1c5e4272d87ba5a9abdcceb19cd5"
        );
        let page = SessionAuditPage {
            schema_version: SESSION_AUDIT_PAGE_SCHEMA_VERSION,
            task_id: Uuid::parse_str("12345678-1234-4abc-8def-123456789abc")?,
            session_id: "session-1".to_owned(),
            run_id: "run-1".to_owned(),
            offset: 0,
            next_offset: Some(1),
            total_events: 2,
            snapshot_revision: 17,
            snapshot_at: 120,
            events,
            page_digest: digest,
        };
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../schemas/examples/session-audit-page.v6.json"
        ))?;
        assert_eq!(serde_json::to_value(&page)?, expected);
        Ok(())
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one public serialization fixture must lock every event shape together"
    )]
    fn public_audit_example_locks_every_event_serialization()
    -> Result<(), Box<dyn std::error::Error>> {
        let hash = |byte| Digest32::from_bytes([byte; 32]).to_string();
        let task_id = Uuid::parse_str("11111111-1111-4111-8111-111111111111")?;
        let authorization_id = Uuid::parse_str("33333333-3333-4333-8333-333333333333")?;
        let restore_id = Uuid::parse_str("44444444-4444-4444-8444-444444444444")?;
        let recovery_id = Uuid::parse_str("55555555-5555-4555-8555-555555555555")?;
        let page = SessionAuditPage {
            schema_version: SESSION_AUDIT_PAGE_SCHEMA_VERSION,
            task_id,
            session_id: "session-1".to_owned(),
            run_id: "run-1".to_owned(),
            offset: 0,
            next_offset: None,
            total_events: 8,
            snapshot_revision: 17,
            snapshot_at: 1_200,
            events: vec![
                SessionAuditEvent::SessionApproved {
                    event_id: "session-approved:1".to_owned(),
                    recorded_at: 100,
                    task_id,
                    run_id: "run-1".to_owned(),
                    workspace_root: "/workspace".to_owned(),
                    policy_hash: hash(1),
                    expires_at: 2_000,
                },
                SessionAuditEvent::SessionRevoked {
                    event_id: "session-revoked:1".to_owned(),
                    recorded_at: 110,
                    task_id,
                    run_id: "run-1".to_owned(),
                    revocation_digest: hash(2),
                },
                SessionAuditEvent::ActionDecision {
                    event_id: "action-decision:1".to_owned(),
                    recorded_at: 120,
                    approval_id: Uuid::parse_str("22222222-2222-4222-8222-222222222222")?,
                    tool_call_id: "call-1".to_owned(),
                    proposal_digest: hash(3),
                    decision: ApprovalDecision::Approved,
                    evidence_hash: hash(4),
                    consumed: true,
                },
                SessionAuditEvent::ActionStarted {
                    event_id: "action-started:1".to_owned(),
                    recorded_at: 130,
                    authorization_id,
                    tool_call_id: "call-1".to_owned(),
                    extension_id: "developer".to_owned(),
                    tool_name: "read".to_owned(),
                    proposal_digest: hash(5),
                    request_hash: hash(6),
                    conformance_evaluation_hashes: vec![hash(7)],
                    task_scope_status: TaskScopeStatus::WithinApprovedAccess,
                    review_status: TaskReviewStatus::NotRequired,
                    decision_reason_code: "POLICY_CONFORMANT".to_owned(),
                    task_control_hash: hash(8),
                    task_control_provenance: "DECISION_BOUND".to_owned(),
                    intent_evaluation_hash: hash(10),
                    intent_assessment: review_assessment(IntentEvaluationProfile::PreExecution),
                },
                SessionAuditEvent::ActionCompleted {
                    event_id: "action-completed:1".to_owned(),
                    recorded_at: 140,
                    authorization_id,
                    tool_call_id: "call-1".to_owned(),
                    outcome: "SUCCEEDED".to_owned(),
                    state: "SUCCEEDED".to_owned(),
                    record_hash: Some(hash(7)),
                    execution_lineage_hash: hash(8),
                    task_scope_status: TaskScopeStatus::WithinApprovedAccess,
                    review_status: TaskReviewStatus::NotRequired,
                    decision_reason_code: "POLICY_CONFORMANT".to_owned(),
                    task_control_hash: hash(9),
                    task_control_provenance: TaskControlProvenance::LineageBound,
                    intent_pre_evaluation_hash: hash(10),
                    intent_complete_evaluation_hash: Some(hash(11)),
                    intent_pre_assessment: review_assessment(IntentEvaluationProfile::PreExecution),
                    intent_complete_assessment: review_assessment(
                        IntentEvaluationProfile::CompleteTrace,
                    ),
                },
                SessionAuditEvent::ActionDenied {
                    event_id: "action-denied:1".to_owned(),
                    recorded_at: 150,
                    denial_id: 1,
                    attempted_run_id: "run-1".to_owned(),
                    tool_call_id: "call-2".to_owned(),
                    proposal_digest: hash(10),
                    reason_code: "CAPABILITY_NOT_APPROVED".to_owned(),
                },
                SessionAuditEvent::RestorePrepared {
                    event_id: "restore-prepared:1".to_owned(),
                    recorded_at: 160,
                    restore_id,
                    recovery_id,
                    relative_path: "notes.txt".to_owned(),
                    content_hash: hash(11),
                },
                SessionAuditEvent::RestoreCompleted {
                    event_id: "restore-completed:1".to_owned(),
                    recorded_at: 170,
                    restore_id,
                    recovery_id,
                    relative_path: "notes.txt".to_owned(),
                    record_hash: hash(12),
                },
            ],
            page_digest: hash(13),
        };
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../schemas/examples/session-audit-page.all-events.v6.json"
        ))?;
        assert_eq!(serde_json::to_value(&page)?, expected);
        Ok(())
    }
}
