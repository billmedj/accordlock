//! Trusted, local authorization runtime for the `AccordLock` Goose distribution.
//!
//! Goose may propose actions, but this crate is the authority that binds each
//! proposal to a pre-approved task/session, creates and atomically consumes
//! a single-use authorization, and durably records the observed outcome. The Desktop
//! HTTP surface contains only health and runtime-owned atomic execution; the
//! caller-reported core protocol is an explicit non-Desktop feature.

#![forbid(unsafe_code)]

mod audit;
mod canonical;
mod control;
mod execution_trace;
mod filesystem;
mod http;
mod ledger;
mod live_intent;
mod model;
mod network;
mod notification;
mod policy;
mod recovery;
mod terminal;

pub use audit::{
    MAX_AUDIT_PAGE_ENCODED_BYTES, MAX_AUDIT_PAGE_EVENTS, SESSION_AUDIT_PAGE_DIGEST_DOMAIN,
    SESSION_AUDIT_PAGE_SCHEMA_VERSION, SessionAuditEvent, SessionAuditPage, SessionAuditQuery,
};
pub use control::{
    CONTROL_CHANNEL_SCHEMA_VERSION, CONTROL_FRAME_MAGIC, ControlChannelError, ControlChannelExit,
    MAX_CONTROL_FRAME_BYTES, serve_audit_control_channel, serve_control_channel,
};
pub use execution_trace::{TaskControlProvenance, TaskReviewStatus, TaskScopeStatus};
pub use filesystem::FILESYSTEM_EXECUTE_PATH;
pub use http::{
    AUTHORIZE_PATH, HEALTH_PATH, MAX_REQUEST_BODY_BYTES, OBSERVE_PATH, Runtime, RuntimeConfig,
    RuntimeConfigError, RuntimeServeError,
};
pub use ledger::{
    ActionApprovalRegistration, ApprovalRegistration, AttemptSnapshot, Ledger, LedgerError,
    RevocationRegistration,
};
pub use live_intent::{
    COMPLETE_LIVE_INTENT_BUNDLE_SCHEMA_VERSION, CompleteLiveIntentBundle,
    INTENT_ASSESSMENT_SCHEMA_VERSION, IntentAssessment, IntentAssessmentStatus,
    LIVE_INTENT_EVALUATION_CONTEXT_SCHEMA_VERSION, LiveIntentError, LiveIntentEvaluationContext,
    PRE_EXECUTION_LIVE_INTENT_BUNDLE_SCHEMA_VERSION, PreExecutionLiveIntentBundle,
};
pub use model::{
    AGENT_PLAN_CHECKPOINT_SCHEMA_VERSION, APPROVED_SESSION_SCHEMA_VERSION, AgentPlanCheckpoint,
    ApprovedSession, Capability, DESKTOP_PROTOCOL_SCHEMA_VERSION, MAX_AGENT_PLAN_MATERIAL_BYTES,
    MAX_TASK_OBJECTIVE_BYTES, SESSION_REVOCATION_SCHEMA_VERSION, SessionRevocation,
    SessionRevocationError, TOOL_CALL_PROPOSAL_SCHEMA_VERSION, TOOL_EXECUTION_SCHEMA_VERSION,
    TaskBindingError, ToolCallProposal, ToolExecutionObservation, WireValidationError,
};
pub use network::{
    HTTPS_EXECUTE_PATH, HttpsEgress, HttpsEgressError, HttpsEgressPolicy, HttpsEgressRequest,
    HttpsEgressResponse, HttpsHeader, HttpsMethod, HttpsPolicyError, WebPkiHttpsEgress,
    WebPkiHttpsEgressBuildError,
};
pub use notification::{
    CONNECTION_TEST_FRAME_MAGIC, ConnectionTestReport, MAX_NOTIFICATION_REQUEST_BYTES,
    NOTIFICATION_FRAME_MAGIC, NotificationDispatchReport, NotificationRequestError,
    serve_connection_test_request, serve_review_notification_request,
};
pub use policy::{
    ACTION_APPROVAL_SCHEMA_VERSION, ActionApproval, ActionApprovalRequest, ActionDescriptor,
    ActionType, ApprovalDecision, MAX_ACTION_APPROVAL_LIFETIME_SECONDS,
    MAX_APPROVAL_RELATIVE_PATH_BYTES, MAX_PREAUTHORIZED_CAPABILITIES, MAX_PROTECTED_PATHS,
    PreauthorizedCapability, TASK_POLICY_SCHEMA_VERSION, TaskPolicy, TaskPolicyError,
};
pub use recovery::{
    FILE_RESTORE_CHALLENGE_DIGEST_DOMAIN, FILE_RESTORE_RECORD_DIGEST_DOMAIN, FileRestoreChallenge,
    FileRestoreCommitOutcome, FileRestoreCommitRequest, FileRestoreError,
    FileRestorePrepareOutcome, FileRestorePrepareRequest, FileRestoreRecord,
    file_restore_challenge_digest, file_restore_record_digest,
};
pub use terminal::{TERMINAL_EXECUTE_PATH, TerminalConfigError, TerminalProgram};
