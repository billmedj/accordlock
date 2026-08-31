//! Durable v13 submission and control-work state boundary.
//!
//! Public requests contribute only a signed proposal envelope. Trusted time,
//! active authority, evaluation nonces, grant selection, work fencing, authorization
//! identifiers, consumption, and outbox lineage are all derived or reloaded
//! inside state-owned serialization boundaries.

use accordlock_ingress::{
    FrozenIngressVerifier, IngressRecoveryProbe, StaticallyVerifiedIngressSubmission,
    VerifiedHistoricalIngress,
};
use accordlock_protocol::{
    AgentProposal, AuthorityDomainState, AuthorityVector, CanonicalEncode, CoseVerifier, Digest32,
    SignedEvaluation, canonical_hash,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    ConsumeKey, ConsumeSuccess, IssuanceSnapshot, IssuedAuthorizationRecord, Scope, StateError,
};

/// Fixed server policy for one control-work lease.
pub const CONTROL_WORK_LEASE_SECONDS: i64 = 30;

const CONTROL_EVALUATION_COMMITMENT_DOMAIN: &[u8] =
    b"accordlock:v13:control-evaluation-commitment\0";
const CONTROL_DECISION_COMMITMENT_DOMAIN: &[u8] = b"accordlock:v13:control-decision-commitment\0";
const CONTROL_EVENT_COMMITMENT_DOMAIN: &[u8] = b"accordlock:v13:control-event-commitment\0";

/// Durable queue phase. Transitions are strictly forward-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlWorkPhase {
    Evaluate,
    Issue,
    Consume,
    Done,
}

/// Stable external status projection. It never contains an authorization, credential,
/// lease, grant capability, or execution authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlStatusCode {
    Accepted,
    Authorized,
    ControlDenied,
    ManualResolutionRequired,
    AuthorizationIssued,
    DispatchPending,
    FailedClosed,
}

impl ControlStatusCode {
    const fn code(self) -> u8 {
        match self {
            Self::Accepted => 1,
            Self::Authorized => 2,
            Self::ControlDenied => 3,
            Self::ManualResolutionRequired => 4,
            Self::AuthorizationIssued => 5,
            Self::DispatchPending => 6,
            Self::FailedClosed => 7,
        }
    }
}

/// Trusted scheduler selector for a fixed worker loop. State returns only the
/// corresponding phase, but this enum is not a worker credential: production
/// composition must never derive it from request input and must bind each loop
/// to its configured role (and, where required, separate database authority).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlWorkerRole {
    Evaluator,
    Issuer,
    Consumer,
}

impl ControlWorkerRole {
    pub(crate) const fn phase(self) -> ControlWorkPhase {
        match self {
            Self::Evaluator => ControlWorkPhase::Evaluate,
            Self::Issuer => ControlWorkPhase::Issue,
            Self::Consumer => ControlWorkPhase::Consume,
        }
    }
}

/// Exact outcome of the signed kernel evaluation, when the kernel was called.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlKernelOutcome {
    Allow,
    Deny,
}

impl ControlKernelOutcome {
    const fn code(self) -> u8 {
        match self {
            Self::Allow => 1,
            Self::Deny => 2,
        }
    }
}

/// Server control-plane decision after applying current grant state to the
/// signed kernel outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlOutcome {
    Allow,
    Deny,
    Manual,
}

impl ControlOutcome {
    const fn code(self) -> u8 {
        match self {
            Self::Allow => 1,
            Self::Deny => 2,
            Self::Manual => 3,
        }
    }
}

/// Bounded reason vocabulary for control decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlDecisionReason {
    ControlAllow,
    IngressExpired,
    AuthorityChanged,
    KernelDeny,
    GrantUnavailable,
    GrantAmbiguous,
}

impl ControlDecisionReason {
    const fn code(self) -> u8 {
        match self {
            Self::ControlAllow => 1,
            Self::IngressExpired => 2,
            Self::AuthorityChanged => 3,
            Self::KernelDeny => 4,
            Self::GrantUnavailable => 5,
            Self::GrantAmbiguous => 6,
        }
    }
}

/// Terminal fail-closed reason after a control decision already exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlWorkFinalizationReason {
    IngressExpired,
    AuthorityChanged,
    GrantUnavailable,
    AuthorizationExpired,
    /// The authorization itself was still live, but its immutable delivery profile or
    /// one of its frozen dependencies left no positive dispatch window.
    DispatchWindowExpired,
}

impl ControlWorkFinalizationReason {
    const fn code(self) -> u8 {
        match self {
            Self::IngressExpired => 1,
            Self::AuthorityChanged => 2,
            Self::GrantUnavailable => 3,
            Self::AuthorizationExpired => 4,
            Self::DispatchWindowExpired => 5,
        }
    }
}

/// Typed status reason spanning both immutable control decisions and later
/// fail-closed work finalization without collapsing either vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "reason", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlStatusReason {
    Decision(ControlDecisionReason),
    Finalization(ControlWorkFinalizationReason),
}

/// Stable key usable after an ambiguous intake response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlSubmissionRecoveryKey {
    replay_scope: String,
    key_id: String,
    nonce: Uuid,
    canonical_payload_commitment: Digest32,
}

impl ControlSubmissionRecoveryKey {
    pub(crate) fn new(
        replay_scope: String,
        key_id: String,
        nonce: Uuid,
        canonical_payload_commitment: Digest32,
    ) -> Self {
        Self {
            replay_scope,
            key_id,
            nonce,
            canonical_payload_commitment,
        }
    }

    #[must_use]
    pub fn replay_scope(&self) -> &str {
        &self.replay_scope
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub const fn nonce(&self) -> Uuid {
        self.nonce
    }

    #[must_use]
    pub const fn canonical_payload_commitment(&self) -> Digest32 {
        self.canonical_payload_commitment
    }
}

/// Receipt returned only for a newly committed intake.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlSubmissionReceipt {
    submission_id: Uuid,
    receipt_id: Uuid,
    request_id: Uuid,
    scope: Scope,
    accepted_at: i64,
    canonical_payload_commitment: Digest32,
}

impl ControlSubmissionReceipt {
    pub(crate) fn new(
        submission_id: Uuid,
        receipt_id: Uuid,
        request_id: Uuid,
        scope: Scope,
        accepted_at: i64,
        canonical_payload_commitment: Digest32,
    ) -> Self {
        Self {
            submission_id,
            receipt_id,
            request_id,
            scope,
            accepted_at,
            canonical_payload_commitment,
        }
    }

    #[must_use]
    pub const fn submission_id(&self) -> Uuid {
        self.submission_id
    }

    #[must_use]
    pub const fn receipt_id(&self) -> Uuid {
        self.receipt_id
    }

    #[must_use]
    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }

    #[must_use]
    pub const fn scope(&self) -> &Scope {
        &self.scope
    }

    #[must_use]
    pub const fn accepted_at(&self) -> i64 {
        self.accepted_at
    }

    #[must_use]
    pub const fn canonical_payload_commitment(&self) -> Digest32 {
        self.canonical_payload_commitment
    }
}

/// Inert reference returned for exact committed recovery, including after
/// ingress expiry or registry rotation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveredSubmissionRef {
    receipt: ControlSubmissionReceipt,
    status: ControlStatusCode,
    revision: u64,
}

impl RecoveredSubmissionRef {
    pub(crate) fn new(
        receipt: ControlSubmissionReceipt,
        status: ControlStatusCode,
        revision: u64,
    ) -> Self {
        Self {
            receipt,
            status,
            revision,
        }
    }

    #[must_use]
    pub const fn receipt(&self) -> &ControlSubmissionReceipt {
        &self.receipt
    }

    #[must_use]
    pub const fn status(&self) -> ControlStatusCode {
        self.status
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

/// Explicit result of the atomic intake boundary.
#[derive(Debug, PartialEq, Eq)]
pub enum ControlSubmissionIntakeOutcome {
    Fresh(ControlSubmissionReceipt),
    Recovered(RecoveredSubmissionRef),
    OutcomeUnknown(ControlSubmissionRecoveryKey),
}

/// Read-only external status view.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlStatusSnapshot {
    submission_id: Uuid,
    receipt_id: Uuid,
    status: ControlStatusCode,
    reason: Option<ControlStatusReason>,
    revision: u64,
    observed_at: i64,
}

impl ControlStatusSnapshot {
    pub(crate) fn new(
        submission_id: Uuid,
        receipt_id: Uuid,
        status: ControlStatusCode,
        reason: Option<ControlStatusReason>,
        revision: u64,
        observed_at: i64,
    ) -> Self {
        Self {
            submission_id,
            receipt_id,
            status,
            reason,
            revision,
            observed_at,
        }
    }

    #[must_use]
    pub const fn submission_id(&self) -> Uuid {
        self.submission_id
    }

    #[must_use]
    pub const fn receipt_id(&self) -> Uuid {
        self.receipt_id
    }

    #[must_use]
    pub const fn status(&self) -> ControlStatusCode {
        self.status
    }

    #[must_use]
    pub const fn reason(&self) -> Option<ControlStatusReason> {
        self.reason
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn observed_at(&self) -> i64 {
        self.observed_at
    }
}

/// Worker-selected idempotency identity. Lease duration and queue phase are
/// server policy and cannot be supplied by the worker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlWorkClaimRequest {
    worker_id: String,
    role: ControlWorkerRole,
    claim_id: Uuid,
}

impl ControlWorkClaimRequest {
    /// Creates one exact retry key before a worker asks state to claim work.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::InvalidRecord`] for a nil claim or a malformed
    /// bounded worker identity.
    pub fn new(
        worker_id: impl Into<String>,
        role: ControlWorkerRole,
        claim_id: Uuid,
    ) -> Result<Self, StateError> {
        let worker_id = worker_id.into();
        if claim_id.is_nil() || !valid_worker_id(&worker_id) {
            return Err(StateError::InvalidRecord(
                "control worker identity or claim identifier is invalid".to_owned(),
            ));
        }
        Ok(Self {
            worker_id,
            role,
            claim_id,
        })
    }

    #[must_use]
    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    #[must_use]
    pub const fn role(&self) -> ControlWorkerRole {
        self.role
    }

    #[must_use]
    pub const fn claim_id(&self) -> Uuid {
        self.claim_id
    }
}

/// Explicit recovery key returned when claim commit state is indeterminate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlWorkClaimRecoveryKey {
    worker_id: String,
    role: ControlWorkerRole,
    claim_id: Uuid,
}

impl ControlWorkClaimRecoveryKey {
    pub(crate) fn from_request(request: &ControlWorkClaimRequest) -> Self {
        Self {
            worker_id: request.worker_id.clone(),
            role: request.role,
            claim_id: request.claim_id,
        }
    }

    #[must_use]
    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    #[must_use]
    pub const fn role(&self) -> ControlWorkerRole {
        self.role
    }

    #[must_use]
    pub const fn claim_id(&self) -> Uuid {
        self.claim_id
    }
}

/// Opaque, non-cloneable and non-serializable phase authority.
#[derive(Debug, PartialEq, Eq)]
pub struct ControlWorkLease {
    pub(crate) state_instance_id: Uuid,
    pub(crate) submission_id: Uuid,
    pub(crate) phase: ControlWorkPhase,
    pub(crate) worker_id: String,
    pub(crate) claim_id: Uuid,
    pub(crate) fence: u64,
    pub(crate) claimed_at: i64,
    pub(crate) lease_until: i64,
}

impl ControlWorkLease {
    #[must_use]
    pub const fn submission_id(&self) -> Uuid {
        self.submission_id
    }

    #[must_use]
    pub const fn phase(&self) -> ControlWorkPhase {
        self.phase
    }

    #[must_use]
    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    #[must_use]
    pub const fn claim_id(&self) -> Uuid {
        self.claim_id
    }

    #[must_use]
    pub const fn fence(&self) -> u64 {
        self.fence
    }

    #[must_use]
    pub const fn claimed_at(&self) -> i64 {
        self.claimed_at
    }

    #[must_use]
    pub const fn lease_until(&self) -> i64 {
        self.lease_until
    }
}

/// Evaluation capability reconstructed only from a current exact durable row
/// under an active claim, DB time, HWM, frozen-signature re-verification, and
/// exact current principal-registry authority.
#[derive(Debug, PartialEq, Eq)]
pub struct ControlEvaluationWork {
    pub(crate) lease: ControlWorkLease,
    pub(crate) scope: Scope,
    pub(crate) proposal: AgentProposal,
    pub(crate) caller_tenant: String,
    pub(crate) caller_actor: String,
    pub(crate) accepted_at: i64,
    pub(crate) ingress_expires_at: i64,
    pub(crate) ingress_authority_domain: AuthorityDomainState,
    pub(crate) active_authority: AuthorityVector,
    pub(crate) evaluation_nonce: Uuid,
}

impl ControlEvaluationWork {
    #[must_use]
    pub const fn lease(&self) -> &ControlWorkLease {
        &self.lease
    }

    #[must_use]
    pub const fn scope(&self) -> &Scope {
        &self.scope
    }

    #[must_use]
    pub const fn proposal(&self) -> &AgentProposal {
        &self.proposal
    }

    #[must_use]
    pub fn caller_tenant(&self) -> &str {
        &self.caller_tenant
    }

    #[must_use]
    pub fn caller_actor(&self) -> &str {
        &self.caller_actor
    }

    #[must_use]
    pub const fn accepted_at(&self) -> i64 {
        self.accepted_at
    }

    #[must_use]
    pub const fn ingress_expires_at(&self) -> i64 {
        self.ingress_expires_at
    }

    #[must_use]
    pub const fn ingress_authority_domain(&self) -> &AuthorityDomainState {
        &self.ingress_authority_domain
    }

    #[must_use]
    pub const fn active_authority(&self) -> &AuthorityVector {
        &self.active_authority
    }

    #[must_use]
    pub const fn evaluation_nonce(&self) -> Uuid {
        self.evaluation_nonce
    }
}

/// Issuance capability containing the exact durable signed evaluation and the
/// single server-selected current grant.
#[derive(Debug, PartialEq, Eq)]
pub struct ControlIssuanceWork {
    pub(crate) lease: ControlWorkLease,
    pub(crate) scope: Scope,
    pub(crate) proposal: AgentProposal,
    pub(crate) signed_evaluation: SignedEvaluation,
    pub(crate) selected_grant_id: Uuid,
    pub(crate) decision_id: Uuid,
}

impl ControlIssuanceWork {
    #[must_use]
    pub const fn lease(&self) -> &ControlWorkLease {
        &self.lease
    }

    #[must_use]
    pub const fn scope(&self) -> &Scope {
        &self.scope
    }

    #[must_use]
    pub const fn proposal(&self) -> &AgentProposal {
        &self.proposal
    }

    #[must_use]
    pub const fn signed_evaluation(&self) -> &SignedEvaluation {
        &self.signed_evaluation
    }

    #[must_use]
    pub const fn selected_grant_id(&self) -> Uuid {
        self.selected_grant_id
    }

    #[must_use]
    pub const fn decision_id(&self) -> Uuid {
        self.decision_id
    }
}

/// Consumption capability containing only the exact server-derived authorization
/// identity linked during the preceding phase.
#[derive(Debug, PartialEq, Eq)]
pub struct ControlConsumptionWork {
    pub(crate) lease: ControlWorkLease,
    pub(crate) consume_key: ConsumeKey,
}

impl ControlConsumptionWork {
    #[must_use]
    pub const fn lease(&self) -> &ControlWorkLease {
        &self.lease
    }

    #[must_use]
    pub const fn consume_key(&self) -> &ConsumeKey {
        &self.consume_key
    }
}

/// Phase-specific authority returned by the durable queue.
#[derive(Debug, PartialEq, Eq)]
pub enum ClaimedControlWork {
    Evaluate(ControlEvaluationWork),
    Issue(ControlIssuanceWork),
    Consume(ControlConsumptionWork),
}

/// Claim-or-recover result. No token is returned for an ambiguous outcome.
#[derive(Debug, PartialEq, Eq)]
pub enum ControlWorkClaimOutcome {
    Claimed(ClaimedControlWork),
    Recovered(ClaimedControlWork),
    /// A pre-kernel expiry/authority decision was committed while selecting
    /// work, so no capability was returned.
    DecisionFinalized(ControlDecisionReceipt),
    WorkFinalized(ControlWorkFinalizationReceipt),
    /// Exact inert history for a claim whose phase already committed. It
    /// carries no lease or execution authority; a CONSUME key may be passed to
    /// the ordinary read-only recovery API to reload the durable tuple.
    PhaseCompleted(ControlPhaseCompletionReceipt),
    NoWork,
    OutcomeUnknown(ControlWorkClaimRecoveryKey),
}

/// Inert exact-retry receipt for a successfully completed work claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlPhaseCompletionReceipt {
    submission_id: Uuid,
    claim_id: Uuid,
    fence: u64,
    worker_id: String,
    phase: ControlWorkPhase,
    completed_at: i64,
    decision_id: Uuid,
    consume_key: Option<ConsumeKey>,
}

impl ControlPhaseCompletionReceipt {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        submission_id: Uuid,
        claim_id: Uuid,
        fence: u64,
        worker_id: String,
        phase: ControlWorkPhase,
        completed_at: i64,
        decision_id: Uuid,
        consume_key: Option<ConsumeKey>,
    ) -> Result<Self, StateError> {
        let receipt = Self {
            submission_id,
            claim_id,
            fence,
            worker_id,
            phase,
            completed_at,
            decision_id,
            consume_key,
        };
        if receipt.submission_id.is_nil()
            || receipt.claim_id.is_nil()
            || receipt.decision_id.is_nil()
            || receipt.fence == 0
            || receipt.completed_at < 0
            || !valid_worker_id(&receipt.worker_id)
            || receipt.phase == ControlWorkPhase::Done
            || receipt.consume_key.is_some() != (receipt.phase == ControlWorkPhase::Consume)
        {
            return Err(StateError::InvalidRecord(
                "control phase completion receipt is malformed".to_owned(),
            ));
        }
        if let Some(key) = &receipt.consume_key {
            key.validate()?;
        }
        Ok(receipt)
    }

    #[must_use]
    pub const fn submission_id(&self) -> Uuid {
        self.submission_id
    }

    #[must_use]
    pub const fn claim_id(&self) -> Uuid {
        self.claim_id
    }

    #[must_use]
    pub const fn fence(&self) -> u64 {
        self.fence
    }

    #[must_use]
    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    #[must_use]
    pub const fn phase(&self) -> ControlWorkPhase {
        self.phase
    }

    #[must_use]
    pub const fn completed_at(&self) -> i64 {
        self.completed_at
    }

    #[must_use]
    pub const fn decision_id(&self) -> Uuid {
        self.decision_id
    }

    #[must_use]
    pub const fn consume_key(&self) -> Option<&ConsumeKey> {
        self.consume_key.as_ref()
    }
}

/// Terminal fail-closed result for ISSUE or CONSUME after an immutable control
/// decision was already committed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlWorkFinalizationReceipt {
    submission_id: Uuid,
    phase: ControlWorkPhase,
    reason: ControlWorkFinalizationReason,
    finalized_at: i64,
}

impl ControlWorkFinalizationReceipt {
    pub(crate) fn new(
        submission_id: Uuid,
        phase: ControlWorkPhase,
        reason: ControlWorkFinalizationReason,
        finalized_at: i64,
    ) -> Self {
        Self {
            submission_id,
            phase,
            reason,
            finalized_at,
        }
    }

    #[must_use]
    pub const fn submission_id(&self) -> Uuid {
        self.submission_id
    }

    #[must_use]
    pub const fn phase(&self) -> ControlWorkPhase {
        self.phase
    }

    #[must_use]
    pub const fn reason(&self) -> ControlWorkFinalizationReason {
        self.reason
    }

    #[must_use]
    pub const fn finalized_at(&self) -> i64 {
        self.finalized_at
    }
}

/// Immutable control decision summary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlDecisionReceipt {
    decision_id: Uuid,
    submission_id: Uuid,
    kernel_outcome: Option<ControlKernelOutcome>,
    control_outcome: ControlOutcome,
    reason: ControlDecisionReason,
    selected_grant_id: Option<Uuid>,
    decided_at: i64,
}

impl ControlDecisionReceipt {
    pub(crate) fn new(
        decision_id: Uuid,
        submission_id: Uuid,
        kernel_outcome: Option<ControlKernelOutcome>,
        control_outcome: ControlOutcome,
        reason: ControlDecisionReason,
        selected_grant_id: Option<Uuid>,
        decided_at: i64,
    ) -> Self {
        Self {
            decision_id,
            submission_id,
            kernel_outcome,
            control_outcome,
            reason,
            selected_grant_id,
            decided_at,
        }
    }

    #[must_use]
    pub const fn decision_id(&self) -> Uuid {
        self.decision_id
    }

    #[must_use]
    pub const fn submission_id(&self) -> Uuid {
        self.submission_id
    }

    #[must_use]
    pub const fn kernel_outcome(&self) -> Option<ControlKernelOutcome> {
        self.kernel_outcome
    }

    #[must_use]
    pub const fn control_outcome(&self) -> ControlOutcome {
        self.control_outcome
    }

    #[must_use]
    pub const fn reason(&self) -> ControlDecisionReason {
        self.reason
    }

    #[must_use]
    pub const fn selected_grant_id(&self) -> Option<Uuid> {
        self.selected_grant_id
    }

    #[must_use]
    pub const fn decided_at(&self) -> i64 {
        self.decided_at
    }
}

/// Atomic deterministic authorization-record + control-link outcome. `OutcomeUnknown`
/// never returns signed material as success; a worker must reclaim durable
/// state to learn whether ISSUE advanced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlIssuanceCommitOutcome {
    Committed,
    Recovered,
    /// Currentness disappeared after ISSUE was claimed. State committed a
    /// terminal fail-closed result instead of creating authorization material.
    Finalized(ControlWorkFinalizationReceipt),
    OutcomeUnknown {
        submission_id: Uuid,
    },
}

/// Atomic consume/outbox + control-link outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlConsumptionCommitOutcome {
    Committed(ConsumeSuccess),
    Recovered(ConsumeSuccess),
    /// Currentness or the effective dispatch window disappeared after CONSUME
    /// was claimed. State committed a terminal fail-closed result.
    Finalized(ControlWorkFinalizationReceipt),
    OutcomeUnknown {
        submission_id: Uuid,
    },
}

/// Sealed durable control-plane state API.
pub trait ControlPlaneState: crate::sealed::Sealed + Send + Sync {
    /// Looks up frozen verifier material by exact canonical payload before any
    /// current-time or HWM check. Absence is not an authentication result.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when the probe or its durable frozen lineage is
    /// malformed, ambiguous, or unavailable.
    fn control_recovery_verifier(
        &self,
        probe: &IngressRecoveryProbe,
    ) -> Result<Option<FrozenIngressVerifier>, StateError>;

    /// Returns an inert exact historical reference after comparing every
    /// verified frozen fact back to the immutable durable row. The first wire
    /// audit remains the stored wire, never the presented retry wire.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when no exact submission exists or any frozen,
    /// indexed, status, queue, or artifact lineage check fails.
    fn recover_control_submission(
        &self,
        verified: &VerifiedHistoricalIngress,
    ) -> Result<RecoveredSubmissionRef, StateError>;

    /// Under one state-owned lock/transaction: reloads exact current authority,
    /// locks HWM, samples trusted time after locks, persists authenticated
    /// temporal rejection HWM, and on success atomically writes HWM + permanent
    /// v13 nonce + immutable submission + ACCEPTED status/event + EVALUATE READY
    /// work. Caller-provided time/authority is never trusted independently of
    /// the current rooted registry binding.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] for invalid authentication, routing, authority,
    /// time, replay, collision, or durable-state invariants.
    fn accept_control_submission_or_recover(
        &self,
        verified: StaticallyVerifiedIngressSubmission,
    ) -> Result<ControlSubmissionIntakeOutcome, StateError>;

    /// Claims or exactly recovers one phase with DB-time/HWM lease fencing.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when the request is malformed or the selected
    /// queue, claim, lease, role, HWM, or artifact lineage is inconsistent.
    fn claim_next_control_work_or_recover(
        &self,
        request: &ControlWorkClaimRequest,
    ) -> Result<ControlWorkClaimOutcome, StateError>;

    /// Persists the exact signed kernel evaluation before issuance and chooses
    /// zero or one matching current grant inside the same transaction. More
    /// than one grant is structural corruption in this mono-grant profile.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] if the work capability, evaluation signature,
    /// authority, lease, policy result, or selected server grant is invalid.
    fn record_control_evaluation(
        &self,
        work: ControlEvaluationWork,
        signed_evaluation: &SignedEvaluation,
        evaluator: &CoseVerifier,
    ) -> Result<ControlDecisionReceipt, StateError>;

    /// Revalidates the exact ISSUE lease/fence/decision/current grant and
    /// returns a non-forgeable issuance snapshot whose `issued_at` is fixed to
    /// the durable claim time, making retries byte-deterministic.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] if current authority, grant, time, lease, or the
    /// durable decision lineage no longer authorizations issuance.
    fn control_issuance_snapshot(
        &self,
        work: &ControlIssuanceWork,
    ) -> Result<IssuanceSnapshot, StateError>;

    /// Atomically records-or-recovers the exact deterministic authorization, creates
    /// its control issuance link/status/event, and advances work to CONSUME.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when the work, authorization, signer, grant, lease, or
    /// existing durable tuple does not match the exact control lineage.
    fn record_and_link_control_issuance_or_recover(
        &self,
        work: ControlIssuanceWork,
        issued: &IssuedAuthorizationRecord,
    ) -> Result<ControlIssuanceCommitOutcome, StateError>;

    /// Atomically consumes-or-recovers the exact authorization, writes the consumption
    /// receipt and execution outbox, creates the control link/status/event, and
    /// moves the queue to DONE. No caller-supplied receipt/outbox is accepted.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when consumption is no longer authorized or any
    /// work, authorization, receipt, outbox, lease, or lineage invariant fails.
    fn consume_and_link_control_or_recover(
        &self,
        work: ControlConsumptionWork,
    ) -> Result<ControlConsumptionCommitOutcome, StateError>;

    /// Loads the inert status projection by stable receipt identifier.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when the scope/receipt is unknown or the complete
    /// frozen status, event, queue, and phase-artifact lineage is invalid.
    fn control_status(
        &self,
        scope: &Scope,
        receipt_id: Uuid,
    ) -> Result<ControlStatusSnapshot, StateError>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredControlSubmission {
    pub state_instance_id: Uuid,
    pub submission_id: Uuid,
    pub receipt_id: Uuid,
    pub evaluation_nonce: Uuid,
    pub replay_scope: String,
    pub key_id: String,
    pub nonce: Uuid,
    pub canonical_payload_commitment: Digest32,
    pub first_wire_commitment: Digest32,
    pub first_wire_json: Vec<u8>,
    pub canonical_claims: Vec<u8>,
    pub cose_sign1: Vec<u8>,
    pub proposal: AgentProposal,
    pub proposal_commitment: Digest32,
    pub tenant: String,
    pub environment: String,
    pub actor: String,
    pub audience: String,
    pub ingress_issued_at: i64,
    pub ingress_expires_at: i64,
    pub accepted_at: i64,
    pub key_public_key: [u8; 32],
    pub key_not_before: i64,
    pub key_expires_at: i64,
    pub maximum_lifetime_seconds: i64,
    pub ingress_authority_domain: AuthorityDomainState,
}

impl StoredControlSubmission {
    fn prospective_ids(
        state_instance_id: Uuid,
        canonical_payload_commitment: Digest32,
        request_id: Uuid,
    ) -> (Uuid, Uuid, Uuid) {
        let submission_id = derive_control_uuid(
            b"accordlock:v13:control-submission",
            &[
                state_instance_id.as_bytes(),
                canonical_payload_commitment.as_bytes(),
            ],
        );
        let receipt_id = derive_control_uuid(
            b"accordlock:v13:control-receipt",
            &[state_instance_id.as_bytes(), submission_id.as_bytes()],
        );
        let evaluation_nonce = derive_control_uuid(
            b"accordlock:v13:evaluation-nonce",
            &[
                state_instance_id.as_bytes(),
                submission_id.as_bytes(),
                request_id.as_bytes(),
            ],
        );
        (submission_id, receipt_id, evaluation_nonce)
    }

    pub(crate) fn prospective_evaluation_nonce(
        state_instance_id: Uuid,
        verified: &StaticallyVerifiedIngressSubmission,
    ) -> Uuid {
        Self::prospective_ids(
            state_instance_id,
            verified.canonical_payload_commitment(),
            verified.proposal().request_id,
        )
        .2
    }

    pub(crate) fn from_verified(
        state_instance_id: Uuid,
        verified: &StaticallyVerifiedIngressSubmission,
        accepted_at: i64,
    ) -> Result<Self, StateError> {
        let proposal_commitment = canonical_hash(verified.proposal())?;
        let (submission_id, receipt_id, evaluation_nonce) = Self::prospective_ids(
            state_instance_id,
            verified.canonical_payload_commitment(),
            verified.proposal().request_id,
        );
        let stored = Self {
            state_instance_id,
            submission_id,
            receipt_id,
            evaluation_nonce,
            replay_scope: verified.replay_scope().as_str().to_owned(),
            key_id: verified.key_id().to_owned(),
            nonce: verified.nonce(),
            canonical_payload_commitment: verified.canonical_payload_commitment(),
            first_wire_commitment: verified.wire_commitment(),
            first_wire_json: verified.wire_json().to_vec(),
            canonical_claims: verified.canonical_claims().to_vec(),
            cose_sign1: verified.cose_sign1().to_vec(),
            proposal: verified.proposal().clone(),
            proposal_commitment,
            tenant: verified.caller().tenant().to_owned(),
            environment: verified.proposal().template.environment.clone(),
            actor: verified.caller().actor().to_owned(),
            audience: verified.claims().audience.clone(),
            ingress_issued_at: verified.claims().issued_at,
            ingress_expires_at: verified.claims().expires_at,
            accepted_at,
            key_public_key: verified.key_public_key(),
            key_not_before: verified.key_not_before(),
            key_expires_at: verified.key_expires_at(),
            maximum_lifetime_seconds: verified.maximum_lifetime_seconds(),
            ingress_authority_domain: verified.authority_domain().clone(),
        };
        stored.validate()?;
        Ok(stored)
    }

    pub(crate) fn validate(&self) -> Result<(), StateError> {
        let zero = Digest32::from_bytes([0; 32]);
        let expected_ids = Self::prospective_ids(
            self.state_instance_id,
            self.canonical_payload_commitment,
            self.proposal.request_id,
        );
        if self.state_instance_id.is_nil()
            || self.submission_id.is_nil()
            || self.receipt_id.is_nil()
            || self.evaluation_nonce.is_nil()
            || self.nonce.is_nil()
            || self.proposal.request_id.is_nil()
            || (self.submission_id, self.receipt_id, self.evaluation_nonce) != expected_ids
            || self.canonical_payload_commitment == zero
            || self.first_wire_commitment == zero
            || self.proposal_commitment == zero
            || self.accepted_at < 0
            || self.ingress_issued_at < 0
            || self.accepted_at < self.ingress_issued_at
            || self.accepted_at >= self.ingress_expires_at
            || self.accepted_at < self.key_not_before
            || self.accepted_at >= self.key_expires_at
            || self.ingress_issued_at < self.key_not_before
            || self.ingress_expires_at > self.key_expires_at
            || self.maximum_lifetime_seconds <= 0
            || self
                .ingress_expires_at
                .checked_sub(self.ingress_issued_at)
                .is_none_or(|lifetime| lifetime <= 0 || lifetime > self.maximum_lifetime_seconds)
            || self.tenant != self.proposal.tenant
            || self.actor != self.proposal.actor
            || self.environment != self.proposal.template.environment
            || self.replay_scope != self.audience
            || self.audience != self.proposal.template.audience
            || self.proposal_commitment != canonical_hash(&self.proposal)?
            || self.canonical_claims.is_empty()
            || self.cose_sign1.is_empty()
            || self.first_wire_json.is_empty()
        {
            return Err(StateError::InvalidRecord(
                "durable control submission is malformed or internally inconsistent".to_owned(),
            ));
        }
        let probe = IngressRecoveryProbe::parse_bytes(&self.first_wire_json)
            .map_err(|error| StateError::InvalidRecord(error.to_string()))?;
        if probe.canonical_payload_commitment() != self.canonical_payload_commitment
            || probe.wire_commitment() != self.first_wire_commitment
            || probe.key_id() != self.key_id
            || probe.claims().proposal != self.proposal
            || probe.claims().nonce != self.nonce
            || probe.claims().issued_at != self.ingress_issued_at
            || probe.claims().expires_at != self.ingress_expires_at
            || probe.claims().canonical_bytes().map_err(|error| {
                StateError::InvalidRecord(format!("stored ingress claims are invalid: {error}"))
            })? != self.canonical_claims
            || probe.cose_sign1() != self.cose_sign1
        {
            return Err(StateError::InvalidRecord(
                "durable control submission does not match its signed wire lineage".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn scope(&self) -> Scope {
        Scope {
            tenant: self.tenant.clone(),
            environment: self.environment.clone(),
        }
    }

    pub(crate) fn receipt(&self) -> ControlSubmissionReceipt {
        ControlSubmissionReceipt::new(
            self.submission_id,
            self.receipt_id,
            self.proposal.request_id,
            self.scope(),
            self.accepted_at,
            self.canonical_payload_commitment,
        )
    }

    pub(crate) fn recovery_key(&self) -> ControlSubmissionRecoveryKey {
        ControlSubmissionRecoveryKey::new(
            self.replay_scope.clone(),
            self.key_id.clone(),
            self.nonce,
            self.canonical_payload_commitment,
        )
    }

    pub(crate) fn frozen_verifier(&self) -> Result<FrozenIngressVerifier, StateError> {
        FrozenIngressVerifier::from_persisted(
            self.canonical_payload_commitment,
            self.key_id.clone(),
            self.key_public_key,
            self.tenant.clone(),
            self.actor.clone(),
            self.audience.clone(),
            self.key_not_before,
            self.key_expires_at,
            self.maximum_lifetime_seconds,
            self.ingress_authority_domain.clone(),
        )
        .map_err(|error| StateError::InvalidRecord(error.to_string()))
    }

    pub(crate) fn reverify_frozen_wire(&self) -> Result<(), StateError> {
        let verified = IngressRecoveryProbe::parse_bytes(&self.first_wire_json)
            .map_err(|error| StateError::InvalidRecord(error.to_string()))?
            .verify_historical(&self.frozen_verifier()?)
            .map_err(|error| StateError::InvalidRecord(error.to_string()))?;
        self.matches_historical(&verified)
    }

    pub(crate) fn matches_historical(
        &self,
        verified: &VerifiedHistoricalIngress,
    ) -> Result<(), StateError> {
        if verified.canonical_payload_commitment() != self.canonical_payload_commitment
            || verified.key_id() != self.key_id
            || verified.claims().nonce != self.nonce
            || verified.claims().proposal != self.proposal
            || verified.claims().issued_at != self.ingress_issued_at
            || verified.claims().expires_at != self.ingress_expires_at
            || verified.claims().audience != self.audience
            || verified.authority_domain() != &self.ingress_authority_domain
        {
            return Err(StateError::InvalidRecord(
                "historical ingress verification differs from durable submission".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredControlDecision {
    pub receipt: ControlDecisionReceipt,
    pub evaluation_id: Option<Uuid>,
    pub evaluation_commitment: Option<Digest32>,
    pub decision_commitment: Digest32,
    pub signed_evaluation: Option<SignedEvaluation>,
    pub evaluator_key_id: Option<String>,
    pub evaluator_public_key: Option<[u8; 32]>,
}

pub(crate) fn derive_control_evaluation_id(
    state_instance_id: Uuid,
    submission_id: Uuid,
    evaluation_nonce: Uuid,
) -> Uuid {
    derive_control_uuid(
        b"accordlock:v13:control-evaluation",
        &[
            state_instance_id.as_bytes(),
            submission_id.as_bytes(),
            evaluation_nonce.as_bytes(),
        ],
    )
}

pub(crate) fn derive_control_decision_id(
    state_instance_id: Uuid,
    submission_id: Uuid,
    evaluation_nonce: Uuid,
) -> Uuid {
    derive_control_uuid(
        b"accordlock:v13:control-decision",
        &[
            state_instance_id.as_bytes(),
            submission_id.as_bytes(),
            evaluation_nonce.as_bytes(),
        ],
    )
}

pub(crate) fn control_evaluation_commitment(
    evaluation_id: Uuid,
    submission_id: Uuid,
    claim_id: Uuid,
    scope: &Scope,
    signed_evaluation: &SignedEvaluation,
    evaluator: &CoseVerifier,
) -> Result<Digest32, StateError> {
    scope.validate()?;
    if evaluation_id.is_nil() || submission_id.is_nil() || claim_id.is_nil() {
        return Err(StateError::InvalidRecord(
            "control evaluation commitment identifiers must be non-nil".to_owned(),
        ));
    }
    let canonical_attestation = signed_evaluation.attestation.canonical_bytes()?;
    let mut material = Vec::new();
    push_commitment_frame(&mut material, CONTROL_EVALUATION_COMMITMENT_DOMAIN);
    push_commitment_frame(&mut material, evaluation_id.as_bytes());
    push_commitment_frame(&mut material, submission_id.as_bytes());
    push_commitment_frame(&mut material, claim_id.as_bytes());
    push_commitment_frame(&mut material, scope.tenant.as_bytes());
    push_commitment_frame(&mut material, scope.environment.as_bytes());
    push_commitment_frame(&mut material, &canonical_attestation);
    push_commitment_frame(&mut material, &signed_evaluation.cose_sign1);
    push_commitment_frame(&mut material, evaluator.key_id().as_bytes());
    push_commitment_frame(&mut material, &evaluator.public_key_bytes());
    Ok(Digest32::sha256(&material))
}

pub(crate) fn control_decision_commitment(
    claim_id: Uuid,
    scope: &Scope,
    receipt: &ControlDecisionReceipt,
) -> Result<Digest32, StateError> {
    scope.validate()?;
    if claim_id.is_nil() || receipt.decision_id.is_nil() || receipt.submission_id.is_nil() {
        return Err(StateError::InvalidRecord(
            "control decision commitment identifiers must be non-nil".to_owned(),
        ));
    }
    let mut material = Vec::new();
    push_commitment_frame(&mut material, CONTROL_DECISION_COMMITMENT_DOMAIN);
    push_commitment_frame(&mut material, receipt.decision_id.as_bytes());
    push_commitment_frame(&mut material, receipt.submission_id.as_bytes());
    push_commitment_frame(&mut material, claim_id.as_bytes());
    push_commitment_frame(&mut material, scope.tenant.as_bytes());
    push_commitment_frame(&mut material, scope.environment.as_bytes());
    push_commitment_frame(
        &mut material,
        &[receipt.kernel_outcome.map_or(0, ControlKernelOutcome::code)],
    );
    push_commitment_frame(&mut material, &[receipt.control_outcome.code()]);
    push_commitment_frame(&mut material, &[receipt.reason.code()]);
    if let Some(grant_id) = receipt.selected_grant_id {
        push_commitment_frame(&mut material, &[1]);
        push_commitment_frame(&mut material, grant_id.as_bytes());
    } else {
        push_commitment_frame(&mut material, &[0]);
        push_commitment_frame(&mut material, &[]);
    }
    push_commitment_frame(&mut material, &receipt.decided_at.to_be_bytes());
    Ok(Digest32::sha256(&material))
}

pub(crate) fn control_event_commitment(
    snapshot: &ControlStatusSnapshot,
) -> Result<Digest32, StateError> {
    if snapshot.submission_id.is_nil()
        || snapshot.receipt_id.is_nil()
        || snapshot.revision == 0
        || snapshot.observed_at < 0
    {
        return Err(StateError::InvalidRecord(
            "control event commitment fields are malformed".to_owned(),
        ));
    }
    let mut material = Vec::new();
    push_commitment_frame(&mut material, CONTROL_EVENT_COMMITMENT_DOMAIN);
    push_commitment_frame(&mut material, snapshot.submission_id.as_bytes());
    push_commitment_frame(&mut material, snapshot.receipt_id.as_bytes());
    push_commitment_frame(&mut material, &snapshot.revision.to_be_bytes());
    push_commitment_frame(&mut material, &[snapshot.status.code()]);
    match snapshot.reason {
        Some(ControlStatusReason::Decision(reason)) => {
            push_commitment_frame(&mut material, &[1]);
            push_commitment_frame(&mut material, &[reason.code()]);
        }
        Some(ControlStatusReason::Finalization(reason)) => {
            push_commitment_frame(&mut material, &[2]);
            push_commitment_frame(&mut material, &[reason.code()]);
        }
        None => {
            push_commitment_frame(&mut material, &[0]);
            push_commitment_frame(&mut material, &[]);
        }
    }
    push_commitment_frame(&mut material, &snapshot.observed_at.to_be_bytes());
    Ok(Digest32::sha256(&material))
}

fn push_commitment_frame(material: &mut Vec<u8>, value: &[u8]) {
    material.extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    material.extend_from_slice(value);
}

fn derive_control_uuid(domain: &[u8], components: &[&[u8]]) -> Uuid {
    let mut material = Vec::new();
    material.extend_from_slice(
        &u64::try_from(domain.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    material.extend_from_slice(domain);
    for component in components {
        material.extend_from_slice(
            &u64::try_from(component.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        material.extend_from_slice(component);
    }
    let digest = Digest32::sha256(&material);
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn valid_worker_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._:/@-".contains(&byte)
        })
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use accordlock_protocol::{
        DecisionOutcome, EVALUATION_ATTESTATION_SCHEMA_VERSION, EVALUATION_DOMAIN,
        EvaluationAttestation, ReasonCode, SigningIdentity, sign_cose,
    };

    use super::*;

    fn test_domain(label: &str) -> AuthorityDomainState {
        AuthorityDomainState {
            root: Digest32::sha256(label.as_bytes()),
            epoch: 1,
            activation_id: Uuid::new_v4(),
        }
    }

    fn test_authority() -> AuthorityVector {
        AuthorityVector {
            policy: test_domain("policy"),
            registry: test_domain("registry"),
            revocation: test_domain("revocation"),
            connector: test_domain("connector"),
            resource: test_domain("resource"),
            signer: test_domain("signer"),
            mediation: test_domain("mediation"),
            grant_registry: test_domain("grant"),
            office_act_registry: test_domain("office"),
            principal_registry: test_domain("principal"),
            workload_build_allowlist: test_domain("build"),
            kernel_configuration: test_domain("kernel"),
        }
    }

    fn signed_evaluation(identity: &SigningIdentity) -> SignedEvaluation {
        let authority = test_authority();
        let attestation = EvaluationAttestation {
            schema_version: EVALUATION_ATTESTATION_SCHEMA_VERSION,
            request_id: Uuid::from_u128(1),
            evaluation_nonce: Uuid::from_u128(2),
            tenant: "acme".to_owned(),
            actor: "worker-a".to_owned(),
            evaluated_at: 100,
            outcome: DecisionOutcome::Allow,
            reasons: vec![ReasonCode::Allowed],
            template_hash: Digest32::sha256(b"template"),
            evidence_root: Digest32::sha256(b"evidence"),
            principals: vec!["principal-a".to_owned()],
            policy_root: authority.policy.root,
            authority,
            consume_before: 150,
        };
        SignedEvaluation {
            cose_sign1: sign_cose(
                &attestation.canonical_bytes().unwrap(),
                EVALUATION_DOMAIN,
                identity,
            )
            .unwrap(),
            attestation,
        }
    }

    #[test]
    fn evaluation_commitment_binds_canonical_attestation_and_exact_cose() {
        let evaluator = SigningIdentity::from_seed("commitment-evaluator", [71; 32]);
        let scope = Scope::new("acme", "prod").unwrap();
        let evaluation_id = Uuid::from_u128(3);
        let submission_id = Uuid::from_u128(4);
        let claim_id = Uuid::from_u128(5);
        let signed = signed_evaluation(&evaluator);
        let first = control_evaluation_commitment(
            evaluation_id,
            submission_id,
            claim_id,
            &scope,
            &signed,
            &evaluator.verifier(),
        )
        .unwrap();
        assert_eq!(
            first,
            control_evaluation_commitment(
                evaluation_id,
                submission_id,
                claim_id,
                &scope,
                &signed,
                &evaluator.verifier(),
            )
            .unwrap()
        );

        let mut changed_cose = signed.clone();
        changed_cose.cose_sign1.push(0);
        assert_ne!(
            first,
            control_evaluation_commitment(
                evaluation_id,
                submission_id,
                claim_id,
                &scope,
                &changed_cose,
                &evaluator.verifier(),
            )
            .unwrap()
        );
        let mut changed_attestation = signed;
        changed_attestation
            .attestation
            .principals
            .push("principal-b".to_owned());
        assert_ne!(
            first,
            control_evaluation_commitment(
                evaluation_id,
                submission_id,
                claim_id,
                &scope,
                &changed_attestation,
                &evaluator.verifier(),
            )
            .unwrap()
        );
    }

    #[test]
    fn decision_and_event_commitments_bind_every_projection_field() {
        let scope = Scope::new("acme", "prod").unwrap();
        let receipt = ControlDecisionReceipt::new(
            Uuid::from_u128(10),
            Uuid::from_u128(11),
            Some(ControlKernelOutcome::Allow),
            ControlOutcome::Allow,
            ControlDecisionReason::ControlAllow,
            Some(Uuid::from_u128(12)),
            101,
        );
        let decision = control_decision_commitment(Uuid::from_u128(13), &scope, &receipt).unwrap();
        let changed = ControlDecisionReceipt::new(
            receipt.decision_id(),
            receipt.submission_id(),
            receipt.kernel_outcome(),
            receipt.control_outcome(),
            receipt.reason(),
            Some(Uuid::from_u128(14)),
            receipt.decided_at(),
        );
        assert_ne!(
            decision,
            control_decision_commitment(Uuid::from_u128(13), &scope, &changed).unwrap()
        );

        let event = ControlStatusSnapshot::new(
            receipt.submission_id(),
            Uuid::from_u128(15),
            ControlStatusCode::Authorized,
            Some(ControlStatusReason::Decision(
                ControlDecisionReason::ControlAllow,
            )),
            2,
            101,
        );
        let event_commitment = control_event_commitment(&event).unwrap();
        let changed_event = ControlStatusSnapshot::new(
            event.submission_id(),
            event.receipt_id(),
            ControlStatusCode::FailedClosed,
            Some(ControlStatusReason::Finalization(
                ControlWorkFinalizationReason::AuthorityChanged,
            )),
            event.revision(),
            event.observed_at(),
        );
        assert_ne!(
            event_commitment,
            control_event_commitment(&changed_event).unwrap()
        );
    }
}
