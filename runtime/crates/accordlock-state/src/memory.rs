use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use accordlock_ingress::{
    FrozenIngressVerifier, IngressRecoveryProbe, StaticallyVerifiedIngressSubmission,
    VerifiedHistoricalIngress,
};
use accordlock_protocol::{
    AuthorityVector, CanonicalEncode, ConsumptionReceipt, CoseVerifier, DecisionOutcome, Digest32,
    EVALUATION_ATTESTATION_SCHEMA_VERSION, EVALUATION_DOMAIN, ReasonCode, SignedEvaluation,
    canonical_hash, evaluator_verifier_root, verify_cose,
};
use accordlock_terminal_witness::ActivatedWitnessRegistry;
use parking_lot::Mutex;
use uuid::Uuid;

use crate::acquisition::{
    DISPATCH_ACQUISITION_LEASE_SECONDS, DispatchAcquisitionAuthority,
    DispatchAcquisitionDisposition, DispatchAcquisitionOutcome, DispatchAcquisitionReceipt,
    DispatchAcquisitionRequest, DispatchQueueDispositionReason, DispatchQueueDispositionReceipt,
    DispatchRecoveryWork, DispatchWork, dispatch_authority_fact_commitment,
    dispatch_grant_fact_commitment, dispatch_outbox_fact_commitment,
};
use crate::broker::{
    AcquiredBrokerOperationRequest, AuthenticatedDispatchCredentialReview, BrokerCleanupRequest,
    BrokerIoAuthority, BrokerJournalCapability, BrokerJournalCapabilityIssuer,
    BrokerJournalOperation, BrokerJournalOutcome, BrokerJournalPhase, BrokerJournalSelector,
    BrokerJournalState, BrokerOperationAudit, BrokerOperationIntent, BrokerOperationReceipt,
    BrokerOperationRequest, BrokerReconciliationAuthority, BrokerReconciliationRequest,
    BrokerReconciliationResult, BrokerSecretObservation, BrokerTokenIssueObservation,
    CredentialReviewIoAuthority, DispatchBrokerRestartContext, DispatchCredentialReviewAudit,
    DispatchCredentialReviewPhase, DispatchCredentialReviewRecoveryKey,
    DispatchRestartDeletionEvidence, RejectedDispatchCredentialReview, ReviewedDispatchCredential,
    StoredBrokerOperation, StoredDispatchCredentialReview, broker_result_commitment,
    pending_broker_reconciliation, validate_cleanup_clock,
};
use crate::control::{
    CONTROL_WORK_LEASE_SECONDS, ClaimedControlWork, ControlConsumptionCommitOutcome,
    ControlConsumptionWork, ControlDecisionReason, ControlDecisionReceipt, ControlEvaluationWork,
    ControlIssuanceCommitOutcome, ControlIssuanceWork, ControlKernelOutcome, ControlOutcome,
    ControlPhaseCompletionReceipt, ControlPlaneState, ControlStatusCode, ControlStatusReason,
    ControlStatusSnapshot, ControlSubmissionIntakeOutcome, ControlWorkClaimOutcome,
    ControlWorkClaimRequest, ControlWorkFinalizationReason, ControlWorkFinalizationReceipt,
    ControlWorkLease, ControlWorkPhase, ControlWorkerRole, RecoveredSubmissionRef,
    StoredControlDecision, StoredControlSubmission, control_decision_commitment,
    control_evaluation_commitment, control_event_commitment, derive_control_decision_id,
    derive_control_evaluation_id,
};
use crate::eks_registry::{
    ActivationKey, CurrentEksAttempt, EksDestinationProfile, EksDestinationRegistryState,
    EksRegistryError, FrozenEksAttempt, PhysicalOwner, PhysicalOwnershipKey,
    PinnedRouteOwnershipKey, RootedEksDestination, derive_attempt_facts,
};
use crate::ingress_replay::{
    IngressNonceConsumption, IngressReplayDecision, IngressReplayScope, IngressReplayState,
    valid_gc_limit, validate_observed_time,
};
use crate::model::{
    AdmissionAuthorization, AdmissionAuthorizationRequest, AdmissionContext, AttemptInFlight,
    ClaimedDispatch, ConsumeKey, ConsumeSuccess, DISPATCH_CLAIM_LEASE_SECONDS,
    DispatchAttemptAcquisition, DispatchClaimRequest, DispatchClaimToken,
    DispatchCredentialBinding, DispatchRecoveryAcquisition, DispatchSnapshot, GrantRegistration,
    GrantSnapshot, IssuanceSnapshot, IssuedAuthorizationRecord, OutboxEntry, OutboxStatus,
    PhysicalResourceKey, RecoveryNoSendReceipt, RecoveryNoSendRetirementOutcome,
    RecoveryNoSendRetirementReceipt, Scope, StateError, TransactionalState, admission_projection,
    ensure_monotone_authority, is_temporal_rejection_for_sample,
    validate_admission_provider_commitment, validate_authority_vector, validate_consumption,
    validate_current_grant, validate_dispatch_immutable_facts, validate_dispatch_snapshot,
    validate_grant_for_authorization, validate_recovered_consumption,
    validate_revocation_transition,
};
use crate::terminal::{
    StoredSecretDeletionObservation, StoredTerminalRetirement, TerminalDurableInputs,
    TerminalRetirementAudit, TerminalRetirementContext, TerminalRetirementReceipt,
    TerminalRetirementRequest, TerminalRetirementState, TerminalWitnessRegistryReceipt,
    authenticate_terminal_evidence, derive_terminal_context, same_activated_registry,
    validate_terminal_evidence_time,
};

/// Trusted time source used by the in-memory adapter.
pub trait TrustedClock: Send + Sync {
    /// Returns trusted Unix time in whole seconds.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] if the clock is before the Unix epoch or cannot be
    /// represented by the profile's signed integer.
    fn now_unix_seconds(&self) -> Result<i64, StateError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl TrustedClock for SystemClock {
    fn now_unix_seconds(&self) -> Result<i64, StateError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| StateError::ClockBeforeUnixEpoch)?;
        i64::try_from(duration.as_secs()).map_err(|_| StateError::ClockBeforeUnixEpoch)
    }
}

#[derive(Default)]
struct MemoryState {
    authorities: HashMap<Scope, AuthorityVector>,
    high_water: HashMap<Scope, i64>,
    grants: HashMap<(Scope, Uuid), GrantSnapshot>,
    authorizations: HashMap<(Scope, Uuid), IssuedAuthorizationRecord>,
    transactions: HashMap<(Scope, Uuid), Uuid>,
    receipts: HashMap<(Scope, Uuid), ConsumptionReceipt>,
    outbox: HashMap<(Scope, Uuid), OutboxEntry>,
    dispatch_claims: HashMap<(Scope, Uuid), MemoryDispatchClaim>,
    dispatch_claim_ids: HashMap<Uuid, (Scope, Uuid)>,
    dispatch_acquisitions: HashMap<Uuid, MemoryDispatchAcquisition>,
    latest_dispatch_acquisition: HashMap<(Scope, Uuid), Uuid>,
    dispatch_dispositions: HashMap<Uuid, DispatchQueueDispositionReceipt>,
    dispatch_disposition_by_submission: HashMap<Uuid, Uuid>,
    physical_reservations: HashMap<PhysicalResourceKey, (Scope, Uuid)>,
    admission_authorizations: HashMap<String, MemoryAdmissionAuthorization>,
    admission_transactions: HashMap<(Scope, Uuid), String>,
    admission_claim_ids: HashMap<Uuid, String>,
    admission_fences: HashMap<u64, String>,
    admission_provider_requests: HashMap<Digest32, String>,
    broker_operations: HashMap<(Scope, Uuid, BrokerJournalOperation), StoredBrokerOperation>,
    credential_reviews: HashMap<(Scope, Uuid), StoredDispatchCredentialReview>,
    credential_review_ids: HashMap<Uuid, (Scope, Uuid)>,
    secret_deletion_observations: HashMap<(Scope, Uuid), StoredSecretDeletionObservation>,
    secret_deletion_entry_ids: HashMap<Uuid, (Scope, Uuid)>,
    terminal_witness_registries: HashMap<Digest32, ActivatedWitnessRegistry>,
    terminal_witness_registry_bindings: HashMap<ActivationKey, Digest32>,
    terminal_retirements: HashMap<(Scope, Uuid), StoredTerminalRetirement>,
    terminalization_ids: HashMap<Uuid, (Scope, Uuid)>,
    terminal_effect_evidence_ids: HashMap<Uuid, (Scope, Uuid)>,
    terminal_retirement_evidence_ids: HashMap<Uuid, (Scope, Uuid)>,
    terminal_effect_envelope_commitments: HashMap<Digest32, (Scope, Uuid)>,
    terminal_retirement_envelope_commitments: HashMap<Digest32, (Scope, Uuid)>,
    eks_physical_owners: HashMap<PhysicalOwnershipKey, PhysicalOwner>,
    eks_route_owners: HashMap<PinnedRouteOwnershipKey, PhysicalOwner>,
    eks_destinations: HashMap<ActivationKey, RootedEksDestination>,
    ingress_replay_high_water: HashMap<IngressReplayScope, i64>,
    ingress_replay_nonces: HashMap<(IngressReplayScope, String, Uuid), i64>,
    ingress_replay_v13_nonces: HashSet<(IngressReplayScope, String, Uuid)>,
    control_submissions: HashMap<Uuid, StoredControlSubmission>,
    control_by_payload_commitment: HashMap<Digest32, Uuid>,
    control_by_request: HashMap<(Scope, Uuid), Uuid>,
    control_by_receipt: HashMap<(Scope, Uuid), Uuid>,
    control_by_receipt_id: HashMap<Uuid, Uuid>,
    control_by_evaluation_nonce: HashMap<Uuid, Uuid>,
    control_by_decision_id: HashMap<Uuid, Uuid>,
    control_by_evaluation_commitment: HashMap<Digest32, Uuid>,
    control_by_decision_commitment: HashMap<Digest32, Uuid>,
    control_by_event_commitment: HashMap<Digest32, (Uuid, u64)>,
    control_event_commitments: HashMap<(Uuid, u64), Digest32>,
    control_statuses: HashMap<Uuid, ControlStatusSnapshot>,
    control_events: HashMap<Uuid, Vec<ControlStatusSnapshot>>,
    control_queue: HashMap<Uuid, MemoryControlQueue>,
    control_claims: HashMap<Uuid, MemoryControlClaim>,
    control_decisions: HashMap<Uuid, StoredControlDecision>,
    control_issuances: HashMap<Uuid, IssuedAuthorizationRecord>,
    control_consumptions: HashMap<Uuid, ConsumeSuccess>,
    next_dispatch_fence: u64,
    next_dispatch_acquisition_fence: u64,
    next_control_fence: u64,
}

/// Savepoint for the v13 in-memory adapter. `PostgreSQL` supplies rollback at
/// the transaction boundary; the conformance adapter must provide the same
/// observable all-or-nothing behavior even though its shared maps are updated
/// in place behind one mutex.
#[derive(Clone)]
struct MemoryControlSavepoint {
    high_water: HashMap<Scope, i64>,
    grants: HashMap<(Scope, Uuid), GrantSnapshot>,
    authorizations: HashMap<(Scope, Uuid), IssuedAuthorizationRecord>,
    transactions: HashMap<(Scope, Uuid), Uuid>,
    receipts: HashMap<(Scope, Uuid), ConsumptionReceipt>,
    outbox: HashMap<(Scope, Uuid), OutboxEntry>,
    ingress_replay_high_water: HashMap<IngressReplayScope, i64>,
    ingress_replay_nonces: HashMap<(IngressReplayScope, String, Uuid), i64>,
    ingress_replay_v13_nonces: HashSet<(IngressReplayScope, String, Uuid)>,
    control_submissions: HashMap<Uuid, StoredControlSubmission>,
    control_by_payload_commitment: HashMap<Digest32, Uuid>,
    control_by_request: HashMap<(Scope, Uuid), Uuid>,
    control_by_receipt: HashMap<(Scope, Uuid), Uuid>,
    control_by_receipt_id: HashMap<Uuid, Uuid>,
    control_by_evaluation_nonce: HashMap<Uuid, Uuid>,
    control_by_decision_id: HashMap<Uuid, Uuid>,
    control_by_evaluation_commitment: HashMap<Digest32, Uuid>,
    control_by_decision_commitment: HashMap<Digest32, Uuid>,
    control_by_event_commitment: HashMap<Digest32, (Uuid, u64)>,
    control_event_commitments: HashMap<(Uuid, u64), Digest32>,
    control_statuses: HashMap<Uuid, ControlStatusSnapshot>,
    control_events: HashMap<Uuid, Vec<ControlStatusSnapshot>>,
    control_queue: HashMap<Uuid, MemoryControlQueue>,
    control_claims: HashMap<Uuid, MemoryControlClaim>,
    control_decisions: HashMap<Uuid, StoredControlDecision>,
    control_issuances: HashMap<Uuid, IssuedAuthorizationRecord>,
    control_consumptions: HashMap<Uuid, ConsumeSuccess>,
    next_control_fence: u64,
}

impl MemoryControlSavepoint {
    fn capture(state: &MemoryState) -> Self {
        Self {
            high_water: state.high_water.clone(),
            grants: state.grants.clone(),
            authorizations: state.authorizations.clone(),
            transactions: state.transactions.clone(),
            receipts: state.receipts.clone(),
            outbox: state.outbox.clone(),
            ingress_replay_high_water: state.ingress_replay_high_water.clone(),
            ingress_replay_nonces: state.ingress_replay_nonces.clone(),
            ingress_replay_v13_nonces: state.ingress_replay_v13_nonces.clone(),
            control_submissions: state.control_submissions.clone(),
            control_by_payload_commitment: state.control_by_payload_commitment.clone(),
            control_by_request: state.control_by_request.clone(),
            control_by_receipt: state.control_by_receipt.clone(),
            control_by_receipt_id: state.control_by_receipt_id.clone(),
            control_by_evaluation_nonce: state.control_by_evaluation_nonce.clone(),
            control_by_decision_id: state.control_by_decision_id.clone(),
            control_by_evaluation_commitment: state.control_by_evaluation_commitment.clone(),
            control_by_decision_commitment: state.control_by_decision_commitment.clone(),
            control_by_event_commitment: state.control_by_event_commitment.clone(),
            control_event_commitments: state.control_event_commitments.clone(),
            control_statuses: state.control_statuses.clone(),
            control_events: state.control_events.clone(),
            control_queue: state.control_queue.clone(),
            control_claims: state.control_claims.clone(),
            control_decisions: state.control_decisions.clone(),
            control_issuances: state.control_issuances.clone(),
            control_consumptions: state.control_consumptions.clone(),
            next_control_fence: state.next_control_fence,
        }
    }

    fn restore(self, state: &mut MemoryState) {
        state.high_water = self.high_water;
        state.grants = self.grants;
        state.authorizations = self.authorizations;
        state.transactions = self.transactions;
        state.receipts = self.receipts;
        state.outbox = self.outbox;
        state.ingress_replay_high_water = self.ingress_replay_high_water;
        state.ingress_replay_nonces = self.ingress_replay_nonces;
        state.ingress_replay_v13_nonces = self.ingress_replay_v13_nonces;
        state.control_submissions = self.control_submissions;
        state.control_by_payload_commitment = self.control_by_payload_commitment;
        state.control_by_request = self.control_by_request;
        state.control_by_receipt = self.control_by_receipt;
        state.control_by_receipt_id = self.control_by_receipt_id;
        state.control_by_evaluation_nonce = self.control_by_evaluation_nonce;
        state.control_by_decision_id = self.control_by_decision_id;
        state.control_by_evaluation_commitment = self.control_by_evaluation_commitment;
        state.control_by_decision_commitment = self.control_by_decision_commitment;
        state.control_by_event_commitment = self.control_by_event_commitment;
        state.control_event_commitments = self.control_event_commitments;
        state.control_statuses = self.control_statuses;
        state.control_events = self.control_events;
        state.control_queue = self.control_queue;
        state.control_claims = self.control_claims;
        state.control_decisions = self.control_decisions;
        state.control_issuances = self.control_issuances;
        state.control_consumptions = self.control_consumptions;
        state.next_control_fence = self.next_control_fence;
    }
}

fn finish_memory_control_scope_transaction<T>(
    state: &mut MemoryState,
    savepoint: MemoryControlSavepoint,
    stored: &StoredControlSubmission,
    observed_at: i64,
    result: Result<T, StateError>,
) -> Result<T, StateError> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => {
            let preserve_hwm = is_temporal_rejection_for_sample(&error, observed_at);
            savepoint.restore(state);
            if preserve_hwm {
                memory_advance_control_high_water(state, stored, observed_at)?;
            }
            Err(error)
        }
    }
}

fn memory_control_high_water(
    state: &MemoryState,
    stored: &StoredControlSubmission,
) -> Result<i64, StateError> {
    let replay_scope = IngressReplayScope::new(stored.replay_scope.clone())?;
    let scope_high_water = state.high_water.get(&stored.scope()).copied().unwrap_or(0);
    let ingress_high_water = state
        .ingress_replay_high_water
        .get(&replay_scope)
        .copied()
        .unwrap_or(0);
    Ok(scope_high_water.max(ingress_high_water))
}

fn memory_advance_control_high_water(
    state: &mut MemoryState,
    stored: &StoredControlSubmission,
    observed_at: i64,
) -> Result<(), StateError> {
    let replay_scope = IngressReplayScope::new(stored.replay_scope.clone())?;
    let scope = stored.scope();
    let scope_prior = state.high_water.get(&scope).copied().unwrap_or(0);
    let ingress_prior = state
        .ingress_replay_high_water
        .get(&replay_scope)
        .copied()
        .unwrap_or(0);
    state.high_water.insert(scope, scope_prior.max(observed_at));
    state
        .ingress_replay_high_water
        .insert(replay_scope, ingress_prior.max(observed_at));
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MemoryDispatchClaimState {
    Claimed,
    AttemptInFlight,
    RecoveryNoSend,
    RecoveryRetired,
    Disposed,
    Terminal,
}

#[derive(Debug)]
struct MemoryDispatchClaim {
    token: DispatchClaimToken,
    state: MemoryDispatchClaimState,
    attempt_started_at: Option<i64>,
    attempt_acquisition: Option<DispatchAttemptAcquisition>,
    credential: Option<DispatchCredentialBinding>,
    credential_review_id: Option<Uuid>,
    recovery_safe_after: Option<i64>,
    recovery_retired_at: Option<i64>,
    terminalization_id: Option<Uuid>,
}

#[derive(Clone, Debug)]
struct MemoryDispatchAcquisition {
    token: DispatchClaimToken,
    acquisition_id: Uuid,
    lease_fence: u64,
    worker_id: String,
    acquired_at: i64,
    lease_until: i64,
    dispatch_deadline: i64,
    control_submission_id: Option<Uuid>,
    selection_kind: MemoryDispatchAcquisitionKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MemoryDispatchAcquisitionKind {
    ControlQueue,
    #[allow(dead_code)]
    ControlBootstrapV13,
    LegacyBootstrap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MemoryControlQueue {
    phase: ControlWorkPhase,
    active_claim_id: Option<Uuid>,
}

#[derive(Clone, Debug)]
struct MemoryControlClaim {
    submission_id: Uuid,
    phase: ControlWorkPhase,
    worker_id: String,
    role: ControlWorkerRole,
    claim_id: Uuid,
    fence: u64,
    claimed_at: i64,
    lease_until: i64,
    completed: bool,
    completed_at: Option<i64>,
    finalized_decision: Option<Uuid>,
    finalized_work: Option<ControlWorkFinalizationReceipt>,
}

#[derive(Debug)]
struct MemoryAdmissionAuthorization {
    request: AdmissionAuthorizationRequest,
    authorized_at: i64,
}

/// Process-local implementation with one mutex as its serialization point.
///
/// It is intended for deterministic conformance and local development. It is
/// not durable and therefore cannot satisfy the production storage profile.
#[derive(Clone)]
pub struct InMemoryStore {
    inner: Arc<Mutex<MemoryState>>,
    clock: Arc<dyn TrustedClock>,
    state_instance_id: Uuid,
    broker_capability_issuer: BrokerJournalCapabilityIssuer,
}

impl fmt::Debug for InMemoryStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemoryStore")
            .field("clock", &"<trusted-clock>")
            .finish_non_exhaustive()
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryStore {
    #[must_use]
    pub fn new() -> Self {
        Self::with_clock(Arc::new(SystemClock))
    }

    #[must_use]
    pub fn with_clock(clock: Arc<dyn TrustedClock>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(MemoryState::default())),
            clock,
            state_instance_id: Uuid::new_v4(),
            broker_capability_issuer: BrokerJournalCapabilityIssuer::default(),
        }
    }

    fn require_broker_capability(
        &self,
        capability: &BrokerJournalCapability,
    ) -> Result<(), StateError> {
        self.broker_capability_issuer
            .validate(capability, self.state_instance_id)
    }

    fn recover_exact(&self, key: &ConsumeKey) -> Result<ConsumeSuccess, StateError> {
        key.validate()?;
        let state = self.inner.lock();
        let authorization_key = (key.scope.clone(), key.authorization_id);
        let issued = state
            .authorizations
            .get(&authorization_key)
            .ok_or(StateError::AuthorizationNotFound)?;
        if issued.transaction_id != key.transaction_id {
            return Err(StateError::TransactionMismatch);
        }
        let indexed_authorization_id = state
            .transactions
            .get(&(key.scope.clone(), key.transaction_id))
            .ok_or(StateError::TransactionMismatch)?;
        if indexed_authorization_id != &key.authorization_id {
            return Err(StateError::TransactionMismatch);
        }
        let receipt = state
            .receipts
            .get(&authorization_key)
            .ok_or(StateError::ConsumptionNotFound)?;
        let outbox = state
            .outbox
            .get(&authorization_key)
            .ok_or(StateError::ConsumptionNotFound)?;
        let success = validate_recovered_consumption(key, issued, receipt, outbox)?;
        validate_memory_control_consumption_lineage_if_owned(&state, key, issued, receipt, outbox)?;
        Ok(success)
    }
}

fn memory_dispatch_snapshot(
    state: &MemoryState,
    key: &ConsumeKey,
    observed_time: i64,
) -> Result<DispatchSnapshot, StateError> {
    memory_dispatch_snapshot_at_high_water(
        state,
        key,
        observed_time,
        state.high_water.get(&key.scope).copied(),
    )
}

fn memory_dispatch_snapshot_at_high_water(
    state: &MemoryState,
    key: &ConsumeKey,
    observed_time: i64,
    high_water: Option<i64>,
) -> Result<DispatchSnapshot, StateError> {
    let authorization_key = (key.scope.clone(), key.authorization_id);
    let issued = state
        .authorizations
        .get(&authorization_key)
        .cloned()
        .ok_or(StateError::AuthorizationNotFound)?;
    if issued.transaction_id != key.transaction_id {
        return Err(StateError::TransactionMismatch);
    }
    let indexed_authorization_id = state
        .transactions
        .get(&(key.scope.clone(), key.transaction_id))
        .ok_or(StateError::TransactionMismatch)?;
    if indexed_authorization_id != &key.authorization_id {
        return Err(StateError::TransactionMismatch);
    }
    let authority = state
        .authorities
        .get(&key.scope)
        .cloned()
        .ok_or(StateError::AuthorityNotInitialized)?;
    let grant = state
        .grants
        .get(&(key.scope.clone(), issued.authorization().grant_id))
        .cloned()
        .ok_or(StateError::GrantNotFound)?;
    if grant.uses == 0 {
        return Err(StateError::GrantNotConsumed);
    }
    let receipt = state
        .receipts
        .get(&authorization_key)
        .cloned()
        .ok_or(StateError::ConsumptionNotFound)?;
    let outbox = state
        .outbox
        .get(&authorization_key)
        .cloned()
        .ok_or(StateError::ConsumptionNotFound)?;
    validate_memory_control_consumption_lineage_if_owned(state, key, &issued, &receipt, &outbox)?;
    validate_dispatch_snapshot(
        key,
        &authority,
        &grant,
        &issued,
        &receipt,
        &outbox,
        observed_time,
        high_water,
    )
}

fn memory_dispatch_snapshot_with_high_water(
    state: &mut MemoryState,
    key: &ConsumeKey,
    observed_time: i64,
) -> Result<DispatchSnapshot, StateError> {
    let result = memory_dispatch_snapshot(state, key, observed_time);
    let observation_is_monotone = state
        .high_water
        .get(&key.scope)
        .is_none_or(|high_water| observed_time >= *high_water);
    let must_persist = result.is_ok()
        || result
            .as_ref()
            .is_err_and(|error| is_temporal_rejection_for_sample(error, observed_time));
    if observation_is_monotone && must_persist {
        state.high_water.insert(key.scope.clone(), observed_time);
    }
    result
}

struct MemoryPostAttemptLineage {
    token: DispatchClaimToken,
    started_at: i64,
    credential_token_digest: Digest32,
    service_account_uid: String,
    credential_id: String,
    credential_not_before: i64,
    credential_expires_at: i64,
    credential_commitment: Digest32,
    control_submission: Option<StoredControlSubmission>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MemoryPostAttemptPhase {
    AttemptInFlight,
    Terminal,
}

#[allow(clippy::too_many_lines)]
fn memory_post_attempt_lineage_for_phase(
    state: &MemoryState,
    key: &ConsumeKey,
    required_phase: MemoryPostAttemptPhase,
) -> Result<MemoryPostAttemptLineage, StateError> {
    let claim = state
        .dispatch_claims
        .get(&(key.scope.clone(), key.authorization_id))
        .ok_or(StateError::DispatchClaimNotFound)?;
    if claim.token.key() != key {
        return Err(StateError::AdmissionClaimMismatch);
    }
    let owns_active_reservation = state
        .physical_reservations
        .get(claim.token.physical_resource())
        == Some(&(key.scope.clone(), key.authorization_id));
    let phase_matches = match required_phase {
        MemoryPostAttemptPhase::AttemptInFlight => {
            claim.state == MemoryDispatchClaimState::AttemptInFlight && owns_active_reservation
        }
        MemoryPostAttemptPhase::Terminal => {
            claim.state == MemoryDispatchClaimState::Terminal && !owns_active_reservation
        }
    };
    if !phase_matches {
        return Err(StateError::AdmissionClaimNotInFlight);
    }
    let started_at = claim.attempt_started_at.ok_or_else(|| {
        StateError::InvalidRecord("ATTEMPT_IN_FLIGHT claim has no durable start time".to_owned())
    })?;
    let attempt = claim.attempt_acquisition.as_ref().ok_or_else(|| {
        StateError::InvalidRecord(
            "ATTEMPT_IN_FLIGHT claim has no durable acquisition binding".to_owned(),
        )
    })?;
    let credential = claim.credential.as_ref().ok_or_else(|| {
        StateError::InvalidRecord(
            "ATTEMPT_IN_FLIGHT claim has no durable credential binding".to_owned(),
        )
    })?;
    let acquisition = state
        .dispatch_acquisitions
        .get(&attempt.acquisition_id())
        .ok_or(StateError::DispatchAcquisitionMismatch)?;
    if acquisition.token != claim.token
        || acquisition.lease_fence != attempt.lease_fence()
        || acquisition.worker_id != attempt.worker_id()
        || acquisition.acquired_at != attempt.acquired_at()
        || acquisition.lease_until != attempt.lease_until()
        || acquisition.dispatch_deadline != attempt.dispatch_deadline()
        || acquisition.control_submission_id != attempt.control_submission_id()
    {
        return Err(StateError::DispatchAcquisitionMismatch);
    }
    let authority = memory_dispatch_acquisition_authority(acquisition);
    let control_submission = match acquisition.selection_kind {
        MemoryDispatchAcquisitionKind::ControlQueue => {
            let submission_id = acquisition
                .control_submission_id
                .ok_or(StateError::DispatchCredentialReviewMismatch)?;
            if credential.binding_version() != 2 || !credential.matches_acquisition(&authority) {
                return Err(StateError::DispatchCredentialReviewMismatch);
            }
            let review_id = claim
                .credential_review_id
                .filter(|review_id| Some(*review_id) == attempt.credential_review_id())
                .filter(|review_id| Some(*review_id) == credential.credential_review_id())
                .ok_or(StateError::DispatchCredentialReviewMismatch)?;
            let review = state
                .credential_reviews
                .get(&(key.scope.clone(), key.authorization_id))
                .ok_or(StateError::DispatchCredentialReviewNotFound)?;
            let review_commitment = review
                .review_commitment
                .ok_or(StateError::DispatchCredentialReviewMismatch)?;
            if review.review_id != review_id
                || review.phase != DispatchCredentialReviewPhase::Authenticated
                || !credential.matches_review(&authority, review_id, review_commitment)
                || attempt.credential_lifecycle_policy() != Some(review.credential_lifecycle_policy)
                || attempt.destination_activation_commitment()
                    != Some(review.destination_activation_commitment)
            {
                return Err(StateError::DispatchCredentialReviewMismatch);
            }
            validate_memory_credential_review_frozen_lineage(state, review)?;
            validate_memory_attempt_broker_lineage(state, &authority, credential, 2)?;
            Some(memory_control_submission_for_dispatch(state, submission_id, key)?.clone())
        }
        MemoryDispatchAcquisitionKind::ControlBootstrapV13 => {
            let submission_id = acquisition
                .control_submission_id
                .ok_or(StateError::AdmissionCredentialMismatch)?;
            if acquisition.acquisition_id != claim.token.claim_id()
                || acquisition.lease_fence != claim.token.fence()
                || acquisition.worker_id != claim.token.worker_id()
                || acquisition.acquired_at != claim.token.claimed_at()
                || acquisition.lease_until != claim.token.lease_until()
                || credential.binding_version() != 1
                || !credential.matches_token(&claim.token)
                || claim.credential_review_id.is_some()
                || attempt.credential_review_id().is_some()
                || credential.credential_review_id().is_some()
            {
                return Err(StateError::AdmissionCredentialMismatch);
            }
            validate_memory_optional_bootstrap_attempt_broker_lineage(
                state, &authority, credential,
            )?;
            Some(memory_control_submission_for_dispatch(state, submission_id, key)?.clone())
        }
        MemoryDispatchAcquisitionKind::LegacyBootstrap => {
            // The acquisition lease fence has its own monotone sequence; it
            // is validated against the durable attempt above, not against the
            // stable claim fence.
            if acquisition.control_submission_id.is_some()
                || acquisition.acquisition_id != claim.token.claim_id()
                || acquisition.worker_id != claim.token.worker_id()
                || acquisition.acquired_at != claim.token.claimed_at()
                || acquisition.lease_until != claim.token.lease_until()
                || claim.credential_review_id.is_some()
                || attempt.credential_review_id().is_some()
                || credential.credential_review_id().is_some()
                || (credential.binding_version() == 2
                    && !credential.matches_acquisition(&authority))
                || (credential.binding_version() == 1 && !credential.matches_token(&claim.token))
                || !matches!(credential.binding_version(), 1 | 2)
            {
                return Err(StateError::AdmissionCredentialMismatch);
            }
            // Historical and post-v14 non-control bootstrap ATTEMPT rows are
            // deliberately token-only compatibility records. They do not
            // require a broker journal; the profile is frozen by the exact
            // bootstrap acquisition tuple above and can never mint a control
            // acquisition or provider authority.
            None
        }
    };
    Ok(MemoryPostAttemptLineage {
        token: claim.token.clone(),
        started_at,
        credential_token_digest: credential.token_digest(),
        service_account_uid: credential.service_account_uid().to_owned(),
        credential_id: credential.credential_id().to_owned(),
        credential_not_before: credential.not_before(),
        credential_expires_at: credential.expires_at(),
        credential_commitment: credential.commitment(),
        control_submission,
    })
}

fn memory_post_attempt_lineage(
    state: &MemoryState,
    key: &ConsumeKey,
) -> Result<MemoryPostAttemptLineage, StateError> {
    memory_post_attempt_lineage_for_phase(state, key, MemoryPostAttemptPhase::AttemptInFlight)
}

fn validate_memory_admission_claim(
    state: &MemoryState,
    request: &AdmissionAuthorizationRequest,
) -> Result<(), StateError> {
    let lineage = memory_post_attempt_lineage(state, request.key())?;
    if lineage.token.claim_id() != request.claim_id()
        || lineage.token.fence() != request.fence()
        || lineage.token.physical_resource() != request.physical_resource()
    {
        return Err(StateError::AdmissionClaimMismatch);
    }
    if lineage.credential_token_digest != request.credential_token_digest()
        || lineage.service_account_uid != request.service_account_uid()
        || lineage.credential_id != request.credential_id()
        || lineage.credential_commitment != request.credential_binding_commitment()
    {
        return Err(StateError::AdmissionCredentialMismatch);
    }
    Ok(())
}

impl crate::sealed::Sealed for InMemoryStore {}

fn memory_destination_for_authority(
    state: &MemoryState,
    scope: &Scope,
    authority: &AuthorityVector,
) -> Result<RootedEksDestination, EksRegistryError> {
    let key = ActivationKey {
        scope: scope.clone(),
        resource_activation_id: authority.resource.activation_id,
        mediation_activation_id: authority.mediation.activation_id,
    };
    let destination = state
        .eks_destinations
        .get(&key)
        .cloned()
        .ok_or(EksRegistryError::NotFound)?;
    destination.validate(scope)?;
    if !destination.matches_authority(authority) {
        return Err(EksRegistryError::AuthorityRootMismatch);
    }
    let owner = destination.physical_owner(scope);
    if !state
        .eks_physical_owners
        .get(&owner.physical_key)
        .is_some_and(|existing| existing.same_immutable_ownership(&owner))
        || !state
            .eks_route_owners
            .get(&owner.route_key)
            .is_some_and(|existing| existing.same_immutable_ownership(&owner))
    {
        return Err(EksRegistryError::PhysicalAliasConflict);
    }
    Ok(destination)
}

fn memory_frozen_destination_for_authority(
    state: &MemoryState,
    scope: &Scope,
    authority: &AuthorityVector,
) -> Result<RootedEksDestination, EksRegistryError> {
    let key = ActivationKey {
        scope: scope.clone(),
        resource_activation_id: authority.resource.activation_id,
        mediation_activation_id: authority.mediation.activation_id,
    };
    let destination = state
        .eks_destinations
        .get(&key)
        .cloned()
        .ok_or(EksRegistryError::NotFound)?;
    destination.validate(scope)?;
    if !destination.matches_authority(authority) {
        return Err(EksRegistryError::AuthorityRootMismatch);
    }
    Ok(destination)
}

fn memory_frozen_destination_for_review(
    state: &MemoryState,
    scope: &Scope,
    authority: &AuthorityVector,
    activation_commitment: Digest32,
) -> Result<RootedEksDestination, EksRegistryError> {
    let destination = memory_frozen_destination_for_authority(state, scope, authority)?;
    if destination.activation_commitment != activation_commitment {
        return Err(EksRegistryError::AuthorityRootMismatch);
    }
    Ok(destination)
}

fn memory_claim_for_attempt<'a>(
    state: &'a MemoryState,
    key: &ConsumeKey,
    physical: &PhysicalResourceKey,
) -> Result<&'a MemoryDispatchClaim, EksRegistryError> {
    let claim = state
        .dispatch_claims
        .get(&(key.scope.clone(), key.authorization_id))
        .ok_or(EksRegistryError::FrozenLineageUnavailable)?;
    if claim.token.key() != key
        || claim.token.physical_resource() != physical
        || state.physical_reservations.get(physical)
            != Some(&(key.scope.clone(), key.authorization_id))
    {
        return Err(EksRegistryError::FrozenLineageUnavailable);
    }
    Ok(claim)
}

fn memory_frozen_lineage(
    state: &MemoryState,
    key: &ConsumeKey,
    claim: &MemoryDispatchClaim,
    destination: &RootedEksDestination,
) -> Result<(), EksRegistryError> {
    let Some(create) = state.broker_operations.get(&(
        key.scope.clone(),
        key.authorization_id,
        BrokerJournalOperation::CreateSecret,
    )) else {
        return Err(EksRegistryError::FrozenLineageUnavailable);
    };
    create.validate()?;
    let route = Digest32::from_bytes(*destination.profile.route().commitment().as_bytes());
    if create.key != *key
        || create.claim_id != claim.token.claim_id()
        || create.fence != claim.token.fence()
        || create.state_instance_id != claim.token.state_instance_id()
        || create.physical_resource != *claim.token.physical_resource()
        || create.route_commitment != route
    {
        return Err(EksRegistryError::FrozenLineageUnavailable);
    }
    if create.phase == BrokerJournalPhase::ReconcileOnly {
        return Ok(());
    }
    if create.phase != BrokerJournalPhase::Committed
        || create.outcome != Some(BrokerJournalOutcome::CreateMatching)
        || create.bound_secret_uid.is_none()
    {
        return Err(EksRegistryError::FrozenLineageUnavailable);
    }
    let delete = state
        .broker_operations
        .get(&(
            key.scope.clone(),
            key.authorization_id,
            BrokerJournalOperation::DeleteSecret,
        ))
        .ok_or(EksRegistryError::FrozenLineageUnavailable)?;
    delete.validate()?;
    if delete.key != *key
        || delete.claim_id != create.claim_id
        || delete.fence != create.fence
        || delete.state_instance_id != create.state_instance_id
        || delete.physical_resource != create.physical_resource
        || delete.route_commitment != create.route_commitment
        || delete.bound_secret_name != create.bound_secret_name
        || delete.bound_secret_uid != create.bound_secret_uid
        || !matches!(
            delete.phase,
            BrokerJournalPhase::InFlight
                | BrokerJournalPhase::Unknown
                | BrokerJournalPhase::ReconcileOnly
                | BrokerJournalPhase::Committed
                | BrokerJournalPhase::Terminal
        )
    {
        return Err(EksRegistryError::FrozenLineageUnavailable);
    }
    Ok(())
}

impl EksDestinationRegistryState for InMemoryStore {
    fn activate_eks_destination(
        &self,
        scope: &Scope,
        profile: &EksDestinationProfile,
    ) -> Result<(), EksRegistryError> {
        scope.validate()?;
        let mut state = self.inner.lock();
        let active = state
            .authorities
            .get(scope)
            .cloned()
            .ok_or(StateError::AuthorityNotInitialized)?;
        let destination = RootedEksDestination::activate(scope, profile, &active)?;
        let owner = destination.physical_owner(scope);

        if state
            .eks_physical_owners
            .get(&owner.physical_key)
            .is_some_and(|existing| !existing.same_immutable_ownership(&owner))
            || state
                .eks_route_owners
                .get(&owner.route_key)
                .is_some_and(|existing| !existing.same_immutable_ownership(&owner))
        {
            return Err(EksRegistryError::PhysicalAliasConflict);
        }
        let activation_key = destination.activation_key(scope);
        if state
            .eks_destinations
            .get(&activation_key)
            .is_some_and(|existing| existing != &destination)
        {
            return Err(EksRegistryError::ActivationConflict);
        }

        state
            .eks_physical_owners
            .entry(owner.physical_key.clone())
            .or_insert_with(|| owner.clone());
        state
            .eks_route_owners
            .entry(owner.route_key.clone())
            .or_insert(owner);
        state
            .eks_destinations
            .entry(activation_key)
            .or_insert(destination);
        Ok(())
    }

    fn load_current_eks_attempt(
        &self,
        scope: &Scope,
        transaction_id: Uuid,
    ) -> Result<CurrentEksAttempt, EksRegistryError> {
        scope.validate()?;
        if transaction_id.is_nil() {
            return Err(EksRegistryError::NotFound);
        }
        let mut state = self.inner.lock();
        let authorization_id = state
            .transactions
            .get(&(scope.clone(), transaction_id))
            .copied()
            .ok_or(EksRegistryError::NotFound)?;
        let key = ConsumeKey {
            scope: scope.clone(),
            transaction_id,
            authorization_id,
        };
        let authorization_key = (scope.clone(), authorization_id);
        let preflight_issued = state
            .authorizations
            .get(&authorization_key)
            .ok_or(StateError::AuthorizationNotFound)?;
        preflight_issued.validate()?;
        if preflight_issued.transaction_id != transaction_id {
            return Err(EksRegistryError::FrozenLineageUnavailable);
        }
        let preflight_physical =
            PhysicalResourceKey::from_authorization(preflight_issued.authorization())?;
        let preflight_claim = memory_claim_for_attempt(&state, &key, &preflight_physical)?;
        require_memory_bootstrap_acquisition(&state, &preflight_claim.token)?;
        let observed_at = self.clock.now_unix_seconds()?;
        let snapshot = memory_dispatch_snapshot_with_high_water(&mut state, &key, observed_at)?;
        let physical = PhysicalResourceKey::from_authorization(snapshot.issued().authorization())?;
        if physical != preflight_physical {
            return Err(EksRegistryError::FrozenLineageUnavailable);
        }
        let claim = memory_claim_for_attempt(&state, &key, &physical)?;
        if observed_at >= claim.token.lease_until() {
            return Err(EksRegistryError::State(
                StateError::DispatchClaimLeaseExpired {
                    observed: observed_at,
                    lease_until: claim.token.lease_until(),
                },
            ));
        }
        let destination = memory_destination_for_authority(&state, scope, snapshot.authority())?;
        let facts = derive_attempt_facts(
            scope,
            transaction_id,
            authorization_id,
            snapshot.issued().authorization().template_hash,
            &snapshot.issued().authorization().template,
            &destination,
        )?;
        if facts.physical_resource() != claim.token.physical_resource() {
            return Err(EksRegistryError::FrozenLineageUnavailable);
        }
        Ok(CurrentEksAttempt::new(
            facts,
            snapshot.checked_at(),
            snapshot.receipt().dispatch_deadline,
        ))
    }

    fn load_current_eks_attempt_for_acquisition(
        &self,
        authority: &DispatchAcquisitionAuthority,
    ) -> Result<CurrentEksAttempt, EksRegistryError> {
        authority.claim().key().validate()?;
        let mut state = self.inner.lock();
        require_memory_control_acquisition(self.state_instance_id, &state, authority)?;
        let observed_at = self.clock.now_unix_seconds()?;
        let (snapshot, _) = memory_revalidate_control_acquisition_locked(
            self.state_instance_id,
            &mut state,
            authority,
            observed_at,
        )?;
        let key = authority.claim().key();
        let destination =
            memory_destination_for_authority(&state, &key.scope, snapshot.authority())?;
        let facts = derive_attempt_facts(
            &key.scope,
            key.transaction_id,
            key.authorization_id,
            snapshot.issued().authorization().template_hash,
            &snapshot.issued().authorization().template,
            &destination,
        )?;
        if facts.physical_resource() != authority.claim().physical_resource() {
            return Err(EksRegistryError::FrozenLineageUnavailable);
        }
        Ok(CurrentEksAttempt::new(
            facts,
            snapshot.checked_at(),
            snapshot.receipt().dispatch_deadline,
        ))
    }

    fn load_frozen_eks_attempt(
        &self,
        scope: &Scope,
        transaction_id: Uuid,
    ) -> Result<FrozenEksAttempt, EksRegistryError> {
        scope.validate()?;
        if transaction_id.is_nil() {
            return Err(EksRegistryError::NotFound);
        }
        let state = self.inner.lock();
        let authorization_id = state
            .transactions
            .get(&(scope.clone(), transaction_id))
            .copied()
            .ok_or(EksRegistryError::NotFound)?;
        let key = ConsumeKey {
            scope: scope.clone(),
            transaction_id,
            authorization_id,
        };
        let authorization_key = (scope.clone(), authorization_id);
        let issued = state
            .authorizations
            .get(&authorization_key)
            .cloned()
            .ok_or(StateError::AuthorizationNotFound)?;
        let receipt = state
            .receipts
            .get(&authorization_key)
            .cloned()
            .ok_or(StateError::ConsumptionNotFound)?;
        let outbox = state
            .outbox
            .get(&authorization_key)
            .cloned()
            .ok_or(StateError::ConsumptionNotFound)?;
        validate_recovered_consumption(&key, &issued, &receipt, &outbox)?;
        let physical = PhysicalResourceKey::from_authorization(issued.authorization())?;
        let claim = memory_claim_for_attempt(&state, &key, &physical)?;
        require_memory_bootstrap_acquisition(&state, &claim.token)?;
        let destination = memory_frozen_destination_for_authority(
            &state,
            scope,
            &issued.authorization().authority,
        )?;
        memory_frozen_lineage(&state, &key, claim, &destination)?;
        let facts = derive_attempt_facts(
            scope,
            transaction_id,
            authorization_id,
            issued.authorization().template_hash,
            &issued.authorization().template,
            &destination,
        )?;
        Ok(FrozenEksAttempt::new(facts))
    }

    #[allow(clippy::too_many_lines)]
    fn load_frozen_eks_attempt_for_journal(
        &self,
        selector: &BrokerJournalSelector,
    ) -> Result<FrozenEksAttempt, EksRegistryError> {
        selector.key().validate()?;
        if selector.entry_id().is_nil()
            || selector.origin_acquisition_id().is_nil()
            || selector.origin_lease_fence() == 0
            || selector.operation() == BrokerJournalOperation::IssueToken
        {
            return Err(EksRegistryError::FrozenLineageUnavailable);
        }
        let state = self.inner.lock();
        let operation = state
            .broker_operations
            .get(&broker_memory_key(selector.key(), selector.operation()))
            .ok_or(EksRegistryError::FrozenLineageUnavailable)?;
        operation.validate()?;
        if operation.entry_id != selector.entry_id()
            || operation.request_commitment != selector.request_commitment()
            || operation.origin_acquisition_id != selector.origin_acquisition_id()
            || operation.origin_lease_fence != selector.origin_lease_fence()
            || operation.operation != selector.operation()
            || !matches!(
                operation.phase,
                BrokerJournalPhase::InFlight
                    | BrokerJournalPhase::Unknown
                    | BrokerJournalPhase::ReconcileOnly
                    | BrokerJournalPhase::Committed
                    | BrokerJournalPhase::Terminal
            )
        {
            return Err(EksRegistryError::FrozenLineageUnavailable);
        }
        let acquisition = state
            .dispatch_acquisitions
            .get(&operation.origin_acquisition_id)
            .ok_or(EksRegistryError::FrozenLineageUnavailable)?;
        if acquisition.acquisition_id != operation.origin_acquisition_id
            || acquisition.lease_fence != operation.origin_lease_fence
            || acquisition.token.claim_id() != operation.claim_id
            || acquisition.token.fence() != operation.fence
            || acquisition.token.state_instance_id() != operation.state_instance_id
            || acquisition.token.key() != selector.key()
            || acquisition.token.physical_resource() != &operation.physical_resource
            || (operation.acquisition_binding_version == 1
                && (acquisition.selection_kind
                    != MemoryDispatchAcquisitionKind::ControlBootstrapV13
                    && acquisition.selection_kind
                        != MemoryDispatchAcquisitionKind::LegacyBootstrap))
            || (operation.acquisition_binding_version == 2
                && acquisition.selection_kind == MemoryDispatchAcquisitionKind::ControlBootstrapV13
                && operation.operation != BrokerJournalOperation::DeleteSecret)
        {
            return Err(EksRegistryError::FrozenLineageUnavailable);
        }
        let authorization_key = (
            selector.key().scope.clone(),
            selector.key().authorization_id,
        );
        let issued = state
            .authorizations
            .get(&authorization_key)
            .cloned()
            .ok_or(StateError::AuthorizationNotFound)?;
        let receipt = state
            .receipts
            .get(&authorization_key)
            .cloned()
            .ok_or(StateError::ConsumptionNotFound)?;
        let outbox = state
            .outbox
            .get(&authorization_key)
            .cloned()
            .ok_or(StateError::ConsumptionNotFound)?;
        validate_recovered_consumption(selector.key(), &issued, &receipt, &outbox)?;
        let physical = PhysicalResourceKey::from_authorization(issued.authorization())?;
        let claim = memory_claim_for_attempt(&state, selector.key(), &physical)?;
        if claim.token != acquisition.token {
            return Err(EksRegistryError::FrozenLineageUnavailable);
        }
        if let Some(attempt) = &claim.attempt_acquisition {
            if attempt.acquisition_id() != acquisition.acquisition_id
                || attempt.lease_fence() != acquisition.lease_fence
                || attempt.worker_id() != acquisition.worker_id
                || attempt.acquired_at() != acquisition.acquired_at
                || attempt.lease_until() != acquisition.lease_until
                || attempt.dispatch_deadline() != acquisition.dispatch_deadline
                || attempt.control_submission_id() != acquisition.control_submission_id
            {
                return Err(EksRegistryError::FrozenLineageUnavailable);
            }
            let required_phase = match claim.state {
                MemoryDispatchClaimState::AttemptInFlight => {
                    MemoryPostAttemptPhase::AttemptInFlight
                }
                MemoryDispatchClaimState::Terminal => MemoryPostAttemptPhase::Terminal,
                _ => return Err(EksRegistryError::FrozenLineageUnavailable),
            };
            memory_post_attempt_lineage_for_phase(&state, selector.key(), required_phase)
                .map_err(|_| EksRegistryError::FrozenLineageUnavailable)?;
        }
        if selector.operation() == BrokerJournalOperation::DeleteSecret {
            let create = state
                .broker_operations
                .get(&broker_memory_key(
                    selector.key(),
                    BrokerJournalOperation::CreateSecret,
                ))
                .ok_or(EksRegistryError::FrozenLineageUnavailable)?;
            create.validate()?;
            if create.phase != BrokerJournalPhase::Committed
                || create.outcome != Some(BrokerJournalOutcome::CreateMatching)
                || create.origin_acquisition_id != operation.origin_acquisition_id
                || create.origin_lease_fence != operation.origin_lease_fence
                || create.route_commitment != operation.route_commitment
                || create.bound_secret_uid != operation.bound_secret_uid
            {
                return Err(EksRegistryError::FrozenLineageUnavailable);
            }
        }
        let destination = memory_frozen_destination_for_authority(
            &state,
            &selector.key().scope,
            &issued.authorization().authority,
        )?;
        let facts = derive_attempt_facts(
            &selector.key().scope,
            selector.key().transaction_id,
            selector.key().authorization_id,
            issued.authorization().template_hash,
            &issued.authorization().template,
            &destination,
        )?;
        if facts.physical_resource() != &operation.physical_resource
            || Digest32::from_bytes(*facts.route().commitment().as_bytes())
                != operation.route_commitment
        {
            return Err(EksRegistryError::FrozenLineageUnavailable);
        }
        Ok(FrozenEksAttempt::new(facts))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MemoryTerminalClaimPhase {
    AttemptInFlight,
    Terminal,
}

#[allow(clippy::too_many_lines)]
fn memory_terminal_context(
    state: &MemoryState,
    key: &ConsumeKey,
    required_phase: MemoryTerminalClaimPhase,
) -> Result<
    (
        TerminalRetirementContext,
        DispatchClaimToken,
        ActivatedWitnessRegistry,
    ),
    StateError,
> {
    key.validate()?;
    let authorization_key = (key.scope.clone(), key.authorization_id);
    let issued = state
        .authorizations
        .get(&authorization_key)
        .ok_or(StateError::TerminalRetirementLineageUnavailable)?;
    let receipt = state
        .receipts
        .get(&authorization_key)
        .ok_or(StateError::TerminalRetirementLineageUnavailable)?;
    let outbox = state
        .outbox
        .get(&authorization_key)
        .ok_or(StateError::TerminalRetirementLineageUnavailable)?;
    validate_recovered_consumption(key, issued, receipt, outbox)?;
    let physical = PhysicalResourceKey::from_authorization(issued.authorization())?;
    let claim = state
        .dispatch_claims
        .get(&authorization_key)
        .ok_or(StateError::DispatchClaimNotFound)?;
    if claim.token.key() != key || claim.token.physical_resource() != &physical {
        return Err(StateError::TerminalRetirementLineageUnavailable);
    }
    let owns_active_reservation = state.physical_reservations.get(&physical)
        == Some(&(key.scope.clone(), key.authorization_id));
    match required_phase {
        MemoryTerminalClaimPhase::AttemptInFlight
            if claim.state != MemoryDispatchClaimState::AttemptInFlight
                || !owns_active_reservation
                || claim.terminalization_id.is_some() =>
        {
            return Err(StateError::TerminalRetirementLineageUnavailable);
        }
        MemoryTerminalClaimPhase::Terminal
            if claim.state != MemoryDispatchClaimState::Terminal
                || owns_active_reservation
                || claim.terminalization_id.is_none() =>
        {
            return Err(StateError::TerminalRetirementLineageUnavailable);
        }
        _ => {}
    }
    let post_attempt_phase = match required_phase {
        MemoryTerminalClaimPhase::AttemptInFlight => MemoryPostAttemptPhase::AttemptInFlight,
        MemoryTerminalClaimPhase::Terminal => MemoryPostAttemptPhase::Terminal,
    };
    let post_attempt = memory_post_attempt_lineage_for_phase(state, key, post_attempt_phase)
        .map_err(|_| StateError::TerminalRetirementLineageUnavailable)?;
    if post_attempt.token != claim.token {
        return Err(StateError::TerminalRetirementLineageUnavailable);
    }
    let attempt_started_at = claim
        .attempt_started_at
        .ok_or(StateError::TerminalRetirementLineageUnavailable)?;
    let credential = claim
        .credential
        .as_ref()
        .ok_or(StateError::TerminalRetirementLineageUnavailable)?;

    let activation = ActivationKey {
        scope: key.scope.clone(),
        resource_activation_id: issued.authorization().authority.resource.activation_id,
        mediation_activation_id: issued.authorization().authority.mediation.activation_id,
    };
    let destination = memory_frozen_destination_for_authority(
        state,
        &key.scope,
        &issued.authorization().authority,
    )
    .map_err(|_| StateError::TerminalRetirementLineageUnavailable)?;
    let facts = derive_attempt_facts(
        &key.scope,
        key.transaction_id,
        key.authorization_id,
        issued.authorization().template_hash,
        &issued.authorization().template,
        &destination,
    )
    .map_err(|_| StateError::TerminalRetirementLineageUnavailable)?;

    let admission_uid = state
        .admission_transactions
        .get(&(key.scope.clone(), key.transaction_id))
        .ok_or(StateError::TerminalRetirementLineageUnavailable)?;
    let admission = &state
        .admission_authorizations
        .get(admission_uid)
        .ok_or(StateError::TerminalRetirementLineageUnavailable)?
        .request;
    let create = state
        .broker_operations
        .get(&broker_memory_key(
            key,
            BrokerJournalOperation::CreateSecret,
        ))
        .ok_or(StateError::TerminalRetirementLineageUnavailable)?;
    let issue = state
        .broker_operations
        .get(&broker_memory_key(key, BrokerJournalOperation::IssueToken))
        .ok_or(StateError::TerminalRetirementLineageUnavailable)?;
    let delete = state
        .broker_operations
        .get(&broker_memory_key(
            key,
            BrokerJournalOperation::DeleteSecret,
        ))
        .ok_or(StateError::TerminalRetirementLineageUnavailable)?;
    let deletion = state
        .secret_deletion_observations
        .get(&authorization_key)
        .ok_or(StateError::TerminalRetirementLineageUnavailable)?;
    let context = derive_terminal_context(TerminalDurableInputs {
        claim: &claim.token,
        attempt_started_at,
        credential,
        activation: &activation,
        facts: &facts,
        admission,
        create,
        issue,
        delete,
        deletion,
    })?;
    let bound_commitment = state
        .terminal_witness_registry_bindings
        .get(&activation)
        .copied()
        .ok_or(StateError::TerminalWitnessRegistryNotFound)?;
    if bound_commitment != context.registry_commitment() {
        return Err(StateError::TerminalWitnessRegistryMismatch);
    }
    let registry = state
        .terminal_witness_registries
        .get(&bound_commitment)
        .cloned()
        .ok_or(StateError::TerminalWitnessRegistryNotFound)?;
    if registry.commitment() != bound_commitment {
        return Err(StateError::TerminalWitnessRegistryMismatch);
    }
    Ok((context, claim.token.clone(), registry))
}

impl TerminalRetirementState for InMemoryStore {
    fn register_terminal_witness_registry_or_recover(
        &self,
        scope: &Scope,
        resource_activation_id: Uuid,
        mediation_activation_id: Uuid,
        registry: &ActivatedWitnessRegistry,
    ) -> Result<TerminalWitnessRegistryReceipt, StateError> {
        scope.validate()?;
        if resource_activation_id.is_nil()
            || mediation_activation_id.is_nil()
            || registry.commitment() == Digest32::from_bytes([0; 32])
        {
            return Err(StateError::TerminalWitnessRegistryMismatch);
        }
        let activation = ActivationKey {
            scope: scope.clone(),
            resource_activation_id,
            mediation_activation_id,
        };
        let mut state = self.inner.lock();
        let destination = state
            .eks_destinations
            .get(&activation)
            .ok_or(StateError::TerminalRetirementLineageUnavailable)?;
        destination
            .validate(scope)
            .map_err(|_| StateError::TerminalRetirementLineageUnavailable)?;
        if destination.profile.terminal_witness_registry_commitment() != registry.commitment()
            || registry.entries().iter().any(|entry| {
                entry.scope().tenant() != scope.tenant
                    || entry.scope().environment() != scope.environment
                    || entry.cluster_identity() != destination.profile.route().cluster_identity()
            })
        {
            return Err(StateError::TerminalWitnessRegistryMismatch);
        }

        if let Some(existing) = state
            .terminal_witness_registries
            .get(&registry.commitment())
            && !same_activated_registry(existing, registry)
        {
            return Err(StateError::TerminalWitnessRegistryMismatch);
        }
        if let Some(existing) = state
            .terminal_witness_registry_bindings
            .get(&activation)
            .copied()
        {
            if existing != registry.commitment()
                || !state
                    .terminal_witness_registries
                    .get(&existing)
                    .is_some_and(|stored| same_activated_registry(stored, registry))
            {
                return Err(StateError::TerminalWitnessRegistryMismatch);
            }
            return Ok(TerminalWitnessRegistryReceipt::new(
                scope.clone(),
                resource_activation_id,
                mediation_activation_id,
                existing,
                true,
            ));
        }

        state
            .terminal_witness_registries
            .entry(registry.commitment())
            .or_insert_with(|| registry.clone());
        state
            .terminal_witness_registry_bindings
            .insert(activation, registry.commitment());
        Ok(TerminalWitnessRegistryReceipt::new(
            scope.clone(),
            resource_activation_id,
            mediation_activation_id,
            registry.commitment(),
            false,
        ))
    }

    fn terminal_retirement_context(
        &self,
        key: &ConsumeKey,
    ) -> Result<TerminalRetirementContext, StateError> {
        let state = self.inner.lock();
        memory_terminal_context(&state, key, MemoryTerminalClaimPhase::AttemptInFlight)
            .map(|(context, _, _)| context)
    }

    #[allow(clippy::too_many_lines)]
    fn finalize_terminal_retirement_or_recover(
        &self,
        request: &TerminalRetirementRequest,
    ) -> Result<TerminalRetirementReceipt, StateError> {
        request.key().validate()?;
        let memory_key = (request.key().scope.clone(), request.key().authorization_id);
        let mut state = self.inner.lock();

        if let Some(stored) = state.terminal_retirements.get(&memory_key).cloned() {
            stored.validate()?;
            if !stored.exact_request(request) {
                return Err(StateError::TerminalRetirementMismatch);
            }
            let (context, claim, registry) =
                memory_terminal_context(&state, request.key(), MemoryTerminalClaimPhase::Terminal)?;
            if !stored.matches_context_and_claim(&context, &claim)?
                || state.terminalization_ids.get(&request.terminalization_id()) != Some(&memory_key)
                || state
                    .terminal_effect_evidence_ids
                    .get(&stored.audit.effect_evidence_id())
                    != Some(&memory_key)
                || state
                    .terminal_retirement_evidence_ids
                    .get(&stored.audit.retirement_evidence_id())
                    != Some(&memory_key)
                || state
                    .terminal_effect_envelope_commitments
                    .get(&stored.audit.effect_envelope_commitment())
                    != Some(&memory_key)
                || state
                    .terminal_retirement_envelope_commitments
                    .get(&stored.audit.retirement_envelope_commitment())
                    != Some(&memory_key)
            {
                return Err(StateError::TerminalRetirementMismatch);
            }
            let evidence = authenticate_terminal_evidence(&context, &registry, request)?;
            validate_terminal_evidence_time(&evidence, stored.audit.finalized_at())?;
            return Ok(TerminalRetirementReceipt::new(stored.audit, true));
        }

        if state
            .terminalization_ids
            .contains_key(&request.terminalization_id())
        {
            return Err(StateError::TerminalRetirementMismatch);
        }
        let (context, claim, registry) = memory_terminal_context(
            &state,
            request.key(),
            MemoryTerminalClaimPhase::AttemptInFlight,
        )?;
        let post_attempt = memory_post_attempt_lineage(&state, request.key())?;
        // Both signatures and their complete durable bindings are checked
        // before trusted time is sampled, so malformed or misrouted evidence
        // cannot advance the high-water mark.
        let evidence = authenticate_terminal_evidence(&context, &registry, request)?;
        if state
            .terminal_effect_evidence_ids
            .contains_key(&evidence.effect.claims().evidence_id())
            || state
                .terminal_retirement_evidence_ids
                .contains_key(&evidence.retirement.claims().evidence_id())
            || state
                .terminal_effect_envelope_commitments
                .contains_key(&Digest32::sha256(request.effect_envelope()))
            || state
                .terminal_retirement_envelope_commitments
                .contains_key(&Digest32::sha256(request.retirement_envelope()))
        {
            return Err(StateError::TerminalRetirementMismatch);
        }

        let trusted_now = self.clock.now_unix_seconds()?;
        memory_advance_cleanup_high_water(
            &mut state,
            request.key(),
            post_attempt.control_submission.as_ref(),
            trusted_now,
        )?;
        validate_terminal_evidence_time(&evidence, trusted_now)?;
        let stored = StoredTerminalRetirement::new(
            request,
            &claim,
            &context,
            &evidence.effect,
            &evidence.retirement,
            trusted_now,
        )?;
        stored.validate()?;

        if state.physical_reservations.get(claim.physical_resource())
            != Some(&(request.key().scope.clone(), request.key().authorization_id))
        {
            return Err(StateError::TerminalRetirementLineageUnavailable);
        }
        let claim_row = state
            .dispatch_claims
            .get_mut(&memory_key)
            .ok_or(StateError::DispatchClaimNotFound)?;
        if claim_row.token != claim
            || claim_row.state != MemoryDispatchClaimState::AttemptInFlight
            || claim_row.terminalization_id.is_some()
        {
            return Err(StateError::TerminalRetirementMismatch);
        }
        claim_row.state = MemoryDispatchClaimState::Terminal;
        claim_row.terminalization_id = Some(request.terminalization_id());
        if state
            .physical_reservations
            .remove(claim.physical_resource())
            != Some((request.key().scope.clone(), request.key().authorization_id))
        {
            return Err(StateError::TerminalRetirementOutcomeUnknown);
        }
        state
            .terminalization_ids
            .insert(request.terminalization_id(), memory_key.clone());
        state
            .terminal_effect_evidence_ids
            .insert(stored.audit.effect_evidence_id(), memory_key.clone());
        state
            .terminal_retirement_evidence_ids
            .insert(stored.audit.retirement_evidence_id(), memory_key.clone());
        state.terminal_effect_envelope_commitments.insert(
            stored.audit.effect_envelope_commitment(),
            memory_key.clone(),
        );
        state.terminal_retirement_envelope_commitments.insert(
            stored.audit.retirement_envelope_commitment(),
            memory_key.clone(),
        );
        let audit = stored.audit.clone();
        state.terminal_retirements.insert(memory_key, stored);
        Ok(TerminalRetirementReceipt::new(audit, false))
    }

    fn terminal_retirement_audit(
        &self,
        key: &ConsumeKey,
    ) -> Result<TerminalRetirementAudit, StateError> {
        key.validate()?;
        let state = self.inner.lock();
        let stored = state
            .terminal_retirements
            .get(&(key.scope.clone(), key.authorization_id))
            .cloned()
            .ok_or(StateError::TerminalRetirementLineageUnavailable)?;
        stored.validate()?;
        let memory_key = (key.scope.clone(), key.authorization_id);
        let (context, claim, registry) =
            memory_terminal_context(&state, key, MemoryTerminalClaimPhase::Terminal)?;
        if !stored.matches_context_and_claim(&context, &claim)?
            || state
                .terminalization_ids
                .get(&stored.audit.terminalization_id())
                != Some(&memory_key)
            || state
                .terminal_effect_evidence_ids
                .get(&stored.audit.effect_evidence_id())
                != Some(&memory_key)
            || state
                .terminal_retirement_evidence_ids
                .get(&stored.audit.retirement_evidence_id())
                != Some(&memory_key)
            || state
                .terminal_effect_envelope_commitments
                .get(&stored.audit.effect_envelope_commitment())
                != Some(&memory_key)
            || state
                .terminal_retirement_envelope_commitments
                .get(&stored.audit.retirement_envelope_commitment())
                != Some(&memory_key)
        {
            return Err(StateError::TerminalRetirementMismatch);
        }
        let request = TerminalRetirementRequest::new(
            key.clone(),
            stored.audit.terminalization_id(),
            stored.effect_envelope.clone(),
            stored.retirement_envelope.clone(),
        )?;
        let evidence = authenticate_terminal_evidence(&context, &registry, &request)?;
        validate_terminal_evidence_time(&evidence, stored.audit.finalized_at())?;
        Ok(stored.audit.clone())
    }
}

impl IngressReplayState for InMemoryStore {
    fn observe_ingress_time(
        &self,
        scope: &IngressReplayScope,
        observed_unix_s: i64,
    ) -> Result<(), StateError> {
        validate_observed_time(observed_unix_s)?;
        let mut state = self.inner.lock();
        let high_water = state
            .ingress_replay_high_water
            .entry(scope.clone())
            .or_insert(0);
        if observed_unix_s < *high_water {
            return Err(StateError::ClockRollback {
                observed: observed_unix_s,
                high_water: *high_water,
            });
        }
        *high_water = observed_unix_s;
        Ok(())
    }

    fn consume_ingress_nonce(
        &self,
        request: &IngressNonceConsumption,
    ) -> Result<IngressReplayDecision, StateError> {
        validate_observed_time(request.observed_unix_s())?;
        let mut state = self.inner.lock();
        let prior_high_water = state
            .ingress_replay_high_water
            .get(request.scope())
            .copied()
            .unwrap_or(0);
        if request.observed_unix_s() < prior_high_water {
            return Err(StateError::ClockRollback {
                observed: request.observed_unix_s(),
                high_water: prior_high_water,
            });
        }
        let replay_key = (
            request.scope().clone(),
            request.key_id().to_owned(),
            request.nonce(),
        );
        state
            .ingress_replay_high_water
            .insert(request.scope().clone(), request.observed_unix_s());
        if state.ingress_replay_v13_nonces.contains(&replay_key) {
            return Ok(IngressReplayDecision::AlreadyUsed);
        }
        if state
            .ingress_replay_nonces
            .get(&replay_key)
            .is_some_and(|expires_unix_s| *expires_unix_s > request.observed_unix_s())
        {
            return Ok(IngressReplayDecision::AlreadyUsed);
        }
        state
            .ingress_replay_nonces
            .insert(replay_key, request.expires_unix_s());
        Ok(IngressReplayDecision::Consumed)
    }

    fn prune_expired_ingress_nonces(
        &self,
        scope: &IngressReplayScope,
        limit: u32,
    ) -> Result<u32, StateError> {
        if !valid_gc_limit(limit) {
            return Err(StateError::InvalidRecord(
                "ingress replay GC batch is outside the bounded profile".to_owned(),
            ));
        }
        let mut state = self.inner.lock();
        let high_water = state
            .ingress_replay_high_water
            .get(scope)
            .copied()
            .ok_or_else(|| {
                StateError::InvalidRecord("ingress replay scope is not initialized".to_owned())
            })?;
        let mut expired = state
            .ingress_replay_nonces
            .iter()
            .filter_map(|((candidate_scope, key_id, nonce), expires_unix_s)| {
                let replay_key = (candidate_scope.clone(), key_id.clone(), *nonce);
                (candidate_scope == scope
                    && *expires_unix_s <= high_water
                    && !state.ingress_replay_v13_nonces.contains(&replay_key))
                .then_some((*expires_unix_s, key_id.clone(), *nonce))
            })
            .collect::<Vec<_>>();
        expired.sort_unstable();
        let limit = usize::try_from(limit).map_err(|_| {
            StateError::InvalidRecord("ingress replay GC batch cannot be represented".to_owned())
        })?;
        let selected = expired.into_iter().take(limit).collect::<Vec<_>>();
        for (_, key_id, nonce) in &selected {
            state
                .ingress_replay_nonces
                .remove(&(scope.clone(), key_id.clone(), *nonce));
        }
        u32::try_from(selected.len()).map_err(|_| {
            StateError::InvalidRecord("ingress replay GC result cannot be represented".to_owned())
        })
    }
}

fn memory_control_recovered(
    state: &MemoryState,
    stored: &StoredControlSubmission,
) -> Result<RecoveredSubmissionRef, StateError> {
    let status = memory_validate_control_recovery_projection(state, stored)?;
    Ok(RecoveredSubmissionRef::new(
        stored.receipt(),
        status.status(),
        status.revision(),
    ))
}

fn memory_control_lease(state_instance_id: Uuid, claim: &MemoryControlClaim) -> ControlWorkLease {
    ControlWorkLease {
        state_instance_id,
        submission_id: claim.submission_id,
        phase: claim.phase,
        worker_id: claim.worker_id.clone(),
        claim_id: claim.claim_id,
        fence: claim.fence,
        claimed_at: claim.claimed_at,
        lease_until: claim.lease_until,
    }
}

fn invalid_control_lineage(message: impl Into<String>) -> StateError {
    StateError::InvalidRecord(message.into())
}

/// Validates the complete append-only public event projection without sampling
/// time or consulting current authority. Completed-work recovery must remain
/// inert, but it may only return history whose current projection and both
/// commitment indexes still agree exactly.
fn memory_validate_control_event_chain(
    state: &MemoryState,
    stored: &StoredControlSubmission,
) -> Result<ControlStatusSnapshot, StateError> {
    let current = state
        .control_statuses
        .get(&stored.submission_id)
        .ok_or_else(|| invalid_control_lineage("control status projection is missing"))?;
    let events = state
        .control_events
        .get(&stored.submission_id)
        .ok_or_else(|| invalid_control_lineage("control event history is missing"))?;
    let revision = usize::try_from(current.revision()).map_err(|_| {
        invalid_control_lineage("control status revision cannot index its event history")
    })?;
    if revision == 0
        || events.len() != revision
        || events.last() != Some(current)
        || current.submission_id() != stored.submission_id
        || current.receipt_id() != stored.receipt_id
    {
        return Err(invalid_control_lineage(
            "control status projection does not equal the last gapless event",
        ));
    }

    let indexed_events = state
        .control_event_commitments
        .keys()
        .filter(|(submission_id, _)| *submission_id == stored.submission_id)
        .count();
    let reverse_indexed_events = state
        .control_by_event_commitment
        .values()
        .filter(|(submission_id, _)| *submission_id == stored.submission_id)
        .count();
    if indexed_events != events.len() || reverse_indexed_events != events.len() {
        return Err(invalid_control_lineage(
            "control event commitment index has missing or surplus revisions",
        ));
    }

    let mut prior_observed_at = None;
    for (offset, event) in events.iter().enumerate() {
        let expected_revision = u64::try_from(offset + 1)
            .map_err(|_| invalid_control_lineage("control event revision cannot be represented"))?;
        if event.submission_id() != stored.submission_id
            || event.receipt_id() != stored.receipt_id
            || event.revision() != expected_revision
            || prior_observed_at.is_some_and(|prior| event.observed_at() < prior)
        {
            return Err(invalid_control_lineage(
                "control event history is not identity-bound, gapless, and monotone",
            ));
        }
        if expected_revision == 1
            && (event.status() != ControlStatusCode::Accepted
                || event.reason().is_some()
                || event.observed_at() != stored.accepted_at)
        {
            return Err(invalid_control_lineage(
                "control ACCEPTED event does not match immutable intake",
            ));
        }
        prior_observed_at = Some(event.observed_at());
        let commitment = control_event_commitment(event)?;
        let tuple = (stored.submission_id, expected_revision);
        if state.control_event_commitments.get(&tuple) != Some(&commitment)
            || state.control_by_event_commitment.get(&commitment) != Some(&tuple)
            || state
                .control_by_event_commitment
                .values()
                .filter(|candidate| **candidate == tuple)
                .count()
                != 1
        {
            return Err(invalid_control_lineage(
                "control event commitment lineage is incomplete or ambiguous",
            ));
        }
    }
    Ok(current.clone())
}

fn memory_require_control_event(
    state: &MemoryState,
    stored: &StoredControlSubmission,
    revision: u64,
    status: ControlStatusCode,
    reason: Option<ControlStatusReason>,
    observed_at: i64,
) -> Result<ControlStatusSnapshot, StateError> {
    let current = memory_validate_control_event_chain(state, stored)?;
    let offset = revision
        .checked_sub(1)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| invalid_control_lineage("control event revision is invalid"))?;
    let event = state
        .control_events
        .get(&stored.submission_id)
        .and_then(|events| events.get(offset))
        .ok_or_else(|| invalid_control_lineage("required control event is missing"))?;
    if event.status() != status
        || event.reason() != reason
        || event.observed_at() != observed_at
        || event.revision() != revision
    {
        return Err(invalid_control_lineage(
            "required control event does not match its exact artifact and time",
        ));
    }
    Ok(current)
}

fn memory_validate_control_submission_lineage(
    state: &MemoryState,
    stored: &StoredControlSubmission,
) -> Result<(), StateError> {
    stored.validate()?;
    stored.reverify_frozen_wire()?;
    let scope = stored.scope();
    let replay_scope = IngressReplayScope::new(&stored.replay_scope)?;
    let replay_key = (replay_scope, stored.key_id.clone(), stored.nonce);
    if state.control_submissions.get(&stored.submission_id) != Some(stored)
        || state
            .control_by_payload_commitment
            .get(&stored.canonical_payload_commitment)
            != Some(&stored.submission_id)
        || state
            .control_by_request
            .get(&(scope.clone(), stored.proposal.request_id))
            != Some(&stored.submission_id)
        || state.control_by_receipt.get(&(scope, stored.receipt_id)) != Some(&stored.submission_id)
        || state.control_by_receipt_id.get(&stored.receipt_id) != Some(&stored.submission_id)
        || state
            .control_by_evaluation_nonce
            .get(&stored.evaluation_nonce)
            != Some(&stored.submission_id)
        || state.ingress_replay_nonces.get(&replay_key) != Some(&stored.ingress_expires_at)
        || !state.ingress_replay_v13_nonces.contains(&replay_key)
    {
        return Err(invalid_control_lineage(
            "control submission and permanent intake indexes do not agree",
        ));
    }
    for owner_count in [
        state
            .control_by_payload_commitment
            .values()
            .filter(|submission_id| **submission_id == stored.submission_id)
            .count(),
        state
            .control_by_request
            .values()
            .filter(|submission_id| **submission_id == stored.submission_id)
            .count(),
        state
            .control_by_receipt
            .values()
            .filter(|submission_id| **submission_id == stored.submission_id)
            .count(),
        state
            .control_by_receipt_id
            .values()
            .filter(|submission_id| **submission_id == stored.submission_id)
            .count(),
        state
            .control_by_evaluation_nonce
            .values()
            .filter(|submission_id| **submission_id == stored.submission_id)
            .count(),
    ] {
        if owner_count != 1 {
            return Err(invalid_control_lineage(
                "control submission has missing or ambiguous ownership indexes",
            ));
        }
    }
    Ok(())
}

fn memory_validate_completed_control_claim_shape(
    state: &MemoryState,
    stored: &StoredControlSubmission,
    claim: &MemoryControlClaim,
) -> Result<(), StateError> {
    let indexed = state
        .control_claims
        .get(&claim.claim_id)
        .ok_or_else(|| invalid_control_lineage("completed control claim is not indexed"))?;
    let expected_lease_until = claim
        .claimed_at
        .checked_add(CONTROL_WORK_LEASE_SECONDS)
        .ok_or_else(|| invalid_control_lineage("completed control claim lease overflowed"))?;
    let completed_at = claim
        .completed_at
        .ok_or_else(|| invalid_control_lineage("completed control claim time is missing"))?;
    if claim.submission_id != stored.submission_id
        || claim.phase == ControlWorkPhase::Done
        || claim.role.phase() != claim.phase
        || ControlWorkClaimRequest::new(claim.worker_id.clone(), claim.role, claim.claim_id)
            .is_err()
        || claim.fence == 0
        || claim.claimed_at < stored.accepted_at
        || claim.lease_until != expected_lease_until
        || completed_at < claim.claimed_at
        || completed_at >= claim.lease_until
        || !claim.completed
        || indexed.submission_id != claim.submission_id
        || indexed.phase != claim.phase
        || indexed.worker_id != claim.worker_id
        || indexed.role != claim.role
        || indexed.fence != claim.fence
        || indexed.claimed_at != claim.claimed_at
        || indexed.lease_until != claim.lease_until
        || indexed.completed != claim.completed
        || indexed.completed_at != claim.completed_at
        || indexed.finalized_decision != claim.finalized_decision
        || indexed.finalized_work != claim.finalized_work
        || state
            .control_claims
            .values()
            .filter(|candidate| candidate.fence == claim.fence)
            .count()
            != 1
    {
        return Err(invalid_control_lineage(
            "completed control claim identity, lease, fence, or completion is invalid",
        ));
    }
    Ok(())
}

fn memory_unique_successful_control_claim(
    state: &MemoryState,
    submission_id: Uuid,
    phase: ControlWorkPhase,
) -> Result<MemoryControlClaim, StateError> {
    let mut matching = state.control_claims.values().filter(|claim| {
        claim.submission_id == submission_id
            && claim.phase == phase
            && claim.completed
            && claim.finalized_decision.is_none()
            && claim.finalized_work.is_none()
    });
    let claim = matching
        .next()
        .cloned()
        .ok_or_else(|| invalid_control_lineage("successful control phase claim is missing"))?;
    let stored = state
        .control_submissions
        .get(&submission_id)
        .ok_or_else(|| invalid_control_lineage("successful control phase submission is missing"))?;
    if matching.next().is_some() {
        return Err(invalid_control_lineage(
            "successful control phase claim is malformed or ambiguous",
        ));
    }
    memory_validate_completed_control_claim_shape(state, stored, &claim)?;
    Ok(claim)
}

/// Recomputes the immutable decision and optional signed-evaluation lineage
/// from the exact EVALUATE claim. This deliberately uses frozen evaluator
/// material from the record rather than current registries.
#[allow(clippy::too_many_lines)]
fn memory_validate_control_decision_lineage(
    state: &MemoryState,
    stored: &StoredControlSubmission,
    evaluation_claim: &MemoryControlClaim,
) -> Result<StoredControlDecision, StateError> {
    memory_validate_control_submission_lineage(state, stored)?;
    memory_validate_completed_control_claim_shape(state, stored, evaluation_claim)?;
    if evaluation_claim.submission_id != stored.submission_id
        || evaluation_claim.phase != ControlWorkPhase::Evaluate
        || !evaluation_claim.completed
        || evaluation_claim.finalized_work.is_some()
    {
        return Err(StateError::ControlWorkMismatch);
    }
    let completed_at = evaluation_claim
        .completed_at
        .ok_or_else(|| invalid_control_lineage("EVALUATE completion time is missing"))?;
    let decision = state
        .control_decisions
        .get(&stored.submission_id)
        .cloned()
        .ok_or_else(|| invalid_control_lineage("control decision artifact is missing"))?;
    let expected_decision_id = derive_control_decision_id(
        stored.state_instance_id,
        stored.submission_id,
        stored.evaluation_nonce,
    );
    let expected_decision_commitment = control_decision_commitment(
        evaluation_claim.claim_id,
        &stored.scope(),
        &decision.receipt,
    )?;
    if decision.receipt.decision_id() != expected_decision_id
        || decision.receipt.submission_id() != stored.submission_id
        || decision.receipt.decided_at() != completed_at
        || decision.decision_commitment != expected_decision_commitment
        || state.control_by_decision_id.get(&expected_decision_id) != Some(&stored.submission_id)
        || state
            .control_by_decision_commitment
            .get(&expected_decision_commitment)
            != Some(&stored.submission_id)
        || state
            .control_by_decision_id
            .values()
            .filter(|submission_id| **submission_id == stored.submission_id)
            .count()
            != 1
        || state
            .control_by_decision_commitment
            .values()
            .filter(|submission_id| **submission_id == stored.submission_id)
            .count()
            != 1
    {
        return Err(invalid_control_lineage(
            "control decision identity or commitment lineage is incomplete",
        ));
    }

    match &decision.signed_evaluation {
        None => {
            if evaluation_claim.finalized_decision != Some(expected_decision_id)
                || decision.evaluation_id.is_some()
                || decision.evaluation_commitment.is_some()
                || decision.evaluator_key_id.is_some()
                || decision.evaluator_public_key.is_some()
                || decision.receipt.kernel_outcome().is_some()
                || decision.receipt.control_outcome() != ControlOutcome::Deny
                || !matches!(
                    decision.receipt.reason(),
                    ControlDecisionReason::IngressExpired | ControlDecisionReason::AuthorityChanged
                )
                || decision.receipt.selected_grant_id().is_some()
                || state
                    .control_by_evaluation_commitment
                    .values()
                    .any(|submission_id| *submission_id == stored.submission_id)
            {
                return Err(invalid_control_lineage(
                    "pre-kernel decision has an evaluation artifact or invalid outcome matrix",
                ));
            }
        }
        Some(signed_evaluation) => {
            if evaluation_claim.finalized_decision.is_some() {
                return Err(invalid_control_lineage(
                    "signed EVALUATE completion is marked as pre-kernel finalization",
                ));
            }
            let evaluation_id = decision
                .evaluation_id
                .ok_or_else(|| invalid_control_lineage("signed evaluation id is missing"))?;
            let evaluation_commitment = decision.evaluation_commitment.ok_or_else(|| {
                invalid_control_lineage("signed evaluation commitment is missing")
            })?;
            let evaluator_key_id = decision
                .evaluator_key_id
                .as_ref()
                .ok_or_else(|| invalid_control_lineage("frozen evaluator key id is missing"))?;
            let evaluator_public_key = decision
                .evaluator_public_key
                .ok_or_else(|| invalid_control_lineage("frozen evaluator public key is missing"))?;
            let expected_evaluation_id = derive_control_evaluation_id(
                stored.state_instance_id,
                stored.submission_id,
                stored.evaluation_nonce,
            );
            let verifier =
                CoseVerifier::from_public_key(evaluator_key_id.clone(), evaluator_public_key)
                    .map_err(|error| {
                        invalid_control_lineage(format!("frozen evaluator key is invalid: {error}"))
                    })?;
            let expected_evaluation_commitment = control_evaluation_commitment(
                evaluation_id,
                stored.submission_id,
                evaluation_claim.claim_id,
                &stored.scope(),
                signed_evaluation,
                &verifier,
            )?;
            let attestation = &signed_evaluation.attestation;
            let signed_payload = verify_cose(
                &signed_evaluation.cose_sign1,
                EVALUATION_DOMAIN,
                &verifier,
            )
            .map_err(|error| {
                invalid_control_lineage(format!("stored evaluation signature is invalid: {error}"))
            })?;
            let expected_matrix = match attestation.outcome {
                DecisionOutcome::Deny => {
                    decision.receipt.kernel_outcome() == Some(ControlKernelOutcome::Deny)
                        && decision.receipt.control_outcome() == ControlOutcome::Deny
                        && decision.receipt.reason() == ControlDecisionReason::KernelDeny
                        && decision.receipt.selected_grant_id().is_none()
                        && !attestation.reasons.is_empty()
                        && !attestation.reasons.contains(&ReasonCode::Allowed)
                }
                DecisionOutcome::Allow => {
                    decision.receipt.kernel_outcome() == Some(ControlKernelOutcome::Allow)
                        && attestation.reasons.as_slice() == [ReasonCode::Allowed]
                        && matches!(
                            (
                                decision.receipt.control_outcome(),
                                decision.receipt.reason(),
                                decision.receipt.selected_grant_id(),
                            ),
                            (
                                ControlOutcome::Allow,
                                ControlDecisionReason::ControlAllow,
                                Some(_)
                            ) | (
                                ControlOutcome::Deny,
                                ControlDecisionReason::GrantUnavailable,
                                None
                            )
                        )
                }
            };
            if evaluation_id != expected_evaluation_id
                || evaluation_commitment != expected_evaluation_commitment
                || state
                    .control_by_evaluation_commitment
                    .get(&evaluation_commitment)
                    != Some(&stored.submission_id)
                || state
                    .control_by_evaluation_commitment
                    .values()
                    .filter(|submission_id| **submission_id == stored.submission_id)
                    .count()
                    != 1
                || signed_payload != attestation.canonical_bytes()?
                || attestation.schema_version != EVALUATION_ATTESTATION_SCHEMA_VERSION
                || attestation.evaluation_nonce != stored.evaluation_nonce
                || attestation.request_id != stored.proposal.request_id
                || attestation.tenant != stored.tenant
                || attestation.actor != stored.actor
                || attestation.evaluated_at != evaluation_claim.claimed_at
                || attestation.template_hash != canonical_hash(&stored.proposal.template)?
                || attestation.policy_root != attestation.authority.policy.root
                || attestation.authority.principal_registry != stored.ingress_authority_domain
                || evaluator_verifier_root(evaluator_key_id, evaluator_public_key)
                    .map_err(|error| invalid_control_lineage(error.to_string()))?
                    != attestation.authority.kernel_configuration.root
                || attestation.consume_before <= attestation.evaluated_at
                || attestation.consume_before > stored.ingress_expires_at
                || !expected_matrix
            {
                return Err(invalid_control_lineage(
                    "signed evaluation and decision artifacts do not form one exact lineage",
                ));
            }
        }
    }

    let status_code = match decision.receipt.control_outcome() {
        ControlOutcome::Allow => ControlStatusCode::Authorized,
        ControlOutcome::Deny => ControlStatusCode::ControlDenied,
        ControlOutcome::Manual => ControlStatusCode::ManualResolutionRequired,
    };
    memory_require_control_event(
        state,
        stored,
        2,
        status_code,
        Some(ControlStatusReason::Decision(decision.receipt.reason())),
        completed_at,
    )?;
    Ok(decision)
}

#[allow(clippy::too_many_lines)]
fn memory_validate_control_issuance_lineage(
    state: &MemoryState,
    stored: &StoredControlSubmission,
    decision: &StoredControlDecision,
    issue_claim: &MemoryControlClaim,
) -> Result<IssuedAuthorizationRecord, StateError> {
    memory_validate_completed_control_claim_shape(state, stored, issue_claim)?;
    if issue_claim.submission_id != stored.submission_id
        || issue_claim.phase != ControlWorkPhase::Issue
        || !issue_claim.completed
        || issue_claim.finalized_decision.is_some()
        || issue_claim.finalized_work.is_some()
        || decision.receipt.control_outcome() != ControlOutcome::Allow
    {
        return Err(StateError::ControlWorkMismatch);
    }
    let completed_at = issue_claim
        .completed_at
        .ok_or_else(|| invalid_control_lineage("ISSUE completion time is missing"))?;
    let signed_evaluation = decision
        .signed_evaluation
        .as_ref()
        .ok_or_else(|| invalid_control_lineage("ISSUE decision lacks its evaluation"))?;
    let grant_id = decision
        .receipt
        .selected_grant_id()
        .ok_or_else(|| invalid_control_lineage("ISSUE decision lacks its selected grant"))?;
    let issued = state
        .control_issuances
        .get(&stored.submission_id)
        .cloned()
        .ok_or_else(|| invalid_control_lineage("control issuance artifact is missing"))?;
    issued.validate().map_err(|error| {
        invalid_control_lineage(format!("control issuance is invalid: {error}"))
    })?;
    let authorization = issued.authorization();
    let authorization_key = (issued.scope(), authorization.authorization_id);
    let transaction_key = (issued.scope(), issued.transaction_id);
    if state.authorizations.get(&authorization_key) != Some(&issued)
        || state.transactions.get(&transaction_key) != Some(&authorization.authorization_id)
        || memory_control_owner_for_authorization(state, &issued)? != Some(stored.submission_id)
        || state
            .control_issuances
            .values()
            .filter(|candidate| **candidate == issued)
            .count()
            != 1
        || state
            .authorizations
            .values()
            .filter(|candidate| **candidate == issued)
            .count()
            != 1
        || state
            .transactions
            .iter()
            .filter(|((scope, _), authorization_id)| {
                scope == &issued.scope() && **authorization_id == authorization.authorization_id
            })
            .count()
            != 1
        || authorization.request_id != stored.proposal.request_id
        || authorization.evaluation_nonce != stored.evaluation_nonce
        || authorization.tenant != stored.tenant
        || authorization.holder != stored.actor
        || authorization.template != stored.proposal.template
        || authorization.grant_id != grant_id
        || authorization.issued_at != issue_claim.claimed_at
        || authorization.not_before != issue_claim.claimed_at
        || authorization.consume_before > signed_evaluation.attestation.consume_before
        || authorization.template_hash != signed_evaluation.attestation.template_hash
        || authorization.evidence_root != signed_evaluation.attestation.evidence_root
        || authorization.principals != signed_evaluation.attestation.principals
        || authorization.policy_root != signed_evaluation.attestation.policy_root
        || authorization.authority != signed_evaluation.attestation.authority
    {
        return Err(invalid_control_lineage(
            "control issuance, authorization, transaction, decision, and evaluation do not agree",
        ));
    }
    if let Some(grant) = state.grants.get(&(stored.scope(), grant_id)) {
        validate_grant_for_authorization(&grant.registration, authorization).map_err(|error| {
            invalid_control_lineage(format!(
                "control issuance grant binding is invalid: {error}"
            ))
        })?;
        if authorization.consume_before
            != signed_evaluation
                .attestation
                .consume_before
                .min(grant.registration.grant.expires_at)
        {
            return Err(invalid_control_lineage(
                "control issuance expiry does not match evaluation and grant",
            ));
        }
    }
    memory_require_control_event(
        state,
        stored,
        3,
        ControlStatusCode::AuthorizationIssued,
        Some(ControlStatusReason::Decision(
            ControlDecisionReason::ControlAllow,
        )),
        completed_at,
    )?;
    Ok(issued)
}

fn memory_validate_control_consumption_lineage(
    state: &MemoryState,
    stored: &StoredControlSubmission,
    decision: &StoredControlDecision,
    consume_claim: &MemoryControlClaim,
) -> Result<(ConsumeSuccess, ConsumeKey), StateError> {
    memory_validate_completed_control_claim_shape(state, stored, consume_claim)?;
    if consume_claim.submission_id != stored.submission_id
        || consume_claim.phase != ControlWorkPhase::Consume
        || !consume_claim.completed
        || consume_claim.finalized_decision.is_some()
        || consume_claim.finalized_work.is_some()
    {
        return Err(StateError::ControlWorkMismatch);
    }
    let completed_at = consume_claim
        .completed_at
        .ok_or_else(|| invalid_control_lineage("CONSUME completion time is missing"))?;
    let issue_claim = memory_unique_successful_control_claim(
        state,
        stored.submission_id,
        ControlWorkPhase::Issue,
    )?;
    let issued = memory_validate_control_issuance_lineage(state, stored, decision, &issue_claim)?;
    let key = ConsumeKey {
        scope: issued.scope(),
        transaction_id: issued.transaction_id,
        authorization_id: issued.authorization().authorization_id,
    };
    let success = state
        .control_consumptions
        .get(&stored.submission_id)
        .cloned()
        .ok_or_else(|| invalid_control_lineage("control consumption artifact is missing"))?;
    let expected =
        validate_recovered_consumption(&key, &issued, success.receipt(), success.outbox())
            .map_err(|error| {
                invalid_control_lineage(format!("control consumption tuple is invalid: {error}"))
            })?;
    let authorization_key = (key.scope.clone(), key.authorization_id);
    if success != expected
        || success.issued() != &issued
        || state.receipts.get(&authorization_key) != Some(success.receipt())
        || state.outbox.get(&authorization_key) != Some(success.outbox())
        || state
            .control_consumptions
            .values()
            .filter(|candidate| **candidate == success)
            .count()
            != 1
        || state
            .receipts
            .values()
            .filter(|candidate| **candidate == *success.receipt())
            .count()
            != 1
        || state
            .outbox
            .values()
            .filter(|candidate| **candidate == *success.outbox())
            .count()
            != 1
        || success.receipt().consumed_at != completed_at
    {
        return Err(invalid_control_lineage(
            "control consumption, receipt, outbox, authorization, and claim do not agree",
        ));
    }
    memory_require_control_event(
        state,
        stored,
        4,
        ControlStatusCode::DispatchPending,
        Some(ControlStatusReason::Decision(
            ControlDecisionReason::ControlAllow,
        )),
        completed_at,
    )?;
    Ok((success, key))
}

fn memory_validate_control_decision_finalized(
    state: &MemoryState,
    claim: &MemoryControlClaim,
) -> Result<ControlDecisionReceipt, StateError> {
    if claim.phase != ControlWorkPhase::Evaluate
        || !claim.completed
        || claim.finalized_decision.is_none()
        || claim.finalized_work.is_some()
    {
        return Err(StateError::ControlWorkMismatch);
    }
    let stored = state
        .control_submissions
        .get(&claim.submission_id)
        .cloned()
        .ok_or_else(|| invalid_control_lineage("finalized decision submission is missing"))?;
    memory_validate_control_submission_lineage(state, &stored)?;
    memory_validate_completed_control_claim_shape(state, &stored, claim)?;
    let decision = memory_validate_control_decision_lineage(state, &stored, claim)?;
    if claim.finalized_decision != Some(decision.receipt.decision_id())
        || state.control_issuances.contains_key(&stored.submission_id)
        || state.authorizations.values().any(|issued| {
            issued.scope() == stored.scope()
                && (issued.authorization().request_id == stored.proposal.request_id
                    || issued.authorization().evaluation_nonce == stored.evaluation_nonce)
        })
        || state
            .control_consumptions
            .contains_key(&stored.submission_id)
        || state
            .control_claims
            .values()
            .filter(|candidate| {
                candidate.submission_id == stored.submission_id
                    && candidate.finalized_decision.is_some()
            })
            .count()
            != 1
    {
        return Err(invalid_control_lineage(
            "pre-kernel finalization has conflicting durable artifacts",
        ));
    }
    let queue = state
        .control_queue
        .get(&stored.submission_id)
        .ok_or_else(|| invalid_control_lineage("finalized decision queue is missing"))?;
    let current = memory_validate_control_event_chain(state, &stored)?;
    if queue.phase != ControlWorkPhase::Done
        || queue.active_claim_id.is_some()
        || current.revision() != 2
        || current.status() != ControlStatusCode::ControlDenied
        || current.reason() != Some(ControlStatusReason::Decision(decision.receipt.reason()))
        || current.observed_at() != decision.receipt.decided_at()
    {
        return Err(invalid_control_lineage(
            "pre-kernel finalization is not terminal in queue and status",
        ));
    }
    Ok(decision.receipt)
}

#[allow(clippy::too_many_lines)]
fn memory_validate_control_work_finalized(
    state: &MemoryState,
    claim: &MemoryControlClaim,
    expected: &ControlWorkFinalizationReceipt,
) -> Result<ControlWorkFinalizationReceipt, StateError> {
    if !matches!(
        claim.phase,
        ControlWorkPhase::Issue | ControlWorkPhase::Consume
    ) || !claim.completed
        || claim.finalized_decision.is_some()
        || claim.finalized_work.as_ref() != Some(expected)
        || claim.completed_at != Some(expected.finalized_at())
        || expected.submission_id() != claim.submission_id
        || expected.phase() != claim.phase
    {
        return Err(StateError::ControlWorkMismatch);
    }
    let stored = state
        .control_submissions
        .get(&claim.submission_id)
        .cloned()
        .ok_or_else(|| invalid_control_lineage("work finalization submission is missing"))?;
    memory_validate_control_submission_lineage(state, &stored)?;
    memory_validate_completed_control_claim_shape(state, &stored, claim)?;
    let evaluation_claim = memory_unique_successful_control_claim(
        state,
        stored.submission_id,
        ControlWorkPhase::Evaluate,
    )?;
    let decision = memory_validate_control_decision_lineage(state, &stored, &evaluation_claim)?;
    if decision.receipt.control_outcome() != ControlOutcome::Allow
        || state
            .control_claims
            .values()
            .filter(|candidate| {
                candidate.submission_id == stored.submission_id
                    && candidate.finalized_work.is_some()
            })
            .count()
            != 1
        || state
            .control_consumptions
            .contains_key(&stored.submission_id)
    {
        return Err(invalid_control_lineage(
            "post-decision finalization has conflicting durable artifacts",
        ));
    }

    match claim.phase {
        ControlWorkPhase::Issue => {
            if state.control_issuances.contains_key(&stored.submission_id)
                || state.authorizations.values().any(|issued| {
                    issued.scope() == stored.scope()
                        && (issued.authorization().request_id == stored.proposal.request_id
                            || issued.authorization().evaluation_nonce == stored.evaluation_nonce)
                })
            {
                return Err(invalid_control_lineage(
                    "failed-closed ISSUE has a successful issuance artifact",
                ));
            }
        }
        ControlWorkPhase::Consume => {
            let issue_claim = memory_unique_successful_control_claim(
                state,
                stored.submission_id,
                ControlWorkPhase::Issue,
            )?;
            let issued =
                memory_validate_control_issuance_lineage(state, &stored, &decision, &issue_claim)?;
            let authorization_key = (issued.scope(), issued.authorization().authorization_id);
            if state.receipts.contains_key(&authorization_key)
                || state.outbox.contains_key(&authorization_key)
            {
                return Err(invalid_control_lineage(
                    "failed-closed CONSUME has a receipt or outbox artifact",
                ));
            }
        }
        ControlWorkPhase::Evaluate | ControlWorkPhase::Done => {
            return Err(StateError::ControlWorkMismatch);
        }
    }

    let queue = state
        .control_queue
        .get(&stored.submission_id)
        .ok_or_else(|| invalid_control_lineage("work finalization queue is missing"))?;
    let expected_revision = match claim.phase {
        ControlWorkPhase::Issue => 3,
        ControlWorkPhase::Consume => 4,
        ControlWorkPhase::Evaluate | ControlWorkPhase::Done => unreachable!(),
    };
    let current = memory_require_control_event(
        state,
        &stored,
        expected_revision,
        ControlStatusCode::FailedClosed,
        Some(ControlStatusReason::Finalization(expected.reason())),
        expected.finalized_at(),
    )?;
    if queue.phase != ControlWorkPhase::Done
        || queue.active_claim_id.is_some()
        || current.revision() != expected_revision
        || current.status() != ControlStatusCode::FailedClosed
        || current.reason() != Some(ControlStatusReason::Finalization(expected.reason()))
        || current.observed_at() != expected.finalized_at()
    {
        return Err(invalid_control_lineage(
            "work finalization is not terminal in queue and status",
        ));
    }
    Ok(expected.clone())
}

/// Proves that the current queue and public projection are the only state that
/// can follow the immutable decision and completed artifacts. Older claim
/// retries remain valid after later phases advance, but a forged jump to DONE
/// or a status without its exact artifact is rejected.
#[allow(clippy::too_many_lines)]
fn memory_validate_control_current_progress(
    state: &MemoryState,
    stored: &StoredControlSubmission,
    decision: &StoredControlDecision,
) -> Result<(), StateError> {
    let queue = state
        .control_queue
        .get(&stored.submission_id)
        .ok_or_else(|| invalid_control_lineage("control queue projection is missing"))?;
    let current = memory_validate_control_event_chain(state, stored)?;
    if let Some(active_claim_id) = queue.active_claim_id {
        let active_claim = state.control_claims.get(&active_claim_id).ok_or_else(|| {
            invalid_control_lineage("control queue points to a missing active claim")
        })?;
        if queue.phase == ControlWorkPhase::Done
            || active_claim.submission_id != stored.submission_id
            || active_claim.phase != queue.phase
            || active_claim.completed
        {
            return Err(invalid_control_lineage(
                "control queue active claim does not match its current phase",
            ));
        }
    }

    if decision.receipt.control_outcome() != ControlOutcome::Allow {
        if queue.phase != ControlWorkPhase::Done
            || queue.active_claim_id.is_some()
            || current.revision() != 2
            || state.control_issuances.contains_key(&stored.submission_id)
            || state
                .control_consumptions
                .contains_key(&stored.submission_id)
        {
            return Err(invalid_control_lineage(
                "denied control decision has non-terminal downstream projection",
            ));
        }
        return Ok(());
    }

    match queue.phase {
        ControlWorkPhase::Evaluate => Err(invalid_control_lineage(
            "completed EVALUATE decision left the queue in EVALUATE",
        )),
        ControlWorkPhase::Issue => {
            if current.revision() != 2
                || current.status() != ControlStatusCode::Authorized
                || state.control_issuances.contains_key(&stored.submission_id)
                || state
                    .control_consumptions
                    .contains_key(&stored.submission_id)
            {
                return Err(invalid_control_lineage(
                    "authorized queue projection conflicts with downstream artifacts",
                ));
            }
            Ok(())
        }
        ControlWorkPhase::Consume => {
            let issue_claim = memory_unique_successful_control_claim(
                state,
                stored.submission_id,
                ControlWorkPhase::Issue,
            )?;
            memory_validate_control_issuance_lineage(state, stored, decision, &issue_claim)?;
            if current.revision() != 3
                || current.status() != ControlStatusCode::AuthorizationIssued
                || state
                    .control_consumptions
                    .contains_key(&stored.submission_id)
            {
                return Err(invalid_control_lineage(
                    "CONSUME queue projection conflicts with issuance lineage",
                ));
            }
            Ok(())
        }
        ControlWorkPhase::Done => {
            if queue.active_claim_id.is_some() {
                return Err(invalid_control_lineage(
                    "DONE control queue retains an active claim",
                ));
            }
            if state
                .control_consumptions
                .contains_key(&stored.submission_id)
            {
                if state.control_claims.values().any(|claim| {
                    claim.submission_id == stored.submission_id && claim.finalized_work.is_some()
                }) {
                    return Err(invalid_control_lineage(
                        "successful consumption and fail-closed finalization coexist",
                    ));
                }
                let consume_claim = memory_unique_successful_control_claim(
                    state,
                    stored.submission_id,
                    ControlWorkPhase::Consume,
                )?;
                memory_validate_control_consumption_lineage(
                    state,
                    stored,
                    decision,
                    &consume_claim,
                )?;
                if current.revision() != 4 || current.status() != ControlStatusCode::DispatchPending
                {
                    return Err(invalid_control_lineage(
                        "successful CONSUME is missing its terminal public projection",
                    ));
                }
                return Ok(());
            }

            let mut finalized = state.control_claims.values().filter(|claim| {
                claim.submission_id == stored.submission_id && claim.finalized_work.is_some()
            });
            let finalized_claim = finalized.next().cloned().ok_or_else(|| {
                invalid_control_lineage("DONE queue has no consumption or finalization")
            })?;
            if finalized.next().is_some() {
                return Err(invalid_control_lineage(
                    "DONE queue has multiple work finalizations",
                ));
            }
            let receipt = finalized_claim
                .finalized_work
                .clone()
                .ok_or_else(|| invalid_control_lineage("work finalization receipt is missing"))?;
            memory_validate_control_work_finalized(state, &finalized_claim, &receipt)?;
            Ok(())
        }
    }
}

/// Revalidates the complete durable projection before returning either a
/// recovered intake reference or a public status snapshot. This is deliberately
/// clock- and current-authority-inert: history is authenticated from its frozen
/// artifacts, while partial or contradictory history fails closed.
#[allow(clippy::too_many_lines)]
fn memory_validate_control_recovery_projection(
    state: &MemoryState,
    stored: &StoredControlSubmission,
) -> Result<ControlStatusSnapshot, StateError> {
    memory_validate_control_submission_lineage(state, stored)?;
    let current = memory_validate_control_event_chain(state, stored)?;
    let queue = state
        .control_queue
        .get(&stored.submission_id)
        .ok_or_else(|| invalid_control_lineage("control queue projection is missing"))?;

    if let Some(decision) = state.control_decisions.get(&stored.submission_id) {
        if decision.signed_evaluation.is_none() {
            let mut finalized = state.control_claims.values().filter(|claim| {
                claim.submission_id == stored.submission_id
                    && claim.phase == ControlWorkPhase::Evaluate
                    && claim.finalized_decision == Some(decision.receipt.decision_id())
            });
            let claim = finalized
                .next()
                .cloned()
                .ok_or_else(|| invalid_control_lineage("pre-kernel decision claim is missing"))?;
            if finalized.next().is_some()
                || memory_validate_control_decision_finalized(state, &claim)? != decision.receipt
            {
                return Err(invalid_control_lineage(
                    "pre-kernel decision recovery is missing its unique claim lineage",
                ));
            }
        } else {
            let evaluation_claim = memory_unique_successful_control_claim(
                state,
                stored.submission_id,
                ControlWorkPhase::Evaluate,
            )?;
            let validated =
                memory_validate_control_decision_lineage(state, stored, &evaluation_claim)?;
            if &validated != decision {
                return Err(invalid_control_lineage(
                    "control decision recovery differs from its authenticated artifact",
                ));
            }
            memory_validate_control_current_progress(state, stored, &validated)?;
        }
        return Ok(current);
    }

    if current.revision() != 1
        || current.status() != ControlStatusCode::Accepted
        || current.reason().is_some()
        || current.observed_at() != stored.accepted_at
        || queue.phase != ControlWorkPhase::Evaluate
        || state.control_issuances.contains_key(&stored.submission_id)
        || state
            .control_consumptions
            .contains_key(&stored.submission_id)
        || state
            .control_by_decision_id
            .values()
            .any(|submission_id| *submission_id == stored.submission_id)
        || state
            .control_by_decision_commitment
            .values()
            .any(|submission_id| *submission_id == stored.submission_id)
        || state
            .control_by_evaluation_commitment
            .values()
            .any(|submission_id| *submission_id == stored.submission_id)
    {
        return Err(invalid_control_lineage(
            "ACCEPTED projection has decision or downstream artifacts",
        ));
    }

    let mut claims = state
        .control_claims
        .values()
        .filter(|claim| claim.submission_id == stored.submission_id)
        .cloned()
        .collect::<Vec<_>>();
    match queue.active_claim_id {
        None if !claims.is_empty() => {
            return Err(invalid_control_lineage(
                "unclaimed ACCEPTED queue has historical claim rows",
            ));
        }
        Some(active_claim_id) if !claims.iter().any(|claim| claim.claim_id == active_claim_id) => {
            return Err(invalid_control_lineage(
                "ACCEPTED queue points to a missing active EVALUATE claim",
            ));
        }
        _ => {}
    }

    claims.sort_unstable_by_key(|claim| (claim.claimed_at, claim.fence));
    let mut previous: Option<&MemoryControlClaim> = None;
    for claim in &claims {
        let expected_lease_until = claim
            .claimed_at
            .checked_add(CONTROL_WORK_LEASE_SECONDS)
            .ok_or_else(|| invalid_control_lineage("active control claim lease overflowed"))?;
        if claim.phase != ControlWorkPhase::Evaluate
            || claim.role != ControlWorkerRole::Evaluator
            || claim.completed
            || claim.completed_at.is_some()
            || claim.finalized_decision.is_some()
            || claim.finalized_work.is_some()
            || claim.fence == 0
            || claim.claimed_at < stored.accepted_at
            || claim.lease_until != expected_lease_until
            || ControlWorkClaimRequest::new(claim.worker_id.clone(), claim.role, claim.claim_id)
                .is_err()
            || state
                .control_claims
                .values()
                .filter(|candidate| candidate.fence == claim.fence)
                .count()
                != 1
            || previous.is_some_and(|prior| {
                prior.lease_until > claim.claimed_at || prior.fence >= claim.fence
            })
        {
            return Err(invalid_control_lineage(
                "ACCEPTED EVALUATE claim history is malformed or overlapping",
            ));
        }
        previous = Some(claim);
    }
    if let Some(active_claim_id) = queue.active_claim_id
        && claims.last().map(|claim| claim.claim_id) != Some(active_claim_id)
    {
        return Err(invalid_control_lineage(
            "ACCEPTED queue does not point to the newest fenced claim",
        ));
    }
    Ok(current)
}

fn memory_control_phase_completed(
    state: &MemoryState,
    claim: &MemoryControlClaim,
) -> Result<ControlPhaseCompletionReceipt, StateError> {
    if !claim.completed || claim.finalized_decision.is_some() || claim.finalized_work.is_some() {
        return Err(StateError::ControlWorkMismatch);
    }
    let completed_at = claim.completed_at.ok_or(StateError::ControlWorkMismatch)?;
    let unique = memory_unique_successful_control_claim(state, claim.submission_id, claim.phase)?;
    if unique.claim_id != claim.claim_id || unique.fence != claim.fence {
        return Err(invalid_control_lineage(
            "completed phase does not have one exact successful claim",
        ));
    }
    let stored = state
        .control_submissions
        .get(&claim.submission_id)
        .cloned()
        .ok_or_else(|| invalid_control_lineage("completed phase submission is missing"))?;
    stored.validate()?;
    stored.reverify_frozen_wire()?;
    let evaluation_claim = if claim.phase == ControlWorkPhase::Evaluate {
        claim.clone()
    } else {
        memory_unique_successful_control_claim(
            state,
            stored.submission_id,
            ControlWorkPhase::Evaluate,
        )?
    };
    let decision = memory_validate_control_decision_lineage(state, &stored, &evaluation_claim)?;
    if decision.signed_evaluation.is_none() {
        return Err(invalid_control_lineage(
            "successful phase completion lacks a signed evaluation",
        ));
    }
    let consume_key = match claim.phase {
        ControlWorkPhase::Evaluate => None,
        ControlWorkPhase::Issue => {
            memory_validate_control_issuance_lineage(state, &stored, &decision, claim)?;
            None
        }
        ControlWorkPhase::Consume => {
            let (_, key) =
                memory_validate_control_consumption_lineage(state, &stored, &decision, claim)?;
            Some(key)
        }
        ControlWorkPhase::Done => return Err(StateError::ControlWorkMismatch),
    };
    memory_validate_control_current_progress(state, &stored, &decision)?;
    ControlPhaseCompletionReceipt::new(
        claim.submission_id,
        claim.claim_id,
        claim.fence,
        claim.worker_id.clone(),
        claim.phase,
        completed_at,
        decision.receipt.decision_id(),
        consume_key,
    )
}

/// Returns the immutable v13 owner of an authorization, if any ownership signal is
/// present. A single signal is enough to make the authorization control-owned; all
/// remaining indexes and the exact atomic ISSUE tuple must then agree.
fn memory_control_owner_for_authorization(
    state: &MemoryState,
    issued: &IssuedAuthorizationRecord,
) -> Result<Option<Uuid>, StateError> {
    let scope = issued.scope();
    let authorization = issued.authorization();
    let request_owner = state
        .control_by_request
        .get(&(scope.clone(), authorization.request_id))
        .copied();
    let evaluation_owner = state
        .control_by_evaluation_nonce
        .get(&authorization.evaluation_nonce)
        .copied();
    let issuance_owners = state
        .control_issuances
        .iter()
        .filter_map(|(submission_id, stored)| (stored == issued).then_some(*submission_id))
        .collect::<Vec<_>>();
    if issuance_owners.len() > 1 {
        return Err(StateError::InvalidRecord(
            "authorization is linked to multiple control submissions".to_owned(),
        ));
    }

    let mut owner = None;
    for candidate in [
        request_owner,
        evaluation_owner,
        issuance_owners.first().copied(),
    ]
    .into_iter()
    .flatten()
    {
        if owner.is_some_and(|existing| existing != candidate) {
            return Err(StateError::InvalidRecord(
                "control authorization ownership indexes disagree".to_owned(),
            ));
        }
        owner = Some(candidate);
    }
    let Some(submission_id) = owner else {
        return Ok(None);
    };
    let submission = state
        .control_submissions
        .get(&submission_id)
        .ok_or_else(|| {
            StateError::InvalidRecord(
                "control-owned authorization lacks its immutable submission".to_owned(),
            )
        })?;
    if submission.scope() != scope
        || submission.proposal.request_id != authorization.request_id
        || submission.evaluation_nonce != authorization.evaluation_nonce
        || state.control_issuances.get(&submission_id) != Some(issued)
    {
        return Err(StateError::InvalidRecord(
            "control-owned authorization has incomplete ISSUE lineage".to_owned(),
        ));
    }
    Ok(Some(submission_id))
}

/// Legacy recovery and every dispatch-capability path call this gate. A
/// receipt/outbox tuple belonging to v13 is usable only after the combined
/// CONSUME transaction committed its control link, completion, terminal queue
/// projection, and public status. Partial legacy tuples are never adopted.
fn validate_memory_control_consumption_lineage_if_owned(
    state: &MemoryState,
    key: &ConsumeKey,
    issued: &IssuedAuthorizationRecord,
    receipt: &ConsumptionReceipt,
    outbox: &OutboxEntry,
) -> Result<(), StateError> {
    let Some(submission_id) = memory_control_owner_for_authorization(state, issued)? else {
        return Ok(());
    };
    let success = validate_recovered_consumption(key, issued, receipt, outbox)?;
    if state.control_consumptions.get(&submission_id) != Some(&success) {
        return Err(StateError::InvalidRecord(
            "control-owned consumption lacks its atomic control link".to_owned(),
        ));
    }
    let queue = state
        .control_queue
        .get(&submission_id)
        .ok_or(StateError::ControlWorkNotFound)?;
    if queue.phase != ControlWorkPhase::Done || queue.active_claim_id.is_some() {
        return Err(StateError::InvalidRecord(
            "control-owned consumption is not terminal in its work queue".to_owned(),
        ));
    }
    let submission = state
        .control_submissions
        .get(&submission_id)
        .ok_or(StateError::ControlSubmissionMismatch)?;
    let status = state
        .control_statuses
        .get(&submission_id)
        .ok_or(StateError::ControlStatusNotFound)?;
    if status.receipt_id() != submission.receipt_id
        || status.status() != ControlStatusCode::DispatchPending
        || state
            .control_events
            .get(&submission_id)
            .and_then(|events| events.last())
            != Some(status)
    {
        return Err(StateError::InvalidRecord(
            "control-owned consumption status lineage is incomplete".to_owned(),
        ));
    }
    let mut completed_claims = state.control_claims.values().filter(|claim| {
        claim.submission_id == submission_id
            && claim.phase == ControlWorkPhase::Consume
            && claim.completed
            && claim.finalized_work.is_none()
            && claim.finalized_decision.is_none()
    });
    let claim = completed_claims.next().ok_or_else(|| {
        StateError::InvalidRecord(
            "control-owned consumption lacks its completed CONSUME claim".to_owned(),
        )
    })?;
    if completed_claims.next().is_some() {
        return Err(StateError::InvalidRecord(
            "control-owned consumption has multiple completed CONSUME claims".to_owned(),
        ));
    }
    let completion = memory_control_phase_completed(state, claim)?;
    if completion.consume_key() != Some(key) || completion.completed_at() != receipt.consumed_at {
        return Err(StateError::InvalidRecord(
            "control-owned consumption completion does not match its durable tuple".to_owned(),
        ));
    }
    Ok(())
}

fn memory_build_control_work(
    state: &MemoryState,
    state_instance_id: Uuid,
    claim: &MemoryControlClaim,
) -> Result<ClaimedControlWork, StateError> {
    let stored = state
        .control_submissions
        .get(&claim.submission_id)
        .ok_or(StateError::ControlSubmissionMismatch)?;
    stored.validate()?;
    let lease = memory_control_lease(state_instance_id, claim);
    match claim.phase {
        ControlWorkPhase::Evaluate => {
            let active_authority = state
                .authorities
                .get(&stored.scope())
                .cloned()
                .ok_or(StateError::AuthorityNotInitialized)?;
            Ok(ClaimedControlWork::Evaluate(ControlEvaluationWork {
                lease,
                scope: stored.scope(),
                proposal: stored.proposal.clone(),
                caller_tenant: stored.tenant.clone(),
                caller_actor: stored.actor.clone(),
                accepted_at: stored.accepted_at,
                ingress_expires_at: stored.ingress_expires_at,
                ingress_authority_domain: stored.ingress_authority_domain.clone(),
                active_authority,
                evaluation_nonce: stored.evaluation_nonce,
            }))
        }
        ControlWorkPhase::Issue => {
            let decision = state
                .control_decisions
                .get(&claim.submission_id)
                .ok_or(StateError::ControlDecisionMismatch)?;
            let signed_evaluation = decision
                .signed_evaluation
                .clone()
                .ok_or(StateError::ControlDecisionMismatch)?;
            let selected_grant_id = decision
                .receipt
                .selected_grant_id()
                .ok_or(StateError::ControlDecisionMismatch)?;
            if decision.receipt.control_outcome() != ControlOutcome::Allow {
                return Err(StateError::ControlDecisionMismatch);
            }
            Ok(ClaimedControlWork::Issue(ControlIssuanceWork {
                lease,
                scope: stored.scope(),
                proposal: stored.proposal.clone(),
                signed_evaluation,
                selected_grant_id,
                decision_id: decision.receipt.decision_id(),
            }))
        }
        ControlWorkPhase::Consume => {
            let issued = state
                .control_issuances
                .get(&claim.submission_id)
                .ok_or(StateError::ControlDecisionMismatch)?;
            Ok(ClaimedControlWork::Consume(ControlConsumptionWork {
                lease,
                consume_key: ConsumeKey {
                    scope: issued.scope(),
                    transaction_id: issued.transaction_id,
                    authorization_id: issued.authorization().authorization_id,
                },
            }))
        }
        ControlWorkPhase::Done => Err(StateError::ControlWorkMismatch),
    }
}

fn memory_push_control_status(
    state: &mut MemoryState,
    submission_id: Uuid,
    receipt_id: Uuid,
    status_code: ControlStatusCode,
    reason: Option<ControlStatusReason>,
    observed_at: i64,
) -> Result<ControlStatusSnapshot, StateError> {
    let prior = state
        .control_statuses
        .get(&submission_id)
        .ok_or(StateError::ControlStatusNotFound)?;
    let revision = prior
        .revision()
        .checked_add(1)
        .ok_or_else(|| StateError::InvalidRecord("control status revision exhausted".to_owned()))?;
    let status = ControlStatusSnapshot::new(
        submission_id,
        receipt_id,
        status_code,
        reason,
        revision,
        observed_at,
    );
    let event_commitment = control_event_commitment(&status)?;
    if state
        .control_by_event_commitment
        .contains_key(&event_commitment)
        || state
            .control_event_commitments
            .contains_key(&(submission_id, revision))
    {
        return Err(StateError::InvalidRecord(
            "control event commitment collision or duplicate revision".to_owned(),
        ));
    }
    state.control_statuses.insert(submission_id, status.clone());
    state
        .control_events
        .get_mut(&submission_id)
        .ok_or(StateError::ControlStatusNotFound)?
        .push(status.clone());
    state
        .control_by_event_commitment
        .insert(event_commitment, (submission_id, revision));
    state
        .control_event_commitments
        .insert((submission_id, revision), event_commitment);
    Ok(status)
}

fn memory_finalize_pre_kernel(
    state: &mut MemoryState,
    submission_id: Uuid,
    claim_id: Uuid,
    reason: ControlDecisionReason,
    now: i64,
) -> Result<ControlDecisionReceipt, StateError> {
    let stored = state
        .control_submissions
        .get(&submission_id)
        .cloned()
        .ok_or(StateError::ControlSubmissionMismatch)?;
    let decision_id = derive_control_decision_id(
        stored.state_instance_id,
        submission_id,
        stored.evaluation_nonce,
    );
    let receipt = ControlDecisionReceipt::new(
        decision_id,
        submission_id,
        None,
        ControlOutcome::Deny,
        reason,
        None,
        now,
    );
    let decision_commitment = control_decision_commitment(claim_id, &stored.scope(), &receipt)?;
    if let Some(existing) = state.control_decisions.get(&submission_id) {
        if existing.receipt != receipt
            || existing.decision_commitment != decision_commitment
            || state
                .control_by_decision_commitment
                .get(&decision_commitment)
                != Some(&submission_id)
        {
            return Err(StateError::ControlDecisionMismatch);
        }
    } else {
        if state.control_by_decision_id.contains_key(&decision_id)
            || state
                .control_by_decision_commitment
                .contains_key(&decision_commitment)
        {
            return Err(StateError::ControlDecisionMismatch);
        }
        state.control_decisions.insert(
            submission_id,
            StoredControlDecision {
                receipt: receipt.clone(),
                evaluation_id: None,
                evaluation_commitment: None,
                decision_commitment,
                signed_evaluation: None,
                evaluator_key_id: None,
                evaluator_public_key: None,
            },
        );
        state
            .control_by_decision_id
            .insert(decision_id, submission_id);
        state
            .control_by_decision_commitment
            .insert(decision_commitment, submission_id);
        memory_push_control_status(
            state,
            submission_id,
            stored.receipt_id,
            ControlStatusCode::ControlDenied,
            Some(ControlStatusReason::Decision(reason)),
            now,
        )?;
    }
    let queue = state
        .control_queue
        .get_mut(&submission_id)
        .ok_or(StateError::ControlWorkNotFound)?;
    queue.phase = ControlWorkPhase::Done;
    queue.active_claim_id = None;
    let claim = state
        .control_claims
        .get_mut(&claim_id)
        .ok_or(StateError::ControlWorkNotFound)?;
    claim.completed = true;
    claim.completed_at = Some(now);
    claim.finalized_decision = Some(decision_id);
    let claim = state
        .control_claims
        .get(&claim_id)
        .cloned()
        .ok_or(StateError::ControlWorkNotFound)?;
    let recovered = memory_validate_control_decision_finalized(state, &claim)?;
    if recovered != receipt {
        return Err(invalid_control_lineage(
            "fresh pre-kernel finalization differs from durable recovery",
        ));
    }
    Ok(recovered)
}

fn memory_finalize_post_decision(
    state: &mut MemoryState,
    submission_id: Uuid,
    claim_id: Uuid,
    phase: ControlWorkPhase,
    reason: ControlWorkFinalizationReason,
    now: i64,
) -> Result<ControlWorkFinalizationReceipt, StateError> {
    let stored = state
        .control_submissions
        .get(&submission_id)
        .cloned()
        .ok_or(StateError::ControlSubmissionMismatch)?;
    let decision = state
        .control_decisions
        .get(&submission_id)
        .ok_or(StateError::ControlDecisionMismatch)?;
    if decision.receipt.control_outcome() != ControlOutcome::Allow
        || state
            .control_by_decision_id
            .get(&decision.receipt.decision_id())
            != Some(&submission_id)
    {
        return Err(StateError::ControlDecisionMismatch);
    }
    let receipt = ControlWorkFinalizationReceipt::new(submission_id, phase, reason, now);
    memory_push_control_status(
        state,
        submission_id,
        stored.receipt_id,
        ControlStatusCode::FailedClosed,
        Some(ControlStatusReason::Finalization(reason)),
        now,
    )?;
    let queue = state
        .control_queue
        .get_mut(&submission_id)
        .ok_or(StateError::ControlWorkNotFound)?;
    queue.phase = ControlWorkPhase::Done;
    queue.active_claim_id = None;
    let claim = state
        .control_claims
        .get_mut(&claim_id)
        .ok_or(StateError::ControlWorkNotFound)?;
    claim.completed = true;
    claim.completed_at = Some(now);
    claim.finalized_work = Some(receipt.clone());
    let claim = state
        .control_claims
        .get(&claim_id)
        .cloned()
        .ok_or(StateError::ControlWorkNotFound)?;
    memory_validate_control_work_finalized(state, &claim, &receipt)
}

fn control_grant_allows(
    grant: &accordlock_protocol::CapabilityGrant,
    proposal: &accordlock_protocol::AgentProposal,
) -> bool {
    grant.holder == proposal.actor
        && grant.tenant == proposal.tenant
        && grant.operation == proposal.template.operation
        && grant.repository == proposal.template.repository
        && grant.audience == proposal.template.audience
        && grant.cluster_identity == proposal.template.cluster_identity
        && grant.namespace == proposal.template.namespace
        && grant.deployment_uid == proposal.template.deployment_uid
        && grant.container == proposal.template.container
        && grant.image_repository == proposal.template.image_repository
}

enum MemoryControlPreflight {
    Ready,
    DecisionFinalized(ControlDecisionReceipt),
    WorkFinalized(ControlWorkFinalizationReceipt),
}

fn memory_control_structural_preflight(
    state: &MemoryState,
    submission_id: Uuid,
    phase: ControlWorkPhase,
) -> Result<(), StateError> {
    let stored = state
        .control_submissions
        .get(&submission_id)
        .ok_or(StateError::ControlSubmissionMismatch)?;
    stored.validate()?;
    stored.reverify_frozen_wire()?;
    if state
        .control_statuses
        .get(&submission_id)
        .is_none_or(|status| status.revision() == u64::MAX)
        || !state.control_events.contains_key(&submission_id)
        || state
            .control_queue
            .get(&submission_id)
            .is_none_or(|queue| queue.phase != phase)
        || !state.authorities.contains_key(&stored.scope())
    {
        return Err(StateError::ControlWorkMismatch);
    }
    match phase {
        ControlWorkPhase::Evaluate => Ok(()),
        ControlWorkPhase::Issue => {
            let decision = state
                .control_decisions
                .get(&submission_id)
                .ok_or(StateError::ControlDecisionMismatch)?;
            if decision.receipt.control_outcome() != ControlOutcome::Allow
                || decision.receipt.selected_grant_id().is_none()
                || decision.signed_evaluation.is_none()
                || decision.evaluator_key_id.is_none()
                || decision.evaluator_public_key.is_none()
            {
                return Err(StateError::ControlDecisionMismatch);
            }
            if let Some(issued) = state.control_issuances.get(&submission_id) {
                issued.validate()?;
                if state
                    .authorizations
                    .get(&(issued.scope(), issued.authorization().authorization_id))
                    != Some(issued)
                    || state
                        .transactions
                        .get(&(issued.scope(), issued.transaction_id))
                        != Some(&issued.authorization().authorization_id)
                {
                    return Err(StateError::InvalidRecord(
                        "partial control issuance/authorization/transaction tuple exists"
                            .to_owned(),
                    ));
                }
                return Err(StateError::InvalidRecord(
                    "completed issuance tuple is linked to active ISSUE work".to_owned(),
                ));
            }
            Ok(())
        }
        ControlWorkPhase::Consume => {
            let issued = state
                .control_issuances
                .get(&submission_id)
                .ok_or(StateError::AuthorizationNotFound)?;
            issued.validate()?;
            if state
                .authorizations
                .get(&(issued.scope(), issued.authorization().authorization_id))
                != Some(issued)
                || state
                    .transactions
                    .get(&(issued.scope(), issued.transaction_id))
                    != Some(&issued.authorization().authorization_id)
            {
                return Err(StateError::AuthorizationNotFound);
            }
            Ok(())
        }
        ControlWorkPhase::Done => Err(StateError::ControlWorkMismatch),
    }
}

#[allow(clippy::too_many_lines)]
fn memory_control_preflight(
    state: &mut MemoryState,
    claim_id: Uuid,
    now: i64,
) -> Result<MemoryControlPreflight, StateError> {
    let claim = state
        .control_claims
        .get(&claim_id)
        .cloned()
        .ok_or(StateError::ControlWorkNotFound)?;
    let stored = state
        .control_submissions
        .get(&claim.submission_id)
        .cloned()
        .ok_or(StateError::ControlSubmissionMismatch)?;
    stored.reverify_frozen_wire()?;
    if now < stored.accepted_at {
        return Err(StateError::ClockRollback {
            observed: now,
            high_water: stored.accepted_at,
        });
    }
    let active = state
        .authorities
        .get(&stored.scope())
        .cloned()
        .ok_or(StateError::AuthorityNotInitialized)?;
    if claim.phase == ControlWorkPhase::Evaluate {
        if active.principal_registry != stored.ingress_authority_domain {
            return memory_finalize_pre_kernel(
                state,
                stored.submission_id,
                claim_id,
                ControlDecisionReason::AuthorityChanged,
                now,
            )
            .map(MemoryControlPreflight::DecisionFinalized);
        }
        if now >= stored.ingress_expires_at {
            return memory_finalize_pre_kernel(
                state,
                stored.submission_id,
                claim_id,
                ControlDecisionReason::IngressExpired,
                now,
            )
            .map(MemoryControlPreflight::DecisionFinalized);
        }
        return Ok(MemoryControlPreflight::Ready);
    }

    let decision = state
        .control_decisions
        .get(&stored.submission_id)
        .cloned()
        .ok_or(StateError::ControlDecisionMismatch)?;
    let evaluation = decision
        .signed_evaluation
        .as_ref()
        .ok_or(StateError::ControlDecisionMismatch)?;

    // The v13 CONSUME transaction owns receipt + outbox + control link. Any
    // receipt/outbox visible while this claim remains active is therefore a
    // mixed-mode or partial tuple, never recoverable current work.
    if claim.phase == ControlWorkPhase::Consume {
        let issued = state
            .control_issuances
            .get(&stored.submission_id)
            .ok_or(StateError::AuthorizationNotFound)?;
        let authorization_key = (stored.scope(), issued.authorization().authorization_id);
        match (
            state.receipts.get(&authorization_key),
            state.outbox.get(&authorization_key),
        ) {
            (Some(_), Some(_)) => {
                return Err(StateError::InvalidRecord(
                    "receipt/outbox exists outside atomic control consumption".to_owned(),
                ));
            }
            (None, None) => {}
            _ => {
                return Err(StateError::InvalidRecord(
                    "partial consumption/outbox tuple exists".to_owned(),
                ));
            }
        }
    }

    if active != evaluation.attestation.authority {
        return memory_finalize_post_decision(
            state,
            stored.submission_id,
            claim_id,
            claim.phase,
            ControlWorkFinalizationReason::AuthorityChanged,
            now,
        )
        .map(MemoryControlPreflight::WorkFinalized);
    }
    if now >= stored.ingress_expires_at {
        return memory_finalize_post_decision(
            state,
            stored.submission_id,
            claim_id,
            claim.phase,
            ControlWorkFinalizationReason::IngressExpired,
            now,
        )
        .map(MemoryControlPreflight::WorkFinalized);
    }
    if now >= evaluation.attestation.consume_before {
        return memory_finalize_post_decision(
            state,
            stored.submission_id,
            claim_id,
            claim.phase,
            ControlWorkFinalizationReason::AuthorizationExpired,
            now,
        )
        .map(MemoryControlPreflight::WorkFinalized);
    }
    let grant_id = decision
        .receipt
        .selected_grant_id()
        .ok_or(StateError::ControlDecisionMismatch)?;
    let grant = state.grants.get(&(stored.scope(), grant_id));
    if grant.is_none_or(|snapshot| {
        !control_grant_allows(&snapshot.registration.grant, &stored.proposal)
    }) {
        return memory_finalize_post_decision(
            state,
            stored.submission_id,
            claim_id,
            claim.phase,
            ControlWorkFinalizationReason::GrantUnavailable,
            now,
        )
        .map(MemoryControlPreflight::WorkFinalized);
    }
    let grant = grant.ok_or(StateError::GrantNotFound)?;
    if let Err(error) = validate_current_grant(&active, grant, now) {
        let reason = if claim.phase == ControlWorkPhase::Consume
            && is_temporal_rejection_for_sample(&error, now)
        {
            ControlWorkFinalizationReason::DispatchWindowExpired
        } else {
            ControlWorkFinalizationReason::GrantUnavailable
        };
        return memory_finalize_post_decision(
            state,
            stored.submission_id,
            claim_id,
            claim.phase,
            reason,
            now,
        )
        .map(MemoryControlPreflight::WorkFinalized);
    }

    // CONSUME must validate the complete effective delivery window, not only
    // ingress/evaluation/grant expiry. A frozen profile hard-cap or immutable
    // dependency may close first. Such an exact trusted-time rejection is a
    // terminal state transition, never a retry loop.
    if claim.phase == ControlWorkPhase::Consume {
        let issued = state
            .control_issuances
            .get(&stored.submission_id)
            .ok_or(StateError::AuthorizationNotFound)?;
        let high_water = Some(memory_control_high_water(state, &stored)?);
        if let Err(error) = validate_consumption(&active, grant, issued, now, high_water) {
            let reason = match error {
                StateError::AuthorizationExpired { observed, .. } if observed == now => {
                    ControlWorkFinalizationReason::AuthorizationExpired
                }
                ref temporal if is_temporal_rejection_for_sample(temporal, now) => {
                    ControlWorkFinalizationReason::DispatchWindowExpired
                }
                StateError::GrantRevoked | StateError::GrantExhausted => {
                    ControlWorkFinalizationReason::GrantUnavailable
                }
                other => return Err(other),
            };
            return memory_finalize_post_decision(
                state,
                stored.submission_id,
                claim_id,
                claim.phase,
                reason,
                now,
            )
            .map(MemoryControlPreflight::WorkFinalized);
        }
    }
    Ok(MemoryControlPreflight::Ready)
}

#[allow(clippy::too_many_lines)]
fn memory_claim_next_control_work(
    store: &InMemoryStore,
    request: &ControlWorkClaimRequest,
) -> Result<ControlWorkClaimOutcome, StateError> {
    let mut state = store.inner.lock();
    if let Some(existing) = state.control_claims.get(&request.claim_id()).cloned() {
        if existing.worker_id != request.worker_id() || existing.role != request.role() {
            return Err(StateError::ControlWorkMismatch);
        }
        if existing.finalized_decision.is_some() {
            return memory_validate_control_decision_finalized(&state, &existing)
                .map(ControlWorkClaimOutcome::DecisionFinalized);
        }
        if let Some(finalized) = &existing.finalized_work {
            return memory_validate_control_work_finalized(&state, &existing, finalized)
                .map(ControlWorkClaimOutcome::WorkFinalized);
        }
        if existing.completed {
            return memory_control_phase_completed(&state, &existing)
                .map(ControlWorkClaimOutcome::PhaseCompleted);
        }
        if state
            .control_queue
            .get(&existing.submission_id)
            .is_none_or(|queue| {
                queue.phase != existing.phase || queue.active_claim_id != Some(existing.claim_id)
            })
        {
            return Err(StateError::ControlWorkMismatch);
        }
        let now = store.clock.now_unix_seconds()?;
        let stored = state
            .control_submissions
            .get(&existing.submission_id)
            .cloned()
            .ok_or(StateError::ControlSubmissionMismatch)?;
        memory_control_structural_preflight(&state, existing.submission_id, existing.phase)?;
        let high_water = memory_control_high_water(&state, &stored)?;
        if now < high_water || now < stored.accepted_at {
            return Err(StateError::ClockRollback {
                observed: now,
                high_water: high_water.max(stored.accepted_at),
            });
        }
        if now >= existing.lease_until {
            memory_advance_control_high_water(&mut state, &stored, now)?;
            return Err(StateError::ControlWorkLeaseExpired {
                observed: now,
                lease_until: existing.lease_until,
            });
        }
        let savepoint = MemoryControlSavepoint::capture(&state);
        memory_advance_control_high_water(&mut state, &stored, now)?;
        let result = match memory_control_preflight(&mut state, existing.claim_id, now) {
            Ok(MemoryControlPreflight::Ready) => {
                memory_build_control_work(&state, store.state_instance_id, &existing)
                    .map(ControlWorkClaimOutcome::Recovered)
            }
            Ok(MemoryControlPreflight::DecisionFinalized(receipt)) => {
                Ok(ControlWorkClaimOutcome::DecisionFinalized(receipt))
            }
            Ok(MemoryControlPreflight::WorkFinalized(receipt)) => {
                Ok(ControlWorkClaimOutcome::WorkFinalized(receipt))
            }
            Err(error) => Err(error),
        };
        return finish_memory_control_scope_transaction(
            &mut state, savepoint, &stored, now, result,
        );
    }

    let now = store.clock.now_unix_seconds()?;
    let desired_phase = request.role().phase();
    let selected = state
        .control_queue
        .iter()
        .filter_map(|(submission_id, queue)| {
            if queue.phase != desired_phase {
                return None;
            }
            let available = queue.active_claim_id.is_none_or(|claim_id| {
                state
                    .control_claims
                    .get(&claim_id)
                    .is_some_and(|claim| !claim.completed && now >= claim.lease_until)
            });
            available.then(|| {
                state
                    .control_submissions
                    .get(submission_id)
                    .map(|stored| (stored.accepted_at, *submission_id))
            })?
        })
        .min()
        .map(|(_, submission_id)| submission_id);
    let Some(submission_id) = selected else {
        return Ok(ControlWorkClaimOutcome::NoWork);
    };
    let stored = state
        .control_submissions
        .get(&submission_id)
        .cloned()
        .ok_or(StateError::ControlSubmissionMismatch)?;
    memory_control_structural_preflight(&state, submission_id, desired_phase)?;
    let high_water = memory_control_high_water(&state, &stored)?;
    if now < high_water || now < stored.accepted_at {
        return Err(StateError::ClockRollback {
            observed: now,
            high_water: high_water.max(stored.accepted_at),
        });
    }
    let fence = state
        .next_control_fence
        .checked_add(1)
        .ok_or(StateError::ControlWorkFenceExhausted)?;
    let lease_until = now
        .checked_add(CONTROL_WORK_LEASE_SECONDS)
        .ok_or(StateError::DeadlineOverflow)?;
    let savepoint = MemoryControlSavepoint::capture(&state);
    state.next_control_fence = fence;
    memory_advance_control_high_water(&mut state, &stored, now)?;
    let claim = MemoryControlClaim {
        submission_id,
        phase: desired_phase,
        worker_id: request.worker_id().to_owned(),
        role: request.role(),
        claim_id: request.claim_id(),
        fence,
        claimed_at: now,
        lease_until,
        completed: false,
        completed_at: None,
        finalized_decision: None,
        finalized_work: None,
    };
    state
        .control_claims
        .insert(request.claim_id(), claim.clone());
    state
        .control_queue
        .get_mut(&submission_id)
        .ok_or(StateError::ControlWorkNotFound)?
        .active_claim_id = Some(request.claim_id());
    let result = match memory_control_preflight(&mut state, request.claim_id(), now) {
        Ok(MemoryControlPreflight::Ready) => {
            memory_build_control_work(&state, store.state_instance_id, &claim)
                .map(ControlWorkClaimOutcome::Claimed)
        }
        Ok(MemoryControlPreflight::DecisionFinalized(receipt)) => {
            Ok(ControlWorkClaimOutcome::DecisionFinalized(receipt))
        }
        Ok(MemoryControlPreflight::WorkFinalized(receipt)) => {
            Ok(ControlWorkClaimOutcome::WorkFinalized(receipt))
        }
        Err(error) => Err(error),
    };
    finish_memory_control_scope_transaction(&mut state, savepoint, &stored, now, result)
}

fn memory_validate_control_lease(
    state: &mut MemoryState,
    state_instance_id: Uuid,
    lease: &ControlWorkLease,
    expected_phase: ControlWorkPhase,
    now: i64,
) -> Result<MemoryControlClaim, StateError> {
    if lease.state_instance_id != state_instance_id || lease.phase != expected_phase {
        return Err(StateError::ControlWorkMismatch);
    }
    let claim = state
        .control_claims
        .get(&lease.claim_id)
        .cloned()
        .ok_or(StateError::ControlWorkNotFound)?;
    if claim.completed
        || !memory_control_claim_matches_lease(&claim, state_instance_id, lease, expected_phase)
        || state
            .control_queue
            .get(&lease.submission_id)
            .is_none_or(|queue| {
                queue.phase != expected_phase || queue.active_claim_id != Some(lease.claim_id)
            })
    {
        return Err(StateError::ControlWorkMismatch);
    }
    if now >= lease.lease_until {
        let stored = state
            .control_submissions
            .get(&lease.submission_id)
            .cloned()
            .ok_or(StateError::ControlSubmissionMismatch)?;
        let high_water = memory_control_high_water(state, &stored)?;
        if now < high_water {
            return Err(StateError::ClockRollback {
                observed: now,
                high_water,
            });
        }
        // Once an exact opaque lease has been observed expired, persist that
        // trusted sample before returning. A later clock rollback can then
        // never resurrect the same capability inside its former window.
        memory_advance_control_high_water(state, &stored, now)?;
        return Err(StateError::ControlWorkLeaseExpired {
            observed: now,
            lease_until: lease.lease_until,
        });
    }
    Ok(claim)
}

fn memory_control_claim_matches_lease(
    claim: &MemoryControlClaim,
    state_instance_id: Uuid,
    lease: &ControlWorkLease,
    expected_phase: ControlWorkPhase,
) -> bool {
    lease.state_instance_id == state_instance_id
        && lease.phase == expected_phase
        && claim.submission_id == lease.submission_id
        && claim.phase == lease.phase
        && claim.worker_id == lease.worker_id
        && claim.claim_id == lease.claim_id
        && claim.fence == lease.fence
        && claim.claimed_at == lease.claimed_at
        && claim.lease_until == lease.lease_until
        && claim.role.phase() == expected_phase
}

// The capability is intentionally consumed by the public boundary even though
// validation only needs borrowed fields inside this adapter.
#[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
fn memory_record_control_evaluation(
    store: &InMemoryStore,
    work: ControlEvaluationWork,
    signed_evaluation: &SignedEvaluation,
    evaluator: &CoseVerifier,
) -> Result<ControlDecisionReceipt, StateError> {
    let mut state = store.inner.lock();
    let now = store.clock.now_unix_seconds()?;
    let claim = memory_validate_control_lease(
        &mut state,
        store.state_instance_id,
        &work.lease,
        ControlWorkPhase::Evaluate,
        now,
    )?;
    let stored = state
        .control_submissions
        .get(&claim.submission_id)
        .cloned()
        .ok_or(StateError::ControlSubmissionMismatch)?;
    memory_control_structural_preflight(&state, stored.submission_id, ControlWorkPhase::Evaluate)?;
    let scope = stored.scope();
    let high_water = memory_control_high_water(&state, &stored)?;
    if now < high_water || now < stored.accepted_at {
        return Err(StateError::ClockRollback {
            observed: now,
            high_water: high_water.max(stored.accepted_at),
        });
    }
    let savepoint = MemoryControlSavepoint::capture(&state);
    let result = (|| {
        memory_advance_control_high_water(&mut state, &stored, now)?;
        match memory_control_preflight(&mut state, claim.claim_id, now)? {
            MemoryControlPreflight::DecisionFinalized(receipt) => return Ok(receipt),
            MemoryControlPreflight::WorkFinalized(_) => {
                return Err(StateError::ControlDecisionMismatch);
            }
            MemoryControlPreflight::Ready => {}
        }
        let active = state
            .authorities
            .get(&stored.scope())
            .cloned()
            .ok_or(StateError::AuthorityNotInitialized)?;
        if work.scope != stored.scope()
            || work.proposal != stored.proposal
            || work.caller_tenant != stored.tenant
            || work.caller_actor != stored.actor
            || work.accepted_at != stored.accepted_at
            || work.ingress_expires_at != stored.ingress_expires_at
            || work.ingress_authority_domain != stored.ingress_authority_domain
            || work.active_authority != active
            || work.evaluation_nonce != stored.evaluation_nonce
        {
            return Err(StateError::ControlWorkMismatch);
        }
        let evaluator_root =
            evaluator_verifier_root(evaluator.key_id(), evaluator.public_key_bytes())
                .map_err(|error| StateError::InvalidRecord(error.to_string()))?;
        if evaluator_root != active.kernel_configuration.root {
            return Err(StateError::AuthorityMismatch);
        }
        let payload = verify_cose(&signed_evaluation.cose_sign1, EVALUATION_DOMAIN, evaluator)
            .map_err(|error| {
                StateError::InvalidRecord(format!("evaluation signature invalid: {error}"))
            })?;
        let canonical = signed_evaluation.attestation.canonical_bytes()?;
        let evaluation = &signed_evaluation.attestation;
        let reasons_valid = match evaluation.outcome {
            DecisionOutcome::Allow => evaluation.reasons.as_slice() == [ReasonCode::Allowed],
            DecisionOutcome::Deny => {
                !evaluation.reasons.is_empty() && !evaluation.reasons.contains(&ReasonCode::Allowed)
            }
        };
        if payload != canonical
            || evaluation.schema_version != EVALUATION_ATTESTATION_SCHEMA_VERSION
            || evaluation.evaluation_nonce != stored.evaluation_nonce
            || evaluation.request_id != stored.proposal.request_id
            || evaluation.tenant != stored.tenant
            || evaluation.actor != stored.actor
            || evaluation.evaluated_at != claim.claimed_at
            || evaluation.authority != active
            || evaluation.template_hash != canonical_hash(&stored.proposal.template)?
            || evaluation.policy_root != active.policy.root
            || evaluation.consume_before <= evaluation.evaluated_at
            || evaluation.consume_before > stored.ingress_expires_at
            || !reasons_valid
        {
            return Err(StateError::ControlDecisionMismatch);
        }

        let (kernel_outcome, control_outcome, reason, selected_grant_id) = match evaluation.outcome
        {
            DecisionOutcome::Deny => (
                ControlKernelOutcome::Deny,
                ControlOutcome::Deny,
                ControlDecisionReason::KernelDeny,
                None,
            ),
            DecisionOutcome::Allow => {
                let matching = state
                    .grants
                    .iter()
                    .filter_map(|((scope, grant_id), snapshot)| {
                        (scope == &stored.scope()
                            && validate_current_grant(&active, snapshot, now).is_ok()
                            && control_grant_allows(&snapshot.registration.grant, &stored.proposal))
                        .then_some(*grant_id)
                    })
                    .collect::<Vec<_>>();
                match matching.as_slice() {
                    [] => (
                        ControlKernelOutcome::Allow,
                        ControlOutcome::Deny,
                        ControlDecisionReason::GrantUnavailable,
                        None,
                    ),
                    [grant_id] => (
                        ControlKernelOutcome::Allow,
                        ControlOutcome::Allow,
                        ControlDecisionReason::ControlAllow,
                        Some(*grant_id),
                    ),
                    _ => {
                        return Err(StateError::InvalidRecord(
                            "multiple current grants exist in the mono-grant control profile"
                                .to_owned(),
                        ));
                    }
                }
            }
        };
        let decision_id = derive_control_decision_id(
            stored.state_instance_id,
            stored.submission_id,
            stored.evaluation_nonce,
        );
        let evaluation_id = derive_control_evaluation_id(
            stored.state_instance_id,
            stored.submission_id,
            stored.evaluation_nonce,
        );
        let receipt = ControlDecisionReceipt::new(
            decision_id,
            stored.submission_id,
            Some(kernel_outcome),
            control_outcome,
            reason,
            selected_grant_id,
            now,
        );
        let evaluation_commitment = control_evaluation_commitment(
            evaluation_id,
            stored.submission_id,
            claim.claim_id,
            &scope,
            signed_evaluation,
            evaluator,
        )?;
        let decision_commitment = control_decision_commitment(claim.claim_id, &scope, &receipt)?;
        if state.control_decisions.contains_key(&stored.submission_id)
            || state.control_by_decision_id.contains_key(&decision_id)
            || state
                .control_by_evaluation_commitment
                .contains_key(&evaluation_commitment)
            || state
                .control_by_decision_commitment
                .contains_key(&decision_commitment)
        {
            return Err(StateError::ControlDecisionMismatch);
        }
        state.control_decisions.insert(
            stored.submission_id,
            StoredControlDecision {
                receipt: receipt.clone(),
                evaluation_id: Some(evaluation_id),
                evaluation_commitment: Some(evaluation_commitment),
                decision_commitment,
                signed_evaluation: Some(signed_evaluation.clone()),
                evaluator_key_id: Some(evaluator.key_id().to_owned()),
                evaluator_public_key: Some(evaluator.public_key_bytes()),
            },
        );
        state
            .control_by_decision_id
            .insert(decision_id, stored.submission_id);
        state
            .control_by_evaluation_commitment
            .insert(evaluation_commitment, stored.submission_id);
        state
            .control_by_decision_commitment
            .insert(decision_commitment, stored.submission_id);
        let next_phase = if control_outcome == ControlOutcome::Allow {
            ControlWorkPhase::Issue
        } else {
            ControlWorkPhase::Done
        };
        let status_code = if control_outcome == ControlOutcome::Allow {
            ControlStatusCode::Authorized
        } else if control_outcome == ControlOutcome::Manual {
            ControlStatusCode::ManualResolutionRequired
        } else {
            ControlStatusCode::ControlDenied
        };
        memory_push_control_status(
            &mut state,
            stored.submission_id,
            stored.receipt_id,
            status_code,
            Some(ControlStatusReason::Decision(reason)),
            now,
        )?;
        let queue = state
            .control_queue
            .get_mut(&stored.submission_id)
            .ok_or(StateError::ControlWorkNotFound)?;
        queue.phase = next_phase;
        queue.active_claim_id = None;
        let claim = state
            .control_claims
            .get_mut(&claim.claim_id)
            .ok_or(StateError::ControlWorkNotFound)?;
        claim.completed = true;
        claim.completed_at = Some(now);
        // Signed kernel evaluation is a successful phase completion. Only the
        // pre-kernel fail-closed path uses `finalized_decision`; exact retry of a
        // signed evaluation therefore recovers inert `PhaseCompleted` history.
        Ok(receipt)
    })();
    finish_memory_control_scope_transaction(&mut state, savepoint, &stored, now, result)
}

fn memory_control_issuance_snapshot(
    store: &InMemoryStore,
    work: &ControlIssuanceWork,
) -> Result<IssuanceSnapshot, StateError> {
    let mut state = store.inner.lock();
    let now = store.clock.now_unix_seconds()?;
    let claim = memory_validate_control_lease(
        &mut state,
        store.state_instance_id,
        &work.lease,
        ControlWorkPhase::Issue,
        now,
    )?;
    let stored = state
        .control_submissions
        .get(&claim.submission_id)
        .cloned()
        .ok_or(StateError::ControlSubmissionMismatch)?;
    stored.reverify_frozen_wire()?;
    let decision = state
        .control_decisions
        .get(&stored.submission_id)
        .cloned()
        .ok_or(StateError::ControlDecisionMismatch)?;
    if decision.receipt.decision_id() != work.decision_id
        || decision.receipt.control_outcome() != ControlOutcome::Allow
        || decision.receipt.selected_grant_id() != Some(work.selected_grant_id)
        || decision.signed_evaluation.as_ref() != Some(&work.signed_evaluation)
        || work.scope != stored.scope()
        || work.proposal != stored.proposal
    {
        return Err(StateError::ControlWorkMismatch);
    }
    let active = state
        .authorities
        .get(&stored.scope())
        .cloned()
        .ok_or(StateError::AuthorityNotInitialized)?;
    let high_water = memory_control_high_water(&state, &stored)?;
    if now < high_water || now < stored.accepted_at {
        return Err(StateError::ClockRollback {
            observed: now,
            high_water: high_water.max(stored.accepted_at),
        });
    }
    if active != work.signed_evaluation.attestation.authority
        || active.principal_registry != stored.ingress_authority_domain
    {
        return Err(StateError::AuthorityMismatch);
    }
    if now >= stored.ingress_expires_at || now >= work.signed_evaluation.attestation.consume_before
    {
        memory_advance_control_high_water(&mut state, &stored, now)?;
        return Err(StateError::AuthorizationExpired {
            observed: now,
            consume_before: work.signed_evaluation.attestation.consume_before,
        });
    }
    let grant = state
        .grants
        .get(&(stored.scope(), work.selected_grant_id))
        .cloned()
        .ok_or(StateError::GrantNotFound)?;
    match validate_current_grant(&active, &grant, now) {
        Ok(()) => {}
        Err(error) if is_temporal_rejection_for_sample(&error, now) => {
            memory_advance_control_high_water(&mut state, &stored, now)?;
            return Err(error);
        }
        Err(error) => return Err(error),
    }
    if !control_grant_allows(&grant.registration.grant, &stored.proposal) {
        return Err(StateError::GrantMismatch);
    }
    memory_advance_control_high_water(&mut state, &stored, now)?;
    Ok(IssuanceSnapshot::new(
        stored.scope(),
        grant.registration,
        work.lease.claimed_at,
    ))
}

// Ownership transfer is the one-shot API guarantee; keep the value parameter.
#[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
fn memory_record_and_link_control_issuance(
    store: &InMemoryStore,
    work: ControlIssuanceWork,
    issued: &IssuedAuthorizationRecord,
) -> Result<ControlIssuanceCommitOutcome, StateError> {
    issued.validate()?;
    let mut state = store.inner.lock();
    if let Some(completed_claim) = state.control_claims.get(&work.lease.claim_id)
        && memory_control_claim_matches_lease(
            completed_claim,
            store.state_instance_id,
            &work.lease,
            ControlWorkPhase::Issue,
        )
        && completed_claim.completed
    {
        if let Some(finalized) = &completed_claim.finalized_work {
            return memory_validate_control_work_finalized(&state, completed_claim, finalized)
                .map(ControlIssuanceCommitOutcome::Finalized);
        }
        memory_control_phase_completed(&state, completed_claim)?;
        let existing = state
            .control_issuances
            .get(&completed_claim.submission_id)
            .ok_or_else(|| invalid_control_lineage("completed ISSUE artifact is missing"))?;
        if existing != issued
            || state
                .authorizations
                .get(&(existing.scope(), existing.authorization().authorization_id))
                != Some(existing)
            || state
                .transactions
                .get(&(existing.scope(), existing.transaction_id))
                != Some(&existing.authorization().authorization_id)
        {
            return Err(StateError::InvalidRecord(
                "completed ISSUE retry has incomplete durable lineage".to_owned(),
            ));
        }
        return Ok(ControlIssuanceCommitOutcome::Recovered);
    }
    let now = store.clock.now_unix_seconds()?;
    let claim = memory_validate_control_lease(
        &mut state,
        store.state_instance_id,
        &work.lease,
        ControlWorkPhase::Issue,
        now,
    )?;
    let stored = state
        .control_submissions
        .get(&claim.submission_id)
        .cloned()
        .ok_or(StateError::ControlSubmissionMismatch)?;
    memory_control_structural_preflight(&state, stored.submission_id, ControlWorkPhase::Issue)?;
    let high_water = memory_control_high_water(&state, &stored)?;
    if now < high_water || now < stored.accepted_at {
        return Err(StateError::ClockRollback {
            observed: now,
            high_water: high_water.max(stored.accepted_at),
        });
    }
    let savepoint = MemoryControlSavepoint::capture(&state);
    let result = (|| {
        memory_advance_control_high_water(&mut state, &stored, now)?;
        match memory_control_preflight(&mut state, claim.claim_id, now)? {
            MemoryControlPreflight::Ready => {}
            MemoryControlPreflight::WorkFinalized(receipt) => {
                return Ok(ControlIssuanceCommitOutcome::Finalized(receipt));
            }
            MemoryControlPreflight::DecisionFinalized(_) => {
                return Err(StateError::ControlWorkMismatch);
            }
        }
        let decision = state
            .control_decisions
            .get(&stored.submission_id)
            .cloned()
            .ok_or(StateError::ControlDecisionMismatch)?;
        let evaluation = &work.signed_evaluation.attestation;
        let active = state
            .authorities
            .get(&stored.scope())
            .cloned()
            .ok_or(StateError::AuthorityNotInitialized)?;
        let grant = state
            .grants
            .get(&(stored.scope(), work.selected_grant_id))
            .cloned()
            .ok_or(StateError::GrantNotFound)?;
        if decision.receipt.decision_id() != work.decision_id
            || decision.receipt.control_outcome() != ControlOutcome::Allow
            || decision.receipt.selected_grant_id() != Some(work.selected_grant_id)
            || decision.signed_evaluation.as_ref() != Some(&work.signed_evaluation)
            || work.scope != stored.scope()
            || work.proposal != stored.proposal
            || issued.scope() != stored.scope()
            || issued.authorization().request_id != stored.proposal.request_id
            || issued.authorization().evaluation_nonce != stored.evaluation_nonce
            || issued.authorization().tenant != stored.tenant
            || issued.authorization().holder != stored.actor
            || issued.authorization().template != stored.proposal.template
            || issued.authorization().grant_id != work.selected_grant_id
            || issued.authorization().issued_at != work.lease.claimed_at
            || issued.authorization().not_before != work.lease.claimed_at
            || issued.authorization().consume_before
                != evaluation
                    .consume_before
                    .min(grant.registration.grant.expires_at)
            || issued.authorization().template_hash != evaluation.template_hash
            || issued.authorization().evidence_root != evaluation.evidence_root
            || issued.authorization().principals != evaluation.principals
            || issued.authorization().policy_root != evaluation.policy_root
            || issued.authorization().authority != evaluation.authority
            || evaluation.authority != active
        {
            return Err(StateError::ControlDecisionMismatch);
        }
        validate_current_grant(&active, &grant, now)?;
        validate_grant_for_authorization(&grant.registration, issued.authorization())?;
        let authorization_key = (stored.scope(), issued.authorization().authorization_id);
        let transaction_key = (stored.scope(), issued.transaction_id);
        match (
            state.control_issuances.get(&stored.submission_id),
            state.authorizations.get(&authorization_key),
            state.transactions.get(&transaction_key),
        ) {
            (Some(_), Some(_), Some(_)) => {
                return Err(StateError::InvalidRecord(
                    "complete ISSUE tuple exists while its claim is still active".to_owned(),
                ));
            }
            (Some(_), _, _) => {
                return Err(StateError::InvalidRecord(
                    "partial control issuance/authorization/transaction tuple exists".to_owned(),
                ));
            }
            (None, None, None) => {}
            (None, _, _) => return Err(StateError::AuthorizationAlreadyExists),
        }
        state
            .transactions
            .insert(transaction_key, issued.authorization().authorization_id);
        state
            .authorizations
            .insert(authorization_key, issued.clone());
        state
            .control_issuances
            .insert(stored.submission_id, issued.clone());
        memory_push_control_status(
            &mut state,
            stored.submission_id,
            stored.receipt_id,
            ControlStatusCode::AuthorizationIssued,
            Some(ControlStatusReason::Decision(
                ControlDecisionReason::ControlAllow,
            )),
            now,
        )?;
        let queue = state
            .control_queue
            .get_mut(&stored.submission_id)
            .ok_or(StateError::ControlWorkNotFound)?;
        queue.phase = ControlWorkPhase::Consume;
        queue.active_claim_id = None;
        state
            .control_claims
            .get_mut(&claim.claim_id)
            .ok_or(StateError::ControlWorkNotFound)?
            .completed = true;
        state
            .control_claims
            .get_mut(&claim.claim_id)
            .ok_or(StateError::ControlWorkNotFound)?
            .completed_at = Some(now);
        Ok(ControlIssuanceCommitOutcome::Committed)
    })();
    finish_memory_control_scope_transaction(&mut state, savepoint, &stored, now, result)
}

// Ownership transfer is the one-shot API guarantee; keep the value parameter.
#[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
fn memory_consume_and_link_control(
    store: &InMemoryStore,
    work: ControlConsumptionWork,
) -> Result<ControlConsumptionCommitOutcome, StateError> {
    let mut state = store.inner.lock();
    if let Some(completed_claim) = state.control_claims.get(&work.lease.claim_id)
        && memory_control_claim_matches_lease(
            completed_claim,
            store.state_instance_id,
            &work.lease,
            ControlWorkPhase::Consume,
        )
        && completed_claim.completed
    {
        if let Some(finalized) = &completed_claim.finalized_work {
            return memory_validate_control_work_finalized(&state, completed_claim, finalized)
                .map(ControlConsumptionCommitOutcome::Finalized);
        }
        let completion = memory_control_phase_completed(&state, completed_claim)?;
        if completion.consume_key() != Some(&work.consume_key) {
            return Err(StateError::ControlWorkMismatch);
        }
        let success = state
            .control_consumptions
            .get(&completed_claim.submission_id)
            .cloned()
            .ok_or_else(|| invalid_control_lineage("completed CONSUME artifact is missing"))?;
        return Ok(ControlConsumptionCommitOutcome::Recovered(success));
    }
    let now = store.clock.now_unix_seconds()?;
    let claim = memory_validate_control_lease(
        &mut state,
        store.state_instance_id,
        &work.lease,
        ControlWorkPhase::Consume,
        now,
    )?;
    let stored = state
        .control_submissions
        .get(&claim.submission_id)
        .cloned()
        .ok_or(StateError::ControlSubmissionMismatch)?;
    memory_control_structural_preflight(&state, stored.submission_id, ControlWorkPhase::Consume)?;
    if work.consume_key.scope != stored.scope() {
        return Err(StateError::ControlWorkMismatch);
    }
    let issued = state
        .control_issuances
        .get(&stored.submission_id)
        .cloned()
        .ok_or(StateError::AuthorizationNotFound)?;
    if work.consume_key.transaction_id != issued.transaction_id
        || work.consume_key.authorization_id != issued.authorization().authorization_id
    {
        return Err(StateError::ControlWorkMismatch);
    }
    let high_water = memory_control_high_water(&state, &stored)?;
    if now < high_water || now < stored.accepted_at {
        return Err(StateError::ClockRollback {
            observed: now,
            high_water: high_water.max(stored.accepted_at),
        });
    }
    let authorization_key = (stored.scope(), issued.authorization().authorization_id);
    match (
        state.receipts.get(&authorization_key).cloned(),
        state.outbox.get(&authorization_key).cloned(),
    ) {
        (Some(_), Some(_)) => {
            return Err(StateError::InvalidRecord(
                "receipt/outbox exists outside atomic control consumption".to_owned(),
            ));
        }
        (None, None) => {}
        _ => {
            return Err(StateError::InvalidRecord(
                "partial consumption/outbox tuple exists".to_owned(),
            ));
        }
    }
    if state
        .control_consumptions
        .contains_key(&stored.submission_id)
    {
        return Err(StateError::InvalidRecord(
            "partial control consumption tuple exists".to_owned(),
        ));
    }
    let savepoint = MemoryControlSavepoint::capture(&state);
    let result = (|| {
        memory_advance_control_high_water(&mut state, &stored, now)?;
        match memory_control_preflight(&mut state, claim.claim_id, now)? {
            MemoryControlPreflight::Ready => {}
            MemoryControlPreflight::WorkFinalized(receipt) => {
                return Ok(ControlConsumptionCommitOutcome::Finalized(receipt));
            }
            MemoryControlPreflight::DecisionFinalized(_) => {
                return Err(StateError::ControlWorkMismatch);
            }
        }
        let active = state
            .authorities
            .get(&stored.scope())
            .cloned()
            .ok_or(StateError::AuthorityNotInitialized)?;
        let grant_key = (stored.scope(), issued.authorization().grant_id);
        let grant = state
            .grants
            .get(&grant_key)
            .cloned()
            .ok_or(StateError::GrantNotFound)?;
        let dispatch_deadline =
            validate_consumption(&active, &grant, &issued, now, Some(high_water))?;
        let receipt = ConsumptionReceipt {
            schema_version: issued.authorization().schema_version,
            transaction_id: issued.transaction_id,
            authorization_id: issued.authorization().authorization_id,
            consumed_at: now,
            dispatch_deadline,
            authority: active,
            authorization_hash: issued.authorization_hash,
        };
        let outbox = OutboxEntry {
            scope: stored.scope(),
            transaction_id: issued.transaction_id,
            authorization_id: issued.authorization().authorization_id,
            dispatch_deadline,
            status: OutboxStatus::PendingWitness,
            receipt: receipt.clone(),
        };
        let mutable_grant = state
            .grants
            .get_mut(&grant_key)
            .ok_or(StateError::GrantNotFound)?;
        mutable_grant.uses = mutable_grant
            .uses
            .checked_add(1)
            .ok_or(StateError::GrantExhausted)?;
        state
            .receipts
            .insert(authorization_key.clone(), receipt.clone());
        state.outbox.insert(authorization_key, outbox.clone());
        let success = ConsumeSuccess::new(receipt, outbox, issued.clone());
        memory_advance_control_high_water(&mut state, &stored, now)?;
        state
            .control_consumptions
            .insert(stored.submission_id, success.clone());
        memory_push_control_status(
            &mut state,
            stored.submission_id,
            stored.receipt_id,
            ControlStatusCode::DispatchPending,
            Some(ControlStatusReason::Decision(
                ControlDecisionReason::ControlAllow,
            )),
            now,
        )?;
        let queue = state
            .control_queue
            .get_mut(&stored.submission_id)
            .ok_or(StateError::ControlWorkNotFound)?;
        queue.phase = ControlWorkPhase::Done;
        queue.active_claim_id = None;
        state
            .control_claims
            .get_mut(&claim.claim_id)
            .ok_or(StateError::ControlWorkNotFound)?
            .completed = true;
        state
            .control_claims
            .get_mut(&claim.claim_id)
            .ok_or(StateError::ControlWorkNotFound)?
            .completed_at = Some(now);
        Ok(ControlConsumptionCommitOutcome::Committed(success))
    })();
    finish_memory_control_scope_transaction(&mut state, savepoint, &stored, now, result)
}

impl ControlPlaneState for InMemoryStore {
    fn control_recovery_verifier(
        &self,
        probe: &IngressRecoveryProbe,
    ) -> Result<Option<FrozenIngressVerifier>, StateError> {
        let state = self.inner.lock();
        let Some(submission_id) = state
            .control_by_payload_commitment
            .get(&probe.canonical_payload_commitment())
        else {
            return Ok(None);
        };
        let stored = state
            .control_submissions
            .get(submission_id)
            .ok_or(StateError::ControlSubmissionMismatch)?;
        stored.validate()?;
        if stored.replay_scope != probe.claims().audience
            || stored.key_id != probe.key_id()
            || stored.nonce != probe.claims().nonce
            || stored.canonical_payload_commitment != probe.canonical_payload_commitment()
        {
            return Err(StateError::ControlSubmissionMismatch);
        }
        stored.frozen_verifier().map(Some)
    }

    fn recover_control_submission(
        &self,
        verified: &VerifiedHistoricalIngress,
    ) -> Result<RecoveredSubmissionRef, StateError> {
        let state = self.inner.lock();
        let submission_id = state
            .control_by_payload_commitment
            .get(&verified.canonical_payload_commitment())
            .ok_or(StateError::ControlSubmissionNotFound)?;
        let stored = state
            .control_submissions
            .get(submission_id)
            .ok_or(StateError::ControlSubmissionMismatch)?;
        stored.matches_historical(verified)?;
        memory_control_recovered(&state, stored)
    }

    #[allow(clippy::too_many_lines)]
    fn accept_control_submission_or_recover(
        &self,
        verified: StaticallyVerifiedIngressSubmission,
    ) -> Result<ControlSubmissionIntakeOutcome, StateError> {
        let canonical_payload_commitment = verified.canonical_payload_commitment();
        let mut state = self.inner.lock();

        // Exact committed recovery precedes every currentness and clock check.
        if let Some(submission_id) = state
            .control_by_payload_commitment
            .get(&canonical_payload_commitment)
        {
            let stored = state
                .control_submissions
                .get(submission_id)
                .ok_or(StateError::ControlSubmissionMismatch)?;
            if stored.key_id != verified.key_id()
                || stored.nonce != verified.nonce()
                || stored.proposal != *verified.proposal()
            {
                return Err(StateError::ControlSubmissionMismatch);
            }
            return memory_control_recovered(&state, stored)
                .map(ControlSubmissionIntakeOutcome::Recovered);
        }

        let scope = Scope::new(
            verified.caller().tenant(),
            &verified.proposal().template.environment,
        )?;
        let active = state
            .authorities
            .get(&scope)
            .cloned()
            .ok_or(StateError::AuthorityNotInitialized)?;
        // A self-activated registry or rotated registry never advances either
        // HWM. The active rooted domain is the state-owned trust anchor.
        if &active.principal_registry != verified.authority_domain() {
            return Err(StateError::AuthorityMismatch);
        }
        if state
            .control_by_request
            .contains_key(&(scope.clone(), verified.proposal().request_id))
        {
            return Err(StateError::ControlRequestConflict);
        }
        // A v13 submission must not retroactively claim ownership of an
        // already-materialized profile-v2 authorization. Such a collision is
        // structural and therefore remains inert with respect to both HWMs.
        let prospective_evaluation_nonce = StoredControlSubmission::prospective_evaluation_nonce(
            self.state_instance_id,
            &verified,
        );
        if state.authorizations.values().any(|issued| {
            (issued.scope() == scope
                && issued.authorization().request_id == verified.proposal().request_id)
                || issued.authorization().evaluation_nonce == prospective_evaluation_nonce
        }) {
            return Err(StateError::ControlRequestConflict);
        }

        let replay_scope = IngressReplayScope::new(verified.replay_scope().as_str())?;
        let ingress_high_water = state
            .ingress_replay_high_water
            .get(&replay_scope)
            .copied()
            .unwrap_or(0);
        let scope_high_water = state.high_water.get(&scope).copied().unwrap_or(0);
        // The trusted clock is sampled only after the global memory lock and
        // both exact HWM domains have been located.
        let observed = self.clock.now_unix_seconds()?;
        let high_water = ingress_high_water.max(scope_high_water);
        if observed < high_water {
            return Err(StateError::ClockRollback {
                observed,
                high_water,
            });
        }

        let temporal_error =
            if observed < verified.key_not_before() || observed >= verified.key_expires_at() {
                Some(StateError::ControlIngressKeyNotCurrent { observed })
            } else if observed < verified.claims().issued_at {
                Some(StateError::ControlIngressNotYetValid {
                    observed,
                    not_before: verified.claims().issued_at,
                })
            } else if observed >= verified.expires_at() {
                Some(StateError::ControlIngressExpired {
                    observed,
                    expires_at: verified.expires_at(),
                })
            } else {
                None
            };
        if let Some(error) = temporal_error {
            state
                .ingress_replay_high_water
                .insert(replay_scope, observed);
            state.high_water.insert(scope, observed);
            return Err(error);
        }

        let replay_key = (
            replay_scope.clone(),
            verified.key_id().to_owned(),
            verified.nonce(),
        );
        if state.ingress_replay_v13_nonces.contains(&replay_key)
            || state
                .ingress_replay_nonces
                .get(&replay_key)
                .is_some_and(|expiry| *expiry > observed)
        {
            state
                .ingress_replay_high_water
                .insert(replay_scope, observed);
            state.high_water.insert(scope, observed);
            return Err(StateError::ControlNonceAlreadyUsed);
        }

        let stored =
            StoredControlSubmission::from_verified(self.state_instance_id, &verified, observed)?;
        let receipt = stored.receipt();
        let status = ControlStatusSnapshot::new(
            stored.submission_id,
            stored.receipt_id,
            ControlStatusCode::Accepted,
            None,
            1,
            observed,
        );
        let accepted_event_commitment = control_event_commitment(&status)?;
        if state
            .control_submissions
            .contains_key(&stored.submission_id)
            || state.control_by_receipt_id.contains_key(&stored.receipt_id)
            || state
                .control_by_evaluation_nonce
                .contains_key(&stored.evaluation_nonce)
            || state
                .control_by_receipt
                .contains_key(&(scope.clone(), stored.receipt_id))
            || state.control_statuses.contains_key(&stored.submission_id)
            || state.control_events.contains_key(&stored.submission_id)
            || state
                .control_by_event_commitment
                .contains_key(&accepted_event_commitment)
            || state
                .control_event_commitments
                .contains_key(&(stored.submission_id, 1))
            || state.control_queue.contains_key(&stored.submission_id)
            || state.control_decisions.contains_key(&stored.submission_id)
            || state.control_issuances.contains_key(&stored.submission_id)
            || state
                .control_consumptions
                .contains_key(&stored.submission_id)
        {
            return Err(StateError::ControlSubmissionMismatch);
        }
        state
            .ingress_replay_high_water
            .insert(replay_scope.clone(), observed);
        state.high_water.insert(scope.clone(), observed);
        state
            .ingress_replay_nonces
            .insert(replay_key.clone(), stored.ingress_expires_at);
        state.ingress_replay_v13_nonces.insert(replay_key);
        state
            .control_by_payload_commitment
            .insert(stored.canonical_payload_commitment, stored.submission_id);
        state.control_by_request.insert(
            (scope.clone(), stored.proposal.request_id),
            stored.submission_id,
        );
        state
            .control_by_receipt
            .insert((scope, stored.receipt_id), stored.submission_id);
        state
            .control_by_receipt_id
            .insert(stored.receipt_id, stored.submission_id);
        state
            .control_by_evaluation_nonce
            .insert(stored.evaluation_nonce, stored.submission_id);
        state
            .control_statuses
            .insert(stored.submission_id, status.clone());
        state
            .control_events
            .insert(stored.submission_id, vec![status]);
        state
            .control_by_event_commitment
            .insert(accepted_event_commitment, (stored.submission_id, 1));
        state
            .control_event_commitments
            .insert((stored.submission_id, 1), accepted_event_commitment);
        state.control_queue.insert(
            stored.submission_id,
            MemoryControlQueue {
                phase: ControlWorkPhase::Evaluate,
                active_claim_id: None,
            },
        );
        state
            .control_submissions
            .insert(stored.submission_id, stored);
        Ok(ControlSubmissionIntakeOutcome::Fresh(receipt))
    }

    fn claim_next_control_work_or_recover(
        &self,
        request: &ControlWorkClaimRequest,
    ) -> Result<ControlWorkClaimOutcome, StateError> {
        memory_claim_next_control_work(self, request)
    }

    fn record_control_evaluation(
        &self,
        work: ControlEvaluationWork,
        signed_evaluation: &SignedEvaluation,
        evaluator: &CoseVerifier,
    ) -> Result<ControlDecisionReceipt, StateError> {
        memory_record_control_evaluation(self, work, signed_evaluation, evaluator)
    }

    fn control_issuance_snapshot(
        &self,
        work: &ControlIssuanceWork,
    ) -> Result<IssuanceSnapshot, StateError> {
        memory_control_issuance_snapshot(self, work)
    }

    fn record_and_link_control_issuance_or_recover(
        &self,
        work: ControlIssuanceWork,
        issued: &IssuedAuthorizationRecord,
    ) -> Result<ControlIssuanceCommitOutcome, StateError> {
        memory_record_and_link_control_issuance(self, work, issued)
    }

    fn consume_and_link_control_or_recover(
        &self,
        work: ControlConsumptionWork,
    ) -> Result<ControlConsumptionCommitOutcome, StateError> {
        memory_consume_and_link_control(self, work)
    }

    fn control_status(
        &self,
        scope: &Scope,
        receipt_id: Uuid,
    ) -> Result<ControlStatusSnapshot, StateError> {
        scope.validate()?;
        let state = self.inner.lock();
        let submission_id = state
            .control_by_receipt
            .get(&(scope.clone(), receipt_id))
            .ok_or(StateError::ControlStatusNotFound)?;
        let stored = state
            .control_submissions
            .get(submission_id)
            .ok_or(StateError::ControlStatusNotFound)?;
        memory_validate_control_recovery_projection(&state, stored)
    }
}

fn memory_dispatch_acquisition_receipt(
    acquisition: &MemoryDispatchAcquisition,
    disposition: DispatchAcquisitionDisposition,
) -> DispatchAcquisitionReceipt {
    DispatchAcquisitionReceipt::new(
        acquisition.acquisition_id,
        acquisition.lease_fence,
        acquisition.worker_id.clone(),
        acquisition.token.claim_id(),
        acquisition.token.fence(),
        acquisition.acquired_at,
        acquisition.lease_until,
        disposition,
    )
}

fn memory_dispatch_acquisition_authority(
    acquisition: &MemoryDispatchAcquisition,
) -> DispatchAcquisitionAuthority {
    DispatchAcquisitionAuthority::new(
        acquisition.token.clone(),
        acquisition.acquisition_id,
        acquisition.lease_fence,
        acquisition.worker_id.clone(),
        acquisition.acquired_at,
        acquisition.lease_until,
        acquisition.dispatch_deadline,
        acquisition.control_submission_id,
    )
}

fn memory_recovery_acquisition(
    acquisition: &MemoryDispatchAcquisition,
) -> Result<DispatchRecoveryAcquisition, StateError> {
    Ok(DispatchRecoveryAcquisition::new(
        acquisition.acquisition_id,
        acquisition.lease_fence,
        acquisition.worker_id.clone(),
        acquisition.acquired_at,
        acquisition.lease_until,
        acquisition.dispatch_deadline,
        acquisition
            .control_submission_id
            .ok_or(StateError::DispatchAcquisitionMismatch)?,
    ))
}

fn memory_dispatch_artifact_disposition(
    state: &MemoryState,
    acquisition: &MemoryDispatchAcquisition,
) -> Result<Option<DispatchAcquisitionDisposition>, StateError> {
    let key = acquisition.token.key();
    let claim = state
        .dispatch_claims
        .get(&(key.scope.clone(), key.authorization_id))
        .ok_or(StateError::DispatchClaimNotFound)?;
    if claim.token.claim_id() != acquisition.token.claim_id()
        || claim.token.fence() != acquisition.token.fence()
        || claim.token.state_instance_id() != acquisition.token.state_instance_id()
    {
        return Err(StateError::DispatchAcquisitionMismatch);
    }
    if claim.state == MemoryDispatchClaimState::Terminal
        || claim.terminalization_id.is_some()
        || state
            .terminal_retirements
            .contains_key(&(key.scope.clone(), key.authorization_id))
    {
        return Ok(Some(DispatchAcquisitionDisposition::Terminal));
    }
    if claim.state == MemoryDispatchClaimState::RecoveryRetired {
        return Ok(Some(DispatchAcquisitionDisposition::RecoveryRetired));
    }
    if claim.state == MemoryDispatchClaimState::RecoveryNoSend {
        return Ok(Some(DispatchAcquisitionDisposition::RecoveryNoSend));
    }
    if claim.state == MemoryDispatchClaimState::AttemptInFlight
        || claim.attempt_started_at.is_some()
        || claim.attempt_acquisition.is_some()
        || claim.credential.is_some()
    {
        return Ok(Some(DispatchAcquisitionDisposition::AttemptInFlight));
    }
    if state
        .broker_operations
        .keys()
        .any(|(scope, authorization_id, _)| {
            scope == &key.scope && authorization_id == &key.authorization_id
        })
        || state
            .credential_reviews
            .contains_key(&(key.scope.clone(), key.authorization_id))
    {
        return Ok(Some(DispatchAcquisitionDisposition::BrokerArtifactPresent));
    }
    if state
        .admission_transactions
        .contains_key(&(key.scope.clone(), key.transaction_id))
        || state
            .admission_claim_ids
            .contains_key(&acquisition.token.claim_id())
    {
        return Ok(Some(
            DispatchAcquisitionDisposition::AdmissionArtifactPresent,
        ));
    }
    Ok(None)
}

fn memory_control_submission_for_dispatch<'a>(
    state: &'a MemoryState,
    submission_id: Uuid,
    key: &ConsumeKey,
) -> Result<&'a StoredControlSubmission, StateError> {
    let success = state
        .control_consumptions
        .get(&submission_id)
        .ok_or(StateError::ControlWorkMismatch)?;
    if success.outbox().scope != key.scope
        || success.outbox().authorization_id != key.authorization_id
        || success.outbox().transaction_id != key.transaction_id
    {
        return Err(StateError::ControlWorkMismatch);
    }
    validate_memory_control_consumption_lineage_if_owned(
        state,
        key,
        success.issued(),
        success.receipt(),
        success.outbox(),
    )?;
    state
        .control_submissions
        .get(&submission_id)
        .ok_or(StateError::ControlSubmissionMismatch)
}

fn memory_dispatch_snapshot_with_dual_high_water(
    state: &mut MemoryState,
    stored: &StoredControlSubmission,
    key: &ConsumeKey,
    observed_at: i64,
) -> Result<DispatchSnapshot, StateError> {
    let high_water = memory_control_high_water(state, stored)?
        .max(stored.accepted_at)
        .max(
            state
                .receipts
                .get(&(key.scope.clone(), key.authorization_id))
                .ok_or(StateError::ConsumptionNotFound)?
                .consumed_at,
        );
    let result = memory_dispatch_snapshot_at_high_water(state, key, observed_at, Some(high_water));
    let must_persist = result.is_ok()
        || result
            .as_ref()
            .is_err_and(|error| is_temporal_rejection_for_sample(error, observed_at));
    if observed_at >= high_water && must_persist {
        memory_advance_control_high_water(state, stored, observed_at)?;
    }
    result
}

fn memory_dispatch_candidates(
    state: &MemoryState,
    scope: &Scope,
) -> Result<Vec<(Uuid, ConsumeKey)>, StateError> {
    let mut candidates = Vec::new();
    for (submission_id, success) in &state.control_consumptions {
        if let Some(disposition_id) = state.dispatch_disposition_by_submission.get(submission_id) {
            let disposition = state
                .dispatch_dispositions
                .get(disposition_id)
                .ok_or(StateError::DispatchAcquisitionMismatch)?;
            disposition.validate()?;
            if disposition.control_submission_id() != *submission_id {
                return Err(StateError::DispatchAcquisitionMismatch);
            }
            continue;
        }
        let outbox = success.outbox();
        if outbox.status != OutboxStatus::PendingWitness || outbox.scope != *scope {
            continue;
        }
        let key = ConsumeKey {
            scope: outbox.scope.clone(),
            transaction_id: outbox.transaction_id,
            authorization_id: outbox.authorization_id,
        };
        memory_control_submission_for_dispatch(state, *submission_id, &key)?;
        candidates.push((success.receipt().consumed_at, *submission_id, key));
    }
    candidates.sort_by_key(|(consumed_at, submission_id, _)| (*consumed_at, *submission_id));
    Ok(candidates
        .into_iter()
        .map(|(_, submission_id, key)| (submission_id, key))
        .collect())
}

impl TransactionalState for InMemoryStore {
    fn compare_and_activate_authority(
        &self,
        scope: &Scope,
        expected: Option<&AuthorityVector>,
        next: &AuthorityVector,
    ) -> Result<(), StateError> {
        scope.validate()?;
        validate_authority_vector(next)?;
        let mut state = self.inner.lock();
        match (state.authorities.get(scope), expected) {
            (None, None) => {
                state.authorities.insert(scope.clone(), next.clone());
                Ok(())
            }
            (Some(current), Some(expected)) if current == expected => {
                ensure_monotone_authority(current, next)?;
                state.authorities.insert(scope.clone(), next.clone());
                Ok(())
            }
            _ => Err(StateError::AuthorityCompareFailed),
        }
    }

    fn active_authority(&self, scope: &Scope) -> Result<AuthorityVector, StateError> {
        scope.validate()?;
        self.inner
            .lock()
            .authorities
            .get(scope)
            .cloned()
            .ok_or(StateError::AuthorityNotInitialized)
    }

    fn register_grant(&self, grant: &GrantRegistration) -> Result<(), StateError> {
        grant.validate()?;
        let key = (grant.scope(), grant.grant.grant_id);
        let mut state = self.inner.lock();
        let active = state
            .authorities
            .get(&key.0)
            .cloned()
            .ok_or(StateError::AuthorityNotInitialized)?;
        if state.grants.keys().any(|(scope, _)| scope == &key.0) {
            return Err(StateError::GrantAlreadyExists);
        }
        let observed_time = self.clock.now_unix_seconds()?;
        if let Some(high_water) = state.high_water.get(&key.0).copied()
            && observed_time < high_water
        {
            return Err(StateError::ClockRollback {
                observed: observed_time,
                high_water,
            });
        }
        let snapshot = GrantSnapshot {
            registration: grant.clone(),
            uses: 0,
            revoked: false,
        };
        match validate_current_grant(&active, &snapshot, observed_time) {
            Ok(()) => {}
            Err(error) if is_temporal_rejection_for_sample(&error, observed_time) => {
                state.high_water.insert(key.0, observed_time);
                return Err(error);
            }
            Err(error) => return Err(error),
        }
        state.high_water.insert(key.0.clone(), observed_time);
        state.grants.insert(key, snapshot);
        Ok(())
    }

    fn grant_snapshot(&self, scope: &Scope, grant_id: Uuid) -> Result<GrantSnapshot, StateError> {
        scope.validate()?;
        self.inner
            .lock()
            .grants
            .get(&(scope.clone(), grant_id))
            .cloned()
            .ok_or(StateError::GrantNotFound)
    }

    fn issuance_snapshot(
        &self,
        scope: &Scope,
        grant_id: Uuid,
    ) -> Result<IssuanceSnapshot, StateError> {
        scope.validate()?;
        let mut state = self.inner.lock();
        let active = state
            .authorities
            .get(scope)
            .cloned()
            .ok_or(StateError::AuthorityNotInitialized)?;
        let grant = state
            .grants
            .get(&(scope.clone(), grant_id))
            .cloned()
            .ok_or(StateError::GrantNotFound)?;
        let observed_time = self.clock.now_unix_seconds()?;
        if let Some(high_water) = state.high_water.get(scope).copied()
            && observed_time < high_water
        {
            return Err(StateError::ClockRollback {
                observed: observed_time,
                high_water,
            });
        }
        match validate_current_grant(&active, &grant, observed_time) {
            Ok(()) => {}
            Err(error) if is_temporal_rejection_for_sample(&error, observed_time) => {
                state.high_water.insert(scope.clone(), observed_time);
                return Err(error);
            }
            Err(error) => return Err(error),
        }
        state.high_water.insert(scope.clone(), observed_time);
        Ok(IssuanceSnapshot::new(
            scope.clone(),
            grant.registration,
            observed_time,
        ))
    }

    fn revoke_grant(
        &self,
        scope: &Scope,
        grant_id: Uuid,
        expected_authority: &AuthorityVector,
        next_authority: &AuthorityVector,
    ) -> Result<(), StateError> {
        scope.validate()?;
        let mut state = self.inner.lock();
        let active = state
            .authorities
            .get(scope)
            .ok_or(StateError::AuthorityNotInitialized)?;
        if active != expected_authority {
            return Err(StateError::AuthorityCompareFailed);
        }
        validate_revocation_transition(grant_id, expected_authority, next_authority)?;
        let grant = state
            .grants
            .get_mut(&(scope.clone(), grant_id))
            .ok_or(StateError::GrantNotFound)?;
        grant.revoked = true;
        state
            .authorities
            .insert(scope.clone(), next_authority.clone());
        Ok(())
    }

    fn record_issued_authorization(
        &self,
        record: &IssuedAuthorizationRecord,
    ) -> Result<(), StateError> {
        record.validate()?;
        let scope = record.scope();
        scope.validate()?;

        let mut state = self.inner.lock();
        if state
            .control_by_request
            .contains_key(&(scope.clone(), record.authorization().request_id))
            || state
                .control_by_evaluation_nonce
                .contains_key(&record.authorization().evaluation_nonce)
        {
            return Err(StateError::ControlWorkMismatch);
        }
        let active = state
            .authorities
            .get(&scope)
            .cloned()
            .ok_or(StateError::AuthorityNotInitialized)?;
        if active != record.signed_authorization.authorization.authority {
            return Err(StateError::AuthorityMismatch);
        }
        let grant = state
            .grants
            .get(&(
                scope.clone(),
                record.signed_authorization.authorization.grant_id,
            ))
            .cloned()
            .ok_or(StateError::GrantNotFound)?;
        validate_grant_for_authorization(
            &grant.registration,
            &record.signed_authorization.authorization,
        )?;
        let authorization_key = (
            scope.clone(),
            record.signed_authorization.authorization.authorization_id,
        );
        let transaction_key = (scope.clone(), record.transaction_id);
        if state.authorizations.contains_key(&authorization_key)
            || state.transactions.contains_key(&transaction_key)
        {
            return Err(StateError::AuthorizationAlreadyExists);
        }

        let observed_time = self.clock.now_unix_seconds()?;
        if let Some(high_water) = state.high_water.get(&scope).copied()
            && observed_time < high_water
        {
            return Err(StateError::ClockRollback {
                observed: observed_time,
                high_water,
            });
        }
        match validate_current_grant(&active, &grant, observed_time) {
            Ok(()) => {}
            Err(error) if is_temporal_rejection_for_sample(&error, observed_time) => {
                state.high_water.insert(scope, observed_time);
                return Err(error);
            }
            Err(error) => return Err(error),
        }
        if record.signed_authorization.authorization.issued_at > observed_time
            || observed_time >= record.signed_authorization.authorization.consume_before
        {
            let error = StateError::AuthorizationExpired {
                observed: observed_time,
                consume_before: record.signed_authorization.authorization.consume_before,
            };
            state.high_water.insert(scope, observed_time);
            return Err(error);
        }

        state.high_water.insert(scope, observed_time);
        state.transactions.insert(
            transaction_key,
            record.signed_authorization.authorization.authorization_id,
        );
        state
            .authorizations
            .insert(authorization_key, record.clone());
        Ok(())
    }

    fn consume(&self, key: &ConsumeKey) -> Result<ConsumeSuccess, StateError> {
        key.validate()?;
        let mut state = self.inner.lock();
        let authorization_key = (key.scope.clone(), key.authorization_id);
        let issued = state
            .authorizations
            .get(&authorization_key)
            .cloned()
            .ok_or(StateError::AuthorizationNotFound)?;
        if issued.transaction_id != key.transaction_id {
            return Err(StateError::TransactionMismatch);
        }
        let indexed_authorization_id = state
            .transactions
            .get(&(key.scope.clone(), key.transaction_id))
            .ok_or(StateError::AuthorizationNotFound)?;
        if indexed_authorization_id != &key.authorization_id {
            return Err(StateError::TransactionMismatch);
        }
        if state
            .control_by_request
            .contains_key(&(key.scope.clone(), issued.authorization().request_id))
            || state
                .control_by_evaluation_nonce
                .contains_key(&issued.authorization().evaluation_nonce)
            || state.control_issuances.values().any(|control| {
                control.scope() == key.scope
                    && control.authorization().authorization_id == key.authorization_id
                    && control.transaction_id == key.transaction_id
            })
        {
            return Err(StateError::ControlWorkMismatch);
        }
        if state.receipts.contains_key(&authorization_key) {
            return Err(StateError::AlreadyConsumed);
        }

        let active = state
            .authorities
            .get(&key.scope)
            .cloned()
            .ok_or(StateError::AuthorityNotInitialized)?;
        let grant_key = (
            key.scope.clone(),
            issued.signed_authorization.authorization.grant_id,
        );
        let grant = state
            .grants
            .get(&grant_key)
            .cloned()
            .ok_or(StateError::GrantNotFound)?;
        let observed_time = self.clock.now_unix_seconds()?;
        let high_water = state.high_water.get(&key.scope).copied();
        let dispatch_deadline =
            match validate_consumption(&active, &grant, &issued, observed_time, high_water) {
                Ok(deadline) => deadline,
                Err(error) if is_temporal_rejection_for_sample(&error, observed_time) => {
                    state.high_water.insert(key.scope.clone(), observed_time);
                    return Err(error);
                }
                Err(error) => return Err(error),
            };

        let receipt = ConsumptionReceipt {
            schema_version: issued.signed_authorization.authorization.schema_version,
            transaction_id: issued.transaction_id,
            authorization_id: issued.signed_authorization.authorization.authorization_id,
            consumed_at: observed_time,
            dispatch_deadline,
            authority: active,
            authorization_hash: issued.authorization_hash,
        };
        let outbox = OutboxEntry {
            scope: key.scope.clone(),
            transaction_id: issued.transaction_id,
            authorization_id: issued.signed_authorization.authorization.authorization_id,
            dispatch_deadline,
            status: OutboxStatus::PendingWitness,
            receipt: receipt.clone(),
        };

        let mutable_grant = state
            .grants
            .get_mut(&grant_key)
            .ok_or(StateError::GrantNotFound)?;
        mutable_grant.uses = mutable_grant
            .uses
            .checked_add(1)
            .ok_or(StateError::GrantExhausted)?;
        state.high_water.insert(key.scope.clone(), observed_time);
        state
            .receipts
            .insert(authorization_key.clone(), receipt.clone());
        state.outbox.insert(authorization_key, outbox.clone());

        Ok(ConsumeSuccess::new(receipt, outbox, issued))
    }

    fn consume_or_recover(&self, key: &ConsumeKey) -> Result<ConsumeSuccess, StateError> {
        // Recovery is a read-only operation and must remain available for a
        // v13 tuple whose consumption was committed by the combined control
        // transaction. The legacy `consume` path is intentionally barred from
        // creating such a tuple, so try exact inert recovery first.
        match self.recover_exact(key) {
            Ok(success) => return Ok(success),
            Err(StateError::ConsumptionNotFound | StateError::AuthorizationNotFound) => {}
            Err(error) => return Err(error),
        }
        match self.consume(key) {
            Err(StateError::AlreadyConsumed) => match self.recover_exact(key) {
                Err(StateError::ConsumptionNotFound | StateError::AuthorizationNotFound) => {
                    Err(StateError::InvalidRecord(
                        "consumed authorization lacks its exact receipt and outbox tuple"
                            .to_owned(),
                    ))
                }
                result => result,
            },
            result => result,
        }
    }

    fn dispatch_snapshot(&self, key: &ConsumeKey) -> Result<DispatchSnapshot, StateError> {
        key.validate()?;
        let mut state = self.inner.lock();
        // The process-local mutex remains held while trusted time is sampled,
        // the complete tuple is validated, and the accepted high-water mark is
        // committed.
        let observed_time = self.clock.now_unix_seconds()?;
        memory_dispatch_snapshot_with_high_water(&mut state, key, observed_time)
    }

    #[allow(clippy::too_many_lines)]
    fn claim_dispatch(
        &self,
        request: &DispatchClaimRequest,
    ) -> Result<ClaimedDispatch, StateError> {
        request.validate()?;
        let mut state = self.inner.lock();
        let issued = state
            .authorizations
            .get(&(request.key.scope.clone(), request.key.authorization_id))
            .ok_or(StateError::AuthorizationNotFound)?;
        if memory_control_owner_for_authorization(&state, issued)?.is_some() {
            return Err(StateError::DispatchAcquisitionRequired);
        }
        let claim_key = (request.key.scope.clone(), request.key.authorization_id);
        if let Some(existing) = state.dispatch_claims.get(&claim_key) {
            return if existing.token.key() == &request.key
                && existing.token.claim_id() == request.claim_id
                && existing.token.worker_id() == request.worker_id
            {
                Err(StateError::DispatchClaimOutcomeUnknown)
            } else {
                Err(StateError::DispatchAlreadyClaimed)
            };
        }
        if state.dispatch_claim_ids.contains_key(&request.claim_id) {
            return Err(StateError::DispatchAlreadyClaimed);
        }
        if state.dispatch_acquisitions.contains_key(&request.claim_id)
            || state.dispatch_dispositions.contains_key(&request.claim_id)
        {
            return Err(StateError::DispatchAlreadyClaimed);
        }

        let observed_time = self.clock.now_unix_seconds()?;
        let snapshot =
            memory_dispatch_snapshot_with_high_water(&mut state, &request.key, observed_time)?;
        let physical_resource =
            PhysicalResourceKey::from_authorization(snapshot.issued().authorization())?;
        if state.physical_reservations.contains_key(&physical_resource) {
            return Err(StateError::PhysicalResourceAlreadyReserved);
        }
        let lease_cap = observed_time
            .checked_add(DISPATCH_CLAIM_LEASE_SECONDS)
            .ok_or(StateError::DeadlineOverflow)?;
        let lease_until = lease_cap.min(snapshot.receipt().dispatch_deadline);
        if lease_until <= observed_time {
            return Err(StateError::DispatchDeadlineExpired {
                observed: observed_time,
                dispatch_deadline: snapshot.receipt().dispatch_deadline,
            });
        }
        let fence = state
            .next_dispatch_fence
            .checked_add(1)
            .ok_or(StateError::DispatchFenceExhausted)?;
        let lease_fence = state
            .next_dispatch_acquisition_fence
            .checked_add(1)
            .ok_or(StateError::DispatchAcquisitionFenceExhausted)?;
        let control_submission_id =
            memory_control_owner_for_authorization(&state, snapshot.issued())?;
        let token = DispatchClaimToken::new(
            request.key.clone(),
            physical_resource.clone(),
            request.claim_id,
            request.worker_id.clone(),
            fence,
            observed_time,
            lease_until,
            self.state_instance_id,
        );
        state.next_dispatch_fence = fence;
        state.next_dispatch_acquisition_fence = lease_fence;
        state.dispatch_claim_ids.insert(
            request.claim_id,
            (request.key.scope.clone(), request.key.authorization_id),
        );
        state.physical_reservations.insert(
            physical_resource,
            (request.key.scope.clone(), request.key.authorization_id),
        );
        state.dispatch_claims.insert(
            claim_key.clone(),
            MemoryDispatchClaim {
                token: token.clone(),
                state: MemoryDispatchClaimState::Claimed,
                attempt_started_at: None,
                attempt_acquisition: None,
                credential: None,
                credential_review_id: None,
                recovery_safe_after: None,
                recovery_retired_at: None,
                terminalization_id: None,
            },
        );
        state.dispatch_acquisitions.insert(
            request.claim_id,
            MemoryDispatchAcquisition {
                token: token.clone(),
                acquisition_id: request.claim_id,
                lease_fence,
                worker_id: request.worker_id.clone(),
                acquired_at: observed_time,
                lease_until,
                dispatch_deadline: snapshot.receipt().dispatch_deadline,
                control_submission_id,
                selection_kind: MemoryDispatchAcquisitionKind::LegacyBootstrap,
            },
        );
        state
            .latest_dispatch_acquisition
            .insert(claim_key, request.claim_id);
        Ok(ClaimedDispatch::new(snapshot, token))
    }

    #[allow(clippy::too_many_lines)]
    fn claim_next_pending_dispatch_or_recover(
        &self,
        scope: &Scope,
        request: &DispatchAcquisitionRequest,
    ) -> Result<DispatchAcquisitionOutcome, StateError> {
        scope.validate()?;
        request.validate()?;
        let mut state = self.inner.lock();

        if let Some(disposition) = state
            .dispatch_dispositions
            .get(&request.acquisition_id())
            .cloned()
        {
            disposition.validate()?;
            if disposition.worker_id() != request.worker_id()
                || disposition.key().scope != *scope
                || disposition.state_instance_id() != self.state_instance_id
                || state
                    .dispatch_disposition_by_submission
                    .get(&disposition.control_submission_id())
                    != Some(&disposition.dispatch_request_id())
            {
                return Err(StateError::DispatchAcquisitionMismatch);
            }
            memory_control_submission_for_dispatch(
                &state,
                disposition.control_submission_id(),
                disposition.key(),
            )?;
            return Ok(DispatchAcquisitionOutcome::Disposed(disposition));
        }

        if let Some(existing) = state
            .dispatch_acquisitions
            .get(&request.acquisition_id())
            .cloned()
        {
            if existing.worker_id != request.worker_id()
                || existing.control_submission_id.is_none()
                || existing.selection_kind != MemoryDispatchAcquisitionKind::ControlQueue
                || existing.token.key().scope != *scope
                || existing.token.state_instance_id() != self.state_instance_id
            {
                return Err(StateError::DispatchAcquisitionMismatch);
            }
            let claim_key = (
                existing.token.key().scope.clone(),
                existing.token.key().authorization_id,
            );
            let submission_id = existing
                .control_submission_id
                .ok_or(StateError::DispatchAcquisitionMismatch)?;
            let stored = memory_control_submission_for_dispatch(
                &state,
                submission_id,
                existing.token.key(),
            )?
            .clone();
            if state
                .outbox
                .get(&claim_key)
                .ok_or(StateError::ConsumptionNotFound)?
                .dispatch_deadline
                != existing.dispatch_deadline
            {
                return Err(StateError::DispatchAcquisitionMismatch);
            }
            let queue_disposition = if let Some(disposition_id) =
                state.dispatch_disposition_by_submission.get(&submission_id)
            {
                let disposition = state
                    .dispatch_dispositions
                    .get(disposition_id)
                    .ok_or(StateError::DispatchAcquisitionMismatch)?;
                disposition.validate()?;
                if disposition.control_submission_id() != submission_id
                    || disposition.key() != existing.token.key()
                {
                    return Err(StateError::DispatchAcquisitionMismatch);
                }
                Some(disposition)
            } else {
                None
            };
            if state.latest_dispatch_acquisition.get(&claim_key) != Some(&existing.acquisition_id) {
                return Ok(DispatchAcquisitionOutcome::Inert(
                    memory_dispatch_acquisition_receipt(
                        &existing,
                        DispatchAcquisitionDisposition::Superseded,
                    ),
                ));
            }
            if queue_disposition.is_some() {
                return Ok(DispatchAcquisitionOutcome::Quarantined(
                    memory_dispatch_acquisition_receipt(
                        &existing,
                        DispatchAcquisitionDisposition::QueueDisposed,
                    ),
                ));
            }
            if let Some(disposition) = memory_dispatch_artifact_disposition(&state, &existing)? {
                return Ok(DispatchAcquisitionOutcome::Quarantined(
                    memory_dispatch_acquisition_receipt(&existing, disposition),
                ));
            }
            let durable_high_water = memory_control_high_water(&state, &stored)?
                .max(stored.accepted_at)
                .max(existing.acquired_at);
            if durable_high_water >= existing.lease_until {
                return Ok(DispatchAcquisitionOutcome::Inert(
                    memory_dispatch_acquisition_receipt(
                        &existing,
                        DispatchAcquisitionDisposition::Expired,
                    ),
                ));
            }
            let observed_at = self.clock.now_unix_seconds()?;
            if observed_at < durable_high_water {
                return Err(StateError::ClockRollback {
                    observed: observed_at,
                    high_water: durable_high_water,
                });
            }
            if observed_at >= existing.lease_until {
                memory_advance_control_high_water(&mut state, &stored, observed_at)?;
                return Ok(DispatchAcquisitionOutcome::Inert(
                    memory_dispatch_acquisition_receipt(
                        &existing,
                        DispatchAcquisitionDisposition::Expired,
                    ),
                ));
            }
            let snapshot = memory_dispatch_snapshot_with_dual_high_water(
                &mut state,
                &stored,
                existing.token.key(),
                observed_at,
            )?;
            if snapshot.receipt().dispatch_deadline != existing.dispatch_deadline {
                return Err(StateError::DispatchAcquisitionMismatch);
            }
            return Ok(DispatchAcquisitionOutcome::Recovered(DispatchWork::new(
                snapshot,
                memory_dispatch_acquisition_authority(&existing),
            )));
        }

        let candidates = memory_dispatch_candidates(&state, scope)?;
        // Recovery work is selected server-side. Discovery of a missing
        // cleanup step is clock/HWM inert; a no-send generation whose DELETE
        // absence is already durable is redelivered only once its rooted
        // retirement margin is logically due, so it cannot starve unrelated
        // physical resources while waiting.
        let mut recovery_clock_sample = None;
        let mut selected_recovery = None;
        for (candidate_index, (_, key)) in candidates.iter().enumerate() {
            let claim_key = (key.scope.clone(), key.authorization_id);
            let Some(claim) = state.dispatch_claims.get(&claim_key) else {
                continue;
            };
            let Some(latest_id) = state.latest_dispatch_acquisition.get(&claim_key) else {
                return Err(StateError::DispatchAcquisitionMismatch);
            };
            let latest = state
                .dispatch_acquisitions
                .get(latest_id)
                .ok_or(StateError::DispatchAcquisitionMismatch)?;
            if latest.token != claim.token
                || !matches!(
                    latest.selection_kind,
                    MemoryDispatchAcquisitionKind::ControlQueue
                        | MemoryDispatchAcquisitionKind::ControlBootstrapV13
                )
            {
                continue;
            }
            let Some(disposition) = memory_dispatch_artifact_disposition(&state, latest)? else {
                continue;
            };
            if !matches!(
                disposition,
                DispatchAcquisitionDisposition::BrokerArtifactPresent
                    | DispatchAcquisitionDisposition::RecoveryNoSend
                    | DispatchAcquisitionDisposition::AttemptInFlight
            ) {
                continue;
            }
            let recovery_key = crate::DispatchAcquisitionRecoveryKey::from_durable_acquisition(
                &key.scope,
                &latest.worker_id,
                latest.acquisition_id,
            )?;
            let actionable = match disposition {
                DispatchAcquisitionDisposition::BrokerArtifactPresent => true,
                DispatchAcquisitionDisposition::AttemptInFlight => {
                    memory_post_attempt_lineage_for_phase(
                        &state,
                        key,
                        MemoryPostAttemptPhase::AttemptInFlight,
                    )?;
                    memory_exact_delete_absence(&state, latest)?.is_none()
                        && !memory_exact_delete_terminal_conflict(&state, latest)?
                }
                DispatchAcquisitionDisposition::RecoveryNoSend => {
                    let lineage = memory_no_send_lineage(&state, &recovery_key)?;
                    if let Some(absent_at) = memory_exact_delete_absence(&state, latest)? {
                        let propagation_safe_after = absent_at
                            .checked_add(
                                lineage
                                    .lifecycle_policy
                                    .deletion_propagation_hard_max_seconds(),
                            )
                            .and_then(|value| {
                                value.checked_add(
                                    lineage.lifecycle_policy.clock_uncertainty_seconds(),
                                )
                            })
                            .ok_or(StateError::DeadlineOverflow)?;
                        let safe_after =
                            claim.recovery_safe_after.unwrap_or(propagation_safe_after);
                        let submission = memory_control_submission_for_dispatch(
                            &state,
                            latest
                                .control_submission_id
                                .ok_or(StateError::DispatchAcquisitionMismatch)?,
                            key,
                        )?;
                        let durable_high_water = memory_control_high_water(&state, submission)?;
                        let observed_at = if let Some(observed_at) = recovery_clock_sample {
                            observed_at
                        } else {
                            let observed_at = self.clock.now_unix_seconds()?;
                            recovery_clock_sample = Some(observed_at);
                            observed_at
                        };
                        observed_at.max(durable_high_water) >= safe_after
                    } else {
                        !(lineage.create.phase == BrokerJournalPhase::Terminal
                            && lineage.create.outcome
                                == Some(BrokerJournalOutcome::CreateConflicting)
                            || lineage.delete.as_ref().is_some_and(|delete| {
                                delete.phase == BrokerJournalPhase::Terminal
                                    && delete.outcome
                                        == Some(BrokerJournalOutcome::DeleteConflicting)
                            }))
                    }
                }
                _ => false,
            };
            if !actionable {
                continue;
            }
            selected_recovery = Some((
                candidate_index,
                DispatchRecoveryWork::new(recovery_key, disposition),
            ));
            break;
        }

        let observed_at = match recovery_clock_sample {
            Some(observed_at) => observed_at,
            None => self.clock.now_unix_seconds()?,
        };
        let mut selected = None;
        for (candidate_index, (submission_id, key)) in candidates.into_iter().enumerate() {
            let stored =
                memory_control_submission_for_dispatch(&state, submission_id, &key)?.clone();
            let dispatch_deadline = state
                .outbox
                .get(&(key.scope.clone(), key.authorization_id))
                .ok_or(StateError::ConsumptionNotFound)?
                .dispatch_deadline;
            let claim_key = (key.scope.clone(), key.authorization_id);
            if let Some(claim) = state.dispatch_claims.get(&claim_key) {
                if claim.state != MemoryDispatchClaimState::Claimed
                    || claim.attempt_started_at.is_some()
                    || claim.credential.is_some()
                    || claim.terminalization_id.is_some()
                {
                    continue;
                }
                let Some(latest_id) = state.latest_dispatch_acquisition.get(&claim_key) else {
                    return Err(StateError::DispatchAcquisitionMismatch);
                };
                let latest = state
                    .dispatch_acquisitions
                    .get(latest_id)
                    .ok_or(StateError::DispatchAcquisitionMismatch)?;
                let takeover_floor = observed_at.max(
                    memory_control_high_water(&state, &stored)?
                        .max(stored.accepted_at)
                        .max(latest.acquired_at),
                );
                if latest.lease_until > takeover_floor
                    || memory_dispatch_artifact_disposition(&state, latest)?.is_some()
                {
                    continue;
                }
            } else {
                let success = state
                    .control_consumptions
                    .get(&submission_id)
                    .ok_or(StateError::ControlWorkMismatch)?;
                let physical =
                    PhysicalResourceKey::from_authorization(success.issued().authorization())?;
                if state.physical_reservations.contains_key(&physical) {
                    continue;
                }
            }
            selected = Some((
                candidate_index,
                submission_id,
                key,
                stored,
                dispatch_deadline,
            ));
            break;
        }
        let Some((selected_index, submission_id, key, stored, dispatch_deadline)) = selected else {
            return Ok(selected_recovery
                .map_or(DispatchAcquisitionOutcome::NoWork, |(_, recovery)| {
                    DispatchAcquisitionOutcome::RecoveryRequired(recovery)
                }));
        };
        if let Some((recovery_index, recovery)) = selected_recovery
            && recovery_index <= selected_index
        {
            return Ok(DispatchAcquisitionOutcome::RecoveryRequired(recovery));
        }

        let success = state
            .control_consumptions
            .get(&submission_id)
            .cloned()
            .ok_or(StateError::ControlWorkMismatch)?;
        let current_authority = state
            .authorities
            .get(&key.scope)
            .cloned()
            .ok_or(StateError::AuthorityNotInitialized)?;
        let grant = state
            .grants
            .get(&(key.scope.clone(), success.issued().authorization().grant_id))
            .cloned()
            .ok_or(StateError::GrantNotFound)?;
        validate_dispatch_immutable_facts(
            &key,
            &grant,
            success.issued(),
            success.receipt(),
            success.outbox(),
        )?;
        let durable_high_water = memory_control_high_water(&state, &stored)?
            .max(stored.accepted_at)
            .max(success.receipt().consumed_at);
        if observed_at < durable_high_water {
            return Err(StateError::ClockRollback {
                observed: observed_at,
                high_water: durable_high_water,
            });
        }
        let disposition_reason = if observed_at >= dispatch_deadline {
            Some(DispatchQueueDispositionReason::DispatchDeadlineExpired)
        } else if current_authority != success.issued().authorization().authority {
            Some(DispatchQueueDispositionReason::AuthorityChanged)
        } else if grant.revoked {
            Some(DispatchQueueDispositionReason::GrantRevoked)
        } else {
            None
        };
        if let Some(reason) = disposition_reason {
            let stable_claim_key = (key.scope.clone(), key.authorization_id);
            let linked_acquisition = state
                .dispatch_claims
                .get(&stable_claim_key)
                .map(|claim| {
                    let acquisition_id = *state
                        .latest_dispatch_acquisition
                        .get(&stable_claim_key)
                        .ok_or(StateError::DispatchAcquisitionMismatch)?;
                    let acquisition = state
                        .dispatch_acquisitions
                        .get(&acquisition_id)
                        .ok_or(StateError::DispatchAcquisitionMismatch)?;
                    if claim.state != MemoryDispatchClaimState::Claimed
                        || claim.attempt_started_at.is_some()
                        || claim.attempt_acquisition.is_some()
                        || claim.credential.is_some()
                        || claim.credential_review_id.is_some()
                        || claim.terminalization_id.is_some()
                        || acquisition.token != claim.token
                        || acquisition.lease_until > observed_at
                        || memory_dispatch_artifact_disposition(&state, acquisition)?.is_some()
                        || state
                            .physical_reservations
                            .get(claim.token.physical_resource())
                            != Some(&stable_claim_key)
                    {
                        return Err(StateError::DispatchAcquisitionMismatch);
                    }
                    Ok((
                        claim.token.claim_id(),
                        claim.token.fence(),
                        acquisition.acquisition_id,
                        acquisition.lease_fence,
                        claim.token.physical_resource().clone(),
                    ))
                })
                .transpose()?;
            let (claim_id, claim_fence, acquisition_id, lease_fence) = linked_acquisition
                .as_ref()
                .map_or((None, None, None, None), |linked| {
                    (
                        Some(linked.0),
                        Some(linked.1),
                        Some(linked.2),
                        Some(linked.3),
                    )
                });
            let receipt = DispatchQueueDispositionReceipt::new(
                request.acquisition_id(),
                request.worker_id().to_owned(),
                submission_id,
                key,
                self.state_instance_id,
                claim_id,
                claim_fence,
                acquisition_id,
                lease_fence,
                reason,
                observed_at,
                dispatch_deadline,
                success.issued().authorization_hash,
                dispatch_grant_fact_commitment(&grant)?,
                dispatch_outbox_fact_commitment(success.outbox())?,
                dispatch_authority_fact_commitment(&success.issued().authorization().authority)?,
                dispatch_authority_fact_commitment(&current_authority)?,
            )?;
            if state
                .dispatch_dispositions
                .contains_key(&request.acquisition_id())
                || state
                    .dispatch_disposition_by_submission
                    .contains_key(&submission_id)
            {
                return Err(StateError::DispatchAcquisitionMismatch);
            }
            memory_advance_control_high_water(&mut state, &stored, observed_at)?;
            if let Some(linked) = linked_acquisition {
                let linked_claim = state
                    .dispatch_claims
                    .get_mut(&stable_claim_key)
                    .ok_or(StateError::DispatchAcquisitionMismatch)?;
                linked_claim.state = MemoryDispatchClaimState::Disposed;
                let removed = state.physical_reservations.remove(&linked.4);
                debug_assert_eq!(removed.as_ref(), Some(&stable_claim_key));
            }
            let prior = state
                .dispatch_dispositions
                .insert(request.acquisition_id(), receipt.clone());
            debug_assert!(prior.is_none());
            let prior = state
                .dispatch_disposition_by_submission
                .insert(submission_id, request.acquisition_id());
            debug_assert!(prior.is_none());
            return Ok(DispatchAcquisitionOutcome::Disposed(receipt));
        }
        let lease_cap = observed_at
            .checked_add(DISPATCH_ACQUISITION_LEASE_SECONDS)
            .ok_or(StateError::DeadlineOverflow)?;
        let lease_until = lease_cap.min(dispatch_deadline);
        if lease_until <= observed_at {
            return Ok(DispatchAcquisitionOutcome::NoWork);
        }
        let lease_fence = state
            .next_dispatch_acquisition_fence
            .checked_add(1)
            .ok_or(StateError::DispatchAcquisitionFenceExhausted)?;
        let claim_key = (key.scope.clone(), key.authorization_id);
        let existing_claim = state.dispatch_claims.get(&claim_key).map(|claim| {
            (
                claim.token.clone(),
                claim.state,
                claim.attempt_started_at,
                claim.credential.is_some(),
                claim.terminalization_id,
            )
        });
        let (token, new_claim_fence) = if let Some((
            token,
            claim_state,
            attempt_started_at,
            has_credential,
            terminalization_id,
        )) = existing_claim
        {
            let latest_id = state
                .latest_dispatch_acquisition
                .get(&claim_key)
                .ok_or(StateError::DispatchAcquisitionMismatch)?;
            let latest = state
                .dispatch_acquisitions
                .get(latest_id)
                .ok_or(StateError::DispatchAcquisitionMismatch)?;
            if claim_state != MemoryDispatchClaimState::Claimed
                || attempt_started_at.is_some()
                || has_credential
                || terminalization_id.is_some()
                || latest.lease_until > observed_at
                || memory_dispatch_artifact_disposition(&state, latest)?.is_some()
            {
                return Ok(DispatchAcquisitionOutcome::NoWork);
            }
            (token, None)
        } else {
            let physical_resource = PhysicalResourceKey::from_authorization(
                state
                    .control_consumptions
                    .get(&submission_id)
                    .ok_or(StateError::ControlWorkMismatch)?
                    .issued()
                    .authorization(),
            )?;
            if state.physical_reservations.contains_key(&physical_resource) {
                return Ok(DispatchAcquisitionOutcome::NoWork);
            }
            let fence = state
                .next_dispatch_fence
                .checked_add(1)
                .ok_or(StateError::DispatchFenceExhausted)?;
            let mut claim_id = Uuid::new_v4();
            while state.dispatch_claim_ids.contains_key(&claim_id)
                || state.dispatch_acquisitions.contains_key(&claim_id)
                || claim_id == request.acquisition_id()
            {
                claim_id = Uuid::new_v4();
            }
            (
                DispatchClaimToken::new(
                    key.clone(),
                    physical_resource,
                    claim_id,
                    request.worker_id().to_owned(),
                    fence,
                    observed_at,
                    lease_until,
                    self.state_instance_id,
                ),
                Some(fence),
            )
        };

        let snapshot =
            memory_dispatch_snapshot_with_dual_high_water(&mut state, &stored, &key, observed_at)?;
        if snapshot.receipt().dispatch_deadline != dispatch_deadline
            || PhysicalResourceKey::from_authorization(snapshot.issued().authorization())?
                != *token.physical_resource()
        {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        if let Some(fence) = new_claim_fence {
            state.next_dispatch_fence = fence;
            state
                .dispatch_claim_ids
                .insert(token.claim_id(), (key.scope.clone(), key.authorization_id));
            state.physical_reservations.insert(
                token.physical_resource().clone(),
                (key.scope.clone(), key.authorization_id),
            );
            state.dispatch_claims.insert(
                claim_key.clone(),
                MemoryDispatchClaim {
                    token: token.clone(),
                    state: MemoryDispatchClaimState::Claimed,
                    attempt_started_at: None,
                    attempt_acquisition: None,
                    credential: None,
                    credential_review_id: None,
                    recovery_safe_after: None,
                    recovery_retired_at: None,
                    terminalization_id: None,
                },
            );
        }
        let acquisition = MemoryDispatchAcquisition {
            // CONTROL_QUEUE request identities are disjoint from the stable
            // claim namespace; equality is reserved for migration/legacy
            // bootstrap generations.
            token: token.clone(),
            acquisition_id: request.acquisition_id(),
            lease_fence,
            worker_id: request.worker_id().to_owned(),
            acquired_at: observed_at,
            lease_until,
            dispatch_deadline,
            control_submission_id: Some(submission_id),
            selection_kind: MemoryDispatchAcquisitionKind::ControlQueue,
        };
        if acquisition.acquisition_id == acquisition.token.claim_id() {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        state.next_dispatch_acquisition_fence = lease_fence;
        state
            .dispatch_acquisitions
            .insert(request.acquisition_id(), acquisition.clone());
        state
            .latest_dispatch_acquisition
            .insert(claim_key, request.acquisition_id());
        Ok(DispatchAcquisitionOutcome::Acquired(DispatchWork::new(
            snapshot,
            memory_dispatch_acquisition_authority(&acquisition),
        )))
    }

    fn revalidate_dispatch_claim(
        &self,
        token: &DispatchClaimToken,
    ) -> Result<DispatchSnapshot, StateError> {
        token.key().validate()?;
        let mut state = self.inner.lock();
        if token.state_instance_id() != self.state_instance_id {
            return Err(StateError::DispatchClaimMismatch);
        }
        let claim = state
            .dispatch_claims
            .get(&(token.key().scope.clone(), token.key().authorization_id))
            .ok_or(StateError::DispatchClaimNotFound)?;
        if claim.token != *token {
            return Err(StateError::DispatchClaimMismatch);
        }
        if state.physical_reservations.get(token.physical_resource())
            != Some(&(token.key().scope.clone(), token.key().authorization_id))
        {
            return Err(StateError::DispatchClaimMismatch);
        }
        if claim.state == MemoryDispatchClaimState::AttemptInFlight {
            return Err(StateError::DispatchAttemptOutcomeUnknown);
        }
        require_memory_bootstrap_acquisition(&state, token)?;
        let observed_time = self.clock.now_unix_seconds()?;
        let snapshot =
            memory_dispatch_snapshot_with_high_water(&mut state, token.key(), observed_time)?;
        if PhysicalResourceKey::from_authorization(snapshot.issued().authorization())?
            != *token.physical_resource()
        {
            return Err(StateError::DispatchClaimMismatch);
        }
        if observed_time >= token.lease_until() {
            return Err(StateError::DispatchClaimLeaseExpired {
                observed: observed_time,
                lease_until: token.lease_until(),
            });
        }
        Ok(snapshot)
    }

    fn revalidate_dispatch_acquisition(
        &self,
        authority: &DispatchAcquisitionAuthority,
    ) -> Result<DispatchSnapshot, StateError> {
        authority.claim().key().validate()?;
        let mut state = self.inner.lock();
        require_memory_control_acquisition(self.state_instance_id, &state, authority)?;
        let observed_at = self.clock.now_unix_seconds()?;
        memory_revalidate_control_acquisition_locked(
            self.state_instance_id,
            &mut state,
            authority,
            observed_at,
        )
        .map(|(snapshot, _)| snapshot)
    }

    fn mark_attempt_in_flight(
        &self,
        token: &DispatchClaimToken,
        credential: DispatchCredentialBinding,
    ) -> Result<AttemptInFlight, StateError> {
        token.key().validate()?;
        if !credential.matches_token(token) {
            return Err(StateError::DispatchClaimMismatch);
        }
        let mut state = self.inner.lock();
        if token.state_instance_id() != self.state_instance_id {
            return Err(StateError::DispatchClaimMismatch);
        }
        let claim_key = (token.key().scope.clone(), token.key().authorization_id);
        let claim = state
            .dispatch_claims
            .get(&claim_key)
            .ok_or(StateError::DispatchClaimNotFound)?;
        if claim.token != *token {
            return Err(StateError::DispatchClaimMismatch);
        }
        if state.physical_reservations.get(token.physical_resource())
            != Some(&(token.key().scope.clone(), token.key().authorization_id))
        {
            return Err(StateError::DispatchClaimMismatch);
        }
        if claim.state == MemoryDispatchClaimState::AttemptInFlight {
            return Err(StateError::DispatchAttemptOutcomeUnknown);
        }
        let acquisition = require_memory_bootstrap_acquisition(&state, token)?.clone();
        let authority = memory_dispatch_acquisition_authority(&acquisition);
        let credential = credential.into_v2(&authority)?;
        let observed_time = self.clock.now_unix_seconds()?;
        let snapshot =
            memory_dispatch_snapshot_with_high_water(&mut state, token.key(), observed_time)?;
        if PhysicalResourceKey::from_authorization(snapshot.issued().authorization())?
            != *token.physical_resource()
        {
            return Err(StateError::DispatchClaimMismatch);
        }
        if observed_time >= token.lease_until() {
            return Err(StateError::DispatchClaimLeaseExpired {
                observed: observed_time,
                lease_until: token.lease_until(),
            });
        }
        if credential.not_before() > observed_time || credential.expires_at() <= observed_time {
            return Err(StateError::DispatchCredentialExpired);
        }
        let claim = state
            .dispatch_claims
            .get_mut(&claim_key)
            .ok_or(StateError::DispatchClaimNotFound)?;
        claim.state = MemoryDispatchClaimState::AttemptInFlight;
        claim.attempt_started_at = Some(observed_time);
        claim.attempt_acquisition = Some(DispatchAttemptAcquisition::from_authority(&authority));
        claim.credential = Some(credential);
        Ok(AttemptInFlight::new(snapshot, authority, observed_time))
    }

    fn mark_dispatch_acquisition_attempt_in_flight(
        &self,
        reviewed: ReviewedDispatchCredential,
    ) -> Result<AttemptInFlight, StateError> {
        let authority = reviewed.stored.authority();
        authority.claim().key().validate()?;
        reviewed.stored.validate()?;
        let review_commitment = reviewed
            .stored
            .review_commitment
            .ok_or(StateError::DispatchCredentialReviewMismatch)?;
        if reviewed.stored.phase != DispatchCredentialReviewPhase::Authenticated
            || !reviewed.binding.matches_review(
                &authority,
                reviewed.stored.review_id,
                review_commitment,
            )
        {
            return Err(StateError::DispatchCredentialReviewMismatch);
        }
        let mut state = self.inner.lock();
        require_memory_control_acquisition(self.state_instance_id, &state, &authority)?;
        let review_key = (
            authority.claim().key().scope.clone(),
            authority.claim().key().authorization_id,
        );
        let durable_review = state
            .credential_reviews
            .get(&review_key)
            .ok_or(StateError::DispatchCredentialReviewNotFound)?;
        if durable_review != &reviewed.stored {
            return Err(StateError::DispatchCredentialReviewMismatch);
        }
        validate_memory_credential_review_frozen_lineage(&state, durable_review)?;
        validate_memory_attempt_broker_lineage(&state, &authority, &reviewed.binding, 2)?;
        let observed_at = self.clock.now_unix_seconds()?;
        let (snapshot, _) = memory_revalidate_control_acquisition_locked(
            self.state_instance_id,
            &mut state,
            &authority,
            observed_at,
        )?;
        if reviewed.binding.not_before() > observed_at
            || reviewed.binding.expires_at() <= observed_at
        {
            return Err(StateError::DispatchCredentialExpired);
        }
        let claim_key = (
            authority.claim().key().scope.clone(),
            authority.claim().key().authorization_id,
        );
        let attempt = AttemptInFlight::new_reviewed(snapshot, authority, &reviewed, observed_at);
        let attempt_acquisition = attempt.acquisition().clone();
        let credential_review_id = reviewed.stored.review_id;
        let credential = reviewed.binding;
        let claim = state
            .dispatch_claims
            .get_mut(&claim_key)
            .ok_or(StateError::DispatchClaimNotFound)?;
        if claim.state != MemoryDispatchClaimState::Claimed
            || claim.attempt_started_at.is_some()
            || claim.attempt_acquisition.is_some()
            || claim.credential.is_some()
            || claim.credential_review_id.is_some()
        {
            return Err(StateError::DispatchAttemptOutcomeUnknown);
        }
        claim.state = MemoryDispatchClaimState::AttemptInFlight;
        claim.attempt_started_at = Some(observed_at);
        claim.attempt_acquisition = Some(attempt_acquisition);
        claim.credential = Some(credential);
        claim.credential_review_id = Some(credential_review_id);
        Ok(attempt)
    }

    fn close_dispatch_acquisition_no_send(
        &self,
        recovery_key: &crate::DispatchAcquisitionRecoveryKey,
    ) -> Result<RecoveryNoSendReceipt, StateError> {
        let mut state = self.inner.lock();
        // Frozen lineage only: no clock, HWM, current authority, or credential
        // currentness participates in this no-send CAS.
        let lineage = memory_no_send_lineage(&state, recovery_key)?;
        let claim_key = (
            lineage.acquisition.token.key().scope.clone(),
            lineage.acquisition.token.key().authorization_id,
        );
        let recovery_acquisition = memory_recovery_acquisition(&lineage.acquisition)?;
        let receipt = RecoveryNoSendReceipt::new(
            lineage.acquisition.token.key().clone(),
            recovery_acquisition,
        );
        let claim = state
            .dispatch_claims
            .get_mut(&claim_key)
            .ok_or(StateError::DispatchClaimNotFound)?;
        match claim.state {
            MemoryDispatchClaimState::Claimed => {
                claim.state = MemoryDispatchClaimState::RecoveryNoSend;
                Ok(receipt)
            }
            MemoryDispatchClaimState::RecoveryNoSend
            | MemoryDispatchClaimState::RecoveryRetired => Ok(receipt),
            _ => Err(StateError::DispatchAttemptOutcomeUnknown),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn retire_recovery_no_send(
        &self,
        recovery_key: &crate::DispatchAcquisitionRecoveryKey,
    ) -> Result<RecoveryNoSendRetirementOutcome, StateError> {
        let mut state = self.inner.lock();
        let lineage = memory_no_send_lineage(&state, recovery_key)?;
        let acquisition = lineage.acquisition;
        let claim_key = (
            acquisition.token.key().scope.clone(),
            acquisition.token.key().authorization_id,
        );
        let claim = state
            .dispatch_claims
            .get(&claim_key)
            .ok_or(StateError::DispatchClaimNotFound)?;
        if claim.token != acquisition.token {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        if !matches!(
            claim.state,
            MemoryDispatchClaimState::RecoveryNoSend | MemoryDispatchClaimState::RecoveryRetired
        ) {
            return Err(StateError::DispatchAttemptOutcomeUnknown);
        }
        let creation_absent_at = if lineage.create.phase == BrokerJournalPhase::ReconcileOnly
            && lineage.create.outcome.is_none()
            && lineage.create.bound_secret_uid.is_none()
            && lineage.create.reconciliation_count > 0
            && lineage.create.last_reconciliation_outcome
                == Some(BrokerJournalOutcome::CreateAbsent)
            && !lineage.has_issue
            && lineage.review.is_none()
            && lineage.delete.is_none()
        {
            Some(
                lineage
                    .create
                    .last_reconciled_at
                    .ok_or(StateError::BrokerOperationMismatch)?,
            )
        } else {
            None
        };
        if let Some(absent_at) = creation_absent_at {
            let recovery_acquisition = memory_recovery_acquisition(&acquisition)?;
            if claim.state == MemoryDispatchClaimState::RecoveryRetired {
                if claim.recovery_safe_after != Some(absent_at)
                    || claim.recovery_retired_at != Some(absent_at)
                {
                    return Err(StateError::DispatchAcquisitionMismatch);
                }
                return Ok(RecoveryNoSendRetirementOutcome::Recovered(
                    RecoveryNoSendRetirementReceipt::new(
                        acquisition.token.key().clone(),
                        recovery_acquisition,
                        absent_at,
                        absent_at,
                    ),
                ));
            }
            if state
                .physical_reservations
                .get(acquisition.token.physical_resource())
                != Some(&claim_key)
            {
                return Err(StateError::DispatchAcquisitionMismatch);
            }
            let receipt = RecoveryNoSendRetirementReceipt::new(
                acquisition.token.key().clone(),
                recovery_acquisition,
                absent_at,
                absent_at,
            );
            let claim = state
                .dispatch_claims
                .get_mut(&claim_key)
                .ok_or(StateError::DispatchClaimNotFound)?;
            if claim.state != MemoryDispatchClaimState::RecoveryNoSend {
                return Err(StateError::DispatchAttemptOutcomeUnknown);
            }
            claim.state = MemoryDispatchClaimState::RecoveryRetired;
            claim.recovery_safe_after = Some(absent_at);
            claim.recovery_retired_at = Some(absent_at);
            state
                .physical_reservations
                .remove(acquisition.token.physical_resource());
            return Ok(RecoveryNoSendRetirementOutcome::Retired(receipt));
        }
        let delete = lineage
            .delete
            .as_ref()
            .ok_or(StateError::BrokerOperationNotFound)?;
        let valid_delete_binding = match acquisition.selection_kind {
            MemoryDispatchAcquisitionKind::ControlQueue => delete.acquisition_binding_version == 2,
            MemoryDispatchAcquisitionKind::ControlBootstrapV13 => {
                matches!(delete.acquisition_binding_version, 1 | 2)
            }
            MemoryDispatchAcquisitionKind::LegacyBootstrap => false,
        };
        if delete.phase != BrokerJournalPhase::Committed
            || delete.outcome != Some(BrokerJournalOutcome::DeleteAbsent)
            || !valid_delete_binding
            || delete.origin_acquisition_id != acquisition.acquisition_id
            || delete.origin_lease_fence != acquisition.lease_fence
            || delete.claim_id != acquisition.token.claim_id()
            || delete.fence != acquisition.token.fence()
            || delete.state_instance_id != acquisition.token.state_instance_id()
            || delete.physical_resource != *acquisition.token.physical_resource()
        {
            return Err(StateError::BrokerOperationMismatch);
        }
        let deletion = state
            .secret_deletion_observations
            .get(&claim_key)
            .ok_or(StateError::BrokerOperationMismatch)?;
        if deletion
            != &StoredSecretDeletionObservation::from_committed_delete(
                delete,
                deletion.observed_at,
            )?
        {
            return Err(StateError::BrokerOperationMismatch);
        }
        let propagation_safe_after = deletion
            .observed_at
            .checked_add(
                lineage
                    .lifecycle_policy
                    .deletion_propagation_hard_max_seconds(),
            )
            .and_then(|value| {
                value.checked_add(lineage.lifecycle_policy.clock_uncertainty_seconds())
            })
            .ok_or(StateError::DeadlineOverflow)?;
        let computed_safe_after = propagation_safe_after;
        // Once a Pending decision has persisted its bound, later durable review
        // transitions must not rewrite the retirement clock.  The stored bound
        // is the byte-stable recovery contract for every subsequent retry.
        let safe_after = claim.recovery_safe_after.unwrap_or(computed_safe_after);
        if state.admission_transactions.contains_key(&(
            acquisition.token.key().scope.clone(),
            acquisition.token.key().transaction_id,
        )) || state.terminal_retirements.contains_key(&claim_key)
        {
            return Err(StateError::DispatchAcquisitionMismatch);
        }

        let recovery_acquisition = memory_recovery_acquisition(&acquisition)?;
        if claim.state == MemoryDispatchClaimState::RecoveryRetired {
            let claim = state
                .dispatch_claims
                .get(&claim_key)
                .ok_or(StateError::DispatchClaimNotFound)?;
            let retired_at = claim
                .recovery_retired_at
                .ok_or(StateError::DispatchAcquisitionMismatch)?;
            if claim.recovery_safe_after != Some(safe_after) || retired_at < safe_after {
                return Err(StateError::DispatchAcquisitionMismatch);
            }
            return Ok(RecoveryNoSendRetirementOutcome::Recovered(
                RecoveryNoSendRetirementReceipt::new(
                    acquisition.token.key().clone(),
                    recovery_acquisition,
                    safe_after,
                    retired_at,
                ),
            ));
        }

        let control_submission = memory_control_submission_for_dispatch(
            &state,
            acquisition
                .control_submission_id
                .ok_or(StateError::DispatchAcquisitionMismatch)?,
            acquisition.token.key(),
        )?
        .clone();
        let observed_at = self.clock.now_unix_seconds()?;
        memory_advance_cleanup_high_water(
            &mut state,
            acquisition.token.key(),
            Some(&control_submission),
            observed_at,
        )?;
        if observed_at < safe_after {
            let claim = state
                .dispatch_claims
                .get_mut(&claim_key)
                .ok_or(StateError::DispatchClaimNotFound)?;
            if claim.state != MemoryDispatchClaimState::RecoveryNoSend
                || claim
                    .recovery_safe_after
                    .is_some_and(|stored| stored != safe_after)
                || claim.recovery_retired_at.is_some()
            {
                return Err(StateError::DispatchAcquisitionMismatch);
            }
            claim.recovery_safe_after = Some(safe_after);
            return Ok(RecoveryNoSendRetirementOutcome::Pending { safe_after });
        }
        if state
            .physical_reservations
            .get(acquisition.token.physical_resource())
            != Some(&claim_key)
        {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        let receipt = RecoveryNoSendRetirementReceipt::new(
            acquisition.token.key().clone(),
            recovery_acquisition,
            safe_after,
            observed_at,
        );
        let claim = state
            .dispatch_claims
            .get_mut(&claim_key)
            .ok_or(StateError::DispatchClaimNotFound)?;
        if claim.state != MemoryDispatchClaimState::RecoveryNoSend
            || claim
                .recovery_safe_after
                .is_some_and(|stored| stored != safe_after)
            || claim.recovery_retired_at.is_some()
        {
            return Err(StateError::DispatchAttemptOutcomeUnknown);
        }
        claim.state = MemoryDispatchClaimState::RecoveryRetired;
        claim.recovery_safe_after = Some(safe_after);
        claim.recovery_retired_at = Some(observed_at);
        state
            .physical_reservations
            .remove(acquisition.token.physical_resource());
        Ok(RecoveryNoSendRetirementOutcome::Retired(receipt))
    }

    fn admission_context(&self, key: &ConsumeKey) -> Result<AdmissionContext, StateError> {
        key.validate()?;
        let mut state = self.inner.lock();

        // Check routing, transaction, durable attempt state, and reservation
        // before sampling time. An unrelated lookup must not advance this
        // scope's trusted-time high-water mark.
        let lineage = memory_post_attempt_lineage(&state, key)?;
        let token = lineage.token;
        let started_at = lineage.started_at;

        let observed_time = self.clock.now_unix_seconds()?;
        let snapshot = if let Some(stored) = lineage.control_submission.as_ref() {
            memory_dispatch_snapshot_with_dual_high_water(&mut state, stored, key, observed_time)?
        } else {
            memory_dispatch_snapshot_with_high_water(&mut state, key, observed_time)?
        };
        let physical_resource =
            PhysicalResourceKey::from_authorization(snapshot.issued().authorization())?;
        if physical_resource != *token.physical_resource() {
            return Err(StateError::AdmissionClaimMismatch);
        }
        if started_at < 0 || started_at > snapshot.checked_at() {
            return Err(StateError::InvalidRecord(
                "dispatch attempt start time is outside the current interval".to_owned(),
            ));
        }
        let (operation_hash, provider_request_commitment) =
            admission_projection(snapshot.issued())?;
        Ok(AdmissionContext::new(
            key.clone(),
            token.claim_id(),
            token.fence(),
            physical_resource,
            lineage.credential_token_digest,
            lineage.service_account_uid,
            lineage.credential_id,
            lineage.credential_not_before,
            lineage.credential_expires_at,
            lineage.credential_commitment,
            snapshot.issued().authorization().template.clone(),
            snapshot.issued().authorization().template_hash,
            operation_hash,
            provider_request_commitment,
            started_at,
            snapshot.checked_at(),
            snapshot.receipt().dispatch_deadline,
            snapshot.authority().clone(),
        ))
    }

    fn authorize_admission_or_recover(
        &self,
        request: &AdmissionAuthorizationRequest,
    ) -> Result<AdmissionAuthorization, StateError> {
        request.validate()?;
        let mut state = self.inner.lock();

        let recovered_authorized_at =
            if let Some(existing) = state.admission_authorizations.get(request.admission_uid()) {
                if existing.request != *request {
                    return Err(StateError::AdmissionUidMismatch);
                }
                Some(existing.authorized_at)
            } else {
                let transaction_key = (request.scope().clone(), request.transaction_id());
                if state.admission_transactions.contains_key(&transaction_key)
                    || state.admission_claim_ids.contains_key(&request.claim_id())
                    || state.admission_fences.contains_key(&request.fence())
                {
                    return Err(StateError::AdmissionAlreadyAuthorized);
                }
                if state
                    .admission_provider_requests
                    .contains_key(&request.provider_request_commitment())
                {
                    return Err(StateError::AdmissionProviderRequestReplay);
                }
                None
            };

        // Routing and claim identity are checked before sampling trusted time,
        // so an unrelated request cannot advance another scope's high-water.
        validate_memory_admission_claim(&state, request)?;
        let lineage = memory_post_attempt_lineage(&state, request.key())?;
        let issued = state
            .authorizations
            .get(&(request.scope().clone(), request.authorization_id()))
            .ok_or(StateError::AuthorizationNotFound)?;
        validate_admission_provider_commitment(request, issued)?;
        let observed_time = self.clock.now_unix_seconds()?;
        let snapshot = if let Some(stored) = lineage.control_submission.as_ref() {
            memory_dispatch_snapshot_with_dual_high_water(
                &mut state,
                stored,
                request.key(),
                observed_time,
            )?
        } else {
            memory_dispatch_snapshot_with_high_water(&mut state, request.key(), observed_time)?
        };
        if PhysicalResourceKey::from_authorization(snapshot.issued().authorization())?
            != *request.physical_resource()
        {
            return Err(StateError::AdmissionClaimMismatch);
        }

        if let Some(authorized_at) = recovered_authorized_at {
            return Ok(AdmissionAuthorization::new(
                request.clone(),
                authorized_at,
                observed_time,
                true,
            ));
        }

        let uid = request.admission_uid().to_owned();
        state.admission_transactions.insert(
            (request.scope().clone(), request.transaction_id()),
            uid.clone(),
        );
        state
            .admission_claim_ids
            .insert(request.claim_id(), uid.clone());
        state.admission_fences.insert(request.fence(), uid.clone());
        state
            .admission_provider_requests
            .insert(request.provider_request_commitment(), uid.clone());
        state.admission_authorizations.insert(
            uid,
            MemoryAdmissionAuthorization {
                request: request.clone(),
                authorized_at: observed_time,
            },
        );
        Ok(AdmissionAuthorization::new(
            request.clone(),
            observed_time,
            observed_time,
            false,
        ))
    }

    fn consumption_receipt(&self, key: &ConsumeKey) -> Result<ConsumptionReceipt, StateError> {
        key.validate()?;
        self.inner
            .lock()
            .receipts
            .get(&(key.scope.clone(), key.authorization_id))
            .filter(|receipt| receipt.transaction_id == key.transaction_id)
            .cloned()
            .ok_or(StateError::ConsumptionNotFound)
    }

    fn outbox_entry(&self, key: &ConsumeKey) -> Result<OutboxEntry, StateError> {
        key.validate()?;
        self.inner
            .lock()
            .outbox
            .get(&(key.scope.clone(), key.authorization_id))
            .filter(|entry| entry.transaction_id == key.transaction_id)
            .cloned()
            .ok_or(StateError::ConsumptionNotFound)
    }

    fn time_high_water(&self, scope: &Scope) -> Result<Option<i64>, StateError> {
        scope.validate()?;
        Ok(self.inner.lock().high_water.get(scope).copied())
    }
}

fn broker_memory_key(
    key: &ConsumeKey,
    operation: BrokerJournalOperation,
) -> (Scope, Uuid, BrokerJournalOperation) {
    (key.scope.clone(), key.authorization_id, operation)
}

fn memory_exact_delete_absence(
    state: &MemoryState,
    acquisition: &MemoryDispatchAcquisition,
) -> Result<Option<i64>, StateError> {
    let key = acquisition.token.key();
    let Some(delete) = state.broker_operations.get(&broker_memory_key(
        key,
        BrokerJournalOperation::DeleteSecret,
    )) else {
        return Ok(None);
    };
    delete.validate()?;
    if delete.phase != BrokerJournalPhase::Committed
        || delete.outcome != Some(BrokerJournalOutcome::DeleteAbsent)
    {
        return Ok(None);
    }
    let create = state
        .broker_operations
        .get(&broker_memory_key(
            key,
            BrokerJournalOperation::CreateSecret,
        ))
        .ok_or(StateError::BrokerOperationNotFound)?;
    create.validate()?;
    let versions_match = match acquisition.selection_kind {
        MemoryDispatchAcquisitionKind::ControlQueue => {
            create.acquisition_binding_version == 2 && delete.acquisition_binding_version == 2
        }
        MemoryDispatchAcquisitionKind::ControlBootstrapV13 => {
            create.acquisition_binding_version == 1
                && matches!(delete.acquisition_binding_version, 1 | 2)
        }
        MemoryDispatchAcquisitionKind::LegacyBootstrap => false,
    };
    if !versions_match
        || create.key != *key
        || create.claim_id != acquisition.token.claim_id()
        || create.fence != acquisition.token.fence()
        || create.state_instance_id != acquisition.token.state_instance_id()
        || create.origin_acquisition_id != acquisition.acquisition_id
        || create.origin_lease_fence != acquisition.lease_fence
        || create.physical_resource != *acquisition.token.physical_resource()
        || delete.key != create.key
        || delete.claim_id != create.claim_id
        || delete.fence != create.fence
        || delete.state_instance_id != create.state_instance_id
        || delete.origin_acquisition_id != create.origin_acquisition_id
        || delete.origin_lease_fence != create.origin_lease_fence
        || delete.physical_resource != create.physical_resource
        || delete.route_commitment != create.route_commitment
        || delete.bound_secret_uid != create.bound_secret_uid
    {
        return Err(StateError::BrokerOperationMismatch);
    }
    let claim_key = (key.scope.clone(), key.authorization_id);
    let deletion = state
        .secret_deletion_observations
        .get(&claim_key)
        .ok_or(StateError::BrokerOperationMismatch)?;
    let exact =
        StoredSecretDeletionObservation::from_committed_delete(delete, deletion.observed_at)?;
    if deletion != &exact
        || state.secret_deletion_entry_ids.get(&delete.entry_id) != Some(&claim_key)
    {
        return Err(StateError::BrokerOperationMismatch);
    }
    Ok(Some(deletion.observed_at))
}

fn memory_exact_delete_terminal_conflict(
    state: &MemoryState,
    acquisition: &MemoryDispatchAcquisition,
) -> Result<bool, StateError> {
    let key = acquisition.token.key();
    let Some(delete) = state.broker_operations.get(&broker_memory_key(
        key,
        BrokerJournalOperation::DeleteSecret,
    )) else {
        return Ok(false);
    };
    delete.validate()?;
    if delete.phase != BrokerJournalPhase::Terminal
        || delete.outcome != Some(BrokerJournalOutcome::DeleteConflicting)
    {
        return Ok(false);
    }
    let create = state
        .broker_operations
        .get(&broker_memory_key(
            key,
            BrokerJournalOperation::CreateSecret,
        ))
        .ok_or(StateError::BrokerOperationNotFound)?;
    create.validate()?;
    let versions_match = match acquisition.selection_kind {
        MemoryDispatchAcquisitionKind::ControlQueue => {
            create.acquisition_binding_version == 2 && delete.acquisition_binding_version == 2
        }
        MemoryDispatchAcquisitionKind::ControlBootstrapV13 => {
            create.acquisition_binding_version == 1
                && matches!(delete.acquisition_binding_version, 1 | 2)
        }
        MemoryDispatchAcquisitionKind::LegacyBootstrap => false,
    };
    if !versions_match
        || create.key != *key
        || create.claim_id != acquisition.token.claim_id()
        || create.fence != acquisition.token.fence()
        || create.state_instance_id != acquisition.token.state_instance_id()
        || create.origin_acquisition_id != acquisition.acquisition_id
        || create.origin_lease_fence != acquisition.lease_fence
        || create.physical_resource != *acquisition.token.physical_resource()
        || delete.key != create.key
        || delete.claim_id != create.claim_id
        || delete.fence != create.fence
        || delete.state_instance_id != create.state_instance_id
        || delete.origin_acquisition_id != create.origin_acquisition_id
        || delete.origin_lease_fence != create.origin_lease_fence
        || delete.physical_resource != create.physical_resource
        || delete.route_commitment != create.route_commitment
        || delete.bound_secret_uid != create.bound_secret_uid
    {
        return Err(StateError::BrokerOperationMismatch);
    }
    Ok(true)
}

fn require_memory_claim<'a>(
    state: &'a MemoryState,
    key: &ConsumeKey,
) -> Result<&'a MemoryDispatchClaim, StateError> {
    let claim = state
        .dispatch_claims
        .get(&(key.scope.clone(), key.authorization_id))
        .ok_or(StateError::DispatchClaimNotFound)?;
    if claim.token.key() != key
        || state
            .physical_reservations
            .get(claim.token.physical_resource())
            != Some(&(key.scope.clone(), key.authorization_id))
    {
        return Err(StateError::BrokerOperationMismatch);
    }
    Ok(claim)
}

fn require_memory_token<'a>(
    store_instance_id: Uuid,
    state: &'a MemoryState,
    token: &DispatchClaimToken,
) -> Result<&'a MemoryDispatchClaim, StateError> {
    if token.state_instance_id() != store_instance_id {
        return Err(StateError::BrokerOperationMismatch);
    }
    let claim = require_memory_claim(state, token.key())?;
    if claim.token != *token || claim.state != MemoryDispatchClaimState::Claimed {
        return Err(StateError::BrokerOperationOutcomeUnknown);
    }
    Ok(claim)
}

fn require_matching_create<'a>(
    state: &'a MemoryState,
    key: &ConsumeKey,
    route_commitment: Digest32,
) -> Result<&'a StoredBrokerOperation, StateError> {
    let create = state
        .broker_operations
        .get(&broker_memory_key(
            key,
            BrokerJournalOperation::CreateSecret,
        ))
        .ok_or(StateError::BrokerOperationNotFound)?;
    if create.phase != BrokerJournalPhase::Committed
        || create.outcome != Some(BrokerJournalOutcome::CreateMatching)
        || create.route_commitment != route_commitment
        || create.bound_secret_uid.is_none()
    {
        return Err(StateError::BrokerOperationMismatch);
    }
    Ok(create)
}

fn require_matching_create_for_acquisition<'a>(
    state: &'a MemoryState,
    authority: &DispatchAcquisitionAuthority,
    route_commitment: Digest32,
) -> Result<&'a StoredBrokerOperation, StateError> {
    let create = require_matching_create(state, authority.claim().key(), route_commitment)?;
    if create.acquisition_binding_version != 2
        || create.claim_id != authority.claim().claim_id()
        || create.fence != authority.claim().fence()
        || create.state_instance_id != authority.claim().state_instance_id()
        || create.origin_acquisition_id != authority.acquisition_id()
        || create.origin_lease_fence != authority.lease_fence()
        || create.physical_resource != *authority.claim().physical_resource()
    {
        return Err(StateError::BrokerOperationMismatch);
    }
    Ok(create)
}

fn validate_memory_attempt_broker_lineage(
    state: &MemoryState,
    authority: &DispatchAcquisitionAuthority,
    credential: &DispatchCredentialBinding,
    binding_version: i16,
) -> Result<(), StateError> {
    let create = state
        .broker_operations
        .get(&broker_memory_key(
            authority.claim().key(),
            BrokerJournalOperation::CreateSecret,
        ))
        .ok_or(StateError::BrokerOperationNotFound)?;
    let issue = state
        .broker_operations
        .get(&broker_memory_key(
            authority.claim().key(),
            BrokerJournalOperation::IssueToken,
        ))
        .ok_or(StateError::BrokerOperationNotFound)?;
    validate_memory_attempt_broker_rows(create, issue, authority, credential, binding_version)
}

fn validate_memory_optional_bootstrap_attempt_broker_lineage(
    state: &MemoryState,
    authority: &DispatchAcquisitionAuthority,
    credential: &DispatchCredentialBinding,
) -> Result<(), StateError> {
    let create = state.broker_operations.get(&broker_memory_key(
        authority.claim().key(),
        BrokerJournalOperation::CreateSecret,
    ));
    let issue = state.broker_operations.get(&broker_memory_key(
        authority.claim().key(),
        BrokerJournalOperation::IssueToken,
    ));
    match (create, issue) {
        (None, None) => Ok(()),
        (Some(create), Some(issue)) => {
            validate_memory_attempt_broker_rows(create, issue, authority, credential, 1)
        }
        _ => Err(StateError::BrokerOperationMismatch),
    }
}

fn validate_memory_attempt_broker_rows(
    create: &StoredBrokerOperation,
    issue: &StoredBrokerOperation,
    authority: &DispatchAcquisitionAuthority,
    credential: &DispatchCredentialBinding,
    binding_version: i16,
) -> Result<(), StateError> {
    create.validate()?;
    issue.validate()?;
    for operation in [create, issue] {
        if operation.acquisition_binding_version != binding_version
            || operation.claim_id != authority.claim().claim_id()
            || operation.fence != authority.claim().fence()
            || operation.state_instance_id != authority.claim().state_instance_id()
            || operation.origin_acquisition_id != authority.acquisition_id()
            || operation.origin_lease_fence != authority.lease_fence()
            || operation.physical_resource != *authority.claim().physical_resource()
        {
            return Err(StateError::BrokerOperationMismatch);
        }
    }
    if create.phase != BrokerJournalPhase::Committed
        || create.outcome != Some(BrokerJournalOutcome::CreateMatching)
        || create.bound_secret_uid.is_none()
        || issue.phase != BrokerJournalPhase::Committed
        || issue.outcome != Some(BrokerJournalOutcome::TokenIssued)
        || issue.route_commitment != create.route_commitment
        || issue.bound_secret_uid != create.bound_secret_uid
        || issue.token_digest != Some(credential.token_digest())
        || issue.token_expires_at != Some(credential.expires_at())
        || issue.credential_policy.is_none()
    {
        return Err(StateError::BrokerOperationMismatch);
    }
    Ok(())
}

fn validate_memory_credential_review_frozen_lineage(
    state: &MemoryState,
    review: &StoredDispatchCredentialReview,
) -> Result<(), StateError> {
    review.validate()?;
    let key = review.token.key();
    let acquisition = state
        .dispatch_acquisitions
        .get(&review.acquisition_id)
        .ok_or(StateError::DispatchCredentialReviewMismatch)?;
    if acquisition.token != review.token
        || acquisition.lease_fence != review.lease_fence
        || acquisition.worker_id != review.acquisition_worker_id
        || acquisition.acquired_at != review.acquired_at
        || acquisition.lease_until != review.lease_until
        || acquisition.dispatch_deadline != review.dispatch_deadline
        || acquisition.control_submission_id != review.control_submission_id
    {
        return Err(StateError::DispatchCredentialReviewMismatch);
    }
    if let Some(submission_id) = review.control_submission_id {
        memory_control_submission_for_dispatch(state, submission_id, key)?;
    }
    let create = state
        .broker_operations
        .get(&broker_memory_key(
            key,
            BrokerJournalOperation::CreateSecret,
        ))
        .ok_or(StateError::BrokerOperationNotFound)?;
    let issue = state
        .broker_operations
        .get(&broker_memory_key(key, BrokerJournalOperation::IssueToken))
        .ok_or(StateError::BrokerOperationNotFound)?;
    create.validate()?;
    issue.validate()?;
    if create.entry_id != review.create_entry_id
        || create.request_commitment != review.create_request_commitment
        || issue.entry_id != review.token_entry_id
        || issue.request_commitment != review.token_request_commitment
        || create.phase != BrokerJournalPhase::Committed
        || create.outcome != Some(BrokerJournalOutcome::CreateMatching)
        || issue.phase != BrokerJournalPhase::Committed
        || issue.outcome != Some(BrokerJournalOutcome::TokenIssued)
        || create.origin_acquisition_id != review.acquisition_id
        || create.origin_lease_fence != review.lease_fence
        || issue.origin_acquisition_id != review.acquisition_id
        || issue.origin_lease_fence != review.lease_fence
        || create.acquisition_binding_version != 2
        || issue.acquisition_binding_version != 2
        || create.bound_secret_uid.as_deref() != Some(&review.expected_bound_secret_uid)
        || issue.bound_secret_uid.as_deref() != Some(&review.expected_bound_secret_uid)
        || issue.token_digest != Some(review.expected_token_digest)
        || issue.token_expires_at != Some(review.expected_token_expires_at)
        || issue.route_commitment != create.route_commitment
    {
        return Err(StateError::DispatchCredentialReviewMismatch);
    }
    let issued = state
        .authorizations
        .get(&(key.scope.clone(), key.authorization_id))
        .ok_or(StateError::AuthorizationNotFound)?;
    let destination = memory_frozen_destination_for_review(
        state,
        &key.scope,
        &issued.authorization().authority,
        review.destination_activation_commitment,
    )
    .map_err(|_| StateError::DispatchCredentialReviewMismatch)?;
    let facts = derive_attempt_facts(
        &key.scope,
        key.transaction_id,
        key.authorization_id,
        issued.authorization().template_hash,
        &issued.authorization().template,
        &destination,
    )
    .map_err(|_| StateError::DispatchCredentialReviewMismatch)?;
    let rooted_route_commitment = Digest32::from_bytes(*facts.route().commitment().as_bytes());
    for operation in [create, issue] {
        if operation.claim_id != review.token.claim_id()
            || operation.fence != review.token.fence()
            || operation.state_instance_id != review.token.state_instance_id()
            || operation.physical_resource != *review.token.physical_resource()
            || operation.route_commitment != rooted_route_commitment
        {
            return Err(StateError::DispatchCredentialReviewMismatch);
        }
    }
    if create.result_commitment != Some(review.create_result_commitment)
        || issue.result_commitment != Some(review.token_result_commitment)
        || issue.credential_policy != Some(review.token_credential_policy)
        || review.expected_route_commitment != rooted_route_commitment
        || facts.token_subject() != review.expected_subject
        || facts.token_audience() != review.expected_audience
        || facts.service_account_uid() != review.expected_service_account_uid
        || facts.credential_lifecycle_policy() != review.credential_lifecycle_policy
        || facts.activation_commitment() != review.destination_activation_commitment
        || facts.physical_resource() != review.token.physical_resource()
    {
        return Err(StateError::DispatchCredentialReviewMismatch);
    }
    Ok(())
}

fn adopt_or_insert_memory_intent(
    state: &mut MemoryState,
    candidate: StoredBrokerOperation,
) -> Result<BrokerOperationIntent, StateError> {
    let key = broker_memory_key(&candidate.key, candidate.operation);
    if let Some(existing) = state.broker_operations.get(&key) {
        if !existing.same_request_material(&candidate) {
            return Err(StateError::BrokerOperationMismatch);
        }
        return if existing.phase == BrokerJournalPhase::Intent {
            Ok(BrokerOperationIntent::new(existing.clone()))
        } else {
            Err(StateError::BrokerOperationOutcomeUnknown)
        };
    }
    state.broker_operations.insert(key, candidate.clone());
    Ok(BrokerOperationIntent::new(candidate))
}

fn require_memory_bootstrap_acquisition<'a>(
    state: &'a MemoryState,
    token: &DispatchClaimToken,
) -> Result<&'a MemoryDispatchAcquisition, StateError> {
    let acquisition_id = state
        .latest_dispatch_acquisition
        .get(&(token.key().scope.clone(), token.key().authorization_id))
        .copied()
        .ok_or(StateError::DispatchAcquisitionMismatch)?;
    let acquisition = state
        .dispatch_acquisitions
        .get(&acquisition_id)
        .ok_or(StateError::DispatchAcquisitionMismatch)?;
    if acquisition.control_submission_id.is_some()
        || acquisition.selection_kind != MemoryDispatchAcquisitionKind::LegacyBootstrap
    {
        return Err(StateError::DispatchAcquisitionRequired);
    }
    if acquisition.token != *token || acquisition_id != token.claim_id() {
        return Err(StateError::DispatchAcquisitionMismatch);
    }
    Ok(acquisition)
}

fn require_memory_control_acquisition<'a>(
    store_instance_id: Uuid,
    state: &'a MemoryState,
    authority: &DispatchAcquisitionAuthority,
) -> Result<&'a MemoryDispatchAcquisition, StateError> {
    let token = authority.claim();
    token.key().validate()?;
    if token.state_instance_id() != store_instance_id {
        return Err(StateError::DispatchAcquisitionMismatch);
    }
    let claim_key = (token.key().scope.clone(), token.key().authorization_id);
    let claim = state
        .dispatch_claims
        .get(&claim_key)
        .ok_or(StateError::DispatchClaimNotFound)?;
    if claim.token != *token
        || state.physical_reservations.get(token.physical_resource()) != Some(&claim_key)
    {
        return Err(StateError::DispatchAcquisitionMismatch);
    }
    if claim.state != MemoryDispatchClaimState::Claimed
        || claim.attempt_started_at.is_some()
        || claim.attempt_acquisition.is_some()
        || claim.credential.is_some()
        || claim.terminalization_id.is_some()
    {
        return Err(StateError::DispatchAttemptOutcomeUnknown);
    }
    let latest_id = state
        .latest_dispatch_acquisition
        .get(&claim_key)
        .copied()
        .ok_or(StateError::DispatchAcquisitionMismatch)?;
    if latest_id != authority.acquisition_id() {
        return Err(StateError::DispatchAcquisitionMismatch);
    }
    let acquisition = state
        .dispatch_acquisitions
        .get(&latest_id)
        .ok_or(StateError::DispatchAcquisitionMismatch)?;
    if acquisition.selection_kind != MemoryDispatchAcquisitionKind::ControlQueue
        || acquisition.control_submission_id.is_none()
        || acquisition.token != *token
        || acquisition.acquisition_id != authority.acquisition_id()
        || acquisition.lease_fence != authority.lease_fence()
        || acquisition.worker_id != authority.worker_id()
        || acquisition.acquired_at != authority.acquired_at()
        || acquisition.lease_until != authority.lease_until()
        || acquisition.dispatch_deadline != authority.dispatch_deadline()
        || acquisition.control_submission_id != authority.control_submission_id()
    {
        return Err(StateError::DispatchAcquisitionMismatch);
    }
    let submission_id = acquisition
        .control_submission_id
        .ok_or(StateError::DispatchAcquisitionMismatch)?;
    if state
        .dispatch_disposition_by_submission
        .contains_key(&submission_id)
        || state
            .admission_transactions
            .contains_key(&(token.key().scope.clone(), token.key().transaction_id))
        || state.admission_claim_ids.contains_key(&token.claim_id())
        || state
            .terminal_retirements
            .contains_key(&(token.key().scope.clone(), token.key().authorization_id))
    {
        return Err(StateError::DispatchAcquisitionMismatch);
    }
    for operation in state.broker_operations.values().filter(|operation| {
        operation.key.scope == token.key().scope
            && operation.key.authorization_id == token.key().authorization_id
    }) {
        operation.validate()?;
        if operation.operation == BrokerJournalOperation::DeleteSecret
            || operation.acquisition_binding_version != 2
            || operation.claim_id != token.claim_id()
            || operation.fence != token.fence()
            || operation.state_instance_id != token.state_instance_id()
            || operation.origin_acquisition_id != acquisition.acquisition_id
            || operation.origin_lease_fence != acquisition.lease_fence
            || operation.physical_resource != *token.physical_resource()
        {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
    }
    Ok(acquisition)
}

fn memory_acquisition_from_recovery_key<'a>(
    state: &'a MemoryState,
    key: &crate::DispatchAcquisitionRecoveryKey,
) -> Result<&'a MemoryDispatchAcquisition, StateError> {
    key.scope().validate()?;
    if key.acquisition_id().is_nil() || !crate::acquisition::valid_worker_id(key.worker_id()) {
        return Err(StateError::DispatchAcquisitionMismatch);
    }
    let acquisition = state
        .dispatch_acquisitions
        .get(&key.acquisition_id())
        .ok_or(StateError::DispatchAcquisitionMismatch)?;
    if acquisition.token.key().scope != *key.scope()
        || acquisition.worker_id != key.worker_id()
        || (acquisition.selection_kind == MemoryDispatchAcquisitionKind::ControlQueue
            && acquisition.control_submission_id.is_none())
        || (acquisition.selection_kind == MemoryDispatchAcquisitionKind::ControlBootstrapV13
            && acquisition.control_submission_id.is_none())
        || (acquisition.selection_kind == MemoryDispatchAcquisitionKind::LegacyBootstrap
            && acquisition.control_submission_id.is_some())
    {
        return Err(StateError::DispatchAcquisitionMismatch);
    }
    if let Some(submission_id) = acquisition.control_submission_id {
        memory_control_submission_for_dispatch(state, submission_id, acquisition.token.key())?;
    }
    Ok(acquisition)
}

#[derive(Clone)]
struct MemoryNoSendLineage {
    acquisition: MemoryDispatchAcquisition,
    lifecycle_policy: accordlock_eks_profile::EksCredentialLifecyclePolicy,
    create: StoredBrokerOperation,
    has_issue: bool,
    review: Option<StoredDispatchCredentialReview>,
    delete: Option<StoredBrokerOperation>,
}

#[allow(clippy::too_many_lines)]
fn memory_no_send_lineage(
    state: &MemoryState,
    recovery_key: &crate::DispatchAcquisitionRecoveryKey,
) -> Result<MemoryNoSendLineage, StateError> {
    let acquisition = memory_acquisition_from_recovery_key(state, recovery_key)?.clone();
    if !matches!(
        acquisition.selection_kind,
        MemoryDispatchAcquisitionKind::ControlQueue
            | MemoryDispatchAcquisitionKind::ControlBootstrapV13
    ) {
        return Err(StateError::DispatchAcquisitionMismatch);
    }
    let key = acquisition.token.key();
    let claim_key = (key.scope.clone(), key.authorization_id);
    if state.latest_dispatch_acquisition.get(&claim_key) != Some(&acquisition.acquisition_id) {
        return Err(StateError::DispatchAcquisitionMismatch);
    }
    let claim = state
        .dispatch_claims
        .get(&claim_key)
        .ok_or(StateError::DispatchClaimNotFound)?;
    let owns_reservation = state
        .physical_reservations
        .get(acquisition.token.physical_resource())
        == Some(&claim_key);
    let valid_recovery_state = match claim.state {
        MemoryDispatchClaimState::Claimed => {
            owns_reservation
                && claim.recovery_safe_after.is_none()
                && claim.recovery_retired_at.is_none()
        }
        MemoryDispatchClaimState::RecoveryNoSend => {
            owns_reservation && claim.recovery_retired_at.is_none()
        }
        MemoryDispatchClaimState::RecoveryRetired => {
            !owns_reservation
                && claim.recovery_safe_after.is_some()
                && claim.recovery_retired_at.is_some()
        }
        _ => false,
    };
    if claim.token != acquisition.token
        || !valid_recovery_state
        || claim.attempt_started_at.is_some()
        || claim.attempt_acquisition.is_some()
        || claim.credential.is_some()
        || claim.credential_review_id.is_some()
        || claim.terminalization_id.is_some()
    {
        return Err(StateError::DispatchAttemptOutcomeUnknown);
    }
    if acquisition.selection_kind == MemoryDispatchAcquisitionKind::ControlBootstrapV13
        && (acquisition.acquisition_id != acquisition.token.claim_id()
            || acquisition.lease_fence != acquisition.token.fence()
            || acquisition.worker_id != acquisition.token.worker_id()
            || acquisition.acquired_at != acquisition.token.claimed_at()
            || acquisition.lease_until != acquisition.token.lease_until())
    {
        return Err(StateError::DispatchAcquisitionMismatch);
    }
    let submission_id = acquisition
        .control_submission_id
        .ok_or(StateError::DispatchAcquisitionMismatch)?;
    memory_control_submission_for_dispatch(state, submission_id, key)?;
    if state
        .dispatch_disposition_by_submission
        .contains_key(&submission_id)
        || state
            .admission_transactions
            .contains_key(&(key.scope.clone(), key.transaction_id))
        || state
            .admission_claim_ids
            .contains_key(&acquisition.token.claim_id())
        || state.terminal_retirements.contains_key(&claim_key)
    {
        return Err(StateError::DispatchAcquisitionMismatch);
    }

    let issued = state
        .authorizations
        .get(&claim_key)
        .ok_or(StateError::AuthorizationNotFound)?;
    let receipt = state
        .receipts
        .get(&claim_key)
        .ok_or(StateError::ConsumptionNotFound)?;
    let outbox = state
        .outbox
        .get(&claim_key)
        .ok_or(StateError::ConsumptionNotFound)?;
    validate_recovered_consumption(key, issued, receipt, outbox)?;
    let destination = memory_frozen_destination_for_authority(
        state,
        &key.scope,
        &issued.authorization().authority,
    )
    .map_err(|_| StateError::BrokerOperationMismatch)?;
    let facts = derive_attempt_facts(
        &key.scope,
        key.transaction_id,
        key.authorization_id,
        issued.authorization().template_hash,
        &issued.authorization().template,
        &destination,
    )
    .map_err(|_| StateError::BrokerOperationMismatch)?;
    if facts.physical_resource() != acquisition.token.physical_resource() {
        return Err(StateError::BrokerOperationMismatch);
    }
    let rooted_route = Digest32::from_bytes(*facts.route().commitment().as_bytes());
    let create = state
        .broker_operations
        .get(&broker_memory_key(
            key,
            BrokerJournalOperation::CreateSecret,
        ))
        .ok_or(StateError::BrokerOperationNotFound)?;
    create.validate()?;
    let create_binding_version = match acquisition.selection_kind {
        MemoryDispatchAcquisitionKind::ControlQueue => 2,
        MemoryDispatchAcquisitionKind::ControlBootstrapV13 => 1,
        MemoryDispatchAcquisitionKind::LegacyBootstrap => unreachable!(),
    };
    if create.key != *key
        || create.claim_id != acquisition.token.claim_id()
        || create.fence != acquisition.token.fence()
        || create.state_instance_id != acquisition.token.state_instance_id()
        || create.origin_acquisition_id != acquisition.acquisition_id
        || create.origin_lease_fence != acquisition.lease_fence
        || create.acquisition_binding_version != create_binding_version
        || create.physical_resource != *acquisition.token.physical_resource()
        || create.route_commitment != rooted_route
    {
        return Err(StateError::BrokerOperationMismatch);
    }
    let issue = state
        .broker_operations
        .get(&broker_memory_key(key, BrokerJournalOperation::IssueToken));
    if let Some(issue) = issue {
        issue.validate()?;
        if issue.key != *key
            || issue.claim_id != create.claim_id
            || issue.fence != create.fence
            || issue.state_instance_id != create.state_instance_id
            || issue.origin_acquisition_id != create.origin_acquisition_id
            || issue.origin_lease_fence != create.origin_lease_fence
            || issue.acquisition_binding_version != create_binding_version
            || issue.physical_resource != create.physical_resource
            || issue.route_commitment != rooted_route
            || issue.bound_secret_uid != create.bound_secret_uid
        {
            return Err(StateError::BrokerOperationMismatch);
        }
    }
    let review = state.credential_reviews.get(&claim_key);
    if let Some(review) = review {
        if acquisition.selection_kind != MemoryDispatchAcquisitionKind::ControlQueue
            || review.acquisition_id != acquisition.acquisition_id
        {
            return Err(StateError::DispatchCredentialReviewMismatch);
        }
        validate_memory_credential_review_frozen_lineage(state, review)?;
    }
    let delete = state
        .broker_operations
        .get(&broker_memory_key(
            key,
            BrokerJournalOperation::DeleteSecret,
        ))
        .cloned();
    if let Some(delete) = &delete {
        delete.validate()?;
        let valid_delete_binding = match acquisition.selection_kind {
            MemoryDispatchAcquisitionKind::ControlQueue => delete.acquisition_binding_version == 2,
            MemoryDispatchAcquisitionKind::ControlBootstrapV13 => {
                matches!(delete.acquisition_binding_version, 1 | 2)
            }
            MemoryDispatchAcquisitionKind::LegacyBootstrap => false,
        };
        if !valid_delete_binding
            || delete.claim_id != create.claim_id
            || delete.fence != create.fence
            || delete.state_instance_id != create.state_instance_id
            || delete.origin_acquisition_id != create.origin_acquisition_id
            || delete.origin_lease_fence != create.origin_lease_fence
            || delete.physical_resource != create.physical_resource
            || delete.route_commitment != rooted_route
            || delete.bound_secret_uid != create.bound_secret_uid
        {
            return Err(StateError::BrokerOperationMismatch);
        }
    }
    Ok(MemoryNoSendLineage {
        acquisition,
        lifecycle_policy: facts.credential_lifecycle_policy(),
        create: create.clone(),
        has_issue: issue.is_some(),
        review: review.cloned(),
        delete,
    })
}

fn memory_revalidate_control_acquisition_locked(
    store_instance_id: Uuid,
    state: &mut MemoryState,
    authority: &DispatchAcquisitionAuthority,
    observed_at: i64,
) -> Result<(DispatchSnapshot, MemoryDispatchAcquisition), StateError> {
    let acquisition =
        require_memory_control_acquisition(store_instance_id, state, authority)?.clone();
    let submission_id = acquisition
        .control_submission_id
        .ok_or(StateError::DispatchAcquisitionMismatch)?;
    let stored =
        memory_control_submission_for_dispatch(state, submission_id, authority.claim().key())?
            .clone();
    let snapshot = memory_dispatch_snapshot_with_dual_high_water(
        state,
        &stored,
        authority.claim().key(),
        observed_at,
    )?;
    if snapshot.receipt().dispatch_deadline != acquisition.dispatch_deadline
        || snapshot.checked_at() < acquisition.acquired_at
        || PhysicalResourceKey::from_authorization(snapshot.issued().authorization())?
            != *authority.claim().physical_resource()
    {
        return Err(StateError::DispatchAcquisitionMismatch);
    }
    if snapshot.checked_at() >= acquisition.lease_until {
        return Err(StateError::DispatchClaimLeaseExpired {
            observed: snapshot.checked_at(),
            lease_until: acquisition.lease_until,
        });
    }
    Ok((snapshot, acquisition))
}

fn memory_cleanup_control_submission(
    state: &MemoryState,
    key: &ConsumeKey,
    origin_acquisition_id: Uuid,
    origin_lease_fence: u64,
) -> Result<Option<StoredControlSubmission>, StateError> {
    let acquisition = state
        .dispatch_acquisitions
        .get(&origin_acquisition_id)
        .ok_or(StateError::DispatchAcquisitionMismatch)?;
    if acquisition.acquisition_id != origin_acquisition_id
        || acquisition.lease_fence != origin_lease_fence
        || acquisition.token.key() != key
    {
        return Err(StateError::DispatchAcquisitionMismatch);
    }
    acquisition
        .control_submission_id
        .map(|submission_id| {
            memory_control_submission_for_dispatch(state, submission_id, key).cloned()
        })
        .transpose()
}

fn memory_advance_cleanup_high_water(
    state: &mut MemoryState,
    key: &ConsumeKey,
    control_submission: Option<&StoredControlSubmission>,
    observed_at: i64,
) -> Result<(), StateError> {
    let high_water = if let Some(stored) = control_submission {
        memory_control_high_water(state, stored)?
    } else {
        state.high_water.get(&key.scope).copied().unwrap_or(0)
    };
    validate_cleanup_clock(&key.scope, Some(high_water), observed_at)?;
    if let Some(stored) = control_submission {
        memory_advance_control_high_water(state, stored, observed_at)
    } else {
        state.high_water.insert(key.scope.clone(), observed_at);
        Ok(())
    }
}

fn exact_memory_operation<'a>(
    state: &'a MemoryState,
    expected: &StoredBrokerOperation,
) -> Result<&'a StoredBrokerOperation, StateError> {
    let stored = state
        .broker_operations
        .get(&broker_memory_key(&expected.key, expected.operation))
        .ok_or(StateError::BrokerOperationNotFound)?;
    if !stored.matches_intent(expected) || !stored.same_request_material(expected) {
        return Err(StateError::BrokerOperationMismatch);
    }
    Ok(stored)
}

fn exact_memory_operation_mut<'a>(
    state: &'a mut MemoryState,
    expected: &StoredBrokerOperation,
) -> Result<&'a mut StoredBrokerOperation, StateError> {
    let stored = state
        .broker_operations
        .get_mut(&broker_memory_key(&expected.key, expected.operation))
        .ok_or(StateError::BrokerOperationNotFound)?;
    if !stored.matches_intent(expected) || !stored.same_request_material(expected) {
        return Err(StateError::BrokerOperationMismatch);
    }
    Ok(stored)
}

fn finish_memory_secret_observation(
    stored: &mut StoredBrokerOperation,
    observation: BrokerSecretObservation,
    direct_create: bool,
) -> Result<(), StateError> {
    let evidence = observation.evidence_commitment();
    let (phase, outcome, observed_uid) = match (stored.operation, observation) {
        (
            BrokerJournalOperation::CreateSecret,
            BrokerSecretObservation::Matching { secret_uid, .. },
        ) => (
            BrokerJournalPhase::Committed,
            BrokerJournalOutcome::CreateMatching,
            Some(secret_uid),
        ),
        (BrokerJournalOperation::CreateSecret, BrokerSecretObservation::Conflicting { .. })
            if !direct_create =>
        {
            (
                BrokerJournalPhase::Terminal,
                BrokerJournalOutcome::CreateConflicting,
                None,
            )
        }
        (BrokerJournalOperation::DeleteSecret, BrokerSecretObservation::Absent { .. })
            if !direct_create =>
        {
            (
                BrokerJournalPhase::Committed,
                BrokerJournalOutcome::DeleteAbsent,
                stored.bound_secret_uid.clone(),
            )
        }
        (
            BrokerJournalOperation::DeleteSecret,
            BrokerSecretObservation::Matching { .. } | BrokerSecretObservation::Conflicting { .. },
        ) if !direct_create => (
            BrokerJournalPhase::Terminal,
            BrokerJournalOutcome::DeleteConflicting,
            stored.bound_secret_uid.clone(),
        ),
        _ => return Err(StateError::BrokerOperationMismatch),
    };
    stored.bound_secret_uid = observed_uid;
    stored.phase = phase;
    stored.outcome = Some(outcome);
    stored.provider_evidence_commitment = Some(evidence);
    stored.result_commitment = Some(broker_result_commitment(
        stored.request_commitment,
        outcome,
        stored.bound_secret_uid.as_deref(),
        evidence,
        None,
        None,
    )?);
    stored.validate()
}

impl BrokerJournalState for InMemoryStore {
    fn issue_broker_journal_capability(&mut self) -> Result<BrokerJournalCapability, StateError> {
        self.broker_capability_issuer.issue(self.state_instance_id)
    }

    fn prepare_broker_operation(
        &self,
        capability: &BrokerJournalCapability,
        request: BrokerOperationRequest,
    ) -> Result<BrokerOperationIntent, StateError> {
        self.require_broker_capability(capability)?;
        let mut state = self.inner.lock();
        let token = request.token();
        require_memory_token(self.state_instance_id, &state, token)?;
        let acquisition = require_memory_bootstrap_acquisition(&state, token)?.clone();
        let observed_at = self.clock.now_unix_seconds()?;
        let snapshot =
            memory_dispatch_snapshot_with_high_water(&mut state, token.key(), observed_at)?;
        if snapshot.checked_at() >= token.lease_until() {
            return Err(StateError::DispatchClaimLeaseExpired {
                observed: snapshot.checked_at(),
                lease_until: token.lease_until(),
            });
        }
        if PhysicalResourceKey::from_authorization(snapshot.issued().authorization())?
            != *token.physical_resource()
        {
            return Err(StateError::BrokerOperationMismatch);
        }
        let bound_secret_uid = if request.operation() == BrokerJournalOperation::IssueToken {
            Some(
                require_matching_create(&state, token.key(), request.route_commitment())?
                    .bound_secret_uid
                    .clone()
                    .ok_or(StateError::BrokerOperationMismatch)?,
            )
        } else {
            None
        };
        let candidate = StoredBrokerOperation::new_intent(
            Uuid::new_v4(),
            token.key().clone(),
            token.claim_id(),
            token.fence(),
            token.state_instance_id(),
            acquisition.acquisition_id,
            acquisition.lease_fence,
            token.physical_resource().clone(),
            request.route_commitment(),
            bound_secret_uid,
            request.operation(),
            snapshot.checked_at(),
            request.credential_policy(),
        )?;
        adopt_or_insert_memory_intent(&mut state, candidate)
    }

    fn begin_broker_operation_for_acquisition(
        &self,
        capability: &BrokerJournalCapability,
        authority: &DispatchAcquisitionAuthority,
        request: AcquiredBrokerOperationRequest,
    ) -> Result<BrokerIoAuthority, StateError> {
        self.require_broker_capability(capability)?;
        authority.claim().key().validate()?;
        if !request.matches_authority(authority) {
            return Err(StateError::BrokerOperationMismatch);
        }
        let mut state = self.inner.lock();
        require_memory_control_acquisition(self.state_instance_id, &state, authority)?;
        let observed_at = self.clock.now_unix_seconds()?;
        let (snapshot, acquisition) = memory_revalidate_control_acquisition_locked(
            self.state_instance_id,
            &mut state,
            authority,
            observed_at,
        )?;
        let bound_secret_uid = if request.operation() == BrokerJournalOperation::IssueToken {
            Some(
                require_matching_create_for_acquisition(
                    &state,
                    authority,
                    request.route_commitment(),
                )?
                .bound_secret_uid
                .clone()
                .ok_or(StateError::BrokerOperationMismatch)?,
            )
        } else {
            None
        };
        let candidate = StoredBrokerOperation::new_intent(
            Uuid::new_v4(),
            authority.claim().key().clone(),
            authority.claim().claim_id(),
            authority.claim().fence(),
            authority.claim().state_instance_id(),
            acquisition.acquisition_id,
            acquisition.lease_fence,
            authority.claim().physical_resource().clone(),
            request.route_commitment(),
            bound_secret_uid,
            request.operation(),
            snapshot.checked_at(),
            request.credential_policy(),
        )?;
        let operation_key = broker_memory_key(&candidate.key, candidate.operation);
        let expected = if let Some(existing) = state.broker_operations.get(&operation_key) {
            existing.validate()?;
            if !existing.same_request_material(&candidate) {
                return Err(StateError::BrokerOperationMismatch);
            }
            if existing.phase != BrokerJournalPhase::Intent {
                return Err(StateError::BrokerOperationOutcomeUnknown);
            }
            existing.clone()
        } else {
            state
                .broker_operations
                .insert(operation_key.clone(), candidate.clone());
            candidate
        };
        let current = state
            .broker_operations
            .get(&operation_key)
            .ok_or(StateError::BrokerOperationNotFound)?;
        if !current.matches_intent(&expected)
            || !current.same_request_material(&expected)
            || current.phase != BrokerJournalPhase::Intent
        {
            return Err(StateError::BrokerOperationOutcomeUnknown);
        }
        let mut started = current.clone();
        started.phase = BrokerJournalPhase::InFlight;
        started.started_at = Some(observed_at);
        if let Some(policy) = started.credential_policy {
            started.credential_safe_after = Some(policy.safe_after(observed_at)?);
        }
        started.validate()?;
        state
            .broker_operations
            .insert(operation_key, started.clone());
        Ok(BrokerIoAuthority::new(started))
    }

    #[allow(clippy::too_many_lines)]
    fn begin_dispatch_credential_review(
        &self,
        capability: &BrokerJournalCapability,
        authority: &DispatchAcquisitionAuthority,
        token_journal: &BrokerJournalSelector,
    ) -> Result<CredentialReviewIoAuthority, StateError> {
        self.require_broker_capability(capability)?;
        authority.claim().key().validate()?;
        if token_journal.key() != authority.claim().key()
            || token_journal.operation() != BrokerJournalOperation::IssueToken
            || token_journal.origin_acquisition_id() != authority.acquisition_id()
            || token_journal.origin_lease_fence() != authority.lease_fence()
        {
            return Err(StateError::DispatchCredentialReviewMismatch);
        }
        let mut state = self.inner.lock();
        require_memory_control_acquisition(self.state_instance_id, &state, authority)?;
        if state.credential_reviews.contains_key(&(
            authority.claim().key().scope.clone(),
            authority.claim().key().authorization_id,
        )) {
            return Err(StateError::DispatchCredentialReviewOutcomeUnknown);
        }
        let observed_at = self.clock.now_unix_seconds()?;
        let (snapshot, acquisition) = memory_revalidate_control_acquisition_locked(
            self.state_instance_id,
            &mut state,
            authority,
            observed_at,
        )?;
        let issue = state
            .broker_operations
            .get(&broker_memory_key(
                authority.claim().key(),
                BrokerJournalOperation::IssueToken,
            ))
            .ok_or(StateError::BrokerOperationNotFound)?;
        issue.validate()?;
        if issue.entry_id != token_journal.entry_id()
            || issue.request_commitment != token_journal.request_commitment()
            || issue.phase != BrokerJournalPhase::Committed
            || issue.outcome != Some(BrokerJournalOutcome::TokenIssued)
            || issue.acquisition_binding_version != 2
            || issue.origin_acquisition_id != acquisition.acquisition_id
            || issue.origin_lease_fence != acquisition.lease_fence
        {
            return Err(StateError::DispatchCredentialReviewMismatch);
        }
        let create =
            require_matching_create_for_acquisition(&state, authority, issue.route_commitment)?;
        let expected_token_digest = issue
            .token_digest
            .ok_or(StateError::DispatchCredentialReviewMismatch)?;
        let expected_token_expires_at = issue
            .token_expires_at
            .ok_or(StateError::DispatchCredentialReviewMismatch)?;
        let expected_bound_secret_uid = issue
            .bound_secret_uid
            .clone()
            .ok_or(StateError::DispatchCredentialReviewMismatch)?;
        if create.bound_secret_uid.as_deref() != Some(&expected_bound_secret_uid) {
            return Err(StateError::DispatchCredentialReviewMismatch);
        }
        let destination = memory_destination_for_authority(
            &state,
            &authority.claim().key().scope,
            snapshot.authority(),
        )
        .map_err(|_| StateError::DispatchCredentialReviewMismatch)?;
        let facts = derive_attempt_facts(
            &authority.claim().key().scope,
            authority.claim().key().transaction_id,
            authority.claim().key().authorization_id,
            snapshot.issued().authorization().template_hash,
            &snapshot.issued().authorization().template,
            &destination,
        )
        .map_err(|_| StateError::DispatchCredentialReviewMismatch)?;
        if facts.physical_resource() != authority.claim().physical_resource() {
            return Err(StateError::DispatchCredentialReviewMismatch);
        }
        let mut review_id = Uuid::new_v4();
        while state.credential_review_ids.contains_key(&review_id)
            || state.dispatch_claim_ids.contains_key(&review_id)
            || state.dispatch_acquisitions.contains_key(&review_id)
            || state.dispatch_dispositions.contains_key(&review_id)
        {
            review_id = Uuid::new_v4();
        }
        let stored = StoredDispatchCredentialReview {
            review_id,
            token: authority.claim().clone(),
            acquisition_id: authority.acquisition_id(),
            lease_fence: authority.lease_fence(),
            acquisition_worker_id: authority.worker_id().to_owned(),
            acquired_at: authority.acquired_at(),
            lease_until: authority.lease_until(),
            dispatch_deadline: authority.dispatch_deadline(),
            control_submission_id: authority.control_submission_id(),
            create_entry_id: create.entry_id,
            create_request_commitment: create.request_commitment,
            create_result_commitment: create
                .result_commitment
                .ok_or(StateError::DispatchCredentialReviewMismatch)?,
            token_entry_id: issue.entry_id,
            token_request_commitment: issue.request_commitment,
            token_result_commitment: issue
                .result_commitment
                .ok_or(StateError::DispatchCredentialReviewMismatch)?,
            expected_route_commitment: Digest32::from_bytes(*facts.route().commitment().as_bytes()),
            token_credential_policy: issue
                .credential_policy
                .ok_or(StateError::DispatchCredentialReviewMismatch)?,
            expected_token_digest,
            expected_token_expires_at,
            expected_subject: facts.token_subject().to_owned(),
            expected_audience: facts.token_audience().to_owned(),
            expected_service_account_uid: facts.service_account_uid().to_owned(),
            expected_bound_secret_uid,
            credential_lifecycle_policy: facts.credential_lifecycle_policy(),
            destination_activation_commitment: facts.activation_commitment(),
            phase: DispatchCredentialReviewPhase::InFlight,
            begun_at: snapshot.checked_at(),
            reviewed_at: None,
            claims: None,
            review_evidence_commitment: None,
            review_commitment: None,
        };
        stored.validate()?;
        let review_key = (
            authority.claim().key().scope.clone(),
            authority.claim().key().authorization_id,
        );
        state
            .credential_review_ids
            .insert(review_id, review_key.clone());
        state.credential_reviews.insert(review_key, stored.clone());
        Ok(CredentialReviewIoAuthority::new(stored))
    }

    fn record_authenticated_dispatch_credential(
        &self,
        authority: CredentialReviewIoAuthority,
        observation: AuthenticatedDispatchCredentialReview,
    ) -> Result<ReviewedDispatchCredential, StateError> {
        let expected = authority.stored;
        expected.validate()?;
        let mut state = self.inner.lock();
        let review_key = (
            expected.token.key().scope.clone(),
            expected.token.key().authorization_id,
        );
        let current = state
            .credential_reviews
            .get(&review_key)
            .ok_or(StateError::DispatchCredentialReviewNotFound)?;
        if current != &expected || current.phase != DispatchCredentialReviewPhase::InFlight {
            return Err(StateError::DispatchCredentialReviewOutcomeUnknown);
        }
        validate_memory_credential_review_frozen_lineage(&state, current)?;
        let acquisition_authority = current.authority();
        require_memory_control_acquisition(self.state_instance_id, &state, &acquisition_authority)?;
        let observed_at = self.clock.now_unix_seconds()?;
        let (snapshot, _) = memory_revalidate_control_acquisition_locked(
            self.state_instance_id,
            &mut state,
            &acquisition_authority,
            observed_at,
        )?;
        if observation.claims().not_before() > snapshot.checked_at()
            || observation.claims().expires_at() <= snapshot.checked_at()
        {
            return Err(StateError::DispatchCredentialExpired);
        }
        let current = state
            .credential_reviews
            .get(&review_key)
            .ok_or(StateError::DispatchCredentialReviewNotFound)?;
        let terminal = current.finish_authenticated(observation, snapshot.checked_at())?;
        validate_memory_credential_review_frozen_lineage(&state, &terminal)?;
        let reviewed = terminal.reviewed_credential()?;
        state.credential_reviews.insert(review_key, terminal);
        Ok(reviewed)
    }

    fn recover_authenticated_dispatch_credential(
        &self,
        key: &DispatchCredentialReviewRecoveryKey,
    ) -> Result<ReviewedDispatchCredential, StateError> {
        key.key().validate()?;
        if key.review_id().is_nil() || key.acquisition_id().is_nil() || key.lease_fence() == 0 {
            return Err(StateError::DispatchCredentialReviewMismatch);
        }
        let state = self.inner.lock();
        let review = state
            .credential_reviews
            .get(&(key.key().scope.clone(), key.key().authorization_id))
            .ok_or(StateError::DispatchCredentialReviewNotFound)?;
        if review.token.key() != key.key()
            || review.review_id != key.review_id()
            || review.acquisition_id != key.acquisition_id()
            || review.lease_fence != key.lease_fence()
        {
            return Err(StateError::DispatchCredentialReviewMismatch);
        }
        validate_memory_credential_review_frozen_lineage(&state, review)?;
        review.reviewed_credential()
    }

    fn record_rejected_dispatch_credential(
        &self,
        authority: CredentialReviewIoAuthority,
        observation: RejectedDispatchCredentialReview,
    ) -> Result<DispatchCredentialReviewAudit, StateError> {
        let expected = authority.stored;
        expected.validate()?;
        let mut state = self.inner.lock();
        let review_key = (
            expected.token.key().scope.clone(),
            expected.token.key().authorization_id,
        );
        let current = state
            .credential_reviews
            .get(&review_key)
            .ok_or(StateError::DispatchCredentialReviewNotFound)?;
        if current != &expected || current.phase != DispatchCredentialReviewPhase::InFlight {
            return Err(StateError::DispatchCredentialReviewOutcomeUnknown);
        }
        validate_memory_credential_review_frozen_lineage(&state, current)?;
        let observed_at = self.clock.now_unix_seconds()?;
        let stored = if let Some(submission_id) = current.control_submission_id {
            memory_control_submission_for_dispatch(&state, submission_id, current.token.key())?
                .clone()
        } else {
            return Err(StateError::DispatchCredentialReviewMismatch);
        };
        let high_water = memory_control_high_water(&state, &stored)?;
        if observed_at < high_water {
            return Err(StateError::ClockRollback {
                observed: observed_at,
                high_water,
            });
        }
        let terminal = current.finish_rejected(observation, observed_at)?;
        memory_advance_control_high_water(&mut state, &stored, observed_at)?;
        state
            .credential_reviews
            .insert(review_key, terminal.clone());
        Ok(DispatchCredentialReviewAudit::new(terminal))
    }

    fn dispatch_credential_review_audit(
        &self,
        acquisition_key: &crate::DispatchAcquisitionRecoveryKey,
    ) -> Result<DispatchCredentialReviewAudit, StateError> {
        acquisition_key.scope().validate()?;
        if acquisition_key.acquisition_id().is_nil()
            || !crate::acquisition::valid_worker_id(acquisition_key.worker_id())
        {
            return Err(StateError::DispatchCredentialReviewMismatch);
        }
        let state = self.inner.lock();
        let acquisition = state
            .dispatch_acquisitions
            .get(&acquisition_key.acquisition_id())
            .ok_or(StateError::DispatchCredentialReviewNotFound)?;
        if acquisition.token.key().scope != *acquisition_key.scope()
            || acquisition.worker_id != acquisition_key.worker_id()
        {
            return Err(StateError::DispatchCredentialReviewMismatch);
        }
        let key = acquisition.token.key();
        let review = state
            .credential_reviews
            .get(&(key.scope.clone(), key.authorization_id))
            .ok_or(StateError::DispatchCredentialReviewNotFound)?;
        if review.token.key() != key || review.acquisition_id != acquisition_key.acquisition_id() {
            return Err(StateError::DispatchCredentialReviewMismatch);
        }
        validate_memory_credential_review_frozen_lineage(&state, review)?;
        Ok(DispatchCredentialReviewAudit::new(review.clone()))
    }

    #[allow(clippy::too_many_lines)]
    fn dispatch_broker_restart_context(
        &self,
        acquisition_key: &crate::DispatchAcquisitionRecoveryKey,
    ) -> Result<DispatchBrokerRestartContext, StateError> {
        let state = self.inner.lock();
        let acquisition = memory_acquisition_from_recovery_key(&state, acquisition_key)?;
        let key = acquisition.token.key();
        let claim = state
            .dispatch_claims
            .get(&(key.scope.clone(), key.authorization_id))
            .ok_or(StateError::DispatchClaimNotFound)?;
        if claim.token != acquisition.token {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        let issued = state
            .authorizations
            .get(&(key.scope.clone(), key.authorization_id))
            .ok_or(StateError::AuthorizationNotFound)?;
        let receipt = state
            .receipts
            .get(&(key.scope.clone(), key.authorization_id))
            .ok_or(StateError::ConsumptionNotFound)?;
        let outbox = state
            .outbox
            .get(&(key.scope.clone(), key.authorization_id))
            .ok_or(StateError::ConsumptionNotFound)?;
        validate_recovered_consumption(key, issued, receipt, outbox)?;
        let destination = memory_frozen_destination_for_authority(
            &state,
            &key.scope,
            &issued.authorization().authority,
        )
        .map_err(|_| StateError::BrokerOperationMismatch)?;
        let facts = derive_attempt_facts(
            &key.scope,
            key.transaction_id,
            key.authorization_id,
            issued.authorization().template_hash,
            &issued.authorization().template,
            &destination,
        )
        .map_err(|_| StateError::BrokerOperationMismatch)?;
        if facts.physical_resource() != acquisition.token.physical_resource() {
            return Err(StateError::BrokerOperationMismatch);
        }
        let rooted_route = Digest32::from_bytes(*facts.route().commitment().as_bytes());
        let create = state
            .broker_operations
            .get(&broker_memory_key(
                key,
                BrokerJournalOperation::CreateSecret,
            ))
            .ok_or(StateError::BrokerOperationNotFound)?;
        create.validate()?;
        let valid_binding_version = match acquisition.selection_kind {
            MemoryDispatchAcquisitionKind::ControlQueue => create.acquisition_binding_version == 2,
            MemoryDispatchAcquisitionKind::ControlBootstrapV13 => {
                create.acquisition_binding_version == 1
            }
            MemoryDispatchAcquisitionKind::LegacyBootstrap => {
                matches!(create.acquisition_binding_version, 1 | 2)
            }
        };
        if create.key != *key
            || create.claim_id != acquisition.token.claim_id()
            || create.fence != acquisition.token.fence()
            || create.state_instance_id != acquisition.token.state_instance_id()
            || create.origin_acquisition_id != acquisition.acquisition_id
            || create.origin_lease_fence != acquisition.lease_fence
            || !valid_binding_version
            || create.physical_resource != *acquisition.token.physical_resource()
            || create.route_commitment != rooted_route
        {
            return Err(StateError::BrokerOperationMismatch);
        }
        let issue = state
            .broker_operations
            .get(&broker_memory_key(key, BrokerJournalOperation::IssueToken));
        if let Some(issue) = issue {
            issue.validate()?;
            if issue.key != *key
                || issue.claim_id != create.claim_id
                || issue.fence != create.fence
                || issue.state_instance_id != create.state_instance_id
                || issue.origin_acquisition_id != create.origin_acquisition_id
                || issue.origin_lease_fence != create.origin_lease_fence
                || issue.acquisition_binding_version != create.acquisition_binding_version
                || issue.physical_resource != create.physical_resource
                || issue.route_commitment != rooted_route
                || issue.bound_secret_uid != create.bound_secret_uid
            {
                return Err(StateError::BrokerOperationMismatch);
            }
        }
        let review = state
            .credential_reviews
            .get(&(key.scope.clone(), key.authorization_id));
        if let Some(review) = review {
            if create.acquisition_binding_version != 2
                || review.acquisition_id != acquisition.acquisition_id
            {
                return Err(StateError::DispatchCredentialReviewMismatch);
            }
            validate_memory_credential_review_frozen_lineage(&state, review)?;
        }
        let delete = state.broker_operations.get(&broker_memory_key(
            key,
            BrokerJournalOperation::DeleteSecret,
        ));
        if let Some(delete) = delete {
            delete.validate()?;
            if delete.claim_id != create.claim_id
                || delete.fence != create.fence
                || delete.state_instance_id != create.state_instance_id
                || delete.origin_acquisition_id != create.origin_acquisition_id
                || delete.origin_lease_fence != create.origin_lease_fence
                || (acquisition.selection_kind == MemoryDispatchAcquisitionKind::ControlQueue
                    && delete.acquisition_binding_version != 2)
                || (acquisition.selection_kind
                    == MemoryDispatchAcquisitionKind::ControlBootstrapV13
                    && !matches!(delete.acquisition_binding_version, 1 | 2))
                || (acquisition.selection_kind == MemoryDispatchAcquisitionKind::LegacyBootstrap
                    && delete.acquisition_binding_version != create.acquisition_binding_version)
                || delete.physical_resource != create.physical_resource
                || delete.route_commitment != rooted_route
                || delete.bound_secret_uid != create.bound_secret_uid
            {
                return Err(StateError::BrokerOperationMismatch);
            }
            if delete.phase == BrokerJournalPhase::Committed
                && delete.outcome == Some(BrokerJournalOutcome::DeleteAbsent)
            {
                let deletion = state
                    .secret_deletion_observations
                    .get(&(key.scope.clone(), key.authorization_id))
                    .ok_or(StateError::BrokerOperationMismatch)?;
                let exact = StoredSecretDeletionObservation::from_committed_delete(
                    delete,
                    deletion.observed_at,
                )?;
                if deletion != &exact
                    || state.secret_deletion_entry_ids.get(&delete.entry_id)
                        != Some(&(key.scope.clone(), key.authorization_id))
                {
                    return Err(StateError::BrokerOperationMismatch);
                }
                let rejected_review = state
                    .credential_reviews
                    .get(&(key.scope.clone(), key.authorization_id))
                    .filter(|review| review.phase == DispatchCredentialReviewPhase::Rejected)
                    .and_then(|review| {
                        review
                            .reviewed_at
                            .zip(review.review_evidence_commitment)
                            .filter(|(reviewed_at, _)| *reviewed_at >= deletion.observed_at)
                    });
                let evidence = DispatchRestartDeletionEvidence::new(
                    deletion.observed_at,
                    deletion.provider_evidence_commitment,
                    facts.credential_lifecycle_policy(),
                    rejected_review.map(|facts| facts.0),
                    rejected_review.map(|facts| facts.1),
                )?;
                return Ok(DispatchBrokerRestartContext::deletion_already_absent(
                    key.clone(),
                    evidence,
                ));
            }
        }
        if claim.state == MemoryDispatchClaimState::RecoveryNoSend
            && create.phase == BrokerJournalPhase::ReconcileOnly
            && create.outcome.is_none()
            && create.bound_secret_uid.is_none()
            && create.reconciliation_count > 0
            && create.last_reconciliation_outcome == Some(BrokerJournalOutcome::CreateAbsent)
            && create.last_reconciliation_evidence_commitment.is_some()
            && create.last_reconciled_at.is_some()
            && issue.is_none()
            && review.is_none()
            && delete.is_none()
        {
            return Ok(DispatchBrokerRestartContext::creation_already_absent(
                key.clone(),
            ));
        }
        match (create.phase, create.outcome) {
            (BrokerJournalPhase::Committed, Some(BrokerJournalOutcome::CreateMatching)) => {
                Ok(DispatchBrokerRestartContext::cleanup_secret(
                    BrokerCleanupRequest::new(key.clone(), *rooted_route.as_bytes())?,
                ))
            }
            (
                BrokerJournalPhase::Intent
                | BrokerJournalPhase::InFlight
                | BrokerJournalPhase::Unknown
                | BrokerJournalPhase::ReconcileOnly,
                None,
            ) => Ok(DispatchBrokerRestartContext::reconcile_create(
                BrokerReconciliationRequest::new(
                    key.clone(),
                    BrokerJournalOperation::CreateSecret,
                    *rooted_route.as_bytes(),
                )?,
            )),
            _ => Err(StateError::BrokerOperationInvalidTransition),
        }
    }

    fn prepare_broker_cleanup(
        &self,
        capability: &BrokerJournalCapability,
        request: &BrokerCleanupRequest,
    ) -> Result<BrokerOperationIntent, StateError> {
        self.require_broker_capability(capability)?;
        let mut state = self.inner.lock();
        let token = require_memory_claim(&state, request.key())?.token.clone();
        if token.state_instance_id() != self.state_instance_id {
            return Err(StateError::BrokerOperationMismatch);
        }
        let (bound_secret_uid, origin_acquisition_id, origin_lease_fence) = {
            let create =
                require_matching_create(&state, request.key(), request.route_commitment())?;
            (
                create
                    .bound_secret_uid
                    .clone()
                    .ok_or(StateError::BrokerOperationMismatch)?,
                create.origin_acquisition_id,
                create.origin_lease_fence,
            )
        };
        let historical_delete = state
            .broker_operations
            .get(&broker_memory_key(
                request.key(),
                BrokerJournalOperation::DeleteSecret,
            ))
            .filter(|delete| delete.acquisition_binding_version == 1)
            .cloned();
        if let Some(delete) = &historical_delete {
            let origin = state
                .dispatch_acquisitions
                .get(&origin_acquisition_id)
                .ok_or(StateError::DispatchAcquisitionMismatch)?;
            delete.validate()?;
            if origin.selection_kind != MemoryDispatchAcquisitionKind::ControlBootstrapV13
                || origin.acquisition_id != origin.token.claim_id()
                || origin.lease_fence != origin.token.fence()
                || delete.phase != BrokerJournalPhase::Intent
                || delete.key != *request.key()
                || delete.claim_id != token.claim_id()
                || delete.fence != token.fence()
                || delete.state_instance_id != token.state_instance_id()
                || delete.origin_acquisition_id != origin_acquisition_id
                || delete.origin_lease_fence != origin_lease_fence
                || delete.physical_resource != *token.physical_resource()
                || delete.route_commitment != request.route_commitment()
                || delete.bound_secret_uid.as_deref() != Some(&bound_secret_uid)
            {
                return Err(StateError::BrokerOperationMismatch);
            }
        }
        let control_submission = memory_cleanup_control_submission(
            &state,
            request.key(),
            origin_acquisition_id,
            origin_lease_fence,
        )?;
        let observed_at = self.clock.now_unix_seconds()?;
        memory_advance_cleanup_high_water(
            &mut state,
            request.key(),
            control_submission.as_ref(),
            observed_at,
        )?;
        if let Some(delete) = historical_delete {
            return Ok(BrokerOperationIntent::new(delete));
        }
        let candidate = StoredBrokerOperation::new_intent(
            Uuid::new_v4(),
            request.key().clone(),
            token.claim_id(),
            token.fence(),
            token.state_instance_id(),
            origin_acquisition_id,
            origin_lease_fence,
            token.physical_resource().clone(),
            request.route_commitment(),
            Some(bound_secret_uid),
            BrokerJournalOperation::DeleteSecret,
            observed_at,
            None,
        )?;
        adopt_or_insert_memory_intent(&mut state, candidate)
    }

    fn begin_broker_io(
        &self,
        capability: &BrokerJournalCapability,
        intent: BrokerOperationIntent,
    ) -> Result<BrokerIoAuthority, StateError> {
        self.require_broker_capability(capability)?;
        let expected = intent.stored;
        let mut state = self.inner.lock();
        let current = exact_memory_operation(&state, &expected)?;
        if current.phase != BrokerJournalPhase::Intent {
            return Err(StateError::BrokerOperationOutcomeUnknown);
        }
        let token = require_memory_claim(&state, &expected.key)?.token.clone();
        if token.claim_id() != expected.claim_id
            || token.fence() != expected.fence
            || token.state_instance_id() != expected.state_instance_id
            || token.physical_resource() != &expected.physical_resource
        {
            return Err(StateError::BrokerOperationMismatch);
        }
        if expected.operation != BrokerJournalOperation::DeleteSecret {
            require_memory_bootstrap_acquisition(&state, &token)?;
        }
        let cleanup_submission = if expected.operation == BrokerJournalOperation::DeleteSecret {
            memory_cleanup_control_submission(
                &state,
                &expected.key,
                expected.origin_acquisition_id,
                expected.origin_lease_fence,
            )?
        } else {
            None
        };
        let observed_at = self.clock.now_unix_seconds()?;
        if expected.operation == BrokerJournalOperation::DeleteSecret {
            memory_advance_cleanup_high_water(
                &mut state,
                &expected.key,
                cleanup_submission.as_ref(),
                observed_at,
            )?;
        } else {
            require_memory_token(self.state_instance_id, &state, &token)?;
            let snapshot =
                memory_dispatch_snapshot_with_high_water(&mut state, &expected.key, observed_at)?;
            if snapshot.checked_at() >= token.lease_until() {
                return Err(StateError::DispatchClaimLeaseExpired {
                    observed: snapshot.checked_at(),
                    lease_until: token.lease_until(),
                });
            }
        }
        let stored = exact_memory_operation_mut(&mut state, &expected)?;
        if stored.phase != BrokerJournalPhase::Intent {
            return Err(StateError::BrokerOperationOutcomeUnknown);
        }
        stored.phase = BrokerJournalPhase::InFlight;
        stored.started_at = Some(observed_at);
        if let Some(policy) = stored.credential_policy {
            stored.credential_safe_after = Some(policy.safe_after(observed_at)?);
        }
        stored.validate()?;
        Ok(BrokerIoAuthority::new(stored.clone()))
    }

    fn commit_broker_create(
        &self,
        authority: BrokerIoAuthority,
        observation: BrokerSecretObservation,
    ) -> Result<BrokerOperationReceipt, StateError> {
        let expected = authority.stored;
        if expected.operation != BrokerJournalOperation::CreateSecret {
            return Err(StateError::BrokerOperationMismatch);
        }
        let mut state = self.inner.lock();
        let stored = exact_memory_operation_mut(&mut state, &expected)?;
        if stored.phase != BrokerJournalPhase::InFlight {
            return Err(StateError::BrokerOperationOutcomeUnknown);
        }
        finish_memory_secret_observation(stored, observation, true)?;
        Ok(BrokerOperationReceipt::new(stored.audit(), false))
    }

    fn commit_broker_token_issue(
        &self,
        authority: BrokerIoAuthority,
        observation: &BrokerTokenIssueObservation,
    ) -> Result<BrokerOperationReceipt, StateError> {
        let expected = authority.stored;
        if expected.operation != BrokerJournalOperation::IssueToken {
            return Err(StateError::BrokerOperationMismatch);
        }
        let mut state = self.inner.lock();
        let stored = exact_memory_operation_mut(&mut state, &expected)?;
        if stored.phase != BrokerJournalPhase::InFlight {
            return Err(StateError::BrokerOperationOutcomeUnknown);
        }
        let started_at = stored
            .started_at
            .ok_or(StateError::BrokerOperationMismatch)?;
        let safe_after = stored
            .credential_safe_after
            .ok_or(StateError::BrokerOperationMismatch)?;
        if observation.expires_at() <= started_at || observation.expires_at() > safe_after {
            return Err(StateError::BrokerOperationMismatch);
        }
        stored.phase = BrokerJournalPhase::Committed;
        stored.outcome = Some(BrokerJournalOutcome::TokenIssued);
        stored.provider_evidence_commitment = Some(observation.evidence_commitment());
        stored.token_digest = Some(observation.token_digest());
        stored.token_expires_at = Some(observation.expires_at());
        stored.result_commitment = Some(broker_result_commitment(
            stored.request_commitment,
            BrokerJournalOutcome::TokenIssued,
            stored.bound_secret_uid.as_deref(),
            observation.evidence_commitment(),
            Some(observation.token_digest()),
            Some(observation.expires_at()),
        )?);
        stored.validate()?;
        Ok(BrokerOperationReceipt::new(stored.audit(), false))
    }

    fn mark_broker_io_unknown(
        &self,
        authority: BrokerIoAuthority,
    ) -> Result<BrokerOperationAudit, StateError> {
        let expected = authority.stored;
        let mut state = self.inner.lock();
        let stored = exact_memory_operation_mut(&mut state, &expected)?;
        if stored.phase == BrokerJournalPhase::Unknown {
            return Ok(stored.audit());
        }
        if stored.phase != BrokerJournalPhase::InFlight {
            return Err(StateError::BrokerOperationInvalidTransition);
        }
        stored.phase = BrokerJournalPhase::Unknown;
        stored.validate()?;
        Ok(stored.audit())
    }

    fn begin_broker_reconciliation(
        &self,
        capability: &BrokerJournalCapability,
        request: &BrokerReconciliationRequest,
    ) -> Result<BrokerReconciliationAuthority, StateError> {
        self.require_broker_capability(capability)?;
        if request.operation() == BrokerJournalOperation::IssueToken {
            return Err(StateError::BrokerTokenReissueForbidden);
        }
        let mut state = self.inner.lock();
        let key = broker_memory_key(request.key(), request.operation());
        let existing = state
            .broker_operations
            .get(&key)
            .ok_or(StateError::BrokerOperationNotFound)?;
        if existing.route_commitment != request.route_commitment() {
            return Err(StateError::BrokerOperationMismatch);
        }
        let token = require_memory_claim(&state, request.key())?.token.clone();
        if token.claim_id() != existing.claim_id
            || token.fence() != existing.fence
            || token.state_instance_id() != existing.state_instance_id
            || token.physical_resource() != &existing.physical_resource
        {
            return Err(StateError::BrokerOperationMismatch);
        }
        let control_submission = memory_cleanup_control_submission(
            &state,
            request.key(),
            existing.origin_acquisition_id,
            existing.origin_lease_fence,
        )?;
        let observed_at = self.clock.now_unix_seconds()?;
        memory_advance_cleanup_high_water(
            &mut state,
            request.key(),
            control_submission.as_ref(),
            observed_at,
        )?;
        let stored = state
            .broker_operations
            .get_mut(&key)
            .ok_or(StateError::BrokerOperationNotFound)?;
        match stored.phase {
            BrokerJournalPhase::Intent => {
                stored.started_at = Some(observed_at);
                stored.phase = BrokerJournalPhase::ReconcileOnly;
            }
            BrokerJournalPhase::InFlight | BrokerJournalPhase::Unknown => {
                stored.phase = BrokerJournalPhase::ReconcileOnly;
            }
            BrokerJournalPhase::ReconcileOnly => {}
            _ => return Err(StateError::BrokerOperationInvalidTransition),
        }
        stored.validate()?;
        Ok(BrokerReconciliationAuthority::new(stored.clone()))
    }

    fn commit_broker_reconciliation(
        &self,
        authority: BrokerReconciliationAuthority,
        observation: BrokerSecretObservation,
    ) -> Result<BrokerReconciliationResult, StateError> {
        let expected = authority.stored;
        let mut state = self.inner.lock();
        let current = exact_memory_operation(&state, &expected)?.clone();
        if current.phase != BrokerJournalPhase::ReconcileOnly
            || current.reconciliation_count != expected.reconciliation_count
        {
            return Err(StateError::BrokerOperationInvalidTransition);
        }
        let control_submission = memory_cleanup_control_submission(
            &state,
            &expected.key,
            current.origin_acquisition_id,
            current.origin_lease_fence,
        )?;
        let observed_at = self.clock.now_unix_seconds()?;
        memory_advance_cleanup_high_water(
            &mut state,
            &expected.key,
            control_submission.as_ref(),
            observed_at,
        )?;
        let mut next = current;
        let result = if let Some((outcome, evidence)) =
            pending_broker_reconciliation(&next, &observation)
        {
            next.reconciliation_count = next
                .reconciliation_count
                .checked_add(1)
                .ok_or(StateError::BrokerOperationOutcomeUnknown)?;
            next.last_reconciliation_outcome = Some(outcome);
            next.last_reconciliation_evidence_commitment = Some(evidence);
            next.last_reconciled_at = Some(observed_at);
            next.validate()?;
            BrokerReconciliationResult::Pending(BrokerReconciliationAuthority::new(next.clone()))
        } else {
            finish_memory_secret_observation(&mut next, observation, false)?;
            BrokerReconciliationResult::Completed(BrokerOperationReceipt::new(next.audit(), false))
        };
        let deletion_observation = if next.operation == BrokerJournalOperation::DeleteSecret
            && next.phase == BrokerJournalPhase::Committed
            && next.outcome == Some(BrokerJournalOutcome::DeleteAbsent)
        {
            Some(StoredSecretDeletionObservation::from_committed_delete(
                &next,
                observed_at,
            )?)
        } else {
            None
        };
        if let Some(deletion) = &deletion_observation {
            let observation_key = (expected.key.scope.clone(), expected.key.authorization_id);
            if state
                .secret_deletion_observations
                .get(&observation_key)
                .is_some_and(|existing| existing != deletion)
                || state
                    .secret_deletion_entry_ids
                    .get(&deletion.entry_id)
                    .is_some_and(|existing| existing != &observation_key)
            {
                return Err(StateError::BrokerOperationMismatch);
            }
        }
        state
            .broker_operations
            .insert(broker_memory_key(&expected.key, expected.operation), next);
        if let Some(deletion) = deletion_observation {
            let observation_key = (expected.key.scope.clone(), expected.key.authorization_id);
            state
                .secret_deletion_entry_ids
                .insert(deletion.entry_id, observation_key.clone());
            state
                .secret_deletion_observations
                .insert(observation_key, deletion);
        }
        Ok(result)
    }

    fn broker_operation_audit(
        &self,
        key: &ConsumeKey,
        operation: BrokerJournalOperation,
    ) -> Result<BrokerOperationAudit, StateError> {
        key.validate()?;
        let state = self.inner.lock();
        let stored = state
            .broker_operations
            .get(&broker_memory_key(key, operation))
            .ok_or(StateError::BrokerOperationNotFound)?;
        if stored.key != *key {
            return Err(StateError::BrokerOperationMismatch);
        }
        stored.validate()?;
        Ok(stored.audit())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::sync::atomic::{AtomicI64, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::{net::SocketAddr, str::FromStr as _};

    use accordlock_eks_profile::{
        CaTrustCommitment, EksBrokerManagementBindings, EksCredentialLifecyclePolicy,
        EksManagementAuthorityBinding, EksRouteProfile, EksRouteProfileInput, PinnedSocketTarget,
    };
    use accordlock_protocol::{
        AuthorityDomainState, AuthorityVector, CanonicalEncode, CapabilityGrant,
        DeploymentTemplate, Digest32, EXECUTION_AUTHORIZATION_DOMAIN, ExecutionAuthorization,
        SignedAuthorization, SigningIdentity, authorization_signer_root, canonical_hash, sign_cose,
    };
    use accordlock_terminal_witness::{
        ActivatedWitnessRegistry, CredentialRetirementClaims, EffectObservationClaims,
        EffectObservationResult, ExactExecutionOutcome, RegisteredWitnessVerifier, RetirementBasis,
        SignedEffectWitness, WitnessIssuer, WitnessRegistryAuthority, WitnessRole, WitnessScope,
        WitnessVerifierStatus, sign_credential_retirement, sign_effect_observation,
    };

    use super::*;
    use crate::{
        BrokerCredentialSafetyPolicy, DispatchDeadlinePolicy, IssuedAuthorizationRecord,
        grant_revocation_root,
    };

    #[derive(Debug)]
    struct TestClock(AtomicI64);

    impl TestClock {
        fn new(now: i64) -> Self {
            Self(AtomicI64::new(now))
        }

        fn set(&self, now: i64) {
            self.0.store(now, Ordering::SeqCst);
        }
    }

    impl TrustedClock for TestClock {
        fn now_unix_seconds(&self) -> Result<i64, StateError> {
            Ok(self.0.load(Ordering::SeqCst))
        }
    }

    fn digest(label: &str) -> Digest32 {
        Digest32::sha256(label.as_bytes())
    }

    fn domain(label: &str, epoch: u64) -> AuthorityDomainState {
        AuthorityDomainState {
            root: digest(label),
            epoch,
            activation_id: Uuid::new_v4(),
        }
    }

    fn authority() -> AuthorityVector {
        let signer = authorization_signer();
        let mut authority = AuthorityVector {
            policy: domain("policy", 1),
            registry: domain("registry", 1),
            revocation: domain("revocation", 1),
            connector: domain("connector", 1),
            resource: domain("resource", 1),
            signer: domain("signer", 1),
            mediation: domain("mediation", 1),
            grant_registry: domain("grant", 1),
            office_act_registry: domain("office", 1),
            principal_registry: domain("principal", 1),
            workload_build_allowlist: domain("build", 1),
            kernel_configuration: domain("kernel", 1),
        };
        authority.signer.root =
            authorization_signer_root(signer.key_id(), signer.public_key_bytes()).unwrap();
        authority
    }

    fn authorization_signer() -> SigningIdentity {
        SigningIdentity::from_seed("state-test-authorization", [91; 32])
    }

    fn template() -> DeploymentTemplate {
        DeploymentTemplate {
            operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
            environment: "prod".to_owned(),
            audience: "accordlock-executor:prod".to_owned(),
            repository: "acme/payments".to_owned(),
            commit_sha: "1111111111111111111111111111111111111111".to_owned(),
            image_repository: "registry.example/acme/payments".to_owned(),
            image_digest: digest("new-image"),
            cluster_identity: "cluster-a".to_owned(),
            namespace: "payments".to_owned(),
            deployment: "payments".to_owned(),
            deployment_uid: "deployment-uid".to_owned(),
            container: "app".to_owned(),
            container_index: 0,
            prior_image_digest: digest("old-image"),
            resource_version: "1001".to_owned(),
            prior_projection_hash: digest("projection"),
            prior_transaction_annotation: Some("none".to_owned()),
            prior_authorization_annotation: Some("none".to_owned()),
            prior_operation_hash_annotation: Some("none".to_owned()),
        }
    }

    fn grant(maximum_uses: u32) -> GrantRegistration {
        let capability = CapabilityGrant {
            grant_id: Uuid::from_u128(10),
            holder: "workload-a".to_owned(),
            tenant: "acme".to_owned(),
            operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
            repository: "acme/payments".to_owned(),
            audience: "accordlock-executor:prod".to_owned(),
            cluster_identity: "cluster-a".to_owned(),
            namespace: "payments".to_owned(),
            deployment_uid: "deployment-uid".to_owned(),
            container: "app".to_owned(),
            image_repository: "registry.example/acme/payments".to_owned(),
            not_before: 50,
            expires_at: 500,
            maximum_uses,
        };
        let mut active = authority();
        active.grant_registry.root = canonical_hash(&capability).unwrap();
        GrantRegistration {
            environment: "prod".to_owned(),
            grant: capability,
            authority: active,
            dispatch_deadline_policy: DispatchDeadlinePolicy {
                max_dispatch_delay_seconds: 30,
                profile_hard_cap: 1_000,
                immutable_dependency_expiries: vec![120, 150],
            },
        }
    }

    fn issued(
        auth: AuthorityVector,
        authorization_id: Uuid,
        transaction_id: Uuid,
    ) -> IssuedAuthorizationRecord {
        let template = template();
        let template_hash = canonical_hash(&template).unwrap();
        let authorization = ExecutionAuthorization {
            schema_version: accordlock_protocol::EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
            authorization_id,
            evaluation_nonce: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            tenant: "acme".to_owned(),
            holder: "workload-a".to_owned(),
            audience: "accordlock-executor:prod".to_owned(),
            issued_at: 90,
            not_before: 90,
            consume_before: 200,
            dispatch_deadline_policy: DispatchDeadlinePolicy {
                max_dispatch_delay_seconds: 30,
                profile_hard_cap: 1_000,
                immutable_dependency_expiries: vec![120, 150],
            },
            grant_id: Uuid::from_u128(10),
            template,
            template_hash,
            evidence_root: digest("evidence"),
            principals: vec!["principal-a".to_owned()],
            policy_root: auth.policy.root,
            authority: auth,
        };
        let signer = authorization_signer();
        let cose_sign1 = sign_cose(
            &authorization.canonical_bytes().unwrap(),
            EXECUTION_AUTHORIZATION_DOMAIN,
            &signer,
        )
        .unwrap();
        IssuedAuthorizationRecord::new(
            transaction_id,
            SignedAuthorization {
                authorization,
                cose_sign1,
            },
            signer.key_id().to_owned(),
            signer.public_key_bytes(),
        )
        .unwrap_or_else(|error| panic!("valid fixture: {error}"))
    }

    fn resign(record: &mut IssuedAuthorizationRecord) {
        let signer = authorization_signer();
        record.authorization_hash =
            canonical_hash(&record.signed_authorization.authorization).unwrap();
        record.signed_authorization.cose_sign1 = sign_cose(
            &record
                .signed_authorization
                .authorization
                .canonical_bytes()
                .unwrap(),
            EXECUTION_AUTHORIZATION_DOMAIN,
            &signer,
        )
        .unwrap();
    }

    fn setup(maximum_uses: u32) -> (InMemoryStore, Arc<TestClock>, AuthorityVector) {
        let clock = Arc::new(TestClock::new(100));
        let store = InMemoryStore::with_clock(clock.clone());
        let registration = grant(maximum_uses);
        let auth = registration.authority.clone();
        store
            .compare_and_activate_authority(&Scope::new("acme", "prod").unwrap(), None, &auth)
            .unwrap();
        store.register_grant(&registration).unwrap();
        (store, clock, auth)
    }

    fn consumed_key(
        store: &InMemoryStore,
        auth: AuthorityVector,
        transaction_id: u128,
        authorization_id: u128,
    ) -> ConsumeKey {
        let record = issued(
            auth,
            Uuid::from_u128(authorization_id),
            Uuid::from_u128(transaction_id),
        );
        let key = ConsumeKey {
            scope: Scope::new("acme", "prod").unwrap(),
            transaction_id: record.transaction_id,
            authorization_id: record.authorization().authorization_id,
        };
        store.record_issued_authorization(&record).unwrap();
        store.consume(&key).unwrap();
        key
    }

    fn claim_request(key: &ConsumeKey, claim_id: u128, worker_id: &str) -> DispatchClaimRequest {
        DispatchClaimRequest {
            key: key.clone(),
            claim_id: Uuid::from_u128(claim_id),
            worker_id: worker_id.to_owned(),
        }
    }

    fn credential(token: &DispatchClaimToken) -> DispatchCredentialBinding {
        token
            .bind_authenticated_credential(
                [77; 32],
                "service-account-uid".to_owned(),
                "AUTHORIZATION_ID=7ee52be0-9045-4653-aa5e-0da57b8dccdc".to_owned(),
                90,
                500,
            )
            .unwrap()
    }

    fn begin_attempt(
        store: &InMemoryStore,
        clock: &TestClock,
        key: &ConsumeKey,
        claim_id: u128,
    ) -> DispatchClaimToken {
        clock.set(105);
        let claimed = store
            .claim_dispatch(&claim_request(key, claim_id, "worker-admission"))
            .unwrap();
        let token = claimed.token().clone();
        clock.set(106);
        store
            .mark_attempt_in_flight(&token, credential(&token))
            .unwrap();
        token
    }

    fn admission_request(
        store: &InMemoryStore,
        key: &ConsumeKey,
        admission_uid: &str,
        observation_label: &str,
    ) -> AdmissionAuthorizationRequest {
        store
            .admission_context(key)
            .unwrap()
            .authorization_request(
                admission_uid.to_owned(),
                "service-account-uid",
                "AUTHORIZATION_ID=7ee52be0-9045-4653-aa5e-0da57b8dccdc",
                digest(&format!("old-{observation_label}")),
                digest(&format!("new-{observation_label}")),
                digest("executor-identity"),
                digest("observer-identity"),
            )
            .unwrap()
    }

    fn broker_claim(
        store: &InMemoryStore,
        clock: &TestClock,
        auth: AuthorityVector,
        seed: u128,
    ) -> (ConsumeKey, DispatchClaimToken) {
        let key = consumed_key(store, auth, seed, seed + 1);
        clock.set(101);
        let claimed = store
            .claim_dispatch(&claim_request(&key, seed + 2, "worker-broker"))
            .unwrap();
        (key, claimed.token().clone())
    }

    fn broker_capability(store: &InMemoryStore) -> BrokerJournalCapability {
        let mut bootstrap = store.clone();
        bootstrap.issue_broker_journal_capability().unwrap()
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn broker_journal_is_one_shot_and_cleanup_survives_deadline() {
        let (store, clock, auth) = setup(1);
        let capability = broker_capability(&store);
        let (key, token) = broker_claim(&store, &clock, auth, 700);
        let route = [42; 32];

        clock.set(102);
        let create_intent = store
            .prepare_broker_operation(
                &capability,
                BrokerOperationRequest::create(&token, route).unwrap(),
            )
            .unwrap();
        assert_eq!(create_intent.audit().phase(), BrokerJournalPhase::Intent);
        clock.set(103);
        let create_authority = store.begin_broker_io(&capability, create_intent).unwrap();
        let created = store
            .commit_broker_create(
                create_authority,
                BrokerSecretObservation::matching("secret-uid-700".to_owned(), [11; 32]).unwrap(),
            )
            .unwrap();
        assert_eq!(
            created.audit().outcome(),
            Some(BrokerJournalOutcome::CreateMatching)
        );

        clock.set(104);
        let issue_intent = store
            .prepare_broker_operation(
                &capability,
                BrokerOperationRequest::issue_token(
                    &token,
                    route,
                    BrokerCredentialSafetyPolicy::new(60, 5).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        let issue_authority = store.begin_broker_io(&capability, issue_intent).unwrap();
        let unknown = store.mark_broker_io_unknown(issue_authority).unwrap();
        assert_eq!(unknown.phase(), BrokerJournalPhase::Unknown);
        assert_eq!(unknown.credential_safe_after(), Some(169));
        assert!(matches!(
            store.prepare_broker_operation(
                &capability,
                BrokerOperationRequest::issue_token(
                    &token,
                    route,
                    BrokerCredentialSafetyPolicy::new(60, 5).unwrap(),
                )
                .unwrap()
            ),
            Err(StateError::BrokerOperationOutcomeUnknown)
        ));
        assert!(matches!(
            BrokerReconciliationRequest::new(
                key.clone(),
                BrokerJournalOperation::IssueToken,
                route
            ),
            Err(StateError::BrokerTokenReissueForbidden)
        ));

        // The dispatch deadline is 120. Exact cleanup remains authorized
        // after that deadline because blocking cleanup would retain a possibly
        // live credential. It still advances the monotone HWM and binds the
        // original route/name/UID.
        clock.set(130);
        let cleanup = store
            .prepare_broker_cleanup(
                &capability,
                &BrokerCleanupRequest::new(key.clone(), route).unwrap(),
            )
            .unwrap();
        assert_eq!(cleanup.audit().bound_secret_uid(), Some("secret-uid-700"));
        let delete_authority = store.begin_broker_io(&capability, cleanup).unwrap();
        store.mark_broker_io_unknown(delete_authority).unwrap();
        let reconcile = store
            .begin_broker_reconciliation(
                &capability,
                &BrokerReconciliationRequest::new(
                    key.clone(),
                    BrokerJournalOperation::DeleteSecret,
                    route,
                )
                .unwrap(),
            )
            .unwrap();
        let stale_reconcile = store
            .begin_broker_reconciliation(
                &capability,
                &BrokerReconciliationRequest::new(
                    key.clone(),
                    BrokerJournalOperation::DeleteSecret,
                    route,
                )
                .unwrap(),
            )
            .unwrap();
        let still_present = store
            .commit_broker_reconciliation(
                reconcile,
                BrokerSecretObservation::matching("secret-uid-700".to_owned(), [12; 32]).unwrap(),
            )
            .unwrap();
        assert!(still_present.is_pending());
        let retry = still_present.into_pending().unwrap();
        assert_eq!(retry.audit().phase(), BrokerJournalPhase::ReconcileOnly);
        assert_eq!(retry.audit().reconciliation_count(), 1);
        assert_eq!(
            retry.audit().last_reconciliation_outcome(),
            Some(BrokerJournalOutcome::DeletePresent)
        );
        assert!(matches!(
            store.commit_broker_reconciliation(
                stale_reconcile,
                BrokerSecretObservation::absent([14; 32]).unwrap()
            ),
            Err(StateError::BrokerOperationInvalidTransition)
        ));
        clock.set(131);
        let deleted = store
            .commit_broker_reconciliation(retry, BrokerSecretObservation::absent([13; 32]).unwrap())
            .unwrap()
            .into_completed()
            .unwrap();
        assert_eq!(deleted.audit().phase(), BrokerJournalPhase::Committed);
        assert_eq!(
            store
                .broker_operation_audit(&key, BrokerJournalOperation::DeleteSecret)
                .unwrap()
                .outcome(),
            Some(BrokerJournalOutcome::DeleteAbsent)
        );
    }

    #[test]
    fn broker_create_absence_remains_get_only_until_late_match() {
        let (store, clock, auth) = setup(1);
        let capability = broker_capability(&store);
        let (key, token) = broker_claim(&store, &clock, auth, 705);
        let route = [45; 32];
        clock.set(102);
        let create = store
            .prepare_broker_operation(
                &capability,
                BrokerOperationRequest::create(&token, route).unwrap(),
            )
            .and_then(|intent| store.begin_broker_io(&capability, intent))
            .unwrap();
        store.mark_broker_io_unknown(create).unwrap();
        let reconcile = store
            .begin_broker_reconciliation(
                &capability,
                &BrokerReconciliationRequest::new(
                    key.clone(),
                    BrokerJournalOperation::CreateSecret,
                    route,
                )
                .unwrap(),
            )
            .unwrap();
        let absent = store
            .commit_broker_reconciliation(
                reconcile,
                BrokerSecretObservation::absent([46; 32]).unwrap(),
            )
            .unwrap();
        let retry = absent.into_pending().unwrap();
        assert_eq!(retry.audit().reconciliation_count(), 1);
        assert_eq!(
            retry.audit().last_reconciliation_outcome(),
            Some(BrokerJournalOutcome::CreateAbsent)
        );
        clock.set(103);
        let completed = store
            .commit_broker_reconciliation(
                retry,
                BrokerSecretObservation::matching("late-secret-uid".to_owned(), [47; 32]).unwrap(),
            )
            .unwrap()
            .into_completed()
            .unwrap();
        assert_eq!(completed.audit().phase(), BrokerJournalPhase::Committed);
        assert_eq!(completed.audit().reconciliation_count(), 1);
        assert_eq!(
            completed.audit().outcome(),
            Some(BrokerJournalOutcome::CreateMatching)
        );
        assert!(matches!(
            store.prepare_broker_operation(
                &capability,
                BrokerOperationRequest::create(&token, route).unwrap(),
            ),
            Err(StateError::BrokerOperationOutcomeUnknown)
        ));
    }

    #[test]
    fn broker_intent_race_has_one_in_flight_authority() {
        let (store, clock, auth) = setup(1);
        let capability = Arc::new(broker_capability(&store));
        let (_key, token) = broker_claim(&store, &clock, auth, 710);
        let route = [43; 32];
        clock.set(102);
        let first = store
            .prepare_broker_operation(
                &capability,
                BrokerOperationRequest::create(&token, route).unwrap(),
            )
            .unwrap();
        let second = store
            .prepare_broker_operation(
                &capability,
                BrokerOperationRequest::create(&token, route).unwrap(),
            )
            .unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let handles = [first, second].map(|intent| {
            let store = store.clone();
            let barrier = barrier.clone();
            let capability = capability.clone();
            thread::spawn(move || {
                barrier.wait();
                store.begin_broker_io(&capability, intent)
            })
        });
        let results = handles.map(|handle| handle.join().unwrap());
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(StateError::BrokerOperationOutcomeUnknown)))
                .count(),
            1
        );
    }

    #[test]
    fn token_result_is_bound_to_frozen_upper_expiry() {
        let (store, clock, auth) = setup(1);
        let capability = broker_capability(&store);
        let (_key, token) = broker_claim(&store, &clock, auth, 720);
        let route = [44; 32];
        clock.set(102);
        let create = store
            .prepare_broker_operation(
                &capability,
                BrokerOperationRequest::create(&token, route).unwrap(),
            )
            .and_then(|intent| store.begin_broker_io(&capability, intent))
            .unwrap();
        store
            .commit_broker_create(
                create,
                BrokerSecretObservation::matching("secret-uid-720".to_owned(), [21; 32]).unwrap(),
            )
            .unwrap();
        clock.set(103);
        let issue = store
            .prepare_broker_operation(
                &capability,
                BrokerOperationRequest::issue_token(
                    &token,
                    route,
                    BrokerCredentialSafetyPolicy::new(10, 2).unwrap(),
                )
                .unwrap(),
            )
            .and_then(|intent| store.begin_broker_io(&capability, intent))
            .unwrap();
        let too_late = BrokerTokenIssueObservation::new([31; 32], 116, [32; 32]).unwrap();
        assert!(matches!(
            store.commit_broker_token_issue(issue, &too_late),
            Err(StateError::BrokerOperationMismatch)
        ));
    }

    #[test]
    fn scope_rejects_whitespace_aliases() {
        assert!(Scope::new(" acme", "prod").is_err());
        assert!(Scope::new("acme", "prod ").is_err());
    }

    #[test]
    fn issuance_record_rejects_a_authorization_that_expired_during_signing() {
        let (store, clock, auth) = setup(1);
        let mut record = issued(auth, Uuid::from_u128(18), Uuid::from_u128(19));
        record.signed_authorization.authorization.consume_before = 110;
        resign(&mut record);
        clock.set(record.authorization().consume_before);

        assert!(matches!(
            store.record_issued_authorization(&record),
            Err(StateError::AuthorizationExpired {
                observed,
                consume_before
            }) if observed == consume_before
                && consume_before == record.authorization().consume_before
        ));
        assert!(store.inner.lock().authorizations.is_empty());
        assert!(store.inner.lock().transactions.is_empty());
        assert_eq!(
            store.time_high_water(&record.scope()).unwrap(),
            Some(record.authorization().consume_before)
        );

        clock.set(record.authorization().consume_before - 1);
        assert!(matches!(
            store.record_issued_authorization(&record),
            Err(StateError::ClockRollback {
                observed,
                high_water
            }) if observed + 1 == high_water
                && high_water == record.authorization().consume_before
        ));
    }

    #[test]
    fn issuance_snapshot_expiry_persists_high_water_and_rejects_rollback() {
        let (store, clock, _) = setup(1);
        let scope = Scope::new("acme", "prod").unwrap();
        clock.set(500);
        assert!(matches!(
            store.issuance_snapshot(&scope, Uuid::from_u128(10)),
            Err(StateError::GrantExpired {
                observed: 500,
                expires_at: 500
            })
        ));
        assert_eq!(store.time_high_water(&scope).unwrap(), Some(500));

        clock.set(499);
        assert!(matches!(
            store.issuance_snapshot(&scope, Uuid::from_u128(10)),
            Err(StateError::ClockRollback {
                observed: 499,
                high_water: 500
            })
        ));
    }

    #[test]
    fn consumption_uses_stored_state_and_writes_receipt_and_outbox() {
        let (store, _, auth) = setup(2);
        let transaction_id = Uuid::from_u128(20);
        let authorization_id = Uuid::from_u128(21);
        let record = issued(auth, authorization_id, transaction_id);
        store.record_issued_authorization(&record).unwrap();
        let key = ConsumeKey {
            scope: Scope::new("acme", "prod").unwrap(),
            transaction_id,
            authorization_id,
        };

        let success = store.consume(&key).unwrap();
        assert_eq!(success.receipt().consumed_at, 100);
        assert_eq!(success.receipt().dispatch_deadline, 120);
        assert_eq!(success.outbox().status, OutboxStatus::PendingWitness);
        assert_eq!(store.time_high_water(&key.scope).unwrap(), Some(100));
        assert_eq!(store.consumption_receipt(&key).unwrap(), *success.receipt());
        assert_eq!(store.outbox_entry(&key).unwrap(), *success.outbox());
        assert_eq!(
            store
                .grant_snapshot(&key.scope, Uuid::from_u128(10))
                .unwrap()
                .uses,
            1
        );
    }

    #[test]
    fn consume_or_recover_returns_the_exact_committed_tuple() {
        let (store, _, auth) = setup(2);
        let transaction_id = Uuid::from_u128(22);
        let authorization_id = Uuid::from_u128(23);
        store
            .record_issued_authorization(&issued(auth, authorization_id, transaction_id))
            .unwrap();
        let key = ConsumeKey {
            scope: Scope::new("acme", "prod").unwrap(),
            transaction_id,
            authorization_id,
        };

        // Treat the first success as if its response were lost after commit.
        let committed = store.consume(&key).unwrap();
        assert!(matches!(
            store.consume(&key),
            Err(StateError::AlreadyConsumed)
        ));
        let recovered = store.consume_or_recover(&key).unwrap();

        assert_eq!(
            serde_json::to_vec(recovered.receipt()).unwrap(),
            serde_json::to_vec(committed.receipt()).unwrap()
        );
        assert_eq!(
            serde_json::to_vec(recovered.outbox()).unwrap(),
            serde_json::to_vec(committed.outbox()).unwrap()
        );
    }

    #[test]
    fn consume_or_recover_never_adopts_a_consumed_authorization_id_for_another_transaction() {
        let (store, _, auth) = setup(2);
        let transaction_id = Uuid::from_u128(24);
        let authorization_id = Uuid::from_u128(25);
        store
            .record_issued_authorization(&issued(auth, authorization_id, transaction_id))
            .unwrap();
        let key = ConsumeKey {
            scope: Scope::new("acme", "prod").unwrap(),
            transaction_id,
            authorization_id,
        };
        store.consume(&key).unwrap();

        let wrong_transaction = ConsumeKey {
            transaction_id: Uuid::from_u128(26),
            ..key
        };
        assert!(matches!(
            store.consume_or_recover(&wrong_transaction),
            Err(StateError::TransactionMismatch)
        ));
    }

    #[test]
    fn consume_or_recover_rejects_a_corrupt_committed_tuple() {
        let (store, _, auth) = setup(2);
        let transaction_id = Uuid::from_u128(27);
        let authorization_id = Uuid::from_u128(28);
        store
            .record_issued_authorization(&issued(auth, authorization_id, transaction_id))
            .unwrap();
        let key = ConsumeKey {
            scope: Scope::new("acme", "prod").unwrap(),
            transaction_id,
            authorization_id,
        };
        store.consume(&key).unwrap();

        store
            .inner
            .lock()
            .outbox
            .get_mut(&(key.scope.clone(), key.authorization_id))
            .unwrap()
            .dispatch_deadline += 1;
        assert!(matches!(
            store.consume_or_recover(&key),
            Err(StateError::InvalidRecord(_))
        ));
    }

    #[test]
    fn consumption_cannot_override_deadline_inputs_after_issuance() {
        let (store, _, auth) = setup(2);
        let transaction_id = Uuid::from_u128(25);
        let authorization_id = Uuid::from_u128(26);
        let mut record = issued(auth, authorization_id, transaction_id);
        store.record_issued_authorization(&record).unwrap();

        // This is only the caller's local copy. The consumption API accepts no
        // deadline or authority values and reloads the frozen record instead.
        record
            .signed_authorization
            .authorization
            .dispatch_deadline_policy
            .profile_hard_cap = 101;
        record
            .signed_authorization
            .authorization
            .dispatch_deadline_policy
            .immutable_dependency_expiries = vec![101];

        let success = store
            .consume(&ConsumeKey {
                scope: Scope::new("acme", "prod").unwrap(),
                transaction_id,
                authorization_id,
            })
            .unwrap();
        assert_eq!(success.receipt().dispatch_deadline, 120);
    }

    #[test]
    fn issuance_rejects_divergent_template_audience_even_with_rehashed_authorization() {
        let (store, _, auth) = setup(1);
        let mut record = issued(auth, Uuid::from_u128(27), Uuid::from_u128(28));
        record.signed_authorization.authorization.template.audience =
            "different-executor".to_owned();
        resign(&mut record);

        assert!(matches!(
            store.record_issued_authorization(&record),
            Err(StateError::InvalidRecord(message))
                if message.contains("audience")
        ));
    }

    #[test]
    fn issuance_rejects_authorization_window_beyond_registered_grant() {
        let (store, _, auth) = setup(1);
        let mut record = issued(auth, Uuid::from_u128(29), Uuid::from_u128(30));
        record.signed_authorization.authorization.consume_before = 501;
        resign(&mut record);

        assert!(matches!(
            store.record_issued_authorization(&record),
            Err(StateError::GrantMismatch)
        ));
    }

    #[test]
    fn concurrent_consumption_has_exactly_one_winner() {
        let (store, _, auth) = setup(8);
        let transaction_id = Uuid::from_u128(30);
        let authorization_id = Uuid::from_u128(31);
        store
            .record_issued_authorization(&issued(auth, authorization_id, transaction_id))
            .unwrap();
        let key = ConsumeKey {
            scope: Scope::new("acme", "prod").unwrap(),
            transaction_id,
            authorization_id,
        };
        let barrier = Arc::new(Barrier::new(16));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let store = store.clone();
            let key = key.clone();
            let barrier = barrier.clone();
            handles.push(thread::spawn(move || {
                barrier.wait();
                store.consume(&key)
            }));
        }

        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(StateError::AlreadyConsumed)))
                .count(),
            15
        );
    }

    #[test]
    fn authority_change_invalidates_the_issued_authorization() {
        let (store, _, auth) = setup(2);
        let transaction_id = Uuid::from_u128(40);
        let authorization_id = Uuid::from_u128(41);
        store
            .record_issued_authorization(&issued(auth.clone(), authorization_id, transaction_id))
            .unwrap();

        let mut next = auth.clone();
        next.policy = domain("policy-v2", 2);
        let scope = Scope::new("acme", "prod").unwrap();
        store
            .compare_and_activate_authority(&scope, Some(&auth), &next)
            .unwrap();
        let error = store
            .consume(&ConsumeKey {
                scope,
                transaction_id,
                authorization_id,
            })
            .unwrap_err();
        assert!(matches!(error, StateError::AuthorityMismatch));
    }

    #[test]
    fn durable_high_water_rejects_clock_rollback() {
        let (store, clock, auth) = setup(2);
        let first = issued(auth.clone(), Uuid::from_u128(51), Uuid::from_u128(50));
        store.record_issued_authorization(&first).unwrap();
        store
            .consume(&ConsumeKey {
                scope: Scope::new("acme", "prod").unwrap(),
                transaction_id: first.transaction_id,
                authorization_id: first.signed_authorization.authorization.authorization_id,
            })
            .unwrap();

        let second = issued(auth, Uuid::from_u128(53), Uuid::from_u128(52));
        store.record_issued_authorization(&second).unwrap();
        clock.set(99);
        let error = store
            .consume(&ConsumeKey {
                scope: Scope::new("acme", "prod").unwrap(),
                transaction_id: second.transaction_id,
                authorization_id: second.signed_authorization.authorization.authorization_id,
            })
            .unwrap_err();
        assert!(matches!(
            error,
            StateError::ClockRollback {
                observed: 99,
                high_water: 100
            }
        ));
    }

    #[test]
    fn exact_consume_before_boundary_is_expired() {
        let (store, clock, auth) = setup(2);
        let record = issued(auth, Uuid::from_u128(61), Uuid::from_u128(60));
        store.record_issued_authorization(&record).unwrap();
        clock.set(200);
        let error = store
            .consume(&ConsumeKey {
                scope: Scope::new("acme", "prod").unwrap(),
                transaction_id: record.transaction_id,
                authorization_id: record.signed_authorization.authorization.authorization_id,
            })
            .unwrap_err();
        assert!(matches!(
            error,
            StateError::AuthorizationExpired {
                observed: 200,
                consume_before: 200
            }
        ));
        assert_eq!(
            store
                .time_high_water(&Scope::new("acme", "prod").unwrap())
                .unwrap(),
            Some(200)
        );

        clock.set(199);
        assert!(matches!(
            store.consume(&ConsumeKey {
                scope: Scope::new("acme", "prod").unwrap(),
                transaction_id: record.transaction_id,
                authorization_id: record.signed_authorization.authorization.authorization_id,
            }),
            Err(StateError::ClockRollback {
                observed: 199,
                high_water: 200
            })
        ));
    }

    #[test]
    fn grant_use_is_consumed_once_across_distinct_authorizations() {
        let (store, _, auth) = setup(1);
        let first = issued(auth.clone(), Uuid::from_u128(71), Uuid::from_u128(70));
        let second = issued(auth, Uuid::from_u128(73), Uuid::from_u128(72));
        store.record_issued_authorization(&first).unwrap();
        store.record_issued_authorization(&second).unwrap();
        store
            .consume(&ConsumeKey {
                scope: Scope::new("acme", "prod").unwrap(),
                transaction_id: first.transaction_id,
                authorization_id: first.signed_authorization.authorization.authorization_id,
            })
            .unwrap();
        let error = store
            .consume(&ConsumeKey {
                scope: Scope::new("acme", "prod").unwrap(),
                transaction_id: second.transaction_id,
                authorization_id: second.signed_authorization.authorization.authorization_id,
            })
            .unwrap_err();
        assert!(matches!(error, StateError::GrantExhausted));
    }

    #[test]
    fn non_monotone_authority_activation_is_rejected() {
        let (store, _, auth) = setup(1);
        let mut invalid = auth.clone();
        invalid.policy.root = digest("changed-without-epoch");
        let error = store
            .compare_and_activate_authority(
                &Scope::new("acme", "prod").unwrap(),
                Some(&auth),
                &invalid,
            )
            .unwrap_err();
        assert!(matches!(error, StateError::NonMonotoneAuthority));
    }

    #[test]
    fn unsigned_wrong_signer_and_root_mismatch_records_are_rejected() {
        let (store, _, auth) = setup(4);

        let mut unsigned = issued(auth.clone(), Uuid::from_u128(91), Uuid::from_u128(90));
        unsigned.signed_authorization.cose_sign1.clear();
        assert!(matches!(
            store.record_issued_authorization(&unsigned),
            Err(StateError::InvalidAuthorizationSignature(_))
        ));

        let mut wrong_signer = issued(auth.clone(), Uuid::from_u128(93), Uuid::from_u128(92));
        let attacker = SigningIdentity::from_seed("attacker-authorization", [99; 32]);
        wrong_signer.signer_key_id = attacker.key_id().to_owned();
        wrong_signer.signer_public_key = attacker.public_key_bytes();
        wrong_signer.signed_authorization.cose_sign1 = sign_cose(
            &wrong_signer
                .signed_authorization
                .authorization
                .canonical_bytes()
                .unwrap(),
            EXECUTION_AUTHORIZATION_DOMAIN,
            &attacker,
        )
        .unwrap();
        assert!(matches!(
            store.record_issued_authorization(&wrong_signer),
            Err(StateError::InvalidAuthorizationSignature(_))
        ));

        let mut root_mismatch = issued(auth, Uuid::from_u128(95), Uuid::from_u128(94));
        root_mismatch
            .signed_authorization
            .authorization
            .authority
            .signer
            .root = digest("forged-root");
        resign(&mut root_mismatch);
        assert!(matches!(
            store.record_issued_authorization(&root_mismatch),
            Err(StateError::InvalidAuthorizationSignature(_))
        ));
    }

    #[test]
    fn grant_registration_requires_the_exact_committed_snapshot() {
        let clock = Arc::new(TestClock::new(100));
        let store = InMemoryStore::with_clock(clock);
        let mut registration = grant(1);
        let scope = registration.scope();
        let committed = registration.authority.clone();
        store
            .compare_and_activate_authority(&scope, None, &committed)
            .unwrap();

        registration.grant.audience = "fabricated-executor".to_owned();
        assert!(matches!(
            store.register_grant(&registration),
            Err(StateError::GrantRegistryRootMismatch)
        ));
    }

    #[test]
    fn grant_registration_persists_success_and_temporal_rejection_time() {
        let clock = Arc::new(TestClock::new(100));
        let store = InMemoryStore::with_clock(clock.clone());
        let registration = grant(1);
        let scope = registration.scope();
        store
            .compare_and_activate_authority(&scope, None, &registration.authority)
            .unwrap();
        store.register_grant(&registration).unwrap();
        assert_eq!(store.time_high_water(&scope).unwrap(), Some(100));

        clock.set(99);
        assert!(matches!(
            store.issuance_snapshot(&scope, registration.grant.grant_id),
            Err(StateError::ClockRollback {
                observed: 99,
                high_water: 100
            })
        ));

        let expired_clock = Arc::new(TestClock::new(500));
        let expired_store = InMemoryStore::with_clock(expired_clock.clone());
        let expired_registration = grant(1);
        let expired_scope = expired_registration.scope();
        expired_store
            .compare_and_activate_authority(&expired_scope, None, &expired_registration.authority)
            .unwrap();
        assert!(matches!(
            expired_store.register_grant(&expired_registration),
            Err(StateError::GrantExpired {
                observed: 500,
                expires_at: 500
            })
        ));
        assert_eq!(
            expired_store.time_high_water(&expired_scope).unwrap(),
            Some(500)
        );

        expired_clock.set(499);
        assert!(matches!(
            expired_store.register_grant(&expired_registration),
            Err(StateError::ClockRollback {
                observed: 499,
                high_water: 500
            })
        ));
        assert!(matches!(
            expired_store.grant_snapshot(&expired_scope, expired_registration.grant.grant_id),
            Err(StateError::GrantNotFound)
        ));
    }

    #[test]
    fn revocation_is_atomic_and_the_final_record_recheck_fails_closed() {
        let (store, _, auth) = setup(3);
        let scope = Scope::new("acme", "prod").unwrap();
        let grant_id = Uuid::from_u128(10);
        let before_race = issued(auth.clone(), Uuid::from_u128(97), Uuid::from_u128(96));
        let already_recorded = issued(auth.clone(), Uuid::from_u128(99), Uuid::from_u128(98));
        store
            .record_issued_authorization(&already_recorded)
            .unwrap();

        assert!(matches!(
            store.revoke_grant(&scope, grant_id, &auth, &auth),
            Err(StateError::NonMonotoneAuthority)
        ));
        assert!(!store.grant_snapshot(&scope, grant_id).unwrap().revoked);

        let mut revoked = auth.clone();
        revoked.revocation.epoch += 1;
        revoked.revocation.activation_id = Uuid::from_u128(0xa0);
        revoked.revocation.root = grant_revocation_root(grant_id);
        store
            .revoke_grant(&scope, grant_id, &auth, &revoked)
            .unwrap();
        assert!(store.grant_snapshot(&scope, grant_id).unwrap().revoked);
        assert_eq!(store.active_authority(&scope).unwrap(), revoked);

        // Models a signature produced immediately before revocation. The
        // state adapter's second check must reject its durable record.
        assert!(matches!(
            store.record_issued_authorization(&before_race),
            Err(StateError::AuthorityMismatch | StateError::GrantRevoked)
        ));
        assert!(matches!(
            store.consume(&ConsumeKey {
                scope,
                transaction_id: already_recorded.transaction_id,
                authorization_id: already_recorded
                    .signed_authorization
                    .authorization
                    .authorization_id,
            }),
            Err(StateError::AuthorityMismatch | StateError::GrantRevoked)
        ));
    }

    #[test]
    fn dispatch_snapshot_reloads_the_exact_consumed_tuple_at_maximum_uses() {
        let (store, clock, auth) = setup(1);
        let record = issued(auth.clone(), Uuid::from_u128(0xb1), Uuid::from_u128(0xb0));
        let key = ConsumeKey {
            scope: Scope::new("acme", "prod").unwrap(),
            transaction_id: record.transaction_id,
            authorization_id: record.signed_authorization.authorization.authorization_id,
        };
        store.record_issued_authorization(&record).unwrap();
        let consumed = store.consume(&key).unwrap();
        assert_eq!(
            store
                .grant_snapshot(&key.scope, Uuid::from_u128(10))
                .unwrap()
                .uses,
            1
        );

        clock.set(110);
        let snapshot = store.dispatch_snapshot(&key).unwrap();
        assert_eq!(snapshot.scope(), &key.scope);
        assert_eq!(snapshot.checked_at(), 110);
        assert_eq!(snapshot.authority(), &auth);
        assert_eq!(snapshot.issued(), &record);
        assert_eq!(snapshot.receipt(), consumed.receipt());
        assert_eq!(snapshot.outbox(), consumed.outbox());
        assert_eq!(store.time_high_water(&key.scope).unwrap(), Some(110));

        // Even a restored or corrupted-low HWM cannot make a dispatch
        // observation predate the immutable consumption receipt.
        store.inner.lock().high_water.insert(key.scope.clone(), 0);
        clock.set(99);
        assert!(matches!(
            store.dispatch_snapshot(&key),
            Err(StateError::ClockRollback {
                observed: 99,
                high_water: 100
            })
        ));
        assert_eq!(store.time_high_water(&key.scope).unwrap(), Some(0));
    }

    #[test]
    fn dispatch_deadline_boundary_persists_high_water_and_rejects_rollback() {
        let (store, clock, auth) = setup(1);
        let record = issued(auth, Uuid::from_u128(0xb3), Uuid::from_u128(0xb2));
        let key = ConsumeKey {
            scope: Scope::new("acme", "prod").unwrap(),
            transaction_id: record.transaction_id,
            authorization_id: record.signed_authorization.authorization.authorization_id,
        };
        store.record_issued_authorization(&record).unwrap();
        store.consume(&key).unwrap();

        clock.set(120);
        assert!(matches!(
            store.dispatch_snapshot(&key),
            Err(StateError::DispatchDeadlineExpired {
                observed: 120,
                dispatch_deadline: 120
            })
        ));
        assert_eq!(store.time_high_water(&key.scope).unwrap(), Some(120));

        clock.set(119);
        assert!(matches!(
            store.dispatch_snapshot(&key),
            Err(StateError::ClockRollback {
                observed: 119,
                high_water: 120
            })
        ));
        assert_eq!(store.time_high_water(&key.scope).unwrap(), Some(120));
    }

    #[test]
    fn dispatch_snapshot_rejects_authority_change_and_revocation() {
        let (authority_store, authority_clock, authority) = setup(2);
        let authority_record = issued(
            authority.clone(),
            Uuid::from_u128(0xb5),
            Uuid::from_u128(0xb4),
        );
        let authority_key = ConsumeKey {
            scope: Scope::new("acme", "prod").unwrap(),
            transaction_id: authority_record.transaction_id,
            authorization_id: authority_record
                .signed_authorization
                .authorization
                .authorization_id,
        };
        authority_store
            .record_issued_authorization(&authority_record)
            .unwrap();
        authority_store.consume(&authority_key).unwrap();
        let mut advanced = authority.clone();
        advanced.policy = domain("policy-v2", 2);
        authority_store
            .compare_and_activate_authority(&authority_key.scope, Some(&authority), &advanced)
            .unwrap();
        authority_clock.set(110);
        assert!(matches!(
            authority_store.dispatch_snapshot(&authority_key),
            Err(StateError::AuthorityMismatch)
        ));

        let (revoked_store, revoked_clock, authority) = setup(2);
        let revoked_record = issued(
            authority.clone(),
            Uuid::from_u128(0xb7),
            Uuid::from_u128(0xb6),
        );
        let revoked_key = ConsumeKey {
            scope: Scope::new("acme", "prod").unwrap(),
            transaction_id: revoked_record.transaction_id,
            authorization_id: revoked_record
                .signed_authorization
                .authorization
                .authorization_id,
        };
        revoked_store
            .record_issued_authorization(&revoked_record)
            .unwrap();
        revoked_store.consume(&revoked_key).unwrap();
        let mut revoked_authority = authority.clone();
        revoked_authority.revocation.epoch += 1;
        revoked_authority.revocation.activation_id = Uuid::from_u128(0xb8);
        revoked_authority.revocation.root = grant_revocation_root(Uuid::from_u128(10));
        revoked_store
            .revoke_grant(
                &revoked_key.scope,
                Uuid::from_u128(10),
                &authority,
                &revoked_authority,
            )
            .unwrap();
        revoked_clock.set(110);
        assert!(matches!(
            revoked_store.dispatch_snapshot(&revoked_key),
            Err(StateError::GrantRevoked)
        ));
    }

    #[test]
    fn dispatch_snapshot_rejects_clock_rollback() {
        let (store, clock, auth) = setup(2);
        let record = issued(auth, Uuid::from_u128(0xba), Uuid::from_u128(0xb9));
        let key = ConsumeKey {
            scope: Scope::new("acme", "prod").unwrap(),
            transaction_id: record.transaction_id,
            authorization_id: record.signed_authorization.authorization.authorization_id,
        };
        store.record_issued_authorization(&record).unwrap();
        store.consume(&key).unwrap();
        clock.set(110);
        store.dispatch_snapshot(&key).unwrap();

        clock.set(109);
        assert!(matches!(
            store.dispatch_snapshot(&key),
            Err(StateError::ClockRollback {
                observed: 109,
                high_water: 110
            })
        ));
        assert_eq!(store.time_high_water(&key.scope).unwrap(), Some(110));
    }

    #[test]
    fn dispatch_snapshot_rejects_unconsumed_corrupt_and_misrouted_state() {
        let (unconsumed_store, _, auth) = setup(2);
        let unconsumed = issued(auth, Uuid::from_u128(0xbc), Uuid::from_u128(0xbb));
        let unconsumed_key = ConsumeKey {
            scope: Scope::new("acme", "prod").unwrap(),
            transaction_id: unconsumed.transaction_id,
            authorization_id: unconsumed
                .signed_authorization
                .authorization
                .authorization_id,
        };
        unconsumed_store
            .record_issued_authorization(&unconsumed)
            .unwrap();
        assert!(matches!(
            unconsumed_store.dispatch_snapshot(&unconsumed_key),
            Err(StateError::GrantNotConsumed)
        ));

        let wrong_key = ConsumeKey {
            transaction_id: Uuid::from_u128(0xbd),
            ..unconsumed_key
        };
        assert!(matches!(
            unconsumed_store.dispatch_snapshot(&wrong_key),
            Err(StateError::TransactionMismatch)
        ));

        let (corrupt_store, corrupt_clock, auth) = setup(2);
        let corrupt = issued(auth, Uuid::from_u128(0xbf), Uuid::from_u128(0xbe));
        let corrupt_key = ConsumeKey {
            scope: Scope::new("acme", "prod").unwrap(),
            transaction_id: corrupt.transaction_id,
            authorization_id: corrupt.signed_authorization.authorization.authorization_id,
        };
        corrupt_store.record_issued_authorization(&corrupt).unwrap();
        corrupt_store.consume(&corrupt_key).unwrap();
        corrupt_store
            .inner
            .lock()
            .authorizations
            .get_mut(&(corrupt_key.scope.clone(), corrupt_key.authorization_id))
            .unwrap()
            .signed_authorization
            .cose_sign1
            .clear();
        corrupt_clock.set(110);
        assert!(matches!(
            corrupt_store.dispatch_snapshot(&corrupt_key),
            Err(StateError::InvalidAuthorizationSignature(_))
        ));
        assert_eq!(
            corrupt_store.time_high_water(&corrupt_key.scope).unwrap(),
            Some(100)
        );
    }

    #[test]
    fn misrouted_dispatch_request_cannot_poison_high_water() {
        let (store, clock, auth) = setup(1);
        let key = consumed_key(&store, auth, 0xbf_01, 0xbf_02);
        let wrong_transaction = ConsumeKey {
            transaction_id: Uuid::from_u128(0xbf_03),
            ..key.clone()
        };

        clock.set(110);
        assert!(matches!(
            store.dispatch_snapshot(&wrong_transaction),
            Err(StateError::TransactionMismatch)
        ));
        assert_eq!(store.time_high_water(&key.scope).unwrap(), Some(100));

        clock.set(109);
        assert_eq!(store.dispatch_snapshot(&key).unwrap().checked_at(), 109);
        assert_eq!(store.time_high_water(&key.scope).unwrap(), Some(109));
    }

    #[test]
    fn durable_claim_is_exclusive_and_same_request_never_recovers_authority() {
        let (store, clock, auth) = setup(1);
        let key = consumed_key(&store, auth, 0xc0, 0xc1);
        clock.set(105);
        let request = claim_request(&key, 0xc2, "worker-a");
        let claimed = store.claim_dispatch(&request).unwrap();
        assert_eq!(claimed.snapshot().checked_at(), 105);
        assert_eq!(claimed.token().key(), &key);
        assert_eq!(claimed.token().claim_id(), request.claim_id);
        assert_eq!(claimed.token().worker_id(), "worker-a");
        assert_eq!(claimed.token().fence(), 1);
        assert_eq!(claimed.token().claimed_at(), 105);
        assert_eq!(claimed.token().lease_until(), 120);

        assert!(matches!(
            store.claim_dispatch(&request),
            Err(StateError::DispatchClaimOutcomeUnknown)
        ));
        let different = claim_request(&key, 0xc3, "worker-b");
        assert!(matches!(
            store.claim_dispatch(&different),
            Err(StateError::DispatchAlreadyClaimed)
        ));
        let reused_id_different_worker = claim_request(&key, 0xc2, "worker-b");
        assert!(matches!(
            store.claim_dispatch(&reused_id_different_worker),
            Err(StateError::DispatchAlreadyClaimed)
        ));
        assert!(matches!(
            store.claim_dispatch(&claim_request(&key, 0xc4, "Worker-A")),
            Err(StateError::InvalidRecord(_))
        ));
        assert_eq!(store.time_high_water(&key.scope).unwrap(), Some(105));
    }

    #[test]
    fn concurrent_distinct_claims_have_one_winner() {
        let (store, clock, auth) = setup(1);
        let key = consumed_key(&store, auth, 0xc5, 0xc6);
        clock.set(105);
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for (claim_id, worker) in [(0xc7, "worker-a"), (0xc8, "worker-b")] {
            let store = store.clone();
            let request = claim_request(&key, claim_id, worker);
            let barrier = barrier.clone();
            handles.push(thread::spawn(move || {
                barrier.wait();
                store.claim_dispatch(&request)
            }));
        }
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(StateError::DispatchAlreadyClaimed)))
                .count(),
            1
        );
    }

    #[test]
    fn concurrent_authorizations_for_one_physical_resource_have_one_winner() {
        let (store, clock, auth) = setup(2);
        let first_key = consumed_key(&store, auth.clone(), 0xc5_10, 0xc6_10);
        let second_key = consumed_key(&store, auth, 0xc5_11, 0xc6_11);
        clock.set(105);
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for (key, claim_id, worker) in [
            (first_key, 0xc7_10, "worker-a"),
            (second_key, 0xc7_11, "worker-b"),
        ] {
            let store = store.clone();
            let request = claim_request(&key, claim_id, worker);
            let barrier = barrier.clone();
            handles.push(thread::spawn(move || {
                barrier.wait();
                store.claim_dispatch(&request)
            }));
        }
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(StateError::PhysicalResourceAlreadyReserved)))
                .count(),
            1
        );
        let winner = results
            .iter()
            .find_map(|result| result.as_ref().ok())
            .unwrap();
        assert_eq!(
            winner.token().physical_resource().cluster_identity(),
            "cluster-a"
        );
        assert_eq!(winner.token().physical_resource().namespace(), "payments");
        assert_eq!(
            winner.token().physical_resource().deployment_uid(),
            "deployment-uid"
        );
    }

    #[test]
    fn expired_claim_creation_persists_high_water_and_rejects_rollback() {
        let (store, clock, auth) = setup(1);
        let key = consumed_key(&store, auth, 0xc5_01, 0xc6_01);
        let request = claim_request(&key, 0xc7_01, "worker-a");

        clock.set(120);
        assert!(matches!(
            store.claim_dispatch(&request),
            Err(StateError::DispatchDeadlineExpired {
                observed: 120,
                dispatch_deadline: 120
            })
        ));
        assert_eq!(store.time_high_water(&key.scope).unwrap(), Some(120));
        assert!(
            !store
                .inner
                .lock()
                .dispatch_claims
                .contains_key(&(key.scope.clone(), key.authorization_id))
        );

        clock.set(119);
        assert!(matches!(
            store.claim_dispatch(&request),
            Err(StateError::ClockRollback {
                observed: 119,
                high_water: 120
            })
        ));
        assert_eq!(store.time_high_water(&key.scope).unwrap(), Some(120));
    }

    #[test]
    fn expired_claim_revalidation_persists_high_water_and_rejects_rollback() {
        let (store, clock, auth) = setup(1);
        let key = consumed_key(&store, auth, 0xc5_02, 0xc6_02);
        clock.set(105);
        let claimed = store
            .claim_dispatch(&claim_request(&key, 0xc7_02, "worker-a"))
            .unwrap();

        clock.set(120);
        assert!(matches!(
            store.revalidate_dispatch_claim(claimed.token()),
            Err(StateError::DispatchDeadlineExpired {
                observed: 120,
                dispatch_deadline: 120
            })
        ));
        assert_eq!(store.time_high_water(&key.scope).unwrap(), Some(120));

        clock.set(119);
        assert!(matches!(
            store.revalidate_dispatch_claim(claimed.token()),
            Err(StateError::ClockRollback {
                observed: 119,
                high_water: 120
            })
        ));
    }

    #[test]
    fn expired_claim_lease_on_mark_persists_high_water_and_rejects_rollback() {
        let clock = Arc::new(TestClock::new(100));
        let store = InMemoryStore::with_clock(clock.clone());
        let mut registration = grant(1);
        registration.dispatch_deadline_policy = DispatchDeadlinePolicy {
            max_dispatch_delay_seconds: 100,
            profile_hard_cap: 1_000,
            immutable_dependency_expiries: vec![180],
        };
        let scope = registration.scope();
        let auth = registration.authority.clone();
        store
            .compare_and_activate_authority(&scope, None, &auth)
            .unwrap();
        store.register_grant(&registration).unwrap();
        let mut record = issued(auth, Uuid::from_u128(0xc6_03), Uuid::from_u128(0xc5_03));
        record
            .signed_authorization
            .authorization
            .dispatch_deadline_policy = registration.dispatch_deadline_policy;
        resign(&mut record);
        let key = ConsumeKey {
            scope,
            transaction_id: record.transaction_id,
            authorization_id: record.authorization().authorization_id,
        };
        store.record_issued_authorization(&record).unwrap();
        let consumed = store.consume(&key).unwrap();
        assert_eq!(consumed.receipt().dispatch_deadline, 180);
        clock.set(105);
        let claimed = store
            .claim_dispatch(&claim_request(&key, 0xc7_03, "worker-a"))
            .unwrap();
        assert_eq!(claimed.token().lease_until(), 135);

        clock.set(135);
        assert!(matches!(
            store.mark_attempt_in_flight(claimed.token(), credential(claimed.token())),
            Err(StateError::DispatchClaimLeaseExpired {
                observed: 135,
                lease_until: 135
            })
        ));
        assert_eq!(store.time_high_water(&key.scope).unwrap(), Some(135));
        let durable_claim = store
            .inner
            .lock()
            .dispatch_claims
            .get(&(key.scope.clone(), key.authorization_id))
            .map(|claim| (claim.state, claim.attempt_started_at))
            .unwrap();
        assert_eq!(durable_claim, (MemoryDispatchClaimState::Claimed, None));

        clock.set(134);
        assert!(matches!(
            store.mark_attempt_in_flight(claimed.token(), credential(claimed.token())),
            Err(StateError::ClockRollback {
                observed: 134,
                high_water: 135
            })
        ));
    }

    #[test]
    fn mark_attempt_is_one_shot_and_resource_reservation_is_not_released() {
        let (store, clock, auth) = setup(2);
        let first_key = consumed_key(&store, auth.clone(), 0xc9, 0xca);
        let second_key = consumed_key(&store, auth, 0xcb, 0xcc);
        clock.set(105);
        let first = store
            .claim_dispatch(&claim_request(&first_key, 0xcd, "worker-a"))
            .unwrap();
        assert!(matches!(
            store.claim_dispatch(&claim_request(&second_key, 0xce, "worker-b")),
            Err(StateError::PhysicalResourceAlreadyReserved)
        ));

        let token = first.token().clone();
        clock.set(106);
        assert_eq!(
            store
                .revalidate_dispatch_claim(&token)
                .unwrap()
                .checked_at(),
            106
        );
        let attempt = store
            .mark_attempt_in_flight(&token, credential(&token))
            .unwrap();
        assert_eq!(attempt.started_at(), 106);
        assert_eq!(attempt.token(), &token);
        assert!(matches!(
            store.mark_attempt_in_flight(&token, credential(&token)),
            Err(StateError::DispatchAttemptOutcomeUnknown)
        ));
        assert!(matches!(
            store.revalidate_dispatch_claim(&token),
            Err(StateError::DispatchAttemptOutcomeUnknown)
        ));
        assert!(matches!(
            store.claim_dispatch(&claim_request(&second_key, 0xcf, "worker-b")),
            Err(StateError::PhysicalResourceAlreadyReserved)
        ));
        assert_eq!(
            store
                .inner
                .lock()
                .dispatch_claims
                .get(&(first_key.scope.clone(), first_key.authorization_id))
                .unwrap()
                .attempt_started_at,
            Some(106)
        );
    }

    #[test]
    fn revocation_and_wrong_store_block_claim_use_without_hwm_advance() {
        let (revoked_store, revoked_clock, auth) = setup(1);
        let revoked_key = consumed_key(&revoked_store, auth.clone(), 0xcf, 0xd0);
        revoked_clock.set(105);
        let revoked = revoked_store
            .claim_dispatch(&claim_request(&revoked_key, 0xd1, "worker-a"))
            .unwrap();
        let mut next = auth.clone();
        next.revocation.epoch += 1;
        next.revocation.activation_id = Uuid::from_u128(0xd2);
        next.revocation.root = grant_revocation_root(Uuid::from_u128(10));
        revoked_store
            .revoke_grant(&revoked_key.scope, Uuid::from_u128(10), &auth, &next)
            .unwrap();
        revoked_clock.set(106);
        assert!(matches!(
            revoked_store.mark_attempt_in_flight(revoked.token(), credential(revoked.token())),
            Err(StateError::GrantRevoked | StateError::AuthorityMismatch)
        ));
        assert_eq!(
            revoked_store.time_high_water(&revoked_key.scope).unwrap(),
            Some(105)
        );

        revoked_clock.set(400);
        let unrelated = InMemoryStore::with_clock(revoked_clock);
        assert!(matches!(
            unrelated.revalidate_dispatch_claim(revoked.token()),
            Err(StateError::DispatchClaimMismatch)
        ));
        assert_eq!(unrelated.time_high_water(&revoked_key.scope).unwrap(), None);
    }

    #[test]
    fn admission_context_is_state_derived_and_non_consuming() {
        let (store, clock, auth) = setup(1);
        let key = consumed_key(&store, auth, 0xd1_01, 0xd2_01);
        clock.set(105);
        let claimed = store
            .claim_dispatch(&claim_request(&key, 0xd3_01, "worker-admission"))
            .unwrap();
        let high_water_before = store.time_high_water(&key.scope).unwrap();

        clock.set(400);
        assert!(matches!(
            store.admission_context(&key),
            Err(StateError::AdmissionClaimNotInFlight)
        ));
        assert_eq!(
            store.time_high_water(&key.scope).unwrap(),
            high_water_before
        );
        assert!(store.inner.lock().admission_authorizations.is_empty());

        clock.set(106);
        store
            .mark_attempt_in_flight(claimed.token(), credential(claimed.token()))
            .unwrap();
        let context = store.admission_context(&key).unwrap();
        let prepared = accordlock_k8s::prepare_patch(
            context.template(),
            key.transaction_id,
            key.authorization_id,
        )
        .unwrap();
        assert_eq!(context.key(), &key);
        assert_eq!(context.claim_id(), claimed.token().claim_id());
        assert_eq!(context.fence(), claimed.token().fence());
        assert_eq!(
            context.credential_token_digest(),
            Digest32::from_bytes([77; 32])
        );
        assert_eq!(context.service_account_uid(), "service-account-uid");
        assert_eq!(
            context.credential_id(),
            "AUTHORIZATION_ID=7ee52be0-9045-4653-aa5e-0da57b8dccdc"
        );
        assert_eq!(context.credential_not_before(), 90);
        assert_eq!(context.credential_expires_at(), 500);
        assert_ne!(
            context.credential_binding_commitment(),
            Digest32::from_bytes([0; 32])
        );
        assert_eq!(
            context.physical_resource(),
            claimed.token().physical_resource()
        );
        assert_eq!(
            context.template_hash(),
            canonical_hash(context.template()).unwrap()
        );
        assert_eq!(context.operation_hash(), prepared.operation_hash);
        assert_eq!(
            context.provider_request_commitment(),
            prepared.final_wire_commitment
        );
        assert_eq!(context.started_at(), 106);
        assert_eq!(context.checked_at(), 106);
        assert_eq!(context.dispatch_deadline(), 120);
        assert_eq!(context.authority(), claimed.snapshot().authority());
        assert!(store.inner.lock().admission_authorizations.is_empty());
    }

    #[test]
    fn admission_authorization_is_exact_one_shot_and_recoverable_while_current() {
        let (store, clock, auth) = setup(1);
        let key = consumed_key(&store, auth, 0xd1_02, 0xd2_02);
        begin_attempt(&store, &clock, &key, 0xd3_02);
        let request = admission_request(&store, &key, "review-1", "one");

        clock.set(107);
        let first = store.authorize_admission_or_recover(&request).unwrap();
        assert!(!first.was_recovered());
        assert_eq!(first.authorized_at(), 107);
        assert_eq!(first.checked_at(), 107);

        clock.set(108);
        let recovered = store.authorize_admission_or_recover(&request).unwrap();
        assert!(recovered.was_recovered());
        assert_eq!(recovered.authorized_at(), 107);
        assert_eq!(recovered.checked_at(), 108);

        let changed_same_uid = admission_request(&store, &key, "review-1", "changed");
        assert!(matches!(
            store.authorize_admission_or_recover(&changed_same_uid),
            Err(StateError::AdmissionUidMismatch)
        ));
        let different_uid = admission_request(&store, &key, "review-2", "one");
        assert!(matches!(
            store.authorize_admission_or_recover(&different_uid),
            Err(StateError::AdmissionAlreadyAuthorized)
        ));
        assert_eq!(store.inner.lock().admission_authorizations.len(), 1);
    }

    #[test]
    fn same_service_account_with_another_credential_is_rejected_without_consumption() {
        let (store, clock, auth) = setup(1);
        let key = consumed_key(&store, auth, 0xd1_04, 0xd2_04);
        begin_attempt(&store, &clock, &key, 0xd3_04);
        let mismatch = store
            .admission_context(&key)
            .unwrap()
            .authorization_request(
                "review-credential".to_owned(),
                "service-account-uid",
                "AUTHORIZATION_ID=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                digest("old"),
                digest("new"),
                digest("executor"),
                digest("observer"),
            );
        assert!(matches!(
            mismatch,
            Err(StateError::AdmissionCredentialMismatch)
        ));
        assert!(store.inner.lock().admission_authorizations.is_empty());

        let exact = admission_request(&store, &key, "review-credential", "exact");
        clock.set(107);
        assert!(store.authorize_admission_or_recover(&exact).is_ok());
    }

    #[test]
    fn admission_rejects_zero_or_substituted_commitments_without_hwm_poisoning() {
        let (store, clock, auth) = setup(1);
        let key = consumed_key(&store, auth, 0xd1_03, 0xd2_03);
        let token = begin_attempt(&store, &clock, &key, 0xd3_03);
        let zero = Digest32::from_bytes([0; 32]);
        assert!(matches!(
            store
                .admission_context(&key)
                .unwrap()
                .authorization_request(
                    "review-zero".to_owned(),
                    "service-account-uid",
                    "AUTHORIZATION_ID=7ee52be0-9045-4653-aa5e-0da57b8dccdc",
                    zero,
                    digest("new"),
                    digest("executor"),
                    digest("observer"),
                ),
            Err(StateError::InvalidRecord(_))
        ));

        let context = store.admission_context(&key).unwrap();
        let wrong_provider = AdmissionAuthorizationRequest::new(
            key.clone(),
            token.claim_id(),
            token.fence(),
            token.physical_resource().clone(),
            context.credential_token_digest(),
            context.service_account_uid().to_owned(),
            context.credential_id().to_owned(),
            context.credential_binding_commitment(),
            "review-substitution".to_owned(),
            digest("attacker-provider-request"),
            digest("old"),
            digest("new"),
            digest("executor"),
            digest("observer"),
        )
        .unwrap();
        let high_water_before = store.time_high_water(&key.scope).unwrap();
        clock.set(400);
        assert!(matches!(
            store.authorize_admission_or_recover(&wrong_provider),
            Err(StateError::AdmissionProviderRequestMismatch)
        ));
        assert_eq!(
            store.time_high_water(&key.scope).unwrap(),
            high_water_before
        );
        assert!(store.inner.lock().admission_authorizations.is_empty());
    }

    #[test]
    fn historical_admission_is_not_recovered_after_authority_change() {
        let (store, clock, auth) = setup(1);
        let key = consumed_key(&store, auth.clone(), 0xd1_04, 0xd2_04);
        begin_attempt(&store, &clock, &key, 0xd3_04);
        let request = admission_request(&store, &key, "review-authority", "authority");
        clock.set(107);
        store.authorize_admission_or_recover(&request).unwrap();

        let mut next = auth.clone();
        next.policy.epoch += 1;
        next.policy.activation_id = Uuid::from_u128(0xd4_04);
        next.policy.root = digest("new-policy-root");
        store
            .compare_and_activate_authority(&key.scope, Some(&auth), &next)
            .unwrap();
        clock.set(108);
        assert!(matches!(
            store.authorize_admission_or_recover(&request),
            Err(StateError::AuthorityMismatch)
        ));
        assert_eq!(store.inner.lock().admission_authorizations.len(), 1);
    }

    #[test]
    fn historical_admission_is_not_recovered_after_revocation_or_deadline() {
        let (revoked_store, revoked_clock, auth) = setup(1);
        let revoked_key = consumed_key(&revoked_store, auth.clone(), 0xd1_05, 0xd2_05);
        begin_attempt(&revoked_store, &revoked_clock, &revoked_key, 0xd3_05);
        let revoked_request =
            admission_request(&revoked_store, &revoked_key, "review-revoked", "revoked");
        revoked_clock.set(107);
        revoked_store
            .authorize_admission_or_recover(&revoked_request)
            .unwrap();
        let mut next = auth.clone();
        next.revocation.epoch += 1;
        next.revocation.activation_id = Uuid::from_u128(0xd4_05);
        next.revocation.root = grant_revocation_root(Uuid::from_u128(10));
        revoked_store
            .revoke_grant(&revoked_key.scope, Uuid::from_u128(10), &auth, &next)
            .unwrap();
        assert!(matches!(
            revoked_store.authorize_admission_or_recover(&revoked_request),
            Err(StateError::GrantRevoked | StateError::AuthorityMismatch)
        ));
        assert_eq!(revoked_store.inner.lock().admission_authorizations.len(), 1);

        let (expired_store, expired_clock, expired_auth) = setup(1);
        let expired_key = consumed_key(&expired_store, expired_auth, 0xd1_06, 0xd2_06);
        begin_attempt(&expired_store, &expired_clock, &expired_key, 0xd3_06);
        let expired_request =
            admission_request(&expired_store, &expired_key, "review-expired", "expired");
        expired_clock.set(107);
        expired_store
            .authorize_admission_or_recover(&expired_request)
            .unwrap();
        expired_clock.set(120);
        assert!(matches!(
            expired_store.authorize_admission_or_recover(&expired_request),
            Err(StateError::DispatchDeadlineExpired {
                observed: 120,
                dispatch_deadline: 120
            })
        ));
        assert_eq!(
            expired_store.time_high_water(&expired_key.scope).unwrap(),
            Some(120)
        );
        assert_eq!(expired_store.inner.lock().admission_authorizations.len(), 1);
    }

    #[test]
    fn concurrent_admission_uids_have_one_winner() {
        let (store, clock, auth) = setup(1);
        let key = consumed_key(&store, auth, 0xd1_07, 0xd2_07);
        begin_attempt(&store, &clock, &key, 0xd3_07);
        let requests = [
            admission_request(&store, &key, "review-race-a", "race"),
            admission_request(&store, &key, "review-race-b", "race"),
        ];
        clock.set(107);
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for request in requests {
            let store = store.clone();
            let barrier = barrier.clone();
            handles.push(thread::spawn(move || {
                barrier.wait();
                store.authorize_admission_or_recover(&request)
            }));
        }
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(StateError::AdmissionAlreadyAuthorized)))
                .count(),
            1
        );
        assert_eq!(store.inner.lock().admission_authorizations.len(), 1);
    }

    fn ingress_consumption(
        scope: &IngressReplayScope,
        key_id: &str,
        nonce: u128,
        expires_unix_s: i64,
        observed_unix_s: i64,
    ) -> IngressNonceConsumption {
        IngressNonceConsumption::new(
            scope.clone(),
            key_id,
            Uuid::from_u128(nonce),
            expires_unix_s,
            observed_unix_s,
        )
        .unwrap()
    }

    const REGISTRY_DEPLOYMENT_UID: &str = "11111111-1111-4111-8111-111111111111";
    const REGISTRY_SERVICE_ACCOUNT_UID: &str = "22222222-2222-4222-8222-222222222222";

    fn registry_route(
        cluster_identity: &str,
        api_server_identity: &str,
        socket: &str,
    ) -> EksRouteProfile {
        let certificates = vec![b"registry-test-ca".to_vec()];
        EksRouteProfile::new(EksRouteProfileInput {
            cluster_trust_domain: "spiffe://example.test/eks/prod-a",
            cluster_identity,
            api_server_identity,
            dns_server_name: "api.prod-a.eks.amazonaws.com",
            port: 443,
            socket_target: PinnedSocketTarget::new(SocketAddr::from_str(socket).unwrap()).unwrap(),
            ca_trust_commitment: CaTrustCommitment::from_der_certificates(&certificates).unwrap(),
            namespace: "payments",
            deployment_name: "payments",
            deployment_uid: REGISTRY_DEPLOYMENT_UID,
            attempt_service_account_name: "accordlock-attempt",
            attempt_service_account_uid: REGISTRY_SERVICE_ACCOUNT_UID,
            token_audience: "urn:accordlock:kubernetes-api:prod-a",
        })
        .unwrap()
    }

    fn registry_profile(route: EksRouteProfile, rbac: u8, terminal: u8) -> EksDestinationProfile {
        registry_profile_with_security(
            route,
            rbac,
            terminal,
            EksCredentialLifecyclePolicy::new(600, 900, 5, 60).unwrap(),
            registry_management_bindings(0x81),
        )
    }

    fn registry_management_bindings(marker: u8) -> EksBrokerManagementBindings {
        EksBrokerManagementBindings::new(
            EksManagementAuthorityBinding::new(
                format!("spiffe://accordlock.test/secret/{marker}"),
                [marker; 32],
            )
            .unwrap(),
            EksManagementAuthorityBinding::new(
                format!("spiffe://accordlock.test/token/{}", marker.wrapping_add(1)),
                [marker.wrapping_add(1); 32],
            )
            .unwrap(),
            EksManagementAuthorityBinding::new(
                format!("spiffe://accordlock.test/review/{}", marker.wrapping_add(2)),
                [marker.wrapping_add(2); 32],
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn registry_profile_with_security(
        route: EksRouteProfile,
        rbac: u8,
        terminal: u8,
        lifecycle: EksCredentialLifecyclePolicy,
        management: EksBrokerManagementBindings,
    ) -> EksDestinationProfile {
        EksDestinationProfile::new(route, [rbac; 32], [terminal; 32], lifecycle, management)
            .unwrap()
    }

    fn registry_management_substitution(
        original: &EksBrokerManagementBindings,
        variant: u8,
    ) -> EksBrokerManagementBindings {
        let changed = |binding: &EksManagementAuthorityBinding, subject: String, root: [u8; 32]| {
            EksManagementAuthorityBinding::new(
                if subject.is_empty() {
                    binding.subject().to_owned()
                } else {
                    subject
                },
                root,
            )
            .unwrap()
        };
        let mut secret = original.secret_lifecycle().clone();
        let mut token = original.service_account_token().clone();
        let mut review = original.token_review().clone();
        match variant {
            0 => {
                secret = changed(
                    &secret,
                    "spiffe://accordlock.test/secret/changed".to_owned(),
                    secret.rbac_commitment(),
                );
            }
            1 => secret = changed(&secret, String::new(), [0x91; 32]),
            2 => {
                token = changed(
                    &token,
                    "spiffe://accordlock.test/token/changed".to_owned(),
                    token.rbac_commitment(),
                );
            }
            3 => token = changed(&token, String::new(), [0x92; 32]),
            4 => {
                review = changed(
                    &review,
                    "spiffe://accordlock.test/review/changed".to_owned(),
                    review.rbac_commitment(),
                );
            }
            5 => review = changed(&review, String::new(), [0x93; 32]),
            _ => unreachable!("test substitution variant is bounded"),
        }
        EksBrokerManagementBindings::new(secret, token, review).unwrap()
    }

    fn registry_authority(
        scope: &Scope,
        profile: &EksDestinationProfile,
        capability: Option<&CapabilityGrant>,
    ) -> AuthorityVector {
        let mut active = authority();
        active.resource.root = profile.resource_root(scope).unwrap();
        active.mediation.root = profile.mediation_root(scope, &active.resource).unwrap();
        if let Some(capability) = capability {
            active.grant_registry.root = canonical_hash(capability).unwrap();
        }
        active
    }

    fn registry_capability(tenant: &str, cluster_identity: &str) -> CapabilityGrant {
        CapabilityGrant {
            grant_id: Uuid::new_v4(),
            holder: "workload-a".to_owned(),
            tenant: tenant.to_owned(),
            operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
            repository: "acme/payments".to_owned(),
            audience: "accordlock-executor:prod".to_owned(),
            cluster_identity: cluster_identity.to_owned(),
            namespace: "payments".to_owned(),
            deployment_uid: REGISTRY_DEPLOYMENT_UID.to_owned(),
            container: "app".to_owned(),
            image_repository: "registry.example/acme/payments".to_owned(),
            not_before: 50,
            expires_at: 500,
            maximum_uses: 1,
        }
    }

    fn registry_template(cluster_identity: &str) -> DeploymentTemplate {
        DeploymentTemplate {
            cluster_identity: cluster_identity.to_owned(),
            deployment_uid: REGISTRY_DEPLOYMENT_UID.to_owned(),
            ..template()
        }
    }

    fn registry_issued(
        scope: &Scope,
        active: AuthorityVector,
        capability: &CapabilityGrant,
        transaction_id: Uuid,
        authorization_id: Uuid,
    ) -> IssuedAuthorizationRecord {
        let template = registry_template(&capability.cluster_identity);
        let authorization = ExecutionAuthorization {
            schema_version: accordlock_protocol::EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
            authorization_id,
            evaluation_nonce: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            tenant: scope.tenant.clone(),
            holder: capability.holder.clone(),
            audience: "accordlock-executor:prod".to_owned(),
            issued_at: 90,
            not_before: 90,
            consume_before: 200,
            dispatch_deadline_policy: DispatchDeadlinePolicy {
                max_dispatch_delay_seconds: 60,
                profile_hard_cap: 1_000,
                immutable_dependency_expiries: vec![150],
            },
            grant_id: capability.grant_id,
            template_hash: canonical_hash(&template).unwrap(),
            template,
            evidence_root: digest("registry-evidence"),
            principals: vec!["principal-a".to_owned()],
            policy_root: active.policy.root,
            authority: active,
        };
        let signer = authorization_signer();
        let cose_sign1 = sign_cose(
            &authorization.canonical_bytes().unwrap(),
            EXECUTION_AUTHORIZATION_DOMAIN,
            &signer,
        )
        .unwrap();
        IssuedAuthorizationRecord::new(
            transaction_id,
            SignedAuthorization {
                authorization,
                cose_sign1,
            },
            signer.key_id().to_owned(),
            signer.public_key_bytes(),
        )
        .unwrap()
    }

    fn rooted_registry_attempt() -> (
        InMemoryStore,
        Arc<TestClock>,
        ConsumeKey,
        DispatchClaimToken,
        EksDestinationProfile,
        AuthorityVector,
    ) {
        let clock = Arc::new(TestClock::new(100));
        let store = InMemoryStore::with_clock(clock.clone());
        let scope = Scope::new("acme-registry", "prod").unwrap();
        let profile = registry_profile(
            registry_route(
                "eks://prod-a",
                "urn:accordlock:api:prod-a",
                "192.0.2.41:443",
            ),
            0x41,
            0x51,
        );
        let capability = registry_capability(&scope.tenant, profile.route().cluster_identity());
        let active = registry_authority(&scope, &profile, Some(&capability));
        store
            .compare_and_activate_authority(&scope, None, &active)
            .unwrap();
        store.activate_eks_destination(&scope, &profile).unwrap();
        let registration = GrantRegistration {
            environment: scope.environment.clone(),
            grant: capability.clone(),
            authority: active.clone(),
            dispatch_deadline_policy: DispatchDeadlinePolicy {
                max_dispatch_delay_seconds: 60,
                profile_hard_cap: 1_000,
                immutable_dependency_expiries: vec![150],
            },
        };
        store.register_grant(&registration).unwrap();
        let transaction_id = Uuid::new_v4();
        let authorization_id = Uuid::new_v4();
        let record = registry_issued(
            &scope,
            active.clone(),
            &capability,
            transaction_id,
            authorization_id,
        );
        store.record_issued_authorization(&record).unwrap();
        let key = ConsumeKey {
            scope,
            transaction_id,
            authorization_id,
        };
        store.consume(&key).unwrap();
        clock.set(101);
        let token = store
            .claim_dispatch(&claim_request(&key, 0xe1_01, "worker-registry"))
            .unwrap()
            .token()
            .clone();
        (store, clock, key, token, profile, active)
    }

    const TERMINAL_EFFECT_OBSERVER: &str = "spiffe://accordlock.test/observer/effect";
    const TERMINAL_RETIREMENT_OBSERVER: &str = "spiffe://accordlock.test/observer/retirement";
    const TERMINAL_AUTHORITY_VERSION: u64 = 7;

    struct TerminalMemoryFixture {
        store: InMemoryStore,
        clock: Arc<TestClock>,
        key: ConsumeKey,
        token: DispatchClaimToken,
        registry: ActivatedWitnessRegistry,
        effect_signer: SigningIdentity,
        retirement_signer: SigningIdentity,
        resource_activation_id: Uuid,
        mediation_activation_id: Uuid,
        initial_registry_receipt: TerminalWitnessRegistryReceipt,
    }

    fn terminal_registry_entry(
        scope: &Scope,
        cluster_identity: &str,
        signer: &SigningIdentity,
        role: WitnessRole,
        observer_identity: &str,
    ) -> RegisteredWitnessVerifier {
        RegisteredWitnessVerifier::new(
            WitnessScope::new(scope.tenant.clone(), scope.environment.clone()).unwrap(),
            cluster_identity,
            role,
            observer_identity,
            signer.key_id(),
            signer.public_key_bytes(),
            1,
            2_000,
            1_999,
            TERMINAL_AUTHORITY_VERSION,
            digest("terminal-observer-authority"),
            WitnessVerifierStatus::Active,
        )
        .unwrap()
    }

    fn terminal_registry_for_signers(
        scope: &Scope,
        cluster_identity: &str,
        effect_signer: &SigningIdentity,
        retirement_signer: &SigningIdentity,
        activation_id: Uuid,
    ) -> ActivatedWitnessRegistry {
        let entries = vec![
            terminal_registry_entry(
                scope,
                cluster_identity,
                effect_signer,
                WitnessRole::ExactEffect,
                TERMINAL_EFFECT_OBSERVER,
            ),
            terminal_registry_entry(
                scope,
                cluster_identity,
                retirement_signer,
                WitnessRole::CredentialRetirement,
                TERMINAL_RETIREMENT_OBSERVER,
            ),
        ];
        let material_root = ActivatedWitnessRegistry::compute_material_root(&entries).unwrap();
        ActivatedWitnessRegistry::new(
            WitnessRegistryAuthority::new(material_root, 12, activation_id).unwrap(),
            entries,
        )
        .unwrap()
    }

    #[allow(clippy::too_many_lines)]
    fn terminal_memory_fixture() -> TerminalMemoryFixture {
        let clock = Arc::new(TestClock::new(100));
        let store = InMemoryStore::with_clock(clock.clone());
        let broker_capability = broker_capability(&store);
        let scope = Scope::new("acme-terminal", "prod").unwrap();
        let cluster_identity = "eks://terminal-prod-a";
        let effect_signer = SigningIdentity::from_seed("terminal-effect-v1", [0xa1; 32]);
        let retirement_signer = SigningIdentity::from_seed("terminal-retirement-v1", [0xa2; 32]);
        let registry = terminal_registry_for_signers(
            &scope,
            cluster_identity,
            &effect_signer,
            &retirement_signer,
            Uuid::from_u128(0xa3),
        );
        let profile = EksDestinationProfile::new(
            registry_route(
                cluster_identity,
                "urn:accordlock:api:terminal-prod-a",
                "192.0.2.51:443",
            ),
            [0xa4; 32],
            *registry.commitment().as_bytes(),
            EksCredentialLifecyclePolicy::new(600, 900, 5, 60).unwrap(),
            registry_management_bindings(0xa5),
        )
        .unwrap();
        let capability = registry_capability(&scope.tenant, profile.route().cluster_identity());
        let active = registry_authority(&scope, &profile, Some(&capability));
        store
            .compare_and_activate_authority(&scope, None, &active)
            .unwrap();
        store.activate_eks_destination(&scope, &profile).unwrap();
        let initial_registry_receipt = store
            .register_terminal_witness_registry_or_recover(
                &scope,
                active.resource.activation_id,
                active.mediation.activation_id,
                &registry,
            )
            .unwrap();
        store
            .register_grant(&GrantRegistration {
                environment: scope.environment.clone(),
                grant: capability.clone(),
                authority: active.clone(),
                dispatch_deadline_policy: DispatchDeadlinePolicy {
                    max_dispatch_delay_seconds: 60,
                    profile_hard_cap: 1_000,
                    immutable_dependency_expiries: vec![150],
                },
            })
            .unwrap();

        let transaction_id = Uuid::from_u128(0xa6);
        let authorization_id = Uuid::from_u128(0xa7);
        let record = registry_issued(
            &scope,
            active.clone(),
            &capability,
            transaction_id,
            authorization_id,
        );
        store.record_issued_authorization(&record).unwrap();
        let key = ConsumeKey {
            scope,
            transaction_id,
            authorization_id,
        };
        store.consume(&key).unwrap();
        clock.set(101);
        let token = store
            .claim_dispatch(&claim_request(&key, 0xa8, "worker-terminal"))
            .unwrap()
            .token()
            .clone();
        let route = *profile.route().commitment().as_bytes();

        clock.set(102);
        let create = store
            .prepare_broker_operation(
                &broker_capability,
                BrokerOperationRequest::create(&token, route).unwrap(),
            )
            .and_then(|intent| store.begin_broker_io(&broker_capability, intent))
            .unwrap();
        store
            .commit_broker_create(
                create,
                BrokerSecretObservation::matching("secret-uid-terminal".to_owned(), [0xa9; 32])
                    .unwrap(),
            )
            .unwrap();

        clock.set(103);
        let issue = store
            .prepare_broker_operation(
                &broker_capability,
                BrokerOperationRequest::issue_token(
                    &token,
                    route,
                    BrokerCredentialSafetyPolicy::new(900, 5).unwrap(),
                )
                .unwrap(),
            )
            .and_then(|intent| store.begin_broker_io(&broker_capability, intent))
            .unwrap();
        store
            .commit_broker_token_issue(
                issue,
                &BrokerTokenIssueObservation::new([0xaa; 32], 500, [0xab; 32]).unwrap(),
            )
            .unwrap();

        clock.set(105);
        store
            .mark_attempt_in_flight(
                &token,
                token
                    .bind_authenticated_credential(
                        [0xaa; 32],
                        REGISTRY_SERVICE_ACCOUNT_UID.to_owned(),
                        "AUTHORIZATION_ID=7ee52be0-9045-4653-aa5e-0da57b8dccdc".to_owned(),
                        90,
                        500,
                    )
                    .unwrap(),
            )
            .unwrap();

        clock.set(106);
        let admission = store
            .admission_context(&key)
            .unwrap()
            .authorization_request(
                "terminal-admission-uid".to_owned(),
                REGISTRY_SERVICE_ACCOUNT_UID,
                "AUTHORIZATION_ID=7ee52be0-9045-4653-aa5e-0da57b8dccdc",
                digest("terminal-old-object"),
                digest("terminal-new-object"),
                digest("terminal-executor"),
                digest("terminal-admission-observer"),
            )
            .unwrap();
        store.authorize_admission_or_recover(&admission).unwrap();

        clock.set(107);
        let delete = store
            .prepare_broker_cleanup(
                &broker_capability,
                &BrokerCleanupRequest::new(key.clone(), route).unwrap(),
            )
            .and_then(|intent| store.begin_broker_io(&broker_capability, intent))
            .unwrap();
        store.mark_broker_io_unknown(delete).unwrap();
        clock.set(108);
        let reconcile = store
            .begin_broker_reconciliation(
                &broker_capability,
                &BrokerReconciliationRequest::new(
                    key.clone(),
                    BrokerJournalOperation::DeleteSecret,
                    route,
                )
                .unwrap(),
            )
            .unwrap();
        let retry = store
            .commit_broker_reconciliation(
                reconcile,
                BrokerSecretObservation::matching("secret-uid-terminal".to_owned(), [0xac; 32])
                    .unwrap(),
            )
            .unwrap()
            .into_pending()
            .unwrap();
        clock.set(109);
        store
            .commit_broker_reconciliation(
                retry,
                BrokerSecretObservation::absent([0xad; 32]).unwrap(),
            )
            .unwrap()
            .into_completed()
            .unwrap();

        TerminalMemoryFixture {
            store,
            clock,
            key,
            token,
            registry,
            effect_signer,
            retirement_signer,
            resource_activation_id: active.resource.activation_id,
            mediation_activation_id: active.mediation.activation_id,
            initial_registry_receipt,
        }
    }

    fn terminal_request(
        fixture: &TerminalMemoryFixture,
        terminalization_id: Uuid,
        effect_evidence_id: Uuid,
        retirement_evidence_id: Uuid,
        observed_at: i64,
    ) -> TerminalRetirementRequest {
        let context = fixture
            .store
            .terminal_retirement_context(&fixture.key)
            .unwrap();
        let observation_started_at = context
            .retirement_expectation()
            .deletion()
            .observed_at()
            .checked_add(1)
            .unwrap();
        let effect_claims = EffectObservationClaims::new(
            effect_evidence_id,
            context.attempt().clone(),
            WitnessIssuer::new(
                TERMINAL_EFFECT_OBSERVER,
                fixture.effect_signer.key_id(),
                TERMINAL_AUTHORITY_VERSION,
            )
            .unwrap(),
            EffectObservationResult::new(
                ExactExecutionOutcome::KubernetesDeploymentUpdatedV1,
                digest("terminal-effect-response"),
                digest("terminal-effect-post-state"),
                digest("terminal-effect-complete-observation"),
                REGISTRY_DEPLOYMENT_UID,
                "terminal-resource-version-2",
                "terminal-audit-cursor",
            )
            .unwrap(),
            observation_started_at,
            observed_at,
        )
        .unwrap();
        let retirement_claims = CredentialRetirementClaims::new(
            retirement_evidence_id,
            context.attempt().clone(),
            WitnessIssuer::new(
                TERMINAL_RETIREMENT_OBSERVER,
                fixture.retirement_signer.key_id(),
                TERMINAL_AUTHORITY_VERSION,
            )
            .unwrap(),
            context.credential().clone(),
            context.retirement_expectation().deletion().clone(),
            RetirementBasis::token_review_rejected(
                context.attempt(),
                context.credential(),
                digest("terminal-token-review-response"),
                observation_started_at,
            )
            .unwrap(),
            observation_started_at,
            observed_at,
        )
        .unwrap();
        let effect = sign_effect_observation(effect_claims, &fixture.effect_signer).unwrap();
        let retirement =
            sign_credential_retirement(retirement_claims, &fixture.retirement_signer).unwrap();
        TerminalRetirementRequest::new(
            fixture.key.clone(),
            terminalization_id,
            effect.exact_envelope_bytes().unwrap(),
            retirement.exact_envelope_bytes().unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn terminal_registry_and_final_delete_are_exactly_rooted_and_append_only() {
        let fixture = terminal_memory_fixture();
        assert!(!fixture.initial_registry_receipt.was_recovered());
        assert_eq!(
            fixture.initial_registry_receipt.registry_commitment(),
            fixture.registry.commitment()
        );
        let recovered = fixture
            .store
            .register_terminal_witness_registry_or_recover(
                &fixture.key.scope,
                fixture.resource_activation_id,
                fixture.mediation_activation_id,
                &fixture.registry,
            )
            .unwrap();
        assert!(recovered.was_recovered());

        let activation = ActivationKey {
            scope: fixture.key.scope.clone(),
            resource_activation_id: fixture.resource_activation_id,
            mediation_activation_id: fixture.mediation_activation_id,
        };
        let state = fixture.store.inner.lock();
        let destination = state.eks_destinations.get(&activation).unwrap();
        assert_eq!(
            destination.profile.terminal_witness_registry_commitment(),
            fixture.registry.commitment()
        );
        assert_eq!(
            state.terminal_witness_registry_bindings.get(&activation),
            Some(&fixture.registry.commitment())
        );
        let journal = state
            .broker_operations
            .get(&broker_memory_key(
                &fixture.key,
                BrokerJournalOperation::DeleteSecret,
            ))
            .unwrap();
        let deletion = state
            .secret_deletion_observations
            .get(&(fixture.key.scope.clone(), fixture.key.authorization_id))
            .unwrap();
        assert_eq!(journal.phase, BrokerJournalPhase::Committed);
        assert_eq!(journal.outcome, Some(BrokerJournalOutcome::DeleteAbsent));
        assert_eq!(deletion.entry_id, journal.entry_id);
        assert_eq!(
            deletion.journal_request_commitment,
            journal.request_commitment
        );
        assert_eq!(
            deletion.journal_result_commitment,
            journal.result_commitment.unwrap()
        );
        assert_eq!(
            deletion.provider_evidence_commitment,
            journal.provider_evidence_commitment.unwrap()
        );
        assert_eq!(deletion.reconciliation_floor_at, 108);
        assert_eq!(deletion.observed_at, 109);
        assert_eq!(
            StoredSecretDeletionObservation::from_committed_delete(journal, 109).unwrap(),
            *deletion
        );
        drop(state);

        let wrong_registry = terminal_registry_for_signers(
            &fixture.key.scope,
            "eks://terminal-prod-a",
            &fixture.effect_signer,
            &fixture.retirement_signer,
            Uuid::from_u128(0xb0),
        );
        assert_ne!(wrong_registry.commitment(), fixture.registry.commitment());
        assert!(matches!(
            fixture.store.register_terminal_witness_registry_or_recover(
                &fixture.key.scope,
                fixture.resource_activation_id,
                fixture.mediation_activation_id,
                &wrong_registry,
            ),
            Err(StateError::TerminalWitnessRegistryMismatch)
        ));
    }

    #[test]
    fn terminal_retirement_is_atomic_concurrent_and_exactly_recoverable() {
        let fixture = terminal_memory_fixture();
        fixture.clock.set(112);
        let request = terminal_request(
            &fixture,
            Uuid::from_u128(0xb1),
            Uuid::from_u128(0xb2),
            Uuid::from_u128(0xb3),
            112,
        );
        let barrier = Arc::new(Barrier::new(8));
        let handles = (0..8)
            .map(|_| {
                let store = fixture.store.clone();
                let request = request.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    store.finalize_terminal_retirement_or_recover(&request)
                })
            })
            .collect::<Vec<_>>();
        let receipts = handles
            .into_iter()
            .map(|handle| handle.join().unwrap().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            receipts
                .iter()
                .filter(|receipt| !receipt.was_recovered())
                .count(),
            1
        );
        assert_eq!(
            receipts
                .iter()
                .filter(|receipt| receipt.was_recovered())
                .count(),
            7
        );
        assert!(
            receipts
                .windows(2)
                .all(|pair| pair[0].audit() == pair[1].audit())
        );

        let audit = fixture
            .store
            .terminal_retirement_audit(&fixture.key)
            .unwrap();
        assert_eq!(audit, *receipts[0].audit());
        assert_eq!(audit.claim_id(), fixture.token.claim_id());
        assert_eq!(audit.fence(), fixture.token.fence());
        assert_eq!(audit.state_instance_id(), fixture.token.state_instance_id());
        assert_eq!(audit.registry_commitment(), fixture.registry.commitment());
        assert_eq!(audit.finalized_at(), 112);
        assert_ne!(
            audit.terminal_record_commitment(),
            Digest32::from_bytes([0; 32])
        );
        assert!(matches!(
            fixture.store.terminal_retirement_context(&fixture.key),
            Err(StateError::TerminalRetirementLineageUnavailable)
        ));

        let state = fixture.store.inner.lock();
        let claim_key = (fixture.key.scope.clone(), fixture.key.authorization_id);
        let claim = state.dispatch_claims.get(&claim_key).unwrap();
        assert_eq!(claim.state, MemoryDispatchClaimState::Terminal);
        assert_eq!(claim.token, fixture.token);
        assert_eq!(claim.terminalization_id, Some(Uuid::from_u128(0xb1)));
        assert!(
            !state
                .physical_reservations
                .contains_key(fixture.token.physical_resource())
        );
        assert_eq!(state.broker_operations.len(), 3);
        assert_eq!(state.secret_deletion_observations.len(), 1);
        assert_eq!(state.admission_authorizations.len(), 1);
        assert_eq!(state.terminal_retirements.len(), 1);
        assert_eq!(
            state.terminalization_ids.get(&Uuid::from_u128(0xb1)),
            Some(&claim_key)
        );
        assert_eq!(state.high_water.get(&fixture.key.scope), Some(&112));
    }

    #[test]
    fn terminal_memory_audit_revalidates_historical_registry_and_binding() {
        let fixture = terminal_memory_fixture();
        fixture.clock.set(112);
        let request = terminal_request(
            &fixture,
            Uuid::from_u128(0xb4),
            Uuid::from_u128(0xb5),
            Uuid::from_u128(0xb6),
            112,
        );
        fixture
            .store
            .finalize_terminal_retirement_or_recover(&request)
            .unwrap();
        assert!(
            fixture
                .store
                .terminal_retirement_audit(&fixture.key)
                .is_ok()
        );

        let activation = ActivationKey {
            scope: fixture.key.scope.clone(),
            resource_activation_id: fixture.resource_activation_id,
            mediation_activation_id: fixture.mediation_activation_id,
        };
        let removed_binding = fixture
            .store
            .inner
            .lock()
            .terminal_witness_registry_bindings
            .remove(&activation)
            .unwrap();
        assert!(matches!(
            fixture.store.terminal_retirement_audit(&fixture.key),
            Err(StateError::TerminalWitnessRegistryNotFound)
        ));
        fixture
            .store
            .inner
            .lock()
            .terminal_witness_registry_bindings
            .insert(activation, removed_binding);

        let removed_registry = fixture
            .store
            .inner
            .lock()
            .terminal_witness_registries
            .remove(&fixture.registry.commitment())
            .unwrap();
        assert!(matches!(
            fixture.store.terminal_retirement_audit(&fixture.key),
            Err(StateError::TerminalWitnessRegistryNotFound)
        ));
        fixture
            .store
            .inner
            .lock()
            .terminal_witness_registries
            .insert(fixture.registry.commitment(), removed_registry);
        assert!(
            fixture
                .store
                .terminal_retirement_audit(&fixture.key)
                .is_ok()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn unauthenticated_or_misrouted_terminal_evidence_is_hwm_inert() {
        let fixture = terminal_memory_fixture();
        fixture.clock.set(112);
        let valid = terminal_request(
            &fixture,
            Uuid::from_u128(0xc1),
            Uuid::from_u128(0xc2),
            Uuid::from_u128(0xc3),
            112,
        );
        let baseline = fixture.store.time_high_water(&fixture.key.scope).unwrap();

        let (effect, _) = valid.decoded().unwrap();
        let mut corrupted_cose = effect.cose_sign1().to_vec();
        *corrupted_cose.last_mut().unwrap() ^= 1;
        let corrupted_effect = SignedEffectWitness::from_untrusted_parts(
            effect.key_id(),
            effect.claims().clone(),
            corrupted_cose,
        )
        .unwrap();
        let corrupted = TerminalRetirementRequest::new(
            fixture.key.clone(),
            valid.terminalization_id(),
            corrupted_effect.exact_envelope_bytes().unwrap(),
            valid.retirement_envelope().to_vec(),
        )
        .unwrap();
        assert!(matches!(
            fixture
                .store
                .finalize_terminal_retirement_or_recover(&corrupted),
            Err(StateError::TerminalEvidenceInvalid(_))
        ));
        assert_eq!(
            fixture.store.time_high_water(&fixture.key.scope).unwrap(),
            baseline
        );

        let wrong_transaction = TerminalRetirementRequest::new(
            ConsumeKey {
                scope: fixture.key.scope.clone(),
                transaction_id: Uuid::from_u128(0xc4),
                authorization_id: fixture.key.authorization_id,
            },
            valid.terminalization_id(),
            valid.effect_envelope().to_vec(),
            valid.retirement_envelope().to_vec(),
        )
        .unwrap();
        assert!(
            fixture
                .store
                .finalize_terminal_retirement_or_recover(&wrong_transaction)
                .is_err()
        );
        assert_eq!(
            fixture.store.time_high_water(&fixture.key.scope).unwrap(),
            baseline
        );

        let activation = ActivationKey {
            scope: fixture.key.scope.clone(),
            resource_activation_id: fixture.resource_activation_id,
            mediation_activation_id: fixture.mediation_activation_id,
        };
        fixture
            .store
            .inner
            .lock()
            .terminal_witness_registry_bindings
            .insert(activation.clone(), digest("wrong-terminal-registry"));
        assert!(matches!(
            fixture
                .store
                .finalize_terminal_retirement_or_recover(&valid),
            Err(StateError::TerminalWitnessRegistryMismatch)
        ));
        assert_eq!(
            fixture.store.time_high_water(&fixture.key.scope).unwrap(),
            baseline
        );
        fixture
            .store
            .inner
            .lock()
            .terminal_witness_registry_bindings
            .insert(activation, fixture.registry.commitment());

        let context = fixture
            .store
            .terminal_retirement_context(&fixture.key)
            .unwrap();
        let wrong_role_claims = EffectObservationClaims::new(
            Uuid::from_u128(0xc5),
            context.attempt().clone(),
            WitnessIssuer::new(
                TERMINAL_RETIREMENT_OBSERVER,
                fixture.retirement_signer.key_id(),
                TERMINAL_AUTHORITY_VERSION,
            )
            .unwrap(),
            EffectObservationResult::new(
                ExactExecutionOutcome::KubernetesDeploymentUpdatedV1,
                digest("wrong-role-response"),
                digest("wrong-role-post-state"),
                digest("wrong-role-complete"),
                REGISTRY_DEPLOYMENT_UID,
                "terminal-resource-version-3",
                "wrong-role-audit-cursor",
            )
            .unwrap(),
            110,
            112,
        )
        .unwrap();
        let wrong_role = sign_effect_observation(wrong_role_claims, &fixture.retirement_signer)
            .unwrap()
            .exact_envelope_bytes()
            .unwrap();
        let purpose_confused = TerminalRetirementRequest::new(
            fixture.key.clone(),
            Uuid::from_u128(0xc6),
            wrong_role,
            valid.retirement_envelope().to_vec(),
        )
        .unwrap();
        assert!(matches!(
            fixture
                .store
                .finalize_terminal_retirement_or_recover(&purpose_confused),
            Err(StateError::TerminalEvidenceInvalid(_))
        ));
        assert_eq!(
            fixture.store.time_high_water(&fixture.key.scope).unwrap(),
            baseline
        );
    }

    #[test]
    fn authenticated_future_terminal_evidence_persists_hwm_then_detects_rollback() {
        let fixture = terminal_memory_fixture();
        let request = terminal_request(
            &fixture,
            Uuid::from_u128(0xd1),
            Uuid::from_u128(0xd2),
            Uuid::from_u128(0xd3),
            120,
        );
        fixture.clock.set(115);
        assert!(matches!(
            fixture
                .store
                .finalize_terminal_retirement_or_recover(&request),
            Err(StateError::TerminalEvidenceFuture {
                observed: 120,
                trusted_now: 115
            })
        ));
        assert_eq!(
            fixture.store.time_high_water(&fixture.key.scope).unwrap(),
            Some(115)
        );
        assert!(fixture.store.inner.lock().terminal_retirements.is_empty());

        fixture.clock.set(114);
        assert!(matches!(
            fixture
                .store
                .finalize_terminal_retirement_or_recover(&request),
            Err(StateError::ClockRollback {
                observed: 114,
                high_water: 115
            })
        ));
        assert_eq!(
            fixture.store.time_high_water(&fixture.key.scope).unwrap(),
            Some(115)
        );

        fixture.clock.set(120);
        let receipt = fixture
            .store
            .finalize_terminal_retirement_or_recover(&request)
            .unwrap();
        assert!(!receipt.was_recovered());
        assert_eq!(receipt.audit().finalized_at(), 120);
        assert_eq!(
            fixture.store.time_high_water(&fixture.key.scope).unwrap(),
            Some(120)
        );
    }

    #[test]
    fn terminal_evidence_ids_and_envelope_commitments_are_globally_unique() {
        let fixture = terminal_memory_fixture();
        fixture.clock.set(112);
        let request = terminal_request(
            &fixture,
            Uuid::from_u128(0xe1),
            Uuid::from_u128(0xe2),
            Uuid::from_u128(0xe3),
            112,
        );
        let (effect, retirement) = request.decoded().unwrap();
        let effect_id = effect.claims().evidence_id();
        let retirement_id = retirement.claims().evidence_id();
        let effect_commitment = Digest32::sha256(request.effect_envelope());
        let retirement_commitment = Digest32::sha256(request.retirement_envelope());
        let other = (
            Scope::new("other-terminal-owner", "prod").unwrap(),
            Uuid::new_v4(),
        );
        let baseline = fixture.store.time_high_water(&fixture.key.scope).unwrap();

        fixture
            .store
            .inner
            .lock()
            .terminal_effect_evidence_ids
            .insert(effect_id, other.clone());
        assert!(matches!(
            fixture
                .store
                .finalize_terminal_retirement_or_recover(&request),
            Err(StateError::TerminalRetirementMismatch)
        ));
        fixture
            .store
            .inner
            .lock()
            .terminal_effect_evidence_ids
            .remove(&effect_id);

        fixture
            .store
            .inner
            .lock()
            .terminal_retirement_evidence_ids
            .insert(retirement_id, other.clone());
        assert!(matches!(
            fixture
                .store
                .finalize_terminal_retirement_or_recover(&request),
            Err(StateError::TerminalRetirementMismatch)
        ));
        fixture
            .store
            .inner
            .lock()
            .terminal_retirement_evidence_ids
            .remove(&retirement_id);

        fixture
            .store
            .inner
            .lock()
            .terminal_effect_envelope_commitments
            .insert(effect_commitment, other.clone());
        assert!(matches!(
            fixture
                .store
                .finalize_terminal_retirement_or_recover(&request),
            Err(StateError::TerminalRetirementMismatch)
        ));
        fixture
            .store
            .inner
            .lock()
            .terminal_effect_envelope_commitments
            .remove(&effect_commitment);

        fixture
            .store
            .inner
            .lock()
            .terminal_retirement_envelope_commitments
            .insert(retirement_commitment, other);
        assert!(matches!(
            fixture
                .store
                .finalize_terminal_retirement_or_recover(&request),
            Err(StateError::TerminalRetirementMismatch)
        ));
        fixture
            .store
            .inner
            .lock()
            .terminal_retirement_envelope_commitments
            .remove(&retirement_commitment);
        assert_eq!(
            fixture.store.time_high_water(&fixture.key.scope).unwrap(),
            baseline
        );

        let receipt = fixture
            .store
            .finalize_terminal_retirement_or_recover(&request)
            .unwrap();
        assert!(!receipt.was_recovered());
    }

    #[test]
    fn deletion_observation_before_start_or_reconciliation_floor_fails_closed() {
        let fixture = terminal_memory_fixture();
        let observation_key = (fixture.key.scope.clone(), fixture.key.authorization_id);
        let (original, started_at, floor) = {
            let state = fixture.store.inner.lock();
            let deletion = state
                .secret_deletion_observations
                .get(&observation_key)
                .unwrap()
                .clone();
            let journal = state
                .broker_operations
                .get(&broker_memory_key(
                    &fixture.key,
                    BrokerJournalOperation::DeleteSecret,
                ))
                .unwrap();
            (
                deletion,
                journal.started_at.unwrap(),
                journal.last_reconciled_at.unwrap(),
            )
        };
        assert!(floor > started_at);

        fixture
            .store
            .inner
            .lock()
            .secret_deletion_observations
            .get_mut(&observation_key)
            .unwrap()
            .observed_at = started_at - 1;
        assert!(matches!(
            fixture.store.terminal_retirement_context(&fixture.key),
            Err(StateError::InvalidRecord(_) | StateError::TerminalRetirementLineageUnavailable)
        ));

        fixture
            .store
            .inner
            .lock()
            .secret_deletion_observations
            .insert(observation_key.clone(), original.clone());
        fixture
            .store
            .inner
            .lock()
            .secret_deletion_observations
            .get_mut(&observation_key)
            .unwrap()
            .observed_at = floor - 1;
        assert!(floor > started_at);
        assert!(matches!(
            fixture.store.terminal_retirement_context(&fixture.key),
            Err(StateError::InvalidRecord(_) | StateError::TerminalRetirementLineageUnavailable)
        ));

        fixture
            .store
            .inner
            .lock()
            .secret_deletion_observations
            .insert(observation_key, original);
        assert!(
            fixture
                .store
                .terminal_retirement_context(&fixture.key)
                .is_ok()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn rooted_eks_registry_derives_current_and_frozen_attempts() {
        let (store, clock, key, token, profile, active) = rooted_registry_attempt();
        let broker_capability = broker_capability(&store);
        clock.set(102);
        let current = store
            .load_current_eks_attempt(&key.scope, key.transaction_id)
            .unwrap();
        assert!(current.facts().route().exactly_matches(profile.route()));
        assert_eq!(
            current.facts().physical_resource(),
            token.physical_resource()
        );
        assert_eq!(
            current.facts().token_subject(),
            "system:serviceaccount:payments:accordlock-attempt"
        );
        assert_eq!(
            current.facts().service_account_uid(),
            REGISTRY_SERVICE_ACCOUNT_UID
        );
        assert_eq!(
            current.facts().effective_rbac_commitment(),
            digest_bytes(0x41)
        );
        assert_eq!(
            current.facts().terminal_witness_registry_commitment(),
            digest_bytes(0x51)
        );
        assert_eq!(
            current.facts().credential_lifecycle_policy(),
            EksCredentialLifecyclePolicy::new(600, 900, 5, 60).unwrap()
        );
        assert_eq!(
            current.facts().broker_management_bindings(),
            profile.broker_management_bindings()
        );
        assert_ne!(
            current.facts().template_hash(),
            Digest32::from_bytes([0; 32])
        );
        assert_ne!(
            current.facts().operation_hash(),
            Digest32::from_bytes([0; 32])
        );
        assert_ne!(
            current.facts().execution_command_commitment(),
            Digest32::from_bytes([0; 32])
        );
        assert_ne!(
            current.facts().provider_request_commitment(),
            Digest32::from_bytes([0; 32])
        );
        assert!(matches!(
            store.load_frozen_eks_attempt(&key.scope, key.transaction_id),
            Err(EksRegistryError::FrozenLineageUnavailable)
        ));

        let route = *profile.route().commitment().as_bytes();
        clock.set(103);
        let create = store
            .prepare_broker_operation(
                &broker_capability,
                BrokerOperationRequest::create(&token, route).unwrap(),
            )
            .and_then(|intent| store.begin_broker_io(&broker_capability, intent))
            .unwrap();
        store.mark_broker_io_unknown(create).unwrap();
        let reconciliation = store
            .begin_broker_reconciliation(
                &broker_capability,
                &BrokerReconciliationRequest::new(
                    key.clone(),
                    BrokerJournalOperation::CreateSecret,
                    route,
                )
                .unwrap(),
            )
            .unwrap();
        drop(reconciliation);
        let frozen = store
            .load_frozen_eks_attempt(&key.scope, key.transaction_id)
            .unwrap();
        assert_eq!(
            frozen.facts().activation_commitment(),
            current.facts().activation_commitment()
        );

        let mut revoked = active.clone();
        revoked.revocation.epoch += 1;
        revoked.revocation.activation_id = Uuid::new_v4();
        revoked.revocation.root = digest("registry-revocation-advanced");
        // Any full-authority change invalidates current facts. Frozen cleanup
        // remains pinned to the consumed authorization and exact broker journal.
        store
            .compare_and_activate_authority(&key.scope, Some(&active), &revoked)
            .unwrap();
        clock.set(104);
        assert!(
            store
                .load_current_eks_attempt(&key.scope, key.transaction_id)
                .is_err()
        );
        assert!(
            store
                .load_frozen_eks_attempt(&key.scope, key.transaction_id)
                .is_ok()
        );
    }

    #[test]
    fn rooted_eks_registry_claim_preflight_is_hwm_inert() {
        let (store, clock, key, token, _, _) = rooted_registry_attempt();
        let before = store.time_high_water(&key.scope).unwrap();
        store
            .inner
            .lock()
            .physical_reservations
            .remove(token.physical_resource());
        clock.set(102);
        assert!(matches!(
            store.load_current_eks_attempt(&key.scope, key.transaction_id),
            Err(EksRegistryError::FrozenLineageUnavailable)
        ));
        assert_eq!(store.time_high_water(&key.scope).unwrap(), before);
    }

    #[test]
    fn rooted_eks_registry_lease_expiry_persists_hwm() {
        let (store, clock, key, token, _, _) = rooted_registry_attempt();
        clock.set(token.lease_until());
        assert!(matches!(
            store.load_current_eks_attempt(&key.scope, key.transaction_id),
            Err(EksRegistryError::State(
                StateError::DispatchClaimLeaseExpired {
                    observed,
                    lease_until
                }
            )) if observed == token.lease_until() && lease_until == token.lease_until()
        ));
        assert_eq!(
            store.time_high_water(&key.scope).unwrap(),
            Some(token.lease_until())
        );
    }

    const fn digest_bytes(marker: u8) -> Digest32 {
        Digest32::from_bytes([marker; 32])
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn rooted_eks_registry_rejects_root_terminal_and_global_alias_substitution() {
        let clock = Arc::new(TestClock::new(100));
        let store = InMemoryStore::with_clock(clock);
        let first_scope = Scope::new("owner-a", "prod").unwrap();
        let first = registry_profile(
            registry_route(
                "eks://prod-a",
                "urn:accordlock:api:shared",
                "192.0.2.42:443",
            ),
            0x61,
            0x71,
        );
        let first_authority = registry_authority(&first_scope, &first, None);
        store
            .compare_and_activate_authority(&first_scope, None, &first_authority)
            .unwrap();
        store
            .activate_eks_destination(&first_scope, &first)
            .unwrap();
        store
            .activate_eks_destination(&first_scope, &first)
            .unwrap();

        let first_resource_activation = first_authority.resource.clone();
        let mut rotated = first_authority.clone();
        rotated.resource.epoch += 1;
        rotated.resource.activation_id = Uuid::new_v4();
        rotated.mediation.epoch += 1;
        rotated.mediation.activation_id = Uuid::new_v4();
        rotated.mediation.root = first
            .mediation_root(&first_scope, &rotated.resource)
            .unwrap();
        store
            .compare_and_activate_authority(&first_scope, Some(&first_authority), &rotated)
            .unwrap();
        store
            .activate_eks_destination(&first_scope, &first)
            .unwrap();
        let state = store.inner.lock();
        assert_eq!(state.eks_destinations.len(), 2);
        assert_eq!(
            state
                .eks_physical_owners
                .values()
                .next()
                .unwrap()
                .first_resource_authority,
            first_resource_activation
        );
        drop(state);

        let terminal_substitution = registry_profile(first.route().clone(), 0x61, 0x72);
        assert!(matches!(
            store.activate_eks_destination(&first_scope, &terminal_substitution),
            Err(EksRegistryError::AuthorityRootMismatch)
        ));

        for lifecycle in [
            EksCredentialLifecyclePolicy::new(601, 900, 5, 60).unwrap(),
            EksCredentialLifecyclePolicy::new(600, 901, 5, 60).unwrap(),
            EksCredentialLifecyclePolicy::new(600, 900, 6, 60).unwrap(),
            EksCredentialLifecyclePolicy::new(600, 900, 5, 61).unwrap(),
        ] {
            let substituted = registry_profile_with_security(
                first.route().clone(),
                0x61,
                0x71,
                lifecycle,
                first.broker_management_bindings().clone(),
            );
            assert!(matches!(
                store.activate_eks_destination(&first_scope, &substituted),
                Err(EksRegistryError::AuthorityRootMismatch)
            ));
        }

        let original_management = first.broker_management_bindings();
        let permuted_management = EksBrokerManagementBindings::new(
            original_management.service_account_token().clone(),
            original_management.secret_lifecycle().clone(),
            original_management.token_review().clone(),
        )
        .unwrap();
        let management_substitution = registry_profile_with_security(
            first.route().clone(),
            0x61,
            0x71,
            first.credential_lifecycle_policy(),
            permuted_management,
        );
        assert!(matches!(
            store.activate_eks_destination(&first_scope, &management_substitution),
            Err(EksRegistryError::AuthorityRootMismatch)
        ));

        for variant in 0..6 {
            let changed_management = registry_management_substitution(original_management, variant);
            let substituted = registry_profile_with_security(
                first.route().clone(),
                0x61,
                0x71,
                first.credential_lifecycle_policy(),
                changed_management,
            );
            assert!(matches!(
                store.activate_eks_destination(&first_scope, &substituted),
                Err(EksRegistryError::AuthorityRootMismatch)
            ));
        }

        let second_scope = Scope::new("owner-b", "prod").unwrap();
        let cluster_alias = registry_profile(
            registry_route(
                "eks://alias-for-prod-a",
                "urn:accordlock:api:shared",
                "192.0.2.42:443",
            ),
            0x62,
            0x73,
        );
        let second_authority = registry_authority(&second_scope, &cluster_alias, None);
        store
            .compare_and_activate_authority(&second_scope, None, &second_authority)
            .unwrap();
        assert!(matches!(
            store.activate_eks_destination(&second_scope, &cluster_alias),
            Err(EksRegistryError::PhysicalAliasConflict)
        ));

        let api_alias = registry_profile(
            registry_route(
                "eks://another-alias",
                "urn:accordlock:api:alternate",
                "192.0.2.42:443",
            ),
            0x63,
            0x74,
        );
        let third_scope = Scope::new("owner-c", "prod").unwrap();
        let third_authority = registry_authority(&third_scope, &api_alias, None);
        store
            .compare_and_activate_authority(&third_scope, None, &third_authority)
            .unwrap();
        assert!(matches!(
            store.activate_eks_destination(&third_scope, &api_alias),
            Err(EksRegistryError::PhysicalAliasConflict)
        ));
    }

    #[test]
    fn ingress_replay_is_scope_and_key_bound_and_reusable_at_expiry() {
        let store = InMemoryStore::new();
        let first = IngressReplayScope::new("accordlock://tenant-a/prod").unwrap();
        let second = IngressReplayScope::new("accordlock://tenant-b/prod").unwrap();
        let initial = ingress_consumption(&first, "key-a", 0xe1, 20, 10);
        assert_eq!(
            store.consume_ingress_nonce(&initial).unwrap(),
            IngressReplayDecision::Consumed
        );
        assert_eq!(
            store
                .consume_ingress_nonce(&ingress_consumption(&first, "key-a", 0xe1, 21, 19))
                .unwrap(),
            IngressReplayDecision::AlreadyUsed
        );
        assert_eq!(
            store
                .consume_ingress_nonce(&ingress_consumption(&first, "key-b", 0xe1, 21, 19))
                .unwrap(),
            IngressReplayDecision::Consumed
        );
        assert_eq!(
            store
                .consume_ingress_nonce(&ingress_consumption(&second, "key-a", 0xe1, 21, 19))
                .unwrap(),
            IngressReplayDecision::Consumed
        );
        assert_eq!(
            store
                .consume_ingress_nonce(&ingress_consumption(&first, "key-a", 0xe1, 30, 20))
                .unwrap(),
            IngressReplayDecision::Consumed
        );
    }

    #[test]
    fn ingress_rollback_and_invalid_requests_do_not_mutate_state() {
        let store = InMemoryStore::new();
        let scope = IngressReplayScope::new("accordlock://tenant-a/prod").unwrap();
        store.observe_ingress_time(&scope, 30).unwrap();
        assert!(matches!(
            store.observe_ingress_time(&scope, 29),
            Err(StateError::ClockRollback {
                observed: 29,
                high_water: 30
            })
        ));
        assert!(IngressNonceConsumption::new(scope.clone(), "key-a", Uuid::nil(), 40, 31).is_err());
        let state = store.inner.lock();
        assert_eq!(state.ingress_replay_high_water.get(&scope), Some(&30));
        assert!(state.ingress_replay_nonces.is_empty());
    }

    #[test]
    fn ingress_gc_is_bounded_by_durable_high_water_and_never_creates_scope() {
        let store = InMemoryStore::new();
        let absent = IngressReplayScope::new("accordlock://absent/prod").unwrap();
        assert!(matches!(
            store.prune_expired_ingress_nonces(&absent, 1),
            Err(StateError::InvalidRecord(_))
        ));
        assert!(store.inner.lock().ingress_replay_high_water.is_empty());

        let scope = IngressReplayScope::new("accordlock://tenant-a/prod").unwrap();
        store
            .consume_ingress_nonce(&ingress_consumption(&scope, "key-a", 0xe2, 15, 10))
            .unwrap();
        store
            .consume_ingress_nonce(&ingress_consumption(&scope, "key-a", 0xe3, 16, 10))
            .unwrap();
        store
            .consume_ingress_nonce(&ingress_consumption(&scope, "key-a", 0xe4, 30, 10))
            .unwrap();
        store.observe_ingress_time(&scope, 20).unwrap();
        assert_eq!(store.prune_expired_ingress_nonces(&scope, 1).unwrap(), 1);
        let state = store.inner.lock();
        assert_eq!(state.ingress_replay_high_water.get(&scope), Some(&20));
        assert_eq!(state.ingress_replay_nonces.len(), 2);
    }

    #[test]
    fn concurrent_ingress_consumption_has_exactly_one_winner() {
        let store = InMemoryStore::new();
        let scope = IngressReplayScope::new("accordlock://tenant-a/prod").unwrap();
        let request = ingress_consumption(&scope, "key-a", 0xe5, 30, 10);
        let barrier = Arc::new(Barrier::new(16));
        let handles = (0..16)
            .map(|_| {
                let store = store.clone();
                let request = request.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    store.consume_ingress_nonce(&request)
                })
            })
            .collect::<Vec<_>>();
        let decisions = handles
            .into_iter()
            .map(|handle| handle.join().unwrap().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            decisions
                .iter()
                .filter(|decision| **decision == IngressReplayDecision::Consumed)
                .count(),
            1
        );
        assert_eq!(
            decisions
                .iter()
                .filter(|decision| **decision == IngressReplayDecision::AlreadyUsed)
                .count(),
            15
        );
    }
}

#[cfg(test)]
mod control_tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::collections::BTreeSet;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicI64, Ordering};

    use accordlock_eks_profile::{
        CaTrustCommitment, EksBrokerManagementBindings, EksCredentialLifecyclePolicy,
        EksManagementAuthorityBinding, EksRouteProfile, EksRouteProfileInput, PinnedSocketTarget,
    };
    use accordlock_ingress::{
        ActivatedIngressRegistry, INGRESS_SCHEMA_VERSION, IngressAuthenticator, IngressClaims,
        IngressKeyStatus, IngressRecoveryProbe, MemoryReplayGuard, RegisteredIngressKey,
        sign_ingress_request,
    };
    use accordlock_protocol::{
        AgentProposal, AuthorityDomainState, CapabilityGrant, DeploymentTemplate,
        DispatchDeadlinePolicy, EXECUTION_AUTHORIZATION_DOMAIN,
        EXECUTION_AUTHORIZATION_SCHEMA_VERSION, EvaluationAttestation, ExecutionAuthorization,
        SignedAuthorization, SigningIdentity, authorization_signer_root, canonical_hash,
        evaluator_verifier_root, sign_cose,
    };

    use super::*;
    use crate::{
        BrokerCredentialSafetyPolicy, ControlSubmissionReceipt, DispatchBrokerRestartAction,
        DispatchCredentialReviewClaims,
    };

    const CONTROL_NOW: i64 = 100;
    const CONTROL_AUDIENCE: &str = "accordlock-executor:prod";

    fn broker_capability(store: &InMemoryStore) -> BrokerJournalCapability {
        let mut bootstrap = store.clone();
        bootstrap.issue_broker_journal_capability().unwrap()
    }

    #[derive(Debug)]
    struct ControlClock(AtomicI64);

    impl ControlClock {
        fn new(now: i64) -> Self {
            Self(AtomicI64::new(now))
        }

        fn set(&self, now: i64) {
            self.0.store(now, Ordering::SeqCst);
        }
    }

    impl TrustedClock for ControlClock {
        fn now_unix_seconds(&self) -> Result<i64, StateError> {
            Ok(self.0.load(Ordering::SeqCst))
        }
    }

    struct ControlFixture {
        store: InMemoryStore,
        clock: Arc<ControlClock>,
        authenticator: IngressAuthenticator<MemoryReplayGuard>,
        ingress_signer: SigningIdentity,
        evaluator: SigningIdentity,
        authorization_signer: SigningIdentity,
        authority: AuthorityVector,
        grant: GrantRegistration,
        proposal_template: DeploymentTemplate,
    }

    impl ControlFixture {
        fn new(register_grant: bool) -> Self {
            Self::with_dispatch_policy(
                register_grant,
                DispatchDeadlinePolicy {
                    max_dispatch_delay_seconds: 30,
                    profile_hard_cap: 500,
                    immutable_dependency_expiries: vec![400],
                },
            )
        }

        fn with_dispatch_policy(
            register_grant: bool,
            dispatch_deadline_policy: DispatchDeadlinePolicy,
        ) -> Self {
            Self::with_policies(
                register_grant,
                dispatch_deadline_policy,
                EksCredentialLifecyclePolicy::new(600, 900, 5, 60).unwrap(),
            )
        }

        #[allow(clippy::too_many_lines)]
        fn with_policies(
            register_grant: bool,
            dispatch_deadline_policy: DispatchDeadlinePolicy,
            credential_lifecycle_policy: EksCredentialLifecyclePolicy,
        ) -> Self {
            let clock = Arc::new(ControlClock::new(CONTROL_NOW));
            let store = InMemoryStore::with_clock(clock.clone());
            let ingress_signer = SigningIdentity::from_seed("control-ingress", [31; 32]);
            let evaluator = SigningIdentity::from_seed("control-evaluator", [32; 32]);
            let authorization_signer =
                SigningIdentity::from_seed("control-authorization", [33; 32]);
            let registration = RegisteredIngressKey {
                key_id: ingress_signer.key_id().to_owned(),
                public_key: ingress_signer.public_key_bytes(),
                tenant: "acme".to_owned(),
                actor: "workload-a".to_owned(),
                allowed_audiences: BTreeSet::from([CONTROL_AUDIENCE.to_owned()]),
                not_before: 50,
                expires_at: 500,
                status: IngressKeyStatus::Active,
            };
            let principal_root = ActivatedIngressRegistry::compute_root(
                CONTROL_AUDIENCE,
                120,
                std::slice::from_ref(&registration),
            )
            .unwrap();
            let principal_registry = AuthorityDomainState {
                root: principal_root,
                epoch: 1,
                activation_id: Uuid::from_u128(0x1301),
            };
            let registry = ActivatedIngressRegistry::new(
                principal_registry.clone(),
                CONTROL_AUDIENCE,
                120,
                vec![registration],
            )
            .unwrap();
            let authenticator =
                IngressAuthenticator::new(registry, MemoryReplayGuard::default()).unwrap();

            let scope = Scope::new("acme", "prod").unwrap();
            let route = EksRouteProfile::new(EksRouteProfileInput {
                cluster_trust_domain: "spiffe://example.test/eks/control",
                cluster_identity: "eks://cluster-a",
                api_server_identity: "urn:accordlock:api:control",
                dns_server_name: "control.eks.example.test",
                port: 443,
                socket_target: PinnedSocketTarget::new(
                    SocketAddr::from_str("192.0.2.20:443").unwrap(),
                )
                .unwrap(),
                ca_trust_commitment: CaTrustCommitment::from_der_certificates(&[
                    b"control-test-ca".to_vec(),
                ])
                .unwrap(),
                namespace: "payments",
                deployment_name: "payments",
                deployment_uid: "11111111-1111-4111-8111-111111111111",
                attempt_service_account_name: "accordlock-attempt",
                attempt_service_account_uid: "22222222-2222-4222-8222-222222222222",
                token_audience: "urn:accordlock:kubernetes-api:control",
            })
            .unwrap();
            let management = EksBrokerManagementBindings::new(
                EksManagementAuthorityBinding::new(
                    "spiffe://accordlock.test/control/secret".to_owned(),
                    [0xa1; 32],
                )
                .unwrap(),
                EksManagementAuthorityBinding::new(
                    "spiffe://accordlock.test/control/token".to_owned(),
                    [0xa2; 32],
                )
                .unwrap(),
                EksManagementAuthorityBinding::new(
                    "spiffe://accordlock.test/control/review".to_owned(),
                    [0xa3; 32],
                )
                .unwrap(),
            )
            .unwrap();
            let destination = EksDestinationProfile::new(
                route,
                [0xa4; 32],
                [0xa5; 32],
                credential_lifecycle_policy,
                management,
            )
            .unwrap();
            let capability = CapabilityGrant {
                grant_id: Uuid::from_u128(0x1310),
                holder: "workload-a".to_owned(),
                tenant: "acme".to_owned(),
                operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
                repository: "acme/payments".to_owned(),
                audience: CONTROL_AUDIENCE.to_owned(),
                cluster_identity: "eks://cluster-a".to_owned(),
                namespace: "payments".to_owned(),
                deployment_uid: "11111111-1111-4111-8111-111111111111".to_owned(),
                container: "app".to_owned(),
                image_repository: "registry.example/acme/payments".to_owned(),
                not_before: 50,
                expires_at: 500,
                maximum_uses: 8,
            };
            let mut authority = control_authority();
            authority.principal_registry = principal_registry;
            authority.kernel_configuration.root =
                evaluator_verifier_root(evaluator.key_id(), evaluator.public_key_bytes()).unwrap();
            authority.signer.root = authorization_signer_root(
                authorization_signer.key_id(),
                authorization_signer.public_key_bytes(),
            )
            .unwrap();
            authority.grant_registry.root = canonical_hash(&capability).unwrap();
            authority.resource.root = destination.resource_root(&scope).unwrap();
            authority.mediation.root = destination
                .mediation_root(&scope, &authority.resource)
                .unwrap();
            let grant = GrantRegistration {
                environment: "prod".to_owned(),
                grant: capability,
                authority: authority.clone(),
                dispatch_deadline_policy,
            };
            store
                .compare_and_activate_authority(&scope, None, &authority)
                .unwrap();
            store
                .activate_eks_destination(&scope, &destination)
                .unwrap();
            if register_grant {
                store.register_grant(&grant).unwrap();
            }
            Self {
                store,
                clock,
                authenticator,
                ingress_signer,
                evaluator,
                authorization_signer,
                authority,
                grant,
                proposal_template: control_proposal(Uuid::nil()).template,
            }
        }

        fn signed_wire(
            &self,
            request_id: u128,
            nonce: u128,
            issued_at: i64,
            expires_at: i64,
        ) -> Vec<u8> {
            let mut proposal = control_proposal(Uuid::from_u128(request_id));
            proposal.template = self.proposal_template.clone();
            let request = sign_ingress_request(
                IngressClaims {
                    schema_version: INGRESS_SCHEMA_VERSION,
                    audience: CONTROL_AUDIENCE.to_owned(),
                    issued_at,
                    expires_at,
                    nonce: Uuid::from_u128(nonce),
                    proposal,
                },
                &self.ingress_signer,
            )
            .unwrap();
            serde_json::to_vec(&request).unwrap()
        }

        fn verify_wire(&self, wire: &[u8]) -> StaticallyVerifiedIngressSubmission {
            self.authenticator
                .verify_durable_static(IngressRecoveryProbe::parse_bytes(wire).unwrap())
                .unwrap()
        }

        fn accept(&self, request_id: u128, nonce: u128) -> ControlSubmissionReceipt {
            self.accept_with_expiry(request_id, nonce, 160)
        }

        fn accept_with_expiry(
            &self,
            request_id: u128,
            nonce: u128,
            expires_at: i64,
        ) -> ControlSubmissionReceipt {
            let wire = self.signed_wire(request_id, nonce, 99, expires_at);
            match self
                .store
                .accept_control_submission_or_recover(self.verify_wire(&wire))
                .unwrap()
            {
                ControlSubmissionIntakeOutcome::Fresh(receipt) => receipt,
                other => panic!("expected fresh control intake, got {other:?}"),
            }
        }
    }

    fn control_domain(label: &str) -> AuthorityDomainState {
        AuthorityDomainState {
            root: Digest32::sha256(label.as_bytes()),
            epoch: 1,
            activation_id: Uuid::new_v4(),
        }
    }

    fn control_authority() -> AuthorityVector {
        AuthorityVector {
            policy: control_domain("control-policy"),
            registry: control_domain("control-registry"),
            revocation: control_domain("control-revocation"),
            connector: control_domain("control-connector"),
            resource: control_domain("control-resource"),
            signer: control_domain("control-signer"),
            mediation: control_domain("control-mediation"),
            grant_registry: control_domain("control-grant"),
            office_act_registry: control_domain("control-office"),
            principal_registry: control_domain("control-principal"),
            workload_build_allowlist: control_domain("control-build"),
            kernel_configuration: control_domain("control-kernel"),
        }
    }

    fn control_proposal(request_id: Uuid) -> AgentProposal {
        AgentProposal {
            schema_version: 1,
            request_id,
            tenant: "acme".to_owned(),
            actor: "workload-a".to_owned(),
            template: DeploymentTemplate {
                operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
                environment: "prod".to_owned(),
                audience: CONTROL_AUDIENCE.to_owned(),
                repository: "acme/payments".to_owned(),
                commit_sha: "1111111111111111111111111111111111111111".to_owned(),
                image_repository: "registry.example/acme/payments".to_owned(),
                image_digest: Digest32::sha256(b"control-image"),
                cluster_identity: "eks://cluster-a".to_owned(),
                namespace: "payments".to_owned(),
                deployment: "payments".to_owned(),
                deployment_uid: "11111111-1111-4111-8111-111111111111".to_owned(),
                container: "app".to_owned(),
                container_index: 0,
                prior_image_digest: Digest32::sha256(b"control-prior-image"),
                resource_version: "1001".to_owned(),
                prior_projection_hash: Digest32::sha256(b"control-projection"),
                prior_transaction_annotation: Some("none".to_owned()),
                prior_authorization_annotation: Some("none".to_owned()),
                prior_operation_hash_annotation: Some("none".to_owned()),
            },
        }
    }

    fn rotate_control_fixture_to_distinct_physical(fixture: &mut ControlFixture, label: &str) {
        let scope = Scope::new("acme", "prod").unwrap();
        let cluster_identity = format!("eks://cluster-{label}");
        let api_server_identity = format!("urn:accordlock:api:{label}");
        let dns_server_name = format!("{label}.eks.example.test");
        let deployment_uid = Uuid::new_v4().to_string();
        let route = EksRouteProfile::new(EksRouteProfileInput {
            cluster_trust_domain: "spiffe://example.test/eks/control-rotated",
            cluster_identity: &cluster_identity,
            api_server_identity: &api_server_identity,
            dns_server_name: &dns_server_name,
            port: 443,
            socket_target: PinnedSocketTarget::new(SocketAddr::from_str("192.0.2.21:443").unwrap())
                .unwrap(),
            ca_trust_commitment: CaTrustCommitment::from_der_certificates(&[
                b"control-test-ca-rotated".to_vec(),
            ])
            .unwrap(),
            namespace: "payments",
            deployment_name: "payments",
            deployment_uid: &deployment_uid,
            attempt_service_account_name: "accordlock-attempt",
            attempt_service_account_uid: "33333333-3333-4333-8333-333333333333",
            token_audience: "urn:accordlock:kubernetes-api:control-rotated",
        })
        .unwrap();
        let management = EksBrokerManagementBindings::new(
            EksManagementAuthorityBinding::new(
                "spiffe://accordlock.test/control/secret-rotated".to_owned(),
                [0xb1; 32],
            )
            .unwrap(),
            EksManagementAuthorityBinding::new(
                "spiffe://accordlock.test/control/token-rotated".to_owned(),
                [0xb2; 32],
            )
            .unwrap(),
            EksManagementAuthorityBinding::new(
                "spiffe://accordlock.test/control/review-rotated".to_owned(),
                [0xb3; 32],
            )
            .unwrap(),
        )
        .unwrap();
        let destination = EksDestinationProfile::new(
            route,
            [0xb4; 32],
            [0xb5; 32],
            EksCredentialLifecyclePolicy::new(600, 900, 5, 60).unwrap(),
            management,
        )
        .unwrap();
        let mut capability = fixture.grant.grant.clone();
        capability.grant_id = Uuid::new_v4();
        capability.cluster_identity.clone_from(&cluster_identity);
        capability.deployment_uid.clone_from(&deployment_uid);
        let mut next_authority = fixture.authority.clone();
        next_authority.resource.epoch += 1;
        next_authority.resource.activation_id = Uuid::new_v4();
        next_authority.resource.root = destination.resource_root(&scope).unwrap();
        next_authority.mediation.epoch += 1;
        next_authority.mediation.activation_id = Uuid::new_v4();
        next_authority.mediation.root = destination
            .mediation_root(&scope, &next_authority.resource)
            .unwrap();
        next_authority.grant_registry.epoch += 1;
        next_authority.grant_registry.activation_id = Uuid::new_v4();
        next_authority.grant_registry.root = canonical_hash(&capability).unwrap();
        fixture
            .store
            .compare_and_activate_authority(&scope, Some(&fixture.authority), &next_authority)
            .unwrap();
        fixture
            .store
            .activate_eks_destination(&scope, &destination)
            .unwrap();
        let registration = GrantRegistration {
            environment: "prod".to_owned(),
            grant: capability,
            authority: next_authority.clone(),
            dispatch_deadline_policy: fixture.grant.dispatch_deadline_policy.clone(),
        };
        // The public conformance adapter intentionally authorizations only one grant
        // registration per scope. This test-only rotation archives the fully
        // consumed A1 grant so the scanner can exercise an independently valid
        // A2 physical tail in that same scope; A1 remains represented by its
        // immutable authorization, consumption, control and broker histories.
        fixture
            .store
            .inner
            .lock()
            .grants
            .remove(&(scope.clone(), fixture.grant.grant.grant_id));
        fixture.store.register_grant(&registration).unwrap();
        fixture
            .proposal_template
            .cluster_identity
            .clone_from(&cluster_identity);
        fixture
            .proposal_template
            .deployment_uid
            .clone_from(&deployment_uid);
        fixture.authority = next_authority;
        fixture.grant = registration;
    }

    fn claim_evaluation(fixture: &ControlFixture, claim_id: u128) -> ControlEvaluationWork {
        let request = ControlWorkClaimRequest::new(
            "worker-evaluator",
            ControlWorkerRole::Evaluator,
            Uuid::from_u128(claim_id),
        )
        .unwrap();
        match fixture
            .store
            .claim_next_control_work_or_recover(&request)
            .unwrap()
        {
            ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Evaluate(work)) => work,
            other => panic!("expected EVALUATE work, got {other:?}"),
        }
    }

    fn assert_control_dual_high_water(fixture: &ControlFixture, expected: i64) {
        let scope = Scope::new("acme", "prod").unwrap();
        let replay_scope = IngressReplayScope::new(CONTROL_AUDIENCE).unwrap();
        let state = fixture.store.inner.lock();
        assert_eq!(state.high_water.get(&scope), Some(&expected));
        assert_eq!(
            state.ingress_replay_high_water.get(&replay_scope),
            Some(&expected)
        );
    }

    fn signed_control_evaluation(
        work: &ControlEvaluationWork,
        evaluator: &SigningIdentity,
        outcome: DecisionOutcome,
    ) -> SignedEvaluation {
        let reasons = if outcome == DecisionOutcome::Allow {
            vec![ReasonCode::Allowed]
        } else {
            vec![ReasonCode::ActorNotAllowed]
        };
        let attestation = EvaluationAttestation {
            schema_version: EVALUATION_ATTESTATION_SCHEMA_VERSION,
            request_id: work.proposal().request_id,
            evaluation_nonce: work.evaluation_nonce(),
            tenant: work.caller_tenant().to_owned(),
            actor: work.caller_actor().to_owned(),
            evaluated_at: work.lease().claimed_at(),
            outcome,
            reasons,
            template_hash: canonical_hash(&work.proposal().template).unwrap(),
            evidence_root: Digest32::sha256(b"control-evidence"),
            principals: vec!["principal-a".to_owned()],
            policy_root: work.active_authority().policy.root,
            authority: work.active_authority().clone(),
            consume_before: work.ingress_expires_at() - 10,
        };
        let cose_sign1 = sign_cose(
            &attestation.canonical_bytes().unwrap(),
            EVALUATION_DOMAIN,
            evaluator,
        )
        .unwrap();
        SignedEvaluation {
            attestation,
            cose_sign1,
        }
    }

    fn authorize(fixture: &ControlFixture, claim_id: u128) -> ControlDecisionReceipt {
        let work = claim_evaluation(fixture, claim_id);
        let signed = signed_control_evaluation(&work, &fixture.evaluator, DecisionOutcome::Allow);
        fixture.clock.set(CONTROL_NOW + 1);
        fixture
            .store
            .record_control_evaluation(work, &signed, &fixture.evaluator.verifier())
            .unwrap()
    }

    fn claim_issuance(fixture: &ControlFixture, claim_id: u128) -> ControlIssuanceWork {
        fixture.clock.set(CONTROL_NOW + 2);
        let request = ControlWorkClaimRequest::new(
            "worker-issuer",
            ControlWorkerRole::Issuer,
            Uuid::from_u128(claim_id),
        )
        .unwrap();
        match fixture
            .store
            .claim_next_control_work_or_recover(&request)
            .unwrap()
        {
            ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Issue(work)) => work,
            other => panic!("expected ISSUE work, got {other:?}"),
        }
    }

    fn issued_for_control_work(
        work: &ControlIssuanceWork,
        snapshot: &IssuanceSnapshot,
        signer: &SigningIdentity,
        seed: u128,
    ) -> IssuedAuthorizationRecord {
        let evaluation = &work.signed_evaluation().attestation;
        let registration = snapshot.registration();
        let authorization = ExecutionAuthorization {
            schema_version: EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
            authorization_id: Uuid::from_u128(seed),
            evaluation_nonce: evaluation.evaluation_nonce,
            request_id: evaluation.request_id,
            tenant: work.proposal().tenant.clone(),
            holder: work.proposal().actor.clone(),
            audience: work.proposal().template.audience.clone(),
            issued_at: snapshot.issued_at(),
            not_before: snapshot.issued_at(),
            consume_before: evaluation.consume_before.min(registration.grant.expires_at),
            dispatch_deadline_policy: registration.dispatch_deadline_policy.clone(),
            grant_id: work.selected_grant_id(),
            template: work.proposal().template.clone(),
            template_hash: evaluation.template_hash,
            evidence_root: evaluation.evidence_root,
            principals: evaluation.principals.clone(),
            policy_root: evaluation.policy_root,
            authority: evaluation.authority.clone(),
        };
        let cose_sign1 = sign_cose(
            &authorization.canonical_bytes().unwrap(),
            EXECUTION_AUTHORIZATION_DOMAIN,
            signer,
        )
        .unwrap();
        IssuedAuthorizationRecord::new(
            Uuid::from_u128(seed + 1),
            SignedAuthorization {
                authorization,
                cose_sign1,
            },
            signer.key_id().to_owned(),
            signer.public_key_bytes(),
        )
        .unwrap()
    }

    fn issue(fixture: &ControlFixture, claim_id: u128, seed: u128) -> ConsumeKey {
        let work = claim_issuance(fixture, claim_id);
        let snapshot = fixture.store.control_issuance_snapshot(&work).unwrap();
        let issued = issued_for_control_work(&work, &snapshot, &fixture.authorization_signer, seed);
        fixture.clock.set(CONTROL_NOW + 3);
        assert_eq!(
            fixture
                .store
                .record_and_link_control_issuance_or_recover(work, &issued)
                .unwrap(),
            ControlIssuanceCommitOutcome::Committed
        );
        ConsumeKey {
            scope: issued.scope(),
            transaction_id: issued.transaction_id,
            authorization_id: issued.authorization().authorization_id,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn complete_control_dispatch_at(
        fixture: &ControlFixture,
        base: i64,
        request_id: u128,
        nonce: u128,
        evaluation_claim_id: u128,
        issuance_claim_id: u128,
        authorization_seed: u128,
        consumption_claim_id: u128,
    ) -> (ControlSubmissionReceipt, ConsumeKey) {
        complete_control_dispatch_at_with_ingress_expiry(
            fixture,
            base,
            request_id,
            nonce,
            evaluation_claim_id,
            issuance_claim_id,
            authorization_seed,
            consumption_claim_id,
            160,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn complete_control_dispatch_at_with_ingress_expiry(
        fixture: &ControlFixture,
        base: i64,
        request_id: u128,
        nonce: u128,
        evaluation_claim_id: u128,
        issuance_claim_id: u128,
        authorization_seed: u128,
        consumption_claim_id: u128,
        ingress_expires_at: i64,
    ) -> (ControlSubmissionReceipt, ConsumeKey) {
        fixture.clock.set(base);
        let receipt = fixture.accept_with_expiry(request_id, nonce, ingress_expires_at);
        let evaluation_work = claim_evaluation(fixture, evaluation_claim_id);
        let signed =
            signed_control_evaluation(&evaluation_work, &fixture.evaluator, DecisionOutcome::Allow);
        fixture.clock.set(base + 1);
        fixture
            .store
            .record_control_evaluation(evaluation_work, &signed, &fixture.evaluator.verifier())
            .unwrap();

        fixture.clock.set(base + 2);
        let issuance_request = ControlWorkClaimRequest::new(
            "worker-issuer",
            ControlWorkerRole::Issuer,
            Uuid::from_u128(issuance_claim_id),
        )
        .unwrap();
        let issuance_work = match fixture
            .store
            .claim_next_control_work_or_recover(&issuance_request)
            .unwrap()
        {
            ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Issue(work)) => work,
            other => panic!("expected ISSUE work, got {other:?}"),
        };
        let issuance_snapshot = fixture
            .store
            .control_issuance_snapshot(&issuance_work)
            .unwrap();
        let issued = issued_for_control_work(
            &issuance_work,
            &issuance_snapshot,
            &fixture.authorization_signer,
            authorization_seed,
        );
        fixture.clock.set(base + 3);
        assert_eq!(
            fixture
                .store
                .record_and_link_control_issuance_or_recover(issuance_work, &issued)
                .unwrap(),
            ControlIssuanceCommitOutcome::Committed
        );

        fixture.clock.set(base + 4);
        let consumption_request = ControlWorkClaimRequest::new(
            "worker-consumer",
            ControlWorkerRole::Consumer,
            Uuid::from_u128(consumption_claim_id),
        )
        .unwrap();
        let consumption_work = match fixture
            .store
            .claim_next_control_work_or_recover(&consumption_request)
            .unwrap()
        {
            ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Consume(work)) => work,
            other => panic!("expected CONSUME work, got {other:?}"),
        };
        let key = consumption_work.consume_key().clone();
        fixture.clock.set(base + 5);
        assert!(matches!(
            fixture
                .store
                .consume_and_link_control_or_recover(consumption_work)
                .unwrap(),
            ControlConsumptionCommitOutcome::Committed(_)
        ));
        (receipt, key)
    }

    fn duplicate_control_lease(lease: &ControlWorkLease) -> ControlWorkLease {
        ControlWorkLease {
            state_instance_id: lease.state_instance_id,
            submission_id: lease.submission_id,
            phase: lease.phase,
            worker_id: lease.worker_id.clone(),
            claim_id: lease.claim_id,
            fence: lease.fence,
            claimed_at: lease.claimed_at,
            lease_until: lease.lease_until,
        }
    }

    fn duplicate_evaluation_work(work: &ControlEvaluationWork) -> ControlEvaluationWork {
        ControlEvaluationWork {
            lease: duplicate_control_lease(&work.lease),
            scope: work.scope.clone(),
            proposal: work.proposal.clone(),
            caller_tenant: work.caller_tenant.clone(),
            caller_actor: work.caller_actor.clone(),
            accepted_at: work.accepted_at,
            ingress_expires_at: work.ingress_expires_at,
            ingress_authority_domain: work.ingress_authority_domain.clone(),
            active_authority: work.active_authority.clone(),
            evaluation_nonce: work.evaluation_nonce,
        }
    }

    fn duplicate_issuance_work(work: &ControlIssuanceWork) -> ControlIssuanceWork {
        ControlIssuanceWork {
            lease: duplicate_control_lease(&work.lease),
            scope: work.scope.clone(),
            proposal: work.proposal.clone(),
            signed_evaluation: work.signed_evaluation.clone(),
            selected_grant_id: work.selected_grant_id,
            decision_id: work.decision_id,
        }
    }

    fn duplicate_consumption_work(work: &ControlConsumptionWork) -> ControlConsumptionWork {
        ControlConsumptionWork {
            lease: duplicate_control_lease(&work.lease),
            consume_key: work.consume_key.clone(),
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn v14_memory_acquisition_exact_recovery_takeover_and_expiry_are_durable() {
        let fixture = ControlFixture::with_dispatch_policy(
            true,
            DispatchDeadlinePolicy {
                max_dispatch_delay_seconds: 100,
                profile_hard_cap: 500,
                immutable_dependency_expiries: vec![400],
            },
        );
        let (submission, key) = complete_control_dispatch_at(
            &fixture, 100, 0x1400, 0x1401, 0x1402, 0x1403, 0x1404, 0x1406,
        );
        fixture.clock.set(106);
        let first_request =
            DispatchAcquisitionRequest::new("memory-v14-a", Uuid::from_u128(0x1410)).unwrap();
        let (first_id, stable_claim, first_fence, first_lease_until) = match fixture
            .store
            .claim_next_pending_dispatch_or_recover(submission.scope(), &first_request)
            .unwrap()
        {
            DispatchAcquisitionOutcome::Acquired(work) => (
                work.authority().acquisition_id(),
                work.authority().claim().claim_id(),
                work.authority().lease_fence(),
                work.authority().lease_until(),
            ),
            other => panic!("expected first memory acquisition, got {other:?}"),
        };
        assert_eq!(first_id, first_request.acquisition_id());
        assert_eq!(first_lease_until, 136);

        fixture.clock.set(107);
        match fixture
            .store
            .claim_next_pending_dispatch_or_recover(submission.scope(), &first_request)
            .unwrap()
        {
            DispatchAcquisitionOutcome::Recovered(work) => {
                assert_eq!(work.authority().acquisition_id(), first_id);
                assert_eq!(work.authority().lease_fence(), first_fence);
                assert_eq!(work.authority().claim().claim_id(), stable_claim);
            }
            other => panic!("expected exact memory recovery, got {other:?}"),
        }

        fixture.clock.set(105);
        assert!(matches!(
            fixture
                .store
                .claim_next_pending_dispatch_or_recover(submission.scope(), &first_request),
            Err(StateError::ClockRollback {
                observed: 105,
                high_water: 107
            })
        ));

        fixture.clock.set(136);
        let second_request =
            DispatchAcquisitionRequest::new("memory-v14-b", Uuid::from_u128(0x1411)).unwrap();
        let (second_id, second_fence, second_lease_until) = match fixture
            .store
            .claim_next_pending_dispatch_or_recover(submission.scope(), &second_request)
            .unwrap()
        {
            DispatchAcquisitionOutcome::Acquired(work) => {
                assert_eq!(work.authority().claim().claim_id(), stable_claim);
                (
                    work.authority().acquisition_id(),
                    work.authority().lease_fence(),
                    work.authority().lease_until(),
                )
            }
            other => panic!("expected memory takeover, got {other:?}"),
        };
        assert!(second_fence > first_fence);
        assert_eq!(second_lease_until, 150);
        match fixture
            .store
            .claim_next_pending_dispatch_or_recover(submission.scope(), &first_request)
            .unwrap()
        {
            DispatchAcquisitionOutcome::Inert(receipt) => {
                assert_eq!(receipt.acquisition_id(), first_id);
                assert_eq!(
                    receipt.disposition(),
                    DispatchAcquisitionDisposition::Superseded
                );
            }
            other => panic!("expected superseded memory history, got {other:?}"),
        }

        fixture.clock.set(second_lease_until);
        let expired = match fixture
            .store
            .claim_next_pending_dispatch_or_recover(submission.scope(), &second_request)
            .unwrap()
        {
            DispatchAcquisitionOutcome::Inert(receipt) => {
                assert_eq!(receipt.acquisition_id(), second_id);
                assert_eq!(
                    receipt.disposition(),
                    DispatchAcquisitionDisposition::Expired
                );
                receipt
            }
            other => panic!("expected expired memory acquisition, got {other:?}"),
        };
        fixture.clock.set(second_lease_until - 1);
        match fixture
            .store
            .claim_next_pending_dispatch_or_recover(submission.scope(), &second_request)
            .unwrap()
        {
            DispatchAcquisitionOutcome::Inert(recovered) => assert_eq!(recovered, expired),
            other => panic!("durable HWM should prove inert expiry, got {other:?}"),
        }
        let rollback_takeover =
            DispatchAcquisitionRequest::new("memory-v14-c", Uuid::from_u128(0x1412)).unwrap();
        assert!(matches!(
            fixture
                .store
                .claim_next_pending_dispatch_or_recover(submission.scope(), &rollback_takeover),
            Err(StateError::ClockRollback {
                observed,
                high_water
            }) if observed == second_lease_until - 1 && high_water == second_lease_until
        ));
        assert_eq!(
            fixture.store.time_high_water(&key.scope).unwrap(),
            Some(second_lease_until)
        );
    }

    #[test]
    fn v14_memory_disposes_expired_fifo_head_then_acquires_next_work() {
        let fixture = ControlFixture::new(true);
        let (first, first_key) = complete_control_dispatch_at(
            &fixture, 100, 0x1420, 0x1421, 0x1422, 0x1423, 0x1424, 0x1426,
        );
        let (_, second_key) = complete_control_dispatch_at(
            &fixture, 106, 0x1430, 0x1431, 0x1432, 0x1433, 0x1434, 0x1436,
        );
        fixture.clock.set(135);
        let disposition_request =
            DispatchAcquisitionRequest::new("memory-v14-dispose", Uuid::from_u128(0x1440)).unwrap();
        match fixture
            .store
            .claim_next_pending_dispatch_or_recover(first.scope(), &disposition_request)
            .unwrap()
        {
            DispatchAcquisitionOutcome::Disposed(receipt) => {
                assert_eq!(receipt.key(), &first_key);
                assert_eq!(
                    receipt.reason(),
                    DispatchQueueDispositionReason::DispatchDeadlineExpired
                );
                assert_eq!(receipt.observed_at(), 135);
            }
            other => panic!("expected expired memory FIFO head, got {other:?}"),
        }
        assert_control_dual_high_water(&fixture, 135);

        fixture.clock.set(134);
        let rollback_request =
            DispatchAcquisitionRequest::new("memory-v14-rollback", Uuid::from_u128(0x1441))
                .unwrap();
        assert!(matches!(
            fixture
                .store
                .claim_next_pending_dispatch_or_recover(first.scope(), &rollback_request),
            Err(StateError::ClockRollback {
                observed: 134,
                high_water: 135
            })
        ));
        fixture.clock.set(135);
        let acquisition_request =
            DispatchAcquisitionRequest::new("memory-v14-next", Uuid::from_u128(0x1442)).unwrap();
        match fixture
            .store
            .claim_next_pending_dispatch_or_recover(first.scope(), &acquisition_request)
            .unwrap()
        {
            DispatchAcquisitionOutcome::Acquired(work) => {
                assert_eq!(work.authority().claim().key(), &second_key);
            }
            other => panic!("expected next memory FIFO work, got {other:?}"),
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn v14_memory_discovers_and_retires_create_absent_no_send_then_releases_physical() {
        let fixture = ControlFixture::with_dispatch_policy(
            true,
            DispatchDeadlinePolicy {
                max_dispatch_delay_seconds: 100,
                profile_hard_cap: 500,
                immutable_dependency_expiries: vec![400],
            },
        );
        let broker_capability = broker_capability(&fixture.store);
        let (first_submission, first_key) = complete_control_dispatch_at(
            &fixture, 100, 0x1470, 0x1471, 0x1472, 0x1473, 0x1474, 0x1476,
        );
        let (_, second_key) = complete_control_dispatch_at(
            &fixture, 106, 0x1480, 0x1481, 0x1482, 0x1483, 0x1484, 0x1486,
        );

        fixture.clock.set(112);
        let original_request =
            DispatchAcquisitionRequest::new("memory-v14-lost", Uuid::from_u128(0x1490)).unwrap();
        let authority = match fixture
            .store
            .claim_next_pending_dispatch_or_recover(first_submission.scope(), &original_request)
            .unwrap()
        {
            DispatchAcquisitionOutcome::Acquired(work) => work.into_parts().1,
            other => panic!("expected acquired create work, got {other:?}"),
        };
        assert_eq!(authority.claim().key(), &first_key);
        let current = fixture
            .store
            .load_current_eks_attempt_for_acquisition(&authority)
            .unwrap();
        let route_commitment = *current.facts().route().commitment().as_bytes();
        let create_io = fixture
            .store
            .begin_broker_operation_for_acquisition(
                &broker_capability,
                &authority,
                AcquiredBrokerOperationRequest::create(&authority, route_commitment).unwrap(),
            )
            .unwrap();
        fixture.store.mark_broker_io_unknown(create_io).unwrap();
        drop(authority);

        fixture.clock.set(113);
        let supervisor_request =
            DispatchAcquisitionRequest::new("memory-v14-supervisor", Uuid::from_u128(0x1491))
                .unwrap();
        let recovery_work = match fixture
            .store
            .claim_next_pending_dispatch_or_recover(first_submission.scope(), &supervisor_request)
            .unwrap()
        {
            DispatchAcquisitionOutcome::RecoveryRequired(work) => {
                assert_eq!(
                    work.disposition(),
                    DispatchAcquisitionDisposition::BrokerArtifactPresent
                );
                work
            }
            other => panic!("expected server-discovered recovery, got {other:?}"),
        };
        let recovery_key = recovery_work.recovery_key();
        let no_send = fixture
            .store
            .close_dispatch_acquisition_no_send(recovery_key)
            .unwrap();
        assert_eq!(no_send.key(), &first_key);
        let restart = fixture
            .store
            .dispatch_broker_restart_context(recovery_key)
            .unwrap();
        assert_eq!(
            restart.action(),
            DispatchBrokerRestartAction::ReconcileCreate
        );
        let reconciliation = fixture
            .store
            .begin_broker_reconciliation(
                &broker_capability,
                &restart.reconciliation_request().unwrap(),
            )
            .unwrap();
        fixture
            .store
            .commit_broker_reconciliation(
                reconciliation,
                BrokerSecretObservation::absent([0xc1; 32]).unwrap(),
            )
            .unwrap();
        let absent = fixture
            .store
            .dispatch_broker_restart_context(recovery_key)
            .unwrap();
        assert_eq!(
            absent.action(),
            DispatchBrokerRestartAction::CreationAlreadyAbsent
        );
        assert!(matches!(
            fixture.store.retire_recovery_no_send(recovery_key).unwrap(),
            RecoveryNoSendRetirementOutcome::Retired(_)
        ));

        fixture.clock.set(114);
        let tail_request =
            DispatchAcquisitionRequest::new("memory-v14-tail", Uuid::from_u128(0x1492)).unwrap();
        match fixture
            .store
            .claim_next_pending_dispatch_or_recover(first_submission.scope(), &tail_request)
            .unwrap()
        {
            DispatchAcquisitionOutcome::Acquired(work) => {
                assert_eq!(work.authority().claim().key(), &second_key);
            }
            other => panic!("retired no-send head should release its physical tail: {other:?}"),
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn v14_memory_no_send_persists_safe_bound_then_releases_same_physical_at_due_time() {
        let fixture = ControlFixture::with_policies(
            true,
            DispatchDeadlinePolicy {
                max_dispatch_delay_seconds: 120,
                profile_hard_cap: 500,
                immutable_dependency_expiries: vec![400],
            },
            EksCredentialLifecyclePolicy::new(600, 900, 5, 60).unwrap(),
        );
        let broker_capability = broker_capability(&fixture.store);
        let (first_submission, first_key) = complete_control_dispatch_at_with_ingress_expiry(
            &fixture, 100, 0x14a0, 0x14a1, 0x14a2, 0x14a3, 0x14a4, 0x14a6, 219,
        );
        let (_, second_key) = complete_control_dispatch_at_with_ingress_expiry(
            &fixture, 106, 0x14b0, 0x14b1, 0x14b2, 0x14b3, 0x14b4, 0x14b6, 219,
        );

        fixture.clock.set(112);
        let original_request =
            DispatchAcquisitionRequest::new("memory-v14-pending", Uuid::from_u128(0x14c0)).unwrap();
        let authority = match fixture
            .store
            .claim_next_pending_dispatch_or_recover(first_submission.scope(), &original_request)
            .unwrap()
        {
            DispatchAcquisitionOutcome::Acquired(work) => work.into_parts().1,
            other => panic!("expected acquired pending work, got {other:?}"),
        };
        assert_eq!(authority.claim().key(), &first_key);
        let current = fixture
            .store
            .load_current_eks_attempt_for_acquisition(&authority)
            .unwrap();
        let route_commitment = *current.facts().route().commitment().as_bytes();
        let create = fixture
            .store
            .begin_broker_operation_for_acquisition(
                &broker_capability,
                &authority,
                AcquiredBrokerOperationRequest::create(&authority, route_commitment).unwrap(),
            )
            .unwrap();
        fixture
            .store
            .commit_broker_create(
                create,
                BrokerSecretObservation::matching("secret-uid-pending".to_owned(), [0xd1; 32])
                    .unwrap(),
            )
            .unwrap();
        drop(authority);

        let recovery_key = original_request.recovery_key(first_submission.scope());
        fixture
            .store
            .close_dispatch_acquisition_no_send(&recovery_key)
            .unwrap();
        let cleanup_context = fixture
            .store
            .dispatch_broker_restart_context(&recovery_key)
            .unwrap();
        assert_eq!(
            cleanup_context.action(),
            DispatchBrokerRestartAction::CleanupSecret
        );
        let cleanup = fixture
            .store
            .prepare_broker_cleanup(
                &broker_capability,
                &cleanup_context.cleanup_request().unwrap(),
            )
            .unwrap();
        let cleanup_io = fixture
            .store
            .begin_broker_io(&broker_capability, cleanup)
            .unwrap();
        fixture.store.mark_broker_io_unknown(cleanup_io).unwrap();
        let reconciliation_context = fixture
            .store
            .dispatch_broker_restart_context(&recovery_key)
            .unwrap();
        assert_eq!(
            reconciliation_context.action(),
            DispatchBrokerRestartAction::CleanupSecret
        );
        let reconciliation = fixture
            .store
            .begin_broker_reconciliation(
                &broker_capability,
                &BrokerReconciliationRequest::new(
                    first_key.clone(),
                    BrokerJournalOperation::DeleteSecret,
                    route_commitment,
                )
                .unwrap(),
            )
            .unwrap();
        fixture
            .store
            .commit_broker_reconciliation(
                reconciliation,
                BrokerSecretObservation::absent([0xd2; 32]).unwrap(),
            )
            .unwrap();

        let safe_after = 112 + 60 + 5;
        assert!(matches!(
            fixture.store.retire_recovery_no_send(&recovery_key).unwrap(),
            RecoveryNoSendRetirementOutcome::Pending { safe_after: stored }
                if stored == safe_after
        ));
        assert!(matches!(
            fixture.store.retire_recovery_no_send(&recovery_key).unwrap(),
            RecoveryNoSendRetirementOutcome::Pending { safe_after: stored }
                if stored == safe_after
        ));

        fixture.clock.set(safe_after - 1);
        let blocked_tail =
            DispatchAcquisitionRequest::new("memory-v14-blocked", Uuid::from_u128(0x14c1)).unwrap();
        assert!(matches!(
            fixture
                .store
                .claim_next_pending_dispatch_or_recover(first_submission.scope(), &blocked_tail)
                .unwrap(),
            DispatchAcquisitionOutcome::NoWork
        ));

        fixture.clock.set(safe_after);
        let retirement_request =
            DispatchAcquisitionRequest::new("memory-v14-retire", Uuid::from_u128(0x14c2)).unwrap();
        match fixture
            .store
            .claim_next_pending_dispatch_or_recover(first_submission.scope(), &retirement_request)
            .unwrap()
        {
            DispatchAcquisitionOutcome::RecoveryRequired(work) => {
                assert_eq!(work.recovery_key(), &recovery_key);
                assert_eq!(
                    work.disposition(),
                    DispatchAcquisitionDisposition::RecoveryNoSend
                );
            }
            other => panic!("due no-send retirement was not rediscovered: {other:?}"),
        }
        assert!(matches!(
            fixture
                .store
                .retire_recovery_no_send(&recovery_key)
                .unwrap(),
            RecoveryNoSendRetirementOutcome::Retired(_)
        ));
        assert!(matches!(
            fixture
                .store
                .retire_recovery_no_send(&recovery_key)
                .unwrap(),
            RecoveryNoSendRetirementOutcome::Recovered(_)
        ));

        let tail_request =
            DispatchAcquisitionRequest::new("memory-v14-unblocked", Uuid::from_u128(0x14c3))
                .unwrap();
        match fixture
            .store
            .claim_next_pending_dispatch_or_recover(first_submission.scope(), &tail_request)
            .unwrap()
        {
            DispatchAcquisitionOutcome::Acquired(work) => {
                assert_eq!(work.authority().claim().key(), &second_key);
            }
            other => panic!("retired safe-bound head should release its physical tail: {other:?}"),
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn v14_memory_skips_terminal_delete_conflict_and_acquires_distinct_physical_tail() {
        let mut fixture = ControlFixture::with_dispatch_policy(
            true,
            DispatchDeadlinePolicy {
                max_dispatch_delay_seconds: 120,
                profile_hard_cap: 500,
                immutable_dependency_expiries: vec![400],
            },
        );
        let broker_capability = broker_capability(&fixture.store);
        let (first_submission, first_key) = complete_control_dispatch_at_with_ingress_expiry(
            &fixture, 100, 0x14d0, 0x14d1, 0x14d2, 0x14d3, 0x14d4, 0x14d6, 219,
        );
        fixture.clock.set(112);
        let first_request =
            DispatchAcquisitionRequest::new("memory-v14-conflict", Uuid::from_u128(0x14e0))
                .unwrap();
        let authority = match fixture
            .store
            .claim_next_pending_dispatch_or_recover(first_submission.scope(), &first_request)
            .unwrap()
        {
            DispatchAcquisitionOutcome::Acquired(work) => work.into_parts().1,
            other => panic!("expected acquired conflict head, got {other:?}"),
        };
        let current = fixture
            .store
            .load_current_eks_attempt_for_acquisition(&authority)
            .unwrap();
        let route_commitment = *current.facts().route().commitment().as_bytes();
        let create = fixture
            .store
            .begin_broker_operation_for_acquisition(
                &broker_capability,
                &authority,
                AcquiredBrokerOperationRequest::create(&authority, route_commitment).unwrap(),
            )
            .unwrap();
        fixture
            .store
            .commit_broker_create(
                create,
                BrokerSecretObservation::matching("secret-uid-conflict".to_owned(), [0xe1; 32])
                    .unwrap(),
            )
            .unwrap();
        drop(authority);
        let recovery_key = first_request.recovery_key(first_submission.scope());
        fixture
            .store
            .close_dispatch_acquisition_no_send(&recovery_key)
            .unwrap();
        let cleanup_context = fixture
            .store
            .dispatch_broker_restart_context(&recovery_key)
            .unwrap();
        let cleanup = fixture
            .store
            .prepare_broker_cleanup(
                &broker_capability,
                &cleanup_context.cleanup_request().unwrap(),
            )
            .unwrap();
        let cleanup_io = fixture
            .store
            .begin_broker_io(&broker_capability, cleanup)
            .unwrap();
        fixture.store.mark_broker_io_unknown(cleanup_io).unwrap();
        let reconciliation = fixture
            .store
            .begin_broker_reconciliation(
                &broker_capability,
                &BrokerReconciliationRequest::new(
                    first_key.clone(),
                    BrokerJournalOperation::DeleteSecret,
                    route_commitment,
                )
                .unwrap(),
            )
            .unwrap();
        fixture
            .store
            .commit_broker_reconciliation(
                reconciliation,
                BrokerSecretObservation::conflicting([0xe2; 32]).unwrap(),
            )
            .unwrap();

        rotate_control_fixture_to_distinct_physical(&mut fixture, "tail");
        let (_, tail_key) = complete_control_dispatch_at_with_ingress_expiry(
            &fixture, 114, 0x14f0, 0x14f1, 0x14f2, 0x14f3, 0x14f4, 0x14f6, 219,
        );
        fixture.clock.set(120);
        let tail_request =
            DispatchAcquisitionRequest::new("memory-v14-conflict-tail", Uuid::from_u128(0x1500))
                .unwrap();
        match fixture
            .store
            .claim_next_pending_dispatch_or_recover(first_submission.scope(), &tail_request)
            .unwrap()
        {
            DispatchAcquisitionOutcome::Acquired(work) => {
                assert_eq!(work.authority().claim().key(), &tail_key);
                assert_ne!(
                    work.authority().claim().physical_resource(),
                    &PhysicalResourceKey::new(
                        "eks://cluster-a".to_owned(),
                        "payments".to_owned(),
                        "11111111-1111-4111-8111-111111111111".to_owned()
                    )
                    .unwrap()
                );
            }
            other => panic!("terminal DELETE conflict starved distinct tail: {other:?}"),
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn v14_memory_global_fifo_precedes_newer_recovery_with_older_productive_head() {
        let mut fixture = ControlFixture::with_dispatch_policy(
            true,
            DispatchDeadlinePolicy {
                max_dispatch_delay_seconds: 100,
                profile_hard_cap: 500,
                immutable_dependency_expiries: vec![400],
            },
        );
        let broker_capability = broker_capability(&fixture.store);
        let scope = Scope::new("acme", "prod").unwrap();
        let first_grant_key = (scope.clone(), fixture.grant.grant.grant_id);
        let (first_submission, first_key) = complete_control_dispatch_at_with_ingress_expiry(
            &fixture, 100, 0x1510, 0x1511, 0x1512, 0x1513, 0x1514, 0x1516, 219,
        );
        let first_grant = fixture
            .store
            .inner
            .lock()
            .grants
            .get(&first_grant_key)
            .unwrap()
            .clone();
        fixture.clock.set(112);
        let first_request =
            DispatchAcquisitionRequest::new("memory-v14-fifo-a", Uuid::from_u128(0x1520)).unwrap();
        match fixture
            .store
            .claim_next_pending_dispatch_or_recover(first_submission.scope(), &first_request)
            .unwrap()
        {
            DispatchAcquisitionOutcome::Acquired(work) => {
                assert_eq!(work.authority().claim().key(), &first_key);
            }
            other => panic!("expected older acquired FIFO head, got {other:?}"),
        }

        rotate_control_fixture_to_distinct_physical(&mut fixture, "fifo-recovery");
        // The conformance adapter authorizations one current grant per scope, while
        // this scheduler regression needs both immutable historical A facts
        // and current B facts to remain independently valid.  Reinsert the
        // archived A snapshot directly into the in-memory audit map; only B
        // matches the active authority and can be selected for new issuance.
        fixture
            .store
            .inner
            .lock()
            .grants
            .insert(first_grant_key, first_grant);
        let (second_submission, second_key) = complete_control_dispatch_at_with_ingress_expiry(
            &fixture, 114, 0x1530, 0x1531, 0x1532, 0x1533, 0x1534, 0x1536, 219,
        );
        fixture.clock.set(120);
        let second_request =
            DispatchAcquisitionRequest::new("memory-v14-fifo-b", Uuid::from_u128(0x1540)).unwrap();
        let second_authority = match fixture
            .store
            .claim_next_pending_dispatch_or_recover(second_submission.scope(), &second_request)
            .unwrap()
        {
            DispatchAcquisitionOutcome::Acquired(work) => work.into_parts().1,
            other => panic!("expected newer acquired recovery head, got {other:?}"),
        };
        assert_eq!(second_authority.claim().key(), &second_key);
        let second_attempt = fixture
            .store
            .load_current_eks_attempt_for_acquisition(&second_authority)
            .unwrap();
        let route_commitment = *second_attempt.facts().route().commitment().as_bytes();
        let _broker_io = fixture
            .store
            .begin_broker_operation_for_acquisition(
                &broker_capability,
                &second_authority,
                AcquiredBrokerOperationRequest::create(&second_authority, route_commitment)
                    .unwrap(),
            )
            .unwrap();
        drop(second_authority);

        // A is now an expired productive/disposition head; B is a newer
        // server-selected recovery.  Global FIFO must process A first.
        fixture.clock.set(143);
        let supervisor =
            DispatchAcquisitionRequest::new("memory-v14-fifo-supervisor", Uuid::from_u128(0x1550))
                .unwrap();
        let recovery_supervisor =
            DispatchAcquisitionRequest::new("memory-v14-fifo-recovery", Uuid::from_u128(0x1551))
                .unwrap();
        match fixture
            .store
            .claim_next_pending_dispatch_or_recover(first_submission.scope(), &supervisor)
            .unwrap()
        {
            DispatchAcquisitionOutcome::Disposed(receipt) => {
                assert_eq!(receipt.key(), &first_key);
                assert_eq!(
                    receipt.reason(),
                    DispatchQueueDispositionReason::AuthorityChanged
                );
            }
            other => panic!("newer recovery bypassed older productive FIFO head: {other:?}"),
        }
        match fixture
            .store
            .claim_next_pending_dispatch_or_recover(first_submission.scope(), &recovery_supervisor)
            .unwrap()
        {
            DispatchAcquisitionOutcome::RecoveryRequired(work) => {
                assert_eq!(
                    work.recovery_key().acquisition_id(),
                    second_request.acquisition_id()
                );
                assert_eq!(
                    work.disposition(),
                    DispatchAcquisitionDisposition::BrokerArtifactPresent
                );
            }
            other => panic!("expected newer recovery after older disposition, got {other:?}"),
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn v14_memory_review_proof_binds_broker_lineage_and_attempt_cas() {
        let fixture = ControlFixture::with_dispatch_policy(
            true,
            DispatchDeadlinePolicy {
                max_dispatch_delay_seconds: 100,
                profile_hard_cap: 500,
                immutable_dependency_expiries: vec![400],
            },
        );
        let broker_capability = broker_capability(&fixture.store);
        let (submission, key) = complete_control_dispatch_at(
            &fixture, 100, 0x1450, 0x1451, 0x1452, 0x1453, 0x1454, 0x1456,
        );
        fixture.clock.set(106);
        let acquisition_request =
            DispatchAcquisitionRequest::new("memory-v14-review", Uuid::from_u128(0x1460)).unwrap();
        let first = match fixture
            .store
            .claim_next_pending_dispatch_or_recover(submission.scope(), &acquisition_request)
            .unwrap()
        {
            DispatchAcquisitionOutcome::Acquired(work) => work.into_parts().1,
            other => panic!("expected acquired review work, got {other:?}"),
        };
        fixture.clock.set(107);
        let recovered = match fixture
            .store
            .claim_next_pending_dispatch_or_recover(submission.scope(), &acquisition_request)
            .unwrap()
        {
            DispatchAcquisitionOutcome::Recovered(work) => work.into_parts().1,
            other => panic!("expected exact recovered review work, got {other:?}"),
        };
        assert_eq!(first, recovered);

        let stable_token = first.claim().clone();
        let high_water_before_legacy = fixture.store.time_high_water(&key.scope).unwrap();
        assert!(matches!(
            fixture.store.revalidate_dispatch_claim(&stable_token),
            Err(StateError::DispatchAcquisitionRequired)
        ));
        let forged_legacy = stable_token
            .bind_authenticated_credential(
                [0xb1; 32],
                "service-account-uid".to_owned(),
                format!("AUTHORIZATION_ID={}", Uuid::from_u128(0x1461)),
                105,
                125,
            )
            .unwrap();
        assert!(matches!(
            fixture
                .store
                .mark_attempt_in_flight(&stable_token, forged_legacy),
            Err(StateError::DispatchAcquisitionRequired)
        ));
        assert_eq!(
            fixture.store.time_high_water(&key.scope).unwrap(),
            high_water_before_legacy
        );

        let current = fixture
            .store
            .load_current_eks_attempt_for_acquisition(&first)
            .unwrap();
        let route_commitment = *current.facts().route().commitment().as_bytes();
        let expected_subject = current.facts().token_subject().to_owned();
        let expected_audience = current.facts().token_audience().to_owned();
        let expected_service_account_uid = current.facts().service_account_uid().to_owned();
        let expected_lifecycle = current.facts().credential_lifecycle_policy();
        let expected_activation = current.facts().activation_commitment();

        let create = fixture
            .store
            .begin_broker_operation_for_acquisition(
                &broker_capability,
                &first,
                AcquiredBrokerOperationRequest::create(&first, route_commitment).unwrap(),
            )
            .unwrap();
        let restart_key = acquisition_request.recovery_key(submission.scope());
        let create_uncertain = fixture
            .store
            .dispatch_broker_restart_context(&restart_key)
            .unwrap();
        assert_eq!(create_uncertain.key(), &key);
        assert_eq!(
            create_uncertain.action(),
            DispatchBrokerRestartAction::ReconcileCreate
        );
        assert_eq!(
            create_uncertain
                .reconciliation_request()
                .unwrap()
                .operation(),
            BrokerJournalOperation::CreateSecret
        );
        fixture
            .store
            .commit_broker_create(
                create,
                BrokerSecretObservation::matching("secret-uid-control".to_owned(), [0xb2; 32])
                    .unwrap(),
            )
            .unwrap();
        let create_committed = fixture
            .store
            .dispatch_broker_restart_context(&restart_key)
            .unwrap();
        assert_eq!(
            create_committed.action(),
            DispatchBrokerRestartAction::CleanupSecret
        );
        assert_eq!(create_committed.cleanup_request().unwrap().key(), &key);
        assert!(matches!(
            fixture.store.begin_broker_operation_for_acquisition(
                &broker_capability,
                &recovered,
                AcquiredBrokerOperationRequest::create(&recovered, route_commitment).unwrap(),
            ),
            Err(StateError::BrokerOperationOutcomeUnknown)
        ));

        let credential_policy = BrokerCredentialSafetyPolicy::new(20, 0).unwrap();
        let issue = fixture
            .store
            .begin_broker_operation_for_acquisition(
                &broker_capability,
                &first,
                AcquiredBrokerOperationRequest::issue_token(
                    &first,
                    route_commitment,
                    credential_policy,
                )
                .unwrap(),
            )
            .unwrap();
        let token_receipt = fixture
            .store
            .commit_broker_token_issue(
                issue,
                &BrokerTokenIssueObservation::new([0xb1; 32], 125, [0xb3; 32]).unwrap(),
            )
            .unwrap();
        assert_eq!(
            fixture
                .store
                .dispatch_broker_restart_context(&restart_key)
                .unwrap()
                .action(),
            DispatchBrokerRestartAction::CleanupSecret
        );

        fixture.clock.set(108);
        let review_io = fixture
            .store
            .begin_dispatch_credential_review(
                &broker_capability,
                &recovered,
                &token_receipt.audit().selector(),
            )
            .unwrap();
        assert_eq!(
            fixture
                .store
                .dispatch_broker_restart_context(&restart_key)
                .unwrap()
                .action(),
            DispatchBrokerRestartAction::CleanupSecret
        );
        let recovery_key_before_commit = review_io.recovery_key();
        let credential_authorization_id = Uuid::from_u128(0x1462);
        assert_ne!(credential_authorization_id, key.authorization_id);
        let claims = DispatchCredentialReviewClaims::new(
            [0xb1; 32],
            expected_subject,
            expected_audience,
            expected_service_account_uid,
            format!("AUTHORIZATION_ID={credential_authorization_id}"),
            "secret-uid-control".to_owned(),
            105,
            125,
        )
        .unwrap();
        let reviewed = fixture
            .store
            .record_authenticated_dispatch_credential(
                review_io,
                AuthenticatedDispatchCredentialReview::new(claims, [0xb4; 32]).unwrap(),
            )
            .unwrap();
        let recovered_review_before_restart = fixture
            .store
            .recover_authenticated_dispatch_credential(&recovery_key_before_commit)
            .unwrap();
        assert_eq!(
            reviewed.review_id(),
            recovered_review_before_restart.review_id()
        );
        assert_eq!(
            reviewed.claims().credential_id(),
            format!("AUTHORIZATION_ID={credential_authorization_id}")
        );
        assert_eq!(reviewed.credential_lifecycle_policy(), expected_lifecycle);
        assert_eq!(
            reviewed.destination_activation_commitment(),
            expected_activation
        );
        match fixture
            .store
            .claim_next_pending_dispatch_or_recover(submission.scope(), &acquisition_request)
            .unwrap()
        {
            DispatchAcquisitionOutcome::Quarantined(receipt) => assert_eq!(
                receipt.disposition(),
                DispatchAcquisitionDisposition::BrokerArtifactPresent
            ),
            other => panic!("review artifact must quarantine acquisition recovery, got {other:?}"),
        }

        drop(reviewed);
        drop(recovered_review_before_restart);
        drop(first);
        drop(recovered);
        let audit = fixture
            .store
            .dispatch_credential_review_audit(&acquisition_request.recovery_key(submission.scope()))
            .unwrap();
        let review_recovery_key = audit.recovery_key().unwrap();
        assert_eq!(review_recovery_key.review_id(), audit.review_id());
        let restart_review = fixture
            .store
            .recover_authenticated_dispatch_credential(&review_recovery_key)
            .unwrap();
        let duplicate_restart_review = fixture
            .store
            .recover_authenticated_dispatch_credential(&review_recovery_key)
            .unwrap();
        let attempt = fixture
            .store
            .mark_dispatch_acquisition_attempt_in_flight(restart_review)
            .unwrap();
        assert_eq!(
            attempt.acquisition_id(),
            acquisition_request.acquisition_id()
        );
        assert_eq!(attempt.acquisition_worker_id(), "memory-v14-review");
        assert_eq!(
            attempt.acquisition().credential_review_id(),
            Some(audit.review_id())
        );
        assert_eq!(
            attempt.acquisition().credential_lifecycle_policy(),
            Some(expected_lifecycle)
        );
        assert_eq!(
            attempt.acquisition().destination_activation_commitment(),
            Some(expected_activation)
        );
        assert!(matches!(
            fixture
                .store
                .mark_dispatch_acquisition_attempt_in_flight(duplicate_restart_review),
            Err(StateError::DispatchAttemptOutcomeUnknown | StateError::DispatchAcquisitionMismatch)
        ));

        assert!(
            fixture
                .store
                .recover_authenticated_dispatch_credential(&review_recovery_key)
                .is_ok()
        );
        let after_attempt = fixture
            .store
            .dispatch_broker_restart_context(&restart_key)
            .unwrap();
        assert_eq!(
            after_attempt.action(),
            DispatchBrokerRestartAction::CleanupSecret
        );
        let cleanup_request = after_attempt.cleanup_request().unwrap();
        let cleanup_intent = fixture
            .store
            .prepare_broker_cleanup(&broker_capability, &cleanup_request)
            .unwrap();
        let cleanup_io = fixture
            .store
            .begin_broker_io(&broker_capability, cleanup_intent)
            .unwrap();
        fixture.store.mark_broker_io_unknown(cleanup_io).unwrap();
        let cleanup_reconciliation = fixture
            .store
            .begin_broker_reconciliation(
                &broker_capability,
                &BrokerReconciliationRequest::new(
                    key.clone(),
                    BrokerJournalOperation::DeleteSecret,
                    route_commitment,
                )
                .unwrap(),
            )
            .unwrap();
        let deleted = fixture
            .store
            .commit_broker_reconciliation(
                cleanup_reconciliation,
                BrokerSecretObservation::absent([0xb5; 32]).unwrap(),
            )
            .unwrap();
        assert!(matches!(deleted, BrokerReconciliationResult::Completed(_)));
        let committed_absence = fixture
            .store
            .dispatch_broker_restart_context(&restart_key)
            .unwrap();
        assert_eq!(committed_absence.key(), &key);
        assert_eq!(
            committed_absence.action(),
            DispatchBrokerRestartAction::DeletionAlreadyAbsent
        );
        assert!(committed_absence.cleanup_request().is_none());
        assert!(committed_absence.reconciliation_request().is_none());
    }

    #[test]
    fn v13_intake_is_atomic_and_historical_recovery_is_time_authority_inert() {
        let fixture = ControlFixture::new(false);
        let compact = fixture.signed_wire(0x1300, 0x1301, 99, 160);
        let value: serde_json::Value = serde_json::from_slice(&compact).unwrap();
        let pretty = serde_json::to_vec_pretty(&value).unwrap();
        let compact_probe = IngressRecoveryProbe::parse_bytes(&compact).unwrap();
        let canonical_payload_commitment = compact_probe.canonical_payload_commitment();
        let first_wire_commitment = compact_probe.wire_commitment();
        let receipt = match fixture
            .store
            .accept_control_submission_or_recover(fixture.verify_wire(&compact))
            .unwrap()
        {
            ControlSubmissionIntakeOutcome::Fresh(receipt) => receipt,
            other => panic!("expected fresh intake, got {other:?}"),
        };
        {
            let state = fixture.store.inner.lock();
            let stored = state
                .control_submissions
                .get(&receipt.submission_id())
                .unwrap();
            assert_eq!(stored.first_wire_json, compact);
            assert_eq!(stored.first_wire_commitment, first_wire_commitment);
            assert_eq!(
                state.control_queue[&receipt.submission_id()].phase,
                ControlWorkPhase::Evaluate
            );
            assert_eq!(
                state.control_statuses[&receipt.submission_id()].status(),
                ControlStatusCode::Accepted
            );
            assert!(
                state
                    .ingress_replay_v13_nonces
                    .iter()
                    .any(|tuple| tuple.2 == Uuid::from_u128(0x1301))
            );
        }

        let mut rotated = fixture.authority.clone();
        rotated.principal_registry = AuthorityDomainState {
            root: Digest32::sha256(b"rotated-principal-registry"),
            epoch: fixture.authority.principal_registry.epoch + 1,
            activation_id: Uuid::from_u128(0x13ff),
        };
        fixture
            .store
            .compare_and_activate_authority(receipt.scope(), Some(&fixture.authority), &rotated)
            .unwrap();
        fixture.clock.set(-1);
        {
            let mut state = fixture.store.inner.lock();
            state.high_water.insert(receipt.scope().clone(), 10_000);
            state
                .ingress_replay_high_water
                .insert(IngressReplayScope::new(CONTROL_AUDIENCE).unwrap(), 10_000);
        }

        let retry_probe = IngressRecoveryProbe::parse_bytes(&pretty).unwrap();
        assert_eq!(
            retry_probe.canonical_payload_commitment(),
            canonical_payload_commitment
        );
        assert_ne!(retry_probe.wire_commitment(), first_wire_commitment);
        let frozen = fixture
            .store
            .control_recovery_verifier(&retry_probe)
            .unwrap()
            .unwrap();
        let historical = retry_probe.verify_historical(&frozen).unwrap();
        let recovered = fixture
            .store
            .recover_control_submission(&historical)
            .unwrap();
        assert_eq!(recovered.receipt(), &receipt);
        let state = fixture.store.inner.lock();
        let stored = state
            .control_submissions
            .get(&receipt.submission_id())
            .unwrap();
        assert_eq!(stored.first_wire_commitment, first_wire_commitment);
        assert_eq!(stored.first_wire_json, compact);
    }

    #[test]
    fn v13_temporal_rejection_advances_both_hwm_but_authority_mismatch_is_inert() {
        let fixture = ControlFixture::new(false);
        let expired = fixture.signed_wire(0x1311, 0x1312, 50, CONTROL_NOW);
        assert!(matches!(
            fixture
                .store
                .accept_control_submission_or_recover(fixture.verify_wire(&expired)),
            Err(StateError::ControlIngressExpired {
                observed: CONTROL_NOW,
                expires_at: CONTROL_NOW
            })
        ));
        let scope = Scope::new("acme", "prod").unwrap();
        let replay_scope = IngressReplayScope::new(CONTROL_AUDIENCE).unwrap();
        {
            let state = fixture.store.inner.lock();
            assert_eq!(state.high_water.get(&scope), Some(&CONTROL_NOW));
            assert_eq!(
                state.ingress_replay_high_water.get(&replay_scope),
                Some(&CONTROL_NOW)
            );
            assert!(state.control_submissions.is_empty());
            assert!(state.ingress_replay_v13_nonces.is_empty());
        }

        let other = ControlFixture::new(false);
        other.store.inner.lock().high_water.clear();
        let mut self_activated = other.authority.clone();
        self_activated.principal_registry = control_domain("attacker-principal");
        let wire = other.signed_wire(0x1313, 0x1314, 99, 160);
        let verified = other.verify_wire(&wire);
        // The opaque static result is still insufficient: state reloads the
        // exact active principal registry rather than trusting its getter.
        other
            .store
            .inner
            .lock()
            .authorities
            .get_mut(&scope)
            .unwrap()
            .principal_registry = self_activated.principal_registry;
        assert!(matches!(
            other.store.accept_control_submission_or_recover(verified),
            Err(StateError::AuthorityMismatch)
        ));
        let state = other.store.inner.lock();
        assert!(state.high_water.is_empty());
        assert!(state.ingress_replay_high_water.is_empty());
    }

    #[test]
    fn v13_control_claim_observes_the_shared_ingress_high_water() {
        let fixture = ControlFixture::new(false);
        let receipt = fixture.accept(0x1315, 0x1316);
        let replay_scope = IngressReplayScope::new(CONTROL_AUDIENCE).unwrap();

        // This audience-scoped observation can originate from another business
        // scope. Every later control transition must therefore use the maximum
        // of its own scope HWM and this shared ingress HWM.
        fixture
            .store
            .observe_ingress_time(&replay_scope, CONTROL_NOW + 20)
            .unwrap();
        fixture.clock.set(CONTROL_NOW + 10);
        let request = ControlWorkClaimRequest::new(
            "worker-shared-ingress-hwm",
            ControlWorkerRole::Evaluator,
            Uuid::from_u128(0x1317),
        )
        .unwrap();
        assert!(matches!(
            fixture.store.claim_next_control_work_or_recover(&request),
            Err(StateError::ClockRollback {
                observed: 110,
                high_water: 120,
            })
        ));
        {
            let state = fixture.store.inner.lock();
            assert!(!state.control_claims.contains_key(&request.claim_id()));
            assert_eq!(state.next_control_fence, 0);
            assert_eq!(state.high_water.get(receipt.scope()), Some(&CONTROL_NOW));
            assert_eq!(
                state.ingress_replay_high_water.get(&replay_scope),
                Some(&(CONTROL_NOW + 20))
            );
        }

        fixture.clock.set(CONTROL_NOW + 20);
        assert!(matches!(
            fixture
                .store
                .claim_next_control_work_or_recover(&request)
                .unwrap(),
            ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Evaluate(_))
        ));
        let state = fixture.store.inner.lock();
        assert_eq!(
            state.high_water.get(receipt.scope()),
            Some(&(CONTROL_NOW + 20))
        );
        assert_eq!(
            state.ingress_replay_high_water.get(&replay_scope),
            Some(&(CONTROL_NOW + 20))
        );
    }

    #[test]
    fn v13_intake_rejects_global_receipt_and_evaluation_nonce_collisions_without_mutation() {
        for collide_receipt in [true, false] {
            let fixture = ControlFixture::new(false);
            let wire = fixture.signed_wire(0x1320, 0x1321, 99, 160);
            let verified = fixture.verify_wire(&wire);
            let expected = StoredControlSubmission::from_verified(
                fixture.store.state_instance_id,
                &verified,
                CONTROL_NOW,
            )
            .unwrap();
            {
                let mut state = fixture.store.inner.lock();
                if collide_receipt {
                    state
                        .control_by_receipt_id
                        .insert(expected.receipt_id, Uuid::from_u128(0xdead));
                } else {
                    state
                        .control_by_evaluation_nonce
                        .insert(expected.evaluation_nonce, Uuid::from_u128(0xbeef));
                }
            }
            assert!(matches!(
                fixture.store.accept_control_submission_or_recover(verified),
                Err(StateError::ControlSubmissionMismatch)
            ));
            let state = fixture.store.inner.lock();
            assert!(state.control_submissions.is_empty());
            assert!(state.control_queue.is_empty());
            assert!(state.ingress_replay_v13_nonces.is_empty());
            assert!(state.high_water.is_empty());
            assert!(state.ingress_replay_high_water.is_empty());
        }
    }

    #[test]
    fn v13_queue_enforces_phase_selector_exact_recovery_and_fenced_takeover() {
        let fixture = ControlFixture::new(false);
        fixture.accept(0x1330, 0x1331);
        let issuer = ControlWorkClaimRequest::new(
            "worker-issuer",
            ControlWorkerRole::Issuer,
            Uuid::from_u128(0x1332),
        )
        .unwrap();
        assert_eq!(
            fixture
                .store
                .claim_next_control_work_or_recover(&issuer)
                .unwrap(),
            ControlWorkClaimOutcome::NoWork
        );
        let first_request = ControlWorkClaimRequest::new(
            "worker-evaluator-a",
            ControlWorkerRole::Evaluator,
            Uuid::from_u128(0x1333),
        )
        .unwrap();
        let first_fence = match fixture
            .store
            .claim_next_control_work_or_recover(&first_request)
            .unwrap()
        {
            ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Evaluate(work)) => {
                work.lease().fence()
            }
            other => panic!("expected first claim, got {other:?}"),
        };
        assert!(matches!(
            fixture
                .store
                .claim_next_control_work_or_recover(&first_request)
                .unwrap(),
            ControlWorkClaimOutcome::Recovered(ClaimedControlWork::Evaluate(_))
        ));
        let takeover = ControlWorkClaimRequest::new(
            "worker-evaluator-b",
            ControlWorkerRole::Evaluator,
            Uuid::from_u128(0x1334),
        )
        .unwrap();
        assert_eq!(
            fixture
                .store
                .claim_next_control_work_or_recover(&takeover)
                .unwrap(),
            ControlWorkClaimOutcome::NoWork
        );
        fixture.clock.set(CONTROL_NOW + CONTROL_WORK_LEASE_SECONDS);
        let second_fence = match fixture
            .store
            .claim_next_control_work_or_recover(&takeover)
            .unwrap()
        {
            ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Evaluate(work)) => {
                work.lease().fence()
            }
            other => panic!("expected takeover, got {other:?}"),
        };
        assert!(second_fence > first_fence);
    }

    #[test]
    fn v13_signed_evaluation_retry_is_phase_completed_not_prekernel_finalized() {
        let fixture = ControlFixture::new(true);
        fixture.accept(0x1335, 0x1336);
        let request = ControlWorkClaimRequest::new(
            "worker-evaluator",
            ControlWorkerRole::Evaluator,
            Uuid::from_u128(0x1337),
        )
        .unwrap();
        let work = match fixture
            .store
            .claim_next_control_work_or_recover(&request)
            .unwrap()
        {
            ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Evaluate(work)) => work,
            other => panic!("expected EVALUATE, got {other:?}"),
        };
        let signed = signed_control_evaluation(&work, &fixture.evaluator, DecisionOutcome::Allow);
        fixture.clock.set(101);
        fixture
            .store
            .record_control_evaluation(work, &signed, &fixture.evaluator.verifier())
            .unwrap();
        fixture.clock.set(-1);
        let completed = match fixture
            .store
            .claim_next_control_work_or_recover(&request)
            .unwrap()
        {
            ControlWorkClaimOutcome::PhaseCompleted(receipt) => receipt,
            other => panic!("expected signed EVALUATE completion, got {other:?}"),
        };
        assert_eq!(completed.phase(), ControlWorkPhase::Evaluate);
        assert_eq!(completed.consume_key(), None);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn v13_expired_capabilities_advance_hwm_and_cannot_resurrect_after_rollback() {
        let eval = ControlFixture::new(true);
        eval.accept(0x1338, 0x1339);
        let eval_work = claim_evaluation(&eval, 0x133a);
        let eval_retry = duplicate_evaluation_work(&eval_work);
        let signed = signed_control_evaluation(&eval_work, &eval.evaluator, DecisionOutcome::Allow);
        let expired_at = eval_work.lease().lease_until() + 1;
        eval.clock.set(expired_at);
        assert!(matches!(
            eval.store.record_control_evaluation(
                eval_work,
                &signed,
                &eval.evaluator.verifier()
            ),
            Err(StateError::ControlWorkLeaseExpired { observed, .. })
                if observed == expired_at
        ));
        eval.clock.set(expired_at - 1);
        assert!(matches!(
            eval.store.record_control_evaluation(
                eval_retry,
                &signed,
                &eval.evaluator.verifier()
            ),
            Err(StateError::ClockRollback { high_water, .. })
                if high_water == expired_at
        ));
        assert_control_dual_high_water(&eval, expired_at);

        let snapshot_fixture = ControlFixture::new(true);
        snapshot_fixture.accept(0x133b, 0x133c);
        authorize(&snapshot_fixture, 0x133d);
        let snapshot_work = claim_issuance(&snapshot_fixture, 0x133e);
        let snapshot_expired = snapshot_work.lease().lease_until() + 1;
        snapshot_fixture.clock.set(snapshot_expired);
        assert!(matches!(
            snapshot_fixture
                .store
                .control_issuance_snapshot(&snapshot_work),
            Err(StateError::ControlWorkLeaseExpired { observed, .. })
                if observed == snapshot_expired
        ));
        snapshot_fixture.clock.set(snapshot_expired - 1);
        assert!(matches!(
            snapshot_fixture
                .store
                .control_issuance_snapshot(&snapshot_work),
            Err(StateError::ClockRollback { high_water, .. })
                if high_water == snapshot_expired
        ));
        assert_control_dual_high_water(&snapshot_fixture, snapshot_expired);

        let issue_fixture = ControlFixture::new(true);
        issue_fixture.accept(0x133f, 0x1340);
        authorize(&issue_fixture, 0x1341);
        let issue_work = claim_issuance(&issue_fixture, 0x1342);
        let issue_retry = duplicate_issuance_work(&issue_work);
        let snapshot = issue_fixture
            .store
            .control_issuance_snapshot(&issue_work)
            .unwrap();
        let issued = issued_for_control_work(
            &issue_work,
            &snapshot,
            &issue_fixture.authorization_signer,
            0x1343,
        );
        let issue_expired = issue_work.lease().lease_until() + 1;
        issue_fixture.clock.set(issue_expired);
        assert!(matches!(
            issue_fixture
                .store
                .record_and_link_control_issuance_or_recover(issue_work, &issued),
            Err(StateError::ControlWorkLeaseExpired { observed, .. })
                if observed == issue_expired
        ));
        issue_fixture.clock.set(issue_expired - 1);
        assert!(matches!(
            issue_fixture
                .store
                .record_and_link_control_issuance_or_recover(issue_retry, &issued),
            Err(StateError::ClockRollback { high_water, .. })
                if high_water == issue_expired
        ));
        assert_control_dual_high_water(&issue_fixture, issue_expired);

        let consume_fixture = ControlFixture::new(true);
        consume_fixture.accept(0x1344, 0x1345);
        authorize(&consume_fixture, 0x1346);
        issue(&consume_fixture, 0x1347, 0x1348);
        consume_fixture.clock.set(104);
        let request = ControlWorkClaimRequest::new(
            "worker-consumer",
            ControlWorkerRole::Consumer,
            Uuid::from_u128(0x1349),
        )
        .unwrap();
        let consume_work = match consume_fixture
            .store
            .claim_next_control_work_or_recover(&request)
            .unwrap()
        {
            ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Consume(work)) => work,
            other => panic!("expected CONSUME, got {other:?}"),
        };
        let consume_retry = duplicate_consumption_work(&consume_work);
        let consume_expired = consume_work.lease().lease_until() + 1;
        consume_fixture.clock.set(consume_expired);
        assert!(matches!(
            consume_fixture
                .store
                .consume_and_link_control_or_recover(consume_work),
            Err(StateError::ControlWorkLeaseExpired { observed, .. })
                if observed == consume_expired
        ));
        consume_fixture.clock.set(consume_expired - 1);
        assert!(matches!(
            consume_fixture
                .store
                .consume_and_link_control_or_recover(consume_retry),
            Err(StateError::ClockRollback { high_water, .. })
                if high_water == consume_expired
        ));
        assert_control_dual_high_water(&consume_fixture, consume_expired);
    }

    #[test]
    fn v13_structural_claim_failure_rolls_back_claim_fence_queue_and_hwm() {
        let fixture = ControlFixture::new(false);
        let receipt = fixture.accept(0x1340, 0x1341);
        let scope = receipt.scope().clone();
        let (prior_hwm, prior_fence);
        {
            let mut state = fixture.store.inner.lock();
            state
                .control_submissions
                .get_mut(&receipt.submission_id())
                .unwrap()
                .first_wire_json = b"{}".to_vec();
            prior_hwm = state.high_water.clone();
            prior_fence = state.next_control_fence;
        }
        fixture.clock.set(CONTROL_NOW + 1);
        let request = ControlWorkClaimRequest::new(
            "worker-evaluator",
            ControlWorkerRole::Evaluator,
            Uuid::from_u128(0x1342),
        )
        .unwrap();
        assert!(matches!(
            fixture.store.claim_next_control_work_or_recover(&request),
            Err(StateError::InvalidRecord(_))
        ));
        let state = fixture.store.inner.lock();
        assert_eq!(state.high_water, prior_hwm);
        assert_eq!(state.next_control_fence, prior_fence);
        assert!(state.control_claims.is_empty());
        assert_eq!(
            state.control_queue[&receipt.submission_id()],
            MemoryControlQueue {
                phase: ControlWorkPhase::Evaluate,
                active_claim_id: None
            }
        );
        assert_eq!(state.high_water.get(&scope), Some(&CONTROL_NOW));
    }

    #[test]
    fn v13_evaluation_preserves_kernel_outcome_and_rejects_multi_grant_corruption() {
        let no_grant = ControlFixture::new(false);
        no_grant.accept(0x1350, 0x1351);
        let unavailable = authorize(&no_grant, 0x1352);
        assert_eq!(
            unavailable.kernel_outcome(),
            Some(ControlKernelOutcome::Allow)
        );
        assert_eq!(unavailable.control_outcome(), ControlOutcome::Deny);
        assert_eq!(
            unavailable.reason(),
            ControlDecisionReason::GrantUnavailable
        );
        assert_eq!(unavailable.selected_grant_id(), None);

        let one_grant = ControlFixture::new(true);
        one_grant.accept(0x1353, 0x1354);
        let allowed = authorize(&one_grant, 0x1355);
        assert_eq!(allowed.kernel_outcome(), Some(ControlKernelOutcome::Allow));
        assert_eq!(allowed.control_outcome(), ControlOutcome::Allow);
        assert_eq!(allowed.reason(), ControlDecisionReason::ControlAllow);
        assert_eq!(
            allowed.selected_grant_id(),
            Some(one_grant.grant.grant.grant_id)
        );

        let many = ControlFixture::new(true);
        many.accept(0x1356, 0x1357);
        {
            let mut state = many.store.inner.lock();
            let snapshot = state
                .grants
                .get(&(
                    Scope::new("acme", "prod").unwrap(),
                    many.grant.grant.grant_id,
                ))
                .unwrap()
                .clone();
            state.grants.insert(
                (Scope::new("acme", "prod").unwrap(), Uuid::from_u128(0x13aa)),
                snapshot,
            );
        }
        let work = claim_evaluation(&many, 0x1358);
        let signed = signed_control_evaluation(&work, &many.evaluator, DecisionOutcome::Allow);
        many.clock.set(CONTROL_NOW + 1);
        assert!(matches!(
            many.store.record_control_evaluation(
                work,
                &signed,
                &many.evaluator.verifier()
            ),
            Err(StateError::InvalidRecord(message))
                if message.contains("multiple current grants")
        ));
        let state = many.store.inner.lock();
        assert!(state.control_decisions.is_empty());
        assert!(state.control_by_decision_id.is_empty());
    }

    #[test]
    fn v13_prekernel_expiry_commits_deny_without_evaluation_capability() {
        let fixture = ControlFixture::new(false);
        let receipt = fixture.accept(0x1360, 0x1361);
        fixture.clock.set(160);
        let request = ControlWorkClaimRequest::new(
            "worker-evaluator",
            ControlWorkerRole::Evaluator,
            Uuid::from_u128(0x1362),
        )
        .unwrap();
        let decision = match fixture
            .store
            .claim_next_control_work_or_recover(&request)
            .unwrap()
        {
            ControlWorkClaimOutcome::DecisionFinalized(receipt) => receipt,
            other => panic!("expected pre-kernel denial, got {other:?}"),
        };
        assert_eq!(decision.kernel_outcome(), None);
        assert_eq!(decision.control_outcome(), ControlOutcome::Deny);
        assert_eq!(decision.reason(), ControlDecisionReason::IngressExpired);
        let state = fixture.store.inner.lock();
        assert_eq!(
            state.control_queue[&receipt.submission_id()].phase,
            ControlWorkPhase::Done
        );
        assert!(
            state.control_decisions[&receipt.submission_id()]
                .signed_evaluation
                .is_none()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn v13_atomic_issue_and_consume_block_legacy_bypasses_and_recover_completion() {
        let fixture = ControlFixture::new(true);
        let receipt = fixture.accept(0x1370, 0x1371);
        authorize(&fixture, 0x1372);
        let issue_request = ControlWorkClaimRequest::new(
            "worker-issuer",
            ControlWorkerRole::Issuer,
            Uuid::from_u128(0x1373),
        )
        .unwrap();
        fixture.clock.set(102);
        let issue_work = match fixture
            .store
            .claim_next_control_work_or_recover(&issue_request)
            .unwrap()
        {
            ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Issue(work)) => work,
            other => panic!("expected ISSUE, got {other:?}"),
        };
        let snapshot = fixture
            .store
            .control_issuance_snapshot(&issue_work)
            .unwrap();
        let issued = issued_for_control_work(
            &issue_work,
            &snapshot,
            &fixture.authorization_signer,
            0x1374,
        );
        assert!(matches!(
            fixture.store.record_issued_authorization(&issued),
            Err(StateError::ControlWorkMismatch)
        ));
        fixture.clock.set(103);
        assert_eq!(
            fixture
                .store
                .record_and_link_control_issuance_or_recover(issue_work, &issued)
                .unwrap(),
            ControlIssuanceCommitOutcome::Committed
        );
        fixture.clock.set(-1);
        let issue_completion = match fixture
            .store
            .claim_next_control_work_or_recover(&issue_request)
            .unwrap()
        {
            ControlWorkClaimOutcome::PhaseCompleted(completion) => completion,
            other => panic!("expected ISSUE completion, got {other:?}"),
        };
        assert_eq!(issue_completion.phase(), ControlWorkPhase::Issue);
        assert_eq!(issue_completion.consume_key(), None);

        let key = ConsumeKey {
            scope: issued.scope(),
            transaction_id: issued.transaction_id,
            authorization_id: issued.authorization().authorization_id,
        };
        assert!(matches!(
            fixture.store.consume(&key),
            Err(StateError::ControlWorkMismatch)
        ));
        {
            let state = fixture.store.inner.lock();
            assert!(
                !state
                    .receipts
                    .contains_key(&(key.scope.clone(), key.authorization_id))
            );
            assert!(
                !state
                    .outbox
                    .contains_key(&(key.scope.clone(), key.authorization_id))
            );
            assert_eq!(
                state.grants[&(key.scope.clone(), fixture.grant.grant.grant_id)].uses,
                0
            );
        }
        fixture.clock.set(104);
        let consume_request = ControlWorkClaimRequest::new(
            "worker-consumer",
            ControlWorkerRole::Consumer,
            Uuid::from_u128(0x1375),
        )
        .unwrap();
        let consume_work = match fixture
            .store
            .claim_next_control_work_or_recover(&consume_request)
            .unwrap()
        {
            ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Consume(work)) => work,
            other => panic!("expected CONSUME, got {other:?}"),
        };
        fixture.clock.set(105);
        let success = match fixture
            .store
            .consume_and_link_control_or_recover(consume_work)
            .unwrap()
        {
            ControlConsumptionCommitOutcome::Committed(success) => success,
            other => panic!("expected committed CONSUME, got {other:?}"),
        };
        assert_eq!(success.issued(), &issued);
        fixture.clock.set(-1);
        let consume_completion = match fixture
            .store
            .claim_next_control_work_or_recover(&consume_request)
            .unwrap()
        {
            ControlWorkClaimOutcome::PhaseCompleted(completion) => completion,
            other => panic!("expected CONSUME completion, got {other:?}"),
        };
        assert_eq!(consume_completion.phase(), ControlWorkPhase::Consume);
        assert_eq!(consume_completion.consume_key(), Some(&key));
        assert_eq!(consume_completion.submission_id(), receipt.submission_id());
        assert_eq!(fixture.store.consume_or_recover(&key).unwrap(), success);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn v13_exact_completed_retries_recover_full_lineage_without_sampling_time() {
        let fixture = ControlFixture::new(true);
        let receipt = fixture.accept(0x1376, 0x1377);
        let evaluation_request = ControlWorkClaimRequest::new(
            "worker-evaluator",
            ControlWorkerRole::Evaluator,
            Uuid::from_u128(0x1378),
        )
        .unwrap();
        let evaluation_work = match fixture
            .store
            .claim_next_control_work_or_recover(&evaluation_request)
            .unwrap()
        {
            ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Evaluate(work)) => work,
            other => panic!("expected EVALUATE, got {other:?}"),
        };
        let signed =
            signed_control_evaluation(&evaluation_work, &fixture.evaluator, DecisionOutcome::Allow);
        fixture.clock.set(101);
        fixture
            .store
            .record_control_evaluation(evaluation_work, &signed, &fixture.evaluator.verifier())
            .unwrap();

        fixture.clock.set(102);
        let issue_request = ControlWorkClaimRequest::new(
            "worker-issuer",
            ControlWorkerRole::Issuer,
            Uuid::from_u128(0x1379),
        )
        .unwrap();
        let issue_work = match fixture
            .store
            .claim_next_control_work_or_recover(&issue_request)
            .unwrap()
        {
            ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Issue(work)) => work,
            other => panic!("expected ISSUE, got {other:?}"),
        };
        let issue_retry = duplicate_issuance_work(&issue_work);
        let snapshot = fixture
            .store
            .control_issuance_snapshot(&issue_work)
            .unwrap();
        let issued = issued_for_control_work(
            &issue_work,
            &snapshot,
            &fixture.authorization_signer,
            0x137a,
        );
        fixture.clock.set(103);
        assert_eq!(
            fixture
                .store
                .record_and_link_control_issuance_or_recover(issue_work, &issued)
                .unwrap(),
            ControlIssuanceCommitOutcome::Committed
        );
        let before_issue_retry = fixture.store.inner.lock().high_water.clone();
        fixture.clock.set(-1);
        assert_eq!(
            fixture
                .store
                .record_and_link_control_issuance_or_recover(issue_retry, &issued)
                .unwrap(),
            ControlIssuanceCommitOutcome::Recovered
        );
        assert_eq!(fixture.store.inner.lock().high_water, before_issue_retry);

        fixture.clock.set(104);
        let consume_request = ControlWorkClaimRequest::new(
            "worker-consumer",
            ControlWorkerRole::Consumer,
            Uuid::from_u128(0x137b),
        )
        .unwrap();
        let consume_work = match fixture
            .store
            .claim_next_control_work_or_recover(&consume_request)
            .unwrap()
        {
            ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Consume(work)) => work,
            other => panic!("expected CONSUME, got {other:?}"),
        };
        let consume_retry = duplicate_consumption_work(&consume_work);
        fixture.clock.set(105);
        let success = match fixture
            .store
            .consume_and_link_control_or_recover(consume_work)
            .unwrap()
        {
            ControlConsumptionCommitOutcome::Committed(success) => success,
            other => panic!("expected committed CONSUME, got {other:?}"),
        };
        let before_all_retries = fixture.store.inner.lock().high_water.clone();
        fixture.clock.set(-1);
        assert_eq!(
            fixture
                .store
                .consume_and_link_control_or_recover(consume_retry)
                .unwrap(),
            ControlConsumptionCommitOutcome::Recovered(success.clone())
        );
        for (request, phase, expected_key) in [
            (&evaluation_request, ControlWorkPhase::Evaluate, None),
            (&issue_request, ControlWorkPhase::Issue, None),
            (
                &consume_request,
                ControlWorkPhase::Consume,
                Some(ConsumeKey {
                    scope: issued.scope(),
                    transaction_id: issued.transaction_id,
                    authorization_id: issued.authorization().authorization_id,
                }),
            ),
        ] {
            let completion = match fixture
                .store
                .claim_next_control_work_or_recover(request)
                .unwrap()
            {
                ControlWorkClaimOutcome::PhaseCompleted(completion) => completion,
                other => panic!("expected {phase:?} completion, got {other:?}"),
            };
            assert_eq!(completion.submission_id(), receipt.submission_id());
            assert_eq!(completion.phase(), phase);
            assert_eq!(completion.consume_key(), expected_key.as_ref());
        }
        assert_eq!(fixture.store.inner.lock().high_water, before_all_retries);
    }

    #[test]
    fn v13_completed_evaluate_retry_rejects_broken_evaluation_commitment_inertly() {
        let fixture = ControlFixture::new(true);
        let receipt = fixture.accept(0x137c, 0x137d);
        authorize(&fixture, 0x137e);
        let request = ControlWorkClaimRequest::new(
            "worker-evaluator",
            ControlWorkerRole::Evaluator,
            Uuid::from_u128(0x137e),
        )
        .unwrap();
        let before;
        {
            let mut state = fixture.store.inner.lock();
            let commitment = state.control_decisions[&receipt.submission_id()]
                .evaluation_commitment
                .unwrap();
            state.control_by_evaluation_commitment.remove(&commitment);
            before = state.high_water.clone();
        }
        fixture.clock.set(-1);
        assert!(matches!(
            fixture.store.claim_next_control_work_or_recover(&request),
            Err(StateError::InvalidRecord(_) | StateError::ControlWorkMismatch)
        ));
        assert_eq!(fixture.store.inner.lock().high_water, before);
    }

    #[test]
    fn v13_completed_issue_retry_rejects_partial_authorization_tuple_inertly() {
        let fixture = ControlFixture::new(true);
        fixture.accept(0x137f, 0x1380);
        authorize(&fixture, 0x1381);
        let issue_work = claim_issuance(&fixture, 0x1382);
        let issue_retry = duplicate_issuance_work(&issue_work);
        let snapshot = fixture
            .store
            .control_issuance_snapshot(&issue_work)
            .unwrap();
        let issued = issued_for_control_work(
            &issue_work,
            &snapshot,
            &fixture.authorization_signer,
            0x1383,
        );
        fixture.clock.set(103);
        assert_eq!(
            fixture
                .store
                .record_and_link_control_issuance_or_recover(issue_work, &issued)
                .unwrap(),
            ControlIssuanceCommitOutcome::Committed
        );
        let before;
        {
            let mut state = fixture.store.inner.lock();
            state
                .transactions
                .remove(&(issued.scope(), issued.transaction_id));
            before = state.high_water.clone();
        }
        fixture.clock.set(-1);
        assert!(matches!(
            fixture
                .store
                .record_and_link_control_issuance_or_recover(issue_retry, &issued),
            Err(StateError::InvalidRecord(_) | StateError::ControlWorkMismatch)
        ));
        assert_eq!(fixture.store.inner.lock().high_water, before);
    }

    #[test]
    fn v13_completed_consume_retry_rejects_partial_receipt_outbox_tuple_inertly() {
        let fixture = ControlFixture::new(true);
        let receipt = fixture.accept(0x1384, 0x1385);
        authorize(&fixture, 0x1386);
        let key = issue(&fixture, 0x1387, 0x1388);
        fixture.clock.set(104);
        let request = ControlWorkClaimRequest::new(
            "worker-consumer",
            ControlWorkerRole::Consumer,
            Uuid::from_u128(0x1389),
        )
        .unwrap();
        let work = match fixture
            .store
            .claim_next_control_work_or_recover(&request)
            .unwrap()
        {
            ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Consume(work)) => work,
            other => panic!("expected CONSUME, got {other:?}"),
        };
        let retry = duplicate_consumption_work(&work);
        fixture.clock.set(105);
        assert!(matches!(
            fixture.store.consume_and_link_control_or_recover(work),
            Ok(ControlConsumptionCommitOutcome::Committed(_))
        ));
        let before;
        {
            let mut state = fixture.store.inner.lock();
            state
                .outbox
                .remove(&(key.scope.clone(), key.authorization_id));
            assert!(
                state
                    .control_consumptions
                    .contains_key(&receipt.submission_id())
            );
            before = state.high_water.clone();
        }
        fixture.clock.set(-1);
        assert!(matches!(
            fixture.store.consume_and_link_control_or_recover(retry),
            Err(StateError::InvalidRecord(_) | StateError::ControlWorkMismatch)
        ));
        assert_eq!(fixture.store.inner.lock().high_water, before);
    }

    #[test]
    fn v13_finalized_retries_validate_terminal_decision_work_and_event_lineage_inertly() {
        let prekernel = ControlFixture::new(false);
        let prekernel_receipt = prekernel.accept(0x138a, 0x138b);
        prekernel.clock.set(160);
        let decision_request = ControlWorkClaimRequest::new(
            "worker-evaluator",
            ControlWorkerRole::Evaluator,
            Uuid::from_u128(0x138c),
        )
        .unwrap();
        let first_decision = match prekernel
            .store
            .claim_next_control_work_or_recover(&decision_request)
            .unwrap()
        {
            ControlWorkClaimOutcome::DecisionFinalized(receipt) => receipt,
            other => panic!("expected pre-kernel finalization, got {other:?}"),
        };
        prekernel.clock.set(-1);
        assert_eq!(
            prekernel
                .store
                .claim_next_control_work_or_recover(&decision_request)
                .unwrap(),
            ControlWorkClaimOutcome::DecisionFinalized(first_decision)
        );
        let before_decision_corruption;
        {
            let mut state = prekernel.store.inner.lock();
            let commitment =
                state.control_decisions[&prekernel_receipt.submission_id()].decision_commitment;
            state.control_by_decision_commitment.remove(&commitment);
            before_decision_corruption = state.high_water.clone();
        }
        assert!(matches!(
            prekernel
                .store
                .claim_next_control_work_or_recover(&decision_request),
            Err(StateError::InvalidRecord(_) | StateError::ControlWorkMismatch)
        ));
        assert_eq!(
            prekernel.store.inner.lock().high_water,
            before_decision_corruption
        );

        let finalized = ControlFixture::with_dispatch_policy(
            true,
            DispatchDeadlinePolicy {
                max_dispatch_delay_seconds: 30,
                profile_hard_cap: 104,
                immutable_dependency_expiries: vec![140],
            },
        );
        let finalized_receipt = finalized.accept(0x138d, 0x138e);
        authorize(&finalized, 0x138f);
        issue(&finalized, 0x1390, 0x1391);
        finalized.clock.set(104);
        let work_request = ControlWorkClaimRequest::new(
            "worker-consumer",
            ControlWorkerRole::Consumer,
            Uuid::from_u128(0x1392),
        )
        .unwrap();
        let first_finalization = match finalized
            .store
            .claim_next_control_work_or_recover(&work_request)
            .unwrap()
        {
            ControlWorkClaimOutcome::WorkFinalized(receipt) => receipt,
            other => panic!("expected work finalization, got {other:?}"),
        };
        finalized.clock.set(-1);
        assert_eq!(
            finalized
                .store
                .claim_next_control_work_or_recover(&work_request)
                .unwrap(),
            ControlWorkClaimOutcome::WorkFinalized(first_finalization)
        );
        let before_event_corruption;
        {
            let mut state = finalized.store.inner.lock();
            state
                .control_event_commitments
                .remove(&(finalized_receipt.submission_id(), 4));
            before_event_corruption = state.high_water.clone();
        }
        assert!(matches!(
            finalized
                .store
                .claim_next_control_work_or_recover(&work_request),
            Err(StateError::InvalidRecord(_) | StateError::ControlWorkMismatch)
        ));
        assert_eq!(
            finalized.store.inner.lock().high_water,
            before_event_corruption
        );
    }

    #[test]
    fn v13_status_and_intake_recovery_reject_corrupt_downstream_lineage_inertly() {
        let fixture = ControlFixture::new(true);
        let receipt = fixture.accept(0x1393, 0x1394);
        authorize(&fixture, 0x1395);
        let (stored, before) = {
            let mut state = fixture.store.inner.lock();
            let stored = state.control_submissions[&receipt.submission_id()].clone();
            let Some(commitment) =
                state.control_decisions[&receipt.submission_id()].evaluation_commitment
            else {
                panic!("authorized decision has an evaluation commitment");
            };
            state.control_by_evaluation_commitment.remove(&commitment);
            (stored, state.high_water.clone())
        };

        fixture.clock.set(-1);
        assert!(matches!(
            fixture
                .store
                .control_status(receipt.scope(), receipt.receipt_id()),
            Err(StateError::InvalidRecord(_) | StateError::ControlWorkMismatch)
        ));
        {
            let state = fixture.store.inner.lock();
            assert!(matches!(
                memory_control_recovered(&state, &stored),
                Err(StateError::InvalidRecord(_) | StateError::ControlWorkMismatch)
            ));
            assert_eq!(state.high_water, before);
        }
    }

    #[test]
    fn v13_control_owned_dispatch_paths_reject_a_complete_legacy_tuple_without_control_link() {
        let fixture = ControlFixture::new(true);
        let receipt = fixture.accept(0x1376, 0x1377);
        authorize(&fixture, 0x1378);
        let key = issue(&fixture, 0x1379, 0x137a);
        fixture.clock.set(104);
        let consume_request = ControlWorkClaimRequest::new(
            "worker-consumer",
            ControlWorkerRole::Consumer,
            Uuid::from_u128(0x137b),
        )
        .unwrap();
        let consume_work = match fixture
            .store
            .claim_next_control_work_or_recover(&consume_request)
            .unwrap()
        {
            ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Consume(work)) => work,
            other => panic!("expected CONSUME, got {other:?}"),
        };
        fixture.clock.set(105);
        assert!(matches!(
            fixture
                .store
                .consume_and_link_control_or_recover(consume_work)
                .unwrap(),
            ControlConsumptionCommitOutcome::Committed(_)
        ));

        // Simulate a complete receipt/outbox legacy tuple with the atomic v13
        // control link missing. No recovery or dispatch capability may adopt
        // it, even though the ordinary receipt/outbox validation succeeds.
        fixture
            .store
            .inner
            .lock()
            .control_consumptions
            .remove(&receipt.submission_id());
        fixture.clock.set(106);
        for result in [
            fixture.store.recover_exact(&key).map(|_| ()),
            fixture.store.consume_or_recover(&key).map(|_| ()),
            fixture.store.dispatch_snapshot(&key).map(|_| ()),
        ] {
            assert!(matches!(result, Err(StateError::InvalidRecord(_))));
        }
        assert!(matches!(
            fixture.store.claim_dispatch(&DispatchClaimRequest {
                key: key.clone(),
                claim_id: Uuid::from_u128(0x137c),
                worker_id: "worker-dispatch".to_owned(),
            }),
            Err(StateError::DispatchAcquisitionRequired)
        ));
        let state = fixture.store.inner.lock();
        assert!(state.dispatch_claims.is_empty());
        assert!(state.physical_reservations.is_empty());
    }

    #[test]
    fn v13_consume_preflight_finalizes_closed_when_profile_window_expires() {
        let fixture = ControlFixture::with_dispatch_policy(
            true,
            DispatchDeadlinePolicy {
                max_dispatch_delay_seconds: 30,
                profile_hard_cap: 104,
                immutable_dependency_expiries: vec![140],
            },
        );
        let receipt = fixture.accept(0x1380, 0x1381);
        authorize(&fixture, 0x1382);
        issue(&fixture, 0x1383, 0x1384);
        fixture.clock.set(104);
        let request = ControlWorkClaimRequest::new(
            "worker-consumer",
            ControlWorkerRole::Consumer,
            Uuid::from_u128(0x1385),
        )
        .unwrap();
        let finalized = match fixture
            .store
            .claim_next_control_work_or_recover(&request)
            .unwrap()
        {
            ControlWorkClaimOutcome::WorkFinalized(receipt) => receipt,
            other => panic!("expected fail-closed CONSUME, got {other:?}"),
        };
        assert_eq!(finalized.phase(), ControlWorkPhase::Consume);
        assert_eq!(
            finalized.reason(),
            ControlWorkFinalizationReason::DispatchWindowExpired
        );
        let status = fixture
            .store
            .control_status(receipt.scope(), receipt.receipt_id())
            .unwrap();
        assert_eq!(status.status(), ControlStatusCode::FailedClosed);
        assert_eq!(
            status.reason(),
            Some(ControlStatusReason::Finalization(
                ControlWorkFinalizationReason::DispatchWindowExpired
            ))
        );
    }

    #[test]
    fn v13_permanent_nonce_survives_gc_and_blocks_legacy_reuse_after_expiry() {
        let fixture = ControlFixture::new(false);
        let wire = fixture.signed_wire(0x1390, 0x1391, 99, 160);
        let verified = fixture.verify_wire(&wire);
        let key_id = verified.key_id().to_owned();
        fixture
            .store
            .accept_control_submission_or_recover(verified)
            .unwrap();
        let replay_scope = IngressReplayScope::new(CONTROL_AUDIENCE).unwrap();
        fixture
            .store
            .observe_ingress_time(&replay_scope, 200)
            .unwrap();
        assert_eq!(
            fixture
                .store
                .prune_expired_ingress_nonces(&replay_scope, 100)
                .unwrap(),
            0
        );
        let legacy = IngressNonceConsumption::new(
            replay_scope.clone(),
            key_id,
            Uuid::from_u128(0x1391),
            300,
            200,
        )
        .unwrap();
        assert_eq!(
            fixture.store.consume_ingress_nonce(&legacy).unwrap(),
            IngressReplayDecision::AlreadyUsed
        );
        let state = fixture.store.inner.lock();
        assert_eq!(
            state.ingress_replay_high_water.get(&replay_scope),
            Some(&200)
        );
        assert_eq!(
            state.ingress_replay_nonces.get(&(
                replay_scope,
                legacy.key_id().to_owned(),
                legacy.nonce()
            )),
            Some(&160)
        );
    }

    #[test]
    fn v13_intake_cannot_retroactively_claim_an_existing_legacy_authorization() {
        let source = ControlFixture::new(true);
        source.accept(0x139a, 0x139b);
        authorize(&source, 0x139c);
        let key = issue(&source, 0x139d, 0x139e);
        let issued = source
            .store
            .inner
            .lock()
            .authorizations
            .get(&(key.scope.clone(), key.authorization_id))
            .unwrap()
            .clone();

        // The second store has no control ledger for this signed authorization. It is
        // therefore a legitimate pre-existing profile-v2 legacy tuple.
        let legacy = ControlFixture::new(true);
        {
            let scope = Scope::new("acme", "prod").unwrap();
            let mut state = legacy.store.inner.lock();
            state
                .authorities
                .insert(scope.clone(), source.authority.clone());
            state.grants.insert(
                (scope, source.grant.grant.grant_id),
                GrantSnapshot {
                    registration: source.grant.clone(),
                    uses: 0,
                    revoked: false,
                },
            );
        }
        legacy.clock.set(104);
        legacy.store.record_issued_authorization(&issued).unwrap();
        legacy.clock.set(105);
        let consumed = legacy.store.consume_or_recover(&key).unwrap();
        let (prior_scope_hwm, prior_ingress_hwm) = {
            let state = legacy.store.inner.lock();
            (
                state.high_water.clone(),
                state.ingress_replay_high_water.clone(),
            )
        };

        let colliding = legacy.signed_wire(0x139a, 0x139f, 99, 160);
        assert!(matches!(
            legacy
                .store
                .accept_control_submission_or_recover(legacy.verify_wire(&colliding)),
            Err(StateError::ControlRequestConflict)
        ));
        let state = legacy.store.inner.lock();
        assert!(state.control_submissions.is_empty());
        assert_eq!(state.high_water, prior_scope_hwm);
        assert_eq!(state.ingress_replay_high_water, prior_ingress_hwm);
        drop(state);
        legacy.clock.set(-1);
        assert_eq!(legacy.store.consume_or_recover(&key).unwrap(), consumed);
    }
}
