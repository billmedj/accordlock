//! Bounded, mono-role composition for the v13 durable control queue.
//!
//! Each public worker performs at most one claim and one phase transition per
//! call. Roles, signing identities, policy, registry, and state adapters are
//! fixed at construction. The only retry input is an opaque local recovery
//! token minted from an exact claim; no API accepts a raw claim identifier or
//! reconstructs a work capability.
//!
//! Exact retry requires the supervisor to retain `ClaimAttempt` or
//! `ClaimRecovery`. Because neither is clonable or serializable, a full process
//! crash loses an unjournaled identity; this crate does not claim autonomous
//! restart or infer that an unknown external effect did not happen.

use core::fmt;

use accordlock_issuance::{AuthorizationIssuer, IssuanceError};
use accordlock_kernel::{ActivatedAttesterRegistry, KernelContext, KernelError};
use accordlock_protocol::{CoseVerifier, PolicyConfig, SigningIdentity, TrustedEvidenceSet};
use accordlock_state::{
    ClaimedControlWork, ConsumeSuccess, ControlConsumptionCommitOutcome, ControlDecisionReceipt,
    ControlPhaseCompletionReceipt, ControlPlaneState, ControlStatusSnapshot,
    ControlWorkClaimOutcome, ControlWorkClaimRecoveryKey, ControlWorkClaimRequest,
    ControlWorkFinalizationReason, ControlWorkFinalizationReceipt, ControlWorkPhase,
    ControlWorkerRole, Scope, StateError, TransactionalState,
};
use thiserror::Error;
use uuid::Uuid;

/// Exact result of one bounded worker call.
///
/// `DecisionFinalized`, `WorkFinalized`, and `PhaseCompleted` are inert durable
/// history and contain no execution authority. Claim and commit ambiguity are
/// deliberately distinct and never masquerade as a successful advance.
#[derive(Debug)]
pub enum ControlStep<T> {
    /// The worker completed or exactly recovered its phase operation.
    Advanced(T),
    /// State finalized a pre-kernel control decision while selecting work.
    DecisionFinalized(ControlDecisionReceipt),
    /// State finalized ISSUE or CONSUME while selecting work.
    WorkFinalized(ControlWorkFinalizationReceipt),
    /// Exact inert recovery of a claim whose phase already committed.
    PhaseCompleted(ControlPhaseCompletionReceipt),
    /// No ready work exists for this worker's fixed role.
    NoWork,
    /// Claim commit state is indeterminate. No work capability was returned.
    ClaimOutcomeUnknown(ClaimRecovery),
    /// A phase commit finalized fail-closed after a capability was claimed.
    CommitFinalized(CommitFinalization),
    /// A phase commit is indeterminate. No success material is returned.
    CommitOutcomeUnknown {
        facts: CommitAmbiguity,
        recovery: ClaimRecovery,
    },
}

/// Opaque, process-local identity for one bounded claim attempt.
///
/// A trusted supervisor creates this value before entering a worker call and
/// retains it until the call resolves. Reusing the same value after a worker
/// task dies recovers the exact state claim. It exposes no raw claim ID and
/// implements neither serialization nor `Clone`.
pub struct ClaimAttempt {
    worker_id: String,
    role: ControlWorkerRole,
    claim_id: Uuid,
}

impl fmt::Debug for ClaimAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaimAttempt")
            .field("worker_id", &self.worker_id)
            .field("role", &self.role)
            .field("claim_id", &"<opaque>")
            .finish()
    }
}

/// Opaque, process-local authority to repeat one exact ambiguous claim.
///
/// It deliberately exposes no raw claim identifier and implements neither
/// serialization nor `Clone`. A supervisor may retain it in memory and hand it
/// back only to the worker instance that produced it.
pub struct ClaimRecovery {
    worker_id: String,
    role: ControlWorkerRole,
    claim_id: Uuid,
}

impl fmt::Debug for ClaimRecovery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaimRecovery")
            .field("worker_id", &self.worker_id)
            .field("role", &self.role)
            .field("claim_id", &"<opaque>")
            .finish()
    }
}

impl ClaimRecovery {
    fn from_request(request: &ControlWorkClaimRequest) -> Self {
        Self {
            worker_id: request.worker_id().to_owned(),
            role: request.role(),
            claim_id: request.claim_id(),
        }
    }

    fn from_state(recovery: &ControlWorkClaimRecoveryKey) -> Self {
        Self {
            worker_id: recovery.worker_id().to_owned(),
            role: recovery.role(),
            claim_id: recovery.claim_id(),
        }
    }
}

/// Terminal facts surfaced by ISSUE when `AuthorizationIssuer` reports a state-owned
/// fail-closed finalization after the work capability was claimed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitFinalization {
    submission_id: Uuid,
    phase: ControlWorkPhase,
    reason: ControlWorkFinalizationReason,
    finalized_at: i64,
}

impl CommitFinalization {
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

    fn from_receipt(receipt: &ControlWorkFinalizationReceipt) -> Self {
        Self {
            submission_id: receipt.submission_id(),
            phase: receipt.phase(),
            reason: receipt.reason(),
            finalized_at: receipt.finalized_at(),
        }
    }
}

/// Exact phase and submission identity for an indeterminate phase commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitAmbiguity {
    submission_id: Uuid,
    phase: ControlWorkPhase,
}

impl CommitAmbiguity {
    #[must_use]
    pub const fn submission_id(&self) -> Uuid {
        self.submission_id
    }

    #[must_use]
    pub const fn phase(&self) -> ControlWorkPhase {
        self.phase
    }
}

/// Successful EVALUATE transition. The signed evaluation remains in state and
/// is reloaded only as opaque ISSUE authority; it is not exported here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluationAdvance {
    decision: ControlDecisionReceipt,
}

impl EvaluationAdvance {
    #[must_use]
    pub const fn decision(&self) -> &ControlDecisionReceipt {
        &self.decision
    }
}

/// Inert acknowledgement of a successful ISSUE transition.
///
/// The signed authorization and consume key remain inside durable state. The
/// underlying issuer intentionally treats a fresh deterministic commit and
/// byte-exact recovery as the same safe result, so this type exposes neither
/// distinction nor security material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IssuanceAdvance {
    submission_id: Uuid,
}

impl IssuanceAdvance {
    #[must_use]
    pub const fn submission_id(&self) -> Uuid {
        self.submission_id
    }
}

/// Whether CONSUME was newly committed or exactly recovered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsumptionAdvance {
    Committed(ConsumeSuccess),
    Recovered(ConsumeSuccess),
}

/// Fail-closed worker composition errors.
#[derive(Debug, Error)]
pub enum ControlWorkerError {
    #[error("control worker configuration is invalid: {0}")]
    InvalidConfiguration(#[source] StateError),
    #[error("durable control state rejected the operation: {0}")]
    State(#[from] StateError),
    #[error("kernel evaluation failed closed: {0}")]
    Kernel(#[from] KernelError),
    #[error("authorization issuance failed closed: {0}")]
    Issuance(#[source] IssuanceError),
    #[error("state returned a claim outcome inconsistent with local role/worker/claim authority")]
    ClaimOutcomeMismatch,
    #[error("claim attempt or recovery token does not belong to this fixed worker identity")]
    ClaimIdentityMismatch,
}

#[derive(Clone, Debug)]
struct WorkerIdentity {
    worker_id: String,
    role: ControlWorkerRole,
}

impl WorkerIdentity {
    fn new(
        worker_id: impl Into<String>,
        role: ControlWorkerRole,
    ) -> Result<Self, ControlWorkerError> {
        let worker_id = worker_id.into();
        // Reuse the state boundary's canonical identity validator. The fixed
        // non-nil value is validation-only and is never submitted as a claim.
        ControlWorkClaimRequest::new(worker_id.clone(), role, Uuid::from_u128(1))
            .map_err(ControlWorkerError::InvalidConfiguration)?;
        Ok(Self { worker_id, role })
    }

    fn begin_attempt(&self) -> ClaimAttempt {
        ClaimAttempt {
            worker_id: self.worker_id.clone(),
            role: self.role,
            claim_id: Uuid::new_v4(),
        }
    }

    fn attempt_request(
        &self,
        attempt: &ClaimAttempt,
    ) -> Result<ControlWorkClaimRequest, ControlWorkerError> {
        if attempt.worker_id != self.worker_id || attempt.role != self.role {
            return Err(ControlWorkerError::ClaimIdentityMismatch);
        }
        ControlWorkClaimRequest::new(self.worker_id.clone(), self.role, attempt.claim_id)
            .map_err(|_| ControlWorkerError::ClaimIdentityMismatch)
    }

    fn recovery_request(
        &self,
        recovery: &ClaimRecovery,
    ) -> Result<ControlWorkClaimRequest, ControlWorkerError> {
        if recovery.worker_id != self.worker_id || recovery.role != self.role {
            return Err(ControlWorkerError::ClaimIdentityMismatch);
        }
        ControlWorkClaimRequest::new(self.worker_id.clone(), self.role, recovery.claim_id)
            .map_err(|_| ControlWorkerError::ClaimIdentityMismatch)
    }

    const fn phase(&self) -> ControlWorkPhase {
        phase_for_role(self.role)
    }
}

const fn phase_for_role(role: ControlWorkerRole) -> ControlWorkPhase {
    match role {
        ControlWorkerRole::Evaluator => ControlWorkPhase::Evaluate,
        ControlWorkerRole::Issuer => ControlWorkPhase::Issue,
        ControlWorkerRole::Consumer => ControlWorkPhase::Consume,
    }
}

fn claimed_phase(work: &ClaimedControlWork) -> ControlWorkPhase {
    match work {
        ClaimedControlWork::Evaluate(_) => ControlWorkPhase::Evaluate,
        ClaimedControlWork::Issue(_) => ControlWorkPhase::Issue,
        ClaimedControlWork::Consume(_) => ControlWorkPhase::Consume,
    }
}

fn claimed_lease(work: &ClaimedControlWork) -> &accordlock_state::ControlWorkLease {
    match work {
        ClaimedControlWork::Evaluate(work) => work.lease(),
        ClaimedControlWork::Issue(work) => work.lease(),
        ClaimedControlWork::Consume(work) => work.lease(),
    }
}

fn validate_claim_outcome(
    identity: &WorkerIdentity,
    request: &ControlWorkClaimRequest,
    outcome: &ControlWorkClaimOutcome,
) -> Result<(), ControlWorkerError> {
    match outcome {
        ControlWorkClaimOutcome::Claimed(work) | ControlWorkClaimOutcome::Recovered(work) => {
            let lease = claimed_lease(work);
            if claimed_phase(work) != identity.phase()
                || lease.phase() != identity.phase()
                || lease.worker_id() != identity.worker_id
                || lease.claim_id() != request.claim_id()
            {
                return Err(ControlWorkerError::ClaimOutcomeMismatch);
            }
        }
        ControlWorkClaimOutcome::PhaseCompleted(receipt) => {
            if receipt.phase() != identity.phase()
                || receipt.worker_id() != identity.worker_id
                || receipt.claim_id() != request.claim_id()
            {
                return Err(ControlWorkerError::ClaimOutcomeMismatch);
            }
        }
        ControlWorkClaimOutcome::WorkFinalized(receipt) => {
            if receipt.phase() != identity.phase() {
                return Err(ControlWorkerError::ClaimOutcomeMismatch);
            }
        }
        ControlWorkClaimOutcome::OutcomeUnknown(recovery) => {
            if recovery.role() != identity.role
                || recovery.worker_id() != identity.worker_id
                || recovery.claim_id() != request.claim_id()
            {
                return Err(ControlWorkerError::ClaimOutcomeMismatch);
            }
        }
        ControlWorkClaimOutcome::DecisionFinalized(_) | ControlWorkClaimOutcome::NoWork => {}
    }
    Ok(())
}

fn claim<S: ControlPlaneState>(
    state: &S,
    identity: &WorkerIdentity,
    request: &ControlWorkClaimRequest,
) -> Result<ControlWorkClaimOutcome, ControlWorkerError> {
    let outcome = state.claim_next_control_work_or_recover(request)?;
    validate_claim_outcome(identity, request, &outcome)?;
    Ok(outcome)
}

enum MappedClaim<T> {
    Inert(ControlStep<T>),
    Claimed(Box<ClaimedControlWork>),
}

fn map_claim<T>(outcome: ControlWorkClaimOutcome) -> MappedClaim<T> {
    match outcome {
        ControlWorkClaimOutcome::Claimed(work) | ControlWorkClaimOutcome::Recovered(work) => {
            MappedClaim::Claimed(Box::new(work))
        }
        ControlWorkClaimOutcome::DecisionFinalized(receipt) => {
            MappedClaim::Inert(ControlStep::DecisionFinalized(receipt))
        }
        ControlWorkClaimOutcome::WorkFinalized(receipt) => {
            MappedClaim::Inert(ControlStep::WorkFinalized(receipt))
        }
        ControlWorkClaimOutcome::PhaseCompleted(receipt) => {
            MappedClaim::Inert(ControlStep::PhaseCompleted(receipt))
        }
        ControlWorkClaimOutcome::NoWork => MappedClaim::Inert(ControlStep::NoWork),
        ControlWorkClaimOutcome::OutcomeUnknown(recovery) => MappedClaim::Inert(
            ControlStep::ClaimOutcomeUnknown(ClaimRecovery::from_state(&recovery)),
        ),
    }
}

/// Fixed-role EVALUATE worker.
pub struct EvaluatorWorker<S> {
    state: S,
    identity: WorkerIdentity,
    policy: PolicyConfig,
    registry: ActivatedAttesterRegistry,
    evaluator: SigningIdentity,
}

impl<S> fmt::Debug for EvaluatorWorker<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvaluatorWorker")
            .field("worker_id", &self.identity.worker_id)
            .field("role", &self.identity.role)
            .field("state", &"<trusted-state>")
            .field("policy", &"<authority-bound>")
            .field("registry", &"<authority-bound>")
            .field("evaluator", &"<isolated>")
            .finish()
    }
}

impl<S: ControlPlaneState> EvaluatorWorker<S> {
    /// Constructs a worker permanently bound to the EVALUATE role.
    ///
    /// # Errors
    ///
    /// Returns [`ControlWorkerError::InvalidConfiguration`] when the local
    /// worker identity is not in the canonical bounded profile.
    pub fn new(
        state: S,
        worker_id: impl Into<String>,
        policy: PolicyConfig,
        registry: ActivatedAttesterRegistry,
        evaluator: SigningIdentity,
    ) -> Result<Self, ControlWorkerError> {
        Ok(Self {
            state,
            identity: WorkerIdentity::new(worker_id, ControlWorkerRole::Evaluator)?,
            policy,
            registry,
            evaluator,
        })
    }

    /// Creates the opaque local identity for one EVALUATE attempt.
    #[must_use]
    pub fn begin_attempt(&self) -> ClaimAttempt {
        self.identity.begin_attempt()
    }

    /// Performs at most one EVALUATE step under an exact local attempt.
    ///
    /// # Errors
    ///
    /// Returns [`ControlWorkerError`] if claim validation, kernel evaluation,
    /// signature binding, or the durable decision write fails closed.
    pub fn run_once(
        &self,
        attempt: &ClaimAttempt,
        evidence: &TrustedEvidenceSet,
    ) -> Result<ControlStep<EvaluationAdvance>, ControlWorkerError> {
        let request = self.identity.attempt_request(attempt)?;
        let outcome = claim(&self.state, &self.identity, &request)?;
        self.process(outcome, evidence)
    }

    /// Repeats only the exact claim identified by a prior ambiguous result.
    ///
    /// # Errors
    ///
    /// Returns [`ControlWorkerError::ClaimIdentityMismatch`] for a token from a
    /// different worker, or another [`ControlWorkerError`] if recovery or the
    /// bounded EVALUATE operation fails closed.
    pub fn recover_once(
        &self,
        recovery: &ClaimRecovery,
        evidence: &TrustedEvidenceSet,
    ) -> Result<ControlStep<EvaluationAdvance>, ControlWorkerError> {
        let request = self.identity.recovery_request(recovery)?;
        let outcome = claim(&self.state, &self.identity, &request)?;
        self.process(outcome, evidence)
    }

    fn process(
        &self,
        outcome: ControlWorkClaimOutcome,
        evidence: &TrustedEvidenceSet,
    ) -> Result<ControlStep<EvaluationAdvance>, ControlWorkerError> {
        let work = match map_claim(outcome) {
            MappedClaim::Inert(inert) => return Ok(inert),
            MappedClaim::Claimed(work) => match *work {
                ClaimedControlWork::Evaluate(work) => work,
                _ => return Err(ControlWorkerError::ClaimOutcomeMismatch),
            },
        };
        let context =
            KernelContext::from_control_work(work, self.policy.clone(), self.registry.clone())?;
        let (work, signed_evaluation) = context.evaluate_control(evidence, &self.evaluator)?;
        let evaluator = self.evaluator.verifier();
        let decision =
            self.state
                .record_control_evaluation(work, &signed_evaluation, &evaluator)?;
        Ok(ControlStep::Advanced(EvaluationAdvance { decision }))
    }
}

/// Fixed-role ISSUE worker.
pub struct IssuerWorker<S> {
    state: S,
    identity: WorkerIdentity,
    issuer: AuthorizationIssuer<S>,
}

impl<S> fmt::Debug for IssuerWorker<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuerWorker")
            .field("worker_id", &self.identity.worker_id)
            .field("role", &self.identity.role)
            .field("state", &"<trusted-state>")
            .field("issuer", &"<isolated>")
            .finish()
    }
}

impl<S> IssuerWorker<S>
where
    S: Clone + ControlPlaneState + TransactionalState,
{
    /// Constructs a worker permanently bound to the ISSUE role. The state
    /// clone must be another handle to the same durable state instance.
    ///
    /// # Errors
    ///
    /// Returns [`ControlWorkerError::InvalidConfiguration`] when the local
    /// worker identity is not in the canonical bounded profile.
    pub fn new(
        state: S,
        worker_id: impl Into<String>,
        evaluator: CoseVerifier,
        authorization_signer: SigningIdentity,
    ) -> Result<Self, ControlWorkerError> {
        let identity = WorkerIdentity::new(worker_id, ControlWorkerRole::Issuer)?;
        let issuer = AuthorizationIssuer::new(state.clone(), evaluator, authorization_signer);
        Ok(Self {
            state,
            identity,
            issuer,
        })
    }

    /// Creates the opaque local identity for one ISSUE attempt.
    #[must_use]
    pub fn begin_attempt(&self) -> ClaimAttempt {
        self.identity.begin_attempt()
    }

    /// Performs at most one ISSUE step under an exact local attempt.
    ///
    /// # Errors
    ///
    /// Returns [`ControlWorkerError`] if claim validation or deterministic
    /// state-backed issuance fails closed.
    pub fn run_once(
        &self,
        attempt: &ClaimAttempt,
    ) -> Result<ControlStep<IssuanceAdvance>, ControlWorkerError> {
        let request = self.identity.attempt_request(attempt)?;
        let outcome = claim(&self.state, &self.identity, &request)?;
        self.process(outcome, &request)
    }

    /// Repeats only the exact claim identified by a prior ambiguous result.
    ///
    /// # Errors
    ///
    /// Returns [`ControlWorkerError::ClaimIdentityMismatch`] for a token from a
    /// different worker, or another [`ControlWorkerError`] if recovery or the
    /// bounded ISSUE operation fails closed.
    pub fn recover_once(
        &self,
        recovery: &ClaimRecovery,
    ) -> Result<ControlStep<IssuanceAdvance>, ControlWorkerError> {
        let request = self.identity.recovery_request(recovery)?;
        let outcome = claim(&self.state, &self.identity, &request)?;
        self.process(outcome, &request)
    }

    fn process(
        &self,
        outcome: ControlWorkClaimOutcome,
        request: &ControlWorkClaimRequest,
    ) -> Result<ControlStep<IssuanceAdvance>, ControlWorkerError> {
        let work = match map_claim(outcome) {
            MappedClaim::Inert(inert) => return Ok(inert),
            MappedClaim::Claimed(work) => match *work {
                ClaimedControlWork::Issue(work) => work,
                _ => return Err(ControlWorkerError::ClaimOutcomeMismatch),
            },
        };
        let submission_id = work.lease().submission_id();
        match self.issuer.issue_or_recover(work) {
            Ok(issuance) => {
                // Product composition does not release the pre-consumption
                // authorization or consume key. The exact tuple is already durable
                // and the CONSUME worker reloads it through state authority.
                drop(issuance);
                Ok(ControlStep::Advanced(IssuanceAdvance { submission_id }))
            }
            Err(IssuanceError::ControlIssuanceFinalized {
                submission_id,
                reason,
                finalized_at,
            }) => Ok(ControlStep::CommitFinalized(CommitFinalization {
                submission_id,
                phase: ControlWorkPhase::Issue,
                reason,
                finalized_at,
            })),
            Err(IssuanceError::ControlIssuanceOutcomeUnknown { submission_id }) => {
                Ok(ControlStep::CommitOutcomeUnknown {
                    facts: CommitAmbiguity {
                        submission_id,
                        phase: ControlWorkPhase::Issue,
                    },
                    recovery: ClaimRecovery::from_request(request),
                })
            }
            Err(error) => Err(ControlWorkerError::Issuance(error)),
        }
    }
}

/// Fixed-role CONSUME worker.
pub struct ConsumerWorker<S> {
    state: S,
    identity: WorkerIdentity,
}

impl<S> fmt::Debug for ConsumerWorker<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsumerWorker")
            .field("worker_id", &self.identity.worker_id)
            .field("role", &self.identity.role)
            .field("state", &"<trusted-state>")
            .finish()
    }
}

impl<S: ControlPlaneState> ConsumerWorker<S> {
    /// Constructs a worker permanently bound to the CONSUME role.
    ///
    /// # Errors
    ///
    /// Returns [`ControlWorkerError::InvalidConfiguration`] when the local
    /// worker identity is not in the canonical bounded profile.
    pub fn new(state: S, worker_id: impl Into<String>) -> Result<Self, ControlWorkerError> {
        Ok(Self {
            state,
            identity: WorkerIdentity::new(worker_id, ControlWorkerRole::Consumer)?,
        })
    }

    /// Creates the opaque local identity for one CONSUME attempt.
    #[must_use]
    pub fn begin_attempt(&self) -> ClaimAttempt {
        self.identity.begin_attempt()
    }

    /// Performs at most one CONSUME step under an exact local attempt.
    ///
    /// # Errors
    ///
    /// Returns [`ControlWorkerError`] if claim validation or the atomic
    /// consume/outbox/control-link transition fails closed.
    pub fn run_once(
        &self,
        attempt: &ClaimAttempt,
    ) -> Result<ControlStep<ConsumptionAdvance>, ControlWorkerError> {
        let request = self.identity.attempt_request(attempt)?;
        let outcome = claim(&self.state, &self.identity, &request)?;
        self.process(outcome, &request)
    }

    /// Repeats only the exact claim identified by a prior ambiguous result.
    ///
    /// # Errors
    ///
    /// Returns [`ControlWorkerError::ClaimIdentityMismatch`] for a token from a
    /// different worker, or another [`ControlWorkerError`] if recovery or the
    /// bounded CONSUME operation fails closed.
    pub fn recover_once(
        &self,
        recovery: &ClaimRecovery,
    ) -> Result<ControlStep<ConsumptionAdvance>, ControlWorkerError> {
        let request = self.identity.recovery_request(recovery)?;
        let outcome = claim(&self.state, &self.identity, &request)?;
        self.process(outcome, &request)
    }

    fn process(
        &self,
        outcome: ControlWorkClaimOutcome,
        request: &ControlWorkClaimRequest,
    ) -> Result<ControlStep<ConsumptionAdvance>, ControlWorkerError> {
        let work = match map_claim(outcome) {
            MappedClaim::Inert(inert) => return Ok(inert),
            MappedClaim::Claimed(work) => match *work {
                ClaimedControlWork::Consume(work) => work,
                _ => return Err(ControlWorkerError::ClaimOutcomeMismatch),
            },
        };
        let submission_id = work.lease().submission_id();
        match self.state.consume_and_link_control_or_recover(work)? {
            ControlConsumptionCommitOutcome::Committed(success) => Ok(ControlStep::Advanced(
                ConsumptionAdvance::Committed(success),
            )),
            ControlConsumptionCommitOutcome::Recovered(success) => Ok(ControlStep::Advanced(
                ConsumptionAdvance::Recovered(success),
            )),
            ControlConsumptionCommitOutcome::Finalized(receipt) => {
                if receipt.submission_id() != submission_id
                    || receipt.phase() != ControlWorkPhase::Consume
                {
                    return Err(ControlWorkerError::ClaimOutcomeMismatch);
                }
                Ok(ControlStep::CommitFinalized(
                    CommitFinalization::from_receipt(&receipt),
                ))
            }
            ControlConsumptionCommitOutcome::OutcomeUnknown {
                submission_id: observed,
            } => {
                if observed != submission_id {
                    return Err(ControlWorkerError::ClaimOutcomeMismatch);
                }
                Ok(ControlStep::CommitOutcomeUnknown {
                    facts: CommitAmbiguity {
                        submission_id,
                        phase: ControlWorkPhase::Consume,
                    },
                    recovery: ClaimRecovery::from_request(request),
                })
            }
        }
    }
}

/// Read-only status helper kept separate from the role workers. It returns
/// only the inert state projection and cannot claim or advance work.
///
/// # Errors
///
/// Returns [`StateError`] when the receipt does not exist in the exact scope or
/// its durable projection is malformed.
pub fn control_status<S: ControlPlaneState>(
    state: &S,
    scope: &Scope,
    receipt_id: Uuid,
) -> Result<ControlStatusSnapshot, StateError> {
    state.control_status(scope, receipt_id)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicI64, Ordering};

    use accordlock_ingress::{
        ActivatedIngressRegistry, INGRESS_SCHEMA_VERSION, IngressAuthenticator, IngressClaims,
        IngressKeyStatus, IngressRecoveryProbe, MemoryReplayGuard, RegisteredIngressKey,
        StaticallyVerifiedIngressSubmission, sign_ingress_request,
    };
    use accordlock_kernel::{ActivatedAttesterRegistry, sign_evaluation};
    use accordlock_protocol::{
        AgentProposal, AttesterScope, AttesterStatus, AuthorityDomainState, AuthorityVector,
        CapabilityGrant, DeploymentTemplate, Digest32, DispatchDeadlinePolicy,
        EVALUATION_ATTESTATION_SCHEMA_VERSION, EvaluationAttestation, ReasonCode,
        RegisteredAttester, authorization_signer_root, canonical_hash, evaluator_verifier_root,
    };
    use accordlock_state::{
        ClaimedControlWork, ControlDecisionReason, ControlOutcome, ControlStatusCode,
        ControlSubmissionIntakeOutcome, GrantRegistration, InMemoryStore, TrustedClock,
    };

    use super::*;

    #[derive(Debug)]
    struct TestClock(AtomicI64);

    impl TestClock {
        fn new(now: i64) -> Self {
            Self(AtomicI64::new(now))
        }
    }

    impl TrustedClock for TestClock {
        fn now_unix_seconds(&self) -> Result<i64, StateError> {
            Ok(self.0.load(Ordering::SeqCst))
        }
    }

    struct Fixture {
        store: InMemoryStore,
        scope: Scope,
        proposal: AgentProposal,
        policy: PolicyConfig,
        authority: AuthorityVector,
        grant: CapabilityGrant,
        evaluator: SigningIdentity,
        ingress_signer: SigningIdentity,
    }

    impl Fixture {
        fn new() -> Self {
            let store = InMemoryStore::with_clock(Arc::new(TestClock::new(100)));
            let scope = Scope::new("acme", "prod").unwrap();
            let proposal = AgentProposal {
                schema_version: 1,
                request_id: Uuid::from_u128(0x101),
                tenant: scope.tenant.clone(),
                actor: "workload:release".to_owned(),
                template: template("accordlock-executor:prod"),
            };
            let policy = policy(&proposal);
            let grant = CapabilityGrant {
                grant_id: Uuid::from_u128(0x201),
                holder: proposal.actor.clone(),
                tenant: proposal.tenant.clone(),
                operation: proposal.template.operation.clone(),
                repository: proposal.template.repository.clone(),
                audience: proposal.template.audience.clone(),
                cluster_identity: proposal.template.cluster_identity.clone(),
                namespace: proposal.template.namespace.clone(),
                deployment_uid: proposal.template.deployment_uid.clone(),
                container: proposal.template.container.clone(),
                image_repository: proposal.template.image_repository.clone(),
                not_before: 50,
                expires_at: 300,
                maximum_uses: 2,
            };
            let evaluator = SigningIdentity::from_seed("control-test-evaluator", [41; 32]);
            let authorization_signer =
                SigningIdentity::from_seed("control-test-authorization", [42; 32]);
            let ingress_signer = SigningIdentity::from_seed("control-test-ingress", [43; 32]);
            let mut authority = authority();
            authority.policy.root = canonical_hash(&policy).unwrap();
            authority.registry.root =
                ActivatedAttesterRegistry::compute_root(&attester_entries(&proposal)).unwrap();
            authority.grant_registry.root = canonical_hash(&grant).unwrap();
            authority.signer.root = authorization_signer_root(
                authorization_signer.key_id(),
                authorization_signer.public_key_bytes(),
            )
            .unwrap();
            authority.kernel_configuration.root =
                evaluator_verifier_root(evaluator.key_id(), evaluator.public_key_bytes()).unwrap();
            authority.principal_registry.root = ActivatedIngressRegistry::compute_root(
                &proposal.template.audience,
                120,
                &[ingress_registration(&proposal, &ingress_signer)],
            )
            .unwrap();
            store
                .compare_and_activate_authority(&scope, None, &authority)
                .unwrap();
            store
                .register_grant(&GrantRegistration {
                    environment: scope.environment.clone(),
                    grant: grant.clone(),
                    authority: authority.clone(),
                    dispatch_deadline_policy: DispatchDeadlinePolicy {
                        max_dispatch_delay_seconds: 30,
                        profile_hard_cap: 200,
                        immutable_dependency_expiries: vec![190],
                    },
                })
                .unwrap();
            Self {
                store,
                scope,
                proposal,
                policy,
                authority,
                grant,
                evaluator,
                ingress_signer,
            }
        }

        fn verified_submission(&self, nonce: u128) -> StaticallyVerifiedIngressSubmission {
            let registry = ActivatedIngressRegistry::new(
                self.authority.principal_registry.clone(),
                self.proposal.template.audience.clone(),
                120,
                vec![ingress_registration(&self.proposal, &self.ingress_signer)],
            )
            .unwrap();
            let authenticator =
                IngressAuthenticator::new(registry, MemoryReplayGuard::default()).unwrap();
            let claims = IngressClaims {
                schema_version: INGRESS_SCHEMA_VERSION,
                audience: self.proposal.template.audience.clone(),
                issued_at: 99,
                expires_at: 180,
                nonce: Uuid::from_u128(nonce),
                proposal: self.proposal.clone(),
            };
            let wire =
                serde_json::to_vec(&sign_ingress_request(claims, &self.ingress_signer).unwrap())
                    .unwrap();
            let probe = IngressRecoveryProbe::parse_bytes(&wire).unwrap();
            authenticator.verify_durable_static(probe).unwrap()
        }

        fn accept(&self, nonce: u128) -> Uuid {
            match self
                .store
                .accept_control_submission_or_recover(self.verified_submission(nonce))
                .unwrap()
            {
                ControlSubmissionIntakeOutcome::Fresh(receipt) => receipt.receipt_id(),
                other => panic!("expected fresh intake, got {other:?}"),
            }
        }

        fn prepare_issue_queue(&self, nonce: u128) -> Uuid {
            let receipt_id = self.accept(nonce);
            let claim = ControlWorkClaimRequest::new(
                "fixture-evaluator",
                ControlWorkerRole::Evaluator,
                Uuid::from_u128(nonce + 1),
            )
            .unwrap();
            let work = match self
                .store
                .claim_next_control_work_or_recover(&claim)
                .unwrap()
            {
                ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Evaluate(work)) => work,
                other => panic!("expected EVALUATE work, got {other:?}"),
            };
            let attestation = EvaluationAttestation {
                schema_version: EVALUATION_ATTESTATION_SCHEMA_VERSION,
                request_id: work.proposal().request_id,
                evaluation_nonce: work.evaluation_nonce(),
                tenant: work.proposal().tenant.clone(),
                actor: work.proposal().actor.clone(),
                evaluated_at: work.lease().claimed_at(),
                outcome: accordlock_protocol::DecisionOutcome::Allow,
                reasons: vec![ReasonCode::Allowed],
                template_hash: canonical_hash(&work.proposal().template).unwrap(),
                evidence_root: digest("evidence"),
                principals: vec!["principal:review".to_owned()],
                policy_root: self.authority.policy.root,
                authority: self.authority.clone(),
                consume_before: 160,
            };
            let signed = sign_evaluation(attestation, &self.evaluator).unwrap();
            let decision = self
                .store
                .record_control_evaluation(work, &signed, &self.evaluator.verifier())
                .unwrap();
            assert_eq!(decision.selected_grant_id(), Some(self.grant.grant_id));
            receipt_id
        }
    }

    fn ingress_registration(
        proposal: &AgentProposal,
        signer: &SigningIdentity,
    ) -> RegisteredIngressKey {
        RegisteredIngressKey {
            key_id: signer.key_id().to_owned(),
            public_key: signer.public_key_bytes(),
            tenant: proposal.tenant.clone(),
            actor: proposal.actor.clone(),
            allowed_audiences: BTreeSet::from([proposal.template.audience.clone()]),
            not_before: 50,
            expires_at: 300,
            status: IngressKeyStatus::Active,
        }
    }

    fn attester_entries(proposal: &AgentProposal) -> Vec<RegisteredAttester> {
        let signer = SigningIdentity::from_seed("control-test-review", [44; 32]);
        vec![RegisteredAttester {
            tenant: proposal.tenant.clone(),
            environment: proposal.template.environment.clone(),
            issuer: signer.key_id().to_owned(),
            key_id: signer.key_id().to_owned(),
            public_key: signer.public_key_bytes(),
            principal_id: "principal:review".to_owned(),
            base_grade: 3,
            status: AttesterStatus::Active,
            scopes: vec![AttesterScope::Review {
                repository: proposal.template.repository.clone(),
            }],
        }]
    }

    fn digest(label: &str) -> Digest32 {
        Digest32::sha256(label.as_bytes())
    }

    fn domain(label: &str) -> AuthorityDomainState {
        AuthorityDomainState {
            root: digest(label),
            epoch: 1,
            activation_id: Uuid::new_v4(),
        }
    }

    fn authority() -> AuthorityVector {
        AuthorityVector {
            policy: domain("policy"),
            registry: domain("registry"),
            revocation: domain("revocation"),
            connector: domain("connector"),
            resource: domain("resource"),
            signer: domain("signer"),
            mediation: domain("mediation"),
            grant_registry: domain("grant-registry"),
            office_act_registry: domain("office"),
            principal_registry: domain("principal"),
            workload_build_allowlist: domain("build"),
            kernel_configuration: domain("kernel"),
        }
    }

    fn policy(proposal: &AgentProposal) -> PolicyConfig {
        PolicyConfig {
            policy_id: "deploy-prod-v1".to_owned(),
            allowed_actors: vec![proposal.actor.clone()],
            allowed_repositories: vec![proposal.template.repository.clone()],
            allowed_image_repositories: vec![proposal.template.image_repository.clone()],
            allowed_clusters: vec![proposal.template.cluster_identity.clone()],
            allowed_namespaces: vec![proposal.template.namespace.clone()],
            minimum_review_grade: 2,
            minimum_build_grade: 2,
            maximum_evidence_age_seconds: 60,
            maximum_authorization_lifetime_seconds: 60,
        }
    }

    fn template(audience: &str) -> DeploymentTemplate {
        DeploymentTemplate {
            operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
            environment: "prod".to_owned(),
            audience: audience.to_owned(),
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
            prior_transaction_annotation: None,
            prior_authorization_annotation: None,
            prior_operation_hash_annotation: None,
        }
    }

    #[test]
    fn worker_identity_is_canonical_and_role_fixed() {
        let evaluator = WorkerIdentity::new("eval-01", ControlWorkerRole::Evaluator).unwrap();
        let issuer = WorkerIdentity::new("issue-01", ControlWorkerRole::Issuer).unwrap();
        let consumer = WorkerIdentity::new("consume-01", ControlWorkerRole::Consumer).unwrap();

        assert_eq!(evaluator.phase(), ControlWorkPhase::Evaluate);
        assert_eq!(issuer.phase(), ControlWorkPhase::Issue);
        assert_eq!(consumer.phase(), ControlWorkPhase::Consume);
        assert!(WorkerIdentity::new(" BAD ", ControlWorkerRole::Evaluator).is_err());
        assert!(WorkerIdentity::new("", ControlWorkerRole::Issuer).is_err());
    }

    #[test]
    fn fresh_claim_identity_is_created_inside_the_worker() {
        let identity = WorkerIdentity::new("eval-01", ControlWorkerRole::Evaluator).unwrap();
        let first = identity.begin_attempt();
        let second = identity.begin_attempt();

        assert_eq!(first.worker_id, "eval-01");
        assert_eq!(first.role, ControlWorkerRole::Evaluator);
        assert!(!first.claim_id.is_nil());
        assert_ne!(first.claim_id, second.claim_id);
    }

    #[test]
    fn opaque_recovery_cannot_cross_worker_roles() {
        let evaluator = WorkerIdentity::new("eval-01", ControlWorkerRole::Evaluator).unwrap();
        let issuer = WorkerIdentity::new("issue-01", ControlWorkerRole::Issuer).unwrap();
        let attempt = evaluator.begin_attempt();
        let request = evaluator.attempt_request(&attempt).unwrap();
        let raw_claim_id = request.claim_id().to_string();
        let recovery = ClaimRecovery::from_request(&request);

        assert!(evaluator.recovery_request(&recovery).is_ok());
        assert!(issuer.recovery_request(&recovery).is_err());
        assert!(!format!("{recovery:?}").contains(&raw_claim_id));
    }

    #[test]
    fn evaluator_exactly_recovers_precommit_crash_and_postcommit_retry() {
        let evaluation_fixture = Fixture::new();
        evaluation_fixture.accept(0x5300);
        let registry = ActivatedAttesterRegistry::new(
            evaluation_fixture.authority.registry.clone(),
            attester_entries(&evaluation_fixture.proposal),
        )
        .unwrap();
        let evaluation_worker = EvaluatorWorker::new(
            evaluation_fixture.store.clone(),
            "evaluator-recovery",
            evaluation_fixture.policy.clone(),
            registry,
            SigningIdentity::from_seed("control-test-evaluator", [41; 32]),
        )
        .unwrap();
        let evidence = TrustedEvidenceSet {
            request_id: evaluation_fixture.proposal.request_id,
            evidence: Vec::new(),
        };
        let evaluation_attempt = evaluation_worker.begin_attempt();
        let evaluation_request = evaluation_worker
            .identity
            .attempt_request(&evaluation_attempt)
            .unwrap();
        let abandoned_evaluation = claim(
            &evaluation_worker.state,
            &evaluation_worker.identity,
            &evaluation_request,
        )
        .unwrap();
        assert!(matches!(
            &abandoned_evaluation,
            ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Evaluate(_))
        ));
        drop(abandoned_evaluation);
        assert!(matches!(
            evaluation_worker
                .run_once(&evaluation_attempt, &evidence)
                .unwrap(),
            ControlStep::Advanced(_)
        ));
        let evaluation_history = evaluation_worker
            .run_once(&evaluation_attempt, &evidence)
            .unwrap();
        assert!(matches!(
            evaluation_history,
            ControlStep::PhaseCompleted(receipt)
                if receipt.phase() == ControlWorkPhase::Evaluate
                    && receipt.worker_id() == "evaluator-recovery"
        ));
    }

    #[test]
    fn issuer_and_consumer_exactly_recover_crash_and_postcommit_retry() {
        let execution_fixture = Fixture::new();
        execution_fixture.prepare_issue_queue(0x5400);
        let issue_worker = IssuerWorker::new(
            execution_fixture.store.clone(),
            "issuer-recovery",
            execution_fixture.evaluator.verifier(),
            SigningIdentity::from_seed("control-test-authorization", [42; 32]),
        )
        .unwrap();
        let issue_attempt = issue_worker.begin_attempt();
        let issue_request = issue_worker
            .identity
            .attempt_request(&issue_attempt)
            .unwrap();
        let abandoned_issue =
            claim(&issue_worker.state, &issue_worker.identity, &issue_request).unwrap();
        assert!(matches!(
            &abandoned_issue,
            ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Issue(_))
        ));
        drop(abandoned_issue);
        assert!(matches!(
            issue_worker.run_once(&issue_attempt).unwrap(),
            ControlStep::Advanced(_)
        ));
        let issue_history = issue_worker.run_once(&issue_attempt).unwrap();
        assert!(matches!(
            issue_history,
            ControlStep::PhaseCompleted(receipt)
                if receipt.phase() == ControlWorkPhase::Issue
                    && receipt.worker_id() == "issuer-recovery"
        ));

        let consume_worker =
            ConsumerWorker::new(execution_fixture.store.clone(), "consumer-recovery").unwrap();
        let consume_attempt = consume_worker.begin_attempt();
        let consume_request = consume_worker
            .identity
            .attempt_request(&consume_attempt)
            .unwrap();
        let abandoned_consume = claim(
            &consume_worker.state,
            &consume_worker.identity,
            &consume_request,
        )
        .unwrap();
        assert!(matches!(
            &abandoned_consume,
            ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Consume(_))
        ));
        drop(abandoned_consume);
        assert!(matches!(
            consume_worker.run_once(&consume_attempt).unwrap(),
            ControlStep::Advanced(ConsumptionAdvance::Committed(_))
        ));
        let consume_history = consume_worker.run_once(&consume_attempt).unwrap();
        assert!(matches!(
            consume_history,
            ControlStep::PhaseCompleted(receipt)
                if receipt.phase() == ControlWorkPhase::Consume
                    && receipt.worker_id() == "consumer-recovery"
                    && receipt.consume_key().is_some()
        ));
    }

    #[test]
    fn evaluator_worker_commits_a_deny_without_exporting_signed_material() {
        let fixture = Fixture::new();
        let receipt_id = fixture.accept(0x5100);
        let registry = ActivatedAttesterRegistry::new(
            fixture.authority.registry.clone(),
            attester_entries(&fixture.proposal),
        )
        .unwrap();
        let worker = EvaluatorWorker::new(
            fixture.store.clone(),
            "evaluator-loop",
            fixture.policy.clone(),
            registry,
            SigningIdentity::from_seed("control-test-evaluator", [41; 32]),
        )
        .unwrap();
        let evidence = TrustedEvidenceSet {
            request_id: fixture.proposal.request_id,
            evidence: Vec::new(),
        };

        let attempt = worker.begin_attempt();
        let result = worker.run_once(&attempt, &evidence).unwrap();
        let ControlStep::Advanced(advance) = result else {
            panic!("expected a committed deny decision");
        };
        assert_eq!(advance.decision().control_outcome(), ControlOutcome::Deny);
        assert_eq!(
            advance.decision().reason(),
            ControlDecisionReason::KernelDeny
        );
        assert_eq!(
            control_status(&fixture.store, &fixture.scope, receipt_id)
                .unwrap()
                .status(),
            ControlStatusCode::ControlDenied
        );
        let next_attempt = worker.begin_attempt();
        assert!(matches!(
            worker.run_once(&next_attempt, &evidence),
            Ok(ControlStep::NoWork)
        ));
    }

    #[test]
    fn issuer_and_consumer_workers_complete_the_exact_durable_lineage() {
        let fixture = Fixture::new();
        let receipt_id = fixture.prepare_issue_queue(0x5200);
        let issue_worker = IssuerWorker::new(
            fixture.store.clone(),
            "issuer-loop",
            fixture.evaluator.verifier(),
            SigningIdentity::from_seed("control-test-authorization", [42; 32]),
        )
        .unwrap();

        let issue_attempt = issue_worker.begin_attempt();
        let issue_result = issue_worker.run_once(&issue_attempt).unwrap();
        let ControlStep::Advanced(issuance_advance) = issue_result else {
            panic!("expected deterministic issuance");
        };
        assert!(!issuance_advance.submission_id().is_nil());
        assert_eq!(
            control_status(&fixture.store, &fixture.scope, receipt_id)
                .unwrap()
                .status(),
            ControlStatusCode::AuthorizationIssued
        );

        let consume_worker = ConsumerWorker::new(fixture.store.clone(), "consumer-loop").unwrap();
        let consume_attempt = consume_worker.begin_attempt();
        let consume_result = consume_worker.run_once(&consume_attempt).unwrap();
        let ControlStep::Advanced(ConsumptionAdvance::Committed(consume_success)) = consume_result
        else {
            panic!("expected atomic consume and outbox commit");
        };
        assert_eq!(
            consume_success.issued().transaction_id,
            consume_success.receipt().transaction_id
        );
        assert_eq!(
            consume_success
                .issued()
                .signed_authorization
                .authorization
                .authorization_id,
            consume_success.receipt().authorization_id
        );
        assert_eq!(
            control_status(&fixture.store, &fixture.scope, receipt_id)
                .unwrap()
                .status(),
            ControlStatusCode::DispatchPending
        );
        let next_attempt = consume_worker.begin_attempt();
        assert!(matches!(
            consume_worker.run_once(&next_attempt),
            Ok(ControlStep::NoWork)
        ));
    }
}
