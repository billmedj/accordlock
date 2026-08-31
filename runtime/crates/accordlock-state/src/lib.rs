//! Transactional state for authorization issuance and single-use consumption.
//!
//! Consumption is intentionally identifier-only. The adapter reloads the
//! issued authorization, grant, active authority vector, deadline inputs, and trusted
//! time from its own state. An API caller therefore has no field through which
//! to replace authority or widen a deadline at consumption time.

mod acquisition;
mod broker;
mod control;
mod eks_registry;
mod ingress_replay;
mod memory;
mod model;
mod postgres;
mod terminal;

pub(crate) mod sealed {
    pub trait Sealed {}
}

pub use accordlock_protocol::DispatchDeadlinePolicy;
pub use acquisition::{
    DISPATCH_ACQUISITION_LEASE_SECONDS, DispatchAcquisitionAuthority,
    DispatchAcquisitionDisposition, DispatchAcquisitionOutcome, DispatchAcquisitionReceipt,
    DispatchAcquisitionRecoveryKey, DispatchAcquisitionRequest, DispatchQueueDispositionReason,
    DispatchQueueDispositionReceipt, DispatchRecoveryWork, DispatchWork,
};
pub use broker::{
    AcquiredBrokerOperationRequest, AuthenticatedDispatchCredentialReview, BrokerCleanupRequest,
    BrokerCredentialSafetyPolicy, BrokerIoAuthority, BrokerJournalCapability,
    BrokerJournalOperation, BrokerJournalOutcome, BrokerJournalPhase, BrokerJournalSelector,
    BrokerJournalState, BrokerOperationAudit, BrokerOperationIntent, BrokerOperationReceipt,
    BrokerOperationRequest, BrokerReconciliationAuthority, BrokerReconciliationRequest,
    BrokerReconciliationResult, BrokerSecretObservation, BrokerTokenIssueObservation,
    CredentialReviewIoAuthority, DispatchBrokerRestartAction, DispatchBrokerRestartContext,
    DispatchCredentialReviewAudit, DispatchCredentialReviewClaims, DispatchCredentialReviewPhase,
    DispatchCredentialReviewRecoveryKey, DispatchRestartDeletionEvidence,
    RejectedDispatchCredentialReview, ReviewedDispatchCredential,
};
pub use control::{
    CONTROL_WORK_LEASE_SECONDS, ClaimedControlWork, ControlConsumptionCommitOutcome,
    ControlConsumptionWork, ControlDecisionReason, ControlDecisionReceipt, ControlEvaluationWork,
    ControlIssuanceCommitOutcome, ControlIssuanceWork, ControlKernelOutcome, ControlOutcome,
    ControlPhaseCompletionReceipt, ControlPlaneState, ControlStatusCode, ControlStatusReason,
    ControlStatusSnapshot, ControlSubmissionIntakeOutcome, ControlSubmissionReceipt,
    ControlSubmissionRecoveryKey, ControlWorkClaimOutcome, ControlWorkClaimRecoveryKey,
    ControlWorkClaimRequest, ControlWorkFinalizationReason, ControlWorkFinalizationReceipt,
    ControlWorkLease, ControlWorkPhase, ControlWorkerRole, RecoveredSubmissionRef,
};
pub use eks_registry::{
    CurrentEksAttempt, EksAttemptFacts, EksDestinationProfile, EksDestinationRegistryState,
    EksRegistryError, FrozenEksAttempt,
};
pub use ingress_replay::{
    IngressNonceConsumption, IngressReplayDecision, IngressReplayScope, IngressReplayState,
    MAX_INGRESS_REPLAY_GC_BATCH, MAX_INGRESS_REPLAY_SCOPE_BYTES,
};
pub use memory::{InMemoryStore, SystemClock, TrustedClock};
pub use model::{
    AdmissionAuthorization, AdmissionAuthorizationRequest, AdmissionContext, AttemptInFlight,
    ClaimedDispatch, ConsumeKey, ConsumeSuccess, DISPATCH_CLAIM_LEASE_SECONDS,
    DispatchAttemptAcquisition, DispatchClaimRequest, DispatchClaimToken,
    DispatchCredentialBinding, DispatchRecoveryAcquisition, DispatchSnapshot, GrantRegistration,
    GrantSnapshot, IssuanceSnapshot, IssuedAuthorizationRecord, OutboxEntry, OutboxStatus,
    PhysicalResourceKey, RecoveryNoSendReceipt, RecoveryNoSendRetirementOutcome,
    RecoveryNoSendRetirementReceipt, Scope, StateError, TransactionalState,
    compute_dispatch_deadline, grant_revocation_root,
};
pub use postgres::{PostgresStore, TlsPostgresConfig, TlsPostgresConfigError, TlsPostgresStore};
pub use terminal::{
    TerminalRetirementAudit, TerminalRetirementContext, TerminalRetirementReceipt,
    TerminalRetirementRequest, TerminalRetirementState, TerminalWitnessRegistryReceipt,
};
