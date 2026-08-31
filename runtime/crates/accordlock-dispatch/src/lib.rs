//! Deterministic reference machine for post-consumption dispatch safety.
//!
//! The in-memory machine performs no network, Kubernetes, or credential
//! operation. The bridge delegates claim and attempt linearization to a
//! `accordlock-state` adapter and derives Kubernetes request commitments, but it
//! still performs no provider call.

mod bridge;
mod machine;
mod model;

pub use bridge::{
    AuthorizedProviderAttempt, BridgeError, DispatchImport, RecoveredAttemptCommit,
    authority_version_from_vector,
};
pub use machine::DispatchMachine;
pub use model::{
    AuthenticatedObserver, AuthorityVersion, BoundObjectObservation, ConsumptionBinding,
    CredentialClaims, CredentialInvalidationEvidence, CredentialProfile, DispatchBounds,
    DispatchClaim, DispatchError, EffectBinding, EffectEvidenceSnapshot, EffectTemplate,
    ExactEffectEvidence, LifecyclePhase, LogicalOwner, NonIssuanceEvidence, PhysicalResourceId,
    PreparedExecution, ProviderOutcome, ReconciliationOutcome,
};

#[cfg(test)]
#[path = "../tests/lifecycle.rs"]
mod lifecycle_tests;

#[cfg(test)]
#[path = "../tests/phase_b_recovery.rs"]
mod phase_b_recovery_tests;
