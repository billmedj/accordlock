//! Single public EKS enforcement path from a durable dispatch claim to one
//! native provider attempt.
//!
//! Request-facing data is limited to [`DispatchAcquisitionRequest`]. All effect and
//! credential authority is fixed at trusted bootstrap or reloaded from state.
//!
//! Raw journal observations are inert without the unique store-bound
//! capability held privately by [`EksEnforcement`]. In particular, omitting
//! that trusted-bootstrap object cannot start productive broker I/O. Issuing
//! it is itself part of the explicitly trusted bootstrap/DB-credential TCB:
//!
//! ```compile_fail
//! # use accordlock_state::{
//! #     AcquiredBrokerOperationRequest, BrokerJournalState,
//! #     DispatchAcquisitionAuthority,
//! # };
//! # fn forged_begin<S: BrokerJournalState>(
//! #     state: &S,
//! #     acquisition: &DispatchAcquisitionAuthority,
//! #     request: AcquiredBrokerOperationRequest,
//! # ) {
//! state.begin_broker_operation_for_acquisition(acquisition, request);
//! # }
//! ```

use std::fmt;

use accordlock_dispatch::{
    AuthorizedProviderAttempt, BoundObjectObservation, BridgeError, DispatchMachine, EffectBinding,
    ExactEffectEvidence, PreparedExecution, ProviderOutcome,
};
use accordlock_eks_broker::{
    AttemptAuthoritySource, AttemptLookup, BoundSecret, BrokerConfig, BrokerConfigError,
    BrokerFailure, BrokerOperation as EksBrokerOperation, DeletionEvidence, EksCredentialBroker,
    JournaledIssuedToken, JournaledSecretReconciliation, ManagementCredentialSource,
    RetirementAssessment, StateBackedAttemptAuthority, TokenRejectionEvidence, TokenReviewResult,
};
use accordlock_eks_profile::{EksRouteProfile, RouteField};
use accordlock_executor::{
    EksExecutionInput, ExclusiveBearer, ExclusiveEksExecutor, ExecutorError, NativeEksTransport,
    TrustedClock,
};
use accordlock_protocol::DeploymentTemplate;
use accordlock_state::{
    AcquiredBrokerOperationRequest, BrokerCleanupRequest, BrokerCredentialSafetyPolicy,
    BrokerJournalCapability, BrokerJournalOperation, BrokerJournalOutcome, BrokerJournalPhase,
    BrokerJournalState, BrokerOperationAudit, BrokerReconciliationRequest, ConsumeKey,
    DispatchAcquisitionAuthority, DispatchAcquisitionDisposition, DispatchAcquisitionOutcome,
    DispatchAcquisitionRecoveryKey, DispatchAcquisitionRequest, DispatchBrokerRestartAction,
    DispatchBrokerRestartContext, DispatchRestartDeletionEvidence, EksDestinationRegistryState,
    RecoveryNoSendRetirementOutcome, ReviewedDispatchCredential, Scope, StateError,
    TransactionalState,
};
use uuid::Uuid;

/// Exact stage at which automatic progress stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnforcementStage {
    AdmissionCredentialBinding,
    DurableBrokerLifecycle,
    Claim,
    StateTemplate,
    Prepare,
    SecretCreate,
    SecretReconcile,
    CredentialIssue,
    TokenReview,
    CredentialRecord,
    AttemptCommit,
    ProviderEffect,
}

/// Cross-crate proof boundary that is not yet available to production.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnforcementReadinessBlocker {
    /// Three operation-bound identities exist in code, but their exact live
    /// effective-RBAC closures and credential separation have not yet been
    /// witnessed on the activated cluster.
    ManagementRbacLiveProof,
    /// Server TLS authenticates the webhook to Kubernetes, but the deployed
    /// webhook still lacks an environment-proven origin boundary for callers.
    AuthenticatedWebhookCallerBoundary,
    /// The configured token audience has not yet been proved against the exact
    /// live Kubernetes API endpoint used for the provider request.
    KubernetesApiAudienceLiveProof,
}

impl EnforcementReadinessBlocker {
    /// Stable machine-readable code for public readiness reports.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ManagementRbacLiveProof => "MANAGEMENT_RBAC_LIVE_PROOF",
            Self::AuthenticatedWebhookCallerBoundary => "AUTHENTICATED_WEBHOOK_CALLER_BOUNDARY",
            Self::KubernetesApiAudienceLiveProof => "KUBERNETES_API_AUDIENCE_LIVE_PROOF",
        }
    }
}

/// Live deployment proofs that must exist before productive EKS enforcement
/// can be enabled.
///
/// This list is intentionally exported for diagnostics only. It is not a
/// readiness switch: [`EksEnforcement::execute`] remains fail-closed and no
/// public API can construct the private proof required by the mechanical path.
#[must_use]
pub const fn production_readiness_blockers() -> [EnforcementReadinessBlocker; 3] {
    [
        EnforcementReadinessBlocker::ManagementRbacLiveProof,
        EnforcementReadinessBlocker::AuthenticatedWebhookCallerBoundary,
        EnforcementReadinessBlocker::KubernetesApiAudienceLiveProof,
    ]
}

/// Coarse, non-secret failure classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuarantineReason {
    Rejected,
    DefinitelyNotSent,
    OutcomeUnknown,
    AuthorityUnavailable,
    TrustedTimeUnavailable,
    InternalInvariant,
}

/// State of the one bound credential after cleanup was attempted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialRetirement {
    Confirmed,
    Pending { safe_after: i64 },
    Unknown,
}

/// Complete non-secret result of one enforcement call.
///
/// No variant contains a bearer, caller-selected provider request, or a value
/// that can reconstruct one-shot execution authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnforcementOutcome {
    /// Production is disabled before any external operation because required
    /// live deployment proofs do not yet exist.
    ReadinessBlocked {
        acquisition_id: Uuid,
        blockers: [EnforcementReadinessBlocker; 3],
    },
    /// No eligible state-selected work exists for the configured scope.
    NoWork { acquisition_id: Uuid },
    /// Exact retry history exists but can no longer mint authority.
    AcquisitionInert {
        acquisition_id: Uuid,
        disposition: DispatchAcquisitionDisposition,
    },
    /// The server disposed an irrecoverably stale queue item.
    QueueDisposed { acquisition_id: Uuid },
    /// The acquisition commit result could not be proved either way.
    AcquisitionOutcomeUnknown { acquisition_id: Uuid },
    /// The exact provider effect was verified. `lifecycle_recorded` reports
    /// whether the process-local machine accepted the same evidence.
    EffectEstablished {
        transaction_id: Uuid,
        lifecycle_recorded: bool,
        retirement: CredentialRetirement,
    },
    /// Automatic progress stopped and no mutation retry is authorized.
    Quarantined {
        transaction_id: Uuid,
        stage: EnforcementStage,
        reason: QuarantineReason,
        conservative_safe_after: Option<i64>,
        retirement: CredentialRetirement,
    },
}

/// Production-only composition of transactional state, the fixed EKS broker,
/// and the exclusive native EKS executor.
///
/// The generic parameters are trusted bootstrap adapters, not request-facing
/// provider selection. The public execution method remains fixed to EKS.
pub struct EksEnforcement<S, M, BC, T, EC, OC> {
    route_profile: EksRouteProfile,
    scope: Scope,
    state: S,
    broker_journal_capability: BrokerJournalCapability,
    machine: DispatchMachine,
    broker: EksCredentialBroker<StateBackedAttemptAuthority<S>, M, BC>,
    executor: ExclusiveEksExecutor<T, EC>,
    orchestration_clock: OC,
}

/// Deliberately uninhabited compile anchor for the private mechanical path.
///
/// The public API cannot construct, name, or obtain this value. Keeping the
/// type empty prevents dormant code from becoming an accidental readiness
/// switch while the three live proofs remain outstanding.
#[derive(Debug)]
enum VerifiedLiveDeploymentBoundaries {}

/// Trusted-bootstrap route mismatch. Construction fails before any Secret or
/// provider operation can begin.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum EnforcementConfigError {
    #[error("tenant/environment scope is invalid")]
    InvalidScope,
    #[error("fixed EKS broker configuration is invalid")]
    BrokerConfig(#[source] BrokerConfigError),
    #[error("broker route differs from the orchestrator route at {0:?}")]
    BrokerRouteMismatch(RouteField),
    #[error("executor route differs from the orchestrator route at {0:?}")]
    ExecutorRouteMismatch(RouteField),
    #[error("broker and executor EKS credential lifecycle policies differ")]
    CredentialLifecyclePolicyMismatch,
    #[error("durable broker journal capability is unavailable")]
    BrokerJournalCapabilityUnavailable,
}

fn validate_unified_route(
    orchestrator: &EksRouteProfile,
    broker: &EksRouteProfile,
    executor: &EksRouteProfile,
) -> Result<(), EnforcementConfigError> {
    if let Some(field) = orchestrator.first_mismatch(broker) {
        return Err(EnforcementConfigError::BrokerRouteMismatch(field));
    }
    if let Some(field) = orchestrator.first_mismatch(executor) {
        return Err(EnforcementConfigError::ExecutorRouteMismatch(field));
    }
    Ok(())
}

impl<S, M, BC, T, EC, OC> fmt::Debug for EksEnforcement<S, M, BC, T, EC, OC> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EksEnforcement")
            .field("route_profile", &self.route_profile)
            .field("scope", &self.scope)
            .field("state", &"[TRANSACTIONAL STATE]")
            .field("machine", &"[PROCESS-LOCAL DISPATCH MACHINE]")
            .field("broker", &"[FIXED EKS CREDENTIAL BROKER]")
            .field("executor", &"[EXCLUSIVE NATIVE EKS EXECUTOR]")
            .field("orchestration_clock", &"[TRUSTED CLOCK]")
            // The store-bound broker journal capability is deliberately
            // omitted; even its presence is bootstrap-internal state.
            .finish_non_exhaustive()
    }
}

impl<S, M, BC, T, EC, OC> EksEnforcement<S, M, BC, T, EC, OC>
where
    S: BrokerJournalState + EksDestinationRegistryState + Clone,
    M: ManagementCredentialSource,
    BC: TrustedClock,
    T: NativeEksTransport,
    EC: TrustedClock,
    OC: TrustedClock,
{
    /// Installs already-validated trusted bootstrap dependencies and composes
    /// the broker with the same durable state handle used by orchestration.
    ///
    /// Destination registration and authority activation must already exist in
    /// `state` and `machine`. The broker authority is always a
    /// [`StateBackedAttemptAuthority`] fixed to `scope`; callers cannot inject
    /// a volatile [`AttemptAuthoritySource`]. The complete EKS credential
    /// lifecycle tuple is compared across broker and executor at bootstrap and
    /// again from rooted current facts before provider I/O.
    ///
    /// # Errors
    ///
    /// Returns [`EnforcementConfigError`] for an invalid scope or broker
    /// configuration, or when the broker or executor differs from the
    /// orchestrator's complete EKS route. Broker errors are deliberately
    /// coarse and contain no credential or endpoint material.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        route_profile: EksRouteProfile,
        scope: Scope,
        mut state: S,
        machine: DispatchMachine,
        broker_config: BrokerConfig,
        management_credentials: M,
        broker_clock: BC,
        executor: ExclusiveEksExecutor<T, EC>,
        orchestration_clock: OC,
    ) -> Result<Self, EnforcementConfigError> {
        Scope::new(scope.tenant.clone(), scope.environment.clone())
            .map_err(|_| EnforcementConfigError::InvalidScope)?;
        let authority = StateBackedAttemptAuthority::new(state.clone(), scope.clone());
        let broker = EksCredentialBroker::new(
            broker_config,
            authority,
            management_credentials,
            broker_clock,
        )
        .map_err(EnforcementConfigError::BrokerConfig)?;
        validate_unified_route(
            &route_profile,
            broker.route_profile(),
            executor.route_profile(),
        )?;
        let broker_policy = broker
            .credential_lifecycle_policy()
            .map_err(|_| EnforcementConfigError::CredentialLifecyclePolicyMismatch)?;
        if broker_policy != executor.credential_lifecycle_policy() {
            return Err(EnforcementConfigError::CredentialLifecyclePolicyMismatch);
        }
        // Issue the unique store-bound journal capability only after every
        // pure bootstrap validation succeeds. A bad route/config retry must
        // not burn the sole productive journal handle.
        let broker_journal_capability = state
            .issue_broker_journal_capability()
            .map_err(|_| EnforcementConfigError::BrokerJournalCapabilityUnavailable)?;
        Ok(Self {
            route_profile,
            scope,
            state,
            broker_journal_capability,
            machine,
            broker,
            executor,
            orchestration_clock,
        })
    }

    /// Fails closed until all three live deployment proofs are available.
    ///
    /// Durable attempt facts are now composed from the rooted destination
    /// registry. Live management-RBAC evidence, deployed webhook-caller
    /// authentication, and a live proof of the Kubernetes API audience remain
    /// mandatory. No public or dormant gate value can bypass them, so this
    /// entry point performs no broker or provider operation.
    pub fn execute(&mut self, request: &DispatchAcquisitionRequest) -> EnforcementOutcome {
        production_readiness_blocked(request.acquisition_id())
    }

    /// Keeps the fully composed mechanical path type-checked without exposing
    /// a constructible readiness switch. Safe Rust cannot call this method
    /// because [`VerifiedLiveDeploymentBoundaries`] is uninhabited.
    #[allow(dead_code)]
    fn execute_after_live_verification(
        &mut self,
        _verified: &VerifiedLiveDeploymentBoundaries,
        request: &DispatchAcquisitionRequest,
    ) -> EnforcementOutcome {
        run_enforcement(
            &self.state,
            &self.broker_journal_capability,
            &mut self.machine,
            &self.broker,
            &self.executor,
            &self.orchestration_clock,
            &self.scope,
            *self.route_profile.commitment().as_bytes(),
            request,
        )
    }
}

const fn production_readiness_blocked(acquisition_id: Uuid) -> EnforcementOutcome {
    EnforcementOutcome::ReadinessBlocked {
        acquisition_id,
        blockers: production_readiness_blockers(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PortFailureKind {
    Rejected,
    DefinitelyNotSent,
    OutcomeUnknown,
    Unavailable,
    Invalid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PortFailure {
    kind: PortFailureKind,
    conservative_safe_after: Option<i64>,
}

impl PortFailure {
    const fn new(kind: PortFailureKind) -> Self {
        Self {
            kind,
            conservative_safe_after: None,
        }
    }
}

struct JournaledPortValue<T> {
    value: T,
    audit: BrokerOperationAudit,
}

enum ReconciledSecret<S> {
    Matching(JournaledPortValue<S>),
    Absent(BrokerOperationAudit),
    Conflicting(BrokerOperationAudit),
}

enum ReviewedCredential<R> {
    Authenticated {
        reviewed: Box<ReviewedDispatchCredential>,
        bearer: ExclusiveBearer,
    },
    Rejected(R),
}

enum ObservedDeletion<D> {
    Present(BrokerOperationAudit),
    Absent(JournaledPortValue<D>),
    Conflicting(BrokerOperationAudit),
}

trait BrokerPort<S: BrokerJournalState> {
    type Secret: Clone;
    type Issued;
    type Rejection;
    type Deletion;

    fn create(
        &self,
        state: &S,
        journal_capability: &BrokerJournalCapability,
        acquisition: &DispatchAcquisitionAuthority,
        route_commitment: [u8; 32],
    ) -> Result<JournaledPortValue<Self::Secret>, PortFailure>;
    fn reconcile_create(
        &self,
        state: &S,
        journal_capability: &BrokerJournalCapability,
        request: BrokerReconciliationRequest,
    ) -> Result<ReconciledSecret<Self::Secret>, PortFailure>;
    fn prepared(secret: &Self::Secret) -> PreparedExecution;
    fn issue(
        &self,
        state: &S,
        journal_capability: &BrokerJournalCapability,
        acquisition: &DispatchAcquisitionAuthority,
        route_commitment: [u8; 32],
    ) -> Result<JournaledPortValue<Self::Issued>, PortFailure>;
    fn review(
        &self,
        state: &S,
        journal_capability: &BrokerJournalCapability,
        acquisition: &DispatchAcquisitionAuthority,
        issued: Self::Issued,
    ) -> Result<ReviewedCredential<Self::Rejection>, PortFailure>;
    fn delete(
        &self,
        state: &S,
        journal_capability: &BrokerJournalCapability,
        request: BrokerCleanupRequest,
    ) -> Result<BrokerOperationAudit, PortFailure>;
    fn verify_deleted(
        &self,
        state: &S,
        journal_capability: &BrokerJournalCapability,
        request: BrokerReconciliationRequest,
    ) -> Result<ObservedDeletion<Self::Deletion>, PortFailure>;
    fn retirement(&self, deletion: &Self::Deletion) -> Result<CredentialRetirement, PortFailure>;
    fn recovered_retirement(
        &self,
        evidence: &DispatchRestartDeletionEvidence,
    ) -> Result<CredentialRetirement, PortFailure>;
}

impl<S, A, M, C> BrokerPort<S> for EksCredentialBroker<A, M, C>
where
    S: BrokerJournalState,
    A: AttemptAuthoritySource,
    M: ManagementCredentialSource,
    C: TrustedClock,
{
    type Secret = BoundSecret;
    type Issued = JournaledIssuedToken;
    type Rejection = TokenRejectionEvidence;
    type Deletion = DeletionEvidence;

    fn create(
        &self,
        state: &S,
        journal_capability: &BrokerJournalCapability,
        acquisition: &DispatchAcquisitionAuthority,
        route_commitment: [u8; 32],
    ) -> Result<JournaledPortValue<Self::Secret>, PortFailure> {
        self.validate_acquisition_io_window(acquisition, EksBrokerOperation::CreateSecret)
            .map_err(|failure| map_broker_failure(&failure))?;
        let request = AcquiredBrokerOperationRequest::create(acquisition, route_commitment)
            .map_err(|error| map_state_failure(&error))?;
        let authority = state
            .begin_broker_operation_for_acquisition(journal_capability, acquisition, request)
            .map_err(|error| map_state_failure(&error))?;
        let created = self
            .create_bound_secret(state, acquisition, authority)
            .map_err(|failure| map_broker_failure(&failure))?;
        let (secret, receipt) = created.into_parts();
        Ok(JournaledPortValue {
            value: secret,
            audit: receipt.audit().clone(),
        })
    }

    fn reconcile_create(
        &self,
        state: &S,
        journal_capability: &BrokerJournalCapability,
        request: BrokerReconciliationRequest,
    ) -> Result<ReconciledSecret<Self::Secret>, PortFailure> {
        if request.operation() != BrokerJournalOperation::CreateSecret {
            return Err(PortFailure::new(PortFailureKind::Invalid));
        }
        let authority = state
            .begin_broker_reconciliation(journal_capability, &request)
            .map_err(|error| map_state_failure(&error))?;
        match self
            .reconcile_bound_secret(state, authority)
            .map_err(|failure| map_broker_failure(&failure))?
        {
            JournaledSecretReconciliation::CreateCommitted { secret, receipt } => {
                Ok(ReconciledSecret::Matching(JournaledPortValue {
                    value: *secret,
                    audit: receipt.audit().clone(),
                }))
            }
            JournaledSecretReconciliation::Pending { audit }
                if audit.last_reconciliation_outcome()
                    == Some(BrokerJournalOutcome::CreateAbsent) =>
            {
                Ok(ReconciledSecret::Absent(audit))
            }
            JournaledSecretReconciliation::Terminal { receipt }
                if receipt.audit().outcome() == Some(BrokerJournalOutcome::CreateConflicting) =>
            {
                Ok(ReconciledSecret::Conflicting(receipt.audit().clone()))
            }
            JournaledSecretReconciliation::DeleteCommitted { .. }
            | JournaledSecretReconciliation::Pending { .. }
            | JournaledSecretReconciliation::Terminal { .. } => {
                Err(PortFailure::new(PortFailureKind::Invalid))
            }
        }
    }

    fn prepared(secret: &Self::Secret) -> PreparedExecution {
        secret.prepared_execution()
    }

    fn issue(
        &self,
        state: &S,
        journal_capability: &BrokerJournalCapability,
        acquisition: &DispatchAcquisitionAuthority,
        route_commitment: [u8; 32],
    ) -> Result<JournaledPortValue<Self::Issued>, PortFailure> {
        self.validate_acquisition_io_window(acquisition, EksBrokerOperation::TokenRequest)
            .map_err(|failure| map_broker_failure(&failure))?;
        let (rooted_policy, _) = self
            .current_execution_profile(acquisition)
            .map_err(|failure| map_broker_failure(&failure))?;
        let policy = BrokerCredentialSafetyPolicy::new(
            rooted_policy.server_lifetime_hard_max_seconds(),
            rooted_policy.clock_uncertainty_seconds(),
        )
        .map_err(|error| map_state_failure(&error))?;
        let request =
            AcquiredBrokerOperationRequest::issue_token(acquisition, route_commitment, policy)
                .map_err(|error| map_state_failure(&error))?;
        let authority = state
            .begin_broker_operation_for_acquisition(journal_capability, acquisition, request)
            .map_err(|error| map_state_failure(&error))?;
        let issued = self
            .request_bound_token(state, acquisition, authority)
            .map_err(|failure| map_broker_failure(&failure))?;
        let audit = issued.receipt().audit().clone();
        Ok(JournaledPortValue {
            value: issued,
            audit,
        })
    }

    fn review(
        &self,
        state: &S,
        journal_capability: &BrokerJournalCapability,
        acquisition: &DispatchAcquisitionAuthority,
        issued: Self::Issued,
    ) -> Result<ReviewedCredential<Self::Rejection>, PortFailure> {
        match self.review_token(state, journal_capability, acquisition, issued) {
            Ok(TokenReviewResult::Authenticated(credential)) => {
                let (reviewed, bearer) = (*credential)
                    .into_dispatch_and_executor()
                    .map_err(|_| PortFailure::new(PortFailureKind::Invalid))?;
                Ok(ReviewedCredential::Authenticated {
                    reviewed: Box::new(reviewed),
                    bearer,
                })
            }
            Ok(TokenReviewResult::Rejected(evidence)) => Ok(ReviewedCredential::Rejected(evidence)),
            Err(error) => {
                let (failure, issued, recovery) = error.into_parts();
                let Some(recovery) = recovery else {
                    let mapped = map_broker_failure(&failure);
                    drop(issued);
                    return Err(mapped);
                };
                match self.recover_reviewed_token(state, acquisition, issued, recovery) {
                    Ok(credential) => {
                        let (reviewed, bearer) = credential
                            .into_dispatch_and_executor()
                            .map_err(|_| PortFailure::new(PortFailureKind::Invalid))?;
                        Ok(ReviewedCredential::Authenticated {
                            reviewed: Box::new(reviewed),
                            bearer,
                        })
                    }
                    Err(error) => {
                        let (failure, issued, _recovery) = error.into_parts();
                        let mapped = map_broker_failure(&failure);
                        drop(issued);
                        Err(mapped)
                    }
                }
            }
        }
    }

    fn delete(
        &self,
        state: &S,
        journal_capability: &BrokerJournalCapability,
        request: BrokerCleanupRequest,
    ) -> Result<BrokerOperationAudit, PortFailure> {
        let intent = state
            .prepare_broker_cleanup(journal_capability, &request)
            .map_err(|error| map_state_failure(&error))?;
        let authority = state
            .begin_broker_io(journal_capability, intent)
            .map_err(|error| map_state_failure(&error))?;
        self.delete_bound_secret(state, authority)
            .map(|acknowledged| acknowledged.into_parts().1)
            .map_err(|failure| map_broker_failure(&failure))
    }

    fn verify_deleted(
        &self,
        state: &S,
        journal_capability: &BrokerJournalCapability,
        request: BrokerReconciliationRequest,
    ) -> Result<ObservedDeletion<Self::Deletion>, PortFailure> {
        if request.operation() != BrokerJournalOperation::DeleteSecret {
            return Err(PortFailure::new(PortFailureKind::Invalid));
        }
        let authority = state
            .begin_broker_reconciliation(journal_capability, &request)
            .map_err(|error| map_state_failure(&error))?;
        match self
            .reconcile_bound_secret(state, authority)
            .map_err(|failure| map_broker_failure(&failure))?
        {
            JournaledSecretReconciliation::DeleteCommitted { deletion, receipt } => {
                Ok(ObservedDeletion::Absent(JournaledPortValue {
                    value: deletion,
                    audit: receipt.audit().clone(),
                }))
            }
            JournaledSecretReconciliation::Pending { audit }
                if audit.last_reconciliation_outcome()
                    == Some(BrokerJournalOutcome::DeletePresent) =>
            {
                Ok(ObservedDeletion::Present(audit))
            }
            JournaledSecretReconciliation::Terminal { receipt }
                if receipt.audit().outcome() == Some(BrokerJournalOutcome::DeleteConflicting) =>
            {
                Ok(ObservedDeletion::Conflicting(receipt.audit().clone()))
            }
            JournaledSecretReconciliation::CreateCommitted { .. }
            | JournaledSecretReconciliation::Pending { .. }
            | JournaledSecretReconciliation::Terminal { .. } => {
                Err(PortFailure::new(PortFailureKind::Invalid))
            }
        }
    }

    fn retirement(&self, deletion: &Self::Deletion) -> Result<CredentialRetirement, PortFailure> {
        match self
            .assess_retirement(deletion, None)
            .map_err(|failure| map_broker_failure(&failure))?
        {
            RetirementAssessment::Confirmed(_) => Ok(CredentialRetirement::Confirmed),
            RetirementAssessment::Pending { safe_after } => {
                Ok(CredentialRetirement::Pending { safe_after })
            }
        }
    }

    fn recovered_retirement(
        &self,
        evidence: &DispatchRestartDeletionEvidence,
    ) -> Result<CredentialRetirement, PortFailure> {
        match self
            .assess_recovered_retirement(evidence)
            .map_err(|failure| map_broker_failure(&failure))?
        {
            RetirementAssessment::Confirmed(_) => Ok(CredentialRetirement::Confirmed),
            RetirementAssessment::Pending { safe_after } => {
                Ok(CredentialRetirement::Pending { safe_after })
            }
        }
    }
}

fn map_broker_failure(failure: &BrokerFailure) -> PortFailure {
    match failure {
        BrokerFailure::DefinitelyNotSent { .. } => {
            PortFailure::new(PortFailureKind::DefinitelyNotSent)
        }
        BrokerFailure::OutcomeUnknown {
            conservative_credential_safe_after,
            ..
        } => PortFailure {
            kind: PortFailureKind::OutcomeUnknown,
            conservative_safe_after: *conservative_credential_safe_after,
        },
        BrokerFailure::ProviderRejected { .. } => PortFailure::new(PortFailureKind::Rejected),
        BrokerFailure::Authority(_) | BrokerFailure::CredentialSource(_) | BrokerFailure::Clock => {
            PortFailure::new(PortFailureKind::Unavailable)
        }
        BrokerFailure::RouteMismatch(_) | BrokerFailure::InvalidObservation { .. } => {
            PortFailure::new(PortFailureKind::Invalid)
        }
        BrokerFailure::JournalState => PortFailure::new(PortFailureKind::OutcomeUnknown),
    }
}

fn map_state_failure(failure: &StateError) -> PortFailure {
    match failure {
        StateError::BrokerOperationOutcomeUnknown
        | StateError::BrokerOperationInvalidTransition
        | StateError::BrokerTokenReissueForbidden
        | StateError::DispatchClaimOutcomeUnknown
        | StateError::DispatchAttemptOutcomeUnknown => {
            PortFailure::new(PortFailureKind::OutcomeUnknown)
        }
        StateError::Database(_)
        | StateError::RetryableConflict
        | StateError::RetryLimitExhausted => PortFailure::new(PortFailureKind::Unavailable),
        StateError::BrokerOperationMismatch
        | StateError::BrokerOperationNotFound
        | StateError::InvalidRecord(_)
        | StateError::SchemaMismatch(_) => PortFailure::new(PortFailureKind::Invalid),
        _ => PortFailure::new(PortFailureKind::Rejected),
    }
}

trait ExecutorPort {
    fn execute_once(
        &self,
        attempt: AuthorizedProviderAttempt,
        template: DeploymentTemplate,
        bearer: ExclusiveBearer,
    ) -> Result<ExactEffectEvidence, ExecutorError>;
}

impl<T, C> ExecutorPort for ExclusiveEksExecutor<T, C>
where
    T: NativeEksTransport,
    C: TrustedClock,
{
    fn execute_once(
        &self,
        attempt: AuthorizedProviderAttempt,
        template: DeploymentTemplate,
        bearer: ExclusiveBearer,
    ) -> Result<ExactEffectEvidence, ExecutorError> {
        let credential_lifecycle_policy = attempt.credential_lifecycle_policy();
        let destination_activation_commitment = attempt.destination_activation_commitment();
        self.execute(
            attempt,
            EksExecutionInput::new(
                template,
                bearer,
                credential_lifecycle_policy,
                destination_activation_commitment,
            ),
        )
        .map(accordlock_executor::EksEffectObservation::into_evidence)
    }
}

#[allow(
    clippy::manual_let_else,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]
fn run_enforcement<S, B, E, C>(
    state: &S,
    journal_capability: &BrokerJournalCapability,
    machine: &mut DispatchMachine,
    broker: &B,
    executor: &E,
    clock: &C,
    expected_scope: &Scope,
    route_commitment: [u8; 32],
    request: &DispatchAcquisitionRequest,
) -> EnforcementOutcome
where
    S: BrokerJournalState,
    B: BrokerPort<S>,
    E: ExecutorPort,
    C: TrustedClock,
{
    let work = match state.claim_next_pending_dispatch_or_recover(expected_scope, request) {
        Ok(
            DispatchAcquisitionOutcome::Acquired(work)
            | DispatchAcquisitionOutcome::Recovered(work),
        ) => work,
        Ok(DispatchAcquisitionOutcome::RecoveryRequired(work)) => {
            let disposition = work.disposition();
            if requires_broker_restart(disposition) {
                return close_broker_restart(
                    state,
                    journal_capability,
                    machine,
                    broker,
                    work.recovery_key(),
                    disposition,
                );
            }
            return EnforcementOutcome::AcquisitionInert {
                acquisition_id: work.recovery_key().acquisition_id(),
                disposition,
            };
        }
        Ok(
            DispatchAcquisitionOutcome::Inert(receipt)
            | DispatchAcquisitionOutcome::Quarantined(receipt),
        ) => {
            return EnforcementOutcome::AcquisitionInert {
                acquisition_id: request.acquisition_id(),
                disposition: receipt.disposition(),
            };
        }
        Ok(DispatchAcquisitionOutcome::Disposed(_)) => {
            return EnforcementOutcome::QueueDisposed {
                acquisition_id: request.acquisition_id(),
            };
        }
        Ok(DispatchAcquisitionOutcome::NoWork) => {
            return EnforcementOutcome::NoWork {
                acquisition_id: request.acquisition_id(),
            };
        }
        Ok(DispatchAcquisitionOutcome::OutcomeUnknown(recovery)) => {
            return EnforcementOutcome::AcquisitionOutcomeUnknown {
                acquisition_id: recovery.acquisition_id(),
            };
        }
        Err(_) => {
            return EnforcementOutcome::AcquisitionOutcomeUnknown {
                acquisition_id: request.acquisition_id(),
            };
        }
    };
    let transaction_id = work.snapshot().receipt().transaction_id;
    let key = work.authority().claim().key().clone();
    let imported = match machine.import_acquired_dispatch(work) {
        Ok(imported) => imported,
        Err(error) => {
            return quarantined_bridge(transaction_id, EnforcementStage::Claim, &error);
        }
    };
    let claim = match machine.prepare_claimed_dispatch(&imported) {
        Ok(claim) => claim,
        Err(error) => {
            return quarantined_bridge(transaction_id, EnforcementStage::Prepare, &error);
        }
    };
    let template = match state_template(state, &imported) {
        Ok(template) => template,
        Err(error) => {
            return quarantined_bridge(transaction_id, EnforcementStage::StateTemplate, &error);
        }
    };
    let lookup = AttemptLookup::for_transaction(transaction_id);
    if claim.bound_object_name != lookup.bound_secret_name() {
        return quarantined(
            transaction_id,
            EnforcementStage::Prepare,
            QuarantineReason::InternalInvariant,
            None,
            CredentialRetirement::Unknown,
        );
    }

    if let Err(error) = machine.begin_bound_object_create_from_state(state, &imported, &claim) {
        return quarantined_bridge(transaction_id, EnforcementStage::SecretCreate, &error);
    }

    let secret = match broker.create(
        state,
        journal_capability,
        imported.acquisition_authority(),
        route_commitment,
    ) {
        Ok(created)
            if audit_matches(
                &created.audit,
                &key,
                route_commitment,
                BrokerJournalOperation::CreateSecret,
                BrokerJournalPhase::Committed,
                Some(BrokerJournalOutcome::CreateMatching),
            ) =>
        {
            created.value
        }
        Ok(_) => {
            return quarantined(
                transaction_id,
                EnforcementStage::SecretCreate,
                QuarantineReason::InternalInvariant,
                None,
                CredentialRetirement::Unknown,
            );
        }
        Err(create_failure) => {
            let Ok(observed_at) = trusted_now(clock) else {
                return quarantined(
                    transaction_id,
                    EnforcementStage::SecretCreate,
                    QuarantineReason::TrustedTimeUnavailable,
                    create_failure.conservative_safe_after,
                    CredentialRetirement::Unknown,
                );
            };
            if machine
                .mark_bound_object_create_unknown(transaction_id, &claim, observed_at)
                .and_then(|()| {
                    machine.begin_bound_object_reconciliation(transaction_id, &claim, observed_at)
                })
                .is_err()
            {
                return quarantined(
                    transaction_id,
                    EnforcementStage::SecretCreate,
                    QuarantineReason::InternalInvariant,
                    create_failure.conservative_safe_after,
                    CredentialRetirement::Unknown,
                );
            }
            let reconcile_request = match BrokerReconciliationRequest::new(
                key.clone(),
                BrokerJournalOperation::CreateSecret,
                route_commitment,
            ) {
                Ok(request) => request,
                Err(_) => {
                    return quarantined(
                        transaction_id,
                        EnforcementStage::SecretReconcile,
                        QuarantineReason::InternalInvariant,
                        create_failure.conservative_safe_after,
                        CredentialRetirement::Unknown,
                    );
                }
            };
            match broker.reconcile_create(state, journal_capability, reconcile_request) {
                Ok(ReconciledSecret::Matching(created))
                    if audit_matches(
                        &created.audit,
                        &key,
                        route_commitment,
                        BrokerJournalOperation::CreateSecret,
                        BrokerJournalPhase::Committed,
                        Some(BrokerJournalOutcome::CreateMatching),
                    ) =>
                {
                    created.value
                }
                Ok(ReconciledSecret::Absent(audit))
                    if audit_matches(
                        &audit,
                        &key,
                        route_commitment,
                        BrokerJournalOperation::CreateSecret,
                        BrokerJournalPhase::ReconcileOnly,
                        None,
                    ) && audit.last_reconciliation_outcome()
                        == Some(BrokerJournalOutcome::CreateAbsent) =>
                {
                    let _ignored = machine.resolve_bound_object(
                        transaction_id,
                        &claim,
                        observed_at,
                        BoundObjectObservation::Absent,
                    );
                    return quarantined(
                        transaction_id,
                        EnforcementStage::SecretReconcile,
                        reason_from_port(create_failure),
                        create_failure.conservative_safe_after,
                        CredentialRetirement::Unknown,
                    );
                }
                Ok(ReconciledSecret::Conflicting(audit))
                    if audit_matches(
                        &audit,
                        &key,
                        route_commitment,
                        BrokerJournalOperation::CreateSecret,
                        BrokerJournalPhase::Terminal,
                        Some(BrokerJournalOutcome::CreateConflicting),
                    ) =>
                {
                    let _ignored = machine.resolve_bound_object(
                        transaction_id,
                        &claim,
                        observed_at,
                        BoundObjectObservation::Conflicting,
                    );
                    return quarantined(
                        transaction_id,
                        EnforcementStage::SecretReconcile,
                        reason_from_port(create_failure),
                        create_failure.conservative_safe_after,
                        CredentialRetirement::Unknown,
                    );
                }
                Ok(_) => {
                    return quarantined(
                        transaction_id,
                        EnforcementStage::SecretReconcile,
                        QuarantineReason::InternalInvariant,
                        create_failure.conservative_safe_after,
                        CredentialRetirement::Unknown,
                    );
                }
                Err(failure) => {
                    return quarantined_port(
                        transaction_id,
                        EnforcementStage::SecretReconcile,
                        failure,
                        CredentialRetirement::Unknown,
                    );
                }
            }
        }
    };

    let prepared = B::prepared(&secret);
    let Ok(resolve_at) = trusted_now(clock) else {
        let retirement = cleanup(state, journal_capability, broker, &key, route_commitment);
        return quarantined(
            transaction_id,
            EnforcementStage::SecretCreate,
            QuarantineReason::TrustedTimeUnavailable,
            None,
            retirement,
        );
    };
    if let Err(error) = machine.resolve_bound_object(
        transaction_id,
        &claim,
        resolve_at,
        BoundObjectObservation::Matching(Box::new(prepared.clone())),
    ) {
        let retirement = cleanup(state, journal_capability, broker, &key, route_commitment);
        return quarantined_dispatch(
            transaction_id,
            EnforcementStage::SecretCreate,
            &error,
            retirement,
        );
    }

    if let Err(error) = machine.begin_credential_issue_from_state(state, &imported, &claim) {
        let retirement = cleanup(state, journal_capability, broker, &key, route_commitment);
        return quarantined_bridge(transaction_id, EnforcementStage::CredentialIssue, &error)
            .with_retirement(retirement);
    }
    let issued = match broker.issue(
        state,
        journal_capability,
        imported.acquisition_authority(),
        route_commitment,
    ) {
        Ok(issued)
            if audit_matches(
                &issued.audit,
                &key,
                route_commitment,
                BrokerJournalOperation::IssueToken,
                BrokerJournalPhase::Committed,
                Some(BrokerJournalOutcome::TokenIssued),
            ) =>
        {
            issued.value
        }
        Ok(_) => {
            mark_credential_unknown(machine, transaction_id, &claim, clock);
            let retirement = cleanup(state, journal_capability, broker, &key, route_commitment);
            return quarantined(
                transaction_id,
                EnforcementStage::CredentialIssue,
                QuarantineReason::InternalInvariant,
                None,
                retirement,
            );
        }
        Err(failure) => {
            mark_credential_unknown(machine, transaction_id, &claim, clock);
            let retirement = cleanup(state, journal_capability, broker, &key, route_commitment);
            return quarantined_port(
                transaction_id,
                EnforcementStage::CredentialIssue,
                failure,
                retirement,
            );
        }
    };

    let (reviewed, bearer) = match broker.review(
        state,
        journal_capability,
        imported.acquisition_authority(),
        issued,
    ) {
        Ok(ReviewedCredential::Authenticated { reviewed, bearer }) => (reviewed, bearer),
        Ok(ReviewedCredential::Rejected(rejection)) => {
            mark_credential_unknown(machine, transaction_id, &claim, clock);
            // This rejection predates DELETE and its subsequent GET-absence
            // observation, so it cannot prove terminal credential retirement.
            drop(rejection);
            let retirement = cleanup(state, journal_capability, broker, &key, route_commitment);
            return quarantined(
                transaction_id,
                EnforcementStage::TokenReview,
                QuarantineReason::Rejected,
                None,
                retirement,
            );
        }
        Err(failure) => {
            mark_credential_unknown(machine, transaction_id, &claim, clock);
            let retirement = cleanup(state, journal_capability, broker, &key, route_commitment);
            return quarantined_port(
                transaction_id,
                EnforcementStage::TokenReview,
                failure,
                retirement,
            );
        }
    };

    let binding = binding_from(&prepared, *reviewed.claims().token_digest().as_bytes());
    let attempt = match machine
        .authorize_provider_attempt_from_state(state, imported, &claim, &binding, *reviewed)
    {
        Ok(attempt) => attempt,
        Err(error) => {
            drop(bearer);
            let retirement = cleanup(state, journal_capability, broker, &key, route_commitment);
            return quarantined_bridge(transaction_id, EnforcementStage::AttemptCommit, &error)
                .with_retirement(retirement);
        }
    };

    let evidence = match executor.execute_once(attempt, template, bearer) {
        Ok(evidence) => evidence,
        Err(error) => {
            let observed_at = trusted_now(clock).ok();
            if let Some(now) = observed_at {
                let _ignored = machine.record_provider_outcome(
                    transaction_id,
                    &claim,
                    now,
                    ProviderOutcome::Unknown,
                );
            }
            let retirement = cleanup(state, journal_capability, broker, &key, route_commitment);
            return quarantined(
                transaction_id,
                EnforcementStage::ProviderEffect,
                reason_from_executor(&error),
                None,
                retirement,
            );
        }
    };

    let lifecycle_recorded = machine
        .record_provider_outcome(
            transaction_id,
            &claim,
            evidence.observed_at,
            ProviderOutcome::Success {
                evidence: Box::new(evidence),
            },
        )
        .is_ok();
    let retirement = cleanup(state, journal_capability, broker, &key, route_commitment);
    EnforcementOutcome::EffectEstablished {
        transaction_id,
        lifecycle_recorded,
        retirement,
    }
}

const fn requires_broker_restart(disposition: DispatchAcquisitionDisposition) -> bool {
    matches!(
        disposition,
        DispatchAcquisitionDisposition::BrokerArtifactPresent
            | DispatchAcquisitionDisposition::AttemptInFlight
            | DispatchAcquisitionDisposition::RecoveryNoSend
    )
}

/// Recovers only enough durable state to reconcile or clean up the exact
/// acquisition-bound broker artifact after a process restart.
///
/// Every pre-attempt broker artifact enters `RECOVERY_NO_SEND` by its opaque,
/// server-selected historical recovery key before cleanup. Exact cleanup then
/// advances it to `RECOVERY_RETIRED` only after state independently verifies
/// the rooted retirement bound and releases the reservation. If the attempt
/// already committed, the no-send CAS fails and cleanup proceeds without
/// releasing productive attempt state. Bearer custody never survives either
/// restart, so this path cannot construct `DispatchImport`,
/// `AuthorizedProviderAttempt`, or invoke `ExecutorPort`.
#[allow(clippy::manual_let_else)]
fn close_broker_restart<S, B>(
    state: &S,
    journal_capability: &BrokerJournalCapability,
    machine: &DispatchMachine,
    broker: &B,
    acquisition_recovery: &DispatchAcquisitionRecoveryKey,
    disposition: DispatchAcquisitionDisposition,
) -> EnforcementOutcome
where
    S: BrokerJournalState,
    B: BrokerPort<S>,
{
    let mut closure_mismatch = false;
    let mut recovery_no_send = disposition == DispatchAcquisitionDisposition::RecoveryNoSend;
    let mut expected_closed_key = None;
    if disposition == DispatchAcquisitionDisposition::BrokerArtifactPresent {
        match machine.close_recovered_attempt_from_state(state, acquisition_recovery) {
            Ok(committed) => {
                recovery_no_send = true;
                expected_closed_key = Some(committed.key().clone());
            }
            Err(BridgeError::State(StateError::DispatchAttemptOutcomeUnknown)) => {
                // A productive ATTEMPT won the CAS. It remains cleanup-only and
                // can never be downgraded to no-send or reservation release.
            }
            Err(_) => {
                closure_mismatch = true;
            }
        }
    }

    let context = match state.dispatch_broker_restart_context(acquisition_recovery) {
        Ok(context) => context,
        Err(_) => {
            return EnforcementOutcome::AcquisitionOutcomeUnknown {
                acquisition_id: acquisition_recovery.acquisition_id(),
            };
        }
    };
    let Some(context_key) = restart_context_key(&context) else {
        return EnforcementOutcome::AcquisitionOutcomeUnknown {
            acquisition_id: acquisition_recovery.acquisition_id(),
        };
    };
    let transaction_id = context_key.transaction_id;
    if expected_closed_key
        .as_ref()
        .is_some_and(|expected| expected != &context_key)
    {
        closure_mismatch = true;
    }
    let mut retirement = restart_retirement(
        state,
        journal_capability,
        broker,
        acquisition_recovery,
        &context,
    );
    if recovery_no_send && !closure_mismatch {
        retirement = finalize_recovery_no_send_retirement(
            state,
            acquisition_recovery,
            &context_key,
            retirement,
        );
    }
    quarantined(
        transaction_id,
        EnforcementStage::DurableBrokerLifecycle,
        if closure_mismatch {
            QuarantineReason::InternalInvariant
        } else {
            QuarantineReason::OutcomeUnknown
        },
        None,
        retirement,
    )
}

fn finalize_recovery_no_send_retirement<S: BrokerJournalState>(
    state: &S,
    recovery: &DispatchAcquisitionRecoveryKey,
    expected_key: &ConsumeKey,
    retirement: CredentialRetirement,
) -> CredentialRetirement {
    match state.retire_recovery_no_send(recovery) {
        Ok(RecoveryNoSendRetirementOutcome::Pending { safe_after }) => match retirement {
            CredentialRetirement::Confirmed => CredentialRetirement::Pending { safe_after },
            CredentialRetirement::Pending {
                safe_after: observed,
            } if observed == safe_after => CredentialRetirement::Pending { safe_after },
            CredentialRetirement::Pending { .. } | CredentialRetirement::Unknown => {
                CredentialRetirement::Unknown
            }
        },
        Ok(
            RecoveryNoSendRetirementOutcome::Retired(receipt)
            | RecoveryNoSendRetirementOutcome::Recovered(receipt),
        ) if receipt.key() == expected_key
            && receipt.key().scope == *recovery.scope()
            && receipt.acquisition().acquisition_id() == recovery.acquisition_id()
            && receipt.acquisition().worker_id() == recovery.worker_id()
            && receipt.acquisition().lease_fence() > 0
            && receipt.acquisition().acquired_at() >= 0
            && receipt.acquisition().acquired_at() < receipt.acquisition().lease_until()
            && receipt.acquisition().lease_until() <= receipt.acquisition().dispatch_deadline()
            && !receipt.acquisition().control_submission_id().is_nil()
            && receipt.retired_at() >= receipt.safe_after() =>
        {
            match retirement {
                CredentialRetirement::Confirmed => CredentialRetirement::Confirmed,
                CredentialRetirement::Pending { safe_after }
                    if safe_after == receipt.safe_after() =>
                {
                    CredentialRetirement::Confirmed
                }
                CredentialRetirement::Pending { .. } | CredentialRetirement::Unknown => {
                    CredentialRetirement::Unknown
                }
            }
        }
        Ok(
            RecoveryNoSendRetirementOutcome::Retired(_)
            | RecoveryNoSendRetirementOutcome::Recovered(_),
        )
        | Err(_) => CredentialRetirement::Unknown,
    }
}

fn restart_context_key(context: &DispatchBrokerRestartContext) -> Option<ConsumeKey> {
    match context.action() {
        DispatchBrokerRestartAction::ReconcileCreate => context
            .reconciliation_request()
            .filter(|request| request.key() == context.key())
            .map(|request| request.key().clone()),
        DispatchBrokerRestartAction::CleanupSecret => context
            .cleanup_request()
            .filter(|request| request.key() == context.key())
            .map(|request| request.key().clone()),
        DispatchBrokerRestartAction::CreationAlreadyAbsent
        | DispatchBrokerRestartAction::DeletionAlreadyAbsent => Some(context.key().clone()),
    }
}

fn restart_retirement<S, B>(
    state: &S,
    journal_capability: &BrokerJournalCapability,
    broker: &B,
    recovery: &DispatchAcquisitionRecoveryKey,
    context: &DispatchBrokerRestartContext,
) -> CredentialRetirement
where
    S: BrokerJournalState,
    B: BrokerPort<S>,
{
    match context.action() {
        DispatchBrokerRestartAction::CreationAlreadyAbsent => {
            // State authenticated exact CREATE-GET absence before any token,
            // review, or provider boundary. No bearer ever existed, so the
            // no-send retirement CAS may release the tail immediately.
            CredentialRetirement::Confirmed
        }
        DispatchBrokerRestartAction::DeletionAlreadyAbsent => {
            // State authenticated an append-only DELETE/GET-absence result for
            // this exact acquisition lineage. Absence authorizes no more I/O,
            // but bearer retirement always waits for the rooted propagation
            // bound. A TokenReview rejection is audit-only and cannot shorten
            // that delay because its provider-observation time is not durable.
            context
                .deletion_evidence()
                .map_or(CredentialRetirement::Unknown, |evidence| {
                    broker
                        .recovered_retirement(evidence)
                        .unwrap_or(CredentialRetirement::Unknown)
                })
        }
        DispatchBrokerRestartAction::CleanupSecret => context
            .cleanup_request()
            .map_or(CredentialRetirement::Unknown, |request| {
                cleanup_request(state, journal_capability, broker, request)
            }),
        DispatchBrokerRestartAction::ReconcileCreate => {
            let Some(request) = context.reconciliation_request() else {
                return CredentialRetirement::Unknown;
            };
            let expected_key = request.key().clone();
            let Ok(observation) = broker.reconcile_create(state, journal_capability, request)
            else {
                return CredentialRetirement::Unknown;
            };
            let reloaded = state.dispatch_broker_restart_context(recovery).ok();
            if let Some(next) = reloaded
                && restart_context_key(&next).as_ref() == Some(&expected_key)
            {
                match next.action() {
                    DispatchBrokerRestartAction::CreationAlreadyAbsent => {
                        return CredentialRetirement::Confirmed;
                    }
                    DispatchBrokerRestartAction::CleanupSecret => {
                        return next
                            .cleanup_request()
                            .map_or(CredentialRetirement::Unknown, |request| {
                                cleanup_request(state, journal_capability, broker, request)
                            });
                    }
                    DispatchBrokerRestartAction::ReconcileCreate
                    | DispatchBrokerRestartAction::DeletionAlreadyAbsent => {}
                }
            }
            // The observation alone is not trusted as retirement authority.
            // Only the reloaded state-derived CreationAlreadyAbsent action can
            // prove that no token/review/provider boundary followed CREATE.
            let _ = observation;
            CredentialRetirement::Unknown
        }
    }
}

trait OutcomeExt {
    fn with_retirement(self, retirement: CredentialRetirement) -> Self;
}

impl OutcomeExt for EnforcementOutcome {
    fn with_retirement(self, retirement: CredentialRetirement) -> Self {
        match self {
            Self::Quarantined {
                transaction_id,
                stage,
                reason,
                conservative_safe_after,
                ..
            } => Self::Quarantined {
                transaction_id,
                stage,
                reason,
                conservative_safe_after,
                retirement,
            },
            readiness @ Self::ReadinessBlocked { .. } => readiness,
            effect => effect,
        }
    }
}

fn state_template<S: TransactionalState>(
    state: &S,
    imported: &accordlock_dispatch::DispatchImport,
) -> Result<DeploymentTemplate, BridgeError> {
    let authority = imported.acquisition_authority();
    let token = authority.claim();
    let snapshot = state.revalidate_dispatch_acquisition(authority)?;
    let issued = snapshot.issued();
    if issued.transaction_id != token.key().transaction_id
        || issued.authorization().authorization_id != token.key().authorization_id
        || issued.scope() != token.key().scope.clone()
    {
        return Err(BridgeError::SnapshotMismatch);
    }
    Ok(issued.authorization().template.clone())
}

fn binding_from(prepared: &PreparedExecution, token_digest: [u8; 32]) -> EffectBinding {
    EffectBinding {
        template_hash: prepared.template_hash,
        operation_hash: prepared.operation_hash,
        execution_command_commitment: prepared.execution_command_commitment,
        final_wire_commitment: prepared.final_wire_commitment,
        effective_rbac_commitment: prepared.effective_rbac_commitment,
        token_digest,
    }
}

fn cleanup<S, B>(
    state: &S,
    journal_capability: &BrokerJournalCapability,
    broker: &B,
    key: &ConsumeKey,
    route_commitment: [u8; 32],
) -> CredentialRetirement
where
    S: BrokerJournalState,
    B: BrokerPort<S>,
{
    let Ok(request) = BrokerCleanupRequest::new(key.clone(), route_commitment) else {
        return CredentialRetirement::Unknown;
    };
    cleanup_request(state, journal_capability, broker, request)
}

fn cleanup_request<S, B>(
    state: &S,
    journal_capability: &BrokerJournalCapability,
    broker: &B,
    request: BrokerCleanupRequest,
) -> CredentialRetirement
where
    S: BrokerJournalState,
    B: BrokerPort<S>,
{
    let key = request.key().clone();
    let route_commitment = *request.route_commitment().as_bytes();
    let delete_audit = broker.delete(state, journal_capability, request);
    if let Ok(audit) = &delete_audit
        && !audit_matches(
            audit,
            &key,
            route_commitment,
            BrokerJournalOperation::DeleteSecret,
            BrokerJournalPhase::Unknown,
            None,
        )
    {
        return CredentialRetirement::Unknown;
    }

    let Ok(reconciliation) = BrokerReconciliationRequest::new(
        key.clone(),
        BrokerJournalOperation::DeleteSecret,
        route_commitment,
    ) else {
        return CredentialRetirement::Unknown;
    };
    match broker.verify_deleted(state, journal_capability, reconciliation) {
        Ok(ObservedDeletion::Absent(deleted))
            if audit_matches(
                &deleted.audit,
                &key,
                route_commitment,
                BrokerJournalOperation::DeleteSecret,
                BrokerJournalPhase::Committed,
                Some(BrokerJournalOutcome::DeleteAbsent),
            ) =>
        {
            broker
                .retirement(&deleted.value)
                .unwrap_or(CredentialRetirement::Unknown)
        }
        Ok(ObservedDeletion::Present(audit))
            if audit_matches(
                &audit,
                &key,
                route_commitment,
                BrokerJournalOperation::DeleteSecret,
                BrokerJournalPhase::ReconcileOnly,
                None,
            ) && audit.last_reconciliation_outcome()
                == Some(BrokerJournalOutcome::DeletePresent) =>
        {
            CredentialRetirement::Unknown
        }
        Ok(ObservedDeletion::Conflicting(audit))
            if audit_matches(
                &audit,
                &key,
                route_commitment,
                BrokerJournalOperation::DeleteSecret,
                BrokerJournalPhase::Terminal,
                Some(BrokerJournalOutcome::DeleteConflicting),
            ) =>
        {
            CredentialRetirement::Unknown
        }
        Ok(_) | Err(_) => CredentialRetirement::Unknown,
    }
}

fn audit_matches(
    audit: &BrokerOperationAudit,
    key: &ConsumeKey,
    route_commitment: [u8; 32],
    operation: BrokerJournalOperation,
    phase: BrokerJournalPhase,
    outcome: Option<BrokerJournalOutcome>,
) -> bool {
    audit.key() == key
        && audit.route_commitment().as_bytes() == &route_commitment
        && audit.operation() == operation
        && audit.phase() == phase
        && audit.outcome() == outcome
}

fn mark_credential_unknown<C: TrustedClock>(
    machine: &mut DispatchMachine,
    transaction_id: Uuid,
    claim: &accordlock_dispatch::DispatchClaim,
    clock: &C,
) {
    if let Ok(now) = trusted_now(clock) {
        let _ignored = machine.mark_credential_issue_unknown(transaction_id, claim, now);
    }
}

fn trusted_now<C: TrustedClock>(clock: &C) -> Result<i64, ()> {
    clock.unix_seconds().map_err(|_| ()).and_then(
        |value| {
            if value < 0 { Err(()) } else { Ok(value) }
        },
    )
}

fn reason_from_port(failure: PortFailure) -> QuarantineReason {
    match failure.kind {
        PortFailureKind::Rejected => QuarantineReason::Rejected,
        PortFailureKind::DefinitelyNotSent => QuarantineReason::DefinitelyNotSent,
        PortFailureKind::OutcomeUnknown => QuarantineReason::OutcomeUnknown,
        PortFailureKind::Unavailable => QuarantineReason::AuthorityUnavailable,
        PortFailureKind::Invalid => QuarantineReason::InternalInvariant,
    }
}

fn reason_from_executor(error: &ExecutorError) -> QuarantineReason {
    match error {
        ExecutorError::PatchDefinitelyNotSent(_) => QuarantineReason::DefinitelyNotSent,
        ExecutorError::PatchOutcomeUnknown(_)
        | ExecutorError::PatchStatusOutcomeUnknown(_)
        | ExecutorError::EffectUnverifiable(_)
        | ExecutorError::ObservationTimeInvalid { .. }
        | ExecutorError::ResponseIdentityMismatch => QuarantineReason::OutcomeUnknown,
        ExecutorError::Clock(_) => QuarantineReason::TrustedTimeUnavailable,
        _ => QuarantineReason::Rejected,
    }
}

fn reason_from_bridge(error: &BridgeError) -> QuarantineReason {
    match error {
        BridgeError::State(
            accordlock_state::StateError::DispatchClaimOutcomeUnknown
            | accordlock_state::StateError::DispatchAttemptOutcomeUnknown
            | accordlock_state::StateError::ConsumptionOutcomeUnknown
            | accordlock_state::StateError::AdmissionOutcomeUnknown,
        ) => QuarantineReason::OutcomeUnknown,
        BridgeError::State(
            accordlock_state::StateError::Database(_)
            | accordlock_state::StateError::RetryableConflict
            | accordlock_state::StateError::RetryLimitExhausted,
        ) => QuarantineReason::AuthorityUnavailable,
        BridgeError::SnapshotMismatch
        | BridgeError::ScopeMismatch
        | BridgeError::Canonical(_)
        | BridgeError::CommitmentLengthOverflow
        | BridgeError::AuthorityEpochOverflow
        | BridgeError::Projection(_) => QuarantineReason::InternalInvariant,
        BridgeError::State(_) | BridgeError::Dispatch(_) => QuarantineReason::Rejected,
    }
}

fn reason_from_dispatch(error: &accordlock_dispatch::DispatchError) -> QuarantineReason {
    match error {
        accordlock_dispatch::DispatchError::InvalidTime => QuarantineReason::TrustedTimeUnavailable,
        accordlock_dispatch::DispatchError::InvalidTransition
        | accordlock_dispatch::DispatchError::InvalidCommitment
        | accordlock_dispatch::DispatchError::InvalidEvidence
        | accordlock_dispatch::DispatchError::ArithmeticOverflow => {
            QuarantineReason::InternalInvariant
        }
        _ => QuarantineReason::Rejected,
    }
}

fn quarantined_bridge(
    transaction_id: Uuid,
    stage: EnforcementStage,
    error: &BridgeError,
) -> EnforcementOutcome {
    quarantined(
        transaction_id,
        stage,
        reason_from_bridge(error),
        None,
        CredentialRetirement::Unknown,
    )
}

fn quarantined_dispatch(
    transaction_id: Uuid,
    stage: EnforcementStage,
    error: &accordlock_dispatch::DispatchError,
    retirement: CredentialRetirement,
) -> EnforcementOutcome {
    quarantined(
        transaction_id,
        stage,
        reason_from_dispatch(error),
        None,
        retirement,
    )
}

fn quarantined_port(
    transaction_id: Uuid,
    stage: EnforcementStage,
    failure: PortFailure,
    retirement: CredentialRetirement,
) -> EnforcementOutcome {
    quarantined(
        transaction_id,
        stage,
        reason_from_port(failure),
        failure.conservative_safe_after,
        retirement,
    )
}

const fn quarantined(
    transaction_id: Uuid,
    stage: EnforcementStage,
    reason: QuarantineReason,
    conservative_safe_after: Option<i64>,
    retirement: CredentialRetirement,
) -> EnforcementOutcome {
    EnforcementOutcome::Quarantined {
        transaction_id,
        stage,
        reason,
        conservative_safe_after,
        retirement,
    }
}

// `tests.rs` is the pre-acquisition v13 harness. It is retained as migration
// history but deliberately cannot compile against the productive v14 traits.
#[cfg(any())]
mod tests;

#[cfg(test)]
mod phase_b_tests;
