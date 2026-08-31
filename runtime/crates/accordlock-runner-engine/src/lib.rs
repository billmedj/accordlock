//! Fail-closed composition root for one enterprise `AccordLock` runner.
//!
//! This engine authenticates an exact credential-free dispatch before any
//! provider read, collects evidence through runner-owned transports, and
//! prepares (but cannot execute) the existing EKS effect path while its live
//! readiness proofs remain unavailable.

#![forbid(unsafe_code)]

use std::{fmt, sync::Arc};

mod state;

pub use state::{
    InMemoryRunnerStateStore, RunnerReplayKind, RunnerStateError, RunnerStateReservation,
    RunnerStateStore, SqliteRunnerStateStore,
};

use accordlock_connectors::{ConnectorRuntime, TrustedClock, TrustedSourceSet};
use accordlock_enforcement::{EnforcementReadinessBlocker, production_readiness_blockers};
use accordlock_evaluation::PolicyDecisionRecord;
use accordlock_k8s::{PreparedPatch, patch_wire_body, prepare_patch, validate_preconditions};
use accordlock_protocol::{
    CoseVerifier, Digest32, ExecutionAuthorization, TrustedEvidenceSet, canonical_hash,
};
use accordlock_provider_adapters::{
    AdapterConfigError, AuthenticatedTransportIdentity, EcrAdapterConfig,
    EcrAuthenticatedTransport, EcrSourceAdapter, GitHubAdapterConfig, GitHubAuthenticatedTransport,
    GitHubSourceAdapter, HttpsEndpoint, KubernetesAdapterConfig, KubernetesAuthenticatedTransport,
    KubernetesSourceAdapter,
};
use accordlock_runner_bridge::{
    PreparedDeployment, PreparedEvidenceLookup, RunnerBridgeError,
    prepare_authorized_deployment_with_approval, prepare_evidence_lookup,
};
use accordlock_runner_protocol::{
    ActionApprovalError, AutonomyMode, EnterpriseEnvironmentProfile,
    ExpectedActionApprovalBindings, RunnerAction, RunnerDispatch, RunnerProtocolError,
    RunnerRegistration, VerifiedActionApproval, action_approval_authority_commitment,
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

/// Hard per-namespace bound on retained runner replay entries.
pub const MAX_ACCEPTED_DISPATCHES: usize = 4_096;

/// Exact non-secret facts presented to the trusted channel authenticator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispatchAuthenticationRequest {
    pub runner_id: Uuid,
    pub dispatch_hash: Digest32,
    pub runner_attestation_hash: Digest32,
    pub trusted_now: i64,
}

/// Successful live-channel authentication, bound to one dispatch digest.
///
/// This type is intentionally not serializable. It contains no credentials;
/// the channel-binding digest is evidence that credentials were verified by
/// the runner-owned authenticator, not the credential itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispatchAuthentication {
    runner_id: Uuid,
    dispatch_hash: Digest32,
    runner_attestation_hash: Digest32,
    channel_binding_hash: Digest32,
    authenticated_at: i64,
}

impl DispatchAuthentication {
    /// Creates the categorical result returned by a trusted authenticator.
    /// The engine independently rechecks every echoed binding.
    #[must_use]
    pub const fn new(
        runner_id: Uuid,
        dispatch_hash: Digest32,
        runner_attestation_hash: Digest32,
        channel_binding_hash: Digest32,
        authenticated_at: i64,
    ) -> Self {
        Self {
            runner_id,
            dispatch_hash,
            runner_attestation_hash,
            channel_binding_hash,
            authenticated_at,
        }
    }

    #[must_use]
    pub const fn channel_binding_hash(&self) -> Digest32 {
        self.channel_binding_hash
    }

    #[must_use]
    pub const fn authenticated_at(&self) -> i64 {
        self.authenticated_at
    }
}

/// Trusted bootstrap boundary that owns dispatch-channel authentication.
pub trait DispatchAuthenticator: Send + Sync {
    /// Returns the fixed public identity of this exact authenticator.
    ///
    /// # Errors
    ///
    /// Returns an error if its public bootstrap identity is unavailable.
    fn public_identity(
        &self,
    ) -> Result<AuthenticatedTransportIdentity, DispatchAuthenticationError>;

    /// Authenticates the current channel for exactly one dispatch.
    ///
    /// # Errors
    ///
    /// Returns a categorical rejection or availability failure without secret
    /// material.
    fn authenticate(
        &self,
        request: DispatchAuthenticationRequest,
    ) -> Result<DispatchAuthentication, DispatchAuthenticationError>;
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum DispatchAuthenticationError {
    #[error("dispatch channel authentication was rejected")]
    Rejected,
    #[error("dispatch channel authentication is unavailable")]
    Unavailable,
}

/// Result of one authenticated, read-only supply-chain observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectedRunnerEvidence {
    pub lookup: PreparedEvidenceLookup,
    pub authentication: DispatchAuthentication,
    pub evidence: TrustedEvidenceSet,
}

/// Exact deployment preparation held behind the core's live readiness gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadinessBlockedDeployment {
    pub prepared: PreparedDeployment,
    pub authentication: DispatchAuthentication,
    pub blockers: [EnforcementReadinessBlocker; 3],
}

/// Explicit execution outcome for an account-free deployment exhibit.
///
/// The exhibit derives the exact Kubernetes request body but cannot release it
/// to a transport or obtain provider credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalDeploymentExecutionOutcome {
    NotSent,
}

/// Exact no-credential exhibit of the Kubernetes request an accepted runner
/// dispatch would produce.
///
/// The patch is derived by `accordlock-k8s`, the same bounded request builder
/// consumed by the native EKS executor. The result remains held behind the
/// production readiness blockers and never invokes a provider transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalDeploymentExhibit {
    pub deployment: ReadinessBlockedDeployment,
    pub snapshot_hash: Digest32,
    pub prepared_patch: PreparedPatch,
    pub exact_patch_body: Vec<u8>,
    pub execution_outcome: LocalDeploymentExecutionOutcome,
}

/// Fixed credential-free provider endpoints and response bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunnerProviderEndpoints {
    github: HttpsEndpoint,
    ecr: HttpsEndpoint,
    kubernetes: HttpsEndpoint,
    maximum_response_bytes: usize,
}

impl RunnerProviderEndpoints {
    #[must_use]
    pub const fn new(
        github: HttpsEndpoint,
        ecr: HttpsEndpoint,
        kubernetes: HttpsEndpoint,
        maximum_response_bytes: usize,
    ) -> Self {
        Self {
            github,
            ecr,
            kubernetes,
            maximum_response_bytes,
        }
    }
}

/// Runner-owned authenticated transport capabilities. Debug output is redacted.
pub struct RunnerProviderTransports {
    github: Arc<dyn GitHubAuthenticatedTransport>,
    ecr: Arc<dyn EcrAuthenticatedTransport>,
    kubernetes: Arc<dyn KubernetesAuthenticatedTransport>,
}

impl RunnerProviderTransports {
    #[must_use]
    pub fn new(
        github: Arc<dyn GitHubAuthenticatedTransport>,
        ecr: Arc<dyn EcrAuthenticatedTransport>,
        kubernetes: Arc<dyn KubernetesAuthenticatedTransport>,
    ) -> Self {
        Self {
            github,
            ecr,
            kubernetes,
        }
    }
}

impl fmt::Debug for RunnerProviderTransports {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunnerProviderTransports")
            .field("github", &"<runner-owned authenticated transport>")
            .field("ecr", &"<runner-owned authenticated transport>")
            .field("kubernetes", &"<runner-owned authenticated transport>")
            .finish()
    }
}

/// Constructs connector sources from one profile and runner-side transports.
/// All conformance routes are derived from the validated profile.
///
/// # Errors
///
/// Returns a profile or adapter configuration error before any provider read.
pub fn trusted_provider_sources_for_profile(
    profile: &EnterpriseEnvironmentProfile,
    endpoints: RunnerProviderEndpoints,
    transports: RunnerProviderTransports,
) -> Result<TrustedSourceSet, ProviderCompositionError> {
    profile.validate()?;
    let (github_owner, github_repository) = profile
        .github_repository
        .split_once('/')
        .ok_or(ProviderCompositionError::ProfileRepositoryRoute)?;
    let github_config = GitHubAdapterConfig::new(
        endpoints.github,
        github_owner,
        github_repository,
        profile.github_workflow_ref.clone(),
        endpoints.maximum_response_bytes,
    )?;
    let ecr_config = EcrAdapterConfig::new(
        endpoints.ecr,
        profile.aws_account_id.clone(),
        profile.aws_region.clone(),
        profile.ecr_repository.clone(),
        profile.github_repository.clone(),
        endpoints.maximum_response_bytes,
    )?;
    let kubernetes_config = KubernetesAdapterConfig::new(
        endpoints.kubernetes,
        profile.eks_cluster_identity(),
        profile.kubernetes_namespace.clone(),
        profile.kubernetes_deployment.clone(),
        profile.kubernetes_container.clone(),
        profile.github_repository.clone(),
        profile.ecr_image_repository(),
        endpoints.maximum_response_bytes,
    )?;
    let approval = GitHubSourceAdapter::new(github_config.clone(), Arc::clone(&transports.github))?;
    let build = GitHubSourceAdapter::new(github_config, transports.github)?;
    let artifact = EcrSourceAdapter::new(ecr_config, transports.ecr)?;
    let target = KubernetesSourceAdapter::new(kubernetes_config, transports.kubernetes)?;
    Ok(TrustedSourceSet::new(
        Box::new(approval),
        Box::new(build),
        Box::new(artifact),
        Box::new(target),
    )?)
}

#[derive(Debug, Error)]
pub enum ProviderCompositionError {
    #[error("runner environment profile is invalid: {0}")]
    RunnerProtocol(#[from] RunnerProtocolError),
    #[error("runner profile GitHub repository route is invalid")]
    ProfileRepositoryRoute,
    #[error("provider adapter configuration is invalid: {0}")]
    Adapter(#[from] AdapterConfigError),
    #[error("trusted connector source composition is invalid: {0}")]
    Connector(#[from] accordlock_connectors::ConnectorError),
}

/// One immutable enterprise runner composition.
pub struct EnterpriseRunner {
    profile: EnterpriseEnvironmentProfile,
    registration: RunnerRegistration,
    connectors: ConnectorRuntime,
    action_approval_verifier: CoseVerifier,
    authenticator: Box<dyn DispatchAuthenticator>,
    clock: Box<dyn TrustedClock>,
    state: Arc<dyn RunnerStateStore>,
}

impl fmt::Debug for EnterpriseRunner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnterpriseRunner")
            .field("profile", &self.profile)
            .field("registration", &self.registration)
            .field("connectors", &self.connectors)
            .field(
                "action_approval_verifier",
                &self.action_approval_verifier.key_id(),
            )
            .field("authenticator", &"<runner-owned authenticator>")
            .field("clock", &"<runner-owned trusted clock>")
            .field("state", &"<runner-owned replay and trusted-time state>")
            .finish()
    }
}

impl EnterpriseRunner {
    /// Creates an immutable runner root. Provider transports, connector
    /// signers and channel authentication are injected trusted-bootstrap
    /// dependencies, never dispatch fields.
    ///
    /// # Errors
    ///
    /// Rejects a malformed, expired or cross-environment enrollment.
    pub fn new(
        profile: EnterpriseEnvironmentProfile,
        registration: RunnerRegistration,
        connectors: ConnectorRuntime,
        action_approval_verifier: CoseVerifier,
        authenticator: Box<dyn DispatchAuthenticator>,
        clock: Box<dyn TrustedClock>,
    ) -> Result<Self, RunnerEngineError> {
        Self::new_with_state_store(
            profile,
            registration,
            connectors,
            action_approval_verifier,
            authenticator,
            clock,
            Arc::new(InMemoryRunnerStateStore::new()),
        )
    }

    /// Creates a runner backed by strict single-host `SQLite` state.
    ///
    /// The caller opens the store as an explicit trusted-bootstrap step. This
    /// constructor does not silently create or migrate a state path while
    /// validating an unrelated environment profile.
    ///
    /// # Errors
    ///
    /// Rejects invalid bootstrap bindings, unavailable/corrupt state, or a
    /// trusted clock below the durable high-water mark.
    pub fn new_durable(
        profile: EnterpriseEnvironmentProfile,
        registration: RunnerRegistration,
        connectors: ConnectorRuntime,
        action_approval_verifier: CoseVerifier,
        authenticator: Box<dyn DispatchAuthenticator>,
        clock: Box<dyn TrustedClock>,
        state: SqliteRunnerStateStore,
    ) -> Result<Self, RunnerEngineError> {
        Self::new_with_state_store(
            profile,
            registration,
            connectors,
            action_approval_verifier,
            authenticator,
            clock,
            Arc::new(state),
        )
    }

    /// Creates a runner with an injected object-safe state implementation.
    ///
    /// Production implementations must provide atomic cross-process replay
    /// reservations and rollback-resistant high-water persistence. The state
    /// store is a trusted bootstrap capability, never a dispatch field.
    ///
    /// # Errors
    ///
    /// Rejects invalid bootstrap bindings, unavailable/corrupt state, or a
    /// trusted clock below the retained high-water mark.
    pub fn new_with_state_store(
        profile: EnterpriseEnvironmentProfile,
        registration: RunnerRegistration,
        connectors: ConnectorRuntime,
        action_approval_verifier: CoseVerifier,
        authenticator: Box<dyn DispatchAuthenticator>,
        clock: Box<dyn TrustedClock>,
        state: Arc<dyn RunnerStateStore>,
    ) -> Result<Self, RunnerEngineError> {
        profile.validate()?;
        registration.validate()?;
        let connector_commitments = connectors.configuration_commitments()?;
        if connector_commitments.github_connector_hash != profile.github_connector_hash
            || connector_commitments.ecr_connector_hash != profile.ecr_connector_hash
            || connector_commitments.kubernetes_connector_hash != profile.kubernetes_connector_hash
        {
            return Err(RunnerEngineError::ConnectorCommitmentMismatch);
        }
        if action_approval_authority_commitment(&action_approval_verifier)
            != profile.action_approval_authority_hash
        {
            return Err(RunnerEngineError::ActionApprovalAuthorityMismatch);
        }
        let authenticator_identity_hash = authenticator.public_identity()?.digest();
        let aws_identity_hash = aws_identity_commitment(
            &profile.aws_account_id,
            &profile.aws_region,
            connector_commitments.ecr_transport_identity_hash,
            connector_commitments.kubernetes_transport_identity_hash,
            authenticator_identity_hash,
        );
        if aws_identity_hash != profile.aws_identity_hash {
            return Err(RunnerEngineError::AwsIdentityCommitmentMismatch);
        }
        if registration.organization_id != profile.organization_id
            || registration.environment_id != profile.environment_id
            || registration.environment_profile_hash != profile.digest()?
        {
            return Err(RunnerEngineError::EnvironmentBindingMismatch);
        }
        // The first potentially external read happens only after every
        // bootstrap commitment and enrollment binding has matched.
        let trusted_now = read_trusted_time(clock.as_ref())?;
        profile.validate_at(trusted_now)?;
        registration.validate_at(trusted_now)?;
        state
            .observe_trusted_time(trusted_now)
            .map_err(map_trusted_time_state_error)?;
        Ok(Self {
            profile,
            registration,
            connectors,
            action_approval_verifier,
            authenticator,
            clock,
            state,
        })
    }

    /// Authenticates, binds and collects four read-only provider assertions.
    /// No provider is contacted until dispatch authentication and the runner
    /// bridge validations have both succeeded.
    ///
    /// # Errors
    ///
    /// Fails closed for authentication, binding, replay, provider, clock or
    /// connector errors. Failed provider collection releases the exact pending
    /// replay reservation so the delivery may be retried.
    pub fn collect_evidence(
        &self,
        dispatch: &RunnerDispatch,
        decision: &PolicyDecisionRecord,
    ) -> Result<CollectedRunnerEvidence, RunnerEngineError> {
        if decision.decision == accordlock_evaluation::EnforcementDecision::RequireApproval {
            return Err(RunnerEngineError::VerifiedActionApprovalRequired);
        }
        let trusted_now = self.trusted_now()?;
        let dispatch_hash = dispatch.digest(&self.registration)?;
        let authentication = self.authenticate(dispatch_hash, trusted_now)?;
        let lookup = prepare_evidence_lookup(
            &self.profile,
            &self.registration,
            dispatch,
            decision,
            trusted_now,
        )?;
        let reservation = self.reserve(dispatch_hash, dispatch.expires_at)?;
        match self.connectors.collect(&lookup.request) {
            Ok(evidence) => {
                reservation.commit()?;
                Ok(CollectedRunnerEvidence {
                    lookup,
                    authentication,
                    evidence,
                })
            }
            Err(error) => {
                reservation.release()?;
                Err(RunnerEngineError::Connector(error))
            }
        }
    }

    /// Authenticates and reconstructs one exact deployment, then stops at the
    /// same non-overridable readiness blockers exported by the native EKS
    /// enforcement path. This method performs no provider write.
    ///
    /// # Errors
    ///
    /// Fails for authentication, replay, policy evaluation, authorization or target binding drift.
    pub fn prepare_production_deployment(
        &self,
        dispatch: &RunnerDispatch,
        decision: &PolicyDecisionRecord,
        authorization: &ExecutionAuthorization,
    ) -> Result<ReadinessBlockedDeployment, RunnerEngineError> {
        let trusted_now = self.trusted_now()?;
        let (prepared, verified_approval) =
            self.prepare_deployment_bindings(dispatch, decision, authorization, trusted_now)?;
        let authentication =
            self.accept_prepared_deployment(dispatch, verified_approval.as_ref(), trusted_now)?;
        Ok(ReadinessBlockedDeployment {
            prepared,
            authentication,
            blockers: production_readiness_blockers(),
        })
    }

    /// Derives the exact bounded Kubernetes PATCH for one authenticated runner
    /// dispatch without loading credentials or contacting a provider.
    ///
    /// The supplied Deployment must serialize to the projection hash committed
    /// by the action authorization and satisfy every Kubernetes precondition.
    /// Successful preparation consumes the same durable dispatch and approval
    /// replay slots as production preparation. The returned execution outcome
    /// is always [`LocalDeploymentExecutionOutcome::NotSent`]. This is a consumed
    /// test dispatch, not a reusable production preview.
    ///
    /// # Errors
    ///
    /// Fails closed for any runner, approval, authorization, snapshot,
    /// Kubernetes projection, authentication, clock, or durable-state error.
    pub fn run_local_deployment_exhibit(
        &self,
        dispatch: &RunnerDispatch,
        decision: &PolicyDecisionRecord,
        authorization: &ExecutionAuthorization,
        current_deployment: &Value,
    ) -> Result<LocalDeploymentExhibit, RunnerEngineError> {
        let trusted_now = self.trusted_now()?;
        let (prepared, verified_approval) =
            self.prepare_deployment_bindings(dispatch, decision, authorization, trusted_now)?;
        let snapshot_bytes = serde_json::to_vec(current_deployment)
            .map_err(|error| RunnerEngineError::DeploymentSnapshotEncoding(error.to_string()))?;
        let snapshot_hash = Digest32::sha256(&snapshot_bytes);
        if snapshot_hash != prepared.proposal.template.prior_projection_hash {
            return Err(RunnerEngineError::DeploymentSnapshotMismatch);
        }
        validate_preconditions(current_deployment, &prepared.proposal.template)?;
        let prepared_patch = prepare_patch(
            &prepared.proposal.template,
            prepared.transaction_id,
            authorization.authorization_id,
        )?;
        let exact_patch_body = patch_wire_body(&prepared_patch)?;
        let authentication =
            self.accept_prepared_deployment(dispatch, verified_approval.as_ref(), trusted_now)?;
        Ok(LocalDeploymentExhibit {
            deployment: ReadinessBlockedDeployment {
                prepared,
                authentication,
                blockers: production_readiness_blockers(),
            },
            snapshot_hash,
            prepared_patch,
            exact_patch_body,
            execution_outcome: LocalDeploymentExecutionOutcome::NotSent,
        })
    }

    fn prepare_deployment_bindings(
        &self,
        dispatch: &RunnerDispatch,
        decision: &PolicyDecisionRecord,
        authorization: &ExecutionAuthorization,
        trusted_now: i64,
    ) -> Result<(PreparedDeployment, Option<VerifiedActionApproval>), RunnerEngineError> {
        let verified_approval =
            self.verify_action_approval(dispatch, decision, authorization, trusted_now)?;
        // Reconstruct and validate every dispatch/decision/authorization binding
        // before channel authentication or provider/effect I/O.
        let prepared = prepare_authorized_deployment_with_approval(
            &self.profile,
            &self.registration,
            dispatch,
            decision,
            authorization,
            verified_approval.as_ref(),
            trusted_now,
        )?;
        Ok((prepared, verified_approval))
    }

    fn accept_prepared_deployment(
        &self,
        dispatch: &RunnerDispatch,
        verified_approval: Option<&VerifiedActionApproval>,
        trusted_now: i64,
    ) -> Result<DispatchAuthentication, RunnerEngineError> {
        let approval_reservation = verified_approval
            .map(|approval| {
                self.reserve_action_approval(approval.signed_hash(), approval.expires_at())
            })
            .transpose()?;
        let dispatch_hash = dispatch.digest(&self.registration)?;
        let authentication = self.authenticate(dispatch_hash, trusted_now)?;
        let reservation = self.reserve(dispatch_hash, dispatch.expires_at)?;
        reservation.commit()?;
        if let Some(reservation) = approval_reservation {
            reservation.commit()?;
        }
        Ok(authentication)
    }

    fn verify_action_approval(
        &self,
        dispatch: &RunnerDispatch,
        decision: &PolicyDecisionRecord,
        authorization: &ExecutionAuthorization,
        trusted_now: i64,
    ) -> Result<Option<VerifiedActionApproval>, RunnerEngineError> {
        let required = decision.decision
            == accordlock_evaluation::EnforcementDecision::RequireApproval
            || (matches!(&dispatch.action, RunnerAction::DeployEksImage { .. })
                && self.profile.autonomy_mode == AutonomyMode::PrepareAndAsk);
        let Some(signed) = dispatch.action_approval.as_ref() else {
            return if required {
                Err(RunnerEngineError::ActionApprovalRequired)
            } else {
                Ok(None)
            };
        };
        let expected = ExpectedActionApprovalBindings {
            task_id: dispatch.task_id,
            task_hash: dispatch.task_hash,
            session_id: &dispatch.session_id,
            principal_id: &dispatch.principal_id,
            runner_id: dispatch.runner_id,
            environment_profile_hash: self.profile.digest()?,
            policy_decision_hash: decision.digest()?,
            action_hash: dispatch.action.digest()?,
            authorization_id: authorization.authorization_id,
            authorization_hash: canonical_hash(authorization)?,
            authorization_evidence_root: authorization.evidence_root,
        };
        Ok(Some(signed.verify(
            &self.action_approval_verifier,
            &expected,
            trusted_now,
        )?))
    }

    fn authenticate(
        &self,
        dispatch_hash: Digest32,
        trusted_now: i64,
    ) -> Result<DispatchAuthentication, RunnerEngineError> {
        let expected = DispatchAuthenticationRequest {
            runner_id: self.registration.runner_id,
            dispatch_hash,
            runner_attestation_hash: self.registration.runner_attestation_hash,
            trusted_now,
        };
        let authenticated = self.authenticator.authenticate(expected)?;
        if authenticated.runner_id != expected.runner_id
            || authenticated.dispatch_hash != expected.dispatch_hash
            || authenticated.runner_attestation_hash != expected.runner_attestation_hash
            || authenticated.authenticated_at != expected.trusted_now
            || authenticated.channel_binding_hash == Digest32::from_bytes([0; 32])
        {
            return Err(RunnerEngineError::AuthenticationBindingMismatch);
        }
        Ok(authenticated)
    }

    fn trusted_now(&self) -> Result<i64, RunnerEngineError> {
        let value = read_trusted_time(self.clock.as_ref())?;
        self.state
            .observe_trusted_time(value)
            .map_err(map_trusted_time_state_error)?;
        Ok(value)
    }

    fn reserve(
        &self,
        dispatch_hash: Digest32,
        retain_until: i64,
    ) -> Result<ReplayReservation, RunnerEngineError> {
        self.reserve_replay(RunnerReplayKind::Dispatch, dispatch_hash, retain_until)
    }

    fn reserve_action_approval(
        &self,
        signed_hash: Digest32,
        retain_until: i64,
    ) -> Result<ReplayReservation, RunnerEngineError> {
        self.reserve_replay(RunnerReplayKind::ActionApproval, signed_hash, retain_until)
    }

    fn reserve_replay(
        &self,
        kind: RunnerReplayKind,
        digest: Digest32,
        retain_until: i64,
    ) -> Result<ReplayReservation, RunnerEngineError> {
        let token = self
            .state
            .reserve(kind, digest, retain_until)
            .map_err(|error| map_replay_state_error(kind, error))?;
        if token.kind() != kind || token.digest() != digest || token.reservation_id().is_nil() {
            return Err(RunnerEngineError::RunnerStateCorrupt);
        }
        Ok(ReplayReservation {
            state: Arc::clone(&self.state),
            token: Some(token),
        })
    }
}

fn read_trusted_time(clock: &dyn TrustedClock) -> Result<i64, RunnerEngineError> {
    let value = clock
        .unix_seconds()
        .map_err(|_| RunnerEngineError::TrustedClockUnavailable)?;
    if value < 0 {
        return Err(RunnerEngineError::TrustedClockUnavailable);
    }
    Ok(value)
}

struct ReplayReservation {
    state: Arc<dyn RunnerStateStore>,
    token: Option<RunnerStateReservation>,
}

impl ReplayReservation {
    fn commit(mut self) -> Result<(), RunnerEngineError> {
        let token = self
            .token
            .take()
            .ok_or(RunnerEngineError::RunnerStateReservationAmbiguous)?;
        self.state
            .commit(&token)
            .map_err(|error| map_replay_state_error(token.kind(), error))
    }

    fn release(mut self) -> Result<(), RunnerEngineError> {
        let token = self
            .token
            .take()
            .ok_or(RunnerEngineError::RunnerStateReservationAmbiguous)?;
        self.state
            .release(&token)
            .map_err(|error| map_replay_state_error(token.kind(), error))
    }
}

impl Drop for ReplayReservation {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            // A normal pre-effect error may release its reservation. If state
            // is unavailable or the result is ambiguous, the retained pending
            // marker continues to fail closed. A finalization attempt always
            // removes the token before I/O and is therefore never undone here.
            let _ = self.state.release(&token);
        }
    }
}

fn map_trusted_time_state_error(error: RunnerStateError) -> RunnerEngineError {
    match error {
        RunnerStateError::ClockRollback => RunnerEngineError::TrustedClockRollback,
        RunnerStateError::Corrupt => RunnerEngineError::RunnerStateCorrupt,
        RunnerStateError::ReservationAmbiguous => {
            RunnerEngineError::RunnerStateReservationAmbiguous
        }
        RunnerStateError::Unavailable
        | RunnerStateError::InvalidConfiguration
        | RunnerStateError::AlreadyReserved
        | RunnerStateError::CapacityExceeded => RunnerEngineError::TrustedClockStateUnavailable,
    }
}

fn map_replay_state_error(kind: RunnerReplayKind, error: RunnerStateError) -> RunnerEngineError {
    match error {
        RunnerStateError::AlreadyReserved => match kind {
            RunnerReplayKind::Dispatch => RunnerEngineError::DispatchReplay,
            RunnerReplayKind::ActionApproval => RunnerEngineError::ActionApprovalReplay,
        },
        RunnerStateError::CapacityExceeded => RunnerEngineError::ReplayCapacityExceeded,
        RunnerStateError::ReservationAmbiguous => {
            RunnerEngineError::RunnerStateReservationAmbiguous
        }
        RunnerStateError::Corrupt => RunnerEngineError::RunnerStateCorrupt,
        RunnerStateError::Unavailable | RunnerStateError::InvalidConfiguration => match kind {
            RunnerReplayKind::Dispatch => RunnerEngineError::ReplayStateUnavailable,
            RunnerReplayKind::ActionApproval => {
                RunnerEngineError::ActionApprovalReplayStateUnavailable
            }
        },
        RunnerStateError::ClockRollback => RunnerEngineError::TrustedClockRollback,
    }
}

#[derive(Debug, Error)]
pub enum RunnerEngineError {
    #[error("runner protocol validation failed: {0}")]
    RunnerProtocol(#[from] RunnerProtocolError),
    #[error("runner bridge validation failed: {0}")]
    RunnerBridge(#[from] RunnerBridgeError),
    #[error("canonical AccordLock encoding failed: {0}")]
    Canonical(#[from] accordlock_protocol::CanonicalError),
    #[error("policy evaluation validation failed: {0}")]
    Evaluation(#[from] accordlock_evaluation::PolicyEvaluationError),
    #[error("dispatch authentication failed: {0}")]
    Authentication(#[from] DispatchAuthenticationError),
    #[error("authenticated channel did not bind the exact runner dispatch")]
    AuthenticationBindingMismatch,
    #[error("runner enrollment does not bind this environment profile")]
    EnvironmentBindingMismatch,
    #[error("connector runtime commitment does not match the environment profile")]
    ConnectorCommitmentMismatch,
    #[error("AWS transport/authenticator identity does not match the environment profile")]
    AwsIdentityCommitmentMismatch,
    #[error("action approval verifier does not match the environment profile")]
    ActionApprovalAuthorityMismatch,
    #[error("policy decision requires a verified action approval")]
    VerifiedActionApprovalRequired,
    #[error("approval-gated observation requires a separately bound authorization")]
    ActionApprovalRequired,
    #[error("action approval validation failed: {0}")]
    ActionApproval(#[from] ActionApprovalError),
    #[error("action approval was already accepted")]
    ActionApprovalReplay,
    #[error("action approval replay state is unavailable")]
    ActionApprovalReplayStateUnavailable,
    #[error("runner dispatch was already accepted")]
    DispatchReplay,
    #[error("runner replay state is unavailable")]
    ReplayStateUnavailable,
    #[error("runner replay quota is exhausted")]
    ReplayCapacityExceeded,
    #[error("runner trusted clock is unavailable or invalid")]
    TrustedClockUnavailable,
    #[error("runner trusted clock moved backwards")]
    TrustedClockRollback,
    #[error("runner trusted-clock high-water state is unavailable")]
    TrustedClockStateUnavailable,
    #[error("runner state is corrupt or has an unsupported schema")]
    RunnerStateCorrupt,
    #[error("runner replay reservation has an ambiguous lifecycle")]
    RunnerStateReservationAmbiguous,
    #[error("trusted connector collection failed: {0}")]
    Connector(#[from] accordlock_connectors::ConnectorError),
    #[error("Kubernetes deployment snapshot does not match the authorized projection")]
    DeploymentSnapshotMismatch,
    #[error("Kubernetes deployment snapshot could not be encoded: {0}")]
    DeploymentSnapshotEncoding(String),
    #[error("Kubernetes deployment request is invalid: {0}")]
    KubernetesProjection(#[from] accordlock_k8s::ProjectionError),
}

/// Commits to the exact public AWS identities used by the ECR transport,
/// Kubernetes transport and dispatch-channel authenticator.
#[must_use]
pub fn aws_identity_commitment(
    aws_account_id: &str,
    aws_region: &str,
    ecr_transport_identity_hash: Digest32,
    kubernetes_transport_identity_hash: Digest32,
    dispatch_authenticator_identity_hash: Digest32,
) -> Digest32 {
    const DOMAIN: &[u8] = b"accordlock:v2:aws-runner-identity";
    let mut hash = Sha256::new();
    commit_identity_bytes(&mut hash, DOMAIN);
    commit_identity_bytes(&mut hash, aws_account_id.as_bytes());
    commit_identity_bytes(&mut hash, aws_region.as_bytes());
    hash.update(ecr_transport_identity_hash.as_bytes());
    hash.update(kubernetes_transport_identity_hash.as_bytes());
    hash.update(dispatch_authenticator_identity_hash.as_bytes());
    Digest32::from_bytes(hash.finalize().into())
}

fn commit_identity_bytes(hash: &mut Sha256, value: &[u8]) {
    hash.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hash.update(value);
}

#[cfg(test)]
mod tests;
