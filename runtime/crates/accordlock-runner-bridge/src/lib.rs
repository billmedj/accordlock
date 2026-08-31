//! Deterministic bridge from runner dispatches to trusted `AccordLock` inputs.

#![forbid(unsafe_code)]

use accordlock_connectors::{
    ArtifactLookupId, BuildLookupId, EvidenceLookupRequest, ReviewLookupId, TargetLookupId,
};
use accordlock_evaluation::{EnforcementDecision, PolicyDecisionRecord, PolicyEvaluationError};
use accordlock_protocol::{
    AgentProposal, CanonicalEncode, DeploymentTemplate, Digest32, ExecutionAuthorization,
    canonical_hash,
};
use accordlock_runner_protocol::{
    AutonomyMode, EnterpriseEnvironmentProfile, RunnerAction, RunnerDispatch, RunnerProtocolError,
    RunnerRegistration, VerifiedActionApproval,
};
use thiserror::Error;

pub const DEPLOY_EKS_IMAGE_OPERATION_V1: &str = "DEPLOY_EKS_IMAGE_V1";
pub const AGENT_PROPOSAL_SCHEMA_VERSION: u16 = 1;

/// Lookup-only request plus the commitments needed by an audit ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedEvidenceLookup {
    pub request: EvidenceLookupRequest,
    pub environment_profile_hash: Digest32,
    pub runner_registration_hash: Digest32,
    pub runner_dispatch_hash: Digest32,
    pub policy_decision_hash: Digest32,
}

/// Exact core proposal reconstructed from a credential-free dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedDeployment {
    pub proposal: AgentProposal,
    /// State-created transaction identifier committed by the runner action.
    pub transaction_id: uuid::Uuid,
    pub template_hash: Digest32,
    pub authorization_hash: Digest32,
    pub runner_dispatch_hash: Digest32,
    pub policy_decision_hash: Digest32,
}

/// Converts the observation action into the only caller-controlled shape
/// accepted by the trusted connector runtime.
///
/// # Errors
///
/// Fails closed when profile, enrollment, dispatch or any lookup identifier is
/// invalid, or when the dispatch carries an effect-producing action.
pub fn prepare_evidence_lookup(
    profile: &EnterpriseEnvironmentProfile,
    registration: &RunnerRegistration,
    dispatch: &RunnerDispatch,
    decision: &PolicyDecisionRecord,
    trusted_now: i64,
) -> Result<PreparedEvidenceLookup, RunnerBridgeError> {
    let bindings = validate_bindings(profile, registration, dispatch, decision, None, trusted_now)?;
    let RunnerAction::ObserveSupplyChain {
        review_lookup_id,
        build_lookup_id,
        artifact_lookup_id,
        target_lookup_id,
    } = &dispatch.action
    else {
        return Err(RunnerBridgeError::WrongAction);
    };
    let request = EvidenceLookupRequest::new(
        dispatch.dispatch_id,
        ReviewLookupId::parse(review_lookup_id.clone())?,
        BuildLookupId::parse(build_lookup_id.clone())?,
        ArtifactLookupId::parse(artifact_lookup_id.clone())?,
        TargetLookupId::parse(target_lookup_id.clone())?,
    );
    Ok(PreparedEvidenceLookup {
        request,
        environment_profile_hash: bindings.profile,
        runner_registration_hash: bindings.registration,
        runner_dispatch_hash: bindings.dispatch,
        policy_decision_hash: bindings.evaluation,
    })
}

/// Reconstructs the EKS operation and proves that the signed-authorization payload
/// authorizes exactly that operation. Signature verification and atomic
/// single-use consumption remain mandatory responsibilities of the existing
/// `AccordLock` broker immediately after this pure boundary.
///
/// # Errors
///
/// Fails closed for any enrollment drift, target substitution, authorization
/// substitution, identity mismatch, invalid canonical form, or time mismatch.
pub fn prepare_authorized_deployment_with_approval(
    profile: &EnterpriseEnvironmentProfile,
    registration: &RunnerRegistration,
    dispatch: &RunnerDispatch,
    decision: &PolicyDecisionRecord,
    authorization: &ExecutionAuthorization,
    action_approval: Option<&VerifiedActionApproval>,
    trusted_now: i64,
) -> Result<PreparedDeployment, RunnerBridgeError> {
    if action_approval
        .is_some_and(|approval| approval.authority_hash() != profile.action_approval_authority_hash)
    {
        return Err(RunnerBridgeError::ActionApprovalAuthorityMismatch);
    }
    let bindings = validate_bindings(
        profile,
        registration,
        dispatch,
        decision,
        action_approval,
        trusted_now,
    )?;
    if action_approval.is_some_and(|approval| {
        approval.authorization_evidence_root() != authorization.evidence_root
    }) {
        return Err(RunnerBridgeError::ActionApprovalEvidenceRootMismatch);
    }
    let RunnerAction::DeployEksImage {
        transaction_id,
        commit_sha,
        image_digest,
        deployment_uid,
        resource_version,
        container_index,
        prior_image_digest,
        prior_projection_hash,
        prior_transaction_annotation,
        prior_authorization_annotation,
        prior_operation_hash_annotation,
    } = &dispatch.action
    else {
        return Err(RunnerBridgeError::WrongAction);
    };

    let template = DeploymentTemplate {
        operation: DEPLOY_EKS_IMAGE_OPERATION_V1.to_owned(),
        environment: profile.environment_id.clone(),
        audience: profile.executor_audience.clone(),
        repository: profile.github_repository.clone(),
        commit_sha: commit_sha.clone(),
        image_repository: profile.ecr_image_repository(),
        image_digest: *image_digest,
        cluster_identity: profile.eks_cluster_identity(),
        namespace: profile.kubernetes_namespace.clone(),
        deployment: profile.kubernetes_deployment.clone(),
        deployment_uid: deployment_uid.clone(),
        container: profile.kubernetes_container.clone(),
        container_index: *container_index,
        prior_image_digest: *prior_image_digest,
        resource_version: resource_version.clone(),
        prior_projection_hash: *prior_projection_hash,
        prior_transaction_annotation: prior_transaction_annotation.clone(),
        prior_authorization_annotation: prior_authorization_annotation.clone(),
        prior_operation_hash_annotation: prior_operation_hash_annotation.clone(),
    };
    let template_hash = canonical_hash(&template)?;
    let authorization_hash = canonical_hash(authorization)?;

    if dispatch.authorization_id != authorization.authorization_id
        || dispatch.authorization_hash != authorization_hash
        || authorization.request_id != dispatch.dispatch_id
        || authorization.tenant != profile.organization_id
        || authorization.holder != dispatch.principal_id
        || authorization.audience != profile.executor_audience
        || authorization.template != template
        || authorization.template_hash != template_hash
        || dispatch.created_at < authorization.not_before
        || dispatch.expires_at > authorization.consume_before
    {
        return Err(RunnerBridgeError::AuthorizationBindingMismatch);
    }

    let proposal = AgentProposal {
        schema_version: AGENT_PROPOSAL_SCHEMA_VERSION,
        request_id: dispatch.dispatch_id,
        tenant: profile.organization_id.clone(),
        actor: dispatch.principal_id.clone(),
        template,
    };
    let _ = proposal.canonical_bytes()?;
    Ok(PreparedDeployment {
        proposal,
        transaction_id: *transaction_id,
        template_hash,
        authorization_hash,
        runner_dispatch_hash: bindings.dispatch,
        policy_decision_hash: bindings.evaluation,
    })
}

/// Compatibility entry point for effects which do not require human approval.
///
/// Approval-gated callers must use the approval-aware entry point with a verified,
/// non-serializable proof.
///
/// # Errors
///
/// Returns the same fail-closed validation errors as the approval-aware entry
/// point; approval-gated calls are rejected because this wrapper supplies none.
pub fn prepare_authorized_deployment(
    profile: &EnterpriseEnvironmentProfile,
    registration: &RunnerRegistration,
    dispatch: &RunnerDispatch,
    decision: &PolicyDecisionRecord,
    authorization: &ExecutionAuthorization,
    trusted_now: i64,
) -> Result<PreparedDeployment, RunnerBridgeError> {
    prepare_authorized_deployment_with_approval(
        profile,
        registration,
        dispatch,
        decision,
        authorization,
        None,
        trusted_now,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Bindings {
    profile: Digest32,
    registration: Digest32,
    dispatch: Digest32,
    evaluation: Digest32,
}

fn validate_bindings(
    profile: &EnterpriseEnvironmentProfile,
    registration: &RunnerRegistration,
    dispatch: &RunnerDispatch,
    decision: &PolicyDecisionRecord,
    action_approval: Option<&VerifiedActionApproval>,
    trusted_now: i64,
) -> Result<Bindings, RunnerBridgeError> {
    profile.validate_at(trusted_now)?;
    registration.validate_at(trusted_now)?;
    dispatch.validate_at(registration, trusted_now)?;
    let profile_hash = profile.digest()?;
    let registration_hash = registration.digest()?;
    let dispatch_hash = dispatch.digest(registration)?;
    if registration.organization_id != profile.organization_id
        || registration.environment_id != profile.environment_id
        || registration.environment_profile_hash != profile_hash
        || dispatch.environment_profile_hash != profile_hash
        || dispatch.runner_registration_hash != registration_hash
    {
        return Err(RunnerBridgeError::EnvironmentBindingMismatch);
    }
    let evaluation_hash = decision.digest()?;
    if evaluation_hash != dispatch.policy_decision_hash {
        return Err(RunnerBridgeError::EvaluationDigestMismatch);
    }
    if decision.task_hash != dispatch.task_hash {
        return Err(RunnerBridgeError::EvaluationTaskMismatch);
    }
    if decision.action_hash != dispatch.action.digest()? {
        return Err(RunnerBridgeError::EvaluationActionMismatch);
    }
    if decision.policy_epoch != profile.policy_epoch {
        return Err(RunnerBridgeError::EvaluationPolicyEpochMismatch);
    }
    if decision
        .resource_reservation_hashes
        .binary_search(&dispatch.resource_reservation_hash)
        .is_err()
    {
        return Err(RunnerBridgeError::EvaluationReservationMismatch);
    }
    validate_autonomy(profile, dispatch, decision.decision, action_approval)?;
    Ok(Bindings {
        profile: profile_hash,
        registration: registration_hash,
        dispatch: dispatch_hash,
        evaluation: evaluation_hash,
    })
}

fn validate_autonomy(
    profile: &EnterpriseEnvironmentProfile,
    dispatch: &RunnerDispatch,
    decision: EnforcementDecision,
    action_approval: Option<&VerifiedActionApproval>,
) -> Result<(), RunnerBridgeError> {
    if decision == EnforcementDecision::Deny {
        return Err(RunnerBridgeError::EvaluationBlocked);
    }
    let performs_external_action = matches!(&dispatch.action, RunnerAction::DeployEksImage { .. });
    if performs_external_action && profile.autonomy_mode == AutonomyMode::Observe {
        return Err(RunnerBridgeError::ObserveModeActionForbidden);
    }
    if decision == EnforcementDecision::RequireApproval && action_approval.is_none() {
        return Err(RunnerBridgeError::ActionApprovalRequired);
    }
    if performs_external_action
        && profile.autonomy_mode == AutonomyMode::PrepareAndAsk
        && action_approval.is_none()
    {
        return Err(RunnerBridgeError::PrepareAndAskActionApprovalRequired);
    }
    // DENY returned above and REQUIRE_APPROVAL without an approval returned above;
    // therefore a bounded-automation external action without an approval can only
    // be ALLOW.
    Ok(())
}

#[derive(Debug, Error)]
pub enum RunnerBridgeError {
    #[error("runner protocol validation failed: {0}")]
    RunnerProtocol(#[from] RunnerProtocolError),
    #[error("connector lookup validation failed: {0}")]
    Connector(#[from] accordlock_connectors::ConnectorError),
    #[error("canonical AccordLock encoding failed: {0}")]
    Canonical(#[from] accordlock_protocol::CanonicalError),
    #[error("policy evaluation validation failed: {0}")]
    Evaluation(#[from] PolicyEvaluationError),
    #[error("runner enrollment does not match the environment profile")]
    EnvironmentBindingMismatch,
    #[error("runner dispatch carries the wrong action for this bridge")]
    WrongAction,
    #[error("single-use action authorization does not bind the exact runner dispatch")]
    AuthorizationBindingMismatch,
    #[error("runner dispatch does not commit to the supplied policy evaluation decision")]
    EvaluationDigestMismatch,
    #[error("policy evaluation decision does not bind the runner task")]
    EvaluationTaskMismatch,
    #[error("policy evaluation decision does not bind the exact runner action")]
    EvaluationActionMismatch,
    #[error("policy evaluation decision was produced under another policy epoch")]
    EvaluationPolicyEpochMismatch,
    #[error("runner resource reservation is absent from the policy evaluation decision")]
    EvaluationReservationMismatch,
    #[error("policy evaluation blocks this runner dispatch")]
    EvaluationBlocked,
    #[error("policy evaluation requires an exact signed action approval")]
    ActionApprovalRequired,
    #[error("prepare-and-ask mode requires an action approval before an external action")]
    PrepareAndAskActionApprovalRequired,
    #[error("action approval evidence does not equal the authorization evidence root")]
    ActionApprovalEvidenceRootMismatch,
    #[error("verified action approval came from an authority outside the environment profile")]
    ActionApprovalAuthorityMismatch,
    #[error("observe mode forbids effect-producing runner actions")]
    ObserveModeActionForbidden,
}

#[cfg(test)]
mod tests {
    use super::*;
    use accordlock_evaluation::{
        DecisionReason, EnforcementDecision, POLICY_DECISION_SCHEMA_VERSION, PolicyDecisionRecord,
    };
    use accordlock_protocol::{
        AuthorityDomainState, AuthorityVector, DispatchDeadlinePolicy,
        EXECUTION_AUTHORIZATION_SCHEMA_VERSION, SigningIdentity,
    };
    use accordlock_runner_protocol::{
        ACTION_APPROVAL_SCHEMA_VERSION, ActionApprovalAttestation, ApprovalDecision, AutonomyMode,
        EnvironmentTier, ExpectedActionApprovalBindings, RUNNER_PROTOCOL_SCHEMA_VERSION,
        RunnerCapability, SignedActionApproval, action_approval_authority_commitment,
    };
    use uuid::Uuid;

    const NOW: i64 = 1_900_000_000;

    fn digest(seed: u8) -> Digest32 {
        Digest32::from_bytes([seed; 32])
    }

    fn approval_signer(seed: u8) -> SigningIdentity {
        SigningIdentity::from_seed("action-approval-key", [seed; 32])
    }

    fn trusted_approval_signer() -> SigningIdentity {
        approval_signer(0xb1)
    }

    fn profile() -> EnterpriseEnvironmentProfile {
        EnterpriseEnvironmentProfile {
            schema_version: RUNNER_PROTOCOL_SCHEMA_VERSION,
            profile_id: Uuid::from_bytes([1; 16]),
            organization_id: "acme".to_owned(),
            environment_id: "payments-staging".to_owned(),
            tier: EnvironmentTier::Staging,
            autonomy_mode: AutonomyMode::BoundedAutomatic,
            production_autonomy_approval_hash: None,
            executor_audience: "accordlock-eks-executor".to_owned(),
            github_repository: "acme/payments".to_owned(),
            github_workflow_ref: ".github/workflows/release.yml@refs/heads/main".to_owned(),
            aws_account_id: "111122223333".to_owned(),
            aws_region: "eu-west-1".to_owned(),
            ecr_repository: "acme/payments".to_owned(),
            eks_cluster_name: "staging-a".to_owned(),
            kubernetes_namespace: "payments".to_owned(),
            kubernetes_deployment: "payments-api".to_owned(),
            kubernetes_container: "application".to_owned(),
            policy_hash: digest(1),
            policy_epoch: 1,
            github_connector_hash: digest(2),
            aws_identity_hash: digest(3),
            ecr_connector_hash: digest(4),
            kubernetes_connector_hash: digest(5),
            action_approval_authority_hash: action_approval_authority_commitment(
                &trusted_approval_signer().verifier(),
            ),
            created_at: NOW,
            expires_at: NOW + 86_400,
        }
    }

    fn registration(profile_hash: Digest32) -> RunnerRegistration {
        RunnerRegistration {
            schema_version: RUNNER_PROTOCOL_SCHEMA_VERSION,
            runner_id: Uuid::from_bytes([2; 16]),
            organization_id: "acme".to_owned(),
            environment_id: "payments-staging".to_owned(),
            environment_profile_hash: profile_hash,
            runner_attestation_hash: digest(6),
            capabilities: vec![
                RunnerCapability::ObserveGithub,
                RunnerCapability::ObserveEcr,
                RunnerCapability::ObserveKubernetes,
                RunnerCapability::DeployEksImage,
            ],
            enrolled_at: NOW,
            expires_at: NOW + 3_600,
        }
    }

    fn authority() -> AuthorityVector {
        let state = AuthorityDomainState {
            root: digest(20),
            epoch: 1,
            activation_id: Uuid::from_bytes([20; 16]),
        };
        AuthorityVector {
            policy: state.clone(),
            registry: state.clone(),
            revocation: state.clone(),
            connector: state.clone(),
            resource: state.clone(),
            signer: state.clone(),
            mediation: state.clone(),
            grant_registry: state.clone(),
            office_act_registry: state.clone(),
            principal_registry: state.clone(),
            workload_build_allowlist: state.clone(),
            kernel_configuration: state,
        }
    }

    fn template(profile: &EnterpriseEnvironmentProfile) -> DeploymentTemplate {
        DeploymentTemplate {
            operation: DEPLOY_EKS_IMAGE_OPERATION_V1.to_owned(),
            environment: profile.environment_id.clone(),
            audience: profile.executor_audience.clone(),
            repository: profile.github_repository.clone(),
            commit_sha: "a".repeat(40),
            image_repository: profile.ecr_image_repository(),
            image_digest: digest(10),
            cluster_identity: profile.eks_cluster_identity(),
            namespace: profile.kubernetes_namespace.clone(),
            deployment: profile.kubernetes_deployment.clone(),
            deployment_uid: "11111111-2222-4333-8444-555555555555".to_owned(),
            container: profile.kubernetes_container.clone(),
            container_index: 0,
            prior_image_digest: digest(11),
            resource_version: "83191".to_owned(),
            prior_projection_hash: digest(12),
            prior_transaction_annotation: None,
            prior_authorization_annotation: None,
            prior_operation_hash_annotation: None,
        }
    }

    fn authorization(
        profile: &EnterpriseEnvironmentProfile,
        request_id: Uuid,
    ) -> Result<ExecutionAuthorization, accordlock_protocol::CanonicalError> {
        let template = template(profile);
        Ok(ExecutionAuthorization {
            schema_version: EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
            authorization_id: Uuid::from_bytes([5; 16]),
            evaluation_nonce: Uuid::from_bytes([7; 16]),
            request_id,
            tenant: profile.organization_id.clone(),
            holder: "user:alice@example.com".to_owned(),
            audience: profile.executor_audience.clone(),
            issued_at: NOW + 5,
            not_before: NOW + 5,
            consume_before: NOW + 120,
            dispatch_deadline_policy: DispatchDeadlinePolicy {
                max_dispatch_delay_seconds: 60,
                profile_hard_cap: NOW + 120,
                immutable_dependency_expiries: vec![NOW + 120],
            },
            grant_id: Uuid::from_bytes([8; 16]),
            template_hash: canonical_hash(&template)?,
            template,
            evidence_root: digest(21),
            principals: vec!["user:alice@example.com".to_owned()],
            policy_root: profile.policy_hash,
            authority: authority(),
        })
    }

    fn deployment_dispatch(
        profile: &EnterpriseEnvironmentProfile,
        registration: &RunnerRegistration,
        authorization: &ExecutionAuthorization,
    ) -> Result<RunnerDispatch, Box<dyn std::error::Error>> {
        Ok(RunnerDispatch {
            schema_version: RUNNER_PROTOCOL_SCHEMA_VERSION,
            dispatch_id: authorization.request_id,
            task_id: Uuid::from_bytes([4; 16]),
            task_hash: digest(18),
            session_id: "session-1".to_owned(),
            principal_id: authorization.holder.clone(),
            runner_id: registration.runner_id,
            environment_profile_hash: profile.digest()?,
            runner_registration_hash: registration.digest()?,
            policy_decision_hash: digest(7),
            resource_reservation_hash: digest(8),
            authorization_id: authorization.authorization_id,
            authorization_hash: canonical_hash(authorization)?,
            action_approval: None,
            action: RunnerAction::DeployEksImage {
                transaction_id: Uuid::from_bytes([6; 16]),
                commit_sha: authorization.template.commit_sha.clone(),
                image_digest: authorization.template.image_digest,
                deployment_uid: authorization.template.deployment_uid.clone(),
                resource_version: authorization.template.resource_version.clone(),
                container_index: authorization.template.container_index,
                prior_image_digest: authorization.template.prior_image_digest,
                prior_projection_hash: authorization.template.prior_projection_hash,
                prior_transaction_annotation: None,
                prior_authorization_annotation: None,
                prior_operation_hash_annotation: None,
            },
            created_at: NOW + 10,
            expires_at: NOW + 70,
        })
    }

    fn bind_decision(
        profile: &EnterpriseEnvironmentProfile,
        dispatch: &mut RunnerDispatch,
        baseline_decision: EnforcementDecision,
        decision: EnforcementDecision,
        reasons: Vec<DecisionReason>,
    ) -> Result<PolicyDecisionRecord, Box<dyn std::error::Error>> {
        let decision = PolicyDecisionRecord {
            schema_version: POLICY_DECISION_SCHEMA_VERSION,
            decision_id: Uuid::from_bytes([30; 16]),
            task_hash: dispatch.task_hash,
            action_hash: dispatch.action.digest()?,
            sequence: 0,
            parent_decision_hash: None,
            requirement_hashes: vec![digest(30)],
            transformation_step_hashes: vec![digest(31)],
            conformance_evaluation_hashes: vec![digest(32)],
            resource_request_hashes: vec![digest(33)],
            resource_quota_hashes: vec![digest(34)],
            resource_reservation_hashes: vec![dispatch.resource_reservation_hash],
            baseline_decision,
            decision,
            reasons,
            policy_epoch: profile.policy_epoch,
            evaluated_at: dispatch.created_at - 1,
        };
        dispatch.policy_decision_hash = decision.digest()?;
        Ok(decision)
    }

    fn verified_approval(
        profile: &EnterpriseEnvironmentProfile,
        dispatch: &RunnerDispatch,
        decision: &PolicyDecisionRecord,
        authorization: &ExecutionAuthorization,
        signer: &SigningIdentity,
    ) -> Result<VerifiedActionApproval, Box<dyn std::error::Error>> {
        let attestation = ActionApprovalAttestation {
            schema_version: ACTION_APPROVAL_SCHEMA_VERSION,
            approval_id: Uuid::new_v4(),
            task_id: dispatch.task_id,
            task_hash: dispatch.task_hash,
            session_id: dispatch.session_id.clone(),
            principal_id: dispatch.principal_id.clone(),
            approver_id: "approver:bob".to_owned(),
            runner_id: dispatch.runner_id,
            environment_profile_hash: profile.digest()?,
            policy_decision_hash: decision.digest()?,
            action_hash: dispatch.action.digest()?,
            authorization_id: authorization.authorization_id,
            authorization_hash: canonical_hash(authorization)?,
            authorization_evidence_root: authorization.evidence_root,
            decision: ApprovalDecision::Approved,
            issued_at: NOW + 10,
            expires_at: NOW + 60,
            key_id: signer.key_id().to_owned(),
        };
        let signed_approval = SignedActionApproval::sign(attestation, signer)?;
        let expected = ExpectedActionApprovalBindings {
            task_id: dispatch.task_id,
            task_hash: dispatch.task_hash,
            session_id: &dispatch.session_id,
            principal_id: &dispatch.principal_id,
            runner_id: dispatch.runner_id,
            environment_profile_hash: profile.digest()?,
            policy_decision_hash: decision.digest()?,
            action_hash: dispatch.action.digest()?,
            authorization_id: authorization.authorization_id,
            authorization_hash: canonical_hash(authorization)?,
            authorization_evidence_root: authorization.evidence_root,
        };
        Ok(signed_approval.verify(&signer.verifier(), &expected, NOW + 20)?)
    }

    fn deployment_fixture(
        autonomy_mode: AutonomyMode,
        _approval_requested: Option<Digest32>,
    ) -> Result<
        (
            EnterpriseEnvironmentProfile,
            RunnerRegistration,
            ExecutionAuthorization,
            RunnerDispatch,
        ),
        Box<dyn std::error::Error>,
    > {
        let mut profile = profile();
        profile.autonomy_mode = autonomy_mode;
        let registration = registration(profile.digest()?);
        let authorization = authorization(&profile, Uuid::from_bytes([3; 16]))?;
        let dispatch = deployment_dispatch(&profile, &registration, &authorization)?;
        Ok((profile, registration, authorization, dispatch))
    }

    #[test]
    fn observation_becomes_lookup_only_connector_input() -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile();
        let registration = registration(profile.digest()?);
        let mut dispatch = RunnerDispatch {
            schema_version: RUNNER_PROTOCOL_SCHEMA_VERSION,
            dispatch_id: Uuid::from_bytes([3; 16]),
            task_id: Uuid::from_bytes([4; 16]),
            task_hash: digest(18),
            session_id: "session-1".to_owned(),
            principal_id: "user:alice@example.com".to_owned(),
            runner_id: registration.runner_id,
            environment_profile_hash: profile.digest()?,
            runner_registration_hash: registration.digest()?,
            policy_decision_hash: digest(7),
            resource_reservation_hash: digest(8),
            authorization_id: Uuid::from_bytes([5; 16]),
            authorization_hash: digest(9),
            action_approval: None,
            action: RunnerAction::ObserveSupplyChain {
                review_lookup_id: "approval-42".to_owned(),
                build_lookup_id: "run-314".to_owned(),
                artifact_lookup_id: "sha256-image".to_owned(),
                target_lookup_id: "payments-staging".to_owned(),
            },
            created_at: NOW + 10,
            expires_at: NOW + 70,
        };
        let decision = bind_decision(
            &profile,
            &mut dispatch,
            EnforcementDecision::Allow,
            EnforcementDecision::Allow,
            vec![DecisionReason::RequirementSatisfied],
        )?;
        let prepared =
            prepare_evidence_lookup(&profile, &registration, &dispatch, &decision, NOW + 20)?;
        assert_eq!(prepared.request.request_id, dispatch.dispatch_id);
        assert_eq!(prepared.request.review_lookup_id.as_str(), "approval-42");
        assert_eq!(prepared.policy_decision_hash, decision.digest()?);
        Ok(())
    }

    #[test]
    fn runner_handoff_resamples_trusted_time() -> Result<(), Box<dyn std::error::Error>> {
        let (profile, registration, authorization, mut dispatch) =
            deployment_fixture(AutonomyMode::BoundedAutomatic, None)?;
        let decision = bind_decision(
            &profile,
            &mut dispatch,
            EnforcementDecision::Allow,
            EnforcementDecision::Allow,
            vec![DecisionReason::RequirementSatisfied],
        )?;

        for invalid_now in [NOW + 9, NOW + 70] {
            assert!(matches!(
                prepare_authorized_deployment(
                    &profile,
                    &registration,
                    &dispatch,
                    &decision,
                    &authorization,
                    invalid_now,
                ),
                Err(RunnerBridgeError::RunnerProtocol(
                    RunnerProtocolError::NotCurrent("runner dispatch")
                ))
            ));
        }
        Ok(())
    }

    #[test]
    fn deployment_must_match_every_authorization_bound_target_field()
    -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile();
        let registration = registration(profile.digest()?);
        let authorization = authorization(&profile, Uuid::from_bytes([3; 16]))?;
        let mut dispatch = deployment_dispatch(&profile, &registration, &authorization)?;
        let decision = bind_decision(
            &profile,
            &mut dispatch,
            EnforcementDecision::Allow,
            EnforcementDecision::Allow,
            vec![
                DecisionReason::RequirementSatisfied,
                DecisionReason::ResourceReservationConfirmed,
            ],
        )?;
        let prepared = prepare_authorized_deployment(
            &profile,
            &registration,
            &dispatch,
            &decision,
            &authorization,
            NOW + 20,
        )?;
        assert_eq!(prepared.proposal.template, authorization.template);
        assert_eq!(prepared.transaction_id, Uuid::from_bytes([6; 16]));

        let mut substituted = dispatch;
        if let RunnerAction::DeployEksImage {
            resource_version, ..
        } = &mut substituted.action
        {
            *resource_version = "83192".to_owned();
        }
        assert!(matches!(
            prepare_authorized_deployment(
                &profile,
                &registration,
                &substituted,
                &decision,
                &authorization,
                NOW + 20,
            ),
            Err(RunnerBridgeError::EvaluationActionMismatch)
        ));
        Ok(())
    }

    #[test]
    fn substituted_evaluation_and_task_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let (profile, registration, authorization, mut dispatch) =
            deployment_fixture(AutonomyMode::BoundedAutomatic, None)?;
        let mut decision = bind_decision(
            &profile,
            &mut dispatch,
            EnforcementDecision::Allow,
            EnforcementDecision::Allow,
            vec![DecisionReason::RequirementSatisfied],
        )?;

        decision.conformance_evaluation_hashes = vec![digest(99)];
        assert!(matches!(
            prepare_authorized_deployment(
                &profile,
                &registration,
                &dispatch,
                &decision,
                &authorization,
                NOW + 20,
            ),
            Err(RunnerBridgeError::EvaluationDigestMismatch)
        ));

        decision.task_hash = digest(98);
        dispatch.policy_decision_hash = decision.digest()?;
        assert!(matches!(
            prepare_authorized_deployment(
                &profile,
                &registration,
                &dispatch,
                &decision,
                &authorization,
                NOW + 20,
            ),
            Err(RunnerBridgeError::EvaluationTaskMismatch)
        ));
        Ok(())
    }

    #[test]
    fn policy_epoch_and_resource_reservation_are_exactly_bound()
    -> Result<(), Box<dyn std::error::Error>> {
        let (profile, registration, authorization, mut dispatch) =
            deployment_fixture(AutonomyMode::BoundedAutomatic, None)?;
        let mut decision = bind_decision(
            &profile,
            &mut dispatch,
            EnforcementDecision::Allow,
            EnforcementDecision::Allow,
            vec![DecisionReason::RequirementSatisfied],
        )?;

        decision.policy_epoch += 1;
        dispatch.policy_decision_hash = decision.digest()?;
        assert!(matches!(
            prepare_authorized_deployment(
                &profile,
                &registration,
                &dispatch,
                &decision,
                &authorization,
                NOW + 20,
            ),
            Err(RunnerBridgeError::EvaluationPolicyEpochMismatch)
        ));

        decision.policy_epoch = profile.policy_epoch;
        decision.resource_reservation_hashes = vec![digest(99)];
        dispatch.policy_decision_hash = decision.digest()?;
        assert!(matches!(
            prepare_authorized_deployment(
                &profile,
                &registration,
                &dispatch,
                &decision,
                &authorization,
                NOW + 20,
            ),
            Err(RunnerBridgeError::EvaluationReservationMismatch)
        ));
        Ok(())
    }

    #[test]
    fn blocked_evaluation_refuses_even_with_action_approval()
    -> Result<(), Box<dyn std::error::Error>> {
        let (profile, registration, authorization, mut dispatch) =
            deployment_fixture(AutonomyMode::PrepareAndAsk, Some(digest(19)))?;
        let decision = bind_decision(
            &profile,
            &mut dispatch,
            EnforcementDecision::Allow,
            EnforcementDecision::Deny,
            vec![DecisionReason::RequirementViolated],
        )?;
        assert!(matches!(
            prepare_authorized_deployment(
                &profile,
                &registration,
                &dispatch,
                &decision,
                &authorization,
                NOW + 20,
            ),
            Err(RunnerBridgeError::EvaluationBlocked)
        ));
        Ok(())
    }

    #[test]
    fn policy_decision_requires_an_action_approval() -> Result<(), Box<dyn std::error::Error>> {
        let (profile, registration, authorization, mut dispatch) =
            deployment_fixture(AutonomyMode::BoundedAutomatic, None)?;
        let decision = bind_decision(
            &profile,
            &mut dispatch,
            EnforcementDecision::Allow,
            EnforcementDecision::RequireApproval,
            vec![DecisionReason::ConformanceInconclusive],
        )?;
        assert!(matches!(
            prepare_authorized_deployment(
                &profile,
                &registration,
                &dispatch,
                &decision,
                &authorization,
                NOW + 20,
            ),
            Err(RunnerBridgeError::ActionApprovalRequired)
        ));
        Ok(())
    }

    #[test]
    fn prepare_and_ask_requires_approval_even_when_conformance_is_clear()
    -> Result<(), Box<dyn std::error::Error>> {
        let (profile, registration, authorization, mut dispatch) =
            deployment_fixture(AutonomyMode::PrepareAndAsk, None)?;
        let decision = bind_decision(
            &profile,
            &mut dispatch,
            EnforcementDecision::Allow,
            EnforcementDecision::Allow,
            vec![DecisionReason::RequirementSatisfied],
        )?;
        assert!(matches!(
            prepare_authorized_deployment(
                &profile,
                &registration,
                &dispatch,
                &decision,
                &authorization,
                NOW + 20,
            ),
            Err(RunnerBridgeError::PrepareAndAskActionApprovalRequired)
        ));
        Ok(())
    }

    #[test]
    fn enrolled_action_approval_authority_allows_prepare_and_ask()
    -> Result<(), Box<dyn std::error::Error>> {
        let (profile, registration, authorization, mut dispatch) =
            deployment_fixture(AutonomyMode::PrepareAndAsk, None)?;
        let decision = bind_decision(
            &profile,
            &mut dispatch,
            EnforcementDecision::Allow,
            EnforcementDecision::Allow,
            vec![DecisionReason::RequirementSatisfied],
        )?;
        let approval = verified_approval(
            &profile,
            &dispatch,
            &decision,
            &authorization,
            &trusted_approval_signer(),
        )?;

        let prepared = prepare_authorized_deployment_with_approval(
            &profile,
            &registration,
            &dispatch,
            &decision,
            &authorization,
            Some(&approval),
            NOW + 20,
        )?;
        assert_eq!(prepared.policy_decision_hash, decision.digest()?);
        Ok(())
    }

    #[test]
    fn self_signed_approval_from_unenrolled_authority_is_rejected_by_bridge()
    -> Result<(), Box<dyn std::error::Error>> {
        let (profile, registration, authorization, mut dispatch) =
            deployment_fixture(AutonomyMode::PrepareAndAsk, None)?;
        let decision = bind_decision(
            &profile,
            &mut dispatch,
            EnforcementDecision::Allow,
            EnforcementDecision::Allow,
            vec![DecisionReason::RequirementSatisfied],
        )?;
        let attacker = approval_signer(0xcc);
        let self_verified =
            verified_approval(&profile, &dispatch, &decision, &authorization, &attacker)?;
        assert_ne!(
            self_verified.authority_hash(),
            profile.action_approval_authority_hash
        );

        assert!(matches!(
            prepare_authorized_deployment_with_approval(
                &profile,
                &registration,
                &dispatch,
                &decision,
                &authorization,
                Some(&self_verified),
                NOW + 20,
            ),
            Err(RunnerBridgeError::ActionApprovalAuthorityMismatch)
        ));
        Ok(())
    }

    #[test]
    fn observe_mode_cannot_prepare_a_deployment() -> Result<(), Box<dyn std::error::Error>> {
        let (profile, registration, authorization, mut dispatch) =
            deployment_fixture(AutonomyMode::Observe, Some(digest(19)))?;
        let decision = bind_decision(
            &profile,
            &mut dispatch,
            EnforcementDecision::Allow,
            EnforcementDecision::Allow,
            vec![DecisionReason::RequirementSatisfied],
        )?;
        assert!(matches!(
            prepare_authorized_deployment(
                &profile,
                &registration,
                &dispatch,
                &decision,
                &authorization,
                NOW + 20,
            ),
            Err(RunnerBridgeError::ObserveModeActionForbidden)
        ));
        Ok(())
    }

    #[test]
    fn bounded_automation_accepts_exact_allow_without_action_approval()
    -> Result<(), Box<dyn std::error::Error>> {
        let (profile, registration, authorization, mut dispatch) =
            deployment_fixture(AutonomyMode::BoundedAutomatic, None)?;
        let decision = bind_decision(
            &profile,
            &mut dispatch,
            EnforcementDecision::Allow,
            EnforcementDecision::Allow,
            vec![
                DecisionReason::RequirementSatisfied,
                DecisionReason::ResourceReservationConfirmed,
            ],
        )?;
        let prepared = prepare_authorized_deployment(
            &profile,
            &registration,
            &dispatch,
            &decision,
            &authorization,
            NOW + 20,
        )?;
        assert_eq!(prepared.policy_decision_hash, decision.digest()?);
        Ok(())
    }
}
