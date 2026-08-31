use std::sync::{
    Arc,
    atomic::{AtomicI64, AtomicUsize, Ordering},
};

use accordlock_connectors::{
    ClockReadError, ConnectorRuntime, TrustedClock, TrustedEvidenceRoute, TrustedRouteSet,
    ValidityProfile,
};
use accordlock_evaluation::{
    DecisionReason, EnforcementDecision, POLICY_DECISION_SCHEMA_VERSION, PolicyDecisionRecord,
};
use accordlock_protocol::{
    AuthorityDomainState, AuthorityVector, CompletenessProfile, DeploymentTemplate,
    DispatchDeadlinePolicy, EXECUTION_AUTHORIZATION_SCHEMA_VERSION, EvidenceKind, SigningIdentity,
    canonical_hash,
};
use accordlock_provider_adapters::{
    AuthenticatedJsonResponse, EcrReadRequest, GitHubReadOperation, GitHubReadRequest,
    HttpsEndpoint, KubernetesReadRequest, ResponseMediaType, TransportFailure, ecr_artifact_lookup,
    github_actions_lookup, github_review_lookup, kubernetes_target_lookup,
};
use accordlock_runner_protocol::{
    AutonomyMode, EnvironmentTier, RUNNER_PROTOCOL_SCHEMA_VERSION, RunnerAction, RunnerCapability,
};
use serde_json::json;

use super::*;

const NOW: i64 = 1_900_000_000;
const REQUEST_ID: Uuid = Uuid::from_bytes([0xa0; 16]);
const DEPLOYMENT_UID: Uuid = Uuid::from_bytes([
    0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x43, 0x33, 0x84, 0x44, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
]);

#[derive(Clone, Copy, Debug)]
enum AuthMode {
    Exact,
    Reject,
    SubstituteDigest,
    SubstituteIdentity,
}

#[derive(Debug)]
struct FixtureAuthenticator {
    mode: AuthMode,
    calls: Arc<AtomicUsize>,
}

impl DispatchAuthenticator for FixtureAuthenticator {
    fn public_identity(
        &self,
    ) -> Result<AuthenticatedTransportIdentity, DispatchAuthenticationError> {
        let trust_seed = if matches!(self.mode, AuthMode::SubstituteIdentity) {
            0xee
        } else {
            0xa4
        };
        AuthenticatedTransportIdentity::new(
            "fixture-dispatch-auth-v1",
            "arn:aws:iam::111122223333:role/accordlock-runner",
            "fixture:aws",
            digest(trust_seed),
        )
        .map_err(|_| DispatchAuthenticationError::Rejected)
    }

    fn authenticate(
        &self,
        request: DispatchAuthenticationRequest,
    ) -> Result<DispatchAuthentication, DispatchAuthenticationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if matches!(self.mode, AuthMode::Reject) {
            return Err(DispatchAuthenticationError::Rejected);
        }
        let dispatch_hash = if matches!(self.mode, AuthMode::SubstituteDigest) {
            digest(0xfe)
        } else {
            request.dispatch_hash
        };
        Ok(DispatchAuthentication::new(
            request.runner_id,
            dispatch_hash,
            request.runner_attestation_hash,
            digest(0xcd),
            request.trusted_now,
        ))
    }
}

#[derive(Debug)]
struct FixedClock(Arc<AtomicI64>);

impl TrustedClock for FixedClock {
    fn unix_seconds(&self) -> Result<i64, ClockReadError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

#[derive(Debug)]
struct CountingClock {
    now: i64,
    calls: Arc<AtomicUsize>,
}

impl TrustedClock for CountingClock {
    fn unix_seconds(&self) -> Result<i64, ClockReadError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.now)
    }
}

#[derive(Debug)]
struct GitHubFixtureTransport {
    request_id: Uuid,
    reads: Arc<AtomicUsize>,
}

impl GitHubAuthenticatedTransport for GitHubFixtureTransport {
    fn public_identity(&self) -> Result<AuthenticatedTransportIdentity, AdapterConfigError> {
        AuthenticatedTransportIdentity::new(
            "fixture-github-v1",
            "github-app:acme",
            "fixture:github",
            digest(0xa1),
        )
    }

    fn read(
        &self,
        request: &GitHubReadRequest,
    ) -> Result<AuthenticatedJsonResponse, TransportFailure> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let body = match request.operation {
            GitHubReadOperation::PullReviewDecision => json!({
                "schema_version": 1,
                "request_id": self.request_id,
                "evidence_id": Uuid::from_bytes([1; 16]),
                "observed_at": NOW + 15,
                "source_sequence": 91,
                "repository": "acme/payments",
                "pull_number": 17,
                "commit_sha": "a".repeat(40),
                "approved": true
            }),
            GitHubReadOperation::ActionsBuildAttestation => json!({
                "schema_version": 1,
                "request_id": self.request_id,
                "evidence_id": Uuid::from_bytes([2; 16]),
                "observed_at": NOW + 15,
                "source_sequence": 92,
                "repository": "acme/payments",
                "workflow_ref": ".github/workflows/release.yml@refs/heads/main",
                "run_id": 83,
                "commit_sha": "a".repeat(40),
                "succeeded": true,
                "input_manifest_root": digest(0x44),
                "completeness_profile": "HERMETIC_INPUTS_V1",
                "output_digest": digest(0x55)
            }),
        };
        let bytes = serde_json::to_vec(&body).map_err(|_| TransportFailure::Integrity)?;
        Ok(AuthenticatedJsonResponse::new(
            200,
            ResponseMediaType::Json,
            bytes,
        ))
    }
}

#[derive(Debug)]
struct EcrFixtureTransport {
    request_id: Uuid,
    reads: Arc<AtomicUsize>,
    returned_digest: Digest32,
    source_repository: String,
    identity_seed: u8,
}

impl EcrAuthenticatedTransport for EcrFixtureTransport {
    fn public_identity(&self) -> Result<AuthenticatedTransportIdentity, AdapterConfigError> {
        AuthenticatedTransportIdentity::new(
            "fixture-aws-sigv4-v1",
            "arn:aws:iam::111122223333:role/accordlock-runner",
            "fixture:aws",
            digest(self.identity_seed),
        )
    }

    fn read(
        &self,
        _request: &EcrReadRequest,
    ) -> Result<AuthenticatedJsonResponse, TransportFailure> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let body = json!({
            "schema_version": 1,
            "request_id": self.request_id,
            "evidence_id": Uuid::from_bytes([3; 16]),
            "observed_at": NOW + 15,
            "source_sequence": 93,
            "registry_id": "111122223333",
            "region": "us-east-1",
            "repository_name": "acme/payments",
            "image_digest": self.returned_digest,
            "source_repository": self.source_repository,
            "commit_sha": "a".repeat(40),
            "source_run_id": 83,
            "signature_valid": true,
            "quarantined": false
        });
        let bytes = serde_json::to_vec(&body).map_err(|_| TransportFailure::Integrity)?;
        Ok(AuthenticatedJsonResponse::new(
            200,
            ResponseMediaType::Json,
            bytes,
        ))
    }
}

#[derive(Debug)]
struct KubernetesFixtureTransport {
    request_id: Uuid,
    reads: Arc<AtomicUsize>,
}

impl KubernetesAuthenticatedTransport for KubernetesFixtureTransport {
    fn public_identity(&self) -> Result<AuthenticatedTransportIdentity, AdapterConfigError> {
        AuthenticatedTransportIdentity::new(
            "fixture-eks-auth-v1",
            "arn:aws:iam::111122223333:role/accordlock-runner",
            "fixture:aws",
            digest(0xa3),
        )
    }

    fn read(
        &self,
        _request: &KubernetesReadRequest,
    ) -> Result<AuthenticatedJsonResponse, TransportFailure> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let body = json!({
            "schema_version": 1,
            "request_id": self.request_id,
            "evidence_id": Uuid::from_bytes([4; 16]),
            "observed_at": NOW + 15,
            "source_sequence": 94,
            "cluster_identity": "arn:aws:eks:us-east-1:111122223333:cluster/staging-a",
            "namespace": "payments",
            "deployment": "payments-api",
            "deployment_uid": DEPLOYMENT_UID,
            "resource_version": "83191",
            "container": "application",
            "source_repository": "acme/payments",
            "commit_sha": "a".repeat(40),
            "image_repository": "111122223333.dkr.ecr.us-east-1.amazonaws.com/acme/payments",
            "desired_image_digest": digest(0x55),
            "current_image": digest(0x66),
            "projection_hash": digest(0x77)
        });
        let bytes = serde_json::to_vec(&body).map_err(|_| TransportFailure::Integrity)?;
        Ok(AuthenticatedJsonResponse::new(
            200,
            ResponseMediaType::Json,
            bytes,
        ))
    }
}

fn digest(seed: u8) -> Digest32 {
    Digest32::from_bytes([seed; 32])
}

fn domain(seed: u8) -> AuthorityDomainState {
    AuthorityDomainState {
        root: digest(seed),
        epoch: u64::from(seed),
        activation_id: Uuid::from_bytes([seed; 16]),
    }
}

fn authority() -> AuthorityVector {
    AuthorityVector {
        policy: domain(1),
        registry: domain(2),
        revocation: domain(3),
        connector: domain(4),
        resource: domain(5),
        signer: domain(6),
        mediation: domain(7),
        grant_registry: domain(8),
        office_act_registry: domain(9),
        principal_registry: domain(10),
        workload_build_allowlist: domain(11),
        kernel_configuration: domain(12),
    }
}

fn profile() -> EnterpriseEnvironmentProfile {
    let approval_verifier = action_approval_signer().verifier();
    EnterpriseEnvironmentProfile {
        schema_version: RUNNER_PROTOCOL_SCHEMA_VERSION,
        profile_id: Uuid::from_bytes([21; 16]),
        organization_id: "acme".to_owned(),
        environment_id: "payments-staging".to_owned(),
        tier: EnvironmentTier::Staging,
        autonomy_mode: AutonomyMode::BoundedAutomatic,
        production_autonomy_approval_hash: None,
        executor_audience: "accordlock-eks-executor".to_owned(),
        github_repository: "acme/payments".to_owned(),
        github_workflow_ref: ".github/workflows/release.yml@refs/heads/main".to_owned(),
        aws_account_id: "111122223333".to_owned(),
        aws_region: "us-east-1".to_owned(),
        ecr_repository: "acme/payments".to_owned(),
        eks_cluster_name: "staging-a".to_owned(),
        kubernetes_namespace: "payments".to_owned(),
        kubernetes_deployment: "payments-api".to_owned(),
        kubernetes_container: "application".to_owned(),
        policy_hash: digest(20),
        policy_epoch: 1,
        github_connector_hash: digest(21),
        aws_identity_hash: digest(22),
        ecr_connector_hash: digest(23),
        kubernetes_connector_hash: digest(24),
        action_approval_authority_hash: action_approval_authority_commitment(&approval_verifier),
        created_at: NOW,
        expires_at: NOW + 86_400,
    }
}

fn action_approval_signer() -> SigningIdentity {
    SigningIdentity::from_seed("action-approval-key", [0xb1; 32])
}

fn action_approval_verifier() -> CoseVerifier {
    action_approval_signer().verifier()
}

fn commit_profile_to_runtime(
    profile: &mut EnterpriseEnvironmentProfile,
    runtime: &ConnectorRuntime,
    authenticator: &FixtureAuthenticator,
) -> Result<(), Box<dyn std::error::Error>> {
    let commitments = runtime.configuration_commitments()?;
    profile.github_connector_hash = commitments.github_connector_hash;
    profile.ecr_connector_hash = commitments.ecr_connector_hash;
    profile.kubernetes_connector_hash = commitments.kubernetes_connector_hash;
    profile.aws_identity_hash = aws_identity_commitment(
        &profile.aws_account_id,
        &profile.aws_region,
        commitments.ecr_transport_identity_hash,
        commitments.kubernetes_transport_identity_hash,
        authenticator.public_identity()?.digest(),
    );
    Ok(())
}

fn registration(
    profile: &EnterpriseEnvironmentProfile,
) -> Result<RunnerRegistration, RunnerProtocolError> {
    Ok(RunnerRegistration {
        schema_version: RUNNER_PROTOCOL_SCHEMA_VERSION,
        runner_id: Uuid::from_bytes([22; 16]),
        organization_id: profile.organization_id.clone(),
        environment_id: profile.environment_id.clone(),
        environment_profile_hash: profile.digest()?,
        runner_attestation_hash: digest(25),
        capabilities: vec![
            RunnerCapability::ObserveGithub,
            RunnerCapability::ObserveEcr,
            RunnerCapability::ObserveKubernetes,
            RunnerCapability::DeployEksImage,
        ],
        enrolled_at: NOW,
        expires_at: NOW + 3_600,
    })
}

fn route(
    kind: EvidenceKind,
    seed: u8,
    prefix: &str,
) -> Result<TrustedEvidenceRoute, accordlock_connectors::ConnectorError> {
    TrustedEvidenceRoute::new(
        kind,
        format!("runner-{kind:?}").to_ascii_lowercase(),
        prefix,
        SigningIdentity::from_seed(
            format!("runner-{kind:?}-key").to_ascii_lowercase(),
            [seed; 32],
        ),
    )
}

fn connector_runtime(
    request_id: Uuid,
    reads: Arc<AtomicUsize>,
) -> Result<ConnectorRuntime, Box<dyn std::error::Error>> {
    connector_runtime_variant(
        request_id,
        reads,
        digest(0x55),
        "acme/payments",
        "api.github.example",
        0xa2,
    )
}

fn connector_runtime_with_ecr(
    request_id: Uuid,
    reads: Arc<AtomicUsize>,
    returned_digest: Digest32,
    source_repository: &str,
) -> Result<ConnectorRuntime, Box<dyn std::error::Error>> {
    connector_runtime_variant(
        request_id,
        reads,
        returned_digest,
        source_repository,
        "api.github.example",
        0xa2,
    )
}

fn connector_runtime_variant(
    request_id: Uuid,
    reads: Arc<AtomicUsize>,
    returned_digest: Digest32,
    source_repository: &str,
    github_authority: &str,
    ecr_identity_seed: u8,
) -> Result<ConnectorRuntime, Box<dyn std::error::Error>> {
    let source_profile = profile();
    let sources = trusted_provider_sources_for_profile(
        &source_profile,
        RunnerProviderEndpoints::new(
            HttpsEndpoint::new(github_authority, "/api/v3")?,
            HttpsEndpoint::new("api.ecr.us-east-1.amazonaws.com", "/")?,
            HttpsEndpoint::new("cluster.example", "/")?,
            16_384,
        ),
        RunnerProviderTransports::new(
            Arc::new(GitHubFixtureTransport {
                request_id,
                reads: Arc::clone(&reads),
            }),
            Arc::new(EcrFixtureTransport {
                request_id,
                reads: Arc::clone(&reads),
                returned_digest,
                source_repository: source_repository.to_owned(),
                identity_seed: ecr_identity_seed,
            }),
            Arc::new(KubernetesFixtureTransport { request_id, reads }),
        ),
    )?;
    let routes = TrustedRouteSet::new(
        route(
            EvidenceKind::Review,
            31,
            &format!("https://{github_authority}/api/v3/"),
        )?,
        route(
            EvidenceKind::Build,
            32,
            &format!("https://{github_authority}/api/v3/"),
        )?,
        route(
            EvidenceKind::Artifact,
            33,
            "https://api.ecr.us-east-1.amazonaws.com/",
        )?,
        route(EvidenceKind::Target, 34, "https://cluster.example/")?,
    )?;
    Ok(ConnectorRuntime::new(
        sources,
        routes,
        Box::new(FixedClock(Arc::new(AtomicI64::new(NOW + 20)))),
        authority(),
        ValidityProfile::new(300, 60, 5, CompletenessProfile::HermeticInputsV1)?,
    ))
}

fn observation_dispatch(
    profile: &EnterpriseEnvironmentProfile,
    registration: &RunnerRegistration,
) -> Result<RunnerDispatch, Box<dyn std::error::Error>> {
    Ok(RunnerDispatch {
        schema_version: RUNNER_PROTOCOL_SCHEMA_VERSION,
        dispatch_id: REQUEST_ID,
        task_id: Uuid::from_bytes([23; 16]),
        task_hash: digest(40),
        session_id: "session-1".to_owned(),
        principal_id: "user:alice@example.com".to_owned(),
        runner_id: registration.runner_id,
        environment_profile_hash: profile.digest()?,
        runner_registration_hash: registration.digest()?,
        policy_decision_hash: digest(41),
        resource_reservation_hash: digest(42),
        authorization_id: Uuid::from_bytes([24; 16]),
        authorization_hash: digest(43),
        action_approval: None,
        action: RunnerAction::ObserveSupplyChain {
            review_lookup_id: github_review_lookup(REQUEST_ID, 17)?.as_str().to_owned(),
            build_lookup_id: github_actions_lookup(REQUEST_ID, 83)?.as_str().to_owned(),
            artifact_lookup_id: ecr_artifact_lookup(REQUEST_ID, digest(0x55))?
                .as_str()
                .to_owned(),
            target_lookup_id: kubernetes_target_lookup(REQUEST_ID, DEPLOYMENT_UID, "83191")?
                .as_str()
                .to_owned(),
        },
        created_at: NOW + 10,
        expires_at: NOW + 70,
    })
}

fn bind_decision(
    profile: &EnterpriseEnvironmentProfile,
    dispatch: &mut RunnerDispatch,
    decision: EnforcementDecision,
) -> Result<PolicyDecisionRecord, Box<dyn std::error::Error>> {
    let reasons = match decision {
        EnforcementDecision::Allow => vec![DecisionReason::RequirementSatisfied],
        EnforcementDecision::RequireApproval => vec![DecisionReason::ConformanceInconclusive],
        EnforcementDecision::Deny => vec![DecisionReason::RequirementViolated],
    };
    let decision = PolicyDecisionRecord {
        schema_version: POLICY_DECISION_SCHEMA_VERSION,
        decision_id: Uuid::from_bytes([25; 16]),
        task_hash: dispatch.task_hash,
        action_hash: dispatch.action.digest()?,
        sequence: 0,
        parent_decision_hash: None,
        requirement_hashes: vec![digest(50)],
        transformation_step_hashes: vec![digest(51)],
        conformance_evaluation_hashes: vec![digest(52)],
        resource_request_hashes: vec![digest(53)],
        resource_quota_hashes: vec![digest(54)],
        resource_reservation_hashes: vec![dispatch.resource_reservation_hash],
        baseline_decision: EnforcementDecision::Allow,
        decision,
        reasons,
        policy_epoch: profile.policy_epoch,
        evaluated_at: NOW + 9,
    };
    dispatch.policy_decision_hash = decision.digest()?;
    Ok(decision)
}

fn engine(
    mode: AuthMode,
    reads: Arc<AtomicUsize>,
    auth_calls: Arc<AtomicUsize>,
) -> Result<
    (
        EnterpriseRunner,
        EnterpriseEnvironmentProfile,
        RunnerRegistration,
    ),
    Box<dyn std::error::Error>,
> {
    let mut profile = profile();
    let runtime = connector_runtime(REQUEST_ID, reads)?;
    let authenticator = FixtureAuthenticator {
        mode,
        calls: auth_calls,
    };
    commit_profile_to_runtime(&mut profile, &runtime, &authenticator)?;
    let registration = registration(&profile)?;
    let runner = EnterpriseRunner::new(
        profile.clone(),
        registration.clone(),
        runtime,
        action_approval_verifier(),
        Box::new(authenticator),
        Box::new(FixedClock(Arc::new(AtomicI64::new(NOW + 20)))),
    )?;
    Ok((runner, profile, registration))
}

fn deployment_template(profile: &EnterpriseEnvironmentProfile) -> DeploymentTemplate {
    DeploymentTemplate {
        operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
        environment: profile.environment_id.clone(),
        audience: profile.executor_audience.clone(),
        repository: profile.github_repository.clone(),
        commit_sha: "a".repeat(40),
        image_repository: profile.ecr_image_repository(),
        image_digest: digest(0x55),
        cluster_identity: profile.eks_cluster_identity(),
        namespace: profile.kubernetes_namespace.clone(),
        deployment: profile.kubernetes_deployment.clone(),
        deployment_uid: DEPLOYMENT_UID.to_string(),
        container: profile.kubernetes_container.clone(),
        container_index: 0,
        prior_image_digest: digest(0x66),
        resource_version: "83191".to_owned(),
        prior_projection_hash: digest(0x77),
        prior_transaction_annotation: None,
        prior_authorization_annotation: None,
        prior_operation_hash_annotation: None,
    }
}

fn deployment_snapshot(template: &DeploymentTemplate) -> serde_json::Value {
    json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": template.deployment,
            "namespace": template.namespace,
            "uid": template.deployment_uid,
            "resourceVersion": template.resource_version,
            "generation": 7,
            "annotations": {
                "accordlock.io/transaction-id": template.prior_transaction_annotation,
                "accordlock.io/authorization-id": template.prior_authorization_annotation,
                "accordlock.io/operation-hash": template.prior_operation_hash_annotation
            }
        },
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": "payments"}},
            "template": {
                "metadata": {"labels": {"app": "payments"}},
                "spec": {
                    "containers": [{
                        "name": template.container,
                        "image": format!("{}@{}", template.image_repository, template.prior_image_digest)
                    }]
                }
            }
        },
        "status": {"replicas": 1}
    })
}

fn authorization(
    profile: &EnterpriseEnvironmentProfile,
) -> Result<ExecutionAuthorization, accordlock_protocol::CanonicalError> {
    let template = deployment_template(profile);
    Ok(ExecutionAuthorization {
        schema_version: EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
        authorization_id: Uuid::from_bytes([26; 16]),
        evaluation_nonce: Uuid::from_bytes([27; 16]),
        request_id: REQUEST_ID,
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
        grant_id: Uuid::from_bytes([28; 16]),
        template_hash: canonical_hash(&template)?,
        template,
        evidence_root: digest(60),
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
        task_id: Uuid::from_bytes([23; 16]),
        task_hash: digest(40),
        session_id: "session-1".to_owned(),
        principal_id: authorization.holder.clone(),
        runner_id: registration.runner_id,
        environment_profile_hash: profile.digest()?,
        runner_registration_hash: registration.digest()?,
        policy_decision_hash: digest(41),
        resource_reservation_hash: digest(42),
        authorization_id: authorization.authorization_id,
        authorization_hash: canonical_hash(authorization)?,
        action_approval: None,
        action: RunnerAction::DeployEksImage {
            transaction_id: Uuid::from_bytes([0x2a; 16]),
            commit_sha: authorization.template.commit_sha.clone(),
            image_digest: authorization.template.image_digest,
            deployment_uid: authorization.template.deployment_uid.clone(),
            resource_version: authorization.template.resource_version.clone(),
            container_index: authorization.template.container_index,
            prior_image_digest: authorization.template.prior_image_digest,
            prior_projection_hash: authorization.template.prior_projection_hash,
            prior_transaction_annotation: authorization
                .template
                .prior_transaction_annotation
                .clone(),
            prior_authorization_annotation: authorization
                .template
                .prior_authorization_annotation
                .clone(),
            prior_operation_hash_annotation: authorization
                .template
                .prior_operation_hash_annotation
                .clone(),
        },
        created_at: NOW + 10,
        expires_at: NOW + 70,
    })
}

fn deployment_exhibit_inputs(
    profile: &EnterpriseEnvironmentProfile,
    registration: &RunnerRegistration,
) -> Result<
    (
        ExecutionAuthorization,
        serde_json::Value,
        RunnerDispatch,
        PolicyDecisionRecord,
    ),
    Box<dyn std::error::Error>,
> {
    let mut authorization = authorization(profile)?;
    authorization.template.prior_transaction_annotation = Some("unassigned".to_owned());
    authorization.template.prior_authorization_annotation = Some("unassigned".to_owned());
    authorization.template.prior_operation_hash_annotation = Some("unassigned".to_owned());
    let snapshot = deployment_snapshot(&authorization.template);
    authorization.template.prior_projection_hash =
        Digest32::sha256(&serde_json::to_vec(&snapshot)?);
    authorization.template_hash = canonical_hash(&authorization.template)?;
    let mut dispatch = deployment_dispatch(profile, registration, &authorization)?;
    let decision = bind_decision(profile, &mut dispatch, EnforcementDecision::Allow)?;
    Ok((authorization, snapshot, dispatch, decision))
}

fn attach_action_approval(
    dispatch: &mut RunnerDispatch,
    authorization: &ExecutionAuthorization,
    approver_id: &str,
    issued_at: i64,
    expires_at: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let signer = action_approval_signer();
    attach_action_approval_with_signer(
        dispatch,
        authorization,
        approver_id,
        issued_at,
        expires_at,
        &signer,
    )
}

fn attach_action_approval_with_signer(
    dispatch: &mut RunnerDispatch,
    authorization: &ExecutionAuthorization,
    approver_id: &str,
    issued_at: i64,
    expires_at: i64,
    signer: &SigningIdentity,
) -> Result<(), Box<dyn std::error::Error>> {
    let attestation = accordlock_runner_protocol::ActionApprovalAttestation {
        schema_version: accordlock_runner_protocol::ACTION_APPROVAL_SCHEMA_VERSION,
        approval_id: Uuid::new_v4(),
        task_id: dispatch.task_id,
        task_hash: dispatch.task_hash,
        session_id: dispatch.session_id.clone(),
        principal_id: dispatch.principal_id.clone(),
        approver_id: approver_id.to_owned(),
        runner_id: dispatch.runner_id,
        environment_profile_hash: dispatch.environment_profile_hash,
        policy_decision_hash: dispatch.policy_decision_hash,
        action_hash: dispatch.action.digest()?,
        authorization_id: authorization.authorization_id,
        authorization_hash: canonical_hash(authorization)?,
        authorization_evidence_root: authorization.evidence_root,
        decision: accordlock_runner_protocol::ApprovalDecision::Approved,
        issued_at,
        expires_at,
        key_id: signer.key_id().to_owned(),
    };
    dispatch.action_approval = Some(accordlock_runner_protocol::SignedActionApproval::sign(
        attestation,
        signer,
    )?);
    Ok(())
}

struct ApprovedProductionFixture {
    runner: EnterpriseRunner,
    authorization: ExecutionAuthorization,
    dispatch: RunnerDispatch,
    decision: PolicyDecisionRecord,
}

fn approved_production_fixture(
    reads: Arc<AtomicUsize>,
    auth_calls: Arc<AtomicUsize>,
) -> Result<ApprovedProductionFixture, Box<dyn std::error::Error>> {
    let mut profile = profile();
    profile.tier = EnvironmentTier::Production;
    profile.autonomy_mode = AutonomyMode::PrepareAndAsk;
    profile.production_autonomy_approval_hash = Some(digest(62));
    let runtime = connector_runtime(REQUEST_ID, reads)?;
    let authenticator = FixtureAuthenticator {
        mode: AuthMode::Exact,
        calls: auth_calls,
    };
    commit_profile_to_runtime(&mut profile, &runtime, &authenticator)?;
    let registration = registration(&profile)?;
    let runner = EnterpriseRunner::new(
        profile.clone(),
        registration.clone(),
        runtime,
        action_approval_verifier(),
        Box::new(authenticator),
        Box::new(FixedClock(Arc::new(AtomicI64::new(NOW + 20)))),
    )?;
    let authorization = authorization(&profile)?;
    let mut dispatch = deployment_dispatch(&profile, &registration, &authorization)?;
    let decision = bind_decision(&profile, &mut dispatch, EnforcementDecision::Allow)?;
    attach_action_approval(
        &mut dispatch,
        &authorization,
        "approver:bob",
        NOW + 10,
        NOW + 60,
    )?;
    Ok(ApprovedProductionFixture {
        runner,
        authorization,
        dispatch,
        decision,
    })
}

#[test]
fn authenticated_provider_transports_collect_exact_evidence_once()
-> Result<(), Box<dyn std::error::Error>> {
    let reads = Arc::new(AtomicUsize::new(0));
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let (runner, profile, registration) =
        engine(AuthMode::Exact, Arc::clone(&reads), Arc::clone(&auth_calls))?;
    let mut dispatch = observation_dispatch(&profile, &registration)?;
    let decision = bind_decision(&profile, &mut dispatch, EnforcementDecision::Allow)?;

    let collected = runner.collect_evidence(&dispatch, &decision)?;
    assert_eq!(collected.evidence.request_id, REQUEST_ID);
    assert_eq!(collected.evidence.evidence.len(), 4);
    assert_eq!(reads.load(Ordering::SeqCst), 4);
    assert_eq!(auth_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        collected.authentication.channel_binding_hash(),
        digest(0xcd)
    );

    assert!(matches!(
        runner.collect_evidence(&dispatch, &decision),
        Err(RunnerEngineError::DispatchReplay)
    ));
    assert_eq!(reads.load(Ordering::SeqCst), 4);
    Ok(())
}

#[test]
fn durable_runner_rejects_dispatch_replay_after_process_reconstruction()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let state_path = root.path().join("enterprise-runner.sqlite3");
    let (dispatch, decision) = {
        let reads = Arc::new(AtomicUsize::new(0));
        let mut profile = profile();
        let runtime = connector_runtime(REQUEST_ID, Arc::clone(&reads))?;
        let authenticator = FixtureAuthenticator {
            mode: AuthMode::Exact,
            calls: Arc::new(AtomicUsize::new(0)),
        };
        commit_profile_to_runtime(&mut profile, &runtime, &authenticator)?;
        let registration = registration(&profile)?;
        let runner = EnterpriseRunner::new_durable(
            profile.clone(),
            registration.clone(),
            runtime,
            action_approval_verifier(),
            Box::new(authenticator),
            Box::new(FixedClock(Arc::new(AtomicI64::new(NOW + 20)))),
            SqliteRunnerStateStore::open(&state_path)?,
        )?;
        let mut dispatch = observation_dispatch(&profile, &registration)?;
        let decision = bind_decision(&profile, &mut dispatch, EnforcementDecision::Allow)?;
        runner.collect_evidence(&dispatch, &decision)?;
        assert_eq!(reads.load(Ordering::SeqCst), 4);
        (dispatch, decision)
    };
    let reads = Arc::new(AtomicUsize::new(0));
    let mut profile = profile();
    let runtime = connector_runtime(REQUEST_ID, Arc::clone(&reads))?;
    let authenticator = FixtureAuthenticator {
        mode: AuthMode::Exact,
        calls: Arc::new(AtomicUsize::new(0)),
    };
    commit_profile_to_runtime(&mut profile, &runtime, &authenticator)?;
    let registration = registration(&profile)?;
    let runner = EnterpriseRunner::new_durable(
        profile,
        registration,
        runtime,
        action_approval_verifier(),
        Box::new(authenticator),
        Box::new(FixedClock(Arc::new(AtomicI64::new(NOW + 20)))),
        SqliteRunnerStateStore::open(&state_path)?,
    )?;
    assert!(matches!(
        runner.collect_evidence(&dispatch, &decision),
        Err(RunnerEngineError::DispatchReplay)
    ));
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn full_connector_path_rejects_substituted_ecr_digest_and_repository()
-> Result<(), Box<dyn std::error::Error>> {
    for (returned_digest, source_repository) in [
        (digest(0x99), "acme/payments"),
        (digest(0x55), "acme/substituted"),
    ] {
        let reads = Arc::new(AtomicUsize::new(0));
        let mut profile = profile();
        let runtime = connector_runtime_with_ecr(
            REQUEST_ID,
            Arc::clone(&reads),
            returned_digest,
            source_repository,
        )?;
        let authenticator = FixtureAuthenticator {
            mode: AuthMode::Exact,
            calls: Arc::new(AtomicUsize::new(0)),
        };
        commit_profile_to_runtime(&mut profile, &runtime, &authenticator)?;
        let registration = registration(&profile)?;
        let runner = EnterpriseRunner::new(
            profile.clone(),
            registration.clone(),
            runtime,
            action_approval_verifier(),
            Box::new(authenticator),
            Box::new(FixedClock(Arc::new(AtomicI64::new(NOW + 20)))),
        )?;
        let mut dispatch = observation_dispatch(&profile, &registration)?;
        let decision = bind_decision(&profile, &mut dispatch, EnforcementDecision::Allow)?;
        assert!(matches!(
            runner.collect_evidence(&dispatch, &decision),
            Err(RunnerEngineError::Connector(_))
        ));
        assert_eq!(reads.load(Ordering::SeqCst), 3);
    }
    Ok(())
}

#[test]
fn durable_pending_dispatch_is_released_after_known_connector_rejection()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let reads = Arc::new(AtomicUsize::new(0));
    let mut profile = profile();
    let runtime = connector_runtime_with_ecr(
        REQUEST_ID,
        Arc::clone(&reads),
        digest(0x99),
        "acme/payments",
    )?;
    let authenticator = FixtureAuthenticator {
        mode: AuthMode::Exact,
        calls: Arc::new(AtomicUsize::new(0)),
    };
    commit_profile_to_runtime(&mut profile, &runtime, &authenticator)?;
    let registration = registration(&profile)?;
    let runner = EnterpriseRunner::new_durable(
        profile.clone(),
        registration.clone(),
        runtime,
        action_approval_verifier(),
        Box::new(authenticator),
        Box::new(FixedClock(Arc::new(AtomicI64::new(NOW + 20)))),
        SqliteRunnerStateStore::open(root.path().join("connector-error.sqlite3"))?,
    )?;
    let mut dispatch = observation_dispatch(&profile, &registration)?;
    let decision = bind_decision(&profile, &mut dispatch, EnforcementDecision::Allow)?;
    for expected_reads in [3, 6] {
        assert!(matches!(
            runner.collect_evidence(&dispatch, &decision),
            Err(RunnerEngineError::Connector(_))
        ));
        assert_eq!(reads.load(Ordering::SeqCst), expected_reads);
    }
    Ok(())
}

#[test]
fn rejected_or_substituted_authentication_performs_no_provider_read()
-> Result<(), Box<dyn std::error::Error>> {
    for mode in [AuthMode::Reject, AuthMode::SubstituteDigest] {
        let reads = Arc::new(AtomicUsize::new(0));
        let (runner, profile, registration) =
            engine(mode, Arc::clone(&reads), Arc::new(AtomicUsize::new(0)))?;
        let mut dispatch = observation_dispatch(&profile, &registration)?;
        let decision = bind_decision(&profile, &mut dispatch, EnforcementDecision::Allow)?;
        let result = runner.collect_evidence(&dispatch, &decision);
        match mode {
            AuthMode::Reject => assert!(matches!(
                result,
                Err(RunnerEngineError::Authentication(
                    DispatchAuthenticationError::Rejected
                ))
            )),
            AuthMode::SubstituteDigest => assert!(matches!(
                result,
                Err(RunnerEngineError::AuthenticationBindingMismatch)
            )),
            AuthMode::Exact | AuthMode::SubstituteIdentity => {
                return Err("mode is not part of this hostile test".into());
            }
        }
        assert_eq!(reads.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[test]
fn policy_denial_is_rejected_before_provider_collection() -> Result<(), Box<dyn std::error::Error>>
{
    let reads = Arc::new(AtomicUsize::new(0));
    let (runner, profile, registration) = engine(
        AuthMode::Exact,
        Arc::clone(&reads),
        Arc::new(AtomicUsize::new(0)),
    )?;
    let mut dispatch = observation_dispatch(&profile, &registration)?;
    let decision = bind_decision(&profile, &mut dispatch, EnforcementDecision::Deny)?;
    assert!(matches!(
        runner.collect_evidence(&dispatch, &decision),
        Err(RunnerEngineError::RunnerBridge(
            RunnerBridgeError::EvaluationBlocked
        ))
    ));
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn injected_clock_rejects_future_and_expired_dispatch_without_provider_reads()
-> Result<(), Box<dyn std::error::Error>> {
    let reads = Arc::new(AtomicUsize::new(0));
    for invalid_now in [NOW + 9, NOW + 70] {
        let mut profile = profile();
        let runtime = connector_runtime(REQUEST_ID, Arc::clone(&reads))?;
        let authenticator = FixtureAuthenticator {
            mode: AuthMode::Exact,
            calls: Arc::new(AtomicUsize::new(0)),
        };
        commit_profile_to_runtime(&mut profile, &runtime, &authenticator)?;
        let registration = registration(&profile)?;
        let runner = EnterpriseRunner::new(
            profile.clone(),
            registration.clone(),
            runtime,
            action_approval_verifier(),
            Box::new(authenticator),
            Box::new(FixedClock(Arc::new(AtomicI64::new(invalid_now)))),
        )?;
        let mut dispatch = observation_dispatch(&profile, &registration)?;
        let decision = bind_decision(&profile, &mut dispatch, EnforcementDecision::Allow)?;
        assert!(matches!(
            runner.collect_evidence(&dispatch, &decision),
            Err(RunnerEngineError::RunnerBridge(
                RunnerBridgeError::RunnerProtocol(RunnerProtocolError::NotCurrent(
                    "runner dispatch"
                ))
            ))
        ));
    }
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn trusted_clock_rollback_is_rejected_before_authentication_or_provider_io()
-> Result<(), Box<dyn std::error::Error>> {
    let reads = Arc::new(AtomicUsize::new(0));
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let clock = Arc::new(AtomicI64::new(NOW + 20));
    let mut profile = profile();
    let runtime = connector_runtime(REQUEST_ID, Arc::clone(&reads))?;
    let authenticator = FixtureAuthenticator {
        mode: AuthMode::Exact,
        calls: Arc::clone(&auth_calls),
    };
    commit_profile_to_runtime(&mut profile, &runtime, &authenticator)?;
    let registration = registration(&profile)?;
    let runner = EnterpriseRunner::new(
        profile.clone(),
        registration.clone(),
        runtime,
        action_approval_verifier(),
        Box::new(authenticator),
        Box::new(FixedClock(Arc::clone(&clock))),
    )?;
    let mut dispatch = observation_dispatch(&profile, &registration)?;
    let decision = bind_decision(&profile, &mut dispatch, EnforcementDecision::Allow)?;
    clock.store(NOW + 19, Ordering::SeqCst);

    assert!(matches!(
        runner.collect_evidence(&dispatch, &decision),
        Err(RunnerEngineError::TrustedClockRollback)
    ));
    assert_eq!(auth_calls.load(Ordering::SeqCst), 0);
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn replay_memory_is_hard_bounded_and_fails_closed_at_capacity()
-> Result<(), Box<dyn std::error::Error>> {
    let (runner, _, _) = engine(
        AuthMode::Exact,
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicUsize::new(0)),
    )?;
    for index in 0..MAX_ACCEPTED_DISPATCHES {
        let index = u64::try_from(index)?;
        runner
            .reserve(Digest32::sha256(&index.to_be_bytes()), NOW + 70)?
            .commit()?;
    }
    assert!(matches!(
        runner.reserve(Digest32::sha256(b"quota+1"), NOW + 70),
        Err(RunnerEngineError::ReplayCapacityExceeded)
    ));
    Ok(())
}

#[test]
fn production_preparation_is_always_readiness_blocked_and_side_effect_free()
-> Result<(), Box<dyn std::error::Error>> {
    let reads = Arc::new(AtomicUsize::new(0));
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let mut profile = profile();
    profile.tier = EnvironmentTier::Production;
    profile.autonomy_mode = AutonomyMode::PrepareAndAsk;
    profile.production_autonomy_approval_hash = Some(digest(62));
    let runtime = connector_runtime(REQUEST_ID, Arc::clone(&reads))?;
    let authenticator = FixtureAuthenticator {
        mode: AuthMode::Exact,
        calls: Arc::clone(&auth_calls),
    };
    commit_profile_to_runtime(&mut profile, &runtime, &authenticator)?;
    let registration = registration(&profile)?;
    let runner = EnterpriseRunner::new(
        profile.clone(),
        registration.clone(),
        runtime,
        action_approval_verifier(),
        Box::new(authenticator),
        Box::new(FixedClock(Arc::new(AtomicI64::new(NOW + 20)))),
    )?;
    let authorization = authorization(&profile)?;
    let mut dispatch = deployment_dispatch(&profile, &registration, &authorization)?;
    let decision = bind_decision(&profile, &mut dispatch, EnforcementDecision::Allow)?;
    attach_action_approval(
        &mut dispatch,
        &authorization,
        "approver:bob",
        NOW + 10,
        NOW + 60,
    )?;

    let held = runner.prepare_production_deployment(&dispatch, &decision, &authorization)?;
    assert_eq!(held.prepared.proposal.template, authorization.template);
    assert_eq!(held.blockers, production_readiness_blockers());
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    assert_eq!(auth_calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn account_free_exhibit_binds_transaction_exact_patch_and_replay()
-> Result<(), Box<dyn std::error::Error>> {
    let reads = Arc::new(AtomicUsize::new(0));
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let (runner, profile, registration) =
        engine(AuthMode::Exact, Arc::clone(&reads), Arc::clone(&auth_calls))?;
    let (authorization, snapshot, dispatch, decision) =
        deployment_exhibit_inputs(&profile, &registration)?;

    let mut substituted_snapshot = snapshot.clone();
    substituted_snapshot["metadata"]["resourceVersion"] = json!("83192");
    assert!(matches!(
        runner.run_local_deployment_exhibit(
            &dispatch,
            &decision,
            &authorization,
            &substituted_snapshot,
        ),
        Err(RunnerEngineError::DeploymentSnapshotMismatch)
    ));
    assert_eq!(auth_calls.load(Ordering::SeqCst), 0);

    let exhibit =
        runner.run_local_deployment_exhibit(&dispatch, &decision, &authorization, &snapshot)?;
    assert_eq!(
        exhibit.execution_outcome,
        LocalDeploymentExecutionOutcome::NotSent
    );
    assert_eq!(
        exhibit.deployment.prepared.transaction_id,
        Uuid::from_bytes([0x2a; 16])
    );
    assert_eq!(
        exhibit.snapshot_hash,
        authorization.template.prior_projection_hash
    );
    assert_eq!(
        exhibit.exact_patch_body,
        accordlock_k8s::patch_wire_body(&exhibit.prepared_patch)?
    );
    let patch_text = std::str::from_utf8(&exhibit.exact_patch_body)?;
    assert!(patch_text.contains(&Uuid::from_bytes([0x2a; 16]).to_string()));
    assert!(patch_text.contains(&authorization.authorization_id.to_string()));
    assert_eq!(exhibit.deployment.blockers, production_readiness_blockers());
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    assert_eq!(auth_calls.load(Ordering::SeqCst), 1);

    assert!(matches!(
        runner.run_local_deployment_exhibit(&dispatch, &decision, &authorization, &snapshot,),
        Err(RunnerEngineError::DispatchReplay)
    ));
    Ok(())
}

#[test]
fn local_exhibit_replay_is_rejected_after_durable_runner_reconstruction()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let state_path = root.path().join("deployment-exhibit.sqlite3");
    let (authorization, snapshot, dispatch, decision) = {
        let mut profile = profile();
        let runtime = connector_runtime(REQUEST_ID, Arc::new(AtomicUsize::new(0)))?;
        let authenticator = FixtureAuthenticator {
            mode: AuthMode::Exact,
            calls: Arc::new(AtomicUsize::new(0)),
        };
        commit_profile_to_runtime(&mut profile, &runtime, &authenticator)?;
        let registration = registration(&profile)?;
        let runner = EnterpriseRunner::new_durable(
            profile.clone(),
            registration.clone(),
            runtime,
            action_approval_verifier(),
            Box::new(authenticator),
            Box::new(FixedClock(Arc::new(AtomicI64::new(NOW + 20)))),
            SqliteRunnerStateStore::open(&state_path)?,
        )?;
        let (authorization, snapshot, dispatch, decision) =
            deployment_exhibit_inputs(&profile, &registration)?;
        runner.run_local_deployment_exhibit(&dispatch, &decision, &authorization, &snapshot)?;
        (authorization, snapshot, dispatch, decision)
    };

    let mut profile = profile();
    let runtime = connector_runtime(REQUEST_ID, Arc::new(AtomicUsize::new(0)))?;
    let authenticator = FixtureAuthenticator {
        mode: AuthMode::Exact,
        calls: Arc::new(AtomicUsize::new(0)),
    };
    commit_profile_to_runtime(&mut profile, &runtime, &authenticator)?;
    let registration = registration(&profile)?;
    let runner = EnterpriseRunner::new_durable(
        profile,
        registration,
        runtime,
        action_approval_verifier(),
        Box::new(authenticator),
        Box::new(FixedClock(Arc::new(AtomicI64::new(NOW + 20)))),
        SqliteRunnerStateStore::open(&state_path)?,
    )?;
    assert!(matches!(
        runner.run_local_deployment_exhibit(&dispatch, &decision, &authorization, &snapshot,),
        Err(RunnerEngineError::DispatchReplay)
    ));
    Ok(())
}

#[test]
fn deployment_substitution_is_rejected_without_provider_or_effect_io()
-> Result<(), Box<dyn std::error::Error>> {
    let reads = Arc::new(AtomicUsize::new(0));
    let mut profile = profile();
    profile.tier = EnvironmentTier::Production;
    profile.autonomy_mode = AutonomyMode::PrepareAndAsk;
    profile.production_autonomy_approval_hash = Some(digest(62));
    let runtime = connector_runtime(REQUEST_ID, Arc::clone(&reads))?;
    let authenticator = FixtureAuthenticator {
        mode: AuthMode::Exact,
        calls: Arc::new(AtomicUsize::new(0)),
    };
    commit_profile_to_runtime(&mut profile, &runtime, &authenticator)?;
    let registration = registration(&profile)?;
    let runner = EnterpriseRunner::new(
        profile.clone(),
        registration.clone(),
        runtime,
        action_approval_verifier(),
        Box::new(authenticator),
        Box::new(FixedClock(Arc::new(AtomicI64::new(NOW + 20)))),
    )?;
    let authorization = authorization(&profile)?;
    let mut dispatch = deployment_dispatch(&profile, &registration, &authorization)?;
    let decision = bind_decision(&profile, &mut dispatch, EnforcementDecision::Allow)?;
    if let RunnerAction::DeployEksImage { image_digest, .. } = &mut dispatch.action {
        *image_digest = digest(0x99);
    }
    attach_action_approval(
        &mut dispatch,
        &authorization,
        "approver:bob",
        NOW + 10,
        NOW + 60,
    )?;
    assert!(matches!(
        runner.prepare_production_deployment(&dispatch, &decision, &authorization),
        Err(RunnerEngineError::RunnerBridge(
            RunnerBridgeError::EvaluationActionMismatch
        ))
    ));
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn connector_endpoint_commitment_mismatch_is_rejected_before_any_io()
-> Result<(), Box<dyn std::error::Error>> {
    let reads = Arc::new(AtomicUsize::new(0));
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let clock_calls = Arc::new(AtomicUsize::new(0));
    let baseline_decision = connector_runtime(REQUEST_ID, Arc::clone(&reads))?;
    let mut profile = profile();
    let authenticator = FixtureAuthenticator {
        mode: AuthMode::Exact,
        calls: Arc::clone(&auth_calls),
    };
    commit_profile_to_runtime(&mut profile, &baseline_decision, &authenticator)?;
    let baseline_hash = baseline_decision
        .configuration_commitments()?
        .github_connector_hash;
    let substituted = connector_runtime_variant(
        REQUEST_ID,
        Arc::clone(&reads),
        digest(0x55),
        "acme/payments",
        "substituted.github.example",
        0xa2,
    )?;
    assert_ne!(
        baseline_hash,
        substituted
            .configuration_commitments()?
            .github_connector_hash
    );
    let registration = registration(&profile)?;
    assert!(matches!(
        EnterpriseRunner::new(
            profile,
            registration,
            substituted,
            action_approval_verifier(),
            Box::new(authenticator),
            Box::new(CountingClock {
                now: NOW + 20,
                calls: Arc::clone(&clock_calls),
            }),
        ),
        Err(RunnerEngineError::ConnectorCommitmentMismatch)
    ));
    assert_eq!(clock_calls.load(Ordering::SeqCst), 0);
    assert_eq!(auth_calls.load(Ordering::SeqCst), 0);
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn aws_authenticator_identity_mismatch_is_rejected_before_any_io()
-> Result<(), Box<dyn std::error::Error>> {
    let reads = Arc::new(AtomicUsize::new(0));
    let clock_calls = Arc::new(AtomicUsize::new(0));
    let runtime = connector_runtime(REQUEST_ID, Arc::clone(&reads))?;
    let mut profile = profile();
    let enrolled_authenticator = FixtureAuthenticator {
        mode: AuthMode::Exact,
        calls: Arc::new(AtomicUsize::new(0)),
    };
    commit_profile_to_runtime(&mut profile, &runtime, &enrolled_authenticator)?;
    let registration = registration(&profile)?;
    let runtime_auth_calls = Arc::new(AtomicUsize::new(0));
    assert!(matches!(
        EnterpriseRunner::new(
            profile,
            registration,
            runtime,
            action_approval_verifier(),
            Box::new(FixtureAuthenticator {
                mode: AuthMode::SubstituteIdentity,
                calls: Arc::clone(&runtime_auth_calls),
            }),
            Box::new(CountingClock {
                now: NOW + 20,
                calls: Arc::clone(&clock_calls),
            }),
        ),
        Err(RunnerEngineError::AwsIdentityCommitmentMismatch)
    ));
    assert_eq!(clock_calls.load(Ordering::SeqCst), 0);
    assert_eq!(runtime_auth_calls.load(Ordering::SeqCst), 0);
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn aws_transport_identity_is_committed_and_rechecked_before_any_io()
-> Result<(), Box<dyn std::error::Error>> {
    let reads = Arc::new(AtomicUsize::new(0));
    let clock_calls = Arc::new(AtomicUsize::new(0));
    let baseline_decision = connector_runtime(REQUEST_ID, Arc::clone(&reads))?;
    let mut profile = profile();
    let authenticator = FixtureAuthenticator {
        mode: AuthMode::Exact,
        calls: Arc::new(AtomicUsize::new(0)),
    };
    commit_profile_to_runtime(&mut profile, &baseline_decision, &authenticator)?;
    let baseline_commitments = baseline_decision.configuration_commitments()?;
    let substituted = connector_runtime_variant(
        REQUEST_ID,
        Arc::clone(&reads),
        digest(0x55),
        "acme/payments",
        "api.github.example",
        0xaf,
    )?;
    let substituted_commitments = substituted.configuration_commitments()?;
    assert_ne!(
        baseline_commitments.ecr_connector_hash,
        substituted_commitments.ecr_connector_hash
    );
    assert_ne!(
        baseline_commitments.ecr_transport_identity_hash,
        substituted_commitments.ecr_transport_identity_hash
    );

    // Accept the substituted connector configuration while deliberately
    // retaining the enrolled AWS identity root: the independent AWS binding
    // must still reject it.
    profile.github_connector_hash = substituted_commitments.github_connector_hash;
    profile.ecr_connector_hash = substituted_commitments.ecr_connector_hash;
    profile.kubernetes_connector_hash = substituted_commitments.kubernetes_connector_hash;
    let registration = registration(&profile)?;
    assert!(matches!(
        EnterpriseRunner::new(
            profile,
            registration,
            substituted,
            action_approval_verifier(),
            Box::new(authenticator),
            Box::new(CountingClock {
                now: NOW + 20,
                calls: Arc::clone(&clock_calls),
            }),
        ),
        Err(RunnerEngineError::AwsIdentityCommitmentMismatch)
    ));
    assert_eq!(clock_calls.load(Ordering::SeqCst), 0);
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn copied_authorization_evidence_root_without_signed_approval_is_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let reads = Arc::new(AtomicUsize::new(0));
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let mut value = approved_production_fixture(Arc::clone(&reads), Arc::clone(&auth_calls))?;
    value.dispatch.action_approval = None;
    assert!(matches!(
        value.runner.prepare_production_deployment(
            &value.dispatch,
            &value.decision,
            &value.authorization,
        ),
        Err(RunnerEngineError::ActionApprovalRequired)
    ));
    assert_eq!(auth_calls.load(Ordering::SeqCst), 0);
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn action_approval_authority_substitution_is_rejected_before_any_io()
-> Result<(), Box<dyn std::error::Error>> {
    let reads = Arc::new(AtomicUsize::new(0));
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let clock_calls = Arc::new(AtomicUsize::new(0));
    let runtime = connector_runtime(REQUEST_ID, Arc::clone(&reads))?;
    let mut profile = profile();
    let authenticator = FixtureAuthenticator {
        mode: AuthMode::Exact,
        calls: Arc::clone(&auth_calls),
    };
    commit_profile_to_runtime(&mut profile, &runtime, &authenticator)?;
    profile.action_approval_authority_hash = action_approval_authority_commitment(
        &SigningIdentity::from_seed("action-approval-key", [0xbc; 32]).verifier(),
    );
    let registration = registration(&profile)?;
    assert!(matches!(
        EnterpriseRunner::new(
            profile,
            registration,
            runtime,
            action_approval_verifier(),
            Box::new(authenticator),
            Box::new(CountingClock {
                now: NOW + 20,
                calls: Arc::clone(&clock_calls),
            }),
        ),
        Err(RunnerEngineError::ActionApprovalAuthorityMismatch)
    ));
    assert_eq!(clock_calls.load(Ordering::SeqCst), 0);
    assert_eq!(auth_calls.load(Ordering::SeqCst), 0);
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn self_signed_action_approval_is_rejected_before_authentication()
-> Result<(), Box<dyn std::error::Error>> {
    let reads = Arc::new(AtomicUsize::new(0));
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let mut value = approved_production_fixture(Arc::clone(&reads), Arc::clone(&auth_calls))?;
    let attacker = SigningIdentity::from_seed("action-approval-key", [0xcc; 32]);
    attach_action_approval_with_signer(
        &mut value.dispatch,
        &value.authorization,
        "approver:mallory",
        NOW + 10,
        NOW + 60,
        &attacker,
    )?;

    assert!(matches!(
        value.runner.prepare_production_deployment(
            &value.dispatch,
            &value.decision,
            &value.authorization,
        ),
        Err(RunnerEngineError::ActionApproval(
            ActionApprovalError::InvalidSignature
        ))
    ));
    assert_eq!(auth_calls.load(Ordering::SeqCst), 0);
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn forged_or_wrong_action_approval_is_rejected_before_authentication()
-> Result<(), Box<dyn std::error::Error>> {
    for wrong_action in [false, true] {
        let reads = Arc::new(AtomicUsize::new(0));
        let auth_calls = Arc::new(AtomicUsize::new(0));
        let mut value = approved_production_fixture(Arc::clone(&reads), Arc::clone(&auth_calls))?;
        if wrong_action {
            if let RunnerAction::DeployEksImage { image_digest, .. } = &mut value.dispatch.action {
                *image_digest = digest(0xf1);
            }
        } else {
            let signature = value
                .dispatch
                .action_approval
                .as_mut()
                .and_then(|approval| approval.cose_sign1.last_mut())
                .ok_or("missing approval signature")?;
            *signature ^= 1;
        }
        assert!(matches!(
            value.runner.prepare_production_deployment(
                &value.dispatch,
                &value.decision,
                &value.authorization,
            ),
            Err(RunnerEngineError::ActionApproval(_))
        ));
        assert_eq!(auth_calls.load(Ordering::SeqCst), 0);
        assert_eq!(reads.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[test]
fn expired_action_approval_is_rejected_before_authentication()
-> Result<(), Box<dyn std::error::Error>> {
    let reads = Arc::new(AtomicUsize::new(0));
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let mut value = approved_production_fixture(Arc::clone(&reads), Arc::clone(&auth_calls))?;
    attach_action_approval(
        &mut value.dispatch,
        &value.authorization,
        "approver:bob",
        NOW + 1,
        NOW + 10,
    )?;
    assert!(matches!(
        value.runner.prepare_production_deployment(
            &value.dispatch,
            &value.decision,
            &value.authorization,
        ),
        Err(RunnerEngineError::ActionApproval(
            ActionApprovalError::NotCurrent
        ))
    ));
    assert_eq!(auth_calls.load(Ordering::SeqCst), 0);
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn accepted_action_approval_is_single_use() -> Result<(), Box<dyn std::error::Error>> {
    let reads = Arc::new(AtomicUsize::new(0));
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let value = approved_production_fixture(Arc::clone(&reads), Arc::clone(&auth_calls))?;
    value.runner.prepare_production_deployment(
        &value.dispatch,
        &value.decision,
        &value.authorization,
    )?;
    assert!(matches!(
        value.runner.prepare_production_deployment(
            &value.dispatch,
            &value.decision,
            &value.authorization,
        ),
        Err(RunnerEngineError::ActionApprovalReplay)
    ));
    assert_eq!(auth_calls.load(Ordering::SeqCst), 1);
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn durable_action_approval_replay_is_rejected_after_runner_reconstruction()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let state_path = root.path().join("approval-runner.sqlite3");
    let (authorization, dispatch, decision) = {
        let mut profile = profile();
        profile.tier = EnvironmentTier::Production;
        profile.autonomy_mode = AutonomyMode::PrepareAndAsk;
        profile.production_autonomy_approval_hash = Some(digest(62));
        let runtime = connector_runtime(REQUEST_ID, Arc::new(AtomicUsize::new(0)))?;
        let authenticator = FixtureAuthenticator {
            mode: AuthMode::Exact,
            calls: Arc::new(AtomicUsize::new(0)),
        };
        commit_profile_to_runtime(&mut profile, &runtime, &authenticator)?;
        let registration = registration(&profile)?;
        let runner = EnterpriseRunner::new_durable(
            profile.clone(),
            registration.clone(),
            runtime,
            action_approval_verifier(),
            Box::new(authenticator),
            Box::new(FixedClock(Arc::new(AtomicI64::new(NOW + 20)))),
            SqliteRunnerStateStore::open(&state_path)?,
        )?;
        let authorization = authorization(&profile)?;
        let mut dispatch = deployment_dispatch(&profile, &registration, &authorization)?;
        let decision = bind_decision(&profile, &mut dispatch, EnforcementDecision::Allow)?;
        attach_action_approval(
            &mut dispatch,
            &authorization,
            "approver:bob",
            NOW + 10,
            NOW + 60,
        )?;
        runner.prepare_production_deployment(&dispatch, &decision, &authorization)?;
        (authorization, dispatch, decision)
    };

    let mut profile = profile();
    profile.tier = EnvironmentTier::Production;
    profile.autonomy_mode = AutonomyMode::PrepareAndAsk;
    profile.production_autonomy_approval_hash = Some(digest(62));
    let runtime = connector_runtime(REQUEST_ID, Arc::new(AtomicUsize::new(0)))?;
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let authenticator = FixtureAuthenticator {
        mode: AuthMode::Exact,
        calls: Arc::clone(&auth_calls),
    };
    commit_profile_to_runtime(&mut profile, &runtime, &authenticator)?;
    let registration = registration(&profile)?;
    let runner = EnterpriseRunner::new_durable(
        profile,
        registration,
        runtime,
        action_approval_verifier(),
        Box::new(authenticator),
        Box::new(FixedClock(Arc::new(AtomicI64::new(NOW + 20)))),
        SqliteRunnerStateStore::open(&state_path)?,
    )?;
    assert!(matches!(
        runner.prepare_production_deployment(&dispatch, &decision, &authorization),
        Err(RunnerEngineError::ActionApprovalReplay)
    ));
    assert_eq!(auth_calls.load(Ordering::SeqCst), 0);
    Ok(())
}
