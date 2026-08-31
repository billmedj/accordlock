use std::{
    collections::BTreeSet,
    fs,
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use accordlock_connectors::{
    ClockReadError, ConnectorRuntime, TrustedClock, TrustedEvidenceRoute, TrustedRouteSet,
    ValidityProfile,
};
use accordlock_evaluation::{
    DecisionReason, EnforcementDecision, POLICY_DECISION_SCHEMA_VERSION, PolicyDecisionRecord,
};
use accordlock_ingress::{
    ActivatedIngressRegistry, INGRESS_SCHEMA_VERSION, IngressAuthenticator, IngressClaims,
    IngressKeyStatus, MemoryReplayGuard, RegisteredIngressKey, sign_ingress_request,
};
use accordlock_kernel::{ActivatedAttesterRegistry, KernelContext, evaluate, sign_evaluation};
use accordlock_protocol::{
    AgentProposal, AttesterScope, AttesterStatus, AuthorityDomainState, AuthorityVector,
    CompletenessProfile, DecisionOutcome, DeploymentTemplate, Digest32, EvidenceKind,
    EvidencePayload, PolicyConfig, RegisteredAttester, SigningIdentity, canonical_hash,
    evaluator_verifier_root,
};
use accordlock_provider_adapters::{
    AuthenticatedTransportIdentity, HttpsEndpoint, ecr_artifact_lookup, github_actions_lookup,
    github_review_lookup, kubernetes_target_lookup,
};
use accordlock_runner_engine::{
    DispatchAuthentication, DispatchAuthenticationError, DispatchAuthenticationRequest,
    DispatchAuthenticator, EnterpriseRunner, RunnerProviderEndpoints, RunnerProviderTransports,
    aws_identity_commitment, trusted_provider_sources_for_profile,
};
use accordlock_runner_protocol::{
    AutonomyMode, EnterpriseEnvironmentProfile, EnvironmentTier, RUNNER_PROTOCOL_SCHEMA_VERSION,
    RunnerAction, RunnerCapability, RunnerDispatch, RunnerRegistration,
    action_approval_authority_commitment,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::{
    model::{
        CandidateReceipt, CheckKind, CheckReceipt, CheckStatus, CredentialBundle, Effect,
        MAX_TRUST_RECORD_BYTES, PREFLIGHT_SCHEMA_VERSION, PreflightCommand, PreflightOutcome,
        PreflightProfile, SignedArtifactTrustRecord, SignedBuildTrustRecord,
        SignedPreflightReceipt, TargetReceipt, UnsignedPreflightReceipt, sign_receipt,
    },
    transports::{
        EcrTransport, EksClusterDiscovery, EksDiscoveryTransport, GitHubTransport,
        KubernetesTransport, TargetPrestate,
    },
};

const PLACEHOLDER_COMMIT: &str = "0000000000000000000000000000000000000000";

#[derive(Clone, Copy, Debug)]
struct FixedClock(i64);

impl TrustedClock for FixedClock {
    fn unix_seconds(&self) -> Result<i64, ClockReadError> {
        Ok(self.0)
    }
}

#[derive(Debug)]
struct LocalDispatchAuthenticator {
    identity_hash: Digest32,
}

impl DispatchAuthenticator for LocalDispatchAuthenticator {
    fn public_identity(
        &self,
    ) -> Result<AuthenticatedTransportIdentity, DispatchAuthenticationError> {
        AuthenticatedTransportIdentity::new(
            "accordlock-local-preflight-dispatch-v1",
            format!("runner-key:{}", &self.identity_hash.to_hex()[..16]),
            "inherited-credential:preflight-runner",
            self.identity_hash,
        )
        .map_err(|_| DispatchAuthenticationError::Rejected)
    }

    fn authenticate(
        &self,
        request: DispatchAuthenticationRequest,
    ) -> Result<DispatchAuthentication, DispatchAuthenticationError> {
        let mut hash = Sha256::new();
        hash.update(b"accordlock:v1:local-preflight-dispatch-channel\0");
        hash.update(self.identity_hash.as_bytes());
        hash.update(request.runner_id.as_bytes());
        hash.update(request.dispatch_hash.as_bytes());
        hash.update(request.runner_attestation_hash.as_bytes());
        hash.update(request.trusted_now.to_be_bytes());
        Ok(DispatchAuthentication::new(
            request.runner_id,
            request.dispatch_hash,
            request.runner_attestation_hash,
            Digest32::from_bytes(hash.finalize().into()),
            request.trusted_now,
        ))
    }
}

#[derive(Clone, Copy, Debug)]
struct RunFailure {
    code: &'static str,
}

impl RunFailure {
    const fn new(code: &'static str) -> Self {
        Self { code }
    }
}

#[derive(Debug, Default)]
struct Progress {
    build: Option<SignedBuildTrustRecord>,
    cluster: Option<EksClusterDiscovery>,
    target: Option<TargetPrestate>,
}

/// Reads nonnegative Unix seconds from the local system clock.
///
/// # Errors
/// Returns `TRUSTED_CLOCK_UNAVAILABLE` if the clock is before the Unix epoch
/// or cannot fit the protocol time representation.
pub fn current_unix_seconds() -> Result<i64, &'static str> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "TRUSTED_CLOCK_UNAVAILABLE")?;
    i64::try_from(duration.as_secs()).map_err(|_| "TRUSTED_CLOCK_UNAVAILABLE")
}

/// Executes exactly one read-only deployment preflight and returns an Ed25519
/// signed receipt. Provider and evidence failures become signed
/// `INDETERMINATE` receipts; invalid local bootstrap material is returned as a
/// caller-visible error because no trustworthy receipt can be issued.
///
/// # Errors
/// Returns a stable categorical code when local profile, credential, request,
/// clock, or receipt-signing bootstrap cannot be trusted.
pub fn run_preflight(
    profile: &PreflightProfile,
    credentials: CredentialBundle,
    command: &PreflightCommand,
    trusted_now: i64,
) -> Result<SignedPreflightReceipt, &'static str> {
    profile.validate().map_err(|_| "INVALID_PROFILE")?;
    credentials
        .validate(profile)
        .map_err(|_| "INVALID_CREDENTIALS")?;
    command.validate(profile).map_err(|_| "INVALID_REQUEST")?;
    if trusted_now < profile.created_at || trusted_now >= profile.expires_at {
        return Err("PROFILE_NOT_CURRENT");
    }
    let receipt_seed = credentials
        .receipt_signing_seed
        .seed()
        .map_err(|_| "INVALID_CREDENTIALS")?;
    let master_seed = credentials
        .runner_master_seed
        .seed()
        .map_err(|_| "INVALID_CREDENTIALS")?;
    let profile_hash = profile.digest().map_err(|_| "INVALID_PROFILE")?;
    let request_id = derived_uuid(&master_seed, b"request", command.check_id().as_bytes());
    let runner_id = derived_uuid(&master_seed, b"runner", profile.profile_id.as_bytes());
    let mut progress = Progress::default();
    let shared_profile = Arc::new(profile.clone());
    let shared_credentials = Arc::new(credentials);

    match run_determinate(
        &shared_profile,
        &shared_credentials,
        command,
        trusted_now,
        request_id,
        runner_id,
        master_seed,
        &mut progress,
    ) {
        Ok(payload) => {
            sign_receipt(payload, profile, receipt_seed).map_err(|_| "RECEIPT_SIGNING_FAILED")
        }
        Err(failure) => {
            let payload = indeterminate_receipt(
                profile,
                command,
                trusted_now,
                request_id,
                runner_id,
                profile_hash,
                master_seed,
                &progress,
                failure.code,
            );
            sign_receipt(payload, profile, receipt_seed).map_err(|_| "RECEIPT_SIGNING_FAILED")
        }
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn run_determinate(
    profile: &Arc<PreflightProfile>,
    credentials: &Arc<CredentialBundle>,
    command: &PreflightCommand,
    now: i64,
    request_id: Uuid,
    runner_id: Uuid,
    master_seed: [u8; 32],
    progress: &mut Progress,
) -> Result<UnsignedPreflightReceipt, RunFailure> {
    let PreflightCommand::RunDeploymentPreflight {
        pull_number,
        actions_run_id,
        image_digest,
        ..
    } = command;

    let build: SignedBuildTrustRecord = read_trust_record(
        &profile.build_trust.records_directory,
        &format!("{actions_run_id}.json"),
    )
    .map_err(|()| RunFailure::new("BUILD_TRUST_RECORD_UNAVAILABLE"))?;
    build
        .verify(profile, *actions_run_id, *image_digest, now)
        .map_err(|_| RunFailure::new("BUILD_TRUST_RECORD_INVALID"))?;
    progress.build = Some(build.clone());

    let artifact: SignedArtifactTrustRecord = read_trust_record(
        &profile.artifact_trust.records_directory,
        &format!("{}.json", image_digest.to_hex()),
    )
    .map_err(|()| RunFailure::new("ARTIFACT_TRUST_RECORD_UNAVAILABLE"))?;
    artifact
        .verify(profile, *image_digest, now)
        .map_err(|_| RunFailure::new("ARTIFACT_TRUST_RECORD_INVALID"))?;

    let cluster = EksDiscoveryTransport::new(Arc::clone(profile), Arc::clone(credentials), now)
        .and_then(|transport| transport.describe_cluster())
        .map_err(|_| RunFailure::new("EKS_CLUSTER_DISCOVERY_UNAVAILABLE"))?;
    progress.cluster = Some(cluster.clone());

    let target = KubernetesTransport::discover(profile, credentials, &cluster, now)
        .map_err(|_| RunFailure::new("KUBERNETES_TARGET_UNAVAILABLE"))?;
    progress.target = Some(target.clone());

    let policy = PolicyConfig {
        policy_id: format!("deployment-preflight:{}", profile.environment_id),
        allowed_actors: vec![profile.actor_id.clone()],
        allowed_repositories: vec![profile.github_repository()],
        allowed_image_repositories: vec![profile.ecr_image_repository()],
        allowed_clusters: vec![cluster.cluster_identity.clone()],
        allowed_namespaces: vec![profile.kubernetes.namespace.clone()],
        minimum_review_grade: 3,
        minimum_build_grade: 3,
        maximum_evidence_age_seconds: profile.maximum_source_age_seconds.max(1),
        maximum_authorization_lifetime_seconds: 120,
    };

    let proposal = AgentProposal {
        schema_version: 1,
        request_id,
        tenant: profile.organization_id.clone(),
        actor: profile.actor_id.clone(),
        template: DeploymentTemplate {
            operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
            environment: profile.environment_id.clone(),
            audience: profile.executor_audience.clone(),
            repository: profile.github_repository(),
            commit_sha: build.payload.commit_sha.clone(),
            image_repository: profile.ecr_image_repository(),
            image_digest: *image_digest,
            cluster_identity: cluster.cluster_identity.clone(),
            namespace: profile.kubernetes.namespace.clone(),
            deployment: profile.kubernetes.deployment.clone(),
            deployment_uid: target.deployment_uid.to_string(),
            container: profile.kubernetes.container.clone(),
            container_index: 0,
            prior_image_digest: target.current_image_digest,
            resource_version: target.resource_version.clone(),
            prior_projection_hash: target.projection_hash,
            prior_transaction_annotation: None,
            prior_authorization_annotation: None,
            prior_operation_hash_annotation: None,
        },
    };

    let review_signer = signing_identity(&master_seed, "preflight-review", b"review");
    let build_signer = signing_identity(&master_seed, "preflight-build", b"build");
    let artifact_signer = signing_identity(&master_seed, "preflight-artifact", b"artifact");
    let target_signer = signing_identity(&master_seed, "preflight-target", b"target");
    let action_signer = signing_identity(&master_seed, "preflight-action-approval", b"approval");
    let ingress_signer = signing_identity(&master_seed, "preflight-ingress", b"ingress");
    let evaluator = signing_identity(&master_seed, "preflight-evaluator", b"evaluator");

    let ingress_registration = RegisteredIngressKey {
        key_id: ingress_signer.key_id().to_owned(),
        public_key: ingress_signer.public_key_bytes(),
        tenant: profile.organization_id.clone(),
        actor: profile.actor_id.clone(),
        allowed_audiences: BTreeSet::from([profile.executor_audience.clone()]),
        not_before: now.saturating_sub(60),
        expires_at: now.saturating_add(300),
        status: IngressKeyStatus::Active,
    };

    let issuers = [
        "accordlock-preflight-review",
        "accordlock-preflight-build",
        "accordlock-preflight-artifact",
        "accordlock-preflight-target",
    ];
    let mut attesters = vec![
        registered_attester(
            profile,
            issuers[0],
            &review_signer,
            AttesterScope::Review {
                repository: profile.github_repository(),
            },
        ),
        registered_attester(
            profile,
            issuers[1],
            &build_signer,
            AttesterScope::Build {
                repository: profile.github_repository(),
                workflow_ref: profile.github.workflow_ref.clone(),
            },
        ),
        registered_attester(
            profile,
            issuers[2],
            &artifact_signer,
            AttesterScope::Artifact {
                image_repository: profile.ecr_image_repository(),
            },
        ),
        registered_attester(
            profile,
            issuers[3],
            &target_signer,
            AttesterScope::Target {
                cluster_identity: cluster.cluster_identity.clone(),
                namespace: profile.kubernetes.namespace.clone(),
                deployment_uid: target.deployment_uid.to_string(),
            },
        ),
    ];
    attesters
        .sort_by(|left, right| (&left.issuer, &left.key_id).cmp(&(&right.issuer, &right.key_id)));

    let mut authority = authority_vector(
        profile,
        canonical_hash(&policy).map_err(|_| RunFailure::new("POLICY_CONFIGURATION_INVALID"))?,
    );
    authority.registry.root = ActivatedAttesterRegistry::compute_root(&attesters)
        .map_err(|_| RunFailure::new("ATTESTER_REGISTRY_INVALID"))?;
    authority.principal_registry.root = ActivatedIngressRegistry::compute_root(
        &profile.executor_audience,
        180,
        std::slice::from_ref(&ingress_registration),
    )
    .map_err(|_| RunFailure::new("INGRESS_REGISTRY_INVALID"))?;
    authority.kernel_configuration.root =
        evaluator_verifier_root(evaluator.key_id(), evaluator.public_key_bytes())
            .map_err(|_| RunFailure::new("EVALUATOR_CONFIGURATION_INVALID"))?;

    let github = Arc::new(
        GitHubTransport::new(
            Arc::clone(profile),
            Arc::clone(credentials),
            request_id,
            *pull_number,
            *actions_run_id,
            *image_digest,
            build.clone(),
            now,
        )
        .map_err(|_| RunFailure::new("GITHUB_TRANSPORT_INVALID"))?,
    );
    let ecr = Arc::new(
        EcrTransport::new(
            Arc::clone(profile),
            Arc::clone(credentials),
            request_id,
            *image_digest,
            artifact,
            now,
        )
        .map_err(|_| RunFailure::new("ECR_TRANSPORT_INVALID"))?,
    );
    let kubernetes = Arc::new(
        KubernetesTransport::new(
            Arc::clone(profile),
            Arc::clone(credentials),
            request_id,
            build.payload.commit_sha.clone(),
            *image_digest,
            target.clone(),
            cluster.clone(),
            now,
        )
        .map_err(|_| RunFailure::new("KUBERNETES_TRANSPORT_INVALID"))?,
    );

    let action_verifier = action_signer.verifier();
    let mut environment = EnterpriseEnvironmentProfile {
        schema_version: RUNNER_PROTOCOL_SCHEMA_VERSION,
        profile_id: profile.profile_id,
        organization_id: profile.organization_id.clone(),
        environment_id: profile.environment_id.clone(),
        tier: EnvironmentTier::Staging,
        autonomy_mode: AutonomyMode::Observe,
        production_autonomy_approval_hash: None,
        executor_audience: profile.executor_audience.clone(),
        github_repository: profile.github_repository(),
        github_workflow_ref: profile.github.workflow_ref.clone(),
        aws_account_id: profile.ecr.registry_id.clone(),
        aws_region: profile.ecr.region.clone(),
        ecr_repository: profile.ecr.repository.clone(),
        eks_cluster_name: profile.kubernetes.cluster_name.clone(),
        kubernetes_namespace: profile.kubernetes.namespace.clone(),
        kubernetes_deployment: profile.kubernetes.deployment.clone(),
        kubernetes_container: profile.kubernetes.container.clone(),
        policy_hash: authority.policy.root,
        policy_epoch: authority.policy.epoch,
        github_connector_hash: derived_digest(&master_seed, b"placeholder-github", &[]),
        aws_identity_hash: derived_digest(&master_seed, b"placeholder-aws", &[]),
        ecr_connector_hash: derived_digest(&master_seed, b"placeholder-ecr", &[]),
        kubernetes_connector_hash: derived_digest(&master_seed, b"placeholder-k8s", &[]),
        action_approval_authority_hash: action_approval_authority_commitment(&action_verifier),
        created_at: now.saturating_sub(1),
        expires_at: now.saturating_add(300),
    };
    let ecr_authority = format!("api.ecr.{}.amazonaws.com", profile.ecr.region);
    let endpoints = RunnerProviderEndpoints::new(
        HttpsEndpoint::new(&profile.github.authority, &profile.github.api_base_path)
            .map_err(|_| RunFailure::new("GITHUB_ENDPOINT_INVALID"))?,
        HttpsEndpoint::new(&ecr_authority, "/")
            .map_err(|_| RunFailure::new("ECR_ENDPOINT_INVALID"))?,
        HttpsEndpoint::new(cluster.endpoint_authority(), "/")
            .map_err(|_| RunFailure::new("KUBERNETES_ENDPOINT_INVALID"))?,
        profile
            .github
            .maximum_response_bytes
            .min(profile.ecr.maximum_response_bytes)
            .min(profile.kubernetes.maximum_response_bytes),
    );
    let sources = trusted_provider_sources_for_profile(
        &environment,
        endpoints,
        RunnerProviderTransports::new(github, ecr, kubernetes),
    )
    .map_err(|_| RunFailure::new("PROVIDER_COMPOSITION_INVALID"))?;
    let github_prefix = source_prefix(&profile.github.authority, &profile.github.api_base_path);
    let kubernetes_prefix = source_prefix(cluster.endpoint_authority(), "/");
    let routes = TrustedRouteSet::new(
        TrustedEvidenceRoute::new(
            EvidenceKind::Review,
            issuers[0],
            &github_prefix,
            review_signer,
        )
        .map_err(|_| RunFailure::new("CONNECTOR_ROUTE_INVALID"))?,
        TrustedEvidenceRoute::new(
            EvidenceKind::Build,
            issuers[1],
            &github_prefix,
            build_signer,
        )
        .map_err(|_| RunFailure::new("CONNECTOR_ROUTE_INVALID"))?,
        TrustedEvidenceRoute::new(
            EvidenceKind::Artifact,
            issuers[2],
            format!("https://{ecr_authority}/"),
            artifact_signer,
        )
        .map_err(|_| RunFailure::new("CONNECTOR_ROUTE_INVALID"))?,
        TrustedEvidenceRoute::new(
            EvidenceKind::Target,
            issuers[3],
            kubernetes_prefix,
            target_signer,
        )
        .map_err(|_| RunFailure::new("CONNECTOR_ROUTE_INVALID"))?,
    )
    .map_err(|_| RunFailure::new("CONNECTOR_ROUTE_INVALID"))?;
    let validity = ValidityProfile::new(
        profile.evidence_ttl_seconds,
        profile.maximum_source_age_seconds,
        profile.maximum_future_skew_seconds,
        CompletenessProfile::HermeticInputsV1,
    )
    .map_err(|_| RunFailure::new("EVIDENCE_VALIDITY_INVALID"))?;
    let runtime = ConnectorRuntime::new(
        sources,
        routes,
        Box::new(FixedClock(now)),
        authority.clone(),
        validity,
    );
    let commitments = runtime
        .configuration_commitments()
        .map_err(|_| RunFailure::new("CONNECTOR_COMMITMENT_FAILED"))?;
    let authenticator = LocalDispatchAuthenticator {
        identity_hash: derived_digest(&master_seed, b"dispatch-authenticator", &[]),
    };
    let authenticator_identity = authenticator
        .public_identity()
        .map_err(|_| RunFailure::new("DISPATCH_AUTHENTICATOR_INVALID"))?;
    environment.github_connector_hash = commitments.github_connector_hash;
    environment.ecr_connector_hash = commitments.ecr_connector_hash;
    environment.kubernetes_connector_hash = commitments.kubernetes_connector_hash;
    environment.aws_identity_hash = aws_identity_commitment(
        &environment.aws_account_id,
        &environment.aws_region,
        commitments.ecr_transport_identity_hash,
        commitments.kubernetes_transport_identity_hash,
        authenticator_identity.digest(),
    );

    let registration = RunnerRegistration {
        schema_version: RUNNER_PROTOCOL_SCHEMA_VERSION,
        runner_id,
        organization_id: profile.organization_id.clone(),
        environment_id: profile.environment_id.clone(),
        environment_profile_hash: environment
            .digest()
            .map_err(|_| RunFailure::new("ENVIRONMENT_PROFILE_INVALID"))?,
        runner_attestation_hash: derived_digest(&master_seed, b"runner-attestation", &[]),
        capabilities: vec![
            RunnerCapability::ObserveGithub,
            RunnerCapability::ObserveEcr,
            RunnerCapability::ObserveKubernetes,
        ],
        enrolled_at: now.saturating_sub(1),
        expires_at: now.saturating_add(300),
    };
    let registration_hash = registration
        .digest()
        .map_err(|_| RunFailure::new("RUNNER_REGISTRATION_INVALID"))?;
    let runner = EnterpriseRunner::new(
        environment.clone(),
        registration.clone(),
        runtime,
        action_verifier,
        Box::new(authenticator),
        Box::new(FixedClock(now)),
    )
    .map_err(|_| RunFailure::new("RUNNER_BOOTSTRAP_FAILED"))?;

    let action = RunnerAction::ObserveSupplyChain {
        review_lookup_id: github_review_lookup(request_id, *pull_number)
            .map_err(|_| RunFailure::new("LOOKUP_INVALID"))?
            .as_str()
            .to_owned(),
        build_lookup_id: github_actions_lookup(request_id, *actions_run_id)
            .map_err(|_| RunFailure::new("LOOKUP_INVALID"))?
            .as_str()
            .to_owned(),
        artifact_lookup_id: ecr_artifact_lookup(request_id, *image_digest)
            .map_err(|_| RunFailure::new("LOOKUP_INVALID"))?
            .as_str()
            .to_owned(),
        target_lookup_id: kubernetes_target_lookup(
            request_id,
            target.deployment_uid,
            &target.resource_version,
        )
        .map_err(|_| RunFailure::new("LOOKUP_INVALID"))?
        .as_str()
        .to_owned(),
    };
    let task_hash = derived_digest(&master_seed, b"task", request_id.as_bytes());
    let reservation_hash = derived_digest(&master_seed, b"reservation", request_id.as_bytes());
    let decision = PolicyDecisionRecord {
        schema_version: POLICY_DECISION_SCHEMA_VERSION,
        decision_id: derived_uuid(&master_seed, b"decision", request_id.as_bytes()),
        task_hash,
        action_hash: action
            .digest()
            .map_err(|_| RunFailure::new("RUNNER_ACTION_INVALID"))?,
        sequence: 0,
        parent_decision_hash: None,
        requirement_hashes: vec![authority.policy.root],
        transformation_step_hashes: vec![build.payload.input_manifest_root],
        conformance_evaluation_hashes: Vec::new(),
        resource_request_hashes: Vec::new(),
        resource_quota_hashes: Vec::new(),
        resource_reservation_hashes: vec![reservation_hash],
        baseline_decision: EnforcementDecision::Allow,
        decision: EnforcementDecision::Allow,
        reasons: vec![DecisionReason::RequirementSatisfied],
        policy_epoch: environment.policy_epoch,
        evaluated_at: now.saturating_sub(1),
    };
    let policy_decision_hash = decision
        .digest()
        .map_err(|_| RunFailure::new("POLICY_DECISION_INVALID"))?;
    let dispatch = RunnerDispatch {
        schema_version: RUNNER_PROTOCOL_SCHEMA_VERSION,
        dispatch_id: request_id,
        task_id: derived_uuid(&master_seed, b"task-id", request_id.as_bytes()),
        task_hash,
        session_id: format!("preflight-{}", command.check_id()),
        principal_id: profile.actor_id.clone(),
        runner_id,
        environment_profile_hash: environment
            .digest()
            .map_err(|_| RunFailure::new("ENVIRONMENT_PROFILE_INVALID"))?,
        runner_registration_hash: registration_hash,
        policy_decision_hash,
        resource_reservation_hash: reservation_hash,
        authorization_id: derived_uuid(
            &master_seed,
            b"observe-authorization",
            request_id.as_bytes(),
        ),
        authorization_hash: derived_digest(
            &master_seed,
            b"observe-authorization",
            request_id.as_bytes(),
        ),
        action_approval: None,
        action,
        created_at: now.saturating_sub(1),
        expires_at: now.saturating_add(60),
    };
    let dispatch_hash = dispatch
        .digest(&registration)
        .map_err(|_| RunFailure::new("RUNNER_DISPATCH_INVALID"))?;
    let collected = runner
        .collect_evidence(&dispatch, &decision)
        .map_err(|_| RunFailure::new("EVIDENCE_COLLECTION_FAILED"))?;

    let ingress_registry = ActivatedIngressRegistry::new(
        authority.principal_registry.clone(),
        profile.executor_audience.clone(),
        180,
        vec![ingress_registration],
    )
    .map_err(|_| RunFailure::new("INGRESS_REGISTRY_INVALID"))?;
    let ingress_authenticator =
        IngressAuthenticator::new(ingress_registry, MemoryReplayGuard::default())
            .map_err(|_| RunFailure::new("INGRESS_AUTHENTICATOR_INVALID"))?;
    let ingress_claims = IngressClaims {
        schema_version: INGRESS_SCHEMA_VERSION,
        audience: profile.executor_audience.clone(),
        issued_at: now.saturating_sub(1),
        expires_at: now.saturating_add(60),
        nonce: derived_uuid(&master_seed, b"ingress-nonce", request_id.as_bytes()),
        proposal: proposal.clone(),
    };
    let signed_ingress = sign_ingress_request(ingress_claims, &ingress_signer)
        .map_err(|_| RunFailure::new("INGRESS_SIGNING_FAILED"))?;
    let ingress_wire = serde_json::to_string(&signed_ingress)
        .map_err(|_| RunFailure::new("INGRESS_SERIALIZATION_FAILED"))?;
    let authenticated_ingress = ingress_authenticator
        .authenticate_json(&ingress_wire, now)
        .map_err(|_| RunFailure::new("INGRESS_AUTHENTICATION_FAILED"))?;
    let attester_registry = ActivatedAttesterRegistry::new(authority.registry.clone(), attesters)
        .map_err(|_| RunFailure::new("ATTESTER_REGISTRY_INVALID"))?;
    let context = KernelContext::from_authenticated_ingress(
        authenticated_ingress,
        now,
        derived_uuid(&master_seed, b"evaluation-nonce", request_id.as_bytes()),
        policy,
        authority,
        attester_registry,
    )
    .map_err(|_| RunFailure::new("KERNEL_CONTEXT_INVALID"))?;
    let evaluation = evaluate(&proposal, &collected.evidence, &context)
        .map_err(|_| RunFailure::new("KERNEL_EVALUATION_FAILED"))?;
    let outcome = match evaluation.outcome {
        DecisionOutcome::Allow => PreflightOutcome::Passed,
        DecisionOutcome::Deny => PreflightOutcome::Blocked,
    };
    let reason_codes = evaluation
        .reasons
        .iter()
        .copied()
        .map(reason_code)
        .collect();
    let evidence_root = evaluation.evidence_root;
    let valid_until = collected
        .evidence
        .evidence
        .iter()
        .map(|item| item.assertion.valid_until)
        .min();
    let checks = checks_from_evidence(&collected.evidence.evidence, now)?;
    let evaluation_attestation = sign_evaluation(evaluation, &evaluator)
        .map_err(|_| RunFailure::new("EVALUATION_SIGNING_FAILED"))?;

    Ok(UnsignedPreflightReceipt {
        schema_version: PREFLIGHT_SCHEMA_VERSION,
        check_id: command.check_id(),
        request_id,
        environment_id: profile.environment_id.clone(),
        environment_profile_hash: profile
            .digest()
            .map_err(|_| RunFailure::new("PROFILE_DIGEST_FAILED"))?,
        runner_id,
        runner_registration_hash: registration_hash,
        dispatch_hash,
        policy_decision_hash: Some(policy_decision_hash),
        outcome,
        reason_codes,
        candidate: candidate_receipt(profile, command, Some(&build)),
        target: target_receipt(profile, Some(&target), Some(&cluster)),
        checks,
        evidence_root: Some(evidence_root),
        evaluation_attestation: Some(evaluation_attestation),
        started_at: now,
        completed_at: now,
        valid_until,
        effect: Effect::None,
        deployment_performed: false,
    })
}

fn checks_from_evidence(
    evidence: &[accordlock_protocol::SignedEvidence],
    now: i64,
) -> Result<Vec<CheckReceipt>, RunFailure> {
    let mut checks = Vec::with_capacity(4);
    for item in evidence {
        let assertion = &item.assertion;
        let freshness = now.saturating_sub(assertion.observed_at);
        let (kind, passed, summary, blocked_code) = match &assertion.payload {
            EvidencePayload::Review { approved, .. } => (
                CheckKind::CodeReview,
                *approved,
                if *approved {
                    "Required review is approved."
                } else {
                    "Required review is not approved."
                },
                "REVIEW_NOT_APPROVED",
            ),
            EvidencePayload::Build { succeeded, .. } => (
                CheckKind::Build,
                *succeeded,
                if *succeeded {
                    "The selected build completed successfully."
                } else {
                    "The selected build did not succeed."
                },
                "BUILD_NOT_SUCCESSFUL",
            ),
            EvidencePayload::Artifact {
                signature_valid,
                quarantined,
                ..
            } => {
                let passed = *signature_valid && !*quarantined;
                (
                    CheckKind::Image,
                    passed,
                    if passed {
                        "The image is trusted and not quarantined."
                    } else {
                        "The image trust check failed."
                    },
                    "IMAGE_TRUST_FAILED",
                )
            }
            EvidencePayload::Target { .. } => (
                CheckKind::Target,
                true,
                "The deployment target is current and exactly identified.",
                "TARGET_STATE_MISMATCH",
            ),
        };
        checks.push(CheckReceipt {
            kind,
            status: if passed {
                CheckStatus::Passed
            } else {
                CheckStatus::Blocked
            },
            summary: summary.to_owned(),
            reason_code: (!passed).then(|| blocked_code.to_owned()),
            observed_at: Some(assertion.observed_at),
            freshness_seconds: Some(freshness),
            evidence_reference: Some(assertion.source_uri.clone()),
        });
    }
    checks.sort_by_key(|check| match check.kind {
        CheckKind::CodeReview => 0,
        CheckKind::Build => 1,
        CheckKind::Image => 2,
        CheckKind::Target => 3,
    });
    if checks.len() != 4 {
        return Err(RunFailure::new("EVIDENCE_SET_INCOMPLETE"));
    }
    Ok(checks)
}

#[allow(clippy::too_many_arguments)]
fn indeterminate_receipt(
    profile: &PreflightProfile,
    command: &PreflightCommand,
    now: i64,
    request_id: Uuid,
    runner_id: Uuid,
    profile_hash: Digest32,
    master_seed: [u8; 32],
    progress: &Progress,
    reason: &'static str,
) -> UnsignedPreflightReceipt {
    let checks = [
        CheckKind::CodeReview,
        CheckKind::Build,
        CheckKind::Image,
        CheckKind::Target,
    ]
    .into_iter()
    .map(|kind| CheckReceipt {
        kind,
        status: CheckStatus::Indeterminate,
        summary: "This check could not be completed from trusted evidence.".to_owned(),
        reason_code: Some(reason.to_owned()),
        observed_at: None,
        freshness_seconds: None,
        evidence_reference: None,
    })
    .collect();
    UnsignedPreflightReceipt {
        schema_version: PREFLIGHT_SCHEMA_VERSION,
        check_id: command.check_id(),
        request_id,
        environment_id: profile.environment_id.clone(),
        environment_profile_hash: profile_hash,
        runner_id,
        runner_registration_hash: derived_digest(
            &master_seed,
            b"indeterminate-registration",
            request_id.as_bytes(),
        ),
        dispatch_hash: derived_digest(
            &master_seed,
            b"indeterminate-dispatch",
            request_id.as_bytes(),
        ),
        policy_decision_hash: None,
        outcome: PreflightOutcome::Indeterminate,
        reason_codes: vec![reason.to_owned()],
        candidate: candidate_receipt(profile, command, progress.build.as_ref()),
        target: target_receipt(profile, progress.target.as_ref(), progress.cluster.as_ref()),
        checks,
        evidence_root: None,
        evaluation_attestation: None,
        started_at: now,
        completed_at: now,
        valid_until: None,
        effect: Effect::None,
        deployment_performed: false,
    }
}

fn candidate_receipt(
    profile: &PreflightProfile,
    command: &PreflightCommand,
    build: Option<&SignedBuildTrustRecord>,
) -> CandidateReceipt {
    let PreflightCommand::RunDeploymentPreflight {
        pull_number,
        actions_run_id,
        image_digest,
        ..
    } = command;
    CandidateReceipt {
        repository: profile.github_repository(),
        pull_number: *pull_number,
        commit_sha: build.map_or_else(
            || PLACEHOLDER_COMMIT.to_owned(),
            |value| value.payload.commit_sha.clone(),
        ),
        workflow_ref: profile.github.workflow_ref.clone(),
        actions_run_id: *actions_run_id,
        ecr_repository: profile.ecr_image_repository(),
        image_digest: *image_digest,
    }
}

fn target_receipt(
    profile: &PreflightProfile,
    target: Option<&TargetPrestate>,
    cluster: Option<&EksClusterDiscovery>,
) -> TargetReceipt {
    TargetReceipt {
        cluster_identity: target
            .map(|value| value.cluster_identity.clone())
            .or_else(|| cluster.map(|value| value.cluster_identity.clone()))
            .unwrap_or_else(|| "unresolved".to_owned()),
        cluster_endpoint: target
            .map(|value| value.cluster_endpoint.clone())
            .or_else(|| cluster.map(|value| value.cluster_endpoint.clone()))
            .unwrap_or_else(|| "unresolved".to_owned()),
        cluster_ca_hash: target
            .map(|value| value.cluster_ca_hash)
            .or_else(|| cluster.map(|value| value.cluster_ca_hash))
            .unwrap_or_else(|| Digest32::from_bytes([0; 32])),
        namespace: profile.kubernetes.namespace.clone(),
        deployment: profile.kubernetes.deployment.clone(),
        deployment_uid: target.map_or_else(
            || "unresolved".to_owned(),
            |value| value.deployment_uid.to_string(),
        ),
        resource_version: target.map_or_else(
            || "unresolved".to_owned(),
            |value| value.resource_version.clone(),
        ),
        container: profile.kubernetes.container.clone(),
        observed_image_digest: target.map_or_else(
            || Digest32::from_bytes([0; 32]),
            |value| value.current_image_digest,
        ),
    }
}

fn read_trust_record<T: serde::de::DeserializeOwned>(
    directory: &Path,
    file_name: &str,
) -> Result<T, ()> {
    if file_name.is_empty()
        || file_name.len() > 128
        || !file_name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
    {
        return Err(());
    }
    let root = fs::canonicalize(directory).map_err(|_| ())?;
    if !root.is_dir() {
        return Err(());
    }
    let candidate = fs::canonicalize(root.join(file_name)).map_err(|_| ())?;
    if candidate.parent() != Some(root.as_path()) || !candidate.is_file() {
        return Err(());
    }
    let metadata = fs::metadata(&candidate).map_err(|_| ())?;
    if metadata.len() > u64::try_from(MAX_TRUST_RECORD_BYTES).unwrap_or(u64::MAX) {
        return Err(());
    }
    let bytes = fs::read(candidate).map_err(|_| ())?;
    serde_json::from_slice(&bytes).map_err(|_| ())
}

fn registered_attester(
    profile: &PreflightProfile,
    issuer: &str,
    signer: &SigningIdentity,
    scope: AttesterScope,
) -> RegisteredAttester {
    RegisteredAttester {
        tenant: profile.organization_id.clone(),
        environment: profile.environment_id.clone(),
        issuer: issuer.to_owned(),
        key_id: signer.key_id().to_owned(),
        public_key: signer.public_key_bytes(),
        principal_id: format!("runner:{}", profile.profile_id),
        base_grade: 3,
        status: AttesterStatus::Active,
        scopes: vec![scope],
    }
}

fn authority_vector(profile: &PreflightProfile, policy_root: Digest32) -> AuthorityVector {
    AuthorityVector {
        policy: AuthorityDomainState {
            root: policy_root,
            epoch: 1,
            activation_id: domain_uuid(profile, b"policy"),
        },
        registry: authority_domain(profile, b"registry"),
        revocation: authority_domain(profile, b"revocation"),
        connector: authority_domain(profile, b"connector"),
        resource: authority_domain(profile, b"resource"),
        signer: authority_domain(profile, b"signer"),
        mediation: authority_domain(profile, b"mediation"),
        grant_registry: authority_domain(profile, b"grant-registry"),
        office_act_registry: authority_domain(profile, b"office-act-registry"),
        principal_registry: authority_domain(profile, b"principal-registry"),
        workload_build_allowlist: authority_domain(profile, b"workload-build-allowlist"),
        kernel_configuration: authority_domain(profile, b"kernel-configuration"),
    }
}

fn authority_domain(profile: &PreflightProfile, label: &[u8]) -> AuthorityDomainState {
    let profile_bytes = profile.profile_id.as_bytes();
    AuthorityDomainState {
        root: domain_hash(
            b"accordlock:v1:preflight-authority-root\0",
            label,
            profile_bytes,
        ),
        epoch: 1,
        activation_id: domain_uuid(profile, label),
    }
}

fn domain_uuid(profile: &PreflightProfile, label: &[u8]) -> Uuid {
    let digest = domain_hash(
        b"accordlock:v1:preflight-authority-activation\0",
        label,
        profile.profile_id.as_bytes(),
    );
    uuid_from_digest(digest)
}

fn signing_identity(seed: &[u8; 32], key_id: &str, label: &[u8]) -> SigningIdentity {
    SigningIdentity::from_seed(key_id, derive_seed(seed, label))
}

fn derive_seed(seed: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"accordlock:v1:preflight-derived-key\0");
    hash.update(u64::try_from(label.len()).unwrap_or(u64::MAX).to_be_bytes());
    hash.update(label);
    hash.update(seed);
    hash.finalize().into()
}

fn derived_digest(seed: &[u8; 32], label: &[u8], context: &[u8]) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(b"accordlock:v1:preflight-derived-value\0");
    hash.update(u64::try_from(label.len()).unwrap_or(u64::MAX).to_be_bytes());
    hash.update(label);
    hash.update(
        u64::try_from(context.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hash.update(context);
    hash.update(seed);
    Digest32::from_bytes(hash.finalize().into())
}

fn derived_uuid(seed: &[u8; 32], label: &[u8], context: &[u8]) -> Uuid {
    uuid_from_digest(derived_digest(seed, label, context))
}

fn uuid_from_digest(digest: Digest32) -> Uuid {
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    if bytes == [0; 16] {
        bytes[15] = 1;
    }
    Uuid::from_bytes(bytes)
}

fn domain_hash(domain: &[u8], label: &[u8], context: &[u8]) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(u64::try_from(label.len()).unwrap_or(u64::MAX).to_be_bytes());
    hash.update(label);
    hash.update(
        u64::try_from(context.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hash.update(context);
    Digest32::from_bytes(hash.finalize().into())
}

fn source_prefix(authority: &str, base_path: &str) -> String {
    if base_path == "/" {
        format!("https://{authority}/")
    } else {
        format!("https://{authority}{base_path}/")
    }
}

fn reason_code(reason: accordlock_protocol::ReasonCode) -> String {
    serde_json::to_string(&reason)
        .unwrap_or_else(|_| "\"EVIDENCE_DEFECTIVE\"".to_owned())
        .trim_matches('"')
        .to_owned()
}
