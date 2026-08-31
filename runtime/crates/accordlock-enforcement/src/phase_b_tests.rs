#![allow(
    clippy::expect_used,
    clippy::manual_let_else,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::{
    collections::BTreeSet,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicI64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use accordlock_dispatch::{
    CredentialProfile, DispatchBounds, LogicalOwner, PhysicalResourceId,
    authority_version_from_vector,
};
use accordlock_eks_broker::{
    BrokerEndpointConfig, BrokerManagementIdentities, BrokerManagementIdentity, BrokerProfile,
    CredentialSourceError, ManagementBearer, ManagementCredentialRequest,
};
use accordlock_eks_profile::{
    CaTrustCommitment, EksBrokerManagementBindings, EksCredentialLifecyclePolicy,
    EksManagementAuthorityBinding, EksRouteProfileInput, PinnedSocketTarget,
};
use accordlock_executor::{
    ExecutorConfig, NativeEksResponse, NativeGetRequest, NativePatchRequest,
    NativePreWriteAuthorization, TransportFailure,
};
use accordlock_ingress::{
    ActivatedIngressRegistry, INGRESS_SCHEMA_VERSION, IngressAuthenticator, IngressClaims,
    IngressKeyStatus, IngressRecoveryProbe, MemoryReplayGuard, RegisteredIngressKey,
    sign_ingress_request,
};
use accordlock_protocol::{
    AgentProposal, AuthorityDomainState, AuthorityVector, CanonicalEncode, CapabilityGrant,
    DecisionOutcome, DeploymentTemplate, Digest32, DispatchDeadlinePolicy,
    EVALUATION_ATTESTATION_SCHEMA_VERSION, EVALUATION_DOMAIN, EXECUTION_AUTHORIZATION_DOMAIN,
    EXECUTION_AUTHORIZATION_SCHEMA_VERSION, EvaluationAttestation, ExecutionAuthorization,
    ReasonCode, SignedAuthorization, SignedEvaluation, SigningIdentity, authorization_signer_root,
    canonical_hash, evaluator_verifier_root, sign_cose,
};
use accordlock_state::{
    AcquiredBrokerOperationRequest, AuthenticatedDispatchCredentialReview, BrokerSecretObservation,
    BrokerTokenIssueObservation, ClaimedControlWork, ControlConsumptionCommitOutcome,
    ControlIssuanceCommitOutcome, ControlPlaneState, ControlSubmissionIntakeOutcome,
    ControlWorkClaimOutcome, ControlWorkClaimRequest, ControlWorkerRole,
    DispatchAcquisitionAuthority, DispatchCredentialReviewClaims, EksDestinationProfile,
    EksDestinationRegistryState, GrantRegistration, InMemoryStore, IssuedAuthorizationRecord,
    RejectedDispatchCredentialReview,
};
use uuid::Uuid;

use super::*;

// Self-signed P-256 test trust anchor. Keeping the DER inline makes the
// trusted-bootstrap tests exercise the production rustls constructor without
// adding a certificate-generation dependency or a release harness backdoor.
const BOOTSTRAP_CA_DER_HEX: &str = "308201513081f7a00302010202140458e95204d7c230dd4e4da23695e390b18f6d51300a06082a8648ce3d04030230173115301306035504030c0c70686173652d622e74657374301e170d3236303831363138353435335a170d3336303831333138353435335a30173115301306035504030c0c70686173652d622e746573743059301306072a8648ce3d020106082a8648ce3d030107034200046087fc481ea769083a3691674de0eab51e58e0cf828f90bfc604a216d97a9e4031b2199d0c90c72e1732605b8d3b9117350b172f6cc65e19e9975023a78f4fa1a321301f301d0603551d0e041604142770d7aeb49b30e919756e1c7daa8dee158056b3300a06082a8648ce3d0403020349003046022100f2418625b9fac1458e9c8082fce49b16b604a36403c0e00b8a965c1df0eba513022100cceaa32e2d6db1896f3d25a0e9520df4975e5bbcf89df1fb9fd6f98526a26bfd";

fn bootstrap_ca_der() -> Vec<u8> {
    fn nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => unreachable!("static DER hex is lowercase ASCII"),
        }
    }

    BOOTSTRAP_CA_DER_HEX
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect()
}

fn route(socket_octet: u8) -> EksRouteProfile {
    let ca_der = bootstrap_ca_der();
    EksRouteProfile::new(EksRouteProfileInput {
        cluster_trust_domain: "spiffe://example.test/eks/prod-a",
        cluster_identity: "eks://prod-a",
        api_server_identity: "urn:accordlock:api:prod-a",
        dns_server_name: "api.prod-a.eks.amazonaws.com",
        port: 443,
        socket_target: PinnedSocketTarget::new(SocketAddr::from(([192, 0, 2, socket_octet], 443)))
            .unwrap(),
        ca_trust_commitment: CaTrustCommitment::from_der_certificates(&[ca_der]).unwrap(),
        namespace: "payments",
        deployment_name: "api",
        deployment_uid: "11111111-1111-4111-8111-111111111111",
        attempt_service_account_name: "accordlock-attempt",
        attempt_service_account_uid: "22222222-2222-4222-8222-222222222222",
        token_audience: "urn:accordlock:kubernetes-api:prod-a",
    })
    .unwrap()
}

#[test]
fn restart_routing_includes_broker_artifacts_attempts_and_no_send_cleanup_only() {
    assert!(requires_broker_restart(
        DispatchAcquisitionDisposition::BrokerArtifactPresent
    ));
    assert!(requires_broker_restart(
        DispatchAcquisitionDisposition::AttemptInFlight
    ));
    assert!(requires_broker_restart(
        DispatchAcquisitionDisposition::RecoveryNoSend
    ));
    for disposition in [
        DispatchAcquisitionDisposition::Expired,
        DispatchAcquisitionDisposition::Superseded,
        DispatchAcquisitionDisposition::RecoveryRetired,
        DispatchAcquisitionDisposition::AdmissionArtifactPresent,
        DispatchAcquisitionDisposition::Terminal,
        DispatchAcquisitionDisposition::QueueDisposed,
    ] {
        assert!(!requires_broker_restart(disposition));
    }
}

#[test]
fn public_readiness_report_is_complete_and_not_a_bypass() {
    assert_eq!(
        production_readiness_blockers().map(EnforcementReadinessBlocker::code),
        [
            "MANAGEMENT_RBAC_LIVE_PROOF",
            "AUTHENTICATED_WEBHOOK_CALLER_BOUNDARY",
            "KUBERNETES_API_AUDIENCE_LIVE_PROOF",
        ]
    );
    assert_eq!(
        production_readiness_blocked(Uuid::from_u128(0x14ff)),
        EnforcementOutcome::ReadinessBlocked {
            acquisition_id: Uuid::from_u128(0x14ff),
            blockers: production_readiness_blockers(),
        }
    );
}

#[test]
fn pre_work_outcomes_expose_only_server_selected_acquisition_identity() {
    let acquisition_id = Uuid::from_u128(0x1401);
    let outcomes = [
        EnforcementOutcome::NoWork { acquisition_id },
        EnforcementOutcome::QueueDisposed { acquisition_id },
        EnforcementOutcome::AcquisitionOutcomeUnknown { acquisition_id },
        EnforcementOutcome::AcquisitionInert {
            acquisition_id,
            disposition: DispatchAcquisitionDisposition::BrokerArtifactPresent,
        },
    ];
    for outcome in outcomes {
        let observed = match outcome {
            EnforcementOutcome::NoWork { acquisition_id }
            | EnforcementOutcome::QueueDisposed { acquisition_id }
            | EnforcementOutcome::AcquisitionOutcomeUnknown { acquisition_id }
            | EnforcementOutcome::AcquisitionInert { acquisition_id, .. } => acquisition_id,
            _ => unreachable!("fixture contains only pre-work outcomes"),
        };
        assert_eq!(observed, acquisition_id);
    }
}

#[test]
fn unified_route_rejects_transport_substitution_at_bootstrap() {
    let fixed = route(21);
    let substituted = route(22);
    assert_eq!(
        validate_unified_route(&fixed, &fixed, &substituted),
        Err(EnforcementConfigError::ExecutorRouteMismatch(
            RouteField::SocketTarget
        ))
    );
}

#[test]
fn restart_stage_is_distinct_from_productive_provider_effect() {
    let transaction_id = Uuid::from_u128(0x1402);
    let outcome = quarantined(
        transaction_id,
        EnforcementStage::DurableBrokerLifecycle,
        QuarantineReason::OutcomeUnknown,
        None,
        CredentialRetirement::Unknown,
    );
    assert!(matches!(
        outcome,
        EnforcementOutcome::Quarantined {
            transaction_id: observed,
            stage: EnforcementStage::DurableBrokerLifecycle,
            reason: QuarantineReason::OutcomeUnknown,
            ..
        } if observed == transaction_id
    ));
}

const CONTROL_NOW: i64 = 100;
const CONTROL_AUDIENCE: &str = "accordlock-executor:prod";
const TOKEN_DIGEST: [u8; 32] = [0xd1; 32];
const SECRET_UID: &str = "33333333-3333-4333-8333-333333333333";

#[derive(Debug)]
struct ControlClock(AtomicI64);

impl ControlClock {
    fn new(now: i64) -> Self {
        Self(AtomicI64::new(now))
    }

    fn set(&self, now: i64) {
        self.0.store(now, Ordering::SeqCst);
    }

    fn advance(&self) -> i64 {
        self.0.fetch_add(1, Ordering::SeqCst) + 1
    }

    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

impl accordlock_state::TrustedClock for ControlClock {
    fn now_unix_seconds(&self) -> Result<i64, StateError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

#[derive(Clone, Copy, Debug)]
struct OrchestrationClock;

impl TrustedClock for OrchestrationClock {
    fn unix_seconds(&self) -> Result<i64, String> {
        Ok(120)
    }
}

#[derive(Debug)]
struct BootstrapManagementCredentials;

impl ManagementCredentialSource for BootstrapManagementCredentials {
    fn credential(
        &self,
        _request: &ManagementCredentialRequest,
    ) -> Result<ManagementBearer, CredentialSourceError> {
        Err(CredentialSourceError::Unavailable)
    }
}

#[derive(Debug)]
struct BootstrapTransport(EksRouteProfile);

impl NativeEksTransport for BootstrapTransport {
    fn route_profile(&self) -> &EksRouteProfile {
        &self.0
    }

    fn operation_timeout_upper_bound(&self) -> Duration {
        Duration::from_secs(1)
    }

    fn get_deployment(
        &self,
        _request: NativeGetRequest<'_>,
    ) -> Result<NativeEksResponse, TransportFailure> {
        panic!("bootstrap test never performs provider I/O")
    }

    fn patch_deployment(
        &self,
        _request: NativePatchRequest<'_>,
        _immediately_before_first_write: NativePreWriteAuthorization<'_>,
    ) -> Result<NativeEksResponse, TransportFailure> {
        panic!("bootstrap test never performs provider I/O")
    }
}

type BootstrapEnforcement = EksEnforcement<
    InMemoryStore,
    BootstrapManagementCredentials,
    OrchestrationClock,
    BootstrapTransport,
    OrchestrationClock,
    OrchestrationClock,
>;

fn bootstrap_management_identities() -> BrokerManagementIdentities {
    BrokerManagementIdentities::new(
        BrokerManagementIdentity::new(
            "spiffe://accordlock.test/control/secret".to_owned(),
            [0xa1; 32],
        )
        .unwrap(),
        BrokerManagementIdentity::new(
            "spiffe://accordlock.test/control/token".to_owned(),
            [0xa2; 32],
        )
        .unwrap(),
        BrokerManagementIdentity::new(
            "spiffe://accordlock.test/control/review".to_owned(),
            [0xa3; 32],
        )
        .unwrap(),
    )
    .unwrap()
}

fn bootstrap_policy() -> EksCredentialLifecyclePolicy {
    EksCredentialLifecyclePolicy::new(60, 600, 1, 60).unwrap()
}

fn bootstrap_broker_config(route_profile: EksRouteProfile) -> BrokerConfig {
    BrokerConfig::new(
        BrokerEndpointConfig::new(vec![bootstrap_ca_der()]),
        BrokerProfile::new(route_profile, 60, 600).with_retirement_bounds(1, 60),
        bootstrap_management_identities(),
    )
}

fn bootstrap_machine() -> DispatchMachine {
    DispatchMachine::new(
        DispatchBounds {
            max_dispatch_delay_s: 100,
            token_lifetime_upper_bound_s: 600,
            clock_uncertainty_s: 1,
            minimum_remaining_lifetime_s: 1,
            lease_ttl_s: 30,
        },
        authority_version_from_vector(&control_authority()).unwrap(),
        106,
    )
    .unwrap()
}

fn bootstrap_enforcement(
    state: InMemoryStore,
    orchestrator_route: EksRouteProfile,
    broker_route: EksRouteProfile,
    executor_route: EksRouteProfile,
) -> Result<BootstrapEnforcement, EnforcementConfigError> {
    let executor = ExclusiveEksExecutor::new(
        ExecutorConfig::new(
            executor_route.clone(),
            "phase-b/bootstrap-observer".to_owned(),
            bootstrap_policy(),
        )
        .unwrap(),
        BootstrapTransport(executor_route),
        OrchestrationClock,
    );
    EksEnforcement::new(
        orchestrator_route,
        Scope::new("acme", "prod").unwrap(),
        state,
        bootstrap_machine(),
        bootstrap_broker_config(broker_route),
        BootstrapManagementCredentials,
        OrchestrationClock,
        executor,
        OrchestrationClock,
    )
}

#[test]
fn invalid_config_does_not_burn_capability_and_second_enforcement_is_rejected() {
    let state = InMemoryStore::new();
    let fixed = route(21);
    let substituted = route(22);

    assert!(matches!(
        bootstrap_enforcement(state.clone(), fixed.clone(), fixed.clone(), substituted,),
        Err(EnforcementConfigError::ExecutorRouteMismatch(
            RouteField::SocketTarget
        ))
    ));

    let _first =
        bootstrap_enforcement(state.clone(), fixed.clone(), fixed.clone(), fixed.clone()).unwrap();
    assert!(matches!(
        bootstrap_enforcement(state, fixed.clone(), fixed.clone(), fixed),
        Err(EnforcementConfigError::BrokerJournalCapabilityUnavailable)
    ));
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

fn control_template() -> DeploymentTemplate {
    DeploymentTemplate {
        operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
        environment: "prod".to_owned(),
        audience: CONTROL_AUDIENCE.to_owned(),
        repository: "acme/payments".to_owned(),
        commit_sha: "1111111111111111111111111111111111111111".to_owned(),
        image_repository: "registry.example/acme/payments".to_owned(),
        image_digest: Digest32::sha256(b"control-image"),
        cluster_identity: "eks://prod-a".to_owned(),
        namespace: "payments".to_owned(),
        deployment: "api".to_owned(),
        deployment_uid: "11111111-1111-4111-8111-111111111111".to_owned(),
        container: "app".to_owned(),
        container_index: 0,
        prior_image_digest: Digest32::sha256(b"control-prior-image"),
        resource_version: "1001".to_owned(),
        prior_projection_hash: Digest32::sha256(b"control-projection"),
        prior_transaction_annotation: Some("none".to_owned()),
        prior_authorization_annotation: Some("none".to_owned()),
        prior_operation_hash_annotation: Some("none".to_owned()),
    }
}

fn management_bindings() -> EksBrokerManagementBindings {
    EksBrokerManagementBindings::new(
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
    .unwrap()
}

struct ControlFixture {
    store: InMemoryStore,
    journal_capability: BrokerJournalCapability,
    clock: Arc<ControlClock>,
    scope: Scope,
    key: ConsumeKey,
    request: DispatchAcquisitionRequest,
    acquisition: DispatchAcquisitionAuthority,
    route: EksRouteProfile,
    authority: AuthorityVector,
}

impl ControlFixture {
    fn new(seed: u128) -> Self {
        let clock = Arc::new(ControlClock::new(CONTROL_NOW));
        let state_clock: Arc<dyn accordlock_state::TrustedClock> = clock.clone();
        let mut store = InMemoryStore::with_clock(state_clock);
        let journal_capability = store.issue_broker_journal_capability().unwrap();
        let scope = Scope::new("acme", "prod").unwrap();
        let route = route(21);
        let lifecycle_policy = EksCredentialLifecyclePolicy::new(60, 600, 1, 60).unwrap();
        let destination = EksDestinationProfile::new(
            route.clone(),
            [0xa4; 32],
            [0xa5; 32],
            lifecycle_policy,
            management_bindings(),
        )
        .unwrap();
        let ingress_signer = SigningIdentity::from_seed("phase-b-ingress", [0x31; 32]);
        let evaluator = SigningIdentity::from_seed("phase-b-evaluator", [0x32; 32]);
        let authorization_signer = SigningIdentity::from_seed("phase-b-authorization", [0x33; 32]);
        let ingress_key = RegisteredIngressKey {
            key_id: ingress_signer.key_id().to_owned(),
            public_key: ingress_signer.public_key_bytes(),
            tenant: "acme".to_owned(),
            actor: "workload-a".to_owned(),
            allowed_audiences: BTreeSet::from([CONTROL_AUDIENCE.to_owned()]),
            not_before: 50,
            expires_at: 300,
            status: IngressKeyStatus::Active,
        };
        let principal_root = ActivatedIngressRegistry::compute_root(
            CONTROL_AUDIENCE,
            120,
            std::slice::from_ref(&ingress_key),
        )
        .unwrap();
        let principal_registry = AuthorityDomainState {
            root: principal_root,
            epoch: 1,
            activation_id: Uuid::from_u128(seed + 20),
        };
        let registry = ActivatedIngressRegistry::new(
            principal_registry.clone(),
            CONTROL_AUDIENCE,
            120,
            vec![ingress_key],
        )
        .unwrap();
        let authenticator =
            IngressAuthenticator::new(registry, MemoryReplayGuard::default()).unwrap();
        let template = control_template();
        let capability = CapabilityGrant {
            grant_id: Uuid::from_u128(seed + 10),
            holder: "workload-a".to_owned(),
            tenant: "acme".to_owned(),
            operation: template.operation.clone(),
            repository: template.repository.clone(),
            audience: template.audience.clone(),
            cluster_identity: template.cluster_identity.clone(),
            namespace: template.namespace.clone(),
            deployment_uid: template.deployment_uid.clone(),
            container: template.container.clone(),
            image_repository: template.image_repository.clone(),
            not_before: 50,
            expires_at: 300,
            maximum_uses: 1,
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
            dispatch_deadline_policy: DispatchDeadlinePolicy {
                max_dispatch_delay_seconds: 100,
                profile_hard_cap: 250,
                immutable_dependency_expiries: vec![220],
            },
        };
        store
            .compare_and_activate_authority(&scope, None, &authority)
            .unwrap();
        store
            .activate_eks_destination(&scope, &destination)
            .unwrap();
        store.register_grant(&grant).unwrap();

        let proposal = AgentProposal {
            schema_version: 1,
            request_id: Uuid::from_u128(seed + 30),
            tenant: "acme".to_owned(),
            actor: "workload-a".to_owned(),
            template,
        };
        let signed_ingress = sign_ingress_request(
            IngressClaims {
                schema_version: INGRESS_SCHEMA_VERSION,
                audience: CONTROL_AUDIENCE.to_owned(),
                issued_at: 99,
                expires_at: 200,
                nonce: Uuid::from_u128(seed + 31),
                proposal,
            },
            &ingress_signer,
        )
        .unwrap();
        let wire = serde_json::to_vec(&signed_ingress).unwrap();
        let verified = authenticator
            .verify_durable_static(IngressRecoveryProbe::parse_bytes(&wire).unwrap())
            .unwrap();
        assert!(matches!(
            store
                .accept_control_submission_or_recover(verified)
                .unwrap(),
            ControlSubmissionIntakeOutcome::Fresh(_)
        ));

        let evaluation_request = ControlWorkClaimRequest::new(
            "phase-b-evaluator",
            ControlWorkerRole::Evaluator,
            Uuid::from_u128(seed + 32),
        )
        .unwrap();
        let evaluation_work = match store
            .claim_next_control_work_or_recover(&evaluation_request)
            .unwrap()
        {
            ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Evaluate(work)) => work,
            outcome => panic!("expected evaluation work, got {outcome:?}"),
        };
        let evaluation = EvaluationAttestation {
            schema_version: EVALUATION_ATTESTATION_SCHEMA_VERSION,
            request_id: evaluation_work.proposal().request_id,
            evaluation_nonce: evaluation_work.evaluation_nonce(),
            tenant: evaluation_work.caller_tenant().to_owned(),
            actor: evaluation_work.caller_actor().to_owned(),
            evaluated_at: evaluation_work.lease().claimed_at(),
            outcome: DecisionOutcome::Allow,
            reasons: vec![ReasonCode::Allowed],
            template_hash: canonical_hash(&evaluation_work.proposal().template).unwrap(),
            evidence_root: Digest32::sha256(b"phase-b-evidence"),
            principals: vec!["principal-a".to_owned()],
            policy_root: evaluation_work.active_authority().policy.root,
            authority: evaluation_work.active_authority().clone(),
            consume_before: 180,
        };
        let evaluation_cose = sign_cose(
            &evaluation.canonical_bytes().unwrap(),
            EVALUATION_DOMAIN,
            &evaluator,
        )
        .unwrap();
        store
            .record_control_evaluation(
                evaluation_work,
                &SignedEvaluation {
                    attestation: evaluation,
                    cose_sign1: evaluation_cose,
                },
                &evaluator.verifier(),
            )
            .unwrap();

        clock.set(102);
        let issuance_request = ControlWorkClaimRequest::new(
            "phase-b-issuer",
            ControlWorkerRole::Issuer,
            Uuid::from_u128(seed + 33),
        )
        .unwrap();
        let issuance_work = match store
            .claim_next_control_work_or_recover(&issuance_request)
            .unwrap()
        {
            ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Issue(work)) => work,
            outcome => panic!("expected issuance work, got {outcome:?}"),
        };
        let issuance_snapshot = store.control_issuance_snapshot(&issuance_work).unwrap();
        let evaluation = &issuance_work.signed_evaluation().attestation;
        let authorization = ExecutionAuthorization {
            schema_version: EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
            authorization_id: Uuid::from_u128(seed + 1),
            evaluation_nonce: evaluation.evaluation_nonce,
            request_id: evaluation.request_id,
            tenant: issuance_work.proposal().tenant.clone(),
            holder: issuance_work.proposal().actor.clone(),
            audience: issuance_work.proposal().template.audience.clone(),
            issued_at: issuance_snapshot.issued_at(),
            not_before: issuance_snapshot.issued_at(),
            consume_before: evaluation.consume_before,
            dispatch_deadline_policy: issuance_snapshot
                .registration()
                .dispatch_deadline_policy
                .clone(),
            grant_id: issuance_work.selected_grant_id(),
            template: issuance_work.proposal().template.clone(),
            template_hash: evaluation.template_hash,
            evidence_root: evaluation.evidence_root,
            principals: evaluation.principals.clone(),
            policy_root: evaluation.policy_root,
            authority: evaluation.authority.clone(),
        };
        let authorization_cose = sign_cose(
            &authorization.canonical_bytes().unwrap(),
            EXECUTION_AUTHORIZATION_DOMAIN,
            &authorization_signer,
        )
        .unwrap();
        let issued = IssuedAuthorizationRecord::new(
            Uuid::from_u128(seed),
            SignedAuthorization {
                authorization,
                cose_sign1: authorization_cose,
            },
            authorization_signer.key_id().to_owned(),
            authorization_signer.public_key_bytes(),
        )
        .unwrap();
        assert_eq!(
            store
                .record_and_link_control_issuance_or_recover(issuance_work, &issued)
                .unwrap(),
            ControlIssuanceCommitOutcome::Committed
        );

        clock.set(104);
        let consumption_request = ControlWorkClaimRequest::new(
            "phase-b-consumer",
            ControlWorkerRole::Consumer,
            Uuid::from_u128(seed + 34),
        )
        .unwrap();
        let consumption_work = match store
            .claim_next_control_work_or_recover(&consumption_request)
            .unwrap()
        {
            ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Consume(work)) => work,
            outcome => panic!("expected consumption work, got {outcome:?}"),
        };
        let key = consumption_work.consume_key().clone();
        clock.set(105);
        assert!(matches!(
            store
                .consume_and_link_control_or_recover(consumption_work)
                .unwrap(),
            ControlConsumptionCommitOutcome::Committed(_)
        ));
        clock.set(106);
        let request = DispatchAcquisitionRequest::new(
            format!("phase-b-worker-{seed}"),
            Uuid::from_u128(seed + 2),
        )
        .unwrap();
        let acquisition = match store
            .claim_next_pending_dispatch_or_recover(&scope, &request)
            .unwrap()
        {
            DispatchAcquisitionOutcome::Acquired(work) => work.into_parts().1,
            outcome => panic!("expected acquisition, got {outcome:?}"),
        };
        Self {
            store,
            journal_capability,
            clock,
            scope,
            key,
            request,
            acquisition,
            route,
            authority,
        }
    }

    fn machine(&self) -> DispatchMachine {
        let mut machine = DispatchMachine::new(
            DispatchBounds {
                max_dispatch_delay_s: 100,
                token_lifetime_upper_bound_s: 600,
                clock_uncertainty_s: 1,
                minimum_remaining_lifetime_s: 1,
                lease_ttl_s: 30,
            },
            authority_version_from_vector(&self.authority).unwrap(),
            106,
        )
        .unwrap();
        machine
            .register_destination(
                PhysicalResourceId {
                    cluster_trust_domain: self.route.cluster_identity().to_owned(),
                    api_server_identity: self.route.api_server_identity().to_owned(),
                    namespace: self.route.namespace().to_owned(),
                    deployment_uid: self.route.deployment_uid().to_owned(),
                },
                LogicalOwner {
                    tenant: self.scope.tenant.clone(),
                    environment: self.scope.environment.clone(),
                },
                CredentialProfile {
                    token_subject: format!(
                        "system:serviceaccount:{}:{}",
                        self.route.namespace(),
                        self.route.attempt_service_account_name()
                    ),
                    token_audience: self.route.token_audience().to_owned(),
                    effective_rbac_commitment: [0xa4; 32],
                },
            )
            .unwrap();
        machine
    }

    fn commit_create(&self) -> BrokerOperationAudit {
        self.clock.advance();
        let request = AcquiredBrokerOperationRequest::create(
            &self.acquisition,
            *self.route.commitment().as_bytes(),
        )
        .unwrap();
        let io = self
            .store
            .begin_broker_operation_for_acquisition(
                &self.journal_capability,
                &self.acquisition,
                request,
            )
            .unwrap();
        self.store
            .commit_broker_create(
                io,
                BrokerSecretObservation::matching(SECRET_UID.to_owned(), [0xb1; 32]).unwrap(),
            )
            .unwrap()
            .audit()
            .clone()
    }

    fn begin_uncertain_create(&self) {
        self.clock.advance();
        let request = AcquiredBrokerOperationRequest::create(
            &self.acquisition,
            *self.route.commitment().as_bytes(),
        )
        .unwrap();
        let io = self
            .store
            .begin_broker_operation_for_acquisition(
                &self.journal_capability,
                &self.acquisition,
                request,
            )
            .unwrap();
        self.store.mark_broker_io_unknown(io).unwrap();
    }

    fn authenticate_review(&self) -> ReviewedDispatchCredential {
        let _create = self.commit_create();
        self.clock.advance();
        let policy = BrokerCredentialSafetyPolicy::new(600, 1).unwrap();
        let request = AcquiredBrokerOperationRequest::issue_token(
            &self.acquisition,
            *self.route.commitment().as_bytes(),
            policy,
        )
        .unwrap();
        let io = self
            .store
            .begin_broker_operation_for_acquisition(
                &self.journal_capability,
                &self.acquisition,
                request,
            )
            .unwrap();
        let issue = self
            .store
            .commit_broker_token_issue(
                io,
                &BrokerTokenIssueObservation::new(TOKEN_DIGEST, 125, [0xb2; 32]).unwrap(),
            )
            .unwrap();
        self.clock.advance();
        let review_io = self
            .store
            .begin_dispatch_credential_review(
                &self.journal_capability,
                &self.acquisition,
                &issue.audit().selector(),
            )
            .unwrap();
        let claims = DispatchCredentialReviewClaims::new(
            TOKEN_DIGEST,
            format!(
                "system:serviceaccount:{}:{}",
                self.route.namespace(),
                self.route.attempt_service_account_name()
            ),
            self.route.token_audience().to_owned(),
            self.route.attempt_service_account_uid().to_owned(),
            "AUTHORIZATION_ID=44444444-4444-4444-8444-444444444444".to_owned(),
            SECRET_UID.to_owned(),
            106,
            125,
        )
        .unwrap();
        self.store
            .record_authenticated_dispatch_credential(
                review_io,
                AuthenticatedDispatchCredentialReview::new(claims, [0xb3; 32]).unwrap(),
            )
            .unwrap()
    }

    fn commit_delete_absence(&self) {
        let _create = self.commit_create();
        self.clock.advance();
        let cleanup =
            BrokerCleanupRequest::new(self.key.clone(), *self.route.commitment().as_bytes())
                .unwrap();
        let io = self
            .store
            .prepare_broker_cleanup(&self.journal_capability, &cleanup)
            .and_then(|intent| self.store.begin_broker_io(&self.journal_capability, intent))
            .unwrap();
        self.store.mark_broker_io_unknown(io).unwrap();
        self.clock.advance();
        let reconciliation = BrokerReconciliationRequest::new(
            self.key.clone(),
            BrokerJournalOperation::DeleteSecret,
            *self.route.commitment().as_bytes(),
        )
        .unwrap();
        let authority = self
            .store
            .begin_broker_reconciliation(&self.journal_capability, &reconciliation)
            .unwrap();
        assert!(matches!(
            self.store
                .commit_broker_reconciliation(
                    authority,
                    BrokerSecretObservation::absent([0xb4; 32]).unwrap(),
                )
                .unwrap(),
            accordlock_state::BrokerReconciliationResult::Completed(_)
        ));
    }

    fn reject_token_after_delete_absence(&self) {
        let _create = self.commit_create();
        self.clock.advance();
        let policy = BrokerCredentialSafetyPolicy::new(600, 1).unwrap();
        let request = AcquiredBrokerOperationRequest::issue_token(
            &self.acquisition,
            *self.route.commitment().as_bytes(),
            policy,
        )
        .unwrap();
        let io = self
            .store
            .begin_broker_operation_for_acquisition(
                &self.journal_capability,
                &self.acquisition,
                request,
            )
            .unwrap();
        let issue = self
            .store
            .commit_broker_token_issue(
                io,
                &BrokerTokenIssueObservation::new(TOKEN_DIGEST, 125, [0xb5; 32]).unwrap(),
            )
            .unwrap();

        self.clock.advance();
        let review = self
            .store
            .begin_dispatch_credential_review(
                &self.journal_capability,
                &self.acquisition,
                &issue.audit().selector(),
            )
            .unwrap();
        self.clock.advance();
        let cleanup =
            BrokerCleanupRequest::new(self.key.clone(), *self.route.commitment().as_bytes())
                .unwrap();
        let io = self
            .store
            .prepare_broker_cleanup(&self.journal_capability, &cleanup)
            .and_then(|intent| self.store.begin_broker_io(&self.journal_capability, intent))
            .unwrap();
        self.store.mark_broker_io_unknown(io).unwrap();
        self.clock.advance();
        let reconciliation = BrokerReconciliationRequest::new(
            self.key.clone(),
            BrokerJournalOperation::DeleteSecret,
            *self.route.commitment().as_bytes(),
        )
        .unwrap();
        let authority = self
            .store
            .begin_broker_reconciliation(&self.journal_capability, &reconciliation)
            .unwrap();
        assert!(matches!(
            self.store
                .commit_broker_reconciliation(
                    authority,
                    BrokerSecretObservation::absent([0xb6; 32]).unwrap(),
                )
                .unwrap(),
            accordlock_state::BrokerReconciliationResult::Completed(_)
        ));

        self.clock.advance();
        self.store
            .record_rejected_dispatch_credential(
                review,
                RejectedDispatchCredentialReview::new(TOKEN_DIGEST, [0xb7; 32]).unwrap(),
            )
            .unwrap();
    }
}

#[derive(Clone, Debug)]
struct RestartSecret;

#[derive(Debug)]
struct RestartIssued;

#[derive(Debug)]
struct RestartRejection;

#[derive(Debug)]
struct RestartDeletion;

#[derive(Debug)]
struct RestartBroker {
    clock: Arc<ControlClock>,
    create_reconciliation_calls: AtomicUsize,
    delete_calls: AtomicUsize,
    reconciliation_calls: AtomicUsize,
}

impl RestartBroker {
    fn new(clock: Arc<ControlClock>) -> Self {
        Self {
            clock,
            create_reconciliation_calls: AtomicUsize::new(0),
            delete_calls: AtomicUsize::new(0),
            reconciliation_calls: AtomicUsize::new(0),
        }
    }
}

impl BrokerPort<InMemoryStore> for RestartBroker {
    type Secret = RestartSecret;
    type Issued = RestartIssued;
    type Rejection = RestartRejection;
    type Deletion = RestartDeletion;

    fn create(
        &self,
        _state: &InMemoryStore,
        _journal_capability: &BrokerJournalCapability,
        _acquisition: &DispatchAcquisitionAuthority,
        _route_commitment: [u8; 32],
    ) -> Result<JournaledPortValue<Self::Secret>, PortFailure> {
        panic!("restart must not create")
    }

    fn reconcile_create(
        &self,
        state: &InMemoryStore,
        journal_capability: &BrokerJournalCapability,
        request: BrokerReconciliationRequest,
    ) -> Result<ReconciledSecret<Self::Secret>, PortFailure> {
        self.create_reconciliation_calls
            .fetch_add(1, Ordering::SeqCst);
        self.clock.advance();
        let authority = state
            .begin_broker_reconciliation(journal_capability, &request)
            .map_err(|error| map_state_failure(&error))?;
        match state
            .commit_broker_reconciliation(
                authority,
                BrokerSecretObservation::absent([0xc0; 32])
                    .map_err(|error| map_state_failure(&error))?,
            )
            .map_err(|error| map_state_failure(&error))?
        {
            accordlock_state::BrokerReconciliationResult::Pending(authority) => {
                Ok(ReconciledSecret::Absent(authority.audit()))
            }
            accordlock_state::BrokerReconciliationResult::Completed(_) => {
                Err(PortFailure::new(PortFailureKind::Invalid))
            }
        }
    }

    fn prepared(_secret: &Self::Secret) -> PreparedExecution {
        panic!("restart must not prepare provider work")
    }

    fn issue(
        &self,
        _state: &InMemoryStore,
        _journal_capability: &BrokerJournalCapability,
        _acquisition: &DispatchAcquisitionAuthority,
        _route_commitment: [u8; 32],
    ) -> Result<JournaledPortValue<Self::Issued>, PortFailure> {
        panic!("restart must not issue")
    }

    fn review(
        &self,
        _state: &InMemoryStore,
        _journal_capability: &BrokerJournalCapability,
        _acquisition: &DispatchAcquisitionAuthority,
        _issued: Self::Issued,
    ) -> Result<ReviewedCredential<Self::Rejection>, PortFailure> {
        panic!("restart must not review")
    }

    fn delete(
        &self,
        state: &InMemoryStore,
        journal_capability: &BrokerJournalCapability,
        request: BrokerCleanupRequest,
    ) -> Result<BrokerOperationAudit, PortFailure> {
        self.delete_calls.fetch_add(1, Ordering::SeqCst);
        self.clock.advance();
        state
            .prepare_broker_cleanup(journal_capability, &request)
            .and_then(|intent| state.begin_broker_io(journal_capability, intent))
            .and_then(|authority| state.mark_broker_io_unknown(authority))
            .map_err(|error| map_state_failure(&error))
    }

    fn verify_deleted(
        &self,
        state: &InMemoryStore,
        journal_capability: &BrokerJournalCapability,
        request: BrokerReconciliationRequest,
    ) -> Result<ObservedDeletion<Self::Deletion>, PortFailure> {
        self.reconciliation_calls.fetch_add(1, Ordering::SeqCst);
        self.clock.advance();
        let authority = state
            .begin_broker_reconciliation(journal_capability, &request)
            .map_err(|error| map_state_failure(&error))?;
        match state
            .commit_broker_reconciliation(
                authority,
                BrokerSecretObservation::absent([0xc1; 32])
                    .map_err(|error| map_state_failure(&error))?,
            )
            .map_err(|error| map_state_failure(&error))?
        {
            accordlock_state::BrokerReconciliationResult::Completed(receipt) => {
                Ok(ObservedDeletion::Absent(JournaledPortValue {
                    value: RestartDeletion,
                    audit: receipt.audit().clone(),
                }))
            }
            accordlock_state::BrokerReconciliationResult::Pending(_) => {
                Err(PortFailure::new(PortFailureKind::Invalid))
            }
        }
    }

    fn retirement(&self, _deletion: &Self::Deletion) -> Result<CredentialRetirement, PortFailure> {
        Ok(CredentialRetirement::Confirmed)
    }

    fn recovered_retirement(
        &self,
        evidence: &DispatchRestartDeletionEvidence,
    ) -> Result<CredentialRetirement, PortFailure> {
        let policy = evidence.credential_lifecycle_policy();
        let safe_after = evidence
            .absent_observed_at()
            .checked_add(policy.deletion_propagation_hard_max_seconds())
            .and_then(|value| value.checked_add(policy.clock_uncertainty_seconds()))
            .ok_or_else(|| PortFailure::new(PortFailureKind::Invalid))?;
        if self.clock.now() >= safe_after {
            Ok(CredentialRetirement::Confirmed)
        } else {
            Ok(CredentialRetirement::Pending { safe_after })
        }
    }
}

#[derive(Debug, Default)]
struct ExecutorSpy(AtomicUsize);

impl ExecutorPort for ExecutorSpy {
    fn execute_once(
        &self,
        _attempt: AuthorizedProviderAttempt,
        _template: DeploymentTemplate,
        _bearer: ExclusiveBearer,
    ) -> Result<ExactEffectEvidence, ExecutorError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        panic!("restart must never invoke provider execution")
    }
}

fn run_restart(
    fixture: &ControlFixture,
    machine: &mut DispatchMachine,
    broker: &RestartBroker,
    executor: &ExecutorSpy,
) -> EnforcementOutcome {
    let request =
        DispatchAcquisitionRequest::new(fixture.request.worker_id().to_owned(), Uuid::new_v4())
            .unwrap();
    run_enforcement(
        &fixture.store,
        &fixture.journal_capability,
        machine,
        broker,
        executor,
        &OrchestrationClock,
        &fixture.scope,
        *fixture.route.commitment().as_bytes(),
        &request,
    )
}

fn assert_confirmed_restart(outcome: EnforcementOutcome, transaction_id: Uuid) {
    assert!(
        matches!(
            &outcome,
            EnforcementOutcome::Quarantined {
                transaction_id: observed,
                stage: EnforcementStage::DurableBrokerLifecycle,
                reason: QuarantineReason::OutcomeUnknown,
                retirement: CredentialRetirement::Confirmed,
                ..
            } if *observed == transaction_id
        ),
        "expected confirmed restart for {transaction_id}, got {outcome:?}"
    );
}

#[test]
fn authenticated_restart_after_lease_expiry_retires_no_send_without_executor() {
    let fixture = ControlFixture::new(0x2100);
    drop(fixture.authenticate_review());
    fixture.clock.set(fixture.acquisition.lease_until() + 1);
    let broker = RestartBroker::new(Arc::clone(&fixture.clock));
    let executor = ExecutorSpy::default();
    let mut machine = fixture.machine();

    let safe_after = match run_restart(&fixture, &mut machine, &broker, &executor) {
        EnforcementOutcome::Quarantined {
            transaction_id,
            stage: EnforcementStage::DurableBrokerLifecycle,
            reason: QuarantineReason::OutcomeUnknown,
            retirement: CredentialRetirement::Pending { safe_after },
            ..
        } if transaction_id == fixture.key.transaction_id => safe_after,
        outcome => panic!("expected pending no-send retirement, got {outcome:?}"),
    };
    assert_eq!(broker.delete_calls.load(Ordering::SeqCst), 1);
    assert_eq!(broker.reconciliation_calls.load(Ordering::SeqCst), 1);
    assert_eq!(executor.0.load(Ordering::SeqCst), 0);

    fixture.clock.set(safe_after);
    assert_confirmed_restart(
        run_restart(&fixture, &mut machine, &broker, &executor),
        fixture.key.transaction_id,
    );
    assert_eq!(broker.delete_calls.load(Ordering::SeqCst), 1);
    assert_eq!(broker.reconciliation_calls.load(Ordering::SeqCst), 1);
    assert_eq!(executor.0.load(Ordering::SeqCst), 0);

    let drained = run_restart(&fixture, &mut machine, &broker, &executor);
    assert!(
        matches!(drained, EnforcementOutcome::NoWork { .. }),
        "retired recovery must not starve fresh scheduler work: {drained:?}"
    );
    assert!(matches!(
        run_enforcement(
            &fixture.store,
            &fixture.journal_capability,
            &mut machine,
            &broker,
            &executor,
            &OrchestrationClock,
            &fixture.scope,
            *fixture.route.commitment().as_bytes(),
            &fixture.request,
        ),
        EnforcementOutcome::AcquisitionInert {
            acquisition_id,
            disposition: DispatchAcquisitionDisposition::RecoveryRetired,
        } if acquisition_id == fixture.request.acquisition_id()
    ));
    assert_eq!(executor.0.load(Ordering::SeqCst), 0);
}

#[test]
fn pending_retirement_requires_exact_state_and_broker_safe_bound() {
    let fixture = ControlFixture::new(0x2150);
    drop(fixture.authenticate_review());
    fixture.clock.set(fixture.acquisition.lease_until() + 1);
    let broker = RestartBroker::new(Arc::clone(&fixture.clock));
    let executor = ExecutorSpy::default();
    let mut machine = fixture.machine();

    let expected_safe_after = match run_restart(&fixture, &mut machine, &broker, &executor) {
        EnforcementOutcome::Quarantined {
            transaction_id,
            retirement: CredentialRetirement::Pending { safe_after },
            ..
        } if transaction_id == fixture.key.transaction_id => safe_after,
        outcome => panic!("expected initial persisted safe bound: {outcome:?}"),
    };
    let recovery = fixture.request.recovery_key(&fixture.scope);
    assert_eq!(
        finalize_recovery_no_send_retirement(
            &fixture.store,
            &recovery,
            &fixture.key,
            CredentialRetirement::Pending {
                safe_after: expected_safe_after + 1,
            },
        ),
        CredentialRetirement::Unknown,
        "mismatched broker/state safe bounds must fail closed"
    );
    let context = fixture
        .store
        .dispatch_broker_restart_context(&recovery)
        .unwrap();
    let evidence = context.deletion_evidence().unwrap();
    let policy = evidence.credential_lifecycle_policy();
    assert_eq!(
        expected_safe_after,
        evidence.absent_observed_at()
            + policy.deletion_propagation_hard_max_seconds()
            + policy.clock_uncertainty_seconds()
    );
    assert!(matches!(
        fixture.store.retire_recovery_no_send(&recovery),
        Ok(accordlock_state::RecoveryNoSendRetirementOutcome::Pending { safe_after })
            if safe_after == expected_safe_after
    ));
    assert_eq!(executor.0.load(Ordering::SeqCst), 0);
}

#[test]
fn uncertain_create_absence_retires_no_send_without_delete_or_executor() {
    let fixture = ControlFixture::new(0x2180);
    fixture.begin_uncertain_create();
    let broker = RestartBroker::new(Arc::clone(&fixture.clock));
    let executor = ExecutorSpy::default();
    let mut machine = fixture.machine();

    assert_confirmed_restart(
        run_restart(&fixture, &mut machine, &broker, &executor),
        fixture.key.transaction_id,
    );
    assert_eq!(broker.create_reconciliation_calls.load(Ordering::SeqCst), 1);
    assert_eq!(broker.delete_calls.load(Ordering::SeqCst), 0);
    assert_eq!(broker.reconciliation_calls.load(Ordering::SeqCst), 0);
    assert_eq!(executor.0.load(Ordering::SeqCst), 0);

    assert!(matches!(
        run_restart(&fixture, &mut machine, &broker, &executor),
        EnforcementOutcome::NoWork { .. }
    ));
    assert_eq!(broker.create_reconciliation_calls.load(Ordering::SeqCst), 1);
    assert_eq!(executor.0.load(Ordering::SeqCst), 0);
}

#[test]
fn attempt_in_flight_restart_is_cleanup_only_and_never_reconstructs_provider_authority() {
    let fixture = ControlFixture::new(0x2200);
    let reviewed = fixture.authenticate_review();
    let expected_review_id = reviewed.review_id();
    let expected_policy = reviewed.credential_lifecycle_policy();
    let expected_activation = reviewed.destination_activation_commitment();
    fixture.clock.advance();
    let mut machine = fixture.machine();
    let committed = fixture
        .store
        .mark_dispatch_acquisition_attempt_in_flight(reviewed)
        .unwrap();
    assert_eq!(committed.token().key(), &fixture.key);
    assert_eq!(
        committed.acquisition().credential_review_id(),
        Some(expected_review_id)
    );
    assert_eq!(
        committed.acquisition().credential_lifecycle_policy(),
        Some(expected_policy)
    );
    assert_eq!(
        committed.acquisition().destination_activation_commitment(),
        Some(expected_activation)
    );

    let recovery = fixture.request.recovery_key(&fixture.scope);
    assert!(matches!(
        machine.close_recovered_attempt_from_state(&fixture.store, &recovery),
        Err(BridgeError::State(
            StateError::DispatchAttemptOutcomeUnknown
        ))
    ));

    fixture.clock.advance();
    let broker = RestartBroker::new(Arc::clone(&fixture.clock));
    let executor = ExecutorSpy::default();

    assert_confirmed_restart(
        run_restart(&fixture, &mut machine, &broker, &executor),
        fixture.key.transaction_id,
    );
    assert_eq!(broker.delete_calls.load(Ordering::SeqCst), 1);
    assert_eq!(broker.reconciliation_calls.load(Ordering::SeqCst), 1);
    assert_eq!(executor.0.load(Ordering::SeqCst), 0);
}

#[test]
fn durable_delete_absence_restart_confirms_retirement_with_zero_broker_or_provider_io() {
    let fixture = ControlFixture::new(0x2300);
    fixture.commit_delete_absence();
    fixture.clock.advance();
    let broker = RestartBroker::new(Arc::clone(&fixture.clock));
    let executor = ExecutorSpy::default();
    let mut machine = fixture.machine();
    let context = fixture
        .store
        .dispatch_broker_restart_context(&fixture.request.recovery_key(&fixture.scope))
        .unwrap();
    let evidence = context.deletion_evidence().unwrap();
    let policy = evidence.credential_lifecycle_policy();
    let safe_after = evidence.absent_observed_at()
        + policy.deletion_propagation_hard_max_seconds()
        + policy.clock_uncertainty_seconds();

    assert!(matches!(
        run_restart(&fixture, &mut machine, &broker, &executor),
        EnforcementOutcome::Quarantined {
            transaction_id,
            retirement: CredentialRetirement::Pending {
                safe_after: observed
            },
            ..
        } if transaction_id == fixture.key.transaction_id && observed == safe_after
    ));
    assert_eq!(broker.delete_calls.load(Ordering::SeqCst), 0);
    assert_eq!(broker.reconciliation_calls.load(Ordering::SeqCst), 0);
    assert_eq!(executor.0.load(Ordering::SeqCst), 0);

    fixture.clock.set(safe_after);
    assert_confirmed_restart(
        run_restart(&fixture, &mut machine, &broker, &executor),
        fixture.key.transaction_id,
    );
    assert_eq!(broker.delete_calls.load(Ordering::SeqCst), 0);
    assert_eq!(broker.reconciliation_calls.load(Ordering::SeqCst), 0);
    assert_eq!(executor.0.load(Ordering::SeqCst), 0);
}

#[test]
fn exact_post_absence_token_rejection_still_waits_for_rooted_retirement_bound() {
    let fixture = ControlFixture::new(0x2400);
    fixture.reject_token_after_delete_absence();
    let before_close = fixture
        .store
        .dispatch_broker_restart_context(&fixture.request.recovery_key(&fixture.scope))
        .unwrap();
    assert_eq!(
        before_close
            .deletion_evidence()
            .and_then(DispatchRestartDeletionEvidence::rejection_observed_at),
        Some(fixture.clock.now())
    );
    fixture.clock.advance();
    let broker = RestartBroker::new(Arc::clone(&fixture.clock));
    let executor = ExecutorSpy::default();
    let mut machine = fixture.machine();

    let safe_after = match run_restart(&fixture, &mut machine, &broker, &executor) {
        EnforcementOutcome::Quarantined {
            transaction_id,
            retirement: CredentialRetirement::Pending { safe_after },
            ..
        } if transaction_id == fixture.key.transaction_id => safe_after,
        outcome => panic!("expected rejection-bound retirement to remain pending: {outcome:?}"),
    };
    assert_eq!(broker.delete_calls.load(Ordering::SeqCst), 0);
    assert_eq!(broker.reconciliation_calls.load(Ordering::SeqCst), 0);
    assert_eq!(executor.0.load(Ordering::SeqCst), 0);

    fixture.clock.set(safe_after);
    assert_confirmed_restart(
        run_restart(&fixture, &mut machine, &broker, &executor),
        fixture.key.transaction_id,
    );
    assert_eq!(broker.delete_calls.load(Ordering::SeqCst), 0);
    assert_eq!(broker.reconciliation_calls.load(Ordering::SeqCst), 0);
    assert_eq!(executor.0.load(Ordering::SeqCst), 0);
}
