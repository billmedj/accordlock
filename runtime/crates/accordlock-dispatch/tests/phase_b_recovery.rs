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
        atomic::{AtomicI64, Ordering},
    },
};

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
    AgentProposal, AuthorityDomainState, AuthorityVector, CanonicalEncode, CapabilityGrant,
    DecisionOutcome, DeploymentTemplate, Digest32, DispatchDeadlinePolicy,
    EVALUATION_ATTESTATION_SCHEMA_VERSION, EVALUATION_DOMAIN, EXECUTION_AUTHORIZATION_DOMAIN,
    EXECUTION_AUTHORIZATION_SCHEMA_VERSION, EvaluationAttestation, ExecutionAuthorization,
    ReasonCode, SignedAuthorization, SignedEvaluation, SigningIdentity, authorization_signer_root,
    canonical_hash, evaluator_verifier_root, sign_cose,
};
use accordlock_state::{
    AcquiredBrokerOperationRequest, AuthenticatedDispatchCredentialReview, BrokerJournalCapability,
    BrokerJournalState, BrokerSecretObservation, BrokerTokenIssueObservation, ClaimedControlWork,
    ControlConsumptionCommitOutcome, ControlIssuanceCommitOutcome, ControlPlaneState,
    ControlSubmissionIntakeOutcome, ControlWorkClaimOutcome, ControlWorkClaimRequest,
    ControlWorkerRole, DispatchAcquisitionAuthority, DispatchAcquisitionOutcome,
    DispatchAcquisitionRequest, DispatchCredentialReviewClaims, EksDestinationProfile,
    EksDestinationRegistryState, GrantRegistration, InMemoryStore, IssuedAuthorizationRecord,
    Scope, StateError, TransactionalState,
};
use uuid::Uuid;

use super::*;

const NOW: i64 = 100;
const AUDIENCE: &str = "accordlock-executor:prod";
const TOKEN_DIGEST: [u8; 32] = [0xd1; 32];
const SECRET_UID: &str = "33333333-3333-4333-8333-333333333333";
const CREDENTIAL_AUTHORIZATION_ID: &str = "AUTHORIZATION_ID=44444444-4444-4444-8444-444444444444";

#[derive(Debug)]
struct TestClock(AtomicI64);

impl TestClock {
    fn new(now: i64) -> Self {
        Self(AtomicI64::new(now))
    }

    fn set(&self, now: i64) {
        self.0.store(now, Ordering::SeqCst);
    }

    fn advance(&self) -> i64 {
        self.0.fetch_add(1, Ordering::SeqCst) + 1
    }
}

impl accordlock_state::TrustedClock for TestClock {
    fn now_unix_seconds(&self) -> Result<i64, StateError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

fn domain(label: &str) -> AuthorityDomainState {
    AuthorityDomainState {
        root: Digest32::sha256(label.as_bytes()),
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
        grant_registry: domain("grant"),
        office_act_registry: domain("office"),
        principal_registry: domain("principal"),
        workload_build_allowlist: domain("build"),
        kernel_configuration: domain("kernel"),
    }
}

fn route() -> EksRouteProfile {
    EksRouteProfile::new(EksRouteProfileInput {
        cluster_trust_domain: "spiffe://example.test/eks/prod-a",
        cluster_identity: "eks://prod-a",
        api_server_identity: "urn:accordlock:api:prod-a",
        dns_server_name: "api.prod-a.eks.amazonaws.com",
        port: 443,
        socket_target: PinnedSocketTarget::new(SocketAddr::from(([192, 0, 2, 21], 443))).unwrap(),
        ca_trust_commitment: CaTrustCommitment::from_der_certificates(&[
            b"dispatch-phase-b-ca".to_vec()
        ])
        .unwrap(),
        namespace: "payments",
        deployment_name: "api",
        deployment_uid: "11111111-1111-4111-8111-111111111111",
        attempt_service_account_name: "accordlock-attempt",
        attempt_service_account_uid: "22222222-2222-4222-8222-222222222222",
        token_audience: "urn:accordlock:kubernetes-api:prod-a",
    })
    .unwrap()
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

fn template() -> DeploymentTemplate {
    DeploymentTemplate {
        operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
        environment: "prod".to_owned(),
        audience: AUDIENCE.to_owned(),
        repository: "acme/payments".to_owned(),
        commit_sha: "1".repeat(40),
        image_repository: "registry.example/acme/payments".to_owned(),
        image_digest: Digest32::sha256(b"new-image"),
        cluster_identity: "eks://prod-a".to_owned(),
        namespace: "payments".to_owned(),
        deployment: "api".to_owned(),
        deployment_uid: "11111111-1111-4111-8111-111111111111".to_owned(),
        container: "app".to_owned(),
        container_index: 0,
        prior_image_digest: Digest32::sha256(b"old-image"),
        resource_version: "1001".to_owned(),
        prior_projection_hash: Digest32::sha256(b"projection"),
        prior_transaction_annotation: Some("none".to_owned()),
        prior_authorization_annotation: Some("none".to_owned()),
        prior_operation_hash_annotation: Some("none".to_owned()),
    }
}

struct Fixture {
    store: InMemoryStore,
    journal_capability: BrokerJournalCapability,
    clock: Arc<TestClock>,
    scope: Scope,
    key: accordlock_state::ConsumeKey,
    request: DispatchAcquisitionRequest,
    acquisition: DispatchAcquisitionAuthority,
    route: EksRouteProfile,
    authority: AuthorityVector,
}

impl Fixture {
    fn new(seed: u128) -> Self {
        let clock = Arc::new(TestClock::new(NOW));
        let state_clock: Arc<dyn accordlock_state::TrustedClock> = clock.clone();
        let mut store = InMemoryStore::with_clock(state_clock);
        // Raw broker observations in this harness remain inert until trusted
        // bootstrap supplies the unique store-bound journal capability.
        let journal_capability = store.issue_broker_journal_capability().unwrap();
        let scope = Scope::new("acme", "prod").unwrap();
        let route = route();
        let lifecycle = EksCredentialLifecyclePolicy::new(60, 600, 1, 60).unwrap();
        let destination = EksDestinationProfile::new(
            route.clone(),
            [0xa4; 32],
            [0xa5; 32],
            lifecycle,
            management_bindings(),
        )
        .unwrap();
        let ingress_signer = SigningIdentity::from_seed("dispatch-ingress", [0x31; 32]);
        let evaluator = SigningIdentity::from_seed("dispatch-evaluator", [0x32; 32]);
        let authorization_signer = SigningIdentity::from_seed("dispatch-authorization", [0x33; 32]);
        let ingress_key = RegisteredIngressKey {
            key_id: ingress_signer.key_id().to_owned(),
            public_key: ingress_signer.public_key_bytes(),
            tenant: "acme".to_owned(),
            actor: "workload-a".to_owned(),
            allowed_audiences: BTreeSet::from([AUDIENCE.to_owned()]),
            not_before: 50,
            expires_at: 300,
            status: IngressKeyStatus::Active,
        };
        let principal_root = ActivatedIngressRegistry::compute_root(
            AUDIENCE,
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
            AUDIENCE,
            120,
            vec![ingress_key],
        )
        .unwrap();
        let authenticator =
            IngressAuthenticator::new(registry, MemoryReplayGuard::default()).unwrap();
        let deployment = template();
        let capability = CapabilityGrant {
            grant_id: Uuid::from_u128(seed + 10),
            holder: "workload-a".to_owned(),
            tenant: "acme".to_owned(),
            operation: deployment.operation.clone(),
            repository: deployment.repository.clone(),
            audience: deployment.audience.clone(),
            cluster_identity: deployment.cluster_identity.clone(),
            namespace: deployment.namespace.clone(),
            deployment_uid: deployment.deployment_uid.clone(),
            container: deployment.container.clone(),
            image_repository: deployment.image_repository.clone(),
            not_before: 50,
            expires_at: 300,
            maximum_uses: 1,
        };
        let mut authority = authority();
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
        store
            .compare_and_activate_authority(&scope, None, &authority)
            .unwrap();
        store
            .activate_eks_destination(&scope, &destination)
            .unwrap();
        store
            .register_grant(&GrantRegistration {
                environment: "prod".to_owned(),
                grant: capability,
                authority: authority.clone(),
                dispatch_deadline_policy: DispatchDeadlinePolicy {
                    max_dispatch_delay_seconds: 100,
                    profile_hard_cap: 250,
                    immutable_dependency_expiries: vec![220],
                },
            })
            .unwrap();

        let proposal = AgentProposal {
            schema_version: 1,
            request_id: Uuid::from_u128(seed + 30),
            tenant: "acme".to_owned(),
            actor: "workload-a".to_owned(),
            template: deployment,
        };
        let signed_ingress = sign_ingress_request(
            IngressClaims {
                schema_version: INGRESS_SCHEMA_VERSION,
                audience: AUDIENCE.to_owned(),
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

        let evaluation_work = match store
            .claim_next_control_work_or_recover(
                &ControlWorkClaimRequest::new(
                    "dispatch-evaluator",
                    ControlWorkerRole::Evaluator,
                    Uuid::from_u128(seed + 32),
                )
                .unwrap(),
            )
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
            evidence_root: Digest32::sha256(b"evidence"),
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
        let issuance_work = match store
            .claim_next_control_work_or_recover(
                &ControlWorkClaimRequest::new(
                    "dispatch-issuer",
                    ControlWorkerRole::Issuer,
                    Uuid::from_u128(seed + 33),
                )
                .unwrap(),
            )
            .unwrap()
        {
            ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Issue(work)) => work,
            outcome => panic!("expected issuance work, got {outcome:?}"),
        };
        let issuance_snapshot = store.control_issuance_snapshot(&issuance_work).unwrap();
        let evaluated = &issuance_work.signed_evaluation().attestation;
        let authorization_id = Uuid::from_u128(seed + 1);
        assert_ne!(
            format!("AUTHORIZATION_ID={authorization_id}"),
            CREDENTIAL_AUTHORIZATION_ID
        );
        let authorization = ExecutionAuthorization {
            schema_version: EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
            authorization_id,
            evaluation_nonce: evaluated.evaluation_nonce,
            request_id: evaluated.request_id,
            tenant: issuance_work.proposal().tenant.clone(),
            holder: issuance_work.proposal().actor.clone(),
            audience: issuance_work.proposal().template.audience.clone(),
            issued_at: issuance_snapshot.issued_at(),
            not_before: issuance_snapshot.issued_at(),
            consume_before: evaluated.consume_before,
            dispatch_deadline_policy: issuance_snapshot
                .registration()
                .dispatch_deadline_policy
                .clone(),
            grant_id: issuance_work.selected_grant_id(),
            template: issuance_work.proposal().template.clone(),
            template_hash: evaluated.template_hash,
            evidence_root: evaluated.evidence_root,
            principals: evaluated.principals.clone(),
            policy_root: evaluated.policy_root,
            authority: evaluated.authority.clone(),
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
        let consumption_work = match store
            .claim_next_control_work_or_recover(
                &ControlWorkClaimRequest::new(
                    "dispatch-consumer",
                    ControlWorkerRole::Consumer,
                    Uuid::from_u128(seed + 34),
                )
                .unwrap(),
            )
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
            format!("dispatch-worker-{seed}"),
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

    fn authenticate_review(&self) -> accordlock_state::ReviewedDispatchCredential {
        self.clock.advance();
        let create = AcquiredBrokerOperationRequest::create(
            &self.acquisition,
            *self.route.commitment().as_bytes(),
        )
        .unwrap();
        let io = self
            .store
            .begin_broker_operation_for_acquisition(
                &self.journal_capability,
                &self.acquisition,
                create,
            )
            .unwrap();
        self.store
            .commit_broker_create(
                io,
                BrokerSecretObservation::matching(SECRET_UID.to_owned(), [0xb1; 32]).unwrap(),
            )
            .unwrap();

        self.clock.advance();
        let issue = AcquiredBrokerOperationRequest::issue_token(
            &self.acquisition,
            *self.route.commitment().as_bytes(),
            accordlock_state::BrokerCredentialSafetyPolicy::new(600, 1).unwrap(),
        )
        .unwrap();
        let io = self
            .store
            .begin_broker_operation_for_acquisition(
                &self.journal_capability,
                &self.acquisition,
                issue,
            )
            .unwrap();
        let token = self
            .store
            .commit_broker_token_issue(
                io,
                &BrokerTokenIssueObservation::new(TOKEN_DIGEST, 125, [0xb2; 32]).unwrap(),
            )
            .unwrap();

        self.clock.advance();
        let review = self
            .store
            .begin_dispatch_credential_review(
                &self.journal_capability,
                &self.acquisition,
                &token.audit().selector(),
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
            CREDENTIAL_AUTHORIZATION_ID.to_owned(),
            SECRET_UID.to_owned(),
            106,
            125,
        )
        .unwrap();
        self.store
            .record_authenticated_dispatch_credential(
                review,
                AuthenticatedDispatchCredentialReview::new(claims, [0xb3; 32]).unwrap(),
            )
            .unwrap()
    }
}

#[test]
fn recovered_broker_lineage_closes_no_send_after_lease_expiry_without_provider_capability() {
    let fixture = Fixture::new(0x3100);
    drop(fixture.authenticate_review());
    fixture.clock.set(fixture.acquisition.lease_until() + 1);
    let machine = fixture.machine();
    let recovery = fixture.request.recovery_key(&fixture.scope);

    let committed = machine
        .close_recovered_attempt_from_state(&fixture.store, &recovery)
        .unwrap();
    assert_eq!(committed.transaction_id(), fixture.key.transaction_id);
    assert_eq!(committed.key(), &fixture.key);
    assert_eq!(
        committed.acquisition().acquisition_id(),
        fixture.acquisition.acquisition_id()
    );
    assert_eq!(
        committed.acquisition().lease_fence(),
        fixture.acquisition.lease_fence()
    );
    assert_eq!(
        committed.acquisition().worker_id(),
        fixture.acquisition.worker_id()
    );
    assert_eq!(
        committed.acquisition().acquired_at(),
        fixture.acquisition.acquired_at()
    );
    assert_eq!(
        committed.acquisition().lease_until(),
        fixture.acquisition.lease_until()
    );
    assert_eq!(
        committed.acquisition().dispatch_deadline(),
        fixture.acquisition.dispatch_deadline()
    );
    assert_eq!(
        committed.acquisition().control_submission_id(),
        fixture.acquisition.control_submission_id().unwrap()
    );

    let recovered_again = machine
        .close_recovered_attempt_from_state(&fixture.store, &recovery)
        .unwrap();
    assert_eq!(recovered_again.key(), committed.key());
    assert_eq!(recovered_again.acquisition(), committed.acquisition());
}
