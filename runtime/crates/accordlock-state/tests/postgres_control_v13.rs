#![allow(clippy::panic, clippy::too_many_lines, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::process::Command;
use std::sync::{Arc, Barrier, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::Duration;

use accordlock_eks_profile::{
    CaTrustCommitment, EksBrokerManagementBindings, EksCredentialLifecyclePolicy,
    EksManagementAuthorityBinding, EksRouteProfile, EksRouteProfileInput, PinnedSocketTarget,
};
use accordlock_ingress::{
    ActivatedIngressRegistry, INGRESS_SCHEMA_VERSION, IngressAuthenticator, IngressClaims,
    IngressKeyStatus, IngressRecoveryProbe, MemoryReplayGuard, RegisteredIngressKey,
    StaticallyVerifiedIngressSubmission, sign_ingress_request,
};
use accordlock_protocol::{
    AgentProposal, AuthorityDomainState, AuthorityVector, CanonicalEncode, CapabilityGrant,
    DecisionOutcome, DeploymentTemplate, Digest32, EVALUATION_ATTESTATION_SCHEMA_VERSION,
    EVALUATION_DOMAIN, EXECUTION_AUTHORIZATION_DOMAIN, EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
    EvaluationAttestation, ExecutionAuthorization, ReasonCode, SignedAuthorization,
    SignedEvaluation, SigningIdentity, authorization_signer_root, canonical_hash,
    evaluator_verifier_root, sign_cose,
};
use accordlock_state::{
    AcquiredBrokerOperationRequest, BrokerCleanupRequest, BrokerJournalCapability,
    BrokerJournalOperation, BrokerJournalState, BrokerReconciliationRequest,
    BrokerSecretObservation, ClaimedControlWork, ConsumeKey, ControlConsumptionCommitOutcome,
    ControlDecisionReason, ControlIssuanceCommitOutcome, ControlOutcome, ControlPlaneState,
    ControlStatusCode, ControlSubmissionIntakeOutcome, ControlSubmissionReceipt,
    ControlWorkClaimOutcome, ControlWorkClaimRequest, ControlWorkFinalizationReason,
    ControlWorkPhase, ControlWorkerRole, DispatchAcquisitionDisposition,
    DispatchAcquisitionOutcome, DispatchAcquisitionRecoveryKey, DispatchAcquisitionRequest,
    DispatchBrokerRestartAction, DispatchDeadlinePolicy, DispatchQueueDispositionReason,
    EksDestinationProfile, EksDestinationRegistryState, GrantRegistration, IssuanceSnapshot,
    IssuedAuthorizationRecord, PostgresStore, RecoveryNoSendRetirementOutcome, Scope, StateError,
    TransactionalState,
};
use postgres::{Client, NoTls};
use uuid::Uuid;

const CONTROL_ENVIRONMENT: &str = "test";
const COMMIT_LOSS_PHASE_ENV: &str = "ACCORDLOCK_V13_COMMIT_LOSS_PHASE";
const COMMIT_LOSS_EVALUATE_CLAIM_ENV: &str = "ACCORDLOCK_V13_COMMIT_LOSS_EVALUATE_CLAIM";
const COMMIT_LOSS_ISSUE_CLAIM_ENV: &str = "ACCORDLOCK_V13_COMMIT_LOSS_ISSUE_CLAIM";
const COMMIT_LOSS_CONSUME_CLAIM_ENV: &str = "ACCORDLOCK_V13_COMMIT_LOSS_CONSUME_CLAIM";
const COMMIT_LOSS_EXIT_CODE: i32 = 86;

fn serial_postgres_test() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn database_time(url: &str) -> i64 {
    Client::connect(url, NoTls)
        .unwrap()
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint AS now_unix_s",
            &[],
        )
        .unwrap()
        .get("now_unix_s")
}

fn restore_tenant_after_grant_scope_relaxation(url: &str, tenant: &str) {
    let mut client = Client::connect(url, NoTls).unwrap();
    let mut transaction = client.transaction().unwrap();
    transaction
        .execute(
            "CREATE TEMP TABLE accordlock_test_cleanup_submissions
                 ON COMMIT DROP AS
             SELECT submission_id
               FROM public.accordlock_control_submissions
              WHERE tenant=$1",
            &[&tenant],
        )
        .unwrap();
    transaction
        .execute(
            "CREATE TEMP TABLE accordlock_test_cleanup_dispatch_requests
                 ON COMMIT DROP AS
             SELECT acquisition_id AS dispatch_request_id
               FROM public.accordlock_dispatch_acquisitions
              WHERE tenant=$1
             UNION
             SELECT dispatch_request_id
               FROM public.accordlock_dispatch_queue_dispositions
              WHERE tenant=$1",
            &[&tenant],
        )
        .unwrap();
    transaction
        .batch_execute("SET LOCAL session_replication_role = replica")
        .unwrap();
    let submission_child_deletes = transaction
        .query(
            "SELECT format(
                        'DELETE FROM %I.%I WHERE submission_id IN '
                        || '(SELECT submission_id FROM pg_temp.accordlock_test_cleanup_submissions)',
                        namespace.nspname,
                        relation.relname
                    ) AS statement
               FROM pg_catalog.pg_class AS relation
               JOIN pg_catalog.pg_namespace AS namespace
                 ON namespace.oid = relation.relnamespace
               JOIN pg_catalog.pg_attribute AS submission_attribute
                 ON submission_attribute.attrelid = relation.oid
                AND submission_attribute.attname = 'submission_id'
                AND submission_attribute.attnum > 0
                AND NOT submission_attribute.attisdropped
              WHERE namespace.nspname = 'public'
                AND relation.relname LIKE 'accordlock\\_%' ESCAPE '\\'
                AND relation.relkind IN ('r', 'p')
                AND NOT EXISTS (
                    SELECT 1
                      FROM pg_catalog.pg_attribute AS tenant_attribute
                     WHERE tenant_attribute.attrelid = relation.oid
                       AND tenant_attribute.attname = 'tenant'
                       AND tenant_attribute.attnum > 0
                       AND NOT tenant_attribute.attisdropped
                )
              ORDER BY relation.oid DESC",
            &[],
        )
        .unwrap()
        .into_iter()
        .map(|row| row.get::<_, String>("statement"))
        .collect::<Vec<_>>();
    for statement in submission_child_deletes {
        transaction.execute(&statement, &[]).unwrap();
    }
    let delete_statements = transaction
        .query(
            "SELECT format(
                        'DELETE FROM %I.%I WHERE tenant=$1',
                        namespace.nspname,
                        relation.relname
                    ) AS statement
               FROM pg_catalog.pg_class AS relation
               JOIN pg_catalog.pg_namespace AS namespace
                 ON namespace.oid = relation.relnamespace
               JOIN pg_catalog.pg_attribute AS attribute
                 ON attribute.attrelid = relation.oid
                AND attribute.attname = 'tenant'
                AND attribute.attnum > 0
                AND NOT attribute.attisdropped
              WHERE namespace.nspname = 'public'
                AND relation.relname LIKE 'accordlock\\_%' ESCAPE '\\'
                AND relation.relkind IN ('r', 'p')
              ORDER BY relation.oid DESC",
            &[],
        )
        .unwrap()
        .into_iter()
        .map(|row| row.get::<_, String>("statement"))
        .collect::<Vec<_>>();
    for statement in delete_statements {
        transaction.execute(&statement, &[&tenant]).unwrap();
    }
    transaction
        .execute(
            "DELETE FROM public.accordlock_dispatch_request_identities AS identity
              WHERE identity.dispatch_request_id IN (
                    SELECT dispatch_request_id
                      FROM pg_temp.accordlock_test_cleanup_dispatch_requests
              )
                AND NOT EXISTS (
                    SELECT 1
                      FROM public.accordlock_dispatch_acquisitions AS acquisition
                     WHERE acquisition.acquisition_id=identity.dispatch_request_id
                )
                AND NOT EXISTS (
                    SELECT 1
                      FROM public.accordlock_dispatch_queue_dispositions AS disposition
                     WHERE disposition.dispatch_request_id=identity.dispatch_request_id
                )",
            &[],
        )
        .unwrap();
    transaction
        .batch_execute(
            "SET LOCAL session_replication_role = origin;
             DO $cleanup$
             BEGIN
                 IF NOT EXISTS (
                     SELECT 1
                       FROM pg_catalog.pg_constraint
                      WHERE conrelid = 'public.accordlock_grants'::regclass
                        AND conname = 'accordlock_grants_scope_key'
                 ) THEN
                     ALTER TABLE public.accordlock_grants
                         ADD CONSTRAINT accordlock_grants_scope_key
                         UNIQUE (tenant,environment);
                 END IF;
             END
             $cleanup$",
        )
        .unwrap();
    transaction.commit().unwrap();
}

fn control_high_waters(url: &str, scope: &Scope, replay_scope: &str) -> (i64, String, i64, String) {
    let row = Client::connect(url, NoTls)
        .unwrap()
        .query_one(
            "SELECT scope.observed_unix_s AS scope_observed,
                    scope.updated_at::text AS scope_updated,
                    ingress.observed_unix_s AS ingress_observed,
                    ingress.updated_at::text AS ingress_updated
               FROM public.accordlock_time_high_water AS scope
               JOIN public.accordlock_ingress_replay_scopes AS ingress
                 ON ingress.replay_scope=$3
              WHERE scope.tenant=$1 AND scope.environment=$2",
            &[&scope.tenant, &scope.environment, &replay_scope],
        )
        .unwrap();
    (
        row.get("scope_observed"),
        row.get("scope_updated"),
        row.get("ingress_observed"),
        row.get("ingress_updated"),
    )
}

fn control_artifact_counts(url: &str, submission_id: Uuid) -> [i64; 8] {
    let row = Client::connect(url, NoTls)
        .unwrap()
        .query_one(
            "SELECT
                (SELECT count(*) FROM public.accordlock_control_evaluations
                  WHERE submission_id=$1) AS evaluations,
                (SELECT count(*) FROM public.accordlock_control_decisions
                  WHERE submission_id=$1) AS decisions,
                (SELECT count(*) FROM public.accordlock_control_issuances
                  WHERE submission_id=$1) AS issuances,
                (SELECT count(*) FROM public.accordlock_control_consumptions
                  WHERE submission_id=$1) AS consumptions,
                (SELECT count(*) FROM public.accordlock_control_phase_completions
                  WHERE submission_id=$1) AS completions,
                (SELECT count(*) FROM public.accordlock_issued_authorizations AS issued
                  JOIN public.accordlock_control_issuances AS issuance
                    ON issuance.tenant=issued.tenant
                   AND issuance.environment=issued.environment
                   AND issuance.authorization_id=issued.authorization_id
                   AND issuance.transaction_id=issued.transaction_id
                 WHERE issuance.submission_id=$1) AS authorizations,
                (SELECT count(*) FROM public.accordlock_consumptions AS receipt
                  JOIN public.accordlock_control_consumptions AS consumption
                    ON consumption.tenant=receipt.tenant
                   AND consumption.environment=receipt.environment
                   AND consumption.authorization_id=receipt.authorization_id
                   AND consumption.transaction_id=receipt.transaction_id
                 WHERE consumption.submission_id=$1) AS receipts,
                (SELECT count(*) FROM public.accordlock_execution_outbox AS outbox
                  JOIN public.accordlock_control_consumptions AS consumption
                    ON consumption.tenant=outbox.tenant
                   AND consumption.environment=outbox.environment
                   AND consumption.authorization_id=outbox.authorization_id
                   AND consumption.transaction_id=outbox.transaction_id
                 WHERE consumption.submission_id=$1) AS outboxes",
            &[&submission_id],
        )
        .unwrap();
    [
        row.get("evaluations"),
        row.get("decisions"),
        row.get("issuances"),
        row.get("consumptions"),
        row.get("completions"),
        row.get("authorizations"),
        row.get("receipts"),
        row.get("outboxes"),
    ]
}

fn control_domain(label: &str) -> AuthorityDomainState {
    AuthorityDomainState {
        root: Digest32::sha256(label.as_bytes()),
        epoch: 1,
        activation_id: Uuid::new_v4(),
    }
}

fn base_authority(prefix: &str) -> AuthorityVector {
    AuthorityVector {
        policy: control_domain(&format!("{prefix}-policy")),
        registry: control_domain(&format!("{prefix}-registry")),
        revocation: control_domain(&format!("{prefix}-revocation")),
        connector: control_domain(&format!("{prefix}-connector")),
        resource: control_domain(&format!("{prefix}-resource")),
        signer: control_domain(&format!("{prefix}-signer")),
        mediation: control_domain(&format!("{prefix}-mediation")),
        grant_registry: control_domain(&format!("{prefix}-grant")),
        office_act_registry: control_domain(&format!("{prefix}-office")),
        principal_registry: control_domain(&format!("{prefix}-principal")),
        workload_build_allowlist: control_domain(&format!("{prefix}-build")),
        kernel_configuration: control_domain(&format!("{prefix}-kernel")),
    }
}

fn proposal(
    tenant: &str,
    audience: &str,
    request_id: Uuid,
    cluster_identity: &str,
    deployment_uid: &str,
) -> AgentProposal {
    AgentProposal {
        schema_version: 1,
        request_id,
        tenant: tenant.to_owned(),
        actor: "workload-a".to_owned(),
        template: DeploymentTemplate {
            operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
            environment: CONTROL_ENVIRONMENT.to_owned(),
            audience: audience.to_owned(),
            repository: "acme/payments".to_owned(),
            commit_sha: "1111111111111111111111111111111111111111".to_owned(),
            image_repository: "registry.example/acme/payments".to_owned(),
            image_digest: Digest32::sha256(b"v13-control-image"),
            cluster_identity: cluster_identity.to_owned(),
            namespace: "payments".to_owned(),
            deployment: "payments".to_owned(),
            deployment_uid: deployment_uid.to_owned(),
            container: "app".to_owned(),
            container_index: 0,
            prior_image_digest: Digest32::sha256(b"v13-control-prior-image"),
            resource_version: "1001".to_owned(),
            prior_projection_hash: Digest32::sha256(b"v13-control-projection"),
            prior_transaction_annotation: Some("none".to_owned()),
            prior_authorization_annotation: Some("none".to_owned()),
            prior_operation_hash_annotation: Some("none".to_owned()),
        },
    }
}

struct PgControlFixture {
    url: String,
    store: PostgresStore,
    tenant: String,
    audience: String,
    authenticator: IngressAuthenticator<MemoryReplayGuard>,
    ingress_signer: SigningIdentity,
    evaluator: SigningIdentity,
    authorization_signer: SigningIdentity,
    authority: AuthorityVector,
    grant: GrantRegistration,
    destination: EksDestinationProfile,
    proposal_template: DeploymentTemplate,
}

impl PgControlFixture {
    fn new() -> Self {
        Self::with_dispatch_delay(120)
    }

    fn with_dispatch_delay(max_dispatch_delay_seconds: i64) -> Self {
        Self::with_dispatch_delay_and_lifecycle(
            max_dispatch_delay_seconds,
            EksCredentialLifecyclePolicy::new(600, 900, 5, 60).unwrap(),
        )
    }

    fn with_dispatch_delay_and_lifecycle(
        max_dispatch_delay_seconds: i64,
        credential_lifecycle_policy: EksCredentialLifecyclePolicy,
    ) -> Self {
        Self::with_dispatch_delay_lifecycle_and_validity(
            max_dispatch_delay_seconds,
            credential_lifecycle_policy,
            3_600,
        )
    }

    fn with_dispatch_delay_lifecycle_and_validity(
        max_dispatch_delay_seconds: i64,
        credential_lifecycle_policy: EksCredentialLifecyclePolicy,
        validity_seconds: i64,
    ) -> Self {
        assert!(max_dispatch_delay_seconds > 0);
        assert!(validity_seconds > 1_200);
        let url = env::var("ACCORDLOCK_TEST_POSTGRES_URL")
            .unwrap_or_else(|_| panic!("ACCORDLOCK_TEST_POSTGRES_URL is required"));
        let store = PostgresStore::new(url.clone());
        store.migrate().unwrap();
        let suffix = Uuid::new_v4().simple().to_string();
        let tenant = format!("v13-control-{suffix}");
        let audience = format!("accordlock-executor:v13-{suffix}");
        let cluster_identity = format!("urn:accordlock:cluster:{suffix}");
        let deployment_uid = Uuid::new_v4().to_string();
        let now = database_time(&url);
        let ingress_signer = SigningIdentity::from_seed("pg-v13-ingress", [0x71; 32]);
        let evaluator = SigningIdentity::from_seed("pg-v13-evaluator", [0x72; 32]);
        let authorization_signer = SigningIdentity::from_seed("pg-v13-authorization", [0x73; 32]);
        let ingress_key = RegisteredIngressKey {
            key_id: ingress_signer.key_id().to_owned(),
            public_key: ingress_signer.public_key_bytes(),
            tenant: tenant.clone(),
            actor: "workload-a".to_owned(),
            allowed_audiences: BTreeSet::from([audience.clone()]),
            not_before: now.saturating_sub(300),
            expires_at: now.saturating_add(validity_seconds),
            status: IngressKeyStatus::Active,
        };
        let principal_root = ActivatedIngressRegistry::compute_root(
            &audience,
            900,
            std::slice::from_ref(&ingress_key),
        )
        .unwrap();
        let principal_registry = AuthorityDomainState {
            root: principal_root,
            epoch: 1,
            activation_id: Uuid::new_v4(),
        };
        let registry = ActivatedIngressRegistry::new(
            principal_registry.clone(),
            &audience,
            900,
            vec![ingress_key],
        )
        .unwrap();
        let authenticator =
            IngressAuthenticator::new(registry, MemoryReplayGuard::default()).unwrap();

        let capability = CapabilityGrant {
            grant_id: Uuid::new_v4(),
            holder: "workload-a".to_owned(),
            tenant: tenant.clone(),
            operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
            repository: "acme/payments".to_owned(),
            audience: audience.clone(),
            cluster_identity: cluster_identity.clone(),
            namespace: "payments".to_owned(),
            deployment_uid: deployment_uid.clone(),
            container: "app".to_owned(),
            image_repository: "registry.example/acme/payments".to_owned(),
            not_before: now.saturating_sub(300),
            expires_at: now.saturating_add(validity_seconds),
            maximum_uses: 8,
        };
        let route = EksRouteProfile::new(EksRouteProfileInput {
            cluster_trust_domain: "spiffe://example.test/eks/v14",
            cluster_identity: &cluster_identity,
            api_server_identity: &format!("urn:accordlock:api:{suffix}"),
            dns_server_name: "api.v14.eks.example.test",
            port: 443,
            socket_target: PinnedSocketTarget::new(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 70)),
                443,
            ))
            .unwrap(),
            ca_trust_commitment: CaTrustCommitment::from_der_certificates(&[
                b"pg-v14-control-ca".to_vec()
            ])
            .unwrap(),
            namespace: "payments",
            deployment_name: "payments",
            deployment_uid: &deployment_uid,
            attempt_service_account_name: "accordlock-attempt",
            attempt_service_account_uid: "22222222-2222-4222-8222-222222222222",
            token_audience: "urn:accordlock:kubernetes-api:v14",
        })
        .unwrap();
        let destination = EksDestinationProfile::new(
            route,
            [0xc1; 32],
            [0xc2; 32],
            credential_lifecycle_policy,
            EksBrokerManagementBindings::new(
                EksManagementAuthorityBinding::new(
                    "spiffe://accordlock.test/v14/secret".to_owned(),
                    [0xc3; 32],
                )
                .unwrap(),
                EksManagementAuthorityBinding::new(
                    "spiffe://accordlock.test/v14/token".to_owned(),
                    [0xc4; 32],
                )
                .unwrap(),
                EksManagementAuthorityBinding::new(
                    "spiffe://accordlock.test/v14/review".to_owned(),
                    [0xc5; 32],
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let mut authority = base_authority(&suffix);
        authority.principal_registry = principal_registry;
        authority.kernel_configuration.root =
            evaluator_verifier_root(evaluator.key_id(), evaluator.public_key_bytes()).unwrap();
        authority.signer.root = authorization_signer_root(
            authorization_signer.key_id(),
            authorization_signer.public_key_bytes(),
        )
        .unwrap();
        authority.grant_registry.root = canonical_hash(&capability).unwrap();
        let scope = Scope::new(&tenant, CONTROL_ENVIRONMENT).unwrap();
        authority.resource.root = destination.resource_root(&scope).unwrap();
        authority.mediation.root = destination
            .mediation_root(&scope, &authority.resource)
            .unwrap();
        let grant = GrantRegistration {
            environment: CONTROL_ENVIRONMENT.to_owned(),
            grant: capability,
            authority: authority.clone(),
            dispatch_deadline_policy: DispatchDeadlinePolicy {
                max_dispatch_delay_seconds,
                profile_hard_cap: now.saturating_add(validity_seconds - 600),
                immutable_dependency_expiries: vec![now.saturating_add(validity_seconds - 1_200)],
            },
        };
        store
            .compare_and_activate_authority(&scope, None, &authority)
            .unwrap();
        store
            .activate_eks_destination(&scope, &destination)
            .unwrap();
        store.register_grant(&grant).unwrap();
        let proposal_template = proposal(
            &tenant,
            &audience,
            Uuid::nil(),
            &cluster_identity,
            &deployment_uid,
        )
        .template;
        Self {
            url,
            store,
            tenant,
            audience,
            authenticator,
            ingress_signer,
            evaluator,
            authorization_signer,
            authority,
            grant,
            destination,
            proposal_template,
        }
    }

    fn rotate_destination_policy(
        &mut self,
        credential_lifecycle_policy: EksCredentialLifecyclePolicy,
    ) {
        let scope = Scope::new(&self.tenant, CONTROL_ENVIRONMENT).unwrap();
        let destination = EksDestinationProfile::new(
            self.destination.route().clone(),
            *self.destination.effective_rbac_commitment().as_bytes(),
            *self
                .destination
                .terminal_witness_registry_commitment()
                .as_bytes(),
            credential_lifecycle_policy,
            self.destination.broker_management_bindings().clone(),
        )
        .unwrap();
        let mut next_authority = self.authority.clone();
        next_authority.resource.epoch += 1;
        next_authority.resource.activation_id = Uuid::new_v4();
        next_authority.resource.root = destination.resource_root(&scope).unwrap();
        next_authority.mediation.epoch += 1;
        next_authority.mediation.activation_id = Uuid::new_v4();
        next_authority.mediation.root = destination
            .mediation_root(&scope, &next_authority.resource)
            .unwrap();
        self.store
            .compare_and_activate_authority(&scope, Some(&self.authority), &next_authority)
            .unwrap();
        self.store
            .activate_eks_destination(&scope, &destination)
            .unwrap();
        self.authority = next_authority;
        self.destination = destination;
    }

    fn signed_wire(&self, request_id: Uuid, nonce: Uuid) -> Vec<u8> {
        let now = database_time(&self.url);
        let mut request_proposal = proposal(
            &self.tenant,
            &self.audience,
            request_id,
            &self.proposal_template.cluster_identity,
            &self.proposal_template.deployment_uid,
        );
        request_proposal.template = self.proposal_template.clone();
        let request = sign_ingress_request(
            IngressClaims {
                schema_version: INGRESS_SCHEMA_VERSION,
                audience: self.audience.clone(),
                issued_at: now.saturating_sub(1),
                expires_at: now.saturating_add(600),
                nonce,
                proposal: request_proposal,
            },
            &self.ingress_signer,
        )
        .unwrap();
        serde_json::to_vec(&request).unwrap()
    }

    fn rotate_to_distinct_physical(&mut self, label: &str) {
        let scope = Scope::new(&self.tenant, CONTROL_ENVIRONMENT).unwrap();
        let cluster_identity = format!("urn:accordlock:cluster:{label}");
        let api_server_identity = format!("urn:accordlock:api:{label}-{}", self.tenant);
        let deployment_uid = Uuid::new_v4().to_string();
        let route = EksRouteProfile::new(EksRouteProfileInput {
            cluster_trust_domain: "spiffe://example.test/eks/v14-rotated",
            cluster_identity: &cluster_identity,
            api_server_identity: &api_server_identity,
            dns_server_name: "api.v14-rotated.eks.example.test",
            port: 443,
            socket_target: PinnedSocketTarget::new(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 71)),
                443,
            ))
            .unwrap(),
            ca_trust_commitment: CaTrustCommitment::from_der_certificates(&[
                b"pg-v14-control-ca-rotated".to_vec(),
            ])
            .unwrap(),
            namespace: "payments",
            deployment_name: "payments",
            deployment_uid: &deployment_uid,
            attempt_service_account_name: "accordlock-attempt",
            attempt_service_account_uid: "33333333-3333-4333-8333-333333333333",
            token_audience: "urn:accordlock:kubernetes-api:v14-rotated",
        })
        .unwrap();
        let destination = EksDestinationProfile::new(
            route,
            [0xd1; 32],
            [0xd2; 32],
            self.destination.credential_lifecycle_policy(),
            EksBrokerManagementBindings::new(
                EksManagementAuthorityBinding::new(
                    "spiffe://accordlock.test/v14/secret-rotated".to_owned(),
                    [0xd3; 32],
                )
                .unwrap(),
                EksManagementAuthorityBinding::new(
                    "spiffe://accordlock.test/v14/token-rotated".to_owned(),
                    [0xd4; 32],
                )
                .unwrap(),
                EksManagementAuthorityBinding::new(
                    "spiffe://accordlock.test/v14/review-rotated".to_owned(),
                    [0xd5; 32],
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let mut capability = self.grant.grant.clone();
        capability.grant_id = Uuid::new_v4();
        capability.cluster_identity.clone_from(&cluster_identity);
        capability.deployment_uid.clone_from(&deployment_uid);
        let mut next_authority = self.authority.clone();
        next_authority.resource.epoch += 1;
        next_authority.resource.activation_id = Uuid::new_v4();
        next_authority.resource.root = destination.resource_root(&scope).unwrap();
        next_authority.mediation.epoch += 1;
        next_authority.mediation.activation_id = Uuid::new_v4();
        next_authority.mediation.root = destination
            .mediation_root(&scope, &next_authority.resource)
            .unwrap();
        next_authority.grant_registry.epoch += 1;
        next_authority.grant_registry.activation_id = Uuid::new_v4();
        next_authority.grant_registry.root = canonical_hash(&capability).unwrap();
        self.store
            .compare_and_activate_authority(&scope, Some(&self.authority), &next_authority)
            .unwrap();
        self.store
            .activate_eks_destination(&scope, &destination)
            .unwrap();
        let registration = GrantRegistration {
            environment: CONTROL_ENVIRONMENT.to_owned(),
            grant: capability,
            authority: next_authority.clone(),
            dispatch_deadline_policy: self.grant.dispatch_deadline_policy.clone(),
        };
        let mut client = Client::connect(&self.url, NoTls).unwrap();
        client
            .batch_execute("SET session_replication_role = replica;")
            .unwrap();
        assert_eq!(
            client
                .execute(
                    "DELETE FROM public.accordlock_grants
                      WHERE tenant=$1 AND environment=$2 AND grant_id=$3",
                    &[
                        &scope.tenant,
                        &scope.environment,
                        &self.grant.grant.grant_id,
                    ],
                )
                .unwrap(),
            1
        );
        client
            .batch_execute("SET session_replication_role = origin;")
            .unwrap();
        self.store.register_grant(&registration).unwrap();
        self.proposal_template
            .cluster_identity
            .clone_from(&cluster_identity);
        self.proposal_template
            .deployment_uid
            .clone_from(&deployment_uid);
        self.authority = next_authority;
        self.grant = registration;
        self.destination = destination;
    }

    fn verify_wire(&self, wire: &[u8]) -> StaticallyVerifiedIngressSubmission {
        self.authenticator
            .verify_durable_static(IngressRecoveryProbe::parse_bytes(wire).unwrap())
            .unwrap()
    }

    fn accept(&self, wire: &[u8]) -> ControlSubmissionReceipt {
        match self
            .store
            .accept_control_submission_or_recover(self.verify_wire(wire))
            .unwrap()
        {
            ControlSubmissionIntakeOutcome::Fresh(receipt) => receipt,
            other => panic!("expected fresh v13 intake, got {other:?}"),
        }
    }
}

fn signed_evaluation(
    work: &accordlock_state::ControlEvaluationWork,
    evaluator: &SigningIdentity,
) -> SignedEvaluation {
    signed_evaluation_with_outcome(work, evaluator, DecisionOutcome::Allow)
}

fn signed_evaluation_with_outcome(
    work: &accordlock_state::ControlEvaluationWork,
    evaluator: &SigningIdentity,
    outcome: DecisionOutcome,
) -> SignedEvaluation {
    let attestation = EvaluationAttestation {
        schema_version: EVALUATION_ATTESTATION_SCHEMA_VERSION,
        request_id: work.proposal().request_id,
        evaluation_nonce: work.evaluation_nonce(),
        tenant: work.caller_tenant().to_owned(),
        actor: work.caller_actor().to_owned(),
        evaluated_at: work.lease().claimed_at(),
        outcome,
        reasons: if outcome == DecisionOutcome::Allow {
            vec![ReasonCode::Allowed]
        } else {
            vec![ReasonCode::ActorNotAllowed]
        },
        template_hash: canonical_hash(&work.proposal().template).unwrap(),
        evidence_root: Digest32::sha256(b"v13-control-evidence"),
        principals: vec!["principal-a".to_owned()],
        policy_root: work.active_authority().policy.root,
        authority: work.active_authority().clone(),
        consume_before: work.ingress_expires_at().saturating_sub(10),
    };
    let cose_sign1 = sign_cose(
        &attestation.canonical_bytes().unwrap(),
        EVALUATION_DOMAIN,
        evaluator,
    )
    .unwrap();
    SignedEvaluation {
        attestation,
        cose_sign1,
    }
}

fn derive_authorization_uuid(
    domain: &[u8],
    scope: &Scope,
    request_id: Uuid,
    evaluation_nonce: Uuid,
    grant_id: Uuid,
) -> Uuid {
    let mut bytes = Vec::new();
    for component in [
        domain,
        scope.tenant.as_bytes(),
        scope.environment.as_bytes(),
    ] {
        bytes.extend_from_slice(&u64::try_from(component.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(component);
    }
    bytes.extend_from_slice(request_id.as_bytes());
    bytes.extend_from_slice(evaluation_nonce.as_bytes());
    bytes.extend_from_slice(grant_id.as_bytes());
    let digest = Digest32::sha256(&bytes);
    let mut uuid = [0_u8; 16];
    uuid.copy_from_slice(&digest.as_bytes()[..16]);
    uuid[6] = (uuid[6] & 0x0f) | 0x80;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    Uuid::from_bytes(uuid)
}

fn issued_record(
    work: &accordlock_state::ControlIssuanceWork,
    snapshot: &IssuanceSnapshot,
    signer: &SigningIdentity,
) -> IssuedAuthorizationRecord {
    let evaluation = &work.signed_evaluation().attestation;
    let registration = snapshot.registration();
    let authorization_id = derive_authorization_uuid(
        b"accordlock:v1:authorization-id",
        work.scope(),
        work.proposal().request_id,
        evaluation.evaluation_nonce,
        work.selected_grant_id(),
    );
    let transaction_id = derive_authorization_uuid(
        b"accordlock:v1:authorization-transaction",
        work.scope(),
        work.proposal().request_id,
        evaluation.evaluation_nonce,
        work.selected_grant_id(),
    );
    let authorization = ExecutionAuthorization {
        schema_version: EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
        authorization_id,
        evaluation_nonce: evaluation.evaluation_nonce,
        request_id: evaluation.request_id,
        tenant: work.proposal().tenant.clone(),
        holder: work.proposal().actor.clone(),
        audience: work.proposal().template.audience.clone(),
        issued_at: snapshot.issued_at(),
        not_before: snapshot.issued_at(),
        consume_before: evaluation.consume_before.min(registration.grant.expires_at),
        dispatch_deadline_policy: registration.dispatch_deadline_policy.clone(),
        grant_id: work.selected_grant_id(),
        template: work.proposal().template.clone(),
        template_hash: evaluation.template_hash,
        evidence_root: evaluation.evidence_root,
        principals: evaluation.principals.clone(),
        policy_root: evaluation.policy_root,
        authority: evaluation.authority.clone(),
    };
    let cose_sign1 = sign_cose(
        &authorization.canonical_bytes().unwrap(),
        EXECUTION_AUTHORIZATION_DOMAIN,
        signer,
    )
    .unwrap();
    IssuedAuthorizationRecord::new(
        transaction_id,
        SignedAuthorization {
            authorization,
            cose_sign1,
        },
        signer.key_id().to_owned(),
        signer.public_key_bytes(),
    )
    .unwrap()
}

fn orphan_issued_record(
    fixture: &PgControlFixture,
    proposal: &AgentProposal,
    evaluation: &SignedEvaluation,
) -> IssuedAuthorizationRecord {
    let now = database_time(&fixture.url);
    let authorization = ExecutionAuthorization {
        schema_version: EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
        authorization_id: Uuid::new_v4(),
        evaluation_nonce: evaluation.attestation.evaluation_nonce,
        request_id: evaluation.attestation.request_id,
        tenant: proposal.tenant.clone(),
        holder: proposal.actor.clone(),
        audience: proposal.template.audience.clone(),
        issued_at: now,
        not_before: now,
        consume_before: evaluation
            .attestation
            .consume_before
            .min(fixture.grant.grant.expires_at),
        dispatch_deadline_policy: fixture.grant.dispatch_deadline_policy.clone(),
        grant_id: fixture.grant.grant.grant_id,
        template: proposal.template.clone(),
        template_hash: evaluation.attestation.template_hash,
        evidence_root: evaluation.attestation.evidence_root,
        principals: evaluation.attestation.principals.clone(),
        policy_root: evaluation.attestation.policy_root,
        authority: evaluation.attestation.authority.clone(),
    };
    let cose_sign1 = sign_cose(
        &authorization.canonical_bytes().unwrap(),
        EXECUTION_AUTHORIZATION_DOMAIN,
        &fixture.authorization_signer,
    )
    .unwrap();
    IssuedAuthorizationRecord::new(
        Uuid::new_v4(),
        SignedAuthorization {
            authorization,
            cose_sign1,
        },
        fixture.authorization_signer.key_id().to_owned(),
        fixture.authorization_signer.public_key_bytes(),
    )
    .unwrap()
}

fn insert_authorization_direct(url: &str, issued: &IssuedAuthorizationRecord) {
    let record_json = serde_json::to_value(issued).unwrap();
    Client::connect(url, NoTls)
        .unwrap()
        .execute(
            "INSERT INTO public.accordlock_issued_authorizations
                    (tenant,environment,authorization_id,transaction_id,grant_id,record_json,
                     authorization_hash,consume_before,issuance_profile_version,
                     request_id,evaluation_nonce)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,2,$9,$10)",
            &[
                &issued.scope().tenant,
                &issued.scope().environment,
                &issued.authorization().authorization_id,
                &issued.transaction_id,
                &issued.authorization().grant_id,
                &record_json,
                &issued.authorization_hash.to_string(),
                &issued.authorization().consume_before,
                &issued.authorization().request_id,
                &issued.authorization().evaluation_nonce,
            ],
        )
        .unwrap();
}

fn claim_request(worker: &str, role: ControlWorkerRole, claim_id: Uuid) -> ControlWorkClaimRequest {
    ControlWorkClaimRequest::new(worker, role, claim_id).unwrap()
}

fn complete_control_dispatch(fixture: &PgControlFixture) -> (ControlSubmissionReceipt, ConsumeKey) {
    let receipt = fixture.accept(&fixture.signed_wire(Uuid::new_v4(), Uuid::new_v4()));
    let evaluation_work = match fixture
        .store
        .claim_next_control_work_or_recover(&claim_request(
            "pg-v14-evaluator",
            ControlWorkerRole::Evaluator,
            Uuid::new_v4(),
        ))
        .unwrap()
    {
        ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Evaluate(work)) => work,
        other => panic!("expected EVALUATE work, got {other:?}"),
    };
    let evaluation = signed_evaluation(&evaluation_work, &fixture.evaluator);
    fixture
        .store
        .record_control_evaluation(evaluation_work, &evaluation, &fixture.evaluator.verifier())
        .unwrap();

    let issue_work = match fixture
        .store
        .claim_next_control_work_or_recover(&claim_request(
            "pg-v14-issuer",
            ControlWorkerRole::Issuer,
            Uuid::new_v4(),
        ))
        .unwrap()
    {
        ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Issue(work)) => work,
        other => panic!("expected ISSUE work, got {other:?}"),
    };
    let snapshot = fixture
        .store
        .control_issuance_snapshot(&issue_work)
        .unwrap();
    let issued = issued_record(&issue_work, &snapshot, &fixture.authorization_signer);
    assert_eq!(
        fixture
            .store
            .record_and_link_control_issuance_or_recover(issue_work, &issued)
            .unwrap(),
        ControlIssuanceCommitOutcome::Committed
    );

    let consume_work = match fixture
        .store
        .claim_next_control_work_or_recover(&claim_request(
            "pg-v14-consumer",
            ControlWorkerRole::Consumer,
            Uuid::new_v4(),
        ))
        .unwrap()
    {
        ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Consume(work)) => work,
        other => panic!("expected CONSUME work, got {other:?}"),
    };
    let key = consume_work.consume_key().clone();
    assert!(matches!(
        fixture
            .store
            .consume_and_link_control_or_recover(consume_work)
            .unwrap(),
        ControlConsumptionCommitOutcome::Committed(_)
    ));
    (receipt, key)
}

fn durable_dispatch_head_and_tail(
    url: &str,
    first_submission: &ControlSubmissionReceipt,
    first_key: &ConsumeKey,
    second_submission: &ControlSubmissionReceipt,
    second_key: &ConsumeKey,
) -> (ConsumeKey, ConsumeKey) {
    let submission_ids = [
        first_submission.submission_id(),
        second_submission.submission_id(),
    ];
    let ordered: Vec<Uuid> = Client::connect(url, NoTls)
        .unwrap()
        .query(
            "SELECT submission_id
               FROM public.accordlock_control_consumptions
              WHERE submission_id = ANY($1::uuid[])
              ORDER BY linked_at, submission_id",
            &[&submission_ids.as_slice()],
        )
        .unwrap()
        .into_iter()
        .map(|row| row.get("submission_id"))
        .collect();
    assert_eq!(ordered.len(), 2);
    let reverse_submission_ids = [submission_ids[1], submission_ids[0]];
    assert!(
        ordered.as_slice() == submission_ids.as_slice()
            || ordered.as_slice() == reverse_submission_ids.as_slice(),
        "durable queue query returned an unexpected submission set: {ordered:?}"
    );
    if ordered[0] == first_submission.submission_id() {
        (first_key.clone(), second_key.clone())
    } else {
        assert_eq!(ordered[0], second_submission.submission_id());
        (second_key.clone(), first_key.clone())
    }
}

fn wait_until_control_consumption_is_strictly_older(
    url: &str,
    submission: &ControlSubmissionReceipt,
) {
    let linked_at: i64 = Client::connect(url, NoTls)
        .unwrap()
        .query_one(
            "SELECT linked_at
               FROM public.accordlock_control_consumptions
              WHERE submission_id=$1",
            &[&submission.submission_id()],
        )
        .unwrap()
        .get("linked_at");
    for _ in 0..10 {
        if database_time(url) > linked_at {
            return;
        }
        thread::sleep(Duration::from_secs(1));
    }
    panic!("database time did not advance beyond control consumption {linked_at}");
}

fn create_pending_no_send_head(
    fixture: &PgControlFixture,
    broker_capability: &BrokerJournalCapability,
    label: &str,
) -> DispatchAcquisitionRecoveryKey {
    let (submission, key) = complete_control_dispatch(fixture);
    let request =
        DispatchAcquisitionRequest::new(format!("pg-v14-scan-{label}"), Uuid::new_v4()).unwrap();
    let authority = match fixture
        .store
        .claim_next_pending_dispatch_or_recover(submission.scope(), &request)
        .unwrap()
    {
        DispatchAcquisitionOutcome::Acquired(work) => work.into_parts().1,
        other => panic!("expected acquired scan fixture head, got {other:?}"),
    };
    let route_commitment = *fixture.destination.route().commitment().as_bytes();
    let create = fixture
        .store
        .begin_broker_operation_for_acquisition(
            broker_capability,
            &authority,
            AcquiredBrokerOperationRequest::create(&authority, route_commitment).unwrap(),
        )
        .unwrap();
    fixture
        .store
        .commit_broker_create(
            create,
            BrokerSecretObservation::matching(format!("pg-v14-scan-secret-{label}"), [0xe1; 32])
                .unwrap(),
        )
        .unwrap();
    drop(authority);
    let recovery_key = request.recovery_key(submission.scope());
    fixture
        .store
        .close_dispatch_acquisition_no_send(&recovery_key)
        .unwrap();
    let cleanup = fixture
        .store
        .prepare_broker_cleanup(
            broker_capability,
            &BrokerCleanupRequest::new(key.clone(), route_commitment).unwrap(),
        )
        .unwrap();
    let cleanup_io = fixture
        .store
        .begin_broker_io(broker_capability, cleanup)
        .unwrap();
    fixture.store.mark_broker_io_unknown(cleanup_io).unwrap();
    let reconciliation = fixture
        .store
        .begin_broker_reconciliation(
            broker_capability,
            &BrokerReconciliationRequest::new(
                key,
                BrokerJournalOperation::DeleteSecret,
                route_commitment,
            )
            .unwrap(),
        )
        .unwrap();
    fixture
        .store
        .commit_broker_reconciliation(
            reconciliation,
            BrokerSecretObservation::absent([0xe2; 32]).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        fixture
            .store
            .retire_recovery_no_send(&recovery_key)
            .unwrap(),
        RecoveryNoSendRetirementOutcome::Pending { .. }
    ));
    recovery_key
}

fn force_expire_dispatch_acquisition(url: &str, acquisition_id: Uuid) {
    let mut client = Client::connect(url, NoTls).unwrap();
    client
        .batch_execute("SET session_replication_role = replica")
        .unwrap();
    let updated = client
        .execute(
            "UPDATE public.accordlock_dispatch_acquisitions
                SET acquired_unix_s = GREATEST(
                        0,
                        floor(extract(epoch FROM clock_timestamp()))::bigint - 1
                    ),
                    lease_until = floor(
                        extract(epoch FROM clock_timestamp())
                    )::bigint
              WHERE acquisition_id=$1",
            &[&acquisition_id],
        )
        .unwrap();
    client
        .batch_execute("SET session_replication_role = origin")
        .unwrap();
    assert_eq!(updated, 1);
}

fn replace_scope_grant_for_fifo_test(url: &str, registration: &GrantRegistration, uses: i64) {
    let registration_json = serde_json::to_value(registration).unwrap();
    let mut client = Client::connect(url, NoTls).unwrap();
    client
        .batch_execute("SET session_replication_role = replica")
        .unwrap();
    client
        .execute(
            "DELETE FROM public.accordlock_grants
              WHERE tenant=$1 AND environment=$2",
            &[&registration.grant.tenant, &registration.environment],
        )
        .unwrap();
    client
        .execute(
            "INSERT INTO public.accordlock_grants
                    (tenant, environment, grant_id, registration_json, uses,
                     maximum_uses, not_before, expires_at, revoked,
                     issuance_profile_version)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,FALSE,2)",
            &[
                &registration.grant.tenant,
                &registration.environment,
                &registration.grant.grant_id,
                &registration_json,
                &uses,
                &i64::from(registration.grant.maximum_uses),
                &registration.grant.not_before,
                &registration.grant.expires_at,
            ],
        )
        .unwrap();
    client
        .batch_execute("SET session_replication_role = origin")
        .unwrap();
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL"]
#[allow(clippy::too_many_lines)]
fn postgres_v14_create_absent_no_send_retires_and_releases_same_physical() {
    let _serial = serial_postgres_test();
    let mut fixture = PgControlFixture::new();
    let broker_capability = fixture.store.issue_broker_journal_capability().unwrap();
    let (first_submission, first_key) = complete_control_dispatch(&fixture);
    let (second_submission, second_key) = complete_control_dispatch(&fixture);
    let (expected_head_key, tail_key) = durable_dispatch_head_and_tail(
        &fixture.url,
        &first_submission,
        &first_key,
        &second_submission,
        &second_key,
    );

    let original_request =
        DispatchAcquisitionRequest::new("pg-v14-create-absent", Uuid::new_v4()).unwrap();
    let authority = match fixture
        .store
        .claim_next_pending_dispatch_or_recover(first_submission.scope(), &original_request)
        .unwrap()
    {
        DispatchAcquisitionOutcome::Acquired(work) => work.into_parts().1,
        other => panic!("expected acquired CREATE work, got {other:?}"),
    };
    assert_eq!(authority.claim().key(), &expected_head_key);
    let current = fixture
        .store
        .load_current_eks_attempt_for_acquisition(&authority)
        .unwrap();
    let route_commitment = *current.facts().route().commitment().as_bytes();
    let create = fixture
        .store
        .begin_broker_operation_for_acquisition(
            &broker_capability,
            &authority,
            AcquiredBrokerOperationRequest::create(&authority, route_commitment).unwrap(),
        )
        .unwrap();
    fixture.store.mark_broker_io_unknown(create).unwrap();
    drop(authority);

    let supervisor =
        DispatchAcquisitionRequest::new("pg-v14-create-supervisor", Uuid::new_v4()).unwrap();
    let recovery_key = match fixture
        .store
        .claim_next_pending_dispatch_or_recover(first_submission.scope(), &supervisor)
        .unwrap()
    {
        DispatchAcquisitionOutcome::RecoveryRequired(work) => {
            assert_eq!(
                work.disposition(),
                DispatchAcquisitionDisposition::BrokerArtifactPresent
            );
            work.recovery_key().clone()
        }
        other => panic!("expected server-selected CREATE recovery, got {other:?}"),
    };
    fixture
        .store
        .close_dispatch_acquisition_no_send(&recovery_key)
        .unwrap();
    let restart = fixture
        .store
        .dispatch_broker_restart_context(&recovery_key)
        .unwrap();
    assert_eq!(
        restart.action(),
        DispatchBrokerRestartAction::ReconcileCreate
    );
    let reconciliation = fixture
        .store
        .begin_broker_reconciliation(
            &broker_capability,
            &restart.reconciliation_request().unwrap(),
        )
        .unwrap();
    fixture
        .store
        .commit_broker_reconciliation(
            reconciliation,
            BrokerSecretObservation::absent([0xa1; 32]).unwrap(),
        )
        .unwrap();
    assert_eq!(
        fixture
            .store
            .dispatch_broker_restart_context(&recovery_key)
            .unwrap()
            .action(),
        DispatchBrokerRestartAction::CreationAlreadyAbsent
    );
    assert!(matches!(
        fixture
            .store
            .retire_recovery_no_send(&recovery_key)
            .unwrap(),
        RecoveryNoSendRetirementOutcome::Retired(_)
    ));

    let tail_request =
        DispatchAcquisitionRequest::new("pg-v14-create-tail", Uuid::new_v4()).unwrap();
    match fixture
        .store
        .claim_next_pending_dispatch_or_recover(first_submission.scope(), &tail_request)
        .unwrap()
    {
        DispatchAcquisitionOutcome::Acquired(work) => {
            assert_eq!(work.authority().claim().key(), &tail_key);
        }
        other => panic!("retired CREATE_ABSENT head did not release same physical: {other:?}"),
    }
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL"]
#[allow(clippy::too_many_lines)]
fn postgres_v14_terminal_delete_conflict_does_not_starve_distinct_physical_tail() {
    let _serial = serial_postgres_test();
    let mut fixture = PgControlFixture::new();
    let broker_capability = fixture.store.issue_broker_journal_capability().unwrap();
    let (first_submission, first_key) = complete_control_dispatch(&fixture);
    let original_request =
        DispatchAcquisitionRequest::new("pg-v14-delete-conflict", Uuid::new_v4()).unwrap();
    let authority = match fixture
        .store
        .claim_next_pending_dispatch_or_recover(first_submission.scope(), &original_request)
        .unwrap()
    {
        DispatchAcquisitionOutcome::Acquired(work) => work.into_parts().1,
        other => panic!("expected acquired conflict head, got {other:?}"),
    };
    let current = fixture
        .store
        .load_current_eks_attempt_for_acquisition(&authority)
        .unwrap();
    let route_commitment = *current.facts().route().commitment().as_bytes();
    let create = fixture
        .store
        .begin_broker_operation_for_acquisition(
            &broker_capability,
            &authority,
            AcquiredBrokerOperationRequest::create(&authority, route_commitment).unwrap(),
        )
        .unwrap();
    fixture
        .store
        .commit_broker_create(
            create,
            BrokerSecretObservation::matching("pg-secret-conflict".to_owned(), [0xb1; 32]).unwrap(),
        )
        .unwrap();
    drop(authority);
    let recovery_key = original_request.recovery_key(first_submission.scope());
    fixture
        .store
        .close_dispatch_acquisition_no_send(&recovery_key)
        .unwrap();
    let cleanup_context = fixture
        .store
        .dispatch_broker_restart_context(&recovery_key)
        .unwrap();
    let cleanup = fixture
        .store
        .prepare_broker_cleanup(
            &broker_capability,
            &cleanup_context.cleanup_request().unwrap(),
        )
        .unwrap();
    let cleanup_io = fixture
        .store
        .begin_broker_io(&broker_capability, cleanup)
        .unwrap();
    fixture.store.mark_broker_io_unknown(cleanup_io).unwrap();
    let reconciliation = fixture
        .store
        .begin_broker_reconciliation(
            &broker_capability,
            &BrokerReconciliationRequest::new(
                first_key.clone(),
                BrokerJournalOperation::DeleteSecret,
                route_commitment,
            )
            .unwrap(),
        )
        .unwrap();
    fixture
        .store
        .commit_broker_reconciliation(
            reconciliation,
            BrokerSecretObservation::conflicting([0xb2; 32]).unwrap(),
        )
        .unwrap();

    fixture.rotate_to_distinct_physical("conflict-tail");
    wait_until_control_consumption_is_strictly_older(&fixture.url, &first_submission);
    let (tail_submission, tail_key) = complete_control_dispatch(&fixture);
    let (durable_head_key, durable_tail_key) = durable_dispatch_head_and_tail(
        &fixture.url,
        &first_submission,
        &first_key,
        &tail_submission,
        &tail_key,
    );
    assert_eq!(durable_head_key, first_key);
    assert_eq!(durable_tail_key, tail_key);
    let tail_request =
        DispatchAcquisitionRequest::new("pg-v14-conflict-tail", Uuid::new_v4()).unwrap();
    match fixture
        .store
        .claim_next_pending_dispatch_or_recover(first_submission.scope(), &tail_request)
        .unwrap()
    {
        DispatchAcquisitionOutcome::Acquired(work) => {
            assert_eq!(work.authority().claim().key(), &tail_key);
        }
        other => panic!("terminal DELETE conflict starved distinct physical tail: {other:?}"),
    }
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL"]
#[allow(clippy::too_many_lines)]
fn postgres_v14_global_fifo_precedes_newer_recovery_with_older_productive_head() {
    let _serial = serial_postgres_test();
    let mut fixture = PgControlFixture::new();
    let broker_capability = fixture.store.issue_broker_journal_capability().unwrap();
    let (first_submission, first_key) = complete_control_dispatch(&fixture);
    let first_grant = fixture.grant.clone();
    let first_request =
        DispatchAcquisitionRequest::new("pg-v14-global-fifo-a", Uuid::new_v4()).unwrap();
    let first_acquisition = match fixture
        .store
        .claim_next_pending_dispatch_or_recover(first_submission.scope(), &first_request)
        .unwrap()
    {
        DispatchAcquisitionOutcome::Acquired(work) => {
            assert_eq!(work.authority().claim().key(), &first_key);
            work.authority().acquisition_id()
        }
        other => panic!("expected older acquired FIFO head, got {other:?}"),
    };

    fixture.rotate_to_distinct_physical("global-fifo-recovery");
    wait_until_control_consumption_is_strictly_older(&fixture.url, &first_submission);
    let (second_submission, second_key) = complete_control_dispatch(&fixture);
    let (durable_head_key, durable_tail_key) = durable_dispatch_head_and_tail(
        &fixture.url,
        &first_submission,
        &first_key,
        &second_submission,
        &second_key,
    );
    assert_eq!(durable_head_key, first_key);
    assert_eq!(durable_tail_key, second_key);
    let second_grant = fixture.grant.clone();
    let second_request =
        DispatchAcquisitionRequest::new("pg-v14-global-fifo-b", Uuid::new_v4()).unwrap();
    let second_authority = match fixture
        .store
        .claim_next_pending_dispatch_or_recover(second_submission.scope(), &second_request)
        .unwrap()
    {
        DispatchAcquisitionOutcome::Acquired(work) => work.into_parts().1,
        other => panic!("expected newer acquired recovery head, got {other:?}"),
    };
    assert_eq!(second_authority.claim().key(), &second_key);
    let second_attempt = fixture
        .store
        .load_current_eks_attempt_for_acquisition(&second_authority)
        .unwrap();
    let route_commitment = *second_attempt.facts().route().commitment().as_bytes();
    let _broker_io = fixture
        .store
        .begin_broker_operation_for_acquisition(
            &broker_capability,
            &second_authority,
            AcquiredBrokerOperationRequest::create(&second_authority, route_commitment).unwrap(),
        )
        .unwrap();
    drop(second_authority);
    force_expire_dispatch_acquisition(&fixture.url, first_acquisition);

    // The v4 schema intentionally has one registered grant per scope.  This
    // test-only swap presents the immutable A grant while the selector compares
    // A against B's already-durable recovery artifact; B is not dereferenced
    // unless the old recovery-first bug bypasses A.  Restore B immediately
    // afterward and prove that its exact recovery remains readable.
    replace_scope_grant_for_fifo_test(&fixture.url, &first_grant, 1);
    let supervisor =
        DispatchAcquisitionRequest::new("pg-v14-global-fifo-supervisor", Uuid::new_v4()).unwrap();
    match fixture
        .store
        .claim_next_pending_dispatch_or_recover(first_submission.scope(), &supervisor)
        .unwrap()
    {
        DispatchAcquisitionOutcome::Disposed(receipt) => {
            assert_eq!(receipt.key(), &first_key);
            assert_eq!(
                receipt.reason(),
                DispatchQueueDispositionReason::AuthorityChanged
            );
        }
        other => panic!("newer recovery bypassed older productive FIFO head: {other:?}"),
    }

    replace_scope_grant_for_fifo_test(&fixture.url, &second_grant, 1);
    let recovery_supervisor =
        DispatchAcquisitionRequest::new("pg-v14-global-fifo-recovery", Uuid::new_v4()).unwrap();
    match fixture
        .store
        .claim_next_pending_dispatch_or_recover(first_submission.scope(), &recovery_supervisor)
        .unwrap()
    {
        DispatchAcquisitionOutcome::RecoveryRequired(work) => {
            assert_eq!(
                work.recovery_key().acquisition_id(),
                second_request.acquisition_id()
            );
            assert_eq!(
                work.disposition(),
                DispatchAcquisitionDisposition::BrokerArtifactPresent
            );
        }
        other => panic!("expected newer recovery after older disposition, got {other:?}"),
    }
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL"]
#[allow(clippy::too_many_lines)]
fn postgres_v14_no_send_retirement_uses_frozen_activation_policy_after_rotation() {
    let _serial = serial_postgres_test();
    let mut fixture = PgControlFixture::new();
    let broker_capability = fixture.store.issue_broker_journal_capability().unwrap();
    let (submission, key) = complete_control_dispatch(&fixture);
    let original_request =
        DispatchAcquisitionRequest::new("pg-v14-policy-a1", Uuid::new_v4()).unwrap();
    let authority = match fixture
        .store
        .claim_next_pending_dispatch_or_recover(submission.scope(), &original_request)
        .unwrap()
    {
        DispatchAcquisitionOutcome::Acquired(work) => work.into_parts().1,
        other => panic!("expected acquired A1 work, got {other:?}"),
    };
    let current = fixture
        .store
        .load_current_eks_attempt_for_acquisition(&authority)
        .unwrap();
    let route_commitment = *current.facts().route().commitment().as_bytes();
    assert_eq!(
        current
            .facts()
            .credential_lifecycle_policy()
            .deletion_propagation_hard_max_seconds(),
        60
    );
    let create = fixture
        .store
        .begin_broker_operation_for_acquisition(
            &broker_capability,
            &authority,
            AcquiredBrokerOperationRequest::create(&authority, route_commitment).unwrap(),
        )
        .unwrap();
    fixture
        .store
        .commit_broker_create(
            create,
            BrokerSecretObservation::matching("pg-secret-policy-a1".to_owned(), [0xc1; 32])
                .unwrap(),
        )
        .unwrap();
    drop(authority);
    let recovery_key = original_request.recovery_key(submission.scope());
    fixture
        .store
        .close_dispatch_acquisition_no_send(&recovery_key)
        .unwrap();
    let cleanup_context = fixture
        .store
        .dispatch_broker_restart_context(&recovery_key)
        .unwrap();
    let cleanup = fixture
        .store
        .prepare_broker_cleanup(
            &broker_capability,
            &cleanup_context.cleanup_request().unwrap(),
        )
        .unwrap();
    let cleanup_io = fixture
        .store
        .begin_broker_io(&broker_capability, cleanup)
        .unwrap();
    fixture.store.mark_broker_io_unknown(cleanup_io).unwrap();
    let reconciliation = fixture
        .store
        .begin_broker_reconciliation(
            &broker_capability,
            &BrokerReconciliationRequest::new(
                key,
                BrokerJournalOperation::DeleteSecret,
                route_commitment,
            )
            .unwrap(),
        )
        .unwrap();
    fixture
        .store
        .commit_broker_reconciliation(
            reconciliation,
            BrokerSecretObservation::absent([0xc2; 32]).unwrap(),
        )
        .unwrap();
    let absent_at = fixture
        .store
        .dispatch_broker_restart_context(&recovery_key)
        .unwrap()
        .deletion_evidence()
        .unwrap()
        .absent_observed_at();

    fixture.rotate_destination_policy(EksCredentialLifecyclePolicy::new(600, 900, 5, 120).unwrap());
    assert!(matches!(
        fixture
            .store
            .retire_recovery_no_send(&recovery_key)
            .unwrap(),
        RecoveryNoSendRetirementOutcome::Pending { safe_after }
            if safe_after == absent_at + 60 + 5
    ));
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL"]
#[allow(clippy::too_many_lines)]
fn postgres_v14_pending_no_send_becomes_due_and_releases_same_physical() {
    let _serial = serial_postgres_test();
    let mut fixture = PgControlFixture::new();
    let broker_capability = fixture.store.issue_broker_journal_capability().unwrap();
    let (first_submission, first_key) = complete_control_dispatch(&fixture);
    let (second_submission, second_key) = complete_control_dispatch(&fixture);
    let (expected_head_key, tail_key) = durable_dispatch_head_and_tail(
        &fixture.url,
        &first_submission,
        &first_key,
        &second_submission,
        &second_key,
    );
    let original_request =
        DispatchAcquisitionRequest::new("pg-v14-pending-head", Uuid::new_v4()).unwrap();
    let authority = match fixture
        .store
        .claim_next_pending_dispatch_or_recover(first_submission.scope(), &original_request)
        .unwrap()
    {
        DispatchAcquisitionOutcome::Acquired(work) => work.into_parts().1,
        other => panic!("expected acquired pending head, got {other:?}"),
    };
    assert_eq!(authority.claim().key(), &expected_head_key);
    let acquired_key = expected_head_key;
    let current = fixture
        .store
        .load_current_eks_attempt_for_acquisition(&authority)
        .unwrap();
    let route_commitment = *current.facts().route().commitment().as_bytes();
    let create = fixture
        .store
        .begin_broker_operation_for_acquisition(
            &broker_capability,
            &authority,
            AcquiredBrokerOperationRequest::create(&authority, route_commitment).unwrap(),
        )
        .unwrap();
    fixture
        .store
        .commit_broker_create(
            create,
            BrokerSecretObservation::matching("pg-secret-pending".to_owned(), [0xd1; 32]).unwrap(),
        )
        .unwrap();
    drop(authority);
    let recovery_key = original_request.recovery_key(first_submission.scope());
    fixture
        .store
        .close_dispatch_acquisition_no_send(&recovery_key)
        .unwrap();
    let cleanup_context = fixture
        .store
        .dispatch_broker_restart_context(&recovery_key)
        .unwrap();
    let cleanup = fixture
        .store
        .prepare_broker_cleanup(
            &broker_capability,
            &cleanup_context.cleanup_request().unwrap(),
        )
        .unwrap();
    let cleanup_io = fixture
        .store
        .begin_broker_io(&broker_capability, cleanup)
        .unwrap();
    fixture.store.mark_broker_io_unknown(cleanup_io).unwrap();
    let reconciliation = fixture
        .store
        .begin_broker_reconciliation(
            &broker_capability,
            &BrokerReconciliationRequest::new(
                acquired_key.clone(),
                BrokerJournalOperation::DeleteSecret,
                route_commitment,
            )
            .unwrap(),
        )
        .unwrap();
    fixture
        .store
        .commit_broker_reconciliation(
            reconciliation,
            BrokerSecretObservation::absent([0xd2; 32]).unwrap(),
        )
        .unwrap();

    let safe_after = match fixture
        .store
        .retire_recovery_no_send(&recovery_key)
        .unwrap()
    {
        RecoveryNoSendRetirementOutcome::Pending { safe_after } => safe_after,
        other => panic!("expected persisted pending retirement bound, got {other:?}"),
    };
    let stored_safe_after: Option<i64> = Client::connect(&fixture.url, NoTls)
        .unwrap()
        .query_one(
            "SELECT recovery_safe_after_unix_s
               FROM public.accordlock_dispatch_claims
              WHERE tenant=$1 AND environment=$2 AND authorization_id=$3
                AND transaction_id=$4",
            &[
                &acquired_key.scope.tenant,
                &acquired_key.scope.environment,
                &acquired_key.authorization_id,
                &acquired_key.transaction_id,
            ],
        )
        .unwrap()
        .get(0);
    assert_eq!(stored_safe_after, Some(safe_after));

    let before_due = DispatchAcquisitionRequest::new("pg-v14-before-due", Uuid::new_v4()).unwrap();
    assert!(matches!(
        fixture
            .store
            .claim_next_pending_dispatch_or_recover(first_submission.scope(), &before_due)
            .unwrap(),
        DispatchAcquisitionOutcome::NoWork
    ));

    let remaining = safe_after.saturating_sub(database_time(&fixture.url));
    if remaining > 0 {
        thread::sleep(Duration::from_secs(
            u64::try_from(remaining).unwrap().saturating_add(1),
        ));
    }
    let due_request =
        DispatchAcquisitionRequest::new("pg-v14-retirement-due", Uuid::new_v4()).unwrap();
    match fixture
        .store
        .claim_next_pending_dispatch_or_recover(first_submission.scope(), &due_request)
        .unwrap()
    {
        DispatchAcquisitionOutcome::RecoveryRequired(work) => {
            assert_eq!(work.recovery_key(), &recovery_key);
            assert_eq!(
                work.disposition(),
                DispatchAcquisitionDisposition::RecoveryNoSend
            );
        }
        other => panic!("due no-send retirement was not rediscovered: {other:?}"),
    }
    assert!(matches!(
        fixture
            .store
            .retire_recovery_no_send(&recovery_key)
            .unwrap(),
        RecoveryNoSendRetirementOutcome::Retired(_)
    ));
    let tail_request =
        DispatchAcquisitionRequest::new("pg-v14-after-retirement", Uuid::new_v4()).unwrap();
    match fixture
        .store
        .claim_next_pending_dispatch_or_recover(first_submission.scope(), &tail_request)
        .unwrap()
    {
        DispatchAcquisitionOutcome::Acquired(work) => {
            assert_eq!(work.authority().claim().key(), &tail_key);
        }
        other => panic!("retirement did not release same physical tail: {other:?}"),
    }
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL; intentionally builds 257 durable recovery heads"]
#[allow(clippy::too_many_lines)]
fn postgres_v14_scan_skips_more_than_transient_retry_cap_and_reaches_valid_tail() {
    let _serial = serial_postgres_test();
    let mut fixture = PgControlFixture::with_dispatch_delay_lifecycle_and_validity(
        7_200,
        EksCredentialLifecyclePolicy::new(600, 900, 5, 86_400).unwrap(),
        21_600,
    );
    let cleanup_url = fixture.url.clone();
    let cleanup_tenant = fixture.tenant.clone();
    let proof = catch_unwind(AssertUnwindSafe(|| {
        let broker_capability = fixture.store.issue_broker_journal_capability().unwrap();
        let mut historical_grants = Vec::with_capacity(257);

        for index in 0..=256_u16 {
            let label = format!("head-{index}");
            create_pending_no_send_head(&fixture, &broker_capability, &label);
            historical_grants.push(fixture.grant.clone());
            fixture.rotate_to_distinct_physical(&format!("next-{index}"));
        }
        let max_head_linked_at = Client::connect(&fixture.url, NoTls)
            .unwrap()
            .query_one(
                "SELECT max(linked_at)::bigint AS linked_at
               FROM public.accordlock_control_consumptions
              WHERE tenant=$1 AND environment=$2",
                &[&fixture.tenant, &CONTROL_ENVIRONMENT],
            )
            .unwrap()
            .get::<_, i64>("linked_at");
        for _ in 0..10 {
            if database_time(&fixture.url) > max_head_linked_at {
                break;
            }
            thread::sleep(Duration::from_secs(1));
        }
        assert!(database_time(&fixture.url) > max_head_linked_at);
        let (tail_submission, tail_key) = complete_control_dispatch(&fixture);
        let order = Client::connect(&fixture.url, NoTls)
            .unwrap()
            .query_one(
                "SELECT count(*) AS total,
                    count(*) FILTER (
                        WHERE (head.linked_at, head.submission_id)
                            < (tail.linked_at, tail.submission_id)
                    ) AS preceding
               FROM public.accordlock_control_consumptions AS head
               CROSS JOIN public.accordlock_control_consumptions AS tail
              WHERE head.tenant=$1 AND head.environment=$2
                AND head.submission_id<>$3
                AND tail.submission_id=$3",
                &[
                    &fixture.tenant,
                    &CONTROL_ENVIRONMENT,
                    &tail_submission.submission_id(),
                ],
            )
            .unwrap();
        assert_eq!(order.get::<_, i64>("total"), 257);
        assert_eq!(order.get::<_, i64>("preceding"), 257);

        // Each head models the crash point before the Pending retirement CAS:
        // DELETE_ABSENT is durable, while the safe-after bound remains NULL.  The
        // production scan must paginate past every byte-exact recovery lineage.
        // Production grant history is immutable; the fixture's rotation helper
        // normally replaces its one scope row only to keep unrelated tests small.
        // Rehydrate that frozen history under a temporary test-only relaxation,
        // then restore the exact v14 schema before this test returns.
        let mut history_client = Client::connect(&fixture.url, NoTls).unwrap();
        history_client
            .batch_execute(
                "ALTER TABLE public.accordlock_grants
                 DROP CONSTRAINT accordlock_grants_scope_key",
            )
            .unwrap();
        drop(history_client);
        let mut history_client = Client::connect(&fixture.url, NoTls).unwrap();
        let mut history_transaction = history_client.transaction().unwrap();
        for registration in &historical_grants {
            let registration_json = serde_json::to_value(registration).unwrap();
            assert_eq!(
                history_transaction
                    .execute(
                        "INSERT INTO public.accordlock_grants
                                (tenant,environment,grant_id,registration_json,uses,
                                 maximum_uses,not_before,expires_at,revoked,
                                 issuance_profile_version)
                         VALUES ($1,$2,$3,$4,1,$5,$6,$7,FALSE,2)",
                        &[
                            &registration.grant.tenant,
                            &registration.environment,
                            &registration.grant.grant_id,
                            &registration_json,
                            &i64::from(registration.grant.maximum_uses),
                            &registration.grant.not_before,
                            &registration.grant.expires_at,
                        ],
                    )
                    .unwrap(),
                1
            );
        }
        history_transaction.commit().unwrap();
        history_client
            .batch_execute("SET session_replication_role = replica")
            .unwrap();
        assert_eq!(
            history_client
                .execute(
                    "UPDATE public.accordlock_dispatch_claims
                        SET recovery_safe_after_unix_s=NULL
                      WHERE tenant=$1 AND environment=$2
                        AND state='RECOVERY_NO_SEND'",
                    &[&fixture.tenant, &CONTROL_ENVIRONMENT],
                )
                .unwrap(),
            257
        );
        history_client
            .batch_execute("SET session_replication_role = origin")
            .unwrap();
        drop(history_client);

        let request =
            DispatchAcquisitionRequest::new("pg-v14-after-257-skips", Uuid::new_v4()).unwrap();
        match fixture
            .store
            .claim_next_pending_dispatch_or_recover(tail_submission.scope(), &request)
            .unwrap()
        {
            DispatchAcquisitionOutcome::Acquired(work) => {
                assert_eq!(work.authority().claim().key(), &tail_key);
            }
            other => panic!("257 durable skips starved valid tail: {other:?}"),
        }
    }));
    restore_tenant_after_grant_scope_relaxation(&cleanup_url, &cleanup_tenant);
    if let Err(payload) = proof {
        resume_unwind(payload);
    }
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL"]
fn postgres_v14_server_selected_acquisition_and_exact_recovery() {
    let _serial = serial_postgres_test();
    let fixture = PgControlFixture::new();
    let (receipt, key) = complete_control_dispatch(&fixture);
    let legacy = accordlock_state::DispatchClaimRequest {
        key: key.clone(),
        claim_id: Uuid::new_v4(),
        worker_id: "pg-v14-legacy-bypass".to_owned(),
    };
    assert!(matches!(
        fixture.store.claim_dispatch(&legacy),
        Err(StateError::DispatchAcquisitionRequired)
    ));

    let request = DispatchAcquisitionRequest::new("pg-v14-worker", Uuid::new_v4()).unwrap();
    let (claim_id, claim_fence, lease_fence) = match fixture
        .store
        .claim_next_pending_dispatch_or_recover(receipt.scope(), &request)
        .unwrap()
    {
        DispatchAcquisitionOutcome::Acquired(work) => (
            work.authority().claim().claim_id(),
            work.authority().claim().fence(),
            work.authority().lease_fence(),
        ),
        other => panic!("expected acquired dispatch work, got {other:?}"),
    };
    match fixture
        .store
        .claim_next_pending_dispatch_or_recover(receipt.scope(), &request)
        .unwrap()
    {
        DispatchAcquisitionOutcome::Recovered(work) => {
            assert_eq!(work.authority().claim().claim_id(), claim_id);
            assert_eq!(work.authority().claim().fence(), claim_fence);
            assert_eq!(work.authority().lease_fence(), lease_fence);
        }
        other => panic!("expected exact recovered dispatch work, got {other:?}"),
    }
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL"]
fn postgres_v14_hwm_proven_takeover_candidate_surfaces_clock_rollback() {
    let _serial = serial_postgres_test();
    let fixture = PgControlFixture::new();
    let (receipt, _) = complete_control_dispatch(&fixture);
    let first_request =
        DispatchAcquisitionRequest::new("pg-v14-hwm-first", Uuid::new_v4()).unwrap();
    let lease_until = match fixture
        .store
        .claim_next_pending_dispatch_or_recover(receipt.scope(), &first_request)
        .unwrap()
    {
        DispatchAcquisitionOutcome::Acquired(work) => work.authority().lease_until(),
        other => panic!("expected first dispatch acquisition, got {other:?}"),
    };
    assert!(database_time(&fixture.url) < lease_until);

    let mut client = Client::connect(&fixture.url, NoTls).unwrap();
    assert_eq!(
        client
            .execute(
                "UPDATE public.accordlock_time_high_water
                    SET observed_unix_s=$3
                  WHERE tenant=$1 AND environment=$2",
                &[
                    &receipt.scope().tenant,
                    &receipt.scope().environment,
                    &lease_until,
                ],
            )
            .unwrap(),
        1
    );
    assert_eq!(
        client
            .execute(
                "UPDATE public.accordlock_ingress_replay_scopes AS ingress
                    SET observed_unix_s=$2
                   FROM public.accordlock_control_submissions AS submission
                  WHERE submission.submission_id=$1
                    AND ingress.replay_scope=submission.replay_scope
                    AND ingress.state_instance_id=submission.state_instance_id",
                &[&receipt.submission_id(), &lease_until],
            )
            .unwrap(),
        1
    );

    let takeover = DispatchAcquisitionRequest::new("pg-v14-hwm-takeover", Uuid::new_v4()).unwrap();
    assert!(matches!(
        fixture
            .store
            .claim_next_pending_dispatch_or_recover(receipt.scope(), &takeover),
        Err(StateError::ClockRollback { high_water, .. }) if high_water == lease_until
    ));
    assert_eq!(
        client
            .query_one(
                "SELECT count(*)::bigint
                   FROM public.accordlock_dispatch_acquisitions
                  WHERE acquisition_id=$1",
                &[&takeover.acquisition_id()],
            )
            .unwrap()
            .get::<_, i64>(0),
        0
    );
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL"]
fn postgres_v14_disposes_rotated_authority_with_sql_verified_commitments() {
    let _serial = serial_postgres_test();
    let fixture = PgControlFixture::new();
    let (receipt, _) = complete_control_dispatch(&fixture);
    let mut rotated = fixture.authority.clone();
    rotated.connector = AuthorityDomainState {
        root: Digest32::sha256(b"pg-v14-disposition-connector"),
        epoch: rotated.connector.epoch + 1,
        activation_id: Uuid::new_v4(),
    };
    fixture
        .store
        .compare_and_activate_authority(receipt.scope(), Some(&fixture.authority), &rotated)
        .unwrap();
    let request = DispatchAcquisitionRequest::new("pg-v14-disposer", Uuid::new_v4()).unwrap();
    let first = match fixture
        .store
        .claim_next_pending_dispatch_or_recover(receipt.scope(), &request)
        .unwrap()
    {
        DispatchAcquisitionOutcome::Disposed(receipt) => receipt,
        other => panic!("expected disposed queue head, got {other:?}"),
    };
    assert_eq!(
        first.reason(),
        DispatchQueueDispositionReason::AuthorityChanged
    );
    match fixture
        .store
        .claim_next_pending_dispatch_or_recover(receipt.scope(), &request)
        .unwrap()
    {
        DispatchAcquisitionOutcome::Disposed(recovered) => assert_eq!(recovered, first),
        other => panic!("expected exact disposition recovery, got {other:?}"),
    }
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL"]
fn postgres_v14_no_work_rolls_back_unbound_request_identity() {
    let _serial = serial_postgres_test();
    let fixture = PgControlFixture::new();
    let request = DispatchAcquisitionRequest::new("pg-v14-idle", Uuid::new_v4()).unwrap();
    assert!(matches!(
        fixture
            .store
            .claim_next_pending_dispatch_or_recover(
                &Scope::new(&fixture.tenant, CONTROL_ENVIRONMENT).unwrap(),
                &request,
            )
            .unwrap(),
        DispatchAcquisitionOutcome::NoWork
    ));
    let count: i64 = Client::connect(&fixture.url, NoTls)
        .unwrap()
        .query_one(
            "SELECT count(*) FROM public.accordlock_dispatch_request_identities
              WHERE dispatch_request_id=$1",
            &[&request.acquisition_id()],
        )
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL"]
fn postgres_v14_deadline_head_is_disposed_before_next_valid_work() {
    let _serial = serial_postgres_test();
    let fixture = PgControlFixture::with_dispatch_delay(5);
    let (first_submission, first_key) = complete_control_dispatch(&fixture);
    let first_deadline: i64 = Client::connect(&fixture.url, NoTls)
        .unwrap()
        .query_one(
            "SELECT dispatch_deadline
               FROM public.accordlock_execution_outbox
              WHERE tenant=$1 AND environment=$2 AND authorization_id=$3
                AND transaction_id=$4",
            &[
                &first_key.scope.tenant,
                &first_key.scope.environment,
                &first_key.authorization_id,
                &first_key.transaction_id,
            ],
        )
        .unwrap()
        .get(0);
    thread::sleep(Duration::from_secs(6));
    let (_, second_key) = complete_control_dispatch(&fixture);
    let replay_scope: String = Client::connect(&fixture.url, NoTls)
        .unwrap()
        .query_one(
            "SELECT replay_scope FROM public.accordlock_control_submissions
              WHERE submission_id=$1",
            &[&first_submission.submission_id()],
        )
        .unwrap()
        .get(0);
    let (scope_hwm, _, ingress_hwm, _) =
        control_high_waters(&fixture.url, first_submission.scope(), &replay_scope);
    assert!(scope_hwm.max(ingress_hwm) >= first_deadline);

    let dispose = DispatchAcquisitionRequest::new("pg-v14-deadline", Uuid::new_v4()).unwrap();
    match fixture
        .store
        .claim_next_pending_dispatch_or_recover(first_submission.scope(), &dispose)
        .unwrap()
    {
        DispatchAcquisitionOutcome::Disposed(receipt) => {
            assert_eq!(
                receipt.reason(),
                DispatchQueueDispositionReason::DispatchDeadlineExpired
            );
            assert_eq!(receipt.key(), &first_key);
            assert!(receipt.observed_at() >= first_deadline);
        }
        other => panic!("expected expired FIFO head disposition, got {other:?}"),
    }

    let acquire = DispatchAcquisitionRequest::new("pg-v14-after-deadline", Uuid::new_v4()).unwrap();
    match fixture
        .store
        .claim_next_pending_dispatch_or_recover(first_submission.scope(), &acquire)
        .unwrap()
    {
        DispatchAcquisitionOutcome::Acquired(work) => {
            assert_eq!(work.authority().claim().key(), &second_key);
        }
        other => panic!("expected next valid FIFO work, got {other:?}"),
    }
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL"]
fn postgres_v14_two_same_scope_dispositions_make_progress_without_deadlock() {
    let _serial = serial_postgres_test();
    let fixture = PgControlFixture::new();
    let (first, _) = complete_control_dispatch(&fixture);
    let (second, _) = complete_control_dispatch(&fixture);
    let mut rotated = fixture.authority.clone();
    rotated.connector = AuthorityDomainState {
        root: Digest32::sha256(b"pg-v14-concurrent-disposition"),
        epoch: rotated.connector.epoch + 1,
        activation_id: Uuid::new_v4(),
    };
    fixture
        .store
        .compare_and_activate_authority(first.scope(), Some(&fixture.authority), &rotated)
        .unwrap();

    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for (store, scope, worker) in [
        (
            fixture.store.clone(),
            first.scope().clone(),
            "pg-v14-dispose-a",
        ),
        (
            fixture.store.clone(),
            first.scope().clone(),
            "pg-v14-dispose-b",
        ),
    ] {
        let request = DispatchAcquisitionRequest::new(worker, Uuid::new_v4()).unwrap();
        let worker_barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            worker_barrier.wait();
            store
                .claim_next_pending_dispatch_or_recover(&scope, &request)
                .unwrap()
        }));
    }
    barrier.wait();
    let mut submissions = BTreeSet::new();
    for handle in handles {
        match handle.join().unwrap() {
            DispatchAcquisitionOutcome::Disposed(receipt) => {
                assert_eq!(
                    receipt.reason(),
                    DispatchQueueDispositionReason::AuthorityChanged
                );
                submissions.insert(receipt.control_submission_id());
            }
            other => panic!("expected concurrent disposition, got {other:?}"),
        }
    }
    assert_eq!(
        submissions,
        BTreeSet::from([first.submission_id(), second.submission_id()])
    );
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL"]
fn postgres_v14_superseded_receipt_is_stable_after_latest_disposition() {
    let _serial = serial_postgres_test();
    let fixture = PgControlFixture::new();
    let (submission, _) = complete_control_dispatch(&fixture);
    let first_request =
        DispatchAcquisitionRequest::new("pg-v14-generation-a", Uuid::new_v4()).unwrap();
    let (first_acquisition, stable_claim) = match fixture
        .store
        .claim_next_pending_dispatch_or_recover(submission.scope(), &first_request)
        .unwrap()
    {
        DispatchAcquisitionOutcome::Acquired(work) => (
            work.authority().acquisition_id(),
            work.authority().claim().claim_id(),
        ),
        other => panic!("expected first acquisition, got {other:?}"),
    };
    force_expire_dispatch_acquisition(&fixture.url, first_acquisition);

    let second_request =
        DispatchAcquisitionRequest::new("pg-v14-generation-b", Uuid::new_v4()).unwrap();
    let second_acquisition = match fixture
        .store
        .claim_next_pending_dispatch_or_recover(submission.scope(), &second_request)
        .unwrap()
    {
        DispatchAcquisitionOutcome::Acquired(work) => {
            assert_eq!(work.authority().claim().claim_id(), stable_claim);
            work.authority().acquisition_id()
        }
        other => panic!("expected takeover acquisition, got {other:?}"),
    };
    force_expire_dispatch_acquisition(&fixture.url, second_acquisition);

    let mut rotated = fixture.authority.clone();
    rotated.connector = AuthorityDomainState {
        root: Digest32::sha256(b"pg-v14-history-disposition"),
        epoch: rotated.connector.epoch + 1,
        activation_id: Uuid::new_v4(),
    };
    fixture
        .store
        .compare_and_activate_authority(submission.scope(), Some(&fixture.authority), &rotated)
        .unwrap();
    let disposition_request =
        DispatchAcquisitionRequest::new("pg-v14-history-disposer", Uuid::new_v4()).unwrap();
    match fixture
        .store
        .claim_next_pending_dispatch_or_recover(submission.scope(), &disposition_request)
        .unwrap()
    {
        DispatchAcquisitionOutcome::Disposed(receipt) => {
            assert_eq!(receipt.acquisition_id(), Some(second_acquisition));
        }
        other => panic!("expected latest generation disposition, got {other:?}"),
    }

    match fixture
        .store
        .claim_next_pending_dispatch_or_recover(submission.scope(), &first_request)
        .unwrap()
    {
        DispatchAcquisitionOutcome::Inert(receipt) => {
            assert_eq!(receipt.acquisition_id(), first_acquisition);
            assert_eq!(
                receipt.disposition(),
                DispatchAcquisitionDisposition::Superseded
            );
        }
        other => panic!("expected stable superseded history, got {other:?}"),
    }
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL"]
fn postgres_v14_source_and_high_water_guards_reject_direct_tamper() {
    let _serial = serial_postgres_test();
    let fixture = PgControlFixture::new();
    let (submission, key) = complete_control_dispatch(&fixture);
    let mut client = Client::connect(&fixture.url, NoTls).unwrap();
    assert!(
        client
            .execute(
                "UPDATE public.accordlock_execution_outbox
                    SET entry_json=entry_json || '{\"unknown\":true}'::jsonb
                  WHERE tenant=$1 AND environment=$2 AND authorization_id=$3
                    AND transaction_id=$4",
                &[
                    &key.scope.tenant,
                    &key.scope.environment,
                    &key.authorization_id,
                    &key.transaction_id,
                ],
            )
            .is_err()
    );
    assert!(
        client
            .execute(
                "DELETE FROM public.accordlock_consumptions
                  WHERE tenant=$1 AND environment=$2 AND authorization_id=$3
                    AND transaction_id=$4",
                &[
                    &key.scope.tenant,
                    &key.scope.environment,
                    &key.authorization_id,
                    &key.transaction_id,
                ],
            )
            .is_err()
    );
    assert!(
        client
            .execute(
                "UPDATE public.accordlock_grants
                    SET issuance_profile_version=1
                  WHERE tenant=$1 AND environment=$2 AND grant_id=$3",
                &[
                    &key.scope.tenant,
                    &key.scope.environment,
                    &fixture.grant.grant.grant_id,
                ],
            )
            .is_err()
    );
    assert!(
        client
            .execute(
                "UPDATE public.accordlock_issued_authorizations
                    SET record_json=record_json || '{\"unknown\":true}'::jsonb
                  WHERE tenant=$1 AND environment=$2 AND authorization_id=$3
                    AND transaction_id=$4",
                &[
                    &key.scope.tenant,
                    &key.scope.environment,
                    &key.authorization_id,
                    &key.transaction_id,
                ],
            )
            .is_err()
    );
    assert!(
        client
            .execute(
                "UPDATE public.accordlock_time_high_water
                    SET observed_unix_s=observed_unix_s-1
                  WHERE tenant=$1 AND environment=$2",
                &[&key.scope.tenant, &key.scope.environment],
            )
            .is_err()
    );
    let replay_scope: String = client
        .query_one(
            "SELECT replay_scope FROM public.accordlock_control_submissions
              WHERE submission_id=$1",
            &[&submission.submission_id()],
        )
        .unwrap()
        .get(0);
    assert!(
        client
            .execute(
                "UPDATE public.accordlock_ingress_replay_scopes
                    SET observed_unix_s=observed_unix_s-1
                  WHERE replay_scope=$1",
                &[&replay_scope],
            )
            .is_err()
    );
    assert!(
        client
            .execute(
                "UPDATE public.accordlock_authority_state
                    SET authority_json=jsonb_set(
                        authority_json, '{policy,epoch}', '\"1\"'::jsonb
                    )
                  WHERE tenant=$1 AND environment=$2",
                &[&key.scope.tenant, &key.scope.environment],
            )
            .is_err()
    );
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL"]
fn postgres_v13_intake_three_phases_exact_recovery_and_restart() {
    let _serial = serial_postgres_test();
    let fixture = PgControlFixture::new();
    let wire = fixture.signed_wire(Uuid::new_v4(), Uuid::new_v4());
    let receipt = fixture.accept(&wire);

    let evaluate_claim_id = Uuid::new_v4();
    let evaluate_request = claim_request(
        "pg-v13-evaluator",
        ControlWorkerRole::Evaluator,
        evaluate_claim_id,
    );
    let evaluation_work = match fixture
        .store
        .claim_next_control_work_or_recover(&evaluate_request)
        .unwrap()
    {
        ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Evaluate(work)) => work,
        other => panic!("expected EVALUATE work, got {other:?}"),
    };
    let evaluation = signed_evaluation(&evaluation_work, &fixture.evaluator);
    let decision = fixture
        .store
        .record_control_evaluation(evaluation_work, &evaluation, &fixture.evaluator.verifier())
        .unwrap();
    assert_eq!(decision.control_outcome(), ControlOutcome::Allow);
    assert_eq!(decision.reason(), ControlDecisionReason::ControlAllow);
    assert_eq!(
        decision.selected_grant_id(),
        Some(fixture.grant.grant.grant_id)
    );

    let issue_claim_id = Uuid::new_v4();
    let issue_request = claim_request("pg-v13-issuer", ControlWorkerRole::Issuer, issue_claim_id);
    let issue_work = match fixture
        .store
        .claim_next_control_work_or_recover(&issue_request)
        .unwrap()
    {
        ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Issue(work)) => work,
        other => panic!("expected ISSUE work, got {other:?}"),
    };
    let snapshot = fixture
        .store
        .control_issuance_snapshot(&issue_work)
        .unwrap();
    let issued = issued_record(&issue_work, &snapshot, &fixture.authorization_signer);
    assert!(matches!(
        fixture.store.record_issued_authorization(&issued),
        Err(StateError::ControlWorkMismatch)
    ));
    assert_eq!(
        fixture
            .store
            .record_and_link_control_issuance_or_recover(issue_work, &issued)
            .unwrap(),
        ControlIssuanceCommitOutcome::Committed
    );
    let issued_key = ConsumeKey {
        scope: issued.scope(),
        transaction_id: issued.transaction_id,
        authorization_id: issued.authorization().authorization_id,
    };
    assert!(matches!(
        fixture.store.consume(&issued_key),
        Err(StateError::ControlWorkMismatch)
    ));

    let consume_claim_id = Uuid::new_v4();
    let consume_request = claim_request(
        "pg-v13-consumer",
        ControlWorkerRole::Consumer,
        consume_claim_id,
    );
    let consume_work = match fixture
        .store
        .claim_next_control_work_or_recover(&consume_request)
        .unwrap()
    {
        ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Consume(work)) => work,
        other => panic!("expected CONSUME work, got {other:?}"),
    };
    let consume_key = consume_work.consume_key().clone();
    assert_eq!(consume_key, issued_key);
    let success = match fixture
        .store
        .consume_and_link_control_or_recover(consume_work)
        .unwrap()
    {
        ControlConsumptionCommitOutcome::Committed(success) => success,
        other => panic!("expected committed CONSUME, got {other:?}"),
    };
    assert_eq!(success.issued(), &issued);

    let status = fixture
        .store
        .control_status(receipt.scope(), receipt.receipt_id())
        .unwrap();
    assert_eq!(status.status(), ControlStatusCode::DispatchPending);
    assert_eq!(status.revision(), 4);

    let inert_future = database_time(&fixture.url).saturating_add(1_000_000);
    let mut hwm_client = Client::connect(&fixture.url, NoTls).unwrap();
    hwm_client
        .execute(
            "UPDATE public.accordlock_time_high_water
                SET observed_unix_s=$3,updated_at=clock_timestamp()
              WHERE tenant=$1 AND environment=$2",
            &[
                &receipt.scope().tenant,
                &receipt.scope().environment,
                &inert_future,
            ],
        )
        .unwrap();
    hwm_client
        .execute(
            "UPDATE public.accordlock_ingress_replay_scopes
                SET observed_unix_s=$2,updated_at=clock_timestamp()
              WHERE replay_scope=$1",
            &[&fixture.audience, &inert_future],
        )
        .unwrap();
    let hwm_before: (i64, String, i64, String) = {
        let row = hwm_client
            .query_one(
                "SELECT scope.observed_unix_s AS scope_observed,
                        scope.updated_at::text AS scope_updated,
                        ingress.observed_unix_s AS ingress_observed,
                        ingress.updated_at::text AS ingress_updated
                   FROM public.accordlock_time_high_water AS scope
                   JOIN public.accordlock_ingress_replay_scopes AS ingress
                     ON ingress.replay_scope=$3
                  WHERE scope.tenant=$1 AND scope.environment=$2",
                &[
                    &receipt.scope().tenant,
                    &receipt.scope().environment,
                    &fixture.audience,
                ],
            )
            .unwrap();
        (
            row.get("scope_observed"),
            row.get("scope_updated"),
            row.get("ingress_observed"),
            row.get("ingress_updated"),
        )
    };

    for (worker, role, claim_id, expected_phase) in [
        (
            "pg-v13-evaluator",
            ControlWorkerRole::Evaluator,
            evaluate_claim_id,
            ControlWorkPhase::Evaluate,
        ),
        (
            "pg-v13-issuer",
            ControlWorkerRole::Issuer,
            issue_claim_id,
            ControlWorkPhase::Issue,
        ),
        (
            "pg-v13-consumer",
            ControlWorkerRole::Consumer,
            consume_claim_id,
            ControlWorkPhase::Consume,
        ),
    ] {
        match fixture
            .store
            .claim_next_control_work_or_recover(&claim_request(worker, role, claim_id))
            .unwrap()
        {
            ControlWorkClaimOutcome::PhaseCompleted(completion) => {
                assert_eq!(completion.phase(), expected_phase);
                assert_eq!(
                    completion.consume_key(),
                    (expected_phase == ControlWorkPhase::Consume).then_some(&consume_key)
                );
            }
            other => panic!("expected inert completed-phase recovery, got {other:?}"),
        }
    }

    let value: serde_json::Value = serde_json::from_slice(&wire).unwrap();
    let pretty = serde_json::to_vec_pretty(&value).unwrap();
    let mut rotated = fixture.authority.clone();
    rotated.principal_registry = AuthorityDomainState {
        root: Digest32::sha256(b"pg-v13-rotated-principal-registry"),
        epoch: fixture.authority.principal_registry.epoch + 1,
        activation_id: Uuid::new_v4(),
    };
    fixture
        .store
        .compare_and_activate_authority(receipt.scope(), Some(&fixture.authority), &rotated)
        .unwrap();
    match fixture
        .store
        .accept_control_submission_or_recover(fixture.verify_wire(&pretty))
        .unwrap()
    {
        ControlSubmissionIntakeOutcome::Recovered(recovered) => {
            assert_eq!(recovered.receipt(), &receipt);
            assert_eq!(recovered.status(), ControlStatusCode::DispatchPending);
        }
        other => panic!("expected authority-inert exact intake recovery, got {other:?}"),
    }
    let retry_probe = IngressRecoveryProbe::parse_bytes(&pretty).unwrap();
    let frozen = fixture
        .store
        .control_recovery_verifier(&retry_probe)
        .unwrap()
        .unwrap();
    let historical = retry_probe.verify_historical(&frozen).unwrap();
    let recovered = fixture
        .store
        .recover_control_submission(&historical)
        .unwrap();
    assert_eq!(recovered.receipt(), &receipt);
    assert_eq!(recovered.status(), ControlStatusCode::DispatchPending);

    let restarted = PostgresStore::new(fixture.url.clone());
    restarted.migrate().unwrap();
    let restarted_status = restarted
        .control_status(receipt.scope(), receipt.receipt_id())
        .unwrap();
    assert_eq!(restarted_status, status);
    assert_eq!(restarted.consume_or_recover(&consume_key).unwrap(), success);
    let artifact_counts_before = control_artifact_counts(&fixture.url, receipt.submission_id());
    for (worker, role, claim_id, expected_phase) in [
        (
            "pg-v13-evaluator",
            ControlWorkerRole::Evaluator,
            evaluate_claim_id,
            ControlWorkPhase::Evaluate,
        ),
        (
            "pg-v13-issuer",
            ControlWorkerRole::Issuer,
            issue_claim_id,
            ControlWorkPhase::Issue,
        ),
        (
            "pg-v13-consumer",
            ControlWorkerRole::Consumer,
            consume_claim_id,
            ControlWorkPhase::Consume,
        ),
    ] {
        match restarted
            .claim_next_control_work_or_recover(&claim_request(worker, role, claim_id))
            .unwrap()
        {
            ControlWorkClaimOutcome::PhaseCompleted(completion) => {
                assert_eq!(completion.phase(), expected_phase);
                assert_eq!(
                    completion.consume_key(),
                    (expected_phase == ControlWorkPhase::Consume).then_some(&consume_key)
                );
            }
            other => panic!("expected restart {expected_phase:?} completion, got {other:?}"),
        }
    }
    assert_eq!(
        control_artifact_counts(&fixture.url, receipt.submission_id()),
        artifact_counts_before
    );
    assert_eq!(
        restarted
            .control_status(receipt.scope(), receipt.receipt_id())
            .unwrap(),
        status
    );
    let hwm_after: (i64, String, i64, String) = {
        let row = hwm_client
            .query_one(
                "SELECT scope.observed_unix_s AS scope_observed,
                        scope.updated_at::text AS scope_updated,
                        ingress.observed_unix_s AS ingress_observed,
                        ingress.updated_at::text AS ingress_updated
                   FROM public.accordlock_time_high_water AS scope
                   JOIN public.accordlock_ingress_replay_scopes AS ingress
                     ON ingress.replay_scope=$3
                  WHERE scope.tenant=$1 AND scope.environment=$2",
                &[
                    &receipt.scope().tenant,
                    &receipt.scope().environment,
                    &fixture.audience,
                ],
            )
            .unwrap();
        (
            row.get("scope_observed"),
            row.get("scope_updated"),
            row.get("ingress_observed"),
            row.get("ingress_updated"),
        )
    };
    assert_eq!(hwm_after, hwm_before);
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL"]
fn postgres_v13_issue_rejects_partial_authorization_tuple_and_legacy_paths() {
    let _serial = serial_postgres_test();
    let fixture = PgControlFixture::new();
    let wire = fixture.signed_wire(Uuid::new_v4(), Uuid::new_v4());
    let receipt = fixture.accept(&wire);
    let evaluate_request = claim_request(
        "pg-v13-partial-evaluator",
        ControlWorkerRole::Evaluator,
        Uuid::new_v4(),
    );
    let evaluation_work = match fixture
        .store
        .claim_next_control_work_or_recover(&evaluate_request)
        .unwrap()
    {
        ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Evaluate(work)) => work,
        other => panic!("expected EVALUATE work, got {other:?}"),
    };
    let evaluation = signed_evaluation(&evaluation_work, &fixture.evaluator);
    fixture
        .store
        .record_control_evaluation(evaluation_work, &evaluation, &fixture.evaluator.verifier())
        .unwrap();

    let issue_request = claim_request(
        "pg-v13-partial-issuer",
        ControlWorkerRole::Issuer,
        Uuid::new_v4(),
    );
    let issue_work = match fixture
        .store
        .claim_next_control_work_or_recover(&issue_request)
        .unwrap()
    {
        ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Issue(work)) => work,
        other => panic!("expected ISSUE work, got {other:?}"),
    };
    let snapshot = fixture
        .store
        .control_issuance_snapshot(&issue_work)
        .unwrap();
    let issued = issued_record(&issue_work, &snapshot, &fixture.authorization_signer);
    assert!(matches!(
        fixture.store.record_issued_authorization(&issued),
        Err(StateError::ControlWorkMismatch)
    ));

    // Simulate a crashed/bypassing writer that inserted only the legacy
    // authorization half. The combined API must treat this as corruption, never heal
    // it into the control ledger.
    insert_authorization_direct(&fixture.url, &issued);
    assert!(matches!(
        fixture
            .store
            .record_and_link_control_issuance_or_recover(issue_work, &issued),
        Err(StateError::InvalidRecord(message))
            if message.contains("pre-existing authorization/control tuple")
    ));
    let key = ConsumeKey {
        scope: issued.scope(),
        transaction_id: issued.transaction_id,
        authorization_id: issued.authorization().authorization_id,
    };
    assert!(matches!(
        fixture.store.consume_or_recover(&key),
        Err(StateError::ControlWorkMismatch | StateError::InvalidRecord(_))
    ));
    let client = &mut Client::connect(&fixture.url, NoTls).unwrap();
    let counts = client
        .query_one(
            "SELECT
                (SELECT count(*) FROM public.accordlock_control_issuances
                  WHERE submission_id=$1) AS issuances,
                (SELECT count(*) FROM public.accordlock_consumptions
                  WHERE tenant=$2 AND environment=$3 AND authorization_id=$4) AS receipts,
                (SELECT count(*) FROM public.accordlock_execution_outbox
                  WHERE tenant=$2 AND environment=$3 AND authorization_id=$4) AS outbox",
            &[
                &receipt.submission_id(),
                &receipt.scope().tenant,
                &receipt.scope().environment,
                &key.authorization_id,
            ],
        )
        .unwrap();
    assert_eq!(counts.get::<_, i64>("issuances"), 0);
    assert_eq!(counts.get::<_, i64>("receipts"), 0);
    assert_eq!(counts.get::<_, i64>("outbox"), 0);

    // Remove the deliberately injected corrupt half through the same
    // replication-only test boundary used to seed otherwise impossible
    // states. `SET LOCAL` guarantees that normal trigger enforcement is
    // restored when this transaction ends.
    let mut transaction = client.transaction().unwrap();
    transaction
        .batch_execute("SET LOCAL session_replication_role = replica")
        .unwrap();
    let deleted = transaction
        .execute(
            "DELETE FROM public.accordlock_issued_authorizations
              WHERE tenant=$1 AND environment=$2 AND authorization_id=$3 AND transaction_id=$4",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
            ],
        )
        .unwrap();
    assert_eq!(deleted, 1);
    transaction.commit().unwrap();
    let recovered_issue = match fixture
        .store
        .claim_next_control_work_or_recover(&issue_request)
        .unwrap()
    {
        ControlWorkClaimOutcome::Recovered(ClaimedControlWork::Issue(work)) => work,
        other => panic!("expected exact ISSUE recovery after cleanup, got {other:?}"),
    };
    assert_eq!(
        fixture
            .store
            .record_and_link_control_issuance_or_recover(recovered_issue, &issued)
            .unwrap(),
        ControlIssuanceCommitOutcome::Committed
    );
    let consume_request = claim_request(
        "pg-v13-partial-consumer",
        ControlWorkerRole::Consumer,
        Uuid::new_v4(),
    );
    let consume_work = match fixture
        .store
        .claim_next_control_work_or_recover(&consume_request)
        .unwrap()
    {
        ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Consume(work)) => work,
        other => panic!("expected cleanup CONSUME work, got {other:?}"),
    };
    assert!(matches!(
        fixture
            .store
            .consume_and_link_control_or_recover(consume_work)
            .unwrap(),
        ControlConsumptionCommitOutcome::Committed(_)
    ));
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL"]
fn postgres_v13_failed_closed_issue_rejects_orphan_authorization_history() {
    let _serial = serial_postgres_test();
    let fixture = PgControlFixture::new();
    let request_id = Uuid::new_v4();
    let wire = fixture.signed_wire(request_id, Uuid::new_v4());
    let receipt = fixture.accept(&wire);
    let evaluate_request = claim_request(
        "pg-v13-finalize-evaluator",
        ControlWorkerRole::Evaluator,
        Uuid::new_v4(),
    );
    let evaluation_work = match fixture
        .store
        .claim_next_control_work_or_recover(&evaluate_request)
        .unwrap()
    {
        ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Evaluate(work)) => work,
        other => panic!("expected EVALUATE work, got {other:?}"),
    };
    let accepted_proposal = evaluation_work.proposal().clone();
    let evaluation = signed_evaluation(&evaluation_work, &fixture.evaluator);
    fixture
        .store
        .record_control_evaluation(evaluation_work, &evaluation, &fixture.evaluator.verifier())
        .unwrap();

    let mut rotated = fixture.authority.clone();
    rotated.principal_registry = AuthorityDomainState {
        root: Digest32::sha256(b"pg-v13-finalization-authority-loss"),
        epoch: fixture.authority.principal_registry.epoch + 1,
        activation_id: Uuid::new_v4(),
    };
    fixture
        .store
        .compare_and_activate_authority(receipt.scope(), Some(&fixture.authority), &rotated)
        .unwrap();
    let issue_request = claim_request(
        "pg-v13-finalize-issuer",
        ControlWorkerRole::Issuer,
        Uuid::new_v4(),
    );
    match fixture
        .store
        .claim_next_control_work_or_recover(&issue_request)
        .unwrap()
    {
        ControlWorkClaimOutcome::WorkFinalized(finalized) => {
            assert_eq!(finalized.phase(), ControlWorkPhase::Issue);
            assert_eq!(
                finalized.reason(),
                ControlWorkFinalizationReason::AuthorityChanged
            );
        }
        other => panic!("expected fail-closed ISSUE, got {other:?}"),
    }
    assert_eq!(
        fixture
            .store
            .control_status(receipt.scope(), receipt.receipt_id())
            .unwrap()
            .status(),
        ControlStatusCode::FailedClosed
    );

    let orphan = orphan_issued_record(&fixture, &accepted_proposal, &evaluation);
    assert!(matches!(
        fixture.store.record_issued_authorization(&orphan),
        Err(StateError::ControlWorkMismatch)
    ));
    insert_authorization_direct(&fixture.url, &orphan);
    assert!(matches!(
        fixture
            .store
            .control_status(receipt.scope(), receipt.receipt_id()),
        Err(StateError::InvalidRecord(message))
            if message.contains("fail-closed ISSUE history")
    ));
    assert!(matches!(
        fixture
            .store
            .claim_next_control_work_or_recover(&issue_request),
        Err(StateError::InvalidRecord(message))
            if message.contains("fail-closed ISSUE history")
    ));
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL"]
fn postgres_v13_failed_closed_consume_rejects_consumed_authorization_without_link() {
    let _serial = serial_postgres_test();
    let fixture = PgControlFixture::new();
    let wire = fixture.signed_wire(Uuid::new_v4(), Uuid::new_v4());
    let receipt = fixture.accept(&wire);
    let evaluate_request = claim_request(
        "pg-v13-consume-finalize-evaluator",
        ControlWorkerRole::Evaluator,
        Uuid::new_v4(),
    );
    let evaluation_work = match fixture
        .store
        .claim_next_control_work_or_recover(&evaluate_request)
        .unwrap()
    {
        ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Evaluate(work)) => work,
        other => panic!("expected EVALUATE work, got {other:?}"),
    };
    let evaluation = signed_evaluation(&evaluation_work, &fixture.evaluator);
    fixture
        .store
        .record_control_evaluation(evaluation_work, &evaluation, &fixture.evaluator.verifier())
        .unwrap();
    let issue_request = claim_request(
        "pg-v13-consume-finalize-issuer",
        ControlWorkerRole::Issuer,
        Uuid::new_v4(),
    );
    let issue_work = match fixture
        .store
        .claim_next_control_work_or_recover(&issue_request)
        .unwrap()
    {
        ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Issue(work)) => work,
        other => panic!("expected ISSUE work, got {other:?}"),
    };
    let snapshot = fixture
        .store
        .control_issuance_snapshot(&issue_work)
        .unwrap();
    let issued = issued_record(&issue_work, &snapshot, &fixture.authorization_signer);
    assert_eq!(
        fixture
            .store
            .record_and_link_control_issuance_or_recover(issue_work, &issued)
            .unwrap(),
        ControlIssuanceCommitOutcome::Committed
    );

    let mut rotated = fixture.authority.clone();
    rotated.principal_registry = AuthorityDomainState {
        root: Digest32::sha256(b"pg-v13-consume-finalization-authority-loss"),
        epoch: fixture.authority.principal_registry.epoch + 1,
        activation_id: Uuid::new_v4(),
    };
    fixture
        .store
        .compare_and_activate_authority(receipt.scope(), Some(&fixture.authority), &rotated)
        .unwrap();
    let consume_request = claim_request(
        "pg-v13-consume-finalize-consumer",
        ControlWorkerRole::Consumer,
        Uuid::new_v4(),
    );
    match fixture
        .store
        .claim_next_control_work_or_recover(&consume_request)
        .unwrap()
    {
        ControlWorkClaimOutcome::WorkFinalized(finalized) => {
            assert_eq!(finalized.phase(), ControlWorkPhase::Consume);
            assert_eq!(
                finalized.reason(),
                ControlWorkFinalizationReason::AuthorityChanged
            );
        }
        other => panic!("expected fail-closed CONSUME, got {other:?}"),
    }
    assert_eq!(
        fixture
            .store
            .control_status(receipt.scope(), receipt.receipt_id())
            .unwrap()
            .status(),
        ControlStatusCode::FailedClosed
    );

    let key = ConsumeKey {
        scope: issued.scope(),
        transaction_id: issued.transaction_id,
        authorization_id: issued.authorization().authorization_id,
    };
    let tampered = Client::connect(&fixture.url, NoTls)
        .unwrap()
        .execute(
            "UPDATE public.accordlock_issued_authorizations
                SET state='CONSUMED',consumed_at=clock_timestamp()
              WHERE tenant=$1 AND environment=$2 AND authorization_id=$3 AND transaction_id=$4",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
            ],
        )
        .unwrap();
    assert_eq!(tampered, 1);
    assert!(matches!(
        fixture
            .store
            .control_status(receipt.scope(), receipt.receipt_id()),
        Err(StateError::InvalidRecord(message))
            if message.contains("fail-closed CONSUME history")
    ));
    assert!(matches!(
        fixture
            .store
            .claim_next_control_work_or_recover(&consume_request),
        Err(StateError::InvalidRecord(message))
            if message.contains("fail-closed CONSUME history")
    ));
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL"]
fn postgres_v13_exact_claim_recovery_is_fenced_by_both_high_waters() {
    let _serial = serial_postgres_test();
    let fixture = PgControlFixture::new();
    let wire = fixture.signed_wire(Uuid::new_v4(), Uuid::new_v4());
    fixture.accept(&wire);
    let claim_id = Uuid::new_v4();
    let request = claim_request(
        "pg-v13-hwm-evaluator",
        ControlWorkerRole::Evaluator,
        claim_id,
    );
    match fixture
        .store
        .claim_next_control_work_or_recover(&request)
        .unwrap()
    {
        ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Evaluate(_)) => {}
        other => panic!("expected first EVALUATE claim, got {other:?}"),
    }
    let recovered_work = match fixture
        .store
        .claim_next_control_work_or_recover(&request)
        .unwrap()
    {
        ControlWorkClaimOutcome::Recovered(ClaimedControlWork::Evaluate(work)) => work,
        other => panic!("expected exact active-claim recovery, got {other:?}"),
    };

    let rolled_back_floor = database_time(&fixture.url).saturating_add(10);
    let mut client = Client::connect(&fixture.url, NoTls).unwrap();
    let updated_scope = client
        .execute(
            "UPDATE public.accordlock_time_high_water
                SET observed_unix_s=$3,updated_at=clock_timestamp()
              WHERE tenant=$1 AND environment=$2",
            &[&fixture.tenant, &CONTROL_ENVIRONMENT, &rolled_back_floor],
        )
        .unwrap();
    let updated_ingress = client
        .execute(
            "UPDATE public.accordlock_ingress_replay_scopes
                SET observed_unix_s=$2,updated_at=clock_timestamp()
              WHERE replay_scope=$1",
            &[&fixture.audience, &rolled_back_floor],
        )
        .unwrap();
    assert_eq!(updated_scope, 1);
    assert_eq!(updated_ingress, 1);
    let rollback_recovery = fixture.store.claim_next_control_work_or_recover(&request);
    assert!(
        matches!(
            rollback_recovery,
        Err(StateError::ClockRollback { high_water, .. })
            if high_water == rolled_back_floor
        ),
        "expected dual-HWM rollback rejection, got {rollback_recovery:?}"
    );
    while database_time(&fixture.url) < rolled_back_floor {
        thread::sleep(Duration::from_secs(1));
    }
    let denial =
        signed_evaluation_with_outcome(&recovered_work, &fixture.evaluator, DecisionOutcome::Deny);
    let decision = fixture
        .store
        .record_control_evaluation(recovered_work, &denial, &fixture.evaluator.verifier())
        .unwrap();
    assert_eq!(decision.control_outcome(), ControlOutcome::Deny);
    assert_eq!(decision.reason(), ControlDecisionReason::KernelDeny);
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL and waits for one 30s lease"]
fn postgres_v13_takeover_requires_real_lease_expiry_and_increases_fence() {
    let _serial = serial_postgres_test();
    let fixture = PgControlFixture::new();
    let wire = fixture.signed_wire(Uuid::new_v4(), Uuid::new_v4());
    fixture.accept(&wire);
    let first_id = Uuid::new_v4();
    let first_request = claim_request("pg-v13-takeover-a", ControlWorkerRole::Evaluator, first_id);
    let (first_fence, lease_until) = match fixture
        .store
        .claim_next_control_work_or_recover(&first_request)
        .unwrap()
    {
        ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Evaluate(work)) => {
            (work.lease().fence(), work.lease().lease_until())
        }
        other => panic!("expected first EVALUATE claim, got {other:?}"),
    };
    let second_request = claim_request(
        "pg-v13-takeover-b",
        ControlWorkerRole::Evaluator,
        Uuid::new_v4(),
    );
    let first_takeover_attempt = fixture
        .store
        .claim_next_control_work_or_recover(&second_request)
        .unwrap();
    let (second_fence, takeover_work) = match first_takeover_attempt {
        ControlWorkClaimOutcome::NoWork => {
            let remaining = lease_until.saturating_sub(database_time(&fixture.url));
            assert!(
                remaining <= 30,
                "unexpected control lease duration {remaining}"
            );
            thread::sleep(Duration::from_secs(
                u64::try_from(remaining.saturating_add(1)).unwrap(),
            ));
            match fixture
                .store
                .claim_next_control_work_or_recover(&second_request)
                .unwrap()
            {
                ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Evaluate(work)) => {
                    assert!(work.lease().claimed_at() >= lease_until);
                    (work.lease().fence(), work)
                }
                other => panic!("expected fenced takeover, got {other:?}"),
            }
        }
        ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Evaluate(work)) => {
            // A heavily contended CI host may suspend this test for the whole
            // lease. Even then, state must prove the takeover was not early.
            assert!(work.lease().claimed_at() >= lease_until);
            (work.lease().fence(), work)
        }
        other => panic!("unexpected pre-expiry takeover result: {other:?}"),
    };
    assert!(second_fence > first_fence);
    let stale = fixture
        .store
        .claim_next_control_work_or_recover(&first_request);
    assert!(
        matches!(stale, Err(StateError::ControlWorkMismatch)),
        "stale pre-takeover claim unexpectedly recovered: {stale:?}"
    );
    let denial =
        signed_evaluation_with_outcome(&takeover_work, &fixture.evaluator, DecisionOutcome::Deny);
    let decision = fixture
        .store
        .record_control_evaluation(takeover_work, &denial, &fixture.evaluator.verifier())
        .unwrap();
    assert_eq!(decision.control_outcome(), ControlOutcome::Deny);
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL"]
fn postgres_v13_prekernel_decision_and_evaluation_are_mutually_exclusive() {
    let _serial = serial_postgres_test();
    let fixture = PgControlFixture::new();
    let wire = fixture.signed_wire(Uuid::new_v4(), Uuid::new_v4());
    let receipt = fixture.accept(&wire);
    let claim_id = Uuid::new_v4();
    let request = claim_request(
        "pg-v13-prekernel-exclusion",
        ControlWorkerRole::Evaluator,
        claim_id,
    );
    let evaluation_work = match fixture
        .store
        .claim_next_control_work_or_recover(&request)
        .unwrap()
    {
        ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Evaluate(work)) => work,
        other => panic!("expected EVALUATE work, got {other:?}"),
    };
    let submission_id = evaluation_work.lease().submission_id();
    let evaluated_at = evaluation_work.lease().claimed_at();
    let evaluation_id = Uuid::new_v4();
    let decision_id = Uuid::new_v4();
    let evaluation_json = serde_json::json!({});
    let evaluator_key = vec![0x5a_u8; 32];
    let evaluation_commitment = Digest32::sha256(b"pg-v13-orphan-evaluation").to_string();
    let decision_commitment = Digest32::sha256(b"pg-v13-prekernel-decision").to_string();

    let mut client = Client::connect(&fixture.url, NoTls).unwrap();
    let mut evaluation_first = client.transaction().unwrap();
    evaluation_first
        .execute(
            "INSERT INTO public.accordlock_control_evaluations
                    (evaluation_id,submission_id,claim_id,claim_phase,evaluation_nonce,
                     kernel_outcome,signed_evaluation_json,evaluator_key_id,
                     evaluator_public_key,evaluation_commitment,evaluated_at)
             VALUES ($1,$2,$3,'EVALUATE',$4,'ALLOW',$5,'test-evaluator',$6,$7,$8)",
            &[
                &evaluation_id,
                &submission_id,
                &claim_id,
                &evaluation_work.evaluation_nonce(),
                &evaluation_json,
                &evaluator_key,
                &evaluation_commitment,
                &evaluated_at,
            ],
        )
        .unwrap();
    assert!(
        evaluation_first
            .execute(
                "INSERT INTO public.accordlock_control_decisions
                        (decision_id,submission_id,claim_id,claim_phase,evaluation_id,
                         kernel_outcome,control_outcome,reason,selected_grant_id,
                         tenant,environment,decided_at,decision_commitment)
                 VALUES ($1,$2,$3,'EVALUATE',NULL,NULL,'DENY','AUTHORITY_CHANGED',
                         NULL,$4,$5,$6,$7)",
                &[
                    &decision_id,
                    &submission_id,
                    &claim_id,
                    &fixture.tenant,
                    &CONTROL_ENVIRONMENT,
                    &evaluated_at,
                    &decision_commitment,
                ],
            )
            .is_err(),
        "a pre-kernel decision was grafted onto an existing signed evaluation"
    );
    evaluation_first.rollback().unwrap();

    let mut decision_first = client.transaction().unwrap();
    decision_first
        .execute(
            "INSERT INTO public.accordlock_control_decisions
                    (decision_id,submission_id,claim_id,claim_phase,evaluation_id,
                     kernel_outcome,control_outcome,reason,selected_grant_id,
                     tenant,environment,decided_at,decision_commitment)
             VALUES ($1,$2,$3,'EVALUATE',NULL,NULL,'DENY','AUTHORITY_CHANGED',
                     NULL,$4,$5,$6,$7)",
            &[
                &decision_id,
                &submission_id,
                &claim_id,
                &fixture.tenant,
                &CONTROL_ENVIRONMENT,
                &evaluated_at,
                &decision_commitment,
            ],
        )
        .unwrap();
    assert!(
        decision_first
            .execute(
                "INSERT INTO public.accordlock_control_evaluations
                        (evaluation_id,submission_id,claim_id,claim_phase,evaluation_nonce,
                         kernel_outcome,signed_evaluation_json,evaluator_key_id,
                         evaluator_public_key,evaluation_commitment,evaluated_at)
                 VALUES ($1,$2,$3,'EVALUATE',$4,'ALLOW',$5,'test-evaluator',$6,$7,$8)",
                &[
                    &evaluation_id,
                    &submission_id,
                    &claim_id,
                    &evaluation_work.evaluation_nonce(),
                    &evaluation_json,
                    &evaluator_key,
                    &evaluation_commitment,
                    &evaluated_at,
                ],
            )
            .is_err(),
        "a signed evaluation was grafted onto an existing pre-kernel decision"
    );
    decision_first.rollback().unwrap();

    let denial =
        signed_evaluation_with_outcome(&evaluation_work, &fixture.evaluator, DecisionOutcome::Deny);
    let decision = fixture
        .store
        .record_control_evaluation(evaluation_work, &denial, &fixture.evaluator.verifier())
        .unwrap();
    assert_eq!(decision.control_outcome(), ControlOutcome::Deny);
    assert_eq!(decision.reason(), ControlDecisionReason::KernelDeny);
    assert_eq!(
        fixture
            .store
            .control_status(receipt.scope(), receipt.receipt_id())
            .unwrap()
            .status(),
        ControlStatusCode::ControlDenied
    );
    match fixture
        .store
        .claim_next_control_work_or_recover(&request)
        .unwrap()
    {
        ControlWorkClaimOutcome::PhaseCompleted(completion) => {
            assert_eq!(completion.phase(), ControlWorkPhase::Evaluate);
            assert_eq!(completion.consume_key(), None);
        }
        other => panic!("expected signed EVALUATE completion recovery, got {other:?}"),
    }
    assert!(matches!(
        fixture
            .store
            .accept_control_submission_or_recover(fixture.verify_wire(&wire))
            .unwrap(),
        ControlSubmissionIntakeOutcome::Recovered(_)
    ));

    // A committed evaluation-only tuple is not a recoverable historical
    // result. Every read/retry path rejects it without sampling or advancing
    // either durable clock floor.
    let corrupt_fixture = PgControlFixture::new();
    let corrupt_wire = corrupt_fixture.signed_wire(Uuid::new_v4(), Uuid::new_v4());
    let corrupt_receipt = corrupt_fixture.accept(&corrupt_wire);
    let corrupt_request = claim_request(
        "pg-v13-prekernel-partial",
        ControlWorkerRole::Evaluator,
        Uuid::new_v4(),
    );
    let corrupt_work = match corrupt_fixture
        .store
        .claim_next_control_work_or_recover(&corrupt_request)
        .unwrap()
    {
        ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Evaluate(work)) => work,
        other => panic!("expected corrupt-tuple EVALUATE work, got {other:?}"),
    };
    let recovery_probe = IngressRecoveryProbe::parse_bytes(&corrupt_wire).unwrap();
    let frozen = corrupt_fixture
        .store
        .control_recovery_verifier(&recovery_probe)
        .unwrap()
        .unwrap();
    let historical = recovery_probe.verify_historical(&frozen).unwrap();
    let corrupt_evaluation_id = Uuid::new_v4();
    client
        .execute(
            "INSERT INTO public.accordlock_control_evaluations
                    (evaluation_id,submission_id,claim_id,claim_phase,evaluation_nonce,
                     kernel_outcome,signed_evaluation_json,evaluator_key_id,
                     evaluator_public_key,evaluation_commitment,evaluated_at)
             VALUES ($1,$2,$3,'EVALUATE',$4,'ALLOW',$5,'test-evaluator',$6,$7,$8)",
            &[
                &corrupt_evaluation_id,
                &corrupt_work.lease().submission_id(),
                &corrupt_work.lease().claim_id(),
                &corrupt_work.evaluation_nonce(),
                &evaluation_json,
                &evaluator_key,
                &Digest32::sha256(b"pg-v13-committed-orphan-evaluation").to_string(),
                &corrupt_work.lease().claimed_at(),
            ],
        )
        .unwrap();
    let high_waters_before = control_high_waters(
        &corrupt_fixture.url,
        corrupt_receipt.scope(),
        &corrupt_fixture.audience,
    );
    assert!(matches!(
        corrupt_fixture
            .store
            .control_status(corrupt_receipt.scope(), corrupt_receipt.receipt_id()),
        Err(StateError::InvalidRecord(_))
    ));
    assert!(matches!(
        corrupt_fixture
            .store
            .recover_control_submission(&historical),
        Err(StateError::InvalidRecord(_))
    ));
    assert!(matches!(
        corrupt_fixture
            .store
            .claim_next_control_work_or_recover(&corrupt_request),
        Err(StateError::InvalidRecord(_))
    ));
    assert_eq!(
        control_high_waters(
            &corrupt_fixture.url,
            corrupt_receipt.scope(),
            &corrupt_fixture.audience,
        ),
        high_waters_before
    );

    // Restore the deliberately corrupted test row without weakening the live
    // schema after this transaction, then close the claimed queue normally.
    let mut cleanup = client.transaction().unwrap();
    cleanup
        .batch_execute(
            "ALTER TABLE public.accordlock_control_evaluations
                 DISABLE TRIGGER accordlock_control_evaluations_append_only;",
        )
        .unwrap();
    cleanup
        .execute(
            "DELETE FROM public.accordlock_control_evaluations WHERE evaluation_id=$1",
            &[&corrupt_evaluation_id],
        )
        .unwrap();
    cleanup
        .batch_execute(
            "ALTER TABLE public.accordlock_control_evaluations
                 ENABLE TRIGGER accordlock_control_evaluations_append_only;",
        )
        .unwrap();
    cleanup.commit().unwrap();
    let denial = signed_evaluation_with_outcome(
        &corrupt_work,
        &corrupt_fixture.evaluator,
        DecisionOutcome::Deny,
    );
    let decision = corrupt_fixture
        .store
        .record_control_evaluation(corrupt_work, &denial, &corrupt_fixture.evaluator.verifier())
        .unwrap();
    assert_eq!(decision.control_outcome(), ControlOutcome::Deny);
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL"]
fn postgres_v13_evaluate_claim_has_one_fenced_winner_across_stores() {
    let _serial = serial_postgres_test();
    let fixture = PgControlFixture::new();
    let wire = fixture.signed_wire(Uuid::new_v4(), Uuid::new_v4());
    let receipt = fixture.accept(&wire);
    let barrier = Arc::new(Barrier::new(4));
    let requests = (0..4)
        .map(|index| {
            claim_request(
                &format!("pg-v13-race-evaluator-{index}"),
                ControlWorkerRole::Evaluator,
                Uuid::new_v4(),
            )
        })
        .collect::<Vec<_>>();
    let results = thread::scope(|scope| {
        requests
            .into_iter()
            .map(|request| {
                let barrier = Arc::clone(&barrier);
                let url = fixture.url.clone();
                scope.spawn(move || {
                    let store = PostgresStore::new(url);
                    barrier.wait();
                    let result = store.claim_next_control_work_or_recover(&request);
                    (request, result)
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });

    let mut winner = None;
    let mut no_work = 0;
    for (request, result) in results {
        match result.unwrap() {
            ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Evaluate(work)) => {
                assert!(winner.replace((request, work)).is_none());
            }
            ControlWorkClaimOutcome::NoWork => no_work += 1,
            other => panic!("unexpected concurrent EVALUATE claim result: {other:?}"),
        }
    }
    assert_eq!(no_work, 3);
    let (winning_request, winning_work) = winner.unwrap();
    let row = Client::connect(&fixture.url, NoTls)
        .unwrap()
        .query_one(
            "SELECT queue.active_claim_id,claim.fence,
                    (SELECT count(*) FROM public.accordlock_control_work_claims
                      WHERE submission_id=$1) AS claim_count
               FROM public.accordlock_control_work_queue AS queue
               JOIN public.accordlock_control_work_claims AS claim
                 ON claim.submission_id=queue.submission_id
                AND claim.claim_id=queue.active_claim_id
              WHERE queue.submission_id=$1",
            &[&receipt.submission_id()],
        )
        .unwrap();
    assert_eq!(
        row.get::<_, Uuid>("active_claim_id"),
        winning_request.claim_id()
    );
    assert_eq!(row.get::<_, i64>("claim_count"), 1);
    assert_eq!(
        u64::try_from(row.get::<_, i64>("fence")).unwrap(),
        winning_work.lease().fence()
    );

    let denial =
        signed_evaluation_with_outcome(&winning_work, &fixture.evaluator, DecisionOutcome::Deny);
    let decision = fixture
        .store
        .record_control_evaluation(winning_work, &denial, &fixture.evaluator.verifier())
        .unwrap();
    assert_eq!(decision.control_outcome(), ControlOutcome::Deny);
}

#[test]
#[ignore = "helper process that exits immediately after a durable v13 phase commit"]
fn postgres_v13_commit_response_loss_child_process() {
    let Ok(target_phase) = env::var(COMMIT_LOSS_PHASE_ENV) else {
        return;
    };
    let fixture = PgControlFixture::new();
    let wire = fixture.signed_wire(Uuid::new_v4(), Uuid::new_v4());
    fixture.accept(&wire);
    let evaluate_claim_id =
        Uuid::parse_str(&env::var(COMMIT_LOSS_EVALUATE_CLAIM_ENV).unwrap()).unwrap();
    let issue_claim_id = Uuid::parse_str(&env::var(COMMIT_LOSS_ISSUE_CLAIM_ENV).unwrap()).unwrap();
    let consume_claim_id =
        Uuid::parse_str(&env::var(COMMIT_LOSS_CONSUME_CLAIM_ENV).unwrap()).unwrap();

    let evaluation_work = match fixture
        .store
        .claim_next_control_work_or_recover(&claim_request(
            "pg-v13-loss-evaluator",
            ControlWorkerRole::Evaluator,
            evaluate_claim_id,
        ))
        .unwrap()
    {
        ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Evaluate(work)) => work,
        other => panic!("commit-loss child expected EVALUATE work, got {other:?}"),
    };
    let evaluation = signed_evaluation(&evaluation_work, &fixture.evaluator);
    let decision = fixture
        .store
        .record_control_evaluation(evaluation_work, &evaluation, &fixture.evaluator.verifier())
        .unwrap();
    assert_eq!(decision.control_outcome(), ControlOutcome::Allow);
    if target_phase == "EVALUATE" {
        std::process::exit(COMMIT_LOSS_EXIT_CODE);
    }

    let issue_work = match fixture
        .store
        .claim_next_control_work_or_recover(&claim_request(
            "pg-v13-loss-issuer",
            ControlWorkerRole::Issuer,
            issue_claim_id,
        ))
        .unwrap()
    {
        ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Issue(work)) => work,
        other => panic!("commit-loss child expected ISSUE work, got {other:?}"),
    };
    let snapshot = fixture
        .store
        .control_issuance_snapshot(&issue_work)
        .unwrap();
    let issued = issued_record(&issue_work, &snapshot, &fixture.authorization_signer);
    assert_eq!(
        fixture
            .store
            .record_and_link_control_issuance_or_recover(issue_work, &issued)
            .unwrap(),
        ControlIssuanceCommitOutcome::Committed
    );
    if target_phase == "ISSUE" {
        std::process::exit(COMMIT_LOSS_EXIT_CODE);
    }

    let consume_work = match fixture
        .store
        .claim_next_control_work_or_recover(&claim_request(
            "pg-v13-loss-consumer",
            ControlWorkerRole::Consumer,
            consume_claim_id,
        ))
        .unwrap()
    {
        ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Consume(work)) => work,
        other => panic!("commit-loss child expected CONSUME work, got {other:?}"),
    };
    assert!(matches!(
        fixture
            .store
            .consume_and_link_control_or_recover(consume_work)
            .unwrap(),
        ControlConsumptionCommitOutcome::Committed(_)
    ));
    assert_eq!(target_phase, "CONSUME");
    std::process::exit(COMMIT_LOSS_EXIT_CODE);
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL and child-process execution"]
fn postgres_v13_phase_commits_recover_exactly_after_process_response_loss() {
    let _serial = serial_postgres_test();
    let url = env::var("ACCORDLOCK_TEST_POSTGRES_URL").unwrap();
    PostgresStore::new(url.clone()).migrate().unwrap();
    let executable = env::current_exe().unwrap();

    for (target_phase, expected_phase, worker, role) in [
        (
            "EVALUATE",
            ControlWorkPhase::Evaluate,
            "pg-v13-loss-evaluator",
            ControlWorkerRole::Evaluator,
        ),
        (
            "ISSUE",
            ControlWorkPhase::Issue,
            "pg-v13-loss-issuer",
            ControlWorkerRole::Issuer,
        ),
        (
            "CONSUME",
            ControlWorkPhase::Consume,
            "pg-v13-loss-consumer",
            ControlWorkerRole::Consumer,
        ),
    ] {
        let evaluate_claim_id = Uuid::new_v4();
        let issue_claim_id = Uuid::new_v4();
        let consume_claim_id = Uuid::new_v4();
        let target_claim_id = match expected_phase {
            ControlWorkPhase::Evaluate => evaluate_claim_id,
            ControlWorkPhase::Issue => issue_claim_id,
            ControlWorkPhase::Consume => consume_claim_id,
            ControlWorkPhase::Done => unreachable!(),
        };
        // The child emits no success artifact through IPC. It exits
        // immediately after the state API reports the database commit, so the
        // parent sees only an abnormal process status and must recover from DB.
        let output = Command::new(&executable)
            .arg("postgres_v13_commit_response_loss_child_process")
            .arg("--ignored")
            .arg("--exact")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env("ACCORDLOCK_TEST_POSTGRES_URL", &url)
            .env(COMMIT_LOSS_PHASE_ENV, target_phase)
            .env(
                COMMIT_LOSS_EVALUATE_CLAIM_ENV,
                evaluate_claim_id.to_string(),
            )
            .env(COMMIT_LOSS_ISSUE_CLAIM_ENV, issue_claim_id.to_string())
            .env(COMMIT_LOSS_CONSUME_CLAIM_ENV, consume_claim_id.to_string())
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(COMMIT_LOSS_EXIT_CODE),
            "commit-loss child did not exit at its post-commit boundary: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let row = Client::connect(&url, NoTls)
            .unwrap()
            .query_one(
                "SELECT submission.submission_id,submission.tenant,
                        submission.environment,submission.replay_scope,
                        (SELECT count(*)
                           FROM public.accordlock_control_phase_completions AS completion
                          WHERE completion.claim_id=$1) AS completion_count
                   FROM public.accordlock_control_work_claims AS claim
                   JOIN public.accordlock_control_submissions AS submission
                     ON submission.submission_id=claim.submission_id
                  WHERE claim.claim_id=$1",
                &[&target_claim_id],
            )
            .unwrap();
        let submission_id: Uuid = row.get("submission_id");
        let scope = Scope::new(
            row.get::<_, String>("tenant"),
            row.get::<_, String>("environment"),
        )
        .unwrap();
        let replay_scope: String = row.get("replay_scope");
        assert_eq!(row.get::<_, i64>("completion_count"), 1);
        let high_waters_before = control_high_waters(&url, &scope, &replay_scope);
        let artifacts_before = control_artifact_counts(&url, submission_id);
        let restarted = PostgresStore::new(url.clone());
        restarted.migrate().unwrap();
        for _ in 0..2 {
            match restarted
                .claim_next_control_work_or_recover(&claim_request(worker, role, target_claim_id))
                .unwrap()
            {
                ControlWorkClaimOutcome::PhaseCompleted(completion) => {
                    assert_eq!(completion.submission_id(), submission_id);
                    assert_eq!(completion.claim_id(), target_claim_id);
                    assert_eq!(completion.phase(), expected_phase);
                    assert_eq!(
                        completion.consume_key().is_some(),
                        expected_phase == ControlWorkPhase::Consume
                    );
                }
                other => panic!(
                    "expected exact {expected_phase:?} recovery after process loss, got {other:?}"
                ),
            }
        }
        assert_eq!(
            control_artifact_counts(&url, submission_id),
            artifacts_before
        );
        assert_eq!(
            control_high_waters(&url, &scope, &replay_scope),
            high_waters_before
        );
        let completion_count: i64 = Client::connect(&url, NoTls)
            .unwrap()
            .query_one(
                "SELECT count(*) AS completion_count
                   FROM public.accordlock_control_phase_completions
                  WHERE claim_id=$1",
                &[&target_claim_id],
            )
            .unwrap()
            .get("completion_count");
        assert_eq!(completion_count, 1);

        // Leave no downstream READY work behind for another test process.
        // The signing identity is the deterministic fixture identity used by
        // the child; all grants and authority remain server-selected state.
        if expected_phase == ControlWorkPhase::Evaluate {
            let issue_work = match restarted
                .claim_next_control_work_or_recover(&claim_request(
                    "pg-v13-loss-issuer",
                    ControlWorkerRole::Issuer,
                    issue_claim_id,
                ))
                .unwrap()
            {
                ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Issue(work)) => work,
                other => panic!("cleanup expected ISSUE work, got {other:?}"),
            };
            let snapshot = restarted.control_issuance_snapshot(&issue_work).unwrap();
            let signer = SigningIdentity::from_seed("pg-v13-authorization", [0x73; 32]);
            let issued = issued_record(&issue_work, &snapshot, &signer);
            assert_eq!(
                restarted
                    .record_and_link_control_issuance_or_recover(issue_work, &issued)
                    .unwrap(),
                ControlIssuanceCommitOutcome::Committed
            );
        }
        if expected_phase != ControlWorkPhase::Consume {
            let consume_work = match restarted
                .claim_next_control_work_or_recover(&claim_request(
                    "pg-v13-loss-consumer",
                    ControlWorkerRole::Consumer,
                    consume_claim_id,
                ))
                .unwrap()
            {
                ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Consume(work)) => work,
                other => panic!("cleanup expected CONSUME work, got {other:?}"),
            };
            assert!(matches!(
                restarted
                    .consume_and_link_control_or_recover(consume_work)
                    .unwrap(),
                ControlConsumptionCommitOutcome::Committed(_)
            ));
        }
    }
}
