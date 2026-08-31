#![allow(clippy::panic, clippy::too_many_lines, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::env;
use std::sync::{Mutex, MutexGuard, OnceLock};

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
    ClaimedControlWork, ConsumeKey, ControlConsumptionCommitOutcome, ControlIssuanceCommitOutcome,
    ControlPlaneState, ControlSubmissionIntakeOutcome, ControlSubmissionReceipt,
    ControlWorkClaimOutcome, ControlWorkClaimRequest, ControlWorkerRole,
    DispatchAcquisitionAuthority, DispatchAcquisitionDisposition, DispatchAcquisitionOutcome,
    DispatchAcquisitionRequest, DispatchDeadlinePolicy, GrantRegistration, InMemoryStore,
    IssuanceSnapshot, IssuedAuthorizationRecord, PostgresStore, Scope, StateError,
    TransactionalState,
};
use postgres::{Client, Error as PostgresError, NoTls};
use uuid::Uuid;

const TEST_DATABASE_URL_ENV: &str = "ACCORDLOCK_TEST_POSTGRES_URL";
const CONTROL_ENVIRONMENT: &str = "test";

fn serial_postgres_test() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn test_database_url() -> String {
    env::var(TEST_DATABASE_URL_ENV)
        .unwrap_or_else(|_| panic!("{TEST_DATABASE_URL_ENV} is required"))
}

fn configured_store() -> (String, PostgresStore) {
    let url = test_database_url();
    let store = PostgresStore::new(url.clone());
    store.migrate().unwrap();
    (url, store)
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

fn postgres_message(error: &PostgresError) -> &str {
    error
        .as_db_error()
        .map_or("", postgres::error::DbError::message)
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

fn proposal(tenant: &str, audience: &str, request_id: Uuid) -> AgentProposal {
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
            image_digest: Digest32::sha256(b"v14-guard-image"),
            cluster_identity: "cluster-a".to_owned(),
            namespace: "payments".to_owned(),
            deployment: "payments".to_owned(),
            deployment_uid: format!("deployment-{tenant}"),
            container: "app".to_owned(),
            container_index: 0,
            prior_image_digest: Digest32::sha256(b"v14-guard-prior-image"),
            resource_version: "1001".to_owned(),
            prior_projection_hash: Digest32::sha256(b"v14-guard-projection"),
            prior_transaction_annotation: None,
            prior_authorization_annotation: None,
            prior_operation_hash_annotation: None,
        },
    }
}

struct ControlFixture {
    url: String,
    store: PostgresStore,
    tenant: String,
    audience: String,
    authenticator: IngressAuthenticator<MemoryReplayGuard>,
    ingress_signer: SigningIdentity,
    evaluator: SigningIdentity,
    authorization_signer: SigningIdentity,
}

impl ControlFixture {
    fn new() -> Self {
        let (url, store) = configured_store();
        let suffix = Uuid::new_v4().simple().to_string();
        let tenant = format!("v14-guards-{suffix}");
        let audience = format!("accordlock-executor:v14-guards-{suffix}");
        let now = database_time(&url);
        let ingress_signer = SigningIdentity::from_seed("pg-v14-guard-ingress", [0x81; 32]);
        let evaluator = SigningIdentity::from_seed("pg-v14-guard-evaluator", [0x82; 32]);
        let authorization_signer =
            SigningIdentity::from_seed("pg-v14-guard-authorization", [0x83; 32]);
        let ingress_key = RegisteredIngressKey {
            key_id: ingress_signer.key_id().to_owned(),
            public_key: ingress_signer.public_key_bytes(),
            tenant: tenant.clone(),
            actor: "workload-a".to_owned(),
            allowed_audiences: BTreeSet::from([audience.clone()]),
            not_before: now.saturating_sub(300),
            expires_at: now.saturating_add(3_600),
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
            cluster_identity: "cluster-a".to_owned(),
            namespace: "payments".to_owned(),
            deployment_uid: format!("deployment-{tenant}"),
            container: "app".to_owned(),
            image_repository: "registry.example/acme/payments".to_owned(),
            not_before: now.saturating_sub(300),
            expires_at: now.saturating_add(3_600),
            maximum_uses: 8,
        };
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
        let grant = GrantRegistration {
            environment: CONTROL_ENVIRONMENT.to_owned(),
            grant: capability,
            authority: authority.clone(),
            dispatch_deadline_policy: DispatchDeadlinePolicy {
                max_dispatch_delay_seconds: 180,
                profile_hard_cap: now.saturating_add(3_000),
                immutable_dependency_expiries: vec![now.saturating_add(2_400)],
            },
        };
        let scope = Scope::new(&tenant, CONTROL_ENVIRONMENT).unwrap();
        store
            .compare_and_activate_authority(&scope, None, &authority)
            .unwrap();
        store.register_grant(&grant).unwrap();

        Self {
            url,
            store,
            tenant,
            audience,
            authenticator,
            ingress_signer,
            evaluator,
            authorization_signer,
        }
    }

    fn signed_wire(&self) -> Vec<u8> {
        let now = database_time(&self.url);
        let request = sign_ingress_request(
            IngressClaims {
                schema_version: INGRESS_SCHEMA_VERSION,
                audience: self.audience.clone(),
                issued_at: now.saturating_sub(1),
                expires_at: now.saturating_add(600),
                nonce: Uuid::new_v4(),
                proposal: proposal(&self.tenant, &self.audience, Uuid::new_v4()),
            },
            &self.ingress_signer,
        )
        .unwrap();
        serde_json::to_vec(&request).unwrap()
    }

    fn verify_wire(&self, wire: &[u8]) -> StaticallyVerifiedIngressSubmission {
        self.authenticator
            .verify_durable_static(IngressRecoveryProbe::parse_bytes(wire).unwrap())
            .unwrap()
    }

    fn accept(&self) -> ControlSubmissionReceipt {
        let wire = self.signed_wire();
        match self
            .store
            .accept_control_submission_or_recover(self.verify_wire(&wire))
            .unwrap()
        {
            ControlSubmissionIntakeOutcome::Fresh(receipt) => receipt,
            other => panic!("expected fresh control intake, got {other:?}"),
        }
    }
}

fn claim_request(worker: &str, role: ControlWorkerRole) -> ControlWorkClaimRequest {
    ControlWorkClaimRequest::new(worker, role, Uuid::new_v4()).unwrap()
}

fn signed_evaluation(
    work: &accordlock_state::ControlEvaluationWork,
    evaluator: &SigningIdentity,
) -> SignedEvaluation {
    let attestation = EvaluationAttestation {
        schema_version: EVALUATION_ATTESTATION_SCHEMA_VERSION,
        request_id: work.proposal().request_id,
        evaluation_nonce: work.evaluation_nonce(),
        tenant: work.caller_tenant().to_owned(),
        actor: work.caller_actor().to_owned(),
        evaluated_at: work.lease().claimed_at(),
        outcome: DecisionOutcome::Allow,
        reasons: vec![ReasonCode::Allowed],
        template_hash: canonical_hash(&work.proposal().template).unwrap(),
        evidence_root: Digest32::sha256(b"v14-guard-evidence"),
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

fn complete_control_dispatch(fixture: &ControlFixture) -> (ControlSubmissionReceipt, ConsumeKey) {
    let receipt = fixture.accept();
    let evaluation_work = match fixture
        .store
        .claim_next_control_work_or_recover(&claim_request(
            "pg-v14-guard-evaluator",
            ControlWorkerRole::Evaluator,
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
            "pg-v14-guard-issuer",
            ControlWorkerRole::Issuer,
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
            "pg-v14-guard-consumer",
            ControlWorkerRole::Consumer,
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

fn append_broker_field(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&u64::try_from(value.len()).unwrap().to_be_bytes());
    target.extend_from_slice(value);
}

fn broker_create_request_commitment(
    entry_id: Uuid,
    authority: &DispatchAcquisitionAuthority,
    route_commitment: Digest32,
) -> Digest32 {
    let token = authority.claim();
    let key = token.key();
    let physical = token.physical_resource();
    let bound_secret_name = format!("accordlock-{}", key.transaction_id.simple());
    let mut bytes = b"accordlock:v2:broker-operation-request\0".to_vec();
    append_broker_field(&mut bytes, key.scope.tenant.as_bytes());
    append_broker_field(&mut bytes, key.scope.environment.as_bytes());
    bytes.extend_from_slice(key.transaction_id.as_bytes());
    bytes.extend_from_slice(key.authorization_id.as_bytes());
    bytes.extend_from_slice(entry_id.as_bytes());
    bytes.extend_from_slice(token.claim_id().as_bytes());
    bytes.extend_from_slice(&token.fence().to_be_bytes());
    bytes.extend_from_slice(token.state_instance_id().as_bytes());
    bytes.extend_from_slice(authority.acquisition_id().as_bytes());
    bytes.extend_from_slice(&authority.lease_fence().to_be_bytes());
    append_broker_field(&mut bytes, physical.cluster_identity().as_bytes());
    append_broker_field(&mut bytes, physical.namespace().as_bytes());
    append_broker_field(&mut bytes, physical.deployment_uid().as_bytes());
    bytes.extend_from_slice(route_commitment.as_bytes());
    append_broker_field(&mut bytes, bound_secret_name.as_bytes());
    bytes.push(0); // no Secret UID is bound before CREATE commits
    bytes.push(1); // CREATE_SECRET
    bytes.push(0); // no credential lifetime policy for Secret creation
    Digest32::sha256(&bytes)
}

fn insert_control_broker_in_flight(
    url: &str,
    authority: &DispatchAcquisitionAuthority,
    route: [u8; 32],
) -> Uuid {
    let token = authority.claim();
    let key = token.key();
    let physical = token.physical_resource();
    let entry_id = Uuid::new_v4();
    let route_commitment = Digest32::from_bytes(route);
    let request_commitment =
        broker_create_request_commitment(entry_id, authority, route_commitment);
    let bound_secret_name = format!("accordlock-{}", key.transaction_id.simple());
    let fence = i64::try_from(token.fence()).unwrap();
    let lease_fence = i64::try_from(authority.lease_fence()).unwrap();
    let prepared_at = authority.acquired_at();
    let mut client = Client::connect(url, NoTls).unwrap();
    assert_eq!(
        client
            .execute(
                "INSERT INTO public.accordlock_broker_operations
                        (entry_id, tenant, environment, authorization_id, transaction_id,
                         claim_id, fence, state_instance_id,
                         origin_acquisition_id, origin_lease_fence,
                         acquisition_binding_version, cluster_identity,
                         namespace, deployment_uid, route_commitment,
                         bound_secret_name, operation, phase, prepared_unix_s,
                         request_commitment)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,2,$11,$12,$13,$14,
                         $15,'CREATE_SECRET','INTENT',$16,$17)",
                &[
                    &entry_id,
                    &key.scope.tenant,
                    &key.scope.environment,
                    &key.authorization_id,
                    &key.transaction_id,
                    &token.claim_id(),
                    &fence,
                    &token.state_instance_id(),
                    &authority.acquisition_id(),
                    &lease_fence,
                    &physical.cluster_identity(),
                    &physical.namespace(),
                    &physical.deployment_uid(),
                    &route_commitment.to_string(),
                    &bound_secret_name,
                    &prepared_at,
                    &request_commitment.to_string(),
                ],
            )
            .unwrap(),
        1
    );
    assert_eq!(
        client
            .execute(
                "UPDATE public.accordlock_broker_operations
                    SET phase='IN_FLIGHT', started_unix_s=$2,
                        updated_at=clock_timestamp()
                  WHERE entry_id=$1 AND phase='INTENT'",
                &[&entry_id, &prepared_at],
            )
            .unwrap(),
        1
    );
    entry_id
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_v14_broker_in_flight_is_undeletable_and_bars_reacquisition_and_takeover() {
    let _serial = serial_postgres_test();
    let fixture = ControlFixture::new();
    let (receipt, _) = complete_control_dispatch(&fixture);
    let request = DispatchAcquisitionRequest::new("pg-v14-guard-dispatch", Uuid::new_v4()).unwrap();
    let authority = match fixture
        .store
        .claim_next_pending_dispatch_or_recover(receipt.scope(), &request)
        .unwrap()
    {
        DispatchAcquisitionOutcome::Acquired(work) => work.into_parts().1,
        other => panic!("expected acquired dispatch work, got {other:?}"),
    };
    let entry_id = insert_control_broker_in_flight(&fixture.url, &authority, [0x91; 32]);

    let mut client = Client::connect(&fixture.url, NoTls).unwrap();
    let delete_error = client
        .execute(
            "DELETE FROM public.accordlock_broker_operations WHERE entry_id=$1",
            &[&entry_id],
        )
        .unwrap_err();
    assert_eq!(
        postgres_message(&delete_error),
        "broker operation history is append-only"
    );
    let rewind_error = client
        .execute(
            "UPDATE public.accordlock_broker_operations
                SET phase='INTENT', started_unix_s=NULL,
                    updated_at=clock_timestamp()
              WHERE entry_id=$1",
            &[&entry_id],
        )
        .unwrap_err();
    assert_eq!(
        postgres_message(&rewind_error),
        "broker operation phase transition is non-monotone"
    );
    let row = client
        .query_one(
            "SELECT phase, started_unix_s IS NOT NULL AS has_started
               FROM public.accordlock_broker_operations WHERE entry_id=$1",
            &[&entry_id],
        )
        .unwrap();
    assert_eq!(row.get::<_, String>("phase"), "IN_FLIGHT");
    assert!(row.get::<_, bool>("has_started"));

    match fixture
        .store
        .claim_next_pending_dispatch_or_recover(receipt.scope(), &request)
        .unwrap()
    {
        DispatchAcquisitionOutcome::Quarantined(inert) => assert_eq!(
            inert.disposition(),
            DispatchAcquisitionDisposition::BrokerArtifactPresent
        ),
        other => panic!("expected broker-artifact quarantine, got {other:?}"),
    }

    let takeover_id = Uuid::new_v4();
    let takeover_worker = "pg-v14-guard-takeover";
    let mut transaction = client.transaction().unwrap();
    transaction
        .execute(
            "INSERT INTO public.accordlock_dispatch_request_identities
                    (dispatch_request_id, request_kind, worker_id, bound_at)
             VALUES ($1,'ACQUISITION',$2,clock_timestamp())",
            &[&takeover_id, &takeover_worker],
        )
        .unwrap();
    let takeover_error = transaction
        .execute(
            "INSERT INTO public.accordlock_dispatch_acquisitions
                    (acquisition_id, tenant, environment, authorization_id, transaction_id,
                     claim_id, claim_fence, state_instance_id,
                     control_submission_id, selection_kind, worker_id,
                     acquired_unix_s, lease_until, dispatch_deadline)
             SELECT $1, tenant, environment, authorization_id, transaction_id, claim_id,
                    claim_fence, state_instance_id, control_submission_id,
                    'CONTROL_QUEUE', $2, lease_until,
                    LEAST(lease_until + 30, dispatch_deadline),
                    dispatch_deadline
               FROM public.accordlock_dispatch_acquisitions
              WHERE acquisition_id=$3",
            &[&takeover_id, &takeover_worker, &authority.acquisition_id()],
        )
        .unwrap_err();
    assert_eq!(
        postgres_message(&takeover_error),
        "dispatch acquisition takeover is barred by durable artifacts"
    );
    transaction.rollback().unwrap();
    assert_eq!(
        client
            .query_one(
                "SELECT count(*)::bigint AS acquisition_count
                   FROM public.accordlock_dispatch_acquisitions
                  WHERE tenant=$1 AND environment=$2 AND authorization_id=$3",
                &[
                    &authority.claim().key().scope.tenant,
                    &authority.claim().key().scope.environment,
                    &authority.claim().key().authorization_id,
                ],
            )
            .unwrap()
            .get::<_, i64>("acquisition_count"),
        1
    );
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_v14_rejects_high_water_decrease_and_backdated_disposition() {
    let _serial = serial_postgres_test();
    let fixture = ControlFixture::new();
    let (receipt, key) = complete_control_dispatch(&fixture);
    let mut client = Client::connect(&fixture.url, NoTls).unwrap();
    let facts = client
        .query_one(
            "SELECT scope_hwm.observed_unix_s AS scope_hwm,
                    ingress.observed_unix_s AS ingress_hwm,
                    submission.state_instance_id,
                    outbox.dispatch_deadline
               FROM public.accordlock_control_submissions AS submission
               JOIN public.accordlock_ingress_replay_scopes AS ingress
                 ON ingress.replay_scope=submission.replay_scope
                AND ingress.state_instance_id=submission.state_instance_id
               JOIN public.accordlock_time_high_water AS scope_hwm
                 ON scope_hwm.tenant=submission.tenant
                AND scope_hwm.environment=submission.environment
               JOIN public.accordlock_control_consumptions AS consumption
                 ON consumption.submission_id=submission.submission_id
               JOIN public.accordlock_execution_outbox AS outbox
                 ON outbox.tenant=consumption.tenant
                AND outbox.environment=consumption.environment
                AND outbox.authorization_id=consumption.authorization_id
                AND outbox.transaction_id=consumption.transaction_id
              WHERE submission.submission_id=$1",
            &[&receipt.submission_id()],
        )
        .unwrap();
    let scope_hwm: i64 = facts.get("scope_hwm");
    let ingress_hwm: i64 = facts.get("ingress_hwm");
    let state_instance_id: Uuid = facts.get("state_instance_id");
    let dispatch_deadline: i64 = facts.get("dispatch_deadline");
    let backdated = scope_hwm.min(ingress_hwm).saturating_sub(1);

    let hwm_error = client
        .execute(
            "UPDATE public.accordlock_time_high_water
                SET observed_unix_s=$3, updated_at=clock_timestamp()
              WHERE tenant=$1 AND environment=$2",
            &[&key.scope.tenant, &key.scope.environment, &backdated],
        )
        .unwrap_err();
    assert_eq!(
        postgres_message(&hwm_error),
        "dispatch trusted-time high-water cannot decrease"
    );
    assert_eq!(
        client
            .query_one(
                "SELECT observed_unix_s FROM public.accordlock_time_high_water
                  WHERE tenant=$1 AND environment=$2",
                &[&key.scope.tenant, &key.scope.environment],
            )
            .unwrap()
            .get::<_, i64>("observed_unix_s"),
        scope_hwm
    );

    let disposition_id = Uuid::new_v4();
    let worker = "pg-v14-guard-disposer";
    let authorization_commitment = format!("sha256:{}", "11".repeat(32));
    let grant_commitment = format!("sha256:{}", "22".repeat(32));
    let outbox_commitment = format!("sha256:{}", "33".repeat(32));
    let expected_authority = format!("sha256:{}", "44".repeat(32));
    let current_authority = format!("sha256:{}", "55".repeat(32));
    let disposition_commitment = format!("sha256:{}", "66".repeat(32));
    let mut transaction = client.transaction().unwrap();
    transaction
        .execute(
            "INSERT INTO public.accordlock_dispatch_request_identities
                    (dispatch_request_id, request_kind, worker_id, bound_at)
             VALUES ($1,'DISPOSITION',$2,clock_timestamp())",
            &[&disposition_id, &worker],
        )
        .unwrap();
    let disposition_error = transaction
        .execute(
            "INSERT INTO public.accordlock_dispatch_queue_dispositions
                    (dispatch_request_id, worker_id, control_submission_id,
                     tenant, environment, authorization_id, transaction_id,
                     state_instance_id, reason, observed_unix_s,
                     dispatch_deadline, authorization_commitment, grant_commitment,
                     outbox_commitment, expected_authority_commitment,
                     current_authority_commitment, disposition_commitment)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'AUTHORITY_CHANGED',$9,$10,
                     $11,$12,$13,$14,$15,$16)",
            &[
                &disposition_id,
                &worker,
                &receipt.submission_id(),
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
                &state_instance_id,
                &backdated,
                &dispatch_deadline,
                &authorization_commitment,
                &grant_commitment,
                &outbox_commitment,
                &expected_authority,
                &current_authority,
                &disposition_commitment,
            ],
        )
        .unwrap_err();
    assert_eq!(
        postgres_message(&disposition_error),
        "dispatch disposition is not covered by both trusted-time HWMs"
    );
    transaction.rollback().unwrap();
    assert_eq!(
        client
            .query_one(
                "SELECT count(*)::bigint AS disposition_count
                   FROM public.accordlock_dispatch_queue_dispositions
                  WHERE control_submission_id=$1",
                &[&receipt.submission_id()],
            )
            .unwrap()
            .get::<_, i64>("disposition_count"),
        0
    );
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_v14_nil_activation_id_rejection_matches_memory() {
    let _serial = serial_postgres_test();
    let (url, postgres) = configured_store();
    let memory = InMemoryStore::new();
    let suffix = Uuid::new_v4().simple().to_string();
    let postgres_scope = Scope::new(format!("v14-nil-pg-{suffix}"), "test").unwrap();
    let memory_scope = Scope::new(format!("v14-nil-memory-{suffix}"), "test").unwrap();
    let mut invalid = base_authority(&format!("nil-{suffix}"));
    invalid.resource.activation_id = Uuid::nil();

    let postgres_error = postgres
        .compare_and_activate_authority(&postgres_scope, None, &invalid)
        .unwrap_err();
    let memory_error = memory
        .compare_and_activate_authority(&memory_scope, None, &invalid)
        .unwrap_err();
    assert!(matches!(
        &postgres_error,
        StateError::InvalidRecord(message)
            if message == "authority activation identifiers must be non-nil"
    ));
    assert_eq!(postgres_error.to_string(), memory_error.to_string());
    assert_eq!(
        Client::connect(&url, NoTls)
            .unwrap()
            .query_one(
                "SELECT count(*)::bigint AS authority_count
                   FROM public.accordlock_authority_state
                  WHERE tenant=$1 AND environment=$2",
                &[&postgres_scope.tenant, &postgres_scope.environment],
            )
            .unwrap()
            .get::<_, i64>("authority_count"),
        0
    );
}
