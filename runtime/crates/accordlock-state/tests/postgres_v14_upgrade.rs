#![allow(clippy::panic, clippy::too_many_lines, clippy::unwrap_used)]

//! `PostgreSQL` 13 -> 14 upgrade coverage.
//!
//! These tests rebuild the disposable test database from migrations 0001
//! through 0013 before producing authenticated v13 control lineage. They are
//! isolated in their own integration-test binary because that rebuild is
//! schema-wide. Every successful test leaves the database at v14.

use std::collections::BTreeSet;
use std::env;
use std::net::IpAddr;
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
    BrokerCleanupRequest, BrokerJournalOperation, BrokerJournalOutcome, BrokerJournalPhase,
    BrokerJournalState, BrokerReconciliationRequest, BrokerReconciliationResult,
    BrokerSecretObservation, ClaimedControlWork, ConsumeKey, ControlConsumptionCommitOutcome,
    ControlIssuanceCommitOutcome, ControlPlaneState, ControlSubmissionIntakeOutcome,
    ControlSubmissionReceipt, ControlWorkClaimOutcome, ControlWorkClaimRequest, ControlWorkerRole,
    DispatchAcquisitionDisposition, DispatchAcquisitionOutcome, DispatchAcquisitionRequest,
    DispatchClaimRequest, DispatchDeadlinePolicy, GrantRegistration, IssuanceSnapshot,
    IssuedAuthorizationRecord, PostgresStore, Scope, StateError, TransactionalState,
};
use postgres::{Client, Config, NoTls, config::Host};
use uuid::Uuid;

const TEST_DATABASE_URL_ENV: &str = "ACCORDLOCK_TEST_POSTGRES_URL";
const RESET_CONFIRMATION_ENV: &str = "ACCORDLOCK_TEST_POSTGRES_V14_RESET";
const RESET_CONFIRMATION: &str = "DROP_PUBLIC_SCHEMA_OF_ACCORDLOCK_TEST_V2";
const DISPOSABLE_DATABASE_NAME: &str = "accordlock_test_v2";
const CONTROL_ENVIRONMENT: &str = "test";

const V13_MIGRATIONS: [&str; 13] = [
    include_str!("../../../migrations/0001_transactional_state.sql"),
    include_str!("../../../migrations/0002_state_integrity.sql"),
    include_str!("../../../migrations/0003_state_instance.sql"),
    include_str!("../../../migrations/0004_signed_issuance_profile.sql"),
    include_str!("../../../migrations/0005_dispatch_claims.sql"),
    include_str!("../../../migrations/0006_physical_resource_reservations.sql"),
    include_str!("../../../migrations/0007_admission_authorizations.sql"),
    include_str!("../../../migrations/0008_attempt_credential_binding.sql"),
    include_str!("../../../migrations/0009_broker_operation_journal.sql"),
    include_str!("../../../migrations/0010_ingress_replay.sql"),
    include_str!("../../../migrations/0011_eks_destination_registry.sql"),
    include_str!("../../../migrations/0012_terminal_retirement.sql"),
    include_str!("../../../migrations/0013_durable_control_submissions.sql"),
];

fn serial_postgres_test() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn is_loopback_test_host(host: &Host) -> bool {
    match host {
        Host::Tcp(host) if host.eq_ignore_ascii_case("localhost") => true,
        Host::Tcp(host) => host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()),
        #[cfg(unix)]
        Host::Unix(_) => true,
    }
}

fn validate_destructive_test_target(url: &str, confirmation: Option<&str>) -> Result<(), String> {
    if confirmation != Some(RESET_CONFIRMATION) {
        return Err(format!(
            "{RESET_CONFIRMATION_ENV} must equal {RESET_CONFIRMATION}"
        ));
    }
    let config = url
        .parse::<Config>()
        .map_err(|error| format!("invalid {TEST_DATABASE_URL_ENV}: {error}"))?;
    if config.get_dbname() != Some(DISPOSABLE_DATABASE_NAME) {
        return Err(format!(
            "{TEST_DATABASE_URL_ENV} must select the dedicated {DISPOSABLE_DATABASE_NAME} database"
        ));
    }
    if config.get_hosts().is_empty()
        || !config.get_hosts().iter().all(is_loopback_test_host)
        || !config.get_hostaddrs().iter().all(IpAddr::is_loopback)
    {
        return Err(format!(
            "{TEST_DATABASE_URL_ENV} must use only loopback hosts or a local Unix socket"
        ));
    }
    Ok(())
}

fn test_database_url() -> String {
    let url = env::var(TEST_DATABASE_URL_ENV)
        .unwrap_or_else(|_| panic!("{TEST_DATABASE_URL_ENV} is required"));
    let confirmation = env::var(RESET_CONFIRMATION_ENV).ok();
    validate_destructive_test_target(&url, confirmation.as_deref()).unwrap_or_else(|error| {
        panic!("destructive PostgreSQL v14 upgrade guard rejected target: {error}")
    });
    url
}

fn rebuild_v13_store() -> (String, PostgresStore) {
    let url = test_database_url();
    let mut client = Client::connect(&url, NoTls).unwrap();
    let mut transaction = client.transaction().unwrap();
    transaction
        .batch_execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        .unwrap();
    for migration in V13_MIGRATIONS {
        transaction.batch_execute(migration).unwrap();
    }
    transaction.commit().unwrap();
    let v13_shape: (i32, bool, bool, bool) = client
        .query_one(
            "SELECT max(version),
                    to_regclass('public.accordlock_dispatch_request_identities') IS NULL,
                    to_regclass('public.accordlock_dispatch_acquisitions') IS NULL,
                    to_regclass('public.accordlock_dispatch_queue_dispositions') IS NULL
               FROM public.accordlock_schema_migrations",
            &[],
        )
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
        .unwrap();
    assert_eq!(v13_shape, (13, true, true, true));
    let store = PostgresStore::new(url.clone());
    (url, store)
}

#[test]
fn destructive_upgrade_target_guard_is_fail_closed() {
    let local = "postgresql://postgres@127.0.0.1:55432/accordlock_test_v2";
    assert!(validate_destructive_test_target(local, Some(RESET_CONFIRMATION)).is_ok());
    assert!(validate_destructive_test_target(local, None).is_err());
    assert!(
        validate_destructive_test_target(
            "postgresql://postgres@127.0.0.1:55432/shared_production",
            Some(RESET_CONFIRMATION),
        )
        .is_err()
    );
    assert!(
        validate_destructive_test_target(
            "postgresql://postgres@192.0.2.1:55432/accordlock_test_v2",
            Some(RESET_CONFIRMATION),
        )
        .is_err()
    );
    assert!(
        validate_destructive_test_target(
            "postgresql://postgres@localhost:55432/accordlock_test_v2?hostaddr=192.0.2.1",
            Some(RESET_CONFIRMATION),
        )
        .is_err()
    );
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
            image_digest: Digest32::sha256(b"v14-upgrade-image"),
            cluster_identity: "cluster-a".to_owned(),
            namespace: "payments".to_owned(),
            deployment: "payments".to_owned(),
            deployment_uid: format!("deployment-{tenant}"),
            container: "app".to_owned(),
            container_index: 0,
            prior_image_digest: Digest32::sha256(b"v14-upgrade-prior-image"),
            resource_version: "1001".to_owned(),
            prior_projection_hash: Digest32::sha256(b"v14-upgrade-projection"),
            prior_transaction_annotation: Some("none".to_owned()),
            prior_authorization_annotation: Some("none".to_owned()),
            prior_operation_hash_annotation: Some("none".to_owned()),
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
        let (url, store) = rebuild_v13_store();
        let suffix = Uuid::new_v4().simple().to_string();
        let tenant = format!("v14-upgrade-{suffix}");
        let audience = format!("accordlock-executor:v14-upgrade-{suffix}");
        let now = database_time(&url);
        let ingress_signer = SigningIdentity::from_seed("pg-v14-upgrade-ingress", [0x91; 32]);
        let evaluator = SigningIdentity::from_seed("pg-v14-upgrade-evaluator", [0x92; 32]);
        let authorization_signer =
            SigningIdentity::from_seed("pg-v14-upgrade-authorization", [0x93; 32]);
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

    fn accept(&self) -> ControlSubmissionReceipt {
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
        let wire = serde_json::to_vec(&request).unwrap();
        let verified: StaticallyVerifiedIngressSubmission = self
            .authenticator
            .verify_durable_static(IngressRecoveryProbe::parse_bytes(&wire).unwrap())
            .unwrap();
        match self
            .store
            .accept_control_submission_or_recover(verified)
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
        evidence_root: Digest32::sha256(b"v14-upgrade-evidence"),
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
            "pg-v14-upgrade-evaluator",
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
            "pg-v14-upgrade-issuer",
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
            "pg-v14-upgrade-consumer",
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

struct V13Claim {
    claim_id: Uuid,
    worker_id: String,
    fence: i64,
    state_instance_id: Uuid,
    claimed_unix_s: i64,
    lease_until: i64,
}

const V13_BROKER_ROUTE: [u8; 32] = [0x37; 32];
const V13_BROKER_REQUEST_DOMAIN: &[u8] = b"accordlock:v1:broker-operation-request\0";
const V13_BROKER_RESULT_DOMAIN: &[u8] = b"accordlock:v1:broker-operation-result\0";
const V13_CREDENTIAL_BINDING_DOMAIN: &[u8] = b"accordlock:v1:dispatch-credential-binding\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum V13DeletePhase {
    Intent,
    InFlight,
    Unknown,
    ReconcileOnly,
    CommittedAbsent,
}

impl V13DeletePhase {
    const fn database_phase(self) -> &'static str {
        match self {
            Self::Intent => "INTENT",
            Self::InFlight => "IN_FLIGHT",
            Self::Unknown => "UNKNOWN",
            Self::ReconcileOnly => "RECONCILE_ONLY",
            Self::CommittedAbsent => "COMMITTED",
        }
    }

    const fn started(self, started_at: i64) -> Option<i64> {
        match self {
            Self::Intent => None,
            Self::InFlight | Self::Unknown | Self::ReconcileOnly | Self::CommittedAbsent => {
                Some(started_at)
            }
        }
    }
}

fn append_v13_broker_field(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&u64::try_from(value.len()).unwrap().to_be_bytes());
    target.extend_from_slice(value);
}

#[allow(clippy::too_many_arguments)]
fn v13_broker_request_commitment(
    entry_id: Uuid,
    key: &ConsumeKey,
    claim: &V13Claim,
    cluster_identity: &str,
    namespace: &str,
    deployment_uid: &str,
    route_commitment: Digest32,
    bound_secret_name: &str,
    bound_secret_uid: Option<&str>,
    operation_tag: u8,
) -> Digest32 {
    let mut bytes = V13_BROKER_REQUEST_DOMAIN.to_vec();
    append_v13_broker_field(&mut bytes, key.scope.tenant.as_bytes());
    append_v13_broker_field(&mut bytes, key.scope.environment.as_bytes());
    bytes.extend_from_slice(key.transaction_id.as_bytes());
    bytes.extend_from_slice(key.authorization_id.as_bytes());
    bytes.extend_from_slice(entry_id.as_bytes());
    bytes.extend_from_slice(claim.claim_id.as_bytes());
    bytes.extend_from_slice(&u64::try_from(claim.fence).unwrap().to_be_bytes());
    bytes.extend_from_slice(claim.state_instance_id.as_bytes());
    append_v13_broker_field(&mut bytes, cluster_identity.as_bytes());
    append_v13_broker_field(&mut bytes, namespace.as_bytes());
    append_v13_broker_field(&mut bytes, deployment_uid.as_bytes());
    bytes.extend_from_slice(route_commitment.as_bytes());
    append_v13_broker_field(&mut bytes, bound_secret_name.as_bytes());
    if let Some(uid) = bound_secret_uid {
        bytes.push(1);
        append_v13_broker_field(&mut bytes, uid.as_bytes());
    } else {
        bytes.push(0);
    }
    bytes.push(operation_tag);
    bytes.push(0); // CREATE and DELETE have no credential-safety policy.
    Digest32::sha256(&bytes)
}

fn v13_broker_result_commitment(
    request_commitment: Digest32,
    outcome_tag: u8,
    bound_secret_uid: &str,
    evidence_commitment: Digest32,
) -> Digest32 {
    let mut bytes = V13_BROKER_RESULT_DOMAIN.to_vec();
    bytes.extend_from_slice(request_commitment.as_bytes());
    bytes.push(outcome_tag);
    bytes.push(1);
    append_v13_broker_field(&mut bytes, bound_secret_uid.as_bytes());
    bytes.extend_from_slice(evidence_commitment.as_bytes());
    bytes.push(0); // no token digest
    bytes.push(0); // no token expiry
    Digest32::sha256(&bytes)
}

#[allow(clippy::too_many_arguments)]
fn v13_credential_binding_commitment(
    key: &ConsumeKey,
    claim: &V13Claim,
    token_digest: Digest32,
    service_account_uid: &str,
    credential_id: &str,
    not_before: i64,
    expires_at: i64,
) -> Digest32 {
    let mut bytes = V13_CREDENTIAL_BINDING_DOMAIN.to_vec();
    append_v13_broker_field(&mut bytes, key.scope.tenant.as_bytes());
    append_v13_broker_field(&mut bytes, key.scope.environment.as_bytes());
    bytes.extend_from_slice(key.transaction_id.as_bytes());
    bytes.extend_from_slice(key.authorization_id.as_bytes());
    bytes.extend_from_slice(claim.claim_id.as_bytes());
    bytes.extend_from_slice(&u64::try_from(claim.fence).unwrap().to_be_bytes());
    bytes.extend_from_slice(claim.state_instance_id.as_bytes());
    bytes.extend_from_slice(token_digest.as_bytes());
    append_v13_broker_field(&mut bytes, service_account_uid.as_bytes());
    append_v13_broker_field(&mut bytes, credential_id.as_bytes());
    bytes.extend_from_slice(&not_before.to_be_bytes());
    bytes.extend_from_slice(&expires_at.to_be_bytes());
    Digest32::sha256(&bytes)
}

struct V13BrokerSeed {
    delete_entry_id: Option<Uuid>,
    bound_secret_uid: String,
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn insert_v13_broker_history(
    url: &str,
    key: &ConsumeKey,
    claim: &V13Claim,
    cluster_identity: &str,
    namespace: &str,
    deployment_uid: &str,
    delete_phase: Option<V13DeletePhase>,
) -> V13BrokerSeed {
    let mut client = Client::connect(url, NoTls).unwrap();
    let route_commitment = Digest32::from_bytes(V13_BROKER_ROUTE);
    let bound_secret_name = format!("accordlock-{}", key.transaction_id.simple());
    let bound_secret_uid = format!("v13-secret-{}", claim.claim_id.simple());
    let create_entry_id = Uuid::new_v4();
    let create_request = v13_broker_request_commitment(
        create_entry_id,
        key,
        claim,
        cluster_identity,
        namespace,
        deployment_uid,
        route_commitment,
        &bound_secret_name,
        None,
        1,
    );
    let create_evidence = Digest32::from_bytes([0x61; 32]);
    let create_result =
        v13_broker_result_commitment(create_request, 1, &bound_secret_uid, create_evidence);
    let create_started_at = claim.claimed_unix_s.saturating_add(1);
    assert!(create_started_at < claim.lease_until);
    assert_eq!(
        client
            .execute(
                "INSERT INTO public.accordlock_broker_operations
                        (entry_id, tenant, environment, authorization_id, transaction_id,
                         claim_id, fence, state_instance_id, cluster_identity,
                         namespace, deployment_uid, route_commitment,
                         bound_secret_name, bound_secret_uid, operation, phase,
                         prepared_unix_s, started_unix_s, outcome,
                         provider_evidence_commitment, request_commitment,
                         result_commitment)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
                         'CREATE_SECRET','COMMITTED',$15,$16,'CREATE_MATCHING',
                         $17,$18,$19)",
                &[
                    &create_entry_id,
                    &key.scope.tenant,
                    &key.scope.environment,
                    &key.authorization_id,
                    &key.transaction_id,
                    &claim.claim_id,
                    &claim.fence,
                    &claim.state_instance_id,
                    &cluster_identity,
                    &namespace,
                    &deployment_uid,
                    &route_commitment.to_string(),
                    &bound_secret_name,
                    &bound_secret_uid,
                    &claim.claimed_unix_s,
                    &create_started_at,
                    &create_evidence.to_string(),
                    &create_request.to_string(),
                    &create_result.to_string(),
                ],
            )
            .unwrap(),
        1
    );

    let Some(delete_phase) = delete_phase else {
        return V13BrokerSeed {
            delete_entry_id: None,
            bound_secret_uid,
        };
    };
    let delete_entry_id = Uuid::new_v4();
    let delete_request = v13_broker_request_commitment(
        delete_entry_id,
        key,
        claim,
        cluster_identity,
        namespace,
        deployment_uid,
        route_commitment,
        &bound_secret_name,
        Some(&bound_secret_uid),
        3,
    );
    let delete_evidence = Digest32::from_bytes([0x62; 32]);
    let delete_result =
        v13_broker_result_commitment(delete_request, 5, &bound_secret_uid, delete_evidence);
    let delete_prepared_at = create_started_at.saturating_add(1);
    let delete_started_at = delete_prepared_at.saturating_add(1);
    let started = delete_phase.started(delete_started_at);
    let committed = delete_phase == V13DeletePhase::CommittedAbsent;
    let outcome = committed.then_some("DELETE_ABSENT");
    let evidence = committed.then(|| delete_evidence.to_string());
    let result = committed.then(|| delete_result.to_string());
    assert_eq!(
        client
            .execute(
                "INSERT INTO public.accordlock_broker_operations
                        (entry_id, tenant, environment, authorization_id, transaction_id,
                         claim_id, fence, state_instance_id, cluster_identity,
                         namespace, deployment_uid, route_commitment,
                         bound_secret_name, bound_secret_uid, operation, phase,
                         prepared_unix_s, started_unix_s, outcome,
                         provider_evidence_commitment, request_commitment,
                         result_commitment)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
                         'DELETE_SECRET',$15,$16,$17,$18,$19,$20,$21)",
                &[
                    &delete_entry_id,
                    &key.scope.tenant,
                    &key.scope.environment,
                    &key.authorization_id,
                    &key.transaction_id,
                    &claim.claim_id,
                    &claim.fence,
                    &claim.state_instance_id,
                    &cluster_identity,
                    &namespace,
                    &deployment_uid,
                    &route_commitment.to_string(),
                    &bound_secret_name,
                    &bound_secret_uid,
                    &delete_phase.database_phase(),
                    &delete_prepared_at,
                    &started,
                    &outcome,
                    &evidence,
                    &delete_request.to_string(),
                    &result,
                ],
            )
            .unwrap(),
        1
    );
    if committed {
        assert_eq!(
            client
                .execute(
                    "INSERT INTO public.accordlock_broker_secret_deletion_observations
                            (entry_id, tenant, environment, authorization_id, transaction_id,
                             claim_id, fence, state_instance_id, cluster_identity,
                             namespace, deployment_uid, route_commitment,
                             bound_secret_name, bound_secret_uid, operation, phase,
                             started_unix_s, reconciliation_floor_unix_s, outcome,
                             journal_request_commitment, journal_result_commitment,
                             provider_evidence_commitment, observed_unix_s)
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
                             'DELETE_SECRET','COMMITTED',$15,$15,'DELETE_ABSENT',
                             $16,$17,$18,$15)",
                    &[
                        &delete_entry_id,
                        &key.scope.tenant,
                        &key.scope.environment,
                        &key.authorization_id,
                        &key.transaction_id,
                        &claim.claim_id,
                        &claim.fence,
                        &claim.state_instance_id,
                        &cluster_identity,
                        &namespace,
                        &deployment_uid,
                        &route_commitment.to_string(),
                        &bound_secret_name,
                        &bound_secret_uid,
                        &delete_started_at,
                        &delete_request.to_string(),
                        &delete_result.to_string(),
                        &delete_evidence.to_string(),
                    ],
                )
                .unwrap(),
            1
        );
    }
    V13BrokerSeed {
        delete_entry_id: Some(delete_entry_id),
        bound_secret_uid,
    }
}

#[allow(clippy::too_many_arguments)]
fn insert_v13_claim(
    url: &str,
    key: &ConsumeKey,
    worker_id: &str,
    claimed_unix_s: i64,
    lease_until: i64,
    cluster_identity: &str,
    namespace: &str,
    deployment_uid: &str,
) -> V13Claim {
    let mut client = Client::connect(url, NoTls).unwrap();
    let facts = client
        .query_one(
            "SELECT metadata.state_instance_id, outbox.dispatch_deadline
               FROM public.accordlock_state_metadata AS metadata
               JOIN public.accordlock_execution_outbox AS outbox ON TRUE
              WHERE metadata.singleton=TRUE
                AND outbox.tenant=$1 AND outbox.environment=$2
                AND outbox.authorization_id=$3 AND outbox.transaction_id=$4",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
            ],
        )
        .unwrap();
    let state_instance_id: Uuid = facts.get("state_instance_id");
    let dispatch_deadline: i64 = facts.get("dispatch_deadline");
    assert!(lease_until <= dispatch_deadline);
    let claim_id = Uuid::new_v4();
    let fence: i64 = client
        .query_one(
            "INSERT INTO public.accordlock_dispatch_claims
                    (tenant, environment, authorization_id, transaction_id, claim_id,
                     worker_id, state_instance_id, claimed_unix_s,
                     lease_until, state, cluster_identity, namespace,
                     deployment_uid)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'CLAIMED',$10,$11,$12)
          RETURNING fence",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
                &claim_id,
                &worker_id,
                &state_instance_id,
                &claimed_unix_s,
                &lease_until,
                &cluster_identity,
                &namespace,
                &deployment_uid,
            ],
        )
        .unwrap()
        .get("fence");
    V13Claim {
        claim_id,
        worker_id: worker_id.to_owned(),
        fence,
        state_instance_id,
        claimed_unix_s,
        lease_until,
    }
}

struct LegacyDispatchFixture {
    key: ConsumeKey,
    cluster_identity: String,
    namespace: String,
    deployment_uid: String,
}

fn create_legacy_dispatch(store: &PostgresStore, url: &str) -> LegacyDispatchFixture {
    let now = database_time(url);
    let suffix = Uuid::new_v4().simple().to_string();
    let tenant = format!("v14-upgrade-legacy-{suffix}");
    let scope = Scope::new(&tenant, CONTROL_ENVIRONMENT).unwrap();
    let cluster_identity = format!("cluster-legacy-{suffix}");
    let namespace = "payments".to_owned();
    let deployment_uid = format!("deployment-legacy-{suffix}");
    let signer = SigningIdentity::from_seed("pg-v14-upgrade-legacy-authorization", [0x94; 32]);
    let capability = CapabilityGrant {
        grant_id: Uuid::new_v4(),
        holder: "workload-a".to_owned(),
        tenant: tenant.clone(),
        operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
        repository: "acme/payments".to_owned(),
        audience: "accordlock-executor:v14-upgrade-legacy".to_owned(),
        cluster_identity: cluster_identity.clone(),
        namespace: namespace.clone(),
        deployment_uid: deployment_uid.clone(),
        container: "app".to_owned(),
        image_repository: "registry.example/acme/payments".to_owned(),
        not_before: now.saturating_sub(300),
        expires_at: now.saturating_add(3_600),
        maximum_uses: 2,
    };
    let mut authority = base_authority(&suffix);
    authority.signer.root =
        authorization_signer_root(signer.key_id(), signer.public_key_bytes()).unwrap();
    authority.grant_registry.root = canonical_hash(&capability).unwrap();
    store
        .compare_and_activate_authority(&scope, None, &authority)
        .unwrap();
    let deadline_policy = DispatchDeadlinePolicy {
        max_dispatch_delay_seconds: 180,
        profile_hard_cap: now.saturating_add(3_000),
        immutable_dependency_expiries: vec![now.saturating_add(2_400)],
    };
    store
        .register_grant(&GrantRegistration {
            environment: CONTROL_ENVIRONMENT.to_owned(),
            grant: capability.clone(),
            authority: authority.clone(),
            dispatch_deadline_policy: deadline_policy.clone(),
        })
        .unwrap();
    let template = DeploymentTemplate {
        operation: capability.operation.clone(),
        environment: CONTROL_ENVIRONMENT.to_owned(),
        audience: capability.audience.clone(),
        repository: capability.repository.clone(),
        commit_sha: "2222222222222222222222222222222222222222".to_owned(),
        image_repository: capability.image_repository.clone(),
        image_digest: Digest32::sha256(b"v14-upgrade-legacy-image"),
        cluster_identity: cluster_identity.clone(),
        namespace: namespace.clone(),
        deployment: "payments".to_owned(),
        deployment_uid: deployment_uid.clone(),
        container: capability.container.clone(),
        container_index: 0,
        prior_image_digest: Digest32::sha256(b"v14-upgrade-legacy-prior"),
        resource_version: "2001".to_owned(),
        prior_projection_hash: Digest32::sha256(b"v14-upgrade-legacy-projection"),
        prior_transaction_annotation: Some("none".to_owned()),
        prior_authorization_annotation: Some("none".to_owned()),
        prior_operation_hash_annotation: Some("none".to_owned()),
    };
    let authorization_id = Uuid::new_v4();
    let transaction_id = Uuid::new_v4();
    let authorization = ExecutionAuthorization {
        schema_version: EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
        authorization_id,
        evaluation_nonce: Uuid::new_v4(),
        request_id: Uuid::new_v4(),
        tenant,
        holder: capability.holder,
        audience: capability.audience,
        issued_at: now.saturating_sub(1),
        not_before: now.saturating_sub(1),
        consume_before: now.saturating_add(600),
        dispatch_deadline_policy: deadline_policy,
        grant_id: capability.grant_id,
        template_hash: canonical_hash(&template).unwrap(),
        template,
        evidence_root: Digest32::sha256(b"v14-upgrade-legacy-evidence"),
        principals: vec!["principal-a".to_owned()],
        policy_root: authority.policy.root,
        authority,
    };
    let record = IssuedAuthorizationRecord::new(
        transaction_id,
        SignedAuthorization {
            cose_sign1: sign_cose(
                &authorization.canonical_bytes().unwrap(),
                EXECUTION_AUTHORIZATION_DOMAIN,
                &signer,
            )
            .unwrap(),
            authorization,
        },
        signer.key_id().to_owned(),
        signer.public_key_bytes(),
    )
    .unwrap();
    store.record_issued_authorization(&record).unwrap();
    let key = ConsumeKey {
        scope,
        transaction_id,
        authorization_id,
    };
    store.consume(&key).unwrap();
    LegacyDispatchFixture {
        key,
        cluster_identity,
        namespace,
        deployment_uid,
    }
}

fn mark_v13_attempt(url: &str, key: &ConsumeKey, claim: &V13Claim) -> i64 {
    let attempt_started_at = claim.claimed_unix_s.saturating_add(1);
    assert!(attempt_started_at < claim.lease_until);
    let token_digest = Digest32::from_bytes([0xa5; 32]);
    let credential_id = format!("AUTHORIZATION_ID={}", Uuid::new_v4());
    let service_account_uid = "22222222-2222-4222-8222-222222222222";
    let credential_not_before = claim.claimed_unix_s;
    let credential_expires_at = claim.lease_until.saturating_add(300);
    let binding_commitment = v13_credential_binding_commitment(
        key,
        claim,
        token_digest,
        service_account_uid,
        &credential_id,
        credential_not_before,
        credential_expires_at,
    );
    assert_eq!(
        Client::connect(url, NoTls)
            .unwrap()
            .execute(
                "UPDATE public.accordlock_dispatch_claims
                    SET state='ATTEMPT_IN_FLIGHT', attempt_started_at=$2,
                        credential_token_digest=$3,
                        service_account_uid=$4, credential_id=$5,
                        credential_not_before=$6, credential_expires_at=$7,
                        credential_binding_commitment=$8,
                        updated_at=clock_timestamp()
                  WHERE claim_id=$1 AND state='CLAIMED'",
                &[
                    &claim.claim_id,
                    &attempt_started_at,
                    &token_digest.to_string(),
                    &service_account_uid,
                    &credential_id,
                    &credential_not_before,
                    &credential_expires_at,
                    &binding_commitment.to_string(),
                ],
            )
            .unwrap(),
        1
    );
    attempt_started_at
}

fn assert_v14_attempt_backfill(
    client: &mut Client,
    claim: &V13Claim,
    expected_selection_kind: &str,
    expected_control_submission_id: Option<Uuid>,
    attempt_started_at: i64,
) {
    let row = client
        .query_one(
            "SELECT acquisition.acquisition_id, acquisition.claim_id,
                     acquisition.claim_fence, acquisition.lease_fence,
                    acquisition.acquired_unix_s, acquisition.lease_until,
                     acquisition.state_instance_id,
                    acquisition.control_submission_id,
                    acquisition.selection_kind,
                    claim.state, claim.attempt_started_at,
                    claim.attempt_acquisition_id,
                    claim.attempt_lease_fence,
                    claim.attempt_acquired_unix_s,
                    claim.attempt_lease_until,
                    claim.acquisition_binding_version
               FROM public.accordlock_dispatch_acquisitions AS acquisition
               JOIN public.accordlock_dispatch_claims AS claim
                 ON claim.claim_id=acquisition.claim_id
                AND claim.fence=acquisition.claim_fence
                AND claim.state_instance_id=acquisition.state_instance_id
              WHERE acquisition.acquisition_id=$1",
            &[&claim.claim_id],
        )
        .unwrap();
    assert_eq!(row.get::<_, Uuid>("acquisition_id"), claim.claim_id);
    assert_eq!(row.get::<_, Uuid>("claim_id"), claim.claim_id);
    assert_eq!(row.get::<_, i64>("claim_fence"), claim.fence);
    assert_eq!(row.get::<_, i64>("lease_fence"), claim.fence);
    assert_eq!(row.get::<_, i64>("acquired_unix_s"), claim.claimed_unix_s);
    assert_eq!(row.get::<_, i64>("lease_until"), claim.lease_until);
    assert_eq!(
        row.get::<_, Uuid>("state_instance_id"),
        claim.state_instance_id
    );
    assert_eq!(
        row.get::<_, Option<Uuid>>("control_submission_id"),
        expected_control_submission_id
    );
    assert_eq!(
        row.get::<_, String>("selection_kind"),
        expected_selection_kind
    );
    assert_eq!(row.get::<_, String>("state"), "ATTEMPT_IN_FLIGHT");
    assert_eq!(
        row.get::<_, Option<i64>>("attempt_started_at"),
        Some(attempt_started_at)
    );
    assert_eq!(
        row.get::<_, Option<Uuid>>("attempt_acquisition_id"),
        Some(claim.claim_id)
    );
    assert_eq!(
        row.get::<_, Option<i64>>("attempt_lease_fence"),
        Some(claim.fence)
    );
    assert_eq!(
        row.get::<_, Option<i64>>("attempt_acquired_unix_s"),
        Some(claim.claimed_unix_s)
    );
    assert_eq!(
        row.get::<_, Option<i64>>("attempt_lease_until"),
        Some(claim.lease_until)
    );
    assert_eq!(
        row.get::<_, Option<i16>>("acquisition_binding_version"),
        Some(1)
    );
}

fn control_high_waters(url: &str, submission_id: Uuid) -> (i64, i64) {
    Client::connect(url, NoTls)
        .unwrap()
        .query_one(
            "SELECT scope.observed_unix_s, ingress.observed_unix_s
               FROM public.accordlock_control_submissions AS submission
               JOIN public.accordlock_time_high_water AS scope
                 ON scope.tenant=submission.tenant
                AND scope.environment=submission.environment
               JOIN public.accordlock_ingress_replay_scopes AS ingress
                 ON ingress.replay_scope=submission.replay_scope
                AND ingress.state_instance_id=submission.state_instance_id
              WHERE submission.submission_id=$1",
            &[&submission_id],
        )
        .map(|row| (row.get(0), row.get(1)))
        .unwrap()
}

#[test]
#[ignore = "requires guarded ACCORDLOCK_TEST_POSTGRES_URL for the dedicated accordlock_test_v2 database"]
fn postgres_v13_claimed_control_upgrade_is_exact_and_takeover_uses_a_new_generation() {
    let _serial = serial_postgres_test();
    let fixture = ControlFixture::new();
    let (receipt, key) = complete_control_dispatch(&fixture);
    // A crashed v13 worker leaves a CLAIMED row without any broker,
    // admission, attempt, or terminal artifact.  Make its old lease expired
    // without waiting in wall-clock time.
    let now = database_time(&fixture.url);
    let old_acquired_at = now.saturating_sub(40);
    let old_lease_until = now.saturating_sub(10);
    let old_claim = insert_v13_claim(
        &fixture.url,
        &key,
        "pg-v14-upgrade-old-worker",
        old_acquired_at,
        old_lease_until,
        "cluster-a",
        "payments",
        &format!("deployment-{}", fixture.tenant),
    );
    let mut client = Client::connect(&fixture.url, NoTls).unwrap();

    fixture.store.migrate().unwrap();
    fixture.store.validate_schema().unwrap();

    let row = client
        .query_one(
            "SELECT identity.request_kind, identity.worker_id,
                    acquisition.acquisition_id, acquisition.claim_id,
                    acquisition.claim_fence, acquisition.lease_fence,
                    acquisition.state_instance_id,
                    acquisition.control_submission_id,
                    acquisition.selection_kind,
                    acquisition.acquired_unix_s,
                    acquisition.lease_until AS acquisition_lease_until,
                    claim.claimed_unix_s,
                    claim.lease_until AS claim_lease_until
               FROM public.accordlock_dispatch_claims AS claim
               JOIN public.accordlock_dispatch_acquisitions AS acquisition
                 ON acquisition.claim_id=claim.claim_id
                AND acquisition.claim_fence=claim.fence
                AND acquisition.state_instance_id=claim.state_instance_id
               JOIN public.accordlock_dispatch_request_identities AS identity
                 ON identity.dispatch_request_id=acquisition.acquisition_id
              WHERE claim.claim_id=$1",
            &[&old_claim.claim_id],
        )
        .unwrap();
    assert_eq!(row.get::<_, String>("request_kind"), "ACQUISITION");
    assert_eq!(row.get::<_, String>("worker_id"), old_claim.worker_id);
    assert_eq!(row.get::<_, Uuid>("acquisition_id"), old_claim.claim_id);
    assert_eq!(row.get::<_, Uuid>("claim_id"), old_claim.claim_id);
    assert_eq!(row.get::<_, i64>("claim_fence"), old_claim.fence);
    assert_eq!(row.get::<_, i64>("lease_fence"), old_claim.fence);
    assert_eq!(
        row.get::<_, Uuid>("state_instance_id"),
        old_claim.state_instance_id
    );
    assert_eq!(
        row.get::<_, Option<Uuid>>("control_submission_id"),
        Some(receipt.submission_id())
    );
    assert_eq!(
        row.get::<_, String>("selection_kind"),
        "CONTROL_BOOTSTRAP_V13"
    );
    assert_eq!(
        row.get::<_, i64>("acquired_unix_s"),
        old_claim.claimed_unix_s
    );
    assert_eq!(
        row.get::<_, i64>("acquisition_lease_until"),
        old_claim.lease_until
    );
    assert_eq!(
        row.get::<_, i64>("claimed_unix_s"),
        old_claim.claimed_unix_s
    );
    assert_eq!(
        row.get::<_, i64>("claim_lease_until"),
        old_claim.lease_until
    );

    let cardinality: (i64, i64, i64) = client
        .query_one(
            "SELECT
                 (SELECT count(*) FROM public.accordlock_dispatch_claims
                   WHERE claim_id=$1),
                 (SELECT count(*) FROM public.accordlock_dispatch_acquisitions
                   WHERE claim_id=$1),
                 (SELECT count(*) FROM public.accordlock_dispatch_request_identities
                   WHERE dispatch_request_id=$1)",
            &[&old_claim.claim_id],
        )
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .unwrap();
    assert_eq!(cardinality, (1, 1, 1));
    let orphan_count: i64 = client
        .query_one(
            "SELECT count(*)::bigint
               FROM public.accordlock_dispatch_acquisitions AS acquisition
               LEFT JOIN public.accordlock_dispatch_request_identities AS identity
                 ON identity.dispatch_request_id=acquisition.acquisition_id
               LEFT JOIN public.accordlock_dispatch_claims AS claim
                 ON claim.claim_id=acquisition.claim_id
                AND claim.fence=acquisition.claim_fence
                AND claim.state_instance_id=acquisition.state_instance_id
              WHERE identity.dispatch_request_id IS NULL OR claim.claim_id IS NULL",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(orphan_count, 0);

    // The opaque stable token constructor is crate-private, so an external
    // integration fixture cannot recreate a pre-upgrade process's in-memory
    // token. The maximum public-boundary assertion is that the legacy
    // caller-selected claim endpoint recognizes this as control-owned and
    // rejects it before either HWM changes. SQL above additionally proves the
    // migrated generation is CONTROL_BOOTSTRAP_V13, never LEGACY_BOOTSTRAP.
    let before = control_high_waters(&fixture.url, receipt.submission_id());
    assert!(matches!(
        fixture.store.claim_dispatch(&DispatchClaimRequest {
            key: key.clone(),
            claim_id: Uuid::new_v4(),
            worker_id: "pg-v14-upgrade-forbidden-legacy".to_owned(),
        }),
        Err(StateError::DispatchAcquisitionRequired)
    ));
    assert_eq!(
        control_high_waters(&fixture.url, receipt.submission_id()),
        before
    );

    let takeover_request =
        DispatchAcquisitionRequest::new("pg-v14-upgrade-takeover", Uuid::new_v4()).unwrap();
    let takeover = match fixture
        .store
        .claim_next_pending_dispatch_or_recover(&key.scope, &takeover_request)
        .unwrap()
    {
        DispatchAcquisitionOutcome::Acquired(work) => work,
        other => panic!("expected CONTROL_QUEUE takeover, got {other:?}"),
    };
    assert_eq!(takeover.authority().claim().claim_id(), old_claim.claim_id);
    assert!(takeover.authority().lease_fence() > u64::try_from(old_claim.fence).unwrap());
    assert_ne!(takeover.authority().acquisition_id(), old_claim.claim_id);
    let takeover_kind: String = client
        .query_one(
            "SELECT selection_kind
               FROM public.accordlock_dispatch_acquisitions
              WHERE acquisition_id=$1",
            &[&takeover.authority().acquisition_id()],
        )
        .unwrap()
        .get(0);
    assert_eq!(takeover_kind, "CONTROL_QUEUE");
}

#[test]
#[ignore = "requires guarded ACCORDLOCK_TEST_POSTGRES_URL for the dedicated accordlock_test_v2 database"]
fn postgres_v13_attempt_history_backfills_control_and_legacy_without_authority() {
    let _serial = serial_postgres_test();
    let fixture = ControlFixture::new();
    let (control_receipt, control_key) = complete_control_dispatch(&fixture);
    let control_now = database_time(&fixture.url);
    // v13 imposed no 30-second acquisition cap. Preserve a schema-valid long
    // bootstrap lease byte-for-byte without making it a new CONTROL_QUEUE lease.
    let control_claim = insert_v13_claim(
        &fixture.url,
        &control_key,
        "pg-v14-upgrade-control-attempt",
        control_now,
        control_now.saturating_add(60),
        "cluster-a",
        "payments",
        &format!("deployment-{}", fixture.tenant),
    );
    let control_attempt_started = mark_v13_attempt(&fixture.url, &control_key, &control_claim);

    let legacy = create_legacy_dispatch(&fixture.store, &fixture.url);
    let legacy_now = database_time(&fixture.url);
    let legacy_claim = insert_v13_claim(
        &fixture.url,
        &legacy.key,
        "pg-v14-upgrade-legacy-attempt",
        legacy_now,
        legacy_now.saturating_add(60),
        &legacy.cluster_identity,
        &legacy.namespace,
        &legacy.deployment_uid,
    );
    let legacy_attempt_started = mark_v13_attempt(&fixture.url, &legacy.key, &legacy_claim);

    fixture.store.migrate().unwrap();
    fixture.store.validate_schema().unwrap();
    let mut client = Client::connect(&fixture.url, NoTls).unwrap();
    assert_v14_attempt_backfill(
        &mut client,
        &control_claim,
        "CONTROL_BOOTSTRAP_V13",
        Some(control_receipt.submission_id()),
        control_attempt_started,
    );
    assert_v14_attempt_backfill(
        &mut client,
        &legacy_claim,
        "LEGACY_BOOTSTRAP",
        None,
        legacy_attempt_started,
    );
    let historical_control_admission = fixture.store.admission_context(&control_key).unwrap();
    assert_eq!(historical_control_admission.key(), &control_key);
    assert_eq!(
        historical_control_admission.claim_id(),
        control_claim.claim_id
    );
    assert_eq!(
        historical_control_admission.fence(),
        u64::try_from(control_claim.fence).unwrap()
    );
    let historical_legacy_admission = fixture.store.admission_context(&legacy.key).unwrap();
    assert_eq!(historical_legacy_admission.key(), &legacy.key);
    assert_eq!(
        historical_legacy_admission.claim_id(),
        legacy_claim.claim_id
    );

    let request =
        DispatchAcquisitionRequest::new("pg-v14-upgrade-attempt-probe", Uuid::new_v4()).unwrap();
    match fixture
        .store
        .claim_next_pending_dispatch_or_recover(&control_key.scope, &request)
        .unwrap()
    {
        DispatchAcquisitionOutcome::RecoveryRequired(work) => {
            assert_eq!(
                work.disposition(),
                DispatchAcquisitionDisposition::AttemptInFlight
            );
            assert_eq!(work.recovery_key().acquisition_id(), control_claim.claim_id);
        }
        other => panic!("expected inert server-selected ATTEMPT recovery, got {other:?}"),
    }
    let legacy_request =
        DispatchAcquisitionRequest::new("pg-v14-upgrade-legacy-probe", Uuid::new_v4()).unwrap();
    assert!(matches!(
        fixture
            .store
            .claim_next_pending_dispatch_or_recover(&legacy.key.scope, &legacy_request)
            .unwrap(),
        DispatchAcquisitionOutcome::NoWork
    ));
    assert!(matches!(
        fixture.store.claim_dispatch(&DispatchClaimRequest {
            key: legacy.key.clone(),
            claim_id: Uuid::new_v4(),
            worker_id: "pg-v14-upgrade-legacy-reclaim".to_owned(),
        }),
        Err(StateError::DispatchAlreadyClaimed)
    ));

    // The two admission reads above are intentionally productive loader calls,
    // not catalog probes: they prove that exact v1 bootstrap ATTEMPT history
    // remains readable without inventing CREATE/ISSUE rows that never existed.
    // Opaque terminal witnesses remain covered by the terminal integration
    // suite, while neither historical branch can remint acquisition or broker
    // I/O authority.
}

#[test]
#[ignore = "requires guarded ACCORDLOCK_TEST_POSTGRES_URL for the dedicated accordlock_test_v2 database"]
#[allow(clippy::too_many_lines)]
fn postgres_v13_delete_v1_phases_upgrade_to_frozen_cleanup_without_remint() {
    let _serial = serial_postgres_test();
    for phase in [
        V13DeletePhase::Intent,
        V13DeletePhase::InFlight,
        V13DeletePhase::Unknown,
        V13DeletePhase::ReconcileOnly,
        V13DeletePhase::CommittedAbsent,
    ] {
        let mut fixture = ControlFixture::new();
        let (_receipt, key) = complete_control_dispatch(&fixture);
        let now = database_time(&fixture.url);
        let claimed_at = now.saturating_sub(10);
        let deployment_uid = format!("deployment-{}", fixture.tenant);
        let claim = insert_v13_claim(
            &fixture.url,
            &key,
            &format!(
                "pg-v14-upgrade-delete-{}",
                phase.database_phase().to_ascii_lowercase()
            ),
            claimed_at,
            claimed_at.saturating_add(30),
            "cluster-a",
            "payments",
            &deployment_uid,
        );
        let seed = insert_v13_broker_history(
            &fixture.url,
            &key,
            &claim,
            "cluster-a",
            "payments",
            &deployment_uid,
            Some(phase),
        );
        fixture.store.migrate().unwrap();
        fixture.store.validate_schema().unwrap();
        let capability = fixture.store.issue_broker_journal_capability().unwrap();
        let delete_entry_id = seed.delete_entry_id.unwrap();
        let mut client = Client::connect(&fixture.url, NoTls).unwrap();
        let bindings = client
            .query(
                "SELECT operation, origin_acquisition_id,
                        origin_lease_fence, acquisition_binding_version
                   FROM public.accordlock_broker_operations
                  WHERE tenant=$1 AND environment=$2 AND authorization_id=$3
                  ORDER BY operation",
                &[
                    &key.scope.tenant,
                    &key.scope.environment,
                    &key.authorization_id,
                ],
            )
            .unwrap();
        assert_eq!(bindings.len(), 2);
        for row in &bindings {
            assert_eq!(row.get::<_, Uuid>("origin_acquisition_id"), claim.claim_id);
            assert_eq!(row.get::<_, i64>("origin_lease_fence"), claim.fence);
            assert_eq!(row.get::<_, i16>("acquisition_binding_version"), 1);
        }

        let request = BrokerCleanupRequest::new(key.clone(), V13_BROKER_ROUTE).unwrap();
        match phase {
            V13DeletePhase::Intent => {
                let intent = fixture
                    .store
                    .prepare_broker_cleanup(&capability, &request)
                    .unwrap();
                assert_eq!(intent.audit().entry_id(), delete_entry_id);
                assert_eq!(intent.audit().phase(), BrokerJournalPhase::Intent);
                let io = fixture.store.begin_broker_io(&capability, intent).unwrap();
                assert_eq!(io.audit().phase(), BrokerJournalPhase::InFlight);
                assert_eq!(
                    fixture.store.mark_broker_io_unknown(io).unwrap().phase(),
                    BrokerJournalPhase::Unknown
                );
            }
            V13DeletePhase::InFlight | V13DeletePhase::Unknown | V13DeletePhase::ReconcileOnly => {}
            V13DeletePhase::CommittedAbsent => {
                let audit = fixture
                    .store
                    .broker_operation_audit(&key, BrokerJournalOperation::DeleteSecret)
                    .unwrap();
                assert_eq!(audit.entry_id(), delete_entry_id);
                assert_eq!(audit.phase(), BrokerJournalPhase::Committed);
                assert_eq!(audit.outcome(), Some(BrokerJournalOutcome::DeleteAbsent));
                let observations: i64 = client
                    .query_one(
                        "SELECT count(*)::bigint
                           FROM public.accordlock_broker_secret_deletion_observations
                          WHERE entry_id=$1 AND journal_request_commitment=$2
                            AND journal_result_commitment=$3",
                        &[
                            &delete_entry_id,
                            &audit.selector().request_commitment().to_string(),
                            &audit.result_commitment().unwrap().to_string(),
                        ],
                    )
                    .unwrap()
                    .get(0);
                assert_eq!(observations, 1);
                continue;
            }
        }

        let reconciliation = fixture
            .store
            .begin_broker_reconciliation(
                &capability,
                &BrokerReconciliationRequest::new(
                    key.clone(),
                    BrokerJournalOperation::DeleteSecret,
                    V13_BROKER_ROUTE,
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(
            reconciliation.audit().phase(),
            BrokerJournalPhase::ReconcileOnly
        );
        let receipt = match fixture
            .store
            .commit_broker_reconciliation(
                reconciliation,
                BrokerSecretObservation::absent([0x73; 32]).unwrap(),
            )
            .unwrap()
        {
            BrokerReconciliationResult::Completed(receipt) => receipt,
            BrokerReconciliationResult::Pending(_) => {
                panic!("DELETE absence must complete the exact historical cleanup")
            }
        };
        assert_eq!(receipt.audit().entry_id(), delete_entry_id);
        assert_eq!(receipt.audit().phase(), BrokerJournalPhase::Committed);
        assert_eq!(
            receipt.audit().outcome(),
            Some(BrokerJournalOutcome::DeleteAbsent)
        );
        let retained_binding: i16 = client
            .query_one(
                "SELECT acquisition_binding_version
                   FROM public.accordlock_broker_operations
                  WHERE entry_id=$1",
                &[&delete_entry_id],
            )
            .unwrap()
            .get(0);
        assert_eq!(retained_binding, 1);
        let observations: i64 = client
            .query_one(
                "SELECT count(*)::bigint
                   FROM public.accordlock_broker_secret_deletion_observations
                  WHERE entry_id=$1",
                &[&delete_entry_id],
            )
            .unwrap()
            .get(0);
        assert_eq!(observations, 1);
    }
}

#[test]
#[ignore = "requires guarded ACCORDLOCK_TEST_POSTGRES_URL for the dedicated accordlock_test_v2 database"]
#[allow(clippy::too_many_lines)]
fn postgres_v13_create_v1_accepts_only_new_acquisition_bound_delete_v2() {
    let _serial = serial_postgres_test();
    let mut fixture = ControlFixture::new();
    let (_receipt, key) = complete_control_dispatch(&fixture);
    let now = database_time(&fixture.url);
    let claimed_at = now.saturating_sub(10);
    let deployment_uid = format!("deployment-{}", fixture.tenant);
    let claim = insert_v13_claim(
        &fixture.url,
        &key,
        "pg-v14-upgrade-delete-v2",
        claimed_at,
        claimed_at.saturating_add(30),
        "cluster-a",
        "payments",
        &deployment_uid,
    );
    let seed = insert_v13_broker_history(
        &fixture.url,
        &key,
        &claim,
        "cluster-a",
        "payments",
        &deployment_uid,
        None,
    );
    assert!(seed.delete_entry_id.is_none());
    fixture.store.migrate().unwrap();
    fixture.store.validate_schema().unwrap();
    let capability = fixture.store.issue_broker_journal_capability().unwrap();
    let request = BrokerCleanupRequest::new(key.clone(), V13_BROKER_ROUTE).unwrap();
    let intent = fixture
        .store
        .prepare_broker_cleanup(&capability, &request)
        .unwrap();
    assert_eq!(intent.audit().phase(), BrokerJournalPhase::Intent);
    assert_eq!(intent.audit().origin_acquisition_id(), claim.claim_id);
    assert_eq!(
        intent.audit().origin_lease_fence(),
        u64::try_from(claim.fence).unwrap()
    );
    assert_eq!(
        intent.audit().bound_secret_uid(),
        Some(seed.bound_secret_uid.as_str())
    );
    let delete_entry_id = intent.audit().entry_id();
    let binding: i16 = Client::connect(&fixture.url, NoTls)
        .unwrap()
        .query_one(
            "SELECT acquisition_binding_version
               FROM public.accordlock_broker_operations
              WHERE entry_id=$1",
            &[&delete_entry_id],
        )
        .unwrap()
        .get(0);
    assert_eq!(binding, 2);

    let io = fixture.store.begin_broker_io(&capability, intent).unwrap();
    fixture.store.mark_broker_io_unknown(io).unwrap();
    let reconciliation = fixture
        .store
        .begin_broker_reconciliation(
            &capability,
            &BrokerReconciliationRequest::new(
                key.clone(),
                BrokerJournalOperation::DeleteSecret,
                V13_BROKER_ROUTE,
            )
            .unwrap(),
        )
        .unwrap();
    let completion = fixture
        .store
        .commit_broker_reconciliation(
            reconciliation,
            BrokerSecretObservation::absent([0x74; 32]).unwrap(),
        )
        .unwrap();
    let receipt = match completion {
        BrokerReconciliationResult::Completed(receipt) => receipt,
        BrokerReconciliationResult::Pending(_) => {
            panic!("DELETE absence must complete the new v2 cleanup")
        }
    };
    assert_eq!(receipt.audit().phase(), BrokerJournalPhase::Committed);
    assert_eq!(
        receipt.audit().outcome(),
        Some(BrokerJournalOutcome::DeleteAbsent)
    );
    let versions: (i16, i16) = Client::connect(&fixture.url, NoTls)
        .unwrap()
        .query_one(
            "SELECT
                 (SELECT acquisition_binding_version
                    FROM public.accordlock_broker_operations
                   WHERE tenant=$1 AND environment=$2 AND authorization_id=$3
                     AND operation='CREATE_SECRET'),
                 (SELECT acquisition_binding_version
                    FROM public.accordlock_broker_operations
                   WHERE tenant=$1 AND environment=$2 AND authorization_id=$3
                     AND operation='DELETE_SECRET')",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
            ],
        )
        .map(|row| (row.get(0), row.get(1)))
        .unwrap();
    assert_eq!(versions, (1, 2));
}

#[test]
#[ignore = "requires guarded ACCORDLOCK_TEST_POSTGRES_URL for the dedicated accordlock_test_v2 database"]
fn postgres_v13_missing_outbox_aborts_v14_atomically_and_leaves_ledger_at_13() {
    let _serial = serial_postgres_test();
    let fixture = ControlFixture::new();
    let (_receipt, key) = complete_control_dispatch(&fixture);
    let now = database_time(&fixture.url);
    let claim = insert_v13_claim(
        &fixture.url,
        &key,
        "pg-v14-upgrade-corrupt-worker",
        now,
        now.saturating_add(30),
        "cluster-a",
        "payments",
        &format!("deployment-{}", fixture.tenant),
    );
    let mut client = Client::connect(&fixture.url, NoTls).unwrap();

    client
        .batch_execute(
            "CREATE TEMP TABLE accordlock_v14_upgrade_outbox_backup
                 ON COMMIT PRESERVE ROWS AS
             SELECT * FROM public.accordlock_execution_outbox WHERE FALSE;",
        )
        .unwrap();
    assert_eq!(
        client
            .execute(
                "INSERT INTO accordlock_v14_upgrade_outbox_backup
                 SELECT * FROM public.accordlock_execution_outbox
                  WHERE tenant=$1 AND environment=$2 AND authorization_id=$3
                    AND transaction_id=$4",
                &[
                    &key.scope.tenant,
                    &key.scope.environment,
                    &key.authorization_id,
                    &key.transaction_id,
                ],
            )
            .unwrap(),
        1
    );
    // Model a structurally corrupt v13 snapshot produced outside the trusted
    // DB-writer boundary: the FK catalog remains present/validated, but its
    // enforcement trigger is bypassed for this one row deletion.
    client
        .batch_execute("SET session_replication_role = replica;")
        .unwrap();
    let deleted = client
        .execute(
            "DELETE FROM public.accordlock_execution_outbox
              WHERE tenant=$1 AND environment=$2 AND authorization_id=$3
                AND transaction_id=$4",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
            ],
        )
        .unwrap();
    client
        .batch_execute("SET session_replication_role = origin;")
        .unwrap();
    assert_eq!(deleted, 1);

    let migration_error = fixture.store.migrate().unwrap_err();
    match &migration_error {
        StateError::Database(error) => assert_eq!(
            error
                .as_db_error()
                .map_or("", postgres::error::DbError::message),
            "v13 dispatch claims cannot be backfilled to exact v14 acquisitions"
        ),
        other => panic!("unexpected migration failure: {other}"),
    }

    let rolled_back: (i32, bool, bool, bool, bool, bool) = client
        .query_one(
            "SELECT max(version),
                    bool_and(version <> 14),
                    to_regclass('public.accordlock_dispatch_request_identities') IS NULL,
                    to_regclass('public.accordlock_dispatch_acquisitions') IS NULL,
                    to_regclass('public.accordlock_dispatch_queue_dispositions') IS NULL,
                    NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                         WHERE table_schema='public'
                           AND table_name='accordlock_dispatch_claims'
                           AND column_name='attempt_acquisition_id'
                    )
               FROM public.accordlock_schema_migrations",
            &[],
        )
        .map(|row| {
            (
                row.get(0),
                row.get(1),
                row.get(2),
                row.get(3),
                row.get(4),
                row.get(5),
            )
        })
        .unwrap();
    assert_eq!(rolled_back, (13, true, true, true, true, true));
    assert_eq!(
        client
            .query_one(
                "SELECT count(*)::bigint FROM public.accordlock_dispatch_claims
                  WHERE claim_id=$1",
                &[&claim.claim_id],
            )
            .unwrap()
            .get::<_, i64>(0),
        1
    );

    // Restore the disposable database so test order cannot leak a v13 schema.
    assert_eq!(
        client
            .execute(
                "INSERT INTO public.accordlock_execution_outbox
                 SELECT * FROM accordlock_v14_upgrade_outbox_backup",
                &[],
            )
            .unwrap(),
        1
    );
    client
        .batch_execute("DROP TABLE accordlock_v14_upgrade_outbox_backup")
        .unwrap();
    fixture.store.migrate().unwrap();
    fixture.store.validate_schema().unwrap();
}
