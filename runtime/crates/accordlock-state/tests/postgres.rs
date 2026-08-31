#![allow(clippy::panic, clippy::unwrap_used)]

use std::env;
use std::net::{IpAddr, SocketAddr};
use std::process::{Command, Stdio};
use std::str::FromStr as _;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use accordlock_eks_profile::{
    CaTrustCommitment, EksBrokerManagementBindings, EksCredentialLifecyclePolicy,
    EksManagementAuthorityBinding, EksRouteProfile, EksRouteProfileInput, PinnedSocketTarget,
};
use accordlock_protocol::{
    AuthorityDomainState, AuthorityVector, CanonicalEncode, CapabilityGrant, DeploymentTemplate,
    Digest32, EXECUTION_AUTHORIZATION_DOMAIN, ExecutionAuthorization, SignedAuthorization,
    SigningIdentity, authorization_signer_root, canonical_hash, sign_cose,
};
use accordlock_state::{
    AdmissionAuthorizationRequest, BrokerCleanupRequest, BrokerCredentialSafetyPolicy,
    BrokerJournalOperation, BrokerJournalOutcome, BrokerJournalPhase, BrokerJournalState,
    BrokerOperationRequest, BrokerReconciliationRequest, BrokerSecretObservation,
    BrokerTokenIssueObservation, ConsumeKey, DispatchClaimRequest, DispatchClaimToken,
    DispatchCredentialBinding, DispatchDeadlinePolicy, EksDestinationProfile,
    EksDestinationRegistryState, EksRegistryError, GrantRegistration, IngressNonceConsumption,
    IngressReplayDecision, IngressReplayScope, IngressReplayState, IssuedAuthorizationRecord,
    PostgresStore, Scope, StateError, TerminalRetirementContext, TerminalRetirementRequest,
    TerminalRetirementState, TransactionalState, grant_revocation_root,
};
use accordlock_terminal_witness::{
    ActivatedWitnessRegistry, CredentialRetirementClaims, EffectObservationClaims,
    EffectObservationResult, ExactExecutionOutcome, MAX_TERMINAL_WITNESS_ENVELOPE_BYTES,
    RegisteredWitnessVerifier, RetirementBasis, SignedEffectWitness, WitnessIssuer,
    WitnessRegistryAuthority, WitnessRole, WitnessScope, WitnessVerifierStatus,
    sign_credential_retirement, sign_effect_observation,
};
use postgres::types::ToSql;
use postgres::{Client, Config, NoTls, config::Host};
use uuid::Uuid;

const CLAIM_CHILD_REQUEST_ENV: &str = "ACCORDLOCK_TEST_DISPATCH_CLAIM_CHILD_REQUEST";
const ADMISSION_CHILD_REQUEST_ENV: &str = "ACCORDLOCK_TEST_ADMISSION_CHILD_REQUEST";
const BROKER_CHILD_REQUEST_ENV: &str = "ACCORDLOCK_TEST_BROKER_CHILD_REQUEST";
const INGRESS_CHILD_SCOPE_ENV: &str = "ACCORDLOCK_TEST_INGRESS_CHILD_SCOPE";
const INGRESS_CHILD_NONCE_ENV: &str = "ACCORDLOCK_TEST_INGRESS_CHILD_NONCE";
const EKS_REGISTRY_CHILD_TENANT_ENV: &str = "ACCORDLOCK_TEST_EKS_REGISTRY_CHILD_TENANT";
const EKS_REGISTRY_CHILD_CLUSTER_ENV: &str = "ACCORDLOCK_TEST_EKS_REGISTRY_CHILD_CLUSTER";
const EKS_REGISTRY_CHILD_DEPLOYMENT_ENV: &str = "ACCORDLOCK_TEST_EKS_REGISTRY_CHILD_DEPLOYMENT";
const EKS_REGISTRY_CHILD_API_IDENTITY_ENV: &str = "ACCORDLOCK_TEST_EKS_REGISTRY_CHILD_API_IDENTITY";
const BROKER_PROCESS_ROUTE: [u8; 32] = [55; 32];
const TEST_DATABASE_URL_ENV: &str = "ACCORDLOCK_TEST_POSTGRES_URL";
const RESET_CONFIRMATION_ENV: &str = "ACCORDLOCK_TEST_POSTGRES_V14_RESET";
const RESET_CONFIRMATION: &str = "DROP_PUBLIC_SCHEMA_OF_ACCORDLOCK_TEST_V2";
const DISPOSABLE_DATABASE_NAME: &str = "accordlock_test_v2";

fn digest(label: &str) -> Digest32 {
    Digest32::sha256(label.as_bytes())
}

fn domain(label: &str, epoch: u64) -> AuthorityDomainState {
    AuthorityDomainState {
        root: digest(label),
        epoch,
        activation_id: Uuid::new_v4(),
    }
}

fn authority() -> AuthorityVector {
    let suffix = Uuid::new_v4().to_string();
    let signer = authorization_signer();
    let mut authority = AuthorityVector {
        policy: domain(&format!("policy-{suffix}"), 1),
        registry: domain(&format!("registry-{suffix}"), 1),
        revocation: domain(&format!("revocation-{suffix}"), 1),
        connector: domain(&format!("connector-{suffix}"), 1),
        resource: domain(&format!("resource-{suffix}"), 1),
        signer: domain(&format!("signer-{suffix}"), 1),
        mediation: domain(&format!("mediation-{suffix}"), 1),
        grant_registry: domain(&format!("grant-{suffix}"), 1),
        office_act_registry: domain(&format!("office-{suffix}"), 1),
        principal_registry: domain(&format!("principal-{suffix}"), 1),
        workload_build_allowlist: domain(&format!("build-{suffix}"), 1),
        kernel_configuration: domain(&format!("kernel-{suffix}"), 1),
    };
    authority.signer.root =
        authorization_signer_root(signer.key_id(), signer.public_key_bytes()).unwrap();
    authority
}

fn authorization_signer() -> SigningIdentity {
    SigningIdentity::from_seed("state-postgres-authorization", [92; 32])
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

fn replica_execute(client: &mut Client, statement: &str, params: &[&(dyn ToSql + Sync)]) -> u64 {
    let mut transaction = client.transaction().unwrap();
    transaction
        .batch_execute("SET LOCAL session_replication_role = replica")
        .unwrap();
    let affected = transaction.execute(statement, params).unwrap();
    transaction.commit().unwrap();
    affected
}

fn replica_batch_execute(client: &mut Client, statement: &str) {
    let mut transaction = client.transaction().unwrap();
    transaction
        .batch_execute("SET LOCAL session_replication_role = replica")
        .unwrap();
    transaction.batch_execute(statement).unwrap();
    transaction.commit().unwrap();
}

fn set_scope_high_water(url: &str, scope: &Scope, observed_time: i64) {
    let updated = Client::connect(url, NoTls)
        .unwrap()
        .execute(
            "UPDATE public.accordlock_time_high_water
                SET observed_unix_s = $3
              WHERE tenant = $1 AND environment = $2",
            &[&scope.tenant, &scope.environment, &observed_time],
        )
        .unwrap();
    assert_eq!(updated, 1);
}

fn set_high_water(url: &str, key: &ConsumeKey, observed_time: i64) {
    set_scope_high_water(url, &key.scope, observed_time);
}

fn unique_tenant(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4().simple())
}

fn register_fixture(
    store: &PostgresStore,
    tenant: &str,
    now: i64,
    consume_before: i64,
    maximum_uses: u32,
) -> ConsumeKey {
    register_fixture_for_resource(
        store,
        tenant,
        now,
        consume_before,
        maximum_uses,
        "cluster-a",
        "payments",
        &format!("deployment-uid-{tenant}"),
    )
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
fn register_fixture_for_resource(
    store: &PostgresStore,
    tenant: &str,
    now: i64,
    consume_before: i64,
    maximum_uses: u32,
    cluster_identity: &str,
    namespace: &str,
    deployment_uid: &str,
) -> ConsumeKey {
    let environment = "test".to_owned();
    let scope = Scope::new(tenant, &environment).unwrap();
    let grant_id = Uuid::new_v4();
    let authorization_id = Uuid::new_v4();
    let transaction_id = Uuid::new_v4();
    let capability = CapabilityGrant {
        grant_id,
        holder: "workload-a".to_owned(),
        tenant: tenant.to_owned(),
        operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
        repository: "acme/payments".to_owned(),
        audience: "accordlock-executor:test".to_owned(),
        cluster_identity: cluster_identity.to_owned(),
        namespace: namespace.to_owned(),
        deployment_uid: deployment_uid.to_owned(),
        container: "app".to_owned(),
        image_repository: "registry.example/acme/payments".to_owned(),
        not_before: now.saturating_sub(60),
        expires_at: consume_before.saturating_add(600),
        maximum_uses,
    };
    let mut auth = authority();
    auth.grant_registry.root = canonical_hash(&capability).unwrap();
    store
        .compare_and_activate_authority(&scope, None, &auth)
        .unwrap();
    let grant = GrantRegistration {
        environment: environment.clone(),
        grant: capability,
        authority: auth.clone(),
        dispatch_deadline_policy: DispatchDeadlinePolicy {
            max_dispatch_delay_seconds: 30,
            profile_hard_cap: consume_before.saturating_add(600),
            immutable_dependency_expiries: vec![consume_before.saturating_add(600)],
        },
    };
    store.register_grant(&grant).unwrap();

    let template = DeploymentTemplate {
        operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
        environment: environment.clone(),
        audience: "accordlock-executor:test".to_owned(),
        repository: "acme/payments".to_owned(),
        commit_sha: "1111111111111111111111111111111111111111".to_owned(),
        image_repository: "registry.example/acme/payments".to_owned(),
        image_digest: digest("new-image"),
        cluster_identity: cluster_identity.to_owned(),
        namespace: namespace.to_owned(),
        deployment: "payments".to_owned(),
        deployment_uid: deployment_uid.to_owned(),
        container: "app".to_owned(),
        container_index: 0,
        prior_image_digest: digest("old-image"),
        resource_version: "1001".to_owned(),
        prior_projection_hash: digest("projection"),
        prior_transaction_annotation: Some("none".to_owned()),
        prior_authorization_annotation: Some("none".to_owned()),
        prior_operation_hash_annotation: Some("none".to_owned()),
    };
    let template_hash = canonical_hash(&template).unwrap();
    let authorization = ExecutionAuthorization {
        schema_version: accordlock_protocol::EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
        authorization_id,
        evaluation_nonce: Uuid::new_v4(),
        request_id: Uuid::new_v4(),
        tenant: tenant.to_owned(),
        holder: "workload-a".to_owned(),
        audience: "accordlock-executor:test".to_owned(),
        issued_at: now.saturating_sub(1),
        not_before: now.saturating_sub(1),
        consume_before,
        dispatch_deadline_policy: grant.dispatch_deadline_policy.clone(),
        grant_id,
        template,
        template_hash,
        evidence_root: digest("evidence"),
        principals: vec!["principal-a".to_owned()],
        policy_root: auth.policy.root,
        authority: auth,
    };
    let signer = authorization_signer();
    let cose_sign1 = sign_cose(
        &authorization.canonical_bytes().unwrap(),
        EXECUTION_AUTHORIZATION_DOMAIN,
        &signer,
    )
    .unwrap();
    let record = IssuedAuthorizationRecord::new(
        transaction_id,
        SignedAuthorization {
            authorization,
            cose_sign1,
        },
        signer.key_id().to_owned(),
        signer.public_key_bytes(),
    )
    .unwrap();
    store.record_issued_authorization(&record).unwrap();

    ConsumeKey {
        scope,
        transaction_id,
        authorization_id,
    }
}

fn is_loopback_destructive_test_host(host: &Host) -> bool {
    match host {
        Host::Tcp(host) if host.eq_ignore_ascii_case("localhost") => true,
        Host::Tcp(host) => host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()),
        #[cfg(unix)]
        Host::Unix(_) => true,
    }
}

fn validate_historical_rebuild_target(url: &str, confirmation: Option<&str>) -> Result<(), String> {
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
        || !config
            .get_hosts()
            .iter()
            .all(is_loopback_destructive_test_host)
        || !config.get_hostaddrs().iter().all(IpAddr::is_loopback)
    {
        return Err(format!(
            "{TEST_DATABASE_URL_ENV} must use only loopback hosts or a local Unix socket"
        ));
    }
    Ok(())
}

#[test]
fn postgres_historical_rebuild_target_guard_is_fail_closed() {
    let local = "postgresql://postgres@127.0.0.1:55432/accordlock_test_v2";
    assert!(validate_historical_rebuild_target(local, None).is_err());
    assert!(validate_historical_rebuild_target(local, Some("wrong-confirmation")).is_err());
    assert!(
        validate_historical_rebuild_target(
            "postgresql://postgres@127.0.0.1:55432/postgres",
            Some(RESET_CONFIRMATION),
        )
        .is_err()
    );
    assert!(
        validate_historical_rebuild_target(
            "postgresql://postgres@192.0.2.1:55432/accordlock_test_v2",
            Some(RESET_CONFIRMATION),
        )
        .is_err()
    );
    validate_historical_rebuild_target(local, Some(RESET_CONFIRMATION)).unwrap();
}

fn configured_store() -> (String, PostgresStore) {
    let url = env::var(TEST_DATABASE_URL_ENV)
        .unwrap_or_else(|_| panic!("{TEST_DATABASE_URL_ENV} is required"));
    let store = PostgresStore::new(url.clone());
    store.migrate().unwrap();
    (url, store)
}

fn configured_historical_rebuild_store() -> (String, PostgresStore) {
    let url = env::var(TEST_DATABASE_URL_ENV)
        .unwrap_or_else(|_| panic!("{TEST_DATABASE_URL_ENV} is required"));
    let confirmation = env::var(RESET_CONFIRMATION_ENV).ok();
    validate_historical_rebuild_target(&url, confirmation.as_deref()).unwrap_or_else(|error| {
        panic!("historical PostgreSQL rebuild guard rejected target: {error}")
    });
    let store = PostgresStore::new(url.clone());
    store.migrate().unwrap();
    (url, store)
}

const HISTORICAL_POSTGRES_MIGRATIONS: [(&str, &str); 11] = [
    (
        "0001_transactional_state",
        include_str!("../../../migrations/0001_transactional_state.sql"),
    ),
    (
        "0002_state_integrity",
        include_str!("../../../migrations/0002_state_integrity.sql"),
    ),
    (
        "0003_state_instance",
        include_str!("../../../migrations/0003_state_instance.sql"),
    ),
    (
        "0004_signed_issuance_profile",
        include_str!("../../../migrations/0004_signed_issuance_profile.sql"),
    ),
    (
        "0005_dispatch_claims",
        include_str!("../../../migrations/0005_dispatch_claims.sql"),
    ),
    (
        "0006_physical_resource_reservations",
        include_str!("../../../migrations/0006_physical_resource_reservations.sql"),
    ),
    (
        "0007_admission_authorizations",
        include_str!("../../../migrations/0007_admission_authorizations.sql"),
    ),
    (
        "0008_attempt_credential_binding",
        include_str!("../../../migrations/0008_attempt_credential_binding.sql"),
    ),
    (
        "0009_broker_operation_journal",
        include_str!("../../../migrations/0009_broker_operation_journal.sql"),
    ),
    (
        "0010_ingress_replay",
        include_str!("../../../migrations/0010_ingress_replay.sql"),
    ),
    (
        "0011_eks_destination_registry",
        include_str!("../../../migrations/0011_eks_destination_registry.sql"),
    ),
];

fn rebuild_disposable_postgres_through(client: &mut Client, url: &str, version: usize) {
    assert!((1..=HISTORICAL_POSTGRES_MIGRATIONS.len()).contains(&version));
    let confirmation = env::var(RESET_CONFIRMATION_ENV).ok();
    validate_historical_rebuild_target(url, confirmation.as_deref()).unwrap_or_else(|error| {
        panic!("historical PostgreSQL rebuild guard rejected target: {error}")
    });
    client
        .batch_execute("BEGIN; DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        .unwrap();
    for (_, sql) in HISTORICAL_POSTGRES_MIGRATIONS.iter().take(version) {
        client.batch_execute(sql).unwrap();
    }
    let ledger: Vec<(i32, String)> = client
        .query(
            "SELECT version, name
               FROM public.accordlock_schema_migrations
              ORDER BY version",
            &[],
        )
        .unwrap()
        .into_iter()
        .map(|row| (row.get("version"), row.get("name")))
        .collect();
    let expected: Vec<(i32, String)> = HISTORICAL_POSTGRES_MIGRATIONS
        .iter()
        .take(version)
        .enumerate()
        .map(|(index, (name, _))| (i32::try_from(index + 1).unwrap(), (*name).to_owned()))
        .collect();
    assert_eq!(ledger, expected);
    client.batch_execute("COMMIT;").unwrap();
}

#[allow(clippy::too_many_lines)]
fn snapshot_v5_claim_fixture(client: &mut Client, key: &ConsumeKey) {
    client
        .batch_execute(
            "CREATE TEMP TABLE accordlock_test_v5_fixture_backup (
                 kind TEXT PRIMARY KEY,
                 row_json JSONB NOT NULL
             ) ON COMMIT PRESERVE ROWS;",
        )
        .unwrap();
    let statements = [
        (
            "state_metadata",
            "SELECT to_jsonb(source)
               FROM public.accordlock_state_metadata AS source
              WHERE singleton = TRUE",
            Vec::<&(dyn ToSql + Sync)>::new(),
        ),
        (
            "authority",
            "SELECT to_jsonb(source)
               FROM public.accordlock_authority_state AS source
              WHERE tenant = $1 AND environment = $2",
            vec![
                &key.scope.tenant as &(dyn ToSql + Sync),
                &key.scope.environment,
            ],
        ),
        (
            "grant",
            "SELECT to_jsonb(source)
               FROM public.accordlock_grants AS source
              WHERE tenant = $1 AND environment = $2
                AND grant_id = (
                    SELECT grant_id
                      FROM public.accordlock_issued_authorizations
                     WHERE tenant = $1 AND environment = $2
                       AND authorization_id = $3 AND transaction_id = $4
                )",
            vec![
                &key.scope.tenant as &(dyn ToSql + Sync),
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
            ],
        ),
        (
            "issued",
            "SELECT to_jsonb(source)
               FROM public.accordlock_issued_authorizations AS source
              WHERE tenant = $1 AND environment = $2
                AND authorization_id = $3 AND transaction_id = $4",
            vec![
                &key.scope.tenant as &(dyn ToSql + Sync),
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
            ],
        ),
        (
            "high_water",
            "SELECT to_jsonb(source)
               FROM public.accordlock_time_high_water AS source
              WHERE tenant = $1 AND environment = $2",
            vec![
                &key.scope.tenant as &(dyn ToSql + Sync),
                &key.scope.environment,
            ],
        ),
        (
            "consumption",
            "SELECT to_jsonb(source)
               FROM public.accordlock_consumptions AS source
              WHERE tenant = $1 AND environment = $2
                AND authorization_id = $3 AND transaction_id = $4",
            vec![
                &key.scope.tenant as &(dyn ToSql + Sync),
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
            ],
        ),
        (
            "outbox",
            "SELECT to_jsonb(source)
               FROM public.accordlock_execution_outbox AS source
              WHERE tenant = $1 AND environment = $2
                AND authorization_id = $3 AND transaction_id = $4",
            vec![
                &key.scope.tenant as &(dyn ToSql + Sync),
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
            ],
        ),
        (
            "claim",
            "SELECT to_jsonb(source)
               FROM public.accordlock_dispatch_claims AS source
              WHERE tenant = $1 AND environment = $2
                AND authorization_id = $3 AND transaction_id = $4
                AND state = 'CLAIMED'
                AND acquisition_binding_version IS NULL",
            vec![
                &key.scope.tenant as &(dyn ToSql + Sync),
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
            ],
        ),
    ];
    for (kind, query, params) in statements {
        let row_json: serde_json::Value = client.query_one(query, &params).unwrap().get(0);
        assert_eq!(
            client
                .execute(
                    "INSERT INTO pg_temp.accordlock_test_v5_fixture_backup
                            (kind, row_json)
                     VALUES ($1, $2)",
                    &[&kind, &row_json],
                )
                .unwrap(),
            1
        );
    }
}

fn restore_v5_claim_fixture(client: &mut Client) {
    client
        .batch_execute(
            "DELETE FROM public.accordlock_state_metadata;
             INSERT INTO public.accordlock_state_metadata
             SELECT restored.*
               FROM pg_temp.accordlock_test_v5_fixture_backup AS backup
               CROSS JOIN LATERAL jsonb_populate_record(
                   NULL::public.accordlock_state_metadata, backup.row_json
               ) AS restored
              WHERE backup.kind = 'state_metadata';
             INSERT INTO public.accordlock_authority_state
             SELECT restored.*
               FROM pg_temp.accordlock_test_v5_fixture_backup AS backup
               CROSS JOIN LATERAL jsonb_populate_record(
                   NULL::public.accordlock_authority_state, backup.row_json
               ) AS restored
              WHERE backup.kind = 'authority';
             INSERT INTO public.accordlock_grants
             SELECT restored.*
               FROM pg_temp.accordlock_test_v5_fixture_backup AS backup
               CROSS JOIN LATERAL jsonb_populate_record(
                   NULL::public.accordlock_grants, backup.row_json
               ) AS restored
              WHERE backup.kind = 'grant';
             INSERT INTO public.accordlock_issued_authorizations
             SELECT restored.*
               FROM pg_temp.accordlock_test_v5_fixture_backup AS backup
               CROSS JOIN LATERAL jsonb_populate_record(
                   NULL::public.accordlock_issued_authorizations, backup.row_json
               ) AS restored
              WHERE backup.kind = 'issued';
             INSERT INTO public.accordlock_time_high_water
             SELECT restored.*
               FROM pg_temp.accordlock_test_v5_fixture_backup AS backup
               CROSS JOIN LATERAL jsonb_populate_record(
                   NULL::public.accordlock_time_high_water, backup.row_json
               ) AS restored
              WHERE backup.kind = 'high_water';
             INSERT INTO public.accordlock_consumptions
             SELECT restored.*
               FROM pg_temp.accordlock_test_v5_fixture_backup AS backup
               CROSS JOIN LATERAL jsonb_populate_record(
                   NULL::public.accordlock_consumptions, backup.row_json
               ) AS restored
              WHERE backup.kind = 'consumption';
             INSERT INTO public.accordlock_execution_outbox
             SELECT restored.*
               FROM pg_temp.accordlock_test_v5_fixture_backup AS backup
               CROSS JOIN LATERAL jsonb_populate_record(
                   NULL::public.accordlock_execution_outbox, backup.row_json
               ) AS restored
              WHERE backup.kind = 'outbox';
             INSERT INTO public.accordlock_dispatch_claims
                 OVERRIDING SYSTEM VALUE
             SELECT restored.*
               FROM pg_temp.accordlock_test_v5_fixture_backup AS backup
               CROSS JOIN LATERAL jsonb_populate_record(
                   NULL::public.accordlock_dispatch_claims, backup.row_json
               ) AS restored
              WHERE backup.kind = 'claim';
             SELECT pg_catalog.setval(
                 pg_catalog.pg_get_serial_sequence(
                     'public.accordlock_dispatch_claims', 'fence'
                 ),
                 (SELECT max(fence) FROM public.accordlock_dispatch_claims),
                 TRUE
             );
             DROP TABLE pg_temp.accordlock_test_v5_fixture_backup;",
        )
        .unwrap();
}

fn postgres_registry_management_bindings() -> EksBrokerManagementBindings {
    EksBrokerManagementBindings::new(
        EksManagementAuthorityBinding::new("spiffe://accordlock.test/secret", [0x81; 32]).unwrap(),
        EksManagementAuthorityBinding::new("spiffe://accordlock.test/token", [0x82; 32]).unwrap(),
        EksManagementAuthorityBinding::new("spiffe://accordlock.test/review", [0x83; 32]).unwrap(),
    )
    .unwrap()
}

fn postgres_registry_profile(
    cluster_identity: &str,
    deployment_uid: &str,
    api_server_identity: &str,
) -> EksDestinationProfile {
    postgres_registry_profile_with_terminal(
        cluster_identity,
        deployment_uid,
        api_server_identity,
        [0x51; 32],
    )
}

fn postgres_registry_profile_with_terminal(
    cluster_identity: &str,
    deployment_uid: &str,
    api_server_identity: &str,
    terminal_registry_commitment: [u8; 32],
) -> EksDestinationProfile {
    postgres_registry_profile_with_policy(
        cluster_identity,
        deployment_uid,
        api_server_identity,
        terminal_registry_commitment,
        EksCredentialLifecyclePolicy::new(600, 900, 5, 60).unwrap(),
    )
}

fn postgres_registry_profile_with_policy(
    cluster_identity: &str,
    deployment_uid: &str,
    api_server_identity: &str,
    terminal_registry_commitment: [u8; 32],
    credential_lifecycle_policy: EksCredentialLifecyclePolicy,
) -> EksDestinationProfile {
    let route = EksRouteProfile::new(EksRouteProfileInput {
        cluster_trust_domain: "spiffe://example.test/eks/registry",
        cluster_identity,
        api_server_identity,
        dns_server_name: "api.registry.eks.amazonaws.com",
        port: 443,
        socket_target: PinnedSocketTarget::new(SocketAddr::from_str("192.0.2.60:443").unwrap())
            .unwrap(),
        ca_trust_commitment: CaTrustCommitment::from_der_certificates(&[
            b"postgres-registry-ca".to_vec()
        ])
        .unwrap(),
        namespace: "payments",
        deployment_name: "payments",
        deployment_uid,
        attempt_service_account_name: "accordlock-attempt",
        attempt_service_account_uid: "22222222-2222-4222-8222-222222222222",
        token_audience: "urn:accordlock:kubernetes-api:registry",
    })
    .unwrap();
    EksDestinationProfile::new(
        route,
        [0x41; 32],
        terminal_registry_commitment,
        credential_lifecycle_policy,
        postgres_registry_management_bindings(),
    )
    .unwrap()
}

fn postgres_registry_authority(
    scope: &Scope,
    profile: &EksDestinationProfile,
    capability: Option<&CapabilityGrant>,
) -> AuthorityVector {
    let mut active = authority();
    active.resource.root = profile.resource_root(scope).unwrap();
    active.mediation.root = profile.mediation_root(scope, &active.resource).unwrap();
    if let Some(capability) = capability {
        active.grant_registry.root = canonical_hash(capability).unwrap();
    }
    active
}

#[allow(clippy::type_complexity)]
#[allow(clippy::too_many_lines)]
fn register_postgres_registry_fixture(
    url: &str,
    store: &PostgresStore,
) -> (
    ConsumeKey,
    DispatchClaimToken,
    EksDestinationProfile,
    AuthorityVector,
) {
    let now = database_time(url);
    let tenant = unique_tenant("eks-registry");
    let scope = Scope::new(&tenant, "test").unwrap();
    let deployment_uid = Uuid::new_v4().to_string();
    let cluster_identity = format!("urn:accordlock:cluster:{}", Uuid::new_v4().simple());
    let api_server_identity = digest(&format!("api-{deployment_uid}")).to_string();
    let profile =
        postgres_registry_profile(&cluster_identity, &deployment_uid, &api_server_identity);
    let grant_id = Uuid::new_v4();
    let capability = CapabilityGrant {
        grant_id,
        holder: "workload-a".to_owned(),
        tenant: tenant.clone(),
        operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
        repository: "acme/payments".to_owned(),
        audience: "accordlock-executor:test".to_owned(),
        cluster_identity: cluster_identity.clone(),
        namespace: "payments".to_owned(),
        deployment_uid: deployment_uid.clone(),
        container: "app".to_owned(),
        image_repository: "registry.example/acme/payments".to_owned(),
        not_before: now.saturating_sub(60),
        expires_at: now.saturating_add(600),
        maximum_uses: 1,
    };
    let active = postgres_registry_authority(&scope, &profile, Some(&capability));
    store
        .compare_and_activate_authority(&scope, None, &active)
        .unwrap();
    store.activate_eks_destination(&scope, &profile).unwrap();
    let deadline_policy = DispatchDeadlinePolicy {
        max_dispatch_delay_seconds: 60,
        profile_hard_cap: now.saturating_add(600),
        immutable_dependency_expiries: vec![now.saturating_add(600)],
    };
    store
        .register_grant(&GrantRegistration {
            environment: scope.environment.clone(),
            grant: capability,
            authority: active.clone(),
            dispatch_deadline_policy: deadline_policy.clone(),
        })
        .unwrap();
    let template = DeploymentTemplate {
        operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
        environment: scope.environment.clone(),
        audience: "accordlock-executor:test".to_owned(),
        repository: "acme/payments".to_owned(),
        commit_sha: "1111111111111111111111111111111111111111".to_owned(),
        image_repository: "registry.example/acme/payments".to_owned(),
        image_digest: digest("registry-new-image"),
        cluster_identity,
        namespace: "payments".to_owned(),
        deployment: "payments".to_owned(),
        deployment_uid,
        container: "app".to_owned(),
        container_index: 0,
        prior_image_digest: digest("registry-old-image"),
        resource_version: "1001".to_owned(),
        prior_projection_hash: digest("registry-projection"),
        prior_transaction_annotation: Some("none".to_owned()),
        prior_authorization_annotation: Some("none".to_owned()),
        prior_operation_hash_annotation: Some("none".to_owned()),
    };
    let authorization_id = Uuid::new_v4();
    let transaction_id = Uuid::new_v4();
    let authorization = ExecutionAuthorization {
        schema_version: accordlock_protocol::EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
        authorization_id,
        evaluation_nonce: Uuid::new_v4(),
        request_id: Uuid::new_v4(),
        tenant,
        holder: "workload-a".to_owned(),
        audience: "accordlock-executor:test".to_owned(),
        issued_at: now.saturating_sub(1),
        not_before: now.saturating_sub(1),
        consume_before: now.saturating_add(300),
        dispatch_deadline_policy: deadline_policy,
        grant_id,
        template_hash: canonical_hash(&template).unwrap(),
        template,
        evidence_root: digest("registry-evidence"),
        principals: vec!["principal-a".to_owned()],
        policy_root: active.policy.root,
        authority: active.clone(),
    };
    let signer = authorization_signer();
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
    let claim = store
        .claim_dispatch(&dispatch_claim_request(
            &key,
            Uuid::new_v4(),
            "worker-registry",
        ))
        .unwrap()
        .token()
        .clone();
    (key, claim, profile, active)
}

const TERMINAL_EFFECT_OBSERVER: &str = "spiffe://accordlock.test/observer/effect";
const TERMINAL_RETIREMENT_OBSERVER: &str = "spiffe://accordlock.test/observer/retirement";
const TERMINAL_AUTHORITY_VERSION: u64 = 7;
const TERMINAL_CREDENTIAL_ID: &str = "AUTHORIZATION_ID=7ee52be0-9045-4653-aa5e-0da57b8dccdc";

struct TerminalPostgresFixture {
    url: String,
    store: PostgresStore,
    key: ConsumeKey,
    token: DispatchClaimToken,
    registry: ActivatedWitnessRegistry,
    effect_signer: SigningIdentity,
    retirement_signer: SigningIdentity,
    resource_activation_id: Uuid,
    mediation_activation_id: Uuid,
    deployment_uid: String,
    active: AuthorityVector,
    capability: CapabilityGrant,
    deadline_policy: DispatchDeadlinePolicy,
    template: DeploymentTemplate,
}

fn terminal_postgres_registry(
    scope: &Scope,
    cluster_identity: &str,
    now: i64,
    effect_signer: &SigningIdentity,
    retirement_signer: &SigningIdentity,
) -> ActivatedWitnessRegistry {
    let entry = |signer: &SigningIdentity, role, observer: &str| {
        RegisteredWitnessVerifier::new(
            WitnessScope::new(scope.tenant.clone(), scope.environment.clone()).unwrap(),
            cluster_identity,
            role,
            observer,
            signer.key_id(),
            signer.public_key_bytes(),
            now.saturating_sub(600),
            now.saturating_add(3_600),
            now.saturating_add(3_500),
            TERMINAL_AUTHORITY_VERSION,
            digest("terminal-postgres-observer-authority"),
            WitnessVerifierStatus::Active,
        )
        .unwrap()
    };
    let entries = vec![
        entry(
            effect_signer,
            WitnessRole::ExactEffect,
            TERMINAL_EFFECT_OBSERVER,
        ),
        entry(
            retirement_signer,
            WitnessRole::CredentialRetirement,
            TERMINAL_RETIREMENT_OBSERVER,
        ),
    ];
    let material_root = ActivatedWitnessRegistry::compute_material_root(&entries).unwrap();
    ActivatedWitnessRegistry::new(
        WitnessRegistryAuthority::new(material_root, 12, Uuid::new_v4()).unwrap(),
        entries,
    )
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn terminal_postgres_issued(
    scope: &Scope,
    active: &AuthorityVector,
    capability: &CapabilityGrant,
    deadline_policy: &DispatchDeadlinePolicy,
    template: &DeploymentTemplate,
    now: i64,
    transaction_id: Uuid,
    authorization_id: Uuid,
) -> IssuedAuthorizationRecord {
    let authorization = ExecutionAuthorization {
        schema_version: accordlock_protocol::EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
        authorization_id,
        evaluation_nonce: Uuid::new_v4(),
        request_id: Uuid::new_v4(),
        tenant: scope.tenant.clone(),
        holder: capability.holder.clone(),
        audience: "accordlock-executor:test".to_owned(),
        issued_at: now.saturating_sub(1),
        not_before: now.saturating_sub(1),
        consume_before: now.saturating_add(300),
        dispatch_deadline_policy: deadline_policy.clone(),
        grant_id: capability.grant_id,
        template_hash: canonical_hash(template).unwrap(),
        template: template.clone(),
        evidence_root: digest("terminal-postgres-authorization-evidence"),
        principals: vec!["principal-a".to_owned()],
        policy_root: active.policy.root,
        authority: active.clone(),
    };
    let signer = authorization_signer();
    IssuedAuthorizationRecord::new(
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
    .unwrap()
}

#[allow(clippy::too_many_lines)]
fn terminal_postgres_fixture() -> TerminalPostgresFixture {
    terminal_postgres_fixture_with_registry(true)
}

#[allow(clippy::too_many_lines)]
fn terminal_postgres_fixture_with_registry(register_registry: bool) -> TerminalPostgresFixture {
    let (url, mut store) = configured_store();
    let broker_capability = store.issue_broker_journal_capability().unwrap();
    let now = database_time(&url);
    let scope = Scope::new(unique_tenant("terminal-postgres"), "test").unwrap();
    let deployment_uid = Uuid::new_v4().to_string();
    let cluster_identity = format!("urn:accordlock:cluster:{}", Uuid::new_v4().simple());
    let api_server_identity = digest(&format!("terminal-api-{deployment_uid}")).to_string();
    let effect_signer = SigningIdentity::from_seed("terminal-postgres-effect-v1", [0xa1; 32]);
    let retirement_signer =
        SigningIdentity::from_seed("terminal-postgres-retirement-v1", [0xa2; 32]);
    let registry = terminal_postgres_registry(
        &scope,
        &cluster_identity,
        now,
        &effect_signer,
        &retirement_signer,
    );
    let profile = postgres_registry_profile_with_terminal(
        &cluster_identity,
        &deployment_uid,
        &api_server_identity,
        *registry.commitment().as_bytes(),
    );
    let capability = CapabilityGrant {
        grant_id: Uuid::new_v4(),
        holder: "workload-a".to_owned(),
        tenant: scope.tenant.clone(),
        operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
        repository: "acme/payments".to_owned(),
        audience: "accordlock-executor:test".to_owned(),
        cluster_identity: cluster_identity.clone(),
        namespace: "payments".to_owned(),
        deployment_uid: deployment_uid.clone(),
        container: "app".to_owned(),
        image_repository: "registry.example/acme/payments".to_owned(),
        not_before: now.saturating_sub(60),
        expires_at: now.saturating_add(1_800),
        maximum_uses: 2,
    };
    let active = postgres_registry_authority(&scope, &profile, Some(&capability));
    store
        .compare_and_activate_authority(&scope, None, &active)
        .unwrap();
    store.activate_eks_destination(&scope, &profile).unwrap();
    if register_registry {
        let registered = store
            .register_terminal_witness_registry_or_recover(
                &scope,
                active.resource.activation_id,
                active.mediation.activation_id,
                &registry,
            )
            .unwrap();
        assert!(!registered.was_recovered());
    }
    let deadline_policy = DispatchDeadlinePolicy {
        max_dispatch_delay_seconds: 60,
        profile_hard_cap: now.saturating_add(1_800),
        immutable_dependency_expiries: vec![now.saturating_add(1_800)],
    };
    store
        .register_grant(&GrantRegistration {
            environment: scope.environment.clone(),
            grant: capability.clone(),
            authority: active.clone(),
            dispatch_deadline_policy: deadline_policy.clone(),
        })
        .unwrap();
    let template = DeploymentTemplate {
        operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
        environment: scope.environment.clone(),
        audience: "accordlock-executor:test".to_owned(),
        repository: "acme/payments".to_owned(),
        commit_sha: "1111111111111111111111111111111111111111".to_owned(),
        image_repository: "registry.example/acme/payments".to_owned(),
        image_digest: digest("terminal-postgres-new-image"),
        cluster_identity,
        namespace: "payments".to_owned(),
        deployment: "payments".to_owned(),
        deployment_uid: deployment_uid.clone(),
        container: "app".to_owned(),
        container_index: 0,
        prior_image_digest: digest("terminal-postgres-old-image"),
        resource_version: "1001".to_owned(),
        prior_projection_hash: digest("terminal-postgres-projection"),
        prior_transaction_annotation: Some("none".to_owned()),
        prior_authorization_annotation: Some("none".to_owned()),
        prior_operation_hash_annotation: Some("none".to_owned()),
    };
    let transaction_id = Uuid::new_v4();
    let authorization_id = Uuid::new_v4();
    let record = terminal_postgres_issued(
        &scope,
        &active,
        &capability,
        &deadline_policy,
        &template,
        now,
        transaction_id,
        authorization_id,
    );
    store.record_issued_authorization(&record).unwrap();
    let key = ConsumeKey {
        scope,
        transaction_id,
        authorization_id,
    };
    store.consume(&key).unwrap();
    let token = store
        .claim_dispatch(&dispatch_claim_request(
            &key,
            Uuid::new_v4(),
            "worker-terminal-postgres",
        ))
        .unwrap()
        .token()
        .clone();
    let route = *profile.route().commitment().as_bytes();

    let create = store
        .prepare_broker_operation(
            &broker_capability,
            BrokerOperationRequest::create(&token, route).unwrap(),
        )
        .and_then(|intent| store.begin_broker_io(&broker_capability, intent))
        .unwrap();
    store
        .commit_broker_create(
            create,
            BrokerSecretObservation::matching(
                "terminal-postgres-secret-uid".to_owned(),
                [0xa9; 32],
            )
            .unwrap(),
        )
        .unwrap();
    let issue = store
        .prepare_broker_operation(
            &broker_capability,
            BrokerOperationRequest::issue_token(
                &token,
                route,
                BrokerCredentialSafetyPolicy::new(900, 5).unwrap(),
            )
            .unwrap(),
        )
        .and_then(|intent| store.begin_broker_io(&broker_capability, intent))
        .unwrap();
    store
        .commit_broker_token_issue(
            issue,
            &BrokerTokenIssueObservation::new([0xaa; 32], now.saturating_add(300), [0xab; 32])
                .unwrap(),
        )
        .unwrap();
    store
        .mark_attempt_in_flight(
            &token,
            token
                .bind_authenticated_credential(
                    [0xaa; 32],
                    "22222222-2222-4222-8222-222222222222".to_owned(),
                    TERMINAL_CREDENTIAL_ID.to_owned(),
                    now.saturating_sub(10),
                    now.saturating_add(300),
                )
                .unwrap(),
        )
        .unwrap();
    let admission = store
        .admission_context(&key)
        .unwrap()
        .authorization_request(
            format!("terminal-admission-{}", Uuid::new_v4().simple()),
            "22222222-2222-4222-8222-222222222222",
            TERMINAL_CREDENTIAL_ID,
            digest("terminal-postgres-old-object"),
            digest("terminal-postgres-new-object"),
            digest("terminal-postgres-executor"),
            digest("terminal-postgres-admission-observer"),
        )
        .unwrap();
    store.authorize_admission_or_recover(&admission).unwrap();
    let delete = store
        .prepare_broker_cleanup(
            &broker_capability,
            &BrokerCleanupRequest::new(key.clone(), route).unwrap(),
        )
        .and_then(|intent| store.begin_broker_io(&broker_capability, intent))
        .unwrap();
    store.mark_broker_io_unknown(delete).unwrap();
    let reconcile = store
        .begin_broker_reconciliation(
            &broker_capability,
            &BrokerReconciliationRequest::new(
                key.clone(),
                BrokerJournalOperation::DeleteSecret,
                route,
            )
            .unwrap(),
        )
        .unwrap();
    let pending = store
        .commit_broker_reconciliation(
            reconcile,
            BrokerSecretObservation::matching(
                "terminal-postgres-secret-uid".to_owned(),
                [0xac; 32],
            )
            .unwrap(),
        )
        .unwrap()
        .into_pending()
        .unwrap();
    store
        .commit_broker_reconciliation(
            pending,
            BrokerSecretObservation::absent([0xad; 32]).unwrap(),
        )
        .unwrap()
        .into_completed()
        .unwrap();

    TerminalPostgresFixture {
        url,
        store,
        key,
        token,
        registry,
        effect_signer,
        retirement_signer,
        resource_activation_id: active.resource.activation_id,
        mediation_activation_id: active.mediation.activation_id,
        deployment_uid,
        active,
        capability,
        deadline_policy,
        template,
    }
}

fn terminal_postgres_request(
    fixture: &TerminalPostgresFixture,
    terminalization_id: Uuid,
    effect_evidence_id: Uuid,
    retirement_evidence_id: Uuid,
    observed_at: i64,
) -> TerminalRetirementRequest {
    let context = fixture
        .store
        .terminal_retirement_context(&fixture.key)
        .unwrap();
    terminal_postgres_request_for_context(
        fixture,
        &context,
        terminalization_id,
        effect_evidence_id,
        retirement_evidence_id,
        observed_at,
    )
}

fn terminal_postgres_request_for_context(
    fixture: &TerminalPostgresFixture,
    context: &TerminalRetirementContext,
    terminalization_id: Uuid,
    effect_evidence_id: Uuid,
    retirement_evidence_id: Uuid,
    observed_at: i64,
) -> TerminalRetirementRequest {
    let observation_started_at = context
        .retirement_expectation()
        .deletion()
        .observed_at()
        .max(context.attempt().identity().attempt_started_at());
    let effect = sign_effect_observation(
        EffectObservationClaims::new(
            effect_evidence_id,
            context.attempt().clone(),
            WitnessIssuer::new(
                TERMINAL_EFFECT_OBSERVER,
                fixture.effect_signer.key_id(),
                TERMINAL_AUTHORITY_VERSION,
            )
            .unwrap(),
            EffectObservationResult::new(
                ExactExecutionOutcome::KubernetesDeploymentUpdatedV1,
                digest("terminal-postgres-effect-response"),
                digest("terminal-postgres-effect-post-state"),
                digest("terminal-postgres-effect-complete"),
                fixture.deployment_uid.clone(),
                "terminal-postgres-resource-version-2",
                "terminal-postgres-audit-cursor",
            )
            .unwrap(),
            observation_started_at,
            observed_at,
        )
        .unwrap(),
        &fixture.effect_signer,
    )
    .unwrap();
    let retirement = sign_credential_retirement(
        CredentialRetirementClaims::new(
            retirement_evidence_id,
            context.attempt().clone(),
            WitnessIssuer::new(
                TERMINAL_RETIREMENT_OBSERVER,
                fixture.retirement_signer.key_id(),
                TERMINAL_AUTHORITY_VERSION,
            )
            .unwrap(),
            context.credential().clone(),
            context.retirement_expectation().deletion().clone(),
            RetirementBasis::token_review_rejected(
                context.attempt(),
                context.credential(),
                digest("terminal-postgres-token-review-response"),
                observation_started_at,
            )
            .unwrap(),
            observation_started_at,
            observed_at,
        )
        .unwrap(),
        &fixture.retirement_signer,
    )
    .unwrap();
    TerminalRetirementRequest::new(
        fixture.key.clone(),
        terminalization_id,
        effect.exact_envelope_bytes().unwrap(),
        retirement.exact_envelope_bytes().unwrap(),
    )
    .unwrap()
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
#[allow(clippy::too_many_lines)]
fn postgres_terminal_retirement_is_atomic_recoverable_and_reclaimable() {
    let fixture = terminal_postgres_fixture();
    let now = database_time(&fixture.url);
    let request = terminal_postgres_request(
        &fixture,
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        now,
    );

    // A second authorization for the exact physical resource may be consumed, but
    // its claim cannot acquire the active reservation before terminal commit.
    let second_transaction_id = Uuid::new_v4();
    let second_authorization_id = Uuid::new_v4();
    let second_record = terminal_postgres_issued(
        &fixture.key.scope,
        &fixture.active,
        &fixture.capability,
        &fixture.deadline_policy,
        &fixture.template,
        now,
        second_transaction_id,
        second_authorization_id,
    );
    fixture
        .store
        .record_issued_authorization(&second_record)
        .unwrap();
    let second_key = ConsumeKey {
        scope: fixture.key.scope.clone(),
        transaction_id: second_transaction_id,
        authorization_id: second_authorization_id,
    };
    fixture.store.consume(&second_key).unwrap();
    let second_claim = dispatch_claim_request(
        &second_key,
        Uuid::new_v4(),
        "worker-terminal-postgres-reclaim",
    );
    assert!(matches!(
        fixture.store.claim_dispatch(&second_claim),
        Err(StateError::PhysicalResourceAlreadyReserved)
    ));

    let barrier = Arc::new(Barrier::new(4));
    let handles = (0..4)
        .map(|_| {
            let store = PostgresStore::new(fixture.url.clone());
            let request = request.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                store.finalize_terminal_retirement_or_recover(&request)
            })
        })
        .collect::<Vec<_>>();
    let receipts = handles
        .into_iter()
        .map(|handle| handle.join().unwrap().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        receipts
            .iter()
            .filter(|receipt| !receipt.was_recovered())
            .count(),
        1
    );
    assert_eq!(
        receipts
            .iter()
            .filter(|receipt| receipt.was_recovered())
            .count(),
        3
    );
    assert!(
        receipts
            .windows(2)
            .all(|pair| pair[0].audit() == pair[1].audit())
    );

    let restarted = PostgresStore::new(fixture.url.clone());
    let recovered = restarted
        .finalize_terminal_retirement_or_recover(&request)
        .unwrap();
    assert!(recovered.was_recovered());
    assert_eq!(recovered.audit(), receipts[0].audit());
    assert_eq!(
        restarted.terminal_retirement_audit(&fixture.key).unwrap(),
        *recovered.audit()
    );

    let reclaimed = restarted.claim_dispatch(&second_claim).unwrap();
    assert!(reclaimed.token().fence() > fixture.token.fence());
    assert_eq!(
        reclaimed.token().physical_resource(),
        fixture.token.physical_resource()
    );
    // Recovery remains exact even after a later claim owns the same physical
    // resource; terminal history and the old fence were not removed.
    assert!(
        restarted
            .finalize_terminal_retirement_or_recover(&request)
            .unwrap()
            .was_recovered()
    );

    let row = Client::connect(&fixture.url, NoTls)
        .unwrap()
        .query_one(
            "SELECT claim.state,
                    claim.terminalization_id,
                    (SELECT count(*)::bigint
                       FROM accordlock_terminal_retirements terminal
                      WHERE terminal.claim_id = claim.claim_id) AS terminal_count,
                    (SELECT count(*)::bigint
                       FROM accordlock_broker_secret_deletion_observations deletion
                      WHERE deletion.claim_id = claim.claim_id) AS deletion_count
               FROM accordlock_dispatch_claims claim
              WHERE claim.tenant = $1 AND claim.environment = $2
                AND claim.authorization_id = $3",
            &[
                &fixture.key.scope.tenant,
                &fixture.key.scope.environment,
                &fixture.key.authorization_id,
            ],
        )
        .unwrap();
    assert_eq!(row.get::<_, String>("state"), "TERMINAL");
    assert_eq!(
        row.get::<_, Option<Uuid>>("terminalization_id"),
        Some(request.terminalization_id())
    );
    assert_eq!(row.get::<_, i64>("terminal_count"), 1);
    assert_eq!(row.get::<_, i64>("deletion_count"), 1);
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_terminal_registry_registration_race_recovers_exact_material() {
    let fixture = terminal_postgres_fixture_with_registry(false);
    let barrier = Arc::new(Barrier::new(2));
    let handles = (0..2)
        .map(|_| {
            let store = PostgresStore::new(fixture.url.clone());
            let scope = fixture.key.scope.clone();
            let registry = fixture.registry.clone();
            let barrier = barrier.clone();
            let resource_activation_id = fixture.resource_activation_id;
            let mediation_activation_id = fixture.mediation_activation_id;
            thread::spawn(move || {
                barrier.wait();
                store.register_terminal_witness_registry_or_recover(
                    &scope,
                    resource_activation_id,
                    mediation_activation_id,
                    &registry,
                )
            })
        })
        .collect::<Vec<_>>();
    let receipts = handles
        .into_iter()
        .map(|handle| handle.join().unwrap().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        receipts
            .iter()
            .filter(|receipt| !receipt.was_recovered())
            .count(),
        1
    );
    assert_eq!(
        receipts
            .iter()
            .filter(|receipt| receipt.was_recovered())
            .count(),
        1
    );
    assert!(
        receipts
            .iter()
            .all(|receipt| receipt.registry_commitment() == fixture.registry.commitment())
    );

    let wrong_retirement = SigningIdentity::from_seed("terminal-wrong-retirement", [0xb1; 32]);
    let wrong_registry = terminal_postgres_registry(
        &fixture.key.scope,
        fixture.token.physical_resource().cluster_identity(),
        database_time(&fixture.url),
        &fixture.effect_signer,
        &wrong_retirement,
    );
    assert!(matches!(
        fixture.store.register_terminal_witness_registry_or_recover(
            &fixture.key.scope,
            fixture.resource_activation_id,
            fixture.mediation_activation_id,
            &wrong_registry,
        ),
        Err(StateError::TerminalWitnessRegistryMismatch)
    ));
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_terminal_bad_signature_and_misroute_are_hwm_inert() {
    let fixture = terminal_postgres_fixture();
    let observed_at = database_time(&fixture.url);
    let valid = terminal_postgres_request(
        &fixture,
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        observed_at,
    );
    let baseline = fixture.store.time_high_water(&fixture.key.scope).unwrap();

    let effect =
        SignedEffectWitness::from_canonical_envelope_bytes(valid.effect_envelope()).unwrap();
    let mut corrupted_cose = effect.cose_sign1().to_vec();
    *corrupted_cose.last_mut().unwrap() ^= 1;
    let corrupted_effect = SignedEffectWitness::from_untrusted_parts(
        effect.key_id(),
        effect.claims().clone(),
        corrupted_cose,
    )
    .unwrap();
    let corrupted = TerminalRetirementRequest::new(
        fixture.key.clone(),
        valid.terminalization_id(),
        corrupted_effect.exact_envelope_bytes().unwrap(),
        valid.retirement_envelope().to_vec(),
    )
    .unwrap();
    assert!(matches!(
        fixture
            .store
            .finalize_terminal_retirement_or_recover(&corrupted),
        Err(StateError::TerminalEvidenceInvalid(_))
    ));
    assert_eq!(
        fixture.store.time_high_water(&fixture.key.scope).unwrap(),
        baseline
    );

    let wrong_transaction = TerminalRetirementRequest::new(
        ConsumeKey {
            scope: fixture.key.scope.clone(),
            transaction_id: Uuid::new_v4(),
            authorization_id: fixture.key.authorization_id,
        },
        valid.terminalization_id(),
        valid.effect_envelope().to_vec(),
        valid.retirement_envelope().to_vec(),
    )
    .unwrap();
    assert!(
        fixture
            .store
            .finalize_terminal_retirement_or_recover(&wrong_transaction)
            .is_err()
    );
    assert_eq!(
        fixture.store.time_high_water(&fixture.key.scope).unwrap(),
        baseline
    );
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_terminal_future_evidence_persists_hwm_then_rollback_fails_closed() {
    let fixture = terminal_postgres_fixture();
    let observed_at = database_time(&fixture.url).saturating_add(30);
    let request = terminal_postgres_request(
        &fixture,
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        observed_at,
    );
    let trusted_now = match fixture
        .store
        .finalize_terminal_retirement_or_recover(&request)
    {
        Err(StateError::TerminalEvidenceFuture {
            observed,
            trusted_now,
        }) => {
            assert_eq!(observed, observed_at);
            trusted_now
        }
        result => panic!("unexpected future-witness result: {result:?}"),
    };
    assert_eq!(
        fixture.store.time_high_water(&fixture.key.scope).unwrap(),
        Some(trusted_now)
    );
    assert_eq!(
        Client::connect(&fixture.url, NoTls)
            .unwrap()
            .query_one(
                "SELECT count(*)::bigint AS count
                   FROM accordlock_terminal_retirements
                  WHERE tenant = $1 AND environment = $2 AND authorization_id = $3",
                &[
                    &fixture.key.scope.tenant,
                    &fixture.key.scope.environment,
                    &fixture.key.authorization_id,
                ],
            )
            .unwrap()
            .get::<_, i64>("count"),
        0
    );

    let forced_high_water = trusted_now.saturating_add(20);
    set_high_water(&fixture.url, &fixture.key, forced_high_water);
    assert!(matches!(
        fixture
            .store
            .finalize_terminal_retirement_or_recover(&request),
        Err(StateError::ClockRollback {
            high_water,
            ..
        }) if high_water == forced_high_water
    ));
    assert_eq!(
        fixture.store.time_high_water(&fixture.key.scope).unwrap(),
        Some(forced_high_water)
    );
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_legacy_delete_without_v12_observation_is_not_terminalizable() {
    let fixture = terminal_postgres_fixture();
    let mut client = Client::connect(&fixture.url, NoTls).unwrap();
    client
        .batch_execute(
            "ALTER TABLE accordlock_broker_secret_deletion_observations
                 DISABLE TRIGGER accordlock_broker_secret_deletion_observations_append_only",
        )
        .unwrap();
    let deleted = client
        .execute(
            "DELETE FROM accordlock_broker_secret_deletion_observations
              WHERE tenant = $1 AND environment = $2 AND authorization_id = $3",
            &[
                &fixture.key.scope.tenant,
                &fixture.key.scope.environment,
                &fixture.key.authorization_id,
            ],
        )
        .unwrap();
    client
        .batch_execute(
            "ALTER TABLE accordlock_broker_secret_deletion_observations
                 ENABLE TRIGGER accordlock_broker_secret_deletion_observations_append_only",
        )
        .unwrap();
    assert_eq!(deleted, 1);
    assert!(matches!(
        fixture.store.terminal_retirement_context(&fixture.key),
        Err(StateError::TerminalRetirementLineageUnavailable)
    ));
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_terminal_global_ids_and_envelopes_cannot_move_to_another_claim() {
    let first = terminal_postgres_fixture();
    let first_request = terminal_postgres_request(
        &first,
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        database_time(&first.url),
    );
    let first_effect_id =
        SignedEffectWitness::from_canonical_envelope_bytes(first_request.effect_envelope())
            .unwrap()
            .claims()
            .evidence_id();
    let first_retirement_id =
        accordlock_terminal_witness::SignedCredentialRetirementWitness::from_canonical_envelope_bytes(
            first_request.retirement_envelope(),
        )
        .unwrap()
        .claims()
        .evidence_id();
    first
        .store
        .finalize_terminal_retirement_or_recover(&first_request)
        .unwrap();

    let second = terminal_postgres_fixture();
    let baseline = second.store.time_high_water(&second.key.scope).unwrap();
    let reused_effect_id = terminal_postgres_request(
        &second,
        Uuid::new_v4(),
        first_effect_id,
        Uuid::new_v4(),
        database_time(&second.url),
    );
    assert!(matches!(
        second
            .store
            .finalize_terminal_retirement_or_recover(&reused_effect_id),
        Err(StateError::TerminalRetirementMismatch)
    ));

    let reused_retirement_id = terminal_postgres_request(
        &second,
        Uuid::new_v4(),
        Uuid::new_v4(),
        first_retirement_id,
        database_time(&second.url),
    );
    assert!(matches!(
        second
            .store
            .finalize_terminal_retirement_or_recover(&reused_retirement_id),
        Err(StateError::TerminalRetirementMismatch)
    ));

    let reused_terminalization_id = terminal_postgres_request(
        &second,
        first_request.terminalization_id(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        database_time(&second.url),
    );
    assert!(matches!(
        second
            .store
            .finalize_terminal_retirement_or_recover(&reused_terminalization_id),
        Err(StateError::TerminalRetirementMismatch)
    ));

    let moved_envelopes = TerminalRetirementRequest::new(
        second.key.clone(),
        Uuid::new_v4(),
        first_request.effect_envelope().to_vec(),
        first_request.retirement_envelope().to_vec(),
    )
    .unwrap();
    assert!(
        second
            .store
            .finalize_terminal_retirement_or_recover(&moved_envelopes)
            .is_err()
    );
    assert_eq!(
        second.store.time_high_water(&second.key.scope).unwrap(),
        baseline
    );

    // Evidence identifiers are globally unique inside each purpose-separated
    // role. Reusing the same raw UUID across the other role is unambiguous and
    // intentionally remains valid.
    let cross_role = terminal_postgres_fixture();
    let cross_role_request = terminal_postgres_request(
        &cross_role,
        Uuid::new_v4(),
        first_retirement_id,
        first_effect_id,
        database_time(&cross_role.url),
    );
    assert!(
        cross_role
            .store
            .finalize_terminal_retirement_or_recover(&cross_role_request)
            .is_ok()
    );
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_eks_registry_survives_restart_and_splits_current_from_frozen_cleanup() {
    let (url, mut store) = configured_store();
    let broker_capability = store.issue_broker_journal_capability().unwrap();
    let (key, claim, profile, active) = register_postgres_registry_fixture(&url, &store);
    let restarted = store.clone();
    let current = restarted
        .load_current_eks_attempt(&key.scope, key.transaction_id)
        .unwrap();
    assert!(current.facts().route().exactly_matches(profile.route()));
    assert_eq!(
        current.facts().physical_resource(),
        claim.physical_resource()
    );
    assert_eq!(
        current.facts().token_subject(),
        "system:serviceaccount:payments:accordlock-attempt"
    );
    assert_eq!(
        current.facts().credential_lifecycle_policy(),
        profile.credential_lifecycle_policy()
    );
    assert_eq!(
        current.facts().broker_management_bindings(),
        profile.broker_management_bindings()
    );
    assert!(matches!(
        restarted.load_frozen_eks_attempt(&key.scope, key.transaction_id),
        Err(EksRegistryError::FrozenLineageUnavailable)
    ));

    let route = *profile.route().commitment().as_bytes();
    let create = restarted
        .prepare_broker_operation(
            &broker_capability,
            BrokerOperationRequest::create(&claim, route).unwrap(),
        )
        .and_then(|intent| restarted.begin_broker_io(&broker_capability, intent))
        .unwrap();
    restarted.mark_broker_io_unknown(create).unwrap();
    let reconciliation = restarted
        .begin_broker_reconciliation(
            &broker_capability,
            &BrokerReconciliationRequest::new(
                key.clone(),
                BrokerJournalOperation::CreateSecret,
                route,
            )
            .unwrap(),
        )
        .unwrap();
    drop(reconciliation);
    let frozen = PostgresStore::new(url.clone())
        .load_frozen_eks_attempt(&key.scope, key.transaction_id)
        .unwrap();
    assert_eq!(
        frozen.facts().activation_commitment(),
        current.facts().activation_commitment()
    );

    let mut rotated = active.clone();
    rotated.revocation.epoch += 1;
    rotated.revocation.activation_id = Uuid::new_v4();
    rotated.revocation.root = digest("postgres-registry-revocation");
    restarted
        .compare_and_activate_authority(&key.scope, Some(&active), &rotated)
        .unwrap();
    assert!(
        restarted
            .load_current_eks_attempt(&key.scope, key.transaction_id)
            .is_err()
    );
    assert!(
        PostgresStore::new(url)
            .load_frozen_eks_attempt(&key.scope, key.transaction_id)
            .is_ok()
    );
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_eks_registry_lease_expiry_persists_high_water() {
    let (url, store) = configured_store();
    let (key, _, _, _) = register_postgres_registry_fixture(&url, &store);
    thread::sleep(Duration::from_millis(1_100));
    let expired_lease = database_time(&url);
    let mut client = Client::connect(&url, NoTls).unwrap();
    let original_lease: i64 = client
        .query_one(
            "SELECT lease_until
               FROM public.accordlock_dispatch_claims
              WHERE tenant = $1 AND environment = $2 AND authorization_id = $3",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
            ],
        )
        .unwrap()
        .get("lease_until");
    let updated = replica_execute(
        &mut client,
        "UPDATE public.accordlock_dispatch_claims
            SET lease_until = $4
          WHERE tenant = $1 AND environment = $2 AND authorization_id = $3
            AND claimed_unix_s < $4",
        &[
            &key.scope.tenant,
            &key.scope.environment,
            &key.authorization_id,
            &expired_lease,
        ],
    );
    assert_eq!(updated, 1);
    let expired_result = store.load_current_eks_attempt(&key.scope, key.transaction_id);
    assert_eq!(
        replica_execute(
            &mut client,
            "UPDATE public.accordlock_dispatch_claims
                SET lease_until = $4
              WHERE tenant = $1 AND environment = $2 AND authorization_id = $3",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &original_lease,
            ],
        ),
        1
    );
    let observed = match expired_result {
        Err(EksRegistryError::State(StateError::DispatchClaimLeaseExpired {
            observed,
            lease_until,
        })) => {
            assert_eq!(lease_until, expired_lease);
            observed
        }
        result => panic!("unexpected lease result: {result:?}"),
    };
    assert_eq!(store.time_high_water(&key.scope).unwrap(), Some(observed));
    // Keep the forced HWM comfortably ahead of wall-clock progress while the
    // assertion reconnects to PostgreSQL; a one-second lead is test-flaky.
    set_scope_high_water(&url, &key.scope, observed.saturating_add(60));
    assert!(matches!(
        store.load_current_eks_attempt(&key.scope, key.transaction_id),
        Err(EksRegistryError::State(StateError::ClockRollback { .. }))
    ));
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
#[allow(clippy::too_many_lines)]
fn postgres_eks_registry_rotates_same_owner_and_rejects_global_aliases() {
    let (url, store) = configured_store();
    let deployment_uid = Uuid::new_v4().to_string();
    let api_identity = digest(&format!("shared-api-{deployment_uid}")).to_string();
    let first_scope = Scope::new(unique_tenant("owner-a"), "test").unwrap();
    let first = postgres_registry_profile(
        "urn:accordlock:cluster:owner-a",
        &deployment_uid,
        &api_identity,
    );
    let first_authority = postgres_registry_authority(&first_scope, &first, None);
    store
        .compare_and_activate_authority(&first_scope, None, &first_authority)
        .unwrap();
    store
        .activate_eks_destination(&first_scope, &first)
        .unwrap();
    store
        .activate_eks_destination(&first_scope, &first)
        .unwrap();

    let mut rotated = first_authority.clone();
    let rotated_profile = postgres_registry_profile_with_policy(
        "urn:accordlock:cluster:owner-a",
        &deployment_uid,
        &api_identity,
        [0x51; 32],
        EksCredentialLifecyclePolicy::new(600, 900, 5, 120).unwrap(),
    );
    rotated.resource.epoch += 1;
    rotated.resource.activation_id = Uuid::new_v4();
    rotated.resource.root = rotated_profile.resource_root(&first_scope).unwrap();
    rotated.mediation.epoch += 1;
    rotated.mediation.activation_id = Uuid::new_v4();
    rotated.mediation.root = rotated_profile
        .mediation_root(&first_scope, &rotated.resource)
        .unwrap();
    store
        .compare_and_activate_authority(&first_scope, Some(&first_authority), &rotated)
        .unwrap();
    store
        .activate_eks_destination(&first_scope, &rotated_profile)
        .unwrap();
    let owner_row = Client::connect(&url, NoTls)
        .unwrap()
        .query_one(
            "SELECT first_resource_activation_id,
                    (SELECT count(*)::bigint
                       FROM public.accordlock_eks_destination_activations
                      WHERE tenant = $4 AND environment = $5) AS activation_count
               FROM public.accordlock_eks_physical_owners
              WHERE api_server_identity = $1 AND namespace = $2
                AND deployment_uid = $3",
            &[
                &api_identity,
                &"payments",
                &deployment_uid,
                &first_scope.tenant,
                &first_scope.environment,
            ],
        )
        .unwrap();
    assert_eq!(
        owner_row.get::<_, Uuid>("first_resource_activation_id"),
        first_authority.resource.activation_id
    );
    assert_eq!(owner_row.get::<_, i64>("activation_count"), 2);
    let deletion_bounds: Vec<i64> = Client::connect(&url, NoTls)
        .unwrap()
        .query(
            "SELECT deletion_propagation_hard_max_seconds
               FROM public.accordlock_eks_destination_activations
              WHERE tenant=$1 AND environment=$2
              ORDER BY deletion_propagation_hard_max_seconds",
            &[&first_scope.tenant, &first_scope.environment],
        )
        .unwrap()
        .into_iter()
        .map(|row| row.get("deletion_propagation_hard_max_seconds"))
        .collect();
    assert_eq!(deletion_bounds, vec![60, 120]);

    let second_scope = Scope::new(unique_tenant("owner-b"), "test").unwrap();
    let cluster_alias = postgres_registry_profile(
        "urn:accordlock:cluster:owner-b-alias",
        &deployment_uid,
        &api_identity,
    );
    let second_authority = postgres_registry_authority(&second_scope, &cluster_alias, None);
    store
        .compare_and_activate_authority(&second_scope, None, &second_authority)
        .unwrap();
    assert!(matches!(
        store.activate_eks_destination(&second_scope, &cluster_alias),
        Err(EksRegistryError::PhysicalAliasConflict)
    ));

    let third_scope = Scope::new(unique_tenant("owner-c"), "test").unwrap();
    let api_alias = postgres_registry_profile(
        "urn:accordlock:cluster:owner-c-alias",
        &deployment_uid,
        &digest(&format!("alternate-api-{deployment_uid}")).to_string(),
    );
    let third_authority = postgres_registry_authority(&third_scope, &api_alias, None);
    store
        .compare_and_activate_authority(&third_scope, None, &third_authority)
        .unwrap();
    assert!(matches!(
        store.activate_eks_destination(&third_scope, &api_alias),
        Err(EksRegistryError::PhysicalAliasConflict)
    ));
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_eks_registry_has_one_global_owner_across_store_instances() {
    let (_, first_store) = configured_store();
    let url = env::var("ACCORDLOCK_TEST_POSTGRES_URL").unwrap();
    let second_store = PostgresStore::new(url);
    let deployment_uid = Uuid::new_v4().to_string();
    let api_identity = digest(&format!("race-api-{deployment_uid}")).to_string();
    let first_scope = Scope::new(unique_tenant("owner-race-a"), "test").unwrap();
    let second_scope = Scope::new(unique_tenant("owner-race-b"), "test").unwrap();
    let first_profile = postgres_registry_profile(
        "urn:accordlock:cluster:owner-race-a",
        &deployment_uid,
        &api_identity,
    );
    let second_profile = postgres_registry_profile(
        "urn:accordlock:cluster:owner-race-b",
        &deployment_uid,
        &api_identity,
    );
    let first_authority = postgres_registry_authority(&first_scope, &first_profile, None);
    let second_authority = postgres_registry_authority(&second_scope, &second_profile, None);
    first_store
        .compare_and_activate_authority(&first_scope, None, &first_authority)
        .unwrap();
    first_store
        .compare_and_activate_authority(&second_scope, None, &second_authority)
        .unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let first_handle = {
        let barrier = barrier.clone();
        thread::spawn(move || {
            barrier.wait();
            first_store.activate_eks_destination(&first_scope, &first_profile)
        })
    };
    let second_handle = thread::spawn(move || {
        barrier.wait();
        second_store.activate_eks_destination(&second_scope, &second_profile)
    });
    let results = [first_handle.join().unwrap(), second_handle.join().unwrap()];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(EksRegistryError::PhysicalAliasConflict)))
            .count(),
        1
    );
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
#[allow(clippy::too_many_lines)]
fn postgres_eks_registry_rejects_reconstruction_row_tampering_without_hwm_mutation() {
    let (url, store) = configured_store();
    let (key, _, _, _) = register_postgres_registry_fixture(&url, &store);
    let before = store.time_high_water(&key.scope).unwrap();
    let mut client = Client::connect(&url, NoTls).unwrap();
    let row = client
        .query_one(
            "SELECT dns_server_name, credential_lifecycle_commitment,
                    requested_expiration_seconds,
                    secret_lifecycle_rbac_commitment,
                    activation_commitment
               FROM public.accordlock_eks_destination_activations
              WHERE tenant = $1 AND environment = $2",
            &[&key.scope.tenant, &key.scope.environment],
        )
        .unwrap();
    let text_tampers = [
        (
            "dns_server_name",
            row.get::<_, String>("dns_server_name"),
            "tampered.registry.eks.amazonaws.com".to_owned(),
        ),
        (
            "credential_lifecycle_commitment",
            row.get::<_, String>("credential_lifecycle_commitment"),
            digest("tampered-lifecycle").to_string(),
        ),
        (
            "secret_lifecycle_rbac_commitment",
            row.get::<_, String>("secret_lifecycle_rbac_commitment"),
            digest("tampered-management-rbac").to_string(),
        ),
        (
            "activation_commitment",
            row.get::<_, String>("activation_commitment"),
            digest("tampered-activation").to_string(),
        ),
    ];
    for (column, original, tampered) in text_tampers {
        let update = format!(
            "UPDATE public.accordlock_eks_destination_activations
                SET {column} = $3
              WHERE tenant = $1 AND environment = $2"
        );
        assert_eq!(
            client
                .execute(
                    &update,
                    &[&key.scope.tenant, &key.scope.environment, &tampered],
                )
                .unwrap(),
            1
        );
        assert!(
            store
                .load_current_eks_attempt(&key.scope, key.transaction_id)
                .is_err()
        );
        assert_eq!(store.time_high_water(&key.scope).unwrap(), before);
        assert_eq!(
            client
                .execute(
                    &update,
                    &[&key.scope.tenant, &key.scope.environment, &original],
                )
                .unwrap(),
            1
        );
    }

    let requested: i64 = row.get("requested_expiration_seconds");
    assert_eq!(
        client
            .execute(
                "UPDATE public.accordlock_eks_destination_activations
                    SET requested_expiration_seconds = $3
                  WHERE tenant = $1 AND environment = $2",
                &[
                    &key.scope.tenant,
                    &key.scope.environment,
                    &requested.saturating_add(1),
                ],
            )
            .unwrap(),
        1
    );
    assert!(
        store
            .load_current_eks_attempt(&key.scope, key.transaction_id)
            .is_err()
    );
    assert_eq!(store.time_high_water(&key.scope).unwrap(), before);
    client
        .execute(
            "UPDATE public.accordlock_eks_destination_activations
                SET requested_expiration_seconds = $3
              WHERE tenant = $1 AND environment = $2",
            &[&key.scope.tenant, &key.scope.environment, &requested],
        )
        .unwrap();

    let owner_root: String = client
        .query_one(
            "SELECT first_resource_root
               FROM public.accordlock_eks_physical_owners
              WHERE tenant = $1 AND environment = $2",
            &[&key.scope.tenant, &key.scope.environment],
        )
        .unwrap()
        .get("first_resource_root");
    client
        .execute(
            "UPDATE public.accordlock_eks_physical_owners
                SET first_resource_root = $3
              WHERE tenant = $1 AND environment = $2",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &digest("tampered-owner-lineage").to_string(),
            ],
        )
        .unwrap();
    assert!(
        store
            .load_current_eks_attempt(&key.scope, key.transaction_id)
            .is_err()
    );
    assert_eq!(store.time_high_water(&key.scope).unwrap(), before);
    client
        .execute(
            "UPDATE public.accordlock_eks_physical_owners
                SET first_resource_root = $3
              WHERE tenant = $1 AND environment = $2",
            &[&key.scope.tenant, &key.scope.environment, &owner_root],
        )
        .unwrap();
    assert!(
        store
            .load_current_eks_attempt(&key.scope, key.transaction_id)
            .is_ok()
    );
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_eks_registry_claim_preflight_mismatch_is_hwm_inert() {
    let (url, store) = configured_store();
    let (key, _, _, _) = register_postgres_registry_fixture(&url, &store);
    let before = store.time_high_water(&key.scope).unwrap();
    let mut client = Client::connect(&url, NoTls).unwrap();
    client
        .execute(
            "CREATE TEMP TABLE accordlock_test_claim_preflight_backup AS
             SELECT *
               FROM public.accordlock_dispatch_claims
              WHERE tenant = $1 AND environment = $2 AND authorization_id = $3",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
            ],
        )
        .unwrap();
    assert_eq!(
        replica_execute(
            &mut client,
            "DELETE FROM public.accordlock_dispatch_claims
              WHERE tenant = $1 AND environment = $2 AND authorization_id = $3",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id
            ],
        ),
        1
    );
    let result = store.load_current_eks_attempt(&key.scope, key.transaction_id);
    let after = store.time_high_water(&key.scope);
    replica_batch_execute(
        &mut client,
        "INSERT INTO public.accordlock_dispatch_claims
             OVERRIDING SYSTEM VALUE
         SELECT * FROM accordlock_test_claim_preflight_backup;
         DROP TABLE accordlock_test_claim_preflight_backup;",
    );
    assert!(matches!(
        result,
        Err(EksRegistryError::FrozenLineageUnavailable)
    ));
    assert_eq!(after.unwrap(), before);
}

#[test]
#[ignore = "helper process for the disposable PostgreSQL EKS owner race"]
fn postgres_eks_registry_child_process() {
    let Ok(tenant) = env::var(EKS_REGISTRY_CHILD_TENANT_ENV) else {
        return;
    };
    let url = env::var("ACCORDLOCK_TEST_POSTGRES_URL").unwrap();
    let cluster = env::var(EKS_REGISTRY_CHILD_CLUSTER_ENV).unwrap();
    let deployment = env::var(EKS_REGISTRY_CHILD_DEPLOYMENT_ENV).unwrap();
    let api_identity = env::var(EKS_REGISTRY_CHILD_API_IDENTITY_ENV).unwrap();
    let scope = Scope::new(tenant, "test").unwrap();
    let profile = postgres_registry_profile(&cluster, &deployment, &api_identity);
    match PostgresStore::new(url).activate_eks_destination(&scope, &profile) {
        Ok(()) => println!("ACCORDLOCK_CHILD_EKS_OWNER=ACTIVATED"),
        Err(EksRegistryError::PhysicalAliasConflict) => {
            println!("ACCORDLOCK_CHILD_EKS_OWNER=CONFLICT");
        }
        result => panic!("unexpected child EKS owner result: {result:?}"),
    }
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_eks_registry_has_one_global_owner_across_os_processes() {
    let (url, store) = configured_store();
    let deployment_uid = Uuid::new_v4().to_string();
    let api_identity = digest(&format!("process-api-{deployment_uid}")).to_string();
    let tenants = [
        unique_tenant("owner-process-a"),
        unique_tenant("owner-process-b"),
    ];
    let clusters = [
        "urn:accordlock:cluster:owner-process-a".to_owned(),
        "urn:accordlock:cluster:owner-process-b".to_owned(),
    ];
    for (tenant, cluster) in tenants.iter().zip(&clusters) {
        let scope = Scope::new(tenant, "test").unwrap();
        let profile = postgres_registry_profile(cluster, &deployment_uid, &api_identity);
        let active = postgres_registry_authority(&scope, &profile, None);
        store
            .compare_and_activate_authority(&scope, None, &active)
            .unwrap();
    }
    let executable = env::current_exe().unwrap();
    let children = tenants
        .iter()
        .zip(&clusters)
        .map(|(tenant, cluster)| {
            Command::new(&executable)
                .arg("postgres_eks_registry_child_process")
                .arg("--ignored")
                .arg("--exact")
                .arg("--nocapture")
                .arg("--test-threads=1")
                .env("ACCORDLOCK_TEST_POSTGRES_URL", &url)
                .env(EKS_REGISTRY_CHILD_TENANT_ENV, tenant)
                .env(EKS_REGISTRY_CHILD_CLUSTER_ENV, cluster)
                .env(EKS_REGISTRY_CHILD_DEPLOYMENT_ENV, &deployment_uid)
                .env(EKS_REGISTRY_CHILD_API_IDENTITY_ENV, &api_identity)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect::<Vec<_>>();
    let outputs = children
        .into_iter()
        .map(|child| child.wait_with_output().unwrap())
        .collect::<Vec<_>>();
    assert!(outputs.iter().all(|output| output.status.success()));
    let stdout = outputs
        .iter()
        .map(|output| String::from_utf8_lossy(&output.stdout))
        .collect::<Vec<_>>();
    assert_eq!(
        stdout
            .iter()
            .filter(|output| output.contains("ACCORDLOCK_CHILD_EKS_OWNER=ACTIVATED"))
            .count(),
        1
    );
    assert_eq!(
        stdout
            .iter()
            .filter(|output| output.contains("ACCORDLOCK_CHILD_EKS_OWNER=CONFLICT"))
            .count(),
        1
    );
}

fn ingress_consumption(
    scope: &IngressReplayScope,
    key_id: &str,
    nonce: Uuid,
    expires_unix_s: i64,
    observed_unix_s: i64,
) -> IngressNonceConsumption {
    IngressNonceConsumption::new(
        scope.clone(),
        key_id,
        nonce,
        expires_unix_s,
        observed_unix_s,
    )
    .unwrap()
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_ingress_replay_is_durable_scoped_atomic_and_gc_bounded() {
    let (url, first_store) = configured_store();
    let second_store = PostgresStore::new(url.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    let first_scope =
        IngressReplayScope::new(format!("accordlock://tenant-a/{suffix}/prod")).unwrap();
    let second_scope =
        IngressReplayScope::new(format!("accordlock://tenant-b/{suffix}/prod")).unwrap();
    let nonce = Uuid::new_v4();
    let request = ingress_consumption(&first_scope, "key-a", nonce, 20, 10);
    let barrier = Arc::new(Barrier::new(2));
    let handles = [first_store.clone(), second_store.clone()]
        .into_iter()
        .map(|store| {
            let request = request.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                store.consume_ingress_nonce(&request)
            })
        })
        .collect::<Vec<_>>();
    let decisions = handles
        .into_iter()
        .map(|handle| handle.join().unwrap().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        decisions
            .iter()
            .filter(|decision| **decision == IngressReplayDecision::Consumed)
            .count(),
        1
    );
    assert_eq!(
        decisions
            .iter()
            .filter(|decision| **decision == IngressReplayDecision::AlreadyUsed)
            .count(),
        1
    );

    let reloaded = PostgresStore::new(url.clone());
    assert_eq!(
        reloaded.consume_ingress_nonce(&request).unwrap(),
        IngressReplayDecision::AlreadyUsed
    );
    assert_eq!(
        reloaded
            .consume_ingress_nonce(&ingress_consumption(&second_scope, "key-a", nonce, 20, 10,))
            .unwrap(),
        IngressReplayDecision::Consumed
    );
    assert_eq!(
        reloaded
            .consume_ingress_nonce(&ingress_consumption(&first_scope, "key-a", nonce, 30, 20,))
            .unwrap(),
        IngressReplayDecision::Consumed
    );
    assert!(matches!(
        reloaded.observe_ingress_time(&first_scope, 19),
        Err(StateError::ClockRollback {
            observed: 19,
            high_water: 20
        })
    ));

    for (nonce_value, expiry) in [(0xa1, 25), (0xa2, 26)] {
        reloaded
            .consume_ingress_nonce(&ingress_consumption(
                &first_scope,
                "key-a",
                Uuid::from_u128(nonce_value),
                expiry,
                20,
            ))
            .unwrap();
    }
    reloaded.observe_ingress_time(&first_scope, 30).unwrap();
    assert_eq!(
        reloaded
            .prune_expired_ingress_nonces(&first_scope, 1)
            .unwrap(),
        1
    );

    let absent = IngressReplayScope::new(format!("accordlock://absent/{suffix}/prod")).unwrap();
    assert!(matches!(
        reloaded.prune_expired_ingress_nonces(&absent, 1),
        Err(StateError::InvalidRecord(_))
    ));
    let absent_rows: i64 = Client::connect(&url, NoTls)
        .unwrap()
        .query_one(
            "SELECT count(*)::bigint AS row_count
               FROM public.accordlock_ingress_replay_scopes
              WHERE replay_scope = $1",
            &[&absent.as_str()],
        )
        .unwrap()
        .get("row_count");
    assert_eq!(absent_rows, 0);
}

#[test]
#[ignore = "helper process for the disposable PostgreSQL ingress race"]
fn postgres_ingress_replay_child_process() {
    let Ok(scope) = env::var(INGRESS_CHILD_SCOPE_ENV) else {
        return;
    };
    let url = env::var("ACCORDLOCK_TEST_POSTGRES_URL").unwrap();
    let nonce = Uuid::parse_str(&env::var(INGRESS_CHILD_NONCE_ENV).unwrap()).unwrap();
    let scope = IngressReplayScope::new(scope).unwrap();
    let request = ingress_consumption(&scope, "process-key", nonce, 20, 10);
    match PostgresStore::new(url).consume_ingress_nonce(&request) {
        Ok(IngressReplayDecision::Consumed) => println!("ACCORDLOCK_CHILD_INGRESS=CONSUMED"),
        Ok(IngressReplayDecision::AlreadyUsed) => println!("ACCORDLOCK_CHILD_INGRESS=ALREADY_USED"),
        result => panic!("unexpected child ingress result: {result:?}"),
    }
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_ingress_replay_has_one_winner_across_os_processes() {
    let (url, _) = configured_store();
    let scope = format!("accordlock://process/{}/prod", Uuid::new_v4().simple());
    let nonce = Uuid::new_v4();
    let executable = env::current_exe().unwrap();
    let children = (0..2)
        .map(|_| {
            Command::new(&executable)
                .arg("postgres_ingress_replay_child_process")
                .arg("--ignored")
                .arg("--exact")
                .arg("--nocapture")
                .arg("--test-threads=1")
                .env("ACCORDLOCK_TEST_POSTGRES_URL", &url)
                .env(INGRESS_CHILD_SCOPE_ENV, &scope)
                .env(INGRESS_CHILD_NONCE_ENV, nonce.to_string())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect::<Vec<_>>();
    let outputs = children
        .into_iter()
        .map(|child| child.wait_with_output().unwrap())
        .collect::<Vec<_>>();
    assert!(outputs.iter().all(|output| output.status.success()));
    let combined = outputs
        .iter()
        .map(|output| String::from_utf8_lossy(&output.stdout))
        .collect::<Vec<_>>();
    assert_eq!(
        combined
            .iter()
            .filter(|output| output.contains("ACCORDLOCK_CHILD_INGRESS=CONSUMED"))
            .count(),
        1
    );
    assert_eq!(
        combined
            .iter()
            .filter(|output| output.contains("ACCORDLOCK_CHILD_INGRESS=ALREADY_USED"))
            .count(),
        1
    );
}

fn dispatch_claim_request(
    key: &ConsumeKey,
    claim_id: Uuid,
    worker_id: &str,
) -> DispatchClaimRequest {
    DispatchClaimRequest {
        key: key.clone(),
        claim_id,
        worker_id: worker_id.to_owned(),
    }
}

fn credential(token: &DispatchClaimToken) -> DispatchCredentialBinding {
    token
        .bind_authenticated_credential(
            [77; 32],
            "service-account-uid".to_owned(),
            "AUTHORIZATION_ID=7ee52be0-9045-4653-aa5e-0da57b8dccdc".to_owned(),
            0,
            i64::MAX,
        )
        .unwrap()
}

fn begin_admission_attempt(store: &PostgresStore, key: &ConsumeKey) -> DispatchClaimToken {
    let claimed = store
        .claim_dispatch(&dispatch_claim_request(
            key,
            Uuid::new_v4(),
            "worker-admission",
        ))
        .unwrap();
    let token = claimed.token().clone();
    store
        .mark_attempt_in_flight(&token, credential(&token))
        .unwrap();
    token
}

fn admission_request(
    store: &PostgresStore,
    key: &ConsumeKey,
    admission_uid: &str,
    observation_label: &str,
) -> AdmissionAuthorizationRequest {
    store
        .admission_context(key)
        .unwrap()
        .authorization_request(
            admission_uid.to_owned(),
            "service-account-uid",
            "AUTHORIZATION_ID=7ee52be0-9045-4653-aa5e-0da57b8dccdc",
            digest(&format!("old-{observation_label}")),
            digest(&format!("new-{observation_label}")),
            digest("executor-identity"),
            digest("observer-identity"),
        )
        .unwrap()
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_serializable_consumption_has_one_winner() {
    let (url, store) = configured_store();
    let now = database_time(&url);
    let key = register_fixture(
        &store,
        &unique_tenant("state-concurrency"),
        now,
        now + 300,
        2,
    );

    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let store = store.clone();
        let key = key.clone();
        let barrier = barrier.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            store.consume(&key)
        }));
    }
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    let success = results
        .iter()
        .find_map(|result| result.as_ref().ok())
        .unwrap();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(StateError::AlreadyConsumed)))
            .count(),
        1
    );
    assert_eq!(store.consumption_receipt(&key).unwrap(), *success.receipt());
    assert_eq!(store.outbox_entry(&key).unwrap(), *success.outbox());
    assert_eq!(
        store.time_high_water(&key.scope).unwrap(),
        Some(success.receipt().consumed_at)
    );
    let mut client = Client::connect(&url, NoTls).unwrap();
    let committed = client
        .query_one(
            "SELECT issued.state, grant_row.uses,
                    (SELECT count(*)::bigint
                       FROM public.accordlock_consumptions AS consumption
                      WHERE consumption.tenant = issued.tenant
                        AND consumption.environment = issued.environment
                        AND consumption.authorization_id = issued.authorization_id
                        AND consumption.transaction_id = issued.transaction_id) AS receipt_count,
                    (SELECT count(*)::bigint
                       FROM public.accordlock_execution_outbox AS outbox
                      WHERE outbox.tenant = issued.tenant
                        AND outbox.environment = issued.environment
                        AND outbox.authorization_id = issued.authorization_id
                        AND outbox.transaction_id = issued.transaction_id) AS outbox_count
               FROM public.accordlock_issued_authorizations AS issued
               JOIN public.accordlock_grants AS grant_row
                 ON grant_row.tenant = issued.tenant
                AND grant_row.environment = issued.environment
                AND grant_row.grant_id = issued.grant_id
              WHERE issued.tenant = $1 AND issued.environment = $2
                AND issued.authorization_id = $3 AND issued.transaction_id = $4",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
            ],
        )
        .unwrap();
    assert_eq!(committed.get::<_, String>("state"), "CONSUMED");
    assert_eq!(committed.get::<_, i64>("uses"), 1);
    assert_eq!(committed.get::<_, i64>("receipt_count"), 1);
    assert_eq!(committed.get::<_, i64>("outbox_count"), 1);
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_consume_expiry_commits_high_water_before_error() {
    let (url, store) = configured_store();
    let now = database_time(&url);
    let consume_before = now + 2;
    let key = register_fixture(
        &store,
        &unique_tenant("state-consume-expiry-hwm"),
        now,
        consume_before,
        1,
    );
    while database_time(&url) < consume_before {
        thread::sleep(Duration::from_millis(25));
    }

    let error = store.consume(&key).unwrap_err();
    let observed = match error {
        StateError::AuthorizationExpired {
            observed,
            consume_before: bound,
        } if bound == consume_before && observed >= bound => observed,
        other => panic!("unexpected consume-expiry result: {other:?}"),
    };
    assert_eq!(store.time_high_water(&key.scope).unwrap(), Some(observed));

    let simulated_future = observed + 100;
    set_high_water(&url, &key, simulated_future);
    assert!(matches!(
        store.consume(&key),
        Err(StateError::ClockRollback {
            observed: rollback,
            high_water
        }) if rollback < high_water && high_water == simulated_future
    ));
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
#[allow(clippy::too_many_lines)] // Keep success and rejection rollback traces in one regression.
fn postgres_grant_registration_commits_success_and_rejection_time() {
    let (url, store) = configured_store();
    let now = database_time(&url);
    let tenant = unique_tenant("grant-registration-hwm");
    let scope = Scope::new(&tenant, "test").unwrap();
    let capability = CapabilityGrant {
        grant_id: Uuid::new_v4(),
        holder: "workload-a".to_owned(),
        tenant: tenant.clone(),
        operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
        repository: "acme/payments".to_owned(),
        audience: "accordlock-executor:test".to_owned(),
        cluster_identity: "cluster-a".to_owned(),
        namespace: "payments".to_owned(),
        deployment_uid: "deployment-uid".to_owned(),
        container: "app".to_owned(),
        image_repository: "registry.example/acme/payments".to_owned(),
        not_before: now.saturating_sub(60),
        expires_at: now + 2,
        maximum_uses: 1,
    };
    let mut auth = authority();
    auth.grant_registry.root = canonical_hash(&capability).unwrap();
    store
        .compare_and_activate_authority(&scope, None, &auth)
        .unwrap();
    let registration = GrantRegistration {
        environment: "test".to_owned(),
        grant: capability,
        authority: auth,
        dispatch_deadline_policy: DispatchDeadlinePolicy {
            max_dispatch_delay_seconds: 30,
            profile_hard_cap: now + 300,
            immutable_dependency_expiries: vec![now + 300],
        },
    };

    while database_time(&url) < registration.grant.expires_at {
        thread::sleep(Duration::from_millis(25));
    }
    let observed = match store.register_grant(&registration) {
        Err(StateError::GrantExpired {
            observed,
            expires_at,
        }) if observed >= expires_at && expires_at == registration.grant.expires_at => observed,
        result => panic!("unexpected expired grant-registration result: {result:?}"),
    };
    assert_eq!(store.time_high_water(&scope).unwrap(), Some(observed));
    assert!(matches!(
        store.grant_snapshot(&scope, registration.grant.grant_id),
        Err(StateError::GrantNotFound)
    ));

    let simulated_future = observed + 100;
    set_scope_high_water(&url, &scope, simulated_future);
    assert!(matches!(
        store.register_grant(&registration),
        Err(StateError::ClockRollback {
            observed: rollback,
            high_water
        }) if rollback < high_water && high_water == simulated_future
    ));

    let success_tenant = unique_tenant("grant-registration-success-hwm");
    let success_scope = Scope::new(&success_tenant, "test").unwrap();
    let success_now = database_time(&url);
    let success_capability = CapabilityGrant {
        grant_id: Uuid::new_v4(),
        holder: "workload-a".to_owned(),
        tenant: success_tenant,
        operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
        repository: "acme/payments".to_owned(),
        audience: "accordlock-executor:test".to_owned(),
        cluster_identity: "cluster-a".to_owned(),
        namespace: "payments".to_owned(),
        deployment_uid: "deployment-uid".to_owned(),
        container: "app".to_owned(),
        image_repository: "registry.example/acme/payments".to_owned(),
        not_before: success_now.saturating_sub(60),
        expires_at: success_now + 4,
        maximum_uses: 1,
    };
    let mut success_auth = authority();
    success_auth.grant_registry.root = canonical_hash(&success_capability).unwrap();
    store
        .compare_and_activate_authority(&success_scope, None, &success_auth)
        .unwrap();
    let success_registration = GrantRegistration {
        environment: "test".to_owned(),
        grant: success_capability,
        authority: success_auth,
        dispatch_deadline_policy: DispatchDeadlinePolicy {
            max_dispatch_delay_seconds: 30,
            profile_hard_cap: success_now + 4,
            immutable_dependency_expiries: vec![success_now + 4],
        },
    };
    store.register_grant(&success_registration).unwrap();
    let success_high_water = store.time_high_water(&success_scope).unwrap().unwrap();
    assert!(success_high_water >= success_now);
    while database_time(&url) < success_registration.grant.expires_at {
        thread::sleep(Duration::from_millis(25));
    }
    let issuance_rejected_at =
        match store.issuance_snapshot(&success_scope, success_registration.grant.grant_id) {
            Err(StateError::GrantExpired {
                observed,
                expires_at,
            }) if observed >= expires_at && expires_at == success_registration.grant.expires_at => {
                observed
            }
            result => panic!("unexpected issuance-snapshot expiry result: {result:?}"),
        };
    assert_eq!(
        store.time_high_water(&success_scope).unwrap(),
        Some(issuance_rejected_at)
    );
    set_scope_high_water(&url, &success_scope, issuance_rejected_at + 100);
    assert!(matches!(
        store.issuance_snapshot(&success_scope, success_registration.grant.grant_id),
        Err(StateError::ClockRollback { .. })
    ));
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_final_issuance_record_expiry_commits_high_water_before_error() {
    let (url, store) = configured_store();
    let now = database_time(&url);
    let consume_before = now + 4;
    let key = register_fixture(
        &store,
        &unique_tenant("issuance-record-expiry-hwm"),
        now,
        consume_before,
        1,
    );
    let mut client = Client::connect(&url, NoTls).unwrap();
    let record_json: serde_json::Value = client
        .query_one(
            "SELECT record_json
               FROM public.accordlock_issued_authorizations
              WHERE tenant = $1 AND environment = $2
                AND authorization_id = $3 AND transaction_id = $4",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
            ],
        )
        .unwrap()
        .get("record_json");
    let record: IssuedAuthorizationRecord = serde_json::from_value(record_json).unwrap();
    client
        .execute(
            "CREATE TEMP TABLE accordlock_test_expired_authorization_backup AS
             SELECT *
               FROM public.accordlock_issued_authorizations
              WHERE tenant = $1 AND environment = $2
                AND authorization_id = $3 AND transaction_id = $4",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
            ],
        )
        .unwrap();
    assert_eq!(
        replica_execute(
            &mut client,
            "DELETE FROM public.accordlock_issued_authorizations
              WHERE tenant = $1 AND environment = $2
                AND authorization_id = $3 AND transaction_id = $4",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
            ],
        ),
        1
    );
    while database_time(&url) < consume_before {
        thread::sleep(Duration::from_millis(25));
    }

    let expiry_result = store.record_issued_authorization(&record);
    replica_batch_execute(
        &mut client,
        "INSERT INTO public.accordlock_issued_authorizations
         SELECT * FROM accordlock_test_expired_authorization_backup;
         DROP TABLE accordlock_test_expired_authorization_backup;",
    );
    let observed = match expiry_result {
        Err(StateError::AuthorizationExpired {
            observed,
            consume_before: bound,
        }) if observed >= bound && bound == consume_before => observed,
        result => panic!("unexpected final issuance-record expiry result: {result:?}"),
    };
    assert_eq!(store.time_high_water(&key.scope).unwrap(), Some(observed));
    assert!(
        store
            .grant_snapshot(&key.scope, record.authorization().grant_id)
            .is_ok()
    );

    let simulated_future = observed + 100;
    set_high_water(&url, &key, simulated_future);
    assert!(matches!(
        store.record_issued_authorization(&record),
        Err(StateError::ClockRollback {
            observed: rollback,
            high_water
        }) if rollback < high_water && high_water == simulated_future
    ));
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_consume_or_recover_returns_exact_bytes_and_rejects_another_transaction() {
    let (url, store) = configured_store();
    let now = database_time(&url);
    let key = register_fixture(
        &store,
        &unique_tenant("state-commit-recovery"),
        now,
        now + 300,
        1,
    );

    // Simulate a caller losing the successful response after PostgreSQL committed.
    let committed = store.consume(&key).unwrap();
    assert!(matches!(
        store.consume(&key),
        Err(StateError::AlreadyConsumed)
    ));
    let recovered = store.consume_or_recover(&key).unwrap();
    assert_eq!(
        serde_json::to_vec(recovered.receipt()).unwrap(),
        serde_json::to_vec(committed.receipt()).unwrap()
    );
    assert_eq!(
        serde_json::to_vec(recovered.outbox()).unwrap(),
        serde_json::to_vec(committed.outbox()).unwrap()
    );

    let wrong_transaction = ConsumeKey {
        transaction_id: Uuid::new_v4(),
        ..key
    };
    assert!(matches!(
        store.consume_or_recover(&wrong_transaction),
        Err(StateError::TransactionMismatch)
    ));
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_samples_time_after_waiting_for_state_locks() {
    let (url, store) = configured_store();
    let now = database_time(&url);
    let consume_before = now + 3;
    let key = register_fixture(
        &store,
        &unique_tenant("state-lock-time"),
        now,
        consume_before,
        1,
    );

    let mut blocker_client = Client::connect(&url, NoTls).unwrap();
    blocker_client
        .execute(
            "INSERT INTO public.accordlock_time_high_water
                        (tenant, environment, observed_unix_s)
                 VALUES ($1, $2, 0)
                 ON CONFLICT (tenant, environment) DO NOTHING",
            &[&key.scope.tenant, &key.scope.environment],
        )
        .unwrap();
    let mut blocker = blocker_client.transaction().unwrap();
    blocker
        .query_one(
            "SELECT observed_unix_s
               FROM public.accordlock_time_high_water
              WHERE tenant = $1 AND environment = $2
              FOR UPDATE",
            &[&key.scope.tenant, &key.scope.environment],
        )
        .unwrap();

    let consumer_store = store.clone();
    let consumer_key = key.clone();
    let consumer = thread::spawn(move || consumer_store.consume(&consumer_key));

    let mut observer = Client::connect(&url, NoTls).unwrap();
    let wait_started = Instant::now();
    loop {
        let waiting: bool = observer
            .query_one(
                "SELECT EXISTS (
                    SELECT 1
                      FROM pg_stat_activity
                     WHERE pid <> pg_backend_pid()
                       AND datname = current_database()
                       AND wait_event_type = 'Lock'
                       AND query LIKE '%accordlock_time_high_water%') AS waiting",
                &[],
            )
            .unwrap()
            .get("waiting");
        if waiting {
            break;
        }
        assert!(
            wait_started.elapsed() < Duration::from_secs(2),
            "consumer did not block on the high-water row"
        );
        thread::sleep(Duration::from_millis(20));
    }
    while database_time(&url) < consume_before {
        thread::sleep(Duration::from_millis(25));
    }
    blocker.commit().unwrap();

    assert!(matches!(
        consumer.join().unwrap(),
        Err(StateError::AuthorizationExpired { observed, consume_before: bound })
            if observed >= bound && bound == consume_before
    ));
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
#[allow(clippy::too_many_lines)]
fn postgres_rejects_divergent_scalar_and_json_state() {
    let (url, store) = configured_store();
    let now = database_time(&url);

    let receipt_key = register_fixture(
        &store,
        &unique_tenant("state-receipt-integrity"),
        now,
        now + 300,
        1,
    );
    store.consume(&receipt_key).unwrap();
    let mut client = Client::connect(&url, NoTls).unwrap();
    let original_consumed_unix_s: i64 = client
        .query_one(
            "SELECT consumed_unix_s
               FROM public.accordlock_consumptions
              WHERE tenant = $1 AND environment = $2
                AND authorization_id = $3 AND transaction_id = $4",
            &[
                &receipt_key.scope.tenant,
                &receipt_key.scope.environment,
                &receipt_key.authorization_id,
                &receipt_key.transaction_id,
            ],
        )
        .unwrap()
        .get("consumed_unix_s");
    assert_eq!(
        replica_execute(
            &mut client,
            "UPDATE public.accordlock_consumptions
                SET consumed_unix_s = consumed_unix_s + 1
              WHERE tenant = $1 AND environment = $2
                AND authorization_id = $3 AND transaction_id = $4",
            &[
                &receipt_key.scope.tenant,
                &receipt_key.scope.environment,
                &receipt_key.authorization_id,
                &receipt_key.transaction_id,
            ],
        ),
        1
    );
    let receipt_result = store.consumption_receipt(&receipt_key);
    let receipt_recovery_result = store.consume_or_recover(&receipt_key);
    assert_eq!(
        replica_execute(
            &mut client,
            "UPDATE public.accordlock_consumptions
                SET consumed_unix_s = $5
              WHERE tenant = $1 AND environment = $2
                AND authorization_id = $3 AND transaction_id = $4",
            &[
                &receipt_key.scope.tenant,
                &receipt_key.scope.environment,
                &receipt_key.authorization_id,
                &receipt_key.transaction_id,
                &original_consumed_unix_s,
            ],
        ),
        1
    );
    assert!(matches!(receipt_result, Err(StateError::InvalidRecord(_))));
    assert!(matches!(
        receipt_recovery_result,
        Err(StateError::InvalidRecord(_))
    ));

    let outbox_key = register_fixture(
        &store,
        &unique_tenant("state-outbox-integrity"),
        now,
        now + 300,
        1,
    );
    let consumed = store.consume(&outbox_key).unwrap();
    let original_outbox_json = serde_json::to_value(consumed.outbox()).unwrap();
    let mut corrupted_outbox = consumed.outbox().clone();
    corrupted_outbox.authorization_id = Uuid::new_v4();
    let corrupted_json = serde_json::to_value(corrupted_outbox).unwrap();
    assert_eq!(
        replica_execute(
            &mut client,
            "UPDATE public.accordlock_execution_outbox
                SET entry_json = $5
              WHERE tenant = $1 AND environment = $2
                AND authorization_id = $3 AND transaction_id = $4",
            &[
                &outbox_key.scope.tenant,
                &outbox_key.scope.environment,
                &outbox_key.authorization_id,
                &outbox_key.transaction_id,
                &corrupted_json,
            ],
        ),
        1
    );
    let outbox_result = store.outbox_entry(&outbox_key);
    let outbox_recovery_result = store.consume_or_recover(&outbox_key);
    assert_eq!(
        replica_execute(
            &mut client,
            "UPDATE public.accordlock_execution_outbox
                SET entry_json = $5
              WHERE tenant = $1 AND environment = $2
                AND authorization_id = $3 AND transaction_id = $4",
            &[
                &outbox_key.scope.tenant,
                &outbox_key.scope.environment,
                &outbox_key.authorization_id,
                &outbox_key.transaction_id,
                &original_outbox_json,
            ],
        ),
        1
    );
    assert!(matches!(outbox_result, Err(StateError::InvalidRecord(_))));
    assert!(matches!(
        outbox_recovery_result,
        Err(StateError::InvalidRecord(_))
    ));

    let authorization_key = register_fixture(
        &store,
        &unique_tenant("state-authorization-integrity"),
        now,
        now + 300,
        1,
    );
    let original_consume_before: i64 = client
        .query_one(
            "SELECT consume_before
               FROM public.accordlock_issued_authorizations
              WHERE tenant = $1 AND environment = $2
                AND authorization_id = $3 AND transaction_id = $4",
            &[
                &authorization_key.scope.tenant,
                &authorization_key.scope.environment,
                &authorization_key.authorization_id,
                &authorization_key.transaction_id,
            ],
        )
        .unwrap()
        .get("consume_before");
    assert_eq!(
        replica_execute(
            &mut client,
            "UPDATE public.accordlock_issued_authorizations
                SET consume_before = consume_before + 1
              WHERE tenant = $1 AND environment = $2
                AND authorization_id = $3 AND transaction_id = $4",
            &[
                &authorization_key.scope.tenant,
                &authorization_key.scope.environment,
                &authorization_key.authorization_id,
                &authorization_key.transaction_id,
            ],
        ),
        1
    );
    let authorization_result = store.consume(&authorization_key);
    assert_eq!(
        replica_execute(
            &mut client,
            "UPDATE public.accordlock_issued_authorizations
                SET consume_before = $5
              WHERE tenant = $1 AND environment = $2
                AND authorization_id = $3 AND transaction_id = $4",
            &[
                &authorization_key.scope.tenant,
                &authorization_key.scope.environment,
                &authorization_key.authorization_id,
                &authorization_key.transaction_id,
                &original_consume_before,
            ],
        ),
        1
    );
    assert!(matches!(
        authorization_result,
        Err(StateError::InvalidRecord(_))
    ));
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_recovery_rejects_divergent_issued_authorization_state() {
    let (url, store) = configured_store();
    let now = database_time(&url);
    let key = register_fixture(
        &store,
        &unique_tenant("state-recovered-authorization-integrity"),
        now,
        now + 300,
        1,
    );
    store.consume(&key).unwrap();

    let mut client = Client::connect(&url, NoTls).unwrap();
    let original_authorization_hash: String = client
        .query_one(
            "SELECT authorization_hash
               FROM public.accordlock_issued_authorizations
              WHERE tenant = $1 AND environment = $2
                AND authorization_id = $3 AND transaction_id = $4",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
            ],
        )
        .unwrap()
        .get("authorization_hash");
    let corrupted_authorization_hash = format!("sha256:{}", "0".repeat(64));
    assert_eq!(
        replica_execute(
            &mut client,
            "UPDATE public.accordlock_issued_authorizations
                SET authorization_hash = $5
              WHERE tenant = $1 AND environment = $2
                AND authorization_id = $3 AND transaction_id = $4",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
                &corrupted_authorization_hash,
            ],
        ),
        1
    );
    let recovery_result = store.consume_or_recover(&key);
    assert_eq!(
        replica_execute(
            &mut client,
            "UPDATE public.accordlock_issued_authorizations
                SET authorization_hash = $5
              WHERE tenant = $1 AND environment = $2
                AND authorization_id = $3 AND transaction_id = $4",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
                &original_authorization_hash,
            ],
        ),
        1
    );
    assert!(matches!(recovery_result, Err(StateError::InvalidRecord(_))));
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_revalidates_the_stored_cose_envelope() {
    let (url, store) = configured_store();
    let now = database_time(&url);
    let key = register_fixture(
        &store,
        &unique_tenant("state-signed-authorization-integrity"),
        now,
        now + 300,
        1,
    );
    let mut client = Client::connect(&url, NoTls).unwrap();
    let original_record_json: serde_json::Value = client
        .query_one(
            "SELECT record_json
               FROM public.accordlock_issued_authorizations
              WHERE tenant = $1 AND environment = $2
                AND authorization_id = $3 AND transaction_id = $4",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
            ],
        )
        .unwrap()
        .get("record_json");
    let mut record: IssuedAuthorizationRecord =
        serde_json::from_value(original_record_json.clone()).unwrap();
    record.signed_authorization.cose_sign1.clear();
    let corrupted_record_json = serde_json::to_value(record).unwrap();
    assert_eq!(
        replica_execute(
            &mut client,
            "UPDATE public.accordlock_issued_authorizations
                SET record_json = $5
              WHERE tenant = $1 AND environment = $2
                AND authorization_id = $3 AND transaction_id = $4",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
                &corrupted_record_json,
            ],
        ),
        1
    );
    let authorization_result = store.consume(&key);
    assert_eq!(
        replica_execute(
            &mut client,
            "UPDATE public.accordlock_issued_authorizations
                SET record_json = $5
              WHERE tenant = $1 AND environment = $2
                AND authorization_id = $3 AND transaction_id = $4",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
                &original_record_json,
            ],
        ),
        1
    );
    assert!(matches!(
        authorization_result,
        Err(StateError::InvalidAuthorizationSignature(_))
    ));
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_rejects_divergent_grant_columns_and_json() {
    let (url, store) = configured_store();
    let now = database_time(&url);
    let key = register_fixture(
        &store,
        &unique_tenant("state-grant-integrity"),
        now,
        now + 300,
        1,
    );
    let mut client = Client::connect(&url, NoTls).unwrap();
    let grant_id: Uuid = client
        .query_one(
            "SELECT grant_id
               FROM public.accordlock_issued_authorizations
              WHERE tenant = $1 AND environment = $2
                AND authorization_id = $3 AND transaction_id = $4",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
            ],
        )
        .unwrap()
        .get("grant_id");
    let original_registration_json: serde_json::Value = client
        .query_one(
            "SELECT registration_json
               FROM public.accordlock_grants
              WHERE tenant = $1 AND environment = $2 AND grant_id = $3",
            &[&key.scope.tenant, &key.scope.environment, &grant_id],
        )
        .unwrap()
        .get("registration_json");
    let mut corrupted_grant: GrantRegistration =
        serde_json::from_value(original_registration_json.clone()).unwrap();
    corrupted_grant.grant.maximum_uses += 1;
    let corrupted_registration_json = serde_json::to_value(corrupted_grant).unwrap();
    assert_eq!(
        replica_execute(
            &mut client,
            "UPDATE public.accordlock_grants
                SET registration_json = $4
              WHERE tenant = $1 AND environment = $2 AND grant_id = $3",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &grant_id,
                &corrupted_registration_json,
            ],
        ),
        1
    );
    let grant_result = store.grant_snapshot(&key.scope, grant_id);
    let consume_result = store.consume(&key);
    assert_eq!(
        replica_execute(
            &mut client,
            "UPDATE public.accordlock_grants
                SET registration_json = $4
              WHERE tenant = $1 AND environment = $2 AND grant_id = $3",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &grant_id,
                &original_registration_json,
            ],
        ),
        1
    );
    assert!(matches!(
        grant_result,
        Err(StateError::InvalidRecord(_) | StateError::GrantRegistryRootMismatch)
    ));
    assert!(matches!(
        consume_result,
        Err(StateError::InvalidRecord(_) | StateError::GrantRegistryRootMismatch)
    ));
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_recomputes_stored_dispatch_deadline() {
    let (url, store) = configured_store();
    let now = database_time(&url);
    let key = register_fixture(
        &store,
        &unique_tenant("state-deadline-integrity"),
        now,
        now + 300,
        1,
    );
    let original_receipt = store.consume(&key).unwrap().receipt().clone();
    let original_receipt_json = serde_json::to_value(&original_receipt).unwrap();
    let mut receipt = original_receipt.clone();
    receipt.dispatch_deadline += 1;
    let corrupted_receipt_json = serde_json::to_value(&receipt).unwrap();
    let mut client = Client::connect(&url, NoTls).unwrap();
    assert_eq!(
        replica_execute(
            &mut client,
            "UPDATE public.accordlock_consumptions
                SET receipt_json = $5, dispatch_deadline = $6
              WHERE tenant = $1 AND environment = $2
                AND authorization_id = $3 AND transaction_id = $4",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
                &corrupted_receipt_json,
                &receipt.dispatch_deadline,
            ],
        ),
        1
    );
    let receipt_result = store.consumption_receipt(&key);
    assert_eq!(
        replica_execute(
            &mut client,
            "UPDATE public.accordlock_consumptions
                SET receipt_json = $5, dispatch_deadline = $6
              WHERE tenant = $1 AND environment = $2
                AND authorization_id = $3 AND transaction_id = $4",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
                &original_receipt_json,
                &original_receipt.dispatch_deadline,
            ],
        ),
        1
    );
    assert!(matches!(receipt_result, Err(StateError::InvalidRecord(_))));
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
#[allow(clippy::too_many_lines)]
fn postgres_migration_is_idempotent_and_verified() {
    let (url, store) = configured_store();
    let first_instance_id = store.state_instance_id().unwrap();
    store.migrate().unwrap();
    store.validate_schema().unwrap();
    assert_eq!(store.state_instance_id().unwrap(), first_instance_id);
    let mut client = Client::connect(&url, NoTls).unwrap();
    let versions: Vec<(i32, String)> = client
        .query(
            "SELECT version, name
               FROM public.accordlock_schema_migrations
              ORDER BY version",
            &[],
        )
        .unwrap()
        .into_iter()
        .map(|row| (row.get("version"), row.get("name")))
        .collect();
    assert_eq!(
        versions,
        vec![
            (1, "0001_transactional_state".to_owned()),
            (2, "0002_state_integrity".to_owned()),
            (3, "0003_state_instance".to_owned()),
            (4, "0004_signed_issuance_profile".to_owned()),
            (5, "0005_dispatch_claims".to_owned()),
            (6, "0006_physical_resource_reservations".to_owned()),
            (7, "0007_admission_authorizations".to_owned()),
            (8, "0008_attempt_credential_binding".to_owned()),
            (9, "0009_broker_operation_journal".to_owned()),
            (10, "0010_ingress_replay".to_owned()),
            (11, "0011_eks_destination_registry".to_owned()),
            (12, "0012_terminal_retirement".to_owned()),
            (13, "0013_durable_control_submissions".to_owned()),
            (14, "0014_durable_dispatch_acquisitions".to_owned())
        ]
    );

    client
        .batch_execute(
            "ALTER TABLE public.accordlock_issued_authorizations
                 DROP CONSTRAINT accordlock_issued_authorizations_hash_check;
             ALTER TABLE public.accordlock_issued_authorizations
                 ADD CONSTRAINT accordlock_issued_authorizations_hash_check CHECK (TRUE);",
        )
        .unwrap();
    let drift_result = store.migrate();
    client
        .batch_execute(
            "ALTER TABLE public.accordlock_issued_authorizations
                 DROP CONSTRAINT accordlock_issued_authorizations_hash_check;
             ALTER TABLE public.accordlock_issued_authorizations
                 ADD CONSTRAINT accordlock_issued_authorizations_hash_check
                 CHECK (authorization_hash ~ '^sha256:[0-9a-f]{64}$');",
        )
        .unwrap();
    assert!(matches!(drift_result, Err(StateError::SchemaMismatch(_))));
    store.migrate().unwrap();

    client
        .batch_execute(
            "ALTER TABLE public.accordlock_admission_authorizations
                 DROP CONSTRAINT accordlock_admission_authorizations_grant_id_check;
             ALTER TABLE public.accordlock_admission_authorizations
                 ADD CONSTRAINT accordlock_admission_authorizations_grant_id_check
                 CHECK (TRUE);",
        )
        .unwrap();
    let admission_constraint_drift = store.validate_schema();
    client
        .batch_execute(
            "ALTER TABLE public.accordlock_admission_authorizations
                 DROP CONSTRAINT accordlock_admission_authorizations_grant_id_check;
             ALTER TABLE public.accordlock_admission_authorizations
                 ADD CONSTRAINT accordlock_admission_authorizations_grant_id_check
                 CHECK (grant_id <> '00000000-0000-0000-0000-000000000000'::uuid);",
        )
        .unwrap();
    assert!(matches!(
        admission_constraint_drift,
        Err(StateError::SchemaMismatch(_))
    ));
    store.migrate().unwrap();

    client
        .batch_execute(
            "ALTER TABLE public.accordlock_admission_authorizations
                 ALTER COLUMN observer_identity_commitment DROP NOT NULL;",
        )
        .unwrap();
    let admission_column_drift = store.validate_schema();
    client
        .batch_execute(
            "ALTER TABLE public.accordlock_admission_authorizations
                 ALTER COLUMN observer_identity_commitment SET NOT NULL;",
        )
        .unwrap();
    assert!(matches!(
        admission_column_drift,
        Err(StateError::SchemaMismatch(_))
    ));
    store.migrate().unwrap();

    client
        .batch_execute(
            "ALTER TABLE public.accordlock_broker_operations
                 DROP CONSTRAINT accordlock_broker_operations_time_check;
             ALTER TABLE public.accordlock_broker_operations
                 ADD CONSTRAINT accordlock_broker_operations_time_check CHECK (TRUE);",
        )
        .unwrap();
    let broker_constraint_drift = store.validate_schema();
    client
        .batch_execute(
            "ALTER TABLE public.accordlock_broker_operations
                 DROP CONSTRAINT accordlock_broker_operations_time_check;
             ALTER TABLE public.accordlock_broker_operations
                 ADD CONSTRAINT accordlock_broker_operations_time_check CHECK (
                     prepared_unix_s >= 0
                     AND (started_unix_s IS NULL OR started_unix_s >= prepared_unix_s)
                     AND (credential_safe_after IS NULL
                          OR credential_safe_after > started_unix_s)
                     AND (token_expires_at IS NULL
                          OR (token_expires_at > started_unix_s
                              AND token_expires_at <= credential_safe_after))
                 );",
        )
        .unwrap();
    assert!(matches!(
        broker_constraint_drift,
        Err(StateError::SchemaMismatch(_))
    ));
    store.migrate().unwrap();

    client
        .batch_execute(
            "ALTER TABLE public.accordlock_broker_operations
                 ALTER COLUMN route_commitment DROP NOT NULL;",
        )
        .unwrap();
    let broker_column_drift = store.validate_schema();
    client
        .batch_execute(
            "ALTER TABLE public.accordlock_broker_operations
                 ALTER COLUMN route_commitment SET NOT NULL;",
        )
        .unwrap();
    assert!(matches!(
        broker_column_drift,
        Err(StateError::SchemaMismatch(_))
    ));
    store.migrate().unwrap();

    client
        .batch_execute(
            "ALTER TABLE public.accordlock_broker_operations
                 ALTER COLUMN reconciliation_count DROP NOT NULL;",
        )
        .unwrap();
    let broker_reconciliation_column_drift = store.validate_schema();
    client
        .batch_execute(
            "ALTER TABLE public.accordlock_broker_operations
                 ALTER COLUMN reconciliation_count SET NOT NULL;",
        )
        .unwrap();
    assert!(matches!(
        broker_reconciliation_column_drift,
        Err(StateError::SchemaMismatch(_))
    ));
    store.migrate().unwrap();

    client
        .batch_execute("DROP INDEX public.accordlock_ingress_replay_nonces_expiry_idx;")
        .unwrap();
    let ingress_index_drift = store.validate_schema();
    client
        .batch_execute(
            "CREATE INDEX accordlock_ingress_replay_nonces_expiry_idx
                 ON public.accordlock_ingress_replay_nonces
                    (replay_scope, expires_unix_s, key_id, nonce);",
        )
        .unwrap();
    assert!(matches!(
        ingress_index_drift,
        Err(StateError::SchemaMismatch(_))
    ));

    client
        .batch_execute(
            "ALTER TABLE public.accordlock_ingress_replay_scopes
                 DROP CONSTRAINT accordlock_ingress_replay_scopes_time_check;
             ALTER TABLE public.accordlock_ingress_replay_scopes
                 ADD CONSTRAINT accordlock_ingress_replay_scopes_time_check CHECK (TRUE);",
        )
        .unwrap();
    let ingress_constraint_drift = store.validate_schema();
    client
        .batch_execute(
            "ALTER TABLE public.accordlock_ingress_replay_scopes
                 DROP CONSTRAINT accordlock_ingress_replay_scopes_time_check;
             ALTER TABLE public.accordlock_ingress_replay_scopes
                 ADD CONSTRAINT accordlock_ingress_replay_scopes_time_check
                 CHECK (observed_unix_s >= 0);",
        )
        .unwrap();
    assert!(matches!(
        ingress_constraint_drift,
        Err(StateError::SchemaMismatch(_))
    ));

    client
        .batch_execute(
            "ALTER TABLE public.accordlock_ingress_replay_nonces
                 ALTER COLUMN consumed_unix_s DROP NOT NULL;",
        )
        .unwrap();
    let ingress_column_drift = store.validate_schema();
    client
        .batch_execute(
            "ALTER TABLE public.accordlock_ingress_replay_nonces
                 ALTER COLUMN consumed_unix_s SET NOT NULL;",
        )
        .unwrap();
    assert!(matches!(
        ingress_column_drift,
        Err(StateError::SchemaMismatch(_))
    ));

    client
        .batch_execute(
            "ALTER TABLE public.accordlock_eks_destination_activations
                 DROP CONSTRAINT accordlock_eks_destination_activations_lifecycle_check;
             ALTER TABLE public.accordlock_eks_destination_activations
                 ADD CONSTRAINT accordlock_eks_destination_activations_lifecycle_check
                 CHECK (TRUE);",
        )
        .unwrap();
    let eks_constraint_drift = store.validate_schema();
    client
        .batch_execute(
            "ALTER TABLE public.accordlock_eks_destination_activations
                 DROP CONSTRAINT accordlock_eks_destination_activations_lifecycle_check;
             ALTER TABLE public.accordlock_eks_destination_activations
                 ADD CONSTRAINT accordlock_eks_destination_activations_lifecycle_check CHECK (
                     credential_lifecycle_schema_version = 1
                     AND credential_lifecycle_policy_id =
                         'eks-credential-lifecycle-v1'
                     AND requested_expiration_seconds BETWEEN 1 AND 86400
                     AND server_lifetime_hard_max_seconds BETWEEN
                         requested_expiration_seconds AND 86400
                     AND clock_uncertainty_seconds BETWEEN 0 AND 300
                     AND deletion_propagation_hard_max_seconds BETWEEN 60 AND 86400
                 );",
        )
        .unwrap();
    assert!(matches!(
        eks_constraint_drift,
        Err(StateError::SchemaMismatch(_))
    ));

    client
        .batch_execute(
            "ALTER TABLE public.accordlock_eks_destination_activations
                 ALTER COLUMN token_review_subject DROP NOT NULL;",
        )
        .unwrap();
    let eks_column_drift = store.validate_schema();
    client
        .batch_execute(
            "ALTER TABLE public.accordlock_eks_destination_activations
                 ALTER COLUMN token_review_subject SET NOT NULL;",
        )
        .unwrap();
    assert!(matches!(
        eks_column_drift,
        Err(StateError::SchemaMismatch(_))
    ));

    client
        .batch_execute("DROP INDEX public.accordlock_eks_destination_activations_current_idx;")
        .unwrap();
    let eks_index_drift = store.validate_schema();
    client
        .batch_execute(
            "CREATE INDEX accordlock_eks_destination_activations_current_idx
                 ON public.accordlock_eks_destination_activations
                    (tenant, environment,
                     resource_activation_id, mediation_activation_id);",
        )
        .unwrap();
    assert!(matches!(
        eks_index_drift,
        Err(StateError::SchemaMismatch(_))
    ));
    store.validate_schema().unwrap();
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
#[allow(clippy::too_many_lines)]
fn postgres_terminal_schema_rejects_alias_bound_index_fk_and_trigger_drift() {
    let (url, store) = configured_store();
    let mut client = Client::connect(&url, NoTls).unwrap();
    assert_eq!(MAX_TERMINAL_WITNESS_ENVELOPE_BYTES, 1_115_136);

    client
        .batch_execute(
            "ALTER TABLE public.accordlock_terminal_witness_registry_entries
                 DROP CONSTRAINT accordlock_terminal_witness_registry_entries_observer_key;
             ALTER TABLE public.accordlock_terminal_witness_registry_entries
                 ADD CONSTRAINT accordlock_terminal_witness_registry_entries_observer_key
                 UNIQUE (registry_commitment, observer_identity, role);",
        )
        .unwrap();
    assert!(matches!(
        store.validate_schema(),
        Err(StateError::SchemaMismatch(_))
    ));
    client
        .batch_execute(
            "ALTER TABLE public.accordlock_terminal_witness_registry_entries
                 DROP CONSTRAINT accordlock_terminal_witness_registry_entries_observer_key;
             ALTER TABLE public.accordlock_terminal_witness_registry_entries
                 ADD CONSTRAINT accordlock_terminal_witness_registry_entries_observer_key
                 UNIQUE (registry_commitment, observer_identity);",
        )
        .unwrap();

    let identity_definition: String = client
        .query_one(
            "SELECT pg_get_constraintdef(oid, TRUE) AS definition
               FROM pg_constraint
              WHERE conname = 'accordlock_terminal_retirements_identity_check'",
            &[],
        )
        .unwrap()
        .get("definition");
    assert!(identity_definition.contains("1115136"));
    client
        .batch_execute(
            "ALTER TABLE public.accordlock_terminal_retirements
                 DROP CONSTRAINT accordlock_terminal_retirements_identity_check;
             ALTER TABLE public.accordlock_terminal_retirements
                 ADD CONSTRAINT accordlock_terminal_retirements_identity_check
                 CHECK (
                     octet_length(effect_envelope) BETWEEN 1 AND 1048576
                     AND octet_length(retirement_envelope) BETWEEN 1 AND 1048576
                 );",
        )
        .unwrap();
    assert!(matches!(
        store.validate_schema(),
        Err(StateError::SchemaMismatch(_))
    ));
    client
        .batch_execute(&format!(
            "ALTER TABLE public.accordlock_terminal_retirements
                 DROP CONSTRAINT accordlock_terminal_retirements_identity_check;
             ALTER TABLE public.accordlock_terminal_retirements
                 ADD CONSTRAINT accordlock_terminal_retirements_identity_check
                 {identity_definition};"
        ))
        .unwrap();

    client
        .batch_execute(
            "DROP INDEX public.accordlock_dispatch_claims_active_physical_resource_key;
             CREATE UNIQUE INDEX accordlock_dispatch_claims_active_physical_resource_key
                 ON public.accordlock_dispatch_claims
                    (cluster_identity, namespace, deployment_uid)
                 WHERE state = 'CLAIMED';",
        )
        .unwrap();
    assert!(matches!(
        store.validate_schema(),
        Err(StateError::SchemaMismatch(_))
    ));
    client
        .batch_execute(
            "DROP INDEX public.accordlock_dispatch_claims_active_physical_resource_key;
             CREATE UNIQUE INDEX accordlock_dispatch_claims_active_physical_resource_key
                 ON public.accordlock_dispatch_claims
                    (cluster_identity, namespace, deployment_uid)
                 WHERE state IN ('CLAIMED', 'ATTEMPT_IN_FLIGHT', 'RECOVERY_NO_SEND');",
        )
        .unwrap();

    let terminal_fk: String = client
        .query_one(
            "SELECT pg_get_constraintdef(oid, TRUE) AS definition
               FROM pg_constraint
              WHERE conname = 'accordlock_dispatch_claims_terminal_fkey'",
            &[],
        )
        .unwrap()
        .get("definition");
    client
        .batch_execute(
            "ALTER TABLE public.accordlock_dispatch_claims
                 DROP CONSTRAINT accordlock_dispatch_claims_terminal_fkey;",
        )
        .unwrap();
    assert!(matches!(
        store.validate_schema(),
        Err(StateError::SchemaMismatch(_))
    ));
    client
        .batch_execute(&format!(
            "ALTER TABLE public.accordlock_dispatch_claims
                 ADD CONSTRAINT accordlock_dispatch_claims_terminal_fkey {terminal_fk};"
        ))
        .unwrap();

    client
        .batch_execute(
            "ALTER TABLE public.accordlock_terminal_retirements
                 DISABLE TRIGGER accordlock_terminal_retirements_append_only;",
        )
        .unwrap();
    assert!(matches!(
        store.validate_schema(),
        Err(StateError::SchemaMismatch(_))
    ));
    client
        .batch_execute(
            "ALTER TABLE public.accordlock_terminal_retirements
                 ENABLE TRIGGER accordlock_terminal_retirements_append_only;",
        )
        .unwrap();
    store.validate_schema().unwrap();
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_v11_upgrade_adds_exact_terminal_retirement_schema_without_backfill() {
    let (url, store) = configured_historical_rebuild_store();
    let mut client = Client::connect(&url, NoTls).unwrap();
    rebuild_disposable_postgres_through(&mut client, &url, 11);

    store.migrate().unwrap();
    store.validate_schema().unwrap();
    let migration: (i32, String) = client
        .query_one(
            "SELECT version, name
               FROM public.accordlock_schema_migrations
              WHERE version = 12",
            &[],
        )
        .map(|row| (row.get("version"), row.get("name")))
        .unwrap();
    assert_eq!(migration, (12, "0012_terminal_retirement".to_owned()));
    let profile: (bool, bool, bool, i64) = client
        .query_one(
            "SELECT
                 to_regclass('public.accordlock_terminal_witness_registries') IS NOT NULL,
                 to_regclass('public.accordlock_broker_secret_deletion_observations') IS NOT NULL,
                 to_regclass('public.accordlock_terminal_retirements') IS NOT NULL,
                 (SELECT count(*)::bigint
                    FROM public.accordlock_broker_secret_deletion_observations)",
            &[],
        )
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
        .unwrap();
    assert_eq!(profile, (true, true, true, 0));
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_v10_upgrade_adds_exact_eks_registry_schema() {
    let (url, store) = configured_historical_rebuild_store();
    let mut client = Client::connect(&url, NoTls).unwrap();
    rebuild_disposable_postgres_through(&mut client, &url, 10);
    store.migrate().unwrap();
    store.validate_schema().unwrap();
    let migration: (i32, String) = client
        .query_one(
            "SELECT version, name
               FROM public.accordlock_schema_migrations
              WHERE version = 11",
            &[],
        )
        .map(|row| (row.get("version"), row.get("name")))
        .unwrap();
    assert_eq!(migration, (11, "0011_eks_destination_registry".to_owned()));
    let tables_present: bool = client
        .query_one(
            "SELECT to_regclass('public.accordlock_eks_physical_owners') IS NOT NULL
                    AND to_regclass(
                        'public.accordlock_eks_destination_activations'
                    ) IS NOT NULL AS present",
            &[],
        )
        .unwrap()
        .get("present");
    assert!(tables_present);
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_v5_upgrade_backfills_existing_claim_physical_identity() {
    let (url, store) = configured_historical_rebuild_store();
    let now = database_time(&url);
    let tenant = unique_tenant("physical-upgrade");
    let key = register_fixture(&store, &tenant, now, now + 300, 1);
    store.consume(&key).unwrap();
    let claimed = store
        .claim_dispatch(&dispatch_claim_request(
            &key,
            Uuid::new_v4(),
            "worker-upgrade",
        ))
        .unwrap();
    let expected_uid = format!("deployment-uid-{tenant}");

    let mut client = Client::connect(&url, NoTls).unwrap();
    snapshot_v5_claim_fixture(&mut client, &key);
    rebuild_disposable_postgres_through(&mut client, &url, 5);
    restore_v5_claim_fixture(&mut client);

    store.migrate().unwrap();
    let row = client
        .query_one(
            "SELECT cluster_identity, namespace, deployment_uid
               FROM public.accordlock_dispatch_claims
              WHERE tenant = $1 AND environment = $2 AND authorization_id = $3",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
            ],
        )
        .unwrap();
    assert_eq!(row.get::<_, String>("cluster_identity"), "cluster-a");
    assert_eq!(row.get::<_, String>("namespace"), "payments");
    assert_eq!(row.get::<_, String>("deployment_uid"), expected_uid);
    assert_eq!(
        store
            .revalidate_dispatch_claim(claimed.token())
            .unwrap()
            .issued()
            .transaction_id,
        key.transaction_id
    );
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_rejects_migration_checksum_drift() {
    let (url, store) = configured_store();
    let mut client = Client::connect(&url, NoTls).unwrap();
    let original: String = client
        .query_one(
            "SELECT sha256
               FROM public.accordlock_schema_migrations
              WHERE version = 3",
            &[],
        )
        .unwrap()
        .get("sha256");
    client
        .execute(
            "UPDATE public.accordlock_schema_migrations
                SET sha256 = $1
              WHERE version = 3",
            &[&format!("sha256:{}", "0".repeat(64))],
        )
        .unwrap();
    let drift_result = store.migrate();
    client
        .execute(
            "UPDATE public.accordlock_schema_migrations
                SET sha256 = $1
              WHERE version = 3",
            &[&original],
        )
        .unwrap();
    assert!(matches!(drift_result, Err(StateError::SchemaMismatch(_))));
    store.migrate().unwrap();
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
#[allow(clippy::too_many_lines)]
fn postgres_rejects_dispatch_claim_constraint_and_fence_sequence_drift() {
    let (url, store) = configured_store();
    let mut client = Client::connect(&url, NoTls).unwrap();
    client
        .batch_execute(
            "ALTER TABLE public.accordlock_dispatch_claims
                 DROP CONSTRAINT accordlock_dispatch_claims_worker_id_check;
             ALTER TABLE public.accordlock_dispatch_claims
                 ADD CONSTRAINT accordlock_dispatch_claims_worker_id_check CHECK (TRUE);",
        )
        .unwrap();
    let constraint_drift = store.migrate();
    client
        .batch_execute(
            "ALTER TABLE public.accordlock_dispatch_claims
                 DROP CONSTRAINT accordlock_dispatch_claims_worker_id_check;
             ALTER TABLE public.accordlock_dispatch_claims
                 ADD CONSTRAINT accordlock_dispatch_claims_worker_id_check
                 CHECK (
                     octet_length(worker_id) BETWEEN 1 AND 253
                     AND worker_id ~ '^[a-z]([a-z0-9._:/@-]*[a-z0-9])?$'
                 );",
        )
        .unwrap();
    assert!(matches!(
        constraint_drift,
        Err(StateError::SchemaMismatch(_))
    ));
    store.migrate().unwrap();

    client
        .batch_execute(
            "DROP INDEX public.accordlock_dispatch_claims_active_physical_resource_key;
             CREATE UNIQUE INDEX accordlock_dispatch_claims_active_physical_resource_key
                 ON public.accordlock_dispatch_claims
                    (cluster_identity, namespace, deployment_uid)
                 WHERE state = 'CLAIMED';",
        )
        .unwrap();
    let physical_constraint_drift = store.migrate();
    client
        .batch_execute(
            "DROP INDEX public.accordlock_dispatch_claims_active_physical_resource_key;
             CREATE UNIQUE INDEX accordlock_dispatch_claims_active_physical_resource_key
                 ON public.accordlock_dispatch_claims
                    (cluster_identity, namespace, deployment_uid)
                 WHERE state IN ('CLAIMED', 'ATTEMPT_IN_FLIGHT', 'RECOVERY_NO_SEND');",
        )
        .unwrap();
    assert!(matches!(
        physical_constraint_drift,
        Err(StateError::SchemaMismatch(_))
    ));
    store.migrate().unwrap();

    let sequence_name: String = client
        .query_one(
            "SELECT pg_get_serial_sequence(
                        'public.accordlock_dispatch_claims', 'fence'
                    ) AS sequence_name",
            &[],
        )
        .unwrap()
        .get("sequence_name");
    assert_eq!(sequence_name, "public.accordlock_dispatch_claims_fence_seq");
    client
        .batch_execute("ALTER SEQUENCE public.accordlock_dispatch_claims_fence_seq INCREMENT BY 2")
        .unwrap();
    let sequence_drift = store.migrate();
    client
        .batch_execute("ALTER SEQUENCE public.accordlock_dispatch_claims_fence_seq INCREMENT BY 1")
        .unwrap();
    assert!(matches!(sequence_drift, Err(StateError::SchemaMismatch(_))));
    store.migrate().unwrap();

    client
        .batch_execute("ALTER SEQUENCE public.accordlock_dispatch_claims_fence_seq START WITH 2")
        .unwrap();
    let sequence_start_drift = store.migrate();
    client
        .batch_execute("ALTER SEQUENCE public.accordlock_dispatch_claims_fence_seq START WITH 1")
        .unwrap();
    assert!(matches!(
        sequence_start_drift,
        Err(StateError::SchemaMismatch(_))
    ));
    store.migrate().unwrap();

    client
        .batch_execute(
            "ALTER SEQUENCE public.accordlock_dispatch_claims_fence_seq
                 MAXVALUE 9223372036854775806",
        )
        .unwrap();
    let sequence_max_drift = store.migrate();
    client
        .batch_execute("ALTER SEQUENCE public.accordlock_dispatch_claims_fence_seq NO MAXVALUE")
        .unwrap();
    assert!(matches!(
        sequence_max_drift,
        Err(StateError::SchemaMismatch(_))
    ));
    store.migrate().unwrap();

    let now = database_time(&url);
    let key = register_fixture(
        &store,
        &unique_tenant("dispatch-fence-runtime-drift"),
        now,
        now + 300,
        1,
    );
    store.consume(&key).unwrap();
    store
        .claim_dispatch(&dispatch_claim_request(
            &key,
            Uuid::new_v4(),
            "worker-sequence",
        ))
        .unwrap();
    client
        .batch_execute("ALTER SEQUENCE public.accordlock_dispatch_claims_fence_seq RESTART WITH 1")
        .unwrap();
    let sequence_runtime_drift = store.migrate();
    client
        .query_one(
            "SELECT setval(
                        'public.accordlock_dispatch_claims_fence_seq',
                        (SELECT max(fence) FROM public.accordlock_dispatch_claims),
                        TRUE
                    ) AS restored",
            &[],
        )
        .unwrap();
    assert!(matches!(
        sequence_runtime_drift,
        Err(StateError::SchemaMismatch(_))
    ));
    store.migrate().unwrap();
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_dispatch_snapshot_accepts_exact_consumed_state_at_maximum_uses() {
    let (url, store) = configured_store();
    let now = database_time(&url);
    let key = register_fixture(
        &store,
        &unique_tenant("dispatch-success"),
        now,
        now + 300,
        1,
    );
    assert!(matches!(
        store.dispatch_snapshot(&key),
        Err(StateError::GrantNotConsumed)
    ));

    let consumed = store.consume(&key).unwrap();
    let snapshot = store.dispatch_snapshot(&key).unwrap();
    assert_eq!(snapshot.scope(), &key.scope);
    assert!(snapshot.checked_at() >= consumed.receipt().consumed_at);
    assert!(snapshot.checked_at() < consumed.receipt().dispatch_deadline);
    assert_eq!(snapshot.authority(), &consumed.receipt().authority);
    assert_eq!(snapshot.issued(), consumed.issued());
    assert_eq!(snapshot.receipt(), consumed.receipt());
    assert_eq!(snapshot.outbox(), consumed.outbox());
    assert_eq!(
        store
            .grant_snapshot(&key.scope, consumed.issued().authorization().grant_id)
            .unwrap()
            .uses,
        1
    );
    assert_eq!(
        store.time_high_water(&key.scope).unwrap(),
        Some(snapshot.checked_at())
    );
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_dispatch_snapshot_deadline_rejection_commits_high_water() {
    let (url, store) = configured_store();
    let now = database_time(&url);
    let key = register_fixture(&store, &unique_tenant("dispatch-boundary"), now, now + 4, 1);
    let consumed = store.consume(&key).unwrap();
    while database_time(&url) < consumed.receipt().dispatch_deadline {
        thread::sleep(Duration::from_millis(25));
    }

    let rejected_at = match store.dispatch_snapshot(&key) {
        Err(StateError::DispatchDeadlineExpired {
            observed,
            dispatch_deadline,
        }) if observed >= dispatch_deadline
            && dispatch_deadline == consumed.receipt().dispatch_deadline =>
        {
            observed
        }
        result => panic!("unexpected deadline result: {result:?}"),
    };
    assert_eq!(
        store.time_high_water(&key.scope).unwrap(),
        Some(rejected_at)
    );
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
#[allow(clippy::too_many_lines)]
fn postgres_temporal_claim_rejections_commit_high_water_before_error() {
    let (url, store) = configured_store();
    let now = database_time(&url);
    let creation_key = register_fixture(
        &store,
        &unique_tenant("claim-expired-create"),
        now,
        now + 6,
        1,
    );
    let revalidate_key = register_fixture(
        &store,
        &unique_tenant("claim-expired-revalidate"),
        now,
        now + 6,
        1,
    );
    let mark_key = register_fixture(
        &store,
        &unique_tenant("claim-expired-mark"),
        now,
        now + 6,
        1,
    );
    let creation_consumed = store.consume(&creation_key).unwrap();
    store.consume(&revalidate_key).unwrap();
    store.consume(&mark_key).unwrap();
    let revalidate_claim = store
        .claim_dispatch(&dispatch_claim_request(
            &revalidate_key,
            Uuid::new_v4(),
            "worker-revalidate",
        ))
        .unwrap();
    let mark_claim = store
        .claim_dispatch(&dispatch_claim_request(
            &mark_key,
            Uuid::new_v4(),
            "worker-mark",
        ))
        .unwrap();
    let creation_high_water_before = store.time_high_water(&creation_key.scope).unwrap().unwrap();
    let deadline = creation_consumed.receipt().dispatch_deadline;
    while database_time(&url) < deadline {
        thread::sleep(Duration::from_millis(25));
    }

    let creation_observed = match store.claim_dispatch(&dispatch_claim_request(
        &creation_key,
        Uuid::new_v4(),
        "worker-create",
    )) {
        Err(StateError::DispatchDeadlineExpired {
            observed,
            dispatch_deadline,
        }) if dispatch_deadline == deadline && observed >= dispatch_deadline => observed,
        result => panic!("unexpected expired claim-creation result: {result:?}"),
    };
    // A rejected legacy CREATE has no claim/acquisition child with which to
    // bind its reserved request identity. v14 therefore rolls the whole
    // transaction back, including the sampled scope HWM, while returning the
    // exact temporal observation. Post-claim revalidation and marking below
    // do have durable children and must still commit their sampled HWM.
    assert!(creation_observed >= creation_high_water_before);
    assert_eq!(
        store.time_high_water(&creation_key.scope).unwrap(),
        Some(creation_high_water_before)
    );

    let revalidate_observed = match store.revalidate_dispatch_claim(revalidate_claim.token()) {
        Err(StateError::DispatchDeadlineExpired {
            observed,
            dispatch_deadline,
        }) if observed >= dispatch_deadline => observed,
        result => panic!("unexpected expired claim-revalidation result: {result:?}"),
    };
    assert_eq!(
        store.time_high_water(&revalidate_key.scope).unwrap(),
        Some(revalidate_observed)
    );

    let mark_observed =
        match store.mark_attempt_in_flight(mark_claim.token(), credential(mark_claim.token())) {
            Err(StateError::DispatchDeadlineExpired {
                observed,
                dispatch_deadline,
            }) if observed >= dispatch_deadline => observed,
            result => panic!("unexpected expired claim-mark result: {result:?}"),
        };
    assert_eq!(
        store.time_high_water(&mark_key.scope).unwrap(),
        Some(mark_observed)
    );

    let mut client = Client::connect(&url, NoTls).unwrap();
    let creation_claims: i64 = client
        .query_one(
            "SELECT count(*)::bigint AS claim_count
               FROM public.accordlock_dispatch_claims
              WHERE tenant = $1 AND environment = $2 AND authorization_id = $3",
            &[
                &creation_key.scope.tenant,
                &creation_key.scope.environment,
                &creation_key.authorization_id,
            ],
        )
        .unwrap()
        .get("claim_count");
    assert_eq!(creation_claims, 0);
    for key in [&revalidate_key, &mark_key] {
        let row = client
            .query_one(
                "SELECT state, attempt_started_at
                   FROM public.accordlock_dispatch_claims
                  WHERE tenant = $1 AND environment = $2 AND authorization_id = $3",
                &[
                    &key.scope.tenant,
                    &key.scope.environment,
                    &key.authorization_id,
                ],
            )
            .unwrap();
        assert_eq!(row.get::<_, String>("state"), "CLAIMED");
        assert_eq!(row.get::<_, Option<i64>>("attempt_started_at"), None);
    }

    // PostgreSQL's wall clock cannot be moved by the test. Raising the
    // durable mark simulates the same rollback immediately after each
    // committed temporal rejection.
    let rollback_high_water = database_time(&url) + 60;
    for key in [&creation_key, &revalidate_key, &mark_key] {
        set_high_water(&url, key, rollback_high_water);
    }
    assert!(matches!(
        store.claim_dispatch(&dispatch_claim_request(
            &creation_key,
            Uuid::new_v4(),
            "worker-create-rollback",
        )),
        Err(StateError::ClockRollback {
            observed,
            high_water
        }) if observed < high_water && high_water == rollback_high_water
    ));
    assert!(matches!(
        store.revalidate_dispatch_claim(revalidate_claim.token()),
        Err(StateError::ClockRollback {
            observed,
            high_water
        }) if observed < high_water && high_water == rollback_high_water
    ));
    assert!(matches!(
        store.mark_attempt_in_flight(mark_claim.token(), credential(mark_claim.token())),
        Err(StateError::ClockRollback {
            observed,
            high_water
        }) if observed < high_water && high_water == rollback_high_water
    ));
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_dispatch_snapshot_rejects_authority_change_and_revocation() {
    let (url, store) = configured_store();
    let now = database_time(&url);
    let authority_key = register_fixture(
        &store,
        &unique_tenant("dispatch-authority"),
        now,
        now + 300,
        2,
    );
    store.consume(&authority_key).unwrap();
    let authority = store.active_authority(&authority_key.scope).unwrap();
    let mut advanced = authority.clone();
    advanced.policy.epoch += 1;
    advanced.policy.activation_id = Uuid::new_v4();
    advanced.policy.root = digest("dispatch-policy-v2");
    store
        .compare_and_activate_authority(&authority_key.scope, Some(&authority), &advanced)
        .unwrap();
    assert!(matches!(
        store.dispatch_snapshot(&authority_key),
        Err(StateError::AuthorityMismatch)
    ));

    let revoke_key = register_fixture(
        &store,
        &unique_tenant("dispatch-revocation"),
        now,
        now + 300,
        2,
    );
    let consumed = store.consume(&revoke_key).unwrap();
    let grant_id = consumed.issued().authorization().grant_id;
    let authority = store.active_authority(&revoke_key.scope).unwrap();
    let mut revoked = authority.clone();
    revoked.revocation.epoch += 1;
    revoked.revocation.activation_id = Uuid::new_v4();
    revoked.revocation.root = grant_revocation_root(grant_id);
    store
        .revoke_grant(&revoke_key.scope, grant_id, &authority, &revoked)
        .unwrap();
    assert!(matches!(
        store.dispatch_snapshot(&revoke_key),
        Err(StateError::GrantRevoked)
    ));
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_dispatch_snapshot_rejects_rollback() {
    let (url, store) = configured_store();
    let now = database_time(&url);
    let key = register_fixture(
        &store,
        &unique_tenant("dispatch-rollback"),
        now,
        now + 300,
        2,
    );
    store.consume(&key).unwrap();
    let accepted = store.dispatch_snapshot(&key).unwrap();
    let forged_high_water = accepted.checked_at() + 5;
    Client::connect(&url, NoTls)
        .unwrap()
        .execute(
            "UPDATE public.accordlock_time_high_water
                SET observed_unix_s = $3
              WHERE tenant = $1 AND environment = $2",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &forged_high_water,
            ],
        )
        .unwrap();

    assert!(matches!(
        store.dispatch_snapshot(&key),
        Err(StateError::ClockRollback {
            observed,
            high_water
        }) if observed < high_water && high_water == forged_high_water
    ));
    assert_eq!(
        store.time_high_water(&key.scope).unwrap(),
        Some(forged_high_water)
    );
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
#[allow(clippy::too_many_lines)]
fn postgres_dispatch_snapshot_rejects_corruption_and_wrong_routing() {
    let (url, store) = configured_store();
    let now = database_time(&url);
    let routing_key = register_fixture(
        &store,
        &unique_tenant("dispatch-routing"),
        now,
        now + 300,
        2,
    );
    store.consume(&routing_key).unwrap();
    let wrong_transaction = ConsumeKey {
        transaction_id: Uuid::new_v4(),
        ..routing_key.clone()
    };
    assert!(matches!(
        store.dispatch_snapshot(&wrong_transaction),
        Err(StateError::TransactionMismatch)
    ));

    let original_outbox = store.outbox_entry(&routing_key).unwrap();
    let original_outbox_json = serde_json::to_value(&original_outbox).unwrap();
    let mut outbox = original_outbox.clone();
    outbox.transaction_id = Uuid::new_v4();
    let corrupted_outbox_json = serde_json::to_value(outbox).unwrap();
    let mut client = Client::connect(&url, NoTls).unwrap();
    assert_eq!(
        replica_execute(
            &mut client,
            "UPDATE public.accordlock_execution_outbox
                SET entry_json = $5
              WHERE tenant = $1 AND environment = $2
                AND authorization_id = $3 AND transaction_id = $4",
            &[
                &routing_key.scope.tenant,
                &routing_key.scope.environment,
                &routing_key.authorization_id,
                &routing_key.transaction_id,
                &corrupted_outbox_json,
            ],
        ),
        1
    );
    let routing_result = store.dispatch_snapshot(&routing_key);
    assert_eq!(
        replica_execute(
            &mut client,
            "UPDATE public.accordlock_execution_outbox
                SET entry_json = $5
              WHERE tenant = $1 AND environment = $2
                AND authorization_id = $3 AND transaction_id = $4",
            &[
                &routing_key.scope.tenant,
                &routing_key.scope.environment,
                &routing_key.authorization_id,
                &routing_key.transaction_id,
                &original_outbox_json,
            ],
        ),
        1
    );
    assert!(matches!(routing_result, Err(StateError::InvalidRecord(_))));

    let signature_key = register_fixture(
        &store,
        &unique_tenant("dispatch-signature"),
        now,
        now + 300,
        2,
    );
    store.consume(&signature_key).unwrap();
    let original_record_json: serde_json::Value = client
        .query_one(
            "SELECT record_json
               FROM public.accordlock_issued_authorizations
              WHERE tenant = $1 AND environment = $2
                AND authorization_id = $3 AND transaction_id = $4",
            &[
                &signature_key.scope.tenant,
                &signature_key.scope.environment,
                &signature_key.authorization_id,
                &signature_key.transaction_id,
            ],
        )
        .unwrap()
        .get("record_json");
    let mut record: IssuedAuthorizationRecord =
        serde_json::from_value(original_record_json.clone()).unwrap();
    record.signed_authorization.cose_sign1.clear();
    let corrupted_record_json = serde_json::to_value(record).unwrap();
    assert_eq!(
        replica_execute(
            &mut client,
            "UPDATE public.accordlock_issued_authorizations
                SET record_json = $5
              WHERE tenant = $1 AND environment = $2
                AND authorization_id = $3 AND transaction_id = $4",
            &[
                &signature_key.scope.tenant,
                &signature_key.scope.environment,
                &signature_key.authorization_id,
                &signature_key.transaction_id,
                &corrupted_record_json,
            ],
        ),
        1
    );
    let signature_result = store.dispatch_snapshot(&signature_key);
    assert_eq!(
        replica_execute(
            &mut client,
            "UPDATE public.accordlock_issued_authorizations
                SET record_json = $5
              WHERE tenant = $1 AND environment = $2
                AND authorization_id = $3 AND transaction_id = $4",
            &[
                &signature_key.scope.tenant,
                &signature_key.scope.environment,
                &signature_key.authorization_id,
                &signature_key.transaction_id,
                &original_record_json,
            ],
        ),
        1
    );
    assert!(matches!(
        signature_result,
        Err(StateError::InvalidAuthorizationSignature(_))
    ));
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
#[allow(clippy::too_many_lines)]
fn postgres_admission_context_is_opaque_state_derived_and_non_consuming() {
    let (url, store) = configured_store();
    let now = database_time(&url);
    let mut client = Client::connect(&url, NoTls).unwrap();
    let separated_acquisition_fence: i64 = client
        .query_one(
            "SELECT setval(
                 'public.accordlock_dispatch_acquisitions_lease_fence_seq',
                 GREATEST(
                     (SELECT last_value
                        FROM public.accordlock_dispatch_claims_fence_seq),
                     (SELECT last_value
                        FROM public.accordlock_dispatch_acquisitions_lease_fence_seq)
                 ) + 100,
                 TRUE
             ) AS separated_fence",
            &[],
        )
        .unwrap()
        .get("separated_fence");
    let key = register_fixture(
        &store,
        &unique_tenant("admission-context"),
        now,
        now + 300,
        1,
    );
    store.consume(&key).unwrap();
    let claimed = store
        .claim_dispatch(&dispatch_claim_request(
            &key,
            Uuid::new_v4(),
            "worker-admission-context",
        ))
        .unwrap();
    let acquisition_fence: i64 = client
        .query_one(
            "SELECT lease_fence
               FROM public.accordlock_dispatch_acquisitions
              WHERE tenant = $1 AND environment = $2
                AND claim_id = $3
                AND selection_kind = 'LEGACY_BOOTSTRAP'",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &claimed.token().claim_id(),
            ],
        )
        .unwrap()
        .get("lease_fence");
    assert!(acquisition_fence > separated_acquisition_fence);
    assert_ne!(
        u64::try_from(acquisition_fence).unwrap(),
        claimed.token().fence()
    );
    let high_water_before = store.time_high_water(&key.scope).unwrap();
    assert!(matches!(
        store.admission_context(&key),
        Err(StateError::AdmissionClaimNotInFlight)
    ));
    assert_eq!(
        store.time_high_water(&key.scope).unwrap(),
        high_water_before
    );

    let credential = credential(claimed.token());
    let legacy_binding_commitment = credential.commitment();
    store
        .mark_attempt_in_flight(claimed.token(), credential)
        .unwrap();
    let durable_binding_commitment: Digest32 = Client::connect(&url, NoTls)
        .unwrap()
        .query_one(
            "SELECT credential_binding_commitment
               FROM public.accordlock_dispatch_claims
              WHERE tenant = $1 AND environment = $2
                AND authorization_id = $3 AND transaction_id = $4",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
            ],
        )
        .unwrap()
        .get::<_, String>("credential_binding_commitment")
        .parse()
        .unwrap();
    // Re-open the store so this assertion exercises only the durable row, not
    // any process-local value retained by the writer.
    let reloaded = PostgresStore::new(url.clone());
    reloaded.migrate().unwrap();
    let context = reloaded.admission_context(&key).unwrap();
    let prepared =
        accordlock_k8s::prepare_patch(context.template(), key.transaction_id, key.authorization_id)
            .unwrap();
    assert_eq!(context.key(), &key);
    assert_eq!(context.claim_id(), claimed.token().claim_id());
    assert_eq!(context.fence(), claimed.token().fence());
    assert_eq!(
        context.credential_token_digest(),
        Digest32::from_bytes([77; 32])
    );
    assert_eq!(context.service_account_uid(), "service-account-uid");
    assert_eq!(
        context.credential_id(),
        "AUTHORIZATION_ID=7ee52be0-9045-4653-aa5e-0da57b8dccdc"
    );
    assert_eq!(context.credential_not_before(), 0);
    assert_eq!(context.credential_expires_at(), i64::MAX);
    assert_eq!(
        context.credential_binding_commitment(),
        durable_binding_commitment
    );
    assert_ne!(
        context.credential_binding_commitment(),
        legacy_binding_commitment
    );
    assert_eq!(
        context.physical_resource(),
        claimed.token().physical_resource()
    );
    assert_eq!(
        context.template_hash(),
        canonical_hash(context.template()).unwrap()
    );
    assert_eq!(context.operation_hash(), prepared.operation_hash);
    assert_eq!(
        context.provider_request_commitment(),
        prepared.final_wire_commitment
    );
    assert!(context.started_at() <= context.checked_at());
    assert_eq!(
        context.dispatch_deadline(),
        claimed.snapshot().receipt().dispatch_deadline
    );
    assert_eq!(context.authority(), claimed.snapshot().authority());

    let count: i64 = Client::connect(&url, NoTls)
        .unwrap()
        .query_one(
            "SELECT count(*)::bigint AS authorization_count
               FROM public.accordlock_admission_authorizations
              WHERE tenant = $1 AND environment = $2 AND transaction_id = $3",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.transaction_id,
            ],
        )
        .unwrap()
        .get("authorization_count");
    assert_eq!(count, 0);
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_admission_is_exactly_recoverable_only_while_current() {
    let (url, store) = configured_store();
    let now = database_time(&url);
    let key = register_fixture(&store, &unique_tenant("admission-exact"), now, now + 300, 1);
    store.consume(&key).unwrap();
    begin_admission_attempt(&store, &key);
    let admission_uid = format!("review-exact-{}", Uuid::new_v4().simple());
    let request = admission_request(&store, &key, &admission_uid, "exact");

    let first = store.authorize_admission_or_recover(&request).unwrap();
    assert!(!first.was_recovered());
    let recovered = store.authorize_admission_or_recover(&request).unwrap();
    assert!(recovered.was_recovered());
    assert_eq!(recovered.authorized_at(), first.authorized_at());
    assert!(recovered.checked_at() >= first.checked_at());

    let changed_same_uid = admission_request(&store, &key, &admission_uid, "changed");
    assert!(matches!(
        store.authorize_admission_or_recover(&changed_same_uid),
        Err(StateError::AdmissionUidMismatch)
    ));
    let different_uid = format!("review-different-{}", Uuid::new_v4().simple());
    let different_uid = admission_request(&store, &key, &different_uid, "exact");
    assert!(matches!(
        store.authorize_admission_or_recover(&different_uid),
        Err(StateError::AdmissionAlreadyAuthorized)
    ));

    let authority = store.active_authority(&key.scope).unwrap();
    let mut advanced = authority.clone();
    advanced.policy.epoch += 1;
    advanced.policy.activation_id = Uuid::new_v4();
    advanced.policy.root = digest("admission-policy-v2");
    store
        .compare_and_activate_authority(&key.scope, Some(&authority), &advanced)
        .unwrap();
    assert!(matches!(
        store.authorize_admission_or_recover(&request),
        Err(StateError::AuthorityMismatch)
    ));
    let row = Client::connect(&url, NoTls)
        .unwrap()
        .query_one(
            "SELECT count(*)::bigint AS authorization_count,
                    min(decision) AS decision
               FROM public.accordlock_admission_authorizations
              WHERE admission_uid = $1",
            &[&admission_uid],
        )
        .unwrap();
    assert_eq!(row.get::<_, i64>("authorization_count"), 1);
    assert_eq!(
        row.get::<_, Option<String>>("decision").as_deref(),
        Some("ADMITTED")
    );
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_historical_admission_survives_but_does_not_authorize_after_revoke_or_expiry() {
    let (url, store) = configured_store();
    let now = database_time(&url);
    let revoke_key = register_fixture(
        &store,
        &unique_tenant("admission-revoke"),
        now,
        now + 300,
        1,
    );
    store.consume(&revoke_key).unwrap();
    begin_admission_attempt(&store, &revoke_key);
    let revoke_uid = format!("review-revoke-{}", Uuid::new_v4().simple());
    let revoke_request = admission_request(&store, &revoke_key, &revoke_uid, "revoke");
    store
        .authorize_admission_or_recover(&revoke_request)
        .unwrap();
    let authority = store.active_authority(&revoke_key.scope).unwrap();
    let grant_id = store
        .consumption_receipt(&revoke_key)
        .and_then(|_| store.dispatch_snapshot(&revoke_key))
        .map(|snapshot| snapshot.issued().authorization().grant_id)
        .unwrap();
    let mut revoked = authority.clone();
    revoked.revocation.epoch += 1;
    revoked.revocation.activation_id = Uuid::new_v4();
    revoked.revocation.root = grant_revocation_root(grant_id);
    store
        .revoke_grant(&revoke_key.scope, grant_id, &authority, &revoked)
        .unwrap();
    assert!(matches!(
        store.authorize_admission_or_recover(&revoke_request),
        Err(StateError::GrantRevoked | StateError::AuthorityMismatch)
    ));

    let expiry_now = database_time(&url);
    let expiry_key = register_fixture(
        &store,
        &unique_tenant("admission-expiry"),
        expiry_now,
        expiry_now + 10,
        1,
    );
    let consumed = store.consume(&expiry_key).unwrap();
    let deadline = consumed.receipt().dispatch_deadline;
    begin_admission_attempt(&store, &expiry_key);
    let expiry_uid = format!("review-expiry-{}", Uuid::new_v4().simple());
    let expiry_request = admission_request(&store, &expiry_key, &expiry_uid, "expiry");
    store
        .authorize_admission_or_recover(&expiry_request)
        .unwrap();
    while database_time(&url) < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(matches!(
        store.authorize_admission_or_recover(&expiry_request),
        Err(StateError::DispatchDeadlineExpired { .. }
            | StateError::AuthorizationExpired { .. }
            | StateError::DependencyExpired { .. })
    ));
    assert_eq!(
        Client::connect(&url, NoTls)
            .unwrap()
            .query_one(
                "SELECT count(*)::bigint AS authorization_count
                   FROM public.accordlock_admission_authorizations
                  WHERE admission_uid = $1 OR admission_uid = $2",
                &[&revoke_uid, &expiry_uid],
            )
            .unwrap()
            .get::<_, i64>("authorization_count"),
        2
    );
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_admission_zero_commitment_and_wrong_routing_do_not_mutate_state_or_hwm() {
    let (url, store) = configured_store();
    let now = database_time(&url);
    let key = register_fixture(
        &store,
        &unique_tenant("admission-inputs"),
        now,
        now + 300,
        1,
    );
    store.consume(&key).unwrap();
    begin_admission_attempt(&store, &key);
    let zero = Digest32::from_bytes([0; 32]);
    assert!(matches!(
        store
            .admission_context(&key)
            .unwrap()
            .authorization_request(
                "review-zero".to_owned(),
                "service-account-uid",
                "AUTHORIZATION_ID=7ee52be0-9045-4653-aa5e-0da57b8dccdc",
                zero,
                digest("new"),
                digest("executor"),
                digest("observer"),
            ),
        Err(StateError::InvalidRecord(_))
    ));
    let high_water_before = store.time_high_water(&key.scope).unwrap();
    let wrong_key = ConsumeKey {
        transaction_id: Uuid::new_v4(),
        ..key.clone()
    };
    assert!(matches!(
        store.admission_context(&wrong_key),
        Err(StateError::TransactionMismatch)
    ));
    assert_eq!(
        store.time_high_water(&key.scope).unwrap(),
        high_water_before
    );
    assert_eq!(
        Client::connect(&url, NoTls)
            .unwrap()
            .query_one(
                "SELECT count(*)::bigint AS authorization_count
                   FROM public.accordlock_admission_authorizations
                  WHERE tenant = $1 AND environment = $2",
                &[&key.scope.tenant, &key.scope.environment],
            )
            .unwrap()
            .get::<_, i64>("authorization_count"),
        0
    );
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
#[allow(clippy::too_many_lines)]
fn postgres_broker_journal_never_reissues_and_cleanup_survives_revocation() {
    let (url, mut store) = configured_store();
    let broker_capability = store.issue_broker_journal_capability().unwrap();
    let now = database_time(&url);
    let key = register_fixture(
        &store,
        &unique_tenant("broker-lifecycle"),
        now,
        now + 300,
        1,
    );
    store.consume(&key).unwrap();
    let claimed = store
        .claim_dispatch(&dispatch_claim_request(
            &key,
            Uuid::new_v4(),
            "worker-broker",
        ))
        .unwrap();
    let token = claimed.token().clone();
    let route = [52; 32];

    let create = store
        .prepare_broker_operation(
            &broker_capability,
            BrokerOperationRequest::create(&token, route).unwrap(),
        )
        .and_then(|intent| store.begin_broker_io(&broker_capability, intent))
        .unwrap();
    let created = store
        .commit_broker_create(
            create,
            BrokerSecretObservation::matching("postgres-secret-uid".to_owned(), [61; 32]).unwrap(),
        )
        .unwrap();
    assert_eq!(
        created.audit().outcome(),
        Some(BrokerJournalOutcome::CreateMatching)
    );

    let issue = store
        .prepare_broker_operation(
            &broker_capability,
            BrokerOperationRequest::issue_token(
                &token,
                route,
                BrokerCredentialSafetyPolicy::new(600, 5).unwrap(),
            )
            .unwrap(),
        )
        .and_then(|intent| store.begin_broker_io(&broker_capability, intent))
        .unwrap();
    let issue_audit = store.mark_broker_io_unknown(issue).unwrap();
    assert_eq!(issue_audit.phase(), BrokerJournalPhase::Unknown);
    assert!(issue_audit.credential_safe_after().unwrap() > now);
    assert!(matches!(
        store.prepare_broker_operation(
            &broker_capability,
            BrokerOperationRequest::issue_token(
                &token,
                route,
                BrokerCredentialSafetyPolicy::new(600, 5).unwrap(),
            )
            .unwrap()
        ),
        Err(StateError::BrokerOperationOutcomeUnknown)
    ));

    let grant_id: Uuid = Client::connect(&url, NoTls)
        .unwrap()
        .query_one(
            "SELECT grant_id FROM public.accordlock_issued_authorizations
              WHERE tenant = $1 AND environment = $2 AND authorization_id = $3",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
            ],
        )
        .unwrap()
        .get("grant_id");
    let current = store.active_authority(&key.scope).unwrap();
    let mut revoked = current.clone();
    revoked.revocation.epoch += 1;
    revoked.revocation.activation_id = Uuid::new_v4();
    revoked.revocation.root = grant_revocation_root(grant_id);
    store
        .revoke_grant(&key.scope, grant_id, &current, &revoked)
        .unwrap();

    let cleanup = store
        .prepare_broker_cleanup(
            &broker_capability,
            &BrokerCleanupRequest::new(key.clone(), route).unwrap(),
        )
        .unwrap();
    assert_eq!(
        cleanup.audit().bound_secret_uid(),
        Some("postgres-secret-uid")
    );
    let delete = store.begin_broker_io(&broker_capability, cleanup).unwrap();
    store.mark_broker_io_unknown(delete).unwrap();
    let reconciliation = store
        .begin_broker_reconciliation(
            &broker_capability,
            &BrokerReconciliationRequest::new(
                key.clone(),
                BrokerJournalOperation::DeleteSecret,
                route,
            )
            .unwrap(),
        )
        .unwrap();
    let stale_reconciliation = store
        .begin_broker_reconciliation(
            &broker_capability,
            &BrokerReconciliationRequest::new(
                key.clone(),
                BrokerJournalOperation::DeleteSecret,
                route,
            )
            .unwrap(),
        )
        .unwrap();
    let exact_recovery_probe = store
        .begin_broker_reconciliation(
            &broker_capability,
            &BrokerReconciliationRequest::new(
                key.clone(),
                BrokerJournalOperation::DeleteSecret,
                route,
            )
            .unwrap(),
        )
        .unwrap();
    let pending = store
        .commit_broker_reconciliation(
            reconciliation,
            BrokerSecretObservation::matching("postgres-secret-uid".to_owned(), [62; 32]).unwrap(),
        )
        .unwrap();
    let retry = pending.into_pending().unwrap();
    assert_eq!(retry.audit().phase(), BrokerJournalPhase::ReconcileOnly);
    assert_eq!(retry.audit().reconciliation_count(), 1);
    assert_eq!(
        retry.audit().last_reconciliation_outcome(),
        Some(BrokerJournalOutcome::DeletePresent)
    );
    let recovered_pending = store
        .commit_broker_reconciliation(
            exact_recovery_probe,
            BrokerSecretObservation::matching("postgres-secret-uid".to_owned(), [62; 32]).unwrap(),
        )
        .unwrap()
        .into_pending()
        .unwrap();
    assert_eq!(recovered_pending.audit().reconciliation_count(), 1);
    assert!(matches!(
        store.commit_broker_reconciliation(
            stale_reconciliation,
            BrokerSecretObservation::absent([63; 32]).unwrap()
        ),
        Err(StateError::BrokerOperationOutcomeUnknown)
    ));
    let deleted = store
        .commit_broker_reconciliation(retry, BrokerSecretObservation::absent([64; 32]).unwrap())
        .unwrap()
        .into_completed()
        .unwrap();
    assert_eq!(deleted.audit().phase(), BrokerJournalPhase::Committed);
    assert!(matches!(
        store.prepare_broker_cleanup(
            &broker_capability,
            &BrokerCleanupRequest::new(key, route).unwrap()
        ),
        Err(StateError::BrokerOperationOutcomeUnknown)
    ));
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_broker_create_absence_remains_reconcilable_across_restart() {
    let (url, mut store) = configured_store();
    let broker_capability = store.issue_broker_journal_capability().unwrap();
    let now = database_time(&url);
    let key = register_fixture(
        &store,
        &unique_tenant("broker-create-reconcile"),
        now,
        now + 300,
        1,
    );
    store.consume(&key).unwrap();
    let token = store
        .claim_dispatch(&dispatch_claim_request(
            &key,
            Uuid::new_v4(),
            "worker-broker-create-reconcile",
        ))
        .unwrap()
        .token()
        .clone();
    let route = [53; 32];
    let create = store
        .prepare_broker_operation(
            &broker_capability,
            BrokerOperationRequest::create(&token, route).unwrap(),
        )
        .and_then(|intent| store.begin_broker_io(&broker_capability, intent))
        .unwrap();
    store.mark_broker_io_unknown(create).unwrap();
    let reconcile = store
        .begin_broker_reconciliation(
            &broker_capability,
            &BrokerReconciliationRequest::new(
                key.clone(),
                BrokerJournalOperation::CreateSecret,
                route,
            )
            .unwrap(),
        )
        .unwrap();
    let pending = store
        .commit_broker_reconciliation(
            reconcile,
            BrokerSecretObservation::absent([54; 32]).unwrap(),
        )
        .unwrap()
        .into_pending()
        .unwrap();
    assert_eq!(pending.audit().reconciliation_count(), 1);
    drop(pending);

    let restarted = store.clone();
    let retry = restarted
        .begin_broker_reconciliation(
            &broker_capability,
            &BrokerReconciliationRequest::new(key, BrokerJournalOperation::CreateSecret, route)
                .unwrap(),
        )
        .unwrap();
    assert_eq!(retry.audit().reconciliation_count(), 1);
    let completed = restarted
        .commit_broker_reconciliation(
            retry,
            BrokerSecretObservation::matching("late-postgres-secret".to_owned(), [55; 32]).unwrap(),
        )
        .unwrap()
        .into_completed()
        .unwrap();
    assert_eq!(completed.audit().phase(), BrokerJournalPhase::Committed);
    assert_eq!(completed.audit().reconciliation_count(), 1);
    assert_eq!(
        completed.audit().outcome(),
        Some(BrokerJournalOutcome::CreateMatching)
    );
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_broker_begin_has_one_winner_across_store_instances() {
    let (url, mut store) = configured_store();
    let broker_capability = store.issue_broker_journal_capability().unwrap();
    let now = database_time(&url);
    let key = register_fixture(
        &store,
        &unique_tenant("broker-store-race"),
        now,
        now + 300,
        1,
    );
    store.consume(&key).unwrap();
    let token = store
        .claim_dispatch(&dispatch_claim_request(
            &key,
            Uuid::new_v4(),
            "worker-broker-race",
        ))
        .unwrap()
        .token()
        .clone();
    let route = [53; 32];
    let first_store = store.clone();
    let second_store = store.clone();
    let first = first_store
        .prepare_broker_operation(
            &broker_capability,
            BrokerOperationRequest::create(&token, route).unwrap(),
        )
        .unwrap();
    let second = second_store
        .prepare_broker_operation(
            &broker_capability,
            BrokerOperationRequest::create(&token, route).unwrap(),
        )
        .unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let results = thread::scope(|scope| {
        let handles = [(first_store, first), (second_store, second)].map(|(store, intent)| {
            let barrier = barrier.clone();
            let broker_capability = &broker_capability;
            scope.spawn(move || {
                barrier.wait();
                store.begin_broker_io(broker_capability, intent)
            })
        });
        handles.map(|handle| handle.join().unwrap())
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(StateError::BrokerOperationOutcomeUnknown)))
            .count(),
        1
    );
}

#[test]
#[ignore = "helper process for the disposable PostgreSQL broker race"]
fn postgres_broker_cleanup_child_process() {
    let Ok(key_json) = env::var(BROKER_CHILD_REQUEST_ENV) else {
        return;
    };
    let url = env::var("ACCORDLOCK_TEST_POSTGRES_URL").unwrap();
    let key: ConsumeKey = serde_json::from_str(&key_json).unwrap();
    let mut store = PostgresStore::new(url);
    let broker_capability = store.issue_broker_journal_capability().unwrap();
    let request = BrokerCleanupRequest::new(key, BROKER_PROCESS_ROUTE).unwrap();
    match store
        .prepare_broker_cleanup(&broker_capability, &request)
        .and_then(|intent| store.begin_broker_io(&broker_capability, intent))
    {
        Ok(_) => println!("ACCORDLOCK_CHILD_BROKER=SUCCESS"),
        Err(StateError::BrokerOperationOutcomeUnknown) => {
            println!("ACCORDLOCK_CHILD_BROKER=OUTCOME_UNKNOWN");
        }
        result => panic!("unexpected child broker result: {result:?}"),
    }
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_broker_cleanup_has_one_winner_across_os_processes() {
    let (url, mut store) = configured_store();
    let broker_capability = store.issue_broker_journal_capability().unwrap();
    let now = database_time(&url);
    let key = register_fixture(
        &store,
        &unique_tenant("broker-process-race"),
        now,
        now + 300,
        1,
    );
    store.consume(&key).unwrap();
    let token = store
        .claim_dispatch(&dispatch_claim_request(
            &key,
            Uuid::new_v4(),
            "worker-broker-process",
        ))
        .unwrap()
        .token()
        .clone();
    let create = store
        .prepare_broker_operation(
            &broker_capability,
            BrokerOperationRequest::create(&token, BROKER_PROCESS_ROUTE).unwrap(),
        )
        .and_then(|intent| store.begin_broker_io(&broker_capability, intent))
        .unwrap();
    store
        .commit_broker_create(
            create,
            BrokerSecretObservation::matching("process-secret-uid".to_owned(), [71; 32]).unwrap(),
        )
        .unwrap();

    let executable = env::current_exe().unwrap();
    let mut children = Vec::new();
    for _ in 0..2 {
        children.push(
            Command::new(&executable)
                .arg("postgres_broker_cleanup_child_process")
                .arg("--ignored")
                .arg("--exact")
                .arg("--nocapture")
                .arg("--test-threads=1")
                .env("ACCORDLOCK_TEST_POSTGRES_URL", &url)
                .env(
                    BROKER_CHILD_REQUEST_ENV,
                    serde_json::to_string(&key).unwrap(),
                )
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
    }
    let outputs: Vec<_> = children
        .into_iter()
        .map(|child| child.wait_with_output().unwrap())
        .collect();
    assert!(outputs.iter().all(|output| output.status.success()));
    let combined: Vec<_> = outputs
        .iter()
        .map(|output| String::from_utf8_lossy(&output.stdout))
        .collect();
    assert_eq!(
        combined
            .iter()
            .filter(|output| output.contains("ACCORDLOCK_CHILD_BROKER=SUCCESS"))
            .count(),
        1
    );
    assert_eq!(
        combined
            .iter()
            .filter(|output| output.contains("ACCORDLOCK_CHILD_BROKER=OUTCOME_UNKNOWN"))
            .count(),
        1
    );
    assert_eq!(
        store
            .broker_operation_audit(&key, BrokerJournalOperation::DeleteSecret)
            .unwrap()
            .phase(),
        BrokerJournalPhase::InFlight
    );
    // The winning child exited with its non-clonable send authority. Restart
    // can recover only GET reconciliation, never another DELETE authority.
    let reconciliation = store
        .begin_broker_reconciliation(
            &broker_capability,
            &BrokerReconciliationRequest::new(
                key,
                BrokerJournalOperation::DeleteSecret,
                BROKER_PROCESS_ROUTE,
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        reconciliation.audit().phase(),
        BrokerJournalPhase::ReconcileOnly
    );
}

#[test]
#[ignore = "helper process for the disposable PostgreSQL claim race"]
fn postgres_dispatch_claim_child_process() {
    let Ok(request_json) = env::var(CLAIM_CHILD_REQUEST_ENV) else {
        return;
    };
    let url = env::var("ACCORDLOCK_TEST_POSTGRES_URL").unwrap();
    let request: DispatchClaimRequest = serde_json::from_str(&request_json).unwrap();
    let store = PostgresStore::new(url);
    match store.claim_dispatch(&request) {
        Ok(_) => println!("ACCORDLOCK_CHILD_CLAIM=SUCCESS"),
        Err(StateError::DispatchAlreadyClaimed) => {
            println!("ACCORDLOCK_CHILD_CLAIM=ALREADY_CLAIMED");
        }
        Err(StateError::PhysicalResourceAlreadyReserved) => {
            println!("ACCORDLOCK_CHILD_CLAIM=PHYSICAL_RESOURCE_RESERVED");
        }
        result => panic!("unexpected child claim result: {result:?}"),
    }
}

fn spawn_postgres_dispatch_claim_child(
    executable: &std::path::Path,
    url: &str,
    request: &DispatchClaimRequest,
) -> std::process::Child {
    Command::new(executable)
        .arg("postgres_dispatch_claim_child_process")
        .arg("--ignored")
        .arg("--exact")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env(TEST_DATABASE_URL_ENV, url)
        .env(
            CLAIM_CHILD_REQUEST_ENV,
            serde_json::to_string(request).unwrap(),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

#[test]
#[ignore = "helper process for the disposable PostgreSQL admission race"]
fn postgres_admission_child_process() {
    let Ok(payload_json) = env::var(ADMISSION_CHILD_REQUEST_ENV) else {
        return;
    };
    let url = env::var("ACCORDLOCK_TEST_POSTGRES_URL").unwrap();
    let payload: serde_json::Value = serde_json::from_str(&payload_json).unwrap();
    let key: ConsumeKey = serde_json::from_value(payload["key"].clone()).unwrap();
    let admission_uid = payload["admission_uid"].as_str().unwrap();
    let store = PostgresStore::new(url);
    let request = admission_request(&store, &key, admission_uid, "process-race");
    match store.authorize_admission_or_recover(&request) {
        Ok(_) => println!("ACCORDLOCK_CHILD_ADMISSION=SUCCESS"),
        Err(StateError::AdmissionAlreadyAuthorized) => {
            println!("ACCORDLOCK_CHILD_ADMISSION=ALREADY_AUTHORIZED");
        }
        result => panic!("unexpected child admission result: {result:?}"),
    }
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_admission_has_one_winner_across_os_processes() {
    let (url, store) = configured_store();
    let now = database_time(&url);
    let key = register_fixture(
        &store,
        &unique_tenant("admission-process-race"),
        now,
        now + 300,
        1,
    );
    store.consume(&key).unwrap();
    begin_admission_attempt(&store, &key);

    let executable = env::current_exe().unwrap();
    let mut children = Vec::new();
    for admission_uid in [
        format!("review-process-a-{}", Uuid::new_v4().simple()),
        format!("review-process-b-{}", Uuid::new_v4().simple()),
    ] {
        let payload = serde_json::json!({
            "key": key,
            "admission_uid": admission_uid,
        });
        children.push(
            Command::new(&executable)
                .arg("postgres_admission_child_process")
                .arg("--ignored")
                .arg("--exact")
                .arg("--nocapture")
                .arg("--test-threads=1")
                .env("ACCORDLOCK_TEST_POSTGRES_URL", &url)
                .env(ADMISSION_CHILD_REQUEST_ENV, payload.to_string())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
    }
    let outputs: Vec<_> = children
        .into_iter()
        .map(|child| child.wait_with_output().unwrap())
        .collect();
    for output in &outputs {
        assert!(
            output.status.success(),
            "admission child failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let combined: Vec<_> = outputs
        .iter()
        .map(|output| String::from_utf8_lossy(&output.stdout))
        .collect();
    assert_eq!(
        combined
            .iter()
            .filter(|output| output.contains("ACCORDLOCK_CHILD_ADMISSION=SUCCESS"))
            .count(),
        1
    );
    assert_eq!(
        combined
            .iter()
            .filter(|output| output.contains("ACCORDLOCK_CHILD_ADMISSION=ALREADY_AUTHORIZED"))
            .count(),
        1
    );
    assert_eq!(
        Client::connect(&url, NoTls)
            .unwrap()
            .query_one(
                "SELECT count(*)::bigint AS authorization_count
                   FROM public.accordlock_admission_authorizations
                  WHERE tenant = $1 AND environment = $2 AND transaction_id = $3",
                &[
                    &key.scope.tenant,
                    &key.scope.environment,
                    &key.transaction_id
                ],
            )
            .unwrap()
            .get::<_, i64>("authorization_count"),
        1
    );
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_physical_resource_is_exclusive_across_authorizations_and_os_processes() {
    let (url, store) = configured_store();
    let now = database_time(&url);
    let physical_uid = format!("shared-deployment-{}", Uuid::new_v4().simple());
    let first_key = register_fixture_for_resource(
        &store,
        &unique_tenant("dispatch-physical-process-a"),
        now,
        now + 300,
        1,
        "cluster-shared",
        "payments-shared",
        &physical_uid,
    );
    let second_key = register_fixture_for_resource(
        &store,
        &unique_tenant("dispatch-physical-process-b"),
        now,
        now + 300,
        1,
        "cluster-shared",
        "payments-shared",
        &physical_uid,
    );
    store.consume(&first_key).unwrap();
    store.consume(&second_key).unwrap();

    let executable = env::current_exe().unwrap();
    let mut children = Vec::new();
    for request in [
        dispatch_claim_request(&first_key, Uuid::new_v4(), "worker-physical-a"),
        dispatch_claim_request(&second_key, Uuid::new_v4(), "worker-physical-b"),
    ] {
        children.push(spawn_postgres_dispatch_claim_child(
            &executable,
            &url,
            &request,
        ));
    }
    let outputs: Vec<_> = children
        .into_iter()
        .map(|child| child.wait_with_output().unwrap())
        .collect();
    for output in &outputs {
        assert!(
            output.status.success(),
            "physical claim child failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let combined: Vec<_> = outputs
        .iter()
        .map(|output| String::from_utf8_lossy(&output.stdout))
        .collect();
    assert_eq!(
        combined
            .iter()
            .filter(|output| output.contains("ACCORDLOCK_CHILD_CLAIM=SUCCESS"))
            .count(),
        1
    );
    assert_eq!(
        combined
            .iter()
            .filter(|output| {
                output.contains("ACCORDLOCK_CHILD_CLAIM=PHYSICAL_RESOURCE_RESERVED")
            })
            .count(),
        1
    );

    let row = Client::connect(&url, NoTls)
        .unwrap()
        .query_one(
            "SELECT count(*)::bigint AS reservation_count,
                    min(cluster_identity) AS cluster_identity,
                    min(namespace) AS namespace,
                    min(deployment_uid) AS deployment_uid,
                    min(fence) AS fence
               FROM public.accordlock_dispatch_claims
              WHERE cluster_identity = $1
                AND namespace = $2
                AND deployment_uid = $3",
            &[&"cluster-shared", &"payments-shared", &physical_uid],
        )
        .unwrap();
    assert_eq!(row.get::<_, i64>("reservation_count"), 1);
    assert_eq!(row.get::<_, String>("cluster_identity"), "cluster-shared");
    assert_eq!(row.get::<_, String>("namespace"), "payments-shared");
    assert_eq!(row.get::<_, String>("deployment_uid"), physical_uid);
    assert!(row.get::<_, i64>("fence") > 0);
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_dispatch_claim_is_exclusive_across_os_processes() {
    let (url, store) = configured_store();
    let now = database_time(&url);
    let key = register_fixture(
        &store,
        &unique_tenant("dispatch-claim-process-race"),
        now,
        now + 300,
        1,
    );
    store.consume(&key).unwrap();

    let executable = env::current_exe().unwrap();
    let mut children = Vec::new();
    for (worker_id, claim_id) in [
        ("worker-process-a", Uuid::new_v4()),
        ("worker-process-b", Uuid::new_v4()),
    ] {
        let request = dispatch_claim_request(&key, claim_id, worker_id);
        children.push(spawn_postgres_dispatch_claim_child(
            &executable,
            &url,
            &request,
        ));
    }
    let outputs: Vec<_> = children
        .into_iter()
        .map(|child| child.wait_with_output().unwrap())
        .collect();
    for output in &outputs {
        assert!(
            output.status.success(),
            "claim child failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let combined: Vec<_> = outputs
        .iter()
        .map(|output| String::from_utf8_lossy(&output.stdout))
        .collect();
    assert_eq!(
        combined
            .iter()
            .filter(|output| output.contains("ACCORDLOCK_CHILD_CLAIM=SUCCESS"))
            .count(),
        1
    );
    assert_eq!(
        combined
            .iter()
            .filter(|output| output.contains("ACCORDLOCK_CHILD_CLAIM=ALREADY_CLAIMED"))
            .count(),
        1
    );
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
#[allow(clippy::too_many_lines)]
fn postgres_dispatch_claim_is_exclusive_across_store_instances_and_fences_are_monotone() {
    let (url, store) = configured_store();
    let now = database_time(&url);
    let key = register_fixture(
        &store,
        &unique_tenant("dispatch-claim-race"),
        now,
        now + 300,
        1,
    );
    store.consume(&key).unwrap();

    let requests = [
        dispatch_claim_request(&key, Uuid::new_v4(), "worker-a"),
        dispatch_claim_request(&key, Uuid::new_v4(), "worker-b"),
    ];
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for request in requests {
        let store = store.clone();
        let barrier = barrier.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            let result = store.claim_dispatch(&request);
            (request, result)
        }));
    }
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(
        results.iter().filter(|(_, result)| result.is_ok()).count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|(_, result)| matches!(result, Err(StateError::DispatchAlreadyClaimed)))
            .count(),
        1
    );
    let (winning_request, claimed) = results
        .iter()
        .find_map(|(request, result)| result.as_ref().ok().map(|claim| (request, claim)))
        .unwrap();
    assert_eq!(claimed.token().claim_id(), winning_request.claim_id);
    assert_eq!(claimed.token().worker_id(), winning_request.worker_id);
    assert_eq!(
        claimed.token().state_instance_id(),
        store.state_instance_id().unwrap()
    );
    assert!(claimed.token().lease_until() <= claimed.snapshot().receipt().dispatch_deadline);
    assert!(claimed.token().lease_until() > claimed.token().claimed_at());
    assert!(matches!(
        store.claim_dispatch(winning_request),
        Err(StateError::DispatchClaimOutcomeUnknown)
    ));

    let different_worker = dispatch_claim_request(&key, winning_request.claim_id, "worker-c");
    assert!(matches!(
        store.claim_dispatch(&different_worker),
        Err(StateError::DispatchAcquisitionMismatch)
    ));
    let wrong_transaction = dispatch_claim_request(
        &ConsumeKey {
            transaction_id: Uuid::new_v4(),
            ..key.clone()
        },
        winning_request.claim_id,
        &winning_request.worker_id,
    );
    assert!(matches!(
        store.claim_dispatch(&wrong_transaction),
        Err(StateError::DispatchAlreadyClaimed)
    ));

    let second_key = register_fixture(
        &store,
        &unique_tenant("dispatch-claim-fence"),
        now,
        now + 300,
        1,
    );
    store.consume(&second_key).unwrap();
    let second = store
        .claim_dispatch(&dispatch_claim_request(
            &second_key,
            Uuid::new_v4(),
            "worker-z",
        ))
        .unwrap();
    assert!(second.token().fence() > claimed.token().fence());

    let mut client = Client::connect(&url, NoTls).unwrap();
    let row = client
        .query_one(
            "SELECT count(*)::bigint AS claim_count,
                    min(state) AS state,
                    (SELECT status
                       FROM public.accordlock_execution_outbox
                      WHERE tenant = $1 AND environment = $2 AND authorization_id = $3) AS outbox_status
               FROM public.accordlock_dispatch_claims
              WHERE tenant = $1 AND environment = $2 AND authorization_id = $3",
            &[&key.scope.tenant, &key.scope.environment, &key.authorization_id],
        )
        .unwrap();
    assert_eq!(row.get::<_, i64>("claim_count"), 1);
    assert_eq!(
        row.get::<_, Option<String>>("state").as_deref(),
        Some("CLAIMED")
    );
    assert_eq!(row.get::<_, String>("outbox_status"), "PENDING_WITNESS");
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_attempt_mark_is_one_shot_and_lost_responses_require_reconciliation() {
    let (url, store) = configured_store();
    let now = database_time(&url);
    let key = register_fixture(
        &store,
        &unique_tenant("dispatch-attempt-race"),
        now,
        now + 300,
        1,
    );
    store.consume(&key).unwrap();
    let request = dispatch_claim_request(&key, Uuid::new_v4(), "worker-a");
    let claimed = store.claim_dispatch(&request).unwrap();
    let token = claimed.token().clone();

    // Losing the successful claim response and replaying the exact request
    // cannot reconstruct a second execution authority.
    drop(claimed);
    assert!(matches!(
        store.claim_dispatch(&request),
        Err(StateError::DispatchClaimOutcomeUnknown)
    ));
    store.revalidate_dispatch_claim(&token).unwrap();

    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let store = store.clone();
        let token = token.clone();
        let barrier = barrier.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            store.mark_attempt_in_flight(&token, credential(&token))
        }));
    }
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(StateError::DispatchAttemptOutcomeUnknown)))
            .count(),
        1
    );
    assert!(matches!(
        store.mark_attempt_in_flight(&token, credential(&token)),
        Err(StateError::DispatchAttemptOutcomeUnknown)
    ));
    assert!(matches!(
        store.revalidate_dispatch_claim(&token),
        Err(StateError::DispatchAttemptOutcomeUnknown)
    ));
    let state: String = Client::connect(&url, NoTls)
        .unwrap()
        .query_one(
            "SELECT state
               FROM public.accordlock_dispatch_claims
              WHERE tenant = $1 AND environment = $2 AND authorization_id = $3",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
            ],
        )
        .unwrap()
        .get("state");
    assert_eq!(state, "ATTEMPT_IN_FLIGHT");
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
#[allow(clippy::too_many_lines)]
fn postgres_claim_mark_rechecks_revocation_deadline_and_exact_token() {
    let (url, store) = configured_store();
    let now = database_time(&url);
    let revoked_key = register_fixture(
        &store,
        &unique_tenant("dispatch-claim-revoked"),
        now,
        now + 300,
        1,
    );
    store.consume(&revoked_key).unwrap();
    let revoked = store
        .claim_dispatch(&dispatch_claim_request(
            &revoked_key,
            Uuid::new_v4(),
            "worker-a",
        ))
        .unwrap();
    let current = revoked.snapshot().authority().clone();
    let grant_id = revoked.snapshot().issued().authorization().grant_id;
    let mut next = current.clone();
    next.revocation.epoch += 1;
    next.revocation.activation_id = Uuid::new_v4();
    next.revocation.root = grant_revocation_root(grant_id);
    store
        .revoke_grant(&revoked_key.scope, grant_id, &current, &next)
        .unwrap();
    assert!(matches!(
        store.mark_attempt_in_flight(revoked.token(), credential(revoked.token())),
        Err(StateError::GrantRevoked | StateError::AuthorityMismatch)
    ));

    let deadline_now = database_time(&url);
    let deadline_key = register_fixture(
        &store,
        &unique_tenant("dispatch-claim-deadline"),
        deadline_now,
        deadline_now + 3,
        1,
    );
    store.consume(&deadline_key).unwrap();
    let deadline = store
        .claim_dispatch(&dispatch_claim_request(
            &deadline_key,
            Uuid::new_v4(),
            "worker-b",
        ))
        .unwrap();
    while database_time(&url) < deadline.token().lease_until() {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(matches!(
        store.mark_attempt_in_flight(deadline.token(), credential(deadline.token())),
        Err(StateError::DispatchDeadlineExpired { .. }
            | StateError::AuthorizationExpired { .. }
            | StateError::DependencyExpired { .. }
            | StateError::DispatchClaimLeaseExpired { .. })
    ));

    let corrupt_now = database_time(&url);
    let corrupt_key = register_fixture(
        &store,
        &unique_tenant("dispatch-claim-token"),
        corrupt_now,
        corrupt_now + 300,
        1,
    );
    store.consume(&corrupt_key).unwrap();
    let corrupt = store
        .claim_dispatch(&dispatch_claim_request(
            &corrupt_key,
            Uuid::new_v4(),
            "worker-c",
        ))
        .unwrap();
    let high_water_before_mismatch = store.time_high_water(&corrupt_key.scope).unwrap();
    let original_worker = corrupt.token().worker_id().to_owned();
    let mut client = Client::connect(&url, NoTls).unwrap();
    assert_eq!(
        replica_execute(
            &mut client,
            "UPDATE public.accordlock_dispatch_claims
                SET worker_id = 'worker-mutated'
              WHERE tenant = $1 AND environment = $2 AND authorization_id = $3",
            &[
                &corrupt_key.scope.tenant,
                &corrupt_key.scope.environment,
                &corrupt_key.authorization_id,
            ],
        ),
        1
    );
    let mismatch_result = store.revalidate_dispatch_claim(corrupt.token());
    let high_water_after_mismatch = store.time_high_water(&corrupt_key.scope);
    assert_eq!(
        replica_execute(
            &mut client,
            "UPDATE public.accordlock_dispatch_claims
                SET worker_id = $4
              WHERE tenant = $1 AND environment = $2 AND authorization_id = $3",
            &[
                &corrupt_key.scope.tenant,
                &corrupt_key.scope.environment,
                &corrupt_key.authorization_id,
                &original_worker,
            ],
        ),
        1
    );
    assert!(matches!(
        mismatch_result,
        Err(StateError::DispatchClaimMismatch)
    ));
    assert_eq!(
        high_water_after_mismatch.unwrap(),
        high_water_before_mismatch
    );
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
#[allow(clippy::too_many_lines)]
fn postgres_v13_control_schema_profile_rejects_catalog_and_sequence_drift() {
    let (url, store) = configured_store();
    let mut client = Client::connect(&url, NoTls).unwrap();
    store.validate_schema().unwrap();

    client
        .batch_execute(
            "ALTER TABLE public.accordlock_control_status
                 DISABLE TRIGGER accordlock_control_status_delete_rejected;",
        )
        .unwrap();
    assert!(matches!(
        store.validate_schema(),
        Err(StateError::SchemaMismatch(_))
    ));
    client
        .batch_execute(
            "ALTER TABLE public.accordlock_control_status
                 ENABLE TRIGGER accordlock_control_status_delete_rejected;",
        )
        .unwrap();

    let truncate_guard: String = client
        .query_one(
            "SELECT pg_get_triggerdef(trigger.oid, TRUE) AS definition
               FROM pg_trigger AS trigger
              WHERE trigger.tgrelid =
                    'public.accordlock_control_work_queue'::regclass
                AND trigger.tgname =
                    'accordlock_control_work_queue_truncate_rejected'",
            &[],
        )
        .unwrap()
        .get("definition");
    client
        .batch_execute(
            "DROP TRIGGER accordlock_control_work_queue_truncate_rejected
                 ON public.accordlock_control_work_queue;",
        )
        .unwrap();
    assert!(matches!(
        store.validate_schema(),
        Err(StateError::SchemaMismatch(_))
    ));
    client.batch_execute(&truncate_guard).unwrap();

    let queue_check: String = client
        .query_one(
            "SELECT pg_get_constraintdef(constraint_value.oid, TRUE) AS definition
               FROM pg_constraint AS constraint_value
              WHERE constraint_value.conrelid =
                    'public.accordlock_control_work_queue'::regclass
                AND constraint_value.conname =
                    'accordlock_control_work_queue_state_check'",
            &[],
        )
        .unwrap()
        .get("definition");
    client
        .batch_execute(
            "ALTER TABLE public.accordlock_control_work_queue
                 DROP CONSTRAINT accordlock_control_work_queue_state_check;",
        )
        .unwrap();
    assert!(matches!(
        store.validate_schema(),
        Err(StateError::SchemaMismatch(_))
    ));
    client
        .batch_execute(&format!(
            "ALTER TABLE public.accordlock_control_work_queue
                 ADD CONSTRAINT accordlock_control_work_queue_state_check {queue_check};"
        ))
        .unwrap();

    client
        .batch_execute(
            "ALTER TABLE public.accordlock_control_submissions
                 ALTER COLUMN actor DROP NOT NULL;",
        )
        .unwrap();
    assert!(matches!(
        store.validate_schema(),
        Err(StateError::SchemaMismatch(_))
    ));
    client
        .batch_execute(
            "ALTER TABLE public.accordlock_control_submissions
                 ALTER COLUMN actor SET NOT NULL;",
        )
        .unwrap();

    client
        .batch_execute(
            "ALTER TABLE public.accordlock_control_submissions
                 ALTER COLUMN actor TYPE TEXT COLLATE \"default\";",
        )
        .unwrap();
    assert!(matches!(
        store.validate_schema(),
        Err(StateError::SchemaMismatch(_))
    ));
    client
        .batch_execute(
            "ALTER TABLE public.accordlock_control_submissions
                 ALTER COLUMN actor TYPE TEXT COLLATE \"C\";",
        )
        .unwrap();

    client
        .batch_execute("DROP INDEX public.accordlock_control_work_queue_ready_idx;")
        .unwrap();
    assert!(matches!(
        store.validate_schema(),
        Err(StateError::SchemaMismatch(_))
    ));
    client
        .batch_execute(
            "CREATE INDEX accordlock_control_work_queue_ready_idx
                 ON public.accordlock_control_work_queue
                    (phase, state, submission_id)
                 WHERE state = 'READY';",
        )
        .unwrap();

    let mutation_guard: String = client
        .query_one(
            "SELECT pg_get_functiondef(proc.oid) AS definition
               FROM pg_proc AS proc
              WHERE proc.pronamespace = 'public'::regnamespace
                AND proc.proname =
                    'accordlock_reject_control_history_mutation'",
            &[],
        )
        .unwrap()
        .get("definition");
    client
        .batch_execute(
            "CREATE OR REPLACE FUNCTION
                 public.accordlock_reject_control_history_mutation()
             RETURNS trigger LANGUAGE plpgsql AS $function$
             BEGIN
                 RAISE EXCEPTION 'drifted control mutation guard';
             END
             $function$;",
        )
        .unwrap();
    assert!(matches!(
        store.validate_schema(),
        Err(StateError::SchemaMismatch(_))
    ));
    client.batch_execute(&mutation_guard).unwrap();

    client
        .batch_execute(
            "ALTER SEQUENCE public.accordlock_control_work_claims_fence_seq
                 INCREMENT BY 2;",
        )
        .unwrap();
    assert!(matches!(
        store.validate_schema(),
        Err(StateError::SchemaMismatch(_))
    ));
    client
        .batch_execute(
            "ALTER SEQUENCE public.accordlock_control_work_claims_fence_seq
                 INCREMENT BY 1;",
        )
        .unwrap();

    let sequence_before: i64 = client
        .query_one(
            "SELECT last_value
               FROM public.accordlock_control_work_claims_fence_seq",
            &[],
        )
        .unwrap()
        .get("last_value");
    let claim_id = Uuid::new_v4();
    let submission_id = Uuid::new_v4();
    client
        .batch_execute("SET session_replication_role = replica;")
        .unwrap();
    let fence: i64 = client
        .query_one(
            "INSERT INTO public.accordlock_control_work_claims
                (claim_id, submission_id, role, phase, worker_id,
                 claimed_at, lease_until)
             VALUES ($1, $2, 'EVALUATOR', 'EVALUATE',
                     'schema-profile-worker', 1, 31)
             RETURNING fence",
            &[&claim_id, &submission_id],
        )
        .unwrap()
        .get("fence");
    client
        .batch_execute("SET session_replication_role = origin;")
        .unwrap();
    if fence == 1 {
        client
            .query_one(
                "SELECT setval(
                    'public.accordlock_control_work_claims_fence_seq', 1, FALSE
                )",
                &[],
            )
            .unwrap();
    } else {
        client
            .query_one(
                "SELECT setval(
                    'public.accordlock_control_work_claims_fence_seq', $1, TRUE
                )",
                &[&(fence - 1)],
            )
            .unwrap();
    }
    assert!(matches!(
        store.validate_schema(),
        Err(StateError::SchemaMismatch(_))
    ));
    let restored_last = sequence_before.max(fence);
    client
        .query_one(
            "SELECT setval(
                'public.accordlock_control_work_claims_fence_seq', $1, TRUE
            )",
            &[&restored_last],
        )
        .unwrap();
    client
        .batch_execute("SET session_replication_role = replica;")
        .unwrap();
    client
        .execute(
            "DELETE FROM public.accordlock_control_work_claims
              WHERE claim_id = $1",
            &[&claim_id],
        )
        .unwrap();
    client
        .batch_execute("SET session_replication_role = origin;")
        .unwrap();
    store.validate_schema().unwrap();
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
#[allow(clippy::too_many_lines)]
fn postgres_v14_dispatch_schema_profile_rejects_catalog_and_sequence_drift() {
    let (url, store) = configured_store();
    let mut client = Client::connect(&url, NoTls).unwrap();
    store.validate_schema().unwrap();

    client
        .batch_execute(
            "ALTER TABLE public.accordlock_dispatch_acquisitions
                 DISABLE TRIGGER accordlock_dispatch_acquisitions_append_only;",
        )
        .unwrap();
    let disabled_trigger_drift = store.validate_schema();
    client
        .batch_execute(
            "ALTER TABLE public.accordlock_dispatch_acquisitions
                 ENABLE TRIGGER accordlock_dispatch_acquisitions_append_only;",
        )
        .unwrap();
    assert!(matches!(
        disabled_trigger_drift,
        Err(StateError::SchemaMismatch(_))
    ));
    store.validate_schema().unwrap();

    client
        .batch_execute(
            "ALTER TABLE public.accordlock_dispatch_credential_reviews
                 DISABLE TRIGGER accordlock_dispatch_credential_reviews_update_guard;",
        )
        .unwrap();
    let disabled_review_trigger_drift = store.validate_schema();
    client
        .batch_execute(
            "ALTER TABLE public.accordlock_dispatch_credential_reviews
                 ENABLE TRIGGER accordlock_dispatch_credential_reviews_update_guard;",
        )
        .unwrap();
    assert!(matches!(
        disabled_review_trigger_drift,
        Err(StateError::SchemaMismatch(_))
    ));
    store.validate_schema().unwrap();

    let review_phase_check: String = client
        .query_one(
            "SELECT pg_get_constraintdef(oid, TRUE) AS definition
               FROM pg_constraint
              WHERE conname = 'accordlock_dispatch_credential_reviews_phase_check'",
            &[],
        )
        .unwrap()
        .get("definition");
    client
        .batch_execute(
            "ALTER TABLE public.accordlock_dispatch_credential_reviews
                 DROP CONSTRAINT accordlock_dispatch_credential_reviews_phase_check;
             ALTER TABLE public.accordlock_dispatch_credential_reviews
                 ADD CONSTRAINT accordlock_dispatch_credential_reviews_phase_check
                 CHECK (TRUE);",
        )
        .unwrap();
    let review_check_drift = store.validate_schema();
    client
        .batch_execute(&format!(
            "ALTER TABLE public.accordlock_dispatch_credential_reviews
                 DROP CONSTRAINT accordlock_dispatch_credential_reviews_phase_check;
             ALTER TABLE public.accordlock_dispatch_credential_reviews
                 ADD CONSTRAINT accordlock_dispatch_credential_reviews_phase_check
                 {review_phase_check};"
        ))
        .unwrap();
    assert!(matches!(
        review_check_drift,
        Err(StateError::SchemaMismatch(_))
    ));
    store.validate_schema().unwrap();

    client
        .batch_execute(
            "CREATE TRIGGER zz_eks_activation_profile_drift
                 BEFORE UPDATE ON public.accordlock_eks_destination_activations
                 FOR EACH ROW EXECUTE FUNCTION
                    public.accordlock_reject_dispatch_acquisition_mutation();",
        )
        .unwrap();
    let eks_activation_trigger_drift = store.validate_schema();
    client
        .batch_execute(
            "DROP TRIGGER zz_eks_activation_profile_drift
                 ON public.accordlock_eks_destination_activations;",
        )
        .unwrap();
    assert!(matches!(
        eks_activation_trigger_drift,
        Err(StateError::SchemaMismatch(_))
    ));
    store.validate_schema().unwrap();

    client
        .batch_execute(
            "ALTER TABLE public.accordlock_dispatch_claims
                 DROP CONSTRAINT accordlock_dispatch_claims_credential_review_fkey;",
        )
        .unwrap();
    let review_foreign_key_drift = store.validate_schema();
    client
        .batch_execute(
            "ALTER TABLE public.accordlock_dispatch_claims
                 ADD CONSTRAINT accordlock_dispatch_claims_credential_review_fkey
                 FOREIGN KEY (credential_review_id)
                 REFERENCES public.accordlock_dispatch_credential_reviews(review_id)
                 ON DELETE RESTRICT;",
        )
        .unwrap();
    assert!(matches!(
        review_foreign_key_drift,
        Err(StateError::SchemaMismatch(_))
    ));
    store.validate_schema().unwrap();

    client
        .batch_execute(
            "CREATE TRIGGER zz_deletion_observation_profile_drift
                 BEFORE UPDATE ON public.accordlock_broker_secret_deletion_observations
                 FOR EACH ROW EXECUTE FUNCTION
                    public.accordlock_reject_dispatch_acquisition_mutation();",
        )
        .unwrap();
    let deletion_observation_trigger_drift = store.validate_schema();
    client
        .batch_execute(
            "DROP TRIGGER zz_deletion_observation_profile_drift
                 ON public.accordlock_broker_secret_deletion_observations;",
        )
        .unwrap();
    assert!(matches!(
        deletion_observation_trigger_drift,
        Err(StateError::SchemaMismatch(_))
    ));
    store.validate_schema().unwrap();

    let mutation_guard: String = client
        .query_one(
            "SELECT pg_get_functiondef(proc.oid) AS definition
               FROM pg_proc AS proc
              WHERE proc.pronamespace = 'public'::regnamespace
                AND proc.proname =
                    'accordlock_reject_dispatch_acquisition_mutation'",
            &[],
        )
        .unwrap()
        .get("definition");
    client
        .batch_execute(
            "CREATE OR REPLACE FUNCTION
                 public.accordlock_reject_dispatch_acquisition_mutation()
             RETURNS trigger LANGUAGE plpgsql AS $function$
             BEGIN
                 RAISE EXCEPTION 'drifted dispatch acquisition guard';
             END
             $function$;",
        )
        .unwrap();
    let function_drift = store.validate_schema();
    client.batch_execute(&mutation_guard).unwrap();
    assert!(matches!(function_drift, Err(StateError::SchemaMismatch(_))));
    store.validate_schema().unwrap();

    let review_update_guard: String = client
        .query_one(
            "SELECT pg_get_functiondef(proc.oid) AS definition
               FROM pg_proc AS proc
              WHERE proc.pronamespace = 'public'::regnamespace
                AND proc.proname =
                    'accordlock_guard_dispatch_credential_review_update'",
            &[],
        )
        .unwrap()
        .get("definition");
    client
        .batch_execute(
            "CREATE OR REPLACE FUNCTION
                 public.accordlock_guard_dispatch_credential_review_update()
             RETURNS trigger LANGUAGE plpgsql AS $function$
             BEGIN
                 RAISE EXCEPTION 'drifted credential review guard';
             END
             $function$;",
        )
        .unwrap();
    let review_function_drift = store.validate_schema();
    client.batch_execute(&review_update_guard).unwrap();
    assert!(matches!(
        review_function_drift,
        Err(StateError::SchemaMismatch(_))
    ));
    store.validate_schema().unwrap();

    client
        .batch_execute(
            "CREATE TRIGGER zz_dispatch_profile_drift
                 BEFORE UPDATE ON public.accordlock_dispatch_acquisitions
                 FOR EACH ROW EXECUTE FUNCTION
                    public.accordlock_reject_dispatch_acquisition_mutation();",
        )
        .unwrap();
    let unexpected_trigger_drift = store.validate_schema();
    client
        .batch_execute(
            "DROP TRIGGER zz_dispatch_profile_drift
                 ON public.accordlock_dispatch_acquisitions;",
        )
        .unwrap();
    assert!(matches!(
        unexpected_trigger_drift,
        Err(StateError::SchemaMismatch(_))
    ));
    store.validate_schema().unwrap();

    client
        .batch_execute(
            "ALTER SEQUENCE public.accordlock_dispatch_acquisitions_lease_fence_seq
                 INCREMENT BY 2;",
        )
        .unwrap();
    let sequence_catalog_drift = store.validate_schema();
    client
        .batch_execute(
            "ALTER SEQUENCE public.accordlock_dispatch_acquisitions_lease_fence_seq
                 INCREMENT BY 1;",
        )
        .unwrap();
    assert!(matches!(
        sequence_catalog_drift,
        Err(StateError::SchemaMismatch(_))
    ));
    store.validate_schema().unwrap();

    let now = database_time(&url);
    let key = register_fixture(
        &store,
        &unique_tenant("dispatch-v14-profile-sequence"),
        now,
        now + 300,
        1,
    );
    store.consume(&key).unwrap();
    store
        .claim_dispatch(&dispatch_claim_request(
            &key,
            Uuid::new_v4(),
            "dispatch-v14-profile-worker",
        ))
        .unwrap();
    let maximum_fence: i64 = client
        .query_one(
            "SELECT max(lease_fence) AS maximum_fence
               FROM public.accordlock_dispatch_acquisitions",
            &[],
        )
        .unwrap()
        .get("maximum_fence");
    client
        .query_one(
            "SELECT setval(
                'public.accordlock_dispatch_acquisitions_lease_fence_seq',
                $1, FALSE
            )",
            &[&maximum_fence],
        )
        .unwrap();
    assert!(matches!(
        store.validate_schema(),
        Err(StateError::SchemaMismatch(_))
    ));
    client
        .query_one(
            "SELECT setval(
                'public.accordlock_dispatch_acquisitions_lease_fence_seq',
                $1, TRUE
            )",
            &[&maximum_fence],
        )
        .unwrap();
    store.validate_schema().unwrap();
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn postgres_v14_claim_state_and_terminalization_are_monotone() {
    let (url, store) = configured_store();
    let now = database_time(&url);
    let key = register_fixture(
        &store,
        &unique_tenant("dispatch-v14-claim-fsm"),
        now,
        now + 300,
        1,
    );
    store.consume(&key).unwrap();
    let token = store
        .claim_dispatch(&dispatch_claim_request(
            &key,
            Uuid::new_v4(),
            "dispatch-v14-claim-fsm-worker",
        ))
        .unwrap()
        .token()
        .clone();
    store
        .mark_attempt_in_flight(&token, credential(&token))
        .unwrap();

    let terminalization_id = Uuid::new_v4();
    let mut client = Client::connect(&url, NoTls).unwrap();
    client
        .batch_execute("SET session_replication_role = replica;")
        .unwrap();
    assert_eq!(
        client
            .execute(
                "UPDATE public.accordlock_dispatch_claims
                    SET state='TERMINAL', terminalization_id=$2
                  WHERE claim_id=$1",
                &[&token.claim_id(), &terminalization_id],
            )
            .unwrap(),
        1
    );
    client
        .batch_execute("SET session_replication_role = origin;")
        .unwrap();

    assert!(
        client
            .execute(
                "UPDATE public.accordlock_dispatch_claims
                    SET state='ATTEMPT_IN_FLIGHT', terminalization_id=NULL
                  WHERE claim_id=$1",
                &[&token.claim_id()],
            )
            .is_err()
    );
    assert!(
        client
            .execute(
                "UPDATE public.accordlock_dispatch_claims
                    SET terminalization_id=$2
                  WHERE claim_id=$1",
                &[&token.claim_id(), &Uuid::new_v4()],
            )
            .is_err()
    );
    assert_eq!(
        client
            .execute(
                "UPDATE public.accordlock_dispatch_claims
                    SET updated_at=updated_at
                  WHERE claim_id=$1",
                &[&token.claim_id()],
            )
            .unwrap(),
        1
    );

    client
        .batch_execute("SET session_replication_role = replica;")
        .unwrap();
    client
        .execute(
            "DELETE FROM public.accordlock_dispatch_acquisitions
              WHERE claim_id=$1",
            &[&token.claim_id()],
        )
        .unwrap();
    client
        .execute(
            "DELETE FROM public.accordlock_dispatch_claims WHERE claim_id=$1",
            &[&token.claim_id()],
        )
        .unwrap();
    client
        .execute(
            "DELETE FROM public.accordlock_dispatch_request_identities
              WHERE dispatch_request_id=$1",
            &[&token.claim_id()],
        )
        .unwrap();
    client
        .batch_execute("SET session_replication_role = origin;")
        .unwrap();
}
