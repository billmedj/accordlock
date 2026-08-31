//! Local, live Kubernetes slice for the fixed `accordlock-demo/payments` profile.
//!
//! This module deliberately uses public deterministic test keys. It combines
//! trusted local fixture construction with a real Kubernetes Deployment
//! snapshot; it is not a production ingress, key-custody, or evidence adapter.

use std::collections::BTreeSet;
use std::str::FromStr as _;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use accordlock_ingress::{
    ActivatedIngressRegistry, AuthenticatedIngressRequest, INGRESS_SCHEMA_VERSION,
    IngressAuthenticator, IngressClaims, IngressKeyStatus, MemoryReplayGuard, RegisteredIngressKey,
    sign_ingress_request,
};
use accordlock_issuance::AuthorizationIssuer;
use accordlock_k8s::{
    PreparedPatch, prepare_patch, validate_admission_candidate, validate_authorized_delta,
    validate_eventual_controller_projection, validate_preconditions,
    validate_rollout_ownership_strict,
};
use accordlock_kernel::{
    ActivatedAttesterRegistry, ExplicitAuthorizationVerificationContext, KernelContext, evaluate,
    sign_evaluation, verify_authorization,
};
use accordlock_protocol::{
    AttesterScope, AttesterStatus, AuthorityDomainState, AuthorityVector, CanonicalEncode,
    CapabilityGrant, CompletenessProfile, ConsumptionReceipt, DecisionOutcome, DeploymentTemplate,
    Digest32, DispatchDeadlinePolicy, EVALUATION_DOMAIN, EVIDENCE_ASSERTION_SCHEMA_VERSION,
    EvidenceAssertion, EvidencePayload, PolicyConfig, RegisteredAttester, SignedAuthorization,
    SignedEvaluation, SignedEvidence, SigningIdentity, TrustedEvidenceSet,
    authorization_signer_root, canonical_hash, evaluator_verifier_root, sign_cose, verify_cose,
};
use accordlock_state::{
    ConsumeKey, ConsumeSuccess, GrantRegistration, InMemoryStore, OutboxStatus, PostgresStore,
    Scope, StateError, TransactionalState, TrustedClock, compute_dispatch_deadline,
};
use anyhow::{Context, Result, anyhow, ensure};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

const TENANT: &str = "local-acme";
const ENVIRONMENT: &str = "local-kind";
const ACTOR: &str = "local-test:ci-workload";
const SOURCE_REPOSITORY: &str = "local/accordlock-demo";
const SOURCE_COMMIT: &str = "1111111111111111111111111111111111111111";
const WORKFLOW_REF: &str = "local://accordlock/live-k8s-build-v1";
const RUN_ID: &str = "local-live-run-v1";
const CLUSTER_IDENTITY: &str = "kind://accordlock";
const NAMESPACE: &str = "accordlock-demo";
const DEPLOYMENT: &str = "payments";
const CONTAINER: &str = "app";
const AUDIENCE: &str = "local-test:kind-executor";
const ALLOWED_IMAGE_REPOSITORY: &str = "docker.io/library/nginx";
const PROFILE_LABEL: &str = "deploy-eks-image-v1";
const TEST_KEY_PROFILE: &str = "LOCAL_DETERMINISTIC_TEST_KEYS_ONLY";
const LIVE_SESSION_SCHEMA_VERSION: u16 = 4;

const REVIEW_KEY_ID: &str = "local-test-review-v1";
const BUILD_KEY_ID: &str = "local-test-build-v1";
const ARTIFACT_KEY_ID: &str = "local-test-artifact-v1";
const TARGET_KEY_ID: &str = "local-test-kubernetes-v1";
const EVALUATOR_KEY_ID: &str = "local-test-evaluator-v1";
const AUTHORIZATION_KEY_ID: &str = "local-test-authorization-v1";

const TRANSACTION_ANNOTATION: &str = "accordlock.io/transaction-id";
const AUTHORIZATION_ANNOTATION: &str = "accordlock.io/authorization-id";
const OPERATION_ANNOTATION: &str = "accordlock.io/operation-hash";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalTestKeyManifest {
    pub profile: String,
    pub warning: String,
    pub evaluator_key_id: String,
    pub evaluator_public_key_base64: String,
    pub authorization_key_id: String,
    pub authorization_public_key_base64: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveK8sSession {
    pub schema_version: u16,
    pub session_kind: String,
    pub benchmark: bool,
    pub synthetic_evidence: bool,
    pub state_backend: LiveStateBackend,
    pub durable_consumption: bool,
    pub state_instance_id: Option<Uuid>,
    pub generated_at: i64,
    pub key_manifest: LocalTestKeyManifest,
    pub transaction_id: Uuid,
    pub proposal: accordlock_protocol::AgentProposal,
    pub signed_evaluation: SignedEvaluation,
    pub signed_authorization: SignedAuthorization,
    pub consumption_receipt: ConsumptionReceipt,
    pub consumption_receipt_ref: LiveStateRecordRef,
    pub execution_outbox_ref: LiveStateRecordRef,
    pub execution_outbox_status: OutboxStatus,
    pub before_deployment: Value,
    pub prepared_patch: PreparedPatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LiveStateBackend {
    InMemory,
    #[serde(rename = "POSTGRESQL")]
    PostgreSql,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveStateRecordRef {
    pub tenant: String,
    pub environment: String,
    pub transaction_id: Uuid,
    pub authorization_id: Uuid,
}

impl LiveStateRecordRef {
    fn from_key(key: &ConsumeKey) -> Self {
        Self {
            tenant: key.scope.tenant.clone(),
            environment: key.scope.environment.clone(),
            transaction_id: key.transaction_id,
            authorization_id: key.authorization_id,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
// These independent booleans are an exported audit report, not authorization
// inputs or an implicit state machine.
#[allow(clippy::struct_excessive_bools)]
pub struct LiveK8sValidation {
    pub schema_version: u16,
    pub validation_kind: String,
    pub benchmark: bool,
    pub authorized_delta: bool,
    pub evaluation_signature_valid: bool,
    pub authorization_signature_valid: bool,
    pub session_bindings_valid: bool,
    pub full_projection_valid: bool,
    pub state_backend: LiveStateBackend,
    pub durable_consumption: bool,
    pub state_records_reverified: bool,
    pub transaction_id: Uuid,
    pub authorization_id: Uuid,
    pub operation_hash: Digest32,
    pub warning: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
// These independent booleans report separately verified boundaries and are
// not authorization inputs or an implicit state machine.
#[allow(clippy::struct_excessive_bools)]
pub struct LiveK8sEffectValidation {
    pub schema_version: u16,
    pub validation_kind: String,
    pub benchmark: bool,
    pub persisted_response_valid: bool,
    pub controller_projection_valid: bool,
    pub rollout_ownership_valid: bool,
    pub state_backend: LiveStateBackend,
    pub durable_consumption: bool,
    pub state_records_reverified: bool,
    pub transaction_id: Uuid,
    pub authorization_id: Uuid,
    pub operation_hash: Digest32,
    pub warning: String,
}

#[derive(Clone, Copy, Debug)]
struct SessionIds {
    request_id: Uuid,
    evaluation_nonce: Uuid,
    grant_id: Uuid,
    evidence_ids: [Uuid; 4],
}

impl SessionIds {
    fn random() -> Self {
        Self {
            request_id: Uuid::new_v4(),
            evaluation_nonce: Uuid::new_v4(),
            grant_id: Uuid::new_v4(),
            evidence_ids: [
                Uuid::new_v4(),
                Uuid::new_v4(),
                Uuid::new_v4(),
                Uuid::new_v4(),
            ],
        }
    }

    #[cfg(test)]
    const fn fixed() -> Self {
        Self {
            request_id: Uuid::from_u128(0x501),
            evaluation_nonce: Uuid::from_u128(0x502),
            grant_id: Uuid::from_u128(0x503),
            evidence_ids: [
                Uuid::from_u128(0x511),
                Uuid::from_u128(0x512),
                Uuid::from_u128(0x513),
                Uuid::from_u128(0x514),
            ],
        }
    }
}

#[derive(Debug)]
struct FixedClock(i64);

impl TrustedClock for FixedClock {
    fn now_unix_seconds(&self) -> Result<i64, StateError> {
        Ok(self.0)
    }
}

#[derive(Clone, Copy, Debug)]
enum LiveStoreConfig<'a> {
    InMemory,
    PostgreSql {
        connection_string: &'a str,
        migrate: bool,
    },
}

/// Builds a complete local session from an actual Deployment JSON snapshot.
///
/// The accepted target is deliberately fixed to the checked-in local profile.
/// The public deterministic keys embedded in this binary are test material.
///
/// # Errors
///
/// Fails closed for a malformed or unexpected Deployment, a tag-based image,
/// absent reserved annotations, a denied kernel decision, a signature error,
/// a failed state transition, or an invalid Kubernetes patch precondition.
pub fn prepare_live_session(
    before_deployment: Value,
    new_image_reference: &str,
) -> Result<LiveK8sSession> {
    let now = current_unix_seconds()?;
    prepare_live_session_at(
        before_deployment,
        new_image_reference,
        now,
        SessionIds::random(),
        LiveStoreConfig::InMemory,
    )
}

/// Builds a local live session while persisting issuance, consumption, receipt,
/// and outbox records in the configured `PostgreSQL` database.
///
/// The connection string is trusted local configuration and is never copied
/// into the session. `migrate` must be explicitly selected by the caller. The
/// database path still uses synthetic evidence and public test keys and is not
/// a production dispatcher.
///
/// # Errors
///
/// Returns an error for the same fail-closed conditions as
/// [`prepare_live_session`], or if `PostgreSQL` cannot be reached, migrated, or
/// used to complete the trusted issuance and identifier-only consumption path.
pub fn prepare_live_session_postgres(
    before_deployment: Value,
    new_image_reference: &str,
    connection_string: &str,
    migrate: bool,
) -> Result<LiveK8sSession> {
    ensure!(
        !connection_string.trim().is_empty(),
        "PostgreSQL connection string is empty"
    );
    let now = current_unix_seconds()?;
    prepare_live_session_at(
        before_deployment,
        new_image_reference,
        now,
        SessionIds::random(),
        LiveStoreConfig::PostgreSql {
            connection_string,
            migrate,
        },
    )
}

#[allow(clippy::too_many_lines)]
fn prepare_live_session_at(
    before_deployment: Value,
    new_image_reference: &str,
    now: i64,
    ids: SessionIds,
    store_config: LiveStoreConfig<'_>,
) -> Result<LiveK8sSession> {
    ensure!(now >= 0, "local trusted time is before the Unix epoch");
    // Every harness run gets an isolated authority/grant scope so rerunning
    // the reproducibility suite against the same disposable database cannot
    // collide with a previously consumed single-use grant.
    let environment = format!("{ENVIRONMENT}-{}", ids.request_id.simple());
    let target = parse_live_target(&before_deployment, new_image_reference)?;
    let policy = local_policy();
    let prior_projection_hash = hash_snapshot(&before_deployment)?;
    let template = DeploymentTemplate {
        operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
        environment: environment.clone(),
        audience: AUDIENCE.to_owned(),
        repository: SOURCE_REPOSITORY.to_owned(),
        commit_sha: SOURCE_COMMIT.to_owned(),
        image_repository: target.image_repository.clone(),
        image_digest: target.new_digest,
        cluster_identity: CLUSTER_IDENTITY.to_owned(),
        namespace: target.namespace,
        deployment: target.deployment,
        deployment_uid: target.uid,
        container: target.container,
        container_index: target.container_index,
        prior_image_digest: target.prior_digest,
        resource_version: target.resource_version,
        prior_projection_hash,
        prior_transaction_annotation: Some(target.prior_transaction_annotation),
        prior_authorization_annotation: Some(target.prior_authorization_annotation),
        prior_operation_hash_annotation: Some(target.prior_operation_hash_annotation),
    };
    let proposal = accordlock_protocol::AgentProposal {
        schema_version: 1,
        request_id: ids.request_id,
        tenant: TENANT.to_owned(),
        actor: ACTOR.to_owned(),
        template: template.clone(),
    };
    let grant_expires_at = now
        .checked_add(600)
        .ok_or_else(|| anyhow!("grant validity overflow"))?;
    let grant = CapabilityGrant {
        grant_id: ids.grant_id,
        holder: ACTOR.to_owned(),
        tenant: TENANT.to_owned(),
        operation: template.operation.clone(),
        repository: SOURCE_REPOSITORY.to_owned(),
        audience: AUDIENCE.to_owned(),
        cluster_identity: CLUSTER_IDENTITY.to_owned(),
        namespace: NAMESPACE.to_owned(),
        deployment_uid: template.deployment_uid.clone(),
        container: CONTAINER.to_owned(),
        image_repository: template.image_repository.clone(),
        not_before: now.saturating_sub(1),
        expires_at: grant_expires_at,
        maximum_uses: 1,
    };
    let authorization_identity = authorization_signer();
    let evaluator = evaluator_signer();
    let mut authority = local_authority(&policy, &grant, &authorization_identity, &evaluator)?;
    let ingress = authenticate_local_ingress(&proposal, &mut authority, now)?;
    let review = review_signer();
    let build = build_signer();
    let artifact = artifact_signer();
    let target_signer = target_signer();
    let mut attesters = vec![
        registered_attester(
            &environment,
            REVIEW_KEY_ID,
            &review,
            "local-test:review-principal",
            AttesterScope::Review {
                repository: SOURCE_REPOSITORY.to_owned(),
            },
        ),
        registered_attester(
            &environment,
            BUILD_KEY_ID,
            &build,
            "local-test:build-principal",
            AttesterScope::Build {
                repository: SOURCE_REPOSITORY.to_owned(),
                workflow_ref: WORKFLOW_REF.to_owned(),
            },
        ),
        registered_attester(
            &environment,
            ARTIFACT_KEY_ID,
            &artifact,
            "local-test:artifact-principal",
            AttesterScope::Artifact {
                image_repository: template.image_repository.clone(),
            },
        ),
        registered_attester(
            &environment,
            TARGET_KEY_ID,
            &target_signer,
            "local-test:kubernetes-principal",
            AttesterScope::Target {
                cluster_identity: CLUSTER_IDENTITY.to_owned(),
                namespace: NAMESPACE.to_owned(),
                deployment_uid: template.deployment_uid.clone(),
            },
        ),
    ];
    attesters
        .sort_by(|left, right| (&left.issuer, &left.key_id).cmp(&(&right.issuer, &right.key_id)));
    authority.registry.root = ActivatedAttesterRegistry::compute_root(&attesters)?;
    let attester_registry = ActivatedAttesterRegistry::new(authority.registry.clone(), attesters)?;
    let hard_cap = now
        .checked_add(120)
        .ok_or_else(|| anyhow!("deadline hard-cap overflow"))?;
    let grant_registration = GrantRegistration {
        environment: environment.clone(),
        grant,
        authority: authority.clone(),
        dispatch_deadline_policy: DispatchDeadlinePolicy {
            max_dispatch_delay_seconds: 30,
            profile_hard_cap: hard_cap,
            immutable_dependency_expiries: vec![hard_cap],
        },
    };

    let valid_until = now
        .checked_add(600)
        .ok_or_else(|| anyhow!("evidence validity overflow"))?;
    let observed_at = now.saturating_sub(1);
    let signed_evidence = vec![
        signed_evidence(
            ids.evidence_ids[0],
            REVIEW_KEY_ID,
            &review,
            &authority,
            ids.request_id,
            observed_at,
            valid_until,
            EvidencePayload::Review {
                repository: SOURCE_REPOSITORY.to_owned(),
                commit_sha: SOURCE_COMMIT.to_owned(),
                approved: true,
                review_state_id: "local-test-approved-v1".to_owned(),
            },
        )?,
        signed_evidence(
            ids.evidence_ids[1],
            BUILD_KEY_ID,
            &build,
            &authority,
            ids.request_id,
            observed_at,
            valid_until,
            EvidencePayload::Build {
                repository: SOURCE_REPOSITORY.to_owned(),
                commit_sha: SOURCE_COMMIT.to_owned(),
                workflow_ref: WORKFLOW_REF.to_owned(),
                run_id: RUN_ID.to_owned(),
                succeeded: true,
                input_manifest_root: Digest32::sha256(b"local-test:hermetic-inputs-v1"),
                completeness_profile: CompletenessProfile::HermeticInputsV1,
                output_digest: template.image_digest,
            },
        )?,
        signed_evidence(
            ids.evidence_ids[2],
            ARTIFACT_KEY_ID,
            &artifact,
            &authority,
            ids.request_id,
            observed_at,
            valid_until,
            EvidencePayload::Artifact {
                repository: template.image_repository.clone(),
                digest: template.image_digest,
                source_run_id: RUN_ID.to_owned(),
                signature_valid: true,
                quarantined: false,
            },
        )?,
        signed_evidence(
            ids.evidence_ids[3],
            TARGET_KEY_ID,
            &target_signer,
            &authority,
            ids.request_id,
            observed_at,
            valid_until,
            EvidencePayload::Target {
                cluster_identity: template.cluster_identity.clone(),
                namespace: template.namespace.clone(),
                deployment: template.deployment.clone(),
                deployment_uid: template.deployment_uid.clone(),
                resource_version: template.resource_version.clone(),
                current_image: template.prior_image_digest,
                projection_hash: template.prior_projection_hash,
            },
        )?,
    ];
    let context = KernelContext::from_authenticated_ingress(
        ingress,
        now,
        ids.evaluation_nonce,
        policy,
        authority.clone(),
        attester_registry,
    )?;
    let evidence = TrustedEvidenceSet {
        request_id: ids.request_id,
        evidence: signed_evidence,
    };
    let evaluation = evaluate(&proposal, &evidence, &context)?;
    ensure!(
        evaluation.outcome == DecisionOutcome::Allow,
        "local kernel denied the live session: {:?}",
        evaluation.reasons
    );
    let signed_evaluation = sign_evaluation(evaluation, &evaluator)?;
    let scope = Scope::new(TENANT, &environment)?;
    let (
        signed_authorization,
        consume_key,
        consumption,
        state_backend,
        durable_consumption,
        state_instance_id,
    ) = match store_config {
        LiveStoreConfig::InMemory => {
            let consumption_time = now
                .checked_add(1)
                .ok_or_else(|| anyhow!("consumption time overflow"))?;
            let store = InMemoryStore::with_clock(Arc::new(FixedClock(consumption_time)));
            let (issued, consumed) = issue_and_consume(
                &store,
                &scope,
                &authority,
                &grant_registration,
                &proposal,
                &signed_evaluation,
                &evaluator,
            )?;
            (
                issued.signed_authorization,
                issued.consume_key,
                consumed,
                LiveStateBackend::InMemory,
                false,
                None,
            )
        }
        LiveStoreConfig::PostgreSql {
            connection_string,
            migrate,
        } => {
            let store = PostgresStore::new(connection_string);
            if migrate {
                store
                    .migrate()
                    .context("explicit PostgreSQL migration failed")?;
            }
            let state_instance_id = store
                .state_instance_id()
                .context("PostgreSQL state-lineage identity is unavailable")?;
            let (issued, consumed) = issue_and_consume(
                &store,
                &scope,
                &authority,
                &grant_registration,
                &proposal,
                &signed_evaluation,
                &evaluator,
            )?;
            (
                issued.signed_authorization,
                issued.consume_key,
                consumed,
                LiveStateBackend::PostgreSql,
                true,
                Some(state_instance_id),
            )
        }
    };
    let historical_authorization_verification = ExplicitAuthorizationVerificationContext::new(
        consumption.receipt().consumed_at,
        AUDIENCE,
        &authority,
    )?;
    let _historically_verified_authorization = verify_authorization(
        &signed_authorization,
        &authorization_identity.verifier(),
        &historical_authorization_verification,
    )?;
    let receipt_ref = LiveStateRecordRef::from_key(&consume_key);
    let outbox_ref = LiveStateRecordRef::from_key(&consume_key);

    validate_preconditions(&before_deployment, &template)?;
    let prepared_patch = prepare_patch(
        &template,
        consume_key.transaction_id,
        consume_key.authorization_id,
    )?;
    let session = LiveK8sSession {
        schema_version: LIVE_SESSION_SCHEMA_VERSION,
        session_kind: "LOCAL_LIVE_KUBERNETES_SESSION".to_owned(),
        benchmark: false,
        synthetic_evidence: true,
        state_backend,
        durable_consumption,
        state_instance_id,
        generated_at: now,
        key_manifest: local_key_manifest(),
        transaction_id: consume_key.transaction_id,
        proposal,
        signed_evaluation,
        signed_authorization,
        consumption_receipt: consumption.receipt().clone(),
        consumption_receipt_ref: receipt_ref,
        execution_outbox_ref: outbox_ref,
        execution_outbox_status: consumption.outbox().status,
        before_deployment,
        prepared_patch,
    };
    verify_session_bindings(&session)?;
    Ok(session)
}

fn issue_and_consume<S: TransactionalState + Clone>(
    store: &S,
    scope: &Scope,
    authority: &AuthorityVector,
    grant: &GrantRegistration,
    proposal: &accordlock_protocol::AgentProposal,
    signed_evaluation: &SignedEvaluation,
    evaluator: &SigningIdentity,
) -> Result<(accordlock_issuance::IssuanceSuccess, ConsumeSuccess)> {
    match store.active_authority(scope) {
        Ok(active) => ensure!(
            active == *authority,
            "configured state backend has a different active authority vector"
        ),
        Err(StateError::AuthorityNotInitialized) => {
            store.compare_and_activate_authority(scope, None, authority)?;
        }
        Err(error) => return Err(error.into()),
    }

    store.register_grant(grant)?;
    let authorization_issuer =
        AuthorizationIssuer::new(store.clone(), evaluator.verifier(), authorization_signer());
    let issued =
        authorization_issuer.issue(proposal, signed_evaluation, scope, grant.grant.grant_id)?;

    // This is the public consumption boundary: only stored identifiers cross
    // it. Active authority, trusted time, grant state, and deadline inputs are
    // reloaded by the selected state adapter. The idempotent operation also
    // reloads and cross-validates the exact durable tuple if a database commit
    // succeeded but its response was lost.
    let consumed = store.consume_or_recover(&issued.consume_key)?;
    ensure!(
        store.consumption_receipt(&issued.consume_key)? == *consumed.receipt(),
        "stored consumption receipt differs from the committed result"
    );
    ensure!(
        store.outbox_entry(&issued.consume_key)? == *consumed.outbox(),
        "stored execution outbox entry differs from the committed result"
    );
    ensure!(
        consumed.issued().signed_authorization == issued.signed_authorization,
        "consumption did not reload the exact signed issuance record"
    );
    Ok((issued, consumed))
}

/// Verifies the complete stored session and the persisted PATCH response.
///
/// # Errors
///
/// Fails closed for any cryptographic, cross-object, snapshot, receipt, patch,
/// or full-projection mismatch.
pub fn validate_live_session(
    session: &LiveK8sSession,
    after_deployment: &Value,
) -> Result<LiveK8sValidation> {
    ensure!(
        session.state_backend == LiveStateBackend::InMemory,
        "PostgreSQL sessions require validate_live_session_postgres"
    );
    validate_live_session_inner(session, after_deployment, false)
}

/// Re-verifies a `PostgreSQL`-backed session against the configured database
/// before validating the observed Kubernetes object.
///
/// # Errors
///
/// Fails closed if the session is not labelled as `PostgreSQL`, the configured
/// database lacks the exact committed receipt and pending outbox entry, or any
/// ordinary live-session validation fails.
pub fn validate_live_session_postgres(
    session: &LiveK8sSession,
    after_deployment: &Value,
    connection_string: &str,
) -> Result<LiveK8sValidation> {
    ensure!(
        session.state_backend == LiveStateBackend::PostgreSql && session.durable_consumption,
        "PostgreSQL validation requires a durable PostgreSQL session"
    );
    ensure!(
        !connection_string.trim().is_empty(),
        "PostgreSQL connection string is empty"
    );
    let key = consume_key_from_reference(&session.consumption_receipt_ref)?;
    ensure!(
        LiveStateRecordRef::from_key(&key) == session.execution_outbox_ref,
        "receipt and outbox references differ"
    );
    let store = PostgresStore::new(connection_string);
    let expected_state_instance_id = session
        .state_instance_id
        .context("PostgreSQL session has no state-lineage identity")?;
    ensure!(
        store.state_instance_id()? == expected_state_instance_id,
        "configured PostgreSQL state lineage differs from the session"
    );
    ensure!(
        store.consumption_receipt(&key)? == session.consumption_receipt,
        "durable PostgreSQL receipt differs from the session"
    );
    let outbox = store.outbox_entry(&key)?;
    ensure!(
        outbox.status == session.execution_outbox_status
            && outbox.receipt == session.consumption_receipt,
        "durable PostgreSQL outbox differs from the session"
    );
    validate_live_session_inner(session, after_deployment, true)
}

/// Validates a server-side dry-run candidate before the runner submits the
/// real patch.
///
/// This verifies the complete local session and candidate projection but does
/// not reload `PostgreSQL` state. Durable state is reverified against the actual
/// persisted response after submission.
///
/// # Errors
///
/// Fails closed for any session-binding or dry-run candidate mismatch.
pub fn validate_live_candidate(
    session: &LiveK8sSession,
    candidate: &Value,
) -> Result<LiveK8sValidation> {
    verify_session_bindings(session)?;
    let authorization = &session.signed_authorization.authorization;
    validate_admission_candidate(
        &session.before_deployment,
        candidate,
        &authorization.template,
        session.transaction_id,
        authorization.authorization_id,
        session.prepared_patch.operation_hash,
    )?;
    Ok(LiveK8sValidation {
        schema_version: 1,
        validation_kind: "LOCAL_LIVE_KUBERNETES_SERVER_DRY_RUN_CANDIDATE".to_owned(),
        benchmark: false,
        authorized_delta: true,
        evaluation_signature_valid: true,
        authorization_signature_valid: true,
        session_bindings_valid: true,
        full_projection_valid: true,
        state_backend: session.state_backend,
        durable_consumption: session.durable_consumption,
        state_records_reverified: false,
        transaction_id: session.transaction_id,
        authorization_id: authorization.authorization_id,
        operation_hash: session.prepared_patch.operation_hash,
        warning: "Server dry-run validation is preflight evidence, not an atomic admission decision; persisted-response validation remains required.".to_owned(),
    })
}

/// Validates the synchronous persisted Deployment response and the eventual
/// exhaustive Deployment, `ReplicaSet`, and Pod ownership projection.
///
/// # Errors
///
/// Fails closed for a non-memory session, an invalid persisted response, or
/// any eventual desired-state change outside the controller projection or an
/// incomplete or inconsistent rollout ownership snapshot.
pub fn validate_live_effect(
    session: &LiveK8sSession,
    persisted_response: &Value,
    eventual: &Value,
    replica_sets: &Value,
    pods: &Value,
) -> Result<LiveK8sEffectValidation> {
    let _ = validate_live_session(session, persisted_response)?;
    validate_live_effect_inner(
        session,
        persisted_response,
        eventual,
        replica_sets,
        pods,
        false,
    )
}

/// PostgreSQL-backed form of [`validate_live_effect`].
///
/// # Errors
///
/// Fails closed if durable state cannot be reloaded exactly or either
/// Kubernetes projection is invalid.
pub fn validate_live_effect_postgres(
    session: &LiveK8sSession,
    persisted_response: &Value,
    eventual: &Value,
    replica_sets: &Value,
    pods: &Value,
    connection_string: &str,
) -> Result<LiveK8sEffectValidation> {
    let _ = validate_live_session_postgres(session, persisted_response, connection_string)?;
    validate_live_effect_inner(
        session,
        persisted_response,
        eventual,
        replica_sets,
        pods,
        true,
    )
}

fn validate_live_effect_inner(
    session: &LiveK8sSession,
    persisted_response: &Value,
    eventual: &Value,
    replica_sets: &Value,
    pods: &Value,
    state_records_reverified: bool,
) -> Result<LiveK8sEffectValidation> {
    let authorization = &session.signed_authorization.authorization;
    validate_eventual_controller_projection(
        persisted_response,
        eventual,
        &authorization.template,
        session.transaction_id,
        authorization.authorization_id,
        session.prepared_patch.operation_hash,
    )?;
    validate_rollout_ownership_strict(eventual, replica_sets, pods)?;
    Ok(LiveK8sEffectValidation {
        schema_version: 2,
        validation_kind: "LOCAL_LIVE_KUBERNETES_EVENTUAL_EFFECT".to_owned(),
        benchmark: false,
        persisted_response_valid: true,
        controller_projection_valid: true,
        rollout_ownership_valid: true,
        state_backend: session.state_backend,
        durable_consumption: session.durable_consumption,
        state_records_reverified,
        transaction_id: session.transaction_id,
        authorization_id: authorization.authorization_id,
        operation_hash: session.prepared_patch.operation_hash,
        warning: "The eventual projection checks an exhaustive selector-scoped ReplicaSet and Pod snapshot plus the exact Deployment-to-ReplicaSet-to-Pod ownership chain; separate Kubernetes reads are not an atomic snapshot, and this is not an effect receipt or external review.".to_owned(),
    })
}

fn validate_live_session_inner(
    session: &LiveK8sSession,
    after_deployment: &Value,
    state_records_reverified: bool,
) -> Result<LiveK8sValidation> {
    verify_session_bindings(session)?;
    validate_authorized_delta(
        &session.before_deployment,
        after_deployment,
        &session.signed_authorization.authorization.template,
        session.transaction_id,
        session.signed_authorization.authorization.authorization_id,
        session.prepared_patch.operation_hash,
    )?;
    Ok(LiveK8sValidation {
        schema_version: 1,
        validation_kind: "LOCAL_LIVE_KUBERNETES_PERSISTED_RESPONSE".to_owned(),
        benchmark: false,
        authorized_delta: true,
        evaluation_signature_valid: true,
        authorization_signature_valid: true,
        session_bindings_valid: true,
        full_projection_valid: true,
        state_backend: session.state_backend,
        durable_consumption: session.durable_consumption,
        state_records_reverified,
        transaction_id: session.transaction_id,
        authorization_id: session.signed_authorization.authorization.authorization_id,
        operation_hash: session.prepared_patch.operation_hash,
        warning: match session.state_backend {
            LiveStateBackend::InMemory => "Local deterministic test keys and in-memory consumption; not production evidence, custody, durability, dispatch, or external validation.".to_owned(),
            LiveStateBackend::PostgreSql => "Local deterministic test keys with a PostgreSQL receipt and pending outbox record reverified in the configured database; this is durable consumption, not production evidence, custody, dispatch, effect confirmation, or external validation.".to_owned(),
        },
    })
}

fn consume_key_from_reference(reference: &LiveStateRecordRef) -> Result<ConsumeKey> {
    Ok(ConsumeKey {
        scope: Scope::new(&reference.tenant, &reference.environment)?,
        transaction_id: reference.transaction_id,
        authorization_id: reference.authorization_id,
    })
}

#[allow(clippy::too_many_lines)]
fn verify_session_bindings(session: &LiveK8sSession) -> Result<()> {
    ensure!(
        session.schema_version == LIVE_SESSION_SCHEMA_VERSION,
        "unsupported live session schema"
    );
    ensure!(
        session.session_kind == "LOCAL_LIVE_KUBERNETES_SESSION",
        "unexpected live session kind"
    );
    ensure!(
        !session.benchmark,
        "live session cannot claim benchmark status"
    );
    ensure!(
        session.synthetic_evidence,
        "live session evidence must be labelled synthetic"
    );
    ensure!(
        session.durable_consumption == (session.state_backend == LiveStateBackend::PostgreSql),
        "state backend and durability label are inconsistent"
    );
    let state_instance_binding_valid = match session.state_backend {
        LiveStateBackend::InMemory => session.state_instance_id.is_none(),
        LiveStateBackend::PostgreSql => session.state_instance_id.is_some_and(|id| !id.is_nil()),
    };
    ensure!(
        state_instance_binding_valid,
        "state backend and state-lineage identity are inconsistent"
    );
    ensure!(
        session.key_manifest == local_key_manifest(),
        "live session test-key manifest does not match the compiled local trust anchor"
    );

    let evaluator = evaluator_signer();
    let signed_evaluation_payload = verify_cose(
        &session.signed_evaluation.cose_sign1,
        EVALUATION_DOMAIN,
        &evaluator.verifier(),
    )
    .context("evaluation COSE verification failed")?;
    ensure!(
        signed_evaluation_payload == session.signed_evaluation.attestation.canonical_bytes()?,
        "evaluation COSE payload differs from the canonical attestation"
    );
    ensure!(
        session.signed_evaluation.attestation.outcome == DecisionOutcome::Allow,
        "session evaluation is not ALLOW"
    );
    let authorization_verifier = authorization_signer().verifier();
    let historical_authorization_verification = ExplicitAuthorizationVerificationContext::new(
        session.consumption_receipt.consumed_at,
        AUDIENCE,
        &session.consumption_receipt.authority,
    )
    .context("recorded authorization verification context is invalid")?;
    let _historically_verified_authorization = verify_authorization(
        &session.signed_authorization,
        &authorization_verifier,
        &historical_authorization_verification,
    )
    .context("historical contextual authorization verification failed")?;

    let evaluation = &session.signed_evaluation.attestation;
    let authorization = &session.signed_authorization.authorization;
    let proposal = &session.proposal;
    let template_hash = canonical_hash(&proposal.template)?;
    ensure!(
        proposal.template == authorization.template,
        "proposal and authorization templates differ"
    );
    ensure!(
        proposal.request_id == evaluation.request_id
            && proposal.request_id == authorization.request_id
            && proposal.tenant == evaluation.tenant
            && proposal.tenant == authorization.tenant
            && proposal.actor == evaluation.actor
            && proposal.actor == authorization.holder,
        "proposal identity is not bound consistently"
    );
    ensure!(
        evaluation.evaluation_nonce == authorization.evaluation_nonce
            && evaluation.template_hash == template_hash
            && authorization.template_hash == template_hash
            && evaluation.evidence_root == authorization.evidence_root
            && evaluation.principals == authorization.principals
            && evaluation.policy_root == authorization.policy_root
            && evaluation.authority == authorization.authority
            && evaluation.consume_before >= authorization.consume_before,
        "evaluation-to-authorization binding is inconsistent"
    );
    ensure!(
        authorization.audience == AUDIENCE
            && authorization.template.cluster_identity == CLUSTER_IDENTITY
            && authorization.template.namespace == NAMESPACE
            && authorization.template.deployment == DEPLOYMENT
            && authorization.template.container == CONTAINER
            && authorization.template.image_repository == ALLOWED_IMAGE_REPOSITORY,
        "authorization is outside the compiled local Kubernetes profile"
    );
    ensure!(
        hash_snapshot(&session.before_deployment)? == authorization.template.prior_projection_hash,
        "before snapshot does not match the signed target projection hash"
    );
    validate_preconditions(&session.before_deployment, &authorization.template)?;

    let receipt = &session.consumption_receipt;
    let expected_record_ref = LiveStateRecordRef {
        tenant: authorization.tenant.clone(),
        environment: authorization.template.environment.clone(),
        transaction_id: session.transaction_id,
        authorization_id: authorization.authorization_id,
    };
    let expected_dispatch_deadline = compute_dispatch_deadline(
        receipt.consumed_at,
        authorization.consume_before,
        &authorization.dispatch_deadline_policy,
    )?;
    ensure!(
        receipt.transaction_id == session.transaction_id
            && receipt.authorization_id == authorization.authorization_id
            && receipt.authority == authorization.authority
            && receipt.authorization_hash == canonical_hash(authorization)?
            && receipt.consumed_at >= authorization.not_before
            && receipt.consumed_at < authorization.consume_before
            && receipt.dispatch_deadline > receipt.consumed_at
            && receipt.dispatch_deadline == expected_dispatch_deadline,
        "consumption receipt is inconsistent with the signed authorization"
    );
    ensure!(
        session.consumption_receipt_ref == expected_record_ref
            && session.execution_outbox_ref == expected_record_ref
            && session.execution_outbox_status == OutboxStatus::PendingWitness,
        "receipt or outbox reference is inconsistent with the consumed authorization"
    );
    let recomputed = prepare_patch(
        &authorization.template,
        session.transaction_id,
        authorization.authorization_id,
    )?;
    ensure!(
        recomputed == session.prepared_patch,
        "stored JSON Patch does not match the signed authorization and transaction"
    );
    Ok(())
}

#[derive(Debug)]
struct ParsedTarget {
    namespace: String,
    deployment: String,
    uid: String,
    resource_version: String,
    container: String,
    container_index: u32,
    image_repository: String,
    prior_digest: Digest32,
    new_digest: Digest32,
    prior_transaction_annotation: String,
    prior_authorization_annotation: String,
    prior_operation_hash_annotation: String,
}

fn parse_live_target(before: &Value, new_image_reference: &str) -> Result<ParsedTarget> {
    require_exact(before, "/apiVersion", "apps/v1")?;
    require_exact(before, "/kind", "Deployment")?;
    let deployment = require_string(before, "/metadata/name")?;
    let namespace = require_string(before, "/metadata/namespace")?;
    ensure!(
        deployment == DEPLOYMENT,
        "local profile accepts only Deployment {DEPLOYMENT:?}"
    );
    ensure!(
        namespace == NAMESPACE,
        "local profile accepts only namespace {NAMESPACE:?}"
    );
    require_exact(
        before,
        "/metadata/labels/accordlock.io~1profile",
        PROFILE_LABEL,
    )?;
    ensure!(
        before.pointer("/spec/replicas").and_then(Value::as_u64) == Some(1),
        "local profile requires exactly one desired replica"
    );
    require_exact(before, "/spec/selector/matchLabels/app", "payments")?;
    require_exact(before, "/spec/template/metadata/labels/app", "payments")?;
    require_exact(
        before,
        "/spec/template/spec/serviceAccountName",
        "payments-runtime",
    )?;
    ensure!(
        before
            .pointer("/spec/template/spec/automountServiceAccountToken")
            .and_then(Value::as_bool)
            == Some(false),
        "local profile requires automountServiceAccountToken=false"
    );
    let uid = require_nonempty(before, "/metadata/uid")?;
    let resource_version = require_nonempty(before, "/metadata/resourceVersion")?;
    let containers = before
        .pointer("/spec/template/spec/containers")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("Deployment has no containers array"))?;
    ensure!(
        containers.len() == 1,
        "local profile requires exactly one regular container"
    );
    require_absent_or_empty_array(before, "/spec/template/spec/initContainers")?;
    require_absent_or_empty_array(before, "/spec/template/spec/ephemeralContainers")?;
    let matching_indices: Vec<_> = containers
        .iter()
        .enumerate()
        .filter(|(_, value)| value.get("name").and_then(Value::as_str) == Some(CONTAINER))
        .map(|(index, _)| index)
        .collect();
    ensure!(
        matching_indices.len() == 1,
        "local profile requires exactly one container named {CONTAINER:?}"
    );
    let index = matching_indices[0];
    let current_reference = containers[index]
        .get("image")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("target container has no image string"))?;
    let (prior_repository, prior_digest) = parse_digest_image(current_reference)?;
    let (new_repository, new_digest) = parse_digest_image(new_image_reference)?;
    ensure!(
        prior_repository == new_repository,
        "DEPLOY_EKS_IMAGE_V1 currently requires the image repository to remain unchanged"
    );
    ensure!(
        new_repository == ALLOWED_IMAGE_REPOSITORY,
        "local profile accepts only image repository {ALLOWED_IMAGE_REPOSITORY:?}"
    );
    ensure!(
        prior_digest != new_digest,
        "new image digest equals the current digest"
    );
    let container_index = u32::try_from(index).context("container index exceeds u32")?;
    Ok(ParsedTarget {
        namespace,
        deployment,
        uid,
        resource_version,
        container: CONTAINER.to_owned(),
        container_index,
        image_repository: new_repository,
        prior_digest,
        new_digest,
        prior_transaction_annotation: require_annotation(before, TRANSACTION_ANNOTATION)?,
        prior_authorization_annotation: require_annotation(before, AUTHORIZATION_ANNOTATION)?,
        prior_operation_hash_annotation: require_annotation(before, OPERATION_ANNOTATION)?,
    })
}

fn parse_digest_image(reference: &str) -> Result<(String, Digest32)> {
    let (repository, digest) = reference
        .split_once('@')
        .ok_or_else(|| anyhow!("image reference must be repository@sha256:<64 hex>"))?;
    ensure!(!repository.is_empty(), "image repository is empty");
    ensure!(
        !repository.contains('@') && digest.starts_with("sha256:"),
        "image reference must contain one sha256 digest"
    );
    let digest = Digest32::from_str(digest).map_err(|error| anyhow!(error))?;
    Ok((repository.to_owned(), digest))
}

fn require_string(value: &Value, pointer: &str) -> Result<String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("Deployment field {pointer} must be a string"))
}

fn require_nonempty(value: &Value, pointer: &str) -> Result<String> {
    let result = require_string(value, pointer)?;
    ensure!(
        !result.trim().is_empty(),
        "Deployment field {pointer} is empty"
    );
    Ok(result)
}

fn require_exact(value: &Value, pointer: &str, expected: &str) -> Result<()> {
    ensure!(
        require_string(value, pointer)? == expected,
        "Deployment field {pointer} does not equal {expected:?}"
    );
    Ok(())
}

fn require_annotation(value: &Value, key: &str) -> Result<String> {
    let escaped = key.replace('~', "~0").replace('/', "~1");
    require_string(value, &format!("/metadata/annotations/{escaped}"))
        .with_context(|| format!("reserved annotation {key:?} must be pre-provisioned"))
}

fn require_absent_or_empty_array(value: &Value, pointer: &str) -> Result<()> {
    match value.pointer(pointer) {
        None => Ok(()),
        Some(Value::Array(values)) if values.is_empty() => Ok(()),
        Some(Value::Array(_)) => Err(anyhow!("Deployment field {pointer} must be empty")),
        Some(_) => Err(anyhow!("Deployment field {pointer} must be an array")),
    }
}

fn hash_snapshot(value: &Value) -> Result<Digest32> {
    let bytes = serde_json::to_vec(value).context("Deployment snapshot serialization failed")?;
    Ok(Digest32::sha256(&bytes))
}

fn current_unix_seconds() -> Result<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?;
    i64::try_from(duration.as_secs()).context("Unix time exceeds i64")
}

fn local_policy() -> PolicyConfig {
    PolicyConfig {
        policy_id: "local-live-kind-v1".to_owned(),
        allowed_actors: vec![ACTOR.to_owned()],
        allowed_repositories: vec![SOURCE_REPOSITORY.to_owned()],
        allowed_image_repositories: vec![ALLOWED_IMAGE_REPOSITORY.to_owned()],
        allowed_clusters: vec![CLUSTER_IDENTITY.to_owned()],
        allowed_namespaces: vec![NAMESPACE.to_owned()],
        minimum_review_grade: 2,
        minimum_build_grade: 2,
        maximum_evidence_age_seconds: 60,
        maximum_authorization_lifetime_seconds: 120,
    }
}

fn local_authority(
    policy: &PolicyConfig,
    grant: &CapabilityGrant,
    authorization_signer: &SigningIdentity,
    evaluator: &SigningIdentity,
) -> Result<AuthorityVector> {
    let mut authority = AuthorityVector {
        policy: AuthorityDomainState {
            root: canonical_hash(policy)?,
            epoch: 1,
            activation_id: Uuid::from_u128(0x601),
        },
        registry: domain("registry", 0x602),
        revocation: domain("revocation", 0x603),
        connector: domain("connector", 0x604),
        resource: domain("resource", 0x605),
        signer: domain("signer", 0x606),
        mediation: domain("mediation", 0x607),
        grant_registry: domain("grant-registry", 0x608),
        office_act_registry: domain("office-act-registry", 0x609),
        principal_registry: domain("principal-registry", 0x60a),
        workload_build_allowlist: domain("workload-build-allowlist", 0x60b),
        kernel_configuration: domain("kernel-configuration", 0x60c),
    };
    authority.grant_registry.root = canonical_hash(grant)?;
    authority.signer.root = authorization_signer_root(
        authorization_signer.key_id(),
        authorization_signer.public_key_bytes(),
    )?;
    authority.kernel_configuration.root =
        evaluator_verifier_root(evaluator.key_id(), evaluator.public_key_bytes())?;
    Ok(authority)
}

fn authenticate_local_ingress(
    proposal: &accordlock_protocol::AgentProposal,
    authority: &mut AuthorityVector,
    now: i64,
) -> Result<AuthenticatedIngressRequest> {
    // Deterministic harness bootstrap only: this auto-activates a public test
    // key and fixed nonce behind a fresh process-local replay guard.
    let signer = SigningIdentity::from_seed("local-test-ingress-v1", [0x42; 32]);
    let registration = RegisteredIngressKey {
        key_id: signer.key_id().to_owned(),
        public_key: signer.public_key_bytes(),
        tenant: TENANT.to_owned(),
        actor: ACTOR.to_owned(),
        allowed_audiences: BTreeSet::from([AUDIENCE.to_owned()]),
        not_before: now.saturating_sub(60),
        expires_at: now.saturating_add(300),
        status: IngressKeyStatus::Active,
    };
    authority.principal_registry.root =
        ActivatedIngressRegistry::compute_root(AUDIENCE, 180, std::slice::from_ref(&registration))?;
    let registry = ActivatedIngressRegistry::new(
        authority.principal_registry.clone(),
        AUDIENCE,
        180,
        vec![registration],
    )?;
    let authenticator = IngressAuthenticator::new(registry, MemoryReplayGuard::default())?;
    let claims = IngressClaims {
        schema_version: INGRESS_SCHEMA_VERSION,
        audience: AUDIENCE.to_owned(),
        issued_at: now.saturating_sub(1),
        expires_at: now.saturating_add(120),
        nonce: Uuid::from_u128(0x60d),
        proposal: proposal.clone(),
    };
    let wire = serde_json::to_string(&sign_ingress_request(claims, &signer)?)?;
    Ok(authenticator.authenticate_json(&wire, now)?)
}

fn domain(label: &str, activation: u128) -> AuthorityDomainState {
    AuthorityDomainState {
        root: Digest32::sha256(format!("local-test-authority:{label}:v1").as_bytes()),
        epoch: 1,
        activation_id: Uuid::from_u128(activation),
    }
}

#[allow(clippy::too_many_arguments)]
fn signed_evidence(
    evidence_id: Uuid,
    issuer: &str,
    signer: &SigningIdentity,
    authority: &AuthorityVector,
    request_id: Uuid,
    observed_at: i64,
    valid_until: i64,
    payload: EvidencePayload,
) -> Result<SignedEvidence> {
    let assertion = EvidenceAssertion {
        schema_version: EVIDENCE_ASSERTION_SCHEMA_VERSION,
        request_id,
        evidence_id,
        issuer: issuer.to_owned(),
        key_id: signer.key_id().to_owned(),
        source_uri: format!("local-test://{issuer}/{evidence_id}"),
        observed_at,
        valid_until,
        authority: authority.clone(),
        payload,
    };
    let cose_sign1 = sign_cose(
        &assertion.canonical_bytes()?,
        assertion.payload.kind().domain(),
        signer,
    )?;
    Ok(SignedEvidence {
        assertion,
        cose_sign1,
    })
}

fn registered_attester(
    environment: &str,
    issuer: &str,
    signer: &SigningIdentity,
    principal: &str,
    scope: AttesterScope,
) -> RegisteredAttester {
    RegisteredAttester {
        tenant: TENANT.to_owned(),
        environment: environment.to_owned(),
        issuer: issuer.to_owned(),
        key_id: signer.key_id().to_owned(),
        public_key: signer.public_key_bytes(),
        principal_id: principal.to_owned(),
        base_grade: 3,
        status: AttesterStatus::Active,
        scopes: vec![scope],
    }
}

fn local_key_manifest() -> LocalTestKeyManifest {
    let evaluator = evaluator_signer();
    let authorization = authorization_signer();
    LocalTestKeyManifest {
        profile: TEST_KEY_PROFILE.to_owned(),
        warning: "Seeds are public and compiled into accordlock-cli; never use these keys outside local tests.".to_owned(),
        evaluator_key_id: evaluator.key_id().to_owned(),
        evaluator_public_key_base64: base64::engine::general_purpose::STANDARD
            .encode(evaluator.public_key_bytes()),
        authorization_key_id: authorization.key_id().to_owned(),
        authorization_public_key_base64: base64::engine::general_purpose::STANDARD
            .encode(authorization.public_key_bytes()),
    }
}

fn review_signer() -> SigningIdentity {
    SigningIdentity::from_seed(REVIEW_KEY_ID, [31; 32])
}

fn build_signer() -> SigningIdentity {
    SigningIdentity::from_seed(BUILD_KEY_ID, [32; 32])
}

fn artifact_signer() -> SigningIdentity {
    SigningIdentity::from_seed(ARTIFACT_KEY_ID, [33; 32])
}

fn target_signer() -> SigningIdentity {
    SigningIdentity::from_seed(TARGET_KEY_ID, [34; 32])
}

fn evaluator_signer() -> SigningIdentity {
    SigningIdentity::from_seed(EVALUATOR_KEY_ID, [35; 32])
}

fn authorization_signer() -> SigningIdentity {
    SigningIdentity::from_seed(AUTHORIZATION_KEY_ID, [36; 32])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const OLD_DIGEST: &str = "65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10";
    const NEW_DIGEST: &str = "a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236";

    fn deployment() -> Value {
        json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": DEPLOYMENT,
                "namespace": NAMESPACE,
                "uid": "11111111-2222-4333-8444-555555555555",
                "resourceVersion": "1234",
                "generation": 1,
                "labels": {"accordlock.io/profile": PROFILE_LABEL},
                "annotations": {
                    TRANSACTION_ANNOTATION: "unset",
                    AUTHORIZATION_ANNOTATION: "unset",
                    OPERATION_ANNOTATION: "unset",
                    "deployment.kubernetes.io/revision": "1"
                },
                "managedFields": []
            },
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": "payments"}},
                "template": {
                    "metadata": {"labels": {"app": "payments"}},
                    "spec": {
                        "serviceAccountName": "payments-runtime",
                        "automountServiceAccountToken": false,
                        "containers": [{
                            "name": CONTAINER,
                            "image": format!("{ALLOWED_IMAGE_REPOSITORY}@sha256:{OLD_DIGEST}"),
                            "imagePullPolicy": "IfNotPresent"
                        }]
                    }
                }
            },
            "status": {"availableReplicas": 1}
        })
    }

    fn session() -> Result<LiveK8sSession> {
        prepare_live_session_at(
            deployment(),
            &format!("{ALLOWED_IMAGE_REPOSITORY}@sha256:{NEW_DIGEST}"),
            1_700_000_000,
            SessionIds::fixed(),
            LiveStoreConfig::InMemory,
        )
    }

    fn authorized_after(session: &LiveK8sSession) -> Result<Value> {
        let mut after = session.before_deployment.clone();
        let template = &session.signed_authorization.authorization.template;
        let image_pointer = format!(
            "/spec/template/spec/containers/{}/image",
            template.container_index
        );
        *after
            .pointer_mut(&image_pointer)
            .ok_or_else(|| anyhow!("test image path missing"))? = Value::String(format!(
            "{}@{}",
            template.image_repository, template.image_digest
        ));
        let annotations = after
            .pointer_mut("/metadata/annotations")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| anyhow!("test annotations missing"))?;
        annotations.insert(
            TRANSACTION_ANNOTATION.to_owned(),
            Value::String(session.transaction_id.to_string()),
        );
        annotations.insert(
            AUTHORIZATION_ANNOTATION.to_owned(),
            Value::String(
                session
                    .signed_authorization
                    .authorization
                    .authorization_id
                    .to_string(),
            ),
        );
        annotations.insert(
            OPERATION_ANNOTATION.to_owned(),
            Value::String(session.prepared_patch.operation_hash.to_string()),
        );
        after["metadata"]["resourceVersion"] = Value::String("1235".to_owned());
        after["metadata"]["generation"] = json!(2);
        Ok(after)
    }

    fn rollout_pods(eventual: &Value) -> Value {
        json!({
            "apiVersion":"v1",
            "kind":"List",
            "items":[{
                "apiVersion":"v1",
                "kind":"Pod",
                "metadata":{
                    "name":"payments-abc",
                    "namespace":NAMESPACE,
                    "uid":"cccccccc-dddd-4eee-8fff-000000000000",
                    "labels":{"app":"payments","pod-template-hash":"abc"},
                    "ownerReferences":[{
                        "apiVersion":"apps/v1",
                        "kind":"ReplicaSet",
                        "name":"payments-abc",
                        "uid":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                        "controller":true
                    }]
                },
                "spec":eventual["spec"]["template"]["spec"].clone(),
                "status":{"phase":"Running","conditions":[{"type":"Ready","status":"True"}]}
            }]
        })
    }

    fn rollout_replica_sets(eventual: &Value) -> Value {
        let mut template = eventual["spec"]["template"].clone();
        template["metadata"]["labels"]["pod-template-hash"] = Value::String("abc".to_owned());
        json!({
            "apiVersion":"v1",
            "kind":"List",
            "items":[{
                "apiVersion":"apps/v1",
                "kind":"ReplicaSet",
                "metadata":{
                    "name":"payments-abc",
                    "namespace":NAMESPACE,
                    "uid":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                    "generation":2,
                    "labels":{"app":"payments","pod-template-hash":"abc"},
                    "ownerReferences":[{
                        "apiVersion":"apps/v1",
                        "kind":"Deployment",
                        "name":DEPLOYMENT,
                        "uid":eventual["metadata"]["uid"].clone(),
                        "controller":true
                    }]
                },
                "spec":{
                    "replicas":1,
                    "selector":{"matchLabels":{"app":"payments","pod-template-hash":"abc"}},
                    "template":template
                },
                "status":{
                    "observedGeneration":2,
                    "replicas":1,
                    "fullyLabeledReplicas":1,
                    "readyReplicas":1,
                    "availableReplicas":1
                }
            }]
        })
    }

    #[test]
    fn real_snapshot_drives_signed_consumed_patch_session() -> Result<()> {
        let session = session()?;
        assert_eq!(
            session.signed_evaluation.attestation.outcome,
            DecisionOutcome::Allow
        );
        assert_eq!(
            session
                .signed_authorization
                .authorization
                .template
                .deployment_uid,
            "11111111-2222-4333-8444-555555555555"
        );
        assert_eq!(
            session
                .signed_authorization
                .authorization
                .template
                .resource_version,
            "1234"
        );
        assert_eq!(
            session.consumption_receipt.authorization_id,
            session.signed_authorization.authorization.authorization_id
        );
        assert_eq!(session.state_backend, LiveStateBackend::InMemory);
        assert!(!session.durable_consumption);
        assert_eq!(session.state_instance_id, None);
        assert_eq!(
            session.consumption_receipt_ref,
            session.execution_outbox_ref
        );
        assert_eq!(
            session.execution_outbox_status,
            OutboxStatus::PendingWitness
        );
        assert!(!session.benchmark);
        assert_eq!(
            session.prepared_patch.patch.as_array().map(Vec::len),
            Some(11)
        );
        let report = validate_live_session(&session, &authorized_after(&session)?)?;
        assert!(report.authorized_delta && report.full_projection_valid);
        Ok(())
    }

    #[test]
    fn state_backend_wire_labels_are_explicit() -> Result<()> {
        assert_eq!(
            serde_json::to_value(LiveStateBackend::InMemory)?,
            json!("IN_MEMORY")
        );
        assert_eq!(
            serde_json::to_value(LiveStateBackend::PostgreSql)?,
            json!("POSTGRESQL")
        );
        Ok(())
    }

    #[test]
    fn post_admission_sidecar_fails_closed() -> Result<()> {
        let session = session()?;
        let mut after = authorized_after(&session)?;
        after["spec"]["template"]["spec"]["containers"]
            .as_array_mut()
            .ok_or_else(|| anyhow!("test containers missing"))?
            .push(json!({"name": "injected", "image": "attacker.invalid/sidecar:latest"}));
        assert!(validate_live_session(&session, &after).is_err());
        Ok(())
    }

    #[test]
    fn server_dry_run_candidate_is_validated_without_a_persistence_claim() -> Result<()> {
        let session = session()?;
        let mut candidate = authorized_after(&session)?;
        candidate["metadata"]["resourceVersion"] = Value::String("1234".to_owned());
        candidate["metadata"]["generation"] = json!(1);

        let report = validate_live_candidate(&session, &candidate)?;
        assert_eq!(
            report.validation_kind,
            "LOCAL_LIVE_KUBERNETES_SERVER_DRY_RUN_CANDIDATE"
        );
        assert!(report.full_projection_valid);
        assert!(!report.state_records_reverified);

        candidate["spec"]["template"]["spec"]["containers"]
            .as_array_mut()
            .ok_or_else(|| anyhow!("test containers missing"))?
            .push(json!({"name":"injected","image":"attacker.invalid/sidecar:latest"}));
        assert!(validate_live_candidate(&session, &candidate).is_err());
        Ok(())
    }

    #[test]
    fn controller_annotation_change_is_not_silently_ignored() -> Result<()> {
        let session = session()?;
        let mut after = authorized_after(&session)?;
        after["metadata"]["annotations"]["deployment.kubernetes.io/revision"] =
            Value::String("2".to_owned());
        assert!(validate_live_session(&session, &after).is_err());
        Ok(())
    }

    #[test]
    fn post_admission_status_change_is_not_silently_ignored() -> Result<()> {
        let session = session()?;
        let mut after = authorized_after(&session)?;
        after["status"] = json!({"availableReplicas": 0});
        assert!(validate_live_session(&session, &after).is_err());
        Ok(())
    }

    #[test]
    fn preexisting_regular_or_init_sidecars_are_rejected() -> Result<()> {
        let mut regular = deployment();
        regular["spec"]["template"]["spec"]["containers"]
            .as_array_mut()
            .ok_or_else(|| anyhow!("test containers missing"))?
            .push(json!({"name":"sidecar","image":"attacker.invalid/sidecar:latest"}));
        assert!(
            prepare_live_session_at(
                regular,
                &format!("{ALLOWED_IMAGE_REPOSITORY}@sha256:{NEW_DIGEST}"),
                1_700_000_000,
                SessionIds::fixed(),
                LiveStoreConfig::InMemory,
            )
            .is_err()
        );

        let mut init = deployment();
        init["spec"]["template"]["spec"]["initContainers"] =
            json!([{"name":"init","image":"attacker.invalid/init:latest"}]);
        assert!(
            prepare_live_session_at(
                init,
                &format!("{ALLOWED_IMAGE_REPOSITORY}@sha256:{NEW_DIGEST}"),
                1_700_000_000,
                SessionIds::fixed(),
                LiveStoreConfig::InMemory,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn deployment_outside_the_fixed_runtime_profile_is_rejected() {
        let mut wrong_service_account = deployment();
        wrong_service_account["spec"]["template"]["spec"]["serviceAccountName"] =
            Value::String("elevated".to_owned());
        assert!(
            prepare_live_session_at(
                wrong_service_account,
                &format!("{ALLOWED_IMAGE_REPOSITORY}@sha256:{NEW_DIGEST}"),
                1_700_000_000,
                SessionIds::fixed(),
                LiveStoreConfig::InMemory,
            )
            .is_err()
        );

        let mut automount = deployment();
        automount["spec"]["template"]["spec"]["automountServiceAccountToken"] = json!(true);
        assert!(
            prepare_live_session_at(
                automount,
                &format!("{ALLOWED_IMAGE_REPOSITORY}@sha256:{NEW_DIGEST}"),
                1_700_000_000,
                SessionIds::fixed(),
                LiveStoreConfig::InMemory,
            )
            .is_err()
        );
    }

    #[test]
    fn eventual_controller_projection_is_checked_separately() -> Result<()> {
        let session = session()?;
        let persisted_response = authorized_after(&session)?;
        let mut eventual = persisted_response.clone();
        eventual["metadata"]["resourceVersion"] = Value::String("1240".to_owned());
        eventual["metadata"]["managedFields"] = json!([{"manager":"kube-controller-manager"}]);
        eventual["metadata"]["annotations"]["deployment.kubernetes.io/revision"] =
            Value::String("2".to_owned());
        eventual["status"] = json!({
            "observedGeneration":2,
            "replicas":1,
            "updatedReplicas":1,
            "readyReplicas":1,
            "availableReplicas":1
        });
        let replica_sets = rollout_replica_sets(&eventual);
        let pods = rollout_pods(&eventual);
        let report = validate_live_effect(
            &session,
            &persisted_response,
            &eventual,
            &replica_sets,
            &pods,
        )?;
        assert!(
            report.persisted_response_valid
                && report.controller_projection_valid
                && report.rollout_ownership_valid
        );

        eventual["spec"]["template"]["spec"]["serviceAccountName"] =
            Value::String("elevated".to_owned());
        assert!(
            validate_live_effect(
                &session,
                &persisted_response,
                &eventual,
                &replica_sets,
                &pods
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn eventual_effect_rejects_incomplete_or_foreign_replica_set_snapshot() -> Result<()> {
        let session = session()?;
        let persisted_response = authorized_after(&session)?;
        let mut eventual = persisted_response.clone();
        eventual["metadata"]["resourceVersion"] = Value::String("1240".to_owned());
        eventual["metadata"]["managedFields"] = json!([{"manager":"kube-controller-manager"}]);
        eventual["metadata"]["annotations"]["deployment.kubernetes.io/revision"] =
            Value::String("2".to_owned());
        eventual["status"] = json!({
            "observedGeneration":2,
            "replicas":1,
            "updatedReplicas":1,
            "readyReplicas":1,
            "availableReplicas":1
        });
        let pods = rollout_pods(&eventual);
        let empty_replica_sets = json!({"apiVersion":"v1","kind":"List","items":[]});
        assert!(
            validate_live_effect(
                &session,
                &persisted_response,
                &eventual,
                &empty_replica_sets,
                &pods
            )
            .is_err()
        );

        let mut foreign_replica_sets = rollout_replica_sets(&eventual);
        foreign_replica_sets["items"][0]["metadata"]["ownerReferences"][0]["uid"] =
            Value::String("99999999-8888-4777-8666-555555555555".to_owned());
        assert!(
            validate_live_effect(
                &session,
                &persisted_response,
                &eventual,
                &foreign_replica_sets,
                &pods
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn tag_based_current_image_is_rejected() {
        let mut value = deployment();
        value["spec"]["template"]["spec"]["containers"][0]["image"] =
            Value::String("docker.io/library/nginx:latest".to_owned());
        assert!(
            prepare_live_session_at(
                value,
                &format!("{ALLOWED_IMAGE_REPOSITORY}@sha256:{NEW_DIGEST}"),
                1_700_000_000,
                SessionIds::fixed(),
                LiveStoreConfig::InMemory,
            )
            .is_err()
        );
    }

    #[test]
    fn missing_reserved_annotation_is_rejected() -> Result<()> {
        let mut value = deployment();
        value["metadata"]["annotations"]
            .as_object_mut()
            .ok_or_else(|| anyhow!("test annotations missing"))?
            .remove(AUTHORIZATION_ANNOTATION);
        assert!(
            prepare_live_session_at(
                value,
                &format!("{ALLOWED_IMAGE_REPOSITORY}@sha256:{NEW_DIGEST}"),
                1_700_000_000,
                SessionIds::fixed(),
                LiveStoreConfig::InMemory,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn tampered_before_snapshot_breaks_signed_projection_binding() -> Result<()> {
        let mut session = session()?;
        session.before_deployment["spec"]["replicas"] = json!(99);
        assert!(verify_session_bindings(&session).is_err());
        Ok(())
    }

    #[test]
    fn tampered_patch_is_recomputed_and_rejected() -> Result<()> {
        let mut session = session()?;
        session.prepared_patch.patch[0]["value"] = Value::String("wrong-uid".to_owned());
        assert!(verify_session_bindings(&session).is_err());
        Ok(())
    }

    #[test]
    fn forged_durable_backend_label_is_rejected() -> Result<()> {
        let mut session = session()?;
        session.durable_consumption = true;
        assert!(verify_session_bindings(&session).is_err());
        Ok(())
    }

    #[test]
    fn forged_state_lineage_label_is_rejected() -> Result<()> {
        let mut session = session()?;
        session.state_instance_id = Some(Uuid::new_v4());
        assert!(verify_session_bindings(&session).is_err());
        Ok(())
    }

    #[test]
    #[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
    fn postgres_live_session_persists_receipt_and_outbox() -> Result<()> {
        let connection_string = std::env::var("ACCORDLOCK_TEST_POSTGRES_URL")
            .context("ACCORDLOCK_TEST_POSTGRES_URL is required")?;
        let session = prepare_live_session_postgres(
            deployment(),
            &format!("{ALLOWED_IMAGE_REPOSITORY}@sha256:{NEW_DIGEST}"),
            &connection_string,
            true,
        )?;
        assert_eq!(session.state_backend, LiveStateBackend::PostgreSql);
        assert!(session.durable_consumption);

        let store = PostgresStore::new(connection_string.clone());
        assert_eq!(session.state_instance_id, Some(store.state_instance_id()?));
        let key = ConsumeKey {
            scope: Scope::new(
                &session.consumption_receipt_ref.tenant,
                &session.consumption_receipt_ref.environment,
            )?,
            transaction_id: session.consumption_receipt_ref.transaction_id,
            authorization_id: session.consumption_receipt_ref.authorization_id,
        };
        assert_eq!(
            store.consumption_receipt(&key)?,
            session.consumption_receipt
        );
        assert_eq!(
            store.outbox_entry(&key)?.status,
            OutboxStatus::PendingWitness
        );
        assert!(matches!(
            store.consume(&key),
            Err(StateError::AlreadyConsumed)
        ));
        let recovered = store.consume_or_recover(&key)?;
        assert_eq!(
            serde_json::to_vec(recovered.receipt())?,
            serde_json::to_vec(&session.consumption_receipt)?
        );
        assert_eq!(
            serde_json::to_vec(recovered.outbox())?,
            serde_json::to_vec(&store.outbox_entry(&key)?)?
        );
        assert!(validate_live_session(&session, &authorized_after(&session)?).is_err());
        let report = validate_live_session_postgres(
            &session,
            &authorized_after(&session)?,
            &connection_string,
        )?;
        assert!(report.state_records_reverified);
        let mut wrong_lineage = session.clone();
        wrong_lineage.state_instance_id = Some(Uuid::new_v4());
        assert!(
            validate_live_session_postgres(
                &wrong_lineage,
                &authorized_after(&wrong_lineage)?,
                &connection_string,
            )
            .is_err()
        );
        Ok(())
    }
}
