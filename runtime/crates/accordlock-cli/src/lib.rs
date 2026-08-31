//! Deterministic, synthetic differential scenarios for the local `AccordLock` slice.
//!
//! The fixtures in this crate exercise the real protocol, kernel, state, and
//! Kubernetes projection code. They are conformance exhibits, not benchmark or
//! deployment results.

pub mod live_k8s;

use std::collections::BTreeSet;
use std::sync::Arc;

use accordlock_enforcement::production_readiness_blockers;
use accordlock_ingress::{
    ActivatedIngressRegistry, AuthenticatedIngressRequest, INGRESS_SCHEMA_VERSION,
    IngressAuthenticator, IngressClaims, IngressKeyStatus, MemoryReplayGuard, RegisteredIngressKey,
    sign_ingress_request,
};
use accordlock_issuance::AuthorizationIssuer;
use accordlock_k8s::{ProjectionError, prepare_patch, validate_authorized_delta};
use accordlock_kernel::{
    ActivatedAttesterRegistry, BaselineDecision, BaselineFacts,
    ExplicitAuthorizationVerificationContext, KernelContext, evaluate, evaluate_plain_policy,
    sign_evaluation, verify_authorization,
};
use accordlock_protocol::{
    AttesterScope, AttesterStatus, AuthorityDomainState, AuthorityVector, CanonicalEncode,
    CapabilityGrant, CompletenessProfile, DecisionOutcome, Digest32, DispatchDeadlinePolicy,
    EVALUATION_DOMAIN, EVIDENCE_ASSERTION_SCHEMA_VERSION, EvidenceAssertion, EvidencePayload,
    PolicyConfig, ReasonCode, RegisteredAttester, SignedEvidence, SigningIdentity,
    TrustedEvidenceSet, authorization_signer_root, canonical_hash, evaluator_verifier_root,
    sign_cose, verify_cose,
};
use accordlock_state::{
    GrantRegistration, InMemoryStore, Scope, StateError, TransactionalState, TrustedClock,
};
use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;

const NOW: i64 = 1_700_000_100;
const CONSUMPTION_TIME: i64 = 1_700_000_110;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scenario {
    Dp000,
    Dp101,
    Dp102,
    Dp103,
}

impl Scenario {
    const ALL: [Self; 4] = [Self::Dp000, Self::Dp101, Self::Dp102, Self::Dp103];

    const fn id(self) -> &'static str {
        match self {
            Self::Dp000 => "DP-000",
            Self::Dp101 => "DP-101",
            Self::Dp102 => "DP-102",
            Self::Dp103 => "DP-103",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            "DP-000" | "DP000" => Ok(Self::Dp000),
            "DP-101" | "DP101" => Ok(Self::Dp101),
            "DP-102" | "DP102" => Ok(Self::Dp102),
            "DP-103" | "DP103" => Ok(Self::Dp103),
            _ => {
                bail!("unknown scenario {value:?}; expected all, DP-000, DP-101, DP-102, or DP-103")
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StepStatus {
    NotReached,
    Accepted,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StepResult {
    pub status: StepStatus,
    pub reason: Option<String>,
}

impl StepResult {
    fn not_reached(reason: &str) -> Self {
        Self {
            status: StepStatus::NotReached,
            reason: Some(reason.to_owned()),
        }
    }

    fn accepted() -> Self {
        Self {
            status: StepStatus::Accepted,
            reason: None,
        }
    }

    fn rejected(reason: &str) -> Self {
        Self {
            status: StepStatus::Rejected,
            reason: Some(reason.to_owned()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AccordLockResult {
    pub evaluation_outcome: DecisionOutcome,
    pub evaluation_reasons: Vec<ReasonCode>,
    pub evaluation_signature: StepResult,
    pub authorization: StepResult,
    pub consumption: StepResult,
    pub replay_attempt: StepResult,
    pub post_admission_projection: StepResult,
    pub final_effect_authorized: bool,
    pub transaction_id: Option<Uuid>,
    pub authorization_id: Option<Uuid>,
    pub dispatch_deadline: Option<i64>,
    pub operation_hash: Option<Digest32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScenarioResult {
    pub scenario_id: String,
    pub synthetic: bool,
    pub baseline_profile: String,
    pub comparison_scope: String,
    pub baseline: BaselineDecision,
    pub accordlock: AccordLockResult,
    pub differential_observed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DemoReport {
    pub schema_version: u16,
    pub report_kind: String,
    pub production_ready: bool,
    pub benchmark: bool,
    pub execution_profile: OfflineExecutionProfile,
    pub coverage: OfflineCoverage,
    pub scenarios: Vec<ScenarioResult>,
}

/// Explicit safety and provenance contract for the offline demonstration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OfflineExecutionProfile {
    pub mode: String,
    pub determinism: String,
    pub network_access: String,
    pub external_mutation: String,
    pub credential_source: String,
    pub production_enforcement_entry_point: String,
}

/// Aggregate coverage for exactly the scenarios present in this report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OfflineCoverage {
    pub phases: Vec<PhaseCoverage>,
    pub live_gates: Vec<LiveGate>,
}

/// Whether and where a security phase was exercised by this invocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PhaseCoverage {
    pub phase: String,
    pub status: CoverageStatus,
    pub exercised_by: Vec<String>,
    pub boundary: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageStatus {
    Exercised,
    NotExercised,
}

/// One environment proof that an offline run cannot satisfy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LiveGate {
    pub code: String,
    pub satisfied: bool,
    pub evidence: String,
}

/// Runs all scenarios or one selected scenario and checks the expected
/// fail-closed outcome before returning a report.
///
/// # Errors
///
/// Returns an error for an unknown selector, malformed fixture, failed
/// cryptographic or state transition, or any outcome that differs from the
/// scenario's fail-closed invariant.
pub fn run_selection(selection: &str) -> Result<DemoReport> {
    let scenarios = if selection.eq_ignore_ascii_case("all") {
        Scenario::ALL.to_vec()
    } else {
        vec![Scenario::parse(selection)?]
    };
    let mut results = Vec::with_capacity(scenarios.len());
    for scenario in scenarios {
        let result = run_scenario(scenario)?;
        validate_expected(scenario, &result)?;
        results.push(result);
    }
    let coverage = offline_coverage(&results);
    Ok(DemoReport {
        schema_version: 2,
        report_kind: "OFFLINE_DETERMINISTIC_SECURITY_DEMO".to_owned(),
        production_ready: false,
        benchmark: false,
        execution_profile: OfflineExecutionProfile {
            mode: "OFFLINE_DETERMINISTIC_NO_NETWORK".to_owned(),
            determinism: "FIXED_FIXTURES_AND_OUTPUT".to_owned(),
            network_access: "NOT_ACCESSED".to_owned(),
            external_mutation: "NONE".to_owned(),
            credential_source: "PUBLIC_HARD_CODED_TEST_KEYS_ONLY".to_owned(),
            production_enforcement_entry_point: "NOT_INVOKED".to_owned(),
        },
        coverage,
        scenarios: results,
    })
}

fn offline_coverage(results: &[ScenarioResult]) -> OfflineCoverage {
    let all = scenario_ids_matching(results, |_| true);
    let authorization = scenario_ids_matching(results, |result| {
        result.accordlock.authorization.status == StepStatus::Accepted
    });
    let temporal_recheck = scenario_ids_matching(results, |result| {
        result.accordlock.consumption.reason.as_deref() == Some("AUTHORITY_MISMATCH")
    });
    let consumption = scenario_ids_matching(results, |result| {
        result.accordlock.consumption.status != StepStatus::NotReached
    });
    let replay = scenario_ids_matching(results, |result| {
        result.accordlock.replay_attempt.reason.as_deref() == Some("ALREADY_CONSUMED")
    });
    let projection = scenario_ids_matching(results, |result| {
        result.accordlock.post_admission_projection.status != StepStatus::NotReached
    });

    let phases = vec![
        exercised_phase(
            "AUTHENTICATED_INGRESS",
            all.clone(),
            "Signed local ingress envelope verified against an activated fixture registry",
        ),
        exercised_phase(
            "SIGNED_EVIDENCE_AND_KERNEL_EVALUATION",
            all.clone(),
            "Signed review, build, artifact, and target fixtures evaluated by the real kernel",
        ),
        exercised_phase(
            "SIGNED_EVALUATION_VERIFICATION",
            all,
            "Canonical evaluation bytes signed and verified with public deterministic test keys",
        ),
        phase_from_ids(
            "AUTHORIZATION_ISSUANCE_AND_CONTEXTUAL_VERIFICATION",
            authorization,
            "One-time authorization issued and verified against time, audience, and authority",
        ),
        phase_from_ids(
            "CURRENT_AUTHORITY_RECHECK",
            temporal_recheck,
            "A stale authorization is rejected after authority advancement",
        ),
        phase_from_ids(
            "TRANSACTIONAL_SINGLE_USE_CONSUMPTION",
            consumption,
            "Process-local in-memory adapter only; no durable database claim",
        ),
        phase_from_ids(
            "AUTHORIZATION_REPLAY_REJECTION",
            replay,
            "A second consumption of the same authorization is rejected as already consumed",
        ),
        phase_from_ids(
            "KUBERNETES_PATCH_AND_POST_ADMISSION_DELTA_VALIDATION",
            projection,
            "Pure JSON projection only; no API server or admission webhook was contacted",
        ),
        not_exercised_phase(
            "DURABLE_POSTGRES_STATE",
            "The offline command intentionally uses only fresh process-local state",
        ),
        not_exercised_phase(
            "DISPATCH_ACQUISITION_V14",
            "The productive dispatch queue and acquisition authority are not invoked offline",
        ),
        not_exercised_phase(
            "EKS_CREDENTIAL_BROKER",
            "No management credential, bound Secret, or short-lived bearer is created",
        ),
        not_exercised_phase(
            "NATIVE_EKS_EXECUTOR_AND_PROVIDER_EFFECT",
            "No Kubernetes or cloud request is sent and no provider effect is claimed",
        ),
        not_exercised_phase(
            "ADMISSION_WEBHOOK_CALLER_BOUNDARY",
            "No live AdmissionReview caller identity is available offline",
        ),
        not_exercised_phase(
            "CREDENTIAL_RETIREMENT",
            "No credential exists in this run, so retirement cannot be exercised",
        ),
    ];
    let live_gates = production_readiness_blockers()
        .into_iter()
        .map(|blocker| LiveGate {
            code: blocker.code().to_owned(),
            satisfied: false,
            evidence: "NOT_PROVABLE_BY_OFFLINE_EXECUTION".to_owned(),
        })
        .collect();
    OfflineCoverage { phases, live_gates }
}

fn scenario_ids_matching(
    results: &[ScenarioResult],
    predicate: impl Fn(&ScenarioResult) -> bool,
) -> Vec<String> {
    results
        .iter()
        .filter(|result| predicate(result))
        .map(|result| result.scenario_id.clone())
        .collect()
}

fn exercised_phase(phase: &str, exercised_by: Vec<String>, boundary: &str) -> PhaseCoverage {
    debug_assert!(!exercised_by.is_empty());
    PhaseCoverage {
        phase: phase.to_owned(),
        status: CoverageStatus::Exercised,
        exercised_by,
        boundary: boundary.to_owned(),
    }
}

fn phase_from_ids(phase: &str, exercised_by: Vec<String>, boundary: &str) -> PhaseCoverage {
    let status = if exercised_by.is_empty() {
        CoverageStatus::NotExercised
    } else {
        CoverageStatus::Exercised
    };
    PhaseCoverage {
        phase: phase.to_owned(),
        status,
        exercised_by,
        boundary: boundary.to_owned(),
    }
}

fn not_exercised_phase(phase: &str, boundary: &str) -> PhaseCoverage {
    PhaseCoverage {
        phase: phase.to_owned(),
        status: CoverageStatus::NotExercised,
        exercised_by: Vec::new(),
        boundary: boundary.to_owned(),
    }
}

fn run_scenario(scenario: Scenario) -> Result<ScenarioResult> {
    let fixture = Fixture::new(scenario)?;
    let baseline_facts = BaselineFacts {
        review_approved: true,
        build_succeeded: true,
        artifact_signature_valid: true,
        artifact_quarantined: false,
        target_current: true,
    };
    let baseline =
        evaluate_plain_policy(&fixture.proposal, fixture.context.policy(), &baseline_facts);
    let evaluation = evaluate(&fixture.proposal, &fixture.evidence, &fixture.context)
        .context("kernel evaluation failed")?;
    let signed_evaluation = sign_evaluation(evaluation.clone(), &fixture.evaluator)
        .context("evaluation signing failed")?;
    let signed_payload = verify_cose(
        &signed_evaluation.cose_sign1,
        EVALUATION_DOMAIN,
        &fixture.evaluator.verifier(),
    )
    .context("evaluation signature verification failed")?;
    ensure!(
        signed_payload == evaluation.canonical_bytes()?,
        "signed evaluation payload differs from canonical attestation"
    );

    let mut accordlock = AccordLockResult {
        evaluation_outcome: evaluation.outcome,
        evaluation_reasons: evaluation.reasons.clone(),
        evaluation_signature: StepResult::accepted(),
        authorization: StepResult::not_reached("EVALUATION_DENIED"),
        consumption: StepResult::not_reached("NO_AUTHORIZATION"),
        replay_attempt: StepResult::not_reached("NO_SUCCESSFUL_CONSUMPTION"),
        post_admission_projection: StepResult::not_reached("NO_CONSUMPTION"),
        final_effect_authorized: false,
        transaction_id: None,
        authorization_id: None,
        dispatch_deadline: None,
        operation_hash: None,
    };

    if evaluation.outcome == DecisionOutcome::Allow {
        run_allowed_path(scenario, &fixture, &signed_evaluation, &mut accordlock)?;
    } else if scenario == Scenario::Dp102 {
        accordlock.consumption = run_dp102_temporal_recheck()?;
    }

    Ok(ScenarioResult {
        scenario_id: scenario.id().to_owned(),
        synthetic: true,
        baseline_profile: "PLAIN_POLICY_GATEWAY_REFERENCE".to_owned(),
        comparison_scope: comparison_scope(scenario).to_owned(),
        differential_observed: baseline.allow != accordlock.final_effect_authorized,
        baseline,
        accordlock,
    })
}

fn comparison_scope(scenario: Scenario) -> &'static str {
    match scenario {
        Scenario::Dp000 => "LEGITIMATE_FLOW",
        Scenario::Dp101 => "CROSS_OBJECT_BUILD_TO_ARTIFACT_LINEAGE",
        Scenario::Dp102 => "STALE_BASELINE_FACTS_AND_AUTHORITY_RECHECK",
        Scenario::Dp103 => "POST_ADMISSION_FULL_DELTA",
    }
}

fn run_allowed_path(
    scenario: Scenario,
    fixture: &Fixture,
    signed_evaluation: &accordlock_protocol::SignedEvaluation,
    result: &mut AccordLockResult,
) -> Result<()> {
    let store = InMemoryStore::with_clock(Arc::new(FixedClock(CONSUMPTION_TIME)));
    let scope = Scope::new(
        fixture.proposal.tenant.clone(),
        fixture.proposal.template.environment.clone(),
    )?;
    store.compare_and_activate_authority(&scope, None, fixture.context.active_authority())?;
    store.register_grant(&GrantRegistration {
        environment: fixture.proposal.template.environment.clone(),
        grant: fixture.grant.clone(),
        authority: fixture.context.active_authority().clone(),
        dispatch_deadline_policy: DispatchDeadlinePolicy {
            max_dispatch_delay_seconds: 30,
            profile_hard_cap: NOW + 500,
            immutable_dependency_expiries: vec![NOW + 350],
        },
    })?;
    let authorization_signer = fixture_authorization_signer();
    let authorization_verifier = authorization_signer.verifier();
    let authorization_issuer = AuthorizationIssuer::new(
        store.clone(),
        fixture.evaluator.verifier(),
        authorization_signer,
    );
    let issued = authorization_issuer
        .issue(
            &fixture.proposal,
            signed_evaluation,
            &scope,
            fixture.grant.grant_id,
        )
        .context("authorization issuance failed")?;
    let historical_authorization_verification = ExplicitAuthorizationVerificationContext::new(
        CONSUMPTION_TIME,
        &fixture.proposal.template.audience,
        fixture.context.active_authority(),
    )?;
    let _historically_verified_authorization = verify_authorization(
        &issued.signed_authorization,
        &authorization_verifier,
        &historical_authorization_verification,
    )
    .context("authorization verification failed")?;
    let signed_authorization = issued.signed_authorization;
    let consume_key = issued.consume_key;
    let authorization_id = consume_key.authorization_id;
    let transaction_id = consume_key.transaction_id;
    result.authorization = StepResult::accepted();
    result.authorization_id = Some(authorization_id);
    result.transaction_id = Some(transaction_id);

    let consumed = store.consume(&consume_key)?;
    result.consumption = StepResult::accepted();
    result.dispatch_deadline = Some(consumed.receipt().dispatch_deadline);
    result.replay_attempt = match store.consume(&consume_key) {
        Err(StateError::AlreadyConsumed) => StepResult::rejected("ALREADY_CONSUMED"),
        Err(error) => return Err(error).context("unexpected authorization replay failure"),
        Ok(_) => bail!("single-use authorization was consumed twice"),
    };

    let template = &signed_authorization.authorization.template;
    let old = deployment_object(template);
    let prepared = prepare_patch(template, transaction_id, authorization_id)?;
    let mut after = authorized_after(
        &old,
        template,
        transaction_id,
        authorization_id,
        prepared.operation_hash,
    )?;
    if scenario == Scenario::Dp103 {
        let containers = after
            .pointer_mut("/spec/template/spec/containers")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| anyhow!("fixture containers are missing"))?;
        containers.push(json!({
            "name": "injected-sidecar",
            "image": "registry.example/sidecar@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        }));
    }
    match validate_authorized_delta(
        &old,
        &after,
        template,
        transaction_id,
        authorization_id,
        prepared.operation_hash,
    ) {
        Ok(()) => {
            result.post_admission_projection = StepResult::accepted();
            result.final_effect_authorized = true;
        }
        Err(ProjectionError::UnauthorizedDelta(_)) if scenario == Scenario::Dp103 => {
            result.post_admission_projection =
                StepResult::rejected("UNAUTHORIZED_POST_ADMISSION_DELTA");
        }
        Err(error) => return Err(error).context("Kubernetes projection validation failed"),
    }
    result.operation_hash = Some(prepared.operation_hash);
    Ok(())
}

fn run_dp102_temporal_recheck() -> Result<StepResult> {
    let old = Fixture::new(Scenario::Dp000)?;
    let evaluation = evaluate(&old.proposal, &old.evidence, &old.context)?;
    ensure!(
        evaluation.outcome == DecisionOutcome::Allow,
        "DP-102 setup was not allowed"
    );
    let signed_evaluation = sign_evaluation(evaluation, &old.evaluator)?;
    let store = InMemoryStore::with_clock(Arc::new(FixedClock(CONSUMPTION_TIME)));
    let scope = Scope::new(
        old.proposal.tenant.clone(),
        old.proposal.template.environment.clone(),
    )?;
    store.compare_and_activate_authority(&scope, None, old.context.active_authority())?;
    store.register_grant(&GrantRegistration {
        environment: old.proposal.template.environment.clone(),
        grant: old.grant.clone(),
        authority: old.context.active_authority().clone(),
        dispatch_deadline_policy: DispatchDeadlinePolicy {
            max_dispatch_delay_seconds: 30,
            profile_hard_cap: NOW + 500,
            immutable_dependency_expiries: vec![NOW + 350],
        },
    })?;
    let authorization_signer = fixture_authorization_signer();
    let authorization_issuer = AuthorizationIssuer::new(
        store.clone(),
        old.evaluator.verifier(),
        authorization_signer,
    );
    let issued = authorization_issuer.issue(
        &old.proposal,
        &signed_evaluation,
        &scope,
        old.grant.grant_id,
    )?;
    let advanced = advanced_review_authority(old.context.active_authority());
    store.compare_and_activate_authority(
        &scope,
        Some(old.context.active_authority()),
        &advanced,
    )?;
    match store.consume(&issued.consume_key) {
        Err(StateError::AuthorityMismatch) => Ok(StepResult::rejected("AUTHORITY_MISMATCH")),
        Err(error) => Err(error).context("unexpected DP-102 consumption failure"),
        Ok(_) => bail!("DP-102 stale authorization was consumed after authority advancement"),
    }
}

fn validate_expected(scenario: Scenario, result: &ScenarioResult) -> Result<()> {
    ensure!(
        result.baseline.allow,
        "{} baseline unexpectedly denied",
        scenario.id()
    );
    match scenario {
        Scenario::Dp000 => {
            ensure!(result.accordlock.evaluation_outcome == DecisionOutcome::Allow);
            ensure!(result.accordlock.final_effect_authorized);
            ensure!(!result.differential_observed);
        }
        Scenario::Dp101 => {
            ensure!(result.accordlock.evaluation_outcome == DecisionOutcome::Deny);
            ensure!(
                result
                    .accordlock
                    .evaluation_reasons
                    .contains(&ReasonCode::TransformOutputMismatch)
            );
            ensure!(!result.accordlock.final_effect_authorized && result.differential_observed);
        }
        Scenario::Dp102 => {
            ensure!(result.accordlock.evaluation_outcome == DecisionOutcome::Deny);
            ensure!(
                result
                    .accordlock
                    .evaluation_reasons
                    .contains(&ReasonCode::ReviewNotApproved)
            );
            ensure!(result.accordlock.consumption == StepResult::rejected("AUTHORITY_MISMATCH"));
            ensure!(!result.accordlock.final_effect_authorized && result.differential_observed);
        }
        Scenario::Dp103 => {
            ensure!(result.accordlock.evaluation_outcome == DecisionOutcome::Allow);
            ensure!(
                result.accordlock.post_admission_projection
                    == StepResult::rejected("UNAUTHORIZED_POST_ADMISSION_DELTA")
            );
            ensure!(!result.accordlock.final_effect_authorized && result.differential_observed);
        }
    }
    Ok(())
}

#[derive(Debug)]
struct FixedClock(i64);

impl TrustedClock for FixedClock {
    fn now_unix_seconds(&self) -> Result<i64, StateError> {
        Ok(self.0)
    }
}

fn authenticate_local_fixture_ingress(
    proposal: &accordlock_protocol::AgentProposal,
    authority: &mut AuthorityVector,
    now: i64,
) -> Result<AuthenticatedIngressRequest> {
    // Deterministic harness bootstrap only: this auto-activates a public test
    // key and fixed nonce behind a fresh process-local replay guard.
    let signer = SigningIdentity::from_seed("local-fixture-ingress-v1", [0x41; 32]);
    let registration = RegisteredIngressKey {
        key_id: signer.key_id().to_owned(),
        public_key: signer.public_key_bytes(),
        tenant: proposal.tenant.clone(),
        actor: proposal.actor.clone(),
        allowed_audiences: BTreeSet::from([proposal.template.audience.clone()]),
        not_before: now.saturating_sub(60),
        expires_at: now.saturating_add(120),
        status: IngressKeyStatus::Active,
    };
    authority.principal_registry.root = ActivatedIngressRegistry::compute_root(
        &proposal.template.audience,
        120,
        std::slice::from_ref(&registration),
    )?;
    let registry = ActivatedIngressRegistry::new(
        authority.principal_registry.clone(),
        proposal.template.audience.clone(),
        120,
        vec![registration],
    )?;
    let authenticator = IngressAuthenticator::new(registry, MemoryReplayGuard::default())?;
    let claims = IngressClaims {
        schema_version: INGRESS_SCHEMA_VERSION,
        audience: proposal.template.audience.clone(),
        issued_at: now.saturating_sub(1),
        expires_at: now.saturating_add(60),
        nonce: Uuid::from_u128(0x4101),
        proposal: proposal.clone(),
    };
    let wire = serde_json::to_string(&sign_ingress_request(claims, &signer)?)?;
    Ok(authenticator.authenticate_json(&wire, now)?)
}

struct Fixture {
    proposal: accordlock_protocol::AgentProposal,
    evidence: TrustedEvidenceSet,
    context: KernelContext,
    grant: CapabilityGrant,
    evaluator: SigningIdentity,
}

impl Fixture {
    // Keeping the complete signed fixture assembly together makes review of
    // every field-to-key and field-to-scope binding materially easier.
    #[allow(clippy::too_many_lines)]
    fn new(scenario: Scenario) -> Result<Self> {
        let policy = policy();

        let image_a = Digest32::sha256(b"fixture:image-a");
        let image_b = Digest32::sha256(b"fixture:image-b");
        let requested_image = if scenario == Scenario::Dp101 {
            image_b
        } else {
            image_a
        };
        let template = accordlock_protocol::DeploymentTemplate {
            operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
            environment: "prod".to_owned(),
            audience: "kubernetes.default.svc".to_owned(),
            repository: "acme/payments".to_owned(),
            commit_sha: "1111111111111111111111111111111111111111".to_owned(),
            image_repository: "registry.example/acme/payments".to_owned(),
            image_digest: requested_image,
            cluster_identity: "kind://accordlock-local".to_owned(),
            namespace: "payments-prod".to_owned(),
            deployment: "payments".to_owned(),
            deployment_uid: "11111111-2222-4333-8444-555555555555".to_owned(),
            container: "app".to_owned(),
            container_index: 0,
            prior_image_digest: Digest32::sha256(b"fixture:image-prior"),
            resource_version: "1001".to_owned(),
            prior_projection_hash: Digest32::sha256(b"fixture:prior-projection"),
            prior_transaction_annotation: Some("unset".to_owned()),
            prior_authorization_annotation: Some("unset".to_owned()),
            prior_operation_hash_annotation: Some("unset".to_owned()),
        };
        let request_id = Uuid::from_u128(0x100);
        let proposal = accordlock_protocol::AgentProposal {
            schema_version: 1,
            request_id,
            tenant: "acme".to_owned(),
            actor: "ci-workload-payments".to_owned(),
            template: template.clone(),
        };
        let grant = CapabilityGrant {
            grant_id: Uuid::from_u128(0x150),
            holder: proposal.actor.clone(),
            tenant: proposal.tenant.clone(),
            operation: template.operation.clone(),
            repository: template.repository.clone(),
            audience: template.audience.clone(),
            cluster_identity: template.cluster_identity.clone(),
            namespace: template.namespace.clone(),
            deployment_uid: template.deployment_uid.clone(),
            container: template.container.clone(),
            image_repository: template.image_repository.clone(),
            not_before: NOW - 1_000,
            expires_at: NOW + 1_000,
            maximum_uses: 4,
        };
        let evaluator = SigningIdentity::from_seed("evaluator-v1", [21; 32]);
        let mut authority = authority(&policy)?;
        authority.grant_registry.root = canonical_hash(&grant)?;
        let authorization_signer = fixture_authorization_signer();
        authority.signer.root = authorization_signer_root(
            authorization_signer.key_id(),
            authorization_signer.public_key_bytes(),
        )?;
        authority.kernel_configuration.root =
            evaluator_verifier_root(evaluator.key_id(), evaluator.public_key_bytes())?;
        if scenario == Scenario::Dp102 {
            authority = advanced_review_authority(&authority);
        }
        let ingress = authenticate_local_fixture_ingress(&proposal, &mut authority, NOW)?;

        let review_signer = SigningIdentity::from_seed("review-key-v1", [11; 32]);
        let build_signer = SigningIdentity::from_seed("build-key-v1", [12; 32]);
        let artifact_signer = SigningIdentity::from_seed("artifact-key-v1", [13; 32]);
        let target_signer = SigningIdentity::from_seed("target-key-v1", [14; 32]);
        let run_id = if scenario == Scenario::Dp101 {
            "run-b"
        } else {
            "run-a"
        };
        let mut attesters = vec![
            registered_attester(
                "github-review",
                &review_signer,
                "principal:github-review",
                AttesterScope::Review {
                    repository: template.repository.clone(),
                },
            ),
            registered_attester(
                "github-actions",
                &build_signer,
                "principal:github-actions",
                AttesterScope::Build {
                    repository: template.repository.clone(),
                    workflow_ref: ".github/workflows/release.yml@refs/heads/main".to_owned(),
                },
            ),
            registered_attester(
                "artifact-registry",
                &artifact_signer,
                "principal:artifact-registry",
                AttesterScope::Artifact {
                    image_repository: template.image_repository.clone(),
                },
            ),
            registered_attester(
                "kubernetes-target",
                &target_signer,
                "principal:kubernetes-target",
                AttesterScope::Target {
                    cluster_identity: template.cluster_identity.clone(),
                    namespace: template.namespace.clone(),
                    deployment_uid: template.deployment_uid.clone(),
                },
            ),
        ];
        attesters.sort_by(|left, right| {
            (&left.issuer, &left.key_id).cmp(&(&right.issuer, &right.key_id))
        });
        authority.registry.root = ActivatedAttesterRegistry::compute_root(&attesters)?;
        let attester_registry =
            ActivatedAttesterRegistry::new(authority.registry.clone(), attesters)?;

        let assertions = vec![
            signed_assertion(
                1,
                "github-review",
                &review_signer,
                &authority,
                request_id,
                EvidencePayload::Review {
                    repository: template.repository.clone(),
                    commit_sha: template.commit_sha.clone(),
                    approved: scenario != Scenario::Dp102,
                    review_state_id: if scenario == Scenario::Dp102 {
                        "dismissed-2"
                    } else {
                        "approved-1"
                    }
                    .to_owned(),
                },
            )?,
            signed_assertion(
                2,
                "github-actions",
                &build_signer,
                &authority,
                request_id,
                EvidencePayload::Build {
                    repository: template.repository.clone(),
                    commit_sha: template.commit_sha.clone(),
                    workflow_ref: ".github/workflows/release.yml@refs/heads/main".to_owned(),
                    run_id: "run-a".to_owned(),
                    succeeded: true,
                    input_manifest_root: Digest32::sha256(b"fixture:input-manifest"),
                    completeness_profile: CompletenessProfile::HermeticInputsV1,
                    output_digest: image_a,
                },
            )?,
            signed_assertion(
                3,
                "artifact-registry",
                &artifact_signer,
                &authority,
                request_id,
                EvidencePayload::Artifact {
                    repository: template.image_repository.clone(),
                    digest: requested_image,
                    source_run_id: run_id.to_owned(),
                    signature_valid: true,
                    quarantined: false,
                },
            )?,
            signed_assertion(
                4,
                "kubernetes-target",
                &target_signer,
                &authority,
                request_id,
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
            NOW,
            Uuid::from_u128(0x101),
            policy,
            authority,
            attester_registry,
        )?;
        Ok(Self {
            proposal,
            evidence: TrustedEvidenceSet {
                request_id,
                evidence: assertions,
            },
            context,
            grant,
            evaluator,
        })
    }
}

fn policy() -> PolicyConfig {
    PolicyConfig {
        policy_id: "local-eks-v1".to_owned(),
        allowed_actors: vec!["ci-workload-payments".to_owned()],
        allowed_repositories: vec!["acme/payments".to_owned()],
        allowed_image_repositories: vec!["registry.example/acme/payments".to_owned()],
        allowed_clusters: vec!["kind://accordlock-local".to_owned()],
        allowed_namespaces: vec!["payments-prod".to_owned()],
        minimum_review_grade: 2,
        minimum_build_grade: 2,
        maximum_evidence_age_seconds: 600,
        maximum_authorization_lifetime_seconds: 300,
    }
}

fn authority(policy: &PolicyConfig) -> Result<AuthorityVector> {
    Ok(AuthorityVector {
        policy: AuthorityDomainState {
            root: canonical_hash(policy)?,
            epoch: 1,
            activation_id: Uuid::from_u128(1),
        },
        registry: domain("registry", 2),
        revocation: domain("review-state", 3),
        connector: domain("connector", 4),
        resource: domain("resource", 5),
        signer: domain("signer", 6),
        mediation: domain("mediation", 7),
        grant_registry: domain("grant-registry", 8),
        office_act_registry: domain("office-act-registry", 9),
        principal_registry: domain("principal-registry", 10),
        workload_build_allowlist: domain("workload-build-allowlist", 11),
        kernel_configuration: domain("kernel-configuration", 12),
    })
}

fn domain(label: &str, id: u128) -> AuthorityDomainState {
    AuthorityDomainState {
        root: Digest32::sha256(format!("fixture:{label}:v1").as_bytes()),
        epoch: 1,
        activation_id: Uuid::from_u128(id),
    }
}

fn fixture_authorization_signer() -> SigningIdentity {
    SigningIdentity::from_seed("authorization-v1", [22; 32])
}

fn advanced_review_authority(current: &AuthorityVector) -> AuthorityVector {
    let mut next = current.clone();
    next.revocation = AuthorityDomainState {
        root: Digest32::sha256(b"fixture:review-state:v2-dismissed"),
        epoch: current.revocation.epoch + 1,
        activation_id: Uuid::from_u128(0x102),
    };
    next
}

fn signed_assertion(
    id: u128,
    issuer: &str,
    signer: &SigningIdentity,
    authority: &AuthorityVector,
    request_id: Uuid,
    payload: EvidencePayload,
) -> Result<SignedEvidence> {
    let assertion = EvidenceAssertion {
        schema_version: EVIDENCE_ASSERTION_SCHEMA_VERSION,
        request_id,
        evidence_id: Uuid::from_u128(id),
        issuer: issuer.to_owned(),
        key_id: signer.key_id().to_owned(),
        source_uri: format!("fixture://{issuer}/{id}"),
        observed_at: NOW - 100,
        valid_until: NOW + 500,
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
    issuer: &str,
    signer: &SigningIdentity,
    principal_id: &str,
    scope: AttesterScope,
) -> RegisteredAttester {
    RegisteredAttester {
        tenant: "acme".to_owned(),
        environment: "prod".to_owned(),
        issuer: issuer.to_owned(),
        key_id: signer.key_id().to_owned(),
        public_key: signer.public_key_bytes(),
        principal_id: principal_id.to_owned(),
        base_grade: 3,
        status: AttesterStatus::Active,
        scopes: vec![scope],
    }
}

fn deployment_object(template: &accordlock_protocol::DeploymentTemplate) -> Value {
    json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": template.deployment,
            "namespace": template.namespace,
            "uid": template.deployment_uid,
            "resourceVersion": template.resource_version,
            "generation": 1,
            "annotations": {
                "accordlock.io/transaction-id": template.prior_transaction_annotation,
                "accordlock.io/authorization-id": template.prior_authorization_annotation,
                "accordlock.io/operation-hash": template.prior_operation_hash_annotation
            }
        },
        "spec": {
            "replicas": 2,
            "template": {
                "metadata": {"labels": {"app": "payments"}},
                "spec": {
                    "serviceAccountName": "payments-runtime",
                    "containers": [{
                        "name": template.container,
                        "image": format!("{}@{}", template.image_repository, template.prior_image_digest),
                        "env": []
                    }]
                }
            }
        },
        "status": {"availableReplicas": 2}
    })
}

fn authorized_after(
    old: &Value,
    template: &accordlock_protocol::DeploymentTemplate,
    transaction_id: Uuid,
    authorization_id: Uuid,
    operation_hash: Digest32,
) -> Result<Value> {
    let mut after = old.clone();
    let image_pointer = format!(
        "/spec/template/spec/containers/{}/image",
        template.container_index
    );
    let image = after
        .pointer_mut(&image_pointer)
        .ok_or_else(|| anyhow!("fixture image pointer is missing"))?;
    *image = Value::String(format!(
        "{}@{}",
        template.image_repository, template.image_digest
    ));
    let annotations = after
        .pointer_mut("/metadata/annotations")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow!("fixture annotations are missing"))?;
    annotations.insert(
        "accordlock.io/transaction-id".to_owned(),
        Value::String(transaction_id.to_string()),
    );
    annotations.insert(
        "accordlock.io/authorization-id".to_owned(),
        Value::String(authorization_id.to_string()),
    );
    annotations.insert(
        "accordlock.io/operation-hash".to_owned(),
        Value::String(operation_hash.to_string()),
    );
    after["metadata"]["resourceVersion"] = Value::String("persisted-next-version".to_owned());
    after["metadata"]["generation"] = json!(2);
    Ok(after)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_scenarios_have_the_expected_differential() -> Result<()> {
        let report = run_selection("all")?;
        assert!(!report.production_ready);
        assert_eq!(
            report.execution_profile.determinism,
            "FIXED_FIXTURES_AND_OUTPUT"
        );
        assert_eq!(report.execution_profile.network_access, "NOT_ACCESSED");
        assert_eq!(
            report.execution_profile.credential_source,
            "PUBLIC_HARD_CODED_TEST_KEYS_ONLY"
        );
        assert_eq!(report.coverage.live_gates.len(), 3);
        assert!(
            report
                .coverage
                .live_gates
                .iter()
                .all(|gate| !gate.satisfied)
        );
        assert_eq!(report.scenarios.len(), 4);
        assert!(!report.scenarios[0].differential_observed);
        assert!(
            report.scenarios[1..]
                .iter()
                .all(|result| result.differential_observed)
        );
        Ok(())
    }

    #[test]
    fn happy_path_reaches_a_validated_effect() -> Result<()> {
        let report = run_selection("DP-000")?;
        let result = report
            .scenarios
            .first()
            .ok_or_else(|| anyhow!("missing result"))?;
        assert_eq!(result.accordlock.evaluation_outcome, DecisionOutcome::Allow);
        assert_eq!(result.accordlock.consumption.status, StepStatus::Accepted);
        assert_eq!(
            result.accordlock.replay_attempt,
            StepResult::rejected("ALREADY_CONSUMED")
        );
        assert_eq!(
            result.accordlock.post_admission_projection.status,
            StepStatus::Accepted
        );
        assert!(result.accordlock.final_effect_authorized);
        assert_eq!(
            result.accordlock.dispatch_deadline,
            Some(CONSUMPTION_TIME + 30)
        );
        Ok(())
    }

    #[test]
    fn artifact_swap_is_rejected_on_lineage() -> Result<()> {
        let report = run_selection("dp101")?;
        let result = report
            .scenarios
            .first()
            .ok_or_else(|| anyhow!("missing result"))?;
        assert!(result.baseline.allow);
        assert!(
            result
                .accordlock
                .evaluation_reasons
                .contains(&ReasonCode::TransformOutputMismatch)
        );
        assert!(!result.accordlock.final_effect_authorized);
        Ok(())
    }

    #[test]
    fn dismissed_review_invalidates_current_evaluation_and_old_authorization() -> Result<()> {
        let report = run_selection("DP-102")?;
        let result = report
            .scenarios
            .first()
            .ok_or_else(|| anyhow!("missing result"))?;
        assert!(
            result
                .accordlock
                .evaluation_reasons
                .contains(&ReasonCode::ReviewNotApproved)
        );
        assert_eq!(
            result.accordlock.consumption,
            StepResult::rejected("AUTHORITY_MISMATCH")
        );
        Ok(())
    }

    #[test]
    fn admission_expansion_is_rejected_after_consumption() -> Result<()> {
        let report = run_selection("DP-103")?;
        let result = report
            .scenarios
            .first()
            .ok_or_else(|| anyhow!("missing result"))?;
        assert_eq!(result.accordlock.evaluation_outcome, DecisionOutcome::Allow);
        assert_eq!(result.accordlock.consumption.status, StepStatus::Accepted);
        assert_eq!(
            result.accordlock.post_admission_projection,
            StepResult::rejected("UNAUTHORIZED_POST_ADMISSION_DELTA")
        );
        Ok(())
    }

    #[test]
    fn serialized_report_is_deterministic() -> Result<()> {
        let first = serde_json::to_string(&run_selection("all")?)?;
        let second = serde_json::to_string(&run_selection("all")?)?;
        assert_eq!(first, second);
        Ok(())
    }

    #[test]
    fn offline_coverage_never_claims_live_dispatch() -> Result<()> {
        let report = run_selection("all")?;
        for phase in [
            "DISPATCH_ACQUISITION_V14",
            "EKS_CREDENTIAL_BROKER",
            "NATIVE_EKS_EXECUTOR_AND_PROVIDER_EFFECT",
            "CREDENTIAL_RETIREMENT",
        ] {
            let coverage = report
                .coverage
                .phases
                .iter()
                .find(|candidate| candidate.phase == phase)
                .ok_or_else(|| anyhow!("missing phase {phase}"))?;
            assert_eq!(coverage.status, CoverageStatus::NotExercised);
            assert!(coverage.exercised_by.is_empty());
        }
        Ok(())
    }

    #[test]
    fn unknown_scenario_fails_closed() {
        assert!(run_selection("DP-999").is_err());
    }
}
