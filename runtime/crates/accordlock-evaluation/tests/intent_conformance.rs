use accordlock_evaluation::{
    CalibrationStatus, CanonicalEncode, Digest32, EVIDENCE_LEDGER_SNAPSHOT_SCHEMA_VERSION,
    EVIDENCE_TRUST_POLICY_SCHEMA_VERSION, EnforcementDecision, EvidenceLedgerExpectation,
    EvidenceLedgerSnapshot, EvidenceMethodKind, EvidenceTrustPolicy, EvidenceVerdict,
    INTENT_EVIDENCE_SCHEMA_VERSION, INTENT_TRACE_SCHEMA_VERSION, IntentConformanceEvaluation,
    IntentConformanceEvaluator, IntentConformanceOutcome, IntentConformanceRecord,
    IntentEvaluationCheckpoint, IntentEvaluationContext, IntentEvaluationProfile, IntentEvidence,
    IntentFindingReason, IntentStage, IntentTrace, NormalizedScore,
    PRE_EXECUTION_INTENT_TRACE_SCHEMA_VERSION, PolicyEvaluationError, PreExecutionIntentTrace,
    ScoreInterval, TASK_REQUIREMENT_SCHEMA_VERSION, TRANSFORMATION_STEP_SCHEMA_VERSION,
    TaskRequirement, TransformationStep, WorkflowStage,
};
use uuid::Uuid;

fn uuid(value: u128) -> Uuid {
    Uuid::from_u128(value)
}

fn digest(value: u8) -> Digest32 {
    Digest32::from_bytes([value; 32])
}

fn confidence(
    lower: u32,
    estimate: u32,
    upper: u32,
) -> Result<ScoreInterval, PolicyEvaluationError> {
    ScoreInterval::new(
        NormalizedScore::new(lower)?,
        NormalizedScore::new(estimate)?,
        NormalizedScore::new(upper)?,
    )
}

fn requirement() -> Result<TaskRequirement, PolicyEvaluationError> {
    Ok(TaskRequirement {
        schema_version: TASK_REQUIREMENT_SCHEMA_VERSION,
        requirement_id: uuid(1),
        task_hash: digest(1),
        statement_hash: digest(2),
        minimum_score: NormalizedScore::new(900_000)?,
    })
}

fn steps() -> Result<Vec<TransformationStep>, PolicyEvaluationError> {
    let plan = TransformationStep {
        schema_version: TRANSFORMATION_STEP_SCHEMA_VERSION,
        step_id: uuid(10),
        task_hash: digest(1),
        sequence: 0,
        parent_step_hash: None,
        source_stage: WorkflowStage::Request,
        source_hash: digest(10),
        target_stage: WorkflowStage::Plan,
        target_hash: digest(11),
        recorded_at: 1_000,
    };
    let action = TransformationStep {
        schema_version: TRANSFORMATION_STEP_SCHEMA_VERSION,
        step_id: uuid(11),
        task_hash: digest(1),
        sequence: 1,
        parent_step_hash: Some(plan.digest()?),
        source_stage: WorkflowStage::Plan,
        source_hash: digest(11),
        target_stage: WorkflowStage::Action,
        target_hash: digest(12),
        recorded_at: 1_100,
    };
    let result = TransformationStep {
        schema_version: TRANSFORMATION_STEP_SCHEMA_VERSION,
        step_id: uuid(12),
        task_hash: digest(1),
        sequence: 2,
        parent_step_hash: Some(action.digest()?),
        source_stage: WorkflowStage::Action,
        source_hash: digest(12),
        target_stage: WorkflowStage::Result,
        target_hash: digest(13),
        recorded_at: 1_200,
    };
    Ok(vec![plan, action, result])
}

fn trace(
    requirement: &TaskRequirement,
    steps: &[TransformationStep],
) -> Result<IntentTrace, PolicyEvaluationError> {
    let mut requirement_hashes = vec![requirement.digest()?];
    requirement_hashes.sort_unstable();
    let mut step_hashes = Vec::with_capacity(steps.len());
    for step in steps {
        step_hashes.push(step.digest()?);
    }
    Ok(IntentTrace {
        schema_version: INTENT_TRACE_SCHEMA_VERSION,
        trace_id: uuid(20),
        task_hash: digest(1),
        requirement_hashes,
        request_hash: digest(10),
        plan_hash: digest(11),
        action_hash: digest(12),
        result_hash: digest(13),
        transformation_step_hashes: step_hashes,
        recorded_at: 1_300,
    })
}

struct EvidenceProfile {
    method_kind: EvidenceMethodKind,
    calibration_status: CalibrationStatus,
    calibration_hash: Option<Digest32>,
    confidence: ScoreInterval,
}

fn evidence_item(
    requirement: &TaskRequirement,
    trace: &IntentTrace,
    steps: &[TransformationStep],
    stage: IntentStage,
    verdict: EvidenceVerdict,
    profile: &EvidenceProfile,
    parent: Option<&IntentEvidence>,
) -> Result<IntentEvidence, PolicyEvaluationError> {
    let (sequence, parent_evidence_hash) = match parent {
        Some(previous) => (previous.sequence + 1, Some(previous.digest()?)),
        None => (0, None),
    };
    let transformation_step_hash = if stage == IntentStage::Request {
        None
    } else {
        let step = steps
            .iter()
            .find(|candidate| candidate.target_stage == stage.workflow_stage())
            .ok_or(PolicyEvaluationError::BindingMismatch("test stage"))?;
        Some(step.digest()?)
    };
    Ok(IntentEvidence {
        schema_version: INTENT_EVIDENCE_SCHEMA_VERSION,
        evidence_id: uuid(100 + u128::from(sequence)),
        task_hash: trace.task_hash,
        trace_id: trace.trace_id,
        ledger_hash: digest(70),
        sequence,
        parent_evidence_hash,
        requirement_hash: requirement.digest()?,
        stage,
        subject_hash: trace.subject_hash(stage),
        transformation_step_hash,
        verdict,
        confidence: profile.confidence,
        method_kind: profile.method_kind,
        method_hash: digest(30),
        evaluator_hash: digest(31),
        calibration_status: profile.calibration_status,
        calibration_hash: profile.calibration_hash,
        payload_hash: digest(40 + u8::try_from(sequence).unwrap_or(u8::MAX)),
        observed_at: 1_400 + i64::try_from(sequence).unwrap_or(i64::MAX),
    })
}

fn evidence_chain(
    requirement: &TaskRequirement,
    trace: &IntentTrace,
    steps: &[TransformationStep],
    profile: &EvidenceProfile,
    contradictory_stage: Option<IntentStage>,
) -> Result<Vec<IntentEvidence>, PolicyEvaluationError> {
    let mut chain = Vec::new();
    for stage in IntentStage::ALL {
        let verdict = if contradictory_stage == Some(stage) {
            EvidenceVerdict::Contradicts
        } else {
            EvidenceVerdict::Supports
        };
        let item = evidence_item(
            requirement,
            trace,
            steps,
            stage,
            verdict,
            profile,
            chain.last(),
        )?;
        chain.push(item);
    }
    Ok(chain)
}

fn deterministic_profile() -> Result<EvidenceProfile, PolicyEvaluationError> {
    Ok(EvidenceProfile {
        method_kind: EvidenceMethodKind::DeterministicCheck,
        calibration_status: CalibrationStatus::NotApplicable,
        calibration_hash: None,
        confidence: confidence(950_000, 975_000, 1_000_000)?,
    })
}

fn head(evidence: &[IntentEvidence]) -> Result<Option<Digest32>, PolicyEvaluationError> {
    evidence.last().map(IntentEvidence::digest).transpose()
}

struct TestEvaluationContext {
    snapshot: EvidenceLedgerSnapshot,
    trust_policy: EvidenceTrustPolicy,
    expectation: EvidenceLedgerExpectation,
}

impl TestEvaluationContext {
    fn as_context(&self) -> IntentEvaluationContext<'_> {
        IntentEvaluationContext {
            ledger_snapshot: &self.snapshot,
            ledger_expectation: self.expectation,
            trust_policy: &self.trust_policy,
            minimum_trust_policy_epoch: 7,
        }
    }
}

fn evaluation_context(
    trace: &IntentTrace,
    evidence: &[IntentEvidence],
) -> Result<TestEvaluationContext, PolicyEvaluationError> {
    let mut trusted_provenance_hashes = Vec::new();
    for item in evidence {
        trusted_provenance_hashes.push(item.provenance_digest()?);
    }
    trusted_provenance_hashes.sort_unstable();
    trusted_provenance_hashes.dedup();
    let evidence_count = u64::try_from(evidence.len())
        .map_err(|_| PolicyEvaluationError::ArithmeticOverflow("test evidence count"))?;
    Ok(TestEvaluationContext {
        snapshot: EvidenceLedgerSnapshot {
            schema_version: EVIDENCE_LEDGER_SNAPSHOT_SCHEMA_VERSION,
            snapshot_id: uuid(500),
            ledger_hash: digest(70),
            task_hash: trace.task_hash,
            trace_id: trace.trace_id,
            epoch: 7,
            evidence_count,
            evidence_head: head(evidence)?,
            captured_at: 1_500,
            valid_until: 5_000,
        },
        trust_policy: EvidenceTrustPolicy {
            schema_version: EVIDENCE_TRUST_POLICY_SCHEMA_VERSION,
            policy_id: uuid(501),
            task_hash: trace.task_hash,
            policy_epoch: 7,
            trusted_provenance_hashes,
            valid_from: 1_300,
            valid_until: 5_000,
        },
        expectation: EvidenceLedgerExpectation {
            ledger_hash: digest(70),
            minimum_epoch: 7,
            evaluated_at: 1_600,
        },
    })
}

fn assess(
    baseline: EnforcementDecision,
    trace: &IntentTrace,
    requirement: &TaskRequirement,
    steps: &[TransformationStep],
    evidence: &[IntentEvidence],
) -> Result<IntentConformanceEvaluation, PolicyEvaluationError> {
    let context = evaluation_context(trace, evidence)?;
    IntentConformanceEvaluator::evaluate(
        baseline,
        trace,
        core::slice::from_ref(requirement),
        steps,
        evidence,
        context.as_context(),
    )
}

#[test]
fn pre_execution_rpa_is_complete_without_inventing_a_result_and_is_not_replayable()
-> Result<(), Box<dyn std::error::Error>> {
    let requirement = requirement()?;
    let all_steps = steps()?;
    let full_trace = trace(&requirement, &all_steps)?;
    let checkpoint_steps = &all_steps[..2];
    let checkpoint = PreExecutionIntentTrace {
        schema_version: PRE_EXECUTION_INTENT_TRACE_SCHEMA_VERSION,
        trace_id: full_trace.trace_id,
        task_hash: full_trace.task_hash,
        requirement_hashes: full_trace.requirement_hashes.clone(),
        request_hash: full_trace.request_hash,
        plan_hash: full_trace.plan_hash,
        action_hash: full_trace.action_hash,
        transformation_step_hashes: full_trace.transformation_step_hashes[..2].to_vec(),
        recorded_at: 1_100,
    };
    checkpoint.verify_bindings(core::slice::from_ref(&requirement), checkpoint_steps)?;
    assert!(checkpoint.subject_hash(IntentStage::Result).is_err());

    let all_evidence = evidence_chain(
        &requirement,
        &full_trace,
        &all_steps,
        &deterministic_profile()?,
        None,
    )?;
    let rpa_evidence = &all_evidence[..3];
    let context = evaluation_context(&full_trace, rpa_evidence)?;
    let pre = IntentConformanceEvaluator::evaluate_pre_execution(
        EnforcementDecision::Allow,
        &checkpoint,
        core::slice::from_ref(&requirement),
        checkpoint_steps,
        rpa_evidence,
        context.as_context(),
    )?;
    assert_eq!(pre.profile(), IntentEvaluationProfile::PreExecution);
    assert_eq!(pre.outcome(), IntentConformanceOutcome::Supported);

    let complete = IntentConformanceEvaluator::evaluate(
        EnforcementDecision::Allow,
        &full_trace,
        core::slice::from_ref(&requirement),
        &all_steps,
        rpa_evidence,
        context.as_context(),
    )?;
    assert_eq!(complete.profile(), IntentEvaluationProfile::CompleteTrace);
    assert_eq!(complete.outcome(), IntentConformanceOutcome::Uncertain);
    assert_eq!(
        complete.policy_evaluation().decision(),
        EnforcementDecision::RequireApproval
    );

    let record = IntentConformanceRecord::from_evaluation(&pre)?;
    record.verify_evaluation_for(
        EnforcementDecision::Allow,
        IntentEvaluationCheckpoint::PreExecution(&checkpoint),
        core::slice::from_ref(&requirement),
        checkpoint_steps,
        rpa_evidence,
        context.as_context(),
    )?;
    assert!(
        record
            .verify_bindings_for(
                IntentEvaluationCheckpoint::CompleteTrace(&full_trace),
                context.as_context(),
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn exact_trace_rejects_skipped_or_substituted_checkpoints() -> Result<(), Box<dyn std::error::Error>>
{
    let requirement = requirement()?;
    let steps = steps()?;
    let trace = trace(&requirement, &steps)?;
    trace.verify_bindings(core::slice::from_ref(&requirement), &steps)?;

    let mut substituted = trace.clone();
    substituted.plan_hash = digest(99);
    assert!(matches!(
        substituted.verify_bindings(core::slice::from_ref(&requirement), &steps),
        Err(PolicyEvaluationError::ChainMismatch(
            "intent trace checkpoint"
        ))
    ));

    let skipped = vec![steps[0].clone(), steps[2].clone()];
    assert!(
        trace
            .verify_bindings(core::slice::from_ref(&requirement), &skipped)
            .is_err()
    );
    Ok(())
}

#[test]
fn complete_deterministic_evidence_preserves_but_never_creates_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let requirement = requirement()?;
    let steps = steps()?;
    let trace = trace(&requirement, &steps)?;
    let evidence = evidence_chain(
        &requirement,
        &trace,
        &steps,
        &deterministic_profile()?,
        None,
    )?;

    let assessment = assess(
        EnforcementDecision::RequireApproval,
        &trace,
        &requirement,
        &steps,
        &evidence,
    )?;
    assert_eq!(assessment.outcome(), IntentConformanceOutcome::Supported);
    assert_eq!(
        assessment.policy_evaluation().decision(),
        EnforcementDecision::RequireApproval
    );

    let blocked = assess(
        EnforcementDecision::Deny,
        &trace,
        &requirement,
        &steps,
        &evidence,
    )?;
    assert_eq!(
        blocked.policy_evaluation().decision(),
        EnforcementDecision::Deny
    );
    Ok(())
}

#[test]
fn uncalibrated_model_scores_remain_uncertain_even_when_maximal()
-> Result<(), Box<dyn std::error::Error>> {
    let requirement = requirement()?;
    let steps = steps()?;
    let trace = trace(&requirement, &steps)?;
    let profile = EvidenceProfile {
        method_kind: EvidenceMethodKind::LanguageModel,
        calibration_status: CalibrationStatus::Unverified,
        calibration_hash: None,
        confidence: confidence(1_000_000, 1_000_000, 1_000_000)?,
    };
    let evidence = evidence_chain(&requirement, &trace, &steps, &profile, None)?;
    let assessment = assess(
        EnforcementDecision::Allow,
        &trace,
        &requirement,
        &steps,
        &evidence,
    )?;

    assert_eq!(assessment.outcome(), IntentConformanceOutcome::Uncertain);
    assert_eq!(
        assessment.policy_evaluation().decision(),
        EnforcementDecision::RequireApproval
    );
    assert!(
        assessment
            .findings()
            .iter()
            .all(|finding| finding.reason == IntentFindingReason::UnverifiedProvenance)
    );
    Ok(())
}

#[test]
fn one_contradiction_dominates_all_favorable_scores() -> Result<(), Box<dyn std::error::Error>> {
    let requirement = requirement()?;
    let steps = steps()?;
    let trace = trace(&requirement, &steps)?;
    let evidence = evidence_chain(
        &requirement,
        &trace,
        &steps,
        &deterministic_profile()?,
        Some(IntentStage::Action),
    )?;
    let assessment = assess(
        EnforcementDecision::Allow,
        &trace,
        &requirement,
        &steps,
        &evidence,
    )?;

    assert_eq!(
        assessment.outcome(),
        IntentConformanceOutcome::Nonconformant
    );
    assert_eq!(
        assessment.policy_evaluation().decision(),
        EnforcementDecision::Deny
    );
    assert!(assessment.findings().iter().any(|finding| {
        finding.stage == Some(IntentStage::Action)
            && finding.reason == IntentFindingReason::ContradictoryEvidence
    }));
    Ok(())
}

#[test]
fn authoritative_head_detects_omission_and_reordering() -> Result<(), Box<dyn std::error::Error>> {
    let requirement = requirement()?;
    let steps = steps()?;
    let trace = trace(&requirement, &steps)?;
    let evidence = evidence_chain(
        &requirement,
        &trace,
        &steps,
        &deterministic_profile()?,
        None,
    )?;
    let authoritative_context = evaluation_context(&trace, &evidence)?;

    let omitted = IntentConformanceEvaluator::evaluate(
        EnforcementDecision::Allow,
        &trace,
        core::slice::from_ref(&requirement),
        &steps,
        &evidence[..evidence.len() - 1],
        authoritative_context.as_context(),
    )?;
    assert_eq!(omitted.outcome(), IntentConformanceOutcome::InvalidEvidence);
    assert_eq!(
        omitted.policy_evaluation().decision(),
        EnforcementDecision::Deny
    );
    assert_eq!(
        omitted.findings()[0].reason,
        IntentFindingReason::LedgerSnapshotMismatch
    );

    let mut reordered = evidence.clone();
    reordered.swap(1, 2);
    let reordered_assessment = IntentConformanceEvaluator::evaluate(
        EnforcementDecision::Allow,
        &trace,
        core::slice::from_ref(&requirement),
        &steps,
        &reordered,
        authoritative_context.as_context(),
    )?;
    assert_eq!(
        reordered_assessment.outcome(),
        IntentConformanceOutcome::InvalidEvidence
    );
    assert_eq!(
        reordered_assessment.findings()[0].reason,
        IntentFindingReason::EvidenceChainMismatch
    );
    Ok(())
}

#[test]
fn stage_replay_and_artifact_substitution_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let requirement = requirement()?;
    let steps = steps()?;
    let trace = trace(&requirement, &steps)?;
    let profile = deterministic_profile()?;
    let request = evidence_item(
        &requirement,
        &trace,
        &steps,
        IntentStage::Request,
        EvidenceVerdict::Supports,
        &profile,
        None,
    )?;
    let mut replayed = evidence_item(
        &requirement,
        &trace,
        &steps,
        IntentStage::Plan,
        EvidenceVerdict::Supports,
        &profile,
        Some(&request),
    )?;
    replayed.subject_hash = trace.action_hash;
    let chain = vec![request, replayed];
    let assessment = assess(
        EnforcementDecision::Allow,
        &trace,
        &requirement,
        &steps,
        &chain,
    )?;

    assert_eq!(
        assessment.outcome(),
        IntentConformanceOutcome::InvalidEvidence
    );
    assert_eq!(
        assessment.policy_evaluation().decision(),
        EnforcementDecision::Deny
    );
    Ok(())
}

#[test]
fn missing_stage_and_expired_calibration_require_review() -> Result<(), Box<dyn std::error::Error>>
{
    let requirement = requirement()?;
    let steps = steps()?;
    let trace = trace(&requirement, &steps)?;
    let evidence = evidence_chain(
        &requirement,
        &trace,
        &steps,
        &deterministic_profile()?,
        None,
    )?;
    let incomplete = &evidence[..evidence.len() - 1];
    let missing = assess(
        EnforcementDecision::Allow,
        &trace,
        &requirement,
        &steps,
        incomplete,
    )?;
    assert_eq!(missing.outcome(), IntentConformanceOutcome::Uncertain);
    assert_eq!(
        missing.policy_evaluation().decision(),
        EnforcementDecision::RequireApproval
    );
    assert!(missing.findings().iter().any(|finding| {
        finding.stage == Some(IntentStage::Result)
            && finding.reason == IntentFindingReason::MissingEvidence
    }));

    let expired_profile = EvidenceProfile {
        method_kind: EvidenceMethodKind::StatisticalModel,
        calibration_status: CalibrationStatus::Expired,
        calibration_hash: Some(digest(90)),
        confidence: confidence(950_000, 975_000, 1_000_000)?,
    };
    let expired = evidence_chain(&requirement, &trace, &steps, &expired_profile, None)?;
    let expired_assessment = assess(
        EnforcementDecision::Allow,
        &trace,
        &requirement,
        &steps,
        &expired,
    )?;
    assert_eq!(
        expired_assessment.outcome(),
        IntentConformanceOutcome::Uncertain
    );
    Ok(())
}

#[test]
fn canonical_evidence_commitment_covers_provenance_and_calibration()
-> Result<(), Box<dyn std::error::Error>> {
    let requirement = requirement()?;
    let steps = steps()?;
    let trace = trace(&requirement, &steps)?;
    let profile = EvidenceProfile {
        method_kind: EvidenceMethodKind::LanguageModel,
        calibration_status: CalibrationStatus::Verified,
        calibration_hash: Some(digest(90)),
        confidence: confidence(950_000, 975_000, 1_000_000)?,
    };
    let evidence = evidence_item(
        &requirement,
        &trace,
        &steps,
        IntentStage::Plan,
        EvidenceVerdict::Supports,
        &profile,
        None,
    )?;
    let original_digest = evidence.digest()?;
    let original_bytes = evidence.canonical_bytes()?;

    let mut substituted_evaluator = evidence.clone();
    substituted_evaluator.evaluator_hash = digest(91);
    assert_ne!(substituted_evaluator.digest()?, original_digest);

    let mut substituted_calibration = evidence.clone();
    substituted_calibration.calibration_hash = Some(digest(92));
    assert_ne!(substituted_calibration.digest()?, original_digest);

    let mut substituted_payload = evidence.clone();
    substituted_payload.payload_hash = digest(93);
    assert_ne!(substituted_payload.canonical_bytes()?, original_bytes);

    let mut missing_calibration = evidence;
    missing_calibration.calibration_hash = None;
    assert!(matches!(
        missing_calibration.validate(),
        Err(PolicyEvaluationError::InvalidEvidenceProvenance)
    ));
    Ok(())
}

#[test]
fn aggregate_decision_is_monotone_for_every_baseline() -> Result<(), Box<dyn std::error::Error>> {
    let requirement = requirement()?;
    let steps = steps()?;
    let trace = trace(&requirement, &steps)?;
    let evidence = evidence_chain(
        &requirement,
        &trace,
        &steps,
        &deterministic_profile()?,
        Some(IntentStage::Result),
    )?;

    for baseline in [
        EnforcementDecision::Allow,
        EnforcementDecision::RequireApproval,
        EnforcementDecision::Deny,
    ] {
        let assessment = assess(baseline, &trace, &requirement, &steps, &evidence)?;
        assert!(assessment.policy_evaluation().decision() >= baseline);
    }
    Ok(())
}

#[test]
fn evidence_cannot_replay_across_trace_identity() -> Result<(), Box<dyn std::error::Error>> {
    let requirement = requirement()?;
    let steps = steps()?;
    let original_trace = trace(&requirement, &steps)?;
    let evidence = evidence_chain(
        &requirement,
        &original_trace,
        &steps,
        &deterministic_profile()?,
        None,
    )?;

    let mut other_trace = original_trace;
    other_trace.trace_id = uuid(999);
    other_trace.verify_bindings(core::slice::from_ref(&requirement), &steps)?;
    let context = evaluation_context(&other_trace, &evidence)?;
    let replay = IntentConformanceEvaluator::evaluate(
        EnforcementDecision::Allow,
        &other_trace,
        core::slice::from_ref(&requirement),
        &steps,
        &evidence,
        context.as_context(),
    )?;

    assert_eq!(replay.outcome(), IntentConformanceOutcome::InvalidEvidence);
    assert_eq!(
        replay.policy_evaluation().decision(),
        EnforcementDecision::Deny
    );
    Ok(())
}

#[test]
fn stale_or_rollback_ledger_snapshot_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let requirement = requirement()?;
    let steps = steps()?;
    let trace = trace(&requirement, &steps)?;
    let evidence = evidence_chain(
        &requirement,
        &trace,
        &steps,
        &deterministic_profile()?,
        None,
    )?;

    let mut rollback = evaluation_context(&trace, &evidence)?;
    rollback.expectation.minimum_epoch = rollback.snapshot.epoch + 1;
    let rollback_assessment = IntentConformanceEvaluator::evaluate(
        EnforcementDecision::Allow,
        &trace,
        core::slice::from_ref(&requirement),
        &steps,
        &evidence,
        rollback.as_context(),
    )?;
    assert_eq!(
        rollback_assessment.outcome(),
        IntentConformanceOutcome::InvalidEvidence
    );

    let mut stale = evaluation_context(&trace, &evidence)?;
    stale.snapshot.valid_until = stale.expectation.evaluated_at - 1;
    let stale_assessment = IntentConformanceEvaluator::evaluate(
        EnforcementDecision::Allow,
        &trace,
        core::slice::from_ref(&requirement),
        &steps,
        &evidence,
        stale.as_context(),
    )?;
    assert_eq!(
        stale_assessment.policy_evaluation().decision(),
        EnforcementDecision::Deny
    );
    Ok(())
}

#[test]
fn self_declared_deterministic_method_is_not_trusted_without_policy_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let requirement = requirement()?;
    let steps = steps()?;
    let trace = trace(&requirement, &steps)?;
    let evidence = evidence_chain(
        &requirement,
        &trace,
        &steps,
        &deterministic_profile()?,
        None,
    )?;
    let mut context = evaluation_context(&trace, &evidence)?;
    context.trust_policy.trusted_provenance_hashes.clear();

    let assessment = IntentConformanceEvaluator::evaluate(
        EnforcementDecision::Allow,
        &trace,
        core::slice::from_ref(&requirement),
        &steps,
        &evidence,
        context.as_context(),
    )?;
    assert_eq!(assessment.outcome(), IntentConformanceOutcome::Uncertain);
    assert_eq!(
        assessment.policy_evaluation().decision(),
        EnforcementDecision::RequireApproval
    );
    assert!(
        assessment
            .findings()
            .iter()
            .all(|finding| finding.reason == IntentFindingReason::UnverifiedProvenance)
    );
    Ok(())
}

#[test]
fn authoritative_empty_snapshot_is_review_required_not_invalid()
-> Result<(), Box<dyn std::error::Error>> {
    let requirement = requirement()?;
    let steps = steps()?;
    let trace = trace(&requirement, &steps)?;
    let assessment = assess(
        EnforcementDecision::Allow,
        &trace,
        &requirement,
        &steps,
        &[],
    )?;

    assert_eq!(assessment.outcome(), IntentConformanceOutcome::Uncertain);
    assert_eq!(
        assessment.policy_evaluation().decision(),
        EnforcementDecision::RequireApproval
    );
    assert_eq!(assessment.findings().len(), IntentStage::ALL.len());
    Ok(())
}

#[test]
fn canonical_summary_binds_snapshot_epoch_and_policy() -> Result<(), Box<dyn std::error::Error>> {
    let requirement = requirement()?;
    let steps = steps()?;
    let trace = trace(&requirement, &steps)?;
    let evidence = evidence_chain(
        &requirement,
        &trace,
        &steps,
        &deterministic_profile()?,
        None,
    )?;
    let first_context = evaluation_context(&trace, &evidence)?;
    let first = IntentConformanceEvaluator::evaluate(
        EnforcementDecision::Allow,
        &trace,
        core::slice::from_ref(&requirement),
        &steps,
        &evidence,
        first_context.as_context(),
    )?;
    let first_digest = first.digest()?;

    let mut newer_context = evaluation_context(&trace, &evidence)?;
    newer_context.snapshot.snapshot_id = uuid(777);
    newer_context.snapshot.epoch += 1;
    newer_context.expectation.minimum_epoch = newer_context.snapshot.epoch;
    let newer = IntentConformanceEvaluator::evaluate(
        EnforcementDecision::Allow,
        &trace,
        core::slice::from_ref(&requirement),
        &steps,
        &evidence,
        newer_context.as_context(),
    )?;
    assert_ne!(newer.digest()?, first_digest);
    assert_ne!(newer.ledger_snapshot_hash(), first.ledger_snapshot_hash());
    Ok(())
}

#[test]
fn non_model_evidence_classes_qualify_with_not_applicable_calibration()
-> Result<(), Box<dyn std::error::Error>> {
    let requirement = requirement()?;
    let steps = steps()?;
    let trace = trace(&requirement, &steps)?;

    for method_kind in [
        EvidenceMethodKind::DeterministicCheck,
        EvidenceMethodKind::HumanReview,
        EvidenceMethodKind::ExternalAttestation,
    ] {
        let profile = EvidenceProfile {
            method_kind,
            calibration_status: CalibrationStatus::NotApplicable,
            calibration_hash: None,
            confidence: confidence(950_000, 975_000, 1_000_000)?,
        };
        let evidence = evidence_chain(&requirement, &trace, &steps, &profile, None)?;
        let assessment = assess(
            EnforcementDecision::Allow,
            &trace,
            &requirement,
            &steps,
            &evidence,
        )?;
        assert_eq!(assessment.outcome(), IntentConformanceOutcome::Supported);
        assert_eq!(
            assessment.policy_evaluation().decision(),
            EnforcementDecision::Allow
        );
        assert!(
            assessment
                .findings()
                .iter()
                .all(|finding| finding.reason == IntentFindingReason::Supported)
        );

        let invalid_profile = EvidenceProfile {
            method_kind,
            calibration_status: CalibrationStatus::Verified,
            calibration_hash: Some(digest(90)),
            confidence: profile.confidence,
        };
        let invalid = evidence_item(
            &requirement,
            &trace,
            &steps,
            IntentStage::Request,
            EvidenceVerdict::Supports,
            &invalid_profile,
            None,
        )?;
        assert_eq!(
            invalid.validate(),
            Err(PolicyEvaluationError::InvalidEvidenceProvenance)
        );
    }
    Ok(())
}

#[test]
fn model_evidence_classes_require_verified_calibration_and_hash()
-> Result<(), Box<dyn std::error::Error>> {
    let requirement = requirement()?;
    let steps = steps()?;
    let trace = trace(&requirement, &steps)?;

    for method_kind in [
        EvidenceMethodKind::StatisticalModel,
        EvidenceMethodKind::LanguageModel,
    ] {
        let verified_profile = EvidenceProfile {
            method_kind,
            calibration_status: CalibrationStatus::Verified,
            calibration_hash: Some(digest(90)),
            confidence: confidence(950_000, 975_000, 1_000_000)?,
        };
        let verified = evidence_chain(&requirement, &trace, &steps, &verified_profile, None)?;
        let accepted = assess(
            EnforcementDecision::Allow,
            &trace,
            &requirement,
            &steps,
            &verified,
        )?;
        assert_eq!(accepted.outcome(), IntentConformanceOutcome::Supported);
        assert_eq!(
            accepted.policy_evaluation().decision(),
            EnforcementDecision::Allow
        );

        let unverified_profile = EvidenceProfile {
            method_kind,
            calibration_status: CalibrationStatus::Unverified,
            calibration_hash: None,
            confidence: verified_profile.confidence,
        };
        let unverified = evidence_chain(&requirement, &trace, &steps, &unverified_profile, None)?;
        let review = assess(
            EnforcementDecision::Allow,
            &trace,
            &requirement,
            &steps,
            &unverified,
        )?;
        assert_eq!(review.outcome(), IntentConformanceOutcome::Uncertain);
        assert_eq!(
            review.policy_evaluation().decision(),
            EnforcementDecision::RequireApproval
        );

        for invalid_profile in [
            EvidenceProfile {
                method_kind,
                calibration_status: CalibrationStatus::NotApplicable,
                calibration_hash: None,
                confidence: verified_profile.confidence,
            },
            EvidenceProfile {
                method_kind,
                calibration_status: CalibrationStatus::Verified,
                calibration_hash: None,
                confidence: verified_profile.confidence,
            },
        ] {
            let invalid = evidence_item(
                &requirement,
                &trace,
                &steps,
                IntentStage::Request,
                EvidenceVerdict::Supports,
                &invalid_profile,
                None,
            )?;
            assert_eq!(
                invalid.validate(),
                Err(PolicyEvaluationError::InvalidEvidenceProvenance)
            );
        }
    }
    Ok(())
}

#[test]
fn untrusted_semantic_evidence_requires_review_symmetrically()
-> Result<(), Box<dyn std::error::Error>> {
    let requirement = requirement()?;
    let steps = steps()?;
    let trace = trace(&requirement, &steps)?;

    let contradictory = evidence_chain(
        &requirement,
        &trace,
        &steps,
        &deterministic_profile()?,
        Some(IntentStage::Action),
    )?;
    let mut contradiction_context = evaluation_context(&trace, &contradictory)?;
    contradiction_context
        .trust_policy
        .trusted_provenance_hashes
        .clear();
    let contradiction = IntentConformanceEvaluator::evaluate(
        EnforcementDecision::Allow,
        &trace,
        core::slice::from_ref(&requirement),
        &steps,
        &contradictory,
        contradiction_context.as_context(),
    )?;
    assert_eq!(contradiction.outcome(), IntentConformanceOutcome::Uncertain);
    assert_eq!(
        contradiction.policy_evaluation().decision(),
        EnforcementDecision::RequireApproval
    );
    assert!(
        contradiction
            .findings()
            .iter()
            .all(|finding| finding.reason == IntentFindingReason::UnverifiedProvenance)
    );

    let low_support_profile = EvidenceProfile {
        method_kind: EvidenceMethodKind::DeterministicCheck,
        calibration_status: CalibrationStatus::NotApplicable,
        calibration_hash: None,
        confidence: confidence(100_000, 200_000, 300_000)?,
    };
    let low_support = evidence_chain(&requirement, &trace, &steps, &low_support_profile, None)?;
    let mut low_support_context = evaluation_context(&trace, &low_support)?;
    low_support_context
        .trust_policy
        .trusted_provenance_hashes
        .clear();
    let low_support_assessment = IntentConformanceEvaluator::evaluate(
        EnforcementDecision::Allow,
        &trace,
        core::slice::from_ref(&requirement),
        &steps,
        &low_support,
        low_support_context.as_context(),
    )?;
    assert_eq!(
        low_support_assessment.outcome(),
        IntentConformanceOutcome::Uncertain
    );
    assert_eq!(
        low_support_assessment.policy_evaluation().decision(),
        EnforcementDecision::RequireApproval
    );
    Ok(())
}

#[test]
fn external_record_round_trips_verifies_context_and_has_stable_digest()
-> Result<(), Box<dyn std::error::Error>> {
    let requirement = requirement()?;
    let steps = steps()?;
    let trace = trace(&requirement, &steps)?;
    let evidence = evidence_chain(
        &requirement,
        &trace,
        &steps,
        &deterministic_profile()?,
        None,
    )?;
    let context = evaluation_context(&trace, &evidence)?;
    let evaluation = IntentConformanceEvaluator::evaluate(
        EnforcementDecision::Allow,
        &trace,
        core::slice::from_ref(&requirement),
        &steps,
        &evidence,
        context.as_context(),
    )?;
    let record = IntentConformanceRecord::from_evaluation(&evaluation)?;
    let expected_record: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/examples/intent-conformance-record.v2.json"
    ))?;
    assert_eq!(serde_json::to_value(&record)?, expected_record);
    record.verify_bindings_for(
        IntentEvaluationCheckpoint::CompleteTrace(&trace),
        context.as_context(),
    )?;
    record.verify_evaluation_for(
        EnforcementDecision::Allow,
        IntentEvaluationCheckpoint::CompleteTrace(&trace),
        core::slice::from_ref(&requirement),
        &steps,
        &evidence,
        context.as_context(),
    )?;
    // A self-consistent SUPPORTED record cannot substitute for re-evaluation
    // against the evidence actually presented at the authorization boundary.
    assert!(
        record
            .verify_evaluation_for(
                EnforcementDecision::Allow,
                IntentEvaluationCheckpoint::CompleteTrace(&trace),
                core::slice::from_ref(&requirement),
                &steps,
                &evidence[..3],
                context.as_context(),
            )
            .is_err()
    );
    assert_eq!(record.evaluation_hash(), evaluation.digest()?);
    assert_eq!(record.outcome(), IntentConformanceOutcome::Supported);
    assert_eq!(record.decision(), EnforcementDecision::Allow);

    let json = serde_json::to_value(&record)?;
    let decoded: IntentConformanceRecord = serde_json::from_value(json.clone())?;
    assert_eq!(decoded, record);
    decoded.verify_bindings_for(
        IntentEvaluationCheckpoint::CompleteTrace(&trace),
        context.as_context(),
    )?;

    let mut tampered = json.clone();
    tampered
        .as_object_mut()
        .ok_or("record JSON must be an object")?
        .insert("task_hash".to_owned(), serde_json::json!(digest(99)));
    let tampered_record: IntentConformanceRecord = serde_json::from_value(tampered)?;
    assert!(matches!(
        tampered_record.validate(),
        Err(PolicyEvaluationError::BindingMismatch(
            "intent conformance record evaluation_hash"
        ))
    ));

    let mut with_unknown_field = json;
    with_unknown_field
        .as_object_mut()
        .ok_or("record JSON must be an object")?
        .insert("unexpected".to_owned(), serde_json::json!(true));
    assert!(serde_json::from_value::<IntentConformanceRecord>(with_unknown_field).is_err());

    let mut replaced_context = evaluation_context(&trace, &evidence)?;
    replaced_context.expectation.evaluated_at += 1;
    assert!(matches!(
        record.verify_bindings_for(
            IntentEvaluationCheckpoint::CompleteTrace(&trace),
            replaced_context.as_context()
        ),
        Err(PolicyEvaluationError::BindingMismatch(
            "intent conformance record context"
        ))
    ));

    assert_eq!(
        record.digest()?.to_hex(),
        "5586ebbc16b43b14254fdce65ebe6d4671710ba60a34c8597158a82586700675"
    );
    Ok(())
}
