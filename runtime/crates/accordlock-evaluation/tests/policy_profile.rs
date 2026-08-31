use accordlock_evaluation::{
    CONFORMANCE_EVALUATION_SCHEMA_VERSION, CanonicalEncode, ConformanceEvaluation,
    ConformanceResult, DecisionReason, Digest32, EnforcementDecision, NormalizedScore,
    POLICY_DECISION_SCHEMA_VERSION, PolicyDecisionRecord, PolicyEvaluationError, PolicyEvaluator,
    RESOURCE_QUOTA_SCHEMA_VERSION, RESOURCE_REQUEST_SCHEMA_VERSION, ResourceQuota, ResourceRequest,
    ResourceReservation, ScoreInterval, TASK_REQUIREMENT_SCHEMA_VERSION,
    TRANSFORMATION_STEP_SCHEMA_VERSION, TaskRequirement, TransformationStep, WorkflowStage,
};
use uuid::Uuid;

fn uuid(value: u128) -> Uuid {
    Uuid::from_u128(value)
}

fn digest(value: u8) -> Digest32 {
    Digest32::from_bytes([value; 32])
}

fn score(value: u32) -> Result<NormalizedScore, PolicyEvaluationError> {
    NormalizedScore::new(value)
}

fn requirement() -> Result<TaskRequirement, PolicyEvaluationError> {
    Ok(TaskRequirement {
        schema_version: TASK_REQUIREMENT_SCHEMA_VERSION,
        requirement_id: uuid(1),
        task_hash: digest(1),
        statement_hash: digest(2),
        minimum_score: score(900_000)?,
    })
}

fn root_step() -> TransformationStep {
    TransformationStep {
        schema_version: TRANSFORMATION_STEP_SCHEMA_VERSION,
        step_id: uuid(2),
        task_hash: digest(1),
        sequence: 0,
        parent_step_hash: None,
        source_stage: WorkflowStage::Request,
        source_hash: digest(3),
        target_stage: WorkflowStage::Plan,
        target_hash: digest(4),
        recorded_at: 1_000,
    }
}

fn root_evaluation(
    requirement: &TaskRequirement,
    step: &TransformationStep,
) -> Result<ConformanceEvaluation, PolicyEvaluationError> {
    Ok(ConformanceEvaluation {
        schema_version: CONFORMANCE_EVALUATION_SCHEMA_VERSION,
        conformance_id: uuid(3),
        task_hash: digest(1),
        sequence: 0,
        parent_evaluation_hash: None,
        requirement_hash: requirement.digest()?,
        transformation_step_hash: step.digest()?,
        result: ConformanceResult::Conformant,
        score: ScoreInterval::new(score(920_000)?, score(950_000)?, score(980_000)?)?,
        method_hash: digest(5),
        evidence_hash: digest(6),
        evaluated_at: 1_100,
    })
}

fn decision_record() -> PolicyDecisionRecord {
    PolicyDecisionRecord {
        schema_version: POLICY_DECISION_SCHEMA_VERSION,
        decision_id: uuid(100),
        task_hash: digest(1),
        action_hash: digest(10),
        sequence: 0,
        parent_decision_hash: None,
        requirement_hashes: vec![digest(20)],
        transformation_step_hashes: vec![digest(30)],
        conformance_evaluation_hashes: vec![digest(40)],
        resource_request_hashes: vec![digest(50)],
        resource_quota_hashes: vec![digest(60)],
        resource_reservation_hashes: vec![digest(70)],
        baseline_decision: EnforcementDecision::Allow,
        decision: EnforcementDecision::RequireApproval,
        reasons: vec![DecisionReason::ConformanceInconclusive],
        policy_epoch: 7,
        evaluated_at: 3_000,
    }
}

#[test]
fn score_is_bounded_on_construction_and_deserialization() -> Result<(), Box<dyn std::error::Error>>
{
    assert_eq!(score(0)?.get(), 0);
    assert_eq!(score(1_000_000)?.get(), 1_000_000);
    assert!(matches!(
        score(1_000_001),
        Err(PolicyEvaluationError::ScoreOutOfRange(1_000_001))
    ));
    assert!(serde_json::from_str::<NormalizedScore>("1000001").is_err());
    assert!(ScoreInterval::new(score(2)?, score(1)?, score(3)?).is_err());
    Ok(())
}

#[test]
fn conformance_results_serialize_as_explicit_profile_values()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        serde_json::to_string(&ConformanceResult::Conformant)?,
        "\"CONFORMANT\""
    );
    assert_eq!(
        serde_json::to_string(&ConformanceResult::Nonconformant)?,
        "\"NONCONFORMANT\""
    );
    assert_eq!(
        serde_json::to_string(&ConformanceResult::Inconclusive)?,
        "\"INCONCLUSIVE\""
    );
    Ok(())
}

#[test]
fn transformation_steps_form_an_exact_state_continuity_chain()
-> Result<(), Box<dyn std::error::Error>> {
    let root = root_step();
    root.validate()?;
    let successor = TransformationStep {
        schema_version: TRANSFORMATION_STEP_SCHEMA_VERSION,
        step_id: uuid(4),
        task_hash: root.task_hash,
        sequence: 1,
        parent_step_hash: Some(root.digest()?),
        source_stage: root.target_stage,
        source_hash: root.target_hash,
        target_stage: WorkflowStage::Action,
        target_hash: digest(7),
        recorded_at: 1_010,
    };
    successor.verify_successor_of(&root)?;

    let mut substituted = successor;
    substituted.source_hash = digest(99);
    assert!(matches!(
        substituted.verify_successor_of(&root),
        Err(PolicyEvaluationError::ChainMismatch(
            "step state continuity"
        ))
    ));
    Ok(())
}

#[test]
fn evaluations_bind_step_requirement_and_parent_hash() -> Result<(), Box<dyn std::error::Error>> {
    let requirement = requirement()?;
    let step = root_step();
    let root = root_evaluation(&requirement, &step)?;
    root.verify_bindings(&requirement, &step)?;
    let successor = ConformanceEvaluation {
        schema_version: CONFORMANCE_EVALUATION_SCHEMA_VERSION,
        conformance_id: uuid(5),
        task_hash: root.task_hash,
        sequence: 1,
        parent_evaluation_hash: Some(root.digest()?),
        requirement_hash: root.requirement_hash,
        transformation_step_hash: root.transformation_step_hash,
        result: ConformanceResult::Inconclusive,
        score: ScoreInterval::new(score(850_000)?, score(920_000)?, score(970_000)?)?,
        method_hash: digest(8),
        evidence_hash: digest(9),
        evaluated_at: 1_200,
    };
    successor.verify_successor_of(&root)?;

    let mut wrong_parent = successor;
    wrong_parent.parent_evaluation_hash = Some(digest(99));
    assert!(wrong_parent.verify_successor_of(&root).is_err());
    Ok(())
}

#[test]
fn canonical_commitments_cover_every_security_binding() -> Result<(), Box<dyn std::error::Error>> {
    let requirement = requirement()?;
    let original = requirement.canonical_bytes()?;
    assert_eq!(original, requirement.canonical_bytes()?);
    let original_digest = requirement.digest()?;

    let mut substituted = requirement;
    substituted.minimum_score = score(899_999)?;
    assert_ne!(original_digest, substituted.digest()?);
    assert_ne!(original, substituted.canonical_bytes()?);
    Ok(())
}

#[test]
fn reservations_are_integer_bounded_and_parent_chained() -> Result<(), Box<dyn std::error::Error>> {
    let quota = ResourceQuota {
        schema_version: RESOURCE_QUOTA_SCHEMA_VERSION,
        quota_id: uuid(10),
        task_hash: digest(1),
        resource_kind: "llm.tokens".to_owned(),
        limit: 100,
        policy_epoch: 7,
    };
    let first_request = ResourceRequest {
        schema_version: RESOURCE_REQUEST_SCHEMA_VERSION,
        request_id: uuid(11),
        task_hash: digest(1),
        action_hash: digest(11),
        resource_kind: "llm.tokens".to_owned(),
        units: 60,
    };
    let first = ResourceReservation::reserve(uuid(12), &first_request, &quota, None, 2_000)?;
    assert_eq!(first.reserved_before, 0);
    assert_eq!(first.reserved_through, 60);
    assert_eq!(first.remaining_after, 40);

    let second_request = ResourceRequest {
        schema_version: RESOURCE_REQUEST_SCHEMA_VERSION,
        request_id: uuid(13),
        task_hash: digest(1),
        action_hash: digest(12),
        resource_kind: "llm.tokens".to_owned(),
        units: 40,
    };
    let second =
        ResourceReservation::reserve(uuid(14), &second_request, &quota, Some(&first), 2_010)?;
    second.verify_for(&second_request, &quota, Some(&first))?;
    assert_eq!(second.sequence, 1);
    assert_eq!(second.remaining_after, 0);

    let excess_request = ResourceRequest {
        request_id: uuid(15),
        units: 1,
        ..second_request
    };
    assert!(matches!(
        ResourceReservation::reserve(uuid(16), &excess_request, &quota, Some(&second), 2_020),
        Err(PolicyEvaluationError::QuotaExceeded)
    ));
    Ok(())
}

#[test]
fn valid_scores_and_reservations_do_not_override_policy_approval()
-> Result<(), Box<dyn std::error::Error>> {
    let requirement = requirement()?;
    let step = root_step();
    let evaluation = root_evaluation(&requirement, &step)?;
    let conformance = PolicyEvaluator::evaluate_conformance(
        EnforcementDecision::RequireApproval,
        &requirement,
        &step,
        Some(&evaluation),
    )?;
    assert_eq!(conformance.decision(), EnforcementDecision::RequireApproval);

    let already_blocked = PolicyEvaluator::evaluate_conformance(
        EnforcementDecision::Deny,
        &requirement,
        &step,
        Some(&evaluation),
    )?;
    assert_eq!(already_blocked.decision(), EnforcementDecision::Deny);
    Ok(())
}

#[test]
fn policy_decision_digest_binds_every_runner_handoff_field()
-> Result<(), Box<dyn std::error::Error>> {
    let root = decision_record();
    root.validate()?;
    let root_digest = root.digest()?;
    assert_eq!(
        root_digest.to_hex(),
        "cfe202a85338822ad0ed4b2e688f36cfdfdedb31fa79f48ae6383d81bdef67f9"
    );

    let mut substituted = root.clone();
    substituted.resource_reservation_hashes = vec![digest(71)];
    assert_ne!(substituted.digest()?, root_digest);

    let successor = PolicyDecisionRecord {
        decision_id: uuid(101),
        action_hash: digest(11),
        sequence: 1,
        parent_decision_hash: Some(root_digest),
        baseline_decision: EnforcementDecision::RequireApproval,
        decision: EnforcementDecision::Deny,
        reasons: vec![DecisionReason::ResourceQuotaExceeded],
        evaluated_at: 3_100,
        ..root.clone()
    };
    successor.verify_successor_of(&root)?;

    let mut wrong_parent = successor;
    wrong_parent.parent_decision_hash = Some(digest(99));
    assert!(matches!(
        wrong_parent.verify_successor_of(&root),
        Err(PolicyEvaluationError::ChainMismatch("parent_decision_hash"))
    ));
    Ok(())
}

#[test]
fn decision_record_rejects_downgrade_and_noncanonical_bindings() {
    let mut downgraded = decision_record();
    downgraded.baseline_decision = EnforcementDecision::Deny;
    downgraded.decision = EnforcementDecision::Allow;
    downgraded.reasons = vec![DecisionReason::RequirementSatisfied];
    assert!(matches!(
        downgraded.validate(),
        Err(PolicyEvaluationError::InconsistentEnforcementDecision)
    ));

    let mut unordered = decision_record();
    unordered.requirement_hashes = vec![digest(21), digest(20)];
    assert!(matches!(
        unordered.validate(),
        Err(PolicyEvaluationError::NonCanonicalCollection(
            "requirement_hashes"
        ))
    ));
}
