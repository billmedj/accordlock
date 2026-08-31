use accordlock_evaluation::{
    ActionArtifact, CompletedIntentTrace, Digest32, IntentTraceBuilder, NormalizedScore,
    PlanArtifact, PolicyEvaluationError, RequestArtifact, RequirementCommitment, ResultArtifact,
    TransformationStep,
};

fn digest(value: u8) -> Digest32 {
    Digest32::from_bytes([value; 32])
}

fn requirements() -> Result<[RequirementCommitment; 2], PolicyEvaluationError> {
    Ok([
        RequirementCommitment::new(digest(3), NormalizedScore::new(900_000)?)?,
        RequirementCommitment::new(digest(4), NormalizedScore::new(750_000)?)?,
    ])
}

fn build(
    action_hash: Digest32,
    result_hash: Digest32,
) -> Result<CompletedIntentTrace, PolicyEvaluationError> {
    let task = digest(1);
    IntentTraceBuilder::start(RequestArtifact::new(task, digest(2))?, requirements()?)?
        .append_plan(PlanArtifact::new(task, digest(5), 1_000)?)?
        .append_action(ActionArtifact::new(task, action_hash, 1_100)?)?
        .append_result(ResultArtifact::new(task, result_hash, 1_200)?)
}

#[test]
fn golden_vector_is_stable_and_fully_bound() -> Result<(), PolicyEvaluationError> {
    let completed = build(digest(6), digest(7))?;
    completed.validate()?;

    let requirement_ids = completed
        .requirements()
        .iter()
        .map(|requirement| requirement.requirement_id.to_string())
        .collect::<Vec<_>>();
    let requirement_hashes = completed
        .requirements()
        .iter()
        .map(|requirement| requirement.digest().map(Digest32::to_hex))
        .collect::<Result<Vec<_>, _>>()?;
    let step_ids = completed
        .transformations()
        .iter()
        .map(|step| step.step_id.to_string())
        .collect::<Vec<_>>();
    let step_hashes = completed
        .transformations()
        .iter()
        .map(|step| step.digest().map(Digest32::to_hex))
        .collect::<Result<Vec<_>, _>>()?;

    assert_eq!(
        completed.trace().trace_id.to_string(),
        "8c65cb44-2453-8ec4-8849-959cb5c47439"
    );
    assert_eq!(
        requirement_ids,
        [
            "0e615c80-effb-871b-b6ec-2f55b4a1d185",
            "f2572bde-abe8-89ea-a0ea-ff5932cbfb85",
        ]
    );
    assert_eq!(
        requirement_hashes,
        [
            "093484e925fc96fe34980008f7aeb1f36a792d3ae8540805d56328e4bb0d8da6",
            "c158d69c7aaed08e1e4f660bcc68e867728bfd0a36478b50810c548956bfa220",
        ]
    );
    assert_eq!(
        step_ids,
        [
            "0c3588be-9050-8030-a864-e61497ab6c26",
            "6d25812f-ce78-834a-8c9d-4259eb7c13db",
            "256c36b7-9468-839e-96d9-4f8311b379d6",
        ]
    );
    assert_eq!(
        step_hashes,
        [
            "be7fc1d67c1115929ff78626845c861365bfdc84827fc2cf9fe49a4c8dfa6ed1",
            "2a168a64843d7982c1780a6697924e08343b45ee78c1531b0163a173213af580",
            "a4748e0effc12d10ba430614e2c638796ca24acc3c9ab14526bd301c53e491a8",
        ]
    );
    assert_eq!(
        completed.trace().digest()?.to_hex(),
        "f1e65da8e83c33e2d9df0136a510a2a92d5e089a4c05084351acd9092de2e8ea"
    );

    assert_eq!(completed.trace().task_hash, digest(1));
    assert_eq!(completed.trace().request_hash, digest(2));
    assert_eq!(completed.trace().plan_hash, digest(5));
    assert_eq!(completed.trace().action_hash, digest(6));
    assert_eq!(completed.trace().result_hash, digest(7));
    assert_eq!(completed.trace().recorded_at, 1_200);
    assert_eq!(completed.transformations().len(), 3);
    assert_eq!(completed.requirements().len(), 2);
    Ok(())
}

#[test]
fn input_requirement_order_does_not_change_output() -> Result<(), PolicyEvaluationError> {
    let task = digest(1);
    let [first, second] = requirements()?;
    let left = IntentTraceBuilder::start(RequestArtifact::new(task, digest(2))?, [first, second])?
        .append_plan(PlanArtifact::new(task, digest(5), 1_000)?)?
        .append_action(ActionArtifact::new(task, digest(6), 1_100)?)?
        .append_result(ResultArtifact::new(task, digest(7), 1_200)?)?;
    let right = IntentTraceBuilder::start(RequestArtifact::new(task, digest(2))?, [second, first])?
        .append_plan(PlanArtifact::new(task, digest(5), 1_000)?)?
        .append_action(ActionArtifact::new(task, digest(6), 1_100)?)?
        .append_result(ResultArtifact::new(task, digest(7), 1_200)?)?;

    assert_eq!(left, right);
    Ok(())
}

#[test]
fn cross_task_artifacts_are_rejected_at_every_transition() -> Result<(), PolicyEvaluationError> {
    let task = digest(1);
    let other_task = digest(9);

    assert!(matches!(
        IntentTraceBuilder::start(RequestArtifact::new(task, digest(2))?, requirements()?)?
            .append_plan(PlanArtifact::new(other_task, digest(5), 1_000)?),
        Err(PolicyEvaluationError::BindingMismatch(
            "trace-builder artifact task"
        ))
    ));

    assert!(matches!(
        IntentTraceBuilder::start(RequestArtifact::new(task, digest(2))?, requirements()?)?
            .append_plan(PlanArtifact::new(task, digest(5), 1_000)?)?
            .append_action(ActionArtifact::new(other_task, digest(6), 1_100)?),
        Err(PolicyEvaluationError::BindingMismatch(
            "trace-builder artifact task"
        ))
    ));

    assert!(matches!(
        IntentTraceBuilder::start(RequestArtifact::new(task, digest(2))?, requirements()?)?
            .append_plan(PlanArtifact::new(task, digest(5), 1_000)?)?
            .append_action(ActionArtifact::new(task, digest(6), 1_100)?)?
            .append_result(ResultArtifact::new(other_task, digest(7), 1_200)?),
        Err(PolicyEvaluationError::BindingMismatch(
            "trace-builder artifact task"
        ))
    ));
    Ok(())
}

#[test]
fn timestamps_must_be_monotone() -> Result<(), PolicyEvaluationError> {
    let task = digest(1);
    assert!(matches!(
        IntentTraceBuilder::start(RequestArtifact::new(task, digest(2))?, requirements()?)?
            .append_plan(PlanArtifact::new(task, digest(5), 1_100)?)?
            .append_action(ActionArtifact::new(task, digest(6), 1_000)?),
        Err(PolicyEvaluationError::ChainMismatch(
            "trace-builder artifact time"
        ))
    ));
    assert!(PlanArtifact::new(task, digest(5), 0).is_err());
    Ok(())
}

#[test]
fn duplicate_or_missing_requirements_are_rejected() -> Result<(), PolicyEvaluationError> {
    let task = digest(1);
    let first = RequirementCommitment::new(digest(3), NormalizedScore::new(900_000)?)?;
    let duplicate = RequirementCommitment::new(digest(3), NormalizedScore::new(750_000)?)?;

    assert!(matches!(
        IntentTraceBuilder::start(RequestArtifact::new(task, digest(2))?, [first, duplicate]),
        Err(PolicyEvaluationError::NonCanonicalCollection(
            "trace-builder requirement statements"
        ))
    ));

    assert!(matches!(
        IntentTraceBuilder::start(RequestArtifact::new(task, digest(2))?, core::iter::empty()),
        Err(PolicyEvaluationError::InvalidBindingCollection(
            "trace-builder requirements"
        ))
    ));
    Ok(())
}

#[test]
fn substituted_action_changes_the_chain_and_trace_commitment() -> Result<(), PolicyEvaluationError>
{
    let expected = build(digest(6), digest(7))?;
    let substituted = build(digest(8), digest(7))?;

    assert_eq!(expected.trace().trace_id, substituted.trace().trace_id);
    assert_eq!(
        expected.transformations()[0],
        substituted.transformations()[0]
    );
    assert_ne!(
        expected.transformations()[1].step_id,
        substituted.transformations()[1].step_id
    );
    assert_ne!(
        expected.transformations()[2].parent_step_hash,
        substituted.transformations()[2].parent_step_hash
    );
    assert_ne!(expected.trace().digest()?, substituted.trace().digest()?);
    Ok(())
}

#[test]
fn existing_verifier_rejects_reordered_or_skipped_steps() -> Result<(), PolicyEvaluationError> {
    let complete = build(digest(6), digest(7))?;
    let (mut trace, requirements, mut steps) = complete.into_parts();

    steps.swap(0, 1);
    trace.transformation_step_hashes = steps
        .iter()
        .map(TransformationStep::digest)
        .collect::<Result<Vec<_>, _>>()?;
    assert!(trace.verify_bindings(&requirements, &steps).is_err());

    steps.remove(0);
    trace.transformation_step_hashes = steps
        .iter()
        .map(TransformationStep::digest)
        .collect::<Result<Vec<_>, _>>()?;
    assert!(trace.verify_bindings(&requirements, &steps).is_err());
    Ok(())
}

#[test]
fn zero_hashes_never_enter_the_builder() {
    let zero = Digest32::from_bytes([0; 32]);
    assert!(RequestArtifact::new(zero, digest(2)).is_err());
    assert!(RequestArtifact::new(digest(1), zero).is_err());
    assert!(RequirementCommitment::new(zero, NormalizedScore::ONE).is_err());
    assert!(ActionArtifact::new(digest(1), zero, 1).is_err());
}
