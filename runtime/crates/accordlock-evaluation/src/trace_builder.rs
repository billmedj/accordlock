use core::convert::Infallible;
use core::marker::PhantomData;

use accordlock_protocol::{CanonicalEncode, CanonicalError, Digest32, canonical_hash};
use minicbor::Encoder;
use minicbor::encode::Error as EncodeError;
use uuid::Uuid;

use crate::{
    INTENT_TRACE_SCHEMA_VERSION, MAX_EVALUATION_BINDINGS, NormalizedScore,
    PRE_EXECUTION_INTENT_TRACE_SCHEMA_VERSION, PolicyEvaluationError,
    TASK_REQUIREMENT_SCHEMA_VERSION, TRANSFORMATION_STEP_SCHEMA_VERSION, TaskRequirement,
    TransformationStep, WorkflowStage,
};

const DERIVED_IDENTIFIER_SCHEMA_VERSION: u16 = 1;
const REQUIREMENT_IDENTIFIER_DOMAIN: &str =
    "accordlock:v1:intent-trace-builder:requirement-identifier";
const TRACE_IDENTIFIER_DOMAIN: &str = "accordlock:v1:intent-trace-builder:trace-identifier";
const STEP_IDENTIFIER_DOMAIN: &str = "accordlock:v1:intent-trace-builder:step-identifier";

type VecEncodeError = EncodeError<Infallible>;

/// One immutable requirement supplied to [`IntentTraceBuilder`].
///
/// The builder accepts only the digest of the exact requirement statement and
/// a bounded policy threshold. It has no field for request text, model output,
/// or provider credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequirementCommitment {
    statement_hash: Digest32,
    minimum_score: NormalizedScore,
}

impl RequirementCommitment {
    /// Creates a requirement commitment from an exact statement digest.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError::ZeroDigest`] for an empty commitment.
    pub fn new(
        statement_hash: Digest32,
        minimum_score: NormalizedScore,
    ) -> Result<Self, PolicyEvaluationError> {
        require_digest(statement_hash, "requirement statement_hash")?;
        Ok(Self {
            statement_hash,
            minimum_score,
        })
    }

    /// Returns the exact requirement-statement digest.
    #[must_use]
    pub const fn statement_hash(self) -> Digest32 {
        self.statement_hash
    }

    /// Returns the minimum accepted score for qualified evidence.
    #[must_use]
    pub const fn minimum_score(self) -> NormalizedScore {
        self.minimum_score
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StageArtifact {
    task_hash: Digest32,
    artifact_hash: Digest32,
    recorded_at: Option<i64>,
}

macro_rules! define_artifact {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        ///
        /// This value contains hashes and a timestamp only. Raw content and
        /// credentials cannot be placed in the typed trace-builder API.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $name(StageArtifact);

        impl $name {
            /// Creates a task-bound artifact commitment.
            ///
            /// # Errors
            ///
            /// Rejects zero digests or a nonpositive timestamp.
            pub fn new(
                task_hash: Digest32,
                artifact_hash: Digest32,
                recorded_at: i64,
            ) -> Result<Self, PolicyEvaluationError> {
                require_digest(task_hash, "artifact task_hash")?;
                require_digest(artifact_hash, "artifact_hash")?;
                require_time(recorded_at)?;
                Ok(Self(StageArtifact {
                    task_hash,
                    artifact_hash,
                    recorded_at: Some(recorded_at),
                }))
            }

            /// Returns the task commitment carried by this artifact.
            #[must_use]
            pub const fn task_hash(self) -> Digest32 {
                self.0.task_hash
            }

            /// Returns the exact artifact digest.
            #[must_use]
            pub const fn artifact_hash(self) -> Digest32 {
                self.0.artifact_hash
            }

            /// Returns when the artifact was committed.
            #[must_use]
            pub const fn recorded_at(self) -> i64 {
                match self.0.recorded_at {
                    Some(value) => value,
                    None => unreachable!(),
                }
            }
        }
    };
}

/// Exact task-bound request commitment used to start a trace.
///
/// Requests intentionally have no builder timestamp: the durable workflow
/// clock starts when the plan is committed as the root transformation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestArtifact(StageArtifact);

impl RequestArtifact {
    /// Creates an exact task and request commitment.
    ///
    /// # Errors
    ///
    /// Rejects a zero task or request digest.
    pub fn new(task_hash: Digest32, request_hash: Digest32) -> Result<Self, PolicyEvaluationError> {
        require_digest(task_hash, "request task_hash")?;
        require_digest(request_hash, "request_hash")?;
        Ok(Self(StageArtifact {
            task_hash,
            artifact_hash: request_hash,
            recorded_at: None,
        }))
    }

    /// Returns the exact task commitment.
    #[must_use]
    pub const fn task_hash(self) -> Digest32 {
        self.0.task_hash
    }

    /// Returns the exact request-artifact commitment.
    #[must_use]
    pub const fn artifact_hash(self) -> Digest32 {
        self.0.artifact_hash
    }
}

define_artifact!(PlanArtifact, "Exact task-bound plan commitment.");
define_artifact!(ActionArtifact, "Exact task-bound action commitment.");
define_artifact!(ResultArtifact, "Exact task-bound result commitment.");

/// Type state indicating that the next mandatory artifact is a plan.
#[derive(Debug)]
pub struct AwaitingPlan;
/// Type state indicating that the next mandatory artifact is an action.
#[derive(Debug)]
pub struct AwaitingAction;
/// Type state indicating that the next mandatory artifact is a result.
#[derive(Debug)]
pub struct AwaitingResult;

/// A typed request-to-result trace builder.
///
/// The state type exposes only the next valid transition. A plan cannot be
/// skipped, an action cannot be appended before a plan, and a second stage of
/// the same kind has no method in the public API. Every supplied artifact is
/// also checked against the original task commitment.
///
/// ```compile_fail
/// use accordlock_evaluation::{
///     ActionArtifact, Digest32, IntentTraceBuilder, RequestArtifact,
///     RequirementCommitment, NormalizedScore,
/// };
///
/// let task = Digest32::from_bytes([1; 32]);
/// let request = RequestArtifact::new(task, Digest32::from_bytes([2; 32])).unwrap();
/// let requirement = RequirementCommitment::new(
///     Digest32::from_bytes([3; 32]),
///     NormalizedScore::ONE,
/// ).unwrap();
/// let builder = IntentTraceBuilder::start(request, [requirement]).unwrap();
/// let action = ActionArtifact::new(task, Digest32::from_bytes([4; 32]), 10).unwrap();
/// builder.append_action(action); // A plan is required first.
/// ```
#[derive(Debug)]
pub struct IntentTraceBuilder<State> {
    trace_id: Uuid,
    task_hash: Digest32,
    request_hash: Digest32,
    requirements: Vec<TaskRequirement>,
    requirement_hashes: Vec<Digest32>,
    steps: Vec<TransformationStep>,
    current_stage: WorkflowStage,
    current_hash: Digest32,
    last_recorded_at: Option<i64>,
    state: PhantomData<State>,
}

impl IntentTraceBuilder<AwaitingPlan> {
    /// Starts a trace from exact task, request, and requirement commitments.
    ///
    /// Requirement order does not affect the result. The builder derives
    /// stable `UUIDv8` identifiers from domain-separated canonical commitments,
    /// then stores requirements in canonical digest order.
    ///
    /// # Errors
    ///
    /// Rejects an empty or oversized requirement set, duplicate requirement
    /// statements, invalid commitments, or canonical-encoding failures.
    pub fn start<I>(
        request: RequestArtifact,
        requirements: I,
    ) -> Result<Self, PolicyEvaluationError>
    where
        I: IntoIterator<Item = RequirementCommitment>,
    {
        let mut commitments = requirements
            .into_iter()
            .take(MAX_EVALUATION_BINDINGS + 1)
            .collect::<Vec<_>>();
        if commitments.is_empty() || commitments.len() > MAX_EVALUATION_BINDINGS {
            return Err(PolicyEvaluationError::InvalidBindingCollection(
                "trace-builder requirements",
            ));
        }
        commitments.sort_unstable_by_key(|item| (item.statement_hash, item.minimum_score));
        if commitments
            .windows(2)
            .any(|pair| pair[0].statement_hash == pair[1].statement_hash)
        {
            return Err(PolicyEvaluationError::NonCanonicalCollection(
                "trace-builder requirement statements",
            ));
        }

        let mut derived = Vec::with_capacity(commitments.len());
        for commitment in commitments {
            let identifier = derive_uuid(&RequirementIdentifierSeed {
                task_hash: request.0.task_hash,
                request_hash: request.0.artifact_hash,
                statement_hash: commitment.statement_hash,
                minimum_score: commitment.minimum_score,
            })?;
            let requirement = TaskRequirement {
                schema_version: TASK_REQUIREMENT_SCHEMA_VERSION,
                requirement_id: identifier,
                task_hash: request.0.task_hash,
                statement_hash: commitment.statement_hash,
                minimum_score: commitment.minimum_score,
            };
            derived.push((requirement.digest()?, requirement));
        }
        derived.sort_unstable_by_key(|(hash, _)| *hash);

        let requirement_hashes = derived.iter().map(|(hash, _)| *hash).collect::<Vec<_>>();
        let requirements = derived
            .into_iter()
            .map(|(_, requirement)| requirement)
            .collect::<Vec<_>>();
        let trace_id = derive_uuid(&TraceIdentifierSeed {
            task_hash: request.0.task_hash,
            request_hash: request.0.artifact_hash,
            requirement_hashes: &requirement_hashes,
        })?;

        Ok(Self {
            trace_id,
            task_hash: request.0.task_hash,
            request_hash: request.0.artifact_hash,
            requirements,
            requirement_hashes,
            steps: Vec::with_capacity(3),
            current_stage: WorkflowStage::Request,
            current_hash: request.0.artifact_hash,
            last_recorded_at: None,
            state: PhantomData,
        })
    }

    /// Appends the mandatory plan and advances the type state.
    ///
    /// # Errors
    ///
    /// Rejects a cross-task artifact or an invalid commitment.
    pub fn append_plan(
        self,
        plan: PlanArtifact,
    ) -> Result<IntentTraceBuilder<AwaitingAction>, PolicyEvaluationError> {
        self.append(WorkflowStage::Plan, plan.0)
    }
}

impl IntentTraceBuilder<AwaitingAction> {
    /// Appends the mandatory action and advances the type state.
    ///
    /// # Errors
    ///
    /// Rejects a cross-task artifact or a timestamp earlier than the plan.
    pub fn append_action(
        self,
        action: ActionArtifact,
    ) -> Result<IntentTraceBuilder<AwaitingResult>, PolicyEvaluationError> {
        self.append(WorkflowStage::Action, action.0)
    }
}

impl IntentTraceBuilder<AwaitingResult> {
    /// Returns a typed request-plan-action checkpoint without inventing a
    /// result and without consuming the builder.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] if any checkpoint commitment or
    /// binding is invalid.
    pub fn pre_execution_checkpoint(
        &self,
    ) -> Result<crate::PreExecutionIntentTrace, PolicyEvaluationError> {
        let transformation_step_hashes = self
            .steps
            .iter()
            .map(TransformationStep::digest)
            .collect::<Result<Vec<_>, _>>()?;
        let recorded_at = self
            .last_recorded_at
            .ok_or(PolicyEvaluationError::InvalidTime(
                "pre-execution checkpoint",
            ))?;
        let checkpoint = crate::PreExecutionIntentTrace {
            schema_version: PRE_EXECUTION_INTENT_TRACE_SCHEMA_VERSION,
            trace_id: self.trace_id,
            task_hash: self.task_hash,
            requirement_hashes: self.requirement_hashes.clone(),
            request_hash: self.request_hash,
            plan_hash: target_hash(&self.steps, WorkflowStage::Plan)?,
            action_hash: target_hash(&self.steps, WorkflowStage::Action)?,
            transformation_step_hashes,
            recorded_at,
        };
        checkpoint.verify_bindings(&self.requirements, &self.steps)?;
        Ok(checkpoint)
    }

    /// Requirements committed by the pre-execution checkpoint.
    #[must_use]
    pub fn requirements(&self) -> &[TaskRequirement] {
        &self.requirements
    }

    /// Request-plan-action transformations in exact order.
    #[must_use]
    pub fn transformations(&self) -> &[TransformationStep] {
        &self.steps
    }

    /// Appends the mandatory result and returns a verified complete bundle.
    ///
    /// # Errors
    ///
    /// Rejects a cross-task artifact, a timestamp earlier than the action, or
    /// any failed final binding verification.
    pub fn append_result(
        self,
        result: ResultArtifact,
    ) -> Result<CompletedIntentTrace, PolicyEvaluationError> {
        let complete: IntentTraceBuilder<Complete> =
            self.append(WorkflowStage::Result, result.0)?;
        complete.finish()
    }
}

impl<State> IntentTraceBuilder<State> {
    fn append<Next>(
        mut self,
        target_stage: WorkflowStage,
        artifact: StageArtifact,
    ) -> Result<IntentTraceBuilder<Next>, PolicyEvaluationError> {
        if artifact.task_hash != self.task_hash {
            return Err(PolicyEvaluationError::BindingMismatch(
                "trace-builder artifact task",
            ));
        }
        let recorded_at = artifact
            .recorded_at
            .ok_or(PolicyEvaluationError::InvalidTime(
                "trace-builder artifact recorded_at",
            ))?;
        if self
            .last_recorded_at
            .is_some_and(|previous| recorded_at < previous)
        {
            return Err(PolicyEvaluationError::ChainMismatch(
                "trace-builder artifact time",
            ));
        }

        let sequence = u64::try_from(self.steps.len())
            .map_err(|_| PolicyEvaluationError::ArithmeticOverflow("trace-builder sequence"))?;
        let parent_step_hash = self
            .steps
            .last()
            .map(TransformationStep::digest)
            .transpose()?;
        let step_id = derive_uuid(&StepIdentifierSeed {
            trace_id: self.trace_id,
            task_hash: self.task_hash,
            sequence,
            parent_step_hash,
            source_stage: self.current_stage,
            source_hash: self.current_hash,
            target_stage,
            target_hash: artifact.artifact_hash,
            recorded_at,
        })?;
        let step = TransformationStep {
            schema_version: TRANSFORMATION_STEP_SCHEMA_VERSION,
            step_id,
            task_hash: self.task_hash,
            sequence,
            parent_step_hash,
            source_stage: self.current_stage,
            source_hash: self.current_hash,
            target_stage,
            target_hash: artifact.artifact_hash,
            recorded_at,
        };
        if let Some(parent) = self.steps.last() {
            step.verify_successor_of(parent)?;
        } else {
            step.validate()?;
        }
        self.steps.push(step);

        Ok(IntentTraceBuilder {
            trace_id: self.trace_id,
            task_hash: self.task_hash,
            request_hash: self.request_hash,
            requirements: self.requirements,
            requirement_hashes: self.requirement_hashes,
            steps: self.steps,
            current_stage: target_stage,
            current_hash: artifact.artifact_hash,
            last_recorded_at: Some(recorded_at),
            state: PhantomData,
        })
    }
}

#[derive(Debug)]
struct Complete;

impl IntentTraceBuilder<Complete> {
    fn finish(self) -> Result<CompletedIntentTrace, PolicyEvaluationError> {
        let step_hashes = self
            .steps
            .iter()
            .map(TransformationStep::digest)
            .collect::<Result<Vec<_>, _>>()?;
        let plan_hash = target_hash(&self.steps, WorkflowStage::Plan)?;
        let action_hash = target_hash(&self.steps, WorkflowStage::Action)?;
        let result_hash = target_hash(&self.steps, WorkflowStage::Result)?;
        let recorded_at = self
            .last_recorded_at
            .ok_or(PolicyEvaluationError::InvalidTime(
                "trace-builder completion",
            ))?;
        let trace = crate::IntentTrace {
            schema_version: INTENT_TRACE_SCHEMA_VERSION,
            trace_id: self.trace_id,
            task_hash: self.task_hash,
            requirement_hashes: self.requirement_hashes,
            request_hash: self.request_hash,
            plan_hash,
            action_hash,
            result_hash,
            transformation_step_hashes: step_hashes,
            recorded_at,
        };
        let completed = CompletedIntentTrace {
            trace,
            requirements: self.requirements,
            steps: self.steps,
        };
        completed.validate()?;
        Ok(completed)
    }
}

/// A complete, internally verified request-to-result trace bundle.
///
/// Requirements are in canonical digest order and transformations are in
/// execution order. The bundle can be written atomically by a runtime without
/// reconstructing IDs, parent hashes, or trace bindings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletedIntentTrace {
    trace: crate::IntentTrace,
    requirements: Vec<TaskRequirement>,
    steps: Vec<TransformationStep>,
}

impl CompletedIntentTrace {
    /// Revalidates the complete bundle and every exact binding.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed validation error if any member was altered.
    pub fn validate(&self) -> Result<(), PolicyEvaluationError> {
        self.trace.verify_bindings(&self.requirements, &self.steps)
    }

    /// Returns the durable trace record.
    #[must_use]
    pub const fn trace(&self) -> &crate::IntentTrace {
        &self.trace
    }

    /// Returns task requirements in canonical digest order.
    #[must_use]
    pub fn requirements(&self) -> &[TaskRequirement] {
        &self.requirements
    }

    /// Returns transformations in exact execution order.
    #[must_use]
    pub fn transformations(&self) -> &[TransformationStep] {
        &self.steps
    }

    /// Consumes the bundle for atomic persistence.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        crate::IntentTrace,
        Vec<TaskRequirement>,
        Vec<TransformationStep>,
    ) {
        (self.trace, self.requirements, self.steps)
    }
}

fn target_hash(
    steps: &[TransformationStep],
    target: WorkflowStage,
) -> Result<Digest32, PolicyEvaluationError> {
    steps
        .iter()
        .find(|step| step.target_stage == target)
        .map(|step| step.target_hash)
        .ok_or(PolicyEvaluationError::ChainMismatch(
            "trace-builder checkpoint",
        ))
}

fn require_digest(value: Digest32, field: &'static str) -> Result<(), PolicyEvaluationError> {
    if value.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(PolicyEvaluationError::ZeroDigest(field));
    }
    Ok(())
}

fn require_time(value: i64) -> Result<(), PolicyEvaluationError> {
    if value <= 0 {
        return Err(PolicyEvaluationError::InvalidTime("artifact recorded_at"));
    }
    Ok(())
}

fn derive_uuid(value: &impl CanonicalEncode) -> Result<Uuid, PolicyEvaluationError> {
    let digest = canonical_hash(value)
        .map_err(|error| PolicyEvaluationError::Canonical(error.to_string()))?;
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    // RFC 9562 UUIDv8: custom deterministic bytes, standard variant/version.
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(Uuid::from_bytes(bytes))
}

fn finish(result: Result<Vec<u8>, VecEncodeError>) -> Result<Vec<u8>, CanonicalError> {
    result.map_err(|error| CanonicalError::Encode(error.to_string()))
}

struct RequirementIdentifierSeed {
    task_hash: Digest32,
    request_hash: Digest32,
    statement_hash: Digest32,
    minimum_score: NormalizedScore,
}

impl CanonicalEncode for RequirementIdentifierSeed {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(6)?;
            encoder.u16(DERIVED_IDENTIFIER_SCHEMA_VERSION)?;
            encoder.bytes(self.task_hash.as_bytes())?;
            encoder.bytes(self.request_hash.as_bytes())?;
            encoder.bytes(self.statement_hash.as_bytes())?;
            encoder.u32(self.minimum_score.get())?;
            encoder.str(REQUIREMENT_IDENTIFIER_DOMAIN)?;
            Ok(encoder.into_writer())
        })())
    }
}

struct TraceIdentifierSeed<'a> {
    task_hash: Digest32,
    request_hash: Digest32,
    requirement_hashes: &'a [Digest32],
}

impl CanonicalEncode for TraceIdentifierSeed<'_> {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(5)?;
            encoder.u16(DERIVED_IDENTIFIER_SCHEMA_VERSION)?;
            encoder.bytes(self.task_hash.as_bytes())?;
            encoder.bytes(self.request_hash.as_bytes())?;
            encoder.array(u64::try_from(self.requirement_hashes.len()).unwrap_or(u64::MAX))?;
            for hash in self.requirement_hashes {
                encoder.bytes(hash.as_bytes())?;
            }
            encoder.str(TRACE_IDENTIFIER_DOMAIN)?;
            Ok(encoder.into_writer())
        })())
    }
}

struct StepIdentifierSeed {
    trace_id: Uuid,
    task_hash: Digest32,
    sequence: u64,
    parent_step_hash: Option<Digest32>,
    source_stage: WorkflowStage,
    source_hash: Digest32,
    target_stage: WorkflowStage,
    target_hash: Digest32,
    recorded_at: i64,
}

impl CanonicalEncode for StepIdentifierSeed {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(11)?;
            encoder.u16(DERIVED_IDENTIFIER_SCHEMA_VERSION)?;
            encoder.bytes(self.trace_id.as_bytes())?;
            encoder.bytes(self.task_hash.as_bytes())?;
            encoder.u64(self.sequence)?;
            if let Some(parent) = self.parent_step_hash {
                encoder.bytes(parent.as_bytes())?;
            } else {
                encoder.null()?;
            }
            encoder.u8(self.source_stage.code())?;
            encoder.bytes(self.source_hash.as_bytes())?;
            encoder.u8(self.target_stage.code())?;
            encoder.bytes(self.target_hash.as_bytes())?;
            encoder.i64(self.recorded_at)?;
            encoder.str(STEP_IDENTIFIER_DOMAIN)?;
            Ok(encoder.into_writer())
        })())
    }
}
