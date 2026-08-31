use accordlock_agent_protocol::{
    Digest32, MAX_EXTENSION_BYTES, MAX_RUN_ID_BYTES, MAX_SESSION_ID_BYTES, MAX_TOOL_BYTES,
    MAX_TOOL_CALL_ID_BYTES,
};
use accordlock_evaluation::{
    CONFORMANCE_EVALUATION_SCHEMA_VERSION, ConformanceEvaluation, ConformanceResult,
    DecisionReason, EnforcementDecision, NormalizedScore, POLICY_DECISION_SCHEMA_VERSION,
    PolicyDecisionRecord, PolicyEvaluation, PolicyEvaluator, ScoreInterval,
    TASK_REQUIREMENT_SCHEMA_VERSION, TRANSFORMATION_STEP_SCHEMA_VERSION, TaskRequirement,
    TransformationStep, WorkflowStage,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::path::Path;
use thiserror::Error;
use uuid::Uuid;

use crate::canonical::canonical_json_bytes;

pub const TASK_POLICY_SCHEMA_VERSION: u16 = 2;
pub const ACTION_APPROVAL_SCHEMA_VERSION: u16 = 2;
pub const MAX_ACTION_APPROVAL_LIFETIME_SECONDS: i64 = 5 * 60;
pub const MAX_PREAUTHORIZED_CAPABILITIES: usize = 16;
pub const MAX_APPROVAL_RELATIVE_PATH_BYTES: usize = 4 * 1_024;
pub const MAX_PROTECTED_PATHS: usize = 256;
pub(crate) const AUTOMATIC_ACTION_EVALUATION_SCHEMA_VERSION: u16 = 2;

const TASK_POLICY_DIGEST_DOMAIN: &[u8] = b"accordlock:v2:task-policy";
const ACTION_APPROVAL_REQUEST_DIGEST_DOMAIN: &[u8] = b"accordlock:v2:action-approval-request";
const ACTION_BINDING_DIGEST_DOMAIN: &[u8] = b"accordlock:v2:action-binding";
const TASK_REQUIREMENT_ID_DOMAIN: &[u8] = b"accordlock:v2:task-requirement-id";
const TRANSFORMATION_STEP_ID_DOMAIN: &[u8] = b"accordlock:v2:transformation-step-id";
const POLICY_DECISION_ID_DOMAIN: &[u8] = b"accordlock:v2:policy-decision-id";
const AUTOMATIC_ACTION_EVALUATION_DIGEST_DOMAIN: &[u8] =
    b"accordlock:v2:automatic-action-evaluation";
const AUTOMATIC_ACTION_HASH_DOMAIN: &[u8] = b"accordlock:v2:automatic-action";
const AUTOMATIC_REQUIREMENT_DOMAIN: &[u8] = b"accordlock:v2:automatic-requirement";
const AUTOMATIC_EVIDENCE_DOMAIN: &[u8] = b"accordlock:v2:automatic-scope-evidence";
const AUTOMATIC_METHOD_PROFILE: &[u8] = b"accordlock:v2:validated-local-read-only-scope-evaluator";
const AUTOMATIC_REQUIREMENT_ID_DOMAIN: &[u8] = b"accordlock:v2:automatic-requirement-id";
const AUTOMATIC_TRANSFORMATION_ID_DOMAIN: &[u8] = b"accordlock:v2:automatic-step-id";
const AUTOMATIC_CONFORMANCE_ID_DOMAIN: &[u8] = b"accordlock:v2:automatic-conformance-id";
const AUTOMATIC_POLICY_DECISION_ID_DOMAIN: &[u8] = b"accordlock:v2:automatic-policy-decision-id";

/// Exact capability authorized to pass without a single-use action approval.
///
/// The native profile authorizes only the bounded `developer/read` and
/// `developer/tree` observation tools here. Every other capability is treated
/// as potentially mutating and requires a private approval decision.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreauthorizedCapability {
    pub extension_id: String,
    pub tool_name: String,
}

impl PreauthorizedCapability {
    #[must_use]
    pub fn new(extension_id: impl Into<String>, tool_name: impl Into<String>) -> Self {
        Self {
            extension_id: extension_id.into(),
            tool_name: tool_name.into(),
        }
    }

    fn validate(&self) -> Result<(), TaskPolicyError> {
        validate_text(&self.extension_id, "extension_id", MAX_EXTENSION_BYTES)?;
        validate_text(&self.tool_name, "tool_name", MAX_TOOL_BYTES)?;
        if self.extension_id != "developer" || !matches!(self.tool_name.as_str(), "read" | "tree") {
            return Err(TaskPolicyError::UnsafePreauthorizedCapability);
        }
        Ok(())
    }
}

/// Immutable, closed execution policy approved for one task.
///
/// This is deliberately not a free-text evaluator. It commits the approved
/// objective and the exact observation-only
/// capabilities that may execute automatically. Every other approved tool
/// requires an exact private single-use [`ActionApproval`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskPolicy {
    pub schema_version: u16,
    pub task_objective_hash: Digest32,
    pub preauthorized_capabilities: Vec<PreauthorizedCapability>,
    pub protected_paths: Vec<String>,
}

impl TaskPolicy {
    /// Constructs and canonicalizes the bounded deterministic policy.
    ///
    /// # Errors
    ///
    /// Rejects a zero objective, unsafe automatic tool, or excessive set.
    pub fn new(
        task_objective_hash: Digest32,
        preauthorized_capabilities: impl IntoIterator<Item = PreauthorizedCapability>,
        protected_paths: impl IntoIterator<Item = String>,
    ) -> Result<Self, TaskPolicyError> {
        let mut preauthorized_capabilities =
            preauthorized_capabilities.into_iter().collect::<Vec<_>>();
        preauthorized_capabilities.sort();
        preauthorized_capabilities.dedup();
        let mut protected_paths = protected_paths.into_iter().collect::<Vec<_>>();
        protected_paths.sort();
        protected_paths.dedup();
        let policy = Self {
            schema_version: TASK_POLICY_SCHEMA_VERSION,
            task_objective_hash,
            preauthorized_capabilities,
            protected_paths,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Validates every immutable policy field.
    ///
    /// # Errors
    ///
    /// Rejects unsupported, duplicate, unsorted, excessive, or unsafe data.
    pub fn validate(&self) -> Result<(), TaskPolicyError> {
        if self.schema_version != TASK_POLICY_SCHEMA_VERSION {
            return Err(TaskPolicyError::WrongSchema("task policy"));
        }
        require_digest(self.task_objective_hash, "task_objective_hash")?;
        if self.preauthorized_capabilities.len() > MAX_PREAUTHORIZED_CAPABILITIES {
            return Err(TaskPolicyError::InvalidAutomaticCapabilities);
        }
        let mut previous: Option<&PreauthorizedCapability> = None;
        for capability in &self.preauthorized_capabilities {
            capability.validate()?;
            if previous.is_some_and(|value| value >= capability) {
                return Err(TaskPolicyError::InvalidAutomaticCapabilities);
            }
            previous = Some(capability);
        }
        if self.protected_paths.len() > MAX_PROTECTED_PATHS {
            return Err(TaskPolicyError::InvalidProtectedPaths);
        }
        let mut previous_path: Option<&str> = None;
        for path in &self.protected_paths {
            validate_protected_path(path)?;
            if previous_path.is_some_and(|value| value >= path.as_str()) {
                return Err(TaskPolicyError::InvalidProtectedPaths);
            }
            previous_path = Some(path);
        }
        Ok(())
    }

    /// Domain-separated commitment to the complete approved policy.
    ///
    /// # Errors
    ///
    /// Rejects invalid policy data or canonical-encoding failure.
    pub fn digest(&self) -> Result<Digest32, TaskPolicyError> {
        self.validate()?;
        domain_digest(TASK_POLICY_DIGEST_DOMAIN, self)
    }

    #[must_use]
    pub fn allows_automatic(&self, extension_id: &str, tool_name: &str) -> bool {
        self.preauthorized_capabilities
            .binary_search_by(|candidate| {
                candidate
                    .extension_id
                    .as_str()
                    .cmp(extension_id)
                    .then_with(|| candidate.tool_name.as_str().cmp(tool_name))
            })
            .is_ok()
    }

    #[must_use]
    pub fn protects_path(&self, relative_path: &str) -> bool {
        let candidate = relative_path.replace('\\', "/").to_lowercase();
        self.protected_paths.iter().any(|protected| {
            candidate == *protected || candidate.starts_with(&format!("{protected}/"))
        })
    }
}

/// Closed execution classes that the trusted filesystem broker can prove
/// before an action runs. This is intentionally narrower than the tool
/// protocol: only local observation operations have a class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum AutomaticExecutionClass {
    LocalFileRead,
    LocalDirectoryTree,
}

impl AutomaticExecutionClass {
    pub(crate) fn for_tool(extension_id: &str, tool_name: &str) -> Option<Self> {
        match (extension_id, tool_name) {
            ("developer", "read") => Some(Self::LocalFileRead),
            ("developer", "tree") => Some(Self::LocalDirectoryTree),
            _ => None,
        }
    }

    const fn code(self) -> &'static str {
        match self {
            Self::LocalFileRead => "LOCAL_FILE_READ",
            Self::LocalDirectoryTree => "LOCAL_DIRECTORY_TREE",
        }
    }
}

/// Exact trusted inputs used to build or revalidate one automatic decision.
///
/// The caller must be the native filesystem broker after it has parsed the
/// bounded operation and excluded protected paths. Renderer, model, and HTTP
/// request data cannot construct an automatic evaluation on their own.
#[derive(Clone, Copy)]
pub(crate) struct AutomaticEvaluationInput<'a> {
    pub task_id: Uuid,
    pub session_id: &'a str,
    pub run_id: &'a str,
    pub tool_call_id: &'a str,
    pub proposal_digest: Digest32,
    pub extension_id: &'a str,
    pub tool_name: &'a str,
    pub task_policy: &'a TaskPolicy,
    pub task_policy_hash: Digest32,
    pub policy_epoch: u64,
    pub evaluated_at: i64,
}

#[derive(Serialize)]
struct AutomaticActionBinding<'a> {
    schema_version: u16,
    proposal_digest: Digest32,
    task_policy_hash: Digest32,
    execution_class: &'a str,
}

#[derive(Serialize)]
struct AutomaticRequirementBinding {
    schema_version: u16,
    task_objective_hash: Digest32,
    task_policy_hash: Digest32,
    action_hash: Digest32,
}

/// A type-level claim emitted only after the native scope validator succeeds.
/// It serializes as `true` to preserve the version-two evidence wire format.
#[derive(Clone, Copy)]
struct VerifiedScopeClaim;

impl Serialize for VerifiedScopeClaim {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bool(true)
    }
}

#[derive(Serialize)]
struct AutomaticScopeEvidence<'a> {
    schema_version: u16,
    proposal_digest: Digest32,
    task_policy_hash: Digest32,
    action_hash: Digest32,
    execution_class: &'a str,
    local_workspace_only: VerifiedScopeClaim,
    read_only: VerifiedScopeClaim,
    protected_path_excluded: VerifiedScopeClaim,
    network_disabled: VerifiedScopeClaim,
}

/// Durable pre-execution evidence for one exact local read-only action.
///
/// This record proves structural scope preservation, not equivalence of
/// free-text intent. The complete request-to-result intent evaluator remains a
/// post-execution audit instrument until a canonical action-prefix trace exists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AutomaticActionEvaluation {
    pub schema_version: u16,
    pub task_id: Uuid,
    pub session_id: String,
    pub run_id: String,
    pub tool_call_id: String,
    pub proposal_digest: Digest32,
    pub task_policy_hash: Digest32,
    pub execution_class: AutomaticExecutionClass,
    pub task_requirement: TaskRequirement,
    pub transformation_step: TransformationStep,
    pub conformance_evaluation: ConformanceEvaluation,
    pub policy_decision: PolicyDecisionRecord,
    pub policy_decision_hash: Digest32,
}

fn build_automatic_requirement(
    input: AutomaticEvaluationInput<'_>,
    action_hash: Digest32,
    statement_hash: Digest32,
) -> TaskRequirement {
    TaskRequirement {
        schema_version: TASK_REQUIREMENT_SCHEMA_VERSION,
        requirement_id: derived_policy_uuid(
            AUTOMATIC_REQUIREMENT_ID_DOMAIN,
            input.task_id,
            input.proposal_digest,
            input.task_policy_hash,
            action_hash,
            input.policy_epoch,
            input.evaluated_at,
        ),
        task_hash: input.task_policy_hash,
        statement_hash,
        minimum_score: NormalizedScore::ONE,
    }
}

fn build_automatic_transformation(
    input: AutomaticEvaluationInput<'_>,
    action_hash: Digest32,
    statement_hash: Digest32,
) -> TransformationStep {
    TransformationStep {
        schema_version: TRANSFORMATION_STEP_SCHEMA_VERSION,
        step_id: derived_policy_uuid(
            AUTOMATIC_TRANSFORMATION_ID_DOMAIN,
            input.task_id,
            input.proposal_digest,
            input.task_policy_hash,
            action_hash,
            input.policy_epoch,
            input.evaluated_at,
        ),
        task_hash: input.task_policy_hash,
        sequence: 0,
        parent_step_hash: None,
        source_stage: WorkflowStage::Request,
        source_hash: statement_hash,
        target_stage: WorkflowStage::Action,
        target_hash: action_hash,
        recorded_at: input.evaluated_at,
    }
}

fn build_automatic_conformance(
    input: AutomaticEvaluationInput<'_>,
    execution_class: AutomaticExecutionClass,
    action_hash: Digest32,
    requirement_hash: Digest32,
    transformation_step_hash: Digest32,
) -> Result<ConformanceEvaluation, TaskPolicyError> {
    Ok(ConformanceEvaluation {
        schema_version: CONFORMANCE_EVALUATION_SCHEMA_VERSION,
        conformance_id: derived_policy_uuid(
            AUTOMATIC_CONFORMANCE_ID_DOMAIN,
            input.task_id,
            input.proposal_digest,
            input.task_policy_hash,
            action_hash,
            input.policy_epoch,
            input.evaluated_at,
        ),
        task_hash: input.task_policy_hash,
        sequence: 0,
        parent_evaluation_hash: None,
        requirement_hash,
        transformation_step_hash,
        result: ConformanceResult::Conformant,
        score: ScoreInterval::new(
            NormalizedScore::ONE,
            NormalizedScore::ONE,
            NormalizedScore::ONE,
        )
        .map_err(|_| TaskPolicyError::InvalidEvaluationRecord)?,
        method_hash: Digest32::sha256(AUTOMATIC_METHOD_PROFILE),
        evidence_hash: automatic_evidence_hash(input, execution_class, action_hash)?,
        evaluated_at: input.evaluated_at,
    })
}

struct ExpectedAutomaticEvaluation {
    action: Digest32,
    statement: Digest32,
    requirement: Digest32,
    transformation: Digest32,
    conformance: Digest32,
    method: Digest32,
    evidence: Digest32,
}

impl AutomaticActionEvaluation {
    pub(crate) fn new(
        input: AutomaticEvaluationInput<'_>,
        execution_class: AutomaticExecutionClass,
    ) -> Result<Self, TaskPolicyError> {
        validate_automatic_input(input, execution_class)?;
        let action_hash = automatic_action_hash(input, execution_class)?;
        let statement_hash = domain_digest(
            AUTOMATIC_REQUIREMENT_DOMAIN,
            &AutomaticRequirementBinding {
                schema_version: AUTOMATIC_ACTION_EVALUATION_SCHEMA_VERSION,
                task_objective_hash: input.task_policy.task_objective_hash,
                task_policy_hash: input.task_policy_hash,
                action_hash,
            },
        )?;
        let task_requirement = build_automatic_requirement(input, action_hash, statement_hash);
        let requirement_hash = task_requirement
            .digest()
            .map_err(|_| TaskPolicyError::InvalidEvaluationRecord)?;
        let transformation_step =
            build_automatic_transformation(input, action_hash, statement_hash);
        let transformation_step_hash = transformation_step
            .digest()
            .map_err(|_| TaskPolicyError::InvalidEvaluationRecord)?;
        let conformance_evaluation = build_automatic_conformance(
            input,
            execution_class,
            action_hash,
            requirement_hash,
            transformation_step_hash,
        )?;
        let conformance_evaluation_hash = conformance_evaluation
            .digest()
            .map_err(|_| TaskPolicyError::InvalidEvaluationRecord)?;
        let assessment = PolicyEvaluator::evaluate_conformance(
            EnforcementDecision::Allow,
            &task_requirement,
            &transformation_step,
            Some(&conformance_evaluation),
        )
        .map_err(|_| TaskPolicyError::InvalidEvaluationRecord)?;
        if !assessment.decision().allows_automatic()
            || assessment.reasons() != [DecisionReason::RequirementSatisfied]
        {
            return Err(TaskPolicyError::UnsafeEvaluationDecision);
        }
        let policy_decision = local_policy_decision(
            derived_policy_uuid(
                AUTOMATIC_POLICY_DECISION_ID_DOMAIN,
                input.task_id,
                input.proposal_digest,
                input.task_policy_hash,
                action_hash,
                input.policy_epoch,
                input.evaluated_at,
            ),
            input.task_policy_hash,
            action_hash,
            requirement_hash,
            transformation_step_hash,
            vec![conformance_evaluation_hash],
            input.policy_epoch,
            input.evaluated_at,
            &assessment,
        );
        let policy_decision_hash = policy_decision
            .digest()
            .map_err(|_| TaskPolicyError::InvalidEvaluationRecord)?;
        let record = Self {
            schema_version: AUTOMATIC_ACTION_EVALUATION_SCHEMA_VERSION,
            task_id: input.task_id,
            session_id: input.session_id.to_owned(),
            run_id: input.run_id.to_owned(),
            tool_call_id: input.tool_call_id.to_owned(),
            proposal_digest: input.proposal_digest,
            task_policy_hash: input.task_policy_hash,
            execution_class,
            task_requirement,
            transformation_step,
            conformance_evaluation,
            policy_decision,
            policy_decision_hash,
        };
        record.validate_for(input, execution_class)?;
        Ok(record)
    }

    pub(crate) fn validate_for(
        &self,
        input: AutomaticEvaluationInput<'_>,
        execution_class: AutomaticExecutionClass,
    ) -> Result<(), TaskPolicyError> {
        validate_automatic_input(input, execution_class)?;
        self.validate_scope(input, execution_class)?;
        let expected = self.expected_evaluation(input, execution_class)?;
        self.validate_artifact_chain(input, &expected)?;
        self.validate_deterministic_identities(input, &expected)?;
        self.validate_policy_outcome(input, &expected)
    }

    fn validate_scope(
        &self,
        input: AutomaticEvaluationInput<'_>,
        execution_class: AutomaticExecutionClass,
    ) -> Result<(), TaskPolicyError> {
        if self.schema_version != AUTOMATIC_ACTION_EVALUATION_SCHEMA_VERSION
            || self.task_id != input.task_id
            || self.session_id != input.session_id
            || self.run_id != input.run_id
            || self.tool_call_id != input.tool_call_id
            || self.proposal_digest != input.proposal_digest
            || self.task_policy_hash != input.task_policy_hash
            || self.execution_class != execution_class
        {
            return Err(TaskPolicyError::AutomaticEvaluationScopeMismatch);
        }
        validate_text(&self.session_id, "session_id", MAX_SESSION_ID_BYTES)?;
        validate_text(&self.run_id, "run_id", MAX_RUN_ID_BYTES)?;
        validate_text(&self.tool_call_id, "tool_call_id", MAX_TOOL_CALL_ID_BYTES)?;
        Ok(())
    }

    fn expected_evaluation(
        &self,
        input: AutomaticEvaluationInput<'_>,
        execution_class: AutomaticExecutionClass,
    ) -> Result<ExpectedAutomaticEvaluation, TaskPolicyError> {
        let action_hash = automatic_action_hash(input, execution_class)?;
        let statement_hash = domain_digest(
            AUTOMATIC_REQUIREMENT_DOMAIN,
            &AutomaticRequirementBinding {
                schema_version: AUTOMATIC_ACTION_EVALUATION_SCHEMA_VERSION,
                task_objective_hash: input.task_policy.task_objective_hash,
                task_policy_hash: input.task_policy_hash,
                action_hash,
            },
        )?;
        let requirement_hash = self
            .task_requirement
            .digest()
            .map_err(|_| TaskPolicyError::InvalidEvaluationRecord)?;
        let transformation_hash = self
            .transformation_step
            .digest()
            .map_err(|_| TaskPolicyError::InvalidEvaluationRecord)?;
        let conformance_hash = self
            .conformance_evaluation
            .digest()
            .map_err(|_| TaskPolicyError::InvalidEvaluationRecord)?;
        Ok(ExpectedAutomaticEvaluation {
            action: action_hash,
            statement: statement_hash,
            requirement: requirement_hash,
            transformation: transformation_hash,
            conformance: conformance_hash,
            method: Digest32::sha256(AUTOMATIC_METHOD_PROFILE),
            evidence: automatic_evidence_hash(input, execution_class, action_hash)?,
        })
    }

    fn validate_artifact_chain(
        &self,
        input: AutomaticEvaluationInput<'_>,
        expected: &ExpectedAutomaticEvaluation,
    ) -> Result<(), TaskPolicyError> {
        if self.task_requirement.task_hash != input.task_policy_hash
            || self.task_requirement.statement_hash != expected.statement
            || self.task_requirement.minimum_score != NormalizedScore::ONE
            || self.transformation_step.task_hash != input.task_policy_hash
            || self.transformation_step.sequence != 0
            || self.transformation_step.parent_step_hash.is_some()
            || self.transformation_step.source_stage != WorkflowStage::Request
            || self.transformation_step.source_hash != expected.statement
            || self.transformation_step.target_stage != WorkflowStage::Action
            || self.transformation_step.target_hash != expected.action
            || self.transformation_step.recorded_at != input.evaluated_at
            || self.conformance_evaluation.task_hash != input.task_policy_hash
            || self.conformance_evaluation.sequence != 0
            || self.conformance_evaluation.parent_evaluation_hash.is_some()
            || self.conformance_evaluation.requirement_hash != expected.requirement
            || self.conformance_evaluation.transformation_step_hash != expected.transformation
            || self.conformance_evaluation.result != ConformanceResult::Conformant
            || self.conformance_evaluation.score.lower() != NormalizedScore::ONE
            || self.conformance_evaluation.score.estimate() != NormalizedScore::ONE
            || self.conformance_evaluation.score.upper() != NormalizedScore::ONE
            || self.conformance_evaluation.method_hash != expected.method
            || self.conformance_evaluation.evidence_hash != expected.evidence
            || self.conformance_evaluation.evaluated_at != input.evaluated_at
        {
            return Err(TaskPolicyError::InvalidEvaluationRecord);
        }
        Ok(())
    }

    fn validate_deterministic_identities(
        &self,
        input: AutomaticEvaluationInput<'_>,
        expected: &ExpectedAutomaticEvaluation,
    ) -> Result<(), TaskPolicyError> {
        let expected_requirement_id = derived_policy_uuid(
            AUTOMATIC_REQUIREMENT_ID_DOMAIN,
            input.task_id,
            input.proposal_digest,
            input.task_policy_hash,
            expected.action,
            input.policy_epoch,
            input.evaluated_at,
        );
        let expected_step_id = derived_policy_uuid(
            AUTOMATIC_TRANSFORMATION_ID_DOMAIN,
            input.task_id,
            input.proposal_digest,
            input.task_policy_hash,
            expected.action,
            input.policy_epoch,
            input.evaluated_at,
        );
        let expected_evaluation_id = derived_policy_uuid(
            AUTOMATIC_CONFORMANCE_ID_DOMAIN,
            input.task_id,
            input.proposal_digest,
            input.task_policy_hash,
            expected.action,
            input.policy_epoch,
            input.evaluated_at,
        );
        let expected_decision_id = derived_policy_uuid(
            AUTOMATIC_POLICY_DECISION_ID_DOMAIN,
            input.task_id,
            input.proposal_digest,
            input.task_policy_hash,
            expected.action,
            input.policy_epoch,
            input.evaluated_at,
        );
        if self.task_requirement.requirement_id != expected_requirement_id
            || self.transformation_step.step_id != expected_step_id
            || self.conformance_evaluation.conformance_id != expected_evaluation_id
            || self.policy_decision.decision_id != expected_decision_id
        {
            return Err(TaskPolicyError::NondeterministicEvaluationIdentity);
        }
        Ok(())
    }

    fn validate_policy_outcome(
        &self,
        input: AutomaticEvaluationInput<'_>,
        expected: &ExpectedAutomaticEvaluation,
    ) -> Result<(), TaskPolicyError> {
        let assessment = PolicyEvaluator::evaluate_conformance(
            EnforcementDecision::Allow,
            &self.task_requirement,
            &self.transformation_step,
            Some(&self.conformance_evaluation),
        )
        .map_err(|_| TaskPolicyError::InvalidEvaluationRecord)?;
        if !assessment.decision().allows_automatic()
            || assessment.reasons() != [DecisionReason::RequirementSatisfied]
            || self.policy_decision.task_hash != input.task_policy_hash
            || self.policy_decision.action_hash != expected.action
            || self.policy_decision.requirement_hashes != [expected.requirement]
            || self.policy_decision.transformation_step_hashes != [expected.transformation]
            || self.policy_decision.conformance_evaluation_hashes != [expected.conformance]
            || !self.policy_decision.resource_request_hashes.is_empty()
            || !self.policy_decision.resource_quota_hashes.is_empty()
            || !self.policy_decision.resource_reservation_hashes.is_empty()
            || self.policy_decision.baseline_decision != assessment.baseline_decision()
            || self.policy_decision.decision != assessment.decision()
            || self.policy_decision.reasons != assessment.reasons()
            || self.policy_decision.policy_epoch != input.policy_epoch
            || self.policy_decision.evaluated_at != input.evaluated_at
            || self
                .policy_decision
                .digest()
                .map_err(|_| TaskPolicyError::InvalidEvaluationRecord)?
                != self.policy_decision_hash
        {
            return Err(TaskPolicyError::UnsafeEvaluationDecision);
        }
        Ok(())
    }

    pub(crate) fn digest(&self) -> Result<Digest32, TaskPolicyError> {
        require_digest(self.policy_decision_hash, "policy_decision_hash")?;
        domain_digest(AUTOMATIC_ACTION_EVALUATION_DIGEST_DOMAIN, self)
    }

    pub(crate) fn conformance_evaluation_hash(&self) -> Result<Digest32, TaskPolicyError> {
        self.conformance_evaluation
            .digest()
            .map_err(|_| TaskPolicyError::InvalidEvaluationRecord)
    }
}

fn validate_automatic_input(
    input: AutomaticEvaluationInput<'_>,
    execution_class: AutomaticExecutionClass,
) -> Result<(), TaskPolicyError> {
    if input.task_id.is_nil() || input.policy_epoch == 0 {
        return Err(TaskPolicyError::AutomaticEvaluationScopeMismatch);
    }
    validate_text(input.session_id, "session_id", MAX_SESSION_ID_BYTES)?;
    validate_text(input.run_id, "run_id", MAX_RUN_ID_BYTES)?;
    validate_text(input.tool_call_id, "tool_call_id", MAX_TOOL_CALL_ID_BYTES)?;
    validate_text(input.extension_id, "extension_id", MAX_EXTENSION_BYTES)?;
    validate_text(input.tool_name, "tool_name", MAX_TOOL_BYTES)?;
    require_digest(input.proposal_digest, "proposal_digest")?;
    require_digest(input.task_policy_hash, "task_policy_hash")?;
    if input.evaluated_at <= 0
        || input.task_policy.digest()? != input.task_policy_hash
        || AutomaticExecutionClass::for_tool(input.extension_id, input.tool_name)
            != Some(execution_class)
        || !input
            .task_policy
            .allows_automatic(input.extension_id, input.tool_name)
    {
        return Err(TaskPolicyError::AutomaticEvaluationScopeMismatch);
    }
    Ok(())
}

fn automatic_action_hash(
    input: AutomaticEvaluationInput<'_>,
    execution_class: AutomaticExecutionClass,
) -> Result<Digest32, TaskPolicyError> {
    domain_digest(
        AUTOMATIC_ACTION_HASH_DOMAIN,
        &AutomaticActionBinding {
            schema_version: AUTOMATIC_ACTION_EVALUATION_SCHEMA_VERSION,
            proposal_digest: input.proposal_digest,
            task_policy_hash: input.task_policy_hash,
            execution_class: execution_class.code(),
        },
    )
}

fn automatic_evidence_hash(
    input: AutomaticEvaluationInput<'_>,
    execution_class: AutomaticExecutionClass,
    action_hash: Digest32,
) -> Result<Digest32, TaskPolicyError> {
    domain_digest(
        AUTOMATIC_EVIDENCE_DOMAIN,
        &AutomaticScopeEvidence {
            schema_version: AUTOMATIC_ACTION_EVALUATION_SCHEMA_VERSION,
            proposal_digest: input.proposal_digest,
            task_policy_hash: input.task_policy_hash,
            action_hash,
            execution_class: execution_class.code(),
            local_workspace_only: VerifiedScopeClaim,
            read_only: VerifiedScopeClaim,
            protected_path_excluded: VerifiedScopeClaim,
            network_disabled: VerifiedScopeClaim,
        },
    )
}

/// Trusted resolution over one exact potentially mutating proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalDecision {
    Approved,
    Denied,
}

/// Closed native action class displayed for private approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActionType {
    CreateFile,
    OverwriteFile,
    EditFile,
    DeleteFile,
    ExecuteProcess,
    HttpsRequest,
}

/// Bounded, non-secret action summary produced by the trusted executor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionDescriptor {
    pub extension_id: String,
    pub tool_name: String,
    pub relative_path: String,
    pub action_type: ActionType,
    pub requested_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable_sha256: Option<Digest32>,
}

impl ActionDescriptor {
    fn validate(&self) -> Result<(), TaskPolicyError> {
        validate_text(&self.extension_id, "extension_id", MAX_EXTENSION_BYTES)?;
        validate_text(&self.tool_name, "tool_name", MAX_TOOL_BYTES)?;
        validate_text(
            &self.relative_path,
            "relative_path",
            MAX_APPROVAL_RELATIVE_PATH_BYTES,
        )?;
        let supported = matches!(
            (
                self.extension_id.as_str(),
                self.tool_name.as_str(),
                self.action_type
            ),
            (
                "developer",
                "write",
                ActionType::CreateFile | ActionType::OverwriteFile
            ) | ("developer", "edit", ActionType::EditFile)
                | ("developer", "delete_file", ActionType::DeleteFile)
                | ("developer", "shell", ActionType::ExecuteProcess)
                | (
                    "accordlock_network",
                    "https_request",
                    ActionType::HttpsRequest
                )
        );
        if !supported {
            return Err(TaskPolicyError::InvalidActionEnvelope);
        }
        match self.action_type {
            ActionType::ExecuteProcess => {
                let executable_path = self
                    .executable_path
                    .as_deref()
                    .ok_or(TaskPolicyError::InvalidActionEnvelope)?;
                validate_text(
                    executable_path,
                    "executable_path",
                    MAX_APPROVAL_RELATIVE_PATH_BYTES,
                )?;
                if !Path::new(executable_path).is_absolute() || self.executable_sha256.is_none() {
                    return Err(TaskPolicyError::InvalidActionEnvelope);
                }
            }
            _ if self.executable_path.is_some() || self.executable_sha256.is_some() => {
                return Err(TaskPolicyError::InvalidActionEnvelope);
            }
            _ => {}
        }
        Ok(())
    }

    fn evaluation_hash(
        &self,
        proposal_digest: Digest32,
        prestate_hash: Digest32,
    ) -> Result<Digest32, TaskPolicyError> {
        self.validate()?;
        require_digest(proposal_digest, "proposal_digest")?;
        require_digest(prestate_hash, "prestate_hash")?;
        domain_digest(
            ACTION_BINDING_DIGEST_DOMAIN,
            &ActionEvaluationBinding {
                schema_version: 2,
                proposal_digest,
                prestate_hash,
                action: self,
            },
        )
    }
}

#[derive(Serialize)]
struct ActionEvaluationBinding<'a> {
    schema_version: u16,
    proposal_digest: Digest32,
    prestate_hash: Digest32,
    action: &'a ActionDescriptor,
}

/// Runtime-generated request that a private approval must repeat exactly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionApprovalRequest {
    pub schema_version: u16,
    pub task_id: Uuid,
    pub session_id: String,
    pub run_id: String,
    pub tool_call_id: String,
    pub proposal_digest: Digest32,
    pub task_policy_hash: Digest32,
    pub prestate_hash: Digest32,
    pub action: ActionDescriptor,
    pub task_requirement: TaskRequirement,
    pub transformation_step: TransformationStep,
    pub policy_decision: PolicyDecisionRecord,
    pub policy_decision_hash: Digest32,
}

#[allow(clippy::too_many_arguments)]
fn local_policy_decision(
    decision_id: Uuid,
    task_hash: Digest32,
    action_hash: Digest32,
    requirement_hash: Digest32,
    transformation_step_hash: Digest32,
    conformance_evaluation_hashes: Vec<Digest32>,
    policy_epoch: u64,
    evaluated_at: i64,
    assessment: &PolicyEvaluation,
) -> PolicyDecisionRecord {
    PolicyDecisionRecord {
        schema_version: POLICY_DECISION_SCHEMA_VERSION,
        decision_id,
        task_hash,
        action_hash,
        sequence: 0,
        parent_decision_hash: None,
        requirement_hashes: vec![requirement_hash],
        transformation_step_hashes: vec![transformation_step_hash],
        conformance_evaluation_hashes,
        resource_request_hashes: Vec::new(),
        resource_quota_hashes: Vec::new(),
        resource_reservation_hashes: Vec::new(),
        baseline_decision: assessment.baseline_decision(),
        decision: assessment.decision(),
        reasons: assessment.reasons().to_vec(),
        policy_epoch,
        evaluated_at,
    }
}

impl ActionApprovalRequest {
    /// Constructs one deterministic policy challenge from immutable task and
    /// proposal bindings. No conformance evaluation is invented: the conservative
    /// evaluator therefore requires approval.
    ///
    /// # Errors
    ///
    /// Rejects invalid task, action, time, policy, or policy bindings.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        task_id: Uuid,
        session_id: String,
        run_id: String,
        tool_call_id: String,
        proposal_digest: Digest32,
        task_policy_hash: Digest32,
        task_objective_hash: Digest32,
        policy_epoch: u64,
        approved_at: i64,
        prestate_hash: Digest32,
        action: ActionDescriptor,
    ) -> Result<Self, TaskPolicyError> {
        if task_id.is_nil() {
            return Err(TaskPolicyError::NilIdentifier);
        }
        if approved_at <= 0 {
            return Err(TaskPolicyError::InvalidEvaluationTime);
        }
        let action_hash = action.evaluation_hash(proposal_digest, prestate_hash)?;
        let task_requirement = TaskRequirement {
            schema_version: TASK_REQUIREMENT_SCHEMA_VERSION,
            requirement_id: derived_policy_uuid(
                TASK_REQUIREMENT_ID_DOMAIN,
                task_id,
                proposal_digest,
                prestate_hash,
                action_hash,
                policy_epoch,
                approved_at,
            ),
            task_hash: task_policy_hash,
            statement_hash: task_objective_hash,
            minimum_score: NormalizedScore::ONE,
        };
        let requirement_hash = task_requirement
            .digest()
            .map_err(|_| TaskPolicyError::InvalidEvaluationRecord)?;
        let transformation_step = TransformationStep {
            schema_version: TRANSFORMATION_STEP_SCHEMA_VERSION,
            step_id: derived_policy_uuid(
                TRANSFORMATION_STEP_ID_DOMAIN,
                task_id,
                proposal_digest,
                prestate_hash,
                action_hash,
                policy_epoch,
                approved_at,
            ),
            task_hash: task_policy_hash,
            sequence: 0,
            parent_step_hash: None,
            source_stage: WorkflowStage::Request,
            source_hash: task_objective_hash,
            target_stage: WorkflowStage::Action,
            target_hash: action_hash,
            recorded_at: approved_at,
        };
        let transformation_step_hash = transformation_step
            .digest()
            .map_err(|_| TaskPolicyError::InvalidEvaluationRecord)?;
        let assessment = PolicyEvaluator::evaluate_conformance(
            EnforcementDecision::Allow,
            &task_requirement,
            &transformation_step,
            None,
        )
        .map_err(|_| TaskPolicyError::InvalidEvaluationRecord)?;
        if assessment.decision() != EnforcementDecision::RequireApproval
            || assessment.reasons() != [DecisionReason::ConformanceEvaluationMissing]
        {
            return Err(TaskPolicyError::UnsafeEvaluationDecision);
        }
        let policy_decision = local_policy_decision(
            derived_policy_uuid(
                POLICY_DECISION_ID_DOMAIN,
                task_id,
                proposal_digest,
                prestate_hash,
                action_hash,
                policy_epoch,
                approved_at,
            ),
            task_policy_hash,
            action_hash,
            requirement_hash,
            transformation_step_hash,
            Vec::new(),
            policy_epoch,
            approved_at,
            &assessment,
        );
        let policy_decision_hash = policy_decision
            .digest()
            .map_err(|_| TaskPolicyError::InvalidEvaluationRecord)?;
        let context = Self {
            schema_version: ACTION_APPROVAL_SCHEMA_VERSION,
            task_id,
            session_id,
            run_id,
            tool_call_id,
            proposal_digest,
            task_policy_hash,
            prestate_hash,
            action,
            task_requirement,
            transformation_step,
            policy_decision,
            policy_decision_hash,
        };
        context.digest()?;
        Ok(context)
    }

    /// Validates and hashes the exact bounded challenge shown to the approver.
    ///
    /// # Errors
    ///
    /// Rejects malformed identity, commitment, or action-summary data.
    pub fn digest(&self) -> Result<Digest32, TaskPolicyError> {
        if self.schema_version != ACTION_APPROVAL_SCHEMA_VERSION || self.task_id.is_nil() {
            return Err(TaskPolicyError::WrongSchema("policy approval context"));
        }
        validate_text(&self.session_id, "session_id", MAX_SESSION_ID_BYTES)?;
        validate_text(&self.run_id, "run_id", MAX_RUN_ID_BYTES)?;
        validate_text(&self.tool_call_id, "tool_call_id", MAX_TOOL_CALL_ID_BYTES)?;
        require_digest(self.proposal_digest, "proposal_digest")?;
        require_digest(self.task_policy_hash, "task_policy_hash")?;
        require_digest(self.prestate_hash, "prestate_hash")?;
        self.action.validate()?;
        validate_policy_records(
            self.task_id,
            self.proposal_digest,
            self.task_policy_hash,
            self.prestate_hash,
            Some(&self.action),
            &self.task_requirement,
            &self.transformation_step,
            &self.policy_decision,
            self.policy_decision_hash,
        )?;
        domain_digest(ACTION_APPROVAL_REQUEST_DIGEST_DOMAIN, self)
    }
}

/// Single-use approval installed only through the inherited private ALC1 channel.
///
/// The proposal digest commits all arguments; `prestate_hash` commits the
/// executor-observed target state. An approval can therefore authorize neither a
/// changed proposal nor a changed target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionApproval {
    pub schema_version: u16,
    pub approval_id: Uuid,
    pub task_id: Uuid,
    pub session_id: String,
    pub run_id: String,
    pub tool_call_id: String,
    pub proposal_digest: Digest32,
    pub task_policy_hash: Digest32,
    pub prestate_hash: Digest32,
    pub approval_request_hash: Digest32,
    pub task_requirement: TaskRequirement,
    pub transformation_step: TransformationStep,
    pub policy_decision: PolicyDecisionRecord,
    pub policy_decision_hash: Digest32,
    pub decision: ApprovalDecision,
    pub approval_evidence_hash: Digest32,
    pub decided_at: i64,
    pub expires_at: i64,
}

impl ActionApproval {
    /// Copies the complete policy context into one signed approval record.
    /// Callers choose only the approval identity, decision,
    /// evidence commitment, and bounded validity window.
    ///
    /// # Errors
    ///
    /// Rejects any invalid context or resulting approval.
    #[allow(clippy::too_many_arguments)]
    pub fn for_context(
        context: &ActionApprovalRequest,
        approval_id: Uuid,
        decision: ApprovalDecision,
        approval_evidence_hash: Digest32,
        decided_at: i64,
        expires_at: i64,
    ) -> Result<Self, TaskPolicyError> {
        let approval = Self {
            schema_version: ACTION_APPROVAL_SCHEMA_VERSION,
            approval_id,
            task_id: context.task_id,
            session_id: context.session_id.clone(),
            run_id: context.run_id.clone(),
            tool_call_id: context.tool_call_id.clone(),
            proposal_digest: context.proposal_digest,
            task_policy_hash: context.task_policy_hash,
            prestate_hash: context.prestate_hash,
            approval_request_hash: context.digest()?,
            task_requirement: context.task_requirement.clone(),
            transformation_step: context.transformation_step.clone(),
            policy_decision: context.policy_decision.clone(),
            policy_decision_hash: context.policy_decision_hash,
            decision,
            approval_evidence_hash,
            decided_at,
            expires_at,
        };
        approval.validate()?;
        Ok(approval)
    }

    /// Revalidates the complete single-use approval before durable insertion.
    ///
    /// # Errors
    ///
    /// Rejects unsupported, unbounded, zero-commitment, or invalid-time data.
    pub fn validate(&self) -> Result<(), TaskPolicyError> {
        if self.schema_version != ACTION_APPROVAL_SCHEMA_VERSION {
            return Err(TaskPolicyError::WrongSchema("action approval"));
        }
        if self.approval_id.is_nil() || self.task_id.is_nil() {
            return Err(TaskPolicyError::NilIdentifier);
        }
        validate_text(&self.session_id, "session_id", MAX_SESSION_ID_BYTES)?;
        validate_text(&self.run_id, "run_id", MAX_RUN_ID_BYTES)?;
        validate_text(&self.tool_call_id, "tool_call_id", MAX_TOOL_CALL_ID_BYTES)?;
        require_digest(self.proposal_digest, "proposal_digest")?;
        require_digest(self.task_policy_hash, "task_policy_hash")?;
        require_digest(self.prestate_hash, "prestate_hash")?;
        require_digest(self.approval_request_hash, "approval_request_hash")?;
        require_digest(self.policy_decision_hash, "policy_decision_hash")?;
        require_digest(self.approval_evidence_hash, "approval_evidence_hash")?;
        validate_policy_records(
            self.task_id,
            self.proposal_digest,
            self.task_policy_hash,
            self.prestate_hash,
            None,
            &self.task_requirement,
            &self.transformation_step,
            &self.policy_decision,
            self.policy_decision_hash,
        )?;
        validate_window(
            self.decided_at,
            self.expires_at,
            MAX_ACTION_APPROVAL_LIFETIME_SECONDS,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthorizationDenial {
    ExecutionContextRequired,
    ApprovalRequired,
    ApprovalDenied,
    ApprovalExpired,
    ApprovalScopeMismatch,
    ApprovalAlreadyUsed,
}

impl AuthorizationDenial {
    pub(crate) const fn reason_code(self) -> &'static str {
        match self {
            Self::ExecutionContextRequired => "EXECUTION_CONTEXT_REQUIRED",
            Self::ApprovalRequired => "ACTION_APPROVAL_REQUIRED",
            Self::ApprovalDenied => "ACTION_APPROVAL_DENIED",
            Self::ApprovalExpired => "ACTION_APPROVAL_EXPIRED",
            Self::ApprovalScopeMismatch => "ACTION_APPROVAL_SCOPE_MISMATCH",
            Self::ApprovalAlreadyUsed => "ACTION_APPROVAL_ALREADY_USED",
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_policy_records(
    task_id: Uuid,
    proposal_digest: Digest32,
    task_policy_hash: Digest32,
    prestate_hash: Digest32,
    action: Option<&ActionDescriptor>,
    task_requirement: &TaskRequirement,
    transformation_step: &TransformationStep,
    policy_decision: &PolicyDecisionRecord,
    policy_decision_hash: Digest32,
) -> Result<(), TaskPolicyError> {
    task_requirement
        .validate()
        .map_err(|_| TaskPolicyError::InvalidEvaluationRecord)?;
    transformation_step
        .validate()
        .map_err(|_| TaskPolicyError::InvalidEvaluationRecord)?;
    policy_decision
        .validate()
        .map_err(|_| TaskPolicyError::InvalidEvaluationRecord)?;
    let requirement_hash = task_requirement
        .digest()
        .map_err(|_| TaskPolicyError::InvalidEvaluationRecord)?;
    let transformation_step_hash = transformation_step
        .digest()
        .map_err(|_| TaskPolicyError::InvalidEvaluationRecord)?;
    let computed_policy_decision_hash = policy_decision
        .digest()
        .map_err(|_| TaskPolicyError::InvalidEvaluationRecord)?;
    let action_hash = policy_decision.action_hash;
    if task_requirement.task_hash != task_policy_hash
        || task_requirement.minimum_score != NormalizedScore::ONE
        || transformation_step.task_hash != task_policy_hash
        || transformation_step.source_stage != WorkflowStage::Request
        || transformation_step.source_hash != task_requirement.statement_hash
        || transformation_step.target_stage != WorkflowStage::Action
        || transformation_step.target_hash != action_hash
        || transformation_step.recorded_at != policy_decision.evaluated_at
        || policy_decision.task_hash != task_policy_hash
        || policy_decision.requirement_hashes != [requirement_hash]
        || policy_decision.transformation_step_hashes != [transformation_step_hash]
        || !policy_decision.conformance_evaluation_hashes.is_empty()
        || !policy_decision.resource_request_hashes.is_empty()
        || !policy_decision.resource_quota_hashes.is_empty()
        || !policy_decision.resource_reservation_hashes.is_empty()
        || computed_policy_decision_hash != policy_decision_hash
    {
        return Err(TaskPolicyError::InvalidEvaluationRecord);
    }
    if action.is_some_and(|value| {
        value.evaluation_hash(proposal_digest, prestate_hash) != Ok(action_hash)
    }) {
        return Err(TaskPolicyError::InvalidEvaluationRecord);
    }
    let assessment = PolicyEvaluator::evaluate_conformance(
        EnforcementDecision::Allow,
        task_requirement,
        transformation_step,
        None,
    )
    .map_err(|_| TaskPolicyError::InvalidEvaluationRecord)?;
    if assessment.decision() != EnforcementDecision::RequireApproval
        || assessment.reasons() != [DecisionReason::ConformanceEvaluationMissing]
        || policy_decision.baseline_decision != assessment.baseline_decision()
        || policy_decision.decision != assessment.decision()
        || policy_decision.reasons != assessment.reasons()
    {
        return Err(TaskPolicyError::UnsafeEvaluationDecision);
    }
    let expected_requirement_id = derived_policy_uuid(
        TASK_REQUIREMENT_ID_DOMAIN,
        task_id,
        proposal_digest,
        prestate_hash,
        action_hash,
        policy_decision.policy_epoch,
        policy_decision.evaluated_at,
    );
    let expected_step_id = derived_policy_uuid(
        TRANSFORMATION_STEP_ID_DOMAIN,
        task_id,
        proposal_digest,
        prestate_hash,
        action_hash,
        policy_decision.policy_epoch,
        policy_decision.evaluated_at,
    );
    let expected_decision_id = derived_policy_uuid(
        POLICY_DECISION_ID_DOMAIN,
        task_id,
        proposal_digest,
        prestate_hash,
        action_hash,
        policy_decision.policy_epoch,
        policy_decision.evaluated_at,
    );
    if task_requirement.requirement_id != expected_requirement_id
        || transformation_step.step_id != expected_step_id
        || policy_decision.decision_id != expected_decision_id
    {
        return Err(TaskPolicyError::NondeterministicEvaluationIdentity);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn derived_policy_uuid(
    domain: &[u8],
    task_id: Uuid,
    proposal_digest: Digest32,
    prestate_hash: Digest32,
    action_hash: Digest32,
    policy_epoch: u64,
    approved_at: i64,
) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(task_id.as_bytes());
    hasher.update(proposal_digest.as_bytes());
    hasher.update(prestate_hash.as_bytes());
    hasher.update(action_hash.as_bytes());
    hasher.update(policy_epoch.to_be_bytes());
    hasher.update(approved_at.to_be_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn domain_digest<T: Serialize + ?Sized>(
    domain: &[u8],
    value: &T,
) -> Result<Digest32, TaskPolicyError> {
    let canonical = canonical_json_bytes(value).map_err(|_| TaskPolicyError::CanonicalEncoding)?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(
        u64::try_from(canonical.len())
            .map_err(|_| TaskPolicyError::CanonicalEncoding)?
            .to_be_bytes(),
    );
    hasher.update(canonical);
    Ok(Digest32::from_bytes(hasher.finalize().into()))
}

fn validate_text(
    value: &str,
    field: &'static str,
    maximum_bytes: usize,
) -> Result<(), TaskPolicyError> {
    if value.is_empty()
        || value.len() > maximum_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(TaskPolicyError::InvalidText(field));
    }
    Ok(())
}

fn validate_protected_path(value: &str) -> Result<(), TaskPolicyError> {
    validate_text(value, "protected_path", MAX_APPROVAL_RELATIVE_PATH_BYTES)?;
    if value != value.to_ascii_lowercase()
        || !value.is_ascii()
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains(['\\', ':'])
        || value
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(TaskPolicyError::InvalidProtectedPaths);
    }
    Ok(())
}

fn validate_window(start: i64, end: i64, maximum: i64) -> Result<(), TaskPolicyError> {
    if start < 0 || end <= start || end.saturating_sub(start) > maximum {
        return Err(TaskPolicyError::InvalidWindow);
    }
    Ok(())
}

fn require_digest(value: Digest32, field: &'static str) -> Result<(), TaskPolicyError> {
    if value.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(TaskPolicyError::ZeroDigest(field));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum TaskPolicyError {
    #[error("unsupported {0} schema")]
    WrongSchema(&'static str),
    #[error("policy field is invalid: {0}")]
    InvalidText(&'static str),
    #[error("policy digest must not be zero: {0}")]
    ZeroDigest(&'static str),
    #[error("policy identifier must not be nil")]
    NilIdentifier,
    #[error("action approval window is invalid")]
    InvalidWindow,
    #[error("only bounded read/tree capabilities may be automatic")]
    UnsafePreauthorizedCapability,
    #[error("action descriptor is invalid")]
    InvalidActionEnvelope,
    #[error("policy evaluation time must come from a positive task authorization time")]
    InvalidEvaluationTime,
    #[error("policy evaluation record is malformed or not exactly bound")]
    InvalidEvaluationRecord,
    #[error("automatic evaluation is outside the validated local read-only scope")]
    AutomaticEvaluationScopeMismatch,
    #[error("policy evaluation attempted to authorize without required action approval")]
    UnsafeEvaluationDecision,
    #[error("policy evaluation identifier is not deterministic for this challenge")]
    NondeterministicEvaluationIdentity,
    #[error("automatic policy capability set is duplicate, unsorted, or excessive")]
    InvalidAutomaticCapabilities,
    #[error("protected policy path set is noncanonical, duplicate, or excessive")]
    InvalidProtectedPaths,
    #[error("policy canonical encoding failed")]
    CanonicalEncoding,
}

#[cfg(test)]
mod tests {
    use accordlock_agent_protocol::Digest32;
    use accordlock_evaluation::{DecisionReason, EnforcementDecision};
    use tempfile::TempDir;
    use uuid::Uuid;

    use super::{
        ActionApproval, ActionApprovalRequest, ActionDescriptor, ActionType, ApprovalDecision,
        AutomaticActionEvaluation, AutomaticEvaluationInput, AutomaticExecutionClass,
        PreauthorizedCapability, TaskPolicy, TaskPolicyError,
    };
    use crate::model::{ApprovedSession, Capability};

    fn approval_request(
        tool_call_id: &str,
        relative_path: &str,
    ) -> Result<ActionApprovalRequest, TaskPolicyError> {
        ActionApprovalRequest::new(
            Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
                .unwrap_or_else(|error| unreachable!("valid fixture UUID: {error}")),
            "session-1".to_owned(),
            "run-1".to_owned(),
            tool_call_id.to_owned(),
            Digest32::sha256(format!("proposal:{tool_call_id}").as_bytes()),
            Digest32::sha256(b"policy-policy"),
            Digest32::sha256(b"task-objective"),
            17,
            1_700_000_000,
            Digest32::sha256(format!("prestate:{relative_path}").as_bytes()),
            ActionDescriptor {
                extension_id: "developer".to_owned(),
                tool_name: "write".to_owned(),
                relative_path: relative_path.to_owned(),
                action_type: ActionType::CreateFile,
                requested_bytes: 7,
                executable_path: None,
                executable_sha256: None,
            },
        )
    }

    #[test]
    fn desktop_task_policy_vector_is_stable() -> Result<(), Box<dyn std::error::Error>> {
        let policy = TaskPolicy::new(
            "sha256:fce6cd1e443abd52a2c0c67543ab4cfa3d0947956331c03f9108986932db9a10"
                .parse::<Digest32>()?,
            [
                PreauthorizedCapability::new("developer", "read"),
                PreauthorizedCapability::new("developer", "tree"),
            ],
            [
                ".accordlock".to_owned(),
                ".env".to_owned(),
                ".git".to_owned(),
            ],
        )?;

        assert_eq!(
            policy.digest()?.to_string(),
            "sha256:e7be61a778e979f814577bfe6146acabf320a3324d8c27c89c694335575e5994"
        );

        let workspace = TempDir::new()?;
        let approval = ApprovedSession::new(
            Uuid::new_v4(),
            "desktop-session",
            "desktop-run",
            workspace.path(),
            1,
            policy,
            [
                Capability::new("developer", "edit"),
                Capability::new("developer", "read"),
                Capability::new("developer", "tree"),
                Capability::new("developer", "write"),
            ],
            1,
            301,
        )?;
        assert!(approval.authorizes("developer", "read"));
        assert!(approval.authorizes("developer", "tree"));
        assert!(approval.authorizes("developer", "write"));
        approval.validate()?;
        Ok(())
    }

    #[test]
    fn missing_conformance_evaluation_requires_deterministic_approval()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = approval_request("call-1", "notes.txt")?;
        let retry = approval_request("call-1", "notes.txt")?;

        assert_eq!(first, retry);
        assert_eq!(
            first.policy_decision.baseline_decision,
            EnforcementDecision::Allow
        );
        assert_eq!(
            first.policy_decision.decision,
            EnforcementDecision::RequireApproval
        );
        assert_eq!(
            first.policy_decision.reasons,
            [DecisionReason::ConformanceEvaluationMissing]
        );
        assert!(
            first
                .policy_decision
                .conformance_evaluation_hashes
                .is_empty()
        );
        assert_eq!(first.policy_decision_hash, first.policy_decision.digest()?);
        assert_eq!(first.transformation_step.recorded_at, 1_700_000_000);
        assert_eq!(first.policy_decision.evaluated_at, 1_700_000_000);
        Ok(())
    }

    #[test]
    fn automatic_read_evaluation_is_exact_auditable_and_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let task_id = Uuid::parse_str("cccccccc-cccc-4ccc-8ccc-cccccccccccc")?;
        let policy = TaskPolicy::new(
            Digest32::sha256(b"inspect the approved workspace"),
            [PreauthorizedCapability::new("developer", "read")],
            [".env".to_owned()],
        )?;
        let policy_hash = policy.digest()?;
        let input = AutomaticEvaluationInput {
            task_id,
            session_id: "session-read",
            run_id: "run-read",
            tool_call_id: "call-read",
            proposal_digest: Digest32::sha256(b"exact read proposal"),
            extension_id: "developer",
            tool_name: "read",
            task_policy: &policy,
            task_policy_hash: policy_hash,
            policy_epoch: 9,
            evaluated_at: 1_700_000_100,
        };
        let evaluation =
            AutomaticActionEvaluation::new(input, AutomaticExecutionClass::LocalFileRead)?;

        evaluation.validate_for(input, AutomaticExecutionClass::LocalFileRead)?;
        assert!(evaluation.policy_decision.decision.allows_automatic());
        assert_eq!(
            evaluation.policy_decision.conformance_evaluation_hashes,
            [evaluation.conformance_evaluation_hash()?]
        );
        assert_ne!(evaluation.digest()?.as_bytes(), &[0_u8; 32]);

        let mut substituted = evaluation.clone();
        substituted.conformance_evaluation.evidence_hash =
            Digest32::sha256(b"substituted structural evidence");
        assert_eq!(
            substituted.validate_for(input, AutomaticExecutionClass::LocalFileRead),
            Err(TaskPolicyError::InvalidEvaluationRecord)
        );
        assert_eq!(
            AutomaticActionEvaluation::new(input, AutomaticExecutionClass::LocalDirectoryTree),
            Err(TaskPolicyError::AutomaticEvaluationScopeMismatch)
        );
        Ok(())
    }

    #[test]
    fn approval_echoes_request_and_rejects_decision_substitution()
    -> Result<(), Box<dyn std::error::Error>> {
        let context = approval_request("call-1", "notes.txt")?;
        let approval = ActionApproval::for_context(
            &context,
            Uuid::parse_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")?,
            ApprovalDecision::Approved,
            Digest32::sha256(b"human-checkpoint"),
            1_700_000_001,
            1_700_000_060,
        )?;

        assert_eq!(approval.task_requirement, context.task_requirement);
        assert_eq!(approval.transformation_step, context.transformation_step);
        assert_eq!(approval.policy_decision, context.policy_decision);
        assert_eq!(approval.policy_decision_hash, context.policy_decision_hash);

        let mut substituted_hash = approval.clone();
        substituted_hash.policy_decision_hash = Digest32::sha256(b"substituted-decision");
        assert_eq!(
            substituted_hash.validate(),
            Err(TaskPolicyError::InvalidEvaluationRecord)
        );

        let other = approval_request("call-2", "other.txt")?;
        let mut substituted_record = approval;
        substituted_record.policy_decision = other.policy_decision;
        substituted_record.policy_decision_hash = other.policy_decision_hash;
        assert_eq!(
            substituted_record.validate(),
            Err(TaskPolicyError::InvalidEvaluationRecord)
        );
        Ok(())
    }
}
