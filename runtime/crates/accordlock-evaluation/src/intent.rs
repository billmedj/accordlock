use accordlock_protocol::{Digest32, canonical_hash};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::policy::{DecisionReason, EnforcementDecision, PolicyEvaluation};
use crate::{
    MAX_EVALUATION_BINDINGS, NormalizedScore, PolicyEvaluationError, ScoreInterval,
    TaskRequirement, TransformationStep, WorkflowStage,
};

/// Current schema for an exact request-to-result trace.
pub const INTENT_TRACE_SCHEMA_VERSION: u16 = 2;
/// Current schema for one item of intent-conformance evidence.
pub const INTENT_EVIDENCE_SCHEMA_VERSION: u16 = 2;
/// Current schema for evidence provenance commitments.
pub const EVIDENCE_PROVENANCE_SCHEMA_VERSION: u16 = 2;
/// Current schema for evidence trust policies.
pub const EVIDENCE_TRUST_POLICY_SCHEMA_VERSION: u16 = 2;
/// Current schema for authoritative evidence-ledger snapshots.
pub const EVIDENCE_LEDGER_SNAPSHOT_SCHEMA_VERSION: u16 = 2;
/// Current schema for canonical intent-conformance summaries.
pub const INTENT_CONFORMANCE_EVALUATION_SCHEMA_VERSION: u16 = 3;
/// Current schema for a typed request-plan-action checkpoint.
pub const PRE_EXECUTION_INTENT_TRACE_SCHEMA_VERSION: u16 = 1;

/// The four mandatory checkpoints in an intent-conformance trace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntentStage {
    Request,
    Plan,
    Action,
    Result,
}

/// Canonical evaluation scope selected by the available workflow checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntentEvaluationProfile {
    /// Evaluate request, plan, and proposed action before execution.
    PreExecution,
    /// Evaluate request, plan, action, and observed result.
    CompleteTrace,
}

impl IntentEvaluationProfile {
    /// Mandatory evidence stages for this profile.
    #[must_use]
    pub const fn required_stages(self) -> &'static [IntentStage] {
        match self {
            Self::PreExecution => &[IntentStage::Request, IntentStage::Plan, IntentStage::Action],
            Self::CompleteTrace => &IntentStage::ALL,
        }
    }

    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::PreExecution => 0,
            Self::CompleteTrace => 1,
        }
    }
}

impl IntentStage {
    /// All mandatory stages, in workflow order.
    pub const ALL: [Self; 4] = [Self::Request, Self::Plan, Self::Action, Self::Result];

    /// Returns the corresponding workflow stage.
    #[must_use]
    pub const fn workflow_stage(self) -> WorkflowStage {
        match self {
            Self::Request => WorkflowStage::Request,
            Self::Plan => WorkflowStage::Plan,
            Self::Action => WorkflowStage::Action,
            Self::Result => WorkflowStage::Result,
        }
    }

    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::Request => 0,
            Self::Plan => 1,
            Self::Action => 2,
            Self::Result => 3,
        }
    }
}

/// Provider-neutral class of evaluation method.
///
/// Exact implementations, prompts, rules, and model versions are committed by
/// `method_hash` and `evaluator_hash` on [`IntentEvidence`]. The enum never
/// implies that a provider output is correct.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceMethodKind {
    DeterministicCheck,
    HumanReview,
    StatisticalModel,
    LanguageModel,
    ExternalAttestation,
}

impl EvidenceMethodKind {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::DeterministicCheck => 0,
            Self::HumanReview => 1,
            Self::StatisticalModel => 2,
            Self::LanguageModel => 3,
            Self::ExternalAttestation => 4,
        }
    }

    const fn requires_calibration(self) -> bool {
        matches!(self, Self::StatisticalModel | Self::LanguageModel)
    }
}

/// Status of the calibration evidence for an evaluation method.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CalibrationStatus {
    NotApplicable,
    Verified,
    Unverified,
    Expired,
}

impl CalibrationStatus {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::NotApplicable => 0,
            Self::Verified => 1,
            Self::Unverified => 2,
            Self::Expired => 3,
        }
    }
}

/// Categorical claim made by one evidence item.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceVerdict {
    Supports,
    Contradicts,
    Inconclusive,
}

impl EvidenceVerdict {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::Supports => 0,
            Self::Contradicts => 1,
            Self::Inconclusive => 2,
        }
    }
}

/// Exact provider-neutral provenance tuple for one evaluation method.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceProvenance {
    pub schema_version: u16,
    pub method_kind: EvidenceMethodKind,
    pub method_hash: Digest32,
    pub evaluator_hash: Digest32,
    pub calibration_status: CalibrationStatus,
    pub calibration_hash: Option<Digest32>,
}

impl EvidenceProvenance {
    /// Validates all provenance and calibration commitments.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] for an unsupported schema, a zero
    /// digest, or inconsistent calibration metadata.
    pub fn validate(&self) -> Result<(), PolicyEvaluationError> {
        require_schema(
            self.schema_version,
            EVIDENCE_PROVENANCE_SCHEMA_VERSION,
            "evidence provenance",
        )?;
        require_digest(self.method_hash, "method_hash")?;
        require_digest(self.evaluator_hash, "evaluator_hash")?;
        validate_calibration(
            self.method_kind,
            self.calibration_status,
            self.calibration_hash,
        )
    }

    /// Deterministic commitment to the complete provenance tuple.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] when validation or canonical encoding
    /// fails.
    pub fn digest(&self) -> Result<Digest32, PolicyEvaluationError> {
        self.validate()?;
        canonical_hash(self).map_err(|error| PolicyEvaluationError::Canonical(error.to_string()))
    }
}

/// Versioned allowlist of exact evidence provenance profiles.
///
/// This record makes the trust boundary explicit: declaring an evidence item
/// deterministic or calibrated is insufficient unless its complete provenance
/// digest is admitted by the current task policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceTrustPolicy {
    pub schema_version: u16,
    pub policy_id: Uuid,
    pub task_hash: Digest32,
    pub policy_epoch: u64,
    pub trusted_provenance_hashes: Vec<Digest32>,
    pub valid_from: i64,
    pub valid_until: i64,
}

impl EvidenceTrustPolicy {
    /// Validates the policy identity, scope, epoch, validity window, and exact
    /// sorted allowlist.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] for malformed or noncanonical policy
    /// material.
    pub fn validate(&self) -> Result<(), PolicyEvaluationError> {
        require_schema(
            self.schema_version,
            EVIDENCE_TRUST_POLICY_SCHEMA_VERSION,
            "evidence trust policy",
        )?;
        require_non_nil(self.policy_id, "policy_id")?;
        require_digest(self.task_hash, "task_hash")?;
        require_nonzero(self.policy_epoch, "policy_epoch")?;
        validate_sorted_digests(
            &self.trusted_provenance_hashes,
            "trusted_provenance_hashes",
            false,
        )?;
        require_time_window(self.valid_from, self.valid_until, "evidence trust policy")
    }

    /// Verifies task scope and freshness at one evaluation time.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] when the policy is malformed, belongs
    /// to another task, or is not current at `evaluated_at`.
    pub fn verify_for(
        &self,
        task_hash: Digest32,
        evaluated_at: i64,
    ) -> Result<(), PolicyEvaluationError> {
        self.validate()?;
        require_positive_time(evaluated_at, "evaluated_at")?;
        if self.task_hash != task_hash
            || evaluated_at < self.valid_from
            || evaluated_at > self.valid_until
        {
            return Err(PolicyEvaluationError::BindingMismatch(
                "evidence trust policy",
            ));
        }
        Ok(())
    }

    /// True only when the exact provenance tuple is allowlisted.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] when the policy or evidence provenance
    /// is malformed or cannot be canonically encoded.
    pub fn authorizes(&self, evidence: &IntentEvidence) -> Result<bool, PolicyEvaluationError> {
        self.validate()?;
        let provenance_hash = evidence.provenance_digest()?;
        Ok(self
            .trusted_provenance_hashes
            .binary_search(&provenance_hash)
            .is_ok())
    }

    /// Deterministic commitment to the complete trust policy.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] when validation or canonical encoding
    /// fails.
    pub fn digest(&self) -> Result<Digest32, PolicyEvaluationError> {
        self.validate()?;
        canonical_hash(self).map_err(|error| PolicyEvaluationError::Canonical(error.to_string()))
    }
}

/// Authoritative, bounded snapshot of one evidence ledger.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceLedgerSnapshot {
    pub schema_version: u16,
    pub snapshot_id: Uuid,
    pub ledger_hash: Digest32,
    pub task_hash: Digest32,
    pub trace_id: Uuid,
    pub epoch: u64,
    pub evidence_count: u64,
    pub evidence_head: Option<Digest32>,
    pub captured_at: i64,
    pub valid_until: i64,
}

impl EvidenceLedgerSnapshot {
    /// Validates snapshot identity, scope, head shape, epoch, and validity
    /// window.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] for malformed snapshot material.
    pub fn validate(&self) -> Result<(), PolicyEvaluationError> {
        require_schema(
            self.schema_version,
            EVIDENCE_LEDGER_SNAPSHOT_SCHEMA_VERSION,
            "evidence ledger snapshot",
        )?;
        require_non_nil(self.snapshot_id, "snapshot_id")?;
        require_digest(self.ledger_hash, "ledger_hash")?;
        require_digest(self.task_hash, "task_hash")?;
        require_non_nil(self.trace_id, "trace_id")?;
        require_nonzero(self.epoch, "evidence ledger epoch")?;
        match (self.evidence_count, self.evidence_head) {
            (0, None) => {}
            (0, Some(_)) | (_, None) => {
                return Err(PolicyEvaluationError::InvalidChainRoot(
                    "evidence ledger snapshot",
                ));
            }
            (_, Some(hash)) => require_digest(hash, "evidence_head")?,
        }
        require_time_window(
            self.captured_at,
            self.valid_until,
            "evidence ledger snapshot",
        )
    }

    /// Deterministic commitment to the complete ledger snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] when validation or canonical encoding
    /// fails.
    pub fn digest(&self) -> Result<Digest32, PolicyEvaluationError> {
        self.validate()?;
        canonical_hash(self).map_err(|error| PolicyEvaluationError::Canonical(error.to_string()))
    }
}

/// Trusted currentness input supplied by the ledger integration boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceLedgerExpectation {
    pub ledger_hash: Digest32,
    pub minimum_epoch: u64,
    pub evaluated_at: i64,
}

impl EvidenceLedgerExpectation {
    pub(crate) fn validate(self) -> Result<(), PolicyEvaluationError> {
        require_digest(self.ledger_hash, "expected_ledger_hash")?;
        require_nonzero(self.minimum_epoch, "minimum_ledger_epoch")?;
        require_positive_time(self.evaluated_at, "evaluated_at")
    }
}

/// Evidence state and trust policy used for one evaluation.
#[derive(Clone, Copy, Debug)]
pub struct IntentEvaluationContext<'a> {
    pub ledger_snapshot: &'a EvidenceLedgerSnapshot,
    pub ledger_expectation: EvidenceLedgerExpectation,
    pub trust_policy: &'a EvidenceTrustPolicy,
    pub minimum_trust_policy_epoch: u64,
}

#[derive(Clone, Copy, Debug)]
struct EvaluationBindings {
    profile: IntentEvaluationProfile,
    task_hash: Digest32,
    trace_hash: Digest32,
    ledger_snapshot_hash: Digest32,
    trust_policy_hash: Digest32,
    expected_ledger_hash: Digest32,
    minimum_ledger_epoch: u64,
    minimum_trust_policy_epoch: u64,
    evaluated_at: i64,
    evidence_head: Option<Digest32>,
}

impl EvaluationBindings {
    fn summary(
        self,
        evidence_hashes: Vec<Digest32>,
        outcome: IntentConformanceOutcome,
        policy_evaluation: PolicyEvaluation,
        findings: Vec<IntentFinding>,
    ) -> IntentConformanceEvaluation {
        IntentConformanceEvaluation {
            schema_version: INTENT_CONFORMANCE_EVALUATION_SCHEMA_VERSION,
            profile: self.profile,
            task_hash: self.task_hash,
            trace_hash: self.trace_hash,
            ledger_snapshot_hash: self.ledger_snapshot_hash,
            trust_policy_hash: self.trust_policy_hash,
            expected_ledger_hash: self.expected_ledger_hash,
            minimum_ledger_epoch: self.minimum_ledger_epoch,
            minimum_trust_policy_epoch: self.minimum_trust_policy_epoch,
            evaluated_at: self.evaluated_at,
            evidence_head: self.evidence_head,
            evidence_hashes,
            outcome,
            policy_evaluation,
            findings,
        }
    }

    fn invalid_summary(
        self,
        evidence_hashes: Vec<Digest32>,
        policy_evaluation: PolicyEvaluation,
        reason: IntentFindingReason,
    ) -> IntentConformanceEvaluation {
        self.summary(
            evidence_hashes,
            IntentConformanceOutcome::InvalidEvidence,
            policy_evaluation,
            vec![IntentFinding {
                requirement_hash: None,
                stage: None,
                evidence_hash: None,
                reason,
            }],
        )
    }
}

/// Exact request, plan, action, and result commitments for one task.
///
/// The transformation hashes are ordered, not sorted: they commit to the exact
/// append-only path through the workflow. Intermediate policy, specification,
/// execution, and observation stages are allowed, but the four mandatory
/// checkpoints cannot be skipped or reordered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentTrace {
    pub schema_version: u16,
    pub trace_id: Uuid,
    pub task_hash: Digest32,
    pub requirement_hashes: Vec<Digest32>,
    pub request_hash: Digest32,
    pub plan_hash: Digest32,
    pub action_hash: Digest32,
    pub result_hash: Digest32,
    pub transformation_step_hashes: Vec<Digest32>,
    pub recorded_at: i64,
}

impl IntentTrace {
    /// Validates the local record shape and canonical collections.
    ///
    /// Full workflow continuity is checked by [`Self::verify_bindings`].
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] for malformed identifiers, hashes,
    /// collections, timestamps, or an unsupported schema.
    pub fn validate(&self) -> Result<(), PolicyEvaluationError> {
        require_schema(
            self.schema_version,
            INTENT_TRACE_SCHEMA_VERSION,
            "intent trace",
        )?;
        require_non_nil(self.trace_id, "trace_id")?;
        require_digest(self.task_hash, "task_hash")?;
        validate_sorted_digests(&self.requirement_hashes, "requirement_hashes", true)?;
        require_digest(self.request_hash, "request_hash")?;
        require_digest(self.plan_hash, "plan_hash")?;
        require_digest(self.action_hash, "action_hash")?;
        require_digest(self.result_hash, "result_hash")?;
        validate_ordered_digests(
            &self.transformation_step_hashes,
            "transformation_step_hashes",
            true,
        )?;
        require_positive_time(self.recorded_at, "recorded_at")
    }

    /// Verifies every requirement and transformation against the trace.
    ///
    /// The first transformation must start at the committed request, every
    /// successor must match its exact parent and prior target, stage order must
    /// be strictly increasing, and the path must visit plan, action, and result.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] for any missing, substituted,
    /// reordered, cross-task, or discontinuous requirement or transformation.
    pub fn verify_bindings(
        &self,
        requirements: &[TaskRequirement],
        steps: &[TransformationStep],
    ) -> Result<(), PolicyEvaluationError> {
        self.validate()?;
        if requirements.len() != self.requirement_hashes.len() {
            return Err(PolicyEvaluationError::BindingMismatch(
                "intent trace requirements",
            ));
        }
        let mut requirement_hashes = Vec::with_capacity(requirements.len());
        for requirement in requirements {
            requirement.validate()?;
            if requirement.task_hash != self.task_hash {
                return Err(PolicyEvaluationError::BindingMismatch(
                    "intent trace requirement task",
                ));
            }
            requirement_hashes.push(requirement.digest()?);
        }
        requirement_hashes.sort_unstable();
        if requirement_hashes != self.requirement_hashes
            || !requirement_hashes.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(PolicyEvaluationError::BindingMismatch(
                "intent trace requirements",
            ));
        }

        if steps.len() != self.transformation_step_hashes.len() || steps.is_empty() {
            return Err(PolicyEvaluationError::BindingMismatch(
                "intent trace transformations",
            ));
        }
        for (step, expected_hash) in steps.iter().zip(&self.transformation_step_hashes) {
            step.validate()?;
            if step.task_hash != self.task_hash || step.digest()? != *expected_hash {
                return Err(PolicyEvaluationError::BindingMismatch(
                    "intent trace transformation",
                ));
            }
        }

        let first = &steps[0];
        if first.sequence != 0
            || first.parent_step_hash.is_some()
            || first.source_stage != WorkflowStage::Request
            || first.source_hash != self.request_hash
        {
            return Err(PolicyEvaluationError::ChainMismatch("intent trace root"));
        }

        for pair in steps.windows(2) {
            pair[1].verify_successor_of(&pair[0])?;
        }
        for step in steps {
            if step.source_stage.code() >= step.target_stage.code()
                || step.target_stage.code() > WorkflowStage::Result.code()
            {
                return Err(PolicyEvaluationError::ChainMismatch(
                    "intent trace stage order",
                ));
            }
        }

        Self::verify_checkpoint(steps, IntentStage::Plan, self.plan_hash)?;
        Self::verify_checkpoint(steps, IntentStage::Action, self.action_hash)?;
        Self::verify_checkpoint(steps, IntentStage::Result, self.result_hash)?;
        let last = &steps[steps.len() - 1];
        if last.target_stage != WorkflowStage::Result
            || last.target_hash != self.result_hash
            || last.recorded_at > self.recorded_at
        {
            return Err(PolicyEvaluationError::ChainMismatch(
                "intent trace completion",
            ));
        }
        Ok(())
    }

    fn verify_checkpoint(
        steps: &[TransformationStep],
        stage: IntentStage,
        expected_hash: Digest32,
    ) -> Result<(), PolicyEvaluationError> {
        let mut matches = steps.iter().filter(|step| {
            step.target_stage == stage.workflow_stage() && step.target_hash == expected_hash
        });
        if matches.next().is_none() || matches.next().is_some() {
            return Err(PolicyEvaluationError::ChainMismatch(
                "intent trace checkpoint",
            ));
        }
        Ok(())
    }

    /// Returns the committed artifact hash for a mandatory stage.
    #[must_use]
    pub const fn subject_hash(&self, stage: IntentStage) -> Digest32 {
        match stage {
            IntentStage::Request => self.request_hash,
            IntentStage::Plan => self.plan_hash,
            IntentStage::Action => self.action_hash,
            IntentStage::Result => self.result_hash,
        }
    }

    /// Deterministic commitment to the complete trace.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] when validation or canonical encoding
    /// fails.
    pub fn digest(&self) -> Result<Digest32, PolicyEvaluationError> {
        self.validate()?;
        canonical_hash(self).map_err(|error| PolicyEvaluationError::Canonical(error.to_string()))
    }
}

/// Canonical request-plan-action checkpoint used before any effect executes.
///
/// This type cannot contain or imply a result artifact. It is distinct from
/// [`IntentTrace`], whose terminal result is mandatory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreExecutionIntentTrace {
    pub schema_version: u16,
    pub trace_id: Uuid,
    pub task_hash: Digest32,
    pub requirement_hashes: Vec<Digest32>,
    pub request_hash: Digest32,
    pub plan_hash: Digest32,
    pub action_hash: Digest32,
    pub transformation_step_hashes: Vec<Digest32>,
    pub recorded_at: i64,
}

impl PreExecutionIntentTrace {
    /// Validates the local checkpoint shape.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] for malformed identities,
    /// commitments, collections, time, or schema.
    pub fn validate(&self) -> Result<(), PolicyEvaluationError> {
        require_schema(
            self.schema_version,
            PRE_EXECUTION_INTENT_TRACE_SCHEMA_VERSION,
            "pre-execution intent trace",
        )?;
        require_non_nil(self.trace_id, "trace_id")?;
        require_digest(self.task_hash, "task_hash")?;
        validate_sorted_digests(&self.requirement_hashes, "requirement_hashes", true)?;
        require_digest(self.request_hash, "request_hash")?;
        require_digest(self.plan_hash, "plan_hash")?;
        require_digest(self.action_hash, "action_hash")?;
        validate_ordered_digests(
            &self.transformation_step_hashes,
            "transformation_step_hashes",
            true,
        )?;
        require_positive_time(self.recorded_at, "recorded_at")
    }

    /// Verifies the exact request-plan-action path and its requirements.
    ///
    /// # Errors
    ///
    /// Rejects a missing, repeated, substituted, cross-task, result-bearing,
    /// reordered, or discontinuous checkpoint.
    pub fn verify_bindings(
        &self,
        requirements: &[TaskRequirement],
        steps: &[TransformationStep],
    ) -> Result<(), PolicyEvaluationError> {
        self.validate()?;
        verify_requirement_bindings(self.task_hash, &self.requirement_hashes, requirements)?;
        verify_transformation_bindings(
            self.task_hash,
            self.request_hash,
            &self.transformation_step_hashes,
            steps,
            WorkflowStage::Action,
        )?;
        IntentTrace::verify_checkpoint(steps, IntentStage::Plan, self.plan_hash)?;
        IntentTrace::verify_checkpoint(steps, IntentStage::Action, self.action_hash)?;
        if steps.iter().any(|step| {
            step.source_stage == WorkflowStage::Result || step.target_stage == WorkflowStage::Result
        }) {
            return Err(PolicyEvaluationError::ChainMismatch(
                "pre-execution result stage",
            ));
        }
        let last = &steps[steps.len() - 1];
        if last.target_stage != WorkflowStage::Action
            || last.target_hash != self.action_hash
            || last.recorded_at > self.recorded_at
        {
            return Err(PolicyEvaluationError::ChainMismatch(
                "pre-execution completion",
            ));
        }
        Ok(())
    }

    /// Returns the committed artifact for a pre-execution stage.
    ///
    /// # Errors
    ///
    /// A result has not happened and is therefore rejected rather than
    /// synthesized.
    pub const fn subject_hash(
        &self,
        stage: IntentStage,
    ) -> Result<Digest32, PolicyEvaluationError> {
        match stage {
            IntentStage::Request => Ok(self.request_hash),
            IntentStage::Plan => Ok(self.plan_hash),
            IntentStage::Action => Ok(self.action_hash),
            IntentStage::Result => Err(PolicyEvaluationError::BindingMismatch(
                "pre-execution result",
            )),
        }
    }

    /// Deterministic commitment to this pre-execution checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] when validation or canonical encoding
    /// fails.
    pub fn digest(&self) -> Result<Digest32, PolicyEvaluationError> {
        self.validate()?;
        canonical_hash(self).map_err(|error| PolicyEvaluationError::Canonical(error.to_string()))
    }
}

/// Borrowed evaluation checkpoint with a profile fixed by its concrete type.
#[derive(Clone, Copy, Debug)]
pub enum IntentEvaluationCheckpoint<'a> {
    PreExecution(&'a PreExecutionIntentTrace),
    CompleteTrace(&'a IntentTrace),
}

impl IntentEvaluationCheckpoint<'_> {
    #[must_use]
    pub const fn profile(self) -> IntentEvaluationProfile {
        match self {
            Self::PreExecution(_) => IntentEvaluationProfile::PreExecution,
            Self::CompleteTrace(_) => IntentEvaluationProfile::CompleteTrace,
        }
    }

    #[must_use]
    pub const fn task_hash(self) -> Digest32 {
        match self {
            Self::PreExecution(trace) => trace.task_hash,
            Self::CompleteTrace(trace) => trace.task_hash,
        }
    }

    #[must_use]
    pub const fn trace_id(self) -> Uuid {
        match self {
            Self::PreExecution(trace) => trace.trace_id,
            Self::CompleteTrace(trace) => trace.trace_id,
        }
    }

    #[must_use]
    pub const fn recorded_at(self) -> i64 {
        match self {
            Self::PreExecution(trace) => trace.recorded_at,
            Self::CompleteTrace(trace) => trace.recorded_at,
        }
    }

    /// Validates the concrete checkpoint and all supplied bindings.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error for any invalid profile-specific path.
    pub fn verify_bindings(
        self,
        requirements: &[TaskRequirement],
        steps: &[TransformationStep],
    ) -> Result<(), PolicyEvaluationError> {
        match self {
            Self::PreExecution(trace) => trace.verify_bindings(requirements, steps),
            Self::CompleteTrace(trace) => trace.verify_bindings(requirements, steps),
        }
    }

    /// Returns the exact stage commitment without inventing absent stages.
    ///
    /// # Errors
    ///
    /// Returns a binding error when a stage is not part of this profile.
    pub const fn subject_hash(self, stage: IntentStage) -> Result<Digest32, PolicyEvaluationError> {
        match self {
            Self::PreExecution(trace) => trace.subject_hash(stage),
            Self::CompleteTrace(trace) => Ok(trace.subject_hash(stage)),
        }
    }

    /// Canonical digest of the concrete checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] when validation or encoding fails.
    pub fn digest(self) -> Result<Digest32, PolicyEvaluationError> {
        match self {
            Self::PreExecution(trace) => trace.digest(),
            Self::CompleteTrace(trace) => trace.digest(),
        }
    }
}

fn verify_requirement_bindings(
    task_hash: Digest32,
    expected_hashes: &[Digest32],
    requirements: &[TaskRequirement],
) -> Result<(), PolicyEvaluationError> {
    if requirements.len() != expected_hashes.len() {
        return Err(PolicyEvaluationError::BindingMismatch(
            "intent trace requirements",
        ));
    }
    let mut actual = Vec::with_capacity(requirements.len());
    for requirement in requirements {
        requirement.validate()?;
        if requirement.task_hash != task_hash {
            return Err(PolicyEvaluationError::BindingMismatch(
                "intent trace requirement task",
            ));
        }
        actual.push(requirement.digest()?);
    }
    actual.sort_unstable();
    if actual != expected_hashes || !actual.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(PolicyEvaluationError::BindingMismatch(
            "intent trace requirements",
        ));
    }
    Ok(())
}

fn verify_transformation_bindings(
    task_hash: Digest32,
    request_hash: Digest32,
    expected_hashes: &[Digest32],
    steps: &[TransformationStep],
    terminal_stage: WorkflowStage,
) -> Result<(), PolicyEvaluationError> {
    if steps.len() != expected_hashes.len() || steps.is_empty() {
        return Err(PolicyEvaluationError::BindingMismatch(
            "intent trace transformations",
        ));
    }
    for (step, expected_hash) in steps.iter().zip(expected_hashes) {
        step.validate()?;
        if step.task_hash != task_hash || step.digest()? != *expected_hash {
            return Err(PolicyEvaluationError::BindingMismatch(
                "intent trace transformation",
            ));
        }
    }
    let first = &steps[0];
    if first.sequence != 0
        || first.parent_step_hash.is_some()
        || first.source_stage != WorkflowStage::Request
        || first.source_hash != request_hash
    {
        return Err(PolicyEvaluationError::ChainMismatch("intent trace root"));
    }
    for pair in steps.windows(2) {
        pair[1].verify_successor_of(&pair[0])?;
    }
    if steps.iter().any(|step| {
        step.source_stage.code() >= step.target_stage.code()
            || step.target_stage.code() > terminal_stage.code()
    }) {
        return Err(PolicyEvaluationError::ChainMismatch(
            "intent trace stage order",
        ));
    }
    Ok(())
}

/// One immutable, provider-neutral item of evidence about one requirement and
/// one mandatory stage.
///
/// Evidence forms a task-local parent-hash chain. `method_hash` identifies the
/// exact rule, prompt, rubric, or code; `evaluator_hash` identifies the exact
/// model build, service configuration, reviewer, or verifier;
/// `calibration_hash` commits to calibration material when present; and
/// `payload_hash` commits to the raw output or attestation. None is authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentEvidence {
    pub schema_version: u16,
    pub evidence_id: Uuid,
    pub task_hash: Digest32,
    pub trace_id: Uuid,
    pub ledger_hash: Digest32,
    pub sequence: u64,
    pub parent_evidence_hash: Option<Digest32>,
    pub requirement_hash: Digest32,
    pub stage: IntentStage,
    pub subject_hash: Digest32,
    pub transformation_step_hash: Option<Digest32>,
    pub verdict: EvidenceVerdict,
    pub confidence: ScoreInterval,
    pub method_kind: EvidenceMethodKind,
    pub method_hash: Digest32,
    pub evaluator_hash: Digest32,
    pub calibration_status: CalibrationStatus,
    pub calibration_hash: Option<Digest32>,
    pub payload_hash: Digest32,
    pub observed_at: i64,
}

impl IntentEvidence {
    /// Validates identifiers, chain shape, stage binding shape, and provenance.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] for malformed commitments, inconsistent
    /// provenance, invalid stage bindings, or an unsupported schema.
    pub fn validate(&self) -> Result<(), PolicyEvaluationError> {
        require_schema(
            self.schema_version,
            INTENT_EVIDENCE_SCHEMA_VERSION,
            "intent evidence",
        )?;
        require_non_nil(self.evidence_id, "evidence_id")?;
        require_digest(self.task_hash, "task_hash")?;
        require_non_nil(self.trace_id, "trace_id")?;
        require_digest(self.ledger_hash, "ledger_hash")?;
        validate_parent_shape(self.sequence, self.parent_evidence_hash, "intent evidence")?;
        require_digest(self.requirement_hash, "requirement_hash")?;
        require_digest(self.subject_hash, "subject_hash")?;
        match (self.stage, self.transformation_step_hash) {
            (IntentStage::Request, None) => {}
            (IntentStage::Request, Some(_)) | (_, None) => {
                return Err(PolicyEvaluationError::BindingMismatch(
                    "intent evidence stage",
                ));
            }
            (_, Some(hash)) => require_digest(hash, "transformation_step_hash")?,
        }
        ScoreInterval::new(
            self.confidence.lower(),
            self.confidence.estimate(),
            self.confidence.upper(),
        )?;
        require_digest(self.method_hash, "method_hash")?;
        require_digest(self.evaluator_hash, "evaluator_hash")?;
        validate_calibration(
            self.method_kind,
            self.calibration_status,
            self.calibration_hash,
        )?;
        require_digest(self.payload_hash, "payload_hash")?;
        require_positive_time(self.observed_at, "observed_at")
    }

    /// Verifies the exact task, requirement, stage artifact, and transformation.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] for any substituted or cross-scope
    /// requirement, artifact, or transformation.
    pub fn verify_bindings(
        &self,
        trace: &IntentTrace,
        requirement: &TaskRequirement,
        step: Option<&TransformationStep>,
    ) -> Result<(), PolicyEvaluationError> {
        self.verify_checkpoint_bindings(
            IntentEvaluationCheckpoint::CompleteTrace(trace),
            requirement,
            step,
        )
    }

    /// Verifies this evidence against a profile-specific checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] for a cross-profile stage or any
    /// substituted task, trace, requirement, subject, or transformation.
    pub fn verify_checkpoint_bindings(
        &self,
        checkpoint: IntentEvaluationCheckpoint<'_>,
        requirement: &TaskRequirement,
        step: Option<&TransformationStep>,
    ) -> Result<(), PolicyEvaluationError> {
        self.validate()?;
        let expected_subject = checkpoint.subject_hash(self.stage)?;
        requirement.validate()?;
        if self.task_hash != checkpoint.task_hash()
            || self.trace_id != checkpoint.trace_id()
            || self.task_hash != requirement.task_hash
            || self.requirement_hash != requirement.digest()?
            || self.subject_hash != expected_subject
        {
            return Err(PolicyEvaluationError::BindingMismatch(
                "intent evidence scope",
            ));
        }
        match (self.stage, step) {
            (IntentStage::Request, None) => Ok(()),
            (IntentStage::Request, Some(_)) | (_, None) => Err(
                PolicyEvaluationError::BindingMismatch("intent evidence transformation"),
            ),
            (stage, Some(step)) => {
                step.validate()?;
                if step.task_hash != self.task_hash
                    || step.target_stage != stage.workflow_stage()
                    || step.target_hash != self.subject_hash
                    || self.transformation_step_hash != Some(step.digest()?)
                    || self.observed_at < step.recorded_at
                {
                    return Err(PolicyEvaluationError::BindingMismatch(
                        "intent evidence transformation",
                    ));
                }
                Ok(())
            }
        }
    }

    /// Verifies task-local append-only evidence continuity.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] for a sequence, parent, task, or time
    /// discontinuity.
    pub fn verify_successor_of(&self, parent: &Self) -> Result<(), PolicyEvaluationError> {
        self.validate()?;
        parent.validate()?;
        let expected_sequence =
            parent
                .sequence
                .checked_add(1)
                .ok_or(PolicyEvaluationError::ArithmeticOverflow(
                    "intent evidence sequence",
                ))?;
        if self.sequence != expected_sequence
            || self.parent_evidence_hash != Some(parent.digest()?)
            || self.task_hash != parent.task_hash
            || self.trace_id != parent.trace_id
            || self.ledger_hash != parent.ledger_hash
            || self.observed_at < parent.observed_at
        {
            return Err(PolicyEvaluationError::ChainMismatch("intent evidence"));
        }
        Ok(())
    }

    /// Deterministic commitment to the complete evidence item.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] when validation or canonical encoding
    /// fails.
    pub fn digest(&self) -> Result<Digest32, PolicyEvaluationError> {
        self.validate()?;
        canonical_hash(self).map_err(|error| PolicyEvaluationError::Canonical(error.to_string()))
    }

    /// Returns the exact provenance tuple carried by this evidence item.
    #[must_use]
    pub const fn provenance(&self) -> EvidenceProvenance {
        EvidenceProvenance {
            schema_version: EVIDENCE_PROVENANCE_SCHEMA_VERSION,
            method_kind: self.method_kind,
            method_hash: self.method_hash,
            evaluator_hash: self.evaluator_hash,
            calibration_status: self.calibration_status,
            calibration_hash: self.calibration_hash,
        }
    }

    /// Deterministic commitment to the exact provenance tuple.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] when provenance validation or encoding
    /// fails.
    pub fn provenance_digest(&self) -> Result<Digest32, PolicyEvaluationError> {
        self.provenance().digest()
    }

    fn has_admitted_provenance(
        &self,
        trust_policy: &EvidenceTrustPolicy,
    ) -> Result<bool, PolicyEvaluationError> {
        let policy_was_current = self.observed_at >= trust_policy.valid_from
            && self.observed_at <= trust_policy.valid_until;
        Ok(policy_was_current && trust_policy.authorizes(self)?)
    }

    fn has_qualified_support_provenance(
        &self,
        trust_policy: &EvidenceTrustPolicy,
    ) -> Result<bool, PolicyEvaluationError> {
        let calibration_is_qualified = match self.method_kind {
            EvidenceMethodKind::DeterministicCheck
            | EvidenceMethodKind::HumanReview
            | EvidenceMethodKind::ExternalAttestation => {
                self.calibration_status == CalibrationStatus::NotApplicable
                    && self.calibration_hash.is_none()
            }
            EvidenceMethodKind::StatisticalModel | EvidenceMethodKind::LanguageModel => {
                self.calibration_status == CalibrationStatus::Verified
                    && self.calibration_hash.is_some()
            }
        };
        Ok(calibration_is_qualified && self.has_admitted_provenance(trust_policy)?)
    }
}

/// Conservative aggregate status of an intent-conformance assessment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntentConformanceOutcome {
    Supported,
    Uncertain,
    Nonconformant,
    InvalidEvidence,
}

impl IntentConformanceOutcome {
    pub(crate) const fn code(self) -> u8 {
        self.rank()
    }

    const fn escalate(self, proposed: Self) -> Self {
        if proposed.rank() > self.rank() {
            proposed
        } else {
            self
        }
    }

    const fn rank(self) -> u8 {
        match self {
            Self::Supported => 0,
            Self::Uncertain => 1,
            Self::Nonconformant => 2,
            Self::InvalidEvidence => 3,
        }
    }
}

/// Stable explanation for one stage-level finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntentFindingReason {
    Supported,
    MissingEvidence,
    InconclusiveEvidence,
    UnverifiedProvenance,
    ExpiredCalibration,
    ConfidenceThresholdUncertain,
    BelowThreshold,
    ContradictoryEvidence,
    ScopeMismatch,
    EvidenceChainMismatch,
    LedgerSnapshotMismatch,
    TrustPolicyMismatch,
}

impl IntentFindingReason {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::Supported => 0,
            Self::MissingEvidence => 1,
            Self::InconclusiveEvidence => 2,
            Self::UnverifiedProvenance => 3,
            Self::ExpiredCalibration => 4,
            Self::ConfidenceThresholdUncertain => 5,
            Self::BelowThreshold => 6,
            Self::ContradictoryEvidence => 7,
            Self::ScopeMismatch => 8,
            Self::EvidenceChainMismatch => 9,
            Self::LedgerSnapshotMismatch => 10,
            Self::TrustPolicyMismatch => 11,
        }
    }
}

/// One inspectable finding. Global evidence-chain findings have no requirement
/// or stage; stage-level findings bind both and, when applicable, one evidence
/// digest.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentFinding {
    pub requirement_hash: Option<Digest32>,
    pub stage: Option<IntentStage>,
    pub evidence_hash: Option<Digest32>,
    pub reason: IntentFindingReason,
}

/// Result of provider-independent intent-conformance measurement.
///
/// The embedded policy evaluation starts at caller-supplied authority and can
/// only preserve or strengthen it. This summary is evidence and has no method
/// that manufactures execution permission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntentConformanceEvaluation {
    pub(crate) schema_version: u16,
    pub(crate) profile: IntentEvaluationProfile,
    pub(crate) task_hash: Digest32,
    pub(crate) trace_hash: Digest32,
    pub(crate) ledger_snapshot_hash: Digest32,
    pub(crate) trust_policy_hash: Digest32,
    pub(crate) expected_ledger_hash: Digest32,
    pub(crate) minimum_ledger_epoch: u64,
    pub(crate) minimum_trust_policy_epoch: u64,
    pub(crate) evaluated_at: i64,
    pub(crate) evidence_head: Option<Digest32>,
    pub(crate) evidence_hashes: Vec<Digest32>,
    pub(crate) outcome: IntentConformanceOutcome,
    pub(crate) policy_evaluation: PolicyEvaluation,
    pub(crate) findings: Vec<IntentFinding>,
}

impl IntentConformanceEvaluation {
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub const fn profile(&self) -> IntentEvaluationProfile {
        self.profile
    }

    #[must_use]
    pub const fn task_hash(&self) -> Digest32 {
        self.task_hash
    }

    #[must_use]
    pub const fn trace_hash(&self) -> Digest32 {
        self.trace_hash
    }

    #[must_use]
    pub const fn ledger_snapshot_hash(&self) -> Digest32 {
        self.ledger_snapshot_hash
    }

    #[must_use]
    pub const fn trust_policy_hash(&self) -> Digest32 {
        self.trust_policy_hash
    }

    #[must_use]
    pub const fn evidence_head(&self) -> Option<Digest32> {
        self.evidence_head
    }

    /// Sorted, duplicate-free hashes suitable for a policy-decision binding.
    #[must_use]
    pub fn evidence_hashes(&self) -> &[Digest32] {
        &self.evidence_hashes
    }

    #[must_use]
    pub const fn outcome(&self) -> IntentConformanceOutcome {
        self.outcome
    }

    #[must_use]
    pub const fn policy_evaluation(&self) -> &PolicyEvaluation {
        &self.policy_evaluation
    }

    #[must_use]
    pub fn findings(&self) -> &[IntentFinding] {
        &self.findings
    }

    /// Validates the private canonical summary assembled by the evaluator.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] if an internal commitment is malformed
    /// or its evidence-head shape is inconsistent.
    pub fn validate(&self) -> Result<(), PolicyEvaluationError> {
        require_schema(
            self.schema_version,
            INTENT_CONFORMANCE_EVALUATION_SCHEMA_VERSION,
            "intent conformance evaluation",
        )?;
        require_digest(self.task_hash, "task_hash")?;
        require_digest(self.trace_hash, "trace_hash")?;
        require_digest(self.ledger_snapshot_hash, "ledger_snapshot_hash")?;
        require_digest(self.trust_policy_hash, "trust_policy_hash")?;
        require_digest(self.expected_ledger_hash, "expected_ledger_hash")?;
        require_nonzero(self.minimum_ledger_epoch, "minimum_ledger_epoch")?;
        require_nonzero(
            self.minimum_trust_policy_epoch,
            "minimum_trust_policy_epoch",
        )?;
        require_positive_time(self.evaluated_at, "evaluated_at")?;
        validate_sorted_digests(&self.evidence_hashes, "evidence_hashes", false)?;
        if self.findings.len() > MAX_EVALUATION_BINDINGS.saturating_mul(5) {
            return Err(PolicyEvaluationError::InvalidBindingCollection(
                "intent findings",
            ));
        }
        for finding in &self.findings {
            if let Some(hash) = finding.requirement_hash {
                require_digest(hash, "finding requirement_hash")?;
            }
            if let Some(hash) = finding.evidence_hash {
                require_digest(hash, "finding evidence_hash")?;
            }
        }
        if !self.findings.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(PolicyEvaluationError::NonCanonicalCollection(
                "intent findings",
            ));
        }
        if let Some(head) = self.evidence_head {
            require_digest(head, "evidence_head")?;
        }
        if self.outcome == IntentConformanceOutcome::InvalidEvidence {
            return Ok(());
        }
        match (self.evidence_hashes.is_empty(), self.evidence_head) {
            (true, None) => {}
            (true, Some(_)) | (false, None) => {
                return Err(PolicyEvaluationError::InvalidChainRoot(
                    "intent conformance evidence",
                ));
            }
            (false, Some(head)) => {
                if self.evidence_hashes.binary_search(&head).is_err() {
                    return Err(PolicyEvaluationError::BindingMismatch(
                        "intent conformance evidence head",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Deterministic commitment suitable for
    /// `PolicyDecisionRecord::conformance_evaluation_hashes`.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] when validation or canonical encoding
    /// fails.
    pub fn digest(&self) -> Result<Digest32, PolicyEvaluationError> {
        self.validate()?;
        canonical_hash(self).map_err(|error| PolicyEvaluationError::Canonical(error.to_string()))
    }
}

/// Stateless conservative evaluator for an exact request-to-result trace.
#[derive(Clone, Copy, Debug, Default)]
pub struct IntentConformanceEvaluator;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EvidenceChainCheck {
    Valid,
    EvidenceChainMismatch,
    LedgerSnapshotMismatch,
}

impl IntentConformanceEvaluator {
    /// Measures every requirement at request, plan, action, and result.
    ///
    /// The context must contain a current snapshot from the authoritative
    /// evidence ledger plus the trusted ledger identity, minimum epoch, and
    /// evidence-provenance policy. Every admitted signal is considered, so a
    /// caller cannot cherry-pick only favorable evidence from the supplied
    /// chain.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] for a malformed trace, malformed
    /// evidence record, invalid canonical collection, or encoding failure. An
    /// integration boundary must treat every error as a deny outcome.
    pub fn evaluate(
        baseline_decision: EnforcementDecision,
        trace: &IntentTrace,
        requirements: &[TaskRequirement],
        steps: &[TransformationStep],
        evidence: &[IntentEvidence],
        context: IntentEvaluationContext<'_>,
    ) -> Result<IntentConformanceEvaluation, PolicyEvaluationError> {
        Self::evaluate_checkpoint(
            baseline_decision,
            IntentEvaluationCheckpoint::CompleteTrace(trace),
            requirements,
            steps,
            evidence,
            context,
        )
    }

    /// Evaluates request, plan, and proposed action before execution.
    ///
    /// Result evidence is neither required nor accepted as part of this
    /// profile's checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] for malformed or substituted inputs.
    pub fn evaluate_pre_execution(
        baseline_decision: EnforcementDecision,
        trace: &PreExecutionIntentTrace,
        requirements: &[TaskRequirement],
        steps: &[TransformationStep],
        evidence: &[IntentEvidence],
        context: IntentEvaluationContext<'_>,
    ) -> Result<IntentConformanceEvaluation, PolicyEvaluationError> {
        Self::evaluate_checkpoint(
            baseline_decision,
            IntentEvaluationCheckpoint::PreExecution(trace),
            requirements,
            steps,
            evidence,
            context,
        )
    }

    /// Evaluates the exact stages required by a typed checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] for malformed trace, evidence,
    /// collections, or encoding. Integrations must fail closed on `Err`.
    pub fn evaluate_checkpoint(
        baseline_decision: EnforcementDecision,
        checkpoint: IntentEvaluationCheckpoint<'_>,
        requirements: &[TaskRequirement],
        steps: &[TransformationStep],
        evidence: &[IntentEvidence],
        context: IntentEvaluationContext<'_>,
    ) -> Result<IntentConformanceEvaluation, PolicyEvaluationError> {
        checkpoint.verify_bindings(requirements, steps)?;
        context.ledger_expectation.validate()?;
        context.ledger_snapshot.validate()?;
        context.trust_policy.validate()?;
        require_nonzero(
            context.minimum_trust_policy_epoch,
            "minimum_trust_policy_epoch",
        )?;
        if evidence.len() > MAX_EVALUATION_BINDINGS {
            return Err(PolicyEvaluationError::InvalidBindingCollection(
                "intent evidence",
            ));
        }

        let trace_hash = checkpoint.digest()?;
        let ledger_snapshot_hash = context.ledger_snapshot.digest()?;
        let trust_policy_hash = context.trust_policy.digest()?;
        let bindings = EvaluationBindings {
            profile: checkpoint.profile(),
            task_hash: checkpoint.task_hash(),
            trace_hash,
            ledger_snapshot_hash,
            trust_policy_hash,
            expected_ledger_hash: context.ledger_expectation.ledger_hash,
            minimum_ledger_epoch: context.ledger_expectation.minimum_epoch,
            minimum_trust_policy_epoch: context.minimum_trust_policy_epoch,
            evaluated_at: context.ledger_expectation.evaluated_at,
            evidence_head: context.ledger_snapshot.evidence_head,
        };
        let (evidence_hashes_in_order, sorted_evidence_hashes) = Self::hash_evidence(evidence)?;

        let mut policy_evaluation = PolicyEvaluation::new(baseline_decision);
        if context
            .trust_policy
            .verify_for(
                checkpoint.task_hash(),
                context.ledger_expectation.evaluated_at,
            )
            .is_err()
            || context.trust_policy.policy_epoch < context.minimum_trust_policy_epoch
        {
            policy_evaluation.record(
                EnforcementDecision::Deny,
                DecisionReason::ConformanceScopeMismatch,
            );
            return Ok(bindings.invalid_summary(
                sorted_evidence_hashes,
                policy_evaluation,
                IntentFindingReason::TrustPolicyMismatch,
            ));
        }
        let chain_check = Self::verify_evidence_chain(
            checkpoint,
            evidence,
            &evidence_hashes_in_order,
            context.ledger_snapshot,
            context.ledger_expectation,
        );
        if chain_check != EvidenceChainCheck::Valid {
            policy_evaluation.record(
                EnforcementDecision::Deny,
                DecisionReason::ConformanceScopeMismatch,
            );
            return Ok(bindings.invalid_summary(
                sorted_evidence_hashes,
                policy_evaluation,
                match chain_check {
                    EvidenceChainCheck::Valid => unreachable!(),
                    EvidenceChainCheck::EvidenceChainMismatch => {
                        IntentFindingReason::EvidenceChainMismatch
                    }
                    EvidenceChainCheck::LedgerSnapshotMismatch => {
                        IntentFindingReason::LedgerSnapshotMismatch
                    }
                },
            ));
        }

        if let Some(index) = Self::first_binding_mismatch(checkpoint, requirements, steps, evidence)
        {
            policy_evaluation.record(
                EnforcementDecision::Deny,
                DecisionReason::ConformanceScopeMismatch,
            );
            return Ok(Self::invalid_evidence_summary(
                bindings,
                sorted_evidence_hashes,
                policy_evaluation,
                &evidence[index],
                evidence_hashes_in_order[index],
            ));
        }
        let (outcome, findings) = Self::assess_stages(
            checkpoint.profile(),
            requirements,
            evidence,
            &evidence_hashes_in_order,
            context.trust_policy,
            &mut policy_evaluation,
        )?;

        Ok(bindings.summary(sorted_evidence_hashes, outcome, policy_evaluation, findings))
    }

    fn verify_evidence_chain(
        checkpoint: IntentEvaluationCheckpoint<'_>,
        evidence: &[IntentEvidence],
        hashes: &[Digest32],
        snapshot: &EvidenceLedgerSnapshot,
        expectation: EvidenceLedgerExpectation,
    ) -> EvidenceChainCheck {
        let Ok(evidence_count) = u64::try_from(evidence.len()) else {
            return EvidenceChainCheck::LedgerSnapshotMismatch;
        };
        if snapshot.ledger_hash != expectation.ledger_hash
            || snapshot.task_hash != checkpoint.task_hash()
            || snapshot.trace_id != checkpoint.trace_id()
            || snapshot.epoch < expectation.minimum_epoch
            || snapshot.evidence_count != evidence_count
            || checkpoint.recorded_at() > snapshot.captured_at
            || snapshot.captured_at > expectation.evaluated_at
            || snapshot.valid_until < expectation.evaluated_at
        {
            return EvidenceChainCheck::LedgerSnapshotMismatch;
        }
        if evidence.iter().any(|item| {
            item.trace_id != checkpoint.trace_id()
                || item.ledger_hash != snapshot.ledger_hash
                || item.observed_at > snapshot.captured_at
        }) {
            return EvidenceChainCheck::EvidenceChainMismatch;
        }
        match (evidence.last(), hashes.last(), snapshot.evidence_head) {
            (None, None, None) => return EvidenceChainCheck::Valid,
            (Some(_), Some(actual), Some(expected)) if *actual == expected => {}
            _ => return EvidenceChainCheck::LedgerSnapshotMismatch,
        }
        let first = &evidence[0];
        if first.sequence != 0 || first.parent_evidence_hash.is_some() {
            return EvidenceChainCheck::EvidenceChainMismatch;
        }
        if evidence
            .windows(2)
            .all(|pair| pair[1].verify_successor_of(&pair[0]).is_ok())
        {
            EvidenceChainCheck::Valid
        } else {
            EvidenceChainCheck::EvidenceChainMismatch
        }
    }

    fn hash_evidence(
        evidence: &[IntentEvidence],
    ) -> Result<(Vec<Digest32>, Vec<Digest32>), PolicyEvaluationError> {
        let mut in_order = Vec::with_capacity(evidence.len());
        for item in evidence {
            in_order.push(item.digest()?);
        }
        let mut sorted = in_order.clone();
        sorted.sort_unstable();
        if !sorted.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(PolicyEvaluationError::NonCanonicalCollection(
                "intent evidence hashes",
            ));
        }
        Ok((in_order, sorted))
    }

    fn step_for_stage(
        steps: &[TransformationStep],
        stage: IntentStage,
    ) -> Option<&TransformationStep> {
        if stage == IntentStage::Request {
            return None;
        }
        steps
            .iter()
            .find(|step| step.target_stage == stage.workflow_stage())
    }

    fn first_binding_mismatch(
        checkpoint: IntentEvaluationCheckpoint<'_>,
        requirements: &[TaskRequirement],
        steps: &[TransformationStep],
        evidence: &[IntentEvidence],
    ) -> Option<usize> {
        evidence.iter().position(|item| {
            let Some(requirement) = requirements
                .iter()
                .find(|candidate| candidate.digest().ok() == Some(item.requirement_hash))
            else {
                return true;
            };
            let step = Self::step_for_stage(steps, item.stage);
            item.verify_checkpoint_bindings(checkpoint, requirement, step)
                .is_err()
        })
    }

    fn assess_stages(
        profile: IntentEvaluationProfile,
        requirements: &[TaskRequirement],
        evidence: &[IntentEvidence],
        evidence_hashes: &[Digest32],
        trust_policy: &EvidenceTrustPolicy,
        policy_evaluation: &mut PolicyEvaluation,
    ) -> Result<(IntentConformanceOutcome, Vec<IntentFinding>), PolicyEvaluationError> {
        let mut outcome = IntentConformanceOutcome::Supported;
        let mut findings = Vec::new();
        for requirement in requirements {
            let requirement_hash = requirement.digest()?;
            for &stage in profile.required_stages() {
                let matching: Vec<_> = evidence
                    .iter()
                    .zip(evidence_hashes)
                    .filter(|(item, _)| {
                        item.requirement_hash == requirement_hash && item.stage == stage
                    })
                    .collect();
                if matching.is_empty() {
                    outcome = outcome.escalate(IntentConformanceOutcome::Uncertain);
                    policy_evaluation.record(
                        EnforcementDecision::RequireApproval,
                        DecisionReason::ConformanceEvaluationMissing,
                    );
                    findings.push(IntentFinding {
                        requirement_hash: Some(requirement_hash),
                        stage: Some(stage),
                        evidence_hash: None,
                        reason: IntentFindingReason::MissingEvidence,
                    });
                    continue;
                }

                for (item, item_hash) in matching {
                    let (item_outcome, finding_reason, decision, decision_reason) =
                        classify_evidence(item, requirement.minimum_score, trust_policy)?;
                    outcome = outcome.escalate(item_outcome);
                    policy_evaluation.record(decision, decision_reason);
                    findings.push(IntentFinding {
                        requirement_hash: Some(requirement_hash),
                        stage: Some(stage),
                        evidence_hash: Some(*item_hash),
                        reason: finding_reason,
                    });
                }
            }
        }
        findings.sort_unstable();
        Ok((outcome, findings))
    }

    fn invalid_evidence_summary(
        bindings: EvaluationBindings,
        evidence_hashes: Vec<Digest32>,
        policy_evaluation: PolicyEvaluation,
        item: &IntentEvidence,
        item_hash: Digest32,
    ) -> IntentConformanceEvaluation {
        bindings.summary(
            evidence_hashes,
            IntentConformanceOutcome::InvalidEvidence,
            policy_evaluation,
            vec![IntentFinding {
                requirement_hash: Some(item.requirement_hash),
                stage: Some(item.stage),
                evidence_hash: Some(item_hash),
                reason: IntentFindingReason::ScopeMismatch,
            }],
        )
    }
}

fn classify_evidence(
    evidence: &IntentEvidence,
    minimum_score: NormalizedScore,
    trust_policy: &EvidenceTrustPolicy,
) -> Result<
    (
        IntentConformanceOutcome,
        IntentFindingReason,
        EnforcementDecision,
        DecisionReason,
    ),
    PolicyEvaluationError,
> {
    // Evidence content is interpreted symmetrically only after its exact
    // provenance tuple has been admitted by the current trust policy. An
    // untrusted positive cannot authorize, and an untrusted negative cannot be
    // turned into a denial oracle. Structural failures are handled earlier and
    // remain terminal denials.
    if !evidence.has_admitted_provenance(trust_policy)? {
        return Ok((
            IntentConformanceOutcome::Uncertain,
            IntentFindingReason::UnverifiedProvenance,
            EnforcementDecision::RequireApproval,
            DecisionReason::ConformanceInconclusive,
        ));
    }

    let classification = match evidence.verdict {
        EvidenceVerdict::Contradicts => (
            IntentConformanceOutcome::Nonconformant,
            IntentFindingReason::ContradictoryEvidence,
            EnforcementDecision::Deny,
            DecisionReason::RequirementViolated,
        ),
        EvidenceVerdict::Inconclusive => (
            IntentConformanceOutcome::Uncertain,
            IntentFindingReason::InconclusiveEvidence,
            EnforcementDecision::RequireApproval,
            DecisionReason::ConformanceInconclusive,
        ),
        EvidenceVerdict::Supports if evidence.calibration_status == CalibrationStatus::Expired => (
            IntentConformanceOutcome::Uncertain,
            IntentFindingReason::ExpiredCalibration,
            EnforcementDecision::RequireApproval,
            DecisionReason::ConformanceInconclusive,
        ),
        EvidenceVerdict::Supports
            if !evidence.has_qualified_support_provenance(trust_policy)? =>
        {
            (
                IntentConformanceOutcome::Uncertain,
                IntentFindingReason::UnverifiedProvenance,
                EnforcementDecision::RequireApproval,
                DecisionReason::ConformanceInconclusive,
            )
        }
        EvidenceVerdict::Supports if evidence.confidence.upper() < minimum_score => (
            IntentConformanceOutcome::Nonconformant,
            IntentFindingReason::BelowThreshold,
            EnforcementDecision::Deny,
            DecisionReason::RequirementNotSatisfied,
        ),
        EvidenceVerdict::Supports if evidence.confidence.lower() < minimum_score => (
            IntentConformanceOutcome::Uncertain,
            IntentFindingReason::ConfidenceThresholdUncertain,
            EnforcementDecision::RequireApproval,
            DecisionReason::ConformanceThresholdUncertain,
        ),
        EvidenceVerdict::Supports => (
            IntentConformanceOutcome::Supported,
            IntentFindingReason::Supported,
            EnforcementDecision::Allow,
            DecisionReason::RequirementSatisfied,
        ),
    };
    Ok(classification)
}

fn validate_calibration(
    method_kind: EvidenceMethodKind,
    status: CalibrationStatus,
    calibration_hash: Option<Digest32>,
) -> Result<(), PolicyEvaluationError> {
    if method_kind.requires_calibration() {
        if status == CalibrationStatus::NotApplicable
            || (matches!(
                status,
                CalibrationStatus::Verified | CalibrationStatus::Expired
            ) && calibration_hash.is_none())
        {
            return Err(PolicyEvaluationError::InvalidEvidenceProvenance);
        }
    } else if status != CalibrationStatus::NotApplicable || calibration_hash.is_some() {
        return Err(PolicyEvaluationError::InvalidEvidenceProvenance);
    }
    if status == CalibrationStatus::NotApplicable && calibration_hash.is_some() {
        return Err(PolicyEvaluationError::InvalidEvidenceProvenance);
    }
    if let Some(hash) = calibration_hash {
        require_digest(hash, "calibration_hash")?;
    }
    Ok(())
}

fn require_schema(
    actual: u16,
    expected: u16,
    record: &'static str,
) -> Result<(), PolicyEvaluationError> {
    if actual != expected {
        return Err(PolicyEvaluationError::WrongSchema(record));
    }
    Ok(())
}

fn require_non_nil(value: Uuid, field: &'static str) -> Result<(), PolicyEvaluationError> {
    if value.is_nil() {
        return Err(PolicyEvaluationError::NilIdentifier(field));
    }
    Ok(())
}

fn require_digest(value: Digest32, field: &'static str) -> Result<(), PolicyEvaluationError> {
    if value.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(PolicyEvaluationError::ZeroDigest(field));
    }
    Ok(())
}

fn require_positive_time(value: i64, field: &'static str) -> Result<(), PolicyEvaluationError> {
    if value <= 0 {
        return Err(PolicyEvaluationError::InvalidTime(field));
    }
    Ok(())
}

fn require_nonzero(value: u64, field: &'static str) -> Result<(), PolicyEvaluationError> {
    if value == 0 {
        return Err(PolicyEvaluationError::ZeroUnits(field));
    }
    Ok(())
}

fn require_time_window(
    start: i64,
    end: i64,
    field: &'static str,
) -> Result<(), PolicyEvaluationError> {
    require_positive_time(start, field)?;
    require_positive_time(end, field)?;
    if end < start {
        return Err(PolicyEvaluationError::BindingMismatch(field));
    }
    Ok(())
}

fn validate_parent_shape(
    sequence: u64,
    parent_hash: Option<Digest32>,
    record: &'static str,
) -> Result<(), PolicyEvaluationError> {
    match (sequence, parent_hash) {
        (0, None) => Ok(()),
        (0, Some(_)) | (_, None) => Err(PolicyEvaluationError::InvalidChainRoot(record)),
        (_, Some(hash)) => require_digest(hash, "parent_hash"),
    }
}

fn validate_sorted_digests(
    values: &[Digest32],
    field: &'static str,
    required: bool,
) -> Result<(), PolicyEvaluationError> {
    if values.len() > MAX_EVALUATION_BINDINGS || (required && values.is_empty()) {
        return Err(PolicyEvaluationError::InvalidBindingCollection(field));
    }
    for value in values {
        require_digest(*value, field)?;
    }
    if !values.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(PolicyEvaluationError::NonCanonicalCollection(field));
    }
    Ok(())
}

fn validate_ordered_digests(
    values: &[Digest32],
    field: &'static str,
    required: bool,
) -> Result<(), PolicyEvaluationError> {
    if values.len() > MAX_EVALUATION_BINDINGS || (required && values.is_empty()) {
        return Err(PolicyEvaluationError::InvalidBindingCollection(field));
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    for value in &sorted {
        require_digest(*value, field)?;
    }
    if !sorted.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(PolicyEvaluationError::NonCanonicalCollection(field));
    }
    Ok(())
}
