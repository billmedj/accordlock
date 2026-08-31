use core::fmt;

use accordlock_protocol::{Digest32, canonical_hash};
use serde::{Deserialize, Deserializer, Serialize, de};
use thiserror::Error;
use uuid::Uuid;

use crate::policy::{DecisionReason, EnforcementDecision};

/// Version shared by records in the policy-evaluation protocol.
pub const POLICY_EVALUATION_SCHEMA_VERSION: u16 = 2;
/// Current [`TaskRequirement`] schema version.
pub const TASK_REQUIREMENT_SCHEMA_VERSION: u16 = POLICY_EVALUATION_SCHEMA_VERSION;
/// Current [`TransformationStep`] schema version.
pub const TRANSFORMATION_STEP_SCHEMA_VERSION: u16 = POLICY_EVALUATION_SCHEMA_VERSION;
/// Current [`ConformanceEvaluation`] schema version.
pub const CONFORMANCE_EVALUATION_SCHEMA_VERSION: u16 = POLICY_EVALUATION_SCHEMA_VERSION;
/// Current [`ResourceRequest`] schema version.
pub const RESOURCE_REQUEST_SCHEMA_VERSION: u16 = POLICY_EVALUATION_SCHEMA_VERSION;
/// Current [`ResourceQuota`] schema version.
pub const RESOURCE_QUOTA_SCHEMA_VERSION: u16 = POLICY_EVALUATION_SCHEMA_VERSION;
/// Current [`ResourceReservation`] schema version.
pub const RESOURCE_RESERVATION_SCHEMA_VERSION: u16 = POLICY_EVALUATION_SCHEMA_VERSION;
/// Current [`PolicyDecisionRecord`] schema version.
pub const POLICY_DECISION_SCHEMA_VERSION: u16 = POLICY_EVALUATION_SCHEMA_VERSION;

/// One million parts per million represents the maximum normalized score.
pub const NORMALIZED_SCORE_MAX: u32 = 1_000_000;
/// Maximum UTF-8 bytes in an exact resource dimension identifier.
pub const MAX_RESOURCE_KIND_BYTES: usize = 256;
/// Maximum hashes accepted in any one decision binding collection.
pub const MAX_EVALUATION_BINDINGS: usize = 1_024;

/// A bounded fixed-point score for deterministic policy evaluation.
///
/// Floating point is deliberately excluded from canonical evaluation records.
/// The private field plus checked deserialization makes values above one
/// million unrepresentable through this public API.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct NormalizedScore(u32);

impl NormalizedScore {
    /// Minimum normalized score.
    pub const ZERO: Self = Self(0);
    /// Maximum normalized score.
    pub const ONE: Self = Self(NORMALIZED_SCORE_MAX);

    /// Constructs a bounded parts-per-million value.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError::ScoreOutOfRange`] above one million.
    pub const fn new(value: u32) -> Result<Self, PolicyEvaluationError> {
        if value <= NORMALIZED_SCORE_MAX {
            Ok(Self(value))
        } else {
            Err(PolicyEvaluationError::ScoreOutOfRange(value))
        }
    }

    /// Returns the exact integer parts-per-million representation.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for NormalizedScore {
    type Error = PolicyEvaluationError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<NormalizedScore> for u32 {
    fn from(value: NormalizedScore) -> Self {
        value.get()
    }
}

impl<'de> Deserialize<'de> for NormalizedScore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u32::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// Conservative lower/estimate/upper interval for one normalized score.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScoreInterval {
    lower: NormalizedScore,
    estimate: NormalizedScore,
    upper: NormalizedScore,
}

impl ScoreInterval {
    /// Constructs an ordered, bounded interval.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError::InvalidScoreInterval`] unless
    /// `lower <= estimate <= upper`.
    pub const fn new(
        lower: NormalizedScore,
        estimate: NormalizedScore,
        upper: NormalizedScore,
    ) -> Result<Self, PolicyEvaluationError> {
        if lower.get() <= estimate.get() && estimate.get() <= upper.get() {
            Ok(Self {
                lower,
                estimate,
                upper,
            })
        } else {
            Err(PolicyEvaluationError::InvalidScoreInterval)
        }
    }

    #[must_use]
    pub const fn lower(self) -> NormalizedScore {
        self.lower
    }

    #[must_use]
    pub const fn estimate(self) -> NormalizedScore {
        self.estimate
    }

    #[must_use]
    pub const fn upper(self) -> NormalizedScore {
        self.upper
    }
}

/// Stable stages for a governed execution workflow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorkflowStage {
    Request,
    PolicyDecision,
    Specification,
    Plan,
    Action,
    Execution,
    Observation,
    Result,
    Notification,
    AuditRecord,
}

impl WorkflowStage {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::Request => 0,
            Self::PolicyDecision => 1,
            Self::Specification => 2,
            Self::Plan => 3,
            Self::Action => 4,
            Self::Execution => 5,
            Self::Observation => 6,
            Self::Result => 7,
            Self::Notification => 8,
            Self::AuditRecord => 9,
        }
    }
}

/// Immutable task requirement represented by an exact statement digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRequirement {
    pub schema_version: u16,
    pub requirement_id: Uuid,
    pub task_hash: Digest32,
    pub statement_hash: Digest32,
    pub minimum_score: NormalizedScore,
}

impl TaskRequirement {
    /// Validates schema, identity, and immutable commitments.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] for an unsupported or malformed record.
    pub fn validate(&self) -> Result<(), PolicyEvaluationError> {
        require_schema(
            self.schema_version,
            TASK_REQUIREMENT_SCHEMA_VERSION,
            "task requirement",
        )?;
        require_non_nil(self.requirement_id, "requirement_id")?;
        require_digest(self.task_hash, "task_hash")?;
        require_digest(self.statement_hash, "statement_hash")
    }

    /// Deterministic commitment to the complete requirement.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] when validation or encoding fails.
    pub fn digest(&self) -> Result<Digest32, PolicyEvaluationError> {
        self.validate()?;
        canonical_hash(self).map_err(|error| canonical_error(&error))
    }
}

/// One immutable transformation between two committed workflow states.
///
/// Steps form a parent-hash chain. Sequence zero is the only valid root; each
/// successor must begin at the exact target committed by its parent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransformationStep {
    pub schema_version: u16,
    pub step_id: Uuid,
    pub task_hash: Digest32,
    pub sequence: u64,
    pub parent_step_hash: Option<Digest32>,
    pub source_stage: WorkflowStage,
    pub source_hash: Digest32,
    pub target_stage: WorkflowStage,
    pub target_hash: Digest32,
    pub recorded_at: i64,
}

impl TransformationStep {
    /// Validates the local shape of this step.
    ///
    /// # Errors
    ///
    /// Rejects unsupported schemas, invalid commitments, nonpositive time, or
    /// a root/successor parent-shape mismatch.
    pub fn validate(&self) -> Result<(), PolicyEvaluationError> {
        require_schema(
            self.schema_version,
            TRANSFORMATION_STEP_SCHEMA_VERSION,
            "step",
        )?;
        require_non_nil(self.step_id, "step_id")?;
        require_digest(self.task_hash, "task_hash")?;
        require_digest(self.source_hash, "source_hash")?;
        require_digest(self.target_hash, "target_hash")?;
        require_positive_time(self.recorded_at, "recorded_at")?;
        validate_parent_shape(self.sequence, self.parent_step_hash, "step")
    }

    /// Verifies the exact parent hash, sequence, task, state continuity, and
    /// nondecreasing observation time.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError::ChainMismatch`] for any discontinuity.
    pub fn verify_successor_of(&self, parent: &Self) -> Result<(), PolicyEvaluationError> {
        self.validate()?;
        parent.validate()?;
        let expected_sequence = parent
            .sequence
            .checked_add(1)
            .ok_or(PolicyEvaluationError::ArithmeticOverflow("step sequence"))?;
        if self.sequence != expected_sequence {
            return Err(PolicyEvaluationError::ChainMismatch("step sequence"));
        }
        if self.parent_step_hash != Some(parent.digest()?) {
            return Err(PolicyEvaluationError::ChainMismatch("parent_step_hash"));
        }
        if self.task_hash != parent.task_hash {
            return Err(PolicyEvaluationError::ChainMismatch("step task"));
        }
        if self.source_stage != parent.target_stage || self.source_hash != parent.target_hash {
            return Err(PolicyEvaluationError::ChainMismatch(
                "step state continuity",
            ));
        }
        if self.recorded_at < parent.recorded_at {
            return Err(PolicyEvaluationError::ChainMismatch("step time"));
        }
        Ok(())
    }

    /// Deterministic commitment to the complete step.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] when validation or encoding fails.
    pub fn digest(&self) -> Result<Digest32, PolicyEvaluationError> {
        self.validate()?;
        canonical_hash(self).map_err(|error| canonical_error(&error))
    }
}

/// Conformance result emitted by an evaluation method.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConformanceResult {
    Conformant,
    Nonconformant,
    Inconclusive,
}

impl ConformanceResult {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::Conformant => 0,
            Self::Nonconformant => 1,
            Self::Inconclusive => 2,
        }
    }
}

/// Versioned evidence about one requirement across one step.
///
/// Evaluations form a task-local parent-hash chain independently of the
/// step graph, preserving the exact order in which evidence became available.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceEvaluation {
    pub schema_version: u16,
    pub conformance_id: Uuid,
    pub task_hash: Digest32,
    pub sequence: u64,
    pub parent_evaluation_hash: Option<Digest32>,
    pub requirement_hash: Digest32,
    pub transformation_step_hash: Digest32,
    pub result: ConformanceResult,
    pub score: ScoreInterval,
    pub method_hash: Digest32,
    pub evidence_hash: Digest32,
    pub evaluated_at: i64,
}

impl ConformanceEvaluation {
    /// Validates the bounded, versioned evaluation record.
    ///
    /// # Errors
    ///
    /// Rejects malformed identifiers, commitments, times, or chain shape.
    pub fn validate(&self) -> Result<(), PolicyEvaluationError> {
        require_schema(
            self.schema_version,
            CONFORMANCE_EVALUATION_SCHEMA_VERSION,
            "conformance evaluation",
        )?;
        require_non_nil(self.conformance_id, "conformance_id")?;
        require_digest(self.task_hash, "task_hash")?;
        require_digest(self.requirement_hash, "requirement_hash")?;
        require_digest(self.transformation_step_hash, "transformation_step_hash")?;
        require_digest(self.method_hash, "method_hash")?;
        require_digest(self.evidence_hash, "evidence_hash")?;
        require_positive_time(self.evaluated_at, "evaluated_at")?;
        ScoreInterval::new(
            self.score.lower(),
            self.score.estimate(),
            self.score.upper(),
        )?;
        validate_parent_shape(
            self.sequence,
            self.parent_evaluation_hash,
            "conformance evaluation",
        )
    }

    /// Verifies that this evaluation commits to the supplied requirement and
    /// step rather than merely carrying plausible-looking metrics.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError::BindingMismatch`] for any mismatch.
    pub fn verify_bindings(
        &self,
        requirement: &TaskRequirement,
        step: &TransformationStep,
    ) -> Result<(), PolicyEvaluationError> {
        self.validate()?;
        requirement.validate()?;
        step.validate()?;
        if self.task_hash != requirement.task_hash || self.task_hash != step.task_hash {
            return Err(PolicyEvaluationError::BindingMismatch("evaluation task"));
        }
        if self.requirement_hash != requirement.digest()? {
            return Err(PolicyEvaluationError::BindingMismatch("requirement_hash"));
        }
        if self.transformation_step_hash != step.digest()? {
            return Err(PolicyEvaluationError::BindingMismatch(
                "transformation_step_hash",
            ));
        }
        Ok(())
    }

    /// Verifies the evaluation parent hash, sequence, task, and timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError::ChainMismatch`] for any discontinuity.
    pub fn verify_successor_of(&self, parent: &Self) -> Result<(), PolicyEvaluationError> {
        self.validate()?;
        parent.validate()?;
        let expected_sequence =
            parent
                .sequence
                .checked_add(1)
                .ok_or(PolicyEvaluationError::ArithmeticOverflow(
                    "evaluation sequence",
                ))?;
        if self.sequence != expected_sequence {
            return Err(PolicyEvaluationError::ChainMismatch("evaluation sequence"));
        }
        if self.parent_evaluation_hash != Some(parent.digest()?) {
            return Err(PolicyEvaluationError::ChainMismatch(
                "parent_evaluation_hash",
            ));
        }
        if self.task_hash != parent.task_hash {
            return Err(PolicyEvaluationError::ChainMismatch("evaluation task"));
        }
        if self.evaluated_at < parent.evaluated_at {
            return Err(PolicyEvaluationError::ChainMismatch("evaluation time"));
        }
        Ok(())
    }

    /// Deterministic commitment to the complete evaluation.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] when validation or encoding fails.
    pub fn digest(&self) -> Result<Digest32, PolicyEvaluationError> {
        self.validate()?;
        canonical_hash(self).map_err(|error| canonical_error(&error))
    }
}

/// Durable policy decision bound to all evidence considered for one action.
///
/// Hash collections must be strictly sorted and duplicate-free. The declared
/// decision is recomputed from `baseline_decision` and `reasons` during validation, so
/// neither serialization nor a caller can use metrics to lower authority
/// pressure. Records form a task-local parent-hash chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDecisionRecord {
    pub schema_version: u16,
    pub decision_id: Uuid,
    pub task_hash: Digest32,
    pub action_hash: Digest32,
    pub sequence: u64,
    pub parent_decision_hash: Option<Digest32>,
    pub requirement_hashes: Vec<Digest32>,
    pub transformation_step_hashes: Vec<Digest32>,
    pub conformance_evaluation_hashes: Vec<Digest32>,
    pub resource_request_hashes: Vec<Digest32>,
    pub resource_quota_hashes: Vec<Digest32>,
    pub resource_reservation_hashes: Vec<Digest32>,
    pub baseline_decision: EnforcementDecision,
    pub decision: EnforcementDecision,
    pub reasons: Vec<DecisionReason>,
    pub policy_epoch: u64,
    pub evaluated_at: i64,
}

impl PolicyDecisionRecord {
    /// Validates all evidence bindings, the monotone decision, and chain shape.
    ///
    /// # Errors
    ///
    /// Rejects malformed bindings, unordered collections, decision/reason
    /// inconsistencies, and invalid root/successor shapes.
    pub fn validate(&self) -> Result<(), PolicyEvaluationError> {
        require_schema(
            self.schema_version,
            POLICY_DECISION_SCHEMA_VERSION,
            "evaluation decision",
        )?;
        require_non_nil(self.decision_id, "decision_id")?;
        require_digest(self.task_hash, "task_hash")?;
        require_digest(self.action_hash, "action_hash")?;
        validate_parent_shape(
            self.sequence,
            self.parent_decision_hash,
            "evaluation decision",
        )?;
        validate_digest_collection(&self.requirement_hashes, "requirement_hashes", true)?;
        validate_digest_collection(
            &self.transformation_step_hashes,
            "transformation_step_hashes",
            true,
        )?;
        validate_digest_collection(
            &self.conformance_evaluation_hashes,
            "conformance_evaluation_hashes",
            false,
        )?;
        validate_digest_collection(
            &self.resource_request_hashes,
            "resource_request_hashes",
            false,
        )?;
        validate_digest_collection(&self.resource_quota_hashes, "resource_quota_hashes", false)?;
        validate_digest_collection(
            &self.resource_reservation_hashes,
            "resource_reservation_hashes",
            false,
        )?;
        validate_reasons(&self.reasons)?;
        require_nonzero_units(self.policy_epoch, "policy_epoch")?;
        require_positive_time(self.evaluated_at, "evaluated_at")?;

        let expected = self
            .reasons
            .iter()
            .fold(self.baseline_decision, |decision, reason| {
                decision.escalate(reason.minimum_decision())
            });
        if self.decision != expected {
            return Err(PolicyEvaluationError::InconsistentEnforcementDecision);
        }
        Ok(())
    }

    /// Verifies exact parent hash, sequence, task, epoch, and time monotonicity.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError::ChainMismatch`] for any discontinuity.
    pub fn verify_successor_of(&self, parent: &Self) -> Result<(), PolicyEvaluationError> {
        self.validate()?;
        parent.validate()?;
        let expected_sequence =
            parent
                .sequence
                .checked_add(1)
                .ok_or(PolicyEvaluationError::ArithmeticOverflow(
                    "evaluation decision sequence",
                ))?;
        if self.sequence != expected_sequence {
            return Err(PolicyEvaluationError::ChainMismatch(
                "evaluation decision sequence",
            ));
        }
        if self.parent_decision_hash != Some(parent.digest()?) {
            return Err(PolicyEvaluationError::ChainMismatch("parent_decision_hash"));
        }
        if self.task_hash != parent.task_hash {
            return Err(PolicyEvaluationError::ChainMismatch(
                "evaluation decision task",
            ));
        }
        if self.policy_epoch < parent.policy_epoch {
            return Err(PolicyEvaluationError::ChainMismatch(
                "evaluation decision policy epoch",
            ));
        }
        if self.evaluated_at < parent.evaluated_at {
            return Err(PolicyEvaluationError::ChainMismatch(
                "evaluation decision time",
            ));
        }
        Ok(())
    }

    /// Deterministic commitment suitable for a runner's
    /// `policy_decision_hash` binding.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] when validation or encoding fails.
    pub fn digest(&self) -> Result<Digest32, PolicyEvaluationError> {
        self.validate()?;
        canonical_hash(self).map_err(|error| canonical_error(&error))
    }
}

/// Exact integer resource demand for one committed action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRequest {
    pub schema_version: u16,
    pub request_id: Uuid,
    pub task_hash: Digest32,
    pub action_hash: Digest32,
    pub resource_kind: String,
    pub units: u64,
}

impl ResourceRequest {
    /// Validates an exact, nonzero resource request.
    ///
    /// # Errors
    ///
    /// Rejects invalid schema, identity, commitment, dimension, or units.
    pub fn validate(&self) -> Result<(), PolicyEvaluationError> {
        require_schema(
            self.schema_version,
            RESOURCE_REQUEST_SCHEMA_VERSION,
            "resource request",
        )?;
        require_non_nil(self.request_id, "request_id")?;
        require_digest(self.task_hash, "task_hash")?;
        require_digest(self.action_hash, "action_hash")?;
        require_resource_kind(&self.resource_kind)?;
        require_nonzero_units(self.units, "request units")
    }

    /// Deterministic commitment to the complete request.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] when validation or encoding fails.
    pub fn digest(&self) -> Result<Digest32, PolicyEvaluationError> {
        self.validate()?;
        canonical_hash(self).map_err(|error| canonical_error(&error))
    }
}

/// Immutable task-local quota under one nonzero policy epoch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceQuota {
    pub schema_version: u16,
    pub quota_id: Uuid,
    pub task_hash: Digest32,
    pub resource_kind: String,
    pub limit: u64,
    pub policy_epoch: u64,
}

impl ResourceQuota {
    /// Validates the immutable quota profile.
    ///
    /// # Errors
    ///
    /// Rejects invalid schema, identity, dimension, quota, or epoch.
    pub fn validate(&self) -> Result<(), PolicyEvaluationError> {
        require_schema(
            self.schema_version,
            RESOURCE_QUOTA_SCHEMA_VERSION,
            "resource quota",
        )?;
        require_non_nil(self.quota_id, "quota_id")?;
        require_digest(self.task_hash, "task_hash")?;
        require_resource_kind(&self.resource_kind)?;
        require_nonzero_units(self.limit, "limit")?;
        require_nonzero_units(self.policy_epoch, "policy_epoch")
    }

    /// Deterministic commitment to the complete quota.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] when validation or encoding fails.
    pub fn digest(&self) -> Result<Digest32, PolicyEvaluationError> {
        self.validate()?;
        canonical_hash(self).map_err(|error| canonical_error(&error))
    }
}

/// Monotone, append-only reservation against one immutable quota.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceReservation {
    pub schema_version: u16,
    pub reservation_id: Uuid,
    pub task_hash: Digest32,
    pub request_hash: Digest32,
    pub quota_hash: Digest32,
    pub resource_kind: String,
    pub units: u64,
    pub quota_units: u64,
    pub reserved_before: u64,
    pub reserved_through: u64,
    pub remaining_after: u64,
    pub sequence: u64,
    pub parent_reservation_hash: Option<Digest32>,
    pub reserved_at: i64,
}

impl ResourceReservation {
    /// Atomically derives the next reservation record from an exact request,
    /// quota, and optional prior reservation.
    ///
    /// # Errors
    ///
    /// Rejects mismatched bindings, nonmonotone history, arithmetic overflow,
    /// or a request that exceeds remaining quota.
    pub fn reserve(
        reservation_id: Uuid,
        request: &ResourceRequest,
        quota: &ResourceQuota,
        parent: Option<&Self>,
        reserved_at: i64,
    ) -> Result<Self, PolicyEvaluationError> {
        request.validate()?;
        quota.validate()?;
        require_non_nil(reservation_id, "reservation_id")?;
        require_positive_time(reserved_at, "reserved_at")?;
        if request.task_hash != quota.task_hash {
            return Err(PolicyEvaluationError::BindingMismatch("resource task"));
        }
        if request.resource_kind != quota.resource_kind {
            return Err(PolicyEvaluationError::BindingMismatch("resource_kind"));
        }

        let quota_hash = quota.digest()?;
        let (sequence, parent_reservation_hash, reserved_before) = if let Some(previous) = parent {
            previous.validate()?;
            if previous.task_hash != quota.task_hash
                || previous.quota_hash != quota_hash
                || previous.resource_kind != quota.resource_kind
                || previous.quota_units != quota.limit
            {
                return Err(PolicyEvaluationError::ChainMismatch(
                    "reservation quota lineage",
                ));
            }
            if reserved_at < previous.reserved_at {
                return Err(PolicyEvaluationError::ChainMismatch("reservation time"));
            }
            (
                previous.sequence.checked_add(1).ok_or(
                    PolicyEvaluationError::ArithmeticOverflow("reservation sequence"),
                )?,
                Some(previous.digest()?),
                previous.reserved_through,
            )
        } else {
            (0, None, 0)
        };

        let reserved_through = reserved_before
            .checked_add(request.units)
            .ok_or(PolicyEvaluationError::ArithmeticOverflow("reserved units"))?;
        if reserved_through > quota.limit {
            return Err(PolicyEvaluationError::QuotaExceeded);
        }
        let remaining_after = quota.limit - reserved_through;
        let reservation = Self {
            schema_version: RESOURCE_RESERVATION_SCHEMA_VERSION,
            reservation_id,
            task_hash: request.task_hash,
            request_hash: request.digest()?,
            quota_hash,
            resource_kind: request.resource_kind.clone(),
            units: request.units,
            quota_units: quota.limit,
            reserved_before,
            reserved_through,
            remaining_after,
            sequence,
            parent_reservation_hash,
            reserved_at,
        };
        reservation.validate()?;
        Ok(reservation)
    }

    /// Validates internal arithmetic, bounds, and local chain shape.
    ///
    /// # Errors
    ///
    /// Rejects malformed or internally inconsistent reservations.
    pub fn validate(&self) -> Result<(), PolicyEvaluationError> {
        require_schema(
            self.schema_version,
            RESOURCE_RESERVATION_SCHEMA_VERSION,
            "resource reservation",
        )?;
        require_non_nil(self.reservation_id, "reservation_id")?;
        require_digest(self.task_hash, "task_hash")?;
        require_digest(self.request_hash, "request_hash")?;
        require_digest(self.quota_hash, "quota_hash")?;
        require_resource_kind(&self.resource_kind)?;
        require_nonzero_units(self.units, "reservation units")?;
        require_nonzero_units(self.quota_units, "quota_units")?;
        require_positive_time(self.reserved_at, "reserved_at")?;
        validate_parent_shape(
            self.sequence,
            self.parent_reservation_hash,
            "resource reservation",
        )?;
        let expected_through = self
            .reserved_before
            .checked_add(self.units)
            .ok_or(PolicyEvaluationError::ArithmeticOverflow("reserved units"))?;
        if self.reserved_through != expected_through || self.reserved_through > self.quota_units {
            return Err(PolicyEvaluationError::InvalidReservationArithmetic);
        }
        if self.remaining_after != self.quota_units - self.reserved_through {
            return Err(PolicyEvaluationError::InvalidReservationArithmetic);
        }
        Ok(())
    }

    /// Verifies the request, quota, and optional parent bindings.
    ///
    /// # Errors
    ///
    /// Returns a binding or chain error when any durable field was substituted.
    pub fn verify_for(
        &self,
        request: &ResourceRequest,
        quota: &ResourceQuota,
        parent: Option<&Self>,
    ) -> Result<(), PolicyEvaluationError> {
        self.validate()?;
        request.validate()?;
        quota.validate()?;
        if self.task_hash != request.task_hash
            || self.task_hash != quota.task_hash
            || self.resource_kind != request.resource_kind
            || self.resource_kind != quota.resource_kind
            || self.request_hash != request.digest()?
            || self.quota_hash != quota.digest()?
            || self.units != request.units
            || self.quota_units != quota.limit
        {
            return Err(PolicyEvaluationError::BindingMismatch(
                "resource reservation",
            ));
        }
        match parent {
            Some(previous) => {
                previous.validate()?;
                let expected_sequence = previous.sequence.checked_add(1).ok_or(
                    PolicyEvaluationError::ArithmeticOverflow("reservation sequence"),
                )?;
                if self.sequence != expected_sequence
                    || self.parent_reservation_hash != Some(previous.digest()?)
                    || self.reserved_before != previous.reserved_through
                    || self.reserved_at < previous.reserved_at
                {
                    return Err(PolicyEvaluationError::ChainMismatch("resource reservation"));
                }
            }
            None => {
                if self.sequence != 0
                    || self.parent_reservation_hash.is_some()
                    || self.reserved_before != 0
                {
                    return Err(PolicyEvaluationError::ChainMismatch("reservation root"));
                }
            }
        }
        Ok(())
    }

    /// Deterministic commitment to the complete reservation.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] when validation or encoding fails.
    pub fn digest(&self) -> Result<Digest32, PolicyEvaluationError> {
        self.validate()?;
        canonical_hash(self).map_err(|error| canonical_error(&error))
    }
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

fn require_resource_kind(value: &str) -> Result<(), PolicyEvaluationError> {
    if value.is_empty()
        || value.len() > MAX_RESOURCE_KIND_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(PolicyEvaluationError::InvalidResourceKind);
    }
    Ok(())
}

fn require_nonzero_units(value: u64, field: &'static str) -> Result<(), PolicyEvaluationError> {
    if value == 0 {
        return Err(PolicyEvaluationError::ZeroUnits(field));
    }
    Ok(())
}

fn require_positive_time(value: i64, field: &'static str) -> Result<(), PolicyEvaluationError> {
    if value <= 0 {
        return Err(PolicyEvaluationError::InvalidTime(field));
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

fn validate_digest_collection(
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

fn validate_reasons(values: &[DecisionReason]) -> Result<(), PolicyEvaluationError> {
    if values.is_empty() || values.len() > 12 {
        return Err(PolicyEvaluationError::InvalidBindingCollection("reasons"));
    }
    if !values.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(PolicyEvaluationError::NonCanonicalCollection("reasons"));
    }
    Ok(())
}

fn canonical_error(error: &accordlock_protocol::CanonicalError) -> PolicyEvaluationError {
    PolicyEvaluationError::Canonical(error.to_string())
}

/// Fail-closed validation, binding, and resource-accounting errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyEvaluationError {
    #[error("unsupported schema for {0}")]
    WrongSchema(&'static str),
    #[error("identifier must not be nil: {0}")]
    NilIdentifier(&'static str),
    #[error("digest must not be zero: {0}")]
    ZeroDigest(&'static str),
    #[error("score ppm value is outside 0..=1,000,000: {0}")]
    ScoreOutOfRange(u32),
    #[error("score bounds must satisfy lower <= estimate <= upper")]
    InvalidScoreInterval,
    #[error("resource kind is empty, padded, control-bearing, or too large")]
    InvalidResourceKind,
    #[error("resource value must be nonzero: {0}")]
    ZeroUnits(&'static str),
    #[error("timestamp must be positive: {0}")]
    InvalidTime(&'static str),
    #[error("root and parent-hash shape is invalid for {0}")]
    InvalidChainRoot(&'static str),
    #[error("parent-hash chain mismatch: {0}")]
    ChainMismatch(&'static str),
    #[error("record binding mismatch: {0}")]
    BindingMismatch(&'static str),
    #[error("integer overflow while computing {0}")]
    ArithmeticOverflow(&'static str),
    #[error("resource request exceeds remaining quota")]
    QuotaExceeded,
    #[error("resource reservation arithmetic is inconsistent")]
    InvalidReservationArithmetic,
    #[error("evaluation binding collection is missing or exceeds its bound: {0}")]
    InvalidBindingCollection(&'static str),
    #[error("evaluation collection is not strictly sorted and duplicate-free: {0}")]
    NonCanonicalCollection(&'static str),
    #[error("evidence method and calibration metadata are inconsistent")]
    InvalidEvidenceProvenance,
    #[error("external provider authentication is required")]
    ProviderAuthenticationRequired,
    #[error("provider authentication material is malformed")]
    InvalidProviderAuthentication,
    #[error(
        "declared enforcement decision is inconsistent with baseline_decision and reason codes"
    )]
    InconsistentEnforcementDecision,
    #[error("canonical evaluation encoding failed: {0}")]
    Canonical(String),
}

impl fmt::Display for NormalizedScore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}ppm", self.0)
    }
}
