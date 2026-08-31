use accordlock_protocol::{Digest32, canonical_hash};
use serde::{Deserialize, Serialize};

use crate::{
    DecisionReason, EnforcementDecision, IntentConformanceEvaluation, IntentConformanceEvaluator,
    IntentConformanceOutcome, IntentEvaluationCheckpoint, IntentEvaluationContext,
    IntentEvaluationProfile, IntentEvidence, IntentFinding, PolicyEvaluation,
    PolicyEvaluationError, TaskRequirement, TransformationStep,
};

/// Current schema for the externally serializable intent-conformance record.
pub const INTENT_CONFORMANCE_RECORD_SCHEMA_VERSION: u16 = 2;

/// Strict, portable representation of one completed intent-conformance evaluation.
///
/// The evaluator keeps its in-memory result non-deserializable so callers cannot
/// construct an apparent trusted evaluation. This record is the corresponding
/// untrusted transport format. [`Self::verify_bindings_for`] checks only replay
/// bindings; any authorization-sensitive consumer must call
/// [`Self::verify_evaluation_for`], which re-runs the evaluator. The record is
/// evidence only and contains no grant of execution authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentConformanceRecord {
    pub(crate) schema_version: u16,
    pub(crate) evaluation_schema_version: u16,
    pub(crate) profile: IntentEvaluationProfile,
    pub(crate) evaluation_hash: Digest32,
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
    pub(crate) baseline_decision: EnforcementDecision,
    pub(crate) decision: EnforcementDecision,
    pub(crate) reasons: Vec<DecisionReason>,
    pub(crate) findings: Vec<IntentFinding>,
}

impl IntentConformanceRecord {
    /// Creates the strict transport record for an evaluator-produced result.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] if the evaluation is malformed or its
    /// canonical commitment cannot be produced.
    pub fn from_evaluation(
        evaluation: &IntentConformanceEvaluation,
    ) -> Result<Self, PolicyEvaluationError> {
        evaluation.validate()?;
        let record = Self {
            schema_version: INTENT_CONFORMANCE_RECORD_SCHEMA_VERSION,
            evaluation_schema_version: evaluation.schema_version,
            profile: evaluation.profile,
            evaluation_hash: evaluation.digest()?,
            task_hash: evaluation.task_hash,
            trace_hash: evaluation.trace_hash,
            ledger_snapshot_hash: evaluation.ledger_snapshot_hash,
            trust_policy_hash: evaluation.trust_policy_hash,
            expected_ledger_hash: evaluation.expected_ledger_hash,
            minimum_ledger_epoch: evaluation.minimum_ledger_epoch,
            minimum_trust_policy_epoch: evaluation.minimum_trust_policy_epoch,
            evaluated_at: evaluation.evaluated_at,
            evidence_head: evaluation.evidence_head,
            evidence_hashes: evaluation.evidence_hashes.clone(),
            outcome: evaluation.outcome,
            baseline_decision: evaluation.policy_evaluation.baseline_decision(),
            decision: evaluation.policy_evaluation.decision(),
            reasons: evaluation.policy_evaluation.reasons().to_vec(),
            findings: evaluation.findings.clone(),
        };
        record.validate()?;
        Ok(record)
    }

    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub const fn evaluation_hash(&self) -> Digest32 {
        self.evaluation_hash
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
    pub const fn outcome(&self) -> IntentConformanceOutcome {
        self.outcome
    }

    #[must_use]
    pub const fn decision(&self) -> EnforcementDecision {
        self.decision
    }

    #[must_use]
    pub fn findings(&self) -> &[IntentFinding] {
        &self.findings
    }

    /// Validates the transport record and its exact source-evaluation digest.
    ///
    /// Deserialization alone never establishes trust. Validation reconstructs
    /// the private evaluator summary, checks all collection invariants and the
    /// monotone decision, then recomputes `evaluation_hash`.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] for any malformed, noncanonical, or
    /// internally inconsistent field.
    pub fn validate(&self) -> Result<(), PolicyEvaluationError> {
        if self.schema_version != INTENT_CONFORMANCE_RECORD_SCHEMA_VERSION {
            return Err(PolicyEvaluationError::WrongSchema(
                "intent conformance record",
            ));
        }
        require_digest(self.evaluation_hash, "evaluation_hash")?;
        validate_reasons(&self.reasons)?;

        let evaluation = self.reconstruct_evaluation()?;
        evaluation.validate()?;
        if evaluation.digest()? != self.evaluation_hash {
            return Err(PolicyEvaluationError::BindingMismatch(
                "intent conformance record evaluation_hash",
            ));
        }
        Ok(())
    }

    /// Verifies every context commitment against the exact typed checkpoint and
    /// context currently held by the caller.
    ///
    /// This checks identity, not semantic truth. A record that faithfully
    /// reports invalid evidence still verifies when it is bound to the same
    /// invalid input context that the evaluator observed.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError::BindingMismatch`] when the record was
    /// replayed or any trace, ledger, policy, epoch, time, or head was replaced.
    pub fn verify_bindings_for(
        &self,
        checkpoint: IntentEvaluationCheckpoint<'_>,
        context: IntentEvaluationContext<'_>,
    ) -> Result<(), PolicyEvaluationError> {
        self.validate()?;
        context.ledger_snapshot.validate()?;
        context.ledger_expectation.validate()?;
        context.trust_policy.validate()?;
        if context.minimum_trust_policy_epoch == 0 {
            return Err(PolicyEvaluationError::ZeroUnits(
                "minimum_trust_policy_epoch",
            ));
        }

        if self.profile != checkpoint.profile()
            || self.task_hash != checkpoint.task_hash()
            || self.trace_hash != checkpoint.digest()?
            || self.ledger_snapshot_hash != context.ledger_snapshot.digest()?
            || self.trust_policy_hash != context.trust_policy.digest()?
            || self.expected_ledger_hash != context.ledger_expectation.ledger_hash
            || self.minimum_ledger_epoch != context.ledger_expectation.minimum_epoch
            || self.minimum_trust_policy_epoch != context.minimum_trust_policy_epoch
            || self.evaluated_at != context.ledger_expectation.evaluated_at
            || self.evidence_head != context.ledger_snapshot.evidence_head
        {
            return Err(PolicyEvaluationError::BindingMismatch(
                "intent conformance record context",
            ));
        }
        Ok(())
    }

    /// Re-runs the evaluator over the exact checkpoint, requirements,
    /// transformations, evidence, and context, then compares the complete
    /// canonical result.
    ///
    /// This is the required verification path before an authorization decision
    /// can bind this record. A self-consistent JSON record is not sufficient.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError::BindingMismatch`] if re-evaluation
    /// produces any different profile, outcome, decision, finding, evidence
    /// binding, or digest.
    pub fn verify_evaluation_for(
        &self,
        baseline_decision: EnforcementDecision,
        checkpoint: IntentEvaluationCheckpoint<'_>,
        requirements: &[TaskRequirement],
        steps: &[TransformationStep],
        evidence: &[IntentEvidence],
        context: IntentEvaluationContext<'_>,
    ) -> Result<(), PolicyEvaluationError> {
        self.verify_bindings_for(checkpoint, context)?;
        let expected = IntentConformanceEvaluator::evaluate_checkpoint(
            baseline_decision,
            checkpoint,
            requirements,
            steps,
            evidence,
            context,
        )?;
        let expected_record = Self::from_evaluation(&expected)?;
        if self != &expected_record {
            return Err(PolicyEvaluationError::BindingMismatch(
                "intent conformance record re-evaluation",
            ));
        }
        Ok(())
    }

    /// Deterministic, domain-separated commitment to this transport record.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] when validation or canonical encoding
    /// fails.
    pub fn digest(&self) -> Result<Digest32, PolicyEvaluationError> {
        self.validate()?;
        canonical_hash(self).map_err(|error| PolicyEvaluationError::Canonical(error.to_string()))
    }

    fn reconstruct_evaluation(&self) -> Result<IntentConformanceEvaluation, PolicyEvaluationError> {
        let mut policy_evaluation = PolicyEvaluation::new(self.baseline_decision);
        for reason in &self.reasons {
            policy_evaluation.record(reason.minimum_decision(), *reason);
        }
        if policy_evaluation.decision() != self.decision {
            return Err(PolicyEvaluationError::InconsistentEnforcementDecision);
        }
        Ok(IntentConformanceEvaluation {
            schema_version: self.evaluation_schema_version,
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
            evidence_hashes: self.evidence_hashes.clone(),
            outcome: self.outcome,
            policy_evaluation,
            findings: self.findings.clone(),
        })
    }
}

impl TryFrom<&IntentConformanceEvaluation> for IntentConformanceRecord {
    type Error = PolicyEvaluationError;

    fn try_from(evaluation: &IntentConformanceEvaluation) -> Result<Self, Self::Error> {
        Self::from_evaluation(evaluation)
    }
}

fn require_digest(value: Digest32, field: &'static str) -> Result<(), PolicyEvaluationError> {
    if value.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(PolicyEvaluationError::ZeroDigest(field));
    }
    Ok(())
}

fn validate_reasons(values: &[DecisionReason]) -> Result<(), PolicyEvaluationError> {
    if values.len() > 12 {
        return Err(PolicyEvaluationError::InvalidBindingCollection(
            "intent conformance record reasons",
        ));
    }
    if !values.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(PolicyEvaluationError::NonCanonicalCollection(
            "intent conformance record reasons",
        ));
    }
    Ok(())
}
