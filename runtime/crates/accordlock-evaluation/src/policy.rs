use serde::{Deserialize, Serialize};

use crate::{
    ConformanceEvaluation, ConformanceResult, PolicyEvaluationError, ResourceQuota,
    ResourceRequest, ResourceReservation, TaskRequirement, TransformationStep,
};

/// Monotone authorization pressure emitted by the evaluation layer.
///
/// Ordering is security-relevant: a later assessment may preserve or increase
/// decision, but [`EnforcementDecision::escalate`] can never reduce it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EnforcementDecision {
    Allow,
    RequireApproval,
    Deny,
}

impl EnforcementDecision {
    /// Returns the stricter of the current and proposed severities.
    #[must_use]
    pub const fn escalate(self, proposed: Self) -> Self {
        if proposed.rank() > self.rank() {
            proposed
        } else {
            self
        }
    }

    /// True only when no approval or blocking condition remains.
    #[must_use]
    pub const fn allows_automatic(self) -> bool {
        matches!(self, Self::Allow)
    }

    /// True for a terminal fail-closed assessment.
    #[must_use]
    pub const fn is_blocking(self) -> bool {
        matches!(self, Self::Deny)
    }

    const fn rank(self) -> u8 {
        match self {
            Self::Allow => 0,
            Self::RequireApproval => 1,
            Self::Deny => 2,
        }
    }

    pub(crate) const fn code(self) -> u8 {
        self.rank()
    }
}

/// Stable, non-free-text reason codes produced by the conservative evaluator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionReason {
    RequirementSatisfied,
    ConformanceEvaluationMissing,
    ConformanceInconclusive,
    ConformanceThresholdUncertain,
    RequirementNotSatisfied,
    RequirementViolated,
    ConformanceScopeMismatch,
    ResourceQuotaMissing,
    ResourceReservationMissing,
    ResourceQuotaExceeded,
    ResourceScopeMismatch,
    ResourceReservationConfirmed,
}

impl DecisionReason {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::RequirementSatisfied => 0,
            Self::ConformanceEvaluationMissing => 1,
            Self::ConformanceInconclusive => 2,
            Self::ConformanceThresholdUncertain => 3,
            Self::RequirementNotSatisfied => 4,
            Self::RequirementViolated => 5,
            Self::ConformanceScopeMismatch => 6,
            Self::ResourceQuotaMissing => 7,
            Self::ResourceReservationMissing => 8,
            Self::ResourceQuotaExceeded => 9,
            Self::ResourceScopeMismatch => 10,
            Self::ResourceReservationConfirmed => 11,
        }
    }

    pub(crate) const fn minimum_decision(self) -> EnforcementDecision {
        match self {
            Self::RequirementSatisfied | Self::ResourceReservationConfirmed => {
                EnforcementDecision::Allow
            }
            Self::ConformanceEvaluationMissing
            | Self::ConformanceInconclusive
            | Self::ConformanceThresholdUncertain => EnforcementDecision::RequireApproval,
            Self::RequirementNotSatisfied
            | Self::RequirementViolated
            | Self::ConformanceScopeMismatch
            | Self::ResourceQuotaMissing
            | Self::ResourceReservationMissing
            | Self::ResourceQuotaExceeded
            | Self::ResourceScopeMismatch => EnforcementDecision::Deny,
        }
    }
}

/// One monotone assessment plus deterministic reason codes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyEvaluation {
    baseline_decision: EnforcementDecision,
    decision: EnforcementDecision,
    reasons: Vec<DecisionReason>,
}

impl PolicyEvaluation {
    /// Starts at an authority decision supplied by trusted policy.
    #[must_use]
    pub const fn new(baseline_decision: EnforcementDecision) -> Self {
        Self {
            baseline_decision,
            decision: baseline_decision,
            reasons: Vec::new(),
        }
    }

    /// The policy decision before conformance and resource evidence was considered.
    #[must_use]
    pub const fn baseline_decision(&self) -> EnforcementDecision {
        self.baseline_decision
    }

    /// The final decision, guaranteed to be at least the `baseline_decision`.
    #[must_use]
    pub const fn decision(&self) -> EnforcementDecision {
        self.decision
    }

    /// Sorted, duplicate-free structured findings.
    #[must_use]
    pub fn reasons(&self) -> &[DecisionReason] {
        &self.reasons
    }

    pub(crate) fn record(&mut self, proposed: EnforcementDecision, reason: DecisionReason) {
        self.decision = self.decision.escalate(proposed);
        match self.reasons.binary_search(&reason) {
            Ok(_) => {}
            Err(index) => self.reasons.insert(index, reason),
        }
    }

    fn merge_from(&mut self, other: &Self) {
        self.decision = self.decision.escalate(other.decision);
        for reason in &other.reasons {
            self.record(self.decision, *reason);
        }
    }
}

/// Stateless, deterministic evaluator whose outputs cannot grant authority.
#[derive(Clone, Copy, Debug, Default)]
pub struct PolicyEvaluator;

impl PolicyEvaluator {
    /// Assesses one requirement over one step.
    ///
    /// A missing or unknown evaluation requires approval. A categorical
    /// violation, binding mismatch, or confidence interval wholly below the
    /// requirement threshold blocks. An interval crossing the threshold requires
    /// approval. A preserved lower bound at or above threshold leaves the existing
    /// enforcement decision unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] for structurally malformed trusted inputs.
    pub fn evaluate_conformance(
        baseline_decision: EnforcementDecision,
        requirement: &TaskRequirement,
        step: &TransformationStep,
        evaluation: Option<&ConformanceEvaluation>,
    ) -> Result<PolicyEvaluation, PolicyEvaluationError> {
        requirement.validate()?;
        step.validate()?;
        let mut assessment = PolicyEvaluation::new(baseline_decision);
        let Some(evaluation) = evaluation else {
            assessment.record(
                EnforcementDecision::RequireApproval,
                DecisionReason::ConformanceEvaluationMissing,
            );
            return Ok(assessment);
        };
        evaluation.validate()?;
        if evaluation.verify_bindings(requirement, step).is_err() {
            assessment.record(
                EnforcementDecision::Deny,
                DecisionReason::ConformanceScopeMismatch,
            );
            return Ok(assessment);
        }

        match evaluation.result {
            ConformanceResult::Nonconformant => {
                assessment.record(
                    EnforcementDecision::Deny,
                    DecisionReason::RequirementViolated,
                );
            }
            ConformanceResult::Inconclusive => {
                assessment.record(
                    EnforcementDecision::RequireApproval,
                    DecisionReason::ConformanceInconclusive,
                );
            }
            ConformanceResult::Conformant => {
                if evaluation.score.lower() >= requirement.minimum_score {
                    assessment.record(
                        EnforcementDecision::Allow,
                        DecisionReason::RequirementSatisfied,
                    );
                } else if evaluation.score.upper() < requirement.minimum_score {
                    assessment.record(
                        EnforcementDecision::Deny,
                        DecisionReason::RequirementNotSatisfied,
                    );
                } else {
                    assessment.record(
                        EnforcementDecision::RequireApproval,
                        DecisionReason::ConformanceThresholdUncertain,
                    );
                }
            }
        }
        Ok(assessment)
    }

    /// Assesses whether one request has a current exact reservation.
    ///
    /// Missing quota, missing reservation, exceeded quota, and all binding
    /// mismatches block. A valid reservation only preserves the `baseline_decision`; it
    /// never grants automatic execution.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] for structurally malformed trusted inputs.
    pub fn evaluate_resources(
        baseline_decision: EnforcementDecision,
        request: &ResourceRequest,
        quota: Option<&ResourceQuota>,
        reservation: Option<&ResourceReservation>,
        parent: Option<&ResourceReservation>,
    ) -> Result<PolicyEvaluation, PolicyEvaluationError> {
        request.validate()?;
        let mut assessment = PolicyEvaluation::new(baseline_decision);
        let Some(quota) = quota else {
            assessment.record(
                EnforcementDecision::Deny,
                DecisionReason::ResourceQuotaMissing,
            );
            return Ok(assessment);
        };
        quota.validate()?;
        if request.task_hash != quota.task_hash || request.resource_kind != quota.resource_kind {
            assessment.record(
                EnforcementDecision::Deny,
                DecisionReason::ResourceScopeMismatch,
            );
            return Ok(assessment);
        }

        if let Some(previous) = parent {
            previous.validate()?;
            let requested_through = previous.reserved_through.checked_add(request.units);
            if requested_through.is_none_or(|units| units > quota.limit) {
                assessment.record(
                    EnforcementDecision::Deny,
                    DecisionReason::ResourceQuotaExceeded,
                );
                return Ok(assessment);
            }
        } else if request.units > quota.limit {
            assessment.record(
                EnforcementDecision::Deny,
                DecisionReason::ResourceQuotaExceeded,
            );
            return Ok(assessment);
        }

        let Some(reservation) = reservation else {
            assessment.record(
                EnforcementDecision::Deny,
                DecisionReason::ResourceReservationMissing,
            );
            return Ok(assessment);
        };
        reservation.validate()?;
        if reservation.verify_for(request, quota, parent).is_err() {
            assessment.record(
                EnforcementDecision::Deny,
                DecisionReason::ResourceScopeMismatch,
            );
            return Ok(assessment);
        }
        assessment.record(
            EnforcementDecision::Allow,
            DecisionReason::ResourceReservationConfirmed,
        );
        Ok(assessment)
    }

    /// Combines independent assessments without ever lowering `baseline_decision`.
    #[must_use]
    pub fn aggregate<'a>(
        baseline_decision: EnforcementDecision,
        assessments: impl IntoIterator<Item = &'a PolicyEvaluation>,
    ) -> PolicyEvaluation {
        let mut aggregate = PolicyEvaluation::new(baseline_decision);
        for assessment in assessments {
            aggregate.merge_from(assessment);
        }
        aggregate
    }
}

#[cfg(test)]
mod tests {
    use accordlock_protocol::Digest32;
    use uuid::Uuid;

    use super::{DecisionReason, EnforcementDecision, PolicyEvaluation, PolicyEvaluator};
    use crate::{
        CONFORMANCE_EVALUATION_SCHEMA_VERSION, ConformanceEvaluation, ConformanceResult,
        NormalizedScore, RESOURCE_QUOTA_SCHEMA_VERSION, RESOURCE_REQUEST_SCHEMA_VERSION,
        ScoreInterval, TASK_REQUIREMENT_SCHEMA_VERSION, TRANSFORMATION_STEP_SCHEMA_VERSION,
        TaskRequirement, TransformationStep, WorkflowStage,
    };

    fn uuid(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn digest(value: u8) -> Digest32 {
        Digest32::from_bytes([value; 32])
    }

    fn requirement() -> TaskRequirement {
        TaskRequirement {
            schema_version: TASK_REQUIREMENT_SCHEMA_VERSION,
            requirement_id: uuid(1),
            task_hash: digest(1),
            statement_hash: digest(2),
            minimum_score: NormalizedScore::new(900_000).unwrap_or(NormalizedScore::ZERO),
        }
    }

    fn step() -> TransformationStep {
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

    fn evaluation(
        result: ConformanceResult,
        lower: u32,
        estimate: u32,
        upper: u32,
    ) -> ConformanceEvaluation {
        let requirement = requirement();
        let step = step();
        ConformanceEvaluation {
            schema_version: CONFORMANCE_EVALUATION_SCHEMA_VERSION,
            conformance_id: uuid(3),
            task_hash: digest(1),
            sequence: 0,
            parent_evaluation_hash: None,
            requirement_hash: requirement.digest().unwrap_or(digest(90)),
            transformation_step_hash: step.digest().unwrap_or(digest(91)),
            result,
            score: ScoreInterval::new(
                NormalizedScore::new(lower).unwrap_or(NormalizedScore::ZERO),
                NormalizedScore::new(estimate).unwrap_or(NormalizedScore::ZERO),
                NormalizedScore::new(upper).unwrap_or(NormalizedScore::ONE),
            )
            .unwrap_or_else(|_| {
                ScoreInterval::new(
                    NormalizedScore::ZERO,
                    NormalizedScore::ZERO,
                    NormalizedScore::ONE,
                )
                .unwrap_or_else(|_| unreachable!())
            }),
            method_hash: digest(5),
            evidence_hash: digest(6),
            evaluated_at: 1_100,
        }
    }

    #[test]
    fn conformance_scores_never_lower_existing_enforcement_decision()
    -> Result<(), Box<dyn std::error::Error>> {
        let requirement = requirement();
        let step = step();
        let evaluations = [
            evaluation(ConformanceResult::Conformant, 950_000, 970_000, 990_000),
            evaluation(ConformanceResult::Conformant, 850_000, 925_000, 950_000),
            evaluation(ConformanceResult::Conformant, 700_000, 800_000, 850_000),
            evaluation(ConformanceResult::Inconclusive, 0, 500_000, 1_000_000),
            evaluation(ConformanceResult::Nonconformant, 0, 100_000, 200_000),
        ];
        for baseline_decision in [
            EnforcementDecision::Allow,
            EnforcementDecision::RequireApproval,
            EnforcementDecision::Deny,
        ] {
            for evaluation in &evaluations {
                let result = PolicyEvaluator::evaluate_conformance(
                    baseline_decision,
                    &requirement,
                    &step,
                    Some(evaluation),
                )?;
                assert!(result.decision() >= baseline_decision);
            }
        }
        Ok(())
    }

    #[test]
    fn score_intervals_are_conservative() -> Result<(), Box<dyn std::error::Error>> {
        let requirement = requirement();
        let step = step();
        let preserved = evaluation(ConformanceResult::Conformant, 900_000, 950_000, 990_000);
        let crossing = evaluation(ConformanceResult::Conformant, 850_000, 920_000, 950_000);
        let below = evaluation(ConformanceResult::Conformant, 700_000, 800_000, 899_999);

        let good = PolicyEvaluator::evaluate_conformance(
            EnforcementDecision::Allow,
            &requirement,
            &step,
            Some(&preserved),
        )?;
        assert_eq!(good.decision(), EnforcementDecision::Allow);
        assert_eq!(good.reasons(), &[DecisionReason::RequirementSatisfied]);

        let uncertain = PolicyEvaluator::evaluate_conformance(
            EnforcementDecision::Allow,
            &requirement,
            &step,
            Some(&crossing),
        )?;
        assert_eq!(uncertain.decision(), EnforcementDecision::RequireApproval);

        let failed = PolicyEvaluator::evaluate_conformance(
            EnforcementDecision::Allow,
            &requirement,
            &step,
            Some(&below),
        )?;
        assert_eq!(failed.decision(), EnforcementDecision::Deny);
        Ok(())
    }

    #[test]
    fn inconclusive_evaluation_requires_approval_and_violation_blocks()
    -> Result<(), Box<dyn std::error::Error>> {
        let requirement = requirement();
        let step = step();
        let unknown = evaluation(ConformanceResult::Inconclusive, 0, 500_000, 1_000_000);
        let violated = evaluation(ConformanceResult::Nonconformant, 0, 100_000, 200_000);
        assert_eq!(
            PolicyEvaluator::evaluate_conformance(
                EnforcementDecision::Allow,
                &requirement,
                &step,
                Some(&unknown),
            )?
            .decision(),
            EnforcementDecision::RequireApproval
        );
        assert_eq!(
            PolicyEvaluator::evaluate_conformance(
                EnforcementDecision::Allow,
                &requirement,
                &step,
                Some(&violated),
            )?
            .decision(),
            EnforcementDecision::Deny
        );
        Ok(())
    }

    #[test]
    fn missing_or_substituted_evidence_cannot_authorize() -> Result<(), Box<dyn std::error::Error>>
    {
        let requirement = requirement();
        let step = step();
        let missing = PolicyEvaluator::evaluate_conformance(
            EnforcementDecision::Allow,
            &requirement,
            &step,
            None,
        )?;
        assert_eq!(missing.decision(), EnforcementDecision::RequireApproval);

        let mut substituted =
            evaluation(ConformanceResult::Conformant, 950_000, 975_000, 1_000_000);
        substituted.transformation_step_hash = digest(99);
        let result = PolicyEvaluator::evaluate_conformance(
            EnforcementDecision::Allow,
            &requirement,
            &step,
            Some(&substituted),
        )?;
        assert_eq!(result.decision(), EnforcementDecision::Deny);
        assert_eq!(
            result.reasons(),
            &[DecisionReason::ConformanceScopeMismatch]
        );
        Ok(())
    }

    #[test]
    fn resources_require_exact_quota_and_reservation() -> Result<(), Box<dyn std::error::Error>> {
        use crate::{ResourceQuota, ResourceRequest, ResourceReservation};

        let request = ResourceRequest {
            schema_version: RESOURCE_REQUEST_SCHEMA_VERSION,
            request_id: uuid(10),
            task_hash: digest(1),
            action_hash: digest(10),
            resource_kind: "network.requests".to_owned(),
            units: 2,
        };
        let quota = ResourceQuota {
            schema_version: RESOURCE_QUOTA_SCHEMA_VERSION,
            quota_id: uuid(11),
            task_hash: digest(1),
            resource_kind: "network.requests".to_owned(),
            limit: 4,
            policy_epoch: 1,
        };
        let reservation = ResourceReservation::reserve(uuid(12), &request, &quota, None, 1_200)?;

        let valid = PolicyEvaluator::evaluate_resources(
            EnforcementDecision::RequireApproval,
            &request,
            Some(&quota),
            Some(&reservation),
            None,
        )?;
        assert_eq!(valid.decision(), EnforcementDecision::RequireApproval);

        let missing = PolicyEvaluator::evaluate_resources(
            EnforcementDecision::Allow,
            &request,
            Some(&quota),
            None,
            None,
        )?;
        assert_eq!(missing.decision(), EnforcementDecision::Deny);

        let mut substituted = reservation;
        substituted.request_hash = digest(99);
        let mismatch = PolicyEvaluator::evaluate_resources(
            EnforcementDecision::Allow,
            &request,
            Some(&quota),
            Some(&substituted),
            None,
        )?;
        assert_eq!(mismatch.decision(), EnforcementDecision::Deny);
        Ok(())
    }

    #[test]
    fn aggregate_takes_the_monotone_maximum() {
        let first = PolicyEvaluation::new(EnforcementDecision::Allow);
        let mut second = PolicyEvaluation::new(EnforcementDecision::Allow);
        second.record(
            EnforcementDecision::RequireApproval,
            DecisionReason::ConformanceInconclusive,
        );
        let mut third = PolicyEvaluation::new(EnforcementDecision::Allow);
        third.record(
            EnforcementDecision::Deny,
            DecisionReason::ResourceQuotaMissing,
        );
        let aggregate = PolicyEvaluator::aggregate(
            EnforcementDecision::RequireApproval,
            [&first, &second, &third],
        );
        assert_eq!(
            aggregate.baseline_decision(),
            EnforcementDecision::RequireApproval
        );
        assert_eq!(aggregate.decision(), EnforcementDecision::Deny);
        assert_eq!(aggregate.reasons().len(), 2);
    }
}
