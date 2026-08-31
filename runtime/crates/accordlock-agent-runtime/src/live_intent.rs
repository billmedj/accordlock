//! Strict runtime bridge from an approved task and model plan to the typed
//! intent-conformance evaluator.
//!
//! These bundles are evidence, not execution authority. With the deliberately
//! empty evidence policy constructed here, a valid bundle always requires
//! human approval and can never authorize automatic execution.

use accordlock_agent_protocol::{Digest32, MAX_EXECUTION_DURATION_SECONDS};
use accordlock_evaluation::{
    ActionArtifact, EVIDENCE_LEDGER_SNAPSHOT_SCHEMA_VERSION, EVIDENCE_TRUST_POLICY_SCHEMA_VERSION,
    EnforcementDecision, EvidenceLedgerExpectation, EvidenceLedgerSnapshot, EvidenceTrustPolicy,
    IntentConformanceEvaluator, IntentConformanceOutcome, IntentConformanceRecord,
    IntentEvaluationCheckpoint, IntentEvaluationContext, IntentEvaluationProfile, IntentEvidence,
    IntentFindingReason, IntentTrace, IntentTraceBuilder, NormalizedScore, PlanArtifact,
    PolicyEvaluationError, PreExecutionIntentTrace, RequestArtifact, RequirementCommitment,
    ResultArtifact, TaskRequirement, TransformationStep,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::canonical::{canonical_json_bytes, digest_bytes};
use crate::model::{WireValidationError, parse_digest};
use crate::{ApprovedSession, TaskBindingError, ToolCallProposal};

pub const LIVE_INTENT_EVALUATION_CONTEXT_SCHEMA_VERSION: u16 = 1;
pub const PRE_EXECUTION_LIVE_INTENT_BUNDLE_SCHEMA_VERSION: u16 = 1;
pub const COMPLETE_LIVE_INTENT_BUNDLE_SCHEMA_VERSION: u16 = 1;
pub const INTENT_ASSESSMENT_SCHEMA_VERSION: u16 = 1;

/// Conservative, non-secret projection of a fully re-evaluated intent record.
///
/// This status never grants execution authority. `Verified` is possible only
/// when the provider-independent evaluator admitted non-empty qualified
/// evidence. Missing or inconclusive evidence remains `ReviewRequired`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntentAssessmentStatus {
    Verified,
    ReviewRequired,
    Blocked,
}

/// Bounded audit projection for one intent assessment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentAssessment {
    pub schema_version: u16,
    pub profile: IntentEvaluationProfile,
    pub status: IntentAssessmentStatus,
    pub evidence_count: u16,
    pub finding_reasons: Vec<IntentFindingReason>,
}

impl IntentAssessment {
    fn from_record(
        record: &IntentConformanceRecord,
        evidence_count: usize,
    ) -> Result<Self, LiveIntentError> {
        record.validate()?;
        let evidence_count =
            u16::try_from(evidence_count).map_err(|_| LiveIntentError::InvalidAssessment)?;
        let mut finding_reasons = record
            .findings()
            .iter()
            .map(|finding| finding.reason)
            .collect::<Vec<_>>();
        finding_reasons.sort_unstable();
        finding_reasons.dedup();

        let status = match record.outcome() {
            IntentConformanceOutcome::Supported
                if evidence_count > 0
                    && !finding_reasons.is_empty()
                    && finding_reasons
                        .iter()
                        .all(|reason| *reason == IntentFindingReason::Supported) =>
            {
                IntentAssessmentStatus::Verified
            }
            IntentConformanceOutcome::Supported => {
                return Err(LiveIntentError::InvalidAssessment);
            }
            IntentConformanceOutcome::Uncertain => IntentAssessmentStatus::ReviewRequired,
            IntentConformanceOutcome::Nonconformant | IntentConformanceOutcome::InvalidEvidence => {
                IntentAssessmentStatus::Blocked
            }
        };
        Ok(Self {
            schema_version: INTENT_ASSESSMENT_SCHEMA_VERSION,
            profile: record.profile(),
            status,
            evidence_count,
            finding_reasons,
        })
    }
}

/// Owned, serializable form of the evaluator's borrowed context.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveIntentEvaluationContext {
    pub schema_version: u16,
    pub ledger_snapshot: EvidenceLedgerSnapshot,
    pub ledger_expectation: EvidenceLedgerExpectation,
    pub trust_policy: EvidenceTrustPolicy,
    pub minimum_trust_policy_epoch: u64,
}

impl LiveIntentEvaluationContext {
    fn borrowed(&self) -> IntentEvaluationContext<'_> {
        IntentEvaluationContext {
            ledger_snapshot: &self.ledger_snapshot,
            ledger_expectation: self.ledger_expectation,
            trust_policy: &self.trust_policy,
            minimum_trust_policy_epoch: self.minimum_trust_policy_epoch,
        }
    }
}

/// Persistable request-plan-action evaluation created before an effect runs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreExecutionLiveIntentBundle {
    pub schema_version: u16,
    pub checkpoint: PreExecutionIntentTrace,
    pub requirements: Vec<TaskRequirement>,
    pub transformations: Vec<TransformationStep>,
    pub evidence: Vec<IntentEvidence>,
    pub context: LiveIntentEvaluationContext,
    pub record: IntentConformanceRecord,
}

impl PreExecutionLiveIntentBundle {
    /// Builds and evaluates the exact approved objective, model plan, and tool
    /// proposal. The strict local profile contains no provider evidence.
    ///
    /// # Errors
    ///
    /// Fails when the session, proposal, evaluation time, reconstructed trace,
    /// evaluation context, or resulting strict evaluation is invalid.
    pub fn build_strict(
        session: &ApprovedSession,
        request: &ToolCallProposal,
        evaluated_at: i64,
    ) -> Result<Self, LiveIntentError> {
        validate_live_inputs(session, request, evaluated_at)?;
        let builder = reconstruct_pre_execution(session, request, evaluated_at)?;
        let checkpoint = builder.pre_execution_checkpoint()?;
        let requirements = builder.requirements().to_vec();
        let transformations = builder.transformations().to_vec();
        let evidence = Vec::new();
        let context = strict_context(
            session,
            checkpoint.trace_id,
            evaluated_at,
            session.expires_at,
        )?;
        let evaluation = IntentConformanceEvaluator::evaluate_pre_execution(
            EnforcementDecision::Allow,
            &checkpoint,
            &requirements,
            &transformations,
            &evidence,
            context.borrowed(),
        )?;
        let record = IntentConformanceRecord::from_evaluation(&evaluation)?;
        let bundle = Self {
            schema_version: PRE_EXECUTION_LIVE_INTENT_BUNDLE_SCHEMA_VERSION,
            checkpoint,
            requirements,
            transformations,
            evidence,
            context,
            record,
        };
        bundle.revalidate(session, request)?;
        Ok(bundle)
    }

    /// Reconstructs every commitment and re-runs the evaluator. This is the
    /// required read path for a deserialized bundle.
    ///
    /// # Errors
    ///
    /// Fails when the bundle schema, session, proposal, evaluation context,
    /// reconstructed trace, evidence profile, or stored evaluation is invalid.
    pub fn revalidate(
        &self,
        session: &ApprovedSession,
        request: &ToolCallProposal,
    ) -> Result<(), LiveIntentError> {
        if self.schema_version != PRE_EXECUTION_LIVE_INTENT_BUNDLE_SCHEMA_VERSION {
            return Err(LiveIntentError::WrongSchema(
                "pre-execution live intent bundle",
            ));
        }
        let evaluated_at = self.context.ledger_expectation.evaluated_at;
        validate_live_inputs(session, request, evaluated_at)?;
        validate_strict_context(
            session,
            self.checkpoint.trace_id,
            session.expires_at,
            &self.context,
        )?;
        if !self.evidence.is_empty() {
            return Err(LiveIntentError::UnexpectedEvidence);
        }
        let builder = reconstruct_pre_execution(session, request, evaluated_at)?;
        let checkpoint = builder.pre_execution_checkpoint()?;
        if checkpoint != self.checkpoint
            || builder.requirements() != self.requirements
            || builder.transformations() != self.transformations
        {
            return Err(LiveIntentError::SubstitutedTrace);
        }
        self.record.verify_evaluation_for(
            EnforcementDecision::Allow,
            IntentEvaluationCheckpoint::PreExecution(&self.checkpoint),
            &self.requirements,
            &self.transformations,
            &self.evidence,
            self.context.borrowed(),
        )?;
        require_manual_review(&self.record)
    }

    /// Projects the categorical result after the caller has revalidated this
    /// bundle against its exact approved session and proposal.
    pub(crate) fn assessment(&self) -> Result<IntentAssessment, LiveIntentError> {
        IntentAssessment::from_record(&self.record, self.evidence.len())
    }

    /// Appends an observed result commitment and creates a `COMPLETE_TRACE`
    /// evaluation. No result artifact is invented before this call.
    ///
    /// # Errors
    ///
    /// Fails when the pre-execution bundle cannot be revalidated, the result is
    /// outside the execution window, or the complete trace cannot be evaluated.
    pub fn append_result(
        &self,
        session: &ApprovedSession,
        request: &ToolCallProposal,
        result_digest: Digest32,
        recorded_at: i64,
    ) -> Result<CompleteLiveIntentBundle, LiveIntentError> {
        self.revalidate(session, request)?;
        if recorded_at < self.checkpoint.recorded_at
            || recorded_at.saturating_sub(self.checkpoint.recorded_at)
                > MAX_EXECUTION_DURATION_SECONDS
        {
            return Err(LiveIntentError::InvalidEvaluationTime);
        }
        let builder = reconstruct_pre_execution(
            session,
            request,
            self.context.ledger_expectation.evaluated_at,
        )?;
        let completed = builder.append_result(ResultArtifact::new(
            session.task_policy_hash,
            result_digest,
            recorded_at,
        )?)?;
        let (trace, requirements, transformations) = completed.into_parts();
        let evidence = Vec::new();
        let observation_deadline = session
            .expires_at
            .saturating_add(MAX_EXECUTION_DURATION_SECONDS);
        let context = strict_context(session, trace.trace_id, recorded_at, observation_deadline)?;
        let evaluation = IntentConformanceEvaluator::evaluate(
            EnforcementDecision::Allow,
            &trace,
            &requirements,
            &transformations,
            &evidence,
            context.borrowed(),
        )?;
        let record = IntentConformanceRecord::from_evaluation(&evaluation)?;
        let bundle = CompleteLiveIntentBundle {
            schema_version: COMPLETE_LIVE_INTENT_BUNDLE_SCHEMA_VERSION,
            trace,
            requirements,
            transformations,
            evidence,
            context,
            record,
        };
        bundle.revalidate(session, request, result_digest)?;
        Ok(bundle)
    }
}

/// Persistable request-plan-action-result evaluation created after execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteLiveIntentBundle {
    pub schema_version: u16,
    pub trace: IntentTrace,
    pub requirements: Vec<TaskRequirement>,
    pub transformations: Vec<TransformationStep>,
    pub evidence: Vec<IntentEvidence>,
    pub context: LiveIntentEvaluationContext,
    pub record: IntentConformanceRecord,
}

impl CompleteLiveIntentBundle {
    /// Reconstructs the complete trace, checks the caller-held result digest,
    /// and re-runs the `COMPLETE_TRACE` evaluation.
    ///
    /// # Errors
    ///
    /// Fails when the bundle schema, inputs, timing, evaluation context, result
    /// commitment, reconstructed trace, evidence profile, or record is invalid.
    pub fn revalidate(
        &self,
        session: &ApprovedSession,
        request: &ToolCallProposal,
        expected_result_digest: Digest32,
    ) -> Result<(), LiveIntentError> {
        if self.schema_version != COMPLETE_LIVE_INTENT_BUNDLE_SCHEMA_VERSION {
            return Err(LiveIntentError::WrongSchema("complete live intent bundle"));
        }
        let evaluated_at = self.context.ledger_expectation.evaluated_at;
        let action_recorded_at = self.action_recorded_at()?;
        validate_live_inputs(session, request, action_recorded_at)?;
        let observation_deadline = session
            .expires_at
            .saturating_add(MAX_EXECUTION_DURATION_SECONDS);
        validate_strict_context(
            session,
            self.trace.trace_id,
            observation_deadline,
            &self.context,
        )?;
        if evaluated_at < action_recorded_at
            || evaluated_at.saturating_sub(action_recorded_at) > MAX_EXECUTION_DURATION_SECONDS
        {
            return Err(LiveIntentError::InvalidEvaluationTime);
        }
        if !self.evidence.is_empty() {
            return Err(LiveIntentError::UnexpectedEvidence);
        }
        let builder = reconstruct_pre_execution(session, request, action_recorded_at)?;
        let completed = builder.append_result(ResultArtifact::new(
            session.task_policy_hash,
            expected_result_digest,
            evaluated_at,
        )?)?;
        let (trace, requirements, transformations) = completed.into_parts();
        if trace != self.trace
            || requirements != self.requirements
            || transformations != self.transformations
        {
            return Err(LiveIntentError::SubstitutedTrace);
        }
        self.record.verify_evaluation_for(
            EnforcementDecision::Allow,
            IntentEvaluationCheckpoint::CompleteTrace(&self.trace),
            &self.requirements,
            &self.transformations,
            &self.evidence,
            self.context.borrowed(),
        )?;
        require_manual_review(&self.record)
    }

    /// Projects the categorical result after the caller has revalidated this
    /// bundle against its exact approved session, proposal, and result.
    pub(crate) fn assessment(&self) -> Result<IntentAssessment, LiveIntentError> {
        IntentAssessment::from_record(&self.record, self.evidence.len())
    }
}

fn validate_live_inputs(
    session: &ApprovedSession,
    request: &ToolCallProposal,
    evaluated_at: i64,
) -> Result<(), LiveIntentError> {
    session.validate_durable()?;
    if session.schema_version != crate::APPROVED_SESSION_SCHEMA_VERSION {
        return Err(LiveIntentError::LegacySession);
    }
    request.validate()?;
    if request.session_id != session.session_id
        || request.run_id != session.run_id
        || request.workspace_root != session.workspace_root
    {
        return Err(LiveIntentError::ProposalScopeMismatch);
    }
    if evaluated_at <= 0
        || request.agent_plan_checkpoint.recorded_at < session.approved_at
        || evaluated_at < request.agent_plan_checkpoint.recorded_at
        || evaluated_at < session.approved_at
        || evaluated_at >= session.expires_at
    {
        return Err(LiveIntentError::InvalidEvaluationTime);
    }
    Ok(())
}

fn reconstruct_pre_execution(
    session: &ApprovedSession,
    request: &ToolCallProposal,
    action_recorded_at: i64,
) -> Result<IntentTraceBuilder<accordlock_evaluation::AwaitingResult>, LiveIntentError> {
    let task_hash = session.task_policy_hash;
    let objective_hash = session.task_policy.task_objective_hash;
    let request_artifact = RequestArtifact::new(task_hash, objective_hash)?;
    let requirement = RequirementCommitment::new(objective_hash, NormalizedScore::ONE)?;
    let plan_hash = request.agent_plan_checkpoint.material_digest(request)?;
    let proposal_hash = parse_digest(&request.digest()?)?;
    Ok(IntentTraceBuilder::start(request_artifact, [requirement])?
        .append_plan(PlanArtifact::new(
            task_hash,
            plan_hash,
            request.agent_plan_checkpoint.recorded_at,
        )?)?
        .append_action(ActionArtifact::new(
            task_hash,
            proposal_hash,
            action_recorded_at,
        )?)?)
}

fn strict_context(
    session: &ApprovedSession,
    trace_id: Uuid,
    evaluated_at: i64,
    valid_until: i64,
) -> Result<LiveIntentEvaluationContext, LiveIntentError> {
    let ledger_hash = context_ledger_hash(session.task_policy_hash, trace_id)?;
    Ok(LiveIntentEvaluationContext {
        schema_version: LIVE_INTENT_EVALUATION_CONTEXT_SCHEMA_VERSION,
        ledger_snapshot: EvidenceLedgerSnapshot {
            schema_version: EVIDENCE_LEDGER_SNAPSHOT_SCHEMA_VERSION,
            snapshot_id: Uuid::new_v4(),
            ledger_hash,
            task_hash: session.task_policy_hash,
            trace_id,
            epoch: session.policy_epoch,
            evidence_count: 0,
            evidence_head: None,
            captured_at: evaluated_at,
            valid_until,
        },
        ledger_expectation: EvidenceLedgerExpectation {
            ledger_hash,
            minimum_epoch: session.policy_epoch,
            evaluated_at,
        },
        trust_policy: EvidenceTrustPolicy {
            schema_version: EVIDENCE_TRUST_POLICY_SCHEMA_VERSION,
            policy_id: Uuid::new_v4(),
            task_hash: session.task_policy_hash,
            policy_epoch: session.policy_epoch,
            trusted_provenance_hashes: Vec::new(),
            valid_from: session.approved_at.max(1),
            valid_until,
        },
        minimum_trust_policy_epoch: session.policy_epoch,
    })
}

fn validate_strict_context(
    session: &ApprovedSession,
    trace_id: Uuid,
    valid_until: i64,
    context: &LiveIntentEvaluationContext,
) -> Result<(), LiveIntentError> {
    if context.schema_version != LIVE_INTENT_EVALUATION_CONTEXT_SCHEMA_VERSION
        || context.minimum_trust_policy_epoch != session.policy_epoch
        || context.ledger_snapshot.task_hash != session.task_policy_hash
        || context.ledger_snapshot.trace_id != trace_id
        || context.ledger_snapshot.epoch != session.policy_epoch
        || context.ledger_snapshot.evidence_count != 0
        || context.ledger_snapshot.evidence_head.is_some()
        || context.ledger_snapshot.ledger_hash
            != context_ledger_hash(session.task_policy_hash, trace_id)?
        || context.ledger_expectation.ledger_hash != context.ledger_snapshot.ledger_hash
        || context.ledger_expectation.minimum_epoch != session.policy_epoch
        || context.ledger_snapshot.captured_at != context.ledger_expectation.evaluated_at
        || context.ledger_snapshot.valid_until != valid_until
        || context.trust_policy.task_hash != session.task_policy_hash
        || context.trust_policy.policy_epoch != session.policy_epoch
        || !context.trust_policy.trusted_provenance_hashes.is_empty()
        || context.trust_policy.valid_from != session.approved_at.max(1)
        || context.trust_policy.valid_until != valid_until
    {
        return Err(LiveIntentError::SubstitutedContext);
    }
    Ok(())
}

fn context_ledger_hash(task_hash: Digest32, trace_id: Uuid) -> Result<Digest32, LiveIntentError> {
    const DOMAIN: &[u8] = b"accordlock:v1:live-intent-empty-evidence-ledger\0";
    let bytes = canonical_json_bytes(&(task_hash, trace_id))?;
    let mut material = Vec::with_capacity(DOMAIN.len() + bytes.len());
    material.extend_from_slice(DOMAIN);
    material.extend_from_slice(&bytes);
    Ok(digest_bytes(&material))
}

fn require_manual_review(record: &IntentConformanceRecord) -> Result<(), LiveIntentError> {
    if record.decision() != EnforcementDecision::RequireApproval {
        return Err(LiveIntentError::UnsafeDecision(record.decision()));
    }
    Ok(())
}

// The action time is held by the supplied transformation list, not IntentTrace.
// Keep lookup next to each call so reconstructed chains cannot choose a new time.
impl CompleteLiveIntentBundle {
    fn action_recorded_at(&self) -> Result<i64, LiveIntentError> {
        self.transformations
            .iter()
            .find(|step| step.target_stage == accordlock_evaluation::WorkflowStage::Action)
            .map(|step| step.recorded_at)
            .ok_or(LiveIntentError::SubstitutedTrace)
    }
}

#[derive(Debug, Error)]
pub enum LiveIntentError {
    #[error("unsupported schema: {0}")]
    WrongSchema(&'static str),
    #[error("legacy approved sessions do not contain objective material")]
    LegacySession,
    #[error("proposal does not match the approved session")]
    ProposalScopeMismatch,
    #[error("evaluation time is outside the approved window")]
    InvalidEvaluationTime,
    #[error("intent trace material was substituted")]
    SubstitutedTrace,
    #[error("evaluation context was substituted")]
    SubstitutedContext,
    #[error("the strict local profile cannot contain provider evidence")]
    UnexpectedEvidence,
    #[error("strict no-evidence evaluation produced unsafe decision {0:?}")]
    UnsafeDecision(EnforcementDecision),
    #[error("intent assessment projection is inconsistent with its evidence")]
    InvalidAssessment,
    #[error(transparent)]
    TaskBinding(#[from] TaskBindingError),
    #[error(transparent)]
    Wire(#[from] WireValidationError),
    #[error(transparent)]
    Evaluation(#[from] PolicyEvaluationError),
}

#[cfg(test)]
mod tests {
    use accordlock_agent_protocol::Digest32;
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::{
        AGENT_PLAN_CHECKPOINT_SCHEMA_VERSION, APPROVED_SESSION_SCHEMA_VERSION, AgentPlanCheckpoint,
        Capability, PreauthorizedCapability, TASK_POLICY_SCHEMA_VERSION,
        TOOL_CALL_PROPOSAL_SCHEMA_VERSION, TaskPolicy,
    };

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    struct Fixture {
        _workspace: TempDir,
        session: ApprovedSession,
        proposal: ToolCallProposal,
    }

    fn fixture() -> TestResult<Fixture> {
        let workspace = tempfile::tempdir()?;
        let objective = "Inspect the approved workspace without changing it.";
        let policy = TaskPolicy::new(
            Digest32::sha256(objective.as_bytes()),
            [PreauthorizedCapability::new("developer", "read")],
            Vec::<String>::new(),
        )?;
        assert_eq!(policy.schema_version, TASK_POLICY_SCHEMA_VERSION);
        let session = ApprovedSession::new_with_task_objective(
            Uuid::new_v4(),
            "session-1",
            "run-1",
            workspace.path(),
            1,
            objective,
            policy,
            [Capability::new("developer", "read")],
            100,
            1_000,
        )?;
        assert_eq!(session.schema_version, APPROVED_SESSION_SCHEMA_VERSION);

        let arguments = json!({"path": "README.md"});
        let arguments_sha256 = digest_bytes(&canonical_json_bytes(&arguments)?).to_string();
        let plan_material = json!({
            "text": ["Read README.md from the approved workspace."],
            "tool_requests": [{
                "id": "call-1",
                "name": "developer__read",
                "arguments_sha256": arguments_sha256.clone()
            }]
        });
        let plan_bytes = canonical_json_bytes(&plan_material)?;
        let proposal = ToolCallProposal {
            schema_version: TOOL_CALL_PROPOSAL_SCHEMA_VERSION,
            session_id: session.session_id.clone(),
            run_id: session.run_id.clone(),
            tool_call_id: "call-1".into(),
            workspace_root: session.workspace_root.clone(),
            extension_id: "developer".into(),
            tool_name: "read".into(),
            arguments_sha256,
            arguments,
            agent_plan_checkpoint: AgentPlanCheckpoint {
                schema_version: AGENT_PLAN_CHECKPOINT_SCHEMA_VERSION,
                session_id: session.session_id.clone(),
                run_id: session.run_id.clone(),
                tool_call_id: "call-1".into(),
                material: plan_material,
                material_sha256: digest_bytes(&plan_bytes).to_string(),
                recorded_at: 110,
            },
        };
        Ok(Fixture {
            _workspace: workspace,
            session,
            proposal,
        })
    }

    #[test]
    fn strict_pre_execution_is_exact_and_never_allows_automatic_execution() -> TestResult {
        let fixture = fixture()?;
        let bundle =
            PreExecutionLiveIntentBundle::build_strict(&fixture.session, &fixture.proposal, 120)?;
        assert_eq!(
            bundle.record.decision(),
            EnforcementDecision::RequireApproval
        );
        assert_eq!(
            bundle.assessment()?,
            IntentAssessment {
                schema_version: INTENT_ASSESSMENT_SCHEMA_VERSION,
                profile: IntentEvaluationProfile::PreExecution,
                status: IntentAssessmentStatus::ReviewRequired,
                evidence_count: 0,
                finding_reasons: vec![IntentFindingReason::MissingEvidence],
            }
        );
        bundle.revalidate(&fixture.session, &fixture.proposal)?;

        let mut substituted_plan = fixture.proposal.clone();
        substituted_plan.agent_plan_checkpoint.material = json!({"steps": ["different"]});
        substituted_plan.agent_plan_checkpoint.material_sha256 = digest_bytes(
            &canonical_json_bytes(&substituted_plan.agent_plan_checkpoint.material)?,
        )
        .to_string();
        assert!(
            bundle
                .revalidate(&fixture.session, &substituted_plan)
                .is_err()
        );

        let mut substituted_objective = fixture.session.clone();
        substituted_objective.task_objective.push('!');
        assert!(
            bundle
                .revalidate(&substituted_objective, &fixture.proposal)
                .is_err()
        );

        let mut stale_plan = fixture.proposal.clone();
        stale_plan.agent_plan_checkpoint.recorded_at = fixture.session.approved_at - 1;
        assert!(
            PreExecutionLiveIntentBundle::build_strict(
                &fixture.session,
                &stale_plan,
                fixture.session.approved_at + 1,
            )
            .is_err()
        );

        let mut substituted_proposal = fixture.proposal.clone();
        substituted_proposal.arguments = json!({"path": "Cargo.toml"});
        substituted_proposal.arguments_sha256 =
            digest_bytes(&canonical_json_bytes(&substituted_proposal.arguments)?).to_string();
        assert!(
            bundle
                .revalidate(&fixture.session, &substituted_proposal)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn complete_trace_binds_result_record_and_profile() -> TestResult {
        let fixture = fixture()?;
        let pre =
            PreExecutionLiveIntentBundle::build_strict(&fixture.session, &fixture.proposal, 120)?;
        let result = Digest32::sha256(b"observed result");
        let complete = pre.append_result(&fixture.session, &fixture.proposal, result, 130)?;
        assert_eq!(
            complete.record.decision(),
            EnforcementDecision::RequireApproval
        );
        assert_eq!(
            complete.assessment()?,
            IntentAssessment {
                schema_version: INTENT_ASSESSMENT_SCHEMA_VERSION,
                profile: IntentEvaluationProfile::CompleteTrace,
                status: IntentAssessmentStatus::ReviewRequired,
                evidence_count: 0,
                finding_reasons: vec![IntentFindingReason::MissingEvidence],
            }
        );
        complete.revalidate(&fixture.session, &fixture.proposal, result)?;
        assert!(
            complete
                .revalidate(
                    &fixture.session,
                    &fixture.proposal,
                    Digest32::sha256(b"substituted result")
                )
                .is_err()
        );

        let mut forged = complete.clone();
        let mut record_json = serde_json::to_value(&forged.record)?;
        record_json["evaluation_hash"] = serde_json::to_value(Digest32::sha256(b"forged record"))?;
        forged.record = serde_json::from_value(record_json)?;
        assert!(
            forged
                .revalidate(&fixture.session, &fixture.proposal, result)
                .is_err()
        );
        assert!(forged.assessment().is_err());

        let mut cross_profile = complete;
        cross_profile.record = pre.record.clone();
        assert!(
            cross_profile
                .revalidate(&fixture.session, &fixture.proposal, result)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn result_may_finish_after_expiry_but_not_after_execution_window() -> TestResult {
        let fixture = fixture()?;
        let pre =
            PreExecutionLiveIntentBundle::build_strict(&fixture.session, &fixture.proposal, 999)?;
        let result = Digest32::sha256(b"late observed result");
        let complete = pre.append_result(&fixture.session, &fixture.proposal, result, 1_001)?;
        complete.revalidate(&fixture.session, &fixture.proposal, result)?;
        assert!(
            pre.append_result(
                &fixture.session,
                &fixture.proposal,
                result,
                999 + MAX_EXECUTION_DURATION_SECONDS + 1,
            )
            .is_err()
        );
        Ok(())
    }
}
