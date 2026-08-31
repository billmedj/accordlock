use accordlock_agent_protocol::{
    AuthorizationDecision, AuthorizationOutcome, ExecutionAuthorization, ExecutionRecord,
    ExecutionRequest,
};
#[cfg(test)]
use accordlock_evaluation::{
    ActionArtifact, IntentTraceBuilder, NormalizedScore, PlanArtifact, RequestArtifact,
    RequirementCommitment, ResultArtifact,
};
use accordlock_evaluation::{
    Digest32, IntentTrace, PolicyEvaluationError, TaskRequirement, TransformationStep,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    canonical::domain_digest,
    model::{ApprovedSession, ToolCallProposal},
};

/// Storage schema used by new completed-action records.
pub(crate) const EXECUTION_LINEAGE_BUNDLE_SCHEMA_VERSION: u16 = 4;
const LEGACY_TRACE_BUNDLE_SCHEMA_VERSION_V1: u16 = 1;
const LEGACY_TRACE_BUNDLE_SCHEMA_VERSION_V2: u16 = 2;
const LEGACY_EXECUTION_LINEAGE_BUNDLE_SCHEMA_VERSION_V3: u16 = 3;
const EXECUTION_LINEAGE_SCHEMA_VERSION: u16 = 2;
const LEGACY_EXECUTION_LINEAGE_SCHEMA_VERSION_V1: u16 = 1;
const TASK_CONTROL_PROJECTION_SCHEMA_VERSION: u16 = 2;
const LEGACY_TASK_CONTROL_PROJECTION_SCHEMA_VERSION_V1: u16 = 1;
const LEGACY_INTENT_CONTROL_ARTIFACT_SCHEMA_VERSION: u16 = 1;

const EXECUTION_LINEAGE_DOMAIN: &[u8] = b"accordlock:v2:execution-lineage\0";
const TASK_CONTROL_PROJECTION_DOMAIN: &[u8] = b"accordlock:v2:task-control-projection\0";
const LEGACY_INTENT_CONTROL_ARTIFACT_DOMAIN: &[u8] = b"accordlock:v1:intent-control-artifact\0";
const LEGACY_TRACE_BUNDLE_DOMAIN_V2: &[u8] = b"accordlock:v2:execution-trace-bundle\0";

/// Whether the completed execution was within pre-approved access or required
/// exact, single-use review.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskScopeStatus {
    WithinApprovedAccess,
    ReviewRequired,
}

/// Whether the exact execution required and received human review.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskReviewStatus {
    NotRequired,
    Approved,
}

/// How the compact task-control projection is supported by persisted evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskControlProvenance {
    /// The verified decision digest is a field of the current execution lineage.
    LineageBound,
    /// A legacy schema-2 bundle embeds and commits the former control artifact.
    Embedded,
    /// A legacy schema-1 bundle predates control artifacts; the projection is
    /// reconstructed from its separately verified authorization decision.
    Reconstructed,
}

/// Bounded, non-secret projection of the authorization decision used by the
/// audit UI. It is always derived from a fully verified decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TaskControlProjection {
    pub schema_version: u16,
    pub execution_request_hash: Digest32,
    pub task_policy_hash: Digest32,
    pub authorization_decision_hash: Digest32,
    pub policy_decision_hash: Digest32,
    pub conformance_evaluation_hashes: Vec<Digest32>,
    #[serde(default = "zero_digest", skip_serializing_if = "is_zero_digest")]
    pub intent_evaluation_hash: Digest32,
    pub task_scope_status: TaskScopeStatus,
    pub review_status: TaskReviewStatus,
    pub decision_reason_code: String,
    pub approval_evidence_hash: Option<Digest32>,
    pub decided_at: i64,
}

impl TaskControlProjection {
    pub(crate) fn from_decision(
        decision: &AuthorizationDecision,
    ) -> Result<Self, PolicyEvaluationError> {
        decision
            .validate()
            .map_err(|_| binding_error("authorization decision"))?;
        let (task_scope_status, review_status, expected_reason) = match decision.outcome {
            AuthorizationOutcome::Allow => (
                TaskScopeStatus::WithinApprovedAccess,
                TaskReviewStatus::NotRequired,
                "POLICY_CONFORMANT",
            ),
            AuthorizationOutcome::AllowAfterApproval => (
                TaskScopeStatus::ReviewRequired,
                TaskReviewStatus::Approved,
                "ACTION_APPROVAL_ACCEPTED",
            ),
            AuthorizationOutcome::ApprovalRequired | AuthorizationOutcome::Deny => {
                return Err(binding_error("non-authorizing decision"));
            }
        };
        if decision.reason_code != expected_reason {
            return Err(binding_error("authorization decision reason"));
        }
        let current = decision.schema_version
            == accordlock_agent_protocol::AUTHORIZATION_DECISION_SCHEMA_VERSION;
        Ok(Self {
            schema_version: if current {
                TASK_CONTROL_PROJECTION_SCHEMA_VERSION
            } else {
                LEGACY_TASK_CONTROL_PROJECTION_SCHEMA_VERSION_V1
            },
            execution_request_hash: decision.request_hash,
            task_policy_hash: decision.task_policy_hash,
            authorization_decision_hash: decision
                .digest()
                .map_err(|_| binding_error("authorization decision"))?,
            policy_decision_hash: decision.policy_decision_hash,
            conformance_evaluation_hashes: decision.conformance_evaluation_hashes.clone(),
            intent_evaluation_hash: if current {
                decision.intent_evaluation_hash
            } else {
                zero_digest()
            },
            task_scope_status,
            review_status,
            decision_reason_code: decision.reason_code.clone(),
            approval_evidence_hash: decision.approval_evidence_hash,
            decided_at: decision.decided_at,
        })
    }

    pub(crate) fn digest(&self) -> Result<Digest32, PolicyEvaluationError> {
        match self.schema_version {
            TASK_CONTROL_PROJECTION_SCHEMA_VERSION
                if !is_zero_digest(&self.intent_evaluation_hash) =>
            {
                committed_digest(TASK_CONTROL_PROJECTION_DOMAIN, self)
            }
            LEGACY_TASK_CONTROL_PROJECTION_SCHEMA_VERSION_V1
                if is_zero_digest(&self.intent_evaluation_hash) =>
            {
                committed_digest(b"accordlock:v1:task-control-projection\0", self)
            }
            _ => Err(binding_error("task control projection schema")),
        }
    }
}

/// Exact, provider-neutral lineage for one completed execution.
///
/// Every digest below is derived from the complete validated object. No prompt,
/// tool argument, model output, or tool result is persisted in this record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecutionLineage {
    pub schema_version: u16,
    pub task_id: Uuid,
    pub session_id: String,
    pub run_id: String,
    pub workspace_root: String,
    pub policy_epoch: u64,
    pub task_objective_hash: Digest32,
    pub task_policy_hash: Digest32,
    pub tool_proposal_hash: Digest32,
    pub execution_request_hash: Digest32,
    #[serde(default = "zero_digest", skip_serializing_if = "is_zero_digest")]
    pub intent_evaluation_hash: Digest32,
    pub authorization_decision_hash: Digest32,
    pub execution_authorization_hash: Digest32,
    pub execution_record_hash: Digest32,
    pub started_at: i64,
    pub completed_at: i64,
}

impl ExecutionLineage {
    fn derive(
        approved: &ApprovedSession,
        proposal: &ToolCallProposal,
        request: &ExecutionRequest,
        decision: &AuthorizationDecision,
        authorization: &ExecutionAuthorization,
        record: &ExecutionRecord,
    ) -> Result<Self, PolicyEvaluationError> {
        verify_complete_chain(approved, proposal, request, decision, authorization, record)?;
        Ok(Self {
            schema_version: EXECUTION_LINEAGE_SCHEMA_VERSION,
            task_id: approved.task_id,
            session_id: approved.session_id.clone(),
            run_id: approved.run_id.clone(),
            workspace_root: approved.workspace_root.clone(),
            policy_epoch: approved.policy_epoch,
            task_objective_hash: approved.task_policy.task_objective_hash,
            task_policy_hash: approved.task_policy_hash,
            tool_proposal_hash: proposal_digest(proposal)?,
            execution_request_hash: request
                .digest()
                .map_err(|_| binding_error("execution request"))?,
            intent_evaluation_hash: decision.intent_evaluation_hash,
            authorization_decision_hash: decision
                .digest()
                .map_err(|_| binding_error("authorization decision"))?,
            execution_authorization_hash: authorization
                .digest()
                .map_err(|_| binding_error("execution authorization"))?,
            execution_record_hash: record
                .digest()
                .map_err(|_| binding_error("execution record"))?,
            started_at: record.consumed_at,
            completed_at: record.completed_at,
        })
    }

    fn derive_legacy_v1(
        approved: &ApprovedSession,
        proposal: &ToolCallProposal,
        request: &ExecutionRequest,
        decision: &AuthorizationDecision,
        authorization: &ExecutionAuthorization,
        record: &ExecutionRecord,
    ) -> Result<Self, PolicyEvaluationError> {
        verify_complete_chain(approved, proposal, request, decision, authorization, record)?;
        Ok(Self {
            schema_version: LEGACY_EXECUTION_LINEAGE_SCHEMA_VERSION_V1,
            task_id: approved.task_id,
            session_id: approved.session_id.clone(),
            run_id: approved.run_id.clone(),
            workspace_root: approved.workspace_root.clone(),
            policy_epoch: approved.policy_epoch,
            task_objective_hash: approved.task_policy.task_objective_hash,
            task_policy_hash: approved.task_policy_hash,
            tool_proposal_hash: proposal_digest(proposal)?,
            execution_request_hash: request
                .digest()
                .map_err(|_| binding_error("execution request"))?,
            intent_evaluation_hash: zero_digest(),
            authorization_decision_hash: decision
                .digest()
                .map_err(|_| binding_error("authorization decision"))?,
            execution_authorization_hash: authorization
                .digest()
                .map_err(|_| binding_error("execution authorization"))?,
            execution_record_hash: record
                .digest()
                .map_err(|_| binding_error("execution record"))?,
            started_at: record.consumed_at,
            completed_at: record.completed_at,
        })
    }

    fn digest(&self) -> Result<Digest32, PolicyEvaluationError> {
        match self.schema_version {
            EXECUTION_LINEAGE_SCHEMA_VERSION if !is_zero_digest(&self.intent_evaluation_hash) => {
                committed_digest(EXECUTION_LINEAGE_DOMAIN, self)
            }
            LEGACY_EXECUTION_LINEAGE_SCHEMA_VERSION_V1
                if is_zero_digest(&self.intent_evaluation_hash) =>
            {
                committed_digest(b"accordlock:v1:execution-lineage\0", self)
            }
            _ => Err(binding_error("execution lineage schema")),
        }
    }
}

/// Exact legacy schema-2 payload. Kept only so historical completed actions can
/// still be audited under the commitment format that created them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyIntentControlArtifact {
    schema_version: u16,
    request_hash: Digest32,
    task_policy_hash: Digest32,
    authorization_decision_hash: Digest32,
    policy_decision_hash: Digest32,
    conformance_evaluation_hashes: Vec<Digest32>,
    intent_status: LegacyIntentStatus,
    review_status: TaskReviewStatus,
    reason_code: String,
    approval_evidence_hash: Option<Digest32>,
    evaluated_at: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum LegacyIntentStatus {
    WithinApprovedAccess,
    ReviewRequired,
}

impl LegacyIntentControlArtifact {
    fn from_decision(decision: &AuthorizationDecision) -> Result<Self, PolicyEvaluationError> {
        let current = TaskControlProjection::from_decision(decision)?;
        Ok(Self {
            schema_version: LEGACY_INTENT_CONTROL_ARTIFACT_SCHEMA_VERSION,
            request_hash: current.execution_request_hash,
            task_policy_hash: current.task_policy_hash,
            authorization_decision_hash: current.authorization_decision_hash,
            policy_decision_hash: current.policy_decision_hash,
            conformance_evaluation_hashes: current.conformance_evaluation_hashes,
            intent_status: match current.task_scope_status {
                TaskScopeStatus::WithinApprovedAccess => LegacyIntentStatus::WithinApprovedAccess,
                TaskScopeStatus::ReviewRequired => LegacyIntentStatus::ReviewRequired,
            },
            review_status: current.review_status,
            reason_code: current.decision_reason_code,
            approval_evidence_hash: current.approval_evidence_hash,
            evaluated_at: current.decided_at,
        })
    }

    fn validate_for(&self, decision: &AuthorizationDecision) -> Result<(), PolicyEvaluationError> {
        if self.schema_version != LEGACY_INTENT_CONTROL_ARTIFACT_SCHEMA_VERSION
            || self != &Self::from_decision(decision)?
        {
            return Err(binding_error("legacy intent control artifact"));
        }
        Ok(())
    }

    fn digest(&self) -> Result<Digest32, PolicyEvaluationError> {
        committed_digest(LEGACY_INTENT_CONTROL_ARTIFACT_DOMAIN, self)
    }
}

#[derive(Serialize)]
struct LegacyBundleCommitment<'a> {
    schema_version: u16,
    trace_hash: Digest32,
    intent_control_hash: Digest32,
    intent_control: &'a LegacyIntentControlArtifact,
}

/// Versioned persisted evidence for a completed action.
///
/// Schemas 1 and 2 represent historical `IntentTrace` records; schema 3 is the
/// historical first execution-lineage record. All three are read-only. Schema
/// 4 writes the current lineage, including the pre-execution intent-evaluation
/// commitment bound into authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompletedExecutionEvidence {
    pub schema_version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    trace: Option<IntentTrace>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    requirements: Vec<TaskRequirement>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    transformations: Vec<TransformationStep>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    trace_hash: Option<Digest32>,
    #[serde(
        default,
        rename = "intent_control",
        skip_serializing_if = "Option::is_none"
    )]
    legacy_intent_control: Option<LegacyIntentControlArtifact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bundle_hash: Option<Digest32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lineage: Option<ExecutionLineage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lineage_hash: Option<Digest32>,
}

impl CompletedExecutionEvidence {
    pub(crate) fn build(
        approved: &ApprovedSession,
        proposal: &ToolCallProposal,
        request: &ExecutionRequest,
        decision: &AuthorizationDecision,
        authorization: &ExecutionAuthorization,
        record: &ExecutionRecord,
    ) -> Result<Self, PolicyEvaluationError> {
        let lineage =
            ExecutionLineage::derive(approved, proposal, request, decision, authorization, record)?;
        let lineage_hash = lineage.digest()?;
        let bundle = Self {
            schema_version: EXECUTION_LINEAGE_BUNDLE_SCHEMA_VERSION,
            trace: None,
            requirements: Vec::new(),
            transformations: Vec::new(),
            trace_hash: None,
            legacy_intent_control: None,
            bundle_hash: None,
            lineage: Some(lineage),
            lineage_hash: Some(lineage_hash),
        };
        bundle.validate_for(approved, proposal, request, decision, authorization, record)?;
        Ok(bundle)
    }

    pub(crate) fn validate_for(
        &self,
        approved: &ApprovedSession,
        proposal: &ToolCallProposal,
        request: &ExecutionRequest,
        decision: &AuthorizationDecision,
        authorization: &ExecutionAuthorization,
        record: &ExecutionRecord,
    ) -> Result<(), PolicyEvaluationError> {
        verify_complete_chain(approved, proposal, request, decision, authorization, record)?;
        match self.schema_version {
            LEGACY_TRACE_BUNDLE_SCHEMA_VERSION_V1 | LEGACY_TRACE_BUNDLE_SCHEMA_VERSION_V2 => {
                self.validate_legacy_for(approved, proposal, decision, authorization, record)
            }
            LEGACY_EXECUTION_LINEAGE_BUNDLE_SCHEMA_VERSION_V3 => {
                if self.trace.is_some()
                    || !self.requirements.is_empty()
                    || !self.transformations.is_empty()
                    || self.trace_hash.is_some()
                    || self.legacy_intent_control.is_some()
                    || self.bundle_hash.is_some()
                {
                    return Err(binding_error("legacy execution lineage fields"));
                }
                let expected = ExecutionLineage::derive_legacy_v1(
                    approved,
                    proposal,
                    request,
                    decision,
                    authorization,
                    record,
                )?;
                if self.lineage.as_ref() != Some(&expected)
                    || self.lineage_hash != Some(expected.digest()?)
                {
                    return Err(binding_error("legacy execution lineage"));
                }
                Ok(())
            }
            EXECUTION_LINEAGE_BUNDLE_SCHEMA_VERSION => {
                if self.trace.is_some()
                    || !self.requirements.is_empty()
                    || !self.transformations.is_empty()
                    || self.trace_hash.is_some()
                    || self.legacy_intent_control.is_some()
                    || self.bundle_hash.is_some()
                {
                    return Err(binding_error("execution lineage legacy fields"));
                }
                let expected = ExecutionLineage::derive(
                    approved,
                    proposal,
                    request,
                    decision,
                    authorization,
                    record,
                )?;
                if self.lineage.as_ref() != Some(&expected)
                    || self.lineage_hash != Some(expected.digest()?)
                {
                    return Err(binding_error("execution lineage"));
                }
                Ok(())
            }
            _ => Err(PolicyEvaluationError::WrongSchema(
                "completed execution evidence",
            )),
        }
    }

    pub(crate) fn commitment(&self) -> Result<Digest32, PolicyEvaluationError> {
        match self.schema_version {
            LEGACY_TRACE_BUNDLE_SCHEMA_VERSION_V1
                if self.legacy_intent_control.is_none()
                    && self.bundle_hash.is_none()
                    && self.lineage.is_none()
                    && self.lineage_hash.is_none() =>
            {
                self.trace_hash
                    .ok_or_else(|| binding_error("legacy execution trace hash"))
            }
            LEGACY_TRACE_BUNDLE_SCHEMA_VERSION_V2
                if self.lineage.is_none() && self.lineage_hash.is_none() =>
            {
                let expected = self.compute_legacy_v2_bundle_hash()?;
                if self.bundle_hash != Some(expected) {
                    return Err(binding_error("legacy execution trace commitment"));
                }
                Ok(expected)
            }
            LEGACY_EXECUTION_LINEAGE_BUNDLE_SCHEMA_VERSION_V3
                if self.trace.is_none()
                    && self.requirements.is_empty()
                    && self.transformations.is_empty()
                    && self.trace_hash.is_none()
                    && self.legacy_intent_control.is_none()
                    && self.bundle_hash.is_none() =>
            {
                let lineage = self
                    .lineage
                    .as_ref()
                    .ok_or_else(|| binding_error("missing legacy execution lineage"))?;
                let expected = lineage.digest()?;
                if self.lineage_hash != Some(expected) {
                    return Err(binding_error("legacy execution lineage commitment"));
                }
                Ok(expected)
            }
            EXECUTION_LINEAGE_BUNDLE_SCHEMA_VERSION
                if self.trace.is_none()
                    && self.requirements.is_empty()
                    && self.transformations.is_empty()
                    && self.trace_hash.is_none()
                    && self.legacy_intent_control.is_none()
                    && self.bundle_hash.is_none() =>
            {
                let lineage = self
                    .lineage
                    .as_ref()
                    .ok_or_else(|| binding_error("missing execution lineage"))?;
                let expected = lineage.digest()?;
                if self.lineage_hash != Some(expected) {
                    return Err(binding_error("execution lineage commitment"));
                }
                Ok(expected)
            }
            _ => Err(PolicyEvaluationError::WrongSchema(
                "completed execution evidence",
            )),
        }
    }

    pub(crate) fn task_control_for(
        &self,
        decision: &AuthorizationDecision,
    ) -> Result<(TaskControlProjection, TaskControlProvenance), PolicyEvaluationError> {
        let projection = TaskControlProjection::from_decision(decision)?;
        let provenance = match self.schema_version {
            LEGACY_TRACE_BUNDLE_SCHEMA_VERSION_V1 => TaskControlProvenance::Reconstructed,
            LEGACY_TRACE_BUNDLE_SCHEMA_VERSION_V2 => {
                self.legacy_intent_control
                    .as_ref()
                    .ok_or_else(|| binding_error("missing legacy intent control artifact"))?
                    .validate_for(decision)?;
                TaskControlProvenance::Embedded
            }
            LEGACY_EXECUTION_LINEAGE_BUNDLE_SCHEMA_VERSION_V3 => {
                TaskControlProvenance::LineageBound
            }
            EXECUTION_LINEAGE_BUNDLE_SCHEMA_VERSION => TaskControlProvenance::LineageBound,
            _ => {
                return Err(PolicyEvaluationError::WrongSchema(
                    "completed execution evidence",
                ));
            }
        };
        Ok((projection, provenance))
    }

    /// Derives the current lineage digest from the complete validated chain.
    ///
    /// For schema 4 this equals the embedded lineage commitment. For legacy
    /// schemas 1 and 2 it is deliberately distinct from the historical storage
    /// commitment: the latter is verified by [`Self::commitment`], while this
    /// method constructs the precise lineage that old formats did not contain.
    pub(crate) fn execution_lineage_digest_for(
        &self,
        approved: &ApprovedSession,
        proposal: &ToolCallProposal,
        request: &ExecutionRequest,
        decision: &AuthorizationDecision,
        authorization: &ExecutionAuthorization,
        record: &ExecutionRecord,
    ) -> Result<Digest32, PolicyEvaluationError> {
        self.validate_for(approved, proposal, request, decision, authorization, record)?;
        if self.schema_version == LEGACY_EXECUTION_LINEAGE_BUNDLE_SCHEMA_VERSION_V3 {
            ExecutionLineage::derive_legacy_v1(
                approved,
                proposal,
                request,
                decision,
                authorization,
                record,
            )?
            .digest()
        } else {
            ExecutionLineage::derive(approved, proposal, request, decision, authorization, record)?
                .digest()
        }
    }

    #[cfg(test)]
    pub(crate) fn build_legacy_for_test(
        schema_version: u16,
        approved: &ApprovedSession,
        proposal: &ToolCallProposal,
        request: &ExecutionRequest,
        decision: &AuthorizationDecision,
        authorization: &ExecutionAuthorization,
        record: &ExecutionRecord,
    ) -> Result<Self, PolicyEvaluationError> {
        verify_complete_chain(approved, proposal, request, decision, authorization, record)?;
        if !matches!(
            schema_version,
            LEGACY_TRACE_BUNDLE_SCHEMA_VERSION_V1 | LEGACY_TRACE_BUNDLE_SCHEMA_VERSION_V2
        ) {
            return Err(PolicyEvaluationError::WrongSchema(
                "legacy completed execution evidence",
            ));
        }
        let requirement = RequirementCommitment::new(
            approved.task_policy.task_objective_hash,
            NormalizedScore::ONE,
        )?;
        let completed = IntentTraceBuilder::start(
            RequestArtifact::new(
                approved.task_policy_hash,
                approved.task_policy.task_objective_hash,
            )?,
            [requirement],
        )?
        .append_plan(PlanArtifact::new(
            approved.task_policy_hash,
            proposal_digest(proposal)?,
            record.consumed_at,
        )?)?
        .append_action(ActionArtifact::new(
            approved.task_policy_hash,
            authorization
                .digest()
                .map_err(|_| binding_error("execution authorization"))?,
            record.consumed_at,
        )?)?
        .append_result(ResultArtifact::new(
            approved.task_policy_hash,
            record
                .digest()
                .map_err(|_| binding_error("execution record"))?,
            record.completed_at,
        )?)?;
        let (trace, requirements, transformations) = completed.into_parts();
        let trace_hash = trace.digest()?;
        let mut evidence = Self {
            schema_version,
            trace: Some(trace),
            requirements,
            transformations,
            trace_hash: Some(trace_hash),
            legacy_intent_control: None,
            bundle_hash: None,
            lineage: None,
            lineage_hash: None,
        };
        if schema_version == LEGACY_TRACE_BUNDLE_SCHEMA_VERSION_V2 {
            evidence.legacy_intent_control =
                Some(LegacyIntentControlArtifact::from_decision(decision)?);
            evidence.bundle_hash = Some(evidence.compute_legacy_v2_bundle_hash()?);
        }
        evidence.validate_for(approved, proposal, request, decision, authorization, record)?;
        Ok(evidence)
    }

    fn validate_legacy_for(
        &self,
        approved: &ApprovedSession,
        proposal: &ToolCallProposal,
        decision: &AuthorizationDecision,
        authorization: &ExecutionAuthorization,
        record: &ExecutionRecord,
    ) -> Result<(), PolicyEvaluationError> {
        if self.lineage.is_some() || self.lineage_hash.is_some() {
            return Err(binding_error("legacy execution trace lineage fields"));
        }
        let trace = self
            .trace
            .as_ref()
            .ok_or_else(|| binding_error("missing legacy execution trace"))?;
        let trace_hash = self
            .trace_hash
            .ok_or_else(|| binding_error("missing legacy execution trace hash"))?;
        trace.verify_bindings(&self.requirements, &self.transformations)?;
        if trace.digest()? != trace_hash
            || trace.task_hash != approved.task_policy_hash
            || trace.request_hash != approved.task_policy.task_objective_hash
            || trace.plan_hash != proposal_digest(proposal)?
            || trace.action_hash
                != authorization
                    .digest()
                    .map_err(|_| binding_error("execution authorization"))?
            || trace.result_hash
                != record
                    .digest()
                    .map_err(|_| binding_error("execution record"))?
            || trace.recorded_at != record.completed_at
            || self.transformations.len() != 3
            || self.transformations[0].recorded_at != record.consumed_at
            || self.transformations[1].recorded_at != record.consumed_at
            || self.transformations[2].recorded_at != record.completed_at
        {
            return Err(binding_error("legacy execution trace bundle"));
        }
        match self.schema_version {
            LEGACY_TRACE_BUNDLE_SCHEMA_VERSION_V1 => {
                if self.legacy_intent_control.is_some() || self.bundle_hash.is_some() {
                    return Err(binding_error("legacy schema-1 execution trace bundle"));
                }
            }
            LEGACY_TRACE_BUNDLE_SCHEMA_VERSION_V2 => {
                self.legacy_intent_control
                    .as_ref()
                    .ok_or_else(|| binding_error("missing legacy intent control artifact"))?
                    .validate_for(decision)?;
                if self.bundle_hash != Some(self.compute_legacy_v2_bundle_hash()?) {
                    return Err(binding_error("legacy schema-2 execution trace commitment"));
                }
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    fn compute_legacy_v2_bundle_hash(&self) -> Result<Digest32, PolicyEvaluationError> {
        let trace_hash = self
            .trace_hash
            .ok_or_else(|| binding_error("missing legacy execution trace hash"))?;
        let intent_control = self
            .legacy_intent_control
            .as_ref()
            .ok_or_else(|| binding_error("missing legacy intent control artifact"))?;
        committed_digest(
            LEGACY_TRACE_BUNDLE_DOMAIN_V2,
            &LegacyBundleCommitment {
                schema_version: self.schema_version,
                trace_hash,
                intent_control_hash: intent_control.digest()?,
                intent_control,
            },
        )
    }
}

fn verify_complete_chain(
    approved: &ApprovedSession,
    proposal: &ToolCallProposal,
    request: &ExecutionRequest,
    decision: &AuthorizationDecision,
    authorization: &ExecutionAuthorization,
    record: &ExecutionRecord,
) -> Result<(), PolicyEvaluationError> {
    approved
        .validate_durable()
        .map_err(|_| binding_error("approved session"))?;
    proposal
        .validate()
        .map_err(|_| binding_error("tool proposal"))?;
    request
        .validate()
        .map_err(|_| binding_error("execution request"))?;
    decision
        .verify_for_request(request)
        .map_err(|_| binding_error("authorization decision"))?;
    authorization
        .verify_for(request, decision)
        .map_err(|_| binding_error("execution authorization"))?;
    record
        .verify_for(request, authorization)
        .map_err(|_| binding_error("execution record"))?;

    let proposal_arguments_hash = proposal
        .arguments_digest()
        .map_err(|_| binding_error("tool proposal arguments"))?;
    if proposal.session_id != request.session_id
        || proposal.run_id != request.run_id
        || proposal.tool_call_id != request.tool_call_id
        || proposal.workspace_root != request.workspace
        || proposal.extension_id != request.extension
        || proposal.tool_name != request.tool
        || proposal_arguments_hash != request.canonical_args_hash
    {
        return Err(binding_error("tool proposal to execution request"));
    }

    if request.session_id != approved.session_id
        || request.run_id != approved.run_id
        || request.workspace != approved.workspace_root
        || request.policy_epoch != approved.policy_epoch
        || request.task_policy_hash != approved.task_policy_hash
        || request.created_at < approved.approved_at
        || request.expires_at > approved.expires_at
        || !approved.authorizes(&request.extension, &request.tool)
    {
        return Err(binding_error("approved session scope"));
    }
    Ok(())
}

fn proposal_digest(proposal: &ToolCallProposal) -> Result<Digest32, PolicyEvaluationError> {
    proposal
        .digest()
        .map_err(|_| binding_error("tool proposal"))?
        .parse::<Digest32>()
        .map_err(|_| binding_error("tool proposal digest"))
}

const fn zero_digest() -> Digest32 {
    Digest32::from_bytes([0; 32])
}

fn is_zero_digest(value: &Digest32) -> bool {
    value.as_bytes().iter().all(|byte| *byte == 0)
}

const fn binding_error(field: &'static str) -> PolicyEvaluationError {
    PolicyEvaluationError::BindingMismatch(field)
}

fn committed_digest<T: Serialize + ?Sized>(
    domain: &[u8],
    value: &T,
) -> Result<Digest32, PolicyEvaluationError> {
    domain_digest(domain, value)
        .map_err(|error| PolicyEvaluationError::Canonical(error.to_string()))?
        .parse::<Digest32>()
        .map_err(|error| PolicyEvaluationError::Canonical(error.clone()))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use accordlock_agent_protocol::{
        AUTHORIZATION_DECISION_SCHEMA_VERSION, EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
        EXECUTION_RECORD_SCHEMA_VERSION, EXECUTION_REQUEST_SCHEMA_VERSION, ExecutionOutcome,
    };
    use serde_json::json;

    use super::*;
    use crate::{Capability, TaskPolicy, canonical::digest_bytes};

    struct Chain {
        approved: ApprovedSession,
        proposal: ToolCallProposal,
        request: ExecutionRequest,
        decision: AuthorizationDecision,
        authorization: ExecutionAuthorization,
        record: ExecutionRecord,
    }

    #[allow(clippy::too_many_lines)]
    fn chain(task_id: Uuid, objective: &[u8]) -> Result<Chain, Box<dyn std::error::Error>> {
        let task_policy = TaskPolicy::new(Digest32::sha256(objective), [], [])?;
        let approved = ApprovedSession::new_with_task_objective(
            task_id,
            "session",
            "run",
            Path::new("."),
            7,
            std::str::from_utf8(objective)?,
            task_policy,
            [Capability::new("developer", "read")],
            10,
            100,
        )?;
        let arguments = json!({"path": "README.md"});
        let arguments_sha256 =
            digest_bytes(&crate::canonical::canonical_json_bytes(&arguments)?).to_string();
        let proposal = ToolCallProposal {
            schema_version: crate::model::TOOL_EXECUTION_SCHEMA_VERSION,
            session_id: approved.session_id.clone(),
            run_id: approved.run_id.clone(),
            tool_call_id: "call".to_owned(),
            workspace_root: approved.workspace_root.clone(),
            extension_id: "developer".to_owned(),
            tool_name: "read".to_owned(),
            arguments,
            arguments_sha256: arguments_sha256.clone(),
            agent_plan_checkpoint: crate::model::test_agent_plan_checkpoint(
                &approved.session_id,
                &approved.run_id,
                "call",
                "developer__read",
                &arguments_sha256,
                19,
            ),
        };
        let request = ExecutionRequest {
            schema_version: EXECUTION_REQUEST_SCHEMA_VERSION,
            request_id: Uuid::parse_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")?,
            session_id: approved.session_id.clone(),
            run_id: approved.run_id.clone(),
            tool_call_id: proposal.tool_call_id.clone(),
            workspace: approved.workspace_root.clone(),
            extension: proposal.extension_id.clone(),
            tool: proposal.tool_name.clone(),
            canonical_args_hash: proposal.arguments_digest()?,
            policy_epoch: approved.policy_epoch,
            task_policy_hash: approved.task_policy_hash,
            created_at: 20,
            expires_at: 40,
        };
        let decision = AuthorizationDecision {
            schema_version: AUTHORIZATION_DECISION_SCHEMA_VERSION,
            request_hash: request.digest()?,
            session_id: request.session_id.clone(),
            run_id: request.run_id.clone(),
            tool_call_id: request.tool_call_id.clone(),
            workspace: request.workspace.clone(),
            extension: request.extension.clone(),
            tool: request.tool.clone(),
            canonical_args_hash: request.canonical_args_hash,
            policy_epoch: request.policy_epoch,
            task_policy_hash: request.task_policy_hash,
            policy_decision_hash: Digest32::sha256(b"policy decision"),
            conformance_evaluation_hashes: vec![Digest32::sha256(b"conformance")],
            intent_evaluation_hash: Digest32::sha256(b"pre-execution intent evaluation"),
            outcome: AuthorizationOutcome::Allow,
            reason_code: "POLICY_CONFORMANT".to_owned(),
            approval_evidence_hash: None,
            decided_at: 20,
            expires_at: 40,
        };
        let authorization = ExecutionAuthorization {
            schema_version: EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
            authorization_id: Uuid::parse_str("cccccccc-cccc-4ccc-8ccc-cccccccccccc")?,
            request_hash: request.digest()?,
            authorization_decision_hash: decision.digest()?,
            session_id: request.session_id.clone(),
            run_id: request.run_id.clone(),
            tool_call_id: request.tool_call_id.clone(),
            workspace: request.workspace.clone(),
            extension: request.extension.clone(),
            tool: request.tool.clone(),
            canonical_args_hash: request.canonical_args_hash,
            policy_epoch: request.policy_epoch,
            task_policy_hash: request.task_policy_hash,
            issued_at: 20,
            not_before: 20,
            expires_at: 40,
        };
        let record = ExecutionRecord {
            schema_version: EXECUTION_RECORD_SCHEMA_VERSION,
            record_id: Uuid::parse_str("dddddddd-dddd-4ddd-8ddd-dddddddddddd")?,
            authorization_id: authorization.authorization_id,
            request_hash: request.digest()?,
            authorization_hash: authorization.digest()?,
            session_id: request.session_id.clone(),
            run_id: request.run_id.clone(),
            tool_call_id: request.tool_call_id.clone(),
            workspace: request.workspace.clone(),
            extension: request.extension.clone(),
            tool: request.tool.clone(),
            canonical_args_hash: request.canonical_args_hash,
            policy_epoch: request.policy_epoch,
            task_policy_hash: request.task_policy_hash,
            consumed_at: 20,
            completed_at: 30,
            outcome: ExecutionOutcome::Succeeded,
            result_hash: Digest32::sha256(b"result"),
        };
        Ok(Chain {
            approved,
            proposal,
            request,
            decision,
            authorization,
            record,
        })
    }

    fn legacy_v3_chain(
        task_id: Uuid,
        objective: &[u8],
    ) -> Result<Chain, Box<dyn std::error::Error>> {
        let mut legacy = chain(task_id, objective)?;
        legacy.decision.schema_version = 3;
        legacy.decision.intent_evaluation_hash = zero_digest();
        legacy.authorization.authorization_decision_hash = legacy.decision.digest()?;
        legacy.record.authorization_hash = legacy.authorization.digest()?;
        Ok(legacy)
    }

    fn validate(bundle: &CompletedExecutionEvidence, chain: &Chain) -> bool {
        bundle
            .validate_for(
                &chain.approved,
                &chain.proposal,
                &chain.request,
                &chain.decision,
                &chain.authorization,
                &chain.record,
            )
            .is_ok()
    }

    fn legacy_bundle(
        chain: &Chain,
        schema_version: u16,
    ) -> Result<CompletedExecutionEvidence, Box<dyn std::error::Error>> {
        Ok(CompletedExecutionEvidence::build_legacy_for_test(
            schema_version,
            &chain.approved,
            &chain.proposal,
            &chain.request,
            &chain.decision,
            &chain.authorization,
            &chain.record,
        )?)
    }

    #[test]
    fn lineage_binds_every_complete_transaction_stage() -> Result<(), Box<dyn std::error::Error>> {
        let primary = chain(
            Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")?,
            b"approved task",
        )?;
        let bundle = CompletedExecutionEvidence::build(
            &primary.approved,
            &primary.proposal,
            &primary.request,
            &primary.decision,
            &primary.authorization,
            &primary.record,
        )?;
        assert!(validate(&bundle, &primary));
        assert_eq!(
            bundle.schema_version,
            EXECUTION_LINEAGE_BUNDLE_SCHEMA_VERSION
        );
        assert!(bundle.trace.is_none());
        assert!(bundle.transformations.is_empty());
        assert_eq!(
            bundle.commitment()?,
            bundle.lineage_hash.ok_or("missing hash")?
        );
        let lineage = bundle.lineage.as_ref().ok_or("missing lineage")?;
        assert_eq!(lineage.task_id, primary.approved.task_id);
        assert_eq!(
            lineage.tool_proposal_hash,
            proposal_digest(&primary.proposal)?
        );
        assert_eq!(lineage.execution_request_hash, primary.request.digest()?);
        assert_eq!(
            lineage.intent_evaluation_hash,
            primary.decision.intent_evaluation_hash
        );
        assert_eq!(
            lineage.authorization_decision_hash,
            primary.decision.digest()?
        );
        assert_eq!(
            lineage.execution_authorization_hash,
            primary.authorization.digest()?
        );
        assert_eq!(lineage.execution_record_hash, primary.record.digest()?);
        assert_eq!((lineage.started_at, lineage.completed_at), (20, 30));
        Ok(())
    }

    #[test]
    fn public_completed_execution_example_matches_rust_serialization()
    -> Result<(), Box<dyn std::error::Error>> {
        let lineage = ExecutionLineage {
            schema_version: EXECUTION_LINEAGE_SCHEMA_VERSION,
            task_id: Uuid::parse_str("11111111-1111-4111-8111-111111111111")?,
            session_id: "session-1".to_owned(),
            run_id: "run-1".to_owned(),
            workspace_root: "/workspace".to_owned(),
            policy_epoch: 7,
            task_objective_hash: Digest32::from_bytes([1; 32]),
            task_policy_hash: Digest32::from_bytes([2; 32]),
            tool_proposal_hash: Digest32::from_bytes([3; 32]),
            execution_request_hash: Digest32::from_bytes([4; 32]),
            intent_evaluation_hash: Digest32::from_bytes([8; 32]),
            authorization_decision_hash: Digest32::from_bytes([5; 32]),
            execution_authorization_hash: Digest32::from_bytes([6; 32]),
            execution_record_hash: Digest32::from_bytes([7; 32]),
            started_at: 1_000,
            completed_at: 1_100,
        };
        let lineage_hash = lineage.digest()?;
        let evidence = CompletedExecutionEvidence {
            schema_version: EXECUTION_LINEAGE_BUNDLE_SCHEMA_VERSION,
            trace: None,
            requirements: Vec::new(),
            transformations: Vec::new(),
            trace_hash: None,
            legacy_intent_control: None,
            bundle_hash: None,
            lineage: Some(lineage),
            lineage_hash: Some(lineage_hash),
        };
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../schemas/examples/completed-execution-evidence.v4.json"
        ))?;
        assert_eq!(serde_json::to_value(&evidence)?, expected);
        Ok(())
    }

    #[test]
    fn legacy_trace_schemas_remain_readable_but_are_never_written()
    -> Result<(), Box<dyn std::error::Error>> {
        let chain = chain(
            Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")?,
            b"approved task",
        )?;
        for schema_version in [
            LEGACY_TRACE_BUNDLE_SCHEMA_VERSION_V1,
            LEGACY_TRACE_BUNDLE_SCHEMA_VERSION_V2,
        ] {
            let historical = legacy_bundle(&chain, schema_version)?;
            let encoded = serde_json::to_string(&historical)?;
            let decoded: CompletedExecutionEvidence = serde_json::from_str(&encoded)?;
            assert!(validate(&decoded, &chain));
            assert_eq!(decoded.commitment()?, historical.commitment()?);
            let (_, provenance) = decoded.task_control_for(&chain.decision)?;
            assert_eq!(
                provenance,
                if schema_version == LEGACY_TRACE_BUNDLE_SCHEMA_VERSION_V1 {
                    TaskControlProvenance::Reconstructed
                } else {
                    TaskControlProvenance::Embedded
                }
            );
        }

        let current = CompletedExecutionEvidence::build(
            &chain.approved,
            &chain.proposal,
            &chain.request,
            &chain.decision,
            &chain.authorization,
            &chain.record,
        )?;
        let encoded = serde_json::to_value(&current)?;
        assert_eq!(
            encoded["schema_version"],
            EXECUTION_LINEAGE_BUNDLE_SCHEMA_VERSION
        );
        assert!(encoded.get("lineage").is_some());
        assert!(encoded.get("trace").is_none());
        assert!(encoded.get("intent_control").is_none());
        Ok(())
    }

    #[test]
    fn legacy_v3_lineage_remains_readable_but_new_builds_write_v4()
    -> Result<(), Box<dyn std::error::Error>> {
        let legacy = legacy_v3_chain(
            Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")?,
            b"approved task",
        )?;
        let lineage = ExecutionLineage::derive_legacy_v1(
            &legacy.approved,
            &legacy.proposal,
            &legacy.request,
            &legacy.decision,
            &legacy.authorization,
            &legacy.record,
        )?;
        let historical = CompletedExecutionEvidence {
            schema_version: LEGACY_EXECUTION_LINEAGE_BUNDLE_SCHEMA_VERSION_V3,
            trace: None,
            requirements: Vec::new(),
            transformations: Vec::new(),
            trace_hash: None,
            legacy_intent_control: None,
            bundle_hash: None,
            lineage_hash: Some(lineage.digest()?),
            lineage: Some(lineage),
        };
        let encoded = serde_json::to_string(&historical)?;
        assert!(!encoded.contains("intent_evaluation_hash"));
        let decoded: CompletedExecutionEvidence = serde_json::from_str(&encoded)?;
        assert!(validate(&decoded, &legacy));
        assert_eq!(decoded.commitment()?, historical.commitment()?);

        let current = chain(
            Uuid::parse_str("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")?,
            b"current approved task",
        )?;
        let written = CompletedExecutionEvidence::build(
            &current.approved,
            &current.proposal,
            &current.request,
            &current.decision,
            &current.authorization,
            &current.record,
        )?;
        assert_eq!(
            written.schema_version,
            EXECUTION_LINEAGE_BUNDLE_SCHEMA_VERSION
        );
        assert_eq!(
            written
                .lineage
                .as_ref()
                .ok_or("missing current lineage")?
                .schema_version,
            EXECUTION_LINEAGE_SCHEMA_VERSION
        );
        Ok(())
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one adversarial test must exercise every bound lineage substitution"
    )]
    fn substituted_objects_and_lineage_fields_are_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let chain = chain(
            Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")?,
            b"approved task",
        )?;
        let bundle = CompletedExecutionEvidence::build(
            &chain.approved,
            &chain.proposal,
            &chain.request,
            &chain.decision,
            &chain.authorization,
            &chain.record,
        )?;

        let mut changed_proposal = chain.proposal.clone();
        changed_proposal.tool_call_id = "other-call".to_owned();
        assert!(
            bundle
                .validate_for(
                    &chain.approved,
                    &changed_proposal,
                    &chain.request,
                    &chain.decision,
                    &chain.authorization,
                    &chain.record,
                )
                .is_err()
        );

        let mut changed_request = chain.request.clone();
        changed_request.request_id = Uuid::parse_str("ffffffff-ffff-4fff-8fff-ffffffffffff")?;
        assert!(
            bundle
                .validate_for(
                    &chain.approved,
                    &chain.proposal,
                    &changed_request,
                    &chain.decision,
                    &chain.authorization,
                    &chain.record,
                )
                .is_err()
        );

        let mut changed_decision = chain.decision.clone();
        changed_decision.policy_decision_hash = Digest32::sha256(b"other decision");
        assert!(
            bundle
                .validate_for(
                    &chain.approved,
                    &chain.proposal,
                    &chain.request,
                    &changed_decision,
                    &chain.authorization,
                    &chain.record,
                )
                .is_err()
        );

        let mut changed_intent_decision = chain.decision.clone();
        changed_intent_decision.intent_evaluation_hash =
            Digest32::sha256(b"substituted pre-execution intent evaluation");
        assert!(
            bundle
                .validate_for(
                    &chain.approved,
                    &chain.proposal,
                    &chain.request,
                    &changed_intent_decision,
                    &chain.authorization,
                    &chain.record,
                )
                .is_err()
        );

        let mut changed_authorization = chain.authorization.clone();
        changed_authorization.authorization_id =
            Uuid::parse_str("99999999-9999-4999-8999-999999999999")?;
        assert!(
            bundle
                .validate_for(
                    &chain.approved,
                    &chain.proposal,
                    &chain.request,
                    &chain.decision,
                    &changed_authorization,
                    &chain.record,
                )
                .is_err()
        );

        let mut changed_record = chain.record.clone();
        changed_record.result_hash = Digest32::sha256(b"other result");
        assert!(
            bundle
                .validate_for(
                    &chain.approved,
                    &chain.proposal,
                    &chain.request,
                    &chain.decision,
                    &chain.authorization,
                    &changed_record,
                )
                .is_err()
        );

        let mut tampered = bundle.clone();
        tampered
            .lineage
            .as_mut()
            .ok_or("missing lineage")?
            .started_at += 1;
        assert!(!validate(&tampered, &chain));

        let mut tampered_intent = bundle.clone();
        tampered_intent
            .lineage
            .as_mut()
            .ok_or("missing lineage")?
            .intent_evaluation_hash = Digest32::sha256(b"substituted lineage intent hash");
        tampered_intent.lineage_hash = Some(
            tampered_intent
                .lineage
                .as_ref()
                .ok_or("missing lineage")?
                .digest()?,
        );
        assert!(
            !validate(&tampered_intent, &chain),
            "recommitting a substituted lineage intent hash must not pass exact derivation"
        );
        Ok(())
    }

    #[test]
    fn cross_task_substitution_is_rejected_even_with_matching_capability()
    -> Result<(), Box<dyn std::error::Error>> {
        let primary = chain(
            Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")?,
            b"approved task",
        )?;
        let bundle = CompletedExecutionEvidence::build(
            &primary.approved,
            &primary.proposal,
            &primary.request,
            &primary.decision,
            &primary.authorization,
            &primary.record,
        )?;
        let other = chain(
            Uuid::parse_str("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")?,
            b"approved task",
        )?;
        assert!(
            bundle
                .validate_for(
                    &other.approved,
                    &primary.proposal,
                    &primary.request,
                    &primary.decision,
                    &primary.authorization,
                    &primary.record,
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn substituted_trusted_times_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let chain = chain(
            Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")?,
            b"approved task",
        )?;
        let bundle = CompletedExecutionEvidence::build(
            &chain.approved,
            &chain.proposal,
            &chain.request,
            &chain.decision,
            &chain.authorization,
            &chain.record,
        )?;
        let mut changed_record = chain.record.clone();
        changed_record.completed_at += 1;
        assert!(
            bundle
                .validate_for(
                    &chain.approved,
                    &chain.proposal,
                    &chain.request,
                    &chain.decision,
                    &chain.authorization,
                    &changed_record,
                )
                .is_err()
        );

        let mut invalid_record = chain.record.clone();
        invalid_record.completed_at = invalid_record.consumed_at - 1;
        assert!(
            CompletedExecutionEvidence::build(
                &chain.approved,
                &chain.proposal,
                &chain.request,
                &chain.decision,
                &chain.authorization,
                &invalid_record,
            )
            .is_err()
        );
        Ok(())
    }
}
