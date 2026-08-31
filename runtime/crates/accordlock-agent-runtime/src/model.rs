use std::{collections::BTreeSet, path::Path};

use accordlock_agent_protocol::{
    Digest32, MAX_CANONICAL_ARGUMENT_BYTES, MAX_EXTENSION_BYTES, MAX_RUN_ID_BYTES,
    MAX_SESSION_ID_BYTES, MAX_TOOL_BYTES, MAX_TOOL_CALL_ID_BYTES, MAX_WORKSPACE_BYTES,
    canonical_args_bytes,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

use crate::canonical::{
    EXECUTION_OBSERVATION_DOMAIN, canonical_json_bytes, digest_bytes, domain_digest, goose_digest,
};
use crate::policy::TaskPolicy;

pub const APPROVED_SESSION_SCHEMA_VERSION: u16 = 3;
pub const SESSION_REVOCATION_SCHEMA_VERSION: u16 = 2;
pub const AGENT_PLAN_CHECKPOINT_SCHEMA_VERSION: u16 = 1;
pub const TOOL_CALL_PROPOSAL_SCHEMA_VERSION: u16 = 3;
/// Stable Desktop-facing protocol used by readiness, health, control, audit,
/// and recovery messages.
pub const DESKTOP_PROTOCOL_SCHEMA_VERSION: u16 = 2;
/// Tool-execution protocol shared with Goose. This version advances only when
/// the proposal/observation or governed execution contract changes.
pub const TOOL_EXECUTION_SCHEMA_VERSION: u16 = TOOL_CALL_PROPOSAL_SCHEMA_VERSION;
pub const MAX_TASK_OBJECTIVE_BYTES: usize = 4_000;
pub const MAX_AGENT_PLAN_MATERIAL_BYTES: usize = 512 * 1024;
const MAX_AGENT_PLAN_TEXT_SEGMENTS: usize = 1_024;
const MAX_AGENT_PLAN_TOOL_REQUESTS: usize = 256;
const LEGACY_APPROVED_SESSION_SCHEMA_VERSION: u16 = 2;
const MAX_WIRE_TIMESTAMP: i64 = 9_007_199_254_740_991;
pub(crate) const MAX_APPROVAL_LIFETIME_SECONDS: i64 = 7 * 24 * 60 * 60;
pub(crate) const MAX_CAPABILITIES: usize = 256;
pub(crate) const MAX_OBSERVATION_BYTES: usize = 8 * 1024;

/// Exact extension/tool capability approved by the Task Policy.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    pub extension_id: String,
    pub tool_name: String,
}

impl Capability {
    #[must_use]
    pub fn new(extension_id: impl Into<String>, tool_name: impl Into<String>) -> Self {
        Self {
            extension_id: extension_id.into(),
            tool_name: tool_name.into(),
        }
    }

    fn validate(&self) -> Result<(), TaskBindingError> {
        validate_text(&self.extension_id, "extension_id", MAX_EXTENSION_BYTES)?;
        validate_text(&self.tool_name, "tool_name", MAX_TOOL_BYTES)
    }
}

/// Durable, pre-approved authority binding installed by the trusted Desktop.
///
/// It is intentionally not constructible from Goose request data. A session
/// gains no authority until the Desktop registers this record in the ledger.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedSession {
    pub schema_version: u16,
    pub task_id: Uuid,
    pub session_id: String,
    pub run_id: String,
    pub workspace_root: String,
    pub policy_epoch: u64,
    pub task_policy: TaskPolicy,
    pub task_policy_hash: Digest32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub task_objective: String,
    pub capabilities: Vec<Capability>,
    pub approved_at: i64,
    pub expires_at: i64,
}

impl ApprovedSession {
    /// Constructs a deterministic approval and canonicalizes its workspace.
    ///
    /// # Errors
    ///
    /// Fails when the workspace is missing/non-Unicode or any binding is not
    /// within the strict Task Policy profile.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        task_id: Uuid,
        session_id: impl Into<String>,
        run_id: impl Into<String>,
        workspace: &Path,
        policy_epoch: u64,
        task_policy: TaskPolicy,
        capabilities: impl IntoIterator<Item = Capability>,
        approved_at: i64,
        expires_at: i64,
    ) -> Result<Self, TaskBindingError> {
        Self::new_legacy(
            task_id,
            session_id,
            run_id,
            workspace,
            policy_epoch,
            task_policy,
            capabilities,
            approved_at,
            expires_at,
        )
    }

    /// Constructs the current schema with the exact approved task objective.
    ///
    /// The objective is retained because a digest alone cannot be evaluated for
    /// intent conformance. Its UTF-8 bytes must hash to the objective commitment
    /// already present in `task_policy`.
    ///
    /// # Errors
    ///
    /// Fails when the workspace cannot be canonicalized, the objective does not
    /// match the task-policy commitment, or any session binding is invalid.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_task_objective(
        task_id: Uuid,
        session_id: impl Into<String>,
        run_id: impl Into<String>,
        workspace: &Path,
        policy_epoch: u64,
        task_objective: impl Into<String>,
        task_policy: TaskPolicy,
        capabilities: impl IntoIterator<Item = Capability>,
        approved_at: i64,
        expires_at: i64,
    ) -> Result<Self, TaskBindingError> {
        let workspace_root = canonical_workspace(workspace)?;
        let capabilities = capabilities.into_iter().collect::<BTreeSet<_>>();
        let task_policy_hash = task_policy
            .digest()
            .map_err(|_| TaskBindingError::InvalidTaskPolicy)?;
        let record = Self {
            schema_version: APPROVED_SESSION_SCHEMA_VERSION,
            task_id,
            session_id: session_id.into(),
            run_id: run_id.into(),
            workspace_root,
            policy_epoch,
            task_policy,
            task_policy_hash,
            task_objective: task_objective.into(),
            capabilities: capabilities.into_iter().collect(),
            approved_at,
            expires_at,
        };
        record.validate()?;
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    fn new_legacy(
        task_id: Uuid,
        session_id: impl Into<String>,
        run_id: impl Into<String>,
        workspace: &Path,
        policy_epoch: u64,
        task_policy: TaskPolicy,
        capabilities: impl IntoIterator<Item = Capability>,
        approved_at: i64,
        expires_at: i64,
    ) -> Result<Self, TaskBindingError> {
        let workspace_root = canonical_workspace(workspace)?;
        let capabilities = capabilities.into_iter().collect::<BTreeSet<_>>();
        let task_policy_hash = task_policy
            .digest()
            .map_err(|_| TaskBindingError::InvalidTaskPolicy)?;
        let record = Self {
            schema_version: LEGACY_APPROVED_SESSION_SCHEMA_VERSION,
            task_id,
            session_id: session_id.into(),
            run_id: run_id.into(),
            workspace_root,
            policy_epoch,
            task_policy,
            task_policy_hash,
            task_objective: String::new(),
            capabilities: capabilities.into_iter().collect(),
            approved_at,
            expires_at,
        };
        record.validate()?;
        Ok(record)
    }

    /// Revalidates the complete binding immediately before durable insertion.
    ///
    /// # Errors
    ///
    /// Returns an exact bounded-profile error without weakening the record.
    pub fn validate(&self) -> Result<(), TaskBindingError> {
        self.validate_durable()?;
        if canonical_workspace(Path::new(&self.workspace_root))? != self.workspace_root {
            return Err(TaskBindingError::NonCanonicalWorkspace);
        }
        Ok(())
    }

    /// Revalidates an already-stored approval without requiring the historical
    /// workspace to remain mounted. New approvals still call [`Self::validate`]
    /// and prove the canonical path against the live filesystem before insert.
    pub(crate) fn validate_durable(&self) -> Result<(), TaskBindingError> {
        if !matches!(
            self.schema_version,
            LEGACY_APPROVED_SESSION_SCHEMA_VERSION | APPROVED_SESSION_SCHEMA_VERSION
        ) {
            return Err(TaskBindingError::WrongSchema);
        }
        if self.task_id.is_nil() {
            return Err(TaskBindingError::NilTask);
        }
        validate_text(&self.session_id, "session_id", MAX_SESSION_ID_BYTES)?;
        validate_text(&self.run_id, "run_id", MAX_RUN_ID_BYTES)?;
        validate_text(&self.workspace_root, "workspace_root", MAX_WORKSPACE_BYTES)?;
        if !Path::new(&self.workspace_root).is_absolute() {
            return Err(TaskBindingError::NonCanonicalWorkspace);
        }
        if self.policy_epoch == 0 || self.policy_epoch > i64::MAX as u64 {
            return Err(TaskBindingError::InvalidPolicyEpoch);
        }
        let task_policy_hash = self
            .task_policy
            .digest()
            .map_err(|_| TaskBindingError::InvalidTaskPolicy)?;
        if task_policy_hash != self.task_policy_hash {
            return Err(TaskBindingError::TaskPolicyHashMismatch);
        }
        match self.schema_version {
            APPROVED_SESSION_SCHEMA_VERSION => {
                if self.task_objective.is_empty()
                    || self.task_objective.len() > MAX_TASK_OBJECTIVE_BYTES
                {
                    return Err(TaskBindingError::InvalidTaskObjective);
                }
                if Digest32::sha256(self.task_objective.as_bytes())
                    != self.task_policy.task_objective_hash
                {
                    return Err(TaskBindingError::TaskObjectiveHashMismatch);
                }
            }
            LEGACY_APPROVED_SESSION_SCHEMA_VERSION if self.task_objective.is_empty() => {}
            LEGACY_APPROVED_SESSION_SCHEMA_VERSION => {
                return Err(TaskBindingError::InvalidTaskObjective);
            }
            _ => unreachable!(),
        }
        validate_window(
            self.approved_at,
            self.expires_at,
            MAX_APPROVAL_LIFETIME_SECONDS,
        )?;
        if self.capabilities.is_empty() || self.capabilities.len() > MAX_CAPABILITIES {
            return Err(TaskBindingError::InvalidCapabilities);
        }
        let mut previous: Option<&Capability> = None;
        for capability in &self.capabilities {
            capability.validate()?;
            if previous.is_some_and(|value| value >= capability) {
                return Err(TaskBindingError::InvalidCapabilities);
            }
            previous = Some(capability);
        }
        if self
            .task_policy
            .preauthorized_capabilities
            .iter()
            .any(|capability| !self.authorizes(&capability.extension_id, &capability.tool_name))
        {
            return Err(TaskBindingError::PreauthorizedCapabilityMismatch);
        }
        Ok(())
    }

    pub(crate) fn authorizes(&self, extension_id: &str, tool_name: &str) -> bool {
        self.capabilities
            .binary_search_by(|candidate| {
                candidate
                    .extension_id
                    .as_str()
                    .cmp(extension_id)
                    .then_with(|| candidate.tool_name.as_str().cmp(tool_name))
            })
            .is_ok()
    }
}

/// Minimal immutable identity of an approved authority to disable.
///
/// Revocation deliberately binds all three identifiers. A session or task
/// identifier alone is not enough to mutate authority, and no user-controlled
/// timestamp participates in the idempotence key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRevocation {
    pub schema_version: u16,
    pub task_id: Uuid,
    pub session_id: String,
    pub run_id: String,
}

impl SessionRevocation {
    #[must_use]
    pub fn new(task_id: Uuid, session_id: impl Into<String>, run_id: impl Into<String>) -> Self {
        Self {
            schema_version: SESSION_REVOCATION_SCHEMA_VERSION,
            task_id,
            session_id: session_id.into(),
            run_id: run_id.into(),
        }
    }

    /// Revalidates the exact authority identity before a durable transition.
    ///
    /// # Errors
    ///
    /// Rejects unsupported schemas, nil task identifiers, and unbounded identifiers.
    pub fn validate(&self) -> Result<(), SessionRevocationError> {
        if self.schema_version != SESSION_REVOCATION_SCHEMA_VERSION {
            return Err(SessionRevocationError::WrongSchema);
        }
        if self.task_id.is_nil() {
            return Err(SessionRevocationError::NilTask);
        }
        validate_revocation_text(&self.session_id, "session_id", MAX_SESSION_ID_BYTES)?;
        validate_revocation_text(&self.run_id, "run_id", MAX_RUN_ID_BYTES)
    }
}

/// Exact Goose request DTO for `authorize-and-consume`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCallProposal {
    pub schema_version: u16,
    pub session_id: String,
    pub run_id: String,
    pub tool_call_id: String,
    pub workspace_root: String,
    pub extension_id: String,
    pub tool_name: String,
    pub arguments: Value,
    pub arguments_sha256: String,
    pub agent_plan_checkpoint: AgentPlanCheckpoint,
}

/// Exact model plan bound to one proposed tool call.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPlanCheckpoint {
    pub schema_version: u16,
    pub session_id: String,
    pub run_id: String,
    pub tool_call_id: String,
    pub material: Value,
    pub material_sha256: String,
    pub recorded_at: i64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentPlanMaterial {
    text: Vec<String>,
    tool_requests: Vec<AgentPlanToolRequest>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentPlanToolRequest {
    id: String,
    name: String,
    arguments_sha256: String,
}

impl AgentPlanCheckpoint {
    /// Validates bounded canonical plan material and its exact proposal scope.
    ///
    /// # Errors
    ///
    /// Fails when the proposal or checkpoint is malformed, when their scopes do
    /// not match exactly, or when the canonical plan digest is inconsistent.
    pub fn validate_for(&self, proposal: &ToolCallProposal) -> Result<(), WireValidationError> {
        proposal.validate_without_plan()?;
        self.validate_scope_for(proposal)
    }

    fn validate_scope_for(&self, proposal: &ToolCallProposal) -> Result<(), WireValidationError> {
        if self.schema_version != AGENT_PLAN_CHECKPOINT_SCHEMA_VERSION {
            return Err(WireValidationError::WrongPlanSchema);
        }
        validate_wire_text(&self.session_id, "plan.session_id", MAX_SESSION_ID_BYTES)?;
        validate_wire_text(&self.run_id, "plan.run_id", MAX_RUN_ID_BYTES)?;
        validate_wire_text(
            &self.tool_call_id,
            "plan.tool_call_id",
            MAX_TOOL_CALL_ID_BYTES,
        )?;
        if self.session_id != proposal.session_id
            || self.run_id != proposal.run_id
            || self.tool_call_id != proposal.tool_call_id
        {
            return Err(WireValidationError::PlanScopeMismatch);
        }
        let bytes = canonical_json_bytes(&self.material)?;
        if bytes.len() > MAX_AGENT_PLAN_MATERIAL_BYTES {
            return Err(WireValidationError::PlanMaterialOutOfProfile);
        }
        let material: AgentPlanMaterial = serde_json::from_value(self.material.clone())
            .map_err(|_| WireValidationError::PlanMaterialOutOfProfile)?;
        if material.text.len() > MAX_AGENT_PLAN_TEXT_SEGMENTS
            || material.tool_requests.is_empty()
            || material.tool_requests.len() > MAX_AGENT_PLAN_TOOL_REQUESTS
        {
            return Err(WireValidationError::PlanMaterialOutOfProfile);
        }
        let expected_prefixed_name = format!("{}__{}", proposal.extension_id, proposal.tool_name);
        let mut request_ids = BTreeSet::new();
        let mut matching_request_count = 0_usize;
        for request in &material.tool_requests {
            validate_wire_text(&request.id, "plan.tool_request.id", MAX_TOOL_CALL_ID_BYTES)?;
            validate_wire_text(&request.name, "plan.tool_request.name", MAX_TOOL_BYTES)?;
            parse_digest(&request.arguments_sha256)?;
            if !request_ids.insert(request.id.as_str()) {
                return Err(WireValidationError::PlanMaterialOutOfProfile);
            }
            if request.id == proposal.tool_call_id {
                matching_request_count += 1;
                if request.arguments_sha256 != proposal.arguments_sha256
                    || (request.name != proposal.tool_name
                        && request.name != expected_prefixed_name)
                {
                    return Err(WireValidationError::PlanScopeMismatch);
                }
            }
        }
        if matching_request_count != 1 {
            return Err(WireValidationError::PlanScopeMismatch);
        }
        if self.material_sha256 != digest_bytes(&bytes).to_string() {
            return Err(WireValidationError::PlanDigestMismatch);
        }
        parse_digest(&self.material_sha256)?;
        if !(1..=MAX_WIRE_TIMESTAMP).contains(&self.recorded_at) {
            return Err(WireValidationError::InvalidPlanTimestamp);
        }
        Ok(())
    }

    pub(crate) fn material_digest(
        &self,
        proposal: &ToolCallProposal,
    ) -> Result<Digest32, WireValidationError> {
        self.validate_for(proposal)?;
        parse_digest(&self.material_sha256)
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "the fixed json! fixture is canonical and a Result would burden every test caller"
)]
pub(crate) fn test_agent_plan_checkpoint(
    session_id: &str,
    run_id: &str,
    tool_call_id: &str,
    model_tool_name: &str,
    arguments_sha256: &str,
    recorded_at: i64,
) -> AgentPlanCheckpoint {
    let material = serde_json::json!({
        "text": ["Execute the exact test action."],
        "tool_requests": [{
            "id": tool_call_id,
            "name": model_tool_name,
            "arguments_sha256": arguments_sha256
        }]
    });
    let material_sha256 = digest_bytes(
        &canonical_json_bytes(&material).expect("test plan material must be canonical JSON"),
    )
    .to_string();
    AgentPlanCheckpoint {
        schema_version: AGENT_PLAN_CHECKPOINT_SCHEMA_VERSION,
        session_id: session_id.to_owned(),
        run_id: run_id.to_owned(),
        tool_call_id: tool_call_id.to_owned(),
        material,
        material_sha256,
        recorded_at,
    }
}

impl ToolCallProposal {
    pub(crate) fn validate(&self) -> Result<(), WireValidationError> {
        self.validate_without_plan()?;
        self.agent_plan_checkpoint.validate_scope_for(self)
    }

    fn validate_without_plan(&self) -> Result<(), WireValidationError> {
        if self.schema_version != TOOL_EXECUTION_SCHEMA_VERSION {
            return Err(WireValidationError::WrongSchema);
        }
        validate_wire_text(&self.session_id, "session_id", MAX_SESSION_ID_BYTES)?;
        validate_wire_text(&self.run_id, "run_id", MAX_RUN_ID_BYTES)?;
        validate_wire_text(&self.tool_call_id, "tool_call_id", MAX_TOOL_CALL_ID_BYTES)?;
        validate_wire_text(&self.workspace_root, "workspace_root", MAX_WORKSPACE_BYTES)?;
        validate_wire_text(&self.extension_id, "extension_id", MAX_EXTENSION_BYTES)?;
        validate_wire_text(&self.tool_name, "tool_name", MAX_TOOL_BYTES)?;

        // Reuse the protocol's depth/node/text traversal. Goose's separate
        // sorted-JSON commitment is verified immediately afterwards.
        canonical_args_bytes(&self.arguments)
            .map_err(|_| WireValidationError::ArgumentsOutOfProfile)?;
        let bytes = canonical_json_bytes(&self.arguments)?;
        if bytes.len() > MAX_CANONICAL_ARGUMENT_BYTES {
            return Err(WireValidationError::ArgumentsOutOfProfile);
        }
        let expected = digest_bytes(&bytes).to_string();
        if self.arguments_sha256 != expected {
            return Err(WireValidationError::ArgumentsDigestMismatch);
        }
        let canonical = canonical_workspace(Path::new(&self.workspace_root))
            .map_err(|_| WireValidationError::InvalidWorkspace)?;
        if canonical != self.workspace_root {
            return Err(WireValidationError::InvalidWorkspace);
        }
        Ok(())
    }

    pub(crate) fn digest(&self) -> Result<String, WireValidationError> {
        self.validate()?;
        goose_digest(self)
    }

    pub(crate) fn arguments_digest(&self) -> Result<Digest32, WireValidationError> {
        parse_digest(&self.arguments_sha256)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum WireExecutionOutcome {
    Succeeded,
    ToolReportedError,
    TransportError,
}

/// Exact Goose request DTO for `tool-observations/record`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolExecutionObservation {
    pub schema_version: u16,
    pub authorization_id: String,
    pub proposal_digest: String,
    pub request_hash: String,
    pub(crate) outcome: WireExecutionOutcome,
    pub result_digest: Option<String>,
}

impl ToolExecutionObservation {
    pub(crate) fn validate(&self) -> Result<(), WireValidationError> {
        if self.schema_version != TOOL_EXECUTION_SCHEMA_VERSION {
            return Err(WireValidationError::WrongSchema);
        }
        parse_canonical_uuid(&self.authorization_id)?;
        parse_digest(&self.proposal_digest)?;
        parse_digest(&self.request_hash)?;
        match (self.outcome, self.result_digest.as_deref()) {
            (
                WireExecutionOutcome::Succeeded | WireExecutionOutcome::ToolReportedError,
                Some(value),
            ) => {
                parse_digest(value)?;
            }
            (WireExecutionOutcome::TransportError, None) => {}
            _ => return Err(WireValidationError::InvalidOutcomeEvidence),
        }
        let bytes = canonical_json_bytes(self)?;
        if bytes.len() > MAX_OBSERVATION_BYTES {
            return Err(WireValidationError::ObservationOutOfProfile);
        }
        Ok(())
    }

    pub(crate) fn digest(&self) -> Result<String, WireValidationError> {
        self.validate()?;
        domain_digest(EXECUTION_OBSERVATION_DOMAIN, self)
    }

    pub(crate) fn authorization_id(&self) -> Result<Uuid, WireValidationError> {
        parse_canonical_uuid(&self.authorization_id)
    }
}

pub(crate) fn parse_digest(value: &str) -> Result<Digest32, WireValidationError> {
    let digest = value
        .parse::<Digest32>()
        .map_err(|_| WireValidationError::InvalidDigest)?;
    if digest.to_string() != value {
        return Err(WireValidationError::InvalidDigest);
    }
    Ok(digest)
}

fn parse_canonical_uuid(value: &str) -> Result<Uuid, WireValidationError> {
    let parsed = Uuid::parse_str(value).map_err(|_| WireValidationError::InvalidIdentifier)?;
    if parsed.is_nil() || parsed.to_string() != value {
        return Err(WireValidationError::InvalidIdentifier);
    }
    Ok(parsed)
}

fn canonical_workspace(path: &Path) -> Result<String, TaskBindingError> {
    std::fs::canonicalize(path)
        .map_err(|_| TaskBindingError::InvalidWorkspace)?
        .to_str()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or(TaskBindingError::InvalidWorkspace)
}

fn validate_text(value: &str, field: &'static str, maximum: usize) -> Result<(), TaskBindingError> {
    if value.is_empty() || value.len() > maximum {
        return Err(TaskBindingError::InvalidText(field));
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(TaskBindingError::InvalidText(field));
    }
    Ok(())
}

fn validate_wire_text(
    value: &str,
    field: &'static str,
    maximum: usize,
) -> Result<(), WireValidationError> {
    validate_text(value, field, maximum).map_err(|_| WireValidationError::InvalidField(field))
}

fn validate_revocation_text(
    value: &str,
    field: &'static str,
    maximum: usize,
) -> Result<(), SessionRevocationError> {
    validate_text(value, field, maximum).map_err(|_| SessionRevocationError::InvalidText(field))
}

fn validate_window(start: i64, end: i64, maximum: i64) -> Result<(), TaskBindingError> {
    if start < 0 || end <= start || end.saturating_sub(start) > maximum {
        return Err(TaskBindingError::InvalidWindow);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum TaskBindingError {
    #[error("approved session schema is unsupported")]
    WrongSchema,
    #[error("task identifier must not be nil")]
    NilTask,
    #[error("approved session field is invalid: {0}")]
    InvalidText(&'static str),
    #[error("approved workspace is missing or non-Unicode")]
    InvalidWorkspace,
    #[error("approved workspace is not canonical")]
    NonCanonicalWorkspace,
    #[error("policy epoch must be nonzero")]
    InvalidPolicyEpoch,
    #[error("task policy is outside the bounded profile")]
    InvalidTaskPolicy,
    #[error("task policy hash does not match the immutable policy")]
    TaskPolicyHashMismatch,
    #[error("task objective is missing or outside the bounded profile")]
    InvalidTaskObjective,
    #[error("task objective hash does not match the immutable task policy")]
    TaskObjectiveHashMismatch,
    #[error("preauthorized capability is not allowed by the approved task")]
    PreauthorizedCapabilityMismatch,
    #[error("approval validity window is invalid")]
    InvalidWindow,
    #[error("capability set is empty, duplicate, unsorted, or excessive")]
    InvalidCapabilities,
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum SessionRevocationError {
    #[error("session revocation schema is unsupported")]
    WrongSchema,
    #[error("revoked task identifier must not be nil")]
    NilTask,
    #[error("session revocation field is invalid: {0}")]
    InvalidText(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum WireValidationError {
    #[error("unsupported schema")]
    WrongSchema,
    #[error("invalid field: {0}")]
    InvalidField(&'static str),
    #[error("tool arguments are outside the bounded profile")]
    ArgumentsOutOfProfile,
    #[error("tool argument digest does not match")]
    ArgumentsDigestMismatch,
    #[error("unsupported plan checkpoint schema")]
    WrongPlanSchema,
    #[error("plan checkpoint does not match the proposed tool call")]
    PlanScopeMismatch,
    #[error("plan material is outside the bounded profile")]
    PlanMaterialOutOfProfile,
    #[error("plan material digest does not match")]
    PlanDigestMismatch,
    #[error("plan timestamp is outside the bounded profile")]
    InvalidPlanTimestamp,
    #[error("workspace is invalid or noncanonical")]
    InvalidWorkspace,
    #[error("digest is not canonical")]
    InvalidDigest,
    #[error("identifier is not canonical")]
    InvalidIdentifier,
    #[error("execution outcome evidence is inconsistent")]
    InvalidOutcomeEvidence,
    #[error("observation exceeds the bounded profile")]
    ObservationOutOfProfile,
    #[error("canonical JSON failed")]
    CanonicalJson,
}
