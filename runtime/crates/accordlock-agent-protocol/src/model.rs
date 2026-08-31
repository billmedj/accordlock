use accordlock_protocol::{Digest32, canonical_hash};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Baseline version used by unchanged records in the agent-execution profile.
pub const EXECUTION_PROTOCOL_SCHEMA_VERSION: u16 = 2;
/// Current [`ExecutionRequest`] schema version.
pub const EXECUTION_REQUEST_SCHEMA_VERSION: u16 = EXECUTION_PROTOCOL_SCHEMA_VERSION;
/// Current [`AuthorizationDecision`] schema version. Version 4 additionally
/// binds the exact pre-execution intent evaluation that was available when
/// authority was granted.
pub const AUTHORIZATION_DECISION_SCHEMA_VERSION: u16 = 4;
/// Current [`ExecutionAuthorization`] schema version.
pub const EXECUTION_AUTHORIZATION_SCHEMA_VERSION: u16 = EXECUTION_PROTOCOL_SCHEMA_VERSION;
/// Current [`ExecutionRecord`] schema version.
pub const EXECUTION_RECORD_SCHEMA_VERSION: u16 = EXECUTION_PROTOCOL_SCHEMA_VERSION;

pub const MAX_SESSION_ID_BYTES: usize = 256;
pub const MAX_RUN_ID_BYTES: usize = 256;
pub const MAX_TOOL_CALL_ID_BYTES: usize = 512;
pub const MAX_WORKSPACE_BYTES: usize = 4_096;
pub const MAX_EXTENSION_BYTES: usize = 256;
pub const MAX_TOOL_BYTES: usize = 256;
pub const MAX_REASON_CODE_BYTES: usize = 128;
pub const MAX_REQUEST_LIFETIME_SECONDS: i64 = 15 * 60;
pub const MAX_DECISION_LIFETIME_SECONDS: i64 = 15 * 60;
pub const MAX_AUTHORIZATION_LIFETIME_SECONDS: i64 = 5 * 60;
pub const MAX_EXECUTION_DURATION_SECONDS: i64 = 24 * 60 * 60;
pub const MAX_CANONICAL_ARGUMENT_BYTES: usize = 256 * 1_024;
pub const MAX_CANONICAL_ARGUMENT_DEPTH: usize = 64;
pub const MAX_CANONICAL_ARGUMENT_NODES: usize = 16_384;
pub const MAX_CONFORMANCE_EVALUATION_HASHES: usize = 16;
const LEGACY_AUTHORIZATION_DECISION_SCHEMA_VERSION: u16 = 3;

/// One normalized tool request, before any authorization is granted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRequest {
    pub schema_version: u16,
    pub request_id: Uuid,
    pub session_id: String,
    pub run_id: String,
    pub tool_call_id: String,
    pub workspace: String,
    pub extension: String,
    pub tool: String,
    pub canonical_args_hash: Digest32,
    pub policy_epoch: u64,
    pub task_policy_hash: Digest32,
    pub created_at: i64,
    pub expires_at: i64,
}

impl ExecutionRequest {
    /// Validates the bounded, canonical profile before the request crosses a
    /// trust boundary.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] for an unsupported schema, invalid identity
    /// or commitment, noncanonical text, or invalid validity window.
    pub fn validate(&self) -> Result<(), ValidationError> {
        require_schema(
            self.schema_version,
            EXECUTION_REQUEST_SCHEMA_VERSION,
            "agent execution request",
        )?;
        require_non_nil(self.request_id, "request_id")?;
        validate_bindings(
            &self.session_id,
            &self.run_id,
            &self.tool_call_id,
            &self.workspace,
            &self.extension,
            &self.tool,
            self.canonical_args_hash,
            self.task_policy_hash,
        )?;
        validate_window(
            self.created_at,
            self.expires_at,
            MAX_REQUEST_LIFETIME_SECONDS,
            "request validity",
        )
    }

    /// Deterministic commitment to the complete request.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] when validation or canonical encoding fails.
    pub fn digest(&self) -> Result<Digest32, ValidationError> {
        self.validate()?;
        canonical_hash(self).map_err(|error| ValidationError::Canonical(error.to_string()))
    }
}

/// Result produced by trusted policy evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationOutcome {
    Allow,
    AllowAfterApproval,
    ApprovalRequired,
    Deny,
}

impl AuthorizationOutcome {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::Allow => 0,
            Self::AllowAfterApproval => 1,
            Self::ApprovalRequired => 2,
            Self::Deny => 3,
        }
    }

    #[must_use]
    pub const fn authorizes(self) -> bool {
        matches!(self, Self::Allow | Self::AllowAfterApproval)
    }
}

/// Exact decision over one immutable execution request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationDecision {
    pub schema_version: u16,
    pub request_hash: Digest32,
    pub session_id: String,
    pub run_id: String,
    pub tool_call_id: String,
    pub workspace: String,
    pub extension: String,
    pub tool: String,
    pub canonical_args_hash: Digest32,
    pub policy_epoch: u64,
    pub task_policy_hash: Digest32,
    pub policy_decision_hash: Digest32,
    pub conformance_evaluation_hashes: Vec<Digest32>,
    /// Commitment to the revalidated pre-execution intent record. This is
    /// evidence used at authorization time, not a post-execution assessment.
    #[serde(default = "zero_digest", skip_serializing_if = "is_zero_digest")]
    pub intent_evaluation_hash: Digest32,
    pub outcome: AuthorizationOutcome,
    pub reason_code: String,
    pub approval_evidence_hash: Option<Digest32>,
    pub decided_at: i64,
    pub expires_at: i64,
}

impl AuthorizationDecision {
    /// Validates the decision's profile, bounds, outcome evidence, and window.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] for any malformed or out-of-profile field.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if !matches!(
            self.schema_version,
            LEGACY_AUTHORIZATION_DECISION_SCHEMA_VERSION | AUTHORIZATION_DECISION_SCHEMA_VERSION
        ) {
            return Err(ValidationError::WrongSchema {
                record: "authorization decision",
                expected: AUTHORIZATION_DECISION_SCHEMA_VERSION,
                actual: self.schema_version,
            });
        }
        require_digest(self.request_hash, "request_hash")?;
        validate_bindings(
            &self.session_id,
            &self.run_id,
            &self.tool_call_id,
            &self.workspace,
            &self.extension,
            &self.tool,
            self.canonical_args_hash,
            self.task_policy_hash,
        )?;
        validate_reason_code(&self.reason_code)?;
        require_digest(self.policy_decision_hash, "policy_decision_hash")?;
        validate_conformance_hashes(&self.conformance_evaluation_hashes)?;
        match self.schema_version {
            AUTHORIZATION_DECISION_SCHEMA_VERSION => {
                require_digest(self.intent_evaluation_hash, "intent_evaluation_hash")?;
            }
            LEGACY_AUTHORIZATION_DECISION_SCHEMA_VERSION
                if !is_zero_digest(&self.intent_evaluation_hash) =>
            {
                return Err(ValidationError::UnexpectedIntentEvaluationEvidence);
            }
            LEGACY_AUTHORIZATION_DECISION_SCHEMA_VERSION => {}
            _ => unreachable!("authorization decision schema was checked above"),
        }
        validate_window(
            self.decided_at,
            self.expires_at,
            MAX_DECISION_LIFETIME_SECONDS,
            "decision validity",
        )?;

        match (
            self.outcome,
            self.approval_evidence_hash,
            self.conformance_evaluation_hashes.is_empty(),
        ) {
            (AuthorizationOutcome::Allow, None, false) => Ok(()),
            (AuthorizationOutcome::Allow, None, true) => {
                Err(ValidationError::MissingConformanceEvidence)
            }
            (AuthorizationOutcome::AllowAfterApproval, Some(hash), true) => {
                require_digest(hash, "approval_evidence_hash")
            }
            (AuthorizationOutcome::AllowAfterApproval, None, _) => {
                Err(ValidationError::MissingApprovalEvidence)
            }
            (AuthorizationOutcome::AllowAfterApproval, Some(_), false) => {
                Err(ValidationError::UnexpectedConformanceEvidence)
            }
            (_, Some(_), _) => Err(ValidationError::UnexpectedApprovalEvidence),
            (_, None, false) => Err(ValidationError::UnexpectedConformanceEvidence),
            (_, None, true) => Ok(()),
        }
    }

    /// Verifies both the whole-request commitment and every repeated binding.
    ///
    /// # Errors
    ///
    /// Returns [`BindingError`] when either record is invalid or any commitment,
    /// repeated field, or validity boundary differs.
    pub fn verify_for_request(&self, request: &ExecutionRequest) -> Result<(), BindingError> {
        self.validate()?;
        request.validate()?;
        require_equal_digest("request_hash", self.request_hash, request.digest()?)?;
        verify_repeated_bindings(
            request,
            &self.session_id,
            &self.run_id,
            &self.tool_call_id,
            &self.workspace,
            &self.extension,
            &self.tool,
            self.canonical_args_hash,
            self.policy_epoch,
            self.task_policy_hash,
        )?;
        if self.decided_at < request.created_at {
            return Err(BindingError::Mismatch("decided_at"));
        }
        if self.expires_at > request.expires_at {
            return Err(BindingError::Mismatch("expires_at"));
        }
        Ok(())
    }

    /// Deterministic commitment to the complete decision.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] when validation or canonical encoding fails.
    pub fn digest(&self) -> Result<Digest32, ValidationError> {
        self.validate()?;
        canonical_hash(self).map_err(|error| ValidationError::Canonical(error.to_string()))
    }
}

/// Single-use authority for one exact tool action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAuthorization {
    pub schema_version: u16,
    pub authorization_id: Uuid,
    pub request_hash: Digest32,
    pub authorization_decision_hash: Digest32,
    pub session_id: String,
    pub run_id: String,
    pub tool_call_id: String,
    pub workspace: String,
    pub extension: String,
    pub tool: String,
    pub canonical_args_hash: Digest32,
    pub policy_epoch: u64,
    pub task_policy_hash: Digest32,
    pub issued_at: i64,
    pub not_before: i64,
    pub expires_at: i64,
}

impl ExecutionAuthorization {
    /// Validates the authorization's bounded profile and temporal shape.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] for malformed fields, invalid commitments,
    /// unsupported schema, or an invalid validity window.
    pub fn validate(&self) -> Result<(), ValidationError> {
        require_schema(
            self.schema_version,
            EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
            "execution authorization",
        )?;
        require_non_nil(self.authorization_id, "authorization_id")?;
        require_digest(self.request_hash, "request_hash")?;
        require_digest(
            self.authorization_decision_hash,
            "authorization_decision_hash",
        )?;
        validate_bindings(
            &self.session_id,
            &self.run_id,
            &self.tool_call_id,
            &self.workspace,
            &self.extension,
            &self.tool,
            self.canonical_args_hash,
            self.task_policy_hash,
        )?;
        if self.issued_at < 0 || self.not_before < self.issued_at {
            return Err(ValidationError::InvalidTimeOrder("authorization validity"));
        }
        validate_window(
            self.not_before,
            self.expires_at,
            MAX_AUTHORIZATION_LIFETIME_SECONDS,
            "authorization validity",
        )?;
        let total_lifetime = self
            .expires_at
            .checked_sub(self.issued_at)
            .ok_or(ValidationError::InvalidTimeOrder("authorization validity"))?;
        if total_lifetime > MAX_AUTHORIZATION_LIFETIME_SECONDS {
            return Err(ValidationError::LifetimeExceeded {
                field: "authorization validity",
                maximum_seconds: MAX_AUTHORIZATION_LIFETIME_SECONDS,
            });
        }
        Ok(())
    }

    /// Verifies the authorization's redundant fields against the original request.
    ///
    /// # Errors
    ///
    /// Returns [`BindingError`] when either record is invalid or an exact
    /// commitment, repeated binding, or validity boundary differs.
    pub fn verify_for_request(&self, request: &ExecutionRequest) -> Result<(), BindingError> {
        self.validate()?;
        request.validate()?;
        require_equal_digest("request_hash", self.request_hash, request.digest()?)?;
        verify_repeated_bindings(
            request,
            &self.session_id,
            &self.run_id,
            &self.tool_call_id,
            &self.workspace,
            &self.extension,
            &self.tool,
            self.canonical_args_hash,
            self.policy_epoch,
            self.task_policy_hash,
        )?;
        if self.issued_at < request.created_at || self.expires_at > request.expires_at {
            return Err(BindingError::Mismatch("authorization validity"));
        }
        Ok(())
    }

    /// Verifies the complete request -> decision -> authorization chain.
    ///
    /// # Errors
    ///
    /// Returns [`BindingError`] when the chain is invalid, non-authorizing, or
    /// not exactly bound from request through decision to authorization.
    pub fn verify_for(
        &self,
        request: &ExecutionRequest,
        decision: &AuthorizationDecision,
    ) -> Result<(), BindingError> {
        self.verify_for_request(request)?;
        decision.verify_for_request(request)?;
        if !decision.outcome.authorizes() {
            return Err(BindingError::DecisionDoesNotAuthorize);
        }
        require_equal_digest(
            "authorization_decision_hash",
            self.authorization_decision_hash,
            decision.digest()?,
        )?;
        verify_decision_authorization_bindings(decision, self)?;
        if self.issued_at < decision.decided_at || self.expires_at > decision.expires_at {
            return Err(BindingError::Mismatch("decision validity"));
        }
        Ok(())
    }

    /// Deterministic commitment to the complete authorization.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] when validation or canonical encoding fails.
    pub fn digest(&self) -> Result<Digest32, ValidationError> {
        self.validate()?;
        canonical_hash(self).map_err(|error| ValidationError::Canonical(error.to_string()))
    }
}

/// Outcome of the execution attempt. The result body is represented only by its
/// commitment in [`ExecutionRecord`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionOutcome {
    Succeeded,
    Failed,
    Indeterminate,
}

impl ExecutionOutcome {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::Succeeded => 0,
            Self::Failed => 1,
            Self::Indeterminate => 2,
        }
    }
}

/// Immutable evidence that a consumed authorization reached one execution boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRecord {
    pub schema_version: u16,
    pub record_id: Uuid,
    pub authorization_id: Uuid,
    pub request_hash: Digest32,
    pub authorization_hash: Digest32,
    pub session_id: String,
    pub run_id: String,
    pub tool_call_id: String,
    pub workspace: String,
    pub extension: String,
    pub tool: String,
    pub canonical_args_hash: Digest32,
    pub policy_epoch: u64,
    pub task_policy_hash: Digest32,
    pub consumed_at: i64,
    pub completed_at: i64,
    pub outcome: ExecutionOutcome,
    pub result_hash: Digest32,
}

impl ExecutionRecord {
    /// Validates the record's profile, bindings, outcome commitment, and
    /// bounded execution duration.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] for any malformed or out-of-profile field.
    pub fn validate(&self) -> Result<(), ValidationError> {
        require_schema(
            self.schema_version,
            EXECUTION_RECORD_SCHEMA_VERSION,
            "execution record",
        )?;
        require_non_nil(self.record_id, "record_id")?;
        require_non_nil(self.authorization_id, "authorization_id")?;
        require_digest(self.request_hash, "request_hash")?;
        require_digest(self.authorization_hash, "authorization_hash")?;
        require_digest(self.result_hash, "result_hash")?;
        validate_bindings(
            &self.session_id,
            &self.run_id,
            &self.tool_call_id,
            &self.workspace,
            &self.extension,
            &self.tool,
            self.canonical_args_hash,
            self.task_policy_hash,
        )?;
        validate_duration(
            self.consumed_at,
            self.completed_at,
            MAX_EXECUTION_DURATION_SECONDS,
            "execution duration",
        )
    }

    /// Verifies the complete execution-record binding, including the authorization digest and
    /// the exact consumption window.
    ///
    /// # Errors
    ///
    /// Returns [`BindingError`] when the request or authorization is invalid,
    /// any record binding differs, or consumption occurred outside the authorization.
    pub fn verify_for(
        &self,
        request: &ExecutionRequest,
        authorization: &ExecutionAuthorization,
    ) -> Result<(), BindingError> {
        self.validate()?;
        authorization.verify_for_request(request)?;
        require_equal_uuid(
            "authorization_id",
            self.authorization_id,
            authorization.authorization_id,
        )?;
        require_equal_digest("request_hash", self.request_hash, request.digest()?)?;
        require_equal_digest(
            "authorization_hash",
            self.authorization_hash,
            authorization.digest()?,
        )?;
        verify_repeated_bindings(
            request,
            &self.session_id,
            &self.run_id,
            &self.tool_call_id,
            &self.workspace,
            &self.extension,
            &self.tool,
            self.canonical_args_hash,
            self.policy_epoch,
            self.task_policy_hash,
        )?;
        if self.consumed_at < authorization.not_before
            || self.consumed_at >= authorization.expires_at
        {
            return Err(BindingError::Mismatch("consumed_at"));
        }
        Ok(())
    }

    /// Deterministic commitment to the complete execution record.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] when validation or canonical encoding fails.
    pub fn digest(&self) -> Result<Digest32, ValidationError> {
        self.validate()?;
        canonical_hash(self).map_err(|error| ValidationError::Canonical(error.to_string()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ValidationError {
    #[error("{record} schema version {actual} is unsupported; expected {expected}")]
    WrongSchema {
        record: &'static str,
        expected: u16,
        actual: u16,
    },
    #[error("{0} must not be nil")]
    NilIdentifier(&'static str),
    #[error("{0} must not be empty")]
    Empty(&'static str),
    #[error("{field} exceeds its {maximum_bytes}-byte profile limit")]
    TextTooLong {
        field: &'static str,
        maximum_bytes: usize,
    },
    #[error("{0} must be exact trimmed text without control characters")]
    NonCanonicalText(&'static str),
    #[error("reason_code must contain only ASCII letters, digits, '.', '_', ':', or '-'")]
    InvalidReasonCode,
    #[error("{0} must not be the all-zero digest")]
    ZeroDigest(&'static str),
    #[error("{0} timestamps are invalid or not strictly ordered")]
    InvalidTimeOrder(&'static str),
    #[error("{field} exceeds the {maximum_seconds}-second lifetime limit")]
    LifetimeExceeded {
        field: &'static str,
        maximum_seconds: i64,
    },
    #[error("allow_after_approval requires approval_evidence_hash")]
    MissingApprovalEvidence,
    #[error("approval_evidence_hash is only valid for allow_after_approval")]
    UnexpectedApprovalEvidence,
    #[error("automatic allow requires conformance_evaluation_hashes")]
    MissingConformanceEvidence,
    #[error("conformance_evaluation_hashes are only valid for automatic allow")]
    UnexpectedConformanceEvidence,
    #[error("conformance_evaluation_hashes are duplicate, unsorted, or excessive")]
    InvalidConformanceEvidence,
    #[error("intent_evaluation_hash is only valid for authorization decision schema 4")]
    UnexpectedIntentEvaluationEvidence,
    #[error("canonical tool arguments exceed the byte limit")]
    CanonicalArgumentsTooLarge,
    #[error("canonical tool arguments exceed the nesting-depth limit")]
    CanonicalArgumentsTooDeep,
    #[error("canonical tool arguments exceed the node-count limit")]
    CanonicalArgumentsTooManyNodes,
    #[error("canonical tool argument object key exceeds the profile limit")]
    CanonicalArgumentKeyTooLong,
    #[error("canonical encoding failed: {0}")]
    Canonical(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum BindingError {
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error("exact binding mismatch: {0}")]
    Mismatch(&'static str),
    #[error("authorization decision does not authorize execution")]
    DecisionDoesNotAuthorize,
}

fn require_schema(actual: u16, expected: u16, record: &'static str) -> Result<(), ValidationError> {
    if actual != expected {
        return Err(ValidationError::WrongSchema {
            record,
            expected,
            actual,
        });
    }
    Ok(())
}

fn require_non_nil(value: Uuid, field: &'static str) -> Result<(), ValidationError> {
    if value.is_nil() {
        return Err(ValidationError::NilIdentifier(field));
    }
    Ok(())
}

fn require_digest(value: Digest32, field: &'static str) -> Result<(), ValidationError> {
    if value.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(ValidationError::ZeroDigest(field));
    }
    Ok(())
}

const fn zero_digest() -> Digest32 {
    Digest32::from_bytes([0; 32])
}

fn is_zero_digest(value: &Digest32) -> bool {
    value.as_bytes().iter().all(|byte| *byte == 0)
}

fn validate_conformance_hashes(values: &[Digest32]) -> Result<(), ValidationError> {
    if values.len() > MAX_CONFORMANCE_EVALUATION_HASHES {
        return Err(ValidationError::InvalidConformanceEvidence);
    }
    let mut previous = None;
    for value in values {
        require_digest(*value, "conformance_evaluation_hash")?;
        if previous.is_some_and(|candidate| candidate >= *value) {
            return Err(ValidationError::InvalidConformanceEvidence);
        }
        previous = Some(*value);
    }
    Ok(())
}

fn validate_text(
    value: &str,
    field: &'static str,
    maximum_bytes: usize,
) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::Empty(field));
    }
    if value.len() > maximum_bytes {
        return Err(ValidationError::TextTooLong {
            field,
            maximum_bytes,
        });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ValidationError::NonCanonicalText(field));
    }
    Ok(())
}

fn validate_reason_code(value: &str) -> Result<(), ValidationError> {
    validate_text(value, "reason_code", MAX_REASON_CODE_BYTES)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(ValidationError::InvalidReasonCode);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_bindings(
    session_id: &str,
    run_id: &str,
    tool_call_id: &str,
    workspace: &str,
    extension: &str,
    tool: &str,
    canonical_args_hash: Digest32,
    task_policy_hash: Digest32,
) -> Result<(), ValidationError> {
    validate_text(session_id, "session_id", MAX_SESSION_ID_BYTES)?;
    validate_text(run_id, "run_id", MAX_RUN_ID_BYTES)?;
    validate_text(tool_call_id, "tool_call_id", MAX_TOOL_CALL_ID_BYTES)?;
    validate_text(workspace, "workspace", MAX_WORKSPACE_BYTES)?;
    validate_text(extension, "extension", MAX_EXTENSION_BYTES)?;
    validate_text(tool, "tool", MAX_TOOL_BYTES)?;
    require_digest(canonical_args_hash, "canonical_args_hash")?;
    require_digest(task_policy_hash, "task_policy_hash")
}

fn validate_window(
    starts_at: i64,
    expires_at: i64,
    maximum_seconds: i64,
    field: &'static str,
) -> Result<(), ValidationError> {
    if starts_at < 0 || expires_at <= starts_at {
        return Err(ValidationError::InvalidTimeOrder(field));
    }
    let lifetime = expires_at
        .checked_sub(starts_at)
        .ok_or(ValidationError::InvalidTimeOrder(field))?;
    if lifetime > maximum_seconds {
        return Err(ValidationError::LifetimeExceeded {
            field,
            maximum_seconds,
        });
    }
    Ok(())
}

fn validate_duration(
    starts_at: i64,
    completed_at: i64,
    maximum_seconds: i64,
    field: &'static str,
) -> Result<(), ValidationError> {
    if starts_at < 0 || completed_at < starts_at {
        return Err(ValidationError::InvalidTimeOrder(field));
    }
    let duration = completed_at
        .checked_sub(starts_at)
        .ok_or(ValidationError::InvalidTimeOrder(field))?;
    if duration > maximum_seconds {
        return Err(ValidationError::LifetimeExceeded {
            field,
            maximum_seconds,
        });
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_repeated_bindings(
    request: &ExecutionRequest,
    session_id: &str,
    run_id: &str,
    tool_call_id: &str,
    workspace: &str,
    extension: &str,
    tool: &str,
    canonical_args_hash: Digest32,
    policy_epoch: u64,
    task_policy_hash: Digest32,
) -> Result<(), BindingError> {
    require_equal_str("session_id", session_id, &request.session_id)?;
    require_equal_str("run_id", run_id, &request.run_id)?;
    require_equal_str("tool_call_id", tool_call_id, &request.tool_call_id)?;
    require_equal_str("workspace", workspace, &request.workspace)?;
    require_equal_str("extension", extension, &request.extension)?;
    require_equal_str("tool", tool, &request.tool)?;
    require_equal_digest(
        "canonical_args_hash",
        canonical_args_hash,
        request.canonical_args_hash,
    )?;
    if policy_epoch != request.policy_epoch {
        return Err(BindingError::Mismatch("policy_epoch"));
    }
    require_equal_digest(
        "task_policy_hash",
        task_policy_hash,
        request.task_policy_hash,
    )
}

fn verify_decision_authorization_bindings(
    decision: &AuthorizationDecision,
    authorization: &ExecutionAuthorization,
) -> Result<(), BindingError> {
    require_equal_digest(
        "request_hash",
        authorization.request_hash,
        decision.request_hash,
    )?;
    require_equal_str(
        "session_id",
        &authorization.session_id,
        &decision.session_id,
    )?;
    require_equal_str("run_id", &authorization.run_id, &decision.run_id)?;
    require_equal_str(
        "tool_call_id",
        &authorization.tool_call_id,
        &decision.tool_call_id,
    )?;
    require_equal_str("workspace", &authorization.workspace, &decision.workspace)?;
    require_equal_str("extension", &authorization.extension, &decision.extension)?;
    require_equal_str("tool", &authorization.tool, &decision.tool)?;
    require_equal_digest(
        "canonical_args_hash",
        authorization.canonical_args_hash,
        decision.canonical_args_hash,
    )?;
    if authorization.policy_epoch != decision.policy_epoch {
        return Err(BindingError::Mismatch("policy_epoch"));
    }
    require_equal_digest(
        "task_policy_hash",
        authorization.task_policy_hash,
        decision.task_policy_hash,
    )
}

fn require_equal_str(field: &'static str, left: &str, right: &str) -> Result<(), BindingError> {
    if left != right {
        return Err(BindingError::Mismatch(field));
    }
    Ok(())
}

fn require_equal_digest(
    field: &'static str,
    left: Digest32,
    right: Digest32,
) -> Result<(), BindingError> {
    if left != right {
        return Err(BindingError::Mismatch(field));
    }
    Ok(())
}

fn require_equal_uuid(field: &'static str, left: Uuid, right: Uuid) -> Result<(), BindingError> {
    if left != right {
        return Err(BindingError::Mismatch(field));
    }
    Ok(())
}

pub(crate) fn canonical_validation_error() -> accordlock_protocol::CanonicalError {
    accordlock_protocol::CanonicalError::InvalidValue("agent execution profile")
}
