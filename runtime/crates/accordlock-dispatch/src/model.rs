use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Exact authority state that must remain current until effect release.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityVersion {
    /// Canonical active authority root.
    pub root: [u8; 32],
    /// Monotone authority epoch.
    pub epoch: u64,
}

/// Canonical physical destination identity used as the reservation key.
///
/// Tenant, environment, account alias, display name, and caller strings are
/// intentionally absent.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhysicalResourceId {
    /// Trust domain of the cluster credential.
    pub cluster_trust_domain: String,
    /// Authenticated API-server identity.
    pub api_server_identity: String,
    /// Kubernetes namespace.
    pub namespace: String,
    /// Opaque, server-assigned Deployment UID.
    pub deployment_uid: String,
}

/// Logical owner registered for one physical resource.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalOwner {
    /// `AccordLock` tenant identifier.
    pub tenant: String,
    /// Activated environment identifier.
    pub environment: String,
}

/// Credential identity and authorization closure activated for one physical
/// destination before dispatch begins.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialProfile {
    /// Exact Kubernetes subject allowed for the attempt credential.
    pub token_subject: String,
    /// Exact audience allowed for the attempt credential.
    pub token_audience: String,
    /// Commitment to the complete effective authorization closure.
    pub effective_rbac_commitment: [u8; 32],
}

/// Immutable commitments imported from the consumed authorization and execution
/// template.
///
/// These values are fixed before any provider credential exists. They prevent
/// the dispatch lifecycle for one transaction from being reused for a
/// different logical operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectTemplate {
    /// Canonical hash of the complete authorization-bound execution template.
    pub template_hash: [u8; 32],
    /// Domain-separated logical-operation commitment.
    pub operation_hash: [u8; 32],
    /// Commitment to the immutable execution command expected by the authorization.
    pub execution_command_commitment: [u8; 32],
    /// Commitment to the exact payload provider request expected by the authorization.
    pub final_wire_commitment: [u8; 32],
}

/// Immutable witness imported from the successful authorization-consumption
/// transaction.
///
/// The dispatch lifecycle is therefore bound not only to a transaction string,
/// but also to the single-use authorization and the exact durable receipt that created
/// its outbox work.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumptionBinding {
    /// Single-use authorization identifier.
    pub authorization_id: uuid::Uuid,
    /// Canonical hash of the consumed authorization.
    pub authorization_hash: [u8; 32],
    /// Commitment to the durable consumption receipt and outbox tuple.
    pub receipt_commitment: [u8; 32],
    /// Authorization-bound template and logical-operation commitments.
    pub effect: EffectTemplate,
}

/// Exact command, provider-wire, and credential profile materialized after a
/// matching bound object has been observed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedExecution {
    /// Opaque server-assigned UID of the unique bound object.
    pub bound_object_uid: String,
    /// Canonical hash of the consumed execution template.
    pub template_hash: [u8; 32],
    /// Domain-separated logical-operation commitment.
    pub operation_hash: [u8; 32],
    /// Exact Kubernetes subject expected in the attempt credential.
    pub token_subject: String,
    /// Exact audience expected in the attempt credential.
    pub token_audience: String,
    /// Commitment to the complete effective authorization closure.
    pub effective_rbac_commitment: [u8; 32],
    /// Commitment to the immutable execution command.
    pub execution_command_commitment: [u8; 32],
    /// Commitment to the exact payload provider request.
    pub final_wire_commitment: [u8; 32],
}

/// Validated claims returned with an attempt credential.
///
/// Raw bearer bytes are deliberately absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialClaims {
    /// Digest of the bearer bytes retained only for later equality checks.
    pub token_digest: [u8; 32],
    /// Credential subject.
    pub subject: String,
    /// Credential audience.
    pub audience: String,
    /// Exact UID of the `ServiceAccount` authenticated by `TokenReview`.
    pub service_account_uid: String,
    /// Kubernetes v1.32+ credential identifier (`AUTHORIZATION_ID=<canonical UUID>`).
    pub credential_id: String,
    /// UID of the object to which the credential is bound.
    pub bound_object_uid: String,
    /// Credential not-before time in Unix seconds.
    pub not_before: i64,
    /// Credential expiry time in Unix seconds.
    pub expires_at: i64,
}

/// Authenticated observation that no credential issuance began and that the
/// deterministic bound object is absent or deleted.
///
/// This value routes an externally authenticated observation to one exact
/// lifecycle. It does not make the observation true by construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonIssuanceEvidence {
    /// Transaction whose pre-issuance cancellation was observed.
    pub transaction_id: uuid::Uuid,
    /// Canonical physical destination covered by the observation.
    pub physical: PhysicalResourceId,
    /// Deterministic object name covered by the observation.
    pub bound_object_name: String,
    /// Server UID when an object existed before deletion; absent when create
    /// was never sent.
    pub bound_object_uid: Option<String>,
    /// Canonical hash of the consumed execution template.
    pub template_hash: [u8; 32],
    /// Domain-separated logical-operation commitment.
    pub operation_hash: [u8; 32],
    /// Non-zero commitment to the authenticated external observation.
    pub evidence_commitment: [u8; 32],
}

/// Authenticated observation that the unique credential-bearing bound object
/// was deleted or revoked.
///
/// The optional token digest is `None` only when issuance was indeterminate
/// and no bearer was returned. This value prevents evidence for another
/// object, token, destination, or operation from retiring the current attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialInvalidationEvidence {
    /// Transaction whose credential path was invalidated.
    pub transaction_id: uuid::Uuid,
    /// Canonical physical destination covered by the observation.
    pub physical: PhysicalResourceId,
    /// Deterministic object name covered by the observation.
    pub bound_object_name: String,
    /// Server-assigned UID of the invalidated bound object.
    pub bound_object_uid: String,
    /// Digest of the returned bearer, or `None` for unknown issuance.
    pub token_digest: Option<[u8; 32]>,
    /// Canonical hash of the consumed execution template.
    pub template_hash: [u8; 32],
    /// Domain-separated logical-operation commitment.
    pub operation_hash: [u8; 32],
    /// Commitment to the immutable execution command.
    pub execution_command_commitment: [u8; 32],
    /// Commitment to the exact payload provider request.
    pub final_wire_commitment: [u8; 32],
    /// Commitment to the activated effective authorization closure.
    pub effective_rbac_commitment: [u8; 32],
    /// Non-zero commitment to the authenticated external observation.
    pub evidence_commitment: [u8; 32],
}

/// Commitments that must accompany final release and every provider-result
/// classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectBinding {
    /// Canonical hash of the complete authorization-bound execution template.
    pub template_hash: [u8; 32],
    /// Domain-separated logical-operation commitment.
    pub operation_hash: [u8; 32],
    /// Commitment to the immutable execution command.
    pub execution_command_commitment: [u8; 32],
    /// Commitment to the exact payload provider request.
    pub final_wire_commitment: [u8; 32],
    /// Commitment to the activated effective authorization closure.
    pub effective_rbac_commitment: [u8; 32],
    /// Digest of the exact bearer handed to the executor.
    pub token_digest: [u8; 32],
}

/// Canonical identity and authentication context for an effect observer.
///
/// The machine validates the canonical identifier and requires a non-zero
/// commitment to the authenticated channel or attestation. The caller remains
/// responsible for authenticating that external material before constructing
/// this value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedObserver {
    /// Canonical lower-case observer identifier.
    pub identity: String,
    /// Commitment to the authenticated channel, credential, or attestation
    /// through which the observation was obtained.
    pub authentication_commitment: [u8; 32],
}

/// Fresh authenticated observation that establishes the exact authorized
/// provider effect.
///
/// This common proof shape is used for both a synchronous provider success and
/// an exact-effect reconciliation. Its canonical commitment is derived by the
/// machine and retained in the lifecycle for audit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactEffectEvidence {
    /// Transaction whose effect was observed.
    pub transaction_id: uuid::Uuid,
    /// Canonical physical destination covered by the observation.
    pub physical: PhysicalResourceId,
    /// Complete pre-release effect binding observed at the provider boundary.
    pub binding: EffectBinding,
    /// Commitment to the authenticated provider response.
    pub response_commitment: [u8; 32],
    /// Commitment to the canonical complete post-state projection.
    pub post_state_commitment: [u8; 32],
    /// Server UID of the observed physical resource.
    pub observed_resource_uid: String,
    /// Opaque server resource version of the observed post-state.
    pub observed_resource_version: String,
    /// Trusted observation time in Unix seconds.
    pub observed_at: i64,
    /// Authenticated observer that produced the response and post-state
    /// commitments.
    pub observer: AuthenticatedObserver,
}

impl ExactEffectEvidence {
    /// Returns the canonical domain-separated commitment retained for audit.
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"ACCORDLOCK_DISPATCH_EXACT_EFFECT_EVIDENCE_V1\0");
        hasher.update(self.transaction_id.as_bytes());
        update_string(&mut hasher, &self.physical.cluster_trust_domain);
        update_string(&mut hasher, &self.physical.api_server_identity);
        update_string(&mut hasher, &self.physical.namespace);
        update_string(&mut hasher, &self.physical.deployment_uid);
        hasher.update(self.binding.template_hash);
        hasher.update(self.binding.operation_hash);
        hasher.update(self.binding.execution_command_commitment);
        hasher.update(self.binding.final_wire_commitment);
        hasher.update(self.binding.effective_rbac_commitment);
        hasher.update(self.binding.token_digest);
        hasher.update(self.response_commitment);
        hasher.update(self.post_state_commitment);
        update_string(&mut hasher, &self.observed_resource_uid);
        update_string(&mut hasher, &self.observed_resource_version);
        hasher.update(self.observed_at.to_be_bytes());
        update_string(&mut hasher, &self.observer.identity);
        hasher.update(self.observer.authentication_commitment);
        hasher.finalize().into()
    }
}

fn update_string(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u128).to_be_bytes());
    hasher.update(value.as_bytes());
}

/// Policy bounds used by the reference credential lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispatchBounds {
    /// Maximum interval between consumption and effect release.
    pub max_dispatch_delay_s: i64,
    /// Maximum time for which an issued token may remain usable.
    pub token_lifetime_upper_bound_s: i64,
    /// Additional conservative clock uncertainty.
    pub clock_uncertainty_s: i64,
    /// Minimum token lifetime required at final handoff.
    pub minimum_remaining_lifetime_s: i64,
    /// Lease duration used by the reference machine.
    pub lease_ttl_s: i64,
}

impl DispatchBounds {
    pub(crate) fn validate(self) -> Result<Self, DispatchError> {
        if self.max_dispatch_delay_s <= 0
            || self.token_lifetime_upper_bound_s <= 0
            || self.clock_uncertainty_s < 0
            || self.minimum_remaining_lifetime_s <= 0
            || self.lease_ttl_s <= 0
        {
            return Err(DispatchError::InvalidBounds);
        }
        Ok(self)
    }
}

/// Local lifecycle phase represented by the in-memory reference machine.
///
/// These variants are not durable records. Only the corresponding state-store
/// claim and `ATTEMPT_IN_FLIGHT` transition can provide durable authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LifecyclePhase {
    /// Authorization consumption committed, but no dispatch reservation exists.
    Consumed,
    /// Another transaction holds the physical resource reservation.
    DispatchWaitingResource,
    /// Reservation, lease, and deterministic bound-object create intent exist.
    BoundObjectCreatePending,
    /// The local model recorded create-in-flight before the provider send.
    BoundObjectCreateInFlight,
    /// The create outcome is unknown and a second create is forbidden.
    BoundObjectCreateUnknown,
    /// The deterministic bound-object name is being reconciled.
    BoundObjectReconciling,
    /// A matching bound object and its server UID were recorded.
    CredentialPrepared,
    /// The local model recorded token issuance before the provider request.
    CredentialIssuing,
    /// Token issuance may have happened; automatic retry is forbidden.
    CredentialIssueUnknown,
    /// A known token was lost before release and invalidation is required.
    CredentialInvalidating,
    /// A token with validated claims exists only in trusted volatile custody.
    CredentialReady,
    /// Final release was cancelled before handoff.
    ReleaseCancelled,
    /// One credential handoff was authorized.
    EffectReleased,
    /// The executor began its single provider attempt.
    Executing,
    /// Delivery or provider outcome is ambiguous; resubmission is forbidden.
    ExecutionUnknown,
    /// The complete destination projection is being reconciled.
    Reconciling,
    /// The exact authorized effect was established.
    Executed,
    /// A definite rejection or safely established no-effect result exists.
    ExecutionFailed,
    /// Invalidation is confirmed, but the conservative expiry window is open.
    CredentialQuarantined,
    /// Invalidation and the conservative expiry window are complete.
    CredentialSafeExpired,
    /// Automatic progress is unsafe.
    ManualResolutionRequired,
    /// The reservation was safely released and the transaction is final.
    TransactionFinal,
}

/// Result of the single provider attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderOutcome {
    /// The exact bound effect succeeded.
    Success {
        /// Fresh authenticated provider response and post-state evidence.
        evidence: Box<ExactEffectEvidence>,
    },
    /// The effect may or may not have occurred.
    Unknown,
}

/// Result of destination-state reconciliation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReconciliationOutcome {
    /// The complete, authorization-bound effect was established.
    ExactEffect {
        /// Fresh authenticated destination observation.
        evidence: Box<ExactEffectEvidence>,
    },
    /// Available observations do not establish that no prior effect occurred.
    NoEffectNotEstablished,
    /// Observations conflict or remain incomplete.
    Ambiguous,
}

/// Audit snapshot of the evidence commitment retained by one lifecycle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectEvidenceSnapshot {
    /// Transaction whose state was inspected.
    pub transaction_id: uuid::Uuid,
    /// Canonical physical destination bound to the lifecycle.
    pub physical: PhysicalResourceId,
    /// Current lifecycle phase.
    pub phase: LifecyclePhase,
    /// Canonical exact-effect evidence commitment, present only after an
    /// accepted provider success or exact reconciliation.
    pub evidence_commitment: Option<[u8; 32]>,
}

/// Observation for a deterministic bound-object name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BoundObjectObservation {
    /// No object exists and non-creation is established.
    Absent,
    /// The exact expected object exists with this server UID.
    Matching(Box<PreparedExecution>),
    /// An object exists but ownership or immutable fields conflict.
    Conflicting,
}

/// Lease and fencing identity returned to one worker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchClaim {
    /// Transaction to which this claim is fenced.
    pub transaction_id: uuid::Uuid,
    /// Canonical physical resource protected by the reservation.
    pub physical: PhysicalResourceId,
    /// Authorization, receipt, and effect commitments protected by this lifecycle.
    pub consumption: ConsumptionBinding,
    /// Worker identity that owns the lease.
    pub worker: String,
    /// Monotone fencing token.
    pub fence: u64,
    /// Monotone reservation generation for the physical resource.
    pub reservation_generation: u64,
    /// Deterministic name used for create reconciliation.
    pub bound_object_name: String,
}

/// Errors emitted by the fail-closed reference machine.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DispatchError {
    /// A configured duration is zero, negative, or invalid.
    #[error("invalid dispatch bounds")]
    InvalidBounds,
    /// Trusted time moved backwards or overflowed.
    #[error("trusted time is non-monotone or overflows")]
    InvalidTime,
    /// A physical destination is already registered to another owner.
    #[error("physical destination has a conflicting logical owner")]
    AliasConflict,
    /// A supposedly canonical identity contains empty or unsafe components.
    #[error("resource, owner, or worker identity is malformed")]
    InvalidIdentity,
    /// The owner does not match the active destination registration.
    #[error("logical owner is not registered for this physical destination")]
    RegistrationMismatch,
    /// The transaction identifier already exists.
    #[error("transaction already exists")]
    DuplicateTransaction,
    /// A consumed authorization or durable receipt was already imported by another
    /// transaction.
    #[error("consumption witness was replayed")]
    ConsumptionReplay,
    /// The transaction identifier is unknown.
    #[error("transaction is unknown")]
    UnknownTransaction,
    /// The transition is invalid from the current phase.
    #[error("invalid lifecycle transition")]
    InvalidTransition,
    /// Current authority differs from authority at consumption.
    #[error("authority changed")]
    AuthorityChanged,
    /// Active authority attempted to move backwards or conflict at one epoch.
    #[error("authority activation is non-monotone")]
    AuthorityRollback,
    /// Emergency stop is active.
    #[error("emergency stop is active")]
    EmergencyStop,
    /// Dispatch deadline passed.
    #[error("dispatch deadline has passed")]
    DeadlineExpired,
    /// Another transaction owns the physical reservation.
    #[error("physical resource reservation is busy")]
    ResourceBusy,
    /// Lease owner or fence is stale.
    #[error("stale dispatch lease")]
    StaleLease,
    /// Token claims exceed the registered profile.
    #[error("credential claims are invalid")]
    InvalidCredential,
    /// A template, command, provider-wire, or effect commitment is absent or
    /// differs from the consumed operation.
    #[error("execution commitment is invalid or mismatched")]
    InvalidCommitment,
    /// External lifecycle evidence is malformed or belongs to another route.
    #[error("external lifecycle evidence is invalid or misrouted")]
    InvalidEvidence,
    /// Credential remains live or indeterminate.
    #[error("credential remains live or indeterminate")]
    CredentialStillLive,
    /// Security-critical arithmetic overflowed.
    #[error("security-critical arithmetic overflow")]
    ArithmeticOverflow,
}
