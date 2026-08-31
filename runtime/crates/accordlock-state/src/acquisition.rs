//! Durable v14 dispatch-outbox acquisition boundary.
//!
//! A worker supplies only its canonical identity and an idempotency UUID.
//! State selects the pending v13 outbox item, creates the stable dispatch
//! claim when needed, and returns a short-lived, non-serializable authority.

use accordlock_protocol::{
    AuthorityVector, CanonicalEncode, CanonicalError, Digest32, canonical_hash,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    ConsumeKey, DispatchClaimToken, DispatchSnapshot, GrantSnapshot, OutboxEntry, OutboxStatus,
    Scope, StateError,
};

/// Fixed server policy for one dispatch acquisition lease.
pub const DISPATCH_ACQUISITION_LEASE_SECONDS: i64 = 30;

/// Idempotent request for the next server-selected pending dispatch.
///
/// The request intentionally contains no tenant, transaction, authorization, outbox,
/// claim, fence, deadline, or lease input. `acquisition_id` is only a retry
/// identity; the selected work and stable claim identity remain state-owned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchAcquisitionRequest {
    worker_id: String,
    acquisition_id: Uuid,
}

impl DispatchAcquisitionRequest {
    /// Builds a bounded canonical worker request.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::InvalidRecord`] for a malformed worker identity
    /// or nil acquisition identifier.
    pub fn new(worker_id: impl Into<String>, acquisition_id: Uuid) -> Result<Self, StateError> {
        let worker_id = worker_id.into();
        if acquisition_id.is_nil() || !valid_worker_id(&worker_id) {
            return Err(StateError::InvalidRecord(
                "dispatch acquisition worker or retry identity is invalid".to_owned(),
            ));
        }
        Ok(Self {
            worker_id,
            acquisition_id,
        })
    }

    #[must_use]
    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    #[must_use]
    pub const fn acquisition_id(&self) -> Uuid {
        self.acquisition_id
    }

    pub(crate) fn validate(&self) -> Result<(), StateError> {
        if self.acquisition_id.is_nil() || !valid_worker_id(&self.worker_id) {
            return Err(StateError::InvalidRecord(
                "dispatch acquisition worker or retry identity is invalid".to_owned(),
            ));
        }
        Ok(())
    }

    /// Derives the secret-free selector retained across a process restart.
    #[must_use]
    pub fn recovery_key(&self, scope: &Scope) -> DispatchAcquisitionRecoveryKey {
        DispatchAcquisitionRecoveryKey::from_request(scope, self)
    }
}

/// Explicit key retained after an ambiguous acquisition commit response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchAcquisitionRecoveryKey {
    scope: Scope,
    worker_id: String,
    acquisition_id: Uuid,
}

impl DispatchAcquisitionRecoveryKey {
    pub(crate) fn from_request(scope: &Scope, request: &DispatchAcquisitionRequest) -> Self {
        Self {
            scope: scope.clone(),
            worker_id: request.worker_id.clone(),
            acquisition_id: request.acquisition_id,
        }
    }

    pub(crate) fn from_durable_acquisition(
        scope: &Scope,
        worker_id: &str,
        acquisition_id: Uuid,
    ) -> Result<Self, StateError> {
        let key = Self {
            scope: scope.clone(),
            worker_id: worker_id.to_owned(),
            acquisition_id,
        };
        key.scope.validate()?;
        if key.acquisition_id.is_nil() || !valid_worker_id(&key.worker_id) {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        Ok(key)
    }

    #[must_use]
    pub const fn scope(&self) -> &Scope {
        &self.scope
    }

    #[must_use]
    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    #[must_use]
    pub const fn acquisition_id(&self) -> Uuid {
        self.acquisition_id
    }
}

/// Inert, server-selected recovery work for an acquisition generation whose
/// productive capability can no longer be reconstructed.
///
/// This value is deliberately non-clonable and non-serializable. It exposes
/// only a borrowed secret-free recovery key and the durable quarantine reason;
/// it contains no claim token, snapshot, bearer, or acquisition authority.
#[derive(Debug, PartialEq, Eq)]
pub struct DispatchRecoveryWork {
    recovery_key: DispatchAcquisitionRecoveryKey,
    disposition: DispatchAcquisitionDisposition,
}

impl DispatchRecoveryWork {
    pub(crate) fn new(
        recovery_key: DispatchAcquisitionRecoveryKey,
        disposition: DispatchAcquisitionDisposition,
    ) -> Self {
        Self {
            recovery_key,
            disposition,
        }
    }

    #[must_use]
    pub const fn recovery_key(&self) -> &DispatchAcquisitionRecoveryKey {
        &self.recovery_key
    }

    #[must_use]
    pub const fn disposition(&self) -> DispatchAcquisitionDisposition {
        self.disposition
    }
}

/// Inert reason explaining why exact acquisition history cannot yield a new
/// execution authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DispatchAcquisitionDisposition {
    /// The exact lease expired without any downstream artifact. A distinct
    /// request may safely append a takeover acquisition.
    Expired,
    /// A later acquisition generation superseded this exact lease.
    Superseded,
    /// At least one broker journal row exists, including a pre-I/O intent.
    BrokerArtifactPresent,
    /// The stable claim crossed the irreversible provider-attempt boundary.
    AttemptInFlight,
    /// An authenticated credential was durably closed without any provider
    /// send; frozen cleanup and conservative retirement remain outstanding.
    RecoveryNoSend,
    /// A no-send recovery completed durable Secret retirement and released
    /// its physical reservation. It can never yield execution authority.
    RecoveryRetired,
    /// Admission history exists and must be handled through its own recovery.
    AdmissionArtifactPresent,
    /// Immutable terminal history exists for the stable claim.
    Terminal,
    /// The control-owned queue item was durably disposed after this lease was
    /// created and can no longer mint productive authority.
    QueueDisposed,
}

/// Durable reason that a pending control-owned outbox item cannot ever mint a
/// dispatch acquisition under its consumed security facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DispatchQueueDispositionReason {
    AuthorityChanged,
    GrantRevoked,
    DispatchDeadlineExpired,
}

#[derive(Serialize)]
struct DispatchQueueDispositionMaterial<'a> {
    domain: &'static str,
    dispatch_request_id: Uuid,
    worker_id: &'a str,
    control_submission_id: Uuid,
    key: &'a ConsumeKey,
    state_instance_id: Uuid,
    claim_id: Option<Uuid>,
    claim_fence: Option<u64>,
    acquisition_id: Option<Uuid>,
    lease_fence: Option<u64>,
    reason: DispatchQueueDispositionReason,
    observed_at: i64,
    dispatch_deadline: i64,
    authorization_commitment: Digest32,
    grant_commitment: Digest32,
    outbox_commitment: Digest32,
    expected_authority_commitment: Digest32,
    current_authority_commitment: Digest32,
}

fn framed_bytes<'a>(domain: &str, parts: impl IntoIterator<Item = &'a str>) -> Vec<u8> {
    fn push(material: &mut Vec<u8>, value: &[u8]) {
        material.extend_from_slice(value.len().to_string().as_bytes());
        material.push(b':');
        material.extend_from_slice(value);
    }

    let mut material = Vec::with_capacity(1024);
    push(&mut material, domain.as_bytes());
    for part in parts {
        push(&mut material, part.as_bytes());
    }
    material
}

struct DispatchFactMaterial {
    domain: &'static str,
    parts: Vec<String>,
}

impl CanonicalEncode for DispatchFactMaterial {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        Ok(framed_bytes(
            self.domain,
            self.parts.iter().map(String::as_str),
        ))
    }
}

fn dispatch_fact_commitment(
    domain: &'static str,
    parts: Vec<String>,
) -> Result<Digest32, StateError> {
    Ok(canonical_hash(&DispatchFactMaterial { domain, parts })?)
}

pub(crate) fn dispatch_authority_fact_commitment(
    authority: &AuthorityVector,
) -> Result<Digest32, StateError> {
    let mut parts = Vec::with_capacity(36);
    for domain in authority.domains() {
        parts.push(domain.root.to_string());
        parts.push(domain.epoch.to_string());
        parts.push(domain.activation_id.to_string());
    }
    dispatch_fact_commitment("ACCORDLOCK_DISPATCH_AUTHORITY_FACT_V1", parts)
}

pub(crate) fn dispatch_grant_fact_commitment(
    grant: &GrantSnapshot,
) -> Result<Digest32, StateError> {
    let registration = &grant.registration;
    let capability = &registration.grant;
    let policy = &registration.dispatch_deadline_policy;
    let mut parts = vec![
        capability.tenant.clone(),
        registration.environment.clone(),
        capability.grant_id.to_string(),
        capability.holder.clone(),
        capability.operation.clone(),
        capability.repository.clone(),
        capability.audience.clone(),
        capability.cluster_identity.clone(),
        capability.namespace.clone(),
        capability.deployment_uid.clone(),
        capability.container.clone(),
        capability.image_repository.clone(),
        capability.not_before.to_string(),
        capability.expires_at.to_string(),
        capability.maximum_uses.to_string(),
        policy.max_dispatch_delay_seconds.to_string(),
        policy.profile_hard_cap.to_string(),
        policy.immutable_dependency_expiries.len().to_string(),
    ];
    parts.extend(
        policy
            .immutable_dependency_expiries
            .iter()
            .map(ToString::to_string),
    );
    parts.extend([
        registration.authority.grant_registry.root.to_string(),
        dispatch_authority_fact_commitment(&registration.authority)?.to_string(),
        grant.uses.to_string(),
        capability.maximum_uses.to_string(),
        capability.not_before.to_string(),
        capability.expires_at.to_string(),
        grant.revoked.to_string(),
    ]);
    dispatch_fact_commitment("ACCORDLOCK_DISPATCH_GRANT_FACT_V2", parts)
}

pub(crate) fn dispatch_outbox_fact_commitment(
    outbox: &OutboxEntry,
) -> Result<Digest32, StateError> {
    dispatch_fact_commitment(
        "ACCORDLOCK_DISPATCH_OUTBOX_FACT_V1",
        vec![
            outbox.scope.tenant.clone(),
            outbox.scope.environment.clone(),
            outbox.authorization_id.to_string(),
            outbox.transaction_id.to_string(),
            outbox.dispatch_deadline.to_string(),
            match outbox.status {
                OutboxStatus::PendingWitness => "PENDING_WITNESS".to_owned(),
            },
            outbox.receipt.consumed_at.to_string(),
            outbox.receipt.authorization_hash.to_string(),
            dispatch_authority_fact_commitment(&outbox.receipt.authority)?.to_string(),
        ],
    )
}

impl CanonicalEncode for DispatchQueueDispositionMaterial<'_> {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        fn optional_uuid(value: Option<Uuid>) -> String {
            value.map_or_else(|| "NONE".to_owned(), |value| value.to_string())
        }
        fn optional_u64(value: Option<u64>) -> String {
            value.map_or_else(|| "NONE".to_owned(), |value| value.to_string())
        }

        let parts = vec![
            self.dispatch_request_id.to_string(),
            self.worker_id.to_owned(),
            self.control_submission_id.to_string(),
            self.key.scope.tenant.clone(),
            self.key.scope.environment.clone(),
            self.key.authorization_id.to_string(),
            self.key.transaction_id.to_string(),
            self.state_instance_id.to_string(),
            optional_uuid(self.claim_id),
            optional_u64(self.claim_fence),
            optional_uuid(self.acquisition_id),
            optional_u64(self.lease_fence),
            match self.reason {
                DispatchQueueDispositionReason::AuthorityChanged => "AUTHORITY_CHANGED",
                DispatchQueueDispositionReason::GrantRevoked => "GRANT_REVOKED",
                DispatchQueueDispositionReason::DispatchDeadlineExpired => {
                    "DISPATCH_DEADLINE_EXPIRED"
                }
            }
            .to_owned(),
            self.observed_at.to_string(),
            self.dispatch_deadline.to_string(),
            self.authorization_commitment.to_string(),
            self.grant_commitment.to_string(),
            self.outbox_commitment.to_string(),
            self.expected_authority_commitment.to_string(),
            self.current_authority_commitment.to_string(),
        ];
        Ok(framed_bytes(self.domain, parts.iter().map(String::as_str)))
    }
}

/// Inert receipt for one append-only pre-acquisition queue disposition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchQueueDispositionReceipt {
    dispatch_request_id: Uuid,
    worker_id: String,
    control_submission_id: Uuid,
    key: ConsumeKey,
    state_instance_id: Uuid,
    claim_id: Option<Uuid>,
    claim_fence: Option<u64>,
    acquisition_id: Option<Uuid>,
    lease_fence: Option<u64>,
    reason: DispatchQueueDispositionReason,
    observed_at: i64,
    dispatch_deadline: i64,
    authorization_commitment: Digest32,
    grant_commitment: Digest32,
    outbox_commitment: Digest32,
    expected_authority_commitment: Digest32,
    current_authority_commitment: Digest32,
    disposition_commitment: Digest32,
}

impl DispatchQueueDispositionReceipt {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        dispatch_request_id: Uuid,
        worker_id: String,
        control_submission_id: Uuid,
        key: ConsumeKey,
        state_instance_id: Uuid,
        claim_id: Option<Uuid>,
        claim_fence: Option<u64>,
        acquisition_id: Option<Uuid>,
        lease_fence: Option<u64>,
        reason: DispatchQueueDispositionReason,
        observed_at: i64,
        dispatch_deadline: i64,
        authorization_commitment: Digest32,
        grant_commitment: Digest32,
        outbox_commitment: Digest32,
        expected_authority_commitment: Digest32,
        current_authority_commitment: Digest32,
    ) -> Result<Self, StateError> {
        let optional_count = usize::from(claim_id.is_some())
            + usize::from(claim_fence.is_some())
            + usize::from(acquisition_id.is_some())
            + usize::from(lease_fence.is_some());
        let has_zero_commitment = [
            authorization_commitment,
            grant_commitment,
            outbox_commitment,
            expected_authority_commitment,
            current_authority_commitment,
        ]
        .iter()
        .any(|commitment| commitment.as_bytes().iter().all(|byte| *byte == 0));
        let authority_relationship_invalid = match reason {
            DispatchQueueDispositionReason::AuthorityChanged => {
                expected_authority_commitment == current_authority_commitment
            }
            DispatchQueueDispositionReason::GrantRevoked => {
                expected_authority_commitment != current_authority_commitment
            }
            DispatchQueueDispositionReason::DispatchDeadlineExpired => false,
        };
        let reason_time_invalid = match reason {
            DispatchQueueDispositionReason::DispatchDeadlineExpired => {
                observed_at < dispatch_deadline
            }
            DispatchQueueDispositionReason::AuthorityChanged
            | DispatchQueueDispositionReason::GrantRevoked => observed_at >= dispatch_deadline,
        };
        if dispatch_request_id.is_nil()
            || control_submission_id.is_nil()
            || state_instance_id.is_nil()
            || !valid_worker_id(&worker_id)
            || !matches!(optional_count, 0 | 4)
            || claim_id.is_some_and(|value| value.is_nil())
            || acquisition_id.is_some_and(|value| value.is_nil())
            || claim_fence.is_some_and(|value| value == 0)
            || lease_fence.is_some_and(|value| value == 0)
            || observed_at < 0
            || dispatch_deadline <= 0
            || has_zero_commitment
            || authority_relationship_invalid
            || reason_time_invalid
        {
            return Err(StateError::InvalidRecord(
                "dispatch queue disposition identity or time is invalid".to_owned(),
            ));
        }
        key.validate()?;
        let disposition_commitment = canonical_hash(&DispatchQueueDispositionMaterial {
            domain: "ACCORDLOCK_DISPATCH_QUEUE_DISPOSITION_V1",
            dispatch_request_id,
            worker_id: &worker_id,
            control_submission_id,
            key: &key,
            state_instance_id,
            claim_id,
            claim_fence,
            acquisition_id,
            lease_fence,
            reason,
            observed_at,
            dispatch_deadline,
            authorization_commitment,
            grant_commitment,
            outbox_commitment,
            expected_authority_commitment,
            current_authority_commitment,
        })?;
        Ok(Self {
            dispatch_request_id,
            worker_id,
            control_submission_id,
            key,
            state_instance_id,
            claim_id,
            claim_fence,
            acquisition_id,
            lease_fence,
            reason,
            observed_at,
            dispatch_deadline,
            authorization_commitment,
            grant_commitment,
            outbox_commitment,
            expected_authority_commitment,
            current_authority_commitment,
            disposition_commitment,
        })
    }

    pub(crate) fn validate(&self) -> Result<(), StateError> {
        let expected = Self::new(
            self.dispatch_request_id,
            self.worker_id.clone(),
            self.control_submission_id,
            self.key.clone(),
            self.state_instance_id,
            self.claim_id,
            self.claim_fence,
            self.acquisition_id,
            self.lease_fence,
            self.reason,
            self.observed_at,
            self.dispatch_deadline,
            self.authorization_commitment,
            self.grant_commitment,
            self.outbox_commitment,
            self.expected_authority_commitment,
            self.current_authority_commitment,
        )?;
        if expected.disposition_commitment != self.disposition_commitment {
            return Err(StateError::InvalidRecord(
                "dispatch queue disposition commitment differs".to_owned(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub const fn dispatch_request_id(&self) -> Uuid {
        self.dispatch_request_id
    }

    #[must_use]
    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    #[must_use]
    pub const fn control_submission_id(&self) -> Uuid {
        self.control_submission_id
    }

    #[must_use]
    pub const fn key(&self) -> &ConsumeKey {
        &self.key
    }

    #[must_use]
    pub const fn state_instance_id(&self) -> Uuid {
        self.state_instance_id
    }

    #[must_use]
    pub const fn claim_id(&self) -> Option<Uuid> {
        self.claim_id
    }

    #[must_use]
    pub const fn claim_fence(&self) -> Option<u64> {
        self.claim_fence
    }

    #[must_use]
    pub const fn acquisition_id(&self) -> Option<Uuid> {
        self.acquisition_id
    }

    #[must_use]
    pub const fn lease_fence(&self) -> Option<u64> {
        self.lease_fence
    }

    #[must_use]
    pub const fn reason(&self) -> DispatchQueueDispositionReason {
        self.reason
    }

    #[must_use]
    pub const fn observed_at(&self) -> i64 {
        self.observed_at
    }

    #[must_use]
    pub const fn dispatch_deadline(&self) -> i64 {
        self.dispatch_deadline
    }

    #[must_use]
    pub const fn authorization_commitment(&self) -> Digest32 {
        self.authorization_commitment
    }

    #[must_use]
    pub const fn grant_commitment(&self) -> Digest32 {
        self.grant_commitment
    }

    #[must_use]
    pub const fn outbox_commitment(&self) -> Digest32 {
        self.outbox_commitment
    }

    #[must_use]
    pub const fn expected_authority_commitment(&self) -> Digest32 {
        self.expected_authority_commitment
    }

    #[must_use]
    pub const fn current_authority_commitment(&self) -> Digest32 {
        self.current_authority_commitment
    }

    #[must_use]
    pub const fn disposition_commitment(&self) -> Digest32 {
        self.disposition_commitment
    }
}

/// Redacted, inert exact acquisition history. This value is never authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchAcquisitionReceipt {
    acquisition_id: Uuid,
    lease_fence: u64,
    worker_id: String,
    claim_id: Uuid,
    claim_fence: u64,
    acquired_at: i64,
    lease_until: i64,
    disposition: DispatchAcquisitionDisposition,
}

impl DispatchAcquisitionReceipt {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        acquisition_id: Uuid,
        lease_fence: u64,
        worker_id: String,
        claim_id: Uuid,
        claim_fence: u64,
        acquired_at: i64,
        lease_until: i64,
        disposition: DispatchAcquisitionDisposition,
    ) -> Self {
        Self {
            acquisition_id,
            lease_fence,
            worker_id,
            claim_id,
            claim_fence,
            acquired_at,
            lease_until,
            disposition,
        }
    }

    #[must_use]
    pub const fn acquisition_id(&self) -> Uuid {
        self.acquisition_id
    }

    #[must_use]
    pub const fn lease_fence(&self) -> u64 {
        self.lease_fence
    }

    #[must_use]
    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    #[must_use]
    pub const fn claim_id(&self) -> Uuid {
        self.claim_id
    }

    #[must_use]
    pub const fn claim_fence(&self) -> u64 {
        self.claim_fence
    }

    #[must_use]
    pub const fn acquired_at(&self) -> i64 {
        self.acquired_at
    }

    #[must_use]
    pub const fn lease_until(&self) -> i64 {
        self.lease_until
    }

    #[must_use]
    pub const fn disposition(&self) -> DispatchAcquisitionDisposition {
        self.disposition
    }
}

/// Opaque, non-cloneable and non-serializable lease authority.
///
/// The embedded claim token is stable audit identity. Productive v14 APIs
/// additionally require this exact acquisition generation; possessing the
/// stable token alone is intentionally insufficient once phase B is wired.
#[derive(Debug, PartialEq, Eq)]
pub struct DispatchAcquisitionAuthority {
    pub(crate) claim: DispatchClaimToken,
    pub(crate) acquisition_id: Uuid,
    pub(crate) lease_fence: u64,
    pub(crate) worker_id: String,
    pub(crate) acquired_at: i64,
    pub(crate) lease_until: i64,
    pub(crate) dispatch_deadline: i64,
    pub(crate) control_submission_id: Option<Uuid>,
}

impl DispatchAcquisitionAuthority {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        claim: DispatchClaimToken,
        acquisition_id: Uuid,
        lease_fence: u64,
        worker_id: String,
        acquired_at: i64,
        lease_until: i64,
        dispatch_deadline: i64,
        control_submission_id: Option<Uuid>,
    ) -> Self {
        Self {
            claim,
            acquisition_id,
            lease_fence,
            worker_id,
            acquired_at,
            lease_until,
            dispatch_deadline,
            control_submission_id,
        }
    }

    #[must_use]
    pub const fn claim(&self) -> &DispatchClaimToken {
        &self.claim
    }

    #[must_use]
    pub const fn acquisition_id(&self) -> Uuid {
        self.acquisition_id
    }

    #[must_use]
    pub const fn lease_fence(&self) -> u64 {
        self.lease_fence
    }

    #[must_use]
    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    #[must_use]
    pub const fn acquired_at(&self) -> i64 {
        self.acquired_at
    }

    #[must_use]
    pub const fn lease_until(&self) -> i64 {
        self.lease_until
    }

    #[must_use]
    pub const fn dispatch_deadline(&self) -> i64 {
        self.dispatch_deadline
    }

    #[must_use]
    pub const fn control_submission_id(&self) -> Option<Uuid> {
        self.control_submission_id
    }
}

/// Current dispatch snapshot paired with one exact durable acquisition
/// generation. Exact recovery may reconstruct another non-cloneable object
/// for the same generation; productive downstream CAS enforces one mutation.
#[derive(Debug, PartialEq, Eq)]
pub struct DispatchWork {
    snapshot: DispatchSnapshot,
    authority: DispatchAcquisitionAuthority,
}

impl DispatchWork {
    pub(crate) fn new(snapshot: DispatchSnapshot, authority: DispatchAcquisitionAuthority) -> Self {
        Self {
            snapshot,
            authority,
        }
    }

    #[must_use]
    pub const fn snapshot(&self) -> &DispatchSnapshot {
        &self.snapshot
    }

    #[must_use]
    pub const fn authority(&self) -> &DispatchAcquisitionAuthority {
        &self.authority
    }

    #[must_use]
    pub fn into_parts(self) -> (DispatchSnapshot, DispatchAcquisitionAuthority) {
        (self.snapshot, self.authority)
    }
}

/// Result of server-side selection or exact acquisition recovery.
#[derive(Debug, PartialEq, Eq)]
pub enum DispatchAcquisitionOutcome {
    Acquired(DispatchWork),
    Recovered(DispatchWork),
    RecoveryRequired(DispatchRecoveryWork),
    Inert(DispatchAcquisitionReceipt),
    Quarantined(DispatchAcquisitionReceipt),
    Disposed(DispatchQueueDispositionReceipt),
    NoWork,
    OutcomeUnknown(DispatchAcquisitionRecoveryKey),
}

pub(crate) fn valid_worker_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.is_ascii()
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/' | b'@')
        })
}
