use accordlock_eks_profile::EksCredentialLifecyclePolicy;
use accordlock_protocol::Digest32;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use uuid::Uuid;

use crate::DispatchAcquisitionAuthority;
use crate::model::{
    ConsumeKey, DispatchClaimToken, PhysicalResourceKey, Scope, StateError, TransactionalState,
};

const BROKER_REQUEST_DOMAIN: &[u8] = b"accordlock:v1:broker-operation-request\0";
const BROKER_REQUEST_V2_DOMAIN: &[u8] = b"accordlock:v2:broker-operation-request\0";
const BROKER_RESULT_DOMAIN: &[u8] = b"accordlock:v1:broker-operation-result\0";
const CREDENTIAL_REVIEW_DOMAIN: &[u8] = b"accordlock:v1:dispatch-credential-review\0";
const MAX_SECRET_UID_BYTES: usize = 512;
const MAX_TOKEN_LIFETIME_SECONDS: i64 = 86_400;
const MAX_CLOCK_UNCERTAINTY_SECONDS: i64 = 300;

/// Bootstrap-issued capability required to cross a broker/review I/O
/// boundary. It is bound to one concrete state handle and durable state
/// instance, cannot be cloned or serialized, and is never reconstructed by a
/// recovery/audit API.
pub struct BrokerJournalCapability {
    state_instance_id: Uuid,
    seal: Arc<()>,
}

impl fmt::Debug for BrokerJournalCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerJournalCapability")
            .field("state_instance_id", &self.state_instance_id)
            .field("seal", &"<opaque>")
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct BrokerJournalCapabilityIssuer {
    seal: Arc<()>,
    issued: Arc<AtomicBool>,
}

impl Default for BrokerJournalCapabilityIssuer {
    fn default() -> Self {
        Self {
            seal: Arc::new(()),
            issued: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl BrokerJournalCapabilityIssuer {
    pub(crate) fn issue(
        &self,
        state_instance_id: Uuid,
    ) -> Result<BrokerJournalCapability, StateError> {
        if state_instance_id.is_nil()
            || self
                .issued
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
        {
            return Err(StateError::BrokerOperationInvalidTransition);
        }
        Ok(BrokerJournalCapability {
            state_instance_id,
            seal: Arc::clone(&self.seal),
        })
    }

    pub(crate) fn validate(
        &self,
        capability: &BrokerJournalCapability,
        state_instance_id: Uuid,
    ) -> Result<(), StateError> {
        if state_instance_id.is_nil()
            || capability.state_instance_id != state_instance_id
            || !Arc::ptr_eq(&capability.seal, &self.seal)
        {
            return Err(StateError::BrokerOperationMismatch);
        }
        Ok(())
    }
}

/// The three mutation boundaries in the fixed EKS credential lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BrokerJournalOperation {
    CreateSecret,
    IssueToken,
    DeleteSecret,
}

impl BrokerJournalOperation {
    pub(crate) const fn database_name(self) -> &'static str {
        match self {
            Self::CreateSecret => "CREATE_SECRET",
            Self::IssueToken => "ISSUE_TOKEN",
            Self::DeleteSecret => "DELETE_SECRET",
        }
    }

    pub(crate) fn from_database(value: &str) -> Result<Self, StateError> {
        match value {
            "CREATE_SECRET" => Ok(Self::CreateSecret),
            "ISSUE_TOKEN" => Ok(Self::IssueToken),
            "DELETE_SECRET" => Ok(Self::DeleteSecret),
            _ => Err(StateError::InvalidRecord(format!(
                "unsupported broker journal operation {value}"
            ))),
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::CreateSecret => 1,
            Self::IssueToken => 2,
            Self::DeleteSecret => 3,
        }
    }
}

/// Durable state of one and only one broker mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrokerJournalPhase {
    Intent,
    InFlight,
    Unknown,
    ReconcileOnly,
    Committed,
    Terminal,
}

impl BrokerJournalPhase {
    pub(crate) const fn database_name(self) -> &'static str {
        match self {
            Self::Intent => "INTENT",
            Self::InFlight => "IN_FLIGHT",
            Self::Unknown => "UNKNOWN",
            Self::ReconcileOnly => "RECONCILE_ONLY",
            Self::Committed => "COMMITTED",
            Self::Terminal => "TERMINAL",
        }
    }

    pub(crate) fn from_database(value: &str) -> Result<Self, StateError> {
        match value {
            "INTENT" => Ok(Self::Intent),
            "IN_FLIGHT" => Ok(Self::InFlight),
            "UNKNOWN" => Ok(Self::Unknown),
            "RECONCILE_ONLY" => Ok(Self::ReconcileOnly),
            "COMMITTED" => Ok(Self::Committed),
            "TERMINAL" => Ok(Self::Terminal),
            _ => Err(StateError::InvalidRecord(format!(
                "unsupported broker journal phase {value}"
            ))),
        }
    }
}

/// Authenticated result retained by the broker journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrokerJournalOutcome {
    CreateMatching,
    CreateAbsent,
    CreateConflicting,
    TokenIssued,
    DeleteAbsent,
    DeletePresent,
    DeleteConflicting,
}

impl BrokerJournalOutcome {
    pub(crate) const fn database_name(self) -> &'static str {
        match self {
            Self::CreateMatching => "CREATE_MATCHING",
            Self::CreateAbsent => "CREATE_ABSENT",
            Self::CreateConflicting => "CREATE_CONFLICTING",
            Self::TokenIssued => "TOKEN_ISSUED",
            Self::DeleteAbsent => "DELETE_ABSENT",
            Self::DeletePresent => "DELETE_PRESENT",
            Self::DeleteConflicting => "DELETE_CONFLICTING",
        }
    }

    pub(crate) fn from_database(value: &str) -> Result<Self, StateError> {
        match value {
            "CREATE_MATCHING" => Ok(Self::CreateMatching),
            "CREATE_ABSENT" => Ok(Self::CreateAbsent),
            "CREATE_CONFLICTING" => Ok(Self::CreateConflicting),
            "TOKEN_ISSUED" => Ok(Self::TokenIssued),
            "DELETE_ABSENT" => Ok(Self::DeleteAbsent),
            "DELETE_PRESENT" => Ok(Self::DeletePresent),
            "DELETE_CONFLICTING" => Ok(Self::DeleteConflicting),
            _ => Err(StateError::InvalidRecord(format!(
                "unsupported broker journal outcome {value}"
            ))),
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::CreateMatching => 1,
            Self::CreateAbsent => 2,
            Self::CreateConflicting => 3,
            Self::TokenIssued => 4,
            Self::DeleteAbsent => 5,
            Self::DeletePresent => 6,
            Self::DeleteConflicting => 7,
        }
    }
}

/// Fixed upper bound retained before a `TokenRequest` can cross the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BrokerCredentialSafetyPolicy {
    lifetime_upper_bound_seconds: i64,
    clock_uncertainty_seconds: i64,
}

impl BrokerCredentialSafetyPolicy {
    /// Validates the same bounded lifetime profile enforced by the EKS broker.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::InvalidRecord`] for a non-positive or excessive
    /// lifetime, or for clock uncertainty outside 0..=300 seconds.
    pub fn new(
        lifetime_upper_bound_seconds: i64,
        clock_uncertainty_seconds: i64,
    ) -> Result<Self, StateError> {
        if !(1..=MAX_TOKEN_LIFETIME_SECONDS).contains(&lifetime_upper_bound_seconds)
            || !(0..=MAX_CLOCK_UNCERTAINTY_SECONDS).contains(&clock_uncertainty_seconds)
        {
            return Err(StateError::InvalidRecord(
                "broker credential lifetime or clock-uncertainty bound is invalid".to_owned(),
            ));
        }
        Ok(Self {
            lifetime_upper_bound_seconds,
            clock_uncertainty_seconds,
        })
    }

    #[must_use]
    pub const fn lifetime_upper_bound_seconds(self) -> i64 {
        self.lifetime_upper_bound_seconds
    }

    #[must_use]
    pub const fn clock_uncertainty_seconds(self) -> i64 {
        self.clock_uncertainty_seconds
    }

    pub(crate) fn safe_after(self, started_at: i64) -> Result<i64, StateError> {
        started_at
            .checked_add(self.lifetime_upper_bound_seconds)
            .and_then(|value| value.checked_add(self.clock_uncertainty_seconds))
            .ok_or(StateError::DeadlineOverflow)
    }
}

/// Trusted request for a create or token-issuance intent.
///
/// Construction requires the opaque durable claim token. Delete cleanup has a
/// separate recovery-safe request because cleanup must remain possible after a
/// process lost that token.
#[derive(Debug, PartialEq, Eq)]
pub struct BrokerOperationRequest {
    token: DispatchClaimToken,
    operation: BrokerJournalOperation,
    route_commitment: Digest32,
    credential_policy: Option<BrokerCredentialSafetyPolicy>,
}

impl BrokerOperationRequest {
    /// Binds an immutable Secret create to an exact durable claim and route.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::InvalidRecord`] for a zero route commitment.
    pub fn create(
        token: &DispatchClaimToken,
        route_commitment: [u8; 32],
    ) -> Result<Self, StateError> {
        Self::new(
            token,
            BrokerJournalOperation::CreateSecret,
            route_commitment,
            None,
        )
    }

    /// Binds the sole `TokenRequest` to an exact durable claim, route, and
    /// conservative expiry policy.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::InvalidRecord`] for a zero route commitment.
    pub fn issue_token(
        token: &DispatchClaimToken,
        route_commitment: [u8; 32],
        credential_policy: BrokerCredentialSafetyPolicy,
    ) -> Result<Self, StateError> {
        Self::new(
            token,
            BrokerJournalOperation::IssueToken,
            route_commitment,
            Some(credential_policy),
        )
    }

    fn new(
        token: &DispatchClaimToken,
        operation: BrokerJournalOperation,
        route_commitment: [u8; 32],
        credential_policy: Option<BrokerCredentialSafetyPolicy>,
    ) -> Result<Self, StateError> {
        token.key().validate()?;
        let route_commitment = Digest32::from_bytes(route_commitment);
        if route_commitment == zero_digest()
            || matches!(operation, BrokerJournalOperation::DeleteSecret)
            || (matches!(operation, BrokerJournalOperation::IssueToken)
                != credential_policy.is_some())
        {
            return Err(StateError::InvalidRecord(
                "broker operation request profile is invalid".to_owned(),
            ));
        }
        Ok(Self {
            token: token.clone(),
            operation,
            route_commitment,
            credential_policy,
        })
    }

    pub(crate) const fn token(&self) -> &DispatchClaimToken {
        &self.token
    }

    pub(crate) const fn operation(&self) -> BrokerJournalOperation {
        self.operation
    }

    pub(crate) const fn route_commitment(&self) -> Digest32 {
        self.route_commitment
    }

    pub(crate) const fn credential_policy(&self) -> Option<BrokerCredentialSafetyPolicy> {
        self.credential_policy
    }
}

/// Productive broker request bound to one exact durable acquisition lease.
///
/// The request is non-serializable and can only be constructed from a live
/// opaque acquisition authority. State still revalidates the same generation
/// before preparing or crossing the broker I/O boundary.
#[derive(Debug, PartialEq, Eq)]
pub struct AcquiredBrokerOperationRequest {
    token: DispatchClaimToken,
    acquisition_id: Uuid,
    lease_fence: u64,
    acquisition_worker_id: String,
    acquired_at: i64,
    lease_until: i64,
    dispatch_deadline: i64,
    control_submission_id: Option<Uuid>,
    operation: BrokerJournalOperation,
    route_commitment: Digest32,
    credential_policy: Option<BrokerCredentialSafetyPolicy>,
}

impl AcquiredBrokerOperationRequest {
    /// Builds an exact acquisition-bound Secret-create request.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when the acquisition or route commitment is
    /// structurally invalid.
    pub fn create(
        authority: &DispatchAcquisitionAuthority,
        route_commitment: [u8; 32],
    ) -> Result<Self, StateError> {
        Self::new(
            authority,
            BrokerJournalOperation::CreateSecret,
            route_commitment,
            None,
        )
    }

    /// Builds an exact acquisition-bound token-issuance request.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when the acquisition, route commitment, or
    /// credential policy is structurally invalid.
    pub fn issue_token(
        authority: &DispatchAcquisitionAuthority,
        route_commitment: [u8; 32],
        credential_policy: BrokerCredentialSafetyPolicy,
    ) -> Result<Self, StateError> {
        Self::new(
            authority,
            BrokerJournalOperation::IssueToken,
            route_commitment,
            Some(credential_policy),
        )
    }

    fn new(
        authority: &DispatchAcquisitionAuthority,
        operation: BrokerJournalOperation,
        route_commitment: [u8; 32],
        credential_policy: Option<BrokerCredentialSafetyPolicy>,
    ) -> Result<Self, StateError> {
        let route_commitment = Digest32::from_bytes(route_commitment);
        if route_commitment == zero_digest()
            || matches!(operation, BrokerJournalOperation::DeleteSecret)
            || (matches!(operation, BrokerJournalOperation::IssueToken)
                != credential_policy.is_some())
            || authority.acquisition_id().is_nil()
            || authority.lease_fence() == 0
            || authority.acquired_at() < 0
            || authority.lease_until() <= authority.acquired_at()
            || authority.dispatch_deadline() < authority.lease_until()
        {
            return Err(StateError::InvalidRecord(
                "acquired broker operation request profile is invalid".to_owned(),
            ));
        }
        Ok(Self {
            token: authority.claim().clone(),
            acquisition_id: authority.acquisition_id(),
            lease_fence: authority.lease_fence(),
            acquisition_worker_id: authority.worker_id().to_owned(),
            acquired_at: authority.acquired_at(),
            lease_until: authority.lease_until(),
            dispatch_deadline: authority.dispatch_deadline(),
            control_submission_id: authority.control_submission_id(),
            operation,
            route_commitment,
            credential_policy,
        })
    }

    pub(crate) fn matches_authority(&self, authority: &DispatchAcquisitionAuthority) -> bool {
        self.token == *authority.claim()
            && self.acquisition_id == authority.acquisition_id()
            && self.lease_fence == authority.lease_fence()
            && self.acquisition_worker_id == authority.worker_id()
            && self.acquired_at == authority.acquired_at()
            && self.lease_until == authority.lease_until()
            && self.dispatch_deadline == authority.dispatch_deadline()
            && self.control_submission_id == authority.control_submission_id()
    }

    pub(crate) const fn operation(&self) -> BrokerJournalOperation {
        self.operation
    }

    pub(crate) const fn route_commitment(&self) -> Digest32 {
        self.route_commitment
    }

    pub(crate) const fn credential_policy(&self) -> Option<BrokerCredentialSafetyPolicy> {
        self.credential_policy
    }
}

/// Recovery-safe request for the one exact bound-Secret cleanup intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerCleanupRequest {
    key: ConsumeKey,
    route_commitment: Digest32,
}

impl BrokerCleanupRequest {
    /// Creates an identifier-only cleanup request. State derives the claim,
    /// physical reservation, deterministic Secret name, and matching UID.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::InvalidRecord`] for invalid routing or a zero
    /// route commitment.
    pub fn new(key: ConsumeKey, route_commitment: [u8; 32]) -> Result<Self, StateError> {
        key.validate()?;
        let route_commitment = Digest32::from_bytes(route_commitment);
        if route_commitment == zero_digest() {
            return Err(StateError::InvalidRecord(
                "broker cleanup route commitment is zero".to_owned(),
            ));
        }
        Ok(Self {
            key,
            route_commitment,
        })
    }

    #[must_use]
    pub const fn key(&self) -> &ConsumeKey {
        &self.key
    }

    #[must_use]
    pub const fn route_commitment(&self) -> Digest32 {
        self.route_commitment
    }
}

/// Identifier-only request for read-only create/delete reconciliation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerReconciliationRequest {
    key: ConsumeKey,
    operation: BrokerJournalOperation,
    route_commitment: Digest32,
}

impl BrokerReconciliationRequest {
    /// Creates a read-only reconciliation request.
    ///
    /// Token issuance has no safe GET reconciliation and is rejected here.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] for invalid routing, zero commitment, or token
    /// reissuance.
    pub fn new(
        key: ConsumeKey,
        operation: BrokerJournalOperation,
        route_commitment: [u8; 32],
    ) -> Result<Self, StateError> {
        key.validate()?;
        let route_commitment = Digest32::from_bytes(route_commitment);
        if route_commitment == zero_digest() {
            return Err(StateError::InvalidRecord(
                "broker reconciliation route commitment is zero".to_owned(),
            ));
        }
        if operation == BrokerJournalOperation::IssueToken {
            return Err(StateError::BrokerTokenReissueForbidden);
        }
        Ok(Self {
            key,
            operation,
            route_commitment,
        })
    }

    #[must_use]
    pub const fn key(&self) -> &ConsumeKey {
        &self.key
    }

    #[must_use]
    pub const fn operation(&self) -> BrokerJournalOperation {
        self.operation
    }

    #[must_use]
    pub const fn route_commitment(&self) -> Digest32 {
        self.route_commitment
    }
}

/// Recovery-only action derived from one exact acquisition after its
/// productive authority was lost. Neither variant can mint another mutation
/// or provider-attempt authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchBrokerRestartAction {
    /// Authenticate CREATE uncertainty through GET-only reconciliation.
    ReconcileCreate,
    /// A GET-only CREATE reconciliation durably proved that the deterministic
    /// Secret never existed, before any token/review/provider boundary.
    CreationAlreadyAbsent,
    /// Delete the exact state-bound Secret UID through the cleanup journal.
    CleanupSecret,
    /// The exact cleanup journal and deletion observation already prove that
    /// the bound Secret was absent. No further broker I/O is authorized.
    DeletionAlreadyAbsent,
}

/// State-authenticated, secret-free facts needed to assess credential
/// retirement after a crash that followed durable Secret absence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchRestartDeletionEvidence {
    absent_observed_at: i64,
    evidence_commitment: Digest32,
    credential_lifecycle_policy: EksCredentialLifecyclePolicy,
    rejection_observed_at: Option<i64>,
    rejection_evidence_commitment: Option<Digest32>,
}

impl DispatchRestartDeletionEvidence {
    pub(crate) fn new(
        absent_observed_at: i64,
        evidence_commitment: Digest32,
        credential_lifecycle_policy: EksCredentialLifecyclePolicy,
        rejection_observed_at: Option<i64>,
        rejection_evidence_commitment: Option<Digest32>,
    ) -> Result<Self, StateError> {
        if absent_observed_at < 0
            || evidence_commitment == zero_digest()
            || rejection_observed_at.is_some() != rejection_evidence_commitment.is_some()
            || rejection_observed_at.is_some_and(|observed| observed < absent_observed_at)
            || rejection_evidence_commitment == Some(zero_digest())
        {
            return Err(StateError::InvalidRecord(
                "restart deletion evidence is invalid".to_owned(),
            ));
        }
        Ok(Self {
            absent_observed_at,
            evidence_commitment,
            credential_lifecycle_policy,
            rejection_observed_at,
            rejection_evidence_commitment,
        })
    }

    #[must_use]
    pub const fn absent_observed_at(&self) -> i64 {
        self.absent_observed_at
    }

    #[must_use]
    pub const fn evidence_commitment(&self) -> Digest32 {
        self.evidence_commitment
    }

    #[must_use]
    pub const fn credential_lifecycle_policy(&self) -> EksCredentialLifecyclePolicy {
        self.credential_lifecycle_policy
    }

    #[must_use]
    pub const fn rejection_observed_at(&self) -> Option<i64> {
        self.rejection_observed_at
    }

    #[must_use]
    pub const fn rejection_evidence_commitment(&self) -> Option<Digest32> {
        self.rejection_evidence_commitment
    }
}

/// Secret-free restart context derived and authenticated by state from an
/// acquisition recovery key. It exposes only GET reconciliation or cleanup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchBrokerRestartContext {
    key: ConsumeKey,
    action: DispatchBrokerRestartAction,
    reconciliation_request: Option<BrokerReconciliationRequest>,
    cleanup_request: Option<BrokerCleanupRequest>,
    deletion_evidence: Option<DispatchRestartDeletionEvidence>,
}

impl DispatchBrokerRestartContext {
    pub(crate) fn reconcile_create(request: BrokerReconciliationRequest) -> Self {
        Self {
            key: request.key().clone(),
            action: DispatchBrokerRestartAction::ReconcileCreate,
            reconciliation_request: Some(request),
            cleanup_request: None,
            deletion_evidence: None,
        }
    }

    pub(crate) fn cleanup_secret(request: BrokerCleanupRequest) -> Self {
        Self {
            key: request.key().clone(),
            action: DispatchBrokerRestartAction::CleanupSecret,
            reconciliation_request: None,
            cleanup_request: Some(request),
            deletion_evidence: None,
        }
    }

    pub(crate) fn creation_already_absent(key: ConsumeKey) -> Self {
        Self {
            key,
            action: DispatchBrokerRestartAction::CreationAlreadyAbsent,
            reconciliation_request: None,
            cleanup_request: None,
            deletion_evidence: None,
        }
    }

    pub(crate) fn deletion_already_absent(
        key: ConsumeKey,
        evidence: DispatchRestartDeletionEvidence,
    ) -> Self {
        Self {
            key,
            action: DispatchBrokerRestartAction::DeletionAlreadyAbsent,
            reconciliation_request: None,
            cleanup_request: None,
            deletion_evidence: Some(evidence),
        }
    }

    #[must_use]
    pub const fn key(&self) -> &ConsumeKey {
        &self.key
    }

    #[must_use]
    pub const fn action(&self) -> DispatchBrokerRestartAction {
        self.action
    }

    #[must_use]
    pub fn reconciliation_request(&self) -> Option<BrokerReconciliationRequest> {
        self.reconciliation_request.clone()
    }

    #[must_use]
    pub fn cleanup_request(&self) -> Option<BrokerCleanupRequest> {
        self.cleanup_request.clone()
    }

    #[must_use]
    pub const fn deletion_evidence(&self) -> Option<&DispatchRestartDeletionEvidence> {
        self.deletion_evidence.as_ref()
    }
}

/// Exact authenticated GET observation accepted by reconciliation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerSecretObservation {
    Matching {
        secret_uid: String,
        evidence_commitment: Digest32,
    },
    Absent {
        evidence_commitment: Digest32,
    },
    Conflicting {
        evidence_commitment: Digest32,
    },
}

impl BrokerSecretObservation {
    /// Records one matching immutable Secret observation.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::InvalidRecord`] for an invalid UID or evidence.
    pub fn matching(secret_uid: String, evidence_commitment: [u8; 32]) -> Result<Self, StateError> {
        validate_secret_uid(&secret_uid)?;
        let evidence_commitment = validate_nonzero_digest(evidence_commitment)?;
        Ok(Self::Matching {
            secret_uid,
            evidence_commitment,
        })
    }

    /// Records authenticated absence.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::InvalidRecord`] for zero evidence.
    pub fn absent(evidence_commitment: [u8; 32]) -> Result<Self, StateError> {
        Ok(Self::Absent {
            evidence_commitment: validate_nonzero_digest(evidence_commitment)?,
        })
    }

    /// Records an authenticated conflicting object.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::InvalidRecord`] for zero evidence.
    pub fn conflicting(evidence_commitment: [u8; 32]) -> Result<Self, StateError> {
        Ok(Self::Conflicting {
            evidence_commitment: validate_nonzero_digest(evidence_commitment)?,
        })
    }

    pub(crate) const fn evidence_commitment(&self) -> Digest32 {
        match self {
            Self::Matching {
                evidence_commitment,
                ..
            }
            | Self::Absent {
                evidence_commitment,
            }
            | Self::Conflicting {
                evidence_commitment,
            } => *evidence_commitment,
        }
    }
}

/// Authenticated `TokenRequest` result. Bearer bytes are deliberately absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerTokenIssueObservation {
    token_digest: Digest32,
    expires_at: i64,
    evidence_commitment: Digest32,
}

impl BrokerTokenIssueObservation {
    /// Constructs the redacted authenticated result retained by state.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::InvalidRecord`] for zero commitments or an
    /// invalid expiry.
    pub fn new(
        token_digest: [u8; 32],
        expires_at: i64,
        evidence_commitment: [u8; 32],
    ) -> Result<Self, StateError> {
        let token_digest = validate_nonzero_digest(token_digest)?;
        let evidence_commitment = validate_nonzero_digest(evidence_commitment)?;
        if expires_at <= 0 {
            return Err(StateError::InvalidRecord(
                "broker token expiry must be positive".to_owned(),
            ));
        }
        Ok(Self {
            token_digest,
            expires_at,
            evidence_commitment,
        })
    }

    pub(crate) const fn token_digest(&self) -> Digest32 {
        self.token_digest
    }

    pub(crate) const fn expires_at(&self) -> i64 {
        self.expires_at
    }

    pub(crate) const fn evidence_commitment(&self) -> Digest32 {
        self.evidence_commitment
    }
}

/// Non-authoritative, redacted audit view of one journal row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerOperationAudit {
    entry_id: Uuid,
    key: ConsumeKey,
    claim_id: Uuid,
    fence: u64,
    origin_acquisition_id: Uuid,
    origin_lease_fence: u64,
    physical_resource: PhysicalResourceKey,
    route_commitment: Digest32,
    bound_secret_name: String,
    bound_secret_uid: Option<String>,
    operation: BrokerJournalOperation,
    phase: BrokerJournalPhase,
    prepared_at: i64,
    started_at: Option<i64>,
    credential_policy: Option<BrokerCredentialSafetyPolicy>,
    credential_safe_after: Option<i64>,
    reconciliation_count: u64,
    last_reconciliation_outcome: Option<BrokerJournalOutcome>,
    last_reconciliation_evidence_commitment: Option<Digest32>,
    last_reconciled_at: Option<i64>,
    outcome: Option<BrokerJournalOutcome>,
    result_commitment: Option<Digest32>,
    request_commitment: Digest32,
}

impl BrokerOperationAudit {
    #[must_use]
    pub const fn entry_id(&self) -> Uuid {
        self.entry_id
    }

    #[must_use]
    pub const fn key(&self) -> &ConsumeKey {
        &self.key
    }

    #[must_use]
    pub const fn claim_id(&self) -> Uuid {
        self.claim_id
    }

    #[must_use]
    pub const fn fence(&self) -> u64 {
        self.fence
    }

    #[must_use]
    pub const fn origin_acquisition_id(&self) -> Uuid {
        self.origin_acquisition_id
    }

    #[must_use]
    pub const fn origin_lease_fence(&self) -> u64 {
        self.origin_lease_fence
    }

    #[must_use]
    pub const fn physical_resource(&self) -> &PhysicalResourceKey {
        &self.physical_resource
    }

    #[must_use]
    pub const fn route_commitment(&self) -> Digest32 {
        self.route_commitment
    }

    #[must_use]
    pub fn bound_secret_name(&self) -> &str {
        &self.bound_secret_name
    }

    #[must_use]
    pub fn bound_secret_uid(&self) -> Option<&str> {
        self.bound_secret_uid.as_deref()
    }

    #[must_use]
    pub const fn operation(&self) -> BrokerJournalOperation {
        self.operation
    }

    #[must_use]
    pub const fn phase(&self) -> BrokerJournalPhase {
        self.phase
    }

    #[must_use]
    pub const fn prepared_at(&self) -> i64 {
        self.prepared_at
    }

    #[must_use]
    pub const fn started_at(&self) -> Option<i64> {
        self.started_at
    }

    #[must_use]
    pub const fn credential_policy(&self) -> Option<BrokerCredentialSafetyPolicy> {
        self.credential_policy
    }

    #[must_use]
    pub const fn credential_safe_after(&self) -> Option<i64> {
        self.credential_safe_after
    }

    #[must_use]
    pub const fn reconciliation_count(&self) -> u64 {
        self.reconciliation_count
    }

    #[must_use]
    pub const fn last_reconciliation_outcome(&self) -> Option<BrokerJournalOutcome> {
        self.last_reconciliation_outcome
    }

    #[must_use]
    pub const fn last_reconciliation_evidence_commitment(&self) -> Option<Digest32> {
        self.last_reconciliation_evidence_commitment
    }

    #[must_use]
    pub const fn last_reconciled_at(&self) -> Option<i64> {
        self.last_reconciled_at
    }

    #[must_use]
    pub const fn outcome(&self) -> Option<BrokerJournalOutcome> {
        self.outcome
    }

    #[must_use]
    pub const fn result_commitment(&self) -> Option<Digest32> {
        self.result_commitment
    }

    #[must_use]
    pub fn selector(&self) -> BrokerJournalSelector {
        BrokerJournalSelector {
            key: self.key.clone(),
            entry_id: self.entry_id,
            operation: self.operation,
            request_commitment: self.request_commitment,
            origin_acquisition_id: self.origin_acquisition_id,
            origin_lease_fence: self.origin_lease_fence,
        }
    }
}

/// Exact audit selector for current-free frozen broker/attempt loading.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerJournalSelector {
    key: ConsumeKey,
    entry_id: Uuid,
    operation: BrokerJournalOperation,
    request_commitment: Digest32,
    origin_acquisition_id: Uuid,
    origin_lease_fence: u64,
}

/// Non-secret claims authenticated by the broker's exact Kubernetes
/// `TokenReview` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchCredentialReviewClaims {
    token_digest: Digest32,
    subject: String,
    audience: String,
    service_account_uid: String,
    credential_id: String,
    bound_secret_uid: String,
    not_before: i64,
    expires_at: i64,
}

impl DispatchCredentialReviewClaims {
    #[allow(clippy::too_many_arguments)]
    /// Builds the non-secret claims authenticated by `TokenReview`.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when a digest, identity, credential `AUTHORIZATION_ID`, Secret
    /// UID, or temporal bound is invalid.
    pub fn new(
        token_digest: [u8; 32],
        subject: String,
        audience: String,
        service_account_uid: String,
        credential_id: String,
        bound_secret_uid: String,
        not_before: i64,
        expires_at: i64,
    ) -> Result<Self, StateError> {
        let token_digest = validate_nonzero_digest(token_digest)?;
        let canonical_authorization_id = credential_id
            .strip_prefix("AUTHORIZATION_ID=")
            .and_then(|value| Uuid::parse_str(value).ok())
            .filter(|value| !value.is_nil())
            .is_some_and(|value| credential_id == format!("AUTHORIZATION_ID={value}"));
        if !valid_review_identity(&subject)
            || !valid_review_identity(&audience)
            || !valid_review_identity(&service_account_uid)
            || !canonical_authorization_id
            || validate_secret_uid(&bound_secret_uid).is_err()
            || not_before < 0
            || expires_at <= not_before
        {
            return Err(StateError::InvalidRecord(
                "authenticated credential review claims are invalid".to_owned(),
            ));
        }
        Ok(Self {
            token_digest,
            subject,
            audience,
            service_account_uid,
            credential_id,
            bound_secret_uid,
            not_before,
            expires_at,
        })
    }

    #[must_use]
    pub const fn token_digest(&self) -> Digest32 {
        self.token_digest
    }

    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }

    #[must_use]
    pub fn service_account_uid(&self) -> &str {
        &self.service_account_uid
    }

    #[must_use]
    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }

    #[must_use]
    pub fn bound_secret_uid(&self) -> &str {
        &self.bound_secret_uid
    }

    #[must_use]
    pub const fn not_before(&self) -> i64 {
        self.not_before
    }

    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }
}

/// Authenticated, redacted result returned after the broker completes the
/// exact `TokenReview` I/O authorized by state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedDispatchCredentialReview {
    claims: DispatchCredentialReviewClaims,
    review_evidence_commitment: Digest32,
}

impl AuthenticatedDispatchCredentialReview {
    /// Binds authenticated claims to their provider evidence commitment.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when the evidence commitment is zero.
    pub fn new(
        claims: DispatchCredentialReviewClaims,
        review_evidence_commitment: [u8; 32],
    ) -> Result<Self, StateError> {
        Ok(Self {
            claims,
            review_evidence_commitment: validate_nonzero_digest(review_evidence_commitment)?,
        })
    }

    pub(crate) const fn claims(&self) -> &DispatchCredentialReviewClaims {
        &self.claims
    }
}

/// Authenticated rejection returned by the exact `TokenReview` I/O.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RejectedDispatchCredentialReview {
    token_digest: Digest32,
    review_evidence_commitment: Digest32,
}

impl RejectedDispatchCredentialReview {
    /// Binds a rejected review to the exact token and provider evidence.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when either commitment is zero.
    pub fn new(
        token_digest: [u8; 32],
        review_evidence_commitment: [u8; 32],
    ) -> Result<Self, StateError> {
        Ok(Self {
            token_digest: validate_nonzero_digest(token_digest)?,
            review_evidence_commitment: validate_nonzero_digest(review_evidence_commitment)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchCredentialReviewPhase {
    InFlight,
    Authenticated,
    Rejected,
}

impl DispatchCredentialReviewPhase {
    #[allow(dead_code)]
    pub(crate) const fn database_name(self) -> &'static str {
        match self {
            Self::InFlight => "IN_FLIGHT",
            Self::Authenticated => "AUTHENTICATED",
            Self::Rejected => "REJECTED",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StoredDispatchCredentialReview {
    pub review_id: Uuid,
    pub token: DispatchClaimToken,
    pub acquisition_id: Uuid,
    pub lease_fence: u64,
    pub acquisition_worker_id: String,
    pub acquired_at: i64,
    pub lease_until: i64,
    pub dispatch_deadline: i64,
    pub control_submission_id: Option<Uuid>,
    pub create_entry_id: Uuid,
    pub create_request_commitment: Digest32,
    pub create_result_commitment: Digest32,
    pub token_entry_id: Uuid,
    pub token_request_commitment: Digest32,
    pub token_result_commitment: Digest32,
    pub expected_route_commitment: Digest32,
    pub token_credential_policy: BrokerCredentialSafetyPolicy,
    pub expected_token_digest: Digest32,
    pub expected_token_expires_at: i64,
    pub expected_subject: String,
    pub expected_audience: String,
    pub expected_service_account_uid: String,
    pub expected_bound_secret_uid: String,
    pub credential_lifecycle_policy: EksCredentialLifecyclePolicy,
    pub destination_activation_commitment: Digest32,
    pub phase: DispatchCredentialReviewPhase,
    pub begun_at: i64,
    pub reviewed_at: Option<i64>,
    pub claims: Option<DispatchCredentialReviewClaims>,
    pub review_evidence_commitment: Option<Digest32>,
    pub review_commitment: Option<Digest32>,
}

impl StoredDispatchCredentialReview {
    pub(crate) fn authority(&self) -> DispatchAcquisitionAuthority {
        DispatchAcquisitionAuthority::new(
            self.token.clone(),
            self.acquisition_id,
            self.lease_fence,
            self.acquisition_worker_id.clone(),
            self.acquired_at,
            self.lease_until,
            self.dispatch_deadline,
            self.control_submission_id,
        )
    }

    pub(crate) fn validate(&self) -> Result<(), StateError> {
        self.token.key().validate()?;
        if self.review_id.is_nil()
            || self.acquisition_id.is_nil()
            || self.lease_fence == 0
            || self.create_entry_id.is_nil()
            || self.token_entry_id.is_nil()
            || self.create_request_commitment == zero_digest()
            || self.create_result_commitment == zero_digest()
            || self.token_request_commitment == zero_digest()
            || self.token_result_commitment == zero_digest()
            || self.expected_route_commitment == zero_digest()
            || self.expected_token_digest == zero_digest()
            || self.expected_token_expires_at <= self.begun_at
            || !valid_review_identity(&self.expected_subject)
            || !valid_review_identity(&self.expected_audience)
            || !valid_review_identity(&self.expected_service_account_uid)
            || validate_secret_uid(&self.expected_bound_secret_uid).is_err()
            || self.destination_activation_commitment == zero_digest()
            || self.begun_at < self.acquired_at
            || self.begun_at >= self.lease_until
        {
            return Err(StateError::InvalidRecord(
                "dispatch credential review lineage is invalid".to_owned(),
            ));
        }
        let complete = self.reviewed_at.is_some()
            && self.review_evidence_commitment.is_some()
            && self.review_commitment.is_some();
        match self.phase {
            DispatchCredentialReviewPhase::InFlight => {
                if self.claims.is_some() || complete {
                    return Err(StateError::InvalidRecord(
                        "in-flight credential review has terminal facts".to_owned(),
                    ));
                }
            }
            DispatchCredentialReviewPhase::Authenticated => {
                let claims = self.claims.as_ref().ok_or_else(|| {
                    StateError::InvalidRecord(
                        "authenticated credential review has no claims".to_owned(),
                    )
                })?;
                if !complete
                    || claims.subject != self.expected_subject
                    || claims.audience != self.expected_audience
                    || claims.service_account_uid != self.expected_service_account_uid
                    || claims.bound_secret_uid != self.expected_bound_secret_uid
                    || claims.token_digest != self.expected_token_digest
                    || claims.expires_at != self.expected_token_expires_at
                {
                    return Err(StateError::InvalidRecord(
                        "authenticated credential review differs from frozen facts".to_owned(),
                    ));
                }
            }
            DispatchCredentialReviewPhase::Rejected => {
                if self.claims.is_some() || !complete {
                    return Err(StateError::InvalidRecord(
                        "rejected credential review has an invalid terminal shape".to_owned(),
                    ));
                }
            }
        }
        if let Some(reviewed_at) = self.reviewed_at {
            let authenticated_claims_are_current = self.phase
                != DispatchCredentialReviewPhase::Authenticated
                || self.claims.as_ref().is_some_and(|claims| {
                    claims.not_before <= reviewed_at && reviewed_at < claims.expires_at
                });
            if reviewed_at < self.begun_at
                || (self.phase == DispatchCredentialReviewPhase::Authenticated
                    && reviewed_at >= self.lease_until)
                || !authenticated_claims_are_current
            {
                return Err(StateError::InvalidRecord(
                    "credential review time is outside the acquisition or credential interval"
                        .to_owned(),
                ));
            }
        }
        if let Some(expected) = self.review_commitment
            && expected != dispatch_credential_review_commitment(self)?
        {
            return Err(StateError::InvalidRecord(
                "credential review commitment differs".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn finish_authenticated(
        &self,
        observation: AuthenticatedDispatchCredentialReview,
        reviewed_at: i64,
    ) -> Result<Self, StateError> {
        if self.phase != DispatchCredentialReviewPhase::InFlight {
            return Err(StateError::DispatchCredentialReviewOutcomeUnknown);
        }
        let mut terminal = self.clone();
        terminal.phase = DispatchCredentialReviewPhase::Authenticated;
        terminal.reviewed_at = Some(reviewed_at);
        terminal.claims = Some(observation.claims);
        terminal.review_evidence_commitment = Some(observation.review_evidence_commitment);
        terminal.review_commitment = Some(dispatch_credential_review_commitment(&terminal)?);
        terminal.validate()?;
        Ok(terminal)
    }

    // Consuming the authenticated observation is part of the one-shot review
    // boundary even though both of its digest fields are copied below.
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn finish_rejected(
        &self,
        observation: RejectedDispatchCredentialReview,
        reviewed_at: i64,
    ) -> Result<Self, StateError> {
        if self.phase != DispatchCredentialReviewPhase::InFlight {
            return Err(StateError::DispatchCredentialReviewOutcomeUnknown);
        }
        let RejectedDispatchCredentialReview {
            token_digest,
            review_evidence_commitment,
        } = observation;
        if token_digest != self.expected_token_digest {
            return Err(StateError::DispatchCredentialReviewMismatch);
        }
        let mut terminal = self.clone();
        terminal.phase = DispatchCredentialReviewPhase::Rejected;
        terminal.reviewed_at = Some(reviewed_at);
        terminal.review_evidence_commitment = Some(review_evidence_commitment);
        terminal.review_commitment = Some(dispatch_credential_review_commitment(&terminal)?);
        terminal.validate()?;
        Ok(terminal)
    }

    pub(crate) fn reviewed_credential(&self) -> Result<ReviewedDispatchCredential, StateError> {
        self.validate()?;
        if self.phase != DispatchCredentialReviewPhase::Authenticated {
            return Err(match self.phase {
                DispatchCredentialReviewPhase::Rejected => {
                    StateError::DispatchCredentialReviewRejected
                }
                DispatchCredentialReviewPhase::InFlight => {
                    StateError::DispatchCredentialReviewOutcomeUnknown
                }
                DispatchCredentialReviewPhase::Authenticated => unreachable!(),
            });
        }
        let claims = self.claims.as_ref().ok_or_else(|| {
            StateError::InvalidRecord("authenticated review claims are absent".to_owned())
        })?;
        let review_commitment = self.review_commitment.ok_or_else(|| {
            StateError::InvalidRecord("authenticated review commitment is absent".to_owned())
        })?;
        let review_evidence_commitment = self.review_evidence_commitment.ok_or_else(|| {
            StateError::InvalidRecord("authenticated review evidence is absent".to_owned())
        })?;
        let binding = crate::DispatchCredentialBinding::new_for_review(
            &self.authority(),
            claims,
            self.review_id,
            review_commitment,
        )?;
        Ok(ReviewedDispatchCredential::new(
            self.clone(),
            binding,
            claims.clone(),
            review_evidence_commitment,
        ))
    }
}

/// Redacted audit facts for one durable credential review.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchCredentialReviewAudit {
    stored: StoredDispatchCredentialReview,
}

/// Secret-free exact key retained before the credential-review commit call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchCredentialReviewRecoveryKey {
    key: ConsumeKey,
    review_id: Uuid,
    acquisition_id: Uuid,
    lease_fence: u64,
}

impl DispatchCredentialReviewRecoveryKey {
    #[must_use]
    pub const fn key(&self) -> &ConsumeKey {
        &self.key
    }

    #[must_use]
    pub const fn review_id(&self) -> Uuid {
        self.review_id
    }

    #[must_use]
    pub const fn acquisition_id(&self) -> Uuid {
        self.acquisition_id
    }

    #[must_use]
    pub const fn lease_fence(&self) -> u64 {
        self.lease_fence
    }
}

impl DispatchCredentialReviewAudit {
    pub(crate) fn new(stored: StoredDispatchCredentialReview) -> Self {
        Self { stored }
    }

    #[must_use]
    pub const fn review_id(&self) -> Uuid {
        self.stored.review_id
    }

    #[must_use]
    pub const fn phase(&self) -> DispatchCredentialReviewPhase {
        self.stored.phase
    }

    #[must_use]
    pub const fn reviewed_at(&self) -> Option<i64> {
        self.stored.reviewed_at
    }

    #[must_use]
    pub const fn review_commitment(&self) -> Option<Digest32> {
        self.stored.review_commitment
    }

    /// Reconstructs the secret-free exact recovery selector from durable
    /// audit state. Only an authenticated terminal review can recover proof.
    #[must_use]
    pub fn recovery_key(&self) -> Option<DispatchCredentialReviewRecoveryKey> {
        (self.stored.phase == DispatchCredentialReviewPhase::Authenticated).then(|| {
            DispatchCredentialReviewRecoveryKey {
                key: self.stored.token.key().clone(),
                review_id: self.stored.review_id,
                acquisition_id: self.stored.acquisition_id,
                lease_fence: self.stored.lease_fence,
            }
        })
    }
}

/// One-shot authority to perform exactly one external `TokenReview`.
#[derive(PartialEq, Eq)]
pub struct CredentialReviewIoAuthority {
    pub(crate) stored: StoredDispatchCredentialReview,
}

impl CredentialReviewIoAuthority {
    pub(crate) fn new(stored: StoredDispatchCredentialReview) -> Self {
        Self { stored }
    }

    #[must_use]
    pub const fn review_id(&self) -> Uuid {
        self.stored.review_id
    }

    #[must_use]
    pub fn audit(&self) -> DispatchCredentialReviewAudit {
        DispatchCredentialReviewAudit::new(self.stored.clone())
    }

    #[must_use]
    pub fn recovery_key(&self) -> DispatchCredentialReviewRecoveryKey {
        DispatchCredentialReviewRecoveryKey {
            key: self.stored.token.key().clone(),
            review_id: self.stored.review_id,
            acquisition_id: self.stored.acquisition_id,
            lease_fence: self.stored.lease_fence,
        }
    }
}

impl core::fmt::Debug for CredentialReviewIoAuthority {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CredentialReviewIoAuthority")
            .field("review_id", &self.stored.review_id)
            .field("acquisition_id", &self.stored.acquisition_id)
            .finish_non_exhaustive()
    }
}

/// Opaque durable proof that the exact state-authorized `TokenReview`
/// authenticated the credential committed by the exact token journal row.
#[derive(PartialEq, Eq)]
pub struct ReviewedDispatchCredential {
    pub(crate) stored: StoredDispatchCredentialReview,
    pub(crate) binding: crate::DispatchCredentialBinding,
    claims: DispatchCredentialReviewClaims,
    review_evidence_commitment: Digest32,
}

impl ReviewedDispatchCredential {
    pub(crate) fn new(
        stored: StoredDispatchCredentialReview,
        binding: crate::DispatchCredentialBinding,
        claims: DispatchCredentialReviewClaims,
        review_evidence_commitment: Digest32,
    ) -> Self {
        Self {
            stored,
            binding,
            claims,
            review_evidence_commitment,
        }
    }

    #[must_use]
    pub const fn review_id(&self) -> Uuid {
        self.stored.review_id
    }

    #[must_use]
    pub fn claims(&self) -> &DispatchCredentialReviewClaims {
        &self.claims
    }

    #[must_use]
    pub const fn credential_lifecycle_policy(&self) -> EksCredentialLifecyclePolicy {
        self.stored.credential_lifecycle_policy
    }

    #[must_use]
    pub const fn destination_activation_commitment(&self) -> Digest32 {
        self.stored.destination_activation_commitment
    }

    /// Durable commitment to the provider-authenticated `TokenReview` response.
    #[must_use]
    pub const fn review_evidence_commitment(&self) -> Digest32 {
        self.review_evidence_commitment
    }
}

impl core::fmt::Debug for ReviewedDispatchCredential {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ReviewedDispatchCredential")
            .field("review_id", &self.stored.review_id)
            .field("claims", &self.stored.claims)
            .field("review_commitment", &self.stored.review_commitment)
            .finish_non_exhaustive()
    }
}

impl BrokerJournalSelector {
    #[must_use]
    pub const fn key(&self) -> &ConsumeKey {
        &self.key
    }

    #[must_use]
    pub const fn entry_id(&self) -> Uuid {
        self.entry_id
    }

    #[must_use]
    pub const fn operation(&self) -> BrokerJournalOperation {
        self.operation
    }

    #[must_use]
    pub const fn request_commitment(&self) -> Digest32 {
        self.request_commitment
    }

    #[must_use]
    pub const fn origin_acquisition_id(&self) -> Uuid {
        self.origin_acquisition_id
    }

    #[must_use]
    pub const fn origin_lease_fence(&self) -> u64 {
        self.origin_lease_fence
    }
}

/// Safe-to-adopt durable intent. It is not network authority.
#[derive(Debug, PartialEq, Eq)]
pub struct BrokerOperationIntent {
    pub(crate) stored: StoredBrokerOperation,
}

impl BrokerOperationIntent {
    pub(crate) const fn new(stored: StoredBrokerOperation) -> Self {
        Self { stored }
    }

    #[must_use]
    pub fn audit(&self) -> BrokerOperationAudit {
        self.stored.audit()
    }
}

/// Non-clonable authority for exactly one mutation send.
#[derive(Debug, PartialEq, Eq)]
pub struct BrokerIoAuthority {
    pub(crate) stored: StoredBrokerOperation,
}

impl BrokerIoAuthority {
    pub(crate) const fn new(stored: StoredBrokerOperation) -> Self {
        Self { stored }
    }

    #[must_use]
    pub const fn operation(&self) -> BrokerJournalOperation {
        self.stored.operation
    }

    #[must_use]
    pub fn bound_secret_name(&self) -> &str {
        &self.stored.bound_secret_name
    }

    #[must_use]
    pub fn bound_secret_uid(&self) -> Option<&str> {
        self.stored.bound_secret_uid.as_deref()
    }

    #[must_use]
    pub const fn route_commitment(&self) -> Digest32 {
        self.stored.route_commitment
    }

    #[must_use]
    pub fn audit(&self) -> BrokerOperationAudit {
        self.stored.audit()
    }
}

/// Reconstructable authority for authenticated GET only, never mutation.
#[derive(Debug, PartialEq, Eq)]
pub struct BrokerReconciliationAuthority {
    pub(crate) stored: StoredBrokerOperation,
}

impl BrokerReconciliationAuthority {
    pub(crate) const fn new(stored: StoredBrokerOperation) -> Self {
        Self { stored }
    }

    #[must_use]
    pub const fn operation(&self) -> BrokerJournalOperation {
        self.stored.operation
    }

    #[must_use]
    pub fn bound_secret_name(&self) -> &str {
        &self.stored.bound_secret_name
    }

    #[must_use]
    pub fn bound_secret_uid(&self) -> Option<&str> {
        self.stored.bound_secret_uid.as_deref()
    }

    #[must_use]
    pub const fn route_commitment(&self) -> Digest32 {
        self.stored.route_commitment
    }

    #[must_use]
    pub fn audit(&self) -> BrokerOperationAudit {
        self.stored.audit()
    }
}

/// Exact committed or exactly recovered journal result.
#[derive(Debug, PartialEq, Eq)]
pub struct BrokerOperationReceipt {
    audit: BrokerOperationAudit,
    recovered: bool,
}

/// Result of one authenticated reconciliation GET.
///
/// Eventual absence/presence is not treated as terminal: create absence and
/// matching delete presence return renewed GET-only authority. No variant can
/// restore mutation authority.
#[derive(Debug, PartialEq, Eq)]
pub enum BrokerReconciliationResult {
    Completed(BrokerOperationReceipt),
    Pending(BrokerReconciliationAuthority),
}

impl BrokerReconciliationResult {
    #[must_use]
    pub const fn is_pending(&self) -> bool {
        matches!(self, Self::Pending(_))
    }

    #[must_use]
    pub fn into_completed(self) -> Option<BrokerOperationReceipt> {
        match self {
            Self::Completed(receipt) => Some(receipt),
            Self::Pending(_) => None,
        }
    }

    #[must_use]
    pub fn into_pending(self) -> Option<BrokerReconciliationAuthority> {
        match self {
            Self::Completed(_) => None,
            Self::Pending(authority) => Some(authority),
        }
    }
}

impl BrokerOperationReceipt {
    pub(crate) const fn new(audit: BrokerOperationAudit, recovered: bool) -> Self {
        Self { audit, recovered }
    }

    #[must_use]
    pub const fn audit(&self) -> &BrokerOperationAudit {
        &self.audit
    }

    #[must_use]
    pub const fn was_recovered(&self) -> bool {
        self.recovered
    }
}

/// Durable broker journal shared by memory and `PostgreSQL` state adapters.
pub trait BrokerJournalState: TransactionalState {
    /// Issues the sole non-clonable broker boundary capability for this state
    /// handle. Bootstrap must call this before sharing/cloning the runtime
    /// state handle; a second issuance is rejected.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when this store family already issued its sole
    /// capability or its durable state identity cannot be loaded.
    fn issue_broker_journal_capability(&mut self) -> Result<BrokerJournalCapability, StateError>;

    /// Creates or safely adopts a pre-I/O intent for create or token issuance.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when routing, claim lineage, authority, time, or
    /// an existing journal row does not match.
    fn prepare_broker_operation(
        &self,
        capability: &BrokerJournalCapability,
        request: BrokerOperationRequest,
    ) -> Result<BrokerOperationIntent, StateError>;

    /// Atomically prepares/adopts the exact acquisition-bound intent and
    /// crosses `INTENT -> IN_FLIGHT`. This is the productive v14 boundary:
    /// it cannot durably strand an `INTENT` if the process crashes between
    /// two API calls.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when the capability, acquisition, request,
    /// journal lineage, or current temporal state differs.
    fn begin_broker_operation_for_acquisition(
        &self,
        capability: &BrokerJournalCapability,
        authority: &DispatchAcquisitionAuthority,
        request: AcquiredBrokerOperationRequest,
    ) -> Result<BrokerIoAuthority, StateError>;

    /// Durably crosses the exact acquisition-bound credential review into
    /// `IN_FLIGHT` before any external Kubernetes `TokenReview` request.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when capability, acquisition, token journal, or
    /// rooted expected review facts are not exact and current.
    fn begin_dispatch_credential_review(
        &self,
        capability: &BrokerJournalCapability,
        authority: &DispatchAcquisitionAuthority,
        token_journal: &BrokerJournalSelector,
    ) -> Result<CredentialReviewIoAuthority, StateError>;

    /// Commits an authenticated `TokenReview` result and returns the only
    /// opaque proof accepted by the provider-attempt CAS.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when the consumed I/O authority, observation,
    /// durable review row, or frozen broker lineage differs.
    fn record_authenticated_dispatch_credential(
        &self,
        authority: CredentialReviewIoAuthority,
        observation: AuthenticatedDispatchCredentialReview,
    ) -> Result<ReviewedDispatchCredential, StateError>;

    /// Recovers only a byte-exact durable `AUTHENTICATED` review after an
    /// ambiguous commit response. It is historical/currentness-inert; the
    /// later attempt CAS rechecks the live acquisition and all current state.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] unless the key identifies one exact durable
    /// authenticated review with fully valid frozen lineage.
    fn recover_authenticated_dispatch_credential(
        &self,
        key: &DispatchCredentialReviewRecoveryKey,
    ) -> Result<ReviewedDispatchCredential, StateError>;

    /// Irreversibly records an authenticated `TokenReview` rejection.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when the consumed I/O authority, token digest,
    /// evidence, or durable review transition differs.
    fn record_rejected_dispatch_credential(
        &self,
        authority: CredentialReviewIoAuthority,
        observation: RejectedDispatchCredentialReview,
    ) -> Result<DispatchCredentialReviewAudit, StateError>;

    /// Loads the redacted durable review audit without reconstructing review
    /// I/O or provider-attempt authority.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when no exact review exists or its frozen
    /// acquisition and broker lineage fails validation.
    fn dispatch_credential_review_audit(
        &self,
        acquisition: &crate::DispatchAcquisitionRecoveryKey,
    ) -> Result<DispatchCredentialReviewAudit, StateError>;

    /// Derives only a GET-reconciliation or exact cleanup request after the
    /// acquisition capability was lost. This never reconstructs acquisition,
    /// broker mutation, credential-review I/O, or provider-attempt authority.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when recovery lineage is absent, ambiguous,
    /// conflicting, or structurally invalid.
    fn dispatch_broker_restart_context(
        &self,
        acquisition: &crate::DispatchAcquisitionRecoveryKey,
    ) -> Result<DispatchBrokerRestartContext, StateError>;

    /// Creates or safely adopts the exact cleanup intent using state-derived
    /// Secret identity. Cleanup remains available after authority/deadline
    /// expiry but never for a different route or UID.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when exact lineage, route, UID, or trusted time
    /// cannot be established.
    fn prepare_broker_cleanup(
        &self,
        capability: &BrokerJournalCapability,
        request: &BrokerCleanupRequest,
    ) -> Result<BrokerOperationIntent, StateError>;

    /// Irreversibly crosses `INTENT -> IN_FLIGHT` and returns the sole send
    /// authority. A commit-ambiguous call never reconstructs this value.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when the intent is stale, authority is no longer
    /// current, the clock rolls back, or the transition outcome is unknown.
    fn begin_broker_io(
        &self,
        capability: &BrokerJournalCapability,
        intent: BrokerOperationIntent,
    ) -> Result<BrokerIoAuthority, StateError>;

    /// Commits a matching create response and binds the server Secret UID.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] for mismatched evidence or an ambiguous commit.
    fn commit_broker_create(
        &self,
        authority: BrokerIoAuthority,
        observation: BrokerSecretObservation,
    ) -> Result<BrokerOperationReceipt, StateError>;

    /// Commits the redacted authenticated result of the sole `TokenRequest`.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] for mismatched evidence, an expiry beyond the
    /// frozen upper bound, or an ambiguous commit.
    fn commit_broker_token_issue(
        &self,
        authority: BrokerIoAuthority,
        observation: &BrokerTokenIssueObservation,
    ) -> Result<BrokerOperationReceipt, StateError>;

    /// Converts an in-flight mutation into durable uncertainty. It never
    /// authorizes another send.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] for a mismatched authority or invalid transition.
    fn mark_broker_io_unknown(
        &self,
        authority: BrokerIoAuthority,
    ) -> Result<BrokerOperationAudit, StateError>;

    /// Converts create/delete uncertainty into GET-only authority. An
    /// in-flight row left by a crashed process is first treated as unknown.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] for token issuance, mismatched lineage or route,
    /// clock rollback, or an invalid transition.
    fn begin_broker_reconciliation(
        &self,
        capability: &BrokerJournalCapability,
        request: &BrokerReconciliationRequest,
    ) -> Result<BrokerReconciliationAuthority, StateError>;

    /// Commits an authenticated GET observation without ever restoring
    /// mutation authority.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] for stale GET authority, mismatched evidence,
    /// clock rollback, or an ambiguous commit.
    fn commit_broker_reconciliation(
        &self,
        authority: BrokerReconciliationAuthority,
        observation: BrokerSecretObservation,
    ) -> Result<BrokerReconciliationResult, StateError>;

    /// Loads a redacted audit row. This never reconstructs I/O authority.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when the key is invalid or the journal row is
    /// missing, corrupt, or mismatched.
    fn broker_operation_audit(
        &self,
        key: &ConsumeKey,
        operation: BrokerJournalOperation,
    ) -> Result<BrokerOperationAudit, StateError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StoredBrokerOperation {
    pub entry_id: Uuid,
    pub key: ConsumeKey,
    pub claim_id: Uuid,
    pub fence: u64,
    pub state_instance_id: Uuid,
    pub origin_acquisition_id: Uuid,
    pub origin_lease_fence: u64,
    pub acquisition_binding_version: i16,
    pub physical_resource: PhysicalResourceKey,
    pub route_commitment: Digest32,
    pub bound_secret_name: String,
    pub bound_secret_uid: Option<String>,
    pub operation: BrokerJournalOperation,
    pub phase: BrokerJournalPhase,
    pub prepared_at: i64,
    pub started_at: Option<i64>,
    pub credential_policy: Option<BrokerCredentialSafetyPolicy>,
    pub credential_safe_after: Option<i64>,
    pub reconciliation_count: u64,
    pub last_reconciliation_outcome: Option<BrokerJournalOutcome>,
    pub last_reconciliation_evidence_commitment: Option<Digest32>,
    pub last_reconciled_at: Option<i64>,
    pub outcome: Option<BrokerJournalOutcome>,
    pub provider_evidence_commitment: Option<Digest32>,
    pub token_digest: Option<Digest32>,
    pub token_expires_at: Option<i64>,
    pub request_commitment: Digest32,
    pub result_commitment: Option<Digest32>,
}

impl StoredBrokerOperation {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_intent(
        entry_id: Uuid,
        key: ConsumeKey,
        claim_id: Uuid,
        fence: u64,
        state_instance_id: Uuid,
        origin_acquisition_id: Uuid,
        origin_lease_fence: u64,
        physical_resource: PhysicalResourceKey,
        route_commitment: Digest32,
        bound_secret_uid: Option<String>,
        operation: BrokerJournalOperation,
        prepared_at: i64,
        credential_policy: Option<BrokerCredentialSafetyPolicy>,
    ) -> Result<Self, StateError> {
        let bound_secret_name = deterministic_broker_secret_name(key.transaction_id);
        let request_commitment = broker_request_commitment(
            entry_id,
            &key,
            claim_id,
            fence,
            state_instance_id,
            origin_acquisition_id,
            origin_lease_fence,
            2,
            &physical_resource,
            route_commitment,
            &bound_secret_name,
            bound_secret_uid.as_deref(),
            operation,
            credential_policy,
        )?;
        let stored = Self {
            entry_id,
            key,
            claim_id,
            fence,
            state_instance_id,
            origin_acquisition_id,
            origin_lease_fence,
            acquisition_binding_version: 2,
            physical_resource,
            route_commitment,
            bound_secret_name,
            bound_secret_uid,
            operation,
            phase: BrokerJournalPhase::Intent,
            prepared_at,
            started_at: None,
            credential_policy,
            credential_safe_after: None,
            reconciliation_count: 0,
            last_reconciliation_outcome: None,
            last_reconciliation_evidence_commitment: None,
            last_reconciled_at: None,
            outcome: None,
            provider_evidence_commitment: None,
            token_digest: None,
            token_expires_at: None,
            request_commitment,
            result_commitment: None,
        };
        stored.validate()?;
        Ok(stored)
    }

    pub(crate) fn audit(&self) -> BrokerOperationAudit {
        BrokerOperationAudit {
            entry_id: self.entry_id,
            key: self.key.clone(),
            claim_id: self.claim_id,
            fence: self.fence,
            origin_acquisition_id: self.origin_acquisition_id,
            origin_lease_fence: self.origin_lease_fence,
            physical_resource: self.physical_resource.clone(),
            route_commitment: self.route_commitment,
            bound_secret_name: self.bound_secret_name.clone(),
            bound_secret_uid: self.bound_secret_uid.clone(),
            operation: self.operation,
            phase: self.phase,
            prepared_at: self.prepared_at,
            started_at: self.started_at,
            credential_policy: self.credential_policy,
            credential_safe_after: self.credential_safe_after,
            reconciliation_count: self.reconciliation_count,
            last_reconciliation_outcome: self.last_reconciliation_outcome,
            last_reconciliation_evidence_commitment: self.last_reconciliation_evidence_commitment,
            last_reconciled_at: self.last_reconciled_at,
            outcome: self.outcome,
            result_commitment: self.result_commitment,
            request_commitment: self.request_commitment,
        }
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn validate(&self) -> Result<(), StateError> {
        self.key.validate()?;
        if self.entry_id.is_nil()
            || self.claim_id.is_nil()
            || self.fence == 0
            || self.state_instance_id.is_nil()
            || self.origin_acquisition_id.is_nil()
            || self.origin_lease_fence == 0
            || !matches!(self.acquisition_binding_version, 1 | 2)
            || (self.acquisition_binding_version == 1
                && (self.origin_acquisition_id != self.claim_id
                    || self.origin_lease_fence != self.fence))
            || self.route_commitment == zero_digest()
            || self.request_commitment == zero_digest()
            || self.bound_secret_name != deterministic_broker_secret_name(self.key.transaction_id)
        {
            return Err(StateError::InvalidRecord(
                "broker journal identity is invalid".to_owned(),
            ));
        }
        PhysicalResourceKey::new(
            self.physical_resource.cluster_identity().to_owned(),
            self.physical_resource.namespace().to_owned(),
            self.physical_resource.deployment_uid().to_owned(),
        )?;
        if let Some(uid) = &self.bound_secret_uid {
            validate_secret_uid(uid)?;
        }
        if self.prepared_at < 0
            || self
                .started_at
                .is_some_and(|value| value < self.prepared_at)
        {
            return Err(StateError::InvalidRecord(
                "broker journal time interval is invalid".to_owned(),
            ));
        }
        if (self.operation == BrokerJournalOperation::IssueToken)
            != self.credential_policy.is_some()
            || (self.operation != BrokerJournalOperation::CreateSecret
                && self.bound_secret_uid.is_none())
        {
            return Err(StateError::InvalidRecord(
                "broker journal operation shape is invalid".to_owned(),
            ));
        }
        let active = matches!(
            self.phase,
            BrokerJournalPhase::InFlight
                | BrokerJournalPhase::Unknown
                | BrokerJournalPhase::ReconcileOnly
                | BrokerJournalPhase::Committed
                | BrokerJournalPhase::Terminal
        );
        if active != self.started_at.is_some() {
            return Err(StateError::InvalidRecord(
                "broker journal phase/start binding is invalid".to_owned(),
            ));
        }
        if self.operation == BrokerJournalOperation::IssueToken {
            if active != self.credential_safe_after.is_some() {
                return Err(StateError::InvalidRecord(
                    "token journal lacks its conservative retirement bound".to_owned(),
                ));
            }
        } else if self.credential_safe_after.is_some() {
            return Err(StateError::InvalidRecord(
                "non-token journal contains a credential retirement bound".to_owned(),
            ));
        }
        let has_reconciliation_observation = self.reconciliation_count > 0;
        if has_reconciliation_observation
            != (self.last_reconciliation_outcome.is_some()
                && self.last_reconciliation_evidence_commitment.is_some()
                && self.last_reconciled_at.is_some())
            || (!has_reconciliation_observation
                && (self.last_reconciliation_outcome.is_some()
                    || self.last_reconciliation_evidence_commitment.is_some()
                    || self.last_reconciled_at.is_some()))
        {
            return Err(StateError::InvalidRecord(
                "broker reconciliation observation profile is partial".to_owned(),
            ));
        }
        if has_reconciliation_observation {
            let started_at = self.started_at.ok_or_else(|| {
                StateError::InvalidRecord(
                    "broker reconciliation observation has no operation start".to_owned(),
                )
            })?;
            let reconciled_at = self.last_reconciled_at.ok_or_else(|| {
                StateError::InvalidRecord(
                    "broker reconciliation observation has no trusted time".to_owned(),
                )
            })?;
            if reconciled_at < started_at
                || self.last_reconciliation_evidence_commitment == Some(zero_digest())
                || !matches!(
                    (self.operation, self.last_reconciliation_outcome),
                    (
                        BrokerJournalOperation::CreateSecret,
                        Some(BrokerJournalOutcome::CreateAbsent),
                    ) | (
                        BrokerJournalOperation::DeleteSecret,
                        Some(BrokerJournalOutcome::DeletePresent),
                    )
                )
                || !matches!(
                    self.phase,
                    BrokerJournalPhase::ReconcileOnly
                        | BrokerJournalPhase::Committed
                        | BrokerJournalPhase::Terminal
                )
            {
                return Err(StateError::InvalidRecord(
                    "broker reconciliation observation is inconsistent".to_owned(),
                ));
            }
        }
        let terminal = matches!(
            self.phase,
            BrokerJournalPhase::Committed | BrokerJournalPhase::Terminal
        );
        if terminal
            != (self.outcome.is_some()
                && self.provider_evidence_commitment.is_some()
                && self.result_commitment.is_some())
        {
            return Err(StateError::InvalidRecord(
                "broker journal terminal result is incomplete".to_owned(),
            ));
        }
        if self.phase == BrokerJournalPhase::Committed {
            match (self.operation, self.outcome) {
                (
                    BrokerJournalOperation::CreateSecret,
                    Some(BrokerJournalOutcome::CreateMatching),
                )
                | (BrokerJournalOperation::IssueToken, Some(BrokerJournalOutcome::TokenIssued))
                | (
                    BrokerJournalOperation::DeleteSecret,
                    Some(BrokerJournalOutcome::DeleteAbsent),
                ) => {}
                _ => {
                    return Err(StateError::InvalidRecord(
                        "broker committed outcome does not match its operation".to_owned(),
                    ));
                }
            }
        }
        if self.phase == BrokerJournalPhase::Terminal {
            match (self.operation, self.outcome) {
                (
                    BrokerJournalOperation::CreateSecret,
                    Some(BrokerJournalOutcome::CreateConflicting),
                )
                | (
                    BrokerJournalOperation::DeleteSecret,
                    Some(BrokerJournalOutcome::DeleteConflicting),
                ) => {}
                _ => {
                    return Err(StateError::InvalidRecord(
                        "broker terminal outcome does not match its operation".to_owned(),
                    ));
                }
            }
        }
        if self.outcome == Some(BrokerJournalOutcome::TokenIssued) {
            let started_at = self.started_at.ok_or_else(|| {
                StateError::InvalidRecord("token journal has no start time".to_owned())
            })?;
            let safe_after = self.credential_safe_after.ok_or_else(|| {
                StateError::InvalidRecord("token journal has no safe-after bound".to_owned())
            })?;
            let expires_at = self.token_expires_at.ok_or_else(|| {
                StateError::InvalidRecord("token journal has no expiry".to_owned())
            })?;
            if self.token_digest.is_none() || expires_at <= started_at || expires_at > safe_after {
                return Err(StateError::InvalidRecord(
                    "token journal result exceeds its frozen bounds".to_owned(),
                ));
            }
        } else if self.token_digest.is_some() || self.token_expires_at.is_some() {
            return Err(StateError::InvalidRecord(
                "non-token result contains token metadata".to_owned(),
            ));
        }
        let expected_request = broker_request_commitment(
            self.entry_id,
            &self.key,
            self.claim_id,
            self.fence,
            self.state_instance_id,
            self.origin_acquisition_id,
            self.origin_lease_fence,
            self.acquisition_binding_version,
            &self.physical_resource,
            self.route_commitment,
            &self.bound_secret_name,
            if self.operation == BrokerJournalOperation::CreateSecret
                && self.outcome == Some(BrokerJournalOutcome::CreateMatching)
            {
                None
            } else {
                self.bound_secret_uid.as_deref()
            },
            self.operation,
            self.credential_policy,
        )?;
        if expected_request != self.request_commitment {
            return Err(StateError::InvalidRecord(
                "broker journal request commitment differs".to_owned(),
            ));
        }
        if let (Some(outcome), Some(result)) = (self.outcome, self.result_commitment) {
            let expected = broker_result_commitment(
                self.request_commitment,
                outcome,
                self.bound_secret_uid.as_deref(),
                self.provider_evidence_commitment.ok_or_else(|| {
                    StateError::InvalidRecord("broker result evidence is absent".to_owned())
                })?,
                self.token_digest,
                self.token_expires_at,
            )?;
            if expected != result {
                return Err(StateError::InvalidRecord(
                    "broker journal result commitment differs".to_owned(),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn matches_intent(&self, candidate: &Self) -> bool {
        self.entry_id == candidate.entry_id
            && self.request_commitment == candidate.request_commitment
            && self.key == candidate.key
            && self.operation == candidate.operation
    }

    pub(crate) fn same_request_material(&self, candidate: &Self) -> bool {
        let bound_secret_uid_matches = self.bound_secret_uid == candidate.bound_secret_uid
            || (self.operation == BrokerJournalOperation::CreateSecret
                && self.outcome == Some(BrokerJournalOutcome::CreateMatching)
                && candidate.bound_secret_uid.is_none());
        self.key == candidate.key
            && self.claim_id == candidate.claim_id
            && self.fence == candidate.fence
            && self.state_instance_id == candidate.state_instance_id
            && self.origin_acquisition_id == candidate.origin_acquisition_id
            && self.origin_lease_fence == candidate.origin_lease_fence
            && self.acquisition_binding_version == candidate.acquisition_binding_version
            && self.physical_resource == candidate.physical_resource
            && self.route_commitment == candidate.route_commitment
            && self.bound_secret_name == candidate.bound_secret_name
            && bound_secret_uid_matches
            && self.operation == candidate.operation
            && self.credential_policy == candidate.credential_policy
    }
}

pub(crate) fn pending_broker_reconciliation(
    stored: &StoredBrokerOperation,
    observation: &BrokerSecretObservation,
) -> Option<(BrokerJournalOutcome, Digest32)> {
    match (stored.operation, observation) {
        (BrokerJournalOperation::CreateSecret, BrokerSecretObservation::Absent { .. }) => Some((
            BrokerJournalOutcome::CreateAbsent,
            observation.evidence_commitment(),
        )),
        (
            BrokerJournalOperation::DeleteSecret,
            BrokerSecretObservation::Matching { secret_uid, .. },
        ) if stored.bound_secret_uid.as_deref() == Some(secret_uid.as_str()) => Some((
            BrokerJournalOutcome::DeletePresent,
            observation.evidence_commitment(),
        )),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn broker_request_commitment(
    entry_id: Uuid,
    key: &ConsumeKey,
    claim_id: Uuid,
    fence: u64,
    state_instance_id: Uuid,
    origin_acquisition_id: Uuid,
    origin_lease_fence: u64,
    acquisition_binding_version: i16,
    physical: &PhysicalResourceKey,
    route_commitment: Digest32,
    bound_secret_name: &str,
    bound_secret_uid: Option<&str>,
    operation: BrokerJournalOperation,
    credential_policy: Option<BrokerCredentialSafetyPolicy>,
) -> Result<Digest32, StateError> {
    let mut bytes = match acquisition_binding_version {
        1 if origin_acquisition_id == claim_id && origin_lease_fence == fence => {
            BROKER_REQUEST_DOMAIN.to_vec()
        }
        2 => BROKER_REQUEST_V2_DOMAIN.to_vec(),
        _ => {
            return Err(StateError::InvalidRecord(
                "broker acquisition binding profile is invalid".to_owned(),
            ));
        }
    };
    append_bytes(&mut bytes, key.scope.tenant.as_bytes())?;
    append_bytes(&mut bytes, key.scope.environment.as_bytes())?;
    bytes.extend_from_slice(key.transaction_id.as_bytes());
    bytes.extend_from_slice(key.authorization_id.as_bytes());
    bytes.extend_from_slice(entry_id.as_bytes());
    bytes.extend_from_slice(claim_id.as_bytes());
    bytes.extend_from_slice(&fence.to_be_bytes());
    bytes.extend_from_slice(state_instance_id.as_bytes());
    if acquisition_binding_version == 2 {
        bytes.extend_from_slice(origin_acquisition_id.as_bytes());
        bytes.extend_from_slice(&origin_lease_fence.to_be_bytes());
    }
    append_bytes(&mut bytes, physical.cluster_identity().as_bytes())?;
    append_bytes(&mut bytes, physical.namespace().as_bytes())?;
    append_bytes(&mut bytes, physical.deployment_uid().as_bytes())?;
    bytes.extend_from_slice(route_commitment.as_bytes());
    append_bytes(&mut bytes, bound_secret_name.as_bytes())?;
    if let Some(uid) = bound_secret_uid {
        bytes.push(1);
        append_bytes(&mut bytes, uid.as_bytes())?;
    } else {
        bytes.push(0);
    }
    bytes.push(operation.tag());
    if let Some(policy) = credential_policy {
        bytes.push(1);
        bytes.extend_from_slice(&policy.lifetime_upper_bound_seconds.to_be_bytes());
        bytes.extend_from_slice(&policy.clock_uncertainty_seconds.to_be_bytes());
    } else {
        bytes.push(0);
    }
    Ok(Digest32::sha256(&bytes))
}

pub(crate) fn broker_result_commitment(
    request_commitment: Digest32,
    outcome: BrokerJournalOutcome,
    bound_secret_uid: Option<&str>,
    evidence_commitment: Digest32,
    token_digest: Option<Digest32>,
    token_expires_at: Option<i64>,
) -> Result<Digest32, StateError> {
    let mut bytes = BROKER_RESULT_DOMAIN.to_vec();
    bytes.extend_from_slice(request_commitment.as_bytes());
    bytes.push(outcome.tag());
    if let Some(uid) = bound_secret_uid {
        bytes.push(1);
        append_bytes(&mut bytes, uid.as_bytes())?;
    } else {
        bytes.push(0);
    }
    bytes.extend_from_slice(evidence_commitment.as_bytes());
    if let Some(digest) = token_digest {
        bytes.push(1);
        bytes.extend_from_slice(digest.as_bytes());
    } else {
        bytes.push(0);
    }
    if let Some(expires_at) = token_expires_at {
        bytes.push(1);
        bytes.extend_from_slice(&expires_at.to_be_bytes());
    } else {
        bytes.push(0);
    }
    Ok(Digest32::sha256(&bytes))
}

pub(crate) fn deterministic_broker_secret_name(transaction_id: Uuid) -> String {
    format!("accordlock-{}", transaction_id.simple())
}

pub(crate) fn validate_secret_uid(value: &str) -> Result<(), StateError> {
    if value.is_empty()
        || value.len() > MAX_SECRET_UID_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(StateError::InvalidRecord(
            "bound Secret UID is empty, oversized, padded, or control-bearing".to_owned(),
        ));
    }
    Ok(())
}

fn validate_nonzero_digest(value: [u8; 32]) -> Result<Digest32, StateError> {
    let value = Digest32::from_bytes(value);
    if value == zero_digest() {
        return Err(StateError::InvalidRecord(
            "broker journal commitment cannot be zero".to_owned(),
        ));
    }
    Ok(value)
}

fn valid_review_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.is_ascii()
        && !value.bytes().any(|byte| byte.is_ascii_control())
        && value.trim() == value
}

fn dispatch_credential_review_commitment(
    stored: &StoredDispatchCredentialReview,
) -> Result<Digest32, StateError> {
    let reviewed_at = stored.reviewed_at.ok_or_else(|| {
        StateError::InvalidRecord("terminal credential review has no review time".to_owned())
    })?;
    let evidence = stored.review_evidence_commitment.ok_or_else(|| {
        StateError::InvalidRecord("terminal credential review has no evidence".to_owned())
    })?;
    let mut bytes = CREDENTIAL_REVIEW_DOMAIN.to_vec();
    bytes.extend_from_slice(stored.review_id.as_bytes());
    append_bytes(&mut bytes, stored.token.key().scope.tenant.as_bytes())?;
    append_bytes(&mut bytes, stored.token.key().scope.environment.as_bytes())?;
    bytes.extend_from_slice(stored.token.key().transaction_id.as_bytes());
    bytes.extend_from_slice(stored.token.key().authorization_id.as_bytes());
    bytes.extend_from_slice(stored.token.claim_id().as_bytes());
    append_bytes(&mut bytes, stored.token.worker_id().as_bytes())?;
    bytes.extend_from_slice(&stored.token.fence().to_be_bytes());
    bytes.extend_from_slice(&stored.token.claimed_at().to_be_bytes());
    bytes.extend_from_slice(&stored.token.lease_until().to_be_bytes());
    bytes.extend_from_slice(stored.token.state_instance_id().as_bytes());
    append_bytes(
        &mut bytes,
        stored
            .token
            .physical_resource()
            .cluster_identity()
            .as_bytes(),
    )?;
    append_bytes(
        &mut bytes,
        stored.token.physical_resource().namespace().as_bytes(),
    )?;
    append_bytes(
        &mut bytes,
        stored.token.physical_resource().deployment_uid().as_bytes(),
    )?;
    bytes.extend_from_slice(stored.acquisition_id.as_bytes());
    bytes.extend_from_slice(&stored.lease_fence.to_be_bytes());
    append_bytes(&mut bytes, stored.acquisition_worker_id.as_bytes())?;
    bytes.extend_from_slice(&stored.acquired_at.to_be_bytes());
    bytes.extend_from_slice(&stored.lease_until.to_be_bytes());
    bytes.extend_from_slice(&stored.dispatch_deadline.to_be_bytes());
    match stored.control_submission_id {
        Some(submission_id) => {
            bytes.push(1);
            bytes.extend_from_slice(submission_id.as_bytes());
        }
        None => bytes.push(0),
    }
    bytes.extend_from_slice(stored.create_entry_id.as_bytes());
    bytes.extend_from_slice(stored.create_request_commitment.as_bytes());
    bytes.extend_from_slice(stored.create_result_commitment.as_bytes());
    bytes.extend_from_slice(stored.token_entry_id.as_bytes());
    bytes.extend_from_slice(stored.token_request_commitment.as_bytes());
    bytes.extend_from_slice(stored.token_result_commitment.as_bytes());
    bytes.extend_from_slice(stored.expected_route_commitment.as_bytes());
    bytes.extend_from_slice(
        &stored
            .token_credential_policy
            .lifetime_upper_bound_seconds()
            .to_be_bytes(),
    );
    bytes.extend_from_slice(
        &stored
            .token_credential_policy
            .clock_uncertainty_seconds()
            .to_be_bytes(),
    );
    bytes.extend_from_slice(stored.expected_token_digest.as_bytes());
    bytes.extend_from_slice(&stored.expected_token_expires_at.to_be_bytes());
    append_bytes(&mut bytes, stored.expected_subject.as_bytes())?;
    append_bytes(&mut bytes, stored.expected_audience.as_bytes())?;
    append_bytes(&mut bytes, stored.expected_service_account_uid.as_bytes())?;
    append_bytes(&mut bytes, stored.expected_bound_secret_uid.as_bytes())?;
    bytes.extend_from_slice(stored.credential_lifecycle_policy.commitment().as_bytes());
    bytes.extend_from_slice(stored.destination_activation_commitment.as_bytes());
    bytes.push(match stored.phase {
        DispatchCredentialReviewPhase::Authenticated => 1,
        DispatchCredentialReviewPhase::Rejected => 2,
        DispatchCredentialReviewPhase::InFlight => {
            return Err(StateError::InvalidRecord(
                "in-flight credential review has no terminal commitment".to_owned(),
            ));
        }
    });
    bytes.extend_from_slice(&stored.begun_at.to_be_bytes());
    bytes.extend_from_slice(&reviewed_at.to_be_bytes());
    if let Some(claims) = &stored.claims {
        bytes.push(1);
        bytes.extend_from_slice(claims.token_digest.as_bytes());
        append_bytes(&mut bytes, claims.subject.as_bytes())?;
        append_bytes(&mut bytes, claims.audience.as_bytes())?;
        append_bytes(&mut bytes, claims.service_account_uid.as_bytes())?;
        append_bytes(&mut bytes, claims.credential_id.as_bytes())?;
        append_bytes(&mut bytes, claims.bound_secret_uid.as_bytes())?;
        bytes.extend_from_slice(&claims.not_before.to_be_bytes());
        bytes.extend_from_slice(&claims.expires_at.to_be_bytes());
    } else {
        bytes.push(0);
    }
    bytes.extend_from_slice(evidence.as_bytes());
    Ok(Digest32::sha256(&bytes))
}

const fn zero_digest() -> Digest32 {
    Digest32::from_bytes([0; 32])
}

fn append_bytes(target: &mut Vec<u8>, value: &[u8]) -> Result<(), StateError> {
    let length = u64::try_from(value.len())
        .map_err(|_| StateError::InvalidRecord("broker journal field is too long".to_owned()))?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
    Ok(())
}

pub(crate) fn validate_cleanup_clock(
    scope: &Scope,
    high_water: Option<i64>,
    observed_at: i64,
) -> Result<(), StateError> {
    scope.validate()?;
    if observed_at < 0 {
        return Err(StateError::ClockBeforeUnixEpoch);
    }
    if let Some(high_water) = high_water
        && observed_at < high_water
    {
        return Err(StateError::ClockRollback {
            observed: observed_at,
            high_water,
        });
    }
    Ok(())
}
