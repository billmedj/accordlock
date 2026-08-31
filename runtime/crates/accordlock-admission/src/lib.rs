//! Pure destination-admission profile for `DEPLOY_EKS_IMAGE_V1`.
//!
//! This crate validates a bounded Kubernetes `AdmissionReview`, recomputes the
//! exact `AccordLock` mutation commitments, and asks an [`AdmissionLedger`] to
//! atomically authorize or recover one exact admission UID. It contains no
//! HTTP server, TLS identity adapter, `PostgreSQL` adapter, or Kubernetes webhook
//! registration. Those productive integrations remain separate trust
//! boundaries.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Mutex,
};

use accordlock_dispatch::{AuthorityVersion, PhysicalResourceId, authority_version_from_vector};
use accordlock_k8s::{prepare_patch, validate_admission_candidate};
use accordlock_protocol::{DeploymentTemplate, canonical_hash};
use accordlock_state::{ConsumeKey, Scope, StateError, TransactionalState};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

/// Maximum accepted wire `AdmissionReview` size.
pub const MAX_ADMISSION_REVIEW_BYTES: usize = 1024 * 1024;
const MAX_OBJECT_BYTES: usize = 512 * 1024;
const MAX_UID_BYTES: usize = 128;
const MAX_IDENTITY_BYTES: usize = 512;
const MAX_GROUPS: usize = 32;
const MAX_GROUP_BYTES: usize = 256;
const ADMISSION_CLAIM_DOMAIN: &[u8] = b"accordlock:v2:admission-claim\0";
const EXECUTOR_IDENTITY_DOMAIN: &[u8] = b"accordlock:v2:admission-executor-identity\0";
const ADMISSION_REVIEW_DOMAIN: &[u8] = b"accordlock:v2:admission-review\0";
const CREDENTIAL_ID_EXTRA_KEY: &str = "authentication.kubernetes.io/credential-id";
const OLD_OBJECT_DOMAIN: &[u8] = b"accordlock:v1:admission-old-object\0";
const NEW_OBJECT_DOMAIN: &[u8] = b"accordlock:v1:admission-new-object\0";

/// Canonical logical state scope bound to a durable dispatch claim.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AdmissionScope {
    tenant: String,
    environment: String,
}

impl AdmissionScope {
    /// Creates a bounded non-empty scope.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed scope components.
    pub fn new(tenant: String, environment: String) -> Result<Self, AdmissionProtocolError> {
        if !valid_text(&tenant, MAX_IDENTITY_BYTES) || !valid_text(&environment, MAX_IDENTITY_BYTES)
        {
            return Err(AdmissionProtocolError::InvalidProfile);
        }
        Ok(Self {
            tenant,
            environment,
        })
    }

    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    #[must_use]
    pub fn environment(&self) -> &str {
        &self.environment
    }
}

/// Fixed destination and authenticated executor identity for one webhook
/// profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionProfile {
    cluster_trust_domain: String,
    api_server_identity: String,
    cluster_identity: String,
    executor_username: String,
    executor_groups: BTreeSet<String>,
}

impl AdmissionProfile {
    /// Builds one exact destination admission profile.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or unbounded identity material.
    pub fn new(
        cluster_trust_domain: String,
        api_server_identity: String,
        cluster_identity: String,
        executor_username: String,
        executor_groups: Vec<String>,
    ) -> Result<Self, AdmissionProtocolError> {
        if !valid_text(&cluster_trust_domain, MAX_IDENTITY_BYTES)
            || !valid_text(&api_server_identity, MAX_IDENTITY_BYTES)
            || !valid_text(&cluster_identity, MAX_IDENTITY_BYTES)
            || !valid_service_account_username(&executor_username)
            || executor_groups.is_empty()
            || executor_groups.len() > MAX_GROUPS
            || executor_groups
                .iter()
                .any(|group| !valid_text(group, MAX_GROUP_BYTES))
        {
            return Err(AdmissionProtocolError::InvalidProfile);
        }
        let executor_groups: BTreeSet<_> = executor_groups.into_iter().collect();
        if executor_groups.len() > MAX_GROUPS || !executor_groups.contains("system:authenticated") {
            return Err(AdmissionProtocolError::InvalidProfile);
        }
        Ok(Self {
            cluster_trust_domain,
            api_server_identity,
            cluster_identity,
            executor_username,
            executor_groups,
        })
    }
}

/// Authenticated, state-derived marker presented to destination admission.
///
/// The marker is non-serializable in this crate. The future webhook adapter
/// must obtain it from an authenticated state channel, not from untrusted
/// annotations in the object under review.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionMarker {
    scope: AdmissionScope,
    transaction_id: Uuid,
    authorization_id: Uuid,
    claim_id: Uuid,
    template: DeploymentTemplate,
    template_hash: [u8; 32],
    operation_hash: [u8; 32],
    physical: PhysicalResourceId,
    provider_request_commitment: [u8; 32],
    credential_token_digest: [u8; 32],
    service_account_uid: String,
    credential_id: String,
    credential_binding_commitment: [u8; 32],
    started_at: i64,
    dispatch_deadline: i64,
    authority: AuthorityVersion,
    fence: u64,
}

impl AdmissionMarker {
    /// Constructs a marker for the pure model and conformance tests only.
    ///
    /// This function authenticates nothing. Request-facing production code
    /// must not call it with deserialized material. The productive adapter must
    /// instead expose an opaque marker returned by authenticated state.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn for_model(
        scope: AdmissionScope,
        transaction_id: Uuid,
        authorization_id: Uuid,
        claim_id: Uuid,
        template: DeploymentTemplate,
        template_hash: [u8; 32],
        operation_hash: [u8; 32],
        physical: PhysicalResourceId,
        provider_request_commitment: [u8; 32],
        credential_token_digest: [u8; 32],
        service_account_uid: String,
        credential_id: String,
        credential_binding_commitment: [u8; 32],
        started_at: i64,
        dispatch_deadline: i64,
        authority: AuthorityVersion,
        fence: u64,
    ) -> Self {
        Self {
            scope,
            transaction_id,
            authorization_id,
            claim_id,
            template,
            template_hash,
            operation_hash,
            physical,
            provider_request_commitment,
            credential_token_digest,
            service_account_uid,
            credential_id,
            credential_binding_commitment,
            started_at,
            dispatch_deadline,
            authority,
            fence,
        }
    }
}

/// Authenticated, current destination context supplied by the webhook adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionRuntime {
    now: i64,
    current_authority: AuthorityVersion,
    observer_identity_commitment: [u8; 32],
}

impl AdmissionRuntime {
    /// Constructs runtime premises for the pure model and conformance tests.
    ///
    /// This function authenticates nothing. Production code must derive these
    /// values from trusted time, state, and observer-identity channels.
    #[must_use]
    pub const fn for_model(
        now: i64,
        current_authority: AuthorityVersion,
        observer_identity_commitment: [u8; 32],
    ) -> Self {
        Self {
            now,
            current_authority,
            observer_identity_commitment,
        }
    }
}

/// Atomic claim routed to an admission ledger after all pure review checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionAuthorizationClaim {
    admission_uid: String,
    scope: AdmissionScope,
    transaction_id: Uuid,
    authorization_id: Uuid,
    claim_id: Uuid,
    operation_hash: [u8; 32],
    physical: PhysicalResourceId,
    provider_cluster_identity: String,
    provider_request_commitment: [u8; 32],
    credential_token_digest: [u8; 32],
    service_account_uid: String,
    credential_id: String,
    credential_binding_commitment: [u8; 32],
    review_commitment: [u8; 32],
    old_object_commitment: [u8; 32],
    new_object_commitment: [u8; 32],
    executor_identity_commitment: [u8; 32],
    observer_identity_commitment: [u8; 32],
    started_at: i64,
    dispatch_deadline: i64,
    marker_authority: AuthorityVersion,
    current_authority: AuthorityVersion,
    fence: u64,
    observed_at: i64,
}

impl AdmissionAuthorizationClaim {
    #[must_use]
    pub fn admission_uid(&self) -> &str {
        &self.admission_uid
    }

    #[must_use]
    pub const fn scope(&self) -> &AdmissionScope {
        &self.scope
    }

    #[must_use]
    pub const fn transaction_id(&self) -> Uuid {
        self.transaction_id
    }

    #[must_use]
    pub const fn authorization_id(&self) -> Uuid {
        self.authorization_id
    }

    #[must_use]
    pub const fn claim_id(&self) -> Uuid {
        self.claim_id
    }

    #[must_use]
    pub const fn operation_hash(&self) -> [u8; 32] {
        self.operation_hash
    }

    #[must_use]
    pub const fn physical(&self) -> &PhysicalResourceId {
        &self.physical
    }

    /// Returns the signed provider cluster identity used by durable state.
    /// This is distinct from the authenticated API-server and trust-domain
    /// coordinates in [`PhysicalResourceId`].
    #[must_use]
    pub fn provider_cluster_identity(&self) -> &str {
        &self.provider_cluster_identity
    }

    #[must_use]
    pub const fn provider_request_commitment(&self) -> [u8; 32] {
        self.provider_request_commitment
    }

    #[must_use]
    pub const fn credential_token_digest(&self) -> [u8; 32] {
        self.credential_token_digest
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
    pub const fn credential_binding_commitment(&self) -> [u8; 32] {
        self.credential_binding_commitment
    }

    #[must_use]
    pub const fn review_commitment(&self) -> [u8; 32] {
        self.review_commitment
    }

    #[must_use]
    pub const fn old_object_commitment(&self) -> [u8; 32] {
        self.old_object_commitment
    }

    #[must_use]
    pub const fn new_object_commitment(&self) -> [u8; 32] {
        self.new_object_commitment
    }

    #[must_use]
    pub const fn executor_identity_commitment(&self) -> [u8; 32] {
        self.executor_identity_commitment
    }

    #[must_use]
    pub const fn observer_identity_commitment(&self) -> [u8; 32] {
        self.observer_identity_commitment
    }

    #[must_use]
    pub const fn started_at(&self) -> i64 {
        self.started_at
    }

    #[must_use]
    pub const fn dispatch_deadline(&self) -> i64 {
        self.dispatch_deadline
    }

    #[must_use]
    pub const fn marker_authority(&self) -> &AuthorityVersion {
        &self.marker_authority
    }

    #[must_use]
    pub const fn current_authority(&self) -> &AuthorityVersion {
        &self.current_authority
    }

    #[must_use]
    pub const fn fence(&self) -> u64 {
        self.fence
    }

    #[must_use]
    pub const fn observed_at(&self) -> i64 {
        self.observed_at
    }

    /// Complete domain-separated claim commitment used for exact recovery.
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(ADMISSION_CLAIM_DOMAIN);
        update_bytes(&mut hasher, self.admission_uid.as_bytes());
        update_bytes(&mut hasher, self.scope.tenant.as_bytes());
        update_bytes(&mut hasher, self.scope.environment.as_bytes());
        hasher.update(self.transaction_id.as_bytes());
        hasher.update(self.authorization_id.as_bytes());
        hasher.update(self.claim_id.as_bytes());
        hasher.update(self.operation_hash);
        update_physical(&mut hasher, &self.physical);
        update_bytes(&mut hasher, self.provider_cluster_identity.as_bytes());
        hasher.update(self.provider_request_commitment);
        hasher.update(self.credential_token_digest);
        update_bytes(&mut hasher, self.service_account_uid.as_bytes());
        update_bytes(&mut hasher, self.credential_id.as_bytes());
        hasher.update(self.credential_binding_commitment);
        hasher.update(self.review_commitment);
        hasher.update(self.old_object_commitment);
        hasher.update(self.new_object_commitment);
        hasher.update(self.executor_identity_commitment);
        hasher.update(self.observer_identity_commitment);
        hasher.update(self.started_at.to_be_bytes());
        hasher.update(self.dispatch_deadline.to_be_bytes());
        update_authority(&mut hasher, &self.marker_authority);
        update_authority(&mut hasher, &self.current_authority);
        hasher.update(self.fence.to_be_bytes());
        hasher.finalize().into()
    }
}

/// Idempotent result of one atomic ledger operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionLedgerOutcome {
    /// This call durably authorized the exact UID and claim.
    Authorized,
    /// The exact UID and complete claim were already authorized.
    Recovered,
}

/// Fail-closed atomic-ledger errors.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AdmissionLedgerError {
    #[error("admission time is outside the marker interval")]
    Deadline,
    #[error("current authority differs from marker authority")]
    AuthorityMismatch,
    #[error("admission fence is zero or stale")]
    StaleFence,
    #[error("admission UID already names different claim material")]
    UidMismatch,
    #[error("transaction already used another admission UID")]
    SecondUid,
    #[error("provider request commitment was replayed")]
    ProviderRequestReplay,
    #[error("durable claim identifier was replayed")]
    ClaimReplay,
    #[error("ledger synchronization failed")]
    Unavailable,
}

/// Durable implementations must make this operation one atomic transaction.
pub trait AdmissionLedger: Send + Sync {
    /// Authorizes a new exact UID or recovers the identical existing claim.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed classification for expiry, authority, fence,
    /// replay, UID mismatch, second UID, or storage failure.
    fn authorize_or_recover(
        &self,
        claim: &AdmissionAuthorizationClaim,
    ) -> Result<AdmissionLedgerOutcome, AdmissionLedgerError>;
}

/// Durable adapter from a validated admission claim to `AccordLock` transactional
/// state.
///
/// The claim is request data, not authority. The state implementation reloads
/// the signed authorization, in-flight claim, global physical-resource reservation,
/// active authority and grant, frozen dispatch deadline, trusted clock, and
/// time high-water mark in the same transaction that consumes the admission
/// UID. It also re-derives the provider request commitment from the stored
/// signed template. No marker time or authority value is trusted here.
#[derive(Debug)]
pub struct StateBackedAdmissionLedger<'a, S> {
    state: &'a S,
}

impl<'a, S> StateBackedAdmissionLedger<'a, S> {
    /// Wraps one transactional state adapter.
    #[must_use]
    pub const fn new(state: &'a S) -> Self {
        Self { state }
    }

    /// Returns the wrapped state adapter.
    #[must_use]
    pub const fn state(&self) -> &'a S {
        self.state
    }
}

impl<S: TransactionalState> AdmissionLedger for StateBackedAdmissionLedger<'_, S> {
    fn authorize_or_recover(
        &self,
        claim: &AdmissionAuthorizationClaim,
    ) -> Result<AdmissionLedgerOutcome, AdmissionLedgerError> {
        let scope = Scope::new(claim.scope().tenant(), claim.scope().environment())
            .map_err(|error| map_state_error(&error))?;
        let key = ConsumeKey {
            scope,
            transaction_id: claim.transaction_id(),
            authorization_id: claim.authorization_id(),
        };
        let context = self
            .state
            .admission_context(&key)
            .map_err(|error| map_state_error(&error))?;
        let prepared = prepare_patch(
            context.template(),
            context.key().transaction_id,
            context.key().authorization_id,
        )
        .map_err(|_| AdmissionLedgerError::Unavailable)?;
        if context.claim_id() != claim.claim_id()
            || context.fence() != claim.fence()
            || context.physical_resource().cluster_identity() != claim.provider_cluster_identity()
            || context.physical_resource().namespace() != claim.physical().namespace
            || context.physical_resource().deployment_uid() != claim.physical().deployment_uid
            || context.provider_request_commitment().as_bytes()
                != &claim.provider_request_commitment()
            || context.credential_token_digest().as_bytes() != &claim.credential_token_digest()
            || context.service_account_uid() != claim.service_account_uid()
            || context.credential_id() != claim.credential_id()
            || context.credential_binding_commitment().as_bytes()
                != &claim.credential_binding_commitment()
            || prepared.operation_hash.as_bytes() != &claim.operation_hash()
        {
            return Err(AdmissionLedgerError::ClaimReplay);
        }
        let request = context
            .authorization_request(
                claim.admission_uid().to_owned(),
                claim.service_account_uid(),
                claim.credential_id(),
                accordlock_protocol::Digest32::from_bytes(claim.old_object_commitment()),
                accordlock_protocol::Digest32::from_bytes(claim.new_object_commitment()),
                accordlock_protocol::Digest32::from_bytes(claim.executor_identity_commitment()),
                accordlock_protocol::Digest32::from_bytes(claim.observer_identity_commitment()),
            )
            .map_err(|error| map_state_error(&error))?;
        self.state
            .authorize_admission_or_recover(&request)
            .map(|authorization| {
                if authorization.was_recovered() {
                    AdmissionLedgerOutcome::Recovered
                } else {
                    AdmissionLedgerOutcome::Authorized
                }
            })
            .map_err(|error| map_state_error(&error))
    }
}

fn map_state_error(error: &StateError) -> AdmissionLedgerError {
    match error {
        StateError::EmptyDispatchWindow { .. }
        | StateError::GrantNotYetValid { .. }
        | StateError::GrantExpired { .. }
        | StateError::AuthorizationNotYetValid { .. }
        | StateError::AuthorizationExpired { .. }
        | StateError::DependencyExpired { .. }
        | StateError::DispatchDeadlineExpired { .. }
        | StateError::DispatchClaimLeaseExpired { .. }
        | StateError::DispatchCredentialExpired
        | StateError::ControlIngressKeyNotCurrent { .. }
        | StateError::ControlIngressNotYetValid { .. }
        | StateError::ControlIngressExpired { .. }
        | StateError::ControlWorkLeaseExpired { .. }
        | StateError::ClockRollback { .. } => AdmissionLedgerError::Deadline,
        StateError::AuthorityNotInitialized
        | StateError::AuthorityCompareFailed
        | StateError::AuthorityMismatch
        | StateError::NonMonotoneAuthority
        | StateError::GrantNotFound
        | StateError::GrantMismatch
        | StateError::GrantRegistryRootMismatch
        | StateError::GrantRevoked
        | StateError::GrantExhausted
        | StateError::GrantNotConsumed => AdmissionLedgerError::AuthorityMismatch,
        StateError::AdmissionUidMismatch => AdmissionLedgerError::UidMismatch,
        StateError::AdmissionAlreadyAuthorized => AdmissionLedgerError::SecondUid,
        StateError::AdmissionProviderRequestReplay => AdmissionLedgerError::ProviderRequestReplay,
        StateError::AdmissionClaimNotInFlight
        | StateError::AdmissionClaimMismatch
        | StateError::AdmissionCredentialMismatch
        | StateError::AdmissionProviderRequestMismatch
        | StateError::DispatchClaimNotFound
        | StateError::DispatchClaimMismatch
        | StateError::DispatchAcquisitionMismatch
        | StateError::DispatchAcquisitionRequired
        | StateError::DispatchAlreadyClaimed
        | StateError::DispatchAttemptOutcomeUnknown
        | StateError::PhysicalResourceAlreadyReserved => AdmissionLedgerError::ClaimReplay,
        StateError::DispatchFenceExhausted | StateError::DispatchAcquisitionFenceExhausted => {
            AdmissionLedgerError::StaleFence
        }
        StateError::InvalidRecord(_)
        | StateError::InvalidDeadline(_)
        | StateError::DeadlineOverflow
        | StateError::GrantAlreadyExists
        | StateError::AuthorizationNotFound
        | StateError::AuthorizationAlreadyExists
        | StateError::InvalidAuthorizationSignature(_)
        | StateError::ConsumptionNotFound
        | StateError::TransactionMismatch
        | StateError::DispatchClaimOutcomeUnknown
        | StateError::BrokerOperationNotFound
        | StateError::BrokerOperationMismatch
        | StateError::BrokerOperationOutcomeUnknown
        | StateError::BrokerOperationInvalidTransition
        | StateError::BrokerTokenReissueForbidden
        | StateError::DispatchCredentialReviewNotFound
        | StateError::DispatchCredentialReviewMismatch
        | StateError::DispatchCredentialReviewOutcomeUnknown
        | StateError::DispatchCredentialReviewRejected
        | StateError::TerminalWitnessRegistryNotFound
        | StateError::TerminalWitnessRegistryMismatch
        | StateError::TerminalWitnessRegistryOutcomeUnknown
        | StateError::TerminalRetirementLineageUnavailable
        | StateError::TerminalRetirementMismatch
        | StateError::TerminalRetirementOutcomeUnknown
        | StateError::TerminalEvidenceInvalid(_)
        | StateError::TerminalEvidenceFuture { .. }
        | StateError::AdmissionOutcomeUnknown
        | StateError::AlreadyConsumed
        | StateError::ConsumptionOutcomeUnknown
        | StateError::IngressReplayOutcomeUnknown
        | StateError::ControlSubmissionNotFound
        | StateError::ControlSubmissionMismatch
        | StateError::ControlRequestConflict
        | StateError::ControlNonceAlreadyUsed
        | StateError::ControlWorkNotFound
        | StateError::ControlWorkMismatch
        | StateError::ControlWorkFenceExhausted
        | StateError::ControlDecisionMismatch
        | StateError::ControlStatusNotFound
        | StateError::ClockBeforeUnixEpoch
        | StateError::RetryableConflict
        | StateError::RetryLimitExhausted
        | StateError::SchemaMismatch(_)
        | StateError::UnsafePostgresConnection
        | StateError::Canonical(_)
        | StateError::Serialization(_)
        | StateError::Database(_) => AdmissionLedgerError::Unavailable,
    }
}

/// Process-local executable specification of the ledger behavior.
///
/// This is not a production persistence adapter. It exists for deterministic
/// tests and for conformance of a future `PostgreSQL` implementation.
#[derive(Debug, Default)]
pub struct InMemoryAdmissionLedger {
    state: Mutex<LedgerState>,
}

#[derive(Debug, Default)]
struct LedgerState {
    by_uid: BTreeMap<String, StoredAdmission>,
    by_transaction: BTreeMap<Uuid, String>,
    by_claim_id: BTreeMap<Uuid, String>,
    by_provider_request: BTreeMap<[u8; 32], String>,
    highest_fence: BTreeMap<PhysicalResourceId, u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StoredAdmission {
    claim_commitment: [u8; 32],
    transaction_id: Uuid,
    claim_id: Uuid,
    provider_request_commitment: [u8; 32],
    physical: PhysicalResourceId,
    fence: u64,
}

impl AdmissionLedger for InMemoryAdmissionLedger {
    fn authorize_or_recover(
        &self,
        claim: &AdmissionAuthorizationClaim,
    ) -> Result<AdmissionLedgerOutcome, AdmissionLedgerError> {
        validate_ledger_currentness(claim)?;
        let commitment = claim.commitment();
        let mut state = self
            .state
            .lock()
            .map_err(|_| AdmissionLedgerError::Unavailable)?;

        if let Some(stored) = state.by_uid.get(claim.admission_uid()) {
            return if stored.claim_commitment == commitment
                && stored.transaction_id == claim.transaction_id
                && stored.claim_id == claim.claim_id
                && stored.provider_request_commitment == claim.provider_request_commitment
                && stored.physical == claim.physical
                && stored.fence == claim.fence
            {
                Ok(AdmissionLedgerOutcome::Recovered)
            } else {
                Err(AdmissionLedgerError::UidMismatch)
            };
        }
        if state.by_transaction.contains_key(&claim.transaction_id) {
            return Err(AdmissionLedgerError::SecondUid);
        }
        if state.by_claim_id.contains_key(&claim.claim_id) {
            return Err(AdmissionLedgerError::ClaimReplay);
        }
        if state
            .by_provider_request
            .contains_key(&claim.provider_request_commitment)
        {
            return Err(AdmissionLedgerError::ProviderRequestReplay);
        }
        if state
            .highest_fence
            .get(&claim.physical)
            .is_some_and(|highest| claim.fence <= *highest)
        {
            return Err(AdmissionLedgerError::StaleFence);
        }

        let stored = StoredAdmission {
            claim_commitment: commitment,
            transaction_id: claim.transaction_id,
            claim_id: claim.claim_id,
            provider_request_commitment: claim.provider_request_commitment,
            physical: claim.physical.clone(),
            fence: claim.fence,
        };
        state
            .by_transaction
            .insert(claim.transaction_id, claim.admission_uid.clone());
        state
            .by_claim_id
            .insert(claim.claim_id, claim.admission_uid.clone());
        state.by_provider_request.insert(
            claim.provider_request_commitment,
            claim.admission_uid.clone(),
        );
        state
            .highest_fence
            .insert(claim.physical.clone(), claim.fence);
        state.by_uid.insert(claim.admission_uid.clone(), stored);
        Ok(AdmissionLedgerOutcome::Authorized)
    }
}

fn parse_admission_request(
    review_bytes: &[u8],
) -> Result<WireAdmissionRequest, AdmissionProtocolError> {
    if review_bytes.is_empty() || review_bytes.len() > MAX_ADMISSION_REVIEW_BYTES {
        return Err(AdmissionProtocolError::ReviewSize);
    }
    let _: DuplicateRejectingJson = serde_json::from_slice(review_bytes)
        .map_err(|error| AdmissionProtocolError::Json(error.to_string()))?;
    let review: WireAdmissionReview = serde_json::from_slice(review_bytes)
        .map_err(|error| AdmissionProtocolError::Json(error.to_string()))?;
    if review.api_version != "admission.k8s.io/v1"
        || review.kind != "AdmissionReview"
        || review.response.is_some()
    {
        return Err(AdmissionProtocolError::InvalidEnvelope);
    }
    let request = review
        .request
        .ok_or(AdmissionProtocolError::MissingRequest)?;
    if !valid_admission_uid(&request.uid) {
        return Err(AdmissionProtocolError::InvalidUid);
    }
    Ok(request)
}

/// Pure evaluator for one fixed admission profile.
#[derive(Clone, Debug)]
pub struct AdmissionEngine {
    profile: AdmissionProfile,
}

impl AdmissionEngine {
    #[must_use]
    pub const fn new(profile: AdmissionProfile) -> Self {
        Self { profile }
    }

    /// Parses and evaluates one bounded Kubernetes `AdmissionReview`.
    ///
    /// Once a valid bounded UID has been parsed, all security failures become
    /// deterministic deny responses. Wire failures that prevent safe UID
    /// recovery are returned as protocol errors for the HTTP adapter to reject.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionProtocolError`] when JSON, top-level framing, review
    /// size, or admission UID is invalid.
    pub fn evaluate<L: AdmissionLedger>(
        &self,
        review_bytes: &[u8],
        marker: &AdmissionMarker,
        runtime: &AdmissionRuntime,
        ledger: &L,
    ) -> Result<AdmissionReviewResponse, AdmissionProtocolError> {
        let request = parse_admission_request(review_bytes)?;
        let uid = request.uid.clone();
        let outcome = self.evaluate_request(&request, marker, runtime, ledger);
        Ok(match outcome {
            Ok(AdmissionEvaluationOutcome::Durable(AdmissionLedgerOutcome::Authorized)) => {
                AdmissionReviewResponse::allowed(uid, "AUTHORIZED")
            }
            Ok(AdmissionEvaluationOutcome::Durable(AdmissionLedgerOutcome::Recovered)) => {
                AdmissionReviewResponse::allowed(uid, "RECOVERED")
            }
            Ok(AdmissionEvaluationOutcome::DryRunValidated) => {
                AdmissionReviewResponse::allowed(uid, "DRY_RUN_VALIDATED")
            }
            Err(denial) => AdmissionReviewResponse::denied(uid, denial),
        })
    }

    #[allow(clippy::too_many_lines)]
    fn evaluate_request<L: AdmissionLedger>(
        &self,
        request: &WireAdmissionRequest,
        marker: &AdmissionMarker,
        runtime: &AdmissionRuntime,
        ledger: &L,
    ) -> Result<AdmissionEvaluationOutcome, AdmissionDenial> {
        validate_review_shape(request)?;
        let credential_identity = validate_user(&request.user_info, &self.profile)?;
        validate_marker(marker, runtime, &self.profile)?;
        if credential_identity.service_account_uid != marker.service_account_uid
            || credential_identity.credential_id != marker.credential_id
        {
            return Err(AdmissionDenial::User);
        }

        if request.namespace != marker.template.namespace
            || request.name != marker.template.deployment
        {
            return Err(AdmissionDenial::Destination);
        }
        let old = request
            .old_object
            .as_ref()
            .ok_or(AdmissionDenial::MissingObject)?;
        let new = request
            .object
            .as_ref()
            .ok_or(AdmissionDenial::MissingObject)?;
        let old_bytes = canonical_json_bytes(old)?;
        let new_bytes = canonical_json_bytes(new)?;
        if old_bytes.len() > MAX_OBJECT_BYTES || new_bytes.len() > MAX_OBJECT_BYTES {
            return Err(AdmissionDenial::ObjectSize);
        }

        validate_admission_candidate(
            old,
            new,
            &marker.template,
            marker.transaction_id,
            marker.authorization_id,
            accordlock_protocol::Digest32::from_bytes(marker.operation_hash),
        )
        .map_err(|_| AdmissionDenial::Mutation)?;
        let uid = required_string(new, "/metadata/uid")?;
        let namespace = required_string(new, "/metadata/namespace")?;
        if uid != marker.physical.deployment_uid || namespace != marker.physical.namespace {
            return Err(AdmissionDenial::Destination);
        }

        let review_commitment = review_commitment(request, &old_bytes, &new_bytes);
        let claim = AdmissionAuthorizationClaim {
            admission_uid: request.uid.clone(),
            scope: marker.scope.clone(),
            transaction_id: marker.transaction_id,
            authorization_id: marker.authorization_id,
            claim_id: marker.claim_id,
            operation_hash: marker.operation_hash,
            physical: marker.physical.clone(),
            provider_cluster_identity: marker.template.cluster_identity.clone(),
            provider_request_commitment: marker.provider_request_commitment,
            credential_token_digest: marker.credential_token_digest,
            service_account_uid: credential_identity.service_account_uid,
            credential_id: credential_identity.credential_id,
            credential_binding_commitment: marker.credential_binding_commitment,
            review_commitment,
            old_object_commitment: domain_hash(OLD_OBJECT_DOMAIN, &old_bytes),
            new_object_commitment: domain_hash(NEW_OBJECT_DOMAIN, &new_bytes),
            executor_identity_commitment: executor_identity_commitment(&request.user_info),
            observer_identity_commitment: runtime.observer_identity_commitment,
            started_at: marker.started_at,
            dispatch_deadline: marker.dispatch_deadline,
            marker_authority: marker.authority.clone(),
            current_authority: runtime.current_authority.clone(),
            fence: marker.fence,
            observed_at: runtime.now,
        };
        // Pure fail-fast check. The ledger must repeat these predicates in the
        // same atomic operation as UID/fence consumption; this local check is
        // not a substitute for that linearization point.
        validate_ledger_currentness(&claim).map_err(AdmissionDenial::from)?;
        if request.dry_run == Some(true) {
            return Ok(AdmissionEvaluationOutcome::DryRunValidated);
        }
        ledger
            .authorize_or_recover(&claim)
            .map(AdmissionEvaluationOutcome::Durable)
            .map_err(Into::into)
    }
}

/// Productive destination evaluator whose request-facing API accepts no
/// marker, authority, clock value, claim, fence, template, or provider
/// commitment.
///
/// Tenant and environment scope, destination identity, executor identity, and
/// observer identity are immutable process configuration. The only routing
/// fields extracted from the reviewed object are the transaction and authorization
/// annotations. They select an opaque [`accordlock_state::AdmissionContext`]; they
/// do not authorize anything. Durable state supplies every remaining marker
/// fact and repeats all currentness checks at the final one-shot write.
#[derive(Clone, Debug)]
pub struct StateAdmissionEngine {
    engine: AdmissionEngine,
    scope: AdmissionScope,
    observer_identity_commitment: [u8; 32],
}

impl StateAdmissionEngine {
    /// Constructs a productive engine from trusted deployment configuration.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionProtocolError::InvalidProfile`] when the observer
    /// identity commitment is zero.
    pub fn new(
        profile: AdmissionProfile,
        scope: AdmissionScope,
        observer_identity_commitment: [u8; 32],
    ) -> Result<Self, AdmissionProtocolError> {
        if observer_identity_commitment == [0; 32] {
            return Err(AdmissionProtocolError::InvalidProfile);
        }
        Ok(Self {
            engine: AdmissionEngine::new(profile),
            scope,
            observer_identity_commitment,
        })
    }

    /// Evaluates one live `AdmissionReview` against opaque current state.
    ///
    /// This is the intended library entry point for the future HTTPS webhook.
    /// Dry-run reviews are deterministically denied before any state call,
    /// because obtaining a current durable context advances the trusted-time
    /// high-water mark. This guarantees that `dryRun: true` has no external
    /// state write. A future side-effect-free state snapshot may support a
    /// richer dry-run response without weakening this contract.
    ///
    /// # Errors
    ///
    /// Returns a protocol error only when a bounded response UID cannot be
    /// safely recovered. All later failures become deterministic deny bodies.
    #[allow(clippy::too_many_lines)]
    pub fn evaluate<S: TransactionalState>(
        &self,
        review_bytes: &[u8],
        state: &S,
    ) -> Result<AdmissionReviewResponse, AdmissionProtocolError> {
        let request = parse_admission_request(review_bytes)?;
        let uid = request.uid.clone();
        if let Err(denial) = validate_review_shape(&request)
            .and_then(|()| validate_user(&request.user_info, &self.engine.profile).map(|_| ()))
        {
            return Ok(AdmissionReviewResponse::denied(uid, denial));
        }
        if request.dry_run == Some(true) {
            return Ok(AdmissionReviewResponse::denied(
                uid,
                AdmissionDenial::DryRun,
            ));
        }
        let Some(object) = request.object.as_ref() else {
            return Ok(AdmissionReviewResponse::denied(
                uid,
                AdmissionDenial::MissingObject,
            ));
        };
        let Some(transaction_id) = canonical_annotation_uuid(
            object,
            "/metadata/annotations/accordlock.io~1transaction-id",
        ) else {
            return Ok(AdmissionReviewResponse::denied(
                uid,
                AdmissionDenial::Routing,
            ));
        };
        let Some(authorization_id) = canonical_annotation_uuid(
            object,
            "/metadata/annotations/accordlock.io~1authorization-id",
        ) else {
            return Ok(AdmissionReviewResponse::denied(
                uid,
                AdmissionDenial::Routing,
            ));
        };
        let scope = match Scope::new(self.scope.tenant(), self.scope.environment()) {
            Ok(scope) => scope,
            Err(error) => {
                return Ok(AdmissionReviewResponse::denied(
                    uid,
                    AdmissionDenial::from(map_state_error(&error)),
                ));
            }
        };
        let key = ConsumeKey {
            scope,
            transaction_id,
            authorization_id,
        };
        let context = match state.admission_context(&key) {
            Ok(context) => context,
            Err(error) => {
                return Ok(AdmissionReviewResponse::denied(
                    uid,
                    AdmissionDenial::from(map_state_error(&error)),
                ));
            }
        };
        let Ok(authority) = authority_version_from_vector(context.authority()) else {
            return Ok(AdmissionReviewResponse::denied(
                uid,
                AdmissionDenial::LedgerUnavailable,
            ));
        };
        let template = context.template().clone();
        let template_hash = *context.template_hash().as_bytes();
        let Ok(prepared) = prepare_patch(&template, transaction_id, authorization_id) else {
            return Ok(AdmissionReviewResponse::denied(
                uid,
                AdmissionDenial::LedgerUnavailable,
            ));
        };
        if context.provider_request_commitment() != prepared.final_wire_commitment {
            return Ok(AdmissionReviewResponse::denied(
                uid,
                AdmissionDenial::LedgerUnavailable,
            ));
        }
        let physical = PhysicalResourceId {
            cluster_trust_domain: self.engine.profile.cluster_trust_domain.clone(),
            api_server_identity: self.engine.profile.api_server_identity.clone(),
            namespace: context.physical_resource().namespace().to_owned(),
            deployment_uid: context.physical_resource().deployment_uid().to_owned(),
        };
        if context.operation_hash() != prepared.operation_hash {
            return Ok(AdmissionReviewResponse::denied(
                uid,
                AdmissionDenial::LedgerUnavailable,
            ));
        }
        let checked_at = context.checked_at();
        let started_at = context.started_at();
        let dispatch_deadline = context.dispatch_deadline();
        let marker = AdmissionMarker {
            scope: self.scope.clone(),
            transaction_id,
            authorization_id,
            claim_id: context.claim_id(),
            template,
            template_hash,
            operation_hash: *context.operation_hash().as_bytes(),
            physical,
            provider_request_commitment: *prepared.final_wire_commitment.as_bytes(),
            credential_token_digest: *context.credential_token_digest().as_bytes(),
            service_account_uid: context.service_account_uid().to_owned(),
            credential_id: context.credential_id().to_owned(),
            credential_binding_commitment: *context.credential_binding_commitment().as_bytes(),
            started_at,
            dispatch_deadline,
            authority: authority.clone(),
            fence: context.fence(),
        };
        let runtime = AdmissionRuntime {
            now: checked_at,
            current_authority: authority,
            observer_identity_commitment: self.observer_identity_commitment,
        };
        let ledger = StateBackedAdmissionLedger::new(state);
        self.engine
            .evaluate(review_bytes, &marker, &runtime, &ledger)
    }
}

fn canonical_annotation_uuid(object: &Value, pointer: &str) -> Option<Uuid> {
    let encoded = object.pointer(pointer)?.as_str()?;
    let parsed = Uuid::parse_str(encoded).ok()?;
    (encoded == parsed.to_string() && !parsed.is_nil()).then_some(parsed)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdmissionEvaluationOutcome {
    Durable(AdmissionLedgerOutcome),
    DryRunValidated,
}

/// Deterministic `AdmissionReview` response body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionReviewResponse {
    #[serde(rename = "apiVersion")]
    api_version: &'static str,
    kind: &'static str,
    response: WireAdmissionResponse,
}

impl AdmissionReviewResponse {
    fn allowed(uid: String, ledger_outcome: &'static str) -> Self {
        let mut audit_annotations = BTreeMap::new();
        audit_annotations.insert(
            "accordlock.io/admission-ledger".to_owned(),
            ledger_outcome.to_owned(),
        );
        Self {
            api_version: "admission.k8s.io/v1",
            kind: "AdmissionReview",
            response: WireAdmissionResponse {
                uid,
                allowed: true,
                status: None,
                audit_annotations,
            },
        }
    }

    fn denied(uid: String, denial: AdmissionDenial) -> Self {
        let code = denial.code();
        Self {
            api_version: "admission.k8s.io/v1",
            kind: "AdmissionReview",
            response: WireAdmissionResponse {
                uid,
                allowed: false,
                status: Some(WireStatus {
                    status: "Failure",
                    message: code,
                    reason: "AccordLockAdmissionDenied",
                    code: 403,
                }),
                audit_annotations: BTreeMap::new(),
            },
        }
    }

    #[must_use]
    pub const fn allowed_value(&self) -> bool {
        self.response.allowed
    }

    #[must_use]
    pub fn uid(&self) -> &str {
        &self.response.uid
    }

    #[must_use]
    pub fn denial_code(&self) -> Option<&str> {
        self.response.status.as_ref().map(|status| status.message)
    }

    /// Returns deterministic compact JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns a serialization diagnostic if the response cannot be encoded.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, AdmissionProtocolError> {
        serde_json::to_vec(self).map_err(|error| AdmissionProtocolError::Json(error.to_string()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct WireAdmissionResponse {
    uid: String,
    allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<WireStatus>,
    #[serde(
        rename = "auditAnnotations",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    audit_annotations: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct WireStatus {
    status: &'static str,
    message: &'static str,
    reason: &'static str,
    code: u16,
}

/// Framing and parsing failures for which no safe admission response UID can
/// be produced.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AdmissionProtocolError {
    #[error("admission profile is malformed")]
    InvalidProfile,
    #[error("AdmissionReview is empty or exceeds the wire size bound")]
    ReviewSize,
    #[error("AdmissionReview JSON is invalid: {0}")]
    Json(String),
    #[error("AdmissionReview envelope is not an admission.k8s.io/v1 request")]
    InvalidEnvelope,
    #[error("AdmissionReview request is missing")]
    MissingRequest,
    #[error("AdmissionReview UID is malformed or unbounded")]
    InvalidUid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdmissionDenial {
    Shape,
    User,
    DryRun,
    Routing,
    Marker,
    Destination,
    MissingObject,
    ObjectSize,
    Mutation,
    Deadline,
    Authority,
    Fence,
    UidMismatch,
    SecondUid,
    ProviderReplay,
    ClaimReplay,
    LedgerUnavailable,
}

impl AdmissionDenial {
    const fn code(self) -> &'static str {
        match self {
            Self::Shape => "ACCORDLOCK_REVIEW_SHAPE",
            Self::User => "ACCORDLOCK_EXECUTOR_IDENTITY",
            Self::DryRun => "ACCORDLOCK_DRY_RUN_REQUIRES_SIDE_EFFECT_FREE_STATE",
            Self::Routing => "ACCORDLOCK_ROUTING_ANNOTATION",
            Self::Marker => "ACCORDLOCK_MARKER_MISMATCH",
            Self::Destination => "ACCORDLOCK_PHYSICAL_DESTINATION",
            Self::MissingObject => "ACCORDLOCK_OBJECT_MISSING",
            Self::ObjectSize => "ACCORDLOCK_OBJECT_SIZE",
            Self::Mutation => "ACCORDLOCK_MUTATION_MISMATCH",
            Self::Deadline => "ACCORDLOCK_DEADLINE",
            Self::Authority => "ACCORDLOCK_AUTHORITY",
            Self::Fence => "ACCORDLOCK_FENCE",
            Self::UidMismatch => "ACCORDLOCK_ADMISSION_UID_MISMATCH",
            Self::SecondUid => "ACCORDLOCK_SECOND_ADMISSION_UID",
            Self::ProviderReplay => "ACCORDLOCK_PROVIDER_REQUEST_REPLAY",
            Self::ClaimReplay => "ACCORDLOCK_CLAIM_REPLAY",
            Self::LedgerUnavailable => "ACCORDLOCK_LEDGER_UNAVAILABLE",
        }
    }
}

impl From<AdmissionLedgerError> for AdmissionDenial {
    fn from(error: AdmissionLedgerError) -> Self {
        match error {
            AdmissionLedgerError::Deadline => Self::Deadline,
            AdmissionLedgerError::AuthorityMismatch => Self::Authority,
            AdmissionLedgerError::StaleFence => Self::Fence,
            AdmissionLedgerError::UidMismatch => Self::UidMismatch,
            AdmissionLedgerError::SecondUid => Self::SecondUid,
            AdmissionLedgerError::ProviderRequestReplay => Self::ProviderReplay,
            AdmissionLedgerError::ClaimReplay => Self::ClaimReplay,
            AdmissionLedgerError::Unavailable => Self::LedgerUnavailable,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireAdmissionReview {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    request: Option<WireAdmissionRequest>,
    response: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireAdmissionRequest {
    uid: String,
    kind: GroupVersionKind,
    resource: GroupVersionResource,
    #[serde(rename = "subResource")]
    sub_resource: Option<String>,
    #[serde(rename = "requestKind")]
    request_kind: Option<GroupVersionKind>,
    #[serde(rename = "requestResource")]
    request_resource: Option<GroupVersionResource>,
    #[serde(rename = "requestSubResource")]
    request_sub_resource: Option<String>,
    name: String,
    namespace: String,
    operation: String,
    #[serde(rename = "userInfo")]
    user_info: UserInfo,
    object: Option<Value>,
    #[serde(rename = "oldObject")]
    old_object: Option<Value>,
    #[serde(rename = "dryRun")]
    dry_run: Option<bool>,
    options: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct GroupVersionKind {
    group: String,
    version: String,
    kind: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct GroupVersionResource {
    group: String,
    version: String,
    resource: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserInfo {
    username: String,
    uid: Option<String>,
    groups: Option<Vec<String>>,
    extra: Option<BTreeMap<String, Value>>,
}

/// First-pass JSON validator that rejects duplicate keys at every nesting
/// level before typed deserialization. This prevents parser differential
/// behavior between admission, logging, and Kubernetes components.
#[derive(Debug)]
struct DuplicateRejectingJson;

impl<'de> Deserialize<'de> for DuplicateRejectingJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateRejectingVisitor)
    }
}

struct DuplicateRejectingVisitor;

impl<'de> Visitor<'de> for DuplicateRejectingVisitor {
    type Value = DuplicateRejectingJson;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJson)
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJson)
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJson)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJson)
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJson)
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJson)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJson)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJson)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        DuplicateRejectingJson::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<DuplicateRejectingJson>()?.is_some() {}
        Ok(DuplicateRejectingJson)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate JSON key {key:?}")));
            }
            let _: DuplicateRejectingJson = map.next_value()?;
        }
        Ok(DuplicateRejectingJson)
    }
}

fn validate_review_shape(request: &WireAdmissionRequest) -> Result<(), AdmissionDenial> {
    let deployment_kind = GroupVersionKind {
        group: "apps".to_owned(),
        version: "v1".to_owned(),
        kind: "Deployment".to_owned(),
    };
    let deployment_resource = GroupVersionResource {
        group: "apps".to_owned(),
        version: "v1".to_owned(),
        resource: "deployments".to_owned(),
    };
    if request.kind != deployment_kind
        || request.resource != deployment_resource
        || request
            .request_kind
            .as_ref()
            .is_some_and(|kind| kind != &deployment_kind)
        || request
            .request_resource
            .as_ref()
            .is_some_and(|resource| resource != &deployment_resource)
        || request
            .sub_resource
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        || request
            .request_sub_resource
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        || request.operation != "UPDATE"
        || !valid_dns_label(&request.namespace)
        || !valid_dns_subdomain(&request.name)
    {
        return Err(AdmissionDenial::Shape);
    }
    // UpdateOptions are not interpreted by the security profile. Reject
    // non-object values but retain compatibility with Kubernetes' object.
    if request
        .options
        .as_ref()
        .is_some_and(|options| !options.is_object())
    {
        return Err(AdmissionDenial::Shape);
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct AuthenticatedCredentialIdentity {
    service_account_uid: String,
    credential_id: String,
}

fn validate_user(
    user: &UserInfo,
    profile: &AdmissionProfile,
) -> Result<AuthenticatedCredentialIdentity, AdmissionDenial> {
    let groups = user.groups.as_ref().ok_or(AdmissionDenial::User)?;
    let service_account_uid = user
        .uid
        .as_deref()
        .filter(|uid| valid_text(uid, MAX_IDENTITY_BYTES))
        .ok_or(AdmissionDenial::User)?;
    if user.username != profile.executor_username
        || groups.is_empty()
        || groups.len() > MAX_GROUPS
        || groups
            .iter()
            .any(|group| !valid_text(group, MAX_GROUP_BYTES))
        || groups.iter().collect::<BTreeSet<_>>().len() != groups.len()
        || groups.iter().cloned().collect::<BTreeSet<_>>() != profile.executor_groups
    {
        return Err(AdmissionDenial::User);
    }
    let extra = user.extra.as_ref().ok_or(AdmissionDenial::User)?;
    if extra.len() != 1 {
        return Err(AdmissionDenial::User);
    }
    let values = extra
        .get(CREDENTIAL_ID_EXTRA_KEY)
        .and_then(Value::as_array)
        .filter(|values| values.len() == 1)
        .ok_or(AdmissionDenial::User)?;
    let credential_id = values[0]
        .as_str()
        .filter(|value| valid_credential_id(value))
        .ok_or(AdmissionDenial::User)?;
    Ok(AuthenticatedCredentialIdentity {
        service_account_uid: service_account_uid.to_owned(),
        credential_id: credential_id.to_owned(),
    })
}

fn valid_credential_id(value: &str) -> bool {
    let Some(encoded) = value.strip_prefix("AUTHORIZATION_ID=") else {
        return false;
    };
    Uuid::parse_str(encoded)
        .ok()
        .is_some_and(|parsed| !parsed.is_nil() && encoded == parsed.to_string())
}

fn validate_marker(
    marker: &AdmissionMarker,
    runtime: &AdmissionRuntime,
    profile: &AdmissionProfile,
) -> Result<(), AdmissionDenial> {
    if marker.transaction_id.is_nil()
        || marker.authorization_id.is_nil()
        || marker.claim_id.is_nil()
        || !valid_text(marker.scope.tenant(), MAX_IDENTITY_BYTES)
        || !valid_text(marker.scope.environment(), MAX_IDENTITY_BYTES)
        || marker.template_hash == [0; 32]
        || marker.operation_hash == [0; 32]
        || marker.provider_request_commitment == [0; 32]
        || marker.credential_token_digest == [0; 32]
        || marker.credential_binding_commitment == [0; 32]
        || !valid_text(&marker.service_account_uid, MAX_IDENTITY_BYTES)
        || !valid_credential_id(&marker.credential_id)
        || marker.authority.root == [0; 32]
        || marker.fence == 0
        || marker.started_at < 0
        || marker.dispatch_deadline <= marker.started_at
        || runtime.now < marker.started_at
        || runtime.observer_identity_commitment == [0; 32]
    {
        return Err(AdmissionDenial::Marker);
    }
    if marker.physical.cluster_trust_domain != profile.cluster_trust_domain
        || marker.physical.api_server_identity != profile.api_server_identity
        || marker.template.cluster_identity != profile.cluster_identity
        || marker.template.namespace != marker.physical.namespace
        || marker.template.deployment_uid != marker.physical.deployment_uid
    {
        return Err(AdmissionDenial::Destination);
    }
    let template_hash = canonical_hash(&marker.template).map_err(|_| AdmissionDenial::Marker)?;
    let prepared = prepare_patch(
        &marker.template,
        marker.transaction_id,
        marker.authorization_id,
    )
    .map_err(|_| AdmissionDenial::Marker)?;
    if marker.template_hash != *template_hash.as_bytes()
        || marker.operation_hash != *prepared.operation_hash.as_bytes()
        || marker.provider_request_commitment != *prepared.final_wire_commitment.as_bytes()
    {
        return Err(AdmissionDenial::Marker);
    }
    Ok(())
}

fn validate_ledger_currentness(
    claim: &AdmissionAuthorizationClaim,
) -> Result<(), AdmissionLedgerError> {
    if claim.observed_at < claim.started_at || claim.observed_at >= claim.dispatch_deadline {
        return Err(AdmissionLedgerError::Deadline);
    }
    if claim.marker_authority != claim.current_authority {
        return Err(AdmissionLedgerError::AuthorityMismatch);
    }
    if claim.fence == 0
        || claim.executor_identity_commitment == [0; 32]
        || claim.credential_token_digest == [0; 32]
        || claim.credential_binding_commitment == [0; 32]
        || !valid_text(&claim.service_account_uid, MAX_IDENTITY_BYTES)
        || !valid_credential_id(&claim.credential_id)
        || claim.observer_identity_commitment == [0; 32]
        || claim.old_object_commitment == [0; 32]
        || claim.new_object_commitment == [0; 32]
    {
        return Err(AdmissionLedgerError::StaleFence);
    }
    Ok(())
}

fn review_commitment(
    request: &WireAdmissionRequest,
    old_bytes: &[u8],
    new_bytes: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ADMISSION_REVIEW_DOMAIN);
    update_bytes(&mut hasher, request.uid.as_bytes());
    update_bytes(&mut hasher, request.user_info.username.as_bytes());
    hasher.update(executor_identity_commitment(&request.user_info));
    update_bytes(&mut hasher, request.namespace.as_bytes());
    update_bytes(&mut hasher, request.name.as_bytes());
    update_bytes(&mut hasher, old_bytes);
    update_bytes(&mut hasher, new_bytes);
    hasher.finalize().into()
}

fn executor_identity_commitment(user: &UserInfo) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(EXECUTOR_IDENTITY_DOMAIN);
    update_bytes(&mut hasher, user.username.as_bytes());
    if let Some(uid) = &user.uid {
        update_bytes(&mut hasher, uid.as_bytes());
    } else {
        update_bytes(&mut hasher, &[]);
    }
    let mut groups = user.groups.clone().unwrap_or_default();
    groups.sort();
    for group in groups {
        update_bytes(&mut hasher, group.as_bytes());
    }
    let credential_id = user
        .extra
        .as_ref()
        .and_then(|extra| extra.get(CREDENTIAL_ID_EXTRA_KEY))
        .and_then(Value::as_array)
        .and_then(|values| values.first())
        .and_then(Value::as_str)
        .unwrap_or_default();
    update_bytes(&mut hasher, credential_id.as_bytes());
    hasher.finalize().into()
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    update_bytes(&mut hasher, bytes);
    hasher.finalize().into()
}

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, AdmissionDenial> {
    serde_json::to_vec(value).map_err(|_| AdmissionDenial::Mutation)
}

fn required_string(value: &Value, pointer: &str) -> Result<String, AdmissionDenial> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|candidate| valid_text(candidate, MAX_IDENTITY_BYTES))
        .map(ToOwned::to_owned)
        .ok_or(AdmissionDenial::Destination)
}

fn update_authority(hasher: &mut Sha256, authority: &AuthorityVersion) {
    hasher.update(authority.root);
    hasher.update(authority.epoch.to_be_bytes());
}

fn update_physical(hasher: &mut Sha256, physical: &PhysicalResourceId) {
    update_bytes(hasher, physical.cluster_trust_domain.as_bytes());
    update_bytes(hasher, physical.api_server_identity.as_bytes());
    update_bytes(hasher, physical.namespace.as_bytes());
    update_bytes(hasher, physical.deployment_uid.as_bytes());
}

fn update_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}

fn valid_admission_uid(value: &str) -> bool {
    valid_text(value, MAX_UID_BYTES)
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn valid_service_account_username(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("system:serviceaccount:") else {
        return false;
    };
    let Some((namespace, name)) = rest.split_once(':') else {
        return false;
    };
    valid_dns_label(namespace) && valid_dns_subdomain(name)
}

fn valid_dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn valid_dns_subdomain(value: &str) -> bool {
    !value.is_empty() && value.len() <= 253 && value.split('.').all(valid_dns_label)
}

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicI64, Ordering},
        },
        thread,
    };

    use accordlock_protocol::{
        AuthorityDomainState, AuthorityVector, CanonicalEncode, CapabilityGrant, Digest32,
        DispatchDeadlinePolicy, EXECUTION_AUTHORIZATION_DOMAIN,
        EXECUTION_AUTHORIZATION_SCHEMA_VERSION, ExecutionAuthorization, SignedAuthorization,
        SigningIdentity, authorization_signer_root, sign_cose,
    };
    use accordlock_state::{
        DispatchClaimRequest, GrantRegistration, InMemoryStore, IssuedAuthorizationRecord,
        StateError, TrustedClock, grant_revocation_root,
    };
    use serde_json::json;

    use super::*;

    #[test]
    fn credential_review_state_errors_fail_closed_as_ledger_unavailable() {
        let errors = [
            StateError::DispatchCredentialReviewNotFound,
            StateError::DispatchCredentialReviewMismatch,
            StateError::DispatchCredentialReviewOutcomeUnknown,
            StateError::DispatchCredentialReviewRejected,
        ];

        for error in &errors {
            let mapped = map_state_error(error);
            assert_eq!(mapped, AdmissionLedgerError::Unavailable);
            assert_eq!(
                AdmissionDenial::from(mapped).code(),
                "ACCORDLOCK_LEDGER_UNAVAILABLE"
            );
        }
    }

    #[derive(Clone, Debug)]
    struct Fixture {
        engine: AdmissionEngine,
        marker: AdmissionMarker,
        runtime: AdmissionRuntime,
        review: Value,
        physical: PhysicalResourceId,
    }

    impl Fixture {
        fn new(seed: u128, fence: u64) -> Self {
            let physical = PhysicalResourceId {
                cluster_trust_domain: "spiffe://example.test/eks/cluster-a".to_owned(),
                api_server_identity: "sha256:api-server-a".to_owned(),
                namespace: "payments".to_owned(),
                deployment_uid: format!("deployment-uid-{seed:032x}"),
            };
            Self::with_physical(seed, fence, physical)
        }

        #[allow(clippy::too_many_lines)]
        fn with_physical(seed: u128, fence: u64, physical: PhysicalResourceId) -> Self {
            let transaction_id = Uuid::from_u128(seed | (1_u128 << 120));
            let authorization_id = Uuid::from_u128(seed | (2_u128 << 120));
            let prior_digest = Digest32::from_bytes([0x11; 32]);
            let next_digest = Digest32::from_bytes([0x22; 32]);
            let old = json!({
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {
                    "name": "api",
                    "namespace": physical.namespace,
                    "uid": physical.deployment_uid,
                    "resourceVersion": "10",
                    "generation": 7,
                    "annotations": {
                        "accordlock.io/transaction-id": "none",
                        "accordlock.io/authorization-id": "none",
                        "accordlock.io/operation-hash": "none"
                    },
                    "labels": {"app": "api"}
                },
                "spec": {
                    "replicas": 1,
                    "selector": {"matchLabels": {"app": "api"}},
                    "template": {
                        "metadata": {"labels": {"app": "api"}},
                        "spec": {"containers": [{
                            "name": "api",
                            "image": format!("registry.example.test/team/api@{prior_digest}")
                        }]}
                    }
                }
            });
            let template = DeploymentTemplate {
                operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
                environment: "production".to_owned(),
                audience: "accordlock-executor://payments".to_owned(),
                repository: "https://github.com/example/payments".to_owned(),
                commit_sha: "0123456789abcdef0123456789abcdef01234567".to_owned(),
                image_repository: "registry.example.test/team/api".to_owned(),
                image_digest: next_digest,
                cluster_identity: "eks://cluster-a".to_owned(),
                namespace: "payments".to_owned(),
                deployment: "api".to_owned(),
                deployment_uid: physical.deployment_uid.clone(),
                container: "api".to_owned(),
                container_index: 0,
                prior_image_digest: prior_digest,
                resource_version: "10".to_owned(),
                prior_projection_hash: Digest32::sha256(&serde_json::to_vec(&old).unwrap()),
                prior_transaction_annotation: Some("none".to_owned()),
                prior_authorization_annotation: Some("none".to_owned()),
                prior_operation_hash_annotation: Some("none".to_owned()),
            };
            let prepared = prepare_patch(&template, transaction_id, authorization_id).unwrap();
            let mut new = old.clone();
            *new.pointer_mut("/metadata/resourceVersion").unwrap() = json!("11");
            *new.pointer_mut("/metadata/generation").unwrap() = json!(8);
            *new.pointer_mut("/spec/template/spec/containers/0/image")
                .unwrap() = json!(format!(
                "registry.example.test/team/api@{}",
                template.image_digest
            ));
            *new.pointer_mut("/metadata/annotations/accordlock.io~1transaction-id")
                .unwrap() = json!(transaction_id.to_string());
            *new.pointer_mut("/metadata/annotations/accordlock.io~1authorization-id")
                .unwrap() = json!(authorization_id.to_string());
            *new.pointer_mut("/metadata/annotations/accordlock.io~1operation-hash")
                .unwrap() = json!(prepared.operation_hash.to_string());
            let authority = AuthorityVersion {
                root: [0x51; 32],
                epoch: 12,
            };
            let marker = AdmissionMarker::for_model(
                AdmissionScope::new("acme".to_owned(), "production".to_owned()).unwrap(),
                transaction_id,
                authorization_id,
                Uuid::from_u128(seed | (3_u128 << 120)),
                template,
                *canonical_hash(&prepared_template_for_hash(
                    &old,
                    &physical,
                    next_digest,
                    prior_digest,
                ))
                .unwrap()
                .as_bytes(),
                *prepared.operation_hash.as_bytes(),
                physical.clone(),
                *prepared.final_wire_commitment.as_bytes(),
                [0x91; 32],
                "service-account-uid".to_owned(),
                "AUTHORIZATION_ID=7ee52be0-9045-4653-aa5e-0da57b8dccdc".to_owned(),
                [0x92; 32],
                100,
                180,
                authority.clone(),
                fence,
            );
            // The helper reconstructs the exact same template only to keep the
            // marker construction visibly independent in this adversarial
            // fixture. Assert that premise before testing admission.
            assert_eq!(
                canonical_hash(&marker.template).unwrap().as_bytes(),
                &marker.template_hash
            );
            let review = json!({
                "apiVersion": "admission.k8s.io/v1",
                "kind": "AdmissionReview",
                "request": {
                    "uid": format!("admission-{seed:032x}"),
                    "kind": {"group": "apps", "version": "v1", "kind": "Deployment"},
                    "resource": {"group": "apps", "version": "v1", "resource": "deployments"},
                    "requestKind": {"group": "apps", "version": "v1", "kind": "Deployment"},
                    "requestResource": {"group": "apps", "version": "v1", "resource": "deployments"},
                    "name": "api",
                    "namespace": "payments",
                    "operation": "UPDATE",
                    "userInfo": {
                        "username": "system:serviceaccount:payments:accordlock-executor",
                        "uid": "service-account-uid",
                        "groups": [
                            "system:authenticated",
                            "system:serviceaccounts",
                            "system:serviceaccounts:payments"
                        ],
                        "extra": {
                            "authentication.kubernetes.io/credential-id": [
                                "AUTHORIZATION_ID=7ee52be0-9045-4653-aa5e-0da57b8dccdc"
                            ]
                        }
                    },
                    "object": new,
                    "oldObject": old,
                    "dryRun": false,
                    "options": {"apiVersion": "meta.k8s.io/v1", "kind": "UpdateOptions"}
                }
            });
            let profile = AdmissionProfile::new(
                "spiffe://example.test/eks/cluster-a".to_owned(),
                "sha256:api-server-a".to_owned(),
                "eks://cluster-a".to_owned(),
                "system:serviceaccount:payments:accordlock-executor".to_owned(),
                vec![
                    "system:authenticated".to_owned(),
                    "system:serviceaccounts".to_owned(),
                    "system:serviceaccounts:payments".to_owned(),
                ],
            )
            .unwrap();
            Self {
                engine: AdmissionEngine::new(profile),
                marker,
                runtime: AdmissionRuntime::for_model(101, authority, [0x71; 32]),
                review,
                physical,
            }
        }

        fn bytes(&self) -> Vec<u8> {
            serde_json::to_vec(&self.review).unwrap()
        }
    }

    #[derive(Debug)]
    struct TestClock(AtomicI64);

    impl TestClock {
        fn new(now: i64) -> Self {
            Self(AtomicI64::new(now))
        }

        fn set(&self, now: i64) {
            self.0.store(now, Ordering::SeqCst);
        }
    }

    impl TrustedClock for TestClock {
        fn now_unix_seconds(&self) -> Result<i64, StateError> {
            Ok(self.0.load(Ordering::SeqCst))
        }
    }

    fn authority_domain(label: &str) -> AuthorityDomainState {
        AuthorityDomainState {
            root: Digest32::sha256(label.as_bytes()),
            epoch: 1,
            activation_id: Uuid::new_v4(),
        }
    }

    fn state_authority(signer: &SigningIdentity) -> AuthorityVector {
        let mut authority = AuthorityVector {
            policy: authority_domain("admission-state-policy"),
            registry: authority_domain("admission-state-registry"),
            revocation: authority_domain("admission-state-revocation"),
            connector: authority_domain("admission-state-connector"),
            resource: authority_domain("admission-state-resource"),
            signer: authority_domain("admission-state-signer"),
            mediation: authority_domain("admission-state-mediation"),
            grant_registry: authority_domain("admission-state-grant"),
            office_act_registry: authority_domain("admission-state-office"),
            principal_registry: authority_domain("admission-state-principal"),
            workload_build_allowlist: authority_domain("admission-state-build"),
            kernel_configuration: authority_domain("admission-state-kernel"),
        };
        authority.signer.root =
            authorization_signer_root(signer.key_id(), signer.public_key_bytes()).unwrap();
        authority
    }

    #[derive(Debug)]
    struct StateFixture {
        store: InMemoryStore,
        clock: Arc<TestClock>,
        key: ConsumeKey,
        authority: AuthorityVector,
        grant_id: Uuid,
        marker: AdmissionMarker,
    }

    impl StateFixture {
        #[allow(clippy::too_many_lines)]
        fn in_flight(fixture: &Fixture) -> Self {
            let signer = SigningIdentity::from_seed("admission-state-authorization", [0x44; 32]);
            let template = fixture.marker.template.clone();
            let grant_id = Uuid::from_u128(0xa11ce);
            let grant = CapabilityGrant {
                grant_id,
                holder: "workload-a".to_owned(),
                tenant: fixture.marker.scope.tenant().to_owned(),
                operation: template.operation.clone(),
                repository: template.repository.clone(),
                audience: template.audience.clone(),
                cluster_identity: template.cluster_identity.clone(),
                namespace: template.namespace.clone(),
                deployment_uid: template.deployment_uid.clone(),
                container: template.container.clone(),
                image_repository: template.image_repository.clone(),
                not_before: 50,
                expires_at: 500,
                maximum_uses: 1,
            };
            let mut authority = state_authority(&signer);
            authority.grant_registry.root = canonical_hash(&grant).unwrap();
            let deadline_policy = DispatchDeadlinePolicy {
                max_dispatch_delay_seconds: 80,
                profile_hard_cap: 1_000,
                immutable_dependency_expiries: vec![180],
            };
            let registration = GrantRegistration {
                environment: fixture.marker.scope.environment().to_owned(),
                grant,
                authority: authority.clone(),
                dispatch_deadline_policy: deadline_policy.clone(),
            };
            let scope = Scope::new(
                fixture.marker.scope.tenant(),
                fixture.marker.scope.environment(),
            )
            .unwrap();
            let clock = Arc::new(TestClock::new(100));
            let store = InMemoryStore::with_clock(clock.clone());
            store
                .compare_and_activate_authority(&scope, None, &authority)
                .unwrap();
            store.register_grant(&registration).unwrap();

            let authorization = ExecutionAuthorization {
                schema_version: EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
                authorization_id: fixture.marker.authorization_id,
                evaluation_nonce: Uuid::from_u128(0xe11),
                request_id: Uuid::from_u128(0xe12),
                tenant: fixture.marker.scope.tenant().to_owned(),
                holder: "workload-a".to_owned(),
                audience: template.audience.clone(),
                issued_at: 90,
                not_before: 90,
                consume_before: 200,
                dispatch_deadline_policy: deadline_policy,
                grant_id,
                template: template.clone(),
                template_hash: canonical_hash(&template).unwrap(),
                evidence_root: Digest32::sha256(b"admission-state-evidence"),
                principals: vec!["principal-a".to_owned()],
                policy_root: authority.policy.root,
                authority: authority.clone(),
            };
            let cose_sign1 = sign_cose(
                &authorization.canonical_bytes().unwrap(),
                EXECUTION_AUTHORIZATION_DOMAIN,
                &signer,
            )
            .unwrap();
            let issued = IssuedAuthorizationRecord::new(
                fixture.marker.transaction_id,
                SignedAuthorization {
                    authorization,
                    cose_sign1,
                },
                signer.key_id().to_owned(),
                signer.public_key_bytes(),
            )
            .unwrap();
            let key = ConsumeKey {
                scope,
                transaction_id: fixture.marker.transaction_id,
                authorization_id: fixture.marker.authorization_id,
            };
            store.record_issued_authorization(&issued).unwrap();
            store.consume_or_recover(&key).unwrap();
            clock.set(101);
            let claimed = store
                .claim_dispatch(&DispatchClaimRequest {
                    key: key.clone(),
                    claim_id: fixture.marker.claim_id,
                    worker_id: "worker-a".to_owned(),
                })
                .unwrap();
            assert_eq!(claimed.token().fence(), fixture.marker.fence);
            clock.set(102);
            let credential = claimed
                .token()
                .bind_authenticated_credential(
                    fixture.marker.credential_token_digest,
                    fixture.marker.service_account_uid.clone(),
                    fixture.marker.credential_id.clone(),
                    100,
                    180,
                )
                .unwrap();
            store
                .mark_attempt_in_flight(claimed.token(), credential)
                .unwrap();
            let context = store.admission_context(&key).unwrap();
            let mut marker = fixture.marker.clone();
            marker.credential_token_digest = *context.credential_token_digest().as_bytes();
            marker.service_account_uid = context.service_account_uid().to_owned();
            marker.credential_id = context.credential_id().to_owned();
            marker.credential_binding_commitment =
                *context.credential_binding_commitment().as_bytes();
            Self {
                store,
                clock,
                key,
                authority,
                grant_id,
                marker,
            }
        }

        fn revoke(&self) {
            let mut next = self.authority.clone();
            next.revocation.epoch += 1;
            next.revocation.activation_id = Uuid::new_v4();
            next.revocation.root = grant_revocation_root(self.grant_id);
            self.store
                .revoke_grant(&self.key.scope, self.grant_id, &self.authority, &next)
                .unwrap();
        }
    }

    fn claim_for_fixture(fixture: &Fixture) -> AdmissionAuthorizationClaim {
        let review: WireAdmissionReview = serde_json::from_value(fixture.review.clone()).unwrap();
        let request = review.request.unwrap();
        let old = request.old_object.as_ref().unwrap();
        let new = request.object.as_ref().unwrap();
        let old_bytes = serde_json::to_vec(old).unwrap();
        let new_bytes = serde_json::to_vec(new).unwrap();
        AdmissionAuthorizationClaim {
            admission_uid: request.uid.clone(),
            scope: fixture.marker.scope.clone(),
            transaction_id: fixture.marker.transaction_id,
            authorization_id: fixture.marker.authorization_id,
            claim_id: fixture.marker.claim_id,
            operation_hash: fixture.marker.operation_hash,
            physical: fixture.marker.physical.clone(),
            provider_cluster_identity: fixture.marker.template.cluster_identity.clone(),
            provider_request_commitment: fixture.marker.provider_request_commitment,
            credential_token_digest: fixture.marker.credential_token_digest,
            service_account_uid: fixture.marker.service_account_uid.clone(),
            credential_id: fixture.marker.credential_id.clone(),
            credential_binding_commitment: fixture.marker.credential_binding_commitment,
            review_commitment: review_commitment(&request, &old_bytes, &new_bytes),
            old_object_commitment: domain_hash(OLD_OBJECT_DOMAIN, &old_bytes),
            new_object_commitment: domain_hash(NEW_OBJECT_DOMAIN, &new_bytes),
            executor_identity_commitment: executor_identity_commitment(&request.user_info),
            observer_identity_commitment: fixture.runtime.observer_identity_commitment,
            started_at: fixture.marker.started_at,
            dispatch_deadline: fixture.marker.dispatch_deadline,
            marker_authority: fixture.marker.authority.clone(),
            current_authority: fixture.runtime.current_authority.clone(),
            fence: fixture.marker.fence,
            observed_at: fixture.runtime.now,
        }
    }

    fn prepared_template_for_hash(
        old: &Value,
        physical: &PhysicalResourceId,
        next_digest: Digest32,
        prior_digest: Digest32,
    ) -> DeploymentTemplate {
        DeploymentTemplate {
            operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
            environment: "production".to_owned(),
            audience: "accordlock-executor://payments".to_owned(),
            repository: "https://github.com/example/payments".to_owned(),
            commit_sha: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            image_repository: "registry.example.test/team/api".to_owned(),
            image_digest: next_digest,
            cluster_identity: "eks://cluster-a".to_owned(),
            namespace: "payments".to_owned(),
            deployment: "api".to_owned(),
            deployment_uid: physical.deployment_uid.clone(),
            container: "api".to_owned(),
            container_index: 0,
            prior_image_digest: prior_digest,
            resource_version: "10".to_owned(),
            prior_projection_hash: Digest32::sha256(&serde_json::to_vec(old).unwrap()),
            prior_transaction_annotation: Some("none".to_owned()),
            prior_authorization_annotation: Some("none".to_owned()),
            prior_operation_hash_annotation: Some("none".to_owned()),
        }
    }

    #[test]
    fn exact_review_is_authorized_and_exact_uid_is_recoverable() {
        let fixture = Fixture::new(0x201, 10);
        let ledger = InMemoryAdmissionLedger::default();
        let first = fixture
            .engine
            .evaluate(&fixture.bytes(), &fixture.marker, &fixture.runtime, &ledger)
            .unwrap();
        assert!(first.allowed_value());
        assert!(
            String::from_utf8(first.to_json_bytes().unwrap())
                .unwrap()
                .contains("AUTHORIZED")
        );

        let later_runtime =
            AdmissionRuntime::for_model(102, fixture.marker.authority.clone(), [0x71; 32]);
        let recovered = fixture
            .engine
            .evaluate(&fixture.bytes(), &fixture.marker, &later_runtime, &ledger)
            .unwrap();
        assert!(recovered.allowed_value());
        let first_recovery_bytes = recovered.to_json_bytes().unwrap();
        assert!(
            String::from_utf8(first_recovery_bytes.clone())
                .unwrap()
                .contains("RECOVERED")
        );
        assert_eq!(first_recovery_bytes, recovered.to_json_bytes().unwrap());
    }

    #[test]
    fn dry_run_is_pure_validation_and_does_not_consume_ledger() {
        let mut fixture = Fixture::new(0x211, 11);
        *fixture.review.pointer_mut("/request/dryRun").unwrap() = json!(true);
        let ledger = InMemoryAdmissionLedger::default();
        let dry_run = fixture
            .engine
            .evaluate(&fixture.bytes(), &fixture.marker, &fixture.runtime, &ledger)
            .unwrap();
        assert!(dry_run.allowed_value());
        assert!(
            String::from_utf8(dry_run.to_json_bytes().unwrap())
                .unwrap()
                .contains("DRY_RUN_VALIDATED")
        );

        *fixture.review.pointer_mut("/request/dryRun").unwrap() = json!(false);
        let durable = fixture
            .engine
            .evaluate(&fixture.bytes(), &fixture.marker, &fixture.runtime, &ledger)
            .unwrap();
        assert!(durable.allowed_value());
        assert!(
            String::from_utf8(durable.to_json_bytes().unwrap())
                .unwrap()
                .contains("AUTHORIZED")
        );
    }

    #[test]
    fn second_admission_uid_for_one_transaction_is_denied() {
        let fixture = Fixture::new(0x202, 20);
        let ledger = InMemoryAdmissionLedger::default();
        assert!(
            fixture
                .engine
                .evaluate(&fixture.bytes(), &fixture.marker, &fixture.runtime, &ledger)
                .unwrap()
                .allowed_value()
        );
        let mut replay = fixture.review.clone();
        *replay.pointer_mut("/request/uid").unwrap() = json!("another-admission-uid");
        let denied = fixture
            .engine
            .evaluate(
                &serde_json::to_vec(&replay).unwrap(),
                &fixture.marker,
                &fixture.runtime,
                &ledger,
            )
            .unwrap();
        assert!(!denied.allowed_value());
        assert_eq!(
            denied.denial_code(),
            Some("ACCORDLOCK_SECOND_ADMISSION_UID")
        );
    }

    #[test]
    fn same_uid_with_changed_marker_is_not_recovered() {
        let fixture = Fixture::new(0x203, 30);
        let ledger = InMemoryAdmissionLedger::default();
        assert!(
            fixture
                .engine
                .evaluate(&fixture.bytes(), &fixture.marker, &fixture.runtime, &ledger)
                .unwrap()
                .allowed_value()
        );
        let mut changed = fixture.marker.clone();
        changed.fence += 1;
        let denied = fixture
            .engine
            .evaluate(&fixture.bytes(), &changed, &fixture.runtime, &ledger)
            .unwrap();
        assert_eq!(
            denied.denial_code(),
            Some("ACCORDLOCK_ADMISSION_UID_MISMATCH")
        );
    }

    #[test]
    fn deadline_and_authority_are_checked_inside_atomic_ledger_call() {
        let fixture = Fixture::new(0x204, 40);
        let ledger = InMemoryAdmissionLedger::default();
        let expired = AdmissionRuntime::for_model(
            fixture.marker.dispatch_deadline,
            fixture.marker.authority.clone(),
            [0x71; 32],
        );
        let deadline = fixture
            .engine
            .evaluate(&fixture.bytes(), &fixture.marker, &expired, &ledger)
            .unwrap();
        assert_eq!(deadline.denial_code(), Some("ACCORDLOCK_DEADLINE"));

        let changed_authority = AdmissionRuntime::for_model(
            101,
            AuthorityVersion {
                root: [0x99; 32],
                epoch: fixture.marker.authority.epoch + 1,
            },
            [0x71; 32],
        );
        let authority = fixture
            .engine
            .evaluate(
                &fixture.bytes(),
                &fixture.marker,
                &changed_authority,
                &ledger,
            )
            .unwrap();
        assert_eq!(authority.denial_code(), Some("ACCORDLOCK_AUTHORITY"));
    }

    #[test]
    fn stale_physical_fence_is_denied() {
        let first = Fixture::new(0x205, 60);
        let ledger = InMemoryAdmissionLedger::default();
        assert!(
            first
                .engine
                .evaluate(&first.bytes(), &first.marker, &first.runtime, &ledger)
                .unwrap()
                .allowed_value()
        );
        let stale = Fixture::with_physical(0x206, 59, first.physical.clone());
        let denied = stale
            .engine
            .evaluate(&stale.bytes(), &stale.marker, &stale.runtime, &ledger)
            .unwrap();
        assert_eq!(denied.denial_code(), Some("ACCORDLOCK_FENCE"));
    }

    #[test]
    fn wrong_service_account_is_denied_before_ledger() {
        let mut fixture = Fixture::new(0x207, 70);
        *fixture
            .review
            .pointer_mut("/request/userInfo/username")
            .unwrap() = json!("system:serviceaccount:payments:attacker");
        let denied = fixture
            .engine
            .evaluate(
                &fixture.bytes(),
                &fixture.marker,
                &fixture.runtime,
                &InMemoryAdmissionLedger::default(),
            )
            .unwrap();
        assert_eq!(denied.denial_code(), Some("ACCORDLOCK_EXECUTOR_IDENTITY"));
    }

    #[test]
    fn provider_request_commitment_substitution_is_denied() {
        let fixture = Fixture::new(0x208, 80);
        let mut marker = fixture.marker.clone();
        marker.provider_request_commitment = [0x99; 32];
        let denied = fixture
            .engine
            .evaluate(
                &fixture.bytes(),
                &marker,
                &fixture.runtime,
                &InMemoryAdmissionLedger::default(),
            )
            .unwrap();
        assert_eq!(denied.denial_code(), Some("ACCORDLOCK_MARKER_MISMATCH"));
    }

    #[test]
    fn unauthenticated_runtime_observer_is_denied() {
        let fixture = Fixture::new(0x212, 81);
        let runtime = AdmissionRuntime::for_model(101, fixture.marker.authority.clone(), [0; 32]);
        let denied = fixture
            .engine
            .evaluate(
                &fixture.bytes(),
                &fixture.marker,
                &runtime,
                &InMemoryAdmissionLedger::default(),
            )
            .unwrap();
        assert_eq!(denied.denial_code(), Some("ACCORDLOCK_MARKER_MISMATCH"));
    }

    #[test]
    fn unauthorized_object_delta_is_denied() {
        let mut fixture = Fixture::new(0x209, 90);
        *fixture
            .review
            .pointer_mut("/request/object/spec/replicas")
            .unwrap() = json!(2);
        let denied = fixture
            .engine
            .evaluate(
                &fixture.bytes(),
                &fixture.marker,
                &fixture.runtime,
                &InMemoryAdmissionLedger::default(),
            )
            .unwrap();
        assert_eq!(denied.denial_code(), Some("ACCORDLOCK_MUTATION_MISMATCH"));
    }

    #[test]
    fn unknown_wire_field_and_oversized_review_are_protocol_errors() {
        let fixture = Fixture::new(0x20a, 100);
        let mut unknown = fixture.review.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_owned(), json!(true));
        assert!(matches!(
            fixture.engine.evaluate(
                &serde_json::to_vec(&unknown).unwrap(),
                &fixture.marker,
                &fixture.runtime,
                &InMemoryAdmissionLedger::default(),
            ),
            Err(AdmissionProtocolError::Json(_))
        ));
        assert_eq!(
            fixture.engine.evaluate(
                &vec![b' '; MAX_ADMISSION_REVIEW_BYTES + 1],
                &fixture.marker,
                &fixture.runtime,
                &InMemoryAdmissionLedger::default(),
            ),
            Err(AdmissionProtocolError::ReviewSize)
        );

        let valid = String::from_utf8(fixture.bytes()).unwrap();
        let duplicate_nested_key = valid.replacen(
            "\"metadata\":{\"annotations\"",
            "\"metadata\":{\"name\":\"substituted\",\"annotations\"",
            1,
        );
        assert_ne!(valid, duplicate_nested_key);
        assert!(matches!(
            fixture.engine.evaluate(
                duplicate_nested_key.as_bytes(),
                &fixture.marker,
                &fixture.runtime,
                &InMemoryAdmissionLedger::default(),
            ),
            Err(AdmissionProtocolError::Json(message)) if message.contains("duplicate JSON key")
        ));
    }

    #[test]
    fn concurrent_distinct_uids_for_one_transaction_have_one_winner() {
        let fixture = Fixture::new(0x20b, 110);
        let engine = Arc::new(fixture.engine);
        let marker = Arc::new(fixture.marker);
        let runtime = Arc::new(fixture.runtime);
        let ledger = Arc::new(InMemoryAdmissionLedger::default());
        let first = fixture.review.clone();
        let mut second = fixture.review;
        *second.pointer_mut("/request/uid").unwrap() = json!("second-concurrent-uid");
        let handles: Vec<_> = [first, second]
            .into_iter()
            .map(|review| {
                let engine = engine.clone();
                let marker = marker.clone();
                let runtime = runtime.clone();
                let ledger = ledger.clone();
                thread::spawn(move || {
                    engine
                        .evaluate(
                            &serde_json::to_vec(&review).unwrap(),
                            &marker,
                            &runtime,
                            ledger.as_ref(),
                        )
                        .unwrap()
                })
            })
            .collect();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(
            results
                .iter()
                .filter(|response| response.allowed_value())
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|response| {
                    response.denial_code() == Some("ACCORDLOCK_SECOND_ADMISSION_UID")
                })
                .count(),
            1
        );
    }

    #[test]
    fn ledger_rejects_direct_provider_commitment_replay() {
        let fixture = Fixture::new(0x20c, 120);
        let ledger = InMemoryAdmissionLedger::default();
        let request: WireAdmissionReview = serde_json::from_value(fixture.review.clone()).unwrap();
        let request = request.request.unwrap();
        let old = request.old_object.as_ref().unwrap();
        let new = request.object.as_ref().unwrap();
        let claim = AdmissionAuthorizationClaim {
            admission_uid: request.uid.clone(),
            scope: fixture.marker.scope.clone(),
            transaction_id: fixture.marker.transaction_id,
            authorization_id: fixture.marker.authorization_id,
            claim_id: fixture.marker.claim_id,
            operation_hash: fixture.marker.operation_hash,
            physical: fixture.marker.physical.clone(),
            provider_cluster_identity: fixture.marker.template.cluster_identity.clone(),
            provider_request_commitment: fixture.marker.provider_request_commitment,
            credential_token_digest: fixture.marker.credential_token_digest,
            service_account_uid: fixture.marker.service_account_uid.clone(),
            credential_id: fixture.marker.credential_id.clone(),
            credential_binding_commitment: fixture.marker.credential_binding_commitment,
            review_commitment: review_commitment(
                &request,
                &serde_json::to_vec(old).unwrap(),
                &serde_json::to_vec(new).unwrap(),
            ),
            old_object_commitment: domain_hash(
                OLD_OBJECT_DOMAIN,
                &serde_json::to_vec(old).unwrap(),
            ),
            new_object_commitment: domain_hash(
                NEW_OBJECT_DOMAIN,
                &serde_json::to_vec(new).unwrap(),
            ),
            executor_identity_commitment: executor_identity_commitment(&request.user_info),
            observer_identity_commitment: [0x71; 32],
            started_at: 100,
            dispatch_deadline: 180,
            marker_authority: fixture.marker.authority.clone(),
            current_authority: fixture.marker.authority.clone(),
            fence: 120,
            observed_at: 101,
        };
        assert_eq!(
            ledger.authorize_or_recover(&claim),
            Ok(AdmissionLedgerOutcome::Authorized)
        );
        let mut replay = claim;
        replay.admission_uid = "different-uid".to_owned();
        replay.transaction_id = Uuid::from_u128(0xfeed);
        replay.claim_id = Uuid::from_u128(0xbeef);
        replay.fence += 1;
        assert_eq!(
            ledger.authorize_or_recover(&replay),
            Err(AdmissionLedgerError::ProviderRequestReplay)
        );
    }

    #[test]
    fn state_backed_engine_authorizes_and_recovers_the_exact_in_flight_attempt() {
        let fixture = Fixture::new(0x301, 1);
        let state = StateFixture::in_flight(&fixture);
        let ledger = StateBackedAdmissionLedger::new(&state.store);

        let first = fixture
            .engine
            .evaluate(&fixture.bytes(), &state.marker, &fixture.runtime, &ledger)
            .unwrap();
        assert!(first.allowed_value());
        assert!(
            String::from_utf8(first.to_json_bytes().unwrap())
                .unwrap()
                .contains("AUTHORIZED")
        );

        state.clock.set(103);
        let recovered = fixture
            .engine
            .evaluate(&fixture.bytes(), &state.marker, &fixture.runtime, &ledger)
            .unwrap();
        assert!(recovered.allowed_value());
        assert!(
            String::from_utf8(recovered.to_json_bytes().unwrap())
                .unwrap()
                .contains("RECOVERED")
        );
    }

    #[test]
    fn state_backed_dry_run_never_consumes_the_durable_admission_uid() {
        let mut fixture = Fixture::new(0x302, 1);
        let state = StateFixture::in_flight(&fixture);
        let ledger = StateBackedAdmissionLedger::new(&state.store);
        *fixture.review.pointer_mut("/request/dryRun").unwrap() = json!(true);

        let dry_run = fixture
            .engine
            .evaluate(&fixture.bytes(), &state.marker, &fixture.runtime, &ledger)
            .unwrap();
        assert!(dry_run.allowed_value());
        assert!(
            String::from_utf8(dry_run.to_json_bytes().unwrap())
                .unwrap()
                .contains("DRY_RUN_VALIDATED")
        );

        *fixture.review.pointer_mut("/request/dryRun").unwrap() = json!(false);
        let actual = fixture
            .engine
            .evaluate(&fixture.bytes(), &state.marker, &fixture.runtime, &ledger)
            .unwrap();
        assert!(actual.allowed_value());
        assert!(
            String::from_utf8(actual.to_json_bytes().unwrap())
                .unwrap()
                .contains("AUTHORIZED")
        );
    }

    #[test]
    fn state_backed_adapter_rejects_arbitrary_provider_claim_fence_and_resource() {
        let cases: [fn(&mut AdmissionAuthorizationClaim); 4] = [
            |claim| claim.provider_request_commitment = [0xa1; 32],
            |claim| claim.claim_id = Uuid::from_u128(0xbad1),
            |claim| claim.fence += 1,
            |claim| claim.physical.deployment_uid = "another-deployment-uid".to_owned(),
        ];

        for (index, mutate) in cases.into_iter().enumerate() {
            let fixture = Fixture::new(0x310 + u128::try_from(index).unwrap(), 1);
            let state = StateFixture::in_flight(&fixture);
            let ledger = StateBackedAdmissionLedger::new(&state.store);
            let mut claim = claim_for_fixture(&fixture);
            mutate(&mut claim);
            assert!(ledger.authorize_or_recover(&claim).is_err());
        }
    }

    #[test]
    fn state_backed_adapter_uses_state_time_and_revocation_not_marker_runtime() {
        let expired_fixture = Fixture::new(0x320, 1);
        let expired_state = StateFixture::in_flight(&expired_fixture);
        expired_state.clock.set(180);
        let expired_ledger = StateBackedAdmissionLedger::new(&expired_state.store);
        let expired = expired_fixture
            .engine
            .evaluate(
                &expired_fixture.bytes(),
                &expired_state.marker,
                &expired_fixture.runtime,
                &expired_ledger,
            )
            .unwrap();
        assert_eq!(expired.denial_code(), Some("ACCORDLOCK_DEADLINE"));

        let revoked_fixture = Fixture::new(0x321, 1);
        let revoked_state = StateFixture::in_flight(&revoked_fixture);
        revoked_state.revoke();
        let revoked_ledger = StateBackedAdmissionLedger::new(&revoked_state.store);
        let revoked = revoked_fixture
            .engine
            .evaluate(
                &revoked_fixture.bytes(),
                &revoked_state.marker,
                &revoked_fixture.runtime,
                &revoked_ledger,
            )
            .unwrap();
        assert_eq!(revoked.denial_code(), Some("ACCORDLOCK_AUTHORITY"));
    }

    #[test]
    fn state_backed_adapter_rejects_second_uid_and_nonidentical_recovery() {
        let fixture = Fixture::new(0x330, 1);
        let state = StateFixture::in_flight(&fixture);
        let ledger = StateBackedAdmissionLedger::new(&state.store);
        assert!(
            fixture
                .engine
                .evaluate(&fixture.bytes(), &state.marker, &fixture.runtime, &ledger)
                .unwrap()
                .allowed_value()
        );

        let mut second_uid = claim_for_fixture(&fixture);
        second_uid.credential_token_digest = state.marker.credential_token_digest;
        second_uid.service_account_uid = state.marker.service_account_uid.clone();
        second_uid.credential_id = state.marker.credential_id.clone();
        second_uid.credential_binding_commitment = state.marker.credential_binding_commitment;
        second_uid.admission_uid = "a-second-admission-uid".to_owned();
        assert_eq!(
            ledger.authorize_or_recover(&second_uid),
            Err(AdmissionLedgerError::SecondUid)
        );

        let mut changed_same_uid = claim_for_fixture(&fixture);
        changed_same_uid.credential_token_digest = state.marker.credential_token_digest;
        changed_same_uid.service_account_uid = state.marker.service_account_uid.clone();
        changed_same_uid.credential_id = state.marker.credential_id.clone();
        changed_same_uid.credential_binding_commitment = state.marker.credential_binding_commitment;
        changed_same_uid.old_object_commitment = [0x99; 32];
        assert_eq!(
            ledger.authorize_or_recover(&changed_same_uid),
            Err(AdmissionLedgerError::UidMismatch)
        );
    }

    #[test]
    fn productive_engine_accepts_only_review_bytes_and_state() {
        let fixture = Fixture::new(0x340, 1);
        let state = StateFixture::in_flight(&fixture);
        let engine = StateAdmissionEngine::new(
            fixture.engine.profile.clone(),
            fixture.marker.scope.clone(),
            [0x71; 32],
        )
        .unwrap();

        let first = engine.evaluate(&fixture.bytes(), &state.store).unwrap();
        assert!(first.allowed_value());
        assert!(
            String::from_utf8(first.to_json_bytes().unwrap())
                .unwrap()
                .contains("AUTHORIZED")
        );

        state.clock.set(103);
        let recovered = engine.evaluate(&fixture.bytes(), &state.store).unwrap();
        assert!(recovered.allowed_value());
        assert!(
            String::from_utf8(recovered.to_json_bytes().unwrap())
                .unwrap()
                .contains("RECOVERED")
        );
    }

    #[test]
    fn productive_engine_rejects_credential_substitution_without_consuming_ledger() {
        fn other_credential(review: &mut Value) {
            *review
                .pointer_mut(concat!(
                    "/request/userInfo/extra/",
                    "authentication.kubernetes.io~1credential-id/0"
                ))
                .unwrap() = json!("AUTHORIZATION_ID=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        }
        fn uid_swap(review: &mut Value) {
            *review.pointer_mut("/request/userInfo/uid").unwrap() =
                json!("other-service-account-uid");
        }
        fn missing_extra(review: &mut Value) {
            review
                .pointer_mut("/request/userInfo")
                .and_then(Value::as_object_mut)
                .unwrap()
                .remove("extra");
        }
        fn duplicate_id(review: &mut Value) {
            *review
                .pointer_mut(concat!(
                    "/request/userInfo/extra/",
                    "authentication.kubernetes.io~1credential-id"
                ))
                .unwrap() = json!([
                "AUTHORIZATION_ID=7ee52be0-9045-4653-aa5e-0da57b8dccdc",
                "AUTHORIZATION_ID=7ee52be0-9045-4653-aa5e-0da57b8dccdc"
            ]);
        }
        fn unknown_extra(review: &mut Value) {
            review
                .pointer_mut("/request/userInfo/extra")
                .and_then(Value::as_object_mut)
                .unwrap()
                .insert(
                    "authentication.kubernetes.io/pod-name".to_owned(),
                    json!(["attacker-pod"]),
                );
        }

        let cases: [fn(&mut Value); 5] = [
            other_credential,
            uid_swap,
            missing_extra,
            duplicate_id,
            unknown_extra,
        ];
        for (index, mutate) in cases.into_iter().enumerate() {
            let mut fixture = Fixture::new(0x350 + u128::try_from(index).unwrap(), 1);
            let exact_review = fixture.review.clone();
            let state = StateFixture::in_flight(&fixture);
            let engine = StateAdmissionEngine::new(
                fixture.engine.profile.clone(),
                fixture.marker.scope.clone(),
                [0x71; 32],
            )
            .unwrap();
            mutate(&mut fixture.review);
            let denied = engine.evaluate(&fixture.bytes(), &state.store).unwrap();
            assert_eq!(
                denied.denial_code(),
                Some("ACCORDLOCK_EXECUTOR_IDENTITY"),
                "credential substitution case {index}"
            );

            fixture.review = exact_review;
            let exact = engine.evaluate(&fixture.bytes(), &state.store).unwrap();
            assert!(
                exact.allowed_value(),
                "denied credential case {index} must not consume the admission ledger"
            );
        }
    }

    #[test]
    fn productive_dry_run_is_denied_without_any_state_write() {
        let mut fixture = Fixture::new(0x341, 1);
        let state = StateFixture::in_flight(&fixture);
        let engine = StateAdmissionEngine::new(
            fixture.engine.profile.clone(),
            fixture.marker.scope.clone(),
            [0x71; 32],
        )
        .unwrap();
        state.clock.set(103);
        assert_eq!(
            state.store.time_high_water(&state.key.scope).unwrap(),
            Some(102)
        );
        *fixture.review.pointer_mut("/request/dryRun").unwrap() = json!(true);

        let dry_run = engine.evaluate(&fixture.bytes(), &state.store).unwrap();
        assert!(!dry_run.allowed_value());
        assert_eq!(
            dry_run.denial_code(),
            Some("ACCORDLOCK_DRY_RUN_REQUIRES_SIDE_EFFECT_FREE_STATE")
        );
        assert_eq!(
            state.store.time_high_water(&state.key.scope).unwrap(),
            Some(102)
        );

        *fixture.review.pointer_mut("/request/dryRun").unwrap() = json!(false);
        let live = engine.evaluate(&fixture.bytes(), &state.store).unwrap();
        assert!(live.allowed_value());
        assert!(
            String::from_utf8(live.to_json_bytes().unwrap())
                .unwrap()
                .contains("AUTHORIZED")
        );
    }

    #[test]
    fn productive_engine_treats_annotations_only_as_fail_closed_routing() {
        let mut fixture = Fixture::new(0x342, 1);
        let state = StateFixture::in_flight(&fixture);
        let engine = StateAdmissionEngine::new(
            fixture.engine.profile.clone(),
            fixture.marker.scope.clone(),
            [0x71; 32],
        )
        .unwrap();
        *fixture
            .review
            .pointer_mut("/request/object/metadata/annotations/accordlock.io~1transaction-id")
            .unwrap() = json!(Uuid::from_u128(0xdead).to_string());

        let denied = engine.evaluate(&fixture.bytes(), &state.store).unwrap();
        assert!(!denied.allowed_value());
        assert_eq!(denied.denial_code(), Some("ACCORDLOCK_CLAIM_REPLAY"));
        assert_eq!(
            state.store.time_high_water(&state.key.scope).unwrap(),
            Some(102)
        );
    }
}
