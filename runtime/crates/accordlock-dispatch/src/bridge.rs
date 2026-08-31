use accordlock_eks_profile::EksCredentialLifecyclePolicy;
use accordlock_k8s::{ProjectionError, prepare_patch};
use accordlock_protocol::{AuthorityVector, CanonicalEncode, CanonicalError, canonical_hash};
use accordlock_state::{
    ConsumeKey, DispatchAcquisitionAuthority, DispatchAcquisitionRecoveryKey,
    DispatchAttemptAcquisition, DispatchClaimToken, DispatchRecoveryAcquisition, DispatchSnapshot,
    DispatchWork, OutboxStatus, ReviewedDispatchCredential, StateError, TransactionalState,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    AuthorityVersion, ConsumptionBinding, DispatchClaim, DispatchError, DispatchMachine,
    EffectBinding, EffectTemplate, LogicalOwner, PhysicalResourceId,
};

const CONSUMPTION_TUPLE_DOMAIN: &[u8] = b"accordlock:v1:dispatch-consumption-tuple\0";

/// Opaque local projection of one exact state-backed dispatch claim.
///
/// All fields are private. In particular, this type is not an alternate raw
/// construction path for [`ConsumptionBinding`].
#[derive(Debug, PartialEq, Eq)]
pub struct DispatchImport {
    transaction_id: uuid::Uuid,
    physical: PhysicalResourceId,
    authority_version: AuthorityVersion,
    consumption: ConsumptionBinding,
    checked_at: i64,
    acquisition: DispatchAcquisitionAuthority,
}

impl DispatchImport {
    #[must_use]
    pub const fn transaction_id(&self) -> uuid::Uuid {
        self.transaction_id
    }

    #[must_use]
    pub fn physical(&self) -> &PhysicalResourceId {
        &self.physical
    }

    #[must_use]
    pub fn authority(&self) -> &AuthorityVersion {
        &self.authority_version
    }

    #[must_use]
    pub const fn consumption(&self) -> ConsumptionBinding {
        self.consumption
    }

    #[must_use]
    pub const fn checked_at(&self) -> i64 {
        self.checked_at
    }

    /// Returns the exact non-serializable acquisition generation by reference.
    /// Stable claim identity alone is deliberately not exposed as productive
    /// authority.
    #[must_use]
    pub const fn acquisition_authority(&self) -> &DispatchAcquisitionAuthority {
        &self.acquisition
    }
}

/// One-shot local authority returned only after durable
/// `ATTEMPT_IN_FLIGHT` committed and the exact local transition succeeded.
///
/// The value is deliberately non-clonable and non-serializable. It does not
/// establish external exactly-once delivery; an executor must consume it at
/// its own boundary and must never retry an ambiguous provider result.
#[derive(Debug, PartialEq, Eq)]
pub struct AuthorizedProviderAttempt {
    transaction_id: uuid::Uuid,
    physical: PhysicalResourceId,
    binding: EffectBinding,
    started_at: i64,
    token_not_before: i64,
    token_expires_at: i64,
    service_account_uid: String,
    credential_id: String,
    token: DispatchClaimToken,
    acquisition: DispatchAttemptAcquisition,
    credential_lifecycle_policy: EksCredentialLifecyclePolicy,
    destination_activation_commitment: [u8; 32],
}

/// Inert proof that restart recovery entered durable `RECOVERY_NO_SEND`.
///
/// A restarted process no longer owns the bearer, so this value can authorize
/// cleanup and audit only. It can never be converted into
/// [`AuthorizedProviderAttempt`].
#[derive(Debug, PartialEq, Eq)]
pub struct RecoveredAttemptCommit {
    transaction_id: uuid::Uuid,
    key: ConsumeKey,
    acquisition: DispatchRecoveryAcquisition,
}

impl RecoveredAttemptCommit {
    #[must_use]
    pub const fn transaction_id(&self) -> uuid::Uuid {
        self.transaction_id
    }

    #[must_use]
    pub const fn key(&self) -> &ConsumeKey {
        &self.key
    }

    #[must_use]
    pub const fn acquisition(&self) -> &DispatchRecoveryAcquisition {
        &self.acquisition
    }
}

impl AuthorizedProviderAttempt {
    #[must_use]
    pub const fn transaction_id(&self) -> uuid::Uuid {
        self.transaction_id
    }

    #[must_use]
    pub const fn physical(&self) -> &PhysicalResourceId {
        &self.physical
    }

    #[must_use]
    pub const fn binding(&self) -> &EffectBinding {
        &self.binding
    }

    #[must_use]
    pub const fn started_at(&self) -> i64 {
        self.started_at
    }

    /// Returns the absolute, state-derived deadline after which no provider
    /// request may begin.
    ///
    /// This value is copied from the same opaque durable snapshot that was
    /// revalidated immediately before `ATTEMPT_IN_FLIGHT` committed. It lets
    /// the consuming executor fail closed if local scheduling delays the
    /// network handoff past that bound.
    #[must_use]
    pub const fn dispatch_deadline(&self) -> i64 {
        self.acquisition.dispatch_deadline()
    }

    #[must_use]
    pub const fn token_not_before(&self) -> i64 {
        self.token_not_before
    }

    #[must_use]
    pub const fn token_expires_at(&self) -> i64 {
        self.token_expires_at
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
    pub const fn claim_token(&self) -> &DispatchClaimToken {
        &self.token
    }

    /// Returns the immutable acquisition generation committed by the durable
    /// attempt compare-and-set. This is audit/lifetime data, not reusable
    /// acquisition authority.
    #[must_use]
    pub const fn acquisition(&self) -> &DispatchAttemptAcquisition {
        &self.acquisition
    }

    #[must_use]
    pub const fn credential_lifecycle_policy(&self) -> EksCredentialLifecyclePolicy {
        self.credential_lifecycle_policy
    }

    #[must_use]
    pub const fn destination_activation_commitment(&self) -> [u8; 32] {
        self.destination_activation_commitment
    }
}

/// Fail-closed errors at the transactional-state to dispatch boundary.
#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("state rejected the durable dispatch operation: {0}")]
    State(#[from] StateError),
    #[error("Kubernetes projection could not be derived from the consumed authorization: {0}")]
    Projection(#[from] ProjectionError),
    #[error("canonical commitment derivation failed: {0}")]
    Canonical(#[from] CanonicalError),
    #[error("dispatch machine rejected the state-derived transition: {0}")]
    Dispatch(#[from] DispatchError),
    #[error("authority epoch sum overflowed")]
    AuthorityEpochOverflow,
    #[error("a canonical commitment input is too large")]
    CommitmentLengthOverflow,
    #[error("the opaque state snapshot is internally inconsistent")]
    SnapshotMismatch,
    #[error("one dispatch machine cannot import more than one state scope")]
    ScopeMismatch,
}

struct DerivedSnapshot {
    transaction_id: uuid::Uuid,
    owner: LogicalOwner,
    physical: PhysicalResourceId,
    authority: AuthorityVersion,
    consumption: ConsumptionBinding,
    checked_at: i64,
    dispatch_deadline: i64,
    consumed_at: i64,
}

/// Derives the exact scalar dispatch version from the complete authority
/// vector.
///
/// The root commits to every domain root, epoch, and activation identifier.
/// The scalar epoch is the checked sum of all domain epochs. Along a
/// componentwise-monotone state history, every authority change therefore
/// strictly increases it.
///
/// # Errors
///
/// Returns [`BridgeError`] if canonical encoding or checked addition fails.
pub fn authority_version_from_vector(
    authority: &AuthorityVector,
) -> Result<AuthorityVersion, BridgeError> {
    let root = *canonical_hash(authority)?.as_bytes();
    let epoch = authority
        .domains()
        .into_iter()
        .try_fold(0_u64, |sum, domain| sum.checked_add(domain.epoch))
        .ok_or(BridgeError::AuthorityEpochOverflow)?;
    Ok(AuthorityVersion { root, epoch })
}

/// Commits to the exact durable receipt and pending-witness outbox tuple in an
/// opaque state snapshot.
///
/// This encoding is explicit and length-prefixed. It does not depend on JSON,
/// `serde`, map order, or a caller-provided byte array.
///
/// # Errors
///
/// Returns [`BridgeError`] when canonical receipt encoding or a length
/// conversion fails.
fn consumption_tuple_commitment(snapshot: &DispatchSnapshot) -> Result<[u8; 32], BridgeError> {
    let receipt_bytes = snapshot.receipt().canonical_bytes()?;
    let outbox = snapshot.outbox();
    let mut hasher = Sha256::new();
    hasher.update(CONSUMPTION_TUPLE_DOMAIN);
    update_bytes(&mut hasher, &receipt_bytes)?;
    update_string(&mut hasher, &outbox.scope.tenant)?;
    update_string(&mut hasher, &outbox.scope.environment)?;
    hasher.update(outbox.transaction_id.as_bytes());
    hasher.update(outbox.authorization_id.as_bytes());
    hasher.update(outbox.dispatch_deadline.to_be_bytes());
    let status = match outbox.status {
        OutboxStatus::PendingWitness => 1_u8,
    };
    hasher.update([status]);
    Ok(hasher.finalize().into())
}

impl DispatchMachine {
    /// Imports one server-selected durable dispatch acquisition.
    ///
    /// Owner, route, authority, authorization identifiers, hashes, Kubernetes patch,
    /// execution command, provider wire, consumption time, and deadline are all
    /// derived only from the opaque [`DispatchWork`] returned by state. The
    /// acquisition authority is moved into the import and remains the only
    /// productive state capability throughout broker preparation.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError`] for an existing or ambiguous durable claim, an
    /// invalid snapshot, missing or ambiguous trusted destination registration,
    /// scope mixing, stale authority, or an invalid dispatch interval.
    pub fn import_acquired_dispatch(
        &mut self,
        work: DispatchWork,
    ) -> Result<DispatchImport, BridgeError> {
        let (snapshot, acquisition) = work.into_parts();
        let derived = self.derive_state_snapshot(&snapshot)?;
        if !Self::token_matches_derived(acquisition.claim(), &derived)
            || acquisition.dispatch_deadline() != derived.dispatch_deadline
        {
            return Err(BridgeError::SnapshotMismatch);
        }
        if !self.accepts_bridge_owner(&derived.owner) {
            return Err(BridgeError::ScopeMismatch);
        }
        self.activate_authority(derived.authority.clone())?;
        self.record_consumption_from_snapshot(
            derived.transaction_id,
            derived.owner.clone(),
            derived.physical.clone(),
            derived.authority.clone(),
            derived.consumption,
            derived.consumed_at,
            derived.checked_at,
            derived.dispatch_deadline,
        )?;
        self.bind_dispatch_claim_token(derived.transaction_id, acquisition.claim().clone())?;
        self.bind_bridge_owner(derived.owner);
        Ok(DispatchImport {
            transaction_id: derived.transaction_id,
            physical: derived.physical,
            authority_version: derived.authority,
            consumption: derived.consumption,
            checked_at: derived.checked_at,
            acquisition,
        })
    }

    /// Derives the local worker and trusted preparation time from a successful
    /// durable import.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError`] if the import belongs to another machine or the
    /// local reservation, clock, authority, or identity checks fail.
    pub fn prepare_claimed_dispatch(
        &mut self,
        imported: &DispatchImport,
    ) -> Result<DispatchClaim, BridgeError> {
        if !self
            .bridge_token_matches_transaction(imported.transaction_id, imported.acquisition.claim())
        {
            return Err(BridgeError::SnapshotMismatch);
        }
        Ok(self.prepare_dispatch(
            imported.transaction_id,
            imported.acquisition.worker_id(),
            imported.checked_at,
        )?)
    }

    /// Revalidates the exact durable claim immediately before the local model
    /// authorizes a bound-object create call.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError`] if durable state or the exact local claim and
    /// snapshot binding is no longer valid.
    pub fn begin_bound_object_create_from_state<S: TransactionalState>(
        &mut self,
        state: &S,
        imported: &DispatchImport,
        claim: &DispatchClaim,
    ) -> Result<(), BridgeError> {
        let derived = self.revalidate_acquired_state(state, imported, claim)?;
        self.begin_bound_object_create(derived.transaction_id, claim, derived.checked_at)?;
        Ok(())
    }

    /// Revalidates the exact durable claim immediately before a token request
    /// can begin.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError`] if durable state or the exact local claim and
    /// snapshot binding is no longer valid.
    pub fn begin_credential_issue_from_state<S: TransactionalState>(
        &mut self,
        state: &S,
        imported: &DispatchImport,
        claim: &DispatchClaim,
    ) -> Result<(), BridgeError> {
        let derived = self.revalidate_acquired_state(state, imported, claim)?;
        self.begin_credential_issue(derived.transaction_id, claim, derived.checked_at)?;
        Ok(())
    }

    /// Accepts returned token claims only after another exact durable claim
    /// recheck.
    ///
    /// If state became stale, revoked, expired, or unavailable while the token
    /// request was in flight, the returned token digest and conservative bounds
    /// are retained and the local lifecycle enters invalidation. There is no
    /// caller-provided safety verdict.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError`] for a foreign token or claim, a rejected durable
    /// recheck, or invalid returned credential claims. A post-request durable
    /// rejection still leaves the credential retained for invalidation.
    fn record_credential_result_from_state<S: TransactionalState>(
        &mut self,
        state: &S,
        imported: &DispatchImport,
        claim: &DispatchClaim,
        claims: &crate::CredentialClaims,
    ) -> Result<(), BridgeError> {
        if !self.bridge_token_matches_claim(imported.acquisition.claim(), claim) {
            return Err(BridgeError::SnapshotMismatch);
        }
        let derived = match self.revalidate_acquired_state(state, imported, claim) {
            Ok(derived) => derived,
            Err(error) => {
                self.quarantine_returned_credential_after_state_rejection(
                    claim.transaction_id,
                    claim,
                    claims,
                )?;
                return Err(error);
            }
        };
        match self.record_credential_ready(
            derived.transaction_id,
            claim,
            derived.checked_at,
            claims,
        ) {
            Ok(()) => Ok(()),
            Err(error) => {
                if self.phase(derived.transaction_id)? == crate::LifecyclePhase::CredentialIssuing {
                    self.quarantine_returned_credential_after_state_rejection(
                        derived.transaction_id,
                        claim,
                        claims,
                    )?;
                }
                Err(BridgeError::Dispatch(error))
            }
        }
    }

    /// Commits the durable provider-attempt boundary and only then advances the
    /// local lifecycle.
    ///
    /// The durable linearization point is the state commit to
    /// `ATTEMPT_IN_FLIGHT`, not the later network send. A repeated or ambiguous
    /// mark never returns execution authority. Exact provider-effect evidence
    /// remains a later, separate oracle input.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError`] when state has changed, the grant was revoked,
    /// the deadline passed, the claim differs from current durable state, the
    /// attempt mark is ambiguous, or the local transition fails.
    #[allow(clippy::too_many_lines)]
    pub fn authorize_provider_attempt_from_state<S: TransactionalState>(
        &mut self,
        state: &S,
        imported: DispatchImport,
        claim: &DispatchClaim,
        binding: &EffectBinding,
        reviewed: ReviewedDispatchCredential,
    ) -> Result<AuthorizedProviderAttempt, BridgeError> {
        if !self.bridge_token_matches_claim(imported.acquisition.claim(), claim) {
            return Err(BridgeError::SnapshotMismatch);
        }
        let reviewed_claims = reviewed.claims();
        let claims = crate::CredentialClaims {
            token_digest: *reviewed_claims.token_digest().as_bytes(),
            subject: reviewed_claims.subject().to_owned(),
            audience: reviewed_claims.audience().to_owned(),
            service_account_uid: reviewed_claims.service_account_uid().to_owned(),
            credential_id: reviewed_claims.credential_id().to_owned(),
            bound_object_uid: reviewed_claims.bound_secret_uid().to_owned(),
            not_before: reviewed_claims.not_before(),
            expires_at: reviewed_claims.expires_at(),
        };
        let reviewed_policy = reviewed.credential_lifecycle_policy();
        let reviewed_activation = reviewed.destination_activation_commitment();
        let expected_review_id = reviewed.review_id();
        if reviewed_activation.as_bytes() == &[0; 32] || binding.token_digest != claims.token_digest
        {
            return Err(BridgeError::SnapshotMismatch);
        }
        self.record_credential_result_from_state(state, &imported, claim, &claims)?;
        let preflight = match self.revalidate_acquired_state(state, &imported, claim) {
            Ok(derived) => derived,
            Err(BridgeError::State(error)) => {
                self.handle_provider_state_rejection(&error, claim)?;
                return Err(BridgeError::State(error));
            }
            Err(error) => return Err(error),
        };
        self.preflight_provider_attempt(
            preflight.transaction_id,
            claim,
            binding,
            preflight.checked_at,
        )?;

        let credential_facts = self.credential_authority_facts(preflight.transaction_id, claim)?;
        if credential_facts.token_digest != claims.token_digest
            || credential_facts.service_account_uid != claims.service_account_uid
            || credential_facts.credential_id != claims.credential_id
            || credential_facts.not_before != claims.not_before
            || credential_facts.expires_at != claims.expires_at
        {
            return Err(BridgeError::SnapshotMismatch);
        }

        let expected_acquisition = (
            imported.acquisition.acquisition_id(),
            imported.acquisition.lease_fence(),
            imported.acquisition.worker_id().to_owned(),
            imported.acquisition.acquired_at(),
            imported.acquisition.lease_until(),
            imported.acquisition.dispatch_deadline(),
            imported.acquisition.control_submission_id(),
        );
        let imported_transaction_id = imported.transaction_id;
        // The import owns the productive acquisition authority. No authority
        // survives the proof-only attempt CAS boundary.
        drop(imported);
        let attempt_in_flight = match state.mark_dispatch_acquisition_attempt_in_flight(reviewed) {
            Ok(attempt) => attempt,
            Err(error) => {
                self.handle_provider_state_rejection(&error, claim)?;
                return Err(BridgeError::State(error));
            }
        };
        let (snapshot, committed_token, committed_acquisition, started_at) =
            attempt_in_flight.into_parts();
        let committed = match self.derive_state_snapshot(&snapshot) {
            Ok(derived)
                if committed_token.key().transaction_id == imported_transaction_id
                    && started_at == snapshot.checked_at()
                    && Self::token_matches_derived(&committed_token, &derived)
                    && (
                        committed_acquisition.acquisition_id(),
                        committed_acquisition.lease_fence(),
                        committed_acquisition.worker_id().to_owned(),
                        committed_acquisition.acquired_at(),
                        committed_acquisition.lease_until(),
                        committed_acquisition.dispatch_deadline(),
                        committed_acquisition.control_submission_id(),
                    ) == expected_acquisition
                    && committed_acquisition.dispatch_deadline() == derived.dispatch_deadline
                    && committed_acquisition.credential_review_id() == Some(expected_review_id)
                    && committed_acquisition.credential_lifecycle_policy()
                        == Some(reviewed_policy)
                    && committed_acquisition.destination_activation_commitment()
                        == Some(reviewed_activation)
                    && self.derived_matches_local(&derived, claim) =>
            {
                derived
            }
            Ok(_) | Err(_) => {
                self.force_manual_provider_attempt_uncertainty(claim.transaction_id, claim)?;
                return Err(BridgeError::SnapshotMismatch);
            }
        };

        if let Err(error) = self.release_and_begin_provider_attempt(
            committed.transaction_id,
            claim,
            binding,
            started_at,
        ) {
            self.force_manual_provider_attempt_uncertainty(claim.transaction_id, claim)?;
            return Err(BridgeError::Dispatch(error));
        }
        Ok(AuthorizedProviderAttempt {
            transaction_id: committed.transaction_id,
            physical: committed.physical,
            binding: *binding,
            started_at,
            token_not_before: credential_facts.not_before,
            token_expires_at: credential_facts.expires_at,
            service_account_uid: credential_facts.service_account_uid,
            credential_id: credential_facts.credential_id,
            token: committed_token,
            acquisition: committed_acquisition,
            credential_lifecycle_policy: reviewed_policy,
            destination_activation_commitment: *reviewed_activation.as_bytes(),
        })
    }

    /// Closes one exact pre-attempt broker lineage as durable
    /// `RECOVERY_NO_SEND` without manufacturing provider-I/O authority.
    ///
    /// The server-selected recovery key identifies the historical acquisition.
    /// State reconstructs and validates its frozen acquisition/journal lineage
    /// without sampling time or requiring a still-live productive lease.
    /// Success returns only an inert cleanup/audit value and covers CREATE,
    /// TOKEN, and review artifacts whether or not review authenticated.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError`] when the recovery lineage is stale, substituted,
    /// ambiguous, or its committed acquisition tuple is inconsistent.
    pub fn close_recovered_attempt_from_state<S: TransactionalState>(
        &self,
        state: &S,
        recovery: &DispatchAcquisitionRecoveryKey,
    ) -> Result<RecoveredAttemptCommit, BridgeError> {
        let closed = state.close_dispatch_acquisition_no_send(recovery)?;
        let key = closed.key();
        let acquisition = closed.acquisition();
        if key.transaction_id.is_nil()
            || acquisition.acquisition_id().is_nil()
            || acquisition.lease_fence() == 0
            || acquisition.worker_id().is_empty()
            || acquisition.acquisition_id() != recovery.acquisition_id()
            || acquisition.worker_id() != recovery.worker_id()
            || &key.scope != recovery.scope()
            || acquisition.acquired_at() < 0
            || acquisition.acquired_at() >= acquisition.lease_until()
            || acquisition.lease_until() > acquisition.dispatch_deadline()
            || acquisition.control_submission_id().is_nil()
        {
            return Err(BridgeError::SnapshotMismatch);
        }
        Ok(RecoveredAttemptCommit {
            transaction_id: key.transaction_id,
            key: key.clone(),
            acquisition: acquisition.clone(),
        })
    }

    fn handle_provider_state_rejection(
        &mut self,
        error: &StateError,
        claim: &DispatchClaim,
    ) -> Result<(), BridgeError> {
        let phase = self.phase(claim.transaction_id)?;
        if matches!(error, StateError::DispatchAttemptOutcomeUnknown) {
            if matches!(
                phase,
                crate::LifecyclePhase::CredentialReady | crate::LifecyclePhase::Executing
            ) {
                self.force_manual_provider_attempt_uncertainty(claim.transaction_id, claim)?;
            }
        } else if exact_claim_currentness_rejection(error)
            && phase == crate::LifecyclePhase::CredentialReady
        {
            self.invalidate_ready_credential_after_state_rejection(claim.transaction_id, claim)?;
        }
        Ok(())
    }

    fn revalidate_acquired_state<S: TransactionalState>(
        &self,
        state: &S,
        imported: &DispatchImport,
        claim: &DispatchClaim,
    ) -> Result<DerivedSnapshot, BridgeError> {
        let token = imported.acquisition.claim();
        if !self.bridge_token_matches_claim(token, claim) {
            return Err(BridgeError::SnapshotMismatch);
        }
        let snapshot = state.revalidate_dispatch_acquisition(&imported.acquisition)?;
        let derived = self.derive_state_snapshot(&snapshot)?;
        if !Self::token_matches_derived(token, &derived)
            || !self.derived_matches_local(&derived, claim)
        {
            return Err(BridgeError::SnapshotMismatch);
        }
        Ok(derived)
    }

    fn derived_matches_local(&self, derived: &DerivedSnapshot, claim: &DispatchClaim) -> bool {
        claim.transaction_id == derived.transaction_id
            && claim.physical == derived.physical
            && claim.consumption == derived.consumption
            && self.accepts_bridge_owner(&derived.owner)
            && self.bridge_snapshot_matches(
                derived.transaction_id,
                &derived.owner,
                &derived.physical,
                &derived.authority,
                derived.consumption,
                derived.dispatch_deadline,
            )
    }

    fn token_matches_derived(token: &DispatchClaimToken, derived: &DerivedSnapshot) -> bool {
        token.key().transaction_id == derived.transaction_id
            && token.key().authorization_id == derived.consumption.authorization_id
            && token.key().scope.tenant == derived.owner.tenant
            && token.key().scope.environment == derived.owner.environment
    }

    fn derive_state_snapshot(
        &self,
        snapshot: &DispatchSnapshot,
    ) -> Result<DerivedSnapshot, BridgeError> {
        let issued = snapshot.issued();
        let authorization = issued.authorization();
        let receipt = snapshot.receipt();
        let outbox = snapshot.outbox();
        if issued.scope() != *snapshot.scope()
            || outbox.scope != *snapshot.scope()
            || issued.transaction_id != receipt.transaction_id
            || receipt.transaction_id != outbox.transaction_id
            || authorization.authorization_id != receipt.authorization_id
            || receipt.authorization_id != outbox.authorization_id
            || issued.authorization_hash != receipt.authorization_hash
            || receipt.authority != *snapshot.authority()
            || receipt.dispatch_deadline != outbox.dispatch_deadline
            || snapshot.checked_at() < receipt.consumed_at
            || snapshot.checked_at() >= receipt.dispatch_deadline
        {
            return Err(BridgeError::SnapshotMismatch);
        }

        let owner = LogicalOwner {
            tenant: snapshot.scope().tenant.clone(),
            environment: snapshot.scope().environment.clone(),
        };
        let physical = self.resolve_state_destination(
            &owner,
            &authorization.template.cluster_identity,
            &authorization.template.namespace,
            &authorization.template.deployment_uid,
        )?;
        let prepared = prepare_patch(
            &authorization.template,
            issued.transaction_id,
            authorization.authorization_id,
        )?;
        let authority = authority_version_from_vector(snapshot.authority())?;
        let consumption = ConsumptionBinding {
            authorization_id: authorization.authorization_id,
            authorization_hash: *issued.authorization_hash.as_bytes(),
            receipt_commitment: consumption_tuple_commitment(snapshot)?,
            effect: EffectTemplate {
                template_hash: *authorization.template_hash.as_bytes(),
                operation_hash: *prepared.operation_hash.as_bytes(),
                execution_command_commitment: *prepared.execution_command_commitment.as_bytes(),
                final_wire_commitment: *prepared.final_wire_commitment.as_bytes(),
            },
        };
        Ok(DerivedSnapshot {
            transaction_id: issued.transaction_id,
            owner,
            physical,
            authority,
            consumption,
            checked_at: snapshot.checked_at(),
            dispatch_deadline: receipt.dispatch_deadline,
            consumed_at: receipt.consumed_at,
        })
    }
}

fn update_bytes(hasher: &mut Sha256, value: &[u8]) -> Result<(), BridgeError> {
    let length = u64::try_from(value.len()).map_err(|_| BridgeError::CommitmentLengthOverflow)?;
    hasher.update(length.to_be_bytes());
    hasher.update(value);
    Ok(())
}

fn update_string(hasher: &mut Sha256, value: &str) -> Result<(), BridgeError> {
    update_bytes(hasher, value.as_bytes())
}

fn exact_claim_currentness_rejection(error: &StateError) -> bool {
    matches!(
        error,
        StateError::AuthorityMismatch
            | StateError::GrantMismatch
            | StateError::GrantRegistryRootMismatch
            | StateError::GrantRevoked
            | StateError::GrantNotYetValid { .. }
            | StateError::GrantExpired { .. }
            | StateError::GrantExhausted
            | StateError::GrantNotConsumed
            | StateError::AuthorizationNotYetValid { .. }
            | StateError::AuthorizationExpired { .. }
            | StateError::DependencyExpired { .. }
            | StateError::DispatchDeadlineExpired { .. }
            | StateError::DispatchClaimLeaseExpired { .. }
            | StateError::ClockRollback { .. }
    )
}

// The former v13 claim-token bridge fixtures intentionally do not compile
// against the v14 acquisition-only productive surface. End-to-end v14 bridge
// coverage lives in the control/acquisition integration suite.
#[cfg(any())]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::panic,
        clippy::too_many_lines,
        clippy::unwrap_used
    )]

    use std::sync::Arc;
    use std::sync::atomic::{AtomicI64, Ordering};

    use accordlock_k8s::prepare_patch;
    use accordlock_protocol::{
        AuthorityDomainState, CapabilityGrant, DeploymentTemplate, Digest32,
        DispatchDeadlinePolicy, EXECUTION_AUTHORIZATION_DOMAIN,
        EXECUTION_AUTHORIZATION_SCHEMA_VERSION, ExecutionAuthorization, SignedAuthorization,
        SigningIdentity, authorization_signer_root, canonical_hash, sign_cose,
    };
    use accordlock_state::{
        ConsumeKey, DispatchAcquisitionOutcome, DispatchAcquisitionRequest, GrantRegistration,
        InMemoryStore, IssuedAuthorizationRecord, Scope, TrustedClock, grant_revocation_root,
    };

    use super::*;
    use crate::{
        BoundObjectObservation, CredentialClaims, CredentialProfile, DispatchBounds,
        LifecyclePhase, PreparedExecution,
    };

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

    struct Fixture {
        store: InMemoryStore,
        clock: Arc<TestClock>,
        scope: Scope,
        authority: AuthorityVector,
        grant_id: uuid::Uuid,
        key: ConsumeKey,
        template: DeploymentTemplate,
    }

    impl Fixture {
        fn new() -> Self {
            Self::new_with_ids(0x301, 0x401)
        }

        fn new_with_ids(transaction_id: u128, authorization_id: u128) -> Self {
            let clock = Arc::new(TestClock::new(100));
            let store = InMemoryStore::with_clock(clock.clone());
            let scope = Scope::new("acme", "prod").unwrap();
            let signer = SigningIdentity::from_seed("dispatch-bridge-authorization", [0x51; 32]);
            let template = template();
            let grant = CapabilityGrant {
                grant_id: uuid::Uuid::from_u128(0x201),
                holder: "workload:release".to_owned(),
                tenant: scope.tenant.clone(),
                operation: template.operation.clone(),
                repository: template.repository.clone(),
                audience: template.audience.clone(),
                cluster_identity: template.cluster_identity.clone(),
                namespace: template.namespace.clone(),
                deployment_uid: template.deployment_uid.clone(),
                container: template.container.clone(),
                image_repository: template.image_repository.clone(),
                not_before: 50,
                expires_at: 300,
                maximum_uses: 1,
            };
            let mut authority = authority();
            authority.grant_registry.root = canonical_hash(&grant).unwrap();
            authority.signer.root =
                authorization_signer_root(signer.key_id(), signer.public_key_bytes()).unwrap();
            let deadline_policy = DispatchDeadlinePolicy {
                max_dispatch_delay_seconds: 30,
                profile_hard_cap: 200,
                immutable_dependency_expiries: vec![190],
            };
            let registration = GrantRegistration {
                environment: scope.environment.clone(),
                grant: grant.clone(),
                authority: authority.clone(),
                dispatch_deadline_policy: deadline_policy.clone(),
            };
            store
                .compare_and_activate_authority(&scope, None, &authority)
                .unwrap();
            store.register_grant(&registration).unwrap();

            let transaction_id = uuid::Uuid::from_u128(transaction_id);
            let authorization_id = uuid::Uuid::from_u128(authorization_id);
            let authorization = ExecutionAuthorization {
                schema_version: EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
                authorization_id,
                evaluation_nonce: uuid::Uuid::from_u128(0x501),
                request_id: uuid::Uuid::from_u128(0x601),
                tenant: scope.tenant.clone(),
                holder: grant.holder.clone(),
                audience: template.audience.clone(),
                issued_at: 90,
                not_before: 90,
                consume_before: 180,
                dispatch_deadline_policy: deadline_policy,
                grant_id: grant.grant_id,
                template: template.clone(),
                template_hash: canonical_hash(&template).unwrap(),
                evidence_root: digest("evidence"),
                principals: vec!["principal:review".to_owned()],
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
                transaction_id,
                SignedAuthorization {
                    authorization,
                    cose_sign1,
                },
                signer.key_id().to_owned(),
                signer.public_key_bytes(),
            )
            .unwrap();
            store.record_issued_authorization(&issued).unwrap();
            let key = ConsumeKey {
                scope: scope.clone(),
                transaction_id,
                authorization_id,
            };
            store.consume(&key).unwrap();
            Self {
                store,
                clock,
                scope,
                authority,
                grant_id: grant.grant_id,
                key,
                template,
            }
        }
    }

    fn digest(label: &str) -> Digest32 {
        Digest32::sha256(label.as_bytes())
    }

    fn domain(label: &str, epoch: u64) -> AuthorityDomainState {
        AuthorityDomainState {
            root: digest(label),
            epoch,
            activation_id: uuid::Uuid::new_v4(),
        }
    }

    fn authority() -> AuthorityVector {
        AuthorityVector {
            policy: domain("policy", 1),
            registry: domain("registry", 1),
            revocation: domain("revocation", 1),
            connector: domain("connector", 1),
            resource: domain("resource", 1),
            signer: domain("signer", 1),
            mediation: domain("mediation", 1),
            grant_registry: domain("grant", 1),
            office_act_registry: domain("office", 1),
            principal_registry: domain("principal", 1),
            workload_build_allowlist: domain("build", 1),
            kernel_configuration: domain("kernel", 1),
        }
    }

    fn template() -> DeploymentTemplate {
        DeploymentTemplate {
            operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
            environment: "prod".to_owned(),
            audience: "accordlock-executor:prod".to_owned(),
            repository: "acme/payments".to_owned(),
            commit_sha: "1".repeat(40),
            image_repository: "registry.example/acme/payments".to_owned(),
            image_digest: digest("new-image"),
            cluster_identity: "cluster-a".to_owned(),
            namespace: "payments".to_owned(),
            deployment: "payments".to_owned(),
            deployment_uid: "deployment-uid".to_owned(),
            container: "app".to_owned(),
            container_index: 0,
            prior_image_digest: digest("old-image"),
            resource_version: "1001".to_owned(),
            prior_projection_hash: digest("prior-projection"),
            prior_transaction_annotation: Some("unset".to_owned()),
            prior_authorization_annotation: Some("unset".to_owned()),
            prior_operation_hash_annotation: Some("unset".to_owned()),
        }
    }

    fn credential_profile() -> CredentialProfile {
        CredentialProfile {
            token_subject: "system:serviceaccount:payments:accordlock-attempt".to_owned(),
            token_audience: "https://kubernetes.default.svc".to_owned(),
            effective_rbac_commitment: [0x41; 32],
        }
    }

    fn physical(api_server_identity: &str) -> PhysicalResourceId {
        PhysicalResourceId {
            cluster_trust_domain: "cluster-a".to_owned(),
            api_server_identity: api_server_identity.to_owned(),
            namespace: "payments".to_owned(),
            deployment_uid: "deployment-uid".to_owned(),
        }
    }

    fn machine(fixture: &Fixture, routes: &[&str]) -> DispatchMachine {
        let mut machine = DispatchMachine::new(
            DispatchBounds {
                max_dispatch_delay_s: 30,
                token_lifetime_upper_bound_s: 60,
                clock_uncertainty_s: 0,
                minimum_remaining_lifetime_s: 1,
                lease_ttl_s: 20,
            },
            authority_version_from_vector(&fixture.authority).unwrap(),
            100,
        )
        .unwrap();
        for route in routes {
            machine
                .register_destination(
                    physical(route),
                    LogicalOwner {
                        tenant: fixture.scope.tenant.clone(),
                        environment: fixture.scope.environment.clone(),
                    },
                    credential_profile(),
                )
                .unwrap();
        }
        machine
    }

    fn acquire_work(fixture: &Fixture, acquisition_id: u128, worker: &str) -> DispatchWork {
        let request =
            DispatchAcquisitionRequest::new(worker, uuid::Uuid::from_u128(acquisition_id)).unwrap();
        match fixture
            .store
            .claim_next_pending_dispatch_or_recover(&fixture.scope, &request)
            .unwrap()
        {
            DispatchAcquisitionOutcome::Acquired(work)
            | DispatchAcquisitionOutcome::Recovered(work) => work,
            outcome => panic!("expected productive acquisition, got {outcome:?}"),
        }
    }

    fn revoke(fixture: &Fixture) {
        let mut revoked = fixture.authority.clone();
        revoked.revocation.epoch += 1;
        revoked.revocation.activation_id = uuid::Uuid::new_v4();
        revoked.revocation.root = grant_revocation_root(fixture.grant_id);
        fixture
            .store
            .revoke_grant(
                &fixture.scope,
                fixture.grant_id,
                &fixture.authority,
                &revoked,
            )
            .unwrap();
    }

    fn import(machine: &mut DispatchMachine, fixture: &Fixture, claim_id: u128) -> DispatchImport {
        machine
            .import_acquired_dispatch(acquire_work(fixture, claim_id, "worker-a"))
            .unwrap()
    }

    fn matching_observation(import: &DispatchImport) -> BoundObjectObservation {
        let effect = import.consumption().effect;
        BoundObjectObservation::Matching(Box::new(PreparedExecution {
            bound_object_uid: "bound-object-uid".to_owned(),
            template_hash: effect.template_hash,
            operation_hash: effect.operation_hash,
            token_subject: credential_profile().token_subject,
            token_audience: credential_profile().token_audience,
            effective_rbac_commitment: credential_profile().effective_rbac_commitment,
            execution_command_commitment: effect.execution_command_commitment,
            final_wire_commitment: effect.final_wire_commitment,
        }))
    }

    fn returned_credential() -> CredentialClaims {
        CredentialClaims {
            token_digest: [0x91; 32],
            subject: credential_profile().token_subject,
            audience: credential_profile().token_audience,
            service_account_uid: "service-account-uid".to_owned(),
            credential_id: "AUTHORIZATION_ID=7ee52be0-9045-4653-aa5e-0da57b8dccdc".to_owned(),
            bound_object_uid: "bound-object-uid".to_owned(),
            not_before: 102,
            expires_at: 120,
        }
    }

    fn lifecycle_policy() -> EksCredentialLifecyclePolicy {
        EksCredentialLifecyclePolicy::new(60, 600, 0, 60).unwrap()
    }

    fn stage_credential_prepared(
        machine: &mut DispatchMachine,
        fixture: &Fixture,
        import: &DispatchImport,
    ) -> DispatchClaim {
        let claim = machine.prepare_claimed_dispatch(import).unwrap();
        fixture.clock.set(101);
        machine
            .begin_bound_object_create_from_state(&fixture.store, import, &claim)
            .unwrap();
        machine
            .resolve_bound_object(
                import.transaction_id(),
                &claim,
                101,
                matching_observation(import),
            )
            .unwrap();
        claim
    }

    fn stage_credential_issuing(
        machine: &mut DispatchMachine,
        fixture: &Fixture,
        import: &DispatchImport,
    ) -> DispatchClaim {
        let claim = stage_credential_prepared(machine, fixture, import);
        fixture.clock.set(102);
        machine
            .begin_credential_issue_from_state(&fixture.store, import, &claim)
            .unwrap();
        claim
    }

    fn stage_credential_ready(
        machine: &mut DispatchMachine,
        fixture: &Fixture,
        import: &DispatchImport,
    ) -> DispatchClaim {
        let claim = stage_credential_issuing(machine, fixture, import);
        fixture.clock.set(103);
        machine
            .record_credential_result_from_state(
                &fixture.store,
                import,
                &claim,
                &returned_credential(),
            )
            .unwrap();
        claim
    }

    fn effect_binding(import: &DispatchImport) -> EffectBinding {
        let effect = import.consumption().effect;
        EffectBinding {
            template_hash: effect.template_hash,
            operation_hash: effect.operation_hash,
            execution_command_commitment: effect.execution_command_commitment,
            final_wire_commitment: effect.final_wire_commitment,
            effective_rbac_commitment: credential_profile().effective_rbac_commitment,
            token_digest: [0x91; 32],
        }
    }

    #[test]
    fn exact_claimed_path_returns_one_shot_provider_authority() {
        let fixture = Fixture::new();
        let mut machine = machine(&fixture, &["sha256:api-a"]);
        let import = import(&mut machine, &fixture, 0xc1);
        let prepared = prepare_patch(
            &fixture.template,
            fixture.key.transaction_id,
            fixture.key.authorization_id,
        )
        .unwrap();
        assert_eq!(
            import.consumption().effect.execution_command_commitment,
            *prepared.execution_command_commitment.as_bytes()
        );
        assert_eq!(
            import.consumption().effect.final_wire_commitment,
            *prepared.final_wire_commitment.as_bytes()
        );

        let claim = stage_credential_ready(&mut machine, &fixture, &import);
        let transaction_id = import.transaction_id();
        let expected_physical = import.physical().clone();
        let expected_binding = effect_binding(&import);
        let acquisition_id = import.acquisition_authority().acquisition_id();
        let acquisition_fence = import.acquisition_authority().lease_fence();
        let acquisition_lease_until = import.acquisition_authority().lease_until();
        let expected_dispatch_deadline = fixture
            .store
            .revalidate_dispatch_acquisition(import.acquisition_authority())
            .unwrap()
            .receipt()
            .dispatch_deadline;
        fixture.clock.set(104);
        let authorized = machine
            .authorize_provider_attempt_from_state(
                &fixture.store,
                import,
                &claim,
                &expected_binding,
                lifecycle_policy(),
                [0x72; 32],
            )
            .unwrap();
        assert_eq!(authorized.transaction_id(), transaction_id);
        assert_eq!(authorized.physical(), &expected_physical);
        assert_eq!(authorized.binding(), &expected_binding);
        assert_eq!(authorized.acquisition().acquisition_id(), acquisition_id);
        assert_eq!(authorized.acquisition().lease_fence(), acquisition_fence);
        assert_eq!(
            authorized.acquisition().lease_until(),
            acquisition_lease_until
        );
        assert_eq!(authorized.started_at(), 104);
        assert_eq!(authorized.dispatch_deadline(), expected_dispatch_deadline);
        assert_eq!(authorized.token_not_before(), 102);
        assert_eq!(authorized.token_expires_at(), 120);
        assert_eq!(authorized.service_account_uid(), "service-account-uid");
        assert_eq!(
            authorized.credential_id(),
            "AUTHORIZATION_ID=7ee52be0-9045-4653-aa5e-0da57b8dccdc"
        );
        assert_eq!(
            machine.phase(transaction_id).unwrap(),
            LifecyclePhase::Executing
        );
        let retry = DispatchAcquisitionRequest::new("worker-a", acquisition_id).unwrap();
        assert!(matches!(
            fixture
                .store
                .claim_next_pending_dispatch_or_recover(&fixture.scope, &retry),
            Ok(DispatchAcquisitionOutcome::Quarantined(_))
        ));
    }

    #[test]
    fn exact_retry_recovers_only_the_same_acquisition_generation() {
        let fixture = Fixture::new();
        let mut first = machine(&fixture, &["sha256:api-a"]);
        let mut second = machine(&fixture, &["sha256:api-a"]);
        let imported = first
            .import_acquired_dispatch(acquire_work(&fixture, 0xc2, "worker-a"))
            .unwrap();
        let recovered = second
            .import_acquired_dispatch(acquire_work(&fixture, 0xc2, "worker-a"))
            .unwrap();
        assert_eq!(
            imported.acquisition_authority().acquisition_id(),
            recovered.acquisition_authority().acquisition_id()
        );
        assert_eq!(
            imported.acquisition_authority().lease_fence(),
            recovered.acquisition_authority().lease_fence()
        );
        let distinct = DispatchAcquisitionRequest::new("worker-b", Uuid::from_u128(0xc3)).unwrap();
        assert!(matches!(
            fixture
                .store
                .claim_next_pending_dispatch_or_recover(&fixture.scope, &distinct),
            Ok(DispatchAcquisitionOutcome::NoWork)
        ));
        assert!(
            fixture
                .store
                .revalidate_dispatch_acquisition(imported.acquisition_authority())
                .is_ok()
        );
        assert!(
            fixture
                .store
                .revalidate_dispatch_acquisition(recovered.acquisition_authority())
                .is_ok()
        );
    }

    #[test]
    fn import_rejects_zero_or_ambiguous_registered_routes_after_burning_claim() {
        let absent_fixture = Fixture::new_with_ids(0x311, 0x411);
        let mut absent = machine(&absent_fixture, &[]);
        assert!(matches!(
            absent.import_acquired_dispatch(acquire_work(&absent_fixture, 0xc4, "worker-a")),
            Err(BridgeError::Dispatch(DispatchError::RegistrationMismatch))
        ));

        let ambiguous_fixture = Fixture::new_with_ids(0x312, 0x412);
        let mut ambiguous = machine(&ambiguous_fixture, &["sha256:api-a", "sha256:api-b"]);
        assert!(matches!(
            ambiguous.import_acquired_dispatch(acquire_work(&ambiguous_fixture, 0xc5, "worker-a",)),
            Err(BridgeError::Dispatch(DispatchError::AliasConflict))
        ));
    }

    #[test]
    fn revocation_and_deadline_block_create_before_local_transition() {
        let revoked = Fixture::new_with_ids(0x321, 0x421);
        let mut revoked_machine = machine(&revoked, &["sha256:api-a"]);
        let revoked_import = import(&mut revoked_machine, &revoked, 0xc6);
        let revoked_claim = revoked_machine
            .prepare_claimed_dispatch(&revoked_import)
            .unwrap();
        revoke(&revoked);
        revoked.clock.set(101);
        assert!(matches!(
            revoked_machine.begin_bound_object_create_from_state(
                &revoked.store,
                &revoked_import,
                &revoked_claim,
            ),
            Err(BridgeError::State(
                StateError::AuthorityMismatch | StateError::GrantRevoked
            ))
        ));
        assert_eq!(
            revoked_machine
                .phase(revoked_import.transaction_id())
                .unwrap(),
            LifecyclePhase::BoundObjectCreatePending
        );

        let expired = Fixture::new_with_ids(0x322, 0x422);
        let mut expired_machine = machine(&expired, &["sha256:api-a"]);
        let expired_import = import(&mut expired_machine, &expired, 0xc7);
        let expired_claim = expired_machine
            .prepare_claimed_dispatch(&expired_import)
            .unwrap();
        expired.clock.set(130);
        assert!(matches!(
            expired_machine.begin_bound_object_create_from_state(
                &expired.store,
                &expired_import,
                &expired_claim,
            ),
            Err(BridgeError::State(
                StateError::DispatchClaimLeaseExpired { .. }
                    | StateError::DispatchDeadlineExpired { .. }
            ))
        ));
        assert_eq!(
            expired_machine
                .phase(expired_import.transaction_id())
                .unwrap(),
            LifecyclePhase::BoundObjectCreatePending
        );
    }

    #[test]
    fn revocation_and_deadline_block_token_request_before_local_transition() {
        let revoked = Fixture::new_with_ids(0x331, 0x431);
        let mut revoked_machine = machine(&revoked, &["sha256:api-a"]);
        let revoked_import = import(&mut revoked_machine, &revoked, 0xc8);
        let revoked_claim =
            stage_credential_prepared(&mut revoked_machine, &revoked, &revoked_import);
        revoke(&revoked);
        revoked.clock.set(102);
        assert!(matches!(
            revoked_machine.begin_credential_issue_from_state(
                &revoked.store,
                &revoked_import,
                &revoked_claim,
            ),
            Err(BridgeError::State(
                StateError::AuthorityMismatch | StateError::GrantRevoked
            ))
        ));
        assert_eq!(
            revoked_machine
                .phase(revoked_import.transaction_id())
                .unwrap(),
            LifecyclePhase::CredentialPrepared
        );

        let expired = Fixture::new_with_ids(0x332, 0x432);
        let mut expired_machine = machine(&expired, &["sha256:api-a"]);
        let expired_import = import(&mut expired_machine, &expired, 0xc9);
        let expired_claim =
            stage_credential_prepared(&mut expired_machine, &expired, &expired_import);
        expired.clock.set(130);
        assert!(matches!(
            expired_machine.begin_credential_issue_from_state(
                &expired.store,
                &expired_import,
                &expired_claim,
            ),
            Err(BridgeError::State(
                StateError::DispatchClaimLeaseExpired { .. }
                    | StateError::DispatchDeadlineExpired { .. }
            ))
        ));
        assert_eq!(
            expired_machine
                .phase(expired_import.transaction_id())
                .unwrap(),
            LifecyclePhase::CredentialPrepared
        );
    }

    #[test]
    fn revoked_during_token_request_retains_credential_for_invalidation() {
        let fixture = Fixture::new_with_ids(0x341, 0x441);
        let mut machine = machine(&fixture, &["sha256:api-a"]);
        let import = import(&mut machine, &fixture, 0xca);
        let claim = stage_credential_issuing(&mut machine, &fixture, &import);
        revoke(&fixture);
        fixture.clock.set(103);
        assert!(matches!(
            machine.record_credential_result_from_state(
                &fixture.store,
                &import,
                &claim,
                &returned_credential(),
            ),
            Err(BridgeError::State(
                StateError::AuthorityMismatch | StateError::GrantRevoked
            ))
        ));
        assert_eq!(
            machine.phase(import.transaction_id()).unwrap(),
            LifecyclePhase::CredentialInvalidating
        );

        let effect = import.consumption().effect;
        machine
            .confirm_credential_invalidation(
                import.transaction_id(),
                &crate::CredentialInvalidationEvidence {
                    transaction_id: import.transaction_id(),
                    physical: import.physical().clone(),
                    bound_object_name: claim.bound_object_name.clone(),
                    bound_object_uid: "bound-object-uid".to_owned(),
                    token_digest: Some([0x91; 32]),
                    template_hash: effect.template_hash,
                    operation_hash: effect.operation_hash,
                    execution_command_commitment: effect.execution_command_commitment,
                    final_wire_commitment: effect.final_wire_commitment,
                    effective_rbac_commitment: credential_profile().effective_rbac_commitment,
                    evidence_commitment: [0x71; 32],
                },
                104,
            )
            .unwrap();
        assert_eq!(
            machine.finish_quarantined_credential(import.transaction_id(), 161),
            Err(DispatchError::CredentialStillLive)
        );
        machine
            .finish_quarantined_credential(import.transaction_id(), 162)
            .unwrap();
    }

    #[cfg(any())]
    #[test]
    fn foreign_token_or_forged_claim_cannot_cancel_the_victim() {
        let victim = Fixture::new_with_ids(0x351, 0x451);
        let attacker = Fixture::new_with_ids(0x352, 0x452);
        let mut victim_machine = machine(&victim, &["sha256:api-a"]);
        let mut attacker_machine = machine(&attacker, &["sha256:api-a"]);
        let victim_import = import(&mut victim_machine, &victim, 0xcb);
        let attacker_import = import(&mut attacker_machine, &attacker, 0xcc);
        let victim_claim = stage_credential_ready(&mut victim_machine, &victim, &victim_import);

        assert!(matches!(
            victim_machine.authorize_provider_attempt_from_state(
                &attacker.store,
                victim_import.token(),
                &victim_claim,
                &effect_binding(&victim_import),
            ),
            Err(BridgeError::State(StateError::DispatchClaimMismatch))
        ));
        assert_eq!(
            victim_machine
                .phase(victim_import.transaction_id())
                .unwrap(),
            LifecyclePhase::CredentialReady
        );

        assert!(matches!(
            victim_machine.authorize_provider_attempt_from_state(
                &attacker.store,
                attacker_import.token(),
                &victim_claim,
                &effect_binding(&victim_import),
            ),
            Err(BridgeError::SnapshotMismatch)
        ));
        assert!(
            attacker
                .store
                .revalidate_dispatch_claim(attacker_import.token())
                .is_ok()
        );

        let mut forged = victim_claim.clone();
        forged.consumption.authorization_hash = [0x99; 32];
        assert!(matches!(
            victim_machine.authorize_provider_attempt_from_state(
                &victim.store,
                victim_import.token(),
                &forged,
                &effect_binding(&victim_import),
            ),
            Err(BridgeError::SnapshotMismatch)
        ));
        assert_eq!(
            victim_machine
                .phase(victim_import.transaction_id())
                .unwrap(),
            LifecyclePhase::CredentialReady
        );
    }

    #[test]
    fn revoke_or_deadline_after_ready_forces_credential_invalidation() {
        let revoked = Fixture::new_with_ids(0x361, 0x461);
        let mut revoked_machine = machine(&revoked, &["sha256:api-a"]);
        let revoked_import = import(&mut revoked_machine, &revoked, 0xcd);
        let revoked_claim = stage_credential_ready(&mut revoked_machine, &revoked, &revoked_import);
        revoke(&revoked);
        revoked.clock.set(104);
        assert!(matches!(
            revoked_machine.authorize_provider_attempt_from_state(
                &revoked.store,
                revoked_import.token(),
                &revoked_claim,
                &effect_binding(&revoked_import),
            ),
            Err(BridgeError::State(
                StateError::AuthorityMismatch | StateError::GrantRevoked
            ))
        ));
        assert_eq!(
            revoked_machine
                .phase(revoked_import.transaction_id())
                .unwrap(),
            LifecyclePhase::CredentialInvalidating
        );

        let expired = Fixture::new_with_ids(0x362, 0x462);
        let mut expired_machine = machine(&expired, &["sha256:api-a"]);
        let expired_import = import(&mut expired_machine, &expired, 0xce);
        let expired_claim = stage_credential_ready(&mut expired_machine, &expired, &expired_import);
        expired.clock.set(130);
        assert!(matches!(
            expired_machine.authorize_provider_attempt_from_state(
                &expired.store,
                expired_import.token(),
                &expired_claim,
                &effect_binding(&expired_import),
            ),
            Err(BridgeError::State(
                StateError::DispatchClaimLeaseExpired { .. }
                    | StateError::DispatchDeadlineExpired { .. }
            ))
        ));
        assert_eq!(
            expired_machine
                .phase(expired_import.transaction_id())
                .unwrap(),
            LifecyclePhase::CredentialInvalidating
        );
    }

    #[test]
    fn tuple_commitment_is_deterministic_and_authority_sum_is_checked() {
        let fixture = Fixture::new();
        let first = fixture.store.dispatch_snapshot(&fixture.key).unwrap();
        let first_commitment = consumption_tuple_commitment(&first).unwrap();
        fixture.clock.set(101);
        let second = fixture.store.dispatch_snapshot(&fixture.key).unwrap();
        assert_eq!(
            first_commitment,
            consumption_tuple_commitment(&second).unwrap()
        );
        assert_ne!(first.checked_at(), second.checked_at());

        let mut overflowing = authority();
        overflowing.policy.epoch = u64::MAX;
        overflowing.registry.epoch = 1;
        assert!(matches!(
            authority_version_from_vector(&overflowing),
            Err(BridgeError::AuthorityEpochOverflow)
        ));
    }
}
