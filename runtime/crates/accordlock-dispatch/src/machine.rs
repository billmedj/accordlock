use std::collections::{BTreeMap, BTreeSet};

use accordlock_state::DispatchClaimToken;
use uuid::Uuid;

use crate::model::{
    AuthorityVersion, BoundObjectObservation, ConsumptionBinding, CredentialClaims,
    CredentialInvalidationEvidence, CredentialProfile, DispatchBounds, DispatchClaim,
    DispatchError, EffectBinding, EffectEvidenceSnapshot, EffectTemplate, ExactEffectEvidence,
    LifecyclePhase, LogicalOwner, NonIssuanceEvidence, PhysicalResourceId, PreparedExecution,
    ProviderOutcome, ReconciliationOutcome,
};

#[derive(Clone, Debug)]
struct Lease {
    worker: String,
    fence: u64,
    expires_at: i64,
}

#[derive(Clone, Debug)]
struct Attempt {
    owner: LogicalOwner,
    physical: PhysicalResourceId,
    consumed_authority: AuthorityVersion,
    consumption: ConsumptionBinding,
    emergency_generation: u64,
    dispatch_deadline: i64,
    phase: LifecyclePhase,
    reservation_generation: Option<u64>,
    lease: Option<Lease>,
    bound_object_name: Option<String>,
    bound_object_uid: Option<String>,
    prepared_execution: Option<PreparedExecution>,
    issue_started_at: Option<i64>,
    token_digest: Option<[u8; 32]>,
    token_not_before: Option<i64>,
    token_expires_at: Option<i64>,
    service_account_uid: Option<String>,
    credential_id: Option<String>,
    credential_safe_after: Option<i64>,
    invalidation_confirmed: bool,
    provider_attempt_started_at: Option<i64>,
    reconciliation_started_at: Option<i64>,
    effect_evidence_commitment: Option<[u8; 32]>,
    dispatch_claim_token: Option<DispatchClaimToken>,
}

#[derive(Clone, Debug)]
struct Reservation {
    transaction_id: Uuid,
    generation: u64,
}

#[derive(Clone, Debug)]
struct DestinationRegistration {
    owner: LogicalOwner,
    credential: CredentialProfile,
}

#[derive(Debug)]
pub(crate) struct CredentialAuthorityFacts {
    pub(crate) token_digest: [u8; 32],
    pub(crate) not_before: i64,
    pub(crate) expires_at: i64,
    pub(crate) service_account_uid: String,
    pub(crate) credential_id: String,
}

/// Deterministic in-memory oracle for dispatch lifecycle rules.
#[derive(Debug)]
pub struct DispatchMachine {
    bounds: DispatchBounds,
    active_authority: AuthorityVersion,
    emergency_stop: bool,
    emergency_generation: u64,
    high_water_time: i64,
    registrations: BTreeMap<PhysicalResourceId, DestinationRegistration>,
    attempts: BTreeMap<Uuid, Attempt>,
    consumed_authorization_ids: BTreeSet<Uuid>,
    consumed_authorization_hashes: BTreeSet<[u8; 32]>,
    consumed_receipts: BTreeSet<[u8; 32]>,
    reservations: BTreeMap<PhysicalResourceId, Reservation>,
    reservation_generations: BTreeMap<PhysicalResourceId, u64>,
    next_fence: u64,
    bridge_owner: Option<LogicalOwner>,
}

impl DispatchMachine {
    /// Creates a reference machine with trusted initial authority and time.
    ///
    /// # Errors
    ///
    /// Returns an error when a duration or the initial time is invalid.
    pub fn new(
        bounds: DispatchBounds,
        active_authority: AuthorityVersion,
        initial_time: i64,
    ) -> Result<Self, DispatchError> {
        let bounds = bounds.validate()?;
        if initial_time < 0 {
            return Err(DispatchError::InvalidTime);
        }
        Ok(Self {
            bounds,
            active_authority,
            emergency_stop: false,
            emergency_generation: 0,
            high_water_time: initial_time,
            registrations: BTreeMap::new(),
            attempts: BTreeMap::new(),
            consumed_authorization_ids: BTreeSet::new(),
            consumed_authorization_hashes: BTreeSet::new(),
            consumed_receipts: BTreeSet::new(),
            reservations: BTreeMap::new(),
            reservation_generations: BTreeMap::new(),
            next_fence: 0,
            bridge_owner: None,
        })
    }

    /// Registers an injective owner mapping for a physical resource.
    ///
    /// Repeating the same mapping is idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`DispatchError::AliasConflict`] for another active owner.
    pub fn register_destination(
        &mut self,
        physical: PhysicalResourceId,
        owner: LogicalOwner,
        credential: CredentialProfile,
    ) -> Result<(), DispatchError> {
        if !Self::valid_identity_component(&physical.cluster_trust_domain, 512)
            || !Self::valid_identity_component(&physical.api_server_identity, 512)
            || !Self::valid_identity_component(&physical.namespace, 253)
            || !Self::valid_identity_component(&physical.deployment_uid, 512)
            || !Self::valid_identity_component(&owner.tenant, 253)
            || !Self::valid_identity_component(&owner.environment, 253)
            || !Self::valid_identity_component(&credential.token_subject, 512)
            || !Self::valid_identity_component(&credential.token_audience, 512)
            || credential.effective_rbac_commitment == [0; 32]
        {
            return Err(DispatchError::InvalidIdentity);
        }
        if let Some(current) = self.registrations.get(&physical) {
            if current.owner != owner || current.credential != credential {
                return Err(DispatchError::AliasConflict);
            }
            return Ok(());
        }
        self.registrations
            .insert(physical, DestinationRegistration { owner, credential });
        Ok(())
    }

    /// Activates an authority version monotonically; identical replay is
    /// idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`DispatchError::AuthorityRollback`] for an older epoch or a
    /// conflicting root at the current epoch.
    pub fn activate_authority(&mut self, authority: AuthorityVersion) -> Result<(), DispatchError> {
        if authority == self.active_authority {
            return Ok(());
        }
        if authority.epoch <= self.active_authority.epoch {
            return Err(DispatchError::AuthorityRollback);
        }
        self.active_authority = authority;
        Ok(())
    }

    /// Activates or clears the emergency-stop level.
    ///
    /// Each inactive-to-active transition increments a generation, so clearing
    /// the level does not resurrect attempts prepared before the stop.
    ///
    /// # Errors
    ///
    /// Returns an error if the monotone generation overflows.
    pub fn set_emergency_stop(&mut self, active: bool) -> Result<(), DispatchError> {
        if active && !self.emergency_stop {
            self.emergency_generation = self
                .emergency_generation
                .checked_add(1)
                .ok_or(DispatchError::ArithmeticOverflow)?;
        }
        self.emergency_stop = active;
        Ok(())
    }

    /// Imports an authorization-consumption result from the authority transaction.
    ///
    /// # Errors
    ///
    /// Returns an error for a duplicate transaction, registration mismatch,
    /// non-monotone time, or empty dispatch interval.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_consumption(
        &mut self,
        transaction_id: Uuid,
        owner: LogicalOwner,
        physical: PhysicalResourceId,
        authority: AuthorityVersion,
        consumption: ConsumptionBinding,
        consumed_at: i64,
        dispatch_deadline: i64,
    ) -> Result<(), DispatchError> {
        self.record_consumption_inner(
            transaction_id,
            owner,
            physical,
            authority,
            consumption,
            consumed_at,
            consumed_at,
            dispatch_deadline,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_consumption_from_snapshot(
        &mut self,
        transaction_id: Uuid,
        owner: LogicalOwner,
        physical: PhysicalResourceId,
        authority: AuthorityVersion,
        consumption: ConsumptionBinding,
        consumed_at: i64,
        checked_at: i64,
        dispatch_deadline: i64,
    ) -> Result<(), DispatchError> {
        self.record_consumption_inner(
            transaction_id,
            owner,
            physical,
            authority,
            consumption,
            consumed_at,
            checked_at,
            dispatch_deadline,
        )
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn record_consumption_inner(
        &mut self,
        transaction_id: Uuid,
        owner: LogicalOwner,
        physical: PhysicalResourceId,
        authority: AuthorityVersion,
        consumption: ConsumptionBinding,
        consumed_at: i64,
        observed_at: i64,
        dispatch_deadline: i64,
    ) -> Result<(), DispatchError> {
        self.validate_time(observed_at)?;
        if consumed_at > observed_at || dispatch_deadline <= observed_at {
            return Err(DispatchError::DeadlineExpired);
        }
        let maximum_deadline = consumed_at
            .checked_add(self.bounds.max_dispatch_delay_s)
            .ok_or(DispatchError::ArithmeticOverflow)?;
        if dispatch_deadline > maximum_deadline {
            return Err(DispatchError::DeadlineExpired);
        }
        if transaction_id.is_nil() {
            return Err(DispatchError::InvalidIdentity);
        }
        if self.attempts.contains_key(&transaction_id) {
            return Err(DispatchError::DuplicateTransaction);
        }
        if self
            .consumed_authorization_ids
            .contains(&consumption.authorization_id)
            || self
                .consumed_authorization_hashes
                .contains(&consumption.authorization_hash)
            || self
                .consumed_receipts
                .contains(&consumption.receipt_commitment)
        {
            return Err(DispatchError::ConsumptionReplay);
        }
        if self
            .registrations
            .get(&physical)
            .map(|registration| &registration.owner)
            != Some(&owner)
        {
            return Err(DispatchError::RegistrationMismatch);
        }
        if authority != self.active_authority {
            return Err(DispatchError::AuthorityChanged);
        }
        Self::validate_consumption_binding(consumption)?;
        self.consumed_authorization_ids
            .insert(consumption.authorization_id);
        self.consumed_authorization_hashes
            .insert(consumption.authorization_hash);
        self.consumed_receipts
            .insert(consumption.receipt_commitment);
        self.attempts.insert(
            transaction_id,
            Attempt {
                owner,
                physical,
                consumed_authority: authority,
                consumption,
                emergency_generation: self.emergency_generation,
                dispatch_deadline,
                phase: LifecyclePhase::Consumed,
                reservation_generation: None,
                lease: None,
                bound_object_name: None,
                bound_object_uid: None,
                prepared_execution: None,
                issue_started_at: None,
                token_digest: None,
                token_not_before: None,
                token_expires_at: None,
                service_account_uid: None,
                credential_id: None,
                credential_safe_after: None,
                invalidation_confirmed: false,
                provider_attempt_started_at: None,
                reconciliation_started_at: None,
                effect_evidence_commitment: None,
                dispatch_claim_token: None,
            },
        );
        self.commit_time(observed_at);
        Ok(())
    }

    /// Acquires the physical reservation, lease, fence, and create intent.
    ///
    /// # Errors
    ///
    /// Returns an error for stale authority/time, emergency stop, expiry,
    /// registration mismatch, invalid phase, or a busy reservation.
    pub fn prepare_dispatch(
        &mut self,
        transaction_id: Uuid,
        worker: &str,
        now: i64,
    ) -> Result<DispatchClaim, DispatchError> {
        if !Self::valid_identity_component(worker, 253) {
            return Err(DispatchError::InvalidIdentity);
        }
        self.validate_time(now)?;
        let snapshot = self.attempt(transaction_id)?.clone();
        if !matches!(
            snapshot.phase,
            LifecyclePhase::Consumed | LifecyclePhase::DispatchWaitingResource
        ) {
            return Err(DispatchError::InvalidTransition);
        }
        self.require_authority(&snapshot)?;
        self.require_live_dispatch(&snapshot, now)?;
        if self
            .registrations
            .get(&snapshot.physical)
            .map(|registration| &registration.owner)
            != Some(&snapshot.owner)
        {
            return Err(DispatchError::RegistrationMismatch);
        }
        if let Some(reservation) = self.reservations.get(&snapshot.physical) {
            if reservation.transaction_id != transaction_id {
                self.attempt_mut(transaction_id)?.phase = LifecyclePhase::DispatchWaitingResource;
                self.commit_time(now);
                return Err(DispatchError::ResourceBusy);
            }
            return Err(DispatchError::InvalidTransition);
        }

        let generation = self
            .reservation_generations
            .get(&snapshot.physical)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(DispatchError::ArithmeticOverflow)?;
        let fence = self
            .next_fence
            .checked_add(1)
            .ok_or(DispatchError::ArithmeticOverflow)?;
        let expires_at = now
            .checked_add(self.bounds.lease_ttl_s)
            .ok_or(DispatchError::ArithmeticOverflow)?;
        let bound_object_name = format!("accordlock-{}", transaction_id.simple());

        self.next_fence = fence;
        self.reservation_generations
            .insert(snapshot.physical.clone(), generation);
        self.reservations.insert(
            snapshot.physical.clone(),
            Reservation {
                transaction_id,
                generation,
            },
        );
        {
            let attempt = self.attempt_mut(transaction_id)?;
            attempt.phase = LifecyclePhase::BoundObjectCreatePending;
            attempt.reservation_generation = Some(generation);
            attempt.bound_object_name = Some(bound_object_name.clone());
            attempt.lease = Some(Lease {
                worker: worker.to_owned(),
                fence,
                expires_at,
            });
        }
        let claim = DispatchClaim {
            transaction_id,
            physical: snapshot.physical,
            consumption: snapshot.consumption,
            worker: worker.to_owned(),
            fence,
            reservation_generation: generation,
            bound_object_name,
        };
        self.commit_time(now);
        Ok(claim)
    }

    /// Transfers an expired lease to a new worker with a higher fence.
    ///
    /// # Errors
    ///
    /// Returns an error when time is stale or the current lease still lives.
    pub fn take_over_expired_lease(
        &mut self,
        transaction_id: Uuid,
        new_worker: &str,
        now: i64,
    ) -> Result<DispatchClaim, DispatchError> {
        if !Self::valid_identity_component(new_worker, 253) {
            return Err(DispatchError::InvalidIdentity);
        }
        self.validate_time(now)?;
        let snapshot = self.attempt(transaction_id)?.clone();
        if !matches!(
            snapshot.phase,
            LifecyclePhase::BoundObjectCreatePending
                | LifecyclePhase::BoundObjectCreateUnknown
                | LifecyclePhase::BoundObjectReconciling
                | LifecyclePhase::CredentialPrepared
        ) {
            return Err(DispatchError::InvalidTransition);
        }
        if matches!(
            snapshot.phase,
            LifecyclePhase::BoundObjectCreatePending | LifecyclePhase::CredentialPrepared
        ) {
            if let Err(error) = self.require_authority(&snapshot) {
                self.cancel_release(transaction_id)?;
                self.commit_time(now);
                return Err(error);
            }
            if let Err(error) = self.require_live_dispatch(&snapshot, now) {
                self.cancel_release(transaction_id)?;
                self.commit_time(now);
                return Err(error);
            }
        }
        let current = snapshot.lease.as_ref().ok_or(DispatchError::StaleLease)?;
        if now < current.expires_at {
            return Err(DispatchError::StaleLease);
        }
        let fence = self
            .next_fence
            .checked_add(1)
            .ok_or(DispatchError::ArithmeticOverflow)?;
        let expires_at = now
            .checked_add(self.bounds.lease_ttl_s)
            .ok_or(DispatchError::ArithmeticOverflow)?;
        let reservation_generation = snapshot
            .reservation_generation
            .ok_or(DispatchError::InvalidTransition)?;
        let bound_object_name = snapshot
            .bound_object_name
            .clone()
            .ok_or(DispatchError::InvalidTransition)?;
        self.next_fence = fence;
        self.attempt_mut(transaction_id)?.lease = Some(Lease {
            worker: new_worker.to_owned(),
            fence,
            expires_at,
        });
        let claim = DispatchClaim {
            transaction_id,
            physical: snapshot.physical,
            consumption: snapshot.consumption,
            worker: new_worker.to_owned(),
            fence,
            reservation_generation,
            bound_object_name,
        };
        self.commit_time(now);
        Ok(claim)
    }

    /// Recovers a lease loss at a credential or effect ambiguity boundary.
    ///
    /// This method never creates a new lease or authorizes a retry. Issuance in
    /// flight becomes unknown, a ready token enters invalidation, and a
    /// released or executing effect becomes execution-unknown.
    ///
    /// # Errors
    ///
    /// Returns an error while the lease still lives or from a phase that may
    /// safely use ordinary fenced takeover instead.
    pub fn recover_expired_lease(
        &mut self,
        transaction_id: Uuid,
        now: i64,
    ) -> Result<(), DispatchError> {
        self.validate_time(now)?;
        let snapshot = self.attempt(transaction_id)?.clone();
        let lease = snapshot.lease.as_ref().ok_or(DispatchError::StaleLease)?;
        if now < lease.expires_at {
            return Err(DispatchError::StaleLease);
        }
        let next = match snapshot.phase {
            LifecyclePhase::BoundObjectCreateInFlight => LifecyclePhase::BoundObjectCreateUnknown,
            LifecyclePhase::CredentialIssuing => LifecyclePhase::CredentialIssueUnknown,
            LifecyclePhase::CredentialReady | LifecyclePhase::ReleaseCancelled => {
                LifecyclePhase::CredentialInvalidating
            }
            LifecyclePhase::EffectReleased | LifecyclePhase::Executing => {
                LifecyclePhase::ExecutionUnknown
            }
            _ => return Err(DispatchError::InvalidTransition),
        };
        let safe_after = if snapshot.credential_safe_after.is_some() {
            snapshot.credential_safe_after
        } else if snapshot.phase == LifecyclePhase::CredentialIssuing {
            Some(self.credential_safe_after(now)?)
        } else {
            None
        };
        let attempt = self.attempt_mut(transaction_id)?;
        attempt.phase = next;
        attempt.credential_safe_after = safe_after;
        self.commit_time(now);
        Ok(())
    }

    /// Records the local in-flight marker before any bound-object create
    /// request.
    ///
    /// A production caller must durably persist or reconstruct the equivalent
    /// state. This in-memory transition alone provides no crash recovery.
    ///
    /// # Errors
    ///
    /// Returns an error for stale time, worker, or prior phase.
    pub(crate) fn begin_bound_object_create(
        &mut self,
        transaction_id: Uuid,
        claim: &DispatchClaim,
        now: i64,
    ) -> Result<(), DispatchError> {
        self.validate_time(now)?;
        self.require_lease(transaction_id, claim, now)?;
        let snapshot = self.attempt(transaction_id)?.clone();
        if snapshot.phase != LifecyclePhase::BoundObjectCreatePending {
            return Err(DispatchError::InvalidTransition);
        }
        if let Err(error) = self.require_authority(&snapshot) {
            self.cancel_release(transaction_id)?;
            self.commit_time(now);
            return Err(error);
        }
        if let Err(error) = self.require_live_dispatch(&snapshot, now) {
            self.cancel_release(transaction_id)?;
            self.commit_time(now);
            return Err(error);
        }
        self.attempt_mut(transaction_id)?.phase = LifecyclePhase::BoundObjectCreateInFlight;
        self.commit_time(now);
        Ok(())
    }

    /// Records an indeterminate bound-object create response.
    ///
    /// # Errors
    ///
    /// Returns an error for stale time, worker, or prior phase.
    pub fn mark_bound_object_create_unknown(
        &mut self,
        transaction_id: Uuid,
        claim: &DispatchClaim,
        now: i64,
    ) -> Result<(), DispatchError> {
        self.transition_with_lease(
            transaction_id,
            claim,
            now,
            LifecyclePhase::BoundObjectCreateInFlight,
            LifecyclePhase::BoundObjectCreateUnknown,
        )
    }

    /// Begins reconciliation after an unknown create result.
    ///
    /// # Errors
    ///
    /// Returns an error for stale time, worker, or prior phase.
    pub fn begin_bound_object_reconciliation(
        &mut self,
        transaction_id: Uuid,
        claim: &DispatchClaim,
        now: i64,
    ) -> Result<(), DispatchError> {
        self.transition_with_lease(
            transaction_id,
            claim,
            now,
            LifecyclePhase::BoundObjectCreateUnknown,
            LifecyclePhase::BoundObjectReconciling,
        )
    }

    /// Resolves a bound-object observation without issuing a second create.
    ///
    /// # Errors
    ///
    /// Returns an error for stale worker/time or invalid prior phase.
    pub fn resolve_bound_object(
        &mut self,
        transaction_id: Uuid,
        claim: &DispatchClaim,
        now: i64,
        observation: BoundObjectObservation,
    ) -> Result<(), DispatchError> {
        self.validate_time(now)?;
        self.require_lease(transaction_id, claim, now)?;
        let snapshot = self.attempt(transaction_id)?.clone();
        if !matches!(
            snapshot.phase,
            LifecyclePhase::BoundObjectCreateInFlight | LifecyclePhase::BoundObjectReconciling
        ) {
            return Err(DispatchError::InvalidTransition);
        }
        let credential_profile = &self
            .registrations
            .get(&snapshot.physical)
            .ok_or(DispatchError::RegistrationMismatch)?
            .credential;
        match observation {
            BoundObjectObservation::Matching(prepared)
                if Self::valid_prepared_execution(
                    prepared.as_ref(),
                    snapshot.consumption.effect,
                    credential_profile,
                ) =>
            {
                let attempt = self.attempt_mut(transaction_id)?;
                attempt.bound_object_uid = Some(prepared.bound_object_uid.clone());
                attempt.prepared_execution = Some(*prepared);
                attempt.phase = LifecyclePhase::CredentialPrepared;
            }
            BoundObjectObservation::Absent | BoundObjectObservation::Conflicting => {
                self.attempt_mut(transaction_id)?.phase = LifecyclePhase::ManualResolutionRequired;
            }
            BoundObjectObservation::Matching(_) => {
                return Err(DispatchError::InvalidCommitment);
            }
        }
        self.commit_time(now);
        Ok(())
    }

    /// Records local `CREDENTIAL_PREPARED -> CREDENTIAL_ISSUING` before
    /// `TokenRequest`.
    ///
    /// # Errors
    ///
    /// Returns an error for stale lease/time, expiry, or invalid phase.
    pub(crate) fn begin_credential_issue(
        &mut self,
        transaction_id: Uuid,
        claim: &DispatchClaim,
        now: i64,
    ) -> Result<(), DispatchError> {
        self.validate_time(now)?;
        self.require_lease(transaction_id, claim, now)?;
        let snapshot = self.attempt(transaction_id)?.clone();
        if snapshot.phase != LifecyclePhase::CredentialPrepared
            || snapshot.bound_object_uid.is_none()
            || snapshot.prepared_execution.is_none()
        {
            return Err(DispatchError::InvalidTransition);
        }
        if let Err(error) = self.require_authority(&snapshot) {
            self.cancel_release(transaction_id)?;
            self.commit_time(now);
            return Err(error);
        }
        if let Err(error) = self.require_live_dispatch(&snapshot, now) {
            self.cancel_release(transaction_id)?;
            self.commit_time(now);
            return Err(error);
        }
        let attempt = self.attempt_mut(transaction_id)?;
        attempt.phase = LifecyclePhase::CredentialIssuing;
        attempt.issue_started_at = Some(now);
        self.commit_time(now);
        Ok(())
    }

    /// Records a lost or indeterminate token-issuance result without retry.
    ///
    /// # Errors
    ///
    /// Returns an error for stale lease/time, invalid phase, or overflow.
    pub fn mark_credential_issue_unknown(
        &mut self,
        transaction_id: Uuid,
        claim: &DispatchClaim,
        observed_at: i64,
    ) -> Result<(), DispatchError> {
        self.validate_time(observed_at)?;
        self.require_lease(transaction_id, claim, observed_at)?;
        let safe_after = self.credential_safe_after(observed_at)?;
        let attempt = self.attempt_mut(transaction_id)?;
        if attempt.phase != LifecyclePhase::CredentialIssuing {
            return Err(DispatchError::InvalidTransition);
        }
        attempt.phase = LifecyclePhase::CredentialIssueUnknown;
        attempt.credential_safe_after = Some(safe_after);
        self.commit_time(observed_at);
        Ok(())
    }

    /// Records validated token claims without retaining bearer bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for stale worker/time or invalid token bounds.
    pub(crate) fn record_credential_ready(
        &mut self,
        transaction_id: Uuid,
        claim: &DispatchClaim,
        observed_at: i64,
        claims: &CredentialClaims,
    ) -> Result<(), DispatchError> {
        self.validate_time(observed_at)?;
        self.require_lease(transaction_id, claim, observed_at)?;
        let snapshot = self.attempt(transaction_id)?.clone();
        if snapshot.phase != LifecyclePhase::CredentialIssuing {
            return Err(DispatchError::InvalidTransition);
        }
        let issue_started_at = snapshot
            .issue_started_at
            .ok_or(DispatchError::InvalidTransition)?;
        let prepared = snapshot
            .prepared_execution
            .as_ref()
            .ok_or(DispatchError::InvalidTransition)?;
        let issuer_bound = issue_started_at
            .checked_add(self.bounds.token_lifetime_upper_bound_s)
            .and_then(|value| value.checked_add(self.bounds.clock_uncertainty_s))
            .ok_or(DispatchError::ArithmeticOverflow)?;
        let earliest_not_before = issue_started_at
            .checked_sub(self.bounds.clock_uncertainty_s)
            .ok_or(DispatchError::ArithmeticOverflow)?;
        let actual_safe_after = claims
            .expires_at
            .checked_add(self.bounds.clock_uncertainty_s)
            .ok_or(DispatchError::ArithmeticOverflow)?;
        let safe_after = issuer_bound.max(actual_safe_after);
        let claims_invalid = claims.token_digest == [0; 32]
            || !Self::valid_identity_component(&claims.subject, 512)
            || !Self::valid_identity_component(&claims.audience, 512)
            || !Self::valid_identity_component(&claims.service_account_uid, 512)
            || !Self::valid_credential_id(&claims.credential_id)
            || claims.subject != prepared.token_subject
            || claims.audience != prepared.token_audience
            || claims.bound_object_uid != prepared.bound_object_uid
            || claims.not_before < earliest_not_before
            || claims.not_before > observed_at
            || claims.expires_at <= observed_at
            || claims.expires_at > issuer_bound;
        let authority_error = self.require_authority(&snapshot).err();
        let dispatch_error = self.require_live_dispatch(&snapshot, observed_at).err();
        let attempt = self.attempt_mut(transaction_id)?;
        attempt.token_digest = Some(claims.token_digest);
        attempt.token_not_before = Some(claims.not_before);
        attempt.token_expires_at = Some(claims.expires_at);
        attempt.service_account_uid = Some(claims.service_account_uid.clone());
        attempt.credential_id = Some(claims.credential_id.clone());
        attempt.credential_safe_after = Some(safe_after);
        if claims_invalid {
            attempt.phase = LifecyclePhase::CredentialInvalidating;
            self.commit_time(observed_at);
            return Err(DispatchError::InvalidCredential);
        }
        if let Some(error) = authority_error.or(dispatch_error) {
            attempt.phase = LifecyclePhase::CredentialInvalidating;
            self.commit_time(observed_at);
            return Err(error);
        }
        attempt.phase = LifecyclePhase::CredentialReady;
        self.commit_time(observed_at);
        Ok(())
    }

    /// Retains a returned bearer identity after durable state rejected the
    /// credential result.
    ///
    /// This path is deliberately state-failure-only. It does not classify the
    /// credential as usable and does not require a caller-supplied verdict or
    /// clock. The conservative expiry bound is retained so later invalidation
    /// cannot release the local reservation prematurely.
    pub(crate) fn quarantine_returned_credential_after_state_rejection(
        &mut self,
        transaction_id: Uuid,
        claim: &DispatchClaim,
        claims: &CredentialClaims,
    ) -> Result<(), DispatchError> {
        self.require_claim_identity(transaction_id, claim)?;
        let snapshot = self.attempt(transaction_id)?.clone();
        if snapshot.phase != LifecyclePhase::CredentialIssuing {
            return Err(DispatchError::InvalidTransition);
        }
        let issue_started_at = snapshot
            .issue_started_at
            .ok_or(DispatchError::InvalidTransition)?;
        let issuer_bound = issue_started_at
            .checked_add(self.bounds.token_lifetime_upper_bound_s)
            .and_then(|value| value.checked_add(self.bounds.clock_uncertainty_s))
            .unwrap_or(i64::MAX);
        let returned_bound = claims
            .expires_at
            .checked_add(self.bounds.clock_uncertainty_s)
            .unwrap_or(i64::MAX);
        let attempt = self.attempt_mut(transaction_id)?;
        attempt.token_digest = Some(claims.token_digest);
        attempt.token_not_before = Some(claims.not_before);
        attempt.token_expires_at = Some(claims.expires_at);
        attempt.service_account_uid = Some(claims.service_account_uid.clone());
        attempt.credential_id = Some(claims.credential_id.clone());
        attempt.credential_safe_after = Some(issuer_bound.max(returned_bound));
        attempt.phase = LifecyclePhase::CredentialInvalidating;
        Ok(())
    }

    /// Retires an already validated local credential after the exact durable
    /// claim proves that authority, revocation, validity, or deadline state is
    /// no longer current. Existing digest and conservative expiry bounds are
    /// retained unchanged.
    pub(crate) fn invalidate_ready_credential_after_state_rejection(
        &mut self,
        transaction_id: Uuid,
        claim: &DispatchClaim,
    ) -> Result<(), DispatchError> {
        self.require_claim_identity(transaction_id, claim)?;
        let attempt = self.attempt_mut(transaction_id)?;
        if attempt.phase != LifecyclePhase::CredentialReady
            || attempt.token_digest.is_none()
            || attempt.token_expires_at.is_none()
            || attempt.credential_safe_after.is_none()
        {
            return Err(DispatchError::InvalidTransition);
        }
        attempt.phase = LifecyclePhase::CredentialInvalidating;
        Ok(())
    }

    /// Finalizes a cancelled pre-issuance attempt after the unique bound object
    /// was deleted and non-issuance was positively established.
    ///
    /// # Errors
    ///
    /// Returns an error if token issuance ever began or the phase is not a
    /// pre-issuance cancellation.
    pub fn finalize_confirmed_non_issuance(
        &mut self,
        transaction_id: Uuid,
        evidence: &NonIssuanceEvidence,
        now: i64,
    ) -> Result<(), DispatchError> {
        self.validate_time(now)?;
        let snapshot = self.attempt(transaction_id)?.clone();
        if snapshot.phase != LifecyclePhase::ReleaseCancelled || snapshot.issue_started_at.is_some()
        {
            return Err(DispatchError::InvalidTransition);
        }
        Self::require_non_issuance_evidence(transaction_id, &snapshot, evidence)?;
        self.finalize_and_release(transaction_id)?;
        self.commit_time(now);
        Ok(())
    }

    /// Performs the final authority, lease, deadline, and token checks.
    ///
    /// Success is only the local authorized-handoff linearization point; this
    /// reference machine performs no network delivery.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, authority, lease, time, or token.
    #[cfg(test)]
    pub(crate) fn release_effect(
        &mut self,
        transaction_id: Uuid,
        claim: &DispatchClaim,
        binding: &EffectBinding,
        now: i64,
    ) -> Result<(), DispatchError> {
        self.validate_time(now)?;
        self.require_lease(transaction_id, claim, now)?;
        let snapshot = self.attempt(transaction_id)?.clone();
        if snapshot.phase != LifecyclePhase::CredentialReady || snapshot.token_digest.is_none() {
            return Err(DispatchError::InvalidTransition);
        }
        Self::require_effect_binding(&snapshot, binding)?;
        if let Err(error) = self.require_authority(&snapshot) {
            self.cancel_release(transaction_id)?;
            self.commit_time(now);
            return Err(error);
        }
        if let Err(error) = self.require_live_dispatch(&snapshot, now) {
            self.cancel_release(transaction_id)?;
            self.commit_time(now);
            return Err(error);
        }
        let token_expires_at = snapshot
            .token_expires_at
            .ok_or(DispatchError::InvalidCredential)?;
        let required_until = now
            .checked_add(self.bounds.minimum_remaining_lifetime_s)
            .ok_or(DispatchError::ArithmeticOverflow)?;
        if token_expires_at < required_until {
            self.cancel_release(transaction_id)?;
            self.commit_time(now);
            return Err(DispatchError::InvalidCredential);
        }
        self.attempt_mut(transaction_id)?.phase = LifecyclePhase::EffectReleased;
        self.commit_time(now);
        Ok(())
    }

    /// Records the beginning of the single provider attempt.
    ///
    /// # Errors
    ///
    /// Returns an error for stale lease/time or invalid prior phase.
    #[cfg(test)]
    pub(crate) fn begin_provider_attempt(
        &mut self,
        transaction_id: Uuid,
        claim: &DispatchClaim,
        binding: &EffectBinding,
        now: i64,
    ) -> Result<(), DispatchError> {
        self.validate_time(now)?;
        self.require_lease(transaction_id, claim, now)?;
        let snapshot = self.attempt(transaction_id)?.clone();
        if snapshot.phase != LifecyclePhase::EffectReleased {
            return Err(DispatchError::InvalidTransition);
        }
        Self::require_effect_binding(&snapshot, binding)?;
        let attempt = self.attempt_mut(transaction_id)?;
        attempt.phase = LifecyclePhase::Executing;
        attempt.provider_attempt_started_at = Some(now);
        self.commit_time(now);
        Ok(())
    }

    /// Performs the final release checks and records the start of the one
    /// provider attempt as one local transition.
    ///
    /// This entry point is reserved for the state-backed bridge. It avoids an
    /// externally observable `EffectReleased` interval between authorization
    /// and the provider-attempt transition.
    pub(crate) fn release_and_begin_provider_attempt(
        &mut self,
        transaction_id: Uuid,
        claim: &DispatchClaim,
        binding: &EffectBinding,
        now: i64,
    ) -> Result<(), DispatchError> {
        self.preflight_provider_attempt(transaction_id, claim, binding, now)?;
        let attempt = self.attempt_mut(transaction_id)?;
        attempt.phase = LifecyclePhase::Executing;
        attempt.provider_attempt_started_at = Some(now);
        self.commit_time(now);
        Ok(())
    }

    /// Checks the complete local provider boundary without changing phase,
    /// clock, credential state, or reservation state.
    pub(crate) fn preflight_provider_attempt(
        &self,
        transaction_id: Uuid,
        claim: &DispatchClaim,
        binding: &EffectBinding,
        now: i64,
    ) -> Result<(), DispatchError> {
        self.validate_time(now)?;
        self.require_lease(transaction_id, claim, now)?;
        let snapshot = self.attempt(transaction_id)?;
        if snapshot.phase != LifecyclePhase::CredentialReady || snapshot.token_digest.is_none() {
            return Err(DispatchError::InvalidTransition);
        }
        Self::require_effect_binding(snapshot, binding)?;
        self.require_authority(snapshot)?;
        self.require_live_dispatch(snapshot, now)?;
        let token_expires_at = snapshot
            .token_expires_at
            .ok_or(DispatchError::InvalidCredential)?;
        let required_until = now
            .checked_add(self.bounds.minimum_remaining_lifetime_s)
            .ok_or(DispatchError::ArithmeticOverflow)?;
        if token_expires_at < required_until {
            return Err(DispatchError::InvalidCredential);
        }
        Ok(())
    }

    pub(crate) fn credential_authority_facts(
        &self,
        transaction_id: Uuid,
        claim: &DispatchClaim,
    ) -> Result<CredentialAuthorityFacts, DispatchError> {
        self.require_claim_identity(transaction_id, claim)?;
        let attempt = self.attempt(transaction_id)?;
        if attempt.phase != LifecyclePhase::CredentialReady {
            return Err(DispatchError::InvalidTransition);
        }
        Ok(CredentialAuthorityFacts {
            token_digest: attempt
                .token_digest
                .ok_or(DispatchError::InvalidCredential)?,
            not_before: attempt
                .token_not_before
                .ok_or(DispatchError::InvalidCredential)?,
            expires_at: attempt
                .token_expires_at
                .ok_or(DispatchError::InvalidCredential)?,
            service_account_uid: attempt
                .service_account_uid
                .clone()
                .ok_or(DispatchError::InvalidCredential)?,
            credential_id: attempt
                .credential_id
                .clone()
                .ok_or(DispatchError::InvalidCredential)?,
        })
    }

    /// Prevents any local retry after the durable attempt boundary may have
    /// committed but no one-shot execution authority could be returned.
    pub(crate) fn force_manual_provider_attempt_uncertainty(
        &mut self,
        transaction_id: Uuid,
        claim: &DispatchClaim,
    ) -> Result<(), DispatchError> {
        self.require_claim_identity(transaction_id, claim)?;
        let phase = self.attempt(transaction_id)?.phase;
        if !matches!(
            phase,
            LifecyclePhase::CredentialReady | LifecyclePhase::Executing
        ) {
            return Err(DispatchError::InvalidTransition);
        }
        self.attempt_mut(transaction_id)?.phase = LifecyclePhase::ManualResolutionRequired;
        Ok(())
    }

    /// Records the single provider attempt without retrying ambiguity.
    ///
    /// # Errors
    ///
    /// Returns an error for stale lease/time or invalid prior phase.
    pub fn record_provider_outcome(
        &mut self,
        transaction_id: Uuid,
        claim: &DispatchClaim,
        now: i64,
        outcome: ProviderOutcome,
    ) -> Result<(), DispatchError> {
        self.validate_time(now)?;
        self.require_lease(transaction_id, claim, now)?;
        let snapshot = self.attempt(transaction_id)?.clone();
        if snapshot.phase != LifecyclePhase::Executing {
            return Err(DispatchError::InvalidTransition);
        }
        let (next, evidence_commitment) = match outcome {
            ProviderOutcome::Success { evidence } => {
                let started_at = snapshot
                    .provider_attempt_started_at
                    .ok_or(DispatchError::InvalidEvidence)?;
                let commitment = Self::require_exact_effect_evidence(
                    transaction_id,
                    &snapshot,
                    &evidence,
                    started_at,
                    now,
                )?;
                (LifecyclePhase::Executed, Some(commitment))
            }
            ProviderOutcome::Unknown => (LifecyclePhase::ExecutionUnknown, None),
        };
        let attempt = self.attempt_mut(transaction_id)?;
        attempt.phase = next;
        attempt.effect_evidence_commitment = evidence_commitment;
        self.commit_time(now);
        Ok(())
    }

    /// Moves an unknown effect into reconciliation without a second attempt.
    ///
    /// # Errors
    ///
    /// Returns an error for non-monotone time or invalid prior phase.
    pub fn begin_effect_reconciliation(
        &mut self,
        transaction_id: Uuid,
        now: i64,
    ) -> Result<(), DispatchError> {
        self.validate_time(now)?;
        let attempt = self.attempt_mut(transaction_id)?;
        if attempt.phase != LifecyclePhase::ExecutionUnknown {
            return Err(DispatchError::InvalidTransition);
        }
        attempt.phase = LifecyclePhase::Reconciling;
        attempt.reconciliation_started_at = Some(now);
        self.commit_time(now);
        Ok(())
    }

    /// Resolves reconciliation as exact effect or manual resolution.
    ///
    /// This reference machine deliberately cannot establish no prior effect.
    /// Credential retirement prevents a future effect but does not prove that
    /// an earlier effect did not occur. A future authenticated destination
    /// observation profile is required before automatic no-effect finality.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid phase or unsafe no-effect classification.
    pub fn resolve_effect_reconciliation(
        &mut self,
        transaction_id: Uuid,
        outcome: ReconciliationOutcome,
        now: i64,
    ) -> Result<(), DispatchError> {
        self.validate_time(now)?;
        let snapshot = self.attempt(transaction_id)?.clone();
        if snapshot.phase != LifecyclePhase::Reconciling {
            return Err(DispatchError::InvalidTransition);
        }
        let (next, evidence_commitment) = match outcome {
            ReconciliationOutcome::ExactEffect { evidence } => {
                let started_at = snapshot
                    .reconciliation_started_at
                    .ok_or(DispatchError::InvalidEvidence)?;
                let commitment = Self::require_exact_effect_evidence(
                    transaction_id,
                    &snapshot,
                    &evidence,
                    started_at,
                    now,
                )?;
                (LifecyclePhase::Executed, Some(commitment))
            }
            ReconciliationOutcome::NoEffectNotEstablished | ReconciliationOutcome::Ambiguous => {
                (LifecyclePhase::ManualResolutionRequired, None)
            }
        };
        let attempt = self.attempt_mut(transaction_id)?;
        attempt.phase = next;
        attempt.effect_evidence_commitment = evidence_commitment;
        self.commit_time(now);
        Ok(())
    }

    /// Confirms deletion or revocation of the unique bound object.
    ///
    /// # Errors
    ///
    /// Returns an error when no credential could exist in the current phase.
    pub fn confirm_credential_invalidation(
        &mut self,
        transaction_id: Uuid,
        evidence: &CredentialInvalidationEvidence,
        now: i64,
    ) -> Result<(), DispatchError> {
        self.validate_time(now)?;
        let snapshot = self.attempt(transaction_id)?.clone();
        if !matches!(
            snapshot.phase,
            LifecyclePhase::CredentialIssueUnknown
                | LifecyclePhase::CredentialInvalidating
                | LifecyclePhase::CredentialReady
                | LifecyclePhase::ReleaseCancelled
                | LifecyclePhase::EffectReleased
                | LifecyclePhase::Executing
                | LifecyclePhase::ExecutionUnknown
                | LifecyclePhase::Reconciling
                | LifecyclePhase::Executed
                | LifecyclePhase::ExecutionFailed
                | LifecyclePhase::ManualResolutionRequired
        ) {
            return Err(DispatchError::InvalidTransition);
        }
        Self::require_credential_invalidation_evidence(transaction_id, &snapshot, evidence)?;
        let attempt = self.attempt_mut(transaction_id)?;
        attempt.invalidation_confirmed = true;
        if matches!(
            attempt.phase,
            LifecyclePhase::CredentialIssueUnknown
                | LifecyclePhase::CredentialInvalidating
                | LifecyclePhase::CredentialReady
                | LifecyclePhase::ReleaseCancelled
        ) {
            attempt.phase = LifecyclePhase::CredentialQuarantined;
        }
        self.commit_time(now);
        Ok(())
    }

    /// Finalizes a pre-effect unknown or cancelled credential after safe expiry.
    ///
    /// # Errors
    ///
    /// Returns an error until invalidation and conservative expiry both hold.
    pub fn finish_quarantined_credential(
        &mut self,
        transaction_id: Uuid,
        now: i64,
    ) -> Result<(), DispatchError> {
        self.validate_time(now)?;
        let snapshot = self.attempt(transaction_id)?.clone();
        if snapshot.phase != LifecyclePhase::CredentialQuarantined {
            return Err(DispatchError::InvalidTransition);
        }
        if !Self::credential_is_safe(&snapshot, now) {
            return Err(DispatchError::CredentialStillLive);
        }
        self.attempt_mut(transaction_id)?.phase = LifecyclePhase::CredentialSafeExpired;
        self.finalize_and_release(transaction_id)?;
        self.commit_time(now);
        Ok(())
    }

    /// Finalizes a definite provider result after safe credential retirement.
    ///
    /// # Errors
    ///
    /// Returns an error while the token may live or the result is non-terminal.
    pub fn finalize_terminal_effect(
        &mut self,
        transaction_id: Uuid,
        now: i64,
    ) -> Result<(), DispatchError> {
        self.validate_time(now)?;
        let snapshot = self.attempt(transaction_id)?.clone();
        if !matches!(
            snapshot.phase,
            LifecyclePhase::Executed | LifecyclePhase::ExecutionFailed
        ) {
            return Err(DispatchError::InvalidTransition);
        }
        if !Self::credential_is_safe(&snapshot, now) {
            return Err(DispatchError::CredentialStillLive);
        }
        self.finalize_and_release(transaction_id)?;
        self.commit_time(now);
        Ok(())
    }

    /// Returns the current phase.
    ///
    /// # Errors
    ///
    /// Returns an error when the transaction is unknown.
    pub fn phase(&self, transaction_id: Uuid) -> Result<LifecyclePhase, DispatchError> {
        Ok(self.attempt(transaction_id)?.phase)
    }

    /// Returns the retained exact-effect evidence commitment for audit.
    ///
    /// # Errors
    ///
    /// Returns an error when the transaction is unknown.
    pub fn effect_evidence_snapshot(
        &self,
        transaction_id: Uuid,
    ) -> Result<EffectEvidenceSnapshot, DispatchError> {
        let attempt = self.attempt(transaction_id)?;
        Ok(EffectEvidenceSnapshot {
            transaction_id,
            physical: attempt.physical.clone(),
            phase: attempt.phase,
            evidence_commitment: attempt.effect_evidence_commitment,
        })
    }

    /// Returns whether a physical reservation is held.
    #[must_use]
    pub fn resource_is_reserved(&self, physical: &PhysicalResourceId) -> bool {
        self.reservations.contains_key(physical)
    }

    pub(crate) fn resolve_state_destination(
        &self,
        owner: &LogicalOwner,
        cluster_identity: &str,
        namespace: &str,
        deployment_uid: &str,
    ) -> Result<PhysicalResourceId, DispatchError> {
        let mut matches = self
            .registrations
            .iter()
            .filter(|(physical, registration)| {
                &registration.owner == owner
                    && physical.cluster_trust_domain == cluster_identity
                    && physical.namespace == namespace
                    && physical.deployment_uid == deployment_uid
            })
            .map(|(physical, _)| physical.clone());
        let physical = matches.next().ok_or(DispatchError::RegistrationMismatch)?;
        if matches.next().is_some() {
            return Err(DispatchError::AliasConflict);
        }
        Ok(physical)
    }

    pub(crate) fn accepts_bridge_owner(&self, owner: &LogicalOwner) -> bool {
        self.bridge_owner
            .as_ref()
            .is_none_or(|current| current == owner)
    }

    pub(crate) fn bind_bridge_owner(&mut self, owner: LogicalOwner) {
        debug_assert!(self.accepts_bridge_owner(&owner));
        if self.bridge_owner.is_none() {
            self.bridge_owner = Some(owner);
        }
    }

    pub(crate) fn bind_dispatch_claim_token(
        &mut self,
        transaction_id: Uuid,
        token: DispatchClaimToken,
    ) -> Result<(), DispatchError> {
        let attempt = self.attempt_mut(transaction_id)?;
        if token.key().transaction_id != transaction_id
            || token.key().authorization_id != attempt.consumption.authorization_id
            || token.key().scope.tenant != attempt.owner.tenant
            || token.key().scope.environment != attempt.owner.environment
            || attempt.dispatch_claim_token.is_some()
        {
            return Err(DispatchError::StaleLease);
        }
        attempt.dispatch_claim_token = Some(token);
        Ok(())
    }

    pub(crate) fn bridge_token_matches_claim(
        &self,
        token: &DispatchClaimToken,
        claim: &DispatchClaim,
    ) -> bool {
        self.attempt(claim.transaction_id).is_ok_and(|attempt| {
            attempt.dispatch_claim_token.as_ref() == Some(token)
                && token.key().transaction_id == claim.transaction_id
                && token.key().authorization_id == claim.consumption.authorization_id
                && token.worker_id() == claim.worker
                && claim.physical == attempt.physical
                && claim.consumption == attempt.consumption
        })
    }

    pub(crate) fn bridge_token_matches_transaction(
        &self,
        transaction_id: Uuid,
        token: &DispatchClaimToken,
    ) -> bool {
        self.attempt(transaction_id).is_ok_and(|attempt| {
            attempt.dispatch_claim_token.as_ref() == Some(token)
                && token.key().transaction_id == transaction_id
                && token.key().authorization_id == attempt.consumption.authorization_id
        })
    }

    pub(crate) fn bridge_snapshot_matches(
        &self,
        transaction_id: Uuid,
        owner: &LogicalOwner,
        physical: &PhysicalResourceId,
        authority: &AuthorityVersion,
        consumption: ConsumptionBinding,
        dispatch_deadline: i64,
    ) -> bool {
        self.attempt(transaction_id).is_ok_and(|attempt| {
            &attempt.owner == owner
                && &attempt.physical == physical
                && &attempt.consumed_authority == authority
                && attempt.consumption == consumption
                && attempt.dispatch_deadline == dispatch_deadline
        })
    }

    fn validate_time(&self, now: i64) -> Result<(), DispatchError> {
        if now < self.high_water_time || now < 0 {
            return Err(DispatchError::InvalidTime);
        }
        Ok(())
    }

    fn commit_time(&mut self, now: i64) {
        debug_assert!(now >= self.high_water_time && now >= 0);
        self.high_water_time = now;
    }

    fn attempt(&self, transaction_id: Uuid) -> Result<&Attempt, DispatchError> {
        self.attempts
            .get(&transaction_id)
            .ok_or(DispatchError::UnknownTransaction)
    }

    fn attempt_mut(&mut self, transaction_id: Uuid) -> Result<&mut Attempt, DispatchError> {
        self.attempts
            .get_mut(&transaction_id)
            .ok_or(DispatchError::UnknownTransaction)
    }

    fn require_authority(&self, attempt: &Attempt) -> Result<(), DispatchError> {
        if self.active_authority != attempt.consumed_authority {
            return Err(DispatchError::AuthorityChanged);
        }
        Ok(())
    }

    fn require_live_dispatch(&self, attempt: &Attempt, now: i64) -> Result<(), DispatchError> {
        if self.emergency_stop || attempt.emergency_generation != self.emergency_generation {
            return Err(DispatchError::EmergencyStop);
        }
        if now >= attempt.dispatch_deadline {
            return Err(DispatchError::DeadlineExpired);
        }
        Ok(())
    }

    fn validate_effect_template(effect: EffectTemplate) -> Result<(), DispatchError> {
        if effect.template_hash == [0; 32]
            || effect.operation_hash == [0; 32]
            || effect.execution_command_commitment == [0; 32]
            || effect.final_wire_commitment == [0; 32]
        {
            return Err(DispatchError::InvalidCommitment);
        }
        Ok(())
    }

    fn validate_consumption_binding(consumption: ConsumptionBinding) -> Result<(), DispatchError> {
        if consumption.authorization_id.is_nil()
            || consumption.authorization_hash == [0; 32]
            || consumption.receipt_commitment == [0; 32]
        {
            return Err(DispatchError::InvalidCommitment);
        }
        Self::validate_effect_template(consumption.effect)
    }

    fn valid_prepared_execution(
        prepared: &PreparedExecution,
        effect: EffectTemplate,
        credential: &CredentialProfile,
    ) -> bool {
        Self::valid_identity_component(&prepared.bound_object_uid, 512)
            && Self::valid_identity_component(&prepared.token_subject, 512)
            && Self::valid_identity_component(&prepared.token_audience, 512)
            && prepared.template_hash == effect.template_hash
            && prepared.operation_hash == effect.operation_hash
            && prepared.token_subject == credential.token_subject
            && prepared.token_audience == credential.token_audience
            && prepared.effective_rbac_commitment == credential.effective_rbac_commitment
            && prepared.execution_command_commitment == effect.execution_command_commitment
            && prepared.final_wire_commitment == effect.final_wire_commitment
    }

    fn require_effect_binding(
        attempt: &Attempt,
        binding: &EffectBinding,
    ) -> Result<(), DispatchError> {
        let prepared = attempt
            .prepared_execution
            .as_ref()
            .ok_or(DispatchError::InvalidCommitment)?;
        let token_digest = attempt
            .token_digest
            .ok_or(DispatchError::InvalidCommitment)?;
        if binding.template_hash != attempt.consumption.effect.template_hash
            || binding.operation_hash != attempt.consumption.effect.operation_hash
            || binding.execution_command_commitment
                != attempt.consumption.effect.execution_command_commitment
            || binding.final_wire_commitment != attempt.consumption.effect.final_wire_commitment
            || binding.execution_command_commitment != prepared.execution_command_commitment
            || binding.final_wire_commitment != prepared.final_wire_commitment
            || binding.effective_rbac_commitment != prepared.effective_rbac_commitment
            || binding.token_digest != token_digest
        {
            return Err(DispatchError::InvalidCommitment);
        }
        Ok(())
    }

    fn require_exact_effect_evidence(
        transaction_id: Uuid,
        attempt: &Attempt,
        evidence: &ExactEffectEvidence,
        observation_must_follow: i64,
        now: i64,
    ) -> Result<[u8; 32], DispatchError> {
        if evidence.transaction_id != transaction_id
            || evidence.physical != attempt.physical
            || evidence.response_commitment == [0; 32]
            || evidence.post_state_commitment == [0; 32]
            || evidence.observed_resource_uid != attempt.physical.deployment_uid
            || !Self::valid_canonical_opaque(&evidence.observed_resource_uid, 512)
            || !Self::valid_canonical_opaque(&evidence.observed_resource_version, 512)
            || evidence.observed_at <= observation_must_follow
            || evidence.observed_at > now
            || !Self::valid_canonical_observer_identity(&evidence.observer.identity)
            || evidence.observer.authentication_commitment == [0; 32]
        {
            return Err(DispatchError::InvalidEvidence);
        }
        Self::require_effect_binding(attempt, &evidence.binding)?;
        let commitment = evidence.commitment();
        if commitment == [0; 32] {
            return Err(DispatchError::InvalidEvidence);
        }
        Ok(commitment)
    }

    fn require_non_issuance_evidence(
        transaction_id: Uuid,
        attempt: &Attempt,
        evidence: &NonIssuanceEvidence,
    ) -> Result<(), DispatchError> {
        let bound_object_name = attempt
            .bound_object_name
            .as_ref()
            .ok_or(DispatchError::InvalidEvidence)?;
        if evidence.transaction_id != transaction_id
            || evidence.physical != attempt.physical
            || evidence.bound_object_name != *bound_object_name
            || evidence.bound_object_uid != attempt.bound_object_uid
            || evidence.template_hash != attempt.consumption.effect.template_hash
            || evidence.operation_hash != attempt.consumption.effect.operation_hash
            || evidence.evidence_commitment == [0; 32]
        {
            return Err(DispatchError::InvalidEvidence);
        }
        Ok(())
    }

    fn require_credential_invalidation_evidence(
        transaction_id: Uuid,
        attempt: &Attempt,
        evidence: &CredentialInvalidationEvidence,
    ) -> Result<(), DispatchError> {
        let prepared = attempt
            .prepared_execution
            .as_ref()
            .ok_or(DispatchError::InvalidEvidence)?;
        let bound_object_name = attempt
            .bound_object_name
            .as_ref()
            .ok_or(DispatchError::InvalidEvidence)?;
        if evidence.transaction_id != transaction_id
            || evidence.physical != attempt.physical
            || evidence.bound_object_name != *bound_object_name
            || evidence.bound_object_uid != prepared.bound_object_uid
            || evidence.token_digest != attempt.token_digest
            || evidence.template_hash != attempt.consumption.effect.template_hash
            || evidence.operation_hash != attempt.consumption.effect.operation_hash
            || evidence.execution_command_commitment != prepared.execution_command_commitment
            || evidence.final_wire_commitment != prepared.final_wire_commitment
            || evidence.effective_rbac_commitment != prepared.effective_rbac_commitment
            || evidence.evidence_commitment == [0; 32]
        {
            return Err(DispatchError::InvalidEvidence);
        }
        Ok(())
    }

    fn require_lease(
        &self,
        transaction_id: Uuid,
        claim: &DispatchClaim,
        now: i64,
    ) -> Result<(), DispatchError> {
        self.require_claim_identity(transaction_id, claim)?;
        let attempt = self.attempt(transaction_id)?;
        let lease = attempt.lease.as_ref().ok_or(DispatchError::StaleLease)?;
        if now >= lease.expires_at {
            return Err(DispatchError::StaleLease);
        }
        Ok(())
    }

    fn require_claim_identity(
        &self,
        transaction_id: Uuid,
        claim: &DispatchClaim,
    ) -> Result<(), DispatchError> {
        let attempt = self.attempt(transaction_id)?;
        let lease = attempt.lease.as_ref().ok_or(DispatchError::StaleLease)?;
        if claim.transaction_id != transaction_id
            || claim.physical != attempt.physical
            || claim.consumption != attempt.consumption
            || lease.worker != claim.worker
            || lease.fence != claim.fence
            || attempt.reservation_generation != Some(claim.reservation_generation)
            || attempt.bound_object_name.as_deref() != Some(claim.bound_object_name.as_str())
        {
            return Err(DispatchError::StaleLease);
        }
        Ok(())
    }

    fn transition_with_lease(
        &mut self,
        transaction_id: Uuid,
        claim: &DispatchClaim,
        now: i64,
        from: LifecyclePhase,
        to: LifecyclePhase,
    ) -> Result<(), DispatchError> {
        self.validate_time(now)?;
        self.require_lease(transaction_id, claim, now)?;
        let attempt = self.attempt_mut(transaction_id)?;
        if attempt.phase != from {
            return Err(DispatchError::InvalidTransition);
        }
        attempt.phase = to;
        self.commit_time(now);
        Ok(())
    }

    fn credential_safe_after(&self, observed_at: i64) -> Result<i64, DispatchError> {
        observed_at
            .checked_add(self.bounds.token_lifetime_upper_bound_s)
            .and_then(|value| value.checked_add(self.bounds.clock_uncertainty_s))
            .ok_or(DispatchError::ArithmeticOverflow)
    }

    fn valid_identity_component(value: &str, maximum_length: usize) -> bool {
        !value.is_empty()
            && value.len() <= maximum_length
            && value.trim() == value
            && !value.chars().any(char::is_control)
    }

    fn valid_credential_id(value: &str) -> bool {
        let Some(encoded) = value.strip_prefix("AUTHORIZATION_ID=") else {
            return false;
        };
        Uuid::parse_str(encoded)
            .ok()
            .is_some_and(|parsed| !parsed.is_nil() && encoded == parsed.to_string())
    }

    fn valid_canonical_opaque(value: &str, maximum_length: usize) -> bool {
        Self::valid_identity_component(value, maximum_length)
            && value.is_ascii()
            && value.bytes().all(|byte| byte.is_ascii_graphic())
    }

    fn valid_canonical_observer_identity(value: &str) -> bool {
        Self::valid_identity_component(value, 512)
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

    fn credential_is_safe(attempt: &Attempt, now: i64) -> bool {
        attempt.invalidation_confirmed
            && attempt
                .credential_safe_after
                .is_some_and(|safe_after| now >= safe_after)
    }

    fn cancel_release(&mut self, transaction_id: Uuid) -> Result<(), DispatchError> {
        self.attempt_mut(transaction_id)?.phase = LifecyclePhase::ReleaseCancelled;
        Ok(())
    }

    fn finalize_and_release(&mut self, transaction_id: Uuid) -> Result<(), DispatchError> {
        let physical = self.attempt(transaction_id)?.physical.clone();
        let reservation = self
            .reservations
            .get(&physical)
            .ok_or(DispatchError::InvalidTransition)?;
        if reservation.transaction_id != transaction_id
            || self.attempt(transaction_id)?.reservation_generation != Some(reservation.generation)
        {
            return Err(DispatchError::InvalidTransition);
        }
        self.reservations.remove(&physical);
        self.attempt_mut(transaction_id)?.phase = LifecyclePhase::TransactionFinal;
        Ok(())
    }
}
