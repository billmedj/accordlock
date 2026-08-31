//! Durable terminal evidence and reservation retirement.
//!
//! Request-facing code supplies only routing, one terminalization identifier,
//! and the two canonical signed envelopes. Every attempt, credential,
//! admission, deletion, policy, route, and registry expectation is rebuilt
//! from durable state before either envelope is verified.

use accordlock_protocol::Digest32;
use accordlock_terminal_witness::{
    ActivatedWitnessRegistry, AdmissionLinkage, AttemptIdentity, ConservativeRetirementBound,
    CredentialIdentity, EffectBindingCommitments, PhysicalResourceBinding, RetirementExpectation,
    SecretDeletionObservationV2, SignedCredentialRetirementWitness, SignedEffectWitness,
    TerminalAttemptBinding, VerifiedCredentialRetirementWitness, VerifiedEffectWitness,
    WitnessError, WitnessScope,
};
use uuid::Uuid;

use crate::broker::{
    BrokerJournalOperation, BrokerJournalOutcome, BrokerJournalPhase, StoredBrokerOperation,
};
use crate::eks_registry::{ActivationKey, EksAttemptFacts};
use crate::{
    AdmissionAuthorizationRequest, ConsumeKey, DispatchClaimToken, DispatchCredentialBinding,
    PhysicalResourceKey, Scope, StateError,
};

const TERMINAL_RECORD_COMMITMENT_DOMAIN: &[u8] = b"accordlock:v1:terminal-retirement-record\0";
const MAX_TERMINAL_ENVELOPE_BYTES: usize =
    accordlock_terminal_witness::MAX_TERMINAL_WITNESS_ENVELOPE_BYTES;

/// Exact durable completion of the final post-DELETE GET-absence observation.
///
/// Rows of this shape are append-only. They are written in the same state
/// transaction that commits `DELETE_SECRET/DELETE_ABSENT`; old v9 rows are
/// deliberately not backfilled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StoredSecretDeletionObservation {
    pub entry_id: Uuid,
    pub key: ConsumeKey,
    pub claim_id: Uuid,
    pub fence: u64,
    pub state_instance_id: Uuid,
    pub physical_resource: PhysicalResourceKey,
    pub route_commitment: Digest32,
    pub bound_secret_name: String,
    pub bound_secret_uid: String,
    pub journal_request_commitment: Digest32,
    pub journal_result_commitment: Digest32,
    pub provider_evidence_commitment: Digest32,
    pub reconciliation_floor_at: i64,
    pub observed_at: i64,
}

impl StoredSecretDeletionObservation {
    pub(crate) fn from_committed_delete(
        delete: &StoredBrokerOperation,
        observed_at: i64,
    ) -> Result<Self, StateError> {
        delete.validate()?;
        let started_at = delete.started_at.ok_or_else(|| {
            StateError::InvalidRecord(
                "final Secret-deletion observation has no operation start".to_owned(),
            )
        })?;
        let reconciliation_floor_at = delete.last_reconciled_at.unwrap_or(started_at);
        if delete.operation != BrokerJournalOperation::DeleteSecret
            || delete.phase != BrokerJournalPhase::Committed
            || delete.outcome != Some(BrokerJournalOutcome::DeleteAbsent)
            || observed_at <= 0
            || observed_at < started_at
            || reconciliation_floor_at < started_at
            || observed_at < reconciliation_floor_at
        {
            return Err(StateError::InvalidRecord(
                "final Secret-deletion observation lacks a committed DELETE absence".to_owned(),
            ));
        }
        let bound_secret_uid = delete.bound_secret_uid.clone().ok_or_else(|| {
            StateError::InvalidRecord("committed DELETE absence has no exact Secret UID".to_owned())
        })?;
        let journal_result_commitment = delete.result_commitment.ok_or_else(|| {
            StateError::InvalidRecord(
                "committed DELETE absence has no result commitment".to_owned(),
            )
        })?;
        let provider_evidence_commitment =
            delete.provider_evidence_commitment.ok_or_else(|| {
                StateError::InvalidRecord(
                    "committed DELETE absence has no provider evidence commitment".to_owned(),
                )
            })?;
        Ok(Self {
            entry_id: delete.entry_id,
            key: delete.key.clone(),
            claim_id: delete.claim_id,
            fence: delete.fence,
            state_instance_id: delete.state_instance_id,
            physical_resource: delete.physical_resource.clone(),
            route_commitment: delete.route_commitment,
            bound_secret_name: delete.bound_secret_name.clone(),
            bound_secret_uid,
            journal_request_commitment: delete.request_commitment,
            journal_result_commitment,
            provider_evidence_commitment,
            reconciliation_floor_at,
            observed_at,
        })
    }

    fn payload(
        &self,
        attempt: &TerminalAttemptBinding,
        credential: &CredentialIdentity,
    ) -> Result<accordlock_terminal_witness::SecretDeletionObservation, StateError> {
        SecretDeletionObservationV2::new(
            self.entry_id,
            self.journal_request_commitment,
            self.journal_result_commitment,
            self.provider_evidence_commitment,
            self.observed_at,
        )
        .and_then(|facts| facts.observation(attempt, credential))
        .map_err(terminal_witness_error)
    }
}

/// Canonical registration result for witness material already committed by a
/// historical v11 destination activation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TerminalWitnessRegistryReceipt {
    scope: Scope,
    resource_activation_id: Uuid,
    mediation_activation_id: Uuid,
    registry_commitment: Digest32,
    recovered: bool,
}

impl TerminalWitnessRegistryReceipt {
    #[must_use]
    pub const fn scope(&self) -> &Scope {
        &self.scope
    }

    #[must_use]
    pub const fn resource_activation_id(&self) -> Uuid {
        self.resource_activation_id
    }

    #[must_use]
    pub const fn mediation_activation_id(&self) -> Uuid {
        self.mediation_activation_id
    }

    #[must_use]
    pub const fn registry_commitment(&self) -> Digest32 {
        self.registry_commitment
    }

    #[must_use]
    pub const fn was_recovered(&self) -> bool {
        self.recovered
    }
}

/// Opaque state-derived material supplied to the two independent observers.
///
/// This value is neither authorization nor a release capability. Finalization
/// reloads and verifies the complete tuple again.
#[derive(Clone, Debug)]
pub struct TerminalRetirementContext {
    attempt: TerminalAttemptBinding,
    credential: CredentialIdentity,
    retirement_expectation: RetirementExpectation,
    registry_commitment: Digest32,
    activation: ActivationKey,
    deletion_journal_entry_id: Uuid,
}

impl TerminalRetirementContext {
    #[must_use]
    pub const fn attempt(&self) -> &TerminalAttemptBinding {
        &self.attempt
    }

    #[must_use]
    pub const fn credential(&self) -> &CredentialIdentity {
        &self.credential
    }

    #[must_use]
    pub const fn retirement_expectation(&self) -> &RetirementExpectation {
        &self.retirement_expectation
    }

    #[must_use]
    pub const fn registry_commitment(&self) -> Digest32 {
        self.registry_commitment
    }
}

/// Minimal terminalization request. Signed claims carry the complete tuple,
/// but state never trusts them as the expected tuple.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TerminalRetirementRequest {
    key: ConsumeKey,
    terminalization_id: Uuid,
    effect_envelope: Vec<u8>,
    retirement_envelope: Vec<u8>,
}

impl TerminalRetirementRequest {
    /// Constructs a request from exact canonical persistence envelopes.
    ///
    /// # Errors
    ///
    /// Rejects malformed routing, a nil identifier, oversized input, or either
    /// noncanonical envelope. Signature verification still occurs in state.
    pub fn new(
        key: ConsumeKey,
        terminalization_id: Uuid,
        effect_envelope: Vec<u8>,
        retirement_envelope: Vec<u8>,
    ) -> Result<Self, StateError> {
        key.validate()?;
        if terminalization_id.is_nil()
            || effect_envelope.is_empty()
            || retirement_envelope.is_empty()
            || effect_envelope.len() > MAX_TERMINAL_ENVELOPE_BYTES
            || retirement_envelope.len() > MAX_TERMINAL_ENVELOPE_BYTES
        {
            return Err(StateError::InvalidRecord(
                "terminal-retirement request identity or envelope size is invalid".to_owned(),
            ));
        }
        let effect = SignedEffectWitness::from_canonical_envelope_bytes(&effect_envelope)
            .map_err(terminal_witness_error)?;
        let retirement =
            SignedCredentialRetirementWitness::from_canonical_envelope_bytes(&retirement_envelope)
                .map_err(terminal_witness_error)?;
        if effect
            .exact_envelope_bytes()
            .map_err(terminal_witness_error)?
            != effect_envelope
            || retirement
                .exact_envelope_bytes()
                .map_err(terminal_witness_error)?
                != retirement_envelope
        {
            return Err(StateError::TerminalEvidenceInvalid(
                "terminal witness envelope is not exact canonical bytes".to_owned(),
            ));
        }
        Ok(Self {
            key,
            terminalization_id,
            effect_envelope,
            retirement_envelope,
        })
    }

    #[must_use]
    pub const fn key(&self) -> &ConsumeKey {
        &self.key
    }

    #[must_use]
    pub const fn terminalization_id(&self) -> Uuid {
        self.terminalization_id
    }

    #[must_use]
    pub fn effect_envelope(&self) -> &[u8] {
        &self.effect_envelope
    }

    #[must_use]
    pub fn retirement_envelope(&self) -> &[u8] {
        &self.retirement_envelope
    }

    pub(crate) fn decoded(
        &self,
    ) -> Result<(SignedEffectWitness, SignedCredentialRetirementWitness), StateError> {
        Ok((
            SignedEffectWitness::from_canonical_envelope_bytes(&self.effect_envelope)
                .map_err(terminal_witness_error)?,
            SignedCredentialRetirementWitness::from_canonical_envelope_bytes(
                &self.retirement_envelope,
            )
            .map_err(terminal_witness_error)?,
        ))
    }
}

/// Immutable audit projection of one committed terminal retirement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TerminalRetirementAudit {
    pub(crate) terminalization_id: Uuid,
    pub(crate) key: ConsumeKey,
    pub(crate) claim_id: Uuid,
    pub(crate) fence: u64,
    pub(crate) state_instance_id: Uuid,
    pub(crate) physical_resource: PhysicalResourceKey,
    pub(crate) attempt_binding_commitment: Digest32,
    pub(crate) registry_commitment: Digest32,
    pub(crate) effect_evidence_id: Uuid,
    pub(crate) effect_envelope_commitment: Digest32,
    pub(crate) retirement_evidence_id: Uuid,
    pub(crate) retirement_envelope_commitment: Digest32,
    pub(crate) deletion_journal_entry_id: Uuid,
    pub(crate) deletion_observation_commitment: Digest32,
    pub(crate) finalized_at: i64,
    pub(crate) terminal_record_commitment: Digest32,
}

impl TerminalRetirementAudit {
    #[must_use]
    pub const fn terminalization_id(&self) -> Uuid {
        self.terminalization_id
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
    pub const fn state_instance_id(&self) -> Uuid {
        self.state_instance_id
    }

    #[must_use]
    pub const fn physical_resource(&self) -> &PhysicalResourceKey {
        &self.physical_resource
    }

    #[must_use]
    pub const fn attempt_binding_commitment(&self) -> Digest32 {
        self.attempt_binding_commitment
    }

    #[must_use]
    pub const fn registry_commitment(&self) -> Digest32 {
        self.registry_commitment
    }

    #[must_use]
    pub const fn effect_evidence_id(&self) -> Uuid {
        self.effect_evidence_id
    }

    #[must_use]
    pub const fn effect_envelope_commitment(&self) -> Digest32 {
        self.effect_envelope_commitment
    }

    #[must_use]
    pub const fn retirement_evidence_id(&self) -> Uuid {
        self.retirement_evidence_id
    }

    #[must_use]
    pub const fn retirement_envelope_commitment(&self) -> Digest32 {
        self.retirement_envelope_commitment
    }

    #[must_use]
    pub const fn deletion_journal_entry_id(&self) -> Uuid {
        self.deletion_journal_entry_id
    }

    #[must_use]
    pub const fn deletion_observation_commitment(&self) -> Digest32 {
        self.deletion_observation_commitment
    }

    #[must_use]
    pub const fn finalized_at(&self) -> i64 {
        self.finalized_at
    }

    #[must_use]
    pub const fn terminal_record_commitment(&self) -> Digest32 {
        self.terminal_record_commitment
    }
}

/// Successful terminalization or exact recovery of the same committed tuple.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TerminalRetirementReceipt {
    audit: TerminalRetirementAudit,
    recovered: bool,
}

impl TerminalRetirementReceipt {
    pub(crate) const fn new(audit: TerminalRetirementAudit, recovered: bool) -> Self {
        Self { audit, recovered }
    }

    #[must_use]
    pub const fn audit(&self) -> &TerminalRetirementAudit {
        &self.audit
    }

    #[must_use]
    pub const fn was_recovered(&self) -> bool {
        self.recovered
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StoredTerminalRetirement {
    pub audit: TerminalRetirementAudit,
    pub resource_activation_id: Uuid,
    pub mediation_activation_id: Uuid,
    pub admission_uid: String,
    pub admission_request_commitment: Digest32,
    pub effect_envelope: Vec<u8>,
    pub retirement_envelope: Vec<u8>,
}

impl StoredTerminalRetirement {
    pub(crate) fn new(
        request: &TerminalRetirementRequest,
        claim: &DispatchClaimToken,
        context: &TerminalRetirementContext,
        effect: &VerifiedEffectWitness,
        retirement: &VerifiedCredentialRetirementWitness,
        finalized_at: i64,
    ) -> Result<Self, StateError> {
        if finalized_at <= 0
            || effect.registry_commitment() != context.registry_commitment
            || retirement.registry_commitment() != context.registry_commitment
        {
            return Err(StateError::TerminalEvidenceInvalid(
                "verified terminal evidence registry or finalization time differs".to_owned(),
            ));
        }
        let admission_uid = context
            .attempt
            .admission()
            .admission_uid()
            .ok_or(StateError::TerminalRetirementLineageUnavailable)?
            .to_owned();
        let admission_request_commitment = context
            .attempt
            .admission()
            .request_commitment()
            .ok_or(StateError::TerminalRetirementLineageUnavailable)?;
        let attempt_binding_commitment = context
            .attempt
            .commitment()
            .map_err(terminal_witness_error)?;
        let effect_envelope_commitment = Digest32::sha256(&request.effect_envelope);
        let retirement_envelope_commitment = Digest32::sha256(&request.retirement_envelope);
        let deletion_observation_commitment = context
            .retirement_expectation
            .deletion()
            .observation_commitment();
        let mut audit = TerminalRetirementAudit {
            terminalization_id: request.terminalization_id,
            key: request.key.clone(),
            claim_id: claim.claim_id(),
            fence: claim.fence(),
            state_instance_id: claim.state_instance_id(),
            physical_resource: claim.physical_resource().clone(),
            attempt_binding_commitment,
            registry_commitment: context.registry_commitment,
            effect_evidence_id: effect.claims().evidence_id(),
            effect_envelope_commitment,
            retirement_evidence_id: retirement.claims().evidence_id(),
            retirement_envelope_commitment,
            deletion_journal_entry_id: context.deletion_journal_entry_id,
            deletion_observation_commitment,
            finalized_at,
            terminal_record_commitment: Digest32::from_bytes([0; 32]),
        };
        audit.terminal_record_commitment = terminal_record_commitment(
            &audit,
            &context.activation,
            &admission_uid,
            admission_request_commitment,
            &request.effect_envelope,
            &request.retirement_envelope,
        )?;
        Ok(Self {
            audit,
            resource_activation_id: context.activation.resource_activation_id,
            mediation_activation_id: context.activation.mediation_activation_id,
            admission_uid,
            admission_request_commitment,
            effect_envelope: request.effect_envelope.clone(),
            retirement_envelope: request.retirement_envelope.clone(),
        })
    }

    pub(crate) fn validate(&self) -> Result<(), StateError> {
        self.audit.key.validate()?;
        if self.audit.terminalization_id.is_nil()
            || self.audit.claim_id.is_nil()
            || self.audit.fence == 0
            || self.audit.state_instance_id.is_nil()
            || self.resource_activation_id.is_nil()
            || self.mediation_activation_id.is_nil()
            || self.admission_uid.is_empty()
            || self.audit.finalized_at <= 0
            || self.effect_envelope.is_empty()
            || self.retirement_envelope.is_empty()
        {
            return Err(StateError::InvalidRecord(
                "stored terminal-retirement identity is invalid".to_owned(),
            ));
        }
        let activation = ActivationKey {
            scope: self.audit.key.scope.clone(),
            resource_activation_id: self.resource_activation_id,
            mediation_activation_id: self.mediation_activation_id,
        };
        let expected = terminal_record_commitment(
            &self.audit,
            &activation,
            &self.admission_uid,
            self.admission_request_commitment,
            &self.effect_envelope,
            &self.retirement_envelope,
        )?;
        if expected != self.audit.terminal_record_commitment
            || Digest32::sha256(&self.effect_envelope) != self.audit.effect_envelope_commitment
            || Digest32::sha256(&self.retirement_envelope)
                != self.audit.retirement_envelope_commitment
        {
            return Err(StateError::InvalidRecord(
                "stored terminal-retirement commitment differs".to_owned(),
            ));
        }
        let effect = SignedEffectWitness::from_canonical_envelope_bytes(&self.effect_envelope)
            .map_err(terminal_witness_error)?;
        let retirement = SignedCredentialRetirementWitness::from_canonical_envelope_bytes(
            &self.retirement_envelope,
        )
        .map_err(terminal_witness_error)?;
        if effect
            .exact_envelope_bytes()
            .map_err(terminal_witness_error)?
            != self.effect_envelope
            || retirement
                .exact_envelope_bytes()
                .map_err(terminal_witness_error)?
                != self.retirement_envelope
            || effect.claims().evidence_id() != self.audit.effect_evidence_id
            || retirement.claims().evidence_id() != self.audit.retirement_evidence_id
            || effect.claims().attempt() != retirement.claims().attempt()
            || effect
                .claims()
                .attempt()
                .commitment()
                .map_err(terminal_witness_error)?
                != self.audit.attempt_binding_commitment
            || retirement.claims().deletion().observation_commitment()
                != self.audit.deletion_observation_commitment
            || effect.claims().attempt().identity().state_instance_id()
                != self.audit.state_instance_id
            || effect.claims().attempt().identity().transaction_id()
                != self.audit.key.transaction_id
            || effect.claims().attempt().identity().authorization_id()
                != self.audit.key.authorization_id
            || effect.claims().attempt().identity().claim_id() != self.audit.claim_id
            || effect.claims().attempt().identity().fence() != self.audit.fence
            || effect.claims().attempt().admission().admission_uid()
                != Some(self.admission_uid.as_str())
            || effect.claims().attempt().admission().request_commitment()
                != Some(self.admission_request_commitment)
        {
            return Err(StateError::InvalidRecord(
                "stored terminal-retirement envelopes differ from their audit projection"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn exact_request(&self, request: &TerminalRetirementRequest) -> bool {
        self.audit.terminalization_id == request.terminalization_id
            && self.audit.key == request.key
            && self.effect_envelope == request.effect_envelope
            && self.retirement_envelope == request.retirement_envelope
    }

    pub(crate) fn matches_context_and_claim(
        &self,
        context: &TerminalRetirementContext,
        claim: &DispatchClaimToken,
    ) -> Result<bool, StateError> {
        Ok(self.audit.key == *claim.key()
            && self.audit.claim_id == claim.claim_id()
            && self.audit.fence == claim.fence()
            && self.audit.state_instance_id == claim.state_instance_id()
            && self.audit.physical_resource == *claim.physical_resource()
            && self.resource_activation_id == context.activation.resource_activation_id
            && self.mediation_activation_id == context.activation.mediation_activation_id
            && self.audit.registry_commitment == context.registry_commitment
            && self.audit.deletion_journal_entry_id == context.deletion_journal_entry_id
            && self.audit.deletion_observation_commitment
                == context
                    .retirement_expectation
                    .deletion()
                    .observation_commitment()
            && self.audit.attempt_binding_commitment
                == context
                    .attempt
                    .commitment()
                    .map_err(terminal_witness_error)?
            && context.attempt.admission().admission_uid() == Some(self.admission_uid.as_str())
            && context.attempt.admission().request_commitment()
                == Some(self.admission_request_commitment))
    }
}

/// Complete immutable inputs from which state reconstructs terminal evidence
/// expectations. None of these values is accepted from a terminalization
/// caller.
#[derive(Clone, Copy)]
pub(crate) struct TerminalDurableInputs<'a> {
    pub claim: &'a DispatchClaimToken,
    pub attempt_started_at: i64,
    pub credential: &'a DispatchCredentialBinding,
    pub activation: &'a ActivationKey,
    pub facts: &'a EksAttemptFacts,
    pub admission: &'a AdmissionAuthorizationRequest,
    pub create: &'a StoredBrokerOperation,
    pub issue: &'a StoredBrokerOperation,
    pub delete: &'a StoredBrokerOperation,
    pub deletion: &'a StoredSecretDeletionObservation,
}

/// Rebuilds the exact attempt and retirement expectations exclusively from
/// durable v8-v12 state.
#[allow(clippy::too_many_lines)]
pub(crate) fn derive_terminal_context(
    inputs: TerminalDurableInputs<'_>,
) -> Result<TerminalRetirementContext, StateError> {
    let TerminalDurableInputs {
        claim,
        attempt_started_at,
        credential,
        activation,
        facts,
        admission,
        create,
        issue,
        delete,
        deletion,
    } = inputs;

    claim.key().validate()?;
    admission.validate()?;
    create.validate()?;
    issue.validate()?;
    delete.validate()?;
    if attempt_started_at <= 0
        || !credential.matches_token(claim)
        || credential.not_before() > attempt_started_at
        || credential.expires_at() <= attempt_started_at
        || activation.scope != claim.key().scope
        || facts.scope() != &claim.key().scope
        || facts.transaction_id() != claim.key().transaction_id
        || facts.authorization_id() != claim.key().authorization_id
        || facts.physical_resource() != claim.physical_resource()
    {
        return Err(StateError::TerminalRetirementLineageUnavailable);
    }

    let expected_route = Digest32::from_bytes(*facts.route().commitment().as_bytes());
    let exact_operation = |operation: &StoredBrokerOperation,
                           kind: BrokerJournalOperation,
                           outcome: BrokerJournalOutcome|
     -> bool {
        operation.key == *claim.key()
            && operation.claim_id == claim.claim_id()
            && operation.fence == claim.fence()
            && operation.state_instance_id == claim.state_instance_id()
            && operation.physical_resource == *claim.physical_resource()
            && operation.route_commitment == expected_route
            && operation.operation == kind
            && operation.phase == BrokerJournalPhase::Committed
            && operation.outcome == Some(outcome)
    };
    if !exact_operation(
        create,
        BrokerJournalOperation::CreateSecret,
        BrokerJournalOutcome::CreateMatching,
    ) || !exact_operation(
        issue,
        BrokerJournalOperation::IssueToken,
        BrokerJournalOutcome::TokenIssued,
    ) || !exact_operation(
        delete,
        BrokerJournalOperation::DeleteSecret,
        BrokerJournalOutcome::DeleteAbsent,
    ) {
        return Err(StateError::TerminalRetirementLineageUnavailable);
    }
    let secret_uid = create
        .bound_secret_uid
        .as_deref()
        .ok_or(StateError::TerminalRetirementLineageUnavailable)?;
    if issue.bound_secret_name != create.bound_secret_name
        || delete.bound_secret_name != create.bound_secret_name
        || issue.bound_secret_uid.as_deref() != Some(secret_uid)
        || delete.bound_secret_uid.as_deref() != Some(secret_uid)
    {
        return Err(StateError::TerminalRetirementLineageUnavailable);
    }

    let issuance_started_at = issue
        .started_at
        .ok_or(StateError::TerminalRetirementLineageUnavailable)?;
    let broker_policy = issue
        .credential_policy
        .ok_or(StateError::TerminalRetirementLineageUnavailable)?;
    let lifecycle = facts.credential_lifecycle_policy();
    let expected_broker_safe_after = issuance_started_at
        .checked_add(broker_policy.lifetime_upper_bound_seconds())
        .and_then(|value| value.checked_add(broker_policy.clock_uncertainty_seconds()))
        .ok_or(StateError::TerminalRetirementLineageUnavailable)?;
    if issuance_started_at <= 0
        || issuance_started_at > attempt_started_at
        || broker_policy.lifetime_upper_bound_seconds()
            != lifecycle.server_lifetime_hard_max_seconds()
        || broker_policy.clock_uncertainty_seconds() != lifecycle.clock_uncertainty_seconds()
        || issue.credential_safe_after != Some(expected_broker_safe_after)
        || issue.token_digest != Some(credential.token_digest())
        || issue.token_expires_at != Some(credential.expires_at())
        || credential.service_account_uid() != facts.service_account_uid()
    {
        return Err(StateError::TerminalRetirementLineageUnavailable);
    }

    if admission.key() != claim.key()
        || admission.claim_id() != claim.claim_id()
        || admission.fence() != claim.fence()
        || admission.physical_resource() != claim.physical_resource()
        || admission.credential_token_digest() != credential.token_digest()
        || admission.service_account_uid() != credential.service_account_uid()
        || admission.credential_id() != credential.credential_id()
        || admission.credential_binding_commitment() != credential.commitment()
        || admission.provider_request_commitment() != facts.provider_request_commitment()
    {
        return Err(StateError::TerminalRetirementLineageUnavailable);
    }

    let expected_deletion =
        StoredSecretDeletionObservation::from_committed_delete(delete, deletion.observed_at)?;
    if deletion != &expected_deletion {
        return Err(StateError::TerminalRetirementLineageUnavailable);
    }

    let witness_scope = WitnessScope::new(
        claim.key().scope.tenant.clone(),
        claim.key().scope.environment.clone(),
    )
    .map_err(terminal_witness_error)?;
    let route = facts.route();
    let physical = PhysicalResourceBinding::new(
        route.cluster_trust_domain(),
        route.api_server_identity(),
        route.cluster_identity(),
        route.namespace(),
        route.deployment_uid(),
        route.deployment_name(),
    )
    .map_err(terminal_witness_error)?;
    let identity = AttemptIdentity::new(
        claim.state_instance_id(),
        witness_scope,
        claim.key().transaction_id,
        claim.key().authorization_id,
        claim.claim_id(),
        claim.fence(),
        physical,
        attempt_started_at,
    )
    .map_err(terminal_witness_error)?;
    let effect = EffectBindingCommitments::new(
        expected_route,
        facts.template_hash(),
        facts.operation_hash(),
        facts.execution_command_commitment(),
        facts.provider_request_commitment(),
        facts.effective_rbac_commitment(),
        credential.token_digest(),
    )
    .map_err(terminal_witness_error)?;
    let admission_linkage =
        AdmissionLinkage::required(admission.admission_uid(), admission.commitment()?)
            .map_err(terminal_witness_error)?;
    let attempt = TerminalAttemptBinding::new(identity, effect, admission_linkage);
    let credential = CredentialIdentity::new(
        credential.token_digest(),
        credential.credential_id(),
        credential.service_account_uid(),
        facts.token_audience(),
        facts.token_subject(),
        &create.bound_secret_name,
        secret_uid,
    )
    .map_err(terminal_witness_error)?;
    let deletion_observation = deletion.payload(&attempt, &credential)?;
    let conservative = ConservativeRetirementBound::new(
        lifecycle.policy_id(),
        u64::from(lifecycle.schema_version()),
        Digest32::from_bytes(*lifecycle.commitment().as_bytes()),
        issuance_started_at,
        lifecycle.server_lifetime_hard_max_seconds(),
        lifecycle.deletion_propagation_hard_max_seconds(),
        lifecycle.clock_uncertainty_seconds(),
        deletion.observed_at,
    )
    .map_err(terminal_witness_error)?;
    let retirement_expectation = RetirementExpectation::new(
        &attempt,
        credential.clone(),
        deletion_observation,
        true,
        Some(conservative),
    )
    .map_err(terminal_witness_error)?;
    Ok(TerminalRetirementContext {
        attempt,
        credential,
        retirement_expectation,
        registry_commitment: facts.terminal_witness_registry_commitment(),
        activation: activation.clone(),
        deletion_journal_entry_id: deletion.entry_id,
    })
}

pub(crate) struct AuthenticatedTerminalEvidence {
    pub effect: VerifiedEffectWitness,
    pub retirement: VerifiedCredentialRetirementWitness,
}

/// Authenticates both envelopes and all state-derived bindings without yet
/// applying the store clock. Passing each signed observation as `trusted_now`
/// prevents a forged future timestamp from being classified as temporal
/// before its signature and exact bindings have been verified.
pub(crate) fn authenticate_terminal_evidence(
    context: &TerminalRetirementContext,
    registry: &ActivatedWitnessRegistry,
    request: &TerminalRetirementRequest,
) -> Result<AuthenticatedTerminalEvidence, StateError> {
    if registry.commitment() != context.registry_commitment {
        return Err(StateError::TerminalWitnessRegistryMismatch);
    }
    let (effect, retirement) = request.decoded()?;
    let effect = registry
        .verify_effect(&effect, &context.attempt, effect.claims().observed_at())
        .map_err(terminal_witness_error)?;
    let retirement = registry
        .verify_retirement(
            &retirement,
            &context.attempt,
            &context.retirement_expectation,
            retirement.claims().observed_at(),
        )
        .map_err(terminal_witness_error)?;
    Ok(AuthenticatedTerminalEvidence { effect, retirement })
}

/// Applies the store's trusted-time observation only after both signatures,
/// registry roles, and complete durable bindings are authenticated.
pub(crate) fn validate_terminal_evidence_time(
    evidence: &AuthenticatedTerminalEvidence,
    trusted_now: i64,
) -> Result<(), StateError> {
    if trusted_now <= 0 {
        return Err(StateError::ClockBeforeUnixEpoch);
    }
    let observed = evidence
        .effect
        .claims()
        .observed_at()
        .max(evidence.retirement.claims().observed_at());
    if observed > trusted_now {
        return Err(StateError::TerminalEvidenceFuture {
            observed,
            trusted_now,
        });
    }
    Ok(())
}

pub(crate) fn same_activated_registry(
    left: &ActivatedWitnessRegistry,
    right: &ActivatedWitnessRegistry,
) -> bool {
    left.commitment() == right.commitment()
        && left.authority() == right.authority()
        && left.entries() == right.entries()
}

impl TerminalWitnessRegistryReceipt {
    pub(crate) const fn new(
        scope: Scope,
        resource_activation_id: Uuid,
        mediation_activation_id: Uuid,
        registry_commitment: Digest32,
        recovered: bool,
    ) -> Self {
        Self {
            scope,
            resource_activation_id,
            mediation_activation_id,
            registry_commitment,
            recovered,
        }
    }
}

/// Sealed state API for v12 registry-material registration and atomic terminal
/// reservation retirement.
pub trait TerminalRetirementState: crate::sealed::Sealed + Send + Sync {
    /// Persists exact verifier material only when its full commitment already
    /// appears in the named historical v11 rooted destination activation.
    ///
    /// # Errors
    ///
    /// Fails closed when the activation, complete registry material, durable
    /// state lineage, or an exact recovered binding does not agree.
    fn register_terminal_witness_registry_or_recover(
        &self,
        scope: &Scope,
        resource_activation_id: Uuid,
        mediation_activation_id: Uuid,
        registry: &ActivatedWitnessRegistry,
    ) -> Result<TerminalWitnessRegistryReceipt, StateError>;

    /// Reconstructs the exact observer inputs from durable state. This grants
    /// no release authority and finalization reloads the complete tuple.
    ///
    /// # Errors
    ///
    /// Fails closed for missing, corrupt, legacy-incomplete, non-in-flight, or
    /// mismatched durable lineage.
    fn terminal_retirement_context(
        &self,
        key: &ConsumeKey,
    ) -> Result<TerminalRetirementContext, StateError>;

    /// Verifies both signed witnesses, appends terminal history, transitions
    /// `ATTEMPT_IN_FLIGHT -> TERMINAL`, and releases the active physical
    /// reservation in one transaction; exact retries recover the same record.
    ///
    /// # Errors
    ///
    /// Fails closed for any routing, registry, signature, evidence, time,
    /// replay, state-transition, or exact-recovery mismatch.
    fn finalize_terminal_retirement_or_recover(
        &self,
        request: &TerminalRetirementRequest,
    ) -> Result<TerminalRetirementReceipt, StateError>;

    /// Loads and validates the immutable terminal audit projection.
    ///
    /// # Errors
    ///
    /// Fails closed when terminal history or its durable/signature lineage is
    /// absent, corrupt, or inconsistent.
    fn terminal_retirement_audit(
        &self,
        key: &ConsumeKey,
    ) -> Result<TerminalRetirementAudit, StateError>;
}

fn terminal_record_commitment(
    audit: &TerminalRetirementAudit,
    activation: &ActivationKey,
    admission_uid: &str,
    admission_request_commitment: Digest32,
    effect_envelope: &[u8],
    retirement_envelope: &[u8],
) -> Result<Digest32, StateError> {
    let mut bytes = TERMINAL_RECORD_COMMITMENT_DOMAIN.to_vec();
    bytes.push(1);
    append_terminal_bytes(&mut bytes, audit.key.scope.tenant.as_bytes())?;
    append_terminal_bytes(&mut bytes, audit.key.scope.environment.as_bytes())?;
    bytes.extend_from_slice(audit.key.transaction_id.as_bytes());
    bytes.extend_from_slice(audit.key.authorization_id.as_bytes());
    bytes.extend_from_slice(audit.terminalization_id.as_bytes());
    bytes.extend_from_slice(audit.claim_id.as_bytes());
    bytes.extend_from_slice(&audit.fence.to_be_bytes());
    bytes.extend_from_slice(audit.state_instance_id.as_bytes());
    append_terminal_bytes(
        &mut bytes,
        audit.physical_resource.cluster_identity().as_bytes(),
    )?;
    append_terminal_bytes(&mut bytes, audit.physical_resource.namespace().as_bytes())?;
    append_terminal_bytes(
        &mut bytes,
        audit.physical_resource.deployment_uid().as_bytes(),
    )?;
    bytes.extend_from_slice(audit.attempt_binding_commitment.as_bytes());
    bytes.extend_from_slice(audit.registry_commitment.as_bytes());
    bytes.extend_from_slice(activation.resource_activation_id.as_bytes());
    bytes.extend_from_slice(activation.mediation_activation_id.as_bytes());
    append_terminal_bytes(&mut bytes, admission_uid.as_bytes())?;
    bytes.extend_from_slice(admission_request_commitment.as_bytes());
    bytes.extend_from_slice(audit.effect_evidence_id.as_bytes());
    bytes.extend_from_slice(audit.effect_envelope_commitment.as_bytes());
    bytes.extend_from_slice(audit.retirement_evidence_id.as_bytes());
    bytes.extend_from_slice(audit.retirement_envelope_commitment.as_bytes());
    bytes.extend_from_slice(audit.deletion_journal_entry_id.as_bytes());
    bytes.extend_from_slice(audit.deletion_observation_commitment.as_bytes());
    bytes.extend_from_slice(&audit.finalized_at.to_be_bytes());
    append_terminal_bytes(&mut bytes, effect_envelope)?;
    append_terminal_bytes(&mut bytes, retirement_envelope)?;
    let commitment = Digest32::sha256(&bytes);
    if commitment == Digest32::from_bytes([0; 32]) {
        return Err(StateError::InvalidRecord(
            "terminal-retirement commitment cannot be zero".to_owned(),
        ));
    }
    Ok(commitment)
}

fn append_terminal_bytes(target: &mut Vec<u8>, value: &[u8]) -> Result<(), StateError> {
    let length = u64::try_from(value.len()).map_err(|_| {
        StateError::InvalidRecord("terminal-retirement field is too long".to_owned())
    })?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
    Ok(())
}

#[allow(clippy::needless_pass_by_value)]
fn terminal_witness_error(error: WitnessError) -> StateError {
    StateError::TerminalEvidenceInvalid(error.to_string())
}
