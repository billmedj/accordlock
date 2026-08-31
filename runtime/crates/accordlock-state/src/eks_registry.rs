//! Rooted, durable activation of the single EKS destination profile.
//!
//! Request-facing code never supplies the authority domains, owner, current
//! time, authorization commitments, or physical reservation used by this module.
//! Bootstrap supplies one validated route and two non-secret authorization
//! commitments; state accepts them only when their canonical roots are the
//! roots already active in the resource and mediation authority domains.

use std::fmt;

use accordlock_eks_profile::{
    EksBrokerManagementBindings, EksCredentialLifecyclePolicy, EksRouteProfile,
};
use accordlock_protocol::{AuthorityDomainState, AuthorityVector, Digest32};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    BrokerJournalSelector, DispatchAcquisitionAuthority, PhysicalResourceKey, Scope, StateError,
};

const RESOURCE_ROOT_DOMAIN: &[u8] = b"accordlock:v1:eks-resource-activation\0";
const MEDIATION_ROOT_DOMAIN: &[u8] = b"accordlock:v1:eks-mediation-activation\0";
const ACTIVATION_COMMITMENT_DOMAIN: &[u8] = b"accordlock:v1:eks-destination-activation\0";
const PROFILE_SCHEMA_VERSION: u8 = 1;
const ZERO: Digest32 = Digest32::from_bytes([0; 32]);

/// Trusted bootstrap material for exactly one EKS target and attempt identity.
///
/// This value is not authority by itself. [`EksDestinationRegistryState`] will
/// accept it only when its independently recomputed resource and mediation
/// roots equal the corresponding domains in durable active authority state.
#[derive(Clone, PartialEq, Eq)]
pub struct EksDestinationProfile {
    route: EksRouteProfile,
    effective_rbac_commitment: Digest32,
    terminal_witness_registry_commitment: Digest32,
    credential_lifecycle_policy: EksCredentialLifecyclePolicy,
    broker_management_bindings: EksBrokerManagementBindings,
}

impl EksDestinationProfile {
    /// Builds the narrow profile from a validated route and non-zero roots.
    ///
    /// # Errors
    ///
    /// Returns [`EksRegistryError::InvalidProfile`] for a zero commitment.
    pub fn new(
        route: EksRouteProfile,
        effective_rbac_commitment: [u8; 32],
        terminal_witness_registry_commitment: [u8; 32],
        credential_lifecycle_policy: EksCredentialLifecyclePolicy,
        broker_management_bindings: EksBrokerManagementBindings,
    ) -> Result<Self, EksRegistryError> {
        let effective_rbac_commitment = Digest32::from_bytes(effective_rbac_commitment);
        let terminal_witness_registry_commitment =
            Digest32::from_bytes(terminal_witness_registry_commitment);
        if effective_rbac_commitment == ZERO || terminal_witness_registry_commitment == ZERO {
            return Err(EksRegistryError::InvalidProfile);
        }
        Ok(Self {
            route,
            effective_rbac_commitment,
            terminal_witness_registry_commitment,
            credential_lifecycle_policy,
            broker_management_bindings,
        })
    }

    #[must_use]
    pub const fn route(&self) -> &EksRouteProfile {
        &self.route
    }

    #[must_use]
    pub const fn effective_rbac_commitment(&self) -> Digest32 {
        self.effective_rbac_commitment
    }

    #[must_use]
    pub const fn terminal_witness_registry_commitment(&self) -> Digest32 {
        self.terminal_witness_registry_commitment
    }

    #[must_use]
    pub const fn credential_lifecycle_policy(&self) -> EksCredentialLifecyclePolicy {
        self.credential_lifecycle_policy
    }

    #[must_use]
    pub const fn broker_management_bindings(&self) -> &EksBrokerManagementBindings {
        &self.broker_management_bindings
    }

    /// Computes the canonical root expected in `authority.resource`.
    ///
    /// # Errors
    ///
    /// Returns an error if a length cannot be represented canonically.
    pub fn resource_root(&self, scope: &Scope) -> Result<Digest32, EksRegistryError> {
        scope.validate()?;
        let route = self.route();
        let mut bytes = RESOURCE_ROOT_DOMAIN.to_vec();
        bytes.push(PROFILE_SCHEMA_VERSION);
        append_scope(&mut bytes, scope)?;
        for value in [
            route.cluster_trust_domain(),
            route.cluster_identity(),
            route.api_server_identity(),
            route.dns_server_name(),
        ] {
            append_bytes(&mut bytes, value.as_bytes())?;
        }
        bytes.extend_from_slice(&route.port().to_be_bytes());
        append_bytes(
            &mut bytes,
            route.socket_target().socket_addr().to_string().as_bytes(),
        )?;
        bytes.extend_from_slice(route.ca_trust_commitment().as_bytes());
        for value in [
            route.namespace(),
            route.deployment_name(),
            route.deployment_uid(),
        ] {
            append_bytes(&mut bytes, value.as_bytes())?;
        }
        Ok(Digest32::sha256(&bytes))
    }

    /// Computes the canonical root expected in `authority.mediation`.
    ///
    /// The complete active resource-domain identity is included, preventing a
    /// mediation activation from floating to a different target activation.
    ///
    /// # Errors
    ///
    /// Returns an error if a length cannot be represented canonically.
    pub fn mediation_root(
        &self,
        scope: &Scope,
        resource_authority: &AuthorityDomainState,
    ) -> Result<Digest32, EksRegistryError> {
        scope.validate()?;
        let route = self.route();
        let mut bytes = MEDIATION_ROOT_DOMAIN.to_vec();
        bytes.push(PROFILE_SCHEMA_VERSION);
        append_scope(&mut bytes, scope)?;
        append_authority_domain(&mut bytes, resource_authority);
        for value in [
            route.attempt_service_account_name(),
            route.attempt_service_account_uid(),
            &self.token_subject(),
            route.token_audience(),
        ] {
            append_bytes(&mut bytes, value.as_bytes())?;
        }
        bytes.extend_from_slice(self.effective_rbac_commitment.as_bytes());
        bytes.extend_from_slice(self.terminal_witness_registry_commitment.as_bytes());
        append_lifecycle_policy(&mut bytes, self.credential_lifecycle_policy);
        append_management_bindings(&mut bytes, &self.broker_management_bindings)?;
        Ok(Digest32::sha256(&bytes))
    }

    #[must_use]
    pub fn token_subject(&self) -> String {
        format!(
            "system:serviceaccount:{}:{}",
            self.route.namespace(),
            self.route.attempt_service_account_name()
        )
    }
}

impl fmt::Debug for EksDestinationProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EksDestinationProfile")
            .field("route", &self.route)
            .field("effective_rbac_commitment", &"[COMMITTED]")
            .field("terminal_witness_registry_commitment", &"[COMMITTED]")
            .field("credential_lifecycle_policy", &"[COMMITTED]")
            .field("broker_management_bindings", &"[COMMITTED]")
            .finish()
    }
}

/// Opaque state-derived facts for a currently authorized broker operation.
///
/// Construction is crate-private and the value is not serializable. Every
/// field comes from durable active state or from the stored signed authorization.
#[derive(PartialEq, Eq)]
pub struct CurrentEksAttempt {
    facts: EksAttemptFacts,
    checked_at: i64,
    dispatch_deadline: i64,
}

impl CurrentEksAttempt {
    pub(crate) const fn new(
        facts: EksAttemptFacts,
        checked_at: i64,
        dispatch_deadline: i64,
    ) -> Self {
        Self {
            facts,
            checked_at,
            dispatch_deadline,
        }
    }

    #[must_use]
    pub const fn facts(&self) -> &EksAttemptFacts {
        &self.facts
    }

    #[must_use]
    pub const fn checked_at(&self) -> i64 {
        self.checked_at
    }

    #[must_use]
    pub const fn dispatch_deadline(&self) -> i64 {
        self.dispatch_deadline
    }
}

impl fmt::Debug for CurrentEksAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CurrentEksAttempt")
            .field("facts", &self.facts)
            .field("checked_at", &self.checked_at)
            .field("dispatch_deadline", &self.dispatch_deadline)
            .finish()
    }
}

/// Frozen immutable facts available only for journal-bound cleanup and GET.
#[derive(PartialEq, Eq)]
pub struct FrozenEksAttempt {
    facts: EksAttemptFacts,
}

impl FrozenEksAttempt {
    pub(crate) const fn new(facts: EksAttemptFacts) -> Self {
        Self { facts }
    }

    #[must_use]
    pub const fn facts(&self) -> &EksAttemptFacts {
        &self.facts
    }
}

impl fmt::Debug for FrozenEksAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenEksAttempt")
            .field("facts", &self.facts)
            .finish()
    }
}

/// Complete immutable route, identity, and effect tuple derived by state.
#[derive(PartialEq, Eq)]
pub struct EksAttemptFacts {
    scope: Scope,
    transaction_id: Uuid,
    authorization_id: Uuid,
    route: EksRouteProfile,
    physical_resource: PhysicalResourceKey,
    token_subject: String,
    effective_rbac_commitment: Digest32,
    terminal_witness_registry_commitment: Digest32,
    credential_lifecycle_policy: EksCredentialLifecyclePolicy,
    broker_management_bindings: EksBrokerManagementBindings,
    template_hash: Digest32,
    operation_hash: Digest32,
    execution_command_commitment: Digest32,
    provider_request_commitment: Digest32,
    resource_authority: AuthorityDomainState,
    mediation_authority: AuthorityDomainState,
    activation_commitment: Digest32,
}

impl EksAttemptFacts {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        scope: Scope,
        transaction_id: Uuid,
        authorization_id: Uuid,
        destination: &RootedEksDestination,
        physical_resource: PhysicalResourceKey,
        template_hash: Digest32,
        operation_hash: Digest32,
        execution_command_commitment: Digest32,
        provider_request_commitment: Digest32,
    ) -> Self {
        Self {
            scope,
            transaction_id,
            authorization_id,
            route: destination.profile.route.clone(),
            physical_resource,
            token_subject: destination.profile.token_subject(),
            effective_rbac_commitment: destination.profile.effective_rbac_commitment,
            terminal_witness_registry_commitment: destination
                .profile
                .terminal_witness_registry_commitment,
            credential_lifecycle_policy: destination.profile.credential_lifecycle_policy,
            broker_management_bindings: destination.profile.broker_management_bindings.clone(),
            template_hash,
            operation_hash,
            execution_command_commitment,
            provider_request_commitment,
            resource_authority: destination.resource_authority.clone(),
            mediation_authority: destination.mediation_authority.clone(),
            activation_commitment: destination.activation_commitment,
        }
    }

    #[must_use]
    pub const fn scope(&self) -> &Scope {
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
    pub const fn route(&self) -> &EksRouteProfile {
        &self.route
    }

    #[must_use]
    pub const fn physical_resource(&self) -> &PhysicalResourceKey {
        &self.physical_resource
    }

    #[must_use]
    pub fn token_subject(&self) -> &str {
        &self.token_subject
    }

    #[must_use]
    pub fn token_audience(&self) -> &str {
        self.route.token_audience()
    }

    #[must_use]
    pub fn service_account_uid(&self) -> &str {
        self.route.attempt_service_account_uid()
    }

    #[must_use]
    pub const fn effective_rbac_commitment(&self) -> Digest32 {
        self.effective_rbac_commitment
    }

    #[must_use]
    pub const fn terminal_witness_registry_commitment(&self) -> Digest32 {
        self.terminal_witness_registry_commitment
    }

    #[must_use]
    pub const fn credential_lifecycle_policy(&self) -> EksCredentialLifecyclePolicy {
        self.credential_lifecycle_policy
    }

    #[must_use]
    pub const fn broker_management_bindings(&self) -> &EksBrokerManagementBindings {
        &self.broker_management_bindings
    }

    #[must_use]
    pub const fn template_hash(&self) -> Digest32 {
        self.template_hash
    }

    #[must_use]
    pub const fn operation_hash(&self) -> Digest32 {
        self.operation_hash
    }

    #[must_use]
    pub const fn execution_command_commitment(&self) -> Digest32 {
        self.execution_command_commitment
    }

    #[must_use]
    pub const fn provider_request_commitment(&self) -> Digest32 {
        self.provider_request_commitment
    }

    #[must_use]
    pub const fn resource_authority(&self) -> &AuthorityDomainState {
        &self.resource_authority
    }

    #[must_use]
    pub const fn mediation_authority(&self) -> &AuthorityDomainState {
        &self.mediation_authority
    }

    #[must_use]
    pub const fn activation_commitment(&self) -> Digest32 {
        self.activation_commitment
    }
}

impl fmt::Debug for EksAttemptFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EksAttemptFacts")
            .field("scope", &self.scope)
            .field("transaction_id", &self.transaction_id)
            .field("authorization_id", &self.authorization_id)
            .field("route", &self.route)
            .field("physical_resource", &self.physical_resource)
            .field("commitments", &"[COMMITTED]")
            .finish_non_exhaustive()
    }
}

/// Fail-closed errors at the rooted EKS registry boundary.
#[derive(Debug, Error)]
pub enum EksRegistryError {
    #[error("EKS destination profile is invalid")]
    InvalidProfile,
    #[error("EKS destination roots do not match active resource/mediation authority")]
    AuthorityRootMismatch,
    #[error("EKS physical destination is already owned under another scope or alias")]
    PhysicalAliasConflict,
    #[error("EKS destination activation conflicts with an existing activation")]
    ActivationConflict,
    #[error("EKS destination activation is absent")]
    NotFound,
    #[error("EKS destination activation is ambiguous")]
    Ambiguous,
    #[error("no exact broker-journal lineage authorizes frozen cleanup facts")]
    FrozenLineageUnavailable,
    #[error("transactional state rejected the EKS registry operation: {0}")]
    State(#[from] StateError),
}

/// Sealed state interface for destination activation and attempt resolution.
pub trait EksDestinationRegistryState: crate::sealed::Sealed + Send + Sync {
    /// Activates one profile only when its canonical roots are already active.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid profile, root mismatch, alias conflict,
    /// ambiguous activation, or unavailable durable state.
    fn activate_eks_destination(
        &self,
        scope: &Scope,
        profile: &EksDestinationProfile,
    ) -> Result<(), EksRegistryError>;

    /// Loads current state-derived facts; revocation, authority drift, an
    /// expired claim/deadline, or stale activation is rejected.
    ///
    /// # Errors
    ///
    /// Returns an error for absent, ambiguous, stale, revoked, expired,
    /// corrupt, misrouted, or unavailable durable state.
    fn load_current_eks_attempt(
        &self,
        scope: &Scope,
        transaction_id: Uuid,
    ) -> Result<CurrentEksAttempt, EksRegistryError>;

    /// Loads current attempt facts only after exact acquisition-generation
    /// revalidation. Stable claim identity alone is insufficient.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale, expired, mismatched, corrupt, or
    /// unavailable acquisition and destination lineage.
    fn load_current_eks_attempt_for_acquisition(
        &self,
        authority: &DispatchAcquisitionAuthority,
    ) -> Result<CurrentEksAttempt, EksRegistryError>;

    /// Loads immutable facts only when an exact durable broker journal lineage
    /// exists. It grants no mutation authority and deliberately ignores only
    /// currentness checks needed for safe cleanup/reconciliation.
    ///
    /// # Errors
    ///
    /// Returns an error unless the immutable authorization, claim, reservation,
    /// activation, and broker-journal lineage agree exactly.
    fn load_frozen_eks_attempt(
        &self,
        scope: &Scope,
        transaction_id: Uuid,
    ) -> Result<FrozenEksAttempt, EksRegistryError>;

    /// Loads frozen cleanup facts from an exact immutable broker-journal row.
    ///
    /// # Errors
    ///
    /// Returns an error unless the selector, acquisition, claim, destination,
    /// and journal lineage agree exactly.
    fn load_frozen_eks_attempt_for_journal(
        &self,
        selector: &BrokerJournalSelector,
    ) -> Result<FrozenEksAttempt, EksRegistryError>;
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PhysicalOwnershipKey {
    pub api_server_identity: String,
    pub namespace: String,
    pub deployment_uid: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PinnedRouteOwnershipKey {
    pub socket_target: String,
    pub ca_trust_commitment: Digest32,
    pub namespace: String,
    pub deployment_uid: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PhysicalOwner {
    pub scope: Scope,
    pub cluster_identity: String,
    pub cluster_trust_domain: String,
    pub physical_key: PhysicalOwnershipKey,
    pub route_key: PinnedRouteOwnershipKey,
    pub first_resource_authority: AuthorityDomainState,
}

impl PhysicalOwner {
    pub(crate) fn same_immutable_ownership(&self, candidate: &Self) -> bool {
        self.scope == candidate.scope
            && self.cluster_identity == candidate.cluster_identity
            && self.cluster_trust_domain == candidate.cluster_trust_domain
            && self.physical_key == candidate.physical_key
            && self.route_key == candidate.route_key
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ActivationKey {
    pub scope: Scope,
    pub resource_activation_id: Uuid,
    pub mediation_activation_id: Uuid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RootedEksDestination {
    pub profile: EksDestinationProfile,
    pub resource_authority: AuthorityDomainState,
    pub mediation_authority: AuthorityDomainState,
    pub activation_commitment: Digest32,
}

impl RootedEksDestination {
    pub(crate) fn activate(
        scope: &Scope,
        profile: &EksDestinationProfile,
        active: &AuthorityVector,
    ) -> Result<Self, EksRegistryError> {
        scope.validate()?;
        if active.resource.epoch > i64::MAX as u64 || active.mediation.epoch > i64::MAX as u64 {
            return Err(EksRegistryError::InvalidProfile);
        }
        if profile.resource_root(scope)? != active.resource.root
            || profile.mediation_root(scope, &active.resource)? != active.mediation.root
        {
            return Err(EksRegistryError::AuthorityRootMismatch);
        }
        let activation_commitment =
            activation_commitment(scope, profile, &active.resource, &active.mediation)?;
        Ok(Self {
            profile: profile.clone(),
            resource_authority: active.resource.clone(),
            mediation_authority: active.mediation.clone(),
            activation_commitment,
        })
    }

    pub(crate) fn validate(&self, scope: &Scope) -> Result<(), EksRegistryError> {
        if self.profile.resource_root(scope)? != self.resource_authority.root
            || self
                .profile
                .mediation_root(scope, &self.resource_authority)?
                != self.mediation_authority.root
            || activation_commitment(
                scope,
                &self.profile,
                &self.resource_authority,
                &self.mediation_authority,
            )? != self.activation_commitment
        {
            return Err(EksRegistryError::ActivationConflict);
        }
        Ok(())
    }

    pub(crate) fn physical_owner(&self, scope: &Scope) -> PhysicalOwner {
        let route = self.profile.route();
        PhysicalOwner {
            scope: scope.clone(),
            cluster_identity: route.cluster_identity().to_owned(),
            cluster_trust_domain: route.cluster_trust_domain().to_owned(),
            physical_key: self.physical_key(),
            route_key: self.route_key(),
            first_resource_authority: self.resource_authority.clone(),
        }
    }

    pub(crate) fn physical_key(&self) -> PhysicalOwnershipKey {
        let route = self.profile.route();
        PhysicalOwnershipKey {
            api_server_identity: route.api_server_identity().to_owned(),
            namespace: route.namespace().to_owned(),
            deployment_uid: route.deployment_uid().to_owned(),
        }
    }

    pub(crate) fn route_key(&self) -> PinnedRouteOwnershipKey {
        let route = self.profile.route();
        PinnedRouteOwnershipKey {
            socket_target: route.socket_target().socket_addr().to_string(),
            ca_trust_commitment: Digest32::from_bytes(*route.ca_trust_commitment().as_bytes()),
            namespace: route.namespace().to_owned(),
            deployment_uid: route.deployment_uid().to_owned(),
        }
    }

    pub(crate) fn activation_key(&self, scope: &Scope) -> ActivationKey {
        ActivationKey {
            scope: scope.clone(),
            resource_activation_id: self.resource_authority.activation_id,
            mediation_activation_id: self.mediation_authority.activation_id,
        }
    }

    pub(crate) fn matches_authority(&self, authority: &AuthorityVector) -> bool {
        self.resource_authority == authority.resource
            && self.mediation_authority == authority.mediation
    }
}

pub(crate) fn derive_attempt_facts(
    scope: &Scope,
    transaction_id: Uuid,
    authorization_id: Uuid,
    template_hash: Digest32,
    template: &accordlock_protocol::DeploymentTemplate,
    destination: &RootedEksDestination,
) -> Result<EksAttemptFacts, EksRegistryError> {
    destination.validate(scope)?;
    let route = destination.profile.route();
    if transaction_id.is_nil()
        || authorization_id.is_nil()
        || template.cluster_identity != route.cluster_identity()
        || template.namespace != route.namespace()
        || template.deployment != route.deployment_name()
        || template.deployment_uid != route.deployment_uid()
    {
        return Err(EksRegistryError::ActivationConflict);
    }
    let physical_resource = PhysicalResourceKey::new(
        template.cluster_identity.clone(),
        template.namespace.clone(),
        template.deployment_uid.clone(),
    )?;
    let prepared = accordlock_k8s::prepare_patch(template, transaction_id, authorization_id)
        .map_err(|error| {
            EksRegistryError::State(StateError::InvalidRecord(format!(
                "stored signed EKS template cannot derive exact attempt commitments: {error}"
            )))
        })?;
    Ok(EksAttemptFacts::new(
        scope.clone(),
        transaction_id,
        authorization_id,
        destination,
        physical_resource,
        template_hash,
        prepared.operation_hash,
        prepared.execution_command_commitment,
        prepared.final_wire_commitment,
    ))
}

fn activation_commitment(
    scope: &Scope,
    profile: &EksDestinationProfile,
    resource_authority: &AuthorityDomainState,
    mediation_authority: &AuthorityDomainState,
) -> Result<Digest32, EksRegistryError> {
    let mut bytes = ACTIVATION_COMMITMENT_DOMAIN.to_vec();
    bytes.push(PROFILE_SCHEMA_VERSION);
    append_scope(&mut bytes, scope)?;
    append_authority_domain(&mut bytes, resource_authority);
    append_authority_domain(&mut bytes, mediation_authority);
    bytes.extend_from_slice(profile.route.commitment().as_bytes());
    bytes.extend_from_slice(profile.effective_rbac_commitment.as_bytes());
    bytes.extend_from_slice(profile.terminal_witness_registry_commitment.as_bytes());
    append_lifecycle_policy(&mut bytes, profile.credential_lifecycle_policy);
    append_management_bindings(&mut bytes, &profile.broker_management_bindings)?;
    Ok(Digest32::sha256(&bytes))
}

fn append_lifecycle_policy(target: &mut Vec<u8>, policy: EksCredentialLifecyclePolicy) {
    target.extend_from_slice(policy.commitment().as_bytes());
}

fn append_management_bindings(
    target: &mut Vec<u8>,
    bindings: &EksBrokerManagementBindings,
) -> Result<(), EksRegistryError> {
    for binding in [
        bindings.secret_lifecycle(),
        bindings.service_account_token(),
        bindings.token_review(),
    ] {
        append_bytes(target, binding.subject().as_bytes())?;
        target.extend_from_slice(&binding.rbac_commitment());
    }
    Ok(())
}

fn append_scope(target: &mut Vec<u8>, scope: &Scope) -> Result<(), EksRegistryError> {
    append_bytes(target, scope.tenant.as_bytes())?;
    append_bytes(target, scope.environment.as_bytes())
}

fn append_authority_domain(target: &mut Vec<u8>, domain: &AuthorityDomainState) {
    target.extend_from_slice(domain.root.as_bytes());
    target.extend_from_slice(&domain.epoch.to_be_bytes());
    target.extend_from_slice(domain.activation_id.as_bytes());
}

fn append_bytes(target: &mut Vec<u8>, value: &[u8]) -> Result<(), EksRegistryError> {
    let length = u64::try_from(value.len()).map_err(|_| EksRegistryError::InvalidProfile)?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
    Ok(())
}
