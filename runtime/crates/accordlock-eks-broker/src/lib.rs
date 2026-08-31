#![forbid(unsafe_code)]

//! Fixed-profile EKS broker for one Secret-bound `ServiceAccount` credential.
//!
//! Request-facing input is limited to a transaction and its canonical
//! deterministic Secret name. Destination, namespace, `ServiceAccount`,
//! audience, lifetime policy, and authenticated attempt commitments come from
//! fixed configuration or trusted adapters outside the request.
//!
//! Productive mutation and reconciliation entry points are journal-gated. The
//! following does not compile because request-shaped input is not mutation
//! authority and no raw network mutation surface is public:
//!
//! ```compile_fail
//! # use accordlock_eks_broker::{
//! #     AttemptAuthoritySource, AttemptLookup, EksCredentialBroker, ManagementCredentialSource,
//! # };
//! # use accordlock_executor::TrustedClock;
//! # fn bypass<A, M, C>(broker: &EksCredentialBroker<A, M, C>, lookup: &AttemptLookup)
//! # where
//! #     A: AttemptAuthoritySource,
//! #     M: ManagementCredentialSource,
//! #     C: TrustedClock,
//! # {
//! broker.create_bound_secret(lookup);
//! # }
//! ```

mod http;
mod jwt;

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, mem,
    time::Duration,
};

use accordlock_dispatch::{CredentialClaims, PreparedExecution};
use accordlock_eks_profile::{
    CaTrustCommitment, CaTrustError, EksBrokerManagementBindings, EksCredentialLifecycleCommitment,
    EksCredentialLifecyclePolicy, EksRouteProfile, RouteCommitment, RouteField,
};
use accordlock_executor::{ExclusiveBearer, ExecutorError, TrustedClock};
use accordlock_state::{
    AuthenticatedDispatchCredentialReview, BrokerIoAuthority, BrokerJournalCapability,
    BrokerJournalOperation, BrokerJournalPhase, BrokerJournalSelector, BrokerJournalState,
    BrokerOperationAudit, BrokerOperationReceipt, BrokerReconciliationAuthority,
    BrokerReconciliationResult, BrokerSecretObservation, BrokerTokenIssueObservation,
    DispatchAcquisitionAuthority, DispatchCredentialReviewClaims,
    DispatchCredentialReviewRecoveryKey, DispatchRestartDeletionEvidence, EksAttemptFacts,
    EksDestinationRegistryState, EksRegistryError, PhysicalResourceKey,
    RejectedDispatchCredentialReview, ReviewedDispatchCredential, Scope, StateError,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::{
    EndpointMaterial, FixedHttpsClient, GuardedWireFailure, HttpConfigError, WireBody, WireFailure,
    WireOperation, WireReason, WireResponse,
};
use jwt::{JwtExpectation, parse_rfc3339_utc, validate_bound_token};
use serde::{
    Deserialize,
    de::{self, Deserializer, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

const PROFILE_LABEL: &str = "accordlock.io/profile";
const TRANSACTION_LABEL: &str = "accordlock.io/transaction-id";
const TEMPLATE_LABEL: &str = "accordlock.io/template";
const OPERATION_LABEL: &str = "accordlock.io/operation";
const COMMAND_LABEL: &str = "accordlock.io/command";
const PROVIDER_LABEL: &str = "accordlock.io/provider";
const RBAC_LABEL: &str = "accordlock.io/rbac";
const SERVICE_ACCOUNT_UID_LABEL: &str = "accordlock.io/service-account-uid";
const AUDIENCE_LABEL: &str = "accordlock.io/audience";
const PROFILE_VALUE: &str = "eks-attempt-v1";
const RESPONSE_EVIDENCE_DOMAIN: &[u8] = b"accordlock:v1:eks-broker-response\0";
const TOKEN_REVIEW_PREFIX_DOMAIN: &[u8] = b"accordlock:v1:eks-token-review-rejection\0";
const DELETION_ABSENCE_DOMAIN: &[u8] = b"accordlock:v1:eks-deletion-absence\0";
const MANAGEMENT_CREDENTIAL_COMMITMENT_DOMAIN: &[u8] = b"accordlock:v1:eks-management-credential\0";
const MIN_TIMEOUT: Duration = Duration::from_millis(1);
const MAX_TIMEOUT: Duration = Duration::from_mins(2);
const MIN_INVALIDATION_DELAY_SECONDS: i64 = 60;
const CREDENTIAL_ID_EXTRA_KEY: &str = "authentication.kubernetes.io/credential-id";
const MAX_MANAGEMENT_IDENTITY_BYTES: usize = 512;

/// Fixed network destination and explicit trust material for the API server.
#[derive(Clone, PartialEq, Eq)]
pub struct BrokerEndpointConfig {
    ca_certificates_der: Vec<Vec<u8>>,
    connect_timeout: Duration,
    operation_timeout: Duration,
    max_request_body_bytes: usize,
    max_response_header_bytes: usize,
    max_response_body_bytes: usize,
}

impl fmt::Debug for BrokerEndpointConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerEndpointConfig")
            .field("ca_certificate_count", &self.ca_certificates_der.len())
            .field("connect_timeout", &self.connect_timeout)
            .field("operation_timeout", &self.operation_timeout)
            .field("max_request_body_bytes", &self.max_request_body_bytes)
            .field("max_response_header_bytes", &self.max_response_header_bytes)
            .field("max_response_body_bytes", &self.max_response_body_bytes)
            .finish()
    }
}

impl BrokerEndpointConfig {
    /// Creates explicit trust material and transport bounds. The destination
    /// itself comes exclusively from [`EksRouteProfile`].
    #[must_use]
    pub fn new(ca_certificates_der: Vec<Vec<u8>>) -> Self {
        Self {
            ca_certificates_der,
            connect_timeout: Duration::from_secs(5),
            operation_timeout: Duration::from_secs(15),
            max_request_body_bytes: 1024 * 1024,
            max_response_header_bytes: 32 * 1024,
            max_response_body_bytes: 8 * 1024 * 1024,
        }
    }

    #[must_use]
    pub const fn with_timeouts(
        mut self,
        connect_timeout: Duration,
        operation_timeout: Duration,
    ) -> Self {
        self.connect_timeout = connect_timeout;
        self.operation_timeout = operation_timeout;
        self
    }

    #[must_use]
    pub const fn with_size_limits(
        mut self,
        max_request_body_bytes: usize,
        max_response_header_bytes: usize,
        max_response_body_bytes: usize,
    ) -> Self {
        self.max_request_body_bytes = max_request_body_bytes;
        self.max_response_header_bytes = max_response_header_bytes;
        self.max_response_body_bytes = max_response_body_bytes;
        self
    }
}

/// Fixed credential and retirement policy for one broker instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerProfile {
    route_profile: EksRouteProfile,
    requested_expiration_seconds: i64,
    server_lifetime_upper_bound_seconds: i64,
    clock_uncertainty_seconds: i64,
    invalidation_delay_seconds: i64,
}

impl BrokerProfile {
    #[must_use]
    pub fn new(
        route_profile: EksRouteProfile,
        requested_expiration_seconds: i64,
        server_lifetime_upper_bound_seconds: i64,
    ) -> Self {
        Self {
            route_profile,
            requested_expiration_seconds,
            server_lifetime_upper_bound_seconds,
            clock_uncertainty_seconds: 5,
            invalidation_delay_seconds: MIN_INVALIDATION_DELAY_SECONDS,
        }
    }

    #[must_use]
    pub const fn with_retirement_bounds(
        mut self,
        clock_uncertainty_seconds: i64,
        invalidation_delay_seconds: i64,
    ) -> Self {
        self.clock_uncertainty_seconds = clock_uncertainty_seconds;
        self.invalidation_delay_seconds = invalidation_delay_seconds;
        self
    }

    fn subject(&self) -> String {
        format!(
            "system:serviceaccount:{}:{}",
            self.route_profile.namespace(),
            self.route_profile.attempt_service_account_name()
        )
    }

    fn namespace(&self) -> &str {
        self.route_profile.namespace()
    }

    fn attempt_service_account(&self) -> &str {
        self.route_profile.attempt_service_account_name()
    }

    fn attempt_service_account_uid(&self) -> &str {
        self.route_profile.attempt_service_account_uid()
    }

    /// Audience sent to Kubernetes `TokenRequest` and `TokenReview`. This is
    /// deliberately distinct from `DeploymentTemplate.audience`, which names
    /// the `AccordLock` authorization consumer.
    fn kubernetes_api_audience(&self) -> &str {
        self.route_profile.token_audience()
    }

    const fn route_profile(&self) -> &EksRouteProfile {
        &self.route_profile
    }

    /// Returns the complete rooted lifecycle tuple expected from durable EKS
    /// attempt facts.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityResolutionError::InvalidRecord`] only if an
    /// unchecked in-memory profile is internally inconsistent.
    pub fn credential_lifecycle_policy(
        &self,
    ) -> Result<EksCredentialLifecyclePolicy, AuthorityResolutionError> {
        EksCredentialLifecyclePolicy::new(
            self.requested_expiration_seconds,
            self.server_lifetime_upper_bound_seconds,
            self.clock_uncertainty_seconds,
            self.invalidation_delay_seconds,
        )
        .map_err(|_| AuthorityResolutionError::InvalidRecord)
    }
}

/// One independently provisioned Kubernetes management identity.
///
/// `authorization_commitment` is a non-secret, authenticated commitment to
/// the exact RBAC object set installed for this identity. It is an equality
/// binding, not a substitute for checking those objects at provisioning time.
#[derive(Clone, PartialEq, Eq)]
pub struct BrokerManagementIdentity {
    subject: String,
    authorization_commitment: [u8; 32],
}

impl BrokerManagementIdentity {
    /// Constructs one canonical identity/RBAC binding.
    ///
    /// # Errors
    ///
    /// Rejects empty, non-ASCII, whitespace-bearing, control-bearing, or
    /// oversized subjects and the all-zero commitment sentinel.
    pub fn new(
        subject: String,
        authorization_commitment: [u8; 32],
    ) -> Result<Self, ManagementIdentityError> {
        if subject.is_empty()
            || subject.len() > MAX_MANAGEMENT_IDENTITY_BYTES
            || !subject.is_ascii()
            || subject.trim() != subject
            || subject
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err(ManagementIdentityError::InvalidSubject);
        }
        if authorization_commitment == [0; 32] {
            return Err(ManagementIdentityError::ZeroAuthorizationCommitment);
        }
        Ok(Self {
            subject,
            authorization_commitment,
        })
    }

    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    #[must_use]
    pub const fn authorization_commitment(&self) -> [u8; 32] {
        self.authorization_commitment
    }
}

impl fmt::Debug for BrokerManagementIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerManagementIdentity")
            .field("subject", &self.subject)
            .field(
                "authorization_commitment",
                &URL_SAFE_NO_PAD.encode(self.authorization_commitment),
            )
            .finish()
    }
}

/// Invalid or privilege-unioning management-identity configuration.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ManagementIdentityError {
    #[error("management identity subject is not canonical")]
    InvalidSubject,
    #[error("management RBAC commitment cannot be the all-zero sentinel")]
    ZeroAuthorizationCommitment,
    #[error("one management identity cannot serve different authority families")]
    IdentityReusedAcrossAuthorities,
    #[error("one RBAC authorization scope cannot serve different authority families")]
    AuthorizationReusedAcrossAuthorities,
}

/// Three pairwise-separated management authorities used by the broker.
///
/// Secret create/get/delete intentionally share one lifecycle identity. The
/// exact `ServiceAccount` `TokenRequest` and cluster-scoped `TokenReview` each
/// use a different identity and a different committed RBAC scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerManagementIdentities {
    secret_lifecycle: BrokerManagementIdentity,
    service_account_token: BrokerManagementIdentity,
    token_review: BrokerManagementIdentity,
}

impl BrokerManagementIdentities {
    /// Builds a privilege-separated management profile.
    ///
    /// # Errors
    ///
    /// Rejects any subject or RBAC commitment reused across authority
    /// families. A single union-privileged identity is never representable as
    /// a valid broker configuration.
    pub fn new(
        secret_lifecycle: BrokerManagementIdentity,
        service_account_token: BrokerManagementIdentity,
        token_review: BrokerManagementIdentity,
    ) -> Result<Self, ManagementIdentityError> {
        let subjects = [
            secret_lifecycle.subject(),
            service_account_token.subject(),
            token_review.subject(),
        ];
        if subjects[0] == subjects[1] || subjects[0] == subjects[2] || subjects[1] == subjects[2] {
            return Err(ManagementIdentityError::IdentityReusedAcrossAuthorities);
        }
        let commitments = [
            secret_lifecycle.authorization_commitment(),
            service_account_token.authorization_commitment(),
            token_review.authorization_commitment(),
        ];
        if commitments[0] == commitments[1]
            || commitments[0] == commitments[2]
            || commitments[1] == commitments[2]
        {
            return Err(ManagementIdentityError::AuthorizationReusedAcrossAuthorities);
        }
        Ok(Self {
            secret_lifecycle,
            service_account_token,
            token_review,
        })
    }

    #[must_use]
    pub const fn secret_lifecycle(&self) -> &BrokerManagementIdentity {
        &self.secret_lifecycle
    }

    #[must_use]
    pub const fn service_account_token(&self) -> &BrokerManagementIdentity {
        &self.service_account_token
    }

    #[must_use]
    pub const fn token_review(&self) -> &BrokerManagementIdentity {
        &self.token_review
    }

    const fn identity(&self, authority: BrokerManagementAuthority) -> &BrokerManagementIdentity {
        match authority {
            BrokerManagementAuthority::SecretLifecycle => &self.secret_lifecycle,
            BrokerManagementAuthority::ServiceAccountToken => &self.service_account_token,
            BrokerManagementAuthority::TokenReview => &self.token_review,
        }
    }
}

/// Complete fixed broker configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerConfig {
    endpoint: BrokerEndpointConfig,
    profile: BrokerProfile,
    management_identities: BrokerManagementIdentities,
}

impl BrokerConfig {
    #[must_use]
    pub const fn new(
        endpoint: BrokerEndpointConfig,
        profile: BrokerProfile,
        management_identities: BrokerManagementIdentities,
    ) -> Self {
        Self {
            endpoint,
            profile,
            management_identities,
        }
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum BrokerConfigError {
    #[error("explicit API-server CA bundle is invalid")]
    InvalidCaBundle,
    #[error("explicit API-server CA bytes differ from the EKS route commitment")]
    CaTrustCommitmentMismatch,
    #[error("broker timeout or message-size limits are invalid")]
    InvalidTransportBounds,
    #[error("namespace, ServiceAccount, audience, or lifetime policy is invalid")]
    InvalidProfile,
    #[error("rustls could not construct the fixed authenticated endpoint")]
    TlsConfiguration,
}

/// The only request-shaped selector accepted by the broker.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AttemptLookup {
    transaction_id: Uuid,
    bound_secret_name: String,
}

impl AttemptLookup {
    /// Validates the name against `accordlock-{transaction UUID without hyphens}`.
    ///
    /// # Errors
    ///
    /// Returns [`LookupError`] when the supplied name is not deterministic.
    pub fn new(transaction_id: Uuid, bound_secret_name: String) -> Result<Self, LookupError> {
        if bound_secret_name != deterministic_secret_name(transaction_id) {
            return Err(LookupError::NonCanonicalName);
        }
        Ok(Self {
            transaction_id,
            bound_secret_name,
        })
    }

    #[must_use]
    pub fn for_transaction(transaction_id: Uuid) -> Self {
        Self {
            transaction_id,
            bound_secret_name: deterministic_secret_name(transaction_id),
        }
    }

    #[must_use]
    pub const fn transaction_id(&self) -> Uuid {
        self.transaction_id
    }

    #[must_use]
    pub fn bound_secret_name(&self) -> &str {
        &self.bound_secret_name
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum LookupError {
    #[error("bound Secret name is not the canonical transaction-derived name")]
    NonCanonicalName,
}

#[must_use]
pub fn deterministic_secret_name(transaction_id: Uuid) -> String {
    format!("accordlock-{}", transaction_id.simple())
}

/// Non-zero, typed bindings loaded by a trusted internal authority source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttemptCommitments {
    template_hash: [u8; 32],
    operation_hash: [u8; 32],
    execution_command_commitment: [u8; 32],
    provider_request_commitment: [u8; 32],
    effective_rbac_commitment: [u8; 32],
}

impl AttemptCommitments {
    /// Builds the complete non-zero binding tuple.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityResolutionError::InvalidRecord`] for a zero digest.
    pub fn new(
        template_hash: [u8; 32],
        operation_hash: [u8; 32],
        execution_command_commitment: [u8; 32],
        provider_request_commitment: [u8; 32],
        effective_rbac_commitment: [u8; 32],
    ) -> Result<Self, AuthorityResolutionError> {
        let values = [
            template_hash,
            operation_hash,
            execution_command_commitment,
            provider_request_commitment,
            effective_rbac_commitment,
        ];
        if values.contains(&[0; 32]) {
            return Err(AuthorityResolutionError::InvalidRecord);
        }
        Ok(Self {
            template_hash,
            operation_hash,
            execution_command_commitment,
            provider_request_commitment,
            effective_rbac_commitment,
        })
    }
}

/// Record returned only by the injected trusted authority adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedAttemptRecord {
    lookup: AttemptLookup,
    scope: Scope,
    authorization_id: Uuid,
    route: EksRouteProfile,
    physical_resource: PhysicalResourceKey,
    token_subject: String,
    service_account_uid: String,
    token_audience: String,
    commitments: AttemptCommitments,
    terminal_witness_registry_commitment: [u8; 32],
    credential_lifecycle_policy: EksCredentialLifecyclePolicy,
    credential_lifecycle_commitment: EksCredentialLifecycleCommitment,
    credential_lifecycle_policy_id: String,
    broker_management_bindings: EksBrokerManagementBindings,
    resource_authority: AttemptAuthorityDomainBinding,
    mediation_authority: AttemptAuthorityDomainBinding,
    destination_activation_commitment: [u8; 32],
}

impl TrustedAttemptRecord {
    /// Constructs a complete broker record only from opaque state-derived
    /// facts. No request field can register or replace any security fact.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityResolutionError::InvalidRecord`] if state exposes a
    /// zero, non-canonical, or internally inconsistent binding.
    pub fn from_state_facts(facts: &EksAttemptFacts) -> Result<Self, AuthorityResolutionError> {
        let policy = facts.credential_lifecycle_policy();
        let record = Self {
            lookup: AttemptLookup::for_transaction(facts.transaction_id()),
            scope: facts.scope().clone(),
            authorization_id: facts.authorization_id(),
            route: facts.route().clone(),
            physical_resource: facts.physical_resource().clone(),
            token_subject: facts.token_subject().to_owned(),
            service_account_uid: facts.service_account_uid().to_owned(),
            token_audience: facts.token_audience().to_owned(),
            commitments: AttemptCommitments::new(
                *facts.template_hash().as_bytes(),
                *facts.operation_hash().as_bytes(),
                *facts.execution_command_commitment().as_bytes(),
                *facts.provider_request_commitment().as_bytes(),
                *facts.effective_rbac_commitment().as_bytes(),
            )?,
            terminal_witness_registry_commitment: *facts
                .terminal_witness_registry_commitment()
                .as_bytes(),
            credential_lifecycle_policy: policy,
            credential_lifecycle_commitment: policy.commitment(),
            credential_lifecycle_policy_id: policy.policy_id().to_owned(),
            broker_management_bindings: facts.broker_management_bindings().clone(),
            resource_authority: AttemptAuthorityDomainBinding {
                root: *facts.resource_authority().root.as_bytes(),
                epoch: facts.resource_authority().epoch,
                activation_id: facts.resource_authority().activation_id,
            },
            mediation_authority: AttemptAuthorityDomainBinding {
                root: *facts.mediation_authority().root.as_bytes(),
                epoch: facts.mediation_authority().epoch,
                activation_id: facts.mediation_authority().activation_id,
            },
            destination_activation_commitment: *facts.activation_commitment().as_bytes(),
        };
        record.validate_internal()?;
        Ok(record)
    }

    fn validate_internal(&self) -> Result<(), AuthorityResolutionError> {
        let route = &self.route;
        let expected_subject = format!(
            "system:serviceaccount:{}:{}",
            route.namespace(),
            route.attempt_service_account_name()
        );
        if self.lookup.transaction_id() == Uuid::nil()
            || self.authorization_id == Uuid::nil()
            || self.physical_resource.cluster_identity() != route.cluster_identity()
            || self.physical_resource.namespace() != route.namespace()
            || self.physical_resource.deployment_uid() != route.deployment_uid()
            || self.token_subject != expected_subject
            || self.service_account_uid != route.attempt_service_account_uid()
            || self.token_audience != route.token_audience()
            || self.terminal_witness_registry_commitment == [0; 32]
            || self.credential_lifecycle_commitment != self.credential_lifecycle_policy.commitment()
            || self.credential_lifecycle_policy_id != self.credential_lifecycle_policy.policy_id()
            || !self.resource_authority.is_valid()
            || !self.mediation_authority.is_valid()
            || self.destination_activation_commitment == [0; 32]
        {
            return Err(AuthorityResolutionError::InvalidRecord);
        }
        Ok(())
    }

    #[must_use]
    pub const fn lookup(&self) -> &AttemptLookup {
        &self.lookup
    }

    #[must_use]
    pub const fn scope(&self) -> &Scope {
        &self.scope
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
    pub fn service_account_uid(&self) -> &str {
        &self.service_account_uid
    }

    #[must_use]
    pub fn token_audience(&self) -> &str {
        &self.token_audience
    }

    #[must_use]
    pub const fn template_hash(&self) -> [u8; 32] {
        self.commitments.template_hash
    }

    #[must_use]
    pub const fn operation_hash(&self) -> [u8; 32] {
        self.commitments.operation_hash
    }

    #[must_use]
    pub const fn execution_command_commitment(&self) -> [u8; 32] {
        self.commitments.execution_command_commitment
    }

    #[must_use]
    pub const fn provider_request_commitment(&self) -> [u8; 32] {
        self.commitments.provider_request_commitment
    }

    #[must_use]
    pub const fn effective_rbac_commitment(&self) -> [u8; 32] {
        self.commitments.effective_rbac_commitment
    }

    #[must_use]
    pub const fn terminal_witness_registry_commitment(&self) -> [u8; 32] {
        self.terminal_witness_registry_commitment
    }

    #[must_use]
    pub const fn credential_lifecycle_policy(&self) -> EksCredentialLifecyclePolicy {
        self.credential_lifecycle_policy
    }

    #[must_use]
    pub const fn credential_lifecycle_commitment(&self) -> EksCredentialLifecycleCommitment {
        self.credential_lifecycle_commitment
    }

    #[must_use]
    pub fn credential_lifecycle_policy_id(&self) -> &str {
        &self.credential_lifecycle_policy_id
    }

    #[must_use]
    pub const fn broker_management_bindings(&self) -> &EksBrokerManagementBindings {
        &self.broker_management_bindings
    }

    #[must_use]
    pub const fn resource_authority(&self) -> AttemptAuthorityDomainBinding {
        self.resource_authority
    }

    #[must_use]
    pub const fn mediation_authority(&self) -> AttemptAuthorityDomainBinding {
        self.mediation_authority
    }

    #[must_use]
    pub const fn destination_activation_commitment(&self) -> [u8; 32] {
        self.destination_activation_commitment
    }
}

/// Immutable root, epoch, and activation identity for one authority domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttemptAuthorityDomainBinding {
    root: [u8; 32],
    epoch: u64,
    activation_id: Uuid,
}

impl AttemptAuthorityDomainBinding {
    fn is_valid(self) -> bool {
        self.root != [0; 32] && !self.activation_id.is_nil()
    }

    #[must_use]
    pub const fn root(self) -> [u8; 32] {
        self.root
    }

    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub const fn activation_id(self) -> Uuid {
        self.activation_id
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum AuthorityResolutionError {
    #[error("attempt authority is unavailable")]
    Unavailable,
    #[error("attempt is absent")]
    NotFound,
    #[error("attempt lookup is ambiguous")]
    Ambiguous,
    #[error("trusted attempt record is invalid")]
    InvalidRecord,
}

/// Trusted current-facts boundary. Implementations must not derive facts from
/// the request beyond its canonical transaction/name key.
///
/// This adapter is deliberately incapable of granting network authority.
/// Mutation and reconciliation authority comes only from opaque values issued
/// by [`BrokerJournalState`].
pub trait AttemptAuthoritySource: Send + Sync {
    /// Loads the exact current attempt commitments for create, token issue, or
    /// token review. Implementations must reload rooted durable state and reject
    /// revocation, deadline expiry, or authority drift. A volatile dispatch
    /// machine and fields copied from an observed Secret are not trusted sources.
    ///
    /// # Errors
    ///
    /// Returns a typed authority error for absence, ambiguity, or outage.
    fn load_current(
        &self,
        authority: &DispatchAcquisitionAuthority,
    ) -> Result<TrustedAttemptRecord, AuthorityResolutionError>;

    /// Loads only the frozen exact facts needed for cleanup or authenticated
    /// GET reconciliation after current dispatch authority may have expired.
    ///
    /// Implementations must use durable state bound to the original journal
    /// lineage. This method grants no create, token, delete, or retry authority;
    /// the broker calls it only after validating an opaque journal authority.
    ///
    /// # Errors
    ///
    /// Returns a typed authority error for absence, ambiguity, outage, or a
    /// frozen record that cannot be proven exact.
    fn load_frozen_cleanup(
        &self,
        selector: &BrokerJournalSelector,
    ) -> Result<TrustedAttemptRecord, AuthorityResolutionError>;
}

/// Durable state-backed authority source fixed to one tenant/environment.
///
/// `CurrentEksAttempt` is consumed inside each load and is never exposed as
/// dispatch recovery authority. In particular, this adapter cannot recover a
/// `DispatchMachine`, `DispatchClaimToken`, or a retry right after uncertainty.
#[derive(Clone, Debug)]
pub struct StateBackedAttemptAuthority<S> {
    state: S,
    scope: Scope,
}

impl<S> StateBackedAttemptAuthority<S> {
    #[must_use]
    pub const fn new(state: S, scope: Scope) -> Self {
        Self { state, scope }
    }

    #[must_use]
    pub const fn scope(&self) -> &Scope {
        &self.scope
    }

    #[must_use]
    pub fn into_state(self) -> S {
        self.state
    }
}

impl<S> AttemptAuthoritySource for StateBackedAttemptAuthority<S>
where
    S: EksDestinationRegistryState,
{
    fn load_current(
        &self,
        authority: &DispatchAcquisitionAuthority,
    ) -> Result<TrustedAttemptRecord, AuthorityResolutionError> {
        let current = self
            .state
            .load_current_eks_attempt_for_acquisition(authority)
            .map_err(|error| map_registry_error(&error))?;
        let record = TrustedAttemptRecord::from_state_facts(current.facts())?;
        let lookup = AttemptLookup::for_transaction(authority.claim().key().transaction_id);
        validate_loaded_lookup(&record, &lookup)?;
        if authority.claim().key().scope != self.scope {
            return Err(AuthorityResolutionError::InvalidRecord);
        }
        Ok(record)
    }

    fn load_frozen_cleanup(
        &self,
        selector: &BrokerJournalSelector,
    ) -> Result<TrustedAttemptRecord, AuthorityResolutionError> {
        let frozen = self
            .state
            .load_frozen_eks_attempt_for_journal(selector)
            .map_err(|error| map_registry_error(&error))?;
        let record = TrustedAttemptRecord::from_state_facts(frozen.facts())?;
        let lookup = AttemptLookup::for_transaction(selector.key().transaction_id);
        validate_loaded_lookup(&record, &lookup)?;
        if selector.key().scope != self.scope {
            return Err(AuthorityResolutionError::InvalidRecord);
        }
        Ok(record)
    }
}

fn validate_loaded_lookup(
    record: &TrustedAttemptRecord,
    lookup: &AttemptLookup,
) -> Result<(), AuthorityResolutionError> {
    if record.lookup() != lookup {
        return Err(AuthorityResolutionError::InvalidRecord);
    }
    Ok(())
}

fn map_registry_error(error: &EksRegistryError) -> AuthorityResolutionError {
    match error {
        EksRegistryError::NotFound => AuthorityResolutionError::NotFound,
        EksRegistryError::Ambiguous => AuthorityResolutionError::Ambiguous,
        EksRegistryError::State(
            StateError::RetryableConflict
            | StateError::RetryLimitExhausted
            | StateError::SchemaMismatch(_)
            | StateError::UnsafePostgresConnection
            | StateError::Database(_),
        ) => AuthorityResolutionError::Unavailable,
        EksRegistryError::InvalidProfile
        | EksRegistryError::AuthorityRootMismatch
        | EksRegistryError::PhysicalAliasConflict
        | EksRegistryError::ActivationConflict
        | EksRegistryError::FrozenLineageUnavailable
        | EksRegistryError::State(_) => AuthorityResolutionError::InvalidRecord,
    }
}

/// Privilege domain selected for one management exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrokerManagementAuthority {
    /// Namespace-scoped create/get/delete of only `AccordLock` bound Secrets.
    SecretLifecycle,
    /// Namespace-scoped `TokenRequest` create on one exact `ServiceAccount`.
    ServiceAccountToken,
    /// Cluster-scoped `TokenReview` create, held by a separate identity.
    TokenReview,
}

/// Exact Kubernetes management operation authorized for one bearer instance.
///
/// The full route commitment is always included. Object names, UIDs, audience,
/// and reviewed-token commitment further prevent a credential response for
/// one exchange from being substituted into another exchange.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerManagementOperation {
    SecretCreate {
        route_commitment: RouteCommitment,
        namespace: String,
        secret_name: String,
    },
    SecretGet {
        route_commitment: RouteCommitment,
        namespace: String,
        secret_name: String,
    },
    SecretDelete {
        route_commitment: RouteCommitment,
        namespace: String,
        secret_name: String,
        secret_uid: String,
    },
    ServiceAccountTokenCreate {
        route_commitment: RouteCommitment,
        namespace: String,
        service_account_name: String,
        service_account_uid: String,
        audience: String,
        bound_secret_name: String,
        bound_secret_uid: String,
    },
    TokenReviewCreate {
        route_commitment: RouteCommitment,
        audience: String,
        reviewed_token_commitment: [u8; 32],
    },
}

impl BrokerManagementOperation {
    #[must_use]
    pub const fn authority(&self) -> BrokerManagementAuthority {
        match self {
            Self::SecretCreate { .. } | Self::SecretGet { .. } | Self::SecretDelete { .. } => {
                BrokerManagementAuthority::SecretLifecycle
            }
            Self::ServiceAccountTokenCreate { .. } => {
                BrokerManagementAuthority::ServiceAccountToken
            }
            Self::TokenReviewCreate { .. } => BrokerManagementAuthority::TokenReview,
        }
    }

    #[must_use]
    pub const fn route_commitment(&self) -> RouteCommitment {
        match self {
            Self::SecretCreate {
                route_commitment, ..
            }
            | Self::SecretGet {
                route_commitment, ..
            }
            | Self::SecretDelete {
                route_commitment, ..
            }
            | Self::ServiceAccountTokenCreate {
                route_commitment, ..
            }
            | Self::TokenReviewCreate {
                route_commitment, ..
            } => *route_commitment,
        }
    }

    const fn broker_operation(&self) -> BrokerOperation {
        match self {
            Self::SecretCreate { .. } => BrokerOperation::CreateSecret,
            Self::SecretGet { .. } => BrokerOperation::GetSecret,
            Self::SecretDelete { .. } => BrokerOperation::DeleteSecret,
            Self::ServiceAccountTokenCreate { .. } => BrokerOperation::TokenRequest,
            Self::TokenReviewCreate { .. } => BrokerOperation::TokenReview,
        }
    }

    const fn wire_operation(&self) -> WireOperation {
        match self {
            Self::SecretCreate { .. } => WireOperation::CreateSecret,
            Self::SecretGet { .. } => WireOperation::GetSecret,
            Self::SecretDelete { .. } => WireOperation::DeleteSecret,
            Self::ServiceAccountTokenCreate { .. } => WireOperation::CreateTokenRequest,
            Self::TokenReviewCreate { .. } => WireOperation::CreateTokenReview,
        }
    }
}

/// Non-secret binding the credential source asserts for one bearer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagementCredentialBinding {
    operation: BrokerManagementOperation,
    identity: BrokerManagementIdentity,
}

impl ManagementCredentialBinding {
    #[must_use]
    pub const fn new(
        operation: BrokerManagementOperation,
        identity: BrokerManagementIdentity,
    ) -> Self {
        Self {
            operation,
            identity,
        }
    }

    #[must_use]
    pub const fn operation(&self) -> &BrokerManagementOperation {
        &self.operation
    }

    #[must_use]
    pub const fn identity(&self) -> &BrokerManagementIdentity {
        &self.identity
    }
}

/// Broker-generated request passed to the management-credential source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagementCredentialRequest {
    required_binding: ManagementCredentialBinding,
}

impl ManagementCredentialRequest {
    fn new(operation: BrokerManagementOperation, identity: BrokerManagementIdentity) -> Self {
        Self {
            required_binding: ManagementCredentialBinding::new(operation, identity),
        }
    }

    #[must_use]
    pub const fn operation(&self) -> &BrokerManagementOperation {
        self.required_binding.operation()
    }

    #[must_use]
    pub const fn required_identity(&self) -> &BrokerManagementIdentity {
        self.required_binding.identity()
    }

    /// Copies only non-secret binding metadata for the returned bearer.
    #[must_use]
    pub fn binding(&self) -> ManagementCredentialBinding {
        self.required_binding.clone()
    }
}

/// Linear management bearer bound to one exact Kubernetes API exchange.
///
/// The type is deliberately not `Clone`; the broker consumes and zeroes one
/// instance after its one HTTP exchange.
pub struct ManagementBearer {
    bytes: Vec<u8>,
    binding: ManagementCredentialBinding,
    credential_commitment: [u8; 32],
}

impl ManagementBearer {
    /// Wraps one management credential returned by a trusted source and binds
    /// it to the exact operation/identity metadata asserted by that source.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialSourceError::InvalidCredential`] for unsafe bytes.
    pub fn from_trusted_source(
        bytes: Vec<u8>,
        binding: ManagementCredentialBinding,
    ) -> Result<Self, CredentialSourceError> {
        if !valid_bearer(&bytes) {
            return Err(CredentialSourceError::InvalidCredential);
        }
        let mut hasher = Sha256::new();
        hasher.update(MANAGEMENT_CREDENTIAL_COMMITMENT_DOMAIN);
        update_len(&mut hasher, &bytes);
        let credential_commitment = hasher.finalize().into();
        Ok(Self {
            bytes,
            binding,
            credential_commitment,
        })
    }

    #[must_use]
    pub const fn binding(&self) -> &ManagementCredentialBinding {
        &self.binding
    }

    /// Domain-separated commitment for audit correlation without bearer
    /// disclosure. It conveys no proof of the credential's actual RBAC.
    #[must_use]
    pub const fn credential_commitment(&self) -> [u8; 32] {
        self.credential_commitment
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn validate_for(
        &self,
        request: &ManagementCredentialRequest,
    ) -> Result<(), CredentialSourceError> {
        if self.binding.operation != *request.operation() {
            return Err(CredentialSourceError::OperationBindingMismatch);
        }
        if self.binding.identity != *request.required_identity() {
            return Err(CredentialSourceError::IdentityBindingMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for ManagementBearer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagementBearer")
            .field("bytes", &"[REDACTED]")
            .field("binding", &self.binding)
            .field(
                "credential_commitment",
                &URL_SAFE_NO_PAD.encode(self.credential_commitment),
            )
            .finish()
    }
}

impl Drop for ManagementBearer {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CredentialSourceError {
    #[error("management credential source is unavailable")]
    Unavailable,
    #[error("management credential is invalid")]
    InvalidCredential,
    #[error("management credential is bound to a different operation")]
    OperationBindingMismatch,
    #[error("management credential is bound to a different authority identity")]
    IdentityBindingMismatch,
}

pub trait ManagementCredentialSource: Send + Sync {
    /// Supplies one linearly owned management credential for the exact request.
    /// Implementations must use independently provisioned authorities; they
    /// must not mint differently tagged wrappers around one union bearer.
    ///
    /// # Errors
    ///
    /// Returns a typed source error without secret material.
    fn credential(
        &self,
        request: &ManagementCredentialRequest,
    ) -> Result<ManagementBearer, CredentialSourceError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrokerOperation {
    CreateSecret,
    GetSecret,
    TokenRequest,
    TokenReview,
    DeleteSecret,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureReason {
    InvalidRequest,
    RequestTooLarge,
    Connect,
    TlsAuthentication,
    Deadline,
    RequestWrite,
    ResponseRead,
    InvalidProviderResponse,
    ResponseTooLarge,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum BrokerFailure {
    #[error("broker and native HTTP routes differ at {0:?}")]
    RouteMismatch(RouteField),
    #[error("attempt authority rejected the internal lookup: {0}")]
    Authority(AuthorityResolutionError),
    #[error("management credential source rejected the exchange: {0}")]
    CredentialSource(CredentialSourceError),
    #[error("{operation:?} was definitely not sent: {reason:?}")]
    DefinitelyNotSent {
        operation: BrokerOperation,
        reason: FailureReason,
    },
    #[error("{operation:?} outcome is unknown: {reason:?}")]
    OutcomeUnknown {
        operation: BrokerOperation,
        reason: FailureReason,
        conservative_credential_safe_after: Option<i64>,
    },
    #[error("{operation:?} received definitive provider status {status}")]
    ProviderRejected {
        operation: BrokerOperation,
        status: u16,
    },
    #[error("{operation:?} returned an invalid authenticated observation")]
    InvalidObservation { operation: BrokerOperation },
    #[error("trusted broker time is unavailable, non-monotone, or overflows")]
    Clock,
    #[error("durable broker journal rejected or could not persist the required transition")]
    JournalState,
}

/// Exact server object accepted after create or reconciliation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundSecret {
    lookup: AttemptLookup,
    namespace: String,
    uid: String,
    subject: String,
    audience: String,
    attempt: TrustedAttemptRecord,
    creation_evidence_commitment: [u8; 32],
}

impl BoundSecret {
    #[must_use]
    pub fn lookup(&self) -> &AttemptLookup {
        &self.lookup
    }

    #[must_use]
    pub fn uid(&self) -> &str {
        &self.uid
    }

    #[must_use]
    pub const fn creation_evidence_commitment(&self) -> [u8; 32] {
        self.creation_evidence_commitment
    }

    /// Returns the complete lifecycle policy loaded from rooted durable EKS
    /// attempt facts for this exact Secret lineage.
    #[must_use]
    pub const fn credential_lifecycle_policy(&self) -> EksCredentialLifecyclePolicy {
        self.attempt.credential_lifecycle_policy()
    }

    /// Returns the rooted activation commitment paired with the same current
    /// attempt facts.
    #[must_use]
    pub const fn destination_activation_commitment(&self) -> [u8; 32] {
        self.attempt.destination_activation_commitment()
    }

    #[must_use]
    pub fn prepared_execution(&self) -> PreparedExecution {
        PreparedExecution {
            bound_object_uid: self.uid.clone(),
            template_hash: self.attempt.commitments.template_hash,
            operation_hash: self.attempt.commitments.operation_hash,
            token_subject: self.subject.clone(),
            token_audience: self.audience.clone(),
            effective_rbac_commitment: self.attempt.commitments.effective_rbac_commitment,
            execution_command_commitment: self.attempt.commitments.execution_command_commitment,
            final_wire_commitment: self.attempt.commitments.provider_request_commitment,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretObservation {
    Absent {
        lookup: AttemptLookup,
        evidence_commitment: [u8; 32],
    },
    Matching(Box<BoundSecret>),
    Conflicting {
        lookup: AttemptLookup,
        evidence_commitment: [u8; 32],
    },
}

struct SecretToken(Vec<u8>);

#[cfg(test)]
static SECRET_TOKEN_DROPS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

impl SecretToken {
    fn into_bytes(mut self) -> Vec<u8> {
        mem::take(&mut self.0)
    }
}

impl fmt::Debug for SecretToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SecretToken")
            .field(&"[REDACTED]")
            .finish()
    }
}

impl Drop for SecretToken {
    fn drop(&mut self) {
        self.0.fill(0);
        #[cfg(test)]
        SECRET_TOKEN_DROPS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

pub struct IssuedToken {
    secret: BoundSecret,
    token: SecretToken,
    token_digest: [u8; 32],
    request_started_at: i64,
    returned_at: i64,
    expires_at: i64,
    response_evidence_commitment: [u8; 32],
}

impl fmt::Debug for IssuedToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedToken")
            .field("secret", &self.secret)
            .field("token", &"[REDACTED]")
            .field("token_digest", &self.token_digest)
            .field("request_started_at", &self.request_started_at)
            .field("returned_at", &self.returned_at)
            .field("expires_at", &self.expires_at)
            .field(
                "response_evidence_commitment",
                &self.response_evidence_commitment,
            )
            .finish()
    }
}

impl IssuedToken {
    #[must_use]
    pub const fn token_digest(&self) -> [u8; 32] {
        self.token_digest
    }

    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }

    fn as_bytes(&self) -> &[u8] {
        &self.token.0
    }
}

pub struct ValidatedCredential {
    reviewed: ReviewedDispatchCredential,
    bearer: SecretToken,
    review_evidence_commitment: [u8; 32],
}

impl fmt::Debug for ValidatedCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedCredential")
            .field("reviewed", &self.reviewed)
            .field("bearer", &"[REDACTED]")
            .field(
                "review_evidence_commitment",
                &self.review_evidence_commitment,
            )
            .finish()
    }
}

impl ValidatedCredential {
    #[must_use]
    pub const fn reviewed(&self) -> &ReviewedDispatchCredential {
        &self.reviewed
    }

    #[must_use]
    pub const fn review_evidence_commitment(&self) -> [u8; 32] {
        self.review_evidence_commitment
    }

    /// Moves the durable reviewed credential and bearer into the dispatch and
    /// executor boundaries. The opaque state proof is never reconstructed from
    /// caller-provided claims.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError`] if the executor rejects the credential bytes.
    pub fn into_dispatch_and_executor(
        self,
    ) -> Result<(ReviewedDispatchCredential, ExclusiveBearer), ExecutorError> {
        let bearer = ExclusiveBearer::new(self.bearer.into_bytes())?;
        Ok((self.reviewed, bearer))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenRejectionEvidence {
    lookup: AttemptLookup,
    secret_uid: String,
    token_digest: [u8; 32],
    observed_at: i64,
    evidence_commitment: [u8; 32],
}

#[derive(Debug)]
pub enum TokenReviewResult {
    Authenticated(Box<ValidatedCredential>),
    Rejected(TokenRejectionEvidence),
}

/// Opaque one-shot selector retained after state authorized the exact
/// `TokenReview` I/O.
///
/// It carries no bearer and cannot create a review. It can only be consumed
/// together with the original [`JournaledIssuedToken`] and the same live
/// acquisition by [`EksCredentialBroker::recover_reviewed_token`].
pub struct TokenReviewRecoveryKey {
    state_key: DispatchCredentialReviewRecoveryKey,
}

impl fmt::Debug for TokenReviewRecoveryKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenReviewRecoveryKey")
            .field("review_id", &self.state_key.review_id())
            .field("acquisition_id", &self.state_key.acquisition_id())
            .field("lease_fence", &self.state_key.lease_fence())
            .finish_non_exhaustive()
    }
}

pub struct TokenReviewFailure {
    failure: Box<BrokerFailure>,
    issued: Box<JournaledIssuedToken>,
    recovery: Option<Box<TokenReviewRecoveryKey>>,
}

impl fmt::Debug for TokenReviewFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenReviewFailure")
            .field("failure", &self.failure)
            .field("issued", &"[REDACTED ISSUED TOKEN]")
            .field("recoverable", &self.recovery.is_some())
            .finish()
    }
}

impl fmt::Display for TokenReviewFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.failure.fmt(formatter)
    }
}

impl std::error::Error for TokenReviewFailure {}

impl TokenReviewFailure {
    fn new(
        failure: BrokerFailure,
        issued: JournaledIssuedToken,
        recovery: Option<DispatchCredentialReviewRecoveryKey>,
    ) -> Self {
        Self {
            failure: Box::new(failure),
            issued: Box::new(issued),
            recovery: recovery.map(|state_key| Box::new(TokenReviewRecoveryKey { state_key })),
        }
    }

    #[must_use]
    pub const fn failure(&self) -> &BrokerFailure {
        &self.failure
    }

    /// Returns whether state had already authorized an exact review boundary
    /// before the failure. Pre-begin failures deliberately return `None`.
    #[must_use]
    pub fn recovery_key(&self) -> Option<&TokenReviewRecoveryKey> {
        self.recovery.as_deref()
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        BrokerFailure,
        JournaledIssuedToken,
        Option<TokenReviewRecoveryKey>,
    ) {
        (
            *self.failure,
            *self.issued,
            self.recovery.map(|recovery| *recovery),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeletionAcknowledgement {
    lookup: AttemptLookup,
    secret_uid: String,
    requested_at: i64,
    status: u16,
    evidence_commitment: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeletionEvidence {
    lookup: AttemptLookup,
    secret_uid: String,
    absent_observed_at: i64,
    evidence_commitment: [u8; 32],
}

/// Matching Secret returned only after its exact create result is durable.
#[derive(Debug)]
pub struct JournaledSecretCreation {
    secret: BoundSecret,
    receipt: BrokerOperationReceipt,
}

impl JournaledSecretCreation {
    #[must_use]
    pub const fn secret(&self) -> &BoundSecret {
        &self.secret
    }

    #[must_use]
    pub const fn receipt(&self) -> &BrokerOperationReceipt {
        &self.receipt
    }

    #[must_use]
    pub fn into_parts(self) -> (BoundSecret, BrokerOperationReceipt) {
        (self.secret, self.receipt)
    }
}

/// Secret-bound bearer returned only after the redacted issuance result is durable.
pub struct JournaledIssuedToken {
    issued: IssuedToken,
    receipt: BrokerOperationReceipt,
}

impl fmt::Debug for JournaledIssuedToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JournaledIssuedToken")
            .field("issued", &"[REDACTED ISSUED TOKEN]")
            .field("receipt", &self.receipt)
            .finish()
    }
}

impl JournaledIssuedToken {
    #[must_use]
    pub const fn token_digest(&self) -> [u8; 32] {
        self.issued.token_digest()
    }

    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.issued.expires_at()
    }

    #[must_use]
    pub const fn receipt(&self) -> &BrokerOperationReceipt {
        &self.receipt
    }

    #[must_use]
    pub fn into_parts(self) -> (IssuedToken, BrokerOperationReceipt) {
        (self.issued, self.receipt)
    }
}

/// Provider DELETE acknowledgement after its send authority has been burned.
#[derive(Debug)]
pub struct JournaledDeletionAcknowledgement {
    acknowledgement: DeletionAcknowledgement,
    journal: BrokerOperationAudit,
}

impl JournaledDeletionAcknowledgement {
    #[must_use]
    pub const fn acknowledgement(&self) -> &DeletionAcknowledgement {
        &self.acknowledgement
    }

    #[must_use]
    pub const fn journal(&self) -> &BrokerOperationAudit {
        &self.journal
    }

    #[must_use]
    pub fn into_parts(self) -> (DeletionAcknowledgement, BrokerOperationAudit) {
        (self.acknowledgement, self.journal)
    }
}

/// Public, non-authoritative result of one journaled reconciliation GET.
#[derive(Debug)]
pub enum JournaledSecretReconciliation {
    CreateCommitted {
        secret: Box<BoundSecret>,
        receipt: BrokerOperationReceipt,
    },
    DeleteCommitted {
        deletion: DeletionEvidence,
        receipt: BrokerOperationReceipt,
    },
    Pending {
        audit: BrokerOperationAudit,
    },
    Terminal {
        receipt: BrokerOperationReceipt,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeletionObservation {
    Present(Box<BoundSecret>),
    Absent(DeletionEvidence),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetirementBasis {
    ConservativeInvalidationDelayElapsed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetirementAssessment {
    Confirmed(RetirementBasis),
    Pending { safe_after: i64 },
}

/// Fixed broker with injected trusted authority, management credential, and clock.
pub struct EksCredentialBroker<A, M, C> {
    profile: BrokerProfile,
    management_identities: BrokerManagementIdentities,
    http: FixedHttpsClient,
    authority: A,
    management_credentials: M,
    clock: C,
    #[cfg(test)]
    scripted_exchanges:
        Option<std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<ScriptedExchange>>>>,
    #[cfg(test)]
    review_commit_fault: Option<std::sync::Arc<ReviewCommitFault>>,
}

#[cfg(test)]
enum ScriptedExchange {
    Response {
        status: u16,
        body: Vec<u8>,
    },
    ResponseThen {
        status: u16,
        body: Vec<u8>,
        before_return: Box<dyn FnOnce() + Send>,
    },
    Failure(BrokerFailure),
}

#[cfg(test)]
#[derive(Debug, Default)]
struct ReviewCommitFault {
    hide_record_result_once: std::sync::atomic::AtomicBool,
    fail_first_recovery_once: std::sync::atomic::AtomicBool,
}

impl<A, M, C> fmt::Debug for EksCredentialBroker<A, M, C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EksCredentialBroker")
            .field("profile", &self.profile)
            .field("management_identities", &self.management_identities)
            .field("http", &self.http)
            .field("authority", &"[TRUSTED ADAPTER]")
            .field("management_credentials", &"[REDACTED ADAPTER]")
            .field("clock", &"[TRUSTED CLOCK]")
            .finish_non_exhaustive()
    }
}

impl<A, M, C> EksCredentialBroker<A, M, C>
where
    A: AttemptAuthoritySource,
    M: ManagementCredentialSource,
    C: TrustedClock,
{
    /// Builds the fixed endpoint and validates every profile bound.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerConfigError`] when a fixed trust or policy bound fails.
    pub fn new(
        config: BrokerConfig,
        authority: A,
        management_credentials: M,
        clock: C,
    ) -> Result<Self, BrokerConfigError> {
        validate_config(&config)?;
        let BrokerConfig {
            endpoint,
            profile,
            management_identities,
        } = config;
        let material = EndpointMaterial {
            route_profile: profile.route_profile().clone(),
            ca_certificates_der: endpoint.ca_certificates_der,
            connect_timeout: endpoint.connect_timeout,
            operation_timeout: endpoint.operation_timeout,
            max_request_body_bytes: endpoint.max_request_body_bytes,
            max_response_header_bytes: endpoint.max_response_header_bytes,
            max_response_body_bytes: endpoint.max_response_body_bytes,
        };
        let http = FixedHttpsClient::new(material).map_err(|error| match error {
            HttpConfigError::InvalidCa => BrokerConfigError::InvalidCaBundle,
            HttpConfigError::InvalidTlsProvider => BrokerConfigError::TlsConfiguration,
        })?;
        Ok(Self {
            profile,
            management_identities,
            http,
            authority,
            management_credentials,
            clock,
            #[cfg(test)]
            scripted_exchanges: None,
            #[cfg(test)]
            review_commit_fault: None,
        })
    }

    /// Returns the complete immutable route used for Secret lifecycle and
    /// Kubernetes credential operations.
    #[must_use]
    pub const fn route_profile(&self) -> &EksRouteProfile {
        self.profile.route_profile()
    }

    /// Returns the complete lifecycle policy validated against every current
    /// rooted attempt record.
    ///
    /// # Errors
    ///
    /// Fails closed if the fixed broker profile is internally inconsistent.
    pub fn credential_lifecycle_policy(
        &self,
    ) -> Result<EksCredentialLifecyclePolicy, AuthorityResolutionError> {
        self.profile.credential_lifecycle_policy()
    }

    /// Reloads the exact current acquisition-bound EKS facts and returns only
    /// the complete lifecycle and activation tuple needed by downstream
    /// execution. The acquisition remains borrowed and no mutation authority
    /// is created.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerFailure`] if the exact acquisition, route, activation,
    /// or rooted lifecycle record is not current.
    pub fn current_execution_profile(
        &self,
        acquisition: &DispatchAcquisitionAuthority,
    ) -> Result<(EksCredentialLifecyclePolicy, [u8; 32]), BrokerFailure> {
        let current = self.resolve(acquisition)?;
        Ok((
            current.credential_lifecycle_policy(),
            current.destination_activation_commitment(),
        ))
    }

    /// Checks the strict acquisition/deadline horizon before durable state is
    /// allowed to mint an I/O authority for CREATE or `TokenRequest`.
    ///
    /// The margin covers the complete fixed transport timeout (connect, TLS,
    /// write, and read), rounded up to seconds, plus the rooted clock
    /// uncertainty. Equality with either bound is rejected.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerFailure::DefinitelyNotSent`] if the requested operation
    /// is not an acquisition-bound preflight or the strict horizon is empty.
    pub fn validate_acquisition_io_window(
        &self,
        acquisition: &DispatchAcquisitionAuthority,
        operation: BrokerOperation,
    ) -> Result<(), BrokerFailure> {
        if !matches!(
            operation,
            BrokerOperation::CreateSecret | BrokerOperation::TokenRequest
        ) {
            return Err(BrokerFailure::DefinitelyNotSent {
                operation,
                reason: FailureReason::InvalidRequest,
            });
        }
        let current = self.resolve(acquisition)?;
        self.validate_current_io_window(acquisition, &current, operation, None)
    }

    /// Returns non-secret authority identity and RBAC commitment metadata.
    #[must_use]
    pub const fn management_identities(&self) -> &BrokerManagementIdentities {
        &self.management_identities
    }

    /// Emits one immutable empty `Opaque` Secret create under the sole durable
    /// send authority and commits the exact authenticated response.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerFailure`] without ever returning or reconstructing the
    /// consumed authority. Every non-committed path burns it into uncertainty.
    pub fn create_bound_secret<S: BrokerJournalState>(
        &self,
        journal: &S,
        acquisition: &DispatchAcquisitionAuthority,
        authority: BrokerIoAuthority,
    ) -> Result<JournaledSecretCreation, BrokerFailure> {
        let (audit, lookup, attempt) = match self.current_io_context(
            &authority,
            BrokerJournalOperation::CreateSecret,
            journal,
            acquisition,
        ) {
            Ok(context) => context,
            Err(failure) => return Err(burn_io_authority(journal, authority, failure)),
        };
        debug_assert_eq!(audit.phase(), BrokerJournalPhase::InFlight);
        let secret = match self.create_bound_secret_unjournaled(
            journal,
            &audit,
            &lookup,
            &attempt,
            acquisition,
        ) {
            Ok(secret) => secret,
            Err(failure) => return Err(burn_io_authority(journal, authority, failure)),
        };
        let Ok(observation) = BrokerSecretObservation::matching(
            secret.uid.clone(),
            secret.creation_evidence_commitment,
        ) else {
            return Err(burn_io_authority(
                journal,
                authority,
                BrokerFailure::InvalidObservation {
                    operation: BrokerOperation::CreateSecret,
                },
            ));
        };
        let receipt = journal
            .commit_broker_create(authority, observation)
            .map_err(|_| BrokerFailure::JournalState)?;
        Ok(JournaledSecretCreation { secret, receipt })
    }

    fn create_bound_secret_unjournaled<S: BrokerJournalState>(
        &self,
        journal: &S,
        audit: &BrokerOperationAudit,
        lookup: &AttemptLookup,
        attempt: &TrustedAttemptRecord,
        acquisition: &DispatchAcquisitionAuthority,
    ) -> Result<BoundSecret, BrokerFailure> {
        let labels = exact_labels(&self.profile, attempt);
        let body = serde_json::to_vec(&json!({
            "apiVersion":"v1",
            "kind":"Secret",
            "metadata":{
                "name":lookup.bound_secret_name,
                "namespace":self.profile.namespace(),
                "labels":labels
            },
            "immutable":true,
            "type":"Opaque",
            "data":{}
        }))
        .map_err(|_| BrokerFailure::DefinitelyNotSent {
            operation: BrokerOperation::CreateSecret,
            reason: FailureReason::InvalidRequest,
        })?;
        let path = format!(
            "/api/v1/namespaces/{}/secrets?fieldValidation=Strict",
            self.profile.namespace()
        );
        let response = self.exchange(
            secret_create_management_operation(&self.profile, lookup),
            &path,
            Some("application/json"),
            WireBody::Bytes(&body),
            None,
            || self.revalidate_current_send(journal, audit, lookup, attempt, acquisition),
        )?;
        self.revalidate_current_send(journal, audit, lookup, attempt, acquisition)
            .map_err(|_| post_send_unknown(BrokerOperation::CreateSecret, None))?;
        if response.status != 201 {
            return Err(mutation_status_failure(
                BrokerOperation::CreateSecret,
                response.status,
                None,
            ));
        }
        let evidence = response_evidence(BrokerOperation::CreateSecret, &response);
        parse_matching_secret(response.body(), &self.profile, attempt, evidence).ok_or(
            BrokerFailure::OutcomeUnknown {
                operation: BrokerOperation::CreateSecret,
                reason: FailureReason::InvalidProviderResponse,
                conservative_credential_safe_after: None,
            },
        )
    }

    /// Performs the sole GET-only create/delete reconciliation authorized by
    /// durable state and persists its exact authenticated observation.
    ///
    /// # Errors
    ///
    /// Returns no authority. A pending result may be reacquired only through
    /// [`BrokerJournalState::begin_broker_reconciliation`].
    pub fn reconcile_bound_secret<S: BrokerJournalState>(
        &self,
        journal: &S,
        authority: BrokerReconciliationAuthority,
    ) -> Result<JournaledSecretReconciliation, BrokerFailure> {
        let (audit, lookup, attempt) = self.reconciliation_context(&authority, journal)?;
        match audit.operation() {
            BrokerJournalOperation::CreateSecret => {
                let observed =
                    self.reconcile_secret_unjournaled(journal, &audit, &lookup, &attempt, None)?;
                let state_observation = state_secret_observation(&observed)?;
                let result = journal
                    .commit_broker_reconciliation(authority, state_observation)
                    .map_err(|_| BrokerFailure::JournalState)?;
                Ok(finish_create_reconciliation(observed, result))
            }
            BrokerJournalOperation::DeleteSecret => {
                let expected = self.bound_secret_from_journal(journal, &audit, &attempt)?;
                let observed = self.reconcile_secret_unjournaled(
                    journal,
                    &audit,
                    &lookup,
                    &attempt,
                    Some(&expected),
                )?;
                let deletion = match &observed {
                    SecretObservation::Absent {
                        evidence_commitment,
                        ..
                    } => {
                        let absent_observed_at = self.now()?;
                        Some(DeletionEvidence {
                            lookup: lookup.clone(),
                            secret_uid: expected.uid.clone(),
                            absent_observed_at,
                            evidence_commitment: deletion_absence_commitment(
                                &lookup,
                                &expected.uid,
                                absent_observed_at,
                                *evidence_commitment,
                            ),
                        })
                    }
                    SecretObservation::Matching(_) | SecretObservation::Conflicting { .. } => None,
                };
                let state_observation = match (&observed, &deletion) {
                    (SecretObservation::Absent { .. }, Some(deletion)) => {
                        BrokerSecretObservation::absent(deletion.evidence_commitment).map_err(
                            |_| BrokerFailure::InvalidObservation {
                                operation: BrokerOperation::GetSecret,
                            },
                        )
                    }
                    _ => state_secret_observation(&observed),
                }?;
                let result = journal
                    .commit_broker_reconciliation(authority, state_observation)
                    .map_err(|_| BrokerFailure::JournalState)?;
                Ok(finish_delete_reconciliation(deletion, result))
            }
            BrokerJournalOperation::IssueToken => Err(BrokerFailure::JournalState),
        }
    }

    fn reconcile_secret_unjournaled<S: BrokerJournalState>(
        &self,
        journal: &S,
        audit: &BrokerOperationAudit,
        lookup: &AttemptLookup,
        attempt: &TrustedAttemptRecord,
        expected: Option<&BoundSecret>,
    ) -> Result<SecretObservation, BrokerFailure> {
        if expected.is_some_and(|secret| secret.lookup != *lookup) {
            return Err(BrokerFailure::DefinitelyNotSent {
                operation: BrokerOperation::GetSecret,
                reason: FailureReason::InvalidRequest,
            });
        }
        let response = self.get_secret(journal, audit, lookup, attempt, None)?;
        self.revalidate_frozen_send(journal, audit, lookup, attempt)?;
        let evidence = response_evidence(BrokerOperation::GetSecret, &response);
        match response.status {
            404 => Ok(SecretObservation::Absent {
                lookup: lookup.clone(),
                evidence_commitment: evidence,
            }),
            200 => {
                let parsed =
                    parse_matching_secret(response.body(), &self.profile, attempt, evidence);
                if let Some(secret) = parsed
                    && expected.is_none_or(|candidate| candidate.uid == secret.uid)
                {
                    Ok(SecretObservation::Matching(Box::new(secret)))
                } else {
                    Ok(SecretObservation::Conflicting {
                        lookup: lookup.clone(),
                        evidence_commitment: evidence,
                    })
                }
            }
            status => Err(BrokerFailure::ProviderRejected {
                operation: BrokerOperation::GetSecret,
                status,
            }),
        }
    }

    /// Issues the sole Secret-bound `ServiceAccount` `TokenRequest` and makes
    /// its redacted result durable before bearer custody may escape.
    ///
    /// The returned server expiration is checked against the configured
    /// `server_lifetime_upper_bound_seconds`, not the requested duration.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerFailure`] without a bearer on every HTTP, validation,
    /// or journal failure. Token issuance is never retried or reconciled by GET.
    pub fn request_bound_token<S: BrokerJournalState>(
        &self,
        journal: &S,
        acquisition: &DispatchAcquisitionAuthority,
        authority: BrokerIoAuthority,
    ) -> Result<JournaledIssuedToken, BrokerFailure> {
        let (audit, _lookup, attempt) = match self.current_io_context(
            &authority,
            BrokerJournalOperation::IssueToken,
            journal,
            acquisition,
        ) {
            Ok(context) => context,
            Err(failure) => return Err(burn_io_authority(journal, authority, failure)),
        };
        let secret = match self.bound_secret_from_journal(journal, &audit, &attempt) {
            Ok(secret) => secret,
            Err(failure) => return Err(burn_io_authority(journal, authority, failure)),
        };
        let request_started_at = audit.started_at().unwrap_or_default();
        let conservative_safe_after = audit.credential_safe_after().unwrap_or_default();
        let current = match self.require_current_secret(&secret, acquisition) {
            Ok(current) => current,
            Err(failure) => return Err(burn_io_authority(journal, authority, failure)),
        };
        let issued = match self.request_bound_token_unjournaled(
            journal,
            &audit,
            &secret,
            &current,
            request_started_at,
            conservative_safe_after,
            acquisition,
        ) {
            Ok(issued) => issued,
            Err(failure) => return Err(burn_io_authority(journal, authority, failure)),
        };
        let Ok(observation) = BrokerTokenIssueObservation::new(
            issued.token_digest,
            issued.expires_at,
            issued.response_evidence_commitment,
        ) else {
            return Err(burn_io_authority(
                journal,
                authority,
                BrokerFailure::InvalidObservation {
                    operation: BrokerOperation::TokenRequest,
                },
            ));
        };
        let committed = journal.commit_broker_token_issue(authority, &observation);
        finish_token_commit(issued, committed)
    }

    #[allow(clippy::too_many_arguments)]
    fn request_bound_token_unjournaled<S: BrokerJournalState>(
        &self,
        journal: &S,
        audit: &BrokerOperationAudit,
        secret: &BoundSecret,
        attempt: &TrustedAttemptRecord,
        request_started_at: i64,
        conservative_safe_after: i64,
        acquisition: &DispatchAcquisitionAuthority,
    ) -> Result<IssuedToken, BrokerFailure> {
        let body_value = json!({
            "apiVersion":"authentication.k8s.io/v1",
            "kind":"TokenRequest",
            "spec":{
                "audiences":[self.profile.kubernetes_api_audience()],
                "expirationSeconds":self.profile.requested_expiration_seconds,
                "boundObjectRef":{
                    "apiVersion":"v1",
                    "kind":"Secret",
                    "name":secret.lookup.bound_secret_name,
                    "uid":secret.uid
                }
            }
        });
        let body =
            serde_json::to_vec(&body_value).map_err(|_| BrokerFailure::DefinitelyNotSent {
                operation: BrokerOperation::TokenRequest,
                reason: FailureReason::InvalidRequest,
            })?;
        let path = format!(
            "/api/v1/namespaces/{}/serviceaccounts/{}/token",
            self.profile.namespace(),
            self.profile.attempt_service_account()
        );
        let response = self.exchange(
            token_request_management_operation(&self.profile, secret),
            &path,
            Some("application/json"),
            WireBody::Bytes(&body),
            Some(conservative_safe_after),
            || self.revalidate_current_send(journal, audit, &secret.lookup, attempt, acquisition),
        )?;
        if response.status != 201 {
            return Err(mutation_status_failure(
                BrokerOperation::TokenRequest,
                response.status,
                Some(conservative_safe_after),
            ));
        }
        let returned_at = self.now().map_err(|_| BrokerFailure::OutcomeUnknown {
            operation: BrokerOperation::TokenRequest,
            reason: FailureReason::InvalidProviderResponse,
            conservative_credential_safe_after: Some(conservative_safe_after),
        })?;
        let evidence = response_evidence(BrokerOperation::TokenRequest, &response);
        let (token, expires_at) = parse_token_request_response(
            response.body(),
            &self.profile,
            secret,
            request_started_at,
            returned_at,
        )
        .ok_or(BrokerFailure::OutcomeUnknown {
            operation: BrokerOperation::TokenRequest,
            reason: FailureReason::InvalidProviderResponse,
            conservative_credential_safe_after: Some(conservative_safe_after),
        })?;
        let token_digest = Sha256::digest(&token.0).into();
        let post_request_current =
            self.revalidate_current_send(journal, audit, &secret.lookup, attempt, acquisition);
        if attempt != &secret.attempt || post_request_current.is_err() {
            return Err(BrokerFailure::OutcomeUnknown {
                operation: BrokerOperation::TokenRequest,
                reason: FailureReason::InvalidProviderResponse,
                conservative_credential_safe_after: Some(conservative_safe_after),
            });
        }
        Ok(IssuedToken {
            secret: secret.clone(),
            token,
            token_digest,
            request_started_at,
            returned_at,
            expires_at,
            response_evidence_commitment: evidence,
        })
    }

    /// Authenticates the exact returned token through `TokenReview` and then
    /// validates the JWT's exact Secret binding.
    ///
    /// # Errors
    ///
    /// Returns [`TokenReviewFailure`] with the redacted issued-token custody so
    /// a caller can continue invalidation without losing its expiry bound.
    #[allow(
        clippy::manual_let_else,
        clippy::single_match_else,
        clippy::too_many_lines
    )]
    pub fn review_token<S: BrokerJournalState>(
        &self,
        journal: &S,
        journal_capability: &BrokerJournalCapability,
        acquisition: &DispatchAcquisitionAuthority,
        issued: JournaledIssuedToken,
    ) -> Result<TokenReviewResult, TokenReviewFailure> {
        let credential_window = match self.issued_credential_window(&issued.issued) {
            Ok(window) => window,
            Err(failure) => {
                return Err(TokenReviewFailure::new(failure, issued, None));
            }
        };
        let current = match self.resolve(acquisition) {
            Ok(current) => current,
            Err(failure) => {
                return Err(TokenReviewFailure::new(failure, issued, None));
            }
        };
        if let Err(failure) = self.validate_current_io_window(
            acquisition,
            &current,
            BrokerOperation::TokenReview,
            Some(credential_window),
        ) {
            return Err(TokenReviewFailure::new(failure, issued, None));
        }
        let selector = issued.receipt.audit().selector();
        let review_authority = match journal.begin_dispatch_credential_review(
            journal_capability,
            acquisition,
            &selector,
        ) {
            Ok(authority) => authority,
            Err(_) => {
                return Err(TokenReviewFailure::new(
                    BrokerFailure::JournalState,
                    issued,
                    None,
                ));
            }
        };
        let recovery_key = review_authority.recovery_key();
        match self.review_token_inner(acquisition, &issued.issued) {
            Ok(ParsedReview::Rejected {
                observed_at,
                evidence_commitment,
            }) => {
                let observation = match RejectedDispatchCredentialReview::new(
                    issued.issued.token_digest,
                    evidence_commitment,
                ) {
                    Ok(observation) => observation,
                    Err(_) => {
                        return Err(TokenReviewFailure::new(
                            BrokerFailure::InvalidObservation {
                                operation: BrokerOperation::TokenReview,
                            },
                            issued,
                            Some(recovery_key),
                        ));
                    }
                };
                if journal
                    .record_rejected_dispatch_credential(review_authority, observation)
                    .is_err()
                {
                    return Err(TokenReviewFailure::new(
                        BrokerFailure::JournalState,
                        issued,
                        Some(recovery_key),
                    ));
                }
                Ok(TokenReviewResult::Rejected(TokenRejectionEvidence {
                    lookup: issued.issued.secret.lookup.clone(),
                    secret_uid: issued.issued.secret.uid.clone(),
                    token_digest: issued.issued.token_digest,
                    observed_at,
                    evidence_commitment,
                }))
            }
            Ok(ParsedReview::Authenticated {
                claims,
                evidence_commitment,
            }) => {
                let reviewed_claims = match DispatchCredentialReviewClaims::new(
                    claims.token_digest,
                    claims.subject,
                    claims.audience,
                    claims.service_account_uid,
                    claims.credential_id,
                    claims.bound_object_uid,
                    claims.not_before,
                    claims.expires_at,
                ) {
                    Ok(claims) => claims,
                    Err(_) => {
                        return Err(TokenReviewFailure::new(
                            BrokerFailure::InvalidObservation {
                                operation: BrokerOperation::TokenReview,
                            },
                            issued,
                            Some(recovery_key),
                        ));
                    }
                };
                let observation = match AuthenticatedDispatchCredentialReview::new(
                    reviewed_claims,
                    evidence_commitment,
                ) {
                    Ok(observation) => observation,
                    Err(_) => {
                        return Err(TokenReviewFailure::new(
                            BrokerFailure::InvalidObservation {
                                operation: BrokerOperation::TokenReview,
                            },
                            issued,
                            Some(recovery_key),
                        ));
                    }
                };
                let recorded =
                    journal.record_authenticated_dispatch_credential(review_authority, observation);
                #[cfg(test)]
                let recorded = if self.review_commit_fault.as_ref().is_some_and(|fault| {
                    fault
                        .hide_record_result_once
                        .swap(false, std::sync::atomic::Ordering::SeqCst)
                }) {
                    recorded.and_then(|hidden| {
                        drop(hidden);
                        Err(StateError::DispatchCredentialReviewOutcomeUnknown)
                    })
                } else {
                    recorded
                };
                let reviewed = match recorded {
                    Ok(reviewed) => reviewed,
                    Err(_) => {
                        #[cfg(test)]
                        if self.review_commit_fault.as_ref().is_some_and(|fault| {
                            fault
                                .fail_first_recovery_once
                                .swap(false, std::sync::atomic::Ordering::SeqCst)
                        }) {
                            return Err(TokenReviewFailure::new(
                                BrokerFailure::JournalState,
                                issued,
                                Some(recovery_key),
                            ));
                        }
                        match journal.recover_authenticated_dispatch_credential(&recovery_key) {
                            Ok(reviewed) => reviewed,
                            Err(_) => {
                                return Err(TokenReviewFailure::new(
                                    BrokerFailure::JournalState,
                                    issued,
                                    Some(recovery_key),
                                ));
                            }
                        }
                    }
                };
                Ok(TokenReviewResult::Authenticated(Box::new(
                    ValidatedCredential {
                        reviewed,
                        bearer: issued.issued.token,
                        review_evidence_commitment: evidence_commitment,
                    },
                )))
            }
            Err(failure) => Err(TokenReviewFailure::new(failure, issued, Some(recovery_key))),
        }
    }

    /// Recovers an authenticated durable `TokenReview` while the same process
    /// still owns the original bearer.
    ///
    /// This path performs no provider I/O. It consumes the opaque post-begin
    /// recovery selector and the journaled bearer together, reloads the exact
    /// authenticated state proof, and then revalidates the same acquisition,
    /// rooted attempt, token claims, policy, activation, and strict time
    /// horizon immediately before returning a credential capability.
    ///
    /// # Errors
    ///
    /// Returns [`TokenReviewFailure`] while preserving bearer custody and the
    /// recovery selector if the durable review is not exactly authenticated,
    /// currentness is lost, or any binding/time check fails.
    #[allow(clippy::manual_let_else, clippy::too_many_lines)]
    pub fn recover_reviewed_token<S: BrokerJournalState>(
        &self,
        journal: &S,
        acquisition: &DispatchAcquisitionAuthority,
        issued: JournaledIssuedToken,
        recovery: TokenReviewRecoveryKey,
    ) -> Result<ValidatedCredential, TokenReviewFailure> {
        let invalid = || BrokerFailure::Authority(AuthorityResolutionError::InvalidRecord);
        let state_key = &recovery.state_key;
        if state_key.key() != acquisition.claim().key()
            || state_key.acquisition_id() != acquisition.acquisition_id()
            || state_key.lease_fence() != acquisition.lease_fence()
        {
            return Err(TokenReviewFailure::new(
                invalid(),
                issued,
                Some(recovery.state_key),
            ));
        }

        let jwt = match validate_bound_token(
            issued.issued.as_bytes(),
            JwtExpectation {
                subject: &self.profile.subject(),
                audience: self.profile.kubernetes_api_audience(),
                namespace: self.profile.namespace(),
                service_account: self.profile.attempt_service_account(),
                service_account_uid: self.profile.attempt_service_account_uid(),
                secret_name: &issued.issued.secret.lookup.bound_secret_name,
                secret_uid: &issued.issued.secret.uid,
                expiration: issued.issued.expires_at,
            },
        ) {
            Ok(jwt) => jwt,
            Err(_) => {
                return Err(TokenReviewFailure::new(
                    BrokerFailure::InvalidObservation {
                        operation: BrokerOperation::TokenReview,
                    },
                    issued,
                    Some(recovery.state_key),
                ));
            }
        };

        let token_audit = issued.receipt.audit();
        let current_token_audit =
            journal.broker_operation_audit(state_key.key(), BrokerJournalOperation::IssueToken);
        if self
            .validate_journal_audit(
                token_audit,
                BrokerJournalOperation::IssueToken,
                BrokerJournalPhase::Committed,
            )
            .is_err()
            || token_audit.outcome() != Some(accordlock_state::BrokerJournalOutcome::TokenIssued)
            || token_audit.key() != state_key.key()
            || token_audit.origin_acquisition_id() != state_key.acquisition_id()
            || token_audit.origin_lease_fence() != state_key.lease_fence()
            || token_audit.bound_secret_uid() != Some(issued.issued.secret.uid.as_str())
            || !matches!(&current_token_audit, Ok(current) if current == token_audit)
        {
            return Err(TokenReviewFailure::new(
                invalid(),
                issued,
                Some(recovery.state_key),
            ));
        }

        let reviewed = match journal.recover_authenticated_dispatch_credential(state_key) {
            Ok(reviewed) => reviewed,
            Err(_) => {
                return Err(TokenReviewFailure::new(
                    BrokerFailure::JournalState,
                    issued,
                    Some(recovery.state_key),
                ));
            }
        };
        let claims = reviewed.claims();
        let expected_credential_id =
            format!("AUTHORIZATION_ID={}", jwt.credential_authorization_id);
        if claims.token_digest().as_bytes() != &issued.issued.token_digest
            || claims.subject() != self.profile.subject()
            || claims.audience() != self.profile.kubernetes_api_audience()
            || claims.service_account_uid() != self.profile.attempt_service_account_uid()
            || claims.credential_id() != expected_credential_id
            || claims.bound_secret_uid() != issued.issued.secret.uid
            || claims.not_before() != jwt.not_before
            || claims.expires_at() != jwt.expires_at
        {
            return Err(TokenReviewFailure::new(
                invalid(),
                issued,
                Some(recovery.state_key),
            ));
        }

        let current = match self.require_current_secret(&issued.issued.secret, acquisition) {
            Ok(current) => current,
            Err(failure) => {
                return Err(TokenReviewFailure::new(
                    failure,
                    issued,
                    Some(recovery.state_key),
                ));
            }
        };
        if reviewed.credential_lifecycle_policy() != current.credential_lifecycle_policy()
            || reviewed.destination_activation_commitment().as_bytes()
                != &current.destination_activation_commitment()
        {
            return Err(TokenReviewFailure::new(
                invalid(),
                issued,
                Some(recovery.state_key),
            ));
        }
        if let Err(failure) = self.validate_current_io_window(
            acquisition,
            &current,
            BrokerOperation::TokenReview,
            Some((jwt.not_before, jwt.expires_at)),
        ) {
            return Err(TokenReviewFailure::new(
                failure,
                issued,
                Some(recovery.state_key),
            ));
        }

        Ok(ValidatedCredential {
            review_evidence_commitment: *reviewed.review_evidence_commitment().as_bytes(),
            reviewed,
            bearer: issued.issued.token,
        })
    }

    /// Deletes the exact Secret with a UID precondition and zero grace under
    /// the sole durable send authority.
    ///
    /// # Errors
    ///
    /// Acknowledgement never proves absence. Even on HTTP 200/202 the durable
    /// row becomes UNKNOWN and only GET reconciliation remains possible.
    pub fn delete_bound_secret<S: BrokerJournalState>(
        &self,
        journal: &S,
        authority: BrokerIoAuthority,
    ) -> Result<JournaledDeletionAcknowledgement, BrokerFailure> {
        let (audit, _lookup, attempt) =
            match self.frozen_io_context(&authority, BrokerJournalOperation::DeleteSecret, journal)
            {
                Ok(context) => context,
                Err(failure) => return Err(burn_io_authority(journal, authority, failure)),
            };
        let secret = match self.bound_secret_from_journal(journal, &audit, &attempt) {
            Ok(secret) => secret,
            Err(failure) => return Err(burn_io_authority(journal, authority, failure)),
        };
        if let Err(failure) = self.require_frozen_secret(&secret, &audit.selector()) {
            return Err(burn_io_authority(journal, authority, failure));
        }
        let acknowledgement =
            match self.delete_bound_secret_unjournaled(journal, &audit, &secret, &attempt) {
                Ok(acknowledgement) => acknowledgement,
                Err(failure) => return Err(burn_io_authority(journal, authority, failure)),
            };
        let journal = journal
            .mark_broker_io_unknown(authority)
            .map_err(|_| BrokerFailure::JournalState)?;
        Ok(JournaledDeletionAcknowledgement {
            acknowledgement,
            journal,
        })
    }

    fn delete_bound_secret_unjournaled<S: BrokerJournalState>(
        &self,
        journal: &S,
        audit: &BrokerOperationAudit,
        secret: &BoundSecret,
        attempt: &TrustedAttemptRecord,
    ) -> Result<DeletionAcknowledgement, BrokerFailure> {
        let requested_at = self.now()?;
        let body = serde_json::to_vec(&json!({
            "apiVersion":"v1",
            "kind":"DeleteOptions",
            "gracePeriodSeconds":0,
            "preconditions":{"uid":secret.uid}
        }))
        .map_err(|_| BrokerFailure::DefinitelyNotSent {
            operation: BrokerOperation::DeleteSecret,
            reason: FailureReason::InvalidRequest,
        })?;
        let path = secret_path(self.profile.namespace(), &secret.lookup.bound_secret_name);
        let response = self.exchange(
            secret_delete_management_operation(&self.profile, secret),
            &path,
            Some("application/json"),
            WireBody::Bytes(&body),
            None,
            || self.revalidate_frozen_send(journal, audit, &secret.lookup, attempt),
        )?;
        self.revalidate_frozen_send(journal, audit, &secret.lookup, attempt)
            .map_err(|_| post_send_unknown(BrokerOperation::DeleteSecret, None))?;
        if !matches!(response.status, 200 | 202) {
            return Err(mutation_status_failure(
                BrokerOperation::DeleteSecret,
                response.status,
                None,
            ));
        }
        if !valid_delete_response(response.body()) {
            return Err(BrokerFailure::OutcomeUnknown {
                operation: BrokerOperation::DeleteSecret,
                reason: FailureReason::InvalidProviderResponse,
                conservative_credential_safe_after: None,
            });
        }
        Ok(DeletionAcknowledgement {
            lookup: secret.lookup.clone(),
            secret_uid: secret.uid.clone(),
            requested_at,
            status: response.status,
            evidence_commitment: response_evidence(BrokerOperation::DeleteSecret, &response),
        })
    }

    /// Assesses retirement from exact GET-404 plus the configured conservative
    /// invalidation delay. A `TokenReview` rejection is checked for exact
    /// binding and ordering but never shortens the propagation bound.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerFailure`] for mismatched evidence or trusted-time error.
    pub fn assess_retirement(
        &self,
        deletion: &DeletionEvidence,
        rejection: Option<&TokenRejectionEvidence>,
    ) -> Result<RetirementAssessment, BrokerFailure> {
        assess_retirement_at(&self.profile, deletion, rejection, self.now()?)
    }

    /// Assesses restart retirement from state-authenticated durable absence,
    /// without authorizing HTTP. Optional rejection facts are validated but do
    /// not shorten the rooted deletion-propagation bound.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerFailure`] for malformed temporal ordering, arithmetic
    /// overflow, or unavailable trusted time.
    pub fn assess_recovered_retirement(
        &self,
        evidence: &DispatchRestartDeletionEvidence,
    ) -> Result<RetirementAssessment, BrokerFailure> {
        let absent_at = evidence.absent_observed_at();
        if absent_at < 0 {
            return Err(BrokerFailure::InvalidObservation {
                operation: BrokerOperation::GetSecret,
            });
        }
        if evidence
            .rejection_observed_at()
            .is_some_and(|rejected_at| rejected_at < absent_at)
        {
            return Err(BrokerFailure::InvalidObservation {
                operation: BrokerOperation::TokenReview,
            });
        }
        let policy = evidence.credential_lifecycle_policy();
        let safe_after = absent_at
            .checked_add(policy.deletion_propagation_hard_max_seconds())
            .and_then(|value| value.checked_add(policy.clock_uncertainty_seconds()))
            .ok_or(BrokerFailure::Clock)?;
        if self.now()? >= safe_after {
            Ok(RetirementAssessment::Confirmed(
                RetirementBasis::ConservativeInvalidationDelayElapsed,
            ))
        } else {
            Ok(RetirementAssessment::Pending { safe_after })
        }
    }

    fn review_token_inner(
        &self,
        acquisition: &DispatchAcquisitionAuthority,
        issued: &IssuedToken,
    ) -> Result<ParsedReview, BrokerFailure> {
        let attempt = self.require_current_secret(&issued.secret, acquisition)?;
        let credential_window = self.issued_credential_window(issued)?;
        self.validate_current_io_window(
            acquisition,
            &attempt,
            BrokerOperation::TokenReview,
            Some(credential_window),
        )?;
        let audience_json =
            serde_json::to_string(self.profile.kubernetes_api_audience()).map_err(|_| {
                BrokerFailure::DefinitelyNotSent {
                    operation: BrokerOperation::TokenReview,
                    reason: FailureReason::InvalidRequest,
                }
            })?;
        let prefix = format!(
            "{{\"apiVersion\":\"authentication.k8s.io/v1\",\"kind\":\"TokenReview\",\"spec\":{{\"audiences\":[{audience_json}],\"token\":\""
        );
        let suffix = b"\"}}";
        let response = self.exchange(
            token_review_management_operation(&self.profile, issued),
            "/apis/authentication.k8s.io/v1/tokenreviews",
            Some("application/json"),
            WireBody::TokenReview {
                prefix: prefix.as_bytes(),
                token: issued.as_bytes(),
                suffix,
            },
            issued
                .expires_at
                .checked_add(self.profile.clock_uncertainty_seconds),
            || {
                let current = self.resolve(acquisition)?;
                if current != issued.secret.attempt {
                    return Err(BrokerFailure::Authority(
                        AuthorityResolutionError::InvalidRecord,
                    ));
                }
                self.validate_current_io_window(
                    acquisition,
                    &current,
                    BrokerOperation::TokenReview,
                    Some(credential_window),
                )?;
                Ok(())
            },
        )?;
        if response.status != 201 {
            return Err(BrokerFailure::ProviderRejected {
                operation: BrokerOperation::TokenReview,
                status: response.status,
            });
        }
        let observed_at = self.now()?;
        let evidence = response_evidence(BrokerOperation::TokenReview, &response);
        let parsed = parse_token_review_response(
            response.body(),
            &self.profile,
            issued,
            observed_at,
            evidence,
        )
        .ok_or(BrokerFailure::InvalidObservation {
            operation: BrokerOperation::TokenReview,
        })?;
        if matches!(parsed, ParsedReview::Authenticated { .. }) {
            let current = self.resolve(acquisition)?;
            if current != issued.secret.attempt {
                return Err(BrokerFailure::Authority(
                    AuthorityResolutionError::InvalidRecord,
                ));
            }
        }
        Ok(parsed)
    }

    fn issued_credential_window(&self, issued: &IssuedToken) -> Result<(i64, i64), BrokerFailure> {
        let jwt = validate_bound_token(
            issued.as_bytes(),
            JwtExpectation {
                subject: &self.profile.subject(),
                audience: self.profile.kubernetes_api_audience(),
                namespace: self.profile.namespace(),
                service_account: self.profile.attempt_service_account(),
                service_account_uid: self.profile.attempt_service_account_uid(),
                secret_name: &issued.secret.lookup.bound_secret_name,
                secret_uid: &issued.secret.uid,
                expiration: issued.expires_at,
            },
        )
        .map_err(|_| BrokerFailure::InvalidObservation {
            operation: BrokerOperation::TokenReview,
        })?;
        Ok((jwt.not_before, jwt.expires_at))
    }

    fn current_io_context<S: BrokerJournalState>(
        &self,
        authority: &BrokerIoAuthority,
        expected_operation: BrokerJournalOperation,
        journal: &S,
        acquisition: &DispatchAcquisitionAuthority,
    ) -> Result<(BrokerOperationAudit, AttemptLookup, TrustedAttemptRecord), BrokerFailure> {
        let audit = authority.audit();
        self.validate_journal_audit(&audit, expected_operation, BrokerJournalPhase::InFlight)?;
        let current = journal
            .broker_operation_audit(audit.key(), expected_operation)
            .map_err(|_| BrokerFailure::JournalState)?;
        if current != audit {
            return Err(BrokerFailure::JournalState);
        }
        let lookup = AttemptLookup::new(
            audit.key().transaction_id,
            audit.bound_secret_name().to_owned(),
        )
        .map_err(|_| BrokerFailure::Authority(AuthorityResolutionError::InvalidRecord))?;
        if matches!(expected_operation, BrokerJournalOperation::DeleteSecret)
            || audit.origin_acquisition_id() != acquisition.acquisition_id()
            || audit.origin_lease_fence() != acquisition.lease_fence()
            || audit.key() != acquisition.claim().key()
        {
            return Err(BrokerFailure::Authority(
                AuthorityResolutionError::InvalidRecord,
            ));
        }
        let attempt = self.resolve(acquisition)?;
        if attempt.lookup() != &lookup {
            return Err(BrokerFailure::Authority(
                AuthorityResolutionError::InvalidRecord,
            ));
        }
        Ok((audit, lookup, attempt))
    }

    fn frozen_io_context<S: BrokerJournalState>(
        &self,
        authority: &BrokerIoAuthority,
        expected_operation: BrokerJournalOperation,
        journal: &S,
    ) -> Result<(BrokerOperationAudit, AttemptLookup, TrustedAttemptRecord), BrokerFailure> {
        let audit = authority.audit();
        self.validate_journal_audit(&audit, expected_operation, BrokerJournalPhase::InFlight)?;
        let current = journal
            .broker_operation_audit(audit.key(), expected_operation)
            .map_err(|_| BrokerFailure::JournalState)?;
        if current != audit || !matches!(expected_operation, BrokerJournalOperation::DeleteSecret) {
            return Err(BrokerFailure::JournalState);
        }
        let lookup = AttemptLookup::new(
            audit.key().transaction_id,
            audit.bound_secret_name().to_owned(),
        )
        .map_err(|_| BrokerFailure::Authority(AuthorityResolutionError::InvalidRecord))?;
        let attempt = self.resolve_frozen_cleanup(&audit.selector())?;
        if attempt.lookup() != &lookup {
            return Err(BrokerFailure::Authority(
                AuthorityResolutionError::InvalidRecord,
            ));
        }
        Ok((audit, lookup, attempt))
    }

    fn reconciliation_context<S: BrokerJournalState>(
        &self,
        authority: &BrokerReconciliationAuthority,
        journal: &S,
    ) -> Result<(BrokerOperationAudit, AttemptLookup, TrustedAttemptRecord), BrokerFailure> {
        let audit = authority.audit();
        self.validate_journal_audit(
            &audit,
            authority.operation(),
            BrokerJournalPhase::ReconcileOnly,
        )?;
        let current = journal
            .broker_operation_audit(audit.key(), audit.operation())
            .map_err(|_| BrokerFailure::JournalState)?;
        if current != audit {
            return Err(BrokerFailure::JournalState);
        }
        let lookup = AttemptLookup::new(
            audit.key().transaction_id,
            audit.bound_secret_name().to_owned(),
        )
        .map_err(|_| BrokerFailure::Authority(AuthorityResolutionError::InvalidRecord))?;
        let attempt = self.resolve_frozen_cleanup(&audit.selector())?;
        if attempt.lookup() != &lookup {
            return Err(BrokerFailure::Authority(
                AuthorityResolutionError::InvalidRecord,
            ));
        }
        Ok((audit, lookup, attempt))
    }

    fn validate_journal_audit(
        &self,
        audit: &BrokerOperationAudit,
        expected_operation: BrokerJournalOperation,
        expected_phase: BrokerJournalPhase,
    ) -> Result<(), BrokerFailure> {
        self.ensure_route_integrity()?;
        let route = self.profile.route_profile();
        let physical = audit.physical_resource();
        if audit.operation() != expected_operation
            || audit.phase() != expected_phase
            || audit.started_at().is_none()
            || audit.route_commitment().as_bytes() != route.commitment().as_bytes()
            || physical.cluster_identity() != route.cluster_identity()
            || physical.namespace() != route.namespace()
            || physical.deployment_uid() != route.deployment_uid()
            || audit.bound_secret_name() != deterministic_secret_name(audit.key().transaction_id)
        {
            return Err(BrokerFailure::Authority(
                AuthorityResolutionError::InvalidRecord,
            ));
        }
        let valid_operation_binding = match expected_operation {
            BrokerJournalOperation::CreateSecret => {
                audit.bound_secret_uid().is_none()
                    && audit.credential_policy().is_none()
                    && audit.credential_safe_after().is_none()
            }
            BrokerJournalOperation::IssueToken => {
                let Some(policy) = audit.credential_policy() else {
                    return Err(BrokerFailure::Authority(
                        AuthorityResolutionError::InvalidRecord,
                    ));
                };
                let expected_safe_after = audit
                    .started_at()
                    .and_then(|started| started.checked_add(policy.lifetime_upper_bound_seconds()))
                    .and_then(|value| value.checked_add(policy.clock_uncertainty_seconds()));
                audit.bound_secret_uid().is_some()
                    && policy.lifetime_upper_bound_seconds()
                        == self.profile.server_lifetime_upper_bound_seconds
                    && policy.clock_uncertainty_seconds() == self.profile.clock_uncertainty_seconds
                    && audit.credential_safe_after() == expected_safe_after
            }
            BrokerJournalOperation::DeleteSecret => {
                audit.bound_secret_uid().is_some()
                    && audit.credential_policy().is_none()
                    && audit.credential_safe_after().is_none()
            }
        };
        if !valid_operation_binding {
            return Err(BrokerFailure::Authority(
                AuthorityResolutionError::InvalidRecord,
            ));
        }
        Ok(())
    }

    fn bound_secret_from_journal<S: BrokerJournalState>(
        &self,
        journal: &S,
        operation: &BrokerOperationAudit,
        attempt: &TrustedAttemptRecord,
    ) -> Result<BoundSecret, BrokerFailure> {
        let create = journal
            .broker_operation_audit(operation.key(), BrokerJournalOperation::CreateSecret)
            .map_err(|_| BrokerFailure::JournalState)?;
        let uid = operation
            .bound_secret_uid()
            .ok_or(BrokerFailure::Authority(
                AuthorityResolutionError::InvalidRecord,
            ))?;
        if create.phase() != BrokerJournalPhase::Committed
            || create.outcome() != Some(accordlock_state::BrokerJournalOutcome::CreateMatching)
            || create.key() != operation.key()
            || create.claim_id() != operation.claim_id()
            || create.fence() != operation.fence()
            || create.physical_resource() != operation.physical_resource()
            || create.route_commitment() != operation.route_commitment()
            || create.bound_secret_name() != operation.bound_secret_name()
            || create.bound_secret_uid() != Some(uid)
        {
            return Err(BrokerFailure::Authority(
                AuthorityResolutionError::InvalidRecord,
            ));
        }
        let creation_evidence_commitment = create
            .result_commitment()
            .map(|commitment| *commitment.as_bytes())
            .ok_or(BrokerFailure::JournalState)?;
        Ok(BoundSecret {
            lookup: attempt.lookup.clone(),
            namespace: self.profile.namespace().to_owned(),
            uid: uid.to_owned(),
            subject: self.profile.subject(),
            audience: self.profile.kubernetes_api_audience().to_owned(),
            attempt: attempt.clone(),
            creation_evidence_commitment,
        })
    }

    fn resolve(
        &self,
        acquisition: &DispatchAcquisitionAuthority,
    ) -> Result<TrustedAttemptRecord, BrokerFailure> {
        self.ensure_route_integrity()?;
        let record = self
            .authority
            .load_current(acquisition)
            .map_err(BrokerFailure::Authority)?;
        let lookup = AttemptLookup::for_transaction(acquisition.claim().key().transaction_id);
        self.validate_attempt_record(&record, &lookup)?;
        Ok(record)
    }

    fn resolve_frozen_cleanup(
        &self,
        selector: &BrokerJournalSelector,
    ) -> Result<TrustedAttemptRecord, BrokerFailure> {
        self.ensure_route_integrity()?;
        let record = self
            .authority
            .load_frozen_cleanup(selector)
            .map_err(BrokerFailure::Authority)?;
        let lookup = AttemptLookup::for_transaction(selector.key().transaction_id);
        self.validate_attempt_record(&record, &lookup)?;
        Ok(record)
    }

    fn validate_attempt_record(
        &self,
        record: &TrustedAttemptRecord,
        lookup: &AttemptLookup,
    ) -> Result<(), BrokerFailure> {
        record
            .validate_internal()
            .map_err(BrokerFailure::Authority)?;
        let expected_policy = self
            .profile
            .credential_lifecycle_policy()
            .map_err(BrokerFailure::Authority)?;
        let bindings = record.broker_management_bindings();
        let configured = &self.management_identities;
        let management_matches = [
            (bindings.secret_lifecycle(), configured.secret_lifecycle()),
            (
                bindings.service_account_token(),
                configured.service_account_token(),
            ),
            (bindings.token_review(), configured.token_review()),
        ]
        .into_iter()
        .all(|(rooted, local)| {
            rooted.subject() == local.subject()
                && rooted.rbac_commitment() == local.authorization_commitment()
        });
        if record.lookup() != lookup
            || record
                .route()
                .first_mismatch(self.profile.route_profile())
                .is_some()
            || record.token_subject() != self.profile.subject()
            || record.service_account_uid() != self.profile.attempt_service_account_uid()
            || record.token_audience() != self.profile.kubernetes_api_audience()
            || record.credential_lifecycle_policy() != expected_policy
            || record.credential_lifecycle_commitment() != expected_policy.commitment()
            || record.credential_lifecycle_policy_id() != expected_policy.policy_id()
            || !management_matches
        {
            return Err(BrokerFailure::Authority(
                AuthorityResolutionError::InvalidRecord,
            ));
        }
        Ok(())
    }

    fn ensure_route_integrity(&self) -> Result<(), BrokerFailure> {
        self.profile
            .route_profile()
            .first_mismatch(self.http.route_profile())
            .map_or(Ok(()), |field| Err(BrokerFailure::RouteMismatch(field)))
    }

    fn require_current_secret(
        &self,
        secret: &BoundSecret,
        acquisition: &DispatchAcquisitionAuthority,
    ) -> Result<TrustedAttemptRecord, BrokerFailure> {
        if secret.namespace != self.profile.namespace()
            || secret.subject != self.profile.subject()
            || secret.audience != self.profile.kubernetes_api_audience()
        {
            return Err(BrokerFailure::Authority(
                AuthorityResolutionError::InvalidRecord,
            ));
        }
        let record = self.resolve(acquisition)?;
        if record != secret.attempt {
            return Err(BrokerFailure::Authority(
                AuthorityResolutionError::InvalidRecord,
            ));
        }
        Ok(record)
    }

    fn require_frozen_secret(
        &self,
        secret: &BoundSecret,
        selector: &BrokerJournalSelector,
    ) -> Result<TrustedAttemptRecord, BrokerFailure> {
        if secret.namespace != self.profile.namespace()
            || secret.subject != self.profile.subject()
            || secret.audience != self.profile.kubernetes_api_audience()
        {
            return Err(BrokerFailure::Authority(
                AuthorityResolutionError::InvalidRecord,
            ));
        }
        let record = self.resolve_frozen_cleanup(selector)?;
        if record != secret.attempt {
            return Err(BrokerFailure::Authority(
                AuthorityResolutionError::InvalidRecord,
            ));
        }
        Ok(record)
    }

    fn get_secret<S: BrokerJournalState>(
        &self,
        journal: &S,
        audit: &BrokerOperationAudit,
        lookup: &AttemptLookup,
        attempt: &TrustedAttemptRecord,
        safe_after: Option<i64>,
    ) -> Result<WireResponse, BrokerFailure> {
        let path = secret_path(self.profile.namespace(), &lookup.bound_secret_name);
        self.exchange(
            secret_get_management_operation(&self.profile, lookup),
            &path,
            None,
            WireBody::Empty,
            safe_after,
            || self.revalidate_frozen_send(journal, audit, lookup, attempt),
        )
    }

    fn exchange<F>(
        &self,
        management_operation: BrokerManagementOperation,
        path: &str,
        content_type: Option<&str>,
        body: WireBody<'_>,
        conservative_safe_after: Option<i64>,
        immediately_before_send: F,
    ) -> Result<WireResponse, BrokerFailure>
    where
        F: FnOnce() -> Result<(), BrokerFailure>,
    {
        self.ensure_route_integrity()?;
        let operation = management_operation.broker_operation();
        let wire_operation = management_operation.wire_operation();
        let management = self.management_credential(management_operation)?;
        #[cfg(test)]
        if let Some(script) = &self.scripted_exchanges {
            // Scripted exchanges have no TCP/TLS phase. Preserve the same
            // pre-first-byte ordering and do not consume a script when the
            // boundary rejects the send.
            immediately_before_send()?;
            let scripted = script
                .lock()
                .map_err(|_| BrokerFailure::JournalState)?
                .pop_front()
                .ok_or(BrokerFailure::DefinitelyNotSent {
                    operation,
                    reason: FailureReason::Connect,
                })?;
            return match scripted {
                ScriptedExchange::Response {
                    status,
                    body: response_body,
                } => Ok(WireResponse::for_test(
                    wire_operation,
                    path,
                    content_type,
                    body,
                    status,
                    self.profile
                        .route_profile()
                        .api_server_identity()
                        .to_owned(),
                    response_body,
                )),
                ScriptedExchange::ResponseThen {
                    status,
                    body: response_body,
                    before_return,
                } => {
                    before_return();
                    Ok(WireResponse::for_test(
                        wire_operation,
                        path,
                        content_type,
                        body,
                        status,
                        self.profile
                            .route_profile()
                            .api_server_identity()
                            .to_owned(),
                        response_body,
                    ))
                }
                ScriptedExchange::Failure(failure) => Err(failure),
            };
        }
        self.http
            .exchange(
                wire_operation,
                path,
                management.as_bytes(),
                content_type,
                body,
                immediately_before_send,
            )
            .map_err(|failure| match failure {
                GuardedWireFailure::GuardRejected(failure) => failure,
                GuardedWireFailure::Wire(failure) => {
                    map_wire_failure(operation, failure, conservative_safe_after)
                }
            })
    }

    fn revalidate_current_send<S: BrokerJournalState>(
        &self,
        journal: &S,
        expected_audit: &BrokerOperationAudit,
        lookup: &AttemptLookup,
        expected_attempt: &TrustedAttemptRecord,
        acquisition: &DispatchAcquisitionAuthority,
    ) -> Result<(), BrokerFailure> {
        Self::revalidate_journal_generation(journal, expected_audit)?;
        let current = self.resolve(acquisition)?;
        if current.lookup() != lookup {
            return Err(BrokerFailure::Authority(
                AuthorityResolutionError::InvalidRecord,
            ));
        }
        if &current != expected_attempt {
            return Err(BrokerFailure::Authority(
                AuthorityResolutionError::InvalidRecord,
            ));
        }
        let operation = match expected_audit.operation() {
            BrokerJournalOperation::CreateSecret => BrokerOperation::CreateSecret,
            BrokerJournalOperation::IssueToken => BrokerOperation::TokenRequest,
            BrokerJournalOperation::DeleteSecret => {
                return Err(BrokerFailure::Authority(
                    AuthorityResolutionError::InvalidRecord,
                ));
            }
        };
        self.validate_current_io_window(acquisition, &current, operation, None)?;
        Ok(())
    }

    fn revalidate_frozen_send<S: BrokerJournalState>(
        &self,
        journal: &S,
        expected_audit: &BrokerOperationAudit,
        lookup: &AttemptLookup,
        expected_attempt: &TrustedAttemptRecord,
    ) -> Result<(), BrokerFailure> {
        let frozen = self.resolve_frozen_cleanup(&expected_audit.selector())?;
        Self::revalidate_journal_generation(journal, expected_audit)?;
        if frozen.lookup() != lookup || &frozen != expected_attempt {
            return Err(BrokerFailure::Authority(
                AuthorityResolutionError::InvalidRecord,
            ));
        }
        Ok(())
    }

    fn revalidate_journal_generation<S: BrokerJournalState>(
        journal: &S,
        expected: &BrokerOperationAudit,
    ) -> Result<(), BrokerFailure> {
        let current = journal
            .broker_operation_audit(expected.key(), expected.operation())
            .map_err(|_| BrokerFailure::JournalState)?;
        if current != *expected {
            return Err(BrokerFailure::JournalState);
        }
        Ok(())
    }

    fn management_credential(
        &self,
        operation: BrokerManagementOperation,
    ) -> Result<ManagementBearer, BrokerFailure> {
        self.ensure_route_integrity()?;
        let identity = self
            .management_identities
            .identity(operation.authority())
            .clone();
        let request = ManagementCredentialRequest::new(operation, identity);
        let management = self
            .management_credentials
            .credential(&request)
            .map_err(BrokerFailure::CredentialSource)?;
        management
            .validate_for(&request)
            .map_err(BrokerFailure::CredentialSource)?;
        Ok(management)
    }

    fn now(&self) -> Result<i64, BrokerFailure> {
        self.clock
            .unix_seconds()
            .map_err(|_| BrokerFailure::Clock)
            .and_then(|value| {
                if value < 0 {
                    Err(BrokerFailure::Clock)
                } else {
                    Ok(value)
                }
            })
    }

    fn validate_current_io_window(
        &self,
        acquisition: &DispatchAcquisitionAuthority,
        current: &TrustedAttemptRecord,
        operation: BrokerOperation,
        credential_window: Option<(i64, i64)>,
    ) -> Result<(), BrokerFailure> {
        let now = self.now()?;
        let timeout = duration_ceiling_seconds(self.http.operation_timeout_upper_bound())
            .ok_or(BrokerFailure::Clock)?;
        let uncertainty = current
            .credential_lifecycle_policy()
            .clock_uncertainty_seconds();
        let safe_through = now
            .checked_add(timeout)
            .and_then(|value| value.checked_add(uncertainty))
            .ok_or(BrokerFailure::Clock)?;
        let earliest = now.checked_sub(uncertainty).ok_or(BrokerFailure::Clock)?;
        let credential_valid = credential_window.is_none_or(|(not_before, expires_at)| {
            not_before >= 0
                && expires_at > not_before
                && earliest >= not_before
                && safe_through < expires_at
        });
        if now < acquisition.acquired_at()
            || safe_through >= acquisition.lease_until()
            || safe_through >= acquisition.dispatch_deadline()
            || !credential_valid
        {
            return Err(BrokerFailure::DefinitelyNotSent {
                operation,
                reason: FailureReason::Deadline,
            });
        }
        Ok(())
    }
}

fn duration_ceiling_seconds(duration: Duration) -> Option<i64> {
    let seconds = duration
        .as_secs()
        .checked_add(u64::from(duration.subsec_nanos() != 0))?;
    i64::try_from(seconds).ok()
}

fn burn_io_authority<S: BrokerJournalState>(
    journal: &S,
    authority: BrokerIoAuthority,
    failure: BrokerFailure,
) -> BrokerFailure {
    match journal.mark_broker_io_unknown(authority) {
        Ok(_) => failure,
        Err(_) => BrokerFailure::JournalState,
    }
}

fn finish_token_commit(
    issued: IssuedToken,
    committed: Result<BrokerOperationReceipt, StateError>,
) -> Result<JournaledIssuedToken, BrokerFailure> {
    let receipt = committed.map_err(|_| BrokerFailure::JournalState)?;
    Ok(JournaledIssuedToken { issued, receipt })
}

fn state_secret_observation(
    observed: &SecretObservation,
) -> Result<BrokerSecretObservation, BrokerFailure> {
    let result = match observed {
        SecretObservation::Matching(secret) => BrokerSecretObservation::matching(
            secret.uid.clone(),
            secret.creation_evidence_commitment,
        ),
        SecretObservation::Absent {
            evidence_commitment,
            ..
        } => BrokerSecretObservation::absent(*evidence_commitment),
        SecretObservation::Conflicting {
            evidence_commitment,
            ..
        } => BrokerSecretObservation::conflicting(*evidence_commitment),
    };
    result.map_err(|_| BrokerFailure::InvalidObservation {
        operation: BrokerOperation::GetSecret,
    })
}

fn finish_create_reconciliation(
    observed: SecretObservation,
    result: BrokerReconciliationResult,
) -> JournaledSecretReconciliation {
    match result {
        BrokerReconciliationResult::Pending(authority) => JournaledSecretReconciliation::Pending {
            audit: authority.audit(),
        },
        BrokerReconciliationResult::Completed(receipt) => match observed {
            SecretObservation::Matching(secret)
                if receipt.audit().phase() == BrokerJournalPhase::Committed =>
            {
                JournaledSecretReconciliation::CreateCommitted { secret, receipt }
            }
            SecretObservation::Absent { .. }
            | SecretObservation::Conflicting { .. }
            | SecretObservation::Matching(_) => JournaledSecretReconciliation::Terminal { receipt },
        },
    }
}

fn finish_delete_reconciliation(
    deletion: Option<DeletionEvidence>,
    result: BrokerReconciliationResult,
) -> JournaledSecretReconciliation {
    match result {
        BrokerReconciliationResult::Pending(authority) => JournaledSecretReconciliation::Pending {
            audit: authority.audit(),
        },
        BrokerReconciliationResult::Completed(receipt) => match deletion {
            Some(deletion) if receipt.audit().phase() == BrokerJournalPhase::Committed => {
                JournaledSecretReconciliation::DeleteCommitted { deletion, receipt }
            }
            Some(_) | None => JournaledSecretReconciliation::Terminal { receipt },
        },
    }
}

enum ParsedReview {
    Rejected {
        observed_at: i64,
        evidence_commitment: [u8; 32],
    },
    Authenticated {
        claims: CredentialClaims,
        evidence_commitment: [u8; 32],
    },
}

/// Rejects duplicate JSON object keys before security-relevant `Value`
/// traversal. `serde_json::Value` alone would silently retain the last key.
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

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
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
            if !keys.insert(key) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            let _: DuplicateRejectingJson = map.next_value()?;
        }
        Ok(DuplicateRejectingJson)
    }
}

fn validate_config(config: &BrokerConfig) -> Result<(), BrokerConfigError> {
    let endpoint = &config.endpoint;
    let loaded_ca_commitment = CaTrustCommitment::from_der_certificates(
        &endpoint.ca_certificates_der,
    )
    .map_err(|error| match error {
        CaTrustError::InvalidCertificateCount
        | CaTrustError::InvalidCertificateSize
        | CaTrustError::DuplicateCertificate
        | CaTrustError::ZeroCommitment => BrokerConfigError::InvalidCaBundle,
    })?;
    if loaded_ca_commitment != config.profile.route_profile().ca_trust_commitment() {
        return Err(BrokerConfigError::CaTrustCommitmentMismatch);
    }
    if !(MIN_TIMEOUT..=MAX_TIMEOUT).contains(&endpoint.connect_timeout)
        || !(MIN_TIMEOUT..=MAX_TIMEOUT).contains(&endpoint.operation_timeout)
        || endpoint.connect_timeout > endpoint.operation_timeout
        || endpoint.max_request_body_bytes == 0
        || endpoint.max_request_body_bytes > 16 * 1024 * 1024
        || endpoint.max_response_header_bytes < 1024
        || endpoint.max_response_header_bytes > 256 * 1024
        || endpoint.max_response_body_bytes == 0
        || endpoint.max_response_body_bytes > 64 * 1024 * 1024
    {
        return Err(BrokerConfigError::InvalidTransportBounds);
    }
    let profile = &config.profile;
    if profile.requested_expiration_seconds <= 0
        || profile.server_lifetime_upper_bound_seconds < profile.requested_expiration_seconds
        || profile.server_lifetime_upper_bound_seconds > 86_400
        || !(0..=300).contains(&profile.clock_uncertainty_seconds)
        || !(MIN_INVALIDATION_DELAY_SECONDS..=86_400).contains(&profile.invalidation_delay_seconds)
    {
        return Err(BrokerConfigError::InvalidProfile);
    }
    Ok(())
}

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_bearer(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.len() <= 64 * 1024
        && bytes.iter().copied().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
        })
}

fn secret_create_management_operation(
    profile: &BrokerProfile,
    lookup: &AttemptLookup,
) -> BrokerManagementOperation {
    BrokerManagementOperation::SecretCreate {
        route_commitment: profile.route_profile().commitment(),
        namespace: profile.namespace().to_owned(),
        secret_name: lookup.bound_secret_name.clone(),
    }
}

fn secret_get_management_operation(
    profile: &BrokerProfile,
    lookup: &AttemptLookup,
) -> BrokerManagementOperation {
    BrokerManagementOperation::SecretGet {
        route_commitment: profile.route_profile().commitment(),
        namespace: profile.namespace().to_owned(),
        secret_name: lookup.bound_secret_name.clone(),
    }
}

fn secret_delete_management_operation(
    profile: &BrokerProfile,
    secret: &BoundSecret,
) -> BrokerManagementOperation {
    BrokerManagementOperation::SecretDelete {
        route_commitment: profile.route_profile().commitment(),
        namespace: profile.namespace().to_owned(),
        secret_name: secret.lookup.bound_secret_name.clone(),
        secret_uid: secret.uid.clone(),
    }
}

fn token_request_management_operation(
    profile: &BrokerProfile,
    secret: &BoundSecret,
) -> BrokerManagementOperation {
    BrokerManagementOperation::ServiceAccountTokenCreate {
        route_commitment: profile.route_profile().commitment(),
        namespace: profile.namespace().to_owned(),
        service_account_name: profile.attempt_service_account().to_owned(),
        service_account_uid: profile.attempt_service_account_uid().to_owned(),
        audience: profile.kubernetes_api_audience().to_owned(),
        bound_secret_name: secret.lookup.bound_secret_name.clone(),
        bound_secret_uid: secret.uid.clone(),
    }
}

fn token_review_management_operation(
    profile: &BrokerProfile,
    issued: &IssuedToken,
) -> BrokerManagementOperation {
    BrokerManagementOperation::TokenReviewCreate {
        route_commitment: profile.route_profile().commitment(),
        audience: profile.kubernetes_api_audience().to_owned(),
        reviewed_token_commitment: issued.token_digest,
    }
}

fn exact_labels(
    profile: &BrokerProfile,
    record: &TrustedAttemptRecord,
) -> BTreeMap<&'static str, String> {
    let audience_commitment = Sha256::digest(profile.kubernetes_api_audience().as_bytes());
    BTreeMap::from([
        (PROFILE_LABEL, PROFILE_VALUE.to_owned()),
        (TRANSACTION_LABEL, record.lookup.transaction_id.to_string()),
        (
            TEMPLATE_LABEL,
            URL_SAFE_NO_PAD.encode(record.commitments.template_hash),
        ),
        (
            OPERATION_LABEL,
            URL_SAFE_NO_PAD.encode(record.commitments.operation_hash),
        ),
        (
            COMMAND_LABEL,
            URL_SAFE_NO_PAD.encode(record.commitments.execution_command_commitment),
        ),
        (
            PROVIDER_LABEL,
            URL_SAFE_NO_PAD.encode(record.commitments.provider_request_commitment),
        ),
        (
            RBAC_LABEL,
            URL_SAFE_NO_PAD.encode(record.commitments.effective_rbac_commitment),
        ),
        (
            SERVICE_ACCOUNT_UID_LABEL,
            profile.attempt_service_account_uid().to_owned(),
        ),
        (AUDIENCE_LABEL, URL_SAFE_NO_PAD.encode(audience_commitment)),
    ])
}

fn secret_path(namespace: &str, name: &str) -> String {
    format!("/api/v1/namespaces/{namespace}/secrets/{name}")
}

fn parse_matching_secret(
    body: &[u8],
    profile: &BrokerProfile,
    record: &TrustedAttemptRecord,
    evidence_commitment: [u8; 32],
) -> Option<BoundSecret> {
    let value: Value = serde_json::from_slice(body).ok()?;
    if value.pointer("/apiVersion").and_then(Value::as_str) != Some("v1")
        || value.pointer("/kind").and_then(Value::as_str) != Some("Secret")
        || value.pointer("/metadata/name").and_then(Value::as_str)
            != Some(&record.lookup.bound_secret_name)
        || value.pointer("/metadata/namespace").and_then(Value::as_str) != Some(profile.namespace())
        || value.pointer("/type").and_then(Value::as_str) != Some("Opaque")
        || value.pointer("/immutable").and_then(Value::as_bool) != Some(true)
        || value.pointer("/metadata/deletionTimestamp").is_some()
        || !absent_or_empty_array(value.pointer("/metadata/finalizers"))
        || !absent_or_empty_array(value.pointer("/metadata/ownerReferences"))
        || value
            .pointer("/metadata/generateName")
            .is_some_and(|candidate| candidate.as_str().is_none_or(|text| !text.is_empty()))
        || value
            .pointer("/data")
            .is_some_and(|candidate| candidate.as_object().is_none_or(|map| !map.is_empty()))
    {
        return None;
    }
    let labels = value.pointer("/metadata/labels")?.as_object()?;
    if !labels_match(labels, &exact_labels(profile, record)) {
        return None;
    }
    let uid = value
        .pointer("/metadata/uid")?
        .as_str()
        .filter(|candidate| valid_text(candidate, 512))?
        .to_owned();
    Some(BoundSecret {
        lookup: record.lookup.clone(),
        namespace: profile.namespace().to_owned(),
        uid,
        subject: profile.subject(),
        audience: profile.kubernetes_api_audience().to_owned(),
        attempt: record.clone(),
        creation_evidence_commitment: evidence_commitment,
    })
}

fn absent_or_empty_array(value: Option<&Value>) -> bool {
    value.is_none_or(|candidate| candidate.as_array().is_some_and(Vec::is_empty))
}

fn labels_match(actual: &Map<String, Value>, expected: &BTreeMap<&str, String>) -> bool {
    actual.len() == expected.len()
        && expected.iter().all(|(key, value)| {
            actual
                .get(*key)
                .and_then(Value::as_str)
                .is_some_and(|candidate| candidate == value)
        })
}

fn parse_token_request_response(
    body: &[u8],
    profile: &BrokerProfile,
    secret: &BoundSecret,
    request_started_at: i64,
    returned_at: i64,
) -> Option<(SecretToken, i64)> {
    let mut value: Value = serde_json::from_slice(body).ok()?;
    let token_value = value
        .as_object_mut()?
        .get_mut("status")?
        .as_object_mut()?
        .remove("token")?;
    let token = match token_value {
        Value::String(text) => SecretToken(text.into_bytes()),
        _ => return None,
    };
    if !valid_bearer(&token.0)
        || value.pointer("/apiVersion").and_then(Value::as_str) != Some("authentication.k8s.io/v1")
        || value.pointer("/kind").and_then(Value::as_str) != Some("TokenRequest")
        || !exact_string_array(
            value.pointer("/spec/audiences"),
            profile.kubernetes_api_audience(),
        )
        || value
            .pointer("/spec/expirationSeconds")
            .and_then(Value::as_i64)
            != Some(profile.requested_expiration_seconds)
        || value
            .pointer("/spec/boundObjectRef/apiVersion")
            .and_then(Value::as_str)
            != Some("v1")
        || value
            .pointer("/spec/boundObjectRef/kind")
            .and_then(Value::as_str)
            != Some("Secret")
        || value
            .pointer("/spec/boundObjectRef/name")
            .and_then(Value::as_str)
            != Some(&secret.lookup.bound_secret_name)
        || value
            .pointer("/spec/boundObjectRef/uid")
            .and_then(Value::as_str)
            != Some(&secret.uid)
    {
        return None;
    }
    let expires_at =
        parse_rfc3339_utc(value.pointer("/status/expirationTimestamp")?.as_str()?).ok()?;
    let upper = request_started_at
        .checked_add(profile.server_lifetime_upper_bound_seconds)?
        .checked_add(profile.clock_uncertainty_seconds)?;
    if returned_at < request_started_at || expires_at <= returned_at || expires_at > upper {
        return None;
    }
    Some((token, expires_at))
}

// Keeping all authenticated TokenReview/JWT equality checks in one linear
// fail-closed routine makes omissions visible during security review.
#[allow(clippy::too_many_lines)]
fn parse_token_review_response(
    body: &[u8],
    profile: &BrokerProfile,
    issued: &IssuedToken,
    observed_at: i64,
    evidence_commitment: [u8; 32],
) -> Option<ParsedReview> {
    let _: DuplicateRejectingJson = serde_json::from_slice(body).ok()?;
    let mut value: Value = serde_json::from_slice(body).ok()?;
    let echoed_token = value
        .as_object_mut()?
        .get_mut("spec")?
        .as_object_mut()?
        .remove("token")?;
    let mut echoed_bytes = match echoed_token {
        Value::String(text) => text.into_bytes(),
        _ => return None,
    };
    let exact_echo = echoed_bytes == issued.as_bytes();
    echoed_bytes.fill(0);
    if !exact_echo
        || value.pointer("/apiVersion").and_then(Value::as_str) != Some("authentication.k8s.io/v1")
        || value.pointer("/kind").and_then(Value::as_str) != Some("TokenReview")
        || !exact_string_array(
            value.pointer("/spec/audiences"),
            profile.kubernetes_api_audience(),
        )
    {
        return None;
    }
    let authenticated = value
        .pointer("/status/authenticated")
        .and_then(Value::as_bool)?;
    let review_error = value
        .pointer("/status/error")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !authenticated && review_error.is_empty() {
        return Some(ParsedReview::Rejected {
            observed_at,
            evidence_commitment: rejection_commitment(
                &issued.secret.lookup,
                &issued.secret.uid,
                issued.token_digest,
                observed_at,
                evidence_commitment,
            ),
        });
    }
    if !authenticated
        || !review_error.is_empty()
        || !exact_string_array(
            value.pointer("/status/audiences"),
            profile.kubernetes_api_audience(),
        )
        || value
            .pointer("/status/user/username")
            .and_then(Value::as_str)
            != Some(&profile.subject())
    {
        return None;
    }
    let service_account_uid = value
        .pointer("/status/user/uid")?
        .as_str()
        .filter(|uid| valid_text(uid, 512))?;
    if service_account_uid != profile.attempt_service_account_uid() {
        return None;
    }
    if !exact_service_account_groups(value.pointer("/status/user/groups"), profile.namespace()) {
        return None;
    }
    let (credential_id, token_review_authorization_id) =
        exact_credential_id(value.pointer("/status/user/extra"))?;
    let jwt = validate_bound_token(
        issued.as_bytes(),
        JwtExpectation {
            subject: &profile.subject(),
            audience: profile.kubernetes_api_audience(),
            namespace: profile.namespace(),
            service_account: profile.attempt_service_account(),
            service_account_uid: profile.attempt_service_account_uid(),
            secret_name: &issued.secret.lookup.bound_secret_name,
            secret_uid: &issued.secret.uid,
            expiration: issued.expires_at,
        },
    )
    .ok()?;
    if jwt.credential_authorization_id != token_review_authorization_id {
        return None;
    }
    let earliest = issued
        .request_started_at
        .checked_sub(profile.clock_uncertainty_seconds)?;
    let latest_issue = issued
        .returned_at
        .checked_add(profile.clock_uncertainty_seconds)?;
    if jwt.not_before < earliest
        || jwt.not_before > latest_issue
        || jwt.issued_at < earliest
        || jwt.issued_at > latest_issue
        || jwt.expires_at <= observed_at
    {
        return None;
    }
    Some(ParsedReview::Authenticated {
        claims: CredentialClaims {
            token_digest: issued.token_digest,
            subject: profile.subject(),
            audience: profile.kubernetes_api_audience().to_owned(),
            service_account_uid: service_account_uid.to_owned(),
            credential_id,
            bound_object_uid: issued.secret.uid.clone(),
            not_before: jwt.not_before,
            expires_at: jwt.expires_at,
        },
        evidence_commitment,
    })
}

fn exact_service_account_groups(value: Option<&Value>, namespace: &str) -> bool {
    let Some(values) = value.and_then(Value::as_array) else {
        return false;
    };
    let expected = BTreeSet::from([
        "system:authenticated".to_owned(),
        "system:serviceaccounts".to_owned(),
        format!("system:serviceaccounts:{namespace}"),
    ]);
    let actual: Option<BTreeSet<String>> = values
        .iter()
        .map(|value| value.as_str().map(ToOwned::to_owned))
        .collect();
    actual.is_some_and(|groups| groups.len() == values.len() && groups == expected)
}

fn exact_credential_id(value: Option<&Value>) -> Option<(String, Uuid)> {
    let extra = value?.as_object()?;
    if extra.len() != 1 {
        return None;
    }
    let values = extra.get(CREDENTIAL_ID_EXTRA_KEY)?.as_array()?;
    if values.len() != 1 {
        return None;
    }
    let credential_id = values[0].as_str()?;
    let encoded = credential_id.strip_prefix("AUTHORIZATION_ID=")?;
    let authorization_id = Uuid::parse_str(encoded).ok()?;
    if authorization_id.is_nil() || encoded != authorization_id.to_string() {
        return None;
    }
    Some((credential_id.to_owned(), authorization_id))
}

fn exact_string_array(value: Option<&Value>, expected: &str) -> bool {
    value
        .and_then(Value::as_array)
        .is_some_and(|values| values.len() == 1 && values[0].as_str() == Some(expected))
}

fn valid_delete_response(body: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return false;
    };
    value.pointer("/apiVersion").and_then(Value::as_str) == Some("v1")
        && value.pointer("/kind").and_then(Value::as_str) == Some("Status")
        && value.pointer("/status").and_then(Value::as_str) == Some("Success")
}

fn assess_retirement_at(
    profile: &BrokerProfile,
    deletion: &DeletionEvidence,
    rejection: Option<&TokenRejectionEvidence>,
    now: i64,
) -> Result<RetirementAssessment, BrokerFailure> {
    if rejection.is_some_and(|value| {
        value.lookup != deletion.lookup
            || value.secret_uid != deletion.secret_uid
            || value.observed_at < deletion.absent_observed_at
    }) {
        return Err(BrokerFailure::InvalidObservation {
            operation: BrokerOperation::TokenReview,
        });
    }
    let safe_after = deletion
        .absent_observed_at
        .checked_add(profile.invalidation_delay_seconds)
        .and_then(|value| value.checked_add(profile.clock_uncertainty_seconds))
        .ok_or(BrokerFailure::Clock)?;
    if now >= safe_after {
        Ok(RetirementAssessment::Confirmed(
            RetirementBasis::ConservativeInvalidationDelayElapsed,
        ))
    } else {
        Ok(RetirementAssessment::Pending { safe_after })
    }
}

fn response_evidence(operation: BrokerOperation, response: &WireResponse) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RESPONSE_EVIDENCE_DOMAIN);
    hasher.update([operation_tag(operation)]);
    hasher.update(response.status.to_be_bytes());
    update_len(&mut hasher, response.api_server_identity.as_bytes());
    hasher.update(response.channel_commitment);
    hasher.update(response.request_commitment);
    update_len(&mut hasher, response.body());
    hasher.finalize().into()
}

fn rejection_commitment(
    lookup: &AttemptLookup,
    secret_uid: &str,
    token_digest: [u8; 32],
    observed_at: i64,
    response_commitment: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(TOKEN_REVIEW_PREFIX_DOMAIN);
    hasher.update(lookup.transaction_id.as_bytes());
    update_len(&mut hasher, lookup.bound_secret_name.as_bytes());
    update_len(&mut hasher, secret_uid.as_bytes());
    hasher.update(token_digest);
    hasher.update(observed_at.to_be_bytes());
    hasher.update(response_commitment);
    hasher.finalize().into()
}

fn deletion_absence_commitment(
    lookup: &AttemptLookup,
    secret_uid: &str,
    absent_observed_at: i64,
    response_commitment: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DELETION_ABSENCE_DOMAIN);
    hasher.update(lookup.transaction_id.as_bytes());
    update_len(&mut hasher, lookup.bound_secret_name.as_bytes());
    update_len(&mut hasher, secret_uid.as_bytes());
    hasher.update(absent_observed_at.to_be_bytes());
    hasher.update(response_commitment);
    hasher.finalize().into()
}

const fn operation_tag(operation: BrokerOperation) -> u8 {
    match operation {
        BrokerOperation::CreateSecret => 1,
        BrokerOperation::GetSecret => 2,
        BrokerOperation::TokenRequest => 3,
        BrokerOperation::TokenReview => 4,
        BrokerOperation::DeleteSecret => 5,
    }
}

fn update_len(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}

fn map_wire_failure(
    operation: BrokerOperation,
    failure: WireFailure,
    conservative_credential_safe_after: Option<i64>,
) -> BrokerFailure {
    match failure {
        WireFailure::DefinitelyNotSent(reason) => BrokerFailure::DefinitelyNotSent {
            operation,
            reason: map_wire_reason(reason),
        },
        WireFailure::OutcomeUnknown(reason) => BrokerFailure::OutcomeUnknown {
            operation,
            reason: map_wire_reason(reason),
            conservative_credential_safe_after,
        },
    }
}

fn mutation_status_failure(
    operation: BrokerOperation,
    status: u16,
    conservative_credential_safe_after: Option<i64>,
) -> BrokerFailure {
    if (400..500).contains(&status) {
        BrokerFailure::ProviderRejected { operation, status }
    } else {
        BrokerFailure::OutcomeUnknown {
            operation,
            reason: FailureReason::InvalidProviderResponse,
            conservative_credential_safe_after,
        }
    }
}

const fn post_send_unknown(
    operation: BrokerOperation,
    conservative_credential_safe_after: Option<i64>,
) -> BrokerFailure {
    BrokerFailure::OutcomeUnknown {
        operation,
        reason: FailureReason::InvalidProviderResponse,
        conservative_credential_safe_after,
    }
}

const fn map_wire_reason(reason: WireReason) -> FailureReason {
    match reason {
        WireReason::InvalidPath | WireReason::InvalidBearer => FailureReason::InvalidRequest,
        WireReason::RequestTooLarge => FailureReason::RequestTooLarge,
        WireReason::Connect | WireReason::SocketConfiguration | WireReason::PeerMismatch => {
            FailureReason::Connect
        }
        WireReason::TlsConfiguration
        | WireReason::TlsAuthentication
        | WireReason::TlsAlpn
        | WireReason::MissingPeerBinding => FailureReason::TlsAuthentication,
        WireReason::Deadline => FailureReason::Deadline,
        WireReason::RequestWrite => FailureReason::RequestWrite,
        WireReason::ResponseRead => FailureReason::ResponseRead,
        WireReason::InvalidResponse => FailureReason::InvalidProviderResponse,
        WireReason::ResponseTooLarge => FailureReason::ResponseTooLarge,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeSet, VecDeque},
        net::SocketAddr,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicI64, Ordering},
        },
    };

    use accordlock_eks_profile::{
        EksManagementAuthorityBinding, EksRouteProfileInput, PinnedSocketTarget,
    };
    use accordlock_ingress::{
        ActivatedIngressRegistry, INGRESS_SCHEMA_VERSION, IngressAuthenticator, IngressClaims,
        IngressKeyStatus, IngressRecoveryProbe, MemoryReplayGuard, RegisteredIngressKey,
        sign_ingress_request,
    };
    use accordlock_protocol::{
        AgentProposal, AuthorityDomainState, AuthorityVector, CanonicalEncode, CapabilityGrant,
        DecisionOutcome, DeploymentTemplate, Digest32, DispatchDeadlinePolicy,
        EVALUATION_ATTESTATION_SCHEMA_VERSION, EVALUATION_DOMAIN, EXECUTION_AUTHORIZATION_DOMAIN,
        EXECUTION_AUTHORIZATION_SCHEMA_VERSION, EvaluationAttestation, ExecutionAuthorization,
        ReasonCode, SignedAuthorization, SignedEvaluation, SigningIdentity,
        authorization_signer_root, canonical_hash, evaluator_verifier_root, sign_cose,
    };
    use accordlock_state::{
        AcquiredBrokerOperationRequest, BrokerCleanupRequest, BrokerCredentialSafetyPolicy,
        BrokerReconciliationRequest, ClaimedControlWork, ConsumeKey,
        ControlConsumptionCommitOutcome, ControlIssuanceCommitOutcome, ControlPlaneState,
        ControlSubmissionIntakeOutcome, ControlWorkClaimOutcome, ControlWorkClaimRequest,
        ControlWorkerRole, DispatchAcquisitionAuthority, DispatchAcquisitionOutcome,
        DispatchAcquisitionRequest, EksDestinationProfile, EksDestinationRegistryState,
        GrantRegistration, InMemoryStore, IssuedAuthorizationRecord, Scope, TransactionalState,
    };

    use super::*;

    const SERVICE_ACCOUNT_UID: &str = "22222222-2222-4222-8222-222222222222";
    const KUBERNETES_API_AUDIENCE: &str = "urn:accordlock:kubernetes-api:prod-a";
    const NOW: i64 = 1_700_000_000;

    fn lookup() -> AttemptLookup {
        AttemptLookup::for_transaction(Uuid::from_u128(1))
    }

    fn commitments() -> AttemptCommitments {
        AttemptCommitments::new([1; 32], [2; 32], [3; 32], [4; 32], [5; 32])
            .unwrap_or_else(|error| unreachable!("fixture must be valid: {error}"))
    }

    fn record() -> TrustedAttemptRecord {
        attempt_record(lookup().transaction_id())
    }

    fn profile() -> BrokerProfile {
        BrokerProfile::new(route(), 60, 600).with_retirement_bounds(5, 60)
    }

    fn management_identity(subject: &str, marker: u8) -> BrokerManagementIdentity {
        BrokerManagementIdentity::new(subject.to_owned(), [marker; 32])
            .unwrap_or_else(|error| unreachable!("valid management identity fixture: {error}"))
    }

    fn management_identities() -> BrokerManagementIdentities {
        BrokerManagementIdentities::new(
            management_identity("urn:accordlock:broker:secret-lifecycle", 1),
            management_identity("urn:accordlock:broker:service-account-token", 2),
            management_identity("urn:accordlock:broker:token-review", 3),
        )
        .unwrap_or_else(|error| unreachable!("separated management fixtures: {error}"))
    }

    fn rooted_management_bindings() -> EksBrokerManagementBindings {
        let configured = management_identities();
        EksBrokerManagementBindings::new(
            EksManagementAuthorityBinding::new(
                configured.secret_lifecycle().subject(),
                configured.secret_lifecycle().authorization_commitment(),
            )
            .unwrap_or_else(|error| unreachable!("secret management fixture: {error}")),
            EksManagementAuthorityBinding::new(
                configured.service_account_token().subject(),
                configured
                    .service_account_token()
                    .authorization_commitment(),
            )
            .unwrap_or_else(|error| unreachable!("token management fixture: {error}")),
            EksManagementAuthorityBinding::new(
                configured.token_review().subject(),
                configured.token_review().authorization_commitment(),
            )
            .unwrap_or_else(|error| unreachable!("review management fixture: {error}")),
        )
        .unwrap_or_else(|error| unreachable!("rooted management fixture: {error}"))
    }

    fn route() -> EksRouteProfile {
        let certificates = vec![b"broker-test-ca".to_vec()];
        EksRouteProfile::new(EksRouteProfileInput {
            cluster_trust_domain: "spiffe://example.test/eks/prod-a",
            cluster_identity: "eks://prod-a",
            api_server_identity: "urn:accordlock:api:prod-a",
            dns_server_name: "api.prod-a.eks.amazonaws.com",
            port: 443,
            socket_target: PinnedSocketTarget::new(SocketAddr::from(([192, 0, 2, 21], 443)))
                .unwrap_or_else(|error| unreachable!("valid fixture socket: {error}")),
            ca_trust_commitment: CaTrustCommitment::from_der_certificates(&certificates)
                .unwrap_or_else(|error| unreachable!("valid fixture CA: {error}")),
            namespace: "payments",
            deployment_name: "api",
            deployment_uid: "11111111-1111-4111-8111-111111111111",
            attempt_service_account_name: "accordlock-attempt",
            attempt_service_account_uid: SERVICE_ACCOUNT_UID,
            token_audience: KUBERNETES_API_AUDIENCE,
        })
        .unwrap_or_else(|error| unreachable!("valid fixture route: {error}"))
    }

    #[derive(Debug)]
    struct StateClock(AtomicI64);

    impl StateClock {
        fn new(now: i64) -> Self {
            Self(AtomicI64::new(now))
        }

        fn set(&self, now: i64) {
            self.0.store(now, Ordering::SeqCst);
        }
    }

    impl accordlock_state::TrustedClock for StateClock {
        fn now_unix_seconds(&self) -> Result<i64, accordlock_state::StateError> {
            Ok(self.0.load(Ordering::SeqCst))
        }
    }

    #[derive(Clone, Debug)]
    struct BrokerClock(Arc<AtomicI64>);

    impl BrokerClock {
        fn new(now: i64) -> Self {
            Self(Arc::new(AtomicI64::new(now)))
        }
    }

    impl TrustedClock for BrokerClock {
        fn unix_seconds(&self) -> Result<i64, String> {
            Ok(self.0.load(Ordering::SeqCst))
        }
    }

    #[derive(Clone, Debug)]
    struct FixedAttemptSource(TrustedAttemptRecord);

    impl AttemptAuthoritySource for FixedAttemptSource {
        fn load_current(
            &self,
            authority: &DispatchAcquisitionAuthority,
        ) -> Result<TrustedAttemptRecord, AuthorityResolutionError> {
            let requested = AttemptLookup::for_transaction(authority.claim().key().transaction_id);
            if self.0.lookup == requested {
                Ok(self.0.clone())
            } else {
                Err(AuthorityResolutionError::NotFound)
            }
        }

        fn load_frozen_cleanup(
            &self,
            selector: &BrokerJournalSelector,
        ) -> Result<TrustedAttemptRecord, AuthorityResolutionError> {
            let requested = AttemptLookup::for_transaction(selector.key().transaction_id);
            if self.0.lookup == requested {
                Ok(self.0.clone())
            } else {
                Err(AuthorityResolutionError::NotFound)
            }
        }
    }

    #[derive(Clone, Debug)]
    struct RevocableAttemptSource {
        record: TrustedAttemptRecord,
        current: Arc<AtomicBool>,
    }

    impl AttemptAuthoritySource for RevocableAttemptSource {
        fn load_current(
            &self,
            authority: &DispatchAcquisitionAuthority,
        ) -> Result<TrustedAttemptRecord, AuthorityResolutionError> {
            let requested = AttemptLookup::for_transaction(authority.claim().key().transaction_id);
            if self.current.load(Ordering::SeqCst) && self.record.lookup == requested {
                Ok(self.record.clone())
            } else {
                Err(AuthorityResolutionError::InvalidRecord)
            }
        }

        fn load_frozen_cleanup(
            &self,
            selector: &BrokerJournalSelector,
        ) -> Result<TrustedAttemptRecord, AuthorityResolutionError> {
            let requested = AttemptLookup::for_transaction(selector.key().transaction_id);
            if self.record.lookup == requested {
                Ok(self.record.clone())
            } else {
                Err(AuthorityResolutionError::NotFound)
            }
        }
    }

    #[derive(Clone, Debug)]
    struct DeadlineAttemptSource {
        record: TrustedAttemptRecord,
        clock: Arc<AtomicI64>,
        deadline: i64,
    }

    impl AttemptAuthoritySource for DeadlineAttemptSource {
        fn load_current(
            &self,
            authority: &DispatchAcquisitionAuthority,
        ) -> Result<TrustedAttemptRecord, AuthorityResolutionError> {
            let requested = AttemptLookup::for_transaction(authority.claim().key().transaction_id);
            if self.clock.load(Ordering::SeqCst) <= self.deadline && self.record.lookup == requested
            {
                Ok(self.record.clone())
            } else {
                Err(AuthorityResolutionError::InvalidRecord)
            }
        }

        fn load_frozen_cleanup(
            &self,
            selector: &BrokerJournalSelector,
        ) -> Result<TrustedAttemptRecord, AuthorityResolutionError> {
            let requested = AttemptLookup::for_transaction(selector.key().transaction_id);
            if self.record.lookup == requested {
                Ok(self.record.clone())
            } else {
                Err(AuthorityResolutionError::NotFound)
            }
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct ExactManagementSource;

    impl ManagementCredentialSource for ExactManagementSource {
        fn credential(
            &self,
            request: &ManagementCredentialRequest,
        ) -> Result<ManagementBearer, CredentialSourceError> {
            let bytes = match request.operation().authority() {
                BrokerManagementAuthority::SecretLifecycle => b"secret-management".to_vec(),
                BrokerManagementAuthority::ServiceAccountToken => b"token-management".to_vec(),
                BrokerManagementAuthority::TokenReview => b"review-management".to_vec(),
            };
            ManagementBearer::from_trusted_source(bytes, request.binding())
        }
    }

    #[derive(Clone, Debug)]
    struct RevokingManagementSource(Arc<AtomicBool>);

    impl ManagementCredentialSource for RevokingManagementSource {
        fn credential(
            &self,
            request: &ManagementCredentialRequest,
        ) -> Result<ManagementBearer, CredentialSourceError> {
            let bearer = ManagementBearer::from_trusted_source(
                b"rotating-management".to_vec(),
                request.binding(),
            )?;
            self.0.store(false, Ordering::SeqCst);
            Ok(bearer)
        }
    }

    #[derive(Clone, Debug)]
    struct AdvancingManagementSource {
        clock: Arc<AtomicI64>,
        next: i64,
    }

    impl ManagementCredentialSource for AdvancingManagementSource {
        fn credential(
            &self,
            request: &ManagementCredentialRequest,
        ) -> Result<ManagementBearer, CredentialSourceError> {
            let bearer = ManagementBearer::from_trusted_source(
                b"clock-advancing-management".to_vec(),
                request.binding(),
            )?;
            self.clock.store(self.next, Ordering::SeqCst);
            Ok(bearer)
        }
    }

    type TestBroker = EksCredentialBroker<FixedAttemptSource, ExactManagementSource, BrokerClock>;

    fn attempt_record(transaction_id: Uuid) -> TrustedAttemptRecord {
        let route = route();
        let policy = EksCredentialLifecyclePolicy::new(60, 600, 5, 60)
            .unwrap_or_else(|error| unreachable!("lifecycle fixture: {error}"));
        let record = TrustedAttemptRecord {
            lookup: AttemptLookup::for_transaction(transaction_id),
            scope: Scope::new("acme", "prod")
                .unwrap_or_else(|error| unreachable!("scope fixture: {error}")),
            authorization_id: Uuid::from_u128(transaction_id.as_u128().saturating_add(1)),
            physical_resource: PhysicalResourceKey::new(
                route.cluster_identity().to_owned(),
                route.namespace().to_owned(),
                route.deployment_uid().to_owned(),
            )
            .unwrap_or_else(|error| unreachable!("physical fixture: {error}")),
            token_subject: format!(
                "system:serviceaccount:{}:{}",
                route.namespace(),
                route.attempt_service_account_name()
            ),
            service_account_uid: route.attempt_service_account_uid().to_owned(),
            token_audience: route.token_audience().to_owned(),
            route,
            commitments: commitments(),
            terminal_witness_registry_commitment: [6; 32],
            credential_lifecycle_policy: policy,
            credential_lifecycle_commitment: policy.commitment(),
            credential_lifecycle_policy_id: policy.policy_id().to_owned(),
            broker_management_bindings: rooted_management_bindings(),
            resource_authority: AttemptAuthorityDomainBinding {
                root: [7; 32],
                epoch: 1,
                activation_id: Uuid::from_u128(7),
            },
            mediation_authority: AttemptAuthorityDomainBinding {
                root: [8; 32],
                epoch: 1,
                activation_id: Uuid::from_u128(8),
            },
            destination_activation_commitment: [9; 32],
        };
        record
            .validate_internal()
            .unwrap_or_else(|error| unreachable!("trusted attempt fixture: {error}"));
        record
    }

    fn scripted_broker(transaction_id: Uuid, script: Vec<ScriptedExchange>) -> TestBroker {
        let profile = profile();
        let http = FixedHttpsClient::for_test(profile.route_profile().clone())
            .unwrap_or_else(|error| unreachable!("test HTTPS shell: {error:?}"));
        EksCredentialBroker {
            profile,
            management_identities: management_identities(),
            http,
            authority: FixedAttemptSource(attempt_record(transaction_id)),
            management_credentials: ExactManagementSource,
            clock: BrokerClock::new(NOW + 10),
            scripted_exchanges: Some(Arc::new(std::sync::Mutex::new(VecDeque::from(script)))),
            review_commit_fault: None,
        }
    }

    fn journal_digest(label: &str) -> Digest32 {
        Digest32::sha256(label.as_bytes())
    }

    fn journal_signer() -> SigningIdentity {
        SigningIdentity::from_seed("broker-journal-test", [93; 32])
    }

    fn authority_domain(label: &str) -> AuthorityDomainState {
        AuthorityDomainState {
            root: journal_digest(label),
            epoch: 1,
            activation_id: Uuid::new_v4(),
        }
    }

    fn journal_authority() -> AuthorityVector {
        let signer = journal_signer();
        let mut authority = AuthorityVector {
            policy: authority_domain("policy"),
            registry: authority_domain("registry"),
            revocation: authority_domain("revocation"),
            connector: authority_domain("connector"),
            resource: authority_domain("resource"),
            signer: authority_domain("signer"),
            mediation: authority_domain("mediation"),
            grant_registry: authority_domain("grant"),
            office_act_registry: authority_domain("office"),
            principal_registry: authority_domain("principal"),
            workload_build_allowlist: authority_domain("build"),
            kernel_configuration: authority_domain("kernel"),
        };
        authority.signer.root =
            authorization_signer_root(signer.key_id(), signer.public_key_bytes())
                .unwrap_or_else(|error| unreachable!("signer root fixture: {error}"));
        authority
    }

    fn journal_template() -> DeploymentTemplate {
        DeploymentTemplate {
            operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
            environment: "prod".to_owned(),
            audience: "accordlock-executor:prod".to_owned(),
            repository: "acme/payments".to_owned(),
            commit_sha: "1111111111111111111111111111111111111111".to_owned(),
            image_repository: "registry.example/acme/payments".to_owned(),
            image_digest: journal_digest("new-image"),
            cluster_identity: route().cluster_identity().to_owned(),
            namespace: route().namespace().to_owned(),
            deployment: route().deployment_name().to_owned(),
            deployment_uid: route().deployment_uid().to_owned(),
            container: "app".to_owned(),
            container_index: 0,
            prior_image_digest: journal_digest("old-image"),
            resource_version: "1001".to_owned(),
            prior_projection_hash: journal_digest("projection"),
            prior_transaction_annotation: Some("none".to_owned()),
            prior_authorization_annotation: Some("none".to_owned()),
            prior_operation_hash_annotation: Some("none".to_owned()),
        }
    }

    fn journal_grant() -> GrantRegistration {
        let capability = CapabilityGrant {
            grant_id: Uuid::from_u128(10),
            holder: "workload-a".to_owned(),
            tenant: "acme".to_owned(),
            operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
            repository: "acme/payments".to_owned(),
            audience: "accordlock-executor:prod".to_owned(),
            cluster_identity: route().cluster_identity().to_owned(),
            namespace: route().namespace().to_owned(),
            deployment_uid: route().deployment_uid().to_owned(),
            container: "app".to_owned(),
            image_repository: "registry.example/acme/payments".to_owned(),
            not_before: NOW - 100,
            expires_at: NOW + 10_000,
            maximum_uses: 1,
        };
        let mut authority = journal_authority();
        authority.grant_registry.root = canonical_hash(&capability)
            .unwrap_or_else(|error| unreachable!("grant hash fixture: {error}"));
        GrantRegistration {
            environment: "prod".to_owned(),
            grant: capability,
            authority,
            dispatch_deadline_policy: DispatchDeadlinePolicy {
                max_dispatch_delay_seconds: 300,
                profile_hard_cap: NOW + 1_000,
                immutable_dependency_expiries: vec![NOW + 500, NOW + 800],
            },
        }
    }

    #[allow(clippy::too_many_lines)]
    fn journal_setup(
        seed: u128,
    ) -> (
        InMemoryStore,
        BrokerJournalCapability,
        Arc<StateClock>,
        ConsumeKey,
        DispatchAcquisitionAuthority,
    ) {
        let clock = Arc::new(StateClock::new(NOW));
        let mut store = InMemoryStore::with_clock(clock.clone());
        let journal_capability = store
            .issue_broker_journal_capability()
            .unwrap_or_else(|error| unreachable!("journal capability fixture: {error}"));
        let ingress_signer = SigningIdentity::from_seed("broker-control-ingress", [91; 32]);
        let evaluator = SigningIdentity::from_seed("broker-control-evaluator", [92; 32]);
        let authorization_signer = journal_signer();
        let ingress_key = RegisteredIngressKey {
            key_id: ingress_signer.key_id().to_owned(),
            public_key: ingress_signer.public_key_bytes(),
            tenant: "acme".to_owned(),
            actor: "workload-a".to_owned(),
            allowed_audiences: BTreeSet::from(["accordlock-executor:prod".to_owned()]),
            not_before: NOW - 100,
            expires_at: NOW + 10_000,
            status: IngressKeyStatus::Active,
        };
        let principal_root = ActivatedIngressRegistry::compute_root(
            "accordlock-executor:prod",
            120,
            std::slice::from_ref(&ingress_key),
        )
        .unwrap_or_else(|error| unreachable!("ingress root fixture: {error}"));
        let principal_registry = AuthorityDomainState {
            root: principal_root,
            epoch: 1,
            activation_id: Uuid::from_u128(seed + 20),
        };
        let registry = ActivatedIngressRegistry::new(
            principal_registry.clone(),
            "accordlock-executor:prod",
            120,
            vec![ingress_key],
        )
        .unwrap_or_else(|error| unreachable!("ingress registry fixture: {error}"));
        let authenticator = IngressAuthenticator::new(registry, MemoryReplayGuard::default())
            .unwrap_or_else(|error| unreachable!("ingress authenticator fixture: {error}"));

        let mut registration = journal_grant();
        registration.authority.principal_registry = principal_registry;
        registration.authority.kernel_configuration.root =
            evaluator_verifier_root(evaluator.key_id(), evaluator.public_key_bytes())
                .unwrap_or_else(|error| unreachable!("evaluator root fixture: {error}"));
        let scope = Scope::new("acme", "prod")
            .unwrap_or_else(|error| unreachable!("scope fixture: {error}"));
        let policy = EksCredentialLifecyclePolicy::new(60, 600, 5, 60)
            .unwrap_or_else(|error| unreachable!("destination lifecycle fixture: {error}"));
        let destination = EksDestinationProfile::new(
            route(),
            [5; 32],
            [6; 32],
            policy,
            rooted_management_bindings(),
        )
        .unwrap_or_else(|error| unreachable!("destination fixture: {error}"));
        registration.authority.resource.root = destination
            .resource_root(&scope)
            .unwrap_or_else(|error| unreachable!("resource root fixture: {error}"));
        registration.authority.mediation.root = destination
            .mediation_root(&scope, &registration.authority.resource)
            .unwrap_or_else(|error| unreachable!("mediation root fixture: {error}"));
        let authority = registration.authority.clone();
        store
            .compare_and_activate_authority(&scope, None, &authority)
            .unwrap_or_else(|error| unreachable!("authority fixture: {error}"));
        store
            .activate_eks_destination(&scope, &destination)
            .unwrap_or_else(|error| unreachable!("destination activation fixture: {error}"));
        store
            .register_grant(&registration)
            .unwrap_or_else(|error| unreachable!("grant fixture: {error}"));

        let proposal = AgentProposal {
            schema_version: 1,
            request_id: Uuid::from_u128(seed + 30),
            tenant: "acme".to_owned(),
            actor: "workload-a".to_owned(),
            template: journal_template(),
        };
        let signed_ingress = sign_ingress_request(
            IngressClaims {
                schema_version: INGRESS_SCHEMA_VERSION,
                audience: "accordlock-executor:prod".to_owned(),
                issued_at: NOW - 1,
                expires_at: NOW + 100,
                nonce: Uuid::from_u128(seed + 31),
                proposal,
            },
            &ingress_signer,
        )
        .unwrap_or_else(|error| unreachable!("signed ingress fixture: {error}"));
        let wire = serde_json::to_vec(&signed_ingress)
            .unwrap_or_else(|error| unreachable!("ingress wire fixture: {error}"));
        let verified = authenticator
            .verify_durable_static(
                IngressRecoveryProbe::parse_bytes(&wire)
                    .unwrap_or_else(|error| unreachable!("ingress parse fixture: {error}")),
            )
            .unwrap_or_else(|error| unreachable!("ingress verification fixture: {error}"));
        match store
            .accept_control_submission_or_recover(verified)
            .unwrap_or_else(|error| unreachable!("control intake fixture: {error}"))
        {
            ControlSubmissionIntakeOutcome::Fresh(_) => {}
            outcome => unreachable!("expected fresh control intake, got {outcome:?}"),
        }

        let evaluation_request = ControlWorkClaimRequest::new(
            "broker-evaluator",
            ControlWorkerRole::Evaluator,
            Uuid::from_u128(seed + 32),
        )
        .unwrap_or_else(|error| unreachable!("evaluation request fixture: {error}"));
        let evaluation_work = match store
            .claim_next_control_work_or_recover(&evaluation_request)
            .unwrap_or_else(|error| unreachable!("evaluation claim fixture: {error}"))
        {
            ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Evaluate(work)) => work,
            outcome => unreachable!("expected evaluation work, got {outcome:?}"),
        };
        let evaluation = EvaluationAttestation {
            schema_version: EVALUATION_ATTESTATION_SCHEMA_VERSION,
            request_id: evaluation_work.proposal().request_id,
            evaluation_nonce: evaluation_work.evaluation_nonce(),
            tenant: evaluation_work.caller_tenant().to_owned(),
            actor: evaluation_work.caller_actor().to_owned(),
            evaluated_at: evaluation_work.lease().claimed_at(),
            outcome: DecisionOutcome::Allow,
            reasons: vec![ReasonCode::Allowed],
            template_hash: canonical_hash(&evaluation_work.proposal().template)
                .unwrap_or_else(|error| unreachable!("evaluation template fixture: {error}")),
            evidence_root: journal_digest("control-evidence"),
            principals: vec!["principal-a".to_owned()],
            policy_root: evaluation_work.active_authority().policy.root,
            authority: evaluation_work.active_authority().clone(),
            consume_before: NOW + 90,
        };
        let evaluation_cose = sign_cose(
            &evaluation
                .canonical_bytes()
                .unwrap_or_else(|error| unreachable!("evaluation encoding fixture: {error}")),
            EVALUATION_DOMAIN,
            &evaluator,
        )
        .unwrap_or_else(|error| unreachable!("evaluation signing fixture: {error}"));
        store
            .record_control_evaluation(
                evaluation_work,
                &SignedEvaluation {
                    attestation: evaluation,
                    cose_sign1: evaluation_cose,
                },
                &evaluator.verifier(),
            )
            .unwrap_or_else(|error| unreachable!("evaluation record fixture: {error}"));

        let issuance_request = ControlWorkClaimRequest::new(
            "broker-issuer",
            ControlWorkerRole::Issuer,
            Uuid::from_u128(seed + 33),
        )
        .unwrap_or_else(|error| unreachable!("issuance request fixture: {error}"));
        let issuance_work = match store
            .claim_next_control_work_or_recover(&issuance_request)
            .unwrap_or_else(|error| unreachable!("issuance claim fixture: {error}"))
        {
            ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Issue(work)) => work,
            outcome => unreachable!("expected issuance work, got {outcome:?}"),
        };
        let issuance_snapshot = store
            .control_issuance_snapshot(&issuance_work)
            .unwrap_or_else(|error| unreachable!("issuance snapshot fixture: {error}"));
        let transaction_id = Uuid::from_u128(seed);
        let evaluation = &issuance_work.signed_evaluation().attestation;
        let authorization = ExecutionAuthorization {
            schema_version: EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
            authorization_id: Uuid::from_u128(seed + 1),
            evaluation_nonce: evaluation.evaluation_nonce,
            request_id: evaluation.request_id,
            tenant: issuance_work.proposal().tenant.clone(),
            holder: issuance_work.proposal().actor.clone(),
            audience: issuance_work.proposal().template.audience.clone(),
            issued_at: issuance_snapshot.issued_at(),
            not_before: issuance_snapshot.issued_at(),
            consume_before: evaluation
                .consume_before
                .min(issuance_snapshot.registration().grant.expires_at),
            dispatch_deadline_policy: issuance_snapshot
                .registration()
                .dispatch_deadline_policy
                .clone(),
            grant_id: issuance_work.selected_grant_id(),
            template: issuance_work.proposal().template.clone(),
            template_hash: evaluation.template_hash,
            evidence_root: evaluation.evidence_root,
            principals: evaluation.principals.clone(),
            policy_root: evaluation.policy_root,
            authority: evaluation.authority.clone(),
        };
        let authorization_cose = sign_cose(
            &authorization
                .canonical_bytes()
                .unwrap_or_else(|error| unreachable!("authorization encoding fixture: {error}")),
            EXECUTION_AUTHORIZATION_DOMAIN,
            &authorization_signer,
        )
        .unwrap_or_else(|error| unreachable!("authorization signing fixture: {error}"));
        let record = IssuedAuthorizationRecord::new(
            transaction_id,
            SignedAuthorization {
                authorization,
                cose_sign1: authorization_cose,
            },
            authorization_signer.key_id().to_owned(),
            authorization_signer.public_key_bytes(),
        )
        .unwrap_or_else(|error| unreachable!("issued authorization fixture: {error}"));
        assert_eq!(
            store
                .record_and_link_control_issuance_or_recover(issuance_work, &record)
                .unwrap_or_else(|error| unreachable!("issuance record fixture: {error}")),
            ControlIssuanceCommitOutcome::Committed
        );

        let consumption_request = ControlWorkClaimRequest::new(
            "broker-consumer",
            ControlWorkerRole::Consumer,
            Uuid::from_u128(seed + 34),
        )
        .unwrap_or_else(|error| unreachable!("consumption request fixture: {error}"));
        let consumption_work = match store
            .claim_next_control_work_or_recover(&consumption_request)
            .unwrap_or_else(|error| unreachable!("consumption claim fixture: {error}"))
        {
            ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Consume(work)) => work,
            outcome => unreachable!("expected consumption work, got {outcome:?}"),
        };
        let key = ConsumeKey {
            scope,
            transaction_id,
            authorization_id: record.authorization().authorization_id,
        };
        assert_eq!(consumption_work.consume_key(), &key);
        assert!(matches!(
            store
                .consume_and_link_control_or_recover(consumption_work)
                .unwrap_or_else(|error| unreachable!("consumption fixture: {error}")),
            ControlConsumptionCommitOutcome::Committed(_)
        ));
        clock.set(NOW + 1);
        let request = DispatchAcquisitionRequest::new(
            format!("broker-worker-{seed}"),
            Uuid::from_u128(seed + 2),
        )
        .unwrap_or_else(|error| unreachable!("acquisition request fixture: {error}"));
        let work = match store
            .claim_next_pending_dispatch_or_recover(&key.scope, &request)
            .unwrap_or_else(|error| unreachable!("acquisition fixture: {error}"))
        {
            DispatchAcquisitionOutcome::Acquired(work) => work,
            outcome => unreachable!("expected acquired work, got {outcome:?}"),
        };
        let (_snapshot, authority) = work.into_parts();
        (store, journal_capability, clock, key, authority)
    }

    fn route_commitment() -> [u8; 32] {
        *route().commitment().as_bytes()
    }

    fn create_io_authority(
        store: &InMemoryStore,
        journal_capability: &BrokerJournalCapability,
        clock: &StateClock,
        acquisition: &DispatchAcquisitionAuthority,
    ) -> BrokerIoAuthority {
        clock.set(NOW + 2);
        store
            .begin_broker_operation_for_acquisition(
                journal_capability,
                acquisition,
                AcquiredBrokerOperationRequest::create(acquisition, route_commitment())
                    .unwrap_or_else(|error| unreachable!("create request fixture: {error}")),
            )
            .unwrap_or_else(|error| unreachable!("create authority fixture: {error}"))
    }

    fn issue_io_authority(
        store: &InMemoryStore,
        journal_capability: &BrokerJournalCapability,
        clock: &StateClock,
        acquisition: &DispatchAcquisitionAuthority,
        policy: BrokerCredentialSafetyPolicy,
    ) -> BrokerIoAuthority {
        clock.set(NOW + 3);
        store
            .begin_broker_operation_for_acquisition(
                journal_capability,
                acquisition,
                AcquiredBrokerOperationRequest::issue_token(
                    acquisition,
                    route_commitment(),
                    policy,
                )
                .unwrap_or_else(|error| unreachable!("token request fixture: {error}")),
            )
            .unwrap_or_else(|error| unreachable!("token authority fixture: {error}"))
    }

    fn create_response(transaction_id: Uuid, uid: &str) -> Vec<u8> {
        let attempt = attempt_record(transaction_id);
        create_response_for_attempt(&attempt, uid)
    }

    fn create_response_for_attempt(attempt: &TrustedAttemptRecord, uid: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "apiVersion":"v1",
            "kind":"Secret",
            "metadata":{
                "name":attempt.lookup().bound_secret_name(),
                "namespace":profile().namespace(),
                "uid":uid,
                "resourceVersion":"7",
                "labels":exact_labels(&profile(), attempt)
            },
            "immutable":true,
            "type":"Opaque",
            "data":{}
        }))
        .unwrap_or_else(|error| unreachable!("Secret response fixture: {error}"))
    }

    fn token_response(transaction_id: Uuid, uid: &str) -> Vec<u8> {
        let token = jwt_token(AttemptLookup::for_transaction(transaction_id).bound_secret_name());
        serde_json::to_vec(&json!({
            "apiVersion":"authentication.k8s.io/v1",
            "kind":"TokenRequest",
            "spec":{
                "audiences":[KUBERNETES_API_AUDIENCE],
                "expirationSeconds":60,
                "boundObjectRef":{
                    "apiVersion":"v1",
                    "kind":"Secret",
                    "name":AttemptLookup::for_transaction(transaction_id).bound_secret_name(),
                    "uid":uid
                }
            },
            "status":{
                "token":String::from_utf8_lossy(&token),
                "expirationTimestamp":"2023-11-14T22:15:00Z"
            }
        }))
        .unwrap_or_else(|error| unreachable!("TokenRequest response fixture: {error}"))
    }

    fn authenticated_review_response(transaction_id: Uuid) -> Vec<u8> {
        let token = jwt_token(AttemptLookup::for_transaction(transaction_id).bound_secret_name());
        serde_json::to_vec(&json!({
            "apiVersion":"authentication.k8s.io/v1",
            "kind":"TokenReview",
            "spec":{
                "audiences":[KUBERNETES_API_AUDIENCE],
                "token":String::from_utf8_lossy(&token)
            },
            "status":{
                "authenticated":true,
                "audiences":[KUBERNETES_API_AUDIENCE],
                "user":{
                    "username":"system:serviceaccount:payments:accordlock-attempt",
                    "uid":SERVICE_ACCOUNT_UID,
                    "groups":[
                        "system:serviceaccounts",
                        "system:serviceaccounts:payments",
                        "system:authenticated"
                    ],
                    "extra":{
                        "authentication.kubernetes.io/credential-id":[
                            "AUTHORIZATION_ID=7ee52be0-9045-4653-aa5e-0da57b8dccdc"
                        ]
                    }
                }
            }
        }))
        .unwrap_or_else(|error| unreachable!("TokenReview response fixture: {error}"))
    }

    fn delete_response() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "apiVersion":"v1",
            "kind":"Status",
            "status":"Success"
        }))
        .unwrap_or_else(|error| unreachable!("DELETE response fixture: {error}"))
    }

    fn create_reconciliation_request(key: &ConsumeKey) -> BrokerReconciliationRequest {
        BrokerReconciliationRequest::new(
            key.clone(),
            BrokerJournalOperation::CreateSecret,
            route_commitment(),
        )
        .unwrap_or_else(|error| unreachable!("create reconciliation fixture: {error}"))
    }

    fn delete_reconciliation_request(key: &ConsumeKey) -> BrokerReconciliationRequest {
        BrokerReconciliationRequest::new(
            key.clone(),
            BrokerJournalOperation::DeleteSecret,
            route_commitment(),
        )
        .unwrap_or_else(|error| unreachable!("delete reconciliation fixture: {error}"))
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn journaled_lifecycle_commits_create_and_token_then_get_reconciles_delete() {
        let seed = 8_001;
        let (store, journal_capability, state_clock, key, claim) = journal_setup(seed);
        let transaction_id = key.transaction_id;
        let broker = scripted_broker(
            transaction_id,
            vec![
                ScriptedExchange::Response {
                    status: 201,
                    body: create_response(transaction_id, "secret-uid"),
                },
                ScriptedExchange::Response {
                    status: 201,
                    body: token_response(transaction_id, "secret-uid"),
                },
                ScriptedExchange::Response {
                    status: 202,
                    body: delete_response(),
                },
                ScriptedExchange::Response {
                    status: 200,
                    body: create_response(transaction_id, "secret-uid"),
                },
                ScriptedExchange::Response {
                    status: 404,
                    body: b"{}".to_vec(),
                },
            ],
        );

        let created = broker
            .create_bound_secret(
                &store,
                &claim,
                create_io_authority(&store, &journal_capability, &state_clock, &claim),
            )
            .unwrap_or_else(|error| unreachable!("journaled create: {error}"));
        assert_eq!(
            created.receipt().audit().outcome(),
            Some(accordlock_state::BrokerJournalOutcome::CreateMatching)
        );
        assert_eq!(created.secret().uid(), "secret-uid");

        let issued = broker
            .request_bound_token(
                &store,
                &claim,
                issue_io_authority(
                    &store,
                    &journal_capability,
                    &state_clock,
                    &claim,
                    BrokerCredentialSafetyPolicy::new(600, 5)
                        .unwrap_or_else(|error| unreachable!("token policy fixture: {error}")),
                ),
            )
            .unwrap_or_else(|error| unreachable!("journaled token: {error}"));
        assert_eq!(
            issued.receipt().audit().outcome(),
            Some(accordlock_state::BrokerJournalOutcome::TokenIssued)
        );
        assert_eq!(issued.expires_at(), NOW + 100);

        state_clock.set(NOW + 4);
        let cleanup = store
            .prepare_broker_cleanup(
                &journal_capability,
                &BrokerCleanupRequest::new(key.clone(), route_commitment())
                    .unwrap_or_else(|error| unreachable!("cleanup request fixture: {error}")),
            )
            .and_then(|intent| store.begin_broker_io(&journal_capability, intent))
            .unwrap_or_else(|error| unreachable!("delete authority fixture: {error}"));
        let deleted = broker
            .delete_bound_secret(&store, cleanup)
            .unwrap_or_else(|error| unreachable!("journaled delete: {error}"));
        assert_eq!(deleted.journal().phase(), BrokerJournalPhase::Unknown);

        state_clock.set(NOW + 5);
        let first_get = store
            .begin_broker_reconciliation(&journal_capability, &delete_reconciliation_request(&key))
            .unwrap_or_else(|error| unreachable!("first delete GET authority: {error}"));
        let pending = broker
            .reconcile_bound_secret(&store, first_get)
            .unwrap_or_else(|error| unreachable!("present delete reconciliation: {error}"));
        let JournaledSecretReconciliation::Pending { audit } = pending else {
            unreachable!("matching Secret after DELETE must remain GET-only");
        };
        assert_eq!(audit.phase(), BrokerJournalPhase::ReconcileOnly);
        assert_eq!(audit.reconciliation_count(), 1);

        state_clock.set(NOW + 6);
        let second_get = store
            .begin_broker_reconciliation(&journal_capability, &delete_reconciliation_request(&key))
            .unwrap_or_else(|error| unreachable!("second delete GET authority: {error}"));
        let complete = broker
            .reconcile_bound_secret(&store, second_get)
            .unwrap_or_else(|error| unreachable!("absent delete reconciliation: {error}"));
        let JournaledSecretReconciliation::DeleteCommitted { receipt, .. } = complete else {
            unreachable!("authenticated GET-404 must complete delete");
        };
        assert_eq!(receipt.audit().phase(), BrokerJournalPhase::Committed);
        assert_eq!(
            receipt.audit().outcome(),
            Some(accordlock_state::BrokerJournalOutcome::DeleteAbsent)
        );
    }

    #[test]
    fn create_get_reconciliation_remains_pending_until_late_match() {
        let seed = 8_101;
        let (store, journal_capability, state_clock, key, claim) = journal_setup(seed);
        let broker = scripted_broker(
            key.transaction_id,
            vec![
                ScriptedExchange::Failure(BrokerFailure::OutcomeUnknown {
                    operation: BrokerOperation::CreateSecret,
                    reason: FailureReason::ResponseRead,
                    conservative_credential_safe_after: None,
                }),
                ScriptedExchange::Response {
                    status: 404,
                    body: b"{}".to_vec(),
                },
                ScriptedExchange::Response {
                    status: 200,
                    body: create_response(key.transaction_id, "late-secret-uid"),
                },
            ],
        );
        let failed = broker.create_bound_secret(
            &store,
            &claim,
            create_io_authority(&store, &journal_capability, &state_clock, &claim),
        );
        assert!(matches!(failed, Err(BrokerFailure::OutcomeUnknown { .. })));

        state_clock.set(NOW + 3);
        let first = store
            .begin_broker_reconciliation(&journal_capability, &create_reconciliation_request(&key))
            .unwrap_or_else(|error| unreachable!("first create GET authority: {error}"));
        let pending = broker
            .reconcile_bound_secret(&store, first)
            .unwrap_or_else(|error| unreachable!("absent create reconciliation: {error}"));
        assert!(matches!(
            pending,
            JournaledSecretReconciliation::Pending { ref audit }
                if audit.reconciliation_count() == 1
        ));

        state_clock.set(NOW + 4);
        let second = store
            .begin_broker_reconciliation(&journal_capability, &create_reconciliation_request(&key))
            .unwrap_or_else(|error| unreachable!("second create GET authority: {error}"));
        let complete = broker
            .reconcile_bound_secret(&store, second)
            .unwrap_or_else(|error| unreachable!("late create reconciliation: {error}"));
        let JournaledSecretReconciliation::CreateCommitted { secret, receipt } = complete else {
            unreachable!("late exact Secret must complete create");
        };
        assert_eq!(secret.uid(), "late-secret-uid");
        assert_eq!(receipt.audit().phase(), BrokerJournalPhase::Committed);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn authenticated_review_commit_loss_recovers_same_bearer_without_second_http() {
        let seed = 8_041;
        let (store, journal_capability, state_clock, key, acquisition) = journal_setup(seed);
        let source = StateBackedAttemptAuthority::new(store.clone(), key.scope.clone());
        let current = source
            .load_current(&acquisition)
            .unwrap_or_else(|error| unreachable!("current attempt fixture: {error}"));
        let script = Arc::new(std::sync::Mutex::new(VecDeque::from([
            ScriptedExchange::Response {
                status: 201,
                body: create_response_for_attempt(&current, "secret-uid"),
            },
            ScriptedExchange::Response {
                status: 201,
                body: token_response(key.transaction_id, "secret-uid"),
            },
            ScriptedExchange::Response {
                status: 201,
                body: authenticated_review_response(key.transaction_id),
            },
        ])));
        let fault = Arc::new(ReviewCommitFault {
            hide_record_result_once: AtomicBool::new(true),
            fail_first_recovery_once: AtomicBool::new(true),
        });
        let fixed_profile = profile();
        let http = FixedHttpsClient::for_test(fixed_profile.route_profile().clone())
            .unwrap_or_else(|error| unreachable!("test HTTPS shell: {error:?}"));
        let broker = EksCredentialBroker {
            profile: fixed_profile,
            management_identities: management_identities(),
            http,
            authority: source,
            management_credentials: ExactManagementSource,
            clock: BrokerClock::new(NOW + 10),
            scripted_exchanges: Some(script.clone()),
            review_commit_fault: Some(fault),
        };

        let created = broker
            .create_bound_secret(
                &store,
                &acquisition,
                create_io_authority(&store, &journal_capability, &state_clock, &acquisition),
            )
            .unwrap_or_else(|error| unreachable!("journaled create: {error}"));
        assert_eq!(created.secret().uid(), "secret-uid");
        let issued = broker
            .request_bound_token(
                &store,
                &acquisition,
                issue_io_authority(
                    &store,
                    &journal_capability,
                    &state_clock,
                    &acquisition,
                    BrokerCredentialSafetyPolicy::new(600, 5)
                        .unwrap_or_else(|error| unreachable!("token policy fixture: {error}")),
                ),
            )
            .unwrap_or_else(|error| unreachable!("journaled token: {error}"));

        state_clock.set(NOW + 4);
        let Err(failed) = broker.review_token(&store, &journal_capability, &acquisition, issued)
        else {
            unreachable!("hidden AUTH commit plus unavailable first SELECT must retain recovery");
        };
        assert!(matches!(failed.failure(), BrokerFailure::JournalState));
        assert!(failed.recovery_key().is_some());
        assert_eq!(
            script
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            0,
            "the ambiguous review must have performed exactly one HTTP exchange"
        );

        let (_failure, issued, recovery) = failed.into_parts();
        let recovered = broker
            .recover_reviewed_token(
                &store,
                &acquisition,
                issued,
                recovery.unwrap_or_else(|| unreachable!("post-begin recovery key")),
            )
            .unwrap_or_else(|error| unreachable!("second state recovery must succeed: {error}"));
        assert_eq!(
            recovered.reviewed().claims().credential_id(),
            "AUTHORIZATION_ID=7ee52be0-9045-4653-aa5e-0da57b8dccdc"
        );
        assert_eq!(
            script
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            0,
            "recovery is state-only and must never perform a second TokenReview"
        );
        recovered
            .into_dispatch_and_executor()
            .unwrap_or_else(|error| unreachable!("recovered bearer remains exclusive: {error}"));
    }

    #[test]
    fn stale_get_generation_is_rejected_before_network_io() {
        let seed = 8_151;
        let (store, journal_capability, state_clock, key, claim) = journal_setup(seed);
        let broker = scripted_broker(
            key.transaction_id,
            vec![
                ScriptedExchange::Failure(BrokerFailure::OutcomeUnknown {
                    operation: BrokerOperation::CreateSecret,
                    reason: FailureReason::ResponseRead,
                    conservative_credential_safe_after: None,
                }),
                ScriptedExchange::Response {
                    status: 404,
                    body: b"{}".to_vec(),
                },
                ScriptedExchange::Response {
                    status: 200,
                    body: create_response(key.transaction_id, "late-secret-uid"),
                },
            ],
        );
        drop(broker.create_bound_secret(
            &store,
            &claim,
            create_io_authority(&store, &journal_capability, &state_clock, &claim),
        ));
        state_clock.set(NOW + 3);
        let request = create_reconciliation_request(&key);
        let first = store
            .begin_broker_reconciliation(&journal_capability, &request)
            .unwrap_or_else(|error| unreachable!("first GET authority: {error}"));
        let stale = store
            .begin_broker_reconciliation(&journal_capability, &request)
            .unwrap_or_else(|error| unreachable!("parallel GET authority: {error}"));
        let pending = broker
            .reconcile_bound_secret(&store, first)
            .unwrap_or_else(|error| unreachable!("first GET result: {error}"));
        assert!(matches!(
            pending,
            JournaledSecretReconciliation::Pending { .. }
        ));
        assert!(matches!(
            broker.reconcile_bound_secret(&store, stale),
            Err(BrokerFailure::JournalState)
        ));
        let remaining = broker
            .scripted_exchanges
            .as_ref()
            .and_then(|script| script.lock().ok().map(|queue| queue.len()));
        assert_eq!(remaining, Some(1));
    }

    #[test]
    fn every_create_failure_class_burns_its_consumed_authority() {
        let cases = vec![
            ScriptedExchange::Failure(BrokerFailure::DefinitelyNotSent {
                operation: BrokerOperation::CreateSecret,
                reason: FailureReason::Connect,
            }),
            ScriptedExchange::Failure(BrokerFailure::OutcomeUnknown {
                operation: BrokerOperation::CreateSecret,
                reason: FailureReason::ResponseRead,
                conservative_credential_safe_after: None,
            }),
            ScriptedExchange::Response {
                status: 409,
                body: b"{}".to_vec(),
            },
            ScriptedExchange::Response {
                status: 201,
                body: b"{}".to_vec(),
            },
        ];
        for (offset, scripted) in cases.into_iter().enumerate() {
            let seed = 8_200 + u128::try_from(offset).unwrap_or_default() * 10;
            let (store, journal_capability, state_clock, key, claim) = journal_setup(seed);
            let broker = scripted_broker(key.transaction_id, vec![scripted]);
            assert!(
                broker
                    .create_bound_secret(
                        &store,
                        &claim,
                        create_io_authority(&store, &journal_capability, &state_clock, &claim),
                    )
                    .is_err()
            );
            let audit = store
                .broker_operation_audit(&key, BrokerJournalOperation::CreateSecret)
                .unwrap_or_else(|error| unreachable!("burned create audit: {error}"));
            assert_eq!(audit.phase(), BrokerJournalPhase::Unknown);
        }
    }

    #[test]
    fn operation_and_policy_substitution_are_burned_before_http() {
        let (store, journal_capability, state_clock, key, claim) = journal_setup(8_301);
        let broker = scripted_broker(key.transaction_id, Vec::new());
        let wrong_operation = broker.request_bound_token(
            &store,
            &claim,
            create_io_authority(&store, &journal_capability, &state_clock, &claim),
        );
        assert!(matches!(
            wrong_operation,
            Err(BrokerFailure::Authority(
                AuthorityResolutionError::InvalidRecord
            ))
        ));
        assert_eq!(
            store
                .broker_operation_audit(&key, BrokerJournalOperation::CreateSecret)
                .unwrap_or_else(|error| unreachable!("operation substitution audit: {error}"))
                .phase(),
            BrokerJournalPhase::Unknown
        );

        let (store, journal_capability, state_clock, key, claim) = journal_setup(8_311);
        store
            .commit_broker_create(
                create_io_authority(&store, &journal_capability, &state_clock, &claim),
                BrokerSecretObservation::matching("secret-uid".to_owned(), [31; 32])
                    .unwrap_or_else(|error| unreachable!("create state fixture: {error}")),
            )
            .unwrap_or_else(|error| unreachable!("create commit fixture: {error}"));
        let broker = scripted_broker(key.transaction_id, Vec::new());
        let wrong_policy = broker.request_bound_token(
            &store,
            &claim,
            issue_io_authority(
                &store,
                &journal_capability,
                &state_clock,
                &claim,
                BrokerCredentialSafetyPolicy::new(500, 5)
                    .unwrap_or_else(|error| unreachable!("substituted policy fixture: {error}")),
            ),
        );
        assert!(matches!(
            wrong_policy,
            Err(BrokerFailure::Authority(
                AuthorityResolutionError::InvalidRecord
            ))
        ));
        assert_eq!(
            store
                .broker_operation_audit(&key, BrokerJournalOperation::IssueToken)
                .unwrap_or_else(|error| unreachable!("policy substitution audit: {error}"))
                .phase(),
            BrokerJournalPhase::Unknown
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn route_name_and_uid_substitution_are_fail_closed() {
        let (store, journal_capability, state_clock, key, claim) = journal_setup(8_351);
        state_clock.set(NOW + 2);
        let route_substituted = store
            .begin_broker_operation_for_acquisition(
                &journal_capability,
                &claim,
                AcquiredBrokerOperationRequest::create(&claim, [77; 32])
                    .unwrap_or_else(|error| unreachable!("substituted route request: {error}")),
            )
            .unwrap_or_else(|error| unreachable!("substituted route authority: {error}"));
        let broker = scripted_broker(key.transaction_id, Vec::new());
        assert!(matches!(
            broker.create_bound_secret(&store, &claim, route_substituted),
            Err(BrokerFailure::Authority(
                AuthorityResolutionError::InvalidRecord
            ))
        ));
        assert_eq!(
            store
                .broker_operation_audit(&key, BrokerJournalOperation::CreateSecret)
                .unwrap_or_else(|error| unreachable!("route substitution audit: {error}"))
                .phase(),
            BrokerJournalPhase::Unknown
        );

        let (store, journal_capability, state_clock, key, claim) = journal_setup(8_361);
        let mut wrong_name: Value =
            serde_json::from_slice(&create_response(key.transaction_id, "secret-uid"))
                .unwrap_or_else(|error| unreachable!("wrong-name fixture parse: {error}"));
        wrong_name["metadata"]["name"] = json!("accordlock-attacker");
        let broker = scripted_broker(
            key.transaction_id,
            vec![ScriptedExchange::Response {
                status: 201,
                body: serde_json::to_vec(&wrong_name)
                    .unwrap_or_else(|error| unreachable!("wrong-name fixture encode: {error}")),
            }],
        );
        assert!(
            broker
                .create_bound_secret(
                    &store,
                    &claim,
                    create_io_authority(&store, &journal_capability, &state_clock, &claim),
                )
                .is_err()
        );
        assert_eq!(
            store
                .broker_operation_audit(&key, BrokerJournalOperation::CreateSecret)
                .unwrap_or_else(|error| unreachable!("name substitution audit: {error}"))
                .phase(),
            BrokerJournalPhase::Unknown
        );

        let (store, journal_capability, state_clock, key, claim) = journal_setup(8_371);
        store
            .commit_broker_create(
                create_io_authority(&store, &journal_capability, &state_clock, &claim),
                BrokerSecretObservation::matching("secret-uid".to_owned(), [37; 32])
                    .unwrap_or_else(|error| unreachable!("create state fixture: {error}")),
            )
            .unwrap_or_else(|error| unreachable!("create commit fixture: {error}"));
        let broker = scripted_broker(
            key.transaction_id,
            vec![ScriptedExchange::Response {
                status: 201,
                body: token_response(key.transaction_id, "attacker-secret-uid"),
            }],
        );
        let wrong_uid = broker.request_bound_token(
            &store,
            &claim,
            issue_io_authority(
                &store,
                &journal_capability,
                &state_clock,
                &claim,
                BrokerCredentialSafetyPolicy::new(600, 5)
                    .unwrap_or_else(|error| unreachable!("token policy fixture: {error}")),
            ),
        );
        assert!(matches!(
            wrong_uid,
            Err(BrokerFailure::OutcomeUnknown {
                operation: BrokerOperation::TokenRequest,
                ..
            })
        ));
        assert_eq!(
            store
                .broker_operation_audit(&key, BrokerJournalOperation::IssueToken)
                .unwrap_or_else(|error| unreachable!("UID substitution audit: {error}"))
                .phase(),
            BrokerJournalPhase::Unknown
        );
    }

    #[test]
    fn token_bearer_is_zeroized_and_does_not_escape_on_state_commit_error() {
        let drops_before = SECRET_TOKEN_DROPS.load(Ordering::SeqCst);
        let result = finish_token_commit(issued(), Err(StateError::BrokerOperationOutcomeUnknown));
        assert!(
            matches!(result, Err(BrokerFailure::JournalState)),
            "unexpected token commit result: {result:?}"
        );
        assert!(SECRET_TOKEN_DROPS.load(Ordering::SeqCst) > drops_before);
    }

    #[test]
    fn state_commit_race_never_restores_consumed_create_authority() {
        let seed = 8_401;
        let (store, journal_capability, state_clock, key, claim) = journal_setup(seed);
        let journal_capability = Arc::new(journal_capability);
        let racing_store = store.clone();
        let racing_journal_capability = Arc::clone(&journal_capability);
        let reconciliation = create_reconciliation_request(&key);
        let broker =
            scripted_broker(
                key.transaction_id,
                vec![ScriptedExchange::ResponseThen {
                    status: 201,
                    body: create_response(key.transaction_id, "secret-uid"),
                    before_return: Box::new(move || {
                        drop(racing_store.begin_broker_reconciliation(
                            &racing_journal_capability,
                            &reconciliation,
                        ));
                    }),
                }],
            );
        let result = broker.create_bound_secret(
            &store,
            &claim,
            create_io_authority(&store, &journal_capability, &state_clock, &claim),
        );
        assert!(matches!(result, Err(BrokerFailure::JournalState)));
        let audit = store
            .broker_operation_audit(&key, BrokerJournalOperation::CreateSecret)
            .unwrap_or_else(|error| unreachable!("raced create commit audit: {error}"));
        assert_eq!(audit.phase(), BrokerJournalPhase::ReconcileOnly);
    }

    fn secret() -> BoundSecret {
        BoundSecret {
            lookup: lookup(),
            namespace: "payments".to_owned(),
            uid: "secret-uid".to_owned(),
            subject: "system:serviceaccount:payments:accordlock-attempt".to_owned(),
            audience: KUBERNETES_API_AUDIENCE.to_owned(),
            attempt: record(),
            creation_evidence_commitment: [8; 32],
        }
    }

    fn secret_json() -> Value {
        json!({
            "apiVersion":"v1",
            "kind":"Secret",
            "metadata":{
                "name":lookup().bound_secret_name,
                "namespace":"payments",
                "uid":"secret-uid",
                "resourceVersion":"7",
                "labels":exact_labels(&profile(), &record())
            },
            "immutable":true,
            "type":"Opaque",
            "data":{}
        })
    }

    fn jwt_token(secret_name: &str) -> Vec<u8> {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "sub":"system:serviceaccount:payments:accordlock-attempt",
                "aud":[KUBERNETES_API_AUDIENCE],
                "exp":1_700_000_100_i64,
                "nbf":1_700_000_000_i64,
                "iat":1_700_000_000_i64,
                "authorization_id":"7ee52be0-9045-4653-aa5e-0da57b8dccdc",
                "kubernetes.io":{
                    "namespace":"payments",
                    "serviceaccount":{"name":"accordlock-attempt","uid":SERVICE_ACCOUNT_UID},
                    "secret":{"name":secret_name,"uid":"secret-uid"}
                }
            }))
            .unwrap_or_default(),
        );
        format!("{header}.{payload}.signature").into_bytes()
    }

    fn issued() -> IssuedToken {
        let token = jwt_token(lookup().bound_secret_name());
        IssuedToken {
            secret: secret(),
            token_digest: Sha256::digest(&token).into(),
            token: SecretToken(token),
            request_started_at: 1_700_000_000,
            returned_at: 1_700_000_001,
            expires_at: 1_700_000_100,
            response_evidence_commitment: [9; 32],
        }
    }

    fn authenticated_review(issued: &IssuedToken) -> Value {
        json!({
            "apiVersion":"authentication.k8s.io/v1",
            "kind":"TokenReview",
            "spec":{
                "audiences":[KUBERNETES_API_AUDIENCE],
                "token":String::from_utf8_lossy(issued.as_bytes())
            },
            "status":{
                "authenticated":true,
                "audiences":[KUBERNETES_API_AUDIENCE],
                "user":{
                    "username":"system:serviceaccount:payments:accordlock-attempt",
                    "uid":SERVICE_ACCOUNT_UID,
                    "groups":[
                        "system:serviceaccounts",
                        "system:serviceaccounts:payments",
                        "system:authenticated"
                    ],
                    "extra":{
                        "authentication.kubernetes.io/credential-id":[
                            "AUTHORIZATION_ID=7ee52be0-9045-4653-aa5e-0da57b8dccdc"
                        ]
                    }
                }
            }
        })
    }

    struct FixedBindingSource {
        binding: ManagementCredentialBinding,
    }

    impl ManagementCredentialSource for FixedBindingSource {
        fn credential(
            &self,
            _request: &ManagementCredentialRequest,
        ) -> Result<ManagementBearer, CredentialSourceError> {
            ManagementBearer::from_trusted_source(
                b"management-fixture".to_vec(),
                self.binding.clone(),
            )
        }
    }

    #[test]
    fn deterministic_lookup_rejects_substitution() {
        assert_eq!(
            lookup().bound_secret_name(),
            "accordlock-00000000000000000000000000000001"
        );
        assert_eq!(
            AttemptLookup::new(Uuid::from_u128(1), "accordlock-attacker".to_owned()),
            Err(LookupError::NonCanonicalName)
        );
    }

    #[test]
    fn state_backed_authority_is_scope_fixed_and_loads_only_rooted_facts() {
        let (state, _journal_capability, _clock, key, authority) = journal_setup(8_491);
        let scope = key.scope.clone();
        let source = StateBackedAttemptAuthority::new(state.clone(), scope.clone());
        assert_eq!(source.scope(), &scope);
        let current = source
            .load_current(&authority)
            .unwrap_or_else(|error| unreachable!("rooted attempt must load: {error}"));
        assert_eq!(current.lookup().transaction_id(), key.transaction_id);
        let wrong_scope = Scope::new("acme", "staging")
            .unwrap_or_else(|error| unreachable!("wrong scope fixture: {error}"));
        let wrong_source = StateBackedAttemptAuthority::new(state, wrong_scope);
        assert!(matches!(
            wrong_source.load_current(&authority),
            Err(AuthorityResolutionError::InvalidRecord)
        ));
    }

    #[test]
    fn credential_time_authority_rotation_blocks_create_before_http_and_burns_io() {
        let (store, journal_capability, state_clock, key, claim) = journal_setup(8_501);
        let current = Arc::new(AtomicBool::new(true));
        let script = Arc::new(std::sync::Mutex::new(VecDeque::from([
            ScriptedExchange::Response {
                status: 201,
                body: create_response(key.transaction_id, "secret-uid"),
            },
        ])));
        let fixed_profile = profile();
        let http = FixedHttpsClient::for_test(fixed_profile.route_profile().clone())
            .unwrap_or_else(|error| unreachable!("test HTTPS shell: {error:?}"));
        let broker = EksCredentialBroker {
            profile: fixed_profile,
            management_identities: management_identities(),
            http,
            authority: RevocableAttemptSource {
                record: attempt_record(key.transaction_id),
                current: current.clone(),
            },
            management_credentials: RevokingManagementSource(current),
            clock: BrokerClock::new(NOW + 10),
            scripted_exchanges: Some(script.clone()),
            review_commit_fault: None,
        };
        let result = broker.create_bound_secret(
            &store,
            &claim,
            create_io_authority(&store, &journal_capability, &state_clock, &claim),
        );
        assert!(matches!(
            result,
            Err(BrokerFailure::Authority(
                AuthorityResolutionError::InvalidRecord
            ))
        ));
        assert_eq!(
            script
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            1,
            "pre-send authority failure must not consume an HTTP exchange"
        );
        assert_eq!(
            store
                .broker_operation_audit(&key, BrokerJournalOperation::CreateSecret)
                .unwrap_or_else(|error| unreachable!("rotated authority audit: {error}"))
                .phase(),
            BrokerJournalPhase::Unknown
        );
    }

    #[test]
    fn credential_time_deadline_expiry_blocks_create_before_http_and_burns_io() {
        let (store, journal_capability, state_clock, key, claim) = journal_setup(8_511);
        let authority_clock = Arc::new(AtomicI64::new(NOW + 10));
        let script = Arc::new(std::sync::Mutex::new(VecDeque::from([
            ScriptedExchange::Response {
                status: 201,
                body: create_response(key.transaction_id, "secret-uid"),
            },
        ])));
        let fixed_profile = profile();
        let http = FixedHttpsClient::for_test(fixed_profile.route_profile().clone())
            .unwrap_or_else(|error| unreachable!("test HTTPS shell: {error:?}"));
        let broker = EksCredentialBroker {
            profile: fixed_profile,
            management_identities: management_identities(),
            http,
            authority: DeadlineAttemptSource {
                record: attempt_record(key.transaction_id),
                clock: authority_clock.clone(),
                deadline: NOW + 20,
            },
            management_credentials: AdvancingManagementSource {
                clock: authority_clock,
                next: NOW + 21,
            },
            clock: BrokerClock::new(NOW + 10),
            scripted_exchanges: Some(script.clone()),
            review_commit_fault: None,
        };
        let result = broker.create_bound_secret(
            &store,
            &claim,
            create_io_authority(&store, &journal_capability, &state_clock, &claim),
        );
        assert!(matches!(
            result,
            Err(BrokerFailure::Authority(
                AuthorityResolutionError::InvalidRecord
            ))
        ));
        assert_eq!(
            script
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            1,
            "deadline expiry between credential and send must produce zero HTTP"
        );
        assert_eq!(
            store
                .broker_operation_audit(&key, BrokerJournalOperation::CreateSecret)
                .unwrap_or_else(|error| unreachable!("expired authority audit: {error}"))
                .phase(),
            BrokerJournalPhase::Unknown
        );
    }

    #[test]
    fn post_management_horizon_resample_blocks_http_before_first_byte() {
        let (store, journal_capability, state_clock, key, acquisition) = journal_setup(8_521);
        // The test transport has a one-second complete-operation bound and
        // rooted uncertainty is five seconds. The first sample has seven
        // seconds of lease left and is valid; management credential retrieval
        // advances the same trusted clock until only one second remains.
        let initial = acquisition.lease_until() - 7;
        let after_management = acquisition.lease_until() - 1;
        let shared_clock = Arc::new(AtomicI64::new(initial));
        let script = Arc::new(std::sync::Mutex::new(VecDeque::from([
            ScriptedExchange::Response {
                status: 201,
                body: create_response(key.transaction_id, "secret-uid"),
            },
        ])));
        let fixed_profile = profile();
        let http = FixedHttpsClient::for_test(fixed_profile.route_profile().clone())
            .unwrap_or_else(|error| unreachable!("test HTTPS shell: {error:?}"));
        let broker = EksCredentialBroker {
            profile: fixed_profile,
            management_identities: management_identities(),
            http,
            authority: FixedAttemptSource(attempt_record(key.transaction_id)),
            management_credentials: AdvancingManagementSource {
                clock: shared_clock.clone(),
                next: after_management,
            },
            clock: BrokerClock(shared_clock),
            scripted_exchanges: Some(script.clone()),
            review_commit_fault: None,
        };

        assert_eq!(
            broker.validate_acquisition_io_window(&acquisition, BrokerOperation::CreateSecret),
            Ok(())
        );
        let result = broker.create_bound_secret(
            &store,
            &acquisition,
            create_io_authority(&store, &journal_capability, &state_clock, &acquisition),
        );
        assert!(matches!(
            result,
            Err(BrokerFailure::DefinitelyNotSent {
                operation: BrokerOperation::CreateSecret,
                reason: FailureReason::Deadline,
            })
        ));
        assert_eq!(
            script
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            1,
            "post-management horizon failure must consume zero HTTP scripts"
        );
        assert_eq!(
            store
                .broker_operation_audit(&key, BrokerJournalOperation::CreateSecret)
                .unwrap_or_else(|error| unreachable!("burned create audit: {error}"))
                .phase(),
            BrokerJournalPhase::Unknown
        );
    }

    #[test]
    fn management_profile_rejects_union_identity_and_union_rbac_scope() {
        let union = management_identity("urn:accordlock:broker:union", 9);
        assert_eq!(
            BrokerManagementIdentities::new(
                union.clone(),
                union,
                management_identity("urn:accordlock:broker:review", 8),
            ),
            Err(ManagementIdentityError::IdentityReusedAcrossAuthorities)
        );

        assert_eq!(
            BrokerManagementIdentities::new(
                management_identity("urn:accordlock:broker:secret", 7),
                management_identity("urn:accordlock:broker:token", 7),
                management_identity("urn:accordlock:broker:review", 8),
            ),
            Err(ManagementIdentityError::AuthorizationReusedAcrossAuthorities)
        );
    }

    #[test]
    fn rooted_lifecycle_and_management_bindings_must_equal_fixed_config() {
        let broker = scripted_broker(lookup().transaction_id(), Vec::new());
        let exact = record();
        assert_eq!(broker.validate_attempt_record(&exact, &lookup()), Ok(()));

        let mut wrong_policy = exact.clone();
        let substituted = EksCredentialLifecyclePolicy::new(61, 600, 5, 60)
            .unwrap_or_else(|error| unreachable!("substituted lifecycle fixture: {error}"));
        wrong_policy.credential_lifecycle_policy = substituted;
        wrong_policy.credential_lifecycle_commitment = substituted.commitment();
        wrong_policy.credential_lifecycle_policy_id = substituted.policy_id().to_owned();
        assert!(matches!(
            broker.validate_attempt_record(&wrong_policy, &lookup()),
            Err(BrokerFailure::Authority(
                AuthorityResolutionError::InvalidRecord
            ))
        ));

        let mut wrong_management = exact;
        let configured = rooted_management_bindings();
        wrong_management.broker_management_bindings = EksBrokerManagementBindings::new(
            EksManagementAuthorityBinding::new("urn:accordlock:broker:substituted", [11; 32])
                .unwrap_or_else(|error| unreachable!("substituted management fixture: {error}")),
            configured.service_account_token().clone(),
            configured.token_review().clone(),
        )
        .unwrap_or_else(|error| unreachable!("separated substituted fixture: {error}"));
        assert!(matches!(
            broker.validate_attempt_record(&wrong_management, &lookup()),
            Err(BrokerFailure::Authority(
                AuthorityResolutionError::InvalidRecord
            ))
        ));
    }

    #[test]
    fn source_wrong_operation_is_rejected_before_exchange() {
        let identities = management_identities();
        let request = ManagementCredentialRequest::new(
            secret_create_management_operation(&profile(), &lookup()),
            identities.secret_lifecycle.clone(),
        );
        let source = FixedBindingSource {
            binding: ManagementCredentialBinding::new(
                token_review_management_operation(&profile(), &issued()),
                identities.secret_lifecycle,
            ),
        };
        let bearer = source
            .credential(&request)
            .unwrap_or_else(|error| unreachable!("fixture source: {error}"));
        assert_eq!(
            bearer.validate_for(&request),
            Err(CredentialSourceError::OperationBindingMismatch)
        );
    }

    #[test]
    fn source_wrong_identity_is_rejected_before_exchange() {
        let identities = management_identities();
        let operation = secret_create_management_operation(&profile(), &lookup());
        let request =
            ManagementCredentialRequest::new(operation.clone(), identities.secret_lifecycle);
        let source = FixedBindingSource {
            binding: ManagementCredentialBinding::new(operation, identities.token_review),
        };
        let bearer = source
            .credential(&request)
            .unwrap_or_else(|error| unreachable!("fixture source: {error}"));
        assert_eq!(
            bearer.validate_for(&request),
            Err(CredentialSourceError::IdentityBindingMismatch)
        );
    }

    #[test]
    fn token_review_credential_cannot_be_reused_for_secret_create() {
        let identities = management_identities();
        let review_request = ManagementCredentialRequest::new(
            token_review_management_operation(&profile(), &issued()),
            identities.token_review,
        );
        let review_bearer = ManagementBearer::from_trusted_source(
            b"review-only-management-token".to_vec(),
            review_request.binding(),
        )
        .unwrap_or_else(|error| unreachable!("fixture bearer: {error}"));
        let create_request = ManagementCredentialRequest::new(
            secret_create_management_operation(&profile(), &lookup()),
            identities.secret_lifecycle,
        );
        assert_eq!(
            review_bearer.validate_for(&create_request),
            Err(CredentialSourceError::OperationBindingMismatch)
        );
    }

    #[test]
    fn secret_delete_binding_is_exact_route_name_and_uid() {
        let operation = secret_delete_management_operation(&profile(), &secret());
        let expected_request = ManagementCredentialRequest::new(
            operation.clone(),
            management_identities().secret_lifecycle().clone(),
        );
        let BrokerManagementOperation::SecretDelete {
            route_commitment,
            namespace,
            secret_name,
            secret_uid,
        } = operation
        else {
            unreachable!("delete helper must produce the delete operation");
        };
        assert_eq!(route_commitment, route().commitment());
        assert_eq!(namespace, "payments");
        assert_eq!(secret_name, lookup().bound_secret_name());
        assert_eq!(secret_uid, "secret-uid");

        let substituted = ManagementBearer::from_trusted_source(
            b"delete-management-token".to_vec(),
            ManagementCredentialBinding::new(
                BrokerManagementOperation::SecretDelete {
                    route_commitment,
                    namespace,
                    secret_name,
                    secret_uid: "attacker-secret-uid".to_owned(),
                },
                management_identities().secret_lifecycle().clone(),
            ),
        )
        .unwrap_or_else(|error| unreachable!("valid delete fixture: {error}"));
        assert_eq!(
            substituted.validate_for(&expected_request),
            Err(CredentialSourceError::OperationBindingMismatch)
        );
    }

    #[test]
    fn token_request_binding_names_exact_service_account_uid_and_audience() {
        assert_eq!(
            token_request_management_operation(&profile(), &secret()),
            BrokerManagementOperation::ServiceAccountTokenCreate {
                route_commitment: route().commitment(),
                namespace: "payments".to_owned(),
                service_account_name: "accordlock-attempt".to_owned(),
                service_account_uid: SERVICE_ACCOUNT_UID.to_owned(),
                audience: KUBERNETES_API_AUDIENCE.to_owned(),
                bound_secret_name: lookup().bound_secret_name().to_owned(),
                bound_secret_uid: "secret-uid".to_owned(),
            }
        );
    }

    #[test]
    fn broker_ca_bytes_must_match_the_shared_route_commitment() {
        let exact = BrokerConfig::new(
            BrokerEndpointConfig::new(vec![b"broker-test-ca".to_vec()]),
            profile(),
            management_identities(),
        );
        assert_eq!(validate_config(&exact), Ok(()));

        let substituted = BrokerConfig::new(
            BrokerEndpointConfig::new(vec![b"substituted-ca".to_vec()]),
            profile(),
            management_identities(),
        );
        assert_eq!(
            validate_config(&substituted),
            Err(BrokerConfigError::CaTrustCommitmentMismatch)
        );
    }

    #[test]
    fn secret_projection_requires_exact_labels_and_no_finalizers() {
        let body = serde_json::to_vec(&secret_json()).unwrap_or_default();
        assert!(parse_matching_secret(&body, &profile(), &record(), [7; 32]).is_some());

        let mut extra_label = secret_json();
        extra_label["metadata"]["labels"]["attacker.example/x"] = json!("y");
        assert!(
            parse_matching_secret(
                &serde_json::to_vec(&extra_label).unwrap_or_default(),
                &profile(),
                &record(),
                [7; 32]
            )
            .is_none()
        );

        let mut finalizer = secret_json();
        finalizer["metadata"]["finalizers"] = json!(["attacker.example/hold"]);
        assert!(
            parse_matching_secret(
                &serde_json::to_vec(&finalizer).unwrap_or_default(),
                &profile(),
                &record(),
                [7; 32]
            )
            .is_none()
        );
    }

    #[test]
    fn labels_are_kubernetes_sized_commitments() {
        let labels = exact_labels(&profile(), &record());
        assert_eq!(labels.len(), 9);
        for (key, value) in labels {
            assert!(key.len() <= 63);
            assert!(value.len() <= 63);
        }
    }

    #[test]
    fn token_request_accepts_server_duration_above_request_but_below_server_bound() {
        let raw = b"header.payload.signature";
        let response = json!({
            "apiVersion":"authentication.k8s.io/v1",
            "kind":"TokenRequest",
            "spec":{
                "audiences":[KUBERNETES_API_AUDIENCE],
                "expirationSeconds":60,
                "boundObjectRef":{
                    "apiVersion":"v1","kind":"Secret",
                    "name":lookup().bound_secret_name,
                    "uid":"secret-uid"
                }
            },
            "status":{
                "token":String::from_utf8_lossy(raw),
                "expirationTimestamp":"2023-11-14T22:15:00Z"
            }
        });
        let parsed = parse_token_request_response(
            &serde_json::to_vec(&response).unwrap_or_default(),
            &profile(),
            &secret(),
            1_700_000_000,
            1_700_000_001,
        );
        assert!(parsed.is_some());

        let mut beyond = response;
        beyond["status"]["expirationTimestamp"] = json!("2023-11-14T22:30:00Z");
        assert!(
            parse_token_request_response(
                &serde_json::to_vec(&beyond).unwrap_or_default(),
                &profile(),
                &secret(),
                1_700_000_000,
                1_700_000_001,
            )
            .is_none()
        );
    }

    #[test]
    fn token_review_requires_exact_echo_subject_audience_and_bound_claims() {
        let issued = issued();
        let response = authenticated_review(&issued);
        let parsed = parse_token_review_response(
            &serde_json::to_vec(&response).unwrap_or_default(),
            &profile(),
            &issued,
            1_700_000_002,
            [6; 32],
        );
        let Some(ParsedReview::Authenticated { claims, .. }) = parsed else {
            unreachable!("modern Kubernetes TokenReview fixture must authenticate");
        };
        assert_eq!(claims.service_account_uid, SERVICE_ACCOUNT_UID);
        assert_eq!(
            claims.credential_id,
            "AUTHORIZATION_ID=7ee52be0-9045-4653-aa5e-0da57b8dccdc"
        );

        let mut wrong_subject = response;
        wrong_subject["status"]["user"]["username"] =
            json!("system:serviceaccount:payments:attacker");
        assert!(
            parse_token_review_response(
                &serde_json::to_vec(&wrong_subject).unwrap_or_default(),
                &profile(),
                &issued,
                1_700_000_002,
                [6; 32]
            )
            .is_none()
        );
    }

    #[test]
    fn token_review_rejects_uid_extra_and_authorization_id_substitution_profiles() {
        let issued = issued();
        let rejects = |value: &Value| {
            parse_token_review_response(
                &serde_json::to_vec(value).unwrap_or_default(),
                &profile(),
                &issued,
                1_700_000_002,
                [6; 32],
            )
            .is_none()
        };

        let mut uid_swap = authenticated_review(&issued);
        uid_swap["status"]["user"]["uid"] = json!("other-service-account-uid");
        assert!(rejects(&uid_swap));

        let mut missing = authenticated_review(&issued);
        if let Some(user) = missing["status"]["user"].as_object_mut() {
            user.remove("extra");
        }
        assert!(rejects(&missing));

        let mut duplicate_value = authenticated_review(&issued);
        duplicate_value["status"]["user"]["extra"][CREDENTIAL_ID_EXTRA_KEY] = json!([
            "AUTHORIZATION_ID=7ee52be0-9045-4653-aa5e-0da57b8dccdc",
            "AUTHORIZATION_ID=7ee52be0-9045-4653-aa5e-0da57b8dccdc"
        ]);
        assert!(rejects(&duplicate_value));

        let mut unknown = authenticated_review(&issued);
        unknown["status"]["user"]["extra"]["authentication.kubernetes.io/pod-name"] =
            json!(["attacker-pod"]);
        assert!(rejects(&unknown));

        let mut authorization_id_mismatch = authenticated_review(&issued);
        authorization_id_mismatch["status"]["user"]["extra"][CREDENTIAL_ID_EXTRA_KEY] =
            json!(["AUTHORIZATION_ID=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"]);
        assert!(rejects(&authorization_id_mismatch));
    }

    #[test]
    fn token_review_rejects_duplicate_extra_json_key() {
        let issued = issued();
        let encoded = serde_json::to_string(&authenticated_review(&issued)).unwrap_or_default();
        let needle = concat!(
            "\"authentication.kubernetes.io/credential-id\":[",
            "\"AUTHORIZATION_ID=7ee52be0-9045-4653-aa5e-0da57b8dccdc\"]"
        );
        let duplicate = format!("{needle},{needle}");
        let body = encoded.replacen(needle, &duplicate, 1);
        assert!(
            parse_token_review_response(
                body.as_bytes(),
                &profile(),
                &issued,
                1_700_000_002,
                [6; 32]
            )
            .is_none()
        );
    }

    #[test]
    fn tokenreview_error_is_not_rejection_evidence() {
        let issued = issued();
        let base = json!({
            "apiVersion":"authentication.k8s.io/v1",
            "kind":"TokenReview",
            "spec":{"audiences":[KUBERNETES_API_AUDIENCE],"token":String::from_utf8_lossy(issued.as_bytes())},
            "status":{"authenticated":false}
        });
        assert!(matches!(
            parse_token_review_response(
                &serde_json::to_vec(&base).unwrap_or_default(),
                &profile(),
                &issued,
                1_700_000_002,
                [6; 32]
            ),
            Some(ParsedReview::Rejected { .. })
        ));
        let mut errored = base;
        errored["status"]["error"] = json!("backend unavailable");
        assert!(
            parse_token_review_response(
                &serde_json::to_vec(&errored).unwrap_or_default(),
                &profile(),
                &issued,
                1_700_000_002,
                [6; 32]
            )
            .is_none()
        );
    }

    #[test]
    fn retirement_always_waits_for_delay_after_absence_even_with_rejection() {
        let deletion = DeletionEvidence {
            lookup: lookup(),
            secret_uid: "secret-uid".to_owned(),
            absent_observed_at: 1000,
            evidence_commitment: [3; 32],
        };
        assert_eq!(
            assess_retirement_at(&profile(), &deletion, None, 1064),
            Ok(RetirementAssessment::Pending { safe_after: 1065 })
        );
        assert_eq!(
            assess_retirement_at(&profile(), &deletion, None, 1065),
            Ok(RetirementAssessment::Confirmed(
                RetirementBasis::ConservativeInvalidationDelayElapsed
            ))
        );
        let rejection = TokenRejectionEvidence {
            lookup: lookup(),
            secret_uid: "secret-uid".to_owned(),
            token_digest: [4; 32],
            observed_at: 1001,
            evidence_commitment: [5; 32],
        };
        assert_eq!(
            assess_retirement_at(&profile(), &deletion, Some(&rejection), 1001),
            Ok(RetirementAssessment::Pending { safe_after: 1065 })
        );
        assert_eq!(
            assess_retirement_at(&profile(), &deletion, Some(&rejection), 1065),
            Ok(RetirementAssessment::Confirmed(
                RetirementBasis::ConservativeInvalidationDelayElapsed
            ))
        );
        let stale_rejection = TokenRejectionEvidence {
            observed_at: 999,
            ..rejection
        };
        assert_eq!(
            assess_retirement_at(&profile(), &deletion, Some(&stale_rejection), 1001),
            Err(BrokerFailure::InvalidObservation {
                operation: BrokerOperation::TokenReview
            })
        );
    }

    #[test]
    fn debug_output_redacts_raw_tokens() {
        let operation = secret_create_management_operation(&profile(), &lookup());
        let binding = ManagementCredentialBinding::new(
            operation,
            management_identities().secret_lifecycle.clone(),
        );
        let management =
            ManagementBearer::from_trusted_source(b"management-secret".to_vec(), binding)
                .unwrap_or_else(|error| unreachable!("fixture must be valid: {error}"));
        assert!(!format!("{management:?}").contains("management-secret"));
        assert!(!format!("{:?}", issued()).contains("eyJ"));
    }
}
