//! Purpose-separated, canonical terminal-witness envelopes.
//!
//! This crate verifies signatures and exact bindings. It does not establish
//! observer truth and exposes no state-release operation.

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::fmt;

use accordlock_protocol::{
    CoseVerifier, CryptoError, Digest32, MAX_COSE_SIZE_BYTES, MAX_KEY_ID_BYTES, SigningIdentity,
    sign_cose, verify_cose,
};
use minicbor::{Decoder, Encoder, decode::Error as DecodeError, encode::Error as EncodeError};
use thiserror::Error;
use uuid::Uuid;

/// COSE external-AAD domain for the sole enabled terminal-effect profile.
pub const EXACT_EFFECT_WITNESS_DOMAIN: &str = "accordlock:v1:terminal-exact-effect-witness";
/// COSE external-AAD domain for exact credential-retirement evidence.
pub const CREDENTIAL_RETIREMENT_WITNESS_DOMAIN: &str =
    "accordlock:v1:credential-retirement-witness";
/// Domain prefix for canonical verifier-entry material.
pub const WITNESS_REGISTRY_MATERIAL_DOMAIN: &[u8] =
    b"accordlock:v1:terminal-witness-registry-material\0";
/// Domain prefix for the full material-root, epoch, and activation commitment.
pub const WITNESS_REGISTRY_COMMITMENT_DOMAIN: &[u8] =
    b"accordlock:v1:activated-terminal-witness-registry\0";
/// Domain prefix for one canonical immutable terminal-attempt binding.
pub const TERMINAL_ATTEMPT_BINDING_COMMITMENT_DOMAIN: &[u8] =
    b"accordlock:v1:terminal-attempt-binding\0";
/// Domain prefix for the bearer-free payload `TokenReview` request.
pub const TOKEN_REVIEW_REQUEST_COMMITMENT_DOMAIN: &[u8] =
    b"accordlock:v2:terminal-token-review-request\0";
/// Domain prefix for the durable payload Secret-deletion observation.
pub const SECRET_DELETION_OBSERVATION_COMMITMENT_DOMAIN: &[u8] =
    b"accordlock:v2:terminal-secret-deletion-observation\0";
/// Only accepted canonical payload schema.
pub const TERMINAL_WITNESS_SCHEMA_VERSION: u16 = 1;
/// Maximum verifier registrations accepted in one activated registry.
pub const MAX_WITNESS_REGISTRY_ENTRIES: usize = 256;
/// Maximum deterministic CBOR claims bytes accepted for either profile.
pub const MAX_TERMINAL_WITNESS_CLAIMS_BYTES: usize = 65_536;
/// Maximum persisted envelope size (claims plus exact COSE and framing).
pub const MAX_TERMINAL_WITNESS_ENVELOPE_BYTES: usize =
    MAX_COSE_SIZE_BYTES + MAX_TERMINAL_WITNESS_CLAIMS_BYTES + 1_024;

const MAX_SCOPE_COMPONENT_BYTES: usize = 512;
const MAX_CLUSTER_IDENTITY_BYTES: usize = 512;
const MAX_KUBERNETES_UID_BYTES: usize = 512;
const MAX_DNS_SUBDOMAIN_BYTES: usize = 253;
const MAX_OBSERVER_IDENTITY_BYTES: usize = 512;
const MAX_AUDIENCE_BYTES: usize = 4_096;
const MAX_SUBJECT_BYTES: usize = 4_096;
const MAX_CREDENTIAL_ID_BYTES: usize = 64;
const MAX_AUDIT_CURSOR_BYTES: usize = 1_024;
const MAX_POLICY_ID_BYTES: usize = 256;
const MAX_SERVER_TOKEN_LIFETIME_HARD_S: i64 = 86_400;
const MAX_DELETION_PROPAGATION_HARD_S: i64 = 86_400;
const MAX_CLOCK_UNCERTAINTY_S: i64 = 300;

/// Fail-closed validation and verification errors.
#[derive(Debug, Error)]
pub enum WitnessError {
    #[error("terminal witness record is invalid: {0}")]
    InvalidRecord(&'static str),
    #[error("verifier registry is not in canonical order")]
    NonCanonicalRegistry,
    #[error("verifier registry contains a duplicate or aliased identity")]
    RegistryIdentityAlias,
    #[error("verifier registry does not contain both purpose-separated roles")]
    MissingVerifierRole,
    #[error("activated verifier registry commitment does not match its canonical entries")]
    RegistryCommitmentMismatch,
    #[error("terminal witness key is not registered")]
    UnknownVerifier,
    #[error("terminal witness key is registered for another purpose")]
    VerifierRoleMismatch,
    #[error("terminal witness key is inactive for this observation")]
    VerifierInactive,
    #[error("terminal witness observer, scope, cluster, or authority version is not registered")]
    VerifierBindingMismatch,
    #[error("signed payload differs from the canonical claims")]
    PayloadMismatch,
    #[error("terminal-witness wire object is not in the accepted deterministic encoding")]
    NonCanonicalWire,
    #[error("terminal witness does not exactly match the expected durable attempt")]
    AttemptBindingMismatch,
    #[error("credential witness does not exactly match the expected durable credential")]
    CredentialBindingMismatch,
    #[error("credential witness does not match the expected durable Secret deletion")]
    DeletionBindingMismatch,
    #[error("TokenReview witness does not match the expected durable request commitment")]
    TokenReviewBindingMismatch,
    #[error("conservative retirement bound does not match durable policy state")]
    ConservativePolicyMismatch,
    #[error("terminal witness observation is future, pre-attempt, or non-monotone")]
    InvalidObservationTime,
    #[error("canonical terminal-witness encoding failed: {0}")]
    Canonical(String),
    #[error("terminal-witness cryptographic verification failed: {0}")]
    Crypto(#[from] CryptoError),
}

/// Exact tenant and environment partition.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WitnessScope {
    tenant: String,
    environment: String,
}

impl WitnessScope {
    /// Constructs an exact, non-normalized scope.
    ///
    /// # Errors
    ///
    /// Rejects empty, padded, control-bearing, or oversized components.
    pub fn new(
        tenant: impl Into<String>,
        environment: impl Into<String>,
    ) -> Result<Self, WitnessError> {
        let value = Self {
            tenant: tenant.into(),
            environment: environment.into(),
        };
        if !valid_security_text(&value.tenant, MAX_SCOPE_COMPONENT_BYTES)
            || !valid_security_text(&value.environment, MAX_SCOPE_COMPONENT_BYTES)
        {
            return Err(WitnessError::InvalidRecord("invalid witness scope"));
        }
        Ok(value)
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

/// Exact destination and physical Deployment identity frozen for an attempt.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PhysicalResourceBinding {
    cluster_trust_domain: String,
    api_server_identity: String,
    cluster_identity: String,
    namespace: String,
    deployment_uid: String,
    resource_name: String,
}

impl PhysicalResourceBinding {
    /// Constructs the complete destination binding without normalization.
    ///
    /// # Errors
    ///
    /// Rejects malformed, empty, padded, control-bearing, or oversized values.
    pub fn new(
        cluster_trust_domain: impl Into<String>,
        api_server_identity: impl Into<String>,
        cluster_identity: impl Into<String>,
        namespace: impl Into<String>,
        deployment_uid: impl Into<String>,
        resource_name: impl Into<String>,
    ) -> Result<Self, WitnessError> {
        let value = Self {
            cluster_trust_domain: cluster_trust_domain.into(),
            api_server_identity: api_server_identity.into(),
            cluster_identity: cluster_identity.into(),
            namespace: namespace.into(),
            deployment_uid: deployment_uid.into(),
            resource_name: resource_name.into(),
        };
        if !valid_security_text(&value.cluster_trust_domain, MAX_CLUSTER_IDENTITY_BYTES)
            || !valid_security_text(&value.api_server_identity, MAX_CLUSTER_IDENTITY_BYTES)
            || !valid_security_text(&value.cluster_identity, MAX_CLUSTER_IDENTITY_BYTES)
            || !valid_dns_subdomain(&value.namespace)
            || !valid_security_text(&value.deployment_uid, MAX_KUBERNETES_UID_BYTES)
            || !valid_dns_subdomain(&value.resource_name)
        {
            return Err(WitnessError::InvalidRecord(
                "invalid physical resource binding",
            ));
        }
        Ok(value)
    }

    #[must_use]
    pub fn cluster_trust_domain(&self) -> &str {
        &self.cluster_trust_domain
    }

    #[must_use]
    pub fn api_server_identity(&self) -> &str {
        &self.api_server_identity
    }

    #[must_use]
    pub fn cluster_identity(&self) -> &str {
        &self.cluster_identity
    }

    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    #[must_use]
    pub fn deployment_uid(&self) -> &str {
        &self.deployment_uid
    }

    #[must_use]
    pub fn resource_name(&self) -> &str {
        &self.resource_name
    }
}

/// Immutable state lineage, claim, fence, routing, and attempt-start tuple.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptIdentity {
    state_instance_id: Uuid,
    scope: WitnessScope,
    transaction_id: Uuid,
    authorization_id: Uuid,
    claim_id: Uuid,
    fence: u64,
    physical_resource: PhysicalResourceBinding,
    attempt_started_at: i64,
}

impl AttemptIdentity {
    /// Builds one exact immutable attempt identity.
    ///
    /// # Errors
    ///
    /// Rejects nil identifiers, zero fence, or nonpositive start time.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state_instance_id: Uuid,
        scope: WitnessScope,
        transaction_id: Uuid,
        authorization_id: Uuid,
        claim_id: Uuid,
        fence: u64,
        physical_resource: PhysicalResourceBinding,
        attempt_started_at: i64,
    ) -> Result<Self, WitnessError> {
        if state_instance_id.is_nil()
            || transaction_id.is_nil()
            || authorization_id.is_nil()
            || claim_id.is_nil()
            || fence == 0
            || attempt_started_at <= 0
        {
            return Err(WitnessError::InvalidRecord(
                "invalid attempt identity or start time",
            ));
        }
        Ok(Self {
            state_instance_id,
            scope,
            transaction_id,
            authorization_id,
            claim_id,
            fence,
            physical_resource,
            attempt_started_at,
        })
    }

    #[must_use]
    pub const fn state_instance_id(&self) -> Uuid {
        self.state_instance_id
    }

    #[must_use]
    pub const fn scope(&self) -> &WitnessScope {
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
    pub const fn fence(&self) -> u64 {
        self.fence
    }

    #[must_use]
    pub const fn physical_resource(&self) -> &PhysicalResourceBinding {
        &self.physical_resource
    }

    #[must_use]
    pub const fn attempt_started_at(&self) -> i64 {
        self.attempt_started_at
    }
}

/// The seven nonzero commitments frozen before provider I/O.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectBindingCommitments {
    route_commitment: Digest32,
    template_hash: Digest32,
    operation_hash: Digest32,
    execution_command_commitment: Digest32,
    final_provider_wire_commitment: Digest32,
    effective_rbac_commitment: Digest32,
    token_digest: Digest32,
}

impl EffectBindingCommitments {
    /// Builds the complete frozen effect binding.
    ///
    /// # Errors
    ///
    /// Rejects any zero commitment.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        route_commitment: Digest32,
        template_hash: Digest32,
        operation_hash: Digest32,
        execution_command_commitment: Digest32,
        final_provider_wire_commitment: Digest32,
        effective_rbac_commitment: Digest32,
        token_digest: Digest32,
    ) -> Result<Self, WitnessError> {
        let value = Self {
            route_commitment,
            template_hash,
            operation_hash,
            execution_command_commitment,
            final_provider_wire_commitment,
            effective_rbac_commitment,
            token_digest,
        };
        if value.digests().into_iter().any(is_zero_digest) {
            return Err(WitnessError::InvalidRecord(
                "effect binding contains a zero commitment",
            ));
        }
        Ok(value)
    }

    fn digests(&self) -> [Digest32; 7] {
        [
            self.route_commitment,
            self.template_hash,
            self.operation_hash,
            self.execution_command_commitment,
            self.final_provider_wire_commitment,
            self.effective_rbac_commitment,
            self.token_digest,
        ]
    }

    #[must_use]
    pub const fn route_commitment(&self) -> Digest32 {
        self.route_commitment
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
    pub const fn final_provider_wire_commitment(&self) -> Digest32 {
        self.final_provider_wire_commitment
    }

    #[must_use]
    pub const fn effective_rbac_commitment(&self) -> Digest32 {
        self.effective_rbac_commitment
    }

    #[must_use]
    pub const fn token_digest(&self) -> Digest32 {
        self.token_digest
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AdmissionLinkageKind {
    NotRequired,
    Required {
        admission_uid: String,
        request_commitment: Digest32,
    },
}

/// Unambiguous admission requirement and exact durable authorization linkage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionLinkage {
    kind: AdmissionLinkageKind,
}

impl AdmissionLinkage {
    #[must_use]
    pub const fn not_required() -> Self {
        Self {
            kind: AdmissionLinkageKind::NotRequired,
        }
    }

    /// Requires the exact durable admission UID and request commitment.
    ///
    /// # Errors
    ///
    /// Rejects malformed UIDs or a zero request commitment.
    pub fn required(
        admission_uid: impl Into<String>,
        request_commitment: Digest32,
    ) -> Result<Self, WitnessError> {
        let admission_uid = admission_uid.into();
        if !valid_admission_uid(&admission_uid) || is_zero_digest(request_commitment) {
            return Err(WitnessError::InvalidRecord(
                "invalid required admission linkage",
            ));
        }
        Ok(Self {
            kind: AdmissionLinkageKind::Required {
                admission_uid,
                request_commitment,
            },
        })
    }

    #[must_use]
    pub const fn is_required(&self) -> bool {
        matches!(self.kind, AdmissionLinkageKind::Required { .. })
    }

    #[must_use]
    pub fn admission_uid(&self) -> Option<&str> {
        match &self.kind {
            AdmissionLinkageKind::NotRequired => None,
            AdmissionLinkageKind::Required { admission_uid, .. } => Some(admission_uid),
        }
    }

    #[must_use]
    pub const fn request_commitment(&self) -> Option<Digest32> {
        match self.kind {
            AdmissionLinkageKind::NotRequired => None,
            AdmissionLinkageKind::Required {
                request_commitment, ..
            } => Some(request_commitment),
        }
    }
}

/// Complete immutable attempt tuple shared by both witness purposes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TerminalAttemptBinding {
    identity: AttemptIdentity,
    effect: EffectBindingCommitments,
    admission: AdmissionLinkage,
}

impl TerminalAttemptBinding {
    #[must_use]
    pub const fn new(
        identity: AttemptIdentity,
        effect: EffectBindingCommitments,
        admission: AdmissionLinkage,
    ) -> Self {
        Self {
            identity,
            effect,
            admission,
        }
    }

    #[must_use]
    pub const fn identity(&self) -> &AttemptIdentity {
        &self.identity
    }

    #[must_use]
    pub const fn effect(&self) -> &EffectBindingCommitments {
        &self.effect
    }

    #[must_use]
    pub const fn admission(&self) -> &AdmissionLinkage {
        &self.admission
    }

    /// Returns the canonical, domain-separated commitment to every immutable
    /// attempt field.
    ///
    /// # Errors
    ///
    /// Returns an error if the attempt is invalid or its bounded canonical
    /// representation cannot be encoded.
    pub fn commitment(&self) -> Result<Digest32, WitnessError> {
        validate_attempt(self)?;
        canonical_commitment(
            TERMINAL_ATTEMPT_BINDING_COMMITMENT_DOMAIN,
            &canonical_attempt_binding(self)?,
        )
    }
}

/// Signed observer identity and immutable registry authority version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessIssuer {
    observer_identity: String,
    key_id: String,
    authority_version: u64,
}

impl WitnessIssuer {
    /// Builds exact signed issuer metadata.
    ///
    /// # Errors
    ///
    /// Rejects malformed identities/key IDs or authority version zero.
    pub fn new(
        observer_identity: impl Into<String>,
        key_id: impl Into<String>,
        authority_version: u64,
    ) -> Result<Self, WitnessError> {
        let value = Self {
            observer_identity: observer_identity.into(),
            key_id: key_id.into(),
            authority_version,
        };
        if !valid_security_text(&value.observer_identity, MAX_OBSERVER_IDENTITY_BYTES)
            || !valid_security_text(&value.key_id, MAX_KEY_ID_BYTES)
            || value.authority_version == 0
        {
            return Err(WitnessError::InvalidRecord("invalid witness issuer"));
        }
        Ok(value)
    }

    #[must_use]
    pub fn observer_identity(&self) -> &str {
        &self.observer_identity
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub const fn authority_version(&self) -> u64 {
        self.authority_version
    }
}

/// The only enabled terminal-effect classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectClassification {
    ExactEffectV1,
}

impl EffectClassification {
    const fn code(self) -> u8 {
        match self {
            Self::ExactEffectV1 => 1,
        }
    }
}

/// The only operation-specific exact effect enabled by the current EKS slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExactExecutionOutcome {
    KubernetesDeploymentUpdatedV1,
}

impl ExactExecutionOutcome {
    const fn code(self) -> u8 {
        match self {
            Self::KubernetesDeploymentUpdatedV1 => 1,
        }
    }
}

/// Complete exact-effect result authenticated by an effect observer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectObservationResult {
    outcome: ExactExecutionOutcome,
    response_commitment: Digest32,
    post_state_commitment: Digest32,
    complete_observation_commitment: Digest32,
    resource_uid: String,
    resource_version: String,
    audit_cursor: String,
}

impl EffectObservationResult {
    /// Constructs the operation-specific exact Deployment-update result.
    ///
    /// # Errors
    ///
    /// Rejects zero commitments or malformed destination identifiers.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        outcome: ExactExecutionOutcome,
        response_commitment: Digest32,
        post_state_commitment: Digest32,
        complete_observation_commitment: Digest32,
        resource_uid: impl Into<String>,
        resource_version: impl Into<String>,
        audit_cursor: impl Into<String>,
    ) -> Result<Self, WitnessError> {
        let value = Self {
            outcome,
            response_commitment,
            post_state_commitment,
            complete_observation_commitment,
            resource_uid: resource_uid.into(),
            resource_version: resource_version.into(),
            audit_cursor: audit_cursor.into(),
        };
        if [
            value.response_commitment,
            value.post_state_commitment,
            value.complete_observation_commitment,
        ]
        .into_iter()
        .any(is_zero_digest)
            || !valid_security_text(&value.resource_uid, MAX_KUBERNETES_UID_BYTES)
            || !valid_security_text(&value.resource_version, MAX_KUBERNETES_UID_BYTES)
            || !valid_security_text(&value.audit_cursor, MAX_AUDIT_CURSOR_BYTES)
        {
            return Err(WitnessError::InvalidRecord(
                "invalid exact-effect observation result",
            ));
        }
        Ok(value)
    }

    #[must_use]
    pub const fn outcome(&self) -> ExactExecutionOutcome {
        self.outcome
    }

    #[must_use]
    pub const fn response_commitment(&self) -> Digest32 {
        self.response_commitment
    }

    #[must_use]
    pub const fn post_state_commitment(&self) -> Digest32 {
        self.post_state_commitment
    }

    #[must_use]
    pub const fn complete_observation_commitment(&self) -> Digest32 {
        self.complete_observation_commitment
    }

    #[must_use]
    pub fn resource_uid(&self) -> &str {
        &self.resource_uid
    }

    #[must_use]
    pub fn resource_version(&self) -> &str {
        &self.resource_version
    }

    #[must_use]
    pub fn audit_cursor(&self) -> &str {
        &self.audit_cursor
    }
}

/// Canonical caller-independent claims covered by an exact-effect signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectObservationClaims {
    evidence_id: Uuid,
    attempt: TerminalAttemptBinding,
    issuer: WitnessIssuer,
    result: EffectObservationResult,
    observation_started_at: i64,
    observed_at: i64,
}

impl EffectObservationClaims {
    /// Constructs exact-effect claims with strict temporal ordering.
    ///
    /// # Errors
    ///
    /// Rejects nil evidence, pre-attempt/non-monotone time, or a resource UID
    /// different from the frozen physical Deployment UID.
    pub fn new(
        evidence_id: Uuid,
        attempt: TerminalAttemptBinding,
        issuer: WitnessIssuer,
        result: EffectObservationResult,
        observation_started_at: i64,
        observed_at: i64,
    ) -> Result<Self, WitnessError> {
        if evidence_id.is_nil()
            || observation_started_at < attempt.identity.attempt_started_at
            || observed_at < observation_started_at
            || result.resource_uid != attempt.identity.physical_resource.deployment_uid
        {
            return Err(WitnessError::InvalidRecord(
                "invalid exact-effect evidence identity, resource, or time",
            ));
        }
        Ok(Self {
            evidence_id,
            attempt,
            issuer,
            result,
            observation_started_at,
            observed_at,
        })
    }

    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        TERMINAL_WITNESS_SCHEMA_VERSION
    }

    #[must_use]
    pub const fn classification(&self) -> EffectClassification {
        EffectClassification::ExactEffectV1
    }

    #[must_use]
    pub const fn evidence_id(&self) -> Uuid {
        self.evidence_id
    }

    #[must_use]
    pub const fn attempt(&self) -> &TerminalAttemptBinding {
        &self.attempt
    }

    #[must_use]
    pub const fn issuer(&self) -> &WitnessIssuer {
        &self.issuer
    }

    #[must_use]
    pub const fn result(&self) -> &EffectObservationResult {
        &self.result
    }

    #[must_use]
    pub const fn observation_started_at(&self) -> i64 {
        self.observation_started_at
    }

    #[must_use]
    pub const fn observed_at(&self) -> i64 {
        self.observed_at
    }

    /// Returns the deterministic CBOR bytes authenticated by COSE.
    ///
    /// # Errors
    ///
    /// Returns a canonical-encoding error if the bounded record cannot be
    /// encoded.
    pub fn canonical_claims_bytes(&self) -> Result<Vec<u8>, WitnessError> {
        canonical_effect_claims(self)
    }
}

/// Exact credential identity frozen for the provider attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialIdentity {
    token_digest: Digest32,
    credential_id: String,
    service_account_uid: String,
    audience: String,
    subject: String,
    secret_name: String,
    secret_uid: String,
}

impl CredentialIdentity {
    /// Constructs a bearer-free exact credential binding.
    ///
    /// # Errors
    ///
    /// Rejects a zero token digest, noncanonical credential ID, malformed
    /// Secret name, or unbounded identity/audience/subject fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        token_digest: Digest32,
        credential_id: impl Into<String>,
        service_account_uid: impl Into<String>,
        audience: impl Into<String>,
        subject: impl Into<String>,
        secret_name: impl Into<String>,
        secret_uid: impl Into<String>,
    ) -> Result<Self, WitnessError> {
        let value = Self {
            token_digest,
            credential_id: credential_id.into(),
            service_account_uid: service_account_uid.into(),
            audience: audience.into(),
            subject: subject.into(),
            secret_name: secret_name.into(),
            secret_uid: secret_uid.into(),
        };
        if is_zero_digest(value.token_digest)
            || !valid_credential_id(&value.credential_id)
            || !valid_security_text(&value.service_account_uid, MAX_KUBERNETES_UID_BYTES)
            || !valid_security_text(&value.audience, MAX_AUDIENCE_BYTES)
            || !valid_security_text(&value.subject, MAX_SUBJECT_BYTES)
            || !valid_dns_subdomain(&value.secret_name)
            || !valid_security_text(&value.secret_uid, MAX_KUBERNETES_UID_BYTES)
        {
            return Err(WitnessError::InvalidRecord(
                "invalid exact credential identity",
            ));
        }
        Ok(value)
    }

    #[must_use]
    pub const fn token_digest(&self) -> Digest32 {
        self.token_digest
    }

    #[must_use]
    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }

    #[must_use]
    pub fn service_account_uid(&self) -> &str {
        &self.service_account_uid
    }

    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }

    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    #[must_use]
    pub fn secret_name(&self) -> &str {
        &self.secret_name
    }

    #[must_use]
    pub fn secret_uid(&self) -> &str {
        &self.secret_uid
    }
}

/// Computes the bearer-free payload commitment for the sole supported
/// `TokenReview` request profile.
///
/// The commitment covers the complete immutable attempt and credential. It is
/// deliberately not a hash of the Kubernetes JSON request because that wire
/// contains the raw bearer and therefore cannot be reconstructed by durable
/// state from the persisted token digest.
///
/// # Errors
///
/// Rejects an invalid attempt or credential, a token digest that does not
/// match the attempt, or a canonical-encoding failure.
pub fn token_review_request_commitment(
    attempt: &TerminalAttemptBinding,
    credential: &CredentialIdentity,
) -> Result<Digest32, WitnessError> {
    validate_attempt_credential_pair(attempt, credential)?;
    let encoded: Result<Vec<u8>, VecEncodeError> = (|| {
        let mut encoder = Encoder::new(Vec::new());
        encoder.array(4)?;
        encoder.u16(TERMINAL_WITNESS_SCHEMA_VERSION)?;
        // Fixed profile code: authentication.k8s.io/v1 TokenReview create.
        encoder.u8(1)?;
        encode_attempt(&mut encoder, attempt)?;
        encode_credential(&mut encoder, credential)?;
        Ok(encoder.into_writer())
    })();
    canonical_commitment(
        TOKEN_REVIEW_REQUEST_COMMITMENT_DOMAIN,
        &finish_encoding(encoded)?,
    )
}

/// Exact durable journal facts used to derive a signed Secret-deletion
/// observation without trusting a caller-supplied hash or time.
///
/// The journal entry, request, result, provider-evidence commitment, and
/// trusted completion time are all required. This type does not claim that a
/// deletion is authentic by itself; the resulting observation still has to be
/// covered by a credential-retirement witness from the activated registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretDeletionObservationV2 {
    journal_entry_id: Uuid,
    journal_request_commitment: Digest32,
    journal_result_commitment: Digest32,
    provider_evidence_commitment: Digest32,
    observed_at: i64,
}

impl SecretDeletionObservationV2 {
    /// Constructs the exact durable completion tuple for one DELETE journal.
    ///
    /// # Errors
    ///
    /// Rejects a nil journal entry, any zero commitment, or a nonpositive
    /// trusted observation time.
    pub fn new(
        journal_entry_id: Uuid,
        journal_request_commitment: Digest32,
        journal_result_commitment: Digest32,
        provider_evidence_commitment: Digest32,
        observed_at: i64,
    ) -> Result<Self, WitnessError> {
        if journal_entry_id.is_nil()
            || [
                journal_request_commitment,
                journal_result_commitment,
                provider_evidence_commitment,
            ]
            .into_iter()
            .any(is_zero_digest)
            || observed_at <= 0
        {
            return Err(WitnessError::InvalidRecord(
                "invalid durable Secret-deletion completion facts",
            ));
        }
        Ok(Self {
            journal_entry_id,
            journal_request_commitment,
            journal_result_commitment,
            provider_evidence_commitment,
            observed_at,
        })
    }

    #[must_use]
    pub const fn journal_entry_id(&self) -> Uuid {
        self.journal_entry_id
    }

    #[must_use]
    pub const fn journal_request_commitment(&self) -> Digest32 {
        self.journal_request_commitment
    }

    #[must_use]
    pub const fn journal_result_commitment(&self) -> Digest32 {
        self.journal_result_commitment
    }

    #[must_use]
    pub const fn provider_evidence_commitment(&self) -> Digest32 {
        self.provider_evidence_commitment
    }

    #[must_use]
    pub const fn observed_at(&self) -> i64 {
        self.observed_at
    }

    /// Derives the exact observation expected by credential-retirement
    /// verification.
    ///
    /// # Errors
    ///
    /// Rejects invalid or mismatched attempt/credential facts, a deletion
    /// predating the attempt, or a canonical-encoding failure.
    pub fn observation(
        &self,
        attempt: &TerminalAttemptBinding,
        credential: &CredentialIdentity,
    ) -> Result<SecretDeletionObservation, WitnessError> {
        validate_attempt_credential_pair(attempt, credential)?;
        if self.observed_at < attempt.identity.attempt_started_at {
            return Err(WitnessError::InvalidRecord(
                "Secret deletion predates the provider attempt",
            ));
        }
        let encoded: Result<Vec<u8>, VecEncodeError> = (|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(9)?;
            encoder.u16(TERMINAL_WITNESS_SCHEMA_VERSION)?;
            // Fixed profile code: journaled exact-UID Secret GET absence.
            encoder.u8(1)?;
            encode_attempt(&mut encoder, attempt)?;
            encode_credential(&mut encoder, credential)?;
            encode_uuid(&mut encoder, self.journal_entry_id)?;
            encoder.bytes(self.journal_request_commitment.as_bytes())?;
            encoder.bytes(self.journal_result_commitment.as_bytes())?;
            encoder.bytes(self.provider_evidence_commitment.as_bytes())?;
            encoder.i64(self.observed_at)?;
            Ok(encoder.into_writer())
        })();
        let commitment = canonical_commitment(
            SECRET_DELETION_OBSERVATION_COMMITMENT_DOMAIN,
            &finish_encoding(encoded)?,
        )?;
        SecretDeletionObservation::new(commitment, self.observed_at)
    }
}

/// Authenticated exact-Secret deletion observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretDeletionObservation {
    observation_commitment: Digest32,
    observed_at: i64,
}

impl SecretDeletionObservation {
    /// Builds one exact deletion observation.
    ///
    /// # Errors
    ///
    /// Rejects a zero commitment or nonpositive time.
    pub fn new(observation_commitment: Digest32, observed_at: i64) -> Result<Self, WitnessError> {
        if is_zero_digest(observation_commitment) || observed_at <= 0 {
            return Err(WitnessError::InvalidRecord(
                "invalid Secret deletion observation",
            ));
        }
        Ok(Self {
            observation_commitment,
            observed_at,
        })
    }

    #[must_use]
    pub const fn observation_commitment(&self) -> Digest32 {
        self.observation_commitment
    }

    #[must_use]
    pub const fn observed_at(&self) -> i64 {
        self.observed_at
    }
}

/// Exact immutable credential policy and its internally computed safe-after.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConservativeRetirementBound {
    policy_id: String,
    policy_version: u64,
    policy_commitment: Digest32,
    issuance_started_at: i64,
    server_token_lifetime_hard_max_s: i64,
    deletion_propagation_hard_max_s: i64,
    clock_uncertainty_s: i64,
    deletion_observed_at: i64,
    credential_safe_after: i64,
}

impl ConservativeRetirementBound {
    /// Computes the conservative invalidation boundary from the complete
    /// immutable policy snapshot. The safe-after value is never supplied by
    /// the caller.
    ///
    /// # Errors
    ///
    /// Rejects malformed policy metadata, out-of-profile hard maxima, invalid
    /// time ordering, or arithmetic overflow.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy_id: impl Into<String>,
        policy_version: u64,
        policy_commitment: Digest32,
        issuance_started_at: i64,
        server_token_lifetime_hard_max_s: i64,
        deletion_propagation_hard_max_s: i64,
        clock_uncertainty_s: i64,
        deletion_observed_at: i64,
    ) -> Result<Self, WitnessError> {
        let policy_id = policy_id.into();
        if !valid_security_text(&policy_id, MAX_POLICY_ID_BYTES)
            || policy_version == 0
            || is_zero_digest(policy_commitment)
            || issuance_started_at <= 0
            || deletion_observed_at <= 0
            || !(1..=MAX_SERVER_TOKEN_LIFETIME_HARD_S).contains(&server_token_lifetime_hard_max_s)
            || !(1..=MAX_DELETION_PROPAGATION_HARD_S).contains(&deletion_propagation_hard_max_s)
            || !(0..=MAX_CLOCK_UNCERTAINTY_S).contains(&clock_uncertainty_s)
        {
            return Err(WitnessError::InvalidRecord(
                "invalid conservative credential policy",
            ));
        }
        let issuance_bound = issuance_started_at
            .checked_add(server_token_lifetime_hard_max_s)
            .and_then(|value| value.checked_add(clock_uncertainty_s))
            .ok_or(WitnessError::InvalidRecord(
                "conservative issuance bound overflow",
            ))?;
        let deletion_bound = deletion_observed_at
            .checked_add(deletion_propagation_hard_max_s)
            .and_then(|value| value.checked_add(clock_uncertainty_s))
            .ok_or(WitnessError::InvalidRecord(
                "conservative deletion bound overflow",
            ))?;
        Ok(Self {
            policy_id,
            policy_version,
            policy_commitment,
            issuance_started_at,
            server_token_lifetime_hard_max_s,
            deletion_propagation_hard_max_s,
            clock_uncertainty_s,
            deletion_observed_at,
            credential_safe_after: issuance_bound.max(deletion_bound),
        })
    }

    #[must_use]
    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    #[must_use]
    pub const fn policy_version(&self) -> u64 {
        self.policy_version
    }

    #[must_use]
    pub const fn policy_commitment(&self) -> Digest32 {
        self.policy_commitment
    }

    #[must_use]
    pub const fn issuance_started_at(&self) -> i64 {
        self.issuance_started_at
    }

    #[must_use]
    pub const fn server_token_lifetime_hard_max_s(&self) -> i64 {
        self.server_token_lifetime_hard_max_s
    }

    #[must_use]
    pub const fn deletion_propagation_hard_max_s(&self) -> i64 {
        self.deletion_propagation_hard_max_s
    }

    #[must_use]
    pub const fn clock_uncertainty_s(&self) -> i64 {
        self.clock_uncertainty_s
    }

    #[must_use]
    pub const fn deletion_observed_at(&self) -> i64 {
        self.deletion_observed_at
    }

    #[must_use]
    pub const fn credential_safe_after(&self) -> i64 {
        self.credential_safe_after
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RetirementBasisKind {
    TokenReviewRejected {
        request_commitment: Digest32,
        response_commitment: Digest32,
        rejected_at: i64,
    },
    ConservativeSafeAfter(ConservativeRetirementBound),
}

/// Mutually exclusive exact credential-retirement basis.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetirementBasis {
    kind: RetirementBasisKind,
}

impl RetirementBasis {
    /// Builds exact post-deletion `TokenReview` rejection evidence.
    ///
    /// # Errors
    ///
    /// The bearer-free request commitment is derived from the exact attempt
    /// and credential; callers cannot supply it.
    ///
    /// Rejects invalid or mismatched attempt/credential facts, a zero response
    /// commitment, or a nonpositive rejection time.
    pub fn token_review_rejected(
        attempt: &TerminalAttemptBinding,
        credential: &CredentialIdentity,
        response_commitment: Digest32,
        rejected_at: i64,
    ) -> Result<Self, WitnessError> {
        if is_zero_digest(response_commitment) || rejected_at <= 0 {
            return Err(WitnessError::InvalidRecord(
                "invalid TokenReview rejection evidence",
            ));
        }
        let request_commitment = token_review_request_commitment(attempt, credential)?;
        Ok(Self {
            kind: RetirementBasisKind::TokenReviewRejected {
                request_commitment,
                response_commitment,
                rejected_at,
            },
        })
    }

    #[must_use]
    pub const fn conservative(bound: ConservativeRetirementBound) -> Self {
        Self {
            kind: RetirementBasisKind::ConservativeSafeAfter(bound),
        }
    }

    #[must_use]
    pub const fn is_token_review_rejected(&self) -> bool {
        matches!(self.kind, RetirementBasisKind::TokenReviewRejected { .. })
    }

    #[must_use]
    pub const fn conservative_bound(&self) -> Option<&ConservativeRetirementBound> {
        match &self.kind {
            RetirementBasisKind::TokenReviewRejected { .. } => None,
            RetirementBasisKind::ConservativeSafeAfter(bound) => Some(bound),
        }
    }

    #[must_use]
    pub const fn token_review_request_commitment(&self) -> Option<Digest32> {
        match self.kind {
            RetirementBasisKind::TokenReviewRejected {
                request_commitment, ..
            } => Some(request_commitment),
            RetirementBasisKind::ConservativeSafeAfter(_) => None,
        }
    }

    #[must_use]
    pub const fn token_review_response_commitment(&self) -> Option<Digest32> {
        match self.kind {
            RetirementBasisKind::TokenReviewRejected {
                response_commitment,
                ..
            } => Some(response_commitment),
            RetirementBasisKind::ConservativeSafeAfter(_) => None,
        }
    }

    #[must_use]
    pub const fn token_review_rejected_at(&self) -> Option<i64> {
        match self.kind {
            RetirementBasisKind::TokenReviewRejected { rejected_at, .. } => Some(rejected_at),
            RetirementBasisKind::ConservativeSafeAfter(_) => None,
        }
    }
}

/// Exact durable expectations required to accept either retirement path.
///
/// `TokenReview` rejection may be accepted without a conservative policy. A
/// conservative witness is accepted only when its complete bound equals the
/// expected state-derived bound supplied here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetirementExpectation {
    credential: CredentialIdentity,
    deletion: SecretDeletionObservation,
    token_review_request_commitment: Option<Digest32>,
    conservative_bound: Option<ConservativeRetirementBound>,
}

impl RetirementExpectation {
    /// Builds the exact retirement facts derived from durable state.
    ///
    /// # Errors
    ///
    /// `accept_token_review_rejection` selects the fixed payload-v1 request;
    /// no caller-supplied request commitment is accepted.
    ///
    /// Rejects invalid or mismatched attempt/credential facts or a conservative
    /// policy bound referring to another deletion observation.
    pub fn new(
        attempt: &TerminalAttemptBinding,
        credential: CredentialIdentity,
        deletion: SecretDeletionObservation,
        accept_token_review_rejection: bool,
        conservative_bound: Option<ConservativeRetirementBound>,
    ) -> Result<Self, WitnessError> {
        validate_attempt_credential_pair(attempt, &credential)?;
        if conservative_bound
            .as_ref()
            .is_some_and(|bound| bound.deletion_observed_at != deletion.observed_at)
        {
            return Err(WitnessError::InvalidRecord(
                "invalid durable retirement expectation",
            ));
        }
        let token_review_request_commitment = accept_token_review_rejection
            .then(|| token_review_request_commitment(attempt, &credential))
            .transpose()?;
        Ok(Self {
            credential,
            deletion,
            token_review_request_commitment,
            conservative_bound,
        })
    }

    #[must_use]
    pub const fn credential(&self) -> &CredentialIdentity {
        &self.credential
    }

    #[must_use]
    pub const fn deletion(&self) -> &SecretDeletionObservation {
        &self.deletion
    }

    #[must_use]
    pub const fn token_review_request_commitment(&self) -> Option<Digest32> {
        self.token_review_request_commitment
    }

    #[must_use]
    pub const fn conservative_bound(&self) -> Option<&ConservativeRetirementBound> {
        self.conservative_bound.as_ref()
    }
}

/// Canonical claims covered by a credential-retirement signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialRetirementClaims {
    evidence_id: Uuid,
    attempt: TerminalAttemptBinding,
    issuer: WitnessIssuer,
    credential: CredentialIdentity,
    deletion: SecretDeletionObservation,
    basis: RetirementBasis,
    observation_started_at: i64,
    observed_at: i64,
}

impl CredentialRetirementClaims {
    /// Constructs one exact credential-retirement assertion.
    ///
    /// # Errors
    ///
    /// Rejects nil evidence, wrong token binding, pre-attempt deletion,
    /// rejection before deletion, a mismatched conservative deletion time, or
    /// evidence observed before its internally computed safe-after bound.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        evidence_id: Uuid,
        attempt: TerminalAttemptBinding,
        issuer: WitnessIssuer,
        credential: CredentialIdentity,
        deletion: SecretDeletionObservation,
        basis: RetirementBasis,
        observation_started_at: i64,
        observed_at: i64,
    ) -> Result<Self, WitnessError> {
        if evidence_id.is_nil()
            || credential.token_digest != attempt.effect.token_digest
            || deletion.observed_at < attempt.identity.attempt_started_at
            || observation_started_at < deletion.observed_at
            || observed_at < observation_started_at
        {
            return Err(WitnessError::InvalidRecord(
                "invalid credential-retirement identity, binding, or ordering",
            ));
        }
        match &basis.kind {
            RetirementBasisKind::TokenReviewRejected { rejected_at, .. }
                if *rejected_at < deletion.observed_at || *rejected_at > observed_at =>
            {
                return Err(WitnessError::InvalidRecord(
                    "TokenReview rejection does not follow exact deletion",
                ));
            }
            RetirementBasisKind::ConservativeSafeAfter(bound)
                if bound.deletion_observed_at != deletion.observed_at
                    || bound.issuance_started_at > attempt.identity.attempt_started_at
                    || observed_at < bound.credential_safe_after =>
            {
                return Err(WitnessError::InvalidRecord(
                    "conservative retirement bound is not satisfied",
                ));
            }
            _ => {}
        }
        Ok(Self {
            evidence_id,
            attempt,
            issuer,
            credential,
            deletion,
            basis,
            observation_started_at,
            observed_at,
        })
    }

    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        TERMINAL_WITNESS_SCHEMA_VERSION
    }

    #[must_use]
    pub const fn evidence_id(&self) -> Uuid {
        self.evidence_id
    }

    #[must_use]
    pub const fn attempt(&self) -> &TerminalAttemptBinding {
        &self.attempt
    }

    #[must_use]
    pub const fn issuer(&self) -> &WitnessIssuer {
        &self.issuer
    }

    #[must_use]
    pub const fn credential(&self) -> &CredentialIdentity {
        &self.credential
    }

    #[must_use]
    pub const fn deletion(&self) -> &SecretDeletionObservation {
        &self.deletion
    }

    #[must_use]
    pub const fn basis(&self) -> &RetirementBasis {
        &self.basis
    }

    #[must_use]
    pub const fn observation_started_at(&self) -> i64 {
        self.observation_started_at
    }

    #[must_use]
    pub const fn observed_at(&self) -> i64 {
        self.observed_at
    }

    /// Returns the deterministic CBOR bytes authenticated by COSE.
    ///
    /// # Errors
    ///
    /// Returns a canonical-encoding error if the bounded record cannot be
    /// encoded.
    pub fn canonical_claims_bytes(&self) -> Result<Vec<u8>, WitnessError> {
        canonical_retirement_claims(self)
    }
}

/// Signed exact-effect artifact. It is evidence input, not authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedEffectWitness {
    key_id: String,
    claims: EffectObservationClaims,
    cose_sign1: Vec<u8>,
}

impl SignedEffectWitness {
    /// Reconstitutes an unverified transport artifact.
    ///
    /// This constructor performs only structural bounds checks. Call
    /// [`ActivatedWitnessRegistry::verify_effect`] before using the value as
    /// evidence.
    ///
    /// # Errors
    ///
    /// Rejects malformed key identifiers and oversized COSE objects.
    pub fn from_untrusted_parts(
        key_id: impl Into<String>,
        claims: EffectObservationClaims,
        cose_sign1: Vec<u8>,
    ) -> Result<Self, WitnessError> {
        let key_id = key_id.into();
        validate_effect_claims(&claims)?;
        let claims_bytes = canonical_effect_claims(&claims)?;
        if key_id != claims.issuer.key_id
            || !valid_security_text(&key_id, MAX_KEY_ID_BYTES)
            || cose_sign1.is_empty()
            || cose_sign1.len() > MAX_COSE_SIZE_BYTES
            || canonical_signed_envelope(
                WitnessRole::ExactEffect,
                &key_id,
                &claims_bytes,
                &cose_sign1,
            )?
            .len()
                > MAX_TERMINAL_WITNESS_ENVELOPE_BYTES
        {
            return Err(WitnessError::InvalidRecord(
                "invalid signed effect-witness envelope",
            ));
        }
        Ok(Self {
            key_id,
            claims,
            cose_sign1,
        })
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub const fn claims(&self) -> &EffectObservationClaims {
        &self.claims
    }

    #[must_use]
    pub fn cose_sign1(&self) -> &[u8] {
        &self.cose_sign1
    }

    /// Returns the exact deterministic persistence envelope containing key
    /// ID, canonical claims bytes, and the original COSE bytes.
    ///
    /// # Errors
    ///
    /// Returns a canonical-encoding error if the bounded envelope cannot be
    /// encoded.
    pub fn exact_envelope_bytes(&self) -> Result<Vec<u8>, WitnessError> {
        canonical_signed_envelope(
            WitnessRole::ExactEffect,
            &self.key_id,
            &canonical_effect_claims(&self.claims)?,
            &self.cose_sign1,
        )
    }

    /// Strictly decodes a persisted deterministic envelope.
    ///
    /// The decoder rejects wrong role/schema/arity, indefinite or
    /// non-minimal CBOR, trailing bytes, oversized components, and any claims
    /// that do not round-trip to the exact embedded bytes. Signature trust is
    /// still established only by [`ActivatedWitnessRegistry::verify_effect`].
    ///
    /// # Errors
    ///
    /// Returns a fail-closed wire, claims, bounds, or canonical error.
    pub fn from_canonical_envelope_bytes(bytes: &[u8]) -> Result<Self, WitnessError> {
        decode_effect_envelope(bytes)
    }
}

/// Signed credential-retirement artifact. It contains no bearer token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCredentialRetirementWitness {
    key_id: String,
    claims: CredentialRetirementClaims,
    cose_sign1: Vec<u8>,
}

impl SignedCredentialRetirementWitness {
    /// Reconstitutes an unverified transport artifact.
    ///
    /// This constructor performs only structural bounds checks. Call
    /// [`ActivatedWitnessRegistry::verify_retirement`] before using the value
    /// as evidence.
    ///
    /// # Errors
    ///
    /// Rejects malformed key identifiers and oversized COSE objects.
    pub fn from_untrusted_parts(
        key_id: impl Into<String>,
        claims: CredentialRetirementClaims,
        cose_sign1: Vec<u8>,
    ) -> Result<Self, WitnessError> {
        let key_id = key_id.into();
        validate_retirement_claims(&claims)?;
        let claims_bytes = canonical_retirement_claims(&claims)?;
        if key_id != claims.issuer.key_id
            || !valid_security_text(&key_id, MAX_KEY_ID_BYTES)
            || cose_sign1.is_empty()
            || cose_sign1.len() > MAX_COSE_SIZE_BYTES
            || canonical_signed_envelope(
                WitnessRole::CredentialRetirement,
                &key_id,
                &claims_bytes,
                &cose_sign1,
            )?
            .len()
                > MAX_TERMINAL_WITNESS_ENVELOPE_BYTES
        {
            return Err(WitnessError::InvalidRecord(
                "invalid signed retirement-witness envelope",
            ));
        }
        Ok(Self {
            key_id,
            claims,
            cose_sign1,
        })
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub const fn claims(&self) -> &CredentialRetirementClaims {
        &self.claims
    }

    #[must_use]
    pub fn cose_sign1(&self) -> &[u8] {
        &self.cose_sign1
    }

    /// Returns the exact deterministic persistence envelope containing key
    /// ID, canonical claims bytes, and the original COSE bytes.
    ///
    /// # Errors
    ///
    /// Returns a canonical-encoding error if the bounded envelope cannot be
    /// encoded.
    pub fn exact_envelope_bytes(&self) -> Result<Vec<u8>, WitnessError> {
        canonical_signed_envelope(
            WitnessRole::CredentialRetirement,
            &self.key_id,
            &canonical_retirement_claims(&self.claims)?,
            &self.cose_sign1,
        )
    }

    /// Strictly decodes a persisted deterministic envelope.
    ///
    /// The decoder rejects wrong role/schema/arity, indefinite or
    /// non-minimal CBOR, trailing bytes, oversized components, and any claims
    /// that do not round-trip to the exact embedded bytes. Signature trust is
    /// still established only by
    /// [`ActivatedWitnessRegistry::verify_retirement`].
    ///
    /// # Errors
    ///
    /// Returns a fail-closed wire, claims, bounds, or canonical error.
    pub fn from_canonical_envelope_bytes(bytes: &[u8]) -> Result<Self, WitnessError> {
        decode_retirement_envelope(bytes)
    }
}

/// Cryptographic purpose assigned to exactly one verifier identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WitnessRole {
    ExactEffect,
    CredentialRetirement,
}

impl WitnessRole {
    const fn code(self) -> u8 {
        match self {
            Self::ExactEffect => 1,
            Self::CredentialRetirement => 2,
        }
    }
}

/// Lifecycle state committed into a verifier registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessVerifierStatus {
    Active,
    Retired,
    Revoked,
}

impl WitnessVerifierStatus {
    const fn code(self) -> u8 {
        match self {
            Self::Active => 1,
            Self::Retired => 2,
            Self::Revoked => 3,
        }
    }
}

/// One immutable, purpose-scoped terminal-witness verifier registration.
///
/// Every field is private so registry material can only enter through the
/// bounded constructor and deterministic activation path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredWitnessVerifier {
    scope: WitnessScope,
    cluster_identity: String,
    role: WitnessRole,
    observer_identity: String,
    key_id: String,
    public_key: [u8; 32],
    not_before: i64,
    valid_until: i64,
    accepted_through: i64,
    authority_version: u64,
    authorizing_root: Digest32,
    status: WitnessVerifierStatus,
}

impl RegisteredWitnessVerifier {
    /// Builds one exact verifier registration.
    ///
    /// `valid_until` is exclusive and `accepted_through` is inclusive. The
    /// latter is an immutable cutoff used for both active and retired keys.
    ///
    /// # Errors
    ///
    /// Rejects malformed identity, weak Ed25519 keys, zero authority data, or
    /// invalid temporal bounds.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: WitnessScope,
        cluster_identity: impl Into<String>,
        role: WitnessRole,
        observer_identity: impl Into<String>,
        key_id: impl Into<String>,
        public_key: [u8; 32],
        not_before: i64,
        valid_until: i64,
        accepted_through: i64,
        authority_version: u64,
        authorizing_root: Digest32,
        status: WitnessVerifierStatus,
    ) -> Result<Self, WitnessError> {
        let cluster_identity = cluster_identity.into();
        let observer_identity = observer_identity.into();
        let key_id = key_id.into();
        if !valid_security_text(&cluster_identity, MAX_CLUSTER_IDENTITY_BYTES)
            || !valid_security_text(&observer_identity, MAX_OBSERVER_IDENTITY_BYTES)
            || !valid_security_text(&key_id, MAX_KEY_ID_BYTES)
            || not_before <= 0
            || valid_until <= not_before
            || accepted_through < not_before
            || accepted_through >= valid_until
            || authority_version == 0
            || is_zero_digest(authorizing_root)
        {
            return Err(WitnessError::InvalidRecord(
                "invalid terminal-witness verifier registration",
            ));
        }
        CoseVerifier::from_public_key(key_id.clone(), public_key)?;
        Ok(Self {
            scope,
            cluster_identity,
            role,
            observer_identity,
            key_id,
            public_key,
            not_before,
            valid_until,
            accepted_through,
            authority_version,
            authorizing_root,
            status,
        })
    }

    #[must_use]
    pub const fn scope(&self) -> &WitnessScope {
        &self.scope
    }

    #[must_use]
    pub fn cluster_identity(&self) -> &str {
        &self.cluster_identity
    }

    #[must_use]
    pub const fn role(&self) -> WitnessRole {
        self.role
    }

    #[must_use]
    pub fn observer_identity(&self) -> &str {
        &self.observer_identity
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub const fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    #[must_use]
    pub const fn not_before(&self) -> i64 {
        self.not_before
    }

    #[must_use]
    pub const fn valid_until(&self) -> i64 {
        self.valid_until
    }

    #[must_use]
    pub const fn accepted_through(&self) -> i64 {
        self.accepted_through
    }

    #[must_use]
    pub const fn authority_version(&self) -> u64 {
        self.authority_version
    }

    #[must_use]
    pub const fn authorizing_root(&self) -> Digest32 {
        self.authorizing_root
    }

    #[must_use]
    pub const fn status(&self) -> WitnessVerifierStatus {
        self.status
    }

    fn sort_key(&self) -> (WitnessRole, &str, &str) {
        (self.role, &self.observer_identity, &self.key_id)
    }
}

/// Full activation coordinates for one canonical verifier material root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessRegistryAuthority {
    material_root: Digest32,
    epoch: u64,
    activation_id: Uuid,
}

impl WitnessRegistryAuthority {
    /// Creates an exact activation reference.
    ///
    /// # Errors
    ///
    /// Rejects a zero root, zero epoch, or nil activation identifier.
    pub fn new(
        material_root: Digest32,
        epoch: u64,
        activation_id: Uuid,
    ) -> Result<Self, WitnessError> {
        if is_zero_digest(material_root) || epoch == 0 || activation_id.is_nil() {
            return Err(WitnessError::InvalidRecord(
                "invalid witness-registry activation authority",
            ));
        }
        Ok(Self {
            material_root,
            epoch,
            activation_id,
        })
    }

    #[must_use]
    pub const fn material_root(&self) -> Digest32 {
        self.material_root
    }

    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub const fn activation_id(&self) -> Uuid {
        self.activation_id
    }
}

/// Activated, deterministic, bounded registry used for witness verification.
///
/// [`Self::commitment`] is the full state-binding commitment. It covers the
/// canonical verifier material, registry epoch, and activation identifier.
#[derive(Clone)]
pub struct ActivatedWitnessRegistry {
    authority: WitnessRegistryAuthority,
    entries: Vec<RegisteredWitnessVerifier>,
    by_key_id: BTreeMap<String, usize>,
    commitment: Digest32,
}

impl fmt::Debug for ActivatedWitnessRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActivatedWitnessRegistry")
            .field("authority", &self.authority)
            .field("entry_count", &self.entries.len())
            .field("commitment", &self.commitment)
            .finish_non_exhaustive()
    }
}

impl ActivatedWitnessRegistry {
    /// Activates exact canonical verifier material under an epoch and unique
    /// activation identifier.
    ///
    /// # Errors
    ///
    /// Rejects empty/oversized/noncanonical registries, identity or key
    /// aliases, missing purpose roles, and a material-root mismatch.
    pub fn new(
        authority: WitnessRegistryAuthority,
        entries: Vec<RegisteredWitnessVerifier>,
    ) -> Result<Self, WitnessError> {
        let material_root = Self::compute_material_root(&entries)?;
        if material_root != authority.material_root {
            return Err(WitnessError::RegistryCommitmentMismatch);
        }
        let commitment = activation_commitment(&authority)?;
        let by_key_id = entries
            .iter()
            .enumerate()
            .map(|(index, entry)| (entry.key_id.clone(), index))
            .collect();
        Ok(Self {
            authority,
            entries,
            by_key_id,
            commitment,
        })
    }

    /// Computes the deterministic material root after validating all registry
    /// invariants. This is not the state-binding activation commitment.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed registry or canonical-encoding error.
    pub fn compute_material_root(
        entries: &[RegisteredWitnessVerifier],
    ) -> Result<Digest32, WitnessError> {
        validate_registry_entries(entries)?;
        let canonical = canonical_registry_entries(entries)?;
        let mut input =
            Vec::with_capacity(WITNESS_REGISTRY_MATERIAL_DOMAIN.len() + canonical.len());
        input.extend_from_slice(WITNESS_REGISTRY_MATERIAL_DOMAIN);
        input.extend_from_slice(&canonical);
        Ok(Digest32::sha256(&input))
    }

    #[must_use]
    pub const fn authority(&self) -> &WitnessRegistryAuthority {
        &self.authority
    }

    /// Canonical verifier-entry root, excluding activation coordinates.
    #[must_use]
    pub const fn material_root(&self) -> Digest32 {
        self.authority.material_root
    }

    /// Full commitment over material root, epoch, and activation ID.
    #[must_use]
    pub const fn commitment(&self) -> Digest32 {
        self.commitment
    }

    #[must_use]
    pub fn entries(&self) -> &[RegisteredWitnessVerifier] {
        &self.entries
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Verifies an exact Deployment-update witness against one immutable
    /// durable attempt and a trusted clock.
    ///
    /// # Errors
    ///
    /// Fails closed for every signature, registry, binding, or time mismatch.
    pub fn verify_effect(
        &self,
        signed: &SignedEffectWitness,
        expected_attempt: &TerminalAttemptBinding,
        trusted_now: i64,
    ) -> Result<VerifiedEffectWitness, WitnessError> {
        validate_trusted_now(trusted_now, signed.claims.observed_at)?;
        validate_effect_claims(&signed.claims)?;
        let entry = self.verifier_for(
            &signed.key_id,
            signed.claims.issuer(),
            signed.claims.attempt(),
            signed.claims.observed_at,
            WitnessRole::ExactEffect,
        )?;
        let verifier = CoseVerifier::from_public_key(entry.key_id.clone(), entry.public_key)?;
        let embedded = verify_cose(&signed.cose_sign1, EXACT_EFFECT_WITNESS_DOMAIN, &verifier)?;
        if embedded != canonical_effect_claims(&signed.claims)? {
            return Err(WitnessError::PayloadMismatch);
        }
        if signed.claims.attempt != *expected_attempt {
            return Err(WitnessError::AttemptBindingMismatch);
        }
        Ok(VerifiedEffectWitness {
            signed: signed.clone(),
            registry_authority: self.authority.clone(),
            registry_commitment: self.commitment,
        })
    }

    /// Verifies exact credential retirement against durable attempt,
    /// credential, and (when selected) conservative policy state.
    ///
    /// # Errors
    ///
    /// Fails closed for every signature, registry, binding, policy, or time
    /// mismatch.
    pub fn verify_retirement(
        &self,
        signed: &SignedCredentialRetirementWitness,
        expected_attempt: &TerminalAttemptBinding,
        expectation: &RetirementExpectation,
        trusted_now: i64,
    ) -> Result<VerifiedCredentialRetirementWitness, WitnessError> {
        validate_trusted_now(trusted_now, signed.claims.observed_at)?;
        validate_retirement_claims(&signed.claims)?;
        let entry = self.verifier_for(
            &signed.key_id,
            signed.claims.issuer(),
            signed.claims.attempt(),
            signed.claims.observed_at,
            WitnessRole::CredentialRetirement,
        )?;
        let verifier = CoseVerifier::from_public_key(entry.key_id.clone(), entry.public_key)?;
        let embedded = verify_cose(
            &signed.cose_sign1,
            CREDENTIAL_RETIREMENT_WITNESS_DOMAIN,
            &verifier,
        )?;
        if embedded != canonical_retirement_claims(&signed.claims)? {
            return Err(WitnessError::PayloadMismatch);
        }
        if signed.claims.attempt != *expected_attempt {
            return Err(WitnessError::AttemptBindingMismatch);
        }
        if signed.claims.credential != expectation.credential {
            return Err(WitnessError::CredentialBindingMismatch);
        }
        if signed.claims.deletion != expectation.deletion {
            return Err(WitnessError::DeletionBindingMismatch);
        }
        match &signed.claims.basis.kind {
            RetirementBasisKind::TokenReviewRejected {
                request_commitment, ..
            } if expectation.token_review_request_commitment != Some(*request_commitment) => {
                return Err(WitnessError::TokenReviewBindingMismatch);
            }
            RetirementBasisKind::ConservativeSafeAfter(bound)
                if expectation.conservative_bound.as_ref() != Some(bound) =>
            {
                return Err(WitnessError::ConservativePolicyMismatch);
            }
            _ => {}
        }
        Ok(VerifiedCredentialRetirementWitness {
            signed: signed.clone(),
            registry_authority: self.authority.clone(),
            registry_commitment: self.commitment,
        })
    }

    fn verifier_for(
        &self,
        envelope_key_id: &str,
        issuer: &WitnessIssuer,
        attempt: &TerminalAttemptBinding,
        observed_at: i64,
        expected_role: WitnessRole,
    ) -> Result<&RegisteredWitnessVerifier, WitnessError> {
        if envelope_key_id != issuer.key_id {
            return Err(WitnessError::VerifierBindingMismatch);
        }
        let entry = self
            .by_key_id
            .get(envelope_key_id)
            .map(|index| &self.entries[*index])
            .ok_or(WitnessError::UnknownVerifier)?;
        if entry.role != expected_role {
            return Err(WitnessError::VerifierRoleMismatch);
        }
        if entry.observer_identity != issuer.observer_identity
            || entry.authority_version != issuer.authority_version
            || entry.scope != attempt.identity.scope
            || entry.cluster_identity != attempt.identity.physical_resource.cluster_identity
        {
            return Err(WitnessError::VerifierBindingMismatch);
        }
        if entry.status == WitnessVerifierStatus::Revoked
            || observed_at < entry.not_before
            || observed_at >= entry.valid_until
            || observed_at > entry.accepted_through
        {
            return Err(WitnessError::VerifierInactive);
        }
        Ok(entry)
    }
}

/// Opaque successfully verified exact-effect witness.
///
/// This type has no public constructor. Possession proves only that the
/// configured registry accepted the signature and bindings; it does not make
/// the observer a source of truth or release durable state.
///
/// ```compile_fail
/// use accordlock_terminal_witness::VerifiedEffectWitness;
/// let _ = VerifiedEffectWitness {};
/// ```
#[derive(Debug)]
pub struct VerifiedEffectWitness {
    signed: SignedEffectWitness,
    registry_authority: WitnessRegistryAuthority,
    registry_commitment: Digest32,
}

impl VerifiedEffectWitness {
    #[must_use]
    pub const fn signed(&self) -> &SignedEffectWitness {
        &self.signed
    }

    #[must_use]
    pub const fn claims(&self) -> &EffectObservationClaims {
        &self.signed.claims
    }

    #[must_use]
    pub const fn registry_authority(&self) -> &WitnessRegistryAuthority {
        &self.registry_authority
    }

    #[must_use]
    pub const fn registry_commitment(&self) -> Digest32 {
        self.registry_commitment
    }
}

/// Opaque successfully verified exact credential-retirement witness.
///
/// This type has no public constructor and performs no state release.
///
/// ```compile_fail
/// use accordlock_terminal_witness::VerifiedCredentialRetirementWitness;
/// let _ = VerifiedCredentialRetirementWitness {};
/// ```
#[derive(Debug)]
pub struct VerifiedCredentialRetirementWitness {
    signed: SignedCredentialRetirementWitness,
    registry_authority: WitnessRegistryAuthority,
    registry_commitment: Digest32,
}

impl VerifiedCredentialRetirementWitness {
    #[must_use]
    pub const fn signed(&self) -> &SignedCredentialRetirementWitness {
        &self.signed
    }

    #[must_use]
    pub const fn claims(&self) -> &CredentialRetirementClaims {
        &self.signed.claims
    }

    #[must_use]
    pub const fn registry_authority(&self) -> &WitnessRegistryAuthority {
        &self.registry_authority
    }

    #[must_use]
    pub const fn registry_commitment(&self) -> Digest32 {
        self.registry_commitment
    }
}

/// Signs canonical exact-effect claims with the purpose-specific COSE domain.
///
/// # Errors
///
/// Rejects a signer whose key ID differs from the signed issuer, invalid
/// claims, or a COSE signing failure.
pub fn sign_effect_observation(
    claims: EffectObservationClaims,
    signer: &SigningIdentity,
) -> Result<SignedEffectWitness, WitnessError> {
    validate_effect_claims(&claims)?;
    if signer.key_id() != claims.issuer.key_id {
        return Err(WitnessError::VerifierBindingMismatch);
    }
    let canonical = canonical_effect_claims(&claims)?;
    let cose_sign1 = sign_cose(&canonical, EXACT_EFFECT_WITNESS_DOMAIN, signer)?;
    SignedEffectWitness::from_untrusted_parts(signer.key_id(), claims, cose_sign1)
}

/// Signs canonical exact credential-retirement claims with a distinct COSE
/// domain and signer role.
///
/// # Errors
///
/// Rejects a signer whose key ID differs from the signed issuer, invalid
/// claims, or a COSE signing failure.
pub fn sign_credential_retirement(
    claims: CredentialRetirementClaims,
    signer: &SigningIdentity,
) -> Result<SignedCredentialRetirementWitness, WitnessError> {
    validate_retirement_claims(&claims)?;
    if signer.key_id() != claims.issuer.key_id {
        return Err(WitnessError::VerifierBindingMismatch);
    }
    let canonical = canonical_retirement_claims(&claims)?;
    let cose_sign1 = sign_cose(&canonical, CREDENTIAL_RETIREMENT_WITNESS_DOMAIN, signer)?;
    SignedCredentialRetirementWitness::from_untrusted_parts(signer.key_id(), claims, cose_sign1)
}

type VecEncoder = Encoder<Vec<u8>>;
type VecEncodeError = EncodeError<Infallible>;

fn finish_encoding(result: Result<Vec<u8>, VecEncodeError>) -> Result<Vec<u8>, WitnessError> {
    result.map_err(|error| WitnessError::Canonical(error.to_string()))
}

fn canonical_commitment(domain: &[u8], canonical: &[u8]) -> Result<Digest32, WitnessError> {
    if canonical.len() > MAX_TERMINAL_WITNESS_CLAIMS_BYTES {
        return Err(WitnessError::InvalidRecord(
            "terminal-witness commitment material is oversized",
        ));
    }
    let mut input = Vec::with_capacity(domain.len() + canonical.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(canonical);
    Ok(Digest32::sha256(&input))
}

fn canonical_attempt_binding(value: &TerminalAttemptBinding) -> Result<Vec<u8>, WitnessError> {
    let encoded: Result<Vec<u8>, VecEncodeError> = (|| {
        let mut encoder = Encoder::new(Vec::new());
        encoder.array(2)?;
        encoder.u16(TERMINAL_WITNESS_SCHEMA_VERSION)?;
        encode_attempt(&mut encoder, value)?;
        Ok(encoder.into_writer())
    })();
    finish_encoding(encoded)
}

fn canonical_effect_claims(value: &EffectObservationClaims) -> Result<Vec<u8>, WitnessError> {
    let encoded: Result<Vec<u8>, VecEncodeError> = (|| {
        let mut encoder = Encoder::new(Vec::new());
        encoder.array(8)?;
        encoder.u16(TERMINAL_WITNESS_SCHEMA_VERSION)?;
        encoder.u8(value.classification().code())?;
        encode_uuid(&mut encoder, value.evidence_id)?;
        encode_attempt(&mut encoder, &value.attempt)?;
        encode_issuer(&mut encoder, &value.issuer)?;
        encode_effect_result(&mut encoder, &value.result)?;
        encoder.i64(value.observation_started_at)?;
        encoder.i64(value.observed_at)?;
        Ok(encoder.into_writer())
    })();
    bounded_claims(finish_encoding(encoded)?)
}

fn canonical_retirement_claims(
    value: &CredentialRetirementClaims,
) -> Result<Vec<u8>, WitnessError> {
    let encoded: Result<Vec<u8>, VecEncodeError> = (|| {
        let mut encoder = Encoder::new(Vec::new());
        encoder.array(9)?;
        encoder.u16(TERMINAL_WITNESS_SCHEMA_VERSION)?;
        encode_uuid(&mut encoder, value.evidence_id)?;
        encode_attempt(&mut encoder, &value.attempt)?;
        encode_issuer(&mut encoder, &value.issuer)?;
        encode_credential(&mut encoder, &value.credential)?;
        encode_deletion(&mut encoder, &value.deletion)?;
        encode_retirement_basis(&mut encoder, &value.basis)?;
        encoder.i64(value.observation_started_at)?;
        encoder.i64(value.observed_at)?;
        Ok(encoder.into_writer())
    })();
    bounded_claims(finish_encoding(encoded)?)
}

fn canonical_signed_envelope(
    role: WitnessRole,
    key_id: &str,
    canonical_claims: &[u8],
    cose_sign1: &[u8],
) -> Result<Vec<u8>, WitnessError> {
    let encoded: Result<Vec<u8>, VecEncodeError> = (|| {
        let mut encoder = Encoder::new(Vec::new());
        encoder.array(5)?;
        encoder.u16(TERMINAL_WITNESS_SCHEMA_VERSION)?;
        encoder.u8(role.code())?;
        encoder.str(key_id)?;
        encoder.bytes(canonical_claims)?;
        encoder.bytes(cose_sign1)?;
        Ok(encoder.into_writer())
    })();
    let envelope = finish_encoding(encoded)?;
    if envelope.len() > MAX_TERMINAL_WITNESS_ENVELOPE_BYTES {
        return Err(WitnessError::InvalidRecord(
            "terminal-witness persistence envelope is oversized",
        ));
    }
    Ok(envelope)
}

fn bounded_claims(bytes: Vec<u8>) -> Result<Vec<u8>, WitnessError> {
    if bytes.len() > MAX_TERMINAL_WITNESS_CLAIMS_BYTES {
        return Err(WitnessError::InvalidRecord(
            "terminal-witness canonical claims are oversized",
        ));
    }
    Ok(bytes)
}

/// Strictly decodes deterministic exact-effect claims bytes.
///
/// # Errors
///
/// Rejects malformed, oversized, noncanonical, trailing, or out-of-profile
/// CBOR and every record that fails the normal public constructors.
pub fn decode_effect_claims_canonical(
    bytes: &[u8],
) -> Result<EffectObservationClaims, WitnessError> {
    if bytes.len() > MAX_TERMINAL_WITNESS_CLAIMS_BYTES {
        return Err(WitnessError::InvalidRecord(
            "terminal-witness canonical claims are oversized",
        ));
    }
    let mut decoder = Decoder::new(bytes);
    expect_array(&mut decoder, 8)?;
    expect_schema(&mut decoder)?;
    if decoded(decoder.u8())? != EffectClassification::ExactEffectV1.code() {
        return Err(WitnessError::InvalidRecord(
            "unsupported terminal-effect classification",
        ));
    }
    let evidence_id = decode_uuid(&mut decoder)?;
    let attempt = decode_attempt(&mut decoder)?;
    let issuer = decode_issuer(&mut decoder)?;
    let result = decode_effect_result(&mut decoder)?;
    let observation_started_at = decoded(decoder.i64())?;
    let observed_at = decoded(decoder.i64())?;
    ensure_finished(&decoder, bytes)?;
    let claims = EffectObservationClaims::new(
        evidence_id,
        attempt,
        issuer,
        result,
        observation_started_at,
        observed_at,
    )?;
    if canonical_effect_claims(&claims)? != bytes {
        return Err(WitnessError::NonCanonicalWire);
    }
    Ok(claims)
}

/// Strictly decodes deterministic credential-retirement claims bytes.
///
/// # Errors
///
/// Rejects malformed, oversized, noncanonical, trailing, or out-of-profile
/// CBOR and every record that fails the normal public constructors.
pub fn decode_retirement_claims_canonical(
    bytes: &[u8],
) -> Result<CredentialRetirementClaims, WitnessError> {
    if bytes.len() > MAX_TERMINAL_WITNESS_CLAIMS_BYTES {
        return Err(WitnessError::InvalidRecord(
            "terminal-witness canonical claims are oversized",
        ));
    }
    let mut decoder = Decoder::new(bytes);
    expect_array(&mut decoder, 9)?;
    expect_schema(&mut decoder)?;
    let evidence_id = decode_uuid(&mut decoder)?;
    let attempt = decode_attempt(&mut decoder)?;
    let issuer = decode_issuer(&mut decoder)?;
    let credential = decode_credential(&mut decoder)?;
    let deletion = decode_deletion(&mut decoder)?;
    let basis = decode_retirement_basis(&mut decoder, &attempt, &credential)?;
    let observation_started_at = decoded(decoder.i64())?;
    let observed_at = decoded(decoder.i64())?;
    ensure_finished(&decoder, bytes)?;
    let claims = CredentialRetirementClaims::new(
        evidence_id,
        attempt,
        issuer,
        credential,
        deletion,
        basis,
        observation_started_at,
        observed_at,
    )?;
    if canonical_retirement_claims(&claims)? != bytes {
        return Err(WitnessError::NonCanonicalWire);
    }
    Ok(claims)
}

fn decode_effect_envelope(bytes: &[u8]) -> Result<SignedEffectWitness, WitnessError> {
    let (role, key_id, claims_bytes, cose_sign1) = decode_envelope_parts(bytes)?;
    if role != WitnessRole::ExactEffect {
        return Err(WitnessError::VerifierRoleMismatch);
    }
    let claims = decode_effect_claims_canonical(&claims_bytes)?;
    SignedEffectWitness::from_untrusted_parts(key_id, claims, cose_sign1)
}

fn decode_retirement_envelope(
    bytes: &[u8],
) -> Result<SignedCredentialRetirementWitness, WitnessError> {
    let (role, key_id, claims_bytes, cose_sign1) = decode_envelope_parts(bytes)?;
    if role != WitnessRole::CredentialRetirement {
        return Err(WitnessError::VerifierRoleMismatch);
    }
    let claims = decode_retirement_claims_canonical(&claims_bytes)?;
    SignedCredentialRetirementWitness::from_untrusted_parts(key_id, claims, cose_sign1)
}

fn decode_envelope_parts(
    bytes: &[u8],
) -> Result<(WitnessRole, String, Vec<u8>, Vec<u8>), WitnessError> {
    if bytes.is_empty() || bytes.len() > MAX_TERMINAL_WITNESS_ENVELOPE_BYTES {
        return Err(WitnessError::InvalidRecord(
            "terminal-witness persistence envelope size is out of bounds",
        ));
    }
    let mut decoder = Decoder::new(bytes);
    expect_array(&mut decoder, 5)?;
    expect_schema(&mut decoder)?;
    let role = match decoded(decoder.u8())? {
        1 => WitnessRole::ExactEffect,
        2 => WitnessRole::CredentialRetirement,
        _ => {
            return Err(WitnessError::InvalidRecord(
                "unsupported terminal-witness envelope role",
            ));
        }
    };
    let key_id = decoded(decoder.str())?.to_owned();
    if !valid_security_text(&key_id, MAX_KEY_ID_BYTES) {
        return Err(WitnessError::InvalidRecord(
            "invalid terminal-witness envelope key ID",
        ));
    }
    let claims_bytes = decoded(decoder.bytes())?;
    if claims_bytes.len() > MAX_TERMINAL_WITNESS_CLAIMS_BYTES {
        return Err(WitnessError::InvalidRecord(
            "terminal-witness canonical claims are oversized",
        ));
    }
    let claims_bytes = claims_bytes.to_vec();
    let cose_sign1 = decoded(decoder.bytes())?;
    if cose_sign1.is_empty() || cose_sign1.len() > MAX_COSE_SIZE_BYTES {
        return Err(WitnessError::InvalidRecord(
            "terminal-witness COSE size is out of bounds",
        ));
    }
    let cose_sign1 = cose_sign1.to_vec();
    ensure_finished(&decoder, bytes)?;
    if canonical_signed_envelope(role, &key_id, &claims_bytes, &cose_sign1)? != bytes {
        return Err(WitnessError::NonCanonicalWire);
    }
    Ok((role, key_id, claims_bytes, cose_sign1))
}

fn decode_attempt(decoder: &mut Decoder<'_>) -> Result<TerminalAttemptBinding, WitnessError> {
    expect_array(decoder, 3)?;
    let identity = decode_attempt_identity(decoder)?;
    let effect = decode_effect_bindings(decoder)?;
    let admission = decode_admission(decoder)?;
    Ok(TerminalAttemptBinding::new(identity, effect, admission))
}

fn decode_attempt_identity(decoder: &mut Decoder<'_>) -> Result<AttemptIdentity, WitnessError> {
    expect_array(decoder, 8)?;
    let state_instance_id = decode_uuid(decoder)?;
    let scope = decode_scope(decoder)?;
    let transaction_id = decode_uuid(decoder)?;
    let authorization_id = decode_uuid(decoder)?;
    let claim_id = decode_uuid(decoder)?;
    let fence = decoded(decoder.u64())?;
    let physical_resource = decode_physical_resource(decoder)?;
    let attempt_started_at = decoded(decoder.i64())?;
    AttemptIdentity::new(
        state_instance_id,
        scope,
        transaction_id,
        authorization_id,
        claim_id,
        fence,
        physical_resource,
        attempt_started_at,
    )
}

fn decode_scope(decoder: &mut Decoder<'_>) -> Result<WitnessScope, WitnessError> {
    expect_array(decoder, 2)?;
    let tenant = decoded(decoder.str())?.to_owned();
    let environment = decoded(decoder.str())?.to_owned();
    WitnessScope::new(tenant, environment)
}

fn decode_physical_resource(
    decoder: &mut Decoder<'_>,
) -> Result<PhysicalResourceBinding, WitnessError> {
    expect_array(decoder, 6)?;
    let cluster_trust_domain = decoded(decoder.str())?.to_owned();
    let api_server_identity = decoded(decoder.str())?.to_owned();
    let cluster_identity = decoded(decoder.str())?.to_owned();
    let namespace = decoded(decoder.str())?.to_owned();
    let deployment_uid = decoded(decoder.str())?.to_owned();
    let resource_name = decoded(decoder.str())?.to_owned();
    PhysicalResourceBinding::new(
        cluster_trust_domain,
        api_server_identity,
        cluster_identity,
        namespace,
        deployment_uid,
        resource_name,
    )
}

fn decode_effect_bindings(
    decoder: &mut Decoder<'_>,
) -> Result<EffectBindingCommitments, WitnessError> {
    expect_array(decoder, 7)?;
    EffectBindingCommitments::new(
        decode_digest(decoder)?,
        decode_digest(decoder)?,
        decode_digest(decoder)?,
        decode_digest(decoder)?,
        decode_digest(decoder)?,
        decode_digest(decoder)?,
        decode_digest(decoder)?,
    )
}

fn decode_admission(decoder: &mut Decoder<'_>) -> Result<AdmissionLinkage, WitnessError> {
    let length = decoded(decoder.array())?.ok_or(WitnessError::NonCanonicalWire)?;
    let code = decoded(decoder.u8())?;
    match (length, code) {
        (1, 0) => Ok(AdmissionLinkage::not_required()),
        (3, 1) => {
            let admission_uid = decoded(decoder.str())?.to_owned();
            AdmissionLinkage::required(admission_uid, decode_digest(decoder)?)
        }
        _ => Err(WitnessError::InvalidRecord(
            "invalid admission linkage wire profile",
        )),
    }
}

fn decode_issuer(decoder: &mut Decoder<'_>) -> Result<WitnessIssuer, WitnessError> {
    expect_array(decoder, 3)?;
    let observer_identity = decoded(decoder.str())?.to_owned();
    let key_id = decoded(decoder.str())?.to_owned();
    let authority_version = decoded(decoder.u64())?;
    WitnessIssuer::new(observer_identity, key_id, authority_version)
}

fn decode_effect_result(
    decoder: &mut Decoder<'_>,
) -> Result<EffectObservationResult, WitnessError> {
    expect_array(decoder, 7)?;
    let outcome = match decoded(decoder.u8())? {
        1 => ExactExecutionOutcome::KubernetesDeploymentUpdatedV1,
        _ => {
            return Err(WitnessError::InvalidRecord("unsupported execution outcome"));
        }
    };
    let response_commitment = decode_digest(decoder)?;
    let post_state_commitment = decode_digest(decoder)?;
    let complete_observation_commitment = decode_digest(decoder)?;
    let resource_uid = decoded(decoder.str())?.to_owned();
    let resource_version = decoded(decoder.str())?.to_owned();
    let audit_cursor = decoded(decoder.str())?.to_owned();
    EffectObservationResult::new(
        outcome,
        response_commitment,
        post_state_commitment,
        complete_observation_commitment,
        resource_uid,
        resource_version,
        audit_cursor,
    )
}

fn decode_credential(decoder: &mut Decoder<'_>) -> Result<CredentialIdentity, WitnessError> {
    expect_array(decoder, 7)?;
    let token_digest = decode_digest(decoder)?;
    let credential_id = decoded(decoder.str())?.to_owned();
    let service_account_uid = decoded(decoder.str())?.to_owned();
    let audience = decoded(decoder.str())?.to_owned();
    let subject = decoded(decoder.str())?.to_owned();
    let secret_name = decoded(decoder.str())?.to_owned();
    let secret_uid = decoded(decoder.str())?.to_owned();
    CredentialIdentity::new(
        token_digest,
        credential_id,
        service_account_uid,
        audience,
        subject,
        secret_name,
        secret_uid,
    )
}

fn decode_deletion(decoder: &mut Decoder<'_>) -> Result<SecretDeletionObservation, WitnessError> {
    expect_array(decoder, 2)?;
    SecretDeletionObservation::new(decode_digest(decoder)?, decoded(decoder.i64())?)
}

fn decode_retirement_basis(
    decoder: &mut Decoder<'_>,
    attempt: &TerminalAttemptBinding,
    credential: &CredentialIdentity,
) -> Result<RetirementBasis, WitnessError> {
    let length = decoded(decoder.array())?.ok_or(WitnessError::NonCanonicalWire)?;
    let code = decoded(decoder.u8())?;
    match (length, code) {
        (4, 1) => {
            let encoded_request = decode_digest(decoder)?;
            let basis = RetirementBasis::token_review_rejected(
                attempt,
                credential,
                decode_digest(decoder)?,
                decoded(decoder.i64())?,
            )?;
            if basis.token_review_request_commitment() != Some(encoded_request) {
                return Err(WitnessError::TokenReviewBindingMismatch);
            }
            Ok(basis)
        }
        (2, 2) => Ok(RetirementBasis::conservative(decode_conservative_bound(
            decoder,
        )?)),
        _ => Err(WitnessError::InvalidRecord(
            "invalid credential-retirement basis wire profile",
        )),
    }
}

fn decode_conservative_bound(
    decoder: &mut Decoder<'_>,
) -> Result<ConservativeRetirementBound, WitnessError> {
    expect_array(decoder, 9)?;
    let policy_id = decoded(decoder.str())?.to_owned();
    let policy_version = decoded(decoder.u64())?;
    let policy_commitment = decode_digest(decoder)?;
    let issuance_started_at = decoded(decoder.i64())?;
    let server_token_lifetime_hard_max_s = decoded(decoder.i64())?;
    let deletion_propagation_hard_max_s = decoded(decoder.i64())?;
    let clock_uncertainty_s = decoded(decoder.i64())?;
    let deletion_observed_at = decoded(decoder.i64())?;
    let encoded_safe_after = decoded(decoder.i64())?;
    let bound = ConservativeRetirementBound::new(
        policy_id,
        policy_version,
        policy_commitment,
        issuance_started_at,
        server_token_lifetime_hard_max_s,
        deletion_propagation_hard_max_s,
        clock_uncertainty_s,
        deletion_observed_at,
    )?;
    if bound.credential_safe_after != encoded_safe_after {
        return Err(WitnessError::InvalidRecord(
            "encoded credential safe-after is not internally derived",
        ));
    }
    Ok(bound)
}

fn expect_array(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), WitnessError> {
    if decoded(decoder.array())? != Some(expected) {
        return Err(WitnessError::NonCanonicalWire);
    }
    Ok(())
}

fn expect_schema(decoder: &mut Decoder<'_>) -> Result<(), WitnessError> {
    if decoded(decoder.u16())? != TERMINAL_WITNESS_SCHEMA_VERSION {
        return Err(WitnessError::InvalidRecord(
            "unsupported terminal-witness schema version",
        ));
    }
    Ok(())
}

fn decode_uuid(decoder: &mut Decoder<'_>) -> Result<Uuid, WitnessError> {
    let bytes = decoded(decoder.bytes())?;
    let raw: [u8; 16] = bytes.try_into().map_err(|_| {
        WitnessError::InvalidRecord("UUID wire value must contain exactly 16 bytes")
    })?;
    Ok(Uuid::from_bytes(raw))
}

fn decode_digest(decoder: &mut Decoder<'_>) -> Result<Digest32, WitnessError> {
    let bytes = decoded(decoder.bytes())?;
    let raw: [u8; 32] = bytes.try_into().map_err(|_| {
        WitnessError::InvalidRecord("digest wire value must contain exactly 32 bytes")
    })?;
    Ok(Digest32::from_bytes(raw))
}

fn ensure_finished(decoder: &Decoder<'_>, bytes: &[u8]) -> Result<(), WitnessError> {
    if decoder.position() != bytes.len() {
        return Err(WitnessError::NonCanonicalWire);
    }
    Ok(())
}

fn decoded<T>(result: Result<T, DecodeError>) -> Result<T, WitnessError> {
    result.map_err(|error| WitnessError::Canonical(error.to_string()))
}

fn encode_attempt(
    encoder: &mut VecEncoder,
    value: &TerminalAttemptBinding,
) -> Result<(), VecEncodeError> {
    encoder.array(3)?;
    encode_attempt_identity(encoder, &value.identity)?;
    encode_effect_bindings(encoder, &value.effect)?;
    encode_admission(encoder, &value.admission)?;
    Ok(())
}

fn encode_attempt_identity(
    encoder: &mut VecEncoder,
    value: &AttemptIdentity,
) -> Result<(), VecEncodeError> {
    encoder.array(8)?;
    encode_uuid(encoder, value.state_instance_id)?;
    encode_scope(encoder, &value.scope)?;
    encode_uuid(encoder, value.transaction_id)?;
    encode_uuid(encoder, value.authorization_id)?;
    encode_uuid(encoder, value.claim_id)?;
    encoder.u64(value.fence)?;
    encode_physical_resource(encoder, &value.physical_resource)?;
    encoder.i64(value.attempt_started_at)?;
    Ok(())
}

fn encode_scope(encoder: &mut VecEncoder, value: &WitnessScope) -> Result<(), VecEncodeError> {
    encoder.array(2)?;
    encoder.str(&value.tenant)?;
    encoder.str(&value.environment)?;
    Ok(())
}

fn encode_physical_resource(
    encoder: &mut VecEncoder,
    value: &PhysicalResourceBinding,
) -> Result<(), VecEncodeError> {
    encoder.array(6)?;
    encoder.str(&value.cluster_trust_domain)?;
    encoder.str(&value.api_server_identity)?;
    encoder.str(&value.cluster_identity)?;
    encoder.str(&value.namespace)?;
    encoder.str(&value.deployment_uid)?;
    encoder.str(&value.resource_name)?;
    Ok(())
}

fn encode_effect_bindings(
    encoder: &mut VecEncoder,
    value: &EffectBindingCommitments,
) -> Result<(), VecEncodeError> {
    encoder.array(7)?;
    for digest in value.digests() {
        encoder.bytes(digest.as_bytes())?;
    }
    Ok(())
}

fn encode_admission(
    encoder: &mut VecEncoder,
    value: &AdmissionLinkage,
) -> Result<(), VecEncodeError> {
    match &value.kind {
        AdmissionLinkageKind::NotRequired => {
            encoder.array(1)?;
            encoder.u8(0)?;
        }
        AdmissionLinkageKind::Required {
            admission_uid,
            request_commitment,
        } => {
            encoder.array(3)?;
            encoder.u8(1)?;
            encoder.str(admission_uid)?;
            encoder.bytes(request_commitment.as_bytes())?;
        }
    }
    Ok(())
}

fn encode_issuer(encoder: &mut VecEncoder, value: &WitnessIssuer) -> Result<(), VecEncodeError> {
    encoder.array(3)?;
    encoder.str(&value.observer_identity)?;
    encoder.str(&value.key_id)?;
    encoder.u64(value.authority_version)?;
    Ok(())
}

fn encode_effect_result(
    encoder: &mut VecEncoder,
    value: &EffectObservationResult,
) -> Result<(), VecEncodeError> {
    encoder.array(7)?;
    encoder.u8(value.outcome.code())?;
    encoder.bytes(value.response_commitment.as_bytes())?;
    encoder.bytes(value.post_state_commitment.as_bytes())?;
    encoder.bytes(value.complete_observation_commitment.as_bytes())?;
    encoder.str(&value.resource_uid)?;
    encoder.str(&value.resource_version)?;
    encoder.str(&value.audit_cursor)?;
    Ok(())
}

fn encode_credential(
    encoder: &mut VecEncoder,
    value: &CredentialIdentity,
) -> Result<(), VecEncodeError> {
    encoder.array(7)?;
    encoder.bytes(value.token_digest.as_bytes())?;
    encoder.str(&value.credential_id)?;
    encoder.str(&value.service_account_uid)?;
    encoder.str(&value.audience)?;
    encoder.str(&value.subject)?;
    encoder.str(&value.secret_name)?;
    encoder.str(&value.secret_uid)?;
    Ok(())
}

fn encode_deletion(
    encoder: &mut VecEncoder,
    value: &SecretDeletionObservation,
) -> Result<(), VecEncodeError> {
    encoder.array(2)?;
    encoder.bytes(value.observation_commitment.as_bytes())?;
    encoder.i64(value.observed_at)?;
    Ok(())
}

fn encode_retirement_basis(
    encoder: &mut VecEncoder,
    value: &RetirementBasis,
) -> Result<(), VecEncodeError> {
    match &value.kind {
        RetirementBasisKind::TokenReviewRejected {
            request_commitment,
            response_commitment,
            rejected_at,
        } => {
            encoder.array(4)?;
            encoder.u8(1)?;
            encoder.bytes(request_commitment.as_bytes())?;
            encoder.bytes(response_commitment.as_bytes())?;
            encoder.i64(*rejected_at)?;
        }
        RetirementBasisKind::ConservativeSafeAfter(bound) => {
            encoder.array(2)?;
            encoder.u8(2)?;
            encode_conservative_bound(encoder, bound)?;
        }
    }
    Ok(())
}

fn encode_conservative_bound(
    encoder: &mut VecEncoder,
    value: &ConservativeRetirementBound,
) -> Result<(), VecEncodeError> {
    encoder.array(9)?;
    encoder.str(&value.policy_id)?;
    encoder.u64(value.policy_version)?;
    encoder.bytes(value.policy_commitment.as_bytes())?;
    encoder.i64(value.issuance_started_at)?;
    encoder.i64(value.server_token_lifetime_hard_max_s)?;
    encoder.i64(value.deletion_propagation_hard_max_s)?;
    encoder.i64(value.clock_uncertainty_s)?;
    encoder.i64(value.deletion_observed_at)?;
    encoder.i64(value.credential_safe_after)?;
    Ok(())
}

fn encode_uuid(encoder: &mut VecEncoder, value: Uuid) -> Result<(), VecEncodeError> {
    encoder.bytes(value.as_bytes())?;
    Ok(())
}

fn validate_registry_entries(entries: &[RegisteredWitnessVerifier]) -> Result<(), WitnessError> {
    if entries.is_empty() || entries.len() > MAX_WITNESS_REGISTRY_ENTRIES {
        return Err(WitnessError::InvalidRecord(
            "terminal-witness registry size is out of bounds",
        ));
    }
    let mut previous: Option<(WitnessRole, &str, &str)> = None;
    let mut key_ids = BTreeSet::new();
    let mut public_keys = BTreeSet::new();
    let mut observer_identities = BTreeSet::new();
    let mut effect_role = false;
    let mut retirement_role = false;
    for entry in entries {
        if previous.is_some_and(|prior| prior >= entry.sort_key()) {
            return Err(WitnessError::NonCanonicalRegistry);
        }
        previous = Some(entry.sort_key());
        CoseVerifier::from_public_key(entry.key_id.clone(), entry.public_key)?;
        if !key_ids.insert(entry.key_id.clone())
            || !public_keys.insert(entry.public_key)
            || !observer_identities.insert(entry.observer_identity.clone())
        {
            return Err(WitnessError::RegistryIdentityAlias);
        }
        match entry.role {
            WitnessRole::ExactEffect => effect_role = true,
            WitnessRole::CredentialRetirement => retirement_role = true,
        }
    }
    if !effect_role || !retirement_role {
        return Err(WitnessError::MissingVerifierRole);
    }
    Ok(())
}

fn canonical_registry_entries(
    entries: &[RegisteredWitnessVerifier],
) -> Result<Vec<u8>, WitnessError> {
    let encoded: Result<Vec<u8>, VecEncodeError> = (|| {
        let mut encoder = Encoder::new(Vec::new());
        encoder.array(u64::try_from(entries.len()).unwrap_or(u64::MAX))?;
        for entry in entries {
            encoder.array(12)?;
            encode_scope(&mut encoder, &entry.scope)?;
            encoder.str(&entry.cluster_identity)?;
            encoder.u8(entry.role.code())?;
            encoder.str(&entry.observer_identity)?;
            encoder.str(&entry.key_id)?;
            encoder.bytes(&entry.public_key)?;
            encoder.i64(entry.not_before)?;
            encoder.i64(entry.valid_until)?;
            encoder.i64(entry.accepted_through)?;
            encoder.u64(entry.authority_version)?;
            encoder.bytes(entry.authorizing_root.as_bytes())?;
            encoder.u8(entry.status.code())?;
        }
        Ok(encoder.into_writer())
    })();
    finish_encoding(encoded)
}

fn activation_commitment(authority: &WitnessRegistryAuthority) -> Result<Digest32, WitnessError> {
    let encoded: Result<Vec<u8>, VecEncodeError> = (|| {
        let mut encoder = Encoder::new(Vec::new());
        encoder.array(4)?;
        encoder.u16(TERMINAL_WITNESS_SCHEMA_VERSION)?;
        encoder.bytes(authority.material_root.as_bytes())?;
        encoder.u64(authority.epoch)?;
        encode_uuid(&mut encoder, authority.activation_id)?;
        Ok(encoder.into_writer())
    })();
    let canonical = finish_encoding(encoded)?;
    let mut input = Vec::with_capacity(WITNESS_REGISTRY_COMMITMENT_DOMAIN.len() + canonical.len());
    input.extend_from_slice(WITNESS_REGISTRY_COMMITMENT_DOMAIN);
    input.extend_from_slice(&canonical);
    Ok(Digest32::sha256(&input))
}

fn validate_effect_claims(value: &EffectObservationClaims) -> Result<(), WitnessError> {
    validate_attempt(&value.attempt)?;
    validate_issuer(&value.issuer)?;
    validate_effect_result(&value.result)?;
    if value.evidence_id.is_nil()
        || value.observation_started_at < value.attempt.identity.attempt_started_at
        || value.observed_at < value.observation_started_at
        || value.result.resource_uid != value.attempt.identity.physical_resource.deployment_uid
    {
        return Err(WitnessError::InvalidRecord("invalid exact-effect claims"));
    }
    Ok(())
}

fn validate_retirement_claims(value: &CredentialRetirementClaims) -> Result<(), WitnessError> {
    validate_attempt(&value.attempt)?;
    validate_issuer(&value.issuer)?;
    validate_attempt_credential_pair(&value.attempt, &value.credential)?;
    if value.evidence_id.is_nil()
        || is_zero_digest(value.deletion.observation_commitment)
        || value.deletion.observed_at < value.attempt.identity.attempt_started_at
        || value.observation_started_at < value.deletion.observed_at
        || value.observed_at < value.observation_started_at
        || value.credential.token_digest != value.attempt.effect.token_digest
    {
        return Err(WitnessError::InvalidRecord(
            "invalid credential-retirement claims",
        ));
    }
    match &value.basis.kind {
        RetirementBasisKind::TokenReviewRejected {
            request_commitment,
            response_commitment,
            rejected_at,
        } => {
            if *request_commitment
                != token_review_request_commitment(&value.attempt, &value.credential)?
                || is_zero_digest(*response_commitment)
                || *rejected_at < value.deletion.observed_at
                || *rejected_at > value.observed_at
            {
                return Err(WitnessError::InvalidRecord(
                    "invalid TokenReview retirement basis",
                ));
            }
        }
        RetirementBasisKind::ConservativeSafeAfter(bound) => {
            validate_conservative_bound(bound)?;
            if bound.deletion_observed_at != value.deletion.observed_at
                || bound.issuance_started_at > value.attempt.identity.attempt_started_at
                || value.observed_at < bound.credential_safe_after
            {
                return Err(WitnessError::InvalidRecord(
                    "invalid conservative retirement basis",
                ));
            }
        }
    }
    Ok(())
}

fn validate_attempt(value: &TerminalAttemptBinding) -> Result<(), WitnessError> {
    let identity = &value.identity;
    if identity.state_instance_id.is_nil()
        || identity.transaction_id.is_nil()
        || identity.authorization_id.is_nil()
        || identity.claim_id.is_nil()
        || identity.fence == 0
        || identity.attempt_started_at <= 0
        || !valid_security_text(&identity.scope.tenant, MAX_SCOPE_COMPONENT_BYTES)
        || !valid_security_text(&identity.scope.environment, MAX_SCOPE_COMPONENT_BYTES)
        || !valid_security_text(
            &identity.physical_resource.cluster_trust_domain,
            MAX_CLUSTER_IDENTITY_BYTES,
        )
        || !valid_security_text(
            &identity.physical_resource.api_server_identity,
            MAX_CLUSTER_IDENTITY_BYTES,
        )
        || !valid_security_text(
            &identity.physical_resource.cluster_identity,
            MAX_CLUSTER_IDENTITY_BYTES,
        )
        || !valid_dns_subdomain(&identity.physical_resource.namespace)
        || !valid_security_text(
            &identity.physical_resource.deployment_uid,
            MAX_KUBERNETES_UID_BYTES,
        )
        || !valid_dns_subdomain(&identity.physical_resource.resource_name)
        || value.effect.digests().into_iter().any(is_zero_digest)
    {
        return Err(WitnessError::InvalidRecord("invalid terminal attempt"));
    }
    match &value.admission.kind {
        AdmissionLinkageKind::NotRequired => {}
        AdmissionLinkageKind::Required {
            admission_uid,
            request_commitment,
        } if valid_admission_uid(admission_uid) && !is_zero_digest(*request_commitment) => {}
        AdmissionLinkageKind::Required { .. } => {
            return Err(WitnessError::InvalidRecord(
                "invalid attempt admission linkage",
            ));
        }
    }
    Ok(())
}

fn validate_issuer(value: &WitnessIssuer) -> Result<(), WitnessError> {
    if !valid_security_text(&value.observer_identity, MAX_OBSERVER_IDENTITY_BYTES)
        || !valid_security_text(&value.key_id, MAX_KEY_ID_BYTES)
        || value.authority_version == 0
    {
        return Err(WitnessError::InvalidRecord("invalid witness issuer"));
    }
    Ok(())
}

fn validate_effect_result(value: &EffectObservationResult) -> Result<(), WitnessError> {
    if [
        value.response_commitment,
        value.post_state_commitment,
        value.complete_observation_commitment,
    ]
    .into_iter()
    .any(is_zero_digest)
        || !valid_security_text(&value.resource_uid, MAX_KUBERNETES_UID_BYTES)
        || !valid_security_text(&value.resource_version, MAX_KUBERNETES_UID_BYTES)
        || !valid_security_text(&value.audit_cursor, MAX_AUDIT_CURSOR_BYTES)
    {
        return Err(WitnessError::InvalidRecord("invalid exact-effect result"));
    }
    Ok(())
}

fn validate_credential(value: &CredentialIdentity) -> Result<(), WitnessError> {
    if is_zero_digest(value.token_digest)
        || !valid_credential_id(&value.credential_id)
        || !valid_security_text(&value.service_account_uid, MAX_KUBERNETES_UID_BYTES)
        || !valid_security_text(&value.audience, MAX_AUDIENCE_BYTES)
        || !valid_security_text(&value.subject, MAX_SUBJECT_BYTES)
        || !valid_dns_subdomain(&value.secret_name)
        || !valid_security_text(&value.secret_uid, MAX_KUBERNETES_UID_BYTES)
    {
        return Err(WitnessError::InvalidRecord("invalid credential identity"));
    }
    Ok(())
}

fn validate_attempt_credential_pair(
    attempt: &TerminalAttemptBinding,
    credential: &CredentialIdentity,
) -> Result<(), WitnessError> {
    validate_attempt(attempt)?;
    validate_credential(credential)?;
    if credential.token_digest != attempt.effect.token_digest {
        return Err(WitnessError::CredentialBindingMismatch);
    }
    Ok(())
}

fn validate_conservative_bound(value: &ConservativeRetirementBound) -> Result<(), WitnessError> {
    let recomputed = ConservativeRetirementBound::new(
        value.policy_id.clone(),
        value.policy_version,
        value.policy_commitment,
        value.issuance_started_at,
        value.server_token_lifetime_hard_max_s,
        value.deletion_propagation_hard_max_s,
        value.clock_uncertainty_s,
        value.deletion_observed_at,
    )?;
    if recomputed != *value {
        return Err(WitnessError::InvalidRecord(
            "conservative safe-after was not internally derived",
        ));
    }
    Ok(())
}

fn validate_trusted_now(trusted_now: i64, observed_at: i64) -> Result<(), WitnessError> {
    if trusted_now <= 0 || observed_at > trusted_now {
        return Err(WitnessError::InvalidObservationTime);
    }
    Ok(())
}

fn valid_security_text(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_dns_subdomain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_DNS_SUBDOMAIN_BYTES
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

fn valid_admission_uid(value: &str) -> bool {
    valid_security_text(value, 128)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_credential_id(value: &str) -> bool {
    if value.len() > MAX_CREDENTIAL_ID_BYTES {
        return false;
    }
    let Some(raw_authorization_id) = value.strip_prefix("AUTHORIZATION_ID=") else {
        return false;
    };
    Uuid::parse_str(raw_authorization_id)
        .ok()
        .is_some_and(|uuid| !uuid.is_nil() && uuid.to_string() == raw_authorization_id)
}

fn is_zero_digest(value: Digest32) -> bool {
    value.as_bytes().iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ATTEMPT_STARTED_AT: i64 = 1_000;
    const DELETION_OBSERVED_AT: i64 = 1_100;
    const OBSERVATION_STARTED_AT: i64 = 1_150;
    const OBSERVED_AT: i64 = 1_200;
    const TRUSTED_NOW: i64 = 1_250;

    struct Fixture {
        effect_signer: SigningIdentity,
        retirement_signer: SigningIdentity,
        registry: ActivatedWitnessRegistry,
        attempt: TerminalAttemptBinding,
        credential: CredentialIdentity,
        deletion_facts: SecretDeletionObservationV2,
        deletion: SecretDeletionObservation,
        token_review_request: Digest32,
        conservative: ConservativeRetirementBound,
    }

    fn digest(marker: u8) -> Digest32 {
        Digest32::from_bytes([marker; 32])
    }

    fn uuid(marker: u128) -> Uuid {
        Uuid::from_u128(marker)
    }

    fn effect_entry(signer: &SigningIdentity) -> Result<RegisteredWitnessVerifier, WitnessError> {
        RegisteredWitnessVerifier::new(
            WitnessScope::new("tenant-a", "prod")?,
            "cluster-a",
            WitnessRole::ExactEffect,
            "spiffe://accordlock.test/observer/effect",
            signer.key_id(),
            signer.public_key_bytes(),
            900,
            2_000,
            1_900,
            3,
            digest(90),
            WitnessVerifierStatus::Active,
        )
    }

    fn retirement_entry(
        signer: &SigningIdentity,
    ) -> Result<RegisteredWitnessVerifier, WitnessError> {
        RegisteredWitnessVerifier::new(
            WitnessScope::new("tenant-a", "prod")?,
            "cluster-a",
            WitnessRole::CredentialRetirement,
            "spiffe://accordlock.test/observer/retirement",
            signer.key_id(),
            signer.public_key_bytes(),
            900,
            2_000,
            1_900,
            3,
            digest(90),
            WitnessVerifierStatus::Active,
        )
    }

    fn registry_from_entries(
        entries: Vec<RegisteredWitnessVerifier>,
        epoch: u64,
        activation_id: Uuid,
    ) -> Result<ActivatedWitnessRegistry, WitnessError> {
        let root = ActivatedWitnessRegistry::compute_material_root(&entries)?;
        ActivatedWitnessRegistry::new(
            WitnessRegistryAuthority::new(root, epoch, activation_id)?,
            entries,
        )
    }

    fn fixture() -> Result<Fixture, WitnessError> {
        let effect_signer = SigningIdentity::from_seed("effect-key-v1", [7; 32]);
        let retirement_signer = SigningIdentity::from_seed("retirement-key-v1", [8; 32]);
        let entries = vec![
            effect_entry(&effect_signer)?,
            retirement_entry(&retirement_signer)?,
        ];
        let registry = registry_from_entries(entries, 11, uuid(80))?;
        let physical = PhysicalResourceBinding::new(
            "spiffe://cluster-a.accordlock.test",
            "sha256:api-server-a",
            "cluster-a",
            "workloads",
            "deployment-uid-a",
            "payments-api",
        )?;
        let identity = AttemptIdentity::new(
            uuid(1),
            WitnessScope::new("tenant-a", "prod")?,
            uuid(2),
            uuid(3),
            uuid(4),
            17,
            physical,
            ATTEMPT_STARTED_AT,
        )?;
        let effect = EffectBindingCommitments::new(
            digest(1),
            digest(2),
            digest(3),
            digest(4),
            digest(5),
            digest(6),
            digest(7),
        )?;
        let admission = AdmissionLinkage::required("admission-uid-a", digest(8))?;
        let attempt = TerminalAttemptBinding::new(identity, effect, admission);
        let credential = CredentialIdentity::new(
            digest(7),
            format!("AUTHORIZATION_ID={}", uuid(9)),
            "service-account-uid-a",
            "https://kubernetes.default.svc",
            "system:serviceaccount:workloads:accordlock-executor",
            "accordlock-credential-a",
            "secret-uid-a",
        )?;
        let deletion_facts = SecretDeletionObservationV2::new(
            uuid(40),
            digest(40),
            digest(41),
            digest(42),
            DELETION_OBSERVED_AT,
        )?;
        let deletion = deletion_facts.observation(&attempt, &credential)?;
        let token_review_request = token_review_request_commitment(&attempt, &credential)?;
        let conservative = ConservativeRetirementBound::new(
            "eks-bound-token-v1",
            5,
            digest(43),
            950,
            100,
            50,
            5,
            DELETION_OBSERVED_AT,
        )?;
        Ok(Fixture {
            effect_signer,
            retirement_signer,
            registry,
            attempt,
            credential,
            deletion_facts,
            deletion,
            token_review_request,
            conservative,
        })
    }

    fn effect_claims(fixture: &Fixture) -> Result<EffectObservationClaims, WitnessError> {
        EffectObservationClaims::new(
            uuid(10),
            fixture.attempt.clone(),
            WitnessIssuer::new(
                "spiffe://accordlock.test/observer/effect",
                fixture.effect_signer.key_id(),
                3,
            )?,
            EffectObservationResult::new(
                ExactExecutionOutcome::KubernetesDeploymentUpdatedV1,
                digest(20),
                digest(21),
                digest(22),
                "deployment-uid-a",
                "4815162342",
                "audit-cursor-a",
            )?,
            1_100,
            OBSERVED_AT,
        )
    }

    fn token_retirement_claims(
        fixture: &Fixture,
    ) -> Result<CredentialRetirementClaims, WitnessError> {
        CredentialRetirementClaims::new(
            uuid(11),
            fixture.attempt.clone(),
            WitnessIssuer::new(
                "spiffe://accordlock.test/observer/retirement",
                fixture.retirement_signer.key_id(),
                3,
            )?,
            fixture.credential.clone(),
            fixture.deletion.clone(),
            RetirementBasis::token_review_rejected(
                &fixture.attempt,
                &fixture.credential,
                digest(43),
                1_125,
            )?,
            OBSERVATION_STARTED_AT,
            OBSERVED_AT,
        )
    }

    fn conservative_retirement_claims(
        fixture: &Fixture,
    ) -> Result<CredentialRetirementClaims, WitnessError> {
        CredentialRetirementClaims::new(
            uuid(12),
            fixture.attempt.clone(),
            WitnessIssuer::new(
                "spiffe://accordlock.test/observer/retirement",
                fixture.retirement_signer.key_id(),
                3,
            )?,
            fixture.credential.clone(),
            fixture.deletion.clone(),
            RetirementBasis::conservative(fixture.conservative.clone()),
            OBSERVATION_STARTED_AT,
            OBSERVED_AT,
        )
    }

    fn token_expectation(fixture: &Fixture) -> Result<RetirementExpectation, WitnessError> {
        RetirementExpectation::new(
            &fixture.attempt,
            fixture.credential.clone(),
            fixture.deletion.clone(),
            true,
            None,
        )
    }

    #[test]
    fn exact_effect_round_trips_and_verifies_from_durable_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let claims = effect_claims(&fixture)?;
        let claims_bytes = claims.canonical_claims_bytes()?;
        assert_eq!(decode_effect_claims_canonical(&claims_bytes)?, claims);

        let signed = sign_effect_observation(claims, &fixture.effect_signer)?;
        let envelope = signed.exact_envelope_bytes()?;
        let recovered = SignedEffectWitness::from_canonical_envelope_bytes(&envelope)?;
        assert_eq!(recovered.exact_envelope_bytes()?, envelope);
        let verified = fixture
            .registry
            .verify_effect(&recovered, &fixture.attempt, TRUSTED_NOW)?;
        assert_eq!(verified.signed().cose_sign1(), signed.cose_sign1());
        assert_eq!(
            verified.registry_commitment(),
            fixture.registry.commitment()
        );
        assert_eq!(
            verified.claims().result().resource_uid(),
            "deployment-uid-a"
        );
        Ok(())
    }

    #[test]
    fn token_review_retirement_round_trips_and_verifies() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = fixture()?;
        let claims = token_retirement_claims(&fixture)?;
        let claims_bytes = claims.canonical_claims_bytes()?;
        assert_eq!(decode_retirement_claims_canonical(&claims_bytes)?, claims);
        let signed = sign_credential_retirement(claims, &fixture.retirement_signer)?;
        let envelope = signed.exact_envelope_bytes()?;
        let recovered =
            SignedCredentialRetirementWitness::from_canonical_envelope_bytes(&envelope)?;
        assert_eq!(recovered.exact_envelope_bytes()?, envelope);
        let verified = fixture.registry.verify_retirement(
            &recovered,
            &fixture.attempt,
            &token_expectation(&fixture)?,
            TRUSTED_NOW,
        )?;
        assert!(verified.claims().basis().is_token_review_rejected());
        Ok(())
    }

    #[test]
    fn conservative_retirement_requires_exact_state_derived_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let signed = sign_credential_retirement(
            conservative_retirement_claims(&fixture)?,
            &fixture.retirement_signer,
        )?;
        let expected = RetirementExpectation::new(
            &fixture.attempt,
            fixture.credential.clone(),
            fixture.deletion.clone(),
            false,
            Some(fixture.conservative.clone()),
        )?;
        fixture
            .registry
            .verify_retirement(&signed, &fixture.attempt, &expected, TRUSTED_NOW)?;

        let wrong_bound = ConservativeRetirementBound::new(
            "eks-bound-token-v1",
            6,
            digest(41),
            950,
            100,
            50,
            5,
            DELETION_OBSERVED_AT,
        )?;
        let wrong_expected = RetirementExpectation::new(
            &fixture.attempt,
            fixture.credential.clone(),
            fixture.deletion.clone(),
            false,
            Some(wrong_bound),
        )?;
        assert!(matches!(
            fixture.registry.verify_retirement(
                &signed,
                &fixture.attempt,
                &wrong_expected,
                TRUSTED_NOW
            ),
            Err(WitnessError::ConservativePolicyMismatch)
        ));
        Ok(())
    }

    #[test]
    fn registry_commitment_binds_epoch_and_activation_id() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = fixture()?;
        let entries = fixture.registry.entries().to_vec();
        let other_epoch = registry_from_entries(entries.clone(), 12, uuid(80))?;
        let other_activation = registry_from_entries(entries, 11, uuid(81))?;
        assert_eq!(
            fixture.registry.material_root(),
            other_epoch.material_root()
        );
        assert_eq!(
            fixture.registry.material_root(),
            other_activation.material_root()
        );
        assert_ne!(fixture.registry.commitment(), other_epoch.commitment());
        assert_ne!(fixture.registry.commitment(), other_activation.commitment());
        Ok(())
    }

    #[test]
    fn payload_state_commitments_are_canonical_domain_separated_and_exact()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let attempt_commitment = fixture.attempt.commitment()?;
        assert_eq!(attempt_commitment, fixture.attempt.clone().commitment()?);
        assert!(!is_zero_digest(attempt_commitment));

        let mut other_attempt = fixture.attempt.clone();
        other_attempt.identity.fence += 1;
        assert_ne!(attempt_commitment, other_attempt.commitment()?);

        let token_request = token_review_request_commitment(&fixture.attempt, &fixture.credential)?;
        assert_eq!(token_request, fixture.token_review_request);
        assert_ne!(token_request, attempt_commitment);

        let mut credential_substitutions = Vec::new();
        let mut value = fixture.credential.clone();
        value.credential_id = format!("AUTHORIZATION_ID={}", uuid(101));
        credential_substitutions.push(value);
        let mut value = fixture.credential.clone();
        value.service_account_uid = "service-account-uid-other".to_owned();
        credential_substitutions.push(value);
        let mut value = fixture.credential.clone();
        value.audience = "https://other.kubernetes.default.svc".to_owned();
        credential_substitutions.push(value);
        let mut value = fixture.credential.clone();
        value.subject = "system:serviceaccount:workloads:other".to_owned();
        credential_substitutions.push(value);
        let mut value = fixture.credential.clone();
        value.secret_name = "accordlock-credential-other".to_owned();
        credential_substitutions.push(value);
        let mut value = fixture.credential.clone();
        value.secret_uid = "secret-uid-other".to_owned();
        credential_substitutions.push(value);
        for substituted in credential_substitutions {
            assert_ne!(
                token_request,
                token_review_request_commitment(&fixture.attempt, &substituted)?
            );
        }

        let mut token_attempt = fixture.attempt.clone();
        token_attempt.effect.token_digest = digest(102);
        let mut token_credential = fixture.credential.clone();
        token_credential.token_digest = digest(102);
        assert_ne!(
            token_request,
            token_review_request_commitment(&token_attempt, &token_credential)?
        );
        assert!(matches!(
            token_review_request_commitment(&fixture.attempt, &token_credential),
            Err(WitnessError::CredentialBindingMismatch)
        ));

        let deletion = fixture
            .deletion_facts
            .observation(&fixture.attempt, &fixture.credential)?;
        assert_eq!(deletion, fixture.deletion);
        assert_ne!(deletion.observation_commitment(), attempt_commitment);
        assert_ne!(deletion.observation_commitment(), token_request);

        let mut deletion_substitutions = Vec::new();
        let mut value = fixture.deletion_facts.clone();
        value.journal_entry_id = uuid(103);
        deletion_substitutions.push(value);
        let mut value = fixture.deletion_facts.clone();
        value.journal_request_commitment = digest(104);
        deletion_substitutions.push(value);
        let mut value = fixture.deletion_facts.clone();
        value.journal_result_commitment = digest(105);
        deletion_substitutions.push(value);
        let mut value = fixture.deletion_facts.clone();
        value.provider_evidence_commitment = digest(106);
        deletion_substitutions.push(value);
        let mut value = fixture.deletion_facts.clone();
        value.observed_at += 1;
        deletion_substitutions.push(value);
        for substituted in deletion_substitutions {
            assert_ne!(
                deletion.observation_commitment(),
                substituted
                    .observation(&fixture.attempt, &fixture.credential)?
                    .observation_commitment()
            );
        }

        let basis = RetirementBasis::token_review_rejected(
            &fixture.attempt,
            &fixture.credential,
            digest(107),
            1_125,
        )?;
        assert_eq!(basis.token_review_request_commitment(), Some(token_request));
        let expectation = RetirementExpectation::new(
            &fixture.attempt,
            fixture.credential.clone(),
            fixture.deletion.clone(),
            true,
            None,
        )?;
        assert_eq!(
            expectation.token_review_request_commitment(),
            Some(token_request)
        );
        Ok(())
    }

    #[test]
    fn payload_deletion_and_token_request_reject_free_commitments()
    -> Result<(), Box<dyn std::error::Error>> {
        for candidate in [
            SecretDeletionObservationV2::new(Uuid::nil(), digest(1), digest(2), digest(3), 1),
            SecretDeletionObservationV2::new(
                uuid(1),
                Digest32::from_bytes([0; 32]),
                digest(2),
                digest(3),
                1,
            ),
            SecretDeletionObservationV2::new(
                uuid(1),
                digest(1),
                Digest32::from_bytes([0; 32]),
                digest(3),
                1,
            ),
            SecretDeletionObservationV2::new(
                uuid(1),
                digest(1),
                digest(2),
                Digest32::from_bytes([0; 32]),
                1,
            ),
            SecretDeletionObservationV2::new(uuid(1), digest(1), digest(2), digest(3), 0),
        ] {
            assert!(candidate.is_err());
        }

        let fixture = fixture()?;
        let mut claims = token_retirement_claims(&fixture)?;
        let RetirementBasisKind::TokenReviewRejected {
            request_commitment, ..
        } = &mut claims.basis.kind
        else {
            unreachable!("fixture uses TokenReview rejection")
        };
        *request_commitment = digest(108);
        assert!(matches!(
            sign_credential_retirement(claims, &fixture.retirement_signer),
            Err(WitnessError::InvalidRecord(_))
        ));
        Ok(())
    }

    #[test]
    fn every_attempt_binding_is_substitution_resistant() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let signed = sign_effect_observation(effect_claims(&fixture)?, &fixture.effect_signer)?;
        let mut substitutions = Vec::new();

        let mut value = fixture.attempt.clone();
        value.identity.state_instance_id = uuid(101);
        substitutions.push(value);
        let mut value = fixture.attempt.clone();
        value.identity.scope = WitnessScope::new("tenant-b", "prod")?;
        substitutions.push(value);
        let mut value = fixture.attempt.clone();
        value.identity.transaction_id = uuid(102);
        substitutions.push(value);
        let mut value = fixture.attempt.clone();
        value.identity.authorization_id = uuid(103);
        substitutions.push(value);
        let mut value = fixture.attempt.clone();
        value.identity.claim_id = uuid(104);
        substitutions.push(value);
        let mut value = fixture.attempt.clone();
        value.identity.fence += 1;
        substitutions.push(value);
        let mut value = fixture.attempt.clone();
        value.identity.physical_resource.cluster_trust_domain =
            "spiffe://cluster-b.accordlock.test".to_owned();
        substitutions.push(value);
        let mut value = fixture.attempt.clone();
        value.identity.physical_resource.api_server_identity = "sha256:api-server-b".to_owned();
        substitutions.push(value);
        let mut value = fixture.attempt.clone();
        value.identity.physical_resource.cluster_identity = "cluster-b".to_owned();
        substitutions.push(value);
        let mut value = fixture.attempt.clone();
        value.identity.physical_resource.namespace = "other-workloads".to_owned();
        substitutions.push(value);
        let mut value = fixture.attempt.clone();
        value.identity.physical_resource.deployment_uid = "deployment-uid-b".to_owned();
        substitutions.push(value);
        let mut value = fixture.attempt.clone();
        value.identity.physical_resource.resource_name = "other-api".to_owned();
        substitutions.push(value);
        let mut value = fixture.attempt.clone();
        value.effect.route_commitment = digest(61);
        substitutions.push(value);
        let mut value = fixture.attempt.clone();
        value.effect.template_hash = digest(62);
        substitutions.push(value);
        let mut value = fixture.attempt.clone();
        value.effect.operation_hash = digest(63);
        substitutions.push(value);
        let mut value = fixture.attempt.clone();
        value.effect.execution_command_commitment = digest(64);
        substitutions.push(value);
        let mut value = fixture.attempt.clone();
        value.effect.final_provider_wire_commitment = digest(65);
        substitutions.push(value);
        let mut value = fixture.attempt.clone();
        value.effect.effective_rbac_commitment = digest(66);
        substitutions.push(value);
        let mut value = fixture.attempt.clone();
        value.effect.token_digest = digest(67);
        substitutions.push(value);
        let mut value = fixture.attempt.clone();
        value.admission = AdmissionLinkage::required("admission-uid-b", digest(8))?;
        substitutions.push(value);
        let mut value = fixture.attempt.clone();
        value.admission = AdmissionLinkage::required("admission-uid-a", digest(68))?;
        substitutions.push(value);

        for substituted in substitutions {
            assert!(matches!(
                fixture
                    .registry
                    .verify_effect(&signed, &substituted, TRUSTED_NOW),
                Err(WitnessError::AttemptBindingMismatch)
            ));
        }
        Ok(())
    }

    #[test]
    fn retirement_expectation_binds_every_credential_field()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let signed = sign_credential_retirement(
            token_retirement_claims(&fixture)?,
            &fixture.retirement_signer,
        )?;
        let mut substitutions = Vec::new();
        let mut value = fixture.credential.clone();
        value.token_digest = digest(70);
        substitutions.push(value);
        let mut value = fixture.credential.clone();
        value.credential_id = format!("AUTHORIZATION_ID={}", uuid(71));
        substitutions.push(value);
        let mut value = fixture.credential.clone();
        value.service_account_uid = "service-account-uid-b".to_owned();
        substitutions.push(value);
        let mut value = fixture.credential.clone();
        value.audience = "https://other.kubernetes.svc".to_owned();
        substitutions.push(value);
        let mut value = fixture.credential.clone();
        value.subject = "system:serviceaccount:workloads:other".to_owned();
        substitutions.push(value);
        let mut value = fixture.credential.clone();
        value.secret_name = "accordlock-credential-b".to_owned();
        substitutions.push(value);
        let mut value = fixture.credential.clone();
        value.secret_uid = "secret-uid-b".to_owned();
        substitutions.push(value);

        for substituted in substitutions {
            let mut expectation_attempt = fixture.attempt.clone();
            expectation_attempt.effect.token_digest = substituted.token_digest;
            let expected = RetirementExpectation::new(
                &expectation_attempt,
                substituted,
                fixture.deletion.clone(),
                true,
                None,
            )?;
            assert!(matches!(
                fixture.registry.verify_retirement(
                    &signed,
                    &fixture.attempt,
                    &expected,
                    TRUSTED_NOW
                ),
                Err(WitnessError::CredentialBindingMismatch)
            ));
        }
        Ok(())
    }

    #[test]
    fn retirement_expectation_binds_deletion_and_token_review_request()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let signed = sign_credential_retirement(
            token_retirement_claims(&fixture)?,
            &fixture.retirement_signer,
        )?;
        let other_deletion = SecretDeletionObservation::new(digest(44), DELETION_OBSERVED_AT)?;
        let expected_other_deletion = RetirementExpectation::new(
            &fixture.attempt,
            fixture.credential.clone(),
            other_deletion,
            true,
            None,
        )?;
        assert!(matches!(
            fixture.registry.verify_retirement(
                &signed,
                &fixture.attempt,
                &expected_other_deletion,
                TRUSTED_NOW
            ),
            Err(WitnessError::DeletionBindingMismatch)
        ));

        let mut other_request_attempt = fixture.attempt.clone();
        other_request_attempt
            .identity
            .physical_resource
            .api_server_identity = "sha256:api-server-other".to_owned();
        let expected_other_request = RetirementExpectation::new(
            &other_request_attempt,
            fixture.credential.clone(),
            fixture.deletion.clone(),
            true,
            None,
        )?;
        assert!(matches!(
            fixture.registry.verify_retirement(
                &signed,
                &fixture.attempt,
                &expected_other_request,
                TRUSTED_NOW
            ),
            Err(WitnessError::TokenReviewBindingMismatch)
        ));
        Ok(())
    }

    #[test]
    fn cross_domain_wrong_key_and_role_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let claims = effect_claims(&fixture)?;
        let wrong_domain_cose = sign_cose(
            &claims.canonical_claims_bytes()?,
            CREDENTIAL_RETIREMENT_WITNESS_DOMAIN,
            &fixture.effect_signer,
        )?;
        let wrong_domain = SignedEffectWitness::from_untrusted_parts(
            fixture.effect_signer.key_id(),
            claims.clone(),
            wrong_domain_cose,
        )?;
        assert!(matches!(
            fixture
                .registry
                .verify_effect(&wrong_domain, &fixture.attempt, TRUSTED_NOW),
            Err(WitnessError::Crypto(_))
        ));

        let impostor = SigningIdentity::from_seed(fixture.effect_signer.key_id(), [9; 32]);
        let wrong_key_cose = sign_cose(
            &claims.canonical_claims_bytes()?,
            EXACT_EFFECT_WITNESS_DOMAIN,
            &impostor,
        )?;
        let wrong_key = SignedEffectWitness::from_untrusted_parts(
            fixture.effect_signer.key_id(),
            claims,
            wrong_key_cose,
        )?;
        assert!(matches!(
            fixture
                .registry
                .verify_effect(&wrong_key, &fixture.attempt, TRUSTED_NOW),
            Err(WitnessError::Crypto(_))
        ));

        let wrong_role_claims = EffectObservationClaims::new(
            uuid(13),
            fixture.attempt.clone(),
            WitnessIssuer::new(
                "spiffe://accordlock.test/observer/retirement",
                fixture.retirement_signer.key_id(),
                3,
            )?,
            effect_claims(&fixture)?.result().clone(),
            1_100,
            OBSERVED_AT,
        )?;
        let wrong_role = sign_effect_observation(wrong_role_claims, &fixture.retirement_signer)?;
        assert!(matches!(
            fixture
                .registry
                .verify_effect(&wrong_role, &fixture.attempt, TRUSTED_NOW),
            Err(WitnessError::VerifierRoleMismatch)
        ));
        Ok(())
    }

    #[test]
    fn signed_claim_substitution_and_noncanonical_cose_are_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let signed = sign_effect_observation(effect_claims(&fixture)?, &fixture.effect_signer)?;
        let mut substituted = signed.clone();
        substituted.claims.result.resource_version = "4815162343".to_owned();
        assert!(matches!(
            fixture
                .registry
                .verify_effect(&substituted, &fixture.attempt, TRUSTED_NOW),
            Err(WitnessError::PayloadMismatch)
        ));

        let mut malformed_cose = signed.cose_sign1().to_vec();
        malformed_cose.push(0);
        let malformed = SignedEffectWitness::from_untrusted_parts(
            signed.key_id(),
            signed.claims().clone(),
            malformed_cose,
        )?;
        assert!(matches!(
            fixture
                .registry
                .verify_effect(&malformed, &fixture.attempt, TRUSTED_NOW),
            Err(WitnessError::Crypto(_))
        ));
        Ok(())
    }

    #[test]
    fn wire_decoder_rejects_noncanonical_trailing_wrong_arity_and_wrong_role()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let signed = sign_effect_observation(effect_claims(&fixture)?, &fixture.effect_signer)?;
        let envelope = signed.exact_envelope_bytes()?;

        let mut trailing = envelope.clone();
        trailing.push(0);
        assert!(SignedEffectWitness::from_canonical_envelope_bytes(&trailing).is_err());

        let mut wrong_arity = envelope.clone();
        wrong_arity[0] = 0x84;
        assert!(SignedEffectWitness::from_canonical_envelope_bytes(&wrong_arity).is_err());

        let mut nonminimal_array = vec![0x98, 0x05];
        nonminimal_array.extend_from_slice(&envelope[1..]);
        assert!(matches!(
            SignedEffectWitness::from_canonical_envelope_bytes(&nonminimal_array),
            Err(WitnessError::NonCanonicalWire)
        ));

        let duplicate_map_keys = [0xa2, 0x00, 0x01, 0x00, 0x01];
        assert!(SignedEffectWitness::from_canonical_envelope_bytes(&duplicate_map_keys).is_err());

        let claims_bytes = signed.claims().canonical_claims_bytes()?;
        let wrong_role = canonical_signed_envelope(
            WitnessRole::CredentialRetirement,
            signed.key_id(),
            &claims_bytes,
            signed.cose_sign1(),
        )?;
        assert!(matches!(
            SignedEffectWitness::from_canonical_envelope_bytes(&wrong_role),
            Err(WitnessError::VerifierRoleMismatch)
        ));

        let oversized = vec![0_u8; MAX_TERMINAL_WITNESS_ENVELOPE_BYTES + 1];
        assert!(SignedEffectWitness::from_canonical_envelope_bytes(&oversized).is_err());
        Ok(())
    }

    #[test]
    fn claims_decoder_rejects_trailing_nonminimal_wrong_arity_and_schema()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let canonical = effect_claims(&fixture)?.canonical_claims_bytes()?;
        let mut trailing = canonical.clone();
        trailing.push(0);
        assert!(decode_effect_claims_canonical(&trailing).is_err());

        let mut nonminimal_array = vec![0x98, 0x08];
        nonminimal_array.extend_from_slice(&canonical[1..]);
        assert!(matches!(
            decode_effect_claims_canonical(&nonminimal_array),
            Err(WitnessError::NonCanonicalWire)
        ));

        let mut wrong_arity = canonical.clone();
        wrong_arity[0] = 0x87;
        assert!(decode_effect_claims_canonical(&wrong_arity).is_err());

        let mut wrong_schema = canonical;
        assert_eq!(wrong_schema[1], 1);
        wrong_schema[1] = 2;
        assert!(decode_effect_claims_canonical(&wrong_schema).is_err());
        Ok(())
    }

    #[test]
    fn registry_rejects_order_aliases_weak_keys_missing_role_and_wrong_root()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let effect = fixture.registry.entries()[0].clone();
        let retirement = fixture.registry.entries()[1].clone();
        assert!(matches!(
            ActivatedWitnessRegistry::compute_material_root(&[retirement.clone(), effect.clone()]),
            Err(WitnessError::NonCanonicalRegistry)
        ));
        assert!(matches!(
            ActivatedWitnessRegistry::compute_material_root(std::slice::from_ref(&effect)),
            Err(WitnessError::MissingVerifierRole)
        ));

        let mut aliased_key = retirement.clone();
        aliased_key.key_id = effect.key_id.clone();
        aliased_key.public_key = effect.public_key;
        assert!(matches!(
            ActivatedWitnessRegistry::compute_material_root(&[effect.clone(), aliased_key]),
            Err(WitnessError::RegistryIdentityAlias)
        ));

        let mut aliased_identity = retirement;
        aliased_identity.observer_identity = effect.observer_identity.clone();
        assert!(matches!(
            ActivatedWitnessRegistry::compute_material_root(&[effect.clone(), aliased_identity]),
            Err(WitnessError::RegistryIdentityAlias)
        ));

        let mut weak = [0_u8; 32];
        weak[0] = 1;
        assert!(matches!(
            RegisteredWitnessVerifier::new(
                WitnessScope::new("tenant-a", "prod")?,
                "cluster-a",
                WitnessRole::ExactEffect,
                "observer-weak",
                "weak-key",
                weak,
                1,
                10,
                9,
                1,
                digest(90),
                WitnessVerifierStatus::Active
            ),
            Err(WitnessError::Crypto(CryptoError::InvalidPublicKey))
        ));

        let entries = fixture.registry.entries().to_vec();
        let wrong_authority = WitnessRegistryAuthority::new(digest(99), 11, uuid(80))?;
        assert!(matches!(
            ActivatedWitnessRegistry::new(wrong_authority, entries),
            Err(WitnessError::RegistryCommitmentMismatch)
        ));
        Ok(())
    }

    #[test]
    fn registry_scope_identity_authority_status_cutoff_and_clock_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let base = effect_claims(&fixture)?;

        let mut wrong_scope = base.clone();
        wrong_scope.attempt.identity.scope = WitnessScope::new("tenant-b", "prod")?;
        let signed = sign_effect_observation(wrong_scope, &fixture.effect_signer)?;
        assert!(matches!(
            fixture
                .registry
                .verify_effect(&signed, signed.claims().attempt(), TRUSTED_NOW),
            Err(WitnessError::VerifierBindingMismatch)
        ));

        let mut wrong_identity = base.clone();
        wrong_identity.issuer.observer_identity = "spiffe://other/effect".to_owned();
        let signed = sign_effect_observation(wrong_identity, &fixture.effect_signer)?;
        assert!(matches!(
            fixture
                .registry
                .verify_effect(&signed, signed.claims().attempt(), TRUSTED_NOW),
            Err(WitnessError::VerifierBindingMismatch)
        ));

        let mut wrong_authority = base.clone();
        wrong_authority.issuer.authority_version = 4;
        let signed = sign_effect_observation(wrong_authority, &fixture.effect_signer)?;
        assert!(matches!(
            fixture
                .registry
                .verify_effect(&signed, signed.claims().attempt(), TRUSTED_NOW),
            Err(WitnessError::VerifierBindingMismatch)
        ));

        let signed = sign_effect_observation(base.clone(), &fixture.effect_signer)?;
        assert!(matches!(
            fixture
                .registry
                .verify_effect(&signed, &fixture.attempt, OBSERVED_AT - 1),
            Err(WitnessError::InvalidObservationTime)
        ));

        let mut revoked_entries = fixture.registry.entries().to_vec();
        revoked_entries[0].status = WitnessVerifierStatus::Revoked;
        let revoked = registry_from_entries(revoked_entries, 12, uuid(82))?;
        assert!(matches!(
            revoked.verify_effect(&signed, &fixture.attempt, TRUSTED_NOW),
            Err(WitnessError::VerifierInactive)
        ));

        let mut cutoff_entries = fixture.registry.entries().to_vec();
        cutoff_entries[0].accepted_through = OBSERVED_AT - 1;
        let cutoff = registry_from_entries(cutoff_entries, 12, uuid(83))?;
        assert!(matches!(
            cutoff.verify_effect(&signed, &fixture.attempt, TRUSTED_NOW),
            Err(WitnessError::VerifierInactive)
        ));
        Ok(())
    }

    #[test]
    fn exact_effect_resource_and_time_invariants_are_enforced()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let good_result = effect_claims(&fixture)?.result().clone();
        let wrong_resource = EffectObservationResult::new(
            ExactExecutionOutcome::KubernetesDeploymentUpdatedV1,
            digest(20),
            digest(21),
            digest(22),
            "deployment-uid-b",
            "1",
            "cursor",
        )?;
        assert!(
            EffectObservationClaims::new(
                uuid(20),
                fixture.attempt.clone(),
                effect_claims(&fixture)?.issuer().clone(),
                wrong_resource,
                1_100,
                1_200
            )
            .is_err()
        );
        assert!(
            EffectObservationClaims::new(
                uuid(20),
                fixture.attempt.clone(),
                effect_claims(&fixture)?.issuer().clone(),
                good_result.clone(),
                ATTEMPT_STARTED_AT - 1,
                1_200
            )
            .is_err()
        );
        let issuer = effect_claims(&fixture)?.issuer().clone();
        assert!(
            EffectObservationClaims::new(
                uuid(20),
                fixture.attempt,
                issuer,
                good_result,
                1_200,
                1_199
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn retirement_ordering_and_safe_after_are_enforced() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let issuer = token_retirement_claims(&fixture)?.issuer().clone();
        let early_rejection = RetirementBasis::token_review_rejected(
            &fixture.attempt,
            &fixture.credential,
            digest(43),
            DELETION_OBSERVED_AT - 1,
        )?;
        assert!(
            CredentialRetirementClaims::new(
                uuid(30),
                fixture.attempt.clone(),
                issuer.clone(),
                fixture.credential.clone(),
                fixture.deletion.clone(),
                early_rejection,
                OBSERVATION_STARTED_AT,
                OBSERVED_AT
            )
            .is_err()
        );

        let late_bound = ConservativeRetirementBound::new(
            "policy-late",
            1,
            digest(50),
            950,
            250,
            250,
            5,
            DELETION_OBSERVED_AT,
        )?;
        assert!(
            CredentialRetirementClaims::new(
                uuid(31),
                fixture.attempt,
                issuer,
                fixture.credential,
                fixture.deletion,
                RetirementBasis::conservative(late_bound),
                OBSERVATION_STARTED_AT,
                OBSERVED_AT
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn nil_zero_malformed_and_bound_inputs_are_rejected() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = fixture()?;
        assert!(
            AttemptIdentity::new(
                Uuid::nil(),
                fixture.attempt.identity.scope.clone(),
                uuid(2),
                uuid(3),
                uuid(4),
                1,
                fixture.attempt.identity.physical_resource.clone(),
                ATTEMPT_STARTED_AT
            )
            .is_err()
        );
        assert!(
            EffectBindingCommitments::new(
                Digest32::from_bytes([0; 32]),
                digest(2),
                digest(3),
                digest(4),
                digest(5),
                digest(6),
                digest(7)
            )
            .is_err()
        );
        assert!(
            CredentialIdentity::new(
                digest(7),
                format!(
                    "AUTHORIZATION_ID={}",
                    uuid(0xabcd_efab_cdef_abcd_efab_cdef_abcd_efab)
                        .to_string()
                        .to_uppercase()
                ),
                "service-account-uid-a",
                "audience",
                "subject",
                "secret",
                "secret-uid"
            )
            .is_err()
        );
        assert!(WitnessRegistryAuthority::new(digest(1), 0, uuid(1)).is_err());
        assert!(WitnessRegistryAuthority::new(digest(1), 1, Uuid::nil()).is_err());
        assert!(
            ConservativeRetirementBound::new(
                "policy",
                1,
                digest(1),
                1,
                MAX_SERVER_TOKEN_LIFETIME_HARD_S + 1,
                1,
                0,
                2
            )
            .is_err()
        );
        assert!(
            SignedEffectWitness::from_untrusted_parts(
                fixture.effect_signer.key_id(),
                effect_claims(&fixture)?,
                Vec::new()
            )
            .is_err()
        );
        assert!(
            SignedCredentialRetirementWitness::from_untrusted_parts(
                fixture.retirement_signer.key_id(),
                token_retirement_claims(&fixture)?,
                Vec::new()
            )
            .is_err()
        );
        Ok(())
    }
}
