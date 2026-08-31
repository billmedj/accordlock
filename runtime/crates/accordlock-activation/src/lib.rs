#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Synthetic cryptographic verification of the three live EKS deployment
//! boundaries that remain outside the production enforcement path.
//!
//! This crate deliberately contains no collector, state adapter, distributed
//! replay protocol, or enforcement integration. Its opaque success marker is
//! evidence of verification under the registry, clock, and expected bindings
//! supplied to one call. It is not proof that committed external artifacts are
//! truthful.

use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
    fmt,
    sync::Mutex,
};

use accordlock_eks_profile::{EksBrokerManagementBindings, EksRouteProfile};
use accordlock_protocol::{
    AuthorityVector, CanonicalEncode, CoseVerifier, Digest32, SigningIdentity, sign_cose,
    verify_cose,
};
use minicbor::{Encoder, encode::Error as EncodeError};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

/// Canonical schema version of live deployment-boundary claims.
pub const LIVE_BOUNDARY_CLAIMS_SCHEMA_VERSION: u16 = 1;
/// Longest accepted claims lifetime, in seconds.
pub const MAX_LIVE_BOUNDARY_LIFETIME_SECONDS: i64 = 300;
/// Maximum number of signer registrations in one activated registry.
pub const MAX_LIVE_BOUNDARY_REGISTRY_ENTRIES: usize = 64;
/// Maximum positive raw-artifact count committed by one bundle binding.
pub const MAX_LIVE_BOUNDARY_RAW_ARTIFACTS: u32 = 1_024;
/// Maximum UTF-8 byte length of a tenant or environment scope component.
pub const MAX_ACTIVATION_SCOPE_COMPONENT_BYTES: usize = 128;
/// Maximum UTF-8 byte length of a collector or operator identity.
pub const MAX_LIVE_BOUNDARY_IDENTITY_BYTES: usize = 256;
/// Maximum UTF-8 byte length of a registry key identifier.
pub const MAX_LIVE_BOUNDARY_KEY_ID_BYTES: usize = 256;
/// Maximum canonical claim size accepted before either signature is checked.
pub const MAX_LIVE_BOUNDARY_CLAIMS_BYTES: usize = 65_536;
/// Maximum encoded size accepted for either COSE Sign1 envelope.
pub const MAX_LIVE_BOUNDARY_COSE_BYTES: usize = 131_072;

/// Purpose-separated external AAD for collector attestations.
pub const COLLECTOR_ATTESTATION_DOMAIN: &str =
    "accordlock:v1:live-deployment-boundary-collector-attestation";
/// Purpose-separated external AAD for independent operator approval.
pub const OPERATOR_APPROVAL_DOMAIN: &str =
    "accordlock:v1:live-deployment-boundary-operator-approval";

const ACTIVATION_CONTEXT_DOMAIN: &[u8] = b"accordlock:v1:live-activation-context\0";
const MANAGEMENT_BINDINGS_DOMAIN: &[u8] = b"accordlock:v1:live-management-bindings\0";
const CLAIMS_DOMAIN: &str = "accordlock:v1:live-deployment-boundary-claims";
const REGISTRY_MATERIAL_DOMAIN: &[u8] = b"accordlock:v1:live-boundary-registry-material\0";
const REGISTRY_ACTIVATION_DOMAIN: &[u8] = b"accordlock:v1:live-boundary-registry-activation\0";
const MAX_CLUSTER_IDENTITY_BYTES: usize = 512;
const ZERO: Digest32 = Digest32::from_bytes([0; 32]);

type CanonicalEncoder = Encoder<Vec<u8>>;
type CanonicalEncodeError = EncodeError<Infallible>;

/// Coarse fail-closed errors at the synthetic activation-attestation boundary.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ActivationError {
    /// Tenant or environment text is empty, aliased, or outside its bound.
    #[error("activation scope is invalid")]
    InvalidScope,
    /// A required cryptographic commitment is the all-zero sentinel or aliased.
    #[error("a required commitment is invalid")]
    InvalidCommitment,
    /// The current authority vector contains an unusable domain state.
    #[error("authority vector is invalid")]
    InvalidAuthority,
    /// The three named live-proof commitments are incomplete or aliased.
    #[error("live proof commitments are invalid")]
    InvalidProofSet,
    /// Bundle or raw-artifact binding is invalid or outside its bound.
    #[error("evidence bundle binding is invalid")]
    InvalidBundleBinding,
    /// Signer identity or key reference is malformed or reused.
    #[error("signer reference is invalid")]
    InvalidSignerReference,
    /// Claims are malformed, noncanonical, or temporally ill-shaped.
    #[error("live deployment-boundary claims are invalid")]
    InvalidClaims,
    /// Canonical claims exceed the activation profile size limit.
    #[error("canonical claims exceed the profile size limit")]
    ClaimsTooLarge,
    /// One COSE envelope exceeds the activation profile size limit.
    #[error("COSE envelope exceeds the profile size limit")]
    EnvelopeTooLarge,
    /// Registry material is malformed, ambiguous, noncanonical, or incomplete.
    #[error("live-boundary signer registry is invalid")]
    InvalidRegistry,
    /// Canonical registry material does not match its activated root.
    #[error("live-boundary signer registry root does not match")]
    RegistryRootMismatch,
    /// Signed registry activation does not equal the supplied current registry.
    #[error("attestation is not bound to the current signer registry")]
    RegistryMismatch,
    /// Signed activation context does not equal the supplied current context.
    #[error("attestation activation context is not current")]
    ActivationContextMismatch,
    /// Signed bundle commitments do not equal the independently expected bundle.
    #[error("attestation bundle binding is not the expected binding")]
    BundleBindingMismatch,
    /// Signed proof roots do not equal the independently expected proof tuple.
    #[error("attestation proof commitments are not the expected commitments")]
    ProofCommitmentMismatch,
    /// A referenced signer is absent from the current registry.
    #[error("attestation signer is not registered")]
    SignerNotFound,
    /// A referenced key is registered for the wrong signature purpose.
    #[error("attestation signer has the wrong registry role")]
    SignerRoleMismatch,
    /// Registered scope, cluster, identity, or key material does not bind exactly.
    #[error("attestation signer binding does not match")]
    SignerBindingMismatch,
    /// COSE profile, protected key identifier, purpose, or signature is invalid.
    #[error("attestation signature is invalid")]
    SignatureInvalid,
    /// Verified embedded COSE payload differs from the canonical claims.
    #[error("signed payload does not equal canonical claims")]
    SignaturePayloadMismatch,
    /// Trusted current time is before the Unix epoch.
    #[error("trusted current time is invalid")]
    InvalidTrustedTime,
    /// The attestation claims an observation later than trusted current time.
    #[error("attestation observation is in the future")]
    ObservationInFuture,
    /// The attestation is expired at trusted current time.
    #[error("attestation is expired")]
    AttestationExpired,
    /// A registry signer is revoked, disabled, not yet active, or expired.
    #[error("attestation signer is not active for the complete verification window")]
    SignerInactive,
    /// This evidence identifier was already consumed in this replay domain.
    #[error("evidence identifier was already consumed")]
    ReplayDetected,
    /// The process-local replay guard could not safely read or record state.
    #[error("process-local replay guard is unavailable")]
    ReplayGuardUnavailable,
    /// Deterministic encoding failed.
    #[error("canonical activation encoding failed")]
    CanonicalEncoding,
}

/// Exact tenant/environment partition copied into an activation attestation.
///
/// Construction rejects aliases rather than trimming, lowercasing, or otherwise
/// normalizing either component. A future state adapter must copy its stored
/// tenant and environment bytes exactly and handle rejection fail closed.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActivationScope {
    tenant: String,
    environment: String,
}

impl ActivationScope {
    /// Creates one bounded, exact activation scope.
    ///
    /// # Errors
    ///
    /// Returns [`ActivationError::InvalidScope`] for empty, non-ASCII,
    /// whitespace-containing, control-containing, or oversized components.
    pub fn new(
        tenant: impl Into<String>,
        environment: impl Into<String>,
    ) -> Result<Self, ActivationError> {
        let tenant = tenant.into();
        let environment = environment.into();
        if !valid_security_text(&tenant, MAX_ACTIVATION_SCOPE_COMPONENT_BYTES)
            || !valid_security_text(&environment, MAX_ACTIVATION_SCOPE_COMPONENT_BYTES)
        {
            return Err(ActivationError::InvalidScope);
        }
        Ok(Self {
            tenant,
            environment,
        })
    }

    /// Returns the exact tenant bytes interpreted as UTF-8.
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// Returns the exact environment bytes interpreted as UTF-8.
    #[must_use]
    pub fn environment(&self) -> &str {
        &self.environment
    }
}

impl fmt::Debug for ActivationScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActivationScope")
            .field("tenant", &"[REDACTED]")
            .field("environment", &"[REDACTED]")
            .finish()
    }
}

/// Closed, non-boolean commitments for the three remaining live boundaries.
#[derive(Clone, PartialEq, Eq)]
pub struct LiveProofCommitments {
    management_rbac: Digest32,
    authenticated_webhook_caller_boundary: Digest32,
    kubernetes_api_audience: Digest32,
}

impl LiveProofCommitments {
    /// Creates the exact three-proof tuple.
    ///
    /// No boolean validator result is accepted. Each argument must be a
    /// non-zero, purpose-specific payload commitment, and all three must be
    /// different.
    ///
    /// # Errors
    ///
    /// Returns [`ActivationError::InvalidProofSet`] for zero or reused roots.
    pub fn new(
        management_rbac: Digest32,
        authenticated_webhook_caller_boundary: Digest32,
        kubernetes_api_audience: Digest32,
    ) -> Result<Self, ActivationError> {
        let roots = [
            management_rbac,
            authenticated_webhook_caller_boundary,
            kubernetes_api_audience,
        ];
        if roots.contains(&ZERO)
            || roots[0] == roots[1]
            || roots[0] == roots[2]
            || roots[1] == roots[2]
        {
            return Err(ActivationError::InvalidProofSet);
        }
        Ok(Self {
            management_rbac,
            authenticated_webhook_caller_boundary,
            kubernetes_api_audience,
        })
    }

    /// Payload commitment for the live management-RBAC closure proof.
    #[must_use]
    pub const fn management_rbac(&self) -> Digest32 {
        self.management_rbac
    }

    /// Payload commitment for the authenticated webhook-caller boundary.
    #[must_use]
    pub const fn authenticated_webhook_caller_boundary(&self) -> Digest32 {
        self.authenticated_webhook_caller_boundary
    }

    /// Payload commitment for the live Kubernetes API audience exercise.
    #[must_use]
    pub const fn kubernetes_api_audience(&self) -> Digest32 {
        self.kubernetes_api_audience
    }
}

impl fmt::Debug for LiveProofCommitments {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LiveProofCommitments([COMMITTED])")
    }
}

/// Independently expected commitments to bundle behavior and raw artifacts.
#[derive(Clone, PartialEq, Eq)]
pub struct LiveEvidenceBundleBinding {
    canonical_payload_commitment: Digest32,
    raw_artifact_set_commitment: Digest32,
    raw_artifact_count: u32,
}

impl LiveEvidenceBundleBinding {
    /// Creates one bounded exact bundle binding.
    ///
    /// # Errors
    ///
    /// Rejects zero or aliased commitments and artifact counts outside
    /// `1..=MAX_LIVE_BOUNDARY_RAW_ARTIFACTS`.
    pub fn new(
        canonical_payload_commitment: Digest32,
        raw_artifact_set_commitment: Digest32,
        raw_artifact_count: u32,
    ) -> Result<Self, ActivationError> {
        if canonical_payload_commitment == ZERO
            || raw_artifact_set_commitment == ZERO
            || canonical_payload_commitment == raw_artifact_set_commitment
            || raw_artifact_count == 0
            || raw_artifact_count > MAX_LIVE_BOUNDARY_RAW_ARTIFACTS
        {
            return Err(ActivationError::InvalidBundleBinding);
        }
        Ok(Self {
            canonical_payload_commitment,
            raw_artifact_set_commitment,
            raw_artifact_count,
        })
    }

    /// Commitment to the complete structurally validated evidence bundle.
    #[must_use]
    pub const fn canonical_payload_commitment(&self) -> Digest32 {
        self.canonical_payload_commitment
    }

    /// Commitment to the complete exact raw-artifact set.
    #[must_use]
    pub const fn raw_artifact_set_commitment(&self) -> Digest32 {
        self.raw_artifact_set_commitment
    }

    /// Positive bounded number of artifacts included in the raw set.
    #[must_use]
    pub const fn raw_artifact_count(&self) -> u32 {
        self.raw_artifact_count
    }
}

impl fmt::Debug for LiveEvidenceBundleBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LiveEvidenceBundleBinding")
            .field("commitments", &"[COMMITTED]")
            .field("raw_artifact_count", &self.raw_artifact_count)
            .finish_non_exhaustive()
    }
}

/// Exact identity and key identifier named by one signature slot.
#[derive(Clone, PartialEq, Eq)]
pub struct LiveBoundarySignerReference {
    identity: String,
    key_id: String,
}

impl LiveBoundarySignerReference {
    /// Creates one bounded exact signer reference without normalization.
    ///
    /// # Errors
    ///
    /// Returns [`ActivationError::InvalidSignerReference`] for malformed text.
    pub fn new(
        identity: impl Into<String>,
        key_id: impl Into<String>,
    ) -> Result<Self, ActivationError> {
        let identity = identity.into();
        let key_id = key_id.into();
        if !valid_security_text(&identity, MAX_LIVE_BOUNDARY_IDENTITY_BYTES)
            || !valid_security_text(&key_id, MAX_LIVE_BOUNDARY_KEY_ID_BYTES)
        {
            return Err(ActivationError::InvalidSignerReference);
        }
        Ok(Self { identity, key_id })
    }

    /// Exact registered component identity.
    #[must_use]
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// Exact protected COSE key identifier.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

impl fmt::Debug for LiveBoundarySignerReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LiveBoundarySignerReference([REDACTED])")
    }
}

/// Complete activation context committed by both signatures.
#[derive(Clone, PartialEq, Eq)]
pub struct LiveActivationContext {
    scope: ActivationScope,
    route_commitment: Digest32,
    management_bindings_commitment: Digest32,
    release_commitment: Digest32,
    deployment_activation_id: Uuid,
    authority: AuthorityVector,
    commitment: Digest32,
}

impl LiveActivationContext {
    /// Constructs and commits the complete current activation context.
    ///
    /// The EKS profile's own versioned commitment covers every route field.
    /// The management commitment covers the three ordered subject/RBAC pairs.
    /// The complete authority vector preserves every root, epoch, and
    /// activation identifier without a dependency on durable state.
    ///
    /// # Errors
    ///
    /// Rejects zero release/route roots, a nil deployment activation, an
    /// invalid authority domain, or canonical encoding failure.
    pub fn new(
        scope: ActivationScope,
        route: &EksRouteProfile,
        management_bindings: &EksBrokerManagementBindings,
        release_commitment: Digest32,
        deployment_activation_id: Uuid,
        authority: AuthorityVector,
    ) -> Result<Self, ActivationError> {
        let route_commitment = Digest32::from_bytes(*route.commitment().as_bytes());
        if route_commitment == ZERO
            || release_commitment == ZERO
            || deployment_activation_id.is_nil()
        {
            return Err(ActivationError::InvalidCommitment);
        }
        validate_authority(&authority)?;
        let management_bindings_commitment = management_bindings_commitment(management_bindings)?;
        let mut context = Self {
            scope,
            route_commitment,
            management_bindings_commitment,
            release_commitment,
            deployment_activation_id,
            authority,
            commitment: ZERO,
        };
        context.commitment = Digest32::sha256(&canonical_activation_context(&context)?);
        Ok(context)
    }

    /// Exact tenant/environment scope.
    #[must_use]
    pub const fn scope(&self) -> &ActivationScope {
        &self.scope
    }

    /// Existing versioned commitment to every EKS route field.
    #[must_use]
    pub const fn route_commitment(&self) -> Digest32 {
        self.route_commitment
    }

    /// Commitment to all three configured management identity/RBAC bindings.
    #[must_use]
    pub const fn management_bindings_commitment(&self) -> Digest32 {
        self.management_bindings_commitment
    }

    /// Exact release commitment.
    #[must_use]
    pub const fn release_commitment(&self) -> Digest32 {
        self.release_commitment
    }

    /// Unique identifier of the deployment activation being approved.
    #[must_use]
    pub const fn deployment_activation_id(&self) -> Uuid {
        self.deployment_activation_id
    }

    /// Complete authority vector included in the signed context.
    #[must_use]
    pub const fn authority(&self) -> &AuthorityVector {
        &self.authority
    }

    /// Domain-separated commitment to the complete activation context.
    #[must_use]
    pub const fn commitment(&self) -> Digest32 {
        self.commitment
    }
}

impl fmt::Debug for LiveActivationContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LiveActivationContext")
            .field("scope", &"[REDACTED]")
            .field("route", &"[COMMITTED]")
            .field("management_bindings", &"[COMMITTED]")
            .field("release", &"[COMMITTED]")
            .field("authority", &"[COMMITTED]")
            .field("deployment_activation_id", &"[REDACTED]")
            .finish()
    }
}

/// Purpose assigned to one registry key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LiveBoundarySignerRole {
    /// Authenticated component that attests collected bundle and raw artifacts.
    Collector,
    /// Distinct human/operator authority approving the same exact claims.
    Operator,
}

impl LiveBoundarySignerRole {
    const fn code(self) -> u8 {
        match self {
            Self::Collector => 0,
            Self::Operator => 1,
        }
    }
}

/// Current administrative state of one live-boundary verification key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LiveBoundarySignerStatus {
    /// Key may verify claims within its exact time and registry bindings.
    Active,
    /// Key is administratively disabled.
    Disabled,
    /// Key is permanently revoked.
    Revoked,
}

impl LiveBoundarySignerStatus {
    const fn code(self) -> u8 {
        match self {
            Self::Active => 0,
            Self::Disabled => 1,
            Self::Revoked => 2,
        }
    }
}

/// One bounded, immutable, purpose-scoped registry entry.
#[derive(Clone, PartialEq, Eq)]
pub struct RegisteredLiveBoundarySigner {
    scope: ActivationScope,
    cluster_identity: String,
    role: LiveBoundarySignerRole,
    identity: String,
    key_id: String,
    public_key: [u8; 32],
    not_before: i64,
    valid_until: i64,
    status: LiveBoundarySignerStatus,
}

impl RegisteredLiveBoundarySigner {
    /// Creates one exact collector or operator verifier registration.
    ///
    /// # Errors
    ///
    /// Rejects malformed or oversized identity material, invalid lifetimes,
    /// and invalid or weak Ed25519 public keys.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: ActivationScope,
        cluster_identity: impl Into<String>,
        role: LiveBoundarySignerRole,
        identity: impl Into<String>,
        key_id: impl Into<String>,
        public_key: [u8; 32],
        not_before: i64,
        valid_until: i64,
        status: LiveBoundarySignerStatus,
    ) -> Result<Self, ActivationError> {
        let cluster_identity = cluster_identity.into();
        let identity = identity.into();
        let key_id = key_id.into();
        if !valid_security_text(&cluster_identity, MAX_CLUSTER_IDENTITY_BYTES)
            || !valid_security_text(&identity, MAX_LIVE_BOUNDARY_IDENTITY_BYTES)
            || !valid_security_text(&key_id, MAX_LIVE_BOUNDARY_KEY_ID_BYTES)
            || not_before < 0
            || valid_until <= not_before
            || CoseVerifier::from_public_key(key_id.clone(), public_key).is_err()
        {
            return Err(ActivationError::InvalidRegistry);
        }
        Ok(Self {
            scope,
            cluster_identity,
            role,
            identity,
            key_id,
            public_key,
            not_before,
            valid_until,
            status,
        })
    }

    /// Exact scope for which this signer is registered.
    #[must_use]
    pub const fn scope(&self) -> &ActivationScope {
        &self.scope
    }

    /// Exact EKS cluster identity for which this signer is registered.
    #[must_use]
    pub fn cluster_identity(&self) -> &str {
        &self.cluster_identity
    }

    /// Purpose assigned to this key.
    #[must_use]
    pub const fn role(&self) -> LiveBoundarySignerRole {
        self.role
    }

    /// Exact collector or operator identity.
    #[must_use]
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// Exact protected COSE key identifier.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Exact Ed25519 public key bytes.
    #[must_use]
    pub const fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// Inclusive first second at which the key may verify an observation.
    #[must_use]
    pub const fn not_before(&self) -> i64 {
        self.not_before
    }

    /// Exclusive last second of key validity.
    #[must_use]
    pub const fn valid_until(&self) -> i64 {
        self.valid_until
    }

    /// Current administrative key status.
    #[must_use]
    pub const fn status(&self) -> LiveBoundarySignerStatus {
        self.status
    }

    fn sort_key(&self) -> (LiveBoundarySignerRole, &str, &str) {
        (self.role, &self.identity, &self.key_id)
    }
}

impl fmt::Debug for RegisteredLiveBoundarySigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegisteredLiveBoundarySigner")
            .field("scope", &"[REDACTED]")
            .field("cluster_identity", &"[REDACTED]")
            .field("role", &self.role)
            .field("identity", &"[REDACTED]")
            .field("key", &"[REDACTED]")
            .field("validity", &"[REDACTED]")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

/// Activation coordinates for one exact canonical signer-registry root.
#[derive(Clone, PartialEq, Eq)]
pub struct LiveBoundaryRegistryAuthority {
    material_root: Digest32,
    epoch: u64,
    activation_id: Uuid,
}

impl LiveBoundaryRegistryAuthority {
    /// Creates a non-zero, versioned registry activation reference.
    ///
    /// # Errors
    ///
    /// Rejects a zero material root, zero epoch, or nil activation identifier.
    pub fn new(
        material_root: Digest32,
        epoch: u64,
        activation_id: Uuid,
    ) -> Result<Self, ActivationError> {
        if material_root == ZERO || epoch == 0 || activation_id.is_nil() {
            return Err(ActivationError::InvalidRegistry);
        }
        Ok(Self {
            material_root,
            epoch,
            activation_id,
        })
    }

    /// Canonical root of all registry entries.
    #[must_use]
    pub const fn material_root(&self) -> Digest32 {
        self.material_root
    }

    /// Monotone registry activation epoch supplied by trusted bootstrap.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Unique registry activation identifier.
    #[must_use]
    pub const fn activation_id(&self) -> Uuid {
        self.activation_id
    }
}

impl fmt::Debug for LiveBoundaryRegistryAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LiveBoundaryRegistryAuthority([COMMITTED])")
    }
}

/// Canonical statement jointly signed by the collector and operator.
///
/// This value is data, not verification authority. Only
/// [`ActivatedLiveBoundaryRegistry::verify_current`] can create the opaque
/// verified result.
#[derive(Clone, PartialEq, Eq)]
pub struct LiveDeploymentBoundaryClaims {
    schema_version: u16,
    evidence_id: Uuid,
    activation_context: LiveActivationContext,
    proofs: LiveProofCommitments,
    bundle: LiveEvidenceBundleBinding,
    observed_at: i64,
    valid_until: i64,
    collector: LiveBoundarySignerReference,
    operator: LiveBoundarySignerReference,
    registry_authority: LiveBoundaryRegistryAuthority,
    registry_commitment: Digest32,
}

impl LiveDeploymentBoundaryClaims {
    /// Creates one closed claim set bound to an already activated registry.
    ///
    /// The lifetime is validated structurally here but not against current
    /// time. Current time is deliberately sampled and checked only during
    /// verification, after both cryptographic signatures pass.
    ///
    /// # Errors
    ///
    /// Rejects a nil evidence identifier, an invalid or overlong lifetime,
    /// reused collector/operator identity or key identifier, aliased evidence
    /// roots, and oversized canonical claims.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        evidence_id: Uuid,
        activation_context: LiveActivationContext,
        proofs: LiveProofCommitments,
        bundle: LiveEvidenceBundleBinding,
        observed_at: i64,
        valid_until: i64,
        collector: LiveBoundarySignerReference,
        operator: LiveBoundarySignerReference,
        registry: &ActivatedLiveBoundaryRegistry,
    ) -> Result<Self, ActivationError> {
        let claims = Self {
            schema_version: LIVE_BOUNDARY_CLAIMS_SCHEMA_VERSION,
            evidence_id,
            activation_context,
            proofs,
            bundle,
            observed_at,
            valid_until,
            collector,
            operator,
            registry_authority: registry.authority.clone(),
            registry_commitment: registry.commitment,
        };
        validate_claims_static(&claims)?;
        Ok(claims)
    }

    /// Fixed schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Globally replay-guarded evidence identifier.
    #[must_use]
    pub const fn evidence_id(&self) -> Uuid {
        self.evidence_id
    }

    /// Complete signed activation context.
    #[must_use]
    pub const fn activation_context(&self) -> &LiveActivationContext {
        &self.activation_context
    }

    /// Exact three-proof commitment tuple.
    #[must_use]
    pub const fn proofs(&self) -> &LiveProofCommitments {
        &self.proofs
    }

    /// Exact payload and raw-artifact bundle binding.
    #[must_use]
    pub const fn bundle(&self) -> &LiveEvidenceBundleBinding {
        &self.bundle
    }

    /// Second at which collection completed.
    #[must_use]
    pub const fn observed_at(&self) -> i64 {
        self.observed_at
    }

    /// Exclusive expiry of this attestation.
    #[must_use]
    pub const fn valid_until(&self) -> i64 {
        self.valid_until
    }

    /// Exact collector identity and protected key identifier.
    #[must_use]
    pub const fn collector(&self) -> &LiveBoundarySignerReference {
        &self.collector
    }

    /// Exact independent operator identity and protected key identifier.
    #[must_use]
    pub const fn operator(&self) -> &LiveBoundarySignerReference {
        &self.operator
    }

    /// Registry root, epoch, and activation identifier signed into the claims.
    #[must_use]
    pub const fn registry_authority(&self) -> &LiveBoundaryRegistryAuthority {
        &self.registry_authority
    }

    /// Full commitment to registry material and activation coordinates.
    #[must_use]
    pub const fn registry_commitment(&self) -> Digest32 {
        self.registry_commitment
    }

    /// Commitment to the exact canonical claims embedded in both signatures.
    ///
    /// # Errors
    ///
    /// Returns a canonical encoding or profile-size error.
    pub fn commitment(&self) -> Result<Digest32, ActivationError> {
        Ok(Digest32::sha256(&canonical_claims(self)?))
    }
}

impl fmt::Debug for LiveDeploymentBoundaryClaims {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LiveDeploymentBoundaryClaims")
            .field("schema_version", &self.schema_version)
            .field("evidence_id", &"[REDACTED]")
            .field("activation_context", &"[COMMITTED]")
            .field("proofs", &"[COMMITTED]")
            .field("bundle", &"[COMMITTED]")
            .field("validity", &"[REDACTED]")
            .field("signers", &"[REDACTED]")
            .field("registry", &"[COMMITTED]")
            .finish_non_exhaustive()
    }
}

/// Two purpose-separated COSE signatures over one exact canonical claim set.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedLiveDeploymentBoundaryAttestation {
    claims: LiveDeploymentBoundaryClaims,
    collector_cose_sign1: Vec<u8>,
    operator_cose_sign1: Vec<u8>,
}

impl SignedLiveDeploymentBoundaryAttestation {
    /// Assembles externally produced envelopes without treating them as valid.
    ///
    /// This constructor performs only bounded structural checks. Both COSE
    /// envelopes remain untrusted until `verify_current` validates their
    /// current registry keys, distinct purposes, canonical payloads, time, and
    /// replay state.
    ///
    /// # Errors
    ///
    /// Rejects malformed claims or an empty/oversized envelope.
    pub fn from_parts(
        claims: LiveDeploymentBoundaryClaims,
        collector_cose_sign1: Vec<u8>,
        operator_cose_sign1: Vec<u8>,
    ) -> Result<Self, ActivationError> {
        validate_claims_static(&claims)?;
        validate_envelope_size(&collector_cose_sign1)?;
        validate_envelope_size(&operator_cose_sign1)?;
        Ok(Self {
            claims,
            collector_cose_sign1,
            operator_cose_sign1,
        })
    }

    /// Untrusted claims carried beside the signed envelopes.
    #[must_use]
    pub const fn claims(&self) -> &LiveDeploymentBoundaryClaims {
        &self.claims
    }

    /// Encoded collector COSE Sign1 envelope.
    #[must_use]
    pub fn collector_cose_sign1(&self) -> &[u8] {
        &self.collector_cose_sign1
    }

    /// Encoded operator-approval COSE Sign1 envelope.
    #[must_use]
    pub fn operator_cose_sign1(&self) -> &[u8] {
        &self.operator_cose_sign1
    }
}

impl fmt::Debug for SignedLiveDeploymentBoundaryAttestation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedLiveDeploymentBoundaryAttestation")
            .field("claims", &"[REDACTED]")
            .field("collector_envelope", &"[REDACTED]")
            .field("operator_envelope", &"[REDACTED]")
            .finish()
    }
}

/// Signs one synthetic claim set with distinct collector and operator keys.
///
/// This helper is not a collector. It performs no EKS, Kubernetes, artifact,
/// or offline-validator operation. The current activated registry must still
/// accept both identities and keys during verification.
///
/// # Errors
///
/// Rejects key-reference mismatch, collector/operator key reuse, encoding
/// failure, or an envelope outside the local profile.
pub fn sign_live_deployment_boundary_attestation(
    claims: LiveDeploymentBoundaryClaims,
    collector: &SigningIdentity,
    operator: &SigningIdentity,
) -> Result<SignedLiveDeploymentBoundaryAttestation, ActivationError> {
    validate_claims_static(&claims)?;
    if claims.collector.key_id != collector.key_id()
        || claims.operator.key_id != operator.key_id()
        || collector.key_id() == operator.key_id()
        || collector.public_key_bytes() == operator.public_key_bytes()
    {
        return Err(ActivationError::InvalidSignerReference);
    }
    let canonical = canonical_claims(&claims)?;
    let collector_cose_sign1 = sign_cose(&canonical, COLLECTOR_ATTESTATION_DOMAIN, collector)
        .map_err(|_| ActivationError::SignatureInvalid)?;
    let operator_cose_sign1 = sign_cose(&canonical, OPERATOR_APPROVAL_DOMAIN, operator)
        .map_err(|_| ActivationError::SignatureInvalid)?;
    SignedLiveDeploymentBoundaryAttestation::from_parts(
        claims,
        collector_cose_sign1,
        operator_cose_sign1,
    )
}

/// Activated, deterministic, bounded collector/operator verifier registry.
pub struct ActivatedLiveBoundaryRegistry {
    authority: LiveBoundaryRegistryAuthority,
    entries: Vec<RegisteredLiveBoundarySigner>,
    by_key_id: BTreeMap<String, usize>,
    commitment: Digest32,
}

impl ActivatedLiveBoundaryRegistry {
    /// Activates exact, already sorted signer material under one root and epoch.
    ///
    /// Entries must sort strictly by role, identity, and key identifier. Key
    /// identifiers, public keys, and identities are globally unique across the
    /// registry, and at least one collector and one operator must exist.
    ///
    /// # Errors
    ///
    /// Rejects out-of-bound, noncanonical, incomplete, aliased material or a
    /// material-root mismatch.
    pub fn new(
        authority: LiveBoundaryRegistryAuthority,
        entries: Vec<RegisteredLiveBoundarySigner>,
    ) -> Result<Self, ActivationError> {
        let material_root = Self::compute_material_root(&entries)?;
        if material_root != authority.material_root {
            return Err(ActivationError::RegistryRootMismatch);
        }
        let commitment = registry_activation_commitment(&authority);
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

    /// Computes the canonical root after validating all registry invariants.
    ///
    /// # Errors
    ///
    /// Rejects any out-of-bound, malformed, noncanonical, incomplete, or
    /// aliased entry set.
    pub fn compute_material_root(
        entries: &[RegisteredLiveBoundarySigner],
    ) -> Result<Digest32, ActivationError> {
        validate_registry_entries(entries)?;
        let canonical = canonical_registry_entries(entries)?;
        let mut material = Vec::with_capacity(REGISTRY_MATERIAL_DOMAIN.len() + canonical.len());
        material.extend_from_slice(REGISTRY_MATERIAL_DOMAIN);
        material.extend_from_slice(&canonical);
        Ok(Digest32::sha256(&material))
    }

    /// Current registry activation coordinates.
    #[must_use]
    pub const fn authority(&self) -> &LiveBoundaryRegistryAuthority {
        &self.authority
    }

    /// Complete canonical registry entries.
    #[must_use]
    pub fn entries(&self) -> &[RegisteredLiveBoundarySigner] {
        &self.entries
    }

    /// Full commitment over the material root, epoch, and activation ID.
    #[must_use]
    pub const fn commitment(&self) -> Digest32 {
        self.commitment
    }

    /// Verifies both signatures and every current activation binding, then
    /// consumes the evidence ID in the process-local guard as the final step.
    ///
    /// Static shape and exact expected-context checks happen first. Both COSE
    /// signatures and embedded payloads are then verified. Only after those
    /// checks does the method evaluate trusted current time and signer
    /// lifetimes. Replay consumption is last, so every earlier failure leaves
    /// the guard untouched.
    ///
    /// # Errors
    ///
    /// Fails closed for any structure, context, registry, role, identity, key,
    /// signature, payload, time, bundle, or replay mismatch.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_current(
        &self,
        signed: &SignedLiveDeploymentBoundaryAttestation,
        trusted_now: i64,
        expected_scope: &ActivationScope,
        expected_route: &EksRouteProfile,
        expected_management_bindings: &EksBrokerManagementBindings,
        expected_release_commitment: Digest32,
        expected_deployment_activation_id: Uuid,
        expected_active_authority: &AuthorityVector,
        expected_proofs: &LiveProofCommitments,
        expected_bundle: &LiveEvidenceBundleBinding,
        replay_guard: &MemoryLiveEvidenceReplayGuard,
    ) -> Result<VerifiedLiveDeploymentBoundaries, ActivationError> {
        // 1. Bounded, static, deterministic claim checks. No trusted current
        // time and no replay mutation participate here.
        validate_claims_static(&signed.claims)?;
        validate_envelope_size(&signed.collector_cose_sign1)?;
        validate_envelope_size(&signed.operator_cose_sign1)?;
        let canonical = canonical_claims(&signed.claims)?;

        // 2. Exact current context, expected artifact roots, and current
        // registry activation checks.
        let expected_context = LiveActivationContext::new(
            expected_scope.clone(),
            expected_route,
            expected_management_bindings,
            expected_release_commitment,
            expected_deployment_activation_id,
            expected_active_authority.clone(),
        )?;
        if signed.claims.activation_context != expected_context {
            return Err(ActivationError::ActivationContextMismatch);
        }
        if &signed.claims.bundle != expected_bundle {
            return Err(ActivationError::BundleBindingMismatch);
        }
        if &signed.claims.proofs != expected_proofs {
            return Err(ActivationError::ProofCommitmentMismatch);
        }
        if signed.claims.registry_authority != self.authority
            || signed.claims.registry_commitment != self.commitment
        {
            return Err(ActivationError::RegistryMismatch);
        }

        let collector_entry = self.resolve_signer(
            &signed.claims.collector,
            LiveBoundarySignerRole::Collector,
            expected_scope,
            expected_route.cluster_identity(),
        )?;
        let operator_entry = self.resolve_signer(
            &signed.claims.operator,
            LiveBoundarySignerRole::Operator,
            expected_scope,
            expected_route.cluster_identity(),
        )?;
        if collector_entry.key_id == operator_entry.key_id
            || collector_entry.public_key == operator_entry.public_key
            || collector_entry.identity == operator_entry.identity
        {
            return Err(ActivationError::SignerBindingMismatch);
        }

        // 3. Purpose-separated signatures over the same canonical claims.
        verify_signature(
            &signed.collector_cose_sign1,
            COLLECTOR_ATTESTATION_DOMAIN,
            collector_entry,
            &canonical,
        )?;
        verify_signature(
            &signed.operator_cose_sign1,
            OPERATOR_APPROVAL_DOMAIN,
            operator_entry,
            &canonical,
        )?;

        // 4. Trusted-current-time and current-key checks happen only after
        // both cryptographic envelopes pass.
        validate_current_time(&signed.claims, trusted_now)?;
        validate_signer_current(collector_entry, &signed.claims, trusted_now)?;
        validate_signer_current(operator_entry, &signed.claims, trusted_now)?;

        // 5. This is intentionally the final state-changing operation.
        replay_guard.consume_once(signed.claims.evidence_id)?;

        Ok(VerifiedLiveDeploymentBoundaries {
            evidence_id: signed.claims.evidence_id,
            verified_at: trusted_now,
            observed_at: signed.claims.observed_at,
            valid_until: signed.claims.valid_until,
            activation_context_commitment: signed.claims.activation_context.commitment,
            bundle_canonical_payload_commitment: signed.claims.bundle.canonical_payload_commitment,
            raw_artifact_set_commitment: signed.claims.bundle.raw_artifact_set_commitment,
            raw_artifact_count: signed.claims.bundle.raw_artifact_count,
            registry_commitment: self.commitment,
        })
    }

    fn resolve_signer(
        &self,
        reference: &LiveBoundarySignerReference,
        role: LiveBoundarySignerRole,
        scope: &ActivationScope,
        cluster_identity: &str,
    ) -> Result<&RegisteredLiveBoundarySigner, ActivationError> {
        let entry = self
            .by_key_id
            .get(&reference.key_id)
            .map(|index| &self.entries[*index])
            .ok_or(ActivationError::SignerNotFound)?;
        if entry.role != role {
            return Err(ActivationError::SignerRoleMismatch);
        }
        if entry.identity != reference.identity
            || &entry.scope != scope
            || entry.cluster_identity != cluster_identity
        {
            return Err(ActivationError::SignerBindingMismatch);
        }
        Ok(entry)
    }
}

impl fmt::Debug for ActivatedLiveBoundaryRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActivatedLiveBoundaryRegistry")
            .field("authority", &"[COMMITTED]")
            .field("entry_count", &self.entries.len())
            .field("entries", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Process-local, globally keyed evidence-ID replay guard for synthetic use.
///
/// The guard is intentionally the only accepted replay implementation in this
/// crate, preventing callers from injecting an always-accepting trait object.
/// It is not durable or distributed and therefore cannot support production
/// activation across restarts or replicas.
#[derive(Default)]
pub struct MemoryLiveEvidenceReplayGuard {
    consumed: Mutex<BTreeSet<Uuid>>,
}

impl MemoryLiveEvidenceReplayGuard {
    /// Creates an empty process-local replay domain.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of evidence identifiers consumed by successful verification.
    ///
    /// This is a diagnostic for tests and synthetic supervisors, not a durable
    /// replay receipt.
    ///
    /// # Errors
    ///
    /// Returns [`ActivationError::ReplayGuardUnavailable`] if the internal
    /// lock was poisoned.
    pub fn consumed_count(&self) -> Result<usize, ActivationError> {
        self.consumed
            .lock()
            .map(|values| values.len())
            .map_err(|_| ActivationError::ReplayGuardUnavailable)
    }

    fn consume_once(&self, evidence_id: Uuid) -> Result<(), ActivationError> {
        let mut consumed = self
            .consumed
            .lock()
            .map_err(|_| ActivationError::ReplayGuardUnavailable)?;
        if !consumed.insert(evidence_id) {
            return Err(ActivationError::ReplayDetected);
        }
        Ok(())
    }
}

impl fmt::Debug for MemoryLiveEvidenceReplayGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MemoryLiveEvidenceReplayGuard([REDACTED])")
    }
}

/// Opaque result of exact current-registry, dual-signature, time, and replay
/// verification.
///
/// This type has no public constructor and implements neither `Clone`, `Copy`,
/// nor Serde. It proves the verification operation described by this crate; it
/// does not prove that external artifact contents are truthful.
///
/// ```compile_fail
/// use accordlock_activation::VerifiedLiveDeploymentBoundaries;
/// let _forged = VerifiedLiveDeploymentBoundaries {};
/// ```
///
/// ```compile_fail
/// use accordlock_activation::VerifiedLiveDeploymentBoundaries;
/// fn duplicate(value: VerifiedLiveDeploymentBoundaries) {
///     let _: VerifiedLiveDeploymentBoundaries = value.clone();
/// }
/// ```
///
/// ```compile_fail
/// use accordlock_activation::VerifiedLiveDeploymentBoundaries;
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<VerifiedLiveDeploymentBoundaries>();
/// ```
///
/// ```compile_fail
/// use accordlock_activation::VerifiedLiveDeploymentBoundaries;
/// fn require_deserialize<T: serde::de::DeserializeOwned>() {}
/// require_deserialize::<VerifiedLiveDeploymentBoundaries>();
/// ```
#[derive(PartialEq, Eq)]
pub struct VerifiedLiveDeploymentBoundaries {
    evidence_id: Uuid,
    verified_at: i64,
    observed_at: i64,
    valid_until: i64,
    activation_context_commitment: Digest32,
    bundle_canonical_payload_commitment: Digest32,
    raw_artifact_set_commitment: Digest32,
    raw_artifact_count: u32,
    registry_commitment: Digest32,
}

impl VerifiedLiveDeploymentBoundaries {
    /// Evidence identifier consumed in the process-local replay domain.
    #[must_use]
    pub const fn evidence_id(&self) -> Uuid {
        self.evidence_id
    }

    /// Trusted current time used for this verification.
    #[must_use]
    pub const fn verified_at(&self) -> i64 {
        self.verified_at
    }

    /// Signed collection completion time.
    #[must_use]
    pub const fn observed_at(&self) -> i64 {
        self.observed_at
    }

    /// Exclusive expiry bound that passed this verification.
    #[must_use]
    pub const fn valid_until(&self) -> i64 {
        self.valid_until
    }

    /// Commitment to scope, route, management bindings, release, activation,
    /// and complete authority vector.
    #[must_use]
    pub const fn activation_context_commitment(&self) -> Digest32 {
        self.activation_context_commitment
    }

    /// Independently expected complete payload bundle commitment.
    #[must_use]
    pub const fn bundle_canonical_payload_commitment(&self) -> Digest32 {
        self.bundle_canonical_payload_commitment
    }

    /// Independently expected complete raw-artifact set commitment.
    #[must_use]
    pub const fn raw_artifact_set_commitment(&self) -> Digest32 {
        self.raw_artifact_set_commitment
    }

    /// Positive bounded raw-artifact count committed by the verified claims.
    #[must_use]
    pub const fn raw_artifact_count(&self) -> u32 {
        self.raw_artifact_count
    }

    /// Full current-registry commitment used for both signatures.
    #[must_use]
    pub const fn registry_commitment(&self) -> Digest32 {
        self.registry_commitment
    }
}

impl fmt::Debug for VerifiedLiveDeploymentBoundaries {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedLiveDeploymentBoundaries")
            .field("evidence_id", &"[REDACTED]")
            .field("time_window", &"[REDACTED]")
            .field("activation_context", &"[COMMITTED]")
            .field("bundle", &"[COMMITTED]")
            .field("registry", &"[COMMITTED]")
            .finish()
    }
}

fn valid_security_text(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.is_ascii()
        && value.trim() == value
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
}

fn validate_authority(authority: &AuthorityVector) -> Result<(), ActivationError> {
    if authority
        .domains()
        .iter()
        .any(|domain| domain.root == ZERO || domain.epoch == 0 || domain.activation_id.is_nil())
    {
        return Err(ActivationError::InvalidAuthority);
    }
    Ok(())
}

fn management_bindings_commitment(
    bindings: &EksBrokerManagementBindings,
) -> Result<Digest32, ActivationError> {
    let mut encoder = CanonicalEncoder::new(Vec::new());
    let canonical_bytes = (|| -> Result<Vec<u8>, CanonicalEncodeError> {
        encoder.array(3)?;
        for binding in [
            bindings.secret_lifecycle(),
            bindings.service_account_token(),
            bindings.token_review(),
        ] {
            encoder.array(2)?;
            encoder.str(binding.subject())?;
            encoder.bytes(&binding.rbac_commitment())?;
        }
        Ok(encoder.into_writer())
    })()
    .map_err(|_| ActivationError::CanonicalEncoding)?;
    let mut material = Vec::with_capacity(MANAGEMENT_BINDINGS_DOMAIN.len() + canonical_bytes.len());
    material.extend_from_slice(MANAGEMENT_BINDINGS_DOMAIN);
    material.extend_from_slice(&canonical_bytes);
    let commitment = Digest32::sha256(&material);
    if commitment == ZERO {
        return Err(ActivationError::InvalidCommitment);
    }
    Ok(commitment)
}

fn canonical_activation_context(
    context: &LiveActivationContext,
) -> Result<Vec<u8>, ActivationError> {
    let authority = context
        .authority
        .canonical_bytes()
        .map_err(|_| ActivationError::CanonicalEncoding)?;
    let mut encoder = CanonicalEncoder::new(Vec::new());
    (|| -> Result<Vec<u8>, CanonicalEncodeError> {
        encoder.array(8)?;
        encoder.u16(LIVE_BOUNDARY_CLAIMS_SCHEMA_VERSION)?;
        encode_scope(&mut encoder, &context.scope)?;
        encoder.bytes(context.route_commitment.as_bytes())?;
        encoder.bytes(context.management_bindings_commitment.as_bytes())?;
        encoder.bytes(context.release_commitment.as_bytes())?;
        encoder.bytes(context.deployment_activation_id.as_bytes())?;
        encoder.bytes(&authority)?;
        encoder.bytes(ACTIVATION_CONTEXT_DOMAIN)?;
        Ok(encoder.into_writer())
    })()
    .map_err(|_| ActivationError::CanonicalEncoding)
}

fn validate_activation_context(context: &LiveActivationContext) -> Result<(), ActivationError> {
    if !valid_security_text(context.scope.tenant(), MAX_ACTIVATION_SCOPE_COMPONENT_BYTES)
        || !valid_security_text(
            context.scope.environment(),
            MAX_ACTIVATION_SCOPE_COMPONENT_BYTES,
        )
        || context.route_commitment == ZERO
        || context.management_bindings_commitment == ZERO
        || context.release_commitment == ZERO
        || context.deployment_activation_id.is_nil()
    {
        return Err(ActivationError::InvalidClaims);
    }
    validate_authority(&context.authority)?;
    let commitment = Digest32::sha256(&canonical_activation_context(context)?);
    if context.commitment == ZERO || context.commitment != commitment {
        return Err(ActivationError::InvalidClaims);
    }
    Ok(())
}

fn validate_claims_static(claims: &LiveDeploymentBoundaryClaims) -> Result<(), ActivationError> {
    if claims.schema_version != LIVE_BOUNDARY_CLAIMS_SCHEMA_VERSION
        || claims.evidence_id.is_nil()
        || claims.observed_at < 0
        || claims.valid_until <= claims.observed_at
        || claims
            .valid_until
            .checked_sub(claims.observed_at)
            .is_none_or(|lifetime| lifetime > MAX_LIVE_BOUNDARY_LIFETIME_SECONDS)
    {
        return Err(ActivationError::InvalidClaims);
    }
    validate_activation_context(&claims.activation_context)?;
    if claims.collector.identity == claims.operator.identity
        || claims.collector.key_id == claims.operator.key_id
        || !valid_security_text(&claims.collector.identity, MAX_LIVE_BOUNDARY_IDENTITY_BYTES)
        || !valid_security_text(&claims.collector.key_id, MAX_LIVE_BOUNDARY_KEY_ID_BYTES)
        || !valid_security_text(&claims.operator.identity, MAX_LIVE_BOUNDARY_IDENTITY_BYTES)
        || !valid_security_text(&claims.operator.key_id, MAX_LIVE_BOUNDARY_KEY_ID_BYTES)
    {
        return Err(ActivationError::InvalidSignerReference);
    }
    let proof_roots = [
        claims.proofs.management_rbac,
        claims.proofs.authenticated_webhook_caller_boundary,
        claims.proofs.kubernetes_api_audience,
    ];
    if proof_roots.contains(&ZERO)
        || proof_roots[0] == proof_roots[1]
        || proof_roots[0] == proof_roots[2]
        || proof_roots[1] == proof_roots[2]
    {
        return Err(ActivationError::InvalidProofSet);
    }
    if claims.bundle.canonical_payload_commitment == ZERO
        || claims.bundle.raw_artifact_set_commitment == ZERO
        || claims.bundle.canonical_payload_commitment == claims.bundle.raw_artifact_set_commitment
        || claims.bundle.raw_artifact_count == 0
        || claims.bundle.raw_artifact_count > MAX_LIVE_BOUNDARY_RAW_ARTIFACTS
    {
        return Err(ActivationError::InvalidBundleBinding);
    }
    let all_evidence_roots = [
        proof_roots[0],
        proof_roots[1],
        proof_roots[2],
        claims.bundle.canonical_payload_commitment,
        claims.bundle.raw_artifact_set_commitment,
    ];
    if all_evidence_roots
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .len()
        != all_evidence_roots.len()
    {
        return Err(ActivationError::InvalidCommitment);
    }
    if claims.registry_authority.material_root == ZERO
        || claims.registry_authority.epoch == 0
        || claims.registry_authority.activation_id.is_nil()
        || claims.registry_commitment == ZERO
        || registry_activation_commitment(&claims.registry_authority) != claims.registry_commitment
    {
        return Err(ActivationError::InvalidClaims);
    }
    if canonical_claims_unbounded(claims)?.len() > MAX_LIVE_BOUNDARY_CLAIMS_BYTES {
        return Err(ActivationError::ClaimsTooLarge);
    }
    Ok(())
}

fn canonical_claims(claims: &LiveDeploymentBoundaryClaims) -> Result<Vec<u8>, ActivationError> {
    let canonical = canonical_claims_unbounded(claims)?;
    if canonical.len() > MAX_LIVE_BOUNDARY_CLAIMS_BYTES {
        return Err(ActivationError::ClaimsTooLarge);
    }
    Ok(canonical)
}

fn canonical_claims_unbounded(
    claims: &LiveDeploymentBoundaryClaims,
) -> Result<Vec<u8>, ActivationError> {
    let context = canonical_activation_context(&claims.activation_context)?;
    let mut encoder = CanonicalEncoder::new(Vec::new());
    (|| -> Result<Vec<u8>, CanonicalEncodeError> {
        encoder.array(13)?;
        encoder.u16(claims.schema_version)?;
        encoder.bytes(claims.evidence_id.as_bytes())?;
        encoder.bytes(&context)?;
        encoder.bytes(claims.activation_context.commitment.as_bytes())?;
        encoder.array(3)?;
        encoder.bytes(claims.proofs.management_rbac.as_bytes())?;
        encoder.bytes(
            claims
                .proofs
                .authenticated_webhook_caller_boundary
                .as_bytes(),
        )?;
        encoder.bytes(claims.proofs.kubernetes_api_audience.as_bytes())?;
        encoder.array(3)?;
        encoder.bytes(claims.bundle.canonical_payload_commitment.as_bytes())?;
        encoder.bytes(claims.bundle.raw_artifact_set_commitment.as_bytes())?;
        encoder.u32(claims.bundle.raw_artifact_count)?;
        encoder.i64(claims.observed_at)?;
        encoder.i64(claims.valid_until)?;
        encode_signer_reference(&mut encoder, &claims.collector)?;
        encode_signer_reference(&mut encoder, &claims.operator)?;
        encode_registry_authority(&mut encoder, &claims.registry_authority)?;
        encoder.bytes(claims.registry_commitment.as_bytes())?;
        encoder.str(CLAIMS_DOMAIN)?;
        Ok(encoder.into_writer())
    })()
    .map_err(|_| ActivationError::CanonicalEncoding)
}

fn validate_envelope_size(envelope: &[u8]) -> Result<(), ActivationError> {
    if envelope.is_empty() || envelope.len() > MAX_LIVE_BOUNDARY_COSE_BYTES {
        return Err(ActivationError::EnvelopeTooLarge);
    }
    Ok(())
}

fn validate_registry_entries(
    entries: &[RegisteredLiveBoundarySigner],
) -> Result<(), ActivationError> {
    if entries.len() < 2 || entries.len() > MAX_LIVE_BOUNDARY_REGISTRY_ENTRIES {
        return Err(ActivationError::InvalidRegistry);
    }
    if entries
        .windows(2)
        .any(|pair| pair[0].sort_key() >= pair[1].sort_key())
    {
        return Err(ActivationError::InvalidRegistry);
    }
    let mut identities = BTreeSet::new();
    let mut key_ids = BTreeSet::new();
    let mut public_keys = BTreeSet::new();
    let mut has_collector = false;
    let mut has_operator = false;
    for entry in entries {
        if !valid_security_text(entry.scope.tenant(), MAX_ACTIVATION_SCOPE_COMPONENT_BYTES)
            || !valid_security_text(
                entry.scope.environment(),
                MAX_ACTIVATION_SCOPE_COMPONENT_BYTES,
            )
            || !valid_security_text(&entry.cluster_identity, MAX_CLUSTER_IDENTITY_BYTES)
            || !valid_security_text(&entry.identity, MAX_LIVE_BOUNDARY_IDENTITY_BYTES)
            || !valid_security_text(&entry.key_id, MAX_LIVE_BOUNDARY_KEY_ID_BYTES)
            || entry.not_before < 0
            || entry.valid_until <= entry.not_before
            || CoseVerifier::from_public_key(entry.key_id.clone(), entry.public_key).is_err()
            || !identities.insert(entry.identity.clone())
            || !key_ids.insert(entry.key_id.clone())
            || !public_keys.insert(entry.public_key)
        {
            return Err(ActivationError::InvalidRegistry);
        }
        match entry.role {
            LiveBoundarySignerRole::Collector => has_collector = true,
            LiveBoundarySignerRole::Operator => has_operator = true,
        }
    }
    if !has_collector || !has_operator {
        return Err(ActivationError::InvalidRegistry);
    }
    Ok(())
}

fn canonical_registry_entries(
    entries: &[RegisteredLiveBoundarySigner],
) -> Result<Vec<u8>, ActivationError> {
    let mut encoder = CanonicalEncoder::new(Vec::new());
    (|| -> Result<Vec<u8>, CanonicalEncodeError> {
        encoder.array(2)?;
        encoder.array(u64::try_from(entries.len()).unwrap_or(u64::MAX))?;
        for entry in entries {
            encoder.array(9)?;
            encode_scope(&mut encoder, &entry.scope)?;
            encoder.str(&entry.cluster_identity)?;
            encoder.u8(entry.role.code())?;
            encoder.str(&entry.identity)?;
            encoder.str(&entry.key_id)?;
            encoder.bytes(&entry.public_key)?;
            encoder.i64(entry.not_before)?;
            encoder.i64(entry.valid_until)?;
            encoder.u8(entry.status.code())?;
        }
        encoder.bytes(REGISTRY_MATERIAL_DOMAIN)?;
        Ok(encoder.into_writer())
    })()
    .map_err(|_| ActivationError::CanonicalEncoding)
}

fn registry_activation_commitment(authority: &LiveBoundaryRegistryAuthority) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(REGISTRY_ACTIVATION_DOMAIN);
    hasher.update(authority.material_root.as_bytes());
    hasher.update(authority.epoch.to_be_bytes());
    hasher.update(authority.activation_id.as_bytes());
    Digest32::from_bytes(hasher.finalize().into())
}

fn verify_signature(
    envelope: &[u8],
    domain: &str,
    entry: &RegisteredLiveBoundarySigner,
    expected_payload: &[u8],
) -> Result<(), ActivationError> {
    let verifier = CoseVerifier::from_public_key(entry.key_id.clone(), entry.public_key)
        .map_err(|_| ActivationError::SignatureInvalid)?;
    let embedded =
        verify_cose(envelope, domain, &verifier).map_err(|_| ActivationError::SignatureInvalid)?;
    if embedded != expected_payload {
        return Err(ActivationError::SignaturePayloadMismatch);
    }
    Ok(())
}

fn validate_current_time(
    claims: &LiveDeploymentBoundaryClaims,
    trusted_now: i64,
) -> Result<(), ActivationError> {
    if trusted_now < 0 {
        return Err(ActivationError::InvalidTrustedTime);
    }
    if claims.observed_at > trusted_now {
        return Err(ActivationError::ObservationInFuture);
    }
    if trusted_now >= claims.valid_until {
        return Err(ActivationError::AttestationExpired);
    }
    Ok(())
}

fn validate_signer_current(
    entry: &RegisteredLiveBoundarySigner,
    claims: &LiveDeploymentBoundaryClaims,
    trusted_now: i64,
) -> Result<(), ActivationError> {
    if entry.status != LiveBoundarySignerStatus::Active
        || claims.observed_at < entry.not_before
        || claims.valid_until > entry.valid_until
        || trusted_now < entry.not_before
        || trusted_now >= entry.valid_until
    {
        return Err(ActivationError::SignerInactive);
    }
    Ok(())
}

fn encode_scope(
    encoder: &mut CanonicalEncoder,
    scope: &ActivationScope,
) -> Result<(), CanonicalEncodeError> {
    encoder.array(2)?;
    encoder.str(&scope.tenant)?;
    encoder.str(&scope.environment)?;
    Ok(())
}

fn encode_signer_reference(
    encoder: &mut CanonicalEncoder,
    reference: &LiveBoundarySignerReference,
) -> Result<(), CanonicalEncodeError> {
    encoder.array(2)?;
    encoder.str(&reference.identity)?;
    encoder.str(&reference.key_id)?;
    Ok(())
}

fn encode_registry_authority(
    encoder: &mut CanonicalEncoder,
    authority: &LiveBoundaryRegistryAuthority,
) -> Result<(), CanonicalEncodeError> {
    encoder.array(3)?;
    encoder.bytes(authority.material_root.as_bytes())?;
    encoder.u64(authority.epoch)?;
    encoder.bytes(authority.activation_id.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests;
