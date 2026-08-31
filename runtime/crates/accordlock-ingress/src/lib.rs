//! Local application-layer authentication boundary for `AccordLock` proposals.
//!
//! This crate is deliberately transport-neutral. It authenticates a signed
//! request envelope and derives the caller from a local key registry. It does
//! not implement or claim mTLS, workload identity, a durable replay store, or
//! production key lifecycle management.

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::fmt::Debug;

use accordlock_protocol::{
    AgentProposal, AuthorityDomainState, CanonicalEncode, CoseVerifier, Digest32, SigningIdentity,
    sign_cose, verify_cose,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use minicbor::{Encoder, encode::Error as EncodeError};
use parking_lot::Mutex;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use thiserror::Error;
use uuid::Uuid;

/// External-AAD domain used only for authenticated proposal ingress.
pub const INGRESS_REQUEST_DOMAIN: &str = "accordlock:v2:authenticated-ingress-request";

/// The only ingress claims schema accepted by this candidate implementation.
pub const INGRESS_SCHEMA_VERSION: u16 = 2;

/// Domain frozen inside the complete v2 ingress-claims canonical encoding.
pub const INGRESS_CLAIMS_DOMAIN: &str = "accordlock:v2:ingress-claims";

/// Maximum UTF-8 JSON request size accepted before parsing.
pub const MAX_INGRESS_JSON_BYTES: usize = 65_536;

/// Domain separator for the canonical activated-ingress-registry root.
pub const INGRESS_REGISTRY_ROOT_DOMAIN: &[u8] = b"accordlock:v2:activated-ingress-profile\0";

/// Domain of the format-independent durable ingress recovery identity.
pub const INGRESS_CANONICAL_PAYLOAD_COMMITMENT_DOMAIN: &str =
    "accordlock:v2:durable-ingress-canonical-payload";

/// Domain of the first received JSON wire-image audit commitment.
pub const INGRESS_WIRE_COMMITMENT_DOMAIN: &str = "accordlock:v1:durable-ingress-wire-image";

const MAX_REGISTERED_INGRESS_KEYS: usize = 256;
const MAX_AUDIENCES_PER_INGRESS_KEY: usize = 64;
const MAX_SECURITY_TEXT_BYTES: usize = 4_096;

/// Caller-controlled claims covered by the ingress signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressClaims {
    pub schema_version: u16,
    pub audience: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub nonce: Uuid,
    pub proposal: AgentProposal,
}

impl IngressClaims {
    /// Encodes every claim and the complete domain-separated canonical
    /// [`AgentProposal`] in a fixed deterministic CBOR array.
    ///
    /// # Errors
    ///
    /// Returns [`IngressError::Canonical`] if either canonical encoding fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, IngressError> {
        let proposal = self
            .proposal
            .canonical_bytes()
            .map_err(|error| IngressError::Canonical(error.to_string()))?;

        let encoded: Result<Vec<u8>, EncodeError<Infallible>> = (|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(7)?;
            encoder.u16(self.schema_version)?;
            encoder.str(&self.audience)?;
            encoder.i64(self.issued_at)?;
            encoder.i64(self.expires_at)?;
            encoder.bytes(self.nonce.as_bytes())?;
            encoder.bytes(&proposal)?;
            encoder.str(INGRESS_CLAIMS_DOMAIN)?;
            Ok(encoder.into_writer())
        })();

        encoded.map_err(|error| IngressError::Canonical(error.to_string()))
    }
}

/// Strict JSON wire envelope. `key_id` is only a registry lookup hint. The
/// protected COSE header must contain the same identifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedIngressRequest {
    pub key_id: String,
    pub claims: IngressClaims,
    #[serde(with = "base64url_bytes")]
    pub cose_sign1: Vec<u8>,
}

/// Strictly parsed ingress envelope used to ask durable state for an exact
/// historical recovery candidate.
///
/// This is deliberately not an authentication capability. It contains
/// caller-controlled material and may be constructed before any registry
/// lookup. Its payload commitment is stable across equivalent JSON object
/// reserialization; its wire commitment is not and is retained only for audit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IngressRecoveryProbe {
    request: SignedIngressRequest,
    canonical_claims: Vec<u8>,
    canonical_payload_commitment: Digest32,
    wire_commitment: Digest32,
    wire_json: Vec<u8>,
}

impl IngressRecoveryProbe {
    /// Parses a bounded strict JSON envelope and computes its two independent
    /// commitments. No signature, identity, time, or registry assertion is
    /// made by this operation.
    ///
    /// # Errors
    ///
    /// Returns [`IngressError`] for an oversized, malformed, or
    /// non-canonically encodable request.
    pub fn parse_bytes(wire_bytes: &[u8]) -> Result<Self, IngressError> {
        if wire_bytes.len() > MAX_INGRESS_JSON_BYTES {
            return Err(IngressError::RequestTooLarge);
        }
        let _: DuplicateRejectingJson = serde_json::from_slice(wire_bytes)
            .map_err(|error| IngressError::MalformedJson(error.to_string()))?;
        let request: SignedIngressRequest = serde_json::from_slice(wire_bytes)
            .map_err(|error| IngressError::MalformedJson(error.to_string()))?;
        let canonical_claims = request.claims.canonical_bytes()?;
        let canonical_payload_commitment =
            canonical_payload_commitment(&request.key_id, &canonical_claims, &request.cose_sign1)?;
        let wire_json = wire_bytes.to_vec();
        let wire_commitment = wire_image_commitment(&wire_json)?;
        Ok(Self {
            request,
            canonical_claims,
            canonical_payload_commitment,
            wire_commitment,
            wire_json,
        })
    }

    /// String convenience wrapper for local harnesses. Product transports
    /// should call [`Self::parse_bytes`] with the exact received HTTP entity
    /// body. The v13 profile defines this as the post-transport entity bytes;
    /// deployments should reject content encoding rather than create multiple
    /// wire identities for compressed representations.
    ///
    /// # Errors
    ///
    /// Returns the same strict parsing errors as [`Self::parse_bytes`].
    pub fn parse_json(json: &str) -> Result<Self, IngressError> {
        Self::parse_bytes(json.as_bytes())
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.request.key_id
    }

    #[must_use]
    pub const fn claims(&self) -> &IngressClaims {
        &self.request.claims
    }

    #[must_use]
    pub const fn canonical_payload_commitment(&self) -> Digest32 {
        self.canonical_payload_commitment
    }

    #[must_use]
    pub const fn wire_commitment(&self) -> Digest32 {
        self.wire_commitment
    }

    #[must_use]
    pub fn wire_json(&self) -> &[u8] {
        &self.wire_json
    }

    #[must_use]
    pub fn cose_sign1(&self) -> &[u8] {
        &self.request.cose_sign1
    }

    /// Re-verifies an exact committed envelope using only the verifier and
    /// identity binding frozen when it was first accepted.
    ///
    /// Current time, current key status, and current registry authority are
    /// intentionally not consulted. The result is inert and cannot be turned
    /// into [`AuthenticatedIngressRequest`] or
    /// [`StaticallyVerifiedIngressSubmission`].
    ///
    /// # Errors
    ///
    /// Returns [`IngressError`] unless every signed/static field and the exact
    /// payload recovery identity agree with `frozen`.
    pub fn verify_historical(
        self,
        frozen: &FrozenIngressVerifier,
    ) -> Result<VerifiedHistoricalIngress, IngressError> {
        if self.canonical_payload_commitment != frozen.canonical_payload_commitment
            || self.request.key_id != frozen.key_id
        {
            return Err(IngressError::HistoricalRecoveryMismatch);
        }
        verify_probe_signature(&self, &frozen.key_id, frozen.public_key)?;
        validate_bound_claims(
            &self.request.claims,
            &frozen.audience,
            &frozen.tenant,
            &frozen.actor,
            frozen.key_not_before,
            frozen.key_expires_at,
            frozen.maximum_lifetime_seconds,
        )?;
        Ok(VerifiedHistoricalIngress {
            request: self.request,
            canonical_payload_commitment: self.canonical_payload_commitment,
            wire_commitment: self.wire_commitment,
            authority_domain: frozen.authority_domain.clone(),
        })
    }
}

/// Persisted verification material for one already accepted canonical payload.
///
/// This value is not authority by itself. It can produce only an inert
/// historical verification, and state must compare that result back to the
/// exact immutable submission row before returning a recovery reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrozenIngressVerifier {
    canonical_payload_commitment: Digest32,
    key_id: String,
    public_key: [u8; 32],
    tenant: String,
    actor: String,
    audience: String,
    key_not_before: i64,
    key_expires_at: i64,
    maximum_lifetime_seconds: i64,
    authority_domain: AuthorityDomainState,
}

impl FrozenIngressVerifier {
    /// Reconstructs non-secret verifier material loaded from immutable durable
    /// state. Construction validates shape, but does not authenticate a request.
    ///
    /// # Errors
    ///
    /// Returns [`IngressError::InvalidConfiguration`] for malformed persisted
    /// material.
    #[allow(clippy::too_many_arguments)]
    pub fn from_persisted(
        canonical_payload_commitment: Digest32,
        key_id: String,
        public_key: [u8; 32],
        tenant: String,
        actor: String,
        audience: String,
        key_not_before: i64,
        key_expires_at: i64,
        maximum_lifetime_seconds: i64,
        authority_domain: AuthorityDomainState,
    ) -> Result<Self, IngressError> {
        if canonical_payload_commitment == Digest32::from_bytes([0; 32])
            || !valid_security_text(&key_id)
            || !valid_security_text(&tenant)
            || !valid_security_text(&actor)
            || !valid_security_text(&audience)
            || key_not_before < 0
            || key_expires_at <= key_not_before
            || maximum_lifetime_seconds <= 0
        {
            return Err(IngressError::InvalidConfiguration(
                "frozen ingress verifier material is malformed".to_owned(),
            ));
        }
        validate_authority_domain(&authority_domain)?;
        CoseVerifier::from_public_key(key_id.clone(), public_key).map_err(|_| {
            IngressError::InvalidConfiguration(
                "frozen ingress verification key is malformed".to_owned(),
            )
        })?;
        Ok(Self {
            canonical_payload_commitment,
            key_id,
            public_key,
            tenant,
            actor,
            audience,
            key_not_before,
            key_expires_at,
            maximum_lifetime_seconds,
            authority_domain,
        })
    }

    #[must_use]
    pub const fn canonical_payload_commitment(&self) -> Digest32 {
        self.canonical_payload_commitment
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
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    #[must_use]
    pub fn actor(&self) -> &str {
        &self.actor
    }

    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }

    #[must_use]
    pub const fn key_not_before(&self) -> i64 {
        self.key_not_before
    }

    #[must_use]
    pub const fn key_expires_at(&self) -> i64 {
        self.key_expires_at
    }

    #[must_use]
    pub const fn maximum_lifetime_seconds(&self) -> i64 {
        self.maximum_lifetime_seconds
    }

    #[must_use]
    pub const fn authority_domain(&self) -> &AuthorityDomainState {
        &self.authority_domain
    }
}

/// Cryptographically re-verified reference to historical signed ingress.
///
/// This type is opaque, non-serializable, and intentionally inert. It proves
/// only that the supplied envelope still matches frozen historical material;
/// it never authorizes evaluation or execution.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedHistoricalIngress {
    request: SignedIngressRequest,
    canonical_payload_commitment: Digest32,
    wire_commitment: Digest32,
    authority_domain: AuthorityDomainState,
}

impl VerifiedHistoricalIngress {
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.request.key_id
    }

    #[must_use]
    pub const fn claims(&self) -> &IngressClaims {
        &self.request.claims
    }

    #[must_use]
    pub const fn canonical_payload_commitment(&self) -> Digest32 {
        self.canonical_payload_commitment
    }

    #[must_use]
    pub const fn presented_wire_commitment(&self) -> Digest32 {
        self.wire_commitment
    }

    #[must_use]
    pub const fn authority_domain(&self) -> &AuthorityDomainState {
        &self.authority_domain
    }
}

/// Statically authenticated ingress candidate for the durable v13 state
/// boundary.
///
/// It has no public constructor and implements neither `Clone` nor Serde.
/// Durable state must not trust any time or authority supplied by a caller.
/// It reloads the exact active principal-registry authority, locks its HWM,
/// samples its own trusted clock, repeats temporal checks, and atomically
/// commits HWM + nonce + submission + status + READY work. Possession of this
/// transient static verification alone commits and authorizes nothing.
///
/// ```compile_fail
/// # use accordlock_ingress::StaticallyVerifiedIngressSubmission;
/// let _: StaticallyVerifiedIngressSubmission = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct StaticallyVerifiedIngressSubmission {
    caller: AuthenticatedCaller,
    request: SignedIngressRequest,
    canonical_claims: Vec<u8>,
    replay_scope: ReplayScope,
    maximum_lifetime_seconds: i64,
    key_public_key: [u8; 32],
    key_not_before: i64,
    key_expires_at: i64,
    authority_domain: AuthorityDomainState,
    canonical_payload_commitment: Digest32,
    wire_commitment: Digest32,
    wire_json: Vec<u8>,
}

impl StaticallyVerifiedIngressSubmission {
    #[must_use]
    pub const fn caller(&self) -> &AuthenticatedCaller {
        &self.caller
    }

    #[must_use]
    pub const fn proposal(&self) -> &AgentProposal {
        &self.request.claims.proposal
    }

    #[must_use]
    pub const fn claims(&self) -> &IngressClaims {
        &self.request.claims
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.request.key_id
    }

    #[must_use]
    pub const fn nonce(&self) -> Uuid {
        self.request.claims.nonce
    }

    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.request.claims.expires_at
    }

    #[must_use]
    pub const fn replay_scope(&self) -> &ReplayScope {
        &self.replay_scope
    }

    #[must_use]
    pub const fn authority_domain(&self) -> &AuthorityDomainState {
        &self.authority_domain
    }

    #[must_use]
    pub const fn canonical_payload_commitment(&self) -> Digest32 {
        self.canonical_payload_commitment
    }

    #[must_use]
    pub const fn wire_commitment(&self) -> Digest32 {
        self.wire_commitment
    }

    #[must_use]
    pub fn wire_json(&self) -> &[u8] {
        &self.wire_json
    }

    #[must_use]
    pub fn canonical_claims(&self) -> &[u8] {
        &self.canonical_claims
    }

    #[must_use]
    pub fn cose_sign1(&self) -> &[u8] {
        &self.request.cose_sign1
    }

    #[must_use]
    pub const fn key_public_key(&self) -> [u8; 32] {
        self.key_public_key
    }

    #[must_use]
    pub const fn key_not_before(&self) -> i64 {
        self.key_not_before
    }

    #[must_use]
    pub const fn key_expires_at(&self) -> i64 {
        self.key_expires_at
    }

    #[must_use]
    pub const fn maximum_lifetime_seconds(&self) -> i64 {
        self.maximum_lifetime_seconds
    }
}

/// State of an ingress key in the trusted local registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngressKeyStatus {
    Active,
    Disabled,
    Revoked,
}

impl IngressKeyStatus {
    const fn code(self) -> u8 {
        match self {
            Self::Active => 0,
            Self::Disabled => 1,
            Self::Revoked => 2,
        }
    }
}

/// Tenant and workload identity derived from an activated ingress registry.
///
/// The fields and constructor are intentionally private. Possessing strings
/// that name a tenant and actor is not equivalent to possessing this marker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedCaller {
    tenant: String,
    actor: String,
}

impl AuthenticatedCaller {
    fn new(tenant: String, actor: String) -> Self {
        Self { tenant, actor }
    }

    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    #[must_use]
    pub fn actor(&self) -> &str {
        &self.actor
    }
}

/// Trusted binding from one registered key to one tenant and actor.
#[derive(Clone, Debug)]
pub struct RegisteredIngressKey {
    pub key_id: String,
    pub public_key: [u8; 32],
    pub tenant: String,
    pub actor: String,
    pub allowed_audiences: BTreeSet<String>,
    pub not_before: i64,
    pub expires_at: i64,
    pub status: IngressKeyStatus,
}

/// Immutable ingress-authentication result consumed by the kernel boundary.
///
/// This type deliberately implements neither serialization nor deserialization
/// and has no public constructor. Only a successful [`IngressAuthenticator`]
/// call can create it.
///
/// ```compile_fail
/// # use accordlock_ingress::AuthenticatedIngressRequest;
/// let _: AuthenticatedIngressRequest = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct AuthenticatedIngressRequest {
    caller: AuthenticatedCaller,
    proposal: AgentProposal,
    ingress_key_id: String,
    nonce: Uuid,
    authenticated_at: i64,
    expires_at: i64,
    authority_domain: AuthorityDomainState,
}

impl AuthenticatedIngressRequest {
    #[must_use]
    pub const fn caller(&self) -> &AuthenticatedCaller {
        &self.caller
    }

    #[must_use]
    pub const fn proposal(&self) -> &AgentProposal {
        &self.proposal
    }

    #[must_use]
    pub fn ingress_key_id(&self) -> &str {
        &self.ingress_key_id
    }

    #[must_use]
    pub const fn nonce(&self) -> Uuid {
        self.nonce
    }

    #[must_use]
    pub const fn authenticated_at(&self) -> i64 {
        self.authenticated_at
    }

    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }

    #[must_use]
    pub const fn authority_domain(&self) -> &AuthorityDomainState {
        &self.authority_domain
    }
}

/// Canonical, bounded ingress-key registry activated under an exact principal
/// registry authority-domain state.
#[derive(Clone, Debug)]
pub struct ActivatedIngressRegistry {
    authority_domain: AuthorityDomainState,
    expected_audience: String,
    maximum_lifetime_seconds: i64,
    entries: Vec<RegisteredIngressKey>,
}

impl ActivatedIngressRegistry {
    /// Activates canonical registry bytes under the supplied authority state.
    ///
    /// # Errors
    ///
    /// Fails for malformed authority state, malformed or noncanonical entries,
    /// duplicate key identifiers, public-key aliases, or a root mismatch.
    pub fn new(
        authority_domain: AuthorityDomainState,
        expected_audience: impl Into<String>,
        maximum_lifetime_seconds: i64,
        entries: Vec<RegisteredIngressKey>,
    ) -> Result<Self, IngressError> {
        validate_authority_domain(&authority_domain)?;
        let expected_audience = expected_audience.into();
        let root = Self::compute_root(&expected_audience, maximum_lifetime_seconds, &entries)?;
        if root != authority_domain.root {
            return Err(IngressError::RegistryRootMismatch);
        }
        Ok(Self {
            authority_domain,
            expected_audience,
            maximum_lifetime_seconds,
            entries,
        })
    }

    /// Computes the canonical root for already sorted registry entries.
    ///
    /// # Errors
    ///
    /// Fails for empty, oversized, malformed, unsorted, duplicate, or aliased
    /// registry material.
    pub fn compute_root(
        expected_audience: &str,
        maximum_lifetime_seconds: i64,
        entries: &[RegisteredIngressKey],
    ) -> Result<Digest32, IngressError> {
        let encoded =
            canonical_registry_material(expected_audience, maximum_lifetime_seconds, entries)?;
        let mut material = Vec::with_capacity(INGRESS_REGISTRY_ROOT_DOMAIN.len() + encoded.len());
        material.extend_from_slice(INGRESS_REGISTRY_ROOT_DOMAIN);
        material.extend_from_slice(&encoded);
        Ok(Digest32::sha256(&material))
    }

    #[must_use]
    pub const fn authority_domain(&self) -> &AuthorityDomainState {
        &self.authority_domain
    }

    #[must_use]
    pub fn entries(&self) -> &[RegisteredIngressKey] {
        &self.entries
    }

    #[must_use]
    pub fn expected_audience(&self) -> &str {
        &self.expected_audience
    }

    #[must_use]
    pub const fn maximum_lifetime_seconds(&self) -> i64 {
        self.maximum_lifetime_seconds
    }
}

/// Opaque, exact replay domain derived from the configured ingress audience.
///
/// No trimming, case folding, or Unicode normalization is performed. A replay
/// tuple accepted for one audience therefore cannot be reused for another.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReplayScope(String);

impl ReplayScope {
    /// Validates and owns one exact audience replay domain.
    ///
    /// # Errors
    ///
    /// Returns [`IngressError::InvalidConfiguration`] instead of normalizing
    /// empty, padded, oversized, or control-bearing input.
    pub fn new(audience: impl Into<String>) -> Result<Self, IngressError> {
        let audience = audience.into();
        if !valid_security_text(&audience) {
            return Err(IngressError::InvalidConfiguration(
                "replay audience scope must be exact canonical security text".to_owned(),
            ));
        }
        Ok(Self(audience))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Atomic replay decision required by the authenticator.
pub trait ReplayGuard: Debug + Send + Sync {
    /// Persists one trusted clock observation without consuming a nonce.
    ///
    /// This is called only after exact key lookup, signature verification,
    /// canonical payload equality, and non-temporal request binding. It prevents
    /// an expired authenticated request from becoming valid after clock
    /// rollback.
    ///
    /// # Errors
    ///
    /// Returns [`ReplayGuardError::Unavailable`] when monotonicity or durable
    /// persistence cannot be established.
    fn observe_time(&self, scope: &ReplayScope, now: i64) -> Result<(), ReplayGuardError>;

    /// Consumes `(exact_audience_scope, key_id, nonce)` once until its signed
    /// expiration.
    ///
    /// # Errors
    ///
    /// Returns [`ReplayGuardError::AlreadyUsed`] when the nonce was previously
    /// accepted for the same key, or [`ReplayGuardError::Unavailable`] when the
    /// backend cannot establish a definitive atomic result.
    fn consume(
        &self,
        scope: &ReplayScope,
        key_id: &str,
        nonce: Uuid,
        expires_at: i64,
        now: i64,
    ) -> Result<(), ReplayGuardError>;
}

/// Replay-store failure visible to the ingress boundary.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ReplayGuardError {
    #[error("ingress nonce was already used")]
    AlreadyUsed,
    #[error("replay state is unavailable or indeterminate")]
    Unavailable,
}

/// Process-local replay guard for tests and local demonstrations.
#[derive(Debug, Default)]
pub struct MemoryReplayGuard {
    state: Mutex<MemoryReplayState>,
}

#[derive(Debug, Default)]
struct MemoryReplayState {
    used: BTreeMap<(ReplayScope, String, Uuid), i64>,
    high_water: BTreeMap<ReplayScope, i64>,
}

impl ReplayGuard for MemoryReplayGuard {
    fn observe_time(&self, scope: &ReplayScope, now: i64) -> Result<(), ReplayGuardError> {
        if now < 0 {
            return Err(ReplayGuardError::Unavailable);
        }
        let mut state = self.state.lock();
        if state
            .high_water
            .get(scope)
            .is_some_and(|high_water| now < *high_water)
        {
            return Err(ReplayGuardError::Unavailable);
        }
        state.high_water.insert(scope.clone(), now);
        Ok(())
    }

    fn consume(
        &self,
        scope: &ReplayScope,
        key_id: &str,
        nonce: Uuid,
        expires_at: i64,
        now: i64,
    ) -> Result<(), ReplayGuardError> {
        let mut state = self.state.lock();
        if now < 0
            || expires_at <= now
            || nonce.is_nil()
            || key_id.is_empty()
            || key_id.len() > accordlock_protocol::MAX_KEY_ID_BYTES
            || key_id.trim() != key_id
            || key_id.chars().any(char::is_control)
            || state
                .high_water
                .get(scope)
                .is_some_and(|high_water| now < *high_water)
        {
            return Err(ReplayGuardError::Unavailable);
        }
        state.high_water.insert(scope.clone(), now);
        let replay_key = (scope.clone(), key_id.to_owned(), nonce);
        if state
            .used
            .get(&replay_key)
            .is_some_and(|stored_expiry| *stored_expiry > now)
        {
            return Err(ReplayGuardError::AlreadyUsed);
        }
        state.used.insert(replay_key, expires_at);
        Ok(())
    }
}

/// Static local authenticator backed by a trusted key registry and an
/// injectable atomic replay guard.
#[derive(Debug)]
pub struct IngressAuthenticator<R> {
    expected_audience: String,
    replay_scope: ReplayScope,
    maximum_lifetime_seconds: i64,
    authority_domain: AuthorityDomainState,
    registrations: BTreeMap<String, RegisteredIngressKey>,
    replay_guard: R,
}

impl<R: ReplayGuard> IngressAuthenticator<R> {
    /// Builds an authenticator and rejects ambiguous or invalid registry state.
    ///
    /// # Errors
    ///
    /// Returns [`IngressError::InvalidConfiguration`] for an empty audience,
    /// nonpositive lifetime, duplicate key ID, invalid registration window, or
    /// empty identity/audience binding.
    pub fn new(registry: ActivatedIngressRegistry, replay_guard: R) -> Result<Self, IngressError> {
        let expected_audience = registry.expected_audience;
        let maximum_lifetime_seconds = registry.maximum_lifetime_seconds;
        let replay_scope = ReplayScope::new(expected_audience.clone())?;
        if maximum_lifetime_seconds <= 0 {
            return Err(IngressError::InvalidConfiguration(
                "maximum lifetime must be positive".to_owned(),
            ));
        }

        let authority_domain = registry.authority_domain;
        let mut indexed = BTreeMap::new();
        for registration in registry.entries {
            let key_id = registration.key_id.clone();
            if indexed.insert(key_id.clone(), registration).is_some() {
                return Err(IngressError::InvalidConfiguration(format!(
                    "duplicate ingress key ID after activation: {key_id}"
                )));
            }
        }

        Ok(Self {
            replay_scope,
            expected_audience,
            maximum_lifetime_seconds,
            authority_domain,
            registrations: indexed,
            replay_guard,
        })
    }

    /// Performs current-registry static verification for durable intake.
    ///
    /// This method deliberately takes no clock or replay callback. The returned
    /// opaque value proves signature/canonical payload/current registry/static
    /// identity and signed-window binding only. It must be passed directly to
    /// the state adapter, whose single transaction owns trusted time, HWM,
    /// nonce consumption, submission, status, and initial work creation.
    ///
    /// Exact historical recovery must be attempted before calling this method.
    ///
    /// # Errors
    ///
    /// Returns [`IngressError`] for any static current-registry authentication
    /// failure.
    pub fn verify_durable_static(
        &self,
        probe: IngressRecoveryProbe,
    ) -> Result<StaticallyVerifiedIngressSubmission, IngressError> {
        let registration = self
            .registrations
            .get(probe.key_id())
            .ok_or(IngressError::UnknownKey)?;
        verify_probe_signature(&probe, &registration.key_id, registration.public_key)?;
        if registration.status != IngressKeyStatus::Active {
            return Err(IngressError::KeyNotCurrent);
        }
        validate_bound_claims(
            probe.claims(),
            &self.expected_audience,
            &registration.tenant,
            &registration.actor,
            registration.not_before,
            registration.expires_at,
            self.maximum_lifetime_seconds,
        )?;
        if !registration
            .allowed_audiences
            .contains(&self.expected_audience)
        {
            return Err(IngressError::AudienceNotAllowed);
        }

        Ok(StaticallyVerifiedIngressSubmission {
            caller: AuthenticatedCaller::new(
                registration.tenant.clone(),
                registration.actor.clone(),
            ),
            request: probe.request,
            canonical_claims: probe.canonical_claims,
            replay_scope: self.replay_scope.clone(),
            maximum_lifetime_seconds: self.maximum_lifetime_seconds,
            key_public_key: registration.public_key,
            key_not_before: registration.not_before,
            key_expires_at: registration.expires_at,
            authority_domain: self.authority_domain.clone(),
            canonical_payload_commitment: probe.canonical_payload_commitment,
            wire_commitment: probe.wire_commitment,
            wire_json: probe.wire_json,
        })
    }

    /// Parses a strict JSON envelope, verifies its domain-separated Ed25519
    /// signature, enforces audience and time bounds, maps the key to its trusted
    /// identity, rejects proposal identity spoofing, and atomically consumes the
    /// nonce.
    ///
    /// `now` must come from the server's trusted clock, never from the request.
    ///
    /// # Errors
    ///
    /// Fails closed on malformed or extended JSON, unknown/inactive keys,
    /// cryptographic failure, payload mismatch, invalid audience or time,
    /// identity mismatch, replay, and indeterminate replay-store state.
    #[allow(clippy::too_many_lines)]
    pub fn authenticate_json(
        &self,
        json: &str,
        now: i64,
    ) -> Result<AuthenticatedIngressRequest, IngressError> {
        if now < 0 {
            return Err(IngressError::InvalidTrustedTime);
        }
        if json.len() > MAX_INGRESS_JSON_BYTES {
            return Err(IngressError::RequestTooLarge);
        }
        let _: DuplicateRejectingJson = serde_json::from_str(json)
            .map_err(|error| IngressError::MalformedJson(error.to_string()))?;
        let request: SignedIngressRequest = serde_json::from_str(json)
            .map_err(|error| IngressError::MalformedJson(error.to_string()))?;
        let registration = self
            .registrations
            .get(&request.key_id)
            .ok_or(IngressError::UnknownKey)?;
        let verifier =
            CoseVerifier::from_public_key(registration.key_id.clone(), registration.public_key)
                .map_err(|_| IngressError::SignatureInvalid)?;
        let signed_payload = verify_cose(&request.cose_sign1, INGRESS_REQUEST_DOMAIN, &verifier)
            .map_err(|_| IngressError::SignatureInvalid)?;
        let reconstructed = request.claims.canonical_bytes()?;
        if signed_payload != reconstructed {
            return Err(IngressError::PayloadMismatch);
        }

        if request.claims.schema_version != INGRESS_SCHEMA_VERSION {
            return Err(IngressError::UnsupportedSchemaVersion);
        }
        if request.claims.nonce.is_nil() {
            return Err(IngressError::InvalidNonce);
        }
        if registration.status != IngressKeyStatus::Active {
            return Err(IngressError::KeyNotCurrent);
        }
        if request.claims.audience != self.expected_audience
            || request.claims.proposal.template.audience != self.expected_audience
        {
            return Err(IngressError::AudienceMismatch);
        }
        if !registration
            .allowed_audiences
            .contains(&self.expected_audience)
        {
            return Err(IngressError::AudienceNotAllowed);
        }

        let lifetime = request
            .claims
            .expires_at
            .checked_sub(request.claims.issued_at)
            .ok_or(IngressError::InvalidValidityWindow)?;
        if lifetime <= 0 {
            return Err(IngressError::InvalidValidityWindow);
        }
        if request.claims.issued_at < registration.not_before
            || request.claims.expires_at > registration.expires_at
        {
            return Err(IngressError::RequestOutsideKeyValidity);
        }
        if lifetime > self.maximum_lifetime_seconds {
            return Err(IngressError::LifetimeTooLong);
        }
        if request.claims.proposal.tenant != registration.tenant
            || request.claims.proposal.actor != registration.actor
        {
            return Err(IngressError::CallerBindingMismatch);
        }

        self.replay_guard
            .observe_time(&self.replay_scope, now)
            .map_err(|_| IngressError::ReplayStateUnavailable)?;
        if now < registration.not_before || now >= registration.expires_at {
            return Err(IngressError::KeyNotCurrent);
        }
        if now < request.claims.issued_at {
            return Err(IngressError::NotYetValid);
        }
        if now >= request.claims.expires_at {
            return Err(IngressError::Expired);
        }

        match self.replay_guard.consume(
            &self.replay_scope,
            &registration.key_id,
            request.claims.nonce,
            request.claims.expires_at,
            now,
        ) {
            Ok(()) => {}
            Err(ReplayGuardError::AlreadyUsed) => return Err(IngressError::Replay),
            Err(ReplayGuardError::Unavailable) => {
                return Err(IngressError::ReplayStateUnavailable);
            }
        }

        Ok(AuthenticatedIngressRequest {
            caller: AuthenticatedCaller::new(
                registration.tenant.clone(),
                registration.actor.clone(),
            ),
            proposal: request.claims.proposal,
            ingress_key_id: registration.key_id.clone(),
            nonce: request.claims.nonce,
            authenticated_at: now,
            expires_at: request.claims.expires_at,
            authority_domain: self.authority_domain.clone(),
        })
    }
}

/// Signs a canonical ingress payload and places it in the strict JSON envelope
/// type. Serializing the returned value does not affect the signed bytes.
///
/// # Errors
///
/// Returns [`IngressError::Canonical`] if encoding or COSE signing fails.
pub fn sign_ingress_request(
    claims: IngressClaims,
    signer: &SigningIdentity,
) -> Result<SignedIngressRequest, IngressError> {
    let payload = claims.canonical_bytes()?;
    let cose_sign1 = sign_cose(&payload, INGRESS_REQUEST_DOMAIN, signer)
        .map_err(|error| IngressError::Canonical(error.to_string()))?;
    Ok(SignedIngressRequest {
        key_id: signer.key_id().to_owned(),
        claims,
        cose_sign1,
    })
}

/// Fail-closed ingress rejection categories. External APIs may intentionally
/// collapse these categories to reduce oracle detail.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IngressError {
    #[error("ingress request exceeds the accepted size limit")]
    RequestTooLarge,
    #[error("malformed ingress JSON: {0}")]
    MalformedJson(String),
    #[error("invalid ingress configuration: {0}")]
    InvalidConfiguration(String),
    #[error("activated ingress registry root does not match its canonical content")]
    RegistryRootMismatch,
    #[error("ingress canonical encoding failed: {0}")]
    Canonical(String),
    #[error("unknown ingress key")]
    UnknownKey,
    #[error("ingress key is disabled, revoked, or outside its validity window")]
    KeyNotCurrent,
    #[error("ingress signature is invalid")]
    SignatureInvalid,
    #[error("signed ingress payload does not match the JSON claims")]
    PayloadMismatch,
    #[error("unsupported ingress schema version")]
    UnsupportedSchemaVersion,
    #[error("ingress nonce must not be nil")]
    InvalidNonce,
    #[error("ingress audience does not match this service")]
    AudienceMismatch,
    #[error("registered key is not allowed for this audience")]
    AudienceNotAllowed,
    #[error("ingress validity window is invalid")]
    InvalidValidityWindow,
    #[error("trusted ingress time is invalid")]
    InvalidTrustedTime,
    #[error("ingress request validity is not contained in the registered key validity")]
    RequestOutsideKeyValidity,
    #[error("ingress validity window exceeds the configured maximum")]
    LifetimeTooLong,
    #[error("ingress request is not yet valid")]
    NotYetValid,
    #[error("ingress request has expired")]
    Expired,
    #[error("proposal tenant or actor does not match the registered caller")]
    CallerBindingMismatch,
    #[error("ingress nonce was already consumed")]
    Replay,
    #[error("ingress replay state is unavailable or indeterminate")]
    ReplayStateUnavailable,
    #[error("historical ingress envelope does not match its frozen durable verifier")]
    HistoricalRecoveryMismatch,
}

fn verify_probe_signature(
    probe: &IngressRecoveryProbe,
    key_id: &str,
    public_key: [u8; 32],
) -> Result<(), IngressError> {
    if probe.key_id() != key_id {
        return Err(IngressError::HistoricalRecoveryMismatch);
    }
    let verifier = CoseVerifier::from_public_key(key_id.to_owned(), public_key)
        .map_err(|_| IngressError::SignatureInvalid)?;
    let signed_payload = verify_cose(probe.cose_sign1(), INGRESS_REQUEST_DOMAIN, &verifier)
        .map_err(|_| IngressError::SignatureInvalid)?;
    if signed_payload != probe.canonical_claims {
        return Err(IngressError::PayloadMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_bound_claims(
    claims: &IngressClaims,
    expected_audience: &str,
    tenant: &str,
    actor: &str,
    key_not_before: i64,
    key_expires_at: i64,
    maximum_lifetime_seconds: i64,
) -> Result<(), IngressError> {
    if claims.schema_version != INGRESS_SCHEMA_VERSION {
        return Err(IngressError::UnsupportedSchemaVersion);
    }
    if claims.nonce.is_nil() {
        return Err(IngressError::InvalidNonce);
    }
    if claims.audience != expected_audience
        || claims.proposal.template.audience != expected_audience
    {
        return Err(IngressError::AudienceMismatch);
    }
    let lifetime = claims
        .expires_at
        .checked_sub(claims.issued_at)
        .ok_or(IngressError::InvalidValidityWindow)?;
    if lifetime <= 0 {
        return Err(IngressError::InvalidValidityWindow);
    }
    if claims.issued_at < key_not_before || claims.expires_at > key_expires_at {
        return Err(IngressError::RequestOutsideKeyValidity);
    }
    if lifetime > maximum_lifetime_seconds {
        return Err(IngressError::LifetimeTooLong);
    }
    if claims.proposal.tenant != tenant || claims.proposal.actor != actor {
        return Err(IngressError::CallerBindingMismatch);
    }
    Ok(())
}

fn canonical_payload_commitment(
    key_id: &str,
    canonical_claims: &[u8],
    cose_sign1: &[u8],
) -> Result<Digest32, IngressError> {
    let encoded: Result<Vec<u8>, EncodeError<Infallible>> = (|| {
        let mut encoder = Encoder::new(Vec::new());
        encoder.array(4)?;
        encoder.str(key_id)?;
        encoder.bytes(canonical_claims)?;
        encoder.bytes(cose_sign1)?;
        encoder.str(INGRESS_CANONICAL_PAYLOAD_COMMITMENT_DOMAIN)?;
        Ok(encoder.into_writer())
    })();
    encoded
        .map(|bytes| Digest32::sha256(&bytes))
        .map_err(|error| IngressError::Canonical(error.to_string()))
}

fn wire_image_commitment(wire_json: &[u8]) -> Result<Digest32, IngressError> {
    let encoded: Result<Vec<u8>, EncodeError<Infallible>> = (|| {
        let mut encoder = Encoder::new(Vec::new());
        encoder.array(2)?;
        encoder.bytes(wire_json)?;
        encoder.str(INGRESS_WIRE_COMMITMENT_DOMAIN)?;
        Ok(encoder.into_writer())
    })();
    encoded
        .map(|bytes| Digest32::sha256(&bytes))
        .map_err(|error| IngressError::Canonical(error.to_string()))
}

fn validate_authority_domain(domain: &AuthorityDomainState) -> Result<(), IngressError> {
    if domain.root == Digest32::from_bytes([0; 32])
        || domain.epoch == 0
        || domain.activation_id.is_nil()
    {
        return Err(IngressError::InvalidConfiguration(
            "ingress registry authority state is malformed".to_owned(),
        ));
    }
    Ok(())
}

fn valid_security_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SECURITY_TEXT_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn canonical_registry_material(
    expected_audience: &str,
    maximum_lifetime_seconds: i64,
    entries: &[RegisteredIngressKey],
) -> Result<Vec<u8>, IngressError> {
    if !valid_security_text(expected_audience)
        || maximum_lifetime_seconds <= 0
        || entries.is_empty()
        || entries.len() > MAX_REGISTERED_INGRESS_KEYS
    {
        return Err(IngressError::InvalidConfiguration(
            "ingress profile audience/lifetime/registry is invalid".to_owned(),
        ));
    }

    let mut previous_key_id: Option<&str> = None;
    let mut public_keys = BTreeSet::new();
    for entry in entries {
        if !valid_security_text(&entry.key_id)
            || !valid_security_text(&entry.tenant)
            || !valid_security_text(&entry.actor)
            || entry.allowed_audiences.is_empty()
            || entry.allowed_audiences.len() > MAX_AUDIENCES_PER_INGRESS_KEY
            || entry
                .allowed_audiences
                .iter()
                .any(|audience| !valid_security_text(audience))
            || entry.not_before < 0
            || entry.not_before >= entry.expires_at
        {
            return Err(IngressError::InvalidConfiguration(
                "invalid ingress registration".to_owned(),
            ));
        }
        CoseVerifier::from_public_key(entry.key_id.clone(), entry.public_key).map_err(|_| {
            IngressError::InvalidConfiguration(
                "invalid ingress verification key or key ID".to_owned(),
            )
        })?;
        if previous_key_id.is_some_and(|previous| previous >= entry.key_id.as_str()) {
            return Err(IngressError::InvalidConfiguration(
                "ingress registrations must be strictly sorted by key ID".to_owned(),
            ));
        }
        previous_key_id = Some(&entry.key_id);
        if !public_keys.insert(entry.public_key) {
            return Err(IngressError::InvalidConfiguration(
                "one ingress public key cannot identify multiple registrations".to_owned(),
            ));
        }
    }

    let encoded: Result<Vec<u8>, EncodeError<Infallible>> = (|| {
        let mut encoder = Encoder::new(Vec::new());
        encoder.array(4)?;
        encoder.str(expected_audience)?;
        encoder.i64(maximum_lifetime_seconds)?;
        encoder.array(u64::try_from(entries.len()).unwrap_or(u64::MAX))?;
        for entry in entries {
            encoder.array(9)?;
            encoder.str(&entry.key_id)?;
            encoder.bytes(&entry.public_key)?;
            encoder.str(&entry.tenant)?;
            encoder.str(&entry.actor)?;
            encoder.array(u64::try_from(entry.allowed_audiences.len()).unwrap_or(u64::MAX))?;
            for audience in &entry.allowed_audiences {
                encoder.str(audience)?;
            }
            encoder.i64(entry.not_before)?;
            encoder.i64(entry.expires_at)?;
            encoder.u8(entry.status.code())?;
            encoder.u16(1)?;
        }
        encoder.u16(2)?;
        Ok(encoder.into_writer())
    })();
    encoded.map_err(|error| IngressError::Canonical(error.to_string()))
}

/// First-pass JSON validator rejecting duplicate object keys at every nesting
/// level. This runs before typed deserialization and commitment calculation so
/// no parser differential or last-key-wins interpretation can enter v13 state.
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

mod base64url_bytes {
    use super::*;

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .map_err(de::Error::custom)?;
        if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
            return Err(de::Error::custom("noncanonical base64url encoding"));
        }
        Ok(decoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use accordlock_protocol::{DeploymentTemplate, Digest32};
    use serde_json::{Value, json};

    const NOW: i64 = 1_800_000_000;
    const AUDIENCE: &str = "accordlock-executor://tenant-a/prod/eks";

    #[derive(Debug)]
    struct UnavailableReplayGuard;

    impl ReplayGuard for UnavailableReplayGuard {
        fn observe_time(&self, _scope: &ReplayScope, _now: i64) -> Result<(), ReplayGuardError> {
            Err(ReplayGuardError::Unavailable)
        }

        fn consume(
            &self,
            _scope: &ReplayScope,
            _key_id: &str,
            _nonce: Uuid,
            _expires_at: i64,
            _now: i64,
        ) -> Result<(), ReplayGuardError> {
            Err(ReplayGuardError::Unavailable)
        }
    }

    fn signer(seed: u8) -> SigningIdentity {
        SigningIdentity::from_seed("agent-key-1", [seed; 32])
    }

    fn proposal(tenant: &str, actor: &str) -> AgentProposal {
        AgentProposal {
            schema_version: 1,
            request_id: Uuid::from_u128(1),
            tenant: tenant.to_owned(),
            actor: actor.to_owned(),
            template: DeploymentTemplate {
                operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
                environment: "prod".to_owned(),
                audience: AUDIENCE.to_owned(),
                repository: "acme/payments".to_owned(),
                commit_sha: "0123456789abcdef0123456789abcdef01234567".to_owned(),
                image_repository: "registry.example/payments".to_owned(),
                image_digest: Digest32::from_bytes([1; 32]),
                cluster_identity: "cluster-a".to_owned(),
                namespace: "payments".to_owned(),
                deployment: "api".to_owned(),
                deployment_uid: "deployment-uid".to_owned(),
                container: "api".to_owned(),
                container_index: 0,
                prior_image_digest: Digest32::from_bytes([2; 32]),
                resource_version: "42".to_owned(),
                prior_projection_hash: Digest32::from_bytes([3; 32]),
                prior_transaction_annotation: None,
                prior_authorization_annotation: None,
                prior_operation_hash_annotation: None,
            },
        }
    }

    fn claims(proposal: AgentProposal, nonce: u128) -> IngressClaims {
        IngressClaims {
            schema_version: INGRESS_SCHEMA_VERSION,
            audience: AUDIENCE.to_owned(),
            issued_at: NOW - 1,
            expires_at: NOW + 60,
            nonce: Uuid::from_u128(nonce),
            proposal,
        }
    }

    fn registration(identity: &SigningIdentity) -> RegisteredIngressKey {
        RegisteredIngressKey {
            key_id: identity.key_id().to_owned(),
            public_key: identity.public_key_bytes(),
            tenant: "tenant-a".to_owned(),
            actor: "deploy-agent".to_owned(),
            allowed_audiences: BTreeSet::from([AUDIENCE.to_owned()]),
            not_before: NOW - 100,
            expires_at: NOW + 100,
            status: IngressKeyStatus::Active,
        }
    }

    fn activated_registry(
        entries: Vec<RegisteredIngressKey>,
    ) -> Result<ActivatedIngressRegistry, IngressError> {
        let root = ActivatedIngressRegistry::compute_root(AUDIENCE, 120, &entries)?;
        ActivatedIngressRegistry::new(
            AuthorityDomainState {
                root,
                epoch: 1,
                activation_id: Uuid::from_u128(0x9001),
            },
            AUDIENCE,
            120,
            entries,
        )
    }

    fn authenticator(
        identity: &SigningIdentity,
    ) -> Result<IngressAuthenticator<MemoryReplayGuard>, IngressError> {
        IngressAuthenticator::new(
            activated_registry(vec![registration(identity)])?,
            MemoryReplayGuard::default(),
        )
    }

    #[test]
    fn one_public_key_cannot_alias_two_registered_callers() {
        let identity = signer(1);
        let first = registration(&identity);
        let mut alias = first.clone();
        alias.key_id = "admin-key".to_owned();
        alias.actor = "admin".to_owned();

        let mut entries = vec![first, alias];
        entries.sort_by(|left, right| left.key_id.cmp(&right.key_id));

        assert!(matches!(
            ActivatedIngressRegistry::compute_root(AUDIENCE, 120, &entries),
            Err(IngressError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn weak_registered_public_key_is_rejected_before_serving_requests() {
        let identity = signer(1);
        let mut weak = registration(&identity);
        weak.public_key = [0; 32];
        weak.public_key[0] = 1;

        assert!(matches!(
            ActivatedIngressRegistry::compute_root(AUDIENCE, 120, &[weak]),
            Err(IngressError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn activated_registry_root_binds_identity_audience_status_and_time()
    -> Result<(), Box<dyn std::error::Error>> {
        let identity = signer(1);
        let original = registration(&identity);
        let root =
            ActivatedIngressRegistry::compute_root(AUDIENCE, 120, std::slice::from_ref(&original))?;
        let domain = AuthorityDomainState {
            root,
            epoch: 1,
            activation_id: Uuid::from_u128(0x9002),
        };
        assert!(
            ActivatedIngressRegistry::new(domain.clone(), AUDIENCE, 120, vec![original.clone()])
                .is_ok()
        );
        assert!(matches!(
            ActivatedIngressRegistry::new(
                domain.clone(),
                "accordlock-control://tenant-a/other",
                120,
                vec![original.clone()],
            ),
            Err(IngressError::RegistryRootMismatch)
        ));
        assert!(matches!(
            ActivatedIngressRegistry::new(domain.clone(), AUDIENCE, 121, vec![original.clone()]),
            Err(IngressError::RegistryRootMismatch)
        ));

        let mut mutations = Vec::new();
        let mut tenant = original.clone();
        tenant.tenant = "tenant-b".to_owned();
        mutations.push(tenant);
        let mut actor = original.clone();
        actor.actor = "admin".to_owned();
        mutations.push(actor);
        let mut audience = original.clone();
        audience.allowed_audiences = BTreeSet::from(["other-audience".to_owned()]);
        mutations.push(audience);
        let mut status = original.clone();
        status.status = IngressKeyStatus::Revoked;
        mutations.push(status);
        let mut window = original;
        window.expires_at += 1;
        mutations.push(window);

        for mutation in mutations {
            assert!(matches!(
                ActivatedIngressRegistry::new(domain.clone(), AUDIENCE, 120, vec![mutation]),
                Err(IngressError::RegistryRootMismatch)
            ));
        }
        Ok(())
    }

    #[test]
    fn registry_authority_epoch_and_activation_are_preserved_in_output()
    -> Result<(), Box<dyn std::error::Error>> {
        let identity = signer(1);
        let registration = registration(&identity);
        let root = ActivatedIngressRegistry::compute_root(
            AUDIENCE,
            120,
            std::slice::from_ref(&registration),
        )?;
        let authority_domain = AuthorityDomainState {
            root,
            epoch: 7,
            activation_id: Uuid::from_u128(0x9003),
        };
        let registry = ActivatedIngressRegistry::new(
            authority_domain.clone(),
            AUDIENCE,
            120,
            vec![registration],
        )?;
        let authenticator = IngressAuthenticator::new(registry, MemoryReplayGuard::default())?;
        let json = request_json(&identity, claims(proposal("tenant-a", "deploy-agent"), 15))?;
        let accepted = authenticator.authenticate_json(&json, NOW)?;
        assert_eq!(accepted.authority_domain(), &authority_domain);
        Ok(())
    }

    fn request_json(
        identity: &SigningIdentity,
        request_claims: IngressClaims,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let request = sign_ingress_request(request_claims, identity)?;
        Ok(serde_json::to_string(&request)?)
    }

    fn frozen_from_verified(
        verified: &StaticallyVerifiedIngressSubmission,
    ) -> Result<FrozenIngressVerifier, IngressError> {
        FrozenIngressVerifier::from_persisted(
            verified.canonical_payload_commitment(),
            verified.key_id().to_owned(),
            verified.key_public_key(),
            verified.caller().tenant().to_owned(),
            verified.caller().actor().to_owned(),
            verified.claims().audience.clone(),
            verified.key_not_before(),
            verified.key_expires_at(),
            verified.maximum_lifetime_seconds(),
            verified.authority_domain().clone(),
        )
    }

    #[test]
    fn canonical_recovery_identity_ignores_equivalent_json_reserialization()
    -> Result<(), Box<dyn std::error::Error>> {
        let identity = signer(1);
        let compact = request_json(
            &identity,
            claims(proposal("tenant-a", "deploy-agent"), 0xd001),
        )?;
        let value: Value = serde_json::from_str(&compact)?;
        let pretty = serde_json::to_string_pretty(&value)?;
        assert_ne!(compact.as_bytes(), pretty.as_bytes());

        let compact_probe = IngressRecoveryProbe::parse_json(&compact)?;
        let pretty_probe = IngressRecoveryProbe::parse_json(&pretty)?;
        assert_eq!(
            compact_probe.canonical_payload_commitment(),
            pretty_probe.canonical_payload_commitment()
        );
        assert_ne!(
            compact_probe.wire_commitment(),
            pretty_probe.wire_commitment()
        );
        Ok(())
    }

    #[test]
    fn duplicate_nested_json_key_is_rejected_by_durable_and_legacy_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        let identity = signer(1);
        let auth = authenticator(&identity)?;
        let valid = request_json(
            &identity,
            claims(proposal("tenant-a", "deploy-agent"), 0xd002),
        )?;
        let duplicate = valid.replacen(
            "\"tenant\":\"tenant-a\"",
            "\"tenant\":\"tenant-a\",\"tenant\":\"tenant-a\"",
            1,
        );
        assert_ne!(valid, duplicate);
        assert!(matches!(
            IngressRecoveryProbe::parse_json(&duplicate),
            Err(IngressError::MalformedJson(message))
                if message.contains("duplicate JSON key")
        ));
        assert!(matches!(
            auth.authenticate_json(&duplicate, NOW),
            Err(IngressError::MalformedJson(message))
                if message.contains("duplicate JSON key")
        ));
        Ok(())
    }

    #[test]
    fn frozen_historical_verification_survives_expiry_and_registry_rotation()
    -> Result<(), Box<dyn std::error::Error>> {
        let identity = signer(1);
        let auth = authenticator(&identity)?;
        let json = request_json(
            &identity,
            claims(proposal("tenant-a", "deploy-agent"), 0xd003),
        )?;
        let verified = auth.verify_durable_static(IngressRecoveryProbe::parse_json(&json)?)?;
        let frozen = frozen_from_verified(&verified)?;

        // No current registry or current-time input participates in this
        // historical check. It remains inert even long after signed expiry.
        let historical = IngressRecoveryProbe::parse_json(&json)?.verify_historical(&frozen)?;
        assert_eq!(
            historical.canonical_payload_commitment(),
            verified.canonical_payload_commitment()
        );
        assert_eq!(historical.claims().expires_at, NOW + 60);

        let rotated_identity = signer(2);
        let rotated = authenticator(&rotated_identity)?;
        assert_eq!(
            rotated.verify_durable_static(IngressRecoveryProbe::parse_json(&json)?),
            Err(IngressError::SignatureInvalid)
        );
        assert!(
            IngressRecoveryProbe::parse_json(&json)?
                .verify_historical(&frozen)
                .is_ok()
        );
        Ok(())
    }

    #[test]
    fn historical_recovery_fails_closed_on_payload_verifier_and_identity_mismatch()
    -> Result<(), Box<dyn std::error::Error>> {
        let identity = signer(1);
        let auth = authenticator(&identity)?;
        let json = request_json(
            &identity,
            claims(proposal("tenant-a", "deploy-agent"), 0xd004),
        )?;
        let verified = auth.verify_durable_static(IngressRecoveryProbe::parse_json(&json)?)?;
        let valid = frozen_from_verified(&verified)?;

        let mismatched_payload = FrozenIngressVerifier::from_persisted(
            Digest32::from_bytes([9; 32]),
            valid.key_id().to_owned(),
            valid.public_key(),
            valid.tenant().to_owned(),
            valid.actor().to_owned(),
            valid.audience().to_owned(),
            valid.key_not_before(),
            valid.key_expires_at(),
            valid.maximum_lifetime_seconds(),
            valid.authority_domain().clone(),
        )?;
        assert_eq!(
            IngressRecoveryProbe::parse_json(&json)?.verify_historical(&mismatched_payload),
            Err(IngressError::HistoricalRecoveryMismatch)
        );

        let wrong_identity = FrozenIngressVerifier::from_persisted(
            valid.canonical_payload_commitment(),
            valid.key_id().to_owned(),
            valid.public_key(),
            valid.tenant().to_owned(),
            "different-actor".to_owned(),
            valid.audience().to_owned(),
            valid.key_not_before(),
            valid.key_expires_at(),
            valid.maximum_lifetime_seconds(),
            valid.authority_domain().clone(),
        )?;
        assert_eq!(
            IngressRecoveryProbe::parse_json(&json)?.verify_historical(&wrong_identity),
            Err(IngressError::CallerBindingMismatch)
        );

        let other = signer(2);
        let wrong_key = FrozenIngressVerifier::from_persisted(
            valid.canonical_payload_commitment(),
            valid.key_id().to_owned(),
            other.public_key_bytes(),
            valid.tenant().to_owned(),
            valid.actor().to_owned(),
            valid.audience().to_owned(),
            valid.key_not_before(),
            valid.key_expires_at(),
            valid.maximum_lifetime_seconds(),
            valid.authority_domain().clone(),
        )?;
        assert_eq!(
            IngressRecoveryProbe::parse_json(&json)?.verify_historical(&wrong_key),
            Err(IngressError::SignatureInvalid)
        );
        Ok(())
    }

    #[test]
    fn durable_static_verification_has_no_clock_and_rejects_tampering()
    -> Result<(), Box<dyn std::error::Error>> {
        let identity = signer(1);
        let auth = authenticator(&identity)?;
        let json = request_json(
            &identity,
            claims(proposal("tenant-a", "deploy-agent"), 0xd005),
        )?;
        // Expiry is deliberately left to state-owned trusted time/HWM.
        assert!(
            auth.verify_durable_static(IngressRecoveryProbe::parse_json(&json)?)
                .is_ok()
        );

        let mut tampered: Value = serde_json::from_str(&json)?;
        tampered["claims"]["proposal"]["actor"] = json!("admin");
        let tampered = serde_json::to_string(&tampered)?;
        assert_eq!(
            auth.verify_durable_static(IngressRecoveryProbe::parse_json(&tampered)?),
            Err(IngressError::PayloadMismatch)
        );
        Ok(())
    }

    #[test]
    fn valid_request_derives_caller_from_registry() -> Result<(), Box<dyn std::error::Error>> {
        let identity = signer(1);
        let auth = authenticator(&identity)?;
        let json = request_json(&identity, claims(proposal("tenant-a", "deploy-agent"), 1))?;

        let accepted = auth.authenticate_json(&json, NOW)?;

        assert_eq!(accepted.caller().tenant(), "tenant-a");
        assert_eq!(accepted.caller().actor(), "deploy-agent");
        assert_eq!(accepted.proposal().tenant, accepted.caller().tenant());
        assert_eq!(accepted.proposal().actor, accepted.caller().actor());
        assert_eq!(accepted.authenticated_at(), NOW);
        assert_eq!(accepted.expires_at(), NOW + 60);
        assert_eq!(accepted.ingress_key_id(), identity.key_id());
        assert_eq!(accepted.nonce(), Uuid::from_u128(1));
        Ok(())
    }

    #[test]
    fn oversized_request_is_rejected_before_json_parsing() -> Result<(), Box<dyn std::error::Error>>
    {
        let identity = signer(1);
        let auth = authenticator(&identity)?;
        let oversized = " ".repeat(MAX_INGRESS_JSON_BYTES + 1);

        assert_eq!(
            auth.authenticate_json(&oversized, NOW),
            Err(IngressError::RequestTooLarge)
        );
        Ok(())
    }

    #[test]
    fn signed_actor_and_tenant_spoofing_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let identity = signer(1);
        let auth = authenticator(&identity)?;

        let actor_spoof = request_json(&identity, claims(proposal("tenant-a", "admin"), 2))?;
        assert_eq!(
            auth.authenticate_json(&actor_spoof, NOW),
            Err(IngressError::CallerBindingMismatch)
        );

        let tenant_spoof =
            request_json(&identity, claims(proposal("tenant-b", "deploy-agent"), 3))?;
        assert_eq!(
            auth.authenticate_json(&tenant_spoof, NOW),
            Err(IngressError::CallerBindingMismatch)
        );
        Ok(())
    }

    #[test]
    fn replay_is_rejected_after_one_acceptance() -> Result<(), Box<dyn std::error::Error>> {
        let identity = signer(1);
        let auth = authenticator(&identity)?;
        let json = request_json(&identity, claims(proposal("tenant-a", "deploy-agent"), 4))?;

        assert!(auth.authenticate_json(&json, NOW).is_ok());
        assert_eq!(
            auth.authenticate_json(&json, NOW),
            Err(IngressError::Replay)
        );
        Ok(())
    }

    #[test]
    fn nil_nonce_is_rejected_before_it_can_advance_replay_time()
    -> Result<(), Box<dyn std::error::Error>> {
        let identity = signer(1);
        let auth = authenticator(&identity)?;
        let nil = request_json(&identity, claims(proposal("tenant-a", "deploy-agent"), 0))?;
        assert_eq!(
            auth.authenticate_json(&nil, NOW + 50),
            Err(IngressError::InvalidNonce)
        );

        let valid = request_json(
            &identity,
            claims(proposal("tenant-a", "deploy-agent"), 0xf1),
        )?;
        assert!(auth.authenticate_json(&valid, NOW).is_ok());
        Ok(())
    }

    #[test]
    fn direct_invalid_memory_calls_do_not_poison_high_water()
    -> Result<(), Box<dyn std::error::Error>> {
        let guard = MemoryReplayGuard::default();
        let scope = ReplayScope::new(AUDIENCE)?;
        guard.observe_time(&scope, 20)?;
        assert_eq!(
            guard.consume(&scope, "key-a", Uuid::nil(), 40, 30),
            Err(ReplayGuardError::Unavailable)
        );
        assert_eq!(
            guard.consume(&scope, "key-a", Uuid::from_u128(0xf2), 30, 30),
            Err(ReplayGuardError::Unavailable)
        );
        assert_eq!(
            guard.consume(&scope, " key-a", Uuid::from_u128(0xf2), 40, 30),
            Err(ReplayGuardError::Unavailable)
        );
        assert_eq!(
            guard.observe_time(&scope, -1),
            Err(ReplayGuardError::Unavailable)
        );
        guard.observe_time(&scope, 21)?;
        Ok(())
    }

    #[test]
    fn memory_replay_tuple_is_bound_to_exact_audience_scope()
    -> Result<(), Box<dyn std::error::Error>> {
        let guard = MemoryReplayGuard::default();
        let first = ReplayScope::new("accordlock://tenant-a/prod")?;
        let second = ReplayScope::new("accordlock://tenant-b/prod")?;
        let nonce = Uuid::from_u128(0xf3);
        guard.consume(&first, "key-a", nonce, 20, 10)?;
        guard.consume(&second, "key-a", nonce, 20, 10)?;
        assert_eq!(
            guard.consume(&first, "key-a", nonce, 21, 19),
            Err(ReplayGuardError::AlreadyUsed)
        );
        guard.consume(&first, "key-a", nonce, 30, 20)?;
        Ok(())
    }

    #[test]
    fn local_replay_guard_fails_closed_on_clock_rollback() -> Result<(), Box<dyn std::error::Error>>
    {
        let identity = signer(1);
        let auth = authenticator(&identity)?;
        let original = request_json(&identity, claims(proposal("tenant-a", "deploy-agent"), 13))?;
        assert!(auth.authenticate_json(&original, NOW).is_ok());

        let mut later_claims = claims(proposal("tenant-a", "deploy-agent"), 14);
        later_claims.issued_at = NOW + 69;
        later_claims.expires_at = NOW + 90;
        let later = request_json(&identity, later_claims)?;
        assert!(auth.authenticate_json(&later, NOW + 70).is_ok());

        assert_eq!(
            auth.authenticate_json(&original, NOW + 10),
            Err(IngressError::ReplayStateUnavailable)
        );
        Ok(())
    }

    #[test]
    fn unavailable_replay_state_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let identity = signer(1);
        let auth = IngressAuthenticator::new(
            activated_registry(vec![registration(&identity)])?,
            UnavailableReplayGuard,
        )?;
        let json = request_json(&identity, claims(proposal("tenant-a", "deploy-agent"), 12))?;

        assert_eq!(
            auth.authenticate_json(&json, NOW),
            Err(IngressError::ReplayStateUnavailable)
        );
        Ok(())
    }

    #[test]
    fn wrong_audience_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let identity = signer(1);
        let auth = authenticator(&identity)?;
        let mut wrong = claims(proposal("tenant-a", "deploy-agent"), 5);
        wrong.audience = "accordlock-executor://tenant-a/dev/eks".to_owned();
        let json = request_json(&identity, wrong)?;

        assert_eq!(
            auth.authenticate_json(&json, NOW),
            Err(IngressError::AudienceMismatch)
        );
        Ok(())
    }

    #[test]
    fn template_audience_cannot_diverge_from_ingress_audience()
    -> Result<(), Box<dyn std::error::Error>> {
        let identity = signer(1);
        let auth = authenticator(&identity)?;
        let mut divergent = proposal("tenant-a", "deploy-agent");
        divergent.template.audience = "accordlock-executor://tenant-a/dev/eks".to_owned();
        let json = request_json(&identity, claims(divergent, 11))?;

        assert_eq!(
            auth.authenticate_json(&json, NOW),
            Err(IngressError::AudienceMismatch)
        );
        Ok(())
    }

    #[test]
    fn wrong_domain_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let identity = signer(1);
        let auth = authenticator(&identity)?;
        let request_claims = claims(proposal("tenant-a", "deploy-agent"), 6);
        let cose_sign1 = sign_cose(
            &request_claims.canonical_bytes()?,
            "accordlock:v1:execution-authorization",
            &identity,
        )?;
        let request = SignedIngressRequest {
            key_id: identity.key_id().to_owned(),
            claims: request_claims,
            cose_sign1,
        };

        assert_eq!(
            auth.authenticate_json(&serde_json::to_string(&request)?, NOW),
            Err(IngressError::SignatureInvalid)
        );
        Ok(())
    }

    #[test]
    fn wrong_key_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let registered = signer(1);
        let impostor = signer(2);
        let auth = authenticator(&registered)?;
        let json = request_json(&impostor, claims(proposal("tenant-a", "deploy-agent"), 7))?;

        assert_eq!(
            auth.authenticate_json(&json, NOW),
            Err(IngressError::SignatureInvalid)
        );
        Ok(())
    }

    #[test]
    fn expired_request_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let identity = signer(1);
        let auth = authenticator(&identity)?;
        let mut expired = claims(proposal("tenant-a", "deploy-agent"), 8);
        expired.issued_at = NOW - 60;
        expired.expires_at = NOW;
        let json = request_json(&identity, expired)?;

        assert_eq!(
            auth.authenticate_json(&json, NOW),
            Err(IngressError::Expired)
        );
        assert_eq!(
            auth.authenticate_json(&json, NOW - 1),
            Err(IngressError::ReplayStateUnavailable)
        );
        Ok(())
    }

    #[test]
    fn signed_window_must_be_contained_in_registered_key_window()
    -> Result<(), Box<dyn std::error::Error>> {
        let identity = signer(1);
        let auth = authenticator(&identity)?;

        let mut starts_too_early = claims(proposal("tenant-a", "deploy-agent"), 16);
        starts_too_early.issued_at = NOW - 101;
        starts_too_early.expires_at = NOW + 1;
        let json = request_json(&identity, starts_too_early)?;
        assert_eq!(
            auth.authenticate_json(&json, NOW),
            Err(IngressError::RequestOutsideKeyValidity)
        );

        let mut ends_too_late = claims(proposal("tenant-a", "deploy-agent"), 17);
        ends_too_late.expires_at = NOW + 101;
        let json = request_json(&identity, ends_too_late)?;
        assert_eq!(
            auth.authenticate_json(&json, NOW),
            Err(IngressError::RequestOutsideKeyValidity)
        );
        Ok(())
    }

    #[test]
    fn negative_trusted_time_fails_closed_before_parsing() -> Result<(), Box<dyn std::error::Error>>
    {
        let identity = signer(1);
        let auth = authenticator(&identity)?;
        assert_eq!(
            auth.authenticate_json("not-json", -1),
            Err(IngressError::InvalidTrustedTime)
        );
        Ok(())
    }

    #[test]
    fn unknown_outer_and_nested_fields_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let identity = signer(1);
        let auth = authenticator(&identity)?;
        let signed =
            sign_ingress_request(claims(proposal("tenant-a", "deploy-agent"), 9), &identity)?;
        let mut outer: Value = serde_json::to_value(&signed)?;
        outer["trusted_actor"] = json!("admin");
        assert!(matches!(
            auth.authenticate_json(&serde_json::to_string(&outer)?, NOW),
            Err(IngressError::MalformedJson(_))
        ));

        let mut nested: Value = serde_json::to_value(&signed)?;
        nested["claims"]["proposal"]["grade"] = json!(4);
        assert!(matches!(
            auth.authenticate_json(&serde_json::to_string(&nested)?, NOW),
            Err(IngressError::MalformedJson(_))
        ));
        Ok(())
    }

    #[test]
    fn claims_changed_after_signing_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let identity = signer(1);
        let auth = authenticator(&identity)?;
        let mut request =
            sign_ingress_request(claims(proposal("tenant-a", "deploy-agent"), 10), &identity)?;
        request.claims.proposal.template.namespace = "kube-system".to_owned();

        assert_eq!(
            auth.authenticate_json(&serde_json::to_string(&request)?, NOW),
            Err(IngressError::PayloadMismatch)
        );
        Ok(())
    }
}
