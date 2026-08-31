use core::fmt;

use accordlock_protocol::{
    CanonicalEncode, CanonicalError, CoseVerifier, CryptoError, Digest32, MAX_COSE_SIZE_BYTES,
    MAX_KEY_ID_BYTES, SigningIdentity, evaluator_verifier_root, sign_cose, verify_cose,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{IntentEvaluationProfile, IntentEvidenceRequest, IntentStage, PolicyEvaluationError};

/// Maximum combined canonical material for request-stage evaluation.
pub const MAX_REQUEST_EVIDENCE_MATERIAL_BYTES: usize = 256 * 1024;
/// Maximum combined canonical material for plan-stage evaluation.
pub const MAX_PLAN_EVIDENCE_MATERIAL_BYTES: usize = 512 * 1024;
/// Maximum combined canonical material for action-stage evaluation.
pub const MAX_ACTION_EVIDENCE_MATERIAL_BYTES: usize = 1024 * 1024;
/// Maximum combined canonical material for result-stage evaluation.
pub const MAX_RESULT_EVIDENCE_MATERIAL_BYTES: usize = 1024 * 1024;
pub const EXTERNAL_DISCLOSURE_GRANT_SCHEMA_VERSION: u16 = 1;
pub const MAX_EXTERNAL_DISCLOSURE_GRANT_LIFETIME_SECONDS: i64 = 300;
pub const EXTERNAL_DISCLOSURE_GRANT_SIGNATURE_DOMAIN: &str =
    "accordlock:v1:external-evidence-disclosure-grant";

/// Exact disclosure boundary attached to an evidence request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum EvidenceDisclosurePolicy {
    /// Material must remain in the trusted local process boundary.
    LocalOnly,
    /// Material may be disclosed only to one provider through one egress policy
    /// and authenticated by one exact provider trust root.
    AllowlistedExternal {
        provider_id_hash: Digest32,
        egress_policy_hash: Digest32,
        provider_trust_root: Digest32,
        egress_authority_root: Digest32,
    },
}

impl EvidenceDisclosurePolicy {
    pub(crate) const fn code(&self) -> u8 {
        match self {
            Self::LocalOnly => 0,
            Self::AllowlistedExternal { .. } => 1,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), PolicyEvaluationError> {
        match self {
            Self::LocalOnly => Ok(()),
            Self::AllowlistedExternal {
                provider_id_hash,
                egress_policy_hash,
                provider_trust_root,
                egress_authority_root,
            } => {
                require_digest(*provider_id_hash, "provider_id_hash")?;
                require_digest(*egress_policy_hash, "egress_policy_hash")?;
                require_digest(*provider_trust_root, "provider_trust_root")?;
                require_digest(*egress_authority_root, "egress_authority_root")
            }
        }
    }
}

/// Signed authorization issued by the pinned egress authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalEvidenceDisclosureGrant {
    pub schema_version: u16,
    pub source_request_hash: Digest32,
    pub task_hash: Digest32,
    pub trace_id: Uuid,
    pub evaluation_profile: IntentEvaluationProfile,
    pub stage: IntentStage,
    pub provider_id_hash: Digest32,
    pub egress_policy_hash: Digest32,
    pub provider_trust_root: Digest32,
    pub challenge_hash: Digest32,
    pub authority_key_id: String,
    pub egress_authority_root: Digest32,
    pub issued_at: i64,
    pub valid_until: i64,
    pub cose_sign1: Vec<u8>,
}

/// Opaque proof that a grant was authenticated for one exact request.
pub struct VerifiedExternalEvidenceDisclosure {
    source_request_hash: Digest32,
    provider_id_hash: Digest32,
    egress_policy_hash: Digest32,
    provider_trust_root: Digest32,
    verified_at: i64,
    valid_until: i64,
}

impl fmt::Debug for VerifiedExternalEvidenceDisclosure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedExternalEvidenceDisclosure")
            .field("source_request_hash", &self.source_request_hash)
            .field("provider_id_hash", &self.provider_id_hash)
            .field("egress_policy_hash", &self.egress_policy_hash)
            .field("provider_trust_root", &self.provider_trust_root)
            .field("verified_at", &self.verified_at)
            .field("valid_until", &self.valid_until)
            .field("material", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum ExternalDisclosureAuthorizationError {
    #[error("external disclosure policy does not match")]
    PolicyMismatch,
    #[error("external disclosure grant has an invalid shape")]
    InvalidGrant,
    #[error("external disclosure authority key identifier does not match")]
    WrongKeyId,
    #[error("external disclosure authority root does not match")]
    WrongAuthorityRoot,
    #[error("external disclosure grant scope or request does not match")]
    ScopeMismatch,
    #[error("external disclosure grant is not yet valid")]
    NotYetValid,
    #[error("external disclosure grant has expired")]
    Expired,
    #[error("external disclosure cryptographic verification failed: {0}")]
    Crypto(#[from] CryptoError),
    #[error("external disclosure canonical encoding failed: {0}")]
    Canonical(#[from] CanonicalError),
    #[error("external disclosure request is invalid: {0}")]
    InvalidRequest(#[from] PolicyEvaluationError),
}

impl ExternalEvidenceDisclosureGrant {
    /// Issues a signed grant from the exact authority pinned by the request.
    ///
    /// # Errors
    ///
    /// Rejects an invalid request, disclosure-policy mismatch, wrong signing
    /// authority, invalid time window, or cryptographic encoding failure.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        request: &IntentEvidenceRequest,
        issued_at: i64,
        valid_until: i64,
        identity: &SigningIdentity,
    ) -> Result<Self, ExternalDisclosureAuthorizationError> {
        request.validate()?;
        let EvidenceDisclosurePolicy::AllowlistedExternal {
            provider_id_hash,
            egress_policy_hash,
            provider_trust_root,
            egress_authority_root,
        } = request.disclosure_policy
        else {
            return Err(ExternalDisclosureAuthorizationError::PolicyMismatch);
        };
        let actual_root = evaluator_verifier_root(identity.key_id(), identity.public_key_bytes())?;
        if actual_root != egress_authority_root {
            return Err(ExternalDisclosureAuthorizationError::WrongAuthorityRoot);
        }
        validate_grant_window(request.requested_at, issued_at, valid_until)?;
        let mut grant = Self {
            schema_version: EXTERNAL_DISCLOSURE_GRANT_SCHEMA_VERSION,
            source_request_hash: request.digest()?,
            task_hash: request.task_hash,
            trace_id: request.trace_id,
            evaluation_profile: request.evaluation_profile,
            stage: request.stage,
            provider_id_hash,
            egress_policy_hash,
            provider_trust_root,
            challenge_hash: request.challenge_hash,
            authority_key_id: identity.key_id().to_owned(),
            egress_authority_root,
            issued_at,
            valid_until,
            cose_sign1: Vec::new(),
        };
        grant.cose_sign1 = sign_cose(
            &grant.attestation().canonical_bytes()?,
            EXTERNAL_DISCLOSURE_GRANT_SIGNATURE_DOMAIN,
            identity,
        )?;
        grant.validate_shape()?;
        Ok(grant)
    }

    /// Authenticates this grant and returns an opaque disclosure capability.
    ///
    /// # Errors
    ///
    /// Rejects every request, scope, identity, signature, challenge, or
    /// freshness mismatch.
    pub fn verify_for(
        &self,
        request: &IntentEvidenceRequest,
        verifier: &CoseVerifier,
        verified_at: i64,
    ) -> Result<VerifiedExternalEvidenceDisclosure, ExternalDisclosureAuthorizationError> {
        request.validate()?;
        self.validate_shape()?;
        let EvidenceDisclosurePolicy::AllowlistedExternal {
            provider_id_hash,
            egress_policy_hash,
            provider_trust_root,
            egress_authority_root,
        } = request.disclosure_policy
        else {
            return Err(ExternalDisclosureAuthorizationError::PolicyMismatch);
        };
        if self.authority_key_id != verifier.key_id() {
            return Err(ExternalDisclosureAuthorizationError::WrongKeyId);
        }
        let actual_root = evaluator_verifier_root(verifier.key_id(), verifier.public_key_bytes())?;
        if self.egress_authority_root != egress_authority_root
            || actual_root != egress_authority_root
        {
            return Err(ExternalDisclosureAuthorizationError::WrongAuthorityRoot);
        }
        if self.source_request_hash != request.digest()?
            || self.task_hash != request.task_hash
            || self.trace_id != request.trace_id
            || self.evaluation_profile != request.evaluation_profile
            || self.stage != request.stage
            || self.provider_id_hash != provider_id_hash
            || self.egress_policy_hash != egress_policy_hash
            || self.provider_trust_root != provider_trust_root
            || self.challenge_hash != request.challenge_hash
        {
            return Err(ExternalDisclosureAuthorizationError::ScopeMismatch);
        }
        validate_grant_window(request.requested_at, self.issued_at, self.valid_until)?;
        if verified_at < self.issued_at {
            return Err(ExternalDisclosureAuthorizationError::NotYetValid);
        }
        if verified_at > self.valid_until {
            return Err(ExternalDisclosureAuthorizationError::Expired);
        }
        let expected = self.attestation().canonical_bytes()?;
        let actual = verify_cose(
            &self.cose_sign1,
            EXTERNAL_DISCLOSURE_GRANT_SIGNATURE_DOMAIN,
            verifier,
        )?;
        if actual != expected {
            return Err(ExternalDisclosureAuthorizationError::ScopeMismatch);
        }
        Ok(VerifiedExternalEvidenceDisclosure {
            source_request_hash: self.source_request_hash,
            provider_id_hash,
            egress_policy_hash,
            provider_trust_root,
            verified_at,
            valid_until: self.valid_until,
        })
    }

    fn validate_shape(&self) -> Result<(), ExternalDisclosureAuthorizationError> {
        if self.schema_version != EXTERNAL_DISCLOSURE_GRANT_SCHEMA_VERSION
            || self.authority_key_id.is_empty()
            || self.authority_key_id.len() > MAX_KEY_ID_BYTES
            || self.authority_key_id.trim() != self.authority_key_id
            || self.cose_sign1.is_empty()
            || self.cose_sign1.len() > MAX_COSE_SIZE_BYTES
        {
            return Err(ExternalDisclosureAuthorizationError::InvalidGrant);
        }
        Ok(())
    }

    fn attestation(&self) -> ExternalDisclosureAttestation<'_> {
        ExternalDisclosureAttestation { grant: self }
    }
}

pub(crate) struct ExternalDisclosureAttestation<'a> {
    pub(crate) grant: &'a ExternalEvidenceDisclosureGrant,
}

/// Stable artifact labels used by typed resolver errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceMaterialKind {
    Request,
    Proposal,
    Context,
    ResolverPolicy,
}

/// Fail-closed resolver and disclosure errors that never carry raw material.
#[derive(Debug, Error)]
pub enum EvidenceMaterialError {
    #[error("resolved material belongs to another task")]
    CrossTask,
    #[error("resolved material belongs to another trace")]
    CrossTrace,
    #[error("resolved {0:?} material does not match its commitment")]
    WrongHash(EvidenceMaterialKind),
    #[error("resolved material exceeds the {stage:?} bound: {actual} > {maximum}")]
    Oversize {
        stage: IntentStage,
        maximum: usize,
        actual: usize,
    },
    #[error("required evidence material is missing: {0:?}")]
    Missing(EvidenceMaterialKind),
    #[error("evidence material is temporarily unavailable")]
    Unavailable,
    #[error("the requested material disclosure is not permitted")]
    DisclosureDenied,
    #[error("the evidence request is malformed: {0}")]
    InvalidRequest(PolicyEvaluationError),
}

/// Conservative integration disposition for resolver failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceResolutionDisposition {
    Review,
    Deny,
}

impl EvidenceMaterialError {
    /// Maps unavailable or missing content to abstention/review. Structural,
    /// scope, integrity, and disclosure failures remain denials. There is no
    /// `ALLOW` disposition.
    #[must_use]
    pub const fn disposition(&self) -> EvidenceResolutionDisposition {
        match self {
            Self::Missing(_) | Self::Unavailable => EvidenceResolutionDisposition::Review,
            Self::CrossTask
            | Self::CrossTrace
            | Self::WrongHash(_)
            | Self::Oversize { .. }
            | Self::DisclosureDenied
            | Self::InvalidRequest(_) => EvidenceResolutionDisposition::Deny,
        }
    }
}

/// Trusted resolver boundary for committed evidence artifacts.
pub trait EvidenceArtifactResolver {
    /// Resolves and validates the exact data plane for `request`.
    ///
    /// # Errors
    ///
    /// Returns a typed [`EvidenceMaterialError`]. Missing and unavailable
    /// material must map to review, never automatic execution.
    fn resolve(
        &self,
        request: &IntentEvidenceRequest,
    ) -> Result<BoundedEvidenceMaterial, EvidenceMaterialError>;
}

/// Exact, bounded material held behind the trusted resolver boundary.
///
/// This type is deliberately neither serializable nor deserializable. Its
/// custom `Debug` output reports commitments and sizes only.
#[derive(Clone, PartialEq, Eq)]
pub struct BoundedEvidenceMaterial {
    task_hash: Digest32,
    trace_id: Uuid,
    profile: IntentEvaluationProfile,
    stage: IntentStage,
    source_request_hash: Digest32,
    resolver_policy_hash: Digest32,
    disclosure_policy: EvidenceDisclosurePolicy,
    request_material: Vec<u8>,
    proposal_material: Vec<u8>,
    context_material: Vec<u8>,
}

impl BoundedEvidenceMaterial {
    /// Constructs the data plane from exact canonical bytes returned by a
    /// trusted resolver.
    ///
    /// `resolver_policy_hash` commits to the resolver's redaction and
    /// sensitivity-classification profile. This crate verifies the commitment;
    /// it does not detect secrets or classify content by itself.
    ///
    /// # Errors
    ///
    /// Returns a typed scope, digest, size, or request error.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &IntentEvidenceRequest,
        task_hash: Digest32,
        trace_id: Uuid,
        resolver_policy_hash: Digest32,
        request_material: Vec<u8>,
        proposal_material: Vec<u8>,
        context_material: Vec<u8>,
    ) -> Result<Self, EvidenceMaterialError> {
        request
            .validate()
            .map_err(EvidenceMaterialError::InvalidRequest)?;
        if task_hash != request.task_hash {
            return Err(EvidenceMaterialError::CrossTask);
        }
        if trace_id != request.trace_id {
            return Err(EvidenceMaterialError::CrossTrace);
        }
        if resolver_policy_hash != request.resolver_policy_hash {
            return Err(EvidenceMaterialError::WrongHash(
                EvidenceMaterialKind::ResolverPolicy,
            ));
        }
        verify_material_hash(
            &request_material,
            request.request_hash,
            EvidenceMaterialKind::Request,
        )?;
        verify_material_hash(
            &proposal_material,
            request.proposal_hash,
            EvidenceMaterialKind::Proposal,
        )?;
        verify_material_hash(
            &context_material,
            request.context_hash,
            EvidenceMaterialKind::Context,
        )?;
        let actual = request_material
            .len()
            .checked_add(proposal_material.len())
            .and_then(|size| size.checked_add(context_material.len()))
            .ok_or(EvidenceMaterialError::Oversize {
                stage: request.stage,
                maximum: max_evidence_material_bytes(request.stage),
                actual: usize::MAX,
            })?;
        let maximum = max_evidence_material_bytes(request.stage);
        if actual > maximum {
            return Err(EvidenceMaterialError::Oversize {
                stage: request.stage,
                maximum,
                actual,
            });
        }
        Ok(Self {
            task_hash,
            trace_id,
            profile: request.evaluation_profile,
            stage: request.stage,
            source_request_hash: request
                .digest()
                .map_err(EvidenceMaterialError::InvalidRequest)?,
            resolver_policy_hash,
            disclosure_policy: request.disclosure_policy.clone(),
            request_material,
            proposal_material,
            context_material,
        })
    }

    /// Rechecks scope, commitments, policy, and size against the request.
    ///
    /// # Errors
    ///
    /// Returns a typed mismatch without exposing raw material.
    pub fn verify_for(&self, request: &IntentEvidenceRequest) -> Result<(), EvidenceMaterialError> {
        let rebuilt = Self::new(
            request,
            self.task_hash,
            self.trace_id,
            self.resolver_policy_hash,
            self.request_material.clone(),
            self.proposal_material.clone(),
            self.context_material.clone(),
        )?;
        if self.profile != rebuilt.profile
            || self.stage != rebuilt.stage
            || self.source_request_hash != rebuilt.source_request_hash
            || self.disclosure_policy != rebuilt.disclosure_policy
        {
            return Err(EvidenceMaterialError::WrongHash(
                EvidenceMaterialKind::ResolverPolicy,
            ));
        }
        Ok(())
    }

    /// Opens material only for a local-only request.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceMaterialError::DisclosureDenied`] for an external
    /// disclosure profile.
    pub fn disclose_local(&self) -> Result<DisclosedEvidenceMaterial<'_>, EvidenceMaterialError> {
        if self.disclosure_policy != EvidenceDisclosurePolicy::LocalOnly {
            return Err(EvidenceMaterialError::DisclosureDenied);
        }
        Ok(DisclosedEvidenceMaterial {
            material: self,
            external_scope: None,
        })
    }

    /// Opens material only for the exact provider and egress-policy
    /// commitments authorized by a verified grant.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceMaterialError::DisclosureDenied`] for any mismatch.
    pub fn disclose_external<'a>(
        &'a self,
        authorization: &'a VerifiedExternalEvidenceDisclosure,
        trusted_now: i64,
    ) -> Result<DisclosedEvidenceMaterial<'a>, EvidenceMaterialError> {
        let EvidenceDisclosurePolicy::AllowlistedExternal {
            provider_id_hash,
            egress_policy_hash,
            provider_trust_root,
            ..
        } = self.disclosure_policy
        else {
            return Err(EvidenceMaterialError::DisclosureDenied);
        };
        if authorization.source_request_hash != self.source_request_hash
            || authorization.provider_id_hash != provider_id_hash
            || authorization.egress_policy_hash != egress_policy_hash
            || authorization.provider_trust_root != provider_trust_root
            || trusted_now < authorization.verified_at
            || trusted_now > authorization.valid_until
        {
            return Err(EvidenceMaterialError::DisclosureDenied);
        }
        Ok(DisclosedEvidenceMaterial {
            material: self,
            external_scope: Some(authorization),
        })
    }
}

impl fmt::Debug for BoundedEvidenceMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedEvidenceMaterial")
            .field("task_hash", &self.task_hash)
            .field("trace_id", &self.trace_id)
            .field("profile", &self.profile)
            .field("stage", &self.stage)
            .field("source_request_hash", &self.source_request_hash)
            .field("resolver_policy_hash", &self.resolver_policy_hash)
            .field("disclosure_policy", &self.disclosure_policy)
            .field("request_material", &"[REDACTED]")
            .field("request_bytes", &self.request_material.len())
            .field("proposal_material", &"[REDACTED]")
            .field("proposal_bytes", &self.proposal_material.len())
            .field("context_material", &"[REDACTED]")
            .field("context_bytes", &self.context_material.len())
            .finish()
    }
}

/// Authorized, borrowed view passed to an evidence provider.
pub struct DisclosedEvidenceMaterial<'a> {
    material: &'a BoundedEvidenceMaterial,
    external_scope: Option<&'a VerifiedExternalEvidenceDisclosure>,
}

impl DisclosedEvidenceMaterial<'_> {
    #[must_use]
    pub fn request_bytes(&self) -> &[u8] {
        &self.material.request_material
    }

    #[must_use]
    pub fn proposal_bytes(&self) -> &[u8] {
        &self.material.proposal_material
    }

    #[must_use]
    pub fn context_bytes(&self) -> &[u8] {
        &self.material.context_material
    }

    #[must_use]
    pub const fn resolver_policy_hash(&self) -> Digest32 {
        self.material.resolver_policy_hash
    }

    #[must_use]
    pub fn external_scope(&self) -> Option<(Digest32, Digest32, Digest32, i64)> {
        self.external_scope.map(|scope| {
            (
                scope.provider_id_hash,
                scope.egress_policy_hash,
                scope.provider_trust_root,
                scope.valid_until,
            )
        })
    }
}

impl fmt::Debug for DisclosedEvidenceMaterial<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DisclosedEvidenceMaterial")
            .field("material", &"[REDACTED]")
            .finish()
    }
}

/// Stage-specific maximum for combined request, proposal, and context bytes.
#[must_use]
pub const fn max_evidence_material_bytes(stage: IntentStage) -> usize {
    match stage {
        IntentStage::Request => MAX_REQUEST_EVIDENCE_MATERIAL_BYTES,
        IntentStage::Plan => MAX_PLAN_EVIDENCE_MATERIAL_BYTES,
        IntentStage::Action => MAX_ACTION_EVIDENCE_MATERIAL_BYTES,
        IntentStage::Result => MAX_RESULT_EVIDENCE_MATERIAL_BYTES,
    }
}

fn verify_material_hash(
    material: &[u8],
    expected: Digest32,
    kind: EvidenceMaterialKind,
) -> Result<(), EvidenceMaterialError> {
    if Digest32::sha256(material) != expected {
        return Err(EvidenceMaterialError::WrongHash(kind));
    }
    Ok(())
}

fn require_digest(value: Digest32, field: &'static str) -> Result<(), PolicyEvaluationError> {
    if value.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(PolicyEvaluationError::ZeroDigest(field));
    }
    Ok(())
}

fn validate_grant_window(
    requested_at: i64,
    issued_at: i64,
    valid_until: i64,
) -> Result<(), ExternalDisclosureAuthorizationError> {
    if requested_at <= 0
        || issued_at < requested_at
        || valid_until < issued_at
        || valid_until.saturating_sub(issued_at) > MAX_EXTERNAL_DISCLOSURE_GRANT_LIFETIME_SECONDS
    {
        return Err(ExternalDisclosureAuthorizationError::InvalidGrant);
    }
    Ok(())
}
