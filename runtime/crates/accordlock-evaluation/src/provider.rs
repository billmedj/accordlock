use accordlock_protocol::{
    CanonicalEncode, CoseVerifier, CryptoError, Digest32, MAX_COSE_SIZE_BYTES, MAX_KEY_ID_BYTES,
    SigningIdentity, canonical_hash, evaluator_verifier_root, sign_cose, verify_cose,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    CalibrationStatus, DisclosedEvidenceMaterial, EvidenceDisclosurePolicy,
    IntentEvaluationProfile, IntentEvidence, IntentStage, PolicyEvaluationError,
};

pub const INTENT_EVIDENCE_REQUEST_SCHEMA_VERSION: u16 = 2;
pub const INTENT_EVIDENCE_RESPONSE_SCHEMA_VERSION: u16 = 2;
pub const MAX_PROVIDER_ATTESTATION_LIFETIME_SECONDS: i64 = 300;
pub const PROVIDER_RESPONSE_ATTESTATION_SIGNATURE_DOMAIN: &str =
    "accordlock:v1:intent-evidence-provider-attestation";

/// Hash-only control-plane request for an evidence provider.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentEvidenceRequest {
    pub schema_version: u16,
    pub request_id: Uuid,
    pub evaluation_profile: IntentEvaluationProfile,
    pub task_hash: Digest32,
    pub trace_id: Uuid,
    pub requirement_hash: Digest32,
    pub stage: IntentStage,
    pub request_hash: Digest32,
    pub proposal_hash: Digest32,
    pub context_hash: Digest32,
    pub profile_hash: Digest32,
    pub resolver_policy_hash: Digest32,
    pub disclosure_policy: EvidenceDisclosurePolicy,
    pub challenge_hash: Digest32,
    pub requested_at: i64,
}

impl IntentEvidenceRequest {
    /// Validates scope, profile, commitments, disclosure, challenge, and time.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] for malformed material or a stage
    /// outside the selected evaluation profile.
    pub fn validate(&self) -> Result<(), PolicyEvaluationError> {
        require_schema(
            self.schema_version,
            INTENT_EVIDENCE_REQUEST_SCHEMA_VERSION,
            "intent evidence request",
        )?;
        require_non_nil(self.request_id, "request_id")?;
        if !self
            .evaluation_profile
            .required_stages()
            .contains(&self.stage)
        {
            return Err(PolicyEvaluationError::BindingMismatch(
                "intent evidence request profile stage",
            ));
        }
        require_digest(self.task_hash, "task_hash")?;
        require_non_nil(self.trace_id, "trace_id")?;
        require_digest(self.requirement_hash, "requirement_hash")?;
        require_digest(self.request_hash, "request_hash")?;
        require_digest(self.proposal_hash, "proposal_hash")?;
        require_digest(self.context_hash, "context_hash")?;
        require_digest(self.profile_hash, "profile_hash")?;
        require_digest(self.resolver_policy_hash, "resolver_policy_hash")?;
        self.disclosure_policy.validate()?;
        require_digest(self.challenge_hash, "challenge_hash")?;
        require_positive_time(self.requested_at, "requested_at")
    }

    /// Canonical source-request commitment.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] when validation or encoding fails.
    pub fn digest(&self) -> Result<Digest32, PolicyEvaluationError> {
        self.validate()?;
        canonical_hash(self).map_err(|error| PolicyEvaluationError::Canonical(error.to_string()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ProviderResponseAuthentication {
    Local,
    External {
        provider_key_id: String,
        provider_trust_root: Digest32,
        challenge_hash: Digest32,
        issued_at: i64,
        valid_until: i64,
        cose_sign1: Vec<u8>,
    },
}

/// Evidence response. External instances require cryptographic verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentEvidenceResponse {
    pub schema_version: u16,
    pub response_id: Uuid,
    pub source_request_hash: Digest32,
    pub evidence: IntentEvidence,
    pub evidence_hash: Digest32,
    pub provenance_hash: Digest32,
    pub calibration_status: CalibrationStatus,
    pub calibration_hash: Option<Digest32>,
    pub body_hash: Digest32,
    pub responded_at: i64,
    pub authentication: ProviderResponseAuthentication,
}

impl IntentEvidenceResponse {
    /// Builds a same-process response for a local-only request.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] for nonlocal disclosure or substitution.
    pub fn from_local_evidence(
        response_id: Uuid,
        request: &IntentEvidenceRequest,
        evidence: IntentEvidence,
        responded_at: i64,
    ) -> Result<Self, PolicyEvaluationError> {
        request.validate()?;
        if request.disclosure_policy != EvidenceDisclosurePolicy::LocalOnly {
            return Err(PolicyEvaluationError::ProviderAuthenticationRequired);
        }
        verify_evidence_for_request(&evidence, request)?;
        let mut response = Self::unsigned(
            response_id,
            request,
            evidence,
            responded_at,
            ProviderResponseAuthentication::Local,
        )?;
        response.body_hash = response.body().digest()?;
        response.verify_for(request)?;
        Ok(response)
    }

    /// Builds a signed external provider response using Ed25519/COSE.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderAuthenticationError`] for trust-root, binding,
    /// freshness, encoding, or signing failure.
    #[allow(clippy::too_many_arguments)]
    pub fn from_external_evidence(
        response_id: Uuid,
        request: &IntentEvidenceRequest,
        evidence: IntentEvidence,
        responded_at: i64,
        issued_at: i64,
        valid_until: i64,
        identity: &SigningIdentity,
    ) -> Result<Self, ProviderAuthenticationError> {
        request
            .validate()
            .map_err(ProviderAuthenticationError::InvalidResponse)?;
        let EvidenceDisclosurePolicy::AllowlistedExternal {
            provider_trust_root,
            ..
        } = request.disclosure_policy
        else {
            return Err(ProviderAuthenticationError::DisclosurePolicyMismatch);
        };
        let actual_root = evaluator_verifier_root(identity.key_id(), identity.public_key_bytes())?;
        if actual_root != provider_trust_root {
            return Err(ProviderAuthenticationError::WrongTrustRoot);
        }
        validate_attestation_window(request.requested_at, issued_at, valid_until, responded_at)?;
        verify_evidence_for_request(&evidence, request)
            .map_err(ProviderAuthenticationError::InvalidResponse)?;
        let authentication = ProviderResponseAuthentication::External {
            provider_key_id: identity.key_id().to_owned(),
            provider_trust_root,
            challenge_hash: request.challenge_hash,
            issued_at,
            valid_until,
            cose_sign1: Vec::new(),
        };
        let mut response =
            Self::unsigned(response_id, request, evidence, responded_at, authentication)
                .map_err(ProviderAuthenticationError::InvalidResponse)?;
        response.body_hash = response
            .body()
            .digest()
            .map_err(ProviderAuthenticationError::InvalidResponse)?;
        let attestation = response.attestation()?;
        let signed = sign_cose(
            &attestation.canonical_bytes()?,
            PROVIDER_RESPONSE_ATTESTATION_SIGNATURE_DOMAIN,
            identity,
        )?;
        if let ProviderResponseAuthentication::External { cose_sign1, .. } =
            &mut response.authentication
        {
            *cose_sign1 = signed;
        }
        response
            .validate()
            .map_err(ProviderAuthenticationError::InvalidResponse)?;
        Ok(response)
    }

    /// Validates internal commitments without authenticating an external provider.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] for malformed or inconsistent fields.
    pub fn validate(&self) -> Result<(), PolicyEvaluationError> {
        require_schema(
            self.schema_version,
            INTENT_EVIDENCE_RESPONSE_SCHEMA_VERSION,
            "intent evidence response",
        )?;
        require_non_nil(self.response_id, "response_id")?;
        require_digest(self.source_request_hash, "source_request_hash")?;
        require_digest(self.evidence_hash, "evidence_hash")?;
        require_digest(self.provenance_hash, "provenance_hash")?;
        require_digest(self.body_hash, "body_hash")?;
        require_positive_time(self.responded_at, "responded_at")?;
        self.evidence.validate()?;
        validate_authentication_shape(&self.authentication)?;
        if self.evidence.digest()? != self.evidence_hash
            || self.evidence.provenance_digest()? != self.provenance_hash
            || self.evidence.calibration_status != self.calibration_status
            || self.evidence.calibration_hash != self.calibration_hash
            || self.responded_at < self.evidence.observed_at
            || self.body().digest()? != self.body_hash
        {
            return Err(PolicyEvaluationError::BindingMismatch(
                "intent evidence response",
            ));
        }
        Ok(())
    }

    /// Verifies a same-process response for a local-only request.
    ///
    /// External responses return
    /// [`PolicyEvaluationError::ProviderAuthenticationRequired`] and must use
    /// [`Self::verify_external_for`].
    ///
    /// # Errors
    ///
    /// Returns a fail-closed validation, binding, or authentication error.
    pub fn verify_for(&self, request: &IntentEvidenceRequest) -> Result<(), PolicyEvaluationError> {
        self.verify_request_bindings(request)?;
        match (&request.disclosure_policy, &self.authentication) {
            (EvidenceDisclosurePolicy::LocalOnly, ProviderResponseAuthentication::Local) => Ok(()),
            (
                EvidenceDisclosurePolicy::AllowlistedExternal { .. },
                ProviderResponseAuthentication::External { .. },
            ) => Err(PolicyEvaluationError::ProviderAuthenticationRequired),
            _ => Err(PolicyEvaluationError::BindingMismatch(
                "intent evidence response disclosure",
            )),
        }
    }

    /// Authenticates external key identity, challenge, request, body, freshness,
    /// and signature.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderAuthenticationError`] for every mismatch.
    pub fn verify_external_for(
        &self,
        request: &IntentEvidenceRequest,
        verifier: &CoseVerifier,
        verified_at: i64,
    ) -> Result<(), ProviderAuthenticationError> {
        request
            .validate()
            .map_err(ProviderAuthenticationError::InvalidResponse)?;
        if self.source_request_hash
            != request
                .digest()
                .map_err(ProviderAuthenticationError::InvalidResponse)?
        {
            return Err(ProviderAuthenticationError::SourceRequestMismatch);
        }
        self.verify_request_bindings(request)
            .map_err(ProviderAuthenticationError::InvalidResponse)?;
        let EvidenceDisclosurePolicy::AllowlistedExternal {
            provider_trust_root: expected_root,
            ..
        } = request.disclosure_policy
        else {
            return Err(ProviderAuthenticationError::DisclosurePolicyMismatch);
        };
        let ProviderResponseAuthentication::External {
            provider_key_id,
            provider_trust_root,
            challenge_hash,
            issued_at,
            valid_until,
            cose_sign1,
        } = &self.authentication
        else {
            return Err(ProviderAuthenticationError::AuthenticationMissing);
        };
        if provider_key_id != verifier.key_id() {
            return Err(ProviderAuthenticationError::WrongKeyId);
        }
        let actual_root = evaluator_verifier_root(verifier.key_id(), verifier.public_key_bytes())?;
        if *provider_trust_root != expected_root || actual_root != expected_root {
            return Err(ProviderAuthenticationError::WrongTrustRoot);
        }
        if *challenge_hash != request.challenge_hash {
            return Err(ProviderAuthenticationError::ChallengeMismatch);
        }
        validate_attestation_window(
            request.requested_at,
            *issued_at,
            *valid_until,
            self.responded_at,
        )?;
        if verified_at < *issued_at {
            return Err(ProviderAuthenticationError::NotYetValid);
        }
        if verified_at > *valid_until {
            return Err(ProviderAuthenticationError::Expired);
        }
        let expected_payload = self.attestation()?.canonical_bytes()?;
        let verified_payload = verify_cose(
            cose_sign1,
            PROVIDER_RESPONSE_ATTESTATION_SIGNATURE_DOMAIN,
            verifier,
        )?;
        if verified_payload != expected_payload {
            return Err(ProviderAuthenticationError::SignedPayloadMismatch);
        }
        Ok(())
    }

    /// Canonical commitment including external authentication bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyEvaluationError`] when validation or encoding fails.
    pub fn digest(&self) -> Result<Digest32, PolicyEvaluationError> {
        self.validate()?;
        canonical_hash(self).map_err(|error| PolicyEvaluationError::Canonical(error.to_string()))
    }

    fn unsigned(
        response_id: Uuid,
        request: &IntentEvidenceRequest,
        evidence: IntentEvidence,
        responded_at: i64,
        authentication: ProviderResponseAuthentication,
    ) -> Result<Self, PolicyEvaluationError> {
        Ok(Self {
            schema_version: INTENT_EVIDENCE_RESPONSE_SCHEMA_VERSION,
            response_id,
            source_request_hash: request.digest()?,
            evidence_hash: evidence.digest()?,
            provenance_hash: evidence.provenance_digest()?,
            calibration_status: evidence.calibration_status,
            calibration_hash: evidence.calibration_hash,
            evidence,
            body_hash: Digest32::from_bytes([0; 32]),
            responded_at,
            authentication,
        })
    }

    fn verify_request_bindings(
        &self,
        request: &IntentEvidenceRequest,
    ) -> Result<(), PolicyEvaluationError> {
        self.validate()?;
        request.validate()?;
        if self.source_request_hash != request.digest()? || self.responded_at < request.requested_at
        {
            return Err(PolicyEvaluationError::BindingMismatch(
                "intent evidence response request",
            ));
        }
        verify_evidence_for_request(&self.evidence, request)
    }

    fn body(&self) -> ProviderResponseBody {
        ProviderResponseBody {
            schema_version: 1,
            response_id: self.response_id,
            source_request_hash: self.source_request_hash,
            evidence_hash: self.evidence_hash,
            provenance_hash: self.provenance_hash,
            calibration_status: self.calibration_status,
            calibration_hash: self.calibration_hash,
            responded_at: self.responded_at,
        }
    }

    fn attestation(&self) -> Result<ProviderResponseAttestation, ProviderAuthenticationError> {
        let ProviderResponseAuthentication::External {
            provider_key_id,
            provider_trust_root,
            challenge_hash,
            issued_at,
            valid_until,
            ..
        } = &self.authentication
        else {
            return Err(ProviderAuthenticationError::AuthenticationMissing);
        };
        Ok(ProviderResponseAttestation {
            schema_version: 1,
            provider_key_id: provider_key_id.clone(),
            provider_trust_root: *provider_trust_root,
            challenge_hash: *challenge_hash,
            source_request_hash: self.source_request_hash,
            response_body_hash: self.body_hash,
            issued_at: *issued_at,
            valid_until: *valid_until,
        })
    }
}

/// Provider boundary receiving hash-only control plus authorized material.
pub trait IntentEvidenceProvider {
    type Error;

    /// Produces an evidence response from exact disclosed material.
    ///
    /// # Errors
    ///
    /// Returns the provider's own error. Callers still verify the response.
    fn evaluate(
        &self,
        request: &IntentEvidenceRequest,
        material: &DisclosedEvidenceMaterial<'_>,
    ) -> Result<IntentEvidenceResponse, Self::Error>;
}

#[derive(Debug, Error)]
pub enum ProviderAuthenticationError {
    #[error("provider response is invalid: {0}")]
    InvalidResponse(PolicyEvaluationError),
    #[error("provider disclosure policy does not match")]
    DisclosurePolicyMismatch,
    #[error("external provider authentication is missing")]
    AuthenticationMissing,
    #[error("provider key identifier does not match")]
    WrongKeyId,
    #[error("provider public-key trust root does not match")]
    WrongTrustRoot,
    #[error("provider challenge does not match")]
    ChallengeMismatch,
    #[error("provider response belongs to another request or replay")]
    SourceRequestMismatch,
    #[error("provider attestation lifetime is invalid or too long")]
    InvalidFreshnessWindow,
    #[error("provider attestation is not yet valid")]
    NotYetValid,
    #[error("provider attestation has expired")]
    Expired,
    #[error("signed provider payload does not match the response")]
    SignedPayloadMismatch,
    #[error("provider cryptographic verification failed: {0}")]
    Crypto(#[from] CryptoError),
    #[error("provider canonical encoding failed: {0}")]
    Canonical(#[from] accordlock_protocol::CanonicalError),
}

pub(crate) struct ProviderResponseBody {
    pub(crate) schema_version: u16,
    pub(crate) response_id: Uuid,
    pub(crate) source_request_hash: Digest32,
    pub(crate) evidence_hash: Digest32,
    pub(crate) provenance_hash: Digest32,
    pub(crate) calibration_status: CalibrationStatus,
    pub(crate) calibration_hash: Option<Digest32>,
    pub(crate) responded_at: i64,
}

impl ProviderResponseBody {
    pub(crate) fn digest(&self) -> Result<Digest32, PolicyEvaluationError> {
        canonical_hash(self).map_err(|error| PolicyEvaluationError::Canonical(error.to_string()))
    }
}

pub(crate) struct ProviderResponseAttestation {
    pub(crate) schema_version: u16,
    pub(crate) provider_key_id: String,
    pub(crate) provider_trust_root: Digest32,
    pub(crate) challenge_hash: Digest32,
    pub(crate) source_request_hash: Digest32,
    pub(crate) response_body_hash: Digest32,
    pub(crate) issued_at: i64,
    pub(crate) valid_until: i64,
}

fn verify_evidence_for_request(
    evidence: &IntentEvidence,
    request: &IntentEvidenceRequest,
) -> Result<(), PolicyEvaluationError> {
    evidence.validate()?;
    if evidence.task_hash != request.task_hash
        || evidence.trace_id != request.trace_id
        || evidence.requirement_hash != request.requirement_hash
        || evidence.stage != request.stage
        || evidence.subject_hash != request.proposal_hash
        || evidence.provenance_digest()? != request.profile_hash
        || evidence.observed_at < request.requested_at
    {
        return Err(PolicyEvaluationError::BindingMismatch(
            "intent evidence provider request",
        ));
    }
    Ok(())
}

fn validate_authentication_shape(
    authentication: &ProviderResponseAuthentication,
) -> Result<(), PolicyEvaluationError> {
    match authentication {
        ProviderResponseAuthentication::Local => Ok(()),
        ProviderResponseAuthentication::External {
            provider_key_id,
            provider_trust_root,
            challenge_hash,
            issued_at,
            valid_until,
            cose_sign1,
        } => {
            if provider_key_id.is_empty()
                || provider_key_id.len() > MAX_KEY_ID_BYTES
                || provider_key_id.trim() != provider_key_id
                || provider_key_id.chars().any(char::is_control)
                || cose_sign1.is_empty()
                || cose_sign1.len() > MAX_COSE_SIZE_BYTES
            {
                return Err(PolicyEvaluationError::InvalidProviderAuthentication);
            }
            require_digest(*provider_trust_root, "provider_trust_root")?;
            require_digest(*challenge_hash, "challenge_hash")?;
            require_positive_time(*issued_at, "provider issued_at")?;
            require_positive_time(*valid_until, "provider valid_until")?;
            if *valid_until < *issued_at
                || valid_until.saturating_sub(*issued_at)
                    > MAX_PROVIDER_ATTESTATION_LIFETIME_SECONDS
            {
                return Err(PolicyEvaluationError::InvalidProviderAuthentication);
            }
            Ok(())
        }
    }
}

fn validate_attestation_window(
    requested_at: i64,
    issued_at: i64,
    valid_until: i64,
    responded_at: i64,
) -> Result<(), ProviderAuthenticationError> {
    if requested_at <= 0
        || issued_at < requested_at
        || responded_at < issued_at
        || valid_until < responded_at
        || valid_until.saturating_sub(issued_at) > MAX_PROVIDER_ATTESTATION_LIFETIME_SECONDS
    {
        return Err(ProviderAuthenticationError::InvalidFreshnessWindow);
    }
    Ok(())
}

fn require_schema(
    actual: u16,
    expected: u16,
    record: &'static str,
) -> Result<(), PolicyEvaluationError> {
    if actual != expected {
        return Err(PolicyEvaluationError::WrongSchema(record));
    }
    Ok(())
}

fn require_non_nil(value: Uuid, field: &'static str) -> Result<(), PolicyEvaluationError> {
    if value.is_nil() {
        return Err(PolicyEvaluationError::NilIdentifier(field));
    }
    Ok(())
}

fn require_digest(value: Digest32, field: &'static str) -> Result<(), PolicyEvaluationError> {
    if value.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(PolicyEvaluationError::ZeroDigest(field));
    }
    Ok(())
}

fn require_positive_time(value: i64, field: &'static str) -> Result<(), PolicyEvaluationError> {
    if value <= 0 {
        return Err(PolicyEvaluationError::InvalidTime(field));
    }
    Ok(())
}
