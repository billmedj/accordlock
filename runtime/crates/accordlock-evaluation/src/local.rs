use core::fmt;

use accordlock_protocol::Digest32;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    BoundedEvidenceMaterial, CalibrationStatus, DisclosedEvidenceMaterial,
    EVIDENCE_PROVENANCE_SCHEMA_VERSION, EvidenceArtifactResolver, EvidenceDisclosurePolicy,
    EvidenceMaterialError, EvidenceMaterialKind, EvidenceMethodKind, EvidenceProvenance,
    EvidenceResolutionDisposition, EvidenceVerdict, INTENT_EVIDENCE_SCHEMA_VERSION, IntentEvidence,
    IntentEvidenceProvider, IntentEvidenceRequest, IntentEvidenceResponse, IntentStage,
    NormalizedScore, PolicyEvaluationError, ScoreInterval,
};

const LOCAL_DETERMINISTIC_EVALUATOR_DOMAIN: &[u8] =
    b"accordlock:v1:local-deterministic-evidence-evaluator\0";
const LOCAL_DETERMINISTIC_RULE_DOMAIN: &[u8] = b"accordlock:v1:local-exact-artifact-digest-rule\0";
const LOCAL_DETERMINISTIC_PAYLOAD_DOMAIN: &[u8] =
    b"accordlock:v1:local-deterministic-evidence-payload\0";
const LOCAL_EVIDENCE_ID_DOMAIN: &[u8] = b"accordlock:v1:local-evidence-id\0";
const LOCAL_RESPONSE_ID_DOMAIN: &[u8] = b"accordlock:v1:local-evidence-response-id\0";

/// One material slot that can be checked by the local deterministic provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalArtifactField {
    Request,
    Proposal,
    Context,
}

impl LocalArtifactField {
    const fn code(self) -> u8 {
        match self {
            Self::Request => 0,
            Self::Proposal => 1,
            Self::Context => 2,
        }
    }

    fn bytes<'a>(self, material: &'a DisclosedEvidenceMaterial<'_>) -> &'a [u8] {
        match self {
            Self::Request => material.request_bytes(),
            Self::Proposal => material.proposal_bytes(),
            Self::Context => material.context_bytes(),
        }
    }
}

/// Machine-verifiable rule asserting one exact local artifact digest.
///
/// This rule establishes byte identity only. It must not be described as a
/// general natural-language or intent-preservation judgment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExactArtifactDigestRule {
    artifact: LocalArtifactField,
    expected_digest: Digest32,
}

impl ExactArtifactDigestRule {
    /// Creates an exact digest rule.
    ///
    /// # Errors
    ///
    /// Rejects a zero expected commitment.
    pub fn new(
        artifact: LocalArtifactField,
        expected_digest: Digest32,
    ) -> Result<Self, LocalDeterministicEvidenceError> {
        if is_zero_digest(expected_digest) {
            return Err(LocalDeterministicEvidenceError::InvalidRule);
        }
        Ok(Self {
            artifact,
            expected_digest,
        })
    }

    #[must_use]
    pub const fn artifact(&self) -> LocalArtifactField {
        self.artifact
    }

    #[must_use]
    pub const fn expected_digest(&self) -> Digest32 {
        self.expected_digest
    }

    #[must_use]
    pub fn digest(&self) -> Digest32 {
        domain_digest(
            LOCAL_DETERMINISTIC_RULE_DOMAIN,
            &[&[self.artifact.code()], self.expected_digest.as_bytes()],
        )
    }
}

/// Ledger and time bindings supplied by the trusted local integration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalEvidenceRecordBinding {
    pub ledger_hash: Digest32,
    pub sequence: u64,
    pub parent_evidence_hash: Option<Digest32>,
    pub transformation_step_hash: Option<Digest32>,
    pub observed_at: i64,
    pub responded_at: i64,
}

impl LocalEvidenceRecordBinding {
    /// Validates the chain-independent portion of a record binding.
    ///
    /// Stage-specific transformation binding is checked during evaluation.
    ///
    /// # Errors
    ///
    /// Rejects zero commitments, invalid parent shape, or invalid time order.
    pub fn validate(&self) -> Result<(), LocalDeterministicEvidenceError> {
        if is_zero_digest(self.ledger_hash)
            || self.observed_at <= 0
            || self.responded_at < self.observed_at
            || (self.sequence == 0) != self.parent_evidence_hash.is_none()
            || self.parent_evidence_hash.is_some_and(is_zero_digest)
            || self.transformation_step_hash.is_some_and(is_zero_digest)
        {
            return Err(LocalDeterministicEvidenceError::InvalidRecordBinding);
        }
        Ok(())
    }
}

/// Resolver pinned to one exact local-only evidence request and artifact set.
///
/// Raw material is retained in the non-serializable bounded container and is
/// always redacted from `Debug` output.
#[derive(Clone)]
pub struct PinnedLocalArtifactResolver {
    source_request_hash: Digest32,
    material: BoundedEvidenceMaterial,
}

impl PinnedLocalArtifactResolver {
    /// Pins exact local material to one evidence request.
    ///
    /// # Errors
    ///
    /// Rejects external disclosure, malformed requests, scope substitutions,
    /// commitment mismatches, and stage-size violations.
    pub fn new(
        request: &IntentEvidenceRequest,
        request_material: Vec<u8>,
        proposal_material: Vec<u8>,
        context_material: Vec<u8>,
    ) -> Result<Self, EvidenceMaterialError> {
        if request.disclosure_policy != EvidenceDisclosurePolicy::LocalOnly {
            return Err(EvidenceMaterialError::DisclosureDenied);
        }
        let material = BoundedEvidenceMaterial::new(
            request,
            request.task_hash,
            request.trace_id,
            request.resolver_policy_hash,
            request_material,
            proposal_material,
            context_material,
        )?;
        let source_request_hash = request
            .digest()
            .map_err(EvidenceMaterialError::InvalidRequest)?;
        Ok(Self {
            source_request_hash,
            material,
        })
    }
}

impl fmt::Debug for PinnedLocalArtifactResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedLocalArtifactResolver")
            .field("source_request_hash", &self.source_request_hash)
            .field("material", &"[REDACTED]")
            .finish()
    }
}

impl EvidenceArtifactResolver for PinnedLocalArtifactResolver {
    fn resolve(
        &self,
        request: &IntentEvidenceRequest,
    ) -> Result<BoundedEvidenceMaterial, EvidenceMaterialError> {
        if request.disclosure_policy != EvidenceDisclosurePolicy::LocalOnly {
            return Err(EvidenceMaterialError::DisclosureDenied);
        }
        let request_hash = request
            .digest()
            .map_err(EvidenceMaterialError::InvalidRequest)?;
        if request_hash != self.source_request_hash {
            return Err(EvidenceMaterialError::Missing(
                EvidenceMaterialKind::Request,
            ));
        }
        self.material.verify_for(request)?;
        Ok(self.material.clone())
    }
}

/// Deterministic same-process provider for exact byte-identity constraints.
#[derive(Clone, Debug)]
pub struct LocalDeterministicEvidenceProvider {
    rule: ExactArtifactDigestRule,
    binding: LocalEvidenceRecordBinding,
}

impl LocalDeterministicEvidenceProvider {
    /// Creates a provider for one exact evidence-chain position.
    ///
    /// # Errors
    ///
    /// Rejects malformed ledger, parent, transformation, or time bindings.
    pub fn new(
        rule: ExactArtifactDigestRule,
        binding: LocalEvidenceRecordBinding,
    ) -> Result<Self, LocalDeterministicEvidenceError> {
        binding.validate()?;
        Ok(Self { rule, binding })
    }

    #[must_use]
    pub fn provenance(&self) -> EvidenceProvenance {
        EvidenceProvenance {
            schema_version: EVIDENCE_PROVENANCE_SCHEMA_VERSION,
            method_kind: EvidenceMethodKind::DeterministicCheck,
            method_hash: self.rule.digest(),
            evaluator_hash: Digest32::sha256(LOCAL_DETERMINISTIC_EVALUATOR_DOMAIN),
            calibration_status: CalibrationStatus::NotApplicable,
            calibration_hash: None,
        }
    }

    /// Returns the exact provenance commitment required in
    /// `IntentEvidenceRequest::profile_hash` and the evidence trust policy.
    ///
    /// # Errors
    ///
    /// Returns an encoding error if the provenance record cannot be committed.
    pub fn profile_hash(&self) -> Result<Digest32, LocalDeterministicEvidenceError> {
        self.provenance().digest().map_err(Into::into)
    }

    fn evaluate_inner(
        &self,
        request: &IntentEvidenceRequest,
        material: &DisclosedEvidenceMaterial<'_>,
    ) -> Result<IntentEvidenceResponse, LocalDeterministicEvidenceError> {
        request.validate()?;
        self.binding.validate()?;
        if request.disclosure_policy != EvidenceDisclosurePolicy::LocalOnly
            || material.external_scope().is_some()
        {
            return Err(LocalDeterministicEvidenceError::DisclosureDenied);
        }
        if material.resolver_policy_hash() != request.resolver_policy_hash
            || Digest32::sha256(material.request_bytes()) != request.request_hash
            || Digest32::sha256(material.proposal_bytes()) != request.proposal_hash
            || Digest32::sha256(material.context_bytes()) != request.context_hash
        {
            return Err(LocalDeterministicEvidenceError::MaterialMismatch);
        }
        if request.profile_hash != self.profile_hash()? {
            return Err(LocalDeterministicEvidenceError::ProfileMismatch);
        }
        match (request.stage, self.binding.transformation_step_hash) {
            (IntentStage::Request, None) => {}
            (IntentStage::Request, Some(_)) | (_, None) => {
                return Err(LocalDeterministicEvidenceError::InvalidRecordBinding);
            }
            (_, Some(_)) => {}
        }
        if self.binding.observed_at < request.requested_at {
            return Err(LocalDeterministicEvidenceError::InvalidRecordBinding);
        }

        let actual_digest = Digest32::sha256(self.rule.artifact.bytes(material));
        let verdict = if actual_digest == self.rule.expected_digest {
            EvidenceVerdict::Supports
        } else {
            EvidenceVerdict::Contradicts
        };
        let request_digest = request.digest()?;
        let payload_hash = domain_digest(
            LOCAL_DETERMINISTIC_PAYLOAD_DOMAIN,
            &[
                request_digest.as_bytes(),
                self.rule.digest().as_bytes(),
                actual_digest.as_bytes(),
                self.rule.expected_digest.as_bytes(),
                &[verdict_code(verdict)],
            ],
        );
        let evidence_id = derived_uuid(LOCAL_EVIDENCE_ID_DOMAIN, payload_hash);
        let evidence = IntentEvidence {
            schema_version: INTENT_EVIDENCE_SCHEMA_VERSION,
            evidence_id,
            task_hash: request.task_hash,
            trace_id: request.trace_id,
            ledger_hash: self.binding.ledger_hash,
            sequence: self.binding.sequence,
            parent_evidence_hash: self.binding.parent_evidence_hash,
            requirement_hash: request.requirement_hash,
            stage: request.stage,
            subject_hash: request.proposal_hash,
            transformation_step_hash: self.binding.transformation_step_hash,
            verdict,
            confidence: ScoreInterval::new(
                NormalizedScore::ONE,
                NormalizedScore::ONE,
                NormalizedScore::ONE,
            )?,
            method_kind: EvidenceMethodKind::DeterministicCheck,
            method_hash: self.rule.digest(),
            evaluator_hash: Digest32::sha256(LOCAL_DETERMINISTIC_EVALUATOR_DOMAIN),
            calibration_status: CalibrationStatus::NotApplicable,
            calibration_hash: None,
            payload_hash,
            observed_at: self.binding.observed_at,
        };
        let response_id = derived_uuid(LOCAL_RESPONSE_ID_DOMAIN, evidence.digest()?);
        IntentEvidenceResponse::from_local_evidence(
            response_id,
            request,
            evidence,
            self.binding.responded_at,
        )
        .map_err(Into::into)
    }
}

impl IntentEvidenceProvider for LocalDeterministicEvidenceProvider {
    type Error = LocalDeterministicEvidenceError;

    fn evaluate(
        &self,
        request: &IntentEvidenceRequest,
        material: &DisclosedEvidenceMaterial<'_>,
    ) -> Result<IntentEvidenceResponse, Self::Error> {
        self.evaluate_inner(request, material)
    }
}

/// Non-authorizing result of the local resolver/provider harness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalEvidenceHarnessOutcome {
    Response(Box<IntentEvidenceResponse>),
    Review(LocalEvidenceReviewReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalEvidenceReviewReason {
    MissingMaterial(EvidenceMaterialKind),
    ResolverUnavailable,
}

/// Runs the exact local resolver/disclosure/provider sequence.
///
/// Missing or unavailable material produces explicit review. Every structural,
/// integrity, disclosure, or provider failure is returned as a fail-closed
/// error and must be treated as denial by an authorization integration.
///
/// # Errors
///
/// Returns [`LocalEvidenceHarnessError`] for resolver integrity or disclosure
/// failures, provider failures, and invalid provider responses.
pub fn evaluate_local_evidence(
    resolver: &impl EvidenceArtifactResolver,
    provider: &LocalDeterministicEvidenceProvider,
    request: &IntentEvidenceRequest,
) -> Result<LocalEvidenceHarnessOutcome, LocalEvidenceHarnessError> {
    request.validate()?;
    if request.disclosure_policy != EvidenceDisclosurePolicy::LocalOnly {
        return Err(LocalEvidenceHarnessError::ResolutionDenied(
            EvidenceMaterialError::DisclosureDenied,
        ));
    }
    let material = match resolver.resolve(request) {
        Ok(material) => material,
        Err(EvidenceMaterialError::Missing(kind)) => {
            return Ok(LocalEvidenceHarnessOutcome::Review(
                LocalEvidenceReviewReason::MissingMaterial(kind),
            ));
        }
        Err(EvidenceMaterialError::Unavailable) => {
            return Ok(LocalEvidenceHarnessOutcome::Review(
                LocalEvidenceReviewReason::ResolverUnavailable,
            ));
        }
        Err(error) => {
            debug_assert_eq!(error.disposition(), EvidenceResolutionDisposition::Deny);
            return Err(LocalEvidenceHarnessError::ResolutionDenied(error));
        }
    };
    let disclosed = material
        .disclose_local()
        .map_err(LocalEvidenceHarnessError::ResolutionDenied)?;
    let response = provider
        .evaluate(request, &disclosed)
        .map_err(LocalEvidenceHarnessError::ProviderDenied)?;
    response.verify_for(request)?;
    Ok(LocalEvidenceHarnessOutcome::Response(Box::new(response)))
}

#[derive(Debug, Error)]
pub enum LocalDeterministicEvidenceError {
    #[error("local deterministic rule is invalid")]
    InvalidRule,
    #[error("local evidence record binding is invalid")]
    InvalidRecordBinding,
    #[error("local evidence disclosure is not permitted")]
    DisclosureDenied,
    #[error("local evidence material does not match the request")]
    MaterialMismatch,
    #[error("local evidence profile does not match the configured deterministic rule")]
    ProfileMismatch,
    #[error("local evidence record is invalid: {0}")]
    Evaluation(#[from] PolicyEvaluationError),
}

#[derive(Debug, Error)]
pub enum LocalEvidenceHarnessError {
    #[error("local evidence resolution was denied: {0}")]
    ResolutionDenied(EvidenceMaterialError),
    #[error("local evidence provider failed closed: {0}")]
    ProviderDenied(LocalDeterministicEvidenceError),
    #[error("local evidence contract verification failed: {0}")]
    ContractInvalid(#[from] PolicyEvaluationError),
}

fn is_zero_digest(digest: Digest32) -> bool {
    digest.as_bytes().iter().all(|byte| *byte == 0)
}

fn verdict_code(verdict: EvidenceVerdict) -> u8 {
    match verdict {
        EvidenceVerdict::Supports => 0,
        EvidenceVerdict::Contradicts => 1,
        EvidenceVerdict::Inconclusive => 2,
    }
}

fn domain_digest(domain: &[u8], parts: &[&[u8]]) -> Digest32 {
    let capacity = domain.len()
        + parts
            .iter()
            .map(|part| 8_usize.saturating_add(part.len()))
            .sum::<usize>();
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(domain);
    for part in parts {
        bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
        bytes.extend_from_slice(part);
    }
    Digest32::sha256(&bytes)
}

fn derived_uuid(domain: &[u8], digest: Digest32) -> Uuid {
    let seed = domain_digest(domain, &[digest.as_bytes()]);
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&seed.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}
