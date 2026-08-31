use accordlock_evaluation::{
    BoundedEvidenceMaterial, CalibrationStatus, Digest32, DisclosedEvidenceMaterial,
    EvidenceArtifactResolver, EvidenceDisclosurePolicy, EvidenceMaterialError,
    EvidenceMaterialKind, EvidenceMethodKind, EvidenceResolutionDisposition, EvidenceVerdict,
    ExternalDisclosureAuthorizationError, ExternalEvidenceDisclosureGrant,
    INTENT_EVIDENCE_REQUEST_SCHEMA_VERSION, INTENT_EVIDENCE_SCHEMA_VERSION,
    IntentEvaluationProfile, IntentEvidence, IntentEvidenceProvider, IntentEvidenceRequest,
    IntentEvidenceResponse, IntentStage, MAX_REQUEST_EVIDENCE_MATERIAL_BYTES, NormalizedScore,
    PolicyEvaluationError, ProviderAuthenticationError, ProviderResponseAuthentication,
    ScoreInterval,
};
use accordlock_protocol::{CoseVerifier, SigningIdentity, evaluator_verifier_root};
use uuid::Uuid;

const REQUEST_BYTES: &[u8] = b"summarize the workspace";
const PROPOSAL_BYTES: &[u8] = b"read src/lib.rs";
const CONTEXT_BYTES: &[u8] = b"workspace=/safe";

fn digest(value: u8) -> Digest32 {
    Digest32::from_bytes([value; 32])
}

fn evidence() -> Result<IntentEvidence, PolicyEvaluationError> {
    Ok(IntentEvidence {
        schema_version: INTENT_EVIDENCE_SCHEMA_VERSION,
        evidence_id: Uuid::from_u128(1),
        task_hash: digest(1),
        trace_id: Uuid::from_u128(2),
        ledger_hash: digest(2),
        sequence: 0,
        parent_evidence_hash: None,
        requirement_hash: digest(3),
        stage: IntentStage::Request,
        subject_hash: Digest32::sha256(PROPOSAL_BYTES),
        transformation_step_hash: None,
        verdict: EvidenceVerdict::Supports,
        confidence: ScoreInterval::new(
            NormalizedScore::new(950_000)?,
            NormalizedScore::new(975_000)?,
            NormalizedScore::ONE,
        )?,
        method_kind: EvidenceMethodKind::DeterministicCheck,
        method_hash: digest(5),
        evaluator_hash: digest(6),
        calibration_status: CalibrationStatus::NotApplicable,
        calibration_hash: None,
        payload_hash: digest(7),
        observed_at: 1_100,
    })
}

fn request(
    evidence: &IntentEvidence,
    disclosure_policy: EvidenceDisclosurePolicy,
) -> Result<IntentEvidenceRequest, PolicyEvaluationError> {
    Ok(IntentEvidenceRequest {
        schema_version: INTENT_EVIDENCE_REQUEST_SCHEMA_VERSION,
        request_id: Uuid::from_u128(3),
        evaluation_profile: IntentEvaluationProfile::PreExecution,
        task_hash: evidence.task_hash,
        trace_id: evidence.trace_id,
        requirement_hash: evidence.requirement_hash,
        stage: evidence.stage,
        request_hash: Digest32::sha256(REQUEST_BYTES),
        proposal_hash: evidence.subject_hash,
        context_hash: Digest32::sha256(CONTEXT_BYTES),
        profile_hash: evidence.provenance_digest()?,
        resolver_policy_hash: digest(11),
        disclosure_policy,
        challenge_hash: digest(12),
        requested_at: 1_000,
    })
}

fn material(
    request: &IntentEvidenceRequest,
) -> Result<BoundedEvidenceMaterial, EvidenceMaterialError> {
    BoundedEvidenceMaterial::new(
        request,
        request.task_hash,
        request.trace_id,
        request.resolver_policy_hash,
        REQUEST_BYTES.to_vec(),
        PROPOSAL_BYTES.to_vec(),
        CONTEXT_BYTES.to_vec(),
    )
}

struct FakeResolver {
    material: Option<BoundedEvidenceMaterial>,
}
impl EvidenceArtifactResolver for FakeResolver {
    fn resolve(
        &self,
        request: &IntentEvidenceRequest,
    ) -> Result<BoundedEvidenceMaterial, EvidenceMaterialError> {
        let value = self
            .material
            .clone()
            .ok_or(EvidenceMaterialError::Unavailable)?;
        value.verify_for(request)?;
        Ok(value)
    }
}

#[derive(Clone)]
struct FakeProvider {
    evidence: IntentEvidence,
}
impl IntentEvidenceProvider for FakeProvider {
    type Error = PolicyEvaluationError;
    fn evaluate(
        &self,
        request: &IntentEvidenceRequest,
        material: &DisclosedEvidenceMaterial<'_>,
    ) -> Result<IntentEvidenceResponse, Self::Error> {
        assert_eq!(material.proposal_bytes(), PROPOSAL_BYTES);
        IntentEvidenceResponse::from_local_evidence(
            Uuid::from_u128(4),
            request,
            self.evidence.clone(),
            1_200,
        )
    }
}

#[test]
fn valid_local_provider_path_is_bound_and_has_no_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let evidence = evidence()?;
    let request = request(&evidence, EvidenceDisclosurePolicy::LocalOnly)?;
    let resolver = FakeResolver {
        material: Some(material(&request)?),
    };
    let resolved_material = resolver.resolve(&request)?;
    let disclosed = resolved_material.disclose_local()?;
    let response = FakeProvider { evidence }.evaluate(&request, &disclosed)?;
    let expected_request: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/examples/intent-evidence-request.v2.json"
    ))?;
    let expected_response: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/examples/intent-evidence-response.v2.json"
    ))?;
    assert_eq!(serde_json::to_value(&request)?, expected_request);
    assert_eq!(serde_json::to_value(&response)?, expected_response);
    response.verify_for(&request)?;
    let object = serde_json::to_value(&response)?
        .as_object()
        .cloned()
        .ok_or("object")?;
    assert!(
        !object.contains_key("decision")
            && !object.contains_key("authority")
            && !object.contains_key("authorization")
    );
    Ok(())
}

#[test]
fn resolver_rejects_wrong_hash_cross_task_oversize_and_disclosure()
-> Result<(), Box<dyn std::error::Error>> {
    let evidence = evidence()?;
    let local = request(&evidence, EvidenceDisclosurePolicy::LocalOnly)?;
    assert!(matches!(
        BoundedEvidenceMaterial::new(
            &local,
            local.task_hash,
            local.trace_id,
            local.resolver_policy_hash,
            b"wrong".to_vec(),
            PROPOSAL_BYTES.to_vec(),
            CONTEXT_BYTES.to_vec()
        ),
        Err(EvidenceMaterialError::WrongHash(
            EvidenceMaterialKind::Request
        ))
    ));
    assert!(matches!(
        BoundedEvidenceMaterial::new(
            &local,
            digest(99),
            local.trace_id,
            local.resolver_policy_hash,
            REQUEST_BYTES.to_vec(),
            PROPOSAL_BYTES.to_vec(),
            CONTEXT_BYTES.to_vec()
        ),
        Err(EvidenceMaterialError::CrossTask)
    ));
    let huge = vec![b'x'; MAX_REQUEST_EVIDENCE_MATERIAL_BYTES + 1];
    let mut oversized = local.clone();
    oversized.request_hash = Digest32::sha256(&huge);
    oversized.proposal_hash = Digest32::sha256(b"");
    oversized.context_hash = Digest32::sha256(b"");
    assert!(matches!(
        BoundedEvidenceMaterial::new(
            &oversized,
            oversized.task_hash,
            oversized.trace_id,
            oversized.resolver_policy_hash,
            huge,
            vec![],
            vec![]
        ),
        Err(EvidenceMaterialError::Oversize { .. })
    ));
    Ok(())
}

#[test]
fn unavailable_abstains_to_review_and_debug_redacts_content()
-> Result<(), Box<dyn std::error::Error>> {
    let evidence = evidence()?;
    let request = request(&evidence, EvidenceDisclosurePolicy::LocalOnly)?;
    let resolver = FakeResolver { material: None };
    let Err(error) = resolver.resolve(&request) else {
        return Err("resolver unexpectedly returned material".into());
    };
    assert_eq!(error.disposition(), EvidenceResolutionDisposition::Review);
    let secret_request = b"DO-NOT-PRINT-SECRET".to_vec();
    let mut bound = request.clone();
    bound.request_hash = Digest32::sha256(&secret_request);
    let value = BoundedEvidenceMaterial::new(
        &bound,
        bound.task_hash,
        bound.trace_id,
        bound.resolver_policy_hash,
        secret_request,
        PROPOSAL_BYTES.to_vec(),
        CONTEXT_BYTES.to_vec(),
    )?;
    let debug = format!("{value:?} {:?}", value.disclose_local()?);
    assert!(!debug.contains("DO-NOT-PRINT-SECRET"));
    assert!(debug.contains("REDACTED"));
    Ok(())
}

struct ExternalFixture {
    request: IntentEvidenceRequest,
    evidence: IntentEvidence,
    provider_signer: SigningIdentity,
    provider_verifier: CoseVerifier,
    egress_signer: SigningIdentity,
    egress_verifier: CoseVerifier,
}

fn external_fixture() -> Result<ExternalFixture, Box<dyn std::error::Error>> {
    let evidence = evidence()?;
    let signer = SigningIdentity::from_seed("provider-v1", [42; 32]);
    let verifier = signer.verifier();
    let root = evaluator_verifier_root(signer.key_id(), signer.public_key_bytes())?;
    let egress_signer = SigningIdentity::from_seed("egress-authority-v1", [44; 32]);
    let egress_verifier = egress_signer.verifier();
    let egress_root =
        evaluator_verifier_root(egress_signer.key_id(), egress_signer.public_key_bytes())?;
    let request = request(
        &evidence,
        EvidenceDisclosurePolicy::AllowlistedExternal {
            provider_id_hash: digest(21),
            egress_policy_hash: digest(22),
            provider_trust_root: root,
            egress_authority_root: egress_root,
        },
    )?;
    Ok(ExternalFixture {
        request,
        evidence,
        provider_signer: signer,
        provider_verifier: verifier,
        egress_signer,
        egress_verifier,
    })
}

#[test]
fn authorized_external_provider_requires_valid_cose_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = external_fixture()?;
    let request = fixture.request;
    let evidence = fixture.evidence;
    let signer = fixture.provider_signer;
    let verifier = fixture.provider_verifier;
    let material = material(&request)?;
    let grant =
        ExternalEvidenceDisclosureGrant::issue(&request, 1_105, 1_300, &fixture.egress_signer)?;
    let authorization = grant.verify_for(&request, &fixture.egress_verifier, 1_110)?;
    let disclosed = material.disclose_external(&authorization, 1_115)?;
    assert_eq!(
        disclosed.external_scope().map(|scope| (scope.0, scope.1)),
        Some((digest(21), digest(22)))
    );
    let response = IntentEvidenceResponse::from_external_evidence(
        Uuid::from_u128(9),
        &request,
        evidence,
        1_120,
        1_110,
        1_300,
        &signer,
    )?;
    let serialized = serde_json::to_value(&response)?;
    let authentication = serialized["authentication"]
        .as_object()
        .ok_or("external authentication object")?;
    assert_eq!(authentication["mode"], "EXTERNAL");
    assert_eq!(authentication["provider_key_id"], "provider-v1");
    assert!(
        authentication["cose_sign1"]
            .as_array()
            .is_some_and(|v| !v.is_empty())
    );
    assert_eq!(authentication.len(), 7);
    assert!(matches!(
        response.verify_for(&request),
        Err(PolicyEvaluationError::ProviderAuthenticationRequired)
    ));
    response.verify_external_for(&request, &verifier, 1_200)?;
    Ok(())
}

#[test]
fn public_external_disclosure_grant_example_matches_rust_serialization()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = external_fixture()?;
    let grant = ExternalEvidenceDisclosureGrant::issue(
        &fixture.request,
        1_105,
        1_300,
        &fixture.egress_signer,
    )?;
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/examples/external-evidence-disclosure-grant.v1.json"
    ))?;
    assert_eq!(serde_json::to_value(grant)?, expected);
    Ok(())
}

#[test]
fn external_disclosure_grant_rejects_every_scope_authentication_and_time_substitution()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = external_fixture()?;
    let external_request = fixture.request;
    let authority = fixture.egress_signer;
    let verifier = fixture.egress_verifier;
    let grant =
        ExternalEvidenceDisclosureGrant::issue(&external_request, 1_105, 1_300, &authority)?;
    assert!(matches!(
        ExternalEvidenceDisclosureGrant::issue(&external_request, 1_105, 1_406, &authority),
        Err(ExternalDisclosureAuthorizationError::InvalidGrant)
    ));
    let authorization = grant.verify_for(&external_request, &verifier, 1_110)?;
    let external_material = material(&external_request)?;
    assert!(
        external_material
            .disclose_external(&authorization, 1_115)
            .is_ok()
    );
    assert!(matches!(
        external_material.disclose_external(&authorization, 1_109),
        Err(EvidenceMaterialError::DisclosureDenied)
    ));
    assert!(matches!(
        external_material.disclose_external(&authorization, 1_301),
        Err(EvidenceMaterialError::DisclosureDenied)
    ));

    let wrong_key = SigningIdentity::from_seed("egress-authority-v1", [45; 32]).verifier();
    assert!(matches!(
        grant.verify_for(&external_request, &wrong_key, 1_110),
        Err(ExternalDisclosureAuthorizationError::WrongAuthorityRoot)
    ));
    let wrong_id =
        CoseVerifier::from_public_key("egress-authority-v2", authority.public_key_bytes())?;
    assert!(matches!(
        grant.verify_for(&external_request, &wrong_id, 1_110),
        Err(ExternalDisclosureAuthorizationError::WrongKeyId)
    ));
    let mut bad_signature = grant.clone();
    let last = bad_signature.cose_sign1.len() - 1;
    bad_signature.cose_sign1[last] ^= 1;
    assert!(matches!(
        bad_signature.verify_for(&external_request, &verifier, 1_110),
        Err(ExternalDisclosureAuthorizationError::Crypto(_))
    ));

    for mutate in [
        |grant: &mut ExternalEvidenceDisclosureGrant| grant.provider_id_hash = digest(91),
        |grant: &mut ExternalEvidenceDisclosureGrant| grant.egress_policy_hash = digest(92),
        |grant: &mut ExternalEvidenceDisclosureGrant| grant.challenge_hash = digest(93),
    ] {
        let mut substituted = grant.clone();
        mutate(&mut substituted);
        assert!(matches!(
            substituted.verify_for(&external_request, &verifier, 1_110),
            Err(ExternalDisclosureAuthorizationError::ScopeMismatch)
        ));
    }

    let mut replay = external_request.clone();
    replay.request_id = Uuid::from_u128(999);
    assert!(matches!(
        grant.verify_for(&replay, &verifier, 1_110),
        Err(ExternalDisclosureAuthorizationError::ScopeMismatch)
    ));
    let mut cross_profile = external_request.clone();
    cross_profile.evaluation_profile = IntentEvaluationProfile::CompleteTrace;
    assert!(matches!(
        grant.verify_for(&cross_profile, &verifier, 1_110),
        Err(ExternalDisclosureAuthorizationError::ScopeMismatch)
    ));
    assert!(matches!(
        grant.verify_for(&external_request, &verifier, 1_104),
        Err(ExternalDisclosureAuthorizationError::NotYetValid)
    ));
    assert!(matches!(
        grant.verify_for(&external_request, &verifier, 1_301),
        Err(ExternalDisclosureAuthorizationError::Expired)
    ));

    let local_request = request(&evidence()?, EvidenceDisclosurePolicy::LocalOnly)?;
    assert!(matches!(
        material(&local_request)?.disclose_external(&authorization, 1_115),
        Err(EvidenceMaterialError::DisclosureDenied)
    ));
    let debug = format!("{authorization:?}");
    assert!(debug.contains("REDACTED") && !debug.contains("summarize the workspace"));
    Ok(())
}

#[test]
fn external_auth_rejects_wrong_key_signature_challenge_replay_and_freshness()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = external_fixture()?;
    let request = fixture.request;
    let evidence = fixture.evidence;
    let signer = fixture.provider_signer;
    let verifier = fixture.provider_verifier;
    let response = IntentEvidenceResponse::from_external_evidence(
        Uuid::from_u128(9),
        &request,
        evidence,
        1_120,
        1_110,
        1_300,
        &signer,
    )?;
    let wrong = SigningIdentity::from_seed("provider-v1", [43; 32]).verifier();
    assert!(matches!(
        response.verify_external_for(&request, &wrong, 1_200),
        Err(ProviderAuthenticationError::WrongTrustRoot)
    ));
    let wrong_id_verifier =
        CoseVerifier::from_public_key("provider-v2", signer.public_key_bytes())?;
    assert!(matches!(
        response.verify_external_for(&request, &wrong_id_verifier, 1_200),
        Err(ProviderAuthenticationError::WrongKeyId)
    ));
    let mut bad_signature = response.clone();
    if let ProviderResponseAuthentication::External { cose_sign1, .. } =
        &mut bad_signature.authentication
    {
        let last = cose_sign1.len() - 1;
        cose_sign1[last] ^= 1;
    }
    assert!(matches!(
        bad_signature.verify_external_for(&request, &verifier, 1_200),
        Err(ProviderAuthenticationError::Crypto(_))
    ));
    let mut bad_challenge = response.clone();
    if let ProviderResponseAuthentication::External { challenge_hash, .. } =
        &mut bad_challenge.authentication
    {
        *challenge_hash = digest(77);
    }
    assert!(
        bad_challenge
            .verify_external_for(&request, &verifier, 1_200)
            .is_err()
    );
    let mut replay = request.clone();
    replay.request_id = Uuid::from_u128(999);
    replay.challenge_hash = digest(88);
    assert!(matches!(
        response.verify_external_for(&replay, &verifier, 1_200),
        Err(ProviderAuthenticationError::SourceRequestMismatch)
    ));
    let mut cross_profile = request.clone();
    cross_profile.evaluation_profile = IntentEvaluationProfile::CompleteTrace;
    assert!(matches!(
        response.verify_external_for(&cross_profile, &verifier, 1_200),
        Err(ProviderAuthenticationError::SourceRequestMismatch)
    ));
    assert!(matches!(
        response.verify_external_for(&request, &verifier, 1_301),
        Err(ProviderAuthenticationError::Expired)
    ));
    assert!(matches!(
        response.verify_external_for(&request, &verifier, 1_109),
        Err(ProviderAuthenticationError::NotYetValid)
    ));
    Ok(())
}

#[test]
fn provider_envelopes_reject_unknown_fields() -> Result<(), Box<dyn std::error::Error>> {
    let evidence = evidence()?;
    let request = request(&evidence, EvidenceDisclosurePolicy::LocalOnly)?;
    let response =
        IntentEvidenceResponse::from_local_evidence(Uuid::from_u128(4), &request, evidence, 1_200)?;
    let mut request_json = serde_json::to_value(&request)?;
    request_json
        .as_object_mut()
        .ok_or("object")?
        .insert("unexpected".into(), serde_json::json!(true));
    assert!(serde_json::from_value::<IntentEvidenceRequest>(request_json).is_err());
    let mut response_json = serde_json::to_value(&response)?;
    response_json
        .as_object_mut()
        .ok_or("object")?
        .insert("unexpected".into(), serde_json::json!(true));
    assert!(serde_json::from_value::<IntentEvidenceResponse>(response_json).is_err());
    Ok(())
}
