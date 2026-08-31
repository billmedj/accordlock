use accordlock_evaluation::{
    CalibrationStatus, Digest32, EvidenceArtifactResolver, EvidenceDisclosurePolicy,
    EvidenceMaterialError, EvidenceMethodKind, EvidenceVerdict, ExactArtifactDigestRule,
    INTENT_EVIDENCE_REQUEST_SCHEMA_VERSION, IntentEvaluationProfile, IntentEvidenceProvider,
    IntentEvidenceRequest, IntentStage, LocalArtifactField, LocalDeterministicEvidenceError,
    LocalDeterministicEvidenceProvider, LocalEvidenceHarnessError, LocalEvidenceHarnessOutcome,
    LocalEvidenceRecordBinding, LocalEvidenceReviewReason, PinnedLocalArtifactResolver,
    evaluate_local_evidence,
};
use uuid::Uuid;

const REQUEST: &[u8] = include_bytes!("fixtures/local_evidence/request.txt");
const PROPOSAL: &[u8] = include_bytes!("fixtures/local_evidence/proposal.json");
const CONTEXT: &[u8] = include_bytes!("fixtures/local_evidence/context.json");

fn digest(value: u8) -> Digest32 {
    Digest32::from_bytes([value; 32])
}

fn provider(
    expected_proposal: Digest32,
) -> Result<LocalDeterministicEvidenceProvider, Box<dyn std::error::Error>> {
    Ok(LocalDeterministicEvidenceProvider::new(
        ExactArtifactDigestRule::new(LocalArtifactField::Proposal, expected_proposal)?,
        LocalEvidenceRecordBinding {
            ledger_hash: digest(9),
            sequence: 0,
            parent_evidence_hash: None,
            transformation_step_hash: None,
            observed_at: 1_010,
            responded_at: 1_011,
        },
    )?)
}

fn request(
    provider: &LocalDeterministicEvidenceProvider,
) -> Result<IntentEvidenceRequest, Box<dyn std::error::Error>> {
    Ok(IntentEvidenceRequest {
        schema_version: INTENT_EVIDENCE_REQUEST_SCHEMA_VERSION,
        request_id: Uuid::from_u128(11),
        evaluation_profile: IntentEvaluationProfile::PreExecution,
        task_hash: digest(1),
        trace_id: Uuid::from_u128(12),
        requirement_hash: digest(2),
        stage: IntentStage::Request,
        request_hash: Digest32::sha256(REQUEST),
        proposal_hash: Digest32::sha256(PROPOSAL),
        context_hash: Digest32::sha256(CONTEXT),
        profile_hash: provider.profile_hash()?,
        resolver_policy_hash: digest(3),
        disclosure_policy: EvidenceDisclosurePolicy::LocalOnly,
        challenge_hash: digest(4),
        requested_at: 1_000,
    })
}

fn resolver(
    request: &IntentEvidenceRequest,
) -> Result<PinnedLocalArtifactResolver, EvidenceMaterialError> {
    PinnedLocalArtifactResolver::new(
        request,
        REQUEST.to_vec(),
        PROPOSAL.to_vec(),
        CONTEXT.to_vec(),
    )
}

#[test]
fn exact_local_artifact_produces_bound_deterministic_support()
-> Result<(), Box<dyn std::error::Error>> {
    let provider = provider(Digest32::sha256(PROPOSAL))?;
    let request = request(&provider)?;
    let resolver = resolver(&request)?;
    let first = evaluate_local_evidence(&resolver, &provider, &request)?;
    let second = evaluate_local_evidence(&resolver, &provider, &request)?;
    assert_eq!(first, second);
    let LocalEvidenceHarnessOutcome::Response(response) = first else {
        return Err("exact material unexpectedly required review".into());
    };
    response.verify_for(&request)?;
    assert_eq!(response.evidence.verdict, EvidenceVerdict::Supports);
    assert_eq!(
        response.evidence.method_kind,
        EvidenceMethodKind::DeterministicCheck
    );
    assert_eq!(
        response.evidence.calibration_status,
        CalibrationStatus::NotApplicable
    );
    assert_eq!(response.evidence.calibration_hash, None);
    assert_eq!(response.provenance_hash, provider.profile_hash()?);
    Ok(())
}

#[test]
fn exact_digest_mismatch_is_a_qualified_contradiction_not_similarity()
-> Result<(), Box<dyn std::error::Error>> {
    let provider = provider(Digest32::sha256(b"another approved proposal"))?;
    let request = request(&provider)?;
    let resolver = resolver(&request)?;
    let LocalEvidenceHarnessOutcome::Response(response) =
        evaluate_local_evidence(&resolver, &provider, &request)?
    else {
        return Err("digest mismatch unexpectedly required review".into());
    };
    assert_eq!(response.evidence.verdict, EvidenceVerdict::Contradicts);
    assert_eq!(
        response.evidence.confidence.lower(),
        response.evidence.confidence.upper()
    );
    Ok(())
}

struct UnavailableResolver;

impl EvidenceArtifactResolver for UnavailableResolver {
    fn resolve(
        &self,
        _request: &IntentEvidenceRequest,
    ) -> Result<accordlock_evaluation::BoundedEvidenceMaterial, EvidenceMaterialError> {
        Err(EvidenceMaterialError::Unavailable)
    }
}

#[test]
fn unavailable_material_abstains_and_integrity_failures_deny()
-> Result<(), Box<dyn std::error::Error>> {
    let provider = provider(Digest32::sha256(PROPOSAL))?;
    let request = request(&provider)?;
    let pinned = resolver(&request)?;
    assert_eq!(
        evaluate_local_evidence(&UnavailableResolver, &provider, &request)?,
        LocalEvidenceHarnessOutcome::Review(LocalEvidenceReviewReason::ResolverUnavailable)
    );

    let mut external = request.clone();
    external.disclosure_policy = EvidenceDisclosurePolicy::AllowlistedExternal {
        provider_id_hash: digest(20),
        egress_policy_hash: digest(21),
        provider_trust_root: digest(22),
        egress_authority_root: digest(23),
    };
    assert!(matches!(
        evaluate_local_evidence(&pinned, &provider, &external),
        Err(LocalEvidenceHarnessError::ResolutionDenied(
            EvidenceMaterialError::DisclosureDenied
        ))
    ));

    let mut malformed = request.clone();
    malformed.schema_version = 0;
    assert!(matches!(
        evaluate_local_evidence(&UnavailableResolver, &provider, &malformed),
        Err(LocalEvidenceHarnessError::ContractInvalid(_))
    ));
    Ok(())
}

#[test]
fn substituted_profile_and_invalid_chain_binding_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let provider = provider(Digest32::sha256(PROPOSAL))?;
    let mut request = request(&provider)?;
    request.profile_hash = digest(99);
    let resolver = resolver(&request)?;
    let material = resolver.resolve(&request)?;
    let disclosed = material.disclose_local()?;
    assert!(matches!(
        provider.evaluate(&request, &disclosed),
        Err(LocalDeterministicEvidenceError::ProfileMismatch)
    ));

    assert!(matches!(
        LocalDeterministicEvidenceProvider::new(
            ExactArtifactDigestRule::new(LocalArtifactField::Request, Digest32::sha256(REQUEST))?,
            LocalEvidenceRecordBinding {
                ledger_hash: digest(9),
                sequence: 1,
                parent_evidence_hash: None,
                transformation_step_hash: None,
                observed_at: 1_010,
                responded_at: 1_011,
            }
        ),
        Err(LocalDeterministicEvidenceError::InvalidRecordBinding)
    ));
    Ok(())
}

#[test]
fn resolver_debug_never_contains_local_artifacts() -> Result<(), Box<dyn std::error::Error>> {
    let provider = provider(Digest32::sha256(PROPOSAL))?;
    let request = request(&provider)?;
    let resolver = resolver(&request)?;
    let debug = format!("{resolver:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("release.json"));
    assert!(!debug.contains("approved manifest"));
    Ok(())
}
