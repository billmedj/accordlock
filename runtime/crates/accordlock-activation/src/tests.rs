use std::error::Error;

use accordlock_eks_profile::{
    CaTrustCommitment, EksBrokerManagementBindings, EksManagementAuthorityBinding,
    EksRouteProfileInput, PinnedSocketTarget,
};
use accordlock_protocol::AuthorityDomainState;

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const OBSERVED_AT: i64 = 1_000;
const VALID_UNTIL: i64 = 1_200;
const NOW: i64 = 1_100;

struct Fixture {
    scope: ActivationScope,
    route: EksRouteProfile,
    management: EksBrokerManagementBindings,
    release: Digest32,
    deployment_activation_id: Uuid,
    authority: AuthorityVector,
    proofs: LiveProofCommitments,
    bundle: LiveEvidenceBundleBinding,
    collector: SigningIdentity,
    operator: SigningIdentity,
    registry: ActivatedLiveBoundaryRegistry,
    claims: LiveDeploymentBoundaryClaims,
    signed: SignedLiveDeploymentBoundaryAttestation,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let scope = ActivationScope::new("acme", "production")?;
        let route = route("accordlock-target")?;
        let management = management_bindings("primary")?;
        let release = digest(50);
        let deployment_activation_id = Uuid::from_u128(0x5001);
        let authority = authority();
        let proofs = LiveProofCommitments::new(digest(60), digest(61), digest(62))?;
        let bundle = LiveEvidenceBundleBinding::new(digest(70), digest(71), 23)?;
        let collector = SigningIdentity::from_seed("activation-collector", [101; 32]);
        let operator = SigningIdentity::from_seed("activation-operator", [102; 32]);
        let registry = registry(
            &scope,
            route.cluster_identity(),
            &collector,
            &operator,
            LiveBoundarySignerStatus::Active,
            LiveBoundarySignerStatus::Active,
            0x7001,
        )?;
        let context = LiveActivationContext::new(
            scope.clone(),
            &route,
            &management,
            release,
            deployment_activation_id,
            authority.clone(),
        )?;
        let claims = claims(
            context,
            proofs.clone(),
            bundle.clone(),
            &collector,
            &operator,
            &registry,
            OBSERVED_AT,
            VALID_UNTIL,
        )?;
        let signed =
            sign_live_deployment_boundary_attestation(claims.clone(), &collector, &operator)?;
        Ok(Self {
            scope,
            route,
            management,
            release,
            deployment_activation_id,
            authority,
            proofs,
            bundle,
            collector,
            operator,
            registry,
            claims,
            signed,
        })
    }

    fn resign(
        &self,
        claims: LiveDeploymentBoundaryClaims,
    ) -> Result<SignedLiveDeploymentBoundaryAttestation, ActivationError> {
        sign_live_deployment_boundary_attestation(claims, &self.collector, &self.operator)
    }
}

fn digest(seed: u8) -> Digest32 {
    Digest32::sha256(&[seed])
}

fn domain(seed: u8) -> AuthorityDomainState {
    AuthorityDomainState {
        root: digest(seed),
        epoch: u64::from(seed) + 1,
        activation_id: Uuid::from_u128(u128::from(seed) + 1),
    }
}

fn authority() -> AuthorityVector {
    AuthorityVector {
        policy: domain(1),
        registry: domain(2),
        revocation: domain(3),
        connector: domain(4),
        resource: domain(5),
        signer: domain(6),
        mediation: domain(7),
        grant_registry: domain(8),
        office_act_registry: domain(9),
        principal_registry: domain(10),
        workload_build_allowlist: domain(11),
        kernel_configuration: domain(12),
    }
}

#[derive(Clone, Copy, Debug)]
enum AuthorityCoordinate {
    Root,
    Epoch,
    ActivationId,
}

fn authority_domain_mut(
    authority: &mut AuthorityVector,
    domain_index: usize,
) -> Option<&mut AuthorityDomainState> {
    match domain_index {
        0 => Some(&mut authority.policy),
        1 => Some(&mut authority.registry),
        2 => Some(&mut authority.revocation),
        3 => Some(&mut authority.connector),
        4 => Some(&mut authority.resource),
        5 => Some(&mut authority.signer),
        6 => Some(&mut authority.mediation),
        7 => Some(&mut authority.grant_registry),
        8 => Some(&mut authority.office_act_registry),
        9 => Some(&mut authority.principal_registry),
        10 => Some(&mut authority.workload_build_allowlist),
        11 => Some(&mut authority.kernel_configuration),
        _ => None,
    }
}

fn mutate_authority_coordinate(
    authority: &mut AuthorityVector,
    domain_index: usize,
    coordinate: AuthorityCoordinate,
) {
    let Some(domain) = authority_domain_mut(authority, domain_index) else {
        return;
    };
    let mutation_index = u128::try_from(domain_index).unwrap_or(u128::MAX);
    match coordinate {
        AuthorityCoordinate::Root => {
            domain.root = Digest32::sha256(&[0xf0, u8::try_from(domain_index).unwrap_or(u8::MAX)]);
        }
        AuthorityCoordinate::Epoch => {
            domain.epoch = domain.epoch.saturating_add(10_000);
        }
        AuthorityCoordinate::ActivationId => {
            domain.activation_id = Uuid::from_u128(0xa000 + mutation_index);
        }
    }
}

fn route(namespace: &str) -> Result<EksRouteProfile, Box<dyn Error>> {
    let api_server_identity = digest(20).to_string();
    Ok(EksRouteProfile::new(EksRouteProfileInput {
        cluster_trust_domain: "spiffe://corp.internal/eks/prod-a",
        cluster_identity: "arn:aws:eks:eu-west-1:111122223333:cluster/prod-a",
        api_server_identity: &api_server_identity,
        dns_server_name: "a1b2c3d4.gr7.eu-west-1.eks.amazonaws.com",
        port: 443,
        socket_target: PinnedSocketTarget::parse_canonical("10.0.10.12:443")?,
        ca_trust_commitment: CaTrustCommitment::from_sha256_bytes([21; 32])?,
        namespace,
        deployment_name: "target-app",
        deployment_uid: "11111111-2222-4333-8444-555555555555",
        attempt_service_account_name: "accordlock-executor",
        attempt_service_account_uid: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        token_audience: "https://kubernetes.default.svc",
    })?)
}

fn management_bindings(suffix: &str) -> Result<EksBrokerManagementBindings, Box<dyn Error>> {
    Ok(EksBrokerManagementBindings::new(
        EksManagementAuthorityBinding::new(
            format!("urn:accordlock:management:secret:{suffix}"),
            [31; 32],
        )?,
        EksManagementAuthorityBinding::new(
            format!("urn:accordlock:management:token-request:{suffix}"),
            [32; 32],
        )?,
        EksManagementAuthorityBinding::new(
            format!("urn:accordlock:management:token-review:{suffix}"),
            [33; 32],
        )?,
    )?)
}

fn signer_entry(
    scope: &ActivationScope,
    cluster_identity: &str,
    role: LiveBoundarySignerRole,
    identity: &str,
    signer: &SigningIdentity,
    public_key: [u8; 32],
    status: LiveBoundarySignerStatus,
) -> Result<RegisteredLiveBoundarySigner, ActivationError> {
    RegisteredLiveBoundarySigner::new(
        scope.clone(),
        cluster_identity,
        role,
        identity,
        signer.key_id(),
        public_key,
        900,
        1_300,
        status,
    )
}

fn registry_from_entries(
    entries: Vec<RegisteredLiveBoundarySigner>,
    activation_seed: u128,
) -> Result<ActivatedLiveBoundaryRegistry, ActivationError> {
    let root = ActivatedLiveBoundaryRegistry::compute_material_root(&entries)?;
    ActivatedLiveBoundaryRegistry::new(
        LiveBoundaryRegistryAuthority::new(root, 7, Uuid::from_u128(activation_seed))?,
        entries,
    )
}

fn registry(
    scope: &ActivationScope,
    cluster_identity: &str,
    collector: &SigningIdentity,
    operator: &SigningIdentity,
    collector_status: LiveBoundarySignerStatus,
    operator_status: LiveBoundarySignerStatus,
    activation_seed: u128,
) -> Result<ActivatedLiveBoundaryRegistry, ActivationError> {
    registry_from_entries(
        vec![
            signer_entry(
                scope,
                cluster_identity,
                LiveBoundarySignerRole::Collector,
                "spiffe://corp.internal/accordlock/activation-collector",
                collector,
                collector.public_key_bytes(),
                collector_status,
            )?,
            signer_entry(
                scope,
                cluster_identity,
                LiveBoundarySignerRole::Operator,
                "urn:accordlock:operator:release-approver",
                operator,
                operator.public_key_bytes(),
                operator_status,
            )?,
        ],
        activation_seed,
    )
}

#[allow(clippy::too_many_arguments)]
fn claims(
    context: LiveActivationContext,
    proofs: LiveProofCommitments,
    bundle: LiveEvidenceBundleBinding,
    collector: &SigningIdentity,
    operator: &SigningIdentity,
    registry: &ActivatedLiveBoundaryRegistry,
    observed_at: i64,
    valid_until: i64,
) -> Result<LiveDeploymentBoundaryClaims, ActivationError> {
    LiveDeploymentBoundaryClaims::new(
        Uuid::from_u128(0x6001),
        context,
        proofs,
        bundle,
        observed_at,
        valid_until,
        LiveBoundarySignerReference::new(
            "spiffe://corp.internal/accordlock/activation-collector",
            collector.key_id(),
        )?,
        LiveBoundarySignerReference::new(
            "urn:accordlock:operator:release-approver",
            operator.key_id(),
        )?,
        registry,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_with(
    fixture: &Fixture,
    registry: &ActivatedLiveBoundaryRegistry,
    signed: &SignedLiveDeploymentBoundaryAttestation,
    now: i64,
    scope: &ActivationScope,
    route: &EksRouteProfile,
    management: &EksBrokerManagementBindings,
    release: Digest32,
    deployment_activation_id: Uuid,
    authority: &AuthorityVector,
    proofs: &LiveProofCommitments,
    bundle: &LiveEvidenceBundleBinding,
    replay: &MemoryLiveEvidenceReplayGuard,
) -> Result<VerifiedLiveDeploymentBoundaries, ActivationError> {
    let _ = fixture;
    registry.verify_current(
        signed,
        now,
        scope,
        route,
        management,
        release,
        deployment_activation_id,
        authority,
        proofs,
        bundle,
        replay,
    )
}

fn verify_fixture(
    fixture: &Fixture,
    signed: &SignedLiveDeploymentBoundaryAttestation,
    now: i64,
    replay: &MemoryLiveEvidenceReplayGuard,
) -> Result<VerifiedLiveDeploymentBoundaries, ActivationError> {
    verify_with(
        fixture,
        &fixture.registry,
        signed,
        now,
        &fixture.scope,
        &fixture.route,
        &fixture.management,
        fixture.release,
        fixture.deployment_activation_id,
        &fixture.authority,
        &fixture.proofs,
        &fixture.bundle,
        replay,
    )
}

#[test]
fn valid_dual_attestation_is_opaque_and_replay_is_refused() -> TestResult {
    let fixture = Fixture::new()?;
    let replay = MemoryLiveEvidenceReplayGuard::new();
    let verified = verify_fixture(&fixture, &fixture.signed, NOW, &replay)?;

    assert_eq!(verified.evidence_id(), fixture.claims.evidence_id());
    assert_eq!(verified.verified_at(), NOW);
    assert_eq!(verified.observed_at(), OBSERVED_AT);
    assert_eq!(verified.valid_until(), VALID_UNTIL);
    assert_eq!(
        verified.activation_context_commitment(),
        fixture.claims.activation_context().commitment()
    );
    assert_eq!(
        verified.bundle_canonical_payload_commitment(),
        fixture.bundle.canonical_payload_commitment()
    );
    assert_eq!(
        verified.raw_artifact_set_commitment(),
        fixture.bundle.raw_artifact_set_commitment()
    );
    assert_eq!(verified.raw_artifact_count(), 23);
    assert_eq!(
        verified.registry_commitment(),
        fixture.registry.commitment()
    );
    assert_eq!(replay.consumed_count()?, 1);

    assert!(matches!(
        verify_fixture(&fixture, &fixture.signed, NOW, &replay),
        Err(ActivationError::ReplayDetected)
    ));
    assert_eq!(replay.consumed_count()?, 1);
    Ok(())
}

#[test]
fn proof_bundle_and_raw_artifact_substitution_fail_even_when_resigned() -> TestResult {
    let fixture = Fixture::new()?;
    let replay = MemoryLiveEvidenceReplayGuard::new();

    let substituted_proofs = LiveProofCommitments::new(digest(80), digest(81), digest(82))?;
    let proof_claims = claims(
        fixture.claims.activation_context.clone(),
        substituted_proofs,
        fixture.bundle.clone(),
        &fixture.collector,
        &fixture.operator,
        &fixture.registry,
        OBSERVED_AT,
        VALID_UNTIL,
    )?;
    let proof_signed = fixture.resign(proof_claims)?;
    assert!(matches!(
        verify_fixture(&fixture, &proof_signed, NOW, &replay),
        Err(ActivationError::ProofCommitmentMismatch)
    ));

    for substituted_bundle in [
        LiveEvidenceBundleBinding::new(digest(83), digest(71), 23)?,
        LiveEvidenceBundleBinding::new(digest(70), digest(84), 23)?,
        LiveEvidenceBundleBinding::new(digest(70), digest(71), 24)?,
    ] {
        let substituted_claims = claims(
            fixture.claims.activation_context.clone(),
            fixture.proofs.clone(),
            substituted_bundle,
            &fixture.collector,
            &fixture.operator,
            &fixture.registry,
            OBSERVED_AT,
            VALID_UNTIL,
        )?;
        let substituted_signed = fixture.resign(substituted_claims)?;
        assert!(matches!(
            verify_fixture(&fixture, &substituted_signed, NOW, &replay),
            Err(ActivationError::BundleBindingMismatch)
        ));
    }
    assert_eq!(replay.consumed_count()?, 0);
    Ok(())
}

#[test]
fn scope_route_management_release_and_activation_substitution_fail() -> TestResult {
    let fixture = Fixture::new()?;
    let replay = MemoryLiveEvidenceReplayGuard::new();
    let wrong_scope = ActivationScope::new("acme", "staging")?;
    assert!(matches!(
        verify_with(
            &fixture,
            &fixture.registry,
            &fixture.signed,
            NOW,
            &wrong_scope,
            &fixture.route,
            &fixture.management,
            fixture.release,
            fixture.deployment_activation_id,
            &fixture.authority,
            &fixture.proofs,
            &fixture.bundle,
            &replay,
        ),
        Err(ActivationError::ActivationContextMismatch)
    ));

    let wrong_route = route("another-target")?;
    assert!(matches!(
        verify_with(
            &fixture,
            &fixture.registry,
            &fixture.signed,
            NOW,
            &fixture.scope,
            &wrong_route,
            &fixture.management,
            fixture.release,
            fixture.deployment_activation_id,
            &fixture.authority,
            &fixture.proofs,
            &fixture.bundle,
            &replay,
        ),
        Err(ActivationError::ActivationContextMismatch)
    ));

    let wrong_management = management_bindings("alternate")?;
    assert!(matches!(
        verify_with(
            &fixture,
            &fixture.registry,
            &fixture.signed,
            NOW,
            &fixture.scope,
            &fixture.route,
            &wrong_management,
            fixture.release,
            fixture.deployment_activation_id,
            &fixture.authority,
            &fixture.proofs,
            &fixture.bundle,
            &replay,
        ),
        Err(ActivationError::ActivationContextMismatch)
    ));

    for (release, activation_id) in [
        (digest(85), fixture.deployment_activation_id),
        (fixture.release, Uuid::from_u128(0x5002)),
    ] {
        assert!(matches!(
            verify_with(
                &fixture,
                &fixture.registry,
                &fixture.signed,
                NOW,
                &fixture.scope,
                &fixture.route,
                &fixture.management,
                release,
                activation_id,
                &fixture.authority,
                &fixture.proofs,
                &fixture.bundle,
                &replay,
            ),
            Err(ActivationError::ActivationContextMismatch)
        ));
    }
    assert_eq!(replay.consumed_count()?, 0);
    Ok(())
}

#[test]
fn every_authority_coordinate_is_bound_against_resigning() -> TestResult {
    let fixture = Fixture::new()?;
    let replay = MemoryLiveEvidenceReplayGuard::new();
    for domain_index in 0..12 {
        for coordinate in [
            AuthorityCoordinate::Root,
            AuthorityCoordinate::Epoch,
            AuthorityCoordinate::ActivationId,
        ] {
            let mut substituted_authority = fixture.authority.clone();
            mutate_authority_coordinate(&mut substituted_authority, domain_index, coordinate);
            let context = LiveActivationContext::new(
                fixture.scope.clone(),
                &fixture.route,
                &fixture.management,
                fixture.release,
                fixture.deployment_activation_id,
                substituted_authority,
            )?;
            let substituted_claims = claims(
                context,
                fixture.proofs.clone(),
                fixture.bundle.clone(),
                &fixture.collector,
                &fixture.operator,
                &fixture.registry,
                OBSERVED_AT,
                VALID_UNTIL,
            )?;
            let substituted_signed = fixture.resign(substituted_claims)?;
            assert!(
                matches!(
                    verify_fixture(&fixture, &substituted_signed, NOW, &replay),
                    Err(ActivationError::ActivationContextMismatch)
                ),
                "domain {domain_index}, coordinate {coordinate:?} was not bound"
            );
        }
    }
    assert_eq!(replay.consumed_count()?, 0);
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn signature_purpose_key_and_role_substitution_fail_without_replay_mutation() -> TestResult {
    let fixture = Fixture::new()?;
    let replay = MemoryLiveEvidenceReplayGuard::new();

    let mut substituted_evidence_id = fixture.signed.clone();
    substituted_evidence_id.claims.evidence_id = Uuid::from_u128(0x6002);
    assert!(matches!(
        verify_fixture(&fixture, &substituted_evidence_id, NOW, &replay),
        Err(ActivationError::SignaturePayloadMismatch)
    ));

    let mut substituted_identity_claims = fixture.claims.clone();
    substituted_identity_claims.collector.identity =
        "spiffe://corp.internal/accordlock/another-collector".to_owned();
    let substituted_identity_signed = fixture.resign(substituted_identity_claims)?;
    assert!(matches!(
        verify_fixture(&fixture, &substituted_identity_signed, NOW, &replay),
        Err(ActivationError::SignerBindingMismatch)
    ));

    let mut swapped = fixture.signed.clone();
    std::mem::swap(
        &mut swapped.collector_cose_sign1,
        &mut swapped.operator_cose_sign1,
    );
    assert!(matches!(
        verify_fixture(&fixture, &swapped, NOW, &replay),
        Err(ActivationError::SignatureInvalid)
    ));

    let wrong_collector = SigningIdentity::from_seed("activation-collector", [103; 32]);
    let wrong_key_registry = registry_from_entries(
        vec![
            signer_entry(
                &fixture.scope,
                fixture.route.cluster_identity(),
                LiveBoundarySignerRole::Collector,
                "spiffe://corp.internal/accordlock/activation-collector",
                &fixture.collector,
                wrong_collector.public_key_bytes(),
                LiveBoundarySignerStatus::Active,
            )?,
            signer_entry(
                &fixture.scope,
                fixture.route.cluster_identity(),
                LiveBoundarySignerRole::Operator,
                "urn:accordlock:operator:release-approver",
                &fixture.operator,
                fixture.operator.public_key_bytes(),
                LiveBoundarySignerStatus::Active,
            )?,
        ],
        0x7002,
    )?;
    let wrong_key_claims = claims(
        fixture.claims.activation_context.clone(),
        fixture.proofs.clone(),
        fixture.bundle.clone(),
        &fixture.collector,
        &fixture.operator,
        &wrong_key_registry,
        OBSERVED_AT,
        VALID_UNTIL,
    )?;
    let wrong_key_signed = fixture.resign(wrong_key_claims)?;
    assert!(matches!(
        verify_with(
            &fixture,
            &wrong_key_registry,
            &wrong_key_signed,
            NOW,
            &fixture.scope,
            &fixture.route,
            &fixture.management,
            fixture.release,
            fixture.deployment_activation_id,
            &fixture.authority,
            &fixture.proofs,
            &fixture.bundle,
            &replay,
        ),
        Err(ActivationError::SignatureInvalid)
    ));

    let role_swapped_registry = registry_from_entries(
        vec![
            signer_entry(
                &fixture.scope,
                fixture.route.cluster_identity(),
                LiveBoundarySignerRole::Collector,
                "urn:accordlock:operator:release-approver",
                &fixture.operator,
                fixture.operator.public_key_bytes(),
                LiveBoundarySignerStatus::Active,
            )?,
            signer_entry(
                &fixture.scope,
                fixture.route.cluster_identity(),
                LiveBoundarySignerRole::Operator,
                "spiffe://corp.internal/accordlock/activation-collector",
                &fixture.collector,
                fixture.collector.public_key_bytes(),
                LiveBoundarySignerStatus::Active,
            )?,
        ],
        0x7003,
    )?;
    let role_claims = claims(
        fixture.claims.activation_context.clone(),
        fixture.proofs.clone(),
        fixture.bundle.clone(),
        &fixture.collector,
        &fixture.operator,
        &role_swapped_registry,
        OBSERVED_AT,
        VALID_UNTIL,
    )?;
    let role_signed = fixture.resign(role_claims)?;
    assert!(matches!(
        verify_with(
            &fixture,
            &role_swapped_registry,
            &role_signed,
            NOW,
            &fixture.scope,
            &fixture.route,
            &fixture.management,
            fixture.release,
            fixture.deployment_activation_id,
            &fixture.authority,
            &fixture.proofs,
            &fixture.bundle,
            &replay,
        ),
        Err(ActivationError::SignerRoleMismatch)
    ));
    assert_eq!(replay.consumed_count()?, 0);
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn wrong_registry_scope_cluster_identity_and_status_fail() -> TestResult {
    let fixture = Fixture::new()?;
    let replay = MemoryLiveEvidenceReplayGuard::new();

    let revoked_registry = registry(
        &fixture.scope,
        fixture.route.cluster_identity(),
        &fixture.collector,
        &fixture.operator,
        LiveBoundarySignerStatus::Revoked,
        LiveBoundarySignerStatus::Active,
        0x7101,
    )?;
    let revoked_claims = claims(
        fixture.claims.activation_context.clone(),
        fixture.proofs.clone(),
        fixture.bundle.clone(),
        &fixture.collector,
        &fixture.operator,
        &revoked_registry,
        OBSERVED_AT,
        VALID_UNTIL,
    )?;
    let revoked_signed = fixture.resign(revoked_claims)?;
    assert!(matches!(
        verify_with(
            &fixture,
            &revoked_registry,
            &revoked_signed,
            NOW,
            &fixture.scope,
            &fixture.route,
            &fixture.management,
            fixture.release,
            fixture.deployment_activation_id,
            &fixture.authority,
            &fixture.proofs,
            &fixture.bundle,
            &replay,
        ),
        Err(ActivationError::SignerInactive)
    ));

    let other_scope = ActivationScope::new("other", "production")?;
    let scoped_registry = registry(
        &other_scope,
        fixture.route.cluster_identity(),
        &fixture.collector,
        &fixture.operator,
        LiveBoundarySignerStatus::Active,
        LiveBoundarySignerStatus::Active,
        0x7102,
    )?;
    let scoped_claims = claims(
        fixture.claims.activation_context.clone(),
        fixture.proofs.clone(),
        fixture.bundle.clone(),
        &fixture.collector,
        &fixture.operator,
        &scoped_registry,
        OBSERVED_AT,
        VALID_UNTIL,
    )?;
    let scoped_signed = fixture.resign(scoped_claims)?;
    assert!(matches!(
        verify_with(
            &fixture,
            &scoped_registry,
            &scoped_signed,
            NOW,
            &fixture.scope,
            &fixture.route,
            &fixture.management,
            fixture.release,
            fixture.deployment_activation_id,
            &fixture.authority,
            &fixture.proofs,
            &fixture.bundle,
            &replay,
        ),
        Err(ActivationError::SignerBindingMismatch)
    ));

    let cluster_registry = registry(
        &fixture.scope,
        "arn:aws:eks:eu-west-1:111122223333:cluster/other",
        &fixture.collector,
        &fixture.operator,
        LiveBoundarySignerStatus::Active,
        LiveBoundarySignerStatus::Active,
        0x7103,
    )?;
    let cluster_claims = claims(
        fixture.claims.activation_context.clone(),
        fixture.proofs.clone(),
        fixture.bundle.clone(),
        &fixture.collector,
        &fixture.operator,
        &cluster_registry,
        OBSERVED_AT,
        VALID_UNTIL,
    )?;
    let cluster_signed = fixture.resign(cluster_claims)?;
    assert!(matches!(
        verify_with(
            &fixture,
            &cluster_registry,
            &cluster_signed,
            NOW,
            &fixture.scope,
            &fixture.route,
            &fixture.management,
            fixture.release,
            fixture.deployment_activation_id,
            &fixture.authority,
            &fixture.proofs,
            &fixture.bundle,
            &replay,
        ),
        Err(ActivationError::SignerBindingMismatch)
    ));
    assert_eq!(replay.consumed_count()?, 0);
    Ok(())
}

#[test]
fn time_is_checked_after_signatures_and_before_replay() -> TestResult {
    let fixture = Fixture::new()?;
    let replay = MemoryLiveEvidenceReplayGuard::new();

    let mut invalid_signature = fixture.signed.clone();
    invalid_signature.collector_cose_sign1.push(0);
    assert!(matches!(
        verify_fixture(&fixture, &invalid_signature, VALID_UNTIL, &replay),
        Err(ActivationError::SignatureInvalid)
    ));
    assert_eq!(replay.consumed_count()?, 0);

    assert!(matches!(
        verify_fixture(&fixture, &fixture.signed, OBSERVED_AT - 1, &replay),
        Err(ActivationError::ObservationInFuture)
    ));
    assert_eq!(replay.consumed_count()?, 0);

    assert!(matches!(
        verify_fixture(&fixture, &fixture.signed, VALID_UNTIL, &replay),
        Err(ActivationError::AttestationExpired)
    ));
    assert_eq!(replay.consumed_count()?, 0);
    Ok(())
}

#[test]
fn constructors_enforce_scope_bundle_lifetime_registry_and_envelope_bounds() -> TestResult {
    assert!(matches!(
        ActivationScope::new(" acme", "production"),
        Err(ActivationError::InvalidScope)
    ));
    assert!(matches!(
        LiveEvidenceBundleBinding::new(digest(1), digest(2), 0),
        Err(ActivationError::InvalidBundleBinding)
    ));
    assert!(matches!(
        LiveEvidenceBundleBinding::new(digest(1), digest(2), MAX_LIVE_BOUNDARY_RAW_ARTIFACTS + 1,),
        Err(ActivationError::InvalidBundleBinding)
    ));
    assert!(matches!(
        LiveProofCommitments::new(digest(3), digest(3), digest(4)),
        Err(ActivationError::InvalidProofSet)
    ));

    let fixture = Fixture::new()?;
    assert!(matches!(
        claims(
            fixture.claims.activation_context.clone(),
            fixture.proofs.clone(),
            fixture.bundle.clone(),
            &fixture.collector,
            &fixture.operator,
            &fixture.registry,
            OBSERVED_AT,
            OBSERVED_AT + MAX_LIVE_BOUNDARY_LIFETIME_SECONDS + 1,
        ),
        Err(ActivationError::InvalidClaims)
    ));
    assert!(matches!(
        SignedLiveDeploymentBoundaryAttestation::from_parts(
            fixture.claims.clone(),
            vec![0; MAX_LIVE_BOUNDARY_COSE_BYTES + 1],
            vec![1],
        ),
        Err(ActivationError::EnvelopeTooLarge)
    ));
    assert!(matches!(
        ActivatedLiveBoundaryRegistry::compute_material_root(&[]),
        Err(ActivationError::InvalidRegistry)
    ));

    let aliased = vec![
        signer_entry(
            &fixture.scope,
            fixture.route.cluster_identity(),
            LiveBoundarySignerRole::Collector,
            "spiffe://corp.internal/accordlock/activation-collector",
            &fixture.collector,
            fixture.collector.public_key_bytes(),
            LiveBoundarySignerStatus::Active,
        )?,
        signer_entry(
            &fixture.scope,
            fixture.route.cluster_identity(),
            LiveBoundarySignerRole::Operator,
            "urn:accordlock:operator:release-approver",
            &fixture.operator,
            fixture.collector.public_key_bytes(),
            LiveBoundarySignerStatus::Active,
        )?,
    ];
    assert!(matches!(
        ActivatedLiveBoundaryRegistry::compute_material_root(&aliased),
        Err(ActivationError::InvalidRegistry)
    ));
    Ok(())
}

#[test]
fn registry_activation_substitution_is_refused_before_replay() -> TestResult {
    let fixture = Fixture::new()?;
    let replay = MemoryLiveEvidenceReplayGuard::new();
    let alternate_registry = registry(
        &fixture.scope,
        fixture.route.cluster_identity(),
        &fixture.collector,
        &fixture.operator,
        LiveBoundarySignerStatus::Active,
        LiveBoundarySignerStatus::Active,
        0x7201,
    )?;
    assert!(matches!(
        verify_with(
            &fixture,
            &alternate_registry,
            &fixture.signed,
            NOW,
            &fixture.scope,
            &fixture.route,
            &fixture.management,
            fixture.release,
            fixture.deployment_activation_id,
            &fixture.authority,
            &fixture.proofs,
            &fixture.bundle,
            &replay,
        ),
        Err(ActivationError::RegistryMismatch)
    ));
    assert_eq!(replay.consumed_count()?, 0);
    Ok(())
}
