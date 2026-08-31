use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
};

use accordlock_protocol::{
    AuthorityDomainState, AuthorityVector, CanonicalEncode, CompletenessProfile, CryptoError,
    Digest32, EvidenceKind, EvidencePayload, SigningIdentity, verify_cose,
};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::*;

const NOW: i64 = 1_900_000_000;

#[derive(Debug)]
struct AtomicClock(Arc<AtomicI64>);

impl TrustedClock for AtomicClock {
    fn unix_seconds(&self) -> Result<i64, ClockReadError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

#[derive(Clone, Debug)]
struct ReviewMock {
    snapshot: ReviewSourceSnapshot,
    sequence: Arc<AtomicU64>,
    approved: Arc<AtomicBool>,
}

impl ReviewSource for ReviewMock {
    fn identity_descriptor(&self) -> Result<ConnectorSourceIdentityDescriptor, ConnectorError> {
        source_identity(
            EvidenceKind::Review,
            "https://review.example.invalid/",
            0x71,
        )
    }

    fn fetch(&self, _lookup: &ReviewLookupId) -> Result<ReviewSourceSnapshot, SourceReadError> {
        let mut snapshot = self.snapshot.clone();
        snapshot.meta.source_sequence = self.sequence.load(Ordering::SeqCst);
        snapshot.approved = self.approved.load(Ordering::SeqCst);
        Ok(snapshot)
    }
}

#[derive(Clone, Debug)]
struct BuildMock(BuildSourceSnapshot);

impl BuildSource for BuildMock {
    fn identity_descriptor(&self) -> Result<ConnectorSourceIdentityDescriptor, ConnectorError> {
        source_identity(EvidenceKind::Build, "https://build.example.invalid/", 0x72)
    }

    fn fetch(&self, _lookup: &BuildLookupId) -> Result<BuildSourceSnapshot, SourceReadError> {
        Ok(self.0.clone())
    }
}

#[derive(Clone, Debug)]
struct ArtifactMock(ArtifactSourceSnapshot);

impl ArtifactSource for ArtifactMock {
    fn identity_descriptor(&self) -> Result<ConnectorSourceIdentityDescriptor, ConnectorError> {
        source_identity(
            EvidenceKind::Artifact,
            "https://artifact.example.invalid/",
            0x73,
        )
    }

    fn fetch(&self, _lookup: &ArtifactLookupId) -> Result<ArtifactSourceSnapshot, SourceReadError> {
        Ok(self.0.clone())
    }
}

#[derive(Clone, Debug)]
struct TargetMock(TargetSourceSnapshot);

impl TargetSource for TargetMock {
    fn identity_descriptor(&self) -> Result<ConnectorSourceIdentityDescriptor, ConnectorError> {
        source_identity(
            EvidenceKind::Target,
            "https://target.example.invalid/",
            0x74,
        )
    }

    fn fetch(&self, _lookup: &TargetLookupId) -> Result<TargetSourceSnapshot, SourceReadError> {
        Ok(self.0.clone())
    }
}

struct Fixture {
    request: EvidenceLookupRequest,
    review: ReviewMock,
    build: BuildSourceSnapshot,
    artifact: ArtifactSourceSnapshot,
    target: TargetSourceSnapshot,
    clock: Arc<AtomicI64>,
}

fn domain(seed: u8) -> AuthorityDomainState {
    AuthorityDomainState {
        root: Digest32::from_bytes([seed; 32]),
        epoch: u64::from(seed),
        activation_id: Uuid::from_bytes([seed; 16]),
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

fn source_identity(
    kind: EvidenceKind,
    endpoint: &str,
    seed: u8,
) -> Result<ConnectorSourceIdentityDescriptor, ConnectorError> {
    ConnectorSourceIdentityDescriptor::new(
        kind,
        endpoint,
        Digest32::from_bytes([seed; 32]),
        Digest32::from_bytes([seed.wrapping_add(1); 32]),
    )
}

fn meta(
    request_id: Uuid,
    lookup_id: &str,
    evidence_seed: u8,
    source_uri: &str,
    sequence: u64,
) -> SourceSnapshotMeta {
    SourceSnapshotMeta {
        request_id,
        lookup_id: lookup_id.to_owned(),
        evidence_id: Uuid::from_bytes([evidence_seed; 16]),
        source_uri: source_uri.to_owned(),
        observed_at: NOW - 10,
        source_sequence: sequence,
    }
}

fn fixture() -> Result<Fixture, ConnectorError> {
    let request_id = Uuid::from_bytes([0xa0; 16]);
    let request = EvidenceLookupRequest::new(
        request_id,
        ReviewLookupId::parse("review/17")?,
        BuildLookupId::parse("build/83")?,
        ArtifactLookupId::parse("artifact/sha256:22")?,
        TargetLookupId::parse("target/prod/payments")?,
    );
    let commit_sha = "a".repeat(40);
    let output_digest = Digest32::from_bytes([0x22; 32]);
    let review_snapshot = ReviewSourceSnapshot {
        meta: meta(
            request_id,
            request.review_lookup_id.as_str(),
            1,
            "https://review.example.invalid/records/17",
            101,
        ),
        repository: "acme/payments".to_owned(),
        commit_sha: commit_sha.clone(),
        approved: true,
        review_state_id: "review-state-17".to_owned(),
    };
    Ok(Fixture {
        request,
        review: ReviewMock {
            snapshot: review_snapshot,
            sequence: Arc::new(AtomicU64::new(101)),
            approved: Arc::new(AtomicBool::new(true)),
        },
        build: BuildSourceSnapshot {
            meta: meta(
                request_id,
                "build/83",
                2,
                "https://build.example.invalid/runs/83",
                201,
            ),
            repository: "acme/payments".to_owned(),
            commit_sha: commit_sha.clone(),
            workflow_ref: "acme/payments/.github/workflows/release.yml@refs/heads/main".to_owned(),
            run_id: "83".to_owned(),
            succeeded: true,
            input_manifest_root: Digest32::from_bytes([0x11; 32]),
            completeness_profile: CompletenessProfile::HermeticInputsV1,
            output_digest,
        },
        artifact: ArtifactSourceSnapshot {
            meta: meta(
                request_id,
                "artifact/sha256:22",
                3,
                "https://artifact.example.invalid/manifests/sha256:22",
                301,
            ),
            source_repository: "acme/payments".to_owned(),
            commit_sha: commit_sha.clone(),
            image_repository: "registry.example.invalid/acme/payments".to_owned(),
            digest: output_digest,
            source_run_id: "83".to_owned(),
            signature_valid: true,
            quarantined: false,
        },
        target: TargetSourceSnapshot {
            meta: meta(
                request_id,
                "target/prod/payments",
                4,
                "https://target.example.invalid/clusters/prod/deployments/payments",
                401,
            ),
            source_repository: "acme/payments".to_owned(),
            commit_sha,
            image_repository: "registry.example.invalid/acme/payments".to_owned(),
            desired_image_digest: output_digest,
            cluster_identity: "eks://111122223333/us-east-1/prod".to_owned(),
            namespace: "payments-prod".to_owned(),
            deployment: "payments".to_owned(),
            deployment_uid: "11111111-2222-4333-8444-555555555555".to_owned(),
            resource_version: "83191".to_owned(),
            current_image: Digest32::from_bytes([0x33; 32]),
            projection_hash: Digest32::from_bytes([0x44; 32]),
        },
        clock: Arc::new(AtomicI64::new(NOW)),
    })
}

fn route(
    kind: EvidenceKind,
    seed: u8,
    prefix: &str,
) -> Result<TrustedEvidenceRoute, ConnectorError> {
    TrustedEvidenceRoute::new(
        kind,
        format!("connector-{kind:?}").to_lowercase(),
        prefix,
        SigningIdentity::from_seed(format!("connector-{kind:?}-key").to_lowercase(), [seed; 32]),
    )
}

fn runtime(value: &Fixture) -> Result<ConnectorRuntime, ConnectorError> {
    let sources = TrustedSourceSet::new(
        Box::new(value.review.clone()),
        Box::new(BuildMock(value.build.clone())),
        Box::new(ArtifactMock(value.artifact.clone())),
        Box::new(TargetMock(value.target.clone())),
    )?;
    let routes = TrustedRouteSet::new(
        route(EvidenceKind::Review, 11, "https://review.example.invalid/")?,
        route(EvidenceKind::Build, 12, "https://build.example.invalid/")?,
        route(
            EvidenceKind::Artifact,
            13,
            "https://artifact.example.invalid/",
        )?,
        route(EvidenceKind::Target, 14, "https://target.example.invalid/")?,
    )?;
    Ok(ConnectorRuntime::new(
        sources,
        routes,
        Box::new(AtomicClock(Arc::clone(&value.clock))),
        authority(),
        ValidityProfile::new(300, 60, 5, CompletenessProfile::HermeticInputsV1)?,
    ))
}

#[test]
fn lookup_only_request_rejects_every_security_fact_injection_surface()
-> Result<(), Box<dyn std::error::Error>> {
    let value = serde_json::to_value(&fixture()?.request)?;
    let object = value
        .as_object()
        .ok_or("request did not serialize as an object")?;
    let expected = [
        "request_id",
        "review_lookup_id",
        "build_lookup_id",
        "artifact_lookup_id",
        "target_lookup_id",
    ];
    assert_eq!(object.len(), expected.len());
    assert!(expected.iter().all(|field| object.contains_key(*field)));

    for (field, injected) in [
        ("approved", json!(true)),
        ("succeeded", json!(true)),
        ("signature_valid", json!(true)),
        ("quarantined", json!(false)),
        ("grade", json!(4)),
        ("issuer", json!("attacker")),
        ("key_id", json!("attacker-key")),
        ("authority", json!({})),
        ("observed_at", json!(NOW)),
        ("valid_until", json!(NOW + 10_000)),
        ("verdict", json!("ALLOW")),
        ("evidence", json!([])),
    ] {
        let mut attempted = value.clone();
        attempted
            .as_object_mut()
            .ok_or("request did not serialize as an object")?
            .insert(field.to_owned(), injected);
        assert!(serde_json::from_value::<EvidenceLookupRequest>(attempted).is_err());
    }
    Ok(())
}

#[test]
fn maps_exact_protocol_payloads_and_cose_domains() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let runtime = runtime(&fixture)?;
    let attesters = runtime.attesters();
    let output = runtime.collect(&fixture.request)?;
    assert_eq!(output.request_id, fixture.request.request_id);
    assert_eq!(output.evidence.len(), 4);

    for signed in &output.evidence {
        let descriptor = attesters
            .iter()
            .find(|candidate| candidate.kind == signed.assertion.payload.kind())
            .ok_or("missing descriptor")?;
        assert_eq!(signed.assertion.issuer, descriptor.issuer);
        assert_eq!(signed.assertion.key_id, descriptor.key_id);
        assert_eq!(signed.assertion.request_id, fixture.request.request_id);
        assert_eq!(
            signed.assertion.schema_version,
            accordlock_protocol::EVIDENCE_ASSERTION_SCHEMA_VERSION
        );
        assert_eq!(signed.assertion.authority, authority());
        assert_eq!(
            signed.assertion.valid_until,
            signed.assertion.observed_at + 300
        );
        let verifier = accordlock_protocol::CoseVerifier::from_public_key(
            descriptor.key_id.clone(),
            descriptor.public_key,
        )?;
        let canonical = signed.assertion.canonical_bytes()?;
        assert_eq!(
            verify_cose(
                &signed.cose_sign1,
                signed.assertion.payload.kind().domain(),
                &verifier,
            )?,
            canonical,
        );
        let wrong_domain = match signed.assertion.payload.kind() {
            EvidenceKind::Review => EvidenceKind::Build.domain(),
            _ => EvidenceKind::Review.domain(),
        };
        assert!(matches!(
            verify_cose(&signed.cose_sign1, wrong_domain, &verifier),
            Err(CryptoError::InvalidSignature)
        ));
    }

    assert!(matches!(
        &output.evidence[0].assertion.payload,
        EvidencePayload::Review { repository, commit_sha, approved: true, review_state_id }
            if repository == "acme/payments"
                && commit_sha == &"a".repeat(40)
                && review_state_id == "review-state-17"
    ));
    assert!(matches!(
        &output.evidence[1].assertion.payload,
        EvidencePayload::Build { repository, run_id, succeeded: true, output_digest, .. }
            if repository == "acme/payments" && run_id == "83"
                && *output_digest == Digest32::from_bytes([0x22; 32])
    ));
    assert!(matches!(
        &output.evidence[2].assertion.payload,
        EvidencePayload::Artifact { repository, digest, signature_valid: true, quarantined: false, .. }
            if repository == "registry.example.invalid/acme/payments"
                && *digest == Digest32::from_bytes([0x22; 32])
    ));
    assert!(matches!(
        &output.evidence[3].assertion.payload,
        EvidencePayload::Target { cluster_identity, namespace, deployment, .. }
            if cluster_identity == "eks://111122223333/us-east-1/prod"
                && namespace == "payments-prod" && deployment == "payments"
    ));
    Ok(())
}

#[test]
fn request_and_lookup_mismatches_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let mut request_mismatch = fixture()?;
    request_mismatch.build.meta.request_id = Uuid::from_bytes([0xbb; 16]);
    assert!(matches!(
        runtime(&request_mismatch)?.collect(&request_mismatch.request),
        Err(ConnectorError::RequestBindingMismatch {
            kind: EvidenceKind::Build
        })
    ));

    let mut lookup_mismatch = fixture()?;
    lookup_mismatch.target.meta.lookup_id = "target/prod/other".to_owned();
    assert!(matches!(
        runtime(&lookup_mismatch)?.collect(&lookup_mismatch.request),
        Err(ConnectorError::LookupBindingMismatch {
            kind: EvidenceKind::Target
        })
    ));
    Ok(())
}

#[test]
fn stale_future_and_clock_rollback_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let mut stale = fixture()?;
    stale.review.snapshot.meta.observed_at = NOW - 61;
    assert!(matches!(
        runtime(&stale)?.collect(&stale.request),
        Err(ConnectorError::StaleObservation {
            kind: EvidenceKind::Review
        })
    ));

    let mut future = fixture()?;
    future.artifact.meta.observed_at = NOW + 6;
    assert!(matches!(
        runtime(&future)?.collect(&future.request),
        Err(ConnectorError::FutureObservation {
            kind: EvidenceKind::Artifact
        })
    ));

    let fixture = fixture()?;
    let runtime = runtime(&fixture)?;
    runtime.collect(&fixture.request)?;
    fixture.clock.store(NOW - 1, Ordering::SeqCst);
    assert!(matches!(
        runtime.collect(&fixture.request),
        Err(ConnectorError::ClockRollback)
    ));
    Ok(())
}

#[test]
fn source_rollback_and_same_cursor_equivocation_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let rollback_fixture = fixture()?;
    let rollback_runtime = runtime(&rollback_fixture)?;
    rollback_runtime.collect(&rollback_fixture.request)?;
    rollback_fixture
        .review
        .sequence
        .store(100, Ordering::SeqCst);
    assert!(matches!(
        rollback_runtime.collect(&rollback_fixture.request),
        Err(ConnectorError::SourceRollback {
            kind: EvidenceKind::Review
        })
    ));

    let equivocation_fixture = fixture()?;
    let equivocation_runtime = runtime(&equivocation_fixture)?;
    equivocation_runtime.collect(&equivocation_fixture.request)?;
    equivocation_fixture
        .review
        .approved
        .store(false, Ordering::SeqCst);
    assert!(matches!(
        equivocation_runtime.collect(&equivocation_fixture.request),
        Err(ConnectorError::SourceEquivocation {
            kind: EvidenceKind::Review
        })
    ));
    Ok(())
}

#[test]
fn wrong_commit_output_and_target_routes_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let mut commit = fixture()?;
    commit.artifact.commit_sha = "b".repeat(40);
    assert!(matches!(
        runtime(&commit)?.collect(&commit.request),
        Err(ConnectorError::CommitRouteMismatch)
    ));

    let mut output = fixture()?;
    output.artifact.digest = Digest32::from_bytes([0x99; 32]);
    assert!(matches!(
        runtime(&output)?.collect(&output.request),
        Err(ConnectorError::OutputRouteMismatch)
    ));

    let mut target = fixture()?;
    target.target.image_repository = "registry.example.invalid/acme/other".to_owned();
    assert!(matches!(
        runtime(&target)?.collect(&target.request),
        Err(ConnectorError::TargetRouteMismatch)
    ));
    Ok(())
}

#[test]
fn duplicate_ids_bad_source_uri_and_incomplete_build_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let mut duplicate = fixture()?;
    duplicate.target.meta.evidence_id = duplicate.build.meta.evidence_id;
    assert!(matches!(
        runtime(&duplicate)?.collect(&duplicate.request),
        Err(ConnectorError::DuplicateEvidenceId)
    ));

    let mut uri = fixture()?;
    uri.review.snapshot.meta.source_uri =
        "https://review.example.invalid.attacker.test/records/17".to_owned();
    assert!(matches!(
        runtime(&uri)?.collect(&uri.request),
        Err(ConnectorError::SourceUriMismatch {
            kind: EvidenceKind::Review
        })
    ));

    let mut incomplete = fixture()?;
    incomplete.build.completeness_profile = CompletenessProfile::DeclaredMaterials;
    assert!(matches!(
        runtime(&incomplete)?.collect(&incomplete.request),
        Err(ConnectorError::CompletenessProfileMismatch)
    ));
    Ok(())
}

#[test]
fn serialized_lookup_bounds_and_unknown_fields_are_enforced() {
    assert!(ReviewLookupId::parse(" x").is_err());
    assert!(BuildLookupId::parse("x\n").is_err());
    assert!(ArtifactLookupId::parse("x".repeat(MAX_LOOKUP_ID_BYTES + 1)).is_err());

    let attempted: Value = json!({
        "request_id": Uuid::from_bytes([1; 16]),
        "review_lookup_id": "review/1",
        "build_lookup_id": "build/1",
        "artifact_lookup_id": "artifact/1",
        "target_lookup_id": "target/1",
        "payload": { "approved": true }
    });
    assert!(serde_json::from_value::<EvidenceLookupRequest>(attempted).is_err());
}

#[test]
fn route_kind_substitution_is_rejected_at_bootstrap() -> Result<(), Box<dyn std::error::Error>> {
    let result = TrustedRouteSet::new(
        route(EvidenceKind::Build, 21, "https://review.example.invalid/")?,
        route(EvidenceKind::Review, 22, "https://build.example.invalid/")?,
        route(
            EvidenceKind::Artifact,
            23,
            "https://artifact.example.invalid/",
        )?,
        route(EvidenceKind::Target, 24, "https://target.example.invalid/")?,
    );
    assert!(matches!(
        result,
        Err(ConnectorError::InvalidConfiguration("route kind"))
    ));
    Ok(())
}
