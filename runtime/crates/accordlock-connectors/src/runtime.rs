use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    sync::Mutex,
};

use accordlock_protocol::{
    AuthorityVector, CanonicalEncode, CoseVerifier, Digest32, EVIDENCE_ASSERTION_SCHEMA_VERSION,
    EvidenceAssertion, EvidenceKind, EvidencePayload, SignedEvidence, SigningIdentity,
    TrustedEvidenceSet, sign_cose,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::{
    ArtifactSource, ArtifactSourceSnapshot, BuildSource, BuildSourceSnapshot, ConnectorError,
    ConnectorSourceIdentityDescriptor, EvidenceLookupRequest, MAX_SOURCE_URI_BYTES, ReviewSource,
    ReviewSourceSnapshot, TargetSource, TargetSourceSnapshot, TrustedClock, ValidityProfile,
    validate_commit_sha, validate_lookup_id, validate_text,
};

const CONNECTOR_COMMITMENT_DOMAIN: &[u8] = b"accordlock:v1:connector-runtime";

/// Fixed identity and source-URI route for one trusted source adapter.
pub struct TrustedEvidenceRoute {
    kind: EvidenceKind,
    issuer: String,
    source_uri_prefix: String,
    signer: SigningIdentity,
}

impl fmt::Debug for TrustedEvidenceRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedEvidenceRoute")
            .field("kind", &self.kind)
            .field("issuer", &self.issuer)
            .field("source_uri_prefix", &self.source_uri_prefix)
            .field("key_id", &self.signer.key_id())
            .field("signer", &"<redacted>")
            .finish()
    }
}

impl TrustedEvidenceRoute {
    /// Creates a route at trusted bootstrap.
    ///
    /// `source_uri_prefix` must be a complete HTTPS origin and path prefix
    /// ending in `/`. Collection records must remain below that prefix.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorError::InvalidConfiguration`] for an invalid issuer,
    /// URI route, or signing identity.
    pub fn new(
        kind: EvidenceKind,
        issuer: impl Into<String>,
        source_uri_prefix: impl Into<String>,
        signer: SigningIdentity,
    ) -> Result<Self, ConnectorError> {
        let issuer = issuer.into();
        let source_uri_prefix = source_uri_prefix.into();
        validate_text(&issuer, "issuer", 256)
            .map_err(|_| ConnectorError::InvalidConfiguration("route issuer"))?;
        validate_uri_prefix(&source_uri_prefix)?;
        CoseVerifier::from_public_key(signer.key_id(), signer.public_key_bytes())
            .map_err(|_| ConnectorError::InvalidConfiguration("route signing identity"))?;
        Ok(Self {
            kind,
            issuer,
            source_uri_prefix,
            signer,
        })
    }
}

/// Public verification material for registering one connector attester.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectorAttesterDescriptor {
    pub kind: EvidenceKind,
    pub issuer: String,
    pub key_id: String,
    pub public_key: [u8; 32],
    pub source_uri_prefix: String,
}

/// Four adapters fixed for the lifetime of one runtime.
pub struct TrustedSourceSet {
    review: Box<dyn ReviewSource>,
    build: Box<dyn BuildSource>,
    artifact: Box<dyn ArtifactSource>,
    target: Box<dyn TargetSource>,
    identities: [ConnectorSourceIdentityDescriptor; 4],
}

impl fmt::Debug for TrustedSourceSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedSourceSet")
            .field("review", &"<trusted adapter>")
            .field("build", &"<trusted adapter>")
            .field("artifact", &"<trusted adapter>")
            .field("target", &"<trusted adapter>")
            .finish()
    }
}

impl TrustedSourceSet {
    /// # Errors
    ///
    /// Rejects any source whose intrinsic identity reports the wrong kind.
    pub fn new(
        review: Box<dyn ReviewSource>,
        build: Box<dyn BuildSource>,
        artifact: Box<dyn ArtifactSource>,
        target: Box<dyn TargetSource>,
    ) -> Result<Self, ConnectorError> {
        let identities = [
            review.identity_descriptor()?,
            build.identity_descriptor()?,
            artifact.identity_descriptor()?,
            target.identity_descriptor()?,
        ];
        let expected = [
            EvidenceKind::Review,
            EvidenceKind::Build,
            EvidenceKind::Artifact,
            EvidenceKind::Target,
        ];
        if identities
            .iter()
            .zip(expected)
            .any(|(descriptor, kind)| descriptor.kind != kind)
        {
            return Err(ConnectorError::InvalidConfiguration("source identity kind"));
        }
        Ok(Self {
            review,
            build,
            artifact,
            target,
            identities,
        })
    }
}

/// Four signer/URI routes fixed for the lifetime of one runtime.
#[derive(Debug)]
pub struct TrustedRouteSet {
    review: TrustedEvidenceRoute,
    build: TrustedEvidenceRoute,
    artifact: TrustedEvidenceRoute,
    target: TrustedEvidenceRoute,
}

impl TrustedRouteSet {
    /// Creates the route set and rejects kind-position substitution.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorError::InvalidConfiguration`] when any route is in
    /// the wrong evidence-kind position or key identifiers are duplicated.
    pub fn new(
        review: TrustedEvidenceRoute,
        build: TrustedEvidenceRoute,
        artifact: TrustedEvidenceRoute,
        target: TrustedEvidenceRoute,
    ) -> Result<Self, ConnectorError> {
        if review.kind != EvidenceKind::Review
            || build.kind != EvidenceKind::Build
            || artifact.kind != EvidenceKind::Artifact
            || target.kind != EvidenceKind::Target
        {
            return Err(ConnectorError::InvalidConfiguration("route kind"));
        }
        let key_ids = [
            review.signer.key_id(),
            build.signer.key_id(),
            artifact.signer.key_id(),
            target.signer.key_id(),
        ];
        if key_ids.iter().copied().collect::<HashSet<_>>().len() != key_ids.len() {
            return Err(ConnectorError::InvalidConfiguration(
                "evidence key identifiers must be distinct",
            ));
        }
        Ok(Self {
            review,
            build,
            artifact,
            target,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SourceCheckpoint {
    sequence: u64,
    commitment: Digest32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EvidenceUse {
    request_id: Uuid,
    assertion_commitment: Digest32,
}

#[derive(Debug, Default)]
struct CheckpointState {
    last_clock: Option<i64>,
    sources: BTreeMap<EvidenceKind, SourceCheckpoint>,
    evidence_ids: HashMap<Uuid, EvidenceUse>,
}

/// Fixed trusted connector runtime.
///
/// Runtime construction is a trusted bootstrap operation. Per-request callers
/// can only pass [`EvidenceLookupRequest`]. Rollback checkpoints are atomic
/// across all four source observations but are process-local in this crate.
pub struct ConnectorRuntime {
    sources: TrustedSourceSet,
    routes: TrustedRouteSet,
    clock: Box<dyn TrustedClock>,
    authority: AuthorityVector,
    validity: ValidityProfile,
    checkpoints: Mutex<CheckpointState>,
}

/// Canonical public commitments checked by the enterprise runner at bootstrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorRuntimeCommitments {
    pub github_connector_hash: Digest32,
    pub ecr_connector_hash: Digest32,
    pub kubernetes_connector_hash: Digest32,
    pub ecr_transport_identity_hash: Digest32,
    pub kubernetes_transport_identity_hash: Digest32,
}

impl fmt::Debug for ConnectorRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectorRuntime")
            .field("sources", &self.sources)
            .field("routes", &self.routes)
            .field("clock", &"<trusted clock>")
            .field("authority", &self.authority)
            .field("validity", &self.validity)
            .field("checkpoints", &"<runtime state>")
            .finish()
    }
}

impl ConnectorRuntime {
    /// Constructs one runtime with immutable source, clock, authority, and
    /// signing configuration.
    #[must_use]
    pub fn new(
        sources: TrustedSourceSet,
        routes: TrustedRouteSet,
        clock: Box<dyn TrustedClock>,
        authority: AuthorityVector,
        validity: ValidityProfile,
    ) -> Self {
        Self {
            sources,
            routes,
            clock,
            authority,
            validity,
            checkpoints: Mutex::new(CheckpointState::default()),
        }
    }

    /// Returns public verification descriptors without exposing signing keys.
    #[must_use]
    pub fn attesters(&self) -> [ConnectorAttesterDescriptor; 4] {
        [
            descriptor(&self.routes.review),
            descriptor(&self.routes.build),
            descriptor(&self.routes.artifact),
            descriptor(&self.routes.target),
        ]
    }

    /// Commits to all four attesters and to the exact authority, validity,
    /// endpoint, adapter and authenticated-transport identities.
    ///
    /// # Errors
    ///
    /// Returns an error when a source endpoint disagrees with its attester
    /// route or canonical authority encoding fails.
    pub fn configuration_commitments(&self) -> Result<ConnectorRuntimeCommitments, ConnectorError> {
        let identities = &self.sources.identities;
        let attesters = self.attesters();
        if attesters
            .iter()
            .zip(identities)
            .any(|(attester, identity)| {
                attester.kind != identity.kind
                    || attester.source_uri_prefix != identity.endpoint_uri_prefix
            })
        {
            return Err(ConnectorError::RuntimeIdentityRouteMismatch);
        }
        let authority = self
            .authority
            .canonical_bytes()
            .map_err(|error| ConnectorError::Canonical(error.to_string()))?;
        let github_connector_hash = connector_commitment(
            0,
            &attesters[..2],
            &identities[..2],
            &authority,
            self.validity,
        );
        let ecr_connector_hash = connector_commitment(
            1,
            &attesters[2..3],
            &identities[2..3],
            &authority,
            self.validity,
        );
        let kubernetes_connector_hash = connector_commitment(
            2,
            &attesters[3..],
            &identities[3..],
            &authority,
            self.validity,
        );
        Ok(ConnectorRuntimeCommitments {
            github_connector_hash,
            ecr_connector_hash,
            kubernetes_connector_hash,
            ecr_transport_identity_hash: identities[2].transport_identity_hash,
            kubernetes_transport_identity_hash: identities[3].transport_identity_hash,
        })
    }

    /// Collects, validates, maps, and signs exactly four evidence assertions.
    ///
    /// # Errors
    ///
    /// Fails closed for any source, binding, route, time, rollback, canonical
    /// encoding, or cryptographic error. No partial evidence set is returned.
    pub fn collect(
        &self,
        request: &EvidenceLookupRequest,
    ) -> Result<TrustedEvidenceSet, ConnectorError> {
        if request.request_id.is_nil() {
            return Err(ConnectorError::NilRequestId);
        }
        let now = self
            .clock
            .unix_seconds()
            .map_err(|_| ConnectorError::InvalidConfiguration("trusted clock read"))?;
        if now < 0 {
            return Err(ConnectorError::InvalidConfiguration("trusted clock value"));
        }

        let review = self
            .sources
            .review
            .fetch(&request.review_lookup_id)
            .map_err(|error| source_error(EvidenceKind::Review, error.code()))?;
        let build = self
            .sources
            .build
            .fetch(&request.build_lookup_id)
            .map_err(|error| source_error(EvidenceKind::Build, error.code()))?;
        let artifact = self
            .sources
            .artifact
            .fetch(&request.artifact_lookup_id)
            .map_err(|error| source_error(EvidenceKind::Artifact, error.code()))?;
        let target = self
            .sources
            .target
            .fetch(&request.target_lookup_id)
            .map_err(|error| source_error(EvidenceKind::Target, error.code()))?;

        self.validate_review(request, &review, now)?;
        self.validate_build(request, &build, now)?;
        self.validate_artifact(request, &artifact, now)?;
        self.validate_target(request, &target, now)?;
        validate_cross_source_route(&review, &build, &artifact, &target)?;

        let evidence_ids = [
            review.meta.evidence_id,
            build.meta.evidence_id,
            artifact.meta.evidence_id,
            target.meta.evidence_id,
        ];
        if evidence_ids.iter().any(Uuid::is_nil)
            || evidence_ids.iter().copied().collect::<HashSet<_>>().len() != evidence_ids.len()
        {
            return Err(ConnectorError::DuplicateEvidenceId);
        }

        let prepared = [
            self.prepare_review(review)?,
            self.prepare_build(build)?,
            self.prepare_artifact(artifact)?,
            self.prepare_target(target)?,
        ];
        self.commit_checkpoints(now, &prepared)?;

        Ok(TrustedEvidenceSet {
            request_id: request.request_id,
            evidence: prepared.into_iter().map(|item| item.signed).collect(),
        })
    }

    fn validate_review(
        &self,
        request: &EvidenceLookupRequest,
        snapshot: &ReviewSourceSnapshot,
        now: i64,
    ) -> Result<(), ConnectorError> {
        validate_meta(
            &snapshot.meta,
            request.request_id,
            request.review_lookup_id.as_str(),
            EvidenceKind::Review,
            &self.routes.review.source_uri_prefix,
            now,
            self.validity,
        )?;
        validate_text(&snapshot.repository, "review.repository", 256)?;
        validate_commit_sha(&snapshot.commit_sha, "review.commit_sha")?;
        validate_text(&snapshot.review_state_id, "review.review_state_id", 256)
    }

    fn validate_build(
        &self,
        request: &EvidenceLookupRequest,
        snapshot: &BuildSourceSnapshot,
        now: i64,
    ) -> Result<(), ConnectorError> {
        validate_meta(
            &snapshot.meta,
            request.request_id,
            request.build_lookup_id.as_str(),
            EvidenceKind::Build,
            &self.routes.build.source_uri_prefix,
            now,
            self.validity,
        )?;
        validate_text(&snapshot.repository, "build.repository", 256)?;
        validate_commit_sha(&snapshot.commit_sha, "build.commit_sha")?;
        validate_text(&snapshot.workflow_ref, "build.workflow_ref", 512)?;
        validate_text(&snapshot.run_id, "build.run_id", 256)?;
        if snapshot.completeness_profile != self.validity.required_completeness_profile() {
            return Err(ConnectorError::CompletenessProfileMismatch);
        }
        Ok(())
    }

    fn validate_artifact(
        &self,
        request: &EvidenceLookupRequest,
        snapshot: &ArtifactSourceSnapshot,
        now: i64,
    ) -> Result<(), ConnectorError> {
        validate_meta(
            &snapshot.meta,
            request.request_id,
            request.artifact_lookup_id.as_str(),
            EvidenceKind::Artifact,
            &self.routes.artifact.source_uri_prefix,
            now,
            self.validity,
        )?;
        validate_text(
            &snapshot.source_repository,
            "artifact.source_repository",
            256,
        )?;
        validate_commit_sha(&snapshot.commit_sha, "artifact.commit_sha")?;
        validate_text(&snapshot.image_repository, "artifact.image_repository", 256)?;
        validate_text(&snapshot.source_run_id, "artifact.source_run_id", 256)
    }

    fn validate_target(
        &self,
        request: &EvidenceLookupRequest,
        snapshot: &TargetSourceSnapshot,
        now: i64,
    ) -> Result<(), ConnectorError> {
        validate_meta(
            &snapshot.meta,
            request.request_id,
            request.target_lookup_id.as_str(),
            EvidenceKind::Target,
            &self.routes.target.source_uri_prefix,
            now,
            self.validity,
        )?;
        validate_text(&snapshot.source_repository, "target.source_repository", 256)?;
        validate_commit_sha(&snapshot.commit_sha, "target.commit_sha")?;
        validate_text(&snapshot.image_repository, "target.image_repository", 256)?;
        validate_text(&snapshot.cluster_identity, "target.cluster_identity", 512)?;
        validate_text(&snapshot.namespace, "target.namespace", 253)?;
        validate_text(&snapshot.deployment, "target.deployment", 253)?;
        validate_text(&snapshot.deployment_uid, "target.deployment_uid", 256)?;
        validate_text(&snapshot.resource_version, "target.resource_version", 256)
    }

    fn prepare_review(
        &self,
        snapshot: ReviewSourceSnapshot,
    ) -> Result<PreparedEvidence, ConnectorError> {
        let payload = EvidencePayload::Review {
            repository: snapshot.repository,
            commit_sha: snapshot.commit_sha,
            approved: snapshot.approved,
            review_state_id: snapshot.review_state_id,
        };
        prepare(
            &snapshot.meta,
            payload,
            &[],
            &self.routes.review,
            &self.authority,
            self.validity,
        )
    }

    fn prepare_build(
        &self,
        snapshot: BuildSourceSnapshot,
    ) -> Result<PreparedEvidence, ConnectorError> {
        let payload = EvidencePayload::Build {
            repository: snapshot.repository,
            commit_sha: snapshot.commit_sha,
            workflow_ref: snapshot.workflow_ref,
            run_id: snapshot.run_id,
            succeeded: snapshot.succeeded,
            input_manifest_root: snapshot.input_manifest_root,
            completeness_profile: snapshot.completeness_profile,
            output_digest: snapshot.output_digest,
        };
        prepare(
            &snapshot.meta,
            payload,
            &[],
            &self.routes.build,
            &self.authority,
            self.validity,
        )
    }

    fn prepare_artifact(
        &self,
        snapshot: ArtifactSourceSnapshot,
    ) -> Result<PreparedEvidence, ConnectorError> {
        let extra = [
            snapshot.source_repository.as_bytes(),
            snapshot.commit_sha.as_bytes(),
        ];
        let payload = EvidencePayload::Artifact {
            repository: snapshot.image_repository,
            digest: snapshot.digest,
            source_run_id: snapshot.source_run_id,
            signature_valid: snapshot.signature_valid,
            quarantined: snapshot.quarantined,
        };
        prepare(
            &snapshot.meta,
            payload,
            &extra,
            &self.routes.artifact,
            &self.authority,
            self.validity,
        )
    }

    fn prepare_target(
        &self,
        snapshot: TargetSourceSnapshot,
    ) -> Result<PreparedEvidence, ConnectorError> {
        let extra = [
            snapshot.source_repository.as_bytes(),
            snapshot.commit_sha.as_bytes(),
            snapshot.image_repository.as_bytes(),
            snapshot.desired_image_digest.as_bytes().as_slice(),
        ];
        let payload = EvidencePayload::Target {
            cluster_identity: snapshot.cluster_identity,
            namespace: snapshot.namespace,
            deployment: snapshot.deployment,
            deployment_uid: snapshot.deployment_uid,
            resource_version: snapshot.resource_version,
            current_image: snapshot.current_image,
            projection_hash: snapshot.projection_hash,
        };
        prepare(
            &snapshot.meta,
            payload,
            &extra,
            &self.routes.target,
            &self.authority,
            self.validity,
        )
    }

    fn commit_checkpoints(
        &self,
        now: i64,
        prepared: &[PreparedEvidence; 4],
    ) -> Result<(), ConnectorError> {
        let mut state = self
            .checkpoints
            .lock()
            .map_err(|_| ConnectorError::CheckpointUnavailable)?;
        if state.last_clock.is_some_and(|last| now < last) {
            return Err(ConnectorError::ClockRollback);
        }
        for item in prepared {
            if let Some(checkpoint) = state.sources.get(&item.kind) {
                if item.sequence < checkpoint.sequence {
                    return Err(ConnectorError::SourceRollback { kind: item.kind });
                }
                if item.sequence == checkpoint.sequence
                    && item.source_commitment != checkpoint.commitment
                {
                    return Err(ConnectorError::SourceEquivocation { kind: item.kind });
                }
            }
            if let Some(prior) = state.evidence_ids.get(&item.evidence_id)
                && (prior.request_id != item.request_id
                    || prior.assertion_commitment != item.assertion_commitment)
            {
                return Err(ConnectorError::EvidenceIdReuse);
            }
        }
        state.last_clock = Some(now);
        for item in prepared {
            state.sources.insert(
                item.kind,
                SourceCheckpoint {
                    sequence: item.sequence,
                    commitment: item.source_commitment,
                },
            );
            state.evidence_ids.insert(
                item.evidence_id,
                EvidenceUse {
                    request_id: item.request_id,
                    assertion_commitment: item.assertion_commitment,
                },
            );
        }
        Ok(())
    }
}

fn connector_commitment(
    group: u8,
    attesters: &[ConnectorAttesterDescriptor],
    identities: &[ConnectorSourceIdentityDescriptor],
    authority: &[u8],
    validity: ValidityProfile,
) -> Digest32 {
    let mut hash = Sha256::new();
    commit_bytes(&mut hash, CONNECTOR_COMMITMENT_DOMAIN);
    hash.update([group]);
    hash.update(
        u64::try_from(attesters.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for (attester, identity) in attesters.iter().zip(identities) {
        hash.update([attester.kind.code()]);
        commit_bytes(&mut hash, attester.issuer.as_bytes());
        commit_bytes(&mut hash, attester.key_id.as_bytes());
        commit_bytes(&mut hash, &attester.public_key);
        commit_bytes(&mut hash, attester.source_uri_prefix.as_bytes());
        commit_bytes(&mut hash, identity.endpoint_uri_prefix.as_bytes());
        hash.update(identity.source_identity_hash.as_bytes());
        hash.update(identity.transport_identity_hash.as_bytes());
    }
    commit_bytes(&mut hash, authority);
    hash.update(validity.ttl_seconds().to_be_bytes());
    hash.update(validity.maximum_source_age_seconds().to_be_bytes());
    hash.update(validity.maximum_future_skew_seconds().to_be_bytes());
    hash.update([validity.required_completeness_profile().code()]);
    Digest32::from_bytes(hash.finalize().into())
}

fn commit_bytes(hash: &mut Sha256, value: &[u8]) {
    hash.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hash.update(value);
}

#[derive(Debug)]
struct PreparedEvidence {
    kind: EvidenceKind,
    sequence: u64,
    evidence_id: Uuid,
    request_id: Uuid,
    source_commitment: Digest32,
    assertion_commitment: Digest32,
    signed: SignedEvidence,
}

fn prepare(
    meta: &crate::SourceSnapshotMeta,
    payload: EvidencePayload,
    extra_route_bindings: &[&[u8]],
    route: &TrustedEvidenceRoute,
    authority: &AuthorityVector,
    validity: ValidityProfile,
) -> Result<PreparedEvidence, ConnectorError> {
    let kind = payload.kind();
    let valid_until = meta
        .observed_at
        .checked_add(validity.ttl_seconds())
        .ok_or(ConnectorError::TimeOverflow { kind })?;
    let assertion = EvidenceAssertion {
        schema_version: EVIDENCE_ASSERTION_SCHEMA_VERSION,
        request_id: meta.request_id,
        evidence_id: meta.evidence_id,
        issuer: route.issuer.clone(),
        key_id: route.signer.key_id().to_owned(),
        source_uri: meta.source_uri.clone(),
        observed_at: meta.observed_at,
        valid_until,
        authority: authority.clone(),
        payload,
    };
    let canonical = assertion
        .canonical_bytes()
        .map_err(|error| ConnectorError::Canonical(error.to_string()))?;
    let cose_sign1 = sign_cose(&canonical, kind.domain(), &route.signer)
        .map_err(|error| ConnectorError::Crypto(error.to_string()))?;
    let source_commitment = source_commitment(meta, &canonical, extra_route_bindings)?;
    Ok(PreparedEvidence {
        kind,
        sequence: meta.source_sequence,
        evidence_id: meta.evidence_id,
        request_id: meta.request_id,
        source_commitment,
        assertion_commitment: Digest32::sha256(&canonical),
        signed: SignedEvidence {
            assertion,
            cose_sign1,
        },
    })
}

fn validate_cross_source_route(
    review: &ReviewSourceSnapshot,
    build: &BuildSourceSnapshot,
    artifact: &ArtifactSourceSnapshot,
    target: &TargetSourceSnapshot,
) -> Result<(), ConnectorError> {
    if review.repository != build.repository
        || review.repository != artifact.source_repository
        || review.repository != target.source_repository
    {
        return Err(ConnectorError::RepositoryRouteMismatch);
    }
    if review.commit_sha != build.commit_sha
        || review.commit_sha != artifact.commit_sha
        || review.commit_sha != target.commit_sha
    {
        return Err(ConnectorError::CommitRouteMismatch);
    }
    if build.output_digest != artifact.digest || build.output_digest != target.desired_image_digest
    {
        return Err(ConnectorError::OutputRouteMismatch);
    }
    if build.run_id != artifact.source_run_id {
        return Err(ConnectorError::BuildRunRouteMismatch);
    }
    if artifact.image_repository != target.image_repository {
        return Err(ConnectorError::TargetRouteMismatch);
    }
    Ok(())
}

fn validate_meta(
    meta: &crate::SourceSnapshotMeta,
    request_id: Uuid,
    lookup_id: &str,
    kind: EvidenceKind,
    source_uri_prefix: &str,
    now: i64,
    validity: ValidityProfile,
) -> Result<(), ConnectorError> {
    if meta.request_id != request_id {
        return Err(ConnectorError::RequestBindingMismatch { kind });
    }
    validate_lookup_id(&meta.lookup_id, "source.lookup_id")?;
    if meta.lookup_id != lookup_id {
        return Err(ConnectorError::LookupBindingMismatch { kind });
    }
    if meta.source_sequence == 0 {
        return Err(ConnectorError::InvalidField("source_sequence"));
    }
    validate_source_uri(&meta.source_uri, source_uri_prefix, kind)?;
    if meta.observed_at < 0
        || meta.observed_at < now.saturating_sub(validity.maximum_source_age_seconds())
    {
        return Err(ConnectorError::StaleObservation { kind });
    }
    if meta.observed_at > now.saturating_add(validity.maximum_future_skew_seconds()) {
        return Err(ConnectorError::FutureObservation { kind });
    }
    let valid_until = meta
        .observed_at
        .checked_add(validity.ttl_seconds())
        .ok_or(ConnectorError::TimeOverflow { kind })?;
    if valid_until <= now {
        return Err(ConnectorError::StaleObservation { kind });
    }
    Ok(())
}

fn validate_uri_prefix(prefix: &str) -> Result<(), ConnectorError> {
    if prefix.len() > MAX_SOURCE_URI_BYTES
        || !prefix.starts_with("https://")
        || !prefix.ends_with('/')
        || prefix.chars().any(char::is_whitespace)
        || prefix.chars().any(char::is_control)
        || prefix.contains('@')
        || prefix.contains('#')
        || prefix.contains('?')
    {
        return Err(ConnectorError::InvalidConfiguration("source URI prefix"));
    }
    let authority_and_path = &prefix["https://".len()..];
    let host = authority_and_path.split('/').next().unwrap_or_default();
    if host.is_empty() || host.starts_with('.') || host.ends_with('.') {
        return Err(ConnectorError::InvalidConfiguration("source URI prefix"));
    }
    Ok(())
}

fn validate_source_uri(uri: &str, prefix: &str, kind: EvidenceKind) -> Result<(), ConnectorError> {
    let suffix = uri
        .strip_prefix(prefix)
        .ok_or(ConnectorError::SourceUriMismatch { kind })?;
    if uri.len() > MAX_SOURCE_URI_BYTES
        || suffix.is_empty()
        || uri.chars().any(char::is_whitespace)
        || uri.chars().any(char::is_control)
        || uri.contains('#')
        || suffix
            .split('/')
            .any(|segment| segment == "." || segment == "..")
    {
        return Err(ConnectorError::SourceUriMismatch { kind });
    }
    Ok(())
}

fn source_commitment(
    meta: &crate::SourceSnapshotMeta,
    canonical_assertion: &[u8],
    extra_route_bindings: &[&[u8]],
) -> Result<Digest32, ConnectorError> {
    let mut bytes = Vec::new();
    append_component(&mut bytes, b"accordlock:v2:connector-source-checkpoint")?;
    append_component(&mut bytes, meta.request_id.as_bytes())?;
    append_component(&mut bytes, meta.lookup_id.as_bytes())?;
    append_component(&mut bytes, &meta.source_sequence.to_be_bytes())?;
    append_component(&mut bytes, canonical_assertion)?;
    for binding in extra_route_bindings {
        append_component(&mut bytes, binding)?;
    }
    Ok(Digest32::sha256(&bytes))
}

fn append_component(target: &mut Vec<u8>, component: &[u8]) -> Result<(), ConnectorError> {
    let length = u64::try_from(component.len())
        .map_err(|_| ConnectorError::InvalidField("checkpoint component"))?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(component);
    Ok(())
}

fn descriptor(route: &TrustedEvidenceRoute) -> ConnectorAttesterDescriptor {
    ConnectorAttesterDescriptor {
        kind: route.kind,
        issuer: route.issuer.clone(),
        key_id: route.signer.key_id().to_owned(),
        public_key: route.signer.public_key_bytes(),
        source_uri_prefix: route.source_uri_prefix.clone(),
    }
}

fn source_error(kind: EvidenceKind, code: &str) -> ConnectorError {
    ConnectorError::SourceRead {
        kind,
        code: code.to_owned(),
    }
}
