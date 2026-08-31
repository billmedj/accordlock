use std::{fmt, sync::Arc};

use accordlock_connectors::{
    BuildLookupId, BuildSource, BuildSourceSnapshot, ConnectorSourceIdentityDescriptor,
    ReviewLookupId, ReviewSource, ReviewSourceSnapshot, SourceReadError, SourceSnapshotMeta,
};
use accordlock_protocol::{CompletenessProfile, Digest32, EvidenceKind};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    AdapterConfigError, AuthenticatedJsonResponse, AuthenticatedTransportIdentity, HttpsEndpoint,
    ProviderResponseError, ReadFailures, ReadMethod, RedirectPolicy, TransportFailure,
    parse_strict_json, provider_identity_commitment, split_lookup, validate_commit_sha,
    validate_maximum_response_bytes, validate_positive_meta, validate_route_segment,
};

const REVIEW_LOOKUP_PREFIX: [&str; 3] = ["al1", "github", "review"];
const BUILD_LOOKUP_PREFIX: [&str; 3] = ["al1", "github", "actions"];
const GITHUB_SOURCE_IDENTITY_DOMAIN: &[u8] = b"accordlock:v1:github-source-adapter";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GitHubReadOperation {
    PullReviewDecision,
    ActionsBuildAttestation,
}

/// Credential-free, fixed-route request handed to the runner's GitHub
/// transport. The transport may fan out to GitHub APIs, but must return one
/// authenticated strict observation and must not follow redirects.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubReadRequest {
    pub method: ReadMethod,
    pub authority: String,
    pub path: String,
    pub redirect_policy: RedirectPolicy,
    pub maximum_response_bytes: usize,
    pub operation: GitHubReadOperation,
}

pub trait GitHubAuthenticatedTransport: Send + Sync {
    /// Returns the fixed public identity committed at runner bootstrap.
    ///
    /// # Errors
    ///
    /// Returns an error if the public identity is unavailable or malformed.
    fn public_identity(&self) -> Result<AuthenticatedTransportIdentity, AdapterConfigError>;

    /// Performs one authenticated, integrity-protected GitHub read.
    /// Credentials, headers, TLS state and redirect handling remain private to
    /// this implementation.
    ///
    /// # Errors
    ///
    /// Returns a bounded categorical failure; upstream bodies must never be
    /// copied into it.
    fn read(
        &self,
        request: &GitHubReadRequest,
    ) -> Result<AuthenticatedJsonResponse, TransportFailure>;
}

#[derive(Clone, Debug)]
pub struct GitHubAdapterConfig {
    endpoint: HttpsEndpoint,
    owner: String,
    repository_name: String,
    workflow_ref: String,
    maximum_response_bytes: usize,
}

impl GitHubAdapterConfig {
    /// Creates the exact GitHub repository/workflow route accepted by an
    /// adapter.
    ///
    /// # Errors
    ///
    /// Rejects ambiguous route segments, workflow refs and response bounds.
    pub fn new(
        endpoint: HttpsEndpoint,
        owner: impl Into<String>,
        repository_name: impl Into<String>,
        workflow_ref: impl Into<String>,
        maximum_response_bytes: usize,
    ) -> Result<Self, AdapterConfigError> {
        let owner = owner.into();
        let repository_name = repository_name.into();
        let workflow_ref = workflow_ref.into();
        validate_route_segment(&owner, "GitHub owner")?;
        validate_route_segment(&repository_name, "GitHub repository")?;
        validate_workflow_ref(&workflow_ref)?;
        validate_maximum_response_bytes(maximum_response_bytes)?;
        Ok(Self {
            endpoint,
            owner,
            repository_name,
            workflow_ref,
            maximum_response_bytes,
        })
    }

    #[must_use]
    pub fn repository(&self) -> String {
        format!("{}/{}", self.owner, self.repository_name)
    }

    /// Returns a canonical commitment to this exact non-secret source route.
    #[must_use]
    pub fn identity_hash(&self) -> Digest32 {
        let maximum_response_bytes = u64::try_from(self.maximum_response_bytes)
            .unwrap_or(u64::MAX)
            .to_be_bytes();
        provider_identity_commitment(
            GITHUB_SOURCE_IDENTITY_DOMAIN,
            &[
                self.endpoint.authority().as_bytes(),
                self.endpoint.base_path().as_bytes(),
                self.owner.as_bytes(),
                self.repository_name.as_bytes(),
                self.workflow_ref.as_bytes(),
                &maximum_response_bytes,
            ],
        )
    }

    /// Returns the exact HTTPS prefix from which observations are accepted.
    #[must_use]
    pub fn endpoint_uri_prefix(&self) -> String {
        self.endpoint.source_uri_prefix()
    }
}

pub struct GitHubSourceAdapter {
    config: GitHubAdapterConfig,
    transport: Arc<dyn GitHubAuthenticatedTransport>,
    review_identity: ConnectorSourceIdentityDescriptor,
    build_identity: ConnectorSourceIdentityDescriptor,
    failures: ReadFailures,
}

impl GitHubSourceAdapter {
    /// Binds the fixed provider route to one runner-owned authenticated
    /// transport.
    ///
    /// # Errors
    ///
    /// Returns a configuration error if safe connector failure codes cannot be
    /// initialized.
    pub fn new(
        config: GitHubAdapterConfig,
        transport: Arc<dyn GitHubAuthenticatedTransport>,
    ) -> Result<Self, AdapterConfigError> {
        let endpoint = config.endpoint_uri_prefix();
        let source_identity_hash = config.identity_hash();
        let transport_identity_hash = transport.public_identity()?.digest();
        let review_identity = ConnectorSourceIdentityDescriptor::new(
            EvidenceKind::Review,
            endpoint.clone(),
            source_identity_hash,
            transport_identity_hash,
        )
        .map_err(|_| AdapterConfigError::Invalid("GitHub source identity"))?;
        let build_identity = ConnectorSourceIdentityDescriptor::new(
            EvidenceKind::Build,
            endpoint,
            source_identity_hash,
            transport_identity_hash,
        )
        .map_err(|_| AdapterConfigError::Invalid("GitHub source identity"))?;
        Ok(Self {
            config,
            transport,
            review_identity,
            build_identity,
            failures: ReadFailures::new()?,
        })
    }

    fn review_request(&self, pull_number: u64) -> Result<GitHubReadRequest, AdapterConfigError> {
        let suffix = format!(
            "/repos/{}/{}/pulls/{pull_number}/accordlock-review-decision",
            self.config.owner, self.config.repository_name
        );
        Ok(GitHubReadRequest {
            method: ReadMethod::Get,
            authority: self.config.endpoint.authority().to_owned(),
            path: self.config.endpoint.path(&suffix)?,
            redirect_policy: RedirectPolicy::Deny,
            maximum_response_bytes: self.config.maximum_response_bytes,
            operation: GitHubReadOperation::PullReviewDecision,
        })
    }

    fn build_request(&self, run_id: u64) -> Result<GitHubReadRequest, AdapterConfigError> {
        let suffix = format!(
            "/repos/{}/{}/actions/runs/{run_id}/accordlock-build-attestation",
            self.config.owner, self.config.repository_name
        );
        Ok(GitHubReadRequest {
            method: ReadMethod::Get,
            authority: self.config.endpoint.authority().to_owned(),
            path: self.config.endpoint.path(&suffix)?,
            redirect_policy: RedirectPolicy::Deny,
            maximum_response_bytes: self.config.maximum_response_bytes,
            operation: GitHubReadOperation::ActionsBuildAttestation,
        })
    }
}

impl fmt::Debug for GitHubSourceAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitHubSourceAdapter")
            .field("config", &self.config)
            .field("transport", &"<runner-owned authenticated transport>")
            .finish_non_exhaustive()
    }
}

impl ReviewSource for GitHubSourceAdapter {
    fn identity_descriptor(
        &self,
    ) -> Result<ConnectorSourceIdentityDescriptor, accordlock_connectors::ConnectorError> {
        Ok(self.review_identity.clone())
    }

    fn fetch(&self, lookup: &ReviewLookupId) -> Result<ReviewSourceSnapshot, SourceReadError> {
        let (request_id, tail) = parse_review_lookup(lookup.as_str())
            .map_err(|_| self.failures.invalid_lookup.clone())?;
        let pull_number =
            parse_u64_selector(tail[1]).map_err(|_| self.failures.invalid_lookup.clone())?;
        let request = self
            .review_request(pull_number)
            .map_err(|_| self.failures.invalid_lookup.clone())?;
        let response = self
            .transport
            .read(&request)
            .map_err(|_| self.failures.transport.clone())?;
        let body = response
            .body_for(self.config.maximum_response_bytes)
            .map_err(|_| self.failures.invalid_response.clone())?;
        let wire: GitHubReviewObservation =
            parse_strict_json(&body).map_err(|_| self.failures.invalid_response.clone())?;
        validate_review_observation(&wire, request_id, pull_number, &self.config.repository())
            .map_err(|_| self.failures.invalid_response.clone())?;
        Ok(ReviewSourceSnapshot {
            meta: SourceSnapshotMeta {
                request_id,
                lookup_id: lookup.as_str().to_owned(),
                evidence_id: wire.evidence_id,
                source_uri: self.config.endpoint.source_uri(&request.path),
                observed_at: wire.observed_at,
                source_sequence: wire.source_sequence,
            },
            repository: wire.repository,
            commit_sha: wire.commit_sha,
            approved: wire.approved,
            review_state_id: format!(
                "github:pull:{pull_number}:sequence:{}:evidence:{}",
                wire.source_sequence, wire.evidence_id
            ),
        })
    }
}

impl BuildSource for GitHubSourceAdapter {
    fn identity_descriptor(
        &self,
    ) -> Result<ConnectorSourceIdentityDescriptor, accordlock_connectors::ConnectorError> {
        Ok(self.build_identity.clone())
    }

    fn fetch(&self, lookup: &BuildLookupId) -> Result<BuildSourceSnapshot, SourceReadError> {
        let (request_id, tail) = parse_build_lookup(lookup.as_str())
            .map_err(|_| self.failures.invalid_lookup.clone())?;
        let run_id =
            parse_u64_selector(tail[1]).map_err(|_| self.failures.invalid_lookup.clone())?;
        let request = self
            .build_request(run_id)
            .map_err(|_| self.failures.invalid_lookup.clone())?;
        let response = self
            .transport
            .read(&request)
            .map_err(|_| self.failures.transport.clone())?;
        let body = response
            .body_for(self.config.maximum_response_bytes)
            .map_err(|_| self.failures.invalid_response.clone())?;
        let wire: GitHubBuildObservation =
            parse_strict_json(&body).map_err(|_| self.failures.invalid_response.clone())?;
        validate_build_observation(
            &wire,
            request_id,
            run_id,
            &self.config.repository(),
            &self.config.workflow_ref,
        )
        .map_err(|_| self.failures.invalid_response.clone())?;
        Ok(BuildSourceSnapshot {
            meta: SourceSnapshotMeta {
                request_id,
                lookup_id: lookup.as_str().to_owned(),
                evidence_id: wire.evidence_id,
                source_uri: self.config.endpoint.source_uri(&request.path),
                observed_at: wire.observed_at,
                source_sequence: wire.source_sequence,
            },
            repository: wire.repository,
            commit_sha: wire.commit_sha,
            workflow_ref: wire.workflow_ref,
            run_id: run_id.to_string(),
            succeeded: wire.succeeded,
            input_manifest_root: wire.input_manifest_root,
            completeness_profile: wire.completeness_profile,
            output_digest: wire.output_digest,
        })
    }
}

/// Creates the only canonical review lookup accepted by this adapter.
///
/// The UUID is embedded because [`ReviewSource::fetch`] receives no separate
/// request identifier. The returned snapshot recovers and repeats this UUID,
/// allowing `accordlock-connectors` to enforce the request binding.
///
/// # Errors
///
/// Rejects a nil UUID or zero pull number.
pub fn github_review_lookup(
    request_id: Uuid,
    pull_number: u64,
) -> Result<ReviewLookupId, AdapterConfigError> {
    if request_id.is_nil() || pull_number == 0 {
        return Err(AdapterConfigError::Invalid("GitHub review lookup"));
    }
    ReviewLookupId::parse(format!("al1/github/review/{request_id}/pull/{pull_number}"))
        .map_err(|_| AdapterConfigError::Invalid("GitHub review lookup"))
}

/// Creates the only canonical Actions build lookup accepted by this adapter.
///
/// # Errors
///
/// Rejects a nil UUID or zero run identifier.
pub fn github_actions_lookup(
    request_id: Uuid,
    run_id: u64,
) -> Result<BuildLookupId, AdapterConfigError> {
    if request_id.is_nil() || run_id == 0 {
        return Err(AdapterConfigError::Invalid("GitHub Actions lookup"));
    }
    BuildLookupId::parse(format!("al1/github/actions/{request_id}/run/{run_id}"))
        .map_err(|_| AdapterConfigError::Invalid("GitHub Actions lookup"))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GitHubReviewObservation {
    schema_version: u16,
    request_id: Uuid,
    evidence_id: Uuid,
    observed_at: i64,
    source_sequence: u64,
    repository: String,
    pull_number: u64,
    commit_sha: String,
    approved: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GitHubBuildObservation {
    schema_version: u16,
    request_id: Uuid,
    evidence_id: Uuid,
    observed_at: i64,
    source_sequence: u64,
    repository: String,
    workflow_ref: String,
    run_id: u64,
    commit_sha: String,
    succeeded: bool,
    input_manifest_root: Digest32,
    completeness_profile: CompletenessProfile,
    output_digest: Digest32,
}

fn parse_review_lookup(value: &str) -> Result<(Uuid, Vec<&str>), ProviderResponseError> {
    let (request_id, tail) = split_lookup(value, &REVIEW_LOOKUP_PREFIX, 2)?;
    if tail[0] != "pull" {
        return Err(ProviderResponseError::Binding);
    }
    Ok((request_id, tail))
}

fn parse_build_lookup(value: &str) -> Result<(Uuid, Vec<&str>), ProviderResponseError> {
    let (request_id, tail) = split_lookup(value, &BUILD_LOOKUP_PREFIX, 2)?;
    if tail[0] != "run" {
        return Err(ProviderResponseError::Binding);
    }
    Ok((request_id, tail))
}

fn parse_u64_selector(value: &str) -> Result<u64, ProviderResponseError> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| ProviderResponseError::Binding)?;
    if parsed == 0 || parsed.to_string() != value {
        return Err(ProviderResponseError::Binding);
    }
    Ok(parsed)
}

fn validate_review_observation(
    wire: &GitHubReviewObservation,
    request_id: Uuid,
    pull_number: u64,
    repository: &str,
) -> Result<(), ProviderResponseError> {
    validate_positive_meta(
        wire.request_id,
        wire.evidence_id,
        wire.observed_at,
        wire.source_sequence,
    )?;
    validate_commit_sha(&wire.commit_sha)?;
    if wire.schema_version != crate::PROVIDER_ADAPTER_SCHEMA_VERSION
        || wire.request_id != request_id
        || wire.pull_number != pull_number
        || wire.repository != repository
    {
        return Err(ProviderResponseError::Binding);
    }
    Ok(())
}

fn validate_build_observation(
    wire: &GitHubBuildObservation,
    request_id: Uuid,
    run_id: u64,
    repository: &str,
    workflow_ref: &str,
) -> Result<(), ProviderResponseError> {
    validate_positive_meta(
        wire.request_id,
        wire.evidence_id,
        wire.observed_at,
        wire.source_sequence,
    )?;
    validate_commit_sha(&wire.commit_sha)?;
    if wire.schema_version != crate::PROVIDER_ADAPTER_SCHEMA_VERSION
        || wire.request_id != request_id
        || wire.run_id != run_id
        || wire.repository != repository
        || wire.workflow_ref != workflow_ref
    {
        return Err(ProviderResponseError::Binding);
    }
    Ok(())
}

fn validate_workflow_ref(value: &str) -> Result<(), AdapterConfigError> {
    if value.is_empty()
        || value.len() > 512
        || value.trim() != value
        || !value.starts_with(".github/workflows/")
        || !value.contains("@refs/")
        || value.contains("..")
        || value.contains(['?', '#'])
        || value.chars().any(char::is_control)
    {
        return Err(AdapterConfigError::Invalid("GitHub workflow ref"));
    }
    Ok(())
}
