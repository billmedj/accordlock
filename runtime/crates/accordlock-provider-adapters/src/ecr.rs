use std::{fmt, str::FromStr, sync::Arc};

use accordlock_connectors::{
    ArtifactLookupId, ArtifactSource, ArtifactSourceSnapshot, ConnectorSourceIdentityDescriptor,
    SourceReadError, SourceSnapshotMeta,
};
use accordlock_protocol::{Digest32, EvidenceKind};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    AdapterConfigError, AuthenticatedJsonResponse, AuthenticatedTransportIdentity, HttpsEndpoint,
    ProviderResponseError, ReadFailures, ReadMethod, RedirectPolicy, TransportFailure,
    parse_strict_json, provider_identity_commitment, split_lookup, validate_commit_sha,
    validate_maximum_response_bytes, validate_positive_meta,
};

const ECR_LOOKUP_PREFIX: [&str; 3] = ["al1", "aws", "ecr"];
const ECR_BATCH_GET_TARGET: &str = "AmazonEC2ContainerRegistry_V20150921.BatchGetImage";
const ECR_SOURCE_IDENTITY_DOMAIN: &[u8] = b"accordlock:v1:ecr-source-adapter";

/// Credential-free AWS ECR `BatchGetImage` read specification. The injected
/// runner transport constructs the canonical AWS JSON body and `SigV4` headers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EcrReadRequest {
    pub method: ReadMethod,
    pub authority: String,
    pub path: String,
    pub redirect_policy: RedirectPolicy,
    pub maximum_response_bytes: usize,
    pub sigv4_service: String,
    pub region: String,
    pub x_amz_target: String,
    pub registry_id: String,
    pub repository_name: String,
    pub image_digest: Digest32,
}

pub trait EcrAuthenticatedTransport: Send + Sync {
    /// Returns the fixed public AWS identity committed at runner bootstrap.
    ///
    /// # Errors
    ///
    /// Returns an error if the public identity is unavailable or malformed.
    fn public_identity(&self) -> Result<AuthenticatedTransportIdentity, AdapterConfigError>;

    /// Executes one SigV4-authenticated ECR read. AWS credentials and signing
    /// intermediates must remain inside the transport.
    ///
    /// # Errors
    ///
    /// Returns only a categorical, non-secret-bearing transport failure.
    fn read(&self, request: &EcrReadRequest)
    -> Result<AuthenticatedJsonResponse, TransportFailure>;
}

#[derive(Clone, Debug)]
pub struct EcrAdapterConfig {
    endpoint: HttpsEndpoint,
    registry_id: String,
    region: String,
    repository_name: String,
    source_repository: String,
    maximum_response_bytes: usize,
}

impl EcrAdapterConfig {
    /// Creates one exact ECR repository route and its expected source-code
    /// repository binding.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical AWS account, region, repository and response
    /// bounds.
    pub fn new(
        endpoint: HttpsEndpoint,
        registry_id: impl Into<String>,
        region: impl Into<String>,
        repository_name: impl Into<String>,
        source_repository: impl Into<String>,
        maximum_response_bytes: usize,
    ) -> Result<Self, AdapterConfigError> {
        let registry_id = registry_id.into();
        let region = region.into();
        let repository_name = repository_name.into();
        let source_repository = source_repository.into();
        validate_registry_id(&registry_id)?;
        validate_region(&region)?;
        validate_ecr_repository(&repository_name)?;
        validate_source_repository(&source_repository)?;
        validate_maximum_response_bytes(maximum_response_bytes)?;
        let expected_authority = format!("api.ecr.{region}.amazonaws.com");
        if endpoint.authority() != expected_authority || endpoint.base_path() != "/" {
            return Err(AdapterConfigError::Invalid("ECR endpoint route"));
        }
        Ok(Self {
            endpoint,
            registry_id,
            region,
            repository_name,
            source_repository,
            maximum_response_bytes,
        })
    }

    #[must_use]
    pub fn image_repository(&self) -> String {
        format!(
            "{}.dkr.ecr.{}.amazonaws.com/{}",
            self.registry_id, self.region, self.repository_name
        )
    }

    /// Returns a canonical commitment to this exact non-secret ECR route.
    #[must_use]
    pub fn identity_hash(&self) -> Digest32 {
        let maximum_response_bytes = u64::try_from(self.maximum_response_bytes)
            .unwrap_or(u64::MAX)
            .to_be_bytes();
        provider_identity_commitment(
            ECR_SOURCE_IDENTITY_DOMAIN,
            &[
                self.endpoint.authority().as_bytes(),
                self.endpoint.base_path().as_bytes(),
                self.registry_id.as_bytes(),
                self.region.as_bytes(),
                self.repository_name.as_bytes(),
                self.source_repository.as_bytes(),
                &maximum_response_bytes,
            ],
        )
    }

    /// Returns the exact HTTPS prefix from which observations are accepted.
    #[must_use]
    pub fn endpoint_uri_prefix(&self) -> String {
        self.endpoint.source_uri_prefix()
    }

    fn evidence_source_uri(&self, digest: Digest32) -> String {
        format!(
            "https://{}/accordlock/ecr/registries/{}/repositories/{}/digests/sha256/{}",
            self.endpoint.authority(),
            self.registry_id,
            self.repository_name,
            digest.to_hex()
        )
    }
}

pub struct EcrSourceAdapter {
    config: EcrAdapterConfig,
    transport: Arc<dyn EcrAuthenticatedTransport>,
    identity: ConnectorSourceIdentityDescriptor,
    failures: ReadFailures,
}

impl EcrSourceAdapter {
    /// Binds an exact ECR repository to a runner-owned `SigV4` transport.
    ///
    /// # Errors
    ///
    /// Returns a configuration error if safe failure codes cannot be created.
    pub fn new(
        config: EcrAdapterConfig,
        transport: Arc<dyn EcrAuthenticatedTransport>,
    ) -> Result<Self, AdapterConfigError> {
        let identity = ConnectorSourceIdentityDescriptor::new(
            EvidenceKind::Artifact,
            config.endpoint_uri_prefix(),
            config.identity_hash(),
            transport.public_identity()?.digest(),
        )
        .map_err(|_| AdapterConfigError::Invalid("ECR source identity"))?;
        Ok(Self {
            config,
            transport,
            identity,
            failures: ReadFailures::new()?,
        })
    }

    fn request(&self, digest: Digest32) -> Result<EcrReadRequest, AdapterConfigError> {
        Ok(EcrReadRequest {
            method: ReadMethod::Post,
            authority: self.config.endpoint.authority().to_owned(),
            path: self.config.endpoint.path("/")?,
            redirect_policy: RedirectPolicy::Deny,
            maximum_response_bytes: self.config.maximum_response_bytes,
            sigv4_service: "ecr".to_owned(),
            region: self.config.region.clone(),
            x_amz_target: ECR_BATCH_GET_TARGET.to_owned(),
            registry_id: self.config.registry_id.clone(),
            repository_name: self.config.repository_name.clone(),
            image_digest: digest,
        })
    }
}

impl fmt::Debug for EcrSourceAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EcrSourceAdapter")
            .field("config", &self.config)
            .field("transport", &"<runner-owned SigV4 transport>")
            .finish_non_exhaustive()
    }
}

impl ArtifactSource for EcrSourceAdapter {
    fn identity_descriptor(
        &self,
    ) -> Result<ConnectorSourceIdentityDescriptor, accordlock_connectors::ConnectorError> {
        Ok(self.identity.clone())
    }

    fn fetch(&self, lookup: &ArtifactLookupId) -> Result<ArtifactSourceSnapshot, SourceReadError> {
        let (request_id, digest) =
            parse_ecr_lookup(lookup.as_str()).map_err(|_| self.failures.invalid_lookup.clone())?;
        let request = self
            .request(digest)
            .map_err(|_| self.failures.invalid_lookup.clone())?;
        let response = self
            .transport
            .read(&request)
            .map_err(|_| self.failures.transport.clone())?;
        let body = response
            .body_for(self.config.maximum_response_bytes)
            .map_err(|_| self.failures.invalid_response.clone())?;
        let wire: EcrArtifactObservation =
            parse_strict_json(&body).map_err(|_| self.failures.invalid_response.clone())?;
        validate_observation(&wire, request_id, digest, &self.config)
            .map_err(|_| self.failures.invalid_response.clone())?;
        Ok(ArtifactSourceSnapshot {
            meta: SourceSnapshotMeta {
                request_id,
                lookup_id: lookup.as_str().to_owned(),
                evidence_id: wire.evidence_id,
                // The authenticated AWS request remains the real SigV4 POST
                // to `/`. Evidence gets a distinct immutable logical URI
                // below the trusted route, bound to repository and digest.
                source_uri: self.config.evidence_source_uri(wire.image_digest),
                observed_at: wire.observed_at,
                source_sequence: wire.source_sequence,
            },
            source_repository: wire.source_repository,
            commit_sha: wire.commit_sha,
            image_repository: self.config.image_repository(),
            digest: wire.image_digest,
            source_run_id: wire.source_run_id.to_string(),
            signature_valid: wire.signature_valid,
            quarantined: wire.quarantined,
        })
    }
}

/// Creates an immutable digest-only ECR lookup. Tags are intentionally absent
/// from this API and cannot be parsed by the adapter.
///
/// # Errors
///
/// Rejects nil request identifiers and noncanonical digests.
pub fn ecr_artifact_lookup(
    request_id: Uuid,
    digest: Digest32,
) -> Result<ArtifactLookupId, AdapterConfigError> {
    if request_id.is_nil() {
        return Err(AdapterConfigError::Invalid("ECR artifact lookup"));
    }
    ArtifactLookupId::parse(format!("al1/aws/ecr/{request_id}/digest/{digest}"))
        .map_err(|_| AdapterConfigError::Invalid("ECR artifact lookup"))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EcrArtifactObservation {
    schema_version: u16,
    request_id: Uuid,
    evidence_id: Uuid,
    observed_at: i64,
    source_sequence: u64,
    registry_id: String,
    region: String,
    repository_name: String,
    image_digest: Digest32,
    source_repository: String,
    commit_sha: String,
    source_run_id: u64,
    signature_valid: bool,
    quarantined: bool,
}

fn parse_ecr_lookup(value: &str) -> Result<(Uuid, Digest32), ProviderResponseError> {
    let (request_id, tail) = split_lookup(value, &ECR_LOOKUP_PREFIX, 2)?;
    if tail[0] != "digest" {
        return Err(ProviderResponseError::Binding);
    }
    let digest = Digest32::from_str(tail[1]).map_err(|_| ProviderResponseError::Binding)?;
    if digest.to_string() != tail[1] {
        return Err(ProviderResponseError::Binding);
    }
    Ok((request_id, digest))
}

fn validate_observation(
    wire: &EcrArtifactObservation,
    request_id: Uuid,
    digest: Digest32,
    config: &EcrAdapterConfig,
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
        || wire.registry_id != config.registry_id
        || wire.region != config.region
        || wire.repository_name != config.repository_name
        || wire.source_repository != config.source_repository
        || wire.image_digest != digest
        || wire.source_run_id == 0
    {
        return Err(ProviderResponseError::Binding);
    }
    Ok(())
}

fn validate_registry_id(value: &str) -> Result<(), AdapterConfigError> {
    if value.len() != 12 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AdapterConfigError::Invalid("AWS registry identifier"));
    }
    Ok(())
}

fn validate_region(value: &str) -> Result<(), AdapterConfigError> {
    if value.is_empty()
        || value.len() > 32
        || value != value.to_ascii_lowercase()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || !value.contains('-')
    {
        return Err(AdapterConfigError::Invalid("AWS region"));
    }
    Ok(())
}

fn validate_ecr_repository(value: &str) -> Result<(), AdapterConfigError> {
    if value.is_empty()
        || value.len() > 256
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains("//")
        || value.split('/').any(|segment| {
            segment.is_empty()
                || segment == "."
                || segment == ".."
                || !segment.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-')
                })
        })
    {
        return Err(AdapterConfigError::Invalid("ECR repository"));
    }
    Ok(())
}

fn validate_source_repository(value: &str) -> Result<(), AdapterConfigError> {
    let parts = value.split('/').collect::<Vec<_>>();
    if parts.len() != 2
        || parts
            .iter()
            .any(|part| crate::validate_route_segment(part, "source repository").is_err())
    {
        return Err(AdapterConfigError::Invalid("source repository"));
    }
    Ok(())
}
