use std::{fmt, sync::Arc};

use accordlock_connectors::{
    ConnectorSourceIdentityDescriptor, SourceReadError, SourceSnapshotMeta, TargetLookupId,
    TargetSource, TargetSourceSnapshot,
};
use accordlock_protocol::{Digest32, EvidenceKind};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    AdapterConfigError, AuthenticatedJsonResponse, AuthenticatedTransportIdentity, HttpsEndpoint,
    ProviderResponseError, ReadFailures, ReadMethod, RedirectPolicy, TransportFailure,
    parse_strict_json, provider_identity_commitment, split_lookup, validate_commit_sha,
    validate_maximum_response_bytes, validate_positive_meta, validate_route_segment,
};

const TARGET_LOOKUP_PREFIX: [&str; 3] = ["al1", "kubernetes", "target"];
const KUBERNETES_SOURCE_IDENTITY_DOMAIN: &[u8] = b"accordlock:v1:kubernetes-source-adapter";

/// Credential-free Kubernetes API read. Bearer credentials, client
/// certificates, CA roots and TLS sessions live only in the runner transport.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesReadRequest {
    pub method: ReadMethod,
    pub authority: String,
    pub path: String,
    pub redirect_policy: RedirectPolicy,
    pub maximum_response_bytes: usize,
    pub api_group: String,
    pub api_version: String,
    pub resource: String,
    pub namespace: String,
    pub name: String,
}

pub trait KubernetesAuthenticatedTransport: Send + Sync {
    /// Returns the fixed public cluster transport identity at bootstrap.
    ///
    /// # Errors
    ///
    /// Returns an error if the public identity is unavailable or malformed.
    fn public_identity(&self) -> Result<AuthenticatedTransportIdentity, AdapterConfigError>;

    /// Executes one authenticated Kubernetes GET without following redirects.
    ///
    /// # Errors
    ///
    /// Returns only a categorical failure. API response bodies, tokens and
    /// certificate details must never enter the error.
    fn read(
        &self,
        request: &KubernetesReadRequest,
    ) -> Result<AuthenticatedJsonResponse, TransportFailure>;
}

#[derive(Clone, Debug)]
pub struct KubernetesAdapterConfig {
    endpoint: HttpsEndpoint,
    cluster_identity: String,
    namespace: String,
    deployment: String,
    container: String,
    source_repository: String,
    image_repository: String,
    maximum_response_bytes: usize,
}

impl KubernetesAdapterConfig {
    /// Creates one exact Deployment/container route. This works for EKS and
    /// any conformant Kubernetes API server.
    ///
    /// # Errors
    ///
    /// Rejects ambiguous object routes and unbounded identity fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint: HttpsEndpoint,
        cluster_identity: impl Into<String>,
        namespace: impl Into<String>,
        deployment: impl Into<String>,
        container: impl Into<String>,
        source_repository: impl Into<String>,
        image_repository: impl Into<String>,
        maximum_response_bytes: usize,
    ) -> Result<Self, AdapterConfigError> {
        let cluster_identity = cluster_identity.into();
        let namespace = namespace.into();
        let deployment = deployment.into();
        let container = container.into();
        let source_repository = source_repository.into();
        let image_repository = image_repository.into();
        validate_cluster_identity(&cluster_identity)?;
        validate_dns_label(&namespace, "Kubernetes namespace")?;
        validate_dns_label(&deployment, "Kubernetes deployment")?;
        validate_dns_label(&container, "Kubernetes container")?;
        validate_source_repository(&source_repository)?;
        validate_image_repository(&image_repository)?;
        validate_maximum_response_bytes(maximum_response_bytes)?;
        Ok(Self {
            endpoint,
            cluster_identity,
            namespace,
            deployment,
            container,
            source_repository,
            image_repository,
            maximum_response_bytes,
        })
    }

    /// Returns a canonical commitment to this exact non-secret target route.
    #[must_use]
    pub fn identity_hash(&self) -> Digest32 {
        let maximum_response_bytes = u64::try_from(self.maximum_response_bytes)
            .unwrap_or(u64::MAX)
            .to_be_bytes();
        provider_identity_commitment(
            KUBERNETES_SOURCE_IDENTITY_DOMAIN,
            &[
                self.endpoint.authority().as_bytes(),
                self.endpoint.base_path().as_bytes(),
                self.cluster_identity.as_bytes(),
                self.namespace.as_bytes(),
                self.deployment.as_bytes(),
                self.container.as_bytes(),
                self.source_repository.as_bytes(),
                self.image_repository.as_bytes(),
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

pub struct KubernetesSourceAdapter {
    config: KubernetesAdapterConfig,
    transport: Arc<dyn KubernetesAuthenticatedTransport>,
    identity: ConnectorSourceIdentityDescriptor,
    failures: ReadFailures,
}

impl KubernetesSourceAdapter {
    /// Binds one fixed Kubernetes target route to the runner transport.
    ///
    /// # Errors
    ///
    /// Returns a configuration error if safe failure codes cannot be created.
    pub fn new(
        config: KubernetesAdapterConfig,
        transport: Arc<dyn KubernetesAuthenticatedTransport>,
    ) -> Result<Self, AdapterConfigError> {
        let identity = ConnectorSourceIdentityDescriptor::new(
            EvidenceKind::Target,
            config.endpoint_uri_prefix(),
            config.identity_hash(),
            transport.public_identity()?.digest(),
        )
        .map_err(|_| AdapterConfigError::Invalid("Kubernetes source identity"))?;
        Ok(Self {
            config,
            transport,
            identity,
            failures: ReadFailures::new()?,
        })
    }

    fn request(&self) -> Result<KubernetesReadRequest, AdapterConfigError> {
        let suffix = format!(
            "/apis/apps/v1/namespaces/{}/deployments/{}",
            self.config.namespace, self.config.deployment
        );
        Ok(KubernetesReadRequest {
            method: ReadMethod::Get,
            authority: self.config.endpoint.authority().to_owned(),
            path: self.config.endpoint.path(&suffix)?,
            redirect_policy: RedirectPolicy::Deny,
            maximum_response_bytes: self.config.maximum_response_bytes,
            api_group: "apps".to_owned(),
            api_version: "v1".to_owned(),
            resource: "deployments".to_owned(),
            namespace: self.config.namespace.clone(),
            name: self.config.deployment.clone(),
        })
    }
}

impl fmt::Debug for KubernetesSourceAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KubernetesSourceAdapter")
            .field("config", &self.config)
            .field("transport", &"<runner-owned Kubernetes transport>")
            .finish_non_exhaustive()
    }
}

impl TargetSource for KubernetesSourceAdapter {
    fn identity_descriptor(
        &self,
    ) -> Result<ConnectorSourceIdentityDescriptor, accordlock_connectors::ConnectorError> {
        Ok(self.identity.clone())
    }

    fn fetch(&self, lookup: &TargetLookupId) -> Result<TargetSourceSnapshot, SourceReadError> {
        let (request_id, deployment_uid, resource_version) =
            parse_target_lookup(lookup.as_str())
                .map_err(|_| self.failures.invalid_lookup.clone())?;
        let request = self
            .request()
            .map_err(|_| self.failures.invalid_lookup.clone())?;
        let response = self
            .transport
            .read(&request)
            .map_err(|_| self.failures.transport.clone())?;
        let body = response
            .body_for(self.config.maximum_response_bytes)
            .map_err(|_| self.failures.invalid_response.clone())?;
        let wire: KubernetesTargetObservation =
            parse_strict_json(&body).map_err(|_| self.failures.invalid_response.clone())?;
        validate_observation(
            &wire,
            request_id,
            deployment_uid,
            &resource_version,
            &self.config,
        )
        .map_err(|_| self.failures.invalid_response.clone())?;
        Ok(TargetSourceSnapshot {
            meta: SourceSnapshotMeta {
                request_id,
                lookup_id: lookup.as_str().to_owned(),
                evidence_id: wire.evidence_id,
                source_uri: self.config.endpoint.source_uri(&request.path),
                observed_at: wire.observed_at,
                source_sequence: wire.source_sequence,
            },
            source_repository: wire.source_repository,
            commit_sha: wire.commit_sha,
            image_repository: wire.image_repository,
            desired_image_digest: wire.desired_image_digest,
            cluster_identity: wire.cluster_identity,
            namespace: wire.namespace,
            deployment: wire.deployment,
            deployment_uid: wire.deployment_uid.to_string(),
            resource_version: wire.resource_version,
            current_image: wire.current_image,
            projection_hash: wire.projection_hash,
        })
    }
}

/// Creates an exact target lookup bound to request, Deployment UID and
/// `resourceVersion`.
///
/// # Errors
///
/// Rejects nil identifiers and noncanonical resource versions.
pub fn kubernetes_target_lookup(
    request_id: Uuid,
    deployment_uid: Uuid,
    resource_version: impl Into<String>,
) -> Result<TargetLookupId, AdapterConfigError> {
    let resource_version = resource_version.into();
    if request_id.is_nil() || deployment_uid.is_nil() {
        return Err(AdapterConfigError::Invalid("Kubernetes target lookup"));
    }
    validate_resource_version(&resource_version)
        .map_err(|_| AdapterConfigError::Invalid("Kubernetes resource version"))?;
    TargetLookupId::parse(format!(
        "al1/kubernetes/target/{request_id}/uid/{deployment_uid}/rv/{resource_version}"
    ))
    .map_err(|_| AdapterConfigError::Invalid("Kubernetes target lookup"))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KubernetesTargetObservation {
    schema_version: u16,
    request_id: Uuid,
    evidence_id: Uuid,
    observed_at: i64,
    source_sequence: u64,
    cluster_identity: String,
    namespace: String,
    deployment: String,
    deployment_uid: Uuid,
    resource_version: String,
    container: String,
    source_repository: String,
    commit_sha: String,
    image_repository: String,
    desired_image_digest: Digest32,
    current_image: Digest32,
    projection_hash: Digest32,
}

fn parse_target_lookup(value: &str) -> Result<(Uuid, Uuid, String), ProviderResponseError> {
    let (request_id, tail) = split_lookup(value, &TARGET_LOOKUP_PREFIX, 4)?;
    if tail[0] != "uid" || tail[2] != "rv" {
        return Err(ProviderResponseError::Binding);
    }
    let deployment_uid = Uuid::parse_str(tail[1]).map_err(|_| ProviderResponseError::Binding)?;
    if deployment_uid.is_nil() || deployment_uid.to_string() != tail[1] {
        return Err(ProviderResponseError::Binding);
    }
    validate_resource_version(tail[3])?;
    Ok((request_id, deployment_uid, tail[3].to_owned()))
}

fn validate_observation(
    wire: &KubernetesTargetObservation,
    request_id: Uuid,
    deployment_uid: Uuid,
    resource_version: &str,
    config: &KubernetesAdapterConfig,
) -> Result<(), ProviderResponseError> {
    validate_positive_meta(
        wire.request_id,
        wire.evidence_id,
        wire.observed_at,
        wire.source_sequence,
    )?;
    validate_commit_sha(&wire.commit_sha)?;
    validate_resource_version(&wire.resource_version)?;
    if wire.schema_version != crate::PROVIDER_ADAPTER_SCHEMA_VERSION
        || wire.request_id != request_id
        || wire.cluster_identity != config.cluster_identity
        || wire.namespace != config.namespace
        || wire.deployment != config.deployment
        || wire.deployment_uid != deployment_uid
        || wire.resource_version != resource_version
        || wire.container != config.container
        || wire.source_repository != config.source_repository
        || wire.image_repository != config.image_repository
    {
        return Err(ProviderResponseError::Binding);
    }
    Ok(())
}

fn validate_resource_version(value: &str) -> Result<(), ProviderResponseError> {
    if value.is_empty()
        || value.len() > 64
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(ProviderResponseError::Binding);
    }
    Ok(())
}

fn validate_dns_label(value: &str, label: &'static str) -> Result<(), AdapterConfigError> {
    validate_route_segment(value, label)?;
    if value.len() > 63
        || value != value.to_ascii_lowercase()
        || value.starts_with('-')
        || value.ends_with('-')
        || value.contains(['.', '_'])
    {
        return Err(AdapterConfigError::Invalid(label));
    }
    Ok(())
}

fn validate_cluster_identity(value: &str) -> Result<(), AdapterConfigError> {
    if value.is_empty()
        || value.len() > 512
        || value.trim() != value
        || value.contains(char::is_whitespace)
        || value.chars().any(char::is_control)
    {
        return Err(AdapterConfigError::Invalid("cluster identity"));
    }
    Ok(())
}

fn validate_source_repository(value: &str) -> Result<(), AdapterConfigError> {
    let parts = value.split('/').collect::<Vec<_>>();
    if parts.len() != 2
        || parts
            .iter()
            .any(|part| validate_route_segment(part, "source repository").is_err())
    {
        return Err(AdapterConfigError::Invalid("source repository"));
    }
    Ok(())
}

fn validate_image_repository(value: &str) -> Result<(), AdapterConfigError> {
    if value.is_empty()
        || value.len() > 512
        || value.trim() != value
        || value.contains(['@', ':', '?', '#'])
        || value.chars().any(char::is_control)
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(AdapterConfigError::Invalid("image repository"));
    }
    Ok(())
}
