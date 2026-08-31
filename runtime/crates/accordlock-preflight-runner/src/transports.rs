use std::{collections::BTreeMap, fmt, fmt::Write as _, str::FromStr as _, sync::Arc};

use accordlock_protocol::{CompletenessProfile, Digest32};
use accordlock_provider_adapters::{
    AdapterConfigError, AuthenticatedJsonResponse, AuthenticatedTransportIdentity,
    EcrAuthenticatedTransport, EcrReadRequest, GitHubAuthenticatedTransport, GitHubReadOperation,
    GitHubReadRequest, KubernetesAuthenticatedTransport, KubernetesReadRequest, ReadMethod,
    RedirectPolicy, ResponseMediaType, TransportFailure,
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, Mac as _};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    http::{FixedHttpsClient, HttpMethod, HttpResponse},
    model::{
        CredentialBundle, EKS_ENROLLMENT_SCHEMA_VERSION, EksEnrollmentCredentials,
        EksEnrollmentRequest, EksEnrollmentResult, PreflightProfile, SecretBytes,
        SignedArtifactTrustRecord, SignedBuildTrustRecord,
    },
};

const USER_AGENT: &str = "accordlock-preflight-runner/0.1";
const GITHUB_API_VERSION: &str = "2022-11-28";
const MAX_EKS_CA_DATA_BYTES: usize = 256 * 1024;
const MAX_EKS_CA_CERTIFICATES: usize = 16;
const MAX_EKS_ENROLLMENT_RESPONSE_BYTES: usize = 256 * 1024;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy)]
struct AwsCredentialRef<'a> {
    access_key_id: &'a [u8],
    secret_access_key: &'a [u8],
    session_token: Option<&'a [u8]>,
}

impl<'a> From<&'a CredentialBundle> for AwsCredentialRef<'a> {
    fn from(credentials: &'a CredentialBundle) -> Self {
        Self {
            access_key_id: credentials.aws_access_key_id.expose(),
            secret_access_key: credentials.aws_secret_access_key.expose(),
            session_token: credentials
                .aws_session_token
                .as_ref()
                .map(SecretBytes::expose),
        }
    }
}

impl<'a> From<&'a EksEnrollmentCredentials> for AwsCredentialRef<'a> {
    fn from(credentials: &'a EksEnrollmentCredentials) -> Self {
        Self {
            access_key_id: credentials.aws_access_key_id.expose(),
            secret_access_key: credentials.aws_secret_access_key.expose(),
            session_token: credentials
                .aws_session_token
                .as_ref()
                .map(SecretBytes::expose),
        }
    }
}

struct SecretHeaders(Vec<(&'static str, String)>);

impl SecretHeaders {
    fn as_slice(&self) -> &[(&'static str, String)] {
        &self.0
    }
}

impl Drop for SecretHeaders {
    fn drop(&mut self) {
        for (_, value) in &mut self.0 {
            value.zeroize();
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetPrestate {
    pub cluster_identity: String,
    pub cluster_endpoint: String,
    pub cluster_ca_hash: Digest32,
    pub deployment_uid: Uuid,
    pub resource_version: String,
    pub current_image_digest: Digest32,
    pub projection_hash: Digest32,
    pub observed_at: i64,
    pub evidence_reference: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct EksClusterDiscovery {
    pub cluster_identity: String,
    pub cluster_endpoint: String,
    pub cluster_ca_hash: Digest32,
    pub discovery_identity_hash: Digest32,
    endpoint_authority: String,
    ca_certificates_der: Vec<Vec<u8>>,
}

impl fmt::Debug for EksClusterDiscovery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EksClusterDiscovery")
            .field("cluster_identity", &self.cluster_identity)
            .field("cluster_endpoint", &self.cluster_endpoint)
            .field("cluster_ca_hash", &self.cluster_ca_hash)
            .field("discovery_identity_hash", &self.discovery_identity_hash)
            .field("endpoint_authority", &self.endpoint_authority)
            .field("ca_certificate_count", &self.ca_certificates_der.len())
            .finish()
    }
}

impl EksClusterDiscovery {
    #[must_use]
    pub fn endpoint_authority(&self) -> &str {
        &self.endpoint_authority
    }
}

#[derive(Clone)]
pub struct GitHubTransport {
    profile: Arc<PreflightProfile>,
    credentials: Arc<CredentialBundle>,
    client: FixedHttpsClient,
    request_id: Uuid,
    pull_number: u64,
    run_id: u64,
    build_trust: SignedBuildTrustRecord,
    trusted_now: i64,
}

impl fmt::Debug for GitHubTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitHubTransport")
            .field("authority", &self.client.authority())
            .field("request_id", &self.request_id)
            .field("pull_number", &self.pull_number)
            .field("run_id", &self.run_id)
            .field("credentials", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl GitHubTransport {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile: Arc<PreflightProfile>,
        credentials: Arc<CredentialBundle>,
        request_id: Uuid,
        pull_number: u64,
        run_id: u64,
        image_digest: Digest32,
        build_trust: SignedBuildTrustRecord,
        trusted_now: i64,
    ) -> Result<Self, TransportFailure> {
        build_trust
            .verify(&profile, run_id, image_digest, trusted_now)
            .map_err(|_| TransportFailure::Integrity)?;
        let ca = profile
            .github
            .ca_certificates_der
            .iter()
            .map(|value| value.0.clone())
            .collect::<Vec<_>>();
        let client = FixedHttpsClient::new(
            profile.github.authority.clone(),
            profile.github.socket_address,
            &ca,
        )?;
        Ok(Self {
            profile,
            credentials,
            client,
            request_id,
            pull_number,
            run_id,
            build_trust,
            trusted_now,
        })
    }

    fn headers(&self) -> Result<Vec<(&'static str, String)>, TransportFailure> {
        let token = std::str::from_utf8(self.credentials.github_token.expose())
            .map_err(|_| TransportFailure::Authentication)?;
        Ok(vec![
            ("authorization", format!("Bearer {token}")),
            ("user-agent", USER_AGENT.to_owned()),
            ("x-github-api-version", GITHUB_API_VERSION.to_owned()),
        ])
    }

    fn github_get(&self, suffix: &str, maximum: usize) -> Result<HttpResponse, TransportFailure> {
        let mut path = self.profile.github.api_base_path.clone();
        if path == "/" {
            path.clear();
        }
        path.push_str(suffix);
        let response =
            self.client
                .send_json(HttpMethod::Get, &path, &self.headers()?, &[], maximum)?;
        require_provider_json(response)
    }

    fn read_review(
        &self,
        maximum_response_bytes: usize,
    ) -> Result<AuthenticatedJsonResponse, TransportFailure> {
        let repository = self.profile.github_repository();
        let base = format!(
            "/repos/{}/{}/pulls/{}",
            self.profile.github.owner, self.profile.github.repository, self.pull_number
        );
        let pull: NativePull =
            parse_provider_json(&self.github_get(&base, maximum_response_bytes)?)?;
        if pull.number != self.pull_number || pull.id == 0 || !valid_commit(&pull.head.sha) {
            return Err(TransportFailure::Integrity);
        }
        let reviews_path = format!("{base}/reviews?per_page=100");
        let reviews: Vec<NativeReview> =
            parse_provider_json(&self.github_get(&reviews_path, maximum_response_bytes)?)?;
        if reviews.len() == 100 {
            return Err(TransportFailure::Integrity);
        }
        let mut latest_by_reviewer: BTreeMap<String, &NativeReview> = BTreeMap::new();
        let mut source_sequence = pull.id;
        for review in &reviews {
            if review.id == 0
                || review.user.login.is_empty()
                || !matches!(
                    review.state.as_str(),
                    "APPROVED" | "CHANGES_REQUESTED" | "COMMENTED" | "DISMISSED" | "PENDING"
                )
            {
                return Err(TransportFailure::Integrity);
            }
            source_sequence = source_sequence.max(review.id);
            let replace = latest_by_reviewer
                .get(&review.user.login)
                .is_none_or(|current| current.id < review.id);
            if replace {
                latest_by_reviewer.insert(review.user.login.clone(), review);
            }
        }
        let approvals = latest_by_reviewer
            .values()
            .filter(|review| {
                review.state == "APPROVED"
                    && review.commit_id.as_deref() == Some(pull.head.sha.as_str())
            })
            .count();
        let approved = approvals >= usize::from(self.profile.github.minimum_approvals);
        let body = json!({
            "schema_version": 1,
            "request_id": self.request_id,
            "evidence_id": evidence_id(b"github-review", self.request_id, source_sequence, pull.head.sha.as_bytes()),
            "observed_at": self.trusted_now,
            "source_sequence": source_sequence,
            "repository": repository,
            "pull_number": self.pull_number,
            "commit_sha": pull.head.sha,
            "approved": approved
        });
        normalized_response(&body)
    }

    fn read_build(
        &self,
        maximum_response_bytes: usize,
    ) -> Result<AuthenticatedJsonResponse, TransportFailure> {
        let path = format!(
            "/repos/{}/{}/actions/runs/{}",
            self.profile.github.owner, self.profile.github.repository, self.run_id
        );
        let run: NativeWorkflowRun =
            parse_provider_json(&self.github_get(&path, maximum_response_bytes)?)?;
        if run.id != self.run_id
            || !valid_commit(&run.head_sha)
            || run.path != self.profile.github.workflow_ref
            || run.head_sha != self.build_trust.payload.commit_sha
            || run.run_attempt == 0
        {
            return Err(TransportFailure::Integrity);
        }
        let succeeded = run.status == "completed" && run.conclusion.as_deref() == Some("success");
        let sequence = run
            .id
            .checked_mul(1_000)
            .and_then(|value| value.checked_add(run.run_attempt))
            .ok_or(TransportFailure::Integrity)?;
        let body = json!({
            "schema_version": 1,
            "request_id": self.request_id,
            "evidence_id": evidence_id(b"github-build", self.request_id, sequence, run.head_sha.as_bytes()),
            "observed_at": self.trusted_now,
            "source_sequence": sequence,
            "repository": self.profile.github_repository(),
            "workflow_ref": self.profile.github.workflow_ref,
            "run_id": self.run_id,
            "commit_sha": run.head_sha,
            "succeeded": succeeded,
            "input_manifest_root": self.build_trust.payload.input_manifest_root,
            "completeness_profile": CompletenessProfile::HermeticInputsV1,
            "output_digest": self.build_trust.payload.output_digest
        });
        normalized_response(&body)
    }
}

impl GitHubAuthenticatedTransport for GitHubTransport {
    fn public_identity(&self) -> Result<AuthenticatedTransportIdentity, AdapterConfigError> {
        AuthenticatedTransportIdentity::new(
            "accordlock-github-rest-v1",
            format!("github-repository:{}", self.profile.github_repository()),
            "inherited-credential:github",
            self.client.trust_anchor_hash(),
        )
    }

    fn read(
        &self,
        request: &GitHubReadRequest,
    ) -> Result<AuthenticatedJsonResponse, TransportFailure> {
        if request.method != ReadMethod::Get
            || request.redirect_policy != RedirectPolicy::Deny
            || request.authority != self.profile.github.authority
            || request.maximum_response_bytes > self.profile.github.maximum_response_bytes
        {
            return Err(TransportFailure::Route);
        }
        match request.operation {
            GitHubReadOperation::PullReviewDecision => {
                let expected = logical_github_path(
                    &self.profile,
                    &format!(
                        "/repos/{}/{}/pulls/{}/accordlock-review-decision",
                        self.profile.github.owner, self.profile.github.repository, self.pull_number
                    ),
                );
                if request.path != expected {
                    return Err(TransportFailure::Route);
                }
                self.read_review(request.maximum_response_bytes)
            }
            GitHubReadOperation::ActionsBuildAttestation => {
                let expected = logical_github_path(
                    &self.profile,
                    &format!(
                        "/repos/{}/{}/actions/runs/{}/accordlock-build-attestation",
                        self.profile.github.owner, self.profile.github.repository, self.run_id
                    ),
                );
                if request.path != expected {
                    return Err(TransportFailure::Route);
                }
                self.read_build(request.maximum_response_bytes)
            }
        }
    }
}

#[derive(Clone)]
pub struct EcrTransport {
    profile: Arc<PreflightProfile>,
    credentials: Arc<CredentialBundle>,
    client: FixedHttpsClient,
    request_id: Uuid,
    trust: SignedArtifactTrustRecord,
    trusted_now: i64,
}

impl fmt::Debug for EcrTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EcrTransport")
            .field("authority", &self.client.authority())
            .field("request_id", &self.request_id)
            .field("credentials", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl EcrTransport {
    pub fn new(
        profile: Arc<PreflightProfile>,
        credentials: Arc<CredentialBundle>,
        request_id: Uuid,
        digest: Digest32,
        trust: SignedArtifactTrustRecord,
        trusted_now: i64,
    ) -> Result<Self, TransportFailure> {
        trust
            .verify(&profile, digest, trusted_now)
            .map_err(|_| TransportFailure::Integrity)?;
        let authority = format!("api.ecr.{}.amazonaws.com", profile.ecr.region);
        let ca = profile
            .ecr
            .ca_certificates_der
            .iter()
            .map(|value| value.0.clone())
            .collect::<Vec<_>>();
        let client = FixedHttpsClient::new(authority, profile.ecr.socket_address, &ca)?;
        Ok(Self {
            profile,
            credentials,
            client,
            request_id,
            trust,
            trusted_now,
        })
    }
}

impl EcrAuthenticatedTransport for EcrTransport {
    fn public_identity(&self) -> Result<AuthenticatedTransportIdentity, AdapterConfigError> {
        let access_key_hash = Digest32::sha256(self.credentials.aws_access_key_id.expose());
        AuthenticatedTransportIdentity::new(
            "accordlock-aws-ecr-sigv4-v1",
            format!(
                "configured-aws-credential:{}:{}",
                self.profile.ecr.registry_id,
                &access_key_hash.to_hex()[..16]
            ),
            "inherited-credential:aws",
            self.client.trust_anchor_hash(),
        )
    }

    fn read(
        &self,
        request: &EcrReadRequest,
    ) -> Result<AuthenticatedJsonResponse, TransportFailure> {
        if request.method != ReadMethod::Post
            || request.redirect_policy != RedirectPolicy::Deny
            || request.authority != self.client.authority()
            || request.path != "/"
            || request.sigv4_service != "ecr"
            || request.region != self.profile.ecr.region
            || request.x_amz_target != "AmazonEC2ContainerRegistry_V20150921.BatchGetImage"
            || request.registry_id != self.profile.ecr.registry_id
            || request.repository_name != self.profile.ecr.repository
            || request.image_digest != self.trust.payload.image_digest
            || request.maximum_response_bytes > self.profile.ecr.maximum_response_bytes
        {
            return Err(TransportFailure::Route);
        }
        let body = serde_json::to_vec(&EcrBatchGetRequest {
            image_ids: [EcrImageIdentifier {
                image_digest: request.image_digest.to_string(),
            }],
            registry_id: request.registry_id.clone(),
            repository_name: request.repository_name.clone(),
        })
        .map_err(|_| TransportFailure::Integrity)?;
        let headers = sigv4_headers(
            &self.credentials,
            self.client.authority(),
            &request.region,
            &request.x_amz_target,
            &body,
            self.trusted_now,
        )?;
        let response = require_provider_json(self.client.send_json(
            HttpMethod::Post,
            "/",
            headers.as_slice(),
            &body,
            request.maximum_response_bytes,
        )?)?;
        let native: EcrBatchGetResponse = parse_provider_json(&response)?;
        if !native.failures.is_empty() || native.images.len() != 1 {
            return Err(TransportFailure::Integrity);
        }
        let image = &native.images[0];
        let expected_digest = request.image_digest.to_string();
        if image.registry_id != request.registry_id
            || image.repository_name != request.repository_name
            || image.image_id.image_digest.as_deref() != Some(expected_digest.as_str())
        {
            return Err(TransportFailure::Integrity);
        }
        let sequence = u64::try_from(self.trusted_now).map_err(|_| TransportFailure::Integrity)?;
        let normalized = json!({
            "schema_version": 1,
            "request_id": self.request_id,
            "evidence_id": evidence_id(b"aws-ecr", self.request_id, sequence, request.image_digest.as_bytes()),
            "observed_at": self.trusted_now,
            "source_sequence": sequence,
            "registry_id": self.profile.ecr.registry_id,
            "region": self.profile.ecr.region,
            "repository_name": self.profile.ecr.repository,
            "image_digest": request.image_digest,
            "source_repository": self.trust.payload.source_repository,
            "commit_sha": self.trust.payload.commit_sha,
            "source_run_id": self.trust.payload.source_run_id,
            "signature_valid": self.trust.payload.signature_valid,
            "quarantined": self.trust.payload.quarantined
        });
        normalized_response(&normalized)
    }
}

#[derive(Clone)]
pub struct EksDiscoveryTransport {
    profile: Arc<PreflightProfile>,
    credentials: Arc<CredentialBundle>,
    client: FixedHttpsClient,
    trusted_now: i64,
}

impl fmt::Debug for EksDiscoveryTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EksDiscoveryTransport")
            .field("authority", &self.client.authority())
            .field("cluster_name", &self.profile.kubernetes.cluster_name)
            .field("credentials", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl EksDiscoveryTransport {
    pub fn new(
        profile: Arc<PreflightProfile>,
        credentials: Arc<CredentialBundle>,
        trusted_now: i64,
    ) -> Result<Self, TransportFailure> {
        let authority = eks_authority(&profile.ecr.region);
        let ca = profile
            .eks_discovery
            .ca_certificates_der
            .iter()
            .map(|value| value.0.clone())
            .collect::<Vec<_>>();
        let client = FixedHttpsClient::new(authority, profile.eks_discovery.socket_address, &ca)?;
        Ok(Self {
            profile,
            credentials,
            client,
            trusted_now,
        })
    }

    pub fn describe_cluster(&self) -> Result<EksClusterDiscovery, TransportFailure> {
        let request = EksEnrollmentRequest {
            account_id: self.profile.ecr.registry_id.clone(),
            region: self.profile.ecr.region.clone(),
            cluster_name: self.profile.kubernetes.cluster_name.clone(),
        };
        describe_eks_cluster(
            &request,
            AwsCredentialRef::from(self.credentials.as_ref()),
            &self.client,
            self.trusted_now,
            Some(&self.profile.kubernetes.expected_endpoint),
            self.profile.kubernetes.socket_address,
            self.profile.eks_discovery.maximum_response_bytes,
        )
    }
}

/// Production EKS enrollment transport. Its EKS authority and `WebPKI` trust
/// roots are derived internally; the caller cannot supply a URL, socket, or CA.
pub struct EksEnrollmentTransport {
    request: EksEnrollmentRequest,
    credentials: EksEnrollmentCredentials,
    client: FixedHttpsClient,
    trusted_now: i64,
}

impl fmt::Debug for EksEnrollmentTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EksEnrollmentTransport")
            .field("authority", &self.client.authority())
            .field("account_id", &self.request.account_id)
            .field("region", &self.request.region)
            .field("cluster_name", &self.request.cluster_name)
            .field("credentials", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl EksEnrollmentTransport {
    pub fn new(
        request: EksEnrollmentRequest,
        credentials: EksEnrollmentCredentials,
        trusted_now: i64,
    ) -> Result<Self, TransportFailure> {
        Self::new_with_trust(request, credentials, trusted_now, None, &[])
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        request: EksEnrollmentRequest,
        credentials: EksEnrollmentCredentials,
        trusted_now: i64,
        socket_address: std::net::SocketAddr,
        ca_certificate_der: Vec<u8>,
    ) -> Result<Self, TransportFailure> {
        Self::new_with_trust(
            request,
            credentials,
            trusted_now,
            Some(socket_address),
            &[ca_certificate_der],
        )
    }

    fn new_with_trust(
        request: EksEnrollmentRequest,
        credentials: EksEnrollmentCredentials,
        trusted_now: i64,
        socket_address: Option<std::net::SocketAddr>,
        ca_certificates_der: &[Vec<u8>],
    ) -> Result<Self, TransportFailure> {
        request.validate().map_err(|_| TransportFailure::Route)?;
        credentials
            .validate()
            .map_err(|_| TransportFailure::Authentication)?;
        let client = FixedHttpsClient::new(
            eks_authority(&request.region),
            socket_address,
            ca_certificates_der,
        )?;
        Ok(Self {
            request,
            credentials,
            client,
            trusted_now,
        })
    }

    pub fn describe_cluster(&self) -> Result<EksEnrollmentResult, TransportFailure> {
        let discovery = describe_eks_cluster(
            &self.request,
            AwsCredentialRef::from(&self.credentials),
            &self.client,
            self.trusted_now,
            None,
            None,
            MAX_EKS_ENROLLMENT_RESPONSE_BYTES,
        )?;
        Ok(EksEnrollmentResult {
            schema_version: EKS_ENROLLMENT_SCHEMA_VERSION,
            cluster_arn: discovery.cluster_identity,
            endpoint: discovery.cluster_endpoint,
            cluster_ca_hash: discovery.cluster_ca_hash,
        })
    }
}

fn describe_eks_cluster(
    request: &EksEnrollmentRequest,
    credentials: AwsCredentialRef<'_>,
    client: &FixedHttpsClient,
    trusted_now: i64,
    expected_endpoint: Option<&str>,
    kubernetes_socket_address: Option<std::net::SocketAddr>,
    maximum_response_bytes: usize,
) -> Result<EksClusterDiscovery, TransportFailure> {
    let path = format!("/clusters/{}", request.cluster_name);
    let headers = eks_sigv4_headers(
        credentials,
        client.authority(),
        &request.region,
        &path,
        trusted_now,
    )?;
    let response = require_provider_json(client.send_json(
        HttpMethod::Get,
        &path,
        headers.as_slice(),
        &[],
        maximum_response_bytes,
    )?)?;
    let native: EksDescribeClusterResponse = parse_provider_json(&response)?;
    if native.cluster.name != request.cluster_name
        || native.cluster.arn != request.expected_cluster_arn()
    {
        return Err(TransportFailure::Integrity);
    }
    let cluster_endpoint =
        canonical_eks_cluster_endpoint(&native.cluster.endpoint, expected_endpoint)?;
    let endpoint_authority = cluster_endpoint
        .strip_prefix("https://")
        .ok_or(TransportFailure::Integrity)?
        .to_owned();
    let ca_certificates_der =
        decode_eks_certificate_authority(&native.cluster.certificate_authority.data)?;
    let kubernetes_client = FixedHttpsClient::new(
        endpoint_authority.clone(),
        kubernetes_socket_address,
        &ca_certificates_der,
    )?;
    let cluster_ca_hash = kubernetes_client.trust_anchor_hash();
    let access_key_hash = Digest32::sha256(credentials.access_key_id);
    let transport_identity = AuthenticatedTransportIdentity::new(
        "accordlock-aws-eks-describe-cluster-sigv4-v1",
        format!(
            "configured-aws-credential:{}:{}",
            request.account_id,
            &access_key_hash.to_hex()[..16]
        ),
        "inherited-credential:aws",
        client.trust_anchor_hash(),
    )
    .map_err(|_| TransportFailure::Integrity)?;
    let discovery_identity_hash = eks_discovery_commitment(
        transport_identity.digest(),
        &native.cluster.arn,
        &cluster_endpoint,
        cluster_ca_hash,
    );
    Ok(EksClusterDiscovery {
        cluster_identity: native.cluster.arn,
        cluster_endpoint,
        cluster_ca_hash,
        discovery_identity_hash,
        endpoint_authority,
        ca_certificates_der,
    })
}

#[derive(Clone)]
pub struct KubernetesTransport {
    profile: Arc<PreflightProfile>,
    credentials: Arc<CredentialBundle>,
    client: FixedHttpsClient,
    request_id: Uuid,
    commit_sha: String,
    desired_image_digest: Digest32,
    expected: TargetPrestate,
    cluster: EksClusterDiscovery,
    trusted_now: i64,
}

impl fmt::Debug for KubernetesTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KubernetesTransport")
            .field("authority", &self.client.authority())
            .field("request_id", &self.request_id)
            .field("expected", &self.expected)
            .field("credentials", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl KubernetesTransport {
    fn client_for_discovery(
        profile: &PreflightProfile,
        cluster: &EksClusterDiscovery,
    ) -> Result<FixedHttpsClient, TransportFailure> {
        FixedHttpsClient::new(
            cluster.endpoint_authority.clone(),
            profile.kubernetes.socket_address,
            &cluster.ca_certificates_der,
        )
    }

    pub fn discover(
        profile: &PreflightProfile,
        credentials: &CredentialBundle,
        cluster: &EksClusterDiscovery,
        trusted_now: i64,
    ) -> Result<TargetPrestate, TransportFailure> {
        let client = Self::client_for_discovery(profile, cluster)?;
        if client.trust_anchor_hash() != cluster.cluster_ca_hash {
            return Err(TransportFailure::Integrity);
        }
        let path = kubernetes_path(profile);
        let token = eks_kubernetes_bearer_token(
            credentials,
            &profile.ecr.region,
            &profile.kubernetes.cluster_name,
            trusted_now,
        )?;
        let response = require_provider_json(client.send_json(
            HttpMethod::Get,
            &path,
            &[
                ("authorization", format!("Bearer {token}")),
                ("user-agent", USER_AGENT.to_owned()),
            ],
            &[],
            profile.kubernetes.maximum_response_bytes,
        )?)?;
        let deployment: NativeDeployment = parse_provider_json(&response)?;
        project_target(profile, cluster, &deployment, trusted_now)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile: Arc<PreflightProfile>,
        credentials: Arc<CredentialBundle>,
        request_id: Uuid,
        commit_sha: String,
        desired_image_digest: Digest32,
        expected: TargetPrestate,
        cluster: EksClusterDiscovery,
        trusted_now: i64,
    ) -> Result<Self, TransportFailure> {
        if !valid_commit(&commit_sha) {
            return Err(TransportFailure::Integrity);
        }
        let client = Self::client_for_discovery(&profile, &cluster)?;
        if client.trust_anchor_hash() != cluster.cluster_ca_hash
            || expected.cluster_identity != cluster.cluster_identity
            || expected.cluster_endpoint != cluster.cluster_endpoint
            || expected.cluster_ca_hash != cluster.cluster_ca_hash
        {
            return Err(TransportFailure::Integrity);
        }
        Ok(Self {
            profile,
            credentials,
            client,
            request_id,
            commit_sha,
            desired_image_digest,
            expected,
            cluster,
            trusted_now,
        })
    }

    fn native_read(
        &self,
        maximum_response_bytes: usize,
    ) -> Result<TargetPrestate, TransportFailure> {
        let token = eks_kubernetes_bearer_token(
            &self.credentials,
            &self.profile.ecr.region,
            &self.profile.kubernetes.cluster_name,
            self.trusted_now,
        )?;
        let response = require_provider_json(self.client.send_json(
            HttpMethod::Get,
            &kubernetes_path(&self.profile),
            &[
                ("authorization", format!("Bearer {token}")),
                ("user-agent", USER_AGENT.to_owned()),
            ],
            &[],
            maximum_response_bytes,
        )?)?;
        let deployment: NativeDeployment = parse_provider_json(&response)?;
        project_target(&self.profile, &self.cluster, &deployment, self.trusted_now)
    }
}

impl KubernetesAuthenticatedTransport for KubernetesTransport {
    fn public_identity(&self) -> Result<AuthenticatedTransportIdentity, AdapterConfigError> {
        AuthenticatedTransportIdentity::new(
            "accordlock-kubernetes-get-v1",
            format!("kubernetes-cluster:{}", self.cluster.cluster_identity),
            format!(
                "derived-credential:aws-eks-presigned-sts:{}",
                self.cluster.discovery_identity_hash
            ),
            self.client.trust_anchor_hash(),
        )
    }

    fn read(
        &self,
        request: &KubernetesReadRequest,
    ) -> Result<AuthenticatedJsonResponse, TransportFailure> {
        if request.method != ReadMethod::Get
            || request.redirect_policy != RedirectPolicy::Deny
            || request.authority != self.cluster.endpoint_authority
            || request.path != kubernetes_path(&self.profile)
            || request.maximum_response_bytes > self.profile.kubernetes.maximum_response_bytes
            || request.api_group != "apps"
            || request.api_version != "v1"
            || request.resource != "deployments"
            || request.namespace != self.profile.kubernetes.namespace
            || request.name != self.profile.kubernetes.deployment
        {
            return Err(TransportFailure::Route);
        }
        let observed = self.native_read(request.maximum_response_bytes)?;
        let sequence = observed
            .resource_version
            .parse::<u64>()
            .map_err(|_| TransportFailure::Integrity)?;
        let normalized = json!({
            "schema_version": 1,
            "request_id": self.request_id,
            "evidence_id": evidence_id(b"kubernetes-target", self.request_id, sequence, observed.projection_hash.as_bytes()),
            "observed_at": observed.observed_at,
            "source_sequence": sequence,
            "cluster_identity": self.cluster.cluster_identity,
            "namespace": self.profile.kubernetes.namespace,
            "deployment": self.profile.kubernetes.deployment,
            "deployment_uid": observed.deployment_uid,
            "resource_version": observed.resource_version,
            "container": self.profile.kubernetes.container,
            "source_repository": self.profile.github_repository(),
            "commit_sha": self.commit_sha,
            "image_repository": self.profile.ecr_image_repository(),
            "desired_image_digest": self.desired_image_digest,
            "current_image": observed.current_image_digest,
            "projection_hash": observed.projection_hash
        });
        if observed.deployment_uid != self.expected.deployment_uid
            || observed.resource_version != self.expected.resource_version
            || observed.projection_hash != self.expected.projection_hash
        {
            return Err(TransportFailure::Integrity);
        }
        normalized_response(&normalized)
    }
}

#[derive(Debug, Deserialize)]
struct NativePull {
    id: u64,
    number: u64,
    head: NativePullHead,
}

#[derive(Debug, Deserialize)]
struct NativePullHead {
    sha: String,
}

#[derive(Debug, Deserialize)]
struct NativeReview {
    id: u64,
    user: NativeUser,
    state: String,
    commit_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NativeUser {
    login: String,
}

#[derive(Debug, Deserialize)]
struct NativeWorkflowRun {
    id: u64,
    run_attempt: u64,
    head_sha: String,
    path: String,
    status: String,
    conclusion: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EcrBatchGetRequest {
    image_ids: [EcrImageIdentifier; 1],
    registry_id: String,
    repository_name: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EcrImageIdentifier {
    image_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcrBatchGetResponse {
    #[serde(default)]
    images: Vec<EcrImage>,
    #[serde(default)]
    failures: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcrImage {
    registry_id: String,
    repository_name: String,
    image_id: EcrImageId,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcrImageId {
    image_digest: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EksDescribeClusterResponse {
    cluster: EksCluster,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EksCluster {
    name: String,
    arn: String,
    endpoint: String,
    certificate_authority: EksCertificateAuthority,
}

#[derive(Debug, Deserialize)]
struct EksCertificateAuthority {
    data: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeDeployment {
    api_version: String,
    kind: String,
    metadata: NativeMetadata,
    spec: NativeDeploymentSpec,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeMetadata {
    uid: String,
    resource_version: String,
    namespace: Option<String>,
    name: String,
}

#[derive(Debug, Deserialize)]
struct NativeDeploymentSpec {
    template: NativePodTemplate,
}

#[derive(Debug, Deserialize)]
struct NativePodTemplate {
    spec: NativePodSpec,
}

#[derive(Debug, Deserialize)]
struct NativePodSpec {
    containers: Vec<NativeContainer>,
}

#[derive(Debug, Deserialize, Serialize)]
struct NativeContainer {
    name: String,
    image: String,
}

#[derive(Serialize)]
struct TargetProjection<'a> {
    api_version: &'a str,
    kind: &'a str,
    namespace: &'a str,
    name: &'a str,
    uid: &'a str,
    resource_version: &'a str,
    container: &'a str,
    image: &'a str,
}

fn project_target(
    profile: &PreflightProfile,
    cluster: &EksClusterDiscovery,
    deployment: &NativeDeployment,
    trusted_now: i64,
) -> Result<TargetPrestate, TransportFailure> {
    if deployment.api_version != "apps/v1"
        || deployment.kind != "Deployment"
        || deployment.metadata.namespace.as_deref() != Some(profile.kubernetes.namespace.as_str())
        || deployment.metadata.name != profile.kubernetes.deployment
        || deployment.metadata.uid.to_ascii_lowercase() != deployment.metadata.uid
        || deployment.metadata.resource_version.is_empty()
        || !deployment
            .metadata
            .resource_version
            .bytes()
            .all(|value| value.is_ascii_digit())
    {
        return Err(TransportFailure::Integrity);
    }
    let deployment_uid =
        Uuid::parse_str(&deployment.metadata.uid).map_err(|_| TransportFailure::Integrity)?;
    if deployment_uid.is_nil() || deployment_uid.to_string() != deployment.metadata.uid {
        return Err(TransportFailure::Integrity);
    }
    let mut matches = deployment
        .spec
        .template
        .spec
        .containers
        .iter()
        .filter(|container| container.name == profile.kubernetes.container);
    let container = matches.next().ok_or(TransportFailure::Integrity)?;
    if matches.next().is_some() {
        return Err(TransportFailure::Integrity);
    }
    let expected_prefix = format!("{}@", profile.ecr_image_repository());
    let digest_text = container
        .image
        .strip_prefix(&expected_prefix)
        .ok_or(TransportFailure::Integrity)?;
    let current_image_digest =
        Digest32::from_str(digest_text).map_err(|_| TransportFailure::Integrity)?;
    if current_image_digest.to_string() != digest_text {
        return Err(TransportFailure::Integrity);
    }
    let projection = TargetProjection {
        api_version: &deployment.api_version,
        kind: &deployment.kind,
        namespace: profile.kubernetes.namespace.as_str(),
        name: &deployment.metadata.name,
        uid: &deployment.metadata.uid,
        resource_version: &deployment.metadata.resource_version,
        container: &container.name,
        image: &container.image,
    };
    let encoded = serde_json::to_vec(&projection).map_err(|_| TransportFailure::Integrity)?;
    Ok(TargetPrestate {
        cluster_identity: cluster.cluster_identity.clone(),
        cluster_endpoint: cluster.cluster_endpoint.clone(),
        cluster_ca_hash: cluster.cluster_ca_hash,
        deployment_uid,
        resource_version: deployment.metadata.resource_version.clone(),
        current_image_digest,
        projection_hash: Digest32::sha256(&encoded),
        observed_at: trusted_now,
        evidence_reference: format!(
            "https://{}{}",
            cluster.endpoint_authority,
            kubernetes_path(profile)
        ),
    })
}

fn kubernetes_path(profile: &PreflightProfile) -> String {
    let mut value = String::new();
    let _ = write!(
        value,
        "/apis/apps/v1/namespaces/{}/deployments/{}",
        profile.kubernetes.namespace, profile.kubernetes.deployment
    );
    value
}

fn logical_github_path(profile: &PreflightProfile, suffix: &str) -> String {
    let mut value = profile.github.api_base_path.clone();
    if value == "/" {
        value.clear();
    }
    value.push_str(suffix);
    value
}

fn normalized_response(
    value: &serde_json::Value,
) -> Result<AuthenticatedJsonResponse, TransportFailure> {
    let body = serde_json::to_vec(value).map_err(|_| TransportFailure::Integrity)?;
    Ok(AuthenticatedJsonResponse::new(
        200,
        ResponseMediaType::Json,
        body,
    ))
}

fn require_provider_json(response: HttpResponse) -> Result<HttpResponse, TransportFailure> {
    match response.status {
        200 => {}
        401 | 403 => return Err(TransportFailure::Authentication),
        429 | 500..=599 => return Err(TransportFailure::Unavailable),
        _ => return Err(TransportFailure::Integrity),
    }
    let media_type = response
        .content_type
        .as_deref()
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if media_type != Some("application/json")
        && media_type != Some("application/vnd.github+json")
        && media_type != Some("application/x-amz-json-1.1")
    {
        return Err(TransportFailure::Integrity);
    }
    Ok(response)
}

fn parse_provider_json<T: for<'de> Deserialize<'de>>(
    response: &HttpResponse,
) -> Result<T, TransportFailure> {
    serde_json::from_slice(&response.body).map_err(|_| TransportFailure::Integrity)
}

fn evidence_id(domain: &[u8], request_id: Uuid, sequence: u64, material: &[u8]) -> Uuid {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(request_id.as_bytes());
    hash.update(sequence.to_be_bytes());
    hash.update(material);
    let digest = hash.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    if bytes == [0; 16] {
        bytes[15] = 1;
    }
    Uuid::from_bytes(bytes)
}

fn eks_authority(region: &str) -> String {
    format!("eks.{region}.amazonaws.com")
}

fn canonical_eks_cluster_endpoint(
    value: &str,
    expected_endpoint: Option<&str>,
) -> Result<String, TransportFailure> {
    if value.len() > 512 || value.trim() != value || value.chars().any(char::is_control) {
        return Err(TransportFailure::Integrity);
    }
    let authority = value
        .strip_prefix("https://")
        .ok_or(TransportFailure::Integrity)?;
    if authority.is_empty()
        || authority.contains(['/', ':', '@', '?', '#'])
        || !authority
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return Err(TransportFailure::Integrity);
    }
    let canonical = format!("https://{}", authority.to_ascii_lowercase());
    if expected_endpoint.is_some_and(|expected| canonical != expected) {
        return Err(TransportFailure::Integrity);
    }
    Ok(canonical)
}

fn decode_eks_certificate_authority(value: &str) -> Result<Vec<Vec<u8>>, TransportFailure> {
    if value.is_empty() || value.len() > MAX_EKS_CA_DATA_BYTES {
        return Err(TransportFailure::Integrity);
    }
    let pem = STANDARD
        .decode(value.as_bytes())
        .map_err(|_| TransportFailure::Integrity)?;
    if STANDARD.encode(&pem) != value || pem.is_empty() || pem.len() > MAX_EKS_CA_DATA_BYTES {
        return Err(TransportFailure::Integrity);
    }
    strict_pem_certificates(&pem)
}

fn strict_pem_certificates(pem: &[u8]) -> Result<Vec<Vec<u8>>, TransportFailure> {
    let text = std::str::from_utf8(pem).map_err(|_| TransportFailure::Integrity)?;
    let normalized = text.replace("\r\n", "\n");
    if normalized.contains('\r') {
        return Err(TransportFailure::Integrity);
    }
    let content = normalized.strip_suffix('\n').unwrap_or(&normalized);
    if content.is_empty() || content.ends_with('\n') {
        return Err(TransportFailure::Integrity);
    }
    let mut lines = content.split('\n');
    let mut certificates = Vec::new();
    while let Some(begin) = lines.next() {
        if begin != "-----BEGIN CERTIFICATE-----" || certificates.len() >= MAX_EKS_CA_CERTIFICATES {
            return Err(TransportFailure::Integrity);
        }
        let mut encoded = String::new();
        loop {
            let line = lines.next().ok_or(TransportFailure::Integrity)?;
            if line == "-----END CERTIFICATE-----" {
                break;
            }
            if line.is_empty()
                || line.len() > 128
                || !line
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
                || encoded.len().saturating_add(line.len()) > MAX_EKS_CA_DATA_BYTES
            {
                return Err(TransportFailure::Integrity);
            }
            encoded.push_str(line);
        }
        let certificate = STANDARD
            .decode(encoded.as_bytes())
            .map_err(|_| TransportFailure::Integrity)?;
        if certificate.is_empty()
            || certificate.len() > 128 * 1024
            || STANDARD.encode(&certificate) != encoded
        {
            return Err(TransportFailure::Integrity);
        }
        certificates.push(certificate);
    }
    if certificates.is_empty() {
        return Err(TransportFailure::Integrity);
    }
    Ok(certificates)
}

fn eks_discovery_commitment(
    transport_identity_hash: Digest32,
    cluster_identity: &str,
    cluster_endpoint: &str,
    cluster_ca_hash: Digest32,
) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(b"accordlock:v1:eks-cluster-discovery\0");
    hash.update(transport_identity_hash.as_bytes());
    for value in [cluster_identity.as_bytes(), cluster_endpoint.as_bytes()] {
        hash.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        hash.update(value);
    }
    hash.update(cluster_ca_hash.as_bytes());
    Digest32::from_bytes(hash.finalize().into())
}

fn valid_commit(value: &str) -> bool {
    (value.len() == 40 || value.len() == 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sigv4_headers(
    credentials: &CredentialBundle,
    authority: &str,
    region: &str,
    target: &str,
    body: &[u8],
    unix_seconds: i64,
) -> Result<SecretHeaders, TransportFailure> {
    let access_key = std::str::from_utf8(credentials.aws_access_key_id.expose())
        .map_err(|_| TransportFailure::Authentication)?;
    let secret_key = credentials.aws_secret_access_key.expose();
    let (amz_date, date) = aws_date(unix_seconds)?;
    let payload_hash = hex::encode(Sha256::digest(body));
    let mut canonical_headers = Zeroizing::new(format!(
        "content-type:application/x-amz-json-1.1\nhost:{authority}\nx-amz-date:{amz_date}\n"
    ));
    let mut signed_headers = "content-type;host;x-amz-date".to_owned();
    let session_token = credentials
        .aws_session_token
        .as_ref()
        .map(|value| std::str::from_utf8(value.expose()))
        .transpose()
        .map_err(|_| TransportFailure::Authentication)?;
    if let Some(token) = session_token {
        let _ = writeln!(&mut *canonical_headers, "x-amz-security-token:{token}");
        signed_headers.push_str(";x-amz-security-token");
    }
    let _ = writeln!(&mut *canonical_headers, "x-amz-target:{target}");
    signed_headers.push_str(";x-amz-target");
    let canonical_request = Zeroizing::new(format!(
        "POST\n/\n\n{}\n{signed_headers}\n{payload_hash}",
        canonical_headers.as_str()
    ));
    let scope = format!("{date}/{region}/ecr/aws4_request");
    let string_to_sign = Zeroizing::new(format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    ));
    let mut prefixed = Zeroizing::new(Vec::with_capacity(4 + secret_key.len()));
    prefixed.extend_from_slice(b"AWS4");
    prefixed.extend_from_slice(secret_key);
    let k_date = Zeroizing::new(hmac(&prefixed, date.as_bytes())?);
    let k_region = Zeroizing::new(hmac(k_date.as_ref(), region.as_bytes())?);
    let k_service = Zeroizing::new(hmac(k_region.as_ref(), b"ecr")?);
    let k_signing = Zeroizing::new(hmac(k_service.as_ref(), b"aws4_request")?);
    let signature = Zeroizing::new(hex::encode(hmac(
        k_signing.as_ref(),
        string_to_sign.as_bytes(),
    )?));
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={}",
        signature.as_str()
    );
    let mut headers = vec![
        ("authorization", authorization),
        ("content-type", "application/x-amz-json-1.1".to_owned()),
        ("user-agent", USER_AGENT.to_owned()),
        ("x-amz-date", amz_date),
        ("x-amz-target", target.to_owned()),
    ];
    if let Some(token) = session_token {
        headers.push(("x-amz-security-token", token.to_owned()));
    }
    Ok(SecretHeaders(headers))
}

fn eks_sigv4_headers(
    credentials: AwsCredentialRef<'_>,
    authority: &str,
    region: &str,
    path: &str,
    unix_seconds: i64,
) -> Result<SecretHeaders, TransportFailure> {
    if !path.starts_with("/clusters/")
        || path.len() > 256
        || !path.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'/' | b'-')
        })
    {
        return Err(TransportFailure::Route);
    }
    let access_key = std::str::from_utf8(credentials.access_key_id)
        .map_err(|_| TransportFailure::Authentication)?;
    let secret_key = credentials.secret_access_key;
    let (amz_date, date) = aws_date(unix_seconds)?;
    let mut canonical_headers =
        Zeroizing::new(format!("host:{authority}\nx-amz-date:{amz_date}\n"));
    let mut signed_headers = "host;x-amz-date".to_owned();
    let session_token = credentials
        .session_token
        .map(std::str::from_utf8)
        .transpose()
        .map_err(|_| TransportFailure::Authentication)?;
    if let Some(token) = session_token {
        let _ = writeln!(&mut *canonical_headers, "x-amz-security-token:{token}");
        signed_headers.push_str(";x-amz-security-token");
    }
    let payload_hash = hex::encode(Sha256::digest([]));
    let canonical_request = Zeroizing::new(format!(
        "GET\n{path}\n\n{}\n{signed_headers}\n{payload_hash}",
        canonical_headers.as_str()
    ));
    let scope = format!("{date}/{region}/eks/aws4_request");
    let string_to_sign = Zeroizing::new(format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    ));
    let mut prefixed = Zeroizing::new(Vec::with_capacity(4 + secret_key.len()));
    prefixed.extend_from_slice(b"AWS4");
    prefixed.extend_from_slice(secret_key);
    let k_date = Zeroizing::new(hmac(&prefixed, date.as_bytes())?);
    let k_region = Zeroizing::new(hmac(k_date.as_ref(), region.as_bytes())?);
    let k_service = Zeroizing::new(hmac(k_region.as_ref(), b"eks")?);
    let k_signing = Zeroizing::new(hmac(k_service.as_ref(), b"aws4_request")?);
    let signature = Zeroizing::new(hex::encode(hmac(
        k_signing.as_ref(),
        string_to_sign.as_bytes(),
    )?));
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={}",
        signature.as_str()
    );
    let mut headers = vec![
        ("authorization", authorization),
        ("user-agent", USER_AGENT.to_owned()),
        ("x-amz-date", amz_date),
    ];
    if let Some(token) = session_token {
        headers.push(("x-amz-security-token", token.to_owned()));
    }
    Ok(SecretHeaders(headers))
}

fn eks_kubernetes_bearer_token(
    credentials: &CredentialBundle,
    region: &str,
    cluster_name: &str,
    unix_seconds: i64,
) -> Result<String, TransportFailure> {
    if cluster_name.is_empty()
        || cluster_name.len() > 63
        || !cluster_name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(TransportFailure::Authentication);
    }
    let access_key = std::str::from_utf8(credentials.aws_access_key_id.expose())
        .map_err(|_| TransportFailure::Authentication)?;
    let secret_key = credentials.aws_secret_access_key.expose();
    let (amz_date, date) = aws_date(unix_seconds)?;
    let authority = format!("sts.{region}.amazonaws.com");
    let scope = format!("{date}/{region}/sts/aws4_request");
    let mut canonical_query = format!(
        "Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={}&X-Amz-Date={amz_date}&X-Amz-Expires=60",
        percent_encode(format!("{access_key}/{scope}").as_bytes())
    );
    let session_token = credentials
        .aws_session_token
        .as_ref()
        .map(|value| std::str::from_utf8(value.expose()))
        .transpose()
        .map_err(|_| TransportFailure::Authentication)?;
    if let Some(token) = session_token {
        let _ = write!(
            canonical_query,
            "&X-Amz-Security-Token={}",
            percent_encode(token.as_bytes())
        );
    }
    canonical_query.push_str("&X-Amz-SignedHeaders=host%3Bx-k8s-aws-id");
    let canonical_headers = format!("host:{authority}\nx-k8s-aws-id:{cluster_name}\n");
    let canonical_request = format!(
        "GET\n/\n{canonical_query}\n{canonical_headers}\nhost;x-k8s-aws-id\n{}",
        hex::encode(Sha256::digest([]))
    );
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let mut prefixed = Zeroizing::new(Vec::with_capacity(4 + secret_key.len()));
    prefixed.extend_from_slice(b"AWS4");
    prefixed.extend_from_slice(secret_key);
    let k_date = Zeroizing::new(hmac(&prefixed, date.as_bytes())?);
    let k_region = Zeroizing::new(hmac(k_date.as_ref(), region.as_bytes())?);
    let k_service = Zeroizing::new(hmac(k_region.as_ref(), b"sts")?);
    let k_signing = Zeroizing::new(hmac(k_service.as_ref(), b"aws4_request")?);
    let signature = hex::encode(hmac(k_signing.as_ref(), string_to_sign.as_bytes())?);
    let presigned_url =
        format!("https://{authority}/?{canonical_query}&X-Amz-Signature={signature}");
    Ok(format!(
        "k8s-aws-v1.{}",
        URL_SAFE_NO_PAD.encode(presigned_url.as_bytes())
    ))
}

fn percent_encode(value: &[u8]) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(*byte));
        } else {
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn hmac(key: &[u8], value: &[u8]) -> Result<[u8; 32], TransportFailure> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| TransportFailure::Integrity)?;
    mac.update(value);
    Ok(mac.finalize().into_bytes().into())
}

fn aws_date(unix_seconds: i64) -> Result<(String, String), TransportFailure> {
    if unix_seconds < 0 {
        return Err(TransportFailure::Integrity);
    }
    let days = unix_seconds.div_euclid(86_400);
    let seconds = unix_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days)?;
    let hour = seconds / 3_600;
    let minute = (seconds % 3_600) / 60;
    let second = seconds % 60;
    let short = format!("{year:04}{month:02}{day:02}");
    Ok((format!("{short}T{hour:02}{minute:02}{second:02}Z"), short))
}

fn civil_from_days(days_since_epoch: i64) -> Result<(i64, i64, i64), TransportFailure> {
    let z = days_since_epoch
        .checked_add(719_468)
        .ok_or(TransportFailure::Integrity)?;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    if !(1970..=9999).contains(&year) {
        return Err(TransportFailure::Integrity);
    }
    Ok((year, month, day))
}

#[cfg(test)]
mod eks_token_tests {
    use std::fmt::Debug;

    use base64::Engine as _;
    use serde_json::json;

    use super::{CredentialBundle, TransportFailure, URL_SAFE_NO_PAD, eks_kubernetes_bearer_token};

    fn must<T, E: Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("test fixture failed: {error:?}"))
    }

    fn credentials(session_token: Option<&str>) -> CredentialBundle {
        let mut value = json!({
            "schema_version": 1,
            "github_token": "github-test-token",
            "aws_access_key_id": "AKIATESTACCESS",
            "aws_secret_access_key": "test-secret-access-key-material",
            "runner_master_seed": URL_SAFE_NO_PAD.encode([31_u8; 32]),
            "receipt_signing_seed": URL_SAFE_NO_PAD.encode([32_u8; 32])
        });
        if let Some(token) = session_token {
            must(
                value
                    .as_object_mut()
                    .ok_or("credential fixture must be an object"),
            )
            .insert(
                "aws_session_token".to_owned(),
                serde_json::Value::String(token.to_owned()),
            );
        }
        must(serde_json::from_value(value))
    }

    fn decoded_url(token: &str) -> String {
        let encoded = must(token.strip_prefix("k8s-aws-v1.").ok_or("missing prefix"));
        must(String::from_utf8(must(URL_SAFE_NO_PAD.decode(encoded))))
    }

    #[test]
    fn eks_token_uses_canonical_query_encoding_short_expiry_and_no_padding() {
        let credentials = credentials(Some("session+token/with=reserved"));
        let token = must(eks_kubernetes_bearer_token(
            &credentials,
            "us-east-1",
            "primary",
            200,
        ));
        assert!(!token.contains('='));
        let url = decoded_url(&token);
        let query = must(url.split_once('?').map(|(_, query)| query).ok_or("query"));
        let names = query
            .split('&')
            .map(|parameter| {
                must(
                    parameter
                        .split_once('=')
                        .map(|(name, _)| name)
                        .ok_or("param"),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                "Action",
                "Version",
                "X-Amz-Algorithm",
                "X-Amz-Credential",
                "X-Amz-Date",
                "X-Amz-Expires",
                "X-Amz-Security-Token",
                "X-Amz-SignedHeaders",
                "X-Amz-Signature",
            ]
        );
        assert!(query.contains("X-Amz-Expires=60"));
        assert!(query.contains("X-Amz-SignedHeaders=host%3Bx-k8s-aws-id"));
        assert!(query.contains("X-Amz-Security-Token=session%2Btoken%2Fwith%3Dreserved"));
        assert!(query.contains(
            "X-Amz-Credential=AKIATESTACCESS%2F19700101%2Fus-east-1%2Fsts%2Faws4_request"
        ));
    }

    #[test]
    fn eks_token_signature_binds_cluster_name_session_token_and_clock() {
        let with_session = credentials(Some("test-session-token"));
        let without_session = credentials(None);
        let baseline = must(eks_kubernetes_bearer_token(
            &with_session,
            "us-east-1",
            "primary",
            200,
        ));
        let another_cluster = must(eks_kubernetes_bearer_token(
            &with_session,
            "us-east-1",
            "secondary",
            200,
        ));
        let another_second = must(eks_kubernetes_bearer_token(
            &with_session,
            "us-east-1",
            "primary",
            201,
        ));
        let no_session = must(eks_kubernetes_bearer_token(
            &without_session,
            "us-east-1",
            "primary",
            200,
        ));
        assert_ne!(baseline, another_cluster);
        assert_ne!(baseline, another_second);
        assert_ne!(baseline, no_session);
        assert!(!decoded_url(&no_session).contains("X-Amz-Security-Token"));
        assert!(matches!(
            eks_kubernetes_bearer_token(&with_session, "us-east-1", "primary", -1),
            Err(TransportFailure::Integrity)
        ));
    }

    #[test]
    fn credential_bundle_rejects_legacy_kubernetes_bearer_and_debug_redacts_secrets() {
        let legacy = json!({
            "schema_version": 1,
            "github_token": "github-test-token",
            "aws_access_key_id": "AKIATESTACCESS",
            "aws_secret_access_key": "test-secret-access-key-material",
            "aws_session_token": "test-session-token",
            "kubernetes_bearer_token": "legacy-token",
            "runner_master_seed": URL_SAFE_NO_PAD.encode([31_u8; 32]),
            "receipt_signing_seed": URL_SAFE_NO_PAD.encode([32_u8; 32])
        });
        assert!(serde_json::from_value::<CredentialBundle>(legacy).is_err());

        let credentials = credentials(Some("secret-session-value"));
        let debug = format!("{credentials:?}");
        assert!(!debug.contains("secret-session-value"));
        assert!(!debug.contains("kubernetes_bearer"));
    }
}
