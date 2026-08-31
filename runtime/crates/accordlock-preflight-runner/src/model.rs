use std::{fmt, net::SocketAddr, path::PathBuf, str::FromStr};

use accordlock_protocol::{Digest32, SignedEvaluation};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

pub const PREFLIGHT_SCHEMA_VERSION: u16 = 2;
pub const PREFLIGHT_BUILD_MARKER_SCHEMA_VERSION: u16 = 1;
pub const CREDENTIAL_SCHEMA_VERSION: u16 = 1;
pub const EKS_ENROLLMENT_SCHEMA_VERSION: u16 = 1;
pub const TRUST_RECORD_SCHEMA_VERSION: u16 = 1;
pub const MAX_REQUEST_BYTES: usize = 32 * 1024;
pub const MAX_CREDENTIAL_BYTES: usize = 128 * 1024;
pub const MAX_EKS_ENROLLMENT_INPUT_BYTES: usize = 16 * 1024;
pub const MAX_EKS_ENROLLMENT_OUTPUT_BYTES: usize = 2 * 1024;
pub const MAX_RECEIPT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_TRUST_RECORD_BYTES: usize = 64 * 1024;
pub const PREFLIGHT_PROTOCOL_VERSION: u16 = 1;

const PROFILE_HASH_DOMAIN: &[u8] = b"accordlock:v1:deployment-preflight-profile\0";
const RECEIPT_HASH_DOMAIN: &[u8] = b"accordlock:v1:deployment-preflight-receipt\0";
const RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"accordlock:v1:deployment-preflight-receipt-signature\0";
const BUILD_TRUST_DOMAIN: &[u8] = b"accordlock:v1:build-trust-record\0";
const ARTIFACT_TRUST_DOMAIN: &[u8] = b"accordlock:v1:artifact-trust-record\0";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightProfile {
    pub schema_version: u16,
    pub profile_id: Uuid,
    pub organization_id: String,
    pub environment_id: String,
    pub actor_id: String,
    pub executor_audience: String,
    pub github: GitHubProfile,
    pub ecr: EcrProfile,
    pub eks_discovery: EksDiscoveryProfile,
    pub kubernetes: KubernetesProfile,
    pub build_trust: TrustVerifierProfile,
    pub artifact_trust: TrustVerifierProfile,
    pub receipt: ReceiptVerifierProfile,
    pub evidence_ttl_seconds: i64,
    pub maximum_source_age_seconds: i64,
    pub maximum_future_skew_seconds: i64,
    pub created_at: i64,
    pub expires_at: i64,
}

impl PreflightProfile {
    /// # Errors
    /// Returns [`ModelError::InvalidProfile`] when any configured identity,
    /// endpoint, trust root, lifetime, or bound is not canonical.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.schema_version != PREFLIGHT_SCHEMA_VERSION
            || self.profile_id.is_nil()
            || !valid_text(&self.organization_id, 256)
            || !valid_text(&self.environment_id, 256)
            || !valid_text(&self.actor_id, 512)
            || !valid_text(&self.executor_audience, 512)
            || self.created_at < 0
            || self.expires_at <= self.created_at
            || !(1..=900).contains(&self.evidence_ttl_seconds)
            || !(0..=600).contains(&self.maximum_source_age_seconds)
            || self.maximum_source_age_seconds >= self.evidence_ttl_seconds
            || !(0..=60).contains(&self.maximum_future_skew_seconds)
        {
            return Err(ModelError::InvalidProfile);
        }
        self.github.validate()?;
        self.ecr.validate()?;
        self.eks_discovery.validate()?;
        self.kubernetes.validate()?;
        self.build_trust.validate()?;
        self.artifact_trust.validate()?;
        self.receipt.validate()?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when the profile is invalid or cannot be serialized.
    pub fn digest(&self) -> Result<Digest32, ModelError> {
        self.validate()?;
        let encoded = serde_json::to_vec(self).map_err(|_| ModelError::Serialization)?;
        Ok(domain_hash(PROFILE_HASH_DOMAIN, &encoded))
    }

    #[must_use]
    pub fn github_repository(&self) -> String {
        format!("{}/{}", self.github.owner, self.github.repository)
    }

    #[must_use]
    pub fn ecr_image_repository(&self) -> String {
        format!(
            "{}.dkr.ecr.{}.amazonaws.com/{}",
            self.ecr.registry_id, self.ecr.region, self.ecr.repository
        )
    }

    #[must_use]
    pub fn expected_cluster_arn(&self) -> String {
        format!(
            "arn:aws:eks:{}:{}:cluster/{}",
            self.ecr.region, self.ecr.registry_id, self.kubernetes.cluster_name
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubProfile {
    pub authority: String,
    pub api_base_path: String,
    pub socket_address: Option<SocketAddr>,
    #[serde(default)]
    pub ca_certificates_der: Vec<Base64Bytes>,
    pub owner: String,
    pub repository: String,
    pub workflow_ref: String,
    pub minimum_approvals: u16,
    pub maximum_response_bytes: usize,
}

impl GitHubProfile {
    fn validate(&self) -> Result<(), ModelError> {
        if !valid_authority(&self.authority)
            || !valid_base_path(&self.api_base_path)
            || !valid_route_segment(&self.owner)
            || !valid_route_segment(&self.repository)
            || !valid_text(&self.workflow_ref, 512)
            || self.minimum_approvals == 0
            || self.minimum_approvals > 100
            || !(2..=256 * 1024).contains(&self.maximum_response_bytes)
            || self.ca_certificates_der.len() > 16
        {
            return Err(ModelError::InvalidProfile);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcrProfile {
    pub registry_id: String,
    pub region: String,
    pub repository: String,
    pub socket_address: Option<SocketAddr>,
    #[serde(default)]
    pub ca_certificates_der: Vec<Base64Bytes>,
    pub maximum_response_bytes: usize,
}

impl EcrProfile {
    fn validate(&self) -> Result<(), ModelError> {
        if self.registry_id.len() != 12
            || !self.registry_id.bytes().all(|value| value.is_ascii_digit())
            || !valid_commercial_aws_region(&self.region)
            || !valid_ecr_repository(&self.repository)
            || !(2..=256 * 1024).contains(&self.maximum_response_bytes)
            || self.ca_certificates_der.len() > 16
        {
            return Err(ModelError::InvalidProfile);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EksDiscoveryProfile {
    pub socket_address: Option<SocketAddr>,
    #[serde(default)]
    pub ca_certificates_der: Vec<Base64Bytes>,
    pub maximum_response_bytes: usize,
}

impl EksDiscoveryProfile {
    fn validate(&self) -> Result<(), ModelError> {
        if !(2..=256 * 1024).contains(&self.maximum_response_bytes)
            || self.ca_certificates_der.len() > 16
        {
            return Err(ModelError::InvalidProfile);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesProfile {
    pub expected_endpoint: String,
    pub socket_address: Option<SocketAddr>,
    pub cluster_name: String,
    pub namespace: String,
    pub deployment: String,
    pub container: String,
    pub maximum_response_bytes: usize,
}

impl KubernetesProfile {
    fn validate(&self) -> Result<(), ModelError> {
        if !valid_https_authority_endpoint(&self.expected_endpoint)
            || !valid_dns_label(&self.cluster_name)
            || !valid_dns_label(&self.namespace)
            || !valid_dns_label(&self.deployment)
            || !valid_dns_label(&self.container)
            || !(2..=256 * 1024).contains(&self.maximum_response_bytes)
        {
            return Err(ModelError::InvalidProfile);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustVerifierProfile {
    pub key_id: String,
    pub public_key: Base64Bytes,
    pub records_directory: PathBuf,
}

impl TrustVerifierProfile {
    fn validate(&self) -> Result<(), ModelError> {
        if !valid_text(&self.key_id, 256)
            || self.public_key.0.len() != 32
            || !self.records_directory.is_absolute()
            || VerifyingKey::from_bytes(
                self.public_key
                    .0
                    .as_slice()
                    .try_into()
                    .map_err(|_| ModelError::InvalidProfile)?,
            )
            .is_err()
        {
            return Err(ModelError::InvalidProfile);
        }
        Ok(())
    }

    /// # Errors
    /// Returns an error when the configured Ed25519 public key is invalid.
    pub fn verifying_key(&self) -> Result<VerifyingKey, ModelError> {
        let bytes: [u8; 32] = self
            .public_key
            .0
            .as_slice()
            .try_into()
            .map_err(|_| ModelError::InvalidProfile)?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| ModelError::InvalidProfile)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptVerifierProfile {
    pub key_id: String,
    pub public_key: Base64Bytes,
    pub public_key_hash: Digest32,
}

impl ReceiptVerifierProfile {
    fn validate(&self) -> Result<(), ModelError> {
        if !valid_text(&self.key_id, 256) || self.public_key.0.len() != 32 {
            return Err(ModelError::InvalidProfile);
        }
        let actual = Digest32::sha256(&self.public_key.0);
        if actual != self.public_key_hash {
            return Err(ModelError::InvalidProfile);
        }
        let _: [u8; 32] = self
            .public_key
            .0
            .as_slice()
            .try_into()
            .map_err(|_| ModelError::InvalidProfile)?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when the key or its committed hash is invalid.
    pub fn verifying_key(&self) -> Result<VerifyingKey, ModelError> {
        self.validate()?;
        let bytes: [u8; 32] = self
            .public_key
            .0
            .as_slice()
            .try_into()
            .map_err(|_| ModelError::InvalidProfile)?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| ModelError::InvalidProfile)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Base64Bytes(pub Vec<u8>);

impl fmt::Debug for Base64Bytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_fmt(format_args!("Base64Bytes(<{} bytes>)", self.0.len()))
    }
}

impl Serialize for Base64Bytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Base64Bytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.len() > 256 * 1024 {
            return Err(serde::de::Error::custom("base64 value is too large"));
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(value.as_bytes())
            .map_err(serde::de::Error::custom)?;
        if URL_SAFE_NO_PAD.encode(&decoded) != value {
            return Err(serde::de::Error::custom("base64url is not canonical"));
        }
        Ok(Self(decoded))
    }
}

pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// # Errors
    /// Returns an error unless this secret contains one canonical base64url
    /// encoding of exactly 32 bytes.
    pub fn seed(&self) -> Result<[u8; 32], ModelError> {
        let encoded = std::str::from_utf8(&self.0).map_err(|_| ModelError::InvalidCredentials)?;
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .map_err(|_| ModelError::InvalidCredentials)?;
        if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
            return Err(ModelError::InvalidCredentials);
        }
        decoded
            .as_slice()
            .try_into()
            .map_err(|_| ModelError::InvalidCredentials)
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<'de> Deserialize<'de> for SecretBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.is_empty() || value.len() > 128 * 1024 {
            return Err(serde::de::Error::custom("secret has invalid length"));
        }
        Ok(Self(value.into_bytes()))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialBundle {
    pub schema_version: u16,
    pub github_token: SecretBytes,
    pub aws_access_key_id: SecretBytes,
    pub aws_secret_access_key: SecretBytes,
    pub aws_session_token: Option<SecretBytes>,
    pub runner_master_seed: SecretBytes,
    pub receipt_signing_seed: SecretBytes,
}

impl CredentialBundle {
    /// # Errors
    /// Returns an error for malformed provider secrets, seeds, or a receipt
    /// signing seed that does not match the public profile.
    pub fn validate(&self, profile: &PreflightProfile) -> Result<(), ModelError> {
        if self.schema_version != CREDENTIAL_SCHEMA_VERSION
            || !valid_secret_ascii(self.github_token.expose(), 8, 64 * 1024)
            || !valid_secret_ascii(self.aws_access_key_id.expose(), 8, 256)
            || !valid_secret_ascii(self.aws_secret_access_key.expose(), 16, 4 * 1024)
            || self
                .aws_session_token
                .as_ref()
                .is_some_and(|value| !valid_secret_ascii(value.expose(), 8, 64 * 1024))
            || self.runner_master_seed.seed().is_err()
            || self.receipt_signing_seed.seed().is_err()
        {
            return Err(ModelError::InvalidCredentials);
        }
        let key = SigningKey::from_bytes(&self.receipt_signing_seed.seed()?);
        if key.verifying_key().as_bytes() != profile.receipt.public_key.0.as_slice() {
            return Err(ModelError::CredentialBindingMismatch);
        }
        Ok(())
    }
}

/// One bounded, secret-bearing EKS enrollment request delivered only through
/// the runner's inherited standard-input handle.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EksEnrollmentEnvelope {
    pub schema_version: u16,
    pub request: EksEnrollmentRequest,
    pub credentials: EksEnrollmentCredentials,
}

impl EksEnrollmentEnvelope {
    /// # Errors
    /// Returns [`ModelError::InvalidRequest`] unless the enrollment schema,
    /// target identity, and AWS credentials are canonical and bounded.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.schema_version != EKS_ENROLLMENT_SCHEMA_VERSION {
            return Err(ModelError::InvalidRequest);
        }
        self.request.validate()?;
        self.credentials.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EksEnrollmentRequest {
    pub account_id: String,
    pub region: String,
    pub cluster_name: String,
}

impl EksEnrollmentRequest {
    /// # Errors
    /// Returns [`ModelError::InvalidRequest`] unless every AWS target field is
    /// a canonical commercial-partition identifier.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.account_id.len() != 12
            || !self.account_id.bytes().all(|value| value.is_ascii_digit())
            || !valid_commercial_aws_region(&self.region)
            || !valid_dns_label(&self.cluster_name)
        {
            return Err(ModelError::InvalidRequest);
        }
        Ok(())
    }

    #[must_use]
    pub fn expected_cluster_arn(&self) -> String {
        format!(
            "arn:aws:eks:{}:{}:cluster/{}",
            self.region, self.account_id, self.cluster_name
        )
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EksEnrollmentCredentials {
    pub aws_access_key_id: SecretBytes,
    pub aws_secret_access_key: SecretBytes,
    pub aws_session_token: Option<SecretBytes>,
}

impl EksEnrollmentCredentials {
    /// # Errors
    /// Returns [`ModelError::InvalidCredentials`] unless every AWS secret is
    /// printable ASCII and within the runner's explicit bounds.
    pub fn validate(&self) -> Result<(), ModelError> {
        if !valid_secret_ascii(self.aws_access_key_id.expose(), 8, 256)
            || !valid_secret_ascii(self.aws_secret_access_key.expose(), 16, 4 * 1024)
            || self
                .aws_session_token
                .as_ref()
                .is_some_and(|value| !valid_secret_ascii(value.expose(), 8, 8 * 1024))
        {
            return Err(ModelError::InvalidCredentials);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EksEnrollmentResult {
    pub schema_version: u16,
    pub cluster_arn: String,
    pub endpoint: String,
    pub cluster_ca_hash: Digest32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum PreflightCommand {
    RunDeploymentPreflight {
        schema_version: u16,
        check_id: Uuid,
        environment_id: String,
        environment_profile_hash: Digest32,
        pull_number: u64,
        actions_run_id: u64,
        image_digest: Digest32,
    },
}

impl PreflightCommand {
    /// # Errors
    /// Returns an error when the command is malformed or does not bind the
    /// exact environment profile.
    pub fn validate(&self, profile: &PreflightProfile) -> Result<(), ModelError> {
        let Self::RunDeploymentPreflight {
            schema_version,
            check_id,
            environment_id,
            environment_profile_hash,
            pull_number,
            actions_run_id,
            image_digest,
        } = self;
        if *schema_version != PREFLIGHT_SCHEMA_VERSION
            || check_id.is_nil()
            || environment_id != &profile.environment_id
            || environment_profile_hash != &profile.digest()?
            || *pull_number == 0
            || *actions_run_id == 0
            || *image_digest == Digest32::from_bytes([0; 32])
        {
            return Err(ModelError::InvalidRequest);
        }
        Ok(())
    }

    #[must_use]
    pub const fn check_id(&self) -> Uuid {
        let Self::RunDeploymentPreflight { check_id, .. } = self;
        *check_id
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildTrustPayload {
    pub schema_version: u16,
    pub key_id: String,
    pub repository: String,
    pub workflow_ref: String,
    pub run_id: u64,
    pub commit_sha: String,
    pub input_manifest_root: Digest32,
    pub output_digest: Digest32,
    pub issued_at: i64,
    pub expires_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactTrustPayload {
    pub schema_version: u16,
    pub key_id: String,
    pub registry_id: String,
    pub region: String,
    pub repository_name: String,
    pub image_digest: Digest32,
    pub source_repository: String,
    pub commit_sha: String,
    pub source_run_id: u64,
    pub signature_valid: bool,
    pub quarantined: bool,
    pub issued_at: i64,
    pub expires_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTrustRecord<T> {
    pub payload: T,
    pub signature: String,
}

pub type SignedBuildTrustRecord = SignedTrustRecord<BuildTrustPayload>;
pub type SignedArtifactTrustRecord = SignedTrustRecord<ArtifactTrustPayload>;

impl SignedBuildTrustRecord {
    /// # Errors
    /// Returns an error when the record, signature, time window, or requested
    /// build bindings do not match the profile.
    pub fn verify(
        &self,
        profile: &PreflightProfile,
        run_id: u64,
        digest: Digest32,
        now: i64,
    ) -> Result<(), ModelError> {
        let payload = &self.payload;
        if payload.schema_version != TRUST_RECORD_SCHEMA_VERSION
            || payload.key_id != profile.build_trust.key_id
            || payload.repository != profile.github_repository()
            || payload.workflow_ref != profile.github.workflow_ref
            || payload.run_id != run_id
            || payload.output_digest != digest
            || !valid_commit(&payload.commit_sha)
            || payload.input_manifest_root == Digest32::from_bytes([0; 32])
            || now < payload.issued_at
            || now >= payload.expires_at
        {
            return Err(ModelError::InvalidTrustRecord);
        }
        verify_record(
            BUILD_TRUST_DOMAIN,
            payload,
            &self.signature,
            &profile.build_trust.verifying_key()?,
        )
    }
}

impl SignedArtifactTrustRecord {
    /// # Errors
    /// Returns an error when the record, signature, time window, or requested
    /// artifact bindings do not match the profile.
    pub fn verify(
        &self,
        profile: &PreflightProfile,
        digest: Digest32,
        now: i64,
    ) -> Result<(), ModelError> {
        let payload = &self.payload;
        if payload.schema_version != TRUST_RECORD_SCHEMA_VERSION
            || payload.key_id != profile.artifact_trust.key_id
            || payload.registry_id != profile.ecr.registry_id
            || payload.region != profile.ecr.region
            || payload.repository_name != profile.ecr.repository
            || payload.image_digest != digest
            || payload.source_repository != profile.github_repository()
            || !valid_commit(&payload.commit_sha)
            || payload.source_run_id == 0
            || now < payload.issued_at
            || now >= payload.expires_at
        {
            return Err(ModelError::InvalidTrustRecord);
        }
        verify_record(
            ARTIFACT_TRUST_DOMAIN,
            payload,
            &self.signature,
            &profile.artifact_trust.verifying_key()?,
        )
    }
}

/// Signs a build trust payload with the configured Ed25519 authority.
///
/// # Errors
/// Returns an error if the payload cannot be serialized canonically.
pub fn sign_build_trust_record(
    payload: BuildTrustPayload,
    seed: [u8; 32],
) -> Result<SignedBuildTrustRecord, ModelError> {
    Ok(SignedTrustRecord {
        signature: sign_record(BUILD_TRUST_DOMAIN, &payload, seed)?,
        payload,
    })
}

/// Signs an artifact trust payload with the configured Ed25519 authority.
///
/// # Errors
/// Returns an error if the payload cannot be serialized canonically.
pub fn sign_artifact_trust_record(
    payload: ArtifactTrustPayload,
    seed: [u8; 32],
) -> Result<SignedArtifactTrustRecord, ModelError> {
    Ok(SignedTrustRecord {
        signature: sign_record(ARTIFACT_TRUST_DOMAIN, &payload, seed)?,
        payload,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PreflightOutcome {
    Passed,
    Blocked,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CheckKind {
    CodeReview,
    Build,
    Image,
    Target,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CheckStatus {
    Passed,
    Blocked,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Effect {
    None,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateReceipt {
    pub repository: String,
    pub pull_number: u64,
    pub commit_sha: String,
    pub workflow_ref: String,
    pub actions_run_id: u64,
    pub ecr_repository: String,
    pub image_digest: Digest32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetReceipt {
    pub cluster_identity: String,
    pub cluster_endpoint: String,
    pub cluster_ca_hash: Digest32,
    pub namespace: String,
    pub deployment: String,
    pub deployment_uid: String,
    pub resource_version: String,
    pub container: String,
    pub observed_image_digest: Digest32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckReceipt {
    pub kind: CheckKind,
    pub status: CheckStatus,
    pub summary: String,
    pub reason_code: Option<String>,
    pub observed_at: Option<i64>,
    pub freshness_seconds: Option<i64>,
    pub evidence_reference: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedPreflightReceipt {
    pub schema_version: u16,
    pub check_id: Uuid,
    pub request_id: Uuid,
    pub environment_id: String,
    pub environment_profile_hash: Digest32,
    pub runner_id: Uuid,
    pub runner_registration_hash: Digest32,
    pub dispatch_hash: Digest32,
    pub policy_decision_hash: Option<Digest32>,
    pub outcome: PreflightOutcome,
    pub reason_codes: Vec<String>,
    pub candidate: CandidateReceipt,
    pub target: TargetReceipt,
    pub checks: Vec<CheckReceipt>,
    pub evidence_root: Option<Digest32>,
    pub evaluation_attestation: Option<SignedEvaluation>,
    pub started_at: i64,
    pub completed_at: i64,
    pub valid_until: Option<i64>,
    pub effect: Effect,
    pub deployment_performed: bool,
}

impl UnsignedPreflightReceipt {
    /// # Errors
    /// Returns an error when required bindings, check ordering, outcome
    /// evidence, or the read-only effect declaration are invalid.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.schema_version != PREFLIGHT_SCHEMA_VERSION
            || self.check_id.is_nil()
            || self.request_id.is_nil()
            || !valid_text(&self.environment_id, 256)
            || self.runner_id.is_nil()
            || self.environment_profile_hash == Digest32::from_bytes([0; 32])
            || self.runner_registration_hash == Digest32::from_bytes([0; 32])
            || self.dispatch_hash == Digest32::from_bytes([0; 32])
            || self.started_at < 0
            || self.completed_at < self.started_at
            || self.deployment_performed
            || self.checks.len() != 4
            || self.checks[0].kind != CheckKind::CodeReview
            || self.checks[1].kind != CheckKind::Build
            || self.checks[2].kind != CheckKind::Image
            || self.checks[3].kind != CheckKind::Target
            || !valid_commit(&self.candidate.commit_sha)
            || !valid_text(&self.target.cluster_identity, 512)
            || !valid_text(&self.target.cluster_endpoint, 512)
            || !valid_text(&self.target.namespace, 256)
            || !valid_text(&self.target.deployment, 256)
            || self.target.deployment_uid.is_empty()
            || self.target.resource_version.is_empty()
            || !valid_text(&self.target.container, 256)
            || self.reason_codes.len() > 64
            || self.reason_codes.iter().any(|value| !valid_code(value))
            || self.checks.iter().any(|check| {
                !valid_text(&check.summary, 512)
                    || check
                        .reason_code
                        .as_ref()
                        .is_some_and(|value| !valid_code(value))
                    || check
                        .evidence_reference
                        .as_ref()
                        .is_some_and(|value| !valid_text(value, 2_048))
            })
        {
            return Err(ModelError::InvalidReceipt);
        }
        match self.outcome {
            PreflightOutcome::Passed | PreflightOutcome::Blocked
                if self.policy_decision_hash.is_none()
                    || self.evidence_root.is_none()
                    || self.evaluation_attestation.is_none()
                    || !self.target.cluster_identity.starts_with("arn:aws:eks:")
                    || !self.target.cluster_endpoint.starts_with("https://")
                    || self.target.cluster_ca_hash == Digest32::from_bytes([0; 32]) =>
            {
                return Err(ModelError::InvalidReceipt);
            }
            PreflightOutcome::Indeterminate
                if self.evidence_root.is_some() || self.evaluation_attestation.is_some() =>
            {
                return Err(ModelError::InvalidReceipt);
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPreflightReceipt {
    pub payload: UnsignedPreflightReceipt,
    pub receipt_hash: Digest32,
    pub signer_key_id: String,
    pub receipt_public_key_hash: Digest32,
    pub signature: String,
}

/// Signs a validated read-only preflight receipt.
///
/// # Errors
/// Returns an error if the payload is invalid, cannot be serialized, or the
/// secret key does not match the public profile.
pub fn sign_receipt(
    payload: UnsignedPreflightReceipt,
    profile: &PreflightProfile,
    signing_seed: [u8; 32],
) -> Result<SignedPreflightReceipt, ModelError> {
    payload.validate()?;
    profile.validate()?;
    let signing_key = SigningKey::from_bytes(&signing_seed);
    if signing_key.verifying_key().as_bytes() != profile.receipt.public_key.0.as_slice() {
        return Err(ModelError::CredentialBindingMismatch);
    }
    let encoded = serde_json::to_vec(&payload).map_err(|_| ModelError::Serialization)?;
    let receipt_hash = domain_hash(RECEIPT_HASH_DOMAIN, &encoded);
    let signature = signing_key.sign(&receipt_signature_message(receipt_hash));
    Ok(SignedPreflightReceipt {
        payload,
        receipt_hash,
        signer_key_id: profile.receipt.key_id.clone(),
        receipt_public_key_hash: profile.receipt.public_key_hash,
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
}

/// Verifies all receipt invariants, the canonical payload hash, and Ed25519
/// signature against the public profile.
///
/// # Errors
/// Returns an error for any malformed field, binding mismatch, or signature
/// failure.
pub fn verify_receipt(
    receipt: &SignedPreflightReceipt,
    profile: &PreflightProfile,
) -> Result<(), ModelError> {
    receipt.payload.validate()?;
    profile.validate()?;
    if receipt.signer_key_id != profile.receipt.key_id
        || receipt.receipt_public_key_hash != profile.receipt.public_key_hash
    {
        return Err(ModelError::ReceiptSignature);
    }
    let encoded = serde_json::to_vec(&receipt.payload).map_err(|_| ModelError::Serialization)?;
    let expected_hash = domain_hash(RECEIPT_HASH_DOMAIN, &encoded);
    if expected_hash
        .as_bytes()
        .ct_eq(receipt.receipt_hash.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(ModelError::ReceiptSignature);
    }
    let raw = URL_SAFE_NO_PAD
        .decode(receipt.signature.as_bytes())
        .map_err(|_| ModelError::ReceiptSignature)?;
    if URL_SAFE_NO_PAD.encode(&raw) != receipt.signature {
        return Err(ModelError::ReceiptSignature);
    }
    let signature = Signature::from_slice(&raw).map_err(|_| ModelError::ReceiptSignature)?;
    profile
        .receipt
        .verifying_key()?
        .verify_strict(&receipt_signature_message(receipt.receipt_hash), &signature)
        .map_err(|_| ModelError::ReceiptSignature)
}

/// Public build provenance emitted beside the packaged runner binary.
///
/// The desktop bundle verifier pins the executable bytes and source provenance
/// before launch. Install-specific receipt keys are provisioned separately and
/// never committed into this distributable marker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightRunnerBuildMarker {
    pub schema_version: u16,
    pub component: String,
    pub protocol_version: u16,
    pub binary_sha256: Digest32,
    pub source_commit: String,
    pub dirty: bool,
}

impl PreflightRunnerBuildMarker {
    /// # Errors
    /// Returns an error unless all binary provenance fields use the exact v1
    /// marker contract.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.schema_version != PREFLIGHT_BUILD_MARKER_SCHEMA_VERSION
            || self.component != "accordlock-preflight-runner"
            || self.protocol_version != PREFLIGHT_PROTOCOL_VERSION
            || self.binary_sha256 == Digest32::from_bytes([0; 32])
            || !valid_commit(&self.source_commit)
        {
            return Err(ModelError::InvalidBuildMarker);
        }
        Ok(())
    }
}

fn receipt_signature_message(receipt_hash: Digest32) -> Vec<u8> {
    let mut message = Vec::with_capacity(RECEIPT_SIGNATURE_DOMAIN.len() + 32);
    message.extend_from_slice(RECEIPT_SIGNATURE_DOMAIN);
    message.extend_from_slice(receipt_hash.as_bytes());
    message
}

fn sign_record<T: Serialize>(
    domain: &[u8],
    payload: &T,
    seed: [u8; 32],
) -> Result<String, ModelError> {
    let encoded = serde_json::to_vec(payload).map_err(|_| ModelError::Serialization)?;
    let hash = domain_hash(domain, &encoded);
    let signature = SigningKey::from_bytes(&seed).sign(hash.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

fn verify_record<T: Serialize>(
    domain: &[u8],
    payload: &T,
    encoded_signature: &str,
    key: &VerifyingKey,
) -> Result<(), ModelError> {
    let encoded = serde_json::to_vec(payload).map_err(|_| ModelError::Serialization)?;
    let hash = domain_hash(domain, &encoded);
    let raw = URL_SAFE_NO_PAD
        .decode(encoded_signature.as_bytes())
        .map_err(|_| ModelError::TrustRecordSignature)?;
    if URL_SAFE_NO_PAD.encode(&raw) != encoded_signature {
        return Err(ModelError::TrustRecordSignature);
    }
    let signature = Signature::from_slice(&raw).map_err(|_| ModelError::TrustRecordSignature)?;
    key.verify_strict(hash.as_bytes(), &signature)
        .map_err(|_| ModelError::TrustRecordSignature)
}

fn domain_hash(domain: &[u8], encoded: &[u8]) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(
        u64::try_from(encoded.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hash.update(encoded);
    Digest32::from_bytes(hash.finalize().into())
}

fn valid_secret_ascii(value: &[u8], minimum: usize, maximum: usize) -> bool {
    (minimum..=maximum).contains(&value.len())
        && value
            .iter()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'\r' | b'\n'))
}

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_code(value: &str) -> bool {
    valid_text(value, 128)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_commit(value: &str) -> bool {
    (value.len() == 40 || value.len() == 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_authority(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value == value.to_ascii_lowercase()
        && !value.contains(['/', '@', '?', '#', ':'])
        && value.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn valid_https_authority_endpoint(value: &str) -> bool {
    value.strip_prefix("https://").is_some_and(valid_authority)
}

fn valid_base_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.starts_with('/')
        && (value == "/" || !value.ends_with('/'))
        && !value.contains(['?', '#'])
        && !value.chars().any(char::is_control)
        && value
            .split('/')
            .all(|segment| segment != "." && segment != "..")
}

fn valid_route_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        && value != "."
        && value != ".."
}

fn valid_dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value == value.to_ascii_lowercase()
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_commercial_aws_region(value: &str) -> bool {
    let mut parts = value.split('-');
    let (Some(area), Some(location), Some(number), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    (2..=3).contains(&area.len())
        && (3..=12).contains(&location.len())
        && (1..=2).contains(&number.len())
        && area.bytes().all(|byte| byte.is_ascii_lowercase())
        && location.bytes().all(|byte| byte.is_ascii_lowercase())
        && number.bytes().all(|byte| byte.is_ascii_digit())
        && !number.starts_with('0')
        && !matches!(area, "cn")
}

fn valid_ecr_repository(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains("//")
        && value.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-')
                })
        })
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ModelError {
    #[error("preflight profile is invalid")]
    InvalidProfile,
    #[error("preflight credentials are invalid")]
    InvalidCredentials,
    #[error("credential material does not match the public profile")]
    CredentialBindingMismatch,
    #[error("preflight request is invalid")]
    InvalidRequest,
    #[error("trust record is missing or invalid")]
    InvalidTrustRecord,
    #[error("trust record signature is invalid")]
    TrustRecordSignature,
    #[error("preflight receipt is invalid")]
    InvalidReceipt,
    #[error("preflight receipt signature is invalid")]
    ReceiptSignature,
    #[error("preflight runner build marker is invalid")]
    InvalidBuildMarker,
    #[error("preflight serialization failed")]
    Serialization,
}

/// Parses one canonical `sha256:<hex>` digest.
///
/// # Errors
/// Returns an error for malformed or noncanonical text.
pub fn parse_digest(value: &str) -> Result<Digest32, ModelError> {
    let parsed = Digest32::from_str(value).map_err(|_| ModelError::InvalidRequest)?;
    if parsed.to_string() != value {
        return Err(ModelError::InvalidRequest);
    }
    Ok(parsed)
}
