use core::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

/// Current canonical schema for signed connector evidence.
///
/// Version 2 adds the originating request identifier to the signed assertion.
/// Version-1 evidence is intentionally not accepted as version 2.
pub const EVIDENCE_ASSERTION_SCHEMA_VERSION: u16 = 2;
/// Domain of the evidence-set commitment over version-2 assertions.
pub const EVIDENCE_ROOT_DOMAIN: &str = "accordlock:v2:evidence-root";
/// Current canonical schema for kernel evaluation attestations.
///
/// Version 2 is the first evaluation profile that requires request-bound
/// version-2 evidence assertions.
pub const EVALUATION_ATTESTATION_SCHEMA_VERSION: u16 = 2;
pub const EVALUATION_DOMAIN: &str = "accordlock:v2:evaluation-attestation";
pub const EXECUTION_AUTHORIZATION_DOMAIN: &str = "accordlock:v2:cloud-execution-authorization";
pub const EXECUTION_AUTHORIZATION_SCHEMA_VERSION: u16 = 2;
/// Canonical profile marker embedded in every v2 execution-authorization payload.
///
/// The marker is deliberately not caller-selectable. Durable state remains
/// responsible for enforcing the single consumption that this profile names.
pub const EXECUTION_AUTHORIZATION_SINGLE_USE_PROFILE: u8 = 1;
pub const CONSUMPTION_RECEIPT_DOMAIN: &str = "accordlock:v1:consumption-receipt";
pub const REPLAY_RESULT_DOMAIN: &str = "accordlock:v1:replay-result";
pub const MAX_IMMUTABLE_DEPENDENCY_EXPIRIES: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest32([u8; 32]);

impl Digest32 {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn sha256(bytes: &[u8]) -> Self {
        let mut value = [0_u8; 32];
        value.copy_from_slice(&Sha256::digest(bytes));
        Self(value)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", hex::encode(self.0))
    }
}

impl fmt::Display for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", hex::encode(self.0))
    }
}

impl FromStr for Digest32 {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let raw = input.strip_prefix("sha256:").unwrap_or(input);
        if raw.len() != 64 {
            return Err("digest must contain exactly 64 hexadecimal characters".to_owned());
        }
        let decoded = hex::decode(raw).map_err(|_| "digest is not hexadecimal".to_owned())?;
        let mut value = [0_u8; 32];
        value.copy_from_slice(&decoded);
        Ok(Self(value))
    }
}

impl Serialize for Digest32 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Digest32 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = String::deserialize(deserializer)?;
        let digest = Self::from_str(&input).map_err(de::Error::custom)?;
        if input != digest.to_string() {
            return Err(de::Error::custom(
                "digest must use canonical lowercase sha256:<hex> form",
            ));
        }
        Ok(digest)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityDomainState {
    pub root: Digest32,
    pub epoch: u64,
    pub activation_id: Uuid,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityVector {
    pub policy: AuthorityDomainState,
    pub registry: AuthorityDomainState,
    pub revocation: AuthorityDomainState,
    pub connector: AuthorityDomainState,
    pub resource: AuthorityDomainState,
    pub signer: AuthorityDomainState,
    pub mediation: AuthorityDomainState,
    pub grant_registry: AuthorityDomainState,
    pub office_act_registry: AuthorityDomainState,
    pub principal_registry: AuthorityDomainState,
    pub workload_build_allowlist: AuthorityDomainState,
    pub kernel_configuration: AuthorityDomainState,
}

impl AuthorityVector {
    #[must_use]
    pub fn domains(&self) -> [&AuthorityDomainState; 12] {
        [
            &self.policy,
            &self.registry,
            &self.revocation,
            &self.connector,
            &self.resource,
            &self.signer,
            &self.mediation,
            &self.grant_registry,
            &self.office_act_registry,
            &self.principal_registry,
            &self.workload_build_allowlist,
            &self.kernel_configuration,
        ]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceKind {
    Review,
    Build,
    Artifact,
    Target,
}

impl EvidenceKind {
    #[must_use]
    pub const fn domain(self) -> &'static str {
        match self {
            Self::Review => "accordlock:v2:evidence:review",
            Self::Build => "accordlock:v2:evidence:build",
            Self::Artifact => "accordlock:v2:evidence:artifact",
            Self::Target => "accordlock:v2:evidence:target",
        }
    }

    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Review => 0,
            Self::Build => 1,
            Self::Artifact => 2,
            Self::Target => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CompletenessProfile {
    DeclaredMaterials,
    HermeticInputsV1,
}

impl CompletenessProfile {
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::DeclaredMaterials => 0,
            Self::HermeticInputsV1 => 1,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum EvidencePayload {
    Review {
        repository: String,
        commit_sha: String,
        approved: bool,
        review_state_id: String,
    },
    Build {
        repository: String,
        commit_sha: String,
        workflow_ref: String,
        run_id: String,
        succeeded: bool,
        input_manifest_root: Digest32,
        completeness_profile: CompletenessProfile,
        output_digest: Digest32,
    },
    Artifact {
        repository: String,
        digest: Digest32,
        source_run_id: String,
        signature_valid: bool,
        quarantined: bool,
    },
    Target {
        cluster_identity: String,
        namespace: String,
        deployment: String,
        deployment_uid: String,
        resource_version: String,
        current_image: Digest32,
        projection_hash: Digest32,
    },
}

impl EvidencePayload {
    #[must_use]
    pub const fn kind(&self) -> EvidenceKind {
        match self {
            Self::Review { .. } => EvidenceKind::Review,
            Self::Build { .. } => EvidenceKind::Build,
            Self::Artifact { .. } => EvidenceKind::Artifact,
            Self::Target { .. } => EvidenceKind::Target,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAssertion {
    pub schema_version: u16,
    pub request_id: Uuid,
    pub evidence_id: Uuid,
    pub issuer: String,
    pub key_id: String,
    pub source_uri: String,
    pub observed_at: i64,
    pub valid_until: i64,
    pub authority: AuthorityVector,
    pub payload: EvidencePayload,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEvidence {
    pub assertion: EvidenceAssertion,
    #[serde(with = "base64_bytes")]
    pub cose_sign1: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredAttester {
    pub tenant: String,
    pub environment: String,
    pub issuer: String,
    pub key_id: String,
    #[serde(with = "base64_fixed_32")]
    pub public_key: [u8; 32],
    pub principal_id: String,
    pub base_grade: u8,
    pub status: AttesterStatus,
    pub scopes: Vec<AttesterScope>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttesterStatus {
    Active,
    Disabled,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum AttesterScope {
    Review {
        repository: String,
    },
    Build {
        repository: String,
        workflow_ref: String,
    },
    Artifact {
        image_repository: String,
    },
    Target {
        cluster_identity: String,
        namespace: String,
        deployment_uid: String,
    },
}

impl AttesterScope {
    #[must_use]
    pub const fn kind(&self) -> EvidenceKind {
        match self {
            Self::Review { .. } => EvidenceKind::Review,
            Self::Build { .. } => EvidenceKind::Build,
            Self::Artifact { .. } => EvidenceKind::Artifact,
            Self::Target { .. } => EvidenceKind::Target,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentTemplate {
    pub operation: String,
    pub environment: String,
    /// Audience of the `AccordLock` executor allowed to consume the action authorization.
    ///
    /// This is not the audience of a downstream Kubernetes service-account
    /// token. That separate value belongs to the dispatch credential profile.
    pub audience: String,
    pub repository: String,
    pub commit_sha: String,
    pub image_repository: String,
    pub image_digest: Digest32,
    pub cluster_identity: String,
    pub namespace: String,
    pub deployment: String,
    pub deployment_uid: String,
    pub container: String,
    pub container_index: u32,
    pub prior_image_digest: Digest32,
    pub resource_version: String,
    pub prior_projection_hash: Digest32,
    pub prior_transaction_annotation: Option<String>,
    pub prior_authorization_annotation: Option<String>,
    pub prior_operation_hash_annotation: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    pub policy_id: String,
    pub allowed_actors: Vec<String>,
    pub allowed_repositories: Vec<String>,
    pub allowed_image_repositories: Vec<String>,
    pub allowed_clusters: Vec<String>,
    pub allowed_namespaces: Vec<String>,
    pub minimum_review_grade: u8,
    pub minimum_build_grade: u8,
    pub maximum_evidence_age_seconds: i64,
    pub maximum_authorization_lifetime_seconds: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProposal {
    pub schema_version: u16,
    pub request_id: Uuid,
    pub tenant: String,
    pub actor: String,
    pub template: DeploymentTemplate,
}

/// Evidence delivered through the authenticated connector path.
///
/// This type is intentionally separate from [`AgentProposal`]. The public
/// proposal schema cannot carry policy, authority state, attester registries,
/// clocks, or unsigned security labels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedEvidenceSet {
    pub request_id: Uuid,
    pub evidence: Vec<SignedEvidence>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionOutcome {
    Allow,
    Deny,
}

impl DecisionOutcome {
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Allow => 1,
            Self::Deny => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReasonCode {
    Allowed,
    UnknownAction,
    ActorNotAllowed,
    RepositoryNotAllowed,
    ImageRepositoryNotAllowed,
    TargetNotAllowed,
    CallerSecurityFactRejected,
    EvidenceSignatureInvalid,
    AttesterNotRegistered,
    AttesterScopeViolation,
    EvidenceDefective,
    EvidenceStale,
    EvidenceFromFuture,
    AuthorityEpochMismatch,
    MissingReview,
    ReviewNotApproved,
    ReviewCommitMismatch,
    ReviewGradeInsufficient,
    MissingBuild,
    BuildFailed,
    BuildCommitMismatch,
    BuildGradeInsufficient,
    MissingArtifact,
    ArtifactSignatureInvalid,
    ArtifactQuarantined,
    TransformOutputMismatch,
    MissingTargetSnapshot,
    TargetIdentityMismatch,
    TargetStateMismatch,
    MalformedCommit,
    InvalidValidityWindow,
    PolicyRootMismatch,
    EvidenceRequestMismatch,
}

impl ReasonCode {
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::Allowed => 0,
            Self::UnknownAction => 1,
            Self::ActorNotAllowed => 2,
            Self::RepositoryNotAllowed => 3,
            Self::ImageRepositoryNotAllowed => 4,
            Self::TargetNotAllowed => 5,
            Self::CallerSecurityFactRejected => 6,
            Self::EvidenceSignatureInvalid => 7,
            Self::AttesterNotRegistered => 8,
            Self::AttesterScopeViolation => 9,
            Self::EvidenceDefective => 10,
            Self::EvidenceStale => 11,
            Self::EvidenceFromFuture => 12,
            Self::AuthorityEpochMismatch => 13,
            Self::MissingReview => 14,
            Self::ReviewNotApproved => 15,
            Self::ReviewCommitMismatch => 16,
            Self::ReviewGradeInsufficient => 17,
            Self::MissingBuild => 18,
            Self::BuildFailed => 19,
            Self::BuildCommitMismatch => 20,
            Self::BuildGradeInsufficient => 21,
            Self::MissingArtifact => 22,
            Self::ArtifactSignatureInvalid => 23,
            Self::ArtifactQuarantined => 24,
            Self::TransformOutputMismatch => 25,
            Self::MissingTargetSnapshot => 26,
            Self::TargetIdentityMismatch => 27,
            Self::TargetStateMismatch => 28,
            Self::MalformedCommit => 29,
            Self::InvalidValidityWindow => 30,
            Self::PolicyRootMismatch => 31,
            Self::EvidenceRequestMismatch => 32,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationAttestation {
    pub schema_version: u16,
    pub request_id: Uuid,
    pub evaluation_nonce: Uuid,
    pub tenant: String,
    pub actor: String,
    pub evaluated_at: i64,
    pub outcome: DecisionOutcome,
    pub reasons: Vec<ReasonCode>,
    pub template_hash: Digest32,
    pub evidence_root: Digest32,
    pub principals: Vec<String>,
    pub policy_root: Digest32,
    pub authority: AuthorityVector,
    pub consume_before: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEvaluation {
    pub attestation: EvaluationAttestation,
    #[serde(with = "base64_bytes")]
    pub cose_sign1: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityGrant {
    pub grant_id: Uuid,
    pub holder: String,
    pub tenant: String,
    pub operation: String,
    pub repository: String,
    /// Audience of the `AccordLock` executor authorized by this grant. This is not a
    /// downstream provider-token audience.
    pub audience: String,
    pub cluster_identity: String,
    pub namespace: String,
    pub deployment_uid: String,
    pub container: String,
    pub image_repository: String,
    pub not_before: i64,
    pub expires_at: i64,
    pub maximum_uses: u32,
}

/// Immutable, signed inputs used to derive the absolute dispatch deadline.
///
/// Every value uses integer Unix seconds. Dependency expiries are required to
/// be strictly increasing and duplicate-free by the canonical encoder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchDeadlinePolicy {
    pub max_dispatch_delay_seconds: i64,
    pub profile_hard_cap: i64,
    pub immutable_dependency_expiries: Vec<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAuthorization {
    pub schema_version: u16,
    pub authorization_id: Uuid,
    pub evaluation_nonce: Uuid,
    pub request_id: Uuid,
    pub tenant: String,
    pub holder: String,
    /// Audience of the `AccordLock` executor that may consume this authorization. It is
    /// distinct from any downstream provider credential audience.
    pub audience: String,
    pub issued_at: i64,
    pub not_before: i64,
    pub consume_before: i64,
    pub dispatch_deadline_policy: DispatchDeadlinePolicy,
    pub grant_id: Uuid,
    pub template: DeploymentTemplate,
    pub template_hash: Digest32,
    pub evidence_root: Digest32,
    pub principals: Vec<String>,
    pub policy_root: Digest32,
    pub authority: AuthorityVector,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAuthorization {
    pub authorization: ExecutionAuthorization,
    #[serde(with = "base64_bytes")]
    pub cose_sign1: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumptionReceipt {
    pub schema_version: u16,
    pub transaction_id: Uuid,
    pub authorization_id: Uuid,
    pub consumed_at: i64,
    pub dispatch_deadline: i64,
    pub authority: AuthorityVector,
    pub authorization_hash: Digest32,
}

pub mod base64_bytes {
    use crate::MAX_COSE_SIZE_BYTES;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer, de};

    /// Serializes arbitrary bytes as standard padded Base64.
    ///
    /// # Errors
    ///
    /// Returns the serializer's error if it cannot emit the string.
    pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(value))
    }

    /// Deserializes standard padded Base64 into bytes.
    ///
    /// # Errors
    ///
    /// Returns the deserializer's error when the value is not a string or is
    /// not valid standard Base64.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = String::deserialize(deserializer)?;
        let maximum_encoded_len = MAX_COSE_SIZE_BYTES.div_ceil(3) * 4;
        if input.len() > maximum_encoded_len {
            return Err(de::Error::custom(
                "Base64 COSE object exceeds the accepted profile limit",
            ));
        }
        let decoded = STANDARD.decode(&input).map_err(de::Error::custom)?;
        if decoded.len() > MAX_COSE_SIZE_BYTES {
            return Err(de::Error::custom(
                "decoded COSE object exceeds the accepted profile limit",
            ));
        }
        if STANDARD.encode(&decoded) != input {
            return Err(de::Error::custom("noncanonical Base64 encoding"));
        }
        Ok(decoded)
    }
}

mod base64_fixed_32 {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer, de};

    pub fn serialize<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = String::deserialize(deserializer)?;
        if input.len() != 44 {
            return Err(de::Error::custom(
                "Ed25519 public key must use 44-character padded Base64",
            ));
        }
        let bytes = STANDARD.decode(&input).map_err(de::Error::custom)?;
        if STANDARD.encode(&bytes) != input {
            return Err(de::Error::custom("noncanonical Base64 encoding"));
        }
        bytes
            .try_into()
            .map_err(|_| de::Error::custom("Ed25519 public key must be 32 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::Digest32;

    #[test]
    fn digest_json_requires_one_canonical_text_form() {
        let canonical = format!("\"sha256:{}\"", "ab".repeat(32));
        assert!(serde_json::from_str::<Digest32>(&canonical).is_ok());

        let unprefixed = format!("\"{}\"", "ab".repeat(32));
        assert!(serde_json::from_str::<Digest32>(&unprefixed).is_err());

        let uppercase = format!("\"sha256:{}\"", "AB".repeat(32));
        assert!(serde_json::from_str::<Digest32>(&uppercase).is_err());
    }
}
