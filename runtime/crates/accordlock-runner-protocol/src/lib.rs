//! Credential-free protocol for an `AccordLock` enterprise runner.
//!
//! The model proposes work. The trusted control plane binds that work to an
//! approved environment, conformance evaluation, resource reservation and
//! consumed single-use authorization. Only a separately enrolled execution worker can resolve
//! environment credentials and attempt the exact external effect.

#![forbid(unsafe_code)]

use accordlock_protocol::{CoseVerifier, Digest32, SigningIdentity, sign_cose, verify_cose};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub const RUNNER_PROTOCOL_SCHEMA_VERSION: u16 = 3;
pub const MAX_ID_BYTES: usize = 256;
pub const MAX_ROUTE_BYTES: usize = 1_024;
pub const MAX_CAPABILITIES: usize = 16;
pub const MAX_REGISTRATION_LIFETIME_SECONDS: i64 = 30 * 24 * 60 * 60;
pub const MAX_PROFILE_LIFETIME_SECONDS: i64 = 365 * 24 * 60 * 60;
pub const MAX_DISPATCH_LIFETIME_SECONDS: i64 = 15 * 60;
pub const MAX_EXECUTION_DURATION_SECONDS: i64 = 24 * 60 * 60;

const ENVIRONMENT_PROFILE_DOMAIN: &[u8] = b"accordlock:v3:enterprise-environment";
const RUNNER_REGISTRATION_DOMAIN: &[u8] = b"accordlock:v3:runner-registration";
pub const RUNNER_ACTION_DOMAIN: &[u8] = b"accordlock:v3:runner-action";
const RUNNER_DISPATCH_DOMAIN: &[u8] = b"accordlock:v3:runner-dispatch";
const RUNNER_EXECUTION_RECORD_DOMAIN: &[u8] = b"accordlock:v3:runner-execution-record";
const ACTION_APPROVAL_PAYLOAD_DOMAIN: &[u8] = b"accordlock:v3:action-approval-payload";
const ACTION_APPROVAL_SIGNATURE_DOMAIN: &str = "accordlock:v3:action-approval-signature";
const ACTION_APPROVAL_AUTHORITY_DOMAIN: &[u8] = b"accordlock:v3:action-approval-authority";
const SIGNED_ACTION_APPROVAL_DOMAIN: &[u8] = b"accordlock:v3:signed-action-approval";
pub const ACTION_APPROVAL_SCHEMA_VERSION: u16 = 3;
pub const MAX_ACTION_APPROVAL_LIFETIME_SECONDS: i64 = 15 * 60;
pub const MAX_ACTION_APPROVAL_SIGNATURE_BYTES: usize = 128 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalDecision {
    Approved,
}

/// Exact, action-specific statement signed by the trusted human-approval plane.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionApprovalAttestation {
    pub schema_version: u16,
    pub approval_id: Uuid,
    pub task_id: Uuid,
    pub task_hash: Digest32,
    pub session_id: String,
    pub principal_id: String,
    pub approver_id: String,
    pub runner_id: Uuid,
    pub environment_profile_hash: Digest32,
    pub policy_decision_hash: Digest32,
    pub action_hash: Digest32,
    pub authorization_id: Uuid,
    pub authorization_hash: Digest32,
    pub authorization_evidence_root: Digest32,
    pub decision: ApprovalDecision,
    pub issued_at: i64,
    pub expires_at: i64,
    pub key_id: String,
}

impl ActionApprovalAttestation {
    /// Validates bounded canonical fields without accepting the statement as
    /// authentic.
    ///
    /// # Errors
    ///
    /// Rejects malformed identifiers, commitments or lifetime.
    pub fn validate(&self) -> Result<(), ActionApprovalError> {
        if self.schema_version != ACTION_APPROVAL_SCHEMA_VERSION {
            return Err(ActionApprovalError::Malformed);
        }
        for value in [
            self.approval_id,
            self.task_id,
            self.runner_id,
            self.authorization_id,
        ] {
            if value.is_nil() {
                return Err(ActionApprovalError::Malformed);
            }
        }
        for value in [
            &self.session_id,
            &self.principal_id,
            &self.approver_id,
            &self.key_id,
        ] {
            if value.is_empty()
                || value.len() > MAX_ID_BYTES
                || value.trim() != value
                || value.chars().any(char::is_control)
            {
                return Err(ActionApprovalError::Malformed);
            }
        }
        for digest in [
            self.task_hash,
            self.environment_profile_hash,
            self.policy_decision_hash,
            self.action_hash,
            self.authorization_hash,
            self.authorization_evidence_root,
        ] {
            if digest == Digest32::from_bytes([0; 32]) {
                return Err(ActionApprovalError::Malformed);
            }
        }
        if self.issued_at < 0
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > MAX_ACTION_APPROVAL_LIFETIME_SECONDS
        {
            return Err(ActionApprovalError::Malformed);
        }
        Ok(())
    }

    fn canonical_payload(&self) -> Result<Vec<u8>, ActionApprovalError> {
        self.validate()?;
        let mut payload = Vec::with_capacity(768);
        append_approval_bytes(&mut payload, ACTION_APPROVAL_PAYLOAD_DOMAIN)?;
        payload.extend_from_slice(&self.schema_version.to_be_bytes());
        payload.extend_from_slice(self.approval_id.as_bytes());
        payload.extend_from_slice(self.task_id.as_bytes());
        payload.extend_from_slice(self.task_hash.as_bytes());
        append_approval_bytes(&mut payload, self.session_id.as_bytes())?;
        append_approval_bytes(&mut payload, self.principal_id.as_bytes())?;
        append_approval_bytes(&mut payload, self.approver_id.as_bytes())?;
        payload.extend_from_slice(self.runner_id.as_bytes());
        payload.extend_from_slice(self.environment_profile_hash.as_bytes());
        payload.extend_from_slice(self.policy_decision_hash.as_bytes());
        payload.extend_from_slice(self.action_hash.as_bytes());
        payload.extend_from_slice(self.authorization_id.as_bytes());
        payload.extend_from_slice(self.authorization_hash.as_bytes());
        payload.extend_from_slice(self.authorization_evidence_root.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&self.issued_at.to_be_bytes());
        payload.extend_from_slice(&self.expires_at.to_be_bytes());
        append_approval_bytes(&mut payload, self.key_id.as_bytes())?;
        Ok(payload)
    }
}

/// Serializable signed proof. Possession alone is not verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedActionApproval {
    pub attestation: ActionApprovalAttestation,
    pub cose_sign1: Vec<u8>,
}

impl SignedActionApproval {
    /// Signs one canonical approval statement with an Ed25519 COSE identity.
    ///
    /// # Errors
    ///
    /// Rejects malformed statements, key substitution or signing failure.
    pub fn sign(
        attestation: ActionApprovalAttestation,
        signer: &SigningIdentity,
    ) -> Result<Self, ActionApprovalError> {
        if attestation.key_id != signer.key_id() {
            return Err(ActionApprovalError::KeyMismatch);
        }
        let payload = attestation.canonical_payload()?;
        let cose_sign1 = sign_cose(&payload, ACTION_APPROVAL_SIGNATURE_DOMAIN, signer)
            .map_err(|_| ActionApprovalError::InvalidSignature)?;
        Ok(Self {
            attestation,
            cose_sign1,
        })
    }

    /// Returns the commitment included in a runner dispatch and replay set.
    ///
    /// # Errors
    ///
    /// Rejects malformed or overlarge signed objects.
    pub fn digest(&self) -> Result<Digest32, ActionApprovalError> {
        let payload = self.attestation.canonical_payload()?;
        if self.cose_sign1.is_empty() || self.cose_sign1.len() > MAX_ACTION_APPROVAL_SIGNATURE_BYTES
        {
            return Err(ActionApprovalError::Malformed);
        }
        let mut value = Vec::with_capacity(payload.len() + self.cose_sign1.len() + 64);
        append_approval_bytes(&mut value, SIGNED_ACTION_APPROVAL_DOMAIN)?;
        append_approval_bytes(&mut value, &payload)?;
        append_approval_bytes(&mut value, &self.cose_sign1)?;
        Ok(Digest32::sha256(&value))
    }

    /// Verifies signature, freshness and every action-specific binding.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed, forged, stale or substituted approval proof.
    pub fn verify(
        &self,
        verifier: &CoseVerifier,
        expected: &ExpectedActionApprovalBindings<'_>,
        trusted_now: i64,
    ) -> Result<VerifiedActionApproval, ActionApprovalError> {
        let payload = self.attestation.canonical_payload()?;
        if self.cose_sign1.is_empty()
            || self.cose_sign1.len() > MAX_ACTION_APPROVAL_SIGNATURE_BYTES
            || self.attestation.key_id != verifier.key_id()
        {
            return Err(ActionApprovalError::KeyMismatch);
        }
        let verified_payload =
            verify_cose(&self.cose_sign1, ACTION_APPROVAL_SIGNATURE_DOMAIN, verifier)
                .map_err(|_| ActionApprovalError::InvalidSignature)?;
        if verified_payload != payload {
            return Err(ActionApprovalError::PayloadMismatch);
        }
        if trusted_now < self.attestation.issued_at || trusted_now >= self.attestation.expires_at {
            return Err(ActionApprovalError::NotCurrent);
        }
        if self.attestation.task_id != expected.task_id
            || self.attestation.task_hash != expected.task_hash
            || self.attestation.session_id != expected.session_id
            || self.attestation.principal_id != expected.principal_id
            || self.attestation.runner_id != expected.runner_id
            || self.attestation.environment_profile_hash != expected.environment_profile_hash
            || self.attestation.policy_decision_hash != expected.policy_decision_hash
            || self.attestation.action_hash != expected.action_hash
            || self.attestation.authorization_id != expected.authorization_id
            || self.attestation.authorization_hash != expected.authorization_hash
            || self.attestation.authorization_evidence_root != expected.authorization_evidence_root
            || self.attestation.decision != ApprovalDecision::Approved
        {
            return Err(ActionApprovalError::BindingMismatch);
        }
        Ok(VerifiedActionApproval {
            attestation: self.attestation.clone(),
            signed_hash: self.digest()?,
            authority_hash: action_approval_authority_commitment(verifier),
        })
    }
}

/// Exact trusted values against which a signed approval is verified.
#[derive(Clone, Copy, Debug)]
pub struct ExpectedActionApprovalBindings<'a> {
    pub task_id: Uuid,
    pub task_hash: Digest32,
    pub session_id: &'a str,
    pub principal_id: &'a str,
    pub runner_id: Uuid,
    pub environment_profile_hash: Digest32,
    pub policy_decision_hash: Digest32,
    pub action_hash: Digest32,
    pub authorization_id: Uuid,
    pub authorization_hash: Digest32,
    pub authorization_evidence_root: Digest32,
}

/// Non-serializable proof that signature, freshness and bindings were checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedActionApproval {
    attestation: ActionApprovalAttestation,
    signed_hash: Digest32,
    authority_hash: Digest32,
}

impl VerifiedActionApproval {
    #[must_use]
    pub const fn signed_hash(&self) -> Digest32 {
        self.signed_hash
    }

    #[must_use]
    pub const fn authorization_evidence_root(&self) -> Digest32 {
        self.attestation.authorization_evidence_root
    }

    /// Returns the exact verifier-authority commitment which established this
    /// capability.
    #[must_use]
    pub const fn authority_hash(&self) -> Digest32 {
        self.authority_hash
    }

    /// Returns the signed instant after which this approval is not current.
    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.attestation.expires_at
    }
}

#[derive(Debug, Error)]
pub enum ActionApprovalError {
    #[error("human approval proof is malformed")]
    Malformed,
    #[error("human approval signing key does not match the trusted authority")]
    KeyMismatch,
    #[error("human approval signature is invalid")]
    InvalidSignature,
    #[error("human approval signed payload is not canonical")]
    PayloadMismatch,
    #[error("human approval proof is not current")]
    NotCurrent,
    #[error("human approval proof does not bind the exact action")]
    BindingMismatch,
}

/// Commits the trusted human-approval verifier into an environment profile.
#[must_use]
pub fn action_approval_authority_commitment(verifier: &CoseVerifier) -> Digest32 {
    let mut hash = Commitment::new(ACTION_APPROVAL_AUTHORITY_DOMAIN);
    hash.text(verifier.key_id());
    hash.0.update(verifier.public_key_bytes());
    hash.finish()
}

fn append_approval_bytes(target: &mut Vec<u8>, value: &[u8]) -> Result<(), ActionApprovalError> {
    let length = u64::try_from(value.len()).map_err(|_| ActionApprovalError::Malformed)?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EnvironmentTier {
    Development,
    Staging,
    Production,
}

impl EnvironmentTier {
    const fn code(self) -> u8 {
        match self {
            Self::Development => 0,
            Self::Staging => 1,
            Self::Production => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AutonomyMode {
    Observe,
    PrepareAndAsk,
    BoundedAutomatic,
}

impl AutonomyMode {
    const fn code(self) -> u8 {
        match self {
            Self::Observe => 0,
            Self::PrepareAndAsk => 1,
            Self::BoundedAutomatic => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RunnerCapability {
    ObserveGithub,
    ObserveEcr,
    ObserveKubernetes,
    DeployEksImage,
}

impl RunnerCapability {
    const fn code(self) -> u8 {
        match self {
            Self::ObserveGithub => 0,
            Self::ObserveEcr => 1,
            Self::ObserveKubernetes => 2,
            Self::DeployEksImage => 3,
        }
    }
}

/// Immutable organization-owned environment configuration.
///
/// Connector commitments identify trusted runner-side configuration. Raw
/// credentials are deliberately not representable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseEnvironmentProfile {
    pub schema_version: u16,
    pub profile_id: Uuid,
    pub organization_id: String,
    pub environment_id: String,
    pub tier: EnvironmentTier,
    pub autonomy_mode: AutonomyMode,
    /// Present only when bounded production autonomy was separately reviewed.
    pub production_autonomy_approval_hash: Option<Digest32>,
    pub executor_audience: String,
    pub github_repository: String,
    pub github_workflow_ref: String,
    pub aws_account_id: String,
    pub aws_region: String,
    pub ecr_repository: String,
    pub eks_cluster_name: String,
    pub kubernetes_namespace: String,
    pub kubernetes_deployment: String,
    pub kubernetes_container: String,
    pub policy_hash: Digest32,
    pub policy_epoch: u64,
    pub github_connector_hash: Digest32,
    pub aws_identity_hash: Digest32,
    pub ecr_connector_hash: Digest32,
    pub kubernetes_connector_hash: Digest32,
    /// Domain-separated commitment to the trusted human-approval verifier.
    pub action_approval_authority_hash: Digest32,
    pub created_at: i64,
    pub expires_at: i64,
}

impl EnterpriseEnvironmentProfile {
    /// Validates the fixed environment and its conservative initial autonomy
    /// profile. Production automation is intentionally not enabled by this v1
    /// transport contract.
    ///
    /// # Errors
    ///
    /// Returns [`RunnerProtocolError`] when a field, commitment, lifetime, or
    /// production-autonomy approval binding is invalid.
    pub fn validate(&self) -> Result<(), RunnerProtocolError> {
        require_schema(self.schema_version)?;
        require_uuid(self.profile_id, "profile_id")?;
        validate_id(&self.organization_id, "organization_id")?;
        validate_id(&self.environment_id, "environment_id")?;
        validate_id(&self.executor_audience, "executor_audience")?;
        validate_github_repository(&self.github_repository)?;
        validate_route(&self.github_workflow_ref, "github_workflow_ref")?;
        validate_aws_account(&self.aws_account_id)?;
        validate_aws_region(&self.aws_region)?;
        validate_ecr_repository(&self.ecr_repository)?;
        validate_dns_label(&self.eks_cluster_name, "eks_cluster_name")?;
        validate_dns_label(&self.kubernetes_namespace, "kubernetes_namespace")?;
        validate_dns_label(&self.kubernetes_deployment, "kubernetes_deployment")?;
        validate_dns_label(&self.kubernetes_container, "kubernetes_container")?;
        for (label, digest) in [
            ("policy_hash", self.policy_hash),
            ("github_connector_hash", self.github_connector_hash),
            ("aws_identity_hash", self.aws_identity_hash),
            ("ecr_connector_hash", self.ecr_connector_hash),
            ("kubernetes_connector_hash", self.kubernetes_connector_hash),
            (
                "action_approval_authority_hash",
                self.action_approval_authority_hash,
            ),
        ] {
            require_digest(digest, label)?;
        }
        if self.policy_epoch == 0 {
            return Err(RunnerProtocolError::InvalidPolicyEpoch);
        }
        validate_window(
            self.created_at,
            self.expires_at,
            MAX_PROFILE_LIFETIME_SECONDS,
            "environment profile",
        )?;
        match self.production_autonomy_approval_hash {
            Some(digest) => require_digest(digest, "production_autonomy_approval_hash")?,
            None if self.tier == EnvironmentTier::Production
                && self.autonomy_mode == AutonomyMode::BoundedAutomatic =>
            {
                return Err(RunnerProtocolError::ProductionAutonomyRequiresApproval);
            }
            None => {}
        }
        Ok(())
    }

    /// Validates the profile and proves it is active at a trusted instant.
    ///
    /// The caller must supply time from the trusted control plane or runner,
    /// never from model-authored input.
    ///
    /// # Errors
    ///
    /// Returns [`RunnerProtocolError`] when the profile is malformed, not yet
    /// active, or expired.
    pub fn validate_at(&self, trusted_now: i64) -> Result<(), RunnerProtocolError> {
        self.validate()?;
        require_current(
            trusted_now,
            self.created_at,
            self.expires_at,
            "environment profile",
        )
    }

    /// Returns the domain-separated commitment to this complete profile.
    ///
    /// # Errors
    ///
    /// Returns [`RunnerProtocolError`] when the profile is invalid.
    pub fn digest(&self) -> Result<Digest32, RunnerProtocolError> {
        self.validate()?;
        let mut hash = Commitment::new(ENVIRONMENT_PROFILE_DOMAIN);
        hash.u16(self.schema_version);
        hash.uuid(self.profile_id);
        hash.text(&self.organization_id);
        hash.text(&self.environment_id);
        hash.u8(self.tier.code());
        hash.u8(self.autonomy_mode.code());
        match self.production_autonomy_approval_hash {
            Some(digest) => {
                hash.u8(1);
                hash.digest(digest);
            }
            None => hash.u8(0),
        }
        hash.text(&self.executor_audience);
        hash.text(&self.github_repository);
        hash.text(&self.github_workflow_ref);
        hash.text(&self.aws_account_id);
        hash.text(&self.aws_region);
        hash.text(&self.ecr_repository);
        hash.text(&self.eks_cluster_name);
        hash.text(&self.kubernetes_namespace);
        hash.text(&self.kubernetes_deployment);
        hash.text(&self.kubernetes_container);
        hash.digest(self.policy_hash);
        hash.u64(self.policy_epoch);
        hash.digest(self.github_connector_hash);
        hash.digest(self.aws_identity_hash);
        hash.digest(self.ecr_connector_hash);
        hash.digest(self.kubernetes_connector_hash);
        hash.digest(self.action_approval_authority_hash);
        hash.i64(self.created_at);
        hash.i64(self.expires_at);
        Ok(hash.finish())
    }

    #[must_use]
    pub fn ecr_image_repository(&self) -> String {
        format!(
            "{}.dkr.ecr.{}.amazonaws.com/{}",
            self.aws_account_id, self.aws_region, self.ecr_repository
        )
    }

    #[must_use]
    pub fn eks_cluster_identity(&self) -> String {
        format!(
            "arn:aws:eks:{}:{}:cluster/{}",
            self.aws_region, self.aws_account_id, self.eks_cluster_name
        )
    }
}

/// Short-lived runner enrollment bound to one exact environment profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerRegistration {
    pub schema_version: u16,
    pub runner_id: Uuid,
    pub organization_id: String,
    pub environment_id: String,
    pub environment_profile_hash: Digest32,
    pub runner_attestation_hash: Digest32,
    pub capabilities: Vec<RunnerCapability>,
    pub enrolled_at: i64,
    pub expires_at: i64,
}

impl RunnerRegistration {
    /// Validates one bounded, canonical runner enrollment.
    ///
    /// # Errors
    ///
    /// Returns [`RunnerProtocolError`] for malformed bindings, capabilities,
    /// or enrollment lifetime.
    pub fn validate(&self) -> Result<(), RunnerProtocolError> {
        require_schema(self.schema_version)?;
        require_uuid(self.runner_id, "runner_id")?;
        validate_id(&self.organization_id, "organization_id")?;
        validate_id(&self.environment_id, "environment_id")?;
        require_digest(self.environment_profile_hash, "environment_profile_hash")?;
        require_digest(self.runner_attestation_hash, "runner_attestation_hash")?;
        if self.capabilities.is_empty()
            || self.capabilities.len() > MAX_CAPABILITIES
            || self.capabilities.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(RunnerProtocolError::NonCanonicalCapabilities);
        }
        validate_window(
            self.enrolled_at,
            self.expires_at,
            MAX_REGISTRATION_LIFETIME_SECONDS,
            "runner registration",
        )
    }

    /// Validates the enrollment and proves it is active at a trusted instant.
    ///
    /// # Errors
    ///
    /// Returns [`RunnerProtocolError`] when the registration is malformed,
    /// not yet active, or expired.
    pub fn validate_at(&self, trusted_now: i64) -> Result<(), RunnerProtocolError> {
        self.validate()?;
        require_current(
            trusted_now,
            self.enrolled_at,
            self.expires_at,
            "runner registration",
        )
    }

    /// Returns the domain-separated registration commitment.
    ///
    /// # Errors
    ///
    /// Returns [`RunnerProtocolError`] when the registration is invalid.
    pub fn digest(&self) -> Result<Digest32, RunnerProtocolError> {
        self.validate()?;
        let mut hash = Commitment::new(RUNNER_REGISTRATION_DOMAIN);
        hash.u16(self.schema_version);
        hash.uuid(self.runner_id);
        hash.text(&self.organization_id);
        hash.text(&self.environment_id);
        hash.digest(self.environment_profile_hash);
        hash.digest(self.runner_attestation_hash);
        let capability_count = u64::try_from(self.capabilities.len())
            .map_err(|_| RunnerProtocolError::NonCanonicalCapabilities)?;
        hash.u64(capability_count);
        for capability in &self.capabilities {
            hash.u8(capability.code());
        }
        hash.i64(self.enrolled_at);
        hash.i64(self.expires_at);
        Ok(hash.finish())
    }

    #[must_use]
    pub fn authorizes(&self, capability: RunnerCapability) -> bool {
        self.capabilities.binary_search(&capability).is_ok()
    }
}

/// Exact runner operation. Mutable tags and caller-supplied credentials have
/// no representation in this schema.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum RunnerAction {
    ObserveSupplyChain {
        review_lookup_id: String,
        build_lookup_id: String,
        artifact_lookup_id: String,
        target_lookup_id: String,
    },
    DeployEksImage {
        /// Transaction identifier created by the trusted single-use
        /// consumption path. It is part of the action commitment and becomes
        /// the reserved Kubernetes transaction annotation.
        transaction_id: Uuid,
        commit_sha: String,
        image_digest: Digest32,
        deployment_uid: String,
        resource_version: String,
        container_index: u32,
        prior_image_digest: Digest32,
        prior_projection_hash: Digest32,
        prior_transaction_annotation: Option<String>,
        prior_authorization_annotation: Option<String>,
        prior_operation_hash_annotation: Option<String>,
    },
}

impl RunnerAction {
    /// Validates the exact lookup or immutable deployment action.
    ///
    /// # Errors
    ///
    /// Returns [`RunnerProtocolError`] for a malformed or no-op action.
    pub fn validate(&self) -> Result<(), RunnerProtocolError> {
        match self {
            Self::ObserveSupplyChain {
                review_lookup_id,
                build_lookup_id,
                artifact_lookup_id,
                target_lookup_id,
            } => {
                for (label, value) in [
                    ("review_lookup_id", review_lookup_id),
                    ("build_lookup_id", build_lookup_id),
                    ("artifact_lookup_id", artifact_lookup_id),
                    ("target_lookup_id", target_lookup_id),
                ] {
                    validate_route(value, label)?;
                }
            }
            Self::DeployEksImage {
                transaction_id,
                commit_sha,
                image_digest,
                deployment_uid,
                resource_version,
                container_index: _,
                prior_image_digest,
                prior_projection_hash,
                prior_transaction_annotation,
                prior_authorization_annotation,
                prior_operation_hash_annotation,
            } => {
                require_uuid(*transaction_id, "transaction_id")?;
                validate_commit_sha(commit_sha)?;
                require_digest(*image_digest, "image_digest")?;
                validate_id(deployment_uid, "deployment_uid")?;
                validate_id(resource_version, "resource_version")?;
                require_digest(*prior_image_digest, "prior_image_digest")?;
                require_digest(*prior_projection_hash, "prior_projection_hash")?;
                for (label, annotation) in [
                    ("prior_transaction_annotation", prior_transaction_annotation),
                    (
                        "prior_authorization_annotation",
                        prior_authorization_annotation,
                    ),
                    (
                        "prior_operation_hash_annotation",
                        prior_operation_hash_annotation,
                    ),
                ] {
                    if let Some(value) = annotation {
                        validate_route(value, label)?;
                    }
                }
                if image_digest == prior_image_digest {
                    return Err(RunnerProtocolError::NoopDeployment);
                }
            }
        }
        Ok(())
    }

    /// Returns the domain-separated commitment to this exact action.
    ///
    /// # Errors
    ///
    /// Returns [`RunnerProtocolError`] when the action is invalid.
    pub fn digest(&self) -> Result<Digest32, RunnerProtocolError> {
        self.validate()?;
        let mut hash = Commitment::new(RUNNER_ACTION_DOMAIN);
        self.commit(&mut hash);
        Ok(hash.finish())
    }

    const fn required_capabilities(&self) -> &'static [RunnerCapability] {
        const OBSERVE: &[RunnerCapability] = &[
            RunnerCapability::ObserveGithub,
            RunnerCapability::ObserveEcr,
            RunnerCapability::ObserveKubernetes,
        ];
        const DEPLOY: &[RunnerCapability] = &[RunnerCapability::DeployEksImage];
        match self {
            Self::ObserveSupplyChain { .. } => OBSERVE,
            Self::DeployEksImage { .. } => DEPLOY,
        }
    }

    fn commit(&self, hash: &mut Commitment) {
        match self {
            Self::ObserveSupplyChain {
                review_lookup_id,
                build_lookup_id,
                artifact_lookup_id,
                target_lookup_id,
            } => {
                hash.u8(0);
                hash.text(review_lookup_id);
                hash.text(build_lookup_id);
                hash.text(artifact_lookup_id);
                hash.text(target_lookup_id);
            }
            Self::DeployEksImage {
                transaction_id,
                commit_sha,
                image_digest,
                deployment_uid,
                resource_version,
                container_index,
                prior_image_digest,
                prior_projection_hash,
                prior_transaction_annotation,
                prior_authorization_annotation,
                prior_operation_hash_annotation,
            } => {
                hash.u8(1);
                hash.uuid(*transaction_id);
                hash.text(commit_sha);
                hash.digest(*image_digest);
                hash.text(deployment_uid);
                hash.text(resource_version);
                hash.u32(*container_index);
                hash.digest(*prior_image_digest);
                hash.digest(*prior_projection_hash);
                hash.optional_text(prior_transaction_annotation.as_deref());
                hash.optional_text(prior_authorization_annotation.as_deref());
                hash.optional_text(prior_operation_hash_annotation.as_deref());
            }
        }
    }
}

/// One exact, short-lived command delivered to a previously enrolled runner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerDispatch {
    pub schema_version: u16,
    pub dispatch_id: Uuid,
    pub task_id: Uuid,
    pub task_hash: Digest32,
    pub session_id: String,
    pub principal_id: String,
    pub runner_id: Uuid,
    pub environment_profile_hash: Digest32,
    pub runner_registration_hash: Digest32,
    pub policy_decision_hash: Digest32,
    pub resource_reservation_hash: Digest32,
    pub authorization_id: Uuid,
    pub authorization_hash: Digest32,
    /// Non-forgeable, action-specific proof from the trusted approval plane.
    pub action_approval: Option<SignedActionApproval>,
    pub action: RunnerAction,
    pub created_at: i64,
    pub expires_at: i64,
}

impl RunnerDispatch {
    /// Validates this dispatch against one exact runner registration.
    ///
    /// # Errors
    ///
    /// Returns [`RunnerProtocolError`] for any malformed value, enrollment
    /// drift, missing capability, or invalid time binding.
    pub fn validate(&self, registration: &RunnerRegistration) -> Result<(), RunnerProtocolError> {
        require_schema(self.schema_version)?;
        require_uuid(self.dispatch_id, "dispatch_id")?;
        require_uuid(self.task_id, "task_id")?;
        require_uuid(self.runner_id, "runner_id")?;
        require_uuid(self.authorization_id, "authorization_id")?;
        validate_id(&self.session_id, "session_id")?;
        validate_id(&self.principal_id, "principal_id")?;
        for (label, digest) in [
            ("task_hash", self.task_hash),
            ("environment_profile_hash", self.environment_profile_hash),
            ("runner_registration_hash", self.runner_registration_hash),
            ("policy_decision_hash", self.policy_decision_hash),
            ("resource_reservation_hash", self.resource_reservation_hash),
            ("authorization_hash", self.authorization_hash),
        ] {
            require_digest(digest, label)?;
        }
        if let Some(approval) = &self.action_approval {
            approval
                .digest()
                .map_err(|_| RunnerProtocolError::InvalidActionApproval)?;
        }
        self.action.validate()?;
        registration.validate()?;
        if self.runner_id != registration.runner_id
            || self.environment_profile_hash != registration.environment_profile_hash
            || self.runner_registration_hash != registration.digest()?
        {
            return Err(RunnerProtocolError::RunnerBindingMismatch);
        }
        if self
            .action
            .required_capabilities()
            .iter()
            .any(|capability| !registration.authorizes(*capability))
        {
            return Err(RunnerProtocolError::CapabilityNotEnrolled);
        }
        validate_window(
            self.created_at,
            self.expires_at,
            MAX_DISPATCH_LIFETIME_SECONDS,
            "runner dispatch",
        )?;
        if self.created_at < registration.enrolled_at || self.expires_at > registration.expires_at {
            return Err(RunnerProtocolError::RunnerBindingMismatch);
        }
        Ok(())
    }

    /// Validates all bindings and proves both enrollment and dispatch are
    /// active at one trusted instant.
    ///
    /// # Errors
    ///
    /// Returns [`RunnerProtocolError`] for any invalid binding or when either
    /// object is not current.
    pub fn validate_at(
        &self,
        registration: &RunnerRegistration,
        trusted_now: i64,
    ) -> Result<(), RunnerProtocolError> {
        self.validate(registration)?;
        registration.validate_at(trusted_now)?;
        require_current(
            trusted_now,
            self.created_at,
            self.expires_at,
            "runner dispatch",
        )
    }

    /// Returns the domain-separated dispatch commitment after enrollment
    /// validation.
    ///
    /// # Errors
    ///
    /// Returns [`RunnerProtocolError`] when the dispatch is invalid.
    pub fn digest(
        &self,
        registration: &RunnerRegistration,
    ) -> Result<Digest32, RunnerProtocolError> {
        self.validate(registration)?;
        let mut hash = Commitment::new(RUNNER_DISPATCH_DOMAIN);
        hash.u16(self.schema_version);
        hash.uuid(self.dispatch_id);
        hash.uuid(self.task_id);
        hash.digest(self.task_hash);
        hash.text(&self.session_id);
        hash.text(&self.principal_id);
        hash.uuid(self.runner_id);
        hash.digest(self.environment_profile_hash);
        hash.digest(self.runner_registration_hash);
        hash.digest(self.policy_decision_hash);
        hash.digest(self.resource_reservation_hash);
        hash.uuid(self.authorization_id);
        hash.digest(self.authorization_hash);
        let action_approval_hash = self
            .action_approval
            .as_ref()
            .map(SignedActionApproval::digest)
            .transpose()
            .map_err(|_| RunnerProtocolError::InvalidActionApproval)?;
        hash.optional_digest(action_approval_hash);
        self.action.commit(&mut hash);
        hash.i64(self.created_at);
        hash.i64(self.expires_at);
        Ok(hash.finish())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RunnerExecutionOutcome {
    Verified,
    Failed,
    Indeterminate,
    StoppedSafe,
}

impl RunnerExecutionOutcome {
    const fn code(self) -> u8 {
        match self {
            Self::Verified => 0,
            Self::Failed => 1,
            Self::Indeterminate => 2,
            Self::StoppedSafe => 3,
        }
    }
}

/// Credential-free evidence that a runner attempted one exact dispatch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerExecutionRecord {
    pub schema_version: u16,
    pub record_id: Uuid,
    pub runner_id: Uuid,
    pub dispatch_hash: Digest32,
    pub outcome: RunnerExecutionOutcome,
    pub prestate_hash: Digest32,
    pub poststate_hash: Option<Digest32>,
    pub evidence_root: Digest32,
    pub post_evaluation_hash: Digest32,
    pub started_at: i64,
    pub completed_at: i64,
}

impl RunnerExecutionRecord {
    /// Validates the exact runner outcome and evidence commitments.
    ///
    /// # Errors
    ///
    /// Returns [`RunnerProtocolError`] for malformed commitments, invalid
    /// time, or a verified result without an authenticated poststate.
    pub fn validate(&self) -> Result<(), RunnerProtocolError> {
        require_schema(self.schema_version)?;
        require_uuid(self.record_id, "record_id")?;
        require_uuid(self.runner_id, "runner_id")?;
        require_digest(self.dispatch_hash, "dispatch_hash")?;
        require_digest(self.prestate_hash, "prestate_hash")?;
        require_digest(self.evidence_root, "evidence_root")?;
        require_digest(self.post_evaluation_hash, "post_evaluation_hash")?;
        if let Some(poststate) = self.poststate_hash {
            require_digest(poststate, "poststate_hash")?;
        }
        if self.outcome == RunnerExecutionOutcome::Verified && self.poststate_hash.is_none() {
            return Err(RunnerProtocolError::VerifiedReceiptMissingPoststate);
        }
        validate_window(
            self.started_at,
            self.completed_at,
            MAX_EXECUTION_DURATION_SECONDS,
            "runner record",
        )
    }

    /// Returns the domain-separated record commitment.
    ///
    /// # Errors
    ///
    /// Returns [`RunnerProtocolError`] when the record is invalid.
    pub fn digest(&self) -> Result<Digest32, RunnerProtocolError> {
        self.validate()?;
        let mut hash = Commitment::new(RUNNER_EXECUTION_RECORD_DOMAIN);
        hash.u16(self.schema_version);
        hash.uuid(self.record_id);
        hash.uuid(self.runner_id);
        hash.digest(self.dispatch_hash);
        hash.u8(self.outcome.code());
        hash.digest(self.prestate_hash);
        match self.poststate_hash {
            Some(value) => {
                hash.u8(1);
                hash.digest(value);
            }
            None => hash.u8(0),
        }
        hash.digest(self.evidence_root);
        hash.digest(self.post_evaluation_hash);
        hash.i64(self.started_at);
        hash.i64(self.completed_at);
        Ok(hash.finish())
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RunnerProtocolError {
    #[error("unsupported runner protocol schema")]
    WrongSchema,
    #[error("runner protocol identifier is invalid: {0}")]
    InvalidIdentifier(&'static str),
    #[error("runner protocol route is invalid: {0}")]
    InvalidRoute(&'static str),
    #[error("runner protocol digest is empty: {0}")]
    ZeroDigest(&'static str),
    #[error("runner protocol time window is invalid: {0}")]
    InvalidWindow(&'static str),
    #[error("runner protocol object is not current: {0}")]
    NotCurrent(&'static str),
    #[error("production bounded autonomy requires an explicit approval profile")]
    ProductionAutonomyRequiresApproval,
    #[error("environment profile policy epoch must be positive")]
    InvalidPolicyEpoch,
    #[error("runner capabilities must be sorted, unique and bounded")]
    NonCanonicalCapabilities,
    #[error("dispatch does not match the enrolled runner")]
    RunnerBindingMismatch,
    #[error("runner was not enrolled for this action")]
    CapabilityNotEnrolled,
    #[error("runner dispatch carries an invalid human approval proof")]
    InvalidActionApproval,
    #[error("deployment already names the current immutable image")]
    NoopDeployment,
    #[error("verified runner record lacks an authenticated poststate")]
    VerifiedReceiptMissingPoststate,
}

struct Commitment(Sha256);

impl Commitment {
    fn new(domain: &[u8]) -> Self {
        let mut hash = Sha256::new();
        write_bytes(&mut hash, domain);
        Self(hash)
    }

    fn u8(&mut self, value: u8) {
        self.0.update([value]);
    }

    fn u16(&mut self, value: u16) {
        self.0.update(value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.0.update(value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.0.update(value.to_be_bytes());
    }

    fn i64(&mut self, value: i64) {
        self.0.update(value.to_be_bytes());
    }

    fn uuid(&mut self, value: Uuid) {
        self.0.update(value.as_bytes());
    }

    fn text(&mut self, value: &str) {
        write_bytes(&mut self.0, value.as_bytes());
    }

    fn digest(&mut self, value: Digest32) {
        self.0.update(value.as_bytes());
    }

    fn optional_text(&mut self, value: Option<&str>) {
        match value {
            Some(value) => {
                self.u8(1);
                self.text(value);
            }
            None => self.u8(0),
        }
    }

    fn optional_digest(&mut self, value: Option<Digest32>) {
        match value {
            Some(value) => {
                self.u8(1);
                self.digest(value);
            }
            None => self.u8(0),
        }
    }

    fn finish(self) -> Digest32 {
        Digest32::from_bytes(self.0.finalize().into())
    }
}

fn write_bytes(hash: &mut Sha256, value: &[u8]) {
    let length = u64::try_from(value.len()).unwrap_or(u64::MAX);
    hash.update(length.to_be_bytes());
    hash.update(value);
}

fn require_schema(value: u16) -> Result<(), RunnerProtocolError> {
    if value == RUNNER_PROTOCOL_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(RunnerProtocolError::WrongSchema)
    }
}

fn require_uuid(value: Uuid, label: &'static str) -> Result<(), RunnerProtocolError> {
    if value.is_nil() {
        Err(RunnerProtocolError::InvalidIdentifier(label))
    } else {
        Ok(())
    }
}

fn require_digest(value: Digest32, label: &'static str) -> Result<(), RunnerProtocolError> {
    if value.as_bytes().iter().all(|byte| *byte == 0) {
        Err(RunnerProtocolError::ZeroDigest(label))
    } else {
        Ok(())
    }
}

fn validate_id(value: &str, label: &'static str) -> Result<(), RunnerProtocolError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || value.trim() != value
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        Err(RunnerProtocolError::InvalidIdentifier(label))
    } else {
        Ok(())
    }
}

fn validate_route(value: &str, label: &'static str) -> Result<(), RunnerProtocolError> {
    if value.is_empty()
        || value.len() > MAX_ROUTE_BYTES
        || value.trim() != value
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        Err(RunnerProtocolError::InvalidRoute(label))
    } else {
        Ok(())
    }
}

fn validate_github_repository(value: &str) -> Result<(), RunnerProtocolError> {
    validate_route(value, "github_repository")?;
    let mut parts = value.split('/');
    let owner = parts.next().unwrap_or_default();
    let repository = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || owner.is_empty()
        || repository.is_empty()
        || !owner
            .bytes()
            .chain(repository.bytes())
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(RunnerProtocolError::InvalidRoute("github_repository"));
    }
    Ok(())
}

fn validate_aws_account(value: &str) -> Result<(), RunnerProtocolError> {
    if value.len() != 12 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RunnerProtocolError::InvalidIdentifier("aws_account_id"));
    }
    Ok(())
}

fn validate_aws_region(value: &str) -> Result<(), RunnerProtocolError> {
    if value.len() < 9
        || value.len() > 32
        || value.starts_with('-')
        || value.ends_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || value.bytes().filter(|byte| *byte == b'-').count() < 2
    {
        return Err(RunnerProtocolError::InvalidIdentifier("aws_region"));
    }
    Ok(())
}

fn validate_ecr_repository(value: &str) -> Result<(), RunnerProtocolError> {
    if value.is_empty()
        || value.len() > 256
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains("//")
        || value.contains("..")
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'/' | b'-' | b'_' | b'.')
        })
    {
        return Err(RunnerProtocolError::InvalidRoute("ecr_repository"));
    }
    Ok(())
}

fn validate_dns_label(value: &str, label: &'static str) -> Result<(), RunnerProtocolError> {
    if value.is_empty()
        || value.len() > 63
        || value.starts_with('-')
        || value.ends_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(RunnerProtocolError::InvalidIdentifier(label));
    }
    Ok(())
}

fn validate_commit_sha(value: &str) -> Result<(), RunnerProtocolError> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RunnerProtocolError::InvalidIdentifier("commit_sha"));
    }
    Ok(())
}

fn validate_window(
    start: i64,
    end: i64,
    maximum: i64,
    label: &'static str,
) -> Result<(), RunnerProtocolError> {
    let duration = end.checked_sub(start);
    if start < 0 || !matches!(duration, Some(value) if value > 0 && value <= maximum) {
        return Err(RunnerProtocolError::InvalidWindow(label));
    }
    Ok(())
}

fn require_current(
    trusted_now: i64,
    not_before: i64,
    expires_at: i64,
    label: &'static str,
) -> Result<(), RunnerProtocolError> {
    if trusted_now < not_before || trusted_now >= expires_at {
        Err(RunnerProtocolError::NotCurrent(label))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_900_000_000;

    fn digest(seed: u8) -> Digest32 {
        Digest32::from_bytes([seed; 32])
    }

    fn profile(tier: EnvironmentTier, autonomy_mode: AutonomyMode) -> EnterpriseEnvironmentProfile {
        EnterpriseEnvironmentProfile {
            schema_version: RUNNER_PROTOCOL_SCHEMA_VERSION,
            profile_id: Uuid::from_bytes([1; 16]),
            organization_id: "acme".to_owned(),
            environment_id: "payments-staging".to_owned(),
            tier,
            autonomy_mode,
            production_autonomy_approval_hash: None,
            executor_audience: "accordlock-eks-executor".to_owned(),
            github_repository: "acme/payments".to_owned(),
            github_workflow_ref: ".github/workflows/release.yml@refs/heads/main".to_owned(),
            aws_account_id: "111122223333".to_owned(),
            aws_region: "eu-west-1".to_owned(),
            ecr_repository: "acme/payments".to_owned(),
            eks_cluster_name: "staging-a".to_owned(),
            kubernetes_namespace: "payments".to_owned(),
            kubernetes_deployment: "payments-api".to_owned(),
            kubernetes_container: "application".to_owned(),
            policy_hash: digest(1),
            policy_epoch: 1,
            github_connector_hash: digest(2),
            aws_identity_hash: digest(3),
            ecr_connector_hash: digest(4),
            kubernetes_connector_hash: digest(5),
            action_approval_authority_hash: digest(20),
            created_at: NOW,
            expires_at: NOW + 86_400,
        }
    }

    fn registration(profile_hash: Digest32) -> RunnerRegistration {
        RunnerRegistration {
            schema_version: RUNNER_PROTOCOL_SCHEMA_VERSION,
            runner_id: Uuid::from_bytes([2; 16]),
            organization_id: "acme".to_owned(),
            environment_id: "payments-staging".to_owned(),
            environment_profile_hash: profile_hash,
            runner_attestation_hash: digest(6),
            capabilities: vec![
                RunnerCapability::ObserveGithub,
                RunnerCapability::ObserveEcr,
                RunnerCapability::ObserveKubernetes,
                RunnerCapability::DeployEksImage,
            ],
            enrolled_at: NOW,
            expires_at: NOW + 3_600,
        }
    }

    fn dispatch(registration: &RunnerRegistration) -> Result<RunnerDispatch, RunnerProtocolError> {
        Ok(RunnerDispatch {
            schema_version: RUNNER_PROTOCOL_SCHEMA_VERSION,
            dispatch_id: Uuid::from_bytes([3; 16]),
            task_id: Uuid::from_bytes([4; 16]),
            task_hash: digest(18),
            session_id: "session-1".to_owned(),
            principal_id: "user:alice@example.com".to_owned(),
            runner_id: registration.runner_id,
            environment_profile_hash: registration.environment_profile_hash,
            runner_registration_hash: registration.digest()?,
            policy_decision_hash: digest(7),
            resource_reservation_hash: digest(8),
            authorization_id: Uuid::from_bytes([5; 16]),
            authorization_hash: digest(9),
            action_approval: None,
            action: RunnerAction::DeployEksImage {
                transaction_id: Uuid::from_bytes([6; 16]),
                commit_sha: "a".repeat(40),
                image_digest: digest(10),
                deployment_uid: "11111111-2222-4333-8444-555555555555".to_owned(),
                resource_version: "83191".to_owned(),
                container_index: 0,
                prior_image_digest: digest(11),
                prior_projection_hash: digest(12),
                prior_transaction_annotation: None,
                prior_authorization_annotation: None,
                prior_operation_hash_annotation: None,
            },
            created_at: NOW + 10,
            expires_at: NOW + 70,
        })
    }

    #[test]
    fn staging_profile_is_canonical_and_derives_fixed_routes()
    -> Result<(), Box<dyn std::error::Error>> {
        let value = profile(EnvironmentTier::Staging, AutonomyMode::BoundedAutomatic);
        value.validate()?;
        assert_ne!(value.digest()?, digest(0));
        assert_eq!(
            value.ecr_image_repository(),
            "111122223333.dkr.ecr.eu-west-1.amazonaws.com/acme/payments"
        );
        assert_eq!(
            value.eks_cluster_identity(),
            "arn:aws:eks:eu-west-1:111122223333:cluster/staging-a"
        );
        Ok(())
    }

    #[test]
    fn production_bounded_automation_requires_approval_commitment()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut value = profile(EnvironmentTier::Production, AutonomyMode::BoundedAutomatic);
        assert_eq!(
            value.validate(),
            Err(RunnerProtocolError::ProductionAutonomyRequiresApproval)
        );
        value.production_autonomy_approval_hash = Some(digest(17));
        value.validate()?;
        Ok(())
    }

    #[test]
    fn runner_capabilities_must_be_sorted_and_unique() -> Result<(), Box<dyn std::error::Error>> {
        let value = profile(EnvironmentTier::Staging, AutonomyMode::PrepareAndAsk);
        let mut enrolled = registration(value.digest()?);
        enrolled.capabilities.swap(0, 1);
        assert_eq!(
            enrolled.validate(),
            Err(RunnerProtocolError::NonCanonicalCapabilities)
        );
        Ok(())
    }

    #[test]
    fn dispatch_binds_policy_resources_authorization_and_target_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let value = profile(EnvironmentTier::Staging, AutonomyMode::PrepareAndAsk);
        let enrolled = registration(value.digest()?);
        let original = dispatch(&enrolled)?;
        let baseline = original.digest(&enrolled)?;
        let mut changed = original.clone();
        if let RunnerAction::DeployEksImage {
            resource_version, ..
        } = &mut changed.action
        {
            *resource_version = "83192".to_owned();
        }
        assert_ne!(baseline, changed.digest(&enrolled)?);

        let mut changed_transaction = original.clone();
        if let RunnerAction::DeployEksImage { transaction_id, .. } = &mut changed_transaction.action
        {
            *transaction_id = Uuid::from_bytes([7; 16]);
        }
        assert_ne!(baseline, changed_transaction.digest(&enrolled)?);

        if let RunnerAction::DeployEksImage { transaction_id, .. } = &mut changed_transaction.action
        {
            *transaction_id = Uuid::nil();
        }
        assert_eq!(
            changed_transaction.validate(&enrolled),
            Err(RunnerProtocolError::InvalidIdentifier("transaction_id"))
        );

        let mut wrong_runner = enrolled.clone();
        wrong_runner.runner_id = Uuid::from_bytes([9; 16]);
        assert_eq!(
            original.validate(&wrong_runner),
            Err(RunnerProtocolError::RunnerBindingMismatch)
        );
        Ok(())
    }

    #[test]
    fn trusted_time_rejects_future_and_expired_dispatches() -> Result<(), Box<dyn std::error::Error>>
    {
        let value = profile(EnvironmentTier::Staging, AutonomyMode::PrepareAndAsk);
        let enrolled = registration(value.digest()?);
        let command = dispatch(&enrolled)?;

        value.validate_at(NOW)?;
        enrolled.validate_at(NOW)?;
        command.validate_at(&enrolled, NOW + 20)?;
        assert_eq!(
            command.validate_at(&enrolled, NOW + 9),
            Err(RunnerProtocolError::NotCurrent("runner dispatch"))
        );
        assert_eq!(
            command.validate_at(&enrolled, NOW + 70),
            Err(RunnerProtocolError::NotCurrent("runner dispatch"))
        );
        assert_eq!(
            enrolled.validate_at(NOW + 3_600),
            Err(RunnerProtocolError::NotCurrent("runner registration"))
        );
        Ok(())
    }

    #[test]
    fn unknown_fields_and_secret_shaped_injections_are_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let value = profile(EnvironmentTier::Staging, AutonomyMode::PrepareAndAsk);
        let enrolled = registration(value.digest()?);
        let command = dispatch(&enrolled)?;
        let serialized = serde_json::to_string(&command)?;
        assert!(!serialized.contains("credential"));
        assert!(!serialized.contains("kubeconfig"));
        assert!(!serialized.contains("access_key"));
        let mut json = serde_json::to_value(command)?;
        let object = json
            .as_object_mut()
            .ok_or("runner dispatch did not serialize as an object")?;
        object.insert(
            "aws_secret_access_key".to_owned(),
            serde_json::json!("secret"),
        );
        assert!(serde_json::from_value::<RunnerDispatch>(json).is_err());
        Ok(())
    }

    #[test]
    fn verified_execution_record_requires_a_poststate() {
        let record = RunnerExecutionRecord {
            schema_version: RUNNER_PROTOCOL_SCHEMA_VERSION,
            record_id: Uuid::from_bytes([6; 16]),
            runner_id: Uuid::from_bytes([2; 16]),
            dispatch_hash: digest(13),
            outcome: RunnerExecutionOutcome::Verified,
            prestate_hash: digest(14),
            poststate_hash: None,
            evidence_root: digest(15),
            post_evaluation_hash: digest(16),
            started_at: NOW,
            completed_at: NOW + 10,
        };
        assert_eq!(
            record.validate(),
            Err(RunnerProtocolError::VerifiedReceiptMissingPoststate)
        );
    }
}
