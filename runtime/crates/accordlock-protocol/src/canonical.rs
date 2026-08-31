use std::convert::Infallible;

use minicbor::Encoder;
use minicbor::encode::Error as EncodeError;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    AgentProposal, AuthorityDomainState, AuthorityVector, CONSUMPTION_RECEIPT_DOMAIN,
    CapabilityGrant, ConsumptionReceipt, DeploymentTemplate, Digest32, DispatchDeadlinePolicy,
    EVALUATION_DOMAIN, EVIDENCE_ROOT_DOMAIN, EXECUTION_AUTHORIZATION_DOMAIN,
    EXECUTION_AUTHORIZATION_SINGLE_USE_PROFILE, EvaluationAttestation, EvidenceAssertion,
    EvidencePayload, ExecutionAuthorization, MAX_IMMUTABLE_DEPENDENCY_EXPIRIES, PolicyConfig,
};

type VecEncoder = Encoder<Vec<u8>>;
type VecEncodeError = EncodeError<Infallible>;

/// Domain of the standalone canonical authority-vector commitment.
pub const AUTHORITY_VECTOR_DOMAIN: &str = "accordlock:v1:authority-vector";

/// Domain of the complete standalone proposal commitment.
///
/// The proposal commitment deliberately includes the schema, request identity,
/// tenant, actor, and every deployment-template field. It is the durable v13
/// intent identity and must not be replaced with the template hash alone.
pub const AGENT_PROPOSAL_DOMAIN: &str = "accordlock:v1:agent-proposal";

#[derive(Debug, Error)]
pub enum CanonicalError {
    #[error("canonical CBOR encoding failed: {0}")]
    Encode(String),
    #[error("{0} must be strictly sorted and contain no duplicates")]
    NonCanonicalCollection(&'static str),
    #[error("{0} contains an invalid canonical value")]
    InvalidValue(&'static str),
}

pub trait CanonicalEncode {
    /// Encodes the value using its domain-specific deterministic CBOR layout.
    ///
    /// # Errors
    ///
    /// Returns [`CanonicalError`] if a field cannot be encoded.
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError>;
}

fn finish(result: Result<Vec<u8>, VecEncodeError>) -> Result<Vec<u8>, CanonicalError> {
    result.map_err(|error| CanonicalError::Encode(error.to_string()))
}

fn encode_domain(
    encoder: &mut VecEncoder,
    value: &AuthorityDomainState,
) -> Result<(), VecEncodeError> {
    encoder.array(3)?;
    encoder.bytes(value.root.as_bytes())?;
    encoder.u64(value.epoch)?;
    encoder.bytes(value.activation_id.as_bytes())?;
    Ok(())
}

fn encode_authority(
    encoder: &mut VecEncoder,
    value: &AuthorityVector,
) -> Result<(), VecEncodeError> {
    encoder.array(12)?;
    for domain in value.domains() {
        encode_domain(encoder, domain)?;
    }
    Ok(())
}

fn encode_template(
    encoder: &mut VecEncoder,
    value: &DeploymentTemplate,
) -> Result<(), VecEncodeError> {
    encoder.array(19)?;
    encoder.str(&value.operation)?;
    encoder.str(&value.environment)?;
    encoder.str(&value.audience)?;
    encoder.str(&value.repository)?;
    encoder.str(&value.commit_sha)?;
    encoder.str(&value.image_repository)?;
    encoder.bytes(value.image_digest.as_bytes())?;
    encoder.str(&value.cluster_identity)?;
    encoder.str(&value.namespace)?;
    encoder.str(&value.deployment)?;
    encoder.str(&value.deployment_uid)?;
    encoder.str(&value.container)?;
    encoder.u32(value.container_index)?;
    encoder.bytes(value.prior_image_digest.as_bytes())?;
    encoder.str(&value.resource_version)?;
    encoder.bytes(value.prior_projection_hash.as_bytes())?;
    encode_optional_string(encoder, value.prior_transaction_annotation.as_deref())?;
    encode_optional_string(encoder, value.prior_authorization_annotation.as_deref())?;
    encode_optional_string(encoder, value.prior_operation_hash_annotation.as_deref())?;
    Ok(())
}

fn encode_dispatch_deadline_policy(
    encoder: &mut VecEncoder,
    value: &DispatchDeadlinePolicy,
) -> Result<(), VecEncodeError> {
    encoder.array(3)?;
    encoder.i64(value.max_dispatch_delay_seconds)?;
    encoder.i64(value.profile_hard_cap)?;
    encoder.array(u64::try_from(value.immutable_dependency_expiries.len()).unwrap_or(u64::MAX))?;
    for expiry in &value.immutable_dependency_expiries {
        encoder.i64(*expiry)?;
    }
    Ok(())
}

fn encode_optional_string(
    encoder: &mut VecEncoder,
    value: Option<&str>,
) -> Result<(), VecEncodeError> {
    if let Some(value) = value {
        encoder.str(value)?;
    } else {
        encoder.null()?;
    }
    Ok(())
}

fn encode_payload(encoder: &mut VecEncoder, value: &EvidencePayload) -> Result<(), VecEncodeError> {
    match value {
        EvidencePayload::Review {
            repository,
            commit_sha,
            approved,
            review_state_id,
        } => {
            encoder.array(5)?;
            encoder.u8(0)?;
            encoder.str(repository)?;
            encoder.str(commit_sha)?;
            encoder.bool(*approved)?;
            encoder.str(review_state_id)?;
        }
        EvidencePayload::Build {
            repository,
            commit_sha,
            workflow_ref,
            run_id,
            succeeded,
            input_manifest_root,
            completeness_profile,
            output_digest,
        } => {
            encoder.array(9)?;
            encoder.u8(1)?;
            encoder.str(repository)?;
            encoder.str(commit_sha)?;
            encoder.str(workflow_ref)?;
            encoder.str(run_id)?;
            encoder.bool(*succeeded)?;
            encoder.bytes(input_manifest_root.as_bytes())?;
            encoder.u8(completeness_profile.code())?;
            encoder.bytes(output_digest.as_bytes())?;
        }
        EvidencePayload::Artifact {
            repository,
            digest,
            source_run_id,
            signature_valid,
            quarantined,
        } => {
            encoder.array(6)?;
            encoder.u8(2)?;
            encoder.str(repository)?;
            encoder.bytes(digest.as_bytes())?;
            encoder.str(source_run_id)?;
            encoder.bool(*signature_valid)?;
            encoder.bool(*quarantined)?;
        }
        EvidencePayload::Target {
            cluster_identity,
            namespace,
            deployment,
            deployment_uid,
            resource_version,
            current_image,
            projection_hash,
        } => {
            encoder.array(8)?;
            encoder.u8(3)?;
            encoder.str(cluster_identity)?;
            encoder.str(namespace)?;
            encoder.str(deployment)?;
            encoder.str(deployment_uid)?;
            encoder.str(resource_version)?;
            encoder.bytes(current_image.as_bytes())?;
            encoder.bytes(projection_hash.as_bytes())?;
        }
    }
    Ok(())
}

fn encode_assertion(
    encoder: &mut VecEncoder,
    value: &EvidenceAssertion,
) -> Result<(), VecEncodeError> {
    encoder.array(10)?;
    encoder.u16(value.schema_version)?;
    encoder.bytes(value.request_id.as_bytes())?;
    encoder.bytes(value.evidence_id.as_bytes())?;
    encoder.str(&value.issuer)?;
    encoder.str(&value.key_id)?;
    encoder.str(&value.source_uri)?;
    encoder.i64(value.observed_at)?;
    encoder.i64(value.valid_until)?;
    encode_authority(encoder, &value.authority)?;
    encode_payload(encoder, &value.payload)?;
    Ok(())
}

impl CanonicalEncode for EvidenceAssertion {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encode_assertion(&mut encoder, self)?;
            Ok(encoder.into_writer())
        })())
    }
}

impl CanonicalEncode for DeploymentTemplate {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encode_template(&mut encoder, self)?;
            Ok(encoder.into_writer())
        })())
    }
}

impl CanonicalEncode for AgentProposal {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(6)?;
            encoder.u16(self.schema_version)?;
            encoder.bytes(self.request_id.as_bytes())?;
            encoder.str(&self.tenant)?;
            encoder.str(&self.actor)?;
            encode_template(&mut encoder, &self.template)?;
            encoder.str(AGENT_PROPOSAL_DOMAIN)?;
            Ok(encoder.into_writer())
        })())
    }
}

impl CanonicalEncode for PolicyConfig {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(10)?;
            encoder.str(&self.policy_id)?;
            encode_sorted_strings(&mut encoder, &self.allowed_actors)?;
            encode_sorted_strings(&mut encoder, &self.allowed_repositories)?;
            encode_sorted_strings(&mut encoder, &self.allowed_image_repositories)?;
            encode_sorted_strings(&mut encoder, &self.allowed_clusters)?;
            encode_sorted_strings(&mut encoder, &self.allowed_namespaces)?;
            encoder.u8(self.minimum_review_grade)?;
            encoder.u8(self.minimum_build_grade)?;
            encoder.i64(self.maximum_evidence_age_seconds)?;
            encoder.i64(self.maximum_authorization_lifetime_seconds)?;
            Ok(encoder.into_writer())
        })())
    }
}

fn encode_sorted_strings(
    encoder: &mut VecEncoder,
    values: &[String],
) -> Result<(), VecEncodeError> {
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted.dedup();
    encoder.array(u64::try_from(sorted.len()).unwrap_or(u64::MAX))?;
    for value in &sorted {
        encoder.str(value)?;
    }
    Ok(())
}

fn require_sorted_unique_strings(
    values: &[String],
    field: &'static str,
) -> Result<(), CanonicalError> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(CanonicalError::NonCanonicalCollection(field));
    }
    Ok(())
}

fn require_sorted_unique_i64(values: &[i64], field: &'static str) -> Result<(), CanonicalError> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(CanonicalError::NonCanonicalCollection(field));
    }
    Ok(())
}

impl CanonicalEncode for AuthorityVector {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(2)?;
            encode_authority(&mut encoder, self)?;
            encoder.str(AUTHORITY_VECTOR_DOMAIN)?;
            Ok(encoder.into_writer())
        })())
    }
}

impl CanonicalEncode for EvaluationAttestation {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        require_sorted_unique_strings(&self.principals, "evaluation principals")?;
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(15)?;
            encoder.u16(self.schema_version)?;
            encoder.bytes(self.request_id.as_bytes())?;
            encoder.bytes(self.evaluation_nonce.as_bytes())?;
            encoder.str(&self.tenant)?;
            encoder.str(&self.actor)?;
            encoder.i64(self.evaluated_at)?;
            encoder.u8(self.outcome.code())?;
            encoder.array(u64::try_from(self.reasons.len()).unwrap_or(u64::MAX))?;
            for reason in &self.reasons {
                encoder.u16(reason.code())?;
            }
            encoder.bytes(self.template_hash.as_bytes())?;
            encoder.bytes(self.evidence_root.as_bytes())?;
            encode_sorted_strings(&mut encoder, &self.principals)?;
            encoder.bytes(self.policy_root.as_bytes())?;
            encode_authority(&mut encoder, &self.authority)?;
            encoder.i64(self.consume_before)?;
            encoder.str(EVALUATION_DOMAIN)?;
            Ok(encoder.into_writer())
        })())
    }
}

impl CanonicalEncode for CapabilityGrant {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(15)?;
            encoder.bytes(self.grant_id.as_bytes())?;
            encoder.str(&self.holder)?;
            encoder.str(&self.tenant)?;
            encoder.str(&self.operation)?;
            encoder.str(&self.repository)?;
            encoder.str(&self.audience)?;
            encoder.str(&self.cluster_identity)?;
            encoder.str(&self.namespace)?;
            encoder.str(&self.deployment_uid)?;
            encoder.str(&self.container)?;
            encoder.str(&self.image_repository)?;
            encoder.i64(self.not_before)?;
            encoder.i64(self.expires_at)?;
            encoder.u32(self.maximum_uses)?;
            encoder.str("accordlock:v1:capability-grant")?;
            Ok(encoder.into_writer())
        })())
    }
}

impl CanonicalEncode for ExecutionAuthorization {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        require_sorted_unique_strings(&self.principals, "authorization principals")?;
        if self.dispatch_deadline_policy.max_dispatch_delay_seconds <= 0
            || self.dispatch_deadline_policy.profile_hard_cap < 0
            || self
                .dispatch_deadline_policy
                .immutable_dependency_expiries
                .len()
                > MAX_IMMUTABLE_DEPENDENCY_EXPIRIES
            || self
                .dispatch_deadline_policy
                .immutable_dependency_expiries
                .iter()
                .any(|expiry| *expiry < 0)
        {
            return Err(CanonicalError::InvalidValue(
                "authorization dispatch deadline policy",
            ));
        }
        require_sorted_unique_i64(
            &self.dispatch_deadline_policy.immutable_dependency_expiries,
            "authorization immutable dependency expiries",
        )?;
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(20)?;
            encoder.u16(self.schema_version)?;
            encoder.bytes(self.authorization_id.as_bytes())?;
            encoder.bytes(self.evaluation_nonce.as_bytes())?;
            encoder.bytes(self.request_id.as_bytes())?;
            encoder.str(&self.tenant)?;
            encoder.str(&self.holder)?;
            encoder.str(&self.audience)?;
            encoder.i64(self.issued_at)?;
            encoder.i64(self.not_before)?;
            encoder.i64(self.consume_before)?;
            encode_dispatch_deadline_policy(&mut encoder, &self.dispatch_deadline_policy)?;
            encoder.bytes(self.grant_id.as_bytes())?;
            encode_template(&mut encoder, &self.template)?;
            encoder.bytes(self.template_hash.as_bytes())?;
            encoder.bytes(self.evidence_root.as_bytes())?;
            encode_sorted_strings(&mut encoder, &self.principals)?;
            encoder.bytes(self.policy_root.as_bytes())?;
            encode_authority(&mut encoder, &self.authority)?;
            encoder.str(EXECUTION_AUTHORIZATION_DOMAIN)?;
            encoder.u8(EXECUTION_AUTHORIZATION_SINGLE_USE_PROFILE)?;
            Ok(encoder.into_writer())
        })())
    }
}

impl CanonicalEncode for ConsumptionReceipt {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(8)?;
            encoder.u16(self.schema_version)?;
            encoder.bytes(self.transaction_id.as_bytes())?;
            encoder.bytes(self.authorization_id.as_bytes())?;
            encoder.i64(self.consumed_at)?;
            encoder.i64(self.dispatch_deadline)?;
            encode_authority(&mut encoder, &self.authority)?;
            encoder.bytes(self.authorization_hash.as_bytes())?;
            encoder.str(CONSUMPTION_RECEIPT_DOMAIN)?;
            Ok(encoder.into_writer())
        })())
    }
}

/// Computes SHA-256 over a value's deterministic canonical representation.
///
/// # Errors
///
/// Returns [`CanonicalError`] when canonical encoding fails.
pub fn canonical_hash<T: CanonicalEncode>(value: &T) -> Result<Digest32, CanonicalError> {
    Ok(Digest32::sha256(&value.canonical_bytes()?))
}

/// Computes the deterministic root of evidence assertions ordered by identifier.
///
/// # Errors
///
/// Returns [`CanonicalError`] when the evidence set cannot be encoded.
pub fn evidence_root(values: &[EvidenceAssertion]) -> Result<Digest32, CanonicalError> {
    let mut ordered = values.to_vec();
    ordered.sort_by_key(|value| value.evidence_id);

    let result = (|| -> Result<Vec<u8>, VecEncodeError> {
        let mut encoder = Encoder::new(Vec::new());
        encoder.array(u64::try_from(ordered.len()).unwrap_or(u64::MAX))?;
        for assertion in &ordered {
            encode_assertion(&mut encoder, assertion)?;
        }
        Ok(encoder.into_writer())
    })();
    let bytes = finish(result)?;
    let mut hasher = Sha256::new();
    hasher.update(EVIDENCE_ROOT_DOMAIN.as_bytes());
    hasher.update([0]);
    hasher.update(bytes);
    let mut root = [0_u8; 32];
    root.copy_from_slice(&hasher.finalize());
    Ok(Digest32::from_bytes(root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthorityDomainState, AuthorityVector, EVIDENCE_ASSERTION_SCHEMA_VERSION};
    use serde_json::json;
    use uuid::Uuid;

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

    fn review_assertion(request_id: Uuid) -> EvidenceAssertion {
        EvidenceAssertion {
            schema_version: EVIDENCE_ASSERTION_SCHEMA_VERSION,
            request_id,
            evidence_id: Uuid::from_bytes([0x31; 16]),
            issuer: "review.example".to_owned(),
            key_id: "review-key-v2".to_owned(),
            source_uri: "https://review.example/records/31".to_owned(),
            observed_at: 1_000,
            valid_until: 1_100,
            authority: authority(),
            payload: EvidencePayload::Review {
                repository: "acme/payments".to_owned(),
                commit_sha: "1".repeat(40),
                approved: true,
                review_state_id: "review-state-31".to_owned(),
            },
        }
    }

    #[test]
    fn template_encoding_is_deterministic() -> Result<(), Box<dyn std::error::Error>> {
        let template = DeploymentTemplate {
            operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
            environment: "prod".to_owned(),
            audience: "accordlock-executor".to_owned(),
            repository: "acme/payments".to_owned(),
            commit_sha: "1".repeat(40),
            image_repository: "acme/payments".to_owned(),
            image_digest: Digest32::from_bytes([0xaa; 32]),
            cluster_identity: "kind://accordlock".to_owned(),
            namespace: "payments-prod".to_owned(),
            deployment: "payments".to_owned(),
            deployment_uid: "11111111-2222-4333-8444-555555555555".to_owned(),
            container: "app".to_owned(),
            container_index: 0,
            prior_image_digest: Digest32::from_bytes([0xcc; 32]),
            resource_version: "1001".to_owned(),
            prior_projection_hash: Digest32::from_bytes([0xdd; 32]),
            prior_transaction_annotation: None,
            prior_authorization_annotation: None,
            prior_operation_hash_annotation: None,
        };
        assert_eq!(template.canonical_bytes()?, template.canonical_bytes()?);
        assert_eq!(canonical_hash(&template)?, canonical_hash(&template)?);
        let _ = authority();
        Ok(())
    }

    fn complete_proposal() -> AgentProposal {
        AgentProposal {
            schema_version: 7,
            request_id: Uuid::from_bytes([0x71; 16]),
            tenant: "tenant-a".to_owned(),
            actor: "deploy-agent".to_owned(),
            template: DeploymentTemplate {
                operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
                environment: "prod".to_owned(),
                audience: "accordlock-executor://tenant-a/prod/eks".to_owned(),
                repository: "acme/payments".to_owned(),
                commit_sha: "1".repeat(40),
                image_repository: "registry.example/payments".to_owned(),
                image_digest: Digest32::from_bytes([0xaa; 32]),
                cluster_identity: "cluster-a".to_owned(),
                namespace: "payments".to_owned(),
                deployment: "api".to_owned(),
                deployment_uid: "deployment-uid".to_owned(),
                container: "api".to_owned(),
                container_index: 3,
                prior_image_digest: Digest32::from_bytes([0xbb; 32]),
                resource_version: "42".to_owned(),
                prior_projection_hash: Digest32::from_bytes([0xcc; 32]),
                prior_transaction_annotation: Some("tx-old".to_owned()),
                prior_authorization_annotation: Some("authorization-old".to_owned()),
                prior_operation_hash_annotation: Some("operation-old".to_owned()),
            },
        }
    }

    #[test]
    fn proposal_golden_commitment_covers_every_field() -> Result<(), Box<dyn std::error::Error>> {
        let proposal = complete_proposal();
        let baseline = canonical_hash(&proposal)?;
        assert_eq!(
            baseline.to_string(),
            "sha256:28e55e37311cfc81dec4d25c918b94f8df6cff8deacce58803d004821d2a77e8"
        );

        let mutations = [
            ("/schema_version", json!(8)),
            ("/request_id", json!(Uuid::from_bytes([0x72; 16]))),
            ("/tenant", json!("tenant-b")),
            ("/actor", json!("other-agent")),
            ("/template/operation", json!("OTHER")),
            ("/template/environment", json!("stage")),
            ("/template/audience", json!("other-audience")),
            ("/template/repository", json!("acme/other")),
            ("/template/commit_sha", json!("2".repeat(40))),
            (
                "/template/image_repository",
                json!("registry.example/other"),
            ),
            (
                "/template/image_digest",
                json!(Digest32::from_bytes([0xab; 32])),
            ),
            ("/template/cluster_identity", json!("cluster-b")),
            ("/template/namespace", json!("other")),
            ("/template/deployment", json!("worker")),
            ("/template/deployment_uid", json!("other-uid")),
            ("/template/container", json!("sidecar")),
            ("/template/container_index", json!(4)),
            (
                "/template/prior_image_digest",
                json!(Digest32::from_bytes([0xbc; 32])),
            ),
            ("/template/resource_version", json!("43")),
            (
                "/template/prior_projection_hash",
                json!(Digest32::from_bytes([0xcd; 32])),
            ),
            ("/template/prior_transaction_annotation", json!("tx-new")),
            (
                "/template/prior_authorization_annotation",
                json!("authorization-new"),
            ),
            (
                "/template/prior_operation_hash_annotation",
                json!("operation-new"),
            ),
        ];
        let baseline_json = serde_json::to_value(&proposal)?;
        for (pointer, replacement) in mutations {
            let mut mutated = baseline_json.clone();
            let slot = mutated.pointer_mut(pointer).ok_or_else(|| {
                std::io::Error::other(format!("missing proposal pointer {pointer}"))
            })?;
            *slot = replacement;
            let mutated: AgentProposal = serde_json::from_value(mutated)?;
            assert_ne!(baseline, canonical_hash(&mutated)?, "field {pointer}");
        }
        Ok(())
    }

    #[test]
    fn assertion_and_root_commit_to_request_identifier() -> Result<(), Box<dyn std::error::Error>> {
        let request_a = review_assertion(Uuid::from_bytes([0x41; 16]));
        let request_b = review_assertion(Uuid::from_bytes([0x42; 16]));

        assert_ne!(request_a.canonical_bytes()?, request_b.canonical_bytes()?);
        assert_ne!(
            evidence_root(std::slice::from_ref(&request_a))?,
            evidence_root(std::slice::from_ref(&request_b))?
        );
        Ok(())
    }
}
