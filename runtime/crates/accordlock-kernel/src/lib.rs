//! Deterministic `AccordLock` authorization kernel.

use std::collections::{BTreeMap, BTreeSet};

pub use accordlock_ingress::AuthenticatedCaller;
use accordlock_ingress::AuthenticatedIngressRequest;
use accordlock_protocol::{
    AgentProposal, AttesterScope, AttesterStatus, AuthorityDomainState, AuthorityVector,
    CanonicalEncode, CompletenessProfile, CoseVerifier, DecisionOutcome, Digest32,
    EVALUATION_ATTESTATION_SCHEMA_VERSION, EVALUATION_DOMAIN, EVIDENCE_ASSERTION_SCHEMA_VERSION,
    EXECUTION_AUTHORIZATION_DOMAIN, EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
    EXECUTION_AUTHORIZATION_SINGLE_USE_PROFILE, EvaluationAttestation, EvidenceAssertion,
    EvidenceKind, EvidencePayload, ExecutionAuthorization, MAX_COSE_SIZE_BYTES,
    MAX_IMMUTABLE_DEPENDENCY_EXPIRIES, PolicyConfig, ReasonCode, RegisteredAttester,
    SignedAuthorization, SignedEvaluation, SigningIdentity, TrustedEvidenceSet,
    authorization_signer_root, canonical_hash, evaluator_verifier_root, evidence_root, sign_cose,
    verify_cose,
};
use accordlock_state::{ControlEvaluationWork, ControlWorkPhase, Scope};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

const MAX_EVIDENCE_ITEMS: usize = 64;
const MAX_REGISTERED_ATTESTERS: usize = 256;
const MAX_SCOPES_PER_ATTESTER: usize = 64;
const MAX_POLICY_ENTRIES_PER_FIELD: usize = 256;
const MAX_SECURITY_TEXT_BYTES: usize = 4_096;
const MAX_AGGREGATE_SECURITY_TEXT_BYTES: usize = 524_288;
const MAX_AGGREGATE_COSE_BYTES: usize = 4_194_304;
const MAX_AUTHORITY_GRADE: u8 = 4;
const MAX_AUTHORIZATION_PRINCIPALS: usize = 256;

/// Domain separator for the canonical activated-attester-registry root.
pub const ATTESTER_REGISTRY_ROOT_DOMAIN: &[u8] = b"accordlock:v1:activated-attester-registry\0";

/// Immutable, canonical attester registry activated under one exact registry
/// authority domain.
///
/// The computed root commits to the supplied registry bytes. It does not prove
/// that an attester is honest or that the registry's assertions are true.
#[derive(Clone, Debug)]
pub struct ActivatedAttesterRegistry {
    authority_domain: AuthorityDomainState,
    entries: Vec<RegisteredAttester>,
}

impl ActivatedAttesterRegistry {
    /// Activates a bounded, sorted, duplicate-free registry under an exact
    /// authority-domain state.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError`] if an entry or scope is malformed, ordering is
    /// noncanonical, an identity/key is duplicated, the authority-domain
    /// identity is malformed, or the computed root differs from the activated
    /// registry root.
    pub fn new(
        authority_domain: AuthorityDomainState,
        entries: Vec<RegisteredAttester>,
    ) -> Result<Self, KernelError> {
        validate_authority_domain(&authority_domain)?;
        let root = Self::compute_root(&entries)?;
        if root != authority_domain.root {
            return Err(KernelError::AttesterRegistryRootMismatch);
        }
        Ok(Self {
            authority_domain,
            entries,
        })
    }

    /// Computes the canonical content root for a registry that already obeys
    /// the activated ordering and uniqueness profile.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError`] for malformed, oversized, unsorted, or duplicate
    /// registry material.
    pub fn compute_root(entries: &[RegisteredAttester]) -> Result<Digest32, KernelError> {
        let material = canonical_attester_registry_material(entries)?;
        Ok(Digest32::sha256(&material))
    }

    /// Returns the exact authority-domain state under which this registry was
    /// activated.
    #[must_use]
    pub const fn authority_domain(&self) -> &AuthorityDomainState {
        &self.authority_domain
    }

    /// Returns the canonical registry root.
    #[must_use]
    pub const fn root(&self) -> Digest32 {
        self.authority_domain.root
    }

    /// Returns the immutable canonical registry entries.
    #[must_use]
    pub fn entries(&self) -> &[RegisteredAttester] {
        &self.entries
    }
}

/// Tenant and workload identity carried by a trusted kernel context.
///
/// This type has no public constructor. In the durable product path its values
/// come exclusively from [`ControlEvaluationWork`], which state creates only
/// after revalidating the exact submission, active claim, trusted database
/// time, and current principal-registry authority.
#[derive(Debug, PartialEq, Eq)]
pub struct KernelCaller {
    tenant: String,
    actor: String,
}

impl KernelCaller {
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    #[must_use]
    pub fn actor(&self) -> &str {
        &self.actor
    }
}

/// State that must be supplied by authenticated internal services, never by the
/// public proposal endpoint.
///
/// The context deliberately implements neither `Clone` nor serialization. The
/// product constructor consumes a non-cloneable durable work capability:
///
/// ```compile_fail
/// # use accordlock_state::ControlEvaluationWork;
/// fn clone_authority(work: &ControlEvaluationWork) {
///     let _second_authority = (*work).clone();
/// }
/// ```
///
/// ```compile_fail
/// # use accordlock_kernel::{ActivatedAttesterRegistry, KernelContext};
/// # use accordlock_protocol::PolicyConfig;
/// # use accordlock_state::ControlEvaluationWork;
/// fn reuse_authority(
///     work: ControlEvaluationWork,
///     policy: PolicyConfig,
///     registry: ActivatedAttesterRegistry,
/// ) {
///     let _context = KernelContext::from_control_work(work, policy, registry);
///     let _reused = work.lease();
/// }
/// ```
#[derive(Debug)]
pub struct KernelContext {
    control_work: Option<ControlEvaluationWork>,
    caller: KernelCaller,
    proposal: AgentProposal,
    authenticated_at: i64,
    ingress_expires_at: i64,
    ingress_authority_domain: AuthorityDomainState,
    now: i64,
    evaluation_nonce: Uuid,
    policy: PolicyConfig,
    active_authority: AuthorityVector,
    attester_registry: ActivatedAttesterRegistry,
}

impl KernelContext {
    /// Constructs the production kernel context by consuming one exact durable
    /// EVALUATE-phase capability.
    ///
    /// No caller identity, trusted time, evaluation nonce, scope, or authority
    /// value is accepted at this boundary. `now` is the state-owned claim time,
    /// and every security fact is copied from `work` before that capability is
    /// destroyed. The supplied policy and attester registry are accepted only
    /// when their canonical roots and full activation domains match the active
    /// authority frozen in the work.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError`] if the work is not an EVALUATE capability, its
    /// scope/identity/time bindings are inconsistent, ingress has expired, or
    /// the supplied policy/registry does not match the work authority.
    pub fn from_control_work(
        work: ControlEvaluationWork,
        policy: PolicyConfig,
        attester_registry: ActivatedAttesterRegistry,
    ) -> Result<Self, KernelError> {
        if work.lease().phase() != ControlWorkPhase::Evaluate
            || work.lease().submission_id().is_nil()
            || work.lease().claim_id().is_nil()
            || work.lease().fence() == 0
            || work.lease().lease_until() <= work.lease().claimed_at()
            || !valid_security_text(work.lease().worker_id())
        {
            return Err(KernelError::InvalidContext(
                "durable evaluation work lease is malformed",
            ));
        }

        let claimed_at = work.lease().claimed_at();
        let scope = work.scope().clone();
        let proposal = work.proposal().clone();
        let caller_tenant = work.caller_tenant().to_owned();
        let caller_actor = work.caller_actor().to_owned();
        let authenticated_at = work.accepted_at();
        let ingress_expires_at = work.ingress_expires_at();
        let ingress_authority_domain = work.ingress_authority_domain().clone();
        let active_authority = work.active_authority().clone();
        let evaluation_nonce = work.evaluation_nonce();

        let mut context = Self::from_trusted_parts(
            Some(&scope),
            proposal,
            caller_tenant,
            caller_actor,
            authenticated_at,
            ingress_expires_at,
            ingress_authority_domain,
            claimed_at,
            evaluation_nonce,
            policy,
            active_authority,
            attester_registry,
        )?;
        context.control_work = Some(work);
        Ok(context)
    }

    /// Constructs a kernel context from an opaque authenticated-ingress result.
    ///
    /// This is the legacy synchronous harness path. Product workers must use
    /// [`Self::from_control_work`] so trusted time, current authority, and
    /// identity come from the durable state claim instead of call arguments.
    /// The constructor still binds the policy and canonical attester registry
    /// to the exact active authority vector before evaluation can occur.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError`] for expiry or clock rollback after ingress,
    /// malformed identities/time/authority state, policy-root mismatch, or any
    /// ingress/attester registry-domain mismatch.
    pub fn from_authenticated_ingress(
        ingress: AuthenticatedIngressRequest,
        now: i64,
        evaluation_nonce: Uuid,
        policy: PolicyConfig,
        active_authority: AuthorityVector,
        attester_registry: ActivatedAttesterRegistry,
    ) -> Result<Self, KernelError> {
        let caller_tenant = ingress.caller().tenant().to_owned();
        let caller_actor = ingress.caller().actor().to_owned();
        let proposal = ingress.proposal().clone();
        let authenticated_at = ingress.authenticated_at();
        let ingress_expires_at = ingress.expires_at();
        let ingress_authority_domain = ingress.authority_domain().clone();
        drop(ingress);

        Self::from_trusted_parts(
            None,
            proposal,
            caller_tenant,
            caller_actor,
            authenticated_at,
            ingress_expires_at,
            ingress_authority_domain,
            now,
            evaluation_nonce,
            policy,
            active_authority,
            attester_registry,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_trusted_parts(
        durable_scope: Option<&Scope>,
        proposal: AgentProposal,
        caller_tenant: String,
        caller_actor: String,
        authenticated_at: i64,
        ingress_expires_at: i64,
        ingress_authority_domain: AuthorityDomainState,
        now: i64,
        evaluation_nonce: Uuid,
        policy: PolicyConfig,
        active_authority: AuthorityVector,
        attester_registry: ActivatedAttesterRegistry,
    ) -> Result<Self, KernelError> {
        if now < 0
            || authenticated_at < 0
            || ingress_expires_at <= authenticated_at
            || evaluation_nonce.is_nil()
            || !valid_security_text(&caller_tenant)
            || !valid_security_text(&caller_actor)
            || proposal.tenant != caller_tenant
            || proposal.actor != caller_actor
            || durable_scope.is_some_and(|scope| {
                scope.tenant != proposal.tenant
                    || scope.environment != proposal.template.environment
            })
        {
            return Err(KernelError::InvalidContext(
                "caller identity, durable scope, evaluation nonce, or trusted time is invalid",
            ));
        }
        if now < authenticated_at {
            return Err(KernelError::IngressClockRollback);
        }
        if now >= ingress_expires_at {
            return Err(KernelError::IngressExpired);
        }
        validate_authority_vector(&active_authority)?;
        let policy_root =
            canonical_hash(&policy).map_err(|error| KernelError::Canonical(error.to_string()))?;
        if policy_root != active_authority.policy.root {
            return Err(KernelError::PolicyRootMismatch);
        }
        if attester_registry.authority_domain() != &active_authority.registry {
            return Err(KernelError::AttesterRegistryAuthorityMismatch);
        }
        if ingress_authority_domain != active_authority.principal_registry {
            return Err(KernelError::IngressRegistryAuthorityMismatch);
        }
        Ok(Self {
            control_work: None,
            caller: KernelCaller {
                tenant: caller_tenant,
                actor: caller_actor,
            },
            proposal,
            authenticated_at,
            ingress_expires_at,
            ingress_authority_domain,
            now,
            evaluation_nonce,
            policy,
            active_authority,
            attester_registry,
        })
    }

    #[must_use]
    pub const fn caller(&self) -> &KernelCaller {
        &self.caller
    }

    /// Returns the exact proposal whose signed ingress envelope was accepted.
    #[must_use]
    pub const fn authenticated_proposal(&self) -> &AgentProposal {
        &self.proposal
    }

    #[must_use]
    pub const fn authenticated_at(&self) -> i64 {
        self.authenticated_at
    }

    #[must_use]
    pub const fn ingress_expires_at(&self) -> i64 {
        self.ingress_expires_at
    }

    #[must_use]
    pub const fn ingress_authority_domain(&self) -> &AuthorityDomainState {
        &self.ingress_authority_domain
    }

    #[must_use]
    pub const fn now(&self) -> i64 {
        self.now
    }

    #[must_use]
    pub const fn evaluation_nonce(&self) -> Uuid {
        self.evaluation_nonce
    }

    #[must_use]
    pub const fn policy(&self) -> &PolicyConfig {
        &self.policy
    }

    #[must_use]
    pub const fn active_authority(&self) -> &AuthorityVector {
        &self.active_authority
    }

    #[must_use]
    pub const fn attester_registry(&self) -> &ActivatedAttesterRegistry {
        &self.attester_registry
    }

    /// Evaluates and signs the proposal embedded in durable work, returning
    /// that exact one-shot work authority alongside the signed result.
    ///
    /// Consuming `self` prevents a durable context from authorizing two
    /// independent evaluations, and the API has no proposal argument that a
    /// worker could substitute. No mutable unsigned attestation crosses the
    /// product boundary. The evaluator key must match the kernel-configuration
    /// root in the work authority, and durable state independently repeats that
    /// binding before it records the result.
    ///
    /// # Errors
    ///
    /// Returns the same validation errors as [`evaluate`],
    /// [`KernelError::EvaluatorAuthorityMismatch`] for a substituted signer, or
    /// [`KernelError::InvalidContext`] if called on the legacy synchronous
    /// harness context.
    pub fn evaluate_control(
        self,
        connector_evidence: &TrustedEvidenceSet,
        evaluator: &SigningIdentity,
    ) -> Result<(ControlEvaluationWork, SignedEvaluation), KernelError> {
        if self.control_work.is_none() {
            return Err(KernelError::InvalidContext(
                "durable evaluation requires a control-work capability",
            ));
        }
        let evaluator_root =
            evaluator_verifier_root(evaluator.key_id(), evaluator.public_key_bytes())
                .map_err(|error| KernelError::EvaluationSignature(error.to_string()))?;
        if evaluator_root != self.active_authority.kernel_configuration.root {
            return Err(KernelError::EvaluatorAuthorityMismatch);
        }
        let evaluation = evaluate_inner(&self.proposal, connector_evidence, &self)?;
        let signed_evaluation = sign_evaluation(evaluation, evaluator)?;
        let work = self.control_work.ok_or(KernelError::InvalidContext(
            "durable evaluation requires a control-work capability",
        ))?;
        Ok((work, signed_evaluation))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
// The baseline deliberately models five independent binary checks so the
// comparison does not smuggle AccordLock's lineage graph into the control.
#[allow(clippy::struct_excessive_bools)]
pub struct BaselineFacts {
    pub review_approved: bool,
    pub build_succeeded: bool,
    pub artifact_signature_valid: bool,
    pub artifact_quarantined: bool,
    pub target_current: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineDecision {
    pub allow: bool,
    pub reasons: Vec<String>,
}

#[derive(Debug, Error)]
pub enum KernelError {
    #[error("kernel input exceeds the accepted local profile limits")]
    InputLimitExceeded,
    #[error("canonical encoding failed: {0}")]
    Canonical(String),
    #[error("evaluation signature is invalid: {0}")]
    EvaluationSignature(String),
    #[error("evaluator key does not match the active kernel-configuration authority root")]
    EvaluatorAuthorityMismatch,
    #[error("authorization signature is invalid: {0}")]
    AuthorizationSignature(String),
    #[error("authorization payload does not match the signed bytes")]
    AuthorizationPayloadMismatch,
    #[error("kernel context is invalid: {0}")]
    InvalidContext(&'static str),
    #[error("active policy root does not match the supplied policy")]
    PolicyRootMismatch,
    #[error("attester registry is invalid: {0}")]
    InvalidAttesterRegistry(&'static str),
    #[error("attester registry content root does not match its activated root")]
    AttesterRegistryRootMismatch,
    #[error("activated attester registry does not match the active registry authority domain")]
    AttesterRegistryAuthorityMismatch,
    #[error("authenticated ingress was evaluated after its signed expiry")]
    IngressExpired,
    #[error("kernel trusted time is earlier than ingress authentication time")]
    IngressClockRollback,
    #[error("authenticated ingress registry does not match the active principal registry domain")]
    IngressRegistryAuthorityMismatch,
    #[error("durable control contexts require the consuming evaluate_control operation")]
    DurableContextRequiresConsumingEvaluation,
    #[error("authorization is not executable: {0}")]
    AuthorizationNotExecutable(&'static str),
}

#[derive(Clone, Debug)]
struct VerifiedEvidence {
    assertions: Vec<VerifiedAssertion>,
    reasons: Vec<ReasonCode>,
}

#[derive(Clone, Debug)]
struct VerifiedAssertion {
    assertion: EvidenceAssertion,
    computed_grade: u8,
    principal_id: String,
}

fn valid_security_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SECURITY_TEXT_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_authority_domain(domain: &AuthorityDomainState) -> bool {
    domain.root != Digest32::from_bytes([0; 32]) && !domain.activation_id.is_nil()
}

fn validate_authority_domain(domain: &AuthorityDomainState) -> Result<(), KernelError> {
    if !valid_authority_domain(domain) {
        return Err(KernelError::InvalidAttesterRegistry(
            "registry authority root and activation identifier must be non-zero",
        ));
    }
    Ok(())
}

fn validate_authority_vector(authority: &AuthorityVector) -> Result<(), KernelError> {
    if authority
        .domains()
        .iter()
        .any(|domain| !valid_authority_domain(domain))
    {
        return Err(KernelError::InvalidContext(
            "authority roots and activation identifiers must be non-zero",
        ));
    }
    Ok(())
}

fn append_length_framed(material: &mut Vec<u8>, value: &[u8]) -> Result<(), KernelError> {
    let length = u64::try_from(value.len()).map_err(|_| KernelError::InputLimitExceeded)?;
    material.extend_from_slice(&length.to_be_bytes());
    material.extend_from_slice(value);
    Ok(())
}

fn canonical_scope_material(scope: &AttesterScope) -> Result<Vec<u8>, KernelError> {
    let mut material = Vec::new();
    match scope {
        AttesterScope::Review { repository } => {
            if !valid_security_text(repository) {
                return Err(KernelError::InvalidAttesterRegistry(
                    "attester scope contains an invalid identifier",
                ));
            }
            material.push(0);
            append_length_framed(&mut material, repository.as_bytes())?;
        }
        AttesterScope::Build {
            repository,
            workflow_ref,
        } => {
            if !valid_security_text(repository) || !valid_security_text(workflow_ref) {
                return Err(KernelError::InvalidAttesterRegistry(
                    "attester scope contains an invalid identifier",
                ));
            }
            material.push(1);
            append_length_framed(&mut material, repository.as_bytes())?;
            append_length_framed(&mut material, workflow_ref.as_bytes())?;
        }
        AttesterScope::Artifact { image_repository } => {
            if !valid_security_text(image_repository) {
                return Err(KernelError::InvalidAttesterRegistry(
                    "attester scope contains an invalid identifier",
                ));
            }
            material.push(2);
            append_length_framed(&mut material, image_repository.as_bytes())?;
        }
        AttesterScope::Target {
            cluster_identity,
            namespace,
            deployment_uid,
        } => {
            if !valid_security_text(cluster_identity)
                || !valid_security_text(namespace)
                || !valid_security_text(deployment_uid)
            {
                return Err(KernelError::InvalidAttesterRegistry(
                    "attester scope contains an invalid identifier",
                ));
            }
            material.push(3);
            append_length_framed(&mut material, cluster_identity.as_bytes())?;
            append_length_framed(&mut material, namespace.as_bytes())?;
            append_length_framed(&mut material, deployment_uid.as_bytes())?;
        }
    }
    Ok(material)
}

fn status_code(status: AttesterStatus) -> u8 {
    match status {
        AttesterStatus::Active => 0,
        AttesterStatus::Disabled => 1,
        AttesterStatus::Revoked => 2,
    }
}

#[allow(clippy::too_many_lines)]
fn canonical_attester_registry_material(
    entries: &[RegisteredAttester],
) -> Result<Vec<u8>, KernelError> {
    if entries.is_empty() || entries.len() > MAX_REGISTERED_ATTESTERS {
        return Err(KernelError::InvalidAttesterRegistry(
            "registry cardinality is outside the accepted profile",
        ));
    }

    let mut total_text = 0_usize;
    let mut previous_identity: Option<(&str, &str)> = None;
    let mut public_keys = BTreeSet::new();
    let mut material = Vec::new();
    material.extend_from_slice(ATTESTER_REGISTRY_ROOT_DOMAIN);
    material.extend_from_slice(
        &u64::try_from(entries.len())
            .map_err(|_| KernelError::InputLimitExceeded)?
            .to_be_bytes(),
    );

    for entry in entries {
        let identity = (entry.issuer.as_str(), entry.key_id.as_str());
        let identity_fields = [
            entry.tenant.as_str(),
            entry.environment.as_str(),
            entry.issuer.as_str(),
            entry.key_id.as_str(),
            entry.principal_id.as_str(),
        ];
        if identity_fields
            .iter()
            .any(|value| !valid_security_text(value))
            || identity_fields
                .iter()
                .any(|value| !account_text(&mut total_text, value))
            || entry.scopes.is_empty()
            || entry.scopes.len() > MAX_SCOPES_PER_ATTESTER
            || entry.base_grade > MAX_AUTHORITY_GRADE
            || previous_identity.is_some_and(|previous| previous >= identity)
            || !public_keys.insert(entry.public_key)
            || CoseVerifier::from_public_key(entry.key_id.clone(), entry.public_key).is_err()
        {
            return Err(KernelError::InvalidAttesterRegistry(
                "entries must be valid, strictly identity-sorted, and identity/key unique",
            ));
        }
        previous_identity = Some(identity);

        for field in identity_fields {
            append_length_framed(&mut material, field.as_bytes())?;
        }
        material.extend_from_slice(&entry.public_key);
        material.push(entry.base_grade);
        material.push(status_code(entry.status));
        material.extend_from_slice(
            &u64::try_from(entry.scopes.len())
                .map_err(|_| KernelError::InputLimitExceeded)?
                .to_be_bytes(),
        );

        let mut previous_scope: Option<Vec<u8>> = None;
        for scope in &entry.scopes {
            if !account_scope(&mut total_text, scope) {
                return Err(KernelError::InvalidAttesterRegistry(
                    "attester scope text exceeds the accepted profile",
                ));
            }
            let scope_material = canonical_scope_material(scope)?;
            if previous_scope
                .as_ref()
                .is_some_and(|previous| previous >= &scope_material)
            {
                return Err(KernelError::InvalidAttesterRegistry(
                    "attester scopes must be strictly sorted and duplicate-free",
                ));
            }
            append_length_framed(&mut material, &scope_material)?;
            previous_scope = Some(scope_material);
        }
    }

    Ok(material)
}

fn account_text(total: &mut usize, value: &str) -> bool {
    if value.len() > MAX_SECURITY_TEXT_BYTES {
        return false;
    }
    let Some(next) = total.checked_add(value.len()) else {
        return false;
    };
    if next > MAX_AGGREGATE_SECURITY_TEXT_BYTES {
        return false;
    }
    *total = next;
    true
}

fn account_template(total: &mut usize, template: &accordlock_protocol::DeploymentTemplate) -> bool {
    let required = [
        template.operation.as_str(),
        template.environment.as_str(),
        template.audience.as_str(),
        template.repository.as_str(),
        template.commit_sha.as_str(),
        template.image_repository.as_str(),
        template.cluster_identity.as_str(),
        template.namespace.as_str(),
        template.deployment.as_str(),
        template.deployment_uid.as_str(),
        template.container.as_str(),
        template.resource_version.as_str(),
    ];
    required.iter().all(|value| account_text(total, value))
        && [
            template.prior_transaction_annotation.as_deref(),
            template.prior_authorization_annotation.as_deref(),
            template.prior_operation_hash_annotation.as_deref(),
        ]
        .into_iter()
        .flatten()
        .all(|value| account_text(total, value))
}

fn account_payload(total: &mut usize, payload: &EvidencePayload) -> bool {
    match payload {
        EvidencePayload::Review {
            repository,
            commit_sha,
            review_state_id,
            ..
        } => [
            repository.as_str(),
            commit_sha.as_str(),
            review_state_id.as_str(),
        ]
        .into_iter()
        .all(|value| account_text(total, value)),
        EvidencePayload::Build {
            repository,
            commit_sha,
            workflow_ref,
            run_id,
            ..
        } => [
            repository.as_str(),
            commit_sha.as_str(),
            workflow_ref.as_str(),
            run_id.as_str(),
        ]
        .into_iter()
        .all(|value| account_text(total, value)),
        EvidencePayload::Artifact {
            repository,
            source_run_id,
            ..
        } => [repository.as_str(), source_run_id.as_str()]
            .into_iter()
            .all(|value| account_text(total, value)),
        EvidencePayload::Target {
            cluster_identity,
            namespace,
            deployment,
            deployment_uid,
            resource_version,
            ..
        } => [
            cluster_identity.as_str(),
            namespace.as_str(),
            deployment.as_str(),
            deployment_uid.as_str(),
            resource_version.as_str(),
        ]
        .into_iter()
        .all(|value| account_text(total, value)),
    }
}

fn account_scope(total: &mut usize, scope: &AttesterScope) -> bool {
    match scope {
        AttesterScope::Review { repository }
        | AttesterScope::Artifact {
            image_repository: repository,
        } => account_text(total, repository),
        AttesterScope::Build {
            repository,
            workflow_ref,
        } => account_text(total, repository) && account_text(total, workflow_ref),
        AttesterScope::Target {
            cluster_identity,
            namespace,
            deployment_uid,
        } => {
            account_text(total, cluster_identity)
                && account_text(total, namespace)
                && account_text(total, deployment_uid)
        }
    }
}

fn input_within_profile(
    proposal: &AgentProposal,
    connector_evidence: &TrustedEvidenceSet,
    context: &KernelContext,
) -> bool {
    let policy_lists = [
        &context.policy.allowed_actors,
        &context.policy.allowed_repositories,
        &context.policy.allowed_image_repositories,
        &context.policy.allowed_clusters,
        &context.policy.allowed_namespaces,
    ];
    if connector_evidence.evidence.len() > MAX_EVIDENCE_ITEMS
        || context.attester_registry.entries().len() > MAX_REGISTERED_ATTESTERS
        || policy_lists
            .iter()
            .any(|values| values.len() > MAX_POLICY_ENTRIES_PER_FIELD)
        || context
            .attester_registry
            .entries()
            .iter()
            .any(|attester| attester.scopes.len() > MAX_SCOPES_PER_ATTESTER)
    {
        return false;
    }

    let mut total = 0;
    if !account_text(&mut total, &proposal.tenant)
        || !account_text(&mut total, &proposal.actor)
        || !account_template(&mut total, &proposal.template)
        || !account_text(&mut total, context.caller().tenant())
        || !account_text(&mut total, context.caller().actor())
        || !account_text(&mut total, &context.policy.policy_id)
        || !policy_lists
            .into_iter()
            .flatten()
            .all(|value| account_text(&mut total, value))
    {
        return false;
    }

    let mut aggregate_cose_bytes = 0_usize;
    for signed in &connector_evidence.evidence {
        let Some(next_cose_bytes) = aggregate_cose_bytes.checked_add(signed.cose_sign1.len())
        else {
            return false;
        };
        aggregate_cose_bytes = next_cose_bytes;
        if signed.cose_sign1.len() > MAX_COSE_SIZE_BYTES
            || aggregate_cose_bytes > MAX_AGGREGATE_COSE_BYTES
            || !account_text(&mut total, &signed.assertion.issuer)
            || !account_text(&mut total, &signed.assertion.key_id)
            || !account_text(&mut total, &signed.assertion.source_uri)
            || !account_payload(&mut total, &signed.assertion.payload)
        {
            return false;
        }
    }

    for attester in context.attester_registry.entries() {
        if !account_text(&mut total, &attester.tenant)
            || !account_text(&mut total, &attester.environment)
            || !account_text(&mut total, &attester.issuer)
            || !account_text(&mut total, &attester.key_id)
            || !account_text(&mut total, &attester.principal_id)
            || !attester
                .scopes
                .iter()
                .all(|scope| account_scope(&mut total, scope))
        {
            return false;
        }
    }
    true
}

/// Evaluates authenticated evidence and active policy without consulting a model.
///
/// # Errors
///
/// Returns [`KernelError::Canonical`] if a trusted policy or template cannot be
/// encoded into its deterministic representation.
pub fn evaluate(
    proposal: &AgentProposal,
    connector_evidence: &TrustedEvidenceSet,
    context: &KernelContext,
) -> Result<EvaluationAttestation, KernelError> {
    if context.control_work.is_some() {
        return Err(KernelError::DurableContextRequiresConsumingEvaluation);
    }
    evaluate_inner(proposal, connector_evidence, context)
}

#[allow(clippy::too_many_lines)]
fn evaluate_inner(
    proposal: &AgentProposal,
    connector_evidence: &TrustedEvidenceSet,
    context: &KernelContext,
) -> Result<EvaluationAttestation, KernelError> {
    if !input_within_profile(proposal, connector_evidence, context) {
        return Err(KernelError::InputLimitExceeded);
    }
    let mut reasons = Vec::new();

    if proposal.schema_version != 1 || proposal.template.operation != "DEPLOY_EKS_IMAGE_V1" {
        reasons.push(ReasonCode::UnknownAction);
    }
    if connector_evidence.request_id != proposal.request_id {
        reasons.push(ReasonCode::EvidenceRequestMismatch);
    }
    if proposal != context.authenticated_proposal() {
        reasons.push(ReasonCode::CallerSecurityFactRejected);
    }
    if !is_commit_sha(&proposal.template.commit_sha) {
        reasons.push(ReasonCode::MalformedCommit);
    }
    if !context
        .policy
        .allowed_actors
        .iter()
        .any(|actor| actor == context.caller().actor())
    {
        reasons.push(ReasonCode::ActorNotAllowed);
    }
    if !context
        .policy
        .allowed_repositories
        .contains(&proposal.template.repository)
    {
        reasons.push(ReasonCode::RepositoryNotAllowed);
    }
    if !context
        .policy
        .allowed_image_repositories
        .contains(&proposal.template.image_repository)
    {
        reasons.push(ReasonCode::ImageRepositoryNotAllowed);
    }
    if !context
        .policy
        .allowed_clusters
        .contains(&proposal.template.cluster_identity)
        || !context
            .policy
            .allowed_namespaces
            .contains(&proposal.template.namespace)
    {
        reasons.push(ReasonCode::TargetNotAllowed);
    }

    let computed_policy_root = canonical_hash(&context.policy)
        .map_err(|error| KernelError::Canonical(error.to_string()))?;
    if computed_policy_root != context.active_authority.policy.root {
        reasons.push(ReasonCode::PolicyRootMismatch);
    }

    let verified = verify_evidence(connector_evidence, context, proposal);
    reasons.extend(verified.reasons);
    evaluate_behavior(
        &proposal.template,
        &context.policy,
        &verified.assertions,
        &mut reasons,
    );

    reasons.sort();
    reasons.dedup();
    let allow = reasons.is_empty();
    if allow {
        reasons.push(ReasonCode::Allowed);
    }

    let root_assertions: Vec<_> = verified
        .assertions
        .iter()
        .map(|verified| verified.assertion.clone())
        .collect();
    let evidence_root = evidence_root(&root_assertions)
        .map_err(|error| KernelError::Canonical(error.to_string()))?;
    let mut principals: Vec<_> = verified
        .assertions
        .iter()
        .map(|verified| verified.principal_id.clone())
        .collect();
    principals.sort();
    principals.dedup();
    let template_hash = canonical_hash(&proposal.template)
        .map_err(|error| KernelError::Canonical(error.to_string()))?;
    let consume_before = verified
        .assertions
        .iter()
        .map(|assertion| assertion.assertion.valid_until)
        .chain(std::iter::once(context.now.saturating_add(
            context.policy.maximum_authorization_lifetime_seconds,
        )))
        // The ingress envelope may expire before either the evidence or the
        // policy authorization lifetime.  This bound is carried in the signed
        // evaluation, so the trusted issuance clock cannot mint an authorization from
        // a context that was accepted before expiry and then held past it.
        .chain(std::iter::once(context.ingress_expires_at()))
        .min()
        .unwrap_or(context.now);

    Ok(EvaluationAttestation {
        schema_version: EVALUATION_ATTESTATION_SCHEMA_VERSION,
        request_id: proposal.request_id,
        evaluation_nonce: context.evaluation_nonce,
        tenant: context.caller().tenant().to_owned(),
        actor: context.caller().actor().to_owned(),
        evaluated_at: context.now,
        outcome: if allow {
            DecisionOutcome::Allow
        } else {
            DecisionOutcome::Deny
        },
        reasons,
        template_hash,
        evidence_root,
        principals,
        policy_root: computed_policy_root,
        authority: context.active_authority.clone(),
        consume_before,
    })
}

fn verify_evidence(
    input: &TrustedEvidenceSet,
    context: &KernelContext,
    proposal: &AgentProposal,
) -> VerifiedEvidence {
    let mut registry: BTreeMap<(&str, &str), &RegisteredAttester> = BTreeMap::new();
    let mut registered_public_keys = BTreeSet::new();
    for entry in context.attester_registry.entries() {
        let identity = (entry.issuer.as_str(), entry.key_id.as_str());
        let invalid_entry = entry.tenant.is_empty()
            || entry.environment.is_empty()
            || entry.issuer.is_empty()
            || entry.key_id.is_empty()
            || entry.principal_id.is_empty()
            || entry.scopes.is_empty()
            || entry.base_grade > MAX_AUTHORITY_GRADE
            || accordlock_protocol::CoseVerifier::from_public_key(
                entry.key_id.clone(),
                entry.public_key,
            )
            .is_err();
        if invalid_entry
            || registry.insert(identity, entry).is_some()
            || !registered_public_keys.insert(entry.public_key)
        {
            return VerifiedEvidence {
                assertions: Vec::new(),
                reasons: vec![ReasonCode::EvidenceDefective],
            };
        }
    }
    let mut assertions = Vec::new();
    let mut reasons = Vec::new();
    let mut evidence_ids = BTreeSet::new();

    for signed in &input.evidence {
        let assertion = &signed.assertion;
        if !evidence_ids.insert(assertion.evidence_id) {
            reasons.push(ReasonCode::EvidenceDefective);
            continue;
        }
        let Some(attester) = registry.get(&(assertion.issuer.as_str(), assertion.key_id.as_str()))
        else {
            reasons.push(ReasonCode::AttesterNotRegistered);
            continue;
        };
        let kind = assertion.payload.kind();
        if attester.tenant != proposal.tenant
            || attester.environment != proposal.template.environment
            || attester.status != AttesterStatus::Active
            || !attester
                .scopes
                .iter()
                .any(|scope| scope_matches(scope, &assertion.payload))
        {
            reasons.push(ReasonCode::AttesterScopeViolation);
            continue;
        }

        let Ok(verifier) = accordlock_protocol::CoseVerifier::from_public_key(
            attester.key_id.clone(),
            attester.public_key,
        ) else {
            reasons.push(ReasonCode::EvidenceSignatureInvalid);
            continue;
        };
        let Ok(payload) = verify_cose(&signed.cose_sign1, kind.domain(), &verifier) else {
            reasons.push(ReasonCode::EvidenceSignatureInvalid);
            continue;
        };
        let Ok(expected_payload) = assertion.canonical_bytes() else {
            reasons.push(ReasonCode::EvidenceSignatureInvalid);
            continue;
        };
        if payload != expected_payload {
            reasons.push(ReasonCode::EvidenceSignatureInvalid);
            continue;
        }
        if let Some(reason) = assertion_profile_error(assertion, input, proposal) {
            reasons.push(reason);
            continue;
        }

        if assertion.observed_at > context.now {
            reasons.push(ReasonCode::EvidenceFromFuture);
        }
        if assertion.valid_until <= assertion.observed_at {
            reasons.push(ReasonCode::InvalidValidityWindow);
        }
        if assertion.valid_until <= context.now
            || context.now.saturating_sub(assertion.observed_at)
                > context.policy.maximum_evidence_age_seconds
        {
            reasons.push(ReasonCode::EvidenceStale);
        }
        if assertion.authority != context.active_authority {
            reasons.push(ReasonCode::AuthorityEpochMismatch);
        }
        assertions.push(VerifiedAssertion {
            assertion: assertion.clone(),
            computed_grade: attester.base_grade,
            principal_id: attester.principal_id.clone(),
        });
    }

    VerifiedEvidence {
        assertions,
        reasons,
    }
}

fn assertion_profile_error(
    assertion: &EvidenceAssertion,
    evidence_set: &TrustedEvidenceSet,
    proposal: &AgentProposal,
) -> Option<ReasonCode> {
    if assertion.schema_version != EVIDENCE_ASSERTION_SCHEMA_VERSION {
        Some(ReasonCode::EvidenceDefective)
    } else if assertion.request_id != evidence_set.request_id
        || assertion.request_id != proposal.request_id
    {
        Some(ReasonCode::EvidenceRequestMismatch)
    } else {
        None
    }
}

fn scope_matches(scope: &AttesterScope, payload: &EvidencePayload) -> bool {
    match (scope, payload) {
        (
            AttesterScope::Review {
                repository: allowed,
            },
            EvidencePayload::Review { repository, .. },
        )
        | (
            AttesterScope::Artifact {
                image_repository: allowed,
            },
            EvidencePayload::Artifact { repository, .. },
        ) => allowed == repository,
        (
            AttesterScope::Build {
                repository: allowed_repository,
                workflow_ref: allowed_workflow,
            },
            EvidencePayload::Build {
                repository,
                workflow_ref,
                ..
            },
        ) => allowed_repository == repository && allowed_workflow == workflow_ref,
        (
            AttesterScope::Target {
                cluster_identity: allowed_cluster,
                namespace: allowed_namespace,
                deployment_uid: allowed_uid,
            },
            EvidencePayload::Target {
                cluster_identity,
                namespace,
                deployment_uid,
                ..
            },
        ) => {
            allowed_cluster == cluster_identity
                && allowed_namespace == namespace
                && allowed_uid == deployment_uid
        }
        _ => false,
    }
}

#[allow(clippy::too_many_lines)]
fn evaluate_behavior(
    template: &accordlock_protocol::DeploymentTemplate,
    policy: &PolicyConfig,
    evidence: &[VerifiedAssertion],
    reasons: &mut Vec<ReasonCode>,
) {
    let reviews: Vec<_> = evidence
        .iter()
        .filter(|value| value.assertion.payload.kind() == EvidenceKind::Review)
        .collect();
    if reviews.is_empty() {
        reasons.push(ReasonCode::MissingReview);
    }
    let mut matching_review = false;
    for review in reviews {
        if let EvidencePayload::Review {
            repository,
            commit_sha,
            approved,
            ..
        } = &review.assertion.payload
        {
            if repository != &template.repository || commit_sha != &template.commit_sha {
                reasons.push(ReasonCode::ReviewCommitMismatch);
                continue;
            }
            matching_review = true;
            if !approved {
                reasons.push(ReasonCode::ReviewNotApproved);
            }
            if review.computed_grade < policy.minimum_review_grade {
                reasons.push(ReasonCode::ReviewGradeInsufficient);
            }
        }
    }
    if !matching_review && !evidence.is_empty() {
        reasons.push(ReasonCode::MissingReview);
    }

    let builds: Vec<_> = evidence
        .iter()
        .filter(|value| value.assertion.payload.kind() == EvidenceKind::Build)
        .collect();
    if builds.is_empty() {
        reasons.push(ReasonCode::MissingBuild);
    }
    let mut matching_builds: Vec<(&str, Digest32)> = Vec::new();
    for build in builds {
        if let EvidencePayload::Build {
            repository,
            commit_sha,
            run_id,
            succeeded,
            completeness_profile,
            output_digest,
            ..
        } = &build.assertion.payload
        {
            if repository != &template.repository || commit_sha != &template.commit_sha {
                reasons.push(ReasonCode::BuildCommitMismatch);
                continue;
            }
            if !succeeded {
                reasons.push(ReasonCode::BuildFailed);
            }
            if build.computed_grade < policy.minimum_build_grade {
                reasons.push(ReasonCode::BuildGradeInsufficient);
            }
            if *completeness_profile != CompletenessProfile::HermeticInputsV1 {
                reasons.push(ReasonCode::EvidenceDefective);
            }
            matching_builds.push((run_id.as_str(), *output_digest));
        }
    }

    let artifacts: Vec<_> = evidence
        .iter()
        .filter(|value| value.assertion.payload.kind() == EvidenceKind::Artifact)
        .collect();
    if artifacts.is_empty() {
        reasons.push(ReasonCode::MissingArtifact);
    }
    let mut matching_artifact = false;
    for artifact in artifacts {
        if let EvidencePayload::Artifact {
            repository,
            digest,
            source_run_id,
            signature_valid,
            quarantined,
        } = &artifact.assertion.payload
        {
            if repository != &template.image_repository || digest != &template.image_digest {
                continue;
            }
            matching_artifact = true;
            if !signature_valid {
                reasons.push(ReasonCode::ArtifactSignatureInvalid);
            }
            if *quarantined {
                reasons.push(ReasonCode::ArtifactQuarantined);
            }
            if !matching_builds
                .iter()
                .any(|(run_id, output)| *run_id == source_run_id && *output == *digest)
            {
                reasons.push(ReasonCode::TransformOutputMismatch);
            }
        }
    }
    if !matching_artifact {
        reasons.push(ReasonCode::TransformOutputMismatch);
    }

    let targets: Vec<_> = evidence
        .iter()
        .filter(|value| value.assertion.payload.kind() == EvidenceKind::Target)
        .collect();
    if targets.is_empty() {
        reasons.push(ReasonCode::MissingTargetSnapshot);
    }
    let mut matching_target = false;
    for target in targets {
        if let EvidencePayload::Target {
            cluster_identity,
            namespace,
            deployment,
            deployment_uid,
            resource_version,
            current_image,
            projection_hash,
        } = &target.assertion.payload
        {
            if cluster_identity != &template.cluster_identity
                || namespace != &template.namespace
                || deployment != &template.deployment
                || deployment_uid != &template.deployment_uid
            {
                reasons.push(ReasonCode::TargetIdentityMismatch);
                continue;
            }
            matching_target = true;
            if resource_version != &template.resource_version
                || current_image != &template.prior_image_digest
                || projection_hash != &template.prior_projection_hash
            {
                reasons.push(ReasonCode::TargetStateMismatch);
            }
        }
    }
    if !matching_target && !evidence.is_empty() {
        reasons.push(ReasonCode::MissingTargetSnapshot);
    }
}

/// Signs an evaluation attestation under the evaluation-only COSE domain.
///
/// # Errors
///
/// Returns [`KernelError`] when canonical encoding or signing fails.
pub fn sign_evaluation(
    attestation: EvaluationAttestation,
    evaluator: &SigningIdentity,
) -> Result<SignedEvaluation, KernelError> {
    let payload = attestation
        .canonical_bytes()
        .map_err(|error| KernelError::Canonical(error.to_string()))?;
    let cose_sign1 = sign_cose(&payload, EVALUATION_DOMAIN, evaluator)
        .map_err(|error| KernelError::EvaluationSignature(error.to_string()))?;
    Ok(SignedEvaluation {
        attestation,
        cose_sign1,
    })
}

fn digest_is_zero(value: Digest32) -> bool {
    value == Digest32::from_bytes([0; 32])
}

fn validate_dispatch_policy_at(
    policy: &accordlock_protocol::DispatchDeadlinePolicy,
    now: i64,
    consume_before: i64,
) -> Result<(), KernelError> {
    if policy.max_dispatch_delay_seconds <= 0
        || policy.profile_hard_cap <= now
        || policy.immutable_dependency_expiries.len() > MAX_IMMUTABLE_DEPENDENCY_EXPIRIES
        || policy
            .immutable_dependency_expiries
            .iter()
            .any(|expiry| *expiry <= now)
        || policy
            .immutable_dependency_expiries
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(KernelError::AuthorizationNotExecutable(
            "dispatch deadline policy is invalid, expired, or noncanonical",
        ));
    }
    let delay_deadline = now.checked_add(policy.max_dispatch_delay_seconds).ok_or(
        KernelError::AuthorizationNotExecutable("dispatch deadline overflows trusted time"),
    )?;
    let mut deadline = delay_deadline
        .min(consume_before)
        .min(policy.profile_hard_cap);
    for expiry in &policy.immutable_dependency_expiries {
        deadline = deadline.min(*expiry);
    }
    if deadline <= now {
        return Err(KernelError::AuthorizationNotExecutable(
            "dispatch policy leaves no executable interval",
        ));
    }
    Ok(())
}

fn validate_executable_authorization_fields(
    authorization: &ExecutionAuthorization,
    now: i64,
) -> Result<(), KernelError> {
    let template = &authorization.template;
    let required = [
        authorization.tenant.as_str(),
        authorization.holder.as_str(),
        authorization.audience.as_str(),
        template.operation.as_str(),
        template.environment.as_str(),
        template.audience.as_str(),
        template.repository.as_str(),
        template.commit_sha.as_str(),
        template.image_repository.as_str(),
        template.cluster_identity.as_str(),
        template.namespace.as_str(),
        template.deployment.as_str(),
        template.deployment_uid.as_str(),
        template.container.as_str(),
        template.resource_version.as_str(),
    ];
    if required.iter().any(|value| !valid_security_text(value))
        || !is_commit_sha(&template.commit_sha)
        || [
            template.prior_transaction_annotation.as_deref(),
            template.prior_authorization_annotation.as_deref(),
            template.prior_operation_hash_annotation.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|value| !valid_security_text(value))
    {
        return Err(KernelError::AuthorizationNotExecutable(
            "authorization scope, operation, or resource identity is malformed",
        ));
    }
    if authorization.principals.is_empty()
        || authorization.principals.len() > MAX_AUTHORIZATION_PRINCIPALS
        || authorization
            .principals
            .iter()
            .any(|principal| !valid_security_text(principal))
        || authorization
            .principals
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(KernelError::AuthorizationNotExecutable(
            "authorization principals must be bounded, nonempty, sorted, and duplicate-free",
        ));
    }
    if [
        authorization.template_hash,
        authorization.evidence_root,
        authorization.policy_root,
        template.image_digest,
        template.prior_image_digest,
        template.prior_projection_hash,
    ]
    .into_iter()
    .any(digest_is_zero)
    {
        return Err(KernelError::AuthorizationNotExecutable(
            "authorization security commitments must be non-zero",
        ));
    }
    if authorization
        .authority
        .domains()
        .iter()
        .any(|domain| !valid_authority_domain(domain))
    {
        return Err(KernelError::AuthorizationNotExecutable(
            "authorization authority roots and activation identifiers must be non-zero",
        ));
    }
    validate_dispatch_policy_at(
        &authorization.dispatch_deadline_policy,
        now,
        authorization.consume_before,
    )
}

/// Explicit caller-provided inputs for contextual authorization verification.
///
/// Construction of this value does not establish that its time or authority
/// vector is current. Productive dispatch requires durable consumption, an
/// exclusive state-backed claim, exact current-state revalidation, and the
/// one-shot `ATTEMPT_IN_FLIGHT` commit. The kernel intentionally manufactures
/// none of those state capabilities.
#[derive(Clone, Copy, Debug)]
pub struct ExplicitAuthorizationVerificationContext<'a> {
    now: i64,
    expected_audience: &'a str,
    supplied_authority: &'a AuthorityVector,
}

impl<'a> ExplicitAuthorizationVerificationContext<'a> {
    /// Creates an explicit authorization-verification context.
    ///
    /// The caller remains responsible for the provenance and freshness of all
    /// three inputs. Success only means that the signed authorization agrees with
    /// these supplied values.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError`] if time, audience, or an active authority-domain
    /// identity is malformed.
    pub fn new(
        now: i64,
        expected_audience: &'a str,
        supplied_authority: &'a AuthorityVector,
    ) -> Result<Self, KernelError> {
        if now < 0 || !valid_security_text(expected_audience) {
            return Err(KernelError::InvalidContext(
                "authorization verification time or audience is invalid",
            ));
        }
        validate_authority_vector(supplied_authority)?;
        Ok(Self {
            now,
            expected_audience,
            supplied_authority,
        })
    }

    #[must_use]
    pub const fn now(self) -> i64 {
        self.now
    }

    #[must_use]
    pub const fn expected_audience(self) -> &'a str {
        self.expected_audience
    }

    #[must_use]
    pub const fn supplied_authority(self) -> &'a AuthorityVector {
        self.supplied_authority
    }
}

/// Opaque marker that an authorization passed signature, canonical-form, intrinsic,
/// and explicit caller-provided context checks.
///
/// This marker is not proof of current authority, revocation state, durable
/// consumption, or dispatch eligibility.
#[derive(Clone, Debug)]
pub struct ContextVerifiedAuthorization {
    authorization: ExecutionAuthorization,
    authorization_hash: Digest32,
}

impl ContextVerifiedAuthorization {
    /// Returns the verified authorization payload.
    #[must_use]
    pub const fn authorization(&self) -> &ExecutionAuthorization {
        &self.authorization
    }

    /// Returns the canonical authorization commitment checked during verification.
    #[must_use]
    pub const fn authorization_hash(&self) -> Digest32 {
        self.authorization_hash
    }

    /// Returns the canonical profile marker whose signed encoding requires
    /// durable single-use consumption.
    #[must_use]
    pub const fn single_use_profile(&self) -> u8 {
        EXECUTION_AUTHORIZATION_SINGLE_USE_PROFILE
    }
}

/// Verifies only the authorization's domain-separated signature and canonical payload.
///
/// Passing this check does not establish that the authorization is current,
/// authorized for an executor audience, or bound to active authority. Runtime
/// contextual checks must use [`verify_authorization_in_explicit_context`] or
/// [`verify_authorization`]. Neither function establishes current state.
///
/// # Errors
///
/// Returns [`KernelError`] if the signature, COSE profile, or bound payload is
/// invalid.
pub fn verify_authorization_signature(
    signed_authorization: &SignedAuthorization,
    verifier: &CoseVerifier,
) -> Result<(), KernelError> {
    let signed_payload = verify_cose(
        &signed_authorization.cose_sign1,
        EXECUTION_AUTHORIZATION_DOMAIN,
        verifier,
    )
    .map_err(|error| KernelError::AuthorizationSignature(error.to_string()))?;
    let expected_payload = signed_authorization
        .authorization
        .canonical_bytes()
        .map_err(|error| KernelError::Canonical(error.to_string()))?;
    if signed_payload != expected_payload {
        return Err(KernelError::AuthorizationPayloadMismatch);
    }
    Ok(())
}

/// Verifies a signed action authorization against an explicit caller-provided context.
///
/// This validates the v2/single-use canonical profile, exact active authority
/// and signer root, audience, current validity interval, nonempty dispatch
/// window, identifiers, principals, resource fields, and all security
/// commitments. The returned marker is not a consumption receipt. Durable
/// state must still enforce the single-use transition. This function does not
/// establish that the supplied time or authority is current. Dispatch code must
/// use the state-backed claim and one-shot attempt boundary instead.
///
/// # Errors
///
/// Returns [`KernelError`] for signature/canonical failure or any intrinsic or
/// supplied-context mismatch.
pub fn verify_authorization_in_explicit_context(
    signed_authorization: &SignedAuthorization,
    verifier: &CoseVerifier,
    context: &ExplicitAuthorizationVerificationContext<'_>,
) -> Result<ContextVerifiedAuthorization, KernelError> {
    verify_authorization_signature(signed_authorization, verifier)?;
    let authorization = &signed_authorization.authorization;

    if authorization.schema_version != EXECUTION_AUTHORIZATION_SCHEMA_VERSION {
        return Err(KernelError::AuthorizationNotExecutable(
            "unsupported execution-authorization schema or profile",
        ));
    }
    if [
        authorization.authorization_id,
        authorization.evaluation_nonce,
        authorization.request_id,
        authorization.grant_id,
    ]
    .iter()
    .any(Uuid::is_nil)
    {
        return Err(KernelError::AuthorizationNotExecutable(
            "authorization identifiers must be non-nil",
        ));
    }
    if authorization.issued_at < 0
        || authorization.issued_at > context.now
        || authorization.not_before < authorization.issued_at
        || authorization.not_before > context.now
        || authorization.consume_before <= context.now
    {
        return Err(KernelError::AuthorizationNotExecutable(
            "authorization validity interval is empty, future, or expired",
        ));
    }
    if authorization.authority != *context.supplied_authority {
        return Err(KernelError::AuthorizationNotExecutable(
            "authorization authority is not the exact supplied authority vector",
        ));
    }
    if authorization.audience != context.expected_audience
        || authorization.template.audience != context.expected_audience
    {
        return Err(KernelError::AuthorizationNotExecutable(
            "authorization and template audience do not match the executor audience",
        ));
    }
    validate_executable_authorization_fields(authorization, context.now)?;

    let signer_root = authorization_signer_root(verifier.key_id(), verifier.public_key_bytes())
        .map_err(|error| KernelError::AuthorizationSignature(error.to_string()))?;
    if signer_root != context.supplied_authority.signer.root {
        return Err(KernelError::AuthorizationNotExecutable(
            "authorization verifier does not match the supplied signer authority root",
        ));
    }
    let template_hash = canonical_hash(&authorization.template)
        .map_err(|error| KernelError::Canonical(error.to_string()))?;
    if authorization.template_hash != template_hash {
        return Err(KernelError::AuthorizationNotExecutable(
            "template hash does not match the canonical template",
        ));
    }
    if authorization.policy_root != authorization.authority.policy.root {
        return Err(KernelError::AuthorizationNotExecutable(
            "policy root does not match the authorization authority",
        ));
    }
    let authorization_hash =
        canonical_hash(authorization).map_err(|error| KernelError::Canonical(error.to_string()))?;
    Ok(ContextVerifiedAuthorization {
        authorization: authorization.clone(),
        authorization_hash,
    })
}

/// Verifies an authorization against explicit caller-provided time, audience, and
/// authority inputs.
///
/// This cannot be called without an explicit context, but neither the context
/// nor the returned marker proves currentness. Use the durable state-backed
/// claim, revalidation, and one-shot attempt boundary before an external effect.
///
/// # Errors
///
/// Returns the same errors as [`verify_authorization_in_explicit_context`].
pub fn verify_authorization(
    signed_authorization: &SignedAuthorization,
    verifier: &CoseVerifier,
    context: &ExplicitAuthorizationVerificationContext<'_>,
) -> Result<ContextVerifiedAuthorization, KernelError> {
    verify_authorization_in_explicit_context(signed_authorization, verifier, context)
}

#[must_use]
pub fn evaluate_plain_policy(
    proposal: &AgentProposal,
    policy: &PolicyConfig,
    facts: &BaselineFacts,
) -> BaselineDecision {
    let mut reasons = Vec::new();
    if proposal.template.operation != "DEPLOY_EKS_IMAGE_V1" {
        reasons.push("UNKNOWN_ACTION".to_owned());
    }
    if !policy.allowed_actors.contains(&proposal.actor) {
        reasons.push("ACTOR_NOT_ALLOWED".to_owned());
    }
    if !policy
        .allowed_repositories
        .contains(&proposal.template.repository)
    {
        reasons.push("REPOSITORY_NOT_ALLOWED".to_owned());
    }
    if !policy
        .allowed_image_repositories
        .contains(&proposal.template.image_repository)
    {
        reasons.push("IMAGE_REPOSITORY_NOT_ALLOWED".to_owned());
    }
    if !policy
        .allowed_clusters
        .contains(&proposal.template.cluster_identity)
        || !policy
            .allowed_namespaces
            .contains(&proposal.template.namespace)
    {
        reasons.push("TARGET_NOT_ALLOWED".to_owned());
    }
    if !facts.review_approved {
        reasons.push("REVIEW_NOT_APPROVED".to_owned());
    }
    if !facts.build_succeeded {
        reasons.push("BUILD_FAILED".to_owned());
    }
    if !facts.artifact_signature_valid {
        reasons.push("ARTIFACT_SIGNATURE_INVALID".to_owned());
    }
    if facts.artifact_quarantined {
        reasons.push("ARTIFACT_QUARANTINED".to_owned());
    }
    if !facts.target_current {
        reasons.push("TARGET_NOT_CURRENT".to_owned());
    }
    BaselineDecision {
        allow: reasons.is_empty(),
        reasons,
    }
}

fn is_commit_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use accordlock_ingress::{
        ActivatedIngressRegistry, INGRESS_SCHEMA_VERSION, IngressAuthenticator, IngressClaims,
        IngressKeyStatus, IngressRecoveryProbe, MemoryReplayGuard, RegisteredIngressKey,
        sign_ingress_request,
    };
    use accordlock_protocol::{
        AttesterScope, AttesterStatus, AuthorityDomainState, CompletenessProfile,
        DeploymentTemplate, DispatchDeadlinePolicy, EvidencePayload, SignedEvidence,
    };
    use accordlock_state::{
        ClaimedControlWork, ControlPlaneState, ControlSubmissionIntakeOutcome,
        ControlWorkClaimOutcome, ControlWorkClaimRequest, ControlWorkerRole, InMemoryStore,
        StateError, TransactionalState, TrustedClock,
    };

    #[derive(Debug)]
    struct FixedClock(i64);

    impl TrustedClock for FixedClock {
        fn now_unix_seconds(&self) -> Result<i64, StateError> {
            Ok(self.0)
        }
    }

    fn domain(seed: u8) -> AuthorityDomainState {
        AuthorityDomainState {
            root: Digest32::from_bytes([seed; 32]),
            epoch: u64::from(seed),
            activation_id: Uuid::from_bytes([seed; 16]),
        }
    }

    fn authority(policy_root: Digest32) -> AuthorityVector {
        let mut vector = AuthorityVector {
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
        };
        vector.policy.root = policy_root;
        vector
    }

    fn policy() -> PolicyConfig {
        PolicyConfig {
            policy_id: "deploy-prod-v1".to_owned(),
            allowed_actors: vec!["agent:deployer".to_owned()],
            allowed_repositories: vec!["acme/payments".to_owned()],
            allowed_image_repositories: vec!["acme/payments".to_owned()],
            allowed_clusters: vec!["kind://accordlock".to_owned()],
            allowed_namespaces: vec!["payments-prod".to_owned()],
            minimum_review_grade: 2,
            minimum_build_grade: 2,
            maximum_evidence_age_seconds: 60,
            maximum_authorization_lifetime_seconds: 60,
        }
    }

    fn proposal() -> AgentProposal {
        AgentProposal {
            schema_version: 1,
            request_id: Uuid::from_bytes([20; 16]),
            tenant: "acme".to_owned(),
            actor: "agent:deployer".to_owned(),
            template: DeploymentTemplate {
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
            },
        }
    }

    fn ingress_registration(
        proposal: &AgentProposal,
        signer: &SigningIdentity,
    ) -> RegisteredIngressKey {
        RegisteredIngressKey {
            key_id: signer.key_id().to_owned(),
            public_key: signer.public_key_bytes(),
            tenant: proposal.tenant.clone(),
            actor: proposal.actor.clone(),
            allowed_audiences: BTreeSet::from([proposal.template.audience.clone()]),
            not_before: 900,
            expires_at: 1_200,
            status: IngressKeyStatus::Active,
        }
    }

    fn authenticated_ingress(
        proposal: &AgentProposal,
        authority_domain: AuthorityDomainState,
        authenticated_at: i64,
        expires_at: i64,
    ) -> Result<AuthenticatedIngressRequest, Box<dyn std::error::Error>> {
        let signer = SigningIdentity::from_seed("ingress-agent", [0x31; 32]);
        let registry = ActivatedIngressRegistry::new(
            authority_domain,
            proposal.template.audience.clone(),
            120,
            vec![ingress_registration(proposal, &signer)],
        )?;
        let authenticator = IngressAuthenticator::new(registry, MemoryReplayGuard::default())?;
        let claims = IngressClaims {
            schema_version: INGRESS_SCHEMA_VERSION,
            audience: proposal.template.audience.clone(),
            issued_at: authenticated_at.saturating_sub(1),
            expires_at,
            nonce: Uuid::from_u128(0x3101),
            proposal: proposal.clone(),
        };
        let wire = serde_json::to_string(&sign_ingress_request(claims, &signer)?)?;
        Ok(authenticator.authenticate_json(&wire, authenticated_at)?)
    }

    fn activate_ingress_root(
        proposal: &AgentProposal,
        authority_domain: &mut AuthorityDomainState,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let signer = SigningIdentity::from_seed("ingress-agent", [0x31; 32]);
        authority_domain.root = ActivatedIngressRegistry::compute_root(
            &proposal.template.audience,
            120,
            &[ingress_registration(proposal, &signer)],
        )?;
        Ok(())
    }

    fn sign_evidence(
        signer: &SigningIdentity,
        authority: &AuthorityVector,
        request_id: Uuid,
        payload: EvidencePayload,
        id: u8,
    ) -> Result<SignedEvidence, Box<dyn std::error::Error>> {
        let assertion = EvidenceAssertion {
            schema_version: EVIDENCE_ASSERTION_SCHEMA_VERSION,
            request_id,
            evidence_id: Uuid::from_bytes([id; 16]),
            issuer: signer.key_id().to_owned(),
            key_id: signer.key_id().to_owned(),
            source_uri: format!("test://{}/record", signer.key_id()),
            observed_at: 1_000,
            valid_until: 1_100,
            authority: authority.clone(),
            payload,
        };
        let bytes = assertion.canonical_bytes()?;
        let cose_sign1 = sign_cose(&bytes, assertion.payload.kind().domain(), signer)?;
        Ok(SignedEvidence {
            assertion,
            cose_sign1,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn fixture()
    -> Result<(AgentProposal, TrustedEvidenceSet, KernelContext), Box<dyn std::error::Error>> {
        let policy = policy();
        let policy_root = canonical_hash(&policy)?;
        let mut authority = authority(policy_root);
        let evaluator = SigningIdentity::from_seed("durable-kernel-evaluator", [0x34; 32]);
        authority.kernel_configuration.root =
            evaluator_verifier_root(evaluator.key_id(), evaluator.public_key_bytes())?;
        let proposal = proposal();
        activate_ingress_root(&proposal, &mut authority.principal_registry)?;
        let review = SigningIdentity::from_seed("github", [1; 32]);
        let build = SigningIdentity::from_seed("actions", [2; 32]);
        let artifact = SigningIdentity::from_seed("ecr", [3; 32]);
        let target = SigningIdentity::from_seed("kubernetes", [4; 32]);
        let mut attesters = vec![
            RegisteredAttester {
                tenant: proposal.tenant.clone(),
                environment: proposal.template.environment.clone(),
                issuer: review.key_id().to_owned(),
                key_id: review.key_id().to_owned(),
                public_key: review.public_key_bytes(),
                principal_id: "party:reviewer".to_owned(),
                base_grade: 3,
                status: AttesterStatus::Active,
                scopes: vec![AttesterScope::Review {
                    repository: proposal.template.repository.clone(),
                }],
            },
            RegisteredAttester {
                tenant: proposal.tenant.clone(),
                environment: proposal.template.environment.clone(),
                issuer: build.key_id().to_owned(),
                key_id: build.key_id().to_owned(),
                public_key: build.public_key_bytes(),
                principal_id: "workload:github-actions".to_owned(),
                base_grade: 3,
                status: AttesterStatus::Active,
                scopes: vec![AttesterScope::Build {
                    repository: proposal.template.repository.clone(),
                    workflow_ref: ".github/workflows/release.yml@refs/heads/main".to_owned(),
                }],
            },
            RegisteredAttester {
                tenant: proposal.tenant.clone(),
                environment: proposal.template.environment.clone(),
                issuer: artifact.key_id().to_owned(),
                key_id: artifact.key_id().to_owned(),
                public_key: artifact.public_key_bytes(),
                principal_id: "service:ecr".to_owned(),
                base_grade: 3,
                status: AttesterStatus::Active,
                scopes: vec![AttesterScope::Artifact {
                    image_repository: proposal.template.image_repository.clone(),
                }],
            },
            RegisteredAttester {
                tenant: proposal.tenant.clone(),
                environment: proposal.template.environment.clone(),
                issuer: target.key_id().to_owned(),
                key_id: target.key_id().to_owned(),
                public_key: target.public_key_bytes(),
                principal_id: "service:kubernetes".to_owned(),
                base_grade: 3,
                status: AttesterStatus::Active,
                scopes: vec![AttesterScope::Target {
                    cluster_identity: proposal.template.cluster_identity.clone(),
                    namespace: proposal.template.namespace.clone(),
                    deployment_uid: proposal.template.deployment_uid.clone(),
                }],
            },
        ];
        attesters.sort_by(|left, right| {
            (&left.issuer, &left.key_id).cmp(&(&right.issuer, &right.key_id))
        });
        authority.registry.root = ActivatedAttesterRegistry::compute_root(&attesters)?;
        let attester_registry =
            ActivatedAttesterRegistry::new(authority.registry.clone(), attesters)?;
        let evidence = vec![
            sign_evidence(
                &review,
                &authority,
                proposal.request_id,
                EvidencePayload::Review {
                    repository: proposal.template.repository.clone(),
                    commit_sha: proposal.template.commit_sha.clone(),
                    approved: true,
                    review_state_id: "review-1".to_owned(),
                },
                1,
            )?,
            sign_evidence(
                &build,
                &authority,
                proposal.request_id,
                EvidencePayload::Build {
                    repository: proposal.template.repository.clone(),
                    commit_sha: proposal.template.commit_sha.clone(),
                    workflow_ref: ".github/workflows/release.yml@refs/heads/main".to_owned(),
                    run_id: "9001".to_owned(),
                    succeeded: true,
                    input_manifest_root: Digest32::from_bytes([0x10; 32]),
                    completeness_profile: CompletenessProfile::HermeticInputsV1,
                    output_digest: proposal.template.image_digest,
                },
                2,
            )?,
            sign_evidence(
                &artifact,
                &authority,
                proposal.request_id,
                EvidencePayload::Artifact {
                    repository: proposal.template.image_repository.clone(),
                    digest: proposal.template.image_digest,
                    source_run_id: "9001".to_owned(),
                    signature_valid: true,
                    quarantined: false,
                },
                3,
            )?,
            sign_evidence(
                &target,
                &authority,
                proposal.request_id,
                EvidencePayload::Target {
                    cluster_identity: proposal.template.cluster_identity.clone(),
                    namespace: proposal.template.namespace.clone(),
                    deployment: proposal.template.deployment.clone(),
                    deployment_uid: proposal.template.deployment_uid.clone(),
                    resource_version: proposal.template.resource_version.clone(),
                    current_image: proposal.template.prior_image_digest,
                    projection_hash: proposal.template.prior_projection_hash,
                },
                4,
            )?,
        ];
        let ingress = authenticated_ingress(
            &proposal,
            authority.principal_registry.clone(),
            1_010,
            1_070,
        )?;
        let context = KernelContext::from_authenticated_ingress(
            ingress,
            1_010,
            Uuid::from_bytes([30; 16]),
            policy,
            authority,
            attester_registry,
        )?;
        Ok((
            proposal.clone(),
            TrustedEvidenceSet {
                request_id: proposal.request_id,
                evidence,
            },
            context,
        ))
    }

    fn authorization_fixture()
    -> Result<(SigningIdentity, AuthorityVector, ExecutionAuthorization), KernelError> {
        let signer = SigningIdentity::from_seed("authorization-signer", [0x71; 32]);
        let policy_root = Digest32::from_bytes([0x72; 32]);
        let mut active_authority = authority(policy_root);
        active_authority.signer.root =
            authorization_signer_root(signer.key_id(), signer.public_key_bytes())
                .map_err(|error| KernelError::AuthorizationSignature(error.to_string()))?;
        let template = proposal().template;
        let authorization = ExecutionAuthorization {
            schema_version: EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
            authorization_id: Uuid::from_u128(0x7101),
            evaluation_nonce: Uuid::from_u128(0x7102),
            request_id: Uuid::from_u128(0x7103),
            tenant: "acme".to_owned(),
            holder: "agent:deployer".to_owned(),
            audience: template.audience.clone(),
            issued_at: 1_000,
            not_before: 1_000,
            consume_before: 1_100,
            dispatch_deadline_policy: DispatchDeadlinePolicy {
                max_dispatch_delay_seconds: 30,
                profile_hard_cap: 1_090,
                immutable_dependency_expiries: vec![1_080],
            },
            grant_id: Uuid::from_u128(0x7104),
            template_hash: canonical_hash(&template)
                .map_err(|error| KernelError::Canonical(error.to_string()))?,
            template,
            evidence_root: Digest32::from_bytes([0x73; 32]),
            principals: vec!["party:reviewer".to_owned(), "workload:builder".to_owned()],
            policy_root,
            authority: active_authority.clone(),
        };
        Ok((signer, active_authority, authorization))
    }

    fn sign_authorization_for_domain(
        authorization: ExecutionAuthorization,
        signer: &SigningIdentity,
        domain: &str,
    ) -> Result<SignedAuthorization, KernelError> {
        let payload = authorization
            .canonical_bytes()
            .map_err(|error| KernelError::Canonical(error.to_string()))?;
        let cose_sign1 = sign_cose(&payload, domain, signer)
            .map_err(|error| KernelError::AuthorizationSignature(error.to_string()))?;
        Ok(SignedAuthorization {
            authorization,
            cose_sign1,
        })
    }

    #[test]
    fn explicit_context_verification_returns_an_opaque_context_marker()
    -> Result<(), Box<dyn std::error::Error>> {
        let (signer, active_authority, authorization) = authorization_fixture()?;
        let envelope =
            sign_authorization_for_domain(authorization, &signer, EXECUTION_AUTHORIZATION_DOMAIN)?;
        let context = ExplicitAuthorizationVerificationContext::new(
            1_010,
            "accordlock-executor",
            &active_authority,
        )?;
        let verified =
            verify_authorization_in_explicit_context(&envelope, &signer.verifier(), &context)?;
        assert_eq!(verified.authorization(), &envelope.authorization);
        assert_eq!(
            verified.authorization_hash(),
            canonical_hash(&envelope.authorization)?
        );
        assert_eq!(
            verified.single_use_profile(),
            EXECUTION_AUTHORIZATION_SINGLE_USE_PROFILE
        );
        Ok(())
    }

    #[test]
    fn signed_wrong_template_hash_schema_domain_or_interval_is_not_executable()
    -> Result<(), Box<dyn std::error::Error>> {
        let (signer, active_authority, authorization) = authorization_fixture()?;
        let context = ExplicitAuthorizationVerificationContext::new(
            1_010,
            "accordlock-executor",
            &active_authority,
        )?;

        let mut wrong_hash = authorization.clone();
        wrong_hash.template_hash = Digest32::from_bytes([0x81; 32]);
        let signed_wrong_hash =
            sign_authorization_for_domain(wrong_hash, &signer, EXECUTION_AUTHORIZATION_DOMAIN)?;
        assert!(verify_authorization_signature(&signed_wrong_hash, &signer.verifier()).is_ok());
        assert!(
            verify_authorization_in_explicit_context(
                &signed_wrong_hash,
                &signer.verifier(),
                &context
            )
            .is_err()
        );

        let mut wrong_schema = authorization.clone();
        wrong_schema.schema_version = EXECUTION_AUTHORIZATION_SCHEMA_VERSION - 1;
        let signed_wrong_schema =
            sign_authorization_for_domain(wrong_schema, &signer, EXECUTION_AUTHORIZATION_DOMAIN)?;
        assert!(
            verify_authorization_in_explicit_context(
                &signed_wrong_schema,
                &signer.verifier(),
                &context
            )
            .is_err()
        );

        let signed_wrong_domain =
            sign_authorization_for_domain(authorization.clone(), &signer, EVALUATION_DOMAIN)?;
        assert!(verify_authorization_signature(&signed_wrong_domain, &signer.verifier()).is_err());

        let mut invalid_interval = authorization;
        invalid_interval.not_before = invalid_interval.issued_at - 1;
        let signed_invalid_interval = sign_authorization_for_domain(
            invalid_interval,
            &signer,
            EXECUTION_AUTHORIZATION_DOMAIN,
        )?;
        assert!(
            verify_authorization_in_explicit_context(
                &signed_invalid_interval,
                &signer.verifier(),
                &context
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn contextual_authorization_rejects_wrong_supplied_context_and_zero_placeholders()
    -> Result<(), Box<dyn std::error::Error>> {
        let (signer, active_authority, authorization) = authorization_fixture()?;

        let wrong_audience = ExplicitAuthorizationVerificationContext::new(
            1_010,
            "another-executor",
            &active_authority,
        )?;
        let envelope = sign_authorization_for_domain(
            authorization.clone(),
            &signer,
            EXECUTION_AUTHORIZATION_DOMAIN,
        )?;
        assert!(
            verify_authorization_in_explicit_context(
                &envelope,
                &signer.verifier(),
                &wrong_audience
            )
            .is_err()
        );

        let mut other_authority = active_authority.clone();
        other_authority.registry.epoch += 1;
        other_authority.registry.activation_id = Uuid::from_u128(0x7201);
        let wrong_authority = ExplicitAuthorizationVerificationContext::new(
            1_010,
            "accordlock-executor",
            &other_authority,
        )?;
        assert!(
            verify_authorization_in_explicit_context(
                &envelope,
                &signer.verifier(),
                &wrong_authority
            )
            .is_err()
        );

        let context = ExplicitAuthorizationVerificationContext::new(
            1_010,
            "accordlock-executor",
            &active_authority,
        )?;
        let mut zero_commitment = authorization;
        zero_commitment.evidence_root = Digest32::from_bytes([0; 32]);
        let signed_zero = sign_authorization_for_domain(
            zero_commitment,
            &signer,
            EXECUTION_AUTHORIZATION_DOMAIN,
        )?;
        assert!(
            verify_authorization_in_explicit_context(&signed_zero, &signer.verifier(), &context)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn legitimate_lineage_allows() -> Result<(), Box<dyn std::error::Error>> {
        let (proposal, evidence, context) = fixture()?;
        let decision = evaluate(&proposal, &evidence, &context)?;
        assert_eq!(decision.outcome, DecisionOutcome::Allow);
        assert_eq!(decision.reasons, vec![ReasonCode::Allowed]);
        Ok(())
    }

    #[test]
    fn signed_evaluation_consume_before_is_bounded_by_ingress_expiry()
    -> Result<(), Box<dyn std::error::Error>> {
        let (proposal, evidence, context) = fixture()?;
        let ingress_expiry = context.now + 15;
        let ingress = authenticated_ingress(
            &proposal,
            context.active_authority.principal_registry.clone(),
            context.now,
            ingress_expiry,
        )?;
        let bounded_context = KernelContext::from_authenticated_ingress(
            ingress,
            context.now,
            Uuid::from_u128(0x3301),
            context.policy.clone(),
            context.active_authority.clone(),
            context.attester_registry.clone(),
        )?;

        let evaluation = evaluate(&proposal, &evidence, &bounded_context)?;
        assert_eq!(evaluation.outcome, DecisionOutcome::Allow);
        assert_eq!(evaluation.consume_before, ingress_expiry);
        assert_eq!(
            evaluation.schema_version,
            EVALUATION_ATTESTATION_SCHEMA_VERSION
        );

        let evaluator = SigningIdentity::from_seed("bounded-evaluation", [0x33; 32]);
        let envelope = sign_evaluation(evaluation, &evaluator)?;
        let signed_payload = verify_cose(
            &envelope.cose_sign1,
            EVALUATION_DOMAIN,
            &evaluator.verifier(),
        )?;
        assert_eq!(signed_payload, envelope.attestation.canonical_bytes()?);
        assert_eq!(envelope.attestation.consume_before, ingress_expiry);
        Ok(())
    }

    #[test]
    fn activated_registry_root_binds_security_relevant_attester_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_, _, context) = fixture()?;
        let domain = context.active_authority.registry.clone();
        let original = context.attester_registry.entries().to_vec();

        let mut changed_key = original.clone();
        changed_key[0].public_key =
            SigningIdentity::from_seed("replacement", [99; 32]).public_key_bytes();
        assert!(ActivatedAttesterRegistry::new(domain.clone(), changed_key).is_err());

        let mut changed_scope = original.clone();
        changed_scope[0].scopes = vec![AttesterScope::Build {
            repository: "acme/other".to_owned(),
            workflow_ref: "workflow.yml@main".to_owned(),
        }];
        assert!(ActivatedAttesterRegistry::new(domain.clone(), changed_scope).is_err());

        let mut changed_grade = original.clone();
        changed_grade[0].base_grade = 4;
        assert!(ActivatedAttesterRegistry::new(domain.clone(), changed_grade).is_err());

        let mut changed_principal = original.clone();
        changed_principal[0].principal_id = "party:substituted".to_owned();
        assert!(ActivatedAttesterRegistry::new(domain.clone(), changed_principal).is_err());

        let mut reordered = original.clone();
        reordered.swap(0, 1);
        assert!(matches!(
            ActivatedAttesterRegistry::new(domain.clone(), reordered),
            Err(KernelError::InvalidAttesterRegistry(_))
        ));

        let mut duplicated = original.clone();
        duplicated.insert(1, duplicated[0].clone());
        assert!(matches!(
            ActivatedAttesterRegistry::new(domain.clone(), duplicated),
            Err(KernelError::InvalidAttesterRegistry(_))
        ));

        let mut duplicated_scope = original;
        let scope_duplicate = duplicated_scope[0].scopes[0].clone();
        duplicated_scope[0].scopes.push(scope_duplicate);
        assert!(matches!(
            ActivatedAttesterRegistry::new(domain, duplicated_scope),
            Err(KernelError::InvalidAttesterRegistry(_))
        ));
        Ok(())
    }

    #[test]
    fn kernel_context_rejects_registry_root_epoch_or_activation_mismatch()
    -> Result<(), Box<dyn std::error::Error>> {
        let (proposal, _, context) = fixture()?;
        let entries = context.attester_registry.entries().to_vec();

        let mut wrong_root_domain = context.active_authority.registry.clone();
        wrong_root_domain.root = Digest32::from_bytes([0xf1; 32]);
        assert!(matches!(
            ActivatedAttesterRegistry::new(wrong_root_domain, entries.clone()),
            Err(KernelError::AttesterRegistryRootMismatch)
        ));

        let mut wrong_epoch_domain = context.active_authority.registry.clone();
        wrong_epoch_domain.epoch += 1;
        let wrong_epoch_registry =
            ActivatedAttesterRegistry::new(wrong_epoch_domain, entries.clone())?;
        let ingress = authenticated_ingress(
            &proposal,
            context.active_authority.principal_registry.clone(),
            context.now,
            context.ingress_expires_at(),
        )?;
        assert!(matches!(
            KernelContext::from_authenticated_ingress(
                ingress,
                context.now,
                context.evaluation_nonce,
                context.policy.clone(),
                context.active_authority.clone(),
                wrong_epoch_registry,
            ),
            Err(KernelError::AttesterRegistryAuthorityMismatch)
        ));

        let mut wrong_activation_domain = context.active_authority.registry.clone();
        wrong_activation_domain.activation_id = Uuid::from_u128(0xf2);
        let wrong_activation_registry =
            ActivatedAttesterRegistry::new(wrong_activation_domain, entries)?;
        let ingress = authenticated_ingress(
            &proposal,
            context.active_authority.principal_registry.clone(),
            context.now,
            context.ingress_expires_at(),
        )?;
        assert!(matches!(
            KernelContext::from_authenticated_ingress(
                ingress,
                context.now,
                context.evaluation_nonce,
                context.policy.clone(),
                context.active_authority.clone(),
                wrong_activation_registry,
            ),
            Err(KernelError::AttesterRegistryAuthorityMismatch)
        ));

        let mut wrong_policy_authority = context.active_authority.clone();
        wrong_policy_authority.policy.root = Digest32::from_bytes([0xf3; 32]);
        let ingress = authenticated_ingress(
            &proposal,
            context.active_authority.principal_registry.clone(),
            context.now,
            context.ingress_expires_at(),
        )?;
        assert!(matches!(
            KernelContext::from_authenticated_ingress(
                ingress,
                context.now,
                context.evaluation_nonce,
                context.policy.clone(),
                wrong_policy_authority,
                context.attester_registry.clone(),
            ),
            Err(KernelError::PolicyRootMismatch)
        ));
        Ok(())
    }

    #[test]
    fn durable_context_parts_reject_identity_scope_time_and_authority_substitution()
    -> Result<(), Box<dyn std::error::Error>> {
        let (proposal, _, context) = fixture()?;
        let scope = Scope {
            tenant: proposal.tenant.clone(),
            environment: proposal.template.environment.clone(),
        };

        let mut substituted_scope = scope.clone();
        substituted_scope.environment = "other-environment".to_owned();
        assert!(matches!(
            KernelContext::from_trusted_parts(
                Some(&substituted_scope),
                proposal.clone(),
                context.caller.tenant.clone(),
                context.caller.actor.clone(),
                context.authenticated_at,
                context.ingress_expires_at,
                context.ingress_authority_domain.clone(),
                context.now,
                context.evaluation_nonce,
                context.policy.clone(),
                context.active_authority.clone(),
                context.attester_registry.clone(),
            ),
            Err(KernelError::InvalidContext(_))
        ));

        assert!(matches!(
            KernelContext::from_trusted_parts(
                Some(&scope),
                proposal.clone(),
                context.caller.tenant.clone(),
                "actor:substituted".to_owned(),
                context.authenticated_at,
                context.ingress_expires_at,
                context.ingress_authority_domain.clone(),
                context.now,
                context.evaluation_nonce,
                context.policy.clone(),
                context.active_authority.clone(),
                context.attester_registry.clone(),
            ),
            Err(KernelError::InvalidContext(_))
        ));

        assert!(matches!(
            KernelContext::from_trusted_parts(
                Some(&scope),
                proposal.clone(),
                context.caller.tenant.clone(),
                context.caller.actor.clone(),
                context.authenticated_at,
                context.ingress_expires_at,
                context.ingress_authority_domain.clone(),
                context.authenticated_at - 1,
                context.evaluation_nonce,
                context.policy.clone(),
                context.active_authority.clone(),
                context.attester_registry.clone(),
            ),
            Err(KernelError::IngressClockRollback)
        ));

        assert!(matches!(
            KernelContext::from_trusted_parts(
                Some(&scope),
                proposal.clone(),
                context.caller.tenant.clone(),
                context.caller.actor.clone(),
                context.authenticated_at,
                context.ingress_expires_at,
                context.ingress_authority_domain.clone(),
                context.ingress_expires_at,
                context.evaluation_nonce,
                context.policy.clone(),
                context.active_authority.clone(),
                context.attester_registry.clone(),
            ),
            Err(KernelError::IngressExpired)
        ));

        let mut substituted_ingress_authority = context.ingress_authority_domain.clone();
        substituted_ingress_authority.epoch += 1;
        assert!(matches!(
            KernelContext::from_trusted_parts(
                Some(&scope),
                proposal,
                context.caller.tenant.clone(),
                context.caller.actor.clone(),
                context.authenticated_at,
                context.ingress_expires_at,
                substituted_ingress_authority,
                context.now,
                context.evaluation_nonce,
                context.policy.clone(),
                context.active_authority.clone(),
                context.attester_registry.clone(),
            ),
            Err(KernelError::IngressRegistryAuthorityMismatch)
        ));
        Ok(())
    }

    #[test]
    fn state_claim_builds_one_shot_durable_context_and_returns_work_with_evaluation()
    -> Result<(), Box<dyn std::error::Error>> {
        let (proposal, evidence, legacy_context) = fixture()?;
        let ingress_signer = SigningIdentity::from_seed("ingress-agent", [0x31; 32]);
        let registration = ingress_registration(&proposal, &ingress_signer);
        let registry = ActivatedIngressRegistry::new(
            legacy_context.active_authority.principal_registry.clone(),
            proposal.template.audience.clone(),
            120,
            vec![registration],
        )?;
        let authenticator = IngressAuthenticator::new(registry, MemoryReplayGuard::default())?;
        let claims = IngressClaims {
            schema_version: INGRESS_SCHEMA_VERSION,
            audience: proposal.template.audience.clone(),
            issued_at: 1_009,
            expires_at: 1_070,
            nonce: Uuid::from_u128(0x3301),
            proposal: proposal.clone(),
        };
        let wire = serde_json::to_vec(&sign_ingress_request(claims, &ingress_signer)?)?;
        let verified =
            authenticator.verify_durable_static(IngressRecoveryProbe::parse_bytes(&wire)?)?;

        let store = InMemoryStore::with_clock(Arc::new(FixedClock(1_010)));
        let scope = Scope::new(&proposal.tenant, &proposal.template.environment)?;
        store.compare_and_activate_authority(&scope, None, &legacy_context.active_authority)?;
        assert!(matches!(
            store.accept_control_submission_or_recover(verified)?,
            ControlSubmissionIntakeOutcome::Fresh(_)
        ));
        let claim = ControlWorkClaimRequest::new(
            "kernel-evaluator-1",
            ControlWorkerRole::Evaluator,
            Uuid::from_u128(0x3302),
        )?;
        let work = match store.claim_next_control_work_or_recover(&claim)? {
            ControlWorkClaimOutcome::Claimed(ClaimedControlWork::Evaluate(work)) => work,
            other => return Err(format!("unexpected control claim: {other:?}").into()),
        };
        let claim_id = work.lease().claim_id();
        let claimed_at = work.lease().claimed_at();
        let context = KernelContext::from_control_work(
            work,
            legacy_context.policy.clone(),
            legacy_context.attester_registry.clone(),
        )?;
        assert_eq!(context.now(), claimed_at);
        assert_eq!(context.authenticated_proposal(), &proposal);
        assert!(matches!(
            evaluate(&proposal, &evidence, &context),
            Err(KernelError::DurableContextRequiresConsumingEvaluation)
        ));

        let evaluator = SigningIdentity::from_seed("durable-kernel-evaluator", [0x34; 32]);
        let (returned_work, signed_evaluation) = context.evaluate_control(&evidence, &evaluator)?;
        let evaluation = &signed_evaluation.attestation;
        assert_eq!(returned_work.lease().claim_id(), claim_id);
        assert_eq!(evaluation.evaluated_at, claimed_at);
        assert_eq!(evaluation.outcome, DecisionOutcome::Allow);
        assert_eq!(evaluation.consume_before, 1_070);
        let decision = store.record_control_evaluation(
            returned_work,
            &signed_evaluation,
            &evaluator.verifier(),
        )?;
        // This kernel-only fixture registers no grants. State therefore
        // persists the valid ALLOW attestation but derives CONTROL_DENY.
        assert_eq!(decision.selected_grant_id(), None);
        Ok(())
    }

    #[test]
    fn queued_ingress_expiry_and_clock_rollback_fail_before_evaluation()
    -> Result<(), Box<dyn std::error::Error>> {
        let (proposal, _, context) = fixture()?;
        let ingress = authenticated_ingress(
            &proposal,
            context.active_authority.principal_registry.clone(),
            context.now,
            context.now + 1,
        )?;
        assert!(matches!(
            KernelContext::from_authenticated_ingress(
                ingress,
                context.now + 1,
                Uuid::from_u128(0x3201),
                context.policy.clone(),
                context.active_authority.clone(),
                context.attester_registry.clone(),
            ),
            Err(KernelError::IngressExpired)
        ));

        let ingress = authenticated_ingress(
            &proposal,
            context.active_authority.principal_registry.clone(),
            context.now,
            context.now + 10,
        )?;
        assert!(matches!(
            KernelContext::from_authenticated_ingress(
                ingress,
                context.now - 1,
                Uuid::from_u128(0x3202),
                context.policy.clone(),
                context.active_authority.clone(),
                context.attester_registry.clone(),
            ),
            Err(KernelError::IngressClockRollback)
        ));
        Ok(())
    }

    #[test]
    fn ingress_principal_registry_root_epoch_and_activation_must_be_exact()
    -> Result<(), Box<dyn std::error::Error>> {
        let (proposal, _, context) = fixture()?;
        let mut variants = Vec::new();

        let rotated_signer = SigningIdentity::from_seed("rotated-ingress-agent", [0xe1; 32]);
        let mut rotated_root = context.active_authority.clone();
        rotated_root.principal_registry.root = ActivatedIngressRegistry::compute_root(
            &proposal.template.audience,
            120,
            &[ingress_registration(&proposal, &rotated_signer)],
        )?;
        variants.push(rotated_root);

        let mut advanced_epoch = context.active_authority.clone();
        advanced_epoch.principal_registry.epoch += 1;
        variants.push(advanced_epoch);

        let mut new_activation = context.active_authority.clone();
        new_activation.principal_registry.activation_id = Uuid::from_u128(0xe3);
        variants.push(new_activation);

        for active_authority in variants {
            let ingress = authenticated_ingress(
                &proposal,
                context.active_authority.principal_registry.clone(),
                context.now,
                context.now + 10,
            )?;
            assert!(matches!(
                KernelContext::from_authenticated_ingress(
                    ingress,
                    context.now,
                    Uuid::from_u128(0x3203),
                    context.policy.clone(),
                    active_authority,
                    context.attester_registry.clone(),
                ),
                Err(KernelError::IngressRegistryAuthorityMismatch)
            ));
        }
        Ok(())
    }

    #[test]
    fn exact_authenticated_proposal_is_bound_into_kernel_context()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut proposal, evidence, context) = fixture()?;
        proposal.template.resource_version = "1002".to_owned();
        let decision = evaluate(&proposal, &evidence, &context)?;
        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert!(
            decision
                .reasons
                .contains(&ReasonCode::CallerSecurityFactRejected)
        );
        Ok(())
    }

    #[test]
    fn unsupported_signed_evidence_schema_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let (proposal, mut evidence, context) = fixture()?;
        evidence.evidence[0].assertion.schema_version = 1;
        let review_signer = SigningIdentity::from_seed("github", [1; 32]);
        let payload = evidence.evidence[0].assertion.canonical_bytes()?;
        evidence.evidence[0].cose_sign1 = sign_cose(
            &payload,
            evidence.evidence[0].assertion.payload.kind().domain(),
            &review_signer,
        )?;

        let decision = evaluate(&proposal, &evidence, &context)?;
        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert!(decision.reasons.contains(&ReasonCode::EvidenceDefective));
        Ok(())
    }

    #[test]
    fn intact_signed_assertions_cannot_be_substituted_into_another_request()
    -> Result<(), Box<dyn std::error::Error>> {
        let (proposal_a, evidence_a, context_a) = fixture()?;
        let mut proposal_b = proposal_a;
        proposal_b.request_id = Uuid::from_bytes([0x55; 16]);
        let ingress_b = authenticated_ingress(
            &proposal_b,
            context_a.active_authority.principal_registry.clone(),
            context_a.now,
            context_a.now + 50,
        )?;
        let context_b = KernelContext::from_authenticated_ingress(
            ingress_b,
            context_a.now,
            Uuid::from_u128(0x5501),
            context_a.policy.clone(),
            context_a.active_authority.clone(),
            context_a.attester_registry.clone(),
        )?;
        let substituted = TrustedEvidenceSet {
            request_id: proposal_b.request_id,
            evidence: evidence_a.evidence,
        };

        let decision = evaluate(&proposal_b, &substituted, &context_b)?;
        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert!(
            decision
                .reasons
                .contains(&ReasonCode::EvidenceRequestMismatch)
        );
        Ok(())
    }

    #[test]
    fn signed_assertion_request_id_cannot_be_relabelled_without_resigning()
    -> Result<(), Box<dyn std::error::Error>> {
        let (proposal, mut evidence, context) = fixture()?;
        evidence.evidence[0].assertion.request_id = Uuid::from_bytes([0x56; 16]);

        let decision = evaluate(&proposal, &evidence, &context)?;
        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert!(
            decision
                .reasons
                .contains(&ReasonCode::EvidenceSignatureInvalid)
        );
        Ok(())
    }

    #[test]
    fn excessive_evidence_cardinality_is_rejected_before_evaluation()
    -> Result<(), Box<dyn std::error::Error>> {
        let (proposal, mut evidence, context) = fixture()?;
        while evidence.evidence.len() <= MAX_EVIDENCE_ITEMS {
            evidence.evidence.push(evidence.evidence[0].clone());
        }
        assert!(matches!(
            evaluate(&proposal, &evidence, &context),
            Err(KernelError::InputLimitExceeded)
        ));
        Ok(())
    }

    #[test]
    fn artifact_can_match_any_valid_build_independent_of_evidence_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let (proposal, mut evidence, context) = fixture()?;
        let build = SigningIdentity::from_seed("actions", [2; 32]);
        evidence.evidence.push(sign_evidence(
            &build,
            &context.active_authority,
            proposal.request_id,
            EvidencePayload::Build {
                repository: proposal.template.repository.clone(),
                commit_sha: proposal.template.commit_sha.clone(),
                workflow_ref: ".github/workflows/release.yml@refs/heads/main".to_owned(),
                run_id: "different-valid-run".to_owned(),
                succeeded: true,
                input_manifest_root: Digest32::from_bytes([0x11; 32]),
                completeness_profile: CompletenessProfile::HermeticInputsV1,
                output_digest: Digest32::from_bytes([0xbb; 32]),
            },
            5,
        )?);

        let decision = evaluate(&proposal, &evidence, &context)?;
        assert_eq!(decision.outcome, DecisionOutcome::Allow);
        Ok(())
    }

    #[test]
    fn caller_supplied_security_fact_fails_at_schema_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let (proposal, _, _) = fixture()?;
        let mut value = serde_json::to_value(proposal)?;
        let object = value
            .as_object_mut()
            .ok_or("serialized proposal was not an object")?;
        object.insert("attested".to_owned(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<AgentProposal>(value).is_err());
        Ok(())
    }

    #[test]
    fn proposal_identity_must_match_authenticated_ingress() -> Result<(), Box<dyn std::error::Error>>
    {
        let (mut proposal, evidence, context) = fixture()?;
        proposal.actor = "ci-workload-attacker".to_owned();
        let decision = evaluate(&proposal, &evidence, &context)?;
        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert!(
            decision
                .reasons
                .contains(&ReasonCode::CallerSecurityFactRejected)
        );
        assert_eq!(decision.actor, context.caller().actor());
        Ok(())
    }

    #[test]
    fn artifact_swap_is_denied_but_plain_policy_allows() -> Result<(), Box<dyn std::error::Error>> {
        let (mut proposal, evidence, context) = fixture()?;
        proposal.template.image_digest = Digest32::from_bytes([0xbb; 32]);
        let decision = evaluate(&proposal, &evidence, &context)?;
        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert!(
            decision
                .reasons
                .contains(&ReasonCode::TransformOutputMismatch)
        );

        let baseline = evaluate_plain_policy(
            &proposal,
            &context.policy,
            &BaselineFacts {
                review_approved: true,
                build_succeeded: true,
                artifact_signature_valid: true,
                artifact_quarantined: false,
                target_current: true,
            },
        );
        assert!(baseline.allow);
        Ok(())
    }

    #[test]
    fn target_projection_hash_is_enforced() -> Result<(), Box<dyn std::error::Error>> {
        let (proposal, mut evidence, context) = fixture()?;
        let target = evidence
            .evidence
            .get_mut(3)
            .ok_or("target evidence missing")?;
        if let EvidencePayload::Target {
            projection_hash, ..
        } = &mut target.assertion.payload
        {
            *projection_hash = Digest32::from_bytes([0xee; 32]);
        } else {
            return Err("fourth evidence item is not a target".into());
        }
        let target_signer = SigningIdentity::from_seed("kubernetes", [4; 32]);
        let payload = target.assertion.canonical_bytes()?;
        target.cose_sign1 = sign_cose(
            &payload,
            target.assertion.payload.kind().domain(),
            &target_signer,
        )?;

        let decision = evaluate(&proposal, &evidence, &context)?;
        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert!(decision.reasons.contains(&ReasonCode::TargetStateMismatch));
        Ok(())
    }

    #[test]
    fn unknown_caller_fields_fail_json_parsing() {
        let input = r#"{
          "schema_version": 1,
          "request_id": "14141414-1414-1414-1414-141414141414",
          "tenant": "acme",
          "actor": "agent:deployer",
          "template": {},
          "policy": {"allow": true},
          "agent_supplied_claims": {}
        }"#;
        assert!(serde_json::from_str::<AgentProposal>(input).is_err());
    }
}
