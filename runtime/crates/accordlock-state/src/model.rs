use accordlock_eks_profile::EksCredentialLifecyclePolicy;
use accordlock_protocol::{
    AuthorityVector, CanonicalEncode, CanonicalError, CapabilityGrant, ConsumptionReceipt,
    CoseVerifier, DeploymentTemplate, Digest32, DispatchDeadlinePolicy,
    EXECUTION_AUTHORIZATION_DOMAIN, EXECUTION_AUTHORIZATION_SCHEMA_VERSION, ExecutionAuthorization,
    MAX_IMMUTABLE_DEPENDENCY_EXPIRIES, SignedAuthorization, authorization_signer_root,
    canonical_hash, verify_cose,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Local profile bound for an exclusive dispatch claim.
///
/// A claim never extends the signed dispatch deadline. Expiry does not authorization
/// automatic takeover; it moves recovery outside this minimal profile.
pub const DISPATCH_CLAIM_LEASE_SECONDS: i64 = 30;

/// Tenant and environment partition for all safety-critical state.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub tenant: String,
    pub environment: String,
}

impl Scope {
    /// Constructs a non-empty tenant and environment scope.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::InvalidRecord`] if either component is empty.
    pub fn new(
        tenant: impl Into<String>,
        environment: impl Into<String>,
    ) -> Result<Self, StateError> {
        let scope = Self {
            tenant: tenant.into(),
            environment: environment.into(),
        };
        scope.validate()?;
        Ok(scope)
    }

    pub(crate) fn validate(&self) -> Result<(), StateError> {
        if self.tenant.trim().is_empty()
            || self.environment.trim().is_empty()
            || self.tenant.trim() != self.tenant
            || self.environment.trim() != self.environment
        {
            return Err(StateError::InvalidRecord(
                "tenant and environment must be non-empty and have no surrounding whitespace"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

pub(crate) fn validate_deadline_policy(policy: &DispatchDeadlinePolicy) -> Result<(), StateError> {
    if policy.max_dispatch_delay_seconds <= 0 {
        return Err(StateError::InvalidDeadline(
            "max_dispatch_delay_seconds must be positive".to_owned(),
        ));
    }
    if policy.profile_hard_cap < 0 {
        return Err(StateError::InvalidDeadline(
            "profile_hard_cap must be a non-negative Unix time".to_owned(),
        ));
    }
    if policy.immutable_dependency_expiries.len() > MAX_IMMUTABLE_DEPENDENCY_EXPIRIES
        || policy
            .immutable_dependency_expiries
            .iter()
            .any(|expiry| *expiry < 0)
        || policy
            .immutable_dependency_expiries
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(StateError::InvalidDeadline(
            "dependency expiries must be non-negative, strictly sorted, duplicate-free, and bounded"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Computes the exact absolute deadline frozen by the consumption receipt.
///
/// # Errors
///
/// Returns [`StateError`] for invalid or expired inputs, arithmetic overflow,
/// an expired dependency, or an empty dispatch window.
pub fn compute_dispatch_deadline(
    consumption_time: i64,
    consume_before: i64,
    policy: &DispatchDeadlinePolicy,
) -> Result<i64, StateError> {
    validate_deadline_policy(policy)?;
    if consumption_time < 0 || consume_before < 0 {
        return Err(StateError::InvalidDeadline(
            "times must be non-negative Unix seconds".to_owned(),
        ));
    }
    if consumption_time >= consume_before {
        return Err(StateError::AuthorizationExpired {
            observed: consumption_time,
            consume_before,
        });
    }

    let delay_deadline = consumption_time
        .checked_add(policy.max_dispatch_delay_seconds)
        .ok_or(StateError::DeadlineOverflow)?;
    let mut deadline = delay_deadline
        .min(consume_before)
        .min(policy.profile_hard_cap);

    for expiry in &policy.immutable_dependency_expiries {
        if *expiry <= consumption_time {
            return Err(StateError::DependencyExpired {
                observed: consumption_time,
                expiry: *expiry,
            });
        }
        deadline = deadline.min(*expiry);
    }

    if deadline <= consumption_time {
        return Err(StateError::EmptyDispatchWindow {
            observed: consumption_time,
            deadline,
        });
    }
    Ok(deadline)
}

/// Grant material registered through the trusted issuance/control-plane path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRegistration {
    pub environment: String,
    pub grant: CapabilityGrant,
    /// Exact authority vector under which this grant and issuance profile were
    /// activated. A registration never floats across an authority change.
    pub authority: AuthorityVector,
    /// Trusted control-plane policy copied into every signed authorization issued
    /// from this registration.
    pub dispatch_deadline_policy: DispatchDeadlinePolicy,
}

impl GrantRegistration {
    #[must_use]
    pub fn scope(&self) -> Scope {
        Scope {
            tenant: self.grant.tenant.clone(),
            environment: self.environment.clone(),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), StateError> {
        self.scope().validate()?;
        validate_authority_vector(&self.authority)?;
        validate_deadline_policy(&self.dispatch_deadline_policy)?;
        let grant = &self.grant;
        if self.authority.grant_registry.root != canonical_hash(grant)? {
            return Err(StateError::GrantRegistryRootMismatch);
        }
        if grant.grant_id.is_nil()
            || [
                grant.holder.as_str(),
                grant.operation.as_str(),
                grant.repository.as_str(),
                grant.audience.as_str(),
                grant.cluster_identity.as_str(),
                grant.namespace.as_str(),
                grant.deployment_uid.as_str(),
                grant.container.as_str(),
                grant.image_repository.as_str(),
            ]
            .iter()
            .any(|value| value.trim().is_empty())
        {
            return Err(StateError::InvalidRecord(
                "grant identifiers and bound resource fields must be non-empty".to_owned(),
            ));
        }
        if self.grant.maximum_uses == 0 {
            return Err(StateError::InvalidRecord(
                "grant maximum_uses must be positive".to_owned(),
            ));
        }
        if self.grant.not_before < 0 || self.grant.expires_at <= self.grant.not_before {
            return Err(StateError::InvalidRecord(
                "grant validity interval is empty or invalid".to_owned(),
            ));
        }
        if self.dispatch_deadline_policy.profile_hard_cap <= self.grant.not_before
            || self
                .dispatch_deadline_policy
                .immutable_dependency_expiries
                .iter()
                .any(|expiry| *expiry <= self.grant.not_before)
        {
            return Err(StateError::InvalidDeadline(
                "grant registration has no usable dispatch-policy interval".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantSnapshot {
    pub registration: GrantRegistration,
    pub uses: u32,
    pub revoked: bool,
}

/// Current issuance inputs loaded exclusively from trusted transactional
/// state. Fields are private so request-facing code cannot fabricate a grant,
/// authority vector, clock value, executor audience, or deadline policy.
#[derive(Debug)]
pub struct IssuanceSnapshot {
    scope: Scope,
    registration: GrantRegistration,
    issued_at: i64,
}

impl IssuanceSnapshot {
    pub(crate) fn new(scope: Scope, registration: GrantRegistration, issued_at: i64) -> Self {
        Self {
            scope,
            registration,
            issued_at,
        }
    }

    #[must_use]
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    #[must_use]
    pub fn registration(&self) -> &GrantRegistration {
        &self.registration
    }

    #[must_use]
    pub const fn issued_at(&self) -> i64 {
        self.issued_at
    }
}

/// Authorization and immutable consumption inputs recorded by the trusted signer path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedAuthorizationRecord {
    pub transaction_id: Uuid,
    /// Exact COSE envelope returned by the isolated authorization signer.
    pub signed_authorization: SignedAuthorization,
    /// COSE key identifier committed by `authority.signer.root`.
    pub signer_key_id: String,
    /// Ed25519 public key committed by `authority.signer.root`.
    pub signer_public_key: [u8; 32],
    pub authorization_hash: Digest32,
}

impl IssuedAuthorizationRecord {
    /// Validates and freezes the trusted authorization issuance record.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] for invalid identifiers, validity intervals,
    /// deadline policy, tenant scope, policy binding, or canonical encoding.
    pub fn new(
        transaction_id: Uuid,
        signed_authorization: SignedAuthorization,
        signer_key_id: String,
        signer_public_key: [u8; 32],
    ) -> Result<Self, StateError> {
        let authorization_hash = canonical_hash(&signed_authorization.authorization)?;
        let record = Self {
            transaction_id,
            signed_authorization,
            signer_key_id,
            signer_public_key,
            authorization_hash,
        };
        record.validate()?;
        Ok(record)
    }

    pub(crate) fn validate(&self) -> Result<(), StateError> {
        let authorization = &self.signed_authorization.authorization;
        validate_authority_vector(&authorization.authority)?;
        // A dispatch reservation is derived from these exact signed fields.
        // Reject unsafe identity spellings before they can become durable keys.
        PhysicalResourceKey::from_authorization(authorization)?;
        let verifier =
            CoseVerifier::from_public_key(self.signer_key_id.clone(), self.signer_public_key)
                .map_err(|error| StateError::InvalidAuthorizationSignature(error.to_string()))?;
        let signer_root = authorization_signer_root(&self.signer_key_id, self.signer_public_key)
            .map_err(|error| StateError::InvalidAuthorizationSignature(error.to_string()))?;
        if signer_root != authorization.authority.signer.root {
            return Err(StateError::InvalidAuthorizationSignature(
                "authorization signer does not match the active signer authority root".to_owned(),
            ));
        }
        let signed_payload = verify_cose(
            &self.signed_authorization.cose_sign1,
            EXECUTION_AUTHORIZATION_DOMAIN,
            &verifier,
        )
        .map_err(|error| StateError::InvalidAuthorizationSignature(error.to_string()))?;
        let canonical_payload = authorization.canonical_bytes()?;
        if signed_payload != canonical_payload {
            return Err(StateError::InvalidAuthorizationSignature(
                "COSE payload does not equal the canonical action authorization".to_owned(),
            ));
        }
        if self.transaction_id.is_nil()
            || authorization.authorization_id.is_nil()
            || authorization.grant_id.is_nil()
            || authorization.request_id.is_nil()
            || authorization.evaluation_nonce.is_nil()
        {
            return Err(StateError::InvalidRecord(
                "authorization and transaction identifiers must be non-nil".to_owned(),
            ));
        }
        validate_deadline_policy(&authorization.dispatch_deadline_policy)?;
        if authorization.issued_at < 0
            || authorization.not_before < authorization.issued_at
            || authorization.consume_before <= authorization.not_before
        {
            return Err(StateError::InvalidRecord(
                "authorization validity interval is empty or invalid".to_owned(),
            ));
        }
        if authorization.schema_version != EXECUTION_AUTHORIZATION_SCHEMA_VERSION
            || authorization.tenant.trim().is_empty()
            || authorization.holder.trim().is_empty()
            || authorization.audience.trim().is_empty()
            || authorization.template.environment.trim().is_empty()
        {
            return Err(StateError::InvalidRecord(
                "authorization schema and principal/scope fields must be non-empty".to_owned(),
            ));
        }
        if authorization.audience != authorization.template.audience {
            return Err(StateError::InvalidRecord(
                "authorization audience must equal template audience".to_owned(),
            ));
        }
        if authorization.policy_root != authorization.authority.policy.root {
            return Err(StateError::InvalidRecord(
                "authorization policy_root must equal its authority policy root".to_owned(),
            ));
        }
        if authorization.template_hash != canonical_hash(&authorization.template)? {
            return Err(StateError::InvalidRecord(
                "authorization template_hash must equal the canonical template hash".to_owned(),
            ));
        }
        if self.authorization_hash != canonical_hash(authorization)? {
            return Err(StateError::InvalidRecord(
                "authorization_hash must equal the canonical authorization hash".to_owned(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn scope(&self) -> Scope {
        Scope {
            tenant: self.signed_authorization.authorization.tenant.clone(),
            environment: self
                .signed_authorization
                .authorization
                .template
                .environment
                .clone(),
        }
    }

    #[must_use]
    pub fn authorization(&self) -> &ExecutionAuthorization {
        &self.signed_authorization.authorization
    }
}

/// The only data accepted at consumption time.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumeKey {
    pub scope: Scope,
    pub transaction_id: Uuid,
    pub authorization_id: Uuid,
}

impl ConsumeKey {
    pub(crate) fn validate(&self) -> Result<(), StateError> {
        self.scope.validate()?;
        if self.transaction_id.is_nil() || self.authorization_id.is_nil() {
            return Err(StateError::InvalidRecord(
                "transaction_id and authorization_id must be non-nil".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Exact signed identity used for durable physical-resource exclusion.
///
/// Tenant, environment, Deployment display name, resource version, container,
/// and logical operation are deliberately absent. They must not split two
/// authorizations that target the same Kubernetes Deployment object. The
/// `cluster_identity` value is an authenticated, canonical control-plane
/// identifier under the current vertical-slice profile; no URL or Unicode
/// normalization is performed in this state adapter.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhysicalResourceKey {
    cluster_identity: String,
    namespace: String,
    deployment_uid: String,
}

impl PhysicalResourceKey {
    pub(crate) fn from_authorization(
        authorization: &ExecutionAuthorization,
    ) -> Result<Self, StateError> {
        Self::new(
            authorization.template.cluster_identity.clone(),
            authorization.template.namespace.clone(),
            authorization.template.deployment_uid.clone(),
        )
    }

    /// Constructs a physical-resource identity from authenticated provider
    /// coordinates.
    ///
    /// A value constructed here is not authority by itself. Every state
    /// operation accepting this type compares it with the identity derived
    /// from the stored signed authorization and its durable reservation.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::InvalidRecord`] for an empty, unbounded,
    /// whitespace-padded, or control-bearing component.
    pub fn new(
        cluster_identity: String,
        namespace: String,
        deployment_uid: String,
    ) -> Result<Self, StateError> {
        if !valid_physical_identity_component(&cluster_identity, 512)
            || !valid_physical_identity_component(&namespace, 253)
            || !valid_physical_identity_component(&deployment_uid, 512)
        {
            return Err(StateError::InvalidRecord(
                "physical resource identity must be non-empty, bounded, trimmed, and control-free"
                    .to_owned(),
            ));
        }
        Ok(Self {
            cluster_identity,
            namespace,
            deployment_uid,
        })
    }

    #[must_use]
    pub fn cluster_identity(&self) -> &str {
        &self.cluster_identity
    }

    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    #[must_use]
    pub fn deployment_uid(&self) -> &str {
        &self.deployment_uid
    }
}

/// Exact one-shot Kubernetes admission tuple bound to an in-flight dispatch.
///
/// This is request data, not authorization. The state adapter reloads the
/// signed authorization, current authority and grant, frozen dispatch deadline,
/// trusted-time high-water mark, durable claim, and physical reservation
/// before committing an `ADMITTED` decision. Dry-run requests must be handled
/// before this boundary and must never be converted into this type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionAuthorizationRequest {
    key: ConsumeKey,
    claim_id: Uuid,
    fence: u64,
    physical_resource: PhysicalResourceKey,
    credential_token_digest: Digest32,
    service_account_uid: String,
    credential_id: String,
    credential_binding_commitment: Digest32,
    admission_uid: String,
    provider_request_commitment: Digest32,
    old_object_commitment: Digest32,
    new_object_commitment: Digest32,
    executor_identity_commitment: Digest32,
    observer_identity_commitment: Digest32,
}

impl AdmissionAuthorizationRequest {
    /// Constructs one complete admission authorization tuple from trusted
    /// state facts and request observations.
    ///
    /// This constructor is crate-private. Request-facing code must first load
    /// an [`AdmissionContext`] and consume it through
    /// [`AdmissionContext::authorization_request`].
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        key: ConsumeKey,
        claim_id: Uuid,
        fence: u64,
        physical_resource: PhysicalResourceKey,
        credential_token_digest: Digest32,
        service_account_uid: String,
        credential_id: String,
        credential_binding_commitment: Digest32,
        admission_uid: String,
        provider_request_commitment: Digest32,
        old_object_commitment: Digest32,
        new_object_commitment: Digest32,
        executor_identity_commitment: Digest32,
        observer_identity_commitment: Digest32,
    ) -> Result<Self, StateError> {
        let request = Self {
            key,
            claim_id,
            fence,
            physical_resource,
            credential_token_digest,
            service_account_uid,
            credential_id,
            credential_binding_commitment,
            admission_uid,
            provider_request_commitment,
            old_object_commitment,
            new_object_commitment,
            executor_identity_commitment,
            observer_identity_commitment,
        };
        request.validate()?;
        Ok(request)
    }

    pub(crate) fn validate(&self) -> Result<(), StateError> {
        self.key.validate()?;
        PhysicalResourceKey::new(
            self.physical_resource.cluster_identity.clone(),
            self.physical_resource.namespace.clone(),
            self.physical_resource.deployment_uid.clone(),
        )?;
        if self.claim_id.is_nil()
            || self.fence == 0
            || !valid_admission_uid(&self.admission_uid)
            || !valid_physical_identity_component(&self.service_account_uid, 512)
            || !valid_kubernetes_credential_id(&self.credential_id)
        {
            return Err(StateError::InvalidRecord(
                "admission claim must be non-nil, fence positive, and UID canonical".to_owned(),
            ));
        }
        let zero = Digest32::from_bytes([0_u8; 32]);
        if [
            self.provider_request_commitment,
            self.credential_token_digest,
            self.credential_binding_commitment,
            self.old_object_commitment,
            self.new_object_commitment,
            self.executor_identity_commitment,
            self.observer_identity_commitment,
        ]
        .contains(&zero)
        {
            return Err(StateError::InvalidRecord(
                "admission commitments must be nonzero".to_owned(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn key(&self) -> &ConsumeKey {
        &self.key
    }

    #[must_use]
    pub fn scope(&self) -> &Scope {
        &self.key.scope
    }

    #[must_use]
    pub const fn transaction_id(&self) -> Uuid {
        self.key.transaction_id
    }

    #[must_use]
    pub const fn authorization_id(&self) -> Uuid {
        self.key.authorization_id
    }

    #[must_use]
    pub const fn claim_id(&self) -> Uuid {
        self.claim_id
    }

    #[must_use]
    pub const fn fence(&self) -> u64 {
        self.fence
    }

    #[must_use]
    pub fn physical_resource(&self) -> &PhysicalResourceKey {
        &self.physical_resource
    }

    #[must_use]
    pub fn admission_uid(&self) -> &str {
        &self.admission_uid
    }

    #[must_use]
    pub const fn credential_token_digest(&self) -> Digest32 {
        self.credential_token_digest
    }

    #[must_use]
    pub fn service_account_uid(&self) -> &str {
        &self.service_account_uid
    }

    #[must_use]
    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }

    #[must_use]
    pub const fn credential_binding_commitment(&self) -> Digest32 {
        self.credential_binding_commitment
    }

    #[must_use]
    pub const fn provider_request_commitment(&self) -> Digest32 {
        self.provider_request_commitment
    }

    #[must_use]
    pub const fn old_object_commitment(&self) -> Digest32 {
        self.old_object_commitment
    }

    #[must_use]
    pub const fn new_object_commitment(&self) -> Digest32 {
        self.new_object_commitment
    }

    #[must_use]
    pub const fn executor_identity_commitment(&self) -> Digest32 {
        self.executor_identity_commitment
    }

    #[must_use]
    pub const fn observer_identity_commitment(&self) -> Digest32 {
        self.observer_identity_commitment
    }

    pub(crate) fn commitment(&self) -> Result<Digest32, StateError> {
        let mut bytes = b"accordlock:v2:admission-authorization-request".to_vec();
        append_length_framed(&mut bytes, self.key.scope.tenant.as_bytes())?;
        append_length_framed(&mut bytes, self.key.scope.environment.as_bytes())?;
        bytes.extend_from_slice(self.key.transaction_id.as_bytes());
        bytes.extend_from_slice(self.key.authorization_id.as_bytes());
        bytes.extend_from_slice(self.claim_id.as_bytes());
        bytes.extend_from_slice(&self.fence.to_be_bytes());
        append_length_framed(
            &mut bytes,
            self.physical_resource.cluster_identity.as_bytes(),
        )?;
        append_length_framed(&mut bytes, self.physical_resource.namespace.as_bytes())?;
        append_length_framed(&mut bytes, self.physical_resource.deployment_uid.as_bytes())?;
        bytes.extend_from_slice(self.credential_token_digest.as_bytes());
        append_length_framed(&mut bytes, self.service_account_uid.as_bytes())?;
        append_length_framed(&mut bytes, self.credential_id.as_bytes())?;
        bytes.extend_from_slice(self.credential_binding_commitment.as_bytes());
        append_length_framed(&mut bytes, self.admission_uid.as_bytes())?;
        bytes.extend_from_slice(self.provider_request_commitment.as_bytes());
        bytes.extend_from_slice(self.old_object_commitment.as_bytes());
        bytes.extend_from_slice(self.new_object_commitment.as_bytes());
        bytes.extend_from_slice(self.executor_identity_commitment.as_bytes());
        bytes.extend_from_slice(self.observer_identity_commitment.as_bytes());
        Ok(Digest32::sha256(&bytes))
    }
}

/// Opaque, current state facts needed to validate one Kubernetes admission.
///
/// The routing key is the only caller-provided lookup input. Claim identity,
/// fence, physical resource, signed template, provider request commitment,
/// current authority, and deadline are all reloaded from state. This value is
/// deliberately neither clonable nor serializable and is not authorization:
/// [`TransactionalState::authorize_admission_or_recover`] rechecks the entire
/// tuple atomically before an ALLOW can be emitted.
#[derive(Debug, PartialEq, Eq)]
pub struct AdmissionContext {
    key: ConsumeKey,
    claim_id: Uuid,
    fence: u64,
    physical_resource: PhysicalResourceKey,
    credential_token_digest: Digest32,
    service_account_uid: String,
    credential_id: String,
    credential_not_before: i64,
    credential_expires_at: i64,
    credential_binding_commitment: Digest32,
    template: DeploymentTemplate,
    template_hash: Digest32,
    operation_hash: Digest32,
    provider_request_commitment: Digest32,
    started_at: i64,
    checked_at: i64,
    dispatch_deadline: i64,
    authority: AuthorityVector,
}

impl AdmissionContext {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        key: ConsumeKey,
        claim_id: Uuid,
        fence: u64,
        physical_resource: PhysicalResourceKey,
        credential_token_digest: Digest32,
        service_account_uid: String,
        credential_id: String,
        credential_not_before: i64,
        credential_expires_at: i64,
        credential_binding_commitment: Digest32,
        template: DeploymentTemplate,
        template_hash: Digest32,
        operation_hash: Digest32,
        provider_request_commitment: Digest32,
        started_at: i64,
        checked_at: i64,
        dispatch_deadline: i64,
        authority: AuthorityVector,
    ) -> Self {
        Self {
            key,
            claim_id,
            fence,
            physical_resource,
            credential_token_digest,
            service_account_uid,
            credential_id,
            credential_not_before,
            credential_expires_at,
            credential_binding_commitment,
            template,
            template_hash,
            operation_hash,
            provider_request_commitment,
            started_at,
            checked_at,
            dispatch_deadline,
            authority,
        }
    }

    #[must_use]
    pub fn key(&self) -> &ConsumeKey {
        &self.key
    }

    #[must_use]
    pub const fn claim_id(&self) -> Uuid {
        self.claim_id
    }

    #[must_use]
    pub const fn fence(&self) -> u64 {
        self.fence
    }

    #[must_use]
    pub fn physical_resource(&self) -> &PhysicalResourceKey {
        &self.physical_resource
    }

    #[must_use]
    pub const fn credential_token_digest(&self) -> Digest32 {
        self.credential_token_digest
    }

    #[must_use]
    pub fn service_account_uid(&self) -> &str {
        &self.service_account_uid
    }

    #[must_use]
    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }

    #[must_use]
    pub const fn credential_not_before(&self) -> i64 {
        self.credential_not_before
    }

    #[must_use]
    pub const fn credential_expires_at(&self) -> i64 {
        self.credential_expires_at
    }

    #[must_use]
    pub const fn credential_binding_commitment(&self) -> Digest32 {
        self.credential_binding_commitment
    }

    #[must_use]
    pub fn template(&self) -> &DeploymentTemplate {
        &self.template
    }

    #[must_use]
    pub const fn template_hash(&self) -> Digest32 {
        self.template_hash
    }

    #[must_use]
    pub const fn operation_hash(&self) -> Digest32 {
        self.operation_hash
    }

    #[must_use]
    pub const fn provider_request_commitment(&self) -> Digest32 {
        self.provider_request_commitment
    }

    #[must_use]
    pub const fn started_at(&self) -> i64 {
        self.started_at
    }

    #[must_use]
    pub const fn checked_at(&self) -> i64 {
        self.checked_at
    }

    #[must_use]
    pub const fn dispatch_deadline(&self) -> i64 {
        self.dispatch_deadline
    }

    #[must_use]
    pub fn authority(&self) -> &AuthorityVector {
        &self.authority
    }

    /// Consumes this state-derived context and adds only observations that the
    /// admission boundary must compute from the authenticated review itself.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::InvalidRecord`] for a malformed UID or zero
    /// commitment.
    #[allow(clippy::too_many_arguments)]
    pub fn authorization_request(
        self,
        admission_uid: String,
        observed_service_account_uid: &str,
        observed_credential_id: &str,
        old_object_commitment: Digest32,
        new_object_commitment: Digest32,
        executor_identity_commitment: Digest32,
        observer_identity_commitment: Digest32,
    ) -> Result<AdmissionAuthorizationRequest, StateError> {
        if observed_service_account_uid != self.service_account_uid
            || observed_credential_id != self.credential_id
        {
            return Err(StateError::AdmissionCredentialMismatch);
        }
        AdmissionAuthorizationRequest::new(
            self.key,
            self.claim_id,
            self.fence,
            self.physical_resource,
            self.credential_token_digest,
            self.service_account_uid,
            self.credential_id,
            self.credential_binding_commitment,
            admission_uid,
            self.provider_request_commitment,
            old_object_commitment,
            new_object_commitment,
            executor_identity_commitment,
            observer_identity_commitment,
        )
    }
}

pub(crate) fn validate_admission_provider_commitment(
    request: &AdmissionAuthorizationRequest,
    issued: &IssuedAuthorizationRecord,
) -> Result<(), StateError> {
    if issued.transaction_id != request.transaction_id()
        || issued.authorization().authorization_id != request.authorization_id()
    {
        return Err(StateError::AdmissionClaimMismatch);
    }
    let expected = admission_provider_commitment(issued)?;
    if expected != request.provider_request_commitment {
        return Err(StateError::AdmissionProviderRequestMismatch);
    }
    Ok(())
}

pub(crate) fn admission_provider_commitment(
    issued: &IssuedAuthorizationRecord,
) -> Result<Digest32, StateError> {
    Ok(admission_projection(issued)?.1)
}

pub(crate) fn admission_projection(
    issued: &IssuedAuthorizationRecord,
) -> Result<(Digest32, Digest32), StateError> {
    let prepared = accordlock_k8s::prepare_patch(
        &issued.authorization().template,
        issued.transaction_id,
        issued.authorization().authorization_id,
    )
    .map_err(|error| {
        StateError::InvalidRecord(format!(
            "stored signed Kubernetes template cannot derive its provider request: {error}"
        ))
    })?;
    Ok((prepared.operation_hash, prepared.final_wire_commitment))
}

fn valid_admission_uid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn append_length_framed(target: &mut Vec<u8>, value: &[u8]) -> Result<(), StateError> {
    let length = u64::try_from(value.len())
        .map_err(|_| StateError::InvalidRecord("admission tuple field is too long".to_owned()))?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
    Ok(())
}

/// Opaque proof that one admission decision is durably committed and current.
///
/// The value is deliberately neither clonable nor serializable. A recovered
/// value represents a fresh revalidation of the original exact tuple, not a
/// durable capability surviving authority revocation or deadline expiry.
#[derive(Debug, PartialEq, Eq)]
pub struct AdmissionAuthorization {
    request: AdmissionAuthorizationRequest,
    authorized_at: i64,
    checked_at: i64,
    recovered: bool,
}

impl AdmissionAuthorization {
    pub(crate) fn new(
        request: AdmissionAuthorizationRequest,
        authorized_at: i64,
        checked_at: i64,
        recovered: bool,
    ) -> Self {
        Self {
            request,
            authorized_at,
            checked_at,
            recovered,
        }
    }

    #[must_use]
    pub fn request(&self) -> &AdmissionAuthorizationRequest {
        &self.request
    }

    #[must_use]
    pub const fn authorized_at(&self) -> i64 {
        self.authorized_at
    }

    #[must_use]
    pub const fn checked_at(&self) -> i64 {
        self.checked_at
    }

    #[must_use]
    pub const fn was_recovered(&self) -> bool {
        self.recovered
    }
}

fn valid_physical_identity_component(value: &str, maximum_length: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_length
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

/// Strict request for the one durable dispatch claim associated with a
/// consumed authorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchClaimRequest {
    pub key: ConsumeKey,
    pub claim_id: Uuid,
    pub worker_id: String,
}

impl DispatchClaimRequest {
    pub(crate) fn validate(&self) -> Result<(), StateError> {
        self.key.validate()?;
        if self.claim_id.is_nil() || !valid_canonical_worker_id(&self.worker_id) {
            return Err(StateError::InvalidRecord(
                "claim_id must be non-nil and worker_id must be canonical".to_owned(),
            ));
        }
        Ok(())
    }
}

fn valid_canonical_worker_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.is_ascii()
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/' | b'@')
        })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OutboxStatus {
    PendingWitness,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboxEntry {
    pub scope: Scope,
    pub transaction_id: Uuid,
    pub authorization_id: Uuid,
    pub dispatch_deadline: i64,
    pub status: OutboxStatus,
    pub receipt: ConsumptionReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsumeSuccess {
    receipt: ConsumptionReceipt,
    outbox: OutboxEntry,
    issued: IssuedAuthorizationRecord,
}

impl ConsumeSuccess {
    pub(crate) fn new(
        receipt: ConsumptionReceipt,
        outbox: OutboxEntry,
        issued: IssuedAuthorizationRecord,
    ) -> Self {
        Self {
            receipt,
            outbox,
            issued,
        }
    }

    #[must_use]
    pub fn receipt(&self) -> &ConsumptionReceipt {
        &self.receipt
    }

    #[must_use]
    pub fn outbox(&self) -> &OutboxEntry {
        &self.outbox
    }

    #[must_use]
    pub fn issued(&self) -> &IssuedAuthorizationRecord {
        &self.issued
    }

    #[must_use]
    pub fn into_parts(self) -> (ConsumptionReceipt, OutboxEntry, IssuedAuthorizationRecord) {
        (self.receipt, self.outbox, self.issued)
    }
}

/// Atomically revalidated state required immediately before dispatch.
///
/// The fields are private and the type is deliberately not serializable. A
/// caller can inspect a snapshot but cannot construct one from request data or
/// revive one from storage after its checked time.
#[derive(Debug, PartialEq, Eq)]
pub struct DispatchSnapshot {
    scope: Scope,
    checked_at: i64,
    authority: AuthorityVector,
    issued: IssuedAuthorizationRecord,
    receipt: ConsumptionReceipt,
    outbox: OutboxEntry,
}

impl DispatchSnapshot {
    pub(crate) fn new(
        scope: Scope,
        checked_at: i64,
        authority: AuthorityVector,
        issued: IssuedAuthorizationRecord,
        receipt: ConsumptionReceipt,
        outbox: OutboxEntry,
    ) -> Self {
        Self {
            scope,
            checked_at,
            authority,
            issued,
            receipt,
            outbox,
        }
    }

    #[must_use]
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    #[must_use]
    pub const fn checked_at(&self) -> i64 {
        self.checked_at
    }

    #[must_use]
    pub fn authority(&self) -> &AuthorityVector {
        &self.authority
    }

    #[must_use]
    pub fn issued(&self) -> &IssuedAuthorizationRecord {
        &self.issued
    }

    #[must_use]
    pub fn receipt(&self) -> &ConsumptionReceipt {
        &self.receipt
    }

    #[must_use]
    pub fn outbox(&self) -> &OutboxEntry {
        &self.outbox
    }
}

/// Opaque durable claim and physical-reservation identity.
///
/// The token is clonable for revalidation, but every use is checked against
/// the exact store lineage and claim row. This profile has no release or
/// takeover operation: lease expiry, process death, and an ambiguous provider
/// attempt retain the physical reservation. Safe retirement requires terminal
/// effect and credential-retirement evidence that is outside this state API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchClaimToken {
    key: ConsumeKey,
    physical_resource: PhysicalResourceKey,
    claim_id: Uuid,
    worker_id: String,
    fence: u64,
    claimed_at: i64,
    lease_until: i64,
    state_instance_id: Uuid,
}

impl DispatchClaimToken {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        key: ConsumeKey,
        physical_resource: PhysicalResourceKey,
        claim_id: Uuid,
        worker_id: String,
        fence: u64,
        claimed_at: i64,
        lease_until: i64,
        state_instance_id: Uuid,
    ) -> Self {
        Self {
            key,
            physical_resource,
            claim_id,
            worker_id,
            fence,
            claimed_at,
            lease_until,
            state_instance_id,
        }
    }

    #[must_use]
    pub fn key(&self) -> &ConsumeKey {
        &self.key
    }

    /// Returns the exact physical Deployment identity reserved by this claim.
    #[must_use]
    pub fn physical_resource(&self) -> &PhysicalResourceKey {
        &self.physical_resource
    }

    #[must_use]
    pub const fn claim_id(&self) -> Uuid {
        self.claim_id
    }

    #[must_use]
    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    #[must_use]
    pub const fn fence(&self) -> u64 {
        self.fence
    }

    #[must_use]
    pub const fn claimed_at(&self) -> i64 {
        self.claimed_at
    }

    #[must_use]
    pub const fn lease_until(&self) -> i64 {
        self.lease_until
    }

    #[must_use]
    pub const fn state_instance_id(&self) -> Uuid {
        self.state_instance_id
    }

    /// Binds an authenticated Kubernetes v1.32+ `ServiceAccount` credential to
    /// this exact opaque claim. The returned value cannot be detached from the
    /// store lineage, claim, fence, or credential lifetime.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::InvalidRecord`] for a zero digest, malformed
    /// `ServiceAccount` UID, non-canonical credential ID, or invalid lifetime.
    pub fn bind_authenticated_credential(
        &self,
        token_digest: [u8; 32],
        service_account_uid: String,
        credential_id: String,
        not_before: i64,
        expires_at: i64,
    ) -> Result<DispatchCredentialBinding, StateError> {
        DispatchCredentialBinding::new(
            self,
            Digest32::from_bytes(token_digest),
            service_account_uid,
            credential_id,
            not_before,
            expires_at,
        )
    }
}

/// Exact credential identity frozen into the durable provider-attempt row.
///
/// Construction requires an opaque [`DispatchClaimToken`]. This value is
/// deliberately non-serializable and carries no bearer bytes.
#[derive(Debug, PartialEq, Eq)]
pub struct DispatchCredentialBinding {
    binding_version: i16,
    key: ConsumeKey,
    claim_id: Uuid,
    fence: u64,
    state_instance_id: Uuid,
    acquisition_id: Option<Uuid>,
    acquisition_lease_fence: Option<u64>,
    acquisition_worker_id: Option<String>,
    acquisition_acquired_at: Option<i64>,
    acquisition_lease_until: Option<i64>,
    dispatch_deadline: Option<i64>,
    control_submission_id: Option<Uuid>,
    credential_review_id: Option<Uuid>,
    credential_review_commitment: Option<Digest32>,
    token_digest: Digest32,
    service_account_uid: String,
    credential_id: String,
    not_before: i64,
    expires_at: i64,
    commitment: Digest32,
}

impl DispatchCredentialBinding {
    fn new(
        token: &DispatchClaimToken,
        token_digest: Digest32,
        service_account_uid: String,
        credential_id: String,
        not_before: i64,
        expires_at: i64,
    ) -> Result<Self, StateError> {
        if token_digest == Digest32::from_bytes([0; 32])
            || !valid_physical_identity_component(&service_account_uid, 512)
            || !valid_kubernetes_credential_id(&credential_id)
            || not_before < 0
            || expires_at <= not_before
        {
            return Err(StateError::InvalidRecord(
                "dispatch credential identity or lifetime is invalid".to_owned(),
            ));
        }
        let mut bytes = b"accordlock:v1:dispatch-credential-binding\0".to_vec();
        append_length_framed(&mut bytes, token.key.scope.tenant.as_bytes())?;
        append_length_framed(&mut bytes, token.key.scope.environment.as_bytes())?;
        bytes.extend_from_slice(token.key.transaction_id.as_bytes());
        bytes.extend_from_slice(token.key.authorization_id.as_bytes());
        bytes.extend_from_slice(token.claim_id.as_bytes());
        bytes.extend_from_slice(&token.fence.to_be_bytes());
        bytes.extend_from_slice(token.state_instance_id.as_bytes());
        bytes.extend_from_slice(token_digest.as_bytes());
        append_length_framed(&mut bytes, service_account_uid.as_bytes())?;
        append_length_framed(&mut bytes, credential_id.as_bytes())?;
        bytes.extend_from_slice(&not_before.to_be_bytes());
        bytes.extend_from_slice(&expires_at.to_be_bytes());
        Ok(Self {
            binding_version: 1,
            key: token.key.clone(),
            claim_id: token.claim_id,
            fence: token.fence,
            state_instance_id: token.state_instance_id,
            acquisition_id: None,
            acquisition_lease_fence: None,
            acquisition_worker_id: None,
            acquisition_acquired_at: None,
            acquisition_lease_until: None,
            dispatch_deadline: None,
            control_submission_id: None,
            credential_review_id: None,
            credential_review_commitment: None,
            token_digest,
            service_account_uid,
            credential_id,
            not_before,
            expires_at,
            commitment: Digest32::sha256(&bytes),
        })
    }

    pub(crate) fn new_for_acquisition(
        authority: &crate::DispatchAcquisitionAuthority,
        token_digest: Digest32,
        service_account_uid: String,
        credential_id: String,
        not_before: i64,
        expires_at: i64,
    ) -> Result<Self, StateError> {
        let token = authority.claim();
        if token_digest == Digest32::from_bytes([0; 32])
            || !valid_physical_identity_component(&service_account_uid, 512)
            || !valid_kubernetes_credential_id(&credential_id)
            || not_before < 0
            || expires_at <= not_before
            || authority.acquisition_id().is_nil()
            || authority.lease_fence() == 0
            || authority.worker_id().is_empty()
            || authority.acquired_at() < 0
            || authority.lease_until() <= authority.acquired_at()
            || authority.dispatch_deadline() < authority.lease_until()
        {
            return Err(StateError::InvalidRecord(
                "dispatch acquisition credential identity or lifetime is invalid".to_owned(),
            ));
        }
        let mut bytes = b"accordlock:v2:dispatch-credential-binding\0".to_vec();
        append_length_framed(&mut bytes, token.key.scope.tenant.as_bytes())?;
        append_length_framed(&mut bytes, token.key.scope.environment.as_bytes())?;
        bytes.extend_from_slice(token.key.transaction_id.as_bytes());
        bytes.extend_from_slice(token.key.authorization_id.as_bytes());
        bytes.extend_from_slice(token.claim_id.as_bytes());
        append_length_framed(&mut bytes, token.worker_id.as_bytes())?;
        bytes.extend_from_slice(&token.fence.to_be_bytes());
        bytes.extend_from_slice(&token.claimed_at.to_be_bytes());
        bytes.extend_from_slice(&token.lease_until.to_be_bytes());
        bytes.extend_from_slice(token.state_instance_id.as_bytes());
        append_length_framed(
            &mut bytes,
            token.physical_resource.cluster_identity().as_bytes(),
        )?;
        append_length_framed(&mut bytes, token.physical_resource.namespace().as_bytes())?;
        append_length_framed(
            &mut bytes,
            token.physical_resource.deployment_uid().as_bytes(),
        )?;
        bytes.extend_from_slice(authority.acquisition_id().as_bytes());
        bytes.extend_from_slice(&authority.lease_fence().to_be_bytes());
        append_length_framed(&mut bytes, authority.worker_id().as_bytes())?;
        bytes.extend_from_slice(&authority.acquired_at().to_be_bytes());
        bytes.extend_from_slice(&authority.lease_until().to_be_bytes());
        bytes.extend_from_slice(&authority.dispatch_deadline().to_be_bytes());
        match authority.control_submission_id() {
            Some(submission_id) => {
                bytes.push(1);
                bytes.extend_from_slice(submission_id.as_bytes());
            }
            None => bytes.push(0),
        }
        bytes.extend_from_slice(token_digest.as_bytes());
        append_length_framed(&mut bytes, service_account_uid.as_bytes())?;
        append_length_framed(&mut bytes, credential_id.as_bytes())?;
        bytes.extend_from_slice(&not_before.to_be_bytes());
        bytes.extend_from_slice(&expires_at.to_be_bytes());
        Ok(Self {
            binding_version: 2,
            key: token.key.clone(),
            claim_id: token.claim_id,
            fence: token.fence,
            state_instance_id: token.state_instance_id,
            acquisition_id: Some(authority.acquisition_id()),
            acquisition_lease_fence: Some(authority.lease_fence()),
            acquisition_worker_id: Some(authority.worker_id().to_owned()),
            acquisition_acquired_at: Some(authority.acquired_at()),
            acquisition_lease_until: Some(authority.lease_until()),
            dispatch_deadline: Some(authority.dispatch_deadline()),
            control_submission_id: authority.control_submission_id(),
            credential_review_id: None,
            credential_review_commitment: None,
            token_digest,
            service_account_uid,
            credential_id,
            not_before,
            expires_at,
            commitment: Digest32::sha256(&bytes),
        })
    }

    pub(crate) fn into_v2(
        self,
        authority: &crate::DispatchAcquisitionAuthority,
    ) -> Result<Self, StateError> {
        if !self.matches_token(authority.claim()) {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        Self::new_for_acquisition(
            authority,
            self.token_digest,
            self.service_account_uid,
            self.credential_id,
            self.not_before,
            self.expires_at,
        )
    }

    pub(crate) fn new_for_review(
        authority: &crate::DispatchAcquisitionAuthority,
        claims: &crate::DispatchCredentialReviewClaims,
        review_id: Uuid,
        review_commitment: Digest32,
    ) -> Result<Self, StateError> {
        if review_id.is_nil() || review_commitment == Digest32::from_bytes([0; 32]) {
            return Err(StateError::InvalidRecord(
                "dispatch credential review binding is invalid".to_owned(),
            ));
        }
        let mut binding = Self::new_for_acquisition(
            authority,
            claims.token_digest(),
            claims.service_account_uid().to_owned(),
            claims.credential_id().to_owned(),
            claims.not_before(),
            claims.expires_at(),
        )?;
        let mut bytes = b"accordlock:v2:dispatch-reviewed-credential-binding\0".to_vec();
        bytes.extend_from_slice(binding.commitment.as_bytes());
        bytes.extend_from_slice(review_id.as_bytes());
        bytes.extend_from_slice(review_commitment.as_bytes());
        binding.credential_review_id = Some(review_id);
        binding.credential_review_commitment = Some(review_commitment);
        binding.commitment = Digest32::sha256(&bytes);
        Ok(binding)
    }

    #[must_use]
    pub const fn binding_version(&self) -> i16 {
        self.binding_version
    }

    #[must_use]
    pub const fn token_digest(&self) -> Digest32 {
        self.token_digest
    }

    #[must_use]
    pub fn service_account_uid(&self) -> &str {
        &self.service_account_uid
    }

    #[must_use]
    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }

    #[must_use]
    pub const fn not_before(&self) -> i64 {
        self.not_before
    }

    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }

    #[must_use]
    pub const fn commitment(&self) -> Digest32 {
        self.commitment
    }

    #[must_use]
    pub const fn credential_review_id(&self) -> Option<Uuid> {
        self.credential_review_id
    }

    #[must_use]
    pub const fn credential_review_commitment(&self) -> Option<Digest32> {
        self.credential_review_commitment
    }

    pub(crate) fn matches_acquisition(
        &self,
        authority: &crate::DispatchAcquisitionAuthority,
    ) -> bool {
        self.binding_version == 2
            && self.matches_token(authority.claim())
            && self.acquisition_id == Some(authority.acquisition_id())
            && self.acquisition_lease_fence == Some(authority.lease_fence())
            && self.acquisition_worker_id.as_deref() == Some(authority.worker_id())
            && self.acquisition_acquired_at == Some(authority.acquired_at())
            && self.acquisition_lease_until == Some(authority.lease_until())
            && self.dispatch_deadline == Some(authority.dispatch_deadline())
            && self.control_submission_id == authority.control_submission_id()
    }

    pub(crate) fn matches_review(
        &self,
        authority: &crate::DispatchAcquisitionAuthority,
        review_id: Uuid,
        review_commitment: Digest32,
    ) -> bool {
        self.matches_acquisition(authority)
            && self.credential_review_id == Some(review_id)
            && self.credential_review_commitment == Some(review_commitment)
    }

    pub(crate) fn matches_token(&self, token: &DispatchClaimToken) -> bool {
        self.key == token.key
            && self.claim_id == token.claim_id
            && self.fence == token.fence
            && self.state_instance_id == token.state_instance_id
    }
}

fn valid_kubernetes_credential_id(value: &str) -> bool {
    let Some(encoded) = value.strip_prefix("AUTHORIZATION_ID=") else {
        return false;
    };
    Uuid::parse_str(encoded)
        .ok()
        .is_some_and(|parsed| !parsed.is_nil() && encoded == parsed.to_string())
}

/// The sole successful result of creating a durable dispatch claim.
///
/// This value is non-clonable. Retrying claim creation, including with the
/// same claim identifier, never reconstructs it.
#[derive(Debug, PartialEq, Eq)]
pub struct ClaimedDispatch {
    snapshot: DispatchSnapshot,
    token: DispatchClaimToken,
}

impl ClaimedDispatch {
    pub(crate) fn new(snapshot: DispatchSnapshot, token: DispatchClaimToken) -> Self {
        Self { snapshot, token }
    }

    #[must_use]
    pub fn snapshot(&self) -> &DispatchSnapshot {
        &self.snapshot
    }

    #[must_use]
    pub fn token(&self) -> &DispatchClaimToken {
        &self.token
    }

    #[must_use]
    pub fn into_parts(self) -> (DispatchSnapshot, DispatchClaimToken) {
        (self.snapshot, self.token)
    }
}

/// Immutable acquisition generation committed by the durable
/// `CLAIMED -> ATTEMPT_IN_FLIGHT` compare-and-set.
///
/// This is an audit/lifetime fact, not reusable acquisition authority. It is
/// clonable so post-attempt components can retain the exact fence and lease
/// that state committed without receiving a capability that can prepare more
/// broker work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchAttemptAcquisition {
    acquisition_id: Uuid,
    lease_fence: u64,
    worker_id: String,
    acquired_at: i64,
    lease_until: i64,
    dispatch_deadline: i64,
    control_submission_id: Option<Uuid>,
    credential_review_id: Option<Uuid>,
    credential_lifecycle_policy: Option<EksCredentialLifecyclePolicy>,
    destination_activation_commitment: Option<Digest32>,
}

impl DispatchAttemptAcquisition {
    pub(crate) fn from_authority(authority: &crate::DispatchAcquisitionAuthority) -> Self {
        Self {
            acquisition_id: authority.acquisition_id(),
            lease_fence: authority.lease_fence(),
            worker_id: authority.worker_id().to_owned(),
            acquired_at: authority.acquired_at(),
            lease_until: authority.lease_until(),
            dispatch_deadline: authority.dispatch_deadline(),
            control_submission_id: authority.control_submission_id(),
            credential_review_id: None,
            credential_lifecycle_policy: None,
            destination_activation_commitment: None,
        }
    }

    pub(crate) fn from_reviewed(
        authority: &crate::DispatchAcquisitionAuthority,
        reviewed: &crate::ReviewedDispatchCredential,
    ) -> Self {
        let mut facts = Self::from_authority(authority);
        facts.credential_review_id = Some(reviewed.review_id());
        facts.credential_lifecycle_policy = Some(reviewed.credential_lifecycle_policy());
        facts.destination_activation_commitment =
            Some(reviewed.destination_activation_commitment());
        facts
    }

    #[must_use]
    pub const fn acquisition_id(&self) -> Uuid {
        self.acquisition_id
    }

    #[must_use]
    pub const fn lease_fence(&self) -> u64 {
        self.lease_fence
    }

    #[must_use]
    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    #[must_use]
    pub const fn acquired_at(&self) -> i64 {
        self.acquired_at
    }

    #[must_use]
    pub const fn lease_until(&self) -> i64 {
        self.lease_until
    }

    #[must_use]
    pub const fn dispatch_deadline(&self) -> i64 {
        self.dispatch_deadline
    }

    #[must_use]
    pub const fn control_submission_id(&self) -> Option<Uuid> {
        self.control_submission_id
    }

    #[must_use]
    pub const fn credential_review_id(&self) -> Option<Uuid> {
        self.credential_review_id
    }

    #[must_use]
    pub const fn credential_lifecycle_policy(&self) -> Option<EksCredentialLifecyclePolicy> {
        self.credential_lifecycle_policy
    }

    #[must_use]
    pub const fn destination_activation_commitment(&self) -> Option<Digest32> {
        self.destination_activation_commitment
    }
}

/// Immutable acquisition facts retained by the no-send recovery state.
///
/// These values are audit-only. They do not carry the stable claim token,
/// credential, current snapshot, or any authority that can begin provider I/O.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchRecoveryAcquisition {
    acquisition_id: Uuid,
    lease_fence: u64,
    worker_id: String,
    acquired_at: i64,
    lease_until: i64,
    dispatch_deadline: i64,
    control_submission_id: Uuid,
}

impl DispatchRecoveryAcquisition {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        acquisition_id: Uuid,
        lease_fence: u64,
        worker_id: String,
        acquired_at: i64,
        lease_until: i64,
        dispatch_deadline: i64,
        control_submission_id: Uuid,
    ) -> Self {
        Self {
            acquisition_id,
            lease_fence,
            worker_id,
            acquired_at,
            lease_until,
            dispatch_deadline,
            control_submission_id,
        }
    }

    #[must_use]
    pub const fn acquisition_id(&self) -> Uuid {
        self.acquisition_id
    }

    #[must_use]
    pub const fn lease_fence(&self) -> u64 {
        self.lease_fence
    }

    #[must_use]
    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    #[must_use]
    pub const fn acquired_at(&self) -> i64 {
        self.acquired_at
    }

    #[must_use]
    pub const fn lease_until(&self) -> i64 {
        self.lease_until
    }

    #[must_use]
    pub const fn dispatch_deadline(&self) -> i64 {
        self.dispatch_deadline
    }

    #[must_use]
    pub const fn control_submission_id(&self) -> Uuid {
        self.control_submission_id
    }
}

/// One-shot authority proving that the durable claim was atomically moved to
/// `ATTEMPT_IN_FLIGHT` after a fresh state recheck.
#[derive(Debug, PartialEq, Eq)]
pub struct AttemptInFlight {
    snapshot: DispatchSnapshot,
    token: DispatchClaimToken,
    started_at: i64,
    acquisition: DispatchAttemptAcquisition,
}

/// Inert result of closing an authenticated acquisition after its productive
/// lease/currentness window can no longer be revalidated.
///
/// This value proves only that state durably entered the explicit no-send
/// recovery state. That state is never a provider attempt and never implies
/// that external provider I/O began. The receipt contains no dispatch snapshot,
/// acquisition authority, bearer, or provider-I/O capability; its sole purpose
/// is audit and frozen cleanup.
#[derive(Debug, PartialEq, Eq)]
pub struct RecoveryNoSendReceipt {
    key: ConsumeKey,
    acquisition: DispatchRecoveryAcquisition,
}

impl RecoveryNoSendReceipt {
    pub(crate) fn new(key: ConsumeKey, acquisition: DispatchRecoveryAcquisition) -> Self {
        Self { key, acquisition }
    }

    #[must_use]
    pub const fn key(&self) -> &ConsumeKey {
        &self.key
    }

    #[must_use]
    pub const fn acquisition(&self) -> &DispatchRecoveryAcquisition {
        &self.acquisition
    }
}

/// Durable retirement receipt for a no-send recovery generation.
#[derive(Debug, PartialEq, Eq)]
pub struct RecoveryNoSendRetirementReceipt {
    key: ConsumeKey,
    acquisition: DispatchRecoveryAcquisition,
    safe_after: i64,
    retired_at: i64,
}

impl RecoveryNoSendRetirementReceipt {
    pub(crate) fn new(
        key: ConsumeKey,
        acquisition: DispatchRecoveryAcquisition,
        safe_after: i64,
        retired_at: i64,
    ) -> Self {
        Self {
            key,
            acquisition,
            safe_after,
            retired_at,
        }
    }

    #[must_use]
    pub const fn key(&self) -> &ConsumeKey {
        &self.key
    }

    #[must_use]
    pub const fn acquisition(&self) -> &DispatchRecoveryAcquisition {
        &self.acquisition
    }

    #[must_use]
    pub const fn safe_after(&self) -> i64 {
        self.safe_after
    }

    #[must_use]
    pub const fn retired_at(&self) -> i64 {
        self.retired_at
    }
}

/// Idempotent state result of attempting no-send retirement.
#[derive(Debug, PartialEq, Eq)]
pub enum RecoveryNoSendRetirementOutcome {
    Pending { safe_after: i64 },
    Retired(RecoveryNoSendRetirementReceipt),
    Recovered(RecoveryNoSendRetirementReceipt),
}

impl AttemptInFlight {
    pub(crate) fn new(
        snapshot: DispatchSnapshot,
        authority: crate::DispatchAcquisitionAuthority,
        started_at: i64,
    ) -> Self {
        let acquisition = DispatchAttemptAcquisition::from_authority(&authority);
        let token = authority.claim;
        Self {
            snapshot,
            token,
            started_at,
            acquisition,
        }
    }

    pub(crate) fn new_reviewed(
        snapshot: DispatchSnapshot,
        authority: crate::DispatchAcquisitionAuthority,
        reviewed: &crate::ReviewedDispatchCredential,
        started_at: i64,
    ) -> Self {
        let acquisition = DispatchAttemptAcquisition::from_reviewed(&authority, reviewed);
        let token = authority.claim;
        Self {
            snapshot,
            token,
            started_at,
            acquisition,
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> &DispatchSnapshot {
        &self.snapshot
    }

    #[must_use]
    pub fn token(&self) -> &DispatchClaimToken {
        &self.token
    }

    #[must_use]
    pub const fn started_at(&self) -> i64 {
        self.started_at
    }

    #[must_use]
    pub const fn acquisition(&self) -> &DispatchAttemptAcquisition {
        &self.acquisition
    }

    #[must_use]
    pub const fn acquisition_id(&self) -> Uuid {
        self.acquisition.acquisition_id
    }

    #[must_use]
    pub const fn acquisition_lease_fence(&self) -> u64 {
        self.acquisition.lease_fence
    }

    #[must_use]
    pub fn acquisition_worker_id(&self) -> &str {
        &self.acquisition.worker_id
    }

    #[must_use]
    pub const fn acquisition_acquired_at(&self) -> i64 {
        self.acquisition.acquired_at
    }

    #[must_use]
    pub const fn acquisition_lease_until(&self) -> i64 {
        self.acquisition.lease_until
    }

    #[must_use]
    pub const fn dispatch_deadline(&self) -> i64 {
        self.acquisition.dispatch_deadline
    }

    #[must_use]
    pub const fn control_submission_id(&self) -> Option<Uuid> {
        self.acquisition.control_submission_id
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        DispatchSnapshot,
        DispatchClaimToken,
        DispatchAttemptAcquisition,
        i64,
    ) {
        (self.snapshot, self.token, self.acquisition, self.started_at)
    }
}

#[derive(Debug, Error)]
pub enum StateError {
    #[error("invalid state record: {0}")]
    InvalidRecord(String),
    #[error("invalid deadline inputs: {0}")]
    InvalidDeadline(String),
    #[error("deadline arithmetic overflow")]
    DeadlineOverflow,
    #[error("dispatch window is empty at {observed}; deadline is {deadline}")]
    EmptyDispatchWindow { observed: i64, deadline: i64 },
    #[error("authority state is not initialized")]
    AuthorityNotInitialized,
    #[error("authority compare-and-set failed")]
    AuthorityCompareFailed,
    #[error("authority vector does not exactly match active state")]
    AuthorityMismatch,
    #[error("authority epochs must be monotone and every changed domain must advance")]
    NonMonotoneAuthority,
    #[error("grant is not registered")]
    GrantNotFound,
    #[error("grant is already registered")]
    GrantAlreadyExists,
    #[error("grant does not match the issued authorization")]
    GrantMismatch,
    #[error("active grant-registry root does not commit to the registered grant")]
    GrantRegistryRootMismatch,
    #[error("grant is revoked")]
    GrantRevoked,
    #[error("grant is not valid before {not_before}; observed {observed}")]
    GrantNotYetValid { observed: i64, not_before: i64 },
    #[error("grant expired at {expires_at}; observed {observed}")]
    GrantExpired { observed: i64, expires_at: i64 },
    #[error("grant maximum use count is exhausted")]
    GrantExhausted,
    #[error("grant has no committed consumption")]
    GrantNotConsumed,
    #[error("authorization is not registered")]
    AuthorizationNotFound,
    #[error("authorization or transaction is already registered")]
    AuthorizationAlreadyExists,
    #[error("issued authorization signature or signer-authority binding is invalid: {0}")]
    InvalidAuthorizationSignature(String),
    #[error("consumption receipt or outbox entry does not exist")]
    ConsumptionNotFound,
    #[error("transaction identifier does not match the issued authorization")]
    TransactionMismatch,
    #[error("authorization is not valid before {not_before}; observed {observed}")]
    AuthorizationNotYetValid { observed: i64, not_before: i64 },
    #[error("authorization expired at {consume_before}; observed {observed}")]
    AuthorizationExpired { observed: i64, consume_before: i64 },
    #[error("immutable dependency expired at {expiry}; observed {observed}")]
    DependencyExpired { observed: i64, expiry: i64 },
    #[error("dispatch deadline {dispatch_deadline} reached at {observed}")]
    DispatchDeadlineExpired {
        observed: i64,
        dispatch_deadline: i64,
    },
    #[error("the consumed authorization already has a durable dispatch claim")]
    DispatchAlreadyClaimed,
    #[error("the signed physical resource already has a durable dispatch reservation")]
    PhysicalResourceAlreadyReserved,
    #[error(
        "dispatch claim outcome is unknown; reconciliation is required and no claim authority is returned"
    )]
    DispatchClaimOutcomeUnknown,
    #[error("durable dispatch claim does not exist")]
    DispatchClaimNotFound,
    #[error("dispatch claim token does not exactly match durable state")]
    DispatchClaimMismatch,
    #[error("dispatch acquisition identity, worker, claim, or lease generation does not match")]
    DispatchAcquisitionMismatch,
    #[error("control-owned dispatch work requires a server-selected acquisition")]
    DispatchAcquisitionRequired,
    #[error("global dispatch acquisition lease fence is exhausted")]
    DispatchAcquisitionFenceExhausted,
    #[error("dispatch claim lease expired at {lease_until}; observed {observed}")]
    DispatchClaimLeaseExpired { observed: i64, lease_until: i64 },
    #[error("dispatch credential is not active at the trusted provider-attempt boundary")]
    DispatchCredentialExpired,
    #[error(
        "provider-attempt transition outcome is unknown; reconciliation is required and no attempt authority is returned"
    )]
    DispatchAttemptOutcomeUnknown,
    #[error("durable broker operation does not exist")]
    BrokerOperationNotFound,
    #[error("broker operation does not exactly match durable journal state")]
    BrokerOperationMismatch,
    #[error("broker mutation authority has already crossed or may have crossed the wire boundary")]
    BrokerOperationOutcomeUnknown,
    #[error("broker operation is not in the required durable phase")]
    BrokerOperationInvalidTransition,
    #[error("TokenRequest issuance is one-shot and has no resend or GET reconciliation path")]
    BrokerTokenReissueForbidden,
    #[error("durable dispatch credential review does not exist")]
    DispatchCredentialReviewNotFound,
    #[error("dispatch credential review does not exactly match its acquisition and broker lineage")]
    DispatchCredentialReviewMismatch,
    #[error("dispatch credential review has crossed or may have crossed its durable boundary")]
    DispatchCredentialReviewOutcomeUnknown,
    #[error("dispatch credential review was durably rejected")]
    DispatchCredentialReviewRejected,
    #[error("dispatch claim is not in ATTEMPT_IN_FLIGHT state")]
    AdmissionClaimNotInFlight,
    #[error("admission request does not exactly match its durable dispatch claim and reservation")]
    AdmissionClaimMismatch,
    #[error("admission caller credential does not match the credential frozen for the attempt")]
    AdmissionCredentialMismatch,
    #[error("AdmissionReview UID is already bound to a different authorization tuple")]
    AdmissionUidMismatch,
    #[error("the dispatch transaction already has a different admission authorization")]
    AdmissionAlreadyAuthorized,
    #[error("provider request commitment is already bound to another admission authorization")]
    AdmissionProviderRequestReplay,
    #[error("provider request commitment does not match the stored signed authorization")]
    AdmissionProviderRequestMismatch,
    #[error("terminal-witness registry material is absent")]
    TerminalWitnessRegistryNotFound,
    #[error("terminal-witness registry material or rooted activation differs")]
    TerminalWitnessRegistryMismatch,
    #[error("terminal-witness registry commit outcome is unknown; exact recovery is required")]
    TerminalWitnessRegistryOutcomeUnknown,
    #[error("durable terminal-retirement lineage is incomplete or inconsistent")]
    TerminalRetirementLineageUnavailable,
    #[error("terminal-retirement request differs from committed or durable state")]
    TerminalRetirementMismatch,
    #[error("terminal-retirement commit outcome is unknown; exact recovery is required")]
    TerminalRetirementOutcomeUnknown,
    #[error("terminal evidence is invalid: {0}")]
    TerminalEvidenceInvalid(String),
    #[error(
        "authenticated terminal evidence is future at {observed}; trusted time is {trusted_now}"
    )]
    TerminalEvidenceFuture { observed: i64, trusted_now: i64 },
    #[error(
        "admission authorization outcome is unknown; no admission authority is returned and reconciliation is required"
    )]
    AdmissionOutcomeUnknown,
    #[error("global dispatch fence is exhausted")]
    DispatchFenceExhausted,
    #[error("execution authorization ID has already been consumed")]
    AlreadyConsumed,
    #[error(
        "consumption outcome is unknown; the exact durable receipt and outbox tuple could not be recovered"
    )]
    ConsumptionOutcomeUnknown,
    #[error("ingress replay-ledger outcome is unknown; no authentication success may be returned")]
    IngressReplayOutcomeUnknown,
    #[error("authenticated ingress key is not current at {observed}")]
    ControlIngressKeyNotCurrent { observed: i64 },
    #[error("authenticated ingress request is not valid before {not_before}; observed {observed}")]
    ControlIngressNotYetValid { observed: i64, not_before: i64 },
    #[error("authenticated ingress request expired at {expires_at}; observed {observed}")]
    ControlIngressExpired { observed: i64, expires_at: i64 },
    #[error("durable control submission does not exist")]
    ControlSubmissionNotFound,
    #[error("durable control submission differs from the exact recovery identity")]
    ControlSubmissionMismatch,
    #[error("request identifier is already bound to a different payload submission")]
    ControlRequestConflict,
    #[error("ingress nonce is already bound to another durable or live replay record")]
    ControlNonceAlreadyUsed,
    #[error("durable control work or claim does not exist")]
    ControlWorkNotFound,
    #[error("durable control work claim, role, phase, lease, or fence does not match")]
    ControlWorkMismatch,
    #[error("control work lease expired at {lease_until}; observed {observed}")]
    ControlWorkLeaseExpired { observed: i64, lease_until: i64 },
    #[error("global control-work fence is exhausted")]
    ControlWorkFenceExhausted,
    #[error("stored control evaluation or decision differs from the exact phase result")]
    ControlDecisionMismatch,
    #[error("control status receipt does not exist in the requested scope")]
    ControlStatusNotFound,
    #[error("trusted clock is before the Unix epoch")]
    ClockBeforeUnixEpoch,
    #[error("trusted time rollback: observed {observed}, durable high-water {high_water}")]
    ClockRollback { observed: i64, high_water: i64 },
    #[error("database transaction must be retried")]
    RetryableConflict,
    #[error("database serialization retry limit exhausted")]
    RetryLimitExhausted,
    #[error("database schema does not match the required AccordLock migration profile: {0}")]
    SchemaMismatch(String),
    #[error(
        "the local PostgreSQL adapter requires an explicit loopback address or local Unix socket"
    )]
    UnsafePostgresConnection,
    #[error("canonical encoding failed: {0}")]
    Canonical(#[from] CanonicalError),
    #[error("state serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("database operation failed: {0}")]
    Database(#[from] postgres::Error),
}

/// Returns whether `error` is a trusted-time rejection produced for the exact
/// observation sampled by an exactly routed state operation.
///
/// Callers use this narrow classification only after routing and, where
/// applicable, claim-token identity have been checked. Persisting the sample
/// prevents an expired observation from disappearing on rollback while the
/// equality check prevents a temporal-looking error embedded in stored data
/// from advancing the high-water mark.
pub(crate) fn is_temporal_rejection_for_sample(error: &StateError, observed_time: i64) -> bool {
    match error {
        StateError::EmptyDispatchWindow { observed, .. }
        | StateError::GrantNotYetValid { observed, .. }
        | StateError::GrantExpired { observed, .. }
        | StateError::AuthorizationNotYetValid { observed, .. }
        | StateError::AuthorizationExpired { observed, .. }
        | StateError::DependencyExpired { observed, .. }
        | StateError::DispatchDeadlineExpired { observed, .. }
        | StateError::DispatchClaimLeaseExpired { observed, .. }
        | StateError::ControlIngressKeyNotCurrent { observed }
        | StateError::ControlIngressNotYetValid { observed, .. }
        | StateError::ControlIngressExpired { observed, .. }
        | StateError::ControlWorkLeaseExpired { observed, .. } => *observed == observed_time,
        _ => false,
    }
}

/// Shared interface implemented by the local and `PostgreSQL` adapters.
pub trait TransactionalState: crate::sealed::Sealed + Send + Sync {
    /// Atomically installs `next` only if the exact current vector equals
    /// `expected`. `None` means that the scope must not yet exist.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] for invalid scope, failed comparison, or a
    /// non-monotone authority transition.
    fn compare_and_activate_authority(
        &self,
        scope: &Scope,
        expected: Option<&AuthorityVector>,
        next: &AuthorityVector,
    ) -> Result<(), StateError>;

    /// Loads the exact active authority vector.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when the scope is invalid or uninitialized.
    fn active_authority(&self, scope: &Scope) -> Result<AuthorityVector, StateError>;

    /// Registers trusted capability-grant material.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] if the grant is invalid or already registered.
    fn register_grant(&self, grant: &GrantRegistration) -> Result<(), StateError>;

    /// Loads the current grant, use count, and revocation state.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] if the scope is invalid or the grant is absent.
    fn grant_snapshot(&self, scope: &Scope, grant_id: Uuid) -> Result<GrantSnapshot, StateError>;

    /// Loads a non-forgeable, current grant/authority/time/policy snapshot for
    /// the trusted authorization issuer.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] if any current authority, registration, clock,
    /// revocation, validity, or use-budget condition fails.
    fn issuance_snapshot(
        &self,
        scope: &Scope,
        grant_id: Uuid,
    ) -> Result<IssuanceSnapshot, StateError>;

    /// Revokes a registered grant.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] if the scope is invalid or the grant is absent.
    fn revoke_grant(
        &self,
        scope: &Scope,
        grant_id: Uuid,
        expected_authority: &AuthorityVector,
        next_authority: &AuthorityVector,
    ) -> Result<(), StateError>;

    /// Records immutable issuance material. This is a trusted internal write,
    /// not a public request schema.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] if the record is invalid, mismatched, or already
    /// registered.
    fn record_issued_authorization(
        &self,
        record: &IssuedAuthorizationRecord,
    ) -> Result<(), StateError>;

    /// Consumes using only identifiers. All security state is reloaded.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when any authority, time, grant, authorization, replay,
    /// or transactional precondition fails.
    fn consume(&self, key: &ConsumeKey) -> Result<ConsumeSuccess, StateError>;

    /// Consumes once or recovers the exact previously committed result for the
    /// same tenant, environment, transaction identifier, and execution authorization ID.
    ///
    /// This is the idempotent boundary for callers that may have lost a commit
    /// response. A recovered result is returned only after the issued authorization,
    /// receipt, outbox entry, scalar identity, and frozen deadline agree. An `AUTHORIZATION_ID`
    /// belonging to another transaction is never converted into success.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::ConsumptionOutcomeUnknown`] when a storage failure
    /// prevents the adapter from confirming either a new commit or the exact
    /// durable tuple. Other validation, mismatch, or corruption errors remain
    /// fail-closed.
    fn consume_or_recover(&self, key: &ConsumeKey) -> Result<ConsumeSuccess, StateError>;

    /// Atomically reloads and revalidates all state required immediately
    /// before an external dispatch.
    ///
    /// The durable time high-water mark advances when a complete snapshot is
    /// accepted and when an exact routed record is rejected only because a
    /// trusted temporal boundary was reached. Unknown or mismatched routing
    /// never advances it. The returned value is opaque and cannot be
    /// deserialized or constructed outside this crate.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] if routing, signature, authority, grant,
    /// consumption, outbox, trusted-time, or dispatch-window validation fails.
    fn dispatch_snapshot(&self, key: &ConsumeKey) -> Result<DispatchSnapshot, StateError>;

    /// Atomically validates current dispatch state and creates its only durable
    /// claim plus the global reservation for the exact signed physical
    /// Deployment identity. Tenant, environment, display name, container, and
    /// resource version do not partition that reservation. A repeated request
    /// never reconstructs claim authority. An exact routed temporal rejection
    /// durably advances the trusted-time high-water mark before returning its
    /// deterministic error.
    ///
    /// This minimal profile is fail-closed and intentionally has no release
    /// operation. A later lifecycle API must require terminal effect and
    /// credential-retirement evidence before changing reservation ownership.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::DispatchAlreadyClaimed`] for a distinct second
    /// claim on the same authorization,
    /// [`StateError::PhysicalResourceAlreadyReserved`] for another authorization on
    /// the reserved Deployment, and [`StateError::DispatchClaimOutcomeUnknown`]
    /// for a repeated or commit-ambiguous claim identifier.
    fn claim_dispatch(&self, request: &DispatchClaimRequest)
    -> Result<ClaimedDispatch, StateError>;

    /// Selects the next eligible v13 `DISPATCH_PENDING` outbox item and
    /// atomically creates or takes over its append-only acquisition lease.
    ///
    /// The worker supplies only its canonical identity and an idempotency
    /// UUID. State selects the work and generates the stable claim identity,
    /// stable claim fence, lease fence, timestamps, and deadline. Exact retry
    /// can reconstruct authority only while the same acquisition remains the
    /// latest unexpired generation and no broker, admission, attempt, or
    /// terminal artifact exists.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when the request or trusted scope is invalid,
    /// immutable control lineage cannot be authenticated, trusted time rolls
    /// back, the exact request conflicts with durable history, or the selected
    /// work cannot be acquired safely.
    fn claim_next_pending_dispatch_or_recover(
        &self,
        scope: &Scope,
        request: &crate::DispatchAcquisitionRequest,
    ) -> Result<crate::DispatchAcquisitionOutcome, StateError>;

    /// Revalidates an existing claim against its exact store lineage and the
    /// complete current dispatch snapshot. This does not renew its lease. A
    /// temporal rejection after exact token validation advances the durable
    /// trusted-time high-water mark.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] for a stale, expired, mismatched, or no-longer
    /// active claim, or for any current state validation failure.
    fn revalidate_dispatch_claim(
        &self,
        token: &DispatchClaimToken,
    ) -> Result<DispatchSnapshot, StateError>;

    /// Revalidates one exact latest acquisition generation. Unlike exact
    /// recovery, the held authority may continue after its own CREATE/TOKEN
    /// journal rows exist, but every origin must match this generation.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when the generation is stale, expired,
    /// superseded, mismatched, or no longer current.
    fn revalidate_dispatch_acquisition(
        &self,
        authority: &crate::DispatchAcquisitionAuthority,
    ) -> Result<DispatchSnapshot, StateError>;

    /// Atomically revalidates current state and irreversibly marks the one
    /// provider attempt in flight. A temporal rejection after exact token
    /// validation advances the durable trusted-time high-water mark without
    /// changing the claim state.
    ///
    /// A repeated call or an ambiguous database outcome never reconstructs
    /// [`AttemptInFlight`].
    ///
    /// # Errors
    ///
    /// Returns [`StateError::DispatchAttemptOutcomeUnknown`] when the attempt
    /// may already have crossed the durable boundary.
    fn mark_attempt_in_flight(
        &self,
        token: &DispatchClaimToken,
        credential: DispatchCredentialBinding,
    ) -> Result<AttemptInFlight, StateError>;

    /// Consumes the opaque durable authenticated-review proof, reconstructs
    /// its exact acquisition tuple internally, revalidates latest/current
    /// state and trusted time, then atomically commits the live v2
    /// provider-attempt boundary. This path is productive only while the
    /// caller still holds its independently authenticated bearer and dispatch
    /// import; it never reconstructs either one after a process restart.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when the proof or frozen broker lineage differs,
    /// or when latest/current/temporal revalidation fails.
    fn mark_dispatch_acquisition_attempt_in_flight(
        &self,
        reviewed: crate::ReviewedDispatchCredential,
    ) -> Result<AttemptInFlight, StateError>;

    /// Closes an exact control acquisition with durable pre-attempt broker or
    /// credential-review artifacts through an inert no-send CAS. It never
    /// samples time, consults current authority, or records attempt/credential
    /// facts, and returns no claim, provider, or acquisition authority.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] unless the recovery key identifies the exact
    /// latest control acquisition and its frozen pre-attempt artifacts.
    fn close_dispatch_acquisition_no_send(
        &self,
        key: &crate::DispatchAcquisitionRecoveryKey,
    ) -> Result<RecoveryNoSendReceipt, StateError>;

    /// Retires an exact no-send recovery only after durable Secret absence and
    /// the rooted deletion-propagation plus clock-uncertainty bound. Pending
    /// calls advance trusted dual-HWM state but keep the physical reservation;
    /// the unique retirement CAS releases it without creating provider or
    /// terminal authority.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when no-send lineage, durable absence, rooted
    /// policy, trusted time, or reservation ownership differs.
    fn retire_recovery_no_send(
        &self,
        key: &crate::DispatchAcquisitionRecoveryKey,
    ) -> Result<RecoveryNoSendRetirementOutcome, StateError>;

    /// Loads opaque, state-derived facts for validating one `AdmissionReview`.
    ///
    /// The caller supplies only the durable routing key. The implementation
    /// requires the exact claim to be `ATTEMPT_IN_FLIGHT`, verifies its global
    /// physical reservation, and revalidates authority, grant, deadline, and
    /// trusted time before returning. The result is preparatory data, not an
    /// authorization. Final authorization always rechecks current state.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when routing, claim state, reservation, signed
    /// template, authority, grant, deadline, or trusted-time validation fails.
    fn admission_context(&self, key: &ConsumeKey) -> Result<AdmissionContext, StateError>;

    /// Atomically commits or conditionally recovers one exact Kubernetes
    /// `AdmissionReview` authorization for an in-flight dispatch claim.
    ///
    /// Recovery requires the same UID and complete tuple, then rechecks the
    /// claim, physical reservation, current authority and grant, frozen
    /// deadline, trusted clock, and durable high-water mark. A historical
    /// `ADMITTED` row is retained for audit when any current condition fails,
    /// but it is never returned as current authority. This boundary does not
    /// accept dry-run requests and does not assert that Kubernetes persisted
    /// the admitted object.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] for mismatched, replayed, stale, expired, or
    /// revoked inputs. [`StateError::AdmissionOutcomeUnknown`] means the
    /// durable commit could not be determined and no ALLOW may be emitted.
    fn authorize_admission_or_recover(
        &self,
        request: &AdmissionAuthorizationRequest,
    ) -> Result<AdmissionAuthorization, StateError>;

    /// Loads the durable consumption receipt.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] if the key is invalid or has not been consumed.
    fn consumption_receipt(&self, key: &ConsumeKey) -> Result<ConsumptionReceipt, StateError>;

    /// Loads the durable pending witness outbox entry.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] if the key is invalid or no entry exists.
    fn outbox_entry(&self, key: &ConsumeKey) -> Result<OutboxEntry, StateError>;

    /// Returns the durable accepted-time high-water mark, if initialized.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] if the scope is invalid or storage fails.
    fn time_high_water(&self, scope: &Scope) -> Result<Option<i64>, StateError>;
}

pub(crate) fn ensure_monotone_authority(
    current: &AuthorityVector,
    next: &AuthorityVector,
) -> Result<(), StateError> {
    validate_authority_vector(current)?;
    validate_authority_vector(next)?;
    for (old, new) in current.domains().iter().zip(next.domains()) {
        if new.epoch < old.epoch || (new != *old && new.epoch <= old.epoch) {
            return Err(StateError::NonMonotoneAuthority);
        }
    }
    Ok(())
}

pub(crate) fn validate_authority_vector(authority: &AuthorityVector) -> Result<(), StateError> {
    if authority
        .domains()
        .iter()
        .any(|domain| domain.activation_id.is_nil())
    {
        return Err(StateError::InvalidRecord(
            "authority activation identifiers must be non-nil".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_revocation_transition(
    grant_id: Uuid,
    expected: &AuthorityVector,
    next: &AuthorityVector,
) -> Result<(), StateError> {
    ensure_monotone_authority(expected, next)?;
    let expected_domains = expected.domains();
    let next_domains = next.domains();
    for (index, (old, new)) in expected_domains.iter().zip(next_domains).enumerate() {
        if index == 2 {
            if new.epoch <= old.epoch
                || new.root != grant_revocation_root(grant_id)
                || new.activation_id == old.activation_id
            {
                return Err(StateError::NonMonotoneAuthority);
            }
        } else if new != *old {
            return Err(StateError::NonMonotoneAuthority);
        }
    }
    Ok(())
}

#[must_use]
pub fn grant_revocation_root(grant_id: Uuid) -> Digest32 {
    let mut material = b"accordlock:v1:single-grant-revoked:".to_vec();
    material.extend_from_slice(grant_id.as_bytes());
    Digest32::sha256(&material)
}

pub(crate) fn validate_grant_for_authorization(
    registration: &GrantRegistration,
    authorization: &ExecutionAuthorization,
) -> Result<(), StateError> {
    let grant = &registration.grant;
    if registration.authority != authorization.authority
        || registration.dispatch_deadline_policy != authorization.dispatch_deadline_policy
        || grant.grant_id != authorization.grant_id
        || grant.tenant != authorization.tenant
        || registration.environment != authorization.template.environment
        || grant.holder != authorization.holder
        || grant.operation != authorization.template.operation
        || grant.repository != authorization.template.repository
        || grant.audience != authorization.audience
        || grant.cluster_identity != authorization.template.cluster_identity
        || grant.namespace != authorization.template.namespace
        || grant.deployment_uid != authorization.template.deployment_uid
        || grant.container != authorization.template.container
        || grant.image_repository != authorization.template.image_repository
        || authorization.issued_at < grant.not_before
        || authorization.issued_at >= grant.expires_at
        || authorization.not_before < grant.not_before
        || authorization.consume_before > grant.expires_at
    {
        return Err(StateError::GrantMismatch);
    }
    Ok(())
}

pub(crate) fn validate_current_grant(
    active_authority: &AuthorityVector,
    grant: &GrantSnapshot,
    observed_time: i64,
) -> Result<(), StateError> {
    if observed_time < 0 {
        return Err(StateError::ClockBeforeUnixEpoch);
    }
    grant.registration.validate()?;
    if &grant.registration.authority != active_authority {
        return Err(StateError::AuthorityMismatch);
    }
    if grant.revoked {
        return Err(StateError::GrantRevoked);
    }
    if observed_time < grant.registration.grant.not_before {
        return Err(StateError::GrantNotYetValid {
            observed: observed_time,
            not_before: grant.registration.grant.not_before,
        });
    }
    if observed_time >= grant.registration.grant.expires_at {
        return Err(StateError::GrantExpired {
            observed: observed_time,
            expires_at: grant.registration.grant.expires_at,
        });
    }
    if grant.uses >= grant.registration.grant.maximum_uses {
        return Err(StateError::GrantExhausted);
    }
    compute_dispatch_deadline(
        observed_time,
        grant.registration.grant.expires_at,
        &grant.registration.dispatch_deadline_policy,
    )?;
    Ok(())
}

pub(crate) fn validate_consumption(
    active_authority: &AuthorityVector,
    grant: &GrantSnapshot,
    issued: &IssuedAuthorizationRecord,
    observed_time: i64,
    high_water: Option<i64>,
) -> Result<i64, StateError> {
    if observed_time < 0 {
        return Err(StateError::ClockBeforeUnixEpoch);
    }
    if let Some(high_water) = high_water
        && observed_time < high_water
    {
        return Err(StateError::ClockRollback {
            observed: observed_time,
            high_water,
        });
    }
    issued.validate()?;
    let authorization = issued.authorization();
    if active_authority != &authorization.authority {
        return Err(StateError::AuthorityMismatch);
    }
    validate_grant_for_authorization(&grant.registration, authorization)?;
    if observed_time < authorization.not_before {
        return Err(StateError::AuthorizationNotYetValid {
            observed: observed_time,
            not_before: authorization.not_before,
        });
    }
    if observed_time >= authorization.consume_before {
        return Err(StateError::AuthorizationExpired {
            observed: observed_time,
            consume_before: authorization.consume_before,
        });
    }
    validate_current_grant(active_authority, grant, observed_time)?;
    compute_dispatch_deadline(
        observed_time,
        authorization.consume_before,
        &authorization.dispatch_deadline_policy,
    )
}

pub(crate) fn validate_recovered_consumption(
    key: &ConsumeKey,
    issued: &IssuedAuthorizationRecord,
    receipt: &ConsumptionReceipt,
    outbox: &OutboxEntry,
) -> Result<ConsumeSuccess, StateError> {
    key.validate()?;
    issued.validate()?;
    if issued.transaction_id != key.transaction_id
        || issued.authorization().authorization_id != key.authorization_id
        || issued.scope() != key.scope
    {
        return Err(StateError::TransactionMismatch);
    }
    let expected_dispatch_deadline = compute_dispatch_deadline(
        receipt.consumed_at,
        issued.authorization().consume_before,
        &issued.authorization().dispatch_deadline_policy,
    )?;
    if receipt.schema_version != issued.authorization().schema_version
        || receipt.transaction_id != key.transaction_id
        || receipt.authorization_id != key.authorization_id
        || receipt.authority != issued.authorization().authority
        || receipt.authorization_hash != issued.authorization_hash
        || receipt.consumed_at < issued.authorization().not_before
        || receipt.consumed_at >= issued.authorization().consume_before
        || receipt.dispatch_deadline != expected_dispatch_deadline
        || outbox.scope != key.scope
        || outbox.transaction_id != key.transaction_id
        || outbox.authorization_id != key.authorization_id
        || outbox.dispatch_deadline != expected_dispatch_deadline
        || outbox.status != OutboxStatus::PendingWitness
        || outbox.receipt != *receipt
    {
        return Err(StateError::InvalidRecord(
            "recovered authorization, receipt, outbox, and consume key do not agree".to_owned(),
        ));
    }
    Ok(ConsumeSuccess::new(
        receipt.clone(),
        outbox.clone(),
        issued.clone(),
    ))
}

/// Authenticates the immutable post-CONSUME facts that every dispatch path
/// relies on, without consulting current authority, revocation, or time.
///
/// Queue disposition is intentionally allowed for expected currentness
/// failures, but it must never turn a corrupt grant/authorization/receipt/outbox tuple
/// into durable history. Keep this gate ahead of disposition classification in
/// every adapter.
pub(crate) fn validate_dispatch_immutable_facts(
    key: &ConsumeKey,
    grant: &GrantSnapshot,
    issued: &IssuedAuthorizationRecord,
    receipt: &ConsumptionReceipt,
    outbox: &OutboxEntry,
) -> Result<(), StateError> {
    validate_recovered_consumption(key, issued, receipt, outbox)?;
    grant.registration.validate()?;
    validate_grant_for_authorization(&grant.registration, issued.authorization())?;
    if grant.uses == 0 {
        return Err(StateError::GrantNotConsumed);
    }
    if grant.uses > grant.registration.grant.maximum_uses {
        return Err(StateError::InvalidRecord(
            "stored grant use count exceeds its maximum".to_owned(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_dispatch_snapshot(
    key: &ConsumeKey,
    active_authority: &AuthorityVector,
    grant: &GrantSnapshot,
    issued: &IssuedAuthorizationRecord,
    receipt: &ConsumptionReceipt,
    outbox: &OutboxEntry,
    observed_time: i64,
    high_water: Option<i64>,
) -> Result<DispatchSnapshot, StateError> {
    if observed_time < 0 {
        return Err(StateError::ClockBeforeUnixEpoch);
    }
    if let Some(high_water) = high_water
        && observed_time < high_water
    {
        return Err(StateError::ClockRollback {
            observed: observed_time,
            high_water,
        });
    }

    validate_dispatch_immutable_facts(key, grant, issued, receipt, outbox)?;
    if observed_time < receipt.consumed_at {
        return Err(StateError::ClockRollback {
            observed: observed_time,
            high_water: receipt.consumed_at,
        });
    }
    let authorization = issued.authorization();
    if grant.revoked {
        return Err(StateError::GrantRevoked);
    }
    if active_authority != &authorization.authority
        || active_authority != &receipt.authority
        || active_authority != &grant.registration.authority
    {
        return Err(StateError::AuthorityMismatch);
    }
    if observed_time >= receipt.dispatch_deadline {
        return Err(StateError::DispatchDeadlineExpired {
            observed: observed_time,
            dispatch_deadline: receipt.dispatch_deadline,
        });
    }
    if observed_time >= authorization.consume_before {
        return Err(StateError::AuthorizationExpired {
            observed: observed_time,
            consume_before: authorization.consume_before,
        });
    }
    validate_deadline_policy(&authorization.dispatch_deadline_policy)?;
    if let Some(expiry) = authorization
        .dispatch_deadline_policy
        .immutable_dependency_expiries
        .iter()
        .copied()
        .find(|expiry| *expiry <= observed_time)
    {
        return Err(StateError::DependencyExpired {
            observed: observed_time,
            expiry,
        });
    }

    Ok(DispatchSnapshot::new(
        key.scope.clone(),
        observed_time,
        active_authority.clone(),
        issued.clone(),
        receipt.clone(),
        outbox.clone(),
    ))
}
