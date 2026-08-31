//! Exclusive native EKS effect boundary for one `AccordLock` execution profile.
//!
//! The crate consumes the non-clonable `AuthorizedProviderAttempt` manufactured
//! only after the durable `ATTEMPT_IN_FLIGHT` transition. It then rederives the
//! exact Kubernetes JSON Patch, verifies every available binding, performs a
//! final local deadline and process-wide fence check, and hands the committed
//! bytes to a native transport exactly once.
//!
//! The process-wide fence is not a Kubernetes-enforced fence. It prevents two
//! cooperating executor instances in one process from overlapping or replaying
//! an attempt. Complete mediation still requires exclusive destination
//! credentials and a destination-side fence or equivalent admission rule.

use std::{
    collections::BTreeMap,
    fmt,
    sync::{Mutex, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use accordlock_dispatch::{
    AuthenticatedObserver, AuthorizedProviderAttempt, EffectBinding, ExactEffectEvidence,
    PhysicalResourceId,
};
use accordlock_eks_profile::{EksCredentialLifecyclePolicy, EksRouteProfile, RouteField};
use accordlock_k8s::{
    patch_wire_body, prepare_patch, validate_authorized_delta, validate_preconditions,
};
use accordlock_protocol::{DeploymentTemplate, Digest32, canonical_hash};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

const PATCH_CONTENT_TYPE: &str = "application/json-patch+json";
const RESPONSE_COMMITMENT_DOMAIN: &[u8] = b"accordlock:v1:eks-native-response\0";
const PRE_STATE_COMMITMENT_DOMAIN: &[u8] = b"accordlock:v1:eks-pre-state\0";
const POST_STATE_COMMITMENT_DOMAIN: &[u8] = b"accordlock:v1:eks-post-state\0";
const EMITTED_BODY_COMMITMENT_DOMAIN: &[u8] = b"accordlock:v1:eks-emitted-body\0";

/// Immutable deployment profile owned by one executor instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutorConfig {
    route_profile: EksRouteProfile,
    physical: PhysicalResourceId,
    observer_identity: String,
    credential_lifecycle_policy: EksCredentialLifecyclePolicy,
}

impl ExecutorConfig {
    /// Creates one exact executor profile.
    ///
    /// # Errors
    ///
    /// Returns an error when an identity is empty, non-canonical, or otherwise
    /// unsuitable for a security boundary.
    pub fn new(
        route_profile: EksRouteProfile,
        observer_identity: String,
        credential_lifecycle_policy: EksCredentialLifecyclePolicy,
    ) -> Result<Self, ExecutorError> {
        if !valid_observer_identity(&observer_identity) {
            return Err(ExecutorError::InvalidConfiguration);
        }
        let physical = physical_from_route(&route_profile);
        Ok(Self {
            route_profile,
            physical,
            observer_identity,
            credential_lifecycle_policy,
        })
    }

    #[must_use]
    pub const fn physical(&self) -> &PhysicalResourceId {
        &self.physical
    }

    /// Returns the single complete route from which every executor
    /// destination fact was derived.
    #[must_use]
    pub const fn route_profile(&self) -> &EksRouteProfile {
        &self.route_profile
    }

    /// Returns the complete EKS credential lifecycle tuple used for every
    /// trusted-time decision. The enforcement composition must match this
    /// value against the state-backed broker record before any provider I/O.
    #[must_use]
    pub const fn credential_lifecycle_policy(&self) -> EksCredentialLifecyclePolicy {
        self.credential_lifecycle_policy
    }
}

/// Bearer credential moved into the exclusive execution call.
///
/// The value is non-clonable, redacts `Debug`, and overwrites its allocation on
/// drop. Rust cannot prove that the credential issuer or surrounding process
/// retained no copy. Exclusive custody remains a deployment invariant.
pub struct ExclusiveBearer {
    bytes: Vec<u8>,
}

impl ExclusiveBearer {
    /// Wraps non-empty bearer bytes for one execution attempt.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or unreasonably large credential.
    pub fn new(bytes: Vec<u8>) -> Result<Self, ExecutorError> {
        if bytes.is_empty() || bytes.len() > 64 * 1024 {
            return Err(ExecutorError::InvalidCredential);
        }
        Ok(Self { bytes })
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for ExclusiveBearer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExclusiveBearer")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl Drop for ExclusiveBearer {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

/// Exact caller material consumed together with provider-attempt authority.
#[derive(Debug)]
pub struct EksExecutionInput {
    template: DeploymentTemplate,
    bearer: ExclusiveBearer,
    credential_lifecycle_policy: EksCredentialLifecyclePolicy,
    destination_activation_commitment: [u8; 32],
}

impl EksExecutionInput {
    #[must_use]
    pub const fn new(
        template: DeploymentTemplate,
        bearer: ExclusiveBearer,
        credential_lifecycle_policy: EksCredentialLifecyclePolicy,
        destination_activation_commitment: [u8; 32],
    ) -> Self {
        Self {
            template,
            bearer,
            credential_lifecycle_policy,
            destination_activation_commitment,
        }
    }
}

/// Trusted time source used at the final local send boundary.
pub trait TrustedClock: Send + Sync {
    /// Returns non-negative Unix seconds from a deployment-trusted clock.
    ///
    /// # Errors
    ///
    /// Returns a non-secret diagnostic when trusted time is unavailable.
    fn unix_seconds(&self) -> Result<i64, String>;
}

/// Host system clock adapter. Production profiles should document how the
/// host clock is protected and monitored.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl TrustedClock for SystemClock {
    fn unix_seconds(&self) -> Result<i64, String> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before the Unix epoch".to_owned())?;
        i64::try_from(elapsed.as_secs()).map_err(|_| "Unix time exceeds i64".to_owned())
    }
}

/// Read-only native Kubernetes GET request generated by the executor.
pub struct NativeGetRequest<'a> {
    api_server_identity: &'a str,
    path: &'a str,
    bearer: &'a [u8],
}

impl fmt::Debug for NativeGetRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeGetRequest")
            .field("api_server_identity", &self.api_server_identity)
            .field("path", &self.path)
            .field("bearer", &"[REDACTED]")
            .finish()
    }
}

impl<'a> NativeGetRequest<'a> {
    #[must_use]
    pub const fn api_server_identity(&self) -> &'a str {
        self.api_server_identity
    }

    #[must_use]
    pub const fn method(&self) -> &'static str {
        "GET"
    }

    #[must_use]
    pub const fn path(&self) -> &'a str {
        self.path
    }

    #[must_use]
    pub const fn bearer(&self) -> &'a [u8] {
        self.bearer
    }
}

/// Exact native Kubernetes PATCH request generated by the executor.
///
/// There is no shell command, caller-selected method, caller-selected path, or
/// caller-selected body in this interface.
pub struct NativePatchRequest<'a> {
    api_server_identity: &'a str,
    path: &'a str,
    content_type: &'static str,
    body: &'a [u8],
    bearer: &'a [u8],
    claim_fence: u64,
    acquisition_id: Uuid,
    acquisition_lease_fence: u64,
    transaction_id: Uuid,
    provider_request_commitment: [u8; 32],
}

impl fmt::Debug for NativePatchRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativePatchRequest")
            .field("api_server_identity", &self.api_server_identity)
            .field("path", &self.path)
            .field("content_type", &self.content_type)
            .field("body_length", &self.body.len())
            .field("bearer", &"[REDACTED]")
            .field("claim_fence", &self.claim_fence)
            .field("acquisition_id", &self.acquisition_id)
            .field("acquisition_lease_fence", &self.acquisition_lease_fence)
            .field("transaction_id", &self.transaction_id)
            .field(
                "provider_request_commitment",
                &self.provider_request_commitment,
            )
            .finish()
    }
}

impl<'a> NativePatchRequest<'a> {
    #[must_use]
    pub const fn api_server_identity(&self) -> &'a str {
        self.api_server_identity
    }

    #[must_use]
    pub const fn method(&self) -> &'static str {
        "PATCH"
    }

    #[must_use]
    pub const fn path(&self) -> &'a str {
        self.path
    }

    #[must_use]
    pub const fn content_type(&self) -> &'static str {
        self.content_type
    }

    #[must_use]
    pub const fn body(&self) -> &'a [u8] {
        self.body
    }

    #[must_use]
    pub const fn bearer(&self) -> &'a [u8] {
        self.bearer
    }

    /// Returns the local process fence for telemetry only. Kubernetes does not
    /// enforce this value in the current profile.
    #[must_use]
    pub const fn local_fence(&self) -> u64 {
        self.acquisition_lease_fence
    }

    #[must_use]
    pub const fn stable_claim_fence(&self) -> u64 {
        self.claim_fence
    }

    #[must_use]
    pub const fn acquisition_id(&self) -> Uuid {
        self.acquisition_id
    }

    #[must_use]
    pub const fn transaction_id(&self) -> Uuid {
        self.transaction_id
    }

    /// Returns the re-derived commitment to method, path, content type, and
    /// exact request body. A future destination admission profile can bind and
    /// durably consume this value together with its own admission UID.
    #[must_use]
    pub const fn provider_request_commitment(&self) -> [u8; 32] {
        self.provider_request_commitment
    }
}

/// Exact response bytes and authenticated peer identity returned by a native
/// transport adapter.
#[derive(Clone, PartialEq, Eq)]
pub struct NativeEksResponse {
    status: u16,
    api_server_identity: String,
    channel_authentication_commitment: [u8; 32],
    body: Vec<u8>,
}

impl fmt::Debug for NativeEksResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeEksResponse")
            .field("status", &self.status)
            .field("api_server_identity", &self.api_server_identity)
            .field(
                "channel_authentication_commitment",
                &self.channel_authentication_commitment,
            )
            .field("body_length", &self.body.len())
            .finish()
    }
}

impl NativeEksResponse {
    #[must_use]
    pub const fn new(
        status: u16,
        api_server_identity: String,
        channel_authentication_commitment: [u8; 32],
        body: Vec<u8>,
    ) -> Self {
        Self {
            status,
            api_server_identity,
            channel_authentication_commitment,
            body,
        }
    }

    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// Failure classification supplied by the trusted native transport.
///
/// The executor never retries either class. `DefinitelyNotSent` is useful for
/// audit and recovery policy. `OutcomeUnknown` permanently quarantines the
/// process-local resource key because the destination does not enforce fences.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum TransportFailure {
    #[error("native transport established that the mutation was not sent: {0}")]
    DefinitelyNotSent(String),
    #[error("native transport cannot establish the mutation outcome: {0}")]
    OutcomeUnknown(String),
}

/// One-shot authorization evaluated by a native transport after the TLS peer
/// is authenticated and immediately before its first HTTP application write.
///
/// Consuming this value is the linearization point for a provider mutation.
/// A transport that rejects it must close the authenticated connection and
/// return [`TransportFailure::DefinitelyNotSent`].
pub struct NativePreWriteAuthorization<'a> {
    validator: Option<Box<dyn FnOnce() -> Result<(), TransportFailure> + 'a>>,
}

impl fmt::Debug for NativePreWriteAuthorization<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativePreWriteAuthorization")
            .field("available", &self.validator.is_some())
            .finish()
    }
}

impl<'a> NativePreWriteAuthorization<'a> {
    fn new<F>(validator: F) -> Self
    where
        F: FnOnce() -> Result<(), TransportFailure> + 'a,
    {
        Self {
            validator: Some(Box::new(validator)),
        }
    }

    /// Consumes and evaluates the sole pre-write authorization.
    ///
    /// # Errors
    ///
    /// Returns [`TransportFailure::DefinitelyNotSent`] when the trusted
    /// executor no longer authorizes the first application byte.
    pub fn authorize(mut self) -> Result<(), TransportFailure> {
        self.validator.take().ok_or_else(|| {
            TransportFailure::DefinitelyNotSent(
                "pre-write authorization was already consumed".to_owned(),
            )
        })?()
    }
}

/// Native, non-shell Kubernetes transport boundary.
pub trait NativeEksTransport: Send + Sync {
    /// Returns the exact immutable route used to authenticate and contact the
    /// provider. The executor compares this structurally before every I/O.
    fn route_profile(&self) -> &EksRouteProfile;

    /// Returns a trusted upper bound for one complete provider operation,
    /// including connection establishment, TLS, request write, and response
    /// read. Immediately before PATCH, the executor requires strictly more
    /// token lifetime than this bound plus configured clock uncertainty.
    fn operation_timeout_upper_bound(&self) -> Duration;

    /// Reads the exact Deployment immediately before mutation.
    ///
    /// # Errors
    ///
    /// Returns a typed transport failure. A GET failure never authorizes a
    /// PATCH and is therefore fail-closed.
    fn get_deployment(
        &self,
        request: NativeGetRequest<'_>,
    ) -> Result<NativeEksResponse, TransportFailure>;

    /// Sends the exact committed JSON Patch at most once.
    ///
    /// # Errors
    ///
    /// Returns a typed failure distinguishing known non-delivery from an
    /// ambiguous provider outcome.
    fn patch_deployment(
        &self,
        request: NativePatchRequest<'_>,
        immediately_before_first_write: NativePreWriteAuthorization<'_>,
    ) -> Result<NativeEksResponse, TransportFailure>;
}

/// Typed, locally verified effect observation produced after one native PATCH.
///
/// `local_fence` records process-local exclusion. It is deliberately not part
/// of `ExactEffectEvidence` because the Kubernetes destination has not attested
/// to or enforced that fence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EksEffectObservation {
    transaction_id: Uuid,
    physical: PhysicalResourceId,
    local_fence: u64,
    acquisition_id: Uuid,
    dispatch_deadline: i64,
    sent_at: i64,
    pre_state_commitment: [u8; 32],
    emitted_body_commitment: [u8; 32],
    evidence: ExactEffectEvidence,
}

impl EksEffectObservation {
    #[must_use]
    pub const fn transaction_id(&self) -> Uuid {
        self.transaction_id
    }

    #[must_use]
    pub const fn physical(&self) -> &PhysicalResourceId {
        &self.physical
    }

    #[must_use]
    pub const fn local_fence(&self) -> u64 {
        self.local_fence
    }

    #[must_use]
    pub const fn acquisition_id(&self) -> Uuid {
        self.acquisition_id
    }

    #[must_use]
    pub const fn dispatch_deadline(&self) -> i64 {
        self.dispatch_deadline
    }

    #[must_use]
    pub const fn sent_at(&self) -> i64 {
        self.sent_at
    }

    #[must_use]
    pub const fn pre_state_commitment(&self) -> [u8; 32] {
        self.pre_state_commitment
    }

    #[must_use]
    pub const fn emitted_body_commitment(&self) -> [u8; 32] {
        self.emitted_body_commitment
    }

    #[must_use]
    pub const fn evidence(&self) -> &ExactEffectEvidence {
        &self.evidence
    }

    #[must_use]
    pub fn into_evidence(self) -> ExactEffectEvidence {
        self.evidence
    }
}

/// Fail-closed executor errors. No variant authorizes an automatic retry of a
/// consumed provider attempt.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ExecutorError {
    #[error("executor configuration is malformed")]
    InvalidConfiguration,
    #[error("executor and transport routes differ at {0:?}")]
    RouteMismatch(RouteField),
    #[error("attempt authority is internally malformed: {0}")]
    InvalidAttempt(&'static str),
    #[error("execution credential is empty, oversized, or mismatched")]
    InvalidCredential,
    #[error("state-backed EKS lifecycle or activation facts differ across boundaries")]
    ExecutionProfileMismatch,
    #[error("attempt or template targets another executor destination")]
    DestinationMismatch,
    #[error("template does not match the committed attempt binding: {0}")]
    BindingMismatch(&'static str),
    #[error("Kubernetes projection failed closed: {0}")]
    Projection(String),
    #[error("trusted clock failed: {0}")]
    Clock(String),
    #[error("trusted time {observed} precedes attempt start {started_at}")]
    NonMonotoneTime { observed: i64, started_at: i64 },
    #[error("dispatch deadline {dispatch_deadline} reached at {observed}")]
    DeadlineExpired {
        observed: i64,
        dispatch_deadline: i64,
    },
    #[error("durable claim lease {lease_until} reached at {observed}")]
    LeaseExpired { observed: i64, lease_until: i64 },
    #[error(
        "attempt credential is unusable at {observed}; valid interval is [{not_before}, {expires_at})"
    )]
    CredentialExpired {
        observed: i64,
        not_before: i64,
        expires_at: i64,
    },
    #[error(
        "attempt credential has insufficient lifetime at {observed}; expiry {expires_at} must be more than {required_remaining_seconds}s away"
    )]
    CredentialLifetimeInsufficient {
        observed: i64,
        expires_at: i64,
        required_remaining_seconds: i64,
    },
    #[error(
        "execution horizon {safe_horizon} from trusted time {observed} must be strictly before credential expiry {token_expires_at}, dispatch deadline {dispatch_deadline}, and acquisition lease {acquisition_lease_until}"
    )]
    ExecutionWindowInsufficient {
        observed: i64,
        safe_horizon: i64,
        token_expires_at: i64,
        dispatch_deadline: i64,
        acquisition_lease_until: i64,
    },
    #[error("local fence {presented} is not newer than high-water {highest}")]
    StaleLocalFence { presented: u64, highest: u64 },
    #[error("another local attempt is already in flight for the physical resource")]
    LocalResourceBusy,
    #[error("the physical resource is quarantined after an ambiguous local send")]
    LocalResourceQuarantined,
    #[error("process-local fence registry is unavailable")]
    FenceRegistryUnavailable,
    #[error("preflight GET failed closed: {0}")]
    PreflightTransport(String),
    #[error("API-server response is unauthenticated or from another destination")]
    ResponseIdentityMismatch,
    #[error("preflight API-server GET returned unexpected status {0}")]
    PreflightUnexpectedStatus(u16),
    #[error("post-send API-server status {0} does not establish a no-effect result")]
    PatchStatusOutcomeUnknown(u16),
    #[error("API-server response is not valid JSON: {0}")]
    InvalidResponse(String),
    #[error("preflight snapshot differs from the authorization-bound target projection")]
    PreStateCommitmentMismatch,
    #[error("native transport established that the mutation was not sent: {0}")]
    PatchDefinitelyNotSent(String),
    #[error("native mutation outcome is unknown and the local resource is quarantined: {0}")]
    PatchOutcomeUnknown(String),
    #[error("provider returned success but the exact effect is not established: {0}")]
    EffectUnverifiable(String),
    #[error("post-send observation time {observed} does not follow attempt start {started_at}")]
    ObservationTimeInvalid { observed: i64, started_at: i64 },
}

/// Exclusive execution boundary parameterized by native transport and trusted
/// clock adapters.
#[derive(Debug)]
pub struct ExclusiveEksExecutor<T, C> {
    config: ExecutorConfig,
    transport: T,
    clock: C,
    minimum_safe_horizon_seconds: Option<i64>,
}

impl<T, C> ExclusiveEksExecutor<T, C>
where
    T: NativeEksTransport,
    C: TrustedClock,
{
    /// Constructs an executor from trusted bootstrap dependencies. The exact
    /// executor/transport route comparison is repeated by [`Self::execute`]
    /// immediately before any provider I/O.
    #[must_use]
    pub fn new(config: ExecutorConfig, transport: T, clock: C) -> Self {
        let minimum_safe_horizon_seconds = duration_ceiling_seconds(
            transport.operation_timeout_upper_bound(),
        )
        .and_then(|seconds| {
            seconds.checked_add(
                config
                    .credential_lifecycle_policy
                    .clock_uncertainty_seconds(),
            )
        });
        Self {
            config,
            transport,
            clock,
            minimum_safe_horizon_seconds,
        }
    }

    /// Returns the exact route shared by the executor and its transport.
    #[must_use]
    pub const fn route_profile(&self) -> &EksRouteProfile {
        self.config.route_profile()
    }

    /// Returns the complete credential lifecycle policy fixed at trusted
    /// bootstrap. It is compared with the broker's rooted attempt facts by the
    /// enforcement composition.
    #[must_use]
    pub const fn credential_lifecycle_policy(&self) -> EksCredentialLifecyclePolicy {
        self.config.credential_lifecycle_policy()
    }

    /// Consumes exactly one opaque provider-attempt authority and one bearer.
    ///
    /// No branch retries a PATCH. A failure after possible delivery quarantines
    /// the resource in the process-local fence registry.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError`] on any destination, template, credential,
    /// time, fence, transport, response, or effect-evidence mismatch.
    pub fn execute(
        &self,
        attempt: AuthorizedProviderAttempt,
        input: EksExecutionInput,
    ) -> Result<EksEffectObservation, ExecutorError> {
        ensure_route_match(self.config.route_profile(), self.transport.route_profile())?;
        let facts = AttemptFacts::from_authorized(&attempt);
        // The authority is intentionally consumed by this call. No raw or
        // serializable authority surrogate leaves the extraction boundary.
        drop(attempt);
        self.execute_facts(facts, input)
    }

    #[allow(clippy::too_many_lines)]
    fn execute_facts(
        &self,
        facts: AttemptFacts,
        input: EksExecutionInput,
    ) -> Result<EksEffectObservation, ExecutorError> {
        ensure_route_match(self.config.route_profile(), self.transport.route_profile())?;
        self.validate_attempt(&facts, &input)?;
        let EksExecutionInput {
            template,
            bearer,
            credential_lifecycle_policy,
            destination_activation_commitment,
        } = input;
        if credential_lifecycle_policy != self.config.credential_lifecycle_policy
            || credential_lifecycle_policy != facts.credential_lifecycle_policy
            || destination_activation_commitment == [0; 32]
            || destination_activation_commitment != facts.destination_activation_commitment
        {
            return Err(ExecutorError::ExecutionProfileMismatch);
        }
        let prepared = prepare_patch(&template, facts.transaction_id, facts.authorization_id)
            .map_err(|error| ExecutorError::Projection(error.to_string()))?;
        validate_prepared_binding(&facts.binding, &template, &prepared)?;
        if credential_digest(bearer.as_bytes()) != facts.binding.token_digest {
            return Err(ExecutorError::InvalidCredential);
        }

        let minimum_safe_horizon_seconds = self
            .minimum_safe_horizon_seconds
            .ok_or(ExecutorError::InvalidConfiguration)?;
        let preflight_at = self.clock.unix_seconds().map_err(ExecutorError::Clock)?;
        validate_io_window(
            &facts,
            preflight_at,
            minimum_safe_horizon_seconds,
            self.config
                .credential_lifecycle_policy
                .clock_uncertainty_seconds(),
        )?;

        let path = deployment_path(self.config.route_profile());
        let preflight = self
            .transport
            .get_deployment(NativeGetRequest {
                api_server_identity: &facts.physical.api_server_identity,
                path: &path,
                bearer: bearer.as_bytes(),
            })
            .map_err(|error| ExecutorError::PreflightTransport(error.to_string()))?;
        validate_response_identity(&preflight, &facts.physical)?;
        if preflight.status != 200 {
            return Err(ExecutorError::PreflightUnexpectedStatus(preflight.status));
        }
        let before = parse_json(&preflight.body)?;
        validate_preconditions(&before, &template)
            .map_err(|error| ExecutorError::Projection(error.to_string()))?;
        let before_bytes = canonical_json_bytes(&before)?;
        if Digest32::sha256(&before_bytes) != template.prior_projection_hash {
            return Err(ExecutorError::PreStateCommitmentMismatch);
        }
        let pre_state_commitment = domain_hash(PRE_STATE_COMMITMENT_DOMAIN, &before_bytes);

        let body = patch_wire_body(&prepared)
            .map_err(|error| ExecutorError::Projection(error.to_string()))?;
        let mut local_fence = LocalFenceGuard::acquire(
            facts.physical.clone(),
            facts.transaction_id,
            facts.acquisition_id,
            facts.acquisition_lease_fence,
        )?;
        local_fence.mark_dispatch_started();
        let mut pre_write_error = None;
        let mut sent_at = None;
        let transport_result = {
            let authorization = NativePreWriteAuthorization::new(|| {
                let observed = match self.clock.unix_seconds() {
                    Ok(observed) => observed,
                    Err(detail) => {
                        pre_write_error = Some(ExecutorError::Clock(detail));
                        return Err(TransportFailure::DefinitelyNotSent(
                            "trusted pre-write clock rejected the PATCH".to_owned(),
                        ));
                    }
                };
                if let Err(error) = validate_io_window(
                    &facts,
                    observed,
                    minimum_safe_horizon_seconds,
                    self.config
                        .credential_lifecycle_policy
                        .clock_uncertainty_seconds(),
                ) {
                    pre_write_error = Some(error);
                    return Err(TransportFailure::DefinitelyNotSent(
                        "trusted pre-write execution window rejected the PATCH".to_owned(),
                    ));
                }
                sent_at = Some(observed);
                Ok(())
            });
            self.transport.patch_deployment(
                NativePatchRequest {
                    api_server_identity: &facts.physical.api_server_identity,
                    path: &path,
                    content_type: PATCH_CONTENT_TYPE,
                    body: &body,
                    bearer: bearer.as_bytes(),
                    claim_fence: facts.claim_fence,
                    acquisition_id: facts.acquisition_id,
                    acquisition_lease_fence: facts.acquisition_lease_fence,
                    transaction_id: facts.transaction_id,
                    provider_request_commitment: facts.binding.final_wire_commitment,
                },
                authorization,
            )
        };
        let response = match transport_result {
            Ok(response) => response,
            Err(TransportFailure::DefinitelyNotSent(detail)) => {
                local_fence.complete_safe();
                if let Some(error) = pre_write_error {
                    return Err(error);
                }
                return Err(ExecutorError::PatchDefinitelyNotSent(detail));
            }
            Err(TransportFailure::OutcomeUnknown(detail)) => {
                local_fence.complete_unknown();
                return Err(ExecutorError::PatchOutcomeUnknown(detail));
            }
        };
        let Some(sent_at) = sent_at else {
            // A successful response without consuming the one-shot boundary
            // violates the trusted transport contract and cannot establish a
            // safe no-effect result.
            local_fence.complete_unknown();
            return Err(ExecutorError::PatchOutcomeUnknown(
                "native transport skipped pre-write authorization".to_owned(),
            ));
        };

        if let Err(error) = validate_response_identity(&response, &facts.physical) {
            local_fence.complete_unknown();
            return Err(error);
        }
        if response.status != 200 {
            local_fence.complete_unknown();
            return Err(ExecutorError::PatchStatusOutcomeUnknown(response.status));
        }
        let persisted = match parse_json(&response.body) {
            Ok(value) => value,
            Err(error) => {
                local_fence.complete_unknown();
                return Err(ExecutorError::EffectUnverifiable(error.to_string()));
            }
        };
        if let Err(error) = validate_authorized_delta(
            &before,
            &persisted,
            &template,
            facts.transaction_id,
            facts.authorization_id,
            prepared.operation_hash,
        ) {
            local_fence.complete_unknown();
            return Err(ExecutorError::EffectUnverifiable(error.to_string()));
        }

        let observed_at = match self.clock.unix_seconds() {
            Ok(value) => value,
            Err(error) => {
                local_fence.complete_unknown();
                return Err(ExecutorError::Clock(error));
            }
        };
        if observed_at <= facts.started_at || observed_at < sent_at {
            local_fence.complete_unknown();
            return Err(ExecutorError::ObservationTimeInvalid {
                observed: observed_at,
                started_at: facts.started_at,
            });
        }
        let persisted_bytes = match canonical_json_bytes(&persisted) {
            Ok(bytes) => bytes,
            Err(error) => {
                local_fence.complete_unknown();
                return Err(error);
            }
        };
        let observed_resource_version =
            required_nonempty_string(&persisted, "/metadata/resourceVersion").inspect_err(
                |_error| {
                    local_fence.complete_unknown();
                },
            )?;
        let response_commitment = response_commitment(&response);
        let post_state_commitment = domain_hash(POST_STATE_COMMITMENT_DOMAIN, &persisted_bytes);
        if response_commitment == [0; 32] || post_state_commitment == [0; 32] {
            local_fence.complete_unknown();
            return Err(ExecutorError::EffectUnverifiable(
                "a derived evidence commitment is zero".to_owned(),
            ));
        }

        let evidence = ExactEffectEvidence {
            transaction_id: facts.transaction_id,
            physical: facts.physical.clone(),
            binding: facts.binding,
            response_commitment,
            post_state_commitment,
            observed_resource_uid: facts.physical.deployment_uid.clone(),
            observed_resource_version,
            observed_at,
            observer: AuthenticatedObserver {
                identity: self.config.observer_identity.clone(),
                authentication_commitment: response.channel_authentication_commitment,
            },
        };
        let observation = EksEffectObservation {
            transaction_id: facts.transaction_id,
            physical: facts.physical,
            local_fence: facts.acquisition_lease_fence,
            acquisition_id: facts.acquisition_id,
            dispatch_deadline: facts.dispatch_deadline,
            sent_at,
            pre_state_commitment,
            emitted_body_commitment: domain_hash(EMITTED_BODY_COMMITMENT_DOMAIN, &body),
            evidence,
        };
        local_fence.complete_safe();
        Ok(observation)
    }

    fn validate_attempt(
        &self,
        facts: &AttemptFacts,
        input: &EksExecutionInput,
    ) -> Result<(), ExecutorError> {
        if facts.transaction_id.is_nil()
            || facts.authorization_id.is_nil()
            || facts.claim_fence == 0
            || facts.acquisition_id.is_nil()
            || facts.acquisition_lease_fence == 0
            || !valid_acquisition_worker(&facts.acquisition_worker_id)
            || facts.acquisition_acquired_at < 0
            || facts.started_at < 0
            || facts.started_at < facts.acquisition_acquired_at
            || facts.dispatch_deadline <= facts.started_at
            || facts.lease_until <= facts.started_at
            || facts.lease_until > facts.dispatch_deadline
            || facts.token_not_before < 0
            || facts.token_expires_at <= facts.token_not_before
            || facts.credential_id.is_empty()
        {
            return Err(ExecutorError::InvalidAttempt(
                "identity, fence, or interval",
            ));
        }
        let route = self.config.route_profile();
        if facts.physical != self.config.physical
            || facts.service_account_uid != route.attempt_service_account_uid()
            || input.template.cluster_identity != route.cluster_identity()
            || input.template.namespace != route.namespace()
            || input.template.deployment != route.deployment_name()
            || input.template.deployment_uid != route.deployment_uid()
        {
            return Err(ExecutorError::DestinationMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct AttemptFacts {
    transaction_id: Uuid,
    physical: PhysicalResourceId,
    binding: EffectBinding,
    started_at: i64,
    dispatch_deadline: i64,
    authorization_id: Uuid,
    claim_fence: u64,
    acquisition_id: Uuid,
    acquisition_lease_fence: u64,
    acquisition_worker_id: String,
    acquisition_acquired_at: i64,
    lease_until: i64,
    token_not_before: i64,
    token_expires_at: i64,
    service_account_uid: String,
    credential_id: String,
    credential_lifecycle_policy: EksCredentialLifecyclePolicy,
    destination_activation_commitment: [u8; 32],
}

impl AttemptFacts {
    fn from_authorized(attempt: &AuthorizedProviderAttempt) -> Self {
        Self {
            transaction_id: attempt.transaction_id(),
            physical: attempt.physical().clone(),
            binding: *attempt.binding(),
            started_at: attempt.started_at(),
            dispatch_deadline: attempt.dispatch_deadline(),
            authorization_id: attempt.claim_token().key().authorization_id,
            claim_fence: attempt.claim_token().fence(),
            acquisition_id: attempt.acquisition().acquisition_id(),
            acquisition_lease_fence: attempt.acquisition().lease_fence(),
            acquisition_worker_id: attempt.acquisition().worker_id().to_owned(),
            acquisition_acquired_at: attempt.acquisition().acquired_at(),
            lease_until: attempt.acquisition().lease_until(),
            token_not_before: attempt.token_not_before(),
            token_expires_at: attempt.token_expires_at(),
            service_account_uid: attempt.service_account_uid().to_owned(),
            credential_id: attempt.credential_id().to_owned(),
            credential_lifecycle_policy: attempt.credential_lifecycle_policy(),
            destination_activation_commitment: attempt.destination_activation_commitment(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct FenceEntry {
    highest: u64,
    in_flight: Option<(Uuid, Uuid, u64)>,
    quarantined: bool,
}

static PROCESS_FENCES: OnceLock<Mutex<BTreeMap<PhysicalResourceId, FenceEntry>>> = OnceLock::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FenceCompletion {
    PreSend,
    Dispatched,
    Safe,
    Unknown,
}

#[derive(Debug)]
struct LocalFenceGuard {
    physical: PhysicalResourceId,
    transaction_id: Uuid,
    acquisition_id: Uuid,
    fence: u64,
    completion: FenceCompletion,
}

impl LocalFenceGuard {
    fn acquire(
        physical: PhysicalResourceId,
        transaction_id: Uuid,
        acquisition_id: Uuid,
        fence: u64,
    ) -> Result<Self, ExecutorError> {
        let registry = PROCESS_FENCES.get_or_init(|| Mutex::new(BTreeMap::new()));
        let mut entries = registry
            .lock()
            .map_err(|_| ExecutorError::FenceRegistryUnavailable)?;
        if let Some(entry) = entries.get_mut(&physical) {
            if entry.quarantined {
                return Err(ExecutorError::LocalResourceQuarantined);
            }
            if entry.in_flight.is_some() {
                return Err(ExecutorError::LocalResourceBusy);
            }
            if fence <= entry.highest {
                return Err(ExecutorError::StaleLocalFence {
                    presented: fence,
                    highest: entry.highest,
                });
            }
            entry.highest = fence;
            entry.in_flight = Some((transaction_id, acquisition_id, fence));
        } else {
            entries.insert(
                physical.clone(),
                FenceEntry {
                    highest: fence,
                    in_flight: Some((transaction_id, acquisition_id, fence)),
                    quarantined: false,
                },
            );
        }
        Ok(Self {
            physical,
            transaction_id,
            acquisition_id,
            fence,
            completion: FenceCompletion::PreSend,
        })
    }

    fn mark_dispatch_started(&mut self) {
        self.completion = FenceCompletion::Dispatched;
    }

    fn complete_safe(&mut self) {
        self.completion = FenceCompletion::Safe;
    }

    fn complete_unknown(&mut self) {
        self.completion = FenceCompletion::Unknown;
    }
}

impl Drop for LocalFenceGuard {
    fn drop(&mut self) {
        let Some(registry) = PROCESS_FENCES.get() else {
            return;
        };
        let Ok(mut entries) = registry.lock() else {
            return;
        };
        let Some(entry) = entries.get_mut(&self.physical) else {
            return;
        };
        if entry.in_flight != Some((self.transaction_id, self.acquisition_id, self.fence)) {
            entry.quarantined = true;
            return;
        }
        if matches!(
            self.completion,
            FenceCompletion::Dispatched | FenceCompletion::Unknown
        ) {
            entry.quarantined = true;
        }
        entry.in_flight = None;
    }
}

fn validate_prepared_binding(
    binding: &EffectBinding,
    template: &DeploymentTemplate,
    prepared: &accordlock_k8s::PreparedPatch,
) -> Result<(), ExecutorError> {
    let template_hash =
        canonical_hash(template).map_err(|error| ExecutorError::Projection(error.to_string()))?;
    if binding.template_hash != *template_hash.as_bytes() {
        return Err(ExecutorError::BindingMismatch("template hash"));
    }
    if binding.operation_hash != *prepared.operation_hash.as_bytes() {
        return Err(ExecutorError::BindingMismatch("operation hash"));
    }
    if binding.execution_command_commitment != *prepared.execution_command_commitment.as_bytes() {
        return Err(ExecutorError::BindingMismatch(
            "native execution command commitment",
        ));
    }
    if binding.final_wire_commitment != *prepared.final_wire_commitment.as_bytes() {
        return Err(ExecutorError::BindingMismatch("provider wire commitment"));
    }
    if binding.effective_rbac_commitment == [0; 32] || binding.token_digest == [0; 32] {
        return Err(ExecutorError::BindingMismatch(
            "credential authorization commitment",
        ));
    }
    Ok(())
}

fn validate_io_window(
    facts: &AttemptFacts,
    observed: i64,
    minimum_safe_horizon_seconds: i64,
    clock_uncertainty_seconds: i64,
) -> Result<(), ExecutorError> {
    if observed < facts.started_at {
        return Err(ExecutorError::NonMonotoneTime {
            observed,
            started_at: facts.started_at,
        });
    }
    if observed >= facts.dispatch_deadline {
        return Err(ExecutorError::DeadlineExpired {
            observed,
            dispatch_deadline: facts.dispatch_deadline,
        });
    }
    if observed >= facts.lease_until {
        return Err(ExecutorError::LeaseExpired {
            observed,
            lease_until: facts.lease_until,
        });
    }
    let earliest = observed
        .checked_sub(clock_uncertainty_seconds)
        .ok_or(ExecutorError::InvalidConfiguration)?;
    if earliest < facts.token_not_before || observed >= facts.token_expires_at {
        return Err(ExecutorError::CredentialExpired {
            observed,
            not_before: facts.token_not_before,
            expires_at: facts.token_expires_at,
        });
    }
    let safe_horizon = observed
        .checked_add(minimum_safe_horizon_seconds)
        .ok_or(ExecutorError::InvalidConfiguration)?;
    if minimum_safe_horizon_seconds <= 0
        || safe_horizon >= facts.token_expires_at
        || safe_horizon >= facts.dispatch_deadline
        || safe_horizon >= facts.lease_until
    {
        return Err(ExecutorError::ExecutionWindowInsufficient {
            observed,
            safe_horizon,
            token_expires_at: facts.token_expires_at,
            dispatch_deadline: facts.dispatch_deadline,
            acquisition_lease_until: facts.lease_until,
        });
    }
    Ok(())
}

fn duration_ceiling_seconds(duration: Duration) -> Option<i64> {
    if duration.is_zero() {
        return None;
    }
    let seconds = i64::try_from(duration.as_secs()).ok()?;
    seconds.checked_add(i64::from(duration.subsec_nanos() != 0))
}

fn validate_response_identity(
    response: &NativeEksResponse,
    physical: &PhysicalResourceId,
) -> Result<(), ExecutorError> {
    if response.api_server_identity != physical.api_server_identity
        || response.channel_authentication_commitment == [0; 32]
    {
        return Err(ExecutorError::ResponseIdentityMismatch);
    }
    Ok(())
}

fn deployment_path(route: &EksRouteProfile) -> String {
    format!(
        "/apis/apps/v1/namespaces/{}/deployments/{}",
        route.namespace(),
        route.deployment_name()
    )
}

fn physical_from_route(route: &EksRouteProfile) -> PhysicalResourceId {
    PhysicalResourceId {
        cluster_trust_domain: route.cluster_trust_domain().to_owned(),
        api_server_identity: route.api_server_identity().to_owned(),
        namespace: route.namespace().to_owned(),
        deployment_uid: route.deployment_uid().to_owned(),
    }
}

fn ensure_route_match(
    expected: &EksRouteProfile,
    presented: &EksRouteProfile,
) -> Result<(), ExecutorError> {
    expected
        .first_mismatch(presented)
        .map_or(Ok(()), |field| Err(ExecutorError::RouteMismatch(field)))
}

fn parse_json(bytes: &[u8]) -> Result<Value, ExecutorError> {
    serde_json::from_slice(bytes).map_err(|error| ExecutorError::InvalidResponse(error.to_string()))
}

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, ExecutorError> {
    // serde_json's workspace profile uses its sorted map representation. This
    // matches the snapshot commitment currently used by the live EKS harness.
    serde_json::to_vec(value).map_err(|error| ExecutorError::InvalidResponse(error.to_string()))
}

fn required_nonempty_string(value: &Value, pointer: &str) -> Result<String, ExecutorError> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|candidate| !candidate.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            ExecutorError::EffectUnverifiable(format!(
                "provider response field {pointer} is absent or empty"
            ))
        })
}

fn credential_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn response_commitment(response: &NativeEksResponse) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RESPONSE_COMMITMENT_DOMAIN);
    hasher.update(response.status.to_be_bytes());
    update_len_prefixed(&mut hasher, response.api_server_identity.as_bytes());
    hasher.update(response.channel_authentication_commitment);
    update_len_prefixed(&mut hasher, &response.body);
    hasher.finalize().into()
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    update_len_prefixed(&mut hasher, bytes);
    hasher.finalize().into()
}

fn update_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_observer_identity(value: &str) -> bool {
    valid_text(value, 512)
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

fn valid_acquisition_worker(value: &str) -> bool {
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::{
        collections::VecDeque,
        net::SocketAddr,
        sync::{
            Arc, Mutex,
            atomic::{AtomicI64, Ordering},
        },
    };

    use accordlock_eks_profile::{CaTrustCommitment, EksRouteProfileInput, PinnedSocketTarget};
    use serde_json::json;

    use super::*;

    const BEARER: &[u8] = b"opaque-one-attempt-kubernetes-token";

    #[derive(Debug)]
    struct SequenceClock {
        values: Mutex<VecDeque<i64>>,
    }

    impl SequenceClock {
        fn new(values: impl IntoIterator<Item = i64>) -> Self {
            Self {
                values: Mutex::new(values.into_iter().collect()),
            }
        }
    }

    impl TrustedClock for SequenceClock {
        fn unix_seconds(&self) -> Result<i64, String> {
            self.values
                .lock()
                .map_err(|_| "test clock poisoned".to_owned())?
                .pop_front()
                .ok_or_else(|| "test clock exhausted".to_owned())
        }
    }

    #[derive(Clone, Debug)]
    struct SharedClock(Arc<AtomicI64>);

    impl SharedClock {
        fn new(now: i64) -> Self {
            Self(Arc::new(AtomicI64::new(now)))
        }
    }

    impl TrustedClock for SharedClock {
        fn unix_seconds(&self) -> Result<i64, String> {
            Ok(self.0.load(Ordering::SeqCst))
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum PatchMode {
        Success,
        DefinitelyNotSent,
        Unknown,
        ServerErrorAfterSend,
        WrongIdentity,
        MalformedSuccess,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct CapturedPatch {
        method: String,
        path: String,
        content_type: String,
        body: Vec<u8>,
        bearer: Vec<u8>,
        fence: u64,
        transaction_id: Uuid,
        provider_request_commitment: [u8; 32],
    }

    #[derive(Debug)]
    struct FakeTransportState {
        before: Vec<u8>,
        after: Vec<u8>,
        api_server_identity: String,
        mode: PatchMode,
        get_count: usize,
        patches: Vec<CapturedPatch>,
    }

    #[derive(Clone, Debug)]
    struct FakeTransport {
        route_profile: EksRouteProfile,
        state: Arc<Mutex<FakeTransportState>>,
        pre_write_clock_advance: Option<(Arc<AtomicI64>, i64)>,
    }

    impl FakeTransport {
        fn new(
            route_profile: EksRouteProfile,
            before: Vec<u8>,
            after: Vec<u8>,
            api_server_identity: String,
            mode: PatchMode,
        ) -> Self {
            Self {
                route_profile,
                state: Arc::new(Mutex::new(FakeTransportState {
                    before,
                    after,
                    api_server_identity,
                    mode,
                    get_count: 0,
                    patches: Vec::new(),
                })),
                pre_write_clock_advance: None,
            }
        }

        fn with_pre_write_clock_advance(mut self, clock: &SharedClock, now: i64) -> Self {
            self.pre_write_clock_advance = Some((Arc::clone(&clock.0), now));
            self
        }

        fn patches(&self) -> Vec<CapturedPatch> {
            self.state.lock().unwrap().patches.clone()
        }

        fn get_count(&self) -> usize {
            self.state.lock().unwrap().get_count
        }
    }

    impl NativeEksTransport for FakeTransport {
        fn route_profile(&self) -> &EksRouteProfile {
            &self.route_profile
        }

        fn operation_timeout_upper_bound(&self) -> std::time::Duration {
            std::time::Duration::from_secs(5)
        }

        fn get_deployment(
            &self,
            request: NativeGetRequest<'_>,
        ) -> Result<NativeEksResponse, TransportFailure> {
            assert_eq!(request.method(), "GET");
            assert_eq!(request.bearer(), BEARER);
            let mut state = self.state.lock().unwrap();
            assert_eq!(request.api_server_identity(), state.api_server_identity);
            state.get_count += 1;
            Ok(NativeEksResponse::new(
                200,
                state.api_server_identity.clone(),
                [0x61; 32],
                state.before.clone(),
            ))
        }

        fn patch_deployment(
            &self,
            request: NativePatchRequest<'_>,
            immediately_before_first_write: NativePreWriteAuthorization<'_>,
        ) -> Result<NativeEksResponse, TransportFailure> {
            // Models time advancing while TCP/TLS is in progress. The
            // transport invokes the one-shot authorization only after that
            // phase and before recording the first application write.
            if let Some((clock, now)) = &self.pre_write_clock_advance {
                clock.store(*now, Ordering::SeqCst);
            }
            immediately_before_first_write.authorize()?;
            let mut state = self.state.lock().unwrap();
            state.patches.push(CapturedPatch {
                method: request.method().to_owned(),
                path: request.path().to_owned(),
                content_type: request.content_type().to_owned(),
                body: request.body().to_vec(),
                bearer: request.bearer().to_vec(),
                fence: request.local_fence(),
                transaction_id: request.transaction_id(),
                provider_request_commitment: request.provider_request_commitment(),
            });
            match state.mode {
                PatchMode::Success => Ok(NativeEksResponse::new(
                    200,
                    state.api_server_identity.clone(),
                    [0x62; 32],
                    state.after.clone(),
                )),
                PatchMode::DefinitelyNotSent => Err(TransportFailure::DefinitelyNotSent(
                    "connect failed before write".to_owned(),
                )),
                PatchMode::Unknown => Err(TransportFailure::OutcomeUnknown(
                    "connection closed after request write".to_owned(),
                )),
                PatchMode::ServerErrorAfterSend => Ok(NativeEksResponse::new(
                    503,
                    state.api_server_identity.clone(),
                    [0x62; 32],
                    b"{\"kind\":\"Status\"}".to_vec(),
                )),
                PatchMode::WrongIdentity => Ok(NativeEksResponse::new(
                    200,
                    "sha256:another-api-server".to_owned(),
                    [0x62; 32],
                    state.after.clone(),
                )),
                PatchMode::MalformedSuccess => Ok(NativeEksResponse::new(
                    200,
                    state.api_server_identity.clone(),
                    [0x62; 32],
                    b"not-json".to_vec(),
                )),
            }
        }
    }

    #[derive(Debug)]
    struct Fixture {
        config: ExecutorConfig,
        facts: AttemptFacts,
        template: DeploymentTemplate,
        before: Value,
        after: Value,
    }

    impl Fixture {
        fn new(seed: u128, fence: u64) -> Self {
            let uid = Uuid::from_u128(seed | (9_u128 << 120)).to_string();
            let physical = PhysicalResourceId {
                cluster_trust_domain: "spiffe://example.test/eks/cluster-a".to_owned(),
                api_server_identity: "urn:accordlock:api:cluster-a".to_owned(),
                namespace: "payments".to_owned(),
                deployment_uid: uid.clone(),
            };
            Self::with_physical(seed, fence, &physical)
        }

        #[allow(clippy::too_many_lines)]
        fn with_physical(seed: u128, fence: u64, physical: &PhysicalResourceId) -> Self {
            let transaction_id = Uuid::from_u128(seed | (1_u128 << 120));
            let authorization_id = Uuid::from_u128(seed | (2_u128 << 120));
            let prior_digest = Digest32::from_bytes([0x11; 32]);
            let next_digest = Digest32::from_bytes([0x22; 32]);
            let before = json!({
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {
                    "name": "api",
                    "namespace": physical.namespace,
                    "uid": physical.deployment_uid,
                    "resourceVersion": "10",
                    "generation": 7,
                    "annotations": {
                        "accordlock.io/transaction-id": "none",
                        "accordlock.io/authorization-id": "none",
                        "accordlock.io/operation-hash": "none"
                    },
                    "labels": {"app": "api"}
                },
                "spec": {
                    "replicas": 1,
                    "selector": {"matchLabels": {"app": "api"}},
                    "template": {
                        "metadata": {"labels": {"app": "api"}},
                        "spec": {"containers": [{
                            "name": "api",
                            "image": format!("registry.example.test/team/api@{prior_digest}")
                        }]}
                    }
                }
            });
            let before_bytes = serde_json::to_vec(&before).unwrap();
            let template = DeploymentTemplate {
                operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
                environment: "production".to_owned(),
                audience: "accordlock-executor://payments".to_owned(),
                repository: "https://github.com/example/payments".to_owned(),
                commit_sha: "0123456789abcdef0123456789abcdef01234567".to_owned(),
                image_repository: "registry.example.test/team/api".to_owned(),
                image_digest: next_digest,
                cluster_identity: "eks://cluster-a".to_owned(),
                namespace: "payments".to_owned(),
                deployment: "api".to_owned(),
                deployment_uid: physical.deployment_uid.clone(),
                container: "api".to_owned(),
                container_index: 0,
                prior_image_digest: prior_digest,
                resource_version: "10".to_owned(),
                prior_projection_hash: Digest32::sha256(&before_bytes),
                prior_transaction_annotation: Some("none".to_owned()),
                prior_authorization_annotation: Some("none".to_owned()),
                prior_operation_hash_annotation: Some("none".to_owned()),
            };
            let prepared = prepare_patch(&template, transaction_id, authorization_id).unwrap();
            let mut after = before.clone();
            *after.pointer_mut("/metadata/resourceVersion").unwrap() = json!("11");
            *after.pointer_mut("/metadata/generation").unwrap() = json!(8);
            *after
                .pointer_mut("/spec/template/spec/containers/0/image")
                .unwrap() = json!(format!(
                "registry.example.test/team/api@{}",
                template.image_digest
            ));
            *after
                .pointer_mut("/metadata/annotations/accordlock.io~1transaction-id")
                .unwrap() = json!(transaction_id.to_string());
            *after
                .pointer_mut("/metadata/annotations/accordlock.io~1authorization-id")
                .unwrap() = json!(authorization_id.to_string());
            *after
                .pointer_mut("/metadata/annotations/accordlock.io~1operation-hash")
                .unwrap() = json!(prepared.operation_hash.to_string());
            let facts = AttemptFacts {
                transaction_id,
                physical: physical.clone(),
                binding: EffectBinding {
                    template_hash: *canonical_hash(&template).unwrap().as_bytes(),
                    operation_hash: *prepared.operation_hash.as_bytes(),
                    execution_command_commitment: *prepared.execution_command_commitment.as_bytes(),
                    final_wire_commitment: *prepared.final_wire_commitment.as_bytes(),
                    effective_rbac_commitment: [0x44; 32],
                    token_digest: credential_digest(BEARER),
                },
                started_at: 100,
                dispatch_deadline: 180,
                authorization_id,
                claim_fence: 1,
                acquisition_id: Uuid::from_u128(seed | (3_u128 << 120)),
                acquisition_lease_fence: fence,
                acquisition_worker_id: format!("worker-{seed:x}"),
                acquisition_acquired_at: 99,
                lease_until: 170,
                token_not_before: 100,
                token_expires_at: 170,
                service_account_uid: "33333333-3333-4333-8333-333333333333".to_owned(),
                credential_id: "AUTHORIZATION_ID=44444444-4444-4444-8444-444444444444".to_owned(),
                credential_lifecycle_policy: EksCredentialLifecyclePolicy::new(60, 600, 1, 60)
                    .unwrap(),
                destination_activation_commitment: [0x55; 32],
            };
            let config = ExecutorConfig::new(
                route_for_physical(physical),
                "kubernetes-api-server/cluster-a".to_owned(),
                EksCredentialLifecyclePolicy::new(60, 600, 1, 60).unwrap(),
            )
            .unwrap();
            Self {
                config,
                facts,
                template,
                before,
                after,
            }
        }

        fn input(&self) -> EksExecutionInput {
            EksExecutionInput::new(
                self.template.clone(),
                ExclusiveBearer::new(BEARER.to_vec()).unwrap(),
                self.facts.credential_lifecycle_policy,
                self.facts.destination_activation_commitment,
            )
        }

        fn transport(&self, mode: PatchMode) -> FakeTransport {
            FakeTransport::new(
                self.config.route_profile.clone(),
                serde_json::to_vec(&self.before).unwrap(),
                serde_json::to_vec(&self.after).unwrap(),
                self.config.physical.api_server_identity.clone(),
                mode,
            )
        }
    }

    fn route_for_physical(physical: &PhysicalResourceId) -> EksRouteProfile {
        route_variant(physical, RouteMutation::None)
    }

    #[derive(Clone, Copy)]
    enum RouteMutation {
        None,
        Cluster,
        Dns,
        Socket,
        Ca,
        Namespace,
        DeploymentUid,
        ServiceAccountUid,
        Audience,
    }

    fn route_variant(physical: &PhysicalResourceId, mutation: RouteMutation) -> EksRouteProfile {
        let certificates = vec![match mutation {
            RouteMutation::Ca => b"executor-substituted-ca".to_vec(),
            _ => b"executor-test-ca".to_vec(),
        }];
        let cluster_identity = match mutation {
            RouteMutation::Cluster => "eks://cluster-b",
            _ => "eks://cluster-a",
        };
        let dns_server_name = match mutation {
            RouteMutation::Dns => "api.cluster-b.eks.amazonaws.com",
            _ => "api.cluster-a.eks.amazonaws.com",
        };
        let socket_octet = match mutation {
            RouteMutation::Socket => 12,
            _ => 10,
        };
        let namespace = match mutation {
            RouteMutation::Namespace => "settlements",
            _ => &physical.namespace,
        };
        let deployment_uid = match mutation {
            RouteMutation::DeploymentUid => "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            _ => &physical.deployment_uid,
        };
        let service_account_uid = match mutation {
            RouteMutation::ServiceAccountUid => "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            _ => "33333333-3333-4333-8333-333333333333",
        };
        let audience = match mutation {
            RouteMutation::Audience => "urn:accordlock:audience:alternate",
            _ => "https://kubernetes.default.svc",
        };
        EksRouteProfile::new(EksRouteProfileInput {
            cluster_trust_domain: &physical.cluster_trust_domain,
            cluster_identity,
            api_server_identity: &physical.api_server_identity,
            dns_server_name,
            port: 443,
            socket_target: PinnedSocketTarget::new(SocketAddr::from((
                [192, 0, 2, socket_octet],
                443,
            )))
            .unwrap(),
            ca_trust_commitment: CaTrustCommitment::from_der_certificates(&certificates).unwrap(),
            namespace,
            deployment_name: "api",
            deployment_uid,
            attempt_service_account_name: "accordlock-attempt",
            attempt_service_account_uid: service_account_uid,
            token_audience: audience,
        })
        .unwrap()
    }

    #[test]
    fn exact_attempt_emits_only_committed_native_patch_and_typed_evidence() {
        let fixture = Fixture::new(0x101, 11);
        let transport = fixture.transport(PatchMode::Success);
        let inspector = transport.clone();
        let expected = prepare_patch(
            &fixture.template,
            fixture.facts.transaction_id,
            fixture.facts.authorization_id,
        )
        .unwrap();
        let expected_body = patch_wire_body(&expected).unwrap();
        let executor = ExclusiveEksExecutor::new(
            fixture.config.clone(),
            transport,
            SequenceClock::new([101, 101, 102]),
        );
        let observation = executor
            .execute_facts(fixture.facts.clone(), fixture.input())
            .unwrap();

        let patches = inspector.patches();
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].method, "PATCH");
        assert_eq!(patches[0].content_type, PATCH_CONTENT_TYPE);
        assert_eq!(patches[0].body, expected_body);
        assert_eq!(patches[0].bearer, BEARER);
        assert_eq!(patches[0].fence, 11);
        assert_eq!(patches[0].transaction_id, fixture.facts.transaction_id);
        assert_eq!(
            patches[0].provider_request_commitment,
            fixture.facts.binding.final_wire_commitment
        );
        assert_eq!(observation.local_fence(), 11);
        assert_eq!(observation.sent_at(), 101);
        assert_eq!(observation.evidence().observed_at, 102);
        assert_eq!(
            observation.evidence().binding.final_wire_commitment,
            fixture.facts.binding.final_wire_commitment
        );
        assert_ne!(observation.evidence().commitment(), [0; 32]);
    }

    #[test]
    fn every_cross_route_substitution_is_rejected_before_provider_io() {
        let fixture = Fixture::new(0x111, 111);
        let cases = [
            (RouteMutation::Cluster, RouteField::ClusterIdentity),
            (RouteMutation::Dns, RouteField::DnsServerName),
            (RouteMutation::Socket, RouteField::SocketTarget),
            (RouteMutation::Ca, RouteField::CaTrustCommitment),
            (RouteMutation::Namespace, RouteField::Namespace),
            (RouteMutation::DeploymentUid, RouteField::DeploymentUid),
            (
                RouteMutation::ServiceAccountUid,
                RouteField::AttemptServiceAccountUid,
            ),
            (RouteMutation::Audience, RouteField::TokenAudience),
        ];

        for (mutation, expected_field) in cases {
            let mut transport = fixture.transport(PatchMode::Success);
            transport.route_profile = route_variant(&fixture.config.physical, mutation);
            let inspector = transport.clone();
            let executor = ExclusiveEksExecutor::new(
                fixture.config.clone(),
                transport,
                SequenceClock::new([101, 102]),
            );
            assert_eq!(
                executor.execute_facts(fixture.facts.clone(), fixture.input()),
                Err(ExecutorError::RouteMismatch(expected_field))
            );
            assert_eq!(inspector.get_count(), 0);
            assert!(inspector.patches().is_empty());
        }
    }

    #[test]
    fn substituted_template_is_rejected_before_any_provider_io() {
        let fixture = Fixture::new(0x102, 12);
        let transport = fixture.transport(PatchMode::Success);
        let inspector = transport.clone();
        let mut input = fixture.input();
        input.template.commit_sha = "ffffffffffffffffffffffffffffffffffffffff".to_owned();
        let executor = ExclusiveEksExecutor::new(
            fixture.config.clone(),
            transport,
            SequenceClock::new([101, 102]),
        );

        assert!(matches!(
            executor.execute_facts(fixture.facts, input),
            Err(ExecutorError::BindingMismatch("template hash"))
        ));
        assert_eq!(inspector.get_count(), 0);
        assert!(inspector.patches().is_empty());
    }

    #[test]
    fn substituted_bearer_is_rejected_before_any_provider_io() {
        let fixture = Fixture::new(0x103, 13);
        let transport = fixture.transport(PatchMode::Success);
        let inspector = transport.clone();
        let input = EksExecutionInput::new(
            fixture.template.clone(),
            ExclusiveBearer::new(b"another-token".to_vec()).unwrap(),
            fixture.facts.credential_lifecycle_policy,
            fixture.facts.destination_activation_commitment,
        );
        let executor = ExclusiveEksExecutor::new(
            fixture.config.clone(),
            transport,
            SequenceClock::new([101, 102]),
        );

        assert_eq!(
            executor.execute_facts(fixture.facts, input),
            Err(ExecutorError::InvalidCredential)
        );
        assert_eq!(inspector.get_count(), 0);
        assert!(inspector.patches().is_empty());
    }

    #[test]
    fn deadline_is_checked_after_preflight_and_before_patch() {
        let fixture = Fixture::new(0x104, 14);
        let transport = fixture.transport(PatchMode::Success);
        let inspector = transport.clone();
        let executor =
            ExclusiveEksExecutor::new(fixture.config.clone(), transport, SequenceClock::new([180]));

        assert_eq!(
            executor.execute_facts(fixture.facts.clone(), fixture.input()),
            Err(ExecutorError::DeadlineExpired {
                observed: 180,
                dispatch_deadline: 180,
            })
        );
        assert_eq!(inspector.get_count(), 0);
        assert!(inspector.patches().is_empty());
    }

    #[test]
    fn token_must_outlive_patch_timeout_and_clock_uncertainty() {
        let mut fixture = Fixture::new(0x114, 114);
        // The fake transport promises at most five seconds and the executor
        // profile adds one second of clock uncertainty. Equality with the
        // exclusive expiry boundary is therefore insufficient.
        fixture.facts.token_expires_at = 107;
        let transport = fixture.transport(PatchMode::Success);
        let inspector = transport.clone();
        let executor =
            ExclusiveEksExecutor::new(fixture.config.clone(), transport, SequenceClock::new([101]));

        assert_eq!(
            executor.execute_facts(fixture.facts.clone(), fixture.input()),
            Err(ExecutorError::ExecutionWindowInsufficient {
                observed: 101,
                safe_horizon: 107,
                token_expires_at: 107,
                dispatch_deadline: 180,
                acquisition_lease_until: 170,
            })
        );
        assert_eq!(inspector.get_count(), 0);
        assert!(inspector.patches().is_empty());
    }

    #[test]
    fn post_tls_pre_write_resample_rejects_clock_jump_without_patch_bytes() {
        let fixture = Fixture::new(0x124, 124);
        let clock = SharedClock::new(101);
        let transport = fixture
            .transport(PatchMode::Success)
            .with_pre_write_clock_advance(&clock, 165);
        let inspector = transport.clone();
        let executor = ExclusiveEksExecutor::new(fixture.config.clone(), transport, clock);

        assert_eq!(
            executor.execute_facts(fixture.facts.clone(), fixture.input()),
            Err(ExecutorError::ExecutionWindowInsufficient {
                observed: 165,
                safe_horizon: 171,
                token_expires_at: 170,
                dispatch_deadline: 180,
                acquisition_lease_until: 170,
            })
        );
        assert_eq!(inspector.get_count(), 1);
        assert!(inspector.patches().is_empty());
    }

    #[test]
    fn deadline_and_acquisition_lease_must_outlive_the_full_transport_horizon() {
        let mut deadline = Fixture::new(0x115, 115);
        // Timeout is five seconds and rooted clock uncertainty is one second.
        // At t=101, a deadline of 107 is equality with the conservative
        // horizon and therefore cannot authorize even the preflight GET.
        deadline.facts.dispatch_deadline = 107;
        deadline.facts.lease_until = 107;
        let deadline_transport = deadline.transport(PatchMode::Success);
        let deadline_inspector = deadline_transport.clone();
        let deadline_executor = ExclusiveEksExecutor::new(
            deadline.config.clone(),
            deadline_transport,
            SequenceClock::new([101]),
        );
        assert_eq!(
            deadline_executor.execute_facts(deadline.facts.clone(), deadline.input()),
            Err(ExecutorError::ExecutionWindowInsufficient {
                observed: 101,
                safe_horizon: 107,
                token_expires_at: 170,
                dispatch_deadline: 107,
                acquisition_lease_until: 107,
            })
        );
        assert_eq!(deadline_inspector.get_count(), 0);

        let mut lease = Fixture::new(0x116, 116);
        lease.facts.lease_until = 107;
        let lease_transport = lease.transport(PatchMode::Success);
        let lease_inspector = lease_transport.clone();
        let lease_executor = ExclusiveEksExecutor::new(
            lease.config.clone(),
            lease_transport,
            SequenceClock::new([101]),
        );
        assert_eq!(
            lease_executor.execute_facts(lease.facts.clone(), lease.input()),
            Err(ExecutorError::ExecutionWindowInsufficient {
                observed: 101,
                safe_horizon: 107,
                token_expires_at: 170,
                dispatch_deadline: 180,
                acquisition_lease_until: 107,
            })
        );
        assert_eq!(lease_inspector.get_count(), 0);
    }

    #[test]
    fn clock_uncertainty_cannot_move_not_before_earlier() {
        let mut fixture = Fixture::new(0x117, 117);
        fixture.facts.token_not_before = 101;
        let transport = fixture.transport(PatchMode::Success);
        let inspector = transport.clone();
        let executor =
            ExclusiveEksExecutor::new(fixture.config.clone(), transport, SequenceClock::new([101]));
        assert_eq!(
            executor.execute_facts(fixture.facts.clone(), fixture.input()),
            Err(ExecutorError::CredentialExpired {
                observed: 101,
                not_before: 101,
                expires_at: 170,
            })
        );
        assert_eq!(inspector.get_count(), 0);
    }

    #[test]
    fn rooted_execution_profile_mismatch_is_rejected_before_io() {
        let fixture = Fixture::new(0x118, 118);
        let transport = fixture.transport(PatchMode::Success);
        let inspector = transport.clone();
        let input = EksExecutionInput::new(
            fixture.template.clone(),
            ExclusiveBearer::new(BEARER.to_vec()).unwrap(),
            EksCredentialLifecyclePolicy::new(61, 600, 1, 60).unwrap(),
            fixture.facts.destination_activation_commitment,
        );
        let executor =
            ExclusiveEksExecutor::new(fixture.config.clone(), transport, SequenceClock::new([101]));
        assert_eq!(
            executor.execute_facts(fixture.facts, input),
            Err(ExecutorError::ExecutionProfileMismatch)
        );
        assert_eq!(inspector.get_count(), 0);
    }

    #[test]
    fn live_takeover_acquisition_ignores_expired_stable_claim_lease_facts() {
        let first = Fixture::new(0x119, 119);
        // A takeover deliberately reuses the stable claim token. Its original
        // lease may already be expired; only the committed acquisition-v2
        // lease/fence below may authorize the new provider attempt.
        let original_stable_claim_lease_until = 100;
        let shared_physical = first.config.physical.clone();
        let first_executor = ExclusiveEksExecutor::new(
            first.config.clone(),
            first.transport(PatchMode::Success),
            SequenceClock::new([101, 101, 102]),
        );
        first_executor
            .execute_facts(first.facts.clone(), first.input())
            .unwrap();

        let mut takeover = Fixture::with_physical(0x11a, 120, &shared_physical);
        takeover.facts.claim_fence = first.facts.claim_fence;
        assert!(original_stable_claim_lease_until < takeover.facts.started_at + 1);
        assert!(takeover.facts.lease_until > takeover.facts.started_at + 1);
        let transport = takeover.transport(PatchMode::Success);
        let inspector = transport.clone();
        let executor = ExclusiveEksExecutor::new(
            takeover.config.clone(),
            transport,
            SequenceClock::new([101, 101, 102]),
        );
        let observation = executor
            .execute_facts(takeover.facts.clone(), takeover.input())
            .unwrap();
        assert_eq!(observation.local_fence(), 120);
        assert_eq!(observation.acquisition_id(), takeover.facts.acquisition_id);
        assert_eq!(inspector.patches().len(), 1);
    }

    #[test]
    fn stale_process_fence_is_rejected_before_patch() {
        let first = Fixture::new(0x105, 30);
        let shared_physical = first.config.physical.clone();
        let first_transport = first.transport(PatchMode::Success);
        let first_executor = ExclusiveEksExecutor::new(
            first.config.clone(),
            first_transport,
            SequenceClock::new([101, 101, 102]),
        );
        first_executor
            .execute_facts(first.facts.clone(), first.input())
            .unwrap();

        let stale = Fixture::with_physical(0x106, 29, &shared_physical);
        let stale_transport = stale.transport(PatchMode::Success);
        let inspector = stale_transport.clone();
        let stale_executor = ExclusiveEksExecutor::new(
            stale.config.clone(),
            stale_transport,
            SequenceClock::new([101, 101]),
        );
        assert_eq!(
            stale_executor.execute_facts(stale.facts.clone(), stale.input()),
            Err(ExecutorError::StaleLocalFence {
                presented: 29,
                highest: 30,
            })
        );
        assert_eq!(inspector.get_count(), 1);
        assert!(inspector.patches().is_empty());
    }

    #[test]
    fn ambiguous_send_quarantines_resource_even_for_higher_fence() {
        let first = Fixture::new(0x107, 40);
        let shared_physical = first.config.physical.clone();
        let first_transport = first.transport(PatchMode::Unknown);
        let first_executor = ExclusiveEksExecutor::new(
            first.config.clone(),
            first_transport,
            SequenceClock::new([101, 101]),
        );
        assert!(matches!(
            first_executor.execute_facts(first.facts.clone(), first.input()),
            Err(ExecutorError::PatchOutcomeUnknown(_))
        ));

        let next = Fixture::with_physical(0x108, 41, &shared_physical);
        let next_transport = next.transport(PatchMode::Success);
        let inspector = next_transport.clone();
        let next_executor = ExclusiveEksExecutor::new(
            next.config.clone(),
            next_transport,
            SequenceClock::new([101, 101]),
        );
        assert_eq!(
            next_executor.execute_facts(next.facts.clone(), next.input()),
            Err(ExecutorError::LocalResourceQuarantined)
        );
        assert!(inspector.patches().is_empty());
    }

    #[test]
    fn definitely_not_sent_is_not_retried() {
        let fixture = Fixture::new(0x109, 50);
        let transport = fixture.transport(PatchMode::DefinitelyNotSent);
        let inspector = transport.clone();
        let executor = ExclusiveEksExecutor::new(
            fixture.config.clone(),
            transport,
            SequenceClock::new([101, 101]),
        );
        assert!(matches!(
            executor.execute_facts(fixture.facts.clone(), fixture.input()),
            Err(ExecutorError::PatchDefinitelyNotSent(_))
        ));
        assert_eq!(inspector.patches().len(), 1);
    }

    #[test]
    fn non_success_status_after_send_quarantines_instead_of_proving_no_effect() {
        let first = Fixture::new(0x10e, 55);
        let shared_physical = first.config.physical.clone();
        let transport = first.transport(PatchMode::ServerErrorAfterSend);
        let executor = ExclusiveEksExecutor::new(
            first.config.clone(),
            transport,
            SequenceClock::new([101, 101]),
        );
        assert_eq!(
            executor.execute_facts(first.facts.clone(), first.input()),
            Err(ExecutorError::PatchStatusOutcomeUnknown(503))
        );

        let next = Fixture::with_physical(0x10f, 56, &shared_physical);
        let transport = next.transport(PatchMode::Success);
        let inspector = transport.clone();
        let executor = ExclusiveEksExecutor::new(
            next.config.clone(),
            transport,
            SequenceClock::new([101, 101]),
        );
        assert_eq!(
            executor.execute_facts(next.facts.clone(), next.input()),
            Err(ExecutorError::LocalResourceQuarantined)
        );
        assert!(inspector.patches().is_empty());
    }

    #[test]
    fn wrong_authenticated_destination_after_send_is_fail_closed() {
        let fixture = Fixture::new(0x10a, 60);
        let transport = fixture.transport(PatchMode::WrongIdentity);
        let executor = ExclusiveEksExecutor::new(
            fixture.config.clone(),
            transport,
            SequenceClock::new([101, 101]),
        );
        assert_eq!(
            executor.execute_facts(fixture.facts.clone(), fixture.input()),
            Err(ExecutorError::ResponseIdentityMismatch)
        );
    }

    #[test]
    fn malformed_success_is_not_upgraded_to_effect_evidence() {
        let fixture = Fixture::new(0x10b, 70);
        let transport = fixture.transport(PatchMode::MalformedSuccess);
        let executor = ExclusiveEksExecutor::new(
            fixture.config.clone(),
            transport,
            SequenceClock::new([101, 101]),
        );
        assert!(matches!(
            executor.execute_facts(fixture.facts.clone(), fixture.input()),
            Err(ExecutorError::EffectUnverifiable(_))
        ));
    }

    #[test]
    fn unauthorized_success_delta_is_not_upgraded_to_effect_evidence() {
        let mut fixture = Fixture::new(0x10c, 80);
        *fixture.after.pointer_mut("/spec/replicas").unwrap() = json!(2);
        let transport = fixture.transport(PatchMode::Success);
        let executor = ExclusiveEksExecutor::new(
            fixture.config.clone(),
            transport,
            SequenceClock::new([101, 101]),
        );
        assert!(matches!(
            executor.execute_facts(fixture.facts.clone(), fixture.input()),
            Err(ExecutorError::EffectUnverifiable(_))
        ));
    }

    #[test]
    fn changed_preflight_snapshot_is_rejected_before_patch() {
        let mut fixture = Fixture::new(0x10d, 90);
        *fixture.before.pointer_mut("/metadata/labels/app").unwrap() = json!("changed");
        let transport = fixture.transport(PatchMode::Success);
        let inspector = transport.clone();
        let executor = ExclusiveEksExecutor::new(
            fixture.config.clone(),
            transport,
            SequenceClock::new([101, 101]),
        );
        assert_eq!(
            executor.execute_facts(fixture.facts.clone(), fixture.input()),
            Err(ExecutorError::PreStateCommitmentMismatch)
        );
        assert!(inspector.patches().is_empty());
    }
}
