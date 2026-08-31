//! Trusted-side ports and orchestration.
//!
//! These interfaces are configuration-time dependencies of the service, not
//! per-request inputs. Implementations may own state handles, KMS/HSM clients,
//! signer identities, and dispatcher clients. None of those objects cross the
//! application boundary.

use core::fmt;

pub use accordlock_ingress::AuthenticatedIngressRequest;

use crate::{
    ActionState, PublicReasonCode, StatusEnvelope, StatusLookup, StatusView, SubmissionEnvelope,
    SubmissionReceipt,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TrustedInstant(i64);

impl TrustedInstant {
    #[must_use]
    pub const fn from_unix_seconds(value: i64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn unix_seconds(self) -> i64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustedFailureCode {
    AuthenticationFailed,
    ReplayRejected,
    IngressUnavailable,
    AuthorityUnavailable,
    GrantUnavailable,
    ClockUnavailable,
    SigningOrCommitFailed,
    DispatchFailed,
    StatusUnavailable,
    InvariantViolation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedFailure {
    code: TrustedFailureCode,
}

impl TrustedFailure {
    #[must_use]
    pub const fn new(code: TrustedFailureCode) -> Self {
        Self { code }
    }

    #[must_use]
    pub const fn code(self) -> TrustedFailureCode {
        self.code
    }
}

impl fmt::Display for TrustedFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "trusted workflow failure: {:?}", self.code)
    }
}

impl std::error::Error for TrustedFailure {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceError {
    /// Authentication, proof binding, or replay checks rejected the envelope.
    RequestRejected,
    /// A trusted dependency failed. Internal causes are deliberately not
    /// exposed at the application boundary.
    ControlUnavailable,
    StatusNotFound,
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestRejected => formatter.write_str("request rejected"),
            Self::ControlUnavailable => formatter.write_str("trusted control unavailable"),
            Self::StatusNotFound => formatter.write_str("status not found"),
        }
    }
}

impl std::error::Error for ServiceError {}

impl From<TrustedFailure> for ServiceError {
    fn from(value: TrustedFailure) -> Self {
        match value.code() {
            TrustedFailureCode::AuthenticationFailed | TrustedFailureCode::ReplayRejected => {
                Self::RequestRejected
            }
            TrustedFailureCode::IngressUnavailable
            | TrustedFailureCode::AuthorityUnavailable
            | TrustedFailureCode::GrantUnavailable
            | TrustedFailureCode::ClockUnavailable
            | TrustedFailureCode::SigningOrCommitFailed
            | TrustedFailureCode::DispatchFailed
            | TrustedFailureCode::StatusUnavailable
            | TrustedFailureCode::InvariantViolation => Self::ControlUnavailable,
        }
    }
}

/// TCB boundary for signed action ingress and signed status authentication.
///
/// A submission result is the exact non-constructible capability emitted by
/// `accordlock-ingress`. It is not reduced to caller strings or rebuilt as a
/// parallel application request. The status scope is adapter-defined so a
/// production adapter can keep its constructor and security material private.
pub trait TrustedIngress: Send + Sync {
    type AuthenticatedStatusScope: Send;

    /// Strictly authenticates exact signed proposal-envelope bytes.
    ///
    /// # Errors
    ///
    /// Returns [`TrustedFailure`] for malformed, invalid, expired, replayed,
    /// misbound, or unverifiable input, and for unavailable trusted state.
    fn authenticate_submission(
        &self,
        signed_envelope: &[u8],
    ) -> Result<AuthenticatedIngressRequest, TrustedFailure>;

    /// Authenticates status access and binds it to the exact lookup.
    ///
    /// The returned scope must be unforgeable outside the installed adapter's
    /// TCB and must carry every dimension used by the status store (at least
    /// tenant and environment, plus actor when policy requires it).
    ///
    /// # Errors
    ///
    /// Returns [`TrustedFailure`] for failed signature, lookup binding, replay,
    /// freshness, or scope validation, or when trusted state is unavailable.
    fn authenticate_status(
        &self,
        lookup: &StatusLookup,
        signed_authentication: &[u8],
    ) -> Result<Self::AuthenticatedStatusScope, TrustedFailure>;
}

pub trait TrustedClock: Send + Sync {
    /// Reads time from the configured trusted clock.
    ///
    /// # Errors
    ///
    /// Returns [`TrustedFailure`] if trusted time is unavailable or violates
    /// the implementation's rollback/high-water invariant.
    fn now(&self) -> Result<TrustedInstant, TrustedFailure>;
}

pub enum EnforcementDecision<A, S> {
    Authorized {
        authorization: A,
        status_scope: S,
    },
    Denied {
        reason: PublicReasonCode,
        status_scope: S,
    },
}

impl<A, S> fmt::Debug for EnforcementDecision<A, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorized { .. } => formatter.write_str("Authorized(<opaque>)"),
            Self::Denied { reason, .. } => formatter.debug_tuple("Denied").field(reason).finish(),
        }
    }
}

/// Loads current authority, policy, grant, evidence, and other trusted facts
/// for the exact authenticated proposal.
pub trait TrustedAuthorizer: Send + Sync {
    type Authorization: Send;
    /// Private status-recording scope retained after the ingress capability is
    /// consumed by the kernel. It is not an execution capability and must bind
    /// the exact authenticated request and tenant/environment dimensions.
    type AuthenticatedSubmissionScope: Send;

    /// Consumes the opaque authenticated-ingress capability while evaluating
    /// current trusted state. A real adapter can therefore move the value into
    /// `KernelContext::from_authenticated_ingress`; it never has to clone or
    /// reconstruct the capability. Grant selection is server-side; no grant
    /// body or lookup selector exists in the public submission surface.
    ///
    /// # Errors
    ///
    /// Returns [`TrustedFailure`] when required authority, grant, policy, or
    /// evidence state cannot be loaded or evaluated safely.
    fn authorize(
        &self,
        request: AuthenticatedIngressRequest,
        evaluated_at: TrustedInstant,
    ) -> Result<
        EnforcementDecision<Self::Authorization, Self::AuthenticatedSubmissionScope>,
        TrustedFailure,
    >;
}

/// Owns signing and the durable authorization commit. The signing key is an adapter
/// dependency and cannot be selected by a submission.
pub trait TrustedCommitter<A>: Send + Sync {
    type CommittedAuthorization: Send;

    /// Signs and durably commits an authorization as one fail-closed step.
    ///
    /// # Errors
    ///
    /// Returns [`TrustedFailure`] when signing or durable commit does not
    /// complete according to the implementation's atomicity contract.
    fn sign_and_commit(
        &self,
        authorization: A,
        committed_at: TrustedInstant,
    ) -> Result<Self::CommittedAuthorization, TrustedFailure>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchDisposition {
    Pending,
    AttemptInFlight,
    Succeeded,
    Failed,
    ManualResolutionRequired,
}

impl DispatchDisposition {
    const fn action_state(self) -> ActionState {
        match self {
            Self::Pending => ActionState::DispatchPending,
            Self::AttemptInFlight => ActionState::AttemptInFlight,
            Self::Succeeded => ActionState::Succeeded,
            Self::Failed => ActionState::Failed,
            Self::ManualResolutionRequired => ActionState::ManualResolutionRequired,
        }
    }

    const fn reason(self) -> Option<PublicReasonCode> {
        match self {
            Self::Failed => Some(PublicReasonCode::InternalControlFailure),
            Self::ManualResolutionRequired => Some(PublicReasonCode::DispatchOutcomeUnknown),
            Self::Pending | Self::AttemptInFlight | Self::Succeeded => None,
        }
    }
}

/// Consumes a committed authorization. Implementations must not make the committed
/// authorization recoverable through their public status projection.
pub trait TrustedDispatcher<P>: Send + Sync {
    /// Consumes a committed authorization and attempts or schedules its effect.
    ///
    /// # Errors
    ///
    /// Returns [`TrustedFailure`] only when the implementation can safely
    /// classify the call as a control failure. An outcome-unknown attempt must
    /// return [`DispatchDisposition::ManualResolutionRequired`] instead.
    fn dispatch(
        &self,
        authorization: P,
        dispatched_at: TrustedInstant,
    ) -> Result<DispatchDisposition, TrustedFailure>;
}

/// Stores status projections separately from all execution authority.
pub trait TrustedStatusStore: Send + Sync {
    /// Exact private scope returned by the authorizer after it consumes the
    /// ingress capability. It must carry the request binding needed to record
    /// status without recreating that capability.
    type AuthenticatedSubmissionScope: Send;

    /// Exact authenticated status-scope type created by the paired ingress
    /// adapter. Production implementations should keep it non-constructible to
    /// untrusted application code.
    type AuthenticatedStatusScope: Send;

    /// Persists a non-executable status projection in the complete scope
    /// carried by the authenticated ingress capability.
    ///
    /// # Errors
    ///
    /// Returns [`TrustedFailure`] when the projection cannot be stored or its
    /// scope/invariants cannot be enforced.
    fn record(
        &self,
        scope: &Self::AuthenticatedSubmissionScope,
        state: ActionState,
        reason: Option<PublicReasonCode>,
        observed_at: TrustedInstant,
    ) -> Result<StatusView, TrustedFailure>;

    /// Looks up a projection using both the exact authenticated scope and the
    /// non-authorizing public receipt key.
    ///
    /// # Errors
    ///
    /// Returns [`TrustedFailure`] when the status store is unavailable or its
    /// scope/invariants cannot be enforced.
    fn lookup(
        &self,
        scope: &Self::AuthenticatedStatusScope,
        lookup: &StatusLookup,
    ) -> Result<Option<StatusView>, TrustedFailure>;
}

pub trait TrustedWorkflow<Q>: Send + Sync {
    /// Consumes the opaque ingress capability in the trusted workflow.
    ///
    /// # Errors
    ///
    /// Returns [`TrustedFailure`] when a trusted dependency fails closed.
    fn submit_trusted(
        &self,
        request: AuthenticatedIngressRequest,
    ) -> Result<StatusView, TrustedFailure>;

    /// Consumes an adapter-authenticated status scope and performs one exact
    /// scoped lookup.
    ///
    /// # Errors
    ///
    /// Returns [`TrustedFailure`] when the trusted status dependency fails.
    fn status_trusted(
        &self,
        scope: Q,
        lookup: &StatusLookup,
    ) -> Result<Option<StatusView>, TrustedFailure>;
}

/// Testable trusted-side pipeline. Components are fixed at construction and
/// cannot be supplied or replaced on an individual request.
pub struct TrustedPipeline<C, A, K, D, S> {
    clock: C,
    authorizer: A,
    committer: K,
    dispatcher: D,
    status: S,
}

impl<C, A, K, D, S> fmt::Debug for TrustedPipeline<C, A, K, D, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TrustedPipeline(<trusted components redacted>)")
    }
}

impl<C, A, K, D, S> TrustedPipeline<C, A, K, D, S> {
    #[must_use]
    pub const fn new(clock: C, authorizer: A, committer: K, dispatcher: D, status: S) -> Self {
        Self {
            clock,
            authorizer,
            committer,
            dispatcher,
            status,
        }
    }
}

impl<C, A, K, D, S> TrustedWorkflow<S::AuthenticatedStatusScope> for TrustedPipeline<C, A, K, D, S>
where
    C: TrustedClock,
    A: TrustedAuthorizer,
    K: TrustedCommitter<A::Authorization>,
    D: TrustedDispatcher<K::CommittedAuthorization>,
    S: TrustedStatusStore<AuthenticatedSubmissionScope = A::AuthenticatedSubmissionScope>,
{
    fn submit_trusted(
        &self,
        request: AuthenticatedIngressRequest,
    ) -> Result<StatusView, TrustedFailure> {
        let evaluated_at = self.clock.now()?;
        let decision = self.authorizer.authorize(request, evaluated_at)?;
        let (authorization, status_scope) = match decision {
            EnforcementDecision::Authorized {
                authorization,
                status_scope,
            } => (authorization, status_scope),
            EnforcementDecision::Denied {
                reason,
                status_scope,
            } => {
                return self.status.record(
                    &status_scope,
                    ActionState::Denied,
                    Some(reason),
                    evaluated_at,
                );
            }
        };

        let committed_at = self.clock.now()?;
        if committed_at < evaluated_at {
            return Err(TrustedFailure::new(TrustedFailureCode::InvariantViolation));
        }
        let committed = self
            .committer
            .sign_and_commit(authorization, committed_at)?;
        let dispatched_at = self.clock.now()?;
        if dispatched_at < committed_at {
            return Err(TrustedFailure::new(TrustedFailureCode::InvariantViolation));
        }
        let disposition = self.dispatcher.dispatch(committed, dispatched_at)?;
        self.status.record(
            &status_scope,
            disposition.action_state(),
            disposition.reason(),
            dispatched_at,
        )
    }

    fn status_trusted(
        &self,
        scope: S::AuthenticatedStatusScope,
        lookup: &StatusLookup,
    ) -> Result<Option<StatusView>, TrustedFailure> {
        self.status.lookup(&scope, lookup)
    }
}

/// Public application facade. It owns one TCB ingress verifier and one trusted
/// workflow for its entire lifetime. A caller supplies signed bytes, never an
/// `AuthenticatedIngressRequest`.
pub struct AccordLockService<I, W> {
    ingress: I,
    workflow: W,
}

impl<I, W> fmt::Debug for AccordLockService<I, W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccordLockService(<trusted components redacted>)")
    }
}

impl<I, W> AccordLockService<I, W> {
    #[must_use]
    pub const fn new(ingress: I, workflow: W) -> Self {
        Self { ingress, workflow }
    }

    /// Authenticates exact signed bytes and moves the resulting opaque ingress
    /// capability into the fixed trusted workflow.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError`] on authentication, replay, trusted-workflow,
    /// or response-binding failure.
    pub fn submit(&self, envelope: SubmissionEnvelope) -> Result<SubmissionReceipt, ServiceError>
    where
        I: TrustedIngress,
        W: TrustedWorkflow<I::AuthenticatedStatusScope>,
    {
        let signed_envelope = envelope.into_bytes();
        let request = self.ingress.authenticate_submission(&signed_envelope)?;
        let expected_request_id = request.proposal().request_id.to_string();
        let status = self.workflow.submit_trusted(request)?;
        if status.request_id().as_str() != expected_request_id {
            return Err(ServiceError::ControlUnavailable);
        }
        Ok(SubmissionReceipt::from_status(&status))
    }

    /// Authenticates one exact status lookup and returns an inert projection.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError`] on authentication, trusted-store, binding, or
    /// not-found failure. Cross-scope lookups are indistinguishable from an
    /// absent record at this boundary.
    pub fn status(&self, envelope: StatusEnvelope) -> Result<StatusView, ServiceError>
    where
        I: TrustedIngress,
        W: TrustedWorkflow<I::AuthenticatedStatusScope>,
    {
        let (lookup, signed_authentication) = envelope.into_parts();
        let scope = self
            .ingress
            .authenticate_status(&lookup, &signed_authentication)?;
        let status = self
            .workflow
            .status_trusted(scope, &lookup)?
            .ok_or(ServiceError::StatusNotFound)?;
        if status.receipt_id() != lookup.receipt_id() {
            return Err(ServiceError::ControlUnavailable);
        }
        Ok(status)
    }
}
