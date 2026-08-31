//! Conservative single-step composition of the encrypted outbox and outbound
//! provider transport.

use std::fmt;
use std::time::Duration;

use accordlock_protocol::Digest32;
use thiserror::Error;
use uuid::Uuid;

use crate::transport::validate_and_encode_delivery;
use crate::{
    AckOutcome, ApprovalChannel, BoundedHttpsTransport, ChannelDelivery, ClaimedDelivery,
    DeadLetterOutcome, DeliveryAttempt, DeliveryCredential, DeliveryDisposition,
    DeliveryEndpointConfig, DeliveryLimits, DeliveryOutbox, DeliveryPayloadKind, DeliveryReason,
    DeliveryTransportError, OutboxError, OutboxTerminalReason, RetryOutcome,
    dispatch_channel_delivery, parse_unambiguous_json,
};

const MAX_WORKER_LEASE_SECONDS: i64 = 60 * 60;
const MAX_WORKER_RETRY_SECONDS: u32 = 60 * 60;
const DEFAULT_WORKER_LEASE_SECONDS: i64 = 60;
const DEFAULT_RESOLUTION_RETRY_SECONDS: u32 = 30;

/// Non-secret routing metadata plus an opaque secure-store locator.
pub struct DeliveryResolutionContext<'a> {
    job_id: Uuid,
    channel: ApprovalChannel,
    credential_reference: &'a [u8],
}

impl DeliveryResolutionContext<'_> {
    #[must_use]
    pub const fn job_id(&self) -> Uuid {
        self.job_id
    }

    #[must_use]
    pub const fn channel(&self) -> ApprovalChannel {
        self.channel
    }

    /// Exposes the opaque locator only to the trusted resolver.
    #[must_use]
    pub const fn credential_reference(&self) -> &[u8] {
        self.credential_reference
    }
}

impl fmt::Debug for DeliveryResolutionContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliveryResolutionContext")
            .field("job_id", &self.job_id)
            .field("channel", &self.channel)
            .field("credential_reference", &"[REDACTED]")
            .finish()
    }
}

/// Secret-free reason why endpoint or credential resolution failed.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum DeliveryResolutionError {
    #[error("delivery material is temporarily unavailable")]
    Retryable,
    #[error("delivery material is not configured for this job")]
    Permanent,
}

/// Endpoint and ephemeral credential returned by a trusted host resolver.
pub struct ResolvedDeliveryMaterial {
    endpoint: DeliveryEndpointConfig,
    credential: DeliveryCredential,
}

impl ResolvedDeliveryMaterial {
    #[must_use]
    pub const fn new(endpoint: DeliveryEndpointConfig, credential: DeliveryCredential) -> Self {
        Self {
            endpoint,
            credential,
        }
    }
}

impl fmt::Debug for ResolvedDeliveryMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedDeliveryMaterial")
            .field("endpoint", &self.endpoint)
            .field("credential", &self.credential)
            .finish()
    }
}

/// Trusted boundary that resolves a fixed endpoint and an ephemeral
/// credential from an opaque secure-store reference.
///
/// Implementations must not return credentials to model-visible code, persist
/// them in the outbox, or include references or credentials in logs.
pub trait DeliveryMaterialResolver {
    /// Resolves material for one leased job.
    ///
    /// # Errors
    ///
    /// Returns only a retryable or permanent, secret-free classification.
    fn resolve(
        &mut self,
        context: &DeliveryResolutionContext<'_>,
    ) -> Result<ResolvedDeliveryMaterial, DeliveryResolutionError>;
}

/// Secret-free trusted-time failure.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum TrustedTimeError {
    #[error("trusted time is unavailable")]
    Unavailable,
}

/// Host-supplied monotonic wall-clock boundary used for every state change.
pub trait TrustedTimeSource {
    /// Returns a non-negative Unix timestamp that never moves backwards.
    ///
    /// # Errors
    ///
    /// Returns [`TrustedTimeError::Unavailable`] instead of substituting local
    /// untrusted time.
    fn now(&mut self) -> Result<i64, TrustedTimeError>;
}

/// Bounds for one claim, resolution, request, and settlement step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliveryWorkerConfig {
    lease_seconds: i64,
    resolution_retry_seconds: u32,
    delivery_limits: DeliveryLimits,
}

impl DeliveryWorkerConfig {
    /// Creates a fail-closed worker profile.
    ///
    /// The lease must be longer than the outbound request timeout. This does
    /// not make a provider request atomic with `SQLite`; an expired in-flight
    /// lease is always dead-lettered for manual reconciliation.
    ///
    /// # Errors
    ///
    /// Rejects invalid lease or retry bounds and leases no longer than the
    /// configured request timeout.
    pub fn new(
        lease_seconds: i64,
        resolution_retry_seconds: u32,
        delivery_limits: DeliveryLimits,
    ) -> Result<Self, DeliveryWorkerError> {
        let lease_duration = u64::try_from(lease_seconds)
            .ok()
            .map(Duration::from_secs)
            .ok_or(DeliveryWorkerError::InvalidConfiguration)?;
        if !(1..=MAX_WORKER_LEASE_SECONDS).contains(&lease_seconds)
            || !(1..=MAX_WORKER_RETRY_SECONDS).contains(&resolution_retry_seconds)
            || lease_duration <= delivery_limits.request_timeout()
        {
            return Err(DeliveryWorkerError::InvalidConfiguration);
        }
        Ok(Self {
            lease_seconds,
            resolution_retry_seconds,
            delivery_limits,
        })
    }

    #[must_use]
    pub const fn lease_seconds(self) -> i64 {
        self.lease_seconds
    }

    #[must_use]
    pub const fn resolution_retry_seconds(self) -> u32 {
        self.resolution_retry_seconds
    }

    #[must_use]
    pub const fn delivery_limits(self) -> DeliveryLimits {
        self.delivery_limits
    }
}

impl Default for DeliveryWorkerConfig {
    fn default() -> Self {
        Self {
            lease_seconds: DEFAULT_WORKER_LEASE_SECONDS,
            resolution_retry_seconds: DEFAULT_RESOLUTION_RETRY_SECONDS,
            delivery_limits: DeliveryLimits::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryWorkerRetryReason {
    MaterialUnavailable,
    RateLimited,
    TransportNotSent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryWorkerDeadLetterReason {
    InvalidQueuedDelivery,
    MaterialRejected,
    RequestRejected,
    ProviderRejected,
    AmbiguousDelivery,
    RetryBudgetExhausted,
}

/// Durable result of processing at most one queued delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryWorkerStep {
    Idle,
    Delivered {
        job_id: Uuid,
        attempt: DeliveryAttempt,
    },
    RetryScheduled {
        job_id: Uuid,
        available_at: i64,
        reason: DeliveryWorkerRetryReason,
        attempt: Option<DeliveryAttempt>,
    },
    DeadLettered {
        job_id: Uuid,
        reason: DeliveryWorkerDeadLetterReason,
        attempt: Option<DeliveryAttempt>,
    },
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum DeliveryWorkerError {
    #[error("delivery worker configuration is outside accepted bounds")]
    InvalidConfiguration,
    #[error("trusted time is unavailable or invalid")]
    TrustedTimeUnavailable,
    #[error("delivery outbox transition failed: {0}")]
    Outbox(#[from] OutboxError),
}

/// Claims and settles at most one encrypted delivery job.
///
/// This function dispatches exactly once. Only a proven not-sent transport
/// failure or an explicit provider rate limit is scheduled for retry.
/// Permanent, malformed, post-send, timeout, and otherwise ambiguous outcomes
/// are dead-lettered and require manual reconciliation.
///
/// # Errors
///
/// Returns an error when trusted time or an authenticated outbox transition is
/// unavailable. A leased job left by such an error becomes dead-letter after
/// lease expiry and is never automatically resent.
pub fn process_one_delivery(
    outbox: &mut DeliveryOutbox,
    config: DeliveryWorkerConfig,
    clock: &mut dyn TrustedTimeSource,
    resolver: &mut dyn DeliveryMaterialResolver,
    transport: &mut dyn BoundedHttpsTransport,
) -> Result<DeliveryWorkerStep, DeliveryWorkerError> {
    let claim_now = trusted_now(clock)?;
    let Some(claimed) = outbox.claim(claim_now, config.lease_seconds)? else {
        return Ok(DeliveryWorkerStep::Idle);
    };

    process_claimed_delivery(outbox, config, clock, resolver, transport, &claimed)
}

/// Claims and settles only the delivery job identified by `job_id`.
///
/// This is the strict wake-up path for a caller that authenticated and bound a
/// notification job earlier. It never falls through to another ready job. A
/// future or terminal exact job returns [`DeliveryWorkerStep::Idle`], while an
/// expired exact lease is dead-lettered by the outbox and also returns `Idle`.
/// Dispatch and settlement behavior is otherwise identical to
/// [`process_one_delivery`].
///
/// # Errors
///
/// Returns an error when the identifier, trusted time, or an authenticated
/// outbox transition is invalid or unavailable. A missing exact job returns
/// [`OutboxError::JobNotFound`] through [`DeliveryWorkerError::Outbox`].
pub fn process_exact_delivery(
    job_id: Uuid,
    outbox: &mut DeliveryOutbox,
    config: DeliveryWorkerConfig,
    clock: &mut dyn TrustedTimeSource,
    resolver: &mut dyn DeliveryMaterialResolver,
    transport: &mut dyn BoundedHttpsTransport,
) -> Result<DeliveryWorkerStep, DeliveryWorkerError> {
    let claim_now = trusted_now(clock)?;
    let Some(claimed) = outbox.claim_exact(job_id, claim_now, config.lease_seconds)? else {
        return Ok(DeliveryWorkerStep::Idle);
    };

    process_claimed_delivery(outbox, config, clock, resolver, transport, &claimed)
}

fn process_claimed_delivery(
    outbox: &mut DeliveryOutbox,
    config: DeliveryWorkerConfig,
    clock: &mut dyn TrustedTimeSource,
    resolver: &mut dyn DeliveryMaterialResolver,
    transport: &mut dyn BoundedHttpsTransport,
    claimed: &ClaimedDelivery,
) -> Result<DeliveryWorkerStep, DeliveryWorkerError> {
    let Ok(delivery) = reconstruct_delivery(claimed) else {
        return settle_dead_letter(
            outbox,
            claimed,
            clock,
            DeliveryWorkerDeadLetterReason::InvalidQueuedDelivery,
            None,
        );
    };
    let context = DeliveryResolutionContext {
        job_id: claimed.job_id(),
        channel: claimed.channel(),
        credential_reference: claimed.credential_reference(),
    };
    let material = match resolver.resolve(&context) {
        Ok(material) => material,
        Err(DeliveryResolutionError::Retryable) => {
            return settle_retry(
                outbox,
                claimed,
                clock,
                config.resolution_retry_seconds,
                DeliveryWorkerRetryReason::MaterialUnavailable,
                None,
            );
        }
        Err(DeliveryResolutionError::Permanent) => {
            return settle_dead_letter(
                outbox,
                claimed,
                clock,
                DeliveryWorkerDeadLetterReason::MaterialRejected,
                None,
            );
        }
    };

    dispatch_and_settle(
        outbox, claimed, clock, config, &delivery, &material, transport,
    )
}

fn dispatch_and_settle(
    outbox: &mut DeliveryOutbox,
    claimed: &ClaimedDelivery,
    clock: &mut dyn TrustedTimeSource,
    config: DeliveryWorkerConfig,
    delivery: &ChannelDelivery,
    material: &ResolvedDeliveryMaterial,
    transport: &mut dyn BoundedHttpsTransport,
) -> Result<DeliveryWorkerStep, DeliveryWorkerError> {
    let attempt = match dispatch_channel_delivery(
        delivery,
        &material.endpoint,
        &material.credential,
        config.delivery_limits,
        transport,
    ) {
        Ok(attempt) => attempt,
        Err(
            DeliveryTransportError::InvalidInput
            | DeliveryTransportError::ChannelMismatch
            | DeliveryTransportError::PayloadMismatch
            | DeliveryTransportError::CredentialExposure
            | DeliveryTransportError::Encoding,
        ) => {
            return settle_dead_letter(
                outbox,
                claimed,
                clock,
                DeliveryWorkerDeadLetterReason::RequestRejected,
                None,
            );
        }
    };

    match attempt.disposition() {
        DeliveryDisposition::Accepted => settle_accepted(outbox, claimed, clock, attempt),
        DeliveryDisposition::Retryable => match attempt.reason() {
            DeliveryReason::RateLimited => settle_retry(
                outbox,
                claimed,
                clock,
                attempt
                    .retry_after_seconds()
                    .unwrap_or(config.resolution_retry_seconds),
                DeliveryWorkerRetryReason::RateLimited,
                Some(attempt),
            ),
            DeliveryReason::TransportNotSent => settle_retry(
                outbox,
                claimed,
                clock,
                attempt
                    .retry_after_seconds()
                    .unwrap_or(config.resolution_retry_seconds),
                DeliveryWorkerRetryReason::TransportNotSent,
                Some(attempt),
            ),
            DeliveryReason::ProviderAccepted
            | DeliveryReason::ProviderRejected
            | DeliveryReason::ProviderUnavailable
            | DeliveryReason::MalformedProviderResponse
            | DeliveryReason::ResponseTooLarge
            | DeliveryReason::TransportOutcomeUnknown => settle_dead_letter(
                outbox,
                claimed,
                clock,
                DeliveryWorkerDeadLetterReason::AmbiguousDelivery,
                Some(attempt),
            ),
        },
        DeliveryDisposition::PermanentFailure => settle_dead_letter(
            outbox,
            claimed,
            clock,
            DeliveryWorkerDeadLetterReason::ProviderRejected,
            Some(attempt),
        ),
        DeliveryDisposition::Ambiguous => settle_dead_letter(
            outbox,
            claimed,
            clock,
            DeliveryWorkerDeadLetterReason::AmbiguousDelivery,
            Some(attempt),
        ),
    }
}

fn reconstruct_delivery(claimed: &ClaimedDelivery) -> Result<ChannelDelivery, ()> {
    let destination = std::str::from_utf8(claimed.destination()).map_err(|_| ())?;
    let body = parse_unambiguous_json(claimed.payload()).map_err(|_| ())?;
    let canonical = serde_json::to_vec(&body).map_err(|_| ())?;
    if canonical != claimed.payload() {
        return Err(());
    }
    let delivery = ChannelDelivery {
        channel: claimed.channel(),
        // The durable worker is intentionally notification-only until a
        // callback gateway can preserve and revalidate an interactive
        // challenge binding across the outbox boundary. Never infer authority
        // from provider-controlled JSON.
        payload_kind: DeliveryPayloadKind::ReviewNotification,
        destination: destination.to_owned(),
        media_type: "application/json".to_owned(),
        body,
        body_hash: Digest32::sha256(&canonical),
    };
    validate_and_encode_delivery(&delivery).map_err(|_| ())?;
    Ok(delivery)
}

fn settle_accepted(
    outbox: &mut DeliveryOutbox,
    claimed: &ClaimedDelivery,
    clock: &mut dyn TrustedTimeSource,
    attempt: DeliveryAttempt,
) -> Result<DeliveryWorkerStep, DeliveryWorkerError> {
    let settle_now = trusted_now(clock)?;
    match outbox.ack(claimed.job_id(), claimed.lease_token(), settle_now)? {
        AckOutcome::Delivered | AckOutcome::AlreadyDelivered => Ok(DeliveryWorkerStep::Delivered {
            job_id: claimed.job_id(),
            attempt,
        }),
    }
}

fn settle_retry(
    outbox: &mut DeliveryOutbox,
    claimed: &ClaimedDelivery,
    clock: &mut dyn TrustedTimeSource,
    delay_seconds: u32,
    reason: DeliveryWorkerRetryReason,
    attempt: Option<DeliveryAttempt>,
) -> Result<DeliveryWorkerStep, DeliveryWorkerError> {
    let settle_now = trusted_now(clock)?;
    let delay_seconds = delay_seconds.clamp(1, MAX_WORKER_RETRY_SECONDS);
    match outbox.retry(
        claimed.job_id(),
        claimed.lease_token(),
        settle_now,
        i64::from(delay_seconds),
        attempt.map(attempt_summary_digest),
    )? {
        RetryOutcome::Scheduled { available_at } => Ok(DeliveryWorkerStep::RetryScheduled {
            job_id: claimed.job_id(),
            available_at,
            reason,
            attempt,
        }),
        RetryOutcome::DeadLetter => Ok(DeliveryWorkerStep::DeadLettered {
            job_id: claimed.job_id(),
            reason: DeliveryWorkerDeadLetterReason::RetryBudgetExhausted,
            attempt,
        }),
    }
}

fn settle_dead_letter(
    outbox: &mut DeliveryOutbox,
    claimed: &ClaimedDelivery,
    clock: &mut dyn TrustedTimeSource,
    reason: DeliveryWorkerDeadLetterReason,
    attempt: Option<DeliveryAttempt>,
) -> Result<DeliveryWorkerStep, DeliveryWorkerError> {
    let settle_now = trusted_now(clock)?;
    let terminal_reason = match reason {
        DeliveryWorkerDeadLetterReason::InvalidQueuedDelivery => {
            OutboxTerminalReason::InvalidQueuedDelivery
        }
        DeliveryWorkerDeadLetterReason::MaterialRejected => OutboxTerminalReason::MaterialRejected,
        DeliveryWorkerDeadLetterReason::RequestRejected => OutboxTerminalReason::RequestRejected,
        DeliveryWorkerDeadLetterReason::ProviderRejected => OutboxTerminalReason::ProviderRejected,
        DeliveryWorkerDeadLetterReason::AmbiguousDelivery => {
            OutboxTerminalReason::AmbiguousDelivery
        }
        DeliveryWorkerDeadLetterReason::RetryBudgetExhausted => {
            OutboxTerminalReason::RetryBudgetExhausted
        }
    };
    match outbox.dead_letter(
        claimed.job_id(),
        claimed.lease_token(),
        settle_now,
        terminal_reason,
        attempt.map(attempt_summary_digest),
    )? {
        DeadLetterOutcome::DeadLettered | DeadLetterOutcome::AlreadyDeadLettered => {
            Ok(DeliveryWorkerStep::DeadLettered {
                job_id: claimed.job_id(),
                reason,
                attempt,
            })
        }
    }
}

fn trusted_now(clock: &mut dyn TrustedTimeSource) -> Result<i64, DeliveryWorkerError> {
    clock
        .now()
        .map_err(|_| DeliveryWorkerError::TrustedTimeUnavailable)
        .and_then(|value| {
            if value < 0 {
                Err(DeliveryWorkerError::TrustedTimeUnavailable)
            } else {
                Ok(value)
            }
        })
}

fn attempt_summary_digest(attempt: DeliveryAttempt) -> Digest32 {
    let mut bytes = Vec::with_capacity(80);
    bytes.extend_from_slice(b"accordlock:v1:delivery-attempt-summary");
    bytes.push(match attempt.channel() {
        ApprovalChannel::Slack => 0,
        ApprovalChannel::MicrosoftTeams => 1,
        ApprovalChannel::Telegram => 2,
        ApprovalChannel::WhatsApp => 3,
    });
    bytes.push(match attempt.disposition() {
        DeliveryDisposition::Accepted => 0,
        DeliveryDisposition::Retryable => 1,
        DeliveryDisposition::PermanentFailure => 2,
        DeliveryDisposition::Ambiguous => 3,
    });
    bytes.push(match attempt.reason() {
        DeliveryReason::ProviderAccepted => 0,
        DeliveryReason::RateLimited => 1,
        DeliveryReason::ProviderRejected => 2,
        DeliveryReason::ProviderUnavailable => 3,
        DeliveryReason::MalformedProviderResponse => 4,
        DeliveryReason::ResponseTooLarge => 5,
        DeliveryReason::TransportNotSent => 6,
        DeliveryReason::TransportOutcomeUnknown => 7,
    });
    append_optional_u16(&mut bytes, attempt.status_code());
    append_optional_u32(&mut bytes, attempt.retry_after_seconds());
    match attempt.response_body_hash() {
        Some(hash) => {
            bytes.push(1);
            bytes.extend_from_slice(hash.as_bytes());
        }
        None => bytes.push(0),
    }
    bytes.extend_from_slice(&(attempt.response_body_bytes() as u64).to_be_bytes());
    Digest32::sha256(&bytes)
}

fn append_optional_u16(bytes: &mut Vec<u8>, value: Option<u16>) {
    match value {
        Some(value) => {
            bytes.push(1);
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        None => bytes.push(0),
    }
}

fn append_optional_u32(bytes: &mut Vec<u8>, value: Option<u32>) {
    match value {
        Some(value) => {
            bytes.push(1);
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        None => bytes.push(0),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::error::Error;

    use serde_json::json;

    use super::*;
    use crate::{
        EnqueueRequest, HttpsRequestProgress, HttpsTransportFailure, HttpsTransportFailureKind,
        OutboundHttpsResponse, OutboxEncryptionKey, OutboxState, PreparedHttpsRequest,
        ReviewNotificationPrompt, build_review_notification_delivery,
    };

    const DESTINATION: &[u8] = b"C12345678";
    const CREDENTIAL_REFERENCE: &[u8] = b"windows-credential:slack-primary";
    const SLACK_SECRET: &str = "fixture-slack-credential-0000";

    struct ScriptedClock {
        values: VecDeque<i64>,
    }

    impl ScriptedClock {
        fn new(values: &[i64]) -> Self {
            Self {
                values: values.iter().copied().collect(),
            }
        }
    }

    impl TrustedTimeSource for ScriptedClock {
        fn now(&mut self) -> Result<i64, TrustedTimeError> {
            self.values.pop_front().ok_or(TrustedTimeError::Unavailable)
        }
    }

    #[derive(Clone, Copy)]
    enum ResolutionMode {
        Success,
        Retryable,
        Permanent,
    }

    struct SlackResolver {
        mode: ResolutionMode,
        calls: usize,
    }

    impl SlackResolver {
        const fn new(mode: ResolutionMode) -> Self {
            Self { mode, calls: 0 }
        }
    }

    impl DeliveryMaterialResolver for SlackResolver {
        fn resolve(
            &mut self,
            context: &DeliveryResolutionContext<'_>,
        ) -> Result<ResolvedDeliveryMaterial, DeliveryResolutionError> {
            self.calls += 1;
            assert_eq!(context.channel(), ApprovalChannel::Slack);
            assert_eq!(context.credential_reference(), CREDENTIAL_REFERENCE);
            match self.mode {
                ResolutionMode::Success => Ok(ResolvedDeliveryMaterial::new(
                    DeliveryEndpointConfig::slack(),
                    DeliveryCredential::slack(SLACK_SECRET.to_owned())
                        .map_err(|_| DeliveryResolutionError::Permanent)?,
                )),
                ResolutionMode::Retryable => Err(DeliveryResolutionError::Retryable),
                ResolutionMode::Permanent => Err(DeliveryResolutionError::Permanent),
            }
        }
    }

    #[derive(Clone, Copy)]
    enum TransportMode {
        Success,
        RateLimited,
        Rejected,
        NotSent,
        Ambiguous,
    }

    struct ScriptedTransport {
        mode: TransportMode,
        calls: usize,
    }

    impl ScriptedTransport {
        const fn new(mode: TransportMode) -> Self {
            Self { mode, calls: 0 }
        }

        fn response(
            status: u16,
            retry_after: Option<&str>,
            body: &[u8],
        ) -> Result<OutboundHttpsResponse, HttpsTransportFailure> {
            OutboundHttpsResponse::new(status, retry_after.map(str::to_owned), body.to_vec())
                .map_err(|_| {
                    HttpsTransportFailure::new(
                        HttpsTransportFailureKind::Protocol,
                        HttpsRequestProgress::NotSent,
                    )
                })
        }
    }

    impl BoundedHttpsTransport for ScriptedTransport {
        fn send(
            &mut self,
            request: &PreparedHttpsRequest,
        ) -> Result<OutboundHttpsResponse, HttpsTransportFailure> {
            self.calls += 1;
            assert_eq!(request.channel(), ApprovalChannel::Slack);
            match self.mode {
                TransportMode::Success => {
                    Self::response(200, None, br#"{"ok":true,"ts":"171234.5678"}"#)
                }
                TransportMode::RateLimited => {
                    Self::response(429, Some("7"), br#"{"ok":false,"error":"ratelimited"}"#)
                }
                TransportMode::Rejected => {
                    Self::response(403, None, br#"{"ok":false,"error":"not_authed"}"#)
                }
                TransportMode::NotSent => Err(HttpsTransportFailure::new(
                    HttpsTransportFailureKind::Connect,
                    HttpsRequestProgress::NotSent,
                )),
                TransportMode::Ambiguous => Err(HttpsTransportFailure::new(
                    HttpsTransportFailureKind::Timeout,
                    HttpsRequestProgress::MayHaveBeenSent,
                )),
            }
        }
    }

    fn open_outbox(path: &std::path::Path) -> Result<DeliveryOutbox, OutboxError> {
        DeliveryOutbox::open(path, OutboxEncryptionKey::from_bytes([91; 32]))
    }

    fn enqueue_slack(
        outbox: &mut DeliveryOutbox,
        idempotency_key: &str,
        max_attempts: u8,
    ) -> Result<Uuid, Box<dyn Error>> {
        let delivery = build_review_notification_delivery(
            ApprovalChannel::Slack,
            "C12345678".to_owned(),
            ReviewNotificationPrompt::new(),
        )?;
        let payload = serde_json::to_vec(delivery.body())?;
        Ok(outbox
            .enqueue(&EnqueueRequest {
                channel: ApprovalChannel::Slack,
                destination: DESTINATION,
                payload: &payload,
                credential_reference: CREDENTIAL_REFERENCE,
                idempotency_key,
                max_attempts,
                available_at: 100,
                trusted_now: 90,
            })?
            .job_id())
    }

    #[test]
    fn accepted_delivery_is_acknowledged_once() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let mut outbox = open_outbox(&root.path().join("accepted.sqlite3"))?;
        let job_id = enqueue_slack(&mut outbox, "accepted", 3)?;
        let mut clock = ScriptedClock::new(&[100, 101]);
        let mut resolver = SlackResolver::new(ResolutionMode::Success);
        let mut transport = ScriptedTransport::new(TransportMode::Success);

        let step = process_one_delivery(
            &mut outbox,
            DeliveryWorkerConfig::default(),
            &mut clock,
            &mut resolver,
            &mut transport,
        )?;
        assert!(matches!(
            step,
            DeliveryWorkerStep::Delivered { job_id: id, .. } if id == job_id
        ));
        assert_eq!(transport.calls, 1);
        assert_eq!(resolver.calls, 1);
        assert_eq!(
            outbox.status(job_id)?.ok_or("missing status")?.state,
            OutboxState::Delivered
        );
        Ok(())
    }

    #[test]
    fn exact_worker_dispatches_only_the_authenticated_job() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let mut outbox = open_outbox(&root.path().join("exact-worker.sqlite3"))?;
        let other_id = enqueue_slack(&mut outbox, "exact-worker-other", 3)?;
        let target_id = enqueue_slack(&mut outbox, "exact-worker-target", 3)?;
        let mut clock = ScriptedClock::new(&[100, 101]);
        let mut resolver = SlackResolver::new(ResolutionMode::Success);
        let mut transport = ScriptedTransport::new(TransportMode::Success);

        let step = process_exact_delivery(
            target_id,
            &mut outbox,
            DeliveryWorkerConfig::default(),
            &mut clock,
            &mut resolver,
            &mut transport,
        )?;
        assert!(matches!(
            step,
            DeliveryWorkerStep::Delivered { job_id, .. } if job_id == target_id
        ));
        assert_eq!(resolver.calls, 1);
        assert_eq!(transport.calls, 1);
        assert_eq!(
            outbox
                .status(target_id)?
                .ok_or("missing target status")?
                .state,
            OutboxState::Delivered
        );
        let other_status = outbox.status(other_id)?.ok_or("missing other status")?;
        assert_eq!(other_status.state, OutboxState::Pending);
        assert_eq!(other_status.attempts, 0);
        Ok(())
    }

    #[test]
    fn exact_worker_is_idle_for_a_future_job_and_errors_when_missing() -> Result<(), Box<dyn Error>>
    {
        let root = tempfile::tempdir()?;
        let mut outbox = open_outbox(&root.path().join("exact-worker-idle.sqlite3"))?;
        let ready_id = enqueue_slack(&mut outbox, "exact-worker-ready", 3)?;
        let delivery = build_review_notification_delivery(
            ApprovalChannel::Slack,
            "C12345678".to_owned(),
            ReviewNotificationPrompt::new(),
        )?;
        let payload = serde_json::to_vec(delivery.body())?;
        let future_id = outbox
            .enqueue(&EnqueueRequest {
                channel: ApprovalChannel::Slack,
                destination: DESTINATION,
                payload: &payload,
                credential_reference: CREDENTIAL_REFERENCE,
                idempotency_key: "exact-worker-future",
                max_attempts: 3,
                available_at: 200,
                trusted_now: 90,
            })?
            .job_id();
        let mut clock = ScriptedClock::new(&[100]);
        let mut resolver = SlackResolver::new(ResolutionMode::Success);
        let mut transport = ScriptedTransport::new(TransportMode::Success);

        assert_eq!(
            process_exact_delivery(
                future_id,
                &mut outbox,
                DeliveryWorkerConfig::default(),
                &mut clock,
                &mut resolver,
                &mut transport,
            )?,
            DeliveryWorkerStep::Idle
        );
        assert_eq!(resolver.calls, 0);
        assert_eq!(transport.calls, 0);
        assert_eq!(
            outbox
                .status(ready_id)?
                .ok_or("missing ready status")?
                .state,
            OutboxState::Pending
        );

        let mut missing_clock = ScriptedClock::new(&[100]);
        assert_eq!(
            process_exact_delivery(
                Uuid::new_v4(),
                &mut outbox,
                DeliveryWorkerConfig::default(),
                &mut missing_clock,
                &mut resolver,
                &mut transport,
            ),
            Err(DeliveryWorkerError::Outbox(OutboxError::JobNotFound))
        );
        Ok(())
    }

    #[test]
    fn proven_pre_send_failure_is_scheduled_without_inline_resend() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let mut outbox = open_outbox(&root.path().join("not-sent.sqlite3"))?;
        let job_id = enqueue_slack(&mut outbox, "not-sent", 3)?;
        let mut clock = ScriptedClock::new(&[100, 101]);
        let mut resolver = SlackResolver::new(ResolutionMode::Success);
        let mut transport = ScriptedTransport::new(TransportMode::NotSent);

        let step = process_one_delivery(
            &mut outbox,
            DeliveryWorkerConfig::default(),
            &mut clock,
            &mut resolver,
            &mut transport,
        )?;
        assert_eq!(transport.calls, 1);
        assert!(matches!(
            step,
            DeliveryWorkerStep::RetryScheduled {
                job_id: id,
                available_at: 106,
                reason: DeliveryWorkerRetryReason::TransportNotSent,
                ..
            } if id == job_id
        ));
        assert_eq!(
            outbox.status(job_id)?.ok_or("missing status")?.state,
            OutboxState::Retry
        );
        Ok(())
    }

    #[test]
    fn provider_rate_limit_uses_bounded_retry_after() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let mut outbox = open_outbox(&root.path().join("rate-limit.sqlite3"))?;
        let job_id = enqueue_slack(&mut outbox, "rate-limit", 3)?;
        let mut clock = ScriptedClock::new(&[100, 101]);
        let mut resolver = SlackResolver::new(ResolutionMode::Success);
        let mut transport = ScriptedTransport::new(TransportMode::RateLimited);

        let step = process_one_delivery(
            &mut outbox,
            DeliveryWorkerConfig::default(),
            &mut clock,
            &mut resolver,
            &mut transport,
        )?;
        assert!(matches!(
            step,
            DeliveryWorkerStep::RetryScheduled {
                job_id: id,
                available_at: 108,
                reason: DeliveryWorkerRetryReason::RateLimited,
                ..
            } if id == job_id
        ));
        assert_eq!(transport.calls, 1);
        Ok(())
    }

    #[test]
    fn permanent_provider_rejection_is_dead_lettered() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let mut outbox = open_outbox(&root.path().join("rejected.sqlite3"))?;
        let job_id = enqueue_slack(&mut outbox, "rejected", 3)?;
        let mut clock = ScriptedClock::new(&[100, 101]);
        let mut resolver = SlackResolver::new(ResolutionMode::Success);
        let mut transport = ScriptedTransport::new(TransportMode::Rejected);

        let step = process_one_delivery(
            &mut outbox,
            DeliveryWorkerConfig::default(),
            &mut clock,
            &mut resolver,
            &mut transport,
        )?;
        assert!(matches!(
            step,
            DeliveryWorkerStep::DeadLettered {
                job_id: id,
                reason: DeliveryWorkerDeadLetterReason::ProviderRejected,
                ..
            } if id == job_id
        ));
        let status = outbox.status(job_id)?.ok_or("missing status")?;
        assert_eq!(status.state, OutboxState::DeadLetter);
        assert_eq!(
            status.terminal_reason,
            Some(OutboxTerminalReason::ProviderRejected)
        );
        assert!(status.attempt_summary_hash.is_some());
        Ok(())
    }

    #[test]
    fn ambiguous_transport_outcome_is_never_resent() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let mut outbox = open_outbox(&root.path().join("ambiguous.sqlite3"))?;
        let job_id = enqueue_slack(&mut outbox, "ambiguous", 3)?;
        let mut clock = ScriptedClock::new(&[100, 101]);
        let mut resolver = SlackResolver::new(ResolutionMode::Success);
        let mut transport = ScriptedTransport::new(TransportMode::Ambiguous);

        let step = process_one_delivery(
            &mut outbox,
            DeliveryWorkerConfig::default(),
            &mut clock,
            &mut resolver,
            &mut transport,
        )?;
        assert!(matches!(
            step,
            DeliveryWorkerStep::DeadLettered {
                reason: DeliveryWorkerDeadLetterReason::AmbiguousDelivery,
                ..
            }
        ));
        assert_eq!(transport.calls, 1);

        let mut later_clock = ScriptedClock::new(&[500]);
        let mut later_resolver = SlackResolver::new(ResolutionMode::Success);
        let mut later_transport = ScriptedTransport::new(TransportMode::Success);
        assert_eq!(
            process_one_delivery(
                &mut outbox,
                DeliveryWorkerConfig::default(),
                &mut later_clock,
                &mut later_resolver,
                &mut later_transport,
            )?,
            DeliveryWorkerStep::Idle
        );
        assert_eq!(later_resolver.calls, 0);
        assert_eq!(later_transport.calls, 0);
        let status = outbox.status(job_id)?.ok_or("missing status")?;
        assert_eq!(status.state, OutboxState::DeadLetter);
        assert_eq!(
            status.terminal_reason,
            Some(OutboxTerminalReason::AmbiguousDelivery)
        );
        assert!(status.attempt_summary_hash.is_some());
        Ok(())
    }

    #[test]
    fn crash_after_provider_acceptance_dead_letters_without_resend() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let mut outbox = open_outbox(&root.path().join("crash.sqlite3"))?;
        let job_id = enqueue_slack(&mut outbox, "crash", 3)?;
        let claimed = outbox.claim(100, 10)?.ok_or("missing claim")?;
        let delivery = reconstruct_delivery(&claimed).map_err(|()| "invalid fixture")?;
        let mut resolver = SlackResolver::new(ResolutionMode::Success);
        let material = resolver.resolve(&DeliveryResolutionContext {
            job_id,
            channel: claimed.channel(),
            credential_reference: claimed.credential_reference(),
        })?;
        let mut first_transport = ScriptedTransport::new(TransportMode::Success);
        let attempt = dispatch_channel_delivery(
            &delivery,
            &material.endpoint,
            &material.credential,
            DeliveryLimits::default(),
            &mut first_transport,
        )?;
        assert_eq!(attempt.disposition(), DeliveryDisposition::Accepted);
        assert_eq!(first_transport.calls, 1);
        drop(claimed);

        let mut recovery_clock = ScriptedClock::new(&[110]);
        let mut recovery_resolver = SlackResolver::new(ResolutionMode::Success);
        let mut recovery_transport = ScriptedTransport::new(TransportMode::Success);
        assert_eq!(
            process_one_delivery(
                &mut outbox,
                DeliveryWorkerConfig::default(),
                &mut recovery_clock,
                &mut recovery_resolver,
                &mut recovery_transport,
            )?,
            DeliveryWorkerStep::Idle
        );
        assert_eq!(recovery_resolver.calls, 0);
        assert_eq!(recovery_transport.calls, 0);
        let status = outbox.status(job_id)?.ok_or("missing status")?;
        assert_eq!(status.state, OutboxState::DeadLetter);
        assert_eq!(
            status.terminal_reason,
            Some(OutboxTerminalReason::CrashExpired)
        );
        assert_eq!(status.attempt_summary_hash, None);
        Ok(())
    }

    #[test]
    fn retry_budget_exhaustion_is_durable_and_not_resent() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("retry-exhausted.sqlite3");
        let mut outbox = open_outbox(&path)?;
        let job_id = enqueue_slack(&mut outbox, "retry-exhausted", 1)?;
        let mut clock = ScriptedClock::new(&[100, 101]);
        let mut resolver = SlackResolver::new(ResolutionMode::Success);
        let mut transport = ScriptedTransport::new(TransportMode::NotSent);

        let step = process_one_delivery(
            &mut outbox,
            DeliveryWorkerConfig::default(),
            &mut clock,
            &mut resolver,
            &mut transport,
        )?;
        assert!(matches!(
            step,
            DeliveryWorkerStep::DeadLettered {
                job_id: id,
                reason: DeliveryWorkerDeadLetterReason::RetryBudgetExhausted,
                attempt: Some(_),
            } if id == job_id
        ));
        drop(outbox);

        let mut reopened = open_outbox(&path)?;
        let status = reopened.status(job_id)?.ok_or("missing status")?;
        assert_eq!(status.state, OutboxState::DeadLetter);
        assert_eq!(
            status.terminal_reason,
            Some(OutboxTerminalReason::RetryBudgetExhausted)
        );
        assert!(status.attempt_summary_hash.is_some());

        let mut later_clock = ScriptedClock::new(&[500]);
        let mut later_resolver = SlackResolver::new(ResolutionMode::Success);
        let mut later_transport = ScriptedTransport::new(TransportMode::Success);
        assert_eq!(
            process_one_delivery(
                &mut reopened,
                DeliveryWorkerConfig::default(),
                &mut later_clock,
                &mut later_resolver,
                &mut later_transport,
            )?,
            DeliveryWorkerStep::Idle
        );
        assert_eq!(later_resolver.calls, 0);
        assert_eq!(later_transport.calls, 0);
        Ok(())
    }

    #[test]
    fn material_resolution_is_classified_before_network_io() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let mut outbox = open_outbox(&root.path().join("resolver.sqlite3"))?;
        let retry_id = enqueue_slack(&mut outbox, "resolver-retry", 3)?;
        let mut clock = ScriptedClock::new(&[100, 101]);
        let mut resolver = SlackResolver::new(ResolutionMode::Retryable);
        let mut transport = ScriptedTransport::new(TransportMode::Success);
        let step = process_one_delivery(
            &mut outbox,
            DeliveryWorkerConfig::default(),
            &mut clock,
            &mut resolver,
            &mut transport,
        )?;
        assert!(matches!(
            step,
            DeliveryWorkerStep::RetryScheduled {
                job_id,
                reason: DeliveryWorkerRetryReason::MaterialUnavailable,
                attempt: None,
                ..
            } if job_id == retry_id
        ));
        assert_eq!(transport.calls, 0);

        let permanent_id = enqueue_slack(&mut outbox, "resolver-permanent", 3)?;
        let mut clock = ScriptedClock::new(&[102, 103]);
        let mut resolver = SlackResolver::new(ResolutionMode::Permanent);
        let step = process_one_delivery(
            &mut outbox,
            DeliveryWorkerConfig::default(),
            &mut clock,
            &mut resolver,
            &mut transport,
        )?;
        assert!(matches!(
            step,
            DeliveryWorkerStep::DeadLettered {
                job_id,
                reason: DeliveryWorkerDeadLetterReason::MaterialRejected,
                attempt: None,
            } if job_id == permanent_id
        ));
        assert_eq!(transport.calls, 0);
        let status = outbox.status(permanent_id)?.ok_or("missing status")?;
        assert_eq!(
            status.terminal_reason,
            Some(OutboxTerminalReason::MaterialRejected)
        );
        assert_eq!(status.attempt_summary_hash, None);
        Ok(())
    }

    #[test]
    fn invalid_queued_payload_is_durably_dead_lettered_before_resolution()
    -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let mut outbox = open_outbox(&root.path().join("invalid-payload.sqlite3"))?;
        let job_id = outbox
            .enqueue(&EnqueueRequest {
                channel: ApprovalChannel::Slack,
                destination: DESTINATION,
                payload: b"not-json",
                credential_reference: CREDENTIAL_REFERENCE,
                idempotency_key: "invalid-payload",
                max_attempts: 3,
                available_at: 100,
                trusted_now: 90,
            })?
            .job_id();
        let mut clock = ScriptedClock::new(&[100, 101]);
        let mut resolver = SlackResolver::new(ResolutionMode::Success);
        let mut transport = ScriptedTransport::new(TransportMode::Success);

        assert!(matches!(
            process_one_delivery(
                &mut outbox,
                DeliveryWorkerConfig::default(),
                &mut clock,
                &mut resolver,
                &mut transport,
            )?,
            DeliveryWorkerStep::DeadLettered {
                job_id: id,
                reason: DeliveryWorkerDeadLetterReason::InvalidQueuedDelivery,
                attempt: None,
            } if id == job_id
        ));
        assert_eq!(resolver.calls, 0);
        assert_eq!(transport.calls, 0);
        let status = outbox.status(job_id)?.ok_or("missing status")?;
        assert_eq!(
            status.terminal_reason,
            Some(OutboxTerminalReason::InvalidQueuedDelivery)
        );
        assert_eq!(status.attempt_summary_hash, None);
        Ok(())
    }

    #[test]
    fn provider_shape_mismatch_is_durably_rejected_before_resolution() -> Result<(), Box<dyn Error>>
    {
        let root = tempfile::tempdir()?;
        let mut outbox = open_outbox(&root.path().join("request-rejected.sqlite3"))?;
        let payload = serde_json::to_vec(&json!({
            "channel": "C12345678",
            "text": "Missing required blocks"
        }))?;
        let job_id = outbox
            .enqueue(&EnqueueRequest {
                channel: ApprovalChannel::Slack,
                destination: DESTINATION,
                payload: &payload,
                credential_reference: CREDENTIAL_REFERENCE,
                idempotency_key: "request-rejected",
                max_attempts: 3,
                available_at: 100,
                trusted_now: 90,
            })?
            .job_id();
        let mut clock = ScriptedClock::new(&[100, 101]);
        let mut resolver = SlackResolver::new(ResolutionMode::Success);
        let mut transport = ScriptedTransport::new(TransportMode::Success);

        assert!(matches!(
            process_one_delivery(
                &mut outbox,
                DeliveryWorkerConfig::default(),
                &mut clock,
                &mut resolver,
                &mut transport,
            )?,
            DeliveryWorkerStep::DeadLettered {
                job_id: id,
                reason: DeliveryWorkerDeadLetterReason::InvalidQueuedDelivery,
                attempt: None,
            } if id == job_id
        ));
        assert_eq!(resolver.calls, 0);
        assert_eq!(transport.calls, 0);
        let status = outbox.status(job_id)?.ok_or("missing status")?;
        assert_eq!(
            status.terminal_reason,
            Some(OutboxTerminalReason::InvalidQueuedDelivery)
        );
        assert_eq!(status.attempt_summary_hash, None);
        Ok(())
    }

    #[test]
    fn interactive_payload_is_not_reclassified_after_outbox_reconstruction()
    -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let mut outbox = open_outbox(&root.path().join("interactive-rejected.sqlite3"))?;
        // This satisfies the legacy top-level Slack interactive shape. It must
        // still be rejected because the current durable worker is display-only.
        let payload = serde_json::to_vec(&json!({
            "blocks": [{"type": "actions", "elements": []}],
            "channel": "C12345678",
            "text": "Approve this action"
        }))?;
        let job_id = outbox
            .enqueue(&EnqueueRequest {
                channel: ApprovalChannel::Slack,
                destination: DESTINATION,
                payload: &payload,
                credential_reference: CREDENTIAL_REFERENCE,
                idempotency_key: "interactive-rejected",
                max_attempts: 3,
                available_at: 100,
                trusted_now: 90,
            })?
            .job_id();
        let mut clock = ScriptedClock::new(&[100, 101]);
        let mut resolver = SlackResolver::new(ResolutionMode::Success);
        let mut transport = ScriptedTransport::new(TransportMode::Success);

        assert!(matches!(
            process_one_delivery(
                &mut outbox,
                DeliveryWorkerConfig::default(),
                &mut clock,
                &mut resolver,
                &mut transport,
            )?,
            DeliveryWorkerStep::DeadLettered {
                job_id: id,
                reason: DeliveryWorkerDeadLetterReason::InvalidQueuedDelivery,
                attempt: None,
            } if id == job_id
        ));
        assert_eq!(resolver.calls, 0);
        assert_eq!(transport.calls, 0);
        Ok(())
    }

    #[test]
    fn worker_configuration_requires_lease_longer_than_request_timeout()
    -> Result<(), Box<dyn Error>> {
        let limits = DeliveryLimits::new(Duration::from_secs(15), 1_024)?;
        assert_eq!(
            DeliveryWorkerConfig::new(15, 30, limits),
            Err(DeliveryWorkerError::InvalidConfiguration)
        );
        assert!(DeliveryWorkerConfig::new(16, 30, limits).is_ok());
        Ok(())
    }
}
