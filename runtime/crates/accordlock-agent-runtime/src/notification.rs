//! Main-process-only, display-only approval notification dispatch.
//!
//! This module is deliberately separate from the execution control channel.
//! It accepts one bounded request on an inherited pipe, builds library-owned
//! generic copy, and uses an encrypted durable outbox. It cannot approve,
//! deny, stop, revoke, or otherwise change execution authority.

use std::{
    collections::BTreeSet,
    fs,
    io::{self, Read},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use accordlock_approval_channels::{
    ApprovalChannel, BoundedHttpsTransport, ConnectionTestPrompt, DeliveryCredential,
    DeliveryDisposition, DeliveryEndpointConfig, DeliveryLimits, DeliveryMaterialResolver,
    DeliveryOutbox, DeliveryResolutionContext, DeliveryResolutionError, DeliveryWorkerConfig,
    EnqueueOutcome, EnqueueRequest, OutboxEncryptionKey, OutboxState, ResolvedDeliveryMaterial,
    ReviewNotificationPrompt, TrustedTimeError, TrustedTimeSource, WebPkiHttpsTransport,
    build_connection_test_delivery, build_review_notification_delivery, dispatch_channel_delivery,
    prepare_channel_delivery, process_exact_delivery,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub const NOTIFICATION_FRAME_MAGIC: [u8; 4] = *b"ALN1";
pub const CONNECTION_TEST_FRAME_MAGIC: [u8; 4] = *b"ALT1";
pub const MAX_NOTIFICATION_REQUEST_BYTES: usize = 32 * 1_024;
const NOTIFICATION_FRAME_HEADER_BYTES: usize = 8;
const NOTIFICATION_SCHEMA_VERSION: u16 = 1;
const MAX_NOTIFICATION_CHANNELS: usize = 4;
const MAX_NOTIFICATION_LIFETIME_SECONDS: i64 = 5 * 60;
const OUTBOX_FILENAME: &str = "approval-notifications.v1.sqlite3";
const OUTBOX_MAX_ATTEMPTS: u8 = 3;
const OUTBOX_TERMINAL_RETENTION_SECONDS: i64 = 24 * 60 * 60;
const OUTBOX_PRUNE_LIMIT: u32 = 256;
const DELIVERY_TIMEOUT_SECONDS: u64 = 10;
const DELIVERY_LEASE_SECONDS: i64 = 20;
const DELIVERY_RETRY_SECONDS: u32 = 30;
const DELIVERY_RESPONSE_BYTES: usize = 32 * 1_024;
// This compatibility version is package-owned and intentionally absent from
// the product UI. It can be updated with the adapter without changing stored
// user configuration.
const WHATSAPP_GRAPH_API_VERSION: &str = "v23.0";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReviewNotificationRequest {
    schema_version: u16,
    approval_id: String,
    received_at: i64,
    expires_at: i64,
    outbox_key_hex: String,
    channels: Vec<NotificationChannelConfiguration>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ConnectionTestRequest {
    schema_version: u16,
    channel: NotificationChannelConfiguration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ConnectionTestReport {
    schema_version: u16,
    channel: ApprovalChannel,
    accepted: bool,
    outcome: &'static str,
}

impl Drop for ReviewNotificationRequest {
    fn drop(&mut self) {
        self.outbox_key_hex.zeroize();
    }
}

#[derive(Deserialize, Serialize)]
#[serde(
    tag = "channel",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
enum NotificationChannelConfiguration {
    Slack {
        destination: String,
        access_token: String,
    },
    MicrosoftTeams {
        conversation_id: String,
        service_url: String,
        access_token: String,
    },
    Telegram {
        chat_id: String,
        bot_token: String,
    },
    WhatsApp {
        recipient: String,
        phone_number_id: String,
        access_token: String,
    },
}

impl Drop for NotificationChannelConfiguration {
    fn drop(&mut self) {
        match self {
            Self::Slack { access_token, .. }
            | Self::MicrosoftTeams { access_token, .. }
            | Self::WhatsApp { access_token, .. } => access_token.zeroize(),
            Self::Telegram { bot_token, .. } => bot_token.zeroize(),
        }
    }
}

impl NotificationChannelConfiguration {
    const fn channel(&self) -> ApprovalChannel {
        match self {
            Self::Slack { .. } => ApprovalChannel::Slack,
            Self::MicrosoftTeams { .. } => ApprovalChannel::MicrosoftTeams,
            Self::Telegram { .. } => ApprovalChannel::Telegram,
            Self::WhatsApp { .. } => ApprovalChannel::WhatsApp,
        }
    }

    fn into_material(mut self) -> ProviderMaterial {
        match &mut self {
            Self::Slack {
                destination,
                access_token,
            } => ProviderMaterial {
                channel: ApprovalChannel::Slack,
                destination: std::mem::take(destination),
                endpoint: ProviderEndpoint::Slack,
                secret: Zeroizing::new(std::mem::take(access_token)),
            },
            Self::MicrosoftTeams {
                conversation_id,
                service_url,
                access_token,
            } => ProviderMaterial {
                channel: ApprovalChannel::MicrosoftTeams,
                destination: std::mem::take(conversation_id),
                endpoint: ProviderEndpoint::MicrosoftTeams {
                    service_url: std::mem::take(service_url),
                },
                secret: Zeroizing::new(std::mem::take(access_token)),
            },
            Self::Telegram { chat_id, bot_token } => ProviderMaterial {
                channel: ApprovalChannel::Telegram,
                destination: std::mem::take(chat_id),
                endpoint: ProviderEndpoint::Telegram,
                secret: Zeroizing::new(std::mem::take(bot_token)),
            },
            Self::WhatsApp {
                recipient,
                phone_number_id,
                access_token,
            } => ProviderMaterial {
                channel: ApprovalChannel::WhatsApp,
                destination: std::mem::take(recipient),
                endpoint: ProviderEndpoint::WhatsApp {
                    phone_number_id: std::mem::take(phone_number_id),
                },
                secret: Zeroizing::new(std::mem::take(access_token)),
            },
        }
    }
}

enum ProviderEndpoint {
    Slack,
    MicrosoftTeams { service_url: String },
    Telegram,
    WhatsApp { phone_number_id: String },
}

struct ProviderMaterial {
    channel: ApprovalChannel,
    destination: String,
    endpoint: ProviderEndpoint,
    secret: Zeroizing<String>,
}

impl ProviderMaterial {
    fn endpoint(&self) -> Result<DeliveryEndpointConfig, NotificationRequestError> {
        match &self.endpoint {
            ProviderEndpoint::Slack => Ok(DeliveryEndpointConfig::slack()),
            ProviderEndpoint::MicrosoftTeams { service_url } => {
                DeliveryEndpointConfig::teams_bot_public(service_url.clone())
                    .map_err(|_| NotificationRequestError::InvalidRequest)
            }
            ProviderEndpoint::Telegram => Ok(DeliveryEndpointConfig::telegram()),
            ProviderEndpoint::WhatsApp { phone_number_id } => {
                DeliveryEndpointConfig::whatsapp_cloud(
                    WHATSAPP_GRAPH_API_VERSION,
                    phone_number_id.clone(),
                )
                .map_err(|_| NotificationRequestError::InvalidRequest)
            }
        }
    }

    fn credential(&self) -> Result<DeliveryCredential, NotificationRequestError> {
        let secret = self.secret.as_str().to_owned();
        match self.channel {
            ApprovalChannel::Slack => DeliveryCredential::slack(secret),
            ApprovalChannel::MicrosoftTeams => DeliveryCredential::teams_bot(secret),
            ApprovalChannel::Telegram => DeliveryCredential::telegram(secret),
            ApprovalChannel::WhatsApp => DeliveryCredential::whatsapp_cloud(secret),
        }
        .map_err(|_| NotificationRequestError::InvalidRequest)
    }

    fn configuration_identity(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(b"accordlock:v1:review-notification-provider-config\0");
        update_identity_field(&mut digest, channel_code(self.channel).as_bytes());
        update_identity_field(&mut digest, self.destination.as_bytes());
        match &self.endpoint {
            ProviderEndpoint::Slack => update_identity_field(&mut digest, b"SLACK_FIXED"),
            ProviderEndpoint::MicrosoftTeams { service_url } => {
                update_identity_field(&mut digest, service_url.as_bytes());
            }
            ProviderEndpoint::Telegram => update_identity_field(&mut digest, b"TELEGRAM_FIXED"),
            ProviderEndpoint::WhatsApp { phone_number_id } => {
                update_identity_field(&mut digest, WHATSAPP_GRAPH_API_VERSION.as_bytes());
                update_identity_field(&mut digest, phone_number_id.as_bytes());
            }
        }
        hex::encode(digest.finalize())
    }
}

fn update_identity_field(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

struct NotificationBatch {
    approval_id: String,
    approval_digest: String,
    received_at: i64,
    expires_at: i64,
    key: OutboxEncryptionKey,
    materials: Vec<ProviderMaterial>,
}

struct NotificationDispatchContext {
    approval_id: String,
    approval_digest: String,
    received_at: i64,
    expires_at: i64,
    materials: Vec<ProviderMaterial>,
}

impl NotificationBatch {
    fn into_dispatch_context(self) -> (OutboxEncryptionKey, NotificationDispatchContext) {
        let Self {
            approval_id,
            approval_digest,
            received_at,
            expires_at,
            key,
            materials,
        } = self;
        (
            key,
            NotificationDispatchContext {
                approval_id,
                approval_digest,
                received_at,
                expires_at,
                materials,
            },
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct NotificationDispatchReport {
    pub schema_version: u16,
    pub configured: u8,
    pub enqueued: u8,
    pub existing: u8,
    pub delivered: u8,
    pub retry_scheduled: u8,
    pub dead_lettered: u8,
    pub idle: u8,
    pub next_retry_at: Option<i64>,
}

impl NotificationDispatchReport {
    fn new(configured: usize) -> Result<Self, NotificationRequestError> {
        Ok(Self {
            schema_version: NOTIFICATION_SCHEMA_VERSION,
            configured: u8::try_from(configured)
                .map_err(|_| NotificationRequestError::InvalidRequest)?,
            enqueued: 0,
            existing: 0,
            delivered: 0,
            retry_scheduled: 0,
            dead_lettered: 0,
            idle: 0,
            next_retry_at: None,
        })
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum NotificationRequestError {
    #[error("notification request framing is invalid")]
    InvalidFrame,
    #[error("notification request exceeds the bounded profile")]
    RequestTooLarge,
    #[error("notification request is malformed or outside the display-only profile")]
    InvalidRequest,
    #[error("notification request has expired")]
    Expired,
    #[error("notification storage is unavailable")]
    StorageUnavailable,
    #[error("notification transport is unavailable")]
    TransportUnavailable,
    #[error("notification request input failed")]
    Input,
}

struct MonotonicSystemClock {
    high_watermark: i64,
}

impl MonotonicSystemClock {
    const fn new() -> Self {
        Self { high_watermark: 0 }
    }
}

impl TrustedTimeSource for MonotonicSystemClock {
    fn now(&mut self) -> Result<i64, TrustedTimeError> {
        let now = unix_time().ok_or(TrustedTimeError::Unavailable)?;
        if now < self.high_watermark {
            return Err(TrustedTimeError::Unavailable);
        }
        self.high_watermark = now;
        Ok(now)
    }
}

struct BatchMaterialResolver<'a> {
    approval_digest: &'a str,
    materials: &'a [ProviderMaterial],
    high_watermark: i64,
}

impl DeliveryMaterialResolver for BatchMaterialResolver<'_> {
    fn resolve(
        &mut self,
        context: &DeliveryResolutionContext<'_>,
    ) -> Result<ResolvedDeliveryMaterial, DeliveryResolutionError> {
        let reference = std::str::from_utf8(context.credential_reference())
            .map_err(|_| DeliveryResolutionError::Permanent)?;
        let current = unix_time().ok_or(DeliveryResolutionError::Permanent)?;
        if current < self.high_watermark {
            return Err(DeliveryResolutionError::Permanent);
        }
        self.high_watermark = current;
        let mut fields = reference.split(':');
        if fields.next() != Some("review")
            || fields.next() != Some("v2")
            || fields.next() != Some(self.approval_digest)
        {
            return Err(DeliveryResolutionError::Permanent);
        }
        let expiry = fields
            .next()
            .ok_or(DeliveryResolutionError::Permanent)?
            .parse::<i64>()
            .map_err(|_| DeliveryResolutionError::Permanent)?;
        if fields.next() != Some(channel_code(context.channel())) || expiry <= current {
            return Err(DeliveryResolutionError::Permanent);
        }
        let material = self
            .materials
            .iter()
            .find(|candidate| candidate.channel == context.channel())
            .ok_or(DeliveryResolutionError::Permanent)?;
        if fields.next() != Some(material.configuration_identity().as_str())
            || fields.next().is_some()
        {
            return Err(DeliveryResolutionError::Permanent);
        }
        let endpoint = material
            .endpoint()
            .map_err(|_| DeliveryResolutionError::Permanent)?;
        let credential = material
            .credential()
            .map_err(|_| DeliveryResolutionError::Permanent)?;
        Ok(ResolvedDeliveryMaterial::new(endpoint, credential))
    }
}

/// Reads one exact ALN1 request and performs display-only delivery work.
///
/// # Errors
///
/// Rejects additional frames, malformed JSON, invalid credentials, expired
/// requests, unsafe storage, or unavailable transport without changing any
/// approval state.
pub fn serve_review_notification_request(
    mut input: impl Read,
    data_directory: &Path,
) -> Result<NotificationDispatchReport, NotificationRequestError> {
    let mut body = read_single_frame(&mut input, NOTIFICATION_FRAME_MAGIC)?;
    let request = serde_json::from_slice::<ReviewNotificationRequest>(&body)
        .map_err(|_| NotificationRequestError::InvalidRequest);
    body.zeroize();
    let request = request?;
    dispatch_review_notification_request(request, data_directory)
}

/// Sends one fixed connection-test message with one configured channel.
///
/// # Errors
///
/// Rejects malformed framing, credentials, destinations, or transport setup.
pub fn serve_connection_test_request(
    mut input: impl Read,
) -> Result<ConnectionTestReport, NotificationRequestError> {
    let mut body = read_single_frame(&mut input, CONNECTION_TEST_FRAME_MAGIC)?;
    let request = serde_json::from_slice::<ConnectionTestRequest>(&body)
        .map_err(|_| NotificationRequestError::InvalidRequest);
    body.zeroize();
    let request = request?;
    let mut transport =
        WebPkiHttpsTransport::new().map_err(|_| NotificationRequestError::TransportUnavailable)?;
    dispatch_connection_test_with_transport(request, &mut transport)
}

fn dispatch_connection_test_with_transport(
    request: ConnectionTestRequest,
    transport: &mut dyn BoundedHttpsTransport,
) -> Result<ConnectionTestReport, NotificationRequestError> {
    if request.schema_version != NOTIFICATION_SCHEMA_VERSION {
        return Err(NotificationRequestError::InvalidRequest);
    }
    let material = request.channel.into_material();
    validate_material(&material)?;
    let delivery = build_connection_test_delivery(
        material.channel,
        material.destination.clone(),
        ConnectionTestPrompt::new(),
    )
    .map_err(|_| NotificationRequestError::InvalidRequest)?;
    let endpoint = material.endpoint()?;
    let credential = material.credential()?;
    let attempt = dispatch_channel_delivery(
        &delivery,
        &endpoint,
        &credential,
        delivery_limits(),
        transport,
    )
    .map_err(|_| NotificationRequestError::InvalidRequest)?;
    let outcome = match attempt.disposition() {
        DeliveryDisposition::Accepted => "DELIVERED",
        DeliveryDisposition::Retryable => "RETRYABLE_FAILURE",
        DeliveryDisposition::PermanentFailure => "REJECTED",
        DeliveryDisposition::Ambiguous => "UNKNOWN",
    };
    Ok(ConnectionTestReport {
        schema_version: NOTIFICATION_SCHEMA_VERSION,
        channel: material.channel,
        accepted: attempt.disposition() == DeliveryDisposition::Accepted,
        outcome,
    })
}

fn dispatch_review_notification_request(
    request: ReviewNotificationRequest,
    data_directory: &Path,
) -> Result<NotificationDispatchReport, NotificationRequestError> {
    let now = unix_time().ok_or(NotificationRequestError::InvalidRequest)?;
    let batch = validate_request(request, now)?;
    let outbox_path = data_directory.join(OUTBOX_FILENAME);
    reject_link_or_non_file_if_present(&outbox_path)?;
    let mut transport =
        WebPkiHttpsTransport::new().map_err(|_| NotificationRequestError::TransportUnavailable)?;
    dispatch_with_transport(batch, &outbox_path, now, &mut transport)
}

fn validate_request(
    mut request: ReviewNotificationRequest,
    now: i64,
) -> Result<NotificationBatch, NotificationRequestError> {
    if request.schema_version != NOTIFICATION_SCHEMA_VERSION
        || !valid_approval_id(&request.approval_id)
        || request.channels.is_empty()
        || request.channels.len() > MAX_NOTIFICATION_CHANNELS
        || request.received_at < 0
        || request.received_at > now
        || request.expires_at <= now
    {
        return Err(if request.expires_at <= now {
            NotificationRequestError::Expired
        } else {
            NotificationRequestError::InvalidRequest
        });
    }
    if request.expires_at <= request.received_at
        || request.expires_at - request.received_at > MAX_NOTIFICATION_LIFETIME_SECONDS
    {
        return Err(NotificationRequestError::InvalidRequest);
    }
    let mut key_bytes = Zeroizing::new([0_u8; 32]);
    if request.outbox_key_hex.len() != 64
        || hex::decode_to_slice(request.outbox_key_hex.as_bytes(), key_bytes.as_mut()).is_err()
        || key_bytes.iter().all(|byte| *byte == 0)
    {
        return Err(NotificationRequestError::InvalidRequest);
    }
    request.outbox_key_hex.zeroize();

    let mut channels = BTreeSet::new();
    let mut materials = Vec::with_capacity(request.channels.len());
    for configuration in std::mem::take(&mut request.channels) {
        if !channels.insert(configuration.channel()) {
            return Err(NotificationRequestError::InvalidRequest);
        }
        let material = configuration.into_material();
        validate_material(&material)?;
        materials.push(material);
    }
    materials.sort_by_key(|material| material.channel);
    let approval_digest = request
        .approval_id
        .strip_prefix("action:sha256:")
        .ok_or(NotificationRequestError::InvalidRequest)?
        .to_owned();
    Ok(NotificationBatch {
        approval_id: std::mem::take(&mut request.approval_id),
        approval_digest,
        received_at: request.received_at,
        expires_at: request.expires_at,
        key: OutboxEncryptionKey::from_bytes(*key_bytes),
        materials,
    })
}

fn validate_material(material: &ProviderMaterial) -> Result<(), NotificationRequestError> {
    let delivery = build_review_notification_delivery(
        material.channel,
        material.destination.clone(),
        ReviewNotificationPrompt::new(),
    )
    .map_err(|_| NotificationRequestError::InvalidRequest)?;
    let endpoint = material.endpoint()?;
    let credential = material.credential()?;
    prepare_channel_delivery(&delivery, &endpoint, &credential, delivery_limits())
        .map_err(|_| NotificationRequestError::InvalidRequest)?;
    Ok(())
}

fn dispatch_with_transport(
    batch: NotificationBatch,
    outbox_path: &Path,
    now: i64,
    transport: &mut dyn BoundedHttpsTransport,
) -> Result<NotificationDispatchReport, NotificationRequestError> {
    let (key, context) = batch.into_dispatch_context();
    let mut outbox = DeliveryOutbox::open(outbox_path, key)
        .map_err(|_| NotificationRequestError::StorageUnavailable)?;
    let prune_cutoff = now.saturating_sub(OUTBOX_TERMINAL_RETENTION_SECONDS);
    outbox
        .prune(prune_cutoff, OUTBOX_PRUNE_LIMIT)
        .map_err(|_| NotificationRequestError::StorageUnavailable)?;
    let mut report = NotificationDispatchReport::new(context.materials.len())?;
    let current_job_ids = enqueue_notifications(&mut outbox, &context, now, &mut report)?;
    process_notification_jobs(&mut outbox, &context, now, &current_job_ids, transport)?;
    summarize_notification_jobs(&outbox, &context, current_job_ids, &mut report)?;
    Ok(report)
}

fn enqueue_notifications(
    outbox: &mut DeliveryOutbox,
    context: &NotificationDispatchContext,
    now: i64,
    report: &mut NotificationDispatchReport,
) -> Result<Vec<Uuid>, NotificationRequestError> {
    let mut job_ids = Vec::with_capacity(context.materials.len());
    for material in &context.materials {
        let delivery = build_review_notification_delivery(
            material.channel,
            material.destination.clone(),
            ReviewNotificationPrompt::new(),
        )
        .map_err(|_| NotificationRequestError::InvalidRequest)?;
        let payload = serde_json::to_vec(delivery.body())
            .map_err(|_| NotificationRequestError::InvalidRequest)?;
        let reference = credential_reference(
            material.channel,
            &context.approval_digest,
            context.expires_at,
            &material.configuration_identity(),
        )?;
        let idempotency = format!(
            "review-notification:v1:{}:{}",
            context.approval_id,
            channel_code(material.channel)
        );
        match outbox
            .enqueue(&EnqueueRequest {
                channel: material.channel,
                destination: material.destination.as_bytes(),
                payload: &payload,
                credential_reference: reference.as_bytes(),
                idempotency_key: &idempotency,
                max_attempts: OUTBOX_MAX_ATTEMPTS,
                available_at: context.received_at,
                trusted_now: now,
            })
            .map_err(|_| NotificationRequestError::StorageUnavailable)?
        {
            EnqueueOutcome::Enqueued(job_id) => {
                report.enqueued += 1;
                job_ids.push(job_id);
            }
            EnqueueOutcome::Existing(job_id) => {
                report.existing += 1;
                job_ids.push(job_id);
            }
        }
    }
    Ok(job_ids)
}

fn process_notification_jobs(
    outbox: &mut DeliveryOutbox,
    context: &NotificationDispatchContext,
    now: i64,
    job_ids: &[Uuid],
    transport: &mut dyn BoundedHttpsTransport,
) -> Result<(), NotificationRequestError> {
    let mut clock = MonotonicSystemClock::new();
    let mut resolver = BatchMaterialResolver {
        approval_digest: &context.approval_digest,
        materials: &context.materials,
        high_watermark: now,
    };
    let worker_config = worker_config()?;
    for job_id in job_ids {
        let _step = process_exact_delivery(
            *job_id,
            outbox,
            worker_config,
            &mut clock,
            &mut resolver,
            transport,
        )
        .map_err(|_| NotificationRequestError::StorageUnavailable)?;
    }
    Ok(())
}

fn summarize_notification_jobs(
    outbox: &DeliveryOutbox,
    context: &NotificationDispatchContext,
    job_ids: Vec<Uuid>,
    report: &mut NotificationDispatchReport,
) -> Result<(), NotificationRequestError> {
    for job_id in job_ids {
        let status = outbox
            .status(job_id)
            .map_err(|_| NotificationRequestError::StorageUnavailable)?
            .ok_or(NotificationRequestError::StorageUnavailable)?;
        match status.state {
            OutboxState::Delivered => report.delivered += 1,
            OutboxState::Retry => {
                report.retry_scheduled += 1;
                retain_earliest_retry(
                    &mut report.next_retry_at,
                    status.available_at,
                    context.expires_at,
                );
            }
            OutboxState::DeadLetter => report.dead_lettered += 1,
            OutboxState::Pending => {
                report.idle += 1;
                retain_earliest_retry(
                    &mut report.next_retry_at,
                    status.available_at,
                    context.expires_at,
                );
            }
            OutboxState::Leased => {
                report.idle += 1;
                if let Some(lease_expires_at) = status.lease_expires_at {
                    retain_earliest_retry(
                        &mut report.next_retry_at,
                        lease_expires_at,
                        context.expires_at,
                    );
                }
            }
        }
    }
    Ok(())
}

fn retain_earliest_retry(target: &mut Option<i64>, candidate: i64, expires_at: i64) {
    if candidate < 0 || candidate >= expires_at {
        return;
    }
    *target = Some(target.map_or(candidate, |current| current.min(candidate)));
}

fn delivery_limits() -> DeliveryLimits {
    DeliveryLimits::new(
        Duration::from_secs(DELIVERY_TIMEOUT_SECONDS),
        DELIVERY_RESPONSE_BYTES,
    )
    .unwrap_or_else(|_| unreachable!("fixed notification limits are valid"))
}

fn worker_config() -> Result<DeliveryWorkerConfig, NotificationRequestError> {
    DeliveryWorkerConfig::new(
        DELIVERY_LEASE_SECONDS,
        DELIVERY_RETRY_SECONDS,
        delivery_limits(),
    )
    .map_err(|_| NotificationRequestError::InvalidRequest)
}

fn read_single_frame(
    input: &mut impl Read,
    expected_magic: [u8; 4],
) -> Result<Vec<u8>, NotificationRequestError> {
    let mut header = [0_u8; NOTIFICATION_FRAME_HEADER_BYTES];
    input
        .read_exact(&mut header)
        .map_err(|_| NotificationRequestError::Input)?;
    if header[..4] != expected_magic {
        return Err(NotificationRequestError::InvalidFrame);
    }
    let length = u32::from_be_bytes(
        header[4..]
            .try_into()
            .map_err(|_| NotificationRequestError::InvalidFrame)?,
    ) as usize;
    if length == 0 || length > MAX_NOTIFICATION_REQUEST_BYTES {
        return Err(NotificationRequestError::RequestTooLarge);
    }
    let mut body = vec![0_u8; length];
    input
        .read_exact(&mut body)
        .map_err(|_| NotificationRequestError::Input)?;
    let mut trailing = [0_u8; 1];
    match input.read(&mut trailing) {
        Ok(0) => Ok(body),
        Ok(_) => {
            body.zeroize();
            Err(NotificationRequestError::InvalidFrame)
        }
        Err(error) if error.kind() == io::ErrorKind::Interrupted => {
            body.zeroize();
            Err(NotificationRequestError::Input)
        }
        Err(_) => {
            body.zeroize();
            Err(NotificationRequestError::Input)
        }
    }
}

fn credential_reference(
    channel: ApprovalChannel,
    approval_digest: &str,
    expires_at: i64,
    configuration_identity: &str,
) -> Result<String, NotificationRequestError> {
    if expires_at <= 0
        || approval_digest.len() != 64
        || configuration_identity.len() != 64
        || !approval_digest
            .bytes()
            .chain(configuration_identity.bytes())
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(NotificationRequestError::InvalidRequest);
    }
    Ok(format!(
        "review:v2:{approval_digest}:{expires_at}:{}:{configuration_identity}",
        channel_code(channel),
    ))
}

const fn channel_code(channel: ApprovalChannel) -> &'static str {
    match channel {
        ApprovalChannel::Slack => "SLACK",
        ApprovalChannel::MicrosoftTeams => "MICROSOFT_TEAMS",
        ApprovalChannel::Telegram => "TELEGRAM",
        ApprovalChannel::WhatsApp => "WHATSAPP",
    }
}

fn valid_approval_id(value: &str) -> bool {
    value.strip_prefix("action:sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn unix_time() -> Option<i64> {
    i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs()).ok()
}

fn reject_link_or_non_file_if_present(path: &Path) -> Result<(), NotificationRequestError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(NotificationRequestError::StorageUnavailable)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(NotificationRequestError::StorageUnavailable),
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures use explicit panics and expects as assertions"
)]
mod tests {
    use std::io::Cursor;

    use accordlock_approval_channels::{
        HttpsRequestProgress, HttpsTransportFailure, HttpsTransportFailureKind,
        OutboundHttpsResponse, PreparedHttpsRequest,
    };
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;

    struct AcceptedTransport {
        calls: usize,
    }

    impl BoundedHttpsTransport for AcceptedTransport {
        fn send(
            &mut self,
            request: &PreparedHttpsRequest,
        ) -> Result<OutboundHttpsResponse, HttpsTransportFailure> {
            self.calls += 1;
            if request.channel() != ApprovalChannel::Slack {
                return Err(HttpsTransportFailure::new(
                    HttpsTransportFailureKind::Protocol,
                    HttpsRequestProgress::NotSent,
                ));
            }
            OutboundHttpsResponse::new(200, None, br#"{"ok":true,"ts":"171234.5678"}"#.to_vec())
                .map_err(|_| {
                    HttpsTransportFailure::new(
                        HttpsTransportFailureKind::Protocol,
                        HttpsRequestProgress::NotSent,
                    )
                })
        }
    }

    struct NotSentTransport;

    impl BoundedHttpsTransport for NotSentTransport {
        fn send(
            &mut self,
            _request: &PreparedHttpsRequest,
        ) -> Result<OutboundHttpsResponse, HttpsTransportFailure> {
            Err(HttpsTransportFailure::new(
                HttpsTransportFailureKind::Connect,
                HttpsRequestProgress::NotSent,
            ))
        }
    }

    fn request(received_at: i64) -> ReviewNotificationRequest {
        ReviewNotificationRequest {
            schema_version: NOTIFICATION_SCHEMA_VERSION,
            approval_id: format!("action:sha256:{}", "a".repeat(64)),
            received_at,
            expires_at: received_at + 120,
            outbox_key_hex: "11".repeat(32),
            channels: vec![NotificationChannelConfiguration::Slack {
                destination: "C12345678".to_owned(),
                access_token: "fixture-slack-access-token-00000000".to_owned(),
            }],
        }
    }

    fn frame(value: &serde_json::Value) -> Vec<u8> {
        frame_with_magic(value, NOTIFICATION_FRAME_MAGIC)
    }

    fn frame_with_magic(value: &serde_json::Value, magic: [u8; 4]) -> Vec<u8> {
        let body = serde_json::to_vec(value).unwrap_or_default();
        let mut frame = Vec::with_capacity(NOTIFICATION_FRAME_HEADER_BYTES + body.len());
        frame.extend_from_slice(&magic);
        frame.extend_from_slice(&u32::try_from(body.len()).unwrap_or_default().to_be_bytes());
        frame.extend_from_slice(&body);
        frame
    }

    #[test]
    fn connection_test_uses_fixed_copy_and_one_exact_transport_attempt() {
        let request = ConnectionTestRequest {
            schema_version: NOTIFICATION_SCHEMA_VERSION,
            channel: NotificationChannelConfiguration::Slack {
                destination: "C12345678".to_owned(),
                access_token: "fixture-slack-access-token-00000000".to_owned(),
            },
        };
        let mut transport = AcceptedTransport { calls: 0 };
        let report = dispatch_connection_test_with_transport(request, &mut transport)
            .expect("connection test");
        assert!(report.accepted);
        assert_eq!(report.channel, ApprovalChannel::Slack);
        assert_eq!(report.outcome, "DELIVERED");
        assert_eq!(transport.calls, 1);
    }

    #[test]
    fn connection_test_frame_rejects_provider_callback_fields() {
        let value = json!({
            "schema_version": 1,
            "channel": {
                "channel": "SLACK",
                "destination": "C12345678",
                "access_token": "fixture-slack-access-token-00000000",
                "callback_payload": {}
            }
        });
        let mut body = read_single_frame(
            &mut Cursor::new(frame_with_magic(&value, CONNECTION_TEST_FRAME_MAGIC)),
            CONNECTION_TEST_FRAME_MAGIC,
        )
        .expect("framed request");
        let parsed = serde_json::from_slice::<ConnectionTestRequest>(&body);
        body.zeroize();
        assert!(parsed.is_err());
    }

    #[test]
    fn fixed_payload_is_durable_and_deduplicated_by_exact_approval() {
        let root = TempDir::new().expect("temp directory");
        let now = unix_time().expect("clock");
        let batch = validate_request(request(now), now).expect("valid request");
        let path = root.path().join(OUTBOX_FILENAME);
        let mut transport = AcceptedTransport { calls: 0 };
        let first = dispatch_with_transport(batch, &path, now, &mut transport).expect("dispatch");
        assert_eq!(first.enqueued, 1);
        assert_eq!(first.delivered, 1);

        let later = now + 1;
        let batch = validate_request(request(now), later).expect("valid later retry");
        let second =
            dispatch_with_transport(batch, &path, later, &mut transport).expect("later retry");
        assert_eq!(second.existing, 1);
        assert_eq!(second.delivered, 1);
        assert_eq!(transport.calls, 1);
    }

    #[test]
    fn request_schema_is_exact_and_never_accepts_interaction_fields() {
        let now = unix_time().expect("clock");
        let value = json!({
            "schema_version": 1,
            "approval_id": format!("action:sha256:{}", "b".repeat(64)),
            "received_at": now,
            "expires_at": now + 120,
            "outbox_key_hex": "22".repeat(32),
            "channels": [{
                "channel": "SLACK",
                "destination": "C12345678",
                "access_token": "fixture-slack-access-token-00000000",
                "callback_url": "https://example.invalid/approve"
            }]
        });
        let root = TempDir::new().expect("temp directory");
        assert_eq!(
            serve_review_notification_request(Cursor::new(frame(&value)), root.path()),
            Err(NotificationRequestError::InvalidRequest)
        );
    }

    #[test]
    fn retry_report_is_exact_and_provider_tokens_can_rotate() {
        let root = TempDir::new().expect("temp directory");
        let now = unix_time().expect("clock");
        let path = root.path().join(OUTBOX_FILENAME);
        let batch = validate_request(request(now), now).expect("valid request");
        let report = dispatch_with_transport(batch, &path, now, &mut NotSentTransport)
            .expect("retry is durable");
        assert_eq!(report.retry_scheduled, 1);
        assert!(report.next_retry_at.is_some_and(|retry| retry < now + 120));

        let mut rotated = request(now);
        let NotificationChannelConfiguration::Slack { access_token, .. } = &mut rotated.channels[0]
        else {
            panic!("slack fixture")
        };
        *access_token = "fixture-rotated-slack-token-00000000".to_owned();
        let batch = validate_request(rotated, now).expect("rotated token remains valid");
        let report = dispatch_with_transport(batch, &path, now, &mut NotSentTransport)
            .expect("token rotation keeps the stable binding");
        assert_eq!(report.existing, 1);
        assert_eq!(report.retry_scheduled, 1);
    }

    #[test]
    fn non_secret_provider_substitution_conflicts_with_the_approval_binding() {
        let root = TempDir::new().expect("temp directory");
        let now = unix_time().expect("clock");
        let path = root.path().join(OUTBOX_FILENAME);
        let batch = validate_request(request(now), now).expect("valid request");
        dispatch_with_transport(batch, &path, now, &mut NotSentTransport).expect("first dispatch");

        let mut substituted = request(now);
        let NotificationChannelConfiguration::Slack { destination, .. } =
            &mut substituted.channels[0]
        else {
            panic!("slack fixture")
        };
        *destination = "C87654321".to_owned();
        let batch = validate_request(substituted, now).expect("shape remains valid");
        assert_eq!(
            dispatch_with_transport(batch, &path, now, &mut NotSentTransport),
            Err(NotificationRequestError::StorageUnavailable)
        );
    }

    #[test]
    fn framing_rejects_trailing_bytes_and_expired_requests() {
        let now = unix_time().expect("clock");
        let mut value = serde_json::to_value(request(now)).unwrap_or_else(|_| json!({}));
        value["expires_at"] = json!(now - 1);
        let root = TempDir::new().expect("temp directory");
        assert_eq!(
            serve_review_notification_request(Cursor::new(frame(&value)), root.path()),
            Err(NotificationRequestError::Expired)
        );

        let mut bytes = frame(&json!({}));
        bytes.push(0);
        assert_eq!(
            serve_review_notification_request(Cursor::new(bytes), root.path()),
            Err(NotificationRequestError::InvalidFrame)
        );
    }

    #[test]
    fn report_and_errors_never_render_credentials() {
        let report = NotificationDispatchReport::new(1).expect("report");
        let report_text = serde_json::to_string(&report).expect("report JSON");
        assert!(!report_text.contains("token"));
        for error in [
            NotificationRequestError::InvalidFrame,
            NotificationRequestError::RequestTooLarge,
            NotificationRequestError::InvalidRequest,
            NotificationRequestError::Expired,
            NotificationRequestError::StorageUnavailable,
            NotificationRequestError::TransportUnavailable,
            NotificationRequestError::Input,
        ] {
            assert!(!error.to_string().contains("fixture-"));
        }
    }
}
