//! Provider-specific outbound request preparation and response classification.
//!
//! Request construction and provider classification are independent of the
//! HTTPS implementation. The crate also exports a fixed-authority rustls
//! transport; hosts can inject another implementation for tests or controlled
//! deployment profiles. No implementation owns an account or persists a
//! credential.

use std::fmt;
use std::time::Duration;

use accordlock_protocol::Digest32;
use serde_json::Value;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    ApprovalChannel, ChannelDelivery, ConnectionTestPrompt, DeliveryPayloadKind,
    ReviewNotificationPrompt, parse_unambiguous_json,
};

pub const MAX_DELIVERY_CREDENTIAL_BYTES: usize = 4 * 1_024;
pub const MAX_DELIVERY_ENDPOINT_BYTES: usize = 2 * 1_024;
pub const MAX_DELIVERY_REQUEST_BODY_BYTES: usize = 64 * 1_024;
pub const MAX_DELIVERY_RESPONSE_BODY_BYTES: usize = 64 * 1_024;
pub const MAX_DELIVERY_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_RETRY_AFTER_SECONDS: u32 = 60 * 60;

const MIN_DELIVERY_CREDENTIAL_BYTES: usize = 16;
const MIN_DELIVERY_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_RESPONSE_BODY_BYTES: usize = 32 * 1_024;
const DEFAULT_DELIVERY_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_CONNECT_RETRY_SECONDS: u32 = 5;
const DEFAULT_RATE_LIMIT_RETRY_SECONDS: u32 = 60;

const SLACK_ENDPOINT: &str = "https://slack.com/api/chat.postMessage";
const TELEGRAM_ENDPOINT_PREFIX: &str = "https://api.telegram.org/bot";
const TELEGRAM_ENDPOINT_SUFFIX: &str = "/sendMessage";
const WHATSAPP_ENDPOINT_PREFIX: &str = "https://graph.facebook.com/";
const TEAMS_ENDPOINT_PREFIX: &str = "https://smba.trafficmanager.net/";
const USER_AGENT: &str = "AccordLock/0.1 outbound-adapter";

/// An in-memory provider credential.
///
/// The value is moved into a zeroizing allocation, cannot be cloned or
/// serialized, and is always redacted from `Debug`. The host should load it
/// from an operating-system credential store immediately before dispatch.
pub struct DeliveryCredential {
    channel: ApprovalChannel,
    secret: Zeroizing<String>,
}

impl DeliveryCredential {
    /// Creates a Slack Web API bearer credential.
    ///
    /// # Errors
    ///
    /// Rejects empty, overlong, whitespace-bearing, or control-bearing values.
    pub fn slack(secret: String) -> Result<Self, DeliveryTransportError> {
        Self::new(ApprovalChannel::Slack, secret)
    }

    /// Creates a Telegram bot token.
    ///
    /// # Errors
    ///
    /// Rejects values outside the documented numeric-ID and token alphabet.
    pub fn telegram(secret: String) -> Result<Self, DeliveryTransportError> {
        let secret = Zeroizing::new(secret);
        validate_telegram_token(secret.as_str())?;
        validate_credential(secret.as_str())?;
        Ok(Self {
            channel: ApprovalChannel::Telegram,
            secret,
        })
    }

    /// Creates a `WhatsApp` Cloud API bearer credential.
    ///
    /// # Errors
    ///
    /// Rejects empty, overlong, whitespace-bearing, or control-bearing values.
    pub fn whatsapp_cloud(secret: String) -> Result<Self, DeliveryTransportError> {
        Self::new(ApprovalChannel::WhatsApp, secret)
    }

    /// Creates a Microsoft Bot Framework bearer credential for Teams.
    ///
    /// # Errors
    ///
    /// Rejects empty, overlong, whitespace-bearing, or control-bearing values.
    pub fn teams_bot(secret: String) -> Result<Self, DeliveryTransportError> {
        Self::new(ApprovalChannel::MicrosoftTeams, secret)
    }

    fn new(channel: ApprovalChannel, secret: String) -> Result<Self, DeliveryTransportError> {
        let secret = Zeroizing::new(secret);
        validate_credential(secret.as_str())?;
        Ok(Self { channel, secret })
    }

    fn expose(&self) -> &str {
        self.secret.as_str()
    }
}

impl fmt::Debug for DeliveryCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliveryCredential")
            .field("channel", &self.channel)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

enum EndpointKind {
    Slack,
    Telegram,
    WhatsAppCloud {
        api_version: String,
        phone_number_id: String,
    },
    TeamsBotPublic {
        service_url: String,
    },
}

/// Strict provider endpoint configuration without credentials.
///
/// Hosts cannot supply an arbitrary authority. Slack, Telegram, and `WhatsApp`
/// use fixed official authorities. The Teams adapter is limited to the public
/// Bot Framework authority and an exact, validated public-cloud service URL.
pub struct DeliveryEndpointConfig {
    kind: EndpointKind,
}

impl DeliveryEndpointConfig {
    #[must_use]
    pub const fn slack() -> Self {
        Self {
            kind: EndpointKind::Slack,
        }
    }

    #[must_use]
    pub const fn telegram() -> Self {
        Self {
            kind: EndpointKind::Telegram,
        }
    }

    /// Configures the versioned `WhatsApp` Cloud API messages endpoint.
    ///
    /// # Errors
    ///
    /// Rejects malformed API versions and phone-number identifiers.
    pub fn whatsapp_cloud(
        api_version: impl Into<String>,
        phone_number_id: impl Into<String>,
    ) -> Result<Self, DeliveryTransportError> {
        let api_version = api_version.into();
        let phone_number_id = phone_number_id.into();
        validate_graph_version(&api_version)?;
        validate_ascii_digits(&phone_number_id, 5, 32)?;
        Ok(Self {
            kind: EndpointKind::WhatsAppCloud {
                api_version,
                phone_number_id,
            },
        })
    }

    /// Configures a commercial Teams Bot Framework service URL.
    ///
    /// `service_url` must be copied from the authenticated Teams conversation
    /// reference. Only the public `smba.trafficmanager.net` authority is
    /// accepted; sovereign-cloud authorities require a separate profile.
    ///
    /// # Errors
    ///
    /// Rejects a different authority, query or fragment data, dot segments,
    /// escapes, control characters, or an overlong path.
    pub fn teams_bot_public(
        service_url: impl Into<String>,
    ) -> Result<Self, DeliveryTransportError> {
        let service_url = service_url.into();
        validate_teams_service_url(&service_url)?;
        Ok(Self {
            kind: EndpointKind::TeamsBotPublic { service_url },
        })
    }

    const fn channel(&self) -> ApprovalChannel {
        match self.kind {
            EndpointKind::Slack => ApprovalChannel::Slack,
            EndpointKind::Telegram => ApprovalChannel::Telegram,
            EndpointKind::WhatsAppCloud { .. } => ApprovalChannel::WhatsApp,
            EndpointKind::TeamsBotPublic { .. } => ApprovalChannel::MicrosoftTeams,
        }
    }
}

impl fmt::Debug for DeliveryEndpointConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliveryEndpointConfig")
            .field("channel", &self.channel())
            .field("account_routing", &"[REDACTED]")
            .finish()
    }
}

/// Per-request bounds that a host transport must enforce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliveryLimits {
    request_timeout: Duration,
    max_response_body_bytes: usize,
}

impl DeliveryLimits {
    /// Creates enforceable timeout and response-size limits.
    ///
    /// # Errors
    ///
    /// Rejects limits outside the crate's closed safety bounds.
    pub fn new(
        request_timeout: Duration,
        max_response_body_bytes: usize,
    ) -> Result<Self, DeliveryTransportError> {
        if !(MIN_DELIVERY_TIMEOUT..=MAX_DELIVERY_TIMEOUT).contains(&request_timeout)
            || !(1..=MAX_DELIVERY_RESPONSE_BODY_BYTES).contains(&max_response_body_bytes)
        {
            return Err(DeliveryTransportError::InvalidInput);
        }
        Ok(Self {
            request_timeout,
            max_response_body_bytes,
        })
    }

    #[must_use]
    pub const fn request_timeout(self) -> Duration {
        self.request_timeout
    }

    #[must_use]
    pub const fn max_response_body_bytes(self) -> usize {
        self.max_response_body_bytes
    }
}

impl Default for DeliveryLimits {
    fn default() -> Self {
        Self {
            request_timeout: DEFAULT_DELIVERY_TIMEOUT,
            max_response_body_bytes: DEFAULT_RESPONSE_BODY_BYTES,
        }
    }
}

/// One request header. Values are redacted from `Debug` and zeroized on drop.
pub struct RequestHeader {
    name: &'static str,
    value: Zeroizing<String>,
}

impl RequestHeader {
    fn new(name: &'static str, value: String) -> Self {
        Self {
            name,
            value: Zeroizing::new(value),
        }
    }

    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Exposes the value only to the host HTTPS implementation.
    #[must_use]
    pub fn expose_value(&self) -> &str {
        self.value.as_str()
    }
}

impl fmt::Debug for RequestHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestHeader")
            .field("name", &self.name)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// A fully prepared, bounded HTTPS `POST` request.
///
/// The endpoint is redacted because Telegram places its bot token in the URL.
/// The body and every header value are also redacted. A transport must not
/// follow redirects or copy these values into logs.
pub struct PreparedHttpsRequest {
    channel: ApprovalChannel,
    endpoint: Zeroizing<String>,
    headers: Vec<RequestHeader>,
    body: Zeroizing<Vec<u8>>,
    body_hash: Digest32,
    limits: DeliveryLimits,
}

impl PreparedHttpsRequest {
    #[must_use]
    pub const fn channel(&self) -> ApprovalChannel {
        self.channel
    }

    #[must_use]
    pub const fn method(&self) -> &'static str {
        "POST"
    }

    /// Exposes the exact HTTPS URL only to the host transport.
    #[must_use]
    pub fn expose_endpoint(&self) -> &str {
        self.endpoint.as_str()
    }

    #[must_use]
    pub fn headers(&self) -> &[RequestHeader] {
        &self.headers
    }

    /// Exposes the exact provider payload only to the host transport.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        self.body.as_slice()
    }

    #[must_use]
    pub const fn body_hash(&self) -> Digest32 {
        self.body_hash
    }

    #[must_use]
    pub const fn limits(&self) -> DeliveryLimits {
        self.limits
    }
}

impl fmt::Debug for PreparedHttpsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedHttpsRequest")
            .field("channel", &self.channel)
            .field("method", &self.method())
            .field("endpoint", &"[REDACTED]")
            .field(
                "header_names",
                &self
                    .headers
                    .iter()
                    .map(RequestHeader::name)
                    .collect::<Vec<_>>(),
            )
            .field("body", &"[REDACTED]")
            .field("body_bytes", &self.body.len())
            .field("body_hash", &self.body_hash)
            .field("limits", &self.limits)
            .finish()
    }
}

/// A bounded response collected by a host HTTPS transport.
pub struct OutboundHttpsResponse {
    status_code: u16,
    retry_after: Option<Zeroizing<String>>,
    body: Zeroizing<Vec<u8>>,
}

impl OutboundHttpsResponse {
    /// Creates a provider response already bounded by the host transport.
    ///
    /// # Errors
    ///
    /// Rejects invalid status codes, oversized bodies, and malformed bounded
    /// `Retry-After` values.
    pub fn new(
        status_code: u16,
        retry_after: Option<String>,
        body: Vec<u8>,
    ) -> Result<Self, DeliveryTransportError> {
        let retry_after = retry_after.map(Zeroizing::new);
        let body = Zeroizing::new(body);
        if !(100..=599).contains(&status_code)
            || body.len() > MAX_DELIVERY_RESPONSE_BODY_BYTES
            || retry_after.as_deref().is_some_and(|value| {
                value.is_empty()
                    || value.len() > 64
                    || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
            })
        {
            return Err(DeliveryTransportError::InvalidInput);
        }
        Ok(Self {
            status_code,
            retry_after,
            body,
        })
    }

    #[must_use]
    pub const fn status_code(&self) -> u16 {
        self.status_code
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        self.body.as_slice()
    }
}

impl fmt::Debug for OutboundHttpsResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundHttpsResponse")
            .field("status_code", &self.status_code)
            .field(
                "retry_after",
                &self.retry_after.as_ref().map(|_| "[REDACTED]"),
            )
            .field("body", &"[REDACTED]")
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

/// Whether provider request bytes might have crossed the transport boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpsRequestProgress {
    NotSent,
    MayHaveBeenSent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpsTransportFailureKind {
    NameResolution,
    Connect,
    Tls,
    Timeout,
    Protocol,
    ResponseTooLarge,
}

/// A secret-free transport failure with explicit delivery ambiguity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpsTransportFailure {
    kind: HttpsTransportFailureKind,
    progress: HttpsRequestProgress,
}

impl HttpsTransportFailure {
    #[must_use]
    pub const fn new(kind: HttpsTransportFailureKind, progress: HttpsRequestProgress) -> Self {
        Self { kind, progress }
    }

    #[must_use]
    pub const fn kind(self) -> HttpsTransportFailureKind {
        self.kind
    }

    #[must_use]
    pub const fn progress(self) -> HttpsRequestProgress {
        self.progress
    }
}

/// HTTPS delivery boundary.
///
/// Implementations must verify the exact endpoint's TLS identity, reject
/// redirects and proxies, honor `request.limits()`, collect no more than the
/// allowed response bytes, and avoid request logging. The bundled
/// [`crate::WebPkiHttpsTransport`] is the default public-provider profile.
pub trait BoundedHttpsTransport {
    /// Sends exactly one request without following redirects or retrying.
    ///
    /// # Errors
    ///
    /// Returns a secret-free failure that states whether request bytes may
    /// have crossed the transport boundary.
    fn send(
        &mut self,
        request: &PreparedHttpsRequest,
    ) -> Result<OutboundHttpsResponse, HttpsTransportFailure>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryDisposition {
    Accepted,
    Retryable,
    PermanentFailure,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryReason {
    ProviderAccepted,
    RateLimited,
    ProviderRejected,
    ProviderUnavailable,
    MalformedProviderResponse,
    ResponseTooLarge,
    TransportNotSent,
    TransportOutcomeUnknown,
}

/// Secret-free result suitable for audit and bounded retry scheduling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliveryAttempt {
    channel: ApprovalChannel,
    disposition: DeliveryDisposition,
    reason: DeliveryReason,
    status_code: Option<u16>,
    retry_after_seconds: Option<u32>,
    response_body_hash: Option<Digest32>,
    response_body_bytes: usize,
}

impl DeliveryAttempt {
    #[must_use]
    pub const fn channel(self) -> ApprovalChannel {
        self.channel
    }

    #[must_use]
    pub const fn disposition(self) -> DeliveryDisposition {
        self.disposition
    }

    #[must_use]
    pub const fn reason(self) -> DeliveryReason {
        self.reason
    }

    #[must_use]
    pub const fn status_code(self) -> Option<u16> {
        self.status_code
    }

    #[must_use]
    pub const fn retry_after_seconds(self) -> Option<u32> {
        self.retry_after_seconds
    }

    #[must_use]
    pub const fn response_body_hash(self) -> Option<Digest32> {
        self.response_body_hash
    }

    #[must_use]
    pub const fn response_body_bytes(self) -> usize {
        self.response_body_bytes
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum DeliveryTransportError {
    #[error("delivery transport input is outside accepted bounds")]
    InvalidInput,
    #[error("delivery channel, endpoint, or credential does not match")]
    ChannelMismatch,
    #[error("delivery payload does not match its bound metadata")]
    PayloadMismatch,
    #[error("provider credential would be exposed in the request body")]
    CredentialExposure,
    #[error("delivery request encoding failed")]
    Encoding,
}

/// Prepares one strict provider request without performing I/O.
///
/// # Errors
///
/// Rejects channel substitution, malformed endpoint configuration,
/// destination or payload mismatch, credential exposure, and size violations.
pub fn prepare_channel_delivery(
    delivery: &ChannelDelivery,
    endpoint: &DeliveryEndpointConfig,
    credential: &DeliveryCredential,
    limits: DeliveryLimits,
) -> Result<PreparedHttpsRequest, DeliveryTransportError> {
    if delivery.channel != endpoint.channel() || delivery.channel != credential.channel {
        return Err(DeliveryTransportError::ChannelMismatch);
    }
    if value_contains_text(&delivery.body, credential.expose()) {
        return Err(DeliveryTransportError::CredentialExposure);
    }
    let body = Zeroizing::new(validate_and_encode_delivery(delivery)?);
    if contains_bytes(body.as_slice(), credential.expose().as_bytes()) {
        return Err(DeliveryTransportError::CredentialExposure);
    }

    let mut headers = vec![
        RequestHeader::new("accept", "application/json".to_owned()),
        RequestHeader::new("content-type", "application/json".to_owned()),
        RequestHeader::new("user-agent", USER_AGENT.to_owned()),
    ];
    let url = match &endpoint.kind {
        EndpointKind::Slack => {
            validate_slack_destination(&delivery.destination)?;
            headers.push(bearer_header(credential.expose()));
            SLACK_ENDPOINT.to_owned()
        }
        EndpointKind::Telegram => {
            validate_telegram_destination(&delivery.destination)?;
            format!(
                "{TELEGRAM_ENDPOINT_PREFIX}{}{TELEGRAM_ENDPOINT_SUFFIX}",
                credential.expose()
            )
        }
        EndpointKind::WhatsAppCloud {
            api_version,
            phone_number_id,
        } => {
            validate_whatsapp_destination(&delivery.destination)?;
            headers.push(bearer_header(credential.expose()));
            format!("{WHATSAPP_ENDPOINT_PREFIX}{api_version}/{phone_number_id}/messages")
        }
        EndpointKind::TeamsBotPublic { service_url } => {
            validate_teams_destination(&delivery.destination)?;
            headers.push(bearer_header(credential.expose()));
            format!(
                "{service_url}v3/conversations/{}/activities",
                percent_encode_path_segment(&delivery.destination)
            )
        }
    };
    if url.len() > MAX_DELIVERY_ENDPOINT_BYTES {
        return Err(DeliveryTransportError::InvalidInput);
    }
    let body_hash = Digest32::sha256(body.as_slice());
    Ok(PreparedHttpsRequest {
        channel: delivery.channel,
        endpoint: Zeroizing::new(url),
        headers,
        body,
        body_hash,
        limits,
    })
}

/// Prepares, sends, and classifies one provider delivery through an injected
/// transport. No automatic retry is performed here.
///
/// # Errors
///
/// Returns the same preparation errors as [`prepare_channel_delivery`].
/// Transport failures are classified in the returned [`DeliveryAttempt`].
pub fn dispatch_channel_delivery<T: BoundedHttpsTransport + ?Sized>(
    delivery: &ChannelDelivery,
    endpoint: &DeliveryEndpointConfig,
    credential: &DeliveryCredential,
    limits: DeliveryLimits,
    transport: &mut T,
) -> Result<DeliveryAttempt, DeliveryTransportError> {
    let request = prepare_channel_delivery(delivery, endpoint, credential, limits)?;
    match transport.send(&request) {
        Ok(response) => {
            if response.body.len() > limits.max_response_body_bytes {
                return Ok(attempt(
                    delivery.channel,
                    DeliveryDisposition::Ambiguous,
                    DeliveryReason::ResponseTooLarge,
                    Some(response.status_code),
                    None,
                    Some(Digest32::sha256(response.body())),
                    response.body.len(),
                ));
            }
            Ok(classify_response(delivery.channel, &response))
        }
        Err(failure) => Ok(classify_transport_failure(delivery.channel, failure)),
    }
}

pub(crate) fn validate_and_encode_delivery(
    delivery: &ChannelDelivery,
) -> Result<Vec<u8>, DeliveryTransportError> {
    if delivery.media_type != "application/json" {
        return Err(DeliveryTransportError::PayloadMismatch);
    }
    let valid_shape = match delivery.payload_kind {
        DeliveryPayloadKind::InteractiveApproval => validate_interactive_delivery_shape(delivery),
        DeliveryPayloadKind::ReviewNotification => validate_review_notification_shape(delivery),
        DeliveryPayloadKind::ConnectionTest => validate_connection_test_shape(delivery),
    };
    if !valid_shape {
        return Err(DeliveryTransportError::PayloadMismatch);
    }
    let body = serde_json::to_vec(&delivery.body).map_err(|_| DeliveryTransportError::Encoding)?;
    if body.is_empty()
        || body.len() > MAX_DELIVERY_REQUEST_BODY_BYTES
        || Digest32::sha256(&body) != delivery.body_hash
    {
        return Err(DeliveryTransportError::PayloadMismatch);
    }
    Ok(body)
}

fn validate_interactive_delivery_shape(delivery: &ChannelDelivery) -> bool {
    let Some(object) = delivery.body.as_object() else {
        return false;
    };
    match delivery.channel {
        ApprovalChannel::Slack => {
            exact_keys(object, &["blocks", "channel", "text"])
                && delivery.body.get("channel").and_then(Value::as_str)
                    == Some(delivery.destination.as_str())
                && delivery
                    .body
                    .get("blocks")
                    .and_then(Value::as_array)
                    .is_some_and(|v| !v.is_empty())
        }
        ApprovalChannel::Telegram => {
            exact_keys(object, &["chat_id", "reply_markup", "text"])
                && delivery.body.get("chat_id").and_then(Value::as_str)
                    == Some(delivery.destination.as_str())
                && delivery
                    .body
                    .get("reply_markup")
                    .is_some_and(Value::is_object)
        }
        ApprovalChannel::WhatsApp => {
            exact_keys(object, &["interactive", "messaging_product", "to", "type"])
                && delivery
                    .body
                    .get("messaging_product")
                    .and_then(Value::as_str)
                    == Some("whatsapp")
                && delivery.body.get("to").and_then(Value::as_str)
                    == Some(delivery.destination.as_str())
                && delivery.body.get("type").and_then(Value::as_str) == Some("interactive")
                && delivery
                    .body
                    .get("interactive")
                    .is_some_and(Value::is_object)
        }
        ApprovalChannel::MicrosoftTeams => {
            exact_keys(object, &["attachments", "type"])
                && delivery.body.get("type").and_then(Value::as_str) == Some("message")
                && delivery
                    .body
                    .get("attachments")
                    .and_then(Value::as_array)
                    .is_some_and(|v| !v.is_empty())
        }
    }
}

fn validate_review_notification_shape(delivery: &ChannelDelivery) -> bool {
    let prompt = ReviewNotificationPrompt::new();
    validate_fixed_notification_shape(
        delivery,
        prompt.title(),
        prompt.message(),
        prompt.plain_text(),
    )
}

fn validate_connection_test_shape(delivery: &ChannelDelivery) -> bool {
    let prompt = ConnectionTestPrompt::new();
    validate_fixed_notification_shape(
        delivery,
        prompt.title(),
        prompt.message(),
        prompt.plain_text(),
    )
}

fn validate_fixed_notification_shape(
    delivery: &ChannelDelivery,
    title: &str,
    message: &str,
    plain_text: &str,
) -> bool {
    let Some(object) = delivery.body.as_object() else {
        return false;
    };
    match delivery.channel {
        ApprovalChannel::Slack => {
            if !exact_keys(object, &["blocks", "channel", "text"])
                || string_field(object, "channel") != Some(delivery.destination.as_str())
                || string_field(object, "text") != Some(plain_text)
            {
                return false;
            }
            let Some(blocks) = object.get("blocks").and_then(Value::as_array) else {
                return false;
            };
            blocks.len() == 2
                && exact_slack_text_block(&blocks[0], "header", title)
                && exact_slack_text_block(&blocks[1], "section", message)
        }
        ApprovalChannel::MicrosoftTeams => {
            exact_keys(object, &["text", "type"])
                && string_field(object, "type") == Some("message")
                && string_field(object, "text") == Some(plain_text)
        }
        ApprovalChannel::Telegram => {
            exact_keys(object, &["chat_id", "text"])
                && string_field(object, "chat_id") == Some(delivery.destination.as_str())
                && string_field(object, "text") == Some(plain_text)
        }
        ApprovalChannel::WhatsApp => {
            if !exact_keys(object, &["messaging_product", "text", "to", "type"])
                || string_field(object, "messaging_product") != Some("whatsapp")
                || string_field(object, "to") != Some(delivery.destination.as_str())
                || string_field(object, "type") != Some("text")
            {
                return false;
            }
            object
                .get("text")
                .and_then(Value::as_object)
                .is_some_and(|text| {
                    exact_keys(text, &["body"]) && string_field(text, "body") == Some(plain_text)
                })
        }
    }
}

fn exact_slack_text_block(value: &Value, block_type: &str, expected_text: &str) -> bool {
    let Some(block) = value.as_object() else {
        return false;
    };
    if !exact_keys(block, &["text", "type"]) || string_field(block, "type") != Some(block_type) {
        return false;
    }
    block
        .get("text")
        .and_then(Value::as_object)
        .is_some_and(|text| {
            exact_keys(text, &["text", "type"])
                && string_field(text, "type") == Some("plain_text")
                && string_field(text, "text") == Some(expected_text)
        })
}

fn string_field<'a>(object: &'a serde_json::Map<String, Value>, field: &str) -> Option<&'a str> {
    object.get(field).and_then(Value::as_str)
}

fn exact_keys(object: &serde_json::Map<String, Value>, expected: &[&str]) -> bool {
    object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
}

fn bearer_header(secret: &str) -> RequestHeader {
    RequestHeader::new("authorization", format!("Bearer {secret}"))
}

fn classify_response(
    channel: ApprovalChannel,
    response: &OutboundHttpsResponse,
) -> DeliveryAttempt {
    let body_hash = (!response.body.is_empty()).then(|| Digest32::sha256(response.body()));
    let status = response.status_code;
    if status == 429 {
        return attempt(
            channel,
            DeliveryDisposition::Retryable,
            DeliveryReason::RateLimited,
            Some(status),
            Some(retry_after_seconds(response)),
            body_hash,
            response.body.len(),
        );
    }
    if status == 408 || status == 425 || status >= 500 {
        return attempt(
            channel,
            DeliveryDisposition::Ambiguous,
            DeliveryReason::ProviderUnavailable,
            Some(status),
            None,
            body_hash,
            response.body.len(),
        );
    }
    if !(200..300).contains(&status) {
        return attempt(
            channel,
            DeliveryDisposition::PermanentFailure,
            DeliveryReason::ProviderRejected,
            Some(status),
            None,
            body_hash,
            response.body.len(),
        );
    }

    let Ok(value) = parse_unambiguous_json(response.body()) else {
        return attempt(
            channel,
            DeliveryDisposition::Ambiguous,
            DeliveryReason::MalformedProviderResponse,
            Some(status),
            None,
            body_hash,
            response.body.len(),
        );
    };
    let provider_result = match channel {
        ApprovalChannel::Slack => classify_slack_body(&value),
        ApprovalChannel::Telegram => classify_telegram_body(&value),
        ApprovalChannel::WhatsApp => classify_whatsapp_body(&value),
        ApprovalChannel::MicrosoftTeams => classify_teams_body(&value),
    };
    match provider_result {
        ProviderResult::Accepted => attempt(
            channel,
            DeliveryDisposition::Accepted,
            DeliveryReason::ProviderAccepted,
            Some(status),
            None,
            body_hash,
            response.body.len(),
        ),
        ProviderResult::RateLimited(delay) => attempt(
            channel,
            DeliveryDisposition::Retryable,
            DeliveryReason::RateLimited,
            Some(status),
            Some(delay.unwrap_or_else(|| retry_after_seconds(response))),
            body_hash,
            response.body.len(),
        ),
        ProviderResult::Rejected => attempt(
            channel,
            DeliveryDisposition::PermanentFailure,
            DeliveryReason::ProviderRejected,
            Some(status),
            None,
            body_hash,
            response.body.len(),
        ),
        ProviderResult::Transient | ProviderResult::Malformed => attempt(
            channel,
            DeliveryDisposition::Ambiguous,
            if provider_result == ProviderResult::Transient {
                DeliveryReason::ProviderUnavailable
            } else {
                DeliveryReason::MalformedProviderResponse
            },
            Some(status),
            None,
            body_hash,
            response.body.len(),
        ),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProviderResult {
    Accepted,
    RateLimited(Option<u32>),
    Rejected,
    Transient,
    Malformed,
}

fn classify_slack_body(value: &Value) -> ProviderResult {
    match value.get("ok").and_then(Value::as_bool) {
        Some(true) => {
            if bounded_nonempty_string(value.get("ts"), 128) {
                ProviderResult::Accepted
            } else {
                ProviderResult::Malformed
            }
        }
        Some(false) => match value.get("error").and_then(Value::as_str) {
            Some("ratelimited") => ProviderResult::RateLimited(None),
            Some("internal_error" | "fatal_error" | "service_unavailable" | "request_timeout") => {
                ProviderResult::Transient
            }
            Some(error) if valid_response_identifier(error, 128) => ProviderResult::Rejected,
            _ => ProviderResult::Malformed,
        },
        None => ProviderResult::Malformed,
    }
}

fn classify_telegram_body(value: &Value) -> ProviderResult {
    match value.get("ok").and_then(Value::as_bool) {
        Some(true) => {
            if value
                .get("result")
                .and_then(|result| result.get("message_id"))
                .and_then(Value::as_i64)
                .is_some_and(|id| id > 0)
            {
                ProviderResult::Accepted
            } else {
                ProviderResult::Malformed
            }
        }
        Some(false) => {
            let Some(code) = value.get("error_code").and_then(Value::as_u64) else {
                return ProviderResult::Malformed;
            };
            if code == 429 {
                let delay = value
                    .get("parameters")
                    .and_then(|parameters| parameters.get("retry_after"))
                    .and_then(Value::as_u64)
                    .and_then(|seconds| u32::try_from(seconds).ok())
                    .map(|seconds| seconds.min(MAX_RETRY_AFTER_SECONDS));
                ProviderResult::RateLimited(delay)
            } else if code >= 500 {
                ProviderResult::Transient
            } else if (400..500).contains(&code) {
                ProviderResult::Rejected
            } else {
                ProviderResult::Malformed
            }
        }
        None => ProviderResult::Malformed,
    }
}

fn classify_whatsapp_body(value: &Value) -> ProviderResult {
    if value.get("error").is_some() {
        return ProviderResult::Rejected;
    }
    if value
        .get("messages")
        .and_then(Value::as_array)
        .and_then(|messages| messages.first())
        .and_then(|message| message.get("id"))
        .is_some_and(|id| bounded_nonempty_string(Some(id), 512))
    {
        ProviderResult::Accepted
    } else {
        ProviderResult::Malformed
    }
}

fn classify_teams_body(value: &Value) -> ProviderResult {
    if bounded_nonempty_string(value.get("id"), 512) {
        ProviderResult::Accepted
    } else {
        ProviderResult::Malformed
    }
}

fn bounded_nonempty_string(value: Option<&Value>, max: usize) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|value| valid_response_identifier(value, max))
}

fn valid_response_identifier(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

fn retry_after_seconds(response: &OutboundHttpsResponse) -> u32 {
    response
        .retry_after
        .as_deref()
        .and_then(|value| value.parse::<u64>().ok())
        .and_then(|value| u32::try_from(value).ok())
        .map_or(DEFAULT_RATE_LIMIT_RETRY_SECONDS, |value| {
            value.clamp(1, MAX_RETRY_AFTER_SECONDS)
        })
}

fn classify_transport_failure(
    channel: ApprovalChannel,
    failure: HttpsTransportFailure,
) -> DeliveryAttempt {
    match failure.progress {
        HttpsRequestProgress::NotSent => attempt(
            channel,
            DeliveryDisposition::Retryable,
            DeliveryReason::TransportNotSent,
            None,
            Some(DEFAULT_CONNECT_RETRY_SECONDS),
            None,
            0,
        ),
        HttpsRequestProgress::MayHaveBeenSent => attempt(
            channel,
            DeliveryDisposition::Ambiguous,
            DeliveryReason::TransportOutcomeUnknown,
            None,
            None,
            None,
            0,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
const fn attempt(
    channel: ApprovalChannel,
    disposition: DeliveryDisposition,
    reason: DeliveryReason,
    status_code: Option<u16>,
    retry_after_seconds: Option<u32>,
    response_body_hash: Option<Digest32>,
    response_body_bytes: usize,
) -> DeliveryAttempt {
    DeliveryAttempt {
        channel,
        disposition,
        reason,
        status_code,
        retry_after_seconds,
        response_body_hash,
        response_body_bytes,
    }
}

fn validate_credential(secret: &str) -> Result<(), DeliveryTransportError> {
    if !(MIN_DELIVERY_CREDENTIAL_BYTES..=MAX_DELIVERY_CREDENTIAL_BYTES).contains(&secret.len())
        || !secret.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err(DeliveryTransportError::InvalidInput);
    }
    Ok(())
}

fn validate_telegram_token(secret: &str) -> Result<(), DeliveryTransportError> {
    let Some((bot_id, token)) = secret.split_once(':') else {
        return Err(DeliveryTransportError::InvalidInput);
    };
    if !(5..=20).contains(&bot_id.len())
        || !bot_id.bytes().all(|byte| byte.is_ascii_digit())
        || !(16..=192).contains(&token.len())
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(DeliveryTransportError::InvalidInput);
    }
    Ok(())
}

fn validate_graph_version(value: &str) -> Result<(), DeliveryTransportError> {
    let Some(version) = value.strip_prefix('v') else {
        return Err(DeliveryTransportError::InvalidInput);
    };
    let Some((major, minor)) = version.split_once('.') else {
        return Err(DeliveryTransportError::InvalidInput);
    };
    if !(1..=3).contains(&major.len())
        || !(1..=2).contains(&minor.len())
        || !major.bytes().all(|byte| byte.is_ascii_digit())
        || !minor.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(DeliveryTransportError::InvalidInput);
    }
    Ok(())
}

fn validate_teams_service_url(value: &str) -> Result<(), DeliveryTransportError> {
    let Some(path) = value.strip_prefix(TEAMS_ENDPOINT_PREFIX) else {
        return Err(DeliveryTransportError::InvalidInput);
    };
    let Some(service_path) = path.strip_suffix('/') else {
        return Err(DeliveryTransportError::InvalidInput);
    };
    if value.len() > MAX_DELIVERY_ENDPOINT_BYTES
        || service_path.is_empty()
        || path.contains(['?', '#', '\\', '%'])
        || service_path.split('/').any(|segment| {
            segment.is_empty()
                || segment == "."
                || segment == ".."
                || segment.len() > 128
                || !segment.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
                })
        })
    {
        return Err(DeliveryTransportError::InvalidInput);
    }
    Ok(())
}

fn validate_ascii_digits(
    value: &str,
    min: usize,
    max: usize,
) -> Result<(), DeliveryTransportError> {
    if !(min..=max).contains(&value.len()) || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(DeliveryTransportError::InvalidInput);
    }
    Ok(())
}

fn validate_slack_destination(value: &str) -> Result<(), DeliveryTransportError> {
    if !(2..=64).contains(&value.len())
        || !matches!(value.as_bytes().first(), Some(b'C' | b'D' | b'G' | b'U'))
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return Err(DeliveryTransportError::InvalidInput);
    }
    Ok(())
}

fn validate_telegram_destination(value: &str) -> Result<(), DeliveryTransportError> {
    let digits = value.strip_prefix('-').unwrap_or(value);
    if digits.is_empty()
        || digits.len() > 20
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
        || digits.bytes().all(|byte| byte == b'0')
    {
        return Err(DeliveryTransportError::InvalidInput);
    }
    Ok(())
}

fn validate_whatsapp_destination(value: &str) -> Result<(), DeliveryTransportError> {
    validate_ascii_digits(value, 7, 15)
}

fn validate_teams_destination(value: &str) -> Result<(), DeliveryTransportError> {
    if value.is_empty()
        || value.len() > 256
        || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err(DeliveryTransportError::InvalidInput);
    }
    Ok(())
}

fn percent_encode_path_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(hex_digit(byte >> 4));
            encoded.push(hex_digit(byte & 0x0f));
        }
    }
    encoded
}

const fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'A' + value - 10) as char,
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn value_contains_text(value: &Value, needle: &str) -> bool {
    match value {
        Value::String(text) => text.contains(needle),
        Value::Array(values) => values
            .iter()
            .any(|value| value_contains_text(value, needle)),
        Value::Object(values) => values
            .iter()
            .any(|(key, value)| key.contains(needle) || value_contains_text(value, needle)),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::{Value, json};

    use super::*;

    const SLACK_SECRET: &str = "fixture-slack-credential-0000";
    const TELEGRAM_SECRET: &str = "12345:fixture_token_123";
    const WHATSAPP_SECRET: &str = "fixture-whatsapp-credential-0000";
    const TEAMS_SECRET: &str = "fixture-teams-credential-0000";

    fn delivery(channel: ApprovalChannel, destination: &str, body: Value) -> ChannelDelivery {
        let encoded = serde_json::to_vec(&body).unwrap_or_default();
        ChannelDelivery {
            channel,
            payload_kind: DeliveryPayloadKind::InteractiveApproval,
            destination: destination.to_owned(),
            media_type: "application/json".to_owned(),
            body,
            body_hash: Digest32::sha256(&encoded),
        }
    }

    fn slack_delivery(destination: &str) -> Result<ChannelDelivery, crate::ApprovalChannelError> {
        crate::build_review_notification_delivery(
            ApprovalChannel::Slack,
            destination.to_owned(),
            ReviewNotificationPrompt::new(),
        )
    }

    fn telegram_delivery(
        destination: &str,
    ) -> Result<ChannelDelivery, crate::ApprovalChannelError> {
        crate::build_review_notification_delivery(
            ApprovalChannel::Telegram,
            destination.to_owned(),
            ReviewNotificationPrompt::new(),
        )
    }

    fn whatsapp_delivery(
        destination: &str,
    ) -> Result<ChannelDelivery, crate::ApprovalChannelError> {
        crate::build_review_notification_delivery(
            ApprovalChannel::WhatsApp,
            destination.to_owned(),
            ReviewNotificationPrompt::new(),
        )
    }

    fn teams_delivery(destination: &str) -> Result<ChannelDelivery, crate::ApprovalChannelError> {
        crate::build_review_notification_delivery(
            ApprovalChannel::MicrosoftTeams,
            destination.to_owned(),
            ReviewNotificationPrompt::new(),
        )
    }

    fn authorization_value(request: &PreparedHttpsRequest) -> Option<&str> {
        request
            .headers()
            .iter()
            .find(|header| header.name() == "authorization")
            .map(RequestHeader::expose_value)
    }

    struct StubTransport {
        outcome: Option<Result<OutboundHttpsResponse, HttpsTransportFailure>>,
        calls: usize,
        expected_channel: ApprovalChannel,
    }

    impl StubTransport {
        fn response(
            channel: ApprovalChannel,
            status_code: u16,
            retry_after: Option<&str>,
            body: &[u8],
        ) -> Result<Self, DeliveryTransportError> {
            Ok(Self {
                outcome: Some(Ok(OutboundHttpsResponse::new(
                    status_code,
                    retry_after.map(str::to_owned),
                    body.to_vec(),
                )?)),
                calls: 0,
                expected_channel: channel,
            })
        }

        fn failure(channel: ApprovalChannel, failure: HttpsTransportFailure) -> Self {
            Self {
                outcome: Some(Err(failure)),
                calls: 0,
                expected_channel: channel,
            }
        }
    }

    impl BoundedHttpsTransport for StubTransport {
        fn send(
            &mut self,
            request: &PreparedHttpsRequest,
        ) -> Result<OutboundHttpsResponse, HttpsTransportFailure> {
            self.calls += 1;
            assert_eq!(request.channel(), self.expected_channel);
            match self.outcome.take() {
                Some(outcome) => outcome,
                None => Err(HttpsTransportFailure::new(
                    HttpsTransportFailureKind::Protocol,
                    HttpsRequestProgress::NotSent,
                )),
            }
        }
    }

    #[test]
    fn slack_adapter_uses_fixed_endpoint_bearer_and_bound_payload()
    -> Result<(), Box<dyn std::error::Error>> {
        let delivery = slack_delivery("C12345678")?;
        let credential = DeliveryCredential::slack(SLACK_SECRET.to_owned())?;
        let request = prepare_channel_delivery(
            &delivery,
            &DeliveryEndpointConfig::slack(),
            &credential,
            DeliveryLimits::default(),
        )?;

        assert_eq!(request.method(), "POST");
        assert_eq!(request.expose_endpoint(), SLACK_ENDPOINT);
        assert_eq!(
            authorization_value(&request),
            Some("Bearer fixture-slack-credential-0000")
        );
        assert_eq!(request.body_hash(), delivery.body_hash);
        assert_eq!(request.body(), serde_json::to_vec(&delivery.body)?);
        Ok(())
    }

    #[test]
    fn telegram_adapter_places_validated_token_only_in_redacted_endpoint()
    -> Result<(), Box<dyn std::error::Error>> {
        let delivery = telegram_delivery("-1001234567890")?;
        let credential = DeliveryCredential::telegram(TELEGRAM_SECRET.to_owned())?;
        let request = prepare_channel_delivery(
            &delivery,
            &DeliveryEndpointConfig::telegram(),
            &credential,
            DeliveryLimits::default(),
        )?;

        assert_eq!(
            request.expose_endpoint(),
            "https://api.telegram.org/bot12345:fixture_token_123/sendMessage"
        );
        assert_eq!(authorization_value(&request), None);
        let debug = format!("{request:?}");
        assert!(!debug.contains(TELEGRAM_SECRET));
        assert!(!debug.contains("api.telegram.org"));
        Ok(())
    }

    #[test]
    fn whatsapp_adapter_pins_graph_authority_version_and_phone_id()
    -> Result<(), Box<dyn std::error::Error>> {
        let delivery = whatsapp_delivery("33612345678")?;
        let credential = DeliveryCredential::whatsapp_cloud(WHATSAPP_SECRET.to_owned())?;
        let endpoint = DeliveryEndpointConfig::whatsapp_cloud("v23.0", "123456789012345")?;
        let request =
            prepare_channel_delivery(&delivery, &endpoint, &credential, DeliveryLimits::default())?;

        assert_eq!(
            request.expose_endpoint(),
            "https://graph.facebook.com/v23.0/123456789012345/messages"
        );
        assert_eq!(
            authorization_value(&request),
            Some("Bearer fixture-whatsapp-credential-0000")
        );
        Ok(())
    }

    #[test]
    fn teams_adapter_pins_public_authority_and_encodes_conversation_id()
    -> Result<(), Box<dyn std::error::Error>> {
        let destination = "19:abc/def@thread.v2";
        let delivery = teams_delivery(destination)?;
        let credential = DeliveryCredential::teams_bot(TEAMS_SECRET.to_owned())?;
        let endpoint =
            DeliveryEndpointConfig::teams_bot_public("https://smba.trafficmanager.net/emea/")?;
        let request =
            prepare_channel_delivery(&delivery, &endpoint, &credential, DeliveryLimits::default())?;

        assert_eq!(
            request.expose_endpoint(),
            "https://smba.trafficmanager.net/emea/v3/conversations/19%3Aabc%2Fdef%40thread.v2/activities"
        );
        assert_eq!(
            authorization_value(&request),
            Some("Bearer fixture-teams-credential-0000")
        );
        Ok(())
    }

    #[test]
    fn credentials_and_request_content_are_redacted_from_debug()
    -> Result<(), Box<dyn std::error::Error>> {
        let delivery = slack_delivery("C12345678")?;
        let credential = DeliveryCredential::slack(SLACK_SECRET.to_owned())?;
        assert!(!format!("{credential:?}").contains(SLACK_SECRET));
        let delivery_debug = format!("{delivery:?}");
        assert!(!delivery_debug.contains("C12345678"));
        assert!(!delivery_debug.contains("Review required"));
        let request = prepare_channel_delivery(
            &delivery,
            &DeliveryEndpointConfig::slack(),
            &credential,
            DeliveryLimits::default(),
        )?;
        let request_debug = format!("{request:?}");
        assert!(!request_debug.contains(SLACK_SECRET));
        assert!(!request_debug.contains("C12345678"));
        assert!(!request_debug.contains("Review required"));
        for header in request.headers() {
            assert!(!format!("{header:?}").contains(header.expose_value()));
        }
        Ok(())
    }

    #[test]
    fn channel_destination_payload_and_hash_substitution_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let credential = DeliveryCredential::slack(SLACK_SECRET.to_owned())?;
        let slack_endpoint = DeliveryEndpointConfig::slack();
        let mismatched_endpoint = DeliveryEndpointConfig::telegram();
        let delivery = slack_delivery("C12345678")?;
        assert!(matches!(
            prepare_channel_delivery(
                &delivery,
                &mismatched_endpoint,
                &credential,
                DeliveryLimits::default()
            ),
            Err(DeliveryTransportError::ChannelMismatch)
        ));

        let mut substituted_destination = slack_delivery("C12345678")?;
        substituted_destination.destination = "C87654321".to_owned();
        assert!(matches!(
            prepare_channel_delivery(
                &substituted_destination,
                &slack_endpoint,
                &credential,
                DeliveryLimits::default()
            ),
            Err(DeliveryTransportError::PayloadMismatch)
        ));

        let mut substituted_hash = slack_delivery("C12345678")?;
        substituted_hash.body_hash = Digest32::sha256(b"different");
        assert!(matches!(
            prepare_channel_delivery(
                &substituted_hash,
                &slack_endpoint,
                &credential,
                DeliveryLimits::default()
            ),
            Err(DeliveryTransportError::PayloadMismatch)
        ));
        Ok(())
    }

    #[test]
    fn review_notification_exact_shapes_reject_interactive_and_cross_channel_substitution()
    -> Result<(), Box<dyn std::error::Error>> {
        let deliveries = [
            slack_delivery("C12345678")?,
            teams_delivery("19:conversation@thread.v2")?,
            telegram_delivery("-1001234567890")?,
            whatsapp_delivery("33612345678")?,
        ];

        for delivery in &deliveries {
            assert!(validate_and_encode_delivery(delivery).is_ok());
        }

        for (index, delivery) in deliveries.iter().enumerate() {
            let mut with_interactive_field = delivery.clone();
            let field = match delivery.channel() {
                ApprovalChannel::Slack => "actions",
                ApprovalChannel::MicrosoftTeams => "attachments",
                ApprovalChannel::Telegram => "reply_markup",
                ApprovalChannel::WhatsApp => "interactive",
            };
            with_interactive_field
                .body
                .as_object_mut()
                .ok_or("review notification fixture must be an object")?
                .insert(field.to_owned(), Value::Array(Vec::new()));
            rehash(&mut with_interactive_field);
            assert!(matches!(
                validate_and_encode_delivery(&with_interactive_field),
                Err(DeliveryTransportError::PayloadMismatch)
            ));

            let mut cross_channel = delivery.clone();
            cross_channel.body = deliveries[(index + 1) % deliveries.len()].body.clone();
            rehash(&mut cross_channel);
            assert!(matches!(
                validate_and_encode_delivery(&cross_channel),
                Err(DeliveryTransportError::PayloadMismatch)
            ));
        }
        Ok(())
    }

    #[test]
    fn review_notification_nested_shape_rejects_unapproved_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut slack = slack_delivery("C12345678")?;
        slack
            .body
            .get_mut("blocks")
            .and_then(Value::as_array_mut)
            .and_then(|blocks| blocks.first_mut())
            .and_then(Value::as_object_mut)
            .and_then(|block| block.get_mut("text"))
            .and_then(Value::as_object_mut)
            .ok_or("Slack notification fixture must contain header text")?
            .insert("emoji".to_owned(), Value::Bool(true));
        rehash(&mut slack);
        assert!(matches!(
            validate_and_encode_delivery(&slack),
            Err(DeliveryTransportError::PayloadMismatch)
        ));

        let mut whatsapp = whatsapp_delivery("33612345678")?;
        whatsapp
            .body
            .get_mut("text")
            .and_then(Value::as_object_mut)
            .ok_or("WhatsApp notification fixture must contain text")?
            .insert("preview_url".to_owned(), Value::Bool(false));
        rehash(&mut whatsapp);
        assert!(matches!(
            validate_and_encode_delivery(&whatsapp),
            Err(DeliveryTransportError::PayloadMismatch)
        ));
        Ok(())
    }

    fn rehash(delivery: &mut ChannelDelivery) {
        let encoded = serde_json::to_vec(&delivery.body).unwrap_or_default();
        delivery.body_hash = Digest32::sha256(&encoded);
    }

    #[test]
    fn malformed_configuration_credentials_and_limits_are_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(DeliveryCredential::slack("short".to_owned()).is_err());
        assert!(DeliveryCredential::telegram("not-a-token".to_owned()).is_err());
        assert!(DeliveryEndpointConfig::whatsapp_cloud("23.0", "12345").is_err());
        assert!(DeliveryEndpointConfig::whatsapp_cloud("v23.0", "12/345").is_err());
        assert!(
            DeliveryEndpointConfig::teams_bot_public("https://attacker.invalid/emea/").is_err()
        );
        assert!(
            DeliveryEndpointConfig::teams_bot_public(
                "https://smba.trafficmanager.net/emea/../teams/"
            )
            .is_err()
        );
        assert!(
            DeliveryEndpointConfig::teams_bot_public(
                "https://smba.trafficmanager.net/emea/?redirect=1"
            )
            .is_err()
        );
        assert!(DeliveryLimits::new(Duration::ZERO, 1).is_err());
        assert!(DeliveryLimits::new(Duration::from_secs(31), 1).is_err());
        assert!(DeliveryLimits::new(Duration::from_secs(1), 0).is_err());
        assert!(
            DeliveryLimits::new(Duration::from_secs(1), MAX_DELIVERY_RESPONSE_BODY_BYTES + 1)
                .is_err()
        );
        assert!(OutboundHttpsResponse::new(99, None, Vec::new()).is_err());
        assert!(
            OutboundHttpsResponse::new(200, None, vec![0; MAX_DELIVERY_RESPONSE_BODY_BYTES + 1])
                .is_err()
        );

        let oversized = delivery(
            ApprovalChannel::Slack,
            "C12345678",
            json!({
                "blocks": [{"type": "section"}],
                "channel": "C12345678",
                "text": "x".repeat(MAX_DELIVERY_REQUEST_BODY_BYTES)
            }),
        );
        let credential = DeliveryCredential::slack(SLACK_SECRET.to_owned())?;
        assert!(matches!(
            prepare_channel_delivery(
                &oversized,
                &DeliveryEndpointConfig::slack(),
                &credential,
                DeliveryLimits::default()
            ),
            Err(DeliveryTransportError::PayloadMismatch)
        ));
        Ok(())
    }

    #[test]
    fn payload_with_exact_credential_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let credential = DeliveryCredential::slack(SLACK_SECRET.to_owned())?;
        let delivery = delivery(
            ApprovalChannel::Slack,
            "C12345678",
            json!({
                "blocks": [{"type": "section"}],
                "channel": "C12345678",
                "text": SLACK_SECRET
            }),
        );
        assert!(matches!(
            prepare_channel_delivery(
                &delivery,
                &DeliveryEndpointConfig::slack(),
                &credential,
                DeliveryLimits::default()
            ),
            Err(DeliveryTransportError::CredentialExposure)
        ));
        Ok(())
    }

    #[test]
    fn all_provider_success_contracts_are_checked() -> Result<(), Box<dyn std::error::Error>> {
        let cases = [
            (
                ApprovalChannel::Slack,
                br#"{"ok":true,"ts":"171234.5678"}"#.as_slice(),
            ),
            (
                ApprovalChannel::Telegram,
                br#"{"ok":true,"result":{"message_id":42}}"#.as_slice(),
            ),
            (
                ApprovalChannel::WhatsApp,
                br#"{"messages":[{"id":"wamid.42"}]}"#.as_slice(),
            ),
            (
                ApprovalChannel::MicrosoftTeams,
                br#"{"id":"activity-42"}"#.as_slice(),
            ),
        ];

        for (channel, body) in cases {
            let response = OutboundHttpsResponse::new(200, None, body.to_vec())?;
            let attempt = classify_response(channel, &response);
            assert_eq!(attempt.channel(), channel);
            assert_eq!(attempt.disposition(), DeliveryDisposition::Accepted);
            assert_eq!(attempt.reason(), DeliveryReason::ProviderAccepted);
            assert_eq!(attempt.status_code(), Some(200));
            assert_eq!(attempt.response_body_bytes(), body.len());
            assert_eq!(attempt.response_body_hash(), Some(Digest32::sha256(body)));
        }
        Ok(())
    }

    #[test]
    fn success_status_without_provider_receipt_is_ambiguous()
    -> Result<(), Box<dyn std::error::Error>> {
        let malformed = OutboundHttpsResponse::new(200, None, br#"{"ok":true}"#.to_vec())?;
        let attempt = classify_response(ApprovalChannel::Slack, &malformed);
        assert_eq!(attempt.disposition(), DeliveryDisposition::Ambiguous);
        assert_eq!(attempt.reason(), DeliveryReason::MalformedProviderResponse);

        let duplicate =
            OutboundHttpsResponse::new(200, None, br#"{"ok":true,"ok":true,"ts":"1"}"#.to_vec())?;
        let attempt = classify_response(ApprovalChannel::Slack, &duplicate);
        assert_eq!(attempt.disposition(), DeliveryDisposition::Ambiguous);
        assert_eq!(attempt.reason(), DeliveryReason::MalformedProviderResponse);
        Ok(())
    }

    #[test]
    fn rate_limits_are_bounded_and_never_retried_implicitly()
    -> Result<(), Box<dyn std::error::Error>> {
        let delivery = slack_delivery("C12345678")?;
        let credential = DeliveryCredential::slack(SLACK_SECRET.to_owned())?;
        let endpoint = DeliveryEndpointConfig::slack();
        let mut transport = StubTransport::response(
            ApprovalChannel::Slack,
            429,
            Some("999999999"),
            br#"{"ok":false,"error":"ratelimited"}"#,
        )?;
        let attempt = dispatch_channel_delivery(
            &delivery,
            &endpoint,
            &credential,
            DeliveryLimits::default(),
            &mut transport,
        )?;

        assert_eq!(transport.calls, 1);
        assert_eq!(attempt.disposition(), DeliveryDisposition::Retryable);
        assert_eq!(attempt.reason(), DeliveryReason::RateLimited);
        assert_eq!(attempt.retry_after_seconds(), Some(MAX_RETRY_AFTER_SECONDS));
        Ok(())
    }

    #[test]
    fn provider_and_transport_failures_preserve_delivery_ambiguity()
    -> Result<(), Box<dyn std::error::Error>> {
        let unavailable = OutboundHttpsResponse::new(503, None, b"unavailable".to_vec())?;
        let attempt = classify_response(ApprovalChannel::Slack, &unavailable);
        assert_eq!(attempt.disposition(), DeliveryDisposition::Ambiguous);
        assert_eq!(attempt.reason(), DeliveryReason::ProviderUnavailable);

        let rejected = OutboundHttpsResponse::new(403, None, b"forbidden".to_vec())?;
        let attempt = classify_response(ApprovalChannel::Slack, &rejected);
        assert_eq!(attempt.disposition(), DeliveryDisposition::PermanentFailure);
        assert_eq!(attempt.reason(), DeliveryReason::ProviderRejected);

        let not_sent = classify_transport_failure(
            ApprovalChannel::Slack,
            HttpsTransportFailure::new(
                HttpsTransportFailureKind::Connect,
                HttpsRequestProgress::NotSent,
            ),
        );
        assert_eq!(not_sent.disposition(), DeliveryDisposition::Retryable);
        assert_eq!(not_sent.reason(), DeliveryReason::TransportNotSent);
        assert_eq!(not_sent.retry_after_seconds(), Some(5));

        let maybe_sent = classify_transport_failure(
            ApprovalChannel::Slack,
            HttpsTransportFailure::new(
                HttpsTransportFailureKind::Timeout,
                HttpsRequestProgress::MayHaveBeenSent,
            ),
        );
        assert_eq!(maybe_sent.disposition(), DeliveryDisposition::Ambiguous);
        assert_eq!(maybe_sent.reason(), DeliveryReason::TransportOutcomeUnknown);
        Ok(())
    }

    #[test]
    fn response_cap_is_enforced_even_if_host_returns_too_much()
    -> Result<(), Box<dyn std::error::Error>> {
        let delivery = slack_delivery("C12345678")?;
        let credential = DeliveryCredential::slack(SLACK_SECRET.to_owned())?;
        let endpoint = DeliveryEndpointConfig::slack();
        let limits = DeliveryLimits::new(Duration::from_secs(2), 8)?;
        let mut transport = StubTransport::response(
            ApprovalChannel::Slack,
            200,
            None,
            br#"{"ok":true,"ts":"1"}"#,
        )?;
        let attempt =
            dispatch_channel_delivery(&delivery, &endpoint, &credential, limits, &mut transport)?;

        assert_eq!(transport.calls, 1);
        assert_eq!(attempt.disposition(), DeliveryDisposition::Ambiguous);
        assert_eq!(attempt.reason(), DeliveryReason::ResponseTooLarge);
        assert_eq!(attempt.status_code(), Some(200));
        Ok(())
    }

    #[test]
    fn dispatch_accepts_trait_objects_and_classifies_progress()
    -> Result<(), Box<dyn std::error::Error>> {
        let delivery = slack_delivery("C12345678")?;
        let credential = DeliveryCredential::slack(SLACK_SECRET.to_owned())?;
        let endpoint = DeliveryEndpointConfig::slack();
        let mut stub = StubTransport::failure(
            ApprovalChannel::Slack,
            HttpsTransportFailure::new(
                HttpsTransportFailureKind::Tls,
                HttpsRequestProgress::NotSent,
            ),
        );
        let transport: &mut dyn BoundedHttpsTransport = &mut stub;
        let attempt = dispatch_channel_delivery(
            &delivery,
            &endpoint,
            &credential,
            DeliveryLimits::default(),
            transport,
        )?;
        assert_eq!(attempt.disposition(), DeliveryDisposition::Retryable);
        assert_eq!(stub.calls, 1);
        Ok(())
    }
}
