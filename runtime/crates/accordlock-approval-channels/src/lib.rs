//! Provider-neutral remote approval delivery and interaction verification.
//!
//! Messaging platforms deliver a signed `AccordLock` challenge. They never
//! become execution authority. A verified interaction remains only a human
//! decision input for the trusted approval plane.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;

use accordlock_protocol::{CoseVerifier, Digest32, SigningIdentity, sign_cose, verify_cose};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac as _};
use rand::{RngCore as _, rngs::OsRng};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use uuid::Uuid;

mod native_https;
mod outbox;
mod remote_gateway;
mod sqlite;
mod transport;
mod worker;

pub use native_https::{WebPkiHttpsClientError, WebPkiHttpsTransport};
pub use outbox::{
    AckOutcome, ClaimedDelivery, DeadLetterOutcome, DeliveryOutbox, EnqueueOutcome, EnqueueRequest,
    LeaseToken, OutboxEncryptionKey, OutboxError, OutboxJobStatus, OutboxState,
    OutboxTerminalReason, RetryOutcome,
};
pub use remote_gateway::{
    DurableRemoteApprovalGateway, GatewayRegistrationOutcome, GatewayRevocationOutcome,
    RemoteApprovalGatewayError, process_slack_callback, process_teams_callback,
    process_telegram_callback, process_whatsapp_callback,
};
pub use sqlite::DurableApprovalReplayStore;
pub use transport::{
    BoundedHttpsTransport, DeliveryAttempt, DeliveryCredential, DeliveryDisposition,
    DeliveryEndpointConfig, DeliveryLimits, DeliveryReason, DeliveryTransportError,
    HttpsRequestProgress, HttpsTransportFailure, HttpsTransportFailureKind,
    MAX_DELIVERY_CREDENTIAL_BYTES, MAX_DELIVERY_ENDPOINT_BYTES, MAX_DELIVERY_REQUEST_BODY_BYTES,
    MAX_DELIVERY_RESPONSE_BODY_BYTES, MAX_DELIVERY_TIMEOUT, MAX_RETRY_AFTER_SECONDS,
    OutboundHttpsResponse, PreparedHttpsRequest, RequestHeader, dispatch_channel_delivery,
    prepare_channel_delivery,
};
pub use worker::{
    DeliveryMaterialResolver, DeliveryResolutionContext, DeliveryResolutionError,
    DeliveryWorkerConfig, DeliveryWorkerDeadLetterReason, DeliveryWorkerError,
    DeliveryWorkerRetryReason, DeliveryWorkerStep, ResolvedDeliveryMaterial, TrustedTimeError,
    TrustedTimeSource, process_exact_delivery, process_one_delivery,
};

pub const APPROVAL_CHANNEL_SCHEMA_VERSION: u16 = 1;
pub const MAX_CHALLENGE_LIFETIME_SECONDS: i64 = 15 * 60;
pub const MAX_ID_BYTES: usize = 256;
pub const MAX_PROMPT_TEXT_BYTES: usize = 1_024;
pub const MAX_REVIEW_URL_BYTES: usize = 2_048;
pub const MAX_PROVIDER_EVENT_ID_BYTES: usize = 512;
pub const MAX_SIGNED_CHALLENGE_BYTES: usize = 128 * 1_024;
pub const MAX_WEBHOOK_BODY_BYTES: usize = 1024 * 1024;
pub const MAX_WEBHOOK_SECRET_BYTES: usize = 512;
pub const SLACK_MAX_TIMESTAMP_SKEW_SECONDS: u64 = 5 * 60;
pub const MAX_TEAMS_TOKEN_LIFETIME_SECONDS: i64 = 60 * 60;

const REVIEW_NOTIFICATION_TITLE: &str = "AccordLock alert";
const REVIEW_NOTIFICATION_MESSAGE: &str = "Open Approval Center to see the latest status.";
const REVIEW_NOTIFICATION_TEXT: &str =
    "AccordLock alert\n\nOpen Approval Center to see the latest status.";
const CONNECTION_TEST_TITLE: &str = "AccordLock connected";
const CONNECTION_TEST_MESSAGE: &str = "Approval alerts are ready on this channel.";
const CONNECTION_TEST_TEXT: &str =
    "AccordLock connected\n\nApproval alerts are ready on this channel.";

const CHALLENGE_PAYLOAD_DOMAIN: &[u8] = b"accordlock:v1:remote-approval-challenge";
const CHALLENGE_SIGNATURE_DOMAIN: &str = "accordlock:v1:remote-approval-signature";
const SIGNED_CHALLENGE_DOMAIN: &[u8] = b"accordlock:v1:signed-remote-approval";
const PROMPT_DOMAIN: &[u8] = b"accordlock:v1:remote-approval-prompt";

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalChannel {
    Slack,
    MicrosoftTeams,
    Telegram,
    WhatsApp,
}

impl ApprovalChannel {
    const fn code(self) -> u8 {
        match self {
            Self::Slack => 0,
            Self::MicrosoftTeams => 1,
            Self::Telegram => 2,
            Self::WhatsApp => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RemoteApprovalDecision {
    AllowOnce,
    DenyAction,
    StopTask,
    RevokeTaskAccess,
}

impl RemoteApprovalDecision {
    const fn code(self) -> u8 {
        match self {
            Self::AllowOnce => 0,
            Self::DenyAction => 1,
            Self::StopTask => 2,
            Self::RevokeTaskAccess => 3,
        }
    }

    const fn callback_code(self) -> &'static str {
        match self {
            Self::AllowOnce => "A",
            Self::DenyAction => "D",
            Self::StopTask => "S",
            Self::RevokeTaskAccess => "R",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::AllowOnce => "Allow once",
            Self::DenyAction => "Deny",
            Self::StopTask => "Stop task",
            Self::RevokeTaskAccess => "Revoke access",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "scope",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum ApprovalSubject {
    Action {
        approval_request_hash: Digest32,
        policy_decision_hash: Digest32,
        action_hash: Digest32,
    },
    Task,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalPrompt {
    pub title: String,
    pub summary: String,
    pub project: Option<String>,
    pub review_url: String,
}

impl ApprovalPrompt {
    /// Returns the exact safe-display commitment bound into a challenge.
    ///
    /// # Errors
    ///
    /// Rejects empty, overlong, control-bearing, or non-HTTPS content.
    pub fn digest(&self) -> Result<Digest32, ApprovalChannelError> {
        validate_text(&self.title, MAX_PROMPT_TEXT_BYTES)?;
        validate_text(&self.summary, MAX_PROMPT_TEXT_BYTES)?;
        if let Some(project) = &self.project {
            validate_text(project, MAX_PROMPT_TEXT_BYTES)?;
        }
        validate_review_url(&self.review_url)?;

        let mut bytes = Vec::with_capacity(2_048);
        append_bytes(&mut bytes, PROMPT_DOMAIN)?;
        append_bytes(&mut bytes, self.title.as_bytes())?;
        append_bytes(&mut bytes, self.summary.as_bytes())?;
        match &self.project {
            Some(project) => {
                bytes.push(1);
                append_bytes(&mut bytes, project.as_bytes())?;
            }
            None => bytes.push(0),
        }
        append_bytes(&mut bytes, self.review_url.as_bytes())?;
        Ok(Digest32::sha256(&bytes))
    }
}

/// Library-owned, display-only copy for an Approval Center notification.
///
/// This zero-sized type deliberately accepts no caller-supplied text, link,
/// action description, path, command, identifier, or callback capability.
/// It can therefore direct a recipient to the current local status without
/// disclosing the protected action or suggesting that a remote response works.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReviewNotificationPrompt;

impl ReviewNotificationPrompt {
    /// Creates the fixed, display-only notification prompt.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Returns the fixed notification title.
    #[must_use]
    pub const fn title(self) -> &'static str {
        REVIEW_NOTIFICATION_TITLE
    }

    /// Returns the fixed notification message.
    #[must_use]
    pub const fn message(self) -> &'static str {
        REVIEW_NOTIFICATION_MESSAGE
    }

    /// Returns the fixed plain-text form used by text-only provider payloads.
    #[must_use]
    pub const fn plain_text(self) -> &'static str {
        REVIEW_NOTIFICATION_TEXT
    }
}

/// Library-owned copy for a channel connection test.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConnectionTestPrompt;

impl ConnectionTestPrompt {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub const fn title(self) -> &'static str {
        CONNECTION_TEST_TITLE
    }

    #[must_use]
    pub const fn message(self) -> &'static str {
        CONNECTION_TEST_MESSAGE
    }

    #[must_use]
    pub const fn plain_text(self) -> &'static str {
        CONNECTION_TEST_TEXT
    }
}

/// Signed control-plane statement for one channel, recipient, and exact task
/// or action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalChallenge {
    pub schema_version: u16,
    pub challenge_id: Uuid,
    pub task_id: Uuid,
    pub task_hash: Digest32,
    pub session_id: String,
    pub principal_id: String,
    pub subject: ApprovalSubject,
    pub prompt_hash: Digest32,
    pub interaction_token_hash: Digest32,
    pub channel: ApprovalChannel,
    pub tenant_id: String,
    pub recipient_id: String,
    pub delivery_destination_hash: Digest32,
    pub allowed_decisions: Vec<RemoteApprovalDecision>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub key_id: String,
}

impl ApprovalChallenge {
    /// Validates bounded fields and canonical decision ordering without
    /// accepting the statement as authentic.
    ///
    /// # Errors
    ///
    /// Rejects malformed, ambiguous, overlong, or overbroad challenges.
    pub fn validate(&self) -> Result<(), ApprovalChannelError> {
        if self.schema_version != APPROVAL_CHANNEL_SCHEMA_VERSION
            || self.challenge_id.is_nil()
            || self.task_id.is_nil()
            || is_zero(self.task_hash)
            || is_zero(self.prompt_hash)
            || is_zero(self.interaction_token_hash)
            || is_zero(self.delivery_destination_hash)
        {
            return Err(ApprovalChannelError::MalformedChallenge);
        }
        for value in [
            &self.session_id,
            &self.principal_id,
            &self.tenant_id,
            &self.recipient_id,
            &self.key_id,
        ] {
            validate_identifier(value)?;
        }
        if self.issued_at < 0
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > MAX_CHALLENGE_LIFETIME_SECONDS
        {
            return Err(ApprovalChannelError::MalformedChallenge);
        }
        if self.allowed_decisions.is_empty() || self.allowed_decisions.len() > 4 {
            return Err(ApprovalChannelError::MalformedChallenge);
        }
        if self
            .allowed_decisions
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(ApprovalChannelError::NonCanonicalDecisions);
        }
        match &self.subject {
            ApprovalSubject::Action {
                approval_request_hash,
                policy_decision_hash,
                action_hash,
            } => {
                if [approval_request_hash, policy_decision_hash, action_hash]
                    .into_iter()
                    .any(|digest| is_zero(*digest))
                {
                    return Err(ApprovalChannelError::MalformedChallenge);
                }
            }
            ApprovalSubject::Task => {
                if self.allowed_decisions.iter().any(|decision| {
                    matches!(
                        decision,
                        RemoteApprovalDecision::AllowOnce | RemoteApprovalDecision::DenyAction
                    )
                }) {
                    return Err(ApprovalChannelError::DecisionScopeMismatch);
                }
            }
        }
        Ok(())
    }

    fn canonical_payload(&self) -> Result<Vec<u8>, ApprovalChannelError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(1_024);
        append_bytes(&mut bytes, CHALLENGE_PAYLOAD_DOMAIN)?;
        bytes.extend_from_slice(&self.schema_version.to_be_bytes());
        bytes.extend_from_slice(self.challenge_id.as_bytes());
        bytes.extend_from_slice(self.task_id.as_bytes());
        bytes.extend_from_slice(self.task_hash.as_bytes());
        append_bytes(&mut bytes, self.session_id.as_bytes())?;
        append_bytes(&mut bytes, self.principal_id.as_bytes())?;
        match &self.subject {
            ApprovalSubject::Action {
                approval_request_hash,
                policy_decision_hash,
                action_hash,
            } => {
                bytes.push(0);
                bytes.extend_from_slice(approval_request_hash.as_bytes());
                bytes.extend_from_slice(policy_decision_hash.as_bytes());
                bytes.extend_from_slice(action_hash.as_bytes());
            }
            ApprovalSubject::Task => bytes.push(1),
        }
        bytes.extend_from_slice(self.prompt_hash.as_bytes());
        bytes.extend_from_slice(self.interaction_token_hash.as_bytes());
        bytes.push(self.channel.code());
        append_bytes(&mut bytes, self.tenant_id.as_bytes())?;
        append_bytes(&mut bytes, self.recipient_id.as_bytes())?;
        bytes.extend_from_slice(self.delivery_destination_hash.as_bytes());
        let decision_count = u8::try_from(self.allowed_decisions.len())
            .map_err(|_| ApprovalChannelError::MalformedChallenge)?;
        bytes.push(decision_count);
        for decision in &self.allowed_decisions {
            bytes.push(decision.code());
        }
        bytes.extend_from_slice(&self.issued_at.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        append_bytes(&mut bytes, self.key_id.as_bytes())?;
        Ok(bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedApprovalChallenge {
    pub challenge: ApprovalChallenge,
    pub cose_sign1: Vec<u8>,
}

impl SignedApprovalChallenge {
    /// Signs one canonical remote-approval challenge.
    ///
    /// # Errors
    ///
    /// Rejects malformed statements, key substitution, or signing failure.
    pub fn sign(
        challenge: ApprovalChallenge,
        signer: &SigningIdentity,
    ) -> Result<Self, ApprovalChannelError> {
        if challenge.key_id != signer.key_id() {
            return Err(ApprovalChannelError::KeyMismatch);
        }
        let payload = challenge.canonical_payload()?;
        let cose_sign1 = sign_cose(&payload, CHALLENGE_SIGNATURE_DOMAIN, signer)
            .map_err(|_| ApprovalChannelError::InvalidSignature)?;
        Ok(Self {
            challenge,
            cose_sign1,
        })
    }

    /// Verifies signature and freshness, returning a non-serializable checked
    /// capability.
    ///
    /// # Errors
    ///
    /// Rejects malformed, forged, substituted, or expired challenges.
    pub fn verify(
        &self,
        verifier: &CoseVerifier,
        trusted_now: i64,
    ) -> Result<VerifiedApprovalChallenge, ApprovalChannelError> {
        let payload = self.challenge.canonical_payload()?;
        if self.cose_sign1.is_empty()
            || self.cose_sign1.len() > MAX_SIGNED_CHALLENGE_BYTES
            || self.challenge.key_id != verifier.key_id()
        {
            return Err(ApprovalChannelError::KeyMismatch);
        }
        let verified_payload = verify_cose(&self.cose_sign1, CHALLENGE_SIGNATURE_DOMAIN, verifier)
            .map_err(|_| ApprovalChannelError::InvalidSignature)?;
        if verified_payload != payload {
            return Err(ApprovalChannelError::PayloadMismatch);
        }
        if trusted_now < self.challenge.issued_at || trusted_now >= self.challenge.expires_at {
            return Err(ApprovalChannelError::ExpiredChallenge);
        }
        Ok(VerifiedApprovalChallenge {
            challenge: self.challenge.clone(),
            signed_hash: self.digest()?,
        })
    }

    /// Returns a stable commitment for audit and replay records.
    ///
    /// # Errors
    ///
    /// Rejects malformed or overlarge signed statements.
    pub fn digest(&self) -> Result<Digest32, ApprovalChannelError> {
        let payload = self.challenge.canonical_payload()?;
        if self.cose_sign1.is_empty() || self.cose_sign1.len() > MAX_SIGNED_CHALLENGE_BYTES {
            return Err(ApprovalChannelError::MalformedChallenge);
        }
        let mut bytes = Vec::with_capacity(payload.len() + self.cose_sign1.len() + 64);
        append_bytes(&mut bytes, SIGNED_CHALLENGE_DOMAIN)?;
        append_bytes(&mut bytes, &payload)?;
        append_bytes(&mut bytes, &self.cose_sign1)?;
        Ok(Digest32::sha256(&bytes))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedApprovalChallenge {
    challenge: ApprovalChallenge,
    signed_hash: Digest32,
}

impl VerifiedApprovalChallenge {
    #[must_use]
    pub const fn challenge(&self) -> &ApprovalChallenge {
        &self.challenge
    }

    #[must_use]
    pub const fn signed_hash(&self) -> Digest32 {
        self.signed_hash
    }
}

/// A 256-bit bearer token used only to look up and bind a stored signed
/// challenge. It is necessary but never sufficient to approve an action.
pub struct InteractionToken {
    value: String,
}

impl InteractionToken {
    /// Creates a token from operating-system randomness.
    ///
    /// # Errors
    ///
    /// Returns an error if secure randomness is unavailable.
    pub fn generate() -> Result<Self, ApprovalChannelError> {
        let mut value = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut value)
            .map_err(|_| ApprovalChannelError::RandomnessUnavailable)?;
        Ok(Self {
            value: URL_SAFE_NO_PAD.encode(value),
        })
    }

    /// Parses an existing callback-safe 256-bit token.
    ///
    /// # Errors
    ///
    /// Rejects non-canonical base64url or a value with the wrong size.
    pub fn parse(value: &str) -> Result<Self, ApprovalChannelError> {
        if value.len() != 43 || value.chars().any(char::is_control) {
            return Err(ApprovalChannelError::MalformedToken);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| ApprovalChannelError::MalformedToken)?;
        if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != value {
            return Err(ApprovalChannelError::MalformedToken);
        }
        Ok(Self {
            value: value.to_owned(),
        })
    }

    #[must_use]
    pub fn for_delivery(&self) -> &str {
        &self.value
    }

    #[must_use]
    pub fn digest(&self) -> Digest32 {
        Digest32::sha256(self.value.as_bytes())
    }
}

impl fmt::Debug for InteractionToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InteractionToken")
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Slack signing secret retained only by the trusted webhook transport.
pub struct SlackSigningSecret(Vec<u8>);

impl SlackSigningSecret {
    /// Copies a bounded signing secret into protected application state.
    ///
    /// # Errors
    ///
    /// Rejects implausibly short or overlong secrets.
    pub fn from_bytes(secret: &[u8]) -> Result<Self, ApprovalChannelError> {
        validate_hmac_secret(secret)?;
        Ok(Self(secret.to_vec()))
    }
}

impl fmt::Debug for SlackSigningSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SlackSigningSecret([REDACTED])")
    }
}

impl Drop for SlackSigningSecret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Meta application secret retained only by the trusted webhook transport.
pub struct MetaAppSecret(Vec<u8>);

impl MetaAppSecret {
    /// Copies a bounded application secret into protected application state.
    ///
    /// # Errors
    ///
    /// Rejects implausibly short or overlong secrets.
    pub fn from_bytes(secret: &[u8]) -> Result<Self, ApprovalChannelError> {
        validate_hmac_secret(secret)?;
        Ok(Self(secret.to_vec()))
    }
}

impl fmt::Debug for MetaAppSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MetaAppSecret([REDACTED])")
    }
}

impl Drop for MetaAppSecret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Telegram webhook secret retained only by the trusted webhook transport.
pub struct TelegramWebhookSecret(Vec<u8>);

impl TelegramWebhookSecret {
    /// Copies a Telegram-compatible webhook secret into protected state.
    ///
    /// # Errors
    ///
    /// Rejects values outside Telegram's documented character and size limits.
    pub fn new(secret: &str) -> Result<Self, ApprovalChannelError> {
        if secret.is_empty()
            || secret.len() > 256
            || !secret
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(ApprovalChannelError::MalformedWebhookSecret);
        }
        Ok(Self(secret.as_bytes().to_vec()))
    }
}

impl fmt::Debug for TelegramWebhookSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TelegramWebhookSecret([REDACTED])")
    }
}

impl Drop for TelegramWebhookSecret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Identity facts returned only after provider-specific inbound verification.
/// The authenticated provider event is bound to replay consumption later in
/// the approval flow.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthenticatedChannelActor {
    channel: ApprovalChannel,
    tenant_id: String,
    external_user_id: String,
    provider_event_id: String,
}

impl AuthenticatedChannelActor {
    fn verified(
        channel: ApprovalChannel,
        tenant_id: String,
        external_user_id: String,
        provider_event_id: String,
    ) -> Result<Self, ApprovalChannelError> {
        validate_identifier(&tenant_id)?;
        validate_identifier(&external_user_id)?;
        validate_bounded_identifier(&provider_event_id, MAX_PROVIDER_EVENT_ID_BYTES)?;
        Ok(Self {
            channel,
            tenant_id,
            external_user_id,
            provider_event_id,
        })
    }

    #[must_use]
    pub const fn channel(&self) -> ApprovalChannel {
        self.channel
    }

    #[must_use]
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    #[must_use]
    pub fn external_user_id(&self) -> &str {
        &self.external_user_id
    }

    #[must_use]
    pub fn provider_event_id(&self) -> &str {
        &self.provider_event_id
    }
}

impl fmt::Debug for AuthenticatedChannelActor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedChannelActor")
            .field("channel", &self.channel)
            .field("tenant_id", &"[REDACTED]")
            .field("external_user_id", &"[REDACTED]")
            .field("provider_event_id", &"[REDACTED]")
            .finish()
    }
}

/// Verifies a Slack interactive webhook over the exact raw request bytes.
/// The signed timestamp must be canonical and within five minutes of the
/// trusted clock. Parsing happens only after successful authentication.
///
/// # Errors
///
/// Rejects stale requests, malformed headers or bodies, signature mismatch,
/// duplicate form fields, or incomplete actor identity.
pub fn authenticate_slack_interaction(
    secret: &SlackSigningSecret,
    trusted_now: i64,
    timestamp_header: &str,
    signature_header: &str,
    raw_body: &[u8],
) -> Result<AuthenticatedChannelActor, ApprovalChannelError> {
    validate_webhook_body(raw_body)?;
    let timestamp = parse_canonical_timestamp(timestamp_header)?;
    if trusted_now < 0 || trusted_now.abs_diff(timestamp) > SLACK_MAX_TIMESTAMP_SKEW_SECONDS {
        return Err(ApprovalChannelError::StaleWebhook);
    }
    let supplied_signature = parse_prefixed_signature(signature_header, "v0=")?;
    let mut authenticator = HmacSha256::new_from_slice(&secret.0)
        .map_err(|_| ApprovalChannelError::MalformedWebhookSecret)?;
    authenticator.update(b"v0:");
    authenticator.update(timestamp_header.as_bytes());
    authenticator.update(b":");
    authenticator.update(raw_body);
    authenticator
        .verify_slice(&supplied_signature)
        .map_err(|_| ApprovalChannelError::InvalidWebhookAuthentication)?;

    let payload = parse_slack_form_payload(raw_body)?;
    let value = parse_unambiguous_json(&payload)?;
    let tenant_id = required_nested_string(&value, &["team", "id"])?;
    let external_user_id = required_nested_string(&value, &["user", "id"])?;
    let provider_event_id = required_nested_string(&value, &["trigger_id"])?;
    AuthenticatedChannelActor::verified(
        ApprovalChannel::Slack,
        tenant_id.to_owned(),
        external_user_id.to_owned(),
        provider_event_id.to_owned(),
    )
}

/// Verifies a `WhatsApp` Cloud API webhook over the exact raw request bytes.
/// Meta does not sign a timestamp, so freshness is enforced later by the
/// signed approval challenge and atomic provider-event replay consumption.
///
/// # Errors
///
/// Rejects malformed or ambiguous JSON, signature mismatch, multiple event
/// records, or incomplete actor identity.
pub fn authenticate_whatsapp_interaction(
    secret: &MetaAppSecret,
    signature_header: &str,
    raw_body: &[u8],
) -> Result<AuthenticatedChannelActor, ApprovalChannelError> {
    validate_webhook_body(raw_body)?;
    let supplied_signature = parse_prefixed_signature(signature_header, "sha256=")?;
    verify_hmac_sha256(&secret.0, raw_body, &supplied_signature)?;

    let value = parse_unambiguous_json(raw_body)?;
    if required_nested_string(&value, &["object"])? != "whatsapp_business_account" {
        return Err(ApprovalChannelError::MalformedWebhookBody);
    }
    let entry = required_single_array_item(&value, "entry")?;
    let tenant_id = required_nested_string(entry, &["id"])?;
    let change = required_single_array_item(entry, "changes")?;
    if required_nested_string(change, &["field"])? != "messages" {
        return Err(ApprovalChannelError::MalformedWebhookBody);
    }
    let change_value = change
        .get("value")
        .ok_or(ApprovalChannelError::MalformedWebhookBody)?;
    if required_nested_string(change_value, &["messaging_product"])? != "whatsapp" {
        return Err(ApprovalChannelError::MalformedWebhookBody);
    }
    let message = required_single_array_item(change_value, "messages")?;
    let external_user_id = required_nested_string(message, &["from"])?;
    let provider_event_id = required_nested_string(message, &["id"])?;
    AuthenticatedChannelActor::verified(
        ApprovalChannel::WhatsApp,
        tenant_id.to_owned(),
        external_user_id.to_owned(),
        provider_event_id.to_owned(),
    )
}

/// Verifies Telegram's webhook secret in constant time and then parses one
/// callback update. The configured tenant identifies the receiving bot or
/// organization boundary because Telegram does not include it in the update.
///
/// # Errors
///
/// Rejects secret mismatch, malformed or ambiguous JSON, non-callback
/// updates, or incomplete actor identity.
pub fn authenticate_telegram_callback(
    secret: &TelegramWebhookSecret,
    secret_header: &str,
    tenant_id: &str,
    raw_body: &[u8],
) -> Result<AuthenticatedChannelActor, ApprovalChannelError> {
    validate_identifier(tenant_id)?;
    validate_webhook_body(raw_body)?;
    if secret_header.is_empty()
        || secret_header.len() > 256
        || !secret_header
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(ApprovalChannelError::MalformedWebhookHeader);
    }
    let actual = Digest32::sha256(secret_header.as_bytes());
    let expected = Digest32::sha256(&secret.0);
    if !bool::from(actual.as_bytes().ct_eq(expected.as_bytes())) {
        return Err(ApprovalChannelError::InvalidWebhookAuthentication);
    }

    let value = parse_unambiguous_json(raw_body)?;
    let update_id = required_nonnegative_integer(&value, "update_id")?;
    let callback = value
        .get("callback_query")
        .ok_or(ApprovalChannelError::MalformedWebhookBody)?;
    let external_user_id = required_nested_integer(callback, &["from", "id"])?;
    let callback_id = required_nested_string(callback, &["id"])?;
    let provider_event_id = format!("{update_id}:{callback_id}");
    AuthenticatedChannelActor::verified(
        ApprovalChannel::Telegram,
        tenant_id.to_owned(),
        external_user_id.to_string(),
        provider_event_id,
    )
}

/// Minimal claims view implemented by a trusted Microsoft Entra or Bot
/// Framework verifier after cryptographic JWT validation. This crate never
/// parses an unverified token or selects signing algorithms or keys.
pub trait CryptographicallyVerifiedTeamsClaims {
    fn tenant_id(&self) -> &str;
    fn external_user_id(&self) -> &str;
    fn audience(&self) -> &str;
    fn token_id(&self) -> &str;
    fn not_before(&self) -> i64;
    fn expires_at(&self) -> i64;
}

/// Exact identity and audience expected for one Teams approval endpoint.
#[derive(Clone, PartialEq, Eq)]
pub struct TeamsActorExpectation {
    tenant_id: String,
    external_user_id: String,
    audience: String,
}

impl TeamsActorExpectation {
    /// Creates a bounded exact-match policy for verified Teams claims.
    ///
    /// # Errors
    ///
    /// Rejects missing, overlong, padded, or control-bearing identifiers.
    pub fn new(
        tenant_id: String,
        external_user_id: String,
        audience: String,
    ) -> Result<Self, ApprovalChannelError> {
        validate_identifier(&tenant_id)?;
        validate_identifier(&external_user_id)?;
        validate_identifier(&audience)?;
        Ok(Self {
            tenant_id,
            external_user_id,
            audience,
        })
    }
}

impl fmt::Debug for TeamsActorExpectation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TeamsActorExpectation")
            .field("tenant_id", &"[REDACTED]")
            .field("external_user_id", &"[REDACTED]")
            .field("audience", &"[REDACTED]")
            .finish()
    }
}

/// Applies exact tenant, user, audience, event, and lifetime checks to claims
/// returned by an injected cryptographic OIDC verifier.
///
/// # Errors
///
/// Rejects identity or audience substitution, inactive or overlong tokens,
/// and malformed verified claim values.
pub fn authenticate_teams_claims(
    claims: &impl CryptographicallyVerifiedTeamsClaims,
    expected: &TeamsActorExpectation,
    trusted_now: i64,
) -> Result<AuthenticatedChannelActor, ApprovalChannelError> {
    for value in [
        claims.tenant_id(),
        claims.external_user_id(),
        claims.audience(),
        claims.token_id(),
    ] {
        validate_bounded_identifier(value, MAX_PROVIDER_EVENT_ID_BYTES)?;
    }
    if trusted_now < 0
        || claims.not_before() < 0
        || claims.expires_at() <= claims.not_before()
        || claims.expires_at() - claims.not_before() > MAX_TEAMS_TOKEN_LIFETIME_SECONDS
        || trusted_now < claims.not_before()
        || trusted_now >= claims.expires_at()
    {
        return Err(ApprovalChannelError::StaleWebhook);
    }
    if claims.tenant_id() != expected.tenant_id
        || claims.external_user_id() != expected.external_user_id
        || claims.audience() != expected.audience
    {
        return Err(ApprovalChannelError::ActorBindingMismatch);
    }
    AuthenticatedChannelActor::verified(
        ApprovalChannel::MicrosoftTeams,
        claims.tenant_id().to_owned(),
        claims.external_user_id().to_owned(),
        claims.token_id().to_owned(),
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproverEnrollment {
    pub approver_id: String,
    pub channel: ApprovalChannel,
    pub tenant_id: String,
    pub external_user_id: String,
    pub valid_from: i64,
    pub valid_until: i64,
}

impl ApproverEnrollment {
    fn validate(&self) -> Result<(), ApprovalChannelError> {
        validate_identifier(&self.approver_id)?;
        validate_identifier(&self.tenant_id)?;
        validate_identifier(&self.external_user_id)?;
        if self.valid_from < 0 || self.valid_until <= self.valid_from {
            return Err(ApprovalChannelError::InvalidEnrollment);
        }
        Ok(())
    }
}

pub struct RemoteApprovalInteraction {
    challenge_id: Uuid,
    token: InteractionToken,
    decision: RemoteApprovalDecision,
    provider_event_id: String,
}

impl RemoteApprovalInteraction {
    /// Creates a bounded provider interaction after webhook parsing.
    ///
    /// # Errors
    ///
    /// Rejects nil IDs, malformed tokens, or unsafe provider event IDs.
    pub fn new(
        challenge_id: Uuid,
        token: &str,
        decision: RemoteApprovalDecision,
        provider_event_id: String,
    ) -> Result<Self, ApprovalChannelError> {
        if challenge_id.is_nil() {
            return Err(ApprovalChannelError::MalformedInteraction);
        }
        validate_bounded_identifier(&provider_event_id, MAX_PROVIDER_EVENT_ID_BYTES)?;
        Ok(Self {
            challenge_id,
            token: InteractionToken::parse(token)?,
            decision,
            provider_event_id,
        })
    }
}

impl fmt::Debug for RemoteApprovalInteraction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteApprovalInteraction")
            .field("challenge_id", &self.challenge_id)
            .field("token", &"[REDACTED]")
            .field("decision", &self.decision)
            .field("provider_event_id", &self.provider_event_id)
            .finish()
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ReplayStoreError {
    #[error("approval challenge was already consumed")]
    AlreadyConsumed,
    #[error("approval replay input is invalid")]
    InvalidInput,
    #[error("approval challenge was revoked")]
    Revoked,
    #[error("approval challenge is not registered")]
    UnknownChallenge,
    #[error("approval replay store is unavailable")]
    Unavailable,
}

pub trait ApprovalReplayStore {
    /// Atomically consumes one challenge and provider event. Productive
    /// multi-instance deployments must implement this with durable state.
    ///
    /// # Errors
    ///
    /// Returns `AlreadyConsumed` for replay or `Unavailable` for unknown state.
    fn consume(
        &mut self,
        challenge_id: Uuid,
        provider_event_id: &str,
        expires_at: i64,
    ) -> Result<(), ReplayStoreError>;
}

#[derive(Debug, Default)]
pub struct MemoryApprovalReplayStore {
    challenges: BTreeSet<Uuid>,
    provider_events: BTreeSet<String>,
}

impl ApprovalReplayStore for MemoryApprovalReplayStore {
    fn consume(
        &mut self,
        challenge_id: Uuid,
        provider_event_id: &str,
        _expires_at: i64,
    ) -> Result<(), ReplayStoreError> {
        if self.challenges.contains(&challenge_id)
            || self.provider_events.contains(provider_event_id)
        {
            return Err(ReplayStoreError::AlreadyConsumed);
        }
        self.challenges.insert(challenge_id);
        self.provider_events.insert(provider_event_id.to_owned());
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRemoteDecision {
    challenge_id: Uuid,
    task_id: Uuid,
    approver_id: String,
    decision: RemoteApprovalDecision,
    signed_challenge_hash: Digest32,
    provider_event_id: String,
}

impl VerifiedRemoteDecision {
    #[must_use]
    pub const fn challenge_id(&self) -> Uuid {
        self.challenge_id
    }

    #[must_use]
    pub const fn task_id(&self) -> Uuid {
        self.task_id
    }

    #[must_use]
    pub fn approver_id(&self) -> &str {
        &self.approver_id
    }

    #[must_use]
    pub const fn decision(&self) -> RemoteApprovalDecision {
        self.decision
    }

    #[must_use]
    pub const fn signed_challenge_hash(&self) -> Digest32 {
        self.signed_challenge_hash
    }

    #[must_use]
    pub fn provider_event_id(&self) -> &str {
        &self.provider_event_id
    }
}

/// Verifies the complete remote decision boundary and consumes the challenge
/// once. The returned capability is decision evidence, not permission.
///
/// # Errors
///
/// Fails closed for invalid signatures, expiry, actor or token substitution,
/// inactive enrollment, disallowed decisions, replay, or unavailable state.
pub fn verify_remote_decision(
    signed_challenge: &SignedApprovalChallenge,
    verifier: &CoseVerifier,
    actor: &AuthenticatedChannelActor,
    enrollment: &ApproverEnrollment,
    interaction: &RemoteApprovalInteraction,
    trusted_now: i64,
    replay_store: &mut impl ApprovalReplayStore,
) -> Result<VerifiedRemoteDecision, ApprovalChannelError> {
    let checked_challenge = signed_challenge.verify(verifier, trusted_now)?;
    let challenge = checked_challenge.challenge();
    enrollment.validate()?;
    if trusted_now < enrollment.valid_from || trusted_now >= enrollment.valid_until {
        return Err(ApprovalChannelError::InvalidEnrollment);
    }
    if actor.channel != challenge.channel
        || actor.channel != enrollment.channel
        || actor.tenant_id != challenge.tenant_id
        || actor.tenant_id != enrollment.tenant_id
        || actor.external_user_id != enrollment.external_user_id
        || enrollment.approver_id != challenge.recipient_id
    {
        return Err(ApprovalChannelError::ActorBindingMismatch);
    }
    if interaction.challenge_id != challenge.challenge_id
        || interaction.provider_event_id != actor.provider_event_id
        || !challenge.allowed_decisions.contains(&interaction.decision)
    {
        return Err(ApprovalChannelError::InteractionBindingMismatch);
    }
    let actual_token_hash = interaction.token.digest();
    if !bool::from(
        actual_token_hash
            .as_bytes()
            .ct_eq(challenge.interaction_token_hash.as_bytes()),
    ) {
        return Err(ApprovalChannelError::InteractionBindingMismatch);
    }
    replay_store
        .consume(
            challenge.challenge_id,
            &interaction.provider_event_id,
            challenge.expires_at,
        )
        .map_err(ApprovalChannelError::ReplayStore)?;
    Ok(VerifiedRemoteDecision {
        challenge_id: challenge.challenge_id,
        task_id: challenge.task_id,
        approver_id: enrollment.approver_id.clone(),
        decision: interaction.decision,
        signed_challenge_hash: checked_challenge.signed_hash(),
        provider_event_id: interaction.provider_event_id.clone(),
    })
}

/// Provider payload produced by a checked interactive or display-only builder.
///
/// Fields are intentionally private so external callers cannot substitute a
/// destination, body, or digest between verification and transport.
#[derive(Clone, PartialEq)]
pub struct ChannelDelivery {
    channel: ApprovalChannel,
    payload_kind: DeliveryPayloadKind,
    destination: String,
    media_type: String,
    body: Value,
    body_hash: Digest32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeliveryPayloadKind {
    InteractiveApproval,
    ReviewNotification,
    ConnectionTest,
}

impl ChannelDelivery {
    #[must_use]
    pub const fn channel(&self) -> ApprovalChannel {
        self.channel
    }

    #[must_use]
    pub fn destination(&self) -> &str {
        &self.destination
    }

    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    #[must_use]
    pub const fn body(&self) -> &Value {
        &self.body
    }

    #[must_use]
    pub const fn body_hash(&self) -> Digest32 {
        self.body_hash
    }
}

impl fmt::Debug for ChannelDelivery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChannelDelivery")
            .field("channel", &self.channel)
            .field("payload_kind", &self.payload_kind)
            .field("destination", &"[REDACTED]")
            .field("media_type", &self.media_type)
            .field("body", &"[REDACTED]")
            .field("body_hash", &self.body_hash)
            .finish()
    }
}

/// Builds a minimal provider payload after checking the signed prompt and
/// opaque token bindings. No credential or action content is included.
///
/// # Errors
///
/// Rejects unverified binding changes, invalid destinations, or unsupported
/// provider payload constraints.
pub fn build_channel_delivery(
    challenge: &VerifiedApprovalChallenge,
    prompt: &ApprovalPrompt,
    destination: String,
    token: &InteractionToken,
) -> Result<ChannelDelivery, ApprovalChannelError> {
    validate_identifier(&destination)?;
    let value = challenge.challenge();
    if prompt.digest()? != value.prompt_hash
        || token.digest() != value.interaction_token_hash
        || Digest32::sha256(destination.as_bytes()) != value.delivery_destination_hash
    {
        return Err(ApprovalChannelError::DeliveryBindingMismatch);
    }
    let body = match value.channel {
        ApprovalChannel::Slack => slack_payload(value, prompt, &destination, token),
        ApprovalChannel::MicrosoftTeams => teams_payload(value, prompt, token),
        ApprovalChannel::Telegram => telegram_payload(value, prompt, &destination, token)?,
        ApprovalChannel::WhatsApp => whatsapp_payload(value, prompt, &destination, token),
    };
    channel_delivery(
        value.channel,
        DeliveryPayloadKind::InteractiveApproval,
        destination,
        body,
    )
}

/// Builds a bounded, display-only Approval Center notification.
///
/// The notification text is owned by this crate and contains no callback,
/// review URL, protected action content, path, command, or caller-provided
/// display text. Receiving this message does not grant approval authority.
///
/// # Errors
///
/// Rejects an empty, overlong, or control-bearing destination, or an encoding
/// failure.
pub fn build_review_notification_delivery(
    channel: ApprovalChannel,
    destination: String,
    prompt: ReviewNotificationPrompt,
) -> Result<ChannelDelivery, ApprovalChannelError> {
    build_fixed_notification_delivery(
        channel,
        destination,
        prompt.title(),
        prompt.message(),
        prompt.plain_text(),
        DeliveryPayloadKind::ReviewNotification,
    )
}

/// Builds one fixed, non-interactive connection-test message.
///
/// # Errors
///
/// Rejects malformed destinations or an encoding failure.
pub fn build_connection_test_delivery(
    channel: ApprovalChannel,
    destination: String,
    prompt: ConnectionTestPrompt,
) -> Result<ChannelDelivery, ApprovalChannelError> {
    build_fixed_notification_delivery(
        channel,
        destination,
        prompt.title(),
        prompt.message(),
        prompt.plain_text(),
        DeliveryPayloadKind::ConnectionTest,
    )
}

fn build_fixed_notification_delivery(
    channel: ApprovalChannel,
    destination: String,
    title: &str,
    message: &str,
    plain_text: &str,
    payload_kind: DeliveryPayloadKind,
) -> Result<ChannelDelivery, ApprovalChannelError> {
    validate_identifier(&destination)?;
    validate_text(title, MAX_PROMPT_TEXT_BYTES)?;
    validate_text(message, MAX_PROMPT_TEXT_BYTES)?;
    validate_text(plain_text, MAX_PROMPT_TEXT_BYTES)?;

    let body = match channel {
        ApprovalChannel::Slack => json!({
            "channel": destination.as_str(),
            "text": plain_text,
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": title},
                },
                {
                    "type": "section",
                    "text": {"type": "plain_text", "text": message},
                },
            ],
        }),
        ApprovalChannel::MicrosoftTeams => json!({
            "type": "message",
            "text": plain_text,
        }),
        ApprovalChannel::Telegram => json!({
            "chat_id": destination.as_str(),
            "text": plain_text,
        }),
        ApprovalChannel::WhatsApp => json!({
            "messaging_product": "whatsapp",
            "to": destination.as_str(),
            "type": "text",
            "text": {"body": plain_text},
        }),
    };
    channel_delivery(channel, payload_kind, destination, body)
}

fn channel_delivery(
    channel: ApprovalChannel,
    payload_kind: DeliveryPayloadKind,
    destination: String,
    body: Value,
) -> Result<ChannelDelivery, ApprovalChannelError> {
    let encoded = serde_json::to_vec(&body).map_err(|_| ApprovalChannelError::Encoding)?;
    Ok(ChannelDelivery {
        channel,
        payload_kind,
        destination,
        media_type: "application/json".to_owned(),
        body,
        body_hash: Digest32::sha256(&encoded),
    })
}

fn slack_payload(
    challenge: &ApprovalChallenge,
    prompt: &ApprovalPrompt,
    destination: &str,
    token: &InteractionToken,
) -> Value {
    let actions: Vec<Value> = challenge
        .allowed_decisions
        .iter()
        .map(|decision| {
            json!({
                "type": "button",
                "text": {"type": "plain_text", "text": decision.label()},
                "action_id": format!("accordlock_{}", decision.callback_code().to_lowercase()),
                "value": callback_value(token, *decision),
            })
        })
        .collect();
    json!({
        "channel": destination,
        "text": prompt.title,
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": prompt.title}},
            {"type": "section", "text": {"type": "plain_text", "text": prompt.summary}},
            {"type": "actions", "elements": actions},
            {"type": "context", "elements": [{"type": "mrkdwn", "text": format!("<{}|Review securely in AccordLock>", prompt.review_url)}]},
        ],
    })
}

fn teams_payload(
    challenge: &ApprovalChallenge,
    prompt: &ApprovalPrompt,
    token: &InteractionToken,
) -> Value {
    let mut actions = vec![json!({
        "type": "Action.OpenUrl",
        "title": "Review",
        "url": prompt.review_url,
    })];
    actions.extend(challenge.allowed_decisions.iter().map(|decision| {
        json!({
            "type": "Action.Submit",
            "title": decision.label(),
            "data": {
                "accordlock_token": token.for_delivery(),
                "accordlock_decision": decision.callback_code(),
            },
        })
    }));
    json!({
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.5",
                "body": [
                    {"type": "TextBlock", "text": prompt.title, "weight": "Bolder", "wrap": true},
                    {"type": "TextBlock", "text": prompt.summary, "wrap": true},
                ],
                "actions": actions,
            },
        }],
    })
}

fn telegram_payload(
    challenge: &ApprovalChallenge,
    prompt: &ApprovalPrompt,
    destination: &str,
    token: &InteractionToken,
) -> Result<Value, ApprovalChannelError> {
    let mut keyboard = vec![vec![json!({"text": "Review", "url": prompt.review_url})]];
    for decision in &challenge.allowed_decisions {
        let callback_data = callback_value(token, *decision);
        if callback_data.len() > 64 {
            return Err(ApprovalChannelError::ChannelCapabilityExceeded);
        }
        keyboard.push(vec![
            json!({"text": decision.label(), "callback_data": callback_data}),
        ]);
    }
    Ok(json!({
        "chat_id": destination,
        "text": format!("{}\n\n{}", prompt.title, prompt.summary),
        "reply_markup": {"inline_keyboard": keyboard},
    }))
}

fn whatsapp_payload(
    challenge: &ApprovalChallenge,
    prompt: &ApprovalPrompt,
    destination: &str,
    token: &InteractionToken,
) -> Value {
    let rows: Vec<Value> = challenge
        .allowed_decisions
        .iter()
        .map(|decision| {
            json!({
                "id": callback_value(token, *decision),
                "title": decision.label(),
            })
        })
        .collect();
    json!({
        "messaging_product": "whatsapp",
        "to": destination,
        "type": "interactive",
        "interactive": {
            "type": "list",
            "header": {"type": "text", "text": prompt.title},
            "body": {"text": format!("{}\n\nReview: {}", prompt.summary, prompt.review_url)},
            "action": {
                "button": "Choose action",
                "sections": [{"title": "AccordLock", "rows": rows}],
            },
        },
    })
}

fn callback_value(token: &InteractionToken, decision: RemoteApprovalDecision) -> String {
    format!("{}.{}", token.for_delivery(), decision.callback_code())
}

fn validate_hmac_secret(secret: &[u8]) -> Result<(), ApprovalChannelError> {
    if secret.len() < 16 || secret.len() > MAX_WEBHOOK_SECRET_BYTES {
        return Err(ApprovalChannelError::MalformedWebhookSecret);
    }
    Ok(())
}

fn validate_webhook_body(raw_body: &[u8]) -> Result<(), ApprovalChannelError> {
    if raw_body.is_empty() || raw_body.len() > MAX_WEBHOOK_BODY_BYTES {
        return Err(ApprovalChannelError::MalformedWebhookBody);
    }
    Ok(())
}

fn parse_canonical_timestamp(value: &str) -> Result<i64, ApprovalChannelError> {
    if value.is_empty()
        || value.len() > 20
        || value.bytes().any(|byte| !byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(ApprovalChannelError::MalformedWebhookHeader);
    }
    value
        .parse::<i64>()
        .ok()
        .filter(|timestamp| *timestamp >= 0)
        .ok_or(ApprovalChannelError::MalformedWebhookHeader)
}

fn parse_prefixed_signature(value: &str, prefix: &str) -> Result<[u8; 32], ApprovalChannelError> {
    let encoded = value
        .strip_prefix(prefix)
        .ok_or(ApprovalChannelError::MalformedWebhookHeader)?;
    if encoded.len() != 64
        || encoded
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(ApprovalChannelError::MalformedWebhookHeader);
    }
    let mut signature = [0_u8; 32];
    hex::decode_to_slice(encoded, &mut signature)
        .map_err(|_| ApprovalChannelError::MalformedWebhookHeader)?;
    Ok(signature)
}

fn verify_hmac_sha256(
    secret: &[u8],
    raw_body: &[u8],
    supplied_signature: &[u8; 32],
) -> Result<(), ApprovalChannelError> {
    let mut authenticator = HmacSha256::new_from_slice(secret)
        .map_err(|_| ApprovalChannelError::MalformedWebhookSecret)?;
    authenticator.update(raw_body);
    authenticator
        .verify_slice(supplied_signature)
        .map_err(|_| ApprovalChannelError::InvalidWebhookAuthentication)
}

fn parse_slack_form_payload(raw_body: &[u8]) -> Result<Vec<u8>, ApprovalChannelError> {
    if raw_body.iter().any(|byte| !byte.is_ascii()) {
        return Err(ApprovalChannelError::MalformedWebhookBody);
    }
    let mut fields = raw_body.split(|byte| *byte == b'&');
    let field = fields
        .next()
        .filter(|field| !field.is_empty())
        .ok_or(ApprovalChannelError::MalformedWebhookBody)?;
    if fields.next().is_some() {
        return Err(ApprovalChannelError::MalformedWebhookBody);
    }
    let separator = field
        .iter()
        .position(|byte| *byte == b'=')
        .ok_or(ApprovalChannelError::MalformedWebhookBody)?;
    if field[separator + 1..].contains(&b'=') {
        return Err(ApprovalChannelError::MalformedWebhookBody);
    }
    let key = percent_decode_form_component(&field[..separator])?;
    if key != b"payload" {
        return Err(ApprovalChannelError::MalformedWebhookBody);
    }
    let payload = percent_decode_form_component(&field[separator + 1..])?;
    if payload.is_empty() || payload.len() > MAX_WEBHOOK_BODY_BYTES {
        return Err(ApprovalChannelError::MalformedWebhookBody);
    }
    Ok(payload)
}

fn percent_decode_form_component(value: &[u8]) -> Result<Vec<u8>, ApprovalChannelError> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        match value[index] {
            b'%' => {
                if index + 2 >= value.len() {
                    return Err(ApprovalChannelError::MalformedWebhookBody);
                }
                let high = decode_hex_nibble(value[index + 1])?;
                let low = decode_hex_nibble(value[index + 2])?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    Ok(decoded)
}

fn decode_hex_nibble(value: u8) -> Result<u8, ApprovalChannelError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(ApprovalChannelError::MalformedWebhookBody),
    }
}

struct UniqueJsonValue(Value);

impl<'de> Deserialize<'de> for UniqueJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an unambiguous JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueJsonValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        UniqueJsonValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueJsonValue>()? {
            values.push(value.0);
        }
        Ok(UniqueJsonValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some((key, value)) = map.next_entry::<String, UniqueJsonValue>()? {
            if values.insert(key, value.0).is_some() {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
        }
        Ok(UniqueJsonValue(Value::Object(values)))
    }
}

fn parse_unambiguous_json(raw_body: &[u8]) -> Result<Value, ApprovalChannelError> {
    let mut deserializer = serde_json::Deserializer::from_slice(raw_body);
    let value = UniqueJsonValue::deserialize(&mut deserializer)
        .map_err(|_| ApprovalChannelError::MalformedWebhookBody)?;
    deserializer
        .end()
        .map_err(|_| ApprovalChannelError::MalformedWebhookBody)?;
    Ok(value.0)
}

fn required_nested_string<'a>(
    value: &'a Value,
    path: &[&str],
) -> Result<&'a str, ApprovalChannelError> {
    let mut current = value;
    for segment in path {
        current = current
            .get(*segment)
            .ok_or(ApprovalChannelError::MalformedWebhookBody)?;
    }
    let result = current
        .as_str()
        .ok_or(ApprovalChannelError::MalformedWebhookBody)?;
    validate_bounded_identifier(result, MAX_PROVIDER_EVENT_ID_BYTES)?;
    Ok(result)
}

fn required_single_array_item<'a>(
    value: &'a Value,
    field: &str,
) -> Result<&'a Value, ApprovalChannelError> {
    let entries = value
        .get(field)
        .and_then(Value::as_array)
        .filter(|entries| entries.len() == 1)
        .ok_or(ApprovalChannelError::MalformedWebhookBody)?;
    entries
        .first()
        .ok_or(ApprovalChannelError::MalformedWebhookBody)
}

fn required_nonnegative_integer(value: &Value, field: &str) -> Result<i64, ApprovalChannelError> {
    value
        .get(field)
        .and_then(Value::as_i64)
        .filter(|value| *value >= 0)
        .ok_or(ApprovalChannelError::MalformedWebhookBody)
}

fn required_nested_integer(value: &Value, path: &[&str]) -> Result<i64, ApprovalChannelError> {
    let mut current = value;
    for segment in path {
        current = current
            .get(*segment)
            .ok_or(ApprovalChannelError::MalformedWebhookBody)?;
    }
    current
        .as_i64()
        .filter(|value| *value > 0)
        .ok_or(ApprovalChannelError::MalformedWebhookBody)
}

fn validate_identifier(value: &str) -> Result<(), ApprovalChannelError> {
    validate_bounded_identifier(value, MAX_ID_BYTES)
}

fn validate_bounded_identifier(value: &str, maximum: usize) -> Result<(), ApprovalChannelError> {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(ApprovalChannelError::MalformedIdentifier);
    }
    Ok(())
}

fn validate_text(value: &str, maximum: usize) -> Result<(), ApprovalChannelError> {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value
            .chars()
            .any(|character| character.is_control() && character != '\n')
    {
        return Err(ApprovalChannelError::MalformedPrompt);
    }
    Ok(())
}

fn validate_review_url(value: &str) -> Result<(), ApprovalChannelError> {
    if value.len() > MAX_REVIEW_URL_BYTES
        || !value.starts_with("https://")
        || value.chars().any(char::is_control)
    {
        return Err(ApprovalChannelError::MalformedPrompt);
    }
    let authority = value
        .strip_prefix("https://")
        .and_then(|remaining| remaining.split('/').next())
        .ok_or(ApprovalChannelError::MalformedPrompt)?;
    if authority.is_empty() || authority.contains('@') {
        return Err(ApprovalChannelError::MalformedPrompt);
    }
    Ok(())
}

fn append_bytes(target: &mut Vec<u8>, value: &[u8]) -> Result<(), ApprovalChannelError> {
    let length = u64::try_from(value.len()).map_err(|_| ApprovalChannelError::Encoding)?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
    Ok(())
}

fn is_zero(value: Digest32) -> bool {
    value == Digest32::from_bytes([0; 32])
}

#[derive(Debug, Error)]
pub enum ApprovalChannelError {
    #[error("remote approval challenge is malformed")]
    MalformedChallenge,
    #[error("remote approval identifiers are malformed")]
    MalformedIdentifier,
    #[error("remote approval prompt is malformed")]
    MalformedPrompt,
    #[error("remote approval token is malformed")]
    MalformedToken,
    #[error("remote approval interaction is malformed")]
    MalformedInteraction,
    #[error("remote approval decision order is not canonical")]
    NonCanonicalDecisions,
    #[error("remote approval decision does not match its scope")]
    DecisionScopeMismatch,
    #[error("remote approval key does not match the trusted authority")]
    KeyMismatch,
    #[error("remote approval signature is invalid")]
    InvalidSignature,
    #[error("remote approval signed payload is not canonical")]
    PayloadMismatch,
    #[error("remote approval challenge is expired or not active")]
    ExpiredChallenge,
    #[error("secure randomness is unavailable")]
    RandomnessUnavailable,
    #[error("remote approval enrollment is invalid or inactive")]
    InvalidEnrollment,
    #[error("authenticated channel actor does not match the enrolled recipient")]
    ActorBindingMismatch,
    #[error("remote approval interaction does not match the signed challenge")]
    InteractionBindingMismatch,
    #[error("remote approval delivery does not match the signed challenge")]
    DeliveryBindingMismatch,
    #[error("remote approval payload exceeds a channel capability")]
    ChannelCapabilityExceeded,
    #[error("webhook secret is malformed")]
    MalformedWebhookSecret,
    #[error("webhook authentication header is malformed")]
    MalformedWebhookHeader,
    #[error("webhook body is malformed, ambiguous, or outside size limits")]
    MalformedWebhookBody,
    #[error("webhook authentication failed")]
    InvalidWebhookAuthentication,
    #[error("webhook or verified identity claims are outside their active window")]
    StaleWebhook,
    #[error("remote approval payload encoding failed")]
    Encoding,
    #[error(transparent)]
    ReplayStore(#[from] ReplayStoreError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
    }

    fn signer() -> SigningIdentity {
        SigningIdentity::from_seed("approval-channel-key", [9; 32])
    }

    fn token() -> Result<InteractionToken, ApprovalChannelError> {
        InteractionToken::parse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    }

    fn prompt() -> ApprovalPrompt {
        ApprovalPrompt {
            title: "Action needs review".to_owned(),
            summary: "AccordLock paused before a protected change.".to_owned(),
            project: Some("Payments".to_owned()),
            review_url: "https://review.accordlock.example/requests/42".to_owned(),
        }
    }

    fn challenge(
        channel: ApprovalChannel,
        token: &InteractionToken,
    ) -> Result<ApprovalChallenge, ApprovalChannelError> {
        let mut allowed_decisions = vec![
            RemoteApprovalDecision::AllowOnce,
            RemoteApprovalDecision::DenyAction,
            RemoteApprovalDecision::StopTask,
            RemoteApprovalDecision::RevokeTaskAccess,
        ];
        allowed_decisions.sort_unstable();
        Ok(ApprovalChallenge {
            schema_version: APPROVAL_CHANNEL_SCHEMA_VERSION,
            challenge_id: Uuid::from_u128(1),
            task_id: Uuid::from_u128(2),
            task_hash: digest(1),
            session_id: "session-1".to_owned(),
            principal_id: "principal-1".to_owned(),
            subject: ApprovalSubject::Action {
                approval_request_hash: digest(2),
                policy_decision_hash: digest(3),
                action_hash: digest(4),
            },
            prompt_hash: prompt().digest()?,
            interaction_token_hash: token.digest(),
            channel,
            tenant_id: "tenant-1".to_owned(),
            recipient_id: "approver-1".to_owned(),
            delivery_destination_hash: Digest32::sha256(b"destination-1"),
            allowed_decisions,
            issued_at: 100,
            expires_at: 200,
            key_id: "approval-channel-key".to_owned(),
        })
    }

    fn signed(
        channel: ApprovalChannel,
        token: &InteractionToken,
    ) -> Result<SignedApprovalChallenge, ApprovalChannelError> {
        SignedApprovalChallenge::sign(challenge(channel, token)?, &signer())
    }

    fn actor(
        channel: ApprovalChannel,
        provider_event_id: &str,
    ) -> Result<AuthenticatedChannelActor, ApprovalChannelError> {
        AuthenticatedChannelActor::verified(
            channel,
            "tenant-1".to_owned(),
            "external-1".to_owned(),
            provider_event_id.to_owned(),
        )
    }

    fn enrollment(channel: ApprovalChannel) -> ApproverEnrollment {
        ApproverEnrollment {
            approver_id: "approver-1".to_owned(),
            channel,
            tenant_id: "tenant-1".to_owned(),
            external_user_id: "external-1".to_owned(),
            valid_from: 50,
            valid_until: 300,
        }
    }

    fn percent_encode_json(value: &Value) -> Result<Vec<u8>, serde_json::Error> {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let json = serde_json::to_vec(value)?;
        let mut body = b"payload=".to_vec();
        for byte in json {
            body.push(b'%');
            body.push(HEX[usize::from(byte >> 4)]);
            body.push(HEX[usize::from(byte & 0x0f)]);
        }
        Ok(body)
    }

    fn slack_signature(
        secret: &[u8],
        timestamp: &str,
        raw_body: &[u8],
    ) -> Result<String, ApprovalChannelError> {
        let mut authenticator = HmacSha256::new_from_slice(secret)
            .map_err(|_| ApprovalChannelError::MalformedWebhookSecret)?;
        authenticator.update(b"v0:");
        authenticator.update(timestamp.as_bytes());
        authenticator.update(b":");
        authenticator.update(raw_body);
        Ok(format!(
            "v0={}",
            hex::encode(authenticator.finalize().into_bytes())
        ))
    }

    fn meta_signature(secret: &[u8], raw_body: &[u8]) -> Result<String, ApprovalChannelError> {
        let mut authenticator = HmacSha256::new_from_slice(secret)
            .map_err(|_| ApprovalChannelError::MalformedWebhookSecret)?;
        authenticator.update(raw_body);
        Ok(format!(
            "sha256={}",
            hex::encode(authenticator.finalize().into_bytes())
        ))
    }

    struct TestTeamsClaims {
        tenant_id: String,
        external_user_id: String,
        audience: String,
        token_id: String,
        not_before: i64,
        expires_at: i64,
    }

    impl CryptographicallyVerifiedTeamsClaims for TestTeamsClaims {
        fn tenant_id(&self) -> &str {
            &self.tenant_id
        }

        fn external_user_id(&self) -> &str {
            &self.external_user_id
        }

        fn audience(&self) -> &str {
            &self.audience
        }

        fn token_id(&self) -> &str {
            &self.token_id
        }

        fn not_before(&self) -> i64 {
            self.not_before
        }

        fn expires_at(&self) -> i64 {
            self.expires_at
        }
    }

    fn teams_claims() -> TestTeamsClaims {
        TestTeamsClaims {
            tenant_id: "tenant-1".to_owned(),
            external_user_id: "external-1".to_owned(),
            audience: "api://accordlock-approvals".to_owned(),
            token_id: "teams-token-1".to_owned(),
            not_before: 100,
            expires_at: 3_700,
        }
    }

    #[test]
    fn exact_remote_decision_is_single_use() -> Result<(), Box<dyn std::error::Error>> {
        let token = token()?;
        let signed = signed(ApprovalChannel::Slack, &token)?;
        let verifier = signer().verifier();
        let actor = actor(ApprovalChannel::Slack, "event-1")?;
        let enrollment = enrollment(ApprovalChannel::Slack);
        let interaction = RemoteApprovalInteraction::new(
            Uuid::from_u128(1),
            token.for_delivery(),
            RemoteApprovalDecision::AllowOnce,
            "event-1".to_owned(),
        )?;
        let mut replay = MemoryApprovalReplayStore::default();

        let checked_decision = verify_remote_decision(
            &signed,
            &verifier,
            &actor,
            &enrollment,
            &interaction,
            150,
            &mut replay,
        )?;
        assert_eq!(checked_decision.approver_id(), "approver-1");
        assert_eq!(
            checked_decision.decision(),
            RemoteApprovalDecision::AllowOnce
        );

        let replayed = verify_remote_decision(
            &signed,
            &verifier,
            &actor,
            &enrollment,
            &interaction,
            150,
            &mut replay,
        );
        assert!(matches!(
            replayed,
            Err(ApprovalChannelError::ReplayStore(
                ReplayStoreError::AlreadyConsumed
            ))
        ));
        Ok(())
    }

    #[test]
    fn actor_token_and_channel_substitution_fail_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let token = token()?;
        let signed = signed(ApprovalChannel::Slack, &token)?;
        let verifier = signer().verifier();
        let wrong_actor = actor(ApprovalChannel::Telegram, "event-2")?;
        let enrollment = enrollment(ApprovalChannel::Slack);
        let interaction = RemoteApprovalInteraction::new(
            Uuid::from_u128(1),
            token.for_delivery(),
            RemoteApprovalDecision::AllowOnce,
            "event-2".to_owned(),
        )?;
        let mut replay = MemoryApprovalReplayStore::default();
        assert!(matches!(
            verify_remote_decision(
                &signed,
                &verifier,
                &wrong_actor,
                &enrollment,
                &interaction,
                150,
                &mut replay,
            ),
            Err(ApprovalChannelError::ActorBindingMismatch)
        ));

        let wrong_token = InteractionToken::parse("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE")?;
        let wrong_interaction = RemoteApprovalInteraction::new(
            Uuid::from_u128(1),
            wrong_token.for_delivery(),
            RemoteApprovalDecision::AllowOnce,
            "event-3".to_owned(),
        )?;
        let correct_actor = actor(ApprovalChannel::Slack, "event-3")?;
        assert!(matches!(
            verify_remote_decision(
                &signed,
                &verifier,
                &correct_actor,
                &enrollment,
                &wrong_interaction,
                150,
                &mut replay,
            ),
            Err(ApprovalChannelError::InteractionBindingMismatch)
        ));
        Ok(())
    }

    #[test]
    fn expiry_and_task_scope_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let token = token()?;
        let signed = signed(ApprovalChannel::Slack, &token)?;
        assert!(matches!(
            signed.verify(&signer().verifier(), 200),
            Err(ApprovalChannelError::ExpiredChallenge)
        ));

        let mut invalid = challenge(ApprovalChannel::Slack, &token)?;
        invalid.subject = ApprovalSubject::Task;
        assert!(matches!(
            invalid.validate(),
            Err(ApprovalChannelError::DecisionScopeMismatch)
        ));
        Ok(())
    }

    #[test]
    fn all_channel_payloads_are_bounded_and_content_minimal()
    -> Result<(), Box<dyn std::error::Error>> {
        let token = token()?;
        for channel in [
            ApprovalChannel::Slack,
            ApprovalChannel::MicrosoftTeams,
            ApprovalChannel::Telegram,
            ApprovalChannel::WhatsApp,
        ] {
            let verified = signed(channel, &token)?.verify(&signer().verifier(), 150)?;
            let delivery =
                build_channel_delivery(&verified, &prompt(), "destination-1".to_owned(), &token)?;
            let encoded = serde_json::to_string(&delivery.body)?;
            assert!(encoded.contains("Action needs review"));
            assert!(!encoded.contains(&digest(4).to_string()));
            assert!(!encoded.contains("authorization"));
            assert!(!encoded.contains("credential"));
        }
        Ok(())
    }

    #[test]
    fn review_notifications_are_bounded_fixed_copy_without_remote_actions()
    -> Result<(), Box<dyn std::error::Error>> {
        let prompt = ReviewNotificationPrompt::new();
        assert_eq!(prompt.title(), "AccordLock alert");
        assert_eq!(
            prompt.message(),
            "Open Approval Center to see the latest status."
        );
        assert_eq!(
            prompt.plain_text(),
            "AccordLock alert\n\nOpen Approval Center to see the latest status."
        );
        for (channel, destination) in [
            (ApprovalChannel::Slack, "C12345678"),
            (ApprovalChannel::MicrosoftTeams, "19:conversation@thread.v2"),
            (ApprovalChannel::Telegram, "-1001234567890"),
            (ApprovalChannel::WhatsApp, "33612345678"),
        ] {
            let delivery =
                build_review_notification_delivery(channel, destination.to_owned(), prompt)?;
            let encoded = serde_json::to_string(delivery.body())?;
            assert!(!encoded.is_empty());
            assert!(encoded.len() <= MAX_DELIVERY_REQUEST_BODY_BYTES);
            assert!(encoded.contains(prompt.title()));
            assert!(encoded.contains(prompt.message()));
            assert!(!encoded.contains("waiting"));
            assert!(!encoded.contains("before it expires"));
            assert_no_remote_action_fields(delivery.body());
        }
        Ok(())
    }

    fn assert_no_remote_action_fields(value: &Value) {
        match value {
            Value::Array(values) => {
                for value in values {
                    assert_no_remote_action_fields(value);
                }
            }
            Value::Object(values) => {
                for (key, value) in values {
                    assert!(!matches!(
                        key.as_str(),
                        "action"
                            | "action_id"
                            | "actions"
                            | "attachments"
                            | "button"
                            | "callback_data"
                            | "command"
                            | "data"
                            | "interactive"
                            | "objective"
                            | "path"
                            | "reply_markup"
                            | "token"
                            | "url"
                    ));
                    assert_no_remote_action_fields(value);
                }
            }
            Value::String(text) => {
                let lower = text.to_ascii_lowercase();
                assert!(!lower.contains("http://"));
                assert!(!lower.contains("https://"));
                assert!(!lower.contains("callback"));
                assert!(!lower.contains("button"));
                assert!(!lower.contains("command"));
                assert!(!lower.contains("objective"));
                assert!(!lower.contains("path"));
                assert!(!lower.contains("token"));
                assert!(!lower.contains("url"));
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    #[test]
    fn telegram_callback_values_fit_provider_limit() -> Result<(), Box<dyn std::error::Error>> {
        let token = token()?;
        let verified =
            signed(ApprovalChannel::Telegram, &token)?.verify(&signer().verifier(), 150)?;
        let delivery =
            build_channel_delivery(&verified, &prompt(), "destination-1".to_owned(), &token)?;
        let encoded = serde_json::to_string(&delivery.body)?;
        assert!(encoded.contains("callback_data"));
        for decision in verified.challenge().allowed_decisions.iter().copied() {
            assert!(callback_value(&token, decision).len() <= 64);
        }
        Ok(())
    }

    #[test]
    fn prompt_or_token_substitution_cannot_build_delivery() -> Result<(), Box<dyn std::error::Error>>
    {
        let token = token()?;
        let verified = signed(ApprovalChannel::Slack, &token)?.verify(&signer().verifier(), 150)?;
        let mut altered_prompt = prompt();
        altered_prompt.summary = "Approve a different action.".to_owned();
        assert!(matches!(
            build_channel_delivery(
                &verified,
                &altered_prompt,
                "destination-1".to_owned(),
                &token,
            ),
            Err(ApprovalChannelError::DeliveryBindingMismatch)
        ));
        Ok(())
    }

    #[test]
    fn secrets_are_redacted_from_debug_output() -> Result<(), Box<dyn std::error::Error>> {
        let token = token()?;
        let debug = format!("{token:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(token.for_delivery()));

        let slack_secret = SlackSigningSecret::from_bytes(b"0123456789abcdef0123456789abcdef")?;
        let meta_secret = MetaAppSecret::from_bytes(b"abcdef0123456789abcdef0123456789")?;
        let telegram_secret = TelegramWebhookSecret::new("telegram_secret-42")?;
        assert!(!format!("{slack_secret:?}").contains("0123456789abcdef"));
        assert!(!format!("{meta_secret:?}").contains("abcdef0123456789"));
        assert!(!format!("{telegram_secret:?}").contains("telegram_secret-42"));
        let actor = actor(ApprovalChannel::Slack, "private-event-id")?;
        let actor_debug = format!("{actor:?}");
        assert!(!actor_debug.contains("tenant-1"));
        assert!(!actor_debug.contains("external-1"));
        assert!(!actor_debug.contains("private-event-id"));
        Ok(())
    }

    #[test]
    fn webhook_inputs_are_strictly_bounded() -> Result<(), Box<dyn std::error::Error>> {
        assert!(matches!(
            SlackSigningSecret::from_bytes(b"short"),
            Err(ApprovalChannelError::MalformedWebhookSecret)
        ));
        assert!(matches!(
            TelegramWebhookSecret::new("contains spaces"),
            Err(ApprovalChannelError::MalformedWebhookSecret)
        ));
        let secret = TelegramWebhookSecret::new("telegram_secret-42")?;
        let oversized_body = vec![b'a'; MAX_WEBHOOK_BODY_BYTES + 1];
        assert!(matches!(
            authenticate_telegram_callback(
                &secret,
                "telegram_secret-42",
                "tenant-1",
                &oversized_body,
            ),
            Err(ApprovalChannelError::MalformedWebhookBody)
        ));
        Ok(())
    }

    #[test]
    fn slack_authenticates_exact_raw_unicode_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let secret_bytes = b"0123456789abcdef0123456789abcdef";
        let secret = SlackSigningSecret::from_bytes(secret_bytes)?;
        let composed = percent_encode_json(&json!({
            "team": {"id": "tenant-1"},
            "user": {"id": "external-1"},
            "trigger_id": "slack-event-1",
            "message": "Café"
        }))?;
        let signature = slack_signature(secret_bytes, "1000", &composed)?;
        let actor = authenticate_slack_interaction(&secret, 1_100, "1000", &signature, &composed)?;
        assert_eq!(actor.channel(), ApprovalChannel::Slack);
        assert_eq!(actor.tenant_id(), "tenant-1");
        assert_eq!(actor.external_user_id(), "external-1");
        assert_eq!(actor.provider_event_id(), "slack-event-1");

        let decomposed = percent_encode_json(&json!({
            "team": {"id": "tenant-1"},
            "user": {"id": "external-1"},
            "trigger_id": "slack-event-1",
            "message": "Cafe\u{0301}"
        }))?;
        assert_ne!(composed, decomposed);
        assert!(matches!(
            authenticate_slack_interaction(&secret, 1_100, "1000", &signature, &decomposed),
            Err(ApprovalChannelError::InvalidWebhookAuthentication)
        ));
        Ok(())
    }

    #[test]
    fn slack_rejects_tamper_stale_and_ambiguous_formats() -> Result<(), Box<dyn std::error::Error>>
    {
        let secret_bytes = b"0123456789abcdef0123456789abcdef";
        let secret = SlackSigningSecret::from_bytes(secret_bytes)?;
        let body = percent_encode_json(&json!({
            "team": {"id": "tenant-1"},
            "user": {"id": "external-1"},
            "trigger_id": "slack-event-2"
        }))?;
        let signature = slack_signature(secret_bytes, "1000", &body)?;
        let mut tampered = body.clone();
        let final_byte = tampered.last_mut().ok_or("test body unexpectedly empty")?;
        *final_byte = if *final_byte == b'0' { b'1' } else { b'0' };
        assert!(matches!(
            authenticate_slack_interaction(&secret, 1_100, "1000", &signature, &tampered),
            Err(ApprovalChannelError::InvalidWebhookAuthentication)
        ));
        assert!(matches!(
            authenticate_slack_interaction(&secret, 1_301, "1000", &signature, &body),
            Err(ApprovalChannelError::StaleWebhook)
        ));
        assert!(matches!(
            authenticate_slack_interaction(&secret, 1_100, "01000", &signature, &body),
            Err(ApprovalChannelError::MalformedWebhookHeader)
        ));
        let uppercase_signature = signature.to_ascii_uppercase();
        assert!(matches!(
            authenticate_slack_interaction(&secret, 1_100, "1000", &uppercase_signature, &body,),
            Err(ApprovalChannelError::MalformedWebhookHeader)
        ));

        let mut duplicate = body.clone();
        duplicate.extend_from_slice(b"&");
        duplicate.extend_from_slice(&body);
        let duplicate_signature = slack_signature(secret_bytes, "1000", &duplicate)?;
        assert!(matches!(
            authenticate_slack_interaction(
                &secret,
                1_100,
                "1000",
                &duplicate_signature,
                &duplicate,
            ),
            Err(ApprovalChannelError::MalformedWebhookBody)
        ));
        Ok(())
    }

    #[test]
    fn whatsapp_authentication_binds_actor_and_rejects_ambiguity()
    -> Result<(), Box<dyn std::error::Error>> {
        let secret_bytes = b"abcdef0123456789abcdef0123456789";
        let secret = MetaAppSecret::from_bytes(secret_bytes)?;
        let body = br#"{"object":"whatsapp_business_account","entry":[{"id":"tenant-1","changes":[{"field":"messages","value":{"messaging_product":"whatsapp","messages":[{"from":"external-1","id":"wamid.event-1","text":{"body":"Caf\u00e9"}}]}}]}]}"#;
        let signature = meta_signature(secret_bytes, body)?;
        let actor = authenticate_whatsapp_interaction(&secret, &signature, body)?;
        assert_eq!(actor.channel(), ApprovalChannel::WhatsApp);
        assert_eq!(actor.tenant_id(), "tenant-1");
        assert_eq!(actor.external_user_id(), "external-1");
        assert_eq!(actor.provider_event_id(), "wamid.event-1");

        let replacement_at = body
            .windows(b"external-1".len())
            .position(|window| window == b"external-1")
            .ok_or("test fixture lacks actor ID")?;
        let mut tampered = body.to_vec();
        tampered[replacement_at + b"external-".len()] = b'2';
        assert!(matches!(
            authenticate_whatsapp_interaction(&secret, &signature, &tampered),
            Err(ApprovalChannelError::InvalidWebhookAuthentication)
        ));

        let ambiguous = br#"{"object":"whatsapp_business_account","object":"whatsapp_business_account","entry":[{"id":"tenant-1","changes":[{"field":"messages","value":{"messaging_product":"whatsapp","messages":[{"from":"external-1","id":"wamid.event-2"}]}}]}]}"#;
        let ambiguous_signature = meta_signature(secret_bytes, ambiguous)?;
        assert!(matches!(
            authenticate_whatsapp_interaction(&secret, &ambiguous_signature, ambiguous),
            Err(ApprovalChannelError::MalformedWebhookBody)
        ));
        Ok(())
    }

    #[test]
    fn telegram_secret_and_signed_body_identity_are_both_required()
    -> Result<(), Box<dyn std::error::Error>> {
        let secret = TelegramWebhookSecret::new("telegram_secret-42")?;
        let body = br#"{"update_id":42,"callback_query":{"id":"callback-1","from":{"id":123456},"data":"opaque"}}"#;
        let actor =
            authenticate_telegram_callback(&secret, "telegram_secret-42", "tenant-1", body)?;
        assert_eq!(actor.channel(), ApprovalChannel::Telegram);
        assert_eq!(actor.external_user_id(), "123456");
        assert_eq!(actor.provider_event_id(), "42:callback-1");
        assert!(matches!(
            authenticate_telegram_callback(&secret, "telegram_secret-43", "tenant-1", body),
            Err(ApprovalChannelError::InvalidWebhookAuthentication)
        ));

        let ambiguous = br#"{"update_id":42,"update_id":43,"callback_query":{"id":"callback-1","from":{"id":123456}}}"#;
        assert!(matches!(
            authenticate_telegram_callback(&secret, "telegram_secret-42", "tenant-1", ambiguous,),
            Err(ApprovalChannelError::MalformedWebhookBody)
        ));
        Ok(())
    }

    #[test]
    fn teams_claims_require_exact_identity_audience_and_freshness()
    -> Result<(), Box<dyn std::error::Error>> {
        let expected = TeamsActorExpectation::new(
            "tenant-1".to_owned(),
            "external-1".to_owned(),
            "api://accordlock-approvals".to_owned(),
        )?;
        let actor = authenticate_teams_claims(&teams_claims(), &expected, 200)?;
        assert_eq!(actor.channel(), ApprovalChannel::MicrosoftTeams);
        assert_eq!(actor.provider_event_id(), "teams-token-1");

        let mut wrong_tenant = teams_claims();
        wrong_tenant.tenant_id = "tenant-2".to_owned();
        assert!(matches!(
            authenticate_teams_claims(&wrong_tenant, &expected, 200),
            Err(ApprovalChannelError::ActorBindingMismatch)
        ));
        let mut wrong_user = teams_claims();
        wrong_user.external_user_id = "external-2".to_owned();
        assert!(matches!(
            authenticate_teams_claims(&wrong_user, &expected, 200),
            Err(ApprovalChannelError::ActorBindingMismatch)
        ));
        let mut wrong_audience = teams_claims();
        wrong_audience.audience = "api://another-service".to_owned();
        assert!(matches!(
            authenticate_teams_claims(&wrong_audience, &expected, 200),
            Err(ApprovalChannelError::ActorBindingMismatch)
        ));
        assert!(matches!(
            authenticate_teams_claims(&teams_claims(), &expected, 3_700),
            Err(ApprovalChannelError::StaleWebhook)
        ));
        let mut overlong = teams_claims();
        overlong.expires_at += 1;
        assert!(matches!(
            authenticate_teams_claims(&overlong, &expected, 200),
            Err(ApprovalChannelError::StaleWebhook)
        ));
        Ok(())
    }

    #[test]
    fn authenticated_provider_event_cannot_be_substituted() -> Result<(), Box<dyn std::error::Error>>
    {
        let token = token()?;
        let signed = signed(ApprovalChannel::Slack, &token)?;
        let actor = actor(ApprovalChannel::Slack, "signed-event")?;
        let interaction = RemoteApprovalInteraction::new(
            Uuid::from_u128(1),
            token.for_delivery(),
            RemoteApprovalDecision::AllowOnce,
            "substituted-event".to_owned(),
        )?;
        let mut replay = MemoryApprovalReplayStore::default();
        assert!(matches!(
            verify_remote_decision(
                &signed,
                &signer().verifier(),
                &actor,
                &enrollment(ApprovalChannel::Slack),
                &interaction,
                150,
                &mut replay,
            ),
            Err(ApprovalChannelError::InteractionBindingMismatch)
        ));
        Ok(())
    }
}
