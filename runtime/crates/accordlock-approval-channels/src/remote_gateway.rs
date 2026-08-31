//! Framework-neutral inbound adapters for interactive remote approvals.
//!
//! The gateway authenticates an exact provider request, extracts one bounded
//! callback value, resolves its signed challenge from durable state, and
//! returns [`VerifiedRemoteDecision`] evidence. It cannot execute an action or
//! mint an `AccordLock` authorization.

use std::{path::Path, time::Duration};

use accordlock_protocol::{CoseVerifier, Digest32};
use rusqlite::{Connection, ErrorCode, OptionalExtension as _, TransactionBehavior, params};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    ApprovalChannel, ApprovalChannelError, ApprovalReplayStore, ApproverEnrollment,
    AuthenticatedChannelActor, CryptographicallyVerifiedTeamsClaims, InteractionToken,
    MAX_PROVIDER_EVENT_ID_BYTES, MAX_SIGNED_CHALLENGE_BYTES, MetaAppSecret, RemoteApprovalDecision,
    RemoteApprovalInteraction, ReplayStoreError, SignedApprovalChallenge, SlackSigningSecret,
    TeamsActorExpectation, TelegramWebhookSecret, VerifiedRemoteDecision,
    authenticate_slack_interaction, authenticate_teams_claims, authenticate_telegram_callback,
    authenticate_whatsapp_interaction, parse_slack_form_payload, parse_unambiguous_json,
    required_nested_string, required_single_array_item, validate_webhook_body,
    verify_remote_decision,
};

const GATEWAY_SCHEMA_VERSION: i64 = 1;
const GATEWAY_APPLICATION_ID: i64 = 1_095_520_839;
const BUSY_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_STORED_CHALLENGE_JSON_BYTES: usize = 64 * 1024;
const MAX_STORED_ENROLLMENT_JSON_BYTES: usize = 4 * 1024;
const CALLBACK_VALUE_BYTES: usize = 45;

const GATEWAY_SCHEMA: &str = r"
BEGIN IMMEDIATE;
CREATE TABLE remote_approval_callbacks (
    challenge_id TEXT PRIMARY KEY NOT NULL,
    token_hash BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    signed_hash BLOB NOT NULL UNIQUE CHECK (length(signed_hash) = 32),
    challenge_json BLOB NOT NULL CHECK (
        length(challenge_json) > 0 AND length(challenge_json) <= 65536
    ),
    cose_sign1 BLOB NOT NULL CHECK (
        length(cose_sign1) > 0 AND length(cose_sign1) <= 131072
    ),
    enrollment_json BLOB NOT NULL CHECK (
        length(enrollment_json) > 0 AND length(enrollment_json) <= 4096
    ),
    expires_at INTEGER NOT NULL CHECK (expires_at > 0),
    state TEXT NOT NULL CHECK (state IN ('ACTIVE', 'REVOKED', 'CONSUMED')),
    provider_event_id TEXT UNIQUE,
    CHECK (
        (state = 'CONSUMED' AND provider_event_id IS NOT NULL) OR
        (state != 'CONSUMED' AND provider_event_id IS NULL)
    )
) STRICT;
CREATE INDEX remote_approval_callbacks_expiry_idx
    ON remote_approval_callbacks(expires_at);
PRAGMA user_version = 1;
PRAGMA application_id = 1095520839;
COMMIT;
";

/// Result of idempotently registering a signed callback challenge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayRegistrationOutcome {
    Registered,
    AlreadyRegistered,
}

/// Result of revoking a registered callback challenge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayRevocationOutcome {
    Revoked,
    AlreadyRevoked,
    AlreadyConsumed,
}

/// Fail-closed errors returned by the remote-approval gateway boundary.
#[derive(Debug, Error)]
pub enum RemoteApprovalGatewayError {
    #[error(transparent)]
    Approval(#[from] ApprovalChannelError),
    #[error("remote approval callback is not registered")]
    UnknownApproval,
    #[error("remote approval callback was revoked")]
    Revoked,
    #[error("remote approval callback was already consumed")]
    AlreadyConsumed,
    #[error("remote approval callback conflicts with existing durable state")]
    RegistrationConflict,
    #[error("remote approval callback state is malformed")]
    CorruptState,
    #[error("remote approval trusted time is invalid")]
    InvalidTrustedTime,
    #[error("remote approval callback state is unavailable")]
    StorageUnavailable,
}

struct PendingRemoteApproval {
    signed_challenge: SignedApprovalChallenge,
    enrollment: ApproverEnrollment,
}

/// SQLite-backed pending-challenge registry and atomic replay boundary.
///
/// Use a dedicated database path. Only challenge commitments, the signed
/// challenge, enrollment identity, state, and the consumed provider event are
/// persisted. The bearer interaction token and provider credentials are never
/// written to this database.
pub struct DurableRemoteApprovalGateway {
    connection: Connection,
}

impl std::fmt::Debug for DurableRemoteApprovalGateway {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableRemoteApprovalGateway")
            .finish_non_exhaustive()
    }
}

impl DurableRemoteApprovalGateway {
    /// Opens or creates the dedicated callback database without migrating an
    /// unknown schema.
    ///
    /// # Errors
    ///
    /// Returns `StorageUnavailable` when the file, `SQLite` configuration, or
    /// schema cannot be trusted.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RemoteApprovalGatewayError> {
        let connection =
            Connection::open(path).map_err(|_| RemoteApprovalGatewayError::StorageUnavailable)?;
        connection
            .busy_timeout(BUSY_TIMEOUT)
            .map_err(|_| RemoteApprovalGatewayError::StorageUnavailable)?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA trusted_schema = OFF;",
            )
            .map_err(|_| RemoteApprovalGatewayError::StorageUnavailable)?;
        let version = connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .map_err(|_| RemoteApprovalGatewayError::StorageUnavailable)?;
        let application_id = connection
            .query_row("PRAGMA application_id", [], |row| row.get::<_, i64>(0))
            .map_err(|_| RemoteApprovalGatewayError::StorageUnavailable)?;
        match version {
            0 if application_id == 0 && database_is_empty(&connection)? => connection
                .execute_batch(GATEWAY_SCHEMA)
                .map_err(|_| RemoteApprovalGatewayError::StorageUnavailable)?,
            GATEWAY_SCHEMA_VERSION if application_id == GATEWAY_APPLICATION_ID => {}
            _ => return Err(RemoteApprovalGatewayError::StorageUnavailable),
        }
        validate_gateway_schema(&connection)?;
        connection
            .execute_batch("PRAGMA journal_mode = WAL;")
            .map_err(|_| RemoteApprovalGatewayError::StorageUnavailable)?;
        Ok(Self { connection })
    }

    /// Registers one already-signed challenge and its exact approver binding.
    /// Registration is idempotent only when every persisted commitment is
    /// byte-for-byte identical.
    ///
    /// # Errors
    ///
    /// Refuses invalid signatures, inactive or substituted enrollments,
    /// conflicting records, malformed state, and unavailable storage.
    pub fn register(
        &mut self,
        signed_challenge: &SignedApprovalChallenge,
        enrollment: &ApproverEnrollment,
        verifier: &CoseVerifier,
        trusted_now: i64,
    ) -> Result<GatewayRegistrationOutcome, RemoteApprovalGatewayError> {
        let checked = signed_challenge.verify(verifier, trusted_now)?;
        enrollment.validate()?;
        let challenge = checked.challenge();
        if trusted_now < enrollment.valid_from
            || trusted_now >= enrollment.valid_until
            || enrollment.approver_id != challenge.recipient_id
            || enrollment.channel != challenge.channel
            || enrollment.tenant_id != challenge.tenant_id
        {
            return Err(ApprovalChannelError::ActorBindingMismatch.into());
        }

        let challenge_json = serde_json::to_vec(&signed_challenge.challenge)
            .map_err(|_| RemoteApprovalGatewayError::CorruptState)?;
        let enrollment_json =
            serde_json::to_vec(enrollment).map_err(|_| RemoteApprovalGatewayError::CorruptState)?;
        if challenge_json.is_empty()
            || challenge_json.len() > MAX_STORED_CHALLENGE_JSON_BYTES
            || enrollment_json.is_empty()
            || enrollment_json.len() > MAX_STORED_ENROLLMENT_JSON_BYTES
            || signed_challenge.cose_sign1.is_empty()
            || signed_challenge.cose_sign1.len() > MAX_SIGNED_CHALLENGE_BYTES
        {
            return Err(RemoteApprovalGatewayError::CorruptState);
        }

        let challenge_id = challenge.challenge_id.to_string();
        let token_hash = challenge.interaction_token_hash.as_bytes();
        let signed_hash = checked.signed_hash();
        let insert = self.connection.execute(
            "INSERT INTO remote_approval_callbacks (
                 challenge_id, token_hash, signed_hash, challenge_json,
                 cose_sign1, enrollment_json, expires_at, state,
                 provider_event_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'ACTIVE', NULL)",
            params![
                challenge_id,
                token_hash.as_slice(),
                signed_hash.as_bytes().as_slice(),
                challenge_json,
                &signed_challenge.cose_sign1,
                enrollment_json,
                challenge.expires_at,
            ],
        );
        match insert {
            Ok(1) => Ok(GatewayRegistrationOutcome::Registered),
            Err(error) if is_constraint(&error) => self.classify_registration_conflict(
                challenge.challenge_id,
                challenge.interaction_token_hash,
                signed_hash,
                enrollment,
            ),
            Ok(_) | Err(_) => Err(RemoteApprovalGatewayError::StorageUnavailable),
        }
    }

    /// Revokes a challenge before its callback can be consumed. A concurrent
    /// callback and revocation serialize through an immediate transaction.
    ///
    /// # Errors
    ///
    /// Refuses unknown identifiers, corrupt state, and unavailable storage.
    pub fn revoke(
        &mut self,
        challenge_id: Uuid,
    ) -> Result<GatewayRevocationOutcome, RemoteApprovalGatewayError> {
        if challenge_id.is_nil() {
            return Err(RemoteApprovalGatewayError::UnknownApproval);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| RemoteApprovalGatewayError::StorageUnavailable)?;
        let state = transaction
            .query_row(
                "SELECT state FROM remote_approval_callbacks WHERE challenge_id = ?1",
                params![challenge_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| RemoteApprovalGatewayError::StorageUnavailable)?;
        let outcome = match state.as_deref() {
            Some("ACTIVE") => {
                let changed = transaction
                    .execute(
                        "UPDATE remote_approval_callbacks
                         SET state = 'REVOKED'
                         WHERE challenge_id = ?1 AND state = 'ACTIVE'",
                        params![challenge_id.to_string()],
                    )
                    .map_err(|_| RemoteApprovalGatewayError::StorageUnavailable)?;
                if changed != 1 {
                    return Err(RemoteApprovalGatewayError::StorageUnavailable);
                }
                GatewayRevocationOutcome::Revoked
            }
            Some("REVOKED") => GatewayRevocationOutcome::AlreadyRevoked,
            Some("CONSUMED") => GatewayRevocationOutcome::AlreadyConsumed,
            Some(_) => return Err(RemoteApprovalGatewayError::CorruptState),
            None => return Err(RemoteApprovalGatewayError::UnknownApproval),
        };
        transaction
            .commit()
            .map_err(|_| RemoteApprovalGatewayError::StorageUnavailable)?;
        Ok(outcome)
    }

    /// Removes rows whose signed challenge has expired.
    ///
    /// # Errors
    ///
    /// Refuses invalid trusted time and unavailable storage.
    pub fn prune_expired(&mut self, trusted_now: i64) -> Result<usize, RemoteApprovalGatewayError> {
        if trusted_now < 0 {
            return Err(RemoteApprovalGatewayError::InvalidTrustedTime);
        }
        self.connection
            .execute(
                "DELETE FROM remote_approval_callbacks WHERE expires_at <= ?1",
                params![trusted_now],
            )
            .map_err(|_| RemoteApprovalGatewayError::StorageUnavailable)
    }

    fn classify_registration_conflict(
        &self,
        challenge_id: Uuid,
        token_hash: Digest32,
        signed_hash: Digest32,
        enrollment: &ApproverEnrollment,
    ) -> Result<GatewayRegistrationOutcome, RemoteApprovalGatewayError> {
        let enrollment_json =
            serde_json::to_vec(enrollment).map_err(|_| RemoteApprovalGatewayError::CorruptState)?;
        let existing = self
            .connection
            .query_row(
                "SELECT challenge_id, token_hash, signed_hash, enrollment_json
                 FROM remote_approval_callbacks
                 WHERE challenge_id = ?1 OR token_hash = ?2",
                params![challenge_id.to_string(), token_hash.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| RemoteApprovalGatewayError::StorageUnavailable)?;
        match existing {
            Some((stored_id, stored_token, stored_signed, stored_enrollment))
                if stored_id == challenge_id.to_string()
                    && constant_time_digest_eq(&stored_token, token_hash)
                    && constant_time_digest_eq(&stored_signed, signed_hash)
                    && stored_enrollment == enrollment_json =>
            {
                Ok(GatewayRegistrationOutcome::AlreadyRegistered)
            }
            Some(_) | None => Err(RemoteApprovalGatewayError::RegistrationConflict),
        }
    }

    fn resolve(
        &self,
        token: &InteractionToken,
    ) -> Result<PendingRemoteApproval, RemoteApprovalGatewayError> {
        let token_hash = token.digest();
        let row = self
            .connection
            .query_row(
                "SELECT challenge_id, token_hash, signed_hash, challenge_json,
                        cose_sign1, enrollment_json, expires_at, state
                 FROM remote_approval_callbacks WHERE token_hash = ?1",
                params![token_hash.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, String>(7)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| RemoteApprovalGatewayError::StorageUnavailable)?;
        let Some((
            stored_id,
            stored_token,
            stored_signed_hash,
            challenge_json,
            cose_sign1,
            enrollment_json,
            stored_expires_at,
            state,
        )) = row
        else {
            return Err(RemoteApprovalGatewayError::UnknownApproval);
        };
        match state.as_str() {
            "ACTIVE" => {}
            "REVOKED" => return Err(RemoteApprovalGatewayError::Revoked),
            "CONSUMED" => return Err(RemoteApprovalGatewayError::AlreadyConsumed),
            _ => return Err(RemoteApprovalGatewayError::CorruptState),
        }
        if challenge_json.is_empty()
            || challenge_json.len() > MAX_STORED_CHALLENGE_JSON_BYTES
            || cose_sign1.is_empty()
            || cose_sign1.len() > MAX_SIGNED_CHALLENGE_BYTES
            || enrollment_json.is_empty()
            || enrollment_json.len() > MAX_STORED_ENROLLMENT_JSON_BYTES
            || !constant_time_digest_eq(&stored_token, token_hash)
        {
            return Err(RemoteApprovalGatewayError::CorruptState);
        }
        let challenge = serde_json::from_slice(&challenge_json)
            .map_err(|_| RemoteApprovalGatewayError::CorruptState)?;
        let enrollment = serde_json::from_slice::<ApproverEnrollment>(&enrollment_json)
            .map_err(|_| RemoteApprovalGatewayError::CorruptState)?;
        let signed_challenge = SignedApprovalChallenge {
            challenge,
            cose_sign1,
        };
        if signed_challenge.challenge.challenge_id.to_string() != stored_id
            || signed_challenge.challenge.expires_at != stored_expires_at
            || !constant_time_digest_eq(&stored_signed_hash, signed_challenge.digest()?)
            || signed_challenge.challenge.interaction_token_hash != token_hash
        {
            return Err(RemoteApprovalGatewayError::CorruptState);
        }
        Ok(PendingRemoteApproval {
            signed_challenge,
            enrollment,
        })
    }
}

impl ApprovalReplayStore for DurableRemoteApprovalGateway {
    fn consume(
        &mut self,
        challenge_id: Uuid,
        provider_event_id: &str,
        expires_at: i64,
    ) -> Result<(), ReplayStoreError> {
        if challenge_id.is_nil()
            || expires_at <= 0
            || provider_event_id.is_empty()
            || provider_event_id.len() > MAX_PROVIDER_EVENT_ID_BYTES
            || provider_event_id.chars().any(char::is_control)
        {
            return Err(ReplayStoreError::InvalidInput);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ReplayStoreError::Unavailable)?;
        let row = transaction
            .query_row(
                "SELECT state, expires_at FROM remote_approval_callbacks
                 WHERE challenge_id = ?1",
                params![challenge_id.to_string()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(|_| ReplayStoreError::Unavailable)?;
        let Some((state, stored_expires_at)) = row else {
            return Err(ReplayStoreError::UnknownChallenge);
        };
        if stored_expires_at != expires_at {
            return Err(ReplayStoreError::InvalidInput);
        }
        match state.as_str() {
            "ACTIVE" => {}
            "REVOKED" => return Err(ReplayStoreError::Revoked),
            "CONSUMED" => return Err(ReplayStoreError::AlreadyConsumed),
            _ => return Err(ReplayStoreError::Unavailable),
        }
        let changed = transaction
            .execute(
                "UPDATE remote_approval_callbacks
                 SET state = 'CONSUMED', provider_event_id = ?1
                 WHERE challenge_id = ?2 AND state = 'ACTIVE'",
                params![provider_event_id, challenge_id.to_string()],
            )
            .map_err(|error| {
                if is_constraint(&error) {
                    ReplayStoreError::AlreadyConsumed
                } else {
                    ReplayStoreError::Unavailable
                }
            })?;
        if changed != 1 {
            return Err(ReplayStoreError::Unavailable);
        }
        transaction
            .commit()
            .map_err(|_| ReplayStoreError::Unavailable)
    }
}

/// Authenticates and consumes one Slack block-action callback.
///
/// # Errors
///
/// Refuses unauthenticated, malformed, expired, revoked, replayed, or
/// incorrectly bound callbacks and unavailable durable state.
#[allow(clippy::too_many_arguments)]
pub fn process_slack_callback(
    secret: &SlackSigningSecret,
    trusted_now: i64,
    timestamp_header: &str,
    signature_header: &str,
    raw_body: &[u8],
    verifier: &CoseVerifier,
    gateway: &mut DurableRemoteApprovalGateway,
) -> Result<VerifiedRemoteDecision, RemoteApprovalGatewayError> {
    let actor = authenticate_slack_interaction(
        secret,
        trusted_now,
        timestamp_header,
        signature_header,
        raw_body,
    )?;
    let payload = parse_slack_form_payload(raw_body)?;
    let value = parse_unambiguous_json(&payload)?;
    if required_nested_string(&value, &["type"])? != "block_actions" {
        return Err(ApprovalChannelError::MalformedWebhookBody.into());
    }
    let action = required_single_array_item(&value, "actions")?;
    if required_nested_string(action, &["type"])? != "button" {
        return Err(ApprovalChannelError::MalformedWebhookBody.into());
    }
    let parsed = parse_callback_value(required_nested_string(action, &["value"])?)?;
    let expected_action_id = format!(
        "accordlock_{}",
        callback_code(parsed.decision).to_ascii_lowercase()
    );
    if required_nested_string(action, &["action_id"])? != expected_action_id {
        return Err(ApprovalChannelError::MalformedWebhookBody.into());
    }
    compose_decision(&actor, &parsed, verifier, trusted_now, gateway)
}

/// Authenticates and consumes one Telegram callback query.
///
/// # Errors
///
/// Refuses unauthenticated, malformed, expired, revoked, replayed, or
/// incorrectly bound callbacks and unavailable durable state.
#[allow(clippy::too_many_arguments)]
pub fn process_telegram_callback(
    secret: &TelegramWebhookSecret,
    secret_header: &str,
    tenant_id: &str,
    raw_body: &[u8],
    verifier: &CoseVerifier,
    trusted_now: i64,
    gateway: &mut DurableRemoteApprovalGateway,
) -> Result<VerifiedRemoteDecision, RemoteApprovalGatewayError> {
    let actor = authenticate_telegram_callback(secret, secret_header, tenant_id, raw_body)?;
    let value = parse_unambiguous_json(raw_body)?;
    let callback = value
        .get("callback_query")
        .ok_or(ApprovalChannelError::MalformedWebhookBody)?;
    let parsed = parse_callback_value(required_nested_string(callback, &["data"])?)?;
    compose_decision(&actor, &parsed, verifier, trusted_now, gateway)
}

/// Authenticates and consumes one `WhatsApp` interactive list reply.
///
/// # Errors
///
/// Refuses unauthenticated, malformed, expired, revoked, replayed, or
/// incorrectly bound callbacks and unavailable durable state.
pub fn process_whatsapp_callback(
    secret: &MetaAppSecret,
    signature_header: &str,
    raw_body: &[u8],
    verifier: &CoseVerifier,
    trusted_now: i64,
    gateway: &mut DurableRemoteApprovalGateway,
) -> Result<VerifiedRemoteDecision, RemoteApprovalGatewayError> {
    let actor = authenticate_whatsapp_interaction(secret, signature_header, raw_body)?;
    let value = parse_unambiguous_json(raw_body)?;
    let entry = required_single_array_item(&value, "entry")?;
    let change = required_single_array_item(entry, "changes")?;
    let change_value = change
        .get("value")
        .ok_or(ApprovalChannelError::MalformedWebhookBody)?;
    let message = required_single_array_item(change_value, "messages")?;
    if required_nested_string(message, &["type"])? != "interactive"
        || required_nested_string(message, &["interactive", "type"])? != "list_reply"
    {
        return Err(ApprovalChannelError::MalformedWebhookBody.into());
    }
    let parsed = parse_callback_value(required_nested_string(
        message,
        &["interactive", "list_reply", "id"],
    )?)?;
    compose_decision(&actor, &parsed, verifier, trusted_now, gateway)
}

/// Consumes a Teams Activity only after a host-provided cryptographic token
/// verifier has produced trusted claims. The activity tenant and actor must
/// exactly repeat the verified claims.
///
/// # Errors
///
/// Refuses unverified or mismatched claims, malformed Activities, expired,
/// revoked, replayed, or incorrectly bound callbacks, and unavailable state.
#[allow(clippy::too_many_arguments)]
pub fn process_teams_callback(
    claims: &impl CryptographicallyVerifiedTeamsClaims,
    expected: &TeamsActorExpectation,
    raw_body: &[u8],
    verifier: &CoseVerifier,
    trusted_now: i64,
    gateway: &mut DurableRemoteApprovalGateway,
) -> Result<VerifiedRemoteDecision, RemoteApprovalGatewayError> {
    validate_webhook_body(raw_body)?;
    let claims_actor = authenticate_teams_claims(claims, expected, trusted_now)?;
    let value = parse_unambiguous_json(raw_body)?;
    let event_id = required_nested_string(&value, &["id"])?;
    if required_nested_string(&value, &["conversation", "tenantId"])? != claims_actor.tenant_id()
        || required_nested_string(&value, &["from", "aadObjectId"])?
            != claims_actor.external_user_id()
    {
        return Err(ApprovalChannelError::ActorBindingMismatch.into());
    }
    let activity_type = required_nested_string(&value, &["type"])?;
    let data = match activity_type {
        "message" => value
            .get("value")
            .ok_or(ApprovalChannelError::MalformedWebhookBody)?,
        "invoke" => {
            if required_nested_string(&value, &["name"])? != "adaptiveCard/action" {
                return Err(ApprovalChannelError::MalformedWebhookBody.into());
            }
            value
                .get("value")
                .and_then(|entry| entry.get("action"))
                .and_then(|entry| entry.get("data"))
                .ok_or(ApprovalChannelError::MalformedWebhookBody)?
        }
        _ => return Err(ApprovalChannelError::MalformedWebhookBody.into()),
    };
    let token = required_nested_string(data, &["accordlock_token"])?;
    let decision = parse_decision_code(required_nested_string(data, &["accordlock_decision"])?)?;
    let parsed = ParsedCallback {
        token: InteractionToken::parse(token)?,
        decision,
    };
    let actor = AuthenticatedChannelActor::verified(
        ApprovalChannel::MicrosoftTeams,
        claims_actor.tenant_id().to_owned(),
        claims_actor.external_user_id().to_owned(),
        event_id.to_owned(),
    )?;
    compose_decision(&actor, &parsed, verifier, trusted_now, gateway)
}

struct ParsedCallback {
    token: InteractionToken,
    decision: RemoteApprovalDecision,
}

fn compose_decision(
    actor: &AuthenticatedChannelActor,
    parsed: &ParsedCallback,
    verifier: &CoseVerifier,
    trusted_now: i64,
    gateway: &mut DurableRemoteApprovalGateway,
) -> Result<VerifiedRemoteDecision, RemoteApprovalGatewayError> {
    let pending = gateway.resolve(&parsed.token)?;
    let interaction = RemoteApprovalInteraction::new(
        pending.signed_challenge.challenge.challenge_id,
        parsed.token.for_delivery(),
        parsed.decision,
        actor.provider_event_id().to_owned(),
    )?;
    verify_remote_decision(
        &pending.signed_challenge,
        verifier,
        actor,
        &pending.enrollment,
        &interaction,
        trusted_now,
        gateway,
    )
    .map_err(map_decision_error)
}

fn parse_callback_value(value: &str) -> Result<ParsedCallback, ApprovalChannelError> {
    if value.len() != CALLBACK_VALUE_BYTES || !value.is_ascii() {
        return Err(ApprovalChannelError::MalformedInteraction);
    }
    let (token, decision) = value
        .split_once('.')
        .ok_or(ApprovalChannelError::MalformedInteraction)?;
    if decision.contains('.') {
        return Err(ApprovalChannelError::MalformedInteraction);
    }
    Ok(ParsedCallback {
        token: InteractionToken::parse(token)?,
        decision: parse_decision_code(decision)?,
    })
}

fn parse_decision_code(value: &str) -> Result<RemoteApprovalDecision, ApprovalChannelError> {
    match value {
        "A" => Ok(RemoteApprovalDecision::AllowOnce),
        "D" => Ok(RemoteApprovalDecision::DenyAction),
        "S" => Ok(RemoteApprovalDecision::StopTask),
        "R" => Ok(RemoteApprovalDecision::RevokeTaskAccess),
        _ => Err(ApprovalChannelError::MalformedInteraction),
    }
}

const fn callback_code(decision: RemoteApprovalDecision) -> &'static str {
    match decision {
        RemoteApprovalDecision::AllowOnce => "A",
        RemoteApprovalDecision::DenyAction => "D",
        RemoteApprovalDecision::StopTask => "S",
        RemoteApprovalDecision::RevokeTaskAccess => "R",
    }
}

fn map_decision_error(error: ApprovalChannelError) -> RemoteApprovalGatewayError {
    match error {
        ApprovalChannelError::ReplayStore(ReplayStoreError::Revoked) => {
            RemoteApprovalGatewayError::Revoked
        }
        ApprovalChannelError::ReplayStore(ReplayStoreError::AlreadyConsumed) => {
            RemoteApprovalGatewayError::AlreadyConsumed
        }
        ApprovalChannelError::ReplayStore(ReplayStoreError::UnknownChallenge) => {
            RemoteApprovalGatewayError::UnknownApproval
        }
        ApprovalChannelError::ReplayStore(ReplayStoreError::Unavailable) => {
            RemoteApprovalGatewayError::StorageUnavailable
        }
        ApprovalChannelError::ReplayStore(ReplayStoreError::InvalidInput) => {
            RemoteApprovalGatewayError::CorruptState
        }
        other => RemoteApprovalGatewayError::Approval(other),
    }
}

fn constant_time_digest_eq(value: &[u8], expected: Digest32) -> bool {
    value.len() == expected.as_bytes().len()
        && bool::from(value.ct_eq(expected.as_bytes().as_slice()))
}

fn is_constraint(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(inner, _)
            if inner.code == ErrorCode::ConstraintViolation
    )
}

fn database_is_empty(connection: &Connection) -> Result<bool, RemoteApprovalGatewayError> {
    connection
        .query_row(
            "SELECT NOT EXISTS (
                 SELECT 1 FROM sqlite_schema
                 WHERE name NOT LIKE 'sqlite_%'
             )",
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|_| RemoteApprovalGatewayError::StorageUnavailable)
}

fn validate_gateway_schema(connection: &Connection) -> Result<(), RemoteApprovalGatewayError> {
    connection
        .prepare(
            "SELECT challenge_id, token_hash, signed_hash, challenge_json,
                    cose_sign1, enrollment_json, expires_at, state,
                    provider_event_id
             FROM remote_approval_callbacks LIMIT 0",
        )
        .map(|_| ())
        .map_err(|_| RemoteApprovalGatewayError::StorageUnavailable)
}

#[cfg(test)]
mod tests {
    use accordlock_protocol::SigningIdentity;
    use hmac::{Hmac, Mac as _};
    use serde_json::{Value, json};
    use sha2::Sha256;

    use super::*;
    use crate::{
        APPROVAL_CHANNEL_SCHEMA_VERSION, ApprovalChallenge, ApprovalPrompt, ApprovalSubject,
    };

    type HmacSha256 = Hmac<Sha256>;

    fn signer() -> SigningIdentity {
        SigningIdentity::from_seed("approval-channel-key", [9; 32])
    }

    fn digest(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
    }

    fn token() -> Result<InteractionToken, ApprovalChannelError> {
        InteractionToken::parse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    }

    fn signed(
        channel: ApprovalChannel,
        interaction_token: &InteractionToken,
    ) -> Result<SignedApprovalChallenge, ApprovalChannelError> {
        let prompt = ApprovalPrompt {
            title: "Review action".to_owned(),
            summary: "A protected change is waiting.".to_owned(),
            project: Some("Payments".to_owned()),
            review_url: "https://review.accordlock.example/requests/42".to_owned(),
        };
        SignedApprovalChallenge::sign(
            ApprovalChallenge {
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
                prompt_hash: prompt.digest()?,
                interaction_token_hash: interaction_token.digest(),
                channel,
                tenant_id: "tenant-1".to_owned(),
                recipient_id: "approver-1".to_owned(),
                delivery_destination_hash: Digest32::sha256(b"destination-1"),
                allowed_decisions: vec![
                    RemoteApprovalDecision::AllowOnce,
                    RemoteApprovalDecision::DenyAction,
                    RemoteApprovalDecision::StopTask,
                    RemoteApprovalDecision::RevokeTaskAccess,
                ],
                issued_at: 100,
                expires_at: 200,
                key_id: "approval-channel-key".to_owned(),
            },
            &signer(),
        )
    }

    fn enrollment(channel: ApprovalChannel) -> ApproverEnrollment {
        ApproverEnrollment {
            approver_id: "approver-1".to_owned(),
            channel,
            tenant_id: "tenant-1".to_owned(),
            external_user_id: if channel == ApprovalChannel::Telegram {
                "123456".to_owned()
            } else {
                "external-1".to_owned()
            },
            valid_from: 50,
            valid_until: 300,
        }
    }

    fn gateway(
        channel: ApprovalChannel,
    ) -> Result<(tempfile::TempDir, DurableRemoteApprovalGateway), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let mut gateway = DurableRemoteApprovalGateway::open(root.path().join("gateway.sqlite3"))?;
        let interaction_token = token()?;
        gateway.register(
            &signed(channel, &interaction_token)?,
            &enrollment(channel),
            &signer().verifier(),
            150,
        )?;
        Ok((root, gateway))
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

    struct TestTeamsClaims;

    impl CryptographicallyVerifiedTeamsClaims for TestTeamsClaims {
        fn tenant_id(&self) -> &'static str {
            "tenant-1"
        }

        fn external_user_id(&self) -> &'static str {
            "external-1"
        }

        fn audience(&self) -> &'static str {
            "api://accordlock-approvals"
        }

        fn token_id(&self) -> &'static str {
            "oidc-token-jti"
        }

        fn not_before(&self) -> i64 {
            100
        }

        fn expires_at(&self) -> i64 {
            300
        }
    }

    #[test]
    fn slack_callback_resolves_and_consumes_exactly_once() -> Result<(), Box<dyn std::error::Error>>
    {
        let (root, mut gateway) = gateway(ApprovalChannel::Slack)?;
        let secret_bytes = b"0123456789abcdef0123456789abcdef";
        let secret = SlackSigningSecret::from_bytes(secret_bytes)?;
        let body = percent_encode_json(&json!({
            "type": "block_actions",
            "team": {"id": "tenant-1"},
            "user": {"id": "external-1"},
            "trigger_id": "slack-event-1",
            "actions": [{
                "type": "button",
                "action_id": "accordlock_a",
                "value": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.A"
            }]
        }))?;
        let signature = slack_signature(secret_bytes, "150", &body)?;
        let decision = process_slack_callback(
            &secret,
            150,
            "150",
            &signature,
            &body,
            &signer().verifier(),
            &mut gateway,
        )?;
        assert_eq!(decision.decision(), RemoteApprovalDecision::AllowOnce);
        assert_eq!(decision.provider_event_id(), "slack-event-1");
        drop(gateway);
        let mut gateway = DurableRemoteApprovalGateway::open(root.path().join("gateway.sqlite3"))?;
        assert!(matches!(
            process_slack_callback(
                &secret,
                150,
                "150",
                &signature,
                &body,
                &signer().verifier(),
                &mut gateway,
            ),
            Err(RemoteApprovalGatewayError::AlreadyConsumed)
        ));
        Ok(())
    }

    #[test]
    fn telegram_wrong_actor_and_revocation_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let (_root, mut active_gateway) = gateway(ApprovalChannel::Telegram)?;
        let secret = TelegramWebhookSecret::new("telegram_secret-42")?;
        let wrong_actor = br#"{"update_id":42,"callback_query":{"id":"callback-1","from":{"id":999},"data":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.D"}}"#;
        assert!(matches!(
            process_telegram_callback(
                &secret,
                "telegram_secret-42",
                "tenant-1",
                wrong_actor,
                &signer().verifier(),
                150,
                &mut active_gateway,
            ),
            Err(RemoteApprovalGatewayError::Approval(
                ApprovalChannelError::ActorBindingMismatch
            ))
        ));

        let valid = br#"{"update_id":43,"callback_query":{"id":"callback-2","from":{"id":123456},"data":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.D"}}"#;
        let decision = process_telegram_callback(
            &secret,
            "telegram_secret-42",
            "tenant-1",
            valid,
            &signer().verifier(),
            150,
            &mut active_gateway,
        )?;
        assert_eq!(decision.decision(), RemoteApprovalDecision::DenyAction);

        let (_other_root, mut revoked_gateway) = gateway(ApprovalChannel::Telegram)?;
        assert_eq!(
            revoked_gateway.revoke(Uuid::from_u128(1))?,
            GatewayRevocationOutcome::Revoked
        );
        assert!(matches!(
            process_telegram_callback(
                &secret,
                "telegram_secret-42",
                "tenant-1",
                valid,
                &signer().verifier(),
                150,
                &mut revoked_gateway,
            ),
            Err(RemoteApprovalGatewayError::Revoked)
        ));
        Ok(())
    }

    #[test]
    fn whatsapp_and_teams_exact_adapters_return_evidence() -> Result<(), Box<dyn std::error::Error>>
    {
        let (_root, mut whatsapp_gateway) = gateway(ApprovalChannel::WhatsApp)?;
        let secret_bytes = b"abcdef0123456789abcdef0123456789";
        let secret = MetaAppSecret::from_bytes(secret_bytes)?;
        let body = br#"{"object":"whatsapp_business_account","entry":[{"id":"tenant-1","changes":[{"field":"messages","value":{"messaging_product":"whatsapp","messages":[{"from":"external-1","id":"wamid.event-1","type":"interactive","interactive":{"type":"list_reply","list_reply":{"id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.S"}}}]}}]}]}"#;
        let signature = meta_signature(secret_bytes, body)?;
        assert_eq!(
            process_whatsapp_callback(
                &secret,
                &signature,
                body,
                &signer().verifier(),
                150,
                &mut whatsapp_gateway,
            )?
            .decision(),
            RemoteApprovalDecision::StopTask
        );

        let (_root, mut teams_gateway) = gateway(ApprovalChannel::MicrosoftTeams)?;
        let expected = TeamsActorExpectation::new(
            "tenant-1".to_owned(),
            "external-1".to_owned(),
            "api://accordlock-approvals".to_owned(),
        )?;
        let teams_body = br#"{"type":"message","id":"teams-activity-1","conversation":{"tenantId":"tenant-1"},"from":{"aadObjectId":"external-1"},"value":{"accordlock_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","accordlock_decision":"R"}}"#;
        let evidence = process_teams_callback(
            &TestTeamsClaims,
            &expected,
            teams_body,
            &signer().verifier(),
            150,
            &mut teams_gateway,
        )?;
        assert_eq!(
            evidence.decision(),
            RemoteApprovalDecision::RevokeTaskAccess
        );
        assert_eq!(evidence.provider_event_id(), "teams-activity-1");
        Ok(())
    }

    #[test]
    fn expiry_tamper_and_callback_ambiguity_are_refused() -> Result<(), Box<dyn std::error::Error>>
    {
        let (_root, mut gateway) = gateway(ApprovalChannel::Slack)?;
        let secret_bytes = b"0123456789abcdef0123456789abcdef";
        let secret = SlackSigningSecret::from_bytes(secret_bytes)?;
        let body = percent_encode_json(&json!({
            "type": "block_actions",
            "team": {"id": "tenant-1"},
            "user": {"id": "external-1"},
            "trigger_id": "slack-event-2",
            "actions": [{
                "type": "button",
                "action_id": "accordlock_d",
                "value": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.A"
            }]
        }))?;
        let signature = slack_signature(secret_bytes, "150", &body)?;
        assert!(matches!(
            process_slack_callback(
                &secret,
                150,
                "150",
                &signature,
                &body,
                &signer().verifier(),
                &mut gateway,
            ),
            Err(RemoteApprovalGatewayError::Approval(
                ApprovalChannelError::MalformedWebhookBody
            ))
        ));

        let valid = percent_encode_json(&json!({
            "type": "block_actions",
            "team": {"id": "tenant-1"},
            "user": {"id": "external-1"},
            "trigger_id": "slack-event-3",
            "actions": [{
                "type": "button",
                "action_id": "accordlock_a",
                "value": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.A"
            }]
        }))?;
        let expired_signature = slack_signature(secret_bytes, "200", &valid)?;
        assert!(matches!(
            process_slack_callback(
                &secret,
                200,
                "200",
                &expired_signature,
                &valid,
                &signer().verifier(),
                &mut gateway,
            ),
            Err(RemoteApprovalGatewayError::Approval(
                ApprovalChannelError::ExpiredChallenge
            ))
        ));
        Ok(())
    }

    #[test]
    fn durable_state_survives_reopen_and_registration_is_exactly_idempotent()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("gateway.sqlite3");
        let interaction_token = token()?;
        let signed = signed(ApprovalChannel::Slack, &interaction_token)?;
        {
            let mut gateway = DurableRemoteApprovalGateway::open(&path)?;
            assert_eq!(
                gateway.register(
                    &signed,
                    &enrollment(ApprovalChannel::Slack),
                    &signer().verifier(),
                    150,
                )?,
                GatewayRegistrationOutcome::Registered
            );
            assert_eq!(
                gateway.register(
                    &signed,
                    &enrollment(ApprovalChannel::Slack),
                    &signer().verifier(),
                    150,
                )?,
                GatewayRegistrationOutcome::AlreadyRegistered
            );
        }
        let mut reopened = DurableRemoteApprovalGateway::open(&path)?;
        assert_eq!(
            reopened.revoke(Uuid::from_u128(1))?,
            GatewayRevocationOutcome::Revoked
        );
        drop(reopened);
        let mut reopened = DurableRemoteApprovalGateway::open(&path)?;
        assert_eq!(
            reopened.revoke(Uuid::from_u128(1))?,
            GatewayRevocationOutcome::AlreadyRevoked
        );
        Ok(())
    }

    #[test]
    fn pruning_uses_trusted_expiry_and_teams_body_is_bounded()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_root, mut gateway) = gateway(ApprovalChannel::MicrosoftTeams)?;
        assert!(matches!(
            gateway.prune_expired(-1),
            Err(RemoteApprovalGatewayError::InvalidTrustedTime)
        ));
        assert_eq!(gateway.prune_expired(199)?, 0);

        let expected = TeamsActorExpectation::new(
            "tenant-1".to_owned(),
            "external-1".to_owned(),
            "api://accordlock-approvals".to_owned(),
        )?;
        let oversized = vec![b' '; crate::MAX_WEBHOOK_BODY_BYTES + 1];
        assert!(matches!(
            process_teams_callback(
                &TestTeamsClaims,
                &expected,
                &oversized,
                &signer().verifier(),
                150,
                &mut gateway,
            ),
            Err(RemoteApprovalGatewayError::Approval(
                ApprovalChannelError::MalformedWebhookBody
            ))
        ));
        assert_eq!(gateway.prune_expired(200)?, 1);
        Ok(())
    }

    #[test]
    fn unknown_database_is_rejected_without_modification() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = tempfile::tempdir()?;
        let path = root.path().join("unrelated.sqlite3");
        let connection = Connection::open(&path)?;
        connection.execute_batch(
            "CREATE TABLE preserved (value TEXT NOT NULL);
             INSERT INTO preserved(value) VALUES ('keep');
             PRAGMA user_version = 1;",
        )?;
        drop(connection);
        assert!(matches!(
            DurableRemoteApprovalGateway::open(&path),
            Err(RemoteApprovalGatewayError::StorageUnavailable)
        ));
        let connection = Connection::open(&path)?;
        assert_eq!(
            connection.query_row("SELECT value FROM preserved", [], |row| row
                .get::<_, String>(0))?,
            "keep"
        );
        Ok(())
    }
}
