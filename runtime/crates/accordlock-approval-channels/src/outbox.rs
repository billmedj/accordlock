use std::fmt;
use std::path::Path;
use std::time::Duration;

use accordlock_protocol::Digest32;
use hmac::{Hmac, Mac as _};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom as _, SystemRandom};
use rusqlite::limits::Limit;
use rusqlite::{
    Connection, ErrorCode, OptionalExtension as _, Transaction, TransactionBehavior, params,
};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize as _, Zeroizing};

use crate::ApprovalChannel;

const DATABASE_SCHEMA_VERSION: i64 = 1;
const DATABASE_SCHEMA_VERSION_U16: u16 = 1;
const BUSY_TIMEOUT: Duration = Duration::from_secs(2);
const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const HASH_BYTES: usize = 32;
const LEASE_TOKEN_BYTES: usize = 32;
const AEAD_TAG_BYTES: usize = 16;
const ENVELOPE_HEADER_BYTES: usize = 12;

const MAX_DESTINATION_BYTES: usize = 4 * 1_024;
const MAX_PAYLOAD_BYTES: usize = 256 * 1_024;
const MAX_CREDENTIAL_REFERENCE_BYTES: usize = 16 * 1_024;
const MAX_IDEMPOTENCY_BYTES: usize = 256;
const MAX_CIPHERTEXT_BYTES: usize = MAX_DESTINATION_BYTES
    + MAX_PAYLOAD_BYTES
    + MAX_CREDENTIAL_REFERENCE_BYTES
    + ENVELOPE_HEADER_BYTES
    + AEAD_TAG_BYTES;
const MAX_ATTEMPTS: u8 = 16;
const MAX_LEASE_SECONDS: i64 = 60 * 60;
const MAX_RETRY_DELAY_SECONDS: i64 = 24 * 60 * 60;
const MAX_PRUNE_LIMIT: u32 = 1_000;
const MAX_STORED_JOBS: i64 = 100_000;
const MAX_EXPIRED_TRANSITIONS_PER_CLAIM: usize = 64;
const MAX_SQLITE_VALUE_BYTES: i32 = 512 * 1_024;

const JOB_AAD_DOMAIN: &[u8] = b"accordlock:v1:approval-delivery-outbox";
const KEY_CHECK_AAD: &[u8] = b"accordlock:v1:approval-delivery-outbox:key-check";
const KEY_CHECK_PLAINTEXT: &[u8] = b"accordlock-outbox-key-check-v1";
const DESTINATION_HASH_DOMAIN: &[u8] = b"accordlock:v1:outbox-destination";
const IDEMPOTENCY_HASH_DOMAIN: &[u8] = b"accordlock:v1:outbox-idempotency";
const REQUEST_HASH_DOMAIN: &[u8] = b"accordlock:v1:outbox-request";
const LEASE_HASH_DOMAIN: &[u8] = b"accordlock:v1:outbox-lease";
const STATE_MAC_KEY_DOMAIN: &[u8] = b"accordlock:v1:outbox-state-mac-key";
const STATE_MAC_DOMAIN: &[u8] = b"accordlock:v1:outbox-state";
const METADATA_HASH_KEY_DOMAIN: &[u8] = b"accordlock:v1:outbox-metadata-hash-key";

type StateHmac = Hmac<Sha256>;

const META_TABLE_SQL: &str = r"CREATE TABLE outbox_meta (
    schema_version INTEGER PRIMARY KEY NOT NULL CHECK (schema_version = 1),
    key_check_nonce BLOB NOT NULL CHECK (length(key_check_nonce) = 12),
    key_check_ciphertext BLOB NOT NULL CHECK (length(key_check_ciphertext) = 46)
) STRICT";

const JOB_TABLE_SQL: &str = r"CREATE TABLE delivery_outbox (
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    job_id BLOB PRIMARY KEY NOT NULL CHECK (length(job_id) = 16),
    channel INTEGER NOT NULL CHECK (channel BETWEEN 0 AND 3),
    destination_hash BLOB NOT NULL CHECK (length(destination_hash) = 32),
    idempotency_hash BLOB NOT NULL UNIQUE CHECK (length(idempotency_hash) = 32),
    request_hash BLOB NOT NULL CHECK (length(request_hash) = 32),
    nonce BLOB NOT NULL CHECK (length(nonce) = 12),
    ciphertext BLOB NOT NULL CHECK (length(ciphertext) BETWEEN 31 AND 282652),
    state INTEGER NOT NULL CHECK (state BETWEEN 0 AND 4),
    attempts INTEGER NOT NULL CHECK (attempts BETWEEN 0 AND 16),
    max_attempts INTEGER NOT NULL CHECK (max_attempts BETWEEN 1 AND 16),
    available_at INTEGER NOT NULL CHECK (available_at >= 0),
    lease_expires_at INTEGER,
    lease_token_hash BLOB,
    completion_token_hash BLOB,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= 0),
    delivered_at INTEGER,
    terminal_reason INTEGER,
    attempt_summary_hash BLOB,
    state_mac BLOB NOT NULL CHECK (length(state_mac) = 32),
    CHECK (attempts <= max_attempts),
    CHECK (lease_expires_at IS NULL OR lease_expires_at >= 0),
    CHECK (lease_token_hash IS NULL OR length(lease_token_hash) = 32),
    CHECK (completion_token_hash IS NULL OR length(completion_token_hash) = 32),
    CHECK (delivered_at IS NULL OR delivered_at >= 0),
    CHECK (terminal_reason IS NULL OR terminal_reason BETWEEN 0 AND 6),
    CHECK (attempt_summary_hash IS NULL OR length(attempt_summary_hash) = 32),
    CHECK (
        (state = 1 AND lease_expires_at IS NOT NULL AND lease_token_hash IS NOT NULL
            AND completion_token_hash IS NULL AND delivered_at IS NULL
            AND terminal_reason IS NULL AND attempt_summary_hash IS NULL)
        OR (state = 2 AND lease_expires_at IS NULL AND lease_token_hash IS NULL
            AND completion_token_hash IS NOT NULL AND delivered_at IS NOT NULL
            AND terminal_reason IS NULL AND attempt_summary_hash IS NULL)
        OR (state IN (0, 3) AND lease_expires_at IS NULL AND lease_token_hash IS NULL
            AND completion_token_hash IS NULL AND delivered_at IS NULL
            AND terminal_reason IS NULL AND attempt_summary_hash IS NULL)
        OR (state = 4 AND lease_expires_at IS NULL AND lease_token_hash IS NULL
            AND completion_token_hash IS NOT NULL AND delivered_at IS NULL
            AND terminal_reason IS NOT NULL)
    )
) STRICT";

const READY_INDEX_SQL: &str = r"CREATE INDEX delivery_outbox_ready_idx
ON delivery_outbox(state, available_at, lease_expires_at, created_at)";
const TERMINAL_INDEX_SQL: &str = r"CREATE INDEX delivery_outbox_terminal_idx
ON delivery_outbox(state, updated_at)";

/// A 256-bit key used only to protect one local delivery-outbox database.
///
/// The key is never formatted or persisted by this crate. The trusted host is
/// responsible for loading it from OS-backed secure storage.
pub struct OutboxEncryptionKey([u8; KEY_BYTES]);

impl OutboxEncryptionKey {
    /// Generates a key with the operating system random source.
    ///
    /// # Errors
    ///
    /// Returns [`OutboxError::EntropyUnavailable`] if secure randomness is not
    /// available.
    pub fn generate() -> Result<Self, OutboxError> {
        let random = SystemRandom::new();
        let mut bytes = [0_u8; KEY_BYTES];
        if random.fill(&mut bytes).is_err() {
            bytes.zeroize();
            return Err(OutboxError::EntropyUnavailable);
        }
        Ok(Self(bytes))
    }

    /// Imports an exact 32-byte key supplied by the trusted host.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        Self(bytes)
    }

    fn expose(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }
}

impl fmt::Debug for OutboxEncryptionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OutboxEncryptionKey([REDACTED])")
    }
}

impl Drop for OutboxEncryptionKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// An opaque, single-lease acknowledgement capability.
pub struct LeaseToken([u8; LEASE_TOKEN_BYTES]);

impl LeaseToken {
    fn generate(random: &SystemRandom) -> Result<Self, OutboxError> {
        let mut bytes = [0_u8; LEASE_TOKEN_BYTES];
        if random.fill(&mut bytes).is_err() {
            bytes.zeroize();
            return Err(OutboxError::EntropyUnavailable);
        }
        Ok(Self(bytes))
    }

    fn expose(&self) -> &[u8; LEASE_TOKEN_BYTES] {
        &self.0
    }
}

impl fmt::Debug for LeaseToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LeaseToken([REDACTED])")
    }
}

impl Drop for LeaseToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct SecretBytes(Vec<u8>);

impl SecretBytes {
    fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A bounded request to place one provider-neutral delivery in the outbox.
pub struct EnqueueRequest<'a> {
    pub channel: ApprovalChannel,
    pub destination: &'a [u8],
    pub payload: &'a [u8],
    /// Opaque secure-store locator. This must not contain a provider bearer
    /// credential; the delivery worker resolves credentials only after claim.
    pub credential_reference: &'a [u8],
    pub idempotency_key: &'a str,
    pub max_attempts: u8,
    pub available_at: i64,
    pub trusted_now: i64,
}

impl fmt::Debug for EnqueueRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnqueueRequest")
            .field("channel", &self.channel)
            .field("destination", &"[REDACTED]")
            .field("payload", &"[REDACTED]")
            .field("credential_reference", &"[REDACTED]")
            .field("idempotency_key", &"[REDACTED]")
            .field("max_attempts", &self.max_attempts)
            .field("available_at", &self.available_at)
            .field("trusted_now", &self.trusted_now)
            .finish()
    }
}

/// Result of an idempotent enqueue operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnqueueOutcome {
    Enqueued(Uuid),
    Existing(Uuid),
}

impl EnqueueOutcome {
    /// Returns the durable job identifier.
    #[must_use]
    pub const fn job_id(self) -> Uuid {
        match self {
            Self::Enqueued(job_id) | Self::Existing(job_id) => job_id,
        }
    }
}

/// Durable lifecycle state for a delivery job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutboxState {
    Pending,
    Leased,
    Delivered,
    Retry,
    DeadLetter,
}

impl OutboxState {
    const fn code(self) -> u8 {
        match self {
            Self::Pending => 0,
            Self::Leased => 1,
            Self::Delivered => 2,
            Self::Retry => 3,
            Self::DeadLetter => 4,
        }
    }

    fn from_code(code: i64) -> Result<Self, OutboxError> {
        match code {
            0 => Ok(Self::Pending),
            1 => Ok(Self::Leased),
            2 => Ok(Self::Delivered),
            3 => Ok(Self::Retry),
            4 => Ok(Self::DeadLetter),
            _ => Err(OutboxError::Corrupt),
        }
    }
}

/// Authenticated reason retained for every dead-letter transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutboxTerminalReason {
    CrashExpired,
    RetryBudgetExhausted,
    InvalidQueuedDelivery,
    MaterialRejected,
    RequestRejected,
    ProviderRejected,
    AmbiguousDelivery,
}

impl OutboxTerminalReason {
    const fn code(self) -> u8 {
        match self {
            Self::CrashExpired => 0,
            Self::RetryBudgetExhausted => 1,
            Self::InvalidQueuedDelivery => 2,
            Self::MaterialRejected => 3,
            Self::RequestRejected => 4,
            Self::ProviderRejected => 5,
            Self::AmbiguousDelivery => 6,
        }
    }

    fn from_code(code: i64) -> Result<Self, OutboxError> {
        match code {
            0 => Ok(Self::CrashExpired),
            1 => Ok(Self::RetryBudgetExhausted),
            2 => Ok(Self::InvalidQueuedDelivery),
            3 => Ok(Self::MaterialRejected),
            4 => Ok(Self::RequestRejected),
            5 => Ok(Self::ProviderRejected),
            6 => Ok(Self::AmbiguousDelivery),
            _ => Err(OutboxError::Corrupt),
        }
    }
}

/// Non-secret metadata for one job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutboxJobStatus {
    pub job_id: Uuid,
    pub channel: ApprovalChannel,
    pub state: OutboxState,
    pub attempts: u8,
    pub max_attempts: u8,
    pub available_at: i64,
    pub lease_expires_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    pub delivered_at: Option<i64>,
    pub terminal_reason: Option<OutboxTerminalReason>,
    pub attempt_summary_hash: Option<Digest32>,
}

/// One atomically leased delivery. Secret values are redacted from `Debug` and
/// zeroized when dropped.
pub struct ClaimedDelivery {
    job_id: Uuid,
    channel: ApprovalChannel,
    destination: SecretBytes,
    payload: SecretBytes,
    credential_reference: SecretBytes,
    attempt: u8,
    lease_expires_at: i64,
    lease_token: LeaseToken,
}

impl ClaimedDelivery {
    #[must_use]
    pub const fn job_id(&self) -> Uuid {
        self.job_id
    }

    #[must_use]
    pub const fn channel(&self) -> ApprovalChannel {
        self.channel
    }

    #[must_use]
    pub fn destination(&self) -> &[u8] {
        self.destination.expose()
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        self.payload.expose()
    }

    #[must_use]
    pub fn credential_reference(&self) -> &[u8] {
        self.credential_reference.expose()
    }

    #[must_use]
    pub const fn attempt(&self) -> u8 {
        self.attempt
    }

    #[must_use]
    pub const fn lease_expires_at(&self) -> i64 {
        self.lease_expires_at
    }

    #[must_use]
    pub const fn lease_token(&self) -> &LeaseToken {
        &self.lease_token
    }
}

impl fmt::Debug for ClaimedDelivery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaimedDelivery")
            .field("job_id", &self.job_id)
            .field("channel", &self.channel)
            .field("destination", &"[REDACTED]")
            .field("payload", &"[REDACTED]")
            .field("credential_reference", &"[REDACTED]")
            .field("attempt", &self.attempt)
            .field("lease_expires_at", &self.lease_expires_at)
            .field("lease_token", &self.lease_token)
            .finish()
    }
}

/// Result of acknowledging a successful provider delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckOutcome {
    Delivered,
    AlreadyDelivered,
}

/// Result of releasing a failed delivery attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryOutcome {
    Scheduled { available_at: i64 },
    DeadLetter,
}

/// Result of an explicit fail-closed terminal transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeadLetterOutcome {
    DeadLettered,
    AlreadyDeadLettered,
}

/// Fail-closed outbox errors. Variants never include payloads, destinations,
/// provider credentials, or lease tokens.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum OutboxError {
    #[error("outbox input is outside accepted bounds")]
    InvalidInput,
    #[error("secure randomness is unavailable")]
    EntropyUnavailable,
    #[error("outbox storage is unavailable")]
    Unavailable,
    #[error("outbox schema is unsupported")]
    UnsupportedSchema,
    #[error("outbox storage is corrupt")]
    Corrupt,
    #[error("outbox authentication failed")]
    AuthenticationFailed,
    #[error("idempotency key is already bound to another request")]
    IdempotencyConflict,
    #[error("outbox capacity is exhausted")]
    CapacityExceeded,
    #[error("delivery job was not found")]
    JobNotFound,
    #[error("delivery job is not leased")]
    NotLeased,
    #[error("lease token does not match")]
    LeaseMismatch,
    #[error("delivery lease has expired")]
    LeaseExpired,
}

/// A transactional, encrypted `SQLite` outbox for one local host.
pub struct DeliveryOutbox {
    connection: Connection,
    key: OutboxEncryptionKey,
    random: SystemRandom,
}

impl fmt::Debug for DeliveryOutbox {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliveryOutbox")
            .finish_non_exhaustive()
    }
}

impl DeliveryOutbox {
    /// Opens or creates an encrypted outbox at a trusted host-controlled path.
    ///
    /// Unknown schemas, malformed databases, and wrong keys are rejected. No
    /// plaintext fallback is available.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed [`OutboxError`] if storage, schema, integrity, key
    /// authentication, or secure randomness checks fail.
    pub fn open(path: impl AsRef<Path>, key: OutboxEncryptionKey) -> Result<Self, OutboxError> {
        let random = SystemRandom::new();
        let mut connection = Connection::open(path).map_err(map_storage_error)?;
        connection
            .busy_timeout(BUSY_TIMEOUT)
            .map_err(map_storage_error)?;
        connection
            .set_limit(Limit::SQLITE_LIMIT_LENGTH, MAX_SQLITE_VALUE_BYTES)
            .map_err(map_storage_error)?;
        let schema_version = connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .map_err(map_storage_error)?;
        if !matches!(schema_version, 0 | DATABASE_SCHEMA_VERSION) {
            return Err(OutboxError::UnsupportedSchema);
        }
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA trusted_schema = OFF;
                 PRAGMA synchronous = FULL;",
            )
            .map_err(map_storage_error)?;
        match schema_version {
            0 => initialize_database(&mut connection, &key, &random)?,
            DATABASE_SCHEMA_VERSION => {}
            _ => return Err(OutboxError::UnsupportedSchema),
        }
        verify_integrity(&connection)?;
        verify_schema(&connection)?;
        verify_key(&connection, &key)?;
        let journal_mode = connection
            .query_row("PRAGMA journal_mode = WAL", [], |row| {
                row.get::<_, String>(0)
            })
            .map_err(map_storage_error)?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(OutboxError::Unavailable);
        }

        Ok(Self {
            connection,
            key,
            random,
        })
    }

    /// Idempotently stores one encrypted delivery job.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid bounds, an idempotency conflict, exhausted
    /// capacity, cryptographic failure, corruption, or unavailable storage.
    pub fn enqueue(&mut self, request: &EnqueueRequest<'_>) -> Result<EnqueueOutcome, OutboxError> {
        validate_enqueue(request)?;
        let destination_hash =
            keyed_domain_hash(&self.key, DESTINATION_HASH_DOMAIN, request.destination)?;
        let idempotency_hash = keyed_domain_hash(
            &self.key,
            IDEMPOTENCY_HASH_DOMAIN,
            request.idempotency_key.as_bytes(),
        )?;
        let request_hash = hash_request(&self.key, request)?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_storage_error)?;

        if let Some(existing) = find_by_idempotency(&transaction, &idempotency_hash)? {
            authenticate_stored_job(&self.key, &existing)?;
            if existing.encrypted.request_hash.ct_eq(&request_hash).into() {
                transaction.commit().map_err(map_storage_error)?;
                return Ok(EnqueueOutcome::Existing(existing.encrypted.job_id));
            }
            return Err(OutboxError::IdempotencyConflict);
        }

        let stored_jobs = transaction
            .query_row("SELECT COUNT(*) FROM delivery_outbox", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(map_storage_error)?;
        if !(0..MAX_STORED_JOBS).contains(&stored_jobs) {
            return Err(OutboxError::CapacityExceeded);
        }

        let job_id = Uuid::new_v4();
        let aad = job_aad(
            job_id,
            request.channel,
            &destination_hash,
            &idempotency_hash,
            &request_hash,
        );
        let envelope = encode_envelope(
            request.destination,
            request.payload,
            request.credential_reference,
        )?;
        let (nonce, ciphertext) = seal(&self.key, &self.random, &aad, envelope)?;
        let mut stored = StoredJob {
            encrypted: EncryptedJob {
                job_id,
                channel: request.channel,
                destination_hash,
                idempotency_hash,
                request_hash,
                nonce,
                ciphertext,
            },
            lifecycle: JobLifecycle {
                state: OutboxState::Pending,
                attempts: 0,
                max_attempts: request.max_attempts,
                available_at: request.available_at,
                lease_expires_at: None,
                lease_hash: None,
                completion_hash: None,
                created_at: request.trusted_now,
                updated_at: request.trusted_now,
                delivered_at: None,
                terminal_reason: None,
                attempt_summary_hash: None,
            },
            state_mac: [0_u8; HASH_BYTES],
        };
        stored.state_mac = calculate_state_mac(&self.key, &stored)?;

        transaction
            .execute(
                "INSERT INTO delivery_outbox (
                    schema_version, job_id, channel, destination_hash,
                    idempotency_hash, request_hash, nonce, ciphertext, state,
                    attempts, max_attempts, available_at, lease_expires_at,
                    lease_token_hash, completion_token_hash, created_at,
                    updated_at, delivered_at, terminal_reason,
                    attempt_summary_hash, state_mac
                 ) VALUES (
                    1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 0, ?8, ?9,
                    NULL, NULL, NULL, ?10, ?10, NULL, NULL, NULL, ?11
                 )",
                params![
                    job_id.as_bytes().as_slice(),
                    i64::from(channel_code(request.channel)),
                    destination_hash.as_slice(),
                    idempotency_hash.as_slice(),
                    request_hash.as_slice(),
                    nonce.as_slice(),
                    stored.encrypted.ciphertext.as_slice(),
                    i64::from(request.max_attempts),
                    request.available_at,
                    request.trusted_now,
                    stored.state_mac.as_slice(),
                ],
            )
            .map_err(map_storage_error)?;
        transaction.commit().map_err(map_storage_error)?;
        Ok(EnqueueOutcome::Enqueued(job_id))
    }

    /// Atomically leases the oldest ready job for a bounded interval.
    ///
    /// An expired lease is moved to dead-letter because its provider outcome
    /// may be unknown. It is never reclaimed automatically. A ready job that
    /// has exhausted its attempt budget also remains terminal.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid trusted time or lease duration, corruption,
    /// failed authentication, entropy failure, or unavailable storage.
    pub fn claim(
        &mut self,
        trusted_now: i64,
        lease_seconds: i64,
    ) -> Result<Option<ClaimedDelivery>, OutboxError> {
        if trusted_now < 0 || !(1..=MAX_LEASE_SECONDS).contains(&lease_seconds) {
            return Err(OutboxError::InvalidInput);
        }
        let lease_expires_at = trusted_now
            .checked_add(lease_seconds)
            .ok_or(OutboxError::InvalidInput)?;
        let lease_token = LeaseToken::generate(&self.random)?;
        let lease_hash = lease_token_hash(&lease_token);

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_storage_error)?;
        for _ in 0..MAX_EXPIRED_TRANSITIONS_PER_CLAIM {
            let Some(mut candidate) = find_claim_candidate(&transaction, trusted_now)? else {
                transaction.commit().map_err(map_storage_error)?;
                return Ok(None);
            };
            let secrets = authenticate_stored_job(&self.key, &candidate)?;
            if trusted_now < candidate.lifecycle.updated_at {
                return Err(OutboxError::InvalidInput);
            }
            let previous_mac = candidate.state_mac;

            if candidate.lifecycle.state == OutboxState::Leased {
                let completion_hash = candidate
                    .lifecycle
                    .lease_hash
                    .take()
                    .ok_or(OutboxError::Corrupt)?;
                candidate.lifecycle.state = OutboxState::DeadLetter;
                candidate.lifecycle.lease_expires_at = None;
                candidate.lifecycle.completion_hash = Some(completion_hash);
                candidate.lifecycle.terminal_reason = Some(OutboxTerminalReason::CrashExpired);
                candidate.lifecycle.attempt_summary_hash = None;
                candidate.lifecycle.updated_at = trusted_now;
                candidate.state_mac = calculate_state_mac(&self.key, &candidate)?;
                persist_lifecycle(&transaction, &candidate, &previous_mac)?;
                drop(secrets);
                continue;
            }
            if !matches!(
                candidate.lifecycle.state,
                OutboxState::Pending | OutboxState::Retry
            ) || candidate.lifecycle.attempts >= candidate.lifecycle.max_attempts
            {
                return Err(OutboxError::Corrupt);
            }

            let next_attempt = candidate
                .lifecycle
                .attempts
                .checked_add(1)
                .ok_or(OutboxError::Corrupt)?;
            candidate.lifecycle.state = OutboxState::Leased;
            candidate.lifecycle.attempts = next_attempt;
            candidate.lifecycle.lease_expires_at = Some(lease_expires_at);
            candidate.lifecycle.lease_hash = Some(lease_hash);
            candidate.lifecycle.completion_hash = None;
            candidate.lifecycle.terminal_reason = None;
            candidate.lifecycle.attempt_summary_hash = None;
            candidate.lifecycle.updated_at = trusted_now;
            candidate.lifecycle.delivered_at = None;
            candidate.state_mac = calculate_state_mac(&self.key, &candidate)?;
            persist_lifecycle(&transaction, &candidate, &previous_mac)?;
            transaction.commit().map_err(map_storage_error)?;

            return Ok(Some(ClaimedDelivery {
                job_id: candidate.encrypted.job_id,
                channel: candidate.encrypted.channel,
                destination: secrets.destination,
                payload: secrets.payload,
                credential_reference: secrets.credential_reference,
                attempt: next_attempt,
                lease_expires_at,
                lease_token,
            }));
        }
        transaction.commit().map_err(map_storage_error)?;
        Ok(None)
    }

    /// Atomically leases one exact authenticated job for a bounded interval.
    ///
    /// Unlike [`Self::claim`], this method never searches for or transitions
    /// any other job. A pending or retry job is leased only when it is ready.
    /// Future, actively leased, delivered, and dead-lettered jobs return
    /// `None` without a state change. An expired lease is conservatively
    /// dead-lettered because its provider outcome may be unknown, then also
    /// returns `None`.
    ///
    /// # Errors
    ///
    /// Returns an error for a nil job identifier, invalid trusted time or
    /// lease duration, an absent job, failed authentication, corruption,
    /// entropy failure, or unavailable storage.
    pub fn claim_exact(
        &mut self,
        job_id: Uuid,
        trusted_now: i64,
        lease_seconds: i64,
    ) -> Result<Option<ClaimedDelivery>, OutboxError> {
        validate_job_and_time(job_id, trusted_now)?;
        if !(1..=MAX_LEASE_SECONDS).contains(&lease_seconds) {
            return Err(OutboxError::InvalidInput);
        }
        let lease_expires_at = trusted_now
            .checked_add(lease_seconds)
            .ok_or(OutboxError::InvalidInput)?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_storage_error)?;
        let mut candidate =
            load_stored_job(&transaction, job_id)?.ok_or(OutboxError::JobNotFound)?;
        let secrets = authenticate_stored_job(&self.key, &candidate)?;
        if trusted_now < candidate.lifecycle.updated_at {
            return Err(OutboxError::InvalidInput);
        }

        if candidate.lifecycle.state == OutboxState::Leased {
            let expires_at = candidate
                .lifecycle
                .lease_expires_at
                .ok_or(OutboxError::Corrupt)?;
            if expires_at > trusted_now {
                transaction.commit().map_err(map_storage_error)?;
                return Ok(None);
            }

            let previous_mac = candidate.state_mac;
            let completion_hash = candidate
                .lifecycle
                .lease_hash
                .take()
                .ok_or(OutboxError::Corrupt)?;
            candidate.lifecycle.state = OutboxState::DeadLetter;
            candidate.lifecycle.lease_expires_at = None;
            candidate.lifecycle.completion_hash = Some(completion_hash);
            candidate.lifecycle.terminal_reason = Some(OutboxTerminalReason::CrashExpired);
            candidate.lifecycle.attempt_summary_hash = None;
            candidate.lifecycle.updated_at = trusted_now;
            candidate.state_mac = calculate_state_mac(&self.key, &candidate)?;
            persist_lifecycle(&transaction, &candidate, &previous_mac)?;
            transaction.commit().map_err(map_storage_error)?;
            return Ok(None);
        }

        if matches!(
            candidate.lifecycle.state,
            OutboxState::Delivered | OutboxState::DeadLetter
        ) || candidate.lifecycle.available_at > trusted_now
        {
            transaction.commit().map_err(map_storage_error)?;
            return Ok(None);
        }
        if !matches!(
            candidate.lifecycle.state,
            OutboxState::Pending | OutboxState::Retry
        ) || candidate.lifecycle.attempts >= candidate.lifecycle.max_attempts
        {
            return Err(OutboxError::Corrupt);
        }

        let lease_token = LeaseToken::generate(&self.random)?;
        let lease_hash = lease_token_hash(&lease_token);
        let next_attempt = candidate
            .lifecycle
            .attempts
            .checked_add(1)
            .ok_or(OutboxError::Corrupt)?;
        let previous_mac = candidate.state_mac;
        candidate.lifecycle.state = OutboxState::Leased;
        candidate.lifecycle.attempts = next_attempt;
        candidate.lifecycle.lease_expires_at = Some(lease_expires_at);
        candidate.lifecycle.lease_hash = Some(lease_hash);
        candidate.lifecycle.completion_hash = None;
        candidate.lifecycle.terminal_reason = None;
        candidate.lifecycle.attempt_summary_hash = None;
        candidate.lifecycle.updated_at = trusted_now;
        candidate.lifecycle.delivered_at = None;
        candidate.state_mac = calculate_state_mac(&self.key, &candidate)?;
        persist_lifecycle(&transaction, &candidate, &previous_mac)?;
        transaction.commit().map_err(map_storage_error)?;

        Ok(Some(ClaimedDelivery {
            job_id: candidate.encrypted.job_id,
            channel: candidate.encrypted.channel,
            destination: secrets.destination,
            payload: secrets.payload,
            credential_reference: secrets.credential_reference,
            attempt: next_attempt,
            lease_expires_at,
            lease_token,
        }))
    }

    /// Idempotently records a successful delivery for the active lease.
    ///
    /// # Errors
    ///
    /// Returns an error if trusted time is invalid, the job is absent, the
    /// lease is inactive, mismatched, or expired, or storage fails closed.
    pub fn ack(
        &mut self,
        job_id: Uuid,
        lease_token: &LeaseToken,
        trusted_now: i64,
    ) -> Result<AckOutcome, OutboxError> {
        validate_job_and_time(job_id, trusted_now)?;
        let supplied_hash = lease_token_hash(lease_token);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_storage_error)?;
        let mut job = load_stored_job(&transaction, job_id)?.ok_or(OutboxError::JobNotFound)?;
        let _secrets = authenticate_stored_job(&self.key, &job)?;
        if trusted_now < job.lifecycle.updated_at {
            return Err(OutboxError::InvalidInput);
        }

        if job.lifecycle.state == OutboxState::Delivered {
            let completion_hash = job.lifecycle.completion_hash.ok_or(OutboxError::Corrupt)?;
            if completion_hash.ct_eq(&supplied_hash).into() {
                transaction.commit().map_err(map_storage_error)?;
                return Ok(AckOutcome::AlreadyDelivered);
            }
            return Err(OutboxError::LeaseMismatch);
        }
        validate_active_lease(&job.lifecycle, &supplied_hash, trusted_now)?;
        let previous_mac = job.state_mac;
        job.lifecycle.state = OutboxState::Delivered;
        job.lifecycle.lease_expires_at = None;
        job.lifecycle.lease_hash = None;
        job.lifecycle.completion_hash = Some(supplied_hash);
        job.lifecycle.terminal_reason = None;
        job.lifecycle.attempt_summary_hash = None;
        job.lifecycle.updated_at = trusted_now;
        job.lifecycle.delivered_at = Some(trusted_now);
        job.state_mac = calculate_state_mac(&self.key, &job)?;
        persist_lifecycle(&transaction, &job, &previous_mac)?;
        transaction.commit().map_err(map_storage_error)?;
        Ok(AckOutcome::Delivered)
    }

    /// Releases a failed active lease into a bounded retry or dead-letter state.
    ///
    /// # Errors
    ///
    /// Returns an error if inputs are invalid, the lease is inactive,
    /// mismatched, or expired, or storage fails closed.
    pub fn retry(
        &mut self,
        job_id: Uuid,
        lease_token: &LeaseToken,
        trusted_now: i64,
        delay_seconds: i64,
        attempt_summary_hash: Option<Digest32>,
    ) -> Result<RetryOutcome, OutboxError> {
        validate_job_and_time(job_id, trusted_now)?;
        if !(0..=MAX_RETRY_DELAY_SECONDS).contains(&delay_seconds) {
            return Err(OutboxError::InvalidInput);
        }
        let available_at = trusted_now
            .checked_add(delay_seconds)
            .ok_or(OutboxError::InvalidInput)?;
        let supplied_hash = lease_token_hash(lease_token);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_storage_error)?;
        let mut job = load_stored_job(&transaction, job_id)?.ok_or(OutboxError::JobNotFound)?;
        let _secrets = authenticate_stored_job(&self.key, &job)?;
        if trusted_now < job.lifecycle.updated_at {
            return Err(OutboxError::InvalidInput);
        }
        validate_active_lease(&job.lifecycle, &supplied_hash, trusted_now)?;

        let (state, outcome) = if job.lifecycle.attempts >= job.lifecycle.max_attempts {
            (OutboxState::DeadLetter, RetryOutcome::DeadLetter)
        } else {
            (OutboxState::Retry, RetryOutcome::Scheduled { available_at })
        };
        let previous_mac = job.state_mac;
        job.lifecycle.state = state;
        job.lifecycle.available_at = available_at;
        job.lifecycle.lease_expires_at = None;
        job.lifecycle.lease_hash = None;
        job.lifecycle.completion_hash = (state == OutboxState::DeadLetter).then_some(supplied_hash);
        job.lifecycle.terminal_reason = (state == OutboxState::DeadLetter)
            .then_some(OutboxTerminalReason::RetryBudgetExhausted);
        job.lifecycle.attempt_summary_hash = if state == OutboxState::DeadLetter {
            attempt_summary_hash
        } else {
            None
        };
        job.lifecycle.updated_at = trusted_now;
        job.state_mac = calculate_state_mac(&self.key, &job)?;
        persist_lifecycle(&transaction, &job, &previous_mac)?;
        transaction.commit().map_err(map_storage_error)?;
        Ok(outcome)
    }

    /// Idempotently moves one active lease to fail-closed dead-letter state.
    ///
    /// This transition is used for permanent rejection, ambiguous delivery,
    /// malformed queued data, and any outcome that must never be resent
    /// automatically. Repeating it with the same lease token is safe.
    ///
    /// # Errors
    ///
    /// Returns an error if trusted time is invalid, the job is absent, the
    /// lease token is wrong, the active lease expired, or storage fails closed.
    pub fn dead_letter(
        &mut self,
        job_id: Uuid,
        lease_token: &LeaseToken,
        trusted_now: i64,
        reason: OutboxTerminalReason,
        attempt_summary_hash: Option<Digest32>,
    ) -> Result<DeadLetterOutcome, OutboxError> {
        validate_job_and_time(job_id, trusted_now)?;
        let supplied_hash = lease_token_hash(lease_token);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_storage_error)?;
        let mut job = load_stored_job(&transaction, job_id)?.ok_or(OutboxError::JobNotFound)?;
        let _secrets = authenticate_stored_job(&self.key, &job)?;
        if trusted_now < job.lifecycle.updated_at {
            return Err(OutboxError::InvalidInput);
        }
        if job.lifecycle.state == OutboxState::DeadLetter {
            let completion_hash = job.lifecycle.completion_hash.ok_or(OutboxError::Corrupt)?;
            if completion_hash.ct_eq(&supplied_hash).into() {
                if job.lifecycle.terminal_reason != Some(reason)
                    || job.lifecycle.attempt_summary_hash != attempt_summary_hash
                {
                    return Err(OutboxError::IdempotencyConflict);
                }
                transaction.commit().map_err(map_storage_error)?;
                return Ok(DeadLetterOutcome::AlreadyDeadLettered);
            }
            return Err(OutboxError::LeaseMismatch);
        }
        validate_active_lease(&job.lifecycle, &supplied_hash, trusted_now)?;

        let previous_mac = job.state_mac;
        job.lifecycle.state = OutboxState::DeadLetter;
        job.lifecycle.lease_expires_at = None;
        job.lifecycle.lease_hash = None;
        job.lifecycle.completion_hash = Some(supplied_hash);
        job.lifecycle.terminal_reason = Some(reason);
        job.lifecycle.attempt_summary_hash = attempt_summary_hash;
        job.lifecycle.updated_at = trusted_now;
        job.lifecycle.delivered_at = None;
        job.state_mac = calculate_state_mac(&self.key, &job)?;
        persist_lifecycle(&transaction, &job, &previous_mac)?;
        transaction.commit().map_err(map_storage_error)?;
        Ok(DeadLetterOutcome::DeadLettered)
    }

    /// Returns authenticated, non-secret status metadata for one job.
    ///
    /// # Errors
    ///
    /// Returns an error if the job identifier is invalid, encrypted data is
    /// corrupt, authentication fails, or storage is unavailable.
    pub fn status(&self, job_id: Uuid) -> Result<Option<OutboxJobStatus>, OutboxError> {
        if job_id.is_nil() {
            return Err(OutboxError::InvalidInput);
        }
        let Some(job) = load_stored_job(&self.connection, job_id)? else {
            return Ok(None);
        };
        let _secrets = authenticate_stored_job(&self.key, &job)?;
        Ok(Some(status_from_job(&job)))
    }

    /// Deletes a bounded number of old delivered or dead-letter jobs.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid bounds or unavailable storage.
    pub fn prune(&mut self, updated_before_or_at: i64, limit: u32) -> Result<usize, OutboxError> {
        if updated_before_or_at < 0 || !(1..=MAX_PRUNE_LIMIT).contains(&limit) {
            return Err(OutboxError::InvalidInput);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_storage_error)?;
        let candidates = load_prune_candidates(
            &transaction,
            updated_before_or_at,
            usize::try_from(limit).map_err(|_| OutboxError::InvalidInput)?,
        )?;
        for job in &candidates {
            let _secrets = authenticate_stored_job(&self.key, job)?;
            let deleted = transaction
                .execute(
                    "DELETE FROM delivery_outbox
                     WHERE job_id = ?1 AND state_mac = ?2",
                    params![
                        job.encrypted.job_id.as_bytes().as_slice(),
                        job.state_mac.as_slice(),
                    ],
                )
                .map_err(map_storage_error)?;
            if deleted != 1 {
                return Err(OutboxError::Corrupt);
            }
        }
        transaction.commit().map_err(map_storage_error)?;
        Ok(candidates.len())
    }
}

struct EncryptedJob {
    job_id: Uuid,
    channel: ApprovalChannel,
    destination_hash: [u8; HASH_BYTES],
    idempotency_hash: [u8; HASH_BYTES],
    request_hash: [u8; HASH_BYTES],
    nonce: [u8; NONCE_BYTES],
    ciphertext: Vec<u8>,
}

struct JobLifecycle {
    state: OutboxState,
    attempts: u8,
    max_attempts: u8,
    available_at: i64,
    lease_expires_at: Option<i64>,
    lease_hash: Option<[u8; HASH_BYTES]>,
    completion_hash: Option<[u8; HASH_BYTES]>,
    created_at: i64,
    updated_at: i64,
    delivered_at: Option<i64>,
    terminal_reason: Option<OutboxTerminalReason>,
    attempt_summary_hash: Option<Digest32>,
}

struct StoredJob {
    encrypted: EncryptedJob,
    lifecycle: JobLifecycle,
    state_mac: [u8; HASH_BYTES],
}

struct DecryptedEnvelope {
    destination: SecretBytes,
    payload: SecretBytes,
    credential_reference: SecretBytes,
}

fn initialize_database(
    connection: &mut Connection,
    key: &OutboxEncryptionKey,
    random: &SystemRandom,
) -> Result<(), OutboxError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_storage_error)?;
    let schema_version = transaction
        .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
        .map_err(map_storage_error)?;
    if schema_version == DATABASE_SCHEMA_VERSION {
        transaction.commit().map_err(map_storage_error)?;
        return Ok(());
    }
    if schema_version != 0 {
        return Err(OutboxError::UnsupportedSchema);
    }
    let object_count = transaction
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(map_storage_error)?;
    if object_count != 0 {
        return Err(OutboxError::UnsupportedSchema);
    }
    transaction
        .execute_batch(META_TABLE_SQL)
        .map_err(map_storage_error)?;
    transaction
        .execute_batch(JOB_TABLE_SQL)
        .map_err(map_storage_error)?;
    transaction
        .execute_batch(READY_INDEX_SQL)
        .map_err(map_storage_error)?;
    transaction
        .execute_batch(TERMINAL_INDEX_SQL)
        .map_err(map_storage_error)?;

    let (nonce, ciphertext) = seal(key, random, KEY_CHECK_AAD, KEY_CHECK_PLAINTEXT.to_vec())?;
    transaction
        .execute(
            "INSERT INTO outbox_meta (
                schema_version, key_check_nonce, key_check_ciphertext
             ) VALUES (1, ?1, ?2)",
            params![nonce.as_slice(), ciphertext],
        )
        .map_err(map_storage_error)?;
    transaction
        .execute_batch("PRAGMA user_version = 1")
        .map_err(map_storage_error)?;
    transaction.commit().map_err(map_storage_error)
}

fn verify_integrity(connection: &Connection) -> Result<(), OutboxError> {
    let result = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get::<_, String>(0))
        .map_err(map_storage_error)?;
    if result == "ok" {
        Ok(())
    } else {
        Err(OutboxError::Corrupt)
    }
}

fn verify_schema(connection: &Connection) -> Result<(), OutboxError> {
    let object_count = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(map_storage_error)?;
    if object_count != 4 {
        return Err(OutboxError::Corrupt);
    }
    verify_schema_object(connection, "table", "outbox_meta", META_TABLE_SQL)?;
    verify_schema_object(connection, "table", "delivery_outbox", JOB_TABLE_SQL)?;
    verify_schema_object(
        connection,
        "index",
        "delivery_outbox_ready_idx",
        READY_INDEX_SQL,
    )?;
    verify_schema_object(
        connection,
        "index",
        "delivery_outbox_terminal_idx",
        TERMINAL_INDEX_SQL,
    )
}

fn verify_schema_object(
    connection: &Connection,
    object_type: &str,
    name: &str,
    expected_sql: &str,
) -> Result<(), OutboxError> {
    let stored = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
            params![object_type, name],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(map_storage_error)?
        .ok_or(OutboxError::Corrupt)?;
    if normalize_sql(&stored) == normalize_sql(expected_sql) {
        Ok(())
    } else {
        Err(OutboxError::Corrupt)
    }
}

fn normalize_sql(sql: &str) -> String {
    sql.trim()
        .trim_end_matches(';')
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn verify_key(connection: &Connection, key: &OutboxEncryptionKey) -> Result<(), OutboxError> {
    let (schema_version, nonce, ciphertext) = connection
        .query_row(
            "SELECT schema_version, key_check_nonce, key_check_ciphertext
             FROM outbox_meta",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .map_err(map_storage_error)?;
    if schema_version != DATABASE_SCHEMA_VERSION {
        return Err(OutboxError::Corrupt);
    }
    let nonce = exact_array::<NONCE_BYTES>(nonce)?;
    let plaintext = open_ciphertext(key, &nonce, KEY_CHECK_AAD, ciphertext)?;
    if plaintext.as_slice().ct_eq(KEY_CHECK_PLAINTEXT).into() {
        Ok(())
    } else {
        Err(OutboxError::AuthenticationFailed)
    }
}

fn validate_enqueue(request: &EnqueueRequest<'_>) -> Result<(), OutboxError> {
    if request.destination.is_empty()
        || request.destination.len() > MAX_DESTINATION_BYTES
        || request.payload.is_empty()
        || request.payload.len() > MAX_PAYLOAD_BYTES
        || request.credential_reference.is_empty()
        || request.credential_reference.len() > MAX_CREDENTIAL_REFERENCE_BYTES
        || request.idempotency_key.is_empty()
        || request.idempotency_key.len() > MAX_IDEMPOTENCY_BYTES
        || request.idempotency_key.chars().any(char::is_control)
        || !(1..=MAX_ATTEMPTS).contains(&request.max_attempts)
        || request.available_at < 0
        || request.trusted_now < 0
    {
        return Err(OutboxError::InvalidInput);
    }
    Ok(())
}

fn validate_job_and_time(job_id: Uuid, trusted_now: i64) -> Result<(), OutboxError> {
    if job_id.is_nil() || trusted_now < 0 {
        Err(OutboxError::InvalidInput)
    } else {
        Ok(())
    }
}

fn channel_code(channel: ApprovalChannel) -> u8 {
    match channel {
        ApprovalChannel::Slack => 0,
        ApprovalChannel::MicrosoftTeams => 1,
        ApprovalChannel::Telegram => 2,
        ApprovalChannel::WhatsApp => 3,
    }
}

fn channel_from_code(code: i64) -> Result<ApprovalChannel, OutboxError> {
    match code {
        0 => Ok(ApprovalChannel::Slack),
        1 => Ok(ApprovalChannel::MicrosoftTeams),
        2 => Ok(ApprovalChannel::Telegram),
        3 => Ok(ApprovalChannel::WhatsApp),
        _ => Err(OutboxError::Corrupt),
    }
}

fn domain_hash(domain: &[u8], value: &[u8]) -> [u8; HASH_BYTES] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
    digest.finalize().into()
}

fn keyed_domain_hash(
    key: &OutboxEncryptionKey,
    domain: &[u8],
    value: &[u8],
) -> Result<[u8; HASH_BYTES], OutboxError> {
    let mut mac = derived_hmac(key, METADATA_HASH_KEY_DOMAIN)?;
    hmac::Mac::update(&mut mac, domain);
    hmac::Mac::update(&mut mac, &(value.len() as u64).to_be_bytes());
    hmac::Mac::update(&mut mac, value);
    Ok(mac.finalize().into_bytes().into())
}

fn hash_request(
    key: &OutboxEncryptionKey,
    request: &EnqueueRequest<'_>,
) -> Result<[u8; HASH_BYTES], OutboxError> {
    let mut mac = derived_hmac(key, METADATA_HASH_KEY_DOMAIN)?;
    hmac::Mac::update(&mut mac, REQUEST_HASH_DOMAIN);
    hmac::Mac::update(&mut mac, &[channel_code(request.channel)]);
    update_length_prefixed_mac(&mut mac, request.destination);
    update_length_prefixed_mac(&mut mac, request.payload);
    update_length_prefixed_mac(&mut mac, request.credential_reference);
    update_length_prefixed_mac(&mut mac, request.idempotency_key.as_bytes());
    hmac::Mac::update(&mut mac, &[request.max_attempts]);
    hmac::Mac::update(&mut mac, &request.available_at.to_be_bytes());
    Ok(mac.finalize().into_bytes().into())
}

fn update_length_prefixed_mac(mac: &mut StateHmac, value: &[u8]) {
    hmac::Mac::update(mac, &(value.len() as u64).to_be_bytes());
    hmac::Mac::update(mac, value);
}

fn lease_token_hash(token: &LeaseToken) -> [u8; HASH_BYTES] {
    domain_hash(LEASE_HASH_DOMAIN, token.expose())
}

fn calculate_state_mac(
    key: &OutboxEncryptionKey,
    job: &StoredJob,
) -> Result<[u8; HASH_BYTES], OutboxError> {
    validate_lifecycle(&job.lifecycle)?;
    let mut mac = derived_hmac(key, STATE_MAC_KEY_DOMAIN)?;
    hmac::Mac::update(&mut mac, STATE_MAC_DOMAIN);
    hmac::Mac::update(&mut mac, &DATABASE_SCHEMA_VERSION_U16.to_be_bytes());
    hmac::Mac::update(&mut mac, job.encrypted.job_id.as_bytes());
    hmac::Mac::update(&mut mac, &[channel_code(job.encrypted.channel)]);
    hmac::Mac::update(&mut mac, &job.encrypted.destination_hash);
    hmac::Mac::update(&mut mac, &job.encrypted.idempotency_hash);
    hmac::Mac::update(&mut mac, &job.encrypted.request_hash);
    hmac::Mac::update(&mut mac, &job.encrypted.nonce);
    hmac::Mac::update(
        &mut mac,
        &(job.encrypted.ciphertext.len() as u64).to_be_bytes(),
    );
    hmac::Mac::update(&mut mac, &job.encrypted.ciphertext);
    hmac::Mac::update(&mut mac, &[job.lifecycle.state.code()]);
    hmac::Mac::update(&mut mac, &[job.lifecycle.attempts]);
    hmac::Mac::update(&mut mac, &[job.lifecycle.max_attempts]);
    hmac::Mac::update(&mut mac, &job.lifecycle.available_at.to_be_bytes());
    update_optional_i64_mac(&mut mac, job.lifecycle.lease_expires_at);
    update_optional_hash_mac(&mut mac, job.lifecycle.lease_hash.as_ref());
    update_optional_hash_mac(&mut mac, job.lifecycle.completion_hash.as_ref());
    hmac::Mac::update(&mut mac, &job.lifecycle.created_at.to_be_bytes());
    hmac::Mac::update(&mut mac, &job.lifecycle.updated_at.to_be_bytes());
    update_optional_i64_mac(&mut mac, job.lifecycle.delivered_at);
    match job.lifecycle.terminal_reason {
        Some(reason) => {
            hmac::Mac::update(&mut mac, &[1, reason.code()]);
        }
        None => hmac::Mac::update(&mut mac, &[0]),
    }
    update_optional_hash_mac(
        &mut mac,
        job.lifecycle
            .attempt_summary_hash
            .as_ref()
            .map(Digest32::as_bytes),
    );
    Ok(mac.finalize().into_bytes().into())
}

fn derived_hmac(
    key: &OutboxEncryptionKey,
    derivation_domain: &[u8],
) -> Result<StateHmac, OutboxError> {
    let mut derivation = <StateHmac as hmac::Mac>::new_from_slice(key.expose())
        .map_err(|_| OutboxError::AuthenticationFailed)?;
    hmac::Mac::update(&mut derivation, derivation_domain);
    let derived_bytes = derivation.finalize().into_bytes();
    let mut derived_key = Zeroizing::new([0_u8; HASH_BYTES]);
    derived_key.copy_from_slice(&derived_bytes);
    <StateHmac as hmac::Mac>::new_from_slice(derived_key.as_ref())
        .map_err(|_| OutboxError::AuthenticationFailed)
}

fn update_optional_i64_mac(mac: &mut StateHmac, value: Option<i64>) {
    match value {
        Some(value) => {
            hmac::Mac::update(mac, &[1]);
            hmac::Mac::update(mac, &value.to_be_bytes());
        }
        None => hmac::Mac::update(mac, &[0]),
    }
}

fn update_optional_hash_mac(mac: &mut StateHmac, value: Option<&[u8; HASH_BYTES]>) {
    match value {
        Some(value) => {
            hmac::Mac::update(mac, &[1]);
            hmac::Mac::update(mac, value);
        }
        None => hmac::Mac::update(mac, &[0]),
    }
}

fn authenticate_stored_job(
    key: &OutboxEncryptionKey,
    job: &StoredJob,
) -> Result<DecryptedEnvelope, OutboxError> {
    let expected = calculate_state_mac(key, job)?;
    if !bool::from(expected.ct_eq(&job.state_mac)) {
        return Err(OutboxError::AuthenticationFailed);
    }
    let secrets = authenticate_encrypted_job(key, &job.encrypted)?;
    let destination_hash =
        keyed_domain_hash(key, DESTINATION_HASH_DOMAIN, secrets.destination.expose())?;
    if !bool::from(
        destination_hash
            .as_slice()
            .ct_eq(job.encrypted.destination_hash.as_slice()),
    ) {
        return Err(OutboxError::AuthenticationFailed);
    }
    Ok(secrets)
}

fn persist_lifecycle(
    transaction: &Transaction<'_>,
    job: &StoredJob,
    previous_mac: &[u8; HASH_BYTES],
) -> Result<(), OutboxError> {
    validate_lifecycle(&job.lifecycle)?;
    let lease_hash = job
        .lifecycle
        .lease_hash
        .as_ref()
        .map(<[u8; HASH_BYTES]>::as_slice);
    let completion_hash = job
        .lifecycle
        .completion_hash
        .as_ref()
        .map(<[u8; HASH_BYTES]>::as_slice);
    let terminal_reason = job
        .lifecycle
        .terminal_reason
        .map(OutboxTerminalReason::code);
    let attempt_summary_hash = job
        .lifecycle
        .attempt_summary_hash
        .as_ref()
        .map(Digest32::as_bytes)
        .map(<[u8; HASH_BYTES]>::as_slice);
    let changed = transaction
        .execute(
            "UPDATE delivery_outbox
             SET state = ?1, attempts = ?2, max_attempts = ?3,
                 available_at = ?4, lease_expires_at = ?5,
                 lease_token_hash = ?6, completion_token_hash = ?7,
                 created_at = ?8, updated_at = ?9, delivered_at = ?10,
                 terminal_reason = ?11, attempt_summary_hash = ?12,
                 state_mac = ?13
             WHERE job_id = ?14 AND state_mac = ?15",
            params![
                i64::from(job.lifecycle.state.code()),
                i64::from(job.lifecycle.attempts),
                i64::from(job.lifecycle.max_attempts),
                job.lifecycle.available_at,
                job.lifecycle.lease_expires_at,
                lease_hash,
                completion_hash,
                job.lifecycle.created_at,
                job.lifecycle.updated_at,
                job.lifecycle.delivered_at,
                terminal_reason,
                attempt_summary_hash,
                job.state_mac.as_slice(),
                job.encrypted.job_id.as_bytes().as_slice(),
                previous_mac.as_slice(),
            ],
        )
        .map_err(map_storage_error)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(OutboxError::Corrupt)
    }
}

fn validate_lifecycle(lifecycle: &JobLifecycle) -> Result<(), OutboxError> {
    let state_shape = match lifecycle.state {
        OutboxState::Leased => {
            lifecycle.attempts > 0
                && lifecycle.lease_expires_at.is_some()
                && lifecycle.lease_hash.is_some()
                && lifecycle.completion_hash.is_none()
                && lifecycle.delivered_at.is_none()
                && lifecycle.terminal_reason.is_none()
                && lifecycle.attempt_summary_hash.is_none()
        }
        OutboxState::Delivered => {
            lifecycle.attempts > 0
                && lifecycle.lease_expires_at.is_none()
                && lifecycle.lease_hash.is_none()
                && lifecycle.completion_hash.is_some()
                && lifecycle.delivered_at.is_some()
                && lifecycle.terminal_reason.is_none()
                && lifecycle.attempt_summary_hash.is_none()
        }
        OutboxState::Pending => {
            lifecycle.attempts == 0
                && lifecycle.lease_expires_at.is_none()
                && lifecycle.lease_hash.is_none()
                && lifecycle.completion_hash.is_none()
                && lifecycle.delivered_at.is_none()
                && lifecycle.terminal_reason.is_none()
                && lifecycle.attempt_summary_hash.is_none()
        }
        OutboxState::Retry => {
            lifecycle.attempts > 0
                && lifecycle.lease_expires_at.is_none()
                && lifecycle.lease_hash.is_none()
                && lifecycle.completion_hash.is_none()
                && lifecycle.delivered_at.is_none()
                && lifecycle.terminal_reason.is_none()
                && lifecycle.attempt_summary_hash.is_none()
        }
        OutboxState::DeadLetter => {
            lifecycle.attempts > 0
                && lifecycle.lease_expires_at.is_none()
                && lifecycle.lease_hash.is_none()
                && lifecycle.completion_hash.is_some()
                && lifecycle.delivered_at.is_none()
                && lifecycle.terminal_reason.is_some()
        }
    };
    if !state_shape
        || lifecycle.max_attempts == 0
        || lifecycle.max_attempts > MAX_ATTEMPTS
        || lifecycle.attempts > lifecycle.max_attempts
        || lifecycle.available_at < 0
        || lifecycle.created_at < 0
        || lifecycle.updated_at < lifecycle.created_at
        || lifecycle.lease_expires_at.is_some_and(|value| value < 0)
        || lifecycle
            .delivered_at
            .is_some_and(|value| value < lifecycle.created_at || value > lifecycle.updated_at)
    {
        return Err(OutboxError::Corrupt);
    }
    Ok(())
}

fn job_aad(
    job_id: Uuid,
    channel: ApprovalChannel,
    destination_hash: &[u8; HASH_BYTES],
    idempotency_hash: &[u8; HASH_BYTES],
    request_hash: &[u8; HASH_BYTES],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(JOB_AAD_DOMAIN.len() + 2 + 16 + 1 + HASH_BYTES * 3);
    aad.extend_from_slice(JOB_AAD_DOMAIN);
    aad.extend_from_slice(&DATABASE_SCHEMA_VERSION_U16.to_be_bytes());
    aad.extend_from_slice(job_id.as_bytes());
    aad.push(channel_code(channel));
    aad.extend_from_slice(destination_hash);
    aad.extend_from_slice(idempotency_hash);
    aad.extend_from_slice(request_hash);
    aad
}

fn encode_envelope(
    destination: &[u8],
    payload: &[u8],
    credential_reference: &[u8],
) -> Result<Vec<u8>, OutboxError> {
    let destination_len =
        u32::try_from(destination.len()).map_err(|_| OutboxError::InvalidInput)?;
    let payload_len = u32::try_from(payload.len()).map_err(|_| OutboxError::InvalidInput)?;
    let reference_len =
        u32::try_from(credential_reference.len()).map_err(|_| OutboxError::InvalidInput)?;
    let capacity = ENVELOPE_HEADER_BYTES
        .checked_add(destination.len())
        .and_then(|value| value.checked_add(payload.len()))
        .and_then(|value| value.checked_add(credential_reference.len()))
        .ok_or(OutboxError::InvalidInput)?;
    let mut envelope = Vec::with_capacity(capacity);
    envelope.extend_from_slice(&destination_len.to_be_bytes());
    envelope.extend_from_slice(&payload_len.to_be_bytes());
    envelope.extend_from_slice(&reference_len.to_be_bytes());
    envelope.extend_from_slice(destination);
    envelope.extend_from_slice(payload);
    envelope.extend_from_slice(credential_reference);
    Ok(envelope)
}

fn decode_envelope(plaintext: &[u8]) -> Result<DecryptedEnvelope, OutboxError> {
    if plaintext.len() < ENVELOPE_HEADER_BYTES {
        return Err(OutboxError::Corrupt);
    }
    let destination_len = read_u32(&plaintext[0..4])?;
    let payload_len = read_u32(&plaintext[4..8])?;
    let reference_len = read_u32(&plaintext[8..12])?;
    if destination_len == 0
        || destination_len > MAX_DESTINATION_BYTES
        || payload_len == 0
        || payload_len > MAX_PAYLOAD_BYTES
        || reference_len == 0
        || reference_len > MAX_CREDENTIAL_REFERENCE_BYTES
    {
        return Err(OutboxError::Corrupt);
    }
    let destination_end = ENVELOPE_HEADER_BYTES
        .checked_add(destination_len)
        .ok_or(OutboxError::Corrupt)?;
    let payload_end = destination_end
        .checked_add(payload_len)
        .ok_or(OutboxError::Corrupt)?;
    let reference_end = payload_end
        .checked_add(reference_len)
        .ok_or(OutboxError::Corrupt)?;
    if reference_end != plaintext.len() {
        return Err(OutboxError::Corrupt);
    }
    Ok(DecryptedEnvelope {
        destination: SecretBytes::new(plaintext[ENVELOPE_HEADER_BYTES..destination_end].to_vec()),
        payload: SecretBytes::new(plaintext[destination_end..payload_end].to_vec()),
        credential_reference: SecretBytes::new(plaintext[payload_end..reference_end].to_vec()),
    })
}

fn read_u32(bytes: &[u8]) -> Result<usize, OutboxError> {
    let array = <[u8; 4]>::try_from(bytes).map_err(|_| OutboxError::Corrupt)?;
    usize::try_from(u32::from_be_bytes(array)).map_err(|_| OutboxError::Corrupt)
}

fn seal(
    key: &OutboxEncryptionKey,
    random: &SystemRandom,
    aad: &[u8],
    mut plaintext: Vec<u8>,
) -> Result<([u8; NONCE_BYTES], Vec<u8>), OutboxError> {
    let mut nonce_bytes = [0_u8; NONCE_BYTES];
    random
        .fill(&mut nonce_bytes)
        .map_err(|_| OutboxError::EntropyUnavailable)?;
    let unbound = UnboundKey::new(&aead::AES_256_GCM, key.expose())
        .map_err(|_| OutboxError::AuthenticationFailed)?;
    let sealing_key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    if sealing_key
        .seal_in_place_append_tag(nonce, Aad::from(aad), &mut plaintext)
        .is_err()
    {
        plaintext.zeroize();
        return Err(OutboxError::AuthenticationFailed);
    }
    if plaintext.len() > MAX_CIPHERTEXT_BYTES && aad != KEY_CHECK_AAD {
        plaintext.zeroize();
        return Err(OutboxError::InvalidInput);
    }
    Ok((nonce_bytes, plaintext))
}

fn open_ciphertext(
    key: &OutboxEncryptionKey,
    nonce_bytes: &[u8; NONCE_BYTES],
    aad: &[u8],
    ciphertext: Vec<u8>,
) -> Result<Zeroizing<Vec<u8>>, OutboxError> {
    if ciphertext.len() < AEAD_TAG_BYTES {
        return Err(OutboxError::Corrupt);
    }
    let unbound = UnboundKey::new(&aead::AES_256_GCM, key.expose())
        .map_err(|_| OutboxError::AuthenticationFailed)?;
    let opening_key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(*nonce_bytes);
    let mut plaintext = Zeroizing::new(ciphertext);
    let opened_len = opening_key
        .open_in_place(nonce, Aad::from(aad), plaintext.as_mut_slice())
        .map_err(|_| OutboxError::AuthenticationFailed)?
        .len();
    plaintext.truncate(opened_len);
    Ok(plaintext)
}

fn authenticate_encrypted_job(
    key: &OutboxEncryptionKey,
    encrypted: &EncryptedJob,
) -> Result<DecryptedEnvelope, OutboxError> {
    if encrypted.ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(OutboxError::Corrupt);
    }
    let aad = job_aad(
        encrypted.job_id,
        encrypted.channel,
        &encrypted.destination_hash,
        &encrypted.idempotency_hash,
        &encrypted.request_hash,
    );
    let plaintext = open_ciphertext(key, &encrypted.nonce, &aad, encrypted.ciphertext.clone())?;
    decode_envelope(&plaintext)
}

fn find_by_idempotency(
    transaction: &Transaction<'_>,
    idempotency_hash: &[u8; HASH_BYTES],
) -> Result<Option<StoredJob>, OutboxError> {
    let raw = transaction
        .query_row(
            "SELECT schema_version, job_id, channel, destination_hash,
                    idempotency_hash, request_hash, nonce, ciphertext,
                    state, attempts, max_attempts, available_at,
                    lease_expires_at, lease_token_hash, completion_token_hash,
                    created_at, updated_at, delivered_at, terminal_reason,
                    attempt_summary_hash, state_mac
             FROM delivery_outbox WHERE idempotency_hash = ?1",
            params![idempotency_hash.as_slice()],
            read_stored_row,
        )
        .optional()
        .map_err(map_storage_error)?;
    raw.map(validate_stored_row).transpose()
}

fn find_claim_candidate(
    transaction: &Transaction<'_>,
    trusted_now: i64,
) -> Result<Option<StoredJob>, OutboxError> {
    let raw = transaction
        .query_row(
            "SELECT schema_version, job_id, channel, destination_hash,
                    idempotency_hash, request_hash, nonce, ciphertext,
                    state, attempts, max_attempts, available_at,
                    lease_expires_at, lease_token_hash, completion_token_hash,
                    created_at, updated_at, delivered_at, terminal_reason,
                    attempt_summary_hash, state_mac
             FROM delivery_outbox
             WHERE (
                (state IN (0, 3) AND attempts < max_attempts
                    AND available_at <= ?1)
                OR (state = 1 AND lease_expires_at <= ?1)
             )
             ORDER BY
                CASE WHEN state = 1 THEN lease_expires_at ELSE available_at END,
                created_at, job_id
             LIMIT 1",
            params![trusted_now],
            read_stored_row,
        )
        .optional()
        .map_err(map_storage_error)?;
    raw.map(validate_stored_row).transpose()
}

fn load_stored_job(
    connection: &Connection,
    job_id: Uuid,
) -> Result<Option<StoredJob>, OutboxError> {
    let raw = connection
        .query_row(
            "SELECT schema_version, job_id, channel, destination_hash,
                    idempotency_hash, request_hash, nonce, ciphertext,
                    state, attempts, max_attempts, available_at,
                    lease_expires_at, lease_token_hash, completion_token_hash,
                    created_at, updated_at, delivered_at, terminal_reason,
                    attempt_summary_hash, state_mac
             FROM delivery_outbox WHERE job_id = ?1",
            params![job_id.as_bytes().as_slice()],
            read_stored_row,
        )
        .optional()
        .map_err(map_storage_error)?;
    raw.map(validate_stored_row).transpose()
}

fn validate_active_lease(
    lifecycle: &JobLifecycle,
    supplied_hash: &[u8; HASH_BYTES],
    trusted_now: i64,
) -> Result<(), OutboxError> {
    if lifecycle.state != OutboxState::Leased {
        return Err(OutboxError::NotLeased);
    }
    let stored_hash = lifecycle.lease_hash.as_ref().ok_or(OutboxError::Corrupt)?;
    if !bool::from(stored_hash.ct_eq(supplied_hash)) {
        return Err(OutboxError::LeaseMismatch);
    }
    let expires_at = lifecycle.lease_expires_at.ok_or(OutboxError::Corrupt)?;
    if expires_at <= trusted_now {
        return Err(OutboxError::LeaseExpired);
    }
    Ok(())
}

fn load_prune_candidates(
    transaction: &Transaction<'_>,
    updated_before_or_at: i64,
    limit: usize,
) -> Result<Vec<StoredJob>, OutboxError> {
    let mut statement = transaction
        .prepare(
            "SELECT schema_version, job_id, channel, destination_hash,
                    idempotency_hash, request_hash, nonce, ciphertext,
                    state, attempts, max_attempts, available_at,
                    lease_expires_at, lease_token_hash, completion_token_hash,
                    created_at, updated_at, delivered_at, terminal_reason,
                    attempt_summary_hash, state_mac
             FROM delivery_outbox
             WHERE state IN (2, 4) AND updated_at <= ?1
             ORDER BY updated_at, job_id LIMIT ?2",
        )
        .map_err(map_storage_error)?;
    let rows = statement
        .query_map(
            params![
                updated_before_or_at,
                i64::try_from(limit).map_err(|_| OutboxError::InvalidInput)?,
            ],
            read_stored_row,
        )
        .map_err(map_storage_error)?;
    let raw = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_storage_error)?;
    raw.into_iter().map(validate_stored_row).collect()
}

struct RawStoredJob {
    schema: i64,
    job_id: Vec<u8>,
    channel: i64,
    destination_hash: Vec<u8>,
    idempotency_hash: Vec<u8>,
    request_hash: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    state: i64,
    attempts: i64,
    max_attempts: i64,
    available_at: i64,
    lease_expires_at: Option<i64>,
    lease_hash: Option<Vec<u8>>,
    completion_hash: Option<Vec<u8>>,
    created_at: i64,
    updated_at: i64,
    delivered_at: Option<i64>,
    terminal_reason: Option<i64>,
    attempt_summary_hash: Option<Vec<u8>>,
    state_mac: Vec<u8>,
}

fn read_stored_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawStoredJob> {
    Ok(RawStoredJob {
        schema: row.get(0)?,
        job_id: row.get(1)?,
        channel: row.get(2)?,
        destination_hash: row.get(3)?,
        idempotency_hash: row.get(4)?,
        request_hash: row.get(5)?,
        nonce: row.get(6)?,
        ciphertext: row.get(7)?,
        state: row.get(8)?,
        attempts: row.get(9)?,
        max_attempts: row.get(10)?,
        available_at: row.get(11)?,
        lease_expires_at: row.get(12)?,
        lease_hash: row.get(13)?,
        completion_hash: row.get(14)?,
        created_at: row.get(15)?,
        updated_at: row.get(16)?,
        delivered_at: row.get(17)?,
        terminal_reason: row.get(18)?,
        attempt_summary_hash: row.get(19)?,
        state_mac: row.get(20)?,
    })
}

fn validate_stored_row(raw: RawStoredJob) -> Result<StoredJob, OutboxError> {
    if raw.schema != DATABASE_SCHEMA_VERSION
        || raw.ciphertext.len() < AEAD_TAG_BYTES
        || raw.ciphertext.len() > MAX_CIPHERTEXT_BYTES
    {
        return Err(OutboxError::Corrupt);
    }
    let job_id = Uuid::from_slice(&raw.job_id).map_err(|_| OutboxError::Corrupt)?;
    if job_id.is_nil() {
        return Err(OutboxError::Corrupt);
    }
    let lifecycle = JobLifecycle {
        state: OutboxState::from_code(raw.state)?,
        attempts: validate_attempts(raw.attempts, true)?,
        max_attempts: validate_attempts(raw.max_attempts, false)?,
        available_at: raw.available_at,
        lease_expires_at: raw.lease_expires_at,
        lease_hash: raw.lease_hash.map(exact_array).transpose()?,
        completion_hash: raw.completion_hash.map(exact_array).transpose()?,
        created_at: raw.created_at,
        updated_at: raw.updated_at,
        delivered_at: raw.delivered_at,
        terminal_reason: raw
            .terminal_reason
            .map(OutboxTerminalReason::from_code)
            .transpose()?,
        attempt_summary_hash: raw
            .attempt_summary_hash
            .map(exact_array)
            .transpose()?
            .map(Digest32::from_bytes),
    };
    validate_lifecycle(&lifecycle)?;
    Ok(StoredJob {
        encrypted: EncryptedJob {
            job_id,
            channel: channel_from_code(raw.channel)?,
            destination_hash: exact_array(raw.destination_hash)?,
            idempotency_hash: exact_array(raw.idempotency_hash)?,
            request_hash: exact_array(raw.request_hash)?,
            nonce: exact_array(raw.nonce)?,
            ciphertext: raw.ciphertext,
        },
        lifecycle,
        state_mac: exact_array(raw.state_mac)?,
    })
}

fn status_from_job(job: &StoredJob) -> OutboxJobStatus {
    OutboxJobStatus {
        job_id: job.encrypted.job_id,
        channel: job.encrypted.channel,
        state: job.lifecycle.state,
        attempts: job.lifecycle.attempts,
        max_attempts: job.lifecycle.max_attempts,
        available_at: job.lifecycle.available_at,
        lease_expires_at: job.lifecycle.lease_expires_at,
        created_at: job.lifecycle.created_at,
        updated_at: job.lifecycle.updated_at,
        delivered_at: job.lifecycle.delivered_at,
        terminal_reason: job.lifecycle.terminal_reason,
        attempt_summary_hash: job.lifecycle.attempt_summary_hash,
    }
}

fn validate_attempts(value: i64, allow_zero: bool) -> Result<u8, OutboxError> {
    let converted = u8::try_from(value).map_err(|_| OutboxError::Corrupt)?;
    let lower = u8::from(!allow_zero);
    if (lower..=MAX_ATTEMPTS).contains(&converted) {
        Ok(converted)
    } else {
        Err(OutboxError::Corrupt)
    }
}

fn exact_array<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], OutboxError> {
    bytes.try_into().map_err(|_| OutboxError::Corrupt)
}

#[allow(clippy::needless_pass_by_value)]
fn map_storage_error(error: rusqlite::Error) -> OutboxError {
    match error {
        rusqlite::Error::SqliteFailure(inner, _)
            if matches!(
                inner.code,
                ErrorCode::DatabaseCorrupt
                    | ErrorCode::NotADatabase
                    | ErrorCode::TooBig
                    | ErrorCode::TypeMismatch
            ) =>
        {
            OutboxError::Corrupt
        }
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::QueryReturnedNoRows
        | rusqlite::Error::QueryReturnedMoreThanOneRow => OutboxError::Corrupt,
        _ => OutboxError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Barrier};

    use super::*;

    const DESTINATION: &[u8] = b"https://hooks.example.invalid/services/destination-7f2a";
    const PAYLOAD: &[u8] = b"opaque-provider-payload-4fb846791cb4";
    const CREDENTIAL_REFERENCE: &[u8] = b"secure-store-reference-852416fef078";

    fn key(seed: u8) -> OutboxEncryptionKey {
        OutboxEncryptionKey::from_bytes([seed; KEY_BYTES])
    }

    fn request(idempotency_key: &str) -> EnqueueRequest<'_> {
        EnqueueRequest {
            channel: ApprovalChannel::Slack,
            destination: DESTINATION,
            payload: PAYLOAD,
            credential_reference: CREDENTIAL_REFERENCE,
            idempotency_key,
            max_attempts: 3,
            available_at: 100,
            trusted_now: 90,
        }
    }

    fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
        let mut value = OsString::from(path.as_os_str());
        value.push(suffix);
        PathBuf::from(value)
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }

    #[test]
    fn restart_preserves_and_decrypts_a_job() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("outbox.sqlite3");
        let job_id = {
            let mut outbox = DeliveryOutbox::open(&path, key(7))?;
            outbox.enqueue(&request("restart-job"))?.job_id()
        };

        let mut reopened = DeliveryOutbox::open(&path, key(7))?;
        let status = reopened.status(job_id)?.ok_or("missing status")?;
        assert_eq!(status.state, OutboxState::Pending);
        let claimed = reopened.claim(100, 30)?.ok_or("missing claim")?;
        assert_eq!(claimed.job_id(), job_id);
        assert_eq!(claimed.destination(), DESTINATION);
        assert_eq!(claimed.payload(), PAYLOAD);
        assert_eq!(claimed.credential_reference(), CREDENTIAL_REFERENCE);
        assert_eq!(claimed.attempt(), 1);
        Ok(())
    }

    #[test]
    fn exact_claim_never_leases_another_ready_job() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("exact-only.sqlite3");
        let mut outbox = DeliveryOutbox::open(&path, key(8))?;
        let first_id = outbox.enqueue(&request("exact-first"))?.job_id();
        let target_id = outbox.enqueue(&request("exact-target"))?.job_id();

        let target = outbox
            .claim_exact(target_id, 100, 30)?
            .ok_or("missing exact claim")?;
        assert_eq!(target.job_id(), target_id);
        assert_eq!(
            outbox
                .status(first_id)?
                .ok_or("missing first status")?
                .state,
            OutboxState::Pending
        );
        assert_eq!(
            outbox
                .status(first_id)?
                .ok_or("missing first status")?
                .attempts,
            0
        );
        outbox.ack(target_id, target.lease_token(), 101)?;

        let first = outbox.claim(101, 30)?.ok_or("missing ordinary claim")?;
        assert_eq!(first.job_id(), first_id);
        Ok(())
    }

    #[test]
    fn exact_claim_is_idle_for_future_active_and_terminal_jobs() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("exact-idle.sqlite3");
        let mut outbox = DeliveryOutbox::open(&path, key(10))?;
        let mut future = request("exact-future");
        future.available_at = 110;
        let job_id = outbox.enqueue(&future)?.job_id();

        assert!(outbox.claim_exact(job_id, 100, 20)?.is_none());
        let pending = outbox.status(job_id)?.ok_or("missing pending status")?;
        assert_eq!(pending.state, OutboxState::Pending);
        assert_eq!(pending.attempts, 0);
        assert_eq!(pending.updated_at, 90);

        let claimed = outbox
            .claim_exact(job_id, 110, 20)?
            .ok_or("missing ready exact claim")?;
        assert!(outbox.claim_exact(job_id, 111, 20)?.is_none());
        let active = outbox.status(job_id)?.ok_or("missing active status")?;
        assert_eq!(active.state, OutboxState::Leased);
        assert_eq!(active.attempts, 1);
        assert_eq!(active.updated_at, 110);

        outbox.ack(job_id, claimed.lease_token(), 112)?;
        assert!(outbox.claim_exact(job_id, 113, 20)?.is_none());
        let delivered = outbox.status(job_id)?.ok_or("missing delivered status")?;
        assert_eq!(delivered.state, OutboxState::Delivered);
        assert_eq!(delivered.updated_at, 112);
        Ok(())
    }

    #[test]
    fn exact_claim_validates_identity_and_dead_letters_only_its_expired_lease()
    -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("exact-expired.sqlite3");
        let mut outbox = DeliveryOutbox::open(&path, key(12))?;
        let stale_id = outbox.enqueue(&request("exact-stale"))?.job_id();
        let other_id = outbox.enqueue(&request("exact-other"))?.job_id();

        assert!(matches!(
            outbox.claim_exact(Uuid::nil(), 100, 10),
            Err(OutboxError::InvalidInput)
        ));
        assert!(matches!(
            outbox.claim_exact(Uuid::new_v4(), 100, 10),
            Err(OutboxError::JobNotFound)
        ));
        assert!(matches!(
            outbox.claim_exact(stale_id, -1, 10),
            Err(OutboxError::InvalidInput)
        ));
        assert!(matches!(
            outbox.claim_exact(stale_id, 100, 0),
            Err(OutboxError::InvalidInput)
        ));

        let stale = outbox
            .claim_exact(stale_id, 100, 10)?
            .ok_or("missing stale exact claim")?;
        assert!(outbox.claim_exact(stale_id, 110, 10)?.is_none());
        let stale_status = outbox.status(stale_id)?.ok_or("missing stale status")?;
        assert_eq!(stale_status.state, OutboxState::DeadLetter);
        assert_eq!(
            stale_status.terminal_reason,
            Some(OutboxTerminalReason::CrashExpired)
        );
        assert_eq!(
            outbox
                .status(other_id)?
                .ok_or("missing other status")?
                .state,
            OutboxState::Pending
        );

        let other = outbox
            .claim_exact(other_id, 110, 10)?
            .ok_or("missing other exact claim")?;
        assert_eq!(other.job_id(), other_id);
        drop(stale);
        Ok(())
    }

    #[test]
    fn two_connections_cannot_claim_the_same_active_lease() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("outbox.sqlite3");
        let mut first = DeliveryOutbox::open(&path, key(9))?;
        first.enqueue(&request("double-claim"))?;
        let mut second = DeliveryOutbox::open(&path, key(9))?;

        let claimed = first.claim(100, 30)?.ok_or("missing first claim")?;
        assert!(second.claim(100, 30)?.is_none());
        assert_eq!(
            first.ack(claimed.job_id(), claimed.lease_token(), 101)?,
            AckOutcome::Delivered
        );
        Ok(())
    }

    #[test]
    fn expired_lease_is_dead_lettered_without_automatic_resend() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("outbox.sqlite3");
        let mut first = DeliveryOutbox::open(&path, key(11))?;
        first.enqueue(&request("crash-recovery"))?;
        let stale = first.claim(100, 10)?.ok_or("missing stale claim")?;
        drop(first);

        let mut restarted = DeliveryOutbox::open(&path, key(11))?;
        assert!(restarted.claim(109, 10)?.is_none());
        assert!(restarted.claim(110, 10)?.is_none());
        let status = restarted
            .status(stale.job_id())?
            .ok_or("missing dead-letter status")?;
        assert_eq!(status.state, OutboxState::DeadLetter);
        assert_eq!(
            status.terminal_reason,
            Some(OutboxTerminalReason::CrashExpired)
        );
        assert_eq!(status.attempt_summary_hash, None);
        assert_eq!(
            restarted.dead_letter(
                stale.job_id(),
                stale.lease_token(),
                111,
                OutboxTerminalReason::CrashExpired,
                None,
            )?,
            DeadLetterOutcome::AlreadyDeadLettered
        );
        let wrong_token = LeaseToken::generate(&SystemRandom::new())?;
        assert_eq!(
            restarted.dead_letter(
                stale.job_id(),
                &wrong_token,
                111,
                OutboxTerminalReason::CrashExpired,
                None,
            ),
            Err(OutboxError::LeaseMismatch)
        );
        assert_eq!(
            restarted.dead_letter(
                stale.job_id(),
                stale.lease_token(),
                111,
                OutboxTerminalReason::AmbiguousDelivery,
                None,
            ),
            Err(OutboxError::IdempotencyConflict)
        );
        Ok(())
    }

    #[test]
    fn acknowledgement_replay_is_idempotent_but_token_bound() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("outbox.sqlite3");
        let mut outbox = DeliveryOutbox::open(&path, key(13))?;
        outbox.enqueue(&request("ack-replay"))?;
        let claimed = outbox.claim(100, 20)?.ok_or("missing claim")?;

        assert_eq!(
            outbox.ack(claimed.job_id(), claimed.lease_token(), 101)?,
            AckOutcome::Delivered
        );
        assert_eq!(
            outbox.ack(claimed.job_id(), claimed.lease_token(), 102)?,
            AckOutcome::AlreadyDelivered
        );
        let wrong_token = LeaseToken::generate(&SystemRandom::new())?;
        assert_eq!(
            outbox.ack(claimed.job_id(), &wrong_token, 102),
            Err(OutboxError::LeaseMismatch)
        );
        Ok(())
    }

    #[test]
    fn retry_budget_ends_in_dead_letter_and_terminal_rows_prune() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("outbox.sqlite3");
        let mut outbox = DeliveryOutbox::open(&path, key(15))?;
        let mut enqueue = request("retry-budget");
        enqueue.max_attempts = 2;
        let job_id = outbox.enqueue(&enqueue)?.job_id();

        let first = outbox.claim(100, 20)?.ok_or("missing first claim")?;
        assert_eq!(
            outbox.retry(job_id, first.lease_token(), 101, 9, None)?,
            RetryOutcome::Scheduled { available_at: 110 }
        );
        assert!(outbox.claim(109, 20)?.is_none());
        let second = outbox.claim(110, 20)?.ok_or("missing second claim")?;
        let final_attempt = Digest32::sha256(b"secret-free-attempt-summary");
        assert_eq!(
            outbox.retry(job_id, second.lease_token(), 111, 9, Some(final_attempt))?,
            RetryOutcome::DeadLetter
        );
        drop(outbox);

        let mut outbox = DeliveryOutbox::open(&path, key(15))?;
        let status = outbox.status(job_id)?.ok_or("missing status")?;
        assert_eq!(status.state, OutboxState::DeadLetter);
        assert_eq!(
            status.terminal_reason,
            Some(OutboxTerminalReason::RetryBudgetExhausted)
        );
        assert_eq!(status.attempt_summary_hash, Some(final_attempt));
        assert_eq!(outbox.prune(110, 10)?, 0);
        assert_eq!(outbox.prune(111, 10)?, 1);
        assert!(outbox.status(job_id)?.is_none());
        Ok(())
    }

    #[test]
    fn dead_letter_audit_summary_survives_restart_and_rejects_tamper() -> Result<(), Box<dyn Error>>
    {
        let root = tempfile::tempdir()?;
        let path = root.path().join("outbox.sqlite3");
        let summary = Digest32::sha256(b"ambiguous-response-summary");
        let (job_id, lease_token) = {
            let mut outbox = DeliveryOutbox::open(&path, key(16))?;
            let job_id = outbox.enqueue(&request("durable-dead-letter"))?.job_id();
            let claimed = outbox.claim(100, 20)?.ok_or("missing claim")?;
            assert_eq!(
                outbox.dead_letter(
                    job_id,
                    claimed.lease_token(),
                    101,
                    OutboxTerminalReason::AmbiguousDelivery,
                    Some(summary),
                )?,
                DeadLetterOutcome::DeadLettered
            );
            (job_id, claimed.lease_token().expose().to_owned())
        };

        let lease_token = LeaseToken(lease_token);
        let mut reopened = DeliveryOutbox::open(&path, key(16))?;
        let status = reopened.status(job_id)?.ok_or("missing status")?;
        assert_eq!(
            status.terminal_reason,
            Some(OutboxTerminalReason::AmbiguousDelivery)
        );
        assert_eq!(status.attempt_summary_hash, Some(summary));
        assert_eq!(
            reopened.dead_letter(
                job_id,
                &lease_token,
                102,
                OutboxTerminalReason::AmbiguousDelivery,
                Some(summary),
            )?,
            DeadLetterOutcome::AlreadyDeadLettered
        );
        assert_eq!(
            reopened.dead_letter(
                job_id,
                &lease_token,
                102,
                OutboxTerminalReason::ProviderRejected,
                Some(summary),
            ),
            Err(OutboxError::IdempotencyConflict)
        );
        drop(reopened);

        let connection = Connection::open(&path)?;
        connection.execute(
            "UPDATE delivery_outbox SET terminal_reason = 5 WHERE job_id = ?1",
            params![job_id.as_bytes().as_slice()],
        )?;
        drop(connection);
        let reopened = DeliveryOutbox::open(&path, key(16))?;
        assert_eq!(
            reopened.status(job_id),
            Err(OutboxError::AuthenticationFailed)
        );
        Ok(())
    }

    #[test]
    fn wrong_key_and_ciphertext_corruption_fail_closed() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let wrong_key_path = root.path().join("wrong-key.sqlite3");
        {
            let mut outbox = DeliveryOutbox::open(&wrong_key_path, key(17))?;
            outbox.enqueue(&request("wrong-key"))?;
        }
        assert!(matches!(
            DeliveryOutbox::open(&wrong_key_path, key(18)),
            Err(OutboxError::AuthenticationFailed)
        ));

        let corrupt_path = root.path().join("corrupt.sqlite3");
        {
            let mut outbox = DeliveryOutbox::open(&corrupt_path, key(19))?;
            outbox.enqueue(&request("corrupt-ciphertext"))?;
        }
        let connection = Connection::open(&corrupt_path)?;
        connection.execute(
            "UPDATE delivery_outbox
             SET ciphertext = zeroblob(length(ciphertext))",
            [],
        )?;
        drop(connection);
        let mut reopened = DeliveryOutbox::open(&corrupt_path, key(19))?;
        assert!(matches!(
            reopened.claim(100, 30),
            Err(OutboxError::AuthenticationFailed)
        ));
        Ok(())
    }

    #[test]
    fn lifecycle_tamper_cannot_replay_a_delivered_job() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("lifecycle-tamper.sqlite3");
        let job_id = {
            let mut outbox = DeliveryOutbox::open(&path, key(20))?;
            let job_id = outbox.enqueue(&request("lifecycle-tamper"))?.job_id();
            let claimed = outbox.claim(100, 20)?.ok_or("missing claim")?;
            outbox.ack(job_id, claimed.lease_token(), 101)?;
            job_id
        };
        let connection = Connection::open(&path)?;
        connection.execute(
            "UPDATE delivery_outbox
             SET state = 0, attempts = 0, completion_token_hash = NULL,
                 delivered_at = NULL
             WHERE job_id = ?1",
            params![job_id.as_bytes().as_slice()],
        )?;
        drop(connection);

        let mut reopened = DeliveryOutbox::open(&path, key(20))?;
        assert_eq!(
            reopened.status(job_id),
            Err(OutboxError::AuthenticationFailed)
        );
        assert!(matches!(
            reopened.claim(102, 20),
            Err(OutboxError::AuthenticationFailed)
        ));
        Ok(())
    }

    #[test]
    fn ack_retry_and_prune_authenticate_the_full_row() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;

        let active_path = root.path().join("active-corruption.sqlite3");
        let mut active = DeliveryOutbox::open(&active_path, key(22))?;
        let active_id = active.enqueue(&request("active-corruption"))?.job_id();
        let active_claim = active.claim(100, 20)?.ok_or("missing active claim")?;
        active.connection.execute(
            "UPDATE delivery_outbox
             SET ciphertext = zeroblob(length(ciphertext))
             WHERE job_id = ?1",
            params![active_id.as_bytes().as_slice()],
        )?;
        assert_eq!(
            active.ack(active_id, active_claim.lease_token(), 101),
            Err(OutboxError::AuthenticationFailed)
        );
        assert_eq!(
            active.retry(active_id, active_claim.lease_token(), 101, 5, None),
            Err(OutboxError::AuthenticationFailed)
        );

        let terminal_path = root.path().join("terminal-corruption.sqlite3");
        let mut terminal = DeliveryOutbox::open(&terminal_path, key(24))?;
        let terminal_id = terminal.enqueue(&request("terminal-corruption"))?.job_id();
        let terminal_claim = terminal.claim(100, 20)?.ok_or("missing terminal claim")?;
        terminal.ack(terminal_id, terminal_claim.lease_token(), 101)?;
        terminal.connection.execute(
            "UPDATE delivery_outbox
             SET ciphertext = zeroblob(length(ciphertext))
             WHERE job_id = ?1",
            params![terminal_id.as_bytes().as_slice()],
        )?;
        assert_eq!(
            terminal.prune(101, 10),
            Err(OutboxError::AuthenticationFailed)
        );
        let remaining = terminal.connection.query_row(
            "SELECT COUNT(*) FROM delivery_outbox WHERE job_id = ?1",
            params![terminal_id.as_bytes().as_slice()],
            |row| row.get::<_, i64>(0),
        )?;
        assert_eq!(remaining, 1);
        Ok(())
    }

    #[test]
    fn concurrent_first_open_converges_on_one_schema() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("first-open.sqlite3");
        let barrier = Arc::new(Barrier::new(2));
        let first_path = path.clone();
        let first_barrier = Arc::clone(&barrier);
        let first = std::thread::spawn(move || {
            first_barrier.wait();
            DeliveryOutbox::open(first_path, key(26)).map(drop)
        });
        let second_path = path.clone();
        let second_barrier = Arc::clone(&barrier);
        let second = std::thread::spawn(move || {
            second_barrier.wait();
            DeliveryOutbox::open(second_path, key(26)).map(drop)
        });
        let first_result = first.join();
        let second_result = second.join();
        let Ok(first_open) = first_result else {
            return Err("first open thread panicked".into());
        };
        let Ok(second_open) = second_result else {
            return Err("second open thread panicked".into());
        };
        assert_eq!(first_open, Ok(()));
        assert_eq!(second_open, Ok(()));
        DeliveryOutbox::open(&path, key(26))?;
        Ok(())
    }

    #[test]
    fn unknown_schema_is_rejected_without_plaintext_fallback() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("future.sqlite3");
        let connection = Connection::open(&path)?;
        connection.execute_batch(
            "CREATE TABLE preserved (value TEXT NOT NULL) STRICT;
             INSERT INTO preserved(value) VALUES ('keep');
             PRAGMA user_version = 99;",
        )?;
        drop(connection);

        assert!(matches!(
            DeliveryOutbox::open(&path, key(21)),
            Err(OutboxError::UnsupportedSchema)
        ));
        let connection = Connection::open(&path)?;
        assert_eq!(
            connection.query_row("PRAGMA journal_mode", [], |row| { row.get::<_, String>(0) })?,
            "delete"
        );
        assert_eq!(
            connection.query_row("SELECT value FROM preserved", [], |row| {
                row.get::<_, String>(0)
            })?,
            "keep"
        );
        Ok(())
    }

    #[test]
    fn idempotency_is_exact_and_nonce_is_unique() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("outbox.sqlite3");
        let mut outbox = DeliveryOutbox::open(&path, key(23))?;
        let first = outbox.enqueue(&request("stable-operation"))?;
        assert_eq!(
            outbox.enqueue(&request("stable-operation"))?,
            EnqueueOutcome::Existing(first.job_id())
        );
        let mut conflicting = request("stable-operation");
        conflicting.payload = b"different-payload";
        assert_eq!(
            outbox.enqueue(&conflicting),
            Err(OutboxError::IdempotencyConflict)
        );
        outbox.enqueue(&request("second-operation"))?;

        let mut statement = outbox
            .connection
            .prepare("SELECT nonce FROM delivery_outbox ORDER BY created_at, job_id")?;
        let nonces = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(nonces.len(), 2);
        assert_ne!(nonces[0], nonces[1]);
        let (stored_destination, stored_idempotency) = outbox.connection.query_row(
            "SELECT destination_hash, idempotency_hash
             FROM delivery_outbox WHERE job_id = ?1",
            params![first.job_id().as_bytes().as_slice()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )?;
        assert_ne!(
            stored_destination,
            domain_hash(DESTINATION_HASH_DOMAIN, DESTINATION)
        );
        assert_ne!(
            stored_idempotency,
            domain_hash(IDEMPOTENCY_HASH_DOMAIN, b"stable-operation")
        );
        Ok(())
    }

    #[test]
    fn strict_bounds_reject_oversize_and_invalid_time() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("outbox.sqlite3");
        let mut outbox = DeliveryOutbox::open(&path, key(25))?;
        let oversized = vec![b'x'; MAX_PAYLOAD_BYTES + 1];
        let mut invalid = request("oversize");
        invalid.payload = &oversized;
        assert_eq!(outbox.enqueue(&invalid), Err(OutboxError::InvalidInput));
        assert!(matches!(
            outbox.claim(-1, 10),
            Err(OutboxError::InvalidInput)
        ));
        assert!(matches!(
            outbox.claim(100, MAX_LEASE_SECONDS + 1),
            Err(OutboxError::InvalidInput)
        ));
        assert_eq!(outbox.prune(100, 0), Err(OutboxError::InvalidInput));
        Ok(())
    }

    #[test]
    fn debug_output_redacts_every_secret() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("outbox.sqlite3");
        let encryption_key = key(27);
        assert_eq!(
            format!("{encryption_key:?}"),
            "OutboxEncryptionKey([REDACTED])"
        );
        let enqueue = request("debug-idempotency-secret");
        let request_debug = format!("{enqueue:?}");
        assert!(!request_debug.contains("debug-idempotency-secret"));
        assert!(!request_debug.contains("provider-secret-token"));

        let mut outbox = DeliveryOutbox::open(&path, encryption_key)?;
        outbox.enqueue(&enqueue)?;
        let claimed = outbox.claim(100, 20)?.ok_or("missing claim")?;
        let claim_debug = format!("{claimed:?}");
        assert!(!claim_debug.contains("hooks.example"));
        assert!(!claim_debug.contains("opaque-provider-payload"));
        assert!(!claim_debug.contains("provider-secret-token"));
        assert!(claim_debug.contains("[REDACTED]"));
        Ok(())
    }

    #[test]
    fn sqlite_files_contain_no_plaintext_delivery_material() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("outbox.sqlite3");
        let idempotency = "idempotency-secret-216ae17a6d47";
        {
            let mut outbox = DeliveryOutbox::open(&path, key(29))?;
            outbox.enqueue(&request(idempotency))?;
        }

        let connection = Connection::open(&path)?;
        let checkpoint = connection.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        assert_eq!(checkpoint.0, 0);
        drop(connection);

        for candidate in [
            path.clone(),
            append_suffix(&path, "-wal"),
            append_suffix(&path, "-shm"),
            append_suffix(&path, "-journal"),
        ] {
            if candidate.exists() {
                let bytes = fs::read(candidate)?;
                assert!(!contains_bytes(&bytes, DESTINATION));
                assert!(!contains_bytes(&bytes, PAYLOAD));
                assert!(!contains_bytes(&bytes, CREDENTIAL_REFERENCE));
                assert!(!contains_bytes(&bytes, idempotency.as_bytes()));
            }
        }
        Ok(())
    }

    #[test]
    fn database_uses_wal_and_strict_tables() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("outbox.sqlite3");
        let outbox = DeliveryOutbox::open(&path, key(31))?;
        let journal_mode = outbox
            .connection
            .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))?;
        assert_eq!(journal_mode, "wal");
        let strict_tables = outbox.connection.query_row(
            "SELECT COUNT(*) FROM pragma_table_list
             WHERE schema = 'main' AND name IN ('outbox_meta', 'delivery_outbox')
               AND strict = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        assert_eq!(strict_tables, 2);
        Ok(())
    }
}
