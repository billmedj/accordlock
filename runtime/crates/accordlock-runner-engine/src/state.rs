//! Durable replay reservations and monotonic trusted-time state for a runner.

use std::{collections::HashMap, path::Path, sync::Mutex, time::Duration};

use accordlock_protocol::Digest32;
use rusqlite::{Connection, ErrorCode, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

use crate::MAX_ACCEPTED_DISPATCHES;

const STATE_SCHEMA_VERSION: i64 = 1;
const STATE_APPLICATION_ID: i64 = 0x41_43_4c_52;
const BUSY_TIMEOUT: Duration = Duration::from_secs(2);

const CREATE_SCHEMA: &str = r"
CREATE TABLE runner_state_metadata (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    replay_capacity INTEGER NOT NULL CHECK (replay_capacity > 0),
    trusted_time_high_water INTEGER NOT NULL CHECK (trusted_time_high_water >= 0)
) STRICT;
CREATE TABLE runner_replay_reservations (
    replay_kind INTEGER NOT NULL CHECK (replay_kind IN (1, 2)),
    digest BLOB NOT NULL CHECK (length(digest) = 32),
    reservation_id BLOB NOT NULL CHECK (length(reservation_id) = 16),
    lifecycle INTEGER NOT NULL CHECK (lifecycle IN (0, 1)),
    reserved_at INTEGER NOT NULL CHECK (reserved_at >= 0),
    retain_until INTEGER NOT NULL CHECK (retain_until > reserved_at),
    PRIMARY KEY (replay_kind, digest),
    UNIQUE (replay_kind, reservation_id)
) STRICT;
";

/// Independent replay namespaces maintained by a runner state store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunnerReplayKind {
    Dispatch,
    ActionApproval,
}

impl RunnerReplayKind {
    const fn code(self) -> i64 {
        match self {
            Self::Dispatch => 1,
            Self::ActionApproval => 2,
        }
    }
}

/// Exact identity returned by an atomic replay reservation.
///
/// A state implementation must compare all three fields when committing or
/// releasing a reservation. This prevents a stale owner from finalizing a
/// later reservation for the same digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunnerStateReservation {
    kind: RunnerReplayKind,
    digest: Digest32,
    reservation_id: Uuid,
}

impl RunnerStateReservation {
    /// Creates a reservation identity for a trusted state implementation.
    ///
    /// # Errors
    ///
    /// Rejects a nil reservation identifier.
    pub fn new(
        kind: RunnerReplayKind,
        digest: Digest32,
        reservation_id: Uuid,
    ) -> Result<Self, RunnerStateError> {
        if reservation_id.is_nil() {
            return Err(RunnerStateError::InvalidConfiguration);
        }
        Ok(Self {
            kind,
            digest,
            reservation_id,
        })
    }

    #[must_use]
    pub const fn kind(&self) -> RunnerReplayKind {
        self.kind
    }

    #[must_use]
    pub const fn digest(&self) -> Digest32 {
        self.digest
    }

    #[must_use]
    pub const fn reservation_id(&self) -> Uuid {
        self.reservation_id
    }
}

/// Object-safe state boundary used by `EnterpriseRunner`.
///
/// Implementations are trusted bootstrap dependencies. `reserve` must be
/// atomic across every process sharing the protected environment. A pending
/// reservation is deliberately a replay blocker: a crash must not make an
/// ambiguous delivery eligible again.
pub trait RunnerStateStore: Send + Sync {
    /// Atomically advances the trusted-time high-water mark.
    ///
    /// # Errors
    ///
    /// Returns `ClockRollback` if `trusted_now` is below the retained mark and
    /// fails closed for unavailable or corrupt state.
    fn observe_trusted_time(&self, trusted_now: i64) -> Result<(), RunnerStateError>;

    /// Atomically reserves one digest in its independent replay namespace.
    /// `retain_until` is the verified end of the replayable protocol window,
    /// not a caller-selected cleanup preference.
    ///
    /// # Errors
    ///
    /// Returns `AlreadyReserved` for both pending and unexpired committed
    /// entries, `CapacityExceeded` at the configured hard bound, and otherwise
    /// fails closed for unavailable or corrupt state. Expired committed entries
    /// may be removed; pending entries require explicit reconciliation.
    fn reserve(
        &self,
        kind: RunnerReplayKind,
        digest: Digest32,
        retain_until: i64,
    ) -> Result<RunnerStateReservation, RunnerStateError>;

    /// Marks the exact pending reservation committed.
    ///
    /// # Errors
    ///
    /// Returns `ReservationAmbiguous` unless exactly one matching pending row
    /// is changed. Storage uncertainty leaves the row replay-blocking.
    fn commit(&self, reservation: &RunnerStateReservation) -> Result<(), RunnerStateError>;

    /// Releases an exact pending reservation after a known pre-effect failure.
    ///
    /// # Errors
    ///
    /// Returns `ReservationAmbiguous` unless exactly one matching pending row
    /// is removed. Committed rows can never be released.
    fn release(&self, reservation: &RunnerStateReservation) -> Result<(), RunnerStateError>;
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum RunnerStateError {
    #[error("runner replay digest is already reserved")]
    AlreadyReserved,
    #[error("runner replay capacity is exhausted")]
    CapacityExceeded,
    #[error("trusted clock moved below its durable high-water mark")]
    ClockRollback,
    #[error("runner state reservation is missing, stale, or has ambiguous lifecycle")]
    ReservationAmbiguous,
    #[error("runner state is unavailable")]
    Unavailable,
    #[error("runner state is corrupt or has an unsupported schema")]
    Corrupt,
    #[error("runner state configuration is invalid")]
    InvalidConfiguration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReservationLifecycle {
    Pending,
    Committed,
}

#[derive(Clone, Copy, Debug)]
struct MemoryReservation {
    reservation_id: Uuid,
    lifecycle: ReservationLifecycle,
    retain_until: i64,
}

#[derive(Debug)]
struct MemoryState {
    trusted_time_high_water: i64,
    dispatches: HashMap<Digest32, MemoryReservation>,
    action_approvals: HashMap<Digest32, MemoryReservation>,
}

/// Process-local state for unit tests and account-free local evaluation.
///
/// This implementation preserves the historical `EnterpriseRunner::new`
/// behavior. It is not suitable for a runner that must retain replay state
/// across restart.
#[derive(Debug)]
pub struct InMemoryRunnerStateStore {
    capacity: usize,
    state: Mutex<MemoryState>,
}

impl InMemoryRunnerStateStore {
    /// Creates a process-local store with the production hard bound.
    #[must_use]
    pub fn new() -> Self {
        Self {
            capacity: MAX_ACCEPTED_DISPATCHES,
            state: Mutex::new(MemoryState {
                trusted_time_high_water: 0,
                dispatches: HashMap::new(),
                action_approvals: HashMap::new(),
            }),
        }
    }

    /// Creates a bounded process-local store.
    ///
    /// # Errors
    ///
    /// Rejects zero or a value above the production hard bound.
    pub fn with_capacity(capacity: usize) -> Result<Self, RunnerStateError> {
        validate_capacity(capacity)?;
        Ok(Self {
            capacity,
            state: Mutex::new(MemoryState {
                trusted_time_high_water: 0,
                dispatches: HashMap::new(),
                action_approvals: HashMap::new(),
            }),
        })
    }
}

impl Default for InMemoryRunnerStateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RunnerStateStore for InMemoryRunnerStateStore {
    fn observe_trusted_time(&self, trusted_now: i64) -> Result<(), RunnerStateError> {
        if trusted_now < 0 {
            return Err(RunnerStateError::InvalidConfiguration);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| RunnerStateError::Unavailable)?;
        if trusted_now < state.trusted_time_high_water {
            return Err(RunnerStateError::ClockRollback);
        }
        state.trusted_time_high_water = trusted_now;
        Ok(())
    }

    fn reserve(
        &self,
        kind: RunnerReplayKind,
        digest: Digest32,
        retain_until: i64,
    ) -> Result<RunnerStateReservation, RunnerStateError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RunnerStateError::Unavailable)?;
        let high_water = state.trusted_time_high_water;
        if retain_until <= high_water {
            return Err(RunnerStateError::InvalidConfiguration);
        }
        let entries = memory_entries_mut(&mut state, kind);
        entries.retain(|_, entry| {
            entry.lifecycle == ReservationLifecycle::Pending || entry.retain_until > high_water
        });
        if entries.contains_key(&digest) {
            return Err(RunnerStateError::AlreadyReserved);
        }
        if entries.len() >= self.capacity {
            return Err(RunnerStateError::CapacityExceeded);
        }
        let reservation = RunnerStateReservation::new(kind, digest, Uuid::new_v4())?;
        entries.insert(
            digest,
            MemoryReservation {
                reservation_id: reservation.reservation_id,
                lifecycle: ReservationLifecycle::Pending,
                retain_until,
            },
        );
        Ok(reservation)
    }

    fn commit(&self, reservation: &RunnerStateReservation) -> Result<(), RunnerStateError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RunnerStateError::Unavailable)?;
        let Some(stored) =
            memory_entries_mut(&mut state, reservation.kind).get_mut(&reservation.digest)
        else {
            return Err(RunnerStateError::ReservationAmbiguous);
        };
        if stored.reservation_id != reservation.reservation_id
            || stored.lifecycle != ReservationLifecycle::Pending
        {
            return Err(RunnerStateError::ReservationAmbiguous);
        }
        stored.lifecycle = ReservationLifecycle::Committed;
        Ok(())
    }

    fn release(&self, reservation: &RunnerStateReservation) -> Result<(), RunnerStateError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RunnerStateError::Unavailable)?;
        let entries = memory_entries_mut(&mut state, reservation.kind);
        let Some(stored) = entries.get(&reservation.digest) else {
            return Err(RunnerStateError::ReservationAmbiguous);
        };
        if stored.reservation_id != reservation.reservation_id
            || stored.lifecycle != ReservationLifecycle::Pending
        {
            return Err(RunnerStateError::ReservationAmbiguous);
        }
        entries.remove(&reservation.digest);
        Ok(())
    }
}

fn memory_entries_mut(
    state: &mut MemoryState,
    kind: RunnerReplayKind,
) -> &mut HashMap<Digest32, MemoryReservation> {
    match kind {
        RunnerReplayKind::Dispatch => &mut state.dispatches,
        RunnerReplayKind::ActionApproval => &mut state.action_approvals,
    }
}

/// Strict single-host `SQLite` state for an enterprise runner.
///
/// The database retains only digests, opaque reservation identifiers,
/// lifecycle values, bounded metadata, and trusted time. It contains no
/// provider credentials, task content, approval content, or model output.
pub struct SqliteRunnerStateStore {
    capacity: usize,
    connection: Mutex<Connection>,
}

impl std::fmt::Debug for SqliteRunnerStateStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteRunnerStateStore")
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl SqliteRunnerStateStore {
    /// Opens or creates a store with the production hard bound.
    ///
    /// # Errors
    ///
    /// Unknown schemas, existing unrelated databases, corruption, and storage
    /// failure are rejected without migration or destructive recovery.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RunnerStateError> {
        Self::open_with_capacity(path, MAX_ACCEPTED_DISPATCHES)
    }

    /// Opens or creates a store with an explicit bounded capacity.
    ///
    /// The capacity is persisted and must match on every reopen. This prevents
    /// configuration drift from silently widening retained state.
    ///
    /// # Errors
    ///
    /// Rejects invalid capacity, unknown schema, capacity drift, corruption,
    /// or unavailable storage.
    pub fn open_with_capacity(
        path: impl AsRef<Path>,
        capacity: usize,
    ) -> Result<Self, RunnerStateError> {
        validate_capacity(capacity)?;
        let mut connection = Connection::open(path).map_err(map_storage_error)?;
        connection
            .busy_timeout(BUSY_TIMEOUT)
            .map_err(map_storage_error)?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;
                 PRAGMA trusted_schema = OFF;
                 PRAGMA secure_delete = ON;",
            )
            .map_err(map_storage_error)?;
        let version = connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .map_err(map_storage_error)?;
        match version {
            0 => initialize_schema(&mut connection, capacity)?,
            STATE_SCHEMA_VERSION => validate_schema(&connection, capacity)?,
            _ => return Err(RunnerStateError::Corrupt),
        }
        Ok(Self {
            capacity,
            connection: Mutex::new(connection),
        })
    }
}

impl RunnerStateStore for SqliteRunnerStateStore {
    fn observe_trusted_time(&self, trusted_now: i64) -> Result<(), RunnerStateError> {
        if trusted_now < 0 {
            return Err(RunnerStateError::InvalidConfiguration);
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| RunnerStateError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_storage_error)?;
        let high_water = read_high_water(&transaction)?;
        if trusted_now < high_water {
            return Err(RunnerStateError::ClockRollback);
        }
        transaction
            .execute(
                "UPDATE runner_state_metadata
                 SET trusted_time_high_water = ?1
                 WHERE singleton = 1 AND trusted_time_high_water <= ?1",
                params![trusted_now],
            )
            .map_err(map_storage_error)?;
        transaction.commit().map_err(map_storage_error)
    }

    fn reserve(
        &self,
        kind: RunnerReplayKind,
        digest: Digest32,
        retain_until: i64,
    ) -> Result<RunnerStateReservation, RunnerStateError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| RunnerStateError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_storage_error)?;
        let reserved_at = read_high_water(&transaction)?;
        if retain_until <= reserved_at {
            return Err(RunnerStateError::InvalidConfiguration);
        }
        transaction
            .execute(
                "DELETE FROM runner_replay_reservations
                 WHERE replay_kind = ?1
                   AND lifecycle = 1
                   AND retain_until <= ?2",
                params![kind.code(), reserved_at],
            )
            .map_err(map_storage_error)?;
        let already_retained: i64 = transaction
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM runner_replay_reservations
                     WHERE replay_kind = ?1 AND digest = ?2
                 )",
                params![kind.code(), digest.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(map_storage_error)?;
        if already_retained == 1 {
            return Err(RunnerStateError::AlreadyReserved);
        }
        if already_retained != 0 {
            return Err(RunnerStateError::Corrupt);
        }
        let retained: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM runner_replay_reservations WHERE replay_kind = ?1",
                params![kind.code()],
                |row| row.get(0),
            )
            .map_err(map_storage_error)?;
        let retained = usize::try_from(retained).map_err(|_| RunnerStateError::Corrupt)?;
        if retained >= self.capacity {
            return Err(RunnerStateError::CapacityExceeded);
        }
        let reservation = RunnerStateReservation::new(kind, digest, Uuid::new_v4())?;
        transaction
            .execute(
                "INSERT INTO runner_replay_reservations (
                     replay_kind, digest, reservation_id, lifecycle,
                     reserved_at, retain_until
                 ) VALUES (?1, ?2, ?3, 0, ?4, ?5)",
                params![
                    kind.code(),
                    digest.as_bytes().as_slice(),
                    reservation.reservation_id.as_bytes().as_slice(),
                    reserved_at,
                    retain_until,
                ],
            )
            .map_err(|error| {
                if is_constraint(&error) {
                    RunnerStateError::AlreadyReserved
                } else {
                    map_storage_error(error)
                }
            })?;
        transaction.commit().map_err(map_storage_error)?;
        Ok(reservation)
    }

    fn commit(&self, reservation: &RunnerStateReservation) -> Result<(), RunnerStateError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| RunnerStateError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_storage_error)?;
        let changed = transaction
            .execute(
                "UPDATE runner_replay_reservations
                 SET lifecycle = 1
                 WHERE replay_kind = ?1
                   AND digest = ?2
                   AND reservation_id = ?3
                   AND lifecycle = 0",
                reservation_parameters(reservation),
            )
            .map_err(map_storage_error)?;
        if changed != 1 {
            return Err(RunnerStateError::ReservationAmbiguous);
        }
        transaction.commit().map_err(map_storage_error)
    }

    fn release(&self, reservation: &RunnerStateReservation) -> Result<(), RunnerStateError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| RunnerStateError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_storage_error)?;
        let changed = transaction
            .execute(
                "DELETE FROM runner_replay_reservations
                 WHERE replay_kind = ?1
                   AND digest = ?2
                   AND reservation_id = ?3
                   AND lifecycle = 0",
                reservation_parameters(reservation),
            )
            .map_err(map_storage_error)?;
        if changed != 1 {
            return Err(RunnerStateError::ReservationAmbiguous);
        }
        transaction.commit().map_err(map_storage_error)
    }
}

fn reservation_parameters(reservation: &RunnerStateReservation) -> (i64, &[u8], &[u8]) {
    (
        reservation.kind.code(),
        reservation.digest.as_bytes().as_slice(),
        reservation.reservation_id.as_bytes().as_slice(),
    )
}

fn initialize_schema(connection: &mut Connection, capacity: usize) -> Result<(), RunnerStateError> {
    let capacity_i64 =
        i64::try_from(capacity).map_err(|_| RunnerStateError::InvalidConfiguration)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_storage_error)?;
    let version = transaction
        .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
        .map_err(map_storage_error)?;
    if version == STATE_SCHEMA_VERSION {
        transaction.commit().map_err(map_storage_error)?;
        return validate_schema(connection, capacity);
    }
    if version != 0 {
        return Err(RunnerStateError::Corrupt);
    }
    let existing_objects: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )
        .map_err(map_storage_error)?;
    if existing_objects != 0 {
        return Err(RunnerStateError::Corrupt);
    }
    transaction
        .execute_batch(CREATE_SCHEMA)
        .map_err(map_storage_error)?;
    transaction
        .execute(
            "INSERT INTO runner_state_metadata (
                 singleton, schema_version, replay_capacity, trusted_time_high_water
             ) VALUES (1, 1, ?1, 0)",
            params![capacity_i64],
        )
        .map_err(map_storage_error)?;
    transaction
        .pragma_update(None, "user_version", STATE_SCHEMA_VERSION)
        .map_err(map_storage_error)?;
    transaction
        .pragma_update(None, "application_id", STATE_APPLICATION_ID)
        .map_err(map_storage_error)?;
    transaction.commit().map_err(map_storage_error)
}

fn validate_schema(connection: &Connection, capacity: usize) -> Result<(), RunnerStateError> {
    let application_id = connection
        .query_row("PRAGMA application_id", [], |row| row.get::<_, i64>(0))
        .map_err(map_storage_error)?;
    if application_id != STATE_APPLICATION_ID {
        return Err(RunnerStateError::Corrupt);
    }
    let quick_check: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(map_storage_error)?;
    if quick_check != "ok" {
        return Err(RunnerStateError::Corrupt);
    }
    let schema_objects: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )
        .map_err(map_storage_error)?;
    if schema_objects != 2 {
        return Err(RunnerStateError::Corrupt);
    }
    let metadata_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM runner_state_metadata", [], |row| {
            row.get(0)
        })
        .map_err(map_storage_error)?;
    if metadata_count != 1 {
        return Err(RunnerStateError::Corrupt);
    }
    let (schema_version, retained_capacity, high_water): (i64, i64, i64) = connection
        .query_row(
            "SELECT schema_version, replay_capacity, trusted_time_high_water
             FROM runner_state_metadata WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(map_storage_error)?;
    let capacity = i64::try_from(capacity).map_err(|_| RunnerStateError::InvalidConfiguration)?;
    if schema_version != STATE_SCHEMA_VERSION || retained_capacity != capacity || high_water < 0 {
        return Err(RunnerStateError::Corrupt);
    }
    let invalid_rows: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM runner_replay_reservations
             WHERE replay_kind NOT IN (1, 2)
                OR length(digest) != 32
                OR length(reservation_id) != 16
                OR lifecycle NOT IN (0, 1)
                OR reserved_at < 0
                OR retain_until <= reserved_at",
            [],
            |row| row.get(0),
        )
        .map_err(map_storage_error)?;
    if invalid_rows != 0 {
        return Err(RunnerStateError::Corrupt);
    }
    for kind in [RunnerReplayKind::Dispatch, RunnerReplayKind::ActionApproval] {
        let retained: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM runner_replay_reservations WHERE replay_kind = ?1",
                params![kind.code()],
                |row| row.get(0),
            )
            .map_err(map_storage_error)?;
        if retained < 0 || retained > capacity {
            return Err(RunnerStateError::Corrupt);
        }
    }
    Ok(())
}

fn read_high_water(transaction: &rusqlite::Transaction<'_>) -> Result<i64, RunnerStateError> {
    let value = transaction
        .query_row(
            "SELECT trusted_time_high_water
             FROM runner_state_metadata WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(map_storage_error)?;
    if value < 0 {
        return Err(RunnerStateError::Corrupt);
    }
    Ok(value)
}

fn validate_capacity(capacity: usize) -> Result<(), RunnerStateError> {
    if capacity == 0 || capacity > MAX_ACCEPTED_DISPATCHES {
        return Err(RunnerStateError::InvalidConfiguration);
    }
    Ok(())
}

fn is_constraint(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(inner, _)
            if inner.code == ErrorCode::ConstraintViolation
    )
}

#[allow(clippy::needless_pass_by_value)]
fn map_storage_error(error: rusqlite::Error) -> RunnerStateError {
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
            RunnerStateError::Corrupt
        }
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::QueryReturnedNoRows
        | rusqlite::Error::QueryReturnedMoreThanOneRow => RunnerStateError::Corrupt,
        _ => RunnerStateError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        fs,
        sync::{Arc, Barrier},
        thread,
    };

    use super::*;

    fn digest(seed: u8) -> Digest32 {
        Digest32::from_bytes([seed; 32])
    }

    #[test]
    fn committed_dispatch_and_approval_replay_survive_restart() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("runner.sqlite3");
        {
            let store = SqliteRunnerStateStore::open(&path)?;
            store.observe_trusted_time(200)?;
            let dispatch = store.reserve(RunnerReplayKind::Dispatch, digest(1), 300)?;
            store.commit(&dispatch)?;
            let approval = store.reserve(RunnerReplayKind::ActionApproval, digest(2), 300)?;
            store.commit(&approval)?;
        }
        let reopened = SqliteRunnerStateStore::open(&path)?;
        assert_eq!(
            reopened.reserve(RunnerReplayKind::Dispatch, digest(1), 300),
            Err(RunnerStateError::AlreadyReserved)
        );
        assert_eq!(
            reopened.reserve(RunnerReplayKind::ActionApproval, digest(2), 300),
            Err(RunnerStateError::AlreadyReserved)
        );
        Ok(())
    }

    #[test]
    fn crash_pending_state_is_replay_blocking_after_restart() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("pending.sqlite3");
        {
            let store = SqliteRunnerStateStore::open(&path)?;
            store.observe_trusted_time(200)?;
            let _pending = store.reserve(RunnerReplayKind::Dispatch, digest(3), 300)?;
        }
        let reopened = SqliteRunnerStateStore::open(&path)?;
        assert_eq!(
            reopened.reserve(RunnerReplayKind::Dispatch, digest(3), 300),
            Err(RunnerStateError::AlreadyReserved)
        );
        Ok(())
    }

    #[test]
    fn exact_release_allows_retry_but_commit_is_irreversible() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let store = SqliteRunnerStateStore::open(root.path().join("lifecycle.sqlite3"))?;
        store.observe_trusted_time(200)?;
        let first = store.reserve(RunnerReplayKind::Dispatch, digest(4), 300)?;
        store.release(&first)?;
        let second = store.reserve(RunnerReplayKind::Dispatch, digest(4), 300)?;
        assert_ne!(first.reservation_id(), second.reservation_id());
        assert_eq!(
            store.release(&first),
            Err(RunnerStateError::ReservationAmbiguous)
        );
        store.commit(&second)?;
        assert_eq!(
            store.release(&second),
            Err(RunnerStateError::ReservationAmbiguous)
        );
        assert_eq!(
            store.reserve(RunnerReplayKind::Dispatch, digest(4), 300),
            Err(RunnerStateError::AlreadyReserved)
        );
        Ok(())
    }

    #[test]
    fn durable_high_water_rejects_rollback_after_restart() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("time.sqlite3");
        SqliteRunnerStateStore::open(&path)?.observe_trusted_time(300)?;
        let reopened = SqliteRunnerStateStore::open(&path)?;
        assert_eq!(
            reopened.observe_trusted_time(299),
            Err(RunnerStateError::ClockRollback)
        );
        reopened.observe_trusted_time(300)?;
        reopened.observe_trusted_time(301)?;
        Ok(())
    }

    #[test]
    fn capacity_is_persisted_bounded_and_independent_per_kind() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("capacity.sqlite3");
        let store = SqliteRunnerStateStore::open_with_capacity(&path, 1)?;
        store.observe_trusted_time(200)?;
        store.commit(&store.reserve(RunnerReplayKind::Dispatch, digest(5), 250)?)?;
        assert_eq!(
            store.reserve(RunnerReplayKind::Dispatch, digest(6), 300),
            Err(RunnerStateError::CapacityExceeded)
        );
        store.commit(&store.reserve(RunnerReplayKind::ActionApproval, digest(7), 300)?)?;
        store.observe_trusted_time(250)?;
        store.commit(&store.reserve(RunnerReplayKind::Dispatch, digest(6), 400)?)?;
        drop(store);
        assert!(matches!(
            SqliteRunnerStateStore::open(&path),
            Err(RunnerStateError::Corrupt)
        ));
        SqliteRunnerStateStore::open_with_capacity(&path, 1)?;
        Ok(())
    }

    #[test]
    fn expired_pending_reservation_is_not_pruned_without_reconciliation()
    -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let store = SqliteRunnerStateStore::open_with_capacity(
            root.path().join("pending-capacity.sqlite3"),
            1,
        )?;
        store.observe_trusted_time(200)?;
        let _pending = store.reserve(RunnerReplayKind::Dispatch, digest(9), 250)?;
        store.observe_trusted_time(300)?;
        assert_eq!(
            store.reserve(RunnerReplayKind::Dispatch, digest(10), 400),
            Err(RunnerStateError::CapacityExceeded)
        );
        Ok(())
    }

    #[test]
    fn concurrent_reservation_has_one_winner_across_connections() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("concurrent.sqlite3");
        SqliteRunnerStateStore::open(&path)?.observe_trusted_time(200)?;
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let store = SqliteRunnerStateStore::open(&path)?;
                barrier.wait();
                store.reserve(RunnerReplayKind::Dispatch, digest(8), 300)
            }));
        }
        barrier.wait();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().map_err(|_| "reservation thread panicked"))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Err(RunnerStateError::AlreadyReserved))
                .count(),
            1
        );
        Ok(())
    }

    #[test]
    fn concurrent_first_open_never_adopts_a_partial_schema() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("first-open.sqlite3");
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                SqliteRunnerStateStore::open(&path)
            }));
        }
        barrier.wait();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().map_err(|_| "initialization thread panicked"))
            .collect::<Result<Vec<_>, _>>()?;
        assert!(results.iter().any(Result::is_ok));
        assert!(
            results
                .iter()
                .all(|result| matches!(result, Ok(_) | Err(RunnerStateError::Unavailable)))
        );
        SqliteRunnerStateStore::open(&path)?.observe_trusted_time(200)?;
        Ok(())
    }

    #[test]
    fn invalid_database_bytes_fail_closed_as_corruption() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("corrupt.sqlite3");
        fs::write(&path, b"this is not a sqlite database")?;
        assert!(matches!(
            SqliteRunnerStateStore::open(&path),
            Err(RunnerStateError::Corrupt)
        ));
        Ok(())
    }

    #[test]
    fn unknown_or_unrelated_schema_is_never_modified() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("future.sqlite3");
        let connection = Connection::open(&path)?;
        connection.execute_batch(
            "CREATE TABLE preserved (value TEXT NOT NULL);
             INSERT INTO preserved(value) VALUES ('keep');
             PRAGMA user_version = 99;",
        )?;
        drop(connection);
        assert!(matches!(
            SqliteRunnerStateStore::open(&path),
            Err(RunnerStateError::Corrupt)
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
