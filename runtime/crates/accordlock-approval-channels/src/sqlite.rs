use std::{path::Path, time::Duration};

use rusqlite::{Connection, ErrorCode, TransactionBehavior, params};
use uuid::Uuid;

use crate::{ApprovalReplayStore, MAX_PROVIDER_EVENT_ID_BYTES, ReplayStoreError};

const REPLAY_SCHEMA_VERSION: i64 = 1;
const BUSY_TIMEOUT: Duration = Duration::from_secs(2);

const REPLAY_SCHEMA: &str = r"
BEGIN IMMEDIATE;
CREATE TABLE consumed_approvals (
    challenge_id TEXT PRIMARY KEY NOT NULL,
    provider_event_id TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL CHECK (expires_at > 0)
) STRICT;
CREATE INDEX consumed_approvals_expiry_idx ON consumed_approvals(expires_at);
PRAGMA user_version = 1;
COMMIT;
";

/// Durable, process-independent replay protection for remote approvals.
///
/// A successful insert atomically consumes both the `AccordLock` challenge and
/// the authenticated provider event. Reopening the database cannot resurrect
/// either identifier. The database contains no interaction token, message
/// content, credential, or provider payload.
pub struct DurableApprovalReplayStore {
    connection: Connection,
}

impl std::fmt::Debug for DurableApprovalReplayStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableApprovalReplayStore")
            .finish_non_exhaustive()
    }
}

impl DurableApprovalReplayStore {
    /// Opens or creates a replay database without migrating unknown schemas.
    ///
    /// # Errors
    ///
    /// Returns `Unavailable` if storage cannot be opened, configured, or has
    /// an unsupported schema version.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReplayStoreError> {
        let connection = Connection::open(path).map_err(|_| ReplayStoreError::Unavailable)?;
        connection
            .busy_timeout(BUSY_TIMEOUT)
            .map_err(|_| ReplayStoreError::Unavailable)?;
        connection
            .execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")
            .map_err(|_| ReplayStoreError::Unavailable)?;
        let version = connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .map_err(|_| ReplayStoreError::Unavailable)?;
        match version {
            0 => connection
                .execute_batch(REPLAY_SCHEMA)
                .map_err(|_| ReplayStoreError::Unavailable)?,
            REPLAY_SCHEMA_VERSION => {}
            _ => return Err(ReplayStoreError::Unavailable),
        }
        Ok(Self { connection })
    }

    /// Deletes replay markers only after their signed challenges have expired.
    ///
    /// The trusted host supplies time so OS-clock rollback cannot silently
    /// widen the acceptance window inside this store.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` for negative time and `Unavailable` for storage
    /// failure.
    pub fn prune_expired(&mut self, trusted_now: i64) -> Result<usize, ReplayStoreError> {
        if trusted_now < 0 {
            return Err(ReplayStoreError::InvalidInput);
        }
        self.connection
            .execute(
                "DELETE FROM consumed_approvals WHERE expires_at <= ?1",
                params![trusted_now],
            )
            .map_err(|_| ReplayStoreError::Unavailable)
    }
}

impl ApprovalReplayStore for DurableApprovalReplayStore {
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
        transaction
            .execute(
                "INSERT INTO consumed_approvals (
                     challenge_id, provider_event_id, expires_at
                 ) VALUES (?1, ?2, ?3)",
                params![challenge_id.to_string(), provider_event_id, expires_at],
            )
            .map_err(|error| {
                if is_constraint(&error) {
                    ReplayStoreError::AlreadyConsumed
                } else {
                    ReplayStoreError::Unavailable
                }
            })?;
        transaction
            .commit()
            .map_err(|_| ReplayStoreError::Unavailable)
    }
}

fn is_constraint(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(inner, _)
            if inner.code == ErrorCode::ConstraintViolation
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn challenge(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    #[test]
    fn replay_survives_reopen_and_binds_provider_event() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("approval-replay.sqlite3");
        {
            let mut store = DurableApprovalReplayStore::open(&path)?;
            store.consume(challenge(1), "slack-event-1", 200)?;
        }
        let mut reopened = DurableApprovalReplayStore::open(&path)?;
        assert_eq!(
            reopened.consume(challenge(1), "slack-event-2", 200),
            Err(ReplayStoreError::AlreadyConsumed)
        );
        assert_eq!(
            reopened.consume(challenge(2), "slack-event-1", 200),
            Err(ReplayStoreError::AlreadyConsumed)
        );
        Ok(())
    }

    #[test]
    fn pruning_requires_trusted_time_and_removes_only_expired_rows()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let mut store = DurableApprovalReplayStore::open(root.path().join("replay.sqlite3"))?;
        store.consume(challenge(1), "event-1", 150)?;
        store.consume(challenge(2), "event-2", 250)?;
        assert_eq!(store.prune_expired(-1), Err(ReplayStoreError::InvalidInput));
        assert_eq!(store.prune_expired(200)?, 1);
        store.consume(challenge(1), "event-1", 300)?;
        assert_eq!(
            store.consume(challenge(2), "event-3", 300),
            Err(ReplayStoreError::AlreadyConsumed)
        );
        Ok(())
    }

    #[test]
    fn unknown_schema_is_not_modified() -> Result<(), Box<dyn std::error::Error>> {
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
            DurableApprovalReplayStore::open(&path),
            Err(ReplayStoreError::Unavailable)
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
