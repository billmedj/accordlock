use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;

use accordlock_protocol::Digest32;
use thiserror::Error;
use uuid::Uuid;

use crate::{AuthorizationDecision, BindingError, ExecutionAuthorization, ExecutionRequest};

/// Atomic result returned exactly once for one registered authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationConsumption {
    pub authorization: ExecutionAuthorization,
    pub request_hash: Digest32,
    pub consumed_at: i64,
}

#[derive(Clone)]
struct AuthorizationRecord {
    authorization: ExecutionAuthorization,
    request_hash: Digest32,
    consumed_at: Option<i64>,
}

#[derive(Default)]
struct MemoryAuthorizationState {
    records: BTreeMap<Uuid, AuthorizationRecord>,
    high_water: Option<i64>,
}

/// Process-local reference implementation of atomic single-use consumption.
///
/// Consumed authorization identifiers remain tombstoned so a replay stays distinguishable from an
/// unknown authorization. This intentionally favors security behavior over unbounded
/// long-running use; production should implement the same transition in a
/// durable store with an explicit retention policy.
#[derive(Default)]
pub struct MemoryAuthorizationStore {
    state: Mutex<MemoryAuthorizationState>,
}

impl MemoryAuthorizationStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an authorization only after the entire authorization chain verifies.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationStoreError`] for an invalid chain, duplicate identifier,
    /// unusable validity window, or unavailable store.
    pub fn insert(
        &self,
        request: &ExecutionRequest,
        decision: &AuthorizationDecision,
        authorization: ExecutionAuthorization,
        now: i64,
    ) -> Result<(), AuthorizationStoreError> {
        authorization.verify_for(request, decision)?;
        let request_hash = request.digest().map_err(BindingError::from)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuthorizationStoreError::Unavailable)?;
        observe_time(&mut state, now)?;
        if now < authorization.issued_at {
            return Err(AuthorizationStoreError::NotYetValid);
        }
        if now >= authorization.expires_at {
            return Err(AuthorizationStoreError::Expired);
        }
        if state.records.contains_key(&authorization.authorization_id) {
            return Err(AuthorizationStoreError::DuplicateAuthorization);
        }
        state.records.insert(
            authorization.authorization_id,
            AuthorizationRecord {
                authorization,
                request_hash,
                consumed_at: None,
            },
        );
        Ok(())
    }

    /// Atomically consumes one authorization after re-checking the exact request and
    /// validity window. No failed verification mutates the record.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationStoreError`] for unknown, mismatched, premature,
    /// expired, or already-consumed authorizations, or when the store is unavailable.
    pub fn consume(
        &self,
        request: &ExecutionRequest,
        authorization_id: Uuid,
        now: i64,
    ) -> Result<AuthorizationConsumption, AuthorizationStoreError> {
        request.validate().map_err(BindingError::from)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuthorizationStoreError::Unavailable)?;
        let record = state
            .records
            .get_mut(&authorization_id)
            .ok_or(AuthorizationStoreError::UnknownAuthorization)?;

        record.authorization.verify_for_request(request)?;
        let request_hash = request.digest().map_err(BindingError::from)?;
        if record.request_hash != request_hash {
            return Err(AuthorizationStoreError::Binding(BindingError::Mismatch(
                "request_hash",
            )));
        }
        if record.consumed_at.is_some() {
            return Err(AuthorizationStoreError::Replay);
        }
        observe_time(&mut state, now)?;
        let record = state
            .records
            .get_mut(&authorization_id)
            .ok_or(AuthorizationStoreError::UnknownAuthorization)?;
        if now < record.authorization.not_before {
            return Err(AuthorizationStoreError::NotYetValid);
        }
        if now >= record.authorization.expires_at || now >= request.expires_at {
            return Err(AuthorizationStoreError::Expired);
        }

        record.consumed_at = Some(now);
        Ok(AuthorizationConsumption {
            authorization: record.authorization.clone(),
            request_hash: record.request_hash,
            consumed_at: now,
        })
    }

    /// Number of registered records, including replay tombstones.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationStoreError::Unavailable`] if the store lock is poisoned.
    pub fn len(&self) -> Result<usize, AuthorizationStoreError> {
        self.state
            .lock()
            .map(|state| state.records.len())
            .map_err(|_| AuthorizationStoreError::Unavailable)
    }

    /// Reports whether the store has no registered records or tombstones.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationStoreError::Unavailable`] if the store lock is poisoned.
    pub fn is_empty(&self) -> Result<bool, AuthorizationStoreError> {
        self.len().map(|length| length == 0)
    }
}

impl fmt::Debug for MemoryAuthorizationStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MemoryAuthorizationStore([REDACTED])")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum AuthorizationStoreError {
    #[error(transparent)]
    Binding(#[from] BindingError),
    #[error("authorization identifier is already registered")]
    DuplicateAuthorization,
    #[error("authorization is unknown")]
    UnknownAuthorization,
    #[error("authorization is not valid yet")]
    NotYetValid,
    #[error("authorization has expired")]
    Expired,
    #[error("authorization has already been consumed")]
    Replay,
    #[error("trusted clock moved backwards")]
    ClockRollback,
    #[error("single-use authorization store is unavailable")]
    Unavailable,
}

fn observe_time(
    state: &mut MemoryAuthorizationState,
    now: i64,
) -> Result<(), AuthorizationStoreError> {
    if now < 0 || state.high_water.is_some_and(|high_water| now < high_water) {
        return Err(AuthorizationStoreError::ClockRollback);
    }
    state.high_water = Some(now);
    Ok(())
}
