use uuid::Uuid;

use crate::{StateError, sealed};

/// Maximum exact UTF-8 audience size accepted as an ingress replay scope.
pub const MAX_INGRESS_REPLAY_SCOPE_BYTES: usize = 4_096;
/// Maximum bounded garbage-collection batch.
pub const MAX_INGRESS_REPLAY_GC_BATCH: u32 = 1_000;

/// Exact audience-bound replay scope.
///
/// Construction rejects aliases instead of trimming, case-folding, or Unicode
/// normalizing. `PostgreSQL` stores the same bytes under `COLLATE "C"`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IngressReplayScope(String);

impl IngressReplayScope {
    /// Validates and owns one exact replay-scope value.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::InvalidRecord`] for an empty, oversized,
    /// whitespace-padded, or control-bearing value.
    pub fn new(value: impl Into<String>) -> Result<Self, StateError> {
        let value = value.into();
        if !valid_security_text(&value, MAX_INGRESS_REPLAY_SCOPE_BYTES) {
            return Err(StateError::InvalidRecord(
                "ingress replay scope is not canonical".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact nonce-consumption request accepted by durable state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IngressNonceConsumption {
    scope: IngressReplayScope,
    key_id: String,
    nonce: Uuid,
    expires_unix_s: i64,
    observed_unix_s: i64,
}

impl IngressNonceConsumption {
    /// Builds a fully validated replay tuple.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::InvalidRecord`] for a malformed key identifier,
    /// nil nonce, negative observation, or non-future expiration.
    pub fn new(
        scope: IngressReplayScope,
        key_id: impl Into<String>,
        nonce: Uuid,
        expires_unix_s: i64,
        observed_unix_s: i64,
    ) -> Result<Self, StateError> {
        let key_id = key_id.into();
        if !valid_security_text(&key_id, accordlock_protocol::MAX_KEY_ID_BYTES)
            || nonce.is_nil()
            || observed_unix_s < 0
            || expires_unix_s <= observed_unix_s
        {
            return Err(StateError::InvalidRecord(
                "ingress nonce-consumption request is invalid".to_owned(),
            ));
        }
        Ok(Self {
            scope,
            key_id,
            nonce,
            expires_unix_s,
            observed_unix_s,
        })
    }

    #[must_use]
    pub const fn scope(&self) -> &IngressReplayScope {
        &self.scope
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub const fn nonce(&self) -> Uuid {
        self.nonce
    }

    #[must_use]
    pub const fn expires_unix_s(&self) -> i64 {
        self.expires_unix_s
    }

    #[must_use]
    pub const fn observed_unix_s(&self) -> i64 {
        self.observed_unix_s
    }
}

/// Definitive state decision after a successful commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngressReplayDecision {
    Consumed,
    AlreadyUsed,
}

/// Durable monotone-time and nonce-consumption ledger.
pub trait IngressReplayState: sealed::Sealed + Send + Sync {
    /// Persists one exact trusted-clock observation for the audience scope.
    ///
    /// # Errors
    ///
    /// Fails on rollback, invalid input, unavailable storage, or an ambiguous
    /// commit. A scope high-water row is permanent and has no deletion API.
    fn observe_ingress_time(
        &self,
        scope: &IngressReplayScope,
        observed_unix_s: i64,
    ) -> Result<(), StateError>;

    /// Atomically advances the high-water mark and consumes one nonce.
    ///
    /// # Errors
    ///
    /// Fails on rollback, invalid input, unavailable storage, or ambiguous
    /// commit. A commit ambiguity never recovers as success.
    fn consume_ingress_nonce(
        &self,
        request: &IngressNonceConsumption,
    ) -> Result<IngressReplayDecision, StateError>;

    /// Deletes at most `limit` nonce rows whose signed expiry is no later than
    /// the permanent durable high-water mark. Scope rows are never deleted.
    ///
    /// # Errors
    ///
    /// Fails for an invalid batch bound, missing/corrupt scope, or storage
    /// uncertainty.
    fn prune_expired_ingress_nonces(
        &self,
        scope: &IngressReplayScope,
        limit: u32,
    ) -> Result<u32, StateError>;
}

pub(crate) fn validate_observed_time(observed_unix_s: i64) -> Result<(), StateError> {
    if observed_unix_s < 0 {
        return Err(StateError::ClockBeforeUnixEpoch);
    }
    Ok(())
}

pub(crate) const fn valid_gc_limit(limit: u32) -> bool {
    limit > 0 && limit <= MAX_INGRESS_REPLAY_GC_BATCH
}

fn valid_security_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_scope_rejects_every_implicit_normalization() -> Result<(), Box<dyn std::error::Error>>
    {
        assert!(IngressReplayScope::new("").is_err());
        assert!(IngressReplayScope::new(" audience").is_err());
        assert!(IngressReplayScope::new("audience ").is_err());
        assert!(IngressReplayScope::new("a\nudiance").is_err());
        assert!(IngressReplayScope::new("a".repeat(MAX_INGRESS_REPLAY_SCOPE_BYTES + 1)).is_err());
        let composed = IngressReplayScope::new("accordlock://caf\u{e9}")?;
        let decomposed = IngressReplayScope::new("accordlock://cafe\u{301}")?;
        assert_ne!(composed, decomposed);
        Ok(())
    }

    #[test]
    fn nonce_request_rejects_nil_and_nonfuture_expiry() -> Result<(), Box<dyn std::error::Error>> {
        let scope = IngressReplayScope::new("accordlock://tenant-a/prod")?;
        assert!(IngressNonceConsumption::new(scope.clone(), "key-a", Uuid::nil(), 20, 10).is_err());
        assert!(IngressNonceConsumption::new(scope, "key-a", Uuid::from_u128(1), 10, 10).is_err());
        Ok(())
    }
}
