//! Fail-closed binding from the ingress replay boundary to `AccordLock` state.

use std::fmt;

use accordlock_ingress::{ReplayGuard, ReplayGuardError, ReplayScope};
use accordlock_state::{
    IngressNonceConsumption, IngressReplayDecision, IngressReplayScope, IngressReplayState,
};

/// Adapts a durable `AccordLock` state implementation to the ingress replay guard.
///
/// Storage and validation errors are deliberately collapsed to unavailable.
/// In particular, an ambiguous database commit can never be converted into an
/// authentication success by this layer.
pub struct StateReplayGuard<S> {
    state: S,
}

impl<S> StateReplayGuard<S> {
    #[must_use]
    pub const fn new(state: S) -> Self {
        Self { state }
    }

    #[must_use]
    pub fn into_inner(self) -> S {
        self.state
    }
}

impl<S> fmt::Debug for StateReplayGuard<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StateReplayGuard")
            .field("state", &"<redacted>")
            .finish()
    }
}

impl<S: IngressReplayState> ReplayGuard for StateReplayGuard<S> {
    fn observe_time(&self, scope: &ReplayScope, now: i64) -> Result<(), ReplayGuardError> {
        let scope = durable_scope(scope)?;
        self.state
            .observe_ingress_time(&scope, now)
            .map_err(|_| ReplayGuardError::Unavailable)
    }

    fn consume(
        &self,
        scope: &ReplayScope,
        key_id: &str,
        nonce: uuid::Uuid,
        expires_at: i64,
        now: i64,
    ) -> Result<(), ReplayGuardError> {
        let request =
            IngressNonceConsumption::new(durable_scope(scope)?, key_id, nonce, expires_at, now)
                .map_err(|_| ReplayGuardError::Unavailable)?;
        let decision = self.state.consume_ingress_nonce(&request);
        map_consumption_decision(&decision)
    }
}

fn map_consumption_decision(
    decision: &Result<IngressReplayDecision, accordlock_state::StateError>,
) -> Result<(), ReplayGuardError> {
    match decision {
        Ok(IngressReplayDecision::Consumed) => Ok(()),
        Ok(IngressReplayDecision::AlreadyUsed) => Err(ReplayGuardError::AlreadyUsed),
        Err(_) => Err(ReplayGuardError::Unavailable),
    }
}

fn durable_scope(scope: &ReplayScope) -> Result<IngressReplayScope, ReplayGuardError> {
    IngressReplayScope::new(scope.as_str()).map_err(|_| ReplayGuardError::Unavailable)
}

#[cfg(test)]
mod tests {
    use accordlock_ingress::{ReplayGuard as _, ReplayGuardError, ReplayScope};
    use accordlock_state::{InMemoryStore, StateError};
    use uuid::Uuid;

    use super::{StateReplayGuard, map_consumption_decision};

    #[test]
    fn adapter_preserves_scope_and_exact_expiry_boundary() -> Result<(), Box<dyn std::error::Error>>
    {
        let guard = StateReplayGuard::new(InMemoryStore::new());
        let first = ReplayScope::new("accordlock://tenant-a/prod")?;
        let second = ReplayScope::new("accordlock://tenant-b/prod")?;
        let nonce = Uuid::from_u128(7);

        guard.observe_time(&first, 10)?;
        guard.consume(&first, "key-a", nonce, 20, 10)?;
        assert_eq!(
            guard.consume(&first, "key-a", nonce, 21, 19),
            Err(ReplayGuardError::AlreadyUsed)
        );
        guard.consume(&second, "key-a", nonce, 20, 10)?;
        guard.consume(&first, "key-a", nonce, 30, 20)?;
        Ok(())
    }

    #[test]
    fn invalid_direct_calls_fail_without_advancing_scope_time()
    -> Result<(), Box<dyn std::error::Error>> {
        let guard = StateReplayGuard::new(InMemoryStore::new());
        let scope = ReplayScope::new("accordlock://tenant-a/prod")?;

        assert_eq!(
            guard.consume(&scope, "key-a", Uuid::nil(), 30, 20),
            Err(ReplayGuardError::Unavailable)
        );
        assert_eq!(
            guard.consume(&scope, "key-a", Uuid::from_u128(8), 20, 20),
            Err(ReplayGuardError::Unavailable)
        );
        guard.observe_time(&scope, 10)?;
        Ok(())
    }

    #[test]
    fn ambiguous_commit_can_never_recover_as_authentication_success() {
        let ambiguous = Err(StateError::IngressReplayOutcomeUnknown);
        assert_eq!(
            map_consumption_decision(&ambiguous),
            Err(ReplayGuardError::Unavailable)
        );
    }
}
