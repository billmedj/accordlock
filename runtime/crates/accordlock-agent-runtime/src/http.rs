use std::{
    collections::BTreeMap,
    fmt,
    future::Future,
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use tokio::net::TcpListener;
use tower_http::limit::RequestBodyLimitLayer;

use crate::network::{
    GovernedHttpsError, HTTPS_EXECUTE_PATH, HttpsEgress, HttpsExecutionRequest, SharedHttpsEgress,
    execute_governed as execute_governed_https,
};
use crate::{
    ApprovedSession, Ledger, LedgerError,
    filesystem::{
        FILESYSTEM_EXECUTE_PATH, FilesystemExecutionRequest, GovernedFilesystemError,
        execute_governed,
    },
    model::DESKTOP_PROTOCOL_SCHEMA_VERSION,
    terminal::{
        GovernedTerminalError, TERMINAL_EXECUTE_PATH, TerminalExecutionRequest, TerminalProgram,
        execute_governed as execute_governed_terminal,
    },
};
#[cfg(any(test, feature = "caller-reported-governance"))]
use crate::{
    ledger::{AuthorizationResult, ObservationResult},
    model::{TOOL_EXECUTION_SCHEMA_VERSION, ToolCallProposal, ToolExecutionObservation},
};

pub const AUTHORIZE_PATH: &str = "/api/v2/authorization/tool-calls/authorize-and-consume";
pub const OBSERVE_PATH: &str = "/api/v2/execution/tool-observations/record";
pub const HEALTH_PATH: &str = "/api/v2/health";
pub const MAX_REQUEST_BODY_BYTES: usize = 800 * 1024;
const MIN_BEARER_BYTES: usize = 32;
const MAX_BEARER_BYTES: usize = 512;
const DEFAULT_GRANT_LIFETIME_SECONDS: i64 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuntimeHttpSurface {
    Core,
    AccordLockDesktop,
}

/// Runtime settings. Only a token commitment is retained in memory.
#[derive(Clone, PartialEq, Eq)]
pub struct RuntimeConfig {
    bearer_hash: [u8; 32],
    grant_lifetime_seconds: i64,
    terminal_programs: Arc<BTreeMap<String, TerminalProgram>>,
    http_surface: RuntimeHttpSurface,
}

impl fmt::Debug for RuntimeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeConfig")
            .field("bearer", &"[REDACTED SHA-256 commitment]")
            .field("grant_lifetime_seconds", &self.grant_lifetime_seconds)
            .field(
                "terminal_program_aliases",
                &self.terminal_programs.keys().collect::<Vec<_>>(),
            )
            .field("http_surface", &self.http_surface)
            .finish_non_exhaustive()
    }
}

impl RuntimeConfig {
    /// Builds settings compatible with Goose's strict runtime-token profile.
    ///
    /// # Errors
    ///
    /// Rejects short, excessive, non-ASCII, or ambiguous bearer values.
    pub fn new(bearer: &str) -> Result<Self, RuntimeConfigError> {
        validate_bearer(bearer.as_bytes())?;
        Ok(Self {
            bearer_hash: Sha256::digest(bearer.as_bytes()).into(),
            grant_lifetime_seconds: DEFAULT_GRANT_LIFETIME_SECONDS,
            terminal_programs: Arc::new(BTreeMap::new()),
            http_surface: RuntimeHttpSurface::Core,
        })
    }

    /// Builds the production Desktop profile. Goose receives runtime-owned
    /// atomic execution routes only. Caller-reported authorization and
    /// observation stay absent; governed HTTPS is mounted separately only
    /// when the trusted launcher supplies a valid egress policy.
    ///
    /// # Errors
    ///
    /// Rejects short, excessive, non-ASCII, or ambiguous bearer values.
    pub fn for_accordlock_desktop(bearer: &str) -> Result<Self, RuntimeConfigError> {
        let mut config = Self::new(bearer)?;
        config.http_surface = RuntimeHttpSurface::AccordLockDesktop;
        Ok(config)
    }

    /// Selects a shorter authorization window, never beyond the protocol maximum.
    ///
    /// # Errors
    ///
    /// Rejects zero, negative, or overly long lifetimes.
    pub fn with_grant_lifetime_seconds(mut self, seconds: i64) -> Result<Self, RuntimeConfigError> {
        if !(1..=accordlock_agent_protocol::MAX_AUTHORIZATION_LIFETIME_SECONDS).contains(&seconds) {
            return Err(RuntimeConfigError::InvalidGrantLifetime);
        }
        self.grant_lifetime_seconds = seconds;
        Ok(self)
    }

    /// Installs one trusted alias-to-executable terminal binding.
    ///
    /// # Errors
    ///
    /// Rejects shell interpreters, non-files, noncanonical aliases, or a
    /// conflicting attempt to change an existing alias.
    pub fn with_terminal_program(
        mut self,
        alias: impl Into<String>,
        executable: &Path,
    ) -> Result<Self, RuntimeConfigError> {
        let program = TerminalProgram::new(alias, executable)
            .map_err(|_| RuntimeConfigError::InvalidTerminalProgram)?;
        let programs = Arc::make_mut(&mut self.terminal_programs);
        if let Some(existing) = programs.get(program.alias()) {
            if existing != &program {
                return Err(RuntimeConfigError::ConflictingTerminalProgram);
            }
        } else {
            programs.insert(program.alias().to_owned(), program);
        }
        Ok(self)
    }

    /// Installs one digest-pinned trusted terminal binding.
    ///
    /// # Errors
    ///
    /// Rejects malformed commitments and executables that no longer match the
    /// digest selected by the Desktop main process.
    pub fn with_terminal_program_digest(
        mut self,
        alias: impl Into<String>,
        executable: &Path,
        expected_digest: &str,
    ) -> Result<Self, RuntimeConfigError> {
        let program = TerminalProgram::new_with_expected_digest(alias, executable, expected_digest)
            .map_err(|_| RuntimeConfigError::InvalidTerminalProgram)?;
        let programs = Arc::make_mut(&mut self.terminal_programs);
        if let Some(existing) = programs.get(program.alias()) {
            if existing != &program {
                return Err(RuntimeConfigError::ConflictingTerminalProgram);
            }
        } else {
            programs.insert(program.alias().to_owned(), program);
        }
        Ok(self)
    }
}

/// Embeddable trusted runtime used by `AccordLock` Desktop.
#[derive(Clone, Debug)]
pub struct Runtime {
    state: RuntimeState,
}

impl Runtime {
    /// Opens the `SQLite` ledger and prepares an authenticated runtime.
    ///
    /// # Errors
    ///
    /// Fails closed on configuration or persistence errors.
    pub fn open(database_path: &Path, bearer: &str) -> Result<Self, RuntimeInitializationError> {
        let config = RuntimeConfig::new(bearer)?;
        let ledger = Ledger::open(database_path)?;
        Ok(Self::from_ledger(ledger, config))
    }

    #[must_use]
    pub fn from_ledger(ledger: Ledger, config: RuntimeConfig) -> Self {
        Self {
            state: RuntimeState {
                ledger,
                config: Arc::new(config),
                https_egress: None,
            },
        }
    }

    /// Installs a real trusted HTTPS adapter. Without this explicit step the
    /// authenticated network route returns `NETWORK_EGRESS_NOT_CONFIGURED`.
    ///
    /// # Errors
    ///
    /// Rejects an adapter whose policy is outside the strict bounded profile.
    pub fn with_https_egress(
        mut self,
        egress: Arc<dyn HttpsEgress>,
    ) -> Result<Self, crate::network::HttpsPolicyError> {
        egress.policy().validate()?;
        self.state.https_egress = Some(egress);
        Ok(self)
    }

    /// Trusted bootstrap called by Desktop after the user approves a Task
    /// Contract. There is deliberately no request-derived auto-registration.
    ///
    /// # Errors
    ///
    /// Invalid, duplicate, or unavailable durable bindings are rejected.
    pub fn approve_session(&self, approval: &ApprovedSession) -> Result<(), LedgerError> {
        self.state.ledger.approve_session(approval)
    }

    /// Trusted idempotent registration used only by the inherited Desktop
    /// control channel. This capability is deliberately absent from `router`.
    ///
    /// # Errors
    ///
    /// Invalid, conflicting, or unavailable durable bindings are rejected.
    pub fn register_session(
        &self,
        approval: &ApprovedSession,
    ) -> Result<crate::ledger::ApprovalRegistration, LedgerError> {
        self.state.ledger.register_session(approval)
    }

    /// Trusted idempotent single-use approval registration available only through
    /// the inherited Desktop control channel.
    ///
    /// # Errors
    ///
    /// Invalid, unknown, conflicting, or unavailable bindings are rejected.
    pub fn register_action_approval(
        &self,
        approval: &crate::policy::ActionApproval,
    ) -> Result<crate::ledger::ActionApprovalRegistration, LedgerError> {
        self.state.ledger.register_action_approval(approval)
    }

    /// Trusted idempotent revocation used only by the inherited Desktop
    /// control channel. This capability is deliberately absent from `router`.
    ///
    /// # Errors
    ///
    /// Invalid, unknown, conflicting, or unavailable bindings are rejected.
    pub fn revoke_session(
        &self,
        revocation: &crate::model::SessionRevocation,
    ) -> Result<crate::ledger::RevocationRegistration, LedgerError> {
        self.state.ledger.revoke_session(revocation)
    }

    /// Trusted revocation with an explicit control-plane timestamp.
    ///
    /// # Errors
    ///
    /// Invalid time or any mismatched durable binding is rejected.
    pub fn revoke_session_at(
        &self,
        revocation: &crate::model::SessionRevocation,
        revoked_at: i64,
    ) -> Result<crate::ledger::RevocationRegistration, LedgerError> {
        self.state.ledger.revoke_session_at(revocation, revoked_at)
    }

    /// Resolves and verifies one deleted-file recovery point for the private
    /// Desktop control channel. This operation is deliberately absent from
    /// the HTTP router.
    ///
    /// # Errors
    ///
    /// Rejects unknown, malformed, stale, unsafe, or unverifiable recovery state.
    pub fn prepare_file_restore(
        &self,
        request: &crate::recovery::FileRestorePrepareRequest,
        now: i64,
    ) -> Result<crate::recovery::FileRestorePrepareOutcome, crate::recovery::FileRestoreError> {
        crate::recovery::prepare_file_restore(&self.state.ledger, request, now)
    }

    /// Commits one exact prepared deleted-file restoration for the private
    /// Desktop control channel. This operation is deliberately absent from
    /// the HTTP router.
    ///
    /// # Errors
    ///
    /// Rechecks every filesystem and challenge binding and fails closed on drift.
    pub fn commit_file_restore(
        &self,
        request: &crate::recovery::FileRestoreCommitRequest,
        now: i64,
    ) -> Result<crate::recovery::FileRestoreCommitOutcome, crate::recovery::FileRestoreError> {
        crate::recovery::commit_file_restore(&self.state.ledger, request, now)
    }

    #[must_use]
    pub fn ledger(&self) -> &Ledger {
        &self.state.ledger
    }

    /// Builds the configured bounded HTTP surface.
    ///
    /// The core-library surface keeps its fail-closed HTTPS route for protocol
    /// compatibility. Desktop mounts that route only after a trusted HTTPS
    /// adapter with a valid exact-domain policy has been installed.
    pub fn router(&self) -> Router {
        let router = Router::new()
            .route(FILESYSTEM_EXECUTE_PATH, post(execute_filesystem))
            .route(TERMINAL_EXECUTE_PATH, post(execute_terminal))
            .route(HEALTH_PATH, get(health));
        let router = if self.state.config.http_surface == RuntimeHttpSurface::Core
            || self.state.https_egress.is_some()
        {
            router.route(HTTPS_EXECUTE_PATH, post(execute_https))
        } else {
            router
        };
        #[cfg(any(test, feature = "caller-reported-governance"))]
        let router = if self.state.config.http_surface == RuntimeHttpSurface::Core {
            router
                .route(AUTHORIZE_PATH, post(authorize))
                .route(OBSERVE_PATH, post(observe))
        } else {
            router
        };
        router
            .route_layer(middleware::from_fn_with_state(
                self.state.clone(),
                authenticate,
            ))
            .fallback(not_found)
            .method_not_allowed_fallback(method_not_allowed)
            .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY_BYTES))
            .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
            .layer(middleware::from_fn(harden_response))
            .with_state(self.state.clone())
    }

    /// Serves a pre-bound literal loopback listener until shutdown.
    ///
    /// # Errors
    ///
    /// Refuses non-loopback listeners and propagates server failures.
    pub async fn serve_until<F>(
        &self,
        listener: TcpListener,
        shutdown: F,
    ) -> Result<(), RuntimeServeError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let address = listener
            .local_addr()
            .map_err(|_| RuntimeServeError::Listener)?;
        if !address.ip().is_loopback() {
            return Err(RuntimeServeError::NonLoopback);
        }
        axum::serve(listener, self.router())
            .with_graceful_shutdown(shutdown)
            .await
            .map_err(|_| RuntimeServeError::Serve)
    }

    /// Binds a literal loopback address and serves until shutdown.
    ///
    /// # Errors
    ///
    /// Refuses wildcard/LAN addresses before any socket is opened.
    pub async fn bind_and_serve_until<F>(
        &self,
        address: SocketAddr,
        shutdown: F,
    ) -> Result<(), RuntimeServeError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        if !address.ip().is_loopback() {
            return Err(RuntimeServeError::NonLoopback);
        }
        let listener = TcpListener::bind(address)
            .await
            .map_err(|_| RuntimeServeError::Listener)?;
        self.serve_until(listener, shutdown).await
    }
}

async fn execute_filesystem(
    State(state): State<RuntimeState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !exact_json_content_type(&headers) {
        return error_response(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let Ok(request) = serde_json::from_slice::<FilesystemExecutionRequest>(&body) else {
        return error_response(StatusCode::BAD_REQUEST);
    };
    let ledger = state.ledger.clone();
    let lifetime = state.config.grant_lifetime_seconds;
    let Ok(now) = unix_time() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE);
    };
    let result =
        tokio::task::spawn_blocking(move || execute_governed(&ledger, &request, now, lifetime))
            .await;
    match result {
        Ok(Ok(response)) => Json(response).into_response(),
        Ok(Err(GovernedFilesystemError::Input)) => error_response(StatusCode::BAD_REQUEST),
        Ok(Err(GovernedFilesystemError::Ledger(LedgerError::WireValidation))) => {
            error_response(StatusCode::BAD_REQUEST)
        }
        Ok(Err(
            GovernedFilesystemError::Ledger(_) | GovernedFilesystemError::ExecutionStateUnknown,
        ))
        | Err(_) => error_response(StatusCode::SERVICE_UNAVAILABLE),
    }
}

async fn execute_terminal(
    State(state): State<RuntimeState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !exact_json_content_type(&headers) {
        return error_response(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let Ok(request) = serde_json::from_slice::<TerminalExecutionRequest>(&body) else {
        return error_response(StatusCode::BAD_REQUEST);
    };
    let ledger = state.ledger.clone();
    let programs = Arc::clone(&state.config.terminal_programs);
    let lifetime = state.config.grant_lifetime_seconds;
    let Ok(now) = unix_time() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE);
    };
    let result = tokio::task::spawn_blocking(move || {
        execute_governed_terminal(&ledger, &request, &programs, now, lifetime)
    })
    .await;
    match result {
        Ok(Ok(response)) => Json(response).into_response(),
        Ok(Err(GovernedTerminalError::Input)) => error_response(StatusCode::BAD_REQUEST),
        Ok(Err(GovernedTerminalError::Ledger(LedgerError::WireValidation))) => {
            error_response(StatusCode::BAD_REQUEST)
        }
        Ok(Err(
            GovernedTerminalError::Ledger(_) | GovernedTerminalError::ExecutionStateUnknown,
        ))
        | Err(_) => error_response(StatusCode::SERVICE_UNAVAILABLE),
    }
}

async fn execute_https(
    State(state): State<RuntimeState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !exact_json_content_type(&headers) {
        return error_response(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let Ok(request) = serde_json::from_slice::<HttpsExecutionRequest>(&body) else {
        return error_response(StatusCode::BAD_REQUEST);
    };
    let ledger = state.ledger.clone();
    let egress = state.https_egress.clone();
    let lifetime = state.config.grant_lifetime_seconds;
    let Ok(now) = unix_time() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE);
    };
    let result = tokio::task::spawn_blocking(move || {
        execute_governed_https(&ledger, &request, egress.as_deref(), now, lifetime)
    })
    .await;
    match result {
        Ok(Ok(response)) => Json(response).into_response(),
        Ok(Err(GovernedHttpsError::Input)) => error_response(StatusCode::BAD_REQUEST),
        Ok(Err(GovernedHttpsError::Ledger(LedgerError::WireValidation))) => {
            error_response(StatusCode::BAD_REQUEST)
        }
        Ok(Err(GovernedHttpsError::Ledger(_) | GovernedHttpsError::ExecutionStateUnknown))
        | Err(_) => error_response(StatusCode::SERVICE_UNAVAILABLE),
    }
}

#[derive(Clone, Debug)]
struct RuntimeState {
    ledger: Ledger,
    config: Arc<RuntimeConfig>,
    https_egress: Option<SharedHttpsEgress>,
}

#[cfg(any(test, feature = "caller-reported-governance"))]
async fn authorize(State(state): State<RuntimeState>, headers: HeaderMap, body: Bytes) -> Response {
    if !exact_json_content_type(&headers) {
        return error_response(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let proposal = match serde_json::from_slice::<ToolCallProposal>(&body) {
        Ok(proposal) if proposal.validate().is_ok() => proposal,
        Ok(_) | Err(_) => return error_response(StatusCode::BAD_REQUEST),
    };
    let Ok(proposal_digest) = proposal.digest() else {
        return error_response(StatusCode::BAD_REQUEST);
    };
    let ledger = state.ledger.clone();
    let lifetime = state.config.grant_lifetime_seconds;
    let Ok(now) = unix_time() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE);
    };
    let result = tokio::task::spawn_blocking(move || {
        ledger.authorize_and_consume(&proposal, None, None, now, lifetime)
    })
    .await;
    match result {
        Ok(Ok(AuthorizationResult::Allowed(grant))) => Json(AuthorizationResponse {
            schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
            decision: RuntimeDecision::Allow,
            proposal_digest: grant.proposal_digest,
            request_hash: Some(grant.request_hash.to_string()),
            authorization_id: Some(grant.authorization_id.to_string()),
            reason_code: grant.reason_code,
            issued_at: Some(grant.issued_at),
            not_before: Some(grant.not_before),
            expires_at: Some(grant.expires_at),
        })
        .into_response(),
        Ok(Ok(AuthorizationResult::Denied(reason_code))) => Json(AuthorizationResponse {
            schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
            decision: RuntimeDecision::Deny,
            proposal_digest,
            request_hash: None,
            authorization_id: None,
            reason_code,
            issued_at: None,
            not_before: None,
            expires_at: None,
        })
        .into_response(),
        Ok(Err(LedgerError::WireValidation)) => error_response(StatusCode::BAD_REQUEST),
        Ok(Err(_)) | Err(_) => error_response(StatusCode::SERVICE_UNAVAILABLE),
    }
}

#[cfg(any(test, feature = "caller-reported-governance"))]
async fn observe(State(state): State<RuntimeState>, headers: HeaderMap, body: Bytes) -> Response {
    if !exact_json_content_type(&headers) {
        return error_response(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let observation = match serde_json::from_slice::<ToolExecutionObservation>(&body) {
        Ok(observation) if observation.validate().is_ok() => observation,
        Ok(_) | Err(_) => return error_response(StatusCode::BAD_REQUEST),
    };
    let ledger = state.ledger.clone();
    let Ok(now) = unix_time() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE);
    };
    let result = tokio::task::spawn_blocking(move || ledger.observe(&observation, now)).await;
    match result {
        Ok(Ok(ObservationResult {
            authorization_id,
            observation_digest,
            record_id,
            record_hash,
        })) => Json(ExecutionRecordResponse {
            schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
            recorded: true,
            authorization_id: authorization_id.to_string(),
            observation_digest,
            record_id: record_id.to_string(),
            record_hash,
        })
        .into_response(),
        Ok(Err(LedgerError::WireValidation)) => error_response(StatusCode::BAD_REQUEST),
        Ok(Err(LedgerError::UnknownAuthorization)) => error_response(StatusCode::NOT_FOUND),
        Ok(Err(
            LedgerError::ObservationBindingMismatch
            | LedgerError::ConflictingObservation
            | LedgerError::ObservationWindowExpired,
        )) => error_response(StatusCode::CONFLICT),
        Ok(Err(_)) | Err(_) => error_response(StatusCode::SERVICE_UNAVAILABLE),
    }
}

async fn health() -> Response {
    Json(HealthResponse {
        schema_version: DESKTOP_PROTOCOL_SCHEMA_VERSION,
        status: "READY",
    })
    .into_response()
}

async fn authenticate(State(state): State<RuntimeState>, request: Request, next: Next) -> Response {
    if !valid_authorization(request.headers(), state.config.bearer_hash) {
        let mut response = error_response(StatusCode::UNAUTHORIZED);
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"accordlock-runtime\""),
        );
        return response;
    }
    next.run(request).await
}

fn valid_authorization(headers: &HeaderMap, expected_hash: [u8; 32]) -> bool {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    let bytes = value.as_bytes();
    let Some(bearer) = bytes.strip_prefix(b"Bearer ") else {
        return false;
    };
    if validate_bearer(bearer).is_err() {
        return false;
    }
    let supplied_hash: [u8; 32] = Sha256::digest(bearer).into();
    bool::from(expected_hash.ct_eq(&supplied_hash))
}

fn validate_bearer(value: &[u8]) -> Result<(), RuntimeConfigError> {
    if value.len() < MIN_BEARER_BYTES
        || value.len() > MAX_BEARER_BYTES
        || !value
            .iter()
            .copied()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(RuntimeConfigError::InvalidBearer);
    }
    Ok(())
}

fn exact_json_content_type(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return false;
    };
    values.next().is_none() && value.as_bytes().eq_ignore_ascii_case(b"application/json")
}

async fn harden_response(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

async fn not_found() -> Response {
    error_response(StatusCode::NOT_FOUND)
}

async fn method_not_allowed() -> Response {
    error_response(StatusCode::METHOD_NOT_ALLOWED)
}

fn error_response(status: StatusCode) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: "REQUEST_REJECTED",
        }),
    )
        .into_response()
}

fn unix_time() -> Result<i64, ()> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ())?
        .as_secs();
    i64::try_from(seconds).map_err(|_| ())
}

#[cfg(any(test, feature = "caller-reported-governance"))]
#[derive(Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum RuntimeDecision {
    Allow,
    Deny,
}

#[cfg(any(test, feature = "caller-reported-governance"))]
#[derive(Serialize)]
struct AuthorizationResponse {
    schema_version: u16,
    decision: RuntimeDecision,
    proposal_digest: String,
    request_hash: Option<String>,
    authorization_id: Option<String>,
    reason_code: &'static str,
    issued_at: Option<i64>,
    not_before: Option<i64>,
    expires_at: Option<i64>,
}

#[cfg(any(test, feature = "caller-reported-governance"))]
#[derive(Serialize)]
struct ExecutionRecordResponse {
    schema_version: u16,
    recorded: bool,
    authorization_id: String,
    observation_digest: String,
    record_id: String,
    record_hash: String,
}

#[derive(Serialize)]
struct HealthResponse {
    schema_version: u16,
    status: &'static str,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RuntimeConfigError {
    #[error("runtime bearer is outside the strict token profile")]
    InvalidBearer,
    #[error("runtime grant lifetime is outside the authorization profile")]
    InvalidGrantLifetime,
    #[error("runtime terminal program is outside the strict executable profile")]
    InvalidTerminalProgram,
    #[error("runtime terminal alias is already bound to another executable")]
    ConflictingTerminalProgram,
}

#[derive(Debug, Error)]
pub enum RuntimeInitializationError {
    #[error(transparent)]
    Configuration(#[from] RuntimeConfigError),
    #[error(transparent)]
    Ledger(#[from] LedgerError),
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum RuntimeServeError {
    #[error("runtime may bind only to a literal loopback address")]
    NonLoopback,
    #[error("runtime loopback listener failed")]
    Listener,
    #[error("runtime HTTP server failed")]
    Serve,
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Arc};

    use accordlock_agent_protocol::Digest32;
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use serde_json::{Value, json};
    use tempfile::TempDir;
    use tower::ServiceExt as _;
    use uuid::Uuid;

    use super::*;
    use crate::{
        ActionApproval, ActionApprovalRequest, ApprovalDecision, Capability, HttpsEgress,
        HttpsEgressError, HttpsEgressPolicy, HttpsEgressRequest, HttpsEgressResponse, HttpsHeader,
        HttpsMethod, PreauthorizedCapability, SessionRevocation, TaskPolicy,
        canonical::goose_digest,
    };

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn plan_checkpoint(
        session_id: &str,
        run_id: &str,
        tool_call_id: &str,
        model_tool_name: &str,
        arguments_sha256: &str,
        recorded_at: i64,
    ) -> Value {
        let material = json!({
            "text": ["Execute the requested test action."],
            "tool_requests": [{
                "id": tool_call_id,
                "name": model_tool_name,
                "arguments_sha256": arguments_sha256
            }]
        });
        json!({
            "schema_version": crate::AGENT_PLAN_CHECKPOINT_SCHEMA_VERSION,
            "session_id": session_id,
            "run_id": run_id,
            "tool_call_id": tool_call_id,
            "material_sha256": goose_digest(&material).unwrap_or_default(),
            "material": material,
            "recorded_at": recorded_at
        })
    }

    struct Fixture {
        _root: TempDir,
        workspace: PathBuf,
        runtime: Runtime,
        now: i64,
        task_id: Uuid,
    }

    impl Fixture {
        fn new(current: bool) -> Result<Self, Box<dyn std::error::Error>> {
            let root = tempfile::tempdir()?;
            let workspace = root.path().join("workspace");
            std::fs::create_dir(&workspace)?;
            let database = root.path().join("runtime.sqlite3");
            let runtime = Runtime::open(&database, TOKEN)?;
            let now = unix_time().map_err(|()| "clock unavailable")?;
            let (approved_at, expires_at) = if current {
                (now.saturating_sub(10), now.saturating_add(120))
            } else {
                (now.saturating_sub(120), now.saturating_sub(60))
            };
            let task_id = Uuid::new_v4();
            let approval = ApprovedSession::new_with_task_objective(
                task_id,
                "session-1",
                "session-1",
                &workspace,
                7,
                "task-contract",
                TaskPolicy::new(
                    Digest32::sha256(b"task-contract"),
                    [PreauthorizedCapability::new("developer", "read")],
                    [".accordlock".to_owned()],
                )?,
                [Capability::new("developer", "read")],
                approved_at,
                expires_at,
            )?;
            runtime.approve_session(&approval)?;
            Ok(Self {
                _root: root,
                workspace: std::fs::canonicalize(workspace)?,
                runtime,
                now,
                task_id,
            })
        }

        fn proposal(&self, tool_call_id: &str) -> Value {
            let arguments = json!({"path": "sample.txt"});
            let arguments_sha256 = goose_digest(&arguments).unwrap_or_default();
            json!({
                "schema_version": TOOL_EXECUTION_SCHEMA_VERSION,
                "session_id": "session-1",
                "run_id": "session-1",
                "tool_call_id": tool_call_id,
                "workspace_root": self.workspace.to_string_lossy(),
                "extension_id": "developer",
                "tool_name": "read",
                "arguments": arguments,
                "arguments_sha256": arguments_sha256,
                "agent_plan_checkpoint": plan_checkpoint(
                    "session-1",
                    "session-1",
                    tool_call_id,
                    "developer__read",
                    &arguments_sha256,
                    self.now.saturating_sub(1),
                )
            })
        }
    }

    fn request(
        path: &str,
        token: Option<&str>,
        body: &Value,
    ) -> Result<Request<Body>, axum::http::Error> {
        let mut builder = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        builder.body(Body::from(body.to_string()))
    }

    async fn json_body(response: Response) -> Value {
        match to_bytes(response.into_body(), 1024 * 1024).await {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            Err(_) => Value::Null,
        }
    }

    #[tokio::test]
    async fn bearer_is_mandatory_and_compared_strictly() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new(true)?;
        let missing = fixture
            .runtime
            .router()
            .oneshot(request(AUTHORIZE_PATH, None, &fixture.proposal("call-1"))?)
            .await?;
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
        let wrong = fixture
            .runtime
            .router()
            .oneshot(request(
                AUTHORIZE_PATH,
                Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                &fixture.proposal("call-1"),
            )?)
            .await?;
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn health_contract_is_exact_and_authenticated() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = Fixture::new(true)?;
        let unauthenticated = fixture
            .runtime
            .router()
            .oneshot(Request::builder().uri(HEALTH_PATH).body(Body::empty())?)
            .await?;
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        let authenticated = fixture
            .runtime
            .router()
            .oneshot(
                Request::builder()
                    .uri(HEALTH_PATH)
                    .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(authenticated.status(), StatusCode::OK);
        let bytes = to_bytes(authenticated.into_body(), 4096).await?;
        assert_eq!(bytes.as_ref(), br#"{"schema_version":2,"status":"READY"}"#);
        Ok(())
    }

    #[tokio::test]
    async fn desktop_surface_rejects_caller_reported_receipts_and_unconfigured_network_ingress()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new(true)?;
        let runtime = Runtime::from_ledger(
            fixture.runtime.ledger().clone(),
            RuntimeConfig::for_accordlock_desktop(TOKEN)?,
        );
        let forged_authorization_id = Uuid::new_v4();
        let forged_observation = json!({
            "schema_version": TOOL_EXECUTION_SCHEMA_VERSION,
            "authorization_id": forged_authorization_id.to_string(),
            "proposal_digest": Digest32::sha256(b"forged-proposal").to_string(),
            "request_hash": Digest32::sha256(b"forged-request").to_string(),
            "outcome": "SUCCEEDED",
            "result_digest": Digest32::sha256(b"forged-result").to_string()
        });

        for (path, body) in [
            (AUTHORIZE_PATH, fixture.proposal("caller-reported")),
            (OBSERVE_PATH, forged_observation),
            (HTTPS_EXECUTE_PATH, json!({})),
            ("/api/v2/recovery/filesystem/prepare", json!({})),
            ("/api/v2/recovery/filesystem/commit", json!({})),
        ] {
            let response = runtime
                .router()
                .oneshot(request(path, Some(TOKEN), &body)?)
                .await?;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }
        assert!(matches!(
            runtime.ledger().attempt(forged_authorization_id),
            Err(LedgerError::UnknownAuthorization)
        ));

        for path in [FILESYSTEM_EXECUTE_PATH, TERMINAL_EXECUTE_PATH] {
            let response = runtime
                .router()
                .oneshot(request(path, Some(TOKEN), &json!({}))?)
                .await?;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn malformed_or_digest_mismatched_payload_is_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new(true)?;
        let mut unknown_field = fixture.proposal("call-malformed");
        unknown_field["unexpected"] = json!(true);
        let response = fixture
            .runtime
            .router()
            .oneshot(request(AUTHORIZE_PATH, Some(TOKEN), &unknown_field)?)
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let mut mismatched = fixture.proposal("call-digest");
        mismatched["arguments_sha256"] = json!(Digest32::sha256(b"different").to_string());
        let response = fixture
            .runtime
            .router()
            .oneshot(request(AUTHORIZE_PATH, Some(TOKEN), &mismatched)?)
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn consumed_tool_call_cannot_be_replayed() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new(true)?;
        let first = fixture
            .runtime
            .router()
            .oneshot(request(
                AUTHORIZE_PATH,
                Some(TOKEN),
                &fixture.proposal("call-replay"),
            )?)
            .await?;
        assert_eq!(first.status(), StatusCode::OK);
        let first_body = json_body(first).await;
        assert_eq!(TOOL_EXECUTION_SCHEMA_VERSION, 3);
        assert_eq!(first_body["schema_version"], TOOL_EXECUTION_SCHEMA_VERSION);
        assert_eq!(first_body["decision"], "ALLOW");

        let second = fixture
            .runtime
            .router()
            .oneshot(request(
                AUTHORIZE_PATH,
                Some(TOKEN),
                &fixture.proposal("call-replay"),
            )?)
            .await?;
        assert_eq!(second.status(), StatusCode::OK);
        let second_body = json_body(second).await;
        assert_eq!(second_body["decision"], "DENY");
        assert_eq!(second_body["reason_code"], "TOOL_CALL_REPLAY");
        Ok(())
    }

    #[tokio::test]
    async fn expired_approval_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new(false)?;
        let response = fixture
            .runtime
            .router()
            .oneshot(request(
                AUTHORIZE_PATH,
                Some(TOKEN),
                &fixture.proposal("call-expired"),
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["decision"], "DENY");
        assert_eq!(body["reason_code"], "SESSION_NOT_CURRENT");
        Ok(())
    }

    #[tokio::test]
    async fn unknown_session_and_unknown_authorization_never_gain_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new(true)?;
        let mut proposal = fixture.proposal("call-unknown");
        proposal["session_id"] = json!("not-approved");
        proposal["run_id"] = json!("not-approved");
        proposal["agent_plan_checkpoint"]["session_id"] = json!("not-approved");
        proposal["agent_plan_checkpoint"]["run_id"] = json!("not-approved");
        proposal["arguments_sha256"] =
            goose_digest(&proposal["arguments"]).map_or(Value::Null, Value::String);
        let response = fixture
            .runtime
            .router()
            .oneshot(request(AUTHORIZE_PATH, Some(TOKEN), &proposal)?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_body(response).await["reason_code"], "UNKNOWN_SESSION");

        let unknown_observation = json!({
            "schema_version": TOOL_EXECUTION_SCHEMA_VERSION,
            "authorization_id": Uuid::new_v4().to_string(),
            "proposal_digest": Digest32::sha256(b"proposal").to_string(),
            "request_hash": Digest32::sha256(b"request").to_string(),
            "outcome": "TRANSPORT_ERROR",
            "result_digest": null
        });
        let response = fixture
            .runtime
            .router()
            .oneshot(request(OBSERVE_PATH, Some(TOKEN), &unknown_observation)?)
            .await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn planner_http_surface_cannot_install_or_revoke_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new(true)?;
        let malicious_session = ApprovedSession::new(
            Uuid::new_v4(),
            "planner-created",
            "planner-created",
            &fixture.workspace,
            7,
            TaskPolicy::new(
                Digest32::sha256(b"planner-contract"),
                [PreauthorizedCapability::new("developer", "read")],
                [".accordlock".to_owned()],
            )?,
            [Capability::new("developer", "read")],
            fixture.now.saturating_sub(1),
            fixture.now.saturating_add(120),
        )?;
        let attempted_registration = fixture
            .runtime
            .router()
            .oneshot(request(
                "/api/v1/control/approved-sessions",
                Some(TOKEN),
                &serde_json::to_value(malicious_session)?,
            )?)
            .await?;
        assert_eq!(attempted_registration.status(), StatusCode::NOT_FOUND);

        let revocation = SessionRevocation::new(fixture.task_id, "session-1", "session-1");
        let attempted_revocation = fixture
            .runtime
            .router()
            .oneshot(request(
                "/api/v1/control/revoked-sessions",
                Some(TOKEN),
                &serde_json::to_value(revocation)?,
            )?)
            .await?;
        assert_eq!(attempted_revocation.status(), StatusCode::NOT_FOUND);

        let mut proposal = fixture.proposal("planner-escalation");
        proposal["session_id"] = json!("planner-created");
        proposal["run_id"] = json!("planner-created");
        proposal["agent_plan_checkpoint"]["session_id"] = json!("planner-created");
        proposal["agent_plan_checkpoint"]["run_id"] = json!("planner-created");
        let authorization = fixture
            .runtime
            .router()
            .oneshot(request(AUTHORIZE_PATH, Some(TOKEN), &proposal)?)
            .await?;
        assert_eq!(authorization.status(), StatusCode::OK);
        assert_eq!(
            json_body(authorization).await["reason_code"],
            "UNKNOWN_SESSION"
        );
        Ok(())
    }

    #[tokio::test]
    async fn trusted_revocation_blocks_every_future_authorization()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new(true)?;
        let revocation = SessionRevocation::new(fixture.task_id, "session-1", "session-1");
        assert_eq!(
            fixture.runtime.revoke_session(&revocation)?,
            crate::RevocationRegistration::Revoked
        );

        for tool_call_id in ["after-revoke-1", "after-revoke-2"] {
            let response = fixture
                .runtime
                .router()
                .oneshot(request(
                    AUTHORIZE_PATH,
                    Some(TOKEN),
                    &fixture.proposal(tool_call_id),
                )?)
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(json_body(response).await["reason_code"], "SESSION_REVOKED");
        }
        Ok(())
    }

    #[tokio::test]
    async fn observation_creates_receipt_and_exact_retry_is_idempotent()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new(true)?;
        let proposal = fixture.proposal("call-observe");
        let authorization = fixture
            .runtime
            .router()
            .oneshot(request(AUTHORIZE_PATH, Some(TOKEN), &proposal)?)
            .await?;
        let grant = json_body(authorization).await;
        let observation = json!({
            "schema_version": TOOL_EXECUTION_SCHEMA_VERSION,
            "authorization_id": grant["authorization_id"],
            "proposal_digest": grant["proposal_digest"],
            "request_hash": grant["request_hash"],
            "outcome": "SUCCEEDED",
            "result_digest": Digest32::sha256(b"result").to_string()
        });
        for _ in 0..2 {
            let response = fixture
                .runtime
                .router()
                .oneshot(request(OBSERVE_PATH, Some(TOKEN), &observation)?)
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            let response = json_body(response).await;
            assert_eq!(response["schema_version"], TOOL_EXECUTION_SCHEMA_VERSION);
            assert_eq!(response["recorded"], true);
        }
        let authorization = grant["authorization_id"]
            .as_str()
            .ok_or("missing authorization")?
            .parse::<Uuid>()?;
        let attempt = fixture.runtime.ledger().attempt(authorization)?;
        assert_eq!(attempt.state, "SUCCEEDED");
        assert!(attempt.record_id.is_some());
        assert!(attempt.record_hash.is_some());
        assert!(attempt.completed_at.is_some());
        assert!(attempt.consumed_at >= fixture.now);
        Ok(())
    }

    #[tokio::test]
    async fn mutating_filesystem_action_requires_and_consumes_exact_private_approval()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let workspace = root.path().join("workspace");
        std::fs::create_dir(&workspace)?;
        let runtime = Runtime::open(&root.path().join("runtime.sqlite3"), TOKEN)?;
        let now = unix_time().map_err(|()| "clock unavailable")?;
        let task_id = Uuid::new_v4();
        let approval = ApprovedSession::new_with_task_objective(
            task_id,
            "write-session",
            "write-run",
            &workspace,
            9,
            "write objective",
            TaskPolicy::new(
                Digest32::sha256(b"write objective"),
                [],
                [
                    ".accordlock".to_owned(),
                    ".env".to_owned(),
                    ".git".to_owned(),
                    ".goose".to_owned(),
                    ".ssh".to_owned(),
                    "credentials".to_owned(),
                ],
            )?,
            [Capability::new("developer", "write")],
            now.saturating_sub(10),
            now.saturating_add(120),
        )?;
        runtime.approve_session(&approval)?;
        let arguments = json!({"content": "reviewed", "path": "notes.txt"});
        let arguments_sha256 = goose_digest(&arguments)?;
        let proposal = json!({
            "schema_version": TOOL_EXECUTION_SCHEMA_VERSION,
            "session_id": "write-session",
            "run_id": "write-run",
            "tool_call_id": "write-call",
            "workspace_root": approval.workspace_root,
            "extension_id": "developer",
            "tool_name": "write",
            "arguments_sha256": arguments_sha256.clone(),
            "arguments": arguments,
            "agent_plan_checkpoint": plan_checkpoint(
                "write-session",
                "write-run",
                "write-call",
                "developer__write",
                &arguments_sha256,
                now.saturating_sub(1)
            ),
        });
        let execution =
            json!({"schema_version": TOOL_EXECUTION_SCHEMA_VERSION, "proposal": proposal});

        let first = runtime
            .router()
            .oneshot(request(FILESYSTEM_EXECUTE_PATH, Some(TOKEN), &execution)?)
            .await?;
        assert_eq!(first.status(), StatusCode::OK);
        let first = json_body(first).await;
        assert_eq!(first["status"], "APPROVAL_REQUIRED");
        assert_eq!(first["reason_code"], "ACTION_APPROVAL_REQUIRED");
        assert!(first.get("authorization_id").is_none());
        let context: ActionApprovalRequest =
            serde_json::from_value(first["approval_request"].clone())?;
        assert_eq!(
            first["approval_request_hash"],
            context.digest()?.to_string()
        );
        assert_eq!(context.action.relative_path, "notes.txt");
        assert_eq!(context.action.action_type, crate::ActionType::CreateFile);

        let approval = ActionApproval::for_context(
            &context,
            Uuid::new_v4(),
            ApprovalDecision::Approved,
            Digest32::sha256(b"approved exact action"),
            now.saturating_sub(1),
            now.saturating_add(60),
        )?;
        assert_eq!(
            runtime.register_action_approval(&approval)?,
            crate::ActionApprovalRegistration::Inserted
        );

        let second = runtime
            .router()
            .oneshot(request(FILESYSTEM_EXECUTE_PATH, Some(TOKEN), &execution)?)
            .await?;
        assert_eq!(second.status(), StatusCode::OK);
        let second = json_body(second).await;
        assert_eq!(second["schema_version"], TOOL_EXECUTION_SCHEMA_VERSION);
        assert_eq!(second["status"], "SUCCEEDED");
        assert_eq!(second["reason_code"], "EXECUTED");
        assert_eq!(
            std::fs::read_to_string(workspace.join("notes.txt"))?,
            "reviewed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn new_execution_routes_are_authenticated_and_network_fails_closed_without_egress()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new(true)?;
        let network_arguments = json!({
            "method": "GET",
            "url": "https://api.example.com/v1/status",
            "headers": [],
            "body": null,
            "redirect_policy": "DENY"
        });
        let network_arguments_sha256 = goose_digest(&network_arguments)?;
        let network_proposal = json!({
            "schema_version": TOOL_EXECUTION_SCHEMA_VERSION,
            "session_id": "session-1",
            "run_id": "session-1",
            "tool_call_id": "network-disabled",
            "workspace_root": fixture.workspace.to_string_lossy(),
            "extension_id": "accordlock_network",
            "tool_name": "https_request",
            "arguments_sha256": network_arguments_sha256.clone(),
            "arguments": network_arguments,
            "agent_plan_checkpoint": plan_checkpoint(
                "session-1",
                "session-1",
                "network-disabled",
                "accordlock_network__https_request",
                &network_arguments_sha256,
                fixture.now.saturating_sub(1)
            ),
        });
        let network_execution =
            json!({"schema_version": TOOL_EXECUTION_SCHEMA_VERSION, "proposal": network_proposal});
        let unauthenticated = fixture
            .runtime
            .router()
            .oneshot(request(HTTPS_EXECUTE_PATH, None, &network_execution)?)
            .await?;
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        for _ in 0..2 {
            let disabled = fixture
                .runtime
                .router()
                .oneshot(request(
                    HTTPS_EXECUTE_PATH,
                    Some(TOKEN),
                    &network_execution,
                )?)
                .await?;
            assert_eq!(disabled.status(), StatusCode::OK);
            let disabled = json_body(disabled).await;
            assert_eq!(disabled["status"], "DENIED");
            assert_eq!(disabled["reason_code"], "NETWORK_EGRESS_NOT_CONFIGURED");
            assert!(disabled.get("authorization_id").is_none());
        }

        let terminal_arguments = json!({"argv": ["probe"], "cwd": "."});
        let terminal_arguments_sha256 = goose_digest(&terminal_arguments)?;
        let terminal_proposal = json!({
            "schema_version": TOOL_EXECUTION_SCHEMA_VERSION,
            "session_id": "session-1",
            "run_id": "session-1",
            "tool_call_id": "terminal-auth",
            "workspace_root": fixture.workspace.to_string_lossy(),
            "extension_id": "developer",
            "tool_name": "shell",
            "arguments_sha256": terminal_arguments_sha256.clone(),
            "arguments": terminal_arguments,
            "agent_plan_checkpoint": plan_checkpoint(
                "session-1",
                "session-1",
                "terminal-auth",
                "developer__shell",
                &terminal_arguments_sha256,
                fixture.now.saturating_sub(1)
            ),
        });
        let terminal_execution =
            json!({"schema_version": TOOL_EXECUTION_SCHEMA_VERSION, "proposal": terminal_proposal});
        let unauthenticated = fixture
            .runtime
            .router()
            .oneshot(request(TERMINAL_EXECUTE_PATH, None, &terminal_execution)?)
            .await?;
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[test]
    #[ignore = "spawned only by the policy-controlled terminal integration test"]
    fn terminal_child_probe() {
        println!("terminal-child-ok");
        println!("ci={}", std::env::var("CI").unwrap_or_default());
        println!(
            "accordlock-runtime-token-absent={}",
            std::env::var_os("ACCORDLOCK_RUNTIME_TOKEN").is_none()
        );
        println!(
            "aws-secret-access-key-absent={}",
            std::env::var_os("AWS_SECRET_ACCESS_KEY").is_none()
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn terminal_broker_records_approved_single_use_execution()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let workspace = root.path().join("workspace");
        std::fs::create_dir(&workspace)?;
        let executable = std::env::current_exe()?;
        let config = RuntimeConfig::new(TOKEN)?.with_terminal_program("test-probe", &executable)?;
        let runtime =
            Runtime::from_ledger(Ledger::open(&root.path().join("runtime.sqlite3"))?, config);
        let now = unix_time().map_err(|()| "clock unavailable")?;
        let task_id = Uuid::new_v4();
        let approval = ApprovedSession::new_with_task_objective(
            task_id,
            "terminal-session",
            "terminal-run",
            &workspace,
            11,
            "terminal objective",
            TaskPolicy::new(Digest32::sha256(b"terminal objective"), [], [])?,
            [Capability::new("developer", "shell")],
            now.saturating_sub(10),
            now.saturating_add(120),
        )?;
        runtime.approve_session(&approval)?;
        let arguments = json!({
            "argv": [
                "test-probe",
                "--exact",
                "http::tests::terminal_child_probe",
                "--ignored",
                "--nocapture"
            ],
            "cwd": ".",
            "env": {"CI": "1"},
            "timeout_seconds": 30,
            "max_output_bytes": 65536
        });
        let arguments_sha256 = goose_digest(&arguments)?;
        let proposal = json!({
            "schema_version": TOOL_EXECUTION_SCHEMA_VERSION,
            "session_id": "terminal-session",
            "run_id": "terminal-run",
            "tool_call_id": "terminal-call",
            "workspace_root": approval.workspace_root,
            "extension_id": "developer",
            "tool_name": "shell",
            "arguments_sha256": arguments_sha256.clone(),
            "arguments": arguments,
            "agent_plan_checkpoint": plan_checkpoint(
                "terminal-session",
                "terminal-run",
                "terminal-call",
                "developer__shell",
                &arguments_sha256,
                now.saturating_sub(1)
            ),
        });
        let execution =
            json!({"schema_version": TOOL_EXECUTION_SCHEMA_VERSION, "proposal": proposal});

        let direct = runtime
            .router()
            .oneshot(request(AUTHORIZE_PATH, Some(TOKEN), &proposal)?)
            .await?;
        assert_eq!(direct.status(), StatusCode::OK);
        assert_eq!(
            json_body(direct).await["reason_code"],
            "EXECUTION_CONTEXT_REQUIRED"
        );

        let challenge = runtime
            .router()
            .oneshot(request(TERMINAL_EXECUTE_PATH, Some(TOKEN), &execution)?)
            .await?;
        assert_eq!(challenge.status(), StatusCode::OK);
        let challenge = json_body(challenge).await;
        assert_eq!(challenge["status"], "APPROVAL_REQUIRED");
        let context: ActionApprovalRequest =
            serde_json::from_value(challenge["approval_request"].clone())?;
        assert_eq!(
            context.action.action_type,
            crate::ActionType::ExecuteProcess
        );
        assert_eq!(context.action.relative_path, ".");
        register_action_approval(&runtime, &context, now)?;

        let executed = runtime
            .router()
            .oneshot(request(TERMINAL_EXECUTE_PATH, Some(TOKEN), &execution)?)
            .await?;
        assert_eq!(executed.status(), StatusCode::OK);
        let executed = json_body(executed).await;
        assert_eq!(executed["status"], "SUCCEEDED", "{executed:#}");
        assert_eq!(executed["reason_code"], "EXECUTED");
        assert!(
            executed["result"]["stdout"]
                .as_str()
                .is_some_and(|stdout| stdout.contains("terminal-child-ok"))
        );
        assert!(
            executed["result"]["stdout"]
                .as_str()
                .is_some_and(|stdout| stdout.contains("ci=1"))
        );
        assert!(
            executed["result"]["stdout"]
                .as_str()
                .is_some_and(|stdout| stdout.contains("accordlock-runtime-token-absent=true"))
        );
        assert!(
            executed["result"]["stdout"]
                .as_str()
                .is_some_and(|stdout| stdout.contains("aws-secret-access-key-absent=true"))
        );
        let authorization = executed["authorization_id"]
            .as_str()
            .ok_or("missing terminal authorization")?
            .parse::<Uuid>()?;
        let attempt = runtime.ledger().attempt(authorization)?;
        assert_eq!(attempt.state, "SUCCEEDED");
        assert!(attempt.record_hash.is_some());
        Ok(())
    }

    #[derive(Debug)]
    struct TestHttpsEgress {
        policy: HttpsEgressPolicy,
    }

    impl HttpsEgress for TestHttpsEgress {
        fn policy(&self) -> HttpsEgressPolicy {
            self.policy.clone()
        }

        fn execute(
            &self,
            _request: &HttpsEgressRequest,
        ) -> Result<HttpsEgressResponse, HttpsEgressError> {
            Ok(HttpsEgressResponse {
                status: 200,
                headers: vec![HttpsHeader {
                    name: "content-type".to_owned(),
                    value: "application/json".to_owned(),
                }],
                body: "{\"ok\":true}".to_owned(),
                redirected: false,
            })
        }
    }

    #[tokio::test]
    async fn configured_https_broker_requires_approval_then_records_receipt()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let workspace = root.path().join("workspace");
        std::fs::create_dir(&workspace)?;
        let egress = TestHttpsEgress {
            policy: HttpsEgressPolicy::new(
                "test-egress-v2",
                ["api.example.com".to_owned()],
                [HttpsMethod::Get],
                0,
                65536,
            )?,
        };
        let runtime = Runtime::from_ledger(
            Ledger::open(&root.path().join("runtime.sqlite3"))?,
            RuntimeConfig::new(TOKEN)?,
        )
        .with_https_egress(Arc::new(egress))?;
        let now = unix_time().map_err(|()| "clock unavailable")?;
        let task_id = Uuid::new_v4();
        let approval = ApprovedSession::new_with_task_objective(
            task_id,
            "network-session",
            "network-run",
            &workspace,
            13,
            "network objective",
            TaskPolicy::new(Digest32::sha256(b"network objective"), [], [])?,
            [Capability::new("accordlock_network", "https_request")],
            now.saturating_sub(10),
            now.saturating_add(120),
        )?;
        runtime.approve_session(&approval)?;
        let arguments = json!({
            "method": "GET",
            "url": "https://api.example.com/v1/status",
            "headers": [{"name": "accept", "value": "application/json"}],
            "body": null,
            "timeout_seconds": 30,
            "max_response_bytes": 65536,
            "redirect_policy": "DENY"
        });
        let arguments_sha256 = goose_digest(&arguments)?;
        let proposal = json!({
            "schema_version": TOOL_EXECUTION_SCHEMA_VERSION,
            "session_id": "network-session",
            "run_id": "network-run",
            "tool_call_id": "network-call",
            "workspace_root": approval.workspace_root,
            "extension_id": "accordlock_network",
            "tool_name": "https_request",
            "arguments_sha256": arguments_sha256.clone(),
            "arguments": arguments,
            "agent_plan_checkpoint": plan_checkpoint(
                "network-session",
                "network-run",
                "network-call",
                "accordlock_network__https_request",
                &arguments_sha256,
                now.saturating_sub(1)
            ),
        });
        let execution =
            json!({"schema_version": TOOL_EXECUTION_SCHEMA_VERSION, "proposal": proposal});

        let direct = runtime
            .router()
            .oneshot(request(AUTHORIZE_PATH, Some(TOKEN), &proposal)?)
            .await?;
        assert_eq!(direct.status(), StatusCode::OK);
        assert_eq!(
            json_body(direct).await["reason_code"],
            "EXECUTION_CONTEXT_REQUIRED"
        );

        let challenge = runtime
            .router()
            .oneshot(request(HTTPS_EXECUTE_PATH, Some(TOKEN), &execution)?)
            .await?;
        assert_eq!(challenge.status(), StatusCode::OK);
        let challenge = json_body(challenge).await;
        assert_eq!(challenge["status"], "APPROVAL_REQUIRED");
        let context: ActionApprovalRequest =
            serde_json::from_value(challenge["approval_request"].clone())?;
        assert_eq!(context.action.action_type, crate::ActionType::HttpsRequest);
        register_action_approval(&runtime, &context, now)?;

        let executed = runtime
            .router()
            .oneshot(request(HTTPS_EXECUTE_PATH, Some(TOKEN), &execution)?)
            .await?;
        assert_eq!(executed.status(), StatusCode::OK);
        let executed = json_body(executed).await;
        assert_eq!(executed["status"], "SUCCEEDED");
        assert_eq!(executed["result"]["status"], 200);
        assert_eq!(executed["result"]["body"], "{\"ok\":true}");
        let authorization = executed["authorization_id"]
            .as_str()
            .ok_or("missing network authorization")?
            .parse::<Uuid>()?;
        assert_eq!(runtime.ledger().attempt(authorization)?.state, "SUCCEEDED");
        Ok(())
    }

    fn register_action_approval(
        runtime: &Runtime,
        context: &ActionApprovalRequest,
        now: i64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let approval = ActionApproval::for_context(
            context,
            Uuid::new_v4(),
            ApprovalDecision::Approved,
            Digest32::sha256(b"approved exact native action"),
            now.saturating_sub(1),
            now.saturating_add(60),
        )?;
        assert_eq!(
            runtime.register_action_approval(&approval)?,
            crate::ActionApprovalRegistration::Inserted
        );
        Ok(())
    }
}
