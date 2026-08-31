//! Bounded HTTPS transport for the Kubernetes admission profile.

#![forbid(unsafe_code)]

use std::{
    fmt,
    fs::File,
    future::Future,
    io::Read as _,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use accordlock_admission::{
    AdmissionReviewResponse, MAX_ADMISSION_REVIEW_BYTES, StateAdmissionEngine,
};
use accordlock_state::TransactionalState;
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use axum_server::{
    Handle, Server,
    tls_rustls::{RustlsAcceptor, RustlsConfig},
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tower_http::limit::RequestBodyLimitLayer;

const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_HANDLER_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_GRACEFUL_SHUTDOWN: Duration = Duration::from_secs(30);
const MAX_IN_FLIGHT_REQUESTS: usize = 256;
const MAX_TLS_PEM_BYTES: usize = 1024 * 1024;
const OBSERVER_IDENTITY_DOMAIN: &[u8] = b"accordlock:v1:webhook-logical-observer-identity\0";
/// Required prefix for a canonical logical observer identity.
pub const LOGICAL_OBSERVER_IDENTITY_PREFIX: &str = "urn:accordlock:observer:";
/// Maximum encoded length of a canonical logical observer identity.
pub const MAX_LOGICAL_OBSERVER_IDENTITY_BYTES: usize = 253;

/// Fail-closed application failure visible to the HTTP boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum AdmissionApplicationError {
    /// The request could not be safely interpreted as a bounded review.
    #[error("admission request rejected")]
    InvalidReview,
    /// Current authority, persistence, or another required control is unknown.
    #[error("admission control unavailable")]
    ControlUnavailable,
}

/// Trusted synchronous admission application installed behind the transport.
///
/// Implementations must derive all security facts from authenticated state.
/// The only request-facing argument is the bounded raw `AdmissionReview`.
pub trait AdmissionApplication: Send + Sync + 'static {
    /// Evaluates one review and returns a typed Kubernetes response.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed classification without exposing internal detail.
    fn review(&self, review: &[u8]) -> Result<AdmissionReviewResponse, AdmissionApplicationError>;

    /// Reports whether all controls required to authorize a new review are
    /// currently available.
    fn ready(&self) -> bool;
}

/// Process-local readiness control for the state-backed webhook application.
///
/// The HTTP boundary rejects new reviews while this switch is false. Setting
/// it true grants no authorization by itself; every accepted review still
/// reloads and atomically checks state.
#[derive(Clone, Debug)]
pub struct ReadinessSwitch {
    ready: Arc<AtomicBool>,
}

impl ReadinessSwitch {
    /// Marks the process ready after its composition root has verified all
    /// required local dependencies.
    pub fn mark_ready(&self) {
        self.ready.store(true, Ordering::Release);
    }

    /// Removes the process from readiness before shutdown or after a known
    /// dependency failure.
    pub fn mark_not_ready(&self) {
        self.ready.store(false, Ordering::Release);
    }

    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
}

/// Productive adapter from the state-derived admission engine to HTTPS.
///
/// The adapter owns its state backend and accepts only bounded review bytes at
/// request time. Marker, authority, trusted time, claim, fence, template,
/// destination, and provider commitments are obtained inside
/// [`StateAdmissionEngine`] from [`TransactionalState::admission_context`].
#[derive(Debug)]
pub struct StateAdmissionApplication<S> {
    engine: StateAdmissionEngine,
    state: S,
    readiness: ReadinessSwitch,
}

impl<S> StateAdmissionApplication<S> {
    /// Creates an application in the not-ready state and returns its separate
    /// readiness control.
    #[must_use]
    pub fn new(engine: StateAdmissionEngine, state: S) -> (Self, ReadinessSwitch) {
        let readiness = ReadinessSwitch {
            ready: Arc::new(AtomicBool::new(false)),
        };
        (
            Self {
                engine,
                state,
                readiness: readiness.clone(),
            },
            readiness,
        )
    }

    #[must_use]
    pub const fn state(&self) -> &S {
        &self.state
    }
}

impl<S> AdmissionApplication for StateAdmissionApplication<S>
where
    S: TransactionalState + Send + Sync + 'static,
{
    fn review(&self, review: &[u8]) -> Result<AdmissionReviewResponse, AdmissionApplicationError> {
        self.engine
            .evaluate(review, &self.state)
            .map_err(|_| AdmissionApplicationError::InvalidReview)
    }

    fn ready(&self) -> bool {
        self.readiness.is_ready()
    }
}

/// Bounded TLS listener and handler settings.
#[derive(Clone, PartialEq, Eq)]
pub struct WebhookConfig {
    bind_addr: SocketAddr,
    certificate_path: PathBuf,
    private_key_path: PathBuf,
    handler_timeout: Duration,
    graceful_shutdown: Duration,
    max_in_flight: usize,
}

impl fmt::Debug for WebhookConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebhookConfig")
            .field("bind_addr", &self.bind_addr)
            .field("certificate_path", &"[configured]")
            .field("private_key_path", &"[redacted]")
            .field("handler_timeout", &self.handler_timeout)
            .field("graceful_shutdown", &self.graceful_shutdown)
            .field("max_in_flight", &self.max_in_flight)
            .finish()
    }
}

impl WebhookConfig {
    /// Constructs a bounded server configuration.
    ///
    /// # Errors
    ///
    /// Returns an error for empty/equal paths or unsafe timeout bounds.
    pub fn new(
        bind_addr: SocketAddr,
        certificate_path: PathBuf,
        private_key_path: PathBuf,
        handler_timeout: Duration,
        graceful_shutdown: Duration,
        max_in_flight: usize,
    ) -> Result<Self, WebhookServerError> {
        if path_is_empty(&certificate_path)
            || path_is_empty(&private_key_path)
            || certificate_path == private_key_path
        {
            return Err(WebhookServerError::InvalidConfiguration);
        }
        if handler_timeout.is_zero()
            || handler_timeout > MAX_HANDLER_TIMEOUT
            || graceful_shutdown.is_zero()
            || graceful_shutdown > MAX_GRACEFUL_SHUTDOWN
            || max_in_flight == 0
            || max_in_flight > MAX_IN_FLIGHT_REQUESTS
        {
            return Err(WebhookServerError::InvalidConfiguration);
        }
        Ok(Self {
            bind_addr,
            certificate_path,
            private_key_path,
            handler_timeout,
            graceful_shutdown,
            max_in_flight,
        })
    }

    #[must_use]
    pub const fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    #[must_use]
    pub fn certificate_path(&self) -> &Path {
        &self.certificate_path
    }

    #[must_use]
    pub fn private_key_path(&self) -> &Path {
        &self.private_key_path
    }

    #[must_use]
    pub const fn handler_timeout(&self) -> Duration {
        self.handler_timeout
    }

    #[must_use]
    pub const fn graceful_shutdown(&self) -> Duration {
        self.graceful_shutdown
    }

    #[must_use]
    pub const fn max_in_flight(&self) -> usize {
        self.max_in_flight
    }
}

fn path_is_empty(path: &Path) -> bool {
    path.as_os_str().is_empty()
}

/// TLS server setup or runtime failure.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WebhookServerError {
    #[error("webhook configuration is invalid")]
    InvalidConfiguration,
    #[error("webhook TLS material could not be loaded")]
    TlsMaterial,
    #[error("webhook server failed")]
    Serve,
}

/// A stable, explicit identity for the logical admission observer.
///
/// The canonical form is `urn:accordlock:observer:<segment>[:<segment>...]`.
/// Segments contain only lowercase ASCII letters, digits, and interior
/// hyphens. The identity names the logical service and therefore must remain
/// stable across certificate and pod rotations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogicalObserverIdentity {
    canonical: String,
    commitment: [u8; 32],
}

impl LogicalObserverIdentity {
    /// Parses one canonical logical identity and derives its domain-separated
    /// commitment.
    ///
    /// # Errors
    ///
    /// Returns [`LogicalObserverIdentityError`] for an empty, non-ASCII,
    /// unbounded, non-canonical, or prefix-free value.
    pub fn new(canonical: String) -> Result<Self, LogicalObserverIdentityError> {
        if canonical.len() > MAX_LOGICAL_OBSERVER_IDENTITY_BYTES
            || !canonical.starts_with(LOGICAL_OBSERVER_IDENTITY_PREFIX)
        {
            return Err(LogicalObserverIdentityError);
        }
        let suffix = &canonical[LOGICAL_OBSERVER_IDENTITY_PREFIX.len()..];
        if suffix.is_empty()
            || suffix
                .split(':')
                .any(|segment| !valid_observer_segment(segment))
        {
            return Err(LogicalObserverIdentityError);
        }
        let mut hasher = Sha256::new();
        hasher.update(OBSERVER_IDENTITY_DOMAIN);
        hasher.update(
            u64::try_from(canonical.len())
                .map_err(|_| LogicalObserverIdentityError)?
                .to_be_bytes(),
        );
        hasher.update(canonical.as_bytes());
        let commitment = hasher.finalize().into();
        Ok(Self {
            canonical,
            commitment,
        })
    }

    /// Returns the canonical logical identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    /// Returns the domain-separated commitment to this logical identity.
    #[must_use]
    pub const fn commitment(&self) -> [u8; 32] {
        self.commitment
    }
}

fn valid_observer_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment.len() <= 63
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && segment
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && segment
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

/// Invalid or ambiguous logical observer identity.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("logical observer identity is invalid")]
pub struct LogicalObserverIdentityError;

/// TLS configuration prepared from one bounded, immutable read of the
/// certificate and private-key files.
///
/// Keeping the resulting Rustls configuration in this opaque object prevents
/// a path swap between TLS validation and listener startup. Logical observer
/// identity is deliberately configured and committed separately.
#[derive(Clone)]
pub struct PreparedServerTls {
    rustls: RustlsConfig,
}

impl fmt::Debug for PreparedServerTls {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedServerTls")
            .field("rustls", &"[configured]")
            .finish()
    }
}

/// Loads bounded TLS material exactly once and prepares the Rustls server.
///
/// # Errors
///
/// Returns [`WebhookServerError::TlsMaterial`] when either file cannot be read
/// within the bound or when Rustls rejects the PEM certificate/key pair.
pub async fn prepare_server_tls(
    config: &WebhookConfig,
) -> Result<PreparedServerTls, WebhookServerError> {
    let certificate_path = config.certificate_path().to_path_buf();
    let private_key_path = config.private_key_path().to_path_buf();
    let (certificate_bytes, private_key_bytes) = tokio::join!(
        read_bounded_tls_file(certificate_path),
        read_bounded_tls_file(private_key_path)
    );
    let certificate_bytes = certificate_bytes?;
    let private_key_bytes = private_key_bytes?;
    let rustls = RustlsConfig::from_pem(certificate_bytes, private_key_bytes)
        .await
        .map_err(|_| WebhookServerError::TlsMaterial)?;
    Ok(PreparedServerTls { rustls })
}

async fn read_bounded_tls_file(path: PathBuf) -> Result<Vec<u8>, WebhookServerError> {
    tokio::task::spawn_blocking(move || {
        let file = File::open(path).map_err(|_| WebhookServerError::TlsMaterial)?;
        let read_limit = u64::try_from(MAX_TLS_PEM_BYTES)
            .map_err(|_| WebhookServerError::TlsMaterial)?
            .saturating_add(1);
        let mut bytes = Vec::new();
        file.take(read_limit)
            .read_to_end(&mut bytes)
            .map_err(|_| WebhookServerError::TlsMaterial)?;
        if bytes.is_empty() || bytes.len() > MAX_TLS_PEM_BYTES {
            return Err(WebhookServerError::TlsMaterial);
        }
        Ok(bytes)
    })
    .await
    .map_err(|_| WebhookServerError::TlsMaterial)?
}

#[derive(Debug)]
struct AppState<A> {
    application: Arc<A>,
    handler_timeout: Duration,
    authorizations: Arc<tokio::sync::Semaphore>,
}

impl<A> Clone for AppState<A> {
    fn clone(&self) -> Self {
        Self {
            application: Arc::clone(&self.application),
            handler_timeout: self.handler_timeout,
            authorizations: Arc::clone(&self.authorizations),
        }
    }
}

/// Builds the HTTP router used by the TLS server.
///
/// # Errors
///
/// Returns an error for a zero or excessive handler timeout or concurrency
/// bound.
pub fn router<A: AdmissionApplication>(
    application: Arc<A>,
    handler_timeout: Duration,
    max_in_flight: usize,
) -> Result<Router, WebhookServerError> {
    if handler_timeout.is_zero()
        || handler_timeout > MAX_HANDLER_TIMEOUT
        || max_in_flight == 0
        || max_in_flight > MAX_IN_FLIGHT_REQUESTS
    {
        return Err(WebhookServerError::InvalidConfiguration);
    }
    let state = AppState {
        application,
        handler_timeout,
        authorizations: Arc::new(tokio::sync::Semaphore::new(max_in_flight)),
    };
    Ok(Router::new()
        .route(
            "/validate",
            post(validate::<A>).route_layer(middleware::from_fn_with_state(
                handler_timeout,
                request_deadline,
            )),
        )
        .route("/livez", get(livez))
        .route("/readyz", get(readyz::<A>))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(RequestBodyLimitLayer::new(MAX_ADMISSION_REVIEW_BYTES))
        .layer(DefaultBodyLimit::max(MAX_ADMISSION_REVIEW_BYTES))
        .layer(middleware::from_fn(harden_response))
        .with_state(state))
}

/// Serves HTTPS until the supplied shutdown future completes.
///
/// # Errors
///
/// Returns an error when TLS material cannot be loaded or the listener fails.
pub async fn serve_tls_until<A, F>(
    config: WebhookConfig,
    application: Arc<A>,
    shutdown: F,
) -> Result<(), WebhookServerError>
where
    A: AdmissionApplication,
    F: Future<Output = ()> + Send + 'static,
{
    let tls = prepare_server_tls(&config).await?;
    serve_prepared_tls_until(config, tls, application, shutdown).await
}

/// Serves HTTPS with material returned by [`prepare_server_tls`] until the
/// supplied shutdown future completes.
///
/// This entry point guarantees that listener startup does not re-read mutable
/// certificate paths. It has no role in logical observer identity; callers
/// derive that separately through [`LogicalObserverIdentity`].
///
/// # Errors
///
/// Returns an error when the listener or router fails.
pub async fn serve_prepared_tls_until<A, F>(
    config: WebhookConfig,
    tls: PreparedServerTls,
    application: Arc<A>,
    shutdown: F,
) -> Result<(), WebhookServerError>
where
    A: AdmissionApplication,
    F: Future<Output = ()> + Send + 'static,
{
    let handle = Handle::new();
    let shutdown_handle = handle.clone();
    let grace = config.graceful_shutdown();
    tokio::spawn(async move {
        shutdown.await;
        shutdown_handle.graceful_shutdown(Some(grace));
    });
    let acceptor = RustlsAcceptor::new(tls.rustls).handshake_timeout(config.handler_timeout());
    Server::bind(config.bind_addr())
        .acceptor(acceptor)
        .handle(handle)
        .serve(
            router(
                application,
                config.handler_timeout(),
                config.max_in_flight(),
            )?
            .into_make_service(),
        )
        .await
        .map_err(|_| WebhookServerError::Serve)
}

async fn validate<A: AdmissionApplication>(
    State(state): State<AppState<A>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !exact_json_content_type(&headers) {
        return generic_error(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    if !state.application.ready() {
        return generic_error(StatusCode::SERVICE_UNAVAILABLE);
    }
    let Ok(authorization) = Arc::clone(&state.authorizations).try_acquire_owned() else {
        return generic_error(StatusCode::SERVICE_UNAVAILABLE);
    };
    let application = Arc::clone(&state.application);
    let input = body.to_vec();
    let task = tokio::task::spawn_blocking(move || {
        let _authorization = authorization;
        application.review(&input)
    });
    match tokio::time::timeout(state.handler_timeout, task).await {
        Ok(Ok(Ok(review))) => match review.to_json_bytes() {
            Ok(bytes) if !bytes.is_empty() && bytes.len() <= MAX_RESPONSE_BYTES => {
                json_response(StatusCode::OK, bytes)
            }
            Ok(_) | Err(_) => generic_error(StatusCode::SERVICE_UNAVAILABLE),
        },
        Ok(Ok(Err(AdmissionApplicationError::InvalidReview))) => {
            generic_error(StatusCode::BAD_REQUEST)
        }
        Ok(Ok(Err(AdmissionApplicationError::ControlUnavailable)) | Err(_)) | Err(_) => {
            generic_error(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

async fn request_deadline(
    State(deadline): State<Duration>,
    request: Request,
    next: Next,
) -> Response {
    match tokio::time::timeout(deadline, next.run(request)).await {
        Ok(response) => response,
        Err(_) => generic_error(StatusCode::SERVICE_UNAVAILABLE),
    }
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

async fn livez() -> Response {
    plain_response(StatusCode::OK, "live")
}

async fn readyz<A: AdmissionApplication>(State(state): State<AppState<A>>) -> Response {
    if state.application.ready() {
        plain_response(StatusCode::OK, "ready")
    } else {
        plain_response(StatusCode::SERVICE_UNAVAILABLE, "not ready")
    }
}

async fn not_found() -> Response {
    generic_error(StatusCode::NOT_FOUND)
}

async fn method_not_allowed() -> Response {
    generic_error(StatusCode::METHOD_NOT_ALLOWED)
}

fn exact_json_content_type(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return false;
    };
    values.next().is_none() && value.as_bytes().eq_ignore_ascii_case(b"application/json")
}

fn json_response(status: StatusCode, bytes: Vec<u8>) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        bytes,
    )
        .into_response()
}

fn plain_response(status: StatusCode, body: &'static str) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        body,
    )
        .into_response()
}

fn generic_error(status: StatusCode) -> Response {
    plain_response(status, "request rejected")
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        sync::{
            Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };

    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use rcgen::generate_simple_self_signed;
    use serde_json::json;
    use tower::ServiceExt as _;

    use super::*;

    fn write_runtime_tls_fixture(certificate_path: &Path, private_key_path: &Path) {
        let certified = generate_simple_self_signed(vec!["accordlock-webhook.test".to_owned()])
            .unwrap_or_else(|_| unreachable!());
        fs::write(certificate_path, certified.cert.pem()).unwrap_or_else(|_| unreachable!());
        fs::write(private_key_path, certified.key_pair.serialize_pem())
            .unwrap_or_else(|_| unreachable!());
    }

    #[derive(Debug)]
    struct TestApplication {
        ready: AtomicBool,
        calls: AtomicUsize,
        started: tokio::sync::Notify,
        behavior: Mutex<TestBehavior>,
    }

    #[derive(Clone, Copy, Debug)]
    enum TestBehavior {
        Allow,
        Invalid,
        Unavailable,
        Slow,
    }

    impl TestApplication {
        fn new(behavior: TestBehavior) -> Self {
            Self {
                ready: AtomicBool::new(true),
                calls: AtomicUsize::new(0),
                started: tokio::sync::Notify::new(),
                behavior: Mutex::new(behavior),
            }
        }
    }

    impl AdmissionApplication for TestApplication {
        fn review(
            &self,
            review: &[u8],
        ) -> Result<AdmissionReviewResponse, AdmissionApplicationError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.started.notify_one();
            let behavior = self
                .behavior
                .lock()
                .map_err(|_| AdmissionApplicationError::ControlUnavailable)?;
            match *behavior {
                TestBehavior::Allow => {
                    let uid = serde_json::from_slice::<serde_json::Value>(review)
                        .ok()
                        .and_then(|value| {
                            value.pointer("/request/uid")?.as_str().map(str::to_owned)
                        })
                        .ok_or(AdmissionApplicationError::InvalidReview)?;
                    test_allow_response(&uid)
                }
                TestBehavior::Invalid => Err(AdmissionApplicationError::InvalidReview),
                TestBehavior::Unavailable => Err(AdmissionApplicationError::ControlUnavailable),
                TestBehavior::Slow => {
                    std::thread::sleep(Duration::from_millis(40));
                    Err(AdmissionApplicationError::ControlUnavailable)
                }
            }
        }

        fn ready(&self) -> bool {
            self.ready.load(Ordering::SeqCst)
        }
    }

    fn test_allow_response(
        uid: &str,
    ) -> Result<AdmissionReviewResponse, AdmissionApplicationError> {
        let bytes = serde_json::to_vec(&json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": uid,
                "kind": {"group":"apps","version":"v1","kind":"Deployment"},
                "resource": {"group":"apps","version":"v1","resource":"deployments"},
                "requestKind": {"group":"apps","version":"v1","kind":"Deployment"},
                "requestResource": {"group":"apps","version":"v1","resource":"deployments"},
                "name":"x","namespace":"x","operation":"UPDATE",
                "userInfo":{"username":"system:serviceaccount:x:x","groups":["system:authenticated"]},
                "object":{},"oldObject":{},"dryRun":true,"options":null
            }
        }))
        .map_err(|_| AdmissionApplicationError::ControlUnavailable)?;
        let profile = accordlock_admission::AdmissionProfile::new(
            "cluster".to_owned(),
            "api".to_owned(),
            "cluster".to_owned(),
            "system:serviceaccount:x:x".to_owned(),
            vec!["system:authenticated".to_owned()],
        )
        .map_err(|_| AdmissionApplicationError::ControlUnavailable)?;
        let marker = unreachable_marker();
        let runtime = unreachable_runtime();
        let response = accordlock_admission::AdmissionEngine::new(profile)
            .evaluate(
                &bytes,
                &marker,
                &runtime,
                &accordlock_admission::InMemoryAdmissionLedger::default(),
            )
            .map_err(|_| AdmissionApplicationError::ControlUnavailable)?;
        Ok(response)
    }

    fn unreachable_marker() -> accordlock_admission::AdmissionMarker {
        use accordlock_dispatch::{AuthorityVersion, PhysicalResourceId};
        use accordlock_protocol::{DeploymentTemplate, Digest32, canonical_hash};
        use uuid::Uuid;

        let template = DeploymentTemplate {
            operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
            environment: "test".to_owned(),
            audience: "x".to_owned(),
            repository: "https://github.com/example/x".to_owned(),
            commit_sha: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            image_repository: "registry.example.test/x".to_owned(),
            image_digest: Digest32::from_bytes([0xbb; 32]),
            cluster_identity: "cluster".to_owned(),
            namespace: "x".to_owned(),
            deployment: "x".to_owned(),
            deployment_uid: "uid".to_owned(),
            container: "app".to_owned(),
            container_index: 0,
            prior_image_digest: Digest32::from_bytes([0xaa; 32]),
            resource_version: "1".to_owned(),
            prior_projection_hash: Digest32::from_bytes([1; 32]),
            prior_transaction_annotation: Some("none".to_owned()),
            prior_authorization_annotation: Some("none".to_owned()),
            prior_operation_hash_annotation: Some("none".to_owned()),
        };
        let transaction = Uuid::from_u128(1);
        let authorization_id = Uuid::from_u128(2);
        let prepared = accordlock_k8s::prepare_patch(&template, transaction, authorization_id);
        let (template_hash, operation_hash, provider) =
            prepared.map_or(([1; 32], [2; 32], [3; 32]), |value| {
                (
                    canonical_hash(&template).map_or([1; 32], |digest| *digest.as_bytes()),
                    *value.operation_hash.as_bytes(),
                    *value.final_wire_commitment.as_bytes(),
                )
            });
        accordlock_admission::AdmissionMarker::for_model(
            accordlock_admission::AdmissionScope::new("t".to_owned(), "e".to_owned())
                .unwrap_or_else(|_| unreachable!()),
            transaction,
            authorization_id,
            Uuid::from_u128(3),
            template,
            template_hash,
            operation_hash,
            PhysicalResourceId {
                cluster_trust_domain: "cluster".to_owned(),
                api_server_identity: "api".to_owned(),
                namespace: "x".to_owned(),
                deployment_uid: "uid".to_owned(),
            },
            provider,
            [6; 32],
            "00000000-0000-0000-0000-000000000004".to_owned(),
            "AUTHORIZATION_ID=00000000-0000-0000-0000-000000000005".to_owned(),
            [7; 32],
            1,
            100,
            AuthorityVersion {
                root: [4; 32],
                epoch: 1,
            },
            1,
        )
    }

    fn unreachable_runtime() -> accordlock_admission::AdmissionRuntime {
        accordlock_admission::AdmissionRuntime::for_model(
            2,
            accordlock_dispatch::AuthorityVersion {
                root: [4; 32],
                epoch: 1,
            },
            [5; 32],
        )
    }

    fn request(body: Vec<u8>, content_type: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().method("POST").uri("/validate");
        if let Some(value) = content_type {
            builder = builder.header(header::CONTENT_TYPE, value);
        }
        builder
            .body(Body::from(body))
            .unwrap_or_else(|_| unreachable!())
    }

    fn test_router(application: Arc<TestApplication>, timeout: Duration) -> Router {
        router(application, timeout, 4).unwrap_or_else(|_| unreachable!())
    }

    #[tokio::test]
    async fn transport_returns_typed_json_without_cache() {
        let app = Arc::new(TestApplication::new(TestBehavior::Allow));
        let body = serde_json::to_vec(&json!({"request":{"uid":"u-1"}}))
            .unwrap_or_else(|_| unreachable!());
        let response = test_router(Arc::clone(&app), Duration::from_secs(1))
            .oneshot(request(body, Some("application/json")))
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&axum::http::HeaderValue::from_static("no-store"))
        );
        let bytes = to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
            .await
            .unwrap_or_else(|_| unreachable!());
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or_else(|_| unreachable!());
        assert_eq!(value.pointer("/response/uid"), Some(&json!("u-1")));
    }

    #[tokio::test]
    async fn missing_or_parameterized_content_type_never_calls_application() {
        let app = Arc::new(TestApplication::new(TestBehavior::Allow));
        for content_type in [None, Some("application/json; charset=utf-8")] {
            let response = test_router(Arc::clone(&app), Duration::from_secs(1))
                .oneshot(request(Vec::new(), content_type))
                .await
                .unwrap_or_else(|_| unreachable!());
            assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        }
        assert_eq!(app.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn duplicate_or_comma_folded_content_type_never_calls_application() {
        let app = Arc::new(TestApplication::new(TestBehavior::Allow));
        let service = test_router(Arc::clone(&app), Duration::from_secs(1));
        let mut duplicate = request(Vec::new(), Some("application/json"));
        duplicate.headers_mut().append(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        let duplicate_response = service
            .clone()
            .oneshot(duplicate)
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            duplicate_response.status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );

        let folded_response = service
            .oneshot(request(
                Vec::new(),
                Some("application/json, application/json"),
            ))
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(folded_response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(app.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn application_failures_and_timeout_are_fail_closed() {
        for (behavior, expected) in [
            (TestBehavior::Invalid, StatusCode::BAD_REQUEST),
            (TestBehavior::Unavailable, StatusCode::SERVICE_UNAVAILABLE),
            (TestBehavior::Slow, StatusCode::SERVICE_UNAVAILABLE),
        ] {
            let timeout = if matches!(behavior, TestBehavior::Slow) {
                Duration::from_millis(1)
            } else {
                Duration::from_secs(1)
            };
            let response = test_router(Arc::new(TestApplication::new(behavior)), timeout)
                .oneshot(request(b"{}".to_vec(), Some("application/json")))
                .await
                .unwrap_or_else(|_| unreachable!());
            assert_eq!(response.status(), expected);
        }
    }

    #[tokio::test]
    async fn body_limit_is_enforced_before_application() {
        let app = Arc::new(TestApplication::new(TestBehavior::Allow));
        let response = test_router(Arc::clone(&app), Duration::from_secs(1))
            .oneshot(request(
                vec![b'a'; MAX_ADMISSION_REVIEW_BYTES + 1],
                Some("application/json"),
            ))
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        assert_eq!(
            response.headers().get(header::X_CONTENT_TYPE_OPTIONS),
            Some(&HeaderValue::from_static("nosniff"))
        );
        assert_eq!(app.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn timed_out_blocking_work_retains_its_in_flight_authorization() {
        let app = Arc::new(TestApplication::new(TestBehavior::Slow));
        let service = router(Arc::clone(&app), Duration::from_millis(1), 1)
            .unwrap_or_else(|_| unreachable!());
        let first = service
            .clone()
            .oneshot(request(b"{}".to_vec(), Some("application/json")))
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(first.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            tokio::time::timeout(Duration::from_secs(2), app.started.notified())
                .await
                .is_ok(),
            "the first blocking task must start before the second request"
        );
        let second = service
            .oneshot(request(b"{}".to_vec(), Some("application/json")))
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(app.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn readiness_is_separate_from_liveness() {
        let app = Arc::new(TestApplication::new(TestBehavior::Unavailable));
        app.ready.store(false, Ordering::SeqCst);
        let ready = test_router(Arc::clone(&app), Duration::from_secs(1))
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap_or_else(|_| unreachable!()),
            )
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
        let live = test_router(app, Duration::from_secs(1))
            .oneshot(
                Request::builder()
                    .uri("/livez")
                    .body(Body::empty())
                    .unwrap_or_else(|_| unreachable!()),
            )
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(live.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn not_ready_application_cannot_authorize_a_direct_request() {
        let app = Arc::new(TestApplication::new(TestBehavior::Allow));
        app.ready.store(false, Ordering::SeqCst);
        let body = serde_json::to_vec(&json!({"request":{"uid":"u-not-ready"}}))
            .unwrap_or_else(|_| unreachable!());
        let response = test_router(Arc::clone(&app), Duration::from_secs(1))
            .oneshot(request(body, Some("application/json")))
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(app.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn request_deadline_wraps_the_entire_route_future() {
        let service = Router::new().route(
            "/slow",
            post(|| async {
                tokio::time::sleep(Duration::from_millis(40)).await;
                StatusCode::OK
            })
            .route_layer(middleware::from_fn_with_state(
                Duration::from_millis(1),
                request_deadline,
            )),
        );
        let response = service
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/slow")
                    .body(Body::empty())
                    .unwrap_or_else(|_| unreachable!()),
            )
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn fallback_and_method_errors_are_generic_and_hardened() {
        let service = test_router(
            Arc::new(TestApplication::new(TestBehavior::Allow)),
            Duration::from_secs(1),
        );
        for request in [
            Request::builder()
                .method("GET")
                .uri("/validate")
                .body(Body::empty())
                .unwrap_or_else(|_| unreachable!()),
            Request::builder()
                .method("POST")
                .uri("/missing")
                .body(Body::empty())
                .unwrap_or_else(|_| unreachable!()),
        ] {
            let response = service
                .clone()
                .oneshot(request)
                .await
                .unwrap_or_else(|_| unreachable!());
            assert!(matches!(
                response.status(),
                StatusCode::METHOD_NOT_ALLOWED | StatusCode::NOT_FOUND
            ));
            assert_eq!(
                response.headers().get(header::CACHE_CONTROL),
                Some(&HeaderValue::from_static("no-store"))
            );
            let body = to_bytes(response.into_body(), 64)
                .await
                .unwrap_or_else(|_| unreachable!());
            assert_eq!(body.as_ref(), b"request rejected");
        }
    }

    #[tokio::test]
    async fn prepared_tls_does_not_reread_a_swapped_certificate_path() {
        let directory = env::temp_dir().join(format!(
            "accordlock-webhook-tls-{}",
            uuid::Uuid::new_v4().as_hyphenated()
        ));
        fs::create_dir(&directory).unwrap_or_else(|_| unreachable!());
        let certificate_path = directory.join("cert.pem");
        let private_key_path = directory.join("key.pem");
        write_runtime_tls_fixture(&certificate_path, &private_key_path);
        let config = WebhookConfig::new(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            certificate_path.clone(),
            private_key_path,
            Duration::from_secs(1),
            Duration::from_secs(1),
            1,
        )
        .unwrap_or_else(|_| unreachable!());
        let prepared = prepare_server_tls(&config)
            .await
            .unwrap_or_else(|_| unreachable!());
        fs::write(certificate_path, b"attacker-controlled replacement")
            .unwrap_or_else(|_| unreachable!());
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            serve_prepared_tls_until(
                config,
                prepared,
                Arc::new(TestApplication::new(TestBehavior::Allow)),
                async {},
            ),
        )
        .await;
        assert!(matches!(result, Ok(Ok(()))));
        fs::remove_dir_all(directory).unwrap_or_else(|_| unreachable!());
    }

    #[test]
    fn tls_debug_output_never_discloses_configured_paths() {
        let certificate_path = PathBuf::from("sensitive-certificate-location.pem");
        let private_key_path = PathBuf::from("sensitive-private-key-location.pem");
        let config = WebhookConfig::new(
            SocketAddr::from(([127, 0, 0, 1], 9443)),
            certificate_path.clone(),
            private_key_path.clone(),
            Duration::from_secs(1),
            Duration::from_secs(1),
            1,
        )
        .unwrap_or_else(|_| unreachable!());

        let debug = format!("{config:?}");
        assert!(!debug.contains(&certificate_path.to_string_lossy().to_string()));
        assert!(!debug.contains(&private_key_path.to_string_lossy().to_string()));
        assert!(debug.contains("certificate_path: \"[configured]\""));
        assert!(debug.contains("private_key_path: \"[redacted]\""));
    }

    #[test]
    fn logical_observer_commitment_is_stable_domain_bound_and_distinct() {
        let canonical = "urn:accordlock:observer:acme:production:cluster-a:admission";
        let first =
            LogicalObserverIdentity::new(canonical.to_owned()).unwrap_or_else(|_| unreachable!());
        let repeated =
            LogicalObserverIdentity::new(canonical.to_owned()).unwrap_or_else(|_| unreachable!());
        let second = LogicalObserverIdentity::new(
            "urn:accordlock:observer:acme:production:cluster-b:admission".to_owned(),
        )
        .unwrap_or_else(|_| unreachable!());
        assert_eq!(first.as_str(), canonical);
        assert_eq!(first.commitment(), repeated.commitment());
        assert_ne!(first.commitment(), second.commitment());
        assert_ne!(first.commitment(), [0; 32]);

        let mut unbound = Sha256::new();
        unbound.update(canonical.as_bytes());
        let unbound: [u8; 32] = unbound.finalize().into();
        assert_ne!(first.commitment(), unbound);
    }

    #[test]
    fn logical_observer_identity_rejects_ambiguous_or_unbounded_forms() {
        for invalid in [
            "",
            "observer-a",
            "urn:accordlock:observer:",
            "urn:accordlock:observer:Acme:production:cluster-a",
            "urn:accordlock:observer:acme::cluster-a",
            "urn:accordlock:observer:-acme:production:cluster-a",
            "urn:accordlock:observer:acme:production:cluster-a-",
            "urn:accordlock:observer:acme:production:cluster.a",
            "urn:accordlock:observer:acme:production:cluster-a ",
            "urn:accordlock:observer:acm\u{e9}:production:cluster-a",
        ] {
            assert_eq!(
                LogicalObserverIdentity::new(invalid.to_owned()),
                Err(LogicalObserverIdentityError)
            );
        }
        let unbounded = format!(
            "{}{}",
            LOGICAL_OBSERVER_IDENTITY_PREFIX,
            "a".repeat(MAX_LOGICAL_OBSERVER_IDENTITY_BYTES)
        );
        assert_eq!(
            LogicalObserverIdentity::new(unbounded),
            Err(LogicalObserverIdentityError)
        );
    }

    #[test]
    fn configuration_rejects_equal_paths_and_unsafe_timeouts() {
        let address = SocketAddr::from(([127, 0, 0, 1], 9443));
        assert_eq!(
            WebhookConfig::new(
                address,
                PathBuf::from("same.pem"),
                PathBuf::from("same.pem"),
                Duration::from_secs(1),
                Duration::from_secs(1),
                4,
            ),
            Err(WebhookServerError::InvalidConfiguration)
        );
        assert_eq!(
            WebhookConfig::new(
                address,
                PathBuf::from("cert.pem"),
                PathBuf::from("key.pem"),
                Duration::from_secs(6),
                Duration::from_secs(1),
                4,
            ),
            Err(WebhookServerError::InvalidConfiguration)
        );
    }
}
