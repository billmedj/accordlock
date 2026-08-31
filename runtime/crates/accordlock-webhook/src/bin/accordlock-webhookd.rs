//! Strict composition root for the admission webhook process.

#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet,
    env,
    ffi::OsString,
    fmt,
    fs::File,
    io::Read as _,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    process::ExitCode,
    sync::Arc,
    time::Duration,
};

use accordlock_admission::{AdmissionProfile, AdmissionScope, StateAdmissionEngine};
use accordlock_state::{TlsPostgresConfig, TlsPostgresStore};
use accordlock_webhook::{
    LogicalObserverIdentity, StateAdmissionApplication, WebhookConfig, prepare_server_tls,
    serve_prepared_tls_until,
};
use thiserror::Error;

const MAX_CONFIG_TEXT_BYTES: usize = 512;
const MAX_POSTGRES_CA_BYTES: usize = 1024 * 1024;
const MAX_POSTGRES_CLIENT_IDENTITY_BYTES: usize = 1024 * 1024;
const MAX_POSTGRES_PASSWORD_BYTES: usize = 64 * 1024;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("accordlock-webhookd: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), WebhookdError> {
    let config = RuntimeConfig::from_environment()?;
    let observer_commitment = config.observer_identity.commitment();
    let server_config = WebhookConfig::new(
        config.bind_addr,
        config.certificate_path.clone(),
        config.private_key_path.clone(),
        config.handler_timeout,
        config.graceful_shutdown,
        config.max_in_flight,
    )
    .map_err(|_| WebhookdError::InvalidConfiguration)?;
    let prepared_tls = prepare_server_tls(&server_config)
        .await
        .map_err(|_| WebhookdError::TlsMaterial)?;
    let state = build_remote_state(&config).await?;
    let state = tokio::task::spawn_blocking(move || {
        state
            .validate_schema()
            .map(|()| state)
            .map_err(|_| WebhookdError::StateUnavailable)
    })
    .await
    .map_err(|_| WebhookdError::StateUnavailable)??;
    let profile = AdmissionProfile::new(
        config.cluster_trust_domain,
        config.api_server_identity,
        config.cluster_identity,
        config.executor_username,
        config.executor_groups,
    )
    .map_err(|_| WebhookdError::InvalidConfiguration)?;
    let scope = AdmissionScope::new(config.tenant, config.environment)
        .map_err(|_| WebhookdError::InvalidConfiguration)?;
    let engine = StateAdmissionEngine::new(profile, scope, observer_commitment)
        .map_err(|_| WebhookdError::InvalidConfiguration)?;
    let (application, readiness) = StateAdmissionApplication::new(engine, state);
    readiness.mark_ready();
    let shutdown_readiness = readiness.clone();
    let shutdown = async move {
        shutdown_signal().await;
        shutdown_readiness.mark_not_ready();
    };
    serve_prepared_tls_until(server_config, prepared_tls, Arc::new(application), shutdown)
        .await
        .map_err(|_| WebhookdError::Server)
}

async fn build_remote_state(config: &RuntimeConfig) -> Result<TlsPostgresStore, WebhookdError> {
    let mut password = read_bounded_file(
        config.postgres_password_path.clone(),
        MAX_POSTGRES_PASSWORD_BYTES,
    )
    .await?;
    let ca_pem = read_bounded_file(config.postgres_ca_path.clone(), MAX_POSTGRES_CA_BYTES).await?;
    let postgres = TlsPostgresConfig::new(
        config.postgres_server_name.clone(),
        config.postgres_database.clone(),
        config.postgres_user.clone(),
        &password,
        &ca_pem,
    );
    password.fill(0);
    let mut postgres = postgres.map_err(|_| WebhookdError::InvalidConfiguration)?;
    postgres = postgres
        .with_port(config.postgres_port)
        .and_then(|value| value.with_connect_timeout(config.postgres_connect_timeout))
        .map_err(|_| WebhookdError::InvalidConfiguration)?;
    if let Some(target_address) = config.postgres_target_address {
        postgres = postgres.with_target_address(target_address);
    }
    if let Some((certificate_path, private_key_path)) = &config.postgres_client_identity_paths {
        let (certificate_pem, private_key_pem) = tokio::join!(
            read_bounded_file(certificate_path.clone(), MAX_POSTGRES_CLIENT_IDENTITY_BYTES,),
            read_bounded_file(private_key_path.clone(), MAX_POSTGRES_CLIENT_IDENTITY_BYTES,)
        );
        let (certificate_pem, mut private_key_pem) = match (certificate_pem, private_key_pem) {
            (Ok(certificate_pem), Ok(private_key_pem)) => (certificate_pem, private_key_pem),
            (Err(error), Ok(mut private_key_pem)) => {
                private_key_pem.fill(0);
                return Err(error);
            }
            (Ok(_) | Err(_), Err(error)) => return Err(error),
        };
        let with_identity = postgres.with_client_identity(&certificate_pem, &private_key_pem);
        private_key_pem.fill(0);
        postgres = with_identity.map_err(|_| WebhookdError::InvalidConfiguration)?;
    }
    TlsPostgresStore::new(postgres).map_err(|_| WebhookdError::InvalidConfiguration)
}

async fn read_bounded_file(path: PathBuf, maximum: usize) -> Result<Vec<u8>, WebhookdError> {
    tokio::task::spawn_blocking(move || {
        let file = File::open(path).map_err(|_| WebhookdError::StateConfigurationMaterial)?;
        let limit = u64::try_from(maximum)
            .map_err(|_| WebhookdError::StateConfigurationMaterial)?
            .saturating_add(1);
        let mut bytes = Vec::new();
        file.take(limit)
            .read_to_end(&mut bytes)
            .map_err(|_| WebhookdError::StateConfigurationMaterial)?;
        if bytes.is_empty() || bytes.len() > maximum {
            return Err(WebhookdError::StateConfigurationMaterial);
        }
        Ok(bytes)
    })
    .await
    .map_err(|_| WebhookdError::StateConfigurationMaterial)?
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let terminate = signal(SignalKind::terminate());
    match terminate {
        Ok(mut terminate) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = terminate.recv() => {},
            }
        }
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[derive(Debug, Error, PartialEq, Eq)]
enum WebhookdError {
    #[error("configuration is invalid or incomplete")]
    InvalidConfiguration,
    #[error("TLS material is unavailable or invalid")]
    TlsMaterial,
    #[error("durable-state TLS or credential material is unavailable or invalid")]
    StateConfigurationMaterial,
    #[error("durable state is unavailable or has unexpected schema")]
    StateUnavailable,
    #[error("HTTPS server failed")]
    Server,
}

#[derive(PartialEq, Eq)]
struct RuntimeConfig {
    bind_addr: SocketAddr,
    certificate_path: PathBuf,
    private_key_path: PathBuf,
    handler_timeout: Duration,
    graceful_shutdown: Duration,
    max_in_flight: usize,
    observer_identity: LogicalObserverIdentity,
    postgres_server_name: String,
    postgres_target_address: Option<IpAddr>,
    postgres_port: u16,
    postgres_database: String,
    postgres_user: String,
    postgres_password_path: PathBuf,
    postgres_ca_path: PathBuf,
    postgres_connect_timeout: Duration,
    postgres_client_identity_paths: Option<(PathBuf, PathBuf)>,
    tenant: String,
    environment: String,
    cluster_trust_domain: String,
    api_server_identity: String,
    cluster_identity: String,
    executor_username: String,
    executor_groups: Vec<String>,
}

struct RuntimePaths {
    certificate: PathBuf,
    private_key: PathBuf,
    postgres_password: PathBuf,
    postgres_ca: PathBuf,
    postgres_client_identity: Option<(PathBuf, PathBuf)>,
}

impl fmt::Debug for RuntimeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeConfig")
            .field("bind_addr", &self.bind_addr)
            .field("certificate_path", &"[REDACTED]")
            .field("private_key_path", &"[REDACTED]")
            .field("handler_timeout", &self.handler_timeout)
            .field("graceful_shutdown", &self.graceful_shutdown)
            .field("max_in_flight", &self.max_in_flight)
            .field("observer_identity", &self.observer_identity.as_str())
            .field("postgres_server_name", &self.postgres_server_name)
            .field("postgres_target_address", &self.postgres_target_address)
            .field("postgres_port", &self.postgres_port)
            .field("postgres_database", &self.postgres_database)
            .field("postgres_user", &"[REDACTED]")
            .field("postgres_password_path", &"[REDACTED]")
            .field("postgres_ca_path", &"[REDACTED]")
            .field("postgres_connect_timeout", &self.postgres_connect_timeout)
            .field(
                "postgres_client_identity_paths",
                &self
                    .postgres_client_identity_paths
                    .as_ref()
                    .map(|_| "[REDACTED]"),
            )
            .field("tenant", &self.tenant)
            .field("environment", &self.environment)
            .field("cluster_trust_domain", &self.cluster_trust_domain)
            .field("api_server_identity", &self.api_server_identity)
            .field("cluster_identity", &self.cluster_identity)
            .field("executor_username", &self.executor_username)
            .field("executor_groups", &self.executor_groups)
            .finish()
    }
}

impl RuntimeConfig {
    fn from_environment() -> Result<Self, WebhookdError> {
        Self::from_lookup(|name| env::var_os(name))
    }

    fn from_lookup(
        mut lookup: impl FnMut(&str) -> Option<OsString>,
    ) -> Result<Self, WebhookdError> {
        let bind_addr = required_text(&mut lookup, "ACCORDLOCK_WEBHOOK_BIND_ADDR")?
            .parse::<SocketAddr>()
            .map_err(|_| WebhookdError::InvalidConfiguration)?;
        if bind_addr.port() == 0 {
            return Err(WebhookdError::InvalidConfiguration);
        }
        let paths = runtime_paths(&mut lookup)?;
        let handler_timeout = Duration::from_millis(required_number(
            &mut lookup,
            "ACCORDLOCK_WEBHOOK_HANDLER_TIMEOUT_MS",
            1,
            5_000,
        )?);
        let graceful_shutdown = Duration::from_millis(required_number(
            &mut lookup,
            "ACCORDLOCK_WEBHOOK_GRACEFUL_SHUTDOWN_MS",
            1,
            30_000,
        )?);
        let max_in_flight = usize::try_from(required_number(
            &mut lookup,
            "ACCORDLOCK_WEBHOOK_MAX_IN_FLIGHT",
            1,
            256,
        )?)
        .map_err(|_| WebhookdError::InvalidConfiguration)?;
        let observer_identity = LogicalObserverIdentity::new(required_text(
            &mut lookup,
            "ACCORDLOCK_WEBHOOK_OBSERVER_IDENTITY",
        )?)
        .map_err(|_| WebhookdError::InvalidConfiguration)?;
        let postgres_port = u16::try_from(required_number(
            &mut lookup,
            "ACCORDLOCK_STATE_POSTGRES_PORT",
            1,
            u64::from(u16::MAX),
        )?)
        .map_err(|_| WebhookdError::InvalidConfiguration)?;
        let postgres_connect_timeout = Duration::from_millis(required_number(
            &mut lookup,
            "ACCORDLOCK_STATE_POSTGRES_CONNECT_TIMEOUT_MS",
            1,
            60_000,
        )?);
        let postgres_target_address =
            optional_text(&mut lookup, "ACCORDLOCK_STATE_POSTGRES_TARGET_ADDRESS")?
                .map(|value| {
                    value
                        .parse::<IpAddr>()
                        .map_err(|_| WebhookdError::InvalidConfiguration)
                })
                .transpose()?;
        let executor_groups_json =
            required_text(&mut lookup, "ACCORDLOCK_WEBHOOK_EXECUTOR_GROUPS_JSON")?;
        let executor_groups: Vec<String> = serde_json::from_str(&executor_groups_json)
            .map_err(|_| WebhookdError::InvalidConfiguration)?;
        let unique_groups: BTreeSet<&str> = executor_groups.iter().map(String::as_str).collect();
        if executor_groups.is_empty()
            || unique_groups.len() != executor_groups.len()
            || executor_groups.iter().any(|group| !canonical_text(group))
        {
            return Err(WebhookdError::InvalidConfiguration);
        }
        Ok(Self {
            bind_addr,
            certificate_path: paths.certificate,
            private_key_path: paths.private_key,
            handler_timeout,
            graceful_shutdown,
            max_in_flight,
            observer_identity,
            postgres_server_name: required_text(
                &mut lookup,
                "ACCORDLOCK_STATE_POSTGRES_SERVER_NAME",
            )?,
            postgres_target_address,
            postgres_port,
            postgres_database: required_text(&mut lookup, "ACCORDLOCK_STATE_POSTGRES_DATABASE")?,
            postgres_user: required_text(&mut lookup, "ACCORDLOCK_STATE_POSTGRES_USER")?,
            postgres_password_path: paths.postgres_password,
            postgres_ca_path: paths.postgres_ca,
            postgres_connect_timeout,
            postgres_client_identity_paths: paths.postgres_client_identity,
            tenant: required_text(&mut lookup, "ACCORDLOCK_WEBHOOK_TENANT")?,
            environment: required_text(&mut lookup, "ACCORDLOCK_WEBHOOK_ENVIRONMENT")?,
            cluster_trust_domain: required_text(
                &mut lookup,
                "ACCORDLOCK_WEBHOOK_CLUSTER_TRUST_DOMAIN",
            )?,
            api_server_identity: required_text(
                &mut lookup,
                "ACCORDLOCK_WEBHOOK_API_SERVER_IDENTITY",
            )?,
            cluster_identity: required_text(&mut lookup, "ACCORDLOCK_WEBHOOK_CLUSTER_IDENTITY")?,
            executor_username: required_text(&mut lookup, "ACCORDLOCK_WEBHOOK_EXECUTOR_USERNAME")?,
            executor_groups,
        })
    }
}

fn runtime_paths(
    lookup: &mut impl FnMut(&str) -> Option<OsString>,
) -> Result<RuntimePaths, WebhookdError> {
    let certificate = required_absolute_path(lookup, "ACCORDLOCK_WEBHOOK_TLS_CERT_PATH")?;
    let private_key = required_absolute_path(lookup, "ACCORDLOCK_WEBHOOK_TLS_KEY_PATH")?;
    let postgres_password =
        required_absolute_path(lookup, "ACCORDLOCK_STATE_POSTGRES_PASSWORD_PATH")?;
    let postgres_ca = required_absolute_path(lookup, "ACCORDLOCK_STATE_POSTGRES_CA_PATH")?;
    let postgres_client_certificate =
        optional_absolute_path(lookup, "ACCORDLOCK_STATE_POSTGRES_CLIENT_CERT_PATH")?;
    let postgres_client_private_key =
        optional_absolute_path(lookup, "ACCORDLOCK_STATE_POSTGRES_CLIENT_KEY_PATH")?;
    let postgres_client_identity = match (postgres_client_certificate, postgres_client_private_key)
    {
        (None, None) => None,
        (Some(client_certificate), Some(client_private_key)) => {
            if client_certificate == client_private_key {
                return Err(WebhookdError::InvalidConfiguration);
            }
            Some((client_certificate, client_private_key))
        }
        _ => return Err(WebhookdError::InvalidConfiguration),
    };
    let mut unique = BTreeSet::from([
        certificate.as_path(),
        private_key.as_path(),
        postgres_password.as_path(),
        postgres_ca.as_path(),
    ]);
    if let Some((client_certificate, client_private_key)) = &postgres_client_identity {
        unique.insert(client_certificate.as_path());
        unique.insert(client_private_key.as_path());
    }
    let expected = if postgres_client_identity.is_some() {
        6
    } else {
        4
    };
    if unique.len() != expected {
        return Err(WebhookdError::InvalidConfiguration);
    }
    Ok(RuntimePaths {
        certificate,
        private_key,
        postgres_password,
        postgres_ca,
        postgres_client_identity,
    })
}

fn required_text(
    lookup: &mut impl FnMut(&str) -> Option<OsString>,
    name: &str,
) -> Result<String, WebhookdError> {
    let value = lookup(name).ok_or(WebhookdError::InvalidConfiguration)?;
    let value = value
        .into_string()
        .map_err(|_| WebhookdError::InvalidConfiguration)?;
    if !canonical_text(&value) {
        return Err(WebhookdError::InvalidConfiguration);
    }
    Ok(value)
}

fn optional_text(
    lookup: &mut impl FnMut(&str) -> Option<OsString>,
    name: &str,
) -> Result<Option<String>, WebhookdError> {
    lookup(name)
        .map(|value| {
            let value = value
                .into_string()
                .map_err(|_| WebhookdError::InvalidConfiguration)?;
            if !canonical_text(&value) {
                return Err(WebhookdError::InvalidConfiguration);
            }
            Ok(value)
        })
        .transpose()
}

fn required_absolute_path(
    lookup: &mut impl FnMut(&str) -> Option<OsString>,
    name: &str,
) -> Result<PathBuf, WebhookdError> {
    let path = PathBuf::from(required_text(lookup, name)?);
    if !path.is_absolute() {
        return Err(WebhookdError::InvalidConfiguration);
    }
    Ok(path)
}

fn optional_absolute_path(
    lookup: &mut impl FnMut(&str) -> Option<OsString>,
    name: &str,
) -> Result<Option<PathBuf>, WebhookdError> {
    optional_text(lookup, name)?
        .map(PathBuf::from)
        .map(|path| {
            if !path.is_absolute() {
                return Err(WebhookdError::InvalidConfiguration);
            }
            Ok(path)
        })
        .transpose()
}

fn required_number(
    lookup: &mut impl FnMut(&str) -> Option<OsString>,
    name: &str,
    minimum: u64,
    maximum: u64,
) -> Result<u64, WebhookdError> {
    let value = required_text(lookup, name)?;
    if value.starts_with('+') || (value.len() > 1 && value.starts_with('0')) {
        return Err(WebhookdError::InvalidConfiguration);
    }
    let parsed = value
        .parse::<u64>()
        .map_err(|_| WebhookdError::InvalidConfiguration)?;
    if !(minimum..=maximum).contains(&parsed) {
        return Err(WebhookdError::InvalidConfiguration);
    }
    Ok(parsed)
}

fn canonical_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CONFIG_TEXT_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn valid_values() -> BTreeMap<String, OsString> {
        BTreeMap::from([
            ("ACCORDLOCK_WEBHOOK_BIND_ADDR".to_owned(), "0.0.0.0:9443".into()),
            (
                "ACCORDLOCK_WEBHOOK_TLS_CERT_PATH".to_owned(),
                absolute_test_path("cert.pem").into_os_string(),
            ),
            (
                "ACCORDLOCK_WEBHOOK_TLS_KEY_PATH".to_owned(),
                absolute_test_path("key.pem").into_os_string(),
            ),
            ("ACCORDLOCK_WEBHOOK_HANDLER_TIMEOUT_MS".to_owned(), "1500".into()),
            (
                "ACCORDLOCK_WEBHOOK_GRACEFUL_SHUTDOWN_MS".to_owned(),
                "5000".into(),
            ),
            ("ACCORDLOCK_WEBHOOK_MAX_IN_FLIGHT".to_owned(), "32".into()),
            (
                "ACCORDLOCK_WEBHOOK_OBSERVER_IDENTITY".to_owned(),
                "urn:accordlock:observer:acme:production:cluster-a:admission".into(),
            ),
            (
                "ACCORDLOCK_STATE_POSTGRES_SERVER_NAME".to_owned(),
                "state.internal.example".into(),
            ),
            ("ACCORDLOCK_STATE_POSTGRES_PORT".to_owned(), "5432".into()),
            (
                "ACCORDLOCK_STATE_POSTGRES_DATABASE".to_owned(),
                "accordlock".into(),
            ),
            (
                "ACCORDLOCK_STATE_POSTGRES_USER".to_owned(),
                "accordlock_webhook".into(),
            ),
            (
                "ACCORDLOCK_STATE_POSTGRES_PASSWORD_PATH".to_owned(),
                absolute_test_path("postgres-password").into_os_string(),
            ),
            (
                "ACCORDLOCK_STATE_POSTGRES_CA_PATH".to_owned(),
                absolute_test_path("postgres-ca.pem").into_os_string(),
            ),
            (
                "ACCORDLOCK_STATE_POSTGRES_CONNECT_TIMEOUT_MS".to_owned(),
                "3000".into(),
            ),
            ("ACCORDLOCK_WEBHOOK_TENANT".to_owned(), "acme".into()),
            (
                "ACCORDLOCK_WEBHOOK_ENVIRONMENT".to_owned(),
                "production".into(),
            ),
            (
                "ACCORDLOCK_WEBHOOK_CLUSTER_TRUST_DOMAIN".to_owned(),
                "cluster-a.example".into(),
            ),
            (
                "ACCORDLOCK_WEBHOOK_API_SERVER_IDENTITY".to_owned(),
                "https://api.cluster-a.example:443".into(),
            ),
            (
                "ACCORDLOCK_WEBHOOK_CLUSTER_IDENTITY".to_owned(),
                "eks://cluster-a".into(),
            ),
            (
                "ACCORDLOCK_WEBHOOK_EXECUTOR_USERNAME".to_owned(),
                "system:serviceaccount:accordlock-system:accordlock-executor".into(),
            ),
            (
                "ACCORDLOCK_WEBHOOK_EXECUTOR_GROUPS_JSON".to_owned(),
                r#"["system:authenticated","system:serviceaccounts","system:serviceaccounts:accordlock-system"]"#.into(),
            ),
        ])
    }

    fn absolute_test_path(name: &str) -> PathBuf {
        env::temp_dir().join(name)
    }

    fn parse(values: &BTreeMap<String, OsString>) -> Result<RuntimeConfig, WebhookdError> {
        RuntimeConfig::from_lookup(|name| values.get(name).cloned())
    }

    #[test]
    fn exact_configuration_is_accepted() {
        let values = valid_values();
        let config = parse(&values).unwrap_or_else(|_| unreachable!());
        assert_eq!(config.bind_addr.port(), 9443);
        assert_eq!(config.max_in_flight, 32);
        assert_eq!(config.postgres_port, 5432);
        assert_eq!(config.postgres_connect_timeout, Duration::from_secs(3));
        assert!(config.postgres_target_address.is_none());
        assert!(config.postgres_client_identity_paths.is_none());
        assert_eq!(
            config.observer_identity.as_str(),
            "urn:accordlock:observer:acme:production:cluster-a:admission"
        );
        assert_eq!(config.executor_groups.len(), 3);
    }

    #[test]
    fn configuration_debug_redacts_secret_locations_and_database_identity() {
        let values = valid_values();
        let config = parse(&values).unwrap_or_else(|_| unreachable!());
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("accordlock_webhook"));
        assert!(!rendered.contains("postgres-password"));
        assert!(!rendered.contains("postgres-ca.pem"));
        assert!(!rendered.contains("cert.pem"));
        assert!(!rendered.contains("key.pem"));
        assert!(rendered.matches("[REDACTED]").count() >= 5);
    }

    #[test]
    fn every_required_value_is_fail_closed() {
        let names: Vec<String> = valid_values().keys().cloned().collect();
        for name in names {
            let mut values = valid_values();
            values.remove(&name);
            assert_eq!(parse(&values), Err(WebhookdError::InvalidConfiguration));
        }
    }

    #[test]
    fn duplicate_groups_relative_paths_and_noncanonical_numbers_are_rejected() {
        let mut values = valid_values();
        values.insert(
            "ACCORDLOCK_WEBHOOK_EXECUTOR_GROUPS_JSON".to_owned(),
            r#"["system:authenticated","system:authenticated"]"#.into(),
        );
        assert_eq!(parse(&values), Err(WebhookdError::InvalidConfiguration));

        let mut values = valid_values();
        values.insert(
            "ACCORDLOCK_WEBHOOK_TLS_KEY_PATH".to_owned(),
            "key.pem".into(),
        );
        assert_eq!(parse(&values), Err(WebhookdError::InvalidConfiguration));

        let mut values = valid_values();
        values.insert("ACCORDLOCK_WEBHOOK_MAX_IN_FLIGHT".to_owned(), "032".into());
        assert_eq!(parse(&values), Err(WebhookdError::InvalidConfiguration));

        let mut values = valid_values();
        values.insert(
            "ACCORDLOCK_STATE_POSTGRES_CLIENT_CERT_PATH".to_owned(),
            absolute_test_path("postgres-client.pem").into_os_string(),
        );
        assert_eq!(parse(&values), Err(WebhookdError::InvalidConfiguration));

        let mut values = valid_values();
        values.insert(
            "ACCORDLOCK_STATE_POSTGRES_PASSWORD_PATH".to_owned(),
            absolute_test_path("postgres-ca.pem").into_os_string(),
        );
        assert_eq!(parse(&values), Err(WebhookdError::InvalidConfiguration));

        let mut values = valid_values();
        values.insert(
            "ACCORDLOCK_STATE_POSTGRES_TARGET_ADDRESS".to_owned(),
            "not-an-ip".into(),
        );
        assert_eq!(parse(&values), Err(WebhookdError::InvalidConfiguration));
    }

    #[test]
    fn ambiguous_logical_observer_identities_are_rejected() {
        for invalid in [
            "observer-a",
            "urn:accordlock:observer:",
            "urn:accordlock:observer:Acme:production:cluster-a",
            "urn:accordlock:observer:acme::cluster-a",
            "urn:accordlock:observer:-acme:production:cluster-a",
            "urn:accordlock:observer:acme:production:cluster-a-",
            "urn:accordlock:observer:acme:production:cluster.a",
            "urn:accordlock:observer:acme:production:cluster-a ",
        ] {
            let mut values = valid_values();
            values.insert(
                "ACCORDLOCK_WEBHOOK_OBSERVER_IDENTITY".to_owned(),
                invalid.into(),
            );
            assert_eq!(parse(&values), Err(WebhookdError::InvalidConfiguration));
        }
    }

    #[test]
    fn optional_route_pin_and_client_identity_require_exact_typed_pairs() {
        let mut values = valid_values();
        values.insert(
            "ACCORDLOCK_STATE_POSTGRES_TARGET_ADDRESS".to_owned(),
            "10.0.0.15".into(),
        );
        values.insert(
            "ACCORDLOCK_STATE_POSTGRES_CLIENT_CERT_PATH".to_owned(),
            absolute_test_path("postgres-client.pem").into_os_string(),
        );
        values.insert(
            "ACCORDLOCK_STATE_POSTGRES_CLIENT_KEY_PATH".to_owned(),
            absolute_test_path("postgres-client-key.pem").into_os_string(),
        );
        let config = parse(&values).unwrap_or_else(|_| unreachable!());
        assert_eq!(
            config.postgres_target_address,
            Some(IpAddr::from([10, 0, 0, 15]))
        );
        assert!(config.postgres_client_identity_paths.is_some());
    }
}
