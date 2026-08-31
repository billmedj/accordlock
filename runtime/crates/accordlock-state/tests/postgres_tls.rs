use std::env;
use std::fs;
use std::io;
use std::net::IpAddr;
use std::time::Duration;

use accordlock_state::{TlsPostgresConfig, TlsPostgresStore};

fn required(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(env::var(name)?)
}

#[test]
#[ignore = "requires a disposable TLS PostgreSQL server configured for SCRAM-SHA-256-PLUS"]
fn tls_postgres_migrates_and_validates_over_an_authenticated_connection()
-> Result<(), Box<dyn std::error::Error>> {
    let server_name = required("ACCORDLOCK_TEST_POSTGRES_TLS_SERVER_NAME")?;
    let database = required("ACCORDLOCK_TEST_POSTGRES_TLS_DATABASE")?;
    let user = required("ACCORDLOCK_TEST_POSTGRES_TLS_USER")?;
    let password = required("ACCORDLOCK_TEST_POSTGRES_TLS_PASSWORD")?;
    let ca_pem = fs::read(required("ACCORDLOCK_TEST_POSTGRES_TLS_CA_FILE")?)?;

    let mut config =
        TlsPostgresConfig::new(server_name, database, user, password.as_bytes(), ca_pem)?;
    if let Ok(port) = env::var("ACCORDLOCK_TEST_POSTGRES_TLS_PORT") {
        config = config.with_port(port.parse::<u16>()?)?;
    }
    if let Ok(seconds) = env::var("ACCORDLOCK_TEST_POSTGRES_TLS_CONNECT_TIMEOUT_SECONDS") {
        config = config.with_connect_timeout(Duration::from_secs(seconds.parse::<u64>()?))?;
    }
    if let Ok(address) = env::var("ACCORDLOCK_TEST_POSTGRES_TLS_TARGET_ADDRESS") {
        config = config.with_target_address(address.parse::<IpAddr>()?);
    }

    let client_certificate_file = env::var("ACCORDLOCK_TEST_POSTGRES_TLS_CLIENT_CERT_FILE").ok();
    let client_key_file = env::var("ACCORDLOCK_TEST_POSTGRES_TLS_CLIENT_KEY_FILE").ok();
    config = match (client_certificate_file, client_key_file) {
        (None, None) => config,
        (Some(certificate_file), Some(key_file)) => {
            config.with_client_identity(fs::read(certificate_file)?, fs::read(key_file)?)?
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "client certificate and key files must be configured together",
            )
            .into());
        }
    };

    let store = TlsPostgresStore::new(config)?;
    store.migrate()?;
    store.validate_schema()?;
    assert!(!store.state_instance_id()?.is_nil());
    Ok(())
}
