#![allow(clippy::panic, clippy::too_many_lines, clippy::unwrap_used)]

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use accordlock_cli::live_k8s::{LiveK8sSession, LiveK8sValidation, LiveStateBackend};
use accordlock_state::{ConsumeKey, OutboxStatus, PostgresStore, Scope, TransactionalState};
use uuid::Uuid;

const NEW_IMAGE: &str = "docker.io/library/nginx@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236";

#[test]
fn postgres_mode_fails_closed_without_trusted_configuration() {
    let executable = env!("CARGO_BIN_EXE_accordlock");
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("deployment.json");
    let session_path =
        env::temp_dir().join(format!("accordlock-cli-missing-pg-{}.json", Uuid::new_v4()));
    let output = Command::new(executable)
        .args([
            "live",
            "prepare",
            "--deployment",
            fixture.to_str().unwrap(),
            "--new-image",
            NEW_IMAGE,
            "--state-backend",
            "postgres",
            "--session-out",
            session_path.to_str().unwrap(),
        ])
        .env_remove("ACCORDLOCK_LIVE_POSTGRES_URL")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("ACCORDLOCK_LIVE_POSTGRES_URL"));
    assert!(!session_path.exists());
}

#[test]
#[ignore = "requires ACCORDLOCK_TEST_POSTGRES_URL pointing to a disposable database"]
fn cli_postgres_prepare_and_validate_reverify_durable_state() {
    let connection_string = env::var("ACCORDLOCK_TEST_POSTGRES_URL")
        .unwrap_or_else(|_| panic!("ACCORDLOCK_TEST_POSTGRES_URL is required"));
    let executable = env!("CARGO_BIN_EXE_accordlock");
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("deployment.json");
    let temporary = env::temp_dir().join(format!("accordlock-cli-pg-{}", Uuid::new_v4()));
    fs::create_dir(&temporary).unwrap();
    let session_path = temporary.join("session.json");
    let after_path = temporary.join("after.json");

    let prepare = Command::new(executable)
        .args([
            "live",
            "prepare",
            "--deployment",
            fixture.to_str().unwrap(),
            "--new-image",
            NEW_IMAGE,
            "--state-backend",
            "postgres",
            "--postgres-url-env",
            "ACCORDLOCK_TEST_POSTGRES_URL",
            "--migrate-postgres",
            "--session-out",
            session_path.to_str().unwrap(),
        ])
        .env("ACCORDLOCK_TEST_POSTGRES_URL", &connection_string)
        .output()
        .unwrap();
    assert!(
        prepare.status.success(),
        "{}",
        String::from_utf8_lossy(&prepare.stderr)
    );
    assert!(!String::from_utf8_lossy(&prepare.stdout).contains(&connection_string));
    assert!(!String::from_utf8_lossy(&prepare.stderr).contains(&connection_string));

    let session: LiveK8sSession =
        serde_json::from_slice(&fs::read(&session_path).unwrap()).unwrap();
    assert_eq!(session.state_backend, LiveStateBackend::PostgreSql);
    assert!(session.durable_consumption);
    assert_eq!(
        session.execution_outbox_status,
        OutboxStatus::PendingWitness
    );
    let key = ConsumeKey {
        scope: Scope::new(
            &session.consumption_receipt_ref.tenant,
            &session.consumption_receipt_ref.environment,
        )
        .unwrap(),
        transaction_id: session.consumption_receipt_ref.transaction_id,
        authorization_id: session.consumption_receipt_ref.authorization_id,
    };
    let store = PostgresStore::new(connection_string.clone());
    assert_eq!(
        session.state_instance_id,
        Some(store.state_instance_id().unwrap())
    );
    assert_eq!(
        store.consumption_receipt(&key).unwrap(),
        session.consumption_receipt
    );

    let mut after = session.before_deployment.clone();
    let template = &session.signed_authorization.authorization.template;
    let image_path = format!(
        "/spec/template/spec/containers/{}/image",
        template.container_index
    );
    *after.pointer_mut(&image_path).unwrap() = serde_json::Value::String(format!(
        "{}@{}",
        template.image_repository, template.image_digest
    ));
    let annotations = after["metadata"]["annotations"].as_object_mut().unwrap();
    annotations.insert(
        "accordlock.io/transaction-id".to_owned(),
        serde_json::Value::String(session.transaction_id.to_string()),
    );
    annotations.insert(
        "accordlock.io/authorization-id".to_owned(),
        serde_json::Value::String(
            session
                .signed_authorization
                .authorization
                .authorization_id
                .to_string(),
        ),
    );
    annotations.insert(
        "accordlock.io/operation-hash".to_owned(),
        serde_json::Value::String(session.prepared_patch.operation_hash.to_string()),
    );
    after["metadata"]["resourceVersion"] = serde_json::Value::String("1235".to_owned());
    after["metadata"]["generation"] = serde_json::json!(2);
    fs::write(&after_path, serde_json::to_vec_pretty(&after).unwrap()).unwrap();

    let validate = Command::new(executable)
        .args([
            "live",
            "validate",
            "--session",
            session_path.to_str().unwrap(),
            "--after",
            after_path.to_str().unwrap(),
            "--state-backend",
            "postgres",
            "--postgres-url-env",
            "ACCORDLOCK_TEST_POSTGRES_URL",
            "--compact",
        ])
        .env("ACCORDLOCK_TEST_POSTGRES_URL", &connection_string)
        .output()
        .unwrap();
    assert!(
        validate.status.success(),
        "{}",
        String::from_utf8_lossy(&validate.stderr)
    );
    assert!(!String::from_utf8_lossy(&validate.stdout).contains(&connection_string));
    assert!(!String::from_utf8_lossy(&validate.stderr).contains(&connection_string));
    let report: LiveK8sValidation = serde_json::from_slice(&validate.stdout).unwrap();
    assert!(report.state_records_reverified);
    assert!(report.durable_consumption);

    fs::remove_file(session_path).unwrap();
    fs::remove_file(after_path).unwrap();
    fs::remove_dir(temporary).unwrap();
}
