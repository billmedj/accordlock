use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::Command;

use accordlock_cli::live_k8s::LiveK8sSession;
use serde_json::{Value, json};
use uuid::Uuid;

const NEW_IMAGE: &str = "docker.io/library/nginx@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236";

#[test]
fn prepare_writes_the_exact_committed_patch_body() -> Result<(), Box<dyn Error>> {
    let executable = env!("CARGO_BIN_EXE_accordlock");
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("deployment.json");
    let temporary = env::temp_dir().join(format!("accordlock-cli-k8s-{}", Uuid::new_v4()));
    fs::create_dir(&temporary)?;
    let session_path = temporary.join("session.json");
    let patch_path = temporary.join("patch.json");
    let fixture_text = fixture
        .to_str()
        .ok_or_else(|| io::Error::other("fixture path is not UTF-8"))?;
    let session_text = session_path
        .to_str()
        .ok_or_else(|| io::Error::other("session path is not UTF-8"))?;
    let patch_text = patch_path
        .to_str()
        .ok_or_else(|| io::Error::other("patch path is not UTF-8"))?;

    let output = Command::new(executable)
        .args([
            "live",
            "prepare",
            "--deployment",
            fixture_text,
            "--new-image",
            NEW_IMAGE,
            "--session-out",
            session_text,
            "--patch-out",
            patch_text,
        ])
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let session: LiveK8sSession = serde_json::from_slice(&fs::read(&session_path)?)?;
    let actual = fs::read(&patch_path)?;
    let expected = accordlock_k8s::patch_wire_body(&session.prepared_patch)?;
    assert_eq!(actual, expected);
    assert!(!actual.ends_with(b"\n"));

    let mismatched_backend = Command::new(executable)
        .args([
            "live",
            "validate",
            "--session",
            session_text,
            "--after",
            fixture_text,
            "--state-backend",
            "postgres",
        ])
        .env_remove("ACCORDLOCK_LIVE_POSTGRES_URL")
        .output()?;
    assert!(!mismatched_backend.status.success());
    assert!(
        String::from_utf8_lossy(&mismatched_backend.stderr)
            .contains("does not match trusted --state-backend")
    );

    fs::remove_file(session_path)?;
    fs::remove_file(patch_path)?;
    fs::remove_dir(temporary)?;
    Ok(())
}

#[test]
fn validate_effect_requires_and_checks_replica_set_snapshot() -> Result<(), Box<dyn Error>> {
    let executable = env!("CARGO_BIN_EXE_accordlock");
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures");
    let deployment_path = fixtures.join("deployment.json");
    let replica_sets_path = fixtures.join("replica-sets.json");
    let pods_path = fixtures.join("pods.json");
    let temporary = env::temp_dir().join(format!("accordlock-cli-effect-{}", Uuid::new_v4()));
    fs::create_dir(&temporary)?;
    let session_path = temporary.join("session.json");
    let persisted_path = temporary.join("persisted.json");
    let eventual_path = temporary.join("eventual.json");

    let prepare = Command::new(executable)
        .args(["live", "prepare", "--deployment"])
        .arg(&deployment_path)
        .args(["--new-image", NEW_IMAGE, "--session-out"])
        .arg(&session_path)
        .output()?;
    assert!(
        prepare.status.success(),
        "{}",
        String::from_utf8_lossy(&prepare.stderr)
    );
    let session: LiveK8sSession = serde_json::from_slice(&fs::read(&session_path)?)?;
    let mut persisted: Value = serde_json::from_slice(&fs::read(&deployment_path)?)?;
    let template = &session.signed_authorization.authorization.template;
    persisted["spec"]["template"]["spec"]["containers"][0]["image"] = Value::String(format!(
        "{}@{}",
        template.image_repository, template.image_digest
    ));
    persisted["metadata"]["annotations"]["accordlock.io/transaction-id"] =
        Value::String(session.transaction_id.to_string());
    persisted["metadata"]["annotations"]["accordlock.io/authorization-id"] = Value::String(
        session
            .signed_authorization
            .authorization
            .authorization_id
            .to_string(),
    );
    persisted["metadata"]["annotations"]["accordlock.io/operation-hash"] =
        Value::String(session.prepared_patch.operation_hash.to_string());
    persisted["metadata"]["resourceVersion"] = Value::String("1235".to_owned());
    persisted["metadata"]["generation"] = json!(2);
    fs::write(&persisted_path, serde_json::to_vec(&persisted)?)?;

    let mut eventual = persisted.clone();
    eventual["metadata"]["resourceVersion"] = Value::String("1240".to_owned());
    eventual["metadata"]["managedFields"] = json!([{"manager":"kube-controller-manager"}]);
    eventual["metadata"]["annotations"]["deployment.kubernetes.io/revision"] =
        Value::String("2".to_owned());
    eventual["status"] = json!({
        "observedGeneration":2,
        "replicas":1,
        "updatedReplicas":1,
        "readyReplicas":1,
        "availableReplicas":1
    });
    fs::write(&eventual_path, serde_json::to_vec(&eventual)?)?;

    let validated = Command::new(executable)
        .args(["live", "validate-effect", "--session"])
        .arg(&session_path)
        .arg("--persisted-response")
        .arg(&persisted_path)
        .arg("--after")
        .arg(&eventual_path)
        .arg("--replica-sets")
        .arg(&replica_sets_path)
        .arg("--pods")
        .arg(&pods_path)
        .args(["--state-backend", "in-memory"])
        .output()?;
    assert!(
        validated.status.success(),
        "{}",
        String::from_utf8_lossy(&validated.stderr)
    );
    let report: Value = serde_json::from_slice(&validated.stdout)?;
    assert_eq!(report["schema_version"], json!(2));
    assert_eq!(report["rollout_ownership_valid"], json!(true));

    let missing_replica_sets = Command::new(executable)
        .args(["live", "validate-effect", "--session"])
        .arg(&session_path)
        .arg("--persisted-response")
        .arg(&persisted_path)
        .arg("--after")
        .arg(&eventual_path)
        .arg("--pods")
        .arg(&pods_path)
        .args(["--state-backend", "in-memory"])
        .output()?;
    assert!(!missing_replica_sets.status.success());
    assert!(String::from_utf8_lossy(&missing_replica_sets.stderr).contains("--replica-sets"));

    fs::remove_file(session_path)?;
    fs::remove_file(persisted_path)?;
    fs::remove_file(eventual_path)?;
    fs::remove_dir(temporary)?;
    Ok(())
}
