use std::{
    io::{BufRead, BufReader, Read, Write},
    process::{Child, Command, ExitStatus, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use accordlock_agent_protocol::Digest32;
use accordlock_agent_runtime::{
    ApprovedSession, CONTROL_CHANNEL_SCHEMA_VERSION, CONTROL_FRAME_MAGIC, Capability,
    MAX_CONTROL_FRAME_BYTES, SessionRevocation, TaskPolicy,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use uuid::Uuid;

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

fn write_control_frame(
    input: &mut impl Write,
    value: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let body = serde_json::to_vec(value)?;
    if body.len() > MAX_CONTROL_FRAME_BYTES {
        return Err("fixture exceeds control-channel frame bound".into());
    }
    input.write_all(&CONTROL_FRAME_MAGIC)?;
    input.write_all(&u32::try_from(body.len())?.to_be_bytes())?;
    input.write_all(&body)?;
    input.flush()?;
    Ok(())
}

fn read_control_frame(input: &mut impl Read) -> Result<Value, Box<dyn std::error::Error>> {
    let mut header = [0_u8; 8];
    input.read_exact(&mut header)?;
    if header[..4] != CONTROL_FRAME_MAGIC {
        return Err("control response magic changed".into());
    }
    let response_length = u32::from_be_bytes(header[4..].try_into()?) as usize;
    if response_length > MAX_CONTROL_FRAME_BYTES {
        return Err("control response exceeds bounded profile".into());
    }
    let mut response = vec![0_u8; response_length];
    input.read_exact(&mut response)?;
    Ok(serde_json::from_slice(&response)?)
}

struct ChildGuard {
    child: Child,
    waited: bool,
}

impl ChildGuard {
    fn wait(&mut self) -> std::io::Result<ExitStatus> {
        let status = self.child.wait()?;
        self.waited = true;
        Ok(status)
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.waited {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn assert_readiness(input: &mut impl BufRead) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(CONTROL_CHANNEL_SCHEMA_VERSION, 2);
    let mut readiness = String::new();
    input.read_line(&mut readiness)?;
    let ready_json = readiness
        .strip_prefix("ACCORDLOCK_RUNTIME_READY=")
        .ok_or("readiness prefix changed")?
        .strip_suffix('\n')
        .ok_or("readiness newline missing")?
        .trim_end_matches('\r');
    let ready: Value = serde_json::from_str(ready_json)?;
    assert_eq!(ready["schema_version"], CONTROL_CHANNEL_SCHEMA_VERSION);
    assert!(
        ready["url"]
            .as_str()
            .is_some_and(|url| url.starts_with("http://127.0.0.1:"))
    );
    Ok(())
}

fn approve(
    input: &mut impl Write,
    output: &mut impl Read,
    approval: &ApprovedSession,
) -> Result<Value, Box<dyn std::error::Error>> {
    let request_id = Uuid::new_v4();
    write_control_frame(
        input,
        &json!({
            "schema_version": 2,
            "request_id": request_id.to_string(),
            "method": "APPROVE_SESSION",
            "approved_session": &approval,
        }),
    )?;
    let response = read_control_frame(output)?;
    assert_eq!(response["schema_version"], CONTROL_CHANNEL_SCHEMA_VERSION);
    assert_eq!(response["request_id"], request_id.to_string());
    assert_eq!(response["status"], "ACK");
    assert_eq!(response["code"], "SESSION_APPROVED");
    assert!(
        response["approval_digest"]
            .as_str()
            .is_some_and(|digest| digest.starts_with("sha256:") && digest.len() == 71)
    );
    Ok(response)
}

fn revoke(
    input: &mut impl Write,
    output: &mut impl Read,
    revocation: &SessionRevocation,
) -> Result<Value, Box<dyn std::error::Error>> {
    let request_id = Uuid::new_v4();
    write_control_frame(
        input,
        &json!({
            "schema_version": 2,
            "request_id": request_id.to_string(),
            "method": "REVOKE_SESSION",
            "session_revocation": revocation,
        }),
    )?;
    let response = read_control_frame(output)?;
    assert_eq!(response["request_id"], request_id.to_string());
    assert_eq!(response["status"], "ACK");
    assert_eq!(response["task_id"], revocation.task_id.to_string());
    assert_eq!(response["session_id"], revocation.session_id);
    assert_eq!(response["run_id"], revocation.run_id);
    Ok(response)
}

fn audit(
    input: &mut impl Write,
    output: &mut impl Read,
    session_id: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let request_id = Uuid::new_v4();
    write_control_frame(
        input,
        &json!({
            "schema_version": 2,
            "request_id": request_id.to_string(),
            "method": "GET_SESSION_AUDIT",
            "audit_query": {
                "schema_version": 2,
                "session_id": session_id,
                "offset": 0,
                "limit": 10,
                "snapshot_revision": null,
            },
        }),
    )?;
    let response = read_control_frame(output)?;
    assert_eq!(response["schema_version"], CONTROL_CHANNEL_SCHEMA_VERSION);
    assert_eq!(response["request_id"], request_id.to_string());
    Ok(response)
}

#[test]
fn binary_preserves_readiness_then_serves_private_control_frames()
-> Result<(), Box<dyn std::error::Error>> {
    let root = TempDir::new()?;
    let data = root.path().join("data");
    let workspace = root.path().join("workspace");
    std::fs::create_dir(&data)?;
    std::fs::create_dir(&workspace)?;
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    let approval = ApprovedSession::new_with_task_objective(
        Uuid::new_v4(),
        "desktop-session",
        "desktop-run",
        &workspace,
        1,
        "approved task policy",
        TaskPolicy::new(
            Digest32::sha256(b"approved task policy"),
            [],
            [".accordlock".to_owned()],
        )?,
        [Capability::new("developer", "write")],
        now.saturating_sub(1),
        now.saturating_add(300),
    )?;
    let revocation = SessionRevocation::new(
        approval.task_id,
        approval.session_id.clone(),
        approval.run_id.clone(),
    );

    let child = Command::new(env!("CARGO_BIN_EXE_accordlock-agent-runtime"))
        .args([
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            "--ready-line",
            "--control-stdio",
        ])
        .env("ACCORDLOCK_RUNTIME_TOKEN", TOKEN)
        .env("ACCORDLOCK_RUNTIME_DATA_DIR", &data)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut child = ChildGuard {
        child,
        waited: false,
    };
    let stdout = child.child.stdout.take().ok_or("stdout pipe unavailable")?;
    let mut stdout = BufReader::new(stdout);
    assert_readiness(&mut stdout)?;

    let mut stdin = child.child.stdin.take().ok_or("stdin pipe unavailable")?;
    approve(&mut stdin, &mut stdout, &approval)?;
    let revoked = revoke(&mut stdin, &mut stdout, &revocation)?;
    assert_eq!(revoked["code"], "SESSION_REVOKED");
    assert!(
        revoked["revocation_digest"]
            .as_str()
            .is_some_and(|digest| digest.starts_with("sha256:") && digest.len() == 71)
    );

    let retry = revoke(&mut stdin, &mut stdout, &revocation)?;
    assert_eq!(retry["code"], "SESSION_ALREADY_REVOKED");
    assert_eq!(retry["revocation_digest"], revoked["revocation_digest"]);
    assert_eq!(retry["task_id"], revoked["task_id"]);
    assert_eq!(retry["session_id"], revoked["session_id"]);
    assert_eq!(retry["run_id"], revoked["run_id"]);

    drop(stdin);

    let status = child.wait()?;
    assert!(status.success());
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn historical_audit_process_reopens_a_stopped_runtime_without_write_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let root = TempDir::new()?;
    let data = root.path().join("data");
    let workspace = root.path().join("workspace");
    std::fs::create_dir(&data)?;
    std::fs::create_dir(&workspace)?;
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    let approval = ApprovedSession::new_with_task_objective(
        Uuid::new_v4(),
        "restart-audit-session",
        "restart-audit-run",
        &workspace,
        1,
        "restart audit task",
        TaskPolicy::new(Digest32::sha256(b"restart audit task"), [], [])?,
        [Capability::new("developer", "read")],
        now.saturating_sub(1),
        now.saturating_add(300),
    )?;

    let writer = Command::new(env!("CARGO_BIN_EXE_accordlock-agent-runtime"))
        .args([
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            "--ready-line",
            "--control-stdio",
        ])
        .env("ACCORDLOCK_RUNTIME_TOKEN", TOKEN)
        .env("ACCORDLOCK_RUNTIME_DATA_DIR", &data)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut writer = ChildGuard {
        child: writer,
        waited: false,
    };
    let writer_stdout = writer
        .child
        .stdout
        .take()
        .ok_or("writer stdout unavailable")?;
    let mut writer_stdout = BufReader::new(writer_stdout);
    assert_readiness(&mut writer_stdout)?;
    let mut writer_stdin = writer
        .child
        .stdin
        .take()
        .ok_or("writer stdin unavailable")?;
    approve(&mut writer_stdin, &mut writer_stdout, &approval)?;
    drop(writer_stdin);
    assert!(writer.wait()?.success());

    let reader = Command::new(env!("CARGO_BIN_EXE_accordlock-agent-runtime"))
        .args(["audit", "--control-stdio"])
        .env_remove("ACCORDLOCK_RUNTIME_TOKEN")
        .env("ACCORDLOCK_RUNTIME_DATA_DIR", &data)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut reader = ChildGuard {
        child: reader,
        waited: false,
    };
    let mut reader_stdin = reader
        .child
        .stdin
        .take()
        .ok_or("reader stdin unavailable")?;
    let mut reader_stdout = reader
        .child
        .stdout
        .take()
        .ok_or("reader stdout unavailable")?;

    let page = audit(&mut reader_stdin, &mut reader_stdout, &approval.session_id)?;
    assert_eq!(page["status"], "ACK");
    assert_eq!(page["code"], "SESSION_AUDIT_READY");
    assert_eq!(page["page"]["task_id"], approval.task_id.to_string());
    assert_eq!(page["page"]["session_id"], approval.session_id);
    assert_eq!(page["page"]["run_id"], approval.run_id);
    assert_eq!(page["page"]["total_events"], 1);

    let unknown = audit(&mut reader_stdin, &mut reader_stdout, "unknown-session")?;
    assert_eq!(unknown["status"], "ERROR");
    assert_eq!(unknown["code"], "UNKNOWN_SESSION");
    assert!(unknown["page"].is_null());

    let mutation_id = Uuid::new_v4();
    write_control_frame(
        &mut reader_stdin,
        &json!({
            "schema_version": 2,
            "request_id": mutation_id.to_string(),
            "method": "APPROVE_SESSION",
            "approved_session": &approval,
        }),
    )?;
    let denied_mutation = read_control_frame(&mut reader_stdout)?;
    assert_eq!(denied_mutation["request_id"], mutation_id.to_string());
    assert_eq!(denied_mutation["status"], "ERROR");
    assert_eq!(denied_mutation["code"], "MALFORMED_REQUEST");
    assert!(denied_mutation["page"].is_null());

    let unchanged = audit(&mut reader_stdin, &mut reader_stdout, &approval.session_id)?;
    assert_eq!(unchanged["page"]["total_events"], 1);
    drop(reader_stdin);
    assert!(reader.wait()?.success());
    Ok(())
}
