#![forbid(unsafe_code)]

use std::{
    error::Error,
    ffi::OsString,
    fs, future,
    io::{self, Write as _},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    thread,
};

use accordlock_agent_runtime::{
    ControlChannelError, ControlChannelExit, DESKTOP_PROTOCOL_SCHEMA_VERSION, HttpsEgressPolicy,
    HttpsMethod, Ledger, Runtime, RuntimeConfig, WebPkiHttpsEgress, serve_audit_control_channel,
    serve_connection_test_request, serve_control_channel, serve_review_notification_request,
};
use clap::{Parser, Subcommand};
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

const TOKEN_ENV: &str = "ACCORDLOCK_RUNTIME_TOKEN";
const DATA_DIR_ENV: &str = "ACCORDLOCK_RUNTIME_DATA_DIR";
const NOTIFICATION_DATA_DIR_ENV: &str = "ACCORDLOCK_NOTIFICATION_DATA_DIR";
const DATABASE_FILENAME: &str = "agent-runtime.sqlite3";

#[derive(Debug, Parser)]
#[command(name = "accordlock-agent-runtime", disable_help_subcommand = true)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the trusted loopback governance runtime.
    Serve {
        #[arg(long)]
        host: IpAddr,
        #[arg(long)]
        port: u16,
        #[arg(long)]
        ready_line: bool,
        /// Reserve inherited stdin/stdout as the trusted Desktop control channel.
        #[arg(long)]
        control_stdio: bool,
        /// Trusted `alias=sha256:digest=absolute-executable` terminal binding. Repeatable.
        #[arg(long = "terminal-program")]
        terminal_programs: Vec<String>,
        /// Exact lowercase public DNS name allowed for governed HTTPS GET/HEAD. Repeatable.
        #[arg(long = "https-domain")]
        https_domains: Vec<String>,
    },
    /// Read one existing execution log through the bounded audit-only channel.
    Audit {
        /// Reserve inherited stdin/stdout for audit requests only.
        #[arg(long)]
        control_stdio: bool,
    },
    /// Send one display-only Approval Center notification batch.
    Notify {
        /// Read exactly one bounded ALN1 request from inherited stdin.
        #[arg(long)]
        request_stdio: bool,
    },
    /// Send one fixed channel connection test.
    TestNotification {
        /// Read exactly one bounded ALT1 request from inherited stdin.
        #[arg(long)]
        request_stdio: bool,
    },
}

#[derive(Serialize)]
struct ReadyRecord {
    schema_version: u16,
    url: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    match Arguments::parse().command {
        Command::Serve {
            host,
            port,
            ready_line,
            control_stdio,
            terminal_programs,
            https_domains,
        } => {
            serve(
                host,
                port,
                ready_line,
                control_stdio,
                &terminal_programs,
                &https_domains,
            )
            .await
        }
        Command::Audit { control_stdio } => audit(control_stdio),
        Command::Notify { request_stdio } => notify(request_stdio),
        Command::TestNotification { request_stdio } => test_notification(request_stdio),
    }
}

fn test_notification(request_stdio: bool) -> Result<(), Box<dyn Error>> {
    if !request_stdio {
        return Err("notification test requires the inherited request pipe".into());
    }
    let stdin = io::stdin();
    let report = serve_connection_test_request(stdin.lock())?;
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, &report)?;
    writeln!(stdout)?;
    stdout.flush()?;
    Ok(())
}

fn notify(request_stdio: bool) -> Result<(), Box<dyn Error>> {
    if !request_stdio {
        return Err(
            "display-only notification dispatch requires the inherited request pipe".into(),
        );
    }
    let data_directory = secure_data_directory(required_environment(NOTIFICATION_DATA_DIR_ENV)?)?;
    let stdin = io::stdin();
    let report = serve_review_notification_request(stdin.lock(), &data_directory)?;
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, &report)?;
    writeln!(stdout)?;
    stdout.flush()?;
    Ok(())
}

fn audit(control_stdio: bool) -> Result<(), Box<dyn Error>> {
    if !control_stdio {
        return Err("historical audit requires the inherited control channel".into());
    }
    let data_directory = secure_existing_data_directory(required_environment(DATA_DIR_ENV)?)?;
    let database_path = data_directory.join(DATABASE_FILENAME);
    require_regular_file(&database_path)?;
    let ledger = Ledger::open_read_only(&database_path)?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    match serve_audit_control_channel(&ledger, stdin.lock(), stdout.lock())? {
        ControlChannelExit::ParentClosed => Ok(()),
    }
}

async fn serve(
    host: IpAddr,
    port: u16,
    ready_line: bool,
    control_stdio: bool,
    terminal_programs: &[String],
    https_domains: &[String],
) -> Result<(), Box<dyn Error>> {
    if host != IpAddr::V4(Ipv4Addr::LOCALHOST) {
        return Err("runtime host must be the literal IPv4 loopback 127.0.0.1".into());
    }
    let token = required_unicode_environment(TOKEN_ENV)?;
    let data_directory = secure_data_directory(required_environment(DATA_DIR_ENV)?)?;
    let database_path = data_directory.join(DATABASE_FILENAME);
    reject_symlink_if_present(&database_path)?;
    let mut config = RuntimeConfig::for_accordlock_desktop(&token)?;
    for binding in terminal_programs {
        let (alias, digest, executable) = parse_terminal_program_binding(binding)?;
        config = config.with_terminal_program_digest(alias, Path::new(executable), digest)?;
    }
    let mut runtime = Runtime::from_ledger(Ledger::open(&database_path)?, config);
    if !https_domains.is_empty() {
        let policy = HttpsEgressPolicy::new(
            "accordlock-desktop-readonly-v1",
            https_domains.iter().cloned(),
            [HttpsMethod::Get, HttpsMethod::Head],
            0,
            256 * 1024,
        )?;
        runtime = runtime.with_https_egress(Arc::new(WebPkiHttpsEgress::new(policy)?))?;
    }
    let listener = TcpListener::bind(SocketAddr::new(host, port)).await?;
    let address = listener.local_addr()?;
    if address.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) || address.port() == 0 {
        return Err("runtime listener did not acquire a valid IPv4 loopback port".into());
    }

    if ready_line {
        let record = ReadyRecord {
            schema_version: DESKTOP_PROTOCOL_SCHEMA_VERSION,
            url: format!("http://127.0.0.1:{}", address.port()),
        };
        let encoded = serde_json::to_string(&record)?;
        let mut stdout = io::stdout().lock();
        writeln!(stdout, "ACCORDLOCK_RUNTIME_READY={encoded}")?;
        stdout.flush()?;
    }

    if control_stdio {
        let completion = start_control_channel(runtime.clone())?;
        let server = runtime.serve_until(listener, future::pending());
        tokio::pin!(server);
        tokio::select! {
            result = &mut server => result?,
            _ = tokio::signal::ctrl_c() => {},
            result = completion => match result {
                Ok(Ok(ControlChannelExit::ParentClosed)) => {},
                Ok(Err(error)) => return Err(error.into()),
                Err(_) => return Err("control channel terminated without a result".into()),
            },
        }
    } else {
        runtime
            .serve_until(listener, async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await?;
    }
    Ok(())
}

fn parse_terminal_program_binding(binding: &str) -> Result<(&str, &str, &str), &'static str> {
    let mut fields = binding.splitn(3, '=');
    let alias = fields.next().unwrap_or_default();
    let digest = fields.next().unwrap_or_default();
    let executable = fields.next().unwrap_or_default();
    if alias.is_empty()
        || executable.is_empty()
        || !digest.starts_with("sha256:")
        || digest.len() != "sha256:".len() + 64
        || !digest["sha256:".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("terminal program must use alias=sha256:<lowercase-hex>=absolute-executable");
    }
    Ok((alias, digest, executable))
}

fn start_control_channel(
    runtime: Runtime,
) -> Result<oneshot::Receiver<Result<ControlChannelExit, ControlChannelError>>, io::Error> {
    let (sender, receiver) = oneshot::channel();
    thread::Builder::new()
        .name("accordlock-control-stdio".to_owned())
        .spawn(move || {
            let stdin = io::stdin();
            let stdout = io::stdout();
            let result = serve_control_channel(&runtime, stdin.lock(), stdout.lock());
            let _ = sender.send(result);
        })?;
    Ok(receiver)
}

fn required_environment(name: &str) -> Result<OsString, Box<dyn Error>> {
    std::env::var_os(name).ok_or_else(|| format!("required environment is missing: {name}").into())
}

fn required_unicode_environment(name: &str) -> Result<String, Box<dyn Error>> {
    required_environment(name)?
        .into_string()
        .map_err(|_| format!("required environment is not Unicode: {name}").into())
}

fn secure_data_directory(value: OsString) -> Result<PathBuf, Box<dyn Error>> {
    let requested = PathBuf::from(value);
    if requested.as_os_str().is_empty() || !requested.is_absolute() {
        return Err("runtime data directory must be a nonempty absolute path".into());
    }
    if let Ok(metadata) = fs::symlink_metadata(&requested) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("runtime data directory must be a real directory".into());
        }
    } else {
        fs::create_dir_all(&requested)?;
    }
    let canonical = fs::canonicalize(&requested)?;
    let metadata = fs::symlink_metadata(&canonical)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("runtime data directory is not trustworthy".into());
    }
    Ok(canonical)
}

fn secure_existing_data_directory(value: OsString) -> Result<PathBuf, Box<dyn Error>> {
    let requested = PathBuf::from(value);
    if requested.as_os_str().is_empty() || !requested.is_absolute() {
        return Err("historical runtime data directory must be a nonempty absolute path".into());
    }
    let metadata = fs::symlink_metadata(&requested)
        .map_err(|_| "historical runtime data directory is unavailable")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("historical runtime data directory must be a real directory".into());
    }
    let canonical = fs::canonicalize(&requested)?;
    let canonical_metadata = fs::symlink_metadata(&canonical)?;
    if canonical_metadata.file_type().is_symlink() || !canonical_metadata.is_dir() {
        return Err("historical runtime data directory is not trustworthy".into());
    }
    Ok(canonical)
}

fn reject_symlink_if_present(path: &Path) -> Result<(), Box<dyn Error>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err("runtime database path is not a regular file".into())
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn require_regular_file(path: &Path) -> Result<(), Box<dyn Error>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err("historical runtime database path is not a regular file".into())
        }
        Ok(_) => Ok(()),
        Err(_) => Err("historical runtime database is unavailable".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_program_binding_is_exact_and_windows_paths_keep_their_colon() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let binding = format!("probe={digest}=C:\\Program Files\\Probe\\probe.exe");

        assert_eq!(
            parse_terminal_program_binding(&binding),
            Ok((
                "probe",
                digest.as_str(),
                "C:\\Program Files\\Probe\\probe.exe"
            ))
        );
    }

    #[test]
    fn terminal_program_binding_rejects_unpinned_or_noncanonical_digests() {
        for invalid in [
            "probe=C:\\probe.exe".to_owned(),
            format!("probe=sha256:{}=C:\\probe.exe", "A".repeat(64)),
            format!("probe=sha256:{}=", "a".repeat(64)),
        ] {
            assert!(
                parse_terminal_program_binding(&invalid).is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn serve_cli_accepts_only_explicit_repeatable_https_domains()
    -> Result<(), Box<dyn std::error::Error>> {
        let parsed = Arguments::try_parse_from([
            "accordlock-agent-runtime",
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            "--https-domain",
            "api.example.com",
            "--https-domain",
            "status.example.com",
        ])?;
        let Command::Serve { https_domains, .. } = parsed.command else {
            return Err("expected serve command".into());
        };
        assert_eq!(https_domains, ["api.example.com", "status.example.com"]);
        Ok(())
    }
}
