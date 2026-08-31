use std::env;
use std::fs;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use serde::de::DeserializeOwned;

#[derive(Debug, Parser)]
#[command(
    name = "accordlock",
    about = "Deterministic local AccordLock conformance CLI",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the complete deterministic, credential-free offline security demo.
    Offline {
        /// One of: all, DP-000, DP-101, DP-102, DP-103.
        #[arg(long, default_value = "all")]
        scenario: String,
        /// Emit one-line JSON instead of pretty-printed JSON.
        #[arg(long)]
        compact: bool,
    },
    /// Execute synthetic differential scenarios. This is not a benchmark.
    Demo {
        /// One of: all, DP-000, DP-101, DP-102, DP-103.
        #[arg(long, default_value = "all")]
        scenario: String,
        /// Emit one-line JSON instead of pretty-printed JSON.
        #[arg(long)]
        compact: bool,
    },
    /// Exercise the fixed local kind/Kubernetes profile with test keys.
    Live {
        #[command(subcommand)]
        command: LiveCommand,
    },
}

#[derive(Debug, Subcommand)]
enum LiveCommand {
    /// Build and consume a signed session from a real Deployment snapshot.
    Prepare {
        /// Deployment JSON path, or '-' to read JSON from standard input.
        #[arg(long, default_value = "-")]
        deployment: String,
        /// Immutable replacement image as repository@sha256:<64 hex>.
        #[arg(long)]
        new_image: String,
        /// State adapter used for issuance and identifier-only consumption.
        #[arg(long, value_enum, default_value_t = LiveStateBackendArg::InMemory)]
        state_backend: LiveStateBackendArg,
        /// Name of the environment variable containing the trusted `PostgreSQL` URL.
        #[arg(long, default_value = "ACCORDLOCK_LIVE_POSTGRES_URL")]
        postgres_url_env: String,
        /// Explicitly apply the idempotent `PostgreSQL` schema migration.
        #[arg(long)]
        migrate_postgres: bool,
        /// Write the complete session to this path instead of standard output.
        #[arg(long)]
        session_out: Option<PathBuf>,
        /// Write the exact committed JSON Patch bytes to this path.
        #[arg(long)]
        patch_out: Option<PathBuf>,
        /// Emit one-line JSON instead of pretty-printed JSON.
        #[arg(long)]
        compact: bool,
    },
    /// Validate a server-side dry-run candidate before persistence.
    ValidateCandidate {
        /// Session JSON emitted by `live prepare`.
        #[arg(long)]
        session: PathBuf,
        /// Server-side dry-run candidate JSON, or '-' for standard input.
        #[arg(long)]
        candidate: String,
        /// Emit one-line JSON instead of pretty-printed JSON.
        #[arg(long)]
        compact: bool,
    },
    /// Re-verify a session and the persisted PATCH response Deployment.
    Validate {
        /// Session JSON emitted by `live prepare`.
        #[arg(long)]
        session: PathBuf,
        /// Persisted PATCH response JSON path, or '-' for standard input.
        #[arg(long)]
        after: String,
        /// Trusted state adapter expected for this validation.
        #[arg(long, value_enum)]
        state_backend: LiveStateBackendArg,
        /// Name of the environment variable used to reverify `PostgreSQL` state.
        #[arg(long, default_value = "ACCORDLOCK_LIVE_POSTGRES_URL")]
        postgres_url_env: String,
        /// Emit one-line JSON instead of pretty-printed JSON.
        #[arg(long)]
        compact: bool,
    },
    /// Validate the eventual Deployment, `ReplicaSets`, and Pods against the persisted response.
    ValidateEffect {
        /// Session JSON emitted by `live prepare`.
        #[arg(long)]
        session: PathBuf,
        /// Synchronous persisted PATCH response JSON.
        #[arg(long)]
        persisted_response: String,
        /// Eventual Deployment JSON observed after rollout.
        #[arg(long)]
        after: String,
        /// Exhaustive `ReplicaSet` list JSON observed for the Deployment selector.
        #[arg(long)]
        replica_sets: String,
        /// Pod list JSON observed after rollout.
        #[arg(long)]
        pods: String,
        /// Trusted state adapter expected for this validation.
        #[arg(long, value_enum)]
        state_backend: LiveStateBackendArg,
        /// Name of the environment variable used to reverify `PostgreSQL` state.
        #[arg(long, default_value = "ACCORDLOCK_LIVE_POSTGRES_URL")]
        postgres_url_env: String,
        /// Emit one-line JSON instead of pretty-printed JSON.
        #[arg(long)]
        compact: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum LiveStateBackendArg {
    InMemory,
    Postgres,
}

#[allow(clippy::too_many_lines)]
fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Offline { scenario, compact } | Command::Demo { scenario, compact }) => {
            write_json(&accordlock_cli::run_selection(&scenario)?, compact, None)
        }
        Some(Command::Live {
            command:
                LiveCommand::Prepare {
                    deployment,
                    new_image,
                    state_backend,
                    postgres_url_env,
                    migrate_postgres,
                    session_out,
                    patch_out,
                    compact,
                },
        }) => {
            let before = read_json_input(&deployment)?;
            let session = match state_backend {
                LiveStateBackendArg::InMemory => {
                    ensure!(
                        !migrate_postgres,
                        "--migrate-postgres requires --state-backend postgres"
                    );
                    accordlock_cli::live_k8s::prepare_live_session(before, &new_image)?
                }
                LiveStateBackendArg::Postgres => {
                    ensure!(
                        !postgres_url_env.trim().is_empty(),
                        "--postgres-url-env cannot be empty"
                    );
                    let connection_string = env::var(&postgres_url_env).with_context(|| {
                        format!(
                            "PostgreSQL state backend requires environment variable {postgres_url_env}"
                        )
                    })?;
                    if connection_string.trim().is_empty() {
                        bail!("environment variable {postgres_url_env} is empty");
                    }
                    accordlock_cli::live_k8s::prepare_live_session_postgres(
                        before,
                        &new_image,
                        &connection_string,
                        migrate_postgres,
                    )?
                }
            };
            if let (Some(session_path), Some(patch_path)) = (&session_out, &patch_out) {
                ensure!(
                    session_path != patch_path,
                    "--session-out and --patch-out must be different paths"
                );
            }
            if let Some(path) = patch_out.as_deref() {
                let body = accordlock_k8s::patch_wire_body(&session.prepared_patch)?;
                fs::write(path, body).with_context(|| {
                    format!("failed to write exact JSON Patch body {}", path.display())
                })?;
            }
            write_json(&session, compact, session_out.as_deref())
        }
        Some(Command::Live {
            command:
                LiveCommand::ValidateCandidate {
                    session,
                    candidate,
                    compact,
                },
        }) => {
            let session: accordlock_cli::live_k8s::LiveK8sSession = read_json_file(&session)?;
            let candidate = read_json_input(&candidate)?;
            let report = accordlock_cli::live_k8s::validate_live_candidate(&session, &candidate)?;
            write_json(&report, compact, None)
        }
        Some(Command::Live {
            command:
                LiveCommand::Validate {
                    session,
                    after,
                    state_backend,
                    postgres_url_env,
                    compact,
                },
        }) => {
            let session: accordlock_cli::live_k8s::LiveK8sSession = read_json_file(&session)?;
            let observed = read_json_input(&after)?;
            require_trusted_state_backend(&session, state_backend)?;
            let report = match state_backend {
                LiveStateBackendArg::InMemory => {
                    accordlock_cli::live_k8s::validate_live_session(&session, &observed)?
                }
                LiveStateBackendArg::Postgres => {
                    ensure!(
                        !postgres_url_env.trim().is_empty(),
                        "--postgres-url-env cannot be empty"
                    );
                    let connection_string = env::var(&postgres_url_env).with_context(|| {
                        format!(
                            "PostgreSQL state revalidation requires environment variable {postgres_url_env}"
                        )
                    })?;
                    if connection_string.trim().is_empty() {
                        bail!("environment variable {postgres_url_env} is empty");
                    }
                    accordlock_cli::live_k8s::validate_live_session_postgres(
                        &session,
                        &observed,
                        &connection_string,
                    )?
                }
            };
            write_json(&report, compact, None)
        }
        Some(Command::Live {
            command:
                LiveCommand::ValidateEffect {
                    session,
                    persisted_response,
                    after,
                    replica_sets,
                    pods,
                    state_backend,
                    postgres_url_env,
                    compact,
                },
        }) => {
            let session: accordlock_cli::live_k8s::LiveK8sSession = read_json_file(&session)?;
            let persisted_response = read_json_input(&persisted_response)?;
            let eventual = read_json_input(&after)?;
            let replica_sets = read_json_input(&replica_sets)?;
            let pods = read_json_input(&pods)?;
            require_trusted_state_backend(&session, state_backend)?;
            let report = match state_backend {
                LiveStateBackendArg::InMemory => accordlock_cli::live_k8s::validate_live_effect(
                    &session,
                    &persisted_response,
                    &eventual,
                    &replica_sets,
                    &pods,
                )?,
                LiveStateBackendArg::Postgres => {
                    let connection_string = trusted_connection_string(
                        &postgres_url_env,
                        "PostgreSQL state revalidation",
                    )?;
                    accordlock_cli::live_k8s::validate_live_effect_postgres(
                        &session,
                        &persisted_response,
                        &eventual,
                        &replica_sets,
                        &pods,
                        &connection_string,
                    )?
                }
            };
            write_json(&report, compact, None)
        }
        None => write_json(&accordlock_cli::run_selection("all")?, false, None),
    }
}

fn require_trusted_state_backend(
    session: &accordlock_cli::live_k8s::LiveK8sSession,
    expected: LiveStateBackendArg,
) -> Result<()> {
    let expected_session_backend = match expected {
        LiveStateBackendArg::InMemory => accordlock_cli::live_k8s::LiveStateBackend::InMemory,
        LiveStateBackendArg::Postgres => accordlock_cli::live_k8s::LiveStateBackend::PostgreSql,
    };
    ensure!(
        session.state_backend == expected_session_backend
            && session.durable_consumption == (expected == LiveStateBackendArg::Postgres),
        "session state backend does not match trusted --state-backend"
    );
    Ok(())
}

fn trusted_connection_string(environment_name: &str, purpose: &str) -> Result<String> {
    ensure!(
        !environment_name.trim().is_empty(),
        "--postgres-url-env cannot be empty"
    );
    let connection_string = env::var(environment_name)
        .with_context(|| format!("{purpose} requires environment variable {environment_name}"))?;
    if connection_string.trim().is_empty() {
        bail!("environment variable {environment_name} is empty");
    }
    Ok(connection_string)
}

fn read_json_input<T: DeserializeOwned>(source: &str) -> Result<T> {
    if source == "-" {
        let mut input = String::new();
        io::stdin()
            .read_to_string(&mut input)
            .context("failed to read JSON from standard input")?;
        serde_json::from_str(&input).context("standard input is not valid expected JSON")
    } else {
        read_json_file(Path::new(source))
    }
}

fn read_json_file<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let input = fs::read_to_string(path)
        .with_context(|| format!("failed to read JSON file {}", path.display()))?;
    serde_json::from_str(&input)
        .with_context(|| format!("{} is not valid expected JSON", path.display()))
}

fn write_json<T: Serialize>(value: &T, compact: bool, path: Option<&Path>) -> Result<()> {
    let mut output = if compact {
        serde_json::to_string(value)?
    } else {
        serde_json::to_string_pretty(value)?
    };
    output.push('\n');
    if let Some(path) = path {
        fs::write(path, output)
            .with_context(|| format!("failed to write JSON file {}", path.display()))
    } else {
        print!("{output}");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::{Parser as _, error::ErrorKind};

    #[test]
    fn public_cli_exposes_the_package_version() -> Result<(), &'static str> {
        let Err(error) = Cli::try_parse_from(["accordlock", "--version"]) else {
            return Err("--version did not produce clap's version response");
        };

        assert_eq!(error.kind(), ErrorKind::DisplayVersion);
        assert!(
            error
                .to_string()
                .starts_with(&format!("accordlock {}", env!("CARGO_PKG_VERSION")))
        );
        Ok(())
    }
}
