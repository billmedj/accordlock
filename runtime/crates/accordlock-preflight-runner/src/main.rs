#![forbid(unsafe_code)]

use std::{
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
    process::ExitCode,
};

use accordlock_preflight_runner::{
    EksEnrollmentEnvelope, EksEnrollmentResult, PreflightProfile, current_unix_seconds,
    discover_eks,
    model::{
        CredentialBundle, MAX_CREDENTIAL_BYTES, MAX_EKS_ENROLLMENT_INPUT_BYTES,
        MAX_EKS_ENROLLMENT_OUTPUT_BYTES, MAX_RECEIPT_BYTES, MAX_REQUEST_BYTES,
        PREFLIGHT_BUILD_MARKER_SCHEMA_VERSION, PREFLIGHT_PROTOCOL_VERSION,
        PREFLIGHT_SCHEMA_VERSION, PreflightCommand, PreflightRunnerBuildMarker,
        SignedPreflightReceipt,
    },
    run_preflight, verify_receipt,
};
use accordlock_protocol::Digest32;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand::{RngCore as _, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize as _, Zeroizing};

const MAX_PROFILE_BYTES: usize = 2 * 1024 * 1024;
const MAX_BINARY_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_LOCAL_CHECK_BYTES: usize = MAX_CREDENTIAL_BYTES + MAX_REQUEST_BYTES + 4 * 1024;
const INSTALLATION_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Parser)]
#[command(name = "accordlock-preflight-runner")]
#[command(about = "Read-only AccordLock deployment preflight runner")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run one preflight with command and credentials delivered through the
    /// inherited standard-input handle. No named secret endpoint is used.
    CheckStdio {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        state: PathBuf,
    },
    /// Verify a signed receipt from stdin against a pinned public profile.
    Verify {
        #[arg(long)]
        profile: PathBuf,
    },
    /// Validate a public profile and return its Rust-authoritative commitments.
    ProfileHash {
        #[arg(long)]
        profile: PathBuf,
    },
    /// Generate install-specific keys through the inherited standard-output
    /// handle. This command creates no named secret endpoint.
    InitInstallationStdio,
    /// Authenticate one fixed regional EKS `DescribeCluster` request using AWS
    /// credentials from inherited stdin and emit only public enrollment pins.
    DiscoverEksStdio,
    /// Generate the public build sidecar for a packaged runner executable.
    Marker {
        #[arg(long)]
        binary: PathBuf,
        #[arg(long)]
        source_commit: String,
        #[arg(long, default_value_t = false)]
        dirty: bool,
    },
}

#[derive(Serialize)]
struct VerificationResult {
    valid: bool,
    receipt_hash: Digest32,
    receipt_public_key_hash: Digest32,
}

#[derive(Serialize)]
struct ProfileHashResult {
    valid: bool,
    environment_profile_hash: Digest32,
    receipt_public_key_hash: Digest32,
}

#[derive(Serialize)]
struct InstallationPublicMaterial {
    schema_version: u16,
    receipt_key_id: String,
    receipt_public_key: String,
    receipt_public_key_hash: Digest32,
}

#[derive(Serialize)]
struct InstallationSecrets<'a> {
    schema_version: u16,
    runner_master_seed: &'a str,
    receipt_signing_seed: &'a str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalCheckEnvelope {
    schema_version: u16,
    command: PreflightCommand,
    credentials: CredentialBundle,
}

#[derive(Serialize)]
struct InstallationStdioEnvelope<'a> {
    schema_version: u16,
    public: &'a InstallationPublicMaterial,
    secrets: InstallationSecrets<'a>,
}

struct GeneratedInstallation {
    public: InstallationPublicMaterial,
    runner_seed_text: Zeroizing<String>,
    receipt_seed_text: Zeroizing<String>,
}

fn main() -> ExitCode {
    match execute(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => {
            eprintln!("{{\"error\":\"{code}\"}}");
            ExitCode::from(2)
        }
    }
}

fn execute(cli: Cli) -> Result<(), &'static str> {
    match cli.command {
        Command::CheckStdio { profile, state } => {
            validate_state_directory(&state)?;
            let profile: PreflightProfile = read_json_file(&profile, MAX_PROFILE_BYTES)?;
            let envelope: LocalCheckEnvelope =
                read_secret_json(io::stdin().lock(), MAX_LOCAL_CHECK_BYTES)?;
            if envelope.schema_version != PREFLIGHT_SCHEMA_VERSION {
                return Err("INVALID_REQUEST");
            }
            let now = current_unix_seconds()?;
            let receipt = run_preflight(&profile, envelope.credentials, &envelope.command, now)?;
            write_json(&receipt)
        }
        Command::Verify { profile } => {
            let profile: PreflightProfile = read_json_file(&profile, MAX_PROFILE_BYTES)?;
            let receipt: SignedPreflightReceipt = read_json(io::stdin().lock(), MAX_RECEIPT_BYTES)?;
            verify_receipt(&receipt, &profile).map_err(|_| "RECEIPT_VERIFICATION_FAILED")?;
            write_json(&VerificationResult {
                valid: true,
                receipt_hash: receipt.receipt_hash,
                receipt_public_key_hash: receipt.receipt_public_key_hash,
            })
        }
        Command::ProfileHash { profile } => {
            let profile: PreflightProfile = read_json_file(&profile, MAX_PROFILE_BYTES)?;
            let environment_profile_hash = profile.digest().map_err(|_| "INVALID_PROFILE")?;
            write_json(&ProfileHashResult {
                valid: true,
                environment_profile_hash,
                receipt_public_key_hash: profile.receipt.public_key_hash,
            })
        }
        Command::InitInstallationStdio => init_installation_stdio(),
        Command::DiscoverEksStdio => {
            let now = current_unix_seconds()?;
            discover_eks_stdio_with(io::stdin().lock(), io::stdout().lock(), now, discover_eks)
        }
        Command::Marker {
            binary,
            source_commit,
            dirty,
        } => {
            let binary_sha256 = hash_file(&binary)?;
            let marker = PreflightRunnerBuildMarker {
                schema_version: PREFLIGHT_BUILD_MARKER_SCHEMA_VERSION,
                component: "accordlock-preflight-runner".to_owned(),
                protocol_version: PREFLIGHT_PROTOCOL_VERSION,
                binary_sha256,
                source_commit,
                dirty,
            };
            marker.validate().map_err(|_| "INVALID_BUILD_MARKER")?;
            write_json(&marker)
        }
    }
}

fn discover_eks_stdio_with(
    reader: impl Read,
    writer: impl io::Write,
    trusted_now: i64,
    discover: impl FnOnce(EksEnrollmentEnvelope, i64) -> Result<EksEnrollmentResult, &'static str>,
) -> Result<(), &'static str> {
    let envelope = read_secret_json(reader, MAX_EKS_ENROLLMENT_INPUT_BYTES)?;
    let result = discover(envelope, trusted_now)?;
    write_bounded_json_to(writer, &result, MAX_EKS_ENROLLMENT_OUTPUT_BYTES)
}

fn init_installation_stdio() -> Result<(), &'static str> {
    let installation = generate_installation();
    write_json(&InstallationStdioEnvelope {
        schema_version: INSTALLATION_SCHEMA_VERSION,
        public: &installation.public,
        secrets: InstallationSecrets {
            schema_version: INSTALLATION_SCHEMA_VERSION,
            runner_master_seed: installation.runner_seed_text.as_str(),
            receipt_signing_seed: installation.receipt_seed_text.as_str(),
        },
    })
}

fn generate_installation() -> GeneratedInstallation {
    let mut runner_seed = [0_u8; 32];
    let mut receipt_seed = [0_u8; 32];
    OsRng.fill_bytes(&mut runner_seed);
    OsRng.fill_bytes(&mut receipt_seed);
    let receipt_signer = SigningKey::from_bytes(&receipt_seed);
    let receipt_public_key = receipt_signer.verifying_key().to_bytes();
    let receipt_public_key_hash = Digest32::sha256(&receipt_public_key);
    let runner_seed_text = Zeroizing::new(URL_SAFE_NO_PAD.encode(runner_seed));
    let receipt_seed_text = Zeroizing::new(URL_SAFE_NO_PAD.encode(receipt_seed));
    runner_seed.zeroize();
    receipt_seed.zeroize();
    GeneratedInstallation {
        public: InstallationPublicMaterial {
            schema_version: INSTALLATION_SCHEMA_VERSION,
            receipt_key_id: format!(
                "accordlock-receipt-{}",
                &receipt_public_key_hash.to_hex()[..16]
            ),
            receipt_public_key: URL_SAFE_NO_PAD.encode(receipt_public_key),
            receipt_public_key_hash,
        },
        runner_seed_text,
        receipt_seed_text,
    }
}

fn validate_state_directory(path: &Path) -> Result<(), &'static str> {
    if !path.is_absolute() {
        return Err("INVALID_STATE_DIRECTORY");
    }
    let canonical = fs::canonicalize(path).map_err(|_| "STATE_DIRECTORY_UNAVAILABLE")?;
    if !canonical.is_dir() {
        return Err("STATE_DIRECTORY_UNAVAILABLE");
    }
    Ok(())
}

fn read_json_file<T: serde::de::DeserializeOwned>(
    path: &Path,
    maximum: usize,
) -> Result<T, &'static str> {
    if !path.is_absolute() {
        return Err("INVALID_FILE_PATH");
    }
    let file = File::open(path).map_err(|_| "FILE_UNAVAILABLE")?;
    read_json(file, maximum)
}

fn read_json<T: serde::de::DeserializeOwned>(
    mut reader: impl Read,
    maximum: usize,
) -> Result<T, &'static str> {
    let limit = u64::try_from(maximum).map_err(|_| "INPUT_TOO_LARGE")?;
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| "INPUT_UNAVAILABLE")?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err("INPUT_TOO_LARGE");
    }
    serde_json::from_slice(&bytes).map_err(|_| "INVALID_JSON")
}

/// Read a bounded JSON value whose source bytes contain secrets. The input
/// buffer is zeroized on every return path, including parse and size errors.
fn read_secret_json<T: serde::de::DeserializeOwned>(
    mut reader: impl Read,
    maximum: usize,
) -> Result<T, &'static str> {
    let limit = u64::try_from(maximum).map_err(|_| "INPUT_TOO_LARGE")?;
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .by_ref()
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| "INPUT_UNAVAILABLE")?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err("INPUT_TOO_LARGE");
    }
    serde_json::from_slice(&bytes).map_err(|_| "INVALID_JSON")
}

fn write_json<T: Serialize>(value: &T) -> Result<(), &'static str> {
    write_bounded_json_to(io::stdout().lock(), value, MAX_RECEIPT_BYTES)
}

fn write_bounded_json_to<T: Serialize>(
    mut writer: impl io::Write,
    value: &T,
    maximum: usize,
) -> Result<(), &'static str> {
    let encoded = serde_json::to_vec(value).map_err(|_| "OUTPUT_FAILED")?;
    if encoded.len().saturating_add(1) > maximum {
        return Err("OUTPUT_TOO_LARGE");
    }
    writer
        .write_all(&encoded)
        .and_then(|()| writer.write_all(b"\n"))
        .map_err(|_| "OUTPUT_FAILED")
}

fn hash_file(path: &Path) -> Result<Digest32, &'static str> {
    if !path.is_absolute() {
        return Err("INVALID_FILE_PATH");
    }
    let metadata = fs::metadata(path).map_err(|_| "FILE_UNAVAILABLE")?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_BINARY_BYTES {
        return Err("INVALID_BINARY");
    }
    let mut file = File::open(path).map_err(|_| "FILE_UNAVAILABLE")?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|_| "FILE_UNAVAILABLE")?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(Digest32::from_bytes(hash.finalize().into()))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use accordlock_preflight_runner::{EksEnrollmentResult, model::EKS_ENROLLMENT_SCHEMA_VERSION};
    use accordlock_protocol::Digest32;
    use clap::Parser as _;
    use serde::Deserialize;
    use serde_json::json;

    use super::{Cli, discover_eks_stdio_with, read_secret_json};

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct SecretFixture {
        token: String,
    }

    #[test]
    fn secret_json_input_is_bounded_and_strict() {
        assert_eq!(
            read_secret_json(Cursor::new(br#"{"token":"secret-value"}"#), 64),
            Ok(SecretFixture {
                token: "secret-value".to_owned()
            })
        );
        assert_eq!(
            read_secret_json::<SecretFixture>(Cursor::new(br#"{"token":"x","extra":1}"#), 64),
            Err("INVALID_JSON")
        );
        assert_eq!(
            read_secret_json::<SecretFixture>(Cursor::new(vec![b'x'; 65]), 64),
            Err("INPUT_TOO_LARGE")
        );
    }

    #[test]
    fn named_secret_endpoints_are_not_cli_commands() {
        assert!(Cli::try_parse_from(["runner", "check"]).is_err());
        assert!(Cli::try_parse_from(["runner", "init-installation"]).is_err());
        assert!(Cli::try_parse_from(["runner", "discover-eks"]).is_err());
        assert!(
            Cli::try_parse_from([
                "runner",
                "discover-eks-stdio",
                "--endpoint",
                "https://attacker.invalid"
            ])
            .is_err()
        );
    }

    #[test]
    fn discover_eks_stdio_accepts_only_the_strict_secret_envelope_and_public_output() {
        let input = serde_json::to_vec(&json!({
            "schema_version": EKS_ENROLLMENT_SCHEMA_VERSION,
            "request": {
                "account_id": "123456789012",
                "region": "us-east-1",
                "cluster_name": "primary"
            },
            "credentials": {
                "aws_access_key_id": "AKIATESTACCESS",
                "aws_secret_access_key": "test-secret-access-key-material",
                "aws_session_token": "test-session-token"
            }
        }))
        .unwrap_or_else(|error| unreachable!("fixture must serialize: {error:?}"));
        let mut output = Vec::new();
        let expected_hash = Digest32::sha256(b"cluster-ca");
        let result = discover_eks_stdio_with(
            Cursor::new(input),
            &mut output,
            123,
            |envelope, trusted_now| {
                assert_eq!(trusted_now, 123);
                envelope
                    .validate()
                    .unwrap_or_else(|error| unreachable!("fixture must validate: {error:?}"));
                assert_eq!(envelope.request.account_id, "123456789012");
                assert_eq!(envelope.request.region, "us-east-1");
                assert_eq!(envelope.request.cluster_name, "primary");
                assert_eq!(
                    envelope.credentials.aws_access_key_id.expose(),
                    b"AKIATESTACCESS"
                );
                Ok(EksEnrollmentResult {
                    schema_version: EKS_ENROLLMENT_SCHEMA_VERSION,
                    cluster_arn: "arn:aws:eks:us-east-1:123456789012:cluster/primary".to_owned(),
                    endpoint: "https://primary.eks.test".to_owned(),
                    cluster_ca_hash: expected_hash,
                })
            },
        );
        assert_eq!(result, Ok(()));
        let value: serde_json::Value = serde_json::from_slice(&output)
            .unwrap_or_else(|error| unreachable!("public output must parse: {error:?}"));
        assert_eq!(value.as_object().map(serde_json::Map::len), Some(4));
        assert_eq!(value["schema_version"], json!(1));
        assert_eq!(value["cluster_ca_hash"], json!(expected_hash));
        let output_text = String::from_utf8(output)
            .unwrap_or_else(|error| unreachable!("JSON output must be UTF-8: {error:?}"));
        assert!(!output_text.contains("AKIATESTACCESS"));
        assert!(!output_text.contains("test-secret"));
        assert!(!output_text.contains("session-token"));

        let injected = br#"{
            "schema_version":1,
            "request":{
                "account_id":"123456789012",
                "region":"us-east-1",
                "cluster_name":"primary",
                "endpoint":"https://attacker.invalid"
            },
            "credentials":{
                "aws_access_key_id":"AKIATESTACCESS",
                "aws_secret_access_key":"test-secret-access-key-material",
                "aws_session_token":null
            }
        }"#;
        let mut rejected_output = Vec::new();
        assert_eq!(
            discover_eks_stdio_with(
                Cursor::new(injected),
                &mut rejected_output,
                123,
                |_, _| unreachable!("strict decoding must reject caller transport fields")
            ),
            Err("INVALID_JSON")
        );
        assert!(rejected_output.is_empty());
    }
}
