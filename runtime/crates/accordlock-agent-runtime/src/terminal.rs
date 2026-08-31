use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    str::FromStr as _,
    sync::{Arc, mpsc},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd as _;
#[cfg(windows)]
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};

use accordlock_agent_protocol::Digest32;
#[cfg(windows)]
use process_wrap::std::JobObject;
#[cfg(unix)]
use process_wrap::std::ProcessGroup;
use process_wrap::std::{ChildWrapper, CommandWrap};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unicode_general_category::{GeneralCategory, get_general_category};

use crate::{
    ActionApprovalRequest, ActionDescriptor, ActionType, Ledger, LedgerError,
    canonical::canonical_json_bytes,
    ledger::{AuthorizationGrant, AuthorizationResult, ObservationResult},
    model::{
        TOOL_EXECUTION_SCHEMA_VERSION, ToolCallProposal, ToolExecutionObservation,
        WireExecutionOutcome,
    },
};

pub const TERMINAL_EXECUTE_PATH: &str = "/api/v2/execution/terminal/authorize-and-execute";

const MAX_ARG_COUNT: usize = 128;
const MAX_ARG_BYTES: usize = 4 * 1024;
const MAX_TOTAL_ARG_BYTES: usize = 64 * 1024;
const MAX_ENVIRONMENT_ENTRIES: usize = 16;
const MAX_ENVIRONMENT_VALUE_BYTES: usize = 256;
const MAX_RELATIVE_CWD_BYTES: usize = 4 * 1024;
const MAX_CWD_COMPONENTS: usize = 64;
const MAX_TIMEOUT_SECONDS: u32 = 5 * 60;
const DEFAULT_TIMEOUT_SECONDS: u32 = 60;
const MAX_OUTPUT_BYTES: usize = 256 * 1024;
const DEFAULT_OUTPUT_BYTES: u32 = 64 * 1024;
const OUTPUT_READER_GRACE: Duration = Duration::from_secs(1);
#[cfg(unix)]
const PROCESS_GROUP_CLEANUP_GRACE: Duration = Duration::from_secs(1);
const TERMINAL_PRESTATE_DOMAIN: &[u8] = b"accordlock:v1:terminal-prestate";
const TERMINAL_INVOCATION_DOMAIN: &[u8] = b"accordlock:v1:terminal-invocation";

#[cfg(windows)]
const FILE_SHARE_READ: u32 = 0x0000_0001;

#[cfg(not(any(unix, windows)))]
compile_error!("the governed terminal requires Windows Job Objects or Unix process groups");

const ALLOWED_ENVIRONMENT: &[&str] = &[
    "CARGO_TERM_COLOR",
    "CI",
    "LANG",
    "LC_ALL",
    "NODE_ENV",
    "NO_COLOR",
    "RUST_BACKTRACE",
    "TERM",
    "TZ",
];

const BANNED_EXECUTABLE_STEMS: &[&str] = &[
    "ash",
    "bash",
    "busybox",
    "bun",
    "cmd",
    "command",
    "csh",
    "cscript",
    "dash",
    "deno",
    "doas",
    "dotnet-script",
    "env",
    "expect",
    "fish",
    "jjs",
    "js",
    "ksh",
    "lua",
    "luajit",
    "mshta",
    "node",
    "nodejs",
    "osascript",
    "perl",
    "php",
    "powershell",
    "pwsh",
    "python",
    "python2",
    "python3",
    "regsvr32",
    "ruby",
    "rundll32",
    "runuser",
    "script",
    "setsid",
    "sh",
    "su",
    "sudo",
    "tclsh",
    "toybox",
    "wasi-run",
    "wasmtime",
    "wish",
    "wscript",
    "wsl",
    "xargs",
    "xonsh",
    "zsh",
];

const VERSIONED_INTERPRETER_STEMS: &[&str] = &[
    "bun", "deno", "lua", "luajit", "node", "nodejs", "perl", "php", "python", "ruby",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExecutableIdentity {
    #[cfg(windows)]
    creation_time: u64,
    #[cfg(windows)]
    last_write_time: u64,
    #[cfg(windows)]
    file_size: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

#[derive(Debug)]
struct OpenedExecutable {
    file: File,
    path: PathBuf,
    digest: Digest32,
    identity: ExecutableIdentity,
    identity_handle: same_file::Handle,
}

impl OpenedExecutable {
    #[cfg(target_os = "linux")]
    fn spawn_path(&self) -> PathBuf {
        // Linux resolves this path to the already-open file description. The
        // descriptor remains present while exec resolves it even though the
        // standard library marks it close-on-exec. Native images are required,
        // so there is no shebang interpreter that would need the descriptor
        // after the exec transition.
        PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
    }

    #[cfg(not(target_os = "linux"))]
    fn spawn_path(&self) -> PathBuf {
        self.path.clone()
    }

    fn revalidate(&self) -> Result<(), TerminalToolError> {
        let path_metadata =
            std::fs::symlink_metadata(&self.path).map_err(|_| TerminalToolError::ProgramChanged)?;
        if !path_metadata.is_file() || path_metadata.file_type().is_symlink() {
            return Err(TerminalToolError::ProgramChanged);
        }
        let path_identity_handle = same_file::Handle::from_path(&self.path)
            .map_err(|_| TerminalToolError::ProgramUnavailable)?;
        let handle_metadata = self
            .file
            .metadata()
            .map_err(|_| TerminalToolError::ProgramUnavailable)?;
        let handle_identity = executable_identity(&handle_metadata);
        if path_identity_handle != self.identity_handle || handle_identity != self.identity {
            return Err(TerminalToolError::ProgramChanged);
        }
        if hash_open_file(&self.file)? != self.digest {
            return Err(TerminalToolError::ProgramChanged);
        }
        Ok(())
    }
}

fn is_banned_executable_stem(stem: &str) -> bool {
    BANNED_EXECUTABLE_STEMS.contains(&stem)
        || VERSIONED_INTERPRETER_STEMS.iter().any(|prefix| {
            stem.strip_prefix(prefix).is_some_and(|suffix| {
                !suffix.is_empty()
                    && suffix
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_'))
                    && suffix.bytes().any(|byte| byte.is_ascii_digit())
            })
        })
}

fn canonical_executable_path(path: &Path) -> Result<PathBuf, TerminalToolError> {
    if !path.is_absolute() {
        return Err(TerminalToolError::ProgramUnavailable);
    }
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| TerminalToolError::ProgramUnavailable)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(TerminalToolError::ProgramChanged);
    }
    std::fs::canonicalize(path).map_err(|_| TerminalToolError::ProgramUnavailable)
}

fn open_executable(path: &Path) -> Result<OpenedExecutable, TerminalToolError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| TerminalToolError::ProgramUnavailable)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(TerminalToolError::ProgramChanged);
    }
    let canonical =
        std::fs::canonicalize(path).map_err(|_| TerminalToolError::ProgramUnavailable)?;
    if canonical != path {
        return Err(TerminalToolError::ProgramChanged);
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    options.share_mode(FILE_SHARE_READ);
    let file = options
        .open(&canonical)
        .map_err(|_| TerminalToolError::ProgramUnavailable)?;
    let handle_metadata = file
        .metadata()
        .map_err(|_| TerminalToolError::ProgramUnavailable)?;
    if !handle_metadata.is_file() {
        return Err(TerminalToolError::ProgramChanged);
    }
    let identity = executable_identity(&handle_metadata);
    if executable_identity(&metadata) != identity {
        return Err(TerminalToolError::ProgramChanged);
    }
    let identity_handle = same_file::Handle::from_file(
        file.try_clone()
            .map_err(|_| TerminalToolError::ProgramUnavailable)?,
    )
    .map_err(|_| TerminalToolError::ProgramUnavailable)?;
    let path_identity_handle = same_file::Handle::from_path(&canonical)
        .map_err(|_| TerminalToolError::ProgramUnavailable)?;
    if path_identity_handle != identity_handle {
        return Err(TerminalToolError::ProgramChanged);
    }
    let digest = hash_open_file(&file)?;
    let opened = OpenedExecutable {
        file,
        path: canonical,
        digest,
        identity,
        identity_handle,
    };
    opened.revalidate()?;
    Ok(opened)
}

#[cfg(windows)]
fn executable_identity(metadata: &std::fs::Metadata) -> ExecutableIdentity {
    ExecutableIdentity {
        creation_time: metadata.creation_time(),
        last_write_time: metadata.last_write_time(),
        file_size: metadata.file_size(),
    }
}

#[cfg(unix)]
fn executable_identity(metadata: &std::fs::Metadata) -> ExecutableIdentity {
    ExecutableIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

fn hash_open_file(file: &File) -> Result<Digest32, TerminalToolError> {
    let mut file = file
        .try_clone()
        .map_err(|_| TerminalToolError::ProgramUnavailable)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| TerminalToolError::ProgramUnavailable)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 32 * 1024].into_boxed_slice();
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| TerminalToolError::ProgramUnavailable)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(Digest32::from_bytes(hasher.finalize().into()))
}

fn validate_native_executable(file: &File) -> Result<(), TerminalToolError> {
    let mut file = file
        .try_clone()
        .map_err(|_| TerminalToolError::ProgramUnavailable)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| TerminalToolError::ProgramUnavailable)?;
    let mut magic = [0_u8; 4];
    file.read_exact(&mut magic)
        .map_err(|_| TerminalToolError::ProgramUnavailable)?;
    #[cfg(windows)]
    let valid = if magic.starts_with(b"MZ") {
        let mut offset = [0_u8; 4];
        file.seek(SeekFrom::Start(0x3c))
            .and_then(|_| file.read_exact(&mut offset))
            .map_err(|_| TerminalToolError::ProgramFormatForbidden)?;
        let offset = u64::from(u32::from_le_bytes(offset));
        let length = file
            .metadata()
            .map_err(|_| TerminalToolError::ProgramUnavailable)?
            .len();
        if offset > length.saturating_sub(4) {
            false
        } else {
            let mut signature = [0_u8; 4];
            file.seek(SeekFrom::Start(offset))
                .and_then(|_| file.read_exact(&mut signature))
                .map_err(|_| TerminalToolError::ProgramFormatForbidden)?;
            signature == *b"PE\0\0"
        }
    } else {
        false
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let valid = magic == [0x7f, b'E', b'L', b'F'];
    #[cfg(target_os = "macos")]
    let valid = matches!(
        magic,
        [0xfe, 0xed, 0xfa, 0xce]
            | [0xfe, 0xed, 0xfa, 0xcf]
            | [0xce, 0xfa, 0xed, 0xfe]
            | [0xcf, 0xfa, 0xed, 0xfe]
            | [0xca, 0xfe, 0xba, 0xbe]
            | [0xbe, 0xba, 0xfe, 0xca]
            | [0xca, 0xfe, 0xba, 0xbf]
            | [0xbf, 0xba, 0xfe, 0xca]
    );
    if valid {
        Ok(())
    } else {
        Err(TerminalToolError::ProgramFormatForbidden)
    }
}

/// Trusted alias-to-binary binding installed by the Desktop/runtime owner.
///
/// A proposal carries the alias as `argv[0]`; it never supplies an executable
/// path. The canonical path is rechecked immediately before every spawn.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TerminalProgram {
    alias: String,
    executable: PathBuf,
    executable_sha256: Digest32,
    executable_identity: ExecutableIdentity,
    executable_handle: Arc<same_file::Handle>,
}

impl TerminalProgram {
    /// Creates one exact program binding.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical aliases, links, non-files, shell interpreters, and
    /// paths that cannot be canonicalized as Unicode regular files.
    pub fn new(alias: impl Into<String>, executable: &Path) -> Result<Self, TerminalConfigError> {
        let alias = alias.into();
        validate_alias(&alias)?;
        let canonical = canonical_executable_path(executable)
            .map_err(|_| TerminalConfigError::InvalidExecutable)?;
        let stem = canonical
            .file_stem()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or(TerminalConfigError::InvalidExecutable)?
            .to_ascii_lowercase();
        if is_banned_executable_stem(&stem) {
            return Err(TerminalConfigError::ShellExecutableForbidden);
        }
        #[cfg(windows)]
        if !canonical
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
        {
            return Err(TerminalConfigError::ShellExecutableForbidden);
        }
        let executable =
            open_executable(&canonical).map_err(|_| TerminalConfigError::InvalidExecutable)?;
        validate_native_executable(&executable.file)
            .map_err(|_| TerminalConfigError::ExecutableFormatForbidden)?;
        Ok(Self {
            alias,
            executable: canonical,
            executable_sha256: executable.digest,
            executable_identity: executable.identity.clone(),
            executable_handle: Arc::new(executable.identity_handle),
        })
    }

    /// Creates a binding only when the selected executable still matches the
    /// main-process commitment persisted beside the Desktop application.
    ///
    /// # Errors
    ///
    /// Rejects malformed digests and any executable whose current bytes do
    /// not match the supplied commitment.
    pub fn new_with_expected_digest(
        alias: impl Into<String>,
        executable: &Path,
        expected_digest: &str,
    ) -> Result<Self, TerminalConfigError> {
        let program = Self::new(alias, executable)?;
        let expected = Digest32::from_str(expected_digest)
            .map_err(|_| TerminalConfigError::InvalidExecutableDigest)?;
        if program.executable_sha256 != expected {
            return Err(TerminalConfigError::ExecutableDigestMismatch);
        }
        Ok(program)
    }

    pub(crate) fn alias(&self) -> &str {
        &self.alias
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TerminalExecutionRequest {
    pub schema_version: u16,
    pub proposal: ToolCallProposal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum TerminalExecutionStatus {
    Succeeded,
    ExecutionUnknown,
    Denied,
    ApprovalRequired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum TerminalProcessOutcome {
    Succeeded,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TerminalResult {
    pub program: String,
    pub executable_sha256: String,
    pub invocation_sha256: String,
    pub exit_code: Option<i32>,
    pub outcome: TerminalProcessOutcome,
    pub stdout: String,
    pub stderr: String,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub encoding_lossy: bool,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TerminalExecutionResponse {
    pub schema_version: u16,
    pub proposal_digest: String,
    pub status: TerminalExecutionStatus,
    pub reason_code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<TerminalResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_request: Option<ActionApprovalRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_request_hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PreparedTerminalOperation {
    program: TerminalProgram,
    arguments: Vec<String>,
    cwd: ValidatedRelativeDirectory,
    environment: BTreeMap<String, String>,
    timeout: Duration,
    max_output_bytes: usize,
}

impl PreparedTerminalOperation {
    fn from_proposal(
        proposal: &ToolCallProposal,
        programs: &BTreeMap<String, TerminalProgram>,
    ) -> Result<Self, TerminalInputError> {
        if proposal.extension_id != "developer" || proposal.tool_name != "shell" {
            return Err(TerminalInputError::UnsupportedTool);
        }
        let input: TerminalArguments = serde_json::from_value(proposal.arguments.clone())
            .map_err(|_| TerminalInputError::InvalidArguments)?;
        validate_argv(&input.argv)?;
        let program = programs
            .get(&input.argv[0])
            .cloned()
            .ok_or(TerminalInputError::ProgramNotConfigured)?;
        validate_environment(&input.env)?;
        if !(1..=MAX_TIMEOUT_SECONDS).contains(&input.timeout_seconds) {
            return Err(TerminalInputError::InvalidTimeout);
        }
        let maximum = usize::try_from(input.max_output_bytes)
            .map_err(|_| TerminalInputError::InvalidOutputLimit)?;
        if maximum == 0 || maximum > MAX_OUTPUT_BYTES {
            return Err(TerminalInputError::InvalidOutputLimit);
        }
        Ok(Self {
            program,
            arguments: input.argv.into_iter().skip(1).collect(),
            cwd: ValidatedRelativeDirectory::new(&input.cwd)?,
            environment: input.env,
            timeout: Duration::from_secs(u64::from(input.timeout_seconds)),
            max_output_bytes: maximum,
        })
    }

    fn prestate(&self, workspace_root: &Path) -> Result<TerminalPrestate, TerminalToolError> {
        let executable = open_pinned_program(&self.program)?;
        let cwd = self.cwd.resolve(workspace_root)?;
        Ok(self.prestate_from(&executable, cwd))
    }

    fn prestate_from(&self, executable: &OpenedExecutable, cwd: PathBuf) -> TerminalPrestate {
        TerminalPrestate {
            schema_version: 3,
            executable_sha256: executable.digest,
            executable_identity: executable.identity.clone(),
            executable: executable.path.clone(),
            cwd,
            environment_names: self.environment.keys().cloned().collect(),
        }
    }

    fn invocation_digest(
        &self,
        prestate: &TerminalPrestate,
    ) -> Result<Digest32, TerminalToolError> {
        #[derive(Serialize)]
        #[serde(deny_unknown_fields)]
        struct Invocation<'a> {
            schema_version: u16,
            program: &'a str,
            executable_sha256: Digest32,
            executable_identity: &'a ExecutableIdentity,
            cwd: &'a str,
            arguments: &'a [String],
            environment: &'a BTreeMap<String, String>,
        }

        let encoded = canonical_json_bytes(&Invocation {
            schema_version: 1,
            program: &self.program.alias,
            executable_sha256: prestate.executable_sha256,
            executable_identity: &prestate.executable_identity,
            cwd: &self.cwd.display,
            arguments: &self.arguments,
            environment: &self.environment,
        })
        .map_err(|_| TerminalToolError::InvalidExecutionState)?;
        let mut hasher = Sha256::new();
        hasher.update(TERMINAL_INVOCATION_DOMAIN);
        hasher.update([0]);
        hasher.update(
            u64::try_from(encoded.len())
                .map_err(|_| TerminalToolError::InvalidExecutionState)?
                .to_be_bytes(),
        );
        hasher.update(encoded);
        Ok(Digest32::from_bytes(hasher.finalize().into()))
    }

    fn action(&self, prestate: &TerminalPrestate) -> Result<ActionDescriptor, TerminalToolError> {
        let requested = self
            .arguments
            .iter()
            .map(String::len)
            .chain(self.environment.values().map(String::len))
            .try_fold(0_u64, |sum, length| {
                sum.checked_add(u64::try_from(length).ok()?)
            })
            .ok_or(TerminalToolError::InvalidExecutionState)?;
        Ok(ActionDescriptor {
            extension_id: "developer".to_owned(),
            tool_name: "shell".to_owned(),
            relative_path: self.cwd.display.clone(),
            action_type: ActionType::ExecuteProcess,
            requested_bytes: requested,
            executable_path: Some(
                prestate
                    .executable
                    .to_str()
                    .ok_or(TerminalToolError::InvalidExecutionState)?
                    .to_owned(),
            ),
            executable_sha256: Some(prestate.executable_sha256),
        })
    }

    fn execute(
        &self,
        workspace_root: &Path,
        expected_prestate: Digest32,
    ) -> Result<TerminalResult, TerminalToolError> {
        let executable = open_pinned_program(&self.program)?;
        let cwd = self.cwd.resolve(workspace_root)?;
        let prestate = self.prestate_from(&executable, cwd);
        if prestate.digest()? != expected_prestate {
            return Err(TerminalToolError::ExecutionStateChanged);
        }
        let invocation_sha256 = self.invocation_digest(&prestate)?;
        let mut command = Command::new(executable.spawn_path());
        command
            .args(&self.arguments)
            .current_dir(&prestate.cwd)
            .env_clear()
            .envs(&self.environment)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let started = Instant::now();
        let mut command = contained_command(command);
        let mut child = command
            .spawn()
            .map_err(|_| TerminalToolError::SpawnFailed)?;
        let process_group_id = child.id();
        if executable.revalidate().is_err() {
            return Err(cleanup_or(
                &mut *child,
                process_group_id,
                TerminalToolError::ExecutionStateChanged,
            ));
        }
        let Some(stdout) = child.stdout().take() else {
            return Err(cleanup_or(
                &mut *child,
                process_group_id,
                TerminalToolError::OutputCaptureFailed,
            ));
        };
        let Some(stderr) = child.stderr().take() else {
            return Err(cleanup_or(
                &mut *child,
                process_group_id,
                TerminalToolError::OutputCaptureFailed,
            ));
        };
        let stdout = read_bounded_in_background(stdout, self.max_output_bytes);
        let stderr = read_bounded_in_background(stderr, self.max_output_bytes);

        let status = loop {
            match try_wait_leader(&mut *child) {
                Ok(Some(status)) => {
                    // An authorized program is never allowed to leave background work behind.
                    // The parent status is not considered terminal until its complete job/group
                    // has been terminated and, where the OS supports it, reaped.
                    cleanup_process_tree(&mut *child, process_group_id, true)?;
                    break status;
                }
                Ok(None) if started.elapsed() < self.timeout => {
                    thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => {
                    return Err(cleanup_or(
                        &mut *child,
                        process_group_id,
                        TerminalToolError::TimedOut,
                    ));
                }
                Err(_) => {
                    return Err(cleanup_or(
                        &mut *child,
                        process_group_id,
                        TerminalToolError::WaitFailed,
                    ));
                }
            }
        };
        let stdout = stdout
            .recv_timeout(OUTPUT_READER_GRACE)
            .map_err(|_| TerminalToolError::OutputCaptureFailed)??;
        let stderr = stderr
            .recv_timeout(OUTPUT_READER_GRACE)
            .map_err(|_| TerminalToolError::OutputCaptureFailed)??;
        executable.revalidate()?;
        let stdout_text = sanitize_output(&stdout.bytes);
        let stderr_text = sanitize_output(&stderr.bytes);
        let encoding_lossy = stdout_text.encoding_lossy || stderr_text.encoding_lossy;
        Ok(TerminalResult {
            program: self.program.alias.clone(),
            executable_sha256: executable.digest.to_string(),
            invocation_sha256: invocation_sha256.to_string(),
            exit_code: status.code(),
            outcome: if status.success() {
                TerminalProcessOutcome::Succeeded
            } else {
                TerminalProcessOutcome::Failed
            },
            stdout: stdout_text.text,
            stderr: stderr_text.text,
            stdout_sha256: stdout.sha256.to_string(),
            stderr_sha256: stderr.sha256.to_string(),
            stdout_truncated: stdout.truncated,
            stderr_truncated: stderr.truncated,
            encoding_lossy,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }
}

fn contained_command(command: Command) -> CommandWrap {
    let mut command = CommandWrap::from(command);
    #[cfg(windows)]
    command.wrap(JobObject);
    #[cfg(unix)]
    command.wrap(ProcessGroup::leader());
    command
}

fn try_wait_leader(
    child: &mut dyn ChildWrapper,
) -> std::io::Result<Option<std::process::ExitStatus>> {
    #[cfg(windows)]
    {
        // `JobObjectChild::try_wait` also polls the job completion port. If it
        // consumes the all-processes-exited notification, the later bounded
        // cleanup cannot prove that the complete process tree is gone. Poll
        // only the wrapped leader here and leave the completion notification
        // for `JobObjectChild::wait` after the job-wide termination request.
        child.inner_mut().try_wait()
    }
    #[cfg(unix)]
    {
        child.try_wait()
    }
}

fn cleanup_or(
    child: &mut dyn ChildWrapper,
    process_group_id: u32,
    original: TerminalToolError,
) -> TerminalToolError {
    cleanup_process_tree(child, process_group_id, false)
        .err()
        .unwrap_or(original)
}

#[cfg(unix)]
fn process_group_is_absent(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
}

#[cfg(windows)]
fn cleanup_process_tree(
    child: &mut dyn ChildWrapper,
    _process_group_id: u32,
    _leader_exited: bool,
) -> Result<(), TerminalToolError> {
    // JobObjectChild::kill terminates the complete job and wait() observes the
    // job completion port. A failure means the execution state is not knowable.
    child
        .kill()
        .map_err(|_| TerminalToolError::ProcessTreeCleanupFailed)
}

#[cfg(unix)]
fn cleanup_process_tree(
    child: &mut dyn ChildWrapper,
    process_group_id: u32,
    leader_exited: bool,
) -> Result<(), TerminalToolError> {
    #[cfg(not(target_os = "linux"))]
    let _ = process_group_id;
    // ProcessGroupChild::kill sends SIGKILL to the entire group. If the group
    // has already disappeared after an observed leader exit, an OS-level
    // "not found" result is positive evidence that no member remains in that
    // group. Rust currently exposes Unix ESRCH as `Uncategorized`, so the
    // helper also checks the raw errno. Before an observed exit the same result
    // is ambiguous (for example, a group escape) and therefore fails closed
    // without an unbounded wait.
    match child.kill() {
        Ok(()) => {}
        Err(error) if leader_exited && process_group_is_absent(&error) => {
            return Ok(());
        }
        Err(_) => return Err(TerminalToolError::ProcessTreeCleanupFailed),
    }

    // `wait()` can return after the leader has been reaped. Keep issuing the
    // group-wide kill until the kernel reports that the group no longer
    // contains executable work, so a natural leader exit cannot turn
    // descendants into background work. Linux can retain killed descendants
    // as zombies after they have been reparented outside this process' reap
    // authority. A zombie cannot execute, fork, or perform I/O; requiring
    // `killpg` to return ESRCH would therefore turn successful containment into
    // an ambiguous result. An unreadable or malformed `/proc` view still fails
    // closed. This is process containment, not a filesystem/network sandbox.
    let deadline = Instant::now() + PROCESS_GROUP_CLEANUP_GRACE;
    loop {
        match child.start_kill() {
            Err(error) if process_group_is_absent(&error) => return Ok(()),
            Err(_) => return Err(TerminalToolError::ProcessTreeCleanupFailed),
            Ok(()) => {}
        }
        #[cfg(target_os = "linux")]
        match linux_process_group_has_live_members(process_group_id) {
            Ok(false) => return Ok(()),
            Ok(true) => {}
            Err(()) => return Err(TerminalToolError::ProcessTreeCleanupFailed),
        }
        if Instant::now() >= deadline {
            return Err(TerminalToolError::ProcessTreeCleanupFailed);
        }
        thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(any(target_os = "linux", test))]
fn proc_stat_state_and_group(stat: &str) -> Option<(u8, u32)> {
    // `/proc/<pid>/stat` encloses `comm` in parentheses; that field may contain
    // spaces and closing parentheses. Everything after the final `) ` starts
    // with state, parent PID, then process-group ID.
    let mut fields = stat.rsplit_once(") ")?.1.split_ascii_whitespace();
    let state = fields.next()?.as_bytes();
    let state = *state.first().filter(|_| state.len() == 1)?;
    let _parent_pid = fields.next()?.parse::<u32>().ok()?;
    let process_group = fields.next()?.parse::<u32>().ok()?;
    Some((state, process_group))
}

#[cfg(target_os = "linux")]
fn linux_process_group_has_live_members(process_group_id: u32) -> Result<bool, ()> {
    let entries = std::fs::read_dir("/proc").map_err(|_| ())?;
    for entry in entries {
        let entry = entry.map_err(|_| ())?;
        if entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
            .is_none()
        {
            continue;
        }
        let stat_path = entry.path().join("stat");
        let stat = match std::fs::read_to_string(stat_path) {
            Ok(stat) => stat,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(()),
        };
        let (state, group) = proc_stat_state_and_group(&stat).ok_or(())?;
        if group == process_group_id && state != b'Z' {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn execute_governed(
    ledger: &Ledger,
    request: &TerminalExecutionRequest,
    programs: &BTreeMap<String, TerminalProgram>,
    now: i64,
    grant_lifetime_seconds: i64,
) -> Result<TerminalExecutionResponse, GovernedTerminalError> {
    if request.schema_version != TOOL_EXECUTION_SCHEMA_VERSION {
        return Err(GovernedTerminalError::Input);
    }
    request
        .proposal
        .validate()
        .map_err(|_| GovernedTerminalError::Input)?;
    let proposal_digest = request
        .proposal
        .digest()
        .map_err(|_| GovernedTerminalError::Input)?;
    let operation = match PreparedTerminalOperation::from_proposal(&request.proposal, programs) {
        Ok(operation) => operation,
        Err(TerminalInputError::ProgramNotConfigured) => {
            return Ok(denied_response(
                proposal_digest,
                "TERMINAL_PROGRAM_NOT_CONFIGURED",
                None,
            ));
        }
        Err(_) => return Err(GovernedTerminalError::Input),
    };
    let prestate = operation
        .prestate(Path::new(&request.proposal.workspace_root))
        .map_err(|_| GovernedTerminalError::Input)?;
    let prestate_hash = prestate
        .digest()
        .map_err(|_| GovernedTerminalError::Input)?;
    let approval_request = ledger.action_approval_request(
        &request.proposal,
        prestate_hash,
        operation
            .action(&prestate)
            .map_err(|_| GovernedTerminalError::Input)?,
    )?;
    let _execution_scope = ledger.begin_execution_scope()?;
    match ledger.authorize_and_consume(
        &request.proposal,
        approval_request.as_ref(),
        None,
        now,
        grant_lifetime_seconds,
    )? {
        AuthorizationResult::Denied(reason_code) => Ok(denied_response(
            proposal_digest,
            reason_code,
            if reason_code == "ACTION_APPROVAL_REQUIRED" {
                approval_request
            } else {
                None
            },
        )),
        AuthorizationResult::Allowed(grant) => execute_authorized(
            ledger,
            &request.proposal,
            &operation,
            proposal_digest,
            prestate_hash,
            &grant,
        ),
    }
}

fn execute_authorized(
    ledger: &Ledger,
    proposal: &ToolCallProposal,
    operation: &PreparedTerminalOperation,
    proposal_digest: String,
    prestate_hash: Digest32,
    grant: &AuthorizationGrant,
) -> Result<TerminalExecutionResponse, GovernedTerminalError> {
    if grant.proposal_digest != proposal_digest {
        return Err(GovernedTerminalError::ExecutionStateUnknown);
    }
    let authorization_id = grant.authorization_id.to_string();
    let request_hash = grant.request_hash.to_string();
    match operation.execute(Path::new(&proposal.workspace_root), prestate_hash) {
        Ok(result) => {
            let digest = crate::canonical::goose_digest(&result)
                .map_err(|_| GovernedTerminalError::ExecutionStateUnknown)?;
            let record = observe(
                ledger,
                &authorization_id,
                &proposal_digest,
                &request_hash,
                WireExecutionOutcome::Succeeded,
                Some(digest.clone()),
                completion_time()?,
            )?;
            Ok(success_response(
                proposal_digest,
                authorization_id,
                request_hash,
                record,
                digest,
                result,
            ))
        }
        Err(error) => {
            let reason_code = error.reason_code();
            let evidence = serde_json::json!({ "reason_code": reason_code });
            let evidence_digest = crate::canonical::goose_digest(&evidence)
                .map_err(|_| GovernedTerminalError::ExecutionStateUnknown)?;
            let record = observe(
                ledger,
                &authorization_id,
                &proposal_digest,
                &request_hash,
                WireExecutionOutcome::ToolReportedError,
                Some(evidence_digest),
                completion_time()?,
            )?;
            Ok(execution_state_unknown_response(
                proposal_digest,
                authorization_id,
                request_hash,
                record,
                reason_code,
            ))
        }
    }
}

fn observe(
    ledger: &Ledger,
    authorization_id: &str,
    proposal_digest: &str,
    request_hash: &str,
    outcome: WireExecutionOutcome,
    result_digest: Option<String>,
    now: i64,
) -> Result<ObservationResult, GovernedTerminalError> {
    ledger
        .observe(
            &ToolExecutionObservation {
                schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
                authorization_id: authorization_id.to_owned(),
                proposal_digest: proposal_digest.to_owned(),
                request_hash: request_hash.to_owned(),
                outcome,
                result_digest,
            },
            now,
        )
        .map_err(|_| GovernedTerminalError::ExecutionStateUnknown)
}

fn completion_time() -> Result<i64, GovernedTerminalError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| GovernedTerminalError::ExecutionStateUnknown)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| GovernedTerminalError::ExecutionStateUnknown)
}

fn success_response(
    proposal_digest: String,
    authorization_id: String,
    request_hash: String,
    record: ObservationResult,
    result_sha256: String,
    result: TerminalResult,
) -> TerminalExecutionResponse {
    TerminalExecutionResponse {
        schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
        proposal_digest,
        status: TerminalExecutionStatus::Succeeded,
        reason_code: "EXECUTED",
        authorization_id: Some(authorization_id),
        request_hash: Some(request_hash),
        record_id: Some(record.record_id.to_string()),
        record_hash: Some(record.record_hash),
        result_sha256: Some(result_sha256),
        result: Some(result),
        approval_request: None,
        approval_request_hash: None,
    }
}

fn execution_state_unknown_response(
    proposal_digest: String,
    authorization_id: String,
    request_hash: String,
    record: ObservationResult,
    reason_code: &'static str,
) -> TerminalExecutionResponse {
    TerminalExecutionResponse {
        schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
        proposal_digest,
        status: TerminalExecutionStatus::ExecutionUnknown,
        reason_code,
        authorization_id: Some(authorization_id),
        request_hash: Some(request_hash),
        record_id: Some(record.record_id.to_string()),
        record_hash: Some(record.record_hash),
        result_sha256: None,
        result: None,
        approval_request: None,
        approval_request_hash: None,
    }
}

fn denied_response(
    proposal_digest: String,
    reason_code: &'static str,
    approval_request: Option<ActionApprovalRequest>,
) -> TerminalExecutionResponse {
    let approval_request_hash = approval_request
        .as_ref()
        .and_then(|context| context.digest().ok())
        .map(|digest| digest.to_string());
    TerminalExecutionResponse {
        schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
        proposal_digest,
        status: if approval_request_hash.is_some() && reason_code == "ACTION_APPROVAL_REQUIRED" {
            TerminalExecutionStatus::ApprovalRequired
        } else {
            TerminalExecutionStatus::Denied
        },
        reason_code,
        authorization_id: None,
        request_hash: None,
        record_id: None,
        record_hash: None,
        result_sha256: None,
        result: None,
        approval_request,
        approval_request_hash,
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalArguments {
    argv: Vec<String>,
    #[serde(default = "default_cwd")]
    cwd: String,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default = "default_timeout_seconds")]
    timeout_seconds: u32,
    #[serde(default = "default_output_bytes")]
    max_output_bytes: u32,
}

fn default_cwd() -> String {
    ".".to_owned()
}

const fn default_timeout_seconds() -> u32 {
    DEFAULT_TIMEOUT_SECONDS
}

const fn default_output_bytes() -> u32 {
    DEFAULT_OUTPUT_BYTES
}

fn validate_argv(argv: &[String]) -> Result<(), TerminalInputError> {
    if argv.is_empty() || argv.len() > MAX_ARG_COUNT {
        return Err(TerminalInputError::InvalidArguments);
    }
    validate_alias(&argv[0]).map_err(|_| TerminalInputError::InvalidArguments)?;
    let mut total = 0_usize;
    for (index, argument) in argv.iter().enumerate() {
        if argument.len() > MAX_ARG_BYTES
            || has_disallowed_argument_character(argument)
            || (index != 0 && has_argument_indirection_or_escape(argument))
        {
            return Err(TerminalInputError::InvalidArguments);
        }
        total = total
            .checked_add(argument.len())
            .ok_or(TerminalInputError::InvalidArguments)?;
    }
    if total > MAX_TOTAL_ARG_BYTES {
        return Err(TerminalInputError::InvalidArguments);
    }
    Ok(())
}

fn has_disallowed_argument_character(value: &str) -> bool {
    value.chars().any(|character| {
        character.is_control()
            || matches!(
                get_general_category(character),
                GeneralCategory::Format
                    | GeneralCategory::LineSeparator
                    | GeneralCategory::ParagraphSeparator
            )
    })
}

fn has_argument_indirection_or_escape(argument: &str) -> bool {
    if argument.starts_with('@') || argument.contains("://") {
        return true;
    }
    let value = argument
        .split_once('=')
        .map_or(argument, |(_, value)| value);
    if value.starts_with('/')
        || value.starts_with('\\')
        || value.starts_with("~/")
        || value.starts_with("~\\")
    {
        return true;
    }
    let bytes = value.as_bytes();
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
    {
        return true;
    }
    value.split(['/', '\\']).any(|component| component == "..")
}

fn validate_environment(environment: &BTreeMap<String, String>) -> Result<(), TerminalInputError> {
    if environment.len() > MAX_ENVIRONMENT_ENTRIES {
        return Err(TerminalInputError::InvalidEnvironment);
    }
    for (name, value) in environment {
        if !ALLOWED_ENVIRONMENT.contains(&name.as_str())
            || value.len() > MAX_ENVIRONMENT_VALUE_BYTES
            || !valid_environment_value(name, value)
        {
            return Err(TerminalInputError::InvalidEnvironment);
        }
    }
    Ok(())
}

fn valid_environment_value(name: &str, value: &str) -> bool {
    match name {
        "CI" => matches!(value, "1" | "true"),
        "NO_COLOR" => value == "1",
        "TERM" => matches!(value, "dumb" | "xterm" | "xterm-256color"),
        "LANG" | "LC_ALL" => matches!(value, "C" | "C.UTF-8" | "en_US.UTF-8"),
        "TZ" => value == "UTC",
        "RUST_BACKTRACE" => matches!(value, "0" | "1"),
        "CARGO_TERM_COLOR" => matches!(value, "always" | "auto" | "never"),
        "NODE_ENV" => matches!(value, "development" | "production" | "test"),
        _ => false,
    }
}

fn validate_alias(alias: &str) -> Result<(), TerminalConfigError> {
    if alias.is_empty()
        || alias.len() > 64
        || alias != alias.to_ascii_lowercase()
        || !alias.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
        || is_banned_executable_stem(alias)
    {
        return Err(TerminalConfigError::InvalidAlias);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ValidatedRelativeDirectory {
    path: PathBuf,
    display: String,
}

impl ValidatedRelativeDirectory {
    fn new(value: &str) -> Result<Self, TerminalInputError> {
        if value == "." {
            return Ok(Self {
                path: PathBuf::new(),
                display: ".".to_owned(),
            });
        }
        if value.is_empty()
            || value.len() > MAX_RELATIVE_CWD_BYTES
            || value.starts_with('/')
            || value.contains(['\\', ':'])
            || value.chars().any(char::is_control)
            || value.split('/').any(str::is_empty)
        {
            return Err(TerminalInputError::InvalidCwd);
        }
        let components = Path::new(value).components().collect::<Vec<_>>();
        if components.is_empty() || components.len() > MAX_CWD_COMPONENTS {
            return Err(TerminalInputError::InvalidCwd);
        }
        let mut path = PathBuf::new();
        let mut display = Vec::new();
        for component in components {
            let Component::Normal(value) = component else {
                return Err(TerminalInputError::InvalidCwd);
            };
            let text = value.to_str().ok_or(TerminalInputError::InvalidCwd)?;
            if text.is_empty() || matches!(text, "." | "..") || text.ends_with([' ', '.']) {
                return Err(TerminalInputError::InvalidCwd);
            }
            path.push(value);
            display.push(text.to_owned());
        }
        Ok(Self {
            path,
            display: display.join("/"),
        })
    }

    fn resolve(&self, workspace_root: &Path) -> Result<PathBuf, TerminalToolError> {
        let workspace = std::fs::canonicalize(workspace_root)
            .map_err(|_| TerminalToolError::WorkspaceUnavailable)?;
        let metadata = std::fs::symlink_metadata(&workspace)
            .map_err(|_| TerminalToolError::WorkspaceUnavailable)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(TerminalToolError::WorkspaceUnavailable);
        }
        let mut requested = workspace.clone();
        for component in self.path.components() {
            requested.push(component.as_os_str());
            let metadata = std::fs::symlink_metadata(&requested)
                .map_err(|_| TerminalToolError::WorkingDirectoryUnavailable)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(TerminalToolError::WorkingDirectoryUnavailable);
            }
        }
        let canonical = std::fs::canonicalize(&requested)
            .map_err(|_| TerminalToolError::WorkingDirectoryUnavailable)?;
        if !canonical.starts_with(&workspace) {
            return Err(TerminalToolError::WorkingDirectoryEscapesWorkspace);
        }
        let metadata = std::fs::symlink_metadata(&canonical)
            .map_err(|_| TerminalToolError::WorkingDirectoryUnavailable)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(TerminalToolError::WorkingDirectoryUnavailable);
        }
        Ok(canonical)
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct TerminalPrestate {
    schema_version: u16,
    executable_sha256: Digest32,
    executable_identity: ExecutableIdentity,
    executable: PathBuf,
    cwd: PathBuf,
    environment_names: BTreeSet<String>,
}

impl TerminalPrestate {
    fn digest(&self) -> Result<Digest32, TerminalToolError> {
        let encoded =
            canonical_json_bytes(self).map_err(|_| TerminalToolError::InvalidExecutionState)?;
        let mut hasher = Sha256::new();
        hasher.update(TERMINAL_PRESTATE_DOMAIN);
        hasher.update([0]);
        hasher.update(
            u64::try_from(encoded.len())
                .map_err(|_| TerminalToolError::InvalidExecutionState)?
                .to_be_bytes(),
        );
        hasher.update(encoded);
        Ok(Digest32::from_bytes(hasher.finalize().into()))
    }
}

#[cfg(all(test, unix))]
fn canonical_program(program: &TerminalProgram) -> Result<PathBuf, TerminalToolError> {
    Ok(open_pinned_program(program)?.path)
}

fn open_pinned_program(program: &TerminalProgram) -> Result<OpenedExecutable, TerminalToolError> {
    let executable = open_executable(&program.executable)?;
    if executable.digest != program.executable_sha256
        || executable.identity != program.executable_identity
        || executable.identity_handle != *program.executable_handle
    {
        return Err(TerminalToolError::ProgramChanged);
    }
    validate_native_executable(&executable.file)?;
    Ok(executable)
}

#[cfg(all(test, unix))]
fn hash_file(path: &Path) -> Result<Digest32, TerminalToolError> {
    let file = File::open(path).map_err(|_| TerminalToolError::ProgramUnavailable)?;
    hash_open_file(&file)
}

#[derive(Debug)]
struct BoundedOutput {
    bytes: Vec<u8>,
    sha256: Digest32,
    truncated: bool,
}

#[derive(Debug)]
struct SanitizedOutput {
    text: String,
    encoding_lossy: bool,
}

fn sanitize_output(bytes: &[u8]) -> SanitizedOutput {
    let decoded = String::from_utf8_lossy(bytes);
    let encoding_lossy = matches!(&decoded, Cow::Owned(_));
    let mut text = String::with_capacity(decoded.len());
    for character in decoded.chars() {
        let disallowed = (character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
            || matches!(
                get_general_category(character),
                GeneralCategory::Format
                    | GeneralCategory::LineSeparator
                    | GeneralCategory::ParagraphSeparator
            );
        if disallowed {
            text.push('\u{fffd}');
        } else {
            text.push(character);
        }
    }
    SanitizedOutput {
        text,
        encoding_lossy,
    }
}

fn read_bounded_in_background<R>(
    mut reader: R,
    maximum: usize,
) -> mpsc::Receiver<Result<BoundedOutput, TerminalToolError>>
where
    R: Read + Send + 'static,
{
    let (sender, receiver) = mpsc::sync_channel(1);
    let _ = thread::Builder::new()
        .name("accordlock-terminal-output".to_owned())
        .spawn(move || {
            let mut retained = Vec::with_capacity(maximum.min(8 * 1024));
            let mut truncated = false;
            let mut hasher = Sha256::new();
            let mut buffer = [0_u8; 8 * 1024];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => {
                        hasher.update(&buffer[..read]);
                        let remaining = maximum.saturating_sub(retained.len());
                        retained.extend_from_slice(&buffer[..read.min(remaining)]);
                        truncated |= read > remaining;
                    }
                    Err(_) => {
                        let _ = sender.send(Err(TerminalToolError::OutputCaptureFailed));
                        return;
                    }
                }
            }
            let _ = sender.send(Ok(BoundedOutput {
                bytes: retained,
                sha256: Digest32::from_bytes(hasher.finalize().into()),
                truncated,
            }));
        });
    receiver
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum TerminalConfigError {
    #[error("terminal program alias is outside the strict profile")]
    InvalidAlias,
    #[error("terminal executable must be an existing canonical regular file")]
    InvalidExecutable,
    #[error("terminal executable digest is malformed")]
    InvalidExecutableDigest,
    #[error("terminal executable no longer matches its trusted digest")]
    ExecutableDigestMismatch,
    #[error("terminal executable must be a native platform image, not a script")]
    ExecutableFormatForbidden,
    #[error("shell and command interpreters cannot be terminal broker programs")]
    ShellExecutableForbidden,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
enum TerminalInputError {
    #[error("terminal arguments are malformed")]
    InvalidArguments,
    #[error("terminal working directory is not canonical and relative")]
    InvalidCwd,
    #[error("terminal environment is outside the allowlist")]
    InvalidEnvironment,
    #[error("terminal timeout is outside the bounded profile")]
    InvalidTimeout,
    #[error("terminal output limit is outside the bounded profile")]
    InvalidOutputLimit,
    #[error("terminal program is not configured")]
    ProgramNotConfigured,
    #[error("tool is not brokered by the terminal profile")]
    UnsupportedTool,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
enum TerminalToolError {
    #[error("WORKSPACE_UNAVAILABLE")]
    WorkspaceUnavailable,
    #[error("WORKING_DIRECTORY_UNAVAILABLE")]
    WorkingDirectoryUnavailable,
    #[error("WORKING_DIRECTORY_ESCAPES_WORKSPACE")]
    WorkingDirectoryEscapesWorkspace,
    #[error("PROGRAM_UNAVAILABLE")]
    ProgramUnavailable,
    #[error("PROGRAM_CHANGED")]
    ProgramChanged,
    #[error("PROGRAM_FORMAT_FORBIDDEN")]
    ProgramFormatForbidden,
    #[error("INVALID_EXECUTION_STATE")]
    InvalidExecutionState,
    #[error("EXECUTION_STATE_CHANGED")]
    ExecutionStateChanged,
    #[error("SPAWN_FAILED")]
    SpawnFailed,
    #[error("WAIT_FAILED")]
    WaitFailed,
    #[error("TIMED_OUT")]
    TimedOut,
    #[error("OUTPUT_CAPTURE_FAILED")]
    OutputCaptureFailed,
    #[error("PROCESS_TREE_CLEANUP_FAILED")]
    ProcessTreeCleanupFailed,
}

impl TerminalToolError {
    const fn reason_code(self) -> &'static str {
        match self {
            Self::WorkspaceUnavailable => "WORKSPACE_UNAVAILABLE",
            Self::WorkingDirectoryUnavailable => "WORKING_DIRECTORY_UNAVAILABLE",
            Self::WorkingDirectoryEscapesWorkspace => "WORKING_DIRECTORY_ESCAPES_WORKSPACE",
            Self::ProgramUnavailable => "PROGRAM_UNAVAILABLE",
            Self::ProgramChanged => "PROGRAM_CHANGED",
            Self::ProgramFormatForbidden => "PROGRAM_FORMAT_FORBIDDEN",
            Self::InvalidExecutionState => "INVALID_EXECUTION_STATE",
            Self::ExecutionStateChanged => "EXECUTION_STATE_CHANGED",
            Self::SpawnFailed => "SPAWN_FAILED",
            Self::WaitFailed => "WAIT_FAILED",
            Self::TimedOut => "TIMED_OUT",
            Self::OutputCaptureFailed => "OUTPUT_CAPTURE_FAILED",
            Self::ProcessTreeCleanupFailed => "PROCESS_TREE_CLEANUP_FAILED",
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum GovernedTerminalError {
    #[error("terminal execution request is invalid")]
    Input,
    #[error("terminal ledger is unavailable")]
    Ledger(#[from] LedgerError),
    #[error("terminal execution state is unknown")]
    ExecutionStateUnknown,
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    const PROCESS_TREE_PARENT_TEST: &str = "terminal::tests::process_tree_parent_probe";
    const PROCESS_TREE_DESCENDANT_TEST: &str = "terminal::tests::process_tree_descendant_probe";
    const DESCENDANT_STARTED_MARKER: &str = "accordlock-descendant-started";
    const DESCENDANT_COMPLETED_MARKER: &str = "accordlock-descendant-completed";
    const TIMEOUT_MODE_MARKER: &str = "accordlock-timeout-mode";

    fn proposal(arguments: Value) -> ToolCallProposal {
        let arguments_sha256 = crate::canonical::goose_digest(&arguments).unwrap_or_default();
        ToolCallProposal {
            schema_version: TOOL_EXECUTION_SCHEMA_VERSION,
            session_id: "session".to_owned(),
            run_id: "run".to_owned(),
            tool_call_id: "call".to_owned(),
            workspace_root: std::fs::canonicalize(".")
                .unwrap_or_else(|_| PathBuf::from("."))
                .to_string_lossy()
                .into_owned(),
            extension_id: "developer".to_owned(),
            tool_name: "shell".to_owned(),
            arguments,
            arguments_sha256: arguments_sha256.clone(),
            agent_plan_checkpoint: crate::model::test_agent_plan_checkpoint(
                "session",
                "run",
                "call",
                "developer__shell",
                &arguments_sha256,
                1,
            ),
        }
    }

    #[test]
    fn shell_strings_and_unknown_fields_are_not_a_terminal_contract() {
        for arguments in [
            serde_json::json!({"command": "echo unsafe"}),
            serde_json::json!({"argv": ["probe"], "pty": true}),
            serde_json::json!({"argv": ["probe"], "shell": "cmd.exe"}),
        ] {
            assert!(
                PreparedTerminalOperation::from_proposal(&proposal(arguments), &BTreeMap::new())
                    .is_err()
            );
        }
    }

    #[test]
    fn traversal_secret_environment_and_unbounded_inputs_are_rejected() {
        let executable = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("missing"));
        let program = TerminalProgram::new("probe", &executable);
        if let Ok(program) = program {
            let programs = BTreeMap::from([("probe".to_owned(), program)]);
            for arguments in [
                serde_json::json!({"argv": ["probe"], "cwd": "../escape"}),
                serde_json::json!({"argv": ["probe"], "env": {"API_TOKEN": "secret"}}),
                serde_json::json!({"argv": ["probe"], "timeout_seconds": 301}),
                serde_json::json!({"argv": ["probe"], "max_output_bytes": 262_145}),
                serde_json::json!({"argv": ["probe", "../outside"]}),
                serde_json::json!({"argv": ["probe", "--manifest-path=C:\\outside\\Cargo.toml"]}),
                serde_json::json!({"argv": ["probe", "/outside"]}),
                serde_json::json!({"argv": ["probe", "@response-file"]}),
                serde_json::json!({"argv": ["probe", "https://example.invalid/input"]}),
                serde_json::json!({"argv": ["probe", "safe\u{202e}hidden"]}),
            ] {
                assert!(
                    PreparedTerminalOperation::from_proposal(&proposal(arguments), &programs)
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn output_is_bounded_without_rewriting_captured_bytes() {
        let receiver = read_bounded_in_background(&b"abcdefgh"[..], 4);
        let output = receiver
            .recv_timeout(Duration::from_secs(1))
            .ok()
            .and_then(Result::ok);
        assert!(output.as_ref().is_some_and(|value| value.bytes == b"abcd"));
        assert!(output.as_ref().is_some_and(|value| value.truncated));
        assert_eq!(
            output.map(|value| value.sha256),
            Some(Digest32::sha256(b"abcdefgh"))
        );
    }

    #[test]
    fn terminal_output_cannot_inject_control_or_bidirectional_state() {
        let output = sanitize_output(b"ok\x1b[31mred\xe2\x80\xaehidden\n");

        assert_eq!(output.text, "ok\u{fffd}[31mred\u{fffd}hidden\n");
        assert!(!output.encoding_lossy);
    }

    #[test]
    fn linux_proc_stat_parser_distinguishes_live_members_from_zombies() {
        assert_eq!(
            proc_stat_state_and_group("123 (worker) R 1 42 42 0"),
            Some((b'R', 42))
        );
        assert_eq!(
            proc_stat_state_and_group("124 (worker) name) Z 1 42 42 0"),
            Some((b'Z', 42))
        );
        assert_eq!(proc_stat_state_and_group("malformed"), None);
    }

    #[cfg(unix)]
    #[test]
    fn unix_esrch_proves_an_observed_process_group_is_absent() {
        let absent = std::io::Error::from_raw_os_error(libc::ESRCH);
        let forbidden = std::io::Error::from_raw_os_error(libc::EPERM);

        assert!(process_group_is_absent(&absent));
        assert!(!process_group_is_absent(&forbidden));
    }

    #[test]
    fn direct_interpreters_and_versioned_interpreters_are_forbidden() {
        let executable = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("missing"));
        for alias in ["sh", "powershell", "python3", "python3.12", "node20"] {
            assert_eq!(
                TerminalProgram::new(alias, &executable),
                Err(TerminalConfigError::InvalidAlias)
            );
        }
    }

    #[test]
    fn script_files_cannot_be_provisioned_as_native_programs()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let name = if cfg!(windows) { "probe.exe" } else { "probe" };
        let executable = directory.path().join(name);
        std::fs::write(&executable, b"#!/bin/sh\necho bypass\n")?;

        assert_eq!(
            TerminalProgram::new("probe", &executable),
            Err(TerminalConfigError::ExecutableFormatForbidden)
        );
        Ok(())
    }

    #[test]
    #[ignore = "spawned only by process-tree containment tests"]
    fn process_tree_descendant_probe() -> Result<(), Box<dyn std::error::Error>> {
        std::fs::write(DESCENDANT_STARTED_MARKER, b"started")?;
        thread::sleep(Duration::from_secs(4));
        std::fs::write(DESCENDANT_COMPLETED_MARKER, b"completed")?;
        Ok(())
    }

    #[test]
    #[ignore = "spawned only by process-tree containment tests"]
    fn process_tree_parent_probe() -> Result<(), Box<dyn std::error::Error>> {
        let mut descendant = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                PROCESS_TREE_DESCENDANT_TEST,
                "--ignored",
                "--nocapture",
            ])
            .spawn()?;
        let readiness_deadline = Instant::now() + Duration::from_secs(2);
        while !Path::new(DESCENDANT_STARTED_MARKER).exists() && Instant::now() < readiness_deadline
        {
            thread::sleep(Duration::from_millis(10));
        }
        if !Path::new(DESCENDANT_STARTED_MARKER).exists() {
            let _ = descendant.kill();
            return Err("descendant did not start".into());
        }
        if Path::new(TIMEOUT_MODE_MARKER).exists() {
            thread::sleep(Duration::from_mins(1));
        }
        Ok(())
    }

    fn process_tree_operation(
        workspace: &Path,
        timeout: Duration,
    ) -> Result<(PreparedTerminalOperation, Digest32), Box<dyn std::error::Error>> {
        let executable = std::env::current_exe()?;
        let operation = PreparedTerminalOperation {
            program: TerminalProgram::new("probe", &executable)?,
            arguments: vec![
                "--exact".to_owned(),
                PROCESS_TREE_PARENT_TEST.to_owned(),
                "--ignored".to_owned(),
                "--nocapture".to_owned(),
            ],
            cwd: ValidatedRelativeDirectory::new(".")?,
            environment: BTreeMap::new(),
            timeout,
            max_output_bytes: DEFAULT_OUTPUT_BYTES as usize,
        };
        let expected_prestate = operation.prestate(workspace)?.digest()?;
        Ok((operation, expected_prestate))
    }

    #[test]
    fn natural_parent_exit_cannot_leave_a_background_descendant()
    -> Result<(), Box<dyn std::error::Error>> {
        let workspace = tempfile::tempdir()?;
        let (operation, expected_prestate) =
            process_tree_operation(workspace.path(), Duration::from_secs(10))?;

        let result = operation.execute(workspace.path(), expected_prestate)?;

        assert_eq!(result.outcome, TerminalProcessOutcome::Succeeded);
        assert!(workspace.path().join(DESCENDANT_STARTED_MARKER).exists());
        thread::sleep(Duration::from_secs(5));
        assert!(!workspace.path().join(DESCENDANT_COMPLETED_MARKER).exists());
        Ok(())
    }

    #[test]
    fn timeout_terminates_the_complete_process_tree() -> Result<(), Box<dyn std::error::Error>> {
        let workspace = tempfile::tempdir()?;
        std::fs::write(workspace.path().join(TIMEOUT_MODE_MARKER), b"timeout")?;
        let (operation, expected_prestate) =
            process_tree_operation(workspace.path(), Duration::from_secs(2))?;

        let result = operation.execute(workspace.path(), expected_prestate);

        assert_eq!(result, Err(TerminalToolError::TimedOut));
        assert!(workspace.path().join(DESCENDANT_STARTED_MARKER).exists());
        thread::sleep(Duration::from_secs(5));
        assert!(!workspace.path().join(DESCENDANT_COMPLETED_MARKER).exists());
        Ok(())
    }

    #[test]
    fn reported_execution_error_has_an_explicit_unknown_execution_status()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = execution_state_unknown_response(
            Digest32::sha256(b"proposal").to_string(),
            uuid::Uuid::from_u128(1).to_string(),
            Digest32::sha256(b"request").to_string(),
            ObservationResult {
                authorization_id: uuid::Uuid::from_u128(1),
                observation_digest: Digest32::sha256(b"observation").to_string(),
                record_id: uuid::Uuid::from_u128(2),
                record_hash: Digest32::sha256(b"record").to_string(),
            },
            "TIMED_OUT",
        );
        let wire = serde_json::to_value(response)?;

        assert_eq!(wire["status"], "EXECUTION_UNKNOWN");
        assert_eq!(wire["reason_code"], "TIMED_OUT");
        assert!(wire.get("result").is_none());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn digest_pinned_program_is_rejected_after_replacement()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let name = if cfg!(windows) { "probe.exe" } else { "probe" };
        let executable = directory.path().join(name);
        std::fs::copy(std::env::current_exe()?, &executable)?;
        let digest = hash_file(&executable)?.to_string();
        let program = TerminalProgram::new_with_expected_digest("probe", &executable, &digest)?;

        std::fs::write(&executable, b"substituted executable")?;

        assert_eq!(
            canonical_program(&program),
            Err(TerminalToolError::ProgramChanged)
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn identical_bytes_at_a_different_file_identity_are_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let name = if cfg!(windows) { "probe.exe" } else { "probe" };
        let executable = directory.path().join(name);
        let replacement = directory.path().join(if cfg!(windows) {
            "replacement.exe"
        } else {
            "replacement"
        });
        std::fs::copy(std::env::current_exe()?, &executable)?;
        std::fs::copy(std::env::current_exe()?, &replacement)?;
        let program = TerminalProgram::new("probe", &executable)?;

        std::fs::remove_file(&executable)?;
        std::fs::rename(&replacement, &executable)?;

        assert_eq!(
            canonical_program(&program),
            Err(TerminalToolError::ProgramChanged)
        );
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn pinned_windows_handle_blocks_write_and_delete_until_spawn_finishes()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let executable = directory.path().join("probe.exe");
        std::fs::copy(std::env::current_exe()?, &executable)?;
        let program = TerminalProgram::new("probe", &executable)?;
        let opened = open_pinned_program(&program)?;

        assert!(std::fs::write(&executable, b"replacement").is_err());
        assert!(std::fs::remove_file(&executable).is_err());
        drop(opened);
        drop(program);
        assert!(std::fs::remove_file(&executable).is_ok());
        Ok(())
    }

    #[test]
    fn provisioning_digest_must_match_selected_program() -> Result<(), Box<dyn std::error::Error>> {
        let executable = std::env::current_exe()?;

        assert_eq!(
            TerminalProgram::new_with_expected_digest(
                "probe",
                &executable,
                &Digest32::sha256(b"substitution").to_string(),
            ),
            Err(TerminalConfigError::ExecutableDigestMismatch)
        );
        Ok(())
    }
}
