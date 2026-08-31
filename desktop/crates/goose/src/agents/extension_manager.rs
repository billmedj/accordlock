use anyhow::Result;
#[cfg(unix)]
use axum::http::HeaderValue;
use axum::http::{HeaderMap, HeaderName};
use chrono::{DateTime, Utc};
use futures::stream::{self, FuturesUnordered, StreamExt};
use futures::Stream;
use futures::{future, FutureExt};
use once_cell::sync::Lazy;
use rmcp::service::{ClientInitializeError, ServiceError};
use rmcp::transport::streamable_http_client::{
    StreamableHttpClientTransportConfig, StreamableHttpError,
};
use rmcp::transport::{
    ConfigureCommandExt, DynamicTransportError, StreamableHttpClientTransport, TokioChildProcess,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tracing::{error, warn};

use super::accordlock_authorization::{
    default_policy_enforcement_point, ExecutionOutcome, PolicyEnforcementError,
    PolicyEnforcementPoint, ToolExecutionObservation, ToolExecutionRequest,
};
use super::accordlock_filesystem::{
    classify as classify_filesystem_tool, default_filesystem_broker, FilesystemBroker,
    FilesystemRoute,
};
use super::accordlock_network::{
    default_network_broker, is_brokered as is_brokered_network_tool,
    normalize_tool_arguments as normalize_network_tool_arguments, NetworkBroker,
};
use super::accordlock_terminal::{
    default_terminal_broker, is_brokered as is_brokered_terminal_tool, TerminalBroker,
};
use super::container::Container;
use super::extension::{
    ExtensionConfig, ExtensionError, ExtensionInfo, ExtensionResult, PlatformExtensionContext,
    ToolInfo, PLATFORM_EXTENSIONS,
};
use super::tool_execution::{ToolCallContext, ToolCallNotificationEmitter, ToolCallResult};
use super::types::SharedProvider;
use crate::action_required_manager::ActionRequiredManager;
use crate::agents::extension::{Envs, ProcessExit};
use crate::agents::extension_malware_check;
use crate::agents::mcp_client::{
    GooseMcpClientCapabilities, GooseMcpHostInfo, McpClient, McpClientTrait,
};
use crate::builtin_extension::get_builtin_extension;
use crate::config::extensions::name_to_key;
use crate::config::search_path::SearchPaths;
use crate::config::{get_all_extensions, Config};
use crate::oauth::{oauth_flow, GooseCredentialStore, StaticOAuthClientConfig};
use crate::prompt_template;
use crate::subprocess::configure_subprocess;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ContentBlock, ErrorCode, ErrorData, GetPromptResult,
    MetaObject, Prompt, Resource, ResourceContents, ServerInfo, ServerNotification, Tool,
};
use rmcp::transport::auth::{AuthClient, CredentialStore};
use serde_json::Value;

type McpClientBox = Arc<dyn McpClientTrait>;

const TOOL_CALL_NOTIFICATION_CHANNEL_CAPACITY: usize = 32;

const ACCORDLOCK_AUTHORITY_ENV_KEYS: [&str; 3] = [
    "ACCORDLOCK_RUNTIME_URL",
    "ACCORDLOCK_RUNTIME_TOKEN",
    "ACCORDLOCK_BACKEND_BINDING_SECRET",
];
const MCP_APP_RESOURCE_FAILURE_MESSAGE: &str = "AccordLock could not load this tool view. Retry the tool or open its result without the embedded view.";
const RESOURCE_READ_FAILURE_MESSAGE: &str =
    "AccordLock could not read this resource. Check the connection and try again.";
const RESOURCE_LIST_FAILURE_MESSAGE: &str =
    "AccordLock could not list resources for this connection. Check the connection and try again.";
const TOOL_LIST_FAILURE_MESSAGE: &str =
    "AccordLock could not load the available tools. Check the connection and try again.";
const TOOL_UNAVAILABLE_MESSAGE: &str =
    "The requested tool is unavailable. Refresh tools or choose another tool.";
const TOOL_DISABLED_MESSAGE: &str =
    "The requested tool is disabled. Enable it in Settings and try again.";
const TOOL_REQUEST_FAILURE_MESSAGE: &str =
    "AccordLock could not complete this tool request. Check the connection and try again.";
const TOOL_REPORTED_FAILURE_MESSAGE: &str =
    "The tool reported an error. Check its connection or inputs, then try again.";
const PROMPT_LIST_FAILURE_MESSAGE: &str =
    "AccordLock could not list prompts for this connection. Check the connection and try again.";
const PROMPT_LOAD_FAILURE_MESSAGE: &str =
    "AccordLock could not load that prompt. Check the prompt name and connection, then try again.";

// `ExtensionResult` is the upstream manager contract; its error enum contains
// process-initialization diagnostics that are intentionally large.
#[allow(clippy::result_large_err)]
pub(super) fn enforce_accordlock_extension_policy(
    config: &ExtensionConfig,
    containerized: bool,
) -> ExtensionResult<()> {
    #[cfg(feature = "accordlock-distribution")]
    {
        let built_in_developer = matches!(
            config,
            ExtensionConfig::Builtin { name, .. } | ExtensionConfig::Platform { name, .. }
                if name_to_key(name) == "developer"
        );
        if !built_in_developer || containerized {
            return Err(ExtensionError::ConfigError(
                "AccordLock permits only its policy-enforced developer extension".to_string(),
            ));
        }
    }

    #[cfg(not(feature = "accordlock-distribution"))]
    let _ = (config, containerized);

    Ok(())
}

/// Defense in depth for extension transports. In particular, Docker receives
/// extension environment values as command-line `-e KEY=VALUE` arguments, so
/// scrubbing the host process environment alone is insufficient.
fn strip_accordlock_authority_env(envs: &mut HashMap<String, String>) {
    envs.retain(|key, _| {
        !ACCORDLOCK_AUTHORITY_ENV_KEYS
            .iter()
            .any(|authority_key| authority_key.eq_ignore_ascii_case(key))
    });
}

fn policy_enforcement_error_data(error: PolicyEnforcementError) -> ErrorData {
    let execution_status_unknown = matches!(&error, PolicyEnforcementError::ExecutionUnknown);
    let (error_code, reason_code, message) = match &error {
        PolicyEnforcementError::Denied(reason) => (
            ErrorCode::INVALID_REQUEST,
            reason.as_str(),
            format!(
                "AccordLock denied this exact tool call ({reason}). Do not retry it unchanged."
            ),
        ),
        PolicyEnforcementError::ApprovalRequired(reason) => (
            ErrorCode::INVALID_REQUEST,
            reason.as_str(),
            format!(
                "AccordLock requires approval for this exact tool call ({reason})."
            ),
        ),
        PolicyEnforcementError::ExecutionUnknown => (
            ErrorCode::INTERNAL_ERROR,
            "EXECUTION_STATUS_UNKNOWN",
            "AccordLock could not commit the execution record. The execution status is unknown; do not retry automatically."
                .to_owned(),
        ),
        _ => (
            ErrorCode::INTERNAL_ERROR,
            "POLICY_ENFORCEMENT_UNAVAILABLE",
            "AccordLock could not authorize this exact tool call. No tool was executed."
                .to_owned(),
        ),
    };
    ErrorData::new(
        error_code,
        message,
        Some(serde_json::json!({
            "accordlock": {
                "schemaVersion": 2,
                "reasonCode": reason_code,
                "executionMayHaveOccurred": execution_status_unknown,
                "executionStatus": if execution_status_unknown {
                    "UNKNOWN"
                } else {
                    "NOT_EXECUTED"
                }
            }
        })),
    )
}

struct ActionRequiredStream {
    inner: ReceiverStream<crate::conversation::message::Message>,
    manager: Arc<ActionRequiredManager>,
    session_id: String,
    tool_call_request_id: String,
}

impl ActionRequiredStream {
    fn new(
        receiver: tokio::sync::mpsc::Receiver<crate::conversation::message::Message>,
        manager: Arc<ActionRequiredManager>,
        session_id: String,
        tool_call_request_id: String,
    ) -> Self {
        Self {
            inner: ReceiverStream::new(receiver),
            manager,
            session_id,
            tool_call_request_id,
        }
    }
}

impl Stream for ActionRequiredStream {
    type Item = crate::conversation::message::Message;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(cx)
    }
}

impl Drop for ActionRequiredStream {
    fn drop(&mut self) {
        let manager = self.manager.clone();
        let session_id = self.session_id.clone();
        let tool_call_request_id = self.tool_call_request_id.clone();
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        handle.spawn(async move {
            manager
                .unregister_action_required_stream(&session_id, &tool_call_request_id)
                .await;
        });
    }
}

static RE_ENV_BRACES: Lazy<regex::Regex> =
    Lazy::new(|| regex::Regex::new(r"\$\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}").expect("valid regex"));

static RE_ENV_SIMPLE: Lazy<regex::Regex> =
    Lazy::new(|| regex::Regex::new(r"\$([A-Za-z_][A-Za-z0-9_]*)").expect("valid regex"));

fn resolve_timeout(timeout: Option<u64>) -> u64 {
    timeout.unwrap_or_else(|| {
        Config::global()
            .get_goose_default_extension_timeout()
            .unwrap_or(crate::config::DEFAULT_EXTENSION_TIMEOUT)
    })
}

struct Extension {
    pub config: ExtensionConfig,
    /// Resolved config snapshot (with secrets from keyring substituted)
    /// captured at client-creation time. Used to detect secret rotation
    /// without re-reading the keyring on every comparison. Only held in
    /// memory — never serialized to disk.
    resolved_config: ExtensionConfig,

    client: McpClientBox,
    server_info: Option<ServerInfo>,
    _temp_dir: Option<tempfile::TempDir>,
}

impl Extension {
    fn new(
        config: ExtensionConfig,
        resolved_config: ExtensionConfig,
        client: McpClientBox,
        server_info: Option<ServerInfo>,
        temp_dir: Option<tempfile::TempDir>,
    ) -> Self {
        Self {
            client,
            config,
            resolved_config,
            server_info,
            _temp_dir: temp_dir,
        }
    }

    fn supports_resources(&self) -> bool {
        self.server_info
            .as_ref()
            .and_then(|info| info.capabilities.resources.as_ref())
            .is_some()
    }

    fn get_instructions(&self) -> Option<String> {
        self.client.get_instructions()
    }

    fn get_client(&self) -> McpClientBox {
        self.client.clone()
    }
}

pub struct ExtensionManagerCapabilities {
    pub mcpui: bool,
    pub host_info: Option<GooseMcpHostInfo>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GooseMcpAppToolAttachment {
    pub tool_name: String,
    pub tool_name_is_actual: bool,
    pub extension_name: String,
    pub resource_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_meta: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_error: Option<String>,
}

pub(crate) const TRUSTED_TOOL_UPDATE_META_KEY: &str = "__goose_tool_update_meta";

/// Manages goose extensions / MCP clients and their interactions
pub struct ExtensionManager {
    extensions: Mutex<HashMap<String, Extension>>,
    context: PlatformExtensionContext,
    provider: SharedProvider,
    tools_cache: Mutex<Option<Arc<Vec<Tool>>>>,
    tools_cache_version: AtomicU64,
    client_name: String,
    capabilities: ExtensionManagerCapabilities,
    policy_enforcement_point: Arc<dyn PolicyEnforcementPoint>,
    filesystem_broker: Arc<dyn FilesystemBroker>,
    terminal_broker: Arc<dyn TerminalBroker>,
    network_broker: Arc<dyn NetworkBroker>,
}

/// A flattened representation of a resource used by the agent to prepare inference
#[derive(Debug, Clone)]
pub struct ResourceItem {
    pub extension_name: String, // The name of the extension that owns the resource
    pub uri: String,            // The URI of the resource
    pub name: String,           // The name of the resource
    pub content: String,        // The content of the resource
    pub timestamp: DateTime<Utc>, // The timestamp of the resource
    pub priority: f32,          // The priority of the resource
    pub token_count: Option<u32>, // The token count of the resource (filled in by the agent)
}

impl ResourceItem {
    pub fn new(
        extension_name: String,
        uri: String,
        name: String,
        content: String,
        timestamp: DateTime<Utc>,
        priority: f32,
    ) -> Self {
        Self {
            extension_name,
            uri,
            name,
            content,
            timestamp,
            priority,
            token_count: None,
        }
    }
}

fn resolve_command(cmd: &str) -> PathBuf {
    SearchPaths::builder()
        .with_npm()
        .resolve(cmd)
        .unwrap_or_else(|_| {
            // let the OS raise the error
            PathBuf::from(cmd)
        })
}

fn require_str_parameter<'a>(v: &'a serde_json::Value, name: &str) -> Result<&'a str, ErrorData> {
    let v = v.get(name).ok_or_else(|| {
        ErrorData::new(
            ErrorCode::INVALID_PARAMS,
            format!("The parameter {name} is required"),
            None,
        )
    })?;
    match v.as_str() {
        Some(r) => Ok(r),
        None => Err(ErrorData::new(
            ErrorCode::INVALID_PARAMS,
            format!("The parameter {name} must be a string"),
            None,
        )),
    }
}

pub fn get_parameter_names(tool: &Tool) -> Vec<String> {
    let mut names: Vec<String> = tool
        .input_schema
        .get("properties")
        .and_then(|props| props.as_object())
        .map(|props| props.keys().cloned().collect())
        .unwrap_or_default();
    names.sort();
    names
}

const TOOL_EXTENSION_META_KEY: &str = "goose_extension";

pub fn get_tool_owner(tool: &Tool) -> Option<String> {
    tool.meta
        .as_ref()
        .and_then(|m| m.0.get(TOOL_EXTENSION_META_KEY))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn recover_mangled_tool_name<'a>(
    emitted: &str,
    tool_names: impl Iterator<Item = &'a str>,
) -> Option<String> {
    let trimmed = emitted.trim();
    let stripped = trimmed
        .strip_prefix("functions.")
        .or_else(|| trimmed.strip_prefix("functions:"))
        .unwrap_or(trimmed);

    let mut matched: Option<&str> = None;
    for name in tool_names {
        let separator_mangled = name
            .split_once("__")
            .map(|(extension, tool)| format!("{extension}.{tool}"));

        let matches = stripped == name || separator_mangled.as_deref() == Some(stripped);
        if name == emitted || !matches {
            continue;
        }

        match matched {
            None => matched = Some(name),
            Some(prev) if prev == name => {}
            Some(_) => return None,
        }
    }
    matched.map(|s| s.to_string())
}

fn get_tool_meta_value(tool: &Tool) -> Option<Value> {
    tool.meta.as_ref().map(|meta| Value::Object(meta.0.clone()))
}

pub(crate) fn get_tool_resource_uri(tool: &Tool) -> Option<String> {
    tool.meta
        .as_ref()
        .and_then(|meta| meta.0.get("ui"))
        .and_then(Value::as_object)
        .and_then(|ui| ui.get("resourceUri"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn remove_untrusted_mcp_app_meta(result: &mut CallToolResult) {
    let Some(meta) = result.meta.as_mut() else {
        return;
    };

    meta.0.remove(TRUSTED_TOOL_UPDATE_META_KEY);

    let remove_goose = meta
        .0
        .get_mut("goose")
        .and_then(Value::as_object_mut)
        .map(|goose_meta| {
            goose_meta.remove("mcpApp");
            goose_meta.is_empty()
        })
        .unwrap_or(false);

    if remove_goose {
        meta.0.remove("goose");
    }

    if meta.0.is_empty() {
        result.meta = None;
    }
}

fn insert_trusted_tool_update_meta(
    result: &mut CallToolResult,
    attachment: &GooseMcpAppToolAttachment,
) {
    let Ok(attachment_value) = serde_json::to_value(attachment) else {
        return;
    };

    let mut meta_map = result
        .meta
        .as_ref()
        .map(|meta| meta.0.clone())
        .unwrap_or_default();
    let mut trusted_meta = serde_json::Map::new();
    trusted_meta.insert("mcpApp".to_string(), attachment_value);
    meta_map.insert(
        TRUSTED_TOOL_UPDATE_META_KEY.to_string(),
        Value::Object(trusted_meta),
    );
    result.meta = Some(MetaObject(meta_map));
}

fn is_unprefixed_extension(config: &ExtensionConfig) -> bool {
    match config {
        ExtensionConfig::Platform { name, .. } | ExtensionConfig::Builtin { name, .. } => {
            PLATFORM_EXTENSIONS
                .get(name_to_key(name).as_str())
                .is_some_and(|def| def.unprefixed_tools)
        }
        _ => false,
    }
}

/// Returns true if the named extension is a first-class platform extension
/// whose tools are exposed unprefixed and remain visible during code execution mode.
pub fn is_first_class_extension(name: &str) -> bool {
    PLATFORM_EXTENSIONS
        .get(name_to_key(name).as_str())
        .is_some_and(|def| def.unprefixed_tools)
}

pub fn is_hidden_extension(name: &str) -> bool {
    PLATFORM_EXTENSIONS
        .get(name_to_key(name).as_str())
        .is_some_and(|def| def.hidden)
}

/// Result of resolving a tool call to its owning extension
struct ResolvedTool {
    extension_name: String,
    actual_tool_name: String,
    client: McpClientBox,
    tool_available: bool,
    tool_meta: Option<Value>,
    resource_uri: Option<String>,
}

#[allow(clippy::too_many_arguments)]
async fn child_process_client(
    mut command: Command,
    timeout: &Option<u64>,
    provider: SharedProvider,
    working_dir: &PathBuf,
    docker_container: Option<String>,
    client_name: String,
    capabilities: GooseMcpClientCapabilities,
    action_required: Arc<ActionRequiredManager>,
    extension_manager: Weak<ExtensionManager>,
) -> ExtensionResult<McpClient> {
    configure_subprocess(&mut command);

    if let Ok(path) = SearchPaths::builder().path() {
        command.env("PATH", path);
    }

    if working_dir.exists() && working_dir.is_dir() {
        tracing::info!("Setting MCP process working directory: {:?}", working_dir);
        command.current_dir(working_dir);
    } else {
        tracing::warn!(
            "Working directory doesn't exist or isn't a directory: {:?}",
            working_dir
        );
    }

    let (transport, mut stderr) = TokioChildProcess::builder(command)
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stderr = stderr.take().ok_or_else(|| {
        ExtensionError::SetupError("failed to attach child process stderr".to_owned())
    })?;

    let stderr_task = tokio::spawn(async move {
        let mut all_stderr = Vec::new();
        stderr.read_to_end(&mut all_stderr).await?;
        Ok::<String, std::io::Error>(String::from_utf8_lossy(&all_stderr).into())
    });

    let client_result = McpClient::connect_with_container(
        transport,
        Duration::from_secs(resolve_timeout(*timeout)),
        provider,
        docker_container,
        client_name,
        capabilities,
        working_dir.clone(),
        action_required,
        extension_manager,
    )
    .await;

    match client_result {
        Ok(client) => Ok(client),
        Err(error) => {
            let error_task_out = stderr_task.await?;
            Err::<McpClient, ExtensionError>(match error_task_out {
                Ok(stderr_content) => ProcessExit::new(stderr_content, error).into(),
                Err(e) => e.into(),
            })
        }
    }
}

/// Retry with OAuth for typed auth challenges and wrapped bare HTTP 401 responses.
fn is_oauth_auth_failure(err: &ClientInitializeError) -> bool {
    let ClientInitializeError::TransportError {
        error: DynamicTransportError { error, .. },
        ..
    } = err
    else {
        return false;
    };

    if let Some(http_err) = error.downcast_ref::<StreamableHttpError<reqwest::Error>>() {
        return match http_err {
            StreamableHttpError::AuthRequired(_) => true,
            StreamableHttpError::UnexpectedServerResponse(body) => body.starts_with("HTTP 401"),
            _ => false,
        };
    }

    #[cfg(unix)]
    if let Some(http_err) = error
        .downcast_ref::<StreamableHttpError<rmcp::transport::common::unix_socket::UnixSocketError>>(
        )
    {
        return match http_err {
            StreamableHttpError::AuthRequired(_) => true,
            StreamableHttpError::UnexpectedServerResponse(body) => body.starts_with("HTTP 401"),
            _ => false,
        };
    }

    error
        .to_string()
        .contains("unexpected server response: HTTP 401")
}

fn should_attempt_oauth_fallback(res: &Result<McpClient, ClientInitializeError>) -> bool {
    res.as_ref().err().is_some_and(is_oauth_auth_failure)
}

async fn clear_credentials_on_post_refresh_auth_failure(
    credential_store: &dyn CredentialStore,
    name: &str,
    error: &ExtensionError,
) -> bool {
    let ExtensionError::InitializeError(err) = error else {
        return false;
    };

    if !is_oauth_auth_failure(err) {
        return false;
    }

    if let Err(e) = credential_store.clear().await {
        warn!(
            "[OAuth:{}] error clearing rejected credentials: {}",
            name, e
        );
    }
    true
}

/// Merge environment variables from direct envs and keychain-stored env_keys
pub(crate) async fn merge_environments(
    envs: &Envs,
    env_keys: &[String],
    ext_name: &str,
    config: &Config,
) -> Result<HashMap<String, String>, ExtensionError> {
    let mut all_envs = envs.get_env();

    for key in env_keys {
        if all_envs.contains_key(key) {
            continue;
        }

        match config.get(key, true) {
            Ok(value) => {
                if value.is_null() {
                    warn!(
                        key = %key,
                        ext_name = %ext_name,
                        "Secret key not found in config (returned null)."
                    );
                    continue;
                }

                if let Some(str_val) = value.as_str() {
                    all_envs.insert(key.clone(), str_val.to_string());
                } else {
                    warn!(
                        key = %key,
                        ext_name = %ext_name,
                        value_type = %value.get("type").and_then(|t| t.as_str()).unwrap_or("unknown"),
                        "Secret value is not a string; skipping."
                    );
                }
            }
            Err(e) => {
                error!(
                    key = %key,
                    ext_name = %ext_name,
                    error = %e,
                    "Failed to fetch secret from config."
                );
                return Err(ExtensionError::ConfigError(format!(
                    "Failed to fetch secret '{}' from config: {}",
                    key, e
                )));
            }
        }
    }

    strip_accordlock_authority_env(&mut all_envs);
    Ok(Envs::new(all_envs).get_env())
}

/// Build the pre-registered OAuth client config for a streamable_http
/// extension. The secret is referenced by key and resolved from the merged
/// environment or the config secret store, so it is never stored inline in
/// the extension config.
fn resolve_static_oauth_client(
    client_id: Option<&str>,
    client_secret_key: Option<&str>,
    scopes: &[String],
    envs: &HashMap<String, String>,
    config: &Config,
) -> Result<Option<StaticOAuthClientConfig>, Box<ExtensionError>> {
    let Some(client_id) = client_id else {
        if client_secret_key.is_some() {
            return Err(Box::new(ExtensionError::ConfigError(
                "client_secret_key requires client_id".to_string(),
            )));
        }
        if !scopes.is_empty() {
            return Err(Box::new(ExtensionError::ConfigError(
                "scopes requires client_id".to_string(),
            )));
        }
        return Ok(None);
    };

    let client_secret = match client_secret_key {
        Some(key) => Some(resolve_secret_value(key, envs, config)?),
        None => None,
    };

    Ok(Some(StaticOAuthClientConfig {
        client_id: substitute_env_vars(client_id, envs),
        client_secret,
        scopes: scopes.to_vec(),
    }))
}

fn resolve_secret_value(
    key: &str,
    envs: &HashMap<String, String>,
    config: &Config,
) -> Result<String, Box<ExtensionError>> {
    if let Some(value) = envs.get(key) {
        return Ok(value.clone());
    }

    let value = config.get(key, true).map_err(|error| {
        Box::new(ExtensionError::ConfigError(format!(
            "Failed to fetch secret '{}' from config: {}",
            key, error
        )))
    })?;

    value.as_str().map(str::to_string).ok_or_else(|| {
        Box::new(ExtensionError::ConfigError(format!(
            "Secret '{}' is not a string",
            key
        )))
    })
}

/// Substitute environment variables in a string. Supports both ${VAR} and $VAR syntax.
pub(crate) fn substitute_env_vars(value: &str, env_map: &HashMap<String, String>) -> String {
    let mut result = value.to_string();

    for cap in RE_ENV_BRACES.captures_iter(value) {
        if let Some(var_name) = cap.get(1) {
            if let Some(env_value) = env_map.get(var_name.as_str()) {
                result = result.replace(&cap[0], env_value);
            }
        }
    }

    // Scan the original input for $VAR patterns (not the post-substitution result)
    // to avoid recursive expansion when a substituted value contains $OTHER_VAR.
    for cap in RE_ENV_SIMPLE.captures_iter(value) {
        if let Some(var_name) = cap.get(1) {
            if !value.contains(&format!("${{{}}}", var_name.as_str())) {
                if let Some(env_value) = env_map.get(var_name.as_str()) {
                    result = result.replace(&cap[0], env_value);
                }
            }
        }
    }

    result
}

const GOOSE_USER_AGENT: reqwest::header::HeaderValue =
    reqwest::header::HeaderValue::from_static(concat!("goose/", env!("CARGO_PKG_VERSION")));

#[allow(clippy::too_many_arguments)]
async fn connect_with_auth(
    auth_manager: rmcp::transport::AuthorizationManager,
    action_required: Arc<ActionRequiredManager>,
    uri: &str,
    timeout: Duration,
    headers: &HashMap<String, String>,
    provider: SharedProvider,
    client_name: String,
    capabilities: GooseMcpClientCapabilities,
    roots_dir: &std::path::Path,
    extension_manager: Weak<ExtensionManager>,
) -> ExtensionResult<Box<dyn McpClientTrait>> {
    let mut auth_headers = HeaderMap::new();
    auth_headers.insert(reqwest::header::USER_AGENT, GOOSE_USER_AGENT);
    for (key, value) in headers {
        auth_headers.insert(
            HeaderName::try_from(key)
                .map_err(|_| ExtensionError::ConfigError(format!("invalid header: {}", key)))?,
            value.parse().map_err(|_| {
                ExtensionError::ConfigError(format!("invalid header value: {}", key))
            })?,
        );
    }
    #[allow(unused_mut)]
    let mut auth_client_builder = reqwest::Client::builder().default_headers(auth_headers);
    #[cfg(target_os = "linux")]
    {
        auth_client_builder = auth_client_builder.tcp_user_timeout(Some(timeout));
    }
    let auth_http_client = auth_client_builder
        .build()
        .map_err(|_| ExtensionError::ConfigError("could not construct http client".to_string()))?;
    let auth_client = AuthClient::new(auth_http_client, auth_manager);
    let transport = StreamableHttpClientTransport::with_client(
        auth_client,
        StreamableHttpClientTransportConfig::with_uri(uri),
    );
    Ok(Box::new(
        McpClient::connect(
            transport,
            timeout,
            provider,
            client_name,
            capabilities,
            roots_dir.to_path_buf(),
            action_required,
            extension_manager,
        )
        .await?,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn create_streamable_http_client(
    uri: &str,
    timeout: Option<u64>,
    headers: &HashMap<String, String>,
    name: &str,
    socket: Option<&str>,
    static_oauth_client: Option<StaticOAuthClientConfig>,
    credential_store: Box<dyn CredentialStore>,
    provider: SharedProvider,
    client_name: String,
    capabilities: GooseMcpClientCapabilities,
    roots_dir: &std::path::Path,
    action_required: Arc<ActionRequiredManager>,
    extension_manager: Weak<ExtensionManager>,
) -> ExtensionResult<Box<dyn McpClientTrait>> {
    #[cfg(unix)]
    if let Some(socket_path) = socket {
        return create_unix_socket_http_client(
            uri,
            timeout,
            headers,
            name,
            socket_path,
            provider,
            client_name,
            capabilities,
            roots_dir,
            action_required,
            extension_manager,
        )
        .await;
    }
    #[cfg(not(unix))]
    if socket.is_some() {
        return Err(ExtensionError::ConfigError(
            "Unix domain socket transport is not supported on this platform".to_string(),
        ));
    }

    let mut default_headers = HeaderMap::new();

    default_headers.insert(reqwest::header::USER_AGENT, GOOSE_USER_AGENT);

    for (key, value) in headers {
        default_headers.insert(
            HeaderName::try_from(key)
                .map_err(|_| ExtensionError::ConfigError(format!("invalid header: {}", key)))?,
            value.parse().map_err(|_| {
                ExtensionError::ConfigError(format!("invalid header value: {}", key))
            })?,
        );
    }

    let timeout_duration = Duration::from_secs(resolve_timeout(timeout));

    #[allow(unused_mut)]
    let mut http_client_builder = reqwest::Client::builder().default_headers(default_headers);
    #[cfg(target_os = "linux")]
    {
        http_client_builder = http_client_builder.tcp_user_timeout(Some(timeout_duration));
    }
    let http_client = http_client_builder
        .build()
        .map_err(|_| ExtensionError::ConfigError("could not construct http client".to_string()))?;

    let transport = StreamableHttpClientTransport::with_client(
        http_client,
        StreamableHttpClientTransportConfig::with_uri(uri),
    );

    // If we have stored OAuth credentials, try refreshing and connecting directly.
    // This avoids the unnecessary 401 → browser re-auth cycle on every new session.
    if credential_store.load().await.is_ok_and(|c| c.is_some()) {
        match oauth_flow(
            &uri.to_string(),
            &name.to_string(),
            static_oauth_client.as_ref(),
        )
        .await
        {
            Ok(auth_manager) => {
                let auth_result = connect_with_auth(
                    auth_manager,
                    action_required.clone(),
                    uri,
                    timeout_duration,
                    headers,
                    provider.clone(),
                    client_name.clone(),
                    capabilities.clone(),
                    roots_dir,
                    extension_manager.clone(),
                )
                .await;

                if let Err(error) = &auth_result {
                    if clear_credentials_on_post_refresh_auth_failure(
                        credential_store.as_ref(),
                        name,
                        error,
                    )
                    .await
                    {
                        warn!(
                            "[OAuth:{}] Refreshed token was rejected, falling back to browser auth",
                            name
                        );
                    } else {
                        return auth_result;
                    }
                } else {
                    return auth_result;
                }
            }
            Err(e) => {
                warn!(
                    "[OAuth:{}] Proactive refresh failed: {}, falling back to unauthenticated attempt",
                    name, e
                );
            }
        }
    }

    let client_res = McpClient::connect(
        transport,
        timeout_duration,
        provider.clone(),
        client_name.clone(),
        capabilities.clone(),
        roots_dir.to_path_buf(),
        action_required.clone(),
        extension_manager.clone(),
    )
    .await;

    if should_attempt_oauth_fallback(&client_res) {
        match oauth_flow(
            &uri.to_string(),
            &name.to_string(),
            static_oauth_client.as_ref(),
        )
        .await
        {
            Ok(auth_manager) => {
                connect_with_auth(
                    auth_manager,
                    action_required,
                    uri,
                    timeout_duration,
                    headers,
                    provider,
                    client_name,
                    capabilities,
                    roots_dir,
                    extension_manager,
                )
                .await
            }
            Err(e) => {
                warn!(
                    "[OAuth:{}] Browser authorization flow failed: {:#}",
                    name, e
                );
                Ok(Box::new(client_res?))
            }
        }
    } else {
        Ok(Box::new(client_res?))
    }
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
async fn create_unix_socket_http_client(
    uri: &str,
    timeout: Option<u64>,
    headers: &HashMap<String, String>,
    name: &str,
    socket_path: &str,
    provider: SharedProvider,
    client_name: String,
    capabilities: GooseMcpClientCapabilities,
    roots_dir: &std::path::Path,
    action_required: Arc<ActionRequiredManager>,
    extension_manager: Weak<ExtensionManager>,
) -> ExtensionResult<Box<dyn McpClientTrait>> {
    use rmcp::transport::UnixSocketHttpClient;

    let unix_client = UnixSocketHttpClient::new(socket_path, uri);

    let mut custom_headers = std::collections::HashMap::<HeaderName, HeaderValue>::new();

    custom_headers.insert(
        HeaderName::from_static("user-agent"),
        GOOSE_USER_AGENT
            .to_str()
            .unwrap_or("goose")
            .parse()
            .unwrap_or_else(|_| HeaderValue::from_static("goose")),
    );

    for (key, value) in headers {
        let header_name = HeaderName::try_from(key)
            .map_err(|_| ExtensionError::ConfigError(format!("invalid header: {}", key)))?;
        let header_value = value
            .parse::<HeaderValue>()
            .map_err(|_| ExtensionError::ConfigError(format!("invalid header value: {}", key)))?;
        custom_headers.insert(header_name, header_value);
    }

    let config = StreamableHttpClientTransportConfig::with_uri(uri).custom_headers(custom_headers);
    let transport = StreamableHttpClientTransport::with_client(unix_client, config);

    let timeout_duration = Duration::from_secs(resolve_timeout(timeout));

    let client_res = McpClient::connect(
        transport,
        timeout_duration,
        provider.clone(),
        client_name.clone(),
        capabilities.clone(),
        roots_dir.to_path_buf(),
        action_required,
        extension_manager,
    )
    .await;

    if should_attempt_oauth_fallback(&client_res) {
        tracing::warn!(
            "Extension '{}' returned 401 over Unix domain socket transport; \
             OAuth is not supported for UDS connections",
            name,
        );
    }
    Ok(Box::new(client_res?))
}

impl ExtensionManager {
    fn mcp_client_capabilities(&self) -> GooseMcpClientCapabilities {
        GooseMcpClientCapabilities {
            mcpui: self.capabilities.mcpui,
            host_info: self.capabilities.host_info.clone(),
        }
    }

    pub fn new(
        provider: SharedProvider,
        session_manager: Arc<crate::session::SessionManager>,
        scheduler: Option<Arc<dyn crate::scheduler_trait::SchedulerTrait>>,
        client_name: String,
        capabilities: ExtensionManagerCapabilities,
        use_login_shell_path: bool,
    ) -> Self {
        Self {
            extensions: Mutex::new(HashMap::new()),
            context: PlatformExtensionContext {
                extension_manager: None,
                session_manager,
                scheduler,
                session: None,
                use_login_shell_path,
            },
            provider,
            tools_cache: Mutex::new(None),
            tools_cache_version: AtomicU64::new(0),
            client_name,
            capabilities,
            policy_enforcement_point: default_policy_enforcement_point(),
            filesystem_broker: default_filesystem_broker(),
            terminal_broker: default_terminal_broker(),
            network_broker: default_network_broker(),
        }
    }

    #[cfg(test)]
    fn with_test_policy_enforcement_point(
        mut self,
        policy_enforcement_point: Arc<dyn PolicyEnforcementPoint>,
    ) -> Self {
        self.policy_enforcement_point = policy_enforcement_point;
        self
    }

    #[cfg(test)]
    fn with_test_filesystem_broker(mut self, filesystem_broker: Arc<dyn FilesystemBroker>) -> Self {
        self.filesystem_broker = filesystem_broker;
        self
    }

    #[cfg(test)]
    fn with_test_terminal_broker(mut self, terminal_broker: Arc<dyn TerminalBroker>) -> Self {
        self.terminal_broker = terminal_broker;
        self
    }

    pub fn new_without_provider(data_dir: std::path::PathBuf) -> Self {
        let session_manager = Arc::new(crate::session::SessionManager::new(data_dir));
        Self::new(
            Arc::new(Mutex::new(None)),
            session_manager,
            None,
            "goose-cli".to_string(),
            ExtensionManagerCapabilities {
                mcpui: false,
                host_info: None,
            },
            false,
        )
    }

    pub fn get_context(&self) -> &PlatformExtensionContext {
        &self.context
    }

    pub fn get_provider(&self) -> &SharedProvider {
        &self.provider
    }

    pub async fn supports_resources(&self) -> bool {
        self.extensions
            .lock()
            .await
            .values()
            .any(|ext| ext.supports_resources())
    }

    /// Add an extension with an optional working directory.
    /// If working_dir is None, falls back to current_dir.
    #[allow(clippy::too_many_lines)]
    pub async fn add_extension(
        self: &Arc<Self>,
        config: ExtensionConfig,
        working_dir: Option<PathBuf>,
        container: Option<&Container>,
        session_id: Option<&str>,
    ) -> ExtensionResult<()> {
        enforce_accordlock_extension_policy(&config, container.is_some())?;
        let sanitized_name = config.key();

        // Compare both the unresolved config (to detect structural changes like
        // migrating from plaintext envs to env_keys) and the resolved config (to
        // detect secret rotation where only keyring values changed). Only skip
        // restart if both match.
        let resolved_config = config.clone().resolve(Config::global()).await?;

        if let Some(existing) = self.extensions.lock().await.get(&sanitized_name) {
            if existing.config == config && existing.resolved_config == resolved_config {
                return Ok(());
            }
            tracing::debug!(
                name = sanitized_name,
                "extension config changed, restarting with updated config"
            );
        }

        let mut temp_dir = None;

        let effective_working_dir = working_dir
            .clone()
            .or_else(|| std::env::var("GOOSE_WORKING_DIR").ok().map(PathBuf::from))
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

        let client: Box<dyn McpClientTrait> = match &config {
            ExtensionConfig::Sse { .. } => {
                return Err(ExtensionError::ConfigError(
                    "SSE is unsupported, migrate to streamable_http".to_string(),
                ));
            }
            ExtensionConfig::StreamableHttp {
                uri,
                timeout,
                headers,
                name,
                envs,
                env_keys,
                socket,
                client_id,
                client_secret_key,
                scopes,
                ..
            } => {
                let config = Config::global();
                let all_envs = merge_environments(envs, env_keys, &sanitized_name, config).await?;
                let resolved_uri = substitute_env_vars(uri, &all_envs);
                let resolved_headers = headers
                    .iter()
                    .map(|(k, v)| (k.clone(), substitute_env_vars(v, &all_envs)))
                    .collect();
                let resolved_socket = socket.as_ref().map(|s| substitute_env_vars(s, &all_envs));
                let static_oauth_client = resolve_static_oauth_client(
                    client_id.as_deref(),
                    client_secret_key.as_deref(),
                    scopes,
                    &all_envs,
                    config,
                )
                .map_err(|error| *error)?;
                create_streamable_http_client(
                    &resolved_uri,
                    *timeout,
                    &resolved_headers,
                    name,
                    resolved_socket.as_deref(),
                    static_oauth_client,
                    Box::new(GooseCredentialStore::new(name.to_string())),
                    self.provider.clone(),
                    self.client_name.clone(),
                    self.mcp_client_capabilities(),
                    &effective_working_dir,
                    self.context.session_manager.action_required(),
                    Arc::downgrade(self),
                )
                .await?
            }
            ExtensionConfig::Builtin { ref name, .. }
            | ExtensionConfig::Platform { ref name, .. } => {
                let timeout = if let ExtensionConfig::Builtin { timeout, .. } = &config {
                    *timeout
                } else {
                    None
                };
                let normalized_name = name_to_key(name);

                if let Some(def) = PLATFORM_EXTENSIONS.get(normalized_name.as_str()) {
                    // Platform extension: create via in-process client factory
                    let mut context = self.context.clone();
                    context.extension_manager = Some(Arc::downgrade(self));
                    if let Some(id) = session_id {
                        if let Ok(session) =
                            self.context.session_manager.get_session(id, false).await
                        {
                            context.session = Some(Arc::new(session));
                        }
                    }
                    // A platform extension the host cannot provide (no scheduler
                    // service, say) declines rather than registering with no tools.
                    let Some(client) = (def.client_factory)(context) else {
                        return Ok(());
                    };
                    client
                } else {
                    // Builtin MCP server extension
                    let timeout_secs = resolve_timeout(timeout);
                    let extension_fn =
                        get_builtin_extension(normalized_name.as_str()).ok_or_else(|| {
                            ExtensionError::ConfigError(format!("Unknown extension: {}", name))
                        })?;

                    if let Some(container) = container {
                        let container_id = container.id();
                        tracing::info!(
                            container = %container_id,
                            builtin = %name,
                            "Starting builtin extension inside Docker container"
                        );
                        let command = Command::new("docker").configure(|command| {
                            command
                                .arg("exec")
                                .arg("-i")
                                .arg(container_id)
                                .arg("goose")
                                .arg("mcp")
                                .arg(&normalized_name);
                        });

                        let client = child_process_client(
                            command,
                            &Some(timeout_secs),
                            self.provider.clone(),
                            &effective_working_dir,
                            Some(container_id.to_string()),
                            self.client_name.clone(),
                            self.mcp_client_capabilities(),
                            self.context.session_manager.action_required(),
                            Arc::downgrade(self),
                        )
                        .await?;
                        Box::new(client)
                    } else {
                        let (server_read, client_write) = tokio::io::duplex(65536);
                        let (client_read, server_write) = tokio::io::duplex(65536);
                        extension_fn(server_read, server_write);

                        Box::new(
                            McpClient::connect(
                                (client_read, client_write),
                                Duration::from_secs(timeout_secs),
                                self.provider.clone(),
                                self.client_name.clone(),
                                self.mcp_client_capabilities(),
                                effective_working_dir.clone(),
                                self.context.session_manager.action_required(),
                                Arc::downgrade(self),
                            )
                            .await?,
                        )
                    }
                }
            }
            ExtensionConfig::Stdio {
                cmd,
                args,
                envs,
                env_keys,
                timeout,
                cwd,
                ..
            } => {
                let config = Config::global();
                let mut all_envs =
                    merge_environments(envs, env_keys, &sanitized_name, config).await?;
                let process_working_dir = cwd
                    .as_deref()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| effective_working_dir.clone());

                if let Some(sid) = session_id {
                    all_envs.insert("AGENT_SESSION_ID".to_string(), sid.to_string());
                }

                // This must happen before both branches below: `env_remove`
                // protects a direct child, but cannot redact a value already
                // materialized in `docker exec -e KEY=VALUE` arguments.
                strip_accordlock_authority_env(&mut all_envs);

                // Check for malicious packages before launching the process
                extension_malware_check::deny_if_malicious_cmd_args(cmd, args).await?;

                let command = if let Some(container) = container {
                    let container_id = container.id();
                    tracing::info!(
                        container = %container_id,
                        cmd = %cmd,
                        "Starting stdio extension inside Docker container"
                    );
                    Command::new("docker").configure(|command| {
                        command.arg("exec").arg("-i");
                        for (key, value) in &all_envs {
                            command.arg("-e").arg(format!("{}={}", key, value));
                        }
                        command.arg(container_id);
                        command.arg(cmd);
                        command.args(args);
                    })
                } else {
                    let cmd = resolve_command(cmd);
                    Command::new(cmd).configure(|command| {
                        command.args(args).envs(all_envs);
                    })
                };

                let client = child_process_client(
                    command,
                    timeout,
                    self.provider.clone(),
                    &process_working_dir,
                    container.map(|c| c.id().to_string()),
                    self.client_name.clone(),
                    self.mcp_client_capabilities(),
                    self.context.session_manager.action_required(),
                    Arc::downgrade(self),
                )
                .await?;
                Box::new(client)
            }
            ExtensionConfig::InlinePython {
                name,
                code,
                timeout,
                dependencies,
                ..
            } => {
                let dir = tempdir()?;
                let file_path = dir.path().join(format!("{}.py", name));
                temp_dir = Some(dir);
                std::fs::write(&file_path, code)?;

                let command = Command::new("uvx").configure(|command| {
                    command.arg("--with").arg("mcp");
                    dependencies.iter().flatten().for_each(|dep| {
                        command.arg("--with").arg(dep);
                    });
                    command.arg("python").arg(file_path.to_str().unwrap());
                });

                let client = child_process_client(
                    command,
                    timeout,
                    self.provider.clone(),
                    &effective_working_dir,
                    container.map(|c| c.id().to_string()),
                    self.client_name.clone(),
                    self.mcp_client_capabilities(),
                    self.context.session_manager.action_required(),
                    Arc::downgrade(self),
                )
                .await?;

                Box::new(client)
            }
            ExtensionConfig::Frontend { .. } => {
                return Err(ExtensionError::ConfigError(
                    "Invalid extension type: Frontend extensions cannot be added as server extensions".to_string()
                ));
            }
        };

        let server_info = client.get_info().cloned();

        let mut extensions = self.extensions.lock().await;
        extensions.insert(
            sanitized_name,
            Extension::new(
                config,
                resolved_config,
                Arc::from(client),
                server_info,
                temp_dir,
            ),
        );
        drop(extensions);
        self.invalidate_tools_cache_and_bump_version().await;

        Ok(())
    }

    pub async fn add_client(
        &self,
        name: String,
        config: ExtensionConfig,
        client: McpClientBox,
        info: Option<ServerInfo>,
        temp_dir: Option<TempDir>,
    ) -> ExtensionResult<()> {
        enforce_accordlock_extension_policy(&config, false)?;
        #[cfg(feature = "accordlock-distribution")]
        {
            let _ = (name, client, info, temp_dir);
            Err(ExtensionError::ConfigError(
                "AccordLock does not permit injected extension clients".to_string(),
            ))
        }

        #[cfg(not(feature = "accordlock-distribution"))]
        {
            let normalized = name_to_key(&name);
            self.extensions.lock().await.insert(
                normalized,
                Extension::new(config.clone(), config.clone(), client, info, temp_dir),
            );
            self.invalidate_tools_cache_and_bump_version().await;
            Ok(())
        }
    }

    /// Get extensions info for building the system prompt
    pub async fn get_extensions_info(&self, working_dir: &std::path::Path) -> Vec<ExtensionInfo> {
        let working_dir_str = working_dir.to_string_lossy();
        self.extensions
            .lock()
            .await
            .iter()
            .map(|(name, ext)| {
                let instructions = ext.get_instructions().unwrap_or_default();
                let instructions = instructions.replace("{{WORKING_DIR}}", &working_dir_str);
                ExtensionInfo::new(name, &instructions, ext.supports_resources())
            })
            .collect()
    }

    /// Get aggregated usage statistics
    pub async fn remove_extension(&self, name: &str) -> ExtensionResult<()> {
        let sanitized_name = name_to_key(name);
        self.extensions.lock().await.remove(&sanitized_name);
        self.invalidate_tools_cache_and_bump_version().await;
        Ok(())
    }

    pub async fn update_working_dir(&self, new_dir: &std::path::Path) {
        let extensions = self.extensions.lock().await;
        for (name, ext) in extensions.iter() {
            if let Err(e) = ext.client.update_working_dir(new_dir.to_path_buf()).await {
                tracing::warn!(extension = %name, error = %e, "failed to update roots");
            }
        }
    }

    pub async fn list_extensions(&self) -> ExtensionResult<Vec<String>> {
        Ok(self.extensions.lock().await.keys().cloned().collect())
    }

    pub async fn is_extension_enabled(&self, name: &str) -> bool {
        let normalized = name_to_key(name);
        self.extensions.lock().await.contains_key(&normalized)
    }

    pub async fn get_extension_configs(&self) -> Vec<ExtensionConfig> {
        self.extensions
            .lock()
            .await
            .values()
            .map(|ext| ext.config.clone())
            .collect()
    }

    /// Get all tools from all clients with proper prefixing
    pub async fn get_prefixed_tools(
        &self,
        session_id: &str,
        extension_name: Option<String>,
    ) -> ExtensionResult<Vec<Tool>> {
        let all_tools = self.get_all_tools_cached(session_id).await?;
        Ok(self.filter_tools(&all_tools, extension_name.as_deref(), None))
    }

    pub async fn get_prefixed_tools_excluding(
        &self,
        session_id: &str,
        exclude: &str,
    ) -> ExtensionResult<Vec<Tool>> {
        let all_tools = self.get_all_tools_cached(session_id).await?;
        Ok(self.filter_tools(&all_tools, None, Some(exclude)))
    }

    fn filter_tools(
        &self,
        tools: &[Tool],
        extension_name: Option<&str>,
        exclude: Option<&str>,
    ) -> Vec<Tool> {
        let extension_name_normalized = extension_name.map(name_to_key);
        let exclude_normalized = exclude.map(name_to_key);

        tools
            .iter()
            .filter(|tool| {
                let tool_owner = get_tool_owner(tool)
                    .map(|s| name_to_key(&s))
                    .unwrap_or_else(|| tool.name.split("__").next().unwrap_or("").to_string());

                if let Some(ref excluded) = exclude_normalized {
                    if tool_owner == *excluded {
                        return false;
                    }
                }

                if let Some(ref name_filter) = extension_name_normalized {
                    tool_owner == *name_filter
                } else {
                    true
                }
            })
            .cloned()
            .collect()
    }

    async fn get_all_tools_cached(&self, session_id: &str) -> ExtensionResult<Arc<Vec<Tool>>> {
        {
            let cache = self.tools_cache.lock().await;
            if let Some(ref tools) = *cache {
                return Ok(Arc::clone(tools));
            }
        }

        let version_before = self.tools_cache_version.load(Ordering::SeqCst);
        let tools = Arc::new(self.fetch_all_tools(session_id).await?);

        {
            let mut cache = self.tools_cache.lock().await;
            let version_after = self.tools_cache_version.load(Ordering::SeqCst);
            if version_after == version_before && cache.is_none() {
                *cache = Some(Arc::clone(&tools));
            }
        }

        Ok(tools)
    }

    fn host_supports_mcp_apps(&self) -> bool {
        if let Some(host_info) = &self.capabilities.host_info {
            if host_info.explicit_extensions {
                return host_info.mcpui_enabled();
            }
        }

        self.capabilities.mcpui
    }

    async fn hydrate_mcp_app_attachment(
        client: &McpClientBox,
        session_id: &str,
        resolved_tool: &ResolvedTool,
        cancellation_token: CancellationToken,
    ) -> Option<GooseMcpAppToolAttachment> {
        let resource_uri = resolved_tool.resource_uri.clone()?;

        let mut attachment = GooseMcpAppToolAttachment {
            tool_name: resolved_tool.actual_tool_name.clone(),
            tool_name_is_actual: true,
            extension_name: resolved_tool.extension_name.clone(),
            resource_uri: resource_uri.clone(),
            tool_meta: resolved_tool.tool_meta.clone(),
            resource_result: None,
            read_error: None,
        };

        match client
            .read_resource(session_id, &resource_uri, cancellation_token)
            .await
        {
            Ok(resource_result) => {
                attachment.resource_result = serde_json::to_value(&resource_result).ok();
            }
            Err(error) => {
                warn!(error = ?error, "Failed to hydrate MCP app resource");
                attachment.read_error = Some(MCP_APP_RESOURCE_FAILURE_MESSAGE.to_string());
            }
        }

        Some(attachment)
    }

    pub(crate) async fn invalidate_tools_cache_and_bump_version(&self) {
        self.tools_cache_version.fetch_add(1, Ordering::SeqCst);
        *self.tools_cache.lock().await = None;
    }

    async fn fetch_all_tools(&self, session_id: &str) -> ExtensionResult<Vec<Tool>> {
        let clients: Vec<_> = self
            .extensions
            .lock()
            .await
            .iter()
            .map(|(name, ext)| (name.clone(), ext.config.clone(), ext.get_client()))
            .collect();

        let cancel_token = CancellationToken::default();
        let client_futures = clients.into_iter().map(|(name, config, client)| {
            let cancel_token = cancel_token.clone();
            let ext_name = name.clone();
            async move {
                let mut tools = Vec::new();
                let mut client_tools = match client
                    .list_tools(session_id, None, cancel_token.clone())
                    .await
                {
                    Ok(t) => t,
                    Err(e) => {
                        warn!(extension = %ext_name, error = %e, "Failed to list tools");
                        return (name, vec![]);
                    }
                };

                let expose_unprefixed = is_unprefixed_extension(&config);

                loop {
                    for mut tool in client_tools.tools {
                        if config.is_tool_available(&tool.name) {
                            let public_name = if expose_unprefixed {
                                tool.name.to_string()
                            } else {
                                format!("{}__{}", name, tool.name)
                            };

                            let mut meta_map = tool
                                .meta
                                .as_ref()
                                .map(|m| m.0.clone())
                                .unwrap_or_default();
                            meta_map.insert(
                                TOOL_EXTENSION_META_KEY.to_string(),
                                serde_json::Value::String(name.clone()),
                            );

                            tool.name = public_name.into();
                            tool.meta = Some(rmcp::model::MetaObject(meta_map));

                            let mut schema = (*tool.input_schema).clone();
                            if super::tool_schema_normalize::normalize_input_schema(
                                &mut schema,
                            ) {
                                tool.input_schema = Arc::new(schema);
                            }

                            tools.push(tool);
                        }
                    }

                    if client_tools.next_cursor.is_none() {
                        break;
                    }

                    client_tools = match client
                        .list_tools(session_id, client_tools.next_cursor, cancel_token.clone())
                        .await
                    {
                        Ok(t) => t,
                        Err(e) => {
                            warn!(extension = %ext_name, error = %e, "Failed to list tools (pagination)");
                            break;
                        }
                    };
                }

                (name, tools)
            }
        });

        let results = future::join_all(client_futures).await;

        let mut seen_names: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut tools = Vec::new();
        for (ext_name, client_tools) in results {
            for tool in client_tools {
                let tool_name = tool.name.to_string();
                if seen_names.contains(&tool_name) {
                    warn!(
                        tool = %tool_name,
                        extension = %ext_name,
                        "Duplicate tool name - skipping"
                    );
                    continue;
                }
                seen_names.insert(tool_name);
                tools.push(tool);
            }
        }

        Ok(tools)
    }

    /// Get the extension prompt including client instructions
    pub async fn get_planning_prompt(&self, tools_info: Vec<ToolInfo>) -> String {
        let mut context: HashMap<&str, Value> = HashMap::new();
        context.insert("tools", serde_json::to_value(tools_info).unwrap());

        prompt_template::render_template("plan.md", &context).expect("Prompt should render")
    }

    // Function that gets executed for read_resource tool
    pub async fn read_resource_tool(
        &self,
        session_id: &str,
        params: Value,
        cancellation_token: CancellationToken,
    ) -> Result<Vec<ContentBlock>, ErrorData> {
        let uri = require_str_parameter(&params, "uri")?;
        let extension_name = require_str_parameter(&params, "extension_name")?;

        let read_result = self
            .read_resource(session_id, uri, extension_name, cancellation_token)
            .await?;

        let mut result = Vec::new();
        for content in read_result.contents {
            if let ResourceContents::TextResourceContents { text, .. } = content {
                result.push(ContentBlock::text(format!("{}\n\n{}", uri, text)));
            }
        }
        Ok(result)
    }

    pub async fn read_resource(
        &self,
        session_id: &str,
        uri: &str,
        extension_name: &str,
        cancellation_token: CancellationToken,
    ) -> Result<rmcp::model::ReadResourceResult, ErrorData> {
        let client = self
            .get_server_client(extension_name)
            .await
            .ok_or_else(|| {
                warn!(extension = %extension_name, "Resource connection was not found");
                ErrorData::new(
                    ErrorCode::INVALID_PARAMS,
                    RESOURCE_READ_FAILURE_MESSAGE,
                    None,
                )
            })?;

        client
            .read_resource(session_id, uri, cancellation_token)
            .await
            .map_err(|error| {
                warn!(error = ?error, "Failed to read resource");
                ErrorData::new(
                    ErrorCode::INTERNAL_ERROR,
                    RESOURCE_READ_FAILURE_MESSAGE,
                    None,
                )
            })
    }

    pub async fn get_ui_resources(
        &self,
        session_id: &str,
    ) -> Result<Vec<(String, Resource)>, ErrorData> {
        let mut ui_resources = Vec::new();

        let extensions_to_check: Vec<(String, McpClientBox)> = {
            let extensions = self.extensions.lock().await;
            extensions
                .iter()
                .map(|(name, ext)| (name.clone(), ext.get_client()))
                .collect()
        };

        for (extension_name, client) in extensions_to_check {
            match client
                .list_resources(session_id, None, CancellationToken::default())
                .await
            {
                Ok(list_response) => {
                    for resource in list_response.resources {
                        if resource.uri.starts_with("ui://") {
                            ui_resources.push((extension_name.clone(), resource));
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to list resources for {}: {:?}", extension_name, e);
                }
            }
        }

        Ok(ui_resources)
    }

    async fn list_resources_from_extension(
        &self,
        session_id: &str,
        extension_name: &str,
        cancellation_token: CancellationToken,
    ) -> Result<Vec<ContentBlock>, ErrorData> {
        let client = self
            .get_server_client(extension_name)
            .await
            .ok_or_else(|| {
                warn!(extension = %extension_name, "Resource connection was not found");
                ErrorData::new(
                    ErrorCode::INVALID_PARAMS,
                    RESOURCE_LIST_FAILURE_MESSAGE,
                    None,
                )
            })?;

        client
            .list_resources(session_id, None, cancellation_token)
            .await
            .map_err(|e| {
                warn!(error = ?e, "Failed to list resources for connection");
                ErrorData::new(
                    ErrorCode::INTERNAL_ERROR,
                    RESOURCE_LIST_FAILURE_MESSAGE,
                    None,
                )
            })
            .map(|lr| {
                let resource_list = lr
                    .resources
                    .into_iter()
                    .map(|r| format!("{} - {}, uri: ({})", extension_name, r.name, r.uri))
                    .collect::<Vec<String>>()
                    .join("\n");

                vec![ContentBlock::text(resource_list)]
            })
    }

    pub async fn list_resources(
        &self,
        session_id: &str,
        params: Value,
        cancellation_token: CancellationToken,
    ) -> Result<Vec<ContentBlock>, ErrorData> {
        let extension = params.get("extension_name").and_then(|v| v.as_str());

        match extension {
            Some(extension_name) => {
                // Handle single extension case
                self.list_resources_from_extension(session_id, extension_name, cancellation_token)
                    .await
            }
            None => {
                // Handle all extensions case using FuturesUnordered
                let mut futures = FuturesUnordered::new();

                // Create futures for each resource_capable_extension
                self.extensions
                    .lock()
                    .await
                    .iter()
                    .filter(|(_name, ext)| ext.supports_resources())
                    .map(|(name, _ext)| name.clone())
                    .for_each(|name| {
                        let token = cancellation_token.clone();
                        futures.push(async move {
                            self.list_resources_from_extension(session_id, name.as_str(), token)
                                .await
                        });
                    });

                let mut all_resources = Vec::new();
                let mut errors = Vec::new();

                // Process results as they complete
                while let Some(result) = futures.next().await {
                    match result {
                        Ok(content) => {
                            all_resources.extend(content);
                        }
                        Err(tool_error) => {
                            errors.push(tool_error);
                        }
                    }
                }

                if !errors.is_empty() {
                    tracing::error!(
                        errors = ?errors
                            .into_iter()
                            .map(|e| format!("{:?}", e))
                            .collect::<Vec<_>>(),
                        "errors from listing resources"
                    );
                }

                Ok(all_resources)
            }
        }
    }

    async fn resolve_tool(
        &self,
        session_id: &str,
        tool_name: &str,
    ) -> Result<ResolvedTool, ErrorData> {
        let tools = self.get_all_tools_cached(session_id).await.map_err(|e| {
            warn!(error = %e, "Failed to load available tools");
            ErrorData::new(ErrorCode::INTERNAL_ERROR, TOOL_LIST_FAILURE_MESSAGE, None)
        })?;

        let mut name = tool_name.to_string();
        let mut recovery_attempted = false;
        loop {
            if let Some(tool) = tools.iter().find(|t| *t.name == *name) {
                let owner = get_tool_owner(tool)
                    .or_else(|| name.split_once("__").map(|(prefix, _)| name_to_key(prefix)))
                    .ok_or_else(|| {
                        ErrorData::new(
                            ErrorCode::RESOURCE_NOT_FOUND,
                            TOOL_UNAVAILABLE_MESSAGE,
                            None,
                        )
                    })?;

                let actual_tool_name = name
                    .strip_prefix(&format!("{owner}__"))
                    .unwrap_or(&name)
                    .to_string();

                let (client, tool_available) = {
                    let extensions = self.extensions.lock().await;
                    let extension = extensions.get(&owner).ok_or_else(|| {
                        ErrorData::new(
                            ErrorCode::RESOURCE_NOT_FOUND,
                            TOOL_UNAVAILABLE_MESSAGE,
                            None,
                        )
                    })?;
                    (
                        extension.get_client(),
                        extension.config.is_tool_available(&actual_tool_name),
                    )
                };

                return Ok(ResolvedTool {
                    extension_name: owner,
                    actual_tool_name,
                    client,
                    tool_available,
                    tool_meta: get_tool_meta_value(tool),
                    resource_uri: get_tool_resource_uri(tool),
                });
            }

            if let Some((prefix, actual)) = name.split_once("__") {
                let owner = name_to_key(prefix);
                let resolved_extension = {
                    let extensions = self.extensions.lock().await;
                    extensions.get(&owner).map(|extension| {
                        (
                            extension.get_client(),
                            extension.config.is_tool_available(actual),
                        )
                    })
                };
                if let Some((client, tool_available)) = resolved_extension {
                    return Ok(ResolvedTool {
                        extension_name: owner,
                        actual_tool_name: actual.to_string(),
                        client,
                        tool_available,
                        tool_meta: None,
                        resource_uri: None,
                    });
                }
            }

            if !recovery_attempted {
                recovery_attempted = true;
                if let Some(recovered) =
                    recover_mangled_tool_name(&name, tools.iter().map(|t| t.name.as_ref()))
                {
                    name = recovered;
                    continue;
                }
            }

            break;
        }

        Err(ErrorData::new(
            ErrorCode::RESOURCE_NOT_FOUND,
            TOOL_UNAVAILABLE_MESSAGE,
            None,
        ))
    }

    pub async fn dispatch_tool_call(
        &self,
        ctx: &super::tool_execution::ToolCallContext,
        tool_call: CallToolRequestParams,
        cancellation_token: CancellationToken,
    ) -> std::result::Result<ToolCallResult, ErrorData> {
        let tool_name_str = tool_call.name.to_string();
        let resolved = self.resolve_tool(&ctx.session_id, &tool_name_str).await?;

        if !resolved.tool_available {
            return Err(ErrorData::new(
                ErrorCode::RESOURCE_NOT_FOUND,
                TOOL_DISABLED_MESSAGE,
                None,
            ));
        }

        // Terminal execution is an atomic runtime operation in the policy-enforced
        // distribution. Return from this branch before both the generic
        // policy point and the MCP client so the call is neither double-authorized
        // nor ever executed directly by Goose.
        if self.terminal_broker.enforces_boundary()
            && is_brokered_terminal_tool(&resolved.extension_name, &resolved.actual_tool_name)
        {
            let arguments = tool_call
                .arguments
                .clone()
                .map(Value::Object)
                .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
            let run_id = self
                .terminal_broker
                .derive_run_id(&ctx.session_id)
                .map_err(policy_enforcement_error_data)?;
            let request = ToolExecutionRequest::new(
                &ctx.session_id,
                &run_id,
                ctx.tool_call_request_id.as_deref(),
                ctx.working_dir.as_deref(),
                &resolved.extension_name,
                &resolved.actual_tool_name,
                &tool_name_str,
                arguments,
                ctx.agent_plan_checkpoint.as_ref(),
            )
            .map_err(policy_enforcement_error_data)?;
            let terminal_broker = self.terminal_broker.clone();
            let effect_task = tokio::spawn(async move {
                terminal_broker
                    .authorize_and_execute(&request)
                    .await
                    .map(|outcome| outcome.into_call_tool_result())
                    .map_err(policy_enforcement_error_data)
            });
            let result = async move {
                match effect_task.await {
                    Ok(result) => result,
                    Err(error) => {
                        tracing::error!(%error, "brokered terminal task ended without an execution record");
                        Err(policy_enforcement_error_data(
                            PolicyEnforcementError::ExecutionUnknown,
                        ))
                    }
                }
            };
            return Ok(ToolCallResult {
                result: Box::new(result.boxed()),
                notification_stream: None,
                action_required_stream: None,
            });
        }

        // Governed HTTPS is normalized into a closed read-only request and
        // executed by the trusted runtime. Goose never opens the socket and
        // the developer extension never receives the call.
        if self.network_broker.enforces_boundary()
            && is_brokered_network_tool(&resolved.extension_name, &resolved.actual_tool_name)
        {
            let arguments = tool_call
                .arguments
                .clone()
                .map(Value::Object)
                .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
            let arguments = normalize_network_tool_arguments(arguments)
                .map_err(policy_enforcement_error_data)?;
            let run_id = self
                .network_broker
                .derive_run_id(&ctx.session_id)
                .map_err(policy_enforcement_error_data)?;
            let request = ToolExecutionRequest::new(
                &ctx.session_id,
                &run_id,
                ctx.tool_call_request_id.as_deref(),
                ctx.working_dir.as_deref(),
                "accordlock_network",
                "https_request",
                &tool_name_str,
                arguments,
                ctx.agent_plan_checkpoint.as_ref(),
            )
            .map_err(policy_enforcement_error_data)?;
            let network_broker = self.network_broker.clone();
            let effect_task = tokio::spawn(async move {
                network_broker
                    .authorize_and_execute(&request)
                    .await
                    .map(|outcome| outcome.into_call_tool_result())
                    .map_err(policy_enforcement_error_data)
            });
            let result = async move {
                match effect_task.await {
                    Ok(result) => result,
                    Err(error) => {
                        tracing::error!(%error, "brokered network task ended without an execution record");
                        Err(policy_enforcement_error_data(
                            PolicyEnforcementError::ExecutionUnknown,
                        ))
                    }
                }
            };
            return Ok(ToolCallResult {
                result: Box::new(result.boxed()),
                notification_stream: None,
                action_required_stream: None,
            });
        }

        if self.filesystem_broker.enforces_boundary() {
            match classify_filesystem_tool(&resolved.extension_name, &resolved.actual_tool_name) {
                FilesystemRoute::Brokered => {
                    let arguments = tool_call
                        .arguments
                        .clone()
                        .map(Value::Object)
                        .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
                    let run_id = self
                        .filesystem_broker
                        .derive_run_id(&ctx.session_id)
                        .map_err(policy_enforcement_error_data)?;
                    let request = ToolExecutionRequest::new(
                        &ctx.session_id,
                        &run_id,
                        ctx.tool_call_request_id.as_deref(),
                        ctx.working_dir.as_deref(),
                        &resolved.extension_name,
                        &resolved.actual_tool_name,
                        &tool_name_str,
                        arguments,
                        ctx.agent_plan_checkpoint.as_ref(),
                    )
                    .map_err(policy_enforcement_error_data)?;
                    let filesystem_broker = self.filesystem_broker.clone();
                    let effect_task = tokio::spawn(async move {
                        filesystem_broker
                            .authorize_and_execute(&request)
                            .await
                            .map(|outcome| outcome.into_call_tool_result())
                            .map_err(policy_enforcement_error_data)
                    });
                    let result = async move {
                        match effect_task.await {
                            Ok(result) => result,
                            Err(error) => {
                                tracing::error!(%error, "brokered filesystem task ended without an execution record");
                                Err(policy_enforcement_error_data(
                                    PolicyEnforcementError::ExecutionUnknown,
                                ))
                            }
                        }
                    };
                    return Ok(ToolCallResult {
                        result: Box::new(result.boxed()),
                        notification_stream: None,
                        action_required_stream: None,
                    });
                }
                FilesystemRoute::ForbiddenDirect => {
                    return Err(policy_enforcement_error_data(
                        PolicyEnforcementError::Denied("DIRECT_EXECUTION_DISABLED".to_owned()),
                    ));
                }
                FilesystemRoute::Unrelated => {}
            }
        }

        let execution_authorization = if self.policy_enforcement_point.enforces_tool_policy() {
            let arguments = tool_call
                .arguments
                .clone()
                .map(Value::Object)
                .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
            let run_id = self
                .policy_enforcement_point
                .derive_run_id(&ctx.session_id)
                .map_err(policy_enforcement_error_data)?;
            let request = ToolExecutionRequest::new(
                &ctx.session_id,
                &run_id,
                ctx.tool_call_request_id.as_deref(),
                ctx.working_dir.as_deref(),
                &resolved.extension_name,
                &resolved.actual_tool_name,
                &tool_name_str,
                arguments,
                ctx.agent_plan_checkpoint.as_ref(),
            )
            .map_err(policy_enforcement_error_data)?;
            Some(
                self.policy_enforcement_point
                    .authorize_and_consume(&request)
                    .await
                    .map_err(policy_enforcement_error_data)?,
            )
        } else {
            None
        };

        let arguments = tool_call.arguments.clone();
        let client = resolved.client.clone();
        let hydration_client = client.clone();
        let client_notifications_receiver = client.subscribe().await;
        let session_id = ctx.session_id.clone();
        let action_required_tool_call_request_id = ctx.tool_call_request_id.clone();
        let action_required_manager = self.context.session_manager.action_required();
        let action_required_receiver =
            if let Some(tool_call_request_id) = action_required_tool_call_request_id.clone() {
                if action_required_manager
                    .has_action_required_stream(&session_id, &tool_call_request_id)
                    .await
                {
                    None
                } else {
                    let registered_tool_call_request_id = tool_call_request_id.clone();
                    let receiver = action_required_manager
                        .register_action_required_stream(session_id.clone(), tool_call_request_id)
                        .await;
                    Some((
                        receiver,
                        session_id.clone(),
                        registered_tool_call_request_id,
                    ))
                }
            } else {
                None
            };
        let actual_tool_name = resolved.actual_tool_name.clone();
        let resolved_tool = resolved;
        let should_hydrate_mcp_app = self.host_supports_mcp_apps();
        let read_cancellation_token = cancellation_token.clone();
        let policy_enforcement_point = self.policy_enforcement_point.clone();
        let owned_ctx = ToolCallContext::new(
            ctx.session_id.clone(),
            ctx.working_dir.clone(),
            ctx.tool_call_request_id.clone(),
        );
        let owned_ctx = match ctx.agent_plan_checkpoint.clone() {
            Some(checkpoint) => owned_ctx.with_agent_plan_checkpoint(checkpoint),
            None => owned_ctx,
        };
        let (owned_ctx, tool_call_notifications_receiver) =
            if let Some(notification_emitter) = ctx.notification_emitter().cloned() {
                (
                    owned_ctx.with_notification_emitter(notification_emitter),
                    None,
                )
            } else if owned_ctx.tool_call_request_id.is_some() {
                let (tool_call_notifications_sender, tool_call_notifications_receiver) =
                    mpsc::channel(TOOL_CALL_NOTIFICATION_CHANNEL_CAPACITY);
                (
                    owned_ctx.with_notification_emitter(ToolCallNotificationEmitter::new(
                        tool_call_notifications_sender,
                    )),
                    Some(tool_call_notifications_receiver),
                )
            } else {
                (owned_ctx, None)
            };
        let notification_stream: Box<dyn Stream<Item = ServerNotification> + Send + Unpin> =
            match tool_call_notifications_receiver {
                Some(tool_call_notifications_receiver) => Box::new(stream::select(
                    ReceiverStream::new(client_notifications_receiver),
                    ReceiverStream::new(tool_call_notifications_receiver),
                )),
                None => Box::new(ReceiverStream::new(client_notifications_receiver)),
            };

        let policy_enforced_execution = execution_authorization.is_some();
        // Once one-shot authority has been consumed, dropping the UI/agent
        // waiter must not cancel execution accounting. The detached task
        // completes the attempt and record even if its JoinHandle future
        // is dropped by a caller or disconnect.
        let effect_task = tokio::spawn(async move {
            tracing::debug!(
                "dispatch_tool_call: calling client.call_tool tool={} session_id={} working_dir={:?}",
                actual_tool_name,
                owned_ctx.session_id,
                owned_ctx.working_dir,
            );
            if let Some(authorization) = execution_authorization.as_ref() {
                authorization
                    .ensure_current(chrono::Utc::now().timestamp())
                    .map_err(policy_enforcement_error_data)?;
            }
            let mut call_result = client
                .call_tool(&owned_ctx, &actual_tool_name, arguments, cancellation_token)
                .await
                .map_err(|e| {
                    error!(error = ?e, "Extension tool request failed");
                    let code = match e {
                        ServiceError::McpError(error_data) => error_data.code,
                        _ => ErrorCode::INTERNAL_ERROR,
                    };
                    ErrorData::new(code, TOOL_REQUEST_FAILURE_MESSAGE, None)
                });

            if let Ok(result) = &mut call_result {
                remove_untrusted_mcp_app_meta(result);
            }

            if let Some(authorization) = execution_authorization.as_ref() {
                let (outcome, result_value) = match &call_result {
                    Ok(result) => {
                        let outcome = if result.is_error == Some(true) {
                            ExecutionOutcome::ToolReportedError
                        } else {
                            ExecutionOutcome::Succeeded
                        };
                        let value = serde_json::to_value(result).map_err(|_| {
                            policy_enforcement_error_data(PolicyEnforcementError::ExecutionUnknown)
                        })?;
                        (outcome, Some(value))
                    }
                    Err(_) => (ExecutionOutcome::TransportError, None),
                };
                let execution_record =
                    ToolExecutionObservation::new(authorization, outcome, result_value.as_ref())
                        .map_err(policy_enforcement_error_data)?;
                policy_enforcement_point
                    .record_execution(&execution_record)
                    .await
                    .map_err(|_| {
                        policy_enforcement_error_data(PolicyEnforcementError::ExecutionUnknown)
                    })?;

                // A transport failure or tool-reported error after authority
                // was consumed does not prove that no operation occurred. Never
                // return the ordinary retryable tool error to the agent.
                if call_result
                    .as_ref()
                    .map_or(true, |result| result.is_error == Some(true))
                {
                    return Err(policy_enforcement_error_data(
                        PolicyEnforcementError::ExecutionUnknown,
                    ));
                }
            }

            let mut result = call_result?;

            if result.is_error == Some(true) {
                warn!(tool_result = ?result, "Extension tool reported an error");
                result =
                    CallToolResult::error(vec![ContentBlock::text(TOOL_REPORTED_FAILURE_MESSAGE)]);
            }

            if should_hydrate_mcp_app && result.is_error != Some(true) {
                if let Some(attachment) = Self::hydrate_mcp_app_attachment(
                    &hydration_client,
                    &session_id,
                    &resolved_tool,
                    read_cancellation_token,
                )
                .await
                {
                    insert_trusted_tool_update_meta(&mut result, &attachment);
                }
            }

            Ok(result)
        });
        let fut = async move {
            match effect_task.await {
                Ok(result) => result,
                Err(error) if policy_enforced_execution => {
                    tracing::error!(%error, "policy-enforced tool task ended without an execution record");
                    Err(policy_enforcement_error_data(
                        PolicyEnforcementError::ExecutionUnknown,
                    ))
                }
                Err(error) => {
                    tracing::error!(%error, "extension tool task ended unexpectedly");
                    Err(ErrorData::new(
                        ErrorCode::INTERNAL_ERROR,
                        TOOL_REQUEST_FAILURE_MESSAGE,
                        None,
                    ))
                }
            }
        };

        Ok(ToolCallResult {
            result: Box::new(fut.boxed()),
            notification_stream: Some(notification_stream),
            action_required_stream: action_required_receiver.map(
                |(rx, session_id, tool_call_request_id)| {
                    Box::new(ActionRequiredStream::new(
                        rx,
                        action_required_manager,
                        session_id,
                        tool_call_request_id,
                    )) as _
                },
            ),
        })
    }

    pub async fn list_prompts_from_extension(
        &self,
        session_id: &str,
        extension_name: &str,
        cancellation_token: CancellationToken,
    ) -> Result<Vec<Prompt>, ErrorData> {
        let client = self
            .get_server_client(extension_name)
            .await
            .ok_or_else(|| {
                warn!(extension = %extension_name, "Prompt connection was not found");
                ErrorData::new(ErrorCode::INVALID_PARAMS, PROMPT_LIST_FAILURE_MESSAGE, None)
            })?;

        client
            .list_prompts(session_id, None, cancellation_token)
            .await
            .map_err(|e| {
                warn!(error = ?e, "Failed to list prompts for connection");
                ErrorData::new(ErrorCode::INTERNAL_ERROR, PROMPT_LIST_FAILURE_MESSAGE, None)
            })
            .map(|lp| lp.prompts)
    }

    pub async fn list_prompts(
        &self,
        session_id: &str,
        cancellation_token: CancellationToken,
    ) -> Result<HashMap<String, Vec<Prompt>>, ErrorData> {
        let mut futures = FuturesUnordered::new();

        let names: Vec<_> = self.extensions.lock().await.keys().cloned().collect();
        for extension_name in names {
            let token = cancellation_token.clone();
            futures.push(async move {
                (
                    extension_name.clone(),
                    self.list_prompts_from_extension(session_id, extension_name.as_str(), token)
                        .await,
                )
            });
        }

        let mut all_prompts = HashMap::new();
        let mut errors = Vec::new();

        // Process results as they complete
        while let Some(result) = futures.next().await {
            let (name, prompts) = result;
            match prompts {
                Ok(content) => {
                    all_prompts.insert(name.to_string(), content);
                }
                Err(tool_error) => {
                    errors.push(tool_error);
                }
            }
        }

        if !errors.is_empty() {
            tracing::debug!(
                errors = ?errors
                    .into_iter()
                    .map(|e| format!("{:?}", e))
                    .collect::<Vec<_>>(),
                "errors from listing prompts"
            );
        }

        Ok(all_prompts)
    }

    pub async fn get_prompt(
        &self,
        session_id: &str,
        extension_name: &str,
        name: &str,
        arguments: Value,
        cancellation_token: CancellationToken,
    ) -> Result<GetPromptResult> {
        let client = self
            .get_server_client(extension_name)
            .await
            .ok_or_else(|| {
                warn!(extension = %extension_name, "Prompt connection was not found");
                anyhow::anyhow!(PROMPT_LOAD_FAILURE_MESSAGE)
            })?;

        client
            .get_prompt(session_id, name, arguments, cancellation_token)
            .await
            .map_err(|e| {
                warn!(error = ?e, "Failed to load prompt");
                anyhow::anyhow!(PROMPT_LOAD_FAILURE_MESSAGE)
            })
    }

    pub async fn search_available_extensions(&self) -> Result<Vec<ContentBlock>, ErrorData> {
        let mut output_parts = vec![];

        // First get disabled extensions from current config (skip hidden ones)
        let mut disabled_extensions: Vec<String> = vec![];
        for extension in get_all_extensions() {
            if !extension.enabled && !is_hidden_extension(&extension.config.name()) {
                let config = extension.config.clone();
                let description = match &config {
                    ExtensionConfig::Builtin {
                        description,
                        display_name,
                        ..
                    } => {
                        if description.is_empty() {
                            display_name.as_deref().unwrap_or("Built-in extension")
                        } else {
                            description
                        }
                    }
                    ExtensionConfig::Sse { .. } => "SSE extension (unsupported)",
                    ExtensionConfig::Platform { description, .. }
                    | ExtensionConfig::StreamableHttp { description, .. }
                    | ExtensionConfig::Stdio { description, .. }
                    | ExtensionConfig::Frontend { description, .. }
                    | ExtensionConfig::InlinePython { description, .. } => description,
                };
                disabled_extensions.push(format!("- {} - {}", config.name(), description));
            }
        }

        // Get currently enabled extensions that can be disabled (skip hidden ones)
        let enabled_extensions: Vec<String> = self
            .extensions
            .lock()
            .await
            .keys()
            .filter(|name| !is_hidden_extension(name))
            .cloned()
            .collect();

        // Build output string
        if !disabled_extensions.is_empty() {
            output_parts.push(format!(
                "Extensions available to enable:\n{}\n",
                disabled_extensions.join("\n")
            ));
        } else {
            output_parts.push("No extensions available to enable.\n".to_string());
        }

        if !enabled_extensions.is_empty() {
            output_parts.push(format!(
                "\n\nExtensions available to disable:\n{}\n",
                enabled_extensions
                    .iter()
                    .map(|name| format!("- {}", name))
                    .collect::<Vec<_>>()
                    .join("\n")
            ));
        } else {
            output_parts.push("No extensions that can be disabled.\n".to_string());
        }

        Ok(vec![ContentBlock::text(output_parts.join("\n"))])
    }

    async fn get_server_client(&self, name: impl Into<String>) -> Option<McpClientBox> {
        let normalized = name_to_key(&name.into());
        self.extensions
            .lock()
            .await
            .get(&normalized)
            .map(|ext| ext.get_client())
    }

    pub async fn collect_moim_parts(&self, session_id: &str) -> Vec<String> {
        let mut platform_clients: Vec<(String, McpClientBox)> = {
            let extensions = self.extensions.lock().await;
            extensions
                .iter()
                .filter_map(|(name, extension)| {
                    let is_platform = match &extension.config {
                        ExtensionConfig::Platform { .. } => true,
                        ExtensionConfig::Builtin { name: ext_name, .. } => {
                            PLATFORM_EXTENSIONS.contains_key(name_to_key(ext_name).as_str())
                        }
                        _ => false,
                    };
                    if is_platform {
                        Some((name.clone(), extension.get_client()))
                    } else {
                        None
                    }
                })
                .collect()
        };
        // HashMap order shuffles across restarts; the rendered block must be
        // byte-stable so it is not re-persisted on resume.
        platform_clients.sort_by(|a, b| a.0.cmp(&b.0));

        let mut parts = Vec::new();
        for (name, client) in platform_clients {
            if let Some(moim_content) = client.get_moim(session_id).await {
                tracing::debug!("MOIM content from {}: {} chars", name, moim_content.len());
                parts.push(moim_content);
            }
        }
        parts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::accordlock_authorization::{
        ExecutionAuthorization, ToolExecutionObservation,
    };
    use crate::agents::accordlock_filesystem::{
        BrokeredFilesystemOutcome, BrokeredFilesystemResult, ExecutionEvidence,
    };
    use crate::agents::accordlock_terminal::{
        BrokeredProcessOutcome, BrokeredTerminalOutcome, BrokeredTerminalResult, TerminalBroker,
    };
    use rmcp::model::CallToolResult;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex as StdMutex;

    #[cfg(feature = "accordlock-distribution")]
    #[test]
    fn accordlock_extension_policy_is_closed_before_activation() {
        let developer = ExtensionConfig::Platform {
            name: "developer".to_string(),
            description: String::new(),
            display_name: Some("Developer".to_string()),
            bundled: Some(true),
            available_tools: vec![],
        };
        let stdio = ExtensionConfig::Stdio {
            name: "developer".to_string(),
            description: String::new(),
            cmd: "untrusted-command".to_string(),
            args: vec![],
            envs: Envs::default(),
            env_keys: vec![],
            timeout: None,
            cwd: None,
            bundled: None,
            available_tools: vec![],
        };
        let other_platform = ExtensionConfig::Platform {
            name: "scheduler".to_string(),
            description: String::new(),
            display_name: Some("Scheduler".to_string()),
            bundled: Some(true),
            available_tools: vec![],
        };

        assert!(enforce_accordlock_extension_policy(&developer, false).is_ok());
        assert!(enforce_accordlock_extension_policy(&developer, true).is_err());
        assert!(enforce_accordlock_extension_policy(&stdio, false).is_err());
        assert!(enforce_accordlock_extension_policy(&other_platform, false).is_err());
    }

    #[test]
    fn extension_transport_env_cannot_carry_accordlock_authority() {
        let mut envs = HashMap::from([
            (
                "accordlock_runtime_url".to_string(),
                "http://127.0.0.1:43127".to_string(),
            ),
            (
                "ACCORDLOCK_RUNTIME_TOKEN".to_string(),
                "runtime-token".to_string(),
            ),
            (
                "AccordLock_Backend_Binding_Secret".to_string(),
                "backend-secret".to_string(),
            ),
            ("SAFE_EXTENSION_VALUE".to_string(), "kept".to_string()),
        ]);

        strip_accordlock_authority_env(&mut envs);

        assert_eq!(
            envs,
            HashMap::from([("SAFE_EXTENSION_VALUE".to_string(), "kept".to_string())])
        );
    }

    mod static_oauth_client {
        use super::*;

        fn test_config(dir: &tempfile::TempDir) -> Config {
            Config::new_with_file_secrets(
                dir.path().join("config.yaml"),
                dir.path().join("secrets.yaml"),
            )
            .unwrap()
        }

        #[test]
        fn absent_client_id_yields_no_static_client() {
            let dir = tempfile::tempdir().unwrap();
            let config = test_config(&dir);

            let resolved =
                resolve_static_oauth_client(None, None, &[], &HashMap::new(), &config).unwrap();

            assert_eq!(resolved, None);
        }

        #[test]
        fn client_id_without_secret_resolves_public_client() {
            let dir = tempfile::tempdir().unwrap();
            let config = test_config(&dir);

            let resolved = resolve_static_oauth_client(
                Some("registered-client"),
                None,
                &["scope.read".to_string()],
                &HashMap::new(),
                &config,
            )
            .unwrap()
            .unwrap();

            assert_eq!(resolved.client_id, "registered-client");
            assert_eq!(resolved.client_secret, None);
            assert_eq!(resolved.scopes, vec!["scope.read"]);
        }

        #[test]
        fn client_id_supports_env_substitution() {
            let dir = tempfile::tempdir().unwrap();
            let config = test_config(&dir);
            let envs = HashMap::from([(
                "OAUTH_CLIENT_ID".to_string(),
                "registered-client".to_string(),
            )]);

            let resolved =
                resolve_static_oauth_client(Some("${OAUTH_CLIENT_ID}"), None, &[], &envs, &config)
                    .unwrap()
                    .unwrap();

            assert_eq!(resolved.client_id, "registered-client");
        }

        #[test]
        fn client_secret_resolves_from_envs() {
            let dir = tempfile::tempdir().unwrap();
            let config = test_config(&dir);
            let envs = HashMap::from([(
                "OAUTH_CLIENT_SECRET".to_string(),
                "secret-value".to_string(),
            )]);

            let resolved = resolve_static_oauth_client(
                Some("registered-client"),
                Some("OAUTH_CLIENT_SECRET"),
                &[],
                &envs,
                &config,
            )
            .unwrap()
            .unwrap();

            assert_eq!(resolved.client_secret.as_deref(), Some("secret-value"));
        }

        #[test]
        fn client_secret_falls_back_to_config_secret_store() {
            let dir = tempfile::tempdir().unwrap();
            let config = test_config(&dir);
            config
                .set("OAUTH_CLIENT_SECRET", &"stored-secret", true)
                .unwrap();

            let resolved = resolve_static_oauth_client(
                Some("registered-client"),
                Some("OAUTH_CLIENT_SECRET"),
                &[],
                &HashMap::new(),
                &config,
            )
            .unwrap()
            .unwrap();

            assert_eq!(resolved.client_secret.as_deref(), Some("stored-secret"));
        }

        #[test]
        fn client_secret_key_without_client_id_is_rejected() {
            let dir = tempfile::tempdir().unwrap();
            let config = test_config(&dir);

            let error = resolve_static_oauth_client(
                None,
                Some("OAUTH_CLIENT_SECRET"),
                &[],
                &HashMap::new(),
                &config,
            )
            .unwrap_err();

            assert!(matches!(*error, ExtensionError::ConfigError(_)));
        }

        #[test]
        fn scopes_without_client_id_are_rejected() {
            let dir = tempfile::tempdir().unwrap();
            let config = test_config(&dir);

            let error = resolve_static_oauth_client(
                None,
                None,
                &["scope.read".to_string()],
                &HashMap::new(),
                &config,
            )
            .unwrap_err();

            assert!(matches!(*error, ExtensionError::ConfigError(_)));
        }

        #[test]
        fn missing_client_secret_key_is_an_error() {
            let dir = tempfile::tempdir().unwrap();
            let config = test_config(&dir);

            let error = resolve_static_oauth_client(
                Some("registered-client"),
                Some("MISSING_KEY"),
                &[],
                &HashMap::new(),
                &config,
            )
            .unwrap_err();

            assert!(matches!(*error, ExtensionError::ConfigError(_)));
        }
    }
    use rmcp::model::{CustomNotification, InitializeResult, JsonObject};
    use rmcp::{object, ServiceError as Error};

    use rmcp::model::ListPromptsResult;
    use rmcp::model::ListResourcesResult;
    use rmcp::model::ListToolsResult;
    use rmcp::model::ReadResourceResult;
    use rmcp::model::ServerNotification;

    use tokio::sync::mpsc;

    impl ExtensionManager {
        async fn add_mock_extension(&self, name: String, client: McpClientBox) {
            self.add_mock_extension_with_tools(name, client, vec![])
                .await;
        }

        async fn add_mock_extension_with_tools(
            &self,
            name: String,
            client: McpClientBox,
            available_tools: Vec<String>,
        ) {
            let sanitized_name = name_to_key(&name);
            let config = ExtensionConfig::Builtin {
                name: name.clone(),
                display_name: Some(name.clone()),
                description: "built-in".to_string(),
                timeout: None,
                bundled: None,
                available_tools,
            };
            let extension = Extension::new(config.clone(), config.clone(), client, None, None);
            self.extensions
                .lock()
                .await
                .insert(sanitized_name, extension);
            self.invalidate_tools_cache_and_bump_version().await;
        }
    }

    struct MockClient {}

    #[async_trait::async_trait]
    impl McpClientTrait for MockClient {
        fn get_info(&self) -> Option<&InitializeResult> {
            None
        }

        async fn list_resources(
            &self,
            _session_id: &str,
            _next_cursor: Option<String>,
            _cancellation_token: CancellationToken,
        ) -> Result<ListResourcesResult, Error> {
            Err(Error::TransportClosed)
        }

        async fn read_resource(
            &self,
            _session_id: &str,
            _uri: &str,
            _cancellation_token: CancellationToken,
        ) -> Result<ReadResourceResult, Error> {
            Err(Error::TransportClosed)
        }

        async fn list_tools(
            &self,
            _session_id: &str,
            _next_cursor: Option<String>,
            _cancellation_token: CancellationToken,
        ) -> Result<ListToolsResult, Error> {
            use serde_json::json;
            use std::sync::Arc;
            Ok(ListToolsResult {
                tools: vec![
                    Tool::new(
                        "tool".to_string(),
                        "A basic tool".to_string(),
                        Arc::new(json!({}).as_object().unwrap().clone()),
                    ),
                    Tool::new(
                        "available_tool".to_string(),
                        "An available tool".to_string(),
                        Arc::new(json!({}).as_object().unwrap().clone()),
                    ),
                    Tool::new(
                        "hidden_tool".to_string(),
                        "hidden tool".to_string(),
                        Arc::new(json!({}).as_object().unwrap().clone()),
                    ),
                    {
                        let mut t = Tool::new(
                            "render_chart".to_string(),
                            "Render a chart".to_string(),
                            Arc::new(json!({}).as_object().unwrap().clone()),
                        );
                        t.meta = Some(MetaObject(
                            json!({ "ui": { "resourceUri": "ui://autovisualiser/chart" } })
                                .as_object()
                                .unwrap()
                                .clone(),
                        ));
                        t
                    },
                ],
                next_cursor: None,
                meta: None,
                ..Default::default()
            })
        }

        async fn call_tool(
            &self,
            _ctx: &ToolCallContext,
            name: &str,
            _arguments: Option<JsonObject>,
            _cancellation_token: CancellationToken,
        ) -> Result<CallToolResult, Error> {
            match name {
                "tool" | "test__tool" | "available_tool" | "hidden_tool" | "render_chart" => {
                    Ok(CallToolResult::success(vec![]))
                }
                _ => Err(Error::TransportClosed),
            }
        }

        async fn list_prompts(
            &self,
            _session_id: &str,
            _next_cursor: Option<String>,
            _cancellation_token: CancellationToken,
        ) -> Result<ListPromptsResult, Error> {
            Err(Error::TransportClosed)
        }

        async fn get_prompt(
            &self,
            _session_id: &str,
            _name: &str,
            _arguments: Value,
            _cancellation_token: CancellationToken,
        ) -> Result<GetPromptResult, Error> {
            Err(Error::TransportClosed)
        }

        async fn subscribe(&self) -> mpsc::Receiver<ServerNotification> {
            mpsc::channel(1).1
        }
    }

    #[derive(Clone, Copy)]
    enum TestGateBehavior {
        Allow,
        Deny,
        Unavailable,
        AllowOnce,
        RecordFails,
    }

    struct TestPolicyEnforcementPoint {
        behavior: TestGateBehavior,
        authorizations: AtomicUsize,
        records: AtomicUsize,
    }

    impl TestPolicyEnforcementPoint {
        fn new(behavior: TestGateBehavior) -> Self {
            Self {
                behavior,
                authorizations: AtomicUsize::new(0),
                records: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl PolicyEnforcementPoint for TestPolicyEnforcementPoint {
        fn derive_run_id(&self, session_id: &str) -> Result<String, PolicyEnforcementError> {
            super::super::accordlock_authorization::derive_backend_run_id(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                session_id,
            )
        }

        async fn authorize_and_consume(
            &self,
            request: &ToolExecutionRequest,
        ) -> Result<ExecutionAuthorization, PolicyEnforcementError> {
            let attempt = self.authorizations.fetch_add(1, Ordering::SeqCst);
            match self.behavior {
                TestGateBehavior::Allow | TestGateBehavior::RecordFails => {
                    let now = chrono::Utc::now().timestamp();
                    Ok(ExecutionAuthorization {
                        authorization_id: uuid::Uuid::from_u128(attempt as u128 + 1).to_string(),
                        proposal_digest: request.digest()?,
                        request_hash: "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
                        issued_at: now,
                        not_before: now,
                        expires_at: now + 60,
                    })
                }
                TestGateBehavior::AllowOnce if attempt == 0 => {
                    let now = chrono::Utc::now().timestamp();
                    Ok(ExecutionAuthorization {
                        authorization_id: uuid::Uuid::from_u128(1).to_string(),
                        proposal_digest: request.digest()?,
                        request_hash: "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
                        issued_at: now,
                        not_before: now,
                        expires_at: now + 60,
                    })
                }
                TestGateBehavior::AllowOnce => Err(PolicyEnforcementError::Denied(
                    "ALREADY_CONSUMED".to_owned(),
                )),
                TestGateBehavior::Deny => {
                    Err(PolicyEnforcementError::Denied("POLICY_DENIED".to_owned()))
                }
                TestGateBehavior::Unavailable => Err(PolicyEnforcementError::RuntimeUnavailable),
            }
        }

        async fn record_execution(
            &self,
            _record: &ToolExecutionObservation,
        ) -> Result<(), PolicyEnforcementError> {
            self.records.fetch_add(1, Ordering::SeqCst);
            if matches!(self.behavior, TestGateBehavior::RecordFails) {
                Err(PolicyEnforcementError::ExecutionUnknown)
            } else {
                Ok(())
            }
        }
    }

    struct CountingClient {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl McpClientTrait for CountingClient {
        fn get_info(&self) -> Option<&InitializeResult> {
            None
        }

        async fn list_tools(
            &self,
            session_id: &str,
            next_cursor: Option<String>,
            cancellation_token: CancellationToken,
        ) -> Result<ListToolsResult, Error> {
            MockClient {}
                .list_tools(session_id, next_cursor, cancellation_token)
                .await
        }

        async fn call_tool(
            &self,
            _ctx: &ToolCallContext,
            _name: &str,
            _arguments: Option<JsonObject>,
            _cancellation_token: CancellationToken,
        ) -> Result<CallToolResult, Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(CallToolResult::success(vec![]))
        }

        async fn subscribe(&self) -> mpsc::Receiver<ServerNotification> {
            mpsc::channel(1).1
        }
    }

    struct TestFilesystemBroker {
        calls: Arc<AtomicUsize>,
    }

    #[derive(Clone, Copy, Debug)]
    enum TestTerminalBehavior {
        Success,
        Deny,
        Approval,
        Unavailable,
        Malformed,
        Unknown,
    }

    struct TestTerminalBroker {
        behavior: TestTerminalBehavior,
        calls: Arc<AtomicUsize>,
        request: Arc<StdMutex<Option<ToolExecutionRequest>>>,
    }

    #[async_trait::async_trait]
    impl TerminalBroker for TestTerminalBroker {
        fn enforces_boundary(&self) -> bool {
            true
        }

        fn derive_run_id(&self, session_id: &str) -> Result<String, PolicyEnforcementError> {
            super::super::accordlock_authorization::derive_backend_run_id(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                session_id,
            )
        }

        async fn authorize_and_execute(
            &self,
            request: &ToolExecutionRequest,
        ) -> Result<BrokeredTerminalOutcome, PolicyEnforcementError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.request.lock().unwrap() = Some(request.clone());
            match self.behavior {
                TestTerminalBehavior::Success => Ok(BrokeredTerminalOutcome::Succeeded {
                    result: BrokeredTerminalResult {
                        program: "cargo".to_owned(),
                        exit_code: Some(0),
                        outcome: BrokeredProcessOutcome::Succeeded,
                        stdout: "tests passed\n".to_owned(),
                        stderr: String::new(),
                        stdout_truncated: false,
                        stderr_truncated: false,
                        encoding_lossy: false,
                        duration_ms: 7,
                    },
                    result_sha256:
                        "sha256:3333333333333333333333333333333333333333333333333333333333333333"
                            .to_owned(),
                    evidence: ExecutionEvidence {
                        authorization_id: uuid::Uuid::from_u128(1).to_string(),
                        request_hash:
                            "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                                .to_owned(),
                        record_id: uuid::Uuid::from_u128(2).to_string(),
                        record_hash:
                            "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                                .to_owned(),
                    },
                }),
                TestTerminalBehavior::Deny => {
                    Err(PolicyEnforcementError::Denied("POLICY_DENIED".to_owned()))
                }
                TestTerminalBehavior::Approval => Err(PolicyEnforcementError::ApprovalRequired(
                    "ACTION_APPROVAL_REQUIRED".to_owned(),
                )),
                TestTerminalBehavior::Unavailable => {
                    Err(PolicyEnforcementError::RuntimeUnavailable)
                }
                TestTerminalBehavior::Malformed => {
                    Err(PolicyEnforcementError::InvalidRuntimeResponse)
                }
                TestTerminalBehavior::Unknown => {
                    Err(PolicyEnforcementError::ExecutionUnknown)
                }
            }
        }
    }

    #[async_trait::async_trait]
    impl FilesystemBroker for TestFilesystemBroker {
        fn enforces_boundary(&self) -> bool {
            true
        }

        fn derive_run_id(&self, session_id: &str) -> Result<String, PolicyEnforcementError> {
            super::super::accordlock_authorization::derive_backend_run_id(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                session_id,
            )
        }

        async fn authorize_and_execute(
            &self,
            request: &ToolExecutionRequest,
        ) -> Result<BrokeredFilesystemOutcome, PolicyEnforcementError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let path = request
                .arguments
                .get("path")
                .and_then(Value::as_str)
                .expect("test request has a path")
                .to_owned();
            let result = BrokeredFilesystemResult::Write {
                relative_path: path,
                created: true,
                bytes_written: 5,
                content_sha256:
                    "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
                        .to_owned(),
            };
            let result_sha256 =
                super::super::accordlock_authorization::canonical_json_bytes(&result)
                    .map(|bytes| super::super::accordlock_authorization::sha256_digest(&bytes))?;
            Ok(BrokeredFilesystemOutcome::Succeeded {
                result,
                result_sha256,
                evidence: ExecutionEvidence {
                    authorization_id: uuid::Uuid::from_u128(1).to_string(),
                    request_hash:
                        "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                            .to_owned(),
                    record_id: uuid::Uuid::from_u128(2).to_string(),
                    record_hash:
                        "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                            .to_owned(),
                },
            })
        }
    }

    struct FilesystemCountingClient {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl McpClientTrait for FilesystemCountingClient {
        fn get_info(&self) -> Option<&InitializeResult> {
            None
        }

        async fn list_tools(
            &self,
            _session_id: &str,
            _next_cursor: Option<String>,
            _cancellation_token: CancellationToken,
        ) -> Result<ListToolsResult, Error> {
            Ok(ListToolsResult {
                tools: [
                    "read",
                    "write",
                    "edit",
                    "delete_file",
                    "tree",
                    "shell",
                    "read_image",
                ]
                .into_iter()
                .map(|name| {
                    Tool::new(
                        name.to_owned(),
                        name.to_owned(),
                        Arc::new(JsonObject::new()),
                    )
                })
                .collect(),
                next_cursor: None,
                meta: None,
                ..Default::default()
            })
        }

        async fn call_tool(
            &self,
            _ctx: &ToolCallContext,
            _name: &str,
            _arguments: Option<JsonObject>,
            _cancellation_token: CancellationToken,
        ) -> Result<CallToolResult, Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(CallToolResult::success(vec![]))
        }

        async fn subscribe(&self) -> mpsc::Receiver<ServerNotification> {
            mpsc::channel(1).1
        }
    }

    async fn filesystem_dispatch_manager() -> (
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
        tempfile::TempDir,
        ExtensionManager,
    ) {
        let temporary = tempfile::tempdir().unwrap();
        let broker_calls = Arc::new(AtomicUsize::new(0));
        let client_calls = Arc::new(AtomicUsize::new(0));
        let manager = ExtensionManager::new_without_provider(temporary.path().join("data"))
            .with_test_filesystem_broker(Arc::new(TestFilesystemBroker {
                calls: broker_calls.clone(),
            }));
        manager
            .add_mock_extension(
                "developer".to_owned(),
                Arc::new(FilesystemCountingClient {
                    calls: client_calls.clone(),
                }),
            )
            .await;
        (broker_calls, client_calls, temporary, manager)
    }

    #[tokio::test]
    async fn brokered_filesystem_call_never_reaches_the_goose_client() {
        let (broker_calls, client_calls, workspace, manager) = filesystem_dispatch_manager().await;
        let context = ToolCallContext::new(
            "session".to_owned(),
            Some(workspace.path().to_path_buf()),
            Some("call".to_owned()),
        );
        let tool_call = CallToolRequestParams::new("developer__write").with_arguments(object!({
            "path": "notes.txt",
            "content": "hello"
        }));

        let dispatched = manager
            .dispatch_tool_call(&context, tool_call, CancellationToken::new())
            .await
            .unwrap();
        let result = dispatched.result.await.unwrap();

        assert_eq!(result.is_error, Some(false));
        assert_eq!(broker_calls.load(Ordering::SeqCst), 1);
        assert_eq!(client_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn delete_file_is_brokered_without_direct_or_shell_fallback() {
        let (broker_calls, client_calls, workspace, manager) = filesystem_dispatch_manager().await;
        let context = ToolCallContext::new(
            "session".to_owned(),
            Some(workspace.path().to_path_buf()),
            Some("delete-call".to_owned()),
        );
        let tool_call = CallToolRequestParams::new("developer__delete_file")
            .with_arguments(object!({ "path": "notes.txt" }));

        let dispatched = manager
            .dispatch_tool_call(&context, tool_call, CancellationToken::new())
            .await
            .unwrap();
        let result = dispatched.result.await.unwrap();

        assert_eq!(result.is_error, Some(false));
        assert_eq!(broker_calls.load(Ordering::SeqCst), 1);
        assert_eq!(client_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn unsupported_developer_operation_is_denied_before_goose_client_execution() {
        let (broker_calls, client_calls, workspace, manager) = filesystem_dispatch_manager().await;
        let context = ToolCallContext::new(
            "session".to_owned(),
            Some(workspace.path().to_path_buf()),
            Some("call".to_owned()),
        );
        let tool_call = CallToolRequestParams::new("developer__read_image")
            .with_arguments(object!({"path": "image.png"}));

        let error = match manager
            .dispatch_tool_call(&context, tool_call, CancellationToken::new())
            .await
        {
            Ok(_) => panic!("direct image access must be denied before execution"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("DIRECT_EXECUTION_DISABLED"));
        assert_eq!(broker_calls.load(Ordering::SeqCst), 0);
        assert_eq!(client_calls.load(Ordering::SeqCst), 0);
    }

    async fn terminal_dispatch_manager(
        behavior: TestTerminalBehavior,
    ) -> (
        Arc<TestPolicyEnforcementPoint>,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
        Arc<StdMutex<Option<ToolExecutionRequest>>>,
        tempfile::TempDir,
        ExtensionManager,
    ) {
        let temporary = tempfile::tempdir().unwrap();
        let policy_enforcement_point =
            Arc::new(TestPolicyEnforcementPoint::new(TestGateBehavior::Allow));
        let broker_calls = Arc::new(AtomicUsize::new(0));
        let client_calls = Arc::new(AtomicUsize::new(0));
        let request = Arc::new(StdMutex::new(None));
        let manager = ExtensionManager::new_without_provider(temporary.path().join("data"))
            .with_test_policy_enforcement_point(policy_enforcement_point.clone())
            .with_test_terminal_broker(Arc::new(TestTerminalBroker {
                behavior,
                calls: broker_calls.clone(),
                request: request.clone(),
            }));
        manager
            .add_mock_extension(
                "developer".to_owned(),
                Arc::new(FilesystemCountingClient {
                    calls: client_calls.clone(),
                }),
            )
            .await;
        (
            policy_enforcement_point,
            broker_calls,
            client_calls,
            request,
            temporary,
            manager,
        )
    }

    #[tokio::test]
    async fn policy_enforced_terminal_never_reaches_direct_client_or_generic_policy_point() {
        for behavior in [
            TestTerminalBehavior::Success,
            TestTerminalBehavior::Deny,
            TestTerminalBehavior::Approval,
            TestTerminalBehavior::Unavailable,
            TestTerminalBehavior::Malformed,
            TestTerminalBehavior::Unknown,
        ] {
            let (policy_point, broker_calls, client_calls, _, workspace, manager) =
                terminal_dispatch_manager(behavior).await;
            let context = ToolCallContext::new(
                "session".to_owned(),
                Some(workspace.path().to_path_buf()),
                Some("terminal-call".to_owned()),
            );
            let tool_call =
                CallToolRequestParams::new("developer__shell").with_arguments(object!({
                    "argv": ["cargo", "test", "--lib"],
                    "cwd": ".",
                    "env": {"CI": "1"},
                    "timeout_seconds": 30,
                    "max_output_bytes": 4096
                }));

            let dispatched = manager
                .dispatch_tool_call(&context, tool_call, CancellationToken::new())
                .await
                .unwrap();
            let result = dispatched.result.await;

            assert_eq!(
                result.is_ok(),
                matches!(behavior, TestTerminalBehavior::Success)
            );
            assert_eq!(broker_calls.load(Ordering::SeqCst), 1, "{behavior:?}");
            assert_eq!(client_calls.load(Ordering::SeqCst), 0, "{behavior:?}");
            assert_eq!(policy_point.authorizations.load(Ordering::SeqCst), 0);
            assert_eq!(policy_point.records.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn policy_enforced_terminal_request_is_bound_to_exact_argv_and_context() {
        let (_, broker_calls, client_calls, captured, workspace, manager) =
            terminal_dispatch_manager(TestTerminalBehavior::Success).await;
        let context = ToolCallContext::new(
            "bound-session".to_owned(),
            Some(workspace.path().to_path_buf()),
            Some("bound-call".to_owned()),
        );
        let arguments = object!({
            "argv": ["cargo", "test", "--package", "goose"],
            "cwd": "crates/goose",
            "env": {"CI": "1", "NO_COLOR": "1"},
            "timeout_seconds": 45,
            "max_output_bytes": 8192
        });
        let tool_call =
            CallToolRequestParams::new("developer__shell").with_arguments(arguments.clone());

        let dispatched = manager
            .dispatch_tool_call(&context, tool_call, CancellationToken::new())
            .await
            .unwrap();
        let _ = dispatched.result.await.unwrap();
        let request = captured.lock().unwrap().clone().unwrap();

        assert_eq!(request.session_id, "bound-session");
        assert_eq!(request.tool_call_id, "bound-call");
        assert_eq!(request.extension_id, "developer");
        assert_eq!(request.tool_name, "shell");
        assert_eq!(request.arguments, Value::Object(arguments));
        assert_eq!(
            request.workspace_root,
            std::fs::canonicalize(workspace.path())
                .unwrap()
                .to_str()
                .unwrap()
        );
        assert_eq!(request.digest().unwrap().len(), 71);
        assert_eq!(broker_calls.load(Ordering::SeqCst), 1);
        assert_eq!(client_calls.load(Ordering::SeqCst), 0);
    }

    async fn dispatch_policy_enforced_call(
        behavior: TestGateBehavior,
    ) -> (
        Arc<TestPolicyEnforcementPoint>,
        Arc<AtomicUsize>,
        tempfile::TempDir,
        ExtensionManager,
    ) {
        let temp_dir = tempfile::tempdir().unwrap();
        let policy_enforcement_point = Arc::new(TestPolicyEnforcementPoint::new(behavior));
        let calls = Arc::new(AtomicUsize::new(0));
        let manager = ExtensionManager::new_without_provider(temp_dir.path().join("data"))
            .with_test_policy_enforcement_point(policy_enforcement_point.clone());
        manager
            .add_mock_extension(
                "counting".to_owned(),
                Arc::new(CountingClient {
                    calls: calls.clone(),
                }),
            )
            .await;
        (policy_enforcement_point, calls, temp_dir, manager)
    }

    struct ContextNotificationClient;

    #[async_trait::async_trait]
    impl McpClientTrait for ContextNotificationClient {
        fn get_info(&self) -> Option<&InitializeResult> {
            None
        }

        async fn list_tools(
            &self,
            session_id: &str,
            next_cursor: Option<String>,
            cancellation_token: CancellationToken,
        ) -> Result<ListToolsResult, Error> {
            MockClient {}
                .list_tools(session_id, next_cursor, cancellation_token)
                .await
        }

        async fn call_tool(
            &self,
            ctx: &ToolCallContext,
            _name: &str,
            _arguments: Option<JsonObject>,
            _cancellation_token: CancellationToken,
        ) -> Result<CallToolResult, Error> {
            if let Some(emitter) = ctx.notification_emitter() {
                let request_id = ctx
                    .tool_call_request_id
                    .as_deref()
                    .expect("an emitter requires a request ID");
                emitter.emit_best_effort(ServerNotification::CustomNotification(
                    CustomNotification::new(format!("scoped/{request_id}"), None),
                ));
            }
            Ok(CallToolResult::success(vec![]))
        }

        async fn subscribe(&self) -> mpsc::Receiver<ServerNotification> {
            let (sender, receiver) = mpsc::channel(1);
            sender
                .try_send(ServerNotification::CustomNotification(
                    CustomNotification::new("client/subscription", None),
                ))
                .expect("test notification should fit");
            receiver
        }
    }

    async fn dispatch_notification_methods(ctx: ToolCallContext) -> Vec<String> {
        let temp_dir = tempfile::tempdir().unwrap();
        let extension_manager =
            ExtensionManager::new_without_provider(temp_dir.path().to_path_buf());
        extension_manager
            .add_mock_extension(
                "notifications".to_string(),
                Arc::new(ContextNotificationClient),
            )
            .await;

        let tool_call = CallToolRequestParams::new("notifications__tool".to_string())
            .with_arguments(object!({}));
        let dispatched = extension_manager
            .dispatch_tool_call(&ctx, tool_call, CancellationToken::default())
            .await
            .expect("tool call should dispatch");

        assert!(dispatched.result.await.is_ok());

        let mut methods = dispatched
            .notification_stream
            .expect("notification stream should exist")
            .filter_map(|notification| async move {
                match notification {
                    ServerNotification::CustomNotification(notification) => {
                        Some(notification.method)
                    }
                    _ => None,
                }
            })
            .collect::<Vec<_>>()
            .await;
        methods.sort();
        methods
    }

    #[tokio::test]
    async fn dispatch_merges_request_scoped_and_client_notifications() {
        let methods = dispatch_notification_methods(ToolCallContext::new(
            "session".to_string(),
            None,
            Some("request".to_string()),
        ))
        .await;

        assert_eq!(methods, vec!["client/subscription", "scoped/request"]);
    }

    #[tokio::test]
    async fn dispatch_reuses_existing_notification_emitter() {
        let temp_dir = tempfile::tempdir().unwrap();
        let extension_manager =
            ExtensionManager::new_without_provider(temp_dir.path().to_path_buf());
        extension_manager
            .add_mock_extension(
                "notifications".to_string(),
                Arc::new(ContextNotificationClient),
            )
            .await;
        let (sender, mut receiver) = mpsc::channel(1);
        let ctx = ToolCallContext::new(
            "nested-session".to_string(),
            None,
            Some("nested-request".to_string()),
        )
        .with_notification_emitter(ToolCallNotificationEmitter::new(sender));
        let tool_call = CallToolRequestParams::new("notifications__tool".to_string())
            .with_arguments(object!({}));

        let dispatched = extension_manager
            .dispatch_tool_call(&ctx, tool_call, CancellationToken::default())
            .await
            .expect("tool call should dispatch");
        assert!(dispatched.result.await.is_ok());

        let notification = receiver
            .try_recv()
            .expect("parent emitter should receive nested notification");
        let ServerNotification::CustomNotification(notification) = notification else {
            panic!("expected a custom notification");
        };
        assert_eq!(notification.method, "scoped/nested-request");

        let methods = dispatched
            .notification_stream
            .expect("client notification stream should exist")
            .filter_map(|notification| async move {
                match notification {
                    ServerNotification::CustomNotification(notification) => {
                        Some(notification.method)
                    }
                    _ => None,
                }
            })
            .collect::<Vec<_>>()
            .await;
        assert_eq!(methods, vec!["client/subscription"]);
    }

    #[tokio::test]
    async fn dispatch_without_request_id_uses_only_client_notifications() {
        let methods =
            dispatch_notification_methods(ToolCallContext::new("session".to_string(), None, None))
                .await;

        assert_eq!(methods, vec!["client/subscription"]);
    }

    #[tokio::test]
    async fn test_dispatch_tool_call() {
        use super::super::tool_execution::ToolCallContext;

        let temp_dir = tempfile::tempdir().unwrap();
        let extension_manager =
            ExtensionManager::new_without_provider(temp_dir.path().to_path_buf());

        // Add some mock clients using the helper method
        extension_manager
            .add_mock_extension("test_client".to_string(), Arc::new(MockClient {}))
            .await;

        extension_manager
            .add_mock_extension("__cli__ent__".to_string(), Arc::new(MockClient {}))
            .await;

        extension_manager
            .add_mock_extension("client 🚀".to_string(), Arc::new(MockClient {}))
            .await;

        let ctx = ToolCallContext::new(
            "test-session-id".to_string(),
            None,
            Some("test-req-id".to_string()),
        );

        let tool_call =
            CallToolRequestParams::new("test_client__tool".to_string()).with_arguments(object!({}));

        let result = extension_manager
            .dispatch_tool_call(&ctx, tool_call, CancellationToken::default())
            .await;
        assert!(result.is_ok());

        let tool_call = CallToolRequestParams::new("test_client__available_tool".to_string())
            .with_arguments(object!({}));

        let result = extension_manager
            .dispatch_tool_call(&ctx, tool_call, CancellationToken::default())
            .await;
        assert!(result.is_ok());

        let tool_call = CallToolRequestParams::new("__cli__ent____tool".to_string())
            .with_arguments(object!({}));

        let result = extension_manager
            .dispatch_tool_call(&ctx, tool_call, CancellationToken::default())
            .await;
        assert!(result.is_ok());

        let tool_call =
            CallToolRequestParams::new("client___tool".to_string()).with_arguments(object!({}));

        let result = extension_manager
            .dispatch_tool_call(&ctx, tool_call, CancellationToken::default())
            .await;
        assert!(result.is_ok());

        let invalid_tool_call =
            CallToolRequestParams::new("client___tools".to_string()).with_arguments(object!({}));

        let result = extension_manager
            .dispatch_tool_call(&ctx, invalid_tool_call, CancellationToken::default())
            .await;
        if let Err(err) = result {
            assert_eq!(err.code, ErrorCode::RESOURCE_NOT_FOUND);
        } else {
            panic!("Expected ErrorData with ErrorCode::RESOURCE_NOT_FOUND");
        }

        let invalid_tool_call =
            CallToolRequestParams::new("_client__tools".to_string()).with_arguments(object!({}));

        let result = extension_manager
            .dispatch_tool_call(&ctx, invalid_tool_call, CancellationToken::default())
            .await;
        if let Err(err) = result {
            assert_eq!(err.code, ErrorCode::RESOURCE_NOT_FOUND);
        } else {
            panic!("Expected ErrorData with ErrorCode::RESOURCE_NOT_FOUND");
        }
    }

    #[tokio::test]
    async fn accordlock_exact_allow_executes_once_and_records_execution() {
        let (policy_point, calls, workspace, manager) =
            dispatch_policy_enforced_call(TestGateBehavior::Allow).await;
        let ctx = ToolCallContext::new(
            "session".to_owned(),
            Some(workspace.path().to_path_buf()),
            Some("request".to_owned()),
        );
        let tool_call = CallToolRequestParams::new("counting__tool".to_owned())
            .with_arguments(object!({ "path": "notes.txt" }));

        let dispatched = manager
            .dispatch_tool_call(&ctx, tool_call, CancellationToken::new())
            .await
            .expect("exact call should be authorized");
        assert!(dispatched.result.await.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(policy_point.authorizations.load(Ordering::SeqCst), 1);
        assert_eq!(policy_point.records.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn accordlock_consumed_authority_is_observed_even_if_waiter_is_dropped() {
        let (policy_point, calls, workspace, manager) =
            dispatch_policy_enforced_call(TestGateBehavior::Allow).await;
        let ctx = ToolCallContext::new(
            "session".to_owned(),
            Some(workspace.path().to_path_buf()),
            Some("detached-request".to_owned()),
        );
        let tool_call = CallToolRequestParams::new("counting__tool".to_owned())
            .with_arguments(object!({ "path": "notes.txt" }));

        let dispatched = manager
            .dispatch_tool_call(&ctx, tool_call, CancellationToken::new())
            .await
            .expect("authorization should pass");
        drop(dispatched);

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while policy_point.records.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached policy-enforced operation must reach the execution record");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(policy_point.records.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn accordlock_denial_and_runtime_failure_make_zero_tool_calls() {
        for behavior in [TestGateBehavior::Deny, TestGateBehavior::Unavailable] {
            let (_policy_point, calls, workspace, manager) =
                dispatch_policy_enforced_call(behavior).await;
            let ctx = ToolCallContext::new(
                "session".to_owned(),
                Some(workspace.path().to_path_buf()),
                Some("request".to_owned()),
            );
            let tool_call = CallToolRequestParams::new("counting__tool".to_owned())
                .with_arguments(object!({ "path": "notes.txt" }));

            let result = manager
                .dispatch_tool_call(&ctx, tool_call, CancellationToken::new())
                .await;
            assert!(result.is_err());
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn accordlock_replay_is_denied_before_second_execution() {
        let (_policy_point, calls, workspace, manager) =
            dispatch_policy_enforced_call(TestGateBehavior::AllowOnce).await;
        let ctx = ToolCallContext::new(
            "session".to_owned(),
            Some(workspace.path().to_path_buf()),
            Some("one-use-request".to_owned()),
        );
        let tool_call = CallToolRequestParams::new("counting__tool".to_owned())
            .with_arguments(object!({ "path": "notes.txt" }));

        let first = manager
            .dispatch_tool_call(&ctx, tool_call.clone(), CancellationToken::new())
            .await
            .expect("first consumption should pass");
        assert!(first.result.await.is_ok());
        let replay = manager
            .dispatch_tool_call(&ctx, tool_call, CancellationToken::new())
            .await;
        assert!(replay.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn accordlock_execution_record_failure_is_reported_as_ambiguous() {
        let (_policy_point, calls, workspace, manager) =
            dispatch_policy_enforced_call(TestGateBehavior::RecordFails).await;
        let ctx = ToolCallContext::new(
            "session".to_owned(),
            Some(workspace.path().to_path_buf()),
            Some("request".to_owned()),
        );
        let tool_call = CallToolRequestParams::new("counting__tool".to_owned())
            .with_arguments(object!({ "path": "notes.txt" }));

        let dispatched = manager
            .dispatch_tool_call(&ctx, tool_call, CancellationToken::new())
            .await
            .expect("authorization itself should pass");
        let error = dispatched
            .result
            .await
            .expect_err("missing execution record must not look successful");
        assert!(error.message.contains("execution status is unknown"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_tool_availability_filtering() {
        let temp_dir = tempfile::tempdir().unwrap();
        let extension_manager =
            ExtensionManager::new_without_provider(temp_dir.path().to_path_buf());

        // Only "available_tool" should be available to the LLM
        let available_tools = vec!["available_tool".to_string()];

        extension_manager
            .add_mock_extension_with_tools(
                "test_extension".to_string(),
                Arc::new(MockClient {}),
                available_tools,
            )
            .await;

        let tools = extension_manager
            .get_prefixed_tools("test-session-id", None)
            .await
            .unwrap();

        let tool_names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
        assert!(!tool_names.iter().any(|name| name == "test_extension__tool")); // Default unavailable
        assert!(tool_names
            .iter()
            .any(|name| name == "test_extension__available_tool"));
        assert!(!tool_names
            .iter()
            .any(|name| name == "test_extension__hidden_tool"));
        assert!(tool_names.len() == 1);
    }

    #[tokio::test]
    async fn test_tool_availability_defaults_to_available() {
        let temp_dir = tempfile::tempdir().unwrap();
        let extension_manager =
            ExtensionManager::new_without_provider(temp_dir.path().to_path_buf());

        extension_manager
            .add_mock_extension_with_tools(
                "test_extension".to_string(),
                Arc::new(MockClient {}),
                vec![], // Empty available_tools means all tools are available by default
            )
            .await;

        let tools = extension_manager
            .get_prefixed_tools("test-session-id", None)
            .await
            .unwrap();

        let tool_names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
        assert!(tool_names.iter().any(|name| name == "test_extension__tool"));
        assert!(tool_names
            .iter()
            .any(|name| name == "test_extension__available_tool"));
        assert!(tool_names
            .iter()
            .any(|name| name == "test_extension__hidden_tool"));
        assert!(tool_names
            .iter()
            .any(|name| name == "test_extension__render_chart"));
        assert!(tool_names.len() == 4);
    }

    #[tokio::test]
    async fn test_dispatch_unavailable_tool_returns_error() {
        use super::super::tool_execution::ToolCallContext;

        let temp_dir = tempfile::tempdir().unwrap();
        let extension_manager =
            ExtensionManager::new_without_provider(temp_dir.path().to_path_buf());

        let available_tools = vec!["available_tool".to_string()];

        extension_manager
            .add_mock_extension_with_tools(
                "test_extension".to_string(),
                Arc::new(MockClient {}),
                available_tools,
            )
            .await;

        let ctx = ToolCallContext::new(
            "test-session-id".to_string(),
            None,
            Some("test-req-id".to_string()),
        );

        let unavailable_tool_call = CallToolRequestParams::new("test_extension__tool".to_string())
            .with_arguments(object!({}));

        let result = extension_manager
            .dispatch_tool_call(&ctx, unavailable_tool_call, CancellationToken::default())
            .await;

        if let Err(err) = result {
            assert_eq!(err.code, ErrorCode::RESOURCE_NOT_FOUND);
        } else {
            panic!("Expected ErrorData with ErrorCode::RESOURCE_NOT_FOUND");
        }

        // Try to call an available tool - should succeed
        let available_tool_call =
            CallToolRequestParams::new("test_extension__available_tool".to_string())
                .with_arguments(object!({}));

        let result = extension_manager
            .dispatch_tool_call(&ctx, available_tool_call, CancellationToken::default())
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_streamable_http_header_env_substitution() {
        let mut env_map = HashMap::new();
        env_map.insert("AUTH_TOKEN".to_string(), "secret123".to_string());
        env_map.insert("API_KEY".to_string(), "key456".to_string());

        // Test ${VAR} syntax
        let result = substitute_env_vars("Bearer ${ AUTH_TOKEN }", &env_map);
        assert_eq!(result, "Bearer secret123");

        // Test ${VAR} syntax without spaces
        let result = substitute_env_vars("Bearer ${AUTH_TOKEN}", &env_map);
        assert_eq!(result, "Bearer secret123");

        // Test $VAR syntax
        let result = substitute_env_vars("Bearer $AUTH_TOKEN", &env_map);
        assert_eq!(result, "Bearer secret123");

        // Test multiple substitutions
        let result = substitute_env_vars("Key: $API_KEY, Token: ${AUTH_TOKEN}", &env_map);
        assert_eq!(result, "Key: key456, Token: secret123");

        // Test no substitution when variable doesn't exist
        let result = substitute_env_vars("Bearer ${UNKNOWN_VAR}", &env_map);
        assert_eq!(result, "Bearer ${UNKNOWN_VAR}");

        // Test mixed content
        let result = substitute_env_vars(
            "Authorization: Bearer ${AUTH_TOKEN} and API ${API_KEY}",
            &env_map,
        );
        assert_eq!(result, "Authorization: Bearer secret123 and API key456");
    }

    #[tokio::test]
    async fn test_substitute_env_vars_no_recursive_expansion() {
        let mut env_map = HashMap::new();
        env_map.insert("TOKEN".to_string(), "abc$KEY".to_string());
        env_map.insert("KEY".to_string(), "xyz".to_string());

        // A substituted value containing $KEY should NOT be re-expanded
        let result = substitute_env_vars("${TOKEN}", &env_map);
        assert_eq!(result, "abc$KEY");

        let result = substitute_env_vars("$TOKEN", &env_map);
        assert_eq!(result, "abc$KEY");
    }

    #[tokio::test]
    async fn test_tools_cache_invalidated_on_add_extension() {
        let temp_dir = tempfile::tempdir().unwrap();
        let extension_manager =
            ExtensionManager::new_without_provider(temp_dir.path().to_path_buf());

        extension_manager
            .add_mock_extension("ext_a".to_string(), Arc::new(MockClient {}))
            .await;

        let tools_after_first = extension_manager
            .get_prefixed_tools("test-session-id", None)
            .await
            .unwrap();
        let tool_names: Vec<String> = tools_after_first
            .iter()
            .map(|t| t.name.to_string())
            .collect();
        assert!(tool_names.iter().any(|n| n.starts_with("ext_a__")));
        assert!(!tool_names.iter().any(|n| n.starts_with("ext_b__")));

        extension_manager
            .add_mock_extension("ext_b".to_string(), Arc::new(MockClient {}))
            .await;

        let tools_after_second = extension_manager
            .get_prefixed_tools("test-session-id", None)
            .await
            .unwrap();
        let tool_names: Vec<String> = tools_after_second
            .iter()
            .map(|t| t.name.to_string())
            .collect();
        assert!(tool_names.iter().any(|n| n.starts_with("ext_a__")));
        assert!(tool_names.iter().any(|n| n.starts_with("ext_b__")));
    }

    #[tokio::test]
    async fn test_tools_cache_invalidated_on_remove_extension() {
        let temp_dir = tempfile::tempdir().unwrap();
        let extension_manager =
            ExtensionManager::new_without_provider(temp_dir.path().to_path_buf());

        extension_manager
            .add_mock_extension("ext_a".to_string(), Arc::new(MockClient {}))
            .await;
        extension_manager
            .add_mock_extension("ext_b".to_string(), Arc::new(MockClient {}))
            .await;

        let tools_before = extension_manager
            .get_prefixed_tools("test-session-id", None)
            .await
            .unwrap();
        let tool_names: Vec<String> = tools_before.iter().map(|t| t.name.to_string()).collect();
        assert!(tool_names.iter().any(|n| n.starts_with("ext_a__")));
        assert!(tool_names.iter().any(|n| n.starts_with("ext_b__")));

        extension_manager.remove_extension("ext_b").await.unwrap();

        let tools_after = extension_manager
            .get_prefixed_tools("test-session-id", None)
            .await
            .unwrap();
        let tool_names: Vec<String> = tools_after.iter().map(|t| t.name.to_string()).collect();
        assert!(tool_names.iter().any(|n| n.starts_with("ext_a__")));
        assert!(!tool_names.iter().any(|n| n.starts_with("ext_b__")));
    }

    #[tokio::test]
    async fn test_get_prefixed_tools_excluding() {
        let temp_dir = tempfile::tempdir().unwrap();
        let extension_manager =
            ExtensionManager::new_without_provider(temp_dir.path().to_path_buf());

        extension_manager
            .add_mock_extension("ext_a".to_string(), Arc::new(MockClient {}))
            .await;
        extension_manager
            .add_mock_extension("ext_b".to_string(), Arc::new(MockClient {}))
            .await;

        let tools = extension_manager
            .get_prefixed_tools_excluding("test-session-id", "ext_a")
            .await
            .unwrap();
        let tool_names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();

        assert!(!tool_names.iter().any(|n| n.starts_with("ext_a__")));
        assert!(tool_names.iter().any(|n| n.starts_with("ext_b__")));
    }

    #[tokio::test]
    async fn test_mcp_app_tools_identified_for_code_mode_exclusion() {
        let temp_dir = tempfile::tempdir().unwrap();
        let extension_manager =
            ExtensionManager::new_without_provider(temp_dir.path().to_path_buf());

        extension_manager
            .add_mock_extension("autovisualiser".to_string(), Arc::new(MockClient {}))
            .await;

        let tools = extension_manager
            .get_prefixed_tools_excluding("test-session-id", "code_execution")
            .await
            .unwrap();

        let (mcp_app_tools, regular_tools): (Vec<_>, Vec<_>) = tools
            .iter()
            .partition(|t| get_tool_resource_uri(t).is_some());

        assert_eq!(mcp_app_tools.len(), 1, "exactly one MCP app tool");
        assert_eq!(
            mcp_app_tools[0].name.as_ref(),
            "autovisualiser__render_chart"
        );
        assert!(
            regular_tools
                .iter()
                .all(|t| get_tool_resource_uri(t).is_none()),
            "non-MCP-app tools have no resourceUri"
        );
    }

    #[tokio::test]
    async fn test_get_prefixed_tools_by_extension_name() {
        let temp_dir = tempfile::tempdir().unwrap();
        let extension_manager =
            ExtensionManager::new_without_provider(temp_dir.path().to_path_buf());

        extension_manager
            .add_mock_extension("ext_a".to_string(), Arc::new(MockClient {}))
            .await;
        extension_manager
            .add_mock_extension("ext_b".to_string(), Arc::new(MockClient {}))
            .await;

        let tools = extension_manager
            .get_prefixed_tools("test-session-id", Some("ext_a".to_string()))
            .await
            .unwrap();
        let tool_names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();

        assert!(tool_names.iter().any(|n| n.starts_with("ext_a__")));
        assert!(!tool_names.iter().any(|n| n.starts_with("ext_b__")));
    }

    #[tokio::test]
    async fn test_resolve_tool_error_does_not_reflect_tool_names() {
        let temp_dir = tempfile::tempdir().unwrap();
        let extension_manager =
            ExtensionManager::new_without_provider(temp_dir.path().to_path_buf());

        extension_manager
            .add_mock_extension("ext_a".to_string(), Arc::new(MockClient {}))
            .await;

        let result = extension_manager
            .resolve_tool("test-session-id", "definitely_not_a_real_tool")
            .await;
        let err = match result {
            Ok(_) => panic!("resolve_tool should fail for an unknown name"),
            Err(e) => e,
        };

        let msg = err.message.to_string();
        assert_eq!(msg, TOOL_UNAVAILABLE_MESSAGE);
        assert!(!msg.contains("definitely_not_a_real_tool"));
        assert!(!msg.contains("ext_a__"));
    }

    struct MockDottedClient {}

    #[async_trait::async_trait]
    impl McpClientTrait for MockDottedClient {
        fn get_info(&self) -> Option<&InitializeResult> {
            None
        }

        async fn list_resources(
            &self,
            _session_id: &str,
            _next_cursor: Option<String>,
            _cancellation_token: CancellationToken,
        ) -> Result<ListResourcesResult, Error> {
            Err(Error::TransportClosed)
        }

        async fn read_resource(
            &self,
            _session_id: &str,
            _uri: &str,
            _cancellation_token: CancellationToken,
        ) -> Result<ReadResourceResult, Error> {
            Err(Error::TransportClosed)
        }

        async fn list_tools(
            &self,
            _session_id: &str,
            _next_cursor: Option<String>,
            _cancellation_token: CancellationToken,
        ) -> Result<ListToolsResult, Error> {
            use serde_json::json;
            use std::sync::Arc;
            Ok(ListToolsResult {
                tools: vec![
                    Tool::new(
                        "db.query".to_string(),
                        "A tool with a dotted name".to_string(),
                        Arc::new(json!({}).as_object().unwrap().clone()),
                    ),
                    Tool::new(
                        "db__query".to_string(),
                        "A sibling with the separator name".to_string(),
                        Arc::new(json!({}).as_object().unwrap().clone()),
                    ),
                ],
                next_cursor: None,
                meta: None,
                ..Default::default()
            })
        }

        async fn call_tool(
            &self,
            _ctx: &ToolCallContext,
            name: &str,
            _arguments: Option<JsonObject>,
            _cancellation_token: CancellationToken,
        ) -> Result<CallToolResult, Error> {
            match name {
                "db.query" | "db__query" => Ok(CallToolResult::success(vec![])),
                _ => Err(Error::TransportClosed),
            }
        }

        async fn list_prompts(
            &self,
            _session_id: &str,
            _next_cursor: Option<String>,
            _cancellation_token: CancellationToken,
        ) -> Result<ListPromptsResult, Error> {
            Err(Error::TransportClosed)
        }

        async fn get_prompt(
            &self,
            _session_id: &str,
            _name: &str,
            _arguments: Value,
            _cancellation_token: CancellationToken,
        ) -> Result<GetPromptResult, Error> {
            Err(Error::TransportClosed)
        }

        async fn subscribe(&self) -> mpsc::Receiver<ServerNotification> {
            mpsc::channel(1).1
        }
    }

    #[tokio::test]
    async fn test_resolve_tool_recovers_dotted_mangled_name() {
        let temp_dir = tempfile::tempdir().unwrap();
        let extension_manager =
            ExtensionManager::new_without_provider(temp_dir.path().to_path_buf());
        extension_manager
            .add_mock_extension("test_client".to_string(), Arc::new(MockClient {}))
            .await;

        let resolved = extension_manager
            .resolve_tool("test-session-id", "test_client.tool")
            .await
            .expect("mangled dotted name should resolve to the real tool");
        assert_eq!(resolved.extension_name, "test_client");
        assert_eq!(resolved.actual_tool_name, "tool");
    }

    #[tokio::test]
    async fn test_resolve_tool_recovers_functions_prefixed_name() {
        let temp_dir = tempfile::tempdir().unwrap();
        let extension_manager =
            ExtensionManager::new_without_provider(temp_dir.path().to_path_buf());
        extension_manager
            .add_mock_extension("test_client".to_string(), Arc::new(MockClient {}))
            .await;

        let resolved = extension_manager
            .resolve_tool("test-session-id", "functions.test_client__tool")
            .await
            .expect("functions-prefixed name should resolve to the real tool");
        assert_eq!(resolved.extension_name, "test_client");
        assert_eq!(resolved.actual_tool_name, "tool");
    }

    #[tokio::test]
    async fn test_resolve_tool_exact_dotted_name_never_rewritten() {
        let temp_dir = tempfile::tempdir().unwrap();
        let extension_manager =
            ExtensionManager::new_without_provider(temp_dir.path().to_path_buf());
        extension_manager
            .add_mock_extension("dotted".to_string(), Arc::new(MockDottedClient {}))
            .await;

        let resolved = extension_manager
            .resolve_tool("test-session-id", "dotted__db.query")
            .await
            .expect("exact dotted tool name must resolve");
        assert_eq!(resolved.extension_name, "dotted");
        assert_eq!(resolved.actual_tool_name, "db.query");
    }

    #[tokio::test]
    async fn test_resolve_tool_recovers_mangled_separator_with_dotted_tool_name() {
        let temp_dir = tempfile::tempdir().unwrap();
        let extension_manager =
            ExtensionManager::new_without_provider(temp_dir.path().to_path_buf());
        extension_manager
            .add_mock_extension("dotted".to_string(), Arc::new(MockDottedClient {}))
            .await;

        let resolved = extension_manager
            .resolve_tool("test-session-id", "dotted.db.query")
            .await
            .expect("mangled extension separator should resolve");
        assert_eq!(resolved.extension_name, "dotted");
        assert_eq!(resolved.actual_tool_name, "db.query");
    }

    #[test]
    fn test_recover_mangled_tool_name() {
        let tools = ["developer__shell", "platform__search"];
        assert_eq!(
            recover_mangled_tool_name("developer.shell", tools.iter().copied()).as_deref(),
            Some("developer__shell")
        );
        assert_eq!(
            recover_mangled_tool_name("functions.developer__shell", tools.iter().copied())
                .as_deref(),
            Some("developer__shell")
        );
        assert_eq!(
            recover_mangled_tool_name("functions.developer.shell", tools.iter().copied())
                .as_deref(),
            Some("developer__shell")
        );
        assert_eq!(
            recover_mangled_tool_name("developer shell", tools.iter().copied()),
            None
        );
        assert_eq!(
            recover_mangled_tool_name("developer__shell!", tools.iter().copied()),
            None
        );
        assert_eq!(
            recover_mangled_tool_name("nonexistent.tool", tools.iter().copied()),
            None
        );

        let dotted_tool = ["dotted__db.query"];
        assert_eq!(
            recover_mangled_tool_name("dotted.db.query", dotted_tool.iter().copied()).as_deref(),
            Some("dotted__db.query")
        );
    }

    #[test]
    fn test_remove_untrusted_mcp_app_meta_strips_spoofed_payload() {
        let mut result = CallToolResult::success(vec![]);
        result.meta = Some(MetaObject(
            serde_json::from_value(serde_json::json!({
                "goose": {
                    "mcpApp": {
                        "resourceUri": "ui://spoofed/app",
                    },
                    "other": true,
                },
                TRUSTED_TOOL_UPDATE_META_KEY: {
                    "mcpApp": {
                        "resourceUri": "ui://spoofed/internal",
                    },
                },
            }))
            .unwrap(),
        ));

        remove_untrusted_mcp_app_meta(&mut result);

        let meta = result.meta.expect("expected remaining meta");
        assert_eq!(meta.0.get(TRUSTED_TOOL_UPDATE_META_KEY), None);
        assert_eq!(
            meta.0.get("goose"),
            Some(&serde_json::json!({ "other": true }))
        );
    }

    #[test]
    fn test_insert_trusted_tool_update_meta_stores_backend_payload() {
        let mut result = CallToolResult::success(vec![]);
        let attachment = GooseMcpAppToolAttachment {
            tool_name: "render__secret".to_string(),
            tool_name_is_actual: true,
            extension_name: "weather".to_string(),
            resource_uri: "ui://weather/app".to_string(),
            tool_meta: None,
            resource_result: Some(serde_json::json!({
                "contents": [
                    {
                        "uri": "ui://weather/app",
                        "mimeType": "text/html;profile=mcp-app",
                        "text": "<div>Hello</div>",
                    },
                ],
            })),
            read_error: None,
        };

        insert_trusted_tool_update_meta(&mut result, &attachment);

        let meta = result.meta.expect("expected trusted meta");
        assert_eq!(
            meta.0.get(TRUSTED_TOOL_UPDATE_META_KEY),
            Some(&serde_json::json!({
                "mcpApp": {
                    "toolName": "render__secret",
                    "toolNameIsActual": true,
                    "extensionName": "weather",
                    "resourceUri": "ui://weather/app",
                    "resourceResult": {
                        "contents": [
                            {
                                "uri": "ui://weather/app",
                                "mimeType": "text/html;profile=mcp-app",
                                "text": "<div>Hello</div>",
                            },
                        ],
                    },
                },
            })),
        );
    }

    #[cfg(not(feature = "accordlock-distribution"))]
    #[tokio::test]
    async fn test_add_extension_noop_on_identical_config() {
        // When add_extension is called with a config that is byte-for-byte identical to
        // the already-loaded one, it must return Ok(()) without removing the extension.
        let temp_dir = tempfile::tempdir().unwrap();
        let em = Arc::new(ExtensionManager::new_without_provider(
            temp_dir.path().to_path_buf(),
        ));

        let config = ExtensionConfig::Frontend {
            name: "test-ext".to_string(),
            description: "original".to_string(),
            tools: vec![],
            instructions: None,
            bundled: None,
            available_tools: vec![],
        };

        em.add_client(
            "test-ext".to_string(),
            config.clone(),
            Arc::new(MockClient {}),
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(em.extensions.lock().await.len(), 1);

        // Calling add_extension with the same config must be a no-op (Ok, count unchanged).
        let result = em.add_extension(config, None, None, None).await;
        assert!(result.is_ok(), "identical config should be a no-op");
        assert_eq!(
            em.extensions.lock().await.len(),
            1,
            "extension must not be removed on no-op"
        );
    }

    #[cfg(not(feature = "accordlock-distribution"))]
    #[tokio::test]
    async fn test_add_extension_replaces_extension_on_config_change() {
        // When add_extension is called with an updated config (same name, different fields),
        // the existing extension must be removed so the caller can re-add with new config.
        let temp_dir = tempfile::tempdir().unwrap();
        let em = Arc::new(ExtensionManager::new_without_provider(
            temp_dir.path().to_path_buf(),
        ));

        let config_a = ExtensionConfig::Frontend {
            name: "test-ext".to_string(),
            description: "version-a".to_string(),
            tools: vec![],
            instructions: None,
            bundled: None,
            available_tools: vec![],
        };
        let config_b = ExtensionConfig::Frontend {
            name: "test-ext".to_string(),
            description: "version-b".to_string(), // changed
            tools: vec![],
            instructions: None,
            bundled: None,
            available_tools: vec![],
        };

        em.add_client(
            "test-ext".to_string(),
            config_a,
            Arc::new(MockClient {}),
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(em.extensions.lock().await.len(), 1);

        // add_extension with changed config attempts to create a new client (fails here
        // because Frontend configs cannot be added as server extensions), but must preserve
        // the old extension so the session isn't left without it.
        let result = em.add_extension(config_b, None, None, None).await;
        assert!(result.is_err(), "Frontend add_extension must return Err");
        assert_eq!(
            em.extensions.lock().await.len(),
            1,
            "old extension must be preserved when replacement client creation fails"
        );
    }

    #[cfg(feature = "accordlock-distribution")]
    #[tokio::test]
    async fn accordlock_rejects_injected_developer_client() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manager = ExtensionManager::new_without_provider(temp_dir.path().to_path_buf());
        let config = ExtensionConfig::Platform {
            name: "developer".to_string(),
            description: String::new(),
            display_name: Some("Developer".to_string()),
            bundled: Some(true),
            available_tools: vec![],
        };

        let result = manager
            .add_client(
                "developer".to_string(),
                config,
                Arc::new(MockClient {}),
                None,
                None,
            )
            .await;

        assert!(result.is_err());
        assert!(manager.extensions.lock().await.is_empty());
    }

    fn transport_err(error: Box<dyn std::error::Error + Send + Sync>) -> ClientInitializeError {
        ClientInitializeError::TransportError {
            error: rmcp::transport::DynamicTransportError::from_parts(
                "test",
                std::any::TypeId::of::<()>(),
                error,
            ),
            context: "test context".into(),
        }
    }

    fn streamable_err(
        e: rmcp::transport::streamable_http_client::StreamableHttpError<reqwest::Error>,
    ) -> ClientInitializeError {
        transport_err(Box::new(e))
    }

    #[test]
    fn test_oauth_fallback_on_typed_auth_required() {
        let err = streamable_err(
            rmcp::transport::streamable_http_client::StreamableHttpError::AuthRequired(
                rmcp::transport::streamable_http_client::AuthRequiredError::new(
                    "Bearer realm=\"test\"".to_string(),
                ),
            ),
        );
        assert!(should_attempt_oauth_fallback(&Err(err)));
    }

    #[test]
    fn test_oauth_fallback_on_unexpected_response_http_401_prefix() {
        let err = streamable_err(
            rmcp::transport::streamable_http_client::StreamableHttpError::UnexpectedServerResponse(
                std::borrow::Cow::Borrowed("HTTP 401 Unauthorized"),
            ),
        );
        assert!(should_attempt_oauth_fallback(&Err(err)));
    }

    #[tokio::test]
    async fn test_post_refresh_auth_failure_clears_credentials() {
        use rmcp::transport::auth::{
            InMemoryCredentialStore, OAuthTokenResponse, StoredCredentials,
        };

        let token_response: OAuthTokenResponse = serde_json::from_value(serde_json::json!({
            "access_token": "rejected-token",
            "token_type": "bearer",
        }))
        .expect("valid fake token JSON");
        let store = InMemoryCredentialStore::new();
        store
            .save(StoredCredentials::new(
                "test-client".to_string(),
                Some(token_response),
                vec![],
                None,
            ))
            .await
            .unwrap();

        let err = streamable_err(
            rmcp::transport::streamable_http_client::StreamableHttpError::AuthRequired(
                rmcp::transport::streamable_http_client::AuthRequiredError::new(
                    "Bearer error=\"invalid_token\"".to_string(),
                ),
            ),
        );
        let error = ExtensionError::InitializeError(err);

        assert!(clear_credentials_on_post_refresh_auth_failure(&store, "test-ext", &error).await);
        assert!(store.load().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_invalid_header_name_returns_config_error() {
        let mut headers = HashMap::new();
        headers.insert("bad header name".to_string(), "value".to_string());

        let temp_dir = tempdir().unwrap();
        let provider: SharedProvider = Arc::new(Mutex::new(None));
        let capabilities = GooseMcpClientCapabilities {
            mcpui: false,
            host_info: None,
        };

        let result = create_streamable_http_client(
            "http://localhost:1",
            None,
            &headers,
            "test-ext",
            None,
            None,
            Box::new(rmcp::transport::auth::InMemoryCredentialStore::new()),
            provider,
            "goose-test".to_string(),
            capabilities,
            temp_dir.path(),
            Arc::new(ActionRequiredManager::new()),
            Weak::new(),
        )
        .await;

        let Err(ExtensionError::ConfigError(msg)) = result else {
            panic!("expected ConfigError, got a different result");
        };
        assert!(
            msg.contains("invalid header"),
            "unexpected error message: {msg}"
        );
    }

    #[tokio::test]
    async fn test_invalid_header_value_returns_config_error() {
        let mut headers = HashMap::new();
        headers.insert("x-valid-name".to_string(), "bad\r\nvalue".to_string());

        let temp_dir = tempdir().unwrap();
        let provider: SharedProvider = Arc::new(Mutex::new(None));
        let capabilities = GooseMcpClientCapabilities {
            mcpui: false,
            host_info: None,
        };

        let result = create_streamable_http_client(
            "http://localhost:1",
            None,
            &headers,
            "test-ext",
            None,
            None,
            Box::new(rmcp::transport::auth::InMemoryCredentialStore::new()),
            provider,
            "goose-test".to_string(),
            capabilities,
            temp_dir.path(),
            Arc::new(ActionRequiredManager::new()),
            Weak::new(),
        )
        .await;

        let Err(ExtensionError::ConfigError(msg)) = result else {
            panic!("expected ConfigError, got a different result");
        };
        assert!(
            msg.contains("invalid header value"),
            "unexpected error message: {msg}"
        );
    }

    #[tokio::test]
    async fn test_custom_headers_forwarded_to_http_extension() {
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let mut headers = HashMap::new();
        headers.insert("x-api-key".to_string(), "test-secret-123".to_string());

        let temp_dir = tempdir().unwrap();
        let provider: SharedProvider = Arc::new(Mutex::new(None));
        let capabilities = GooseMcpClientCapabilities {
            mcpui: false,
            host_info: None,
        };

        // The MCP handshake will fail against the stub server. We only care that
        // the outgoing HTTP request carried the custom header.
        let _ = create_streamable_http_client(
            &mock_server.uri(),
            None,
            &headers,
            "test-ext",
            None,
            None,
            Box::new(rmcp::transport::auth::InMemoryCredentialStore::new()),
            provider,
            "goose-test".to_string(),
            capabilities,
            temp_dir.path(),
            Arc::new(ActionRequiredManager::new()),
            Weak::new(),
        )
        .await;

        let received = mock_server.received_requests().await.unwrap();
        assert!(
            !received.is_empty(),
            "expected at least one HTTP request to reach the mock server"
        );
        let header_found = received.iter().any(|req| {
            req.headers
                .get("x-api-key")
                .map(|v| v == "test-secret-123")
                .unwrap_or(false)
        });
        assert!(
            header_found,
            "custom header x-api-key was not forwarded to the extension server"
        );
    }

    /// Directly exercises `connect_with_auth`, which is the code path fixed by
    /// the PR (custom headers were dropped when the OAuth connection path was
    /// taken).  Uses a pre-seeded `InMemoryCredentialStore` with a fake,
    /// non-expiring token so `get_access_token()` returns immediately without
    /// touching any OAuth endpoints or the system keychain.
    #[tokio::test]
    async fn test_custom_headers_forwarded_oauth_path() {
        use rmcp::transport::auth::{
            InMemoryCredentialStore, OAuthTokenResponse, StoredCredentials,
        };
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let mut headers = HashMap::new();
        headers.insert("x-api-key".to_string(), "test-secret-oauth".to_string());

        // Build a fake, non-expiring token. token_received_at=None skips the
        // expiry check, so get_access_token() returns without any network call.
        let token_response: OAuthTokenResponse = serde_json::from_value(serde_json::json!({
            "access_token": "fake-test-token",
            "token_type": "bearer",
        }))
        .expect("valid fake token JSON");
        let creds = StoredCredentials::new(
            "test-client".to_string(),
            Some(token_response),
            vec![],
            None,
        );
        let store = InMemoryCredentialStore::new();
        store.save(creds).await.unwrap();

        let mut auth_manager = rmcp::transport::AuthorizationManager::new(mock_server.uri())
            .await
            .expect("AuthorizationManager::new should not make network calls");
        auth_manager.set_credential_store(store);

        let temp_dir = tempdir().unwrap();
        let provider: SharedProvider = Arc::new(Mutex::new(None));
        let capabilities = GooseMcpClientCapabilities {
            mcpui: false,
            host_info: None,
        };

        // connect_with_auth will fail (mock server isn't an MCP server) but we
        // only care that the outgoing request carried the custom header.
        let _ = connect_with_auth(
            auth_manager,
            Arc::new(ActionRequiredManager::new()),
            &mock_server.uri(),
            Duration::from_secs(5),
            &headers,
            provider,
            "goose-test".to_string(),
            capabilities,
            temp_dir.path(),
            Weak::new(),
        )
        .await;

        let received = mock_server.received_requests().await.unwrap();
        assert!(
            !received.is_empty(),
            "expected at least one HTTP request to reach the mock server"
        );
        let header_found = received.iter().any(|req| {
            req.headers
                .get("x-api-key")
                .map(|v| v == "test-secret-oauth")
                .unwrap_or(false)
        });
        assert!(
            header_found,
            "custom header x-api-key was not forwarded through the OAuth connection path"
        );
    }
}
