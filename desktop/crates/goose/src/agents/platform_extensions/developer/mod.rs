pub mod edit;
pub mod image;
pub mod shell;
mod shell_output_streaming;
pub mod tree;

#[cfg(feature = "accordlock-distribution")]
use crate::agents::accordlock_network::{
    is_enabled as governed_network_enabled, BrokeredHttpsArguments,
};
#[cfg(feature = "accordlock-distribution")]
use crate::agents::accordlock_terminal::{BrokeredTerminalArguments, BrokeredTerminalOutput};
use crate::agents::extension::PlatformExtensionContext;
use crate::agents::mcp_client::{Error, McpClientTrait};
use crate::agents::ToolCallContext;
use anyhow::Result;
use async_trait::async_trait;
#[cfg(not(feature = "accordlock-distribution"))]
use edit::EditTools;
#[cfg(feature = "accordlock-distribution")]
use edit::FileReadParams;
use edit::{FileEditParams, FileWriteParams};
use image::ImageReadParams;
#[cfg(not(feature = "accordlock-distribution"))]
use image::ImageTool;
use indoc::indoc;
use rmcp::model::{
    Annotations, CallToolResult, ContentBlock, Implementation, InitializeResult, JsonObject,
    ListToolsResult, ServerCapabilities, TextContent, Tool, ToolAnnotations,
};
use schemars::{schema_for, JsonSchema};
#[cfg(feature = "accordlock-distribution")]
use serde::Deserialize;
use serde_json::Value;
#[cfg(not(feature = "accordlock-distribution"))]
use shell::ShellTool;
use shell::{shell_display_name, ShellOutput, ShellParams};
#[cfg(any(not(feature = "accordlock-distribution"), test))]
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tree::TreeParams;
#[cfg(not(feature = "accordlock-distribution"))]
use tree::TreeTool;

pub static EXTENSION_NAME: &str = "developer";

#[cfg(feature = "accordlock-distribution")]
#[allow(dead_code)] // This schema-only type is enforced by the trusted filesystem broker.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct FileDeleteParams {
    /// Portable path, relative to the approved workspace, for one regular file.
    path: String,
}

fn visible_text(text: impl Into<String>) -> ContentBlock {
    ContentBlock::Text(
        TextContent::new(text).with_annotations(Annotations::default().with_priority(0.0)),
    )
}

pub struct DeveloperClient {
    info: InitializeResult,
    #[cfg(not(feature = "accordlock-distribution"))]
    shell_tool: Arc<ShellTool>,
    #[cfg(not(feature = "accordlock-distribution"))]
    edit_tools: Arc<EditTools>,
    #[cfg(not(feature = "accordlock-distribution"))]
    tree_tool: Arc<TreeTool>,
    #[cfg(not(feature = "accordlock-distribution"))]
    image_tool: Arc<ImageTool>,
}

fn developer_instructions() -> &'static str {
    if cfg!(feature = "accordlock-distribution") {
        return indoc! {"
            Use the developer extension to inspect and edit files inside the approved workspace.

            Use tree to understand the project, read to inspect text, write to create or replace a
            file, edit for one exact replacement, delete_file to move one exact regular file to
            recoverable storage, and shell for a configured program alias plus literal arguments.
            Never substitute another operation when the exact capability is unavailable. Shell
            accepts argv only: never pass a command string or shell syntax. Always pass portable
            paths relative to the workspace. Each operation is authorized and executed by
            AccordLock's trusted broker. Direct local or network image access is unavailable in
            this security profile. When https_request is present, use it only for exact GET or HEAD
            requests to configured destinations; each request requires one-time approval.
        "};
    }
    if cfg!(windows) {
        indoc! {"
            Use the developer extension to build software and operate a terminal.

            Make sure to use the tools *efficiently* - reading all the content you need in as few
            iterations as possible and then making the requested edits or running commands. You are
            responsible for managing your context window, and to minimize unnecessary turns which
            cost the user money.

            For editing software, prefer the flow of using tree to understand the codebase structure
            and file sizes. When you need to search, prefer findstr or Select-String (via shell).
            Then use type or Get-Content to gather the context you need, always reading before
            editing. Use write and edit to efficiently make changes. Test and verify as appropriate.
        "}
    } else {
        indoc! {"
            Use the developer extension to build software and operate a terminal.

            Make sure to use the tools *efficiently* - reading all the content you need in as few
            iterations as possible and then making the requested edits or running commands. You are
            responsible for managing your context window, and to minimize unnecessary turns which
            cost the user money.

            For editing software, prefer the flow of using tree to understand the codebase structure
            and file sizes. When you need to search, prefer rg which correctly respects gitignored
            content. Then use cat or sed to gather the context you need, always reading before editing.
            Use write and edit to efficiently make changes. Test and verify as appropriate.

            When running Python scripts or commands, always use `python3` instead of `python`.
        "}
    }
}

impl DeveloperClient {
    pub fn new(_context: PlatformExtensionContext) -> Result<Self> {
        let info = InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(EXTENSION_NAME, "1.0.0").with_title("Developer"))
            .with_instructions(developer_instructions());

        Ok(Self {
            info,
            #[cfg(not(feature = "accordlock-distribution"))]
            shell_tool: Arc::new(ShellTool::new(_context.use_login_shell_path)?),
            #[cfg(not(feature = "accordlock-distribution"))]
            edit_tools: Arc::new(EditTools::new()),
            #[cfg(not(feature = "accordlock-distribution"))]
            tree_tool: Arc::new(TreeTool::new()),
            #[cfg(not(feature = "accordlock-distribution"))]
            image_tool: Arc::new(ImageTool::new()),
        })
    }

    fn schema<T: JsonSchema>() -> JsonObject {
        serde_json::to_value(schema_for!(T))
            .expect("schema serialization should succeed")
            .as_object()
            .expect("schema should serialize to an object")
            .clone()
    }

    pub fn parse_args<T: serde::de::DeserializeOwned>(
        arguments: Option<JsonObject>,
    ) -> Result<T, String> {
        let value = arguments
            .map(Value::Object)
            .ok_or_else(|| "Missing arguments".to_string())?;
        serde_json::from_value(value).map_err(|e| format!("Failed to parse arguments: {e}"))
    }

    pub(crate) fn get_tools() -> Vec<Tool> {
        #[allow(unused_mut)]
        let mut tools = vec![
            Tool::new(
                "write".to_string(),
                "Create a new file or overwrite an existing file. Creates parent directories if needed.".to_string(),
                Self::schema::<FileWriteParams>(),
            )
            .annotate(ToolAnnotations::from_raw(
                Some("Write".to_string()),
                Some(false),
                Some(true),
                Some(false),
                Some(false),
            )),
            Tool::new(
                "edit".to_string(),
                "Edit a file by finding and replacing text. The before text must match exactly and uniquely. Use empty after text to delete.".to_string(),
                Self::schema::<FileEditParams>(),
            )
            .annotate(ToolAnnotations::from_raw(
                Some("Edit".to_string()),
                Some(false),
                Some(true),
                Some(false),
                Some(false),
            )),
            Tool::new(
                "shell".to_string(),
                format!(
                    "Execute a shell command in the current dir. Commands run under `{shell}` \
                     (set GOOSE_SHELL to override) - write command strings in that shell's \
                     syntax. Returns an object with stdout and stderr as separate fields. The \
                     output of each stream is limited to up to 2000 lines, and longer outputs \
                     will be saved to a temporary file.",
                    shell = shell_display_name(),
                ),
                Self::schema::<ShellParams>(),
            )
            .with_output_schema::<ShellOutput>()
            .annotate(ToolAnnotations::from_raw(
                Some("Shell".to_string()),
                Some(false),
                Some(true),
                Some(false),
                Some(true),
            )),
            Tool::new(
                "tree".to_string(),
                "List a directory tree with line counts. Traversal respects .gitignore rules.".to_string(),
                Self::schema::<TreeParams>(),
            )
            .annotate(ToolAnnotations::from_raw(
                Some("Tree".to_string()),
                Some(true),
                Some(false),
                Some(true),
                Some(false),
            )),
            Tool::new(
                "read_image".to_string(),
                "Read an image from a local file path or http(s) URL and return it as image content for the model to inspect. Supports png, jpeg, gif, and webp.".to_string(),
                Self::schema::<ImageReadParams>(),
            )
            .annotate(ToolAnnotations::from_raw(
                Some("Read Image".to_string()),
                Some(false),
                Some(false),
                Some(true),
                Some(true),
            )),
        ];
        #[cfg(feature = "accordlock-distribution")]
        {
            tools.retain(|tool| !matches!(tool.name.as_ref(), "shell" | "read_image"));
            tools.insert(
                0,
                Tool::new(
                    "read".to_string(),
                    "Read a UTF-8 text file inside the approved workspace through the AccordLock filesystem broker."
                        .to_string(),
                    Self::schema::<FileReadParams>(),
                )
                .annotate(ToolAnnotations::from_raw(
                    Some("Read".to_string()),
                    Some(true),
                    Some(false),
                    Some(true),
                    Some(false),
                )),
            );
            tools.insert(
                3,
                Tool::new(
                    "delete_file".to_string(),
                    "Move one exact regular file to AccordLock recovery storage. Directory and recursive deletion are not supported."
                        .to_string(),
                    Self::schema::<FileDeleteParams>(),
                )
                .annotate(ToolAnnotations::from_raw(
                    Some("Move file to recovery storage".to_string()),
                    Some(false),
                    Some(true),
                    Some(false),
                    Some(false),
                )),
            );
            tools.insert(
                4,
                Tool::new(
                    "shell".to_string(),
                    "Run one administrator-configured program alias through AccordLock. Pass argv[0] as the alias and every remaining argument as a separate literal value; command strings, shell syntax, executable paths, inherited environment, and PTYs are not supported. cwd must be relative to the approved workspace."
                        .to_string(),
                    Self::schema::<BrokeredTerminalArguments>(),
                )
                .with_output_schema::<BrokeredTerminalOutput>()
                .annotate(ToolAnnotations::from_raw(
                    Some("Run governed program".to_string()),
                    Some(false),
                    Some(true),
                    Some(false),
                    Some(false),
                )),
            );
            if governed_network_enabled() {
                tools.push(
                    Tool::new(
                        "https_request".to_string(),
                        "Read one exact HTTPS URL on an administrator-configured domain. Only GET and HEAD are supported. Every request requires single-use approval; redirects, credentials, proxies, request bodies, and wildcard domains are unavailable."
                            .to_string(),
                        Self::schema::<BrokeredHttpsArguments>(),
                    )
                    .annotate(ToolAnnotations::from_raw(
                        Some("Read approved website".to_string()),
                        Some(true),
                        Some(false),
                        Some(true),
                        Some(true),
                    )),
                );
            }
        }
        tools
    }
}

#[async_trait]
impl McpClientTrait for DeveloperClient {
    async fn list_tools(
        &self,
        _session_id: &str,
        _next_cursor: Option<String>,
        _cancellation_token: CancellationToken,
    ) -> Result<ListToolsResult, Error> {
        Ok(ListToolsResult {
            tools: Self::get_tools(),
            next_cursor: None,
            meta: None,
            ..Default::default()
        })
    }

    async fn call_tool(
        &self,
        ctx: &ToolCallContext,
        name: &str,
        arguments: Option<JsonObject>,
        cancel_token: CancellationToken,
    ) -> Result<CallToolResult, Error> {
        #[cfg(feature = "accordlock-distribution")]
        if matches!(
            name,
            "read"
                | "write"
                | "edit"
                | "delete_file"
                | "tree"
                | "shell"
                | "read_image"
                | "https_request"
        ) {
            return Ok(CallToolResult::error(vec![visible_text(
                "Error: AccordLock tools must execute through the trusted dispatch boundary.",
            )]));
        }

        let working_dir = ctx.working_dir.as_deref();
        #[cfg(feature = "accordlock-distribution")]
        let _ = (&arguments, &cancel_token, working_dir);
        match name {
            #[cfg(not(feature = "accordlock-distribution"))]
            "shell" => match Self::parse_args::<ShellParams>(arguments) {
                Ok(params) => Ok(self
                    .shell_tool
                    .shell_with_cwd_and_emitter(
                        params,
                        working_dir,
                        Some(&ctx.session_id),
                        ctx.notification_emitter().cloned(),
                        cancel_token,
                    )
                    .await),
                Err(error) => Ok(ShellTool::error_result(&format!("Error: {error}"), None)),
            },
            #[cfg(not(feature = "accordlock-distribution"))]
            "write" => match Self::parse_args::<FileWriteParams>(arguments) {
                Ok(params) => Ok(self.edit_tools.file_write_with_cwd(params, working_dir)),
                Err(error) => Ok(CallToolResult::error(vec![visible_text(format!(
                    "Error: {error}"
                ))])),
            },
            #[cfg(not(feature = "accordlock-distribution"))]
            "edit" => match Self::parse_args::<FileEditParams>(arguments) {
                Ok(params) => Ok(self.edit_tools.file_edit_with_cwd(params, working_dir)),
                Err(error) => Ok(CallToolResult::error(vec![visible_text(format!(
                    "Error: {error}"
                ))])),
            },
            #[cfg(not(feature = "accordlock-distribution"))]
            "tree" => match Self::parse_args::<TreeParams>(arguments) {
                Ok(params) => Ok(self.tree_tool.tree_with_cwd(params, working_dir)),
                Err(error) => Ok(CallToolResult::error(vec![visible_text(format!(
                    "Error: {error}"
                ))])),
            },
            #[cfg(not(feature = "accordlock-distribution"))]
            "read_image" => match Self::parse_args::<ImageReadParams>(arguments) {
                Ok(params) => Ok(self
                    .image_tool
                    .image_read_with_cwd(params, working_dir)
                    .await),
                Err(error) => Ok(CallToolResult::error(vec![visible_text(format!(
                    "Error: {error}"
                ))])),
            },
            _ => Ok(CallToolResult::error(vec![visible_text(format!(
                "Error: Unknown tool: {name}"
            ))])),
        }
    }

    fn get_info(&self) -> Option<&InitializeResult> {
        Some(&self.info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SessionManager;
    #[cfg(not(windows))]
    use rmcp::model::ContentBlock;
    use rmcp::object;
    use std::fs;

    #[test]
    fn developer_tools_are_flat() {
        let names: Vec<String> = DeveloperClient::get_tools()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();

        #[cfg(feature = "accordlock-distribution")]
        assert_eq!(
            names,
            vec!["read", "write", "edit", "delete_file", "shell", "tree"]
        );
        #[cfg(not(feature = "accordlock-distribution"))]
        assert_eq!(names, vec!["write", "edit", "shell", "tree", "read_image"]);
    }

    #[cfg(feature = "accordlock-distribution")]
    #[test]
    fn governed_shell_schema_is_direct_argv_only() {
        let shell = DeveloperClient::get_tools()
            .into_iter()
            .find(|tool| tool.name == "shell")
            .unwrap();
        let schema = Value::Object(shell.input_schema.as_ref().clone());
        let properties = schema["properties"].as_object().unwrap();

        assert!(properties.contains_key("argv"));
        assert!(!properties.contains_key("command"));
        assert!(!properties.contains_key("pty"));
        assert_eq!(schema["additionalProperties"], Value::Bool(false));
    }

    #[cfg(not(feature = "accordlock-distribution"))]
    #[test]
    fn read_image_annotations_reflect_network_access() {
        let read_image = DeveloperClient::get_tools()
            .into_iter()
            .find(|tool| tool.name == "read_image")
            .unwrap();
        let annotations = read_image.annotations.unwrap();

        assert_eq!(annotations.read_only_hint, Some(false));
        assert_eq!(annotations.open_world_hint, Some(true));
    }

    fn test_context(data_dir: std::path::PathBuf) -> PlatformExtensionContext {
        PlatformExtensionContext {
            extension_manager: None,
            session_manager: Arc::new(SessionManager::new(data_dir)),
            scheduler: None,
            session: None,
            use_login_shell_path: false,
        }
    }

    #[cfg(not(windows))]
    fn first_text(result: &CallToolResult) -> &str {
        match &result.content[0] {
            ContentBlock::Text(text) => &text.text,
            _ => panic!("expected text content"),
        }
    }

    #[cfg(not(feature = "accordlock-distribution"))]
    #[tokio::test]
    async fn developer_client_uses_working_dir_for_file_tools() {
        let temp = tempfile::tempdir().unwrap();
        let client = DeveloperClient::new(test_context(temp.path().join("sessions"))).unwrap();
        let cwd = temp.path().join("workspace");
        fs::create_dir_all(&cwd).unwrap();

        let ctx = ToolCallContext::new("session".to_owned(), Some(cwd.clone()), None);
        let write = client
            .call_tool(
                &ctx,
                "write",
                Some(object!({
                    "path": "notes.txt",
                    "content": "first line"
                })),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(write.is_error, Some(false));
        assert_eq!(
            fs::read_to_string(cwd.join("notes.txt")).unwrap(),
            "first line"
        );

        let edit = client
            .call_tool(
                &ctx,
                "edit",
                Some(object!({
                    "path": "notes.txt",
                    "before": "first",
                    "after": "updated"
                })),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(edit.is_error, Some(false));
        assert_eq!(
            fs::read_to_string(cwd.join("notes.txt")).unwrap(),
            "updated line"
        );
    }

    #[cfg(feature = "accordlock-distribution")]
    #[tokio::test]
    async fn accordlock_client_cannot_execute_filesystem_tools_directly() {
        let temporary = tempfile::tempdir().unwrap();
        let client = DeveloperClient::new(test_context(temporary.path().join("sessions"))).unwrap();
        let workspace = temporary.path().join("workspace");
        fs::create_dir_all(&workspace).unwrap();
        let context = ToolCallContext::new("session".to_owned(), Some(workspace.clone()), None);

        let result = client
            .call_tool(
                &context,
                "write",
                Some(object!({"path": "blocked.txt", "content": "blocked"})),
                CancellationToken::new(),
            )
            .await
            .unwrap();

        assert_eq!(result.is_error, Some(true));
        assert!(!workspace.join("blocked.txt").exists());
    }

    #[cfg(all(not(windows), not(feature = "accordlock-distribution")))]
    #[tokio::test]
    async fn developer_client_passes_session_id_to_shell_tool() {
        let temp = tempfile::tempdir().unwrap();
        let client = DeveloperClient::new(test_context(temp.path().join("sessions"))).unwrap();
        let ctx = ToolCallContext::new("session-789".to_owned(), None, None);

        let result = client
            .call_tool(
                &ctx,
                "shell",
                Some(object!({
                    "command": "printenv AGENT_SESSION_ID"
                })),
                CancellationToken::new(),
            )
            .await
            .unwrap();

        assert_eq!(result.is_error, Some(false));
        assert_eq!(first_text(&result), "session-789");
    }

    #[cfg(all(not(windows), not(feature = "accordlock-distribution")))]
    #[tokio::test]
    async fn developer_client_uses_working_dir_for_shell_tool() {
        let temp = tempfile::tempdir().unwrap();
        let client = DeveloperClient::new(test_context(temp.path().join("sessions"))).unwrap();
        let cwd = temp.path().join("workspace");
        fs::create_dir_all(&cwd).unwrap();

        let ctx = ToolCallContext::new("session".to_owned(), Some(cwd.clone()), None);
        let result = client
            .call_tool(
                &ctx,
                "shell",
                Some(object!({
                    "command": "pwd"
                })),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(result.is_error, Some(false));
        let observed = std::fs::canonicalize(first_text(&result)).unwrap();
        let expected = std::fs::canonicalize(&cwd).unwrap();
        assert_eq!(observed, expected);
    }
}
