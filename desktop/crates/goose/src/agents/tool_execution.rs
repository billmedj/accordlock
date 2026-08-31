use async_stream::try_stream;
use futures::stream::{self, BoxStream};
use futures::{Stream, StreamExt};
use rmcp::model::CallToolResult;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use std::path::PathBuf;

use crate::config::permission::PermissionLevel;
use crate::conversation::message::Message;
use crate::mcp_utils::ToolResult;
use crate::permission::Permission;
use rmcp::model::{ContentBlock, ServerNotification};

use super::accordlock_authorization::{
    canonical_json_bytes, sha256_digest, AgentPlanCheckpointInput, PolicyEnforcementError,
};

#[derive(Clone)]
pub(crate) struct ToolCallNotificationEmitter {
    sender: mpsc::Sender<ServerNotification>,
}

impl ToolCallNotificationEmitter {
    pub(crate) fn new(sender: mpsc::Sender<ServerNotification>) -> Self {
        Self { sender }
    }

    pub(crate) fn emit_best_effort(&self, notification: ServerNotification) {
        // Do not let a slow notification consumer delay tool execution.
        let _ = self.sender.try_send(notification);
    }
}

/// Context passed through the tool call dispatch chain.
#[derive(Clone)]
pub struct ToolCallContext {
    pub session_id: String,
    pub working_dir: Option<PathBuf>,
    pub tool_call_request_id: Option<String>,
    pub agent_plan_checkpoint: Option<AgentPlanCheckpointInput>,
    notification_emitter: Option<ToolCallNotificationEmitter>,
}

impl ToolCallContext {
    pub fn new(
        session_id: String,
        working_dir: Option<PathBuf>,
        tool_call_request_id: Option<String>,
    ) -> Self {
        Self {
            session_id,
            working_dir,
            tool_call_request_id,
            agent_plan_checkpoint: None,
            notification_emitter: None,
        }
    }

    pub(crate) fn with_agent_plan_checkpoint(
        mut self,
        checkpoint: AgentPlanCheckpointInput,
    ) -> Self {
        self.agent_plan_checkpoint = Some(checkpoint);
        self
    }

    pub fn working_dir_str(&self) -> Option<&str> {
        self.working_dir.as_ref().and_then(|p| p.to_str())
    }

    pub(crate) fn with_notification_emitter(
        mut self,
        notification_emitter: ToolCallNotificationEmitter,
    ) -> Self {
        self.notification_emitter = Some(notification_emitter);
        self
    }

    pub(crate) fn notification_emitter(&self) -> Option<&ToolCallNotificationEmitter> {
        self.notification_emitter.as_ref()
    }
}

/// Capture only the assistant content that is safe and necessary to commit the
/// live plan: user-visible text and the ordered tool-call identities. Provider
/// metadata, hidden reasoning, images, and tool metadata are intentionally
/// excluded.
pub(crate) fn capture_agent_plan_checkpoint(
    message: &Message,
    session_id: &str,
    tool_call_id: &str,
) -> Result<AgentPlanCheckpointInput, PolicyEnforcementError> {
    let visible = message.user_visible_content();
    let mut text = Vec::new();
    let mut tool_requests = Vec::new();
    let mut contains_target = false;

    for content in visible.content {
        match content {
            crate::conversation::message::MessageContent::Text(value) => text.push(value.text),
            crate::conversation::message::MessageContent::ToolRequest(request) => {
                let call = request
                    .tool_call
                    .map_err(|_| PolicyEnforcementError::InvalidAgentPlanCheckpoint)?;
                let arguments = call
                    .arguments
                    .map(serde_json::Value::Object)
                    .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));
                let argument_bytes = canonical_json_bytes(&arguments)?;
                let arguments_sha256 = sha256_digest(&argument_bytes);
                contains_target |= request.id == tool_call_id;
                tool_requests.push(serde_json::json!({
                    "id": request.id,
                    "name": call.name,
                    "arguments_sha256": arguments_sha256,
                }));
            }
            _ => {}
        }
    }

    if !contains_target {
        return Err(PolicyEnforcementError::InvalidAgentPlanCheckpoint);
    }

    AgentPlanCheckpointInput::new(
        session_id.to_owned(),
        tool_call_id.to_owned(),
        serde_json::json!({
            "text": text,
            "tool_requests": tool_requests,
        }),
        chrono::Utc::now().timestamp(),
    )
}

// ToolCallResult combines the result of a tool call with an optional notification stream that
// can be used to receive notifications from the tool.
pub struct ToolCallResult {
    pub result: Box<dyn Future<Output = ToolResult<rmcp::model::CallToolResult>> + Send + Unpin>,
    pub notification_stream: Option<Box<dyn Stream<Item = ServerNotification> + Send + Unpin>>,
    pub action_required_stream: Option<Box<dyn Stream<Item = Message> + Send + Unpin>>,
}

impl From<ToolResult<rmcp::model::CallToolResult>> for ToolCallResult {
    fn from(result: ToolResult<rmcp::model::CallToolResult>) -> Self {
        Self {
            result: Box::new(futures::future::ready(result)),
            notification_stream: None,
            action_required_stream: None,
        }
    }
}

use crate::agents::Agent;
use crate::conversation::message::ToolRequest;
use crate::session::Session;
use crate::tool_inspection::get_security_finding_id_from_results;

pub(super) enum ToolStreamItem<T> {
    ActionRequired(Message),
    Message(ServerNotification),
    Result(T),
}

pub(super) type ToolStream =
    Pin<Box<dyn Stream<Item = ToolStreamItem<ToolResult<CallToolResult>>> + Send>>;

pub(super) fn tool_stream<S, A, F>(rx: S, action_required_rx: A, done: F) -> ToolStream
where
    S: Stream<Item = ServerNotification> + Send + Unpin + 'static,
    A: Stream<Item = Message> + Send + Unpin + 'static,
    F: Future<Output = ToolResult<CallToolResult>> + Send + 'static,
{
    Box::pin(async_stream::stream! {
        tokio::pin!(done);
        let mut rx = rx;
        let mut action_required_rx = action_required_rx;

        loop {
            tokio::select! {
                Some(msg) = action_required_rx.next() => {
                    yield ToolStreamItem::ActionRequired(msg);
                }
                Some(msg) = rx.next() => {
                    yield ToolStreamItem::Message(msg);
                }
                r = &mut done => {
                    yield ToolStreamItem::Result(r);
                    break;
                }
            }
        }
    })
}

pub const DECLINED_RESPONSE: &str = "The user has declined to run this tool. \
    DO NOT attempt to call this tool again. \
    If there are no alternative methods to proceed, clearly explain the situation and STOP.";

pub const CHAT_MODE_TOOL_SKIPPED_RESPONSE: &str = "Let the user know the tool call was skipped in goose chat mode. \
                                        DO NOT apologize for skipping the tool call. DO NOT say sorry. \
                                        Provide an explanation of what the tool call would do, structured as a \
                                        plan for the user. Again, DO NOT apologize. \
                                        **Example Plan:**\n \
                                        1. **Identify Task Scope** - Determine the purpose and expected outcome.\n \
                                        2. **Outline Steps** - Break down the steps.\n \
                                        If needed, adjust the explanation based on user preferences or questions.";

impl Agent {
    pub(super) fn handle_approval_tool_requests<'a>(
        &'a self,
        tool_requests: &'a [ToolRequest],
        tool_futures: &'a mut Vec<(String, ToolStream)>,
        request_to_response_map: &'a mut HashMap<String, Message>,
        cancellation_token: Option<CancellationToken>,
        session: &'a Session,
        inspection_results: &'a [crate::tool_inspection::InspectionResult],
        assistant_message: &'a Message,
    ) -> BoxStream<'a, anyhow::Result<Message>> {
        try_stream! {
        for request in tool_requests.iter() {
            if let Ok(tool_call) = request.tool_call.clone() {
                let security_message = inspection_results.iter()
                    .find(|result| result.tool_request_id == request.id)
                    .and_then(|result| {
                        if let crate::tool_inspection::InspectionAction::RequireApproval(Some(message)) = &result.action {
                            Some(message.clone())
                        } else {
                            None
                        }
                    });

                let confirmation_rx = self.tool_confirmation_router.register(request.id.clone()).await;

                let action_required_msg = Message::assistant()
                    .with_action_required(
                        request.id.clone(),
                        tool_call.name.to_string().clone(),
                        tool_call.arguments.clone().unwrap_or_default(),
                        security_message,
                    )
                    .user_only();
                yield action_required_msg;

                let confirmation = confirmation_rx.await
                    .map_err(|_| anyhow::anyhow!("Confirmation channel closed for request {}", request.id))?;

                if let Some(finding_id) = get_security_finding_id_from_results(&request.id, inspection_results) {
                    let action = match confirmation.permission {
                        Permission::AllowOnce | Permission::AlwaysAllow => "ALLOW",
                        _ => "BLOCK",
                    };
                    tracing::info!(
                        monotonic_counter.goose.prompt_injection_user_decisions = 1,
                        security.event_type = "user_decision",
                        security.action = action,
                        security.finding_id = %finding_id,
                        tool.request_id = %request.id,
                        user.decision = ?confirmation.permission,
                        "security finding: user decision"
                    );
                }

                if confirmation.permission == Permission::AllowOnce || confirmation.permission == Permission::AlwaysAllow {
                    let plan_checkpoint = capture_agent_plan_checkpoint(
                        assistant_message,
                        &session.id,
                        &request.id,
                    )?;
                    let (req_id, tool_result) = self.dispatch_tool_call(
                        tool_call.clone(),
                        request.id.clone(),
                        cancellation_token.clone(),
                        session,
                        Some(plan_checkpoint),
                    ).await;

                    tool_futures.push((req_id, match tool_result {
                        Ok(result) => tool_stream(
                            result.notification_stream.unwrap_or_else(|| Box::new(stream::empty())),
                            result.action_required_stream.unwrap_or_else(|| Box::new(stream::empty())),
                            result.result,
                        ),
                        Err(e) => tool_stream(
                            Box::new(stream::empty()),
                            Box::new(stream::empty()),
                            futures::future::ready(Err(e)),
                        ),
                    }));

                    if confirmation.permission == Permission::AlwaysAllow {
                        self.tool_inspection_manager
                            .update_permission_manager(&tool_call.name, PermissionLevel::AlwaysAllow)
                            .await;
                    }
                } else {
                    if let Some(response) = request_to_response_map.get_mut(&request.id) {
                        response.add_tool_response_with_metadata(
                            request.id.clone(),
                            Ok(CallToolResult::error(vec![ContentBlock::text(DECLINED_RESPONSE)])),
                            request.metadata.as_ref(),
                        );
                    }

                    if confirmation.permission == Permission::AlwaysDeny {
                        self.tool_inspection_manager
                            .update_permission_manager(&tool_call.name, PermissionLevel::NeverAllow)
                            .await;
                    }
                }
            }
        }
    }.boxed()
    }

    pub(crate) fn handle_frontend_tool_request<'a>(
        &'a self,
        tool_request: &'a ToolRequest,
        message_tool_response: &'a mut Message,
    ) -> BoxStream<'a, anyhow::Result<Message>> {
        try_stream! {
                if let Ok(tool_call) = tool_request.tool_call.clone() {
                    if self.is_frontend_tool(&tool_call.name).await {
                        yield Message::assistant().with_frontend_tool_request(
                            tool_request.id.clone(),
                            Ok(tool_call.clone())
                        );

                        if let Some((id, result)) = self.tool_result_rx.lock().await.recv().await {
                            message_tool_response.add_tool_response_with_metadata(
                                id,
                                result,
                                tool_request.metadata.as_ref(),
                            );
                        }
                    }
            }
        }
        .boxed()
    }
}

#[cfg(test)]
mod agent_plan_tests {
    use super::*;
    use rmcp::model::CallToolRequestParams;
    use rmcp::object;

    #[test]
    fn plan_checkpoint_keeps_visible_text_and_ordered_call_hashes_only() {
        let mut message = Message::assistant()
            .with_text("I will inspect, then update.")
            .with_tool_request(
                "call-a",
                Ok(CallToolRequestParams::new("developer__read")
                    .with_arguments(object!({"path": "a.txt"}))),
            )
            .with_tool_request(
                "call-b",
                Ok(CallToolRequestParams::new("developer__write")
                    .with_arguments(object!({"content": "safe", "path": "b.txt"}))),
            );
        if let Some(crate::conversation::message::MessageContent::ToolRequest(request)) =
            message.content.get_mut(1)
        {
            request.tool_meta = Some(serde_json::json!({"secret": "must-not-leak"}));
        }

        let checkpoint = capture_agent_plan_checkpoint(&message, "session", "call-b").unwrap();
        assert_eq!(
            checkpoint.material["text"],
            serde_json::json!(["I will inspect, then update."])
        );
        assert_eq!(checkpoint.material["tool_requests"][0]["id"], "call-a");
        assert_eq!(checkpoint.material["tool_requests"][1]["id"], "call-b");
        assert!(!checkpoint.material.to_string().contains("must-not-leak"));
    }

    #[test]
    fn plan_checkpoint_rejects_a_tool_id_from_another_message() {
        let message = Message::assistant()
            .with_tool_request("call-a", Ok(CallToolRequestParams::new("developer__read")));
        assert_eq!(
            capture_agent_plan_checkpoint(&message, "session", "call-b").unwrap_err(),
            PolicyEnforcementError::InvalidAgentPlanCheckpoint
        );
    }
}
