//! Applies recipe commands and enforces their structured final output.

use std::collections::HashSet;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use rmcp::model::{CallToolResult, ContentBlock, ErrorData, Tool};
use tracing_futures::Instrument;

use crate::agents::final_output_tool::{
    FinalOutputTool, FINAL_OUTPUT_CONTINUATION_MESSAGE, FINAL_OUTPUT_TOOL_NAME,
};
use crate::agents::state_machine::ops_toolcalling::{
    pending_tool_requests, tool_span, ToolDisposition,
};
use crate::agents::state_machine::{
    applied, ends_turn, last_effective_role, messages_since_kickoff, not_applicable, yielded_with,
    ConversationEffect, Emitter, GooseEffect, Operation, OperationResult, SlashCommand,
};
use crate::conversation::message::{Message, MessageContent};
use crate::conversation::{Conversation, EffectiveRole};
use crate::session::Session;

const RECIPE_LOAD_FAILURE_MESSAGE: &str =
    "AccordLock could not load that recipe. Check the recipe name or file and try again.";
const RECIPE_VALIDATION_FAILURE_MESSAGE: &str =
    "This recipe is invalid and cannot be started. Review its response schema and try again.";
const FINAL_OUTPUT_FAILURE_MESSAGE: &str = "The final result did not match the recipe response schema. Return a valid result and try again.";

fn sanitize_final_output_result(
    output: std::result::Result<CallToolResult, ErrorData>,
) -> std::result::Result<CallToolResult, ErrorData> {
    match output {
        Ok(result) if result.is_error == Some(true) => {
            tracing::warn!(tool_result = ?result, "Final output validation failed");
            Ok(CallToolResult::error(vec![ContentBlock::text(
                FINAL_OUTPUT_FAILURE_MESSAGE,
            )]))
        }
        Err(error) => {
            tracing::warn!(error = ?error, "Final output validation failed");
            Err(ErrorData::new(
                error.code,
                FINAL_OUTPUT_FAILURE_MESSAGE,
                None,
            ))
        }
        output => output,
    }
}

pub struct RecipeOperation;

impl RecipeOperation {
    fn final_output(session: &Session) -> Result<Option<FinalOutputTool>> {
        session
            .recipe
            .as_ref()
            .and_then(|recipe| recipe.response.clone())
            .map(FinalOutputTool::try_new)
            .transpose()
            .map_err(|error| anyhow!(error))
    }

    fn successful_final_output(messages: &[Message]) -> Option<String> {
        let successful_responses: HashSet<&str> = messages
            .iter()
            .flat_map(|message| &message.content)
            .filter_map(|content| match content {
                MessageContent::ToolResponse(response)
                    if response
                        .tool_result
                        .as_ref()
                        .is_ok_and(|result| result.is_error != Some(true)) =>
                {
                    Some(response.id.as_str())
                }
                _ => None,
            })
            .collect();

        messages
            .iter()
            .rev()
            .flat_map(|message| message.content.iter().rev())
            .find_map(|content| match content {
                MessageContent::ToolRequest(request)
                    if successful_responses.contains(request.id.as_str()) =>
                {
                    request.tool_call.as_ref().ok().and_then(|tool_call| {
                        (tool_call.name == FINAL_OUTPUT_TOOL_NAME).then(|| {
                            serde_json::Value::Object(
                                tool_call.arguments.clone().unwrap_or_default(),
                            )
                            .to_string()
                        })
                    })
                }
                _ => None,
            })
    }

    async fn command_error(
        &self,
        conversation: &Conversation,
        message: &'static str,
        emit: &Emitter,
    ) -> Result<OperationResult<GooseEffect>> {
        let command = messages_since_kickoff(conversation)?
            .first()
            .cloned()
            .ok_or_else(|| anyhow!("recipe command conversation has no kickoff message"))?;
        let message_id = command
            .id
            .clone()
            .ok_or_else(|| anyhow!("Persisted slash command message has no id"))?;
        let command = command.with_visibility(true, false);
        let response = Message::assistant()
            .with_text(message)
            .with_visibility(true, false);
        emit.message(command).await;
        let response = emit.message(response).await;
        yielded_with([
            ConversationEffect::SetMessageVisibility {
                message_id,
                user_visible: true,
                agent_visible: false,
            }
            .into(),
            response.into(),
        ])
    }
}

#[async_trait]
impl Operation<Session, GooseEffect> for RecipeOperation {
    fn name(&self) -> &'static str {
        "recipe"
    }

    async fn run_command(
        &self,
        command: &SlashCommand<'_>,
        _session: &Session,
        conversation: &Conversation,
        emit: &Emitter,
    ) -> Result<OperationResult<GooseEffect>> {
        let (recipe, prompt) = match crate::slash_commands::recipe_slash_command::resolve_command(
            command.command,
            command.params_str,
        ) {
            Ok(Some(recipe)) => recipe,
            Ok(None) => return not_applicable(),
            Err(error) => {
                tracing::warn!(error = %error, "Recipe command could not be resolved");
                return self
                    .command_error(conversation, RECIPE_LOAD_FAILURE_MESSAGE, emit)
                    .await;
            }
        };

        if let Some(response) = recipe.response.clone() {
            if let Err(error) = FinalOutputTool::try_new(response) {
                tracing::warn!(error = %error, "Recipe response schema is invalid");
                return self
                    .command_error(conversation, RECIPE_VALIDATION_FAILURE_MESSAGE, emit)
                    .await;
            }
        }

        #[cfg(feature = "telemetry")]
        crate::posthog::emit_custom_slash_command_used();

        let command_message = messages_since_kickoff(conversation)?
            .first()
            .ok_or_else(|| anyhow!("recipe command conversation has no kickoff message"))?;
        let message_id = command_message
            .id
            .clone()
            .ok_or_else(|| anyhow!("Persisted slash command message has no id"))?;
        applied([
            ConversationEffect::SetMessageVisibility {
                message_id,
                user_visible: true,
                agent_visible: false,
            }
            .into(),
            GooseEffect::SetRecipe(Box::new(Some(recipe))),
            Message::user()
                .with_text(prompt)
                .with_visibility(false, true)
                .into(),
        ])
    }

    async fn inference_tools(&self, session: &Session) -> Result<Vec<Tool>> {
        Ok(Self::final_output(session)?
            .as_ref()
            .map(FinalOutputTool::tool)
            .into_iter()
            .collect())
    }

    async fn prompt_parts(
        &self,
        session: &Session,
        _conversation: &Conversation,
    ) -> Result<Vec<(String, String)>> {
        Ok(Self::final_output(session)?
            .as_ref()
            .map(|tool| ("final_output".to_string(), tool.system_prompt()))
            .into_iter()
            .collect())
    }

    async fn run(
        &self,
        session: &Session,
        conversation: &Conversation,
        emit: &Emitter,
    ) -> Result<OperationResult<GooseEffect>> {
        let Some(mut final_output) = Self::final_output(session)? else {
            return not_applicable();
        };

        let messages = messages_since_kickoff(conversation)?;
        let pending = pending_tool_requests(messages)
            .into_iter()
            .find(|(request, disposition)| {
                *disposition == ToolDisposition::Execute
                    && request
                        .tool_call
                        .as_ref()
                        .is_ok_and(|tool_call| tool_call.name == FINAL_OUTPUT_TOOL_NAME)
            });
        if let Some((request, _)) = pending {
            let tool_call = request
                .tool_call
                .map_err(|error| anyhow!("final output tool call could not be parsed: {error}"))?;
            let span = tool_span(&tool_call.name, &request.id, &session.id);
            let result = final_output
                .execute_tool_call(tool_call)
                .instrument(span.clone())
                .await;
            let output = sanitize_final_output_result(result.result.instrument(span.clone()).await);
            match &output {
                Ok(result) if result.is_error == Some(true) => {
                    span.record("error.type", "tool_error");
                }
                Err(_) => {
                    span.record("error.type", "tool_execution_error");
                }
                _ => {}
            }
            let mut response = Message::user();
            response.add_tool_response_with_metadata(request.id, output, request.metadata.as_ref());
            let response = emit.message(response).await;
            return applied([response.into()]);
        }

        if let Some(output) = Self::successful_final_output(messages) {
            if last_effective_role(messages)? == EffectiveRole::Tool {
                let message = Message::assistant().with_text(output);
                let message = emit.message(message).await;
                return applied([message.into()]);
            }
            return not_applicable();
        }

        if ends_turn(messages) {
            let message = Message::user().with_text(FINAL_OUTPUT_CONTINUATION_MESSAGE);
            let message = emit.message(message).await;
            return applied([message.into()]);
        }

        not_applicable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::ErrorCode;

    #[test]
    fn final_output_error_does_not_reflect_payload_or_provider_details() {
        let private_detail = "https://provider.invalid/private C:\\Users\\private payload=secret";
        let sanitized = sanitize_final_output_result(Err(ErrorData::new(
            ErrorCode::INVALID_PARAMS,
            private_detail,
            Some(serde_json::json!({ "payload": private_detail })),
        )))
        .expect_err("validation failure should remain an error");

        assert_eq!(sanitized.code, ErrorCode::INVALID_PARAMS);
        assert_eq!(sanitized.message, FINAL_OUTPUT_FAILURE_MESSAGE);
        assert!(sanitized.data.is_none());
    }
}
