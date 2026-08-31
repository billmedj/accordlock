// Modified by AccordLock contributors; see UPSTREAM.md.
//! Runs session diagnostics and feeds repair context back into the turn.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use rmcp::model::Role;

use crate::agents::state_machine::{
    applied, messages_since_kickoff, not_applicable, yielded_with, ConversationEffect, Emitter,
    GooseEffect, Operation, OperationResult, SlashCommand,
};
use crate::conversation::message::Message;
use crate::conversation::Conversation;
use crate::session::Session;

const DOCTOR_FAILURE_MESSAGE: &str = "AccordLock could not complete diagnostics. Check your model connection in Settings, then try again.";

fn doctor_failure_message(error: &anyhow::Error) -> Message {
    tracing::error!(error = %error, "Doctor diagnostics failed");
    Message::assistant().with_text(DOCTOR_FAILURE_MESSAGE)
}

pub struct DoctorOperation;

#[async_trait]
impl Operation<Session, GooseEffect> for DoctorOperation {
    fn name(&self) -> &'static str {
        "doctor"
    }

    async fn run_command(
        &self,
        command: &SlashCommand<'_>,
        session: &Session,
        conversation: &Conversation,
        emit: &Emitter,
    ) -> Result<OperationResult<GooseEffect>> {
        if command.command != "doctor" {
            return not_applicable();
        }

        let command_message = messages_since_kickoff(conversation)?
            .first()
            .cloned()
            .ok_or_else(|| anyhow!("doctor command conversation has no kickoff message"))?;
        let message_id = command_message
            .id
            .clone()
            .ok_or_else(|| anyhow!("Persisted slash command message has no id"))?;
        // Doctor still needs the legacy Agent, so keep that lookup contained at this boundary.
        let agent = crate::execution::manager::AgentManager::instance()
            .await?
            .get_or_create_agent(session.id.clone())
            .await?;
        let result = match crate::doctor::run(&agent, &session.id).await {
            Ok(message) => message,
            Err(error) => doctor_failure_message(&error),
        };

        if result.role == Role::Assistant {
            let command_message = command_message.with_visibility(true, false);
            let result = result.with_visibility(true, false);
            emit.message(command_message).await;
            let result = emit.message(result).await;
            return yielded_with([
                ConversationEffect::SetMessageVisibility {
                    message_id,
                    user_visible: true,
                    agent_visible: false,
                }
                .into(),
                result.into(),
            ]);
        }

        applied([
            ConversationEffect::SetMessageVisibility {
                message_id,
                user_visible: true,
                agent_visible: false,
            }
            .into(),
            result.with_visibility(false, true).into(),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doctor_failure_does_not_reflect_internal_error_details() {
        let private_detail = "https://provider.invalid/private C:\\Users\\private payload=secret";
        let message = doctor_failure_message(&anyhow!(private_detail));

        assert_eq!(message.as_concat_text(), DOCTOR_FAILURE_MESSAGE);
        assert!(!message.as_concat_text().contains(private_detail));
    }
}
