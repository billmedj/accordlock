import type { ActionRequired } from '../types/message';
import { defineMessages, useIntl } from '../i18n';
import { snakeToTitleCase } from '../utils';
import ToolApprovalButtons, { isAccordLockProtectedTool } from './ToolApprovalButtons';

const i18n = defineMessages({
  approvalRequiredWithName: {
    id: 'toolConfirmation.allowToolCallWithName',
    defaultMessage: 'Allow {toolName}?',
  },
  approvalExplanationWithName: {
    id: 'toolConfirmation.technicalPermissionWithName',
    defaultMessage: 'Review this request before it continues.',
  },
});

function formatToolName(fullName: string): string {
  const delimiterIndex = fullName.lastIndexOf('__');
  const shortName = delimiterIndex === -1 ? fullName : fullName.substring(delimiterIndex + 2);
  return snakeToTitleCase(shortName);
}

type ToolConfirmationData = Extract<ActionRequired['data'], { actionType: 'toolConfirmation' }>;

interface ToolConfirmationProps {
  sessionId: string;
  isClicked: boolean;
  actionRequiredContent: ActionRequired & { type: 'actionRequired' };
}

export default function ToolConfirmation({
  sessionId,
  isClicked,
  actionRequiredContent,
}: ToolConfirmationProps) {
  const intl = useIntl();
  const data = actionRequiredContent.data as ToolConfirmationData;
  const { id, toolName, prompt } = data;
  const displayName = formatToolName(toolName);

  if (isAccordLockProtectedTool(toolName)) {
    return (
      <ToolApprovalButtons
        data={{ id, toolName, prompt: prompt ?? undefined, sessionId, isClicked }}
      />
    );
  }

  return (
    <div className="goose-message-content bg-background-primary border border-border-primary rounded-2xl overflow-hidden">
      <div className="bg-background-secondary px-4 py-3 text-text-primary">
        <p className="text-sm font-medium">
          {intl.formatMessage(i18n.approvalRequiredWithName, { toolName: displayName })}
        </p>
        <p className="mt-1 text-xs leading-5 text-text-secondary">
          {intl.formatMessage(i18n.approvalExplanationWithName, {
            toolName: displayName,
          })}
        </p>
      </div>
      <ToolApprovalButtons
        data={{ id, toolName, prompt: prompt ?? undefined, sessionId, isClicked }}
      />
    </div>
  );
}
