// Modified by AccordLock contributors; see UPSTREAM.md.
import { useState, useEffect } from 'react';
import { Button } from './ui/button';
import type { Permission } from '../types/permissions';
import { resolveAcpPermissionRequest } from '../acp/permissionRequests';
import { defineMessages, useIntl } from '../i18n';

const i18n = defineMessages({
  allowOnce: {
    id: 'toolApprovalButtons.allowOnce',
    defaultMessage: 'Approve once',
  },
  deny: {
    id: 'toolApprovalButtons.deny',
    defaultMessage: 'Don’t allow',
  },
  allowedOnce: {
    id: 'toolApprovalButtons.allowedOnce',
    defaultMessage: 'Approved once',
  },
  alwaysAllowed: {
    id: 'toolApprovalButtons.alwaysAllowed',
    defaultMessage: 'Allowed for future requests',
  },
  denied: {
    id: 'toolApprovalButtons.denied',
    defaultMessage: 'Denied',
  },
  deniedOnce: {
    id: 'toolApprovalButtons.deniedOnce',
    defaultMessage: 'Not allowed',
  },
  cancelled: {
    id: 'toolApprovalButtons.cancelled',
    defaultMessage: 'Cancelled',
  },
  staleApprovalRequest: {
    id: 'toolApprovalButtons.staleApprovalRequest',
    defaultMessage: 'This approval request is no longer active.',
  },
  protectedReviewUnavailable: {
    id: 'toolApprovalButtons.protectedReviewUnavailable',
    defaultMessage: 'The secure review couldn’t start. The action remains blocked.',
  },
});

const globalApprovalState = new Map<
  string,
  {
    decision: Permission | null;
    isClicked: boolean;
  }
>();

const ACCORDLOCK_PROTECTED_TOOLS = new Set([
  'developer__delete_file',
  'developer__edit',
  'developer__read',
  'developer__shell',
  'developer__tree',
  'developer__write',
]);

export function isAccordLockProtectedTool(toolName: string): boolean {
  return ACCORDLOCK_PROTECTED_TOOLS.has(toolName);
}

export interface ToolApprovalData {
  id: string;
  toolName: string;
  prompt?: string;
  sessionId: string;
  isClicked?: boolean;
}

export default function ToolApprovalButtons({ data }: { data: ToolApprovalData }) {
  const intl = useIntl();
  const { id, toolName, sessionId, isClicked: initialIsClicked } = data;

  const storedState = globalApprovalState.get(id);
  const [decision, setDecision] = useState<Permission | null>(storedState?.decision ?? null);
  const [isClicked, setIsClicked] = useState(storedState?.isClicked ?? initialIsClicked ?? false);
  const [approvalError, setApprovalError] = useState<string | null>(null);
  const protectedByAccordLock = isAccordLockProtectedTool(toolName);

  const setResolvedDecision = (action: Permission) => {
    setDecision(action);
    setIsClicked(true);
    setApprovalError(null);
  };

  useEffect(() => {
    const currentState = globalApprovalState.get(id);
    if (currentState) {
      setDecision(currentState.decision);
      setIsClicked(currentState.isClicked);
    }
    setApprovalError(null);
  }, [id]);

  useEffect(() => {
    globalApprovalState.set(id, { decision, isClicked });
  }, [id, decision, isClicked]);

  useEffect(() => {
    if (!protectedByAccordLock || isClicked) return;
    try {
      if (resolveAcpPermissionRequest(sessionId, id, 'allow_once')) {
        setDecision('allow_once');
        setIsClicked(true);
        setApprovalError(null);
      } else {
        setApprovalError(intl.formatMessage(i18n.staleApprovalRequest));
      }
    } catch (err) {
      console.error('Error forwarding protected action to AccordLock:', err);
      setApprovalError(intl.formatMessage(i18n.staleApprovalRequest));
    }
  }, [id, intl, isClicked, protectedByAccordLock, sessionId]);

  const handleAction = async (action: Permission) => {
    try {
      if (resolveAcpPermissionRequest(sessionId, id, action)) {
        setResolvedDecision(action);
      } else {
        setApprovalError(intl.formatMessage(i18n.staleApprovalRequest));
      }
    } catch (err) {
      console.error('Error confirming tool action:', err);
    }
  };

  // This ACP layer only forwards protected requests into AccordLock. Positive
  // authority still requires the isolated native exact-action confirmation.
  if (protectedByAccordLock) {
    return approvalError ? (
      <p className="mt-2 text-sm text-text-danger" role="alert">
        {intl.formatMessage(i18n.protectedReviewUnavailable)}
      </p>
    ) : null;
  }

  if (isClicked && decision) {
    const statusMessages: Record<Permission, string> = {
      allow_once: intl.formatMessage(i18n.allowedOnce),
      always_allow: intl.formatMessage(i18n.alwaysAllowed),
      always_deny: intl.formatMessage(i18n.denied),
      deny_once: intl.formatMessage(i18n.deniedOnce),
      cancel: intl.formatMessage(i18n.cancelled),
    };
    return (
      <p className="text-sm text-muted-foreground mt-2">
        {toolName} - {statusMessages[decision]}
      </p>
    );
  }

  return (
    <>
      <div className="flex items-center gap-2 mt-2">
        <Button
          className="rounded-full"
          variant="secondary"
          onClick={() => handleAction('allow_once')}
        >
          {intl.formatMessage(i18n.allowOnce)}
        </Button>
        <Button
          className="rounded-full"
          variant="outline"
          onClick={() => handleAction('deny_once')}
        >
          {intl.formatMessage(i18n.deny)}
        </Button>
      </div>
      {approvalError && (
        <p className="text-sm text-red-500 mt-2" role="alert">
          {approvalError}
        </p>
      )}
    </>
  );
}
