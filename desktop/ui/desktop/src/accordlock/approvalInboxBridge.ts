import type Electron from 'electron';
import type { ApprovalCenterDecision } from './approvalInbox';
import {
  ACCORDLOCK_APPROVAL_INBOX_EVENT,
  type AccordLockApprovalInboxBridge,
} from './approvalInboxIpc';

export function createAccordLockApprovalInboxBridge(): AccordLockApprovalInboxBridge {
  return {
    getPendingApprovals: () => window.electron.getPendingAccordLockActionApprovals(),
    submitDecision: (decision: ApprovalCenterDecision) =>
      window.electron.submitAccordLockApprovalCenterDecision(decision),
    subscribe: (listener) => {
      const handler = (_event: Electron.IpcRendererEvent, value: unknown) => listener(value);
      window.electron.on(ACCORDLOCK_APPROVAL_INBOX_EVENT, handler);
      return () => window.electron.off(ACCORDLOCK_APPROVAL_INBOX_EVENT, handler);
    },
    reportProtocolError: (message) =>
      window.electron.logInfo(`[ACCORDLOCK APPROVAL INBOX] ${message}`),
  };
}
