import type { ApprovalCenterDecision } from './approvalInbox';

/**
 * Narrow transport for renderer-safe approval projections.
 * Channel possession conveys no authority; Electron main validates the sender,
 * exact binding, deadline, and active task before recording any decision.
 */
export const ACCORDLOCK_APPROVAL_INBOX_EVENT = 'accordlock:control:action-approval:inbox' as const;
export const ACCORDLOCK_APPROVAL_INBOX_GET_PENDING =
  'accordlock:control:action-approval:get-pending' as const;
export const ACCORDLOCK_APPROVAL_INBOX_DECIDE =
  'accordlock:control:action-approval:decide' as const;

export interface AccordLockApprovalInboxBridge {
  getPendingApprovals(): Promise<unknown>;
  submitDecision(decision: ApprovalCenterDecision): Promise<unknown>;
  subscribe(listener: (value: unknown) => void): () => void;
  reportProtocolError(message: string): void;
}
