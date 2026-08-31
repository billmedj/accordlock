import { describe, expect, it, vi } from 'vitest';
import type { ApprovalInboxItem } from './approvalInbox';
import {
  approvalNotificationForItem,
  createLocalApprovalNotificationAdapter,
} from './approvalNotifications';

const item: ApprovalInboxItem = {
  id: `action:sha256:${'a'.repeat(64)}`,
  status: 'PENDING',
  canAllowOnce: true,
  contentEvidence: 'Sensitive content hash',
  objective: 'Secret acquisition plan',
  operationLabel: 'Run program',
  preview: 'secret --token value',
  receivedAt: 1_000,
  target: 'C:\\Sensitive',
  targetLabel: 'Working directory',
  workspaceRoot: 'C:\\Sensitive',
  binding: {
    authorizationDigest: `sha256:${'b'.repeat(64)}`,
    approvalRequestHash: `sha256:${'a'.repeat(64)}`,
    prestateHash: `sha256:${'c'.repeat(64)}`,
    proposalDigest: `sha256:${'d'.repeat(64)}`,
    requestExpiresAt: 1_100,
    runId: 'run-1',
    sessionId: 'session-1',
    taskAccessExpiresAt: 2_000,
    taskId: 'task-1',
    taskPolicyHash: `sha256:${'e'.repeat(64)}`,
    toolCallId: 'tool-call-1',
  },
};

describe('local approval notifications', () => {
  it('reuses the existing decision-needed copy without leaking request details', () => {
    const notification = approvalNotificationForItem(item, 1_050);

    expect(notification).toEqual({
      kind: 'APPROVAL_REQUIRED',
      open: { kind: 'APPROVAL', approvalId: item.id },
    });
    expect(JSON.stringify(notification)).not.toContain('Secret');
    expect(JSON.stringify(notification)).not.toContain('token');
  });

  it('opens the exact in-app request and cannot expose a notification decision callback', () => {
    const showNotification = vi.fn();
    const adapter = createLocalApprovalNotificationAdapter({ showNotification });

    expect(adapter.capabilities).toEqual({
      click: 'OPEN_APPROVAL',
      decision: 'IN_APP_ONLY',
      delivery: 'DISPLAY_ONLY',
    });
    expect(adapter.notify(item, 1_050)).toBe(true);
    expect(showNotification).toHaveBeenCalledWith({
      kind: 'APPROVAL_REQUIRED',
      open: { kind: 'APPROVAL', approvalId: item.id },
    });
    expect(Object.keys(adapter)).toEqual(['capabilities', 'notify']);
  });

  it('does not notify for expired or resolved requests', () => {
    const showNotification = vi.fn();
    const adapter = createLocalApprovalNotificationAdapter({ showNotification });

    expect(adapter.notify(item, 1_100)).toBe(false);
    expect(adapter.notify({ ...item, status: 'DENIED' }, 1_050)).toBe(false);
    expect(showNotification).not.toHaveBeenCalled();
  });
});
