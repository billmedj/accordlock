import { act, render, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ApprovalInboxItem } from '../../accordlock/approvalInbox';
import type { AccordLockApprovalInboxBridge } from '../../accordlock/approvalInboxIpc';
import { ApprovalInboxStore } from '../../accordlock/approvalInboxStore';
import type { LocalApprovalNotificationAdapter } from '../../accordlock/approvalNotifications';
import { ApprovalInboxController, shouldShowLocalNotification } from './ApprovalInboxController';

const digest = (character: string) => `sha256:${character.repeat(64)}`;
const item: ApprovalInboxItem = {
  id: `action:${digest('a')}`,
  status: 'PENDING',
  canAllowOnce: true,
  contentEvidence: `Content ${digest('b')}`,
  objective: 'Prepare the release note.',
  operationLabel: 'Edit file',
  preview: 'New',
  receivedAt: 1_000,
  target: 'docs/release.md',
  targetLabel: 'Path',
  workspaceRoot: 'C:\\Work\\product',
  binding: {
    authorizationDigest: digest('c'),
    approvalRequestHash: digest('a'),
    prestateHash: digest('d'),
    proposalDigest: digest('e'),
    requestExpiresAt: 2_000_000_000,
    runId: 'run-1',
    sessionId: 'session-1',
    taskAccessExpiresAt: 2_000_000_100,
    taskId: 'task-1',
    taskPolicyHash: digest('f'),
    toolCallId: 'tool-call-1',
  },
};

afterEach(() => vi.restoreAllMocks());

describe('ApprovalInboxController', () => {
  it('hydrates, subscribes, validates, and notifies once per pending exact action', async () => {
    const store = new ApprovalInboxStore();
    let listener: ((value: unknown) => void) | undefined;
    const reportProtocolError = vi.fn();
    const bridge: AccordLockApprovalInboxBridge = {
      getPendingApprovals: vi.fn().mockResolvedValue([item]),
      submitDecision: vi.fn(),
      subscribe: vi.fn((next) => {
        listener = next;
        return vi.fn();
      }),
      reportProtocolError,
    };
    const notify = vi.fn().mockReturnValue(true);
    const notificationAdapter = {
      capabilities: {
        click: 'OPEN_APPROVAL',
        decision: 'IN_APP_ONLY',
        delivery: 'DISPLAY_ONLY',
      },
      notify,
    } as const satisfies LocalApprovalNotificationAdapter;
    const notificationPolicy = { shouldNotify: vi.fn().mockResolvedValue(true) };
    const notificationLifecycle = { dismiss: vi.fn() };

    render(
      <ApprovalInboxController
        bridge={bridge}
        store={store}
        notificationAdapter={notificationAdapter}
        notificationLifecycle={notificationLifecycle}
        notificationPolicy={notificationPolicy}
      />
    );

    await waitFor(() => expect(store.getSnapshot()).toHaveLength(1));
    await waitFor(() => expect(notify).toHaveBeenCalledTimes(1));

    act(() => listener?.(item));
    expect(notify).toHaveBeenCalledTimes(1);

    act(() => listener?.({ ...item, id: 'forged' }));
    expect(reportProtocolError).toHaveBeenCalledWith(
      'Rejected malformed approval inbox projection'
    );
    expect(store.getSnapshot()).toHaveLength(1);
  });

  it('does not notify while notifications are disabled or any app window is focused', () => {
    expect(shouldShowLocalNotification(false, false)).toBe(false);
    expect(shouldShowLocalNotification(true, true)).toBe(false);
    expect(shouldShowLocalNotification(true, false)).toBe(true);
  });

  it('keeps a pending request in the inbox when local notification policy declines delivery', async () => {
    const store = new ApprovalInboxStore();
    const notify = vi.fn();
    const notificationPolicy = { shouldNotify: vi.fn().mockResolvedValue(false) };
    const bridge: AccordLockApprovalInboxBridge = {
      getPendingApprovals: vi.fn().mockResolvedValue([item]),
      submitDecision: vi.fn(),
      subscribe: vi.fn(() => vi.fn()),
      reportProtocolError: vi.fn(),
    };

    render(
      <ApprovalInboxController
        bridge={bridge}
        store={store}
        notificationAdapter={{
          capabilities: {
            click: 'OPEN_APPROVAL',
            decision: 'IN_APP_ONLY',
            delivery: 'DISPLAY_ONLY',
          },
          notify,
        }}
        notificationLifecycle={{ dismiss: vi.fn() }}
        notificationPolicy={notificationPolicy}
      />
    );

    await waitFor(() => expect(notificationPolicy.shouldNotify).toHaveBeenCalledOnce());
    expect(store.getSnapshot()).toHaveLength(1);
    expect(notify).not.toHaveBeenCalled();
  });

  it('dismisses the exact native notification when the authority reports a final status', async () => {
    const store = new ApprovalInboxStore();
    let listener: ((value: unknown) => void) | undefined;
    const dismiss = vi.fn();
    const bridge: AccordLockApprovalInboxBridge = {
      getPendingApprovals: vi.fn().mockResolvedValue([item]),
      submitDecision: vi.fn(),
      subscribe: vi.fn((next) => {
        listener = next;
        return vi.fn();
      }),
      reportProtocolError: vi.fn(),
    };

    render(
      <ApprovalInboxController
        bridge={bridge}
        store={store}
        notificationAdapter={{
          capabilities: {
            click: 'OPEN_APPROVAL',
            decision: 'IN_APP_ONLY',
            delivery: 'DISPLAY_ONLY',
          },
          notify: vi.fn(),
        }}
        notificationLifecycle={{ dismiss }}
        notificationPolicy={{ shouldNotify: vi.fn().mockResolvedValue(false) }}
      />
    );

    await waitFor(() => expect(store.getSnapshot()).toHaveLength(1));
    act(() => listener?.({ ...item, status: 'DENIED' }));
    expect(dismiss).toHaveBeenCalledWith(item.id);
  });

  it('reports capacity exhaustion distinctly while the new action remains blocked', async () => {
    const store = new ApprovalInboxStore();
    for (let index = 0; index < 128; index += 1) {
      const approvalRequestHash = `sha256:${index.toString(16).padStart(64, '0')}`;
      store.upsert({
        ...item,
        id: `action:${approvalRequestHash}`,
        binding: { ...item.binding, approvalRequestHash },
      });
    }
    const reportProtocolError = vi.fn();
    const bridge: AccordLockApprovalInboxBridge = {
      getPendingApprovals: vi.fn().mockResolvedValue([item]),
      submitDecision: vi.fn(),
      subscribe: vi.fn(() => vi.fn()),
      reportProtocolError,
    };

    render(
      <ApprovalInboxController
        bridge={bridge}
        store={store}
        notificationAdapter={{
          capabilities: {
            click: 'OPEN_APPROVAL',
            decision: 'IN_APP_ONLY',
            delivery: 'DISPLAY_ONLY',
          },
          notify: vi.fn(),
        }}
        notificationLifecycle={{ dismiss: vi.fn() }}
        notificationPolicy={{ shouldNotify: vi.fn().mockResolvedValue(true) }}
      />
    );

    await waitFor(() =>
      expect(reportProtocolError).toHaveBeenCalledWith(
        'Approval inbox capacity reached; the action remains blocked'
      )
    );
    expect(store.getSnapshot()).toHaveLength(128);
  });
});
