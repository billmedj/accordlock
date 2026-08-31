import { describe, expect, it, vi } from 'vitest';
import type { ApprovalCenterDecision, ApprovalInboxItem } from '../../accordlock/approvalInbox';
import { ApprovalInboxStore } from '../../accordlock/approvalInboxStore';
import { executeApprovalCenterDecision } from './ApprovalCenterRoute';

const digest = (character: string) => `sha256:${character.repeat(64)}`;
const item: ApprovalInboxItem = {
  id: `action:${digest('a')}`,
  status: 'PENDING',
  canAllowOnce: true,
  contentEvidence: `Content ${digest('b')}`,
  objective: 'Prepare the release note.',
  operationLabel: 'Edit file',
  preview: 'Before\nOld\n\nAfter\nNew',
  receivedAt: 1_000,
  target: 'docs/release.md',
  targetLabel: 'Path',
  workspaceRoot: 'C:\\Work\\product',
  binding: {
    authorizationDigest: digest('c'),
    approvalRequestHash: digest('a'),
    prestateHash: digest('d'),
    proposalDigest: digest('e'),
    requestExpiresAt: 1_100,
    runId: 'run-1',
    sessionId: 'session-1',
    taskAccessExpiresAt: 2_000,
    taskId: 'task-1',
    taskPolicyHash: digest('f'),
    toolCallId: 'tool-call-1',
  },
};

function decision(intent: ApprovalCenterDecision['intent']): ApprovalCenterDecision {
  return { binding: item.binding, intent, issuedAt: 1_050, itemId: item.id };
}

function dependencies(acknowledgement: ApprovalCenterDecision) {
  const store = new ApprovalInboxStore();
  store.upsert(item);
  const order: string[] = [];
  return {
    order,
    store,
    bridge: {
      submitDecision: vi.fn(async () => {
        order.push('submit');
        return acknowledgement;
      }),
    },
    nowSeconds: vi.fn(() => 1_050),
    revokeTask: vi.fn(async () => {
      order.push('revoke');
    }),
    stopTask: vi.fn(() => order.push('stop')),
    lockTask: vi.fn(() => order.push('lock')),
  };
}

describe('executeApprovalCenterDecision', () => {
  it('stops the model before the trusted Stop task decision and locks after acknowledgement', async () => {
    const requested = decision('STOP_TASK');
    const deps = dependencies(requested);

    await executeApprovalCenterDecision(requested, deps);

    expect(deps.order).toEqual(['stop', 'submit', 'lock']);
    expect(deps.store.getSnapshot()[0].status).toBe('TASK_STOPPED');
  });

  it('revokes access without stopping the model', async () => {
    const requested = decision('REVOKE_ACCESS');
    const deps = dependencies(requested);

    await executeApprovalCenterDecision(requested, deps);

    expect(deps.stopTask).not.toHaveBeenCalled();
    expect(deps.lockTask).toHaveBeenCalledWith('session-1');
    expect(deps.store.getSnapshot()[0].status).toBe('ACCESS_REVOKED');
  });

  it('records a native denial when Allow once is not confirmed', async () => {
    const requested = decision('ALLOW_ONCE');
    const deps = dependencies(decision('DENY_ACTION'));

    const acknowledgement = await executeApprovalCenterDecision(requested, deps);

    expect(acknowledgement.intent).toBe('DENY_ACTION');
    expect(deps.store.getSnapshot()[0].status).toBe('DENIED');
    expect(deps.lockTask).not.toHaveBeenCalled();
  });

  it('rejects an acknowledgement for another exact action', async () => {
    const requested = decision('DENY_ACTION');
    const deps = dependencies({
      ...requested,
      binding: { ...requested.binding, proposalDigest: digest('9') },
    });

    await expect(executeApprovalCenterDecision(requested, deps)).rejects.toThrow(
      'does not match the request'
    );
    expect(deps.store.getSnapshot()[0].status).toBe('PENDING');
  });

  it('keeps task controls available after the exact action expires', async () => {
    const requested = { ...decision('REVOKE_ACCESS'), issuedAt: 1_101 };
    const deps = dependencies(requested);
    deps.store.upsert({ ...item, status: 'EXPIRED' });
    deps.nowSeconds.mockReturnValue(1_101);

    await executeApprovalCenterDecision(requested, deps);

    expect(deps.bridge.submitDecision).not.toHaveBeenCalled();
    expect(deps.order).toEqual(['revoke', 'lock']);
    expect(deps.store.getSnapshot()[0].status).toBe('ACCESS_REVOKED');
  });

  it('keeps task controls available after an action was denied', async () => {
    const requested = decision('STOP_TASK');
    const deps = dependencies(requested);
    deps.store.upsert({ ...item, status: 'DENIED' });

    await executeApprovalCenterDecision(requested, deps);

    expect(deps.bridge.submitDecision).not.toHaveBeenCalled();
    expect(deps.order).toEqual(['stop', 'revoke', 'lock']);
    expect(deps.store.getSnapshot()[0].status).toBe('TASK_STOPPED');
  });
});
