import { describe, expect, it, vi } from 'vitest';
import type { ApprovalCenterDecision, ApprovalInboxItem } from './accordlock/approvalInbox';
import {
  AccordLockApprovalCenterGate,
  resolveTrustedApprovalCenterIntent,
} from './accordlockApprovalCenterGate';

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
  return { binding: item.binding, intent, issuedAt: 1, itemId: item.id };
}

describe('AccordLockApprovalCenterGate', () => {
  it('replaces renderer time and accepts only the owning window and exact binding', async () => {
    const gate = new AccordLockApprovalCenterGate(item, 7);

    expect(() => gate.submit(decision('DENY_ACTION'), 8, 1_050)).toThrow('this window');
    expect(() =>
      gate.submit(
        {
          ...decision('DENY_ACTION'),
          binding: { ...item.binding, proposalDigest: digest('9') },
        },
        7,
        1_050
      )
    ).toThrow('exact pending action');

    const completion = gate.submit(decision('DENY_ACTION'), 7, 1_050);
    const selected = await gate.selection;
    expect(selected?.issuedAt).toBe(1_050);

    gate.complete(selected!);
    await expect(completion).resolves.toEqual(selected);
  });

  it('is single-flight and expires closed', async () => {
    const gate = new AccordLockApprovalCenterGate(item, 7);

    expect(gate.expire(1_099)).toBe(false);
    expect(gate.expire(1_100)).toBe(true);
    await expect(gate.selection).resolves.toBeNull();
    expect(() => gate.submit(decision('ALLOW_ONCE'), 7, 1_100)).toThrow('expired');
  });

  it('rejects a raw renderer approval when trusted reviewability is false', () => {
    const gate = new AccordLockApprovalCenterGate({ ...item, canAllowOnce: false }, 7);

    expect(() => gate.submit(decision('ALLOW_ONCE'), 7, 1_050)).toThrow(
      'cannot be approved from the Approval Center'
    );
    expect(() => gate.submit(decision('DENY_ACTION'), 7, 1_050)).not.toThrow();
  });

  it('permits only native confirmation to turn Allow once into authority', async () => {
    const confirm = vi.fn().mockResolvedValue(true);
    await expect(resolveTrustedApprovalCenterIntent(decision('ALLOW_ONCE'), confirm)).resolves.toBe(
      'ALLOW_ONCE'
    );
    expect(confirm).toHaveBeenCalledOnce();

    confirm.mockResolvedValue(false);
    await expect(resolveTrustedApprovalCenterIntent(decision('ALLOW_ONCE'), confirm)).resolves.toBe(
      'DENY_ACTION'
    );

    confirm.mockClear();
    await expect(
      resolveTrustedApprovalCenterIntent(decision('DENY_ACTION'), confirm)
    ).resolves.toBe('DENY_ACTION');
    expect(confirm).not.toHaveBeenCalled();
  });

  it('rejects an acknowledgement that upgrades or changes the selected intent', async () => {
    const gate = new AccordLockApprovalCenterGate(item, 7);
    const completion = gate.submit(decision('DENY_ACTION'), 7, 1_050);
    await gate.selection;

    expect(() => gate.complete({ ...decision('ALLOW_ONCE'), issuedAt: 1_050 })).toThrow(
      'trusted decision'
    );
    gate.fail(new Error('kept locked'));
    await expect(completion).rejects.toThrow('kept locked');
  });
});
