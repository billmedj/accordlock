import { describe, expect, it } from 'vitest';
import type { AccordLockActionApprovalChallenge } from '../accordlockActionApproval';
import { ACCORDLOCK_CONTROL_PROTOCOL } from './taskIpc';
import type { AccordLockTaskAuthorization } from './taskAuthorizationContract';
import {
  approvalCenterDecisionMatchesItem,
  approvalDecisionAvailability,
  createApprovalCenterDecision,
  projectExactActionApproval,
} from './approvalInbox';
import {
  ApprovalInboxStore,
  MAX_PENDING_APPROVALS,
  MAX_RETAINED_RESOLVED_APPROVALS,
} from './approvalInboxStore';

const digest = (character: string) => `sha256:${character.repeat(64)}`;

const authorization: AccordLockTaskAuthorization = {
  protocol: ACCORDLOCK_CONTROL_PROTOCOL,
  schema_version: 2,
  authorization_id: '11111111-1111-4111-8111-111111111111',
  task_id: '22222222-2222-4222-8222-222222222222',
  session_id: 'session-1',
  authorization_digest: digest('a'),
  objective: 'Update the release note.',
  workspace_root: 'C:\\Work\\product',
  prepared_at: 900,
  expires_at: 2_000,
  task_policy: {
    schema_version: 2,
    task_objective_hash: digest('b'),
    preauthorized_capabilities: [{ extension_id: 'developer', tool_name: 'read' }],
    protected_paths: ['.accordlock', '.git'],
  },
  task_policy_hash: digest('c'),
  capabilities: [
    {
      extension_id: 'developer',
      tool_name: 'read',
      display_name: 'Read files',
      operation_type: 'READ',
    },
    {
      extension_id: 'developer',
      tool_name: 'write',
      display_name: 'Write files',
      operation_type: 'WRITE',
    },
  ],
};

const challenge: AccordLockActionApprovalChallenge = {
  sessionId: authorization.session_id,
  workspaceRoot: authorization.workspace_root,
  proposalDigest: digest('d'),
  approvalRequestHash: digest('e'),
  approvalRequest: {
    schema_version: 2,
    task_id: authorization.task_id,
    session_id: authorization.session_id,
    run_id: 'run-1',
    tool_call_id: 'tool-call-1',
    proposal_digest: digest('d'),
    task_policy_hash: authorization.task_policy_hash,
    prestate_hash: digest('f'),
    action: {
      extension_id: 'developer',
      tool_name: 'write',
      action_type: 'OVERWRITE_FILE',
      relative_path: 'README.md',
      requested_bytes: 5,
    },
    task_requirement: { objective: 'Update the release note.' },
    transformation_step: { operation: 'WRITE' },
    policy_decision: { decision: 'REQUIRE_APPROVAL' },
    policy_decision_hash: digest('1'),
  },
  arguments: { kind: 'write', path: 'README.md', content: 'Hello' },
  operationLabel: 'Replace file',
  targetLabel: 'Path',
  target: 'README.md',
  quantityLabel: 'Proposed UTF-8',
  contentEvidence: `${digest('2')} · 5 bytes`,
  preview: 'Hello',
  previewTruncated: false,
};

function item() {
  return projectExactActionApproval(challenge, authorization, {
    canAllowOnce: true,
    expiresAt: 1_100,
    receivedAt: 1_000,
  });
}

function distinctItem(index: number) {
  const approvalRequestHash = `sha256:${index.toString(16).padStart(64, '0')}`;
  const projected = item();
  return {
    ...projected,
    id: `action:${approvalRequestHash}`,
    binding: {
      ...projected.binding,
      approvalRequestHash,
      proposalDigest: `sha256:${(index + 1_000).toString(16).padStart(64, '0')}`,
      toolCallId: `tool-call-${index}`,
    },
  };
}

describe('approval inbox projection', () => {
  it('keeps the exact action binding and authoritative deadlines', () => {
    const projected = item();

    expect(projected.id).toBe(`action:${challenge.approvalRequestHash}`);
    expect(projected.intentReview).toBe('POLICY_REVIEW');
    expect(projected.binding).toEqual({
      authorizationDigest: authorization.authorization_digest,
      approvalRequestHash: challenge.approvalRequestHash,
      prestateHash: challenge.approvalRequest.prestate_hash,
      proposalDigest: challenge.proposalDigest,
      requestExpiresAt: 1_100,
      runId: 'run-1',
      sessionId: authorization.session_id,
      taskAccessExpiresAt: authorization.expires_at,
      taskId: authorization.task_id,
      taskPolicyHash: authorization.task_policy_hash,
      toolCallId: 'tool-call-1',
    });
    expect(Object.isFrozen(projected)).toBe(true);
    expect(Object.isFrozen(projected.binding)).toBe(true);
  });

  it('projects a missing intent-evidence reason into fixed renderer copy', () => {
    const projected = projectExactActionApproval(
      {
        ...challenge,
        approvalRequest: {
          ...challenge.approvalRequest,
          policy_decision: {
            decision: 'REQUIRE_APPROVAL',
            reasons: ['CONFORMANCE_EVALUATION_MISSING'],
          },
        },
      },
      authorization,
      { canAllowOnce: true, expiresAt: 1_100, receivedAt: 1_000 }
    );

    expect(projected.intentReview).toBe('EVIDENCE_MISSING');
  });

  it('makes a shortened inbox preview explicit before opening the full protected review', () => {
    const projected = projectExactActionApproval(
      {
        ...challenge,
        preview: 'First 1,600 characters',
        previewTruncated: true,
      },
      authorization,
      {
        canAllowOnce: true,
        expiresAt: 1_100,
        receivedAt: 1_000,
      }
    );

    expect(projected.preview).toContain('First 1,600 characters');
    expect(projected.preview).toContain('Full change opens in the protected review.');
    expect(projected.canAllowOnce).toBe(true);
  });

  it('fails closed unless the action belongs to the same task, policy, and workspace', () => {
    expect(() =>
      projectExactActionApproval(
        { ...challenge, workspaceRoot: 'C:\\Work\\other' },
        authorization,
        { expiresAt: 1_100, receivedAt: 1_000 }
      )
    ).toThrow('does not match');

    expect(() =>
      projectExactActionApproval(challenge, authorization, {
        expiresAt: authorization.expires_at + 1,
        receivedAt: 1_000,
      })
    ).toThrow('expiry');
  });

  it('keeps four decisions behaviorally and cryptographically distinct', () => {
    const projected = item();
    for (const intent of ['ALLOW_ONCE', 'DENY_ACTION', 'STOP_TASK', 'REVOKE_ACCESS'] as const) {
      const decision = createApprovalCenterDecision(projected, intent, 'APPROVED', 1_050, 2_000);
      expect(decision.intent).toBe(intent);
      expect(decision.binding.approvalRequestHash).toBe(challenge.approvalRequestHash);
      expect(approvalCenterDecisionMatchesItem(decision, projected)).toBe(true);
    }
  });

  it('disables exact-action decisions after expiry without conflating task controls', () => {
    const availability = approvalDecisionAvailability(item(), 'APPROVED', 1_101, 2_000);

    expect(availability).toEqual({
      allowOnce: false,
      denyAction: false,
      requestExpired: true,
      revokeAccess: true,
      stopTask: true,
      taskAccessActive: true,
    });
    expect(() =>
      createApprovalCenterDecision(item(), 'ALLOW_ONCE', 'APPROVED', 1_101, 2_000)
    ).toThrow('no longer available');
    expect(createApprovalCenterDecision(item(), 'STOP_TASK', 'APPROVED', 1_101, 2_000).intent).toBe(
      'STOP_TASK'
    );
  });

  it('never allows a positive decision when the trusted preview check failed', () => {
    const hidden = projectExactActionApproval(challenge, authorization, {
      expiresAt: 1_100,
      receivedAt: 1_000,
    });
    const availability = approvalDecisionAvailability(hidden, 'APPROVED', 1_050, 2_000);

    expect(availability.allowOnce).toBe(false);
    expect(availability.denyAction).toBe(true);
  });
});

describe('ApprovalInboxStore', () => {
  it('records the first acknowledged decision and rejects a second answer', () => {
    const store = new ApprovalInboxStore();
    const projected = item();
    const allowed = createApprovalCenterDecision(projected, 'ALLOW_ONCE', 'APPROVED', 1_050, 2_000);
    store.upsert(projected);

    expect(store.settle(allowed).status).toBe('ALLOWED_ONCE');
    expect(() => store.settle(allowed)).toThrow('final decision');
  });

  it('rejects identifier reuse with a different exact binding', () => {
    const store = new ApprovalInboxStore();
    const projected = item();
    store.upsert(projected);

    expect(() =>
      store.upsert({
        ...projected,
        binding: { ...projected.binding, proposalDigest: digest('9') },
      })
    ).toThrow('identifier collision');
  });

  it('expires action decisions while preserving an acknowledged task stop', () => {
    const store = new ApprovalInboxStore();
    const projected = item();
    const stop = createApprovalCenterDecision(projected, 'STOP_TASK', 'APPROVED', 1_101, 2_000);
    store.upsert(projected);

    expect(store.expire(1_101)).toBe(1);
    expect(store.getSnapshot()[0].status).toBe('EXPIRED');
    expect(store.expire(1_102)).toBe(0);
    expect(store.settle(stop).status).toBe('TASK_STOPPED');
  });

  it('accepts a delayed trusted acknowledgement issued before local expiry', () => {
    const store = new ApprovalInboxStore();
    const projected = item();
    const allowed = createApprovalCenterDecision(projected, 'ALLOW_ONCE', 'APPROVED', 1_099, 2_000);
    store.upsert(projected);

    expect(store.expire(1_100)).toBe(1);
    expect(store.settle(allowed).status).toBe('ALLOWED_ONCE');
  });

  it('never evicts a pending decision and fails closed at the explicit capacity limit', () => {
    const store = new ApprovalInboxStore();
    for (let index = 0; index < MAX_PENDING_APPROVALS; index += 1) {
      store.upsert(distinctItem(index));
    }

    expect(() => store.upsert(distinctItem(MAX_PENDING_APPROVALS))).toThrow(
      'capacity reached; the action remains blocked'
    );
    expect(store.getSnapshot()).toHaveLength(MAX_PENDING_APPROVALS);
    expect(store.getSnapshot().every((approval) => approval.status === 'PENDING')).toBe(true);
  });

  it('clears sensitive request details after resolution and bounds recent history', () => {
    const store = new ApprovalInboxStore();
    for (let index = 0; index < MAX_RETAINED_RESOLVED_APPROVALS + 3; index += 1) {
      const projected = distinctItem(index);
      store.upsert(projected);
      store.settle({
        binding: projected.binding,
        intent: 'DENY_ACTION',
        issuedAt: 1_050,
        itemId: projected.id,
      });
    }

    const retained = store.getSnapshot();
    expect(retained).toHaveLength(MAX_RETAINED_RESOLVED_APPROVALS);
    expect(
      retained.every(
        (approval) =>
          approval.preview === '' &&
          approval.objective === 'Completed request' &&
          approval.target === 'Details cleared' &&
          approval.workspaceRoot === 'Details cleared' &&
          approval.canAllowOnce === false
      )
    ).toBe(true);
  });
});
