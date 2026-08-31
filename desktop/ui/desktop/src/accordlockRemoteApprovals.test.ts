import { generateKeyPairSync, sign } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { ApprovalInboxItem } from './accordlock/approvalInbox';
import { AccordLockApprovalCenterGate } from './accordlockApprovalCenterGate';
import {
  AccordLockRemoteApprovalGatewayStore,
  accordLockRemoteApprovalBindingHash,
  accordLockRemoteDecisionSigningPayload,
  parseAccordLockRemoteGatewayEnrollment,
  type AccordLockRemoteApprovalSafeStorage,
  type AccordLockRemoteGatewayEnrollmentInput,
} from './accordlockRemoteApprovals';

const temporaryDirectories: string[] = [];
const now = 2_000_000_000;
const digest = (character: string) => `sha256:${character.repeat(64)}`;
const safeStorage: AccordLockRemoteApprovalSafeStorage = {
  decryptString: (ciphertext) => ciphertext.subarray(4).toString('utf8'),
  encryptString: (plaintext) => Buffer.from(`enc:${plaintext}`, 'utf8'),
  isEncryptionAvailable: () => true,
};

const item: ApprovalInboxItem = Object.freeze({
  binding: Object.freeze({
    authorizationDigest: digest('a'),
    approvalRequestHash: digest('b'),
    prestateHash: digest('c'),
    proposalDigest: digest('d'),
    requestExpiresAt: now + 240,
    runId: 'run-1',
    sessionId: 'session-1',
    taskAccessExpiresAt: now + 600,
    taskId: 'task-1',
    taskPolicyHash: digest('e'),
    toolCallId: 'tool-1',
  }),
  canAllowOnce: true,
  contentEvidence: digest('f'),
  id: `action:${digest('b')}`,
  intentReview: 'POLICY_REVIEW',
  objective: 'Apply the reviewed change.',
  operationLabel: 'Edit file',
  preview: 'before → after',
  receivedAt: now - 5,
  status: 'PENDING',
  target: 'src/app.ts',
  targetLabel: 'File',
  workspaceRoot: 'C:\\workspace',
});

async function directory(): Promise<string> {
  const value = await fs.mkdtemp(path.join(os.tmpdir(), 'accordlock-remote-'));
  temporaryDirectories.push(value);
  return value;
}

function fixture() {
  const pair = generateKeyPairSync('ed25519');
  const publicKeySpki = pair.publicKey
    .export({ format: 'der', type: 'spki' })
    .toString('base64url');
  const enrollment: AccordLockRemoteGatewayEnrollmentInput = {
    channels: ['SLACK'],
    enrollmentId: '11111111-1111-4111-8111-111111111111',
    gatewayName: 'Operations gateway',
    protocol: 'accordlock.remote-gateway-enrollment.v1',
    publicKeySpki,
    schemaVersion: 1,
    validFrom: now - 60,
    validUntil: now + 3_600,
  };
  const unsigned = {
    approvalId: item.id,
    approverId: 'operator@example.com',
    bindingHash: accordLockRemoteApprovalBindingHash(item.id, item.binding),
    challengeId: '22222222-2222-4222-8222-222222222222',
    channel: 'SLACK' as const,
    enrollmentId: enrollment.enrollmentId,
    expiresAt: now + 120,
    intent: 'ALLOW_ONCE' as const,
    issuedAt: now - 2,
    protocol: 'accordlock.verified-remote-decision.v1' as const,
    providerEventId: 'slack-event-1',
    receiptId: '33333333-3333-4333-8333-333333333333',
    schemaVersion: 1 as const,
    signedChallengeHash: digest('9'),
    taskId: item.binding.taskId,
  };
  const signature = sign(null, accordLockRemoteDecisionSigningPayload(unsigned), pair.privateKey);
  return { enrollment, pair, receipt: { ...unsigned, signature: signature.toString('base64url') } };
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((value) => fs.rm(value, { recursive: true }))
  );
});

describe('remote approval gateway boundary', () => {
  it('enrolls an exact Ed25519 gateway document and exposes only a fingerprint', async () => {
    const root = await directory();
    const { enrollment } = fixture();
    expect(parseAccordLockRemoteGatewayEnrollment(enrollment)).toEqual(enrollment);
    const store = new AccordLockRemoteApprovalGatewayStore({
      directory: root,
      nowSeconds: () => now,
      safeStorage,
    });
    const summary = await store.enroll(enrollment);
    expect(summary).toMatchObject({
      channels: ['SLACK'],
      gatewayName: 'Operations gateway',
      status: 'ACTIVE',
    });
    expect(summary.fingerprint).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(JSON.stringify(summary)).not.toContain(enrollment.publicKeySpki);
  });

  it('accepts one signed exact decision and consumes it before returning', async () => {
    const root = await directory();
    const { enrollment, receipt } = fixture();
    const store = new AccordLockRemoteApprovalGatewayStore({
      directory: root,
      nowSeconds: () => now,
      safeStorage,
    });
    await store.enroll(enrollment);
    const result = await store.verifyAndConsume(receipt, item, true);
    expect(result.decision).toEqual({
      binding: item.binding,
      intent: 'ALLOW_ONCE',
      issuedAt: now,
      itemId: item.id,
    });
    expect(result.evidence).toMatchObject({
      channel: 'SLACK',
      providerEventId: 'slack-event-1',
    });
    await expect(store.verifyAndConsume(receipt, item, true)).rejects.toThrow('already consumed');
  });

  it('feeds verified evidence through the existing exact Approval Center gate', async () => {
    const root = await directory();
    const { enrollment, receipt } = fixture();
    const store = new AccordLockRemoteApprovalGatewayStore({
      directory: root,
      nowSeconds: () => now,
      safeStorage,
    });
    await store.enroll(enrollment);
    const verified = await store.verifyAndConsume(receipt, item, true);
    const gate = new AccordLockApprovalCenterGate(item, 17);
    const completion = gate.submit(verified.decision, 17, now);
    await expect(gate.selection).resolves.toMatchObject({
      intent: 'ALLOW_ONCE',
      itemId: item.id,
    });
    gate.complete(verified.decision);
    await expect(completion).resolves.toEqual(verified.decision);
  });

  it('rejects a wrong action binding without consuming the valid receipt', async () => {
    const root = await directory();
    const { enrollment, receipt } = fixture();
    const store = new AccordLockRemoteApprovalGatewayStore({
      directory: root,
      nowSeconds: () => now,
      safeStorage,
    });
    await store.enroll(enrollment);
    const wrongItem = {
      ...item,
      binding: { ...item.binding, proposalDigest: digest('0') },
    } satisfies ApprovalInboxItem;
    await expect(store.verifyAndConsume(receipt, wrongItem, true)).rejects.toThrow(
      'does not match'
    );
    await expect(store.verifyAndConsume(receipt, item, true)).resolves.toBeDefined();
  });

  it('rejects disabled channels and stale or revoked enrollments', async () => {
    const root = await directory();
    const { enrollment, receipt } = fixture();
    let trustedNow = now;
    const store = new AccordLockRemoteApprovalGatewayStore({
      directory: root,
      nowSeconds: () => trustedNow,
      safeStorage,
    });
    await store.enroll(enrollment);
    await expect(store.verifyAndConsume(receipt, item, false)).rejects.toThrow('not enabled');
    await store.revoke(enrollment.enrollmentId);
    await expect(store.verifyAndConsume(receipt, item, true)).rejects.toThrow('not active');

    const secondRoot = await directory();
    const expiredStore = new AccordLockRemoteApprovalGatewayStore({
      directory: secondRoot,
      nowSeconds: () => trustedNow,
      safeStorage,
    });
    await expiredStore.enroll(enrollment);
    trustedNow = enrollment.validUntil;
    await expect(expiredStore.verifyAndConsume(receipt, item, true)).rejects.toThrow('not active');
  });

  it('rejects provider event replay across distinct signed receipts and survives restart', async () => {
    const root = await directory();
    const { enrollment, pair, receipt } = fixture();
    const first = new AccordLockRemoteApprovalGatewayStore({
      directory: root,
      nowSeconds: () => now,
      safeStorage,
    });
    await first.enroll(enrollment);
    await first.verifyAndConsume(receipt, item, true);

    const unsigned = {
      ...receipt,
      receiptId: '44444444-4444-4444-8444-444444444444',
      signature: undefined,
    };
    const { signature: _signature, ...payload } = unsigned;
    const replay = {
      ...payload,
      signature: sign(
        null,
        accordLockRemoteDecisionSigningPayload(payload),
        pair.privateKey
      ).toString('base64url'),
    };
    const reopened = new AccordLockRemoteApprovalGatewayStore({
      directory: root,
      nowSeconds: () => now,
      safeStorage,
    });
    await expect(reopened.verifyAndConsume(replay, item, true)).rejects.toThrow('already consumed');
  });

  it('rejects unsigned substitutions and unknown fields', async () => {
    const root = await directory();
    const { enrollment, receipt } = fixture();
    const store = new AccordLockRemoteApprovalGatewayStore({
      directory: root,
      nowSeconds: () => now,
      safeStorage,
    });
    await store.enroll(enrollment);
    await expect(
      store.verifyAndConsume({ ...receipt, intent: 'REVOKE_ACCESS' }, item, true)
    ).rejects.toThrow('signature');
    await expect(
      store.verifyAndConsume({ ...receipt, providerPayload: {} }, item, true)
    ).rejects.toThrow('invalid');
  });
});
