import { createHash, createPublicKey, randomUUID, verify as verifySignature } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import type {
  ApprovalCenterDecision,
  ApprovalCenterIntent,
  ApprovalInboxItem,
  ExactActionApprovalBinding,
} from './accordlock/approvalInbox';
import type { AccordLockApprovalChannelId } from './accordlockApprovalChannels';

const STORE_SCHEMA_VERSION = 1;
const MAX_STORE_BYTES = 512 * 1_024;
const MAX_ENROLLMENT_SECONDS = 400 * 24 * 60 * 60;
const MAX_RECEIPT_SECONDS = 5 * 60;
const MAX_CLOCK_SKEW_SECONDS = 30;
const MAX_CONSUMED_RECEIPTS = 1_024;
const CONSUMED_RETENTION_SECONDS = 24 * 60 * 60;
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const BASE64URL = /^[A-Za-z0-9_-]+$/u;
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const SECURE_LINUX_BACKENDS = new Set(['gnome_libsecret', 'kwallet', 'kwallet5', 'kwallet6']);

export const ACCORDLOCK_REMOTE_APPROVAL_ENROLLMENT_GET =
  'accordlock:remote-approval-enrollment:get';
export const ACCORDLOCK_REMOTE_APPROVAL_ENROLLMENT_IMPORT =
  'accordlock:remote-approval-enrollment:import';
export const ACCORDLOCK_REMOTE_APPROVAL_ENROLLMENT_REVOKE =
  'accordlock:remote-approval-enrollment:revoke';
export const ACCORDLOCK_REMOTE_APPROVAL_RECEIPT_IMPORT =
  'accordlock:remote-approval-receipt:import';

export type AccordLockRemoteGatewayEnrollmentInput = {
  channels: AccordLockApprovalChannelId[];
  enrollmentId: string;
  gatewayName: string;
  protocol: 'accordlock.remote-gateway-enrollment.v1';
  publicKeySpki: string;
  schemaVersion: 1;
  validFrom: number;
  validUntil: number;
};

type StoredEnrollment = AccordLockRemoteGatewayEnrollmentInput & {
  enrolledAt: number;
  revokedAt: number | null;
};

type ConsumedReceipt = {
  consumedAt: number;
  providerEventKey: string;
  receiptId: string;
};

type StoredDocument = {
  consumed: ConsumedReceipt[];
  enrollment: StoredEnrollment | null;
  schemaVersion: 1;
};

export type AccordLockRemoteGatewayEnrollmentSummary = {
  channels: AccordLockApprovalChannelId[];
  enrollmentId: string;
  fingerprint: string;
  gatewayName: string;
  status: 'ACTIVE' | 'EXPIRED' | 'NOT_YET_VALID' | 'REVOKED';
  validUntil: number;
};

export type AccordLockVerifiedRemoteDecisionReceipt = {
  approvalId: string;
  approverId: string;
  bindingHash: string;
  challengeId: string;
  channel: AccordLockApprovalChannelId;
  enrollmentId: string;
  expiresAt: number;
  intent: ApprovalCenterIntent;
  issuedAt: number;
  protocol: 'accordlock.verified-remote-decision.v1';
  providerEventId: string;
  receiptId: string;
  schemaVersion: 1;
  signature: string;
  signedChallengeHash: string;
  taskId: string;
};

export type AccordLockVerifiedRemoteDecisionEvidence = {
  approverId: string;
  challengeId: string;
  channel: AccordLockApprovalChannelId;
  providerEventId: string;
  receiptId: string;
  signedChallengeHash: string;
};

export type AccordLockRemoteApprovalResult = {
  decision: ApprovalCenterDecision;
  evidence: AccordLockVerifiedRemoteDecisionEvidence;
};

export interface AccordLockRemoteApprovalSafeStorage {
  decryptString(ciphertext: Buffer): string;
  encryptString(plaintext: string): Buffer;
  getSelectedStorageBackend?(): string;
  isEncryptionAvailable(): boolean;
}

type StoreOptions = {
  directory: string;
  nowSeconds?: () => number;
  platform?: NodeJS.Platform;
  safeStorage: AccordLockRemoteApprovalSafeStorage;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const sorted = [...expected].sort();
  return actual.length === sorted.length && actual.every((key, index) => key === sorted[index]);
}

function validTime(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function boundedText(value: unknown, maximumBytes: number): value is string {
  return (
    typeof value === 'string' &&
    value.trim() === value &&
    value.length > 0 &&
    Buffer.byteLength(value, 'utf8') <= maximumBytes &&
    ![...value].some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return (
        codePoint <= 0x1f ||
        codePoint === 0x7f ||
        (codePoint >= 0x202a && codePoint <= 0x202e) ||
        (codePoint >= 0x2066 && codePoint <= 0x2069)
      );
    })
  );
}

function channel(value: unknown): value is AccordLockApprovalChannelId {
  return (
    value === 'SLACK' || value === 'MICROSOFT_TEAMS' || value === 'TELEGRAM' || value === 'WHATSAPP'
  );
}

function decisionIntent(value: unknown): value is ApprovalCenterIntent {
  return (
    value === 'ALLOW_ONCE' ||
    value === 'DENY_ACTION' ||
    value === 'STOP_TASK' ||
    value === 'REVOKE_ACCESS'
  );
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error('Remote approval value is invalid');
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (!isRecord(value)) throw new Error('Remote approval value is invalid');
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(',')}}`;
}

export function accordLockRemoteApprovalBindingHash(
  itemId: string,
  binding: Readonly<ExactActionApprovalBinding>
): string {
  return `sha256:${createHash('sha256')
    .update(
      canonicalJson({
        binding: {
          authorizationDigest: binding.authorizationDigest,
          approvalRequestHash: binding.approvalRequestHash,
          prestateHash: binding.prestateHash,
          proposalDigest: binding.proposalDigest,
          requestExpiresAt: binding.requestExpiresAt,
          runId: binding.runId,
          sessionId: binding.sessionId,
          taskAccessExpiresAt: binding.taskAccessExpiresAt,
          taskId: binding.taskId,
          taskPolicyHash: binding.taskPolicyHash,
          toolCallId: binding.toolCallId,
        },
        itemId,
      })
    )
    .digest('hex')}`;
}

function decodeBase64Url(value: string, maximumBytes: number): Buffer {
  if (!BASE64URL.test(value) || value.includes('=')) {
    throw new Error('Remote approval encoding is invalid');
  }
  const decoded = Buffer.from(value, 'base64url');
  if (
    decoded.length === 0 ||
    decoded.length > maximumBytes ||
    decoded.toString('base64url') !== value
  ) {
    decoded.fill(0);
    throw new Error('Remote approval encoding is invalid');
  }
  return decoded;
}

export function parseAccordLockRemoteGatewayEnrollment(
  value: unknown
): AccordLockRemoteGatewayEnrollmentInput {
  if (
    !isRecord(value) ||
    !exactKeys(value, [
      'channels',
      'enrollmentId',
      'gatewayName',
      'protocol',
      'publicKeySpki',
      'schemaVersion',
      'validFrom',
      'validUntil',
    ]) ||
    value.schemaVersion !== 1 ||
    value.protocol !== 'accordlock.remote-gateway-enrollment.v1' ||
    !boundedText(value.gatewayName, 80) ||
    typeof value.enrollmentId !== 'string' ||
    !UUID.test(value.enrollmentId) ||
    !Array.isArray(value.channels) ||
    value.channels.length === 0 ||
    value.channels.length > 4 ||
    !value.channels.every(channel) ||
    new Set(value.channels).size !== value.channels.length ||
    !validTime(value.validFrom) ||
    !validTime(value.validUntil) ||
    value.validUntil <= value.validFrom ||
    value.validUntil - value.validFrom > MAX_ENROLLMENT_SECONDS ||
    typeof value.publicKeySpki !== 'string'
  ) {
    throw new Error('Remote approval gateway enrollment is invalid');
  }
  const publicKey = decodeBase64Url(value.publicKeySpki, 64);
  try {
    if (
      publicKey.length !== 44 ||
      !publicKey.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)
    ) {
      throw new Error('Remote approval gateway key is invalid');
    }
    const key = createPublicKey({ key: publicKey, format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'ed25519') {
      throw new Error('Remote approval gateway key is invalid');
    }
  } finally {
    publicKey.fill(0);
  }
  return {
    channels: [...value.channels].sort(),
    enrollmentId: value.enrollmentId,
    gatewayName: value.gatewayName,
    protocol: value.protocol,
    publicKeySpki: value.publicKeySpki,
    schemaVersion: 1,
    validFrom: value.validFrom,
    validUntil: value.validUntil,
  };
}

export function parseAccordLockVerifiedRemoteDecisionReceipt(
  value: unknown
): AccordLockVerifiedRemoteDecisionReceipt {
  if (
    !isRecord(value) ||
    !exactKeys(value, [
      'approvalId',
      'approverId',
      'bindingHash',
      'challengeId',
      'channel',
      'enrollmentId',
      'expiresAt',
      'intent',
      'issuedAt',
      'protocol',
      'providerEventId',
      'receiptId',
      'schemaVersion',
      'signature',
      'signedChallengeHash',
      'taskId',
    ]) ||
    value.schemaVersion !== 1 ||
    value.protocol !== 'accordlock.verified-remote-decision.v1' ||
    typeof value.enrollmentId !== 'string' ||
    !UUID.test(value.enrollmentId) ||
    typeof value.receiptId !== 'string' ||
    !UUID.test(value.receiptId) ||
    typeof value.challengeId !== 'string' ||
    !UUID.test(value.challengeId) ||
    !channel(value.channel) ||
    !decisionIntent(value.intent) ||
    typeof value.approvalId !== 'string' ||
    !/^action:sha256:[0-9a-f]{64}$/u.test(value.approvalId) ||
    typeof value.bindingHash !== 'string' ||
    !SHA256_DIGEST.test(value.bindingHash) ||
    typeof value.signedChallengeHash !== 'string' ||
    !SHA256_DIGEST.test(value.signedChallengeHash) ||
    !boundedText(value.taskId, 256) ||
    !boundedText(value.approverId, 256) ||
    !boundedText(value.providerEventId, 512) ||
    !validTime(value.issuedAt) ||
    !validTime(value.expiresAt) ||
    value.expiresAt <= value.issuedAt ||
    value.expiresAt - value.issuedAt > MAX_RECEIPT_SECONDS ||
    typeof value.signature !== 'string'
  ) {
    throw new Error('Verified remote decision receipt is invalid');
  }
  const signature = decodeBase64Url(value.signature, 64);
  if (signature.length !== 64) {
    signature.fill(0);
    throw new Error('Verified remote decision signature is invalid');
  }
  signature.fill(0);
  return value as AccordLockVerifiedRemoteDecisionReceipt;
}

export function accordLockRemoteDecisionSigningPayload(
  receipt: Omit<AccordLockVerifiedRemoteDecisionReceipt, 'signature'>
): Buffer {
  return Buffer.from(canonicalJson(receipt), 'utf8');
}

function receiptWithoutSignature(
  receipt: AccordLockVerifiedRemoteDecisionReceipt
): Omit<AccordLockVerifiedRemoteDecisionReceipt, 'signature'> {
  const { signature: _signature, ...unsigned } = receipt;
  return unsigned;
}

function enrollmentFingerprint(enrollment: AccordLockRemoteGatewayEnrollmentInput): string {
  return `sha256:${createHash('sha256')
    .update(Buffer.from(enrollment.publicKeySpki, 'base64url'))
    .digest('hex')}`;
}

function enrollmentStatus(
  enrollment: StoredEnrollment,
  now: number
): AccordLockRemoteGatewayEnrollmentSummary['status'] {
  if (enrollment.revokedAt !== null) return 'REVOKED';
  if (now < enrollment.validFrom) return 'NOT_YET_VALID';
  if (now >= enrollment.validUntil) return 'EXPIRED';
  return 'ACTIVE';
}

function summary(
  enrollment: StoredEnrollment,
  now: number
): AccordLockRemoteGatewayEnrollmentSummary {
  return {
    channels: [...enrollment.channels],
    enrollmentId: enrollment.enrollmentId,
    fingerprint: enrollmentFingerprint(enrollment),
    gatewayName: enrollment.gatewayName,
    status: enrollmentStatus(enrollment, now),
    validUntil: enrollment.validUntil,
  };
}

export function previewAccordLockRemoteGatewayEnrollment(
  value: unknown,
  now: number
): AccordLockRemoteGatewayEnrollmentSummary {
  if (!validTime(now)) throw new Error('Remote approval trusted time is unavailable');
  const input = parseAccordLockRemoteGatewayEnrollment(value);
  return summary({ ...input, enrolledAt: now, revokedAt: null }, now);
}

function parseStoredDocument(value: unknown): StoredDocument {
  if (
    !isRecord(value) ||
    !exactKeys(value, ['consumed', 'enrollment', 'schemaVersion']) ||
    value.schemaVersion !== STORE_SCHEMA_VERSION ||
    !Array.isArray(value.consumed) ||
    value.consumed.length > MAX_CONSUMED_RECEIPTS
  ) {
    throw new Error('Remote approval gateway state is invalid');
  }
  const enrollment = value.enrollment;
  let parsedEnrollment: StoredEnrollment | null = null;
  if (enrollment !== null) {
    if (
      !isRecord(enrollment) ||
      !validTime(enrollment.enrolledAt) ||
      !(enrollment.revokedAt === null || validTime(enrollment.revokedAt)) ||
      (typeof enrollment.revokedAt === 'number' && enrollment.revokedAt < enrollment.enrolledAt)
    ) {
      throw new Error('Remote approval gateway state is invalid');
    }
    const { enrolledAt, revokedAt, ...input } = enrollment;
    parsedEnrollment = { ...parseAccordLockRemoteGatewayEnrollment(input), enrolledAt, revokedAt };
  }
  const consumed = value.consumed.map((entry): ConsumedReceipt => {
    if (
      !isRecord(entry) ||
      !exactKeys(entry, ['consumedAt', 'providerEventKey', 'receiptId']) ||
      !validTime(entry.consumedAt) ||
      typeof entry.receiptId !== 'string' ||
      !UUID.test(entry.receiptId) ||
      typeof entry.providerEventKey !== 'string' ||
      !SHA256_DIGEST.test(entry.providerEventKey)
    ) {
      throw new Error('Remote approval gateway state is invalid');
    }
    return {
      consumedAt: entry.consumedAt,
      providerEventKey: entry.providerEventKey,
      receiptId: entry.receiptId,
    };
  });
  if (
    new Set(consumed.map((entry) => entry.receiptId)).size !== consumed.length ||
    new Set(consumed.map((entry) => entry.providerEventKey)).size !== consumed.length
  ) {
    throw new Error('Remote approval gateway state is invalid');
  }
  return { consumed, enrollment: parsedEnrollment, schemaVersion: 1 };
}

async function writeAtomic(filePath: string, contents: Buffer): Promise<void> {
  const directory = path.dirname(filePath);
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  const temporaryPath = path.join(directory, `.remote-approval.${randomUUID()}.tmp`);
  let handle: fs.FileHandle | null = null;
  try {
    handle = await fs.open(temporaryPath, 'wx', 0o600);
    await handle.writeFile(contents);
    await handle.sync();
    await handle.close();
    handle = null;
    await fs.rename(temporaryPath, filePath);
  } catch (error) {
    await handle?.close().catch(() => undefined);
    await fs.unlink(temporaryPath).catch(() => undefined);
    throw error;
  }
}

export class AccordLockRemoteApprovalGatewayStore {
  private readonly filePath: string;
  private readonly nowSeconds: () => number;
  private readonly platform: NodeJS.Platform;
  private readonly safeStorage: AccordLockRemoteApprovalSafeStorage;
  private writeTail: Promise<void> = Promise.resolve();

  constructor(options: StoreOptions) {
    this.filePath = path.join(options.directory, 'remote-approval-gateway.v1.bin');
    this.nowSeconds = options.nowSeconds ?? (() => Math.floor(Date.now() / 1_000));
    this.platform = options.platform ?? process.platform;
    this.safeStorage = options.safeStorage;
  }

  async getSummary(): Promise<AccordLockRemoteGatewayEnrollmentSummary | null> {
    await this.writeTail;
    const document = await this.read();
    return document.enrollment ? summary(document.enrollment, this.trustedNow()) : null;
  }

  async enroll(value: unknown): Promise<AccordLockRemoteGatewayEnrollmentSummary> {
    const input = parseAccordLockRemoteGatewayEnrollment(value);
    let result: AccordLockRemoteGatewayEnrollmentSummary | null = null;
    const operation = this.writeTail.then(async () => {
      const now = this.trustedNow();
      if (now >= input.validUntil)
        throw new Error('Remote approval gateway enrollment has expired');
      const document = await this.read();
      document.enrollment = { ...input, enrolledAt: now, revokedAt: null };
      document.consumed = [];
      await this.write(document);
      result = summary(document.enrollment, now);
    });
    this.writeTail = operation.catch(() => undefined);
    await operation;
    if (!result) throw new Error('Remote approval gateway was not enrolled');
    return result;
  }

  async revoke(enrollmentId: unknown): Promise<AccordLockRemoteGatewayEnrollmentSummary> {
    if (typeof enrollmentId !== 'string' || !UUID.test(enrollmentId)) {
      throw new Error('Remote approval gateway enrollment is invalid');
    }
    let result: AccordLockRemoteGatewayEnrollmentSummary | null = null;
    const operation = this.writeTail.then(async () => {
      const now = this.trustedNow();
      const document = await this.read();
      if (!document.enrollment || document.enrollment.enrollmentId !== enrollmentId) {
        throw new Error('Remote approval gateway enrollment was not found');
      }
      document.enrollment.revokedAt ??= now;
      await this.write(document);
      result = summary(document.enrollment, now);
    });
    this.writeTail = operation.catch(() => undefined);
    await operation;
    if (!result) throw new Error('Remote approval gateway was not revoked');
    return result;
  }

  async verifyAndConsume(
    value: unknown,
    item: ApprovalInboxItem,
    channelEnabled: boolean
  ): Promise<AccordLockRemoteApprovalResult> {
    const receipt = parseAccordLockVerifiedRemoteDecisionReceipt(value);
    let result: AccordLockRemoteApprovalResult | null = null;
    const operation = this.writeTail.then(async () => {
      const now = this.trustedNow();
      const document = await this.read();
      const enrollment = document.enrollment;
      if (!enrollment || enrollment.enrollmentId !== receipt.enrollmentId) {
        throw new Error('Remote approval gateway enrollment was not found');
      }
      if (enrollmentStatus(enrollment, now) !== 'ACTIVE') {
        throw new Error('Remote approval gateway enrollment is not active');
      }
      if (!channelEnabled || !enrollment.channels.includes(receipt.channel)) {
        throw new Error('Remote approval channel is not enabled');
      }
      if (
        receipt.issuedAt < enrollment.validFrom ||
        receipt.issuedAt > now + MAX_CLOCK_SKEW_SECONDS ||
        receipt.expiresAt <= now ||
        receipt.expiresAt > enrollment.validUntil ||
        receipt.expiresAt > item.binding.requestExpiresAt ||
        receipt.approvalId !== item.id ||
        receipt.taskId !== item.binding.taskId ||
        receipt.bindingHash !== accordLockRemoteApprovalBindingHash(item.id, item.binding) ||
        (receipt.intent === 'ALLOW_ONCE' && !item.canAllowOnce)
      ) {
        throw new Error('Verified remote decision does not match the pending action');
      }

      const signature = decodeBase64Url(receipt.signature, 64);
      const publicKey = decodeBase64Url(enrollment.publicKeySpki, 64);
      const payload = accordLockRemoteDecisionSigningPayload(receiptWithoutSignature(receipt));
      try {
        const key = createPublicKey({ key: publicKey, format: 'der', type: 'spki' });
        if (!verifySignature(null, payload, key, signature)) {
          throw new Error('Verified remote decision signature is invalid');
        }
      } finally {
        signature.fill(0);
        publicKey.fill(0);
        payload.fill(0);
      }

      const providerEventKey = `sha256:${createHash('sha256')
        .update(`${receipt.channel}\u0000${receipt.providerEventId}`, 'utf8')
        .digest('hex')}`;
      if (
        document.consumed.some(
          (entry) =>
            entry.receiptId === receipt.receiptId || entry.providerEventKey === providerEventKey
        )
      ) {
        throw new Error('Verified remote decision was already consumed');
      }
      document.consumed = [
        ...document.consumed.filter(
          (entry) => now - entry.consumedAt <= CONSUMED_RETENTION_SECONDS
        ),
        { consumedAt: now, providerEventKey, receiptId: receipt.receiptId },
      ];
      if (document.consumed.length > MAX_CONSUMED_RECEIPTS) {
        document.consumed = document.consumed.slice(-MAX_CONSUMED_RECEIPTS);
      }
      await this.write(document);
      result = {
        decision: Object.freeze({
          binding: item.binding,
          intent: receipt.intent,
          issuedAt: now,
          itemId: item.id,
        }),
        evidence: Object.freeze({
          approverId: receipt.approverId,
          challengeId: receipt.challengeId,
          channel: receipt.channel,
          providerEventId: receipt.providerEventId,
          receiptId: receipt.receiptId,
          signedChallengeHash: receipt.signedChallengeHash,
        }),
      };
    });
    this.writeTail = operation.catch(() => undefined);
    await operation;
    if (!result) throw new Error('Verified remote decision was not accepted');
    return result;
  }

  private trustedNow(): number {
    const now = this.nowSeconds();
    if (!validTime(now)) throw new Error('Remote approval trusted time is unavailable');
    return now;
  }

  private requireSecureStorage(): void {
    if (!this.safeStorage.isEncryptionAvailable()) {
      throw new Error('Secure remote approval storage is unavailable');
    }
    if (this.platform === 'linux') {
      const backend = this.safeStorage.getSelectedStorageBackend?.();
      if (!backend || !SECURE_LINUX_BACKENDS.has(backend)) {
        throw new Error('Secure remote approval storage is unavailable');
      }
    }
  }

  private async read(): Promise<StoredDocument> {
    this.requireSecureStorage();
    let encrypted: Buffer;
    try {
      encrypted = await fs.readFile(this.filePath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return { consumed: [], enrollment: null, schemaVersion: 1 };
      }
      throw error;
    }
    if (encrypted.length === 0 || encrypted.length > MAX_STORE_BYTES) {
      throw new Error('Remote approval gateway state is invalid');
    }
    const plaintext = this.safeStorage.decryptString(encrypted);
    if (Buffer.byteLength(plaintext, 'utf8') > MAX_STORE_BYTES) {
      throw new Error('Remote approval gateway state is invalid');
    }
    return parseStoredDocument(JSON.parse(plaintext) as unknown);
  }

  private async write(document: StoredDocument): Promise<void> {
    this.requireSecureStorage();
    const plaintext = JSON.stringify(parseStoredDocument(document));
    if (Buffer.byteLength(plaintext, 'utf8') > MAX_STORE_BYTES) {
      throw new Error('Remote approval gateway state is too large');
    }
    const encrypted = this.safeStorage.encryptString(plaintext);
    if (
      !Buffer.isBuffer(encrypted) ||
      encrypted.length === 0 ||
      encrypted.length > MAX_STORE_BYTES
    ) {
      throw new Error('Remote approval gateway state protection failed');
    }
    await writeAtomic(this.filePath, encrypted);
  }
}
