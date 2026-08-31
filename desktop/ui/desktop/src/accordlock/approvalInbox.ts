import type { AccordLockActionApprovalChallenge } from '../accordlockActionApproval';
import { z } from 'zod';
import { intentReviewCopy, type IntentReviewKind } from './intentReview';

const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/u;

interface ExactActionTaskAuthorization {
  readonly authorization_digest: string;
  readonly expires_at: number;
  readonly objective: string;
  readonly session_id: string;
  readonly task_id: string;
  readonly task_policy_hash: string;
  readonly workspace_root: string;
}

export type ApprovalInboxStatus =
  | 'PENDING'
  | 'ALLOWED_ONCE'
  | 'DENIED'
  | 'EXPIRED'
  | 'TASK_STOPPED'
  | 'ACCESS_REVOKED';

export type ApprovalTaskAccessState = 'PENDING' | 'APPROVED' | 'REJECTED';

export type ApprovalCenterIntent = 'ALLOW_ONCE' | 'DENY_ACTION' | 'STOP_TASK' | 'REVOKE_ACCESS';

/**
 * Immutable identifiers that bind a decision to one exact runtime proposal.
 * The UI never reconstructs an approval request from presentation text.
 */
export interface ExactActionApprovalBinding {
  authorizationDigest: string;
  approvalRequestHash: string;
  prestateHash: string;
  proposalDigest: string;
  requestExpiresAt: number;
  runId: string;
  sessionId: string;
  taskAccessExpiresAt: number;
  taskId: string;
  taskPolicyHash: string;
  toolCallId: string;
}

export interface ApprovalInboxItem {
  binding: Readonly<ExactActionApprovalBinding>;
  canAllowOnce: boolean;
  contentEvidence: string;
  id: string;
  intentReview?: IntentReviewKind;
  objective: string;
  operationLabel: string;
  preview: string;
  receivedAt: number;
  status: ApprovalInboxStatus;
  target: string;
  targetLabel: string;
  workspaceRoot: string;
}

export interface ProjectExactActionApprovalOptions {
  /** Authoritative decision deadline. It may never exceed task access. */
  expiresAt: number;
  /** Result of the existing trusted full-preview check. Defaults closed. */
  canAllowOnce?: boolean;
  receivedAt: number;
}

export type ApprovalCenterDecision = Readonly<{
  binding: Readonly<ExactActionApprovalBinding>;
  intent: ApprovalCenterIntent;
  issuedAt: number;
  itemId: string;
}>;

export interface ApprovalDecisionAvailability {
  allowOnce: boolean;
  denyAction: boolean;
  requestExpired: boolean;
  revokeAccess: boolean;
  stopTask: boolean;
  taskAccessActive: boolean;
}

const unixSecondsSchema = z.number().int().nonnegative().safe();
const digestSchema = z.string().regex(SHA256_DIGEST);
const boundedTextSchema = (maximum: number) =>
  z
    .string()
    .min(1)
    .max(maximum)
    .refine((value) => value.trim().length > 0 && !value.includes('\0'), 'must contain text');

const exactActionApprovalBindingSchema = z
  .object({
    authorizationDigest: digestSchema,
    approvalRequestHash: digestSchema,
    prestateHash: digestSchema,
    proposalDigest: digestSchema,
    requestExpiresAt: unixSecondsSchema,
    runId: boundedTextSchema(256),
    sessionId: boundedTextSchema(256),
    taskAccessExpiresAt: unixSecondsSchema,
    taskId: boundedTextSchema(256),
    taskPolicyHash: digestSchema,
    toolCallId: boundedTextSchema(256),
  })
  .strict();

const approvalInboxItemSchema = z
  .object({
    binding: exactActionApprovalBindingSchema,
    canAllowOnce: z.boolean(),
    contentEvidence: boundedTextSchema(4_096),
    id: boundedTextSchema(96),
    intentReview: z
      .enum(['EVIDENCE_MISSING', 'EVIDENCE_UNCERTAIN', 'POLICY_REVIEW'])
      .default('POLICY_REVIEW'),
    objective: boundedTextSchema(4_000),
    operationLabel: boundedTextSchema(160),
    preview: z.string().max(20_000),
    receivedAt: unixSecondsSchema,
    status: z.enum([
      'PENDING',
      'ALLOWED_ONCE',
      'DENIED',
      'EXPIRED',
      'TASK_STOPPED',
      'ACCESS_REVOKED',
    ]),
    target: boundedTextSchema(4_096),
    targetLabel: boundedTextSchema(160),
    workspaceRoot: boundedTextSchema(4_096),
  })
  .strict()
  .superRefine((item, context) => {
    if (item.id !== `action:${item.binding.approvalRequestHash}`) {
      context.addIssue({
        code: 'custom',
        path: ['id'],
        message: 'must match the exact approval request',
      });
    }
    if (
      item.binding.requestExpiresAt <= item.receivedAt ||
      item.binding.requestExpiresAt > item.binding.taskAccessExpiresAt
    ) {
      context.addIssue({
        code: 'custom',
        path: ['binding', 'requestExpiresAt'],
        message: 'must be inside active task access',
      });
    }
  });

const approvalCenterDecisionSchema = z
  .object({
    binding: exactActionApprovalBindingSchema,
    intent: z.enum(['ALLOW_ONCE', 'DENY_ACTION', 'STOP_TASK', 'REVOKE_ACCESS']),
    issuedAt: unixSecondsSchema,
    itemId: boundedTextSchema(96),
  })
  .strict()
  .superRefine((decision, context) => {
    if (decision.itemId !== `action:${decision.binding.approvalRequestHash}`) {
      context.addIssue({
        code: 'custom',
        path: ['itemId'],
        message: 'must match the exact approval request',
      });
    }
  });

function validUnixSeconds(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

function assertDigest(value: string, label: string): void {
  if (!SHA256_DIGEST.test(value)) {
    throw new Error(`Approval ${label} is invalid`);
  }
}

function assertExactActionMatchesTask(
  challenge: AccordLockActionApprovalChallenge,
  authorization: ExactActionTaskAuthorization
): void {
  const request = challenge.approvalRequest;
  if (
    challenge.sessionId !== authorization.session_id ||
    request.session_id !== authorization.session_id ||
    request.task_id !== authorization.task_id ||
    request.task_policy_hash !== authorization.task_policy_hash ||
    challenge.workspaceRoot !== authorization.workspace_root ||
    challenge.proposalDigest !== request.proposal_digest
  ) {
    throw new Error('Exact action does not match the authorized task');
  }

  assertDigest(authorization.authorization_digest, 'authorization digest');
  assertDigest(challenge.approvalRequestHash, 'request hash');
  assertDigest(challenge.proposalDigest, 'proposal digest');
  assertDigest(request.prestate_hash, 'prestate hash');
  assertDigest(request.task_policy_hash, 'task policy hash');
}

/**
 * Projects an already parsed main-process challenge into renderer-safe data.
 * The original challenge remains in trusted code; decisions carry only its
 * immutable identifiers back to the resolver.
 */
export function projectExactActionApproval(
  challenge: AccordLockActionApprovalChallenge,
  authorization: ExactActionTaskAuthorization,
  options: ProjectExactActionApprovalOptions
): ApprovalInboxItem {
  assertExactActionMatchesTask(challenge, authorization);
  if (
    !validUnixSeconds(options.receivedAt) ||
    !validUnixSeconds(options.expiresAt) ||
    options.expiresAt <= options.receivedAt ||
    options.expiresAt > authorization.expires_at
  ) {
    throw new Error('Approval expiry is invalid');
  }

  const binding = Object.freeze<ExactActionApprovalBinding>({
    authorizationDigest: authorization.authorization_digest,
    approvalRequestHash: challenge.approvalRequestHash,
    prestateHash: challenge.approvalRequest.prestate_hash,
    proposalDigest: challenge.proposalDigest,
    requestExpiresAt: options.expiresAt,
    runId: challenge.approvalRequest.run_id,
    sessionId: authorization.session_id,
    taskAccessExpiresAt: authorization.expires_at,
    taskId: authorization.task_id,
    taskPolicyHash: authorization.task_policy_hash,
    toolCallId: challenge.approvalRequest.tool_call_id,
  });

  return Object.freeze({
    binding,
    canAllowOnce: options.canAllowOnce === true,
    contentEvidence: challenge.contentEvidence,
    id: `action:${challenge.approvalRequestHash}`,
    intentReview: intentReviewCopy(challenge.approvalRequest.policy_decision).kind,
    objective: authorization.objective,
    operationLabel: challenge.operationLabel,
    preview: challenge.previewTruncated
      ? `${challenge.preview}\n… Full change opens in the protected review.`
      : challenge.preview,
    receivedAt: options.receivedAt,
    status: 'PENDING' as const,
    target: challenge.target,
    targetLabel: challenge.targetLabel,
    workspaceRoot: authorization.workspace_root,
  });
}

export function sameExactActionBinding(
  left: Readonly<ExactActionApprovalBinding>,
  right: Readonly<ExactActionApprovalBinding>
): boolean {
  return (
    left.authorizationDigest === right.authorizationDigest &&
    left.approvalRequestHash === right.approvalRequestHash &&
    left.prestateHash === right.prestateHash &&
    left.proposalDigest === right.proposalDigest &&
    left.requestExpiresAt === right.requestExpiresAt &&
    left.runId === right.runId &&
    left.sessionId === right.sessionId &&
    left.taskAccessExpiresAt === right.taskAccessExpiresAt &&
    left.taskId === right.taskId &&
    left.taskPolicyHash === right.taskPolicyHash &&
    left.toolCallId === right.toolCallId
  );
}

export function effectiveApprovalInboxStatus(
  item: ApprovalInboxItem,
  nowSeconds: number
): ApprovalInboxStatus {
  if (item.status === 'PENDING' && nowSeconds >= item.binding.requestExpiresAt) {
    return 'EXPIRED';
  }
  return item.status;
}

export function approvalDecisionAvailability(
  item: ApprovalInboxItem,
  taskAccessState: ApprovalTaskAccessState,
  nowSeconds: number,
  storedTaskExpiry: number | null = null
): ApprovalDecisionAvailability {
  const taskExpiry =
    storedTaskExpiry === null
      ? item.binding.taskAccessExpiresAt
      : Math.min(storedTaskExpiry, item.binding.taskAccessExpiresAt);
  const taskAccessActive = taskAccessState === 'APPROVED' && nowSeconds < taskExpiry;
  const requestExpired = nowSeconds >= item.binding.requestExpiresAt;
  const actionPending = item.status === 'PENDING' && !requestExpired;

  return {
    allowOnce: taskAccessActive && actionPending && item.canAllowOnce,
    denyAction: taskAccessActive && actionPending,
    requestExpired,
    revokeAccess: taskAccessActive,
    stopTask: taskAccessActive,
    taskAccessActive,
  };
}

export function createApprovalCenterDecision(
  item: ApprovalInboxItem,
  intent: ApprovalCenterIntent,
  taskAccessState: ApprovalTaskAccessState,
  nowSeconds: number,
  storedTaskExpiry: number | null = null
): ApprovalCenterDecision {
  if (!validUnixSeconds(nowSeconds)) throw new Error('Decision time is invalid');

  const availability = approvalDecisionAvailability(
    item,
    taskAccessState,
    nowSeconds,
    storedTaskExpiry
  );
  const allowed =
    intent === 'ALLOW_ONCE'
      ? availability.allowOnce
      : intent === 'DENY_ACTION'
        ? availability.denyAction
        : intent === 'STOP_TASK'
          ? availability.stopTask
          : availability.revokeAccess;
  if (!allowed) throw new Error('Decision is no longer available');

  return Object.freeze({
    binding: item.binding,
    intent,
    issuedAt: nowSeconds,
    itemId: item.id,
  });
}

export function approvalCenterDecisionMatchesItem(
  decision: ApprovalCenterDecision,
  item: ApprovalInboxItem
): boolean {
  return decision.itemId === item.id && sameExactActionBinding(decision.binding, item.binding);
}

export function approvalInboxStatusForDecisionIntent(
  intent: ApprovalCenterIntent
): ApprovalInboxStatus {
  switch (intent) {
    case 'ALLOW_ONCE':
      return 'ALLOWED_ONCE';
    case 'DENY_ACTION':
      return 'DENIED';
    case 'STOP_TASK':
      return 'TASK_STOPPED';
    case 'REVOKE_ACCESS':
      return 'ACCESS_REVOKED';
  }
}

/** Strictly validates an IPC projection before it enters renderer state. */
export function parseApprovalInboxItem(value: unknown): ApprovalInboxItem {
  const item = approvalInboxItemSchema.parse(value);
  return Object.freeze({
    ...item,
    binding: Object.freeze({ ...item.binding }),
  });
}

export function parseApprovalInboxItems(value: unknown): readonly ApprovalInboxItem[] {
  if (!Array.isArray(value)) throw new Error('Approval inbox projection must be a list');
  return Object.freeze(value.map(parseApprovalInboxItem));
}

/** Strictly validates a renderer request or a trusted decision acknowledgement. */
export function parseApprovalCenterDecision(value: unknown): ApprovalCenterDecision {
  const decision = approvalCenterDecisionSchema.parse(value);
  return Object.freeze({
    ...decision,
    binding: Object.freeze({ ...decision.binding }),
  });
}
