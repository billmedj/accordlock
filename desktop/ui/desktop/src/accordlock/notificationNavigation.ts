const APPROVAL_ID = /^action:sha256:[0-9a-f]{64}$/;
const SESSION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const MAX_RECORDED_ACTIONS = 1_000_000;

export const ACCORDLOCK_APPROVAL_NOTIFICATION_DISMISS =
  'accordlock:notification:dismiss-approval' as const;

export type ApprovalNotificationOpenTarget = Readonly<{
  kind: 'APPROVAL';
  approvalId: string;
}>;

export type TaskNotificationOpenTarget = Readonly<{
  kind: 'TASK';
  sessionId: string;
}>;

export type NotificationOpenTarget = ApprovalNotificationOpenTarget | TaskNotificationOpenTarget;

/**
 * Closed renderer-to-main notification protocol. The renderer selects an
 * event, never native notification text. Main owns every user-visible word.
 */
export type AccordLockNotificationRequest =
  | Readonly<{
      kind: 'APPROVAL_REQUIRED';
      open: ApprovalNotificationOpenTarget;
    }>
  | Readonly<{
      kind: 'TASK_DECISION_REQUIRED';
      open: TaskNotificationOpenTarget;
    }>
  | Readonly<{
      kind: 'TASK_CHECK_REQUIRED';
      open: TaskNotificationOpenTarget;
    }>
  | Readonly<{
      kind: 'TASK_MODEL_REQUEST_FAILED';
      open: TaskNotificationOpenTarget;
    }>
  | Readonly<{
      kind: 'TASK_NO_CHANGES';
      open: TaskNotificationOpenTarget;
    }>
  | Readonly<{
      actionCount: number;
      kind: 'TASK_FINISHED';
      open: TaskNotificationOpenTarget;
    }>;

export interface AccordLockNotificationPresentation {
  readonly body: string;
  readonly title: string;
}

function isExactRecord(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

export function parseApprovalNotificationId(value: unknown): string {
  if (typeof value !== 'string' || !APPROVAL_ID.test(value)) {
    throw new Error('Invalid approval notification identifier');
  }
  return value;
}

export function parseNotificationOpenTarget(value: unknown): NotificationOpenTarget {
  if (isExactRecord(value, ['kind', 'approvalId'])) {
    if (value.kind !== 'APPROVAL') {
      throw new Error('Invalid notification destination');
    }
    return Object.freeze({
      kind: 'APPROVAL',
      approvalId: parseApprovalNotificationId(value.approvalId),
    });
  }

  if (isExactRecord(value, ['kind', 'sessionId'])) {
    if (value.kind !== 'TASK' || typeof value.sessionId !== 'string') {
      throw new Error('Invalid notification destination');
    }
    if (!SESSION_ID.test(value.sessionId)) {
      throw new Error('Invalid task notification destination');
    }
    return Object.freeze({ kind: 'TASK', sessionId: value.sessionId });
  }

  throw new Error('Invalid notification destination');
}

function requireApprovalTarget(value: unknown): ApprovalNotificationOpenTarget {
  const target = parseNotificationOpenTarget(value);
  if (target.kind !== 'APPROVAL') throw new Error('Approval notification requires an approval');
  return target;
}

function requireTaskTarget(value: unknown): TaskNotificationOpenTarget {
  const target = parseNotificationOpenTarget(value);
  if (target.kind !== 'TASK') throw new Error('Task notification requires a task');
  return target;
}

export function parseAccordLockNotification(value: unknown): AccordLockNotificationRequest {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Invalid notification request');
  }
  const candidate = value as Record<string, unknown>;

  switch (candidate.kind) {
    case 'APPROVAL_REQUIRED':
      if (!isExactRecord(value, ['kind', 'open'])) throw new Error('Invalid notification request');
      return Object.freeze({ kind: candidate.kind, open: requireApprovalTarget(candidate.open) });
    case 'TASK_DECISION_REQUIRED':
    case 'TASK_CHECK_REQUIRED':
    case 'TASK_MODEL_REQUEST_FAILED':
    case 'TASK_NO_CHANGES':
      if (!isExactRecord(value, ['kind', 'open'])) throw new Error('Invalid notification request');
      return Object.freeze({ kind: candidate.kind, open: requireTaskTarget(candidate.open) });
    case 'TASK_FINISHED':
      if (!isExactRecord(value, ['actionCount', 'kind', 'open'])) {
        throw new Error('Invalid notification request');
      }
      if (
        typeof candidate.actionCount !== 'number' ||
        !Number.isSafeInteger(candidate.actionCount) ||
        candidate.actionCount < 1 ||
        candidate.actionCount > MAX_RECORDED_ACTIONS
      ) {
        throw new Error('Invalid recorded action count');
      }
      return Object.freeze({
        actionCount: candidate.actionCount,
        kind: candidate.kind,
        open: requireTaskTarget(candidate.open),
      });
    default:
      throw new Error('Unknown notification event');
  }
}

/** Fixed, secret-free copy rendered only after strict protocol validation. */
export function notificationPresentationForRequest(
  request: AccordLockNotificationRequest
): AccordLockNotificationPresentation {
  switch (request.kind) {
    case 'APPROVAL_REQUIRED':
    case 'TASK_DECISION_REQUIRED':
      return Object.freeze({ title: 'Decision needed', body: 'Review the requested action.' });
    case 'TASK_CHECK_REQUIRED':
      return Object.freeze({ title: 'Check required', body: 'One result could not be verified.' });
    case 'TASK_MODEL_REQUEST_FAILED':
      return Object.freeze({ title: 'Model request failed', body: 'No action was retried.' });
    case 'TASK_NO_CHANGES':
      return Object.freeze({ title: 'Task finished', body: 'No files or commands changed.' });
    case 'TASK_FINISHED': {
      const actionLabel = request.actionCount === 1 ? 'action' : 'actions';
      return Object.freeze({
        title: 'Task finished',
        body: `${request.actionCount} ${actionLabel} recorded.`,
      });
    }
  }
}

export function routeForNotificationTarget(target: NotificationOpenTarget): string {
  if (target.kind === 'APPROVAL') {
    return `/approvals?item=${encodeURIComponent(target.approvalId)}`;
  }
  return `/pair?resumeSessionId=${encodeURIComponent(target.sessionId)}`;
}
