import type Electron from 'electron';
import { z } from 'zod';
import type { AccordLockSessionAuditPage } from '../accordlockRuntime';
import {
  ACCORDLOCK_CONTROL_PROTOCOL,
  ACCORDLOCK_TASK_AUTHORIZATION_EVENT,
  type AccordLockTaskAuditRequest,
  type AccordLockTaskAuthorizationDecisionRequest,
  type AccordLockTaskAuthorizationRevokeRequest,
  type AccordLockTaskRequest,
  type AccordLockTaskRestoreAck,
  type AccordLockTaskRestoreRequest,
} from './taskIpc';
import { parseAccordLockTaskAuthorizationRevokeAck } from './taskAuthorizationContract';
import { parseAccordLockTaskAuditAck } from './runtimeAudit';

const boundedText = (maximum: number) =>
  z
    .string()
    .min(1)
    .max(maximum)
    .refine((value) => value.trim().length > 0 && !value.includes('\0'), 'must contain text');
const canonicalUuid = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
const sha256Digest = z
  .string()
  .regex(/^sha256:[0-9a-f]{64}$/u)
  .refine((value) => value !== `sha256:${'0'.repeat(64)}`, 'must not be the zero digest');
const restoreRelativePath = boundedText(4_096).refine(
  (value) =>
    !value.startsWith('/') &&
    !value.startsWith('\\') &&
    !value.includes('\\') &&
    !value.includes(':') &&
    value
      .split('/')
      .every((component) => component.length > 0 && component !== '.' && component !== '..'),
  'must be a canonical relative path'
);
const restoreRecordSchema = z
  .object({
    restore_id: canonicalUuid,
    record_hash: sha256Digest,
    relative_path: restoreRelativePath,
    content_sha256: sha256Digest,
    completed_at: z.number().int().nonnegative().safe(),
  })
  .strict();
const restoreSuccessAckSchema = z
  .object({
    protocol: z.literal(ACCORDLOCK_CONTROL_PROTOCOL),
    schema_version: z.literal(2),
    session_id: boundedText(256),
    recovery_id: canonicalUuid,
    status: z.enum(['RESTORED', 'ALREADY_RESTORED']),
    record: restoreRecordSchema,
  })
  .strict();
const restoreCancelledAckSchema = z
  .object({
    protocol: z.literal(ACCORDLOCK_CONTROL_PROTOCOL),
    schema_version: z.literal(2),
    session_id: boundedText(256),
    recovery_id: canonicalUuid,
    status: z.literal('CANCELLED'),
    record: z.null(),
  })
  .strict();
const restoreAckSchema = z.union([restoreSuccessAckSchema, restoreCancelledAckSchema]);

export interface AccordLockTaskBridge {
  getPendingTaskAuthorizations: () => Promise<unknown>;
  requestTaskAuthorization: (request: AccordLockTaskRequest) => Promise<unknown>;
  submitTaskAuthorizationDecision: (
    request: AccordLockTaskAuthorizationDecisionRequest
  ) => Promise<unknown>;
  revokeTaskAuthorization: (request: AccordLockTaskAuthorizationRevokeRequest) => Promise<unknown>;
  restoreDeletedFile: (request: AccordLockTaskRestoreRequest) => Promise<unknown>;
  getTaskAudit: (request: AccordLockTaskAuditRequest) => Promise<unknown>;
  subscribeTaskAuthorizations: (listener: (value: unknown) => void) => () => void;
  reportProtocolError: (message: string) => void;
}

/**
 * Adapts Electron IPC to a narrow renderer contract. Renderer code can request
 * or decide task authorization, but it cannot call the trusted runtime directly.
 */
export function createAccordLockTaskBridge(): AccordLockTaskBridge {
  return {
    getPendingTaskAuthorizations: () => window.electron.getPendingAccordLockTaskAuthorizations(),
    requestTaskAuthorization: (request) =>
      window.electron.requestAccordLockTaskAuthorization(request),
    submitTaskAuthorizationDecision: (request) =>
      window.electron.submitAccordLockTaskAuthorizationDecision(request),
    revokeTaskAuthorization: (request) =>
      window.electron.revokeAccordLockTaskAuthorization(request),
    restoreDeletedFile: (request) => window.electron.restoreAccordLockDeletedFile(request),
    getTaskAudit: (request) => window.electron.getAccordLockTaskAudit(request),
    subscribeTaskAuthorizations: (listener) => {
      const handler = (_event: Electron.IpcRendererEvent, value: unknown) => listener(value);
      window.electron.on(ACCORDLOCK_TASK_AUTHORIZATION_EVENT, handler);
      return () => window.electron.off(ACCORDLOCK_TASK_AUTHORIZATION_EVENT, handler);
    },
    reportProtocolError: (message) =>
      window.electron.logInfo(`[ACCORDLOCK CONTROL PROTOCOL] ${message}`),
  };
}

function validateSessionId(sessionId: string): void {
  if (!sessionId || sessionId.trim() !== sessionId || sessionId.length > 256) {
    throw new Error('AccordLock session identifier is invalid');
  }
}

export async function readAccordLockTaskAuditPage(
  sessionId: string,
  offset = 0,
  limit = 100,
  bridge: Pick<AccordLockTaskBridge, 'getTaskAudit'> = createAccordLockTaskBridge(),
  snapshotRevision: number | null = null
): Promise<AccordLockSessionAuditPage> {
  validateSessionId(sessionId);
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > 100_000) {
    throw new Error('AccordLock audit offset is invalid');
  }
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
    throw new Error('AccordLock audit page size is invalid');
  }
  if (
    (snapshotRevision !== null &&
      (!Number.isSafeInteger(snapshotRevision) || snapshotRevision < 0)) ||
    (offset === 0 && snapshotRevision !== null) ||
    (offset > 0 && snapshotRevision === null)
  ) {
    throw new Error('AccordLock audit snapshot revision is invalid');
  }
  const request: AccordLockTaskAuditRequest = {
    protocol: ACCORDLOCK_CONTROL_PROTOCOL,
    schema_version: 2,
    session_id: sessionId,
    offset,
    limit,
    snapshot_revision: snapshotRevision,
  };
  const acknowledgement = parseAccordLockTaskAuditAck(
    await bridge.getTaskAudit(request),
    sessionId,
    offset,
    limit,
    snapshotRevision
  );
  return acknowledgement.page;
}

export async function readAllAccordLockTaskAuditPages(
  sessionId: string,
  bridge: Pick<AccordLockTaskBridge, 'getTaskAudit'> = createAccordLockTaskBridge(),
  initialPage?: AccordLockSessionAuditPage
): Promise<AccordLockSessionAuditPage[]> {
  const firstPage = initialPage
    ? parseAccordLockTaskAuditAck(
        {
          protocol: ACCORDLOCK_CONTROL_PROTOCOL,
          schema_version: 2,
          session_id: sessionId,
          page: initialPage,
        },
        sessionId,
        0,
        100,
        null
      ).page
    : await readAccordLockTaskAuditPage(sessionId, 0, 100, bridge);
  const pages = [firstPage];
  const first = pages[0];
  if (first.session_id !== sessionId || first.offset !== 0) {
    throw new Error('AccordLock audit snapshot does not start at the first record');
  }

  const eventIds = new Set(first.events.map((event) => event.event_id));
  if (eventIds.size !== first.events.length) {
    throw new Error('AccordLock audit snapshot repeats an event');
  }
  let nextOffset = first.next_offset;
  while (nextOffset !== null) {
    let page: AccordLockSessionAuditPage;
    try {
      page = await readAccordLockTaskAuditPage(
        sessionId,
        nextOffset,
        100,
        bridge,
        first.snapshot_revision
      );
    } catch (error) {
      if (error instanceof Error && error.message.includes('AUDIT_SNAPSHOT_CHANGED')) {
        throw new Error('AccordLock audit changed while it was being exported');
      }
      throw error;
    }
    if (
      page.task_id !== first.task_id ||
      page.run_id !== first.run_id ||
      page.snapshot_revision !== first.snapshot_revision ||
      page.snapshot_at !== first.snapshot_at ||
      page.total_events !== first.total_events
    ) {
      throw new Error('AccordLock audit changed while it was being exported');
    }
    for (const event of page.events) {
      if (eventIds.has(event.event_id)) {
        throw new Error('AccordLock audit snapshot repeats an event');
      }
      eventIds.add(event.event_id);
    }
    pages.push(page);
    nextOffset = page.next_offset;
  }

  const loadedEvents = pages.reduce((count, page) => count + page.events.length, 0);
  if (loadedEvents !== first.total_events) {
    throw new Error('AccordLock audit snapshot is incomplete');
  }
  return pages;
}

export function parseAccordLockTaskRestoreAck(
  value: unknown,
  expectedSessionId: string,
  expectedRecoveryId: string
): AccordLockTaskRestoreAck {
  const acknowledgement = restoreAckSchema.parse(value);
  if (
    acknowledgement.session_id !== expectedSessionId ||
    acknowledgement.recovery_id !== expectedRecoveryId
  ) {
    throw new Error('AccordLock restore acknowledgement does not match the request');
  }
  return acknowledgement;
}

export async function restoreAccordLockDeletedFile(
  sessionId: string,
  recoveryId: string,
  bridge: Pick<AccordLockTaskBridge, 'restoreDeletedFile'> = createAccordLockTaskBridge()
): Promise<AccordLockTaskRestoreAck> {
  validateSessionId(sessionId);
  if (!canonicalUuid.safeParse(recoveryId).success) {
    throw new Error('AccordLock recovery identifier is invalid');
  }
  const acknowledgement = await bridge.restoreDeletedFile({
    protocol: ACCORDLOCK_CONTROL_PROTOCOL,
    schema_version: 2,
    session_id: sessionId,
    recovery_id: recoveryId,
  });
  return parseAccordLockTaskRestoreAck(acknowledgement, sessionId, recoveryId);
}

/** Revoke task authorization before destructive renderer session operations. */
export async function revokeAccordLockTaskAuthorization(
  sessionId: string,
  bridge: Pick<AccordLockTaskBridge, 'revokeTaskAuthorization'> = createAccordLockTaskBridge()
) {
  validateSessionId(sessionId);
  const acknowledgement = await bridge.revokeTaskAuthorization({
    protocol: ACCORDLOCK_CONTROL_PROTOCOL,
    schema_version: 2,
    session_id: sessionId,
  });
  return parseAccordLockTaskAuthorizationRevokeAck(acknowledgement, sessionId);
}

export async function revokeBeforeAccordLockSessionDeletion<T>(
  sessionId: string,
  deleteSession: () => Promise<T>,
  bridge: Pick<AccordLockTaskBridge, 'revokeTaskAuthorization'> = createAccordLockTaskBridge()
): Promise<T> {
  await revokeAccordLockTaskAuthorization(sessionId, bridge);
  return deleteSession();
}
