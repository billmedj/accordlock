import { describe, expect, it, vi } from 'vitest';
import type { AccordLockTaskBridge } from './taskBridge';
import {
  parseAccordLockTaskRestoreAck,
  readAccordLockTaskAuditPage,
  readAllAccordLockTaskAuditPages,
  restoreAccordLockDeletedFile,
  revokeBeforeAccordLockSessionDeletion,
} from './taskBridge';

const auditEvent = (eventId: string, recordedAt: number) => ({
  event_id: eventId,
  recorded_at: recordedAt,
  type: 'ACTION_DENIED' as const,
  denial_id: recordedAt,
  attempted_run_id: `attempted-run-${recordedAt}`,
  tool_call_id: `tool-${recordedAt}`,
  proposal_digest: `sha256:${'c'.repeat(64)}`,
  reason_code: 'POLICY_DENIED',
});

const auditAck = (
  sessionId: string,
  offset: number,
  events: ReturnType<typeof auditEvent>[],
  nextOffset: number | null,
  snapshotAt = 20,
  snapshotRevision = 7
) => ({
  protocol: 'accordlock.desktop.control/v2' as const,
  schema_version: 2 as const,
  session_id: sessionId,
  page: {
    schema_version: 6 as const,
    task_id: '55555555-5555-4555-8555-555555555555',
    session_id: sessionId,
    run_id: 'run-1',
    offset,
    next_offset: nextOffset,
    total_events: 2,
    snapshot_revision: snapshotRevision,
    snapshot_at: snapshotAt,
    events,
    page_digest: `sha256:${'d'.repeat(64)}`,
  },
});

const revocationAck = (sessionId: string) => ({
  protocol: 'accordlock.desktop.control/v2',
  schema_version: 2,
  session_id: sessionId,
  task_id: null,
  run_id: null,
  status: 'REVOKED',
  reason_code: 'NO_SESSION_AUTHORIZATION',
  revocation_record: { request_id: null, revocation_digest: null },
});

const recoveryId = '33333333-3333-4333-8333-333333333333';
const restoreAck = (sessionId: string) => ({
  protocol: 'accordlock.desktop.control/v2' as const,
  schema_version: 2 as const,
  session_id: sessionId,
  recovery_id: recoveryId,
  status: 'RESTORED' as const,
  record: {
    restore_id: '44444444-4444-4444-8444-444444444444',
    record_hash: `sha256:${'a'.repeat(64)}`,
    relative_path: 'notes.txt',
    content_sha256: `sha256:${'b'.repeat(64)}`,
    completed_at: 1_725_000_100,
  },
});

describe('revokeBeforeAccordLockSessionDeletion', () => {
  it('waits for strict revocation before invoking destructive deletion', async () => {
    const order: string[] = [];
    const bridge: Pick<AccordLockTaskBridge, 'revokeTaskAuthorization'> = {
      revokeTaskAuthorization: vi.fn(async (request) => {
        order.push('revoke');
        return revocationAck(request.session_id);
      }),
    };
    const deleteSession = vi.fn(async () => {
      order.push('deleted');
      return 'done';
    });

    await expect(
      revokeBeforeAccordLockSessionDeletion('session-1', deleteSession, bridge)
    ).resolves.toBe('done');
    expect(order).toEqual(['revoke', 'deleted']);
  });

  it('never invokes deletion when revocation fails or acknowledges another session', async () => {
    const deleteSession = vi.fn(async () => undefined);
    const unavailable = {
      revokeTaskAuthorization: vi.fn().mockRejectedValue(new Error('runtime unavailable')),
    };
    await expect(
      revokeBeforeAccordLockSessionDeletion('session-1', deleteSession, unavailable)
    ).rejects.toThrow('runtime unavailable');
    expect(deleteSession).not.toHaveBeenCalled();

    const mismatched = {
      revokeTaskAuthorization: vi.fn().mockResolvedValue(revocationAck('session-2')),
    };
    await expect(
      revokeBeforeAccordLockSessionDeletion('session-1', deleteSession, mismatched)
    ).rejects.toThrow('another session');
    expect(deleteSession).not.toHaveBeenCalled();
  });
});

describe('restoreAccordLockDeletedFile', () => {
  it('sends only the session and recovery binding, then accepts a strict acknowledgement', async () => {
    const bridge: Pick<AccordLockTaskBridge, 'restoreDeletedFile'> = {
      restoreDeletedFile: vi.fn().mockResolvedValue(restoreAck('session-1')),
    };

    await expect(
      restoreAccordLockDeletedFile('session-1', recoveryId, bridge)
    ).resolves.toMatchObject({ status: 'RESTORED', recovery_id: recoveryId });
    expect(bridge.restoreDeletedFile).toHaveBeenCalledWith({
      protocol: 'accordlock.desktop.control/v2',
      schema_version: 2,
      session_id: 'session-1',
      recovery_id: recoveryId,
    });
  });

  it('rejects acknowledgements with extra fields or another request binding', () => {
    expect(() =>
      parseAccordLockTaskRestoreAck(
        { ...restoreAck('session-1'), workspace_root: 'C:\\work' },
        'session-1',
        recoveryId
      )
    ).toThrow();
    expect(() =>
      parseAccordLockTaskRestoreAck(restoreAck('session-2'), 'session-1', recoveryId)
    ).toThrow('does not match the request');
    expect(() =>
      parseAccordLockTaskRestoreAck(
        { ...restoreAck('session-1'), recovery_id: '55555555-5555-4555-8555-555555555555' },
        'session-1',
        recoveryId
      )
    ).toThrow('does not match the request');
  });

  it('requires null record data for cancellation and a strict record for success', () => {
    expect(() =>
      parseAccordLockTaskRestoreAck(
        { ...restoreAck('session-1'), status: 'CANCELLED' },
        'session-1',
        recoveryId
      )
    ).toThrow();
    expect(() =>
      parseAccordLockTaskRestoreAck(
        { ...restoreAck('session-1'), record: { ...restoreAck('session-1').record, extra: true } },
        'session-1',
        recoveryId
      )
    ).toThrow();
  });
});

describe('task audit bridge', () => {
  it('requests a bounded page and rejects a response for another offset', async () => {
    const getTaskAudit = vi
      .fn()
      .mockResolvedValue(auditAck('session-1', 0, [auditEvent('e-2', 20)], 1));

    await expect(
      readAccordLockTaskAuditPage('session-1', 0, 1, { getTaskAudit })
    ).resolves.toMatchObject({ offset: 0, next_offset: 1 });
    expect(getTaskAudit).toHaveBeenCalledWith({
      protocol: 'accordlock.desktop.control/v2',
      schema_version: 2,
      session_id: 'session-1',
      offset: 0,
      limit: 1,
      snapshot_revision: null,
    });

    getTaskAudit.mockResolvedValueOnce(auditAck('session-1', 1, [auditEvent('e-1', 10)], null));
    await expect(readAccordLockTaskAuditPage('session-1', 0, 1, { getTaskAudit })).rejects.toThrow(
      'does not match the request'
    );
  });

  it('loads one stable, complete snapshot and rejects a snapshot change', async () => {
    const getTaskAudit = vi.fn(
      async (request: { offset: number; snapshot_revision: number | null }) =>
        request.offset === 0
          ? auditAck('session-1', 0, [auditEvent('e-2', 20)], 1)
          : auditAck('session-1', 1, [auditEvent('e-1', 10)], null)
    );
    await expect(
      readAllAccordLockTaskAuditPages('session-1', { getTaskAudit })
    ).resolves.toHaveLength(2);
    expect(getTaskAudit.mock.calls[1]?.[0].snapshot_revision).toBe(7);

    const changed = vi.fn(async (request: { offset: number }) =>
      request.offset === 0
        ? auditAck('session-1', 0, [auditEvent('e-2', 20)], 1)
        : auditAck('session-1', 1, [auditEvent('e-1', 10)], null, 20, 8)
    );
    await expect(
      readAllAccordLockTaskAuditPages('session-1', { getTaskAudit: changed })
    ).rejects.toThrow('changed while it was being exported');
  });
});
