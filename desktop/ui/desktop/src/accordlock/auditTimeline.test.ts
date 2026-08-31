import { describe, expect, it } from 'vitest';
import type { TaskExecutionEvidence, TaskReport } from './taskReport';
import {
  buildTaskAuditTimeline,
  filterTaskAuditEvents,
  formatTaskAuditExport,
  type BuildTaskAuditTimelineInput,
  type TaskRestoreCapability,
} from './auditTimeline';

const hash = (character: string) => `sha256:${character.repeat(64)}`;

function evidence(overrides: Partial<TaskExecutionEvidence> = {}): TaskExecutionEvidence {
  return {
    authorizationId: '11111111-1111-4111-8111-111111111111',
    operation: 'WRITE',
    outcome: 'SUCCEEDED',
    recordedAt: 1_725_000_000,
    reasonCode: 'EXECUTED',
    recordHash: hash('b'),
    recordId: '22222222-2222-4222-8222-222222222222',
    recovery: null,
    requestHash: hash('a'),
    resultHash: hash('c'),
    target: 'src/main.ts',
    ...overrides,
  };
}

function report(items: TaskExecutionEvidence[], unverifiedActions = 0): TaskReport {
  const successfulActions = items.filter((item) => item.outcome === 'SUCCEEDED').length;
  return {
    evidence: items,
    failedActions: items.length - successfulActions,
    integrity:
      unverifiedActions > 0 ? 'NEEDS_CONFIRMATION' : items.length ? 'VERIFIED' : 'NO_EXECUTION',
    successfulActions,
    unverifiedActions,
  };
}

function input(overrides: Partial<BuildTaskAuditTimelineInput> = {}): BuildTaskAuditTimelineInput {
  return {
    authorization: 'APPROVED',
    expiresAt: 1_800_000_000,
    historyScope: 'TASK_RECORDS_ONLY',
    objective: 'Prepare a verified release',
    pendingDecision: false,
    report: report([evidence()]),
    requestedAt: 1_724_999_900,
    restoreAcknowledgements: [],
    restoreCapabilities: [],
    revocation: null,
    sessionId: 'session-1',
    workspace: 'C:\\work\\accordlock',
    ...overrides,
  };
}

describe('buildTaskAuditTimeline', () => {
  it('projects the request, authorization, action, effect, and outcome from verified task records', () => {
    const timeline = buildTaskAuditTimeline(input());

    expect(timeline.events.map((event) => event.kind)).toEqual([
      'TASK_REQUESTED',
      'ACCESS_ACTIVE',
      'ACTION_RECORDED',
    ]);
    expect(timeline.scopeNotice).toBe('Saved task activity. Earlier records may be unavailable.');

    const action = timeline.events[timeline.events.length - 1];
    expect(action).toMatchObject({
      category: 'CHANGE',
      status: 'VERIFIED',
      title: 'Wrote file · src/main.ts',
      reversibility: { status: 'NOT_SUPPORTED', label: 'No restore point' },
    });
    expect(action?.details).toContainEqual({
      label: 'Outcome',
      details: expect.arrayContaining([
        { label: 'Record ID', value: '22222222-2222-4222-8222-222222222222' },
        { label: 'Verification hash', value: hash('b') },
      ]),
    });
  });

  it('does not turn a recovery copy into a restore control without an exact capability', () => {
    const deleted = evidence({
      operation: 'DELETE',
      recovery: {
        contentHash: hash('d'),
        recoveryId: '33333333-3333-4333-8333-333333333333',
        recoveryPath: '.accordlock/recovery/33333333-3333-4333-8333-333333333333/content',
      },
      target: 'notes.txt',
    });
    const restoreCapability: TaskRestoreCapability = {
      contentHash: hash('d'),
      recordId: deleted.recordId,
      recoveryId: deleted.recovery!.recoveryId,
      recoveryPath: deleted.recovery!.recoveryPath,
    };

    const copyOnly = buildTaskAuditTimeline(input({ report: report([deleted]) }));
    expect(copyOnly.events[copyOnly.events.length - 1]?.reversibility).toMatchObject({
      status: 'RECOVERY_COPY',
      label: 'Recovery copy',
    });
    expect(copyOnly.reversibleCount).toBe(0);

    const mismatch = buildTaskAuditTimeline(
      input({
        report: report([deleted]),
        restoreCapabilities: [{ ...restoreCapability, contentHash: hash('e') }],
      })
    );
    expect(mismatch.events[mismatch.events.length - 1]?.reversibility?.status).toBe(
      'RECOVERY_COPY'
    );

    const restorable = buildTaskAuditTimeline(
      input({ report: report([deleted]), restoreCapabilities: [restoreCapability] })
    );
    expect(restorable.events[restorable.events.length - 1]?.reversibility).toEqual({
      status: 'RESTORABLE',
      label: 'Restorable',
      explanation: 'This file can be restored from its saved copy.',
      request: { ...restoreCapability, target: 'notes.txt' },
    });
    expect(restorable.reversibleCount).toBe(1);
  });

  it('records restore results separately without changing the deletion record', () => {
    const deleted = evidence({
      operation: 'DELETE',
      recovery: {
        contentHash: hash('d'),
        recoveryId: '33333333-3333-4333-8333-333333333333',
        recoveryPath: '.accordlock/recovery/33333333-3333-4333-8333-333333333333/content',
      },
      target: 'notes.txt',
    });
    const capability: TaskRestoreCapability = {
      contentHash: hash('d'),
      recordId: deleted.recordId,
      recoveryId: deleted.recovery!.recoveryId,
      recoveryPath: deleted.recovery!.recoveryPath,
    };
    const timeline = buildTaskAuditTimeline(
      input({
        report: report([deleted]),
        restoreCapabilities: [capability],
        restoreAcknowledgements: [
          {
            protocol: 'accordlock.desktop.control/v2',
            schema_version: 2,
            session_id: 'session-1',
            recovery_id: capability.recoveryId,
            status: 'RESTORED',
            record: {
              restore_id: '44444444-4444-4444-8444-444444444444',
              record_hash: hash('e'),
              relative_path: 'notes.txt',
              content_sha256: hash('d'),
              completed_at: 1_725_000_100,
            },
          },
        ],
      })
    );

    expect(timeline.events.map((event) => event.kind)).toEqual([
      'TASK_REQUESTED',
      'ACCESS_ACTIVE',
      'ACTION_RECORDED',
      'FILE_RESTORE_RECORDED',
    ]);
    expect(timeline.events[2]?.reversibility).toMatchObject({
      status: 'RESTORABLE',
      request: { recoveryId: capability.recoveryId },
    });
    expect(timeline.events[3]).toMatchObject({
      category: 'CHANGE',
      status: 'VERIFIED',
      title: 'Restored file · notes.txt',
      summary: 'The original path now contains the saved copy.',
    });
    expect(timeline.reversibleCount).toBe(0);

    const exported = JSON.parse(formatTaskAuditExport(timeline));
    expect(exported.events[2].kind).toBe('ACTION_RECORDED');
    expect(exported.events[3]).toMatchObject({
      kind: 'FILE_RESTORE_RECORDED',
      title: 'Restored file · notes.txt',
    });
  });

  it('records a cancelled restore as a decision with no claimed file change', () => {
    const timeline = buildTaskAuditTimeline(
      input({
        restoreAcknowledgements: [
          {
            protocol: 'accordlock.desktop.control/v2',
            schema_version: 2,
            session_id: 'session-1',
            recovery_id: '33333333-3333-4333-8333-333333333333',
            status: 'CANCELLED',
            record: null,
          },
        ],
      })
    );

    expect(timeline.events[timeline.events.length - 1]).toMatchObject({
      category: 'DECISION',
      kind: 'FILE_RESTORE_RECORDED',
      status: 'INFO',
      summary: 'No file was restored.',
      title: 'Restore cancelled',
    });
  });

  it('shows pending decisions, incomplete verification, and explicit revocation as separate events', () => {
    const timeline = buildTaskAuditTimeline(
      input({
        pendingDecision: true,
        report: report([evidence()], 2),
        revocation: {
          reasonCode: 'USER_REVOKED',
          recordedAt: 1_725_000_100,
          requestId: 'revoke-request-1',
          revocationHash: hash('f'),
        },
      })
    );

    expect(timeline.events.map((event) => event.kind)).toEqual([
      'TASK_REQUESTED',
      'ACCESS_ACTIVE',
      'ACTION_APPROVAL_REQUESTED',
      'ACTION_RECORDED',
      'VERIFICATION_INCOMPLETE',
      'ACCESS_REVOKED',
    ]);
    expect(timeline.events[timeline.events.length - 1]?.summary).toBe(
      'Future actions are blocked. Earlier effects are unchanged.'
    );
    expect(filterTaskAuditEvents(timeline.events, 'ISSUES').map((event) => event.kind)).toEqual([
      'VERIFICATION_INCOMPLETE',
      'ACCESS_REVOKED',
    ]);
    expect(filterTaskAuditEvents(timeline.events, 'DECISIONS')).toHaveLength(3);
    expect(filterTaskAuditEvents(timeline.events, 'CHANGES')).toHaveLength(1);
  });

  it('exports a versioned projection with its limited history scope stated explicitly', () => {
    const parsed = JSON.parse(formatTaskAuditExport(buildTaskAuditTimeline(input())));

    expect(parsed).toMatchObject({
      schemaVersion: 1,
      recordType: 'accordlock.task-audit-projection',
      historyScope: 'TASK_RECORDS_ONLY',
    });
    expect(parsed.events).toHaveLength(3);
  });
});
