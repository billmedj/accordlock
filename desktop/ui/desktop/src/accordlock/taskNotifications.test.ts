import { describe, expect, it } from 'vitest';
import type { TaskReport } from './taskReport';
import { taskNotificationForReport } from './taskNotifications';

const emptyReport: TaskReport = {
  evidence: [],
  failedActions: 0,
  integrity: 'NO_EXECUTION',
  successfulActions: 0,
  unverifiedActions: 0,
};

describe('taskNotificationForReport', () => {
  it('asks for attention when a decision is waiting', () => {
    expect(taskNotificationForReport(emptyReport, 'session-1', { pendingDecision: true })).toEqual({
      kind: 'TASK_DECISION_REQUIRED',
      open: { kind: 'TASK', sessionId: 'session-1' },
    });
  });

  it('does not describe an unverified action as complete', () => {
    expect(
      taskNotificationForReport(
        {
          ...emptyReport,
          integrity: 'NEEDS_CONFIRMATION',
          unverifiedActions: 1,
        },
        'session-1'
      ).kind
    ).toBe('TASK_CHECK_REQUIRED');
  });

  it('reports model failure separately from a slow or completed run', () => {
    expect(taskNotificationForReport(emptyReport, 'session-1', { modelFailed: true })).toEqual({
      kind: 'TASK_MODEL_REQUEST_FAILED',
      open: { kind: 'TASK', sessionId: 'session-1' },
    });
  });

  it('reports a no-change task as ready for review', () => {
    expect(taskNotificationForReport(emptyReport, 'session-1')).toEqual({
      kind: 'TASK_NO_CHANGES',
      open: { kind: 'TASK', sessionId: 'session-1' },
    });
  });

  it('reports completed actions only when execution evidence exists', () => {
    expect(
      taskNotificationForReport(
        {
          ...emptyReport,
          evidence: [
            {
              authorizationId: 'authorization-1',
              operation: 'WRITE',
              outcome: 'SUCCEEDED',
              recordedAt: 1,
              reasonCode: 'EXECUTED',
              recordHash: 'record-hash',
              recordId: 'record-1',
              recovery: null,
              requestHash: 'request-hash',
              resultHash: 'result-hash',
              target: 'src/main.ts',
            },
          ],
          integrity: 'VERIFIED',
          successfulActions: 1,
        },
        'session-1'
      )
    ).toEqual({
      actionCount: 1,
      kind: 'TASK_FINISHED',
      open: { kind: 'TASK', sessionId: 'session-1' },
    });
  });
});
