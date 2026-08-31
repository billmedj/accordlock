import { describe, expect, it } from 'vitest';
import {
  notificationPresentationForRequest,
  parseAccordLockNotification,
  parseApprovalNotificationId,
  parseNotificationOpenTarget,
  routeForNotificationTarget,
} from './notificationNavigation';

const approvalId = `action:sha256:${'a'.repeat(64)}`;

describe('notification navigation', () => {
  it('accepts exact approval and task destinations', () => {
    expect(parseNotificationOpenTarget({ kind: 'APPROVAL', approvalId })).toEqual({
      kind: 'APPROVAL',
      approvalId,
    });
    expect(parseNotificationOpenTarget({ kind: 'TASK', sessionId: 'session-42' })).toEqual({
      kind: 'TASK',
      sessionId: 'session-42',
    });
  });

  it('builds internal routes with encoded identifiers', () => {
    expect(routeForNotificationTarget({ kind: 'APPROVAL', approvalId })).toBe(
      `/approvals?item=${encodeURIComponent(approvalId)}`
    );
    expect(routeForNotificationTarget({ kind: 'TASK', sessionId: 'session:42' })).toBe(
      '/pair?resumeSessionId=session%3A42'
    );
  });

  it.each([
    null,
    {},
    { kind: 'APPROVAL', approvalId: 'not-a-digest' },
    { kind: 'APPROVAL', approvalId, extra: true },
    { kind: 'TASK', sessionId: '../other' },
    { kind: 'TASK', sessionId: 'session-1', approvalId },
  ])('rejects malformed or ambiguous destinations', (value) => {
    expect(() => parseNotificationOpenTarget(value)).toThrow();
  });

  it('parses a closed notification event and derives fixed copy', () => {
    const parsed = parseAccordLockNotification({
      kind: 'APPROVAL_REQUIRED',
      open: { kind: 'APPROVAL', approvalId },
    });

    expect(parsed).toEqual({
      kind: 'APPROVAL_REQUIRED',
      open: { kind: 'APPROVAL', approvalId },
    });
    expect(notificationPresentationForRequest(parsed)).toEqual({
      title: 'Decision needed',
      body: 'Review the requested action.',
    });

    expect(
      parseAccordLockNotification({
        actionCount: 2,
        kind: 'TASK_FINISHED',
        open: { kind: 'TASK', sessionId: 'session-42' },
      })
    ).toEqual({
      actionCount: 2,
      kind: 'TASK_FINISHED',
      open: { kind: 'TASK', sessionId: 'session-42' },
    });
  });

  it.each([
    { title: 'Forged', body: 'Secret value' },
    { kind: 'APPROVAL_REQUIRED', open: { kind: 'TASK', sessionId: 'session-1' } },
    { kind: 'TASK_NO_CHANGES', open: { kind: 'APPROVAL', approvalId } },
    { kind: 'TASK_NO_CHANGES', open: { kind: 'TASK', sessionId: '../escape' } },
    {
      kind: 'TASK_CHECK_REQUIRED',
      open: { kind: 'TASK', sessionId: 'session-1' },
      title: 'Injected copy',
    },
    { actionCount: 0, kind: 'TASK_FINISHED', open: { kind: 'TASK', sessionId: 'session-1' } },
    {
      actionCount: 1_000_001,
      kind: 'TASK_FINISHED',
      open: { kind: 'TASK', sessionId: 'session-1' },
    },
  ])('rejects malformed notification envelopes', (value) => {
    expect(() => parseAccordLockNotification(value)).toThrow();
  });

  it('validates standalone approval identifiers used for dismissal', () => {
    expect(parseApprovalNotificationId(approvalId)).toBe(approvalId);
    expect(() => parseApprovalNotificationId('action:sha256:forged')).toThrow();
  });
});
