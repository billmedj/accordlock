import type { TaskReport } from './taskReport';
import type { AccordLockNotificationRequest } from './notificationNavigation';

export type TaskNotification = Exclude<
  AccordLockNotificationRequest,
  Readonly<{ kind: 'APPROVAL_REQUIRED'; open: unknown }>
>;

export function taskNotificationForReport(
  report: TaskReport,
  sessionId: string,
  state: { modelFailed?: boolean; pendingDecision?: boolean } = {}
): TaskNotification {
  const open = Object.freeze({ kind: 'TASK' as const, sessionId });

  if (state.pendingDecision) {
    return {
      kind: 'TASK_DECISION_REQUIRED',
      open,
    };
  }

  if (report.integrity === 'NEEDS_CONFIRMATION') {
    return {
      kind: 'TASK_CHECK_REQUIRED',
      open,
    };
  }

  if (state.modelFailed) {
    return {
      kind: 'TASK_MODEL_REQUEST_FAILED',
      open,
    };
  }

  if (report.evidence.length === 0) {
    return {
      kind: 'TASK_NO_CHANGES',
      open,
    };
  }

  return {
    actionCount: report.evidence.length,
    kind: 'TASK_FINISHED',
    open,
  };
}
