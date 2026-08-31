import { Activity, CircleAlert, CircleCheck, Clock3, ShieldCheck, Square } from 'lucide-react';
import { useEffect, useMemo, useRef, useState, type ComponentRef, type ReactNode } from 'react';
import { defineMessages, useIntl } from '../../i18n';
import type { AccordLockSessionAuditPage } from '../../accordlockRuntime';
import type { AccordLockTaskAuthorizationState } from '../../accordlock/taskAuthorizationStore';
import type { AccordLockTaskRestoreAck } from '../../accordlock/taskIpc';
import { formatTaskReportMarkdown, type TaskReport } from '../../accordlock/taskReport';
import {
  buildTaskAuditTimeline,
  formatTaskAuditExport,
  type TaskRestoreCapability,
  type TaskRestoreRequest,
} from '../../accordlock/auditTimeline';
import {
  createAccordLockTaskBridge,
  readAccordLockTaskAuditPage,
  readAllAccordLockTaskAuditPages,
  restoreAccordLockDeletedFile,
  type AccordLockTaskBridge,
} from '../../accordlock/taskBridge';
import {
  formatRuntimeTaskAuditExport,
  mergeRuntimeAuditPage,
  mergeRuntimeAuditPages,
} from '../../accordlock/runtimeAudit';
import { taskStatusCopyForReason } from '../../accordlock/taskStatusCopy';
import { cn } from '../../utils';
import { AccordLockGlyph } from './AccordLockBrand';
import { TaskAuditTimeline, type TaskAuditExportFormat } from './TaskAuditTimeline';
import { toastError, toastSuccess } from '../../toasts';

const i18n = defineMessages({
  task: { id: 'taskStatus.task', defaultMessage: 'Task' },
  taskFallback: { id: 'taskStatus.taskFallback', defaultMessage: 'Untitled task' },
  workspace: { id: 'taskStatus.workspace', defaultMessage: 'Folder: {workspace}' },
  active: { id: 'taskStatus.active', defaultMessage: 'Working' },
  ready: { id: 'taskStatus.ready', defaultMessage: 'Ready to work' },
  readyForReview: { id: 'taskStatus.readyForReview', defaultMessage: 'Ready for review' },
  finishedWithErrors: {
    id: 'taskStatus.finishedWithErrors',
    defaultMessage: 'Needs attention',
  },
  finishedWithErrorsDetail: {
    id: 'taskStatus.finishedWithErrorsDetail',
    defaultMessage: 'One or more protected actions failed.',
  },
  modelSlow: { id: 'taskStatus.modelSlow', defaultMessage: 'Still working' },
  modelSlowDetail: {
    id: 'taskStatus.modelSlowDetail',
    defaultMessage: 'Taking longer than usual.',
  },
  runtimeUnavailable: {
    id: 'taskStatus.runtimeUnavailable',
    defaultMessage: 'Actions paused',
  },
  runtimeUnavailableDetail: {
    id: 'taskStatus.runtimeUnavailableDetail',
    defaultMessage: 'AccordLock is reconnecting.',
  },
  modelFailed: { id: 'taskStatus.modelFailed', defaultMessage: 'Model request failed' },
  modelFailedDetail: {
    id: 'taskStatus.modelFailedDetail',
    defaultMessage: 'Nothing ran after the failure.',
  },
  approvalRequired: {
    id: 'taskStatus.approvalRequired',
    defaultMessage: 'Approval needed',
  },
  approvalDetail: {
    id: 'taskStatus.approvalDetail',
    defaultMessage: 'Review the requested action.',
  },
  reviewResults: {
    id: 'taskStatus.reviewResults',
    defaultMessage: 'Check results',
  },
  locked: { id: 'taskStatus.locked', defaultMessage: 'Task stopped' },
  taskReviewRequired: {
    id: 'taskStatus.taskReviewRequired',
    defaultMessage: 'Confirm task access to begin.',
  },
  activity: { id: 'taskStatus.activity', defaultMessage: 'Audit trail' },
  activityCount: {
    id: 'taskStatus.activityCount',
    defaultMessage: '{count, plural, one {# record} other {# records}}',
  },
  exportFailure: { id: 'taskStatus.exportFailure', defaultMessage: 'Couldn’t export audit trail' },
  exportFailureDetail: {
    id: 'taskStatus.exportFailureDetail',
    defaultMessage: 'Try again after the current action finishes.',
  },
  restoreFailure: { id: 'taskStatus.restoreFailure', defaultMessage: 'Couldn’t restore file' },
  restoreFailureDetail: {
    id: 'taskStatus.restoreFailureDetail',
    defaultMessage: 'The file was not restored. Check task access and try again.',
  },
  restored: { id: 'taskStatus.restored', defaultMessage: 'File restored' },
  restoredDetail: {
    id: 'taskStatus.restoredDetail',
    defaultMessage: '{path} was restored from its saved copy.',
  },
  alreadyRestored: {
    id: 'taskStatus.alreadyRestored',
    defaultMessage: 'File already restored',
  },
  alreadyRestoredDetail: {
    id: 'taskStatus.alreadyRestoredDetail',
    defaultMessage: '{path} is already back in place.',
  },
  stopAndLock: { id: 'taskStatus.stopAndLock', defaultMessage: 'Stop task' },
  stopping: { id: 'taskStatus.stopping', defaultMessage: 'Stopping…' },
  expires: { id: 'taskStatus.expires', defaultMessage: 'Access ends in {duration}' },
  restorableChanges: {
    id: 'taskStatus.restorableChanges',
    defaultMessage: '{count, plural, one {# file can be restored} other {# files can be restored}}',
  },
  protection: { id: 'taskStatus.protection', defaultMessage: 'Protection' },
  protectionOn: {
    id: 'taskStatus.protectionOn',
    defaultMessage: 'On',
  },
  protectionPending: {
    id: 'taskStatus.protectionPending',
    defaultMessage: 'Pending',
  },
  protectionOff: {
    id: 'taskStatus.protectionOff',
    defaultMessage: 'Off',
  },
  goalLocked: { id: 'taskStatus.goalLocked', defaultMessage: 'Goal locked' },
  goalLockedDetail: {
    id: 'taskStatus.goalLockedDetail',
    defaultMessage: 'The approved task goal is fixed for this run.',
  },
  accessScoped: { id: 'taskStatus.accessScoped', defaultMessage: 'Access scoped' },
  accessScopedDetail: {
    id: 'taskStatus.accessScopedDetail',
    defaultMessage: 'Folder, tools, and protected paths stay fixed.',
  },
  stateChecked: { id: 'taskStatus.stateChecked', defaultMessage: 'State checked' },
  stateCheckedDetail: {
    id: 'taskStatus.stateCheckedDetail',
    defaultMessage: 'The target is checked again before a protected action runs.',
  },
  stateCheckReady: { id: 'taskStatus.stateCheckReady', defaultMessage: 'State check ready' },
  stateCheckReadyDetail: {
    id: 'taskStatus.stateCheckReadyDetail',
    defaultMessage: 'The target will be checked before a protected action runs.',
  },
  executionRecorded: {
    id: 'taskStatus.executionRecorded',
    defaultMessage: 'Execution recorded',
  },
  executionRecordedDetail: {
    id: 'taskStatus.executionRecordedDetail',
    defaultMessage:
      '{count, plural, one {# action has a verification record.} other {# actions have verification records.}}',
  },
  noResultYet: { id: 'taskStatus.noResultYet', defaultMessage: 'No result yet' },
  noResultYetDetail: {
    id: 'taskStatus.noResultYetDetail',
    defaultMessage: 'No protected action has run.',
  },
  resultNeedsReview: {
    id: 'taskStatus.resultNeedsReview',
    defaultMessage: 'Result needs review',
  },
  resultNeedsReviewDetail: {
    id: 'taskStatus.resultNeedsReviewDetail',
    defaultMessage: 'Some protected activity could not be verified.',
  },
});

export type TaskStatusPanelProps = {
  authorization: AccordLockTaskAuthorizationState;
  expiresAt: number | null;
  expiresIn: string | null;
  isBusy: boolean;
  isModelSlow: boolean;
  modelFailed: boolean;
  isStopping: boolean;
  objective: string;
  onStopAndLock: () => void;
  pendingDecision: boolean;
  report: TaskReport;
  runtimeUnavailable: boolean;
  sessionId: string;
  taskApproved: boolean;
  taskBridge?: Pick<AccordLockTaskBridge, 'restoreDeletedFile'> &
    Partial<Pick<AccordLockTaskBridge, 'getTaskAudit'>>;
  workspace: string;
};

export function deriveTaskRestoreCapabilities(
  report: TaskReport,
  taskAccessActive: boolean
): TaskRestoreCapability[] {
  if (!taskAccessActive) return [];
  const seenRecoveryIds = new Set<string>();
  const capabilities: TaskRestoreCapability[] = [];
  for (const evidence of report.evidence) {
    if (
      evidence.operation !== 'DELETE' ||
      evidence.outcome !== 'SUCCEEDED' ||
      evidence.reasonCode.includes('UNKNOWN') ||
      !evidence.recovery ||
      seenRecoveryIds.has(evidence.recovery.recoveryId)
    ) {
      continue;
    }
    seenRecoveryIds.add(evidence.recovery.recoveryId);
    capabilities.push({
      contentHash: evidence.recovery.contentHash,
      recordId: evidence.recordId,
      recoveryId: evidence.recovery.recoveryId,
      recoveryPath: evidence.recovery.recoveryPath,
    });
  }
  return capabilities;
}

function StatusIcon({ kind }: { kind: 'danger' | 'success' | 'waiting' }): ReactNode {
  if (kind === 'danger') return <CircleAlert aria-hidden="true" className="size-4" />;
  if (kind === 'success') return <CircleCheck aria-hidden="true" className="size-4" />;
  return <Clock3 aria-hidden="true" className="size-4" />;
}

export function TaskStatusPanel({
  authorization,
  expiresAt,
  expiresIn,
  isBusy,
  isModelSlow,
  modelFailed,
  isStopping,
  objective,
  onStopAndLock,
  pendingDecision,
  report,
  runtimeUnavailable,
  sessionId,
  taskApproved,
  taskBridge,
  workspace,
}: TaskStatusPanelProps) {
  const intl = useIntl();
  const activeTaskBridge = useMemo(() => taskBridge ?? createAccordLockTaskBridge(), [taskBridge]);
  const [restoreAcknowledgements, setRestoreAcknowledgements] = useState<
    AccordLockTaskRestoreAck[]
  >([]);
  const [restoringRecoveryId, setRestoringRecoveryId] = useState<string | null>(null);
  const [runtimeAuditPage, setRuntimeAuditPage] = useState<AccordLockSessionAuditPage | null>(null);
  const restoringRecoveryIdRef = useRef<string | null>(null);
  const auditDetailsRef = useRef<ComponentRef<'details'>>(null);
  const taskAccessActive = authorization === 'APPROVED' && taskApproved;
  const restoreCapabilities = useMemo(
    () => deriveTaskRestoreCapabilities(report, taskAccessActive),
    [report, taskAccessActive]
  );
  const sessionRestoreAcknowledgements = useMemo(
    () =>
      restoreAcknowledgements.filter((acknowledgement) => acknowledgement.session_id === sessionId),
    [restoreAcknowledgements, sessionId]
  );
  const restoredRecoveryIds = useMemo(
    () =>
      new Set(
        sessionRestoreAcknowledgements
          .filter((acknowledgement) => acknowledgement.status !== 'CANCELLED')
          .map((acknowledgement) => acknowledgement.recovery_id)
      ),
    [sessionRestoreAcknowledgements]
  );
  const latestEvidenceRecordId = report.evidence[report.evidence.length - 1]?.recordId ?? null;

  useEffect(() => {
    let cancelled = false;
    let requestInFlight = false;
    setRuntimeAuditPage(null);
    const getTaskAudit = activeTaskBridge.getTaskAudit;
    if (authorization === 'PENDING' || !getTaskAudit || runtimeUnavailable) {
      return () => {
        cancelled = true;
      };
    }
    const refresh = async () => {
      if (cancelled || requestInFlight) return;
      requestInFlight = true;
      try {
        const page = await readAccordLockTaskAuditPage(sessionId, 0, 100, { getTaskAudit });
        if (!cancelled) setRuntimeAuditPage(page);
      } catch {
        // The task-record projection remains available. Private runtime errors are not rendered.
      } finally {
        requestInFlight = false;
      }
    };
    void refresh();
    const polling = isBusy ? window.setInterval(() => void refresh(), 1_000) : null;
    return () => {
      cancelled = true;
      if (polling !== null) window.clearInterval(polling);
    };
  }, [
    activeTaskBridge,
    authorization,
    isBusy,
    latestEvidenceRecordId,
    pendingDecision,
    runtimeUnavailable,
    sessionId,
  ]);
  const status = runtimeUnavailable
    ? {
        title: intl.formatMessage(i18n.runtimeUnavailable),
        detail: intl.formatMessage(i18n.runtimeUnavailableDetail),
        kind: 'danger' as const,
      }
    : modelFailed
      ? {
          title: intl.formatMessage(i18n.modelFailed),
          detail: intl.formatMessage(i18n.modelFailedDetail),
          kind: 'danger' as const,
        }
      : pendingDecision
        ? {
            title: intl.formatMessage(i18n.approvalRequired),
            detail: intl.formatMessage(i18n.approvalDetail),
            kind: 'waiting' as const,
          }
        : report.integrity === 'NEEDS_CONFIRMATION'
          ? {
              title: intl.formatMessage(i18n.reviewResults),
              detail: taskStatusCopyForReason('EXECUTION_UNKNOWN').nextStep,
              kind: 'danger' as const,
            }
          : isModelSlow
            ? {
                title: intl.formatMessage(i18n.modelSlow),
                detail: intl.formatMessage(i18n.modelSlowDetail),
                kind: 'waiting' as const,
              }
            : isBusy
              ? {
                  title: intl.formatMessage(i18n.active),
                  detail: null,
                  kind: 'waiting' as const,
                }
              : taskApproved && report.evidence.length > 0 && report.failedActions > 0
                ? {
                    title: intl.formatMessage(i18n.finishedWithErrors),
                    detail: intl.formatMessage(i18n.finishedWithErrorsDetail),
                    kind: 'danger' as const,
                  }
                : taskApproved && report.evidence.length > 0
                  ? {
                      title: intl.formatMessage(i18n.readyForReview),
                      detail: null,
                      kind: 'success' as const,
                    }
                  : taskApproved
                    ? {
                        title: intl.formatMessage(i18n.ready),
                        detail: null,
                        kind: 'success' as const,
                      }
                    : authorization === 'PENDING'
                      ? {
                          title: intl.formatMessage(i18n.approvalRequired),
                          detail: intl.formatMessage(i18n.taskReviewRequired),
                          kind: 'waiting' as const,
                        }
                      : {
                          title: intl.formatMessage(i18n.locked),
                          detail: null,
                          kind: 'danger' as const,
                        };

  const taskRecordTimeline = useMemo(
    () =>
      buildTaskAuditTimeline({
        authorization,
        expiresAt,
        historyScope: 'TASK_RECORDS_ONLY',
        objective,
        pendingDecision,
        report,
        requestedAt: null,
        restoreAcknowledgements: sessionRestoreAcknowledgements,
        restoreCapabilities,
        revocation: null,
        sessionId,
        workspace,
      }),
    [
      authorization,
      expiresAt,
      objective,
      pendingDecision,
      report,
      restoreCapabilities,
      sessionId,
      sessionRestoreAcknowledgements,
      workspace,
    ]
  );
  const timeline = useMemo(
    () =>
      runtimeAuditPage
        ? mergeRuntimeAuditPage(taskRecordTimeline, runtimeAuditPage)
        : taskRecordTimeline,
    [runtimeAuditPage, taskRecordTimeline]
  );
  const executionChecks = [
    {
      detail: intl.formatMessage(i18n.goalLockedDetail),
      ready: taskAccessActive,
      title: intl.formatMessage(i18n.goalLocked),
      warning: false,
    },
    {
      detail: intl.formatMessage(i18n.accessScopedDetail),
      ready: taskAccessActive,
      title: intl.formatMessage(i18n.accessScoped),
      warning: false,
    },
    {
      detail: intl.formatMessage(
        report.evidence.length > 0 ? i18n.stateCheckedDetail : i18n.stateCheckReadyDetail
      ),
      ready: taskAccessActive && report.evidence.length > 0,
      title: intl.formatMessage(
        report.evidence.length > 0 ? i18n.stateChecked : i18n.stateCheckReady
      ),
      warning: false,
    },
    report.integrity === 'VERIFIED'
      ? {
          detail: intl.formatMessage(i18n.executionRecordedDetail, {
            count: report.evidence.length,
          }),
          ready: true,
          title: intl.formatMessage(i18n.executionRecorded),
          warning: false,
        }
      : report.integrity === 'NEEDS_CONFIRMATION'
        ? {
            detail: intl.formatMessage(i18n.resultNeedsReviewDetail),
            ready: false,
            title: intl.formatMessage(i18n.resultNeedsReview),
            warning: true,
          }
        : {
            detail: intl.formatMessage(i18n.noResultYetDetail),
            ready: false,
            title: intl.formatMessage(i18n.noResultYet),
            warning: false,
          },
  ];

  const restoreDeletedFile = async (request: TaskRestoreRequest) => {
    if (!taskAccessActive || restoringRecoveryIdRef.current !== null) {
      if (!taskAccessActive) {
        toastError({
          title: intl.formatMessage(i18n.restoreFailure),
          msg: intl.formatMessage(i18n.restoreFailureDetail),
        });
      }
      return;
    }

    restoringRecoveryIdRef.current = request.recoveryId;
    setRestoringRecoveryId(request.recoveryId);
    try {
      const acknowledgement = await restoreAccordLockDeletedFile(
        sessionId,
        request.recoveryId,
        activeTaskBridge
      );
      setRestoreAcknowledgements((current) => [...current, acknowledgement]);
      if (acknowledgement.status === 'RESTORED') {
        toastSuccess({
          title: intl.formatMessage(i18n.restored),
          msg: intl.formatMessage(i18n.restoredDetail, {
            path: acknowledgement.record.relative_path,
          }),
        });
      } else if (acknowledgement.status === 'ALREADY_RESTORED') {
        toastSuccess({
          title: intl.formatMessage(i18n.alreadyRestored),
          msg: intl.formatMessage(i18n.alreadyRestoredDetail, {
            path: acknowledgement.record.relative_path,
          }),
        });
      }
    } catch {
      toastError({
        title: intl.formatMessage(i18n.restoreFailure),
        msg: intl.formatMessage(i18n.restoreFailureDetail),
      });
    } finally {
      if (restoringRecoveryIdRef.current === request.recoveryId) {
        restoringRecoveryIdRef.current = null;
        setRestoringRecoveryId(null);
      }
    }
  };

  const exportActivity = async (format: TaskAuditExportFormat) => {
    try {
      const safeSessionId = sessionId.replace(/[^a-zA-Z0-9._-]+/gu, '-').slice(0, 48) || 'task';
      const markdown = format === 'markdown';
      let content: string;
      if (markdown) {
        content = formatTaskReportMarkdown(objective, report, sessionRestoreAcknowledgements);
      } else if (runtimeAuditPage && activeTaskBridge.getTaskAudit) {
        const pages = await readAllAccordLockTaskAuditPages(
          sessionId,
          { getTaskAudit: activeTaskBridge.getTaskAudit },
          runtimeAuditPage
        );
        content = formatRuntimeTaskAuditExport(
          mergeRuntimeAuditPages(taskRecordTimeline, pages),
          pages
        );
      } else {
        content = formatTaskAuditExport(timeline);
      }
      await window.electron.saveAuditFile(
        markdown
          ? `accordlock-${safeSessionId}.report.md`
          : `accordlock-${safeSessionId}.audit.json`,
        content
      );
    } catch {
      toastError({
        title: intl.formatMessage(i18n.exportFailure),
        msg: intl.formatMessage(i18n.exportFailureDetail),
      });
    }
  };

  return (
    <section
      aria-label={intl.formatMessage(i18n.task)}
      data-testid="task-status-panel"
      className="mx-4 mb-2 mt-12 rounded-2xl border border-border-secondary bg-background-primary/95 px-4 py-3 shadow-sm"
    >
      <div className="flex min-w-0 flex-col items-stretch justify-between gap-3 sm:flex-row sm:items-start">
        <div className="flex min-w-0 items-start gap-3">
          <AccordLockGlyph
            className="mt-0.5 size-8 shrink-0 rounded-xl shadow-none"
            active={taskApproved}
          />
          <div className="min-w-0">
            <div className="text-[11px] font-semibold uppercase tracking-[0.14em] text-text-tertiary">
              {intl.formatMessage(i18n.task)}
            </div>
            <h2 className="truncate text-sm font-semibold text-text-primary" title={objective}>
              {objective || intl.formatMessage(i18n.taskFallback)}
            </h2>
            <div className="mt-0.5 flex flex-wrap gap-x-3 text-xs text-text-secondary">
              <span>{intl.formatMessage(i18n.workspace, { workspace })}</span>
              {expiresIn && (
                <span>{intl.formatMessage(i18n.expires, { duration: expiresIn })}</span>
              )}
              {timeline.reversibleCount > 0 && (
                <button
                  type="button"
                  className="font-medium text-text-primary underline decoration-border-primary underline-offset-2 outline-none hover:decoration-text-primary focus-visible:ring-2 focus-visible:ring-ring"
                  onClick={() => {
                    if (!auditDetailsRef.current) return;
                    auditDetailsRef.current.open = true;
                    auditDetailsRef.current.scrollIntoView({
                      behavior: 'smooth',
                      block: 'nearest',
                    });
                  }}
                >
                  {intl.formatMessage(i18n.restorableChanges, {
                    count: timeline.reversibleCount,
                  })}
                </button>
              )}
            </div>
          </div>
        </div>

        <div className="flex shrink-0 items-center justify-end gap-2">
          <div
            role="status"
            className={cn(
              'flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium',
              status.kind === 'danger' && 'bg-red-500/10 text-red-700 dark:text-red-300',
              status.kind === 'waiting' && 'bg-amber-500/10 text-amber-700 dark:text-amber-300',
              status.kind === 'success' && 'bg-green-500/10 text-green-700 dark:text-green-300'
            )}
          >
            <StatusIcon kind={status.kind} />
            <span>{status.title}</span>
          </div>
          {taskApproved && (
            <button
              type="button"
              onClick={onStopAndLock}
              disabled={isStopping}
              className="flex items-center gap-1.5 rounded-lg border border-border-secondary px-2.5 py-1 text-xs font-medium text-text-secondary outline-none transition-colors hover:bg-background-secondary hover:text-text-primary focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50"
            >
              <Square aria-hidden="true" className="size-3" fill="currentColor" />
              {intl.formatMessage(isStopping ? i18n.stopping : i18n.stopAndLock)}
            </button>
          )}
        </div>
      </div>

      {status.detail && <p className="mt-2 text-xs text-text-secondary">{status.detail}</p>}

      <details className="mt-2 text-xs" data-testid="task-protection">
        <summary className="flex cursor-pointer list-none items-center gap-2 rounded-lg py-1 text-text-secondary outline-none hover:text-text-primary focus-visible:ring-2 focus-visible:ring-ring [&::-webkit-details-marker]:hidden">
          <ShieldCheck aria-hidden="true" className="size-3.5" />
          <span className="font-medium">{intl.formatMessage(i18n.protection)}</span>
          <span aria-hidden="true">·</span>
          <span>
            {intl.formatMessage(
              taskAccessActive
                ? i18n.protectionOn
                : authorization === 'PENDING'
                  ? i18n.protectionPending
                  : i18n.protectionOff
            )}
          </span>
        </summary>
        <div className="mt-2 grid gap-2 rounded-xl border border-border-secondary bg-background-secondary/35 p-3 sm:grid-cols-2">
          {executionChecks.map((check) => (
            <div className="flex min-w-0 items-start gap-2" key={check.title}>
              {check.warning ? (
                <CircleAlert
                  aria-hidden="true"
                  className="mt-0.5 size-3.5 shrink-0 text-amber-700 dark:text-amber-300"
                />
              ) : check.ready ? (
                <CircleCheck
                  aria-hidden="true"
                  className="mt-0.5 size-3.5 shrink-0 text-green-700 dark:text-green-300"
                />
              ) : (
                <Clock3
                  aria-hidden="true"
                  className="mt-0.5 size-3.5 shrink-0 text-text-tertiary"
                />
              )}
              <div className="min-w-0">
                <div className="font-medium text-text-primary">{check.title}</div>
                <p className="mt-0.5 leading-4 text-text-tertiary">{check.detail}</p>
              </div>
            </div>
          ))}
        </div>
      </details>

      <details ref={auditDetailsRef} className="mt-2 text-xs" data-testid="task-activity">
        <summary className="flex cursor-pointer list-none items-center gap-2 rounded-lg py-1 text-text-secondary outline-none hover:text-text-primary focus-visible:ring-2 focus-visible:ring-ring [&::-webkit-details-marker]:hidden">
          <Activity aria-hidden="true" className="size-3.5" />
          <span className="font-medium">{intl.formatMessage(i18n.activity)}</span>
          <span aria-hidden="true">·</span>
          <span>
            {intl.formatMessage(i18n.activityCount, {
              count: timeline.events.length,
            })}
          </span>
        </summary>
        <TaskAuditTimeline
          className="mt-3"
          embedded
          timeline={timeline}
          onExport={(format) => void exportActivity(format)}
          onRestore={(request) => void restoreDeletedFile(request)}
          restoredRecoveryIds={restoredRecoveryIds}
          restoringRecoveryId={restoringRecoveryId}
        />
      </details>
    </section>
  );
}
