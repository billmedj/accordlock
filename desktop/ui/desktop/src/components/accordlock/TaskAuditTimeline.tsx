import {
  Activity,
  AlertTriangle,
  Ban,
  Check,
  ChevronDown,
  Clock3,
  Download,
  FileClock,
  FileJson,
  FileText,
  LoaderCircle,
  RotateCcw,
  ShieldCheck,
} from 'lucide-react';
import { useMemo, useState, type ReactNode } from 'react';
import {
  filterTaskAuditEvents,
  type AuditEventStatus,
  type AuditFilter,
  type AuditReversibility,
  type TaskAuditEvent,
  type TaskAuditTimeline as TaskAuditTimelineModel,
  type TaskRestoreRequest,
} from '../../accordlock/auditTimeline';
import { cn } from '../../utils';
import { formatMessageTimestamp } from '../../utils/timeUtils';
import { TaskControlBadge } from './IntentControlBadge';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../ui/dropdown-menu';

const FILTERS: readonly { id: AuditFilter; label: string }[] = [
  { id: 'ALL', label: 'All' },
  { id: 'DECISIONS', label: 'Decisions' },
  { id: 'CHANGES', label: 'Changes' },
  { id: 'ISSUES', label: 'Issues' },
];

export type TaskAuditTimelineProps = {
  className?: string;
  embedded?: boolean;
  onExport?: ((format: TaskAuditExportFormat) => void) | null;
  onRestore?: ((request: TaskRestoreRequest) => void) | null;
  restoredRecoveryIds?: ReadonlySet<string>;
  restoringRecoveryId?: string | null;
  timeline: TaskAuditTimelineModel;
};

export type TaskAuditExportFormat = 'json' | 'markdown';

function ExportMenu({
  className,
  onExport,
}: {
  className?: string;
  onExport: (format: TaskAuditExportFormat) => void;
}) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          className={cn(
            'inline-flex items-center justify-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-medium text-text-secondary outline-none transition-colors hover:bg-background-secondary hover:text-text-primary focus-visible:ring-2 focus-visible:ring-ring',
            className
          )}
        >
          <Download aria-hidden="true" className="size-3.5" />
          Export
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-40">
        <DropdownMenuItem onSelect={() => onExport('markdown')}>
          <FileText aria-hidden="true" />
          Task report (.md)
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={() => onExport('json')}>
          <FileJson aria-hidden="true" />
          Audit data (.json)
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function StatusIcon({ status }: { status: AuditEventStatus }): ReactNode {
  if (status === 'VERIFIED') return <Check aria-hidden="true" className="size-3.5" />;
  if (status === 'WARNING' || status === 'FAILED') {
    return <AlertTriangle aria-hidden="true" className="size-3.5" />;
  }
  if (status === 'BLOCKED') return <Ban aria-hidden="true" className="size-3.5" />;
  if (status === 'PENDING') return <Clock3 aria-hidden="true" className="size-3.5" />;
  return <Activity aria-hidden="true" className="size-3.5" />;
}

function statusClasses(status: AuditEventStatus): string {
  if (status === 'VERIFIED')
    return 'border-green-500/25 bg-green-500/10 text-green-700 dark:text-green-300';
  if (status === 'WARNING' || status === 'FAILED') {
    return 'border-amber-500/30 bg-amber-500/10 text-amber-800 dark:text-amber-300';
  }
  if (status === 'BLOCKED') return 'border-red-500/25 bg-red-500/10 text-red-700 dark:text-red-300';
  if (status === 'PENDING')
    return 'border-blue-500/25 bg-blue-500/10 text-blue-700 dark:text-blue-300';
  return 'border-border-secondary bg-background-secondary text-text-secondary';
}

function reversibilityClasses(status: AuditReversibility['status']): string {
  if (status === 'RESTORABLE') {
    return 'border-green-500/25 bg-green-500/10 text-green-700 dark:text-green-300';
  }
  if (status === 'RECOVERY_COPY') {
    return 'border-blue-500/25 bg-blue-500/10 text-blue-700 dark:text-blue-300';
  }
  if (status === 'UNKNOWN') {
    return 'border-amber-500/25 bg-amber-500/10 text-amber-800 dark:text-amber-300';
  }
  return 'border-border-secondary bg-background-secondary text-text-tertiary';
}

function ReversibilityBadge({ value }: { value: AuditReversibility }) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium',
        reversibilityClasses(value.status)
      )}
      title={value.explanation}
    >
      {value.label}
    </span>
  );
}

function EventDetails({ event }: { event: TaskAuditEvent }) {
  return (
    <div className="grid gap-3 border-t border-border-secondary px-4 py-3 sm:grid-cols-2">
      {event.details.map((section) => (
        <section key={section.label} aria-label={section.label}>
          <h4 className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.12em] text-text-tertiary">
            {section.label}
          </h4>
          <dl className="space-y-1.5">
            {section.details.map((detail) => (
              <div key={`${section.label}:${detail.label}`} className="min-w-0">
                <dt className="text-[11px] text-text-tertiary">{detail.label}</dt>
                <dd
                  className="break-all font-mono text-[11px] leading-4 text-text-secondary"
                  title={detail.value}
                >
                  {detail.value}
                </dd>
              </div>
            ))}
          </dl>
        </section>
      ))}
    </div>
  );
}

function AuditEventRow({
  event,
  onRestore,
  restoredRecoveryIds,
  restoringRecoveryId,
}: {
  event: TaskAuditEvent;
  onRestore: ((request: TaskRestoreRequest) => void) | null;
  restoredRecoveryIds: ReadonlySet<string>;
  restoringRecoveryId: string | null;
}) {
  const restoreRequest =
    event.reversibility?.status === 'RESTORABLE' ? event.reversibility.request : null;
  const restoreComplete = Boolean(
    restoreRequest && restoredRecoveryIds.has(restoreRequest.recoveryId)
  );
  const restoreInFlight = Boolean(
    restoreRequest && restoringRecoveryId === restoreRequest.recoveryId
  );
  return (
    <li className="relative pl-8" data-audit-kind={event.kind}>
      <span
        className={cn(
          'absolute left-0 top-3.5 z-10 flex size-6 items-center justify-center rounded-full border',
          statusClasses(event.status)
        )}
      >
        <StatusIcon status={event.status} />
      </span>
      <details className="group overflow-hidden rounded-xl border border-border-secondary bg-background-primary transition-colors open:bg-background-secondary/25">
        <summary className="flex cursor-pointer list-none items-start gap-3 px-4 py-3 outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring [&::-webkit-details-marker]:hidden">
          <div className="min-w-0 flex-1">
            <div className="flex min-w-0 flex-wrap items-center gap-2">
              <h3
                className="min-w-0 truncate text-sm font-medium text-text-primary"
                title={event.title}
              >
                {event.title}
              </h3>
              {event.taskControl && <TaskControlBadge value={event.taskControl} />}
              {event.reversibility && <ReversibilityBadge value={event.reversibility} />}
            </div>
            <p className="mt-0.5 text-xs text-text-secondary">{event.summary}</p>
            <div className="mt-1 flex items-center gap-2 text-[10px] text-text-tertiary">
              <span>{event.source}</span>
              {event.timestamp !== null && (
                <>
                  <span aria-hidden="true">·</span>
                  <time dateTime={new Date(event.timestamp * 1_000).toISOString()}>
                    {formatMessageTimestamp(event.timestamp)}
                  </time>
                </>
              )}
            </div>
          </div>
          <ChevronDown
            aria-hidden="true"
            className="mt-1 size-4 shrink-0 text-text-tertiary transition-transform group-open:rotate-180"
          />
        </summary>
        <EventDetails event={event} />
        {restoreRequest && onRestore && (
          <div className="flex items-center justify-between gap-3 border-t border-border-secondary px-4 py-3">
            <p className="text-xs text-text-secondary">
              {restoreComplete
                ? 'Restored from the saved copy.'
                : 'The current file will be checked before restore.'}
            </p>
            {restoreComplete ? (
              <span className="inline-flex shrink-0 items-center gap-1.5 text-xs font-medium text-green-700 dark:text-green-300">
                <Check aria-hidden="true" className="size-3.5" />
                Restored
              </span>
            ) : (
              <button
                type="button"
                onClick={() => onRestore(restoreRequest)}
                disabled={restoreInFlight}
                className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-border-secondary bg-background-primary px-3 py-1.5 text-xs font-medium text-text-primary outline-none transition-colors hover:bg-background-secondary focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-wait disabled:opacity-60"
              >
                {restoreInFlight ? (
                  <LoaderCircle aria-hidden="true" className="size-3.5 animate-spin" />
                ) : (
                  <RotateCcw aria-hidden="true" className="size-3.5" />
                )}
                {restoreInFlight ? 'Restoring…' : 'Restore…'}
              </button>
            )}
          </div>
        )}
      </details>
    </li>
  );
}

export function TaskAuditTimeline({
  className,
  embedded = false,
  onExport,
  onRestore,
  restoredRecoveryIds = new Set<string>(),
  restoringRecoveryId = null,
  timeline,
}: TaskAuditTimelineProps) {
  const [filter, setFilter] = useState<AuditFilter>('ALL');
  const events = useMemo(
    () => filterTaskAuditEvents(timeline.events, filter),
    [filter, timeline.events]
  );
  const summary = [
    `${timeline.verifiedActionCount} recorded ${timeline.verifiedActionCount === 1 ? 'action' : 'actions'}`,
    timeline.issueCount > 0
      ? `${timeline.issueCount} ${timeline.issueCount === 1 ? 'issue' : 'issues'}`
      : null,
    timeline.reversibleCount > 0
      ? `${timeline.reversibleCount} restorable ${timeline.reversibleCount === 1 ? 'change' : 'changes'}`
      : null,
  ]
    .filter(Boolean)
    .join(' · ');

  return (
    <section
      className={cn(
        !embedded && 'rounded-2xl border border-border-secondary bg-background-primary',
        className
      )}
    >
      {!embedded && (
        <header className="flex flex-col gap-3 border-b border-border-secondary px-4 py-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="flex min-w-0 items-start gap-3">
            <span className="flex size-9 shrink-0 items-center justify-center rounded-xl bg-background-secondary text-text-secondary">
              <FileClock aria-hidden="true" className="size-[18px]" />
            </span>
            <div className="min-w-0">
              <h2 className="text-base font-semibold text-text-primary">Audit trail</h2>
              <p className="mt-0.5 text-xs text-text-secondary">{summary}</p>
            </div>
          </div>
          {onExport && <ExportMenu className="self-start" onExport={onExport} />}
        </header>
      )}

      <div
        className={cn(
          'flex flex-wrap items-center justify-between gap-2 px-4 py-3',
          embedded && 'rounded-t-xl border border-border-secondary bg-background-primary'
        )}
      >
        <div className="flex items-center gap-1" aria-label="Audit filters">
          {FILTERS.map((item) => (
            <button
              key={item.id}
              type="button"
              aria-pressed={filter === item.id}
              onClick={() => setFilter(item.id)}
              className={cn(
                'rounded-lg px-2.5 py-1 text-xs outline-none transition-colors focus-visible:ring-2 focus-visible:ring-ring',
                filter === item.id
                  ? 'bg-background-secondary font-medium text-text-primary'
                  : 'text-text-secondary hover:text-text-primary'
              )}
            >
              {item.label}
            </button>
          ))}
        </div>
        {embedded && onExport && <ExportMenu className="py-1" onExport={onExport} />}
      </div>

      <div
        className={cn(
          'mx-4 flex items-start gap-2 rounded-lg bg-background-secondary/60 px-3 py-2 text-[11px] leading-4 text-text-secondary',
          embedded && 'mt-3'
        )}
      >
        <ShieldCheck aria-hidden="true" className="mt-0.5 size-3.5 shrink-0" />
        <p>{timeline.scopeNotice}</p>
      </div>

      {events.length > 0 ? (
        <ol
          className={cn(
            'relative mx-4 my-4 space-y-2 before:absolute before:bottom-3 before:left-[11px] before:top-3 before:w-px before:bg-border-secondary',
            embedded && 'mb-0'
          )}
        >
          {events.map((event) => (
            <AuditEventRow
              key={event.id}
              event={event}
              onRestore={onRestore ?? null}
              restoredRecoveryIds={restoredRecoveryIds}
              restoringRecoveryId={restoringRecoveryId}
            />
          ))}
        </ol>
      ) : (
        <div className="px-4 py-10 text-center">
          <p className="text-sm font-medium text-text-primary">No matching activity</p>
          <p className="mt-1 text-xs text-text-secondary">Choose another filter.</p>
        </div>
      )}
    </section>
  );
}
