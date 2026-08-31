import {
  AlertCircle,
  AlertTriangle,
  Ban,
  Check,
  ChevronDown,
  Clock3,
  Download,
  FileClock,
  FileJson,
  FileText,
  Filter,
  LoaderCircle,
  RefreshCw,
  Search,
} from 'lucide-react';
import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import {
  DEFAULT_GLOBAL_AUDIT_FILTERS,
  filterGlobalAuditRecords,
  formatGlobalAuditJson,
  formatGlobalAuditMarkdown,
  loadGlobalAuditDataset,
  type GlobalAuditDataset,
  type GlobalAuditFilters,
  type GlobalAuditRecord,
  type GlobalAuditRecordStatus,
} from '../../accordlock/globalAudit';
import { cn } from '../../utils';
import { formatMessageTimestamp } from '../../utils/timeUtils';
import { MainPanelLayout } from '../Layout/MainPanelLayout';
import { Button } from '../ui/button';
import { TaskControlBadge } from './IntentControlBadge';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../ui/dropdown-menu';
import { Input } from '../ui/input';
import { Skeleton } from '../ui/skeleton';

const INITIAL_VISIBLE_RECORDS = 100;

export type GlobalAuditExportFormat = 'json' | 'markdown';

export type GlobalAuditViewProps = {
  loadAudit?: () => Promise<GlobalAuditDataset>;
  nowSeconds?: () => number;
  onOpenTask?: ((sessionId: string) => void) | null;
  saveAuditFile?: (
    suggestedName: string,
    content: string
  ) => Promise<{ canceled?: boolean; saved?: boolean } | unknown>;
};

function defaultSaveAuditFile(
  suggestedName: string,
  content: string
): Promise<{ canceled: boolean; saved: boolean }> {
  return window.electron.saveAuditFile(suggestedName, content);
}

function isSaveResult(value: unknown): value is { canceled?: boolean; saved?: boolean } {
  return typeof value === 'object' && value !== null;
}

function statusLabel(status: GlobalAuditRecordStatus): string {
  if (status === 'VERIFIED') return 'Recorded';
  if (status === 'PENDING') return 'In progress';
  if (status === 'BLOCKED') return 'Blocked';
  return 'Needs review';
}

function StatusIcon({ status }: { status: GlobalAuditRecordStatus }): ReactNode {
  if (status === 'VERIFIED') return <Check aria-hidden="true" className="size-3.5" />;
  if (status === 'PENDING') return <Clock3 aria-hidden="true" className="size-3.5" />;
  if (status === 'BLOCKED') return <Ban aria-hidden="true" className="size-3.5" />;
  return <AlertTriangle aria-hidden="true" className="size-3.5" />;
}

function statusClasses(status: GlobalAuditRecordStatus): string {
  if (status === 'VERIFIED') {
    return 'border-green-500/25 bg-green-500/10 text-green-700 dark:text-green-300';
  }
  if (status === 'PENDING') {
    return 'border-blue-500/25 bg-blue-500/10 text-blue-700 dark:text-blue-300';
  }
  if (status === 'BLOCKED') {
    return 'border-red-500/25 bg-red-500/10 text-red-700 dark:text-red-300';
  }
  return 'border-amber-500/30 bg-amber-500/10 text-amber-800 dark:text-amber-300';
}

function AuditRecordRow({
  onOpenTask,
  record,
}: {
  onOpenTask: ((sessionId: string) => void) | null;
  record: GlobalAuditRecord;
}) {
  return (
    <details className="group border-b border-border-secondary last:border-b-0">
      <summary className="flex cursor-pointer list-none items-start gap-3 px-4 py-3.5 outline-none transition-colors hover:bg-background-secondary/35 focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring [&::-webkit-details-marker]:hidden">
        <span
          className={cn(
            'mt-0.5 flex size-7 shrink-0 items-center justify-center rounded-full border',
            statusClasses(record.status)
          )}
          aria-label={statusLabel(record.status)}
          title={statusLabel(record.status)}
        >
          <StatusIcon status={record.status} />
        </span>
        <span className="min-w-0 flex-1">
          <span className="flex min-w-0 flex-col gap-1 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
            <span className="flex min-w-0 flex-wrap items-center gap-2">
              <span className="truncate text-sm font-medium text-text-primary">{record.title}</span>
              {record.taskControl && <TaskControlBadge value={record.taskControl} />}
            </span>
            <time
              dateTime={new Date(record.timestamp * 1_000).toISOString()}
              className="shrink-0 text-[11px] text-text-tertiary"
            >
              {formatMessageTimestamp(record.timestamp)}
            </time>
          </span>
          <span className="mt-0.5 block truncate text-xs text-text-secondary">
            {record.taskName} · {record.projectName}
          </span>
          <span className="mt-1 block text-xs leading-5 text-text-tertiary">{record.summary}</span>
        </span>
        <ChevronDown
          aria-hidden="true"
          className="mt-1 size-4 shrink-0 text-text-tertiary transition-transform group-open:rotate-180"
        />
      </summary>
      <div className="border-t border-border-secondary bg-background-secondary/25 px-4 py-4 pl-14">
        <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-2">
          <div className="min-w-0">
            <dt className="text-[10px] font-medium uppercase tracking-[0.1em] text-text-tertiary">
              Workspace
            </dt>
            <dd className="mt-1 break-all text-xs text-text-secondary">{record.workspace}</dd>
          </div>
          <div className="min-w-0">
            <dt className="text-[10px] font-medium uppercase tracking-[0.1em] text-text-tertiary">
              Event
            </dt>
            <dd className="mt-1 font-mono text-[11px] text-text-secondary">{record.event.type}</dd>
          </div>
          {record.details.map((detail) => (
            <div className="min-w-0" key={`${record.id}:${detail.label}`}>
              <dt className="text-[10px] font-medium uppercase tracking-[0.1em] text-text-tertiary">
                {detail.label}
              </dt>
              <dd className="mt-1 break-all font-mono text-[11px] leading-4 text-text-secondary">
                {detail.value}
              </dd>
            </div>
          ))}
        </dl>
        {onOpenTask && (
          <Button
            className="mt-4"
            size="sm"
            variant="outline"
            onClick={() => onOpenTask(record.sessionId)}
          >
            Open task
          </Button>
        )}
      </div>
    </details>
  );
}

function FilterSelect({
  label,
  onChange,
  value,
  children,
}: {
  label: string;
  onChange: (value: string) => void;
  value: string;
  children: ReactNode;
}) {
  return (
    <label className="space-y-1.5">
      <span className="block text-[11px] font-medium text-text-secondary">{label}</span>
      <select
        aria-label={label}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="h-9 w-full rounded-lg border border-border-primary bg-background-primary px-2.5 text-sm text-text-primary outline-none transition-colors hover:border-border-secondary focus:border-border-secondary focus-visible:ring-2 focus-visible:ring-ring"
      >
        {children}
      </select>
    </label>
  );
}

function LoadingView() {
  return (
    <div aria-label="Loading audit" className="space-y-3">
      <Skeleton className="h-20 w-full rounded-2xl" />
      <Skeleton className="h-12 w-full rounded-xl" />
      <Skeleton className="h-64 w-full rounded-2xl" />
    </div>
  );
}

function ExportMenu({
  disabled,
  exporting,
  onExport,
}: {
  disabled: boolean;
  exporting: boolean;
  onExport: (format: GlobalAuditExportFormat) => void;
}) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" disabled={disabled || exporting}>
          {exporting ? (
            <LoaderCircle aria-hidden="true" className="animate-spin" />
          ) : (
            <Download aria-hidden="true" />
          )}
          {exporting ? 'Exporting…' : 'Export all'}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-48">
        <DropdownMenuItem onSelect={() => onExport('markdown')}>
          <FileText aria-hidden="true" />
          Readable report (.md)
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={() => onExport('json')}>
          <FileJson aria-hidden="true" />
          Audit bundle (.json)
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export default function GlobalAuditView({
  loadAudit = loadGlobalAuditDataset,
  nowSeconds = () => Math.floor(Date.now() / 1_000),
  onOpenTask = null,
  saveAuditFile = defaultSaveAuditFile,
}: GlobalAuditViewProps) {
  const [dataset, setDataset] = useState<GlobalAuditDataset | null>(null);
  const [filters, setFilters] = useState<GlobalAuditFilters>(DEFAULT_GLOBAL_AUDIT_FILTERS);
  const [filterPanelOpen, setFilterPanelOpen] = useState(false);
  const [loadError, setLoadError] = useState(false);
  const [loading, setLoading] = useState(true);
  const [exportState, setExportState] = useState<'IDLE' | 'SAVING' | 'SAVED' | 'FAILED'>('IDLE');
  const [visibleRecords, setVisibleRecords] = useState(INITIAL_VISIBLE_RECORDS);

  const refresh = useCallback(async () => {
    setLoading(true);
    setLoadError(false);
    try {
      const nextDataset = await loadAudit();
      setDataset(nextDataset);
    } catch {
      setLoadError(true);
    } finally {
      setLoading(false);
    }
  }, [loadAudit]);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setLoadError(false);
    void loadAudit()
      .then((nextDataset) => {
        if (active) setDataset(nextDataset);
      })
      .catch(() => {
        if (active) setLoadError(true);
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [loadAudit]);

  const filteredRecords = useMemo(
    () => filterGlobalAuditRecords(dataset?.records ?? [], filters, nowSeconds()),
    [dataset, filters, nowSeconds]
  );
  const displayedRecords = filteredRecords.slice(0, visibleRecords);
  const projectOptions = useMemo(() => {
    if (!dataset) return [];
    const names = new Map(dataset.projects.map((project) => [project.id, project.title]));
    for (const session of dataset.sessions) {
      if (session.projectId && !names.has(session.projectId)) {
        const fallback = dataset.records.find((record) => record.projectId === session.projectId);
        names.set(session.projectId, fallback?.projectName ?? session.projectId);
      }
    }
    return [...names].sort((left, right) => left[1].localeCompare(right[1]));
  }, [dataset]);
  const taskOptions = useMemo(
    () =>
      [...(dataset?.sessions ?? [])].sort((left, right) =>
        (left.name.trim() || 'Untitled task').localeCompare(right.name.trim() || 'Untitled task')
      ),
    [dataset]
  );

  useEffect(() => setVisibleRecords(INITIAL_VISIBLE_RECORDS), [filters]);

  const updateFilter = <Key extends keyof GlobalAuditFilters>(
    key: Key,
    value: GlobalAuditFilters[Key]
  ) => setFilters((current) => ({ ...current, [key]: value }));

  const selectedFilterCount = [
    filters.projectId !== 'ALL',
    filters.sessionId !== 'ALL',
    filters.status !== 'ALL',
    filters.time !== 'ALL',
  ].filter(Boolean).length;
  const unavailableCount =
    dataset?.readIssues.filter((issue) => issue.code !== 'NO_HISTORY').length ?? 0;
  const noHistoryCount =
    dataset?.readIssues.filter((issue) => issue.code === 'NO_HISTORY').length ?? 0;
  const reviewCount = dataset?.records.filter((record) => record.status === 'WARNING').length ?? 0;
  const blockedCount = dataset?.records.filter((record) => record.status === 'BLOCKED').length ?? 0;
  const attentionSummary = [
    reviewCount > 0 ? `${reviewCount} to review` : null,
    blockedCount > 0 ? `${blockedCount} blocked` : null,
  ]
    .filter((value): value is string => value !== null)
    .join(' · ');
  const coverageNotices = [
    unavailableCount > 0
      ? `${unavailableCount} ${unavailableCount === 1 ? "task history couldn't" : "task histories couldn't"} be opened here.`
      : null,
    dataset && !dataset.projectCatalogAvailable
      ? 'Project names are unavailable. Task history is still shown.'
      : null,
  ].filter((value): value is string => value !== null);

  const exportAudit = async (format: GlobalAuditExportFormat) => {
    if (!dataset || exportState === 'SAVING') return;
    setExportState('SAVING');
    try {
      const date = new Date(dataset.generatedAt * 1_000).toISOString().replace(/[:.]/gu, '-');
      const markdown = format === 'markdown';
      const result = await saveAuditFile(
        `accordlock-audit-${date}.${markdown ? 'md' : 'json'}`,
        markdown ? formatGlobalAuditMarkdown(dataset) : formatGlobalAuditJson(dataset)
      );
      if (isSaveResult(result) && result.canceled) {
        setExportState('IDLE');
        return;
      }
      if (isSaveResult(result) && result.saved === false) {
        throw new Error('Audit export was not saved');
      }
      setExportState('SAVED');
    } catch {
      setExportState('FAILED');
    }
  };

  const renderContent = () => {
    if (loading) return <LoadingView />;
    if (loadError || !dataset) {
      return (
        <div className="flex min-h-[320px] flex-col items-center justify-center text-center">
          <AlertCircle className="mb-4 size-9 text-text-tertiary" />
          <h2 className="text-lg font-medium text-text-primary">Audit could not be loaded</h2>
          <p className="mt-1 text-sm text-text-secondary">Try again in a moment.</p>
          <Button className="mt-5" variant="outline" onClick={() => void refresh()}>
            Try again
          </Button>
        </div>
      );
    }

    if (dataset.sessions.length === 0) {
      return (
        <div className="flex min-h-[320px] flex-col items-center justify-center text-center">
          <span className="mb-4 rounded-2xl border border-border-secondary bg-background-secondary/45 p-3">
            <FileClock className="size-6 text-text-secondary" />
          </span>
          <h2 className="text-lg font-medium text-text-primary">No tasks yet</h2>
          <p className="mt-1 text-sm text-text-secondary">Recorded activity will appear here.</p>
        </div>
      );
    }

    return (
      <>
        <section className="rounded-2xl border border-border-secondary bg-background-primary px-5 py-4">
          <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
            <strong className="text-2xl font-light tracking-[-0.025em] text-text-primary">
              {dataset.records.length}
            </strong>
            <span className="text-sm text-text-secondary">
              {dataset.records.length === 1 ? 'protected event' : 'protected events'} across{' '}
              {dataset.taskBundles.length}{' '}
              {dataset.taskBundles.length === 1 ? 'protected task' : 'protected tasks'}
            </span>
            {attentionSummary && (
              <span className="text-xs text-text-tertiary">· {attentionSummary}</span>
            )}
          </div>
        </section>

        {coverageNotices.length > 0 && (
          <div
            role="status"
            className="mt-3 flex items-start gap-2 rounded-xl border border-amber-500/25 bg-amber-500/10 px-3.5 py-3 text-xs leading-5 text-amber-900 dark:text-amber-200"
          >
            <AlertTriangle aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
            <p>{coverageNotices.join(' ')}</p>
          </div>
        )}

        <section className="mt-4">
          <div className="flex flex-col gap-2 sm:flex-row">
            <label className="relative min-w-0 flex-1">
              <span className="sr-only">Search audit</span>
              <Search
                aria-hidden="true"
                className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-text-tertiary"
              />
              <Input
                value={filters.query}
                onChange={(event) => updateFilter('query', event.target.value)}
                placeholder="Search tasks, projects, actions…"
                className="pl-9"
              />
            </label>
            <Button
              variant={filterPanelOpen || selectedFilterCount > 0 ? 'secondary' : 'outline'}
              size="sm"
              aria-expanded={filterPanelOpen}
              onClick={() => setFilterPanelOpen((open) => !open)}
            >
              <Filter aria-hidden="true" />
              Filters{selectedFilterCount > 0 ? ` · ${selectedFilterCount}` : ''}
            </Button>
          </div>

          {filterPanelOpen && (
            <div className="mt-2 grid gap-3 rounded-xl border border-border-secondary bg-background-secondary/25 p-3 sm:grid-cols-2 lg:grid-cols-4">
              <FilterSelect
                label="Status"
                value={filters.status}
                onChange={(value) => updateFilter('status', value as GlobalAuditFilters['status'])}
              >
                <option value="ALL">Any status</option>
                <option value="VERIFIED">Recorded</option>
                <option value="PENDING">In progress</option>
                <option value="BLOCKED">Blocked</option>
                <option value="WARNING">Needs review</option>
              </FilterSelect>
              <FilterSelect
                label="Project"
                value={filters.projectId}
                onChange={(value) => updateFilter('projectId', value)}
              >
                <option value="ALL">Any project</option>
                <option value="UNASSIGNED">No project</option>
                {projectOptions.map(([id, name]) => (
                  <option key={id} value={id}>
                    {name}
                  </option>
                ))}
              </FilterSelect>
              <FilterSelect
                label="Task"
                value={filters.sessionId}
                onChange={(value) => updateFilter('sessionId', value)}
              >
                <option value="ALL">Any task</option>
                {taskOptions.map((task) => (
                  <option key={task.id} value={task.id}>
                    {task.name.trim() || 'Untitled task'}
                  </option>
                ))}
              </FilterSelect>
              <FilterSelect
                label="Time"
                value={filters.time}
                onChange={(value) => updateFilter('time', value as GlobalAuditFilters['time'])}
              >
                <option value="ALL">Any time</option>
                <option value="24_HOURS">Last 24 hours</option>
                <option value="7_DAYS">Last 7 days</option>
                <option value="30_DAYS">Last 30 days</option>
              </FilterSelect>
              {selectedFilterCount > 0 && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="justify-self-start px-0 sm:col-span-2 lg:col-span-4"
                  onClick={() =>
                    setFilters((current) => ({
                      ...DEFAULT_GLOBAL_AUDIT_FILTERS,
                      query: current.query,
                    }))
                  }
                >
                  Clear filters
                </Button>
              )}
            </div>
          )}
        </section>

        {filteredRecords.length > 0 ? (
          <section className="mt-3 overflow-hidden rounded-2xl border border-border-secondary bg-background-primary">
            {displayedRecords.map((record) => (
              <AuditRecordRow key={record.id} record={record} onOpenTask={onOpenTask} />
            ))}
            {displayedRecords.length < filteredRecords.length && (
              <div className="flex justify-center border-t border-border-secondary px-4 py-3">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setVisibleRecords((count) => count + INITIAL_VISIBLE_RECORDS)}
                >
                  Show more
                </Button>
              </div>
            )}
          </section>
        ) : (
          <div className="flex min-h-56 flex-col items-center justify-center text-center">
            <Search className="mb-3 size-6 text-text-tertiary" />
            <h2 className="text-sm font-medium text-text-primary">
              {dataset.records.length === 0 ? 'No protected activity yet' : 'No matching events'}
            </h2>
            <p className="mt-1 text-xs text-text-secondary">
              {dataset.records.length === 0
                ? 'Start a protected task to record approvals and actions here.'
                : 'Change the search or filters.'}
            </p>
          </div>
        )}

        {noHistoryCount > 0 && (
          <p className="py-4 text-center text-[11px] text-text-tertiary">
            {noHistoryCount} {noHistoryCount === 1 ? 'task has' : 'tasks have'} no protected
            activity.
          </p>
        )}
      </>
    );
  };

  return (
    <MainPanelLayout>
      <div className="flex min-h-0 flex-1 flex-col">
        <header className="px-8 pb-6 pt-12">
          <div className="mx-auto flex w-full max-w-[980px] items-start justify-between gap-6">
            <div>
              <h1 className="text-4xl font-light tracking-[-0.035em] text-text-primary">Audit</h1>
              <p className="mt-2 text-sm text-text-secondary">
                Protected approvals and actions across tasks.
              </p>
            </div>
            <div className="flex items-center gap-2">
              {exportState === 'SAVED' && (
                <span role="status" className="text-xs text-text-secondary">
                  Saved
                </span>
              )}
              {exportState === 'FAILED' && (
                <span role="alert" className="text-xs text-text-danger">
                  Export failed
                </span>
              )}
              <Button
                variant="ghost"
                size="sm"
                shape="round"
                aria-label="Refresh audit"
                disabled={loading}
                onClick={() => void refresh()}
              >
                <RefreshCw aria-hidden="true" className={cn(loading && 'animate-spin')} />
              </Button>
              <ExportMenu
                disabled={!dataset || dataset.records.length === 0}
                exporting={exportState === 'SAVING'}
                onExport={(format) => void exportAudit(format)}
              />
            </div>
          </div>
        </header>

        <div className="min-h-0 flex-1 overflow-y-auto px-8">
          <div className="mx-auto w-full max-w-[980px] pb-10">{renderContent()}</div>
        </div>
      </div>
    </MainPanelLayout>
  );
}
