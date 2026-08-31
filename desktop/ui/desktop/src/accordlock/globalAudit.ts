import type { AccordLockSessionAuditEvent, AccordLockSessionAuditPage } from '../accordlockRuntime';
import type { TaskControlProjection } from './intentControl';
import { projectCompletedTaskControl, projectDeniedTaskControl } from './intentControl';
import { listProjects, type AccordLockProject } from '../acp/projects';
import { acpListSessions, type SessionListItem, type SessionListPage } from '../acp/sessions';
import {
  createAccordLockTaskBridge,
  readAllAccordLockTaskAuditPages,
  type AccordLockTaskBridge,
} from './taskBridge';

const MAX_SESSION_PAGES = 1_000;
const MAX_SESSIONS = 10_000;
const AUDIT_READ_CONCURRENCY = 4;

export type GlobalAuditRecordStatus = 'VERIFIED' | 'PENDING' | 'BLOCKED' | 'WARNING';
export type GlobalAuditStatusFilter = 'ALL' | GlobalAuditRecordStatus;
export type GlobalAuditTimeFilter = 'ALL' | '24_HOURS' | '7_DAYS' | '30_DAYS';

export type GlobalAuditReadIssueCode = 'NO_HISTORY' | 'OUTSIDE_WINDOW' | 'UNAVAILABLE';

export type GlobalAuditDetail = {
  label: string;
  value: string;
};

export type GlobalAuditRecord = {
  category: 'ACCESS' | 'APPROVAL' | 'EXECUTION' | 'RECOVERY';
  details: GlobalAuditDetail[];
  event: AccordLockSessionAuditEvent;
  id: string;
  taskControl?: TaskControlProjection;
  projectId: string | null;
  projectName: string;
  runId: string;
  sessionId: string;
  status: GlobalAuditRecordStatus;
  summary: string;
  taskId: string;
  taskName: string;
  timestamp: number;
  title: string;
  workspace: string;
};

export type GlobalAuditTaskBundle = {
  projectId: string | null;
  projectName: string;
  runtimePages: AccordLockSessionAuditPage[];
  sessionId: string;
  taskId: string;
  taskName: string;
  workspace: string;
};

export type GlobalAuditReadIssue = {
  code: GlobalAuditReadIssueCode;
  projectId: string | null;
  projectName: string;
  sessionId: string;
  taskName: string;
  workspace: string;
};

export type GlobalAuditDataset = {
  generatedAt: number;
  projectCatalogAvailable: boolean;
  projects: Pick<AccordLockProject, 'id' | 'title' | 'archived'>[];
  records: GlobalAuditRecord[];
  readIssues: GlobalAuditReadIssue[];
  sessions: SessionListItem[];
  taskBundles: GlobalAuditTaskBundle[];
};

export type GlobalAuditFilters = {
  projectId: 'ALL' | 'UNASSIGNED' | string;
  query: string;
  sessionId: 'ALL' | string;
  status: GlobalAuditStatusFilter;
  time: GlobalAuditTimeFilter;
};

export type GlobalAuditDependencies = {
  listProjects: () => Promise<AccordLockProject[]>;
  listSessions: (cursor?: string | null) => Promise<SessionListPage>;
  nowSeconds: () => number;
  readTaskAuditPages: (sessionId: string) => Promise<AccordLockSessionAuditPage[]>;
};

export const DEFAULT_GLOBAL_AUDIT_FILTERS: GlobalAuditFilters = {
  projectId: 'ALL',
  query: '',
  sessionId: 'ALL',
  status: 'ALL',
  time: 'ALL',
};

function defaultDependencies(): GlobalAuditDependencies {
  const bridge = createAccordLockTaskBridge();
  return {
    listProjects,
    listSessions: acpListSessions,
    nowSeconds: () => Math.floor(Date.now() / 1_000),
    readTaskAuditPages: (sessionId) =>
      readAllAccordLockTaskAuditPages(sessionId, {
        getTaskAudit: bridge.getTaskAudit,
      } satisfies Pick<AccordLockTaskBridge, 'getTaskAudit'>),
  };
}

function readableIdentifier(value: string): string {
  const words = value.replace(/[-_]+/gu, ' ').trim();
  if (!words) return 'Project';
  return words.charAt(0).toLocaleUpperCase('en-US') + words.slice(1);
}

function taskName(session: SessionListItem): string {
  return session.name.trim() || 'Untitled task';
}

function projectName(
  session: SessionListItem,
  projectsById: ReadonlyMap<string, Pick<AccordLockProject, 'title'>>
): string {
  if (!session.projectId) return 'No project';
  return projectsById.get(session.projectId)?.title ?? readableIdentifier(session.projectId);
}

function sessionFingerprint(session: SessionListItem): string {
  return JSON.stringify([
    session.id,
    session.name,
    session.workingDir,
    session.updatedAt,
    session.createdAt,
    session.projectId ?? null,
    session.archivedAt ?? null,
  ]);
}

export async function listAllGlobalAuditSessions(
  listSessions: GlobalAuditDependencies['listSessions'] = acpListSessions
): Promise<SessionListItem[]> {
  const sessions: SessionListItem[] = [];
  const fingerprints = new Map<string, string>();
  const seenCursors = new Set<string>();
  let cursor: string | null | undefined;

  for (let pageNumber = 0; pageNumber < MAX_SESSION_PAGES; pageNumber += 1) {
    const page = await listSessions(cursor);
    for (const session of page.sessions) {
      const fingerprint = sessionFingerprint(session);
      const previous = fingerprints.get(session.id);
      if (previous && previous !== fingerprint) {
        throw new Error('The task list changed while the audit was loaded. Try again.');
      }
      if (!previous) {
        fingerprints.set(session.id, fingerprint);
        sessions.push(session);
      }
    }
    if (sessions.length > MAX_SESSIONS) {
      throw new Error('The task list is too large to load safely.');
    }

    cursor = page.nextCursor;
    if (!cursor) return sessions;
    if (seenCursors.has(cursor)) {
      throw new Error('The task list returned a repeated page. Try again.');
    }
    seenCursors.add(cursor);
  }

  throw new Error('The task list has too many pages to load safely.');
}

function classifyReadIssue(error: unknown): GlobalAuditReadIssueCode {
  const message = error instanceof Error ? error.message : '';
  if (/audit binding is unavailable/iu.test(message)) return 'NO_HISTORY';
  if (/different (?:workspace|window)/iu.test(message)) return 'OUTSIDE_WINDOW';
  return 'UNAVAILABLE';
}

async function mapWithConcurrency<Input, Output>(
  inputs: readonly Input[],
  concurrency: number,
  mapper: (input: Input) => Promise<Output>
): Promise<Output[]> {
  const outputs = new Array<Output>(inputs.length);
  let nextIndex = 0;

  const workers = Array.from({ length: Math.min(concurrency, inputs.length) }, async () => {
    while (nextIndex < inputs.length) {
      const index = nextIndex;
      nextIndex += 1;
      outputs[index] = await mapper(inputs[index]);
    }
  });
  await Promise.all(workers);
  return outputs;
}

type ProjectedEvent = Pick<
  GlobalAuditRecord,
  'category' | 'details' | 'taskControl' | 'status' | 'summary' | 'title'
>;

function intentStatusLabel(status: 'VERIFIED' | 'REVIEW_REQUIRED' | 'BLOCKED'): string {
  if (status === 'VERIFIED') return 'Verified';
  if (status === 'BLOCKED') return 'Blocked';
  return 'Not verified';
}

function projectEvent(
  event: AccordLockSessionAuditEvent,
  toolsByAuthorization: ReadonlyMap<string, string>,
  completedAuthorizationIds: ReadonlySet<string>,
  completedRestoreIds: ReadonlySet<string>
): ProjectedEvent {
  switch (event.type) {
    case 'SESSION_APPROVED':
      return {
        category: 'ACCESS',
        details: [
          { label: 'Run ID', value: event.run_id },
          { label: 'Policy hash', value: event.policy_hash },
          { label: 'Access ends', value: new Date(event.expires_at * 1_000).toISOString() },
        ],
        status: 'VERIFIED',
        summary: 'Task access was granted.',
        title: 'Access approved',
      };
    case 'SESSION_REVOKED':
      return {
        category: 'ACCESS',
        details: [
          { label: 'Run ID', value: event.run_id },
          { label: 'Revocation hash', value: event.revocation_digest },
        ],
        status: 'BLOCKED',
        summary: 'Further actions were blocked.',
        title: 'Access revoked',
      };
    case 'ACTION_DECISION':
      return {
        category: 'APPROVAL',
        details: [
          { label: 'Approval ID', value: event.approval_id },
          { label: 'Tool call', value: event.tool_call_id },
          { label: 'Proposal hash', value: event.proposal_digest },
          { label: 'Evidence hash', value: event.evidence_hash },
          { label: 'Used', value: event.consumed ? 'Yes' : 'No' },
        ],
        status: event.decision === 'APPROVED' ? 'VERIFIED' : 'BLOCKED',
        summary: event.consumed ? 'The decision was used once.' : 'The decision was recorded.',
        title: event.decision === 'APPROVED' ? 'Action approved' : 'Action denied',
      };
    case 'ACTION_STARTED':
      return {
        category: 'EXECUTION',
        details: [
          { label: 'Authorization ID', value: event.authorization_id },
          { label: 'Tool call', value: event.tool_call_id },
          { label: 'Tool', value: `${event.extension_id}/${event.tool_name}` },
          { label: 'Proposal hash', value: event.proposal_digest },
          { label: 'Request hash', value: event.request_hash },
          { label: 'Task check', value: intentStatusLabel(event.intent_assessment.status) },
          { label: 'Evidence records', value: String(event.intent_assessment.evidence_count) },
        ],
        status: completedAuthorizationIds.has(event.authorization_id) ? 'VERIFIED' : 'PENDING',
        summary: completedAuthorizationIds.has(event.authorization_id)
          ? 'Execution began.'
          : 'Execution is in progress.',
        title: `Started · ${event.tool_name}`,
      };
    case 'ACTION_COMPLETED': {
      const tool = toolsByAuthorization.get(event.authorization_id);
      const uncertain = event.state === 'EXECUTION_UNKNOWN';
      const taskControl = projectCompletedTaskControl(event);
      return {
        category: 'EXECUTION',
        details: [
          { label: 'Authorization ID', value: event.authorization_id },
          { label: 'Tool call', value: event.tool_call_id },
          { label: 'Outcome', value: event.outcome },
          ...(event.record_hash ? [{ label: 'Record hash', value: event.record_hash }] : []),
          { label: 'Task scope', value: event.task_scope_status },
          { label: 'Review status', value: event.review_status },
          { label: 'Decision reason', value: event.decision_reason_code },
          { label: 'Task control hash', value: event.task_control_hash },
          { label: 'Control provenance', value: event.task_control_provenance },
          { label: 'Execution lineage', value: event.execution_lineage_hash },
          {
            label: 'Task check (before)',
            value: intentStatusLabel(event.intent_pre_assessment.status),
          },
          {
            label: 'Task check (after)',
            value: intentStatusLabel(event.intent_complete_assessment.status),
          },
        ],
        taskControl,
        status: uncertain ? 'WARNING' : 'VERIFIED',
        summary: uncertain
          ? `${taskControl.reason} The final state could not be confirmed.`
          : taskControl.reason,
        title: `${uncertain ? 'Review result' : 'Completed'}${tool ? ` · ${tool}` : ''}`,
      };
    }
    case 'ACTION_DENIED': {
      const taskControl = projectDeniedTaskControl(event.reason_code);
      return {
        category: 'EXECUTION',
        details: [
          { label: 'Denial ID', value: String(event.denial_id) },
          { label: 'Attempted run', value: event.attempted_run_id },
          { label: 'Tool call', value: event.tool_call_id },
          { label: 'Proposal hash', value: event.proposal_digest },
          { label: 'Reason code', value: event.reason_code },
        ],
        taskControl,
        status: 'BLOCKED',
        summary: taskControl.reason,
        title: taskControl.label,
      };
    }
    case 'RESTORE_PREPARED':
      return {
        category: 'RECOVERY',
        details: [
          { label: 'Restore ID', value: event.restore_id },
          { label: 'Recovery ID', value: event.recovery_id },
          { label: 'Content hash', value: event.content_hash },
        ],
        status: completedRestoreIds.has(event.restore_id) ? 'VERIFIED' : 'PENDING',
        summary: completedRestoreIds.has(event.restore_id)
          ? 'Restore checks passed.'
          : 'The saved copy passed its checks.',
        title: `Restore prepared · ${event.relative_path}`,
      };
    case 'RESTORE_COMPLETED':
      return {
        category: 'RECOVERY',
        details: [
          { label: 'Restore ID', value: event.restore_id },
          { label: 'Recovery ID', value: event.recovery_id },
          { label: 'Record hash', value: event.record_hash },
        ],
        status: 'VERIFIED',
        summary: 'The saved copy was restored.',
        title: `File restored · ${event.relative_path}`,
      };
  }
}

function recordsFromBundle(bundle: GlobalAuditTaskBundle): GlobalAuditRecord[] {
  const events = bundle.runtimePages.flatMap((page) => page.events);
  const toolsByAuthorization = new Map(
    events
      .filter(
        (event): event is Extract<AccordLockSessionAuditEvent, { type: 'ACTION_STARTED' }> =>
          event.type === 'ACTION_STARTED'
      )
      .map((event) => [event.authorization_id, event.tool_name])
  );
  const completedAuthorizationIds = new Set(
    events
      .filter((event) => event.type === 'ACTION_COMPLETED')
      .map((event) => event.authorization_id)
  );
  const completedRestoreIds = new Set(
    events.filter((event) => event.type === 'RESTORE_COMPLETED').map((event) => event.restore_id)
  );

  return events.map((event) => ({
    ...projectEvent(event, toolsByAuthorization, completedAuthorizationIds, completedRestoreIds),
    event,
    id: `${bundle.sessionId}:${event.event_id}`,
    projectId: bundle.projectId,
    projectName: bundle.projectName,
    runId: bundle.runtimePages[0].run_id,
    sessionId: bundle.sessionId,
    taskId: bundle.taskId,
    taskName: bundle.taskName,
    timestamp: event.recorded_at,
    workspace: bundle.workspace,
  }));
}

export async function loadGlobalAuditDataset(
  dependencies: GlobalAuditDependencies = defaultDependencies()
): Promise<GlobalAuditDataset> {
  const generatedAt = dependencies.nowSeconds();
  if (!Number.isSafeInteger(generatedAt) || generatedAt < 0) {
    throw new Error('The audit clock is unavailable.');
  }

  const projectsPromise = dependencies
    .listProjects()
    .then((projects) => ({ available: true, projects }))
    .catch(() => ({ available: false, projects: [] as AccordLockProject[] }));
  const sessions = await listAllGlobalAuditSessions(dependencies.listSessions);
  const projectResult = await projectsPromise;
  const projectsById = new Map(projectResult.projects.map((project) => [project.id, project]));

  const taskResults = await mapWithConcurrency(
    sessions,
    AUDIT_READ_CONCURRENCY,
    async (session): Promise<GlobalAuditTaskBundle | GlobalAuditReadIssue> => {
      const metadata = {
        projectId: session.projectId ?? null,
        projectName: projectName(session, projectsById),
        sessionId: session.id,
        taskName: taskName(session),
        workspace: session.workingDir,
      };
      try {
        const runtimePages = await dependencies.readTaskAuditPages(session.id);
        const first = runtimePages[0];
        if (!first || first.session_id !== session.id) {
          throw new Error('The protected audit did not match the task.');
        }
        return {
          ...metadata,
          runtimePages,
          taskId: first.task_id,
        };
      } catch (error) {
        return {
          ...metadata,
          code: classifyReadIssue(error),
        };
      }
    }
  );

  const taskBundles = taskResults.filter(
    (result): result is GlobalAuditTaskBundle => 'runtimePages' in result
  );
  const readIssues = taskResults.filter(
    (result): result is GlobalAuditReadIssue => 'code' in result
  );
  const records = taskBundles
    .flatMap(recordsFromBundle)
    .sort((left, right) => right.timestamp - left.timestamp || left.id.localeCompare(right.id));

  return {
    generatedAt,
    projectCatalogAvailable: projectResult.available,
    projects: projectResult.projects.map(({ id, title, archived }) => ({ id, title, archived })),
    records,
    readIssues,
    sessions,
    taskBundles,
  };
}

function timeWindowSeconds(filter: GlobalAuditTimeFilter): number | null {
  if (filter === '24_HOURS') return 24 * 60 * 60;
  if (filter === '7_DAYS') return 7 * 24 * 60 * 60;
  if (filter === '30_DAYS') return 30 * 24 * 60 * 60;
  return null;
}

function recordSearchText(record: GlobalAuditRecord): string {
  return [
    record.title,
    record.summary,
    record.taskName,
    record.projectName,
    record.workspace,
    record.sessionId,
    record.taskId,
    record.runId,
    record.event.type,
    ...record.details.flatMap((detail) => [detail.label, detail.value]),
  ]
    .join('\n')
    .replace(/[_-]+/gu, ' ')
    .toLocaleLowerCase('en-US');
}

export function filterGlobalAuditRecords(
  records: readonly GlobalAuditRecord[],
  filters: GlobalAuditFilters,
  nowSeconds: number
): GlobalAuditRecord[] {
  const query = filters.query.trim().toLocaleLowerCase('en-US');
  const windowSeconds = timeWindowSeconds(filters.time);
  const cutoff = windowSeconds === null ? null : nowSeconds - windowSeconds;

  return records.filter(
    (record) =>
      (filters.status === 'ALL' || record.status === filters.status) &&
      (filters.projectId === 'ALL' ||
        (filters.projectId === 'UNASSIGNED'
          ? record.projectId === null
          : record.projectId === filters.projectId)) &&
      (filters.sessionId === 'ALL' || record.sessionId === filters.sessionId) &&
      (cutoff === null || record.timestamp >= cutoff) &&
      (!query || recordSearchText(record).includes(query))
  );
}

function markdownText(value: string): string {
  return value
    .replace(/\r?\n/gu, ' ')
    .replace(/\\/gu, '\\\\')
    .replace(/([`*_{}[\]<>#+.!|])/gu, '\\$1');
}

function statusLabel(status: GlobalAuditRecordStatus): string {
  if (status === 'VERIFIED') return 'Recorded';
  if (status === 'PENDING') return 'In progress';
  if (status === 'BLOCKED') return 'Blocked';
  return 'Needs review';
}

export function formatGlobalAuditJson(dataset: GlobalAuditDataset): string {
  return `${JSON.stringify(
    {
      schemaVersion: 1,
      recordType: 'accordlock.global-audit-bundle',
      generatedAt: dataset.generatedAt,
      coverage: {
        sessionsFound: dataset.sessions.length,
        protectedHistories: dataset.taskBundles.length,
        recordedEvents: dataset.records.length,
        projectCatalogAvailable: dataset.projectCatalogAvailable,
        readIssues: dataset.readIssues,
      },
      tasks: dataset.taskBundles.map((bundle) => ({
        sessionId: bundle.sessionId,
        taskId: bundle.taskId,
        taskName: bundle.taskName,
        workspace: bundle.workspace,
        projectId: bundle.projectId,
        projectName: bundle.projectName,
        runtimePages: bundle.runtimePages,
      })),
    },
    null,
    2
  )}\n`;
}

export function formatGlobalAuditMarkdown(dataset: GlobalAuditDataset): string {
  const unavailableCount = dataset.readIssues.filter((issue) => issue.code !== 'NO_HISTORY').length;
  const lines = [
    '# AccordLock audit report',
    '',
    `Generated: ${new Date(dataset.generatedAt * 1_000).toISOString()}`,
    '',
    '## Coverage',
    '',
    `- Tasks found: ${dataset.sessions.length}`,
    `- Protected histories: ${dataset.taskBundles.length}`,
    `- Recorded events: ${dataset.records.length}`,
    `- Histories unavailable: ${unavailableCount}`,
    '',
  ];

  if (!dataset.projectCatalogAvailable) {
    lines.push('Project names were unavailable. Project identifiers are shown where possible.', '');
  }
  if (unavailableCount > 0) {
    lines.push('This report is incomplete because some protected histories could not be read.', '');
  }

  lines.push('## Events', '');
  if (dataset.records.length === 0) {
    lines.push('No protected events were found.', '');
  } else {
    for (const record of dataset.records) {
      lines.push(
        `### ${new Date(record.timestamp * 1_000).toISOString()} — ${markdownText(record.title)}`,
        '',
        `- Task: ${markdownText(record.taskName)}`,
        `- Project: ${markdownText(record.projectName)}`,
        `- Status: ${statusLabel(record.status)}`,
        `- Workspace: ${markdownText(record.workspace)}`,
        `- Session ID: ${markdownText(record.sessionId)}`,
        '',
        markdownText(record.summary),
        ''
      );
      for (const detail of record.details) {
        lines.push(`- ${markdownText(detail.label)}: ${markdownText(detail.value)}`);
      }
      lines.push('');
    }
  }

  return `${lines.join('\n').trimEnd()}\n`;
}
