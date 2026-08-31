import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import type {
  AccordLockSessionAuditEvent,
  AccordLockSessionAuditPage,
} from '../../accordlockRuntime';
import type { GlobalAuditDataset, GlobalAuditRecord } from '../../accordlock/globalAudit';
import type { SessionListItem } from '../../acp/sessions';
import GlobalAuditView from './GlobalAuditView';

vi.mock('../Layout/MainPanelLayout', () => ({
  MainPanelLayout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

const hash = (character: string) => `sha256:${character.repeat(64)}`;

function task(): SessionListItem {
  return {
    id: 'session-1',
    name: 'Release review',
    workingDir: 'C:\\Work\\Release',
    updatedAt: '2026-08-29T10:00:00Z',
    createdAt: '2026-08-29T09:00:00Z',
    messageCount: 4,
    projectId: 'public-release',
  };
}

const deniedEvent: AccordLockSessionAuditEvent = {
  event_id: 'denied-1',
  recorded_at: 1_799_999_900,
  type: 'ACTION_DENIED',
  denial_id: 1,
  attempted_run_id: hash('a'),
  tool_call_id: 'call-1',
  proposal_digest: hash('b'),
  reason_code: 'PATH_OUTSIDE_WORKSPACE',
};

const approvedEvent: AccordLockSessionAuditEvent = {
  event_id: 'approved-1',
  recorded_at: 1_799_999_800,
  type: 'SESSION_APPROVED',
  task_id: '11111111-1111-4111-8111-111111111111',
  run_id: hash('a'),
  workspace_root: 'C:\\Work\\Release',
  policy_hash: hash('c'),
  expires_at: 1_800_003_600,
};

function page(): AccordLockSessionAuditPage {
  return {
    schema_version: 6,
    task_id: '11111111-1111-4111-8111-111111111111',
    session_id: 'session-1',
    run_id: hash('a'),
    offset: 0,
    next_offset: null,
    total_events: 2,
    snapshot_revision: 5,
    snapshot_at: 1_800_000_000,
    events: [deniedEvent, approvedEvent],
    page_digest: hash('d'),
  };
}

function record(
  event: AccordLockSessionAuditEvent,
  overrides: Partial<GlobalAuditRecord> = {}
): GlobalAuditRecord {
  return {
    category: 'EXECUTION',
    details: [{ label: 'Tool call', value: 'call-1' }],
    event,
    id: `session-1:${event.event_id}`,
    projectId: 'public-release',
    projectName: 'Public release',
    runId: hash('a'),
    sessionId: 'session-1',
    status: 'BLOCKED',
    summary: 'Path outside workspace',
    taskId: '11111111-1111-4111-8111-111111111111',
    taskName: 'Release review',
    timestamp: event.recorded_at,
    title: 'Action blocked',
    workspace: 'C:\\Work\\Release',
    ...overrides,
  };
}

function dataset(overrides: Partial<GlobalAuditDataset> = {}): GlobalAuditDataset {
  const session = task();
  return {
    generatedAt: 1_800_000_000,
    projectCatalogAvailable: true,
    projects: [{ id: 'public-release', title: 'Public release', archived: false }],
    records: [
      record(deniedEvent),
      record(approvedEvent, {
        category: 'ACCESS',
        status: 'VERIFIED',
        summary: 'Task access was granted.',
        title: 'Access approved',
      }),
    ],
    readIssues: [],
    sessions: [session],
    taskBundles: [
      {
        projectId: 'public-release',
        projectName: 'Public release',
        runtimePages: [page()],
        sessionId: session.id,
        taskId: '11111111-1111-4111-8111-111111111111',
        taskName: session.name,
        workspace: session.workingDir,
      },
    ],
    ...overrides,
  };
}

beforeAll(() => {
  Object.defineProperty(globalThis.Element.prototype, 'hasPointerCapture', {
    configurable: true,
    value: vi.fn(() => false),
  });
  Object.defineProperty(globalThis.Element.prototype, 'setPointerCapture', {
    configurable: true,
    value: vi.fn(),
  });
  Object.defineProperty(globalThis.Element.prototype, 'releasePointerCapture', {
    configurable: true,
    value: vi.fn(),
  });
});

describe('GlobalAuditView', () => {
  beforeEach(() => vi.clearAllMocks());

  it('loads a compact cross-task trail and reveals filters on demand', async () => {
    const user = userEvent.setup();
    render(
      <GlobalAuditView
        loadAudit={vi.fn().mockResolvedValue(dataset())}
        nowSeconds={() => 1_800_000_000}
      />
    );

    expect(await screen.findByText('protected events across 1 protected task')).toBeVisible();
    expect(screen.getByText('Action blocked')).toBeVisible();
    expect(screen.getByText('Access approved')).toBeVisible();
    expect(screen.queryByLabelText('Status')).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Filters' }));
    await user.selectOptions(screen.getByLabelText('Status'), 'BLOCKED');

    expect(screen.getByText('Action blocked')).toBeVisible();
    expect(screen.queryByText('Access approved')).not.toBeInTheDocument();

    await user.type(screen.getByPlaceholderText('Search tasks, projects, actions…'), 'missing');
    expect(screen.getByText('No matching events')).toBeVisible();
  });

  it('exports the complete loaded snapshot in both formats', async () => {
    const saveAuditFile = vi.fn().mockResolvedValue({ saved: true, canceled: false });
    const user = userEvent.setup();
    render(
      <GlobalAuditView
        loadAudit={vi.fn().mockResolvedValue(dataset())}
        nowSeconds={() => 1_800_000_000}
        saveAuditFile={saveAuditFile}
      />
    );
    await screen.findByText('Action blocked');

    await user.click(screen.getByRole('button', { name: 'Export all' }));
    await user.click(screen.getByRole('menuitem', { name: 'Audit bundle (.json)' }));
    await waitFor(() => expect(saveAuditFile).toHaveBeenCalledTimes(1));
    expect(saveAuditFile.mock.calls[0]?.[0]).toMatch(/^accordlock-audit-.*\.json$/u);
    expect(JSON.parse(saveAuditFile.mock.calls[0]?.[1])).toMatchObject({
      recordType: 'accordlock.global-audit-bundle',
      coverage: { recordedEvents: 2 },
    });

    await user.click(screen.getByRole('button', { name: 'Export all' }));
    await user.click(screen.getByRole('menuitem', { name: 'Readable report (.md)' }));
    await waitFor(() => expect(saveAuditFile).toHaveBeenCalledTimes(2));
    expect(saveAuditFile.mock.calls[1]?.[1]).toContain('# AccordLock audit report');
  });

  it('recovers from a load failure without exposing internal errors', async () => {
    const loadAudit = vi
      .fn()
      .mockRejectedValueOnce(new Error('secret internal path'))
      .mockResolvedValueOnce(dataset());
    const user = userEvent.setup();
    render(<GlobalAuditView loadAudit={loadAudit} nowSeconds={() => 1_800_000_000} />);

    expect(await screen.findByText('Audit could not be loaded')).toBeVisible();
    expect(screen.queryByText('secret internal path')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Try again' }));

    expect(await screen.findByText('Action blocked')).toBeVisible();
    expect(loadAudit).toHaveBeenCalledTimes(2);
  });

  it('separates no history from a protected history that could not be read', async () => {
    const state = dataset({
      records: [],
      taskBundles: [],
      readIssues: [
        {
          code: 'NO_HISTORY',
          projectId: 'public-release',
          projectName: 'Public release',
          sessionId: 'session-1',
          taskName: 'Release review',
          workspace: 'C:\\Work\\Release',
        },
        {
          code: 'OUTSIDE_WINDOW',
          projectId: null,
          projectName: 'No project',
          sessionId: 'session-2',
          taskName: 'Other task',
          workspace: 'D:\\Work\\Other',
        },
      ],
      sessions: [task(), { ...task(), id: 'session-2', name: 'Other task' }],
    });
    render(
      <GlobalAuditView
        loadAudit={vi.fn().mockResolvedValue(state)}
        nowSeconds={() => 1_800_000_000}
      />
    );

    expect(await screen.findByText("1 task history couldn't be opened here.")).toBeVisible();
    expect(screen.getByText('1 task has no protected activity.')).toBeVisible();
    expect(screen.getByText('No protected activity yet')).toBeVisible();
  });
});
