import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { IntlTestWrapper } from '../../i18n/test-utils';
import type { TaskReport } from '../../accordlock/taskReport';
import { toastError, toastSuccess } from '../../toasts';
import {
  deriveTaskRestoreCapabilities,
  TaskStatusPanel,
  type TaskStatusPanelProps,
} from './TaskStatusPanel';

vi.mock('../../toasts', () => ({ toastError: vi.fn(), toastSuccess: vi.fn() }));

const report: TaskReport = {
  evidence: [
    {
      authorizationId: '11111111-1111-4111-8111-111111111111',
      operation: 'WRITE',
      outcome: 'SUCCEEDED',
      recordedAt: 1,
      reasonCode: 'EXECUTED',
      recordHash: `sha256:${'b'.repeat(64)}`,
      recordId: '22222222-2222-4222-8222-222222222222',
      recovery: null,
      requestHash: `sha256:${'a'.repeat(64)}`,
      resultHash: `sha256:${'c'.repeat(64)}`,
      target: 'src/main.ts',
    },
  ],
  failedActions: 0,
  integrity: 'VERIFIED',
  successfulActions: 1,
  unverifiedActions: 0,
};

const recoveryId = '33333333-3333-4333-8333-333333333333';
const runtimeAuditAck = {
  protocol: 'accordlock.desktop.control/v2' as const,
  schema_version: 2 as const,
  session_id: 'session-1',
  page: {
    schema_version: 6 as const,
    task_id: '55555555-5555-4555-8555-555555555555',
    session_id: 'session-1',
    run_id: 'run-1',
    offset: 0,
    next_offset: null,
    total_events: 2,
    snapshot_revision: 17,
    snapshot_at: 20,
    events: [
      {
        event_id: 'denied-1',
        recorded_at: 20,
        type: 'ACTION_DENIED' as const,
        denial_id: 1,
        attempted_run_id: 'attempted-run-1',
        tool_call_id: 'call-1',
        proposal_digest: `sha256:${'d'.repeat(64)}`,
        reason_code: 'POLICY_DENIED',
      },
      {
        event_id: 'approved-1',
        recorded_at: 10,
        type: 'SESSION_APPROVED' as const,
        task_id: '55555555-5555-4555-8555-555555555555',
        run_id: 'run-1',
        workspace_root: 'accordlock',
        policy_hash: `sha256:${'e'.repeat(64)}`,
        expires_at: 2_000_000_000,
      },
    ],
    page_digest: `sha256:${'f'.repeat(64)}`,
  },
};
const deletedReport: TaskReport = {
  evidence: [
    {
      authorizationId: '11111111-1111-4111-8111-111111111111',
      operation: 'DELETE',
      outcome: 'SUCCEEDED',
      recordedAt: 1,
      reasonCode: 'EXECUTED',
      recordHash: `sha256:${'b'.repeat(64)}`,
      recordId: '22222222-2222-4222-8222-222222222222',
      recovery: {
        contentHash: `sha256:${'d'.repeat(64)}`,
        recoveryId,
        recoveryPath: `.accordlock/recovery/${recoveryId}/content`,
      },
      requestHash: `sha256:${'a'.repeat(64)}`,
      resultHash: `sha256:${'c'.repeat(64)}`,
      target: 'notes.txt',
    },
  ],
  failedActions: 0,
  integrity: 'VERIFIED',
  successfulActions: 1,
  unverifiedActions: 0,
};

function renderPanel(overrides: Partial<TaskStatusPanelProps> = {}) {
  const props: TaskStatusPanelProps = {
    authorization: 'APPROVED',
    expiresAt: 2_000_000_000,
    expiresIn: '28m',
    isBusy: false,
    isModelSlow: false,
    isStopping: false,
    modelFailed: false,
    objective: 'Prepare a verified release',
    onStopAndLock: vi.fn(),
    pendingDecision: false,
    report,
    runtimeUnavailable: false,
    sessionId: 'session-1',
    taskApproved: true,
    workspace: 'accordlock',
    ...overrides,
  };
  render(<TaskStatusPanel {...props} />, { wrapper: IntlTestWrapper });
  return props;
}

describe('TaskStatusPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('keeps evidence details collapsed while showing a compact verified summary', () => {
    renderPanel();

    const panel = within(screen.getByTestId('task-status-panel'));
    expect(panel.getByRole('heading', { name: 'Prepare a verified release' })).toBeInTheDocument();
    expect(panel.getByText('Audit trail')).toBeInTheDocument();
    expect(screen.getByText('3 records')).toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent('Ready for review');
    expect(screen.getByTestId('task-protection')).not.toHaveAttribute('open');
    expect(screen.getByTestId('task-activity')).not.toHaveAttribute('open');
    expect(screen.queryByText(/22222222-2222/)).not.toBeVisible();
  });

  it('explains the execution guarantees without exposing internal terminology', () => {
    renderPanel();

    fireEvent.click(screen.getByText('Protection'));
    expect(screen.getByText('Goal locked')).toBeVisible();
    expect(screen.getByText('Access scoped')).toBeVisible();
    expect(screen.getByText('State checked')).toBeVisible();
    expect(screen.getByText('Execution recorded')).toBeVisible();
    expect(screen.getByText('1 action has a verification record.')).toBeVisible();
    const retiredTerms = new RegExp(
      `${['cr', 'cs'].join('')}|${['binding', 'gate'].join(' ')}|${['semanti', 'meter'].join('')}`,
      'i'
    );
    expect(screen.queryByText(retiredTerms)).not.toBeInTheDocument();
  });

  it('does not present a verified failure as a successful finish', () => {
    renderPanel({
      report: {
        ...report,
        evidence: [{ ...report.evidence[0], outcome: 'FAILED' }],
        failedActions: 1,
        successfulActions: 0,
      },
    });

    expect(screen.getByRole('status')).toHaveTextContent('Needs attention');
    expect(screen.getByText('One or more protected actions failed.')).toBeVisible();
  });

  it('exports either a readable report or the audit JSON', async () => {
    const saveAuditFile = vi.fn().mockResolvedValue({ canceled: false, saved: true });
    window.electron.saveAuditFile = saveAuditFile;
    const user = userEvent.setup();
    renderPanel();
    fireEvent.click(screen.getByText('Audit trail'));

    await user.click(screen.getByRole('button', { name: 'Export' }));
    await user.click(screen.getByRole('menuitem', { name: 'Task report (.md)' }));
    await waitFor(() => expect(saveAuditFile).toHaveBeenCalledTimes(1));
    expect(saveAuditFile.mock.calls[0]?.[0]).toBe('accordlock-session-1.report.md');
    expect(saveAuditFile.mock.calls[0]?.[1]).toContain('# AccordLock task report');
    expect(saveAuditFile.mock.calls[0]?.[1]).toContain('Wrote file: src/main.ts');

    await user.click(screen.getByRole('button', { name: 'Export' }));
    await user.click(screen.getByRole('menuitem', { name: 'Audit data (.json)' }));
    await waitFor(() => expect(saveAuditFile).toHaveBeenCalledTimes(2));
    expect(saveAuditFile.mock.calls[1]?.[0]).toBe('accordlock-session-1.audit.json');
    expect(JSON.parse(saveAuditFile.mock.calls[1]?.[1])).toMatchObject({
      recordType: 'accordlock.task-audit-projection',
    });
  });

  it('shows model delay separately from a security runtime failure', () => {
    const { rerender } = render(
      <TaskStatusPanel
        {...({
          authorization: 'APPROVED',
          expiresAt: null,
          expiresIn: null,
          isBusy: true,
          isModelSlow: true,
          isStopping: false,
          modelFailed: false,
          objective: 'Check the release',
          onStopAndLock: vi.fn(),
          pendingDecision: false,
          report,
          runtimeUnavailable: false,
          sessionId: 'session-1',
          taskApproved: true,
          workspace: 'project',
        } satisfies TaskStatusPanelProps)}
      />,
      { wrapper: IntlTestWrapper }
    );
    expect(screen.getByText('Still working')).toBeInTheDocument();
    expect(screen.getByText('Taking longer than usual.')).toBeInTheDocument();

    rerender(
      <IntlTestWrapper>
        <TaskStatusPanel
          authorization="APPROVED"
          expiresAt={null}
          expiresIn={null}
          isBusy={false}
          isModelSlow={false}
          isStopping={false}
          modelFailed={false}
          objective="Check the release"
          onStopAndLock={vi.fn()}
          pendingDecision={false}
          report={report}
          runtimeUnavailable={true}
          sessionId="session-1"
          taskApproved={true}
          workspace="project"
        />
      </IntlTestWrapper>
    );
    expect(screen.getByText('Actions paused')).toBeInTheDocument();
    expect(screen.getByText('AccordLock is reconnecting.')).toBeInTheDocument();
  });

  it('keeps the empty activity timeline available before any action has run', () => {
    renderPanel({
      authorization: 'PENDING',
      report: {
        evidence: [],
        failedActions: 0,
        integrity: 'NO_EXECUTION',
        successfulActions: 0,
        unverifiedActions: 0,
      },
      taskApproved: false,
    });

    expect(screen.getByTestId('task-activity')).not.toHaveAttribute('open');
    expect(screen.getByText('2 records')).toBeInTheDocument();
    expect(screen.getByText('Confirm task access to begin.')).toBeInTheDocument();
  });

  it('shows protection as off after task access is rejected', () => {
    renderPanel({ authorization: 'REJECTED', taskApproved: false });

    expect(screen.getByTestId('task-protection')).toHaveTextContent('Protection·Off');
    expect(screen.getByTestId('task-protection')).not.toHaveTextContent('Pending');
  });

  it('stops and revokes from one immediate control', () => {
    const props = renderPanel();
    fireEvent.click(within(screen.getByTestId('task-status-panel')).getByText('Stop task'));
    expect(props.onStopAndLock).toHaveBeenCalledOnce();
  });

  it('derives restore access only from successful deletes while task access is active', () => {
    expect(deriveTaskRestoreCapabilities(deletedReport, false)).toEqual([]);
    expect(deriveTaskRestoreCapabilities(deletedReport, true)).toEqual([
      {
        contentHash: `sha256:${'d'.repeat(64)}`,
        recordId: '22222222-2222-4222-8222-222222222222',
        recoveryId,
        recoveryPath: `.accordlock/recovery/${recoveryId}/content`,
      },
    ]);
    expect(
      deriveTaskRestoreCapabilities(
        {
          ...deletedReport,
          evidence: [{ ...deletedReport.evidence[0], outcome: 'FAILED' }],
        },
        true
      )
    ).toEqual([]);
  });

  it('restores through the narrow bridge and adds a separate audit event', async () => {
    let resolveRestore!: (value: unknown) => void;
    const restoreDeletedFile = vi.fn(
      () =>
        new Promise<unknown>((resolve) => {
          resolveRestore = resolve;
        })
    );
    renderPanel({ report: deletedReport, taskBridge: { restoreDeletedFile } });

    fireEvent.click(screen.getByText('Audit trail'));
    fireEvent.click(screen.getByText('Moved file to recovery · notes.txt'));
    fireEvent.click(screen.getByRole('button', { name: 'Restore…' }));

    expect(restoreDeletedFile).toHaveBeenCalledWith({
      protocol: 'accordlock.desktop.control/v2',
      schema_version: 2,
      session_id: 'session-1',
      recovery_id: recoveryId,
    });
    expect(screen.getByRole('button', { name: 'Restoring…' })).toBeDisabled();

    resolveRestore({
      protocol: 'accordlock.desktop.control/v2',
      schema_version: 2,
      session_id: 'session-1',
      recovery_id: recoveryId,
      status: 'RESTORED',
      record: {
        restore_id: '44444444-4444-4444-8444-444444444444',
        record_hash: `sha256:${'e'.repeat(64)}`,
        relative_path: 'notes.txt',
        content_sha256: `sha256:${'d'.repeat(64)}`,
        completed_at: 1_725_000_100,
      },
    });

    await waitFor(() => expect(screen.getByText('Restored file · notes.txt')).toBeInTheDocument());
    expect(screen.getByText('Moved file to recovery · notes.txt')).toBeInTheDocument();
    expect(screen.getByText('Restored')).toBeInTheDocument();
    expect(screen.getByText('4 records')).toBeInTheDocument();
    expect(toastSuccess).toHaveBeenCalledWith({
      title: 'File restored',
      msg: 'notes.txt was restored from its saved copy.',
    });
  });

  it('keeps restore available after a clear failure', async () => {
    const restoreDeletedFile = vi.fn().mockRejectedValue(new Error('private runtime detail'));
    renderPanel({ report: deletedReport, taskBridge: { restoreDeletedFile } });

    fireEvent.click(screen.getByText('Audit trail'));
    fireEvent.click(screen.getByText('Moved file to recovery · notes.txt'));
    fireEvent.click(screen.getByRole('button', { name: 'Restore…' }));

    await waitFor(() =>
      expect(toastError).toHaveBeenCalledWith({
        title: 'Couldn’t restore file',
        msg: 'The file was not restored. Check task access and try again.',
      })
    );
    expect(screen.getByRole('button', { name: 'Restore…' })).toBeEnabled();
    expect(screen.queryByText('private runtime detail')).not.toBeInTheDocument();
  });

  it('shows the verified runtime record and exports the complete ledger snapshot', async () => {
    const saveAuditFile = vi.fn().mockResolvedValue({ canceled: false, saved: true });
    window.electron.saveAuditFile = saveAuditFile;
    const getTaskAudit = vi.fn().mockResolvedValue(runtimeAuditAck);
    const user = userEvent.setup();
    renderPanel({
      taskBridge: {
        restoreDeletedFile: vi.fn(),
        getTaskAudit,
      },
    });

    await waitFor(() => expect(screen.getByText('3 records')).toBeInTheDocument());
    fireEvent.click(screen.getByText('Audit trail'));
    expect(await screen.findByRole('heading', { name: 'Blocked' })).toBeInTheDocument();
    expect(screen.getByText('Verified against the execution log.')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Export' }));
    await user.click(screen.getByRole('menuitem', { name: 'Audit data (.json)' }));
    await waitFor(() => expect(saveAuditFile).toHaveBeenCalledOnce());
    const exported = JSON.parse(saveAuditFile.mock.calls[0]?.[1]);
    expect(exported).toMatchObject({
      recordType: 'accordlock.task-audit-bundle',
      historyScope: 'RUNTIME_LEDGER',
      snapshot: { sessionId: 'session-1', totalEvents: 2 },
    });
    expect(exported.runtimePages).toHaveLength(1);
    expect(getTaskAudit).toHaveBeenCalledOnce();
  });

  it('polls the runtime audit only while the task is running', () => {
    const interval = vi.spyOn(window, 'setInterval');
    renderPanel({
      isBusy: true,
      taskBridge: {
        restoreDeletedFile: vi.fn(),
        getTaskAudit: vi.fn().mockResolvedValue(runtimeAuditAck),
      },
    });

    expect(interval).toHaveBeenCalledWith(expect.any(Function), 1_000);
    interval.mockRestore();
  });

  it('keeps the task-record view when the private audit channel is unavailable', async () => {
    renderPanel({
      taskBridge: {
        restoreDeletedFile: vi.fn(),
        getTaskAudit: vi.fn().mockRejectedValue(new Error('private control channel detail')),
      },
    });

    fireEvent.click(screen.getByText('Audit trail'));
    expect(
      await screen.findByText('Saved task activity. Earlier records may be unavailable.')
    ).toBeInTheDocument();
    expect(screen.queryByText('private control channel detail')).not.toBeInTheDocument();
  });
});
