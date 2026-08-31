import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import {
  buildTaskAuditTimeline,
  type BuildTaskAuditTimelineInput,
  type TaskAuditTimeline as TaskAuditTimelineModel,
  type TaskRestoreCapability,
} from '../../accordlock/auditTimeline';
import type { TaskExecutionEvidence, TaskReport } from '../../accordlock/taskReport';
import { TaskAuditTimeline } from './TaskAuditTimeline';

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

function report(items: TaskExecutionEvidence[]): TaskReport {
  return {
    evidence: items,
    failedActions: 0,
    integrity: items.length ? 'VERIFIED' : 'NO_EXECUTION',
    successfulActions: items.length,
    unverifiedActions: 0,
  };
}

function timelineInput(
  item: TaskExecutionEvidence,
  restoreCapabilities: TaskRestoreCapability[] = []
): BuildTaskAuditTimelineInput {
  return {
    authorization: 'APPROVED',
    expiresAt: 1_800_000_000,
    historyScope: 'TASK_RECORDS_ONLY',
    objective: 'Prepare a verified release',
    pendingDecision: true,
    report: report([item]),
    requestedAt: 1_724_999_900,
    restoreAcknowledgements: [],
    restoreCapabilities,
    revocation: null,
    sessionId: 'session-1',
    workspace: 'C:\\work\\accordlock',
  };
}

describe('TaskAuditTimeline', () => {
  it('keeps exact evidence collapsed and filters without cluttering the default view', () => {
    render(<TaskAuditTimeline timeline={buildTaskAuditTimeline(timelineInput(evidence()))} />);

    expect(screen.getByRole('heading', { name: 'Audit trail' })).toBeInTheDocument();
    expect(
      screen.getByText('Saved task activity. Earlier records may be unavailable.')
    ).toBeInTheDocument();
    expect(screen.getByText('Wrote file · src/main.ts')).toBeInTheDocument();
    expect(screen.queryByText(hash('b'))).not.toBeVisible();
    expect(screen.queryByRole('button', { name: /Restore/ })).not.toBeInTheDocument();

    fireEvent.click(screen.getByText('Wrote file · src/main.ts'));
    expect(screen.getByText(hash('b'))).toBeVisible();

    fireEvent.click(screen.getByRole('button', { name: 'Decisions' }));
    expect(screen.getByText('Task access approved')).toBeInTheDocument();
    expect(screen.getByText('Action approval needed')).toBeInTheDocument();
    expect(screen.queryByText('Wrote file · src/main.ts')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Changes' }));
    expect(screen.getByText('Wrote file · src/main.ts')).toBeInTheDocument();
    expect(screen.queryByText('Task access approved')).not.toBeInTheDocument();
  });

  it('offers restore only for a matching recovery record and forwards the exact request', () => {
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
    const onRestore = vi.fn();

    const { rerender } = render(
      <TaskAuditTimeline
        timeline={buildTaskAuditTimeline(timelineInput(deleted))}
        onRestore={onRestore}
      />
    );
    fireEvent.click(screen.getByText('Moved file to recovery · notes.txt'));
    expect(screen.queryByRole('button', { name: /Restore/ })).not.toBeInTheDocument();

    rerender(
      <TaskAuditTimeline
        timeline={buildTaskAuditTimeline(timelineInput(deleted, [capability]))}
        onRestore={onRestore}
      />
    );
    fireEvent.click(screen.getByText('Moved file to recovery · notes.txt'));
    fireEvent.click(screen.getByRole('button', { name: 'Restore…' }));
    expect(onRestore).toHaveBeenCalledWith({ ...capability, target: 'notes.txt' });

    rerender(
      <TaskAuditTimeline
        timeline={buildTaskAuditTimeline(timelineInput(deleted, [capability]))}
        onRestore={onRestore}
        restoringRecoveryId={capability.recoveryId}
      />
    );
    expect(screen.getByRole('button', { name: 'Restoring…' })).toBeDisabled();

    rerender(
      <TaskAuditTimeline
        timeline={buildTaskAuditTimeline(timelineInput(deleted, [capability]))}
        onRestore={onRestore}
        restoredRecoveryIds={new Set([capability.recoveryId])}
      />
    );
    expect(screen.getByText('Restored')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Restore/ })).not.toBeInTheDocument();
  });

  it('offers readable and machine-readable exports from one compact control', async () => {
    const timeline = buildTaskAuditTimeline(timelineInput(evidence()));
    const onExport = vi.fn();
    const { rerender } = render(<TaskAuditTimeline timeline={timeline} />);
    const user = userEvent.setup();

    expect(screen.queryByRole('button', { name: 'Export' })).not.toBeInTheDocument();
    rerender(<TaskAuditTimeline timeline={timeline} onExport={onExport} />);
    await user.click(screen.getByRole('button', { name: 'Export' }));
    await user.click(screen.getByRole('menuitem', { name: 'Task report (.md)' }));
    expect(onExport).toHaveBeenCalledWith('markdown');

    await user.click(screen.getByRole('button', { name: 'Export' }));
    await user.click(screen.getByRole('menuitem', { name: 'Audit data (.json)' }));
    expect(onExport).toHaveBeenCalledWith('json');
  });

  it('shows runtime task control without exposing integrity details until opened', () => {
    const runtimeTimeline: TaskAuditTimelineModel = {
      events: [
        {
          category: 'ACTIVITY',
          details: [
            {
              label: 'Execution',
              details: [{ label: 'Task control hash', value: hash('f') }],
            },
          ],
          id: 'ledger:completed',
          taskControl: {
            label: 'Within approved access',
            reason: 'The action stayed within the approved access.',
            provenance: 'LINEAGE_BOUND',
            status: 'WITHIN_APPROVED_ACCESS',
          },
          kind: 'ACTION_RECORDED',
          reversibility: null,
          source: 'AccordLock',
          status: 'VERIFIED',
          summary: 'The action stayed within the approved access.',
          timestamp: 1_725_000_000,
          title: 'Action completed · write',
        },
      ],
      historyScope: 'RUNTIME_LEDGER',
      issueCount: 0,
      reversibleCount: 0,
      scopeNotice: 'Runtime ledger loaded.',
      verifiedActionCount: 1,
    };

    render(<TaskAuditTimeline timeline={runtimeTimeline} />);
    expect(screen.getByText('Within approved access')).toBeVisible();
    expect(screen.getByText('The action stayed within the approved access.')).toBeVisible();
    expect(screen.queryByText(hash('f'))).not.toBeVisible();
    expect(screen.queryByText(/score/iu)).not.toBeInTheDocument();

    fireEvent.click(screen.getByText('Action completed · write'));
    expect(screen.getByText(hash('f'))).toBeVisible();
  });
});
