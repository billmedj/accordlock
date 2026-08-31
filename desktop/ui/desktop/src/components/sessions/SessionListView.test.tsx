import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { IntlTestWrapper } from '../../i18n/test-utils';
import type { SessionListItem } from '../../acp/sessions';
import type { AccordLockProject } from '../../acp/projects';
import { acpArchiveSession, acpListSessions, acpUnarchiveSession } from '../../acp/sessions';
import { assignTaskToProject, listProjects } from '../../acp/projects';
import { revokeBeforeAccordLockSessionDeletion } from '../../accordlock/taskBridge';
import SessionListView from './SessionListView';

vi.mock('../../acp/sessions', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../acp/sessions')>();
  return {
    ...original,
    acpArchiveSession: vi.fn(),
    acpListSessions: vi.fn(),
    acpUnarchiveSession: vi.fn(),
  };
});

vi.mock('../../accordlock/taskBridge', () => ({
  revokeBeforeAccordLockSessionDeletion: vi.fn(
    async (_sessionId: string, archiveSession: () => Promise<void>) => archiveSession()
  ),
}));

vi.mock('../../acp/projects', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../acp/projects')>();
  return {
    ...original,
    assignTaskToProject: vi.fn(),
    listProjects: vi.fn(),
  };
});

vi.mock('../Layout/MainPanelLayout', () => ({
  MainPanelLayout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

vi.mock('../ui/scroll-area', () => ({
  ScrollArea: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

vi.mock('../conversation/SearchView', () => ({
  SearchView: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

const task: SessionListItem = {
  id: 'task-1',
  name: 'Review the release',
  workingDir: 'C:\\Work\\AccordLock',
  updatedAt: '2026-08-28T08:00:00.000Z',
  createdAt: '2026-08-28T08:00:00.000Z',
  messageCount: 2,
};

const project: AccordLockProject = {
  id: 'website-launch',
  title: 'Website launch',
  description: '',
  instructions: '',
  workingDirs: ['C:\\Work\\AccordLock'],
  archived: false,
  color: '#0F766E',
  sourcePath: 'projects/website-launch.md',
  writable: true,
  properties: { title: 'Website launch', workingDirs: ['C:\\Work\\AccordLock'] },
};

beforeAll(() => {
  vi.stubGlobal(
    'ResizeObserver',
    class ResizeObserver {
      observe() {}
      unobserve() {}
      disconnect() {}
    }
  );
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

describe('SessionListView projects', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.electron.getConfig = vi.fn(() => ({ GOOSE_DISABLE_NOSTR_SHARING: true }));
    vi.mocked(acpListSessions).mockResolvedValue({ sessions: [task], nextCursor: null });
    vi.mocked(acpArchiveSession).mockResolvedValue();
    vi.mocked(acpUnarchiveSession).mockResolvedValue();
    vi.mocked(listProjects).mockResolvedValue([project]);
    vi.mocked(assignTaskToProject).mockResolvedValue();
  });

  it('moves an existing task to a project from one quiet action menu', async () => {
    const user = userEvent.setup();
    render(<SessionListView onSelectSession={vi.fn()} />, { wrapper: IntlTestWrapper });

    await user.click(
      await screen.findByRole(
        'button',
        { name: 'More actions for Review the release' },
        { timeout: 15_000 }
      )
    );
    await user.click(screen.getByRole('menuitem', { name: 'Move to project' }));
    await user.click(screen.getByRole('button', { name: 'Website launch' }));

    await waitFor(() => {
      expect(assignTaskToProject).toHaveBeenCalledWith('task-1', 'website-launch');
    });
    expect(await screen.findByText('Website launch')).toBeVisible();
  });

  it('archives a task without deleting its history', async () => {
    const user = userEvent.setup();
    render(<SessionListView onSelectSession={vi.fn()} />, { wrapper: IntlTestWrapper });

    await user.click(
      await screen.findByRole(
        'button',
        { name: 'More actions for Review the release' },
        { timeout: 15_000 }
      )
    );
    await user.click(screen.getByRole('menuitem', { name: 'Archive task' }));
    await user.click(screen.getByRole('button', { name: 'Archive task' }));

    await waitFor(() => expect(acpArchiveSession).toHaveBeenCalledWith('task-1'));
    expect(revokeBeforeAccordLockSessionDeletion).toHaveBeenCalledWith(
      'task-1',
      expect.any(Function)
    );
  });

  it('restores an archived task from the archived view', async () => {
    vi.mocked(acpListSessions).mockResolvedValue({
      sessions: [{ ...task, archivedAt: '2026-08-29T00:00:00.000Z' }],
      nextCursor: null,
    });
    const user = userEvent.setup();
    render(<SessionListView onSelectSession={vi.fn()} />, { wrapper: IntlTestWrapper });

    await waitFor(() => expect(acpListSessions).toHaveBeenCalled(), { timeout: 15_000 });
    await user.click(
      await screen.findByRole('button', { name: /^Archived/u }, { timeout: 15_000 })
    );
    await user.click(
      await screen.findByRole(
        'button',
        { name: 'More actions for Review the release' },
        { timeout: 15_000 }
      )
    );
    await user.click(screen.getByRole('menuitem', { name: 'Restore task' }));

    await waitFor(() => expect(acpUnarchiveSession).toHaveBeenCalledWith('task-1'));
  });
});
