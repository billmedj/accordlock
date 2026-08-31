import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { IntlTestWrapper } from '../../i18n/test-utils';
import type { AccordLockProject } from '../../acp/projects';
import { createProject, listProjects, setProjectArchived, updateProject } from '../../acp/projects';
import { acpListSessions } from '../../acp/sessions';
import ProjectsView from './ProjectsView';

const { navigate } = vi.hoisted(() => ({ navigate: vi.fn() }));

vi.mock('react-router', () => ({
  useNavigate: () => navigate,
}));

vi.mock('../../acp/projects', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../acp/projects')>();
  return {
    ...original,
    createProject: vi.fn(),
    listProjects: vi.fn(),
    setProjectArchived: vi.fn(),
    updateProject: vi.fn(),
  };
});

vi.mock('../../acp/sessions', () => ({
  acpListSessions: vi.fn(),
}));

vi.mock('../../utils/workingDir', () => ({
  getInitialWorkingDir: () => 'C:\\Work\\Current',
}));

vi.mock('../Layout/MainPanelLayout', () => ({
  MainPanelLayout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

function project(overrides: Partial<AccordLockProject> = {}): AccordLockProject {
  return {
    id: 'website-launch',
    title: 'Website launch',
    description: 'Ship the new website',
    instructions: '',
    workingDirs: ['C:\\Work\\Website'],
    archived: false,
    color: '#6366F1',
    sourcePath: 'C:\\Data\\projects\\website-launch.md',
    writable: true,
    properties: {
      title: 'Website launch',
      workingDirs: ['C:\\Work\\Website'],
      color: '#6366F1',
    },
    ...overrides,
  };
}

function renderView() {
  return render(<ProjectsView />, { wrapper: IntlTestWrapper });
}

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

describe('ProjectsView', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(acpListSessions).mockResolvedValue({ sessions: [], nextCursor: null });
    window.electron.selectProjectFolder = vi.fn().mockResolvedValue(null);
  });

  it('shows active projects with task counts and keeps archived projects behind disclosure', async () => {
    const active = project();
    const archived = project({
      id: 'old-project',
      title: 'Old project',
      archived: true,
      properties: { title: 'Old project', workingDirs: [], archived: true },
    });
    vi.mocked(listProjects).mockResolvedValue([active, archived]);
    vi.mocked(acpListSessions).mockResolvedValue({
      sessions: [
        {
          id: 'task-1',
          name: 'First task',
          workingDir: active.workingDirs[0],
          updatedAt: '2026-01-01T00:00:00Z',
          createdAt: '2026-01-01T00:00:00Z',
          messageCount: 1,
          projectId: active.id,
        },
        {
          id: 'task-2',
          name: 'Second task',
          workingDir: active.workingDirs[0],
          updatedAt: '2026-01-02T00:00:00Z',
          createdAt: '2026-01-02T00:00:00Z',
          messageCount: 1,
          projectId: active.id,
        },
      ],
      nextCursor: null,
    });

    const user = userEvent.setup();
    renderView();

    expect(await screen.findByText('Website launch')).toBeVisible();
    expect(screen.getByText('2 tasks')).toBeVisible();
    expect(screen.getByText('1 folder')).toBeVisible();
    expect(screen.queryByText('Old project')).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Archived (1)' }));

    expect(screen.getByText('Old project')).toBeVisible();
    expect(screen.queryByText('Website launch')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Active projects' })).toBeVisible();
  });

  it('opens the tasks assigned to a project', async () => {
    vi.mocked(listProjects).mockResolvedValue([project()]);

    const user = userEvent.setup();
    renderView();

    await user.click(await screen.findByRole('button', { name: 'Open Website launch' }));

    expect(navigate).toHaveBeenCalledWith('/sessions?projectId=website-launch');
  });

  it('creates a project from a compact editor with progressive instructions', async () => {
    vi.mocked(listProjects).mockResolvedValue([]);
    const created = project({
      id: 'research-release',
      title: 'Research release',
      description: 'Prepare the publication',
      instructions: 'Use the publication checklist.',
      workingDirs: ['C:\\Work\\Current', 'D:\\Papers'],
      color: '#0F766E',
    });
    vi.mocked(createProject).mockResolvedValue(created);

    const user = userEvent.setup();
    renderView();
    await screen.findByText('No projects yet');

    await user.click(screen.getByRole('button', { name: 'New project' }));
    await user.type(screen.getByLabelText('Project name'), 'Research release');
    await user.type(screen.getByLabelText('Description'), 'Prepare the publication');
    expect(screen.getByLabelText('Folders 1')).toHaveValue('C:\\Work\\Current');

    await user.click(screen.getByRole('button', { name: 'Add folder' }));
    await user.type(screen.getByLabelText('Folders 2'), 'D:\\Papers');
    await user.click(screen.getByRole('button', { name: 'Add instructions' }));
    await user.type(
      screen.getByLabelText('Project instructions'),
      'Use the publication checklist.'
    );
    await user.click(screen.getByRole('button', { name: 'Use Teal' }));
    await user.click(screen.getByRole('button', { name: 'Create project' }));

    await waitFor(() => {
      expect(createProject).toHaveBeenCalledWith('research-release', {
        title: 'Research release',
        description: 'Prepare the publication',
        instructions: 'Use the publication checklist.',
        workingDirs: ['C:\\Work\\Current', 'D:\\Papers'],
        color: '#0F766E',
      });
    });
    expect(await screen.findByText('Research release')).toBeVisible();
  });

  it('adds a project folder through the native picker', async () => {
    vi.mocked(listProjects).mockResolvedValue([]);
    window.electron.selectProjectFolder = vi.fn().mockResolvedValue('D:\\Selected');

    const user = userEvent.setup();
    renderView();
    await screen.findByText('No projects yet');

    await user.click(screen.getByRole('button', { name: 'New project' }));
    await user.click(screen.getByRole('button', { name: 'Choose folder 1' }));

    expect(window.electron.selectProjectFolder).toHaveBeenCalledOnce();
    expect(screen.getByLabelText('Folders 1')).toHaveValue('D:\\Selected');
  });

  it('edits and archives a project without exposing deletion', async () => {
    const existing = project();
    vi.mocked(listProjects).mockResolvedValue([existing]);
    vi.mocked(updateProject).mockResolvedValue({ ...existing, title: 'Public website' });
    vi.mocked(setProjectArchived).mockResolvedValue({
      ...existing,
      archived: true,
      properties: { ...existing.properties, archived: true },
    });

    const user = userEvent.setup();
    renderView();
    await screen.findByText('Website launch');

    await user.click(screen.getByRole('button', { name: 'More actions for Website launch' }));
    await user.click(screen.getByRole('menuitem', { name: 'Edit' }));
    const name = screen.getByLabelText('Project name');
    await user.clear(name);
    await user.type(name, 'Public website');
    await user.click(screen.getByRole('button', { name: 'Save changes' }));

    await waitFor(() => expect(updateProject).toHaveBeenCalledTimes(1));
    expect(await screen.findByText('Public website')).toBeVisible();

    await user.click(screen.getByRole('button', { name: 'More actions for Public website' }));
    await user.click(screen.getByRole('menuitem', { name: 'Archive' }));
    expect(
      screen.getByText('“Public website” moves to Archived. Its tasks stay available.')
    ).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Archive' }));

    await waitFor(() => expect(setProjectArchived).toHaveBeenCalledWith(expect.anything(), true));
    expect(screen.queryByText('Public website')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Archived (1)' })).toBeVisible();
    expect(screen.queryByText('Delete')).not.toBeInTheDocument();
  });

  it('shows a recoverable load error', async () => {
    vi.mocked(listProjects)
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValueOnce([project()]);

    const user = userEvent.setup();
    renderView();

    expect(await screen.findByText('Couldn’t load projects')).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Try again' }));

    expect(await screen.findByText('Website launch')).toBeVisible();
    expect(listProjects).toHaveBeenCalledTimes(2);
  });
});
