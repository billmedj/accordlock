import type { SourceEntry } from '@aaif/goose-sdk';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { getAcpClient } from '../acpConnection';
import {
  assignTaskToProject,
  createProject,
  listProjects,
  normalizeProjectWorkingDirs,
  projectFromSource,
  setProjectArchived,
  slugifyProjectTitle,
  uniqueProjectSlug,
  updateProject,
} from '../projects';

vi.mock('../acpConnection', () => ({
  getAcpClient: vi.fn(),
}));

function source(overrides: Partial<SourceEntry> = {}): SourceEntry {
  return {
    type: 'project',
    name: 'website-launch',
    description: 'Launch work',
    content: 'Use the release checklist.',
    path: '/data/projects/website-launch.md',
    global: true,
    writable: true,
    properties: {
      title: 'Website launch',
      workingDirs: ['/work/site'],
      color: '#6366F1',
      preferredProvider: 'openai',
    },
    ...overrides,
  };
}

function clientWithGoose(goose: Record<string, ReturnType<typeof vi.fn>>) {
  vi.mocked(getAcpClient).mockResolvedValue({
    goose,
  } as unknown as Awaited<ReturnType<typeof getAcpClient>>);
  return goose;
}

describe('ACP projects', () => {
  const environmentId = '7aa5a9cb-f5c8-4b8e-8aa3-fcd7f7658707';
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('maps typed project properties without leaking malformed folders', () => {
    const project = projectFromSource(
      source({
        properties: {
          title: 'Website launch',
          workingDirs: ['/work/site/', 4, '', '/work/api'],
          archived: true,
          deploymentEnvironmentId: environmentId,
          preferredProvider: 'openai',
        },
      })
    );

    expect(project).toMatchObject({
      id: 'website-launch',
      title: 'Website launch',
      workingDirs: ['/work/site', '/work/api'],
      archived: true,
      deploymentEnvironmentId: environmentId,
    });
    expect(project.properties.preferredProvider).toBe('openai');
  });

  it('normalizes portable slugs and resolves collisions', () => {
    expect(slugifyProjectTitle('  Déploiement – Été  ')).toBe('deploiement-ete');
    expect(uniqueProjectSlug('Website launch', ['website-launch', 'website-launch-2'])).toBe(
      'website-launch-3'
    );
    expect(normalizeProjectWorkingDirs(['/work/site/', '/work/site', ' C:\\Work\\Api\\ '])).toEqual(
      ['/work/site', 'C:\\Work\\Api']
    );
  });

  it('lists only projects and sorts archived entries last', async () => {
    const goose = clientWithGoose({
      sourcesList_unstable: vi.fn().mockResolvedValue({
        sources: [
          source({ name: 'zeta', properties: { title: 'Zeta', workingDirs: [] } }),
          source({
            name: 'archive',
            properties: { title: 'Archive', workingDirs: [], archived: true },
          }),
          source({ type: 'skill', name: 'ignored' }),
        ],
      }),
    });

    const projects = await listProjects();

    expect(goose.sourcesList_unstable).toHaveBeenCalledWith({ type: 'project' });
    expect(projects.map((project) => project.id)).toEqual(['zeta', 'archive']);
  });

  it('creates a global project source with folders and instructions', async () => {
    const createdSource = source();
    const goose = clientWithGoose({
      sourcesCreate_unstable: vi.fn().mockResolvedValue({ source: createdSource }),
    });

    const created = await createProject('website-launch', {
      title: ' Website launch ',
      description: ' Launch work ',
      instructions: ' Use the release checklist. ',
      workingDirs: ['/work/site/'],
      color: '#6366F1',
      deploymentEnvironmentId: environmentId,
    });

    expect(goose.sourcesCreate_unstable).toHaveBeenCalledWith({
      type: 'project',
      name: 'website-launch',
      description: 'Launch work',
      content: 'Use the release checklist.',
      target: { scope: 'global' },
      properties: {
        title: 'Website launch',
        workingDirs: ['/work/site'],
        archived: false,
        color: '#6366F1',
        deploymentEnvironmentId: environmentId,
      },
    });
    expect(created.id).toBe('website-launch');
  });

  it('updates modeled fields while preserving unknown project properties', async () => {
    const existing = projectFromSource(source());
    const updatedSource = source({
      description: 'Updated',
      properties: {
        ...existing.properties,
        title: 'Launch 2027',
        workingDirs: ['/work/site'],
      },
    });
    const goose = clientWithGoose({
      sourcesUpdate_unstable: vi.fn().mockResolvedValue({ source: updatedSource }),
    });

    await updateProject(existing, {
      title: 'Launch 2027',
      description: 'Updated',
      instructions: existing.instructions,
      workingDirs: existing.workingDirs,
      color: existing.color,
    });

    expect(goose.sourcesUpdate_unstable).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'project',
        path: existing.sourcePath,
        name: existing.id,
        properties: expect.objectContaining({
          title: 'Launch 2027',
          preferredProvider: 'openai',
        }),
      })
    );
  });

  it('archives without deleting the project and can assign a task', async () => {
    const existing = projectFromSource(source());
    const goose = clientWithGoose({
      sourcesUpdate_unstable: vi.fn().mockResolvedValue({
        source: source({ properties: { ...existing.properties, archived: true } }),
      }),
      sessionProjectUpdate_unstable: vi.fn().mockResolvedValue(undefined),
    });

    const archived = await setProjectArchived(existing, true);
    await assignTaskToProject('task-1', existing.id);

    expect(archived.archived).toBe(true);
    expect(goose.sourcesUpdate_unstable).toHaveBeenCalledTimes(1);
    expect(goose.sessionProjectUpdate_unstable).toHaveBeenCalledWith({
      sessionId: 'task-1',
      projectId: 'website-launch',
    });
  });
});
