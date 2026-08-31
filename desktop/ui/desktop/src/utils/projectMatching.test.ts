import { describe, expect, it } from 'vitest';
import type { AccordLockProject } from '../acp/projects';
import {
  canonicalWorkspaceKey,
  projectsForWorkspace,
  uniqueProjectForWorkspace,
} from './projectMatching';

function project(id: string, workingDirs: string[], archived = false): AccordLockProject {
  return {
    id,
    title: id,
    description: '',
    instructions: '',
    workingDirs,
    archived,
    sourcePath: `${id}.md`,
    writable: true,
    properties: { title: id, workingDirs, archived },
  };
}

describe('project workspace matching', () => {
  it('normalizes Windows extended prefixes, separators, case and trailing slashes', () => {
    expect(canonicalWorkspaceKey('\\\\?\\C:\\Work\\Release\\')).toBe('c:/work/release');
    expect(canonicalWorkspaceKey('c:/work/release')).toBe('c:/work/release');
  });

  it('matches only active projects for the exact selected folder', () => {
    const projects = [
      project('Release', ['C:\\Work\\Release']),
      project('Archived', ['C:\\Work\\Release'], true),
      project('Other', ['C:\\Work\\Other']),
    ];

    expect(projectsForWorkspace(projects, '\\\\?\\c:\\work\\release')).toEqual([projects[0]]);
  });

  it('auto-selects only an unambiguous match', () => {
    const first = project('First', ['/work/release']);
    const second = project('Second', ['/work/release']);

    expect(uniqueProjectForWorkspace([first], '/work/release/')).toBe(first);
    expect(uniqueProjectForWorkspace([first, second], '/work/release')).toBeNull();
  });
});
