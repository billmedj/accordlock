import { describe, expect, it } from 'vitest';
import { accordLockTaskTitle, accordLockWorkspaceName, resolveNewTaskProjectId } from './Hub';
import { shouldQueueChatInputDuringLoading } from './ChatInput';
import { canonicalWorkspaceKey } from '../utils/projectMatching';
import type { AccordLockProject } from '../acp/projects';

function project(overrides: Partial<AccordLockProject> = {}): AccordLockProject {
  return {
    id: 'website-launch',
    title: 'Website launch',
    description: '',
    instructions: '',
    workingDirs: ['C:\\Work\\Website'],
    archived: false,
    sourcePath: 'projects/website-launch.md',
    writable: true,
    properties: { title: 'Website launch', workingDirs: ['C:\\Work\\Website'] },
    ...overrides,
  };
}

describe('AccordLock task labels', () => {
  it('uses the validated objective as a readable deterministic task title', () => {
    expect(accordLockTaskTitle('  Review   the release notes\nand fix the broken links  ')).toBe(
      'Review the release notes and fix the broken links'
    );
  });

  it('shortens long objectives without splitting a surrogate pair', () => {
    const title = accordLockTaskTitle(
      '🛡️ Audit this workspace and produce a concise release-readiness report with clear next steps'
    );

    expect(Array.from(title).length).toBeLessThanOrEqual(56);
    expect(title).toMatch(/…$/u);
    expect(title).not.toContain('�');
  });

  it('extracts a leaf folder from Windows and POSIX paths', () => {
    expect(accordLockWorkspaceName('\\\\?\\C:\\Users\\Person\\Acme workspace')).toBe(
      'Acme workspace'
    );
    expect(accordLockWorkspaceName('/Users/person/acme')).toBe('acme');
  });

  it('normalizes a trusted Windows workspace for automatic project matching', () => {
    expect(canonicalWorkspaceKey('\\\\?\\C:\\Users\\Person\\Acme workspace\\')).toBe(
      'c:/users/person/acme workspace'
    );
  });

  it('preselects a project only when the folder identifies one active project', () => {
    const website = project();

    expect(resolveNewTaskProjectId([website], 'C:\\Work\\Website', null, false)).toBe(website.id);
    expect(
      resolveNewTaskProjectId(
        [website, project({ id: 'second', title: 'Second project' })],
        'C:\\Work\\Website',
        null,
        false
      )
    ).toBeNull();
  });

  it('keeps an explicit project choice or clear selection during project refreshes', () => {
    const website = project();
    const research = project({
      id: 'research',
      title: 'Research',
      workingDirs: ['C:\\Work\\Research'],
    });

    expect(
      resolveNewTaskProjectId([website, research], 'C:\\Work\\Website', research.id, true)
    ).toBe(research.id);
    expect(
      resolveNewTaskProjectId([website, research], 'C:\\Work\\Website', null, true)
    ).toBeNull();
    expect(
      resolveNewTaskProjectId(
        [website, { ...research, archived: true }],
        'C:\\Work\\Website',
        research.id,
        true
      )
    ).toBeNull();
  });
});

describe('AccordLock landing composer', () => {
  it('never queues another task while the landing screen is starting', () => {
    expect(shouldQueueChatInputDuringLoading(true, true, true)).toBe(false);
  });

  it('preserves queueing for an active conversation', () => {
    expect(shouldQueueChatInputDuringLoading(false, true, true)).toBe(true);
  });
});
