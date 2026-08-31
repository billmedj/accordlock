import { describe, expect, it, vi } from 'vitest';
import {
  GitBranchAccess,
  MAX_GIT_BRANCHES,
  isValidBranchSelection,
  type GitRunner,
} from './gitBranchAccess';

interface TestEvent {
  windowId: number;
}

function createAccess(runGit: GitRunner, confirmSwitch = vi.fn().mockResolvedValue(true)) {
  const authorizeWorkspace = vi.fn(async (event: TestEvent) => ({
    directory: event.windowId === 7 ? '/trusted/workspace-a' : '/trusted/workspace-b',
    window: { id: event.windowId },
  }));
  return {
    access: new GitBranchAccess({ authorizeWorkspace, confirmSwitch, runGit }),
    authorizeWorkspace,
    confirmSwitch,
  };
}

describe('GitBranchAccess', () => {
  it('derives the Git directory exclusively from the authorized window workspace', async () => {
    const runGit = vi.fn<GitRunner>().mockResolvedValue('refs/heads/main');
    const { access } = createAccess(runGit);

    await expect(access.getBranchInfo({ windowId: 7 })).resolves.toEqual({ branch: 'main' });
    await expect(access.getBranchInfo({ windowId: 8 })).resolves.toEqual({ branch: 'main' });
    expect(runGit.mock.calls.map(([directory]) => directory)).toEqual([
      '/trusted/workspace-a',
      '/trusted/workspace-b',
    ]);
  });

  it('requires confirmation before the exact existing branch mutation', async () => {
    const runGit = vi.fn<GitRunner>(async (_directory, args) => {
      if (args[0] === 'for-each-ref') return 'main\nrelease';
      if (args[0] === 'symbolic-ref') return 'refs/heads/main';
      if (args[0] === 'checkout') return '';
      throw new Error('unexpected Git call');
    });
    const { access, confirmSwitch } = createAccess(runGit);

    await expect(access.switchBranch({ windowId: 7 }, 'release')).resolves.toEqual({
      success: true,
    });
    expect(confirmSwitch).toHaveBeenCalledOnce();
    expect(confirmSwitch).toHaveBeenCalledWith(
      { directory: '/trusted/workspace-a', window: { id: 7 } },
      'release'
    );
    expect(runGit).toHaveBeenLastCalledWith(
      '/trusted/workspace-a',
      ['checkout', '--quiet', 'release'],
      30000
    );
  });

  it('does not mutate when the native confirmation is canceled', async () => {
    const runGit = vi.fn<GitRunner>(async (_directory, args) => {
      if (args[0] === 'for-each-ref') return 'main\nrelease';
      if (args[0] === 'symbolic-ref') return 'refs/heads/main';
      throw new Error('checkout must not run');
    });
    const { access } = createAccess(runGit, vi.fn().mockResolvedValue(false));

    await expect(access.switchBranch({ windowId: 7 }, 'release')).resolves.toEqual({
      success: false,
      canceled: true,
    });
    expect(runGit.mock.calls.some(([, args]) => args[0] === 'checkout')).toBe(false);
  });

  it('rejects option-like and malformed branch input before confirmation', async () => {
    const runGit = vi.fn<GitRunner>();
    const { access, confirmSwitch } = createAccess(runGit);

    for (const branch of ['--force', '../escape', 'bad\nbranch', 'refs/@{upstream}']) {
      await expect(access.switchBranch({ windowId: 7 }, branch)).resolves.toMatchObject({
        success: false,
      });
    }
    expect(confirmSwitch).not.toHaveBeenCalled();
    expect(runGit).not.toHaveBeenCalled();
  });

  it('fails closed on an oversized branch listing', async () => {
    const branches = Array.from({ length: MAX_GIT_BRANCHES + 1 }, (_, index) => `branch-${index}`);
    const runGit = vi.fn<GitRunner>().mockResolvedValue(branches.join('\n'));
    const { access } = createAccess(runGit);

    await expect(access.listBranches({ windowId: 7 })).resolves.toEqual([]);
  });
});

describe('isValidBranchSelection', () => {
  it('accepts normal local branch names and rejects Git ref hazards', () => {
    expect(isValidBranchSelection('feature/secure-ipc')).toBe(true);
    expect(isValidBranchSelection('-force')).toBe(false);
    expect(isValidBranchSelection('feature..escape')).toBe(false);
    expect(isValidBranchSelection('feature lock')).toBe(false);
    expect(isValidBranchSelection('feature[1]')).toBe(false);
  });
});
