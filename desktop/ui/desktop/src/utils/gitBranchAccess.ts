import { execFile } from 'node:child_process';

export const MAX_GIT_BRANCHES = 2048;
const MAX_GIT_OUTPUT_BYTES = 256 * 1024;
const MAX_BRANCH_BYTES = 255;

export interface AuthorizedGitWorkspace<Window> {
  directory: string;
  window: Window;
}

export interface GitBranchSwitchResult {
  success: boolean;
  canceled?: boolean;
  error?: string;
}

export type GitRunner = (directory: string, args: string[], timeout?: number) => Promise<string>;

export interface GitBranchAccessDependencies<Event, Window> {
  authorizeWorkspace: (event: Event) => Promise<AuthorizedGitWorkspace<Window>>;
  confirmSwitch: (workspace: AuthorizedGitWorkspace<Window>, branch: string) => Promise<boolean>;
  runGit?: GitRunner;
}

const gitArgs = (directory: string, args: string[]) => [
  '-c',
  'safe.bareRepository=explicit',
  '-c',
  'core.fsmonitor=false',
  '-C',
  directory,
  ...args,
];

export const runGit: GitRunner = (directory, args, timeout = 3000) =>
  new Promise<string>((resolve, reject) => {
    execFile(
      'git',
      gitArgs(directory, args),
      { timeout, maxBuffer: MAX_GIT_OUTPUT_BYTES, windowsHide: true },
      (error, stdout) => {
        if (error) {
          reject(error);
        } else {
          resolve(stdout.trim());
        }
      }
    );
  });

function byteLength(value: string): number {
  return Buffer.byteLength(value, 'utf8');
}

export function isValidBranchSelection(branch: unknown): branch is string {
  const hasForbiddenCharacter =
    typeof branch === 'string' &&
    [...branch].some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint <= 0x20 || codePoint === 0x7f || '~^:?*[\\'.includes(character);
    });
  return (
    typeof branch === 'string' &&
    branch.length > 0 &&
    branch === branch.trim() &&
    byteLength(branch) <= MAX_BRANCH_BYTES &&
    !branch.startsWith('-') &&
    !hasForbiddenCharacter &&
    !branch.includes('..') &&
    !branch.includes('@{') &&
    !branch.includes('//') &&
    !branch.endsWith('.') &&
    !branch.endsWith('/')
  );
}

function boundedBranches(output: string): string[] {
  const branches = output.split('\n').filter(Boolean);
  if (
    branches.length > MAX_GIT_BRANCHES ||
    branches.some((branch) => !isValidBranchSelection(branch))
  ) {
    throw new Error('Git returned an invalid or oversized branch list');
  }
  return branches;
}

function safeGitError(error: unknown): string {
  const gitError = error as Error & { stderr?: string | Buffer };
  const detail = gitError.stderr?.toString() || gitError.message || 'Git branch switch failed';
  return detail.slice(0, 1024);
}

export class GitBranchAccess<Event, Window> {
  private readonly run: GitRunner;

  constructor(private readonly dependencies: GitBranchAccessDependencies<Event, Window>) {
    this.run = dependencies.runGit ?? runGit;
  }

  private async currentBranch(directory: string): Promise<string | null> {
    try {
      const ref = await this.run(directory, ['symbolic-ref', 'HEAD']);
      const branch = ref.startsWith('refs/heads/') ? ref.slice('refs/heads/'.length) : ref;
      return isValidBranchSelection(branch) ? branch : null;
    } catch {
      const detached = await this.run(directory, ['rev-parse', '--short', 'HEAD']).catch(
        () => null
      );
      return detached && isValidBranchSelection(detached) ? detached : null;
    }
  }

  private async localBranches(directory: string): Promise<string[]> {
    const output = await this.run(directory, [
      'for-each-ref',
      'refs/heads/',
      '--format=%(refname:lstrip=2)',
    ]);
    return boundedBranches(output);
  }

  async getBranchInfo(event: Event): Promise<{ branch: string } | null> {
    const workspace = await this.dependencies.authorizeWorkspace(event);
    const branch = await this.currentBranch(workspace.directory);
    return branch ? { branch } : null;
  }

  async listBranches(event: Event): Promise<string[]> {
    const workspace = await this.dependencies.authorizeWorkspace(event);
    try {
      return await this.localBranches(workspace.directory);
    } catch {
      return [];
    }
  }

  async switchBranch(event: Event, branch: unknown): Promise<GitBranchSwitchResult> {
    const workspace = await this.dependencies.authorizeWorkspace(event);
    if (!isValidBranchSelection(branch)) {
      return { success: false, error: 'Invalid branch selection' };
    }

    try {
      const branches = await this.localBranches(workspace.directory);
      if (!branches.includes(branch)) {
        return { success: false, error: 'The selected local branch no longer exists' };
      }

      const currentBranch = await this.currentBranch(workspace.directory);
      if (currentBranch === branch) {
        return { success: true };
      }

      if (!(await this.dependencies.confirmSwitch(workspace, branch))) {
        return { success: false, canceled: true };
      }

      await this.run(workspace.directory, ['checkout', '--quiet', branch], 30000);
      return { success: true };
    } catch (error) {
      const currentBranch = await this.currentBranch(workspace.directory);
      if (currentBranch === branch) {
        return { success: true };
      }
      return { success: false, error: safeGitError(error) };
    }
  }
}
