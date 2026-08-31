// Modified by AccordLock contributors; see UPSTREAM.md.
import type { BrowserWindow, IpcMainInvokeEvent } from 'electron';
import { ipcMain } from 'electron';
import {
  GitBranchAccess,
  type AuthorizedGitWorkspace,
  type GitBranchAccessDependencies,
} from './gitBranchAccess';

export function registerGitBranchIpc(
  dependencies: GitBranchAccessDependencies<IpcMainInvokeEvent, BrowserWindow>
): void {
  const access = new GitBranchAccess(dependencies);
  ipcMain.handle('get-git-branch-info', (event) => access.getBranchInfo(event));
  ipcMain.handle('list-git-branches', (event) => access.listBranches(event));
  ipcMain.handle('switch-git-branch', (event, branch: unknown) =>
    access.switchBranch(event, branch)
  );
}

export type GitBranchWorkspace = AuthorizedGitWorkspace<BrowserWindow>;
