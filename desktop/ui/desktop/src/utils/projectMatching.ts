import type { AccordLockProject } from '../acp/projects';

function stripExtendedWindowsPrefix(value: string): string {
  if (/^\\\\\?\\unc\\/iu.test(value)) return `\\\\${value.slice(8)}`;
  if (/^\\\\\?\\/u.test(value)) return value.slice(4);
  return value;
}

export function canonicalWorkspaceKey(value: string): string {
  const trimmed = stripExtendedWindowsPrefix(value.trim()).replace(/\\/gu, '/');
  const withoutTrailingSeparators = trimmed.replace(/\/+$/gu, '');
  const canonical = withoutTrailingSeparators || trimmed;
  const looksLikeWindowsPath = /^[A-Za-z]:\//u.test(canonical) || canonical.startsWith('//');
  return looksLikeWindowsPath ? canonical.toLocaleLowerCase('en-US') : canonical;
}

export function projectsForWorkspace(
  projects: readonly AccordLockProject[],
  workspace: string
): AccordLockProject[] {
  const workspaceKey = canonicalWorkspaceKey(workspace);
  if (!workspaceKey) return [];

  return projects
    .filter(
      (project) =>
        !project.archived &&
        project.workingDirs.some((folder) => canonicalWorkspaceKey(folder) === workspaceKey)
    )
    .sort((left, right) =>
      left.title.localeCompare(right.title, undefined, { sensitivity: 'base' })
    );
}

/** Automatic assignment is safe only when the folder identifies one project. */
export function uniqueProjectForWorkspace(
  projects: readonly AccordLockProject[],
  workspace: string
): AccordLockProject | null {
  const matches = projectsForWorkspace(projects, workspace);
  return matches.length === 1 ? matches[0] : null;
}
