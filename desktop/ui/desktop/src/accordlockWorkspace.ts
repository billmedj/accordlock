import path from 'node:path';

export const ACCORDLOCK_DEFAULT_WORKSPACE_DIRECTORY = 'workspace';

function sameOrAncestor(candidate: string, protectedPath: string): boolean {
  const relative = path.relative(path.resolve(candidate), path.resolve(protectedPath));
  return (
    relative === '' ||
    (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative))
  );
}

export function isAccordLockWorkspaceTooBroad(
  candidate: string,
  protectedPaths: readonly string[]
): boolean {
  const resolved = path.resolve(candidate);
  if (path.parse(resolved).root === resolved) {
    return true;
  }
  return protectedPaths.some((protectedPath) => sameOrAncestor(resolved, protectedPath));
}

export function accordLockDefaultWorkspace(userDataDirectory: string): string {
  return path.join(userDataDirectory, ACCORDLOCK_DEFAULT_WORKSPACE_DIRECTORY);
}

export function resolveAccordLockWorkspace(
  requestedWorkingDirectory: string | undefined,
  userDataDirectory: string,
  protectedPaths: readonly string[]
): string {
  const fallback = accordLockDefaultWorkspace(userDataDirectory);
  const requested = requestedWorkingDirectory?.trim();
  if (!requested) {
    return fallback;
  }
  const resolved = path.resolve(requested);
  return isAccordLockWorkspaceTooBroad(resolved, protectedPaths) ? fallback : resolved;
}
