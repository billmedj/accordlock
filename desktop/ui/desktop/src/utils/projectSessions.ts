// Modified by AccordLock contributors; see UPSTREAM.md.
import type { SessionListItem } from '../acp/sessions';
import type { AccordLockProject } from '../acp/projects';

export interface ProjectGroup {
  path: string;
  label: string;
  projectId?: string;
  sessions: SessionListItem[];
  lastActivityAt: string;
}

function getSessionActivityTime(session: SessionListItem): string {
  return session.lastMessageAt ?? session.updatedAt;
}

const UNKNOWN_PROJECT_LABEL = 'Unknown';

export function normalizeProjectPath(workingDir: string): string {
  const normalized = workingDir.trim();
  if (!normalized) {
    return '';
  }

  const withoutTrailingSeparators = normalized.replace(/[\\/]+$/, '');
  return withoutTrailingSeparators || normalized;
}

export function getProjectLabel(workingDir: string): string {
  const normalized = workingDir.trim();
  if (!normalized) {
    return UNKNOWN_PROJECT_LABEL;
  }

  const withoutTrailingSeparators = normalizeProjectPath(workingDir);
  if (!withoutTrailingSeparators) {
    return normalized;
  }

  const parts = withoutTrailingSeparators.split(/[\\/]+/);
  return parts[parts.length - 1] || normalized;
}

function getProjectIdLabel(projectId: string): string {
  const readable = projectId.replace(/[-_]+/gu, ' ').trim();
  if (!readable) return 'Project';
  return readable.charAt(0).toLocaleUpperCase('en-US') + readable.slice(1);
}

/**
 * Groups explicitly assigned tasks by project. Tasks without project metadata
 * retain the previous workspace grouping so older sessions remain useful.
 */
export function groupSessionsByProject(
  sessions: SessionListItem[],
  projects: readonly Pick<AccordLockProject, 'id' | 'title'>[] = []
): ProjectGroup[] {
  const groups = new Map<string, SessionListItem[]>();
  const projectsById = new Map(projects.map((project) => [project.id, project]));

  for (const session of sessions) {
    const key = session.projectId
      ? `project:${session.projectId}`
      : `workspace:${normalizeProjectPath(session.workingDir)}`;
    const existing = groups.get(key);
    if (existing) {
      existing.push(session);
    } else {
      groups.set(key, [session]);
    }
  }

  const baseGroups = Array.from(groups.entries()).map(([key, projectSessions]) => {
    const sortedSessions = [...projectSessions].sort(
      (a, b) =>
        new Date(getSessionActivityTime(b)).getTime() -
        new Date(getSessionActivityTime(a)).getTime()
    );
    const projectId = key.startsWith('project:') ? key.slice('project:'.length) : undefined;
    const path = projectId
      ? key
      : normalizeProjectPath(sortedSessions[0]?.workingDir ?? key.slice('workspace:'.length));
    return {
      path,
      label: projectId
        ? (projectsById.get(projectId)?.title ?? getProjectIdLabel(projectId))
        : getProjectLabel(path),
      projectId,
      sessions: sortedSessions,
      lastActivityAt: getSessionActivityTime(
        sortedSessions[0] ?? ({ updatedAt: '' } as SessionListItem)
      ),
    };
  });

  const labelCounts = baseGroups.reduce((counts, group) => {
    counts.set(group.label, (counts.get(group.label) ?? 0) + 1);
    return counts;
  }, new Map<string, number>());

  return baseGroups
    .map((group) => ({
      ...group,
      label:
        !group.projectId && (labelCounts.get(group.label) ?? 0) > 1
          ? getDisambiguatedProjectLabel(group.path)
          : group.label,
    }))
    .sort((a, b) => new Date(b.lastActivityAt).getTime() - new Date(a.lastActivityAt).getTime());
}

function getDisambiguatedProjectLabel(workingDir: string): string {
  const withoutTrailingSeparators = normalizeProjectPath(workingDir);
  if (!withoutTrailingSeparators) {
    return UNKNOWN_PROJECT_LABEL;
  }
  const parts = withoutTrailingSeparators.split(/[\\/]+/).filter(Boolean);
  if (parts.length >= 2) {
    return `${parts[parts.length - 2]}/${parts[parts.length - 1]}`;
  }

  return getProjectLabel(workingDir);
}
