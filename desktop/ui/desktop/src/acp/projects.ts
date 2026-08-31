import type { SourceEntry } from '@aaif/goose-sdk';
import { getAcpClient } from './acpConnection';
import { isAccordLockEnvironmentProfileId } from '../accordlock/environmentProfiles';

export const PROJECTS_CHANGED_EVENT = 'accordlock:projects-changed';

export interface ProjectProperties {
  [key: string]: unknown;
  title: string;
  workingDirs: string[];
  archived?: boolean;
  color?: string;
  deploymentEnvironmentId?: string;
}

export interface AccordLockProject {
  id: string;
  title: string;
  description: string;
  instructions: string;
  workingDirs: string[];
  archived: boolean;
  color?: string;
  deploymentEnvironmentId?: string;
  sourcePath: string;
  writable: boolean;
  properties: ProjectProperties;
}

export interface ProjectInput {
  title: string;
  description: string;
  instructions: string;
  workingDirs: string[];
  color?: string;
  deploymentEnvironmentId?: string | null;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}

export function normalizeProjectWorkingDirs(workingDirs: string[]): string[] {
  const seen = new Set<string>();
  const normalized: string[] = [];

  for (const candidate of workingDirs) {
    const trimmed = candidate.trim();
    if (!trimmed) continue;

    const path =
      trimmed === '/' || trimmed === '\\' || /^[A-Za-z]:[\\/]$/.test(trimmed)
        ? trimmed
        : trimmed.replace(/[\\/]+$/, '');
    if (!path || seen.has(path)) continue;

    seen.add(path);
    normalized.push(path);
  }

  return normalized;
}

export function projectFromSource(source: SourceEntry): AccordLockProject {
  const rawProperties = source.properties ?? {};
  const title = optionalString(rawProperties.title) ?? source.name;
  const workingDirs = Array.isArray(rawProperties.workingDirs)
    ? normalizeProjectWorkingDirs(
        rawProperties.workingDirs.filter((value): value is string => typeof value === 'string')
      )
    : [];
  const color = optionalString(rawProperties.color);
  const deploymentEnvironmentId = isAccordLockEnvironmentProfileId(
    rawProperties.deploymentEnvironmentId
  )
    ? rawProperties.deploymentEnvironmentId
    : undefined;
  const properties: ProjectProperties = {
    ...rawProperties,
    title,
    workingDirs,
    ...(color ? { color } : {}),
    ...(deploymentEnvironmentId ? { deploymentEnvironmentId } : {}),
  };

  return {
    id: source.name,
    title,
    description: source.description,
    instructions: source.content,
    workingDirs,
    archived: rawProperties.archived === true,
    color,
    deploymentEnvironmentId,
    sourcePath: source.path,
    writable: source.writable !== false,
    properties,
  };
}

export function slugifyProjectTitle(title: string): string {
  const slug = title
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 63)
    .replace(/-+$/g, '');

  return slug || 'project';
}

export function uniqueProjectSlug(title: string, existingIds: Iterable<string>): string {
  const ids = new Set(existingIds);
  const base = slugifyProjectTitle(title);
  if (!ids.has(base)) return base;

  for (let suffix = 2; ; suffix += 1) {
    const suffixText = `-${suffix}`;
    const candidate = `${base.slice(0, 63 - suffixText.length).replace(/-+$/g, '')}${suffixText}`;
    if (!ids.has(candidate)) return candidate;
  }
}

function projectProperties(
  input: ProjectInput,
  existing: ProjectProperties = { title: '', workingDirs: [] },
  archived = false
): ProjectProperties {
  const color = optionalString(input.color);
  const properties: ProjectProperties = {
    ...existing,
    title: input.title.trim(),
    workingDirs: normalizeProjectWorkingDirs(input.workingDirs),
    archived,
  };

  if (color) {
    properties.color = color;
  } else {
    delete properties.color;
  }

  if (
    typeof input.deploymentEnvironmentId === 'string' &&
    isAccordLockEnvironmentProfileId(input.deploymentEnvironmentId)
  ) {
    properties.deploymentEnvironmentId = input.deploymentEnvironmentId;
  } else {
    delete properties.deploymentEnvironmentId;
  }

  return properties;
}

function announceProjectsChanged(): void {
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent(PROJECTS_CHANGED_EVENT));
  }
}

export async function listProjects(): Promise<AccordLockProject[]> {
  const client = await getAcpClient();
  const response = await client.goose.sourcesList_unstable({ type: 'project' });

  return response.sources
    .filter((source) => source.type === 'project')
    .map(projectFromSource)
    .sort(
      (left, right) =>
        Number(left.archived) - Number(right.archived) ||
        left.title.localeCompare(right.title, undefined, { sensitivity: 'base' })
    );
}

export async function createProject(id: string, input: ProjectInput): Promise<AccordLockProject> {
  const client = await getAcpClient();
  const response = await client.goose.sourcesCreate_unstable({
    type: 'project',
    name: id,
    description: input.description.trim(),
    content: input.instructions.trim(),
    target: { scope: 'global' },
    properties: projectProperties(input),
  });
  announceProjectsChanged();
  return projectFromSource(response.source);
}

export async function updateProject(
  project: AccordLockProject,
  input: ProjectInput
): Promise<AccordLockProject> {
  const client = await getAcpClient();
  const response = await client.goose.sourcesUpdate_unstable({
    type: 'project',
    path: project.sourcePath,
    name: project.id,
    description: input.description.trim(),
    content: input.instructions.trim(),
    properties: projectProperties(input, project.properties, project.archived),
  });
  announceProjectsChanged();
  return projectFromSource(response.source);
}

export async function setProjectArchived(
  project: AccordLockProject,
  archived: boolean
): Promise<AccordLockProject> {
  const client = await getAcpClient();
  const response = await client.goose.sourcesUpdate_unstable({
    type: 'project',
    path: project.sourcePath,
    name: project.id,
    description: project.description,
    content: project.instructions,
    properties: {
      ...project.properties,
      title: project.title,
      workingDirs: project.workingDirs,
      archived,
    },
  });
  announceProjectsChanged();
  return projectFromSource(response.source);
}

export async function assignTaskToProject(
  sessionId: string,
  projectId: string | null
): Promise<void> {
  const client = await getAcpClient();
  await client.goose.sessionProjectUpdate_unstable({ sessionId, projectId });
  announceProjectsChanged();
}
