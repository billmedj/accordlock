import { ChevronDown, FolderKanban, FolderPlus } from 'lucide-react';
import { defineMessages, useIntl } from '../../i18n';
import type { AccordLockProject } from '../../acp/projects';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '../ui/dropdown-menu';

const NO_PROJECT_VALUE = 'accordlock:no-project';

const i18n = defineMessages({
  project: { id: 'projectPicker.label', defaultMessage: 'Project' },
  noProject: { id: 'projectPicker.none', defaultMessage: 'No project' },
  selection: {
    id: 'projectPicker.selection',
    defaultMessage: 'Project: {project}',
  },
  addToProject: { id: 'projectPicker.add', defaultMessage: 'Add to project' },
  createProject: { id: 'projectPicker.create', defaultMessage: 'Create project' },
});

export type ProjectPickerProps = {
  onChange: (projectId: string | null) => void;
  onCreateProject?: () => void;
  projects: readonly AccordLockProject[];
  selectedProjectId: string | null;
};

export function ProjectPicker({
  onChange,
  onCreateProject,
  projects,
  selectedProjectId,
}: ProjectPickerProps) {
  const intl = useIntl();
  const activeProjects = projects.filter((project) => !project.archived);
  if (activeProjects.length === 0) {
    return (
      <button
        type="button"
        onClick={onCreateProject}
        disabled={!onCreateProject}
        className="inline-flex h-7 items-center gap-1.5 rounded-full border border-border-secondary px-2.5 text-xs font-medium text-text-secondary outline-none transition-colors hover:bg-background-secondary hover:text-text-primary focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-default disabled:opacity-60"
      >
        <FolderPlus aria-hidden="true" className="size-3.5" />
        {intl.formatMessage(i18n.createProject)}
      </button>
    );
  }

  const selectedProject =
    activeProjects.find((project) => project.id === selectedProjectId) ?? null;
  const selectedLabel = selectedProject?.title ?? intl.formatMessage(i18n.addToProject);
  const accessibleLabel = intl.formatMessage(i18n.selection, { project: selectedLabel });

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          aria-label={accessibleLabel}
          className="inline-flex h-7 max-w-[240px] items-center gap-1.5 rounded-full border border-border-secondary px-2.5 text-xs font-medium text-text-secondary outline-none transition-colors hover:bg-background-secondary hover:text-text-primary focus-visible:ring-2 focus-visible:ring-ring"
        >
          {selectedProject?.color ? (
            <span
              aria-hidden="true"
              className="size-2 shrink-0 rounded-full"
              style={{ backgroundColor: selectedProject.color }}
            />
          ) : (
            <FolderKanban aria-hidden="true" className="size-3.5 shrink-0" />
          )}
          <span className="truncate">{selectedLabel}</span>
          <ChevronDown aria-hidden="true" className="size-3 shrink-0 opacity-60" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="min-w-[220px] max-w-[320px]">
        <DropdownMenuLabel className="text-xs font-medium text-text-tertiary">
          {intl.formatMessage(i18n.project)}
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuRadioGroup
          value={selectedProject?.id ?? NO_PROJECT_VALUE}
          onValueChange={(value) => onChange(value === NO_PROJECT_VALUE ? null : value)}
        >
          <DropdownMenuRadioItem value={NO_PROJECT_VALUE}>
            {intl.formatMessage(i18n.noProject)}
          </DropdownMenuRadioItem>
          {activeProjects.map((project) => (
            <DropdownMenuRadioItem key={project.id} value={project.id}>
              <span
                aria-hidden="true"
                className="size-2 shrink-0 rounded-full bg-text-tertiary"
                style={project.color ? { backgroundColor: project.color } : undefined}
              />
              <span className="truncate">{project.title}</span>
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
