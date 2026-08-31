import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertCircle,
  Archive,
  ChevronRight,
  CloudCog,
  FolderOpen,
  FolderKanban,
  MoreHorizontal,
  Pencil,
  Plus,
  RotateCcw,
  X,
} from 'lucide-react';
import { useNavigate } from 'react-router';
import { defineMessages, useIntl } from '../../i18n';
import {
  createProject,
  listProjects,
  setProjectArchived,
  uniqueProjectSlug,
  updateProject,
  type AccordLockProject,
  type ProjectInput,
} from '../../acp/projects';
import type { AccordLockEnvironmentProfileSummary } from '../../accordlock/environmentProfiles';
import { acpListSessions } from '../../acp/sessions';
import { getInitialWorkingDir } from '../../utils/workingDir';
import { MainPanelLayout } from '../Layout/MainPanelLayout';
import { Button } from '../ui/button';
import { Card } from '../ui/card';
import { ConfirmationModal } from '../ui/ConfirmationModal';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../ui/dialog';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../ui/dropdown-menu';
import { Input } from '../ui/input';
import { Skeleton } from '../ui/skeleton';

const i18n = defineMessages({
  title: { id: 'projects.title', defaultMessage: 'Projects' },
  description: {
    id: 'projects.description',
    defaultMessage: 'Keep related tasks and folders together.',
  },
  newProject: { id: 'projects.newProject', defaultMessage: 'New project' },
  activeProjects: { id: 'projects.activeProjects', defaultMessage: 'Active projects' },
  archivedProjects: { id: 'projects.archivedProjects', defaultMessage: 'Archived' },
  emptyTitle: { id: 'projects.empty.title', defaultMessage: 'No projects yet' },
  emptyDescription: {
    id: 'projects.empty.description',
    defaultMessage: 'Create one to keep related work together.',
  },
  noArchivedTitle: { id: 'projects.archived.empty.title', defaultMessage: 'No archived projects' },
  errorTitle: { id: 'projects.error.title', defaultMessage: 'Couldn’t load projects' },
  errorDescription: {
    id: 'projects.error.description',
    defaultMessage: 'Check the connection and try again.',
  },
  tryAgain: { id: 'projects.tryAgain', defaultMessage: 'Try again' },
  taskCount: {
    id: 'projects.taskCount',
    defaultMessage: '{count, plural, one {# task} other {# tasks}}',
  },
  folderCount: {
    id: 'projects.folderCount',
    defaultMessage: '{count, plural, one {# folder} other {# folders}}',
  },
  edit: { id: 'projects.action.edit', defaultMessage: 'Edit' },
  archive: { id: 'projects.action.archive', defaultMessage: 'Archive' },
  restore: { id: 'projects.action.restore', defaultMessage: 'Restore' },
  moreActions: { id: 'projects.action.more', defaultMessage: 'More actions for {name}' },
  openProject: { id: 'projects.action.open', defaultMessage: 'Open {name}' },
  archiveTitle: { id: 'projects.archive.title', defaultMessage: 'Archive project?' },
  archiveDescription: {
    id: 'projects.archive.description',
    defaultMessage: '“{name}” moves to Archived. Its tasks stay available.',
  },
  actionFailed: {
    id: 'projects.action.failed',
    defaultMessage: 'The project could not be updated. Try again.',
  },
  editorCreateTitle: { id: 'projects.editor.createTitle', defaultMessage: 'New project' },
  editorEditTitle: { id: 'projects.editor.editTitle', defaultMessage: 'Edit project' },
  editorDescription: {
    id: 'projects.editor.description',
    defaultMessage: 'Choose its folders and task guidance.',
  },
  nameLabel: { id: 'projects.editor.name', defaultMessage: 'Project name' },
  namePlaceholder: { id: 'projects.editor.namePlaceholder', defaultMessage: 'Website launch' },
  descriptionLabel: { id: 'projects.editor.summary', defaultMessage: 'Description' },
  descriptionPlaceholder: {
    id: 'projects.editor.summaryPlaceholder',
    defaultMessage: 'What this project is for',
  },
  optional: { id: 'projects.editor.optional', defaultMessage: 'Optional' },
  foldersLabel: { id: 'projects.editor.folders', defaultMessage: 'Folders' },
  foldersHint: {
    id: 'projects.editor.foldersHint',
    defaultMessage: 'Add every folder that belongs to this project.',
  },
  folderPlaceholder: {
    id: 'projects.editor.folderPlaceholder',
    defaultMessage: 'Path to a folder',
  },
  addFolder: { id: 'projects.editor.addFolder', defaultMessage: 'Add folder' },
  chooseFolder: {
    id: 'projects.editor.chooseFolder',
    defaultMessage: 'Choose folder {number}',
  },
  chooseFolderFailed: {
    id: 'projects.editor.chooseFolderFailed',
    defaultMessage: 'The folder picker could not be opened. Try again.',
  },
  removeFolder: { id: 'projects.editor.removeFolder', defaultMessage: 'Remove folder {number}' },
  instructionsLabel: {
    id: 'projects.editor.instructions',
    defaultMessage: 'Project instructions',
  },
  instructionsHint: {
    id: 'projects.editor.instructionsHint',
    defaultMessage: 'Guidance used for work in this project.',
  },
  addInstructions: {
    id: 'projects.editor.addInstructions',
    defaultMessage: 'Add instructions',
  },
  editInstructions: {
    id: 'projects.editor.editInstructions',
    defaultMessage: 'Edit instructions',
  },
  instructionsPlaceholder: {
    id: 'projects.editor.instructionsPlaceholder',
    defaultMessage: 'Conventions, constraints, and useful context',
  },
  environmentLabel: {
    id: 'projects.editor.environment',
    defaultMessage: 'Deployment environment',
  },
  environmentHint: {
    id: 'projects.editor.environmentHint',
    defaultMessage: 'Use this project for deployment checks.',
  },
  noEnvironment: {
    id: 'projects.editor.noEnvironment',
    defaultMessage: 'No deployment environment',
  },
  environmentsUnavailable: {
    id: 'projects.editor.environmentsUnavailable',
    defaultMessage: "Couldn't load deployment environments.",
  },
  colorLabel: { id: 'projects.editor.color', defaultMessage: 'Color' },
  useColor: { id: 'projects.editor.useColor', defaultMessage: 'Use {name}' },
  cancel: { id: 'projects.editor.cancel', defaultMessage: 'Cancel' },
  create: { id: 'projects.editor.create', defaultMessage: 'Create project' },
  save: { id: 'projects.editor.save', defaultMessage: 'Save changes' },
  saving: { id: 'projects.editor.saving', defaultMessage: 'Saving…' },
  nameRequired: { id: 'projects.editor.nameRequired', defaultMessage: 'Enter a project name.' },
  folderRequired: {
    id: 'projects.editor.folderRequired',
    defaultMessage: 'Add at least one folder.',
  },
  saveFailed: {
    id: 'projects.editor.saveFailed',
    defaultMessage: 'The project could not be saved. Try again.',
  },
});

const PROJECT_COLORS = [
  { name: 'Slate', value: '#64748B' },
  { name: 'Indigo', value: '#6366F1' },
  { name: 'Teal', value: '#0F766E' },
  { name: 'Amber', value: '#B45309' },
  { name: 'Rose', value: '#BE123C' },
  { name: 'Violet', value: '#7C3AED' },
] as const;

const DEFAULT_PROJECT_COLOR = PROJECT_COLORS[1].value;

function sortProjects(projects: AccordLockProject[]): AccordLockProject[] {
  return [...projects].sort(
    (left, right) =>
      Number(left.archived) - Number(right.archived) ||
      left.title.localeCompare(right.title, undefined, { sensitivity: 'base' })
  );
}

export async function loadProjectTaskCounts(): Promise<Map<string, number>> {
  const counts = new Map<string, number>();
  const seenCursors = new Set<string>();
  let cursor: string | null | undefined;

  do {
    const page = await acpListSessions(cursor);
    for (const task of page.sessions) {
      if (!task.projectId) continue;
      counts.set(task.projectId, (counts.get(task.projectId) ?? 0) + 1);
    }
    cursor = page.nextCursor;
    if (cursor && seenCursors.has(cursor)) break;
    if (cursor) seenCursors.add(cursor);
  } while (cursor);

  return counts;
}

interface ProjectEditorDialogProps {
  open: boolean;
  project: AccordLockProject | null;
  initialWorkingDir: string;
  onClose: () => void;
  onSave: (input: ProjectInput) => Promise<void>;
}

function ProjectEditorDialog({
  open,
  project,
  initialWorkingDir,
  onClose,
  onSave,
}: ProjectEditorDialogProps) {
  const intl = useIntl();
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [workingDirs, setWorkingDirs] = useState<string[]>([]);
  const [instructions, setInstructions] = useState('');
  const [color, setColor] = useState<string>(DEFAULT_PROJECT_COLOR);
  const [deploymentEnvironmentId, setDeploymentEnvironmentId] = useState<string | null>(null);
  const [environments, setEnvironments] = useState<AccordLockEnvironmentProfileSummary[]>([]);
  const [environmentsUnavailable, setEnvironmentsUnavailable] = useState(false);
  const [showInstructions, setShowInstructions] = useState(false);
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open) return;
    setTitle(project?.title ?? '');
    setDescription(project?.description ?? '');
    setWorkingDirs(
      project?.workingDirs.length
        ? project.workingDirs
        : initialWorkingDir
          ? [initialWorkingDir]
          : ['']
    );
    setInstructions(project?.instructions ?? '');
    setColor(project?.color ?? DEFAULT_PROJECT_COLOR);
    setDeploymentEnvironmentId(project?.deploymentEnvironmentId ?? null);
    setEnvironmentsUnavailable(false);
    setShowInstructions(Boolean(project?.instructions));
    setFieldError(null);
    setSaveError(null);
    setSaving(false);
  }, [initialWorkingDir, open, project]);

  useEffect(() => {
    if (!open || typeof window.electron.listAccordLockEnvironmentProfiles !== 'function') return;
    let active = true;
    void window.electron
      .listAccordLockEnvironmentProfiles()
      .then((profiles) => {
        if (!active) return;
        setEnvironments(profiles);
        setEnvironmentsUnavailable(false);
      })
      .catch(() => {
        if (!active) return;
        setEnvironments([]);
        setEnvironmentsUnavailable(true);
      });
    return () => {
      active = false;
    };
  }, [open]);

  const setFolder = (index: number, value: string) => {
    setWorkingDirs((current) =>
      current.map((folder, position) => (position === index ? value : folder))
    );
  };

  const removeFolder = (index: number) => {
    setWorkingDirs((current) => current.filter((_, position) => position !== index));
  };

  const chooseFolder = async (index: number) => {
    setFieldError(null);
    try {
      const selectedFolder = await window.electron.selectProjectFolder();
      if (selectedFolder) setFolder(index, selectedFolder);
    } catch {
      setFieldError(intl.formatMessage(i18n.chooseFolderFailed));
    }
  };

  const submit = async () => {
    const normalizedTitle = title.trim();
    const normalizedFolders = workingDirs.map((folder) => folder.trim()).filter(Boolean);
    if (!normalizedTitle) {
      setFieldError(intl.formatMessage(i18n.nameRequired));
      return;
    }
    if (normalizedFolders.length === 0) {
      setFieldError(intl.formatMessage(i18n.folderRequired));
      return;
    }

    setFieldError(null);
    setSaveError(null);
    setSaving(true);
    try {
      await onSave({
        title: normalizedTitle,
        description,
        instructions,
        workingDirs: normalizedFolders,
        color,
        ...(deploymentEnvironmentId
          ? { deploymentEnvironmentId }
          : project?.deploymentEnvironmentId
            ? { deploymentEnvironmentId: null }
            : {}),
      });
    } catch {
      setSaveError(intl.formatMessage(i18n.saveFailed));
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(nextOpen) => !nextOpen && !saving && onClose()}>
      <DialogContent className="max-h-[min(760px,calc(100vh-32px))] overflow-y-auto sm:max-w-[560px]">
        <DialogHeader>
          <DialogTitle>
            {intl.formatMessage(project ? i18n.editorEditTitle : i18n.editorCreateTitle)}
          </DialogTitle>
          <DialogDescription>{intl.formatMessage(i18n.editorDescription)}</DialogDescription>
        </DialogHeader>

        <div className="space-y-5 py-1">
          <label className="block space-y-1.5" htmlFor="project-name">
            <span className="text-sm font-medium text-text-primary">
              {intl.formatMessage(i18n.nameLabel)}
            </span>
            <Input
              id="project-name"
              value={title}
              onChange={(event) => setTitle(event.target.value)}
              placeholder={intl.formatMessage(i18n.namePlaceholder)}
              autoFocus
              maxLength={120}
              disabled={saving}
            />
          </label>

          <label className="block space-y-1.5" htmlFor="project-description">
            <span className="flex items-baseline gap-2 text-sm font-medium text-text-primary">
              {intl.formatMessage(i18n.descriptionLabel)}
              <span className="text-xs font-normal text-text-tertiary">
                {intl.formatMessage(i18n.optional)}
              </span>
            </span>
            <Input
              id="project-description"
              aria-label={intl.formatMessage(i18n.descriptionLabel)}
              value={description}
              onChange={(event) => setDescription(event.target.value)}
              placeholder={intl.formatMessage(i18n.descriptionPlaceholder)}
              maxLength={240}
              disabled={saving}
            />
          </label>

          <fieldset className="space-y-2">
            <legend className="text-sm font-medium text-text-primary">
              {intl.formatMessage(i18n.foldersLabel)}
            </legend>
            <p className="text-xs text-text-tertiary">{intl.formatMessage(i18n.foldersHint)}</p>
            <div className="space-y-2">
              {workingDirs.map((folder, index) => (
                <div className="flex gap-2" key={`${index}-${workingDirs.length}`}>
                  <Input
                    aria-label={`${intl.formatMessage(i18n.foldersLabel)} ${index + 1}`}
                    value={folder}
                    onChange={(event) => setFolder(index, event.target.value)}
                    placeholder={intl.formatMessage(i18n.folderPlaceholder)}
                    disabled={saving}
                  />
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    shape="round"
                    aria-label={intl.formatMessage(i18n.chooseFolder, { number: index + 1 })}
                    title={intl.formatMessage(i18n.chooseFolder, { number: index + 1 })}
                    onClick={() => void chooseFolder(index)}
                    disabled={saving}
                  >
                    <FolderOpen className="h-4 w-4" />
                  </Button>
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    shape="round"
                    aria-label={intl.formatMessage(i18n.removeFolder, { number: index + 1 })}
                    onClick={() => removeFolder(index)}
                    disabled={saving}
                  >
                    <X className="h-4 w-4" />
                  </Button>
                </div>
              ))}
            </div>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="-ml-2 gap-2"
              onClick={() => setWorkingDirs((current) => [...current, ''])}
              disabled={saving}
            >
              <Plus className="h-4 w-4" />
              {intl.formatMessage(i18n.addFolder)}
            </Button>
          </fieldset>

          <section className="rounded-xl border border-border-secondary bg-background-secondary/30 p-3.5">
            <div className="flex items-center justify-between gap-4">
              <div>
                <div className="text-sm font-medium text-text-primary">
                  {intl.formatMessage(i18n.instructionsLabel)}
                </div>
                <p className="mt-0.5 text-xs leading-5 text-text-tertiary">
                  {intl.formatMessage(i18n.instructionsHint)}
                </p>
              </div>
              <Button
                type="button"
                variant="outline"
                size="sm"
                aria-expanded={showInstructions}
                onClick={() => setShowInstructions(true)}
                disabled={saving || showInstructions}
              >
                {intl.formatMessage(instructions ? i18n.editInstructions : i18n.addInstructions)}
              </Button>
            </div>
            {showInstructions && (
              <textarea
                aria-label={intl.formatMessage(i18n.instructionsLabel)}
                value={instructions}
                onChange={(event) => setInstructions(event.target.value)}
                placeholder={intl.formatMessage(i18n.instructionsPlaceholder)}
                className="mt-3 min-h-28 w-full resize-y rounded-lg border border-border-primary bg-background-primary px-3 py-2 text-sm leading-6 text-text-primary outline-none transition-colors placeholder:text-text-tertiary focus:border-border-secondary"
                disabled={saving}
              />
            )}
          </section>

          <section className="rounded-xl border border-border-secondary bg-background-secondary/30 p-3.5">
            <div className="flex items-start gap-3">
              <CloudCog
                aria-hidden="true"
                className="mt-0.5 h-4 w-4 shrink-0 text-text-secondary"
              />
              <label className="min-w-0 flex-1 space-y-2" htmlFor="project-environment">
                <span className="block text-sm font-medium text-text-primary">
                  {intl.formatMessage(i18n.environmentLabel)}
                </span>
                <span className="block text-xs leading-5 text-text-tertiary">
                  {intl.formatMessage(i18n.environmentHint)}
                </span>
                <select
                  id="project-environment"
                  value={deploymentEnvironmentId ?? ''}
                  onChange={(event) => setDeploymentEnvironmentId(event.target.value || null)}
                  disabled={saving || environmentsUnavailable}
                  className="h-9 w-full rounded-lg border border-border-primary bg-background-primary px-3 text-sm text-text-primary outline-none focus:border-border-secondary disabled:opacity-60"
                >
                  <option value="">{intl.formatMessage(i18n.noEnvironment)}</option>
                  {environments.map((environment) => (
                    <option key={environment.id} value={environment.id}>
                      {environment.name}
                    </option>
                  ))}
                </select>
                {environmentsUnavailable && (
                  <span className="block text-xs text-text-danger">
                    {intl.formatMessage(i18n.environmentsUnavailable)}
                  </span>
                )}
              </label>
            </div>
          </section>

          <fieldset>
            <legend className="mb-2 text-sm font-medium text-text-primary">
              {intl.formatMessage(i18n.colorLabel)}
            </legend>
            <div className="flex gap-2.5">
              {PROJECT_COLORS.map((option) => (
                <button
                  type="button"
                  key={option.value}
                  aria-label={intl.formatMessage(i18n.useColor, { name: option.name })}
                  aria-pressed={color === option.value}
                  className="h-7 w-7 rounded-full border-2 border-transparent outline-none ring-offset-2 ring-offset-background-primary transition-transform hover:scale-105 focus-visible:ring-2 focus-visible:ring-border-secondary aria-pressed:border-text-primary"
                  style={{ backgroundColor: option.value }}
                  onClick={() => setColor(option.value)}
                  disabled={saving}
                />
              ))}
            </div>
          </fieldset>

          {(fieldError || saveError) && (
            <p role="alert" className="text-sm text-text-danger">
              {fieldError ?? saveError}
            </p>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={saving}>
            {intl.formatMessage(i18n.cancel)}
          </Button>
          <Button onClick={() => void submit()} disabled={saving}>
            {intl.formatMessage(saving ? i18n.saving : project ? i18n.save : i18n.create)}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ProjectSkeleton() {
  return (
    <Card className="flex min-h-[88px] items-center gap-4 border-border-secondary px-5 py-4">
      <Skeleton className="h-3 w-3 rounded-full" />
      <div className="flex-1 space-y-2">
        <Skeleton className="h-5 w-44" />
        <Skeleton className="h-4 w-64" />
      </div>
    </Card>
  );
}

interface ProjectRowProps {
  project: AccordLockProject;
  taskCount: number;
  busy: boolean;
  onOpen: () => void;
  onEdit: () => void;
  onArchive: () => void;
  onRestore: () => void;
}

function ProjectRow({
  project,
  taskCount,
  busy,
  onOpen,
  onEdit,
  onArchive,
  onRestore,
}: ProjectRowProps) {
  const intl = useIntl();
  return (
    <Card className="group flex min-h-[88px] flex-row items-stretch gap-0 overflow-hidden border-border-secondary p-0 transition-colors hover:bg-background-secondary/35">
      <button
        type="button"
        onClick={onOpen}
        aria-label={intl.formatMessage(i18n.openProject, { name: project.title })}
        className="flex min-w-0 flex-1 items-center gap-4 px-5 py-4 text-left outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring"
      >
        <span
          className="h-3 w-3 shrink-0 rounded-full"
          style={{ backgroundColor: project.color ?? DEFAULT_PROJECT_COLOR }}
          aria-hidden="true"
        />
        <div className="min-w-0 flex-1">
          <div className="truncate text-[15px] font-medium text-text-primary">{project.title}</div>
          {project.description && (
            <p className="mt-0.5 truncate text-sm text-text-secondary">{project.description}</p>
          )}
          <div className="mt-1 flex items-center gap-2 text-xs text-text-tertiary">
            <span>{intl.formatMessage(i18n.taskCount, { count: taskCount })}</span>
            <span aria-hidden="true">·</span>
            <span>
              {intl.formatMessage(i18n.folderCount, { count: project.workingDirs.length })}
            </span>
          </div>
        </div>
        <ChevronRight className="h-4 w-4 shrink-0 text-text-tertiary opacity-0 transition-opacity group-hover:opacity-100" />
      </button>
      <div className="flex items-center pr-3">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="sm"
              shape="round"
              aria-label={intl.formatMessage(i18n.moreActions, { name: project.title })}
              disabled={busy || !project.writable}
              className="opacity-60 transition-opacity group-hover:opacity-100 data-[state=open]:opacity-100"
            >
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onSelect={onEdit}>
              <Pencil />
              {intl.formatMessage(i18n.edit)}
            </DropdownMenuItem>
            {project.archived ? (
              <DropdownMenuItem onSelect={onRestore}>
                <RotateCcw />
                {intl.formatMessage(i18n.restore)}
              </DropdownMenuItem>
            ) : (
              <DropdownMenuItem onSelect={onArchive}>
                <Archive />
                {intl.formatMessage(i18n.archive)}
              </DropdownMenuItem>
            )}
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </Card>
  );
}

export default function ProjectsView() {
  const intl = useIntl();
  const navigate = useNavigate();
  const initialWorkingDir = getInitialWorkingDir();
  const [projects, setProjects] = useState<AccordLockProject[]>([]);
  const [taskCounts, setTaskCounts] = useState<Map<string, number>>(new Map());
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [actionError, setActionError] = useState(false);
  const [showArchived, setShowArchived] = useState(false);
  const [editorOpen, setEditorOpen] = useState(false);
  const [editingProject, setEditingProject] = useState<AccordLockProject | null>(null);
  const [archiveCandidate, setArchiveCandidate] = useState<AccordLockProject | null>(null);
  const [busyProjectId, setBusyProjectId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError(false);
    try {
      const [loadedProjects, loadedCounts] = await Promise.all([
        listProjects(),
        loadProjectTaskCounts().catch(() => new Map<string, number>()),
      ]);
      setProjects(loadedProjects);
      setTaskCounts(loadedCounts);
    } catch {
      setLoadError(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const activeProjects = useMemo(() => projects.filter((project) => !project.archived), [projects]);
  const archivedProjects = useMemo(
    () => projects.filter((project) => project.archived),
    [projects]
  );
  const visibleProjects = showArchived ? archivedProjects : activeProjects;

  const openCreate = () => {
    setEditingProject(null);
    setEditorOpen(true);
  };

  const openEdit = (project: AccordLockProject) => {
    setEditingProject(project);
    setEditorOpen(true);
  };

  const saveProject = async (input: ProjectInput) => {
    const saved = editingProject
      ? await updateProject(editingProject, input)
      : await createProject(
          uniqueProjectSlug(
            input.title,
            projects.map((project) => project.id)
          ),
          input
        );
    setProjects((current) =>
      sortProjects([...current.filter((project) => project.id !== saved.id), saved])
    );
    setEditorOpen(false);
    setEditingProject(null);
  };

  const changeArchivedState = async (project: AccordLockProject, archived: boolean) => {
    setBusyProjectId(project.id);
    setActionError(false);
    try {
      const updated = await setProjectArchived(project, archived);
      setProjects((current) =>
        sortProjects([...current.filter((candidate) => candidate.id !== updated.id), updated])
      );
      if (!archived && archivedProjects.length === 1) {
        setShowArchived(false);
      }
    } catch {
      setActionError(true);
    } finally {
      setBusyProjectId(null);
      setArchiveCandidate(null);
    }
  };

  const renderContent = () => {
    if (loading) {
      return (
        <div className="space-y-2">
          <ProjectSkeleton />
          <ProjectSkeleton />
          <ProjectSkeleton />
        </div>
      );
    }

    if (loadError) {
      return (
        <div className="flex min-h-[320px] flex-col items-center justify-center text-center">
          <AlertCircle className="mb-4 h-9 w-9 text-text-tertiary" />
          <h2 className="text-lg font-medium text-text-primary">
            {intl.formatMessage(i18n.errorTitle)}
          </h2>
          <p className="mt-1 text-sm text-text-secondary">
            {intl.formatMessage(i18n.errorDescription)}
          </p>
          <Button className="mt-5" variant="outline" onClick={() => void load()}>
            {intl.formatMessage(i18n.tryAgain)}
          </Button>
        </div>
      );
    }

    if (visibleProjects.length === 0) {
      return (
        <div className="flex min-h-[320px] flex-col items-center justify-center text-center">
          <div className="mb-4 rounded-2xl border border-border-secondary bg-background-secondary/45 p-3">
            <FolderKanban className="h-6 w-6 text-text-secondary" />
          </div>
          <h2 className="text-lg font-medium text-text-primary">
            {intl.formatMessage(showArchived ? i18n.noArchivedTitle : i18n.emptyTitle)}
          </h2>
          {!showArchived && (
            <>
              <p className="mt-1 text-sm text-text-secondary">
                {intl.formatMessage(i18n.emptyDescription)}
              </p>
              <Button className="mt-5 gap-2" onClick={openCreate}>
                <Plus className="h-4 w-4" />
                {intl.formatMessage(i18n.newProject)}
              </Button>
            </>
          )}
        </div>
      );
    }

    return (
      <div className="space-y-2 pb-8">
        {visibleProjects.map((project) => (
          <ProjectRow
            key={project.id}
            project={project}
            taskCount={taskCounts.get(project.id) ?? 0}
            busy={busyProjectId === project.id}
            onOpen={() => navigate(`/sessions?projectId=${encodeURIComponent(project.id)}`)}
            onEdit={() => openEdit(project)}
            onArchive={() => setArchiveCandidate(project)}
            onRestore={() => void changeArchivedState(project, false)}
          />
        ))}
      </div>
    );
  };

  return (
    <MainPanelLayout>
      <div className="flex min-h-0 flex-1 flex-col">
        <header className="px-8 pb-6 pt-12">
          <div className="mx-auto flex w-full max-w-[900px] items-start justify-between gap-6">
            <div>
              <h1 className="text-4xl font-light tracking-[-0.035em] text-text-primary">
                {intl.formatMessage(i18n.title)}
              </h1>
              <p className="mt-2 text-sm text-text-secondary">
                {intl.formatMessage(i18n.description)}
              </p>
            </div>
            {!loading && !loadError && visibleProjects.length > 0 && (
              <Button className="gap-2" onClick={openCreate}>
                <Plus className="h-4 w-4" />
                {intl.formatMessage(i18n.newProject)}
              </Button>
            )}
          </div>
        </header>

        <div className="min-h-0 flex-1 overflow-y-auto px-8">
          <div className="mx-auto w-full max-w-[900px]">
            {archivedProjects.length > 0 && !loadError && (
              <div className="mb-3 flex justify-end">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowArchived((current) => !current)}
                >
                  {intl.formatMessage(showArchived ? i18n.activeProjects : i18n.archivedProjects)}
                  {!showArchived && ` (${archivedProjects.length})`}
                </Button>
              </div>
            )}
            {actionError && (
              <p role="alert" className="mb-3 text-sm text-text-danger">
                {intl.formatMessage(i18n.actionFailed)}
              </p>
            )}
            {renderContent()}
          </div>
        </div>
      </div>

      <ProjectEditorDialog
        open={editorOpen}
        project={editingProject}
        initialWorkingDir={initialWorkingDir}
        onClose={() => {
          setEditorOpen(false);
          setEditingProject(null);
        }}
        onSave={saveProject}
      />

      <ConfirmationModal
        isOpen={Boolean(archiveCandidate)}
        title={intl.formatMessage(i18n.archiveTitle)}
        message={intl.formatMessage(i18n.archiveDescription, {
          name: archiveCandidate?.title ?? '',
        })}
        confirmLabel={intl.formatMessage(i18n.archive)}
        cancelLabel={intl.formatMessage(i18n.cancel)}
        onCancel={() => setArchiveCandidate(null)}
        onConfirm={() => {
          if (archiveCandidate) void changeArchivedState(archiveCandidate, true);
        }}
        isSubmitting={Boolean(archiveCandidate && busyProjectId === archiveCandidate.id)}
      />
    </MainPanelLayout>
  );
}
