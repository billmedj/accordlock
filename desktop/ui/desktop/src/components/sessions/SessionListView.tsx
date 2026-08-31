import { AppEvents } from '../../constants/events';
import { revokeBeforeAccordLockSessionDeletion } from '../../accordlock/taskBridge';
import React, { useEffect, useState, useRef, useCallback, useMemo, startTransition } from 'react';
import { defineMessages, useIntl } from '../../i18n';
import {
  MessageSquareText,
  AlertCircle,
  Calendar,
  Folder,
  Edit2,
  Archive,
  ArchiveRestore,
  Download,
  Upload,
  Share2,
  LoaderCircle,
  ExternalLink,
  Copy,
  Check,
  FolderKanban,
  MoreHorizontal,
  X,
} from 'lucide-react';
import { Card } from '../ui/card';
import { Button } from '../ui/button';
import { ScrollArea } from '../ui/scroll-area';
import { formatMessageTimestamp } from '../../utils/timeUtils';
import { SearchView } from '../conversation/SearchView';
import { MainPanelLayout } from '../Layout/MainPanelLayout';
import { groupSessionsByDate, sessionActivityAt, type DateGroup } from '../../utils/dateUtils';
import { errorMessage } from '../../utils/conversionUtils';
import { Skeleton } from '../ui/skeleton';
import { toast } from 'react-toastify';
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
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '../ui/dropdown-menu';
import {
  acpArchiveSession,
  acpExportSession,
  acpForkSession,
  acpImportSession,
  acpListSessions,
  acpRenameSession,
  acpShareSessionNostr,
  acpUnarchiveSession,
  type SessionListItem,
} from '../../acp/sessions';
import type { SessionExportFormat } from '@aaif/goose-sdk';
import { acpChatSessionActions } from '../../acp/chatSessionStore';
import { cancelAcpPermissionRequestsForSession } from '../../acp/permissionRequests';
import { cancelAcpElicitationRequestsForSession } from '../../acp/elicitationRequests';
import { normalizeWorkspacePathForDisplay, splitDirPath } from '../bottom_menu/DirSwitcher';
import {
  assignTaskToProject,
  listProjects,
  PROJECTS_CHANGED_EVENT,
  type AccordLockProject,
} from '../../acp/projects';

const i18n = defineMessages({
  editSessionTitle: { id: 'sessions.edit.title', defaultMessage: 'Rename task' },
  editSessionPlaceholder: {
    id: 'sessions.edit.placeholder',
    defaultMessage: 'Enter a task name',
  },
  cancel: { id: 'sessions.cancel', defaultMessage: 'Cancel' },
  save: { id: 'sessions.save', defaultMessage: 'Save' },
  saving: { id: 'sessions.saving', defaultMessage: 'Saving...' },
  sessionUpdated: {
    id: 'sessions.toast.updated',
    defaultMessage: 'Task renamed',
  },
  sessionUpdateFailed: {
    id: 'sessions.toast.updateFailed',
    defaultMessage: 'Failed to rename task: {error}',
  },
  chatHistory: { id: 'sessions.chatHistory', defaultMessage: 'Tasks' },
  importSession: { id: 'sessions.import', defaultMessage: 'Import' },
  importNostrSession: { id: 'sessions.importNostr', defaultMessage: 'Import link' },
  importNostrTitle: { id: 'sessions.importNostr.title', defaultMessage: 'Import shared task' },
  importNostrDesc: {
    id: 'sessions.importNostr.description',
    defaultMessage: 'Paste an encrypted AccordLock share link.',
  },
  importNostrPlaceholder: {
    id: 'sessions.importNostr.placeholder',
    defaultMessage: 'accordlock://sessions/nostr?nevent=...&key=...',
  },
  importing: { id: 'sessions.importing', defaultMessage: 'Importing...' },
  searchPlaceholder: { id: 'sessions.searchPlaceholder', defaultMessage: 'Search tasks…' },
  errorLoading: { id: 'sessions.error.loading', defaultMessage: 'Could not load tasks' },
  tryAgain: { id: 'sessions.error.tryAgain', defaultMessage: 'Try again' },
  noSessions: { id: 'sessions.empty.title', defaultMessage: 'No tasks yet' },
  noSessionsDesc: {
    id: 'sessions.empty.description',
    defaultMessage: 'Start a task to see it here.',
  },
  noMatching: { id: 'sessions.search.noResults', defaultMessage: 'No matching tasks' },
  noMatchingDesc: {
    id: 'sessions.search.noResultsDesc',
    defaultMessage: 'Try another search.',
  },
  loadingMore: { id: 'sessions.loadingMore', defaultMessage: 'Loading more tasks…' },
  archiveTitle: { id: 'sessions.archive.title', defaultMessage: 'Archive task?' },
  archiveMessage: {
    id: 'sessions.archive.message',
    defaultMessage: 'Archive “{name}”? You can restore it later.',
  },
  duplicateSuccess: {
    id: 'sessions.toast.duplicated',
    defaultMessage: 'Task "{name}" duplicated',
  },
  duplicateFailed: {
    id: 'sessions.toast.duplicateFailed',
    defaultMessage: 'Failed to duplicate task: {error}',
  },
  archiveSuccess: { id: 'sessions.toast.archived', defaultMessage: 'Task archived' },
  archiveFailed: {
    id: 'sessions.toast.archiveFailed',
    defaultMessage: 'Couldn’t archive “{name}”. {error}',
  },
  restoreSuccess: { id: 'sessions.toast.restored', defaultMessage: 'Task restored' },
  restoreFailed: {
    id: 'sessions.toast.restoreFailed',
    defaultMessage: 'Couldn’t restore “{name}”. {error}',
  },
  importSuccess: { id: 'sessions.toast.imported', defaultMessage: 'Task imported' },
  importFailed: {
    id: 'sessions.toast.importFailed',
    defaultMessage: 'Failed to import task: {error}',
  },
  exportSuccess: { id: 'sessions.toast.exported', defaultMessage: 'Task exported' },
  exportFailed: {
    id: 'sessions.toast.exportFailed',
    defaultMessage: 'Failed to export task: {error}',
  },
  shareNostrSuccess: {
    id: 'sessions.toast.shareNostr',
    defaultMessage: 'Encrypted Nostr share link created',
  },
  shareNostrFailed: {
    id: 'sessions.toast.shareNostrFailed',
    defaultMessage: 'Failed to create Nostr share link: {error}',
  },
  copied: { id: 'sessions.toast.copied', defaultMessage: 'Copied to clipboard' },
  openInNewWindow: { id: 'sessions.action.openNewWindow', defaultMessage: 'Open in new window' },
  editSessionName: { id: 'sessions.action.editName', defaultMessage: 'Rename task' },
  duplicateSession: { id: 'sessions.action.duplicate', defaultMessage: 'Duplicate task' },
  archiveSession: { id: 'sessions.action.archive', defaultMessage: 'Archive task' },
  restoreSession: { id: 'sessions.action.restore', defaultMessage: 'Restore task' },
  exportSession: { id: 'sessions.action.export', defaultMessage: 'Export task' },
  exportAsJson: { id: 'sessions.action.exportJson', defaultMessage: 'JSON' },
  exportAsMarkdown: { id: 'sessions.action.exportMarkdown', defaultMessage: 'Markdown' },
  shareNostrSession: {
    id: 'sessions.action.shareNostr',
    defaultMessage: 'Create encrypted share link',
  },
  shareNostrTitle: {
    id: 'sessions.shareNostr.title',
    defaultMessage: 'Encrypted share link',
  },
  shareNostrDesc: {
    id: 'sessions.shareNostr.description',
    defaultMessage:
      'Anyone with this link can fetch and decrypt the session. Treat it like a secret.',
  },
  close: { id: 'sessions.close', defaultMessage: 'Close' },
  changeProject: { id: 'sessions.action.changeProject', defaultMessage: 'Move to project' },
  changeProjectTitle: { id: 'sessions.project.title', defaultMessage: 'Move task' },
  changeProjectDescription: {
    id: 'sessions.project.description',
    defaultMessage: 'Choose where “{name}” belongs.',
  },
  noProject: { id: 'sessions.project.none', defaultMessage: 'No project' },
  projectUpdated: { id: 'sessions.project.updated', defaultMessage: 'Project updated' },
  projectUpdateFailed: {
    id: 'sessions.project.updateFailed',
    defaultMessage: 'The task could not be moved. Try again.',
  },
  allTasks: { id: 'sessions.project.allTasks', defaultMessage: 'All tasks' },
  activeTasks: { id: 'sessions.active', defaultMessage: 'Active' },
  archivedTasks: { id: 'sessions.archived', defaultMessage: 'Archived' },
  noArchivedTasks: { id: 'sessions.archived.empty', defaultMessage: 'No archived tasks' },
  filteredEmptyTitle: {
    id: 'sessions.project.empty.title',
    defaultMessage: 'No tasks in this project',
  },
  filteredEmptyDescription: {
    id: 'sessions.project.empty.description',
    defaultMessage: 'New tasks started from a project folder appear here.',
  },
  moreActions: {
    id: 'sessions.action.more',
    defaultMessage: 'More actions for {name}',
  },
});

interface EditSessionModalProps {
  session: SessionListItem | null;
  isOpen: boolean;
  onClose: () => void;
  onSave: (sessionId: string, newDescription: string) => Promise<void>;
  disabled?: boolean;
}

const EditSessionModal = React.memo<EditSessionModalProps>(
  ({ session, isOpen, onClose, onSave, disabled = false }) => {
    const intl = useIntl();
    const [description, setDescription] = useState('');
    const [isUpdating, setIsUpdating] = useState(false);

    useEffect(() => {
      if (session && isOpen) {
        setDescription(session.name);
      } else if (!isOpen) {
        setDescription('');
        setIsUpdating(false);
      }
    }, [session, isOpen]);

    const handleSave = useCallback(async () => {
      if (!session || disabled) return;

      const trimmedDescription = description.trim();
      if (trimmedDescription === session.name) {
        onClose();
        return;
      }

      setIsUpdating(true);
      try {
        await acpRenameSession(session.id, trimmedDescription);
        await onSave(session.id, trimmedDescription);
        onClose();
        setTimeout(() => {
          toast.success(intl.formatMessage(i18n.sessionUpdated));
        }, 300);
      } catch (error) {
        const errMsg = errorMessage(error, 'Unknown error occurred');
        console.error('Failed to update session description:', errMsg);
        toast.error(intl.formatMessage(i18n.sessionUpdateFailed, { error: 'Try again.' }));
        setDescription(session.name);
      } finally {
        setIsUpdating(false);
      }
    }, [session, description, onSave, onClose, disabled, intl]);

    const handleCancel = useCallback(() => {
      if (!isUpdating) {
        onClose();
      }
    }, [onClose, isUpdating]);

    const handleKeyDown = useCallback(
      (e: React.KeyboardEvent<HTMLInputElement>) => {
        if (e.key === 'Enter' && !isUpdating) {
          handleSave();
        } else if (e.key === 'Escape' && !isUpdating) {
          handleCancel();
        }
      },
      [handleSave, handleCancel, isUpdating]
    );

    const handleInputChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
      setDescription(e.target.value);
    }, []);

    if (!isOpen || !session) return null;

    return (
      <div className="fixed inset-0 z-[300] flex items-center justify-center bg-black/50">
        <div className="bg-background-primary border border-border-primary rounded-lg p-6 w-[500px] max-w-[90vw]">
          <h3 className="text-lg font-medium text-text-primary mb-4">
            {intl.formatMessage(i18n.editSessionTitle)}
          </h3>

          <div className="space-y-4">
            <div>
              <input
                id="session-description"
                type="text"
                value={description}
                onChange={handleInputChange}
                className="w-full p-3 border border-border-primary rounded-lg bg-background-primary text-text-primary focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder={intl.formatMessage(i18n.editSessionPlaceholder)}
                autoFocus
                maxLength={200}
                onKeyDown={handleKeyDown}
                disabled={isUpdating || disabled}
              />
            </div>
          </div>

          <div className="flex justify-end space-x-3 mt-6">
            <Button onClick={handleCancel} variant="ghost" disabled={isUpdating || disabled}>
              {intl.formatMessage(i18n.cancel)}
            </Button>
            <Button
              onClick={handleSave}
              disabled={!description.trim() || isUpdating || disabled}
              variant="default"
            >
              {isUpdating ? intl.formatMessage(i18n.saving) : intl.formatMessage(i18n.save)}
            </Button>
          </div>
        </div>
      </div>
    );
  }
);

EditSessionModal.displayName = 'EditSessionModal';

// Debounce hook for search
function useDebounce<T>(value: T, delay: number): T {
  const [debouncedValue, setDebouncedValue] = useState<T>(value);

  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedValue(value);
    }, delay);

    return () => {
      window.clearTimeout(handler);
    };
  }, [value, delay]);

  return debouncedValue;
}

function readableProjectId(projectId: string): string {
  const value = projectId.replace(/[-_]+/gu, ' ').trim();
  if (!value) return 'Project';
  return value.charAt(0).toLocaleUpperCase('en-US') + value.slice(1);
}

interface SessionListViewProps {
  onSelectSession: (sessionId: string) => void;
  projectId?: string;
  onClearProjectFilter?: () => void;
}

const SessionListView: React.FC<SessionListViewProps> = React.memo(
  ({ onSelectSession, projectId, onClearProjectFilter }) => {
    const intl = useIntl();
    const [sessions, setSessions] = useState<SessionListItem[]>([]);
    const [projects, setProjects] = useState<AccordLockProject[]>([]);
    const [projectSession, setProjectSession] = useState<SessionListItem | null>(null);
    const [isAssigningProject, setIsAssigningProject] = useState(false);
    const [isPrefetchingSessions, setIsPrefetchingSessions] = useState(false);
    const [dateGroups, setDateGroups] = useState<DateGroup[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [showSkeleton, setShowSkeleton] = useState(true);
    const [showContent, setShowContent] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const [visibleGroupsCount, setVisibleGroupsCount] = useState(15);

    // Edit modal state
    const [showEditModal, setShowEditModal] = useState(false);
    const [editingSession, setEditingSession] = useState<SessionListItem | null>(null);

    const [showArchiveConfirmation, setShowArchiveConfirmation] = useState(false);
    const [sessionToArchive, setSessionToArchive] = useState<SessionListItem | null>(null);
    const [showArchivedTasks, setShowArchivedTasks] = useState(false);

    const [showImportLinkModal, setShowImportLinkModal] = useState(false);
    const [nostrImportLink, setNostrImportLink] = useState('');
    const [isImportingNostr, setIsImportingNostr] = useState(false);
    const [shareLink, setShareLink] = useState('');
    const [showShareLinkModal, setShowShareLinkModal] = useState(false);
    const [sharingSessionId, setSharingSessionId] = useState<string | null>(null);
    const [nostrEnabled, setNostrEnabled] = useState(false);

    // Search state for debouncing
    const [searchTerm, setSearchTerm] = useState('');
    const debouncedSearchTerm = useDebounce(searchTerm, 300); // 300ms debounce
    const debouncedSearchTermRef = useRef(debouncedSearchTerm);
    debouncedSearchTermRef.current = debouncedSearchTerm;

    const containerRef = useRef<HTMLDivElement>(null);
    const loadGenerationRef = useRef(0);
    const hasLoadedRef = useRef(false);

    const fileInputRef = useRef<HTMLInputElement>(null);

    const activeProjects = useMemo(
      () => projects.filter((project) => !project.archived),
      [projects]
    );
    const projectsById = useMemo(
      () => new Map(projects.map((project) => [project.id, project])),
      [projects]
    );
    const selectedProject = projectId ? projectsById.get(projectId) : undefined;
    const archivedTaskCount = useMemo(
      () => sessions.filter((session) => Boolean(session.archivedAt)).length,
      [sessions]
    );
    const filteredSessions = useMemo(() => {
      const archiveFiltered = sessions.filter(
        (session) => Boolean(session.archivedAt) === showArchivedTasks
      );
      return projectId
        ? archiveFiltered.filter((session) => session.projectId === projectId)
        : archiveFiltered;
    }, [projectId, sessions, showArchivedTasks]);

    const visibleDateGroups = useMemo(() => {
      return dateGroups.slice(0, visibleGroupsCount);
    }, [dateGroups, visibleGroupsCount]);

    const previousSearchTermRef = useRef('');
    useEffect(() => {
      const wasSearching = previousSearchTermRef.current.length > 0;
      const isSearching = debouncedSearchTerm.length > 0;
      previousSearchTermRef.current = debouncedSearchTerm;

      if (isSearching) {
        setVisibleGroupsCount(dateGroups.length);
      } else if (wasSearching) {
        setVisibleGroupsCount(15);
      }
    }, [debouncedSearchTerm, dateGroups.length]);

    const loadProjects = useCallback(async () => {
      try {
        setProjects(await listProjects());
      } catch (error) {
        console.error('Failed to load projects:', error);
      }
    }, []);

    useEffect(() => {
      void loadProjects();
      window.addEventListener(PROJECTS_CHANGED_EVENT, loadProjects);
      return () => window.removeEventListener(PROJECTS_CHANGED_EVENT, loadProjects);
    }, [loadProjects]);

    const loadRemainingSessionPages = useCallback(
      async (initialCursor: string, loadId: number, keyword?: string) => {
        let cursor: string | null = initialCursor;
        setIsPrefetchingSessions(true);

        try {
          while (cursor && loadGenerationRef.current === loadId) {
            const resp = await acpListSessions(cursor, { keyword });
            if (loadGenerationRef.current !== loadId) return;

            cursor = resp.nextCursor;
            startTransition(() => {
              setSessions((prev) => {
                const seen = new Set(prev.map((s) => s.id));
                return [...prev, ...resp.sessions.filter((s) => !seen.has(s.id))];
              });
            });
          }
        } catch (err) {
          console.error('Failed to load remaining sessions:', err);
        } finally {
          if (loadGenerationRef.current === loadId) {
            setIsPrefetchingSessions(false);
          }
        }
      },
      []
    );

    const loadSessions = useCallback(
      async (keyword: string = debouncedSearchTermRef.current) => {
        const loadId = loadGenerationRef.current + 1;
        loadGenerationRef.current = loadId;
        // Only show the skeleton on the first load; subsequent loads (e.g. typing a
        // search keyword) update the list in place without flashing the skeleton.
        const isFirstLoad = !hasLoadedRef.current;
        setIsPrefetchingSessions(false);
        setError(null);
        if (isFirstLoad) {
          setIsLoading(true);
          setShowSkeleton(true);
          setShowContent(false);
        }
        try {
          const resp = await acpListSessions(undefined, { keyword });
          if (loadGenerationRef.current !== loadId) return;
          hasLoadedRef.current = true;

          startTransition(() => {
            setSessions(resp.sessions);
          });

          if (resp.nextCursor) {
            void loadRemainingSessionPages(resp.nextCursor, loadId, keyword);
          }
        } catch (err) {
          if (loadGenerationRef.current !== loadId) return;

          console.error('Failed to load sessions:', err);
          setError('Failed to load sessions. Please try again later.');
          setSessions([]);
        } finally {
          if (loadGenerationRef.current === loadId && isFirstLoad) {
            setIsLoading(false);
          }
        }
      },
      [loadRemainingSessionPages]
    );

    const handleScroll = useCallback(
      (target: HTMLDivElement) => {
        const { scrollTop, scrollHeight, clientHeight } = target;
        const threshold = 200;

        if (scrollHeight - scrollTop - clientHeight >= threshold) return;

        if (visibleGroupsCount < dateGroups.length) {
          setVisibleGroupsCount((prev) => Math.min(prev + 5, dateGroups.length));
        }
      },
      [visibleGroupsCount, dateGroups.length]
    );

    useEffect(() => {
      loadSessions(debouncedSearchTerm);
      return () => {
        // Bump the generation so any in-flight load for the previous keyword is discarded.
        loadGenerationRef.current += 1;
      };
    }, [loadSessions, debouncedSearchTerm]);

    // AccordLock keeps network-based task sharing off unless a distribution
    // explicitly enables it.
    useEffect(() => {
      const config = window.electron.getConfig();
      setNostrEnabled(config.GOOSE_DISABLE_NOSTR_SHARING === false);
    }, []);

    // Timing logic to prevent flicker between skeleton and content on initial load
    useEffect(() => {
      if (!isLoading && showSkeleton) {
        setShowSkeleton(false);
        // Use startTransition for non-blocking content show
        startTransition(() => {
          setTimeout(() => {
            setShowContent(true);
          }, 10);
        });
      }
      return () => void 0;
    }, [isLoading, showSkeleton]);

    // Memoize date groups calculation to prevent unnecessary recalculations
    const memoizedDateGroups = useMemo(() => {
      if (filteredSessions.length > 0) {
        return groupSessionsByDate(filteredSessions);
      }
      return [];
    }, [filteredSessions]);

    // Update date groups when filtered sessions change
    useEffect(() => {
      startTransition(() => {
        setDateGroups(memoizedDateGroups);
      });
    }, [memoizedDateGroups]);

    // Handle immediate search input (updates search term for debouncing).
    const handleSearch = useCallback((term: string) => {
      setSearchTerm(term);
    }, []);

    // Handle modal close
    const handleModalClose = useCallback(() => {
      setShowEditModal(false);
      setEditingSession(null);
    }, []);

    const handleModalSave = useCallback(async (sessionId: string, newDescription: string) => {
      // Update state immediately for optimistic UI
      setSessions((prevSessions) =>
        prevSessions.map((s) =>
          s.id === sessionId ? { ...s, name: newDescription, user_set_name: true } : s
        )
      );
      window.dispatchEvent(
        new CustomEvent(AppEvents.SESSION_RENAMED, {
          detail: { sessionId, newName: newDescription, userInitiated: true },
        })
      );
    }, []);

    const handleEditSession = useCallback((session: SessionListItem) => {
      setEditingSession(session);
      setShowEditModal(true);
    }, []);

    const handleProjectSession = useCallback((session: SessionListItem) => {
      setProjectSession(session);
    }, []);

    const handleAssignProject = useCallback(
      async (nextProjectId: string | null) => {
        if (!projectSession || isAssigningProject) return;
        if ((projectSession.projectId ?? null) === nextProjectId) {
          setProjectSession(null);
          return;
        }

        setIsAssigningProject(true);
        try {
          await assignTaskToProject(projectSession.id, nextProjectId);
          setSessions((current) =>
            current.map((session) =>
              session.id === projectSession.id
                ? { ...session, projectId: nextProjectId ?? undefined }
                : session
            )
          );
          setProjectSession(null);
          toast.success(intl.formatMessage(i18n.projectUpdated));
        } catch (error) {
          console.error('Failed to update task project:', error);
          toast.error(intl.formatMessage(i18n.projectUpdateFailed));
        } finally {
          setIsAssigningProject(false);
        }
      },
      [intl, isAssigningProject, projectSession]
    );

    const handleArchiveSession = useCallback((session: SessionListItem) => {
      setSessionToArchive(session);
      setShowArchiveConfirmation(true);
    }, []);

    const handleRestoreSession = useCallback(
      async (session: SessionListItem) => {
        try {
          await acpUnarchiveSession(session.id);
          toast.success(intl.formatMessage(i18n.restoreSuccess));
          window.dispatchEvent(new CustomEvent(AppEvents.SESSION_CREATED));
          await loadSessions();
        } catch (error) {
          console.error('Error restoring session:', error);
          toast.error(
            intl.formatMessage(i18n.restoreFailed, {
              name: session.name,
              error: 'Try again.',
            })
          );
        }
      },
      [intl, loadSessions]
    );

    const handleDuplicateSession = useCallback(
      async (session: SessionListItem) => {
        try {
          await acpForkSession(session.id);
          toast.success(intl.formatMessage(i18n.duplicateSuccess, { name: session.name }));
          window.dispatchEvent(new CustomEvent(AppEvents.SESSION_CREATED));
          await loadSessions();
        } catch (error) {
          console.error('Error duplicating session:', error);
          toast.error(intl.formatMessage(i18n.duplicateFailed, { error: 'Try again.' }));
        }
      },
      [loadSessions, intl]
    );

    const handleConfirmArchive = useCallback(async () => {
      if (!sessionToArchive) return;

      setShowArchiveConfirmation(false);
      const sessionId = sessionToArchive.id;
      const sessionName = sessionToArchive.name;
      setSessionToArchive(null);

      try {
        await revokeBeforeAccordLockSessionDeletion(sessionId, () => acpArchiveSession(sessionId));
        toast.success(intl.formatMessage(i18n.archiveSuccess));
        window.dispatchEvent(new CustomEvent(AppEvents.SESSION_DELETED, { detail: { sessionId } }));
        cancelAcpPermissionRequestsForSession(sessionId);
        cancelAcpElicitationRequestsForSession(sessionId);
        acpChatSessionActions.deleteSnapshot(sessionId);
      } catch (error) {
        console.error('Error archiving session:', error);
        toast.error(
          intl.formatMessage(i18n.archiveFailed, {
            name: sessionName,
            error: 'Try again.',
          })
        );
      }
      await loadSessions();
    }, [sessionToArchive, loadSessions, intl]);

    const handleCancelArchive = useCallback(() => {
      setShowArchiveConfirmation(false);
      setSessionToArchive(null);
    }, []);

    const handleExportSession = useCallback(
      async (session: SessionListItem, format: SessionExportFormat) => {
        try {
          const data = await acpExportSession(session.id, format);
          const isMarkdown = format === 'markdown';
          const blob = new Blob([data], {
            type: isMarkdown ? 'text/markdown' : 'application/json',
          });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `${session.name}.${isMarkdown ? 'md' : 'json'}`;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(url);
          toast.success(intl.formatMessage(i18n.exportSuccess));
        } catch {
          toast.error(intl.formatMessage(i18n.exportFailed, { error: 'Try again.' }));
        }
      },
      [intl]
    );

    const handleShareSessionNostr = useCallback(
      async (session: SessionListItem) => {
        setSharingSessionId(session.id);
        try {
          const response = await acpShareSessionNostr(session.id, []);
          setShareLink(response.deeplink);
          setShowShareLinkModal(true);
          toast.success(intl.formatMessage(i18n.shareNostrSuccess));
        } catch {
          toast.error(intl.formatMessage(i18n.shareNostrFailed, { error: 'Try again.' }));
        } finally {
          setSharingSessionId(null);
        }
      },
      [intl]
    );

    const handleImportClick = useCallback(async () => {
      const native = window.electron?.selectImportSessionFile;
      if (typeof native === 'function') {
        try {
          const result = await native();
          if (!result) return;
          if (result.error) {
            console.error('Native task import failed:', result.error);
            toast.error(intl.formatMessage(i18n.importFailed, { error: 'Try again.' }));
            return;
          }
          await acpImportSession(result.contents, 'json');
          toast.success(intl.formatMessage(i18n.importSuccess));
          window.dispatchEvent(new CustomEvent(AppEvents.SESSION_CREATED));
          await loadSessions();
        } catch {
          toast.error(intl.formatMessage(i18n.importFailed, { error: 'Try again.' }));
        }
        return;
      }
      // Fallback for non-Electron contexts (tests, web build).
      fileInputRef.current?.click();
    }, [intl, loadSessions]);

    const handleImportNostrLink = useCallback(async () => {
      const deeplink = nostrImportLink.trim();
      if (!deeplink) return;

      setIsImportingNostr(true);
      try {
        await acpImportSession(deeplink, 'nostr');
        setNostrImportLink('');
        setShowImportLinkModal(false);
        toast.success(intl.formatMessage(i18n.importSuccess));
        window.dispatchEvent(new CustomEvent(AppEvents.SESSION_CREATED));
        await loadSessions();
      } catch {
        toast.error(intl.formatMessage(i18n.importFailed, { error: 'Try again.' }));
      } finally {
        setIsImportingNostr(false);
      }
    }, [intl, loadSessions, nostrImportLink]);

    const handleCopyShareLink = useCallback(async () => {
      try {
        await navigator.clipboard.writeText(shareLink);
        toast.success(intl.formatMessage(i18n.copied));
      } catch (error) {
        console.error('Failed to copy task link:', error);
        toast.error('AccordLock could not copy the link. Try again.');
      }
    }, [intl, shareLink]);

    const handleImportSession = useCallback(
      async (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        if (!file) return;

        try {
          const json = await file.text();
          await acpImportSession(json, 'json');

          toast.success(intl.formatMessage(i18n.importSuccess));
          window.dispatchEvent(new CustomEvent(AppEvents.SESSION_CREATED));
          await loadSessions();
        } catch (error) {
          console.error('Task file import failed:', error);
          toast.error(intl.formatMessage(i18n.importFailed, { error: 'Try again.' }));
        } finally {
          if (fileInputRef.current) {
            fileInputRef.current.value = '';
          }
        }
      },
      [loadSessions, intl]
    );

    const handleOpenInNewWindow = useCallback((session: SessionListItem) => {
      window.electron.createChatWindow({
        resumeSessionId: session.id,
        viewType: 'pair',
      });
    }, []);

    const SessionItem = React.memo(function SessionItem({
      session,
      project,
      onEditClick,
      onProjectClick,
      onDuplicateClick,
      onArchiveClick,
      onRestoreClick,
      onExportClick,
      onShareClick,
      onOpenInNewWindow,
      isSharing,
    }: {
      session: SessionListItem;
      project?: AccordLockProject;
      onEditClick: (session: SessionListItem) => void;
      onProjectClick: (session: SessionListItem) => void;
      onDuplicateClick: (session: SessionListItem) => void;
      onArchiveClick: (session: SessionListItem) => void;
      onRestoreClick: (session: SessionListItem) => void;
      onExportClick: (session: SessionListItem, format: SessionExportFormat) => void;
      onShareClick: (session: SessionListItem) => void;
      onOpenInNewWindow: (session: SessionListItem) => void;
      isSharing: boolean;
    }) {
      const handleCardClick = useCallback(() => {
        onSelectSession(session.id);
      }, [session.id]);

      const displayName = session.name;
      const projectLabel =
        project?.title ?? (session.projectId ? readableProjectId(session.projectId) : null);

      return (
        <Card
          onClick={handleCardClick}
          onKeyDown={(event) => {
            if (event.target !== event.currentTarget) return;
            if (event.key === 'Enter' || event.key === ' ') {
              event.preventDefault();
              handleCardClick();
            }
          }}
          role="button"
          tabIndex={0}
          className="group relative flex min-h-[76px] cursor-pointer flex-col gap-3 px-5 py-4 transition-colors hover:bg-background-secondary/45 sm:flex-row sm:items-center"
        >
          <div className="min-w-0 flex-1">
            <h3 className="mb-1 truncate text-base" title={displayName}>
              {displayName}
            </h3>
            <div className="flex flex-col gap-0.5 sm:flex-row sm:items-center sm:gap-4">
              <div className="flex items-center text-text-secondary text-xs">
                <Calendar className="w-3 h-3 mr-1 flex-shrink-0" />
                <span>{formatMessageTimestamp(Date.parse(sessionActivityAt(session)) / 1000)}</span>
              </div>
              {projectLabel && (
                <div className="flex min-w-0 items-center gap-1.5 text-xs text-text-secondary">
                  <span
                    className="h-2 w-2 shrink-0 rounded-full"
                    style={{ backgroundColor: project?.color ?? '#64748B' }}
                    aria-hidden="true"
                  />
                  <span className="truncate">{projectLabel}</span>
                </div>
              )}
              <div className="flex min-w-0 items-center text-text-secondary text-xs">
                <Folder className="w-3 h-3 mr-1 flex-shrink-0" />
                <span
                  className="truncate"
                  title={normalizeWorkspacePathForDisplay(session.workingDir)}
                >
                  {splitDirPath(session.workingDir).name}
                </span>
              </div>
            </div>
          </div>
          <div className="flex shrink-0 justify-end opacity-60 transition-opacity group-hover:opacity-100 group-focus-within:opacity-100 has-data-[state=open]:opacity-100">
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button
                  onClick={(e) => e.stopPropagation()}
                  className="cursor-pointer rounded-lg p-2 transition-colors hover:bg-background-tertiary"
                  aria-label={intl.formatMessage(i18n.moreActions, { name: displayName })}
                >
                  <MoreHorizontal className="h-4 w-4 text-text-secondary" />
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent
                align="end"
                className="w-56"
                onClick={(e) => e.stopPropagation()}
              >
                <DropdownMenuItem onSelect={() => onOpenInNewWindow(session)}>
                  <ExternalLink />
                  {intl.formatMessage(i18n.openInNewWindow)}
                </DropdownMenuItem>
                <DropdownMenuItem onSelect={() => onEditClick(session)}>
                  <Edit2 />
                  {intl.formatMessage(i18n.editSessionName)}
                </DropdownMenuItem>
                <DropdownMenuItem onSelect={() => onProjectClick(session)}>
                  <FolderKanban />
                  {intl.formatMessage(i18n.changeProject)}
                </DropdownMenuItem>
                <DropdownMenuItem onSelect={() => onDuplicateClick(session)}>
                  <Copy />
                  {intl.formatMessage(i18n.duplicateSession)}
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem onSelect={() => onExportClick(session, 'json')}>
                  <Download />
                  {intl.formatMessage(i18n.exportAsJson)}
                </DropdownMenuItem>
                <DropdownMenuItem onSelect={() => onExportClick(session, 'markdown')}>
                  <Download />
                  {intl.formatMessage(i18n.exportAsMarkdown)}
                </DropdownMenuItem>
                {nostrEnabled && (
                  <DropdownMenuItem disabled={isSharing} onSelect={() => onShareClick(session)}>
                    {isSharing ? <LoaderCircle className="animate-spin" /> : <Share2 />}
                    {intl.formatMessage(i18n.shareNostrSession)}
                  </DropdownMenuItem>
                )}
                <DropdownMenuSeparator />
                {session.archivedAt ? (
                  <DropdownMenuItem onSelect={() => onRestoreClick(session)}>
                    <ArchiveRestore />
                    {intl.formatMessage(i18n.restoreSession)}
                  </DropdownMenuItem>
                ) : (
                  <DropdownMenuItem onSelect={() => onArchiveClick(session)}>
                    <Archive />
                    {intl.formatMessage(i18n.archiveSession)}
                  </DropdownMenuItem>
                )}
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </Card>
      );
    });

    const SessionSkeleton = React.memo(({ variant = 0 }: { variant?: number }) => {
      const titleWidths = ['w-3/4', 'w-2/3', 'w-4/5', 'w-1/2'];
      const pathWidths = ['w-32', 'w-28', 'w-36', 'w-24'];
      const tokenWidths = ['w-12', 'w-10', 'w-14', 'w-8'];

      return (
        <Card className="session-skeleton h-full py-3 px-4 flex flex-col justify-between">
          <div className="flex-1">
            <Skeleton className={`h-5 ${titleWidths[variant % titleWidths.length]} mb-2`} />
            <div className="flex items-center mb-1">
              <Skeleton className="h-3 w-3 mr-1 rounded-sm" />
              <Skeleton className="h-4 w-20" />
            </div>
            <div className="flex items-center mb-1">
              <Skeleton className="h-3 w-3 mr-1 rounded-sm" />
              <Skeleton className={`h-4 ${pathWidths[variant % pathWidths.length]}`} />
            </div>
          </div>

          <div className="flex items-center justify-between mt-1 pt-2">
            <div className="flex items-center space-x-3">
              <div className="flex items-center">
                <Skeleton className="h-3 w-3 mr-1 rounded-sm" />
                <Skeleton className="h-4 w-8" />
              </div>
              <div className="flex items-center">
                <Skeleton className="h-3 w-3 mr-1 rounded-sm" />
                <Skeleton className={`h-4 ${tokenWidths[variant % tokenWidths.length]}`} />
              </div>
            </div>
          </div>
        </Card>
      );
    });

    SessionSkeleton.displayName = 'SessionSkeleton';

    const renderActualContent = () => {
      if (error) {
        return (
          <div className="flex flex-col items-center justify-center h-full text-text-secondary">
            <AlertCircle className="h-12 w-12 text-red-500 mb-4" />
            <p className="text-lg mb-2">{intl.formatMessage(i18n.errorLoading)}</p>
            <p className="text-sm text-center mb-4">{error}</p>
            <Button onClick={() => loadSessions(debouncedSearchTerm)} variant="default">
              {intl.formatMessage(i18n.tryAgain)}
            </Button>
          </div>
        );
      }

      if (filteredSessions.length === 0) {
        if (isPrefetchingSessions) {
          return (
            <div className="flex h-full items-center justify-center gap-2 text-sm text-text-secondary">
              <LoaderCircle className="h-4 w-4 animate-spin" />
              {intl.formatMessage(i18n.loadingMore)}
            </div>
          );
        }
        // `sessions` holds the keyword-filtered set, so an empty result while searching
        // means "no matches" rather than "no sessions at all".
        if (debouncedSearchTerm) {
          return (
            <div className="flex flex-col items-center justify-center h-full text-text-secondary mt-4">
              <MessageSquareText className="h-12 w-12 mb-4" />
              <p className="text-lg mb-2">{intl.formatMessage(i18n.noMatching)}</p>
              <p className="text-sm">{intl.formatMessage(i18n.noMatchingDesc)}</p>
            </div>
          );
        }
        if (projectId) {
          return (
            <div className="flex h-full flex-col justify-center text-text-secondary">
              <FolderKanban className="mb-4 h-12 w-12" />
              <p className="mb-2 text-lg">{intl.formatMessage(i18n.filteredEmptyTitle)}</p>
              <p className="text-sm">{intl.formatMessage(i18n.filteredEmptyDescription)}</p>
              {onClearProjectFilter && (
                <Button className="mt-5 w-fit" variant="outline" onClick={onClearProjectFilter}>
                  {intl.formatMessage(i18n.allTasks)}
                </Button>
              )}
            </div>
          );
        }
        return (
          <div className="flex flex-col justify-center h-full text-text-secondary">
            {showArchivedTasks ? (
              <>
                <Archive className="h-12 w-12 mb-4" />
                <p className="text-lg mb-2">{intl.formatMessage(i18n.noArchivedTasks)}</p>
              </>
            ) : (
              <>
                <MessageSquareText className="h-12 w-12 mb-4" />
                <p className="text-lg mb-2">{intl.formatMessage(i18n.noSessions)}</p>
                <p className="text-sm">{intl.formatMessage(i18n.noSessionsDesc)}</p>
              </>
            )}
          </div>
        );
      }

      return (
        <div className="space-y-8">
          {visibleDateGroups.map((group) => (
            <div key={group.label} className="space-y-4">
              <div className="sticky top-0 z-10 bg-background-primary/95 backdrop-blur-sm">
                <h2 className="text-text-secondary">{group.label}</h2>
              </div>
              <div className="space-y-2">
                {group.sessions.map((session) => (
                  <SessionItem
                    key={session.id}
                    session={session}
                    project={session.projectId ? projectsById.get(session.projectId) : undefined}
                    onEditClick={handleEditSession}
                    onProjectClick={handleProjectSession}
                    onDuplicateClick={handleDuplicateSession}
                    onArchiveClick={handleArchiveSession}
                    onRestoreClick={(session) => void handleRestoreSession(session)}
                    onExportClick={handleExportSession}
                    onShareClick={handleShareSessionNostr}
                    onOpenInNewWindow={handleOpenInNewWindow}
                    isSharing={sharingSessionId === session.id}
                  />
                ))}
              </div>
            </div>
          ))}

          {isPrefetchingSessions && (
            <div className="flex justify-center py-8">
              <div className="flex items-center space-x-2 text-text-secondary">
                <div className="animate-spin rounded-full h-4 w-4 border-b-2"></div>
                <span>{intl.formatMessage(i18n.loadingMore)}</span>
              </div>
            </div>
          )}
        </div>
      );
    };

    return (
      <>
        <MainPanelLayout>
          <div className="flex-1 flex flex-col min-h-0">
            <div className="bg-background-primary px-8 pb-8 pt-16">
              <div className="flex flex-col page-transition">
                <div className="flex justify-between items-center mb-1">
                  <div className="flex min-w-0 items-center gap-3">
                    <h1 className="text-4xl font-light">{intl.formatMessage(i18n.chatHistory)}</h1>
                    {projectId && onClearProjectFilter && (
                      <Button
                        variant="outline"
                        size="sm"
                        className="min-w-0 gap-2 rounded-full"
                        onClick={onClearProjectFilter}
                        title={intl.formatMessage(i18n.allTasks)}
                      >
                        <span
                          className="h-2 w-2 shrink-0 rounded-full"
                          style={{ backgroundColor: selectedProject?.color ?? '#64748B' }}
                          aria-hidden="true"
                        />
                        <span className="max-w-48 truncate">
                          {selectedProject?.title ?? readableProjectId(projectId)}
                        </span>
                        <X className="h-3.5 w-3.5" />
                      </Button>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <Button
                      onClick={() => setShowArchivedTasks((current) => !current)}
                      variant="outline"
                      size="sm"
                      className="flex items-center gap-2"
                    >
                      {showArchivedTasks ? <ArchiveRestore /> : <Archive />}
                      {intl.formatMessage(
                        showArchivedTasks ? i18n.activeTasks : i18n.archivedTasks
                      )}
                      {!showArchivedTasks && archivedTaskCount > 0 && ` (${archivedTaskCount})`}
                    </Button>
                    {nostrEnabled && (
                      <Button
                        onClick={() => setShowImportLinkModal(true)}
                        variant="outline"
                        size="sm"
                        className="flex items-center gap-2"
                      >
                        <Share2 className="w-4 h-4" />
                        {intl.formatMessage(i18n.importNostrSession)}
                      </Button>
                    )}
                    <Button
                      onClick={handleImportClick}
                      variant="outline"
                      size="sm"
                      className="flex items-center gap-2"
                    >
                      <Upload className="w-4 h-4" />
                      {intl.formatMessage(i18n.importSession)}
                    </Button>
                  </div>
                </div>
              </div>
            </div>

            <div className="flex-1 min-h-0 relative">
              <ScrollArea handleScroll={handleScroll} className="h-full" data-search-scroll-area>
                <div ref={containerRef} className="h-full relative px-8">
                  <SearchView
                    onSearch={handleSearch}
                    className="relative"
                    placeholder={intl.formatMessage(i18n.searchPlaceholder)}
                    showCaseSensitive={false}
                    showNavigation={false}
                    highlightMatches={false}
                  >
                    {/* Skeleton layer - always rendered but conditionally visible */}
                    <div
                      className={`absolute inset-0 transition-opacity duration-300 ${
                        isLoading || showSkeleton
                          ? 'opacity-100 z-10'
                          : 'opacity-0 z-0 pointer-events-none'
                      }`}
                    >
                      <div className="space-y-8">
                        {/* Today section */}
                        <div className="space-y-4">
                          <Skeleton className="h-6 w-16" />
                          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-5 gap-4">
                            <SessionSkeleton variant={0} />
                            <SessionSkeleton variant={1} />
                            <SessionSkeleton variant={2} />
                            <SessionSkeleton variant={3} />
                            <SessionSkeleton variant={0} />
                          </div>
                        </div>

                        {/* Yesterday section */}
                        <div className="space-y-4">
                          <Skeleton className="h-6 w-20" />
                          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-5 gap-4">
                            <SessionSkeleton variant={1} />
                            <SessionSkeleton variant={2} />
                            <SessionSkeleton variant={3} />
                            <SessionSkeleton variant={0} />
                            <SessionSkeleton variant={1} />
                            <SessionSkeleton variant={2} />
                          </div>
                        </div>

                        {/* Additional section */}
                        <div className="space-y-4">
                          <Skeleton className="h-6 w-24" />
                          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-5 gap-4">
                            <SessionSkeleton variant={3} />
                            <SessionSkeleton variant={0} />
                            <SessionSkeleton variant={1} />
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Content layer - always rendered but conditionally visible */}
                    <div
                      className={`relative transition-opacity duration-300 ${
                        showContent ? 'opacity-100 z-10' : 'opacity-0 z-0'
                      }`}
                    >
                      {renderActualContent()}
                    </div>
                  </SearchView>
                </div>
              </ScrollArea>
            </div>
          </div>
        </MainPanelLayout>

        <input
          ref={fileInputRef}
          type="file"
          accept=".json,.jsonl,application/json,application/x-ndjson"
          onChange={handleImportSession}
          className="hidden"
        />

        <EditSessionModal
          session={editingSession}
          isOpen={showEditModal}
          onClose={handleModalClose}
          onSave={handleModalSave}
        />

        <Dialog
          open={Boolean(projectSession)}
          onOpenChange={(open) => !open && !isAssigningProject && setProjectSession(null)}
        >
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>{intl.formatMessage(i18n.changeProjectTitle)}</DialogTitle>
              <DialogDescription>
                {intl.formatMessage(i18n.changeProjectDescription, {
                  name: projectSession?.name ?? '',
                })}
              </DialogDescription>
            </DialogHeader>

            <div className="max-h-80 space-y-1 overflow-y-auto py-1">
              <button
                type="button"
                className="flex min-h-11 w-full items-center gap-3 rounded-lg px-3 text-left text-sm transition-colors hover:bg-background-secondary disabled:opacity-60"
                onClick={() => void handleAssignProject(null)}
                disabled={isAssigningProject}
              >
                <span className="h-2.5 w-2.5 shrink-0 rounded-full border border-border-primary" />
                <span className="min-w-0 flex-1 truncate">
                  {intl.formatMessage(i18n.noProject)}
                </span>
                {!projectSession?.projectId && <Check className="h-4 w-4 text-text-secondary" />}
              </button>
              {activeProjects.map((project) => (
                <button
                  type="button"
                  key={project.id}
                  className="flex min-h-11 w-full items-center gap-3 rounded-lg px-3 text-left text-sm transition-colors hover:bg-background-secondary disabled:opacity-60"
                  onClick={() => void handleAssignProject(project.id)}
                  disabled={isAssigningProject}
                >
                  <span
                    className="h-2.5 w-2.5 shrink-0 rounded-full"
                    style={{ backgroundColor: project.color ?? '#64748B' }}
                    aria-hidden="true"
                  />
                  <span className="min-w-0 flex-1 truncate">{project.title}</span>
                  {projectSession?.projectId === project.id && (
                    <Check className="h-4 w-4 text-text-secondary" />
                  )}
                </button>
              ))}
            </div>
          </DialogContent>
        </Dialog>

        <Dialog open={showImportLinkModal} onOpenChange={setShowImportLinkModal}>
          <DialogContent className="sm:max-w-lg">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Share2 className="w-5 h-5" />
                {intl.formatMessage(i18n.importNostrTitle)}
              </DialogTitle>
              <DialogDescription>{intl.formatMessage(i18n.importNostrDesc)}</DialogDescription>
            </DialogHeader>

            <textarea
              value={nostrImportLink}
              onChange={(event) => setNostrImportLink(event.target.value)}
              placeholder={intl.formatMessage(i18n.importNostrPlaceholder)}
              className="min-h-28 w-full resize-none rounded-lg border border-border-primary bg-background-primary p-3 text-sm text-text-primary outline-none focus:ring-2 focus:ring-border-active"
              disabled={isImportingNostr}
            />

            <DialogFooter>
              <Button
                variant="outline"
                onClick={() => setShowImportLinkModal(false)}
                disabled={isImportingNostr}
              >
                {intl.formatMessage(i18n.cancel)}
              </Button>
              <Button
                onClick={handleImportNostrLink}
                disabled={isImportingNostr || !nostrImportLink.trim()}
              >
                {isImportingNostr ? (
                  <>
                    <LoaderCircle className="w-4 h-4 animate-spin" />
                    {intl.formatMessage(i18n.importing)}
                  </>
                ) : (
                  intl.formatMessage(i18n.importSession)
                )}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        <Dialog open={showShareLinkModal} onOpenChange={setShowShareLinkModal}>
          <DialogContent className="sm:max-w-lg">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Share2 className="w-5 h-5" />
                {intl.formatMessage(i18n.shareNostrTitle)}
              </DialogTitle>
              <DialogDescription>{intl.formatMessage(i18n.shareNostrDesc)}</DialogDescription>
            </DialogHeader>

            <div className="relative rounded-lg border border-border-primary bg-background-secondary p-3 pr-12">
              <code className="block max-h-36 overflow-y-auto break-all text-sm text-text-primary">
                {shareLink}
              </code>
              <Button
                variant="ghost"
                size="sm"
                className="absolute right-2 top-2"
                onClick={handleCopyShareLink}
                disabled={!shareLink}
              >
                <Copy className="h-4 w-4" />
                <span className="sr-only">{intl.formatMessage(i18n.copied)}</span>
              </Button>
            </div>

            <DialogFooter>
              <Button variant="outline" onClick={() => setShowShareLinkModal(false)}>
                {intl.formatMessage(i18n.close)}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        <ConfirmationModal
          isOpen={showArchiveConfirmation}
          title={intl.formatMessage(i18n.archiveTitle)}
          message={intl.formatMessage(i18n.archiveMessage, { name: sessionToArchive?.name ?? '' })}
          confirmLabel={intl.formatMessage(i18n.archiveSession)}
          cancelLabel={intl.formatMessage(i18n.cancel)}
          onConfirm={handleConfirmArchive}
          onCancel={handleCancelArchive}
        />
      </>
    );
  }
);

SessionListView.displayName = 'SessionListView';

export default SessionListView;
