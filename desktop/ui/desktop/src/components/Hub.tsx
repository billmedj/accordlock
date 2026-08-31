// Modified by AccordLock contributors; see UPSTREAM.md.
/**
 * Task-first landing screen.
 *
 * The underlying session machinery remains unchanged, but the product presents
 * an outcome, protected workspace, and model — not a harness configuration
 * surface.
 */

import { useEffect, useRef, useState } from 'react';
import { LoaderCircle, PlugZap, ShieldCheck } from 'lucide-react';
import { defineMessages, useIntl } from '../i18n';
import { AppEvents } from '../constants/events';
import ChatInput from './ChatInput';
import { ChatInputCard } from './ChatInputCard';
import { ChatState } from '../types/chatState';
import 'react-toastify/dist/ReactToastify.css';
import { View, ViewOptions } from '../utils/navigationUtils';
import { useConfig } from './ConfigContext';
import { getInitialWorkingDir } from '../utils/workingDir';
import { createSession } from '../sessions';
import { UserInput } from '../types/message';
import { formatAcpError } from '../acp/errors';
import { toastError } from '../toasts';
import { validateAccordLockObjective } from '../accordlock/taskObjective';
import { selectAccordLockTaskExtensions } from '../accordlock/taskExtensions';
import { acpRenameSession } from '../acp/sessions';
import { listProjects, PROJECTS_CHANGED_EVENT, type AccordLockProject } from '../acp/projects';
import { uniqueProjectForWorkspace } from '../utils/projectMatching';
import { ProjectPicker } from './projects/ProjectPicker';
import type { AccordLockEnvironmentProfileView } from '../accordlock/environmentProfileIpc';
import { ACCORDLOCK_DEPLOYMENT_PREFLIGHT_PROTOCOL } from '../accordlock/deploymentPreflight';
import {
  DeploymentPreflightDialog,
  type DeploymentPreflightCandidateDefaults,
  type DeploymentPreflightDialogInput,
} from './accordlock/DeploymentPreflightDialog';
import type { DeploymentPreflightResultView } from './accordlock/DeploymentPreflightResult';

const MAX_TASK_TITLE_LENGTH = 56;

const i18n = defineMessages({
  title: {
    id: 'hub.title',
    defaultMessage: 'What would you like to get done?',
  },
  taskPlaceholder: {
    id: 'hub.taskPlaceholder',
    defaultMessage: 'Describe the outcome…',
  },
  thisFolder: {
    id: 'hub.thisFolder',
    defaultMessage: 'this folder',
  },
  protectionSummary: {
    id: 'hub.protectionSummary',
    defaultMessage: 'Can read “{workspace}”. Asks before changes and commands.',
  },
  startTask: {
    id: 'hub.startTask',
    defaultMessage: 'Start task',
  },
  startFailure: {
    id: 'hub.startFailure',
    defaultMessage: "Couldn't start task",
  },
  invalidTask: {
    id: 'hub.invalidTask',
    defaultMessage: 'Check the task',
  },
  goalRequired: {
    id: 'hub.goalRequired',
    defaultMessage: 'Describe what you want done.',
  },
  goalTooLarge: {
    id: 'hub.goalTooLarge',
    defaultMessage: 'Shorten the task description.',
  },
  goalUnsafe: {
    id: 'hub.goalUnsafe',
    defaultMessage: 'The task contains hidden characters. Paste it as plain text and try again.',
  },
  attachmentsUnsupported: {
    id: 'hub.attachmentsUnsupported',
    defaultMessage:
      'Remove the images and start with text. You can add them after the task starts.',
  },
  secureToolsUnavailable: {
    id: 'hub.secureToolsUnavailable',
    defaultMessage: "File access couldn't start. Restart AccordLock and try again.",
  },
  verifyDeployment: {
    id: 'hub.verifyDeployment',
    defaultMessage: 'Verify deployment',
  },
  addBuildProof: {
    id: 'hub.addBuildProof',
    defaultMessage: 'Add build proof',
  },
  connectEnvironment: {
    id: 'hub.connectEnvironment',
    defaultMessage: 'Connect environment',
  },
  buildProofFailure: {
    id: 'hub.buildProofFailure',
    defaultMessage: "Couldn't import build proof",
  },
  buildProofFailureDetail: {
    id: 'hub.buildProofFailureDetail',
    defaultMessage: 'Choose the JSON package created by the protected release workflow.',
  },
});

export function accordLockWorkspaceName(workspace: string): string {
  const components = workspace.split(/[\\/]/u).filter(Boolean);
  return components[components.length - 1] ?? workspace;
}

export function accordLockTaskTitle(objective: string): string {
  const compactObjective = objective.replace(/\s+/gu, ' ').trim();
  const characters = Array.from(compactObjective);
  if (characters.length <= MAX_TASK_TITLE_LENGTH) return compactObjective;

  const prefix = characters
    .slice(0, MAX_TASK_TITLE_LENGTH - 1)
    .join('')
    .trimEnd();
  const lastWordBoundary = prefix.lastIndexOf(' ');
  const readablePrefix =
    lastWordBoundary >= Math.floor(MAX_TASK_TITLE_LENGTH * 0.65)
      ? prefix.slice(0, lastWordBoundary)
      : prefix;

  return `${readablePrefix.trimEnd()}…`;
}

/** Preserve an explicit choice; otherwise use the folder only when it identifies one project. */
export function resolveNewTaskProjectId(
  projects: readonly AccordLockProject[],
  workspace: string,
  currentProjectId: string | null,
  explicitlySelected: boolean
): string | null {
  if (explicitlySelected) {
    return projects.some((project) => !project.archived && project.id === currentProjectId)
      ? currentProjectId
      : null;
  }
  return uniqueProjectForWorkspace(projects, workspace)?.id ?? null;
}

export default function Hub({
  setView,
}: {
  setView: (view: View, viewOptions?: ViewOptions) => void;
}) {
  const intl = useIntl();
  const { extensionsList } = useConfig();
  const workingDir = getInitialWorkingDir();
  const [isCreatingSession, setIsCreatingSession] = useState(false);
  const [projects, setProjects] = useState<AccordLockProject[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string | null>(null);
  const [environmentProfiles, setEnvironmentProfiles] = useState<
    AccordLockEnvironmentProfileView[]
  >([]);
  const [preflightOpen, setPreflightOpen] = useState(false);
  const [importingEnvironmentId, setImportingEnvironmentId] = useState<string | null>(null);
  const [candidateDefaults, setCandidateDefaults] = useState<
    Record<string, DeploymentPreflightCandidateDefaults>
  >({});
  const isCreatingSessionRef = useRef(false);
  const projectSelectionExplicitRef = useRef(false);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    const frameId = requestAnimationFrame(() => {
      inputRef.current?.focus();
    });
    return () => cancelAnimationFrame(frameId);
  }, []);

  useEffect(() => {
    let active = true;
    projectSelectionExplicitRef.current = false;
    const refreshProject = () => {
      void listProjects()
        .then((loadedProjects) => {
          if (!active) return;
          setProjects(loadedProjects);
          setSelectedProjectId((currentProjectId) =>
            resolveNewTaskProjectId(
              loadedProjects,
              workingDir,
              currentProjectId,
              projectSelectionExplicitRef.current
            )
          );
        })
        .catch(() => {
          if (!active) return;
          setProjects([]);
          setSelectedProjectId(null);
        });
    };

    refreshProject();
    window.addEventListener(PROJECTS_CHANGED_EVENT, refreshProject);
    return () => {
      active = false;
      window.removeEventListener(PROJECTS_CHANGED_EVENT, refreshProject);
    };
  }, [workingDir]);

  useEffect(() => {
    let active = true;
    void window.electron
      .listAccordLockEnvironmentProfiles()
      .then((profiles) => {
        if (active) setEnvironmentProfiles(profiles);
      })
      .catch(() => {
        if (active) setEnvironmentProfiles([]);
      });
    return () => {
      active = false;
    };
  }, []);

  const handleSubmit = async (input: UserInput) => {
    const { msg: userMessage, images } = input;
    if (isCreatingSessionRef.current) return;

    const objective = validateAccordLockObjective(userMessage);
    if (!objective.ok) {
      const validationMessages = {
        EMPTY: i18n.goalRequired,
        TOO_LARGE: i18n.goalTooLarge,
        UNSAFE_TEXT: i18n.goalUnsafe,
      } as const;
      toastError({
        title: intl.formatMessage(i18n.invalidTask),
        msg: intl.formatMessage(validationMessages[objective.reason]),
      });
      return;
    }
    if (images.length > 0) {
      toastError({
        title: intl.formatMessage(i18n.invalidTask),
        msg: intl.formatMessage(i18n.attachmentsUnsupported),
      });
      return;
    }

    const normalizedInput = { ...input, msg: objective.objective };

    isCreatingSessionRef.current = true;
    setIsCreatingSession(true);

    try {
      const taskExtensions = selectAccordLockTaskExtensions(extensionsList);
      if (taskExtensions.length !== 1) {
        toastError({
          title: intl.formatMessage(i18n.startFailure),
          msg: intl.formatMessage(i18n.secureToolsUnavailable),
        });
        isCreatingSessionRef.current = false;
        setIsCreatingSession(false);
        return;
      }

      const session = await createSession(workingDir, {
        extensionConfigs: taskExtensions,
        projectId: selectedProjectId ?? undefined,
      });
      const taskTitle = accordLockTaskTitle(objective.objective);

      void acpRenameSession(session.id, taskTitle)
        .then(() => {
          window.dispatchEvent(
            new CustomEvent(AppEvents.SESSION_RENAMED, {
              detail: { sessionId: session.id, newName: taskTitle, userInitiated: true },
            })
          );
        })
        .catch((error) => {
          // Naming is helpful, but it must never prevent a validated task from starting.
          console.warn('Could not name the new task:', error);
        });

      window.dispatchEvent(new CustomEvent(AppEvents.SESSION_CREATED));
      window.dispatchEvent(
        new CustomEvent(AppEvents.ADD_ACTIVE_SESSION, {
          detail: { sessionId: session.id, initialMessage: normalizedInput },
        })
      );

      setView('pair', {
        disableAnimation: true,
        resumeSessionId: session.id,
        initialMessage: normalizedInput,
      });
    } catch (error) {
      console.error('Failed to create session:', error);
      toastError({ title: intl.formatMessage(i18n.startFailure), msg: formatAcpError(error) });
      isCreatingSessionRef.current = false;
      setIsCreatingSession(false);
    }
  };

  const workspaceName = accordLockWorkspaceName(workingDir);
  const selectedProject = projects.find((project) => project.id === selectedProjectId) ?? null;
  const selectedEnvironment = selectedProject?.deploymentEnvironmentId
    ? (environmentProfiles.find(
        (environment) => environment.id === selectedProject.deploymentEnvironmentId
      ) ?? null)
    : null;

  const runDeploymentPreflight = async (input: DeploymentPreflightDialogInput) => {
    const result = await window.electron.runAccordLockDeploymentPreflight({
      protocol: ACCORDLOCK_DEPLOYMENT_PREFLIGHT_PROTOCOL,
      schemaVersion: 1,
      ...input,
    });
    setEnvironmentProfiles(await window.electron.listAccordLockEnvironmentProfiles());
    return result;
  };

  const exportDeploymentReceipt = async (result: DeploymentPreflightResultView) => {
    await window.electron.exportAccordLockDeploymentPreflightReceipt(result.receiptHash);
  };

  const openDeploymentAction = async (environment: AccordLockEnvironmentProfileView) => {
    if (environment.ciTrust.status === 'ENROLLED') {
      setPreflightOpen(true);
      return;
    }
    setImportingEnvironmentId(environment.id);
    try {
      const result = await window.electron.importAccordLockDeploymentPreflightCiEvidence(
        environment.id
      );
      if (result.status === 'ENROLLED') {
        setEnvironmentProfiles(await window.electron.listAccordLockEnvironmentProfiles());
        setCandidateDefaults((current) => ({
          ...current,
          [environment.id]: {
            buildRunUrl: `https://github.com/${result.repository}/actions/runs/${result.runId}`,
            imageDigest: result.imageDigest,
          },
        }));
        setPreflightOpen(true);
      }
    } catch {
      toastError({
        title: intl.formatMessage(i18n.buildProofFailure),
        msg: intl.formatMessage(i18n.buildProofFailureDetail),
      });
    } finally {
      setImportingEnvironmentId(null);
    }
  };

  return (
    <div className="relative flex h-full min-h-0 flex-col items-center justify-center overflow-y-auto px-6 pb-[10vh] pt-12 sm:px-10">
      <main className="w-full max-w-[760px]">
        <h1 className="text-[2rem] font-medium leading-tight tracking-[-0.035em] text-text-primary sm:text-[2.5rem]">
          {intl.formatMessage(i18n.title)}
        </h1>

        <ChatInputCard className="mt-7 border-border-secondary shadow-sm">
          <ChatInput
            sessionId={null}
            handleSubmit={handleSubmit}
            chatState={isCreatingSession ? ChatState.LoadingConversation : ChatState.Idle}
            onStop={() => {}}
            initialValue=""
            setView={setView}
            totalTokens={0}
            accumulatedInputTokens={0}
            accumulatedOutputTokens={0}
            droppedFiles={[]}
            onFilesProcessed={() => {}}
            messages={[]}
            disableAnimation={false}
            inputRef={inputRef}
            showExtensionSelector={false}
            showAttachmentButton={false}
            showSessionStatus={false}
            landingMode
            placeholder={intl.formatMessage(i18n.taskPlaceholder)}
            submitLabel={intl.formatMessage(i18n.startTask)}
          />
        </ChatInputCard>

        <div className="mt-3 flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 px-1 text-[13px] leading-5 text-text-secondary">
          <span>
            {intl.formatMessage(i18n.protectionSummary, {
              workspace: workspaceName || intl.formatMessage(i18n.thisFolder),
            })}
          </span>
          <ProjectPicker
            projects={projects}
            selectedProjectId={selectedProjectId}
            onCreateProject={() => setView('projects')}
            onChange={(projectId) => {
              projectSelectionExplicitRef.current = true;
              setSelectedProjectId(projectId);
            }}
          />
          {selectedEnvironment && (
            <button
              type="button"
              disabled={importingEnvironmentId === selectedEnvironment.id}
              onClick={() => void openDeploymentAction(selectedEnvironment)}
              className="inline-flex h-7 items-center gap-1.5 rounded-full border border-border-secondary px-2.5 text-xs font-medium text-text-secondary outline-none transition-colors hover:bg-background-secondary hover:text-text-primary focus-visible:ring-2 focus-visible:ring-ring"
            >
              {importingEnvironmentId === selectedEnvironment.id ? (
                <LoaderCircle aria-hidden="true" className="size-3.5 animate-spin" />
              ) : (
                <ShieldCheck aria-hidden="true" className="size-3.5" />
              )}
              {intl.formatMessage(
                selectedEnvironment.ciTrust.status === 'ENROLLED'
                  ? i18n.verifyDeployment
                  : i18n.addBuildProof
              )}
            </button>
          )}
          {selectedProject && !selectedEnvironment && (
            <button
              type="button"
              onClick={() => setView('settings', { section: 'environments' })}
              className="inline-flex h-7 items-center gap-1.5 rounded-full border border-border-secondary px-2.5 text-xs font-medium text-text-secondary outline-none transition-colors hover:bg-background-secondary hover:text-text-primary focus-visible:ring-2 focus-visible:ring-ring"
            >
              <PlugZap aria-hidden="true" className="size-3.5" />
              {intl.formatMessage(i18n.connectEnvironment)}
            </button>
          )}
        </div>
      </main>
      {selectedEnvironment && (
        <DeploymentPreflightDialog
          open={preflightOpen}
          candidateDefaults={candidateDefaults[selectedEnvironment.id]}
          environment={{
            id: selectedEnvironment.id,
            name: selectedEnvironment.name,
            repository: selectedEnvironment.github.repository,
            workflow: selectedEnvironment.github.workflow,
            target: `${selectedEnvironment.kubernetes.clusterName} · ${selectedEnvironment.kubernetes.namespace}/${selectedEnvironment.kubernetes.deployment}:${selectedEnvironment.kubernetes.container}`,
            status: selectedEnvironment.status,
          }}
          onOpenChange={setPreflightOpen}
          onRun={runDeploymentPreflight}
          onExport={(result) => void exportDeploymentReceipt(result)}
        />
      )}
    </div>
  );
}
