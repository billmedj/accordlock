import { AppEvents } from '../constants/events';
import { revokeBeforeAccordLockSessionDeletion } from '../accordlock/taskBridge';
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { defineMessages, useIntl } from '../i18n';
import { useLocation, useNavigate } from 'react-router';
import { SearchView } from './conversation/SearchView';
import LoadingGoose from './LoadingGoose';
import ProgressiveMessageList from './ProgressiveMessageList';
import { MainPanelLayout } from './Layout/MainPanelLayout';
import ChatInput from './ChatInput';
import { ChatInputCard } from './ChatInputCard';
import { Button } from './ui/button';
import { ScrollArea, ScrollAreaHandle } from './ui/scroll-area';
import { useFileDrop } from '../hooks/useFileDrop';
import { ChatState } from '../types/chatState';
import { ChatType } from '../types/chat';
import { useIsMobile } from '../hooks/use-mobile';
import { useNavigationContextSafe } from './Layout/NavigationContext';
import { cn } from '../utils';
import { useChatSession } from '../hooks/useChatSession';
import { acpDeleteSession } from '../acp/sessions';
import { useNavigation } from '../hooks/useNavigation';
import { RecipeHeader } from './RecipeHeader';
import { RecipeWarningModal } from './ui/RecipeWarningModal';
import { scanRecipe } from '../recipe';
import type { Recipe } from '../recipe';
import RecipeActivities from './recipes/RecipeActivities';
import {
  getTextAndImageContent,
  type ImageData,
  type Message,
  type UserInput,
} from '../types/message';
import { substituteParameters } from '../utils/parameterSubstitution';
import { useAutoSubmit } from '../hooks/useAutoSubmit';
import SessionActionsHeader from './SessionActionsHeader';
import { isAcpRecovering, subscribeToAcpRecovery } from '../acp/acpConnection';
import {
  setAccordLockTaskAuthorization,
  useAccordLockTaskAuthorization,
  useAccordLockTaskAuthorizationExpiry,
} from '../accordlock/taskAuthorizationStore';
import { useTaskSubmit } from '../accordlock/useTaskSubmit';
import { validateAccordLockObjective } from '../accordlock/taskObjective';
import { buildTaskReport, hasPendingTaskDecision } from '../accordlock/taskReport';
import { taskNotificationForReport } from '../accordlock/taskNotifications';
import { TaskStatusPanel } from './accordlock/TaskStatusPanel';
import { stopAndRevokeTask } from '../accordlock/taskLifecycle';

const i18n = defineMessages({
  failedToLoadSession: {
    id: 'baseChat.failedToLoadSession',
    defaultMessage: 'Could not load task',
  },
  goHome: {
    id: 'baseChat.goHome',
    defaultMessage: 'Go home',
  },
  retry: {
    id: 'baseChat.retry',
    defaultMessage: 'Retry',
  },
  reconnecting: {
    id: 'baseChat.reconnecting',
    defaultMessage: 'Connection lost. Reconnecting…',
  },
  endTaskFailed: {
    id: 'baseChat.endTaskFailed',
    defaultMessage:
      'Work stopped, but AccordLock could not confirm that Task access ended. Wait for the security runtime before continuing.',
  },
  taskInputRequired: {
    id: 'baseChat.taskInputRequired',
    defaultMessage:
      'Start a new task with a text goal and no attachments. You can add context after approval.',
  },
});

export function formatAccordLockRemaining(seconds: number): string {
  const safeSeconds = Math.max(0, Math.floor(seconds));
  const hours = Math.floor(safeSeconds / 3_600);
  const minutes = Math.ceil((safeSeconds % 3_600) / 60);
  if (hours > 0) return minutes > 0 ? `${hours}h ${minutes}m` : `${hours}h`;
  return `${Math.max(1, minutes)}m`;
}

export function taskWorkspaceName(path: string | undefined): string {
  if (!path) return 'Selected workspace';
  const segments = path.split(/[\\/]/).filter(Boolean);
  return segments.length > 0 ? segments[segments.length - 1] : 'Selected workspace';
}

interface BaseChatProps {
  setChat: (chat: ChatType) => void;
  onMessageSubmit?: (message: string) => void;
  renderHeader?: () => React.ReactNode;
  customChatInputProps?: Record<string, unknown>;
  customMainLayoutProps?: Record<string, unknown>;
  contentClassName?: string;
  disableSearch?: boolean;
  suppressEmptyState: boolean;
  sessionId: string;
  isActiveSession: boolean;
  initialMessage?: UserInput;
  noAutoSubmit?: boolean;
}

export default function BaseChat({
  setChat,
  renderHeader,
  customChatInputProps = {},
  customMainLayoutProps = {},
  sessionId,
  initialMessage,
  noAutoSubmit,
  isActiveSession,
}: BaseChatProps) {
  const intl = useIntl();
  const location = useLocation();
  const navigate = useNavigate();
  const scrollRef = useRef<ScrollAreaHandle>(null);
  const chatInputRef = useRef<HTMLTextAreaElement>(null);
  const preparedRecipeObjectiveRef = useRef<string | null>(null);
  const activeRunSeenRef = useRef(false);
  const disableAnimation = location.state?.disableAnimation || false;
  const [hasStartedUsingRecipe, setHasStartedUsingRecipe] = React.useState(false);
  const [hasNotAcceptedRecipe, setHasNotAcceptedRecipe] = useState<boolean>();
  const [hasRecipeSecurityWarnings, setHasRecipeSecurityWarnings] = useState(false);
  const [acpRecovering, setAcpRecovering] = useState(isAcpRecovering);
  const [nowSeconds, setNowSeconds] = useState(() => Math.floor(Date.now() / 1_000));
  const [isEndingTask, setIsEndingTask] = useState(false);
  const [taskEndError, setTaskEndError] = useState(false);
  const [taskInputError, setTaskInputError] = useState(false);
  const [isModelSlow, setIsModelSlow] = useState(false);
  const isMobile = useIsMobile();
  const navContext = useNavigationContextSafe();
  const setView = useNavigation();
  const isNavCollapsed = !navContext?.isNavExpanded;
  const contentClassName = cn('pr-1 pb-10 pt-2', (isMobile || isNavCollapsed) && 'pt-3');
  const { droppedFiles, setDroppedFiles, handleDrop, handleDragOver } = useFileDrop();
  const onStreamFinish = useCallback(() => {}, []);

  useEffect(() => subscribeToAcpRecovery(setAcpRecovering), []);

  const {
    session,
    messages,
    chatState,
    progressMessage,
    updateSession,
    handleSubmit,
    onSteerQueuedMessage,
    submitElicitationResponse,
    stopStreaming,
    retrySessionLoad,
    sessionLoadError,
    lastRunError,
    tokenState,
    notifications: toolCallNotifications,
    pauseQueueOnStop,
    queueProcessingBlocked,
    onMessageUpdate,
  } = useChatSession({
    sessionId,
    onStreamFinish,
  });

  const recipe = session?.recipe as Recipe | null | undefined;

  const resolvedInitialMessage = useMemo((): UserInput | undefined => {
    if (!initialMessage) return undefined;
    if (recipe?.prompt && session?.user_recipe_values) {
      return {
        ...initialMessage,
        msg: substituteParameters(initialMessage.msg, session.user_recipe_values),
      };
    }
    return initialMessage;
  }, [initialMessage, recipe?.prompt, session?.user_recipe_values]);

  // noAutoSubmit only suppresses auto-submitting the initial prompt of a fresh session
  // (accordlock://new-session?prompt=...). Once the conversation has messages, later flows
  // such as forks or resumes should auto-submit normally.
  const suppressInitialAutoSubmit = noAutoSubmit && messages.length === 0;
  const taskAuthorization = useAccordLockTaskAuthorization(sessionId);
  const taskExpiry = useAccordLockTaskAuthorizationExpiry(sessionId);
  const taskApproved =
    taskAuthorization === 'APPROVED' && taskExpiry !== null && taskExpiry > nowSeconds;
  const effectiveTaskAuthorization =
    taskAuthorization === 'APPROVED' && !taskApproved ? ('REJECTED' as const) : taskAuthorization;
  const isTaskBusy =
    chatState === ChatState.Streaming ||
    chatState === ChatState.Thinking ||
    chatState === ChatState.Compacting ||
    chatState === ChatState.RestartingAgent;
  const pendingTaskDecision =
    chatState === ChatState.WaitingForUserInput || hasPendingTaskDecision(messages);
  const taskReport = useMemo(() => buildTaskReport(messages), [messages]);
  const taskObjective = useMemo(() => {
    const firstUserMessage = messages.find((message) => message.role === 'user');
    const candidate = firstUserMessage
      ? getTextAndImageContent(firstUserMessage).textContent
      : resolvedInitialMessage?.msg;
    if (!candidate) return '';
    const validated = validateAccordLockObjective(candidate);
    return validated.ok ? validated.objective : candidate.trim();
  }, [messages, resolvedInitialMessage]);
  const workspaceName = taskWorkspaceName(session?.working_dir);

  useEffect(() => {
    setTaskEndError(false);
    setTaskInputError(false);
  }, [taskAuthorization]);

  useEffect(() => {
    const timer = window.setInterval(() => setNowSeconds(Math.floor(Date.now() / 1_000)), 30_000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    if (!isTaskBusy || acpRecovering) {
      setIsModelSlow(false);
      return undefined;
    }
    const timer = window.setTimeout(() => setIsModelSlow(true), 20_000);
    return () => window.clearTimeout(timer);
  }, [acpRecovering, isTaskBusy]);

  useEffect(() => {
    if (isTaskBusy) {
      activeRunSeenRef.current = true;
      return;
    }
    if (!activeRunSeenRef.current || acpRecovering) return;

    const timer = window.setTimeout(() => {
      activeRunSeenRef.current = false;
      const taskNotification = taskNotificationForReport(taskReport, sessionId, {
        modelFailed: lastRunError !== null,
        pendingDecision: pendingTaskDecision,
      });
      void Promise.all([
        window.electron.getSetting('enableNotifications'),
        window.electron.isAnyWindowFocused(),
      ])
        .then(([notificationsEnabled, anyWindowFocused]) => {
          if (notificationsEnabled === true && !anyWindowFocused) {
            window.electron.showNotification(taskNotification);
          }
        })
        .catch((error) => console.warn('Failed to show Task status notification:', error));
    }, 150);
    return () => window.clearTimeout(timer);
  }, [acpRecovering, isTaskBusy, lastRunError, pendingTaskDecision, sessionId, taskReport]);

  useEffect(() => {
    const refreshNow = () => setNowSeconds(Math.floor(Date.now() / 1_000));
    window.electron.on('system-resume', refreshNow);
    return () => window.electron.off('system-resume', refreshNow);
  }, []);

  useEffect(() => {
    if (
      !recipe ||
      hasNotAcceptedRecipe !== false ||
      messages.length > 0 ||
      !resolvedInitialMessage ||
      taskAuthorization !== 'PENDING'
    ) {
      return;
    }
    const objective = validateAccordLockObjective(resolvedInitialMessage.msg);
    if (!objective.ok || resolvedInitialMessage.images.length > 0) {
      setTaskInputError(true);
      return;
    }
    if (preparedRecipeObjectiveRef.current === objective.objective) return;
    preparedRecipeObjectiveRef.current = objective.objective;
    window.dispatchEvent(
      new CustomEvent(AppEvents.ACCORDLOCK_TASK_AUTHORIZATION_REQUEST, {
        detail: { sessionId, objective: objective.objective },
      })
    );
  }, [
    hasNotAcceptedRecipe,
    messages.length,
    taskAuthorization,
    recipe,
    resolvedInitialMessage,
    sessionId,
  ]);

  const handleEndTask = useCallback(async () => {
    if (isEndingTask || !taskApproved) return;
    setIsEndingTask(true);
    setTaskEndError(false);
    try {
      await stopAndRevokeTask(sessionId, stopStreaming);
      setAccordLockTaskAuthorization(sessionId, 'REJECTED');
      window.dispatchEvent(
        new CustomEvent(AppEvents.CLEAR_INITIAL_MESSAGE, { detail: { sessionId } })
      );
    } catch (error) {
      console.error('Failed to end AccordLock task:', error);
      setTaskEndError(true);
    } finally {
      setIsEndingTask(false);
    }
  }, [isEndingTask, sessionId, stopStreaming, taskApproved]);
  const canAutoSubmit =
    taskApproved &&
    !acpRecovering &&
    !suppressInitialAutoSubmit &&
    (session?.session_type === 'scheduled' || !recipe || hasNotAcceptedRecipe === false);

  useAutoSubmit({
    sessionId,
    session,
    messages,
    chatState,
    initialMessage: resolvedInitialMessage,
    canAutoSubmit,
    handleSubmit,
  });

  useEffect(() => {
    let streamState: 'idle' | 'loading' | 'streaming' | 'error' = 'idle';
    if (chatState === ChatState.LoadingConversation) {
      streamState = 'loading';
    } else if (
      chatState === ChatState.Streaming ||
      chatState === ChatState.Thinking ||
      chatState === ChatState.Compacting
    ) {
      streamState = 'streaming';
    } else if (sessionLoadError) {
      streamState = 'error';
    }

    window.dispatchEvent(
      new CustomEvent(AppEvents.SESSION_STATUS_UPDATE, {
        detail: {
          sessionId,
          streamState,
          messageCount: messages.length,
        },
      })
    );
  }, [sessionId, chatState, messages.length, sessionLoadError]);

  // Generate command history from user messages (most recent first)
  const commandHistory = useMemo(() => {
    return messages
      .reduce<string[]>((history, message) => {
        if (message.role === 'user') {
          const text = getTextAndImageContent(message).textContent.trim();
          if (text) {
            history.push(text);
          }
        }
        return history;
      }, [])
      .reverse();
  }, [messages]);

  const submitUserInput = useCallback(
    (input: UserInput) => {
      handleSubmit(input);
    },
    [handleSubmit]
  );
  const submitThroughTask = useTaskSubmit({
    sessionId,
    authorization: effectiveTaskAuthorization,
    submit: submitUserInput,
  });

  const chatInputSubmit = (input: UserInput) => {
    if (recipe && input.msg.trim()) {
      setHasStartedUsingRecipe(true);
    }
    const result = submitThroughTask(input);
    setTaskInputError(result === 'INVALID_TASK');
  };

  const sessionModel = session?.model_config?.model_name ?? null;
  const sessionProvider = session?.provider_name ?? null;
  const sessionLoaded = session !== undefined;
  const latestInference = useMemo(() => {
    for (let i = messages.length - 1; i >= 0; i--) {
      const message = messages[i];
      if (
        message.role === 'assistant' &&
        message.metadata.userVisible &&
        message.metadata.inference
      ) {
        return message.metadata.inference;
      }
    }
    return null;
  }, [messages]);

  useEffect(() => {
    if (!recipe || !isActiveSession || session?.session_type === 'scheduled') return;

    (async () => {
      const accepted = await window.electron.hasAcceptedRecipeBefore(recipe);
      setHasNotAcceptedRecipe(!accepted);

      if (!accepted) {
        const scanResult = await scanRecipe(recipe);
        setHasRecipeSecurityWarnings(scanResult.has_security_warnings);
      }
    })();
  }, [recipe, isActiveSession, session?.session_type]);

  const handleRecipeAccept = async (accept: boolean) => {
    if (recipe && accept) {
      await window.electron.recordRecipeHash(recipe);
      setHasNotAcceptedRecipe(false);
      return;
    }

    if (sessionId) {
      try {
        await revokeBeforeAccordLockSessionDeletion(sessionId, () => acpDeleteSession(sessionId));
        window.dispatchEvent(new CustomEvent(AppEvents.SESSION_DELETED, { detail: { sessionId } }));
      } catch (error) {
        console.error('Failed to delete declined recipe session:', error);
      }
    }
    setView('chat');
  };

  // Track if this is the initial render for session resuming
  const initialRenderRef = useRef(true);

  // Auto-scroll when messages are loaded (for session resuming)
  const handleRenderingComplete = React.useCallback(() => {
    // Only force scroll on the very first render
    if (initialRenderRef.current && messages.length > 0) {
      initialRenderRef.current = false;
      if (scrollRef.current?.scrollToBottom) {
        scrollRef.current.scrollToBottom();
      }
    } else if (scrollRef.current?.isFollowing) {
      if (scrollRef.current?.scrollToBottom) {
        scrollRef.current.scrollToBottom();
      }
    }
  }, [messages.length]);

  // Listen for global scroll-to-bottom requests (e.g., from MCP App message actions)
  useEffect(() => {
    const handleGlobalScrollRequest = () => {
      // Add a small delay to ensure content has been rendered
      setTimeout(() => {
        if (scrollRef.current?.scrollToBottom) {
          scrollRef.current.scrollToBottom();
        }
      }, 200);
    };

    window.addEventListener(AppEvents.SCROLL_CHAT_TO_BOTTOM, handleGlobalScrollRequest);
    return () =>
      window.removeEventListener(AppEvents.SCROLL_CHAT_TO_BOTTOM, handleGlobalScrollRequest);
  }, []);

  useEffect(() => {
    if (
      isActiveSession &&
      sessionId &&
      chatInputRef.current &&
      chatState !== ChatState.LoadingConversation
    ) {
      const timeoutId = setTimeout(() => {
        chatInputRef.current?.focus();
      }, 100);
      return () => clearTimeout(timeoutId);
    }
    return undefined;
  }, [isActiveSession, sessionId, chatState]);

  useEffect(() => {
    const handleSessionForked = (event: Event) => {
      const customEvent = event as CustomEvent<{
        newSessionId: string;
        shouldStartAgent: boolean;
        editedMessage: string;
        editedImages: ImageData[];
      }>;
      window.dispatchEvent(new CustomEvent(AppEvents.SESSION_CREATED));
      const { newSessionId, shouldStartAgent, editedMessage, editedImages } = customEvent.detail;

      const params = new URLSearchParams();
      params.set('resumeSessionId', newSessionId);
      if (shouldStartAgent) {
        params.set('shouldStartAgent', 'true');
      }

      navigate(`/pair?${params.toString()}`, {
        state: {
          disableAnimation: true,
          initialMessage: { msg: editedMessage, images: editedImages },
        },
      });
    };

    window.addEventListener(AppEvents.SESSION_FORKED, handleSessionForked);

    return () => {
      window.removeEventListener(AppEvents.SESSION_FORKED, handleSessionForked);
    };
  }, [location.pathname, navigate]);

  const lastSetNameRef = useRef<string>('');

  useEffect(() => {
    const currentSessionName = session?.name;
    if (currentSessionName && currentSessionName !== lastSetNameRef.current) {
      lastSetNameRef.current = currentSessionName;
      setChat({
        messages,
        recipe,
        sessionId,
        name: currentSessionName,
      });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session?.name, setChat]);

  // If we have a recipe prompt and user recipe values, substitute parameters
  let recipePrompt = '';
  if (messages.length === 0 && recipe?.prompt) {
    recipePrompt = session?.user_recipe_values
      ? substituteParameters(recipe.prompt, session.user_recipe_values)
      : recipe.prompt;
  }

  const initialPrompt =
    noAutoSubmit && messages.length === 0 && resolvedInitialMessage?.msg
      ? resolvedInitialMessage.msg
      : recipePrompt;

  if (sessionLoadError) {
    return (
      <div className="h-full flex flex-col min-h-0">
        <MainPanelLayout
          backgroundColor={'bg-background-primary'}
          removeTopPadding={true}
          {...customMainLayoutProps}
        >
          {renderHeader && renderHeader()}
          <div className="flex flex-col flex-1 min-h-0 relative">
            <div className="flex-1 flex items-center justify-center">
              <div className="flex flex-col items-center justify-center p-8">
                <div className="text-red-700 dark:text-red-300 bg-red-400/50 p-4 rounded-lg mb-4 max-w-md">
                  <h3 className="font-semibold mb-2">
                    {intl.formatMessage(i18n.failedToLoadSession)}
                  </h3>
                  <p className="text-sm">{sessionLoadError}</p>
                </div>
                <div className="flex gap-2">
                  <Button variant="outline" onClick={() => void retrySessionLoad()}>
                    {intl.formatMessage(i18n.retry)}
                  </Button>
                  <Button variant="outline" onClick={() => setView('chat')}>
                    {intl.formatMessage(i18n.goHome)}
                  </Button>
                </div>
              </div>
            </div>
          </div>
        </MainPanelLayout>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col min-h-0">
      <MainPanelLayout
        backgroundColor={'bg-background-primary'}
        removeTopPadding={true}
        {...customMainLayoutProps}
      >
        {/* Custom header */}
        {renderHeader && renderHeader()}

        {/* Chat container with sticky recipe header */}
        <div className="flex flex-col flex-1 min-h-0 relative">
          <SessionActionsHeader session={session} onSessionChange={updateSession} />

          <TaskStatusPanel
            authorization={effectiveTaskAuthorization}
            expiresAt={taskApproved ? taskExpiry : null}
            expiresIn={
              taskApproved && taskExpiry !== null
                ? formatAccordLockRemaining(taskExpiry - nowSeconds)
                : null
            }
            isBusy={isTaskBusy}
            isModelSlow={isModelSlow}
            isStopping={isEndingTask}
            modelFailed={lastRunError !== null}
            objective={taskObjective}
            onStopAndLock={() => void handleEndTask()}
            pendingDecision={pendingTaskDecision}
            report={taskReport}
            runtimeUnavailable={acpRecovering}
            sessionId={sessionId}
            taskApproved={taskApproved}
            workspace={workspaceName}
          />

          <ScrollArea
            ref={scrollRef}
            className={`flex-1 min-h-0 relative ${contentClassName}`}
            autoScroll
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            data-drop-zone="true"
            paddingX={6}
            paddingY={0}
          >
            {recipe?.title && (
              <div className="sticky top-0 z-10 bg-background-primary px-0 -mx-6 mb-6 pt-6">
                <RecipeHeader title={recipe.title} />
              </div>
            )}

            {recipe && (
              <div className={hasStartedUsingRecipe ? 'mb-6' : ''}>
                <RecipeActivities
                  append={(text: string) => chatInputSubmit({ msg: text, images: [] })}
                  activities={Array.isArray(recipe.activities) ? recipe.activities : null}
                  title={recipe.title}
                  parameterValues={session?.user_recipe_values || {}}
                />
              </div>
            )}

            {messages.length > 0 || recipe ? (
              <>
                <SearchView>
                  <ProgressiveMessageList
                    messages={messages}
                    chat={{ sessionId }}
                    toolCallNotifications={toolCallNotifications}
                    append={(text: string) => chatInputSubmit({ msg: text, images: [] })}
                    isUserMessage={(m: Message) => m.role === 'user'}
                    isStreamingMessage={chatState !== ChatState.Idle}
                    onRenderingComplete={handleRenderingComplete}
                    onMessageUpdate={onMessageUpdate}
                    submitElicitationResponse={submitElicitationResponse}
                  />
                </SearchView>

                <div className="block h-8" />
              </>
            ) : null}
          </ScrollArea>

          {chatState !== ChatState.Idle && (
            <div className="absolute bottom-1 left-4 z-20 pointer-events-none">
              <LoadingGoose chatState={chatState} message={progressMessage} />
            </div>
          )}
        </div>

        {acpRecovering && (
          <div role="status" className="mx-4 mb-2 text-sm text-text-secondary">
            {intl.formatMessage(i18n.reconnecting)}
          </div>
        )}

        {taskEndError && (
          <div role="alert" className="mx-4 mb-2 text-sm text-text-danger">
            {intl.formatMessage(i18n.endTaskFailed)}
          </div>
        )}

        {taskInputError && (
          <div role="alert" className="mx-4 mb-2 text-sm text-text-danger">
            {intl.formatMessage(i18n.taskInputRequired)}
          </div>
        )}

        <ChatInputCard
          className={cn(
            'relative z-30 mx-4 mb-4',
            !disableAnimation && 'animate-[fadein_400ms_ease-in_forwards]'
          )}
        >
          <ChatInput
            inputRef={chatInputRef}
            sessionId={sessionId}
            handleSubmit={chatInputSubmit}
            chatState={chatState}
            onStop={stopStreaming}
            onSteerQueuedMessage={onSteerQueuedMessage}
            pauseQueueOnStop={pauseQueueOnStop}
            queueProcessingBlocked={queueProcessingBlocked || acpRecovering}
            commandHistory={commandHistory}
            initialValue={initialPrompt}
            setView={setView}
            totalTokens={tokenState?.totalTokens ?? session?.usage?.total_tokens ?? undefined}
            accumulatedInputTokens={
              tokenState?.accumulatedInputTokens ??
              session?.accumulated_usage?.input_tokens ??
              undefined
            }
            accumulatedOutputTokens={
              tokenState?.accumulatedOutputTokens ??
              session?.accumulated_usage?.output_tokens ??
              undefined
            }
            accumulatedCost={tokenState?.accumulatedCost ?? session?.accumulated_cost ?? undefined}
            droppedFiles={droppedFiles}
            onFilesProcessed={() => setDroppedFiles([])} // Clear dropped files after processing
            messages={messages}
            disableAnimation={disableAnimation}
            recipe={recipe}
            recipeAccepted={!hasNotAcceptedRecipe}
            initialPrompt={initialPrompt}
            sessionModel={sessionModel}
            sessionProvider={sessionProvider}
            sessionLoaded={sessionLoaded}
            workingDir={session?.working_dir}
            latestInference={latestInference}
            showExtensionSelector={false}
            {...customChatInputProps}
          />
        </ChatInputCard>
      </MainPanelLayout>

      {recipe && isActiveSession && session?.session_type !== 'scheduled' && (
        <RecipeWarningModal
          isOpen={!!hasNotAcceptedRecipe}
          onConfirm={() => handleRecipeAccept(true)}
          onCancel={() => handleRecipeAccept(false)}
          recipeDetails={{
            title: recipe.title,
            description: recipe.description,
            instructions: recipe.instructions || undefined,
          }}
          hasSecurityWarnings={hasRecipeSecurityWarnings}
        />
      )}
    </div>
  );
}
