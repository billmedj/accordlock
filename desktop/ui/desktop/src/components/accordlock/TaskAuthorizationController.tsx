import * as DialogPrimitive from '@radix-ui/react-dialog';
import { CircleAlert, LockKeyhole } from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { createAccordLockTaskBridge, type AccordLockTaskBridge } from '../../accordlock/taskBridge';
import {
  clearAccordLockTaskAuthorization,
  getAccordLockTaskAuthorization,
  setAccordLockTaskAuthorization,
} from '../../accordlock/taskAuthorizationStore';
import {
  parseAccordLockTaskAuthorizationDecisionAck,
  parseAccordLockTaskAuthorizationRevokeAck,
  parseAccordLockTaskAuthorization,
  parseAccordLockTaskAuthorizationQueue,
  type AccordLockTaskAuthorization,
} from '../../accordlock/taskAuthorizationContract';
import { ACCORDLOCK_CONTROL_PROTOCOL } from '../../accordlock/taskIpc';
import { AppEvents } from '../../constants/events';
import { defineMessages, useIntl } from '../../i18n';
import { useConfig } from '../ConfigContext';
import { Button } from '../ui/button';
import { TaskAuthorizationDialog, type AccordLockAutonomyMode } from './TaskAuthorizationDialog';

const i18n = defineMessages({
  protocolTitle: {
    id: 'accordLock.taskAuthorization.protocolTitle',
    defaultMessage: 'Task blocked',
  },
  protocolDescription: {
    id: 'accordLock.taskAuthorization.protocolDescription',
    defaultMessage:
      'AccordLock could not verify this task. No actions can run. Restart AccordLock and try again.',
  },
  keepLocked: {
    id: 'accordLock.taskAuthorization.keepLocked',
    defaultMessage: 'Close',
  },
});

interface TaskAuthorizationControllerProps {
  bridge?: AccordLockTaskBridge;
  persistAutonomyMode?: (mode: AccordLockAutonomyMode) => Promise<void>;
}

const MAX_BROWSER_TIMEOUT_MS = 2_147_000_000;

const gooseModeByAutonomyMode: Record<AccordLockAutonomyMode, string> = {
  CAUTIOUS: 'approve',
  BALANCED: 'smart_approve',
  AUTONOMOUS: 'auto',
};

export function ConfiguredTaskAuthorizationController() {
  const { upsert } = useConfig();
  const persistAutonomyMode = useCallback(
    (mode: AccordLockAutonomyMode) => upsert('GOOSE_MODE', gooseModeByAutonomyMode[mode], false),
    [upsert]
  );
  return <TaskAuthorizationController persistAutonomyMode={persistAutonomyMode} />;
}

export function TaskAuthorizationController({
  bridge,
  persistAutonomyMode,
}: TaskAuthorizationControllerProps) {
  const intl = useIntl();
  const activeBridge = useMemo(() => bridge ?? createAccordLockTaskBridge(), [bridge]);
  const [authorizations, setAuthorizations] = useState<AccordLockTaskAuthorization[]>([]);
  const [protocolFailure, setProtocolFailure] = useState(false);
  const authorizationsRef = useRef<AccordLockTaskAuthorization[]>([]);
  const preparationsBySession = useRef(
    new Map<string, { generation: number; objective: string }>()
  );
  const generationBySession = useRef(new Map<string, number>());
  const generationByAuthorization = useRef(new Map<string, number>());
  const deletedSessions = useRef(new Set<string>());
  const terminalAuthorizationIds = useRef(new Set<string>());
  const revocationsBySession = useRef(new Set<string>());
  const expiryTimersBySession = useRef(new Map<string, number>());

  const commitAuthorizations = useCallback((next: AccordLockTaskAuthorization[]) => {
    authorizationsRef.current = next;
    setAuthorizations(next);
  }, []);

  const removeAuthorization = useCallback(
    (authorizationId: string) => {
      terminalAuthorizationIds.current.add(authorizationId);
      generationByAuthorization.current.delete(authorizationId);
      commitAuthorizations(
        authorizationsRef.current.filter(
          (candidate) => candidate.authorization_id !== authorizationId
        )
      );
    },
    [commitAuthorizations]
  );

  const enqueueAuthorizations = useCallback(
    (incoming: readonly AccordLockTaskAuthorization[]) => {
      let next = [...authorizationsRef.current];
      let changed = false;
      const knownAuthorizationIds = new Set(next.map((candidate) => candidate.authorization_id));
      for (const candidate of incoming) {
        if (
          knownAuthorizationIds.has(candidate.authorization_id) ||
          terminalAuthorizationIds.current.has(candidate.authorization_id) ||
          deletedSessions.current.has(candidate.session_id)
        ) {
          continue;
        }
        const superseded = next.filter(
          (queued) =>
            queued.session_id === candidate.session_id &&
            queued.authorization_id !== candidate.authorization_id
        );
        for (const queued of superseded) {
          terminalAuthorizationIds.current.add(queued.authorization_id);
          generationByAuthorization.current.delete(queued.authorization_id);
          knownAuthorizationIds.delete(queued.authorization_id);
        }
        if (superseded.length > 0) {
          next = next.filter((queued) => queued.session_id !== candidate.session_id);
          changed = true;
        }
        const generation = generationBySession.current.get(candidate.session_id) ?? 0;
        generationByAuthorization.current.set(candidate.authorization_id, generation);
        setAccordLockTaskAuthorization(candidate.session_id, 'PENDING');
        knownAuthorizationIds.add(candidate.authorization_id);
        next.push(candidate);
        changed = true;
      }
      if (changed) commitAuthorizations(next);
    },
    [commitAuthorizations]
  );

  const acceptAuthorizationProjection = useCallback(
    (value: unknown) => {
      if (value === null || value === undefined) return;
      try {
        const verifiedAuthorizations = Array.isArray(value)
          ? parseAccordLockTaskAuthorizationQueue(value)
          : [parseAccordLockTaskAuthorization(value)];
        setProtocolFailure(false);
        enqueueAuthorizations(verifiedAuthorizations);
      } catch {
        activeBridge.reportProtocolError('Rejected malformed task authorization projection');
        setProtocolFailure(true);
      }
    },
    [activeBridge, enqueueAuthorizations]
  );

  const handleAuthorizationProtocolError = useCallback(
    (message: string) => {
      activeBridge.reportProtocolError(message);
      void activeBridge
        .getPendingTaskAuthorizations()
        .then(acceptAuthorizationProjection)
        .catch(() => {
          // The currently displayed authorization remains locked. Runtime supervision
          // owns availability reporting; a refresh cannot create authority.
        });
    },
    [acceptAuthorizationProjection, activeBridge]
  );

  const revokeExpiredTask = useCallback(
    (sessionId: string) => {
      setAccordLockTaskAuthorization(sessionId, 'REJECTED');
      window.dispatchEvent(
        new CustomEvent(AppEvents.CLEAR_INITIAL_MESSAGE, { detail: { sessionId } })
      );
      void activeBridge
        .revokeTaskAuthorization({
          protocol: ACCORDLOCK_CONTROL_PROTOCOL,
          schema_version: 2,
          session_id: sessionId,
        })
        .then((value) => parseAccordLockTaskAuthorizationRevokeAck(value, sessionId))
        .catch(() => {
          activeBridge.reportProtocolError('Expired task could not be revoked; it remains locked');
          setProtocolFailure(true);
        });
    },
    [activeBridge]
  );

  const armTaskExpiry = useCallback(
    (sessionId: string, expiresAt: number) => {
      const schedule = () => {
        const remaining = expiresAt * 1_000 - Date.now();
        if (remaining <= 0) {
          expiryTimersBySession.current.delete(sessionId);
          revokeExpiredTask(sessionId);
          return;
        }
        const timer = window.setTimeout(schedule, Math.min(remaining, MAX_BROWSER_TIMEOUT_MS));
        expiryTimersBySession.current.set(sessionId, timer);
      };
      schedule();
    },
    [revokeExpiredTask]
  );

  useEffect(() => {
    let disposed = false;
    const unsubscribe = activeBridge.subscribeTaskAuthorizations((value) => {
      if (!disposed) acceptAuthorizationProjection(value);
    });
    void activeBridge
      .getPendingTaskAuthorizations()
      .then((value) => {
        if (!disposed) acceptAuthorizationProjection(value);
      })
      .catch(() => {
        // Startup supervision reports runtime availability. Absence of a pending
        // authorization is not authority and does not need a renderer-level warning.
      });
    return () => {
      disposed = true;
      unsubscribe();
    };
  }, [acceptAuthorizationProjection, activeBridge]);

  useEffect(() => {
    let disposed = false;
    const expiryTimers = expiryTimersBySession.current;

    const revokeDeletedSession = (sessionId: string) => {
      if (revocationsBySession.current.has(sessionId)) return;
      revocationsBySession.current.add(sessionId);
      void activeBridge
        .revokeTaskAuthorization({
          protocol: ACCORDLOCK_CONTROL_PROTOCOL,
          schema_version: 2,
          session_id: sessionId,
        })
        .then((value) => {
          parseAccordLockTaskAuthorizationRevokeAck(value, sessionId);
        })
        .catch(() => {
          if (disposed) return;
          revocationsBySession.current.delete(sessionId);
          activeBridge.reportProtocolError(
            'Deleted task could not be revoked; the session remains locked'
          );
          setProtocolFailure(true);
        });
    };

    const prepare = (sessionId: string, objective: string) => {
      const generation = generationBySession.current.get(sessionId) ?? 0;
      if (preparationsBySession.current.has(sessionId)) return;
      const preparation = { generation, objective };
      preparationsBySession.current.set(sessionId, preparation);
      setAccordLockTaskAuthorization(sessionId, 'PENDING');
      void activeBridge
        .requestTaskAuthorization({
          protocol: ACCORDLOCK_CONTROL_PROTOCOL,
          schema_version: 2,
          session_id: sessionId,
          objective,
        })
        .then((value) => {
          if (value === null || value === undefined) return;
          const preparedAuthorization = parseAccordLockTaskAuthorization(value);
          if (preparedAuthorization.session_id !== sessionId) {
            throw new Error('Prepared authorization is bound to another session');
          }
          if (
            disposed ||
            deletedSessions.current.has(sessionId) ||
            (generationBySession.current.get(sessionId) ?? 0) !== generation
          ) {
            terminalAuthorizationIds.current.add(preparedAuthorization.authorization_id);
            revokeDeletedSession(sessionId);
            return;
          }
          enqueueAuthorizations([preparedAuthorization]);
        })
        .catch(() => {
          if (disposed || deletedSessions.current.has(sessionId)) return;
          setAccordLockTaskAuthorization(sessionId, 'REJECTED');
          window.dispatchEvent(
            new CustomEvent(AppEvents.CLEAR_INITIAL_MESSAGE, { detail: { sessionId } })
          );
          activeBridge.reportProtocolError('Task preparation failed; the session remains locked');
          setProtocolFailure(true);
        })
        .finally(() => {
          if (preparationsBySession.current.get(sessionId) === preparation) {
            preparationsBySession.current.delete(sessionId);
          }
        });
    };
    const prepareInitialTask = (event: Event) => {
      const detail = (event as CustomEvent<unknown>).detail;
      if (typeof detail !== 'object' || detail === null || !('sessionId' in detail)) return;
      const sessionId = (detail as { sessionId?: unknown }).sessionId;
      if (typeof sessionId !== 'string' || !sessionId.trim()) return;
      deletedSessions.current.delete(sessionId);
      if (
        (detail as { noAutoSubmit?: unknown }).noAutoSubmit === true ||
        (detail as { deferTaskAuthorization?: unknown }).deferTaskAuthorization === true
      ) {
        setAccordLockTaskAuthorization(sessionId, 'PENDING');
        return;
      }
      const authorization = getAccordLockTaskAuthorization(sessionId);
      if (authorization === 'APPROVED' || authorization === 'REJECTED') return;
      const initialMessage = (detail as { initialMessage?: unknown }).initialMessage;
      const objective =
        typeof initialMessage === 'object' &&
        initialMessage !== null &&
        'msg' in initialMessage &&
        typeof (initialMessage as { msg?: unknown }).msg === 'string'
          ? (initialMessage as { msg: string }).msg.trim()
          : '';
      if (objective) prepare(sessionId, objective);
    };
    const prepareSubmittedTask = (event: Event) => {
      const detail = (event as CustomEvent<unknown>).detail;
      if (typeof detail !== 'object' || detail === null) return;
      const sessionId = (detail as { sessionId?: unknown }).sessionId;
      const objective = (detail as { objective?: unknown }).objective;
      if (
        typeof sessionId !== 'string' ||
        !sessionId.trim() ||
        typeof objective !== 'string' ||
        !objective.trim()
      ) {
        return;
      }
      deletedSessions.current.delete(sessionId);
      if (getAccordLockTaskAuthorization(sessionId) === 'APPROVED') return;
      setAccordLockTaskAuthorization(sessionId, 'PENDING');
      prepare(sessionId, objective.trim());
    };
    const forget = (event: Event) => {
      const detail = (event as CustomEvent<{ sessionId?: unknown }>).detail;
      if (typeof detail?.sessionId === 'string') {
        const sessionId = detail.sessionId;
        const expiryTimer = expiryTimers.get(sessionId);
        if (expiryTimer !== undefined) window.clearTimeout(expiryTimer);
        expiryTimers.delete(sessionId);
        deletedSessions.current.add(sessionId);
        generationBySession.current.set(
          sessionId,
          (generationBySession.current.get(sessionId) ?? 0) + 1
        );
        preparationsBySession.current.delete(sessionId);
        revokeDeletedSession(sessionId);
        const removed = authorizationsRef.current.filter(
          (candidate) => candidate.session_id === sessionId
        );
        for (const removedAuthorization of removed) {
          terminalAuthorizationIds.current.add(removedAuthorization.authorization_id);
          generationByAuthorization.current.delete(removedAuthorization.authorization_id);
        }
        if (removed.length > 0) {
          commitAuthorizations(
            authorizationsRef.current.filter((candidate) => candidate.session_id !== sessionId)
          );
        }
        clearAccordLockTaskAuthorization(sessionId);
      }
    };
    window.addEventListener(AppEvents.ADD_ACTIVE_SESSION, prepareInitialTask);
    window.addEventListener(AppEvents.ACCORDLOCK_TASK_AUTHORIZATION_REQUEST, prepareSubmittedTask);
    window.addEventListener(AppEvents.SESSION_DELETED, forget);
    return () => {
      disposed = true;
      for (const timer of expiryTimers.values()) window.clearTimeout(timer);
      expiryTimers.clear();
      window.removeEventListener(AppEvents.ADD_ACTIVE_SESSION, prepareInitialTask);
      window.removeEventListener(
        AppEvents.ACCORDLOCK_TASK_AUTHORIZATION_REQUEST,
        prepareSubmittedTask
      );
      window.removeEventListener(AppEvents.SESSION_DELETED, forget);
    };
  }, [activeBridge, commitAuthorizations, enqueueAuthorizations]);

  const submitTaskDecision = useCallback(
    async (
      taskAuthorization: AccordLockTaskAuthorization,
      request: Parameters<AccordLockTaskBridge['submitTaskAuthorizationDecision']>[0]
    ) => {
      const value = await activeBridge.submitTaskAuthorizationDecision(request);
      const acknowledgement = parseAccordLockTaskAuthorizationDecisionAck(
        value,
        taskAuthorization,
        request.decision
      );
      terminalAuthorizationIds.current.add(taskAuthorization.authorization_id);
      const expectedGeneration = generationByAuthorization.current.get(
        taskAuthorization.authorization_id
      );
      const currentGeneration = generationBySession.current.get(taskAuthorization.session_id) ?? 0;
      if (
        expectedGeneration !== undefined &&
        expectedGeneration === currentGeneration &&
        !deletedSessions.current.has(taskAuthorization.session_id)
      ) {
        setAccordLockTaskAuthorization(
          taskAuthorization.session_id,
          acknowledgement.status,
          acknowledgement.status === 'APPROVED' ? taskAuthorization.expires_at : undefined
        );
        const previousTimer = expiryTimersBySession.current.get(taskAuthorization.session_id);
        if (previousTimer !== undefined) window.clearTimeout(previousTimer);
        expiryTimersBySession.current.delete(taskAuthorization.session_id);
        if (acknowledgement.status === 'APPROVED') {
          armTaskExpiry(taskAuthorization.session_id, taskAuthorization.expires_at);
        }
      }
      if (acknowledgement.status === 'REJECTED') {
        // A rejected Hub objective must never auto-submit later if the user
        // starts a different task in this still-empty session.
        window.dispatchEvent(
          new CustomEvent(AppEvents.CLEAR_INITIAL_MESSAGE, {
            detail: { sessionId: taskAuthorization.session_id },
          })
        );
      }
      return value;
    },
    [activeBridge, armTaskExpiry]
  );

  const authorization = authorizations[0] ?? null;

  useEffect(() => {
    if (!authorization) return;
    const remaining = Math.max(0, authorization.expires_at * 1_000 - Date.now());
    const timer = window.setTimeout(
      () => {
        void activeBridge
          .getPendingTaskAuthorizations()
          .then(acceptAuthorizationProjection)
          .catch(() => {
            // The stale authorization remains visibly locked and cannot be approved.
          });
      },
      Math.min(remaining + 25, MAX_BROWSER_TIMEOUT_MS)
    );
    return () => window.clearTimeout(timer);
  }, [acceptAuthorizationProjection, activeBridge, authorization]);

  return (
    <>
      {authorization && (
        <TaskAuthorizationDialog
          key={authorization.authorization_id}
          authorization={authorization}
          submitDecision={(request) => submitTaskDecision(authorization, request)}
          onResolved={() => removeAuthorization(authorization.authorization_id)}
          onProtocolError={handleAuthorizationProtocolError}
          pendingDecisionCount={authorizations.length}
          persistAutonomyMode={persistAutonomyMode}
        />
      )}

      <DialogPrimitive.Root open={protocolFailure}>
        <DialogPrimitive.Portal>
          <DialogPrimitive.Overlay className="fixed inset-0 z-[10000] bg-black/45 backdrop-blur-md" />
          <DialogPrimitive.Content
            className="fixed left-1/2 top-1/2 z-[10001] w-[min(440px,calc(100vw-32px))] -translate-x-1/2 -translate-y-1/2 rounded-2xl border border-border-danger bg-background-primary p-6 text-text-primary shadow-2xl outline-none"
            onEscapeKeyDown={(event) => event.preventDefault()}
            onPointerDownOutside={(event) => event.preventDefault()}
          >
            <div className="flex items-start gap-4">
              <div className="flex size-10 shrink-0 items-center justify-center rounded-xl bg-background-danger/10 text-text-danger">
                <CircleAlert className="size-5" aria-hidden="true" />
              </div>
              <div>
                <DialogPrimitive.Title className="text-lg font-medium">
                  {intl.formatMessage(i18n.protocolTitle)}
                </DialogPrimitive.Title>
                <DialogPrimitive.Description className="mt-2 text-sm leading-6 text-text-secondary">
                  {intl.formatMessage(i18n.protocolDescription)}
                </DialogPrimitive.Description>
              </div>
            </div>
            <div className="mt-5 flex items-center justify-between gap-4 border-t border-border-primary pt-5">
              <LockKeyhole className="size-4 text-text-secondary" aria-hidden="true" />
              <Button variant="outline" onClick={() => setProtocolFailure(false)}>
                {intl.formatMessage(i18n.keepLocked)}
              </Button>
            </div>
          </DialogPrimitive.Content>
        </DialogPrimitive.Portal>
      </DialogPrimitive.Root>
    </>
  );
}
