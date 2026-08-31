import * as DialogPrimitive from '@radix-ui/react-dialog';
import { CircleAlert, LoaderCircle, ShieldCheck } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import type { AccordLockTaskAuthorizationDecision } from '../../accordlock/taskIpc';
import {
  createAccordLockTaskAuthorizationDecisionRequest,
  parseAccordLockTaskAuthorizationDecisionAck,
  type AccordLockTaskAuthorization,
} from '../../accordlock/taskAuthorizationContract';
import { defineMessages, useIntl } from '../../i18n';
import { Button } from '../ui/button';

const i18n = defineMessages({
  openingTitle: {
    id: 'accordLock.taskAuthorization.openingTitle',
    defaultMessage: 'Opening task review…',
  },
  openingDescription: {
    id: 'accordLock.taskAuthorization.openingDescription',
    defaultMessage: 'Review the folder and allowed actions.',
  },
  cancellingTitle: {
    id: 'accordLock.taskAuthorization.cancellingTitle',
    defaultMessage: 'Cancelling task…',
  },
  cancellingDescription: {
    id: 'accordLock.taskAuthorization.cancellingDescription',
    defaultMessage: 'No task access will be granted.',
  },
  errorTitle: {
    id: 'accordLock.taskAuthorization.errorTitle',
    defaultMessage: 'Couldn’t open confirmation',
  },
  errorDescription: {
    id: 'accordLock.taskAuthorization.errorDescription',
    defaultMessage: 'Try again or cancel the task.',
  },
  retry: {
    id: 'accordLock.taskAuthorization.retry',
    defaultMessage: 'Try again',
  },
  cancel: {
    id: 'accordLock.taskAuthorization.cancel',
    defaultMessage: 'Cancel task',
  },
});

type DecisionState =
  | { phase: 'OPENING'; decision: AccordLockTaskAuthorizationDecision }
  | { phase: 'FAILED' };

export type AccordLockAutonomyMode = 'CAUTIOUS' | 'BALANCED' | 'AUTONOMOUS';

interface TaskAuthorizationDialogProps {
  authorization: AccordLockTaskAuthorization;
  submitDecision: (
    request: ReturnType<typeof createAccordLockTaskAuthorizationDecisionRequest>
  ) => Promise<unknown>;
  onResolved: () => void;
  onProtocolError?: (message: string) => void;
  pendingDecisionCount?: number;
  persistAutonomyMode?: (mode: AccordLockAutonomyMode) => Promise<void>;
}

export function TaskAuthorizationDialog({
  authorization,
  submitDecision,
  onResolved,
  onProtocolError,
  persistAutonomyMode,
}: TaskAuthorizationDialogProps) {
  const intl = useIntl();
  const [decisionState, setDecisionState] = useState<DecisionState>({
    phase: 'OPENING',
    decision: 'APPROVE',
  });
  const activeAuthorization = useRef<string | null>(null);
  const decisionInFlight = useRef(false);
  const mounted = useRef(false);
  const requestSequence = useRef(0);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const decide = useCallback(
    async (decision: AccordLockTaskAuthorizationDecision) => {
      if (decisionInFlight.current) return;

      decisionInFlight.current = true;
      const sequence = ++requestSequence.current;
      setDecisionState({ phase: 'OPENING', decision });

      try {
        if (decision === 'APPROVE') {
          if (Math.floor(Date.now() / 1_000) >= authorization.expires_at) {
            throw new Error('Task authorization expired before confirmation opened');
          }
          await persistAutonomyMode?.('AUTONOMOUS');
        }

        const rawAcknowledgement = await submitDecision(
          createAccordLockTaskAuthorizationDecisionRequest(authorization, decision)
        );
        parseAccordLockTaskAuthorizationDecisionAck(rawAcknowledgement, authorization, decision);

        if (mounted.current && requestSequence.current === sequence) {
          decisionInFlight.current = false;
          onResolved();
        }
      } catch (error) {
        if (mounted.current && requestSequence.current === sequence) {
          decisionInFlight.current = false;
          setDecisionState({ phase: 'FAILED' });
          onProtocolError?.(error instanceof Error ? error.message : 'Invalid runtime response');
        }
      }
    },
    [authorization, onProtocolError, onResolved, persistAutonomyMode, submitDecision]
  );

  useEffect(() => {
    const identity = `${authorization.authorization_id}\u0000${authorization.authorization_digest}`;
    if (activeAuthorization.current === identity) return;
    activeAuthorization.current = identity;
    decisionInFlight.current = false;
    void decide('APPROVE');
  }, [authorization.authorization_digest, authorization.authorization_id, decide]);

  const failed = decisionState.phase === 'FAILED';
  const cancelling = decisionState.phase === 'OPENING' && decisionState.decision === 'REJECT';
  const title = failed
    ? intl.formatMessage(i18n.errorTitle)
    : intl.formatMessage(cancelling ? i18n.cancellingTitle : i18n.openingTitle);
  const description = failed
    ? intl.formatMessage(i18n.errorDescription)
    : intl.formatMessage(cancelling ? i18n.cancellingDescription : i18n.openingDescription);

  return (
    <DialogPrimitive.Root open>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 z-[10000] bg-black/35 backdrop-blur-sm data-[state=open]:animate-in data-[state=open]:fade-in-0" />
        <DialogPrimitive.Content
          className="fixed left-1/2 top-1/2 z-[10001] w-[min(420px,calc(100vw-32px))] -translate-x-1/2 -translate-y-1/2 rounded-2xl border border-border-primary bg-background-primary p-5 text-text-primary shadow-2xl outline-none"
          onEscapeKeyDown={(event) => event.preventDefault()}
          onPointerDownOutside={(event) => event.preventDefault()}
        >
          <div className="flex items-start gap-3.5">
            <div
              className={`flex size-10 shrink-0 items-center justify-center rounded-xl ${
                failed
                  ? 'bg-background-danger/10 text-text-danger'
                  : 'bg-background-secondary text-text-secondary'
              }`}
            >
              {failed ? (
                <CircleAlert className="size-5" aria-hidden="true" />
              ) : (
                <LoaderCircle className="size-5 animate-spin" aria-hidden="true" />
              )}
            </div>
            <div className="min-w-0 flex-1">
              <DialogPrimitive.Title className="text-[17px] font-medium tracking-[-0.01em]">
                {title}
              </DialogPrimitive.Title>
              <DialogPrimitive.Description
                className="mt-1 text-sm leading-5 text-text-secondary"
                role={failed ? 'alert' : 'status'}
                aria-live="polite"
              >
                {description}
              </DialogPrimitive.Description>
              <p
                className="mt-3 line-clamp-2 border-t border-border-primary pt-3 text-xs leading-5 text-text-tertiary"
                title={authorization.objective}
              >
                {authorization.objective}
              </p>
            </div>
          </div>

          {failed && (
            <div className="mt-5 flex justify-end gap-2 border-t border-border-primary pt-4">
              <Button variant="outline" autoFocus onClick={() => void decide('REJECT')}>
                {intl.formatMessage(i18n.cancel)}
              </Button>
              <Button onClick={() => void decide('APPROVE')}>
                <ShieldCheck aria-hidden="true" />
                {intl.formatMessage(i18n.retry)}
              </Button>
            </div>
          )}
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}
