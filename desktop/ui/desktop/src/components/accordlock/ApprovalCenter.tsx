import {
  Ban,
  ChevronDown,
  CircleCheck,
  Clock3,
  Inbox,
  LoaderCircle,
  ShieldOff,
  Square,
} from 'lucide-react';
import { useEffect, useMemo, useRef, useState, type ComponentRef } from 'react';
import {
  approvalDecisionAvailability,
  createApprovalCenterDecision,
  effectiveApprovalInboxStatus,
  type ApprovalCenterDecision,
  type ApprovalCenterIntent,
  type ApprovalInboxItem,
  type ApprovalInboxStatus,
} from '../../accordlock/approvalInbox';
import { intentReviewDescription } from '../../accordlock/intentReview';
import { relevantUserLimits, type IntentActionKind } from '../../accordlock/taskIntent';
import {
  useAccordLockTaskAuthorization,
  useAccordLockTaskAuthorizationExpiry,
} from '../../accordlock/taskAuthorizationStore';
import { Button } from '../ui/button';

export interface ApprovalCenterProps {
  focusItemId?: string;
  items: readonly ApprovalInboxItem[];
  nowSeconds?: number;
  onDecision: (decision: ApprovalCenterDecision) => Promise<void> | void;
}

function useNowSeconds(fixedNow: number | undefined): number {
  const [clock, setClock] = useState(() => Math.floor(Date.now() / 1_000));
  useEffect(() => {
    if (fixedNow !== undefined) return undefined;
    const timer = window.setInterval(() => setClock(Math.floor(Date.now() / 1_000)), 1_000);
    return () => window.clearInterval(timer);
  }, [fixedNow]);
  return fixedNow ?? clock;
}

function expiryLabel(expiresAt: number, nowSeconds: number): string {
  const remaining = expiresAt - nowSeconds;
  if (remaining <= 0) return 'Expired';
  if (remaining < 60) return `Expires in ${remaining}s`;
  if (remaining < 3_600) return `Expires in ${Math.ceil(remaining / 60)}m`;
  return `Expires in ${Math.ceil(remaining / 3_600)}h`;
}

function statusLabel(status: ApprovalInboxStatus): string {
  switch (status) {
    case 'PENDING':
      return 'Review needed';
    case 'ALLOWED_ONCE':
      return 'Approved once';
    case 'DENIED':
      return 'Denied';
    case 'EXPIRED':
      return 'Expired';
    case 'TASK_STOPPED':
      return 'Task stopped';
    case 'ACCESS_REVOKED':
      return 'Access revoked';
  }
}

function shortDigest(digest: string): string {
  return `${digest.slice(0, 15)}…${digest.slice(-8)}`;
}

function actionKindForApproval(item: ApprovalInboxItem): IntentActionKind | null {
  switch (item.operationLabel) {
    case 'Create file':
    case 'Replace file':
      return 'write';
    case 'Edit file':
      return 'edit';
    case 'Move file to recovery storage':
      return 'delete_file';
    case 'Run program':
      return 'shell';
    case 'Read website':
      return 'https_request';
    default:
      return null;
  }
}

function ApprovalCard({
  focusRequested,
  item,
  nowSeconds,
  onDecision,
}: {
  focusRequested: boolean;
  item: ApprovalInboxItem;
  nowSeconds: number;
  onDecision: ApprovalCenterProps['onDecision'];
}) {
  const cardRef = useRef<HTMLElement>(null);
  const taskAccess = useAccordLockTaskAuthorization(item.binding.sessionId);
  const storedTaskExpiry = useAccordLockTaskAuthorizationExpiry(item.binding.sessionId);
  const availability = approvalDecisionAvailability(item, taskAccess, nowSeconds, storedTaskExpiry);
  const status = effectiveApprovalInboxStatus(item, nowSeconds);
  const [inFlight, setInFlight] = useState<ApprovalCenterIntent | null>(null);
  const [error, setError] = useState(false);
  const actionKind = actionKindForApproval(item);
  const userLimits = actionKind ? relevantUserLimits(item.objective, actionKind) : [];

  useEffect(() => {
    if (!focusRequested || !cardRef.current) return;
    cardRef.current.focus({ preventScroll: true });
    cardRef.current.scrollIntoView({ block: 'center' });
  }, [focusRequested]);

  const decide = async (intent: ApprovalCenterIntent) => {
    if (inFlight) return;
    setError(false);
    try {
      const decision = createApprovalCenterDecision(
        item,
        intent,
        taskAccess,
        nowSeconds,
        storedTaskExpiry
      );
      setInFlight(intent);
      await onDecision(decision);
    } catch {
      setError(true);
    } finally {
      setInFlight(null);
    }
  };

  const actionPending = status === 'PENDING';
  const statusTone =
    status === 'PENDING'
      ? 'text-text-secondary'
      : status === 'ALLOWED_ONCE'
        ? 'text-text-primary'
        : 'text-text-danger';

  return (
    <article
      ref={cardRef}
      tabIndex={-1}
      className={`rounded-xl border border-border-primary bg-background-primary p-4 shadow-sm outline-none transition-shadow ${
        focusRequested ? 'ring-2 ring-inset ring-ring' : ''
      }`}
    >
      <div className="flex items-start gap-3">
        <div className="mt-0.5 flex size-9 shrink-0 items-center justify-center rounded-lg bg-background-secondary text-text-secondary">
          {status === 'ALLOWED_ONCE' ? (
            <CircleCheck aria-hidden="true" className="size-4" />
          ) : (
            <Clock3 aria-hidden="true" className="size-4" />
          )}
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <h2 className="truncate text-[15px] font-medium text-text-primary">
                {item.operationLabel}
              </h2>
              {actionPending && (
                <p className="mt-0.5 truncate text-sm text-text-secondary" title={item.target}>
                  {item.target}
                </p>
              )}
            </div>
            <span className={`shrink-0 text-xs ${statusTone}`}>{statusLabel(status)}</span>
          </div>

          {actionPending && (
            <>
              <div className="mt-3 rounded-lg bg-background-secondary px-3 py-2.5">
                <p className="text-xs font-medium text-text-primary">Task check</p>
                <p className="mt-0.5 text-xs leading-5 text-text-secondary">
                  {intentReviewDescription(item.intentReview ?? 'POLICY_REVIEW')}
                </p>
              </div>

              {userLimits.length > 0 && (
                <div className="mt-2 rounded-lg border border-yellow-500/25 bg-yellow-500/10 px-3 py-2.5">
                  <p className="text-xs font-medium text-text-primary">Your limit</p>
                  {userLimits.map((limit) => (
                    <p key={limit} className="mt-0.5 text-xs leading-5 text-text-secondary">
                      {limit}
                    </p>
                  ))}
                </div>
              )}

              <div className="mt-3 flex items-center gap-2 text-xs text-text-tertiary">
                <Clock3 aria-hidden="true" className="size-3.5" />
                <span>{expiryLabel(item.binding.requestExpiresAt, nowSeconds)}</span>
              </div>

              <details className="group mt-3 border-t border-border-primary pt-3">
                <summary className="flex cursor-pointer list-none items-center gap-1.5 text-sm text-text-secondary hover:text-text-primary [&::-webkit-details-marker]:hidden">
                  <ChevronDown
                    aria-hidden="true"
                    className="size-4 transition-transform group-open:rotate-180"
                  />
                  Review details
                </summary>
                <div className="mt-3 rounded-lg bg-background-secondary p-3">
                  <p className="text-xs text-text-tertiary">{item.contentEvidence}</p>
                  <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-words font-mono text-xs leading-5 text-text-primary">
                    {item.preview || '(empty content)'}
                  </pre>
                  <dl className="mt-3 grid gap-1 border-t border-border-primary pt-3 text-xs text-text-tertiary">
                    <div className="grid grid-cols-[auto,minmax(0,1fr)] gap-3">
                      <dt>Task</dt>
                      <dd className="text-right text-text-secondary">{item.objective}</dd>
                    </div>
                    <div className="flex justify-between gap-3">
                      <dt>Request ID</dt>
                      <dd className="font-mono" title={item.binding.approvalRequestHash}>
                        {shortDigest(item.binding.approvalRequestHash)}
                      </dd>
                    </div>
                    <div className="flex justify-between gap-3">
                      <dt>{item.targetLabel}</dt>
                      <dd className="truncate text-right" title={item.target}>
                        {item.target}
                      </dd>
                    </div>
                  </dl>
                </div>
              </details>
            </>
          )}

          {actionPending && (
            <div className="mt-4 flex flex-wrap justify-end gap-2">
              <Button
                variant="outline"
                disabled={!availability.denyAction || inFlight !== null}
                onClick={() => void decide('DENY_ACTION')}
              >
                <Ban aria-hidden="true" />
                Keep blocked
              </Button>
              <Button
                disabled={!availability.allowOnce || inFlight !== null}
                onClick={() => void decide('ALLOW_ONCE')}
              >
                {inFlight === 'ALLOW_ONCE' ? (
                  <LoaderCircle aria-hidden="true" className="animate-spin" />
                ) : (
                  <CircleCheck aria-hidden="true" />
                )}
                Approve once
              </Button>
            </div>
          )}

          {!item.canAllowOnce && actionPending && (
            <p className="mt-2 text-right text-xs text-text-danger">
              This request is incomplete and cannot be approved.
            </p>
          )}

          <details className="group mt-3 border-t border-border-primary pt-3">
            <summary className="flex cursor-pointer list-none items-center gap-1.5 text-sm text-text-secondary hover:text-text-primary [&::-webkit-details-marker]:hidden">
              <ChevronDown
                aria-hidden="true"
                className="size-4 transition-transform group-open:rotate-180"
              />
              Task controls
            </summary>
            <div className="mt-3 grid gap-2">
              <div className="flex items-center justify-between gap-4 rounded-lg bg-background-secondary p-3">
                <div className="min-w-0">
                  <p className="text-sm font-medium text-text-primary">Stop task</p>
                  <p className="mt-0.5 text-xs leading-5 text-text-secondary">
                    End the current run and revoke its access.
                  </p>
                </div>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={!availability.stopTask || inFlight !== null}
                  onClick={() => void decide('STOP_TASK')}
                >
                  <Square aria-hidden="true" />
                  Stop task
                </Button>
              </div>
              <div className="flex items-center justify-between gap-4 rounded-lg bg-background-secondary p-3">
                <div className="min-w-0">
                  <p className="text-sm font-medium text-text-primary">Revoke access</p>
                  <p className="mt-0.5 text-xs leading-5 text-text-secondary">
                    Block future actions. The current run is not stopped.
                  </p>
                </div>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={!availability.revokeAccess || inFlight !== null}
                  onClick={() => void decide('REVOKE_ACCESS')}
                >
                  <ShieldOff aria-hidden="true" />
                  Revoke access
                </Button>
              </div>
            </div>
          </details>

          {error && (
            <p className="mt-3 text-sm text-text-danger" role="alert">
              Couldn’t record your decision. The action remains blocked.
            </p>
          )}
        </div>
      </div>
    </article>
  );
}

export function ApprovalCenter({
  items,
  focusItemId,
  nowSeconds: fixedNow,
  onDecision,
}: ApprovalCenterProps) {
  const nowSeconds = useNowSeconds(fixedNow);
  const recentDecisionsRef = useRef<ComponentRef<'details'>>(null);
  const orderedItems = useMemo(
    () =>
      [...items].sort(
        (left, right) => left.receivedAt - right.receivedAt || left.id.localeCompare(right.id)
      ),
    [items]
  );
  const pendingItems = orderedItems.filter(
    (item) => effectiveApprovalInboxStatus(item, nowSeconds) === 'PENDING'
  );
  const resolvedItems = orderedItems
    .filter((item) => effectiveApprovalInboxStatus(item, nowSeconds) !== 'PENDING')
    .reverse();
  const waiting = pendingItems.length;
  const focusedItemPresent =
    focusItemId === undefined || orderedItems.some((item) => item.id === focusItemId);
  const focusedResolved = resolvedItems.some((item) => item.id === focusItemId);

  useEffect(() => {
    if (focusedResolved && recentDecisionsRef.current) {
      recentDecisionsRef.current.open = true;
    }
  }, [focusItemId, focusedResolved]);

  return (
    <section
      className="mx-auto w-full max-w-[900px] px-8 pb-10 pt-12"
      aria-labelledby="approval-center-title"
    >
      <header className="mb-6 flex items-end justify-between gap-4">
        <div>
          <h1
            id="approval-center-title"
            className="text-4xl font-light tracking-[-0.035em] text-text-primary"
          >
            Approvals
          </h1>
          <p className="mt-1 text-sm text-text-secondary">
            {waiting === 1 ? '1 decision waiting' : `${waiting} decisions waiting`}
          </p>
        </div>
      </header>

      {!focusedItemPresent && (
        <div
          className="mb-4 rounded-xl border border-border-primary bg-background-secondary px-4 py-3"
          role="status"
        >
          <p className="text-sm font-medium text-text-primary">
            This request was resolved or expired.
          </p>
        </div>
      )}

      {pendingItems.length === 0 ? (
        <div className="flex min-h-64 flex-col items-center justify-center rounded-2xl border border-dashed border-border-primary px-6 text-center">
          <div className="flex size-10 items-center justify-center rounded-xl bg-background-secondary text-text-secondary">
            <Inbox aria-hidden="true" className="size-5" />
          </div>
          <h2 className="mt-4 text-base font-medium text-text-primary">No approvals waiting</h2>
        </div>
      ) : (
        <div className="grid gap-3">
          {pendingItems.map((item) => (
            <ApprovalCard
              key={item.id}
              focusRequested={item.id === focusItemId}
              item={item}
              nowSeconds={nowSeconds}
              onDecision={onDecision}
            />
          ))}
        </div>
      )}

      {resolvedItems.length > 0 && (
        <details
          ref={recentDecisionsRef}
          className="group mt-6 border-t border-border-primary pt-4"
        >
          <summary className="flex cursor-pointer list-none items-center gap-2 text-sm text-text-secondary hover:text-text-primary [&::-webkit-details-marker]:hidden">
            <ChevronDown
              aria-hidden="true"
              className="size-4 transition-transform group-open:rotate-180"
            />
            Recent decisions
            <span className="text-xs text-text-tertiary">{resolvedItems.length}</span>
          </summary>
          <div className="mt-3 grid gap-3">
            {resolvedItems.map((item) => (
              <ApprovalCard
                key={item.id}
                focusRequested={item.id === focusItemId}
                item={item}
                nowSeconds={nowSeconds}
                onDecision={onDecision}
              />
            ))}
          </div>
        </details>
      )}
    </section>
  );
}
