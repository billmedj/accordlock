import { useCallback, useMemo } from 'react';
import { useSearchParams } from 'react-router';
import { acpChatSessionController } from '../../acp/chatSessionController';
import {
  approvalCenterDecisionMatchesItem,
  approvalInboxStatusForDecisionIntent,
  parseApprovalCenterDecision,
  type ApprovalCenterDecision,
} from '../../accordlock/approvalInbox';
import { createAccordLockApprovalInboxBridge } from '../../accordlock/approvalInboxBridge';
import type { AccordLockApprovalInboxBridge } from '../../accordlock/approvalInboxIpc';
import {
  approvalInboxStore,
  type ApprovalInboxStore,
  useApprovalInbox,
} from '../../accordlock/approvalInboxStore';
import { setAccordLockTaskAuthorization } from '../../accordlock/taskAuthorizationStore';
import { revokeAccordLockTaskAuthorization } from '../../accordlock/taskBridge';
import { parseNotificationOpenTarget } from '../../accordlock/notificationNavigation';
import { AppEvents } from '../../constants/events';
import { MainPanelLayout } from '../Layout/MainPanelLayout';
import { ApprovalCenter } from './ApprovalCenter';

interface ApprovalCenterDecisionDependencies {
  bridge: Pick<AccordLockApprovalInboxBridge, 'submitDecision'>;
  lockTask(sessionId: string): void;
  nowSeconds(): number;
  revokeTask(sessionId: string): Promise<unknown>;
  stopTask(sessionId: string): void;
  store: ApprovalInboxStore;
}

function applyAcknowledgedDecision(
  store: ApprovalInboxStore,
  acknowledgement: ApprovalCenterDecision
): void {
  const current = store.getSnapshot().find((candidate) => candidate.id === acknowledgement.itemId);
  if (!current || !approvalCenterDecisionMatchesItem(acknowledgement, current)) {
    throw new Error('Approval acknowledgement does not match the inbox');
  }

  const expectedStatus = approvalInboxStatusForDecisionIntent(acknowledgement.intent);
  if (current.status === expectedStatus) return;
  store.settle(acknowledgement);
}

export async function executeApprovalCenterDecision(
  requested: ApprovalCenterDecision,
  dependencies: ApprovalCenterDecisionDependencies
): Promise<ApprovalCenterDecision> {
  const pendingItem = dependencies.store
    .getSnapshot()
    .find((candidate) => candidate.id === requested.itemId);
  if (!pendingItem || !approvalCenterDecisionMatchesItem(requested, pendingItem)) {
    throw new Error('Approval decision does not match the inbox');
  }
  if (requested.intent === 'STOP_TASK') {
    dependencies.stopTask(requested.binding.sessionId);
  }

  const isTaskControl = requested.intent === 'STOP_TASK' || requested.intent === 'REVOKE_ACCESS';
  const actionNoLongerPending =
    pendingItem.status !== 'PENDING' ||
    dependencies.nowSeconds() >= requested.binding.requestExpiresAt;
  if (isTaskControl && actionNoLongerPending) {
    await dependencies.revokeTask(requested.binding.sessionId);
    applyAcknowledgedDecision(dependencies.store, requested);
    dependencies.lockTask(requested.binding.sessionId);
    return requested;
  }

  let rawAcknowledgement: unknown;
  try {
    rawAcknowledgement = await dependencies.bridge.submitDecision(requested);
  } catch (error) {
    if (!isTaskControl || dependencies.nowSeconds() < requested.binding.requestExpiresAt) {
      throw error;
    }
    await dependencies.revokeTask(requested.binding.sessionId);
    applyAcknowledgedDecision(dependencies.store, requested);
    dependencies.lockTask(requested.binding.sessionId);
    return requested;
  }
  const acknowledgement = parseApprovalCenterDecision(rawAcknowledgement);
  const allowedResult =
    acknowledgement.intent === requested.intent ||
    (requested.intent === 'ALLOW_ONCE' && acknowledgement.intent === 'DENY_ACTION');
  if (!allowedResult) {
    throw new Error('Approval acknowledgement changed the requested intent');
  }
  const requestedItem = dependencies.store
    .getSnapshot()
    .find((candidate) => candidate.id === requested.itemId);
  if (
    !requestedItem ||
    !approvalCenterDecisionMatchesItem(requested, requestedItem) ||
    !approvalCenterDecisionMatchesItem(acknowledgement, requestedItem)
  ) {
    throw new Error('Approval acknowledgement does not match the request');
  }

  applyAcknowledgedDecision(dependencies.store, acknowledgement);
  if (acknowledgement.intent === 'STOP_TASK' || acknowledgement.intent === 'REVOKE_ACCESS') {
    dependencies.lockTask(acknowledgement.binding.sessionId);
  }
  return acknowledgement;
}

interface ApprovalCenterRouteProps {
  bridge?: AccordLockApprovalInboxBridge;
  store?: ApprovalInboxStore;
}

export function ApprovalCenterRoute({
  bridge,
  store = approvalInboxStore,
}: ApprovalCenterRouteProps) {
  const [searchParams] = useSearchParams();
  const items = useApprovalInbox(store);
  const activeBridge = useMemo(() => bridge ?? createAccordLockApprovalInboxBridge(), [bridge]);
  const onDecision = useCallback(
    async (decision: ApprovalCenterDecision) => {
      const acknowledgement = await executeApprovalCenterDecision(decision, {
        bridge: activeBridge,
        store,
        nowSeconds: () => Math.floor(Date.now() / 1_000),
        revokeTask: (sessionId) => revokeAccordLockTaskAuthorization(sessionId),
        stopTask: (sessionId) => acpChatSessionController.stop(sessionId),
        lockTask: (sessionId) => {
          setAccordLockTaskAuthorization(sessionId, 'REJECTED');
          window.dispatchEvent(
            new CustomEvent(AppEvents.CLEAR_INITIAL_MESSAGE, { detail: { sessionId } })
          );
        },
      });
      window.electron.dismissApprovalNotification(acknowledgement.itemId);
    },
    [activeBridge, store]
  );
  const focusItemId = useMemo(() => {
    const item = searchParams.get('item');
    if (item === null) return undefined;
    try {
      const target = parseNotificationOpenTarget({ kind: 'APPROVAL', approvalId: item });
      return target.kind === 'APPROVAL' ? target.approvalId : undefined;
    } catch {
      return undefined;
    }
  }, [searchParams]);

  return (
    <MainPanelLayout>
      <div className="min-h-0 flex-1 overflow-y-auto">
        <ApprovalCenter items={items} focusItemId={focusItemId} onDecision={onDecision} />
      </div>
    </MainPanelLayout>
  );
}
