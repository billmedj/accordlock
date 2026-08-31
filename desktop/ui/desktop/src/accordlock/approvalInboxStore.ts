import { useSyncExternalStore } from 'react';
import {
  approvalInboxStatusForDecisionIntent,
  approvalCenterDecisionMatchesItem,
  effectiveApprovalInboxStatus,
  sameExactActionBinding,
  type ApprovalCenterDecision,
  type ApprovalInboxItem,
} from './approvalInbox';

type Listener = () => void;

export const MAX_PENDING_APPROVALS = 128;
export const MAX_RETAINED_RESOLVED_APPROVALS = 32;

const CLEARED_REQUEST_DETAILS = 'Request details cleared after resolution';

function sortItems(items: ApprovalInboxItem[]): ApprovalInboxItem[] {
  return items.sort(
    (left, right) => left.receivedAt - right.receivedAt || left.id.localeCompare(right.id)
  );
}

export class ApprovalInboxStore {
  private readonly items = new Map<string, ApprovalInboxItem>();
  private readonly listeners = new Set<Listener>();
  private snapshot: readonly ApprovalInboxItem[] = Object.freeze([]);

  getSnapshot = (): readonly ApprovalInboxItem[] => this.snapshot;

  subscribe = (listener: Listener): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  private commit(): void {
    this.snapshot = Object.freeze(sortItems([...this.items.values()]));
    for (const listener of this.listeners) listener();
  }

  private pendingCount(): number {
    let count = 0;
    for (const item of this.items.values()) {
      if (item.status === 'PENDING') count += 1;
    }
    return count;
  }

  private scrubResolved(item: ApprovalInboxItem): ApprovalInboxItem {
    if (item.status === 'PENDING') return item;
    return Object.freeze({
      ...item,
      binding: Object.freeze({ ...item.binding }),
      canAllowOnce: false,
      contentEvidence: CLEARED_REQUEST_DETAILS,
      objective: 'Completed request',
      preview: '',
      target: 'Details cleared',
      targetLabel: 'Target',
      workspaceRoot: 'Details cleared',
    });
  }

  private pruneResolved(): void {
    const resolved = [...this.items.values()]
      .filter((item) => item.status !== 'PENDING')
      .sort((left, right) => right.receivedAt - left.receivedAt || right.id.localeCompare(left.id));
    for (const item of resolved.slice(MAX_RETAINED_RESOLVED_APPROVALS)) {
      this.items.delete(item.id);
    }
  }

  upsert(item: ApprovalInboxItem): void {
    const previous = this.items.get(item.id);
    if (previous && !sameExactActionBinding(previous.binding, item.binding)) {
      throw new Error('Approval inbox identifier collision');
    }
    if (
      previous?.status !== undefined &&
      previous.status !== 'PENDING' &&
      item.status === 'PENDING'
    ) {
      throw new Error('Resolved approval cannot become pending again');
    }
    if (previous === item) return;
    if (!previous && item.status === 'PENDING' && this.pendingCount() >= MAX_PENDING_APPROVALS) {
      throw new Error('Approval inbox capacity reached; the action remains blocked');
    }
    const stored = Object.freeze({ ...item, binding: Object.freeze({ ...item.binding }) });
    this.items.set(item.id, this.scrubResolved(stored));
    this.pruneResolved();
    this.commit();
  }

  remove(itemId: string): boolean {
    const removed = this.items.delete(itemId);
    if (removed) this.commit();
    return removed;
  }

  clear(): void {
    if (this.items.size === 0) return;
    this.items.clear();
    this.commit();
  }

  expire(nowSeconds: number): number {
    let expired = 0;
    for (const [id, item] of this.items) {
      if (item.status !== 'PENDING') continue;
      if (effectiveApprovalInboxStatus(item, nowSeconds) !== 'EXPIRED') continue;
      this.items.set(id, this.scrubResolved(Object.freeze({ ...item, status: 'EXPIRED' })));
      expired += 1;
    }
    if (expired > 0) {
      this.pruneResolved();
      this.commit();
    }
    return expired;
  }

  /** Call only after the trusted resolver acknowledges the decision. */
  settle(decision: ApprovalCenterDecision): ApprovalInboxItem {
    const current = this.items.get(decision.itemId);
    if (!current || !approvalCenterDecisionMatchesItem(decision, current)) {
      throw new Error('Decision does not match the pending approval');
    }

    const taskControlAfterAction =
      (current.status === 'ALLOWED_ONCE' ||
        current.status === 'DENIED' ||
        current.status === 'EXPIRED') &&
      (decision.intent === 'STOP_TASK' || decision.intent === 'REVOKE_ACCESS');
    const acknowledgedActionBeforeExpiry =
      current.status === 'EXPIRED' &&
      (decision.intent === 'ALLOW_ONCE' || decision.intent === 'DENY_ACTION') &&
      decision.issuedAt < current.binding.requestExpiresAt;
    if (
      current.status !== 'PENDING' &&
      !taskControlAfterAction &&
      !acknowledgedActionBeforeExpiry
    ) {
      throw new Error('Approval already has a final decision');
    }
    if (
      (decision.intent === 'ALLOW_ONCE' || decision.intent === 'DENY_ACTION') &&
      decision.issuedAt >= current.binding.requestExpiresAt
    ) {
      throw new Error('Approval expired before the decision was recorded');
    }

    const settled = this.scrubResolved(
      Object.freeze({
        ...current,
        status: approvalInboxStatusForDecisionIntent(decision.intent),
      })
    );
    this.items.set(current.id, settled);
    this.pruneResolved();
    this.commit();
    return settled;
  }
}

export const approvalInboxStore = new ApprovalInboxStore();

export function useApprovalInbox(
  store: ApprovalInboxStore = approvalInboxStore
): readonly ApprovalInboxItem[] {
  return useSyncExternalStore(store.subscribe, store.getSnapshot, store.getSnapshot);
}
