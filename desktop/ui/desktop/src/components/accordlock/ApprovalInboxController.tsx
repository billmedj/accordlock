import { useEffect, useMemo, useRef } from 'react';
import {
  parseApprovalInboxItem,
  parseApprovalInboxItems,
  type ApprovalInboxItem,
} from '../../accordlock/approvalInbox';
import { createAccordLockApprovalInboxBridge } from '../../accordlock/approvalInboxBridge';
import type { AccordLockApprovalInboxBridge } from '../../accordlock/approvalInboxIpc';
import {
  createLocalApprovalNotificationAdapter,
  type LocalApprovalNotificationAdapter,
} from '../../accordlock/approvalNotifications';
import { approvalInboxStore, type ApprovalInboxStore } from '../../accordlock/approvalInboxStore';

const CAPACITY_ERROR = 'Approval inbox capacity reached; the action remains blocked';

export interface LocalNotificationPolicy {
  shouldNotify(): Promise<boolean>;
}

export interface ApprovalNotificationLifecycle {
  dismiss(approvalId: string): void;
}

export function shouldShowLocalNotification(enabled: unknown, anyWindowFocused: boolean): boolean {
  return enabled === true && !anyWindowFocused;
}

export const desktopLocalNotificationPolicy: LocalNotificationPolicy = Object.freeze({
  async shouldNotify(): Promise<boolean> {
    const [enabled, focused] = await Promise.all([
      window.electron.getSetting('enableNotifications'),
      window.electron.isAnyWindowFocused(),
    ]);
    return shouldShowLocalNotification(enabled, focused);
  },
});

const desktopApprovalNotificationLifecycle: ApprovalNotificationLifecycle = Object.freeze({
  dismiss: (approvalId: string) => window.electron.dismissApprovalNotification(approvalId),
});

interface ApprovalInboxControllerProps {
  bridge?: AccordLockApprovalInboxBridge;
  notificationLifecycle?: ApprovalNotificationLifecycle;
  notificationPolicy?: LocalNotificationPolicy;
  notificationAdapter?: LocalApprovalNotificationAdapter;
  store?: ApprovalInboxStore;
}

function parseProjection(value: unknown): readonly ApprovalInboxItem[] {
  return Array.isArray(value) ? parseApprovalInboxItems(value) : [parseApprovalInboxItem(value)];
}

/** Keeps the global inbox current even while the Approval Center route is closed. */
export function ApprovalInboxController({
  bridge,
  notificationLifecycle = desktopApprovalNotificationLifecycle,
  notificationPolicy = desktopLocalNotificationPolicy,
  notificationAdapter,
  store = approvalInboxStore,
}: ApprovalInboxControllerProps) {
  const activeBridge = useMemo(() => bridge ?? createAccordLockApprovalInboxBridge(), [bridge]);
  const activeNotifications = useMemo(
    () =>
      notificationAdapter ??
      createLocalApprovalNotificationAdapter({
        showNotification: (data) => window.electron.showNotification(data),
      }),
    [notificationAdapter]
  );
  const notifiedItemIds = useRef(new Set<string>());

  useEffect(() => {
    let disposed = false;

    const notifyIfAllowed = (item: ApprovalInboxItem) => {
      if (notifiedItemIds.current.has(item.id)) return;
      notifiedItemIds.current.add(item.id);
      void Promise.resolve()
        .then(() => notificationPolicy.shouldNotify())
        .then((allowed) => {
          if (!allowed || disposed) return;
          const current = store.getSnapshot().find((candidate) => candidate.id === item.id);
          const nowSeconds = Math.floor(Date.now() / 1_000);
          if (current?.status === 'PENDING' && current.binding.requestExpiresAt > nowSeconds) {
            activeNotifications.notify(current, nowSeconds);
          }
        })
        .catch(() => {
          // Notification delivery is optional and never changes approval authority.
        });
    };

    const accept = (value: unknown) => {
      try {
        const items = parseProjection(value);
        const nowSeconds = Math.floor(Date.now() / 1_000);
        for (const item of items) {
          store.upsert(item);
          if (item.status === 'PENDING' && item.binding.requestExpiresAt > nowSeconds) {
            notifyIfAllowed(item);
          } else {
            notifiedItemIds.current.delete(item.id);
            notificationLifecycle.dismiss(item.id);
          }
        }
      } catch (error) {
        activeBridge.reportProtocolError(
          error instanceof Error && error.message === CAPACITY_ERROR
            ? CAPACITY_ERROR
            : 'Rejected malformed approval inbox projection'
        );
      }
    };

    const unsubscribe = activeBridge.subscribe((value) => {
      if (!disposed) accept(value);
    });
    void Promise.resolve()
      .then(() => activeBridge.getPendingApprovals())
      .then((value) => {
        if (!disposed) accept(value);
      })
      .catch(() => {
        // The main process remains the authority. Missing projections cannot
        // unblock an action and are retried by the next event or app restart.
      });

    const expiryTimer = window.setInterval(() => {
      const nowSeconds = Math.floor(Date.now() / 1_000);
      const expiring = store
        .getSnapshot()
        .filter(
          (candidate) =>
            candidate.status === 'PENDING' && candidate.binding.requestExpiresAt <= nowSeconds
        )
        .map((candidate) => candidate.id);
      store.expire(nowSeconds);
      for (const approvalId of expiring) {
        notifiedItemIds.current.delete(approvalId);
        notificationLifecycle.dismiss(approvalId);
      }
    }, 1_000);

    return () => {
      disposed = true;
      unsubscribe();
      window.clearInterval(expiryTimer);
    };
  }, [activeBridge, activeNotifications, notificationLifecycle, notificationPolicy, store]);

  return null;
}
