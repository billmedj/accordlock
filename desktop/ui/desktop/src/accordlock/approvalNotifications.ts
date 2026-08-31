import type { ApprovalInboxItem } from './approvalInbox';
import type { AccordLockNotificationRequest } from './notificationNavigation';

export interface LocalNotificationBridge {
  showNotification(data: AccordLockNotificationRequest): void;
}

export interface LocalApprovalNotificationAdapter {
  readonly capabilities: Readonly<{
    click: 'OPEN_APPROVAL';
    decision: 'IN_APP_ONLY';
    delivery: 'DISPLAY_ONLY';
  }>;
  notify(item: ApprovalInboxItem, nowSeconds: number): boolean;
}

export function approvalNotificationForItem(
  item: ApprovalInboxItem,
  nowSeconds: number
): AccordLockNotificationRequest | null {
  if (item.status !== 'PENDING' || nowSeconds >= item.binding.requestExpiresAt) return null;
  // Deliberately excludes objective, path, command, content, and binding hashes.
  return {
    kind: 'APPROVAL_REQUIRED',
    open: Object.freeze({ kind: 'APPROVAL' as const, approvalId: item.id }),
  };
}

/**
 * Uses the existing display-only Electron bridge. It cannot submit a decision;
 * clicking the OS notification opens the exact request inside AccordLock.
 */
export function createLocalApprovalNotificationAdapter(
  bridge: LocalNotificationBridge
): LocalApprovalNotificationAdapter {
  return Object.freeze({
    capabilities: Object.freeze({
      click: 'OPEN_APPROVAL' as const,
      decision: 'IN_APP_ONLY' as const,
      delivery: 'DISPLAY_ONLY' as const,
    }),
    notify(item: ApprovalInboxItem, nowSeconds: number): boolean {
      const notification = approvalNotificationForItem(item, nowSeconds);
      if (!notification) return false;
      bridge.showNotification(notification);
      return true;
    },
  });
}
