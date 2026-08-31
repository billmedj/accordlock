export interface ClosableApprovalNotification {
  close(): void;
}

/**
 * Bounded native-notification ownership. Replacing, resolving, or evicting an
 * approval closes its old OS alert so a stale click cannot imply it is active.
 */
export class ApprovalNotificationRegistry<T extends ClosableApprovalNotification> {
  private readonly entries = new Map<string, T>();

  constructor(private readonly maximumEntries = 128) {
    if (!Number.isSafeInteger(maximumEntries) || maximumEntries < 1) {
      throw new Error('Notification registry capacity must be positive');
    }
  }

  get size(): number {
    return this.entries.size;
  }

  register(approvalId: string, notification: T): void {
    const previous = this.entries.get(approvalId);
    if (previous === notification) return;
    if (previous) previous.close();
    this.entries.delete(approvalId);

    while (this.entries.size >= this.maximumEntries) {
      const oldestId = this.entries.keys().next().value as string | undefined;
      if (oldestId === undefined) break;
      this.dismiss(oldestId);
    }
    this.entries.set(approvalId, notification);
  }

  release(approvalId: string, notification: T): void {
    if (this.entries.get(approvalId) === notification) {
      this.entries.delete(approvalId);
    }
  }

  dismiss(approvalId: string): boolean {
    const notification = this.entries.get(approvalId);
    if (!notification) return false;
    this.entries.delete(approvalId);
    notification.close();
    return true;
  }

  clear(): void {
    const notifications = [...this.entries.values()];
    this.entries.clear();
    for (const notification of notifications) notification.close();
  }
}
