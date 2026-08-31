// Modified by AccordLock contributors; see UPSTREAM.md.
import type { GooseServeExitSignal, GooseServeResult, Logger } from './gooseServe';

export const GOOSE_SERVE_EXITED_USER_MESSAGE =
  "This window's local agent engine stopped. Close this window and start a new task. If this keeps happening, restart AccordLock.";

export interface GooseServeLease {
  acpUrl: string;
  secretKey: string;
  cleanup: () => Promise<void>;
  windowIds: Set<number>;
  cleanedUp: boolean;
  exited: boolean;
  exitCode: number | null;
  exitSignal: GooseServeExitSignal;
  unexpectedExitHandled: boolean;
}

export type UnexpectedGooseServeExitHandler = (
  lease: GooseServeLease,
  windowIds: readonly number[]
) => void | Promise<void>;

export class GooseServeLeaseRegistry {
  private leasesByWindowId = new Map<number, GooseServeLease>();

  constructor(
    private readonly logger: Logger,
    private readonly onUnexpectedExit: UnexpectedGooseServeExitHandler
  ) {}

  private notifyUnexpectedExit(lease: GooseServeLease): void {
    if (lease.cleanedUp || lease.unexpectedExitHandled || lease.windowIds.size === 0) {
      return;
    }
    lease.unexpectedExitHandled = true;
    const windowIds = [...lease.windowIds];
    void Promise.resolve(this.onUnexpectedExit(lease, windowIds)).catch((error) => {
      this.logger.error('Failed to revoke AccordLock authority after backend exit:', error);
    });
  }

  create(result: GooseServeResult, secretKey: string): GooseServeLease {
    const lease: GooseServeLease = {
      acpUrl: result.acpUrl,
      secretKey,
      cleanup: result.cleanup,
      windowIds: new Set<number>(),
      cleanedUp: false,
      exited: false,
      exitCode: null,
      exitSignal: null,
      unexpectedExitHandled: false,
    };

    const markExited = ({
      code,
      signal,
      logUnexpected,
    }: {
      code?: number | null;
      signal?: GooseServeExitSignal;
      logUnexpected: boolean;
    }) => {
      const firstExit = !lease.exited;
      lease.exited = true;
      if (code !== undefined) {
        lease.exitCode = code;
      }
      if (signal !== undefined) {
        lease.exitSignal = signal;
      }

      if (logUnexpected && firstExit && !lease.cleanedUp) {
        this.logger.error('Goose ACP server exited unexpectedly', {
          code: lease.exitCode,
          signal: lease.exitSignal,
          windowIds: [...lease.windowIds],
        });
        this.notifyUnexpectedExit(lease);
      }
    };

    result.process.once('exit', (code, signal) => {
      markExited({ code, signal, logUnexpected: true });
    });

    if (result.hasExited()) {
      const exitDetails = result.getExitDetails();
      markExited({ code: exitDetails.code, signal: exitDetails.signal, logUnexpected: false });
    }

    return lease;
  }

  createExternal(
    acpUrl: string,
    secretKey: string,
    cleanup: () => Promise<void> = async () => undefined
  ): GooseServeLease {
    return {
      acpUrl,
      secretKey,
      cleanup,
      windowIds: new Set<number>(),
      cleanedUp: false,
      exited: false,
      exitCode: null,
      exitSignal: null,
      unexpectedExitHandled: false,
    };
  }

  get(windowId: number): GooseServeLease | null {
    return this.leasesByWindowId.get(windowId) ?? null;
  }

  getAcpUrl(windowId: number): string | null {
    const lease = this.get(windowId);
    if (!lease) {
      return null;
    }
    if (lease.exited) {
      throw new Error(GOOSE_SERVE_EXITED_USER_MESSAGE);
    }
    return lease.acpUrl;
  }

  getSecretKey(windowId: number): string | null {
    const lease = this.get(windowId);
    if (!lease) {
      return null;
    }
    if (lease.exited) {
      throw new Error(GOOSE_SERVE_EXITED_USER_MESSAGE);
    }
    return lease.secretKey;
  }

  attachWindow(windowId: number, lease: GooseServeLease) {
    lease.windowIds.add(windowId);
    this.leasesByWindowId.set(windowId, lease);
    if (lease.exited) {
      this.notifyUnexpectedExit(lease);
    }
  }

  async releaseWindow(windowId: number) {
    const lease = this.leasesByWindowId.get(windowId);
    this.leasesByWindowId.delete(windowId);

    if (!lease) {
      return;
    }

    lease.windowIds.delete(windowId);
    if (lease.windowIds.size === 0) {
      await this.cleanupLease(lease);
    }
  }

  async cleanupLease(lease: GooseServeLease) {
    if (lease.cleanedUp) {
      return;
    }

    lease.cleanedUp = true;
    for (const windowId of lease.windowIds) {
      this.leasesByWindowId.delete(windowId);
    }
    lease.windowIds.clear();

    try {
      await lease.cleanup();
    } catch (error) {
      this.logger.error('Failed to cleanup goose serve backend:', error);
    }
  }

  activeLeaseCount(): number {
    return this.uniqueLeases().length;
  }

  async cleanupAll() {
    await Promise.all(this.uniqueLeases().map((lease) => this.cleanupLease(lease)));
  }

  private uniqueLeases(): GooseServeLease[] {
    return [...new Set(this.leasesByWindowId.values())];
  }
}
