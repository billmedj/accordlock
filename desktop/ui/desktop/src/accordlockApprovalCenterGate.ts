import {
  approvalCenterDecisionMatchesItem,
  parseApprovalCenterDecision,
  type ApprovalCenterDecision,
  type ApprovalInboxItem,
} from './accordlock/approvalInbox';

type Completion = {
  promise: Promise<ApprovalCenterDecision>;
  reject: (error: Error) => void;
  resolve: (decision: ApprovalCenterDecision) => void;
};

function validTrustedTime(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

/**
 * Main-process single-flight gate for one exact action. Renderer timestamps and
 * bindings are treated as untrusted input and replaced or verified here.
 */
export class AccordLockApprovalCenterGate {
  readonly selection: Promise<ApprovalCenterDecision | null>;

  private resolveSelection!: (decision: ApprovalCenterDecision | null) => void;
  private selectedDecision: ApprovalCenterDecision | null | undefined;
  private completion: Completion | null = null;

  constructor(
    readonly item: ApprovalInboxItem,
    readonly windowId: number
  ) {
    this.selection = new Promise((resolve) => {
      this.resolveSelection = resolve;
    });
  }

  submit(
    candidate: unknown,
    senderWindowId: number,
    trustedNowSeconds: number
  ): Promise<ApprovalCenterDecision> {
    if (!Number.isSafeInteger(senderWindowId) || senderWindowId !== this.windowId) {
      throw new Error('Approval decision does not belong to this window');
    }
    if (!validTrustedTime(trustedNowSeconds)) {
      throw new Error('Approval decision time is invalid');
    }
    if (trustedNowSeconds >= this.item.binding.requestExpiresAt) {
      this.expire(trustedNowSeconds);
      throw new Error('Approval request has expired');
    }
    if (this.selectedDecision !== undefined) {
      throw new Error('Approval already has a decision in flight');
    }

    const parsed = parseApprovalCenterDecision(candidate);
    if (!approvalCenterDecisionMatchesItem(parsed, this.item)) {
      throw new Error('Approval decision does not match the exact pending action');
    }
    if (parsed.intent === 'ALLOW_ONCE' && !this.item.canAllowOnce) {
      throw new Error('This action cannot be approved from the Approval Center');
    }

    const trustedDecision = Object.freeze({
      ...parsed,
      binding: this.item.binding,
      issuedAt: trustedNowSeconds,
    });
    this.selectedDecision = trustedDecision;
    this.resolveSelection(trustedDecision);

    let resolve!: Completion['resolve'];
    let reject!: Completion['reject'];
    const promise = new Promise<ApprovalCenterDecision>((resolvePromise, rejectPromise) => {
      resolve = resolvePromise;
      reject = rejectPromise;
    });
    this.completion = { promise, reject, resolve };
    return promise;
  }

  expire(trustedNowSeconds: number): boolean {
    if (
      !validTrustedTime(trustedNowSeconds) ||
      trustedNowSeconds < this.item.binding.requestExpiresAt ||
      this.selectedDecision !== undefined
    ) {
      return false;
    }
    this.selectedDecision = null;
    this.resolveSelection(null);
    return true;
  }

  cancel(): boolean {
    if (this.selectedDecision !== undefined) return false;
    this.selectedDecision = null;
    this.resolveSelection(null);
    return true;
  }

  complete(effectiveDecision: ApprovalCenterDecision): void {
    const selected = this.selectedDecision;
    if (!selected || !this.completion) {
      throw new Error('Approval has no renderer decision to complete');
    }
    if (!approvalCenterDecisionMatchesItem(effectiveDecision, this.item)) {
      throw new Error('Approval acknowledgement does not match the exact pending action');
    }
    const allowedIntentTransition =
      effectiveDecision.intent === selected.intent ||
      (selected.intent === 'ALLOW_ONCE' && effectiveDecision.intent === 'DENY_ACTION');
    if (!allowedIntentTransition || effectiveDecision.issuedAt !== selected.issuedAt) {
      throw new Error('Approval acknowledgement does not match the trusted decision');
    }
    this.completion.resolve(effectiveDecision);
    this.completion = null;
  }

  fail(error: unknown): void {
    const completion = this.completion;
    this.completion = null;
    if (!completion) return;
    completion.reject(error instanceof Error ? error : new Error('Approval decision failed'));
  }
}

/** Positive authority always passes through the existing isolated native review. */
export async function resolveTrustedApprovalCenterIntent(
  selection: ApprovalCenterDecision,
  confirmAllowOnce: () => Promise<boolean>
): Promise<ApprovalCenterDecision['intent']> {
  if (selection.intent !== 'ALLOW_ONCE') return selection.intent;
  return (await confirmAllowOnce()) ? 'ALLOW_ONCE' : 'DENY_ACTION';
}
