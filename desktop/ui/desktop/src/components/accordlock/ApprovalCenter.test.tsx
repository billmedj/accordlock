import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ApprovalCenterDecision, ApprovalInboxItem } from '../../accordlock/approvalInbox';
import {
  clearAccordLockTaskAuthorization,
  setAccordLockTaskAuthorization,
} from '../../accordlock/taskAuthorizationStore';
import { ApprovalCenter } from './ApprovalCenter';

const sessionId = 'approval-center-session';

const item: ApprovalInboxItem = {
  id: `action:sha256:${'a'.repeat(64)}`,
  intentReview: 'EVIDENCE_MISSING',
  status: 'PENDING',
  canAllowOnce: true,
  contentEvidence: `Content sha256:${'b'.repeat(64)} · 12 bytes`,
  objective: 'Prepare the release note.',
  operationLabel: 'Edit file',
  preview: 'Before\nOld\n\nAfter\nNew',
  receivedAt: 1_000,
  target: 'docs/release.md',
  targetLabel: 'Path',
  workspaceRoot: 'C:\\Work\\product',
  binding: {
    authorizationDigest: `sha256:${'c'.repeat(64)}`,
    approvalRequestHash: `sha256:${'a'.repeat(64)}`,
    prestateHash: `sha256:${'d'.repeat(64)}`,
    proposalDigest: `sha256:${'e'.repeat(64)}`,
    requestExpiresAt: 1_100,
    runId: 'run-1',
    sessionId,
    taskAccessExpiresAt: 2_000,
    taskId: 'task-1',
    taskPolicyHash: `sha256:${'f'.repeat(64)}`,
    toolCallId: 'tool-call-1',
  },
};

afterEach(() => clearAccordLockTaskAuthorization(sessionId));

function renderCenter(
  onDecision = vi.fn<(decision: ApprovalCenterDecision) => void>(),
  approvalItem: ApprovalInboxItem = item
) {
  setAccordLockTaskAuthorization(sessionId, 'APPROVED', 2_000_000_000);
  render(<ApprovalCenter items={[approvalItem]} nowSeconds={1_050} onDecision={onDecision} />);
  return onDecision;
}

describe('ApprovalCenter', () => {
  it('shows one compact decision with exact details behind disclosure', () => {
    renderCenter();

    expect(screen.getByRole('heading', { name: 'Approvals' })).toBeInTheDocument();
    expect(screen.getByText('1 decision waiting')).toBeInTheDocument();
    expect(screen.getByText('Edit file')).toBeInTheDocument();
    expect(screen.getByText('Review needed')).toBeInTheDocument();
    expect(screen.getByText('Task check')).toBeInTheDocument();
    expect(
      screen.getByText("AccordLock couldn't verify this action from the task alone.")
    ).toBeInTheDocument();
    expect(screen.queryByText('Prepare the release note.')).not.toBeVisible();
    expect(screen.getAllByText('docs/release.md')).not.toHaveLength(0);
    expect(screen.getByText('Expires in 50s')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Approve once' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Keep blocked' })).toBeEnabled();

    fireEvent.click(screen.getByText('Review details'));
    expect(screen.getByText('Prepare the release note.')).toBeVisible();
    expect(screen.getByText(/Before/)).toBeInTheDocument();
    expect(screen.getByText(/sha256:b{64}/)).toBeInTheDocument();
  });

  it('resurfaces an exact user limit only when it is relevant to the action', () => {
    renderCenter(vi.fn(), {
      ...item,
      objective: 'Prepare the release note. Do not change package files.',
    });

    expect(screen.getByText('Your limit')).toBeInTheDocument();
    expect(screen.getByText('Do not change package files.')).toBeInTheDocument();
  });

  it.each([
    ['Approve once', 'ALLOW_ONCE'],
    ['Keep blocked', 'DENY_ACTION'],
  ] as const)('submits %s with the exact binding', async (label, intent) => {
    const onDecision = renderCenter();

    fireEvent.click(screen.getByRole('button', { name: label }));

    await waitFor(() => expect(onDecision).toHaveBeenCalledTimes(1));
    const decision = onDecision.mock.calls[0][0];
    expect(decision.intent).toBe(intent);
    expect(decision.binding.approvalRequestHash).toBe(item.binding.approvalRequestHash);
    expect(decision.binding.toolCallId).toBe(item.binding.toolCallId);
  });

  it.each([
    ['Stop task', 'STOP_TASK'],
    ['Revoke access', 'REVOKE_ACCESS'],
  ] as const)('keeps the task control %s distinct', async (label, intent) => {
    const onDecision = renderCenter();
    fireEvent.click(screen.getByText('Task controls'));

    fireEvent.click(screen.getByRole('button', { name: label }));

    await waitFor(() => expect(onDecision).toHaveBeenCalledTimes(1));
    expect(onDecision.mock.calls[0][0].intent).toBe(intent);
  });

  it('blocks action decisions after request expiry but leaves active task controls available', () => {
    setAccordLockTaskAuthorization(sessionId, 'APPROVED', 2_000_000_000);
    render(<ApprovalCenter items={[item]} nowSeconds={1_101} onDecision={vi.fn()} />);

    expect(screen.getAllByText('Expired')).not.toHaveLength(0);
    expect(screen.queryByRole('button', { name: 'Approve once' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Keep blocked' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByText('Task controls'));
    expect(screen.getByRole('button', { name: 'Stop task' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Revoke access' })).toBeEnabled();
  });

  it('fails closed when task access is not approved', () => {
    setAccordLockTaskAuthorization(sessionId, 'REJECTED');
    render(<ApprovalCenter items={[item]} nowSeconds={1_050} onDecision={vi.fn()} />);

    expect(screen.getByRole('button', { name: 'Approve once' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Keep blocked' })).toBeDisabled();
    fireEvent.click(screen.getByText('Task controls'));
    expect(screen.getByRole('button', { name: 'Stop task' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Revoke access' })).toBeDisabled();
  });

  it('has a quiet empty state', () => {
    render(<ApprovalCenter items={[]} nowSeconds={1_050} onDecision={vi.fn()} />);

    expect(screen.getByText('No approvals waiting')).toBeInTheDocument();
    expect(screen.getByText('0 decisions waiting')).toBeInTheDocument();
  });

  it('explains a stale notification target instead of showing only the generic empty state', () => {
    render(
      <ApprovalCenter
        items={[]}
        focusItemId={`action:sha256:${'9'.repeat(64)}`}
        nowSeconds={1_050}
        onDecision={vi.fn()}
      />
    );

    expect(screen.getByRole('status')).toHaveTextContent('This request was resolved or expired.');
  });

  it('keeps recent decisions out of the primary queue by default', () => {
    render(
      <ApprovalCenter
        items={[{ ...item, status: 'DENIED' }]}
        nowSeconds={1_050}
        onDecision={vi.fn()}
      />
    );

    expect(screen.getByText('0 decisions waiting')).toBeInTheDocument();
    expect(screen.getByText('No approvals waiting')).toBeInTheDocument();
    expect(screen.getByText('Recent decisions').closest('details')).not.toHaveAttribute('open');
  });

  it('focuses the exact request opened from a notification', () => {
    const originalScrollIntoView = HTMLElement.prototype.scrollIntoView;
    const scrollIntoView = vi.fn();
    HTMLElement.prototype.scrollIntoView = scrollIntoView;
    try {
      setAccordLockTaskAuthorization(sessionId, 'APPROVED', 2_000_000_000);
      render(
        <ApprovalCenter
          items={[item]}
          focusItemId={item.id}
          nowSeconds={1_050}
          onDecision={vi.fn()}
        />
      );

      const card = screen.getByText('Edit file').closest('article');
      expect(card).not.toBeNull();
      expect(document.activeElement).toBe(card);
      expect(card).toHaveClass('ring-2');
      expect(scrollIntoView).toHaveBeenCalledWith({ block: 'center' });
    } finally {
      HTMLElement.prototype.scrollIntoView = originalScrollIntoView;
    }
  });
});
