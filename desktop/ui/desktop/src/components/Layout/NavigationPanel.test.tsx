import { fireEvent, render, screen } from '@testing-library/react';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import type { SessionListItem } from '../../acp/sessions';
import { IntlTestWrapper } from '../../i18n/test-utils';
import { Navigation, SessionRow } from './NavigationPanel';

const mockApprovalInbox = vi.hoisted(() => ({ items: [] as Array<{ status: string }> }));

vi.mock('react-router', () => ({
  useLocation: () => ({ pathname: '/' }),
}));

vi.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
      <div {...props}>{children}</div>
    ),
  },
}));

vi.mock('./NavigationContext', () => ({
  useNavigationContext: () => ({ isNavExpanded: true }),
}));

vi.mock('../ConfigContext', () => ({
  useConfig: () => ({ extensionsList: [] }),
}));

vi.mock('../../hooks/useNavigationSessions', () => ({
  useNavigationSessions: () => ({
    recentSessions: [],
    recentSessionsByProject: [],
    activeSessionId: null,
    fetchSessions: vi.fn(),
    handleNavClick: vi.fn(),
    handleSessionClick: vi.fn(),
  }),
}));

vi.mock('../../accordlock/approvalInboxStore', () => ({
  useApprovalInbox: () => mockApprovalInbox.items,
}));

class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}

beforeAll(() => {
  vi.stubGlobal('ResizeObserver', ResizeObserverStub);
});

beforeEach(() => {
  mockApprovalInbox.items = [];
});

afterAll(() => {
  vi.unstubAllGlobals();
});

const session: SessionListItem = {
  id: 'session-1',
  name: 'Review the release',
  workingDir: 'C:\\Work\\accordlock',
  updatedAt: '2026-08-28T00:00:00.000Z',
  createdAt: '2026-08-28T00:00:00.000Z',
  messageCount: 3,
};

function renderSessionRow({ active = false }: { active?: boolean } = {}) {
  const onClick = vi.fn();
  const onRenamed = vi.fn();
  render(
    <IntlTestWrapper>
      <SessionRow
        session={session}
        active={active}
        status={undefined}
        onClick={onClick}
        onRenamed={onRenamed}
      />
    </IntlTestWrapper>
  );
  return { onClick, onRenamed };
}

describe('NavigationPanel SessionRow', () => {
  it('opens a recent task with Enter or Space', () => {
    const { onClick } = renderSessionRow();
    const row = screen.getByRole('button', { name: 'Review the release' });

    fireEvent.keyDown(row, { key: 'Enter' });
    fireEvent.keyDown(row, { key: ' ' });

    expect(onClick).toHaveBeenCalledTimes(2);
  });

  it('keeps inactive task titles quiet', () => {
    renderSessionRow();

    expect(screen.getByText('Review the release')).toHaveClass('text-text-secondary');
  });

  it('identifies the active task to assistive technology', () => {
    renderSessionRow({ active: true });

    expect(screen.getByRole('button', { name: 'Review the release' })).toHaveAttribute(
      'aria-current',
      'page'
    );
  });

  it('does not activate the task while its title is being edited', () => {
    const { onClick } = renderSessionRow();

    fireEvent.doubleClick(screen.getByText('Review the release'));
    const input = screen.getByRole('textbox');
    fireEvent.keyDown(input, { key: 'Enter' });

    expect(onClick).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Review the release' })).toBeInTheDocument();
  });
});

describe('NavigationPanel shell', () => {
  it('shows a flat product navigation and an intentional empty state', () => {
    render(
      <IntlTestWrapper>
        <Navigation />
      </IntlTestWrapper>
    );

    expect(screen.getByRole('button', { name: 'New task' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Approvals' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Projects' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Tasks' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Playbooks' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'More' })).not.toBeInTheDocument();
    expect(screen.getByText('No recent tasks yet')).toBeInTheDocument();
  });

  it('shows a subtle count only while approvals are pending', () => {
    mockApprovalInbox.items = [{ status: 'PENDING' }, { status: 'DENIED' }];

    render(
      <IntlTestWrapper>
        <Navigation />
      </IntlTestWrapper>
    );

    expect(screen.getByLabelText('1 pending approval')).toHaveTextContent('1');
  });
});
