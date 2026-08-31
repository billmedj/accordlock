// Modified by AccordLock contributors; see UPSTREAM.md.
import { render, type RenderOptions, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { resolveAcpPermissionRequest } from '../acp/permissionRequests';
import { IntlTestWrapper } from '../i18n/test-utils';
import ToolApprovalButtons from './ToolApprovalButtons';

vi.mock('../acp/permissionRequests', () => ({
  resolveAcpPermissionRequest: vi.fn(),
}));

const renderWithIntl = (ui: React.ReactElement, options?: RenderOptions) =>
  render(ui, { wrapper: IntlTestWrapper, ...options });

const resolveAcpPermissionRequestMock = vi.mocked(resolveAcpPermissionRequest);

describe('ToolApprovalButtons', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('forwards protected actions into AccordLock secure review', async () => {
    resolveAcpPermissionRequestMock.mockReturnValueOnce(true);

    renderWithIntl(
      <ToolApprovalButtons
        data={{
          id: 'tool-call-approved',
          toolName: 'developer__shell',
          sessionId: 'session-1',
        }}
      />
    );

    await waitFor(() =>
      expect(resolveAcpPermissionRequestMock).toHaveBeenCalledWith(
        'session-1',
        'tool-call-approved',
        'allow_once'
      )
    );
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
    expect(screen.queryByText(/developer__shell/u)).not.toBeInTheDocument();
  });

  it('fails closed when a protected ACP request is no longer pending', async () => {
    resolveAcpPermissionRequestMock.mockReturnValueOnce(false);

    renderWithIntl(
      <ToolApprovalButtons
        data={{
          id: 'tool-call-rerun',
          toolName: 'developer__shell',
          sessionId: 'session-1',
        }}
      />
    );

    expect(
      await screen.findByText('The secure review couldn’t start. The action remains blocked.')
    ).toBeVisible();
  });

  it('keeps one-time controls for non-protected connector actions', async () => {
    resolveAcpPermissionRequestMock.mockReturnValueOnce(true);

    renderWithIntl(
      <ToolApprovalButtons
        data={{
          id: 'connector-call',
          toolName: 'github__create_issue',
          sessionId: 'session-1',
        }}
      />
    );

    await userEvent.click(screen.getByRole('button', { name: 'Approve once' }));
    expect(resolveAcpPermissionRequestMock).toHaveBeenCalledWith(
      'session-1',
      'connector-call',
      'allow_once'
    );
    expect(screen.getByText('github__create_issue - Approved once')).toBeVisible();
  });
});
