import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import ApprovalChannelsSettings from './ApprovalChannelsSettings';

const listChannels = vi.fn();
const saveChannel = vi.fn();
const setEnabled = vi.fn();
const removeChannel = vi.fn();
const getRemoteEnrollment = vi.fn();
const importRemoteEnrollment = vi.fn();
const revokeRemoteEnrollment = vi.fn();
const importRemoteReceipt = vi.fn();
const testChannel = vi.fn();

beforeEach(() => {
  listChannels.mockReset().mockResolvedValue([]);
  saveChannel.mockReset();
  setEnabled.mockReset();
  removeChannel.mockReset();
  getRemoteEnrollment.mockReset().mockResolvedValue(null);
  importRemoteEnrollment.mockReset();
  revokeRemoteEnrollment.mockReset();
  importRemoteReceipt.mockReset();
  testChannel.mockReset().mockResolvedValue({
    accepted: true,
    channel: 'SLACK',
    outcome: 'DELIVERED',
    schema_version: 1,
  });
  Object.assign(window.electron, {
    listAccordLockApprovalChannels: listChannels,
    saveAccordLockApprovalChannel: saveChannel,
    setAccordLockApprovalChannelEnabled: setEnabled,
    removeAccordLockApprovalChannel: removeChannel,
    getAccordLockRemoteApprovalEnrollment: getRemoteEnrollment,
    importAccordLockRemoteApprovalEnrollment: importRemoteEnrollment,
    revokeAccordLockRemoteApprovalEnrollment: revokeRemoteEnrollment,
    importAccordLockRemoteApprovalReceipt: importRemoteReceipt,
    testAccordLockApprovalChannel: testChannel,
  });
});

describe('ApprovalChannelsSettings', () => {
  it('shows plain gateway status and keeps test receipts in technical details', async () => {
    getRemoteEnrollment.mockResolvedValue({
      channels: ['SLACK'],
      enrollmentId: '11111111-1111-4111-8111-111111111111',
      fingerprint: `sha256:${'a'.repeat(64)}`,
      gatewayName: 'Operations gateway',
      status: 'ACTIVE',
      validUntil: 2_100_000_000,
    });
    importRemoteReceipt.mockResolvedValue({
      accepted: true,
      approvalId: `action:sha256:${'b'.repeat(64)}`,
      intent: 'DENY_ACTION',
    });

    render(<ApprovalChannelsSettings />);

    expect(await screen.findByText('Operations gateway · active')).toBeInTheDocument();
    expect(screen.getByText(`Key sha256:${'a'.repeat(64)}`)).not.toBeVisible();
    fireEvent.click(screen.getByText('Technical details'));
    expect(screen.getByText(`Key sha256:${'a'.repeat(64)}`)).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Import a test receipt' }));
    await waitFor(() => expect(importRemoteReceipt).toHaveBeenCalledWith());
  });

  it('keeps provider forms closed until requested and never renders stored secrets', async () => {
    listChannels.mockResolvedValue([
      {
        channel: 'SLACK',
        configuredAt: 1,
        destinationHint: '•••345678',
        enabled: true,
        updatedAt: 1,
      },
    ]);

    render(<ApprovalChannelsSettings />);

    expect(await screen.findByText('Configured · •••345678')).toBeInTheDocument();
    expect(screen.queryByLabelText('Bot token')).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain('accessToken');
    expect(screen.getByRole('switch', { name: 'Enable Slack' })).toBeChecked();
    fireEvent.click(screen.getByRole('button', { name: 'Send test' }));
    await waitFor(() => expect(testChannel).toHaveBeenCalledWith('SLACK'));
    expect(await screen.findByRole('button', { name: 'Sent' })).toBeInTheDocument();
  });

  it('sends one exact configuration and clears the form after save', async () => {
    saveChannel.mockResolvedValue({
      channel: 'SLACK',
      configuredAt: 10,
      destinationHint: '•••345678',
      enabled: true,
      updatedAt: 10,
    });

    render(<ApprovalChannelsSettings />);
    await screen.findAllByText('Not configured');
    fireEvent.click(screen.getByRole('button', { name: /Slack/ }));
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Channel ID'), { target: { value: 'C12345678' } });
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Bot token'), {
      target: { value: 'fixture-slack-access-token-00000000' },
    });
    expect(screen.getByRole('button', { name: 'Save' })).toBeEnabled();
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() =>
      expect(saveChannel).toHaveBeenCalledWith({
        channel: 'SLACK',
        enabled: true,
        accessToken: 'fixture-slack-access-token-00000000',
        destination: 'C12345678',
      })
    );
    expect(await screen.findByText('Configured · •••345678')).toBeInTheDocument();
    expect(screen.queryByLabelText('Bot token')).not.toBeInTheDocument();
  });
});
