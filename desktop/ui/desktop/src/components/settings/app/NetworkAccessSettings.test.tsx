// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { IntlProvider } from 'react-intl';
import NetworkAccessSettings from './NetworkAccessSettings';

const renderSettings = () =>
  render(
    <IntlProvider locale="en">
      <NetworkAccessSettings />
    </IntlProvider>
  );

describe('NetworkAccessSettings', () => {
  afterEach(cleanup);

  beforeEach(() => {
    Object.assign(window.electron, {
      getGovernedNetworkPolicy: vi.fn().mockResolvedValue({
        domains: ['api.example.com'],
        methods: ['GET', 'HEAD'],
        active: true,
      }),
      setGovernedNetworkDomains: vi.fn().mockResolvedValue({
        saved: true,
        canceled: false,
        restartRequired: true,
        domains: ['api.example.com', 'status.example.com'],
        methods: ['GET', 'HEAD'],
      }),
      restartApp: vi.fn(),
    });
  });

  it('states the fixed read-only boundary and saves canonical exact domains', async () => {
    renderSettings();

    const input = await screen.findByLabelText('Allowed domains');
    expect(input).toHaveValue('api.example.com');
    expect(screen.getByText(/Allow GET and HEAD requests/)).toBeInTheDocument();
    expect(screen.getByText(/Each request needs approval/)).toBeInTheDocument();
    expect(screen.getByText(/Redirects, proxies, credentials/)).toBeInTheDocument();

    fireEvent.change(input, {
      target: { value: 'status.example.com\napi.example.com' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save domains' }));

    await waitFor(() =>
      expect(window.electron.setGovernedNetworkDomains).toHaveBeenCalledWith([
        'api.example.com',
        'status.example.com',
      ])
    );
    expect(await screen.findByText('Restart AccordLock to apply these changes.')).toBeVisible();
  });

  it('keeps malformed, wildcard, duplicate and local destinations unsavable', async () => {
    renderSettings();
    const input = await screen.findByLabelText('Allowed domains');
    const save = screen.getByRole('button', { name: 'Save domains' });

    for (const value of [
      '*.example.com',
      'https://api.example.com',
      '127.0.0.1',
      'api.localhost',
      'api.example.com\napi.example.com',
    ]) {
      fireEvent.change(input, { target: { value } });
      expect(save).toBeDisabled();
    }
    expect(window.electron.setGovernedNetworkDomains).not.toHaveBeenCalled();
  });
});
