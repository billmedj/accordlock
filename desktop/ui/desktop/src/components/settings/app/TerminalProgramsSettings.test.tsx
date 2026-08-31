// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { IntlProvider } from 'react-intl';
import TerminalProgramsSettings from './TerminalProgramsSettings';

const binding = {
  alias: 'cargo',
  executable_path: 'C:\\Tools\\cargo.exe',
  executable_sha256: `sha256:${'a'.repeat(64)}`,
} as const;

const renderSettings = () =>
  render(
    <IntlProvider locale="en">
      <TerminalProgramsSettings />
    </IntlProvider>
  );

describe('TerminalProgramsSettings', () => {
  afterEach(cleanup);

  beforeEach(() => {
    Object.assign(window.electron, {
      listAllowedTerminalPrograms: vi.fn().mockResolvedValue([binding]),
      addAllowedTerminalProgram: vi.fn().mockResolvedValue({
        configured: true,
        canceled: false,
        restartRequired: true,
        programs: [binding, { ...binding, alias: 'rustfmt' }],
      }),
      removeAllowedTerminalProgram: vi.fn().mockResolvedValue({
        removed: true,
        canceled: false,
        restartRequired: true,
        programs: [],
      }),
      restartApp: vi.fn(),
    });
  });

  it('shows alias, canonical path, digest, and the honest containment warning', async () => {
    renderSettings();

    expect(await screen.findByText('cargo')).toBeTruthy();
    expect(screen.getByText('C:\\Tools\\cargo.exe')).toBeTruthy();
    expect(screen.getByText(binding.executable_sha256)).toBeTruthy();
    expect(screen.getByText(/Runs outside the workspace/)).toBeTruthy();
    expect(screen.getByText(/can change files or settings anywhere/)).toBeTruthy();
  });

  it('sends only a validated alias to the native-picker API and requests restart', async () => {
    renderSettings();
    await screen.findByText('cargo');
    fireEvent.change(screen.getByLabelText('Program alias'), { target: { value: 'rustfmt' } });
    fireEvent.click(screen.getByRole('button', { name: 'Choose executable…' }));

    await waitFor(() =>
      expect(window.electron.addAllowedTerminalProgram).toHaveBeenCalledWith('rustfmt')
    );
    expect(screen.getByText(/Restart AccordLock/)).toBeTruthy();
  });

  it('removes by alias only after the main-process confirmation path', async () => {
    renderSettings();
    fireEvent.click(await screen.findByRole('button', { name: 'Remove cargo' }));

    await waitFor(() =>
      expect(window.electron.removeAllowedTerminalProgram).toHaveBeenCalledWith('cargo')
    );
    expect(screen.getByText('No program is allowed by default.')).toBeTruthy();
  });
});
