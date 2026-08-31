import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { IntlTestWrapper } from '../../i18n/test-utils';
import SettingsView from './SettingsView';

vi.stubGlobal(
  'ResizeObserver',
  class ResizeObserver {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
);

vi.mock('../Layout/MainPanelLayout', () => ({
  MainPanelLayout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

vi.mock('../../contexts/FeaturesContext', () => ({
  useFeatures: () => ({ localInference: false }),
}));

vi.mock('../../utils/analytics', () => ({
  trackSettingsTabViewed: vi.fn(),
}));

vi.mock('./models/ModelsSection', () => ({
  default: () => <div data-testid="models-settings" />,
}));
vi.mock('./chat/ChatSettingsSection', () => ({
  default: () => <div data-testid="chat-settings" />,
}));
vi.mock('./PromptsSettingsSection', () => ({
  default: () => <div data-testid="prompts-settings" />,
}));
vi.mock('./keyboard/KeyboardShortcutsSection', () => ({
  default: () => <div data-testid="keyboard-settings" />,
}));
vi.mock('./auth/AuthSettingsSection', () => ({
  default: ({ onConnectProvider }: { onConnectProvider?: () => void }) => (
    <div data-testid="auth-settings">
      <button onClick={onConnectProvider}>Connect provider</button>
    </div>
  ),
}));
vi.mock('./localInference/LocalInferenceSection', () => ({
  default: () => <div data-testid="local-inference-settings" />,
}));
vi.mock('./app/AppSettingsSection', () => ({
  default: () => <div data-testid="app-settings" />,
}));
vi.mock('./app/TerminalProgramsSettings', () => ({
  default: () => <div data-testid="terminal-programs-settings" />,
}));
vi.mock('./app/ApprovalChannelsSettings', () => ({
  default: () => <div data-testid="approval-channels-settings" />,
}));
vi.mock('./config/ConfigSettings', () => ({
  default: () => <div data-testid="raw-configuration-editor" />,
}));

describe('SettingsView', () => {
  it('keeps model selection and provider credentials together', async () => {
    const user = userEvent.setup();
    const setView = vi.fn();

    render(<SettingsView onClose={vi.fn()} setView={setView} viewOptions={{}} />, {
      wrapper: IntlTestWrapper,
    });

    expect(screen.getByTestId('models-settings')).toBeVisible();
    expect(screen.getByTestId('auth-settings')).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Connect provider' }));
    expect(setView).toHaveBeenCalledWith('ConfigureProviders');
  });

  it('keeps approval alerts under Notifications', async () => {
    const user = userEvent.setup();

    render(<SettingsView onClose={vi.fn()} setView={vi.fn()} viewOptions={{}} />, {
      wrapper: IntlTestWrapper,
    });

    await user.click(screen.getByRole('tab', { name: 'Notifications' }));

    expect(screen.getByTestId('approval-channels-settings')).toBeVisible();
    expect(screen.getByText('Approval channels')).toBeVisible();
    expect(screen.queryByTestId('auth-settings')).not.toBeInTheDocument();
    expect(screen.queryByTestId('terminal-programs-settings')).not.toBeInTheDocument();
  });

  it('keeps native execution controls under Security with progressive disclosure', async () => {
    const user = userEvent.setup();

    render(<SettingsView onClose={vi.fn()} setView={vi.fn()} viewOptions={{}} />, {
      wrapper: IntlTestWrapper,
    });

    await user.click(screen.getByRole('tab', { name: 'Security' }));

    const manage = screen.getByRole('button', { name: 'Manage Native programs' });
    expect(manage).toHaveAttribute('aria-expanded', 'false');
    await user.click(manage);

    expect(screen.getByTestId('terminal-programs-settings')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Hide Native programs' })).toHaveAttribute(
      'aria-expanded',
      'true'
    );
  });

  it('puts app controls first and keeps keyboard shortcuts behind progressive disclosure', async () => {
    const user = userEvent.setup();

    render(<SettingsView onClose={vi.fn()} setView={vi.fn()} viewOptions={{}} />, {
      wrapper: IntlTestWrapper,
    });

    await user.click(screen.getByRole('tab', { name: 'App' }));

    expect(screen.getByTestId('chat-settings')).toBeVisible();
    expect(screen.getByTestId('app-settings')).toBeVisible();
    expect(screen.queryByTestId('prompts-settings')).not.toBeInTheDocument();
    expect(screen.queryByTestId('keyboard-settings')).not.toBeInTheDocument();
    expect(screen.queryByTestId('raw-configuration-editor')).not.toBeInTheDocument();

    const customize = screen.getByRole('button', { name: /Customize/ });
    expect(customize).toHaveAttribute('aria-expanded', 'false');
    await user.click(customize);

    expect(screen.getByTestId('keyboard-settings')).toBeVisible();
    expect(screen.getByRole('button', { name: /Hide/ })).toHaveAttribute('aria-expanded', 'true');
  });
});
