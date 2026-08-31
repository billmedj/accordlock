import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { acpReadDefaults, acpSaveDefaults } from '../../acp/providers';
import { IntlTestWrapper } from '../../i18n/test-utils';
import OnboardingGuard from './OnboardingGuard';

const modelContext = vi.hoisted(() => ({
  getFallbackModelAndProvider: vi.fn(),
  refreshCurrentModelAndProvider: vi.fn(),
}));

vi.mock('react-router', () => ({
  useNavigate: () => vi.fn(),
}));

vi.mock('../ConfigContext', () => ({
  useConfig: () => ({ upsert: vi.fn() }),
}));

vi.mock('../ModelAndProviderContext', () => ({
  useModelAndProvider: () => modelContext,
}));

vi.mock('../../acp/providers', () => ({
  acpListProviderDetails: vi.fn(),
  acpReadDefaults: vi.fn(),
  acpSaveDefaults: vi.fn(),
}));

vi.mock('../../utils/analytics', () => ({
  setTelemetryEnabled: vi.fn(),
  trackOnboardingCompleted: vi.fn(),
  trackOnboardingProviderSelected: vi.fn(),
  trackOnboardingStarted: vi.fn(),
  trackTelemetryPreference: vi.fn(),
}));

vi.mock('./ProviderSelector', () => ({
  default: () => <div data-testid="provider-selector" />,
}));

vi.mock('./OnboardingSuccess', () => ({
  default: () => <div data-testid="onboarding-success" />,
}));

describe('OnboardingGuard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    modelContext.getFallbackModelAndProvider.mockResolvedValue({ provider: null, model: null });
    modelContext.refreshCurrentModelAndProvider.mockResolvedValue(undefined);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('shows an accessible AccordLock splash while checking the provider', () => {
    vi.mocked(acpReadDefaults).mockImplementation(
      () => new Promise<Awaited<ReturnType<typeof acpReadDefaults>>>(() => undefined)
    );

    render(
      <OnboardingGuard>
        <div>Protected workspace</div>
      </OnboardingGuard>,
      { wrapper: IntlTestWrapper }
    );

    const status = screen.getByRole('status');
    expect(status).toHaveTextContent('AccordLock');
    expect(status).toHaveTextContent('Checking setup');
    expect(status).toHaveTextContent('Verifying your model connection…');
    expect(status.closest('main')).toHaveAttribute('aria-busy', 'true');
    expect(screen.queryByText('Protected workspace')).not.toBeInTheDocument();
  });

  it('returns to the splash immediately while a failed provider check is retried', async () => {
    vi.useFakeTimers();
    vi.mocked(acpReadDefaults).mockRejectedValue(new Error('runtime unavailable'));

    render(
      <OnboardingGuard>
        <div>Protected workspace</div>
      </OnboardingGuard>,
      { wrapper: IntlTestWrapper }
    );

    await act(async () => {
      await vi.runAllTimersAsync();
    });

    expect(screen.getByRole('button', { name: 'Retry' })).toBeVisible();

    vi.mocked(acpReadDefaults).mockImplementation(
      () => new Promise<Awaited<ReturnType<typeof acpReadDefaults>>>(() => undefined)
    );
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));

    expect(screen.getByRole('status')).toHaveTextContent('Checking setup');
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument();
  });

  it('does not treat a provider without a model as a complete setup', async () => {
    vi.mocked(acpReadDefaults).mockResolvedValue({ providerId: 'opencode', modelId: null });

    render(
      <OnboardingGuard>
        <div>Protected workspace</div>
      </OnboardingGuard>,
      { wrapper: IntlTestWrapper }
    );

    expect(await screen.findByTestId('provider-selector')).toBeVisible();
    expect(screen.queryByText('Protected workspace')).not.toBeInTheDocument();
  });

  it('repairs a complete legacy fallback before opening the workspace', async () => {
    vi.mocked(acpReadDefaults).mockResolvedValue({ providerId: 'opencode', modelId: null });
    modelContext.getFallbackModelAndProvider.mockResolvedValue({
      provider: 'opencode',
      model: 'mimo-v2.5-free',
    });

    render(
      <OnboardingGuard>
        <div>Protected workspace</div>
      </OnboardingGuard>,
      { wrapper: IntlTestWrapper }
    );

    expect(await screen.findByText('Protected workspace')).toBeVisible();
    expect(acpSaveDefaults).toHaveBeenCalledWith('opencode', 'mimo-v2.5-free');
    expect(modelContext.refreshCurrentModelAndProvider).toHaveBeenCalledTimes(1);
  });
});
