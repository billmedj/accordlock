// Modified by AccordLock contributors; see UPSTREAM.md.
import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router';
import { useConfig } from '../ConfigContext';
import { useModelAndProvider } from '../ModelAndProviderContext';
import { acpListProviderDetails, acpReadDefaults, acpSaveDefaults } from '../../acp/providers';
import { Button } from '../ui/button';
import ProviderSelector from './ProviderSelector';
import OnboardingSuccess from './OnboardingSuccess';
import {
  trackOnboardingStarted,
  trackOnboardingCompleted,
  trackOnboardingProviderSelected,
  trackTelemetryPreference,
  setTelemetryEnabled as setAnalyticsTelemetryEnabled,
} from '../../utils/analytics';
import { defineMessages, useIntl } from '../../i18n';
import { AccordLockGlyph, AccordLockWordmark } from '../accordlock/AccordLockBrand';

const i18n = defineMessages({
  welcomeTitle: {
    id: 'onboardingGuard.welcomeTitle',
    defaultMessage: 'Welcome to AccordLock',
  },
  welcomeDescription: {
    id: 'onboardingGuard.welcomeDescription',
    defaultMessage: 'Choose a model provider to get started.',
  },
  preparingTitle: {
    id: 'onboardingGuard.preparingTitle',
    defaultMessage: 'Checking setup',
  },
  preparingDescription: {
    id: 'onboardingGuard.preparingDescription',
    defaultMessage: 'Verifying your model connection…',
  },
  checkProviderErrorTitle: {
    id: 'onboardingGuard.checkProviderErrorTitle',
    defaultMessage: 'Could not check your provider',
  },
  checkProviderErrorDescription: {
    id: 'onboardingGuard.checkProviderErrorDescription',
    defaultMessage: 'Check your connection and try again.',
  },
  retry: {
    id: 'onboardingGuard.retry',
    defaultMessage: 'Retry',
  },
});

const TELEMETRY_CONFIG_KEY = 'GOOSE_TELEMETRY_ENABLED';

interface OnboardingGuardProps {
  children: React.ReactNode;
}

export default function OnboardingGuard({ children }: OnboardingGuardProps) {
  const intl = useIntl();
  const navigate = useNavigate();
  const { upsert } = useConfig();
  const { getFallbackModelAndProvider, refreshCurrentModelAndProvider } = useModelAndProvider();

  const [isCheckingProvider, setIsCheckingProvider] = useState(true);
  const [hasProvider, setHasProvider] = useState(false);
  const [checkProviderError, setCheckProviderError] = useState(false);
  const [hasSelection, setHasSelection] = useState(false);
  const [configuredProvider, setConfiguredProvider] = useState<string | null>(null);
  const [configuredProviderDisplayName, setConfiguredProviderDisplayName] = useState<string | null>(
    null
  );
  const [configuredModel, setConfiguredModel] = useState<string | null>(null);
  const hasTrackedOnboardingStart = useRef(false);

  const checkProvider = async (retries = 3, delay = 1000) => {
    setIsCheckingProvider(true);
    setCheckProviderError(false);
    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        const { providerId: provider, modelId: model } = await acpReadDefaults();
        if (provider?.trim() && model?.trim()) {
          await refreshCurrentModelAndProvider();
          setHasProvider(true);
          setIsCheckingProvider(false);
          return;
        }

        const fallback = await getFallbackModelAndProvider();
        if (fallback.provider?.trim() && fallback.model?.trim()) {
          await acpSaveDefaults(fallback.provider, fallback.model);
          await refreshCurrentModelAndProvider();
          setHasProvider(true);
          setIsCheckingProvider(false);
          return;
        }

        setHasProvider(false);
        setIsCheckingProvider(false);
        return;
      } catch (error) {
        console.error(`Error checking provider (attempt ${attempt + 1}/${retries + 1}):`, error);
        if (attempt < retries) {
          await new Promise((resolve) => setTimeout(resolve, delay));
        }
      }
    }
    setCheckProviderError(true);
    setIsCheckingProvider(false);
  };

  useEffect(() => {
    checkProvider();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (
      !isCheckingProvider &&
      !hasProvider &&
      !checkProviderError &&
      !hasTrackedOnboardingStart.current
    ) {
      trackOnboardingStarted();
      hasTrackedOnboardingStart.current = true;
    }
  }, [isCheckingProvider, hasProvider, checkProviderError]);

  const handleConfigured = async (providerName: string, modelId?: string) => {
    trackOnboardingProviderSelected({ provider: providerName });
    const providers = await acpListProviderDetails();
    const matchedProvider = providers.find((p) => p.name === providerName);
    const resolvedModel = modelId ?? matchedProvider?.metadata.default_model ?? null;
    await acpSaveDefaults(providerName, resolvedModel);
    setConfiguredModel(resolvedModel);
    await refreshCurrentModelAndProvider();
    setConfiguredProvider(providerName);
    setConfiguredProviderDisplayName(matchedProvider?.metadata.display_name || providerName);
  };

  const finishOnboarding = async (telemetryEnabled: boolean) => {
    try {
      await upsert(TELEMETRY_CONFIG_KEY, telemetryEnabled, false);
    } catch (error) {
      console.error('Failed to save telemetry preference:', error);
    }
    trackTelemetryPreference(telemetryEnabled, 'onboarding');
    if (configuredProvider) {
      trackOnboardingCompleted(configuredProvider, configuredModel ?? undefined);
    }
    if (!telemetryEnabled) {
      setAnalyticsTelemetryEnabled(false);
    }
    navigate('/', { replace: true });
    setHasProvider(true);
  };

  if (isCheckingProvider) {
    return (
      <main
        className="relative flex h-screen w-full items-center justify-center overflow-hidden bg-background-default px-6"
        aria-busy="true"
      >
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-x-[20%] top-[18%] h-64 rounded-full bg-background-secondary/70 blur-3xl"
        />
        <div
          role="status"
          aria-live="polite"
          aria-atomic="true"
          className="relative flex w-full max-w-sm flex-col items-center text-center"
        >
          <AccordLockWordmark />
          <div
            aria-hidden="true"
            className="my-8 size-5 rounded-full border-2 border-border-default border-t-text-default motion-safe:animate-spin"
          />
          <h1 className="text-xl font-light tracking-[-0.02em] text-text-default">
            {intl.formatMessage(i18n.preparingTitle)}
          </h1>
          <p className="mt-2 text-sm text-text-muted">
            {intl.formatMessage(i18n.preparingDescription)}
          </p>
        </div>
      </main>
    );
  }

  if (checkProviderError) {
    return (
      <div className="flex h-screen w-full flex-col items-center justify-center bg-background-default">
        <div className="text-center max-w-md">
          <div className="mb-4">
            <AccordLockGlyph className="mx-auto size-10" />
          </div>
          <h1 className="text-xl font-light mb-3">
            {intl.formatMessage(i18n.checkProviderErrorTitle)}
          </h1>
          <p className="text-text-muted mb-6">
            {intl.formatMessage(i18n.checkProviderErrorDescription)}
          </p>
          <Button onClick={() => checkProvider()}>{intl.formatMessage(i18n.retry)}</Button>
        </div>
      </div>
    );
  }

  if (hasProvider) {
    return <>{children}</>;
  }

  if (configuredProviderDisplayName) {
    return (
      <OnboardingSuccess providerName={configuredProviderDisplayName} onFinish={finishOnboarding} />
    );
  }

  return (
    <div className="relative h-screen w-full overflow-hidden bg-background-default">
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-x-[15%] top-[10%] h-80 rounded-full bg-background-secondary/70 blur-3xl"
      />
      <div className="h-full overflow-y-auto">
        <div
          className={`flex flex-col items-center p-4 pb-8 transition-all duration-500 ease-in-out ${hasSelection ? 'pt-8' : 'pt-[15vh]'}`}
        >
          <div className="relative mx-auto w-full max-w-2xl">
            <div
              className={`text-left transition-all duration-500 ease-in-out overflow-hidden ${hasSelection ? 'max-h-0 opacity-0 mb-0' : 'max-h-60 opacity-100 mb-8'}`}
            >
              <div className="mb-4">
                <AccordLockWordmark />
              </div>
              <h1 className="mb-3 mt-8 text-3xl font-light tracking-[-0.035em] sm:text-5xl">
                {intl.formatMessage(i18n.welcomeTitle)}
              </h1>
              <p className="max-w-xl text-base leading-7 text-text-muted sm:text-lg">
                {intl.formatMessage(i18n.welcomeDescription)}
              </p>
            </div>

            <ProviderSelector
              onConfigured={handleConfigured}
              onFirstSelection={() => setHasSelection(true)}
            />
          </div>
        </div>
      </div>
    </div>
  );
}
