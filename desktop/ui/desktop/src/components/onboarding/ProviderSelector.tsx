import { useState, useEffect, useMemo, useCallback } from 'react';
import {
  acpCreateCustomProviderFromRequest,
  acpListSetupProviderDetails,
} from '../../acp/providers';
import type { ProviderDetails, UpdateCustomProviderRequest } from '../../types/providers';
import { Select } from '../ui/Select';
import ProviderConfigForm from './ProviderConfigForm';
import LocalModelPicker from './LocalModelPicker';
import CustomProviderForm from '../settings/providers/modal/subcomponents/forms/CustomProviderForm';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../ui/dialog';
import { Compass, HardDrive, Key, LoaderCircle, Plus, RefreshCw } from 'lucide-react';
import { defineMessages, useIntl } from '../../i18n';
import { useFeatures } from '../../contexts/FeaturesContext';
import ProductTourDialog from './ProductTourDialog';

const i18n = defineMessages({
  useLocalModel: {
    id: 'providerSelector.useLocalModel',
    defaultMessage: 'Use a local model',
  },
  localModelDescription: {
    id: 'providerSelector.localModelDescription',
    defaultMessage: 'Download a model and run it on this device. No API key or account needed.',
  },
  connectProvider: {
    id: 'providerSelector.connectProvider',
    defaultMessage: 'Connect a model',
  },
  connectProviderDescription: {
    id: 'providerSelector.connectProviderDescription',
    defaultMessage: 'Use your provider account or API key.',
  },
  discoverWithoutModel: {
    id: 'providerSelector.discoverWithoutModel',
    defaultMessage: 'Explore first',
  },
  discoverWithoutModelDescription: {
    id: 'providerSelector.discoverWithoutModelDescription',
    defaultMessage: 'Preview task access and action approval. No model or files required.',
  },
  selectProvider: {
    id: 'providerSelector.selectProvider',
    defaultMessage: 'Select a provider',
  },
  recommendedProviders: {
    id: 'providerSelector.recommendedProviders',
    defaultMessage: 'Recommended',
  },
  browseAllProviders: {
    id: 'providerSelector.browseAllProviders',
    defaultMessage: 'Browse all {count} providers',
  },
  hideProviderCatalog: {
    id: 'providerSelector.hideProviderCatalog',
    defaultMessage: 'Show fewer providers',
  },
  changeProvider: {
    id: 'providerSelector.changeProvider',
    defaultMessage: 'Choose another provider',
  },
  loadingProviders: {
    id: 'providerSelector.loadingProviders',
    defaultMessage: 'Loading model providers…',
  },
  loadProvidersError: {
    id: 'providerSelector.loadProvidersError',
    defaultMessage: 'AccordLock could not load model providers.',
  },
  retryProviders: {
    id: 'providerSelector.retryProviders',
    defaultMessage: 'Try again',
  },
  addCustomProvider: {
    id: 'providerSelector.addCustomProvider',
    defaultMessage: 'Add a custom provider',
  },
  addCustomProviderTitle: {
    id: 'providerSelector.addCustomProviderTitle',
    defaultMessage: 'Add Custom Provider',
  },
});

const LOCAL_MODEL = 'local-model' as const;
const OWN_PROVIDER = 'own-provider' as const;
const FEATURED_PROVIDER_ORDER = [
  'mistral',
  'anthropic',
  'openai',
  'opencodezen',
  'huggingface',
  'ollama',
  'googlegeminiapikey',
] as const;

type SelectedPath = typeof LOCAL_MODEL | typeof OWN_PROVIDER | null;

interface ProviderOption {
  value: string;
  label: string;
  provider: ProviderDetails;
}

interface ProviderSelectorProps {
  onConfigured: (providerName: string, modelId?: string) => void | Promise<void>;
  onFirstSelection?: () => void;
}

export default function ProviderSelector({
  onConfigured,
  onFirstSelection,
}: ProviderSelectorProps) {
  const intl = useIntl();
  const { localInference } = useFeatures();
  const [providerList, setProviderList] = useState<ProviderDetails[]>([]);
  const [selectedOption, setSelectedOption] = useState<ProviderOption | null>(null);
  const [selectedPath, setSelectedPath] = useState<SelectedPath>(null);
  const [showProviderCatalog, setShowProviderCatalog] = useState(false);
  const [showCustomModal, setShowCustomModal] = useState(false);
  const [showProductTour, setShowProductTour] = useState(false);
  const [isLoadingProviders, setIsLoadingProviders] = useState(true);
  const [providerLoadError, setProviderLoadError] = useState(false);

  const loadProviders = useCallback(async () => {
    setIsLoadingProviders(true);
    setProviderLoadError(false);
    try {
      setProviderList(await acpListSetupProviderDetails());
    } catch (err) {
      setProviderList([]);
      setProviderLoadError(true);
      console.error('Failed to fetch providers:', err);
    } finally {
      setIsLoadingProviders(false);
    }
  }, []);

  useEffect(() => {
    void loadProviders();
  }, [loadProviders]);

  const options: ProviderOption[] = useMemo(() => {
    return [...providerList]
      .sort((a, b) => {
        const aPreferred = a.provider_type === 'Preferred' ? 0 : 1;
        const bPreferred = b.provider_type === 'Preferred' ? 0 : 1;
        if (aPreferred !== bPreferred) return aPreferred - bPreferred;
        return a.metadata.display_name.localeCompare(b.metadata.display_name);
      })
      .map((provider) => ({
        value: provider.name,
        label: provider.metadata.display_name,
        provider,
      }));
  }, [providerList]);

  const featuredOptions = useMemo(() => {
    const byNormalizedLabel = new Map(
      options.map((option) => [option.label.toLowerCase().replace(/[^a-z0-9]/g, ''), option])
    );
    return FEATURED_PROVIDER_ORDER.flatMap((label) => {
      const option = byNormalizedLabel.get(label);
      return option ? [option] : [];
    });
  }, [options]);

  const fuzzyFilterOption = (option: { label: string; value: string }, inputValue: string) => {
    const normalize = (s: string) => s.toLowerCase().replace(/[\s_-]/g, '');
    return (
      normalize(option.label).includes(normalize(inputValue)) ||
      normalize(option.value).includes(normalize(inputValue))
    );
  };

  const handleLocalModelClick = () => {
    setSelectedPath(LOCAL_MODEL);
    setSelectedOption(null);
    onFirstSelection?.();
  };

  const handleOwnProviderClick = () => {
    setSelectedPath(OWN_PROVIDER);
    onFirstSelection?.();
  };

  const handleProviderSelect = (option: ProviderOption | null) => {
    setSelectedOption(option);
    if (option) setShowProviderCatalog(false);
    if (option) onFirstSelection?.();
  };

  const handleCreateCustomProvider = async (data: UpdateCustomProviderRequest) => {
    const result = await acpCreateCustomProviderFromRequest(data);
    setShowCustomModal(false);
    if (result.provider_name) {
      await onConfigured(result.provider_name);
    }
  };

  const selectedProvider = selectedOption?.provider ?? null;

  return (
    <div>
      <div
        className={`mb-6 grid grid-cols-1 gap-3 ${localInference ? 'sm:grid-cols-3' : 'sm:grid-cols-2'}`}
      >
        <button
          type="button"
          onClick={handleOwnProviderClick}
          aria-pressed={selectedPath === OWN_PROVIDER}
          className={`p-4 border rounded-xl text-left transition-all duration-200 cursor-pointer group ${
            selectedPath === OWN_PROVIDER
              ? 'border-blue-400 bg-background-muted'
              : 'border-border-default bg-background-muted hover:border-blue-400'
          }`}
        >
          <Key size={20} className="text-text-muted mb-2" />
          <span className="font-medium text-text-default text-base block">
            {intl.formatMessage(i18n.connectProvider)}
          </span>
          <p className="text-text-muted text-sm mt-1">
            {intl.formatMessage(i18n.connectProviderDescription)}
          </p>
        </button>

        <button
          type="button"
          onClick={() => setShowProductTour(true)}
          aria-haspopup="dialog"
          className="group cursor-pointer rounded-xl border border-border-default bg-background-muted p-4 text-left transition-all duration-200 hover:border-blue-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
        >
          <Compass aria-hidden="true" size={20} className="mb-2 text-text-muted" />
          <span className="block text-base font-medium text-text-default">
            {intl.formatMessage(i18n.discoverWithoutModel)}
          </span>
          <p className="mt-1 text-sm text-text-muted">
            {intl.formatMessage(i18n.discoverWithoutModelDescription)}
          </p>
        </button>

        {localInference && (
          <button
            type="button"
            onClick={handleLocalModelClick}
            aria-pressed={selectedPath === LOCAL_MODEL}
            className={`p-4 border rounded-xl text-left transition-all duration-200 cursor-pointer group ${
              selectedPath === LOCAL_MODEL
                ? 'border-blue-400 bg-background-muted'
                : 'border-border-default bg-background-muted hover:border-blue-400'
            }`}
          >
            <HardDrive size={20} className="text-text-muted mb-2" />
            <span className="font-medium text-text-default text-base block">
              {intl.formatMessage(i18n.useLocalModel)}
            </span>
            <p className="text-text-muted text-sm mt-1">
              {intl.formatMessage(i18n.localModelDescription)}
            </p>
          </button>
        )}
      </div>

      {localInference && selectedPath === LOCAL_MODEL && (
        <div className="animate-in fade-in slide-in-from-top-2 duration-300">
          <LocalModelPicker onConfigured={onConfigured} />
        </div>
      )}

      {selectedPath === OWN_PROVIDER && (
        <div className="animate-in fade-in slide-in-from-top-2 duration-300">
          {isLoadingProviders ? (
            <div
              role="status"
              className="flex items-center gap-2 rounded-lg border border-border-default bg-background-muted px-4 py-4 text-sm text-text-muted"
            >
              <LoaderCircle aria-hidden="true" size={16} className="animate-spin" />
              <span>{intl.formatMessage(i18n.loadingProviders)}</span>
            </div>
          ) : providerLoadError ? (
            <div
              role="alert"
              className="rounded-lg border border-border-default bg-background-muted px-4 py-4"
            >
              <p className="mb-3 text-sm text-text-default">
                {intl.formatMessage(i18n.loadProvidersError)}
              </p>
              <button
                type="button"
                onClick={() => void loadProviders()}
                className="inline-flex items-center gap-2 rounded-md border border-border-default px-3 py-2 text-sm font-medium text-text-default transition-colors hover:border-blue-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
              >
                <RefreshCw aria-hidden="true" size={14} />
                {intl.formatMessage(i18n.retryProviders)}
              </button>
            </div>
          ) : !selectedProvider ? (
            <>
              {featuredOptions.length > 0 && (
                <div className="mb-5">
                  <p className="mb-2 text-xs font-medium uppercase tracking-[0.14em] text-text-muted">
                    {intl.formatMessage(i18n.recommendedProviders)}
                  </p>
                  <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                    {featuredOptions.map((option) => (
                      <button
                        key={option.value}
                        type="button"
                        onClick={() => handleProviderSelect(option)}
                        className="flex min-h-12 items-center gap-3 rounded-lg border border-border-default bg-background-muted px-3 py-2 text-left text-sm font-medium text-text-default transition-colors hover:border-blue-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
                      >
                        <span
                          aria-hidden="true"
                          className="flex size-7 shrink-0 items-center justify-center rounded-md bg-background-secondary text-xs font-semibold text-text-muted"
                        >
                          {option.label.slice(0, 1).toUpperCase()}
                        </span>
                        <span>{option.label}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              <button
                type="button"
                onClick={() => setShowProviderCatalog((visible) => !visible)}
                aria-expanded={showProviderCatalog}
                className="mb-4 text-sm font-medium text-text-muted transition-colors hover:text-text-default focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
              >
                {showProviderCatalog
                  ? intl.formatMessage(i18n.hideProviderCatalog)
                  : intl.formatMessage(i18n.browseAllProviders, { count: options.length })}
              </button>

              {showProviderCatalog && (
                <div className="mb-4 animate-in fade-in slide-in-from-top-1 duration-200">
                  <Select
                    options={options}
                    value={selectedOption}
                    onChange={(option) => handleProviderSelect(option as ProviderOption | null)}
                    placeholder={intl.formatMessage(i18n.selectProvider)}
                    isClearable
                    isSearchable
                    autoFocus
                    filterOption={fuzzyFilterOption}
                  />
                </div>
              )}

              <button
                type="button"
                onClick={() => setShowCustomModal(true)}
                className="mb-6 flex items-center gap-1 text-sm text-text-muted transition-colors hover:text-text-default focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
              >
                <Plus size={14} />
                <span>{intl.formatMessage(i18n.addCustomProvider)}</span>
              </button>
            </>
          ) : (
            <>
              <div className="mb-4 flex items-center justify-between gap-3 rounded-lg border border-border-default bg-background-muted px-4 py-3">
                <span className="font-medium text-text-default">{selectedOption?.label}</span>
                <button
                  type="button"
                  onClick={() => setSelectedOption(null)}
                  className="text-sm text-text-muted transition-colors hover:text-text-default focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
                >
                  {intl.formatMessage(i18n.changeProvider)}
                </button>
              </div>
              <ProviderConfigForm
                key={selectedProvider.name}
                provider={selectedProvider}
                onConfigured={onConfigured}
              />
            </>
          )}
        </div>
      )}

      <Dialog open={showCustomModal} onOpenChange={setShowCustomModal}>
        <DialogContent className="sm:max-w-[600px] max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{intl.formatMessage(i18n.addCustomProviderTitle)}</DialogTitle>
          </DialogHeader>
          <CustomProviderForm
            initialData={null}
            isEditable={true}
            onSubmit={handleCreateCustomProvider}
            onCancel={() => setShowCustomModal(false)}
          />
        </DialogContent>
      </Dialog>

      <ProductTourDialog open={showProductTour} onOpenChange={setShowProductTour} />
    </div>
  );
}
