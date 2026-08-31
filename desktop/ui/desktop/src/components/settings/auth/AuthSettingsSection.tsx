import { useCallback, useEffect, useState } from 'react';
import { KeyRound, Loader2, LogIn, Plus, RefreshCw, Trash2 } from 'lucide-react';
import { toast } from 'react-toastify';
import {
  acpAuthenticateProvider,
  acpDeleteProviderSecret,
  acpListProviderSecrets,
  type ProviderSecretDto,
} from '../../../acp/providers';
import { useModelAndProvider } from '../../ModelAndProviderContext';
import { Button } from '../../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../ui/card';
import { ConfirmationModal } from '../../ui/ConfirmationModal';
import { defineMessages, useIntl } from '../../../i18n';

const i18n = defineMessages({
  title: {
    id: 'authSettings.title',
    defaultMessage: 'Provider credentials',
  },
  description: {
    id: 'authSettings.description',
    defaultMessage: 'Saved on this device.',
  },
  loading: {
    id: 'authSettings.loading',
    defaultMessage: 'Loading credentials...',
  },
  empty: {
    id: 'authSettings.empty',
    defaultMessage: 'No credentials saved.',
  },
  failedToLoad: {
    id: 'authSettings.failedToLoad',
    defaultMessage: 'Failed to load provider credentials',
  },
  deleteTitle: {
    id: 'authSettings.deleteTitle',
    defaultMessage: 'Remove credential',
  },
  deleteMessage: {
    id: 'authSettings.deleteMessage',
    defaultMessage: 'Remove the credential for {provider}?',
  },
  activeProviderWarning: {
    id: 'authSettings.activeProviderWarning',
    defaultMessage: 'This provider may stop working until another credential is configured.',
  },
  delete: {
    id: 'authSettings.delete',
    defaultMessage: 'Remove',
  },
  cancel: {
    id: 'authSettings.cancel',
    defaultMessage: 'Cancel',
  },
  deleted: {
    id: 'authSettings.deleted',
    defaultMessage: 'Credential removed',
  },
  failedToDelete: {
    id: 'authSettings.failedToDelete',
    defaultMessage: 'Failed to delete credential: {error}',
  },
  credential: {
    id: 'authSettings.credential',
    defaultMessage: 'Credential',
  },
  saved: {
    id: 'authSettings.saved',
    defaultMessage: 'Saved',
  },
  notConnected: {
    id: 'authSettings.notConnected',
    defaultMessage: 'Not connected',
  },
  expiresAt: {
    id: 'authSettings.expiresAt',
    defaultMessage: 'Expires {date}',
  },
  deleteCredential: {
    id: 'authSettings.deleteCredential',
    defaultMessage: 'Remove credential',
  },
  signIn: {
    id: 'authSettings.signIn',
    defaultMessage: 'Sign in',
  },
  reauthorize: {
    id: 'authSettings.reauthorize',
    defaultMessage: 'Reauthorize',
  },
  signedIn: {
    id: 'authSettings.signedIn',
    defaultMessage: 'Credential saved',
  },
  failedToConfigure: {
    id: 'authSettings.failedToConfigure',
    defaultMessage: 'Failed to configure credential: {error}',
  },
  connectProvider: {
    id: 'authSettings.connectProvider',
    defaultMessage: 'Connect provider',
  },
});

function credentialSummary(secret: ProviderSecretDto, intl: ReturnType<typeof useIntl>) {
  const state =
    secret.hasSecret || secret.configured
      ? intl.formatMessage(i18n.saved)
      : intl.formatMessage(i18n.notConnected);
  return `${intl.formatMessage(i18n.credential)} · ${state}`;
}

function expiryLabel(secret: ProviderSecretDto, intl: ReturnType<typeof useIntl>) {
  if (!secret.expiresAt) {
    return null;
  }
  return intl.formatMessage(i18n.expiresAt, {
    date: intl.formatDate(new Date(secret.expiresAt), {
      dateStyle: 'medium',
      timeStyle: 'short',
    }),
  });
}

function expiryClass(secret: ProviderSecretDto) {
  if (secret.status === 'expired') {
    return 'border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-300';
  }
  return 'border-green-500/30 bg-green-500/10 text-green-700 dark:text-green-300';
}

export default function AuthSettingsSection({
  onConnectProvider,
}: {
  onConnectProvider?: () => void;
}) {
  const intl = useIntl();
  const { currentProvider } = useModelAndProvider();
  const [secrets, setSecrets] = useState<ProviderSecretDto[]>([]);
  const [loading, setLoading] = useState(true);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [configuringId, setConfiguringId] = useState<string | null>(null);
  const [secretToDelete, setSecretToDelete] = useState<ProviderSecretDto | null>(null);

  const loadSecrets = useCallback(async () => {
    setLoading(true);
    try {
      const secrets = await acpListProviderSecrets();
      setSecrets(secrets);
    } catch (error) {
      console.error('Failed to load provider credentials:', error);
      toast.error(intl.formatMessage(i18n.failedToLoad));
      setSecrets([]);
    } finally {
      setLoading(false);
    }
  }, [intl]);

  useEffect(() => {
    loadSecrets();
  }, [loadSecrets]);

  const confirmDelete = async () => {
    if (!secretToDelete) {
      return;
    }

    setDeletingId(secretToDelete.id);
    try {
      await acpDeleteProviderSecret(secretToDelete.id);
      toast.success(intl.formatMessage(i18n.deleted));
      setSecretToDelete(null);
      await loadSecrets();
    } catch (error) {
      console.error('Failed to delete provider credential:', error);
      toast.error(
        intl.formatMessage(i18n.failedToDelete, {
          error: 'Try again.',
        })
      );
    } finally {
      setDeletingId(null);
    }
  };

  const configureSecret = async (secret: ProviderSecretDto) => {
    if (!secret.configureProvider) {
      return;
    }

    setConfiguringId(secret.id);
    try {
      await acpAuthenticateProvider(secret.configureProvider);
      toast.success(intl.formatMessage(i18n.signedIn));
      await loadSecrets();
    } catch (error) {
      console.error('Failed to configure provider credential:', error);
      toast.error(
        intl.formatMessage(i18n.failedToConfigure, {
          error: 'Try again.',
        })
      );
    } finally {
      setConfiguringId(null);
    }
  };

  const isActiveProvider = secretToDelete?.provider === currentProvider;

  return (
    <section id="auth" className="space-y-4 pr-4 mt-1">
      <Card className="pb-2">
        <CardHeader className="flex-row items-start justify-between gap-4 pb-0">
          <div>
            <CardTitle className="flex items-center gap-2">
              <KeyRound className="h-4 w-4" />
              {intl.formatMessage(i18n.title)}
            </CardTitle>
            <CardDescription>{intl.formatMessage(i18n.description)}</CardDescription>
          </div>
          {onConnectProvider && (
            <Button
              variant="outline"
              size="sm"
              className="shrink-0 gap-2"
              onClick={onConnectProvider}
            >
              <Plus className="h-4 w-4" aria-hidden="true" />
              {intl.formatMessage(i18n.connectProvider)}
            </Button>
          )}
        </CardHeader>
        <CardContent className="px-4 py-2">
          {loading ? (
            <div className="flex items-center gap-2 py-6 text-sm text-text-secondary">
              <Loader2 className="h-4 w-4 animate-spin" />
              {intl.formatMessage(i18n.loading)}
            </div>
          ) : secrets.length === 0 ? (
            <div className="py-6 text-sm text-text-secondary">{intl.formatMessage(i18n.empty)}</div>
          ) : (
            <div className="divide-y divide-border-primary">
              {secrets.map((secret) => (
                <div
                  key={secret.id}
                  className="flex flex-col gap-3 py-3 sm:flex-row sm:items-center sm:justify-between"
                  data-testid="auth-secret-row"
                >
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="text-sm font-medium text-text-primary">
                        {secret.providerDisplayName}
                      </h3>
                      {expiryLabel(secret, intl) && (
                        <span
                          className={`rounded border px-2 py-0.5 text-xs ${expiryClass(secret)}`}
                        >
                          {expiryLabel(secret, intl)}
                        </span>
                      )}
                    </div>
                    <p className="mt-1 text-xs text-text-secondary">
                      {credentialSummary(secret, intl)}
                    </p>
                  </div>
                  <div className="flex items-center gap-2 self-start sm:self-auto">
                    {secret.canConfigure && secret.configureProvider && (
                      <Button
                        variant="outline"
                        size="sm"
                        className="gap-2"
                        disabled={configuringId === secret.id}
                        onClick={() => configureSecret(secret)}
                      >
                        {configuringId === secret.id ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : secret.hasSecret || secret.configured ? (
                          <RefreshCw className="h-4 w-4" />
                        ) : (
                          <LogIn className="h-4 w-4" />
                        )}
                        {secret.hasSecret || secret.configured
                          ? intl.formatMessage(i18n.reauthorize)
                          : intl.formatMessage(i18n.signIn)}
                      </Button>
                    )}
                    {secret.canDelete && (
                      <Button
                        variant="ghost"
                        size="sm"
                        shape="round"
                        className="text-text-secondary hover:text-text-primary"
                        disabled={deletingId === secret.id}
                        onClick={() => setSecretToDelete(secret)}
                        aria-label={intl.formatMessage(i18n.deleteCredential)}
                        title={intl.formatMessage(i18n.deleteCredential)}
                      >
                        {deletingId === secret.id ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                          <Trash2 className="h-4 w-4" />
                        )}
                      </Button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <ConfirmationModal
        isOpen={!!secretToDelete}
        title={intl.formatMessage(i18n.deleteTitle)}
        message={
          secretToDelete
            ? intl.formatMessage(i18n.deleteMessage, {
                provider: secretToDelete.providerDisplayName,
              })
            : ''
        }
        detail={isActiveProvider ? intl.formatMessage(i18n.activeProviderWarning) : undefined}
        onConfirm={confirmDelete}
        onCancel={() => setSecretToDelete(null)}
        confirmLabel={intl.formatMessage(i18n.delete)}
        cancelLabel={intl.formatMessage(i18n.cancel)}
        confirmVariant="destructive"
        isSubmitting={!!deletingId}
      />
    </section>
  );
}
