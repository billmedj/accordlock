import { useEffect, useMemo, useState } from 'react';
import { Globe2, RotateCcw, ShieldCheck } from 'lucide-react';
import { defineMessages, useIntl } from '../../../i18n';
import { Button } from '../../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../ui/card';

const i18n = defineMessages({
  title: { id: 'accordLock.networkAccess.title', defaultMessage: 'Network access' },
  description: {
    id: 'accordLock.networkAccess.description',
    defaultMessage:
      'Allow GET and HEAD requests to specific HTTPS domains. Each request needs approval.',
  },
  label: { id: 'accordLock.networkAccess.label', defaultMessage: 'Allowed domains' },
  placeholder: {
    id: 'accordLock.networkAccess.placeholder',
    defaultMessage: 'api.example.com\nstatus.example.com',
  },
  hint: {
    id: 'accordLock.networkAccess.hint',
    defaultMessage:
      'One lowercase domain per line. No wildcards, URLs, ports, local addresses or credentials.',
  },
  boundary: {
    id: 'accordLock.networkAccess.boundary',
    defaultMessage: 'Redirects, proxies, credentials and local addresses are blocked.',
  },
  save: { id: 'accordLock.networkAccess.save', defaultMessage: 'Save domains' },
  saving: { id: 'accordLock.networkAccess.saving', defaultMessage: 'Saving…' },
  loading: { id: 'accordLock.networkAccess.loading', defaultMessage: 'Loading…' },
  off: { id: 'accordLock.networkAccess.off', defaultMessage: 'Off' },
  ready: { id: 'accordLock.networkAccess.ready', defaultMessage: '{count} allowed' },
  invalid: {
    id: 'accordLock.networkAccess.invalid',
    defaultMessage: 'Use exact lowercase public domains, one per line.',
  },
  loadError: {
    id: 'accordLock.networkAccess.loadError',
    defaultMessage: "Network access couldn't be loaded. Web requests remain unavailable.",
  },
  saveError: {
    id: 'accordLock.networkAccess.saveError',
    defaultMessage: "Network access wasn't changed.",
  },
  restartRequired: {
    id: 'accordLock.networkAccess.restartRequired',
    defaultMessage: 'Restart AccordLock to apply these changes.',
  },
  restart: { id: 'accordLock.networkAccess.restart', defaultMessage: 'Restart now' },
});

const DOMAIN = /^(?=.{1,253}$)(?=.*\.)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$/u;

function parseDomains(value: string): string[] | null {
  const domains = value
    .split(/\r?\n/u)
    .map((domain) => domain.trim())
    .filter(Boolean);
  if (
    domains.length > 64 ||
    domains.some(
      (domain) =>
        !DOMAIN.test(domain) ||
        domain.includes('..') ||
        domain.includes('*') ||
        domain === 'localhost' ||
        domain.endsWith('.localhost') ||
        /^\d{1,3}(?:\.\d{1,3}){3}$/u.test(domain) ||
        domain
          .split('.')
          .some((label) => label.length > 63 || label.startsWith('-') || label.endsWith('-'))
    )
  ) {
    return null;
  }
  const unique = [...new Set(domains)].sort((left, right) => left.localeCompare(right, 'en-US'));
  return unique.length === domains.length ? unique : null;
}

export default function NetworkAccessSettings() {
  const intl = useIntl();
  const [text, setText] = useState('');
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [restartRequired, setRestartRequired] = useState(false);
  const [error, setError] = useState<'loadError' | 'saveError' | null>(null);
  const domains = useMemo(() => parseDomains(text), [text]);

  useEffect(() => {
    window.electron
      .getGovernedNetworkPolicy()
      .then((policy) => {
        setText(policy.domains.join('\n'));
        setRestartRequired(!policy.active);
      })
      .catch(() => setError('loadError'))
      .finally(() => setLoading(false));
  }, []);

  const save = async () => {
    if (domains === null || busy) return;
    setBusy(true);
    setError(null);
    try {
      const result = await window.electron.setGovernedNetworkDomains(domains);
      setText(result.domains.join('\n'));
      setRestartRequired((current) => current || result.restartRequired);
    } catch {
      setError('saveError');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card className="overflow-hidden rounded-lg border-border-primary/80">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-4">
          <div>
            <CardTitle className="flex items-center gap-2">
              <ShieldCheck className="h-4 w-4" aria-hidden="true" />
              {intl.formatMessage(i18n.title)}
            </CardTitle>
            <CardDescription className="mt-1">
              {intl.formatMessage(i18n.description)}
            </CardDescription>
          </div>
          <span className="rounded-full border border-border-primary px-2.5 py-1 text-[10px] font-medium uppercase tracking-[0.12em] text-text-secondary">
            {loading
              ? intl.formatMessage(i18n.loading)
              : intl.formatMessage(text.trim() ? i18n.ready : i18n.off, {
                  count: domains?.length ?? 0,
                })}
          </span>
        </div>
      </CardHeader>
      <CardContent className="space-y-3 px-4">
        <div className="rounded-md border border-border-primary bg-background-secondary/50 px-3 py-2 text-xs text-text-secondary">
          <Globe2 className="mr-2 inline h-3.5 w-3.5" aria-hidden="true" />
          {intl.formatMessage(i18n.boundary)}
        </div>
        <div>
          <label htmlFor="accordlock-network-domains" className="mb-1.5 block text-xs font-medium">
            {intl.formatMessage(i18n.label)}
          </label>
          <textarea
            id="accordlock-network-domains"
            value={text}
            onChange={(event) => setText(event.target.value.toLowerCase())}
            placeholder={intl.formatMessage(i18n.placeholder)}
            rows={4}
            spellCheck={false}
            autoComplete="off"
            disabled={loading || busy}
            className="w-full resize-y rounded-md border border-border-primary bg-background-primary px-3 py-2 font-mono text-sm text-text-primary outline-none transition focus:border-text-secondary"
          />
          <p className="mt-1.5 text-[11px] text-text-secondary">{intl.formatMessage(i18n.hint)}</p>
        </div>
        {text.length > 0 && domains === null && (
          <p className="text-xs text-red-500" role="alert">
            {intl.formatMessage(i18n.invalid)}
          </p>
        )}
        {error && (
          <p className="text-xs text-red-500" role="alert">
            {intl.formatMessage(i18n[error])}
          </p>
        )}
        <div className="flex justify-end">
          <Button
            size="sm"
            disabled={domains === null || busy || loading}
            onClick={() => void save()}
          >
            {intl.formatMessage(busy ? i18n.saving : i18n.save)}
          </Button>
        </div>
        {restartRequired && (
          <div className="flex items-center justify-between gap-3 rounded-md bg-background-secondary px-3 py-2 text-xs">
            <span>{intl.formatMessage(i18n.restartRequired)}</span>
            <Button
              size="sm"
              variant="secondary"
              className="gap-2"
              onClick={window.electron.restartApp}
            >
              <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
              {intl.formatMessage(i18n.restart)}
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
