import { useEffect, useState } from 'react';
import { Plus, RotateCcw, ShieldCheck, SquareTerminal, Trash2 } from 'lucide-react';
import type { AccordLockTerminalProgramBinding } from '../../../accordlockTerminalPrograms';
import { defineMessages, useIntl } from '../../../i18n';
import { Button } from '../../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../ui/card';

const ALIAS_PATTERN = /^[a-z0-9_-]{1,64}$/u;

const i18n = defineMessages({
  title: { id: 'accordLock.terminalPrograms.title', defaultMessage: 'Allowed programs' },
  description: {
    id: 'accordLock.terminalPrograms.description',
    defaultMessage:
      'Add a short name for one specific native program. Choose the program in the system file picker; typed paths are not accepted.',
  },
  optIn: { id: 'accordLock.terminalPrograms.optIn', defaultMessage: 'None by default' },
  warningTitle: {
    id: 'accordLock.terminalPrograms.warningTitle',
    defaultMessage: 'Runs outside the workspace.',
  },
  warning: {
    id: 'accordLock.terminalPrograms.warning',
    defaultMessage:
      'An allowed program can change files or settings anywhere your account can access. AccordLock shows its full path and SHA-256 before each run requires approval.',
  },
  aliasLabel: { id: 'accordLock.terminalPrograms.aliasLabel', defaultMessage: 'Program alias' },
  aliasPlaceholder: {
    id: 'accordLock.terminalPrograms.aliasPlaceholder',
    defaultMessage: 'Alias, for example cargo',
  },
  choose: {
    id: 'accordLock.terminalPrograms.choose',
    defaultMessage: 'Choose executable…',
  },
  aliasError: {
    id: 'accordLock.terminalPrograms.aliasError',
    defaultMessage:
      'Use 1–64 lowercase letters, numbers, hyphens or underscores. Shell aliases are not accepted.',
  },
  loadError: {
    id: 'accordLock.terminalPrograms.loadError',
    defaultMessage: 'Allowed programs could not be loaded. No terminal program was added.',
  },
  addError: {
    id: 'accordLock.terminalPrograms.addError',
    defaultMessage: 'The program was not added. Choose a native executable and a safe alias.',
  },
  removeError: {
    id: 'accordLock.terminalPrograms.removeError',
    defaultMessage: 'The allowed program could not be removed safely.',
  },
  loading: {
    id: 'accordLock.terminalPrograms.loading',
    defaultMessage: 'Loading allowed programs…',
  },
  empty: {
    id: 'accordLock.terminalPrograms.empty',
    defaultMessage: 'No program is allowed by default.',
  },
  remove: {
    id: 'accordLock.terminalPrograms.remove',
    defaultMessage: 'Remove {alias}',
  },
  restartRequired: {
    id: 'accordLock.terminalPrograms.restartRequired',
    defaultMessage: 'Restart AccordLock to activate the updated allowed-program set.',
  },
  restart: { id: 'accordLock.terminalPrograms.restart', defaultMessage: 'Restart now' },
});

export default function TerminalProgramsSettings() {
  const intl = useIntl();
  const [programs, setPrograms] = useState<AccordLockTerminalProgramBinding[]>([]);
  const [alias, setAlias] = useState('');
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [restartRequired, setRestartRequired] = useState(false);
  const [error, setError] = useState<keyof typeof i18n | null>(null);

  useEffect(() => {
    window.electron
      .listAllowedTerminalPrograms()
      .then(setPrograms)
      .catch(() => setError('loadError'))
      .finally(() => setLoading(false));
  }, []);

  const addProgram = async () => {
    if (!ALIAS_PATTERN.test(alias) || busy) return;
    setBusy(true);
    setError(null);
    try {
      const result = await window.electron.addAllowedTerminalProgram(alias);
      setPrograms(result.programs);
      setRestartRequired((current) => current || result.restartRequired);
      if (result.configured) setAlias('');
    } catch {
      setError('addError');
    } finally {
      setBusy(false);
    }
  };

  const removeProgram = async (programAlias: string) => {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      const result = await window.electron.removeAllowedTerminalProgram(programAlias);
      setPrograms(result.programs);
      setRestartRequired((current) => current || result.restartRequired);
    } catch {
      setError('removeError');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card className="rounded-lg border-border-primary/80 overflow-hidden">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-4">
          <div>
            <CardTitle className="flex items-center gap-2">
              <ShieldCheck className="h-4 w-4" aria-hidden="true" />
              {intl.formatMessage(i18n.title)}
            </CardTitle>
            <CardDescription className="mt-1 max-w-2xl">
              {intl.formatMessage(i18n.description)}
            </CardDescription>
          </div>
          <span className="rounded-full border border-border-primary px-2.5 py-1 text-[10px] font-medium uppercase tracking-[0.12em] text-text-secondary">
            {intl.formatMessage(i18n.optIn)}
          </span>
        </div>
      </CardHeader>
      <CardContent className="space-y-4 px-4">
        <div className="rounded-md border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-xs text-text-secondary">
          <strong className="text-text-primary">{intl.formatMessage(i18n.warningTitle)}</strong>{' '}
          {intl.formatMessage(i18n.warning)}
        </div>

        <div className="flex flex-col gap-2 sm:flex-row">
          <label className="sr-only" htmlFor="accordlock-terminal-alias">
            {intl.formatMessage(i18n.aliasLabel)}
          </label>
          <input
            id="accordlock-terminal-alias"
            value={alias}
            onChange={(event) => setAlias(event.target.value.toLowerCase())}
            onKeyDown={(event) => {
              if (event.key === 'Enter') void addProgram();
            }}
            placeholder={intl.formatMessage(i18n.aliasPlaceholder)}
            autoComplete="off"
            spellCheck={false}
            maxLength={64}
            className="h-9 min-w-0 flex-1 rounded-md border border-border-primary bg-background-primary px-3 font-mono text-sm text-text-primary outline-none transition focus:border-text-secondary"
          />
          <Button
            size="sm"
            className="gap-2"
            disabled={!ALIAS_PATTERN.test(alias) || busy}
            onClick={() => void addProgram()}
          >
            <Plus className="h-4 w-4" aria-hidden="true" />
            {intl.formatMessage(i18n.choose)}
          </Button>
        </div>
        {alias.length > 0 && !ALIAS_PATTERN.test(alias) && (
          <p className="text-xs text-red-500" role="alert">
            {intl.formatMessage(i18n.aliasError)}
          </p>
        )}
        {error && (
          <p className="text-xs text-red-500" role="alert">
            {intl.formatMessage(i18n[error])}
          </p>
        )}

        <div className="divide-y divide-border-primary rounded-md border border-border-primary">
          {loading ? (
            <p className="px-3 py-4 text-xs text-text-secondary">
              {intl.formatMessage(i18n.loading)}
            </p>
          ) : programs.length === 0 ? (
            <div className="flex items-center gap-3 px-3 py-4 text-xs text-text-secondary">
              <SquareTerminal className="h-4 w-4" aria-hidden="true" />
              {intl.formatMessage(i18n.empty)}
            </div>
          ) : (
            programs.map((program) => (
              <div key={program.alias} className="flex items-start gap-3 px-3 py-3">
                <SquareTerminal className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
                <div className="min-w-0 flex-1">
                  <div className="font-mono text-sm font-medium text-text-primary">
                    {program.alias}
                  </div>
                  <div className="mt-1 break-all font-mono text-[11px] text-text-secondary">
                    {program.executable_path}
                  </div>
                  <div className="mt-0.5 break-all font-mono text-[10px] text-text-secondary/80">
                    {program.executable_sha256}
                  </div>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  aria-label={intl.formatMessage(i18n.remove, { alias: program.alias })}
                  disabled={busy}
                  onClick={() => void removeProgram(program.alias)}
                >
                  <Trash2 className="h-4 w-4" aria-hidden="true" />
                </Button>
              </div>
            ))
          )}
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
