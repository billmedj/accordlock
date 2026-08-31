import { useRef, useState } from 'react';
import { CornerDownLeft, FolderLock, LockKeyhole } from 'lucide-react';
import { validateAccordLockObjective } from '../accordlock/taskObjective';
import { defineMessages, useIntl } from '../i18n';
import { AccordLockGlyph } from './accordlock/AccordLockBrand';

const messages = defineMessages({
  label: {
    id: 'launcher.label',
    defaultMessage: 'New task',
  },
  placeholder: {
    id: 'launcher.placeholder',
    defaultMessage: 'What should AccordLock accomplish?',
  },
  workspace: {
    id: 'launcher.workspace',
    defaultMessage: 'Folder: {name}',
  },
  reviewRequired: {
    id: 'launcher.reviewRequired',
    defaultMessage: 'Review access before it starts.',
  },
  objectiveRequired: {
    id: 'launcher.objectiveRequired',
    defaultMessage: 'Describe a task in text.',
  },
  objectiveTooLarge: {
    id: 'launcher.objectiveTooLarge',
    defaultMessage: 'Shorten the task description.',
  },
  objectiveUnsafe: {
    id: 'launcher.objectiveUnsafe',
    defaultMessage: 'Paste the task again as plain text.',
  },
});

function workspaceName(workspace: string): string {
  const components = workspace.split(/[\\/]/u).filter(Boolean);
  return components[components.length - 1] ?? workspace;
}

export default function LauncherView() {
  const [query, setQuery] = useState('');
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const intl = useIntl();
  const workspace = String(window.appConfig.get('ACCORDLOCK_LAUNCHER_WORKSPACE') ?? '');

  const handleSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    if (isSubmitting) return;

    const objective = validateAccordLockObjective(query);
    if (!objective.ok) {
      const errorMessages = {
        EMPTY: messages.objectiveRequired,
        TOO_LARGE: messages.objectiveTooLarge,
        UNSAFE_TEXT: messages.objectiveUnsafe,
      } as const;
      setError(intl.formatMessage(errorMessages[objective.reason]));
      return;
    }

    setIsSubmitting(true);
    setError('');
    window.electron.createChatWindow({ query: objective.objective });
    window.setTimeout(() => window.electron.closeWindow(), 200);
  };

  const handleKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === 'Escape') window.electron.closeWindow();
  };

  return (
    <div className="flex h-screen w-screen items-center justify-center overflow-hidden bg-transparent p-1.5">
      <form
        onSubmit={handleSubmit}
        className="flex h-full w-full flex-col justify-center overflow-hidden rounded-[22px] border border-border-primary bg-background-primary/95 px-4 shadow-2xl backdrop-blur-xl"
      >
        <div className="flex min-w-0 items-center gap-3">
          <AccordLockGlyph className="size-10 rounded-xl" />
          <div className="min-w-0 flex-1">
            <label
              htmlFor="accordlock-launcher-input"
              className="mb-1 block text-[10px] font-semibold uppercase tracking-[0.14em] text-text-tertiary"
            >
              {intl.formatMessage(messages.label)}
            </label>
            <input
              id="accordlock-launcher-input"
              ref={inputRef}
              type="text"
              value={query}
              onChange={(event) => {
                setQuery(event.target.value);
                if (error) setError('');
              }}
              onKeyDown={handleKeyDown}
              className="h-8 w-full bg-transparent text-lg font-normal tracking-[-0.015em] text-text-primary outline-none placeholder:text-text-tertiary"
              placeholder={intl.formatMessage(messages.placeholder)}
              aria-invalid={Boolean(error)}
              aria-describedby={error ? 'accordlock-launcher-error' : undefined}
              disabled={isSubmitting}
              autoFocus
            />
          </div>
          <button
            type="submit"
            disabled={isSubmitting}
            aria-label={intl.formatMessage(messages.label)}
            className="grid size-9 shrink-0 place-items-center rounded-xl bg-text-primary text-background-primary transition-opacity hover:opacity-85 disabled:opacity-40"
          >
            <CornerDownLeft className="size-4" aria-hidden="true" />
          </button>
        </div>

        <div className="mt-2 flex min-w-0 items-center gap-4 border-t border-border-secondary pt-2 text-[11px] text-text-tertiary">
          {error ? (
            <p id="accordlock-launcher-error" role="alert" className="truncate text-text-danger">
              {error}
            </p>
          ) : (
            <>
              <span className="inline-flex min-w-0 items-center gap-1.5">
                <FolderLock className="size-3.5 shrink-0" aria-hidden="true" />
                <span className="truncate" title={workspace}>
                  {intl.formatMessage(messages.workspace, {
                    name: workspaceName(workspace) || '—',
                  })}
                </span>
              </span>
              <span className="inline-flex items-center gap-1.5">
                <LockKeyhole className="size-3.5 shrink-0" aria-hidden="true" />
                {intl.formatMessage(messages.reviewRequired)}
              </span>
              <span className="ml-auto shrink-0 font-mono">esc</span>
            </>
          )}
        </div>
      </form>
    </div>
  );
}
