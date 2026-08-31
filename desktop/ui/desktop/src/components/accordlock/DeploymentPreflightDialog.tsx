import { useEffect, useState } from 'react';
import { AlertCircle, GitPullRequest, LoaderCircle, Server } from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../ui/dialog';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import {
  DeploymentPreflightResult,
  type DeploymentPreflightResultView,
} from './DeploymentPreflightResult';

export interface DeploymentPreflightEnvironmentView {
  id: string;
  name: string;
  repository: string;
  workflow: string;
  target: string;
  status: 'SAVED' | 'VERIFIED' | 'FAILED';
}

export interface DeploymentPreflightDialogInput {
  profileId: string;
  pullRequestUrl: string;
  buildRunUrl: string;
  imageDigest: string;
}

export interface DeploymentPreflightCandidateDefaults {
  buildRunUrl: string;
  imageDigest: string;
}

type DialogState =
  | { kind: 'FORM' }
  | { kind: 'RUNNING' }
  | { kind: 'ERROR'; message: string }
  | { kind: 'RESULT'; result: DeploymentPreflightResultView };

function initialState(): DialogState {
  return { kind: 'FORM' };
}

export function DeploymentPreflightDialog({
  open,
  environment,
  candidateDefaults,
  onOpenChange,
  onRun,
  onExport,
}: {
  open: boolean;
  environment: DeploymentPreflightEnvironmentView;
  candidateDefaults?: DeploymentPreflightCandidateDefaults;
  onOpenChange: (open: boolean) => void;
  onRun: (input: DeploymentPreflightDialogInput) => Promise<DeploymentPreflightResultView>;
  onExport: (result: DeploymentPreflightResultView) => void;
}) {
  const [pullRequestUrl, setPullRequestUrl] = useState('');
  const [buildRunUrl, setBuildRunUrl] = useState('');
  const [imageDigest, setImageDigest] = useState('');
  const [state, setState] = useState<DialogState>(initialState);
  const defaultBuildRunUrl = candidateDefaults?.buildRunUrl ?? '';
  const defaultImageDigest = candidateDefaults?.imageDigest ?? '';

  useEffect(() => {
    if (!open) return;
    setPullRequestUrl('');
    setBuildRunUrl(defaultBuildRunUrl);
    setImageDigest(defaultImageDigest);
    setState(initialState());
  }, [defaultBuildRunUrl, defaultImageDigest, environment.id, open]);

  const canRun =
    state.kind !== 'RUNNING' &&
    pullRequestUrl.trim().length > 0 &&
    buildRunUrl.trim().length > 0 &&
    /^sha256:[0-9a-f]{64}$/u.test(imageDigest.trim());

  const run = async () => {
    if (!canRun) return;
    setState({ kind: 'RUNNING' });
    try {
      const result = await onRun({
        profileId: environment.id,
        pullRequestUrl: pullRequestUrl.trim(),
        buildRunUrl: buildRunUrl.trim(),
        imageDigest: imageDigest.trim(),
      });
      setState({ kind: 'RESULT', result });
    } catch (error) {
      setState({
        kind: 'ERROR',
        message: error instanceof Error && error.message ? error.message : "Couldn't run checks.",
      });
    }
  };

  const result = state.kind === 'RESULT' ? state.result : null;

  return (
    <Dialog
      open={open}
      onOpenChange={(nextOpen) => state.kind !== 'RUNNING' && onOpenChange(nextOpen)}
    >
      <DialogContent className="max-h-[min(820px,calc(100vh-32px))] overflow-y-auto sm:max-w-[680px]">
        <DialogHeader>
          <DialogTitle>Verify deployment</DialogTitle>
          <DialogDescription>
            Read-only. Checks the code, build, image, and current target. Nothing is deployed.
          </DialogDescription>
        </DialogHeader>

        {result ? (
          <DeploymentPreflightResult
            result={result}
            onExport={() => onExport(result)}
            onRetry={result.outcome === 'INDETERMINATE' ? () => void run() : undefined}
          />
        ) : (
          <div className="space-y-5 py-1">
            <section className="rounded-xl border border-border-secondary bg-background-secondary/30 px-4 py-3">
              <div className="flex items-start gap-3">
                <Server aria-hidden="true" className="mt-0.5 h-4 w-4 text-text-secondary" />
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <h3 className="text-sm font-medium text-text-primary">{environment.name}</h3>
                    <span className="rounded-full bg-background-secondary px-2 py-0.5 text-[11px] text-text-secondary">
                      {environment.status === 'VERIFIED'
                        ? 'Last check passed'
                        : environment.status === 'FAILED'
                          ? 'Needs attention'
                          : 'Not checked'}
                    </span>
                  </div>
                  <p className="mt-1 text-xs text-text-secondary">
                    {environment.repository} · {environment.workflow}
                  </p>
                  <p className="mt-0.5 truncate text-xs text-text-tertiary">
                    Target · {environment.target}
                  </p>
                </div>
              </div>
            </section>

            <label className="block space-y-1.5" htmlFor="preflight-pull-request">
              <span className="flex items-center gap-2 text-sm font-medium text-text-primary">
                <GitPullRequest aria-hidden="true" className="h-4 w-4" />
                Pull request
              </span>
              <Input
                id="preflight-pull-request"
                value={pullRequestUrl}
                onChange={(event) => setPullRequestUrl(event.target.value)}
                placeholder={`https://github.com/${environment.repository}/pull/42`}
                disabled={state.kind === 'RUNNING'}
                autoFocus
              />
            </label>

            <label className="block space-y-1.5" htmlFor="preflight-build-run">
              <span className="text-sm font-medium text-text-primary">Build run</span>
              <Input
                id="preflight-build-run"
                value={buildRunUrl}
                onChange={(event) => setBuildRunUrl(event.target.value)}
                placeholder={`https://github.com/${environment.repository}/actions/runs/…`}
                disabled={state.kind === 'RUNNING'}
              />
            </label>

            <label className="block space-y-1.5" htmlFor="preflight-image-digest">
              <span className="text-sm font-medium text-text-primary">Image digest</span>
              <Input
                id="preflight-image-digest"
                aria-label="Image digest"
                value={imageDigest}
                onChange={(event) => setImageDigest(event.target.value)}
                placeholder="sha256:…"
                spellCheck={false}
                disabled={state.kind === 'RUNNING'}
                className="font-mono"
              />
              <span className="block text-xs text-text-tertiary">
                Use an immutable SHA-256 digest. Tags such as latest are not accepted.
              </span>
            </label>

            {state.kind === 'ERROR' && (
              <div role="alert" className="flex items-start gap-2 text-sm text-text-danger">
                <AlertCircle aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{state.message}</span>
              </div>
            )}
          </div>
        )}

        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={state.kind === 'RUNNING'}
          >
            {result ? 'Close' : 'Cancel'}
          </Button>
          {!result && (
            <Button type="button" onClick={() => void run()} disabled={!canRun}>
              {state.kind === 'RUNNING' && (
                <LoaderCircle aria-hidden="true" className="h-4 w-4 animate-spin" />
              )}
              {state.kind === 'RUNNING' ? 'Running checks…' : 'Run checks'}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
