import { AlertTriangle, Check, CircleHelp, Download, RotateCw } from 'lucide-react';
import { Button } from '../ui/button';
import { cn } from '../../utils';

export type DeploymentPreflightOutcome = 'PASSED' | 'BLOCKED' | 'INDETERMINATE';
export type DeploymentPreflightCheckKind = 'CODE_REVIEW' | 'BUILD' | 'IMAGE' | 'TARGET';
export type DeploymentPreflightCheckStatus = 'PASSED' | 'BLOCKED' | 'INDETERMINATE';

export interface DeploymentPreflightCheck {
  kind: DeploymentPreflightCheckKind;
  status: DeploymentPreflightCheckStatus;
  summary: string;
  reasonCode?: string;
}

export interface DeploymentPreflightResultView {
  checkId: string;
  outcome: DeploymentPreflightOutcome;
  checks: readonly DeploymentPreflightCheck[];
  completedAt: number;
  validUntil: number | null;
  reasonCodes: readonly string[];
  environmentProfileHash: string;
  receiptHash: string;
  /** Complete locally verified signed receipt, ready for audit export. */
  receiptJson: string;
}

const CHECK_LABELS: Readonly<Record<DeploymentPreflightCheckKind, string>> = {
  CODE_REVIEW: 'Code review',
  BUILD: 'Build',
  IMAGE: 'Image',
  TARGET: 'Target',
};

const REQUIRED_CHECKS: readonly DeploymentPreflightCheckKind[] = [
  'CODE_REVIEW',
  'BUILD',
  'IMAGE',
  'TARGET',
];

function outcomeCopy(outcome: DeploymentPreflightOutcome): {
  title: string;
  description: string;
  className: string;
} {
  switch (outcome) {
    case 'PASSED':
      return {
        title: 'Checks passed',
        description: 'The approved code, build, image, and current target match.',
        className: 'text-green-700 dark:text-green-300',
      };
    case 'BLOCKED':
      return {
        title: 'Checks failed',
        description: 'A verified mismatch or policy violation needs attention.',
        className: 'text-red-700 dark:text-red-300',
      };
    case 'INDETERMINATE':
      return {
        title: "Couldn't verify",
        description: 'AccordLock could not establish a trustworthy result.',
        className: 'text-amber-700 dark:text-amber-300',
      };
  }
}

function utcTime(unixSeconds: number): string {
  return new Intl.DateTimeFormat('en', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
    timeZone: 'UTC',
    timeZoneName: 'short',
  }).format(new Date(unixSeconds * 1_000));
}

function checkIcon(status: DeploymentPreflightCheckStatus) {
  if (status === 'PASSED') {
    return <Check aria-hidden="true" className="h-4 w-4 text-green-700 dark:text-green-300" />;
  }
  if (status === 'BLOCKED') {
    return <AlertTriangle aria-hidden="true" className="h-4 w-4 text-red-700 dark:text-red-300" />;
  }
  return <CircleHelp aria-hidden="true" className="h-4 w-4 text-amber-700 dark:text-amber-300" />;
}

export function validateDeploymentPreflightResultView(
  result: DeploymentPreflightResultView
): boolean {
  if (
    !result.checkId ||
    !Number.isSafeInteger(result.completedAt) ||
    result.completedAt < 0 ||
    (result.validUntil !== null &&
      (!Number.isSafeInteger(result.validUntil) || result.validUntil <= result.completedAt)) ||
    !/^sha256:[0-9a-f]{64}$/u.test(result.environmentProfileHash) ||
    !/^sha256:[0-9a-f]{64}$/u.test(result.receiptHash) ||
    typeof result.receiptJson !== 'string' ||
    result.receiptJson.length === 0 ||
    new TextEncoder().encode(result.receiptJson).byteLength > 256 * 1_024 ||
    result.checks.length !== REQUIRED_CHECKS.length
  ) {
    return false;
  }

  const kinds = result.checks.map((check) => check.kind);
  if (REQUIRED_CHECKS.some((kind, index) => kinds[index] !== kind)) return false;

  if (result.outcome === 'PASSED') {
    return result.checks.every((check) => check.status === 'PASSED');
  }
  if (result.outcome === 'BLOCKED') {
    return result.checks.some((check) => check.status === 'BLOCKED');
  }
  return result.checks.some((check) => check.status === 'INDETERMINATE');
}

export function DeploymentPreflightResult({
  result,
  onExport,
  onRetry,
}: {
  result: DeploymentPreflightResultView;
  onExport: () => void;
  onRetry?: () => void;
}) {
  if (!validateDeploymentPreflightResultView(result)) {
    return (
      <section role="alert" className="rounded-xl border border-border-secondary p-4">
        <h2 className="text-sm font-medium text-text-primary">Result unavailable</h2>
        <p className="mt-1 text-sm text-text-secondary">
          The preflight receipt did not pass local verification.
        </p>
      </section>
    );
  }

  const copy = outcomeCopy(result.outcome);

  return (
    <section
      aria-labelledby={`preflight-${result.checkId}`}
      className="rounded-xl border border-border-secondary bg-background-primary"
    >
      <div className="px-4 pb-3 pt-4">
        <h2
          id={`preflight-${result.checkId}`}
          className={cn('text-lg font-medium', copy.className)}
        >
          {copy.title}
        </h2>
        <p className="mt-1 text-sm text-text-secondary">{copy.description}</p>
      </div>

      <div className="border-y border-border-secondary">
        {result.checks.map((check) => (
          <div
            key={check.kind}
            className="grid grid-cols-[minmax(112px,0.45fr)_minmax(0,1fr)] gap-4 border-b border-border-secondary px-4 py-3 last:border-b-0"
          >
            <div className="flex items-center gap-2 text-sm font-medium text-text-primary">
              {checkIcon(check.status)}
              <span>{CHECK_LABELS[check.kind]}</span>
            </div>
            <div className="min-w-0 text-sm text-text-secondary">
              <p>{check.summary}</p>
              {check.reasonCode && check.status !== 'PASSED' && (
                <p className="mt-0.5 font-mono text-[11px] text-text-tertiary">
                  {check.reasonCode}
                </p>
              )}
            </div>
          </div>
        ))}
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
        <div className="text-xs leading-5 text-text-tertiary">
          <p>
            Checked {utcTime(result.completedAt)}
            {result.validUntil !== null ? ` · Valid until ${utcTime(result.validUntil)}` : ''}
          </p>
          <p>No deployment was performed.</p>
        </div>
        <div className="flex items-center gap-2">
          {result.outcome === 'INDETERMINATE' && onRetry && (
            <Button type="button" variant="outline" size="sm" onClick={onRetry}>
              <RotateCw aria-hidden="true" className="h-4 w-4" />
              Try again
            </Button>
          )}
          <Button type="button" variant="outline" size="sm" onClick={onExport}>
            <Download aria-hidden="true" className="h-4 w-4" />
            Export receipt
          </Button>
        </div>
      </div>

      <details className="border-t border-border-secondary px-4 py-3 text-xs">
        <summary className="cursor-pointer text-text-secondary hover:text-text-primary">
          View details
        </summary>
        <dl className="mt-3 grid gap-2 text-text-tertiary sm:grid-cols-2">
          <div>
            <dt>Environment profile</dt>
            <dd className="mt-0.5 break-all font-mono">{result.environmentProfileHash}</dd>
          </div>
          <div>
            <dt>Receipt</dt>
            <dd className="mt-0.5 break-all font-mono">{result.receiptHash}</dd>
          </div>
          {result.reasonCodes.length > 0 && (
            <div className="sm:col-span-2">
              <dt>Reason codes</dt>
              <dd className="mt-0.5 font-mono">{result.reasonCodes.join(', ')}</dd>
            </div>
          )}
        </dl>
      </details>
    </section>
  );
}
