import { useEffect, useState } from 'react';
import { CircleAlert, Download, LoaderCircle } from 'lucide-react';

import type { DeploymentPreflightReceiptArchiveSummary } from '../../accordlock/deploymentPreflightReceiptArchive';
import { Button } from '../ui/button';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '../ui/dialog';

type HistoryEnvironment = Readonly<{ id: string; name: string }>;

function outcomeCopy(outcome: DeploymentPreflightReceiptArchiveSummary['outcome']): string {
  if (outcome === 'PASSED') return 'Passed';
  if (outcome === 'BLOCKED') return 'Blocked';
  return "Couldn't verify";
}

function outcomeClass(outcome: DeploymentPreflightReceiptArchiveSummary['outcome']): string {
  if (outcome === 'PASSED') return 'text-green-700 dark:text-green-300';
  if (outcome === 'BLOCKED') return 'text-red-700 dark:text-red-300';
  return 'text-amber-700 dark:text-amber-300';
}

function completedAt(value: number): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(value * 1_000));
}

export function DeploymentPreflightHistoryDialog({
  open,
  environment,
  onOpenChange,
}: {
  open: boolean;
  environment: HistoryEnvironment;
  onOpenChange: (open: boolean) => void;
}) {
  const [items, setItems] = useState<readonly DeploymentPreflightReceiptArchiveSummary[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [exporting, setExporting] = useState<string | null>(null);
  const [exported, setExported] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    let active = true;
    setLoading(true);
    setItems([]);
    setError(null);
    setExported(null);
    void window.electron
      .listAccordLockDeploymentPreflightHistory(environment.id)
      .then((history) => {
        if (active) setItems(history);
      })
      .catch(() => {
        if (active) setError("Couldn't load check history.");
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [environment.id, open]);

  const exportReceipt = async (receiptHash: string) => {
    setExporting(receiptHash);
    setError(null);
    try {
      const result = await window.electron.exportAccordLockDeploymentPreflightReceipt(receiptHash);
      if (result.saved) setExported(receiptHash);
    } catch {
      setError("Couldn't export this receipt.");
    } finally {
      setExporting(null);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(nextOpen) => !exporting && onOpenChange(nextOpen)}>
      <DialogContent className="max-h-[min(760px,calc(100vh-32px))] overflow-y-auto sm:max-w-[680px]">
        <DialogHeader>
          <DialogTitle>Check history</DialogTitle>
          <DialogDescription>{environment.name}</DialogDescription>
        </DialogHeader>

        {loading ? (
          <div className="flex h-28 items-center justify-center text-text-secondary">
            <LoaderCircle aria-label="Loading check history" className="h-4 w-4 animate-spin" />
          </div>
        ) : error && items.length === 0 ? (
          <div role="alert" className="flex items-start gap-2 py-6 text-sm text-text-danger">
            <CircleAlert aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0" />
            {error}
          </div>
        ) : items.length === 0 ? (
          <div className="py-8 text-center">
            <p className="text-sm text-text-primary">No checks yet</p>
            <p className="mt-1 text-xs text-text-secondary">Completed checks will appear here.</p>
          </div>
        ) : (
          <div className="divide-y divide-border-subtle rounded-xl border border-border-secondary">
            {items.map((item) => (
              <article key={item.receiptHash} className="flex items-start gap-4 px-4 py-3.5">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                    <span className={`text-xs font-medium ${outcomeClass(item.outcome)}`}>
                      {outcomeCopy(item.outcome)}
                    </span>
                    <span className="text-xs text-text-tertiary">
                      {completedAt(item.completedAt)}
                    </span>
                  </div>
                  <p className="mt-1 truncate text-sm text-text-primary">{item.repository}</p>
                  <p
                    className="mt-0.5 truncate text-xs text-text-secondary"
                    title={item.clusterIdentity}
                  >
                    {item.namespace}/{item.deployment} · {item.clusterIdentity}
                  </p>
                </div>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  disabled={exporting !== null}
                  onClick={() => void exportReceipt(item.receiptHash)}
                >
                  {exporting === item.receiptHash ? (
                    <LoaderCircle aria-hidden="true" className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Download aria-hidden="true" className="h-3.5 w-3.5" />
                  )}
                  {exported === item.receiptHash ? 'Saved' : 'Export'}
                </Button>
              </article>
            ))}
          </div>
        )}

        {error && items.length > 0 ? (
          <p role="alert" className="text-sm text-text-danger">
            {error}
          </p>
        ) : null}
        <p className="text-xs leading-relaxed text-text-tertiary">
          Exports include the receipt and public verification keys. Key ownership depends on your
          organization&apos;s enrollment process.
        </p>
      </DialogContent>
    </Dialog>
  );
}
