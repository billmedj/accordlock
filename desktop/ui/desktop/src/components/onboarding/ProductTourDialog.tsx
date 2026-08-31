import { useEffect, useState } from 'react';
import { ArrowLeft, Check, Eye, LockKeyhole, RotateCcw } from 'lucide-react';
import { defineMessages, useIntl } from '../../i18n';
import { AccordLockGlyph } from '../accordlock/AccordLockBrand';
import { Button } from '../ui/button';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '../ui/dialog';

const i18n = defineMessages({
  eyebrow: {
    id: 'productTour.eyebrow',
    defaultMessage: 'Product tour',
  },
  title: {
    id: 'productTour.title',
    defaultMessage: 'Try the approval flow',
  },
  description: {
    id: 'productTour.description',
    defaultMessage: 'Preview how AccordLock handles a file change.',
  },
  disclaimer: {
    id: 'productTour.disclaimer',
    defaultMessage: "This demo doesn't use a model or touch your files.",
  },
  taskBoundaryTitle: {
    id: 'productTour.taskBoundaryTitle',
    defaultMessage: 'Task access',
  },
  goalLabel: {
    id: 'productTour.goalLabel',
    defaultMessage: 'Outcome',
  },
  goal: {
    id: 'productTour.goal',
    defaultMessage: 'Prepare the README release note for review.',
  },
  folderLabel: {
    id: 'productTour.folderLabel',
    defaultMessage: 'Folder',
  },
  folderValue: {
    id: 'productTour.folderValue',
    defaultMessage: 'Selected folder',
  },
  taskBoundary: {
    id: 'productTour.taskBoundary',
    defaultMessage: 'Can read files in this folder. Asks before changes and commands.',
  },
  exactWriteTitle: {
    id: 'productTour.exactWriteTitle',
    defaultMessage: 'Proposed change',
  },
  fileLabel: {
    id: 'productTour.fileLabel',
    defaultMessage: 'File',
  },
  changeLabel: {
    id: 'productTour.changeLabel',
    defaultMessage: 'Change',
  },
  changeValue: {
    id: 'productTour.changeValue',
    defaultMessage: 'Insert one heading and one status line',
  },
  allowOnce: {
    id: 'productTour.allowOnce',
    defaultMessage: 'Approve once',
  },
  keepLocked: {
    id: 'productTour.keepLocked',
    defaultMessage: 'Keep locked',
  },
  resultTitle: {
    id: 'productTour.resultTitle',
    defaultMessage: 'Decision',
  },
  waitingDecision: {
    id: 'productTour.waitingDecision',
    defaultMessage: 'Choose whether this change can run.',
  },
  allowedDecision: {
    id: 'productTour.allowedDecision',
    defaultMessage: 'Approved once',
  },
  lockedDecision: {
    id: 'productTour.lockedDecision',
    defaultMessage: 'Kept locked',
  },
  allowedExplanation: {
    id: 'productTour.allowedExplanation',
    defaultMessage: 'Only the change shown above can run.',
  },
  lockedExplanation: {
    id: 'productTour.lockedExplanation',
    defaultMessage: 'The proposed change stays blocked.',
  },
  resetDecision: {
    id: 'productTour.resetDecision',
    defaultMessage: 'Reset choice',
  },
  back: {
    id: 'productTour.back',
    defaultMessage: 'Back to provider selection',
  },
});

type TourDecision = 'allowed' | 'locked' | null;

interface ProductTourDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

interface TourStepProps {
  number: number;
  title: React.ReactNode;
  children: React.ReactNode;
  tone?: 'neutral' | 'safe' | 'review';
}

function TourStep({ number, title, children, tone = 'neutral' }: TourStepProps) {
  const toneClass =
    tone === 'safe'
      ? 'border-green-500/25 bg-green-500/[0.04]'
      : tone === 'review'
        ? 'border-amber-500/30 bg-amber-500/[0.05]'
        : 'border-border-default bg-background-muted/55';

  return (
    <li className={`rounded-xl border p-4 ${toneClass}`}>
      <div className="mb-3 flex items-center gap-3">
        <span className="flex size-6 shrink-0 items-center justify-center rounded-full bg-background-inverse text-xs font-semibold text-text-inverse">
          {number}
        </span>
        <h2 className="text-sm font-semibold text-text-default">{title}</h2>
      </div>
      <div className="pl-9">{children}</div>
    </li>
  );
}

export default function ProductTourDialog({ open, onOpenChange }: ProductTourDialogProps) {
  const intl = useIntl();
  const [decision, setDecision] = useState<TourDecision>(null);

  useEffect(() => {
    if (!open) setDecision(null);
  }, [open]);

  const decisionLabel =
    decision === 'allowed'
      ? intl.formatMessage(i18n.allowedDecision)
      : intl.formatMessage(i18n.lockedDecision);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="grid max-h-[calc(100vh-2rem)] grid-rows-[auto_auto_minmax(0,1fr)_auto] gap-0 overflow-hidden p-0 sm:max-w-3xl">
        <DialogHeader className="mb-0 border-b border-border-default px-5 py-5 pr-14 sm:px-7">
          <div className="mb-3 flex items-center gap-3">
            <AccordLockGlyph className="size-8" />
            <span className="text-xs font-semibold uppercase tracking-[0.16em] text-text-muted">
              {intl.formatMessage(i18n.eyebrow)}
            </span>
          </div>
          <DialogTitle className="text-2xl font-light leading-tight tracking-[-0.025em] sm:text-3xl">
            {intl.formatMessage(i18n.title)}
          </DialogTitle>
          <DialogDescription className="pt-2 text-sm leading-6">
            {intl.formatMessage(i18n.description)}
          </DialogDescription>
        </DialogHeader>

        <div
          role="status"
          className="flex items-center gap-2 border-b border-blue-400/25 bg-blue-500/[0.06] px-5 py-2.5 text-xs font-medium text-text-default sm:px-7"
        >
          <Eye aria-hidden="true" className="size-4 shrink-0 text-blue-500" />
          {intl.formatMessage(i18n.disclaimer)}
        </div>

        <div className="overflow-y-auto px-5 py-5 sm:px-7">
          <ol className="space-y-3">
            <TourStep number={1} title={intl.formatMessage(i18n.taskBoundaryTitle)}>
              <dl className="grid gap-3 text-sm sm:grid-cols-2">
                <div>
                  <dt className="text-xs font-medium text-text-muted">
                    {intl.formatMessage(i18n.goalLabel)}
                  </dt>
                  <dd className="mt-1 text-text-default">{intl.formatMessage(i18n.goal)}</dd>
                </div>
                <div>
                  <dt className="text-xs font-medium text-text-muted">
                    {intl.formatMessage(i18n.folderLabel)}
                  </dt>
                  <dd className="mt-1 text-text-default">{intl.formatMessage(i18n.folderValue)}</dd>
                </div>
              </dl>
              <p className="mt-3 border-t border-border-default pt-3 text-sm leading-5 text-text-muted">
                {intl.formatMessage(i18n.taskBoundary)}
              </p>
            </TourStep>

            <TourStep number={2} title={intl.formatMessage(i18n.exactWriteTitle)} tone="review">
              <dl className="grid gap-2 text-xs sm:grid-cols-2">
                <div>
                  <dt className="font-medium text-text-muted">
                    {intl.formatMessage(i18n.fileLabel)}
                  </dt>
                  <dd className="mt-1 font-mono text-text-default">README.md</dd>
                </div>
                <div>
                  <dt className="font-medium text-text-muted">
                    {intl.formatMessage(i18n.changeLabel)}
                  </dt>
                  <dd className="mt-1 text-text-default">{intl.formatMessage(i18n.changeValue)}</dd>
                </div>
              </dl>
              <pre className="mt-3 overflow-x-auto rounded-lg border border-border-default bg-background-default p-3 text-xs leading-5 text-text-default">
                <code>{'+ ## Release candidate\n+ Status: ready for review'}</code>
              </pre>
              <div className="mt-3 flex flex-col gap-2 sm:flex-row">
                <Button
                  type="button"
                  size="sm"
                  aria-pressed={decision === 'allowed'}
                  onClick={() => setDecision('allowed')}
                  className="sm:flex-1"
                >
                  <Check aria-hidden="true" />
                  {intl.formatMessage(i18n.allowOnce)}
                </Button>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  aria-pressed={decision === 'locked'}
                  onClick={() => setDecision('locked')}
                  className="sm:flex-1"
                >
                  <LockKeyhole aria-hidden="true" />
                  {intl.formatMessage(i18n.keepLocked)}
                </Button>
              </div>
            </TourStep>

            <TourStep
              number={3}
              title={intl.formatMessage(i18n.resultTitle)}
              tone={decision === 'allowed' ? 'safe' : 'neutral'}
            >
              {decision ? (
                <div role="status" aria-live="polite">
                  <p className="text-sm font-semibold text-text-default">{decisionLabel}</p>
                  <p className="mt-1 text-sm leading-5 text-text-muted">
                    {intl.formatMessage(
                      decision === 'allowed' ? i18n.allowedExplanation : i18n.lockedExplanation
                    )}
                  </p>
                  <button
                    type="button"
                    onClick={() => setDecision(null)}
                    className="mt-2 inline-flex items-center gap-1 text-xs font-medium text-text-muted underline-offset-4 hover:text-text-default hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
                  >
                    <RotateCcw aria-hidden="true" className="size-3" />
                    {intl.formatMessage(i18n.resetDecision)}
                  </button>
                </div>
              ) : (
                <p className="text-sm leading-5 text-text-muted">
                  {intl.formatMessage(i18n.waitingDecision)}
                </p>
              )}
            </TourStep>
          </ol>
        </div>

        <div className="border-t border-border-default bg-background-muted/40 px-5 py-3 sm:px-7">
          <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
            <ArrowLeft aria-hidden="true" />
            {intl.formatMessage(i18n.back)}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
