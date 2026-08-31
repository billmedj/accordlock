// Modified by AccordLock contributors; see UPSTREAM.md.
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../ui/dialog';
import { defineMessages, useIntl } from '../../i18n';

const i18n = defineMessages({
  title: {
    id: 'privacyInfoModal.title',
    defaultMessage: 'Privacy details',
  },
  description: {
    id: 'privacyInfoModal.description',
    defaultMessage: 'Product analytics are disabled in this release.',
  },
  whatWeCollect: {
    id: 'privacyInfoModal.whatWeCollect',
    defaultMessage: 'If enabled in a future release, analytics may include:',
  },
  collectOs: {
    id: 'privacyInfoModal.collectOs',
    defaultMessage: 'Operating system, version, and architecture',
  },
  collectVersion: {
    id: 'privacyInfoModal.collectVersion',
    defaultMessage: 'AccordLock version and install method',
  },
  collectProvider: {
    id: 'privacyInfoModal.collectProvider',
    defaultMessage: 'Provider and model used',
  },
  collectExtensions: {
    id: 'privacyInfoModal.collectExtensions',
    defaultMessage: 'Built-in extensions and action counts',
  },
  collectSession: {
    id: 'privacyInfoModal.collectSession',
    defaultMessage: 'Task duration, interaction count, and token usage',
  },
  collectErrors: {
    id: 'privacyInfoModal.collectErrors',
    defaultMessage: 'Error categories, such as rate limits or sign-in failures',
  },
  neverCollect: {
    id: 'privacyInfoModal.neverCollect',
    defaultMessage:
      'No product analytics are sent by this release. Future analytics will require opt-in consent and a published data policy.',
  },
});

interface PrivacyInfoModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function PrivacyInfoModal({ isOpen, onClose }: PrivacyInfoModalProps) {
  const intl = useIntl();

  return (
    <Dialog open={isOpen} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="w-[440px]">
        <DialogHeader>
          <DialogTitle className="text-center">{intl.formatMessage(i18n.title)}</DialogTitle>
        </DialogHeader>

        <div>
          <p className="text-text-muted text-sm mb-3">{intl.formatMessage(i18n.description)}</p>
          <p className="font-medium text-text-default text-sm mb-1.5">
            {intl.formatMessage(i18n.whatWeCollect)}
          </p>
          <ul className="text-text-muted text-sm list-disc list-outside space-y-0.5 ml-5 mb-3">
            <li>{intl.formatMessage(i18n.collectOs)}</li>
            <li>{intl.formatMessage(i18n.collectVersion)}</li>
            <li>{intl.formatMessage(i18n.collectProvider)}</li>
            <li>{intl.formatMessage(i18n.collectExtensions)}</li>
            <li>{intl.formatMessage(i18n.collectSession)}</li>
            <li>{intl.formatMessage(i18n.collectErrors)}</li>
          </ul>
          <p className="text-text-muted text-sm">{intl.formatMessage(i18n.neverCollect)}</p>
        </div>
      </DialogContent>
    </Dialog>
  );
}
