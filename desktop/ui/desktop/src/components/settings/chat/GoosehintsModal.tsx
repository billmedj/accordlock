// Modified by AccordLock contributors; see UPSTREAM.md.
import { useState, useEffect } from 'react';
import { Button } from '../../ui/button';
import { Check } from '../../icons';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../../ui/dialog';
import { defineMessages, useIntl } from '../../../i18n';

const i18n = defineMessages({
  dialogTitle: {
    id: 'goosehintsModal.dialogTitle',
    defaultMessage: 'Folder instructions',
  },
  dialogDescription: {
    id: 'goosehintsModal.dialogDescription',
    defaultMessage: 'Add rules and context for this folder.',
  },
  helpText1: {
    id: 'goosehintsModal.helpText1',
    defaultMessage: 'Saved locally. Applies to new tasks in this folder.',
  },
  errorReading: {
    id: 'goosehintsModal.errorReading',
    defaultMessage: 'Could not load folder instructions: {error}',
  },
  fileFound: {
    id: 'goosehintsModal.fileFound',
    defaultMessage: 'Saved in this folder',
  },
  fileCreating: {
    id: 'goosehintsModal.fileCreating',
    defaultMessage: 'Created when you save.',
  },
  placeholder: {
    id: 'goosehintsModal.placeholder',
    defaultMessage: 'Add rules or context for tasks in this folder…',
  },
  savedSuccessfully: {
    id: 'goosehintsModal.savedSuccessfully',
    defaultMessage: 'Instructions saved',
  },
  close: {
    id: 'goosehintsModal.close',
    defaultMessage: 'Close',
  },
  saving: {
    id: 'goosehintsModal.saving',
    defaultMessage: 'Saving...',
  },
  save: {
    id: 'goosehintsModal.save',
    defaultMessage: 'Save',
  },
  failedToAccess: {
    id: 'goosehintsModal.failedToAccess',
    defaultMessage: 'Could not load folder instructions',
  },
  failedToSave: {
    id: 'goosehintsModal.failedToSave',
    defaultMessage: 'Could not save folder instructions',
  },
});

const HelpText = () => {
  const intl = useIntl();

  return (
    <div className="text-sm text-text-secondary">
      <p>{intl.formatMessage(i18n.helpText1)}</p>
    </div>
  );
};

const ErrorDisplay = ({ message }: { message: string }) => {
  return (
    <div className="text-sm text-text-secondary">
      <div className="text-red-600">{message}</div>
    </div>
  );
};

const FileInfo = ({ found }: { found: boolean }) => {
  const intl = useIntl();

  return (
    <div className="text-sm font-medium mb-2">
      {found ? (
        <div className="text-green-600">
          <Check className="w-4 h-4 inline-block" /> {intl.formatMessage(i18n.fileFound)}
        </div>
      ) : (
        <div>{intl.formatMessage(i18n.fileCreating)}</div>
      )}
    </div>
  );
};

interface GoosehintsModalProps {
  directory: string;
  setIsGoosehintsModalOpen: (isOpen: boolean) => void;
}

export const GoosehintsModal = ({ directory, setIsGoosehintsModalOpen }: GoosehintsModalProps) => {
  const intl = useIntl();
  const [goosehintsFile, setGoosehintsFile] = useState<string>('');
  const [goosehintsFileFound, setGoosehintsFileFound] = useState<boolean>(false);
  const [goosehintsFileReadError, setGoosehintsFileReadError] = useState<string>('');
  const [isSaving, setIsSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  useEffect(() => {
    const fetchGoosehintsFile = async () => {
      try {
        const { file, error, found } = await window.electron.readGoosehints();
        setGoosehintsFile(file);
        setGoosehintsFileFound(found);
        if (error) {
          console.error('Project instruction file could not be read:', error);
          setGoosehintsFileReadError(intl.formatMessage(i18n.failedToAccess));
        } else {
          setGoosehintsFileReadError('');
        }
      } catch (error) {
        console.error('Error fetching .goosehints file:', error);
        setGoosehintsFileReadError(intl.formatMessage(i18n.failedToAccess));
      }
    };
    if (directory) fetchGoosehintsFile();
  }, [directory, intl]);

  const writeFile = async () => {
    setIsSaving(true);
    setSaveSuccess(false);
    try {
      const saved = await window.electron.writeGoosehints(goosehintsFile);
      if (!saved) {
        throw new Error('Unable to save .goosehints');
      }
      setSaveSuccess(true);
      setGoosehintsFileFound(true);
      setTimeout(() => setSaveSuccess(false), 3000);
    } catch (error) {
      console.error('Error writing .goosehints file:', error);
      setGoosehintsFileReadError(intl.formatMessage(i18n.failedToSave));
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <Dialog open={true} onOpenChange={(open) => setIsGoosehintsModalOpen(open)}>
      <DialogContent className="flex max-h-[min(720px,calc(100vh-32px))] w-[min(600px,calc(100vw-32px))] max-w-none flex-col sm:max-w-none">
        <DialogHeader>
          <DialogTitle>{intl.formatMessage(i18n.dialogTitle)}</DialogTitle>
          <DialogDescription>{intl.formatMessage(i18n.dialogDescription)}</DialogDescription>
        </DialogHeader>

        <div className="flex-1 overflow-y-auto space-y-4 pt-2 pb-4">
          <HelpText />

          <div>
            {goosehintsFileReadError ? (
              <ErrorDisplay message={goosehintsFileReadError} />
            ) : (
              <div className="space-y-2">
                <FileInfo found={goosehintsFileFound} />
                <textarea
                  value={goosehintsFile}
                  className="h-64 w-full resize-none rounded-xl border border-border-primary bg-background-primary p-3 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-ring"
                  onChange={(event) => setGoosehintsFile(event.target.value)}
                  placeholder={intl.formatMessage(i18n.placeholder)}
                />
              </div>
            )}
          </div>
        </div>

        <DialogFooter>
          {saveSuccess && (
            <span className="text-green-600 text-sm flex items-center gap-1 mr-auto">
              <Check className="w-4 h-4" />
              {intl.formatMessage(i18n.savedSuccessfully)}
            </span>
          )}
          <Button variant="outline" onClick={() => setIsGoosehintsModalOpen(false)}>
            {intl.formatMessage(i18n.close)}
          </Button>
          <Button onClick={writeFile} disabled={isSaving}>
            {isSaving ? intl.formatMessage(i18n.saving) : intl.formatMessage(i18n.save)}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};
