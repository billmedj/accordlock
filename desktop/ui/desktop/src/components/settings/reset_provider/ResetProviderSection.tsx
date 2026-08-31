import { Button } from '../../ui/button';
import { RefreshCw } from 'lucide-react';
import { acpClearDefaults } from '../../../acp/providers';
import { View, ViewOptions } from '../../../utils/navigationUtils';
import { defineMessages, useIntl } from '../../../i18n';

const i18n = defineMessages({
  resetButton: {
    id: 'resetProviderSection.resetButton',
    defaultMessage: 'Clear selection',
  },
});

interface ResetProviderSectionProps {
  setView: (view: View, viewOptions?: ViewOptions) => void;
}

export default function ResetProviderSection(_props: ResetProviderSectionProps) {
  const intl = useIntl();

  const handleResetProvider = async () => {
    try {
      await acpClearDefaults();

      window.electron.reloadApp();
    } catch (error) {
      console.error('Failed to reset provider and model:', error);
    }
  };

  return (
    <div className="p-2">
      <Button
        onClick={handleResetProvider}
        variant="destructive"
        className="flex items-center justify-center gap-2"
      >
        <RefreshCw className="h-4 w-4" />
        {intl.formatMessage(i18n.resetButton)}
      </Button>
    </div>
  );
}
