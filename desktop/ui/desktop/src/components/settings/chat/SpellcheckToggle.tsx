// Modified by AccordLock contributors; see UPSTREAM.md.
import { useState, useEffect } from 'react';
import { Switch } from '../../ui/switch';
import { defineMessages, useIntl } from '../../../i18n';

const i18n = defineMessages({
  title: {
    id: 'spellcheckToggle.title',
    defaultMessage: 'Spell check',
  },
  description: {
    id: 'spellcheckToggle.description',
    defaultMessage: 'Check spelling while you type. Restart AccordLock to apply this change.',
  },
});

export const SpellcheckToggle = () => {
  const intl = useIntl();
  const [enabled, setEnabled] = useState(true);

  useEffect(() => {
    const loadState = async () => {
      const state = await window.electron.getSpellcheckState();
      setEnabled(state);
    };
    loadState();
  }, []);

  const handleToggle = async (checked: boolean) => {
    setEnabled(checked);
    await window.electron.setSpellcheck(checked);
  };

  return (
    <div className="flex items-center justify-between py-2 px-2 hover:bg-background-secondary rounded-lg transition-all">
      <div>
        <h3 className="text-text-primary">{intl.formatMessage(i18n.title)}</h3>
        <p className="text-xs text-text-secondary max-w-md mt-[2px]">
          {intl.formatMessage(i18n.description)}
        </p>
      </div>
      <div className="flex items-center">
        <Switch checked={enabled} onCheckedChange={handleToggle} variant="mono" />
      </div>
    </div>
  );
};
