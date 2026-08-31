// Modified by AccordLock contributors; see UPSTREAM.md.
import { DictationSettings } from '../dictation/DictationSettings';
import { ResponseStylesSection } from '../response_styles/ResponseStylesSection';
import { GoosehintsSection } from './GoosehintsSection';
import { SpellcheckToggle } from './SpellcheckToggle';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../ui/card';
import { defineMessages, useIntl } from '../../../i18n';

const i18n = defineMessages({
  inputTitle: {
    id: 'chatSettings.inputTitle',
    defaultMessage: 'Input',
  },
  inputDescription: {
    id: 'chatSettings.inputDescription',
    defaultMessage: 'Choose how you speak and type task instructions.',
  },
  responseStylesTitle: {
    id: 'chatSettings.responseStylesTitle',
    defaultMessage: 'Responses',
  },
  responseStylesDescription: {
    id: 'chatSettings.responseStylesDescription',
    defaultMessage: 'Choose how much action detail AccordLock shows.',
  },
});

export default function ChatSettingsSection() {
  const intl = useIntl();

  return (
    <div className="space-y-4 pr-4 pb-8 mt-1">
      <Card className="pb-2 rounded-lg">
        <CardContent className="px-2">
          <GoosehintsSection />
        </CardContent>
      </Card>

      <Card className="pb-2 rounded-lg">
        <CardHeader className="pb-0">
          <CardTitle>
            <h2>{intl.formatMessage(i18n.inputTitle)}</h2>
          </CardTitle>
          <CardDescription>{intl.formatMessage(i18n.inputDescription)}</CardDescription>
        </CardHeader>
        <CardContent className="px-2">
          <DictationSettings />
          <SpellcheckToggle />
        </CardContent>
      </Card>

      <Card className="pb-2 rounded-lg">
        <CardHeader className="pb-0">
          <CardTitle>
            <h2>{intl.formatMessage(i18n.responseStylesTitle)}</h2>
          </CardTitle>
          <CardDescription>{intl.formatMessage(i18n.responseStylesDescription)}</CardDescription>
        </CardHeader>
        <CardContent className="px-2">
          <ResponseStylesSection />
        </CardContent>
      </Card>
    </div>
  );
}
