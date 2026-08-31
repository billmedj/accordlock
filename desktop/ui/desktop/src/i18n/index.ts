// Modified by AccordLock contributors; see UPSTREAM.md.
/** English-only react-intl configuration for the desktop renderer. */

import sourceCatalog from './messages/en.json';

export { defineMessages, useIntl } from 'react-intl';

/** en-US is the fixed display and formatting locale. */
export const currentLocale = 'en-US';

/** English source strings remain in defaultMessage and en.json. */
export const currentMessageLocale = 'en';

type SourceMessage = { defaultMessage: string };

const englishMessages = Object.fromEntries(
  Object.entries(sourceCatalog).map(([id, descriptor]) => [
    id,
    (descriptor as SourceMessage).defaultMessage,
  ])
);

/**
 * Load the extracted English catalog so react-intl can resolve message IDs without
 * logging MISSING_TRANSLATION errors. Components keep defaultMessage as a safe fallback.
 */
export async function loadMessages(
  _locale: string = currentMessageLocale
): Promise<Record<string, string>> {
  return englishMessages;
}
