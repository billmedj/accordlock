// Modified by AccordLock contributors; see UPSTREAM.md.
import { describe, expect, it } from 'vitest';
import { currentLocale, currentMessageLocale, loadMessages } from './index';

describe('English-only locale configuration', () => {
  it('always uses the en-US display locale and English source messages', () => {
    expect(currentLocale).toBe('en-US');
    expect(currentMessageLocale).toBe('en');
  });

  it('loads the English catalog used by the first-render safety states', async () => {
    await expect(loadMessages()).resolves.toMatchObject({
      'accordLock.taskAuthorization.protocolTitle': 'Task blocked',
      'accordLock.taskAuthorization.protocolDescription':
        'AccordLock could not verify this task. No actions can run. Restart AccordLock and try again.',
      'accordLock.taskAuthorization.keepLocked': 'Close',
      'onboardingGuard.preparingTitle': 'Checking setup',
      'onboardingGuard.preparingDescription': 'Verifying your model connection…',
      'errorBoundary.reload': 'Reload',
    });
  });
});
