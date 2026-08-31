import { describe, expect, it } from 'vitest';
import { getValidatedTopUpUrl } from './CreditsExhaustedNotification';

describe('getValidatedTopUpUrl', () => {
  it('accepts the trusted provider billing page over HTTPS', () => {
    expect(getValidatedTopUpUrl({ top_up_url: 'https://router.tetrate.ai/billing' })).toBe(
      'https://router.tetrate.ai/billing'
    );
  });

  it.each([
    'http://router.tetrate.ai/billing',
    'https://router.tetrate.ai.evil.example/billing',
    'https://evil.example/billing',
    'javascript:alert(1)',
  ])('rejects an untrusted billing URL: %s', (topUpUrl) => {
    expect(getValidatedTopUpUrl({ top_up_url: topUpUrl })).toBeNull();
  });
});
