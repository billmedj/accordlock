import { describe, expect, it } from 'vitest';
import { RequestError } from '@agentclientprotocol/sdk';
import {
  ACP_REQUEST_FAILED_MESSAGE,
  formatAcpError,
  parseAcpCreditsExhaustedError,
} from '../errors';

describe('formatAcpError', () => {
  it('explains how to recover from an authentication error', () => {
    expect(formatAcpError(RequestError.authRequired())).toBe(
      'Sign in to your provider, then try again.'
    );
  });

  it('does not expose raw provider details', () => {
    const privateDetails =
      'HTTP 500 from https://private-provider.example/v1?api_key=secret payload={token:secret}';

    const message = formatAcpError({
      error: {
        message: privateDetails,
        data: privateDetails,
      },
    });

    expect(message).toBe(ACP_REQUEST_FAILED_MESSAGE);
    expect(message).not.toContain('private-provider.example');
    expect(message).not.toContain('payload');
  });
});

describe('parseAcpCreditsExhaustedError', () => {
  it('parses structured ACP credits exhausted errors', () => {
    expect(
      parseAcpCreditsExhaustedError({
        code: -32603,
        message: 'Please add credits to your account, then resend your message to continue.',
        data: {
          reason: 'credits_exhausted',
          url: 'https://router.tetrate.ai/billing',
        },
      })
    ).toEqual({
      message:
        'This provider account has no available credits. Add credits with the provider, then try again.',
      url: 'https://router.tetrate.ai/billing',
    });
  });

  it('parses wrapped JSON-RPC errors', () => {
    expect(
      parseAcpCreditsExhaustedError({
        error: {
          code: -32603,
          message: 'Add credits to continue.',
          data: {
            reason: 'credits_exhausted',
          },
        },
      })
    ).toEqual({
      message:
        'This provider account has no available credits. Add credits with the provider, then try again.',
    });
  });

  it('does not expose raw credits error details', () => {
    const privateDetails =
      'Billing failed at https://private-provider.example/billing payload={token:secret}';

    const parsed = parseAcpCreditsExhaustedError({
      code: -32603,
      message: privateDetails,
      data: {
        reason: 'credits_exhausted',
      },
    });

    expect(parsed?.message).not.toContain(privateDetails);
    expect(parsed?.message).not.toContain('private-provider.example');
  });

  it('ignores non-credits-exhausted errors', () => {
    expect(
      parseAcpCreditsExhaustedError({
        code: -32603,
        message: 'Something failed.',
        data: {
          reason: 'provider_error',
        },
      })
    ).toBeNull();
  });
});
