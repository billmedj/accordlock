// Modified by AccordLock contributors; see UPSTREAM.md.
import { describe, expect, it } from 'vitest';
import { errorMessage, GENERIC_USER_FACING_ERROR, userFacingErrorMessage } from './conversionUtils';

describe('errorMessage', () => {
  it('prefers ACP JSON-RPC error data over generic messages', () => {
    expect(
      errorMessage({
        error: {
          message: 'Invalid params',
          data: 'MLX backend error: failed to load model',
        },
      })
    ).toBe('MLX backend error: failed to load model');
  });

  it('prefers ACP JSON-RPC error data from Error instances', () => {
    const error = Object.assign(new Error('Invalid params'), {
      error: {
        message: 'Invalid params',
        data: 'MLX backend error: failed to load model',
      },
    });

    expect(errorMessage(error)).toBe('MLX backend error: failed to load model');
  });
});

describe('userFacingErrorMessage', () => {
  const privateDetails =
    'HTTP 500 from https://private-provider.example/v1?api_key=secret payload={token:secret}';

  it('does not reflect Error details into UI copy', () => {
    const message = userFacingErrorMessage(new Error(privateDetails));

    expect(message).toBe(GENERIC_USER_FACING_ERROR);
    expect(message).not.toContain('private-provider.example');
    expect(message).not.toContain('payload');
  });

  it('does not reflect ACP data into contextual UI copy', () => {
    const message = userFacingErrorMessage(
      {
        error: {
          message: 'Request failed',
          data: privateDetails,
        },
      },
      'The request could not be completed. Try again.'
    );

    expect(message).toBe('The request could not be completed. Try again.');
    expect(message).not.toContain(privateDetails);
  });

  it('falls back safely when contextual copy is blank', () => {
    expect(userFacingErrorMessage(privateDetails, '   ')).toBe(GENERIC_USER_FACING_ERROR);
  });
});
