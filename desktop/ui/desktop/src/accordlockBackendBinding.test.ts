import { describe, expect, it } from 'vitest';
import {
  ACCORDLOCK_BACKEND_BINDING_DOMAIN,
  assertAccordLockBackendBindingSecret,
  deriveAccordLockBackendRunId,
  generateAccordLockBackendBindingSecret,
} from './accordlockBackendBinding';

const ZERO_SECRET = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

describe('AccordLock backend binding', () => {
  it('matches the cross-language HMAC-SHA256 test vector', () => {
    expect(ACCORDLOCK_BACKEND_BINDING_DOMAIN).toBe('accordlock.backend-run/v1');
    expect(deriveAccordLockBackendRunId(ZERO_SECRET, 'session-alpha')).toBe(
      'sha256:25afda2a41396a99b76fc018ceae13ee86304c4e235c798c3d87478c3b8f13ad'
    );
  });

  it('generates a fresh canonical 32-byte secret', () => {
    const first = generateAccordLockBackendBindingSecret();
    const second = generateAccordLockBackendBindingSecret();

    expect(first).not.toBe(second);
    expect(Buffer.from(first, 'base64url')).toHaveLength(32);
    expect(first).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(() => assertAccordLockBackendBindingSecret(first)).not.toThrow();
  });

  it('binds both the backend secret and exact session bytes', () => {
    const otherSecret = Buffer.alloc(32, 1).toString('base64url');

    expect(deriveAccordLockBackendRunId(ZERO_SECRET, 'session-alpha')).not.toBe(
      deriveAccordLockBackendRunId(otherSecret, 'session-alpha')
    );
    expect(deriveAccordLockBackendRunId(ZERO_SECRET, 'session-alpha')).not.toBe(
      deriveAccordLockBackendRunId(ZERO_SECRET, 'session-beta')
    );
  });

  it.each(['', 'short', `${ZERO_SECRET}=`, ZERO_SECRET.slice(0, -1) + '+', 'A'.repeat(44)])(
    'rejects a malformed secret without echoing it: %s',
    (secret) => {
      expect(() => deriveAccordLockBackendRunId(secret, 'session-alpha')).toThrow(
        'AccordLock backend binding secret is invalid'
      );
    }
  );

  it.each(['', 'line\nbreak', `oversized-${'x'.repeat(504)}`])(
    'rejects an invalid session identifier',
    (sessionId) => {
      expect(() => deriveAccordLockBackendRunId(ZERO_SECRET, sessionId)).toThrow(
        'AccordLock session identifier is invalid'
      );
    }
  );
});
