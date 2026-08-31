import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  clearAccordLockTaskAuthorization,
  getAccordLockTaskAuthorization,
  getAccordLockTaskAuthorizationExpiry,
  setAccordLockTaskAuthorization,
} from './taskAuthorizationStore';

const sessionId = 'authorization-store-session';

describe('taskAuthorizationStore', () => {
  afterEach(() => {
    clearAccordLockTaskAuthorization(sessionId);
    vi.useRealTimers();
  });

  it('treats approved state without a current expiry as locked', () => {
    setAccordLockTaskAuthorization(sessionId, 'APPROVED');

    expect(getAccordLockTaskAuthorization(sessionId)).toBe('REJECTED');
    expect(getAccordLockTaskAuthorizationExpiry(sessionId)).toBeNull();
  });

  it('stops publishing approval at the exact expiry boundary', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-08-24T00:00:00Z'));
    const expiresAt = Math.floor(Date.now() / 1_000) + 60;
    setAccordLockTaskAuthorization(sessionId, 'APPROVED', expiresAt);

    expect(getAccordLockTaskAuthorization(sessionId)).toBe('APPROVED');
    vi.setSystemTime(new Date('2026-08-24T00:01:00Z'));
    expect(getAccordLockTaskAuthorization(sessionId)).toBe('REJECTED');
  });

  it('removes stale expiry metadata when approval is replaced', () => {
    const expiresAt = Math.floor(Date.now() / 1_000) + 60;
    setAccordLockTaskAuthorization(sessionId, 'APPROVED', expiresAt);
    setAccordLockTaskAuthorization(sessionId, 'APPROVED');

    expect(getAccordLockTaskAuthorizationExpiry(sessionId)).toBeNull();
    expect(getAccordLockTaskAuthorization(sessionId)).toBe('REJECTED');
  });
});
