import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  embeddedPreflightBinarySha256,
  embeddedPreflightProtocolVersion,
  isEmbeddedAccordLockDevelopmentPackage,
} from './accordlockEmbeddedIntegrity';

describe('embedded AccordLock build identity', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('defaults to release-safe behavior when no development flag is embedded', () => {
    expect(isEmbeddedAccordLockDevelopmentPackage()).toBe(false);
  });

  it('recognizes an explicit compile-time development package flag', () => {
    vi.stubGlobal('__ACCORDLOCK_DEVELOPMENT_PACKAGE__', true);

    expect(isEmbeddedAccordLockDevelopmentPackage()).toBe(true);
  });

  it('does not accept truthy non-boolean values', () => {
    vi.stubGlobal('__ACCORDLOCK_DEVELOPMENT_PACKAGE__', 'true');

    expect(isEmbeddedAccordLockDevelopmentPackage()).toBe(false);
  });

  it('accepts only canonical preflight build identity values', () => {
    vi.stubGlobal('__ACCORDLOCK_PREFLIGHT_BINARY_SHA256__', `sha256:${'a'.repeat(64)}`);
    vi.stubGlobal('__ACCORDLOCK_PREFLIGHT_PROTOCOL_VERSION__', 1);

    expect(embeddedPreflightBinarySha256()).toBe(`sha256:${'a'.repeat(64)}`);
    expect(embeddedPreflightProtocolVersion()).toBe(1);

    vi.stubGlobal('__ACCORDLOCK_PREFLIGHT_BINARY_SHA256__', 'a'.repeat(64));
    vi.stubGlobal('__ACCORDLOCK_PREFLIGHT_PROTOCOL_VERSION__', 1.5);
    expect(embeddedPreflightBinarySha256()).toBeUndefined();
    expect(embeddedPreflightProtocolVersion()).toBeUndefined();
  });
});
