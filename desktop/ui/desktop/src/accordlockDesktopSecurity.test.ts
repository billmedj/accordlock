import { describe, expect, it } from 'vitest';
import {
  AccordLockNavigationAllowance,
  isAccordLockExternalUrlAllowed,
  isAccordLockUnsafeViewMenuRole,
  shouldGrantAccordLockMicrophoneCheck,
  shouldGrantAccordLockMicrophoneRequest,
  shouldAllowAccordLockExternalBackend,
  shouldEnableAccordLockRemoteDebugging,
} from './accordlockDesktopSecurity';

describe('AccordLock desktop security controls', () => {
  it('enables remote debugging only for an explicit unpackaged test process', () => {
    expect(shouldEnableAccordLockRemoteDebugging(false, '1')).toBe(true);
    expect(shouldEnableAccordLockRemoteDebugging(false, 'true')).toBe(false);
    expect(shouldEnableAccordLockRemoteDebugging(false, undefined)).toBe(false);
    expect(shouldEnableAccordLockRemoteDebugging(true, '1')).toBe(false);
  });

  it('identifies Electron roles that bypass the revocation-aware reload path', () => {
    for (const role of ['reload', 'forceReload', 'toggleDevTools']) {
      expect(isAccordLockUnsafeViewMenuRole(role)).toBe(true);
    }
    expect(isAccordLockUnsafeViewMenuRole('togglefullscreen')).toBe(false);
  });

  it('opens only explicit HTTPS and email destinations outside the sandbox', () => {
    expect(isAccordLockExternalUrlAllowed('https://example.com/support')).toBe(true);
    expect(isAccordLockExternalUrlAllowed('mailto:security@example.com')).toBe(true);
    expect(isAccordLockExternalUrlAllowed('http://example.com')).toBe(false);
    expect(isAccordLockExternalUrlAllowed('file:///etc/passwd')).toBe(false);
    expect(isAccordLockExternalUrlAllowed('custom-scheme://payload')).toBe(false);
    expect(isAccordLockExternalUrlAllowed('not a url')).toBe(false);
  });

  it('consumes exactly one exact post-revocation navigation allowance', () => {
    const allowance = new AccordLockNavigationAllowance();
    allowance.arm(7, 'file:///accordlock/index.html');

    expect(allowance.consume(7, 'file:///accordlock/index.html')).toBe(true);
    expect(allowance.consume(7, 'file:///accordlock/index.html')).toBe(false);

    allowance.arm(7, 'file:///accordlock/index.html');
    expect(allowance.consume(7, 'https://attacker.example')).toBe(false);
    expect(allowance.consume(7, 'file:///accordlock/index.html')).toBe(false);
  });

  it('allows external backends only in explicit development runs', () => {
    expect(shouldAllowAccordLockExternalBackend(false, '1')).toBe(true);
    expect(shouldAllowAccordLockExternalBackend(false, undefined)).toBe(false);
    expect(shouldAllowAccordLockExternalBackend(true, '1')).toBe(false);
  });

  it('grants only a main-frame microphone permission check from the exact renderer', () => {
    const check = {
      permission: 'media',
      currentUrl: 'file:///C:/Program%20Files/AccordLock/index.html#/task/1',
      requestingUrl: 'file:///C:/Program%20Files/AccordLock/index.html#/task/1',
      requestingOrigin: 'file://',
      securityOrigin: 'file://',
      isMainFrame: true,
      mediaType: 'audio',
    };

    expect(shouldGrantAccordLockMicrophoneCheck(check)).toBe(true);
    expect(shouldGrantAccordLockMicrophoneCheck({ ...check, mediaType: 'video' })).toBe(false);
    expect(shouldGrantAccordLockMicrophoneCheck({ ...check, mediaType: 'unknown' })).toBe(false);
    expect(shouldGrantAccordLockMicrophoneCheck({ ...check, isMainFrame: false })).toBe(false);
    expect(
      shouldGrantAccordLockMicrophoneCheck({
        ...check,
        requestingUrl: 'file:///C:/Users/example/untrusted.html',
      })
    ).toBe(false);
  });

  it('grants only an audio-only main-frame microphone request', () => {
    const request = {
      permission: 'media',
      currentUrl: 'http://127.0.0.1:5173/#/task/1',
      requestingUrl: 'http://127.0.0.1:5173/#/task/1',
      securityOrigin: 'http://127.0.0.1:5173',
      isMainFrame: true,
      mediaTypes: ['audio'] as const,
    };

    expect(shouldGrantAccordLockMicrophoneRequest(request)).toBe(true);
    expect(
      shouldGrantAccordLockMicrophoneRequest({ ...request, mediaTypes: ['audio', 'video'] })
    ).toBe(false);
    expect(shouldGrantAccordLockMicrophoneRequest({ ...request, mediaTypes: ['video'] })).toBe(
      false
    );
    expect(shouldGrantAccordLockMicrophoneRequest({ ...request, mediaTypes: undefined })).toBe(
      false
    );
    expect(
      shouldGrantAccordLockMicrophoneRequest({
        ...request,
        requestingUrl: 'http://127.0.0.1:5173/embedded.html',
      })
    ).toBe(false);
  });

  it('rejects malformed, cross-origin, and non-media permission contexts', () => {
    const check = {
      permission: 'media',
      currentUrl: 'https://desktop.accordlock.test/app',
      requestingUrl: 'https://desktop.accordlock.test/app',
      requestingOrigin: 'https://desktop.accordlock.test',
      securityOrigin: 'https://desktop.accordlock.test',
      isMainFrame: true,
      mediaType: 'audio',
    };

    expect(shouldGrantAccordLockMicrophoneCheck({ ...check, permission: 'geolocation' })).toBe(
      false
    );
    expect(
      shouldGrantAccordLockMicrophoneCheck({
        ...check,
        requestingOrigin: 'https://attacker.example',
      })
    ).toBe(false);
    expect(
      shouldGrantAccordLockMicrophoneCheck({
        ...check,
        securityOrigin: 'https://attacker.example',
      })
    ).toBe(false);
    expect(shouldGrantAccordLockMicrophoneCheck({ ...check, requestingUrl: 'not a url' })).toBe(
      false
    );
  });
});
