// Modified by AccordLock contributors; see UPSTREAM.md.
import { EventEmitter } from 'node:events';
import { describe, expect, it, vi } from 'vitest';
import type { GooseServeResult, Logger } from './gooseServe';
import {
  GOOSE_SERVE_EXITED_USER_MESSAGE,
  GooseServeLeaseRegistry,
} from './gooseServeLeaseRegistry';

function createLogger(): Logger {
  return {
    info: vi.fn(),
    error: vi.fn(),
  };
}

function createStore(
  logger = createLogger(),
  onUnexpectedExit: ConstructorParameters<typeof GooseServeLeaseRegistry>[1] = vi.fn()
) {
  return new GooseServeLeaseRegistry(logger, onUnexpectedExit);
}

function createGooseServeResult(
  overrides: Partial<Pick<GooseServeResult, 'cleanup' | 'hasExited' | 'getExitDetails'>> = {}
): GooseServeResult {
  return {
    acpUrl: 'ws://127.0.0.1:1234/acp?token=test',
    workingDir: '/tmp',
    process: new EventEmitter() as GooseServeResult['process'],
    errorLog: [],
    certFingerprint: null,
    cleanup: vi.fn(async () => undefined),
    hasExited: () => false,
    getExitDetails: () => ({ code: null, signal: null }),
    startupDiagnosticsPath: null,
    getStartupDiagnostics: () => null,
    recordStartupEvent: () => undefined,
    ...overrides,
  };
}

describe('GooseServeLeaseRegistry', () => {
  it('returns the ACP URL for an attached live lease', () => {
    const store = createStore();
    const lease = store.create(createGooseServeResult(), 'local-secret');

    store.attachWindow(1, lease);

    expect(store.getAcpUrl(1)).toBe('ws://127.0.0.1:1234/acp?token=test');
    expect(store.getSecretKey(1)).toBe('local-secret');
  });

  it('throws a recovery message after the process exits', () => {
    const logger = createLogger();
    const onUnexpectedExit = vi.fn();
    const store = createStore(logger, onUnexpectedExit);
    const result = createGooseServeResult();
    const lease = store.create(result, 'local-secret');
    store.attachWindow(1, lease);

    result.process.emit('exit', 1, null);

    expect(() => store.getAcpUrl(1)).toThrow(GOOSE_SERVE_EXITED_USER_MESSAGE);
    expect(() => store.getSecretKey(1)).toThrow(GOOSE_SERVE_EXITED_USER_MESSAGE);
    expect(GOOSE_SERVE_EXITED_USER_MESSAGE).toContain('restart AccordLock');
    expect(GOOSE_SERVE_EXITED_USER_MESSAGE).not.toContain('Goose Desktop');
    expect(logger.error).toHaveBeenCalledWith(
      'Goose ACP server exited unexpectedly',
      expect.objectContaining({ code: 1, signal: null, windowIds: [1] })
    );
    expect(onUnexpectedExit).toHaveBeenCalledWith(lease, [1]);
  });

  it('uses the current child exit state when creating the lease', () => {
    const onUnexpectedExit = vi.fn();
    const store = createStore(createLogger(), onUnexpectedExit);
    const lease = store.create(
      createGooseServeResult({
        hasExited: () => true,
        getExitDetails: () => ({ code: null, signal: 'SIGTERM' }),
      }),
      'local-secret'
    );

    store.attachWindow(1, lease);

    expect(() => store.getAcpUrl(1)).toThrow(GOOSE_SERVE_EXITED_USER_MESSAGE);
    expect(onUnexpectedExit).toHaveBeenCalledWith(lease, [1]);
  });

  it('cleans up once after the last attached window is released', async () => {
    const cleanup = vi.fn(async () => undefined);
    const store = createStore();
    const lease = store.create(createGooseServeResult({ cleanup }), 'local-secret');
    store.attachWindow(1, lease);
    store.attachWindow(2, lease);

    await store.releaseWindow(1);
    expect(cleanup).not.toHaveBeenCalled();
    expect(store.getAcpUrl(2)).toBe('ws://127.0.0.1:1234/acp?token=test');
    expect(store.getSecretKey(2)).toBe('local-secret');

    await store.releaseWindow(2);
    expect(cleanup).toHaveBeenCalledTimes(1);
    expect(store.getAcpUrl(2)).toBeNull();
    expect(store.getSecretKey(2)).toBeNull();
  });

  it('creates an external ACP lease without process cleanup', async () => {
    const store = createStore();
    const lease = store.createExternal('wss://example.com/goose/acp?token=test', 'external-secret');

    store.attachWindow(1, lease);

    expect(store.getAcpUrl(1)).toBe('wss://example.com/goose/acp?token=test');
    expect(store.getSecretKey(1)).toBe('external-secret');

    await store.releaseWindow(1);
    expect(store.getAcpUrl(1)).toBeNull();
    expect(store.getSecretKey(1)).toBeNull();
  });

  it('cleans up external leases after the last attached window is released', async () => {
    const cleanup = vi.fn(async () => undefined);
    const store = createStore();
    const lease = store.createExternal(
      'wss://example.com/goose/acp?token=test',
      'external-secret',
      cleanup
    );
    store.attachWindow(1, lease);
    store.attachWindow(2, lease);

    await store.releaseWindow(1);
    expect(cleanup).not.toHaveBeenCalled();

    await store.releaseWindow(2);
    expect(cleanup).toHaveBeenCalledTimes(1);
  });
});
