// Modified by AccordLock contributors; see UPSTREAM.md.
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  buildGooseServeEnv,
  buildLocalServeUrls,
  findGooseBinaryPath,
  startGooseServe,
} from './gooseServe';

const ZERO_BINDING_SECRET = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

const binaryName = process.platform === 'win32' ? 'goose.exe' : 'goose';
const tempDirs: string[] = [];
type ReadinessFetchInit = Parameters<typeof globalThis.fetch>[1];

function makeTempDir(): string {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'goose-serve-test-'));
  tempDirs.push(tempDir);
  return tempDir;
}

function makeFile(filePath: string): string {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, '');
  fs.chmodSync(filePath, 0o755);
  return filePath;
}

function makeExecutable(filePath: string, contents: string): string {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, contents);
  fs.chmodSync(filePath, 0o755);
  return filePath;
}

async function waitForFileLines(filePath: string): Promise<string[]> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (fs.existsSync(filePath)) {
      return fs.readFileSync(filePath, 'utf8').trim().split('\n');
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`Timed out waiting for ${filePath}`);
}

describe('findGooseBinaryPath', () => {
  afterEach(() => {
    vi.unstubAllEnvs();

    while (tempDirs.length > 0) {
      const tempDir = tempDirs.pop();
      if (tempDir) {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    }
  });

  it('uses GOOSE_BINARY in development builds', () => {
    const tempDir = makeTempDir();
    const overridePath = makeFile(path.join(tempDir, 'override-goose'));
    vi.stubEnv('GOOSE_BINARY', overridePath);

    expect(findGooseBinaryPath({ isPackaged: false })).toBe(overridePath);
  });

  it('rejects GOOSE_BINARY in packaged builds', () => {
    const tempDir = makeTempDir();
    const resourcesPath = path.join(tempDir, 'resources');
    const overridePath = makeFile(path.join(tempDir, 'override-goose'));
    makeFile(path.join(resourcesPath, 'bin', binaryName));
    vi.stubEnv('GOOSE_BINARY', overridePath);

    expect(() => findGooseBinaryPath({ isPackaged: true, resourcesPath })).toThrow(
      'GOOSE_BINARY is only supported in development builds'
    );
  });

  it('prefers the staged binary over target builds in development builds', () => {
    const tempDir = makeTempDir();
    const desktopDir = path.join(tempDir, 'ui', 'desktop');
    const stagedPath = makeFile(path.join(desktopDir, 'src', 'bin', binaryName));
    const debugPath = makeFile(path.join(tempDir, 'target', 'debug', binaryName));
    const releasePath = makeFile(path.join(tempDir, 'target', 'release', binaryName));
    const resolvedPath = findGooseBinaryPath({ isPackaged: false, cwd: desktopDir });
    expect(fs.realpathSync(resolvedPath)).toBe(fs.realpathSync(stagedPath));
    expect(fs.realpathSync(resolvedPath)).not.toBe(fs.realpathSync(releasePath));
    expect(fs.realpathSync(resolvedPath)).not.toBe(fs.realpathSync(debugPath));
  });

  it('uses the bundled goose binary in packaged builds', () => {
    const tempDir = makeTempDir();
    const resourcesPath = path.join(tempDir, 'resources');
    const bundledPath = makeFile(path.join(resourcesPath, 'bin', binaryName));

    const expectedBinarySha256 = createHash('sha256')
      .update(fs.readFileSync(bundledPath))
      .digest('hex');
    expect(findGooseBinaryPath({ isPackaged: true, resourcesPath, expectedBinarySha256 })).toBe(
      bundledPath
    );
  });

  it('rejects a packaged backend that is not anchored to the application bundle', () => {
    const tempDir = makeTempDir();
    const resourcesPath = path.join(tempDir, 'resources');
    makeFile(path.join(resourcesPath, 'bin', binaryName));

    expect(() => findGooseBinaryPath({ isPackaged: true, resourcesPath })).toThrow(
      'Embedded AccordLock backend digest is missing'
    );
    expect(() =>
      findGooseBinaryPath({
        isPackaged: true,
        resourcesPath,
        expectedBinarySha256: 'f'.repeat(64),
      })
    ).toThrow('AccordLock backend digest mismatch');
  });
});

describe('buildLocalServeUrls', () => {
  it('builds HTTP and WS URLs', () => {
    expect(buildLocalServeUrls(1234, 'secret', 'http')).toEqual({
      httpBaseUrl: 'http://127.0.0.1:1234',
      statusUrl: 'http://127.0.0.1:1234/status',
      healthUrl: 'http://127.0.0.1:1234/health',
      acpUrl: 'ws://127.0.0.1:1234/acp?token=secret',
      redactedAcpUrl: 'ws://127.0.0.1:1234/acp?token=REDACTED',
    });
  });

  it('builds HTTPS and WSS URLs', () => {
    expect(buildLocalServeUrls(1234, 'secret', 'https')).toEqual({
      httpBaseUrl: 'https://127.0.0.1:1234',
      statusUrl: 'https://127.0.0.1:1234/status',
      healthUrl: 'https://127.0.0.1:1234/health',
      acpUrl: 'wss://127.0.0.1:1234/acp?token=secret',
      redactedAcpUrl: 'wss://127.0.0.1:1234/acp?token=REDACTED',
    });
  });
});

describe('startGooseServe', () => {
  afterEach(() => {
    vi.unstubAllEnvs();

    while (tempDirs.length > 0) {
      const tempDir = tempDirs.pop();
      if (tempDir) {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    }
  });

  it.skipIf(process.platform === 'win32')('uses the injected readiness fetch', async () => {
    const tempDir = makeTempDir();
    const goosePath = makeExecutable(
      path.join(tempDir, 'goose'),
      '#!/usr/bin/env sh\nwhile true; do sleep 1; done\n'
    );
    vi.stubEnv('GOOSE_BINARY', goosePath);

    const readinessUrls: string[] = [];
    const readinessFetch = vi.fn(async (input: string, _init?: ReadinessFetchInit) => {
      readinessUrls.push(input);
      return new Response(null, { status: 200 });
    });

    const result = await startGooseServe({
      serverSecret: 'test-secret',
      dir: tempDir,
      readinessFetch,
    });

    try {
      expect(readinessFetch).toHaveBeenCalledTimes(1);
      expect(readinessUrls[0]).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/status$/);
    } finally {
      await result.cleanup();
    }
  });

  it.skipIf(process.platform === 'win32')('captures the TLS fingerprint from stdout', async () => {
    const tempDir = makeTempDir();
    const goosePath = makeExecutable(
      path.join(tempDir, 'goose'),
      [
        '#!/usr/bin/env sh',
        'printf "GOOSED_CERT_FINGERPRINT=AA:BB:CC\\n"',
        'while true; do sleep 1; done',
        '',
      ].join('\n')
    );
    vi.stubEnv('GOOSE_BINARY', goosePath);

    let fingerprintLogged!: () => void;
    const fingerprintSeen = new Promise<void>((resolve) => {
      fingerprintLogged = resolve;
    });
    const logger = {
      info: vi.fn((message: unknown) => {
        if (String(message).includes('Pinned cert fingerprint')) {
          fingerprintLogged();
        }
      }),
      error: vi.fn(),
    };
    const readinessFetch = vi.fn(async () => {
      await fingerprintSeen;
      return new Response(null, { status: 200 });
    });

    const result = await startGooseServe({
      serverSecret: 'test-secret',
      dir: tempDir,
      logger,
      readinessFetch,
    });

    try {
      expect(result.certFingerprint).toBe('AA:BB:CC');
    } finally {
      await result.cleanup();
    }
  });

  it.skipIf(process.platform === 'win32')(
    'uses TLS URLs and args when TLS is enabled',
    async () => {
      const tempDir = makeTempDir();
      const argsPath = path.join(tempDir, 'args.txt');
      const goosePath = makeExecutable(
        path.join(tempDir, 'goose'),
        [
          '#!/usr/bin/env sh',
          'printf "%s\\n" "$@" > "$TEST_ARGS_PATH"',
          'printf "GOOSED_CERT_FINGERPRINT=DD:EE:FF\\n"',
          'while true; do sleep 1; done',
          '',
        ].join('\n')
      );
      vi.stubEnv('GOOSE_BINARY', goosePath);

      const readinessUrls: string[] = [];
      let registeredTlsIdentity: { fingerprint: string; origin: string } | null = null;
      const logger = {
        info: vi.fn(),
        error: vi.fn(),
      };
      const readinessFetch = vi.fn(async (input: string, _init?: ReadinessFetchInit) => {
        expect(registeredTlsIdentity).not.toBeNull();
        readinessUrls.push(input);
        return new Response(null, { status: 200 });
      });

      const result = await startGooseServe({
        serverSecret: 'test-secret',
        dir: tempDir,
        tls: true,
        env: {
          TEST_ARGS_PATH: argsPath,
        },
        logger,
        readinessFetch,
        onTlsFingerprint: (identity) => {
          registeredTlsIdentity = identity;
        },
      });

      try {
        expect(readinessUrls[0]).toMatch(/^https:\/\/127\.0\.0\.1:\d+\/status$/);
        expect(result.acpUrl).toMatch(/^wss:\/\/127\.0\.0\.1:\d+\/acp\?token=test-secret$/);
        expect(result.certFingerprint).toBe('DD:EE:FF');
        expect(registeredTlsIdentity).toEqual({
          fingerprint: 'DD:EE:FF',
          origin: expect.stringMatching(/^https:\/\/127\.0\.0\.1:\d+$/),
        });
        const args = await waitForFileLines(argsPath);
        expect(args).toContain('--tls');
        expect(args).not.toContain('--enable-scheduler');
      } finally {
        await result.cleanup();
      }
    }
  );

  it.skipIf(process.platform === 'win32')(
    'waits for TLS fingerprint before probing readiness',
    async () => {
      const tempDir = makeTempDir();
      const goosePath = makeExecutable(
        path.join(tempDir, 'goose'),
        [
          '#!/usr/bin/env sh',
          'sleep 0.1',
          'printf "GOOSED_CERT_FINGERPRINT=11:22:33\\n"',
          'while true; do sleep 1; done',
          '',
        ].join('\n')
      );
      vi.stubEnv('GOOSE_BINARY', goosePath);

      const readinessFetch = vi.fn(async () => new Response(null, { status: 200 }));

      const result = await startGooseServe({
        serverSecret: 'test-secret',
        dir: tempDir,
        tls: true,
        readinessFetch,
      });

      try {
        expect(readinessFetch).toHaveBeenCalled();
        expect(result.certFingerprint).toBe('11:22:33');
      } finally {
        await result.cleanup();
      }
    }
  );
});

describe('buildGooseServeEnv', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('passes binding authority only through the dedicated option', () => {
    vi.stubEnv('ACCORDLOCK_BACKEND_BINDING_SECRET', 'inherited-secret');

    const env = buildGooseServeEnv(
      'server-secret',
      process.execPath,
      {
        ACCORDLOCK_RUNTIME_URL: 'http://127.0.0.1:43127',
        ACCORDLOCK_RUNTIME_TOKEN: 'runtime-token',
      },
      null,
      ZERO_BINDING_SECRET
    );

    expect(env.ACCORDLOCK_BACKEND_BINDING_SECRET).toBe(ZERO_BINDING_SECRET);
    expect(env.ACCORDLOCK_BACKEND_BINDING_SECRET).not.toBe('inherited-secret');
  });

  it('scrubs every inherited AccordLock authority value', () => {
    vi.stubEnv('ACCORDLOCK_RUNTIME_URL', 'http://127.0.0.1:49999');
    vi.stubEnv('ACCORDLOCK_RUNTIME_TOKEN', 'inherited-token');
    vi.stubEnv('ACCORDLOCK_BACKEND_BINDING_SECRET', 'inherited-binding');

    const env = buildGooseServeEnv('server-secret', process.execPath, {});

    expect(env.ACCORDLOCK_RUNTIME_URL).toBeUndefined();
    expect(env.ACCORDLOCK_RUNTIME_TOKEN).toBeUndefined();
    expect(env.ACCORDLOCK_BACKEND_BINDING_SECRET).toBeUndefined();
  });

  it('does not copy arbitrary inherited secrets into the protected backend', () => {
    vi.stubEnv('UNRELATED_VENDOR_API_KEY', 'must-not-cross-process-boundary');
    vi.stubEnv('DATABASE_PASSWORD', 'must-not-cross-process-boundary');

    const env = buildGooseServeEnv('server-secret', process.execPath, {});

    expect(env.UNRELATED_VENDOR_API_KEY).toBeUndefined();
    expect(env.DATABASE_PASSWORD).toBeUndefined();
  });

  it('scrubs and canonicalizes authority keys case-insensitively', () => {
    vi.stubEnv('accordlock_runtime_url', 'http://127.0.0.1:49999');
    vi.stubEnv('AccordLock_Runtime_Token', 'inherited-token');
    vi.stubEnv('accordlock_backend_binding_secret', 'inherited-binding');

    const env = buildGooseServeEnv(
      'server-secret',
      process.execPath,
      {
        accordlock_runtime_url: 'http://127.0.0.1:43127',
        accordlock_runtime_token: 'runtime-token',
      },
      null,
      ZERO_BINDING_SECRET
    );

    expect(env.ACCORDLOCK_RUNTIME_URL).toBe('http://127.0.0.1:43127');
    expect(env.ACCORDLOCK_RUNTIME_TOKEN).toBe('runtime-token');
    expect(env.ACCORDLOCK_BACKEND_BINDING_SECRET).toBe(ZERO_BINDING_SECRET);
    expect(
      Object.keys(env).filter(
        (key) =>
          key.toUpperCase().startsWith('ACCORDLOCK_') &&
          ![
            'ACCORDLOCK_RUNTIME_URL',
            'ACCORDLOCK_RUNTIME_TOKEN',
            'ACCORDLOCK_BACKEND_BINDING_SECRET',
          ].includes(key)
      )
    ).toEqual([]);
  });

  it('requires the explicit runtime URL and token as one complete pair', () => {
    expect(() =>
      buildGooseServeEnv(
        'server-secret',
        process.execPath,
        { ACCORDLOCK_RUNTIME_URL: 'http://127.0.0.1:43127' },
        null,
        ZERO_BINDING_SECRET
      )
    ).toThrow('AccordLock backend runtime authority is incomplete');
  });

  it('fails closed when runtime authority has no backend binding', () => {
    expect(() =>
      buildGooseServeEnv('server-secret', process.execPath, {
        ACCORDLOCK_RUNTIME_URL: 'http://127.0.0.1:43127',
        ACCORDLOCK_RUNTIME_TOKEN: 'runtime-token',
      })
    ).toThrow('AccordLock backend binding secret is required');
  });

  it('fails closed when a backend binding has no runtime authority', () => {
    expect(() =>
      buildGooseServeEnv('server-secret', process.execPath, {}, null, ZERO_BINDING_SECRET)
    ).toThrow('AccordLock backend runtime authority is incomplete');
  });

  it('rejects generic-environment injection of the binding secret', () => {
    expect(() =>
      buildGooseServeEnv('server-secret', process.execPath, {
        accordlock_backend_binding_secret: ZERO_BINDING_SECRET,
      })
    ).toThrow('AccordLock backend binding secret must use the dedicated option');
  });

  it('rejects case-variant duplicates in explicit runtime authority', () => {
    expect(() =>
      buildGooseServeEnv(
        'server-secret',
        process.execPath,
        {
          ACCORDLOCK_RUNTIME_URL: 'http://127.0.0.1:43127',
          accordlock_runtime_url: 'http://127.0.0.1:43128',
          ACCORDLOCK_RUNTIME_TOKEN: 'runtime-token',
        },
        null,
        ZERO_BINDING_SECRET
      )
    ).toThrow('AccordLock backend runtime authority contains duplicate keys');
  });
});
