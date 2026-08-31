import { EventEmitter } from 'node:events';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { AccordLockRestoreChallenge } from './accordlockRestoreWindow';

class MockWebContents extends EventEmitter {
  readonly setWindowOpenHandler = vi.fn();
  private destroyed = false;

  isDestroyed(): boolean {
    return this.destroyed;
  }

  destroyContents(): void {
    if (this.destroyed) return;
    this.destroyed = true;
    this.emit('destroyed');
  }
}

class MockBrowserWindow extends EventEmitter {
  static readonly instances: MockBrowserWindow[] = [];
  static nextLoadBehavior: 'resolve' | 'reject' | 'throw' = 'resolve';
  static throwNextConstruction = false;

  readonly webContents = new MockWebContents();
  readonly loadURL = vi.fn((_url: string) => {
    const behavior = MockBrowserWindow.nextLoadBehavior;
    MockBrowserWindow.nextLoadBehavior = 'resolve';
    if (behavior === 'throw') throw new Error('load failed');
    return behavior === 'reject' ? Promise.reject(new Error('load failed')) : Promise.resolve();
  });
  readonly show = vi.fn();
  readonly focus = vi.fn();
  readonly removeMenu = vi.fn();
  private destroyed = false;

  constructor(readonly options: Record<string, unknown>) {
    super();
    if (MockBrowserWindow.throwNextConstruction) {
      MockBrowserWindow.throwNextConstruction = false;
      throw new Error('window failed');
    }
    MockBrowserWindow.instances.push(this);
  }

  isDestroyed(): boolean {
    return this.destroyed;
  }

  destroy(): void {
    if (this.destroyed) return;
    this.destroyed = true;
    this.webContents.destroyContents();
    this.emit('closed');
  }

  close(): void {
    this.destroy();
  }
}

type RestoreWindowModule = typeof import('./accordlockRestoreWindow');

const FAR_FUTURE_EXPIRY = 4_102_444_800;
const digest = (character: string) => `sha256:${character.repeat(64)}`;

function restoreChallenge(
  overrides: Partial<AccordLockRestoreChallenge> = {}
): AccordLockRestoreChallenge {
  return {
    challengeDigest: digest('b'),
    contentSha256: digest('a'),
    expiresAt: FAR_FUTURE_EXPIRY,
    preparedAt: 1_700_000_000,
    recoveryId: '33333333-3333-4333-8333-333333333333',
    relativePath: 'src/report&notes.txt',
    workspaceRoot: 'C:\\workspace<&',
    ...overrides,
  };
}

function decodedDocument(child: MockBrowserWindow): string {
  const dataUrl = child.loadURL.mock.calls[0]?.[0];
  if (typeof dataUrl !== 'string') throw new Error('restore window did not load a data URL');
  const [header, payload] = dataUrl.split(',', 2);
  expect(header).toBe('data:text/html;charset=utf-8;base64');
  return Buffer.from(payload, 'base64').toString('utf8');
}

function documentNonce(document: string): string {
  const match = document.match(/name="nonce" value="([0-9a-f]{64})"/u);
  if (!match) throw new Error('restore document did not contain a nonce');
  return match[1];
}

function preventableEvent(): { preventDefault: ReturnType<typeof vi.fn> } {
  return { preventDefault: vi.fn() };
}

describe('AccordLock restore confirmation window', () => {
  let module: RestoreWindowModule;

  beforeEach(async () => {
    vi.useRealTimers();
    MockBrowserWindow.instances.length = 0;
    MockBrowserWindow.nextLoadBehavior = 'resolve';
    MockBrowserWindow.throwNextConstruction = false;
    vi.resetModules();
    vi.doMock('electron', () => ({ BrowserWindow: MockBrowserWindow }));
    module = await import('./accordlockRestoreWindow');
  });

  afterEach(() => {
    for (const window of [...MockBrowserWindow.instances].reverse()) window.close();
    vi.useRealTimers();
  });

  async function openRestore(
    challenge: AccordLockRestoreChallenge = restoreChallenge(),
    theme: 'light' | 'dark' = 'light'
  ): Promise<{
    child: MockBrowserWindow;
    parent: MockBrowserWindow;
    result: Promise<'APPROVED' | 'DENIED' | 'FAILED'>;
  }> {
    const parent = new MockBrowserWindow({});
    const result = module.showAccordLockRestoreWindow(
      parent as unknown as Parameters<RestoreWindowModule['showAccordLockRestoreWindow']>[0],
      challenge,
      theme
    );
    const child = MockBrowserWindow.instances[1];
    if (!child) throw new Error('restore child was not created');
    await Promise.resolve();
    await Promise.resolve();
    return { child, parent, result };
  }

  it('creates a modal, scriptless and isolated child with no preload or IPC authority', async () => {
    const { child } = await openRestore();

    expect(child.options).toMatchObject({
      parent: MockBrowserWindow.instances[0],
      modal: true,
      show: false,
      width: 640,
      height: 570,
      minWidth: 460,
      minHeight: 440,
      title: 'Restore file · AccordLock',
      titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'hidden',
      backgroundColor: '#f5f5f3',
      webPreferences: {
        sandbox: true,
        nodeIntegration: false,
        nodeIntegrationInWorker: false,
        nodeIntegrationInSubFrames: false,
        contextIsolation: true,
        javascript: false,
        devTools: false,
        webSecurity: true,
        allowRunningInsecureContent: false,
        webviewTag: false,
        navigateOnDragDrop: false,
        safeDialogs: true,
      },
    });
    expect(child.options.webPreferences).not.toHaveProperty('preload');
    expect(child.removeMenu).toHaveBeenCalledOnce();
    expect(child.show).toHaveBeenCalledOnce();
    expect(child.focus).toHaveBeenCalledOnce();
    const openHandler = child.webContents.setWindowOpenHandler.mock.calls[0]?.[0];
    expect(openHandler?.({ url: 'https://example.com' })).toEqual({ action: 'deny' });
    const attachEvent = preventableEvent();
    child.webContents.emit('will-attach-webview', attachEvent, {}, {});
    expect(attachEvent.preventDefault).toHaveBeenCalledOnce();

    const document = decodedDocument(child);
    expect(document).toContain("default-src 'none'");
    expect(document).toContain('form-action https://accordlock.invalid');
    expect(document).toContain('<html lang="en" data-theme="light">');
    expect(document).not.toContain('<script');
    expect(document).not.toMatch(/ipcRenderer|preload|require\s*\(/u);
  });

  it('shows the exact target, hashes, expiry and no-overwrite behavior after escaping', async () => {
    const challenge = restoreChallenge();
    const { child } = await openRestore(challenge);
    const document = decodedDocument(child);

    expect(document).toContain('<h1>Restore this file?</h1>');
    expect(document).toContain('src/report&amp;notes.txt');
    expect(document).toContain('C:\\\\workspace&lt;&amp;');
    expect(document).toContain(challenge.contentSha256);
    expect(document).toContain(challenge.challengeDigest);
    expect(document).toContain(challenge.recoveryId);
    expect(document).toContain(new Date(challenge.preparedAt * 1_000).toISOString());
    expect(document).toContain(new Date(challenge.expiresAt * 1_000).toISOString());
    expect(document).toContain('<strong>Nothing will be overwritten.</strong>');
    expect(document).toContain('Restore stops if a file already exists at this path.');
    expect(document).toContain('<button class="cancel" type="submit" autofocus>Cancel</button>');
    expect(document).toContain('>Restore file</button>');
  });

  it('makes hidden path characters visible instead of relying on bidi rendering', async () => {
    const relativePath = `src/\u202eevil\u200d\u00a0name.txt  `;
    const { child } = await openRestore(restoreChallenge({ relativePath }));
    const document = decodedDocument(child);

    expect(document).toContain('src/\\u{202E}evil\\u{200D}\\u{00A0}name.txt\\u{0020}\\u{0020}');
    for (const hiddenCharacter of ['\u202e', '\u200d', '\u00a0']) {
      expect(document).not.toContain(hiddenCharacter);
    }
  });

  it('uses the explicit dark theme', async () => {
    const { child } = await openRestore(restoreChallenge(), 'dark');
    const document = decodedDocument(child);

    expect(child.options.backgroundColor).toBe('#191a18');
    expect(document).toContain('<html lang="en" data-theme="dark">');
    expect(document).toContain('<meta name="color-scheme" content="dark">');
    expect(document).toContain(':root, body { background: #191a18; color: #f3f4f1; }');
    expect(document).not.toContain('@media (prefers-color-scheme: dark)');
  });

  it.each([
    ['approve', 'APPROVED'],
    ['deny', 'DENIED'],
  ] as const)('accepts the exact nonce-bound %s decision', async (decision, expected) => {
    const { child, result } = await openRestore();
    const nonce = documentNonce(decodedDocument(child));
    const event = preventableEvent();

    child.webContents.emit(
      'will-navigate',
      event,
      `https://accordlock.invalid/restore-decision?nonce=${nonce}&decision=${decision}`
    );

    await expect(result).resolves.toBe(expected);
    expect(event.preventDefault).toHaveBeenCalledOnce();
    expect(child.isDestroyed()).toBe(true);
  });

  it.each([
    [
      'wrong origin',
      (nonce: string) => `https://example.com/restore-decision?nonce=${nonce}&decision=approve`,
    ],
    [
      'wrong path',
      (nonce: string) => `https://accordlock.invalid/decision?nonce=${nonce}&decision=approve`,
    ],
    [
      'wrong nonce',
      () => `https://accordlock.invalid/restore-decision?nonce=${'0'.repeat(64)}&decision=approve`,
    ],
    [
      'duplicate nonce',
      (nonce: string) =>
        `https://accordlock.invalid/restore-decision?nonce=${nonce}&nonce=${nonce}&decision=approve`,
    ],
    [
      'extra field',
      (nonce: string) =>
        `https://accordlock.invalid/restore-decision?nonce=${nonce}&decision=approve&extra=1`,
    ],
    [
      'unknown decision',
      (nonce: string) =>
        `https://accordlock.invalid/restore-decision?nonce=${nonce}&decision=restore`,
    ],
  ] as const)('fails closed for %s navigation', async (_, urlForNonce) => {
    const { child, result } = await openRestore();
    const nonce = documentNonce(decodedDocument(child));
    const event = preventableEvent();

    child.webContents.emit('will-navigate', event, urlForNonce(nonce));

    await expect(result).resolves.toBe('FAILED');
    expect(event.preventDefault).toHaveBeenCalledOnce();
  });

  it.each(['closed', 'escape'] as const)('treats %s as a denied restore', async (action) => {
    const { child, result } = await openRestore();

    if (action === 'closed') child.close();
    else {
      const event = preventableEvent();
      child.webContents.emit('before-input-event', event, { type: 'keyDown', key: 'Escape' });
      expect(event.preventDefault).toHaveBeenCalledOnce();
    }

    await expect(result).resolves.toBe('DENIED');
  });

  it.each(['crash', 'unresponsive', 'redirect', 'parent-closed'] as const)(
    'returns FAILED when the trusted window hits %s',
    async (failure) => {
      const { child, parent, result } = await openRestore();
      if (failure === 'crash') child.webContents.emit('render-process-gone', {}, {});
      if (failure === 'unresponsive') child.emit('unresponsive');
      if (failure === 'parent-closed') parent.close();
      if (failure === 'redirect') {
        const event = preventableEvent();
        child.webContents.emit('will-redirect', event, 'https://example.com');
        expect(event.preventDefault).toHaveBeenCalledOnce();
      }
      await expect(result).resolves.toBe('FAILED');
    }
  );

  it.each([
    ['absolute path', { relativePath: 'C:\\outside.txt' }],
    ['parent traversal', { relativePath: '../outside.txt' }],
    ['bad content hash', { contentSha256: 'sha256:bad' }],
    ['expired request', { expiresAt: 1_700_000_001 }],
    ['future preparation', { preparedAt: FAR_FUTURE_EXPIRY - 1 }],
  ] as const)(
    'rejects an invalid challenge with %s before opening a child',
    async (_, overrides) => {
      const parent = new MockBrowserWindow({});
      const result = module.showAccordLockRestoreWindow(
        parent as unknown as Parameters<RestoreWindowModule['showAccordLockRestoreWindow']>[0],
        restoreChallenge(overrides)
      );

      await expect(result).resolves.toBe('FAILED');
      expect(MockBrowserWindow.instances).toHaveLength(1);
    }
  );

  it('rejects unknown challenge fields before opening a child', async () => {
    const parent = new MockBrowserWindow({});
    const challenge = { ...restoreChallenge(), unexpectedAuthority: true };
    const result = module.showAccordLockRestoreWindow(
      parent as unknown as Parameters<RestoreWindowModule['showAccordLockRestoreWindow']>[0],
      challenge as AccordLockRestoreChallenge
    );

    await expect(result).resolves.toBe('FAILED');
    expect(MockBrowserWindow.instances).toHaveLength(1);
  });

  it('rejects a destroyed parent or an unknown theme before opening a child', async () => {
    const destroyedParent = new MockBrowserWindow({});
    destroyedParent.close();
    await expect(
      module.showAccordLockRestoreWindow(
        destroyedParent as unknown as Parameters<
          RestoreWindowModule['showAccordLockRestoreWindow']
        >[0],
        restoreChallenge()
      )
    ).resolves.toBe('FAILED');

    const activeParent = new MockBrowserWindow({});
    await expect(
      module.showAccordLockRestoreWindow(
        activeParent as unknown as Parameters<
          RestoreWindowModule['showAccordLockRestoreWindow']
        >[0],
        restoreChallenge(),
        'contrast' as 'light'
      )
    ).resolves.toBe('FAILED');
    expect(MockBrowserWindow.instances).toHaveLength(2);
  });

  it.each(['throw', 'reject'] as const)('returns FAILED when loading must %s', async (behavior) => {
    MockBrowserWindow.nextLoadBehavior = behavior;
    const { child, result } = await openRestore();

    await expect(result).resolves.toBe('FAILED');
    expect(child.isDestroyed()).toBe(true);
    expect(child.show).not.toHaveBeenCalled();
  });

  it('returns FAILED when the restore window cannot be created', async () => {
    const parent = new MockBrowserWindow({});
    MockBrowserWindow.throwNextConstruction = true;
    const result = module.showAccordLockRestoreWindow(
      parent as unknown as Parameters<RestoreWindowModule['showAccordLockRestoreWindow']>[0],
      restoreChallenge()
    );

    await expect(result).resolves.toBe('FAILED');
    expect(MockBrowserWindow.instances).toHaveLength(1);
  });

  it('expires fail-closed at the earlier challenge deadline', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2030-01-01T00:00:00Z'));
    const nowSeconds = Math.floor(Date.now() / 1_000);
    const { child, result } = await openRestore(
      restoreChallenge({ preparedAt: nowSeconds - 1, expiresAt: nowSeconds + 2 })
    );

    await vi.advanceTimersByTimeAsync(2_000);

    await expect(result).resolves.toBe('FAILED');
    expect(child.isDestroyed()).toBe(true);
  });

  it('never leaves a restore decision open longer than five minutes', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2030-01-01T00:00:00Z'));
    const nowSeconds = Math.floor(Date.now() / 1_000);
    const { child, result } = await openRestore(
      restoreChallenge({ preparedAt: nowSeconds - 1, expiresAt: nowSeconds + 3_600 })
    );

    await vi.advanceTimersByTimeAsync(5 * 60 * 1_000);

    await expect(result).resolves.toBe('FAILED');
    expect(child.isDestroyed()).toBe(true);
  });
});
