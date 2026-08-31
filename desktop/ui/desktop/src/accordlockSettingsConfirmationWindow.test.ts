import { EventEmitter } from 'node:events';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

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

  readonly webContents = new MockWebContents();
  readonly loadURL = vi.fn(async (_url: string) => undefined);
  readonly show = vi.fn();
  readonly focus = vi.fn();
  readonly removeMenu = vi.fn();
  private destroyed = false;

  constructor(readonly options: Record<string, unknown>) {
    super();
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

type ConfirmationWindowModule = typeof import('./accordlockSettingsConfirmationWindow');
type ConfirmationCopy =
  import('./accordlockSettingsConfirmationWindow').AccordLockSettingsConfirmationCopy;

const defaultCopy = (): ConfirmationCopy => ({
  title: 'Remove trusted program?',
  message: 'Remove the terminal alias “build”?',
  detail: 'C:\\Tools\\build.exe\n\nsha256:1234',
  confirmLabel: 'Remove',
  cancelLabel: 'Cancel',
  tone: 'warning',
});

function decodedDocument(child: MockBrowserWindow): string {
  const dataUrl = child.loadURL.mock.calls[0]?.[0];
  if (typeof dataUrl !== 'string') throw new Error('confirmation did not load a data URL');
  const [header, payload] = dataUrl.split(',', 2);
  expect(header).toBe('data:text/html;charset=utf-8;base64');
  return Buffer.from(payload, 'base64').toString('utf8');
}

function documentNonce(document: string): string {
  const match = document.match(/name="nonce" value="([0-9a-f]{64})"/u);
  if (!match) throw new Error('confirmation document did not contain a nonce');
  return match[1];
}

function navigationEvent(): { preventDefault: ReturnType<typeof vi.fn> } {
  return { preventDefault: vi.fn() };
}

describe('AccordLock settings confirmation window', () => {
  let module: ConfirmationWindowModule;

  beforeEach(async () => {
    vi.useRealTimers();
    MockBrowserWindow.instances.length = 0;
    vi.resetModules();
    vi.doMock('electron', () => ({ BrowserWindow: MockBrowserWindow }));
    module = await import('./accordlockSettingsConfirmationWindow');
  });

  afterEach(() => {
    for (const window of [...MockBrowserWindow.instances].reverse()) window.close();
    vi.useRealTimers();
  });

  async function openConfirmation(
    copy: ConfirmationCopy = defaultCopy(),
    theme: 'light' | 'dark' = 'light'
  ): Promise<{
    parent: MockBrowserWindow;
    child: MockBrowserWindow;
    result: Promise<boolean>;
  }> {
    const parent = new MockBrowserWindow({});
    const result = module.showAccordLockSettingsConfirmationWindow(
      parent as unknown as Parameters<
        ConfirmationWindowModule['showAccordLockSettingsConfirmationWindow']
      >[0],
      copy,
      theme
    );
    const child = MockBrowserWindow.instances[1];
    if (!child) throw new Error('confirmation child was not created');
    await vi.waitFor(() => expect(child.show).toHaveBeenCalledOnce());
    return { parent, child, result };
  }

  it('creates a main-owned modal with no script, preload, Node, or network authority', async () => {
    const { child } = await openConfirmation();

    expect(child.options).toMatchObject({
      parent: MockBrowserWindow.instances[0],
      modal: true,
      show: false,
      width: 640,
      height: 540,
      minWidth: 460,
      minHeight: 400,
      title: 'Remove trusted program? · AccordLock',
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
        spellcheck: false,
        safeDialogs: true,
      },
    });
    expect(child.options.webPreferences).not.toHaveProperty('preload');
    expect(child.options.webPreferences).toMatchObject({
      partition: expect.stringMatching(/^accordlock-settings-confirmation-[0-9a-f]{64}$/u),
    });
    expect(child.removeMenu).toHaveBeenCalledOnce();
    expect(child.show).toHaveBeenCalledOnce();
    expect(child.focus).toHaveBeenCalledOnce();

    const openHandler = child.webContents.setWindowOpenHandler.mock.calls[0]?.[0];
    expect(openHandler?.({ url: 'https://example.com' })).toEqual({ action: 'deny' });

    const document = decodedDocument(child);
    expect(document).toContain("default-src 'none'");
    expect(document).toContain("connect-src 'none'");
    expect(document).toContain('form-action https://accordlock.invalid');
    expect(document).toContain('target="_self"');
    expect(document).toContain('<html lang="en" data-theme="light">');
    expect(document).toContain('<meta name="color-scheme" content="light">');
    expect(document).not.toContain('<script');
    expect(document).not.toMatch(/ipcRenderer|preload|require\s*\(/u);
  });

  it('bounds and sanitizes all rendered copy while preserving readable line breaks', async () => {
    const { child } = await openConfirmation({
      title: 'Trust <source>?',
      message: `Unsafe </p><script>bad()</script>\u202e\u200b\u00a0text  `,
      detail: 'line one\nline two\tend',
      confirmLabel: 'Trust <now>',
      cancelLabel: 'Cancel',
    });
    const document = decodedDocument(child);

    expect(document).toContain('Trust &lt;source&gt;?');
    expect(document).toContain(
      'Unsafe &lt;/p&gt;&lt;script&gt;bad()&lt;/script&gt;\\u{202E}\\u{200B}\\u{00A0}text\\u{0020}\\u{0020}'
    );
    expect(document).toContain('line one\nline two\\tend');
    expect(document).toContain('Trust &lt;now&gt;');
    expect(document).not.toContain('</p><script>bad()');
    for (const hiddenCharacter of ['\u202e', '\u200b', '\u00a0']) {
      expect(document).not.toContain(hiddenCharacter);
    }
  });

  it('defaults focus to cancellation and supports the legacy button order', async () => {
    const { child } = await openConfirmation();
    const document = decodedDocument(child);

    expect(document).toContain('<button class="cancel" type="submit" autofocus>Cancel</button>');
    expect(document).toContain('<button class="confirm warning" type="submit">Remove</button>');
    expect(document.indexOf('>Cancel</button>')).toBeLessThan(document.indexOf('>Remove</button>'));
  });

  it('can preserve a confirmation-focused, confirmation-first legacy dialog', async () => {
    const { child } = await openConfirmation(
      {
        title: 'Connect this EKS cluster?',
        message: 'production-cluster',
        confirmLabel: 'Connect',
        cancelLabel: 'Cancel',
        tone: 'info',
        defaultButton: 'confirm',
        buttonOrder: 'confirm-first',
      },
      'dark'
    );
    const document = decodedDocument(child);

    expect(child.options.backgroundColor).toBe('#191a18');
    expect(document).toContain('<html lang="en" data-theme="dark">');
    expect(document).toContain('<meta name="color-scheme" content="dark">');
    expect(document).toContain(
      '<button class="confirm info" type="submit" autofocus>Connect</button>'
    );
    expect(document.indexOf('>Connect</button>')).toBeLessThan(
      document.lastIndexOf('>Cancel</button>')
    );
    expect(document).toContain(':root, body { background: #191a18; color: #f3f4f1; }');
    expect(document).not.toContain('@media (prefers-color-scheme: dark)');
  });

  it('returns true only for the exact nonce-bound confirmation navigation', async () => {
    const { child, result } = await openConfirmation();
    const nonce = documentNonce(decodedDocument(child));
    const event = navigationEvent();

    child.webContents.emit(
      'will-navigate',
      event,
      `https://accordlock.invalid/settings-decision?nonce=${nonce}&decision=confirm`
    );

    await expect(result).resolves.toBe(true);
    expect(event.preventDefault).toHaveBeenCalledOnce();
    expect(child.isDestroyed()).toBe(true);
  });

  it.each([
    [
      'cancel decision',
      (nonce: string) =>
        `https://accordlock.invalid/settings-decision?nonce=${nonce}&decision=cancel`,
    ],
    [
      'wrong nonce',
      () => `https://accordlock.invalid/settings-decision?nonce=${'0'.repeat(64)}&decision=confirm`,
    ],
    [
      'wrong origin',
      (nonce: string) => `https://example.com/settings-decision?nonce=${nonce}&decision=confirm`,
    ],
    [
      'wrong path',
      (nonce: string) => `https://accordlock.invalid/other?nonce=${nonce}&decision=confirm`,
    ],
    [
      'extra field',
      (nonce: string) =>
        `https://accordlock.invalid/settings-decision?nonce=${nonce}&decision=confirm&extra=1`,
    ],
    [
      'duplicate decision',
      (nonce: string) =>
        `https://accordlock.invalid/settings-decision?nonce=${nonce}&decision=confirm&decision=confirm`,
    ],
    [
      'fragment',
      (nonce: string) =>
        `https://accordlock.invalid/settings-decision?nonce=${nonce}&decision=confirm#confirm`,
    ],
    ['malformed URL', () => 'not a url'],
  ])('fails closed for a %s', async (_caseName, navigation) => {
    const { child, result } = await openConfirmation();
    const nonce = documentNonce(decodedDocument(child));
    const event = navigationEvent();

    child.webContents.emit('will-navigate', event, navigation(nonce));

    await expect(result).resolves.toBe(false);
    expect(event.preventDefault).toHaveBeenCalledOnce();
  });

  it.each([
    ['the window closes', 'closed'],
    ['Escape is pressed', 'escape'],
    ['the renderer crashes', 'crash'],
    ['the renderer becomes unresponsive', 'unresponsive'],
    ['the parent closes', 'parent'],
    ['a redirect is attempted', 'redirect'],
  ] as const)('fails closed when %s', async (_description, failure) => {
    const { parent, child, result } = await openConfirmation();

    if (failure === 'closed') child.close();
    if (failure === 'escape') {
      child.webContents.emit('before-input-event', navigationEvent(), {
        type: 'keyDown',
        key: 'Escape',
      });
    }
    if (failure === 'crash') child.webContents.emit('render-process-gone', {}, {});
    if (failure === 'unresponsive') child.emit('unresponsive');
    if (failure === 'parent') parent.close();
    if (failure === 'redirect') child.webContents.emit('will-redirect', navigationEvent(), '');

    await expect(result).resolves.toBe(false);
  });

  it('does not open for a destroyed parent, invalid copy, or oversized copy', async () => {
    const parent = new MockBrowserWindow({});
    parent.close();
    await expect(
      module.showAccordLockSettingsConfirmationWindow(
        parent as unknown as Parameters<
          ConfirmationWindowModule['showAccordLockSettingsConfirmationWindow']
        >[0],
        defaultCopy()
      )
    ).resolves.toBe(false);
    expect(MockBrowserWindow.instances).toHaveLength(1);

    const activeParent = new MockBrowserWindow({});
    await expect(
      module.showAccordLockSettingsConfirmationWindow(
        activeParent as unknown as Parameters<
          ConfirmationWindowModule['showAccordLockSettingsConfirmationWindow']
        >[0],
        { ...defaultCopy(), detail: 'x'.repeat(32 * 1_024 + 1) }
      )
    ).resolves.toBe(false);
    expect(MockBrowserWindow.instances).toHaveLength(2);

    await expect(
      module.showAccordLockSettingsConfirmationWindow(
        activeParent as unknown as Parameters<
          ConfirmationWindowModule['showAccordLockSettingsConfirmationWindow']
        >[0],
        { ...defaultCopy(), tone: 'danger' } as unknown as ConfirmationCopy
      )
    ).resolves.toBe(false);
    expect(MockBrowserWindow.instances).toHaveLength(2);
  });

  it('expires open confirmations fail-closed', async () => {
    vi.useFakeTimers();
    const { child, result } = await openConfirmation();

    await vi.advanceTimersByTimeAsync(5 * 60 * 1_000);

    await expect(result).resolves.toBe(false);
    expect(child.isDestroyed()).toBe(true);
  });
});
