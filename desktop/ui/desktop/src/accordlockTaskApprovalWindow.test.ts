import { EventEmitter } from 'node:events';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { AccordLockTaskAuthorization } from './accordlock/taskIpc';

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
  static failNextConstruction = false;
  static nextLoadBehavior: 'resolve' | 'reject' | 'throw' = 'resolve';

  readonly webContents = new MockWebContents();
  readonly loadURL = vi.fn((_url: string) => {
    const behavior = MockBrowserWindow.nextLoadBehavior;
    MockBrowserWindow.nextLoadBehavior = 'resolve';
    if (behavior === 'throw') throw new Error('load threw');
    if (behavior === 'reject') return Promise.reject(new Error('load rejected'));
    return Promise.resolve();
  });
  readonly show = vi.fn();
  readonly focus = vi.fn();
  readonly removeMenu = vi.fn();
  private destroyed = false;

  constructor(readonly options: Record<string, unknown>) {
    super();
    if (MockBrowserWindow.failNextConstruction) {
      MockBrowserWindow.failNextConstruction = false;
      throw new Error('window creation failed');
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

type ApprovalWindowModule = typeof import('./accordlockTaskApprovalWindow');

const digest = (character: string) => `sha256:${character.repeat(64)}`;
const FAR_FUTURE_EXPIRY = 4_102_444_800;

function authorization(
  overrides: Partial<AccordLockTaskAuthorization> = {}
): AccordLockTaskAuthorization {
  return {
    protocol: 'accordlock.desktop.control/v2',
    schema_version: 2,
    authorization_id: '11111111-1111-4111-8111-111111111111',
    task_id: '22222222-2222-4222-8222-222222222222',
    session_id: 'session-1',
    authorization_digest: digest('a'),
    objective: 'Prepare the release notes.',
    workspace_root: '\\\\?\\C:\\workspace',
    prepared_at: 1_700_000_000,
    expires_at: FAR_FUTURE_EXPIRY,
    task_policy: {
      schema_version: 2,
      task_objective_hash: digest('b'),
      preauthorized_capabilities: [
        { extension_id: 'developer', tool_name: 'read' },
        { extension_id: 'developer', tool_name: 'tree' },
      ],
      protected_paths: [
        '.accordlock',
        '.env',
        '.git',
        '.goose',
        '.goosehints',
        '.ssh',
        'credentials',
      ],
    },
    task_policy_hash: digest('c'),
    capabilities: [
      {
        extension_id: 'developer',
        tool_name: 'read',
        display_name: 'Read files',
        operation_type: 'READ',
      },
      {
        extension_id: 'developer',
        tool_name: 'tree',
        display_name: 'Browse workspace',
        operation_type: 'READ',
      },
      {
        extension_id: 'developer',
        tool_name: 'edit',
        display_name: 'Edit files',
        operation_type: 'WRITE',
      },
      {
        extension_id: 'developer',
        tool_name: 'write',
        display_name: 'Write files',
        operation_type: 'WRITE',
      },
      {
        extension_id: 'developer',
        tool_name: 'delete_file',
        display_name: 'Move files to recovery storage',
        operation_type: 'WRITE',
      },
      {
        extension_id: 'developer',
        tool_name: 'shell',
        display_name: 'Run approved programs',
        operation_type: 'EXECUTE',
      },
    ],
    ...overrides,
  };
}

function decodedDocument(child: MockBrowserWindow): string {
  const dataUrl = child.loadURL.mock.calls[0]?.[0];
  if (typeof dataUrl !== 'string') throw new Error('approval window did not load a data URL');
  const [header, payload] = dataUrl.split(',', 2);
  expect(header).toBe('data:text/html;charset=utf-8;base64');
  return Buffer.from(payload, 'base64').toString('utf8');
}

function documentNonce(document: string): string {
  const match = document.match(/name="nonce" value="([0-9a-f]{64})"/u);
  if (!match) throw new Error('approval document did not contain a nonce');
  return match[1];
}

function navigationEvent(): { preventDefault: ReturnType<typeof vi.fn> } {
  return { preventDefault: vi.fn() };
}

describe('AccordLock trusted task approval window', () => {
  let module: ApprovalWindowModule;

  beforeEach(async () => {
    vi.useRealTimers();
    MockBrowserWindow.instances.length = 0;
    MockBrowserWindow.failNextConstruction = false;
    MockBrowserWindow.nextLoadBehavior = 'resolve';
    vi.resetModules();
    vi.doMock('electron', () => ({ BrowserWindow: MockBrowserWindow }));
    module = await import('./accordlockTaskApprovalWindow');
  });

  afterEach(() => {
    for (const window of [...MockBrowserWindow.instances].reverse()) window.close();
    vi.useRealTimers();
  });

  async function openApproval(
    value: AccordLockTaskAuthorization = authorization(),
    theme: 'light' | 'dark' = 'light'
  ): Promise<{
    parent: MockBrowserWindow;
    child: MockBrowserWindow;
    result: ReturnType<ApprovalWindowModule['showAccordLockTaskApprovalWindow']>;
  }> {
    const parent = new MockBrowserWindow({});
    const result = module.showAccordLockTaskApprovalWindow(
      parent as unknown as Parameters<ApprovalWindowModule['showAccordLockTaskApprovalWindow']>[0],
      value,
      theme
    );
    const child = MockBrowserWindow.instances[1];
    if (!child) throw new Error('approval child was not created');
    await Promise.resolve();
    return { parent, child, result };
  }

  it('creates one modal, scriptless and isolated main-process review', async () => {
    const { child } = await openApproval();

    expect(child.options).toMatchObject({
      parent: MockBrowserWindow.instances[0],
      modal: true,
      show: false,
      width: 620,
      height: 610,
      minWidth: 480,
      minHeight: 500,
      title: 'Start task · AccordLock',
      titleBarStyle: 'hidden',
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
      },
    });
    expect(child.options.webPreferences).not.toHaveProperty('preload');
    expect(child.removeMenu).toHaveBeenCalledOnce();
    expect(child.show).toHaveBeenCalledOnce();
    expect(child.focus).toHaveBeenCalledOnce();

    const openHandler = child.webContents.setWindowOpenHandler.mock.calls[0]?.[0];
    expect(openHandler?.({ url: 'https://example.com' })).toEqual({ action: 'deny' });

    const document = decodedDocument(child);
    expect(document).toContain("default-src 'none'");
    expect(document).toContain('form-action https://accordlock.invalid');
    expect(document).not.toContain('<script');
    expect(document).not.toMatch(/ipcRenderer|preload|require\s*\(/u);
  });

  it('renders a compact, calm and accurate access summary', async () => {
    const { child } = await openApproval();
    const document = decodedDocument(child);

    expect(document).toContain('<h1>Review this task</h1>');
    expect(document).toContain('Prepare the release notes.');
    expect(document).toContain('C:\\workspace');
    expect(document).not.toContain('\\\\?\\');
    expect(document).toContain('Task access is fixed once work starts.');
    expect(document).toContain('<dt>Outcome</dt>');
    expect(document).toContain('<dt>Folder</dt>');
    expect(document).toContain('Read files and browse folders');
    expect(document).toContain('Automatic');
    expect(document).toContain('The selected model may receive file content from this folder.');
    expect(document).toContain('Change files or run commands');
    expect(document).toContain('Ask each time');
    expect(document).toContain('Use network or administrator tools');
    expect(document).toContain('Open protected settings or credentials');
    expect(document.match(/<span class="access-state">Blocked<\/span>/gu)).toHaveLength(2);
    expect(document).toContain('grid-template-rows: 40px minmax(0, 1fr) auto;');
    expect(document).toContain('overflow-y: auto;');
    expect(document).not.toContain('position: fixed');
    expect(document).toMatch(/<button class="cancel" type="submit" autofocus>Cancel<\/button>/u);
    expect(document).toContain(
      '<button class="window-close" type="submit" aria-label="Cancel and close"><span aria-hidden="true">×</span></button>'
    );
    expect(document).toContain('>Start task</button>');

    for (const noisyCopy of [
      'Final task approval',
      'protected task',
      'TASK — USER PROVIDED',
      'authorization fingerprint',
      'developer /',
    ]) {
      expect(document).not.toContain(noisyCopy);
    }
  });

  it('shows bounded HTTPS access only when the trusted task capability is present', async () => {
    const configured = authorization({
      capabilities: [
        {
          extension_id: 'accordlock_network',
          tool_name: 'https_request',
          display_name: 'Read approved websites',
          operation_type: 'NETWORK',
        },
        ...authorization().capabilities,
      ],
    });
    const { child } = await openApproval(configured);
    const document = decodedDocument(child);

    expect(document).toContain('Read configured websites (GET/HEAD only)');
    expect(document).toContain('Use other network or administrator tools');
    expect(document.match(/<span class="access-state">Ask each time<\/span>/gu)).toHaveLength(2);
    expect(document.match(/<span class="access-state">Blocked<\/span>/gu)).toHaveLength(2);
    expect(document).not.toContain('Use network or administrator tools</span>');
  });

  it('surfaces literal user limits without model-generated interpretation', async () => {
    const { child } = await openApproval(
      authorization({
        objective:
          'Prepare the release notes. Do not change package files. Work without network access.',
      })
    );
    const document = decodedDocument(child);

    expect(document).toContain('<dt>Your limits</dt>');
    expect(document).toContain('<li>Do not change package files.</li>');
    expect(document).toContain('<li>Work without network access.</li>');
  });

  it('shows categorical file and command bans as blocked instead of approvable', async () => {
    const { child } = await openApproval(
      authorization({
        objective: 'Review this folder. Do not change files.',
      })
    );
    const document = decodedDocument(child);

    expect(document).toContain('<li>Do not change files.</li>');
    expect(document).toContain('Change files or run commands');
    expect(document).toContain('Blocked by your limit');
    expect(document).not.toContain(
      'Change files or run commands</span><span class="access-state">Ask each time'
    );
  });

  it('splits protected actions when only commands are categorically blocked', async () => {
    const { child } = await openApproval(
      authorization({
        objective: 'Prepare the report. Do not run commands.',
      })
    );
    const document = decodedDocument(child);

    expect(document).toContain(
      'Change files</span><span class="access-state">Ask each time</span>'
    );
    expect(document).toContain(
      'Run commands</span><span class="access-state">Blocked by your limit</span>'
    );
  });

  it('blocks configured network access when the task categorically requires offline work', async () => {
    const configured = authorization({
      objective: 'Review the release. Work without network access.',
      capabilities: [
        {
          extension_id: 'accordlock_network',
          tool_name: 'https_request',
          display_name: 'Read approved websites',
          operation_type: 'NETWORK',
        },
        ...authorization().capabilities,
      ],
    });
    const { child } = await openApproval(configured);
    const document = decodedDocument(child);

    expect(document).toContain(
      'Read configured websites (GET/HEAD only)</span><span class="access-state">Blocked by your limit</span>'
    );
  });

  it('keeps scoped file wording as a review reminder without globally blocking changes', async () => {
    const { child } = await openApproval(
      authorization({ objective: 'Prepare the release. Do not change package files.' })
    );
    const document = decodedDocument(child);

    expect(document).toContain('<li>Do not change package files.</li>');
    expect(document).toContain(
      'Change files or run commands</span><span class="access-state">Ask each time</span>'
    );
    expect(document).not.toContain('Blocked by your limit');
  });

  it('uses the resolved application theme instead of the operating-system preference', async () => {
    const { child } = await openApproval(authorization(), 'dark');
    const document = decodedDocument(child);

    expect(child.options.backgroundColor).toBe('#191a18');
    expect(document).toContain('<html lang="en" data-theme="dark">');
    expect(document).toContain('<meta name="color-scheme" content="dark">');
    expect(document).not.toContain('prefers-color-scheme');
    expect(document).toContain(':root, body { background: #191a18; color: #f3f4f1; }');
  });

  it('escapes task data and exposes invisible or directional characters', async () => {
    const value = authorization({
      objective: `</dd><script>bad()</script>safe\u202esecret\nnext\t `,
      workspace_root: '\\\\?\\unc\\server\\share\\folder',
    });
    const { child } = await openApproval(value);
    const document = decodedDocument(child);

    expect(document).toContain('&lt;/dd&gt;&lt;script&gt;bad()&lt;/script&gt;');
    expect(document).not.toContain('<script>bad()');
    expect(document).toContain('safe\\u{202E}secret\\n\nnext\\t\\u{0020}');
    expect(document).not.toContain('\u202e');
    expect(document).toContain('\\\\server\\share\\folder');
    expect(document.toUpperCase()).not.toContain('\\\\?\\UNC\\');
  });

  it('allows only the exact nonce-bound approval navigation', async () => {
    const { child, result } = await openApproval();
    const nonce = documentNonce(decodedDocument(child));
    const event = navigationEvent();

    child.webContents.emit(
      'will-navigate',
      event,
      `https://accordlock.invalid/task-decision?nonce=${nonce}&decision=approve`
    );

    await expect(result).resolves.toBe('APPROVED');
    expect(event.preventDefault).toHaveBeenCalledOnce();
    expect(child.isDestroyed()).toBe(true);
  });

  it('returns CANCELLED for the exact nonce-bound deny navigation', async () => {
    const { child, result } = await openApproval();
    const nonce = documentNonce(decodedDocument(child));
    const event = navigationEvent();

    child.webContents.emit(
      'will-navigate',
      event,
      `https://accordlock.invalid/task-decision?nonce=${nonce}&decision=deny`
    );

    await expect(result).resolves.toBe('CANCELLED');
    expect(event.preventDefault).toHaveBeenCalledOnce();
    expect(child.isDestroyed()).toBe(true);
  });

  it.each([
    ['a wrong nonce', () => `nonce=${'0'.repeat(64)}&decision=approve`],
    ['an extra field', (nonce: string) => `nonce=${nonce}&decision=approve&extra=1`],
    ['a duplicate nonce', (nonce: string) => `nonce=${nonce}&nonce=${nonce}&decision=approve`],
    ['a duplicate decision', (nonce: string) => `nonce=${nonce}&decision=approve&decision=deny`],
    ['an unknown decision', (nonce: string) => `nonce=${nonce}&decision=continue`],
    ['a missing decision', (nonce: string) => `nonce=${nonce}`],
  ])('returns FAILED for %s', async (_, query) => {
    const { child, result } = await openApproval();
    const nonce = documentNonce(decodedDocument(child));
    const event = navigationEvent();

    child.webContents.emit(
      'will-navigate',
      event,
      `https://accordlock.invalid/task-decision?${query(nonce)}`
    );

    await expect(result).resolves.toBe('FAILED');
    expect(event.preventDefault).toHaveBeenCalledOnce();
  });

  it('fails closed for a navigation from another origin', async () => {
    const { child, result } = await openApproval();
    const nonce = documentNonce(decodedDocument(child));
    const event = navigationEvent();

    child.webContents.emit(
      'will-navigate',
      event,
      `https://example.com/task-decision?nonce=${nonce}&decision=approve`
    );

    await expect(result).resolves.toBe('FAILED');
    expect(event.preventDefault).toHaveBeenCalledOnce();
  });

  it.each([
    ['a malformed URL', () => 'not a URL'],
    [
      'a different path',
      (nonce: string) => `https://accordlock.invalid/other?nonce=${nonce}&decision=approve`,
    ],
    [
      'a fragment',
      (nonce: string) =>
        `https://accordlock.invalid/task-decision?nonce=${nonce}&decision=approve#unexpected`,
    ],
    [
      'embedded credentials',
      (nonce: string) =>
        `https://user:password@accordlock.invalid/task-decision?nonce=${nonce}&decision=approve`,
    ],
  ])('returns FAILED for %s', async (_, navigation) => {
    const { child, result } = await openApproval();
    const nonce = documentNonce(decodedDocument(child));
    const event = navigationEvent();

    child.webContents.emit('will-navigate', event, navigation(nonce));

    await expect(result).resolves.toBe('FAILED');
    expect(event.preventDefault).toHaveBeenCalledOnce();
  });

  it.each([
    ['the child closes', 'closed', 'CANCELLED'],
    ['Escape is pressed', 'escape', 'CANCELLED'],
    ['the child becomes unresponsive', 'unresponsive', 'FAILED'],
    ['the renderer crashes', 'crash', 'FAILED'],
    ['the document fails to load', 'load-failure', 'FAILED'],
    ['the parent closes', 'parent-closed', 'CANCELLED'],
    ['the parent contents are destroyed', 'parent-destroyed', 'FAILED'],
    ['the document redirects', 'redirect', 'FAILED'],
  ] as const)('classifies %s', async (_, failure, expected) => {
    const { parent, child, result } = await openApproval();

    if (failure === 'closed') child.close();
    if (failure === 'escape') {
      child.webContents.emit('before-input-event', navigationEvent(), {
        type: 'keyDown',
        key: 'Escape',
      });
    }
    if (failure === 'unresponsive') child.emit('unresponsive');
    if (failure === 'crash') child.webContents.emit('render-process-gone', {}, {});
    if (failure === 'load-failure') child.webContents.emit('did-fail-load', {}, -1, 'failed');
    if (failure === 'parent-closed') parent.emit('closed');
    if (failure === 'parent-destroyed') parent.webContents.destroyContents();
    if (failure === 'redirect') child.webContents.emit('will-redirect', navigationEvent(), 'x');

    await expect(result).resolves.toBe(expected);
    expect(child.isDestroyed()).toBe(true);
  });

  it('returns FAILED when the trusted window cannot be created', async () => {
    const parent = new MockBrowserWindow({});
    MockBrowserWindow.failNextConstruction = true;

    const result = module.showAccordLockTaskApprovalWindow(
      parent as unknown as Parameters<ApprovalWindowModule['showAccordLockTaskApprovalWindow']>[0],
      authorization()
    );

    await expect(result).resolves.toBe('FAILED');
    expect(MockBrowserWindow.instances).toHaveLength(1);
  });

  it.each(['throw', 'reject'] as const)(
    'returns FAILED when loading the trusted document must %s',
    async (behavior) => {
      const parent = new MockBrowserWindow({});
      MockBrowserWindow.nextLoadBehavior = behavior;

      const result = module.showAccordLockTaskApprovalWindow(
        parent as unknown as Parameters<
          ApprovalWindowModule['showAccordLockTaskApprovalWindow']
        >[0],
        authorization()
      );
      const child = MockBrowserWindow.instances[1];
      if (!child) throw new Error('approval child was not created');

      await expect(result).resolves.toBe('FAILED');
      expect(child.isDestroyed()).toBe(true);
      expect(child.show).not.toHaveBeenCalled();
    }
  );

  it('does not create a child for a destroyed parent, an expired task, or changed policy copy', async () => {
    const destroyedParent = new MockBrowserWindow({});
    destroyedParent.close();
    await expect(
      module.showAccordLockTaskApprovalWindow(
        destroyedParent as unknown as Parameters<
          ApprovalWindowModule['showAccordLockTaskApprovalWindow']
        >[0],
        authorization()
      )
    ).resolves.toBe('FAILED');
    expect(MockBrowserWindow.instances).toHaveLength(1);

    const activeParent = new MockBrowserWindow({});
    await expect(
      module.showAccordLockTaskApprovalWindow(
        activeParent as unknown as Parameters<
          ApprovalWindowModule['showAccordLockTaskApprovalWindow']
        >[0],
        authorization({ expires_at: Math.floor(Date.now() / 1_000) })
      )
    ).resolves.toBe('FAILED');
    expect(MockBrowserWindow.instances).toHaveLength(2);

    await expect(
      module.showAccordLockTaskApprovalWindow(
        activeParent as unknown as Parameters<
          ApprovalWindowModule['showAccordLockTaskApprovalWindow']
        >[0],
        authorization({
          capabilities: [
            ...authorization().capabilities,
            {
              extension_id: 'network',
              tool_name: 'fetch',
              display_name: 'Use network',
              operation_type: 'NETWORK',
            },
          ],
        })
      )
    ).resolves.toBe('FAILED');
    expect(MockBrowserWindow.instances).toHaveLength(2);
  });

  it('closes fail-closed at the earliest task or review deadline', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2030-01-01T00:00:00Z'));
    const expiry = Math.floor(Date.now() / 1_000) + 2;
    const { child, result } = await openApproval(authorization({ expires_at: expiry }));

    await vi.advanceTimersByTimeAsync(2_000);

    await expect(result).resolves.toBe('FAILED');
    expect(child.isDestroyed()).toBe(true);
  });

  it('returns FAILED when the five-minute review window times out', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2030-01-01T00:00:00Z'));
    const { child, result } = await openApproval();

    await vi.advanceTimersByTimeAsync(5 * 60 * 1_000);

    await expect(result).resolves.toBe('FAILED');
    expect(child.isDestroyed()).toBe(true);
  });
});
