import { EventEmitter } from 'node:events';
import type { AccordLockActionApprovalChallenge } from './accordlockActionApproval';
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

class MockNotification extends EventEmitter {
  static readonly instances: MockNotification[] = [];

  readonly show = vi.fn();
  readonly close = vi.fn();

  constructor(readonly options: Record<string, unknown>) {
    super();
    MockNotification.instances.push(this);
  }
}

type ApprovalWindowModule = typeof import('./accordlockActionApprovalWindow');

const digest = (character: string) => `sha256:${character.repeat(64)}`;
const FAR_FUTURE_EXPIRY = 4_102_444_800;

function writeChallenge(
  content = `</pre><script>globalThis.compromised=true</script>&<>'"${'x'.repeat(1_700)}END-SENTINEL`
): AccordLockActionApprovalChallenge {
  const requestedBytes = Buffer.byteLength(content, 'utf8');
  return {
    sessionId: 'session-1',
    workspaceRoot: 'C:\\workspace',
    proposalDigest: digest('a'),
    approvalRequestHash: digest('b'),
    approvalRequest: {
      schema_version: 2,
      task_id: '12345678-1234-4abc-8def-123456789abc',
      session_id: 'session-1',
      run_id: 'run-1',
      tool_call_id: 'call-1',
      proposal_digest: digest('a'),
      task_policy_hash: digest('c'),
      prestate_hash: digest('d'),
      action: {
        extension_id: 'developer',
        tool_name: 'write',
        relative_path: 'src/<untrusted>.txt',
        action_type: 'OVERWRITE_FILE',
        requested_bytes: requestedBytes,
      },
      task_requirement: { schema_version: 2 },
      transformation_step: { schema_version: 2 },
      policy_decision: { schema_version: 2 },
      policy_decision_hash: digest('f'),
    },
    arguments: { kind: 'write', path: 'src/<untrusted>.txt', content },
    operationLabel: 'Replace file',
    targetLabel: 'Path',
    target: 'src/<untrusted>.txt',
    quantityLabel: 'Proposed UTF-8',
    contentEvidence: `Content ${digest('e')} · ${requestedBytes} bytes`,
    preview: 'TRUNCATED-PREVIEW-MUST-NOT-BE-USED',
    previewTruncated: true,
  };
}

function editChallenge(): AccordLockActionApprovalChallenge {
  const before = `BEFORE-${'b'.repeat(1_650)}-END`;
  const after = `AFTER-${'a'.repeat(1_650)}-END`;
  const base = writeChallenge();
  return {
    ...base,
    approvalRequest: {
      ...base.approvalRequest,
      action: {
        extension_id: 'developer',
        tool_name: 'edit',
        relative_path: 'src/message.txt',
        action_type: 'EDIT_FILE',
        requested_bytes: Buffer.byteLength(after, 'utf8'),
      },
    },
    arguments: { kind: 'edit', path: 'src/message.txt', before, after },
    operationLabel: 'Edit file',
    target: 'src/message.txt',
    contentEvidence: `Find ${digest('e')} · replace with ${digest('f')}`,
  };
}

function shellChallenge(): AccordLockActionApprovalChallenge {
  const base = writeChallenge('safe');
  return {
    ...base,
    approvalRequest: {
      ...base.approvalRequest,
      action: {
        extension_id: 'developer',
        tool_name: 'shell',
        relative_path: '.',
        action_type: 'EXECUTE_PROCESS',
        requested_bytes: 11,
        executable_path: 'C:\\Program Files\\AccordLock\\probe.exe',
        executable_sha256: `sha256:${'7'.repeat(64)}`,
      },
    },
    arguments: {
      kind: 'shell',
      path: '.',
      argv: ['cargo', 'test', '--lib'],
      env: { CI: '1', NO_COLOR: '1' },
      timeoutSeconds: 60,
      maxOutputBytes: 65_536,
    },
    operationLabel: 'Run program',
    targetLabel: 'Working directory',
    target: '.',
    quantityLabel: 'Direct arguments',
    contentEvidence: `Direct argv ${digest('6')} · 3 entries · no shell string`,
    preview: 'complete terminal preview',
    previewTruncated: false,
  };
}

function deleteChallenge(): AccordLockActionApprovalChallenge {
  const base = writeChallenge('safe');
  return {
    ...base,
    approvalRequest: {
      ...base.approvalRequest,
      action: {
        extension_id: 'developer',
        tool_name: 'delete_file',
        relative_path: 'src/message.txt',
        action_type: 'DELETE_FILE',
        requested_bytes: 11,
      },
    },
    arguments: { kind: 'delete_file', path: 'src/message.txt' },
    operationLabel: 'Move file to recovery storage',
    target: 'src/message.txt',
    quantityLabel: 'Current file',
    contentEvidence: 'Exact current file state · 11 bytes · recoverable',
    preview: 'Move src/message.txt to AccordLock recovery storage.',
    previewTruncated: false,
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

describe('AccordLock exact action approval window', () => {
  let module: ApprovalWindowModule;

  beforeEach(async () => {
    vi.useRealTimers();
    MockBrowserWindow.instances.length = 0;
    MockNotification.instances.length = 0;
    vi.resetModules();
    vi.doMock('electron', () => ({
      app: { getLocale: () => 'en-US' },
      BrowserWindow: MockBrowserWindow,
      Notification: MockNotification,
    }));
    module = await import('./accordlockActionApprovalWindow');
  });

  afterEach(() => {
    for (const window of [...MockBrowserWindow.instances].reverse()) window.close();
    vi.useRealTimers();
  });

  async function openApproval(
    challenge: AccordLockActionApprovalChallenge = writeChallenge(),
    objective = 'Preserve <intent> & do not run "markup"',
    taskExpiresAtSeconds = FAR_FUTURE_EXPIRY,
    theme: 'light' | 'dark' = 'light'
  ): Promise<{
    parent: MockBrowserWindow;
    child: MockBrowserWindow;
    result: Promise<boolean>;
  }> {
    const parent = new MockBrowserWindow({});
    const result = module.showAccordLockActionApprovalWindow(
      parent as unknown as Parameters<
        ApprovalWindowModule['showAccordLockActionApprovalWindow']
      >[0],
      challenge,
      objective,
      taskExpiresAtSeconds,
      theme
    );
    const child = MockBrowserWindow.instances[1];
    if (!child) throw new Error('approval child was not created');
    await Promise.resolve();
    return { parent, child, result };
  }

  it('creates a modal, scriptless and isolated child with no preload or IPC authority', async () => {
    const { child } = await openApproval();

    expect(child.options).toMatchObject({
      parent: MockBrowserWindow.instances[0],
      modal: true,
      show: false,
      width: 780,
      height: 700,
      minWidth: 500,
      minHeight: 520,
      title: 'Approve action · AccordLock',
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
      },
    });
    expect(child.options.webPreferences).not.toHaveProperty('preload');
    expect(child.removeMenu).toHaveBeenCalledOnce();
    expect(child.show).toHaveBeenCalledOnce();
    const openHandler = child.webContents.setWindowOpenHandler.mock.calls[0]?.[0];
    expect(openHandler?.({ url: 'https://example.com' })).toEqual({ action: 'deny' });

    const document = decodedDocument(child);
    expect(document).toContain("default-src 'none'");
    expect(document).toContain('form-action https://accordlock.invalid');
    expect(document).toContain('<html lang="en" data-theme="light">');
    expect(document).toContain('<meta name="color-scheme" content="light">');
    expect(document).not.toContain('@media (prefers-color-scheme: dark)');
    expect(document).not.toContain('<script');
    expect(document).not.toMatch(/ipcRenderer|preload|require\s*\(/u);
  });

  it('notifies without exposing a direct approval action and focuses the trusted approval on click', async () => {
    const { child } = await openApproval();
    const notification = MockNotification.instances[0];

    expect(notification).toBeDefined();
    expect(notification.options).toEqual({
      title: 'Action needs approval',
      body: 'Work is waiting for your decision.',
      silent: false,
    });
    expect(notification.options).not.toHaveProperty('actions');
    expect(notification.show).toHaveBeenCalledOnce();

    notification.emit('click');
    expect(child.focus).toHaveBeenCalledOnce();
  });

  it('renders the complete write, evidence and digest after HTML escaping', async () => {
    const content = `</pre><script data-x="1">bad()</script>&<>'"${'z'.repeat(1_700)}END-SENTINEL`;
    const { child } = await openApproval(writeChallenge(content));
    const document = decodedDocument(child);

    expect(document).toContain(
      '&lt;/pre&gt;&lt;script data-x=&quot;1&quot;&gt;bad()&lt;/script&gt;&amp;&lt;&gt;&#39;&quot;'
    );
    expect(document).toContain(`${'z'.repeat(1_700)}END-SENTINEL`);
    expect(document).toContain('src/&lt;untrusted&gt;.txt');
    expect(document).toContain('Preserve &lt;intent&gt; &amp; do not run &quot;markup&quot;');
    expect(document).not.toContain('TRUNCATED-PREVIEW-MUST-NOT-BE-USED');
    expect(document).toContain(
      `${Buffer.byteLength(content, 'utf8').toLocaleString('en-US')} bytes`
    );
    expect(document).toContain(digest('e'));
    expect(document).toContain(digest('a'));
    expect(document).toContain('<h1>Approve this action?</h1>');
    expect(document).toContain('aria-label="Task check"');
    expect(document).toContain('This action needs your approval.');
    expect(document).not.toContain('Nothing runs unless you approve this exact action.');
    expect(document).toContain('aria-label="Action summary"');
    expect(document).toContain(String.raw`Folder · C:\\workspace`);
    expect(document).toContain('<summary>Verification details</summary>');
    expect(document).toContain(
      '<button class="cancel" type="submit" autofocus>Don\'t run</button>'
    );
    expect(document).not.toContain('Review this action before it runs');
    expect(document).not.toContain('Security details');
    if (process.platform === 'darwin') {
      expect(document).not.toContain('aria-label="Cancel and close"');
    } else {
      expect(document).toContain('aria-label="Cancel and close"');
    }
  });

  it('shows when trusted intent evidence is missing without inventing a score', async () => {
    const base = writeChallenge('safe');
    const { child } = await openApproval({
      ...base,
      approvalRequest: {
        ...base.approvalRequest,
        policy_decision: {
          decision: 'REQUIRE_APPROVAL',
          reasons: ['CONFORMANCE_EVALUATION_MISSING'],
        },
      },
    });
    const document = decodedDocument(child);

    expect(document).toContain('AccordLock couldn&#39;t verify this action from the task alone.');
    expect(document).not.toContain('intent score');
    expect(document).not.toContain('aligned');
  });

  it('matches the explicit dark theme instead of the operating-system preference', async () => {
    const { child } = await openApproval(
      writeChallenge('safe'),
      'Review the exact change',
      FAR_FUTURE_EXPIRY,
      'dark'
    );
    const document = decodedDocument(child);

    expect(child.options.backgroundColor).toBe('#191a18');
    expect(document).toContain('<html lang="en" data-theme="dark">');
    expect(document).toContain('<meta name="color-scheme" content="dark">');
    expect(document).toContain(':root, body { background: #191a18; color: #f3f4f1; }');
    expect(document).toContain('.verification summary { color: #a3a79f; }');
    expect(document).not.toContain('@media (prefers-color-scheme: dark)');
  });

  it('exposes controls, line endings, bidi controls and zero-width text unambiguously', async () => {
    const content = `safe\\literal\r\n\t\u0000\u202e\u200bEND`;
    const { child } = await openApproval(writeChallenge(content));
    const document = decodedDocument(child);

    expect(document).toContain('safe\\\\literal\\r\\n\n\\t\\u{0000}\\u{202E}\\u{200B}END');
    expect(document).not.toContain('\u202e');
    expect(document).not.toContain('\u200b');
    expect(document).not.toContain('\u0000');
  });

  it('exposes Unicode-confusable path and objective text exactly', async () => {
    const path = `src/\u202eevil\u200d\u00a0name.txt  `;
    const objective = `Ship\u2066phase\u2069\u200d\u00a0safely  \nnext `;
    const base = writeChallenge('safe');
    const challenge: AccordLockActionApprovalChallenge = {
      ...base,
      approvalRequest: {
        ...base.approvalRequest,
        action: {
          ...base.approvalRequest.action,
          relative_path: path,
        },
      },
      arguments: { kind: 'write', path, content: 'safe' },
      target: path,
    };

    const { child } = await openApproval(challenge, objective);
    const document = decodedDocument(child);

    expect(document).toContain('src/\\u{202E}evil\\u{200D}\\u{00A0}name.txt\\u{0020}\\u{0020}');
    expect(document).toContain(
      'Ship\\u{2066}phase\\u{2069}\\u{200D}\\u{00A0}safely\\u{0020}\\u{0020}\\n\nnext\\u{0020}'
    );
    for (const hiddenCharacter of ['\u202e', '\u200d', '\u00a0', '\u2066', '\u2069']) {
      expect(document).not.toContain(hiddenCharacter);
    }
  });

  it('renders both complete sides of an edit instead of the truncated preview', async () => {
    const challenge = editChallenge();
    const { child } = await openApproval(challenge);
    const document = decodedDocument(child);

    if (challenge.arguments.kind !== 'edit') throw new Error('expected edit challenge');
    expect(document).toContain(challenge.arguments.before);
    expect(document).toContain(challenge.arguments.after);
    expect(document).toContain('Current text</h2>');
    expect(document).toContain('Replacement</h2>');
    expect(document).not.toContain(challenge.preview);
  });

  it('resurfaces an exact user limit at the relevant action review', async () => {
    const { child } = await openApproval(
      editChallenge(),
      'Prepare the release. Do not change package files.'
    );
    const document = decodedDocument(child);

    expect(document).toContain('From your request');
    expect(document).toContain('<li>Do not change package files.</li>');
    expect(document).not.toContain('intent score');
  });

  it('renders direct terminal argv boundaries and the non-secret environment exactly', async () => {
    const { child } = await openApproval(shellChallenge());
    const document = decodedDocument(child);

    expect(document).toContain('ARGV — direct process invocation; no shell parser');
    expect(document).toContain('0: &quot;cargo&quot;');
    expect(document).toContain('1: &quot;test&quot;');
    expect(document).toContain('CI=&quot;1&quot;');
    expect(document).toContain('Working directory');
    expect(document).toContain('Command to run');
    expect(document).toContain('3 arguments');
    expect(document).toContain('Approve once');
  });

  it('renders delete-file recovery and non-recursive limits explicitly', async () => {
    const { child } = await openApproval(deleteChallenge());
    const document = decodedDocument(child);

    expect(document).toContain('File move details');
    expect(document).toContain('Recoverable · not recursive');
    expect(document).toContain('src/message.txt');
    expect(document).toContain('Move this file to recovery');
    expect(document).toContain('FOLDERS: Not allowed');
    expect(document).toContain('Recoverable · not recursive');
    expect(document).toContain('Current file');
  });

  it('allows only the exact nonce-bound approval navigation', async () => {
    const { child, result } = await openApproval();
    const nonce = documentNonce(decodedDocument(child));
    const event = navigationEvent();

    child.webContents.emit(
      'will-navigate',
      event,
      `https://accordlock.invalid/decision?nonce=${nonce}&decision=approve`
    );

    await expect(result).resolves.toBe(true);
    expect(event.preventDefault).toHaveBeenCalledOnce();
    expect(child.isDestroyed()).toBe(true);
  });

  it.each([
    ['wrong nonce', (_nonce: string) => '0'.repeat(64), 'approve'],
    ['safe decision', (nonce: string) => nonce, 'deny'],
    ['wrong origin', (nonce: string) => nonce, 'approve'],
  ])('fails closed for a %s navigation', async (caseName, nonceForUrl, decision) => {
    const { child, result } = await openApproval();
    const nonce = documentNonce(decodedDocument(child));
    const origin =
      caseName === 'wrong origin' ? 'https://example.com' : 'https://accordlock.invalid';
    const event = navigationEvent();

    child.webContents.emit(
      'will-navigate',
      event,
      `${origin}/decision?nonce=${nonceForUrl(nonce)}&decision=${decision}`
    );

    await expect(result).resolves.toBe(false);
    expect(event.preventDefault).toHaveBeenCalledOnce();
  });

  it.each([
    ['the window is closed', 'closed'],
    ['Escape is pressed', 'escape'],
    ['the renderer crashes', 'crash'],
    ['the parent window is destroyed', 'parent-destroyed'],
  ] as const)('resolves false when %s', async (_, failure) => {
    const { parent, child, result } = await openApproval();

    if (failure === 'closed') child.close();
    if (failure === 'escape') {
      child.webContents.emit('before-input-event', navigationEvent(), {
        type: 'keyDown',
        key: 'Escape',
      });
    }
    if (failure === 'crash') child.webContents.emit('render-process-gone', {}, {});
    if (failure === 'parent-destroyed') parent.close();

    await expect(result).resolves.toBe(false);
  });

  it('does not create a child when the parent is already destroyed or the task expired', async () => {
    const parent = new MockBrowserWindow({});
    parent.close();

    await expect(
      module.showAccordLockActionApprovalWindow(
        parent as unknown as Parameters<
          ApprovalWindowModule['showAccordLockActionApprovalWindow']
        >[0],
        writeChallenge(),
        'objective',
        FAR_FUTURE_EXPIRY
      )
    ).resolves.toBe(false);
    expect(MockBrowserWindow.instances).toHaveLength(1);

    const activeParent = new MockBrowserWindow({});
    await expect(
      module.showAccordLockActionApprovalWindow(
        activeParent as unknown as Parameters<
          ApprovalWindowModule['showAccordLockActionApprovalWindow']
        >[0],
        writeChallenge(),
        'objective',
        Math.floor(Date.now() / 1_000)
      )
    ).resolves.toBe(false);
    expect(MockBrowserWindow.instances).toHaveLength(2);
  });

  it('closes fail-closed when the approval deadline expires', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2030-01-01T00:00:00Z'));
    const expiry = Math.floor(Date.now() / 1_000) + 2;
    const { child, result } = await openApproval(writeChallenge(), 'objective', expiry);

    await vi.advanceTimersByTimeAsync(2_000);

    await expect(result).resolves.toBe(false);
    expect(child.isDestroyed()).toBe(true);
  });
});
