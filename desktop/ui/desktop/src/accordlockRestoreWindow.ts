import { randomBytes, timingSafeEqual } from 'node:crypto';
import { BrowserWindow } from 'electron';

const DECISION_ORIGIN = 'https://accordlock.invalid';
const DECISION_PATH = '/restore-decision';
const NONCE_BYTES = 32;
const MAX_RESTORE_OPEN_MILLISECONDS = 5 * 60 * 1_000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;

const CHALLENGE_KEYS = [
  'challengeDigest',
  'contentSha256',
  'expiresAt',
  'preparedAt',
  'recoveryId',
  'relativePath',
  'workspaceRoot',
] as const;

export type AccordLockRestoreTheme = 'light' | 'dark';
export type AccordLockRestoreResult = 'APPROVED' | 'DENIED' | 'FAILED';

export type AccordLockRestoreChallenge = {
  challengeDigest: string;
  contentSha256: string;
  expiresAt: number;
  preparedAt: number;
  recoveryId: string;
  relativePath: string;
  workspaceRoot: string;
};

interface PreventableEvent {
  preventDefault(): void;
}

interface KeyboardInput {
  key: string;
  type: string;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/gu, (character) => {
    switch (character) {
      case '&':
        return '&amp;';
      case '<':
        return '&lt;';
      case '>':
        return '&gt;';
      case '"':
        return '&quot;';
      case "'":
        return '&#39;';
      default:
        return character;
    }
  });
}

function visibleExactText(value: string): string {
  const characters = [...value];
  const trailingAsciiSpaces = new Array<boolean>(characters.length).fill(false);
  let onlySpacesBeforeBoundary = true;

  for (let index = characters.length - 1; index >= 0; index -= 1) {
    const character = characters[index];
    if (character === ' ') {
      trailingAsciiSpaces[index] = onlySpacesBeforeBoundary;
    } else if (character === '\r' || character === '\n') {
      onlySpacesBeforeBoundary = true;
    } else {
      onlySpacesBeforeBoundary = false;
    }
  }

  let visible = '';
  for (const [index, character] of characters.entries()) {
    const codePoint = character.codePointAt(0) ?? 0;
    if (character === '\\') {
      visible += '\\\\';
    } else if (character === '\r') {
      visible += '\\r';
    } else if (character === '\n') {
      visible += '\\n\n';
    } else if (character === '\t') {
      visible += '\\t';
    } else if (
      trailingAsciiSpaces[index] ||
      (character !== ' ' && /\p{Zs}/u.test(character)) ||
      /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(character) ||
      (codePoint >= 0xfe00 && codePoint <= 0xfe0f) ||
      (codePoint >= 0xe0100 && codePoint <= 0xe01ef)
    ) {
      visible += `\\u{${codePoint.toString(16).toUpperCase().padStart(4, '0')}}`;
    } else {
      visible += character;
    }
  }
  return visible;
}

function isBoundedText(value: unknown, maximum: number): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= maximum &&
    !value.includes('\0')
  );
}

function isSafeRelativePath(value: unknown): value is string {
  if (!isBoundedText(value, 4_096)) return false;
  if (value.startsWith('/') || value.startsWith('\\') || /^[a-z]:/iu.test(value)) return false;
  const segments = value.split(/[\\/]/u);
  return segments.every((segment) => segment.length > 0 && segment !== '.' && segment !== '..');
}

function isValidChallenge(value: unknown, now: number): value is AccordLockRestoreChallenge {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  if (keys.length !== CHALLENGE_KEYS.length) return false;
  if (!keys.every((key, index) => key === CHALLENGE_KEYS[index])) return false;

  const preparedAt = record.preparedAt;
  const expiresAt = record.expiresAt;
  const nowSeconds = Math.floor(now / 1_000);
  return (
    isBoundedText(record.recoveryId, 64) &&
    UUID.test(record.recoveryId) &&
    isSafeRelativePath(record.relativePath) &&
    isBoundedText(record.workspaceRoot, 4_096) &&
    isBoundedText(record.contentSha256, 80) &&
    DIGEST.test(record.contentSha256) &&
    isBoundedText(record.challengeDigest, 80) &&
    DIGEST.test(record.challengeDigest) &&
    Number.isSafeInteger(preparedAt) &&
    Number.isSafeInteger(expiresAt) &&
    (preparedAt as number) >= 0 &&
    (preparedAt as number) <= nowSeconds &&
    (expiresAt as number) > nowSeconds &&
    (expiresAt as number) > (preparedAt as number) &&
    Number.isSafeInteger((expiresAt as number) * 1_000)
  );
}

function decisionForm(
  nonce: string,
  decision: 'approve' | 'deny',
  label: string,
  css: string,
  ariaLabel?: string
): string {
  const autofocus = decision === 'deny' && css === 'cancel' ? ' autofocus' : '';
  const accessibleName = ariaLabel ? ` aria-label="${escapeHtml(ariaLabel)}"` : '';
  return `<form action="${DECISION_ORIGIN}${DECISION_PATH}" method="get" autocomplete="off">
    <input type="hidden" name="nonce" value="${nonce}">
    <input type="hidden" name="decision" value="${decision}">
    <button class="${css}" type="submit"${autofocus}${accessibleName}>${label}</button>
  </form>`;
}

function buildRestoreDocument(
  challenge: AccordLockRestoreChallenge,
  nonce: string,
  theme: AccordLockRestoreTheme
): string {
  const relativePath = escapeHtml(visibleExactText(challenge.relativePath));
  const workspaceRoot = escapeHtml(visibleExactText(challenge.workspaceRoot));
  const recoveryId = escapeHtml(challenge.recoveryId);
  const contentSha256 = escapeHtml(challenge.contentSha256);
  const challengeDigest = escapeHtml(challenge.challengeDigest);
  const preparedAt = escapeHtml(new Date(challenge.preparedAt * 1_000).toISOString());
  const expiresAt = escapeHtml(new Date(challenge.expiresAt * 1_000).toISOString());
  const escapedNonce = escapeHtml(nonce);
  const darkThemeStyles =
    theme === 'dark'
      ? `
      :root, body { background: #191a18; color: #f3f4f1; }
      .window-bar, .intro, dt, .folder, .single-use, details summary { color: #a3a79f; }
      .window-close { color: #aeb1aa; }
      .window-close:hover { background: #30322f; color: #fff; }
      .restore-card, details { border-color: #393c39; background: #232522; }
      .field + .field { border-color: #393c39; }
      dd, .path { color: #f1f2ee; }
      .warning { border-color: #705f35; background: #302b1f; color: #f1e6c8; }
      .warning strong { color: #f2d58c; }
      .details-grid { border-color: #393c39; }
      .actions-shell { border-color: #393c39; background: rgb(28 30 27 / 96%); }
      button { border-color: #484c46; background: #282b27; color: #f2f3ef; }
      .approve { border-color: #f1f2ee; background: #f1f2ee; color: #171816; }
    `
      : '';
  const customClose =
    process.platform === 'darwin'
      ? ''
      : decisionForm(
          escapedNonce,
          'deny',
          '<span aria-hidden="true">×</span>',
          'window-close',
          'Cancel and close'
        );

  return `<!doctype html>
<html lang="en" data-theme="${theme}">
  <head>
    <meta charset="utf-8">
    <meta
      http-equiv="Content-Security-Policy"
      content="default-src 'none'; style-src 'unsafe-inline'; form-action ${DECISION_ORIGIN}; base-uri 'none'; object-src 'none'; frame-ancestors 'none'"
    >
    <meta name="referrer" content="no-referrer">
    <meta name="color-scheme" content="${theme}">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Restore file · AccordLock</title>
    <style>
      :root {
        color-scheme: ${theme};
        font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI Variable", "Segoe UI", sans-serif;
        background: #f5f5f3;
        color: #181917;
      }
      * { box-sizing: border-box; }
      html, body { height: 100%; overflow: hidden; }
      body {
        display: grid;
        grid-template-rows: 40px minmax(0, 1fr) auto;
        margin: 0;
        min-width: 360px;
        background: #f5f5f3;
        color: #181917;
      }
      .window-bar {
        -webkit-app-region: drag;
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: ${process.platform === 'darwin' ? '0 16px 0 78px' : '0 8px 0 20px'};
        color: #696d66;
        font-size: 11px;
        font-weight: 600;
      }
      .window-bar form, .window-close { -webkit-app-region: no-drag; }
      .window-close {
        display: grid;
        width: 30px;
        min-height: 30px;
        padding: 0;
        place-items: center;
        border: 0;
        border-radius: 9px;
        background: transparent;
        color: #747770;
        font: 22px/1 ui-sans-serif, sans-serif;
        cursor: pointer;
      }
      .window-close:hover { background: #e9e9e5; color: #242522; }
      main {
        width: min(100%, 620px);
        margin: 0 auto;
        padding: 16px 26px 24px;
        overflow-y: auto;
        scrollbar-gutter: stable;
      }
      h1 { margin: 0; font-size: 27px; font-weight: 650; letter-spacing: -.035em; }
      .intro { margin: 7px 0 16px; color: #666a63; font-size: 14px; line-height: 1.5; }
      .warning {
        margin: 0 0 14px;
        padding: 11px 13px;
        border: 1px solid #e3d19e;
        border-radius: 11px;
        background: #fffaf0;
        color: #40391f;
        font-size: 12px;
        line-height: 1.5;
      }
      .warning strong { color: #765b17; }
      .restore-card, details {
        overflow: hidden;
        border: 1px solid #dedfda;
        border-radius: 14px;
        background: #fff;
      }
      .field { padding: 13px 15px; }
      .field + .field { border-top: 1px solid #e8e9e5; }
      dt { margin: 0 0 5px; color: #696d66; font-size: 10px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
      dd { margin: 0; overflow-wrap: anywhere; color: #22231f; font-size: 13px; line-height: 1.5; unicode-bidi: plaintext; }
      .path, .hash, .details-grid dd { font-family: ui-monospace, "SFMono-Regular", Consolas, monospace; font-size: 11px; }
      .folder { margin: 6px 0 0; overflow-wrap: anywhere; color: #696d66; font-size: 11px; unicode-bidi: plaintext; }
      details { margin-top: 11px; padding: 11px 14px; }
      details summary { width: fit-content; color: #696d66; cursor: pointer; font-size: 12px; font-weight: 600; }
      details summary:focus-visible { outline: 3px solid #7896e8; outline-offset: 3px; }
      .details-grid { display: grid; gap: 9px; margin-top: 11px; padding-top: 11px; border-top: 1px solid #e8e9e5; }
      .actions-shell {
        border-top: 1px solid #dedfda;
        background: rgb(250 250 248 / 96%);
        backdrop-filter: blur(16px);
      }
      .actions {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 18px;
        width: min(100%, 620px);
        margin: 0 auto;
        padding: 12px 26px;
      }
      .single-use { margin: 0; color: #696d66; font-size: 11px; }
      .buttons { display: flex; justify-content: flex-end; gap: 8px; flex-shrink: 0; }
      form { margin: 0; }
      button {
        min-height: 40px;
        padding: 0 16px;
        border: 1px solid #d0d2cc;
        border-radius: 10px;
        background: #fff;
        color: #20211f;
        font: inherit;
        font-size: 13px;
        font-weight: 650;
        cursor: pointer;
      }
      button:focus-visible { outline: 3px solid #7896e8; outline-offset: 2px; }
      .approve { border-color: #20221f; background: #20221f; color: #fff; }
      @media (max-width: 520px) {
        main { padding: 10px 18px 18px; }
        .actions { align-items: stretch; flex-direction: column; gap: 8px; padding: 11px 18px; }
        .buttons, .buttons form, .buttons button { width: 100%; }
      }
      ${darkThemeStyles}
    </style>
  </head>
  <body>
    <header class="window-bar">
      <span>AccordLock</span>
      ${customClose}
    </header>
    <main>
      <h1>Restore this file?</h1>
      <p class="intro">AccordLock will copy the saved file back to its original path.</p>

      <p class="warning"><strong>Nothing will be overwritten.</strong> Restore stops if a file already exists at this path.</p>

      <dl class="restore-card" aria-label="Restore details">
        <div class="field">
          <dt>File</dt>
          <dd class="path">${relativePath}</dd>
          <p class="folder">Inside ${workspaceRoot}</p>
        </div>
        <div class="field">
          <dt>Saved content hash</dt>
          <dd class="hash">${contentSha256}</dd>
        </div>
      </dl>

      <details>
        <summary>Verification details</summary>
        <dl class="details-grid">
          <div><dt>Recovery ID</dt><dd>${recoveryId}</dd></div>
          <div><dt>Request hash</dt><dd>${challengeDigest}</dd></div>
          <div><dt>Prepared</dt><dd>${preparedAt}</dd></div>
          <div><dt>Expires</dt><dd>${expiresAt}</dd></div>
        </dl>
      </details>
    </main>

    <footer class="actions-shell">
      <div class="actions">
        <p class="single-use">One-time approval</p>
        <div class="buttons">
          ${decisionForm(escapedNonce, 'deny', 'Cancel', 'cancel')}
          ${decisionForm(escapedNonce, 'approve', 'Restore file', 'approve')}
        </div>
      </div>
    </footer>
  </body>
</html>`;
}

function buildDataUrl(document: string): string {
  return `data:text/html;charset=utf-8;base64,${Buffer.from(document, 'utf8').toString('base64')}`;
}

function nonceMatches(candidate: string, expected: string): boolean {
  if (!/^[0-9a-f]{64}$/u.test(candidate) || !/^[0-9a-f]{64}$/u.test(expected)) return false;
  return timingSafeEqual(Buffer.from(candidate, 'hex'), Buffer.from(expected, 'hex'));
}

function decisionNavigationResult(rawUrl: string, expectedNonce: string): AccordLockRestoreResult {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return 'FAILED';
  }

  if (
    url.origin !== DECISION_ORIGIN ||
    url.pathname !== DECISION_PATH ||
    url.hash !== '' ||
    url.username !== '' ||
    url.password !== ''
  ) {
    return 'FAILED';
  }

  const keys = [...url.searchParams.keys()].sort();
  if (keys.length !== 2 || keys[0] !== 'decision' || keys[1] !== 'nonce') return 'FAILED';
  const nonces = url.searchParams.getAll('nonce');
  const decisions = url.searchParams.getAll('decision');
  if (nonces.length !== 1 || decisions.length !== 1 || !nonceMatches(nonces[0], expectedNonce)) {
    return 'FAILED';
  }
  if (decisions[0] === 'approve') return 'APPROVED';
  if (decisions[0] === 'deny') return 'DENIED';
  return 'FAILED';
}

/**
 * Shows a main-process-owned, scriptless confirmation for one exact restore challenge.
 * No positive result is possible without the nonce-bound approval navigation.
 */
export function showAccordLockRestoreWindow(
  parent: BrowserWindow,
  challenge: AccordLockRestoreChallenge,
  theme: AccordLockRestoreTheme = 'light'
): Promise<AccordLockRestoreResult> {
  const now = Date.now();
  if (
    parent.isDestroyed() ||
    parent.webContents.isDestroyed() ||
    (theme !== 'light' && theme !== 'dark') ||
    !isValidChallenge(challenge, now)
  ) {
    return Promise.resolve('FAILED');
  }

  const restoreDeadline = Math.min(
    challenge.expiresAt * 1_000,
    now + MAX_RESTORE_OPEN_MILLISECONDS
  );
  const nonce = randomBytes(NONCE_BYTES).toString('hex');
  const document = buildRestoreDocument(challenge, nonce, theme);
  const dataUrl = buildDataUrl(document);

  let restoreWindow: BrowserWindow;
  try {
    restoreWindow = new BrowserWindow({
      parent,
      modal: true,
      show: false,
      width: 640,
      height: 570,
      minWidth: 460,
      minHeight: 440,
      resizable: true,
      minimizable: false,
      maximizable: false,
      fullscreenable: false,
      skipTaskbar: true,
      autoHideMenuBar: true,
      title: 'Restore file · AccordLock',
      titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'hidden',
      backgroundColor: theme === 'dark' ? '#191a18' : '#f5f5f3',
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
        partition: `accordlock-restore-${nonce}`,
      },
    });
  } catch {
    return Promise.resolve('FAILED');
  }

  restoreWindow.removeMenu();
  restoreWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));

  return new Promise<AccordLockRestoreResult>((resolve) => {
    const contents = restoreWindow.webContents;
    let settled = false;
    let navigationArmed = false;
    let deadlineTimer: ReturnType<typeof setTimeout> | undefined;

    const cleanup = () => {
      parent.removeListener('closed', onParentClosed);
      parent.webContents.removeListener('destroyed', onParentContentsDestroyed);
      restoreWindow.removeListener('closed', onRestoreClosed);
      restoreWindow.removeListener('unresponsive', onRestoreUnresponsive);
      contents.removeListener('before-input-event', onBeforeInput);
      contents.removeListener('did-fail-load', onLoadFailure);
      contents.removeListener('render-process-gone', onRendererGone);
      contents.removeListener('will-attach-webview', onWillAttachWebview);
      if (navigationArmed) {
        contents.removeListener('will-navigate', onWillNavigate);
        contents.removeListener('will-redirect', onWillRedirect);
      }
      if (deadlineTimer) clearTimeout(deadlineTimer);
    };

    const settle = (result: AccordLockRestoreResult) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (!restoreWindow.isDestroyed()) restoreWindow.destroy();
      resolve(result);
    };

    const onParentClosed = () => settle('FAILED');
    const onParentContentsDestroyed = () => settle('FAILED');
    const onRestoreClosed = () => settle('DENIED');
    const onRestoreUnresponsive = () => settle('FAILED');
    const onRendererGone = () => settle('FAILED');
    const onLoadFailure = () => settle('FAILED');
    const onWillAttachWebview = (event: PreventableEvent) => event.preventDefault();
    const onWillRedirect = (event: PreventableEvent) => {
      event.preventDefault();
      settle('FAILED');
    };
    const onWillNavigate = (event: PreventableEvent, url: string) => {
      event.preventDefault();
      settle(decisionNavigationResult(url, nonce));
    };
    const onBeforeInput = (event: PreventableEvent, input: KeyboardInput) => {
      if (input.type === 'keyDown' && input.key === 'Escape') {
        event.preventDefault();
        settle('DENIED');
      }
    };

    parent.once('closed', onParentClosed);
    parent.webContents.once('destroyed', onParentContentsDestroyed);
    restoreWindow.once('closed', onRestoreClosed);
    restoreWindow.once('unresponsive', onRestoreUnresponsive);
    contents.on('before-input-event', onBeforeInput);
    contents.once('did-fail-load', onLoadFailure);
    contents.once('render-process-gone', onRendererGone);
    contents.on('will-attach-webview', onWillAttachWebview);
    deadlineTimer = setTimeout(() => settle('FAILED'), restoreDeadline - Date.now());
    if (typeof deadlineTimer.unref === 'function') deadlineTimer.unref();

    if (parent.isDestroyed() || parent.webContents.isDestroyed()) {
      settle('FAILED');
      return;
    }

    try {
      void restoreWindow
        .loadURL(dataUrl)
        .then(() => {
          if (settled) return;
          if (parent.isDestroyed() || parent.webContents.isDestroyed()) {
            settle('FAILED');
            return;
          }
          contents.on('will-navigate', onWillNavigate);
          contents.on('will-redirect', onWillRedirect);
          navigationArmed = true;
          restoreWindow.show();
          restoreWindow.focus();
        })
        .catch(() => settle('FAILED'));
    } catch {
      settle('FAILED');
    }
  });
}
