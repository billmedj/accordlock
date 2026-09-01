import { randomBytes, timingSafeEqual } from 'node:crypto';
import { BrowserWindow } from 'electron';

import type {
  AccordLockTaskAccessMode,
  AccordLockTaskAccessSelection,
  AccordLockTaskAuthorization,
} from './accordlock/taskIpc';
import { buildTaskIntentBrief, literalBlockingUserLimit } from './accordlock/taskIntent';

const DECISION_ORIGIN = 'https://accordlock.invalid';
const DECISION_PATH = '/task-decision';
const NONCE_BYTES = 32;
const MAX_APPROVAL_OPEN_MILLISECONDS = 5 * 60 * 1_000;

export type AccordLockTaskApprovalResult =
  | { status: 'APPROVED'; access: AccordLockTaskAccessSelection }
  | { status: 'CANCELLED' }
  | { status: 'FAILED' };
export type AccordLockTaskApprovalTheme = 'light' | 'dark';

const EXPECTED_CAPABILITIES = [
  'developer/delete_file/WRITE',
  'developer/edit/WRITE',
  'developer/read/READ',
  'developer/shell/EXECUTE',
  'developer/tree/READ',
  'developer/write/WRITE',
] as const;
const EXPECTED_NETWORK_CAPABILITY = 'accordlock_network/https_request/NETWORK' as const;
const REQUIRED_CAPABILITIES = ['developer/read/READ', 'developer/tree/READ'] as const;
const FILE_CHANGE_CAPABILITIES = [
  'developer/delete_file/WRITE',
  'developer/edit/WRITE',
  'developer/write/WRITE',
] as const;
const EXPECTED_AUTOMATIC_CAPABILITIES = ['developer/read', 'developer/tree'] as const;
const EXPECTED_PROTECTED_PATHS = [
  '.accordlock',
  '.env',
  '.git',
  '.goose',
  '.goosehints',
  '.ssh',
  'credentials',
] as const;

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

/**
 * Makes non-printing and direction-changing characters explicit while keeping
 * ordinary prose and Windows path separators readable.
 */
function visibleTrustedReviewText(value: string): string {
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
    if (character === '\r') {
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

/** Removes only Windows' presentation-only extended path prefix. */
function displayWorkspacePath(workspaceRoot: string): string {
  const extendedUncPrefix = '\\\\?\\UNC\\';
  const extendedPrefix = '\\\\?\\';
  if (
    workspaceRoot.slice(0, extendedUncPrefix.length).toUpperCase() ===
    extendedUncPrefix.toUpperCase()
  ) {
    return `\\\\${workspaceRoot.slice(extendedUncPrefix.length)}`;
  }
  if (workspaceRoot.startsWith(extendedPrefix)) {
    return workspaceRoot.slice(extendedPrefix.length);
  }
  return workspaceRoot;
}

function sameSortedValues(actual: readonly string[], expected: readonly string[]): boolean {
  if (actual.length !== expected.length) return false;
  const sorted = [...actual].sort((left, right) => left.localeCompare(right, 'en-US'));
  return sorted.every((value, index) => value === expected[index]);
}

/**
 * The compact copy below describes one closed policy profile. Refuse to show a
 * misleading approval surface if that profile changes before its copy does.
 */
function hasSupportedPresentationProfile(authorization: AccordLockTaskAuthorization): boolean {
  const capabilities = authorization.capabilities.map(
    ({ extension_id, tool_name, operation_type }) =>
      `${extension_id}/${tool_name}/${operation_type}`
  );
  const automaticCapabilities = authorization.task_policy.preauthorized_capabilities.map(
    ({ extension_id, tool_name }) => `${extension_id}/${tool_name}`
  );
  const capabilitySet = new Set(capabilities);
  const supportedCapabilities = new Set<string>([
    EXPECTED_NETWORK_CAPABILITY,
    ...EXPECTED_CAPABILITIES,
  ]);
  const fileChangeCount = FILE_CHANGE_CAPABILITIES.filter((value) =>
    capabilitySet.has(value)
  ).length;
  return (
    capabilitySet.size === capabilities.length &&
    capabilities.every((value) => supportedCapabilities.has(value)) &&
    REQUIRED_CAPABILITIES.every((value) => capabilitySet.has(value)) &&
    (fileChangeCount === 0 || fileChangeCount === FILE_CHANGE_CAPABILITIES.length) &&
    sameSortedValues(automaticCapabilities, EXPECTED_AUTOMATIC_CAPABILITIES) &&
    sameSortedValues(authorization.task_policy.protected_paths, EXPECTED_PROTECTED_PATHS)
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
  const id = decision === 'approve' ? ' id="task-approval-form"' : '';
  return `<form${id} action="${DECISION_ORIGIN}${DECISION_PATH}" method="get" autocomplete="off">
    <input type="hidden" name="nonce" value="${nonce}">
    <input type="hidden" name="decision" value="${decision}">
    <button class="${css}" type="submit"${autofocus}${accessibleName}>${label}</button>
  </form>`;
}

function taskHasCapability(
  authorization: AccordLockTaskAuthorization,
  extensionId: string,
  toolName: string
): boolean {
  return authorization.capabilities.some(
    ({ extension_id, tool_name }) => extension_id === extensionId && tool_name === toolName
  );
}

function accessControl(
  name: keyof AccordLockTaskAccessSelection,
  label: string,
  value: AccordLockTaskAccessMode,
  fixedState?: string
): string {
  if (fixedState) {
    return `<li>
      <span class="dot"></span>
      <span class="access-label">${label}</span>
      <input form="task-approval-form" type="hidden" name="${name}" value="BLOCKED">
      <span class="access-state">${fixedState}</span>
    </li>`;
  }
  return `<li>
    <span class="dot${value === 'ASK' ? ' ask' : ''}"></span>
    <label class="access-label" for="access-${name}">${label}</label>
    <select form="task-approval-form" id="access-${name}" name="${name}">
      <option value="ASK"${value === 'ASK' ? ' selected' : ''}>Ask each time</option>
      <option value="BLOCKED"${value === 'BLOCKED' ? ' selected' : ''}>Blocked</option>
    </select>
  </li>`;
}

function buildApprovalDocument(
  authorization: AccordLockTaskAuthorization,
  nonce: string,
  theme: AccordLockTaskApprovalTheme,
  networkAvailable: boolean
): string {
  const intent = buildTaskIntentBrief(authorization);
  const objective = escapeHtml(visibleTrustedReviewText(intent.outcome));
  const workspace = escapeHtml(visibleTrustedReviewText(displayWorkspacePath(intent.workspace)));
  const normalizedOutcome = intent.outcome.replace(/\s+/gu, ' ').trim();
  const visibleLimits = intent.userLimits.filter((limit) => limit !== normalizedOutcome);
  const limitsMarkup =
    visibleLimits.length > 0
      ? `<div class="field">
          <dt>Your limits</dt>
          <dd><ul class="intent-limits">${visibleLimits
            .map((limit) => `<li>${escapeHtml(visibleTrustedReviewText(limit))}</li>`)
            .join('')}</ul></dd>
        </div>`
      : '';
  const accessEnds = escapeHtml(
    new Date(authorization.expires_at * 1_000).toLocaleString('en-US', {
      dateStyle: 'medium',
      timeStyle: 'short',
    })
  );
  const escapedNonce = escapeHtml(nonce);
  const darkTheme = theme === 'dark';
  const fileChangesEnabled = taskHasCapability(authorization, 'developer', 'write');
  const commandsEnabled = taskHasCapability(authorization, 'developer', 'shell');
  const networkEnabled = taskHasCapability(authorization, 'accordlock_network', 'https_request');
  const fileChangesBlocked = literalBlockingUserLimit(intent.outcome, 'write') !== null;
  const commandsBlocked = literalBlockingUserLimit(intent.outcome, 'shell') !== null;
  const networkBlocked = literalBlockingUserLimit(intent.outcome, 'https_request') !== null;
  const fileAccessControl = accessControl(
    'file_changes',
    'Change files',
    fileChangesEnabled ? 'ASK' : 'BLOCKED',
    fileChangesBlocked ? 'Blocked by your request' : undefined
  );
  const terminalAccessControl = accessControl(
    'terminal',
    'Run terminal commands',
    commandsEnabled ? 'ASK' : 'BLOCKED',
    commandsBlocked ? 'Blocked by your request' : undefined
  );
  const networkAccessControl = accessControl(
    'network',
    'Read allowed websites',
    networkEnabled ? 'ASK' : 'BLOCKED',
    networkBlocked ? 'Blocked by your request' : networkAvailable ? undefined : 'Set up in Settings'
  );
  const darkThemeStyles = darkTheme
    ? `
      :root, body { background: #191a18; color: #f3f4f1; }
      .window-bar, .intro, dt, .access-state, .expiry { color: #a2a69e; }
      .window-close { color: #aeb1aa; }
      .window-close:hover { background: #30322f; color: #fff; }
      .card { border-color: #383b37; background: #232522; }
      .field + .field, .access li + li { border-color: #353834; }
      dd, .access-label { color: #f1f2ee; }
      .actions-shell { border-color: #383b37; background: rgb(28 30 27 / 96%); }
      button, select { border-color: #484c46; background: #282b27; color: #f2f3ef; }
      .start { border-color: #f1f2ee; background: #f1f2ee; color: #171816; }
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
    <title>Start task · AccordLock</title>
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
        padding: 0 8px 0 20px;
        color: #777a74;
        font-size: 11px;
        font-weight: 600;
        letter-spacing: .01em;
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
        width: min(100%, 600px);
        margin: 0 auto;
        padding: 12px 26px 20px;
        overflow-y: auto;
        scrollbar-gutter: stable;
      }
      h1 { margin: 0; font-size: 27px; font-weight: 650; letter-spacing: -.035em; }
      .intro { max-width: 520px; margin: 8px 0 18px; color: #666a63; font-size: 14px; line-height: 1.5; }
      .card {
        overflow: hidden;
        margin-top: 10px;
        border: 1px solid #dedfda;
        border-radius: 14px;
        background: #fff;
      }
      .field { padding: 13px 16px; }
      .field + .field { border-top: 1px solid #e8e9e5; }
      dt { margin: 0 0 5px; color: #777b73; font-size: 10px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
      dd { margin: 0; overflow-wrap: anywhere; color: #22231f; font-size: 13px; line-height: 1.45; white-space: pre-wrap; unicode-bidi: plaintext; }
      .intent-limits { display: grid; gap: 4px; margin: 0; padding-left: 18px; }
      .workspace { font-family: ui-monospace, "SFMono-Regular", Consolas, monospace; font-size: 12px; }
      .access { margin: 0; padding: 3px 0; list-style: none; }
      .access li {
        display: grid;
        grid-template-columns: 8px minmax(0, 1fr) auto;
        gap: 9px;
        align-items: center;
        min-height: 38px;
        padding: 0 16px;
      }
      .access li + li { border-top: 1px solid #eeefeb; }
      .dot { width: 6px; height: 6px; border-radius: 50%; background: #8a8e86; }
      .dot.allowed { background: #4b8b60; }
      .dot.ask { background: #b78532; }
      .access-label { min-width: 0; font-size: 13px; }
      .access-state { color: #777b73; font-size: 11px; white-space: nowrap; }
      select {
        min-width: 112px;
        min-height: 30px;
        padding: 0 28px 0 10px;
        border: 1px solid #d7d9d3;
        border-radius: 8px;
        background: #fff;
        color: #282a26;
        font: inherit;
        font-size: 11px;
        cursor: pointer;
      }
      select:focus-visible { outline: 3px solid #7896e8; outline-offset: 2px; }
      .expiry { margin: 12px 2px 0; color: #777b73; font-size: 11px; }
      .actions-shell {
        border-top: 1px solid #dedfda;
        background: rgb(250 250 248 / 96%);
        backdrop-filter: blur(16px);
      }
      .actions {
        display: flex;
        justify-content: flex-end;
        gap: 8px;
        width: min(100%, 600px);
        margin: 0 auto;
        padding: 12px 26px;
      }
      form { margin: 0; }
      button {
        min-height: 40px;
        padding: 0 16px;
        border: 1px solid #d0d2cc;
        border-radius: 10px;
        background: #fff;
        color: #20211e;
        font: inherit;
        font-size: 13px;
        font-weight: 650;
        cursor: pointer;
      }
      button:focus-visible { outline: 3px solid #7896e8; outline-offset: 2px; }
      .start { border-color: #20221f; background: #20221f; color: #fff; }
      @media (max-width: 560px) {
        main { padding: 10px 18px 18px; }
        .actions { padding: 11px 18px; }
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
      <h1>Review this task</h1>
      <p class="intro">Choose what the agent can use. These limits lock when the task starts.</p>

      <dl class="card">
        <div class="field">
          <dt>Outcome</dt>
          <dd>${objective}</dd>
        </div>
        <div class="field">
          <dt>Folder</dt>
          <dd class="workspace">${workspace}</dd>
        </div>
        ${limitsMarkup}
      </dl>

      <section class="card" aria-label="Access">
        <ul class="access">
          <li><span class="dot allowed"></span><span class="access-label">Read files and browse folders</span><span class="access-state">Automatic</span></li>
          ${fileAccessControl}
          ${terminalAccessControl}
          ${networkAccessControl}
          <li><span class="dot"></span><span class="access-label">Administrator access</span><span class="access-state">Blocked</span></li>
          <li><span class="dot"></span><span class="access-label">Open protected settings or credentials</span><span class="access-state">Blocked</span></li>
        </ul>
      </section>
      <p class="expiry">Access ends ${accessEnds}</p>
    </main>

    <footer class="actions-shell">
      <div class="actions">
        ${decisionForm(escapedNonce, 'deny', 'Cancel', 'cancel')}
        ${decisionForm(escapedNonce, 'approve', 'Start task', 'start')}
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

function decisionNavigationResult(
  rawUrl: string,
  expectedNonce: string
): AccordLockTaskApprovalResult {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return { status: 'FAILED' };
  }

  if (
    url.origin !== DECISION_ORIGIN ||
    url.pathname !== DECISION_PATH ||
    url.hash !== '' ||
    url.username !== '' ||
    url.password !== ''
  ) {
    return { status: 'FAILED' };
  }

  const keys = [...url.searchParams.keys()].sort();
  const nonceValues = url.searchParams.getAll('nonce');
  const decisionValues = url.searchParams.getAll('decision');
  if (
    nonceValues.length !== 1 ||
    decisionValues.length !== 1 ||
    !nonceMatches(nonceValues[0], expectedNonce)
  ) {
    return { status: 'FAILED' };
  }

  if (decisionValues[0] === 'deny') {
    return keys.length === 2 && keys[0] === 'decision' && keys[1] === 'nonce'
      ? { status: 'CANCELLED' }
      : { status: 'FAILED' };
  }
  if (decisionValues[0] !== 'approve') return { status: 'FAILED' };
  const expectedKeys = ['decision', 'file_changes', 'network', 'nonce', 'terminal'];
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key, index) => key !== expectedKeys[index])
  ) {
    return { status: 'FAILED' };
  }
  const accessNames = ['file_changes', 'terminal', 'network'] as const;
  const access = {} as AccordLockTaskAccessSelection;
  for (const name of accessNames) {
    const values = url.searchParams.getAll(name);
    if (values.length !== 1 || (values[0] !== 'ASK' && values[0] !== 'BLOCKED')) {
      return { status: 'FAILED' };
    }
    access[name] = values[0];
  }
  return { status: 'APPROVED', access };
}

/**
 * Shows a main-process-owned, scriptless review for one verified task authority.
 * Only an exact nonce-bound approval from this isolated child resolves APPROVED.
 */
export function showAccordLockTaskApprovalWindow(
  parent: BrowserWindow,
  authorization: AccordLockTaskAuthorization,
  theme: AccordLockTaskApprovalTheme = 'light',
  networkAvailable = taskHasCapability(authorization, 'accordlock_network', 'https_request')
): Promise<AccordLockTaskApprovalResult> {
  const now = Date.now();
  const taskDeadline = authorization.expires_at * 1_000;
  if (
    parent.isDestroyed() ||
    parent.webContents.isDestroyed() ||
    !Number.isSafeInteger(authorization.expires_at) ||
    !Number.isSafeInteger(taskDeadline) ||
    taskDeadline <= now ||
    !hasSupportedPresentationProfile(authorization)
  ) {
    return Promise.resolve({ status: 'FAILED' });
  }
  const approvalDeadline = Math.min(taskDeadline, now + MAX_APPROVAL_OPEN_MILLISECONDS);

  const nonce = randomBytes(NONCE_BYTES).toString('hex');
  const document = buildApprovalDocument(authorization, nonce, theme, networkAvailable);
  const dataUrl = buildDataUrl(document);

  let approvalWindow: BrowserWindow;
  try {
    approvalWindow = new BrowserWindow({
      parent,
      modal: true,
      show: false,
      width: 620,
      height: 610,
      minWidth: 480,
      minHeight: 500,
      resizable: true,
      minimizable: false,
      maximizable: false,
      fullscreenable: false,
      skipTaskbar: true,
      autoHideMenuBar: true,
      title: 'Start task · AccordLock',
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
        partition: `accordlock-task-approval-${nonce}`,
      },
    });
  } catch {
    return Promise.resolve({ status: 'FAILED' });
  }

  approvalWindow.removeMenu();
  approvalWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));

  return new Promise<AccordLockTaskApprovalResult>((resolve) => {
    const contents = approvalWindow.webContents;
    let settled = false;
    let navigationArmed = false;
    let deadlineTimer: ReturnType<typeof setTimeout> | undefined;

    const cleanup = () => {
      parent.removeListener('closed', onParentClosed);
      parent.webContents.removeListener('destroyed', onParentContentsDestroyed);
      approvalWindow.removeListener('closed', onApprovalClosed);
      approvalWindow.removeListener('unresponsive', onApprovalUnresponsive);
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

    const settle = (result: AccordLockTaskApprovalResult) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (!approvalWindow.isDestroyed()) approvalWindow.destroy();
      resolve(result);
    };

    const onParentClosed = () => settle({ status: 'CANCELLED' });
    const onParentContentsDestroyed = () => settle({ status: 'FAILED' });
    const onApprovalClosed = () => settle({ status: 'CANCELLED' });
    const onApprovalUnresponsive = () => settle({ status: 'FAILED' });
    const onRendererGone = () => settle({ status: 'FAILED' });
    const onLoadFailure = () => settle({ status: 'FAILED' });
    const onWillAttachWebview = (event: PreventableEvent) => event.preventDefault();
    const onWillRedirect = (event: PreventableEvent) => {
      event.preventDefault();
      settle({ status: 'FAILED' });
    };
    const onWillNavigate = (event: PreventableEvent, url: string) => {
      event.preventDefault();
      settle(decisionNavigationResult(url, nonce));
    };
    const onBeforeInput = (event: PreventableEvent, input: KeyboardInput) => {
      if (input.type === 'keyDown' && input.key === 'Escape') {
        event.preventDefault();
        settle({ status: 'CANCELLED' });
      }
    };

    parent.once('closed', onParentClosed);
    parent.webContents.once('destroyed', onParentContentsDestroyed);
    approvalWindow.once('closed', onApprovalClosed);
    approvalWindow.once('unresponsive', onApprovalUnresponsive);
    contents.on('before-input-event', onBeforeInput);
    contents.once('did-fail-load', onLoadFailure);
    contents.once('render-process-gone', onRendererGone);
    contents.on('will-attach-webview', onWillAttachWebview);
    deadlineTimer = setTimeout(() => settle({ status: 'FAILED' }), approvalDeadline - Date.now());
    if (typeof deadlineTimer.unref === 'function') deadlineTimer.unref();

    if (parent.isDestroyed() || parent.webContents.isDestroyed()) {
      settle({ status: parent.isDestroyed() ? 'CANCELLED' : 'FAILED' });
      return;
    }

    try {
      void approvalWindow
        .loadURL(dataUrl)
        .then(() => {
          if (settled) return;
          if (parent.isDestroyed() || parent.webContents.isDestroyed()) {
            settle({ status: parent.isDestroyed() ? 'CANCELLED' : 'FAILED' });
            return;
          }
          contents.on('will-navigate', onWillNavigate);
          contents.on('will-redirect', onWillRedirect);
          navigationArmed = true;
          approvalWindow.show();
          approvalWindow.focus();
        })
        .catch(() => settle({ status: 'FAILED' }));
    } catch {
      settle({ status: 'FAILED' });
    }
  });
}
