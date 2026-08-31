import { randomBytes, timingSafeEqual } from 'node:crypto';
import { BrowserWindow, Notification } from 'electron';

import type { AccordLockActionApprovalChallenge } from './accordlockActionApproval';
import { intentReviewCopy } from './accordlock/intentReview';
import { relevantUserLimits } from './accordlock/taskIntent';

const DECISION_ORIGIN = 'https://accordlock.invalid';
const DECISION_PATH = '/decision';
const NONCE_BYTES = 32;
const MAX_APPROVAL_OPEN_MILLISECONDS = 5 * 60 * 1_000;

const ACTION_APPROVAL_NOTIFICATION = {
  title: 'Action needs approval',
  body: 'Work is waiting for your decision.',
} as const;

export type AccordLockActionApprovalTheme = 'light' | 'dark';

interface PreventableEvent {
  preventDefault(): void;
}

interface KeyboardInput {
  key: string;
  type: string;
}

function showActionApprovalNotification(approvalWindow: BrowserWindow): Notification | null {
  try {
    const notification = new Notification({
      ...ACTION_APPROVAL_NOTIFICATION,
      silent: false,
    });
    notification.on('click', () => {
      if (approvalWindow.isDestroyed()) return;
      approvalWindow.show();
      approvalWindow.focus();
    });
    notification.show();
    return notification;
  } catch {
    // Notifications are an availability aid, never part of the authorization path.
    return null;
  }
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

function exactChangeMarkup(challenge: AccordLockActionApprovalChallenge): string {
  if (challenge.arguments.kind === 'write') {
    return `
      <section class="change-panel" aria-labelledby="content-heading">
        <h2 id="content-heading">New file <span>Full content · hidden characters shown</span></h2>
        <pre>${escapeHtml(visibleExactText(challenge.arguments.content))}</pre>
      </section>`;
  }

  if (challenge.arguments.kind === 'edit') {
    return `
    <div class="diff-grid" aria-label="Complete proposed replacement">
      <section class="change-panel before" aria-labelledby="before-heading">
        <h2 id="before-heading">Current text</h2>
        <pre>${escapeHtml(visibleExactText(challenge.arguments.before))}</pre>
      </section>
      <section class="change-panel after" aria-labelledby="after-heading">
        <h2 id="after-heading">Replacement</h2>
        <pre>${escapeHtml(visibleExactText(challenge.arguments.after))}</pre>
      </section>
    </div>`;
  }

  if (challenge.arguments.kind === 'delete_file') {
    const exact = [
      `FILE: ${JSON.stringify(challenge.arguments.path)}`,
      'ACTION: Move this file to recovery',
      'FOLDERS: Not allowed',
      'RECOVERY: The activity record will include its recovery path',
    ].join('\n');
    return `
      <section class="change-panel" aria-labelledby="delete-heading">
        <h2 id="delete-heading">File move details <span>Recoverable · not recursive</span></h2>
        <pre>${escapeHtml(visibleExactText(exact))}</pre>
      </section>`;
  }

  if (challenge.arguments.kind === 'https_request') {
    const exact = [
      `METHOD: ${challenge.arguments.method}`,
      `URL: ${JSON.stringify(challenge.arguments.url)}`,
      `TIMEOUT: ${challenge.arguments.timeoutSeconds}s`,
      `RESPONSE LIMIT: ${challenge.arguments.maxResponseBytes} bytes`,
      'REQUEST HEADERS: none',
      'REQUEST BODY: none',
      'REDIRECTS: blocked',
      'PROXIES AND AMBIENT CREDENTIALS: blocked',
    ].join('\n');
    return `
      <section class="change-panel" aria-labelledby="network-heading">
        <h2 id="network-heading">HTTPS request <span>Exact destination · read-only</span></h2>
        <pre>${escapeHtml(visibleExactText(exact))}</pre>
      </section>`;
  }

  const argv = challenge.arguments.argv
    .map((argument, index) => `${index}: ${JSON.stringify(argument)}`)
    .join('\n');
  const environment = Object.entries(challenge.arguments.env)
    .sort(([left], [right]) => left.localeCompare(right, 'en-US'))
    .map(([name, value]) => `${name}=${JSON.stringify(value)}`)
    .join('\n');
  const exact = [
    'ARGV — direct process invocation; no shell parser',
    argv,
    '',
    `CWD: ${JSON.stringify(challenge.arguments.path)}`,
    `TIMEOUT: ${challenge.arguments.timeoutSeconds}s`,
    `OUTPUT LIMIT: ${challenge.arguments.maxOutputBytes} bytes`,
    '',
    'ENVIRONMENT — strict non-secret allowlist',
    environment || '(none)',
  ].join('\n');
  return `
    <section class="change-panel" aria-labelledby="command-heading">
      <h2 id="command-heading">Command to run <span>Exact arguments · no shell parsing</span></h2>
      <pre>${escapeHtml(visibleExactText(exact))}</pre>
    </section>`;
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

function buildApprovalDocument(
  challenge: AccordLockActionApprovalChallenge,
  objective: string,
  nonce: string,
  theme: AccordLockActionApprovalTheme
): string {
  const target = escapeHtml(visibleExactText(challenge.target));
  const workspace = escapeHtml(visibleExactText(challenge.workspaceRoot));
  const targetLabel = escapeHtml(challenge.targetLabel);
  const quantityLabel = escapeHtml(challenge.quantityLabel);
  const action = escapeHtml(challenge.operationLabel);
  const escapedObjective = escapeHtml(visibleExactText(objective));
  const escapedNonce = escapeHtml(nonce);
  const evidence = escapeHtml(challenge.contentEvidence);
  const proposalDigest = escapeHtml(challenge.proposalDigest);
  const intentReview = intentReviewCopy(challenge.approvalRequest.policy_decision);
  const requestedBytes = challenge.approvalRequest.action.requested_bytes.toLocaleString('en-US');
  const quantityValue =
    challenge.arguments.kind === 'shell'
      ? `${challenge.arguments.argv.length.toLocaleString('en-US')} ${
          challenge.arguments.argv.length === 1 ? 'argument' : 'arguments'
        }`
      : challenge.arguments.kind === 'https_request'
        ? `${challenge.arguments.maxResponseBytes.toLocaleString('en-US')} bytes`
        : `${requestedBytes} bytes`;
  const userLimits = relevantUserLimits(objective, challenge.arguments.kind);
  const userLimitMarkup =
    userLimits.length > 0
      ? `<aside class="limit-reminder" aria-label="Limit from your request">
          <span>From your request</span>
          <ul>${userLimits
            .map((limit) => `<li>${escapeHtml(visibleExactText(limit))}</li>`)
            .join('')}</ul>
        </aside>`
      : '';
  const darkTheme = theme === 'dark';
  const darkThemeStyles = darkTheme
    ? `
      :root, body { background: #191a18; color: #f3f4f1; }
      .window-bar, .intro, .task-label, dt, h2 span, .folder, .approval-scope, .verification summary { color: #a3a79f; }
      .window-close { color: #aeb1aa; }
      .window-close:hover { background: #30322f; color: #fff; }
      .task-context { border-color: #565a53; }
      .limit-reminder { border-color: #705f35; background: #302b1f; }
      .limit-reminder span { color: #d8bd78; }
      .limit-reminder li { color: #f1e6c8; }
      .intent-review { background: #2a2c29; }
      .intent-review span { color: #aeb1aa; }
      .intent-review strong { color: #f1f2ee; }
      .action-card, .change-panel { border-color: #393c39; background: #232522; }
      .action-row + .action-row, .change-panel h2 { border-color: #393c39; }
      .change-panel h2 { color: #d4d7d1; }
      dd, .task-context p, .action-name, .target { color: #f1f2ee; }
      .before h2 { color: #efaaa3; background: #302321; }
      .after h2 { color: #a9d8b3; background: #203027; }
      pre { background: #1c1e1c; color: #f1f2ef; }
      .verification { border-color: #393c39; }
      .verification summary:hover { color: #f1f2ee; }
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
    <title>Approve action · AccordLock</title>
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
        width: min(100%, 720px);
        margin: 0 auto;
        padding: 14px 28px 24px;
        overflow-y: auto;
        scrollbar-gutter: stable;
      }
      h1 { margin: 0; font-size: 28px; font-weight: 650; letter-spacing: -.035em; }
      .intro { max-width: 560px; margin: 8px 0 16px; color: #666a63; font-size: 14px; line-height: 1.5; }
      .task-context {
        margin: 0 0 14px;
        padding-left: 12px;
        border-left: 2px solid #c9ccc6;
      }
      .task-label { color: #696d66; font-size: 10px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
      .task-context p { max-height: 88px; margin: 4px 0 0; overflow: auto; color: #292a27; font-size: 13px; line-height: 1.45; white-space: pre-wrap; unicode-bidi: plaintext; }
      .limit-reminder {
        margin: 0 0 14px;
        padding: 11px 14px;
        border: 1px solid #e3d19e;
        border-radius: 12px;
        background: #fffaf0;
      }
      .limit-reminder span { color: #765b17; font-size: 10px; font-weight: 700; letter-spacing: .07em; text-transform: uppercase; }
      .limit-reminder ul { display: grid; gap: 4px; margin: 6px 0 0; padding-left: 18px; }
      .limit-reminder li { color: #40391f; font-size: 12px; line-height: 1.45; white-space: pre-wrap; unicode-bidi: plaintext; }
      .intent-review {
        margin: 0 0 14px;
        padding: 11px 14px;
        border-radius: 12px;
        background: #e9eae6;
      }
      .intent-review span { color: #565a53; font-size: 10px; font-weight: 700; letter-spacing: .07em; text-transform: uppercase; }
      .intent-review strong { display: block; margin-top: 4px; color: #292a27; font-size: 12px; font-weight: 500; line-height: 1.45; }
      .action-card, .change-panel {
        overflow: hidden;
        border: 1px solid #dedfda;
        border-radius: 14px;
        background: #fff;
      }
      .action-row { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 22px; padding: 13px 16px; }
      .action-row + .action-row { border-top: 1px solid #e8e9e5; }
      .action-field { min-width: 0; }
      .amount { text-align: right; }
      dt { margin: 0 0 4px; color: #696d66; font-size: 10px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
      dd { margin: 0; overflow-wrap: anywhere; color: #22231f; font-size: 13px; line-height: 1.45; white-space: pre-wrap; unicode-bidi: plaintext; }
      .action-name { font-size: 15px; font-weight: 650; }
      .target { font-family: ui-monospace, "SFMono-Regular", Consolas, monospace; font-size: 12px; }
      .folder { margin: 5px 0 0; overflow-wrap: anywhere; color: #696d66; font-size: 11px; unicode-bidi: plaintext; }
      .diff-grid { display: grid; gap: 10px; }
      .change-panel { margin-top: 10px; }
      .change-panel h2 {
        display: flex;
        align-items: baseline;
        justify-content: space-between;
        gap: 12px;
        margin: 0;
        padding: 11px 15px;
        border-bottom: 1px solid #e2e3e0;
        color: #4c504a;
        font-size: 12px;
        font-weight: 650;
      }
      .change-panel h2 span { color: #696d66; font-size: 10px; font-weight: 500; white-space: nowrap; }
      .before h2 { color: #8a443f; background: #fff7f5; }
      .after h2 { color: #31633e; background: #f4faf5; }
      pre {
        min-height: 64px;
        max-height: 280px;
        margin: 0;
        padding: 15px;
        overflow: auto;
        background: #fbfbfa;
        color: #20211f;
        font: 12px/1.55 ui-monospace, "SFMono-Regular", Consolas, "Liberation Mono", monospace;
        tab-size: 2;
        white-space: pre;
        unicode-bidi: plaintext;
      }
      .verification { margin-top: 12px; padding-top: 10px; border-top: 1px solid #dedfda; }
      .verification summary {
        width: fit-content;
        border-radius: 6px;
        color: #696d66;
        cursor: pointer;
        font-size: 12px;
        font-weight: 600;
      }
      .verification summary:hover { color: #292a27; }
      .verification summary:focus-visible { outline: 3px solid #7896e8; outline-offset: 3px; }
      .verification-grid { display: grid; gap: 9px; padding: 12px 2px 2px; }
      .verification dd { font-family: ui-monospace, "SFMono-Regular", Consolas, monospace; font-size: 10px; overflow-wrap: anywhere; }
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
        width: min(100%, 720px);
        margin: 0 auto;
        padding: 12px 28px;
      }
      .approval-scope { margin: 0; color: #696d66; font-size: 11px; line-height: 1.4; }
      .buttons {
        display: flex;
        justify-content: flex-end;
        gap: 8px;
        flex-shrink: 0;
      }
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
      @media (max-width: 620px) {
        main { padding: 10px 18px 18px; }
        .action-row { grid-template-columns: 1fr; gap: 10px; }
        .amount { text-align: left; }
        .change-panel h2 { align-items: flex-start; flex-direction: column; gap: 3px; }
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
      <h1>Approve this action?</h1>

      <section class="task-context" aria-label="Task context">
        <span class="task-label">Task</span>
        <p>${escapedObjective}</p>
      </section>

      ${userLimitMarkup}

      <aside class="intent-review" aria-label="Task check">
        <span>Task check</span>
        <strong>${escapeHtml(intentReview.description)}</strong>
      </aside>

      <section class="action-card" aria-label="Action summary">
        <dl class="action-row">
          <div class="action-field">
            <dt>Action</dt>
            <dd class="action-name">${action}</dd>
          </div>
          <div class="action-field amount">
            <dt>${quantityLabel}</dt>
            <dd>${quantityValue}</dd>
          </div>
        </dl>
        <dl class="action-row">
          <div class="action-field">
            <dt>${targetLabel}</dt>
            <dd class="target">${target}</dd>
            <p class="folder">Folder · ${workspace}</p>
          </div>
        </dl>
      </section>

      ${exactChangeMarkup(challenge)}

      <details class="verification">
        <summary>Verification details</summary>
        <dl class="verification-grid">
          <div>
            <dt>Content hash</dt>
            <dd>${evidence}</dd>
          </div>
          <div>
            <dt>Proposal hash</dt>
            <dd>${proposalDigest}</dd>
          </div>
        </dl>
      </details>
    </main>

    <footer class="actions-shell">
      <div class="actions">
        <p class="approval-scope">Applies once.</p>
        <div class="buttons">
          ${decisionForm(escapedNonce, 'deny', "Don't run", 'cancel')}
          ${decisionForm(escapedNonce, 'approve', 'Approve once', 'approve')}
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

function isExactApprovalNavigation(rawUrl: string, expectedNonce: string): boolean {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return false;
  }

  if (
    url.origin !== DECISION_ORIGIN ||
    url.pathname !== DECISION_PATH ||
    url.hash !== '' ||
    url.username !== '' ||
    url.password !== ''
  ) {
    return false;
  }

  const keys = [...url.searchParams.keys()].sort();
  if (keys.length !== 2 || keys[0] !== 'decision' || keys[1] !== 'nonce') return false;

  const nonceValues = url.searchParams.getAll('nonce');
  const decisionValues = url.searchParams.getAll('decision');
  return (
    nonceValues.length === 1 &&
    decisionValues.length === 1 &&
    nonceMatches(nonceValues[0], expectedNonce) &&
    decisionValues[0] === 'approve'
  );
}

/**
 * Shows a main-process-only approval surface for an exact protected AccordLock action.
 * The promise resolves true only after a nonce-bound approval navigation from the isolated child.
 */
export function showAccordLockActionApprovalWindow(
  parent: BrowserWindow,
  challenge: AccordLockActionApprovalChallenge,
  objective: string,
  taskExpiresAtSeconds: number,
  theme: AccordLockActionApprovalTheme = 'light'
): Promise<boolean> {
  const now = Date.now();
  const taskDeadline = taskExpiresAtSeconds * 1_000;
  if (
    parent.isDestroyed() ||
    parent.webContents.isDestroyed() ||
    !Number.isSafeInteger(taskExpiresAtSeconds) ||
    taskDeadline <= now
  ) {
    return Promise.resolve(false);
  }
  const approvalDeadline = Math.min(taskDeadline, now + MAX_APPROVAL_OPEN_MILLISECONDS);

  const nonce = randomBytes(NONCE_BYTES).toString('hex');
  const document = buildApprovalDocument(challenge, objective, nonce, theme);
  const dataUrl = buildDataUrl(document);

  let approvalWindow: BrowserWindow;
  try {
    approvalWindow = new BrowserWindow({
      parent,
      modal: true,
      show: false,
      width: 780,
      height: 700,
      minWidth: 500,
      minHeight: 520,
      resizable: true,
      minimizable: false,
      maximizable: false,
      fullscreenable: false,
      skipTaskbar: true,
      autoHideMenuBar: true,
      title: 'Approve action · AccordLock',
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
        partition: `accordlock-approval-${nonce}`,
      },
    });
  } catch {
    return Promise.resolve(false);
  }

  approvalWindow.removeMenu();
  approvalWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));

  return new Promise<boolean>((resolve) => {
    const contents = approvalWindow.webContents;
    let settled = false;
    let navigationArmed = false;
    let deadlineTimer: ReturnType<typeof setTimeout> | undefined;
    let notification: Notification | null = null;

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
      notification?.close();
      notification = null;
    };

    const settle = (approved: boolean) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (!approvalWindow.isDestroyed()) approvalWindow.destroy();
      resolve(approved);
    };

    const onParentClosed = () => settle(false);
    const onParentContentsDestroyed = () => settle(false);
    const onApprovalClosed = () => settle(false);
    const onApprovalUnresponsive = () => settle(false);
    const onRendererGone = () => settle(false);
    const onLoadFailure = () => settle(false);
    const onWillAttachWebview = (event: PreventableEvent) => event.preventDefault();
    const onWillRedirect = (event: PreventableEvent) => {
      event.preventDefault();
      settle(false);
    };
    const onWillNavigate = (event: PreventableEvent, url: string) => {
      event.preventDefault();
      settle(isExactApprovalNavigation(url, nonce));
    };
    const onBeforeInput = (event: PreventableEvent, input: KeyboardInput) => {
      if (input.type === 'keyDown' && input.key === 'Escape') {
        event.preventDefault();
        settle(false);
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
    deadlineTimer = setTimeout(() => settle(false), approvalDeadline - Date.now());
    if (typeof deadlineTimer.unref === 'function') deadlineTimer.unref();

    if (parent.isDestroyed() || parent.webContents.isDestroyed()) {
      settle(false);
      return;
    }

    try {
      void approvalWindow
        .loadURL(dataUrl)
        .then(() => {
          if (settled) return;
          if (parent.isDestroyed() || parent.webContents.isDestroyed()) {
            settle(false);
            return;
          }
          contents.on('will-navigate', onWillNavigate);
          contents.on('will-redirect', onWillRedirect);
          navigationArmed = true;
          approvalWindow.show();
          notification = showActionApprovalNotification(approvalWindow);
        })
        .catch(() => settle(false));
    } catch {
      settle(false);
    }
  });
}
