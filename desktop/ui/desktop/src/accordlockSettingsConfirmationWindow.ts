import { randomBytes, timingSafeEqual } from 'node:crypto';
import { BrowserWindow } from 'electron';

const DECISION_ORIGIN = 'https://accordlock.invalid';
const DECISION_PATH = '/settings-decision';
const NONCE_BYTES = 32;
const MAX_CONFIRMATION_OPEN_MILLISECONDS = 5 * 60 * 1_000;
const MAX_TITLE_BYTES = 160;
const MAX_MESSAGE_BYTES = 1_024;
const MAX_DETAIL_BYTES = 32 * 1_024;
const MAX_BUTTON_LABEL_BYTES = 80;

export type AccordLockSettingsConfirmationTheme = 'light' | 'dark';
export type AccordLockSettingsConfirmationTone = 'warning' | 'info' | 'neutral';

export interface AccordLockSettingsConfirmationCopy {
  title: string;
  message: string;
  detail?: string;
  confirmLabel: string;
  cancelLabel: string;
  tone?: AccordLockSettingsConfirmationTone;
  defaultButton?: 'confirm' | 'cancel';
  buttonOrder?: 'confirm-first' | 'cancel-first';
}

interface TrustedConfirmationCopy {
  title: string;
  message: string;
  detail?: string;
  confirmLabel: string;
  cancelLabel: string;
  tone: AccordLockSettingsConfirmationTone;
  defaultButton: 'confirm' | 'cancel';
  buttonOrder: 'confirm-first' | 'cancel-first';
}

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

function visibleSafeText(value: string): string {
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
    if (character === '\n') {
      visible += '\n';
    } else if (character === '\r') {
      visible += '\\r';
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

function boundedText(value: unknown, maximumBytes: number): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    Buffer.byteLength(value, 'utf8') <= maximumBytes
  );
}

function trustedCopy(value: AccordLockSettingsConfirmationCopy): TrustedConfirmationCopy | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  if (
    !boundedText(value.title, MAX_TITLE_BYTES) ||
    !boundedText(value.message, MAX_MESSAGE_BYTES) ||
    !boundedText(value.confirmLabel, MAX_BUTTON_LABEL_BYTES) ||
    !boundedText(value.cancelLabel, MAX_BUTTON_LABEL_BYTES) ||
    (value.detail !== undefined && !boundedText(value.detail, MAX_DETAIL_BYTES))
  ) {
    return null;
  }

  const tone = value.tone ?? 'warning';
  const defaultButton = value.defaultButton ?? 'cancel';
  const buttonOrder = value.buttonOrder ?? 'cancel-first';
  if (
    !['warning', 'info', 'neutral'].includes(tone) ||
    !['confirm', 'cancel'].includes(defaultButton) ||
    !['confirm-first', 'cancel-first'].includes(buttonOrder)
  ) {
    return null;
  }

  return {
    title: visibleSafeText(value.title),
    message: visibleSafeText(value.message),
    detail: value.detail === undefined ? undefined : visibleSafeText(value.detail),
    confirmLabel: visibleSafeText(value.confirmLabel),
    cancelLabel: visibleSafeText(value.cancelLabel),
    tone,
    defaultButton,
    buttonOrder,
  };
}

function decisionForm(
  nonce: string,
  decision: 'confirm' | 'cancel',
  label: string,
  css: string,
  autofocus: boolean,
  ariaLabel?: string
): string {
  const focus = autofocus ? ' autofocus' : '';
  const accessibleName = ariaLabel ? ` aria-label="${escapeHtml(ariaLabel)}"` : '';
  return `<form action="${DECISION_ORIGIN}${DECISION_PATH}" method="get" target="_self" autocomplete="off">
    <input type="hidden" name="nonce" value="${nonce}">
    <input type="hidden" name="decision" value="${decision}">
    <button class="${css}" type="submit"${focus}${accessibleName}>${escapeHtml(label)}</button>
  </form>`;
}

function buildConfirmationDocument(
  copy: TrustedConfirmationCopy,
  nonce: string,
  theme: AccordLockSettingsConfirmationTheme
): string {
  const title = escapeHtml(copy.title);
  const message = escapeHtml(copy.message);
  const detail = copy.detail === undefined ? '' : escapeHtml(copy.detail);
  const cancelForm = decisionForm(
    nonce,
    'cancel',
    copy.cancelLabel,
    'cancel',
    copy.defaultButton === 'cancel'
  );
  const confirmForm = decisionForm(
    nonce,
    'confirm',
    copy.confirmLabel,
    `confirm ${copy.tone}`,
    copy.defaultButton === 'confirm'
  );
  const buttons =
    copy.buttonOrder === 'confirm-first'
      ? `${confirmForm}\n${cancelForm}`
      : `${cancelForm}\n${confirmForm}`;
  const detailsMarkup = detail
    ? `<section class="details" aria-label="Change details"><p>${detail}</p></section>`
    : '';
  const darkThemeStyles =
    theme === 'dark'
      ? `
      :root, body { background: #191a18; color: #f3f4f1; }
      .window-bar, .eyebrow { color: #a3a79f; }
      .window-close { color: #aeb1aa; }
      .window-close:hover { background: #30322f; color: #fff; }
      .message { color: #d7d9d4; }
      .details { border-color: #3d403b; background: #232522; }
      .details p { color: #f1f2ee; }
      .actions-shell { border-color: #393c39; background: rgb(28 30 27 / 96%); }
      button { border-color: #4a4e47; background: #282b27; color: #f2f3ef; }
      .confirm.info, .confirm.neutral { border-color: #f1f2ee; background: #f1f2ee; color: #171816; }
      .confirm.warning { border-color: #e7c46a; background: #e7c46a; color: #211b0d; }
    `
      : '';
  const customClose =
    process.platform === 'darwin'
      ? ''
      : decisionForm(nonce, 'cancel', '×', 'window-close', false, 'Cancel and close');

  return `<!doctype html>
<html lang="en" data-theme="${theme}">
  <head>
    <meta charset="utf-8">
    <meta
      http-equiv="Content-Security-Policy"
      content="default-src 'none'; connect-src 'none'; img-src 'none'; media-src 'none'; style-src 'unsafe-inline'; form-action ${DECISION_ORIGIN}; base-uri 'none'; object-src 'none'; frame-ancestors 'none'"
    >
    <meta name="referrer" content="no-referrer">
    <meta name="color-scheme" content="${theme}">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${title} · AccordLock</title>
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
        font-weight: 650;
        letter-spacing: .01em;
      }
      .window-bar form, .window-close { -webkit-app-region: no-drag; }
      .window-close {
        display: grid;
        width: 30px;
        min-width: 30px;
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
        padding: 24px 30px 28px;
        overflow-y: auto;
        scrollbar-gutter: stable;
      }
      .eyebrow {
        display: flex;
        align-items: center;
        gap: 8px;
        margin: 0 0 10px;
        color: #62665f;
        font-size: 10px;
        font-weight: 750;
        letter-spacing: .09em;
        text-transform: uppercase;
      }
      .eyebrow::before {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: ${copy.tone === 'warning' ? '#c48b12' : copy.tone === 'info' ? '#4d72c9' : '#777b73'};
        content: '';
      }
      h1 {
        margin: 0;
        overflow-wrap: anywhere;
        font-size: 28px;
        font-weight: 675;
        letter-spacing: -.035em;
        line-height: 1.15;
        unicode-bidi: plaintext;
      }
      .message {
        margin: 10px 0 18px;
        overflow-wrap: anywhere;
        color: #4f534d;
        font-size: 15px;
        line-height: 1.55;
        white-space: pre-wrap;
        unicode-bidi: plaintext;
      }
      .details {
        max-height: 240px;
        overflow: auto;
        border: 1px solid #dedfda;
        border-radius: 14px;
        background: #fff;
      }
      .details p {
        margin: 0;
        padding: 15px 16px;
        overflow-wrap: anywhere;
        color: #282a26;
        font: 12px/1.58 ui-monospace, "SFMono-Regular", Consolas, "Liberation Mono", monospace;
        white-space: pre-wrap;
        unicode-bidi: plaintext;
      }
      .actions-shell {
        border-top: 1px solid #dedfda;
        background: rgb(250 250 248 / 96%);
        backdrop-filter: blur(16px);
      }
      .actions {
        display: flex;
        align-items: center;
        justify-content: flex-end;
        gap: 8px;
        width: min(100%, 620px);
        margin: 0 auto;
        padding: 13px 30px;
      }
      form { margin: 0; }
      button {
        min-width: 118px;
        min-height: 42px;
        padding: 0 17px;
        border: 1px solid #d0d2cc;
        border-radius: 10px;
        background: #fff;
        color: #20211f;
        font: inherit;
        font-size: 13px;
        font-weight: 675;
        cursor: pointer;
      }
      button:hover { filter: brightness(.97); }
      button:focus-visible { outline: 3px solid #7896e8; outline-offset: 2px; }
      .confirm.info, .confirm.neutral { border-color: #20221f; background: #20221f; color: #fff; }
      .confirm.warning { border-color: #8a6010; background: #8a6010; color: #fff; }
      @media (max-width: 520px) {
        main { padding: 18px 20px 22px; }
        h1 { font-size: 24px; }
        .actions { align-items: stretch; flex-direction: column; padding: 11px 20px; }
        .actions form, .actions button { width: 100%; }
      }
      ${darkThemeStyles}
    </style>
  </head>
  <body>
    <header class="window-bar">
      <span>AccordLock</span>
      ${customClose}
    </header>
    <main aria-labelledby="confirmation-title">
      <p class="eyebrow">Protected setting</p>
      <h1 id="confirmation-title">${title}</h1>
      <p class="message">${message}</p>
      ${detailsMarkup}
    </main>
    <footer class="actions-shell">
      <div class="actions">${buttons}</div>
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

function isExactConfirmationNavigation(rawUrl: string, expectedNonce: string): boolean {
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
  const nonces = url.searchParams.getAll('nonce');
  const decisions = url.searchParams.getAll('decision');
  return (
    nonces.length === 1 &&
    decisions.length === 1 &&
    nonceMatches(nonces[0], expectedNonce) &&
    decisions[0] === 'confirm'
  );
}

/**
 * Opens an isolated main-process confirmation. Only its nonce-bound confirm form can return true.
 */
export function showAccordLockSettingsConfirmationWindow(
  parent: BrowserWindow,
  untrustedCopy: AccordLockSettingsConfirmationCopy,
  theme: AccordLockSettingsConfirmationTheme = 'light'
): Promise<boolean> {
  const copy = trustedCopy(untrustedCopy);
  if (
    parent.isDestroyed() ||
    parent.webContents.isDestroyed() ||
    !copy ||
    (theme !== 'light' && theme !== 'dark')
  ) {
    return Promise.resolve(false);
  }

  const nonce = randomBytes(NONCE_BYTES).toString('hex');
  const document = buildConfirmationDocument(copy, nonce, theme);
  const dataUrl = buildDataUrl(document);

  let confirmationWindow: BrowserWindow;
  try {
    confirmationWindow = new BrowserWindow({
      parent,
      modal: true,
      show: false,
      width: 640,
      height: 540,
      minWidth: 460,
      minHeight: 400,
      resizable: true,
      minimizable: false,
      maximizable: false,
      fullscreenable: false,
      skipTaskbar: true,
      autoHideMenuBar: true,
      title: `${copy.title} · AccordLock`,
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
        partition: `accordlock-settings-confirmation-${nonce}`,
      },
    });
    confirmationWindow.removeMenu();
    confirmationWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  } catch {
    if (confirmationWindow! && !confirmationWindow.isDestroyed()) confirmationWindow.destroy();
    return Promise.resolve(false);
  }

  return new Promise<boolean>((resolve) => {
    const contents = confirmationWindow.webContents;
    let settled = false;
    let navigationArmed = false;
    let deadlineTimer: ReturnType<typeof setTimeout> | undefined;

    const cleanup = () => {
      parent.removeListener('closed', onParentClosed);
      parent.webContents.removeListener('destroyed', onParentContentsDestroyed);
      confirmationWindow.removeListener('closed', onConfirmationClosed);
      confirmationWindow.removeListener('unresponsive', onConfirmationUnresponsive);
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

    const settle = (confirmed: boolean) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (!confirmationWindow.isDestroyed()) confirmationWindow.destroy();
      resolve(confirmed);
    };

    const onParentClosed = () => settle(false);
    const onParentContentsDestroyed = () => settle(false);
    const onConfirmationClosed = () => settle(false);
    const onConfirmationUnresponsive = () => settle(false);
    const onRendererGone = () => settle(false);
    const onLoadFailure = () => settle(false);
    const onWillAttachWebview = (event: PreventableEvent) => event.preventDefault();
    const onWillRedirect = (event: PreventableEvent) => {
      event.preventDefault();
      settle(false);
    };
    const onWillNavigate = (event: PreventableEvent, url: string) => {
      event.preventDefault();
      settle(isExactConfirmationNavigation(url, nonce));
    };
    const onBeforeInput = (event: PreventableEvent, input: KeyboardInput) => {
      if (input.type === 'keyDown' && input.key === 'Escape') {
        event.preventDefault();
        settle(false);
      }
    };

    parent.once('closed', onParentClosed);
    parent.webContents.once('destroyed', onParentContentsDestroyed);
    confirmationWindow.once('closed', onConfirmationClosed);
    confirmationWindow.once('unresponsive', onConfirmationUnresponsive);
    contents.on('before-input-event', onBeforeInput);
    contents.once('did-fail-load', onLoadFailure);
    contents.once('render-process-gone', onRendererGone);
    contents.on('will-attach-webview', onWillAttachWebview);
    deadlineTimer = setTimeout(() => settle(false), MAX_CONFIRMATION_OPEN_MILLISECONDS);
    if (typeof deadlineTimer.unref === 'function') deadlineTimer.unref();

    if (parent.isDestroyed() || parent.webContents.isDestroyed()) {
      settle(false);
      return;
    }

    try {
      void confirmationWindow
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
          try {
            confirmationWindow.show();
            confirmationWindow.focus();
          } catch {
            settle(false);
          }
        })
        .catch(() => settle(false));
    } catch {
      settle(false);
    }
  });
}
