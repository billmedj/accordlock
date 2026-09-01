// Modified by AccordLock contributors; see UPSTREAM.md.
import './accordlockBootstrap';
import type {
  IpcMainEvent,
  IpcMainInvokeEvent,
  OpenDialogOptions,
  OpenDialogReturnValue,
  WebContents,
} from 'electron';
import {
  app,
  App,
  BrowserWindow,
  dialog,
  globalShortcut,
  ipcMain,
  Menu,
  MenuItem,
  nativeTheme,
  Notification,
  powerMonitor,
  powerSaveBlocker,
  safeStorage,
  screen,
  session,
  shell,
  Tray,
} from 'electron';
import { pathToFileURL, format as formatUrl, URLSearchParams } from 'node:url';
import { Buffer } from 'node:buffer';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import started from 'electron-squirrel-startup';
import path from 'node:path';
import os from 'node:os';
import { execFileSync, spawn } from 'child_process';
import 'dotenv/config';
import { checkBackendStatus } from './backendStatus';
import { startGooseServe } from './gooseServe';
import {
  embeddedGooseBinarySha256,
  embeddedPreflightBinarySha256,
  embeddedPreflightProtocolVersion,
  embeddedRuntimeBinarySha256,
  isEmbeddedAccordLockDevelopmentPackage,
} from './accordlockEmbeddedIntegrity';
import {
  deriveAccordLockBackendRunId,
  generateAccordLockBackendBindingSecret,
} from './accordlockBackendBinding';
import {
  buildGoosePolicyEnvironment,
  readAccordLockHistoricalAuditPage,
  startAccordLockRuntime,
  type AccordLockFileRestoreChallenge,
  type AccordLockFileRestoreRecord,
  type AccordLockRuntimeHandle,
  type AccordLockSessionAuditPage,
} from './accordlockRuntime';
import {
  dispatchAccordLockConnectionTest,
  dispatchAccordLockReviewNotification,
} from './accordlockApprovalNotificationDispatcher';
import {
  createFreshAccordLockLedgerDirectory,
  resolveAccordLockHistoricalLedgerDirectory,
} from './accordlockHistoricalLedger';
import {
  ACCORDLOCK_APPROVAL_NOTIFICATION_DISMISS,
  notificationPresentationForRequest,
  parseAccordLockNotification,
  parseApprovalNotificationId,
} from './accordlock/notificationNavigation';
import { ApprovalNotificationRegistry } from './accordlock/approvalNotificationRegistry';
import {
  loadAccordLockTerminalPrograms,
  pickAndPersistAccordLockTerminalProgram,
  removeAccordLockTerminalProgram,
  validateAccordLockTerminalProgramAlias,
} from './accordlockTerminalPrograms';
import {
  loadAccordLockNetworkPolicy,
  normalizeAccordLockNetworkDomains,
  writeAccordLockNetworkPolicy,
} from './accordlockNetworkPolicy';
import {
  startAccordLockApprovalProxy,
  type AccordLockApprovalProxyHandle,
  type AccordLockApprovalRequest,
} from './accordlockApprovalProxy';
import {
  bindAccordLockActionApproval,
  canApproveAccordLockAction,
  parseAccordLockActionApprovalChallenge,
  type AccordLockActionApprovalChallenge,
} from './accordlockActionApproval';
import {
  AccordLockApprovalCenterGate,
  resolveTrustedApprovalCenterIntent,
} from './accordlockApprovalCenterGate';
import { showAccordLockActionApprovalWindow } from './accordlockActionApprovalWindow';
import { showAccordLockRestoreWindow } from './accordlockRestoreWindow';
import { showAccordLockSettingsConfirmationWindow } from './accordlockSettingsConfirmationWindow';
import { showAccordLockTaskApprovalWindow } from './accordlockTaskApprovalWindow';
import {
  AccordLockTaskControl,
  interceptUnexpectedAccordLockTopLevelNavigation,
  parseTaskRequest,
  parseTaskRestoreRequest,
  parseTaskAuditRequest,
  parseTaskAuthorizationRevokeRequest,
  revokeAccordLockWindowAuthorizations,
  revokeBeforeAccordLockWindowReload,
  type TrustedAuthorizedTaskContext,
} from './accordlockTaskControl';
import { AccordLockTaskAuditIndex, accordLockAuditWorkspaceId } from './accordlockTaskAuditIndex';
import {
  ACCORDLOCK_APPROVAL_CHANNELS_LIST,
  ACCORDLOCK_APPROVAL_CHANNELS_REMOVE,
  ACCORDLOCK_APPROVAL_CHANNELS_SAVE,
  ACCORDLOCK_APPROVAL_CHANNELS_SET_ENABLED,
  ACCORDLOCK_APPROVAL_CHANNELS_TEST,
  AccordLockApprovalChannelStore,
  isChannelId,
} from './accordlockApprovalChannels';
import {
  ACCORDLOCK_REMOTE_APPROVAL_ENROLLMENT_GET,
  ACCORDLOCK_REMOTE_APPROVAL_ENROLLMENT_IMPORT,
  ACCORDLOCK_REMOTE_APPROVAL_ENROLLMENT_REVOKE,
  ACCORDLOCK_REMOTE_APPROVAL_RECEIPT_IMPORT,
  AccordLockRemoteApprovalGatewayStore,
  parseAccordLockVerifiedRemoteDecisionReceipt,
  previewAccordLockRemoteGatewayEnrollment,
} from './accordlockRemoteApprovals';
import { AccordLockEnvironmentProfileStore } from './accordlockEnvironmentProfileStore';
import { AccordLockPreflightTrustStore } from './accordlockPreflightTrustStore';
import { AccordLockBundledPreflightRunner } from './accordlockPreflightRunnerAdapter';
import { AccordLockEnvironmentProfilePreflightController } from './accordlock/environmentProfilePreflightController';
import { AccordLockDeploymentPreflightReceiptArchive } from './accordlock/deploymentPreflightReceiptArchive';
import { AccordLockDeploymentPreflightCiEvidenceImporter } from './accordlock/deploymentPreflightCiEvidence';
import {
  AccordLockDeploymentPreflightCiEnrollmentController,
  type DeploymentPreflightCiEnrollmentPreview,
} from './accordlock/deploymentPreflightCiEnrollmentController';
import { isAccordLockEnvironmentProfileId } from './accordlock/environmentProfiles';
import { assertPinnedCiRouteUnchanged } from './accordlock/pinnedCiRoute';
import {
  ACCORDLOCK_DEPLOYMENT_PREFLIGHT_RUN,
  ACCORDLOCK_DEPLOYMENT_PREFLIGHT_HISTORY_EXPORT,
  ACCORDLOCK_DEPLOYMENT_PREFLIGHT_HISTORY_LIST,
  ACCORDLOCK_DEPLOYMENT_PREFLIGHT_CI_EVIDENCE_IMPORT,
  ACCORDLOCK_ENVIRONMENT_PROFILES_LIST,
  ACCORDLOCK_ENVIRONMENT_PROFILES_REMOVE,
  ACCORDLOCK_ENVIRONMENT_PROFILES_SAVE,
  deploymentPreflightHistoryExportInputSchema,
  deploymentPreflightHistoryListInputSchema,
  deploymentPreflightCiEvidenceImportInputSchema,
  type AccordLockEnvironmentProfileView,
} from './accordlock/environmentProfileIpc';
import {
  AccordLockNavigationAllowance,
  isAccordLockExternalUrlAllowed,
  isAccordLockUnsafeViewMenuRole,
  shouldAllowAccordLockExternalBackend,
  shouldEnableAccordLockRemoteDebugging,
  shouldGrantAccordLockMicrophoneCheck,
  shouldGrantAccordLockMicrophoneRequest,
} from './accordlockDesktopSecurity';
import { AccordLockDecisionSingleFlight } from './accordlock/decisionSingleFlight';
import { literalBlockingUserLimit } from './accordlock/taskIntent';
import {
  approvalInboxStatusForDecisionIntent,
  parseApprovalCenterDecision,
  projectExactActionApproval,
  type ApprovalInboxItem,
} from './accordlock/approvalInbox';
import {
  ACCORDLOCK_APPROVAL_INBOX_DECIDE,
  ACCORDLOCK_APPROVAL_INBOX_EVENT,
  ACCORDLOCK_APPROVAL_INBOX_GET_PENDING,
} from './accordlock/approvalInboxIpc';
import {
  ACCORDLOCK_TASK_AUTHORIZATION_DECIDE,
  ACCORDLOCK_TASK_AUTHORIZATION_GET_PENDING,
  ACCORDLOCK_TASK_AUTHORIZATION_PREPARE,
  ACCORDLOCK_TASK_AUTHORIZATION_REVOKE,
  ACCORDLOCK_TASK_AUDIT,
  ACCORDLOCK_TASK_RESTORE,
  ACCORDLOCK_CONTROL_PROTOCOL,
  type AccordLockTaskAuditAck,
  type AccordLockTaskRestoreAck,
} from './accordlock/taskIpc';
import { getLoginShellPath } from './loginShellPath';
import { GooseServeLeaseRegistry, type GooseServeLease } from './gooseServeLeaseRegistry';
import { acpWebSocketUrlFromHttpBase, normalizeAcpHttpBaseUrl } from './acp/url';
import { expandTilde, sanitizeGoosePathRoot } from './utils/pathUtils';
import log from './utils/logger';
import { ensureWinShims } from './utils/winShims';
import { addRecentDir, loadRecentDirs } from './utils/recentDirs';
import { errorMessage, formatErrorForLogging } from './utils/conversionUtils';
import type { Settings, SettingKey } from './utils/settings';
import { defaultSettings, getKeyboardShortcuts } from './utils/settings';
import * as crypto from 'crypto';
import * as yaml from 'yaml';
import windowStateKeeper from 'electron-window-state';
import {
  getUpdateAvailable,
  registerUpdateIpcHandlers,
  setAutoDownloadDisabled,
  setTrayRef,
  setupAutoUpdater,
  updateTrayMenu,
} from './utils/autoUpdater';
import { UPDATES_ENABLED } from './updates';
import { registerGitBranchIpc } from './utils/gitBranchIpc';
import './utils/recipeHash';
import installExtension, { REACT_DEVELOPER_TOOLS } from 'electron-devtools-installer';
import { buildCSP } from './utils/csp';
import { accordLockDefaultWorkspace, resolveAccordLockWorkspace } from './accordlockWorkspace';
import {
  DesktopFileAccess,
  isAuthorizedFileAccessRequest,
  readSelectedRecipe,
} from './desktopFileAccess';
import { findSupportedDeepLink, SUPPORTED_DEEP_LINK_SCHEMES } from './utils/deepLinks';
import {
  accordLockWindowsAppUserModelId,
  resolveAccordLockWindowIconPath,
} from './accordlockDesktopBranding';

const ACCORDLOCK_SESSION_PARTITION = 'persist:accordlock';
const getAccordLockElectronSession = () => session.fromPartition(ACCORDLOCK_SESSION_PARTITION);
const fetchFromAccordLockSession: typeof globalThis.fetch = (input, init) =>
  getAccordLockElectronSession().fetch(input instanceof URL ? input.toString() : input, init);

const accordLockTitleBarOverlay = (dark: boolean) => ({
  color: dark ? '#1b1d21' : '#f5f5f3',
  symbolColor: dark ? '#f4f5f7' : '#202226',
  height: 32,
});

const accordLockWindowIconPath = resolveAccordLockWindowIconPath({
  appPath: app.getAppPath(),
  isPackaged: app.isPackaged,
  platform: process.platform,
  resourcesPath: process.resourcesPath,
});

if (process.platform === 'win32') {
  app.setAppUserModelId(accordLockWindowsAppUserModelId(isEmbeddedAccordLockDevelopmentPackage()));
}

function shouldSetupUpdater(): boolean {
  // A packaged AccordLock build must never consume Goose's upstream update
  // configuration. The environment override exists for local updater tests only.
  return UPDATES_ENABLED || (!app.isPackaged && process.env.ENABLE_DEV_UPDATES === 'true');
}

// Settings management
const SETTINGS_FILE = path.join(app.getPath('userData'), 'settings.json');
const STARTUP_LOGS_DIR = path.join(app.getPath('userData'), 'logs', 'startup');

function getSettings(): Settings {
  if (fsSync.existsSync(SETTINGS_FILE)) {
    let stored: Partial<Settings>;
    try {
      const data = fsSync.readFileSync(SETTINGS_FILE, 'utf8');
      stored = JSON.parse(data) as Partial<Settings>;
    } catch (err) {
      console.error('Failed to read settings.json, using defaults:', err);
      return defaultSettings;
    }
    const storedSettings = { ...stored } as Partial<Settings> & { language?: unknown };
    delete storedSettings.language;
    return {
      ...defaultSettings,
      ...storedSettings,
      externalGoosed: {
        ...defaultSettings.externalGoosed,
        ...(storedSettings.externalGoosed ?? {}),
      },
      keyboardShortcuts: {
        ...defaultSettings.keyboardShortcuts,
        ...(storedSettings.keyboardShortcuts ?? {}),
      },
    };
  }
  return defaultSettings;
}

function resolveAccordLockDarkTheme(settings: Settings = getSettings()): boolean {
  return settings.useSystemTheme ? nativeTheme.shouldUseDarkColors : settings.theme === 'dark';
}

function updateSettings(modifier: (settings: Settings) => void): void {
  const settings = getSettings();
  modifier(settings);
  fsSync.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2));
}

async function configureProxy() {
  const httpsProxy = process.env.HTTPS_PROXY || process.env.https_proxy;
  const httpProxy = process.env.HTTP_PROXY || process.env.http_proxy;
  const noProxy = process.env.NO_PROXY || process.env.no_proxy || '';

  const proxyUrl = httpsProxy || httpProxy;

  if (proxyUrl) {
    console.log('[Main] Configuring proxy');
    await getAccordLockElectronSession().setProxy({
      proxyRules: proxyUrl,
      proxyBypassRules: noProxy,
    });
    console.log('[Main] Proxy configured successfully');
  }
}

if (started) app.quit();

// Certificate trust for active backend leases. Renderer requests and
// Main-process requests and renderer requests share the AccordLock partition.
// lease owns a trust record so old windows keep working after settings change.
interface BackendCertificateTrust {
  origin: string;
  hostname: string;
  fingerprint: string;
}

interface BackendCertificateTrustRegistration {
  trust: BackendCertificateTrust;
  release: () => void;
}

const trustedBackendCertificates = new Set<BackendCertificateTrust>();

function normalizeHostname(hostname: string): string {
  return hostname.toLowerCase();
}

function normalizeFingerprint(fp: string): string {
  if (fp.startsWith('sha256/')) {
    const b64 = fp.slice('sha256/'.length);
    const buf = Buffer.from(b64, 'base64');
    return Array.from(buf)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(':')
      .toUpperCase();
  }
  return fp.toUpperCase();
}

function trustBackendCertificate(
  origin: string,
  fingerprint: string
): BackendCertificateTrustRegistration {
  const parsedOrigin = new URL(origin);
  const trust: BackendCertificateTrust = {
    origin: parsedOrigin.origin,
    hostname: normalizeHostname(parsedOrigin.hostname),
    fingerprint: normalizeFingerprint(fingerprint),
  };
  trustedBackendCertificates.add(trust);
  return {
    trust,
    release: () => {
      trustedBackendCertificates.delete(trust);
    },
  };
}

function getBackendCertificateTrusts(hostname: string): BackendCertificateTrust[] {
  const normalizedHostname = normalizeHostname(hostname);
  return [...trustedBackendCertificates].filter((trust) => trust.hostname === normalizedHostname);
}

function verifyBackendCertificate(hostname: string, fingerprint: string): boolean {
  const normalizedFingerprint = normalizeFingerprint(fingerprint);
  const trusts = getBackendCertificateTrusts(hostname);
  return trusts.some((trust) => trust.fingerprint === normalizedFingerprint);
}

function isTrustedHost(hostname: string): boolean {
  return getBackendCertificateTrusts(hostname).length > 0;
}

// Renderer requests: pin to the exact cert once known.
app.on('certificate-error', (event, _webContents, url, _error, certificate, callback) => {
  const parsed = new URL(url);
  const exactOriginTrusts = getBackendCertificateTrusts(parsed.hostname).filter(
    (trust) => trust.origin === parsed.origin
  );
  if (exactOriginTrusts.length === 0) {
    callback(false);
    return;
  }

  event.preventDefault();
  const fingerprint = normalizeFingerprint(certificate.fingerprint);
  callback(exactOriginTrusts.some((trust) => trust.fingerprint === fingerprint));
});

// Main-process requests: pin to the exact cert once known.
app.whenReady().then(() => {
  getAccordLockElectronSession().setCertificateVerifyProc((request, callback) => {
    if (!isTrustedHost(request.hostname)) {
      callback(-3);
      return;
    }

    const match = verifyBackendCertificate(request.hostname, request.certificate.fingerprint);
    callback(match ? 0 : -2);
  });
});

if (shouldEnableAccordLockRemoteDebugging(app.isPackaged, process.env.ENABLE_PLAYWRIGHT)) {
  const debugPort = process.env.PLAYWRIGHT_DEBUG_PORT || '9222';
  console.log(`[Main] Enabling Playwright remote debugging on port ${debugPort}`);
  app.commandLine.appendSwitch('remote-debugging-port', debugPort);
}

// In development mode, force registration as the default protocol client
// In production, register normally
if (MAIN_WINDOW_VITE_DEV_SERVER_URL) {
  // Development mode - force registration
  console.log('[Main] Development mode: registering accordlock://');
  for (const scheme of SUPPORTED_DEEP_LINK_SCHEMES) {
    app.setAsDefaultProtocolClient(scheme);
  }

  if (process.platform === 'darwin') {
    for (const scheme of SUPPORTED_DEEP_LINK_SCHEMES) {
      try {
        // Reset the default handler to ensure dev version takes precedence
        spawn('open', ['-a', process.execPath, '--args', '--reset-protocol-handler', scheme], {
          detached: true,
          stdio: 'ignore',
        });
      } catch {
        console.warn(`[Main] Could not reset ${scheme} protocol handler`);
      }
    }
  }
} else {
  // Production mode - normal registration
  for (const scheme of SUPPORTED_DEEP_LINK_SCHEMES) {
    app.setAsDefaultProtocolClient(scheme);
  }
}

// Keep one writer for protected local state on every desktop platform.
const gotTheLock = app.requestSingleInstanceLock();
let openUrlHandledLaunch = false;
if (!gotTheLock) {
  app.quit();
} else if (process.platform !== 'darwin') {
  app.on('second-instance', (_event, commandLine) => {
    const protocolUrl = findSupportedDeepLink(commandLine);
    if (protocolUrl) {
      const parsedUrl = new URL(protocolUrl);
      // If it's a bot/recipe URL, handle it directly by creating a new window
      if (parsedUrl.hostname === 'bot' || parsedUrl.hostname === 'recipe') {
        app.whenReady().then(async () => {
          const recentDirs = loadRecentDirs();
          const openDir = recentDirs.length > 0 ? recentDirs[0] : null;

          const deeplinkData = parseRecipeDeeplink(protocolUrl);
          const scheduledJobId = parsedUrl.searchParams.get('scheduledJob');

          await createChat(app, {
            dir: openDir || undefined,
            recipeDeeplink: deeplinkData?.config,
            scheduledJobId: scheduledJobId || undefined,
            recipeParameters: deeplinkData?.parameters,
          });
        });
        return; // Skip the rest of the handler
      }

      // Handle new-session URL by creating a fresh chat window
      if (parsedUrl.hostname === 'new-session') {
        app.whenReady().then(async () => {
          const recentDirs = loadRecentDirs();
          const openDir = recentDirs.length > 0 ? recentDirs[0] : null;
          const prompt = parsedUrl.searchParams.get('prompt') || undefined;
          await createChat(app, {
            dir: openDir || undefined,
            initialMessage: prompt,
            initialMessageNoAutoSubmit: prompt !== undefined,
          });
        });
        return;
      }

      if (parsedUrl.hostname === 'resume') {
        app.whenReady().then(async () => {
          const recentDirs = loadRecentDirs();
          const openDir = recentDirs.length > 0 ? recentDirs[0] : null;
          await createResumeChatWindow(parsedUrl, openDir || undefined);
        });
        return;
      }

      // For non-bot URLs, continue with normal handling
      handleProtocolUrl(protocolUrl, parsedUrl);
    }

    // Only focus existing regular windows for non-bot/recipe URLs
    const regularWindows = getRegularWindows();
    if (regularWindows.length > 0) {
      const mainWindow = regularWindows[0];
      if (mainWindow.isMinimized()) {
        mainWindow.restore();
      }
      mainWindow.focus();
    } else if (!protocolUrl) {
      app.whenReady().then(async () => {
        const recentDirs = loadRecentDirs();
        const openDir = recentDirs.length > 0 ? recentDirs[0] : null;
        await createChat(app, { dir: openDir || undefined });
      });
    }
  });

  // Handle protocol URLs on Windows and Linux startup
  const protocolUrl = findSupportedDeepLink(process.argv);
  if (protocolUrl) {
    app.whenReady().then(async () => {
      let parsedUrl: URL;
      try {
        parsedUrl = new URL(protocolUrl);
      } catch (error) {
        log.warn('[Main] Ignoring invalid startup protocol URL:', errorMessage(error));
        return;
      }

      openUrlHandledLaunch = true;
      try {
        await handleProtocolUrl(protocolUrl, parsedUrl);
      } catch (error) {
        log.error('[Main] Failed to handle startup protocol URL:', errorMessage(error));
        if (BrowserWindow.getAllWindows().length === 0) {
          const { dirPath } = parseArgs();
          await createNewWindow(app, dirPath);
        }
      }
    });
  }
}

const pendingDeepLinks = new Map<number, string>();

function queuePendingDeepLink(windowId: number, url: string): void {
  if (pendingDeepLinks.get(windowId) === url) {
    return;
  }
  pendingDeepLinks.set(windowId, url);
}

const reactReadyWindows = new Set<number>();

const DEEPLINK_BURST_DEDUP_MS = 2000;
const recentSessionDeepLinkSends = new Map<string, number>();

function pruneExpiredSessionDeepLinkSends(now: number): void {
  for (const [url, sentAt] of recentSessionDeepLinkSends) {
    if (now - sentAt >= DEEPLINK_BURST_DEDUP_MS) {
      recentSessionDeepLinkSends.delete(url);
    }
  }
}

function isBurstDuplicateSessionDeepLink(url: string): boolean {
  const now = Date.now();
  pruneExpiredSessionDeepLinkSends(now);
  const sentAt = recentSessionDeepLinkSends.get(url);
  return sentAt !== undefined && now - sentAt < DEEPLINK_BURST_DEDUP_MS;
}

function recordSessionDeepLinkSend(url: string): void {
  const now = Date.now();
  recentSessionDeepLinkSends.set(url, now);
  pruneExpiredSessionDeepLinkSends(now);
}

function sendOpenSharedSession(window: BrowserWindow, url: string): void {
  if (isBurstDuplicateSessionDeepLink(url)) {
    log.info('[Main] Ignoring burst duplicate session deep link');
    return;
  }
  recordSessionDeepLinkSend(url);
  window.webContents.send('open-shared-session', url);
}

function deliverExtensionOrSessionDeepLink(
  url: string,
  parsedUrl: URL,
  targetWindow: BrowserWindow
): void {
  if (!reactReadyWindows.has(targetWindow.id) || targetWindow.webContents.isLoadingMainFrame()) {
    queuePendingDeepLink(targetWindow.id, url);
    return;
  }

  if (parsedUrl.hostname === 'extension') {
    targetWindow.webContents.send('add-extension', url);
  } else if (parsedUrl.hostname === 'sessions') {
    sendOpenSharedSession(targetWindow, url);
  }
}

function getResumeSessionId(parsedUrl: URL): string | null {
  try {
    const sessionId = decodeURIComponent(parsedUrl.pathname.replace(/^\/+/, '')).trim();
    return sessionId || null;
  } catch {
    return null;
  }
}

async function createResumeChatWindow(parsedUrl: URL, dir?: string): Promise<boolean> {
  const resumeSessionId = getResumeSessionId(parsedUrl);
  if (!resumeSessionId) {
    log.warn('[Main] Ignoring resume deep link without a session id');
    return false;
  }

  await createChat(app, { dir, resumeSessionId });
  return true;
}

async function handleProtocolUrl(url: string, parsedUrl: URL) {
  if (!url) return;

  const recentDirs = loadRecentDirs();
  const openDir = recentDirs.length > 0 ? recentDirs[0] : null;

  if (parsedUrl.hostname === 'new-session') {
    const prompt = parsedUrl.searchParams.get('prompt') || undefined;
    await createChat(app, {
      dir: openDir || undefined,
      initialMessage: prompt,
      initialMessageNoAutoSubmit: prompt !== undefined,
    });
    return;
  } else if (parsedUrl.hostname === 'resume') {
    await createResumeChatWindow(parsedUrl, openDir || undefined);
    return;
  } else if (parsedUrl.hostname === 'bot' || parsedUrl.hostname === 'recipe') {
    const existingWindows = BrowserWindow.getAllWindows();
    const targetWindow =
      existingWindows.length > 0
        ? existingWindows[0]
        : await createChat(app, { dir: openDir || undefined });
    if (!targetWindow) return;
    await processProtocolUrl(url, parsedUrl, targetWindow);
  } else {
    const regularWindows = getRegularWindows();
    let targetWindow: BrowserWindow | undefined;
    if (regularWindows.length > 0) {
      targetWindow = regularWindows[0];
      if (targetWindow.isMinimized()) {
        targetWindow.restore();
      }
      targetWindow.focus();
    } else {
      targetWindow = await createChat(app, { dir: openDir || undefined });
    }

    if (!targetWindow) return;

    if (targetWindow.webContents.isLoadingMainFrame()) {
      queuePendingDeepLink(targetWindow.id, url);
    } else {
      await processProtocolUrl(url, parsedUrl, targetWindow);
    }
  }
}

async function processProtocolUrl(url: string, parsedUrl: URL, window: BrowserWindow) {
  const recentDirs = loadRecentDirs();
  const openDir = recentDirs.length > 0 ? recentDirs[0] : null;

  if (parsedUrl.hostname === 'extension') {
    window.webContents.send('add-extension', url);
  } else if (parsedUrl.hostname === 'sessions') {
    sendOpenSharedSession(window, url);
  } else if (parsedUrl.hostname === 'bot' || parsedUrl.hostname === 'recipe') {
    const deeplinkData = parseRecipeDeeplink(url);
    const scheduledJobId = parsedUrl.searchParams.get('scheduledJob');

    await createChat(app, {
      dir: openDir || undefined,
      recipeDeeplink: deeplinkData?.config,
      scheduledJobId: scheduledJobId || undefined,
      recipeParameters: deeplinkData?.parameters,
    });
  }
}

let windowDeeplinkURL: string | null = null;

app.on('open-url', async (_event, url) => {
  if (process.platform !== 'win32') {
    const parsedUrl = new URL(url);

    log.info(
      '[Main] Received open-url event:',
      url.includes('key=') ? url.replace(/key=[^&]+/, 'key=REDACTED') : url
    );

    await app.whenReady();

    const recentDirs = loadRecentDirs();
    const openDir = recentDirs.length > 0 ? recentDirs[0] : null;

    // Handle new-session URL by creating a fresh chat window
    if (parsedUrl.hostname === 'new-session') {
      log.info('[Main] Detected new-session URL, creating new chat window');
      openUrlHandledLaunch = true;
      const prompt = parsedUrl.searchParams.get('prompt') || undefined;
      await createChat(app, {
        dir: openDir || undefined,
        initialMessage: prompt,
        initialMessageNoAutoSubmit: prompt !== undefined,
      });
      return;
    }

    if (parsedUrl.hostname === 'resume') {
      log.info('[Main] Detected resume URL, creating session resume window');
      openUrlHandledLaunch = await createResumeChatWindow(parsedUrl, openDir || undefined);
      return;
    }

    // Handle bot/recipe URLs by directly creating a new window
    if (parsedUrl.hostname === 'bot' || parsedUrl.hostname === 'recipe') {
      log.info('[Main] Detected bot/recipe URL, creating new chat window');
      openUrlHandledLaunch = true;
      const deeplinkData = parseRecipeDeeplink(url);
      if (deeplinkData) {
        windowDeeplinkURL = url;
      }
      const scheduledJobId = parsedUrl.searchParams.get('scheduledJob');

      await createChat(app, {
        dir: openDir || undefined,
        recipeDeeplink: deeplinkData?.config,
        scheduledJobId: scheduledJobId || undefined,
        recipeParameters: deeplinkData?.parameters,
      });
      windowDeeplinkURL = null;
      return;
    }

    // For extension/session URLs, send to an existing regular window or open one
    const regularWindows = getRegularWindows();
    if (regularWindows.length > 0) {
      const targetWindow = regularWindows[0];
      if (targetWindow.isMinimized()) targetWindow.restore();
      targetWindow.focus();
      if (parsedUrl.hostname === 'extension' || parsedUrl.hostname === 'sessions') {
        deliverExtensionOrSessionDeepLink(url, parsedUrl, targetWindow);
      }
    } else {
      openUrlHandledLaunch = true;
      const newWindow = await createChat(app, { dir: openDir || undefined });
      if (!newWindow) return;
      queuePendingDeepLink(newWindow.id, url);
    }
  }
});

// Handle macOS drag-and-drop onto dock icon
app.on('will-finish-launching', () => {
  if (process.platform === 'darwin') {
    app.setAboutPanelOptions({
      applicationName: 'AccordLock',
      applicationVersion: app.getVersion(),
    });
  }
});

// Handle drag-and-drop onto dock icon
app.on('open-file', async (event, filePath) => {
  event.preventDefault();
  await handleFileOpen(filePath);
});

// Handle multiple files/folders (macOS only)
if (process.platform === 'darwin') {
  // Use type assertion for non-standard Electron event
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  app.on('open-files' as any, async (event: any, filePaths: string[]) => {
    event.preventDefault();
    for (const filePath of filePaths) {
      await handleFileOpen(filePath);
    }
  });
}

async function handleFileOpen(filePath: string) {
  try {
    if (!filePath || typeof filePath !== 'string') {
      return;
    }

    const stats = fsSync.lstatSync(filePath);
    let targetDir = filePath;

    // If it's a file, use its parent directory
    if (stats.isFile()) {
      targetDir = path.dirname(filePath);
    }

    // Add to recent directories
    addRecentDir(targetDir);

    // Create new window for the directory
    const newWindow = await createChat(app, { dir: targetDir });

    // Focus the new window
    if (newWindow) {
      newWindow.show();
      newWindow.focus();
      newWindow.moveTop();
    }
  } catch (error) {
    console.error('Failed to handle file open:', error);

    // Show user-friendly error notification
    new Notification({
      title: 'AccordLock',
      body: `Could not open directory: ${path.basename(filePath)}`,
    }).show();
  }
}

declare var MAIN_WINDOW_VITE_DEV_SERVER_URL: string;
declare var MAIN_WINDOW_VITE_NAME: string;

function getAppUrl(): URL {
  return MAIN_WINDOW_VITE_DEV_SERVER_URL
    ? new URL(MAIN_WINDOW_VITE_DEV_SERVER_URL)
    : pathToFileURL(path.join(__dirname, `../renderer/${MAIN_WINDOW_VITE_NAME}/index.html`));
}

// Parse command line arguments
const parseArgs = () => {
  let dirPath = null;

  // Remove first two elements in dev mode (electron and script path)
  const args = !dirPath && app.isPackaged ? process.argv : process.argv.slice(2);
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--dir' && i + 1 < args.length) {
      dirPath = args[i + 1];
      break;
    }
  }

  if (!dirPath && process.stdin.isTTY) {
    try {
      const cwd = process.cwd();
      if (path.parse(cwd).root !== cwd) {
        dirPath = cwd;
      }
    } catch {
      // cwd unavailable; fall through to recentDirs
    }
  }

  return { dirPath };
};

interface BundledConfig {
  defaultProvider?: string;
  defaultModel?: string;
  predefinedModels?: string;
  version?: string;
}

const getBundledConfig = (): BundledConfig => {
  //{env-macro-start}//
  //needed when goose is bundled for a specific provider
  //{env-macro-end}//
  return {
    defaultProvider: process.env.GOOSE_DEFAULT_PROVIDER,
    defaultModel: process.env.GOOSE_DEFAULT_MODEL,
    predefinedModels: process.env.GOOSE_PREDEFINED_MODELS,
    version: process.env.GOOSE_VERSION,
  };
};

const { defaultProvider, defaultModel, predefinedModels, version } = getBundledConfig();

interface ExternalBackend {
  source: 'env' | 'settings';
  url: string;
  secret: string;
  certFingerprint?: string;
  workingDir?: string;
}

const getExternalBackendUrlFromEnv = (): string | null => {
  if (!process.env.GOOSE_EXTERNAL_BACKEND) {
    return null;
  }

  const configuredUrl = process.env.GOOSE_EXTERNAL_BACKEND_URL?.trim();
  if (configuredUrl) {
    return configuredUrl;
  }

  return `http://127.0.0.1:${process.env.GOOSE_PORT || '3000'}`;
};

const getExternalBackendFromEnv = (): ExternalBackend | null => {
  const url = getExternalBackendUrlFromEnv();
  if (!url) {
    return null;
  }

  const secret = process.env.GOOSE_SERVER__SECRET_KEY;
  if (!secret) {
    throw new Error(
      'GOOSE_SERVER__SECRET_KEY must be set when using GOOSE_EXTERNAL_BACKEND. ' +
        'Set it to the same value on both the server and the desktop client.'
    );
  }

  return {
    source: 'env',
    url,
    secret,
  };
};

const getServerSecret = (settings: Settings): string => {
  if (settings.externalGoosed?.enabled && settings.externalGoosed.secret) {
    return settings.externalGoosed.secret;
  }
  return '';
};

const getActiveExternalBackend = (settings: Settings): ExternalBackend | null => {
  if (
    !shouldAllowAccordLockExternalBackend(
      app.isPackaged,
      process.env.ACCORDLOCK_ALLOW_EXTERNAL_BACKEND_DEV
    )
  ) {
    return null;
  }
  const envBackend = getExternalBackendFromEnv();
  if (envBackend) {
    return {
      ...envBackend,
      workingDir: settings.externalGoosed?.workingDir,
    };
  }

  if (settings.externalGoosed?.enabled && settings.externalGoosed.url) {
    return {
      source: 'settings',
      url: settings.externalGoosed.url,
      secret: getServerSecret(settings),
      certFingerprint: settings.externalGoosed.certFingerprint,
      workingDir: settings.externalGoosed.workingDir,
    };
  }

  return null;
};

const getExternalBackendForCsp = (settings: Settings) => {
  if (
    !shouldAllowAccordLockExternalBackend(
      app.isPackaged,
      process.env.ACCORDLOCK_ALLOW_EXTERNAL_BACKEND_DEV
    )
  ) {
    return undefined;
  }
  const envUrl = getExternalBackendUrlFromEnv();
  if (!envUrl) {
    return settings.externalGoosed;
  }

  return {
    ...settings.externalGoosed,
    enabled: true,
    url: envUrl,
  };
};

const configuredGoosePathRoot = app.isPackaged ? undefined : sanitizeGoosePathRoot(process.env);
const accordLockEnginePathRoot =
  configuredGoosePathRoot ?? path.join(app.getPath('userData'), 'engine');

let appConfig = {
  GOOSE_DEFAULT_PROVIDER: defaultProvider,
  GOOSE_DEFAULT_MODEL: defaultModel,
  GOOSE_PREDEFINED_MODELS: predefinedModels,
  GOOSE_PATH_ROOT: accordLockEnginePathRoot,
  GOOSE_WORKING_DIR: '',
  // If GOOSE_ALLOWLIST_WARNING env var is not set, defaults to false (strict blocking mode)
  GOOSE_ALLOWLIST_WARNING: process.env.GOOSE_ALLOWLIST_WARNING === 'true',
  // Network-based task sharing is opt-in for AccordLock distributions.
  GOOSE_DISABLE_NOSTR_SHARING: process.env.GOOSE_DISABLE_NOSTR_SHARING !== 'false',
};

const windowMap = new Map<number, BrowserWindow>();

function updateAccordLockTitleBarOverlays(dark: boolean): void {
  if (process.platform !== 'win32') return;
  for (const window of windowMap.values()) {
    if (!window.isDestroyed()) {
      window.setTitleBarOverlay(accordLockTitleBarOverlay(dark));
    }
  }
}

const desktopFileAccess = new DesktopFileAccess();
const accordLockTaskAuditIndex = new AccordLockTaskAuditIndex({
  directory: path.join(app.getPath('userData'), 'accordlock', 'audit-index'),
  safeStorage,
});
const accordLockApprovalChannelStore = new AccordLockApprovalChannelStore({
  directory: path.join(app.getPath('userData'), 'accordlock', 'approval-channels'),
  safeStorage,
});
const accordLockRemoteApprovalGatewayStore = new AccordLockRemoteApprovalGatewayStore({
  directory: path.join(app.getPath('userData'), 'accordlock', 'remote-approvals'),
  safeStorage,
});
const accordLockEnvironmentProfileStore = new AccordLockEnvironmentProfileStore({
  directory: path.join(app.getPath('userData'), 'accordlock', 'environment-profiles'),
  safeStorage,
});
const accordLockPreflightDirectory = path.join(app.getPath('userData'), 'accordlock', 'preflight');
const accordLockDeploymentPreflightReceiptArchive = new AccordLockDeploymentPreflightReceiptArchive(
  {
    directory: path.join(app.getPath('userData'), 'accordlock', 'preflight-receipts'),
  }
);
const accordLockPreflightTrustStore = new AccordLockPreflightTrustStore({
  directory: accordLockPreflightDirectory,
  safeStorage,
});
const accordLockBundledPreflightRunner = new AccordLockBundledPreflightRunner({
  binaryDirectory: runtimeBinDirectory(),
  stateDirectory: accordLockPreflightDirectory,
  trustStore: accordLockPreflightTrustStore,
  isPackaged: app.isPackaged,
  allowDirtyDevelopment:
    (app.isPackaged && isEmbeddedAccordLockDevelopmentPackage()) ||
    (!app.isPackaged && process.env.ACCORDLOCK_ALLOW_DIRTY_RUNTIME_DEV === '1'),
  expectedBinarySha256: app.isPackaged ? embeddedPreflightBinarySha256() : undefined,
  expectedProtocolVersion: app.isPackaged ? embeddedPreflightProtocolVersion() : undefined,
});
const accordLockEnvironmentPreflight = new AccordLockEnvironmentProfilePreflightController(
  accordLockEnvironmentProfileStore,
  {
    runner: accordLockBundledPreflightRunner,
    archive: accordLockDeploymentPreflightReceiptArchive,
  }
);
const accordLockCiEvidenceEnrollment = new AccordLockDeploymentPreflightCiEnrollmentController({
  environmentStore: accordLockEnvironmentProfileStore,
  initializeEnvironmentTrust: (environmentId, signal) =>
    accordLockBundledPreflightRunner.initializeEnvironmentTrust(environmentId, signal),
  trustStore: accordLockPreflightTrustStore,
  trustedStateRoot: accordLockPreflightDirectory,
  importerFactory: (options) => new AccordLockDeploymentPreflightCiEvidenceImporter(options),
  confirm: async () => false,
});

async function accordLockEnvironmentView(
  profile: Awaited<ReturnType<typeof accordLockEnvironmentProfileStore.save>>
): Promise<AccordLockEnvironmentProfileView> {
  const trust = await accordLockPreflightTrustStore.getCiAuthorityStatus(profile.id);
  return {
    ...profile,
    ciTrust:
      trust.status === 'ENROLLED'
        ? {
            status: 'ENROLLED',
            buildAuthorityFingerprint: trust.build.publicKeyHash,
            artifactAuthorityFingerprint: trust.artifact.publicKeyHash,
          }
        : { status: 'UNENROLLED' },
  };
}

async function readBoundedCiEvidence(filePath: string): Promise<unknown> {
  const before = await fs.lstat(filePath, { bigint: true });
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.size < 1n ||
    before.size > 256n * 1024n
  ) {
    throw new Error('Build proof must be a JSON file no larger than 256 KiB');
  }
  const handle = await fs.open(filePath, 'r');
  try {
    const sameFile = (left: typeof before, right: typeof before) =>
      left.dev === right.dev &&
      left.ino === right.ino &&
      left.size === right.size &&
      left.mtimeNs === right.mtimeNs &&
      left.ctimeNs === right.ctimeNs;
    const current = await handle.stat({ bigint: true });
    if (!current.isFile() || !sameFile(before, current))
      throw new Error('Build proof changed while opening');
    const bytes = Buffer.alloc(Number(current.size));
    let offset = 0;
    while (offset < bytes.length) {
      const read = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (read.bytesRead === 0) throw new Error('Build proof ended unexpectedly');
      offset += read.bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    if (!sameFile(current, after)) throw new Error('Build proof changed while reading');
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    return JSON.parse(text) as unknown;
  } finally {
    await handle.close();
  }
}

async function readBoundedRemoteApprovalDocument(filePath: string): Promise<unknown> {
  const before = await fs.lstat(filePath, { bigint: true });
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.size < 1n ||
    before.size > 64n * 1024n
  ) {
    throw new Error('Remote approval document must be a regular JSON file no larger than 64 KiB');
  }
  const handle = await fs.open(filePath, 'r');
  try {
    const current = await handle.stat({ bigint: true });
    if (
      !current.isFile() ||
      current.dev !== before.dev ||
      current.ino !== before.ino ||
      current.size !== before.size ||
      current.mtimeNs !== before.mtimeNs ||
      current.ctimeNs !== before.ctimeNs
    ) {
      throw new Error('Remote approval document changed while opening');
    }
    const bytes = Buffer.alloc(Number(current.size));
    let offset = 0;
    while (offset < bytes.length) {
      const read = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (read.bytesRead === 0) throw new Error('Remote approval document ended unexpectedly');
      offset += read.bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    if (
      after.dev !== current.dev ||
      after.ino !== current.ino ||
      after.size !== current.size ||
      after.mtimeNs !== current.mtimeNs ||
      after.ctimeNs !== current.ctimeNs
    ) {
      throw new Error('Remote approval document changed while reading');
    }
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    bytes.fill(0);
    return JSON.parse(text) as unknown;
  } finally {
    await handle.close();
  }
}

function ciEvidenceConfirmationDetail(preview: DeploymentPreflightCiEnrollmentPreview): string {
  return [
    `Workflow: ${preview.workflow}`,
    `Run: ${preview.runId}`,
    `Commit: ${preview.commit}`,
    `Image: ${preview.imageDigest}`,
    `Registry: ${preview.registry}`,
    `Build key: ${preview.buildAuthorityFingerprint}`,
    `Artifact key: ${preview.artifactAuthorityFingerprint}`,
    preview.note,
  ].join('\n');
}
const accordLockApprovalNotificationDirectory = path.join(
  app.getPath('userData'),
  'accordlock',
  'approval-notifications'
);
const accordLockRuntimeLedgerId = crypto.randomUUID();
const accordLockRuntimeRunsDirectory = path.join(app.getPath('userData'), 'runtime', 'runs');
const accordLockNetworkPolicyPath = path.join(
  app.getPath('userData'),
  'accordlock-governed-network.json'
);
const accordLockStartupNetworkPolicy = loadAccordLockNetworkPolicy(accordLockNetworkPolicyPath);
const accordLockTaskControl = new AccordLockTaskControl(
  accordLockTaskAuditIndex,
  accordLockRuntimeLedgerId,
  (accordLockStartupNetworkPolicy?.allowed_domains.length ?? 0) > 0
);
const accordLockTaskDecisionSingleFlight = new AccordLockDecisionSingleFlight();
const accordLockBackendBindings = new Map<number, string>();
const accordLockActionApprovalTails = new Map<string, Promise<void>>();
const accordLockFileRestoreFlights = new Map<string, Promise<AccordLockTaskRestoreAck>>();
const accordLockPendingActionApprovals = new Map<string, PendingAccordLockActionApproval>();
const accordLockVerifiedRemoteAllowances = new Map<string, string>();
const accordLockApprovalNotifications = new ApprovalNotificationRegistry<Notification>(128);
const ACCORDLOCK_APPROVAL_INBOX_LIFETIME_SECONDS = 5 * 60;
const ACCORDLOCK_APPROVAL_NOTIFICATION_MAX_WAKEUPS = 3;

interface PendingAccordLockActionApproval {
  gate: AccordLockApprovalCenterGate;
  item: ApprovalInboxItem;
  notificationAbort: AbortController;
  notificationRetryTimer: ReturnType<typeof setTimeout> | null;
  notificationWakeups: number;
  onParentClosed: () => void;
  parent: BrowserWindow;
  timer: ReturnType<typeof setTimeout>;
  windowId: number;
}

function emitAccordLockApprovalInboxItem(windowId: number, item: ApprovalInboxItem): void {
  const target = windowMap.get(windowId);
  if (!target || target.isDestroyed() || target.webContents.isDestroyed()) return;
  target.webContents.send(ACCORDLOCK_APPROVAL_INBOX_EVENT, item);
}

function pendingAccordLockApprovalsForWindow(windowId: number): ApprovalInboxItem[] {
  return [...accordLockPendingActionApprovals.values()]
    .filter((pending) => pending.windowId === windowId)
    .map((pending) => pending.item)
    .sort((left, right) => left.receivedAt - right.receivedAt || left.id.localeCompare(right.id));
}

function openAccordLockApprovalInboxEntry(
  challenge: AccordLockActionApprovalChallenge,
  taskContext: TrustedAuthorizedTaskContext,
  parent: BrowserWindow
): PendingAccordLockActionApproval {
  const receivedAt = Math.floor(Date.now() / 1_000);
  const expiresAt = Math.min(
    receivedAt + ACCORDLOCK_APPROVAL_INBOX_LIFETIME_SECONDS,
    taskContext.approvedSession.expires_at
  );
  const item = projectExactActionApproval(challenge, taskContext.authorization, {
    canAllowOnce: canApproveAccordLockAction(challenge),
    expiresAt,
    receivedAt,
  });
  if (accordLockPendingActionApprovals.has(item.id)) {
    throw new Error('Exact action is already waiting for a decision');
  }

  const gate = new AccordLockApprovalCenterGate(item, taskContext.windowId);
  const onParentClosed = () => gate.cancel();
  parent.once('closed', onParentClosed);
  const timer = setTimeout(
    () => {
      gate.expire(Math.floor(Date.now() / 1_000));
    },
    Math.max(1, expiresAt * 1_000 - Date.now())
  );
  if (typeof timer.unref === 'function') timer.unref();

  const pending: PendingAccordLockActionApproval = {
    gate,
    item,
    notificationAbort: new AbortController(),
    notificationRetryTimer: null,
    notificationWakeups: 0,
    onParentClosed,
    parent,
    timer,
    windowId: taskContext.windowId,
  };
  accordLockPendingActionApprovals.set(item.id, pending);
  emitAccordLockApprovalInboxItem(taskContext.windowId, item);
  void dispatchAccordLockApprovalInboxNotification(pending);
  return pending;
}

function isCurrentAccordLockApproval(pending: PendingAccordLockActionApproval): boolean {
  return (
    !pending.notificationAbort.signal.aborted &&
    accordLockPendingActionApprovals.get(pending.item.id) === pending
  );
}

function scheduleAccordLockApprovalNotificationRetry(
  pending: PendingAccordLockActionApproval,
  nextRetryAt: number | null
): void {
  if (
    !isCurrentAccordLockApproval(pending) ||
    nextRetryAt === null ||
    !Number.isSafeInteger(nextRetryAt) ||
    nextRetryAt < 0 ||
    nextRetryAt >= pending.item.binding.requestExpiresAt ||
    pending.notificationWakeups >= ACCORDLOCK_APPROVAL_NOTIFICATION_MAX_WAKEUPS
  ) {
    return;
  }
  const expiryMs = pending.item.binding.requestExpiresAt * 1_000;
  const delayMs = Math.max(1, nextRetryAt * 1_000 - Date.now());
  if (Date.now() + delayMs >= expiryMs) return;

  pending.notificationWakeups += 1;
  const retryTimer = setTimeout(() => {
    if (pending.notificationRetryTimer === retryTimer) {
      pending.notificationRetryTimer = null;
    }
    if (isCurrentAccordLockApproval(pending)) {
      void dispatchAccordLockApprovalInboxNotification(pending);
    }
  }, delayMs);
  pending.notificationRetryTimer = retryTimer;
  if (typeof retryTimer.unref === 'function') retryTimer.unref();
}

async function dispatchAccordLockApprovalInboxNotification(
  pending: PendingAccordLockActionApproval
): Promise<void> {
  try {
    if (!isCurrentAccordLockApproval(pending)) return;
    const bundle = await accordLockApprovalChannelStore.loadNotificationDispatchBundle();
    if (!bundle || !isCurrentAccordLockApproval(pending)) return;
    await fs.mkdir(accordLockApprovalNotificationDirectory, { recursive: true, mode: 0o700 });
    const notificationDirectory = await fs.lstat(accordLockApprovalNotificationDirectory);
    if (!notificationDirectory.isDirectory() || notificationDirectory.isSymbolicLink()) {
      throw new Error('Approval notification storage is unavailable');
    }
    if (!isCurrentAccordLockApproval(pending)) return;
    const report = await dispatchAccordLockReviewNotification({
      approvalId: pending.item.id,
      receivedAt: pending.item.receivedAt,
      expiresAt: pending.item.binding.requestExpiresAt,
      bundle,
      binDirectory: runtimeBinDirectory(),
      dataDirectory: accordLockApprovalNotificationDirectory,
      signal: pending.notificationAbort.signal,
      acceptDirtyDevelopmentMarker: acceptDirtyAccordLockRuntimeMarker(),
      expectedBinarySha256: app.isPackaged ? embeddedRuntimeBinarySha256() : undefined,
    });
    if (!isCurrentAccordLockApproval(pending)) return;
    log.info(
      `AccordLock delivered ${report.delivered} of ${report.configured} configured Approval Center notifications`
    );
    scheduleAccordLockApprovalNotificationRetry(pending, report.next_retry_at);
  } catch {
    if (isCurrentAccordLockApproval(pending)) {
      // Delivery is auxiliary. The exact action remains blocked in Approval Center.
      log.error('AccordLock could not deliver an Approval Center notification');
    }
  }
}

function closeAccordLockApprovalInboxEntry(pending: PendingAccordLockActionApproval): void {
  pending.notificationAbort.abort();
  if (pending.notificationRetryTimer !== null) {
    clearTimeout(pending.notificationRetryTimer);
    pending.notificationRetryTimer = null;
  }
  clearTimeout(pending.timer);
  pending.parent.removeListener('closed', pending.onParentClosed);
  accordLockApprovalNotifications.dismiss(pending.item.id);
  accordLockVerifiedRemoteAllowances.delete(pending.item.id);
  if (accordLockPendingActionApprovals.get(pending.item.id) === pending) {
    accordLockPendingActionApprovals.delete(pending.item.id);
  }
}

async function submitAccordLockVerifiedRemoteDecision(document: unknown): Promise<{
  accepted: true;
  approvalId: string;
  intent: string;
}> {
  const receipt = parseAccordLockVerifiedRemoteDecisionReceipt(document);
  const pending = accordLockPendingActionApprovals.get(receipt.approvalId);
  if (!pending || !isCurrentAccordLockApproval(pending)) {
    throw new Error('Approval request is no longer pending');
  }
  const configuredChannel = (await accordLockApprovalChannelStore.list()).find(
    (candidate) => candidate.channel === receipt.channel
  );
  const verified = await accordLockRemoteApprovalGatewayStore.verifyAndConsume(
    document,
    pending.item,
    configuredChannel?.enabled === true
  );
  if (verified.decision.intent === 'ALLOW_ONCE') {
    accordLockVerifiedRemoteAllowances.set(pending.item.id, verified.evidence.receiptId);
  }
  try {
    await pending.gate.submit(verified.decision, pending.windowId, Math.floor(Date.now() / 1_000));
  } catch (error) {
    accordLockVerifiedRemoteAllowances.delete(pending.item.id);
    throw error;
  }
  return {
    accepted: true,
    approvalId: pending.item.id,
    intent: verified.decision.intent,
  };
}

function enqueueAccordLockActionApproval<T>(
  sessionId: string,
  operation: () => Promise<T>
): Promise<T> {
  const previous = accordLockActionApprovalTails.get(sessionId) ?? Promise.resolve();
  const result = previous.then(operation, operation);
  const tail = result.then(
    () => undefined,
    () => undefined
  );
  accordLockActionApprovalTails.set(sessionId, tail);
  void tail.then(() => {
    if (accordLockActionApprovalTails.get(sessionId) === tail) {
      accordLockActionApprovalTails.delete(sessionId);
    }
  });
  return result;
}

function runAccordLockFileRestoreOnce(
  windowId: number,
  sessionId: string,
  recoveryId: string,
  operation: () => Promise<AccordLockTaskRestoreAck>
): Promise<AccordLockTaskRestoreAck> {
  const key = `${windowId}\u0000${sessionId}\u0000${recoveryId}`;
  const existing = accordLockFileRestoreFlights.get(key);
  if (existing) return existing;
  const result = Promise.resolve().then(operation);
  accordLockFileRestoreFlights.set(key, result);
  const release = () => {
    if (accordLockFileRestoreFlights.get(key) === result) {
      accordLockFileRestoreFlights.delete(key);
    }
  };
  void result.then(release, release);
  return result;
}

function requireRegularRendererWindow(event: IpcMainInvokeEvent | IpcMainEvent): BrowserWindow {
  const senderWindow = BrowserWindow.fromWebContents(event.sender);
  const senderFrame = event.senderFrame;
  if (
    !senderWindow ||
    !senderFrame ||
    !isAuthorizedFileAccessRequest(
      {
        isRegisteredWindow: windowMap.get(senderWindow.id) === senderWindow,
        isMainFrame: senderFrame === event.sender.mainFrame,
        rendererUrl: senderFrame.url,
      },
      getAppUrl()
    )
  ) {
    throw new Error('This renderer is not authorized for local file access');
  }
  return senderWindow;
}

registerGitBranchIpc({
  authorizeWorkspace: async (event) => {
    const senderWindow = requireRegularRendererWindow(event);
    return {
      directory: await desktopFileAccess.authorizedDesktopWorkingDirectory(senderWindow.id),
      window: senderWindow,
    };
  },
  confirmSwitch: async (workspace, branch) => {
    return showAccordLockSettingsConfirmationWindow(
      workspace.window,
      {
        title: 'AccordLock branch protection',
        message: `Switch this workspace to “${branch}”?`,
        detail: `This changes files in the trusted workspace:\n\n${workspace.directory}`,
        confirmLabel: 'Switch branch',
        cancelLabel: 'Keep current branch',
        tone: 'warning',
        defaultButton: 'cancel',
        buttonOrder: 'cancel-first',
      },
      resolveAccordLockDarkTheme() ? 'dark' : 'light'
    );
  },
});

function getRegularWindows(): BrowserWindow[] {
  return [...windowMap.values()].filter((w) => !w.isDestroyed());
}

let shutdownState: 'idle' | 'running' | 'complete' = 'idle';

async function handleUnexpectedGooseServeExit(
  _lease: GooseServeLease,
  windowIds: readonly number[]
): Promise<void> {
  if (shutdownState !== 'idle') return;

  try {
    const runtime = await requireAccordLockRuntime();
    if (runtime) {
      for (const windowId of windowIds) {
        await accordLockTaskControl.revokeWindowAuthorizations(windowId, runtime);
      }
    }
  } catch (error) {
    failClosedTaskRevocation('unexpected agent engine exit', error);
    return;
  }

  if (!accordLockRuntimeExitFailureShown) {
    accordLockRuntimeExitFailureShown = true;
    dialog.showErrorBox(
      'AccordLock Revoked the Task',
      'The supervised agent engine stopped unexpectedly. Its task authorization was revoked and AccordLock will now close safely.'
    );
  }
  app.quit();
}

const gooseServeLeases = new GooseServeLeaseRegistry(log, handleUnexpectedGooseServeExit);

let accordLockRuntimeStart: Promise<AccordLockRuntimeHandle> | null = null;
let accordLockApprovalProxyStart: Promise<AccordLockApprovalProxyHandle> | null = null;
let accordLockRuntimeStartupFailureShown = false;
let accordLockApprovalProxyFailureShown = false;
let accordLockRuntimeExitFailureShown = false;
let accordLockRevocationFailureShown = false;
function runtimeBinDirectory(): string {
  if (app.isPackaged) {
    return path.join(process.resourcesPath, 'bin');
  }
  const developmentOverride = process.env.ACCORDLOCK_RUNTIME_DEV_BIN_DIR?.trim();
  return developmentOverride
    ? path.resolve(developmentOverride)
    : path.join(app.getAppPath(), 'src', 'bin');
}

const terminalProgramConfigurationPath = (): string =>
  path.join(app.getPath('userData'), 'accordlock-terminal-programs.json');

const acceptDirtyAccordLockRuntimeMarker = (): boolean =>
  (app.isPackaged && isEmbeddedAccordLockDevelopmentPackage()) ||
  (!app.isPackaged && process.env.ACCORDLOCK_ALLOW_DIRTY_RUNTIME_DEV === '1');

const startBundledAccordLockRuntime = (): Promise<AccordLockRuntimeHandle> => {
  if (!accordLockRuntimeStart) {
    accordLockRuntimeStart = (async () => {
      const dataDirectory = await createFreshAccordLockLedgerDirectory(
        accordLockRuntimeRunsDirectory,
        accordLockRuntimeLedgerId
      );
      return startAccordLockRuntime({
        binDirectory: runtimeBinDirectory(),
        // Authority is scoped to one supervised Desktop run. The immutable
        // per-run ledger remains on disk as audit evidence, while reopening a
        // Goose session starts with zero inherited authority and a fresh authorization.
        dataDirectory,
        logger: log,
        readinessFetch: fetchFromAccordLockSession,
        acceptDirtyDevelopmentMarker: acceptDirtyAccordLockRuntimeMarker(),
        expectedBinarySha256: app.isPackaged ? embeddedRuntimeBinarySha256() : undefined,
        terminalPrograms: loadAccordLockTerminalPrograms(terminalProgramConfigurationPath()),
        networkDomains: accordLockStartupNetworkPolicy?.allowed_domains ?? [],
        onUnexpectedExit: ({ code, signal }) => {
          log.error(`AccordLock runtime exited unexpectedly (code ${code}, signal ${signal})`);
          if (!accordLockRuntimeExitFailureShown) {
            accordLockRuntimeExitFailureShown = true;
            dialog.showErrorBox(
              'AccordLock Security Runtime Stopped',
              'The trusted execution boundary stopped unexpectedly. AccordLock will close without starting another backend.'
            );
          }
          app.quit();
        },
      });
    })();
  }
  return accordLockRuntimeStart;
};

const accordLockRuntimeStartupMessage = (error: unknown): string => {
  const details = errorMessage(error);
  if (
    details.includes('local alpha state is incompatible') ||
    details.includes('reset the local database') ||
    details.includes('PreReleaseStateResetRequired')
  ) {
    return 'This local preview data was created by an incompatible version. Back it up or reset local app data before continuing.';
  }
  return 'The verified AccordLock runtime could not start. No agent engine was launched.\n\nRestart AccordLock. If the problem continues, reinstall the app or contact your administrator.';
};

const requireAccordLockRuntime = async (): Promise<AccordLockRuntimeHandle | null> => {
  try {
    return await startBundledAccordLockRuntime();
  } catch (error) {
    log.error('AccordLock security runtime is unavailable', error);
    if (!accordLockRuntimeStartupFailureShown) {
      accordLockRuntimeStartupFailureShown = true;
      dialog.showErrorBox(
        'AccordLock Security Runtime Unavailable',
        accordLockRuntimeStartupMessage(error)
      );
    }
    app.quit();
    return null;
  }
};

const resolveAccordLockActionApproval = async (
  challenge: AccordLockActionApprovalChallenge,
  runtime: AccordLockRuntimeHandle,
  signal: AbortSignal
): Promise<boolean> => {
  if (signal.aborted) return false;
  const taskContext = accordLockTaskControl.authorizedContextForSession(challenge.sessionId);
  const categoricalLimit = literalBlockingUserLimit(
    taskContext.objective,
    challenge.arguments.kind
  );
  if (categoricalLimit !== null) {
    const decidedAt = Math.floor(Date.now() / 1_000);
    const currentTask = accordLockTaskControl.authorizedContextForSession(
      challenge.sessionId,
      decidedAt
    );
    if (
      currentTask.windowId !== taskContext.windowId ||
      currentTask.approvedSession.task_id !== taskContext.approvedSession.task_id ||
      currentTask.approvedSession.task_policy_hash !== taskContext.approvedSession.task_policy_hash
    ) {
      throw new Error('The approved task changed during literal-limit enforcement');
    }

    const denial = bindAccordLockActionApproval(
      challenge,
      currentTask.approvedSession,
      'DENIED',
      crypto.randomUUID(),
      decidedAt
    );
    await runtime.registerActionApproval(denial);

    const deniedItem = projectExactActionApproval(challenge, currentTask.authorization, {
      canAllowOnce: false,
      expiresAt: Math.min(
        decidedAt + ACCORDLOCK_APPROVAL_INBOX_LIFETIME_SECONDS,
        currentTask.approvedSession.expires_at
      ),
      receivedAt: decidedAt,
    });
    emitAccordLockApprovalInboxItem(
      currentTask.windowId,
      Object.freeze({ ...deniedItem, status: 'DENIED' })
    );
    log.info('AccordLock denied an exact action because the task contains a categorical limit');
    return true;
  }

  const approvalWindow = windowMap.get(taskContext.windowId);
  if (!approvalWindow || approvalWindow.isDestroyed()) {
    throw new Error('The approved task window is unavailable');
  }
  const pending = openAccordLockApprovalInboxEntry(challenge, taskContext, approvalWindow);
  const cancelDisconnectedApproval = () => pending.gate.cancel();
  signal.addEventListener('abort', cancelDisconnectedApproval, { once: true });
  if (signal.aborted) cancelDisconnectedApproval();

  try {
    const selection = await pending.gate.selection;
    clearTimeout(pending.timer);

    let effectiveIntent = selection?.intent ?? 'DENY_ACTION';
    if (selection) {
      effectiveIntent = await resolveTrustedApprovalCenterIntent(selection, async () => {
        if (signal.aborted) return false;
        if (Math.floor(Date.now() / 1_000) >= pending.item.binding.requestExpiresAt) return false;
        if (!canApproveAccordLockAction(challenge)) return false;
        if (accordLockVerifiedRemoteAllowances.delete(selection.itemId)) return true;
        return showAccordLockActionApprovalWindow(
          approvalWindow,
          challenge,
          taskContext.objective,
          pending.item.binding.requestExpiresAt,
          resolveAccordLockDarkTheme() ? 'dark' : 'light'
        ).catch((error) => {
          log.error('AccordLock exact action approval failed closed', errorMessage(error));
          return false;
        });
      });
    }
    if (signal.aborted) effectiveIntent = 'DENY_ACTION';

    const decidedAt = Math.floor(Date.now() / 1_000);
    if (effectiveIntent === 'ALLOW_ONCE' && decidedAt >= pending.item.binding.requestExpiresAt) {
      effectiveIntent = 'DENY_ACTION';
    }
    const currentTask = accordLockTaskControl.authorizedContextForSession(
      challenge.sessionId,
      decidedAt
    );
    if (
      currentTask.windowId !== taskContext.windowId ||
      currentTask.approvedSession.task_id !== taskContext.approvedSession.task_id ||
      currentTask.approvedSession.task_policy_hash !== taskContext.approvedSession.task_policy_hash
    ) {
      throw new Error('The approved task changed during action approval');
    }

    const actionApproval = bindAccordLockActionApproval(
      challenge,
      currentTask.approvedSession,
      effectiveIntent === 'ALLOW_ONCE' ? 'APPROVED' : 'DENIED',
      crypto.randomUUID(),
      decidedAt
    );
    await runtime.registerActionApproval(actionApproval);

    if (selection && (selection.intent === 'STOP_TASK' || selection.intent === 'REVOKE_ACCESS')) {
      try {
        await accordLockTaskControl.revokeSessionAuthorization(
          taskContext.windowId,
          {
            protocol: ACCORDLOCK_CONTROL_PROTOCOL,
            schema_version: 2,
            session_id: challenge.sessionId,
          },
          runtime
        );
      } catch (error) {
        failClosedTaskRevocation(`approval center ${selection.intent.toLowerCase()}`, error);
        throw error;
      }
    }

    const finalStatus = selection
      ? approvalInboxStatusForDecisionIntent(effectiveIntent)
      : decidedAt >= pending.item.binding.requestExpiresAt
        ? 'EXPIRED'
        : 'DENIED';
    const settledItem = Object.freeze({ ...pending.item, status: finalStatus });
    if (selection) {
      const acknowledgement = Object.freeze({
        ...selection,
        intent: effectiveIntent,
      });
      pending.gate.complete(acknowledgement);
    }
    emitAccordLockApprovalInboxItem(taskContext.windowId, settledItem);

    // `true` means an exact resolution was durably registered. A denied decision
    // is retried as well so Goose receives a regular fail-closed denial.
    return true;
  } catch (error) {
    pending.gate.fail(error);
    emitAccordLockApprovalInboxItem(
      taskContext.windowId,
      Object.freeze({ ...pending.item, status: 'DENIED' })
    );
    throw error;
  } finally {
    signal.removeEventListener('abort', cancelDisconnectedApproval);
    closeAccordLockApprovalInboxEntry(pending);
  }
};

const resolveAccordLockApprovalRequest = (
  request: AccordLockApprovalRequest,
  runtime: AccordLockRuntimeHandle
): Promise<boolean> => {
  if (request.signal.aborted) return Promise.resolve(false);
  const challenge = parseAccordLockActionApprovalChallenge(request);
  return enqueueAccordLockActionApproval(challenge.sessionId, () =>
    resolveAccordLockActionApproval(challenge, runtime, request.signal)
  );
};

function assertFileRestoreChallengeMatchesTask(
  challenge: AccordLockFileRestoreChallenge,
  context: TrustedAuthorizedTaskContext,
  recoveryId: string
): void {
  if (
    challenge.recovery_id !== recoveryId ||
    challenge.task_id !== context.approvedSession.task_id ||
    challenge.session_id !== context.approvedSession.session_id ||
    challenge.run_id !== context.approvedSession.run_id ||
    challenge.workspace_root !== context.approvedSession.workspace_root
  ) {
    throw new Error('The recovery copy does not match the active task');
  }
}

function assertFileRestoreRecordMatchesTask(
  result: AccordLockFileRestoreRecord,
  context: TrustedAuthorizedTaskContext,
  recoveryId: string
): void {
  const record = result.record;
  if (
    record.recovery_id !== recoveryId ||
    record.task_id !== context.approvedSession.task_id ||
    record.session_id !== context.approvedSession.session_id ||
    record.run_id !== context.approvedSession.run_id ||
    record.workspace_root !== context.approvedSession.workspace_root ||
    record.challenge_hash !== result.challengeHash
  ) {
    throw new Error('The restore record does not match the active task');
  }
}

function fileRestoreAck(
  context: TrustedAuthorizedTaskContext,
  recoveryId: string,
  result: AccordLockFileRestoreRecord
): AccordLockTaskRestoreAck {
  return {
    protocol: ACCORDLOCK_CONTROL_PROTOCOL,
    schema_version: 2,
    session_id: context.approvedSession.session_id,
    recovery_id: recoveryId,
    status: result.code === 'FILE_RESTORE_ALREADY_COMMITTED' ? 'ALREADY_RESTORED' : 'RESTORED',
    record: {
      restore_id: result.record.restore_id,
      record_hash: result.recordHash,
      relative_path: result.record.relative_path,
      content_sha256: result.record.content_sha256,
      completed_at: result.record.completed_at,
    },
  };
}

async function restoreAccordLockDeletedFile(
  senderWindow: BrowserWindow,
  sessionId: string,
  recoveryId: string
): Promise<AccordLockTaskRestoreAck> {
  const context = accordLockTaskControl.authorizedContextForSession(sessionId);
  if (context.windowId !== senderWindow.id) {
    throw new Error('The recovery copy belongs to a different task window');
  }
  const runtime = await requireAccordLockRuntime();
  if (!runtime) throw new Error('AccordLock trusted runtime is unavailable');

  const preparation = await runtime.prepareFileRestore(recoveryId);
  if ('record' in preparation) {
    assertFileRestoreRecordMatchesTask(preparation, context, recoveryId);
    return fileRestoreAck(context, recoveryId, preparation);
  }

  assertFileRestoreChallengeMatchesTask(preparation.challenge, context, recoveryId);
  const expiresAt = Math.min(
    context.approvedSession.expires_at,
    preparation.challenge.prepared_at + 5 * 60
  );
  const decision = await showAccordLockRestoreWindow(
    senderWindow,
    {
      recoveryId,
      relativePath: preparation.challenge.relative_path,
      contentSha256: preparation.challenge.content_sha256,
      workspaceRoot: preparation.challenge.workspace_root,
      preparedAt: preparation.challenge.prepared_at,
      expiresAt,
      challengeDigest: preparation.challengeHash,
    },
    resolveAccordLockDarkTheme() ? 'dark' : 'light'
  );
  if (decision === 'FAILED') {
    throw new Error('Trusted file restore confirmation could not be completed');
  }
  if (decision === 'DENIED') {
    return {
      protocol: ACCORDLOCK_CONTROL_PROTOCOL,
      schema_version: 2,
      session_id: sessionId,
      recovery_id: recoveryId,
      status: 'CANCELLED',
      record: null,
    };
  }

  const current = accordLockTaskControl.authorizedContextForSession(sessionId);
  if (
    current.windowId !== context.windowId ||
    current.approvedSession.task_id !== context.approvedSession.task_id ||
    current.approvedSession.run_id !== context.approvedSession.run_id ||
    current.approvedSession.workspace_root !== context.approvedSession.workspace_root
  ) {
    throw new Error('The active task changed during file restore confirmation');
  }
  const result = await runtime.commitFileRestore(preparation.challenge);
  assertFileRestoreRecordMatchesTask(result, current, recoveryId);
  return fileRestoreAck(current, recoveryId, result);
}

const startBundledAccordLockApprovalProxy = (): Promise<AccordLockApprovalProxyHandle> => {
  if (!accordLockApprovalProxyStart) {
    accordLockApprovalProxyStart = startBundledAccordLockRuntime().then((runtime) =>
      startAccordLockApprovalProxy({
        forward: (requestPath, method, body) =>
          runtime.forwardPolicyRequest(requestPath, method, body),
        resolveApproval: (request) => resolveAccordLockApprovalRequest(request, runtime),
      })
    );
  }
  return accordLockApprovalProxyStart;
};

const requireAccordLockApprovalProxy = async (): Promise<AccordLockApprovalProxyHandle | null> => {
  try {
    return await startBundledAccordLockApprovalProxy();
  } catch (error) {
    log.error('AccordLock action-approval boundary is unavailable', errorMessage(error));
    if (!accordLockApprovalProxyFailureShown) {
      accordLockApprovalProxyFailureShown = true;
      dialog.showErrorBox(
        'AccordLock Action Approval Unavailable',
        'The one-time action approval boundary could not start. No policy-enforced agent engine was launched.'
      );
    }
    app.quit();
    return null;
  }
};

const failClosedTaskRevocation = (context: string, error: unknown): void => {
  log.error(`AccordLock task authorization revocation failed (${context})`, error);
  if (!accordLockRevocationFailureShown) {
    accordLockRevocationFailureShown = true;
    dialog.showErrorBox(
      'AccordLock Could Not Revoke Authority',
      'A task could not be revoked safely. AccordLock will close the supervised runtime and quit rather than leave authority active.'
    );
  }
  app.quit();
};

const accordLockWindowReloads = new Map<number, Promise<void>>();
const accordLockNavigationAllowance = new AccordLockNavigationAllowance();

const requestAccordLockWindowReload = (targetWindow: BrowserWindow, context: string): void => {
  const windowId = targetWindow.id;
  if (accordLockWindowReloads.has(windowId)) return;

  const operation = (async () => {
    const runtime = await requireAccordLockRuntime();
    if (!runtime) return;

    await revokeBeforeAccordLockWindowReload(
      windowId,
      () => {
        if (windowMap.get(windowId) === targetWindow && !targetWindow.isDestroyed()) {
          const trustedUrl = targetWindow.webContents.getURL();
          if (
            !isAuthorizedFileAccessRequest(
              {
                isRegisteredWindow: true,
                isMainFrame: true,
                rendererUrl: trustedUrl,
              },
              getAppUrl()
            )
          ) {
            throw new Error('AccordLock refused to reload an untrusted renderer URL');
          }
          accordLockNavigationAllowance.arm(windowId, trustedUrl);
          targetWindow.reload();
        }
      },
      accordLockTaskControl,
      runtime
    );
  })();
  accordLockWindowReloads.set(windowId, operation);
  void operation
    .catch((error) => failClosedTaskRevocation(context, error))
    .finally(() => {
      if (accordLockWindowReloads.get(windowId) === operation) {
        accordLockWindowReloads.delete(windowId);
      }
    });
};

const windowPowerSaveBlockers = new Map<number, number>(); // windowId -> blockerId
// Track pending initial messages per window
const pendingInitialMessages = new Map<number, string>(); // windowId -> initialMessage
const pendingInitialMessageNoAutoSubmit = new Set<number>(); // windowIds whose initialMessage should NOT auto-submit

interface CreateChatOptions {
  initialMessage?: string;
  initialMessageNoAutoSubmit?: boolean;
  dir?: string;
  resumeSessionId?: string;
  viewType?: string;
  recipeDeeplink?: string;
  recipeId?: string;
  scheduledJobId?: string;
  recipeParameters?: Record<string, string>;
}

const createChat = async (
  app: App,
  options: CreateChatOptions = {}
): Promise<BrowserWindow | undefined> => {
  const accordLockRuntime = await requireAccordLockRuntime();
  if (!accordLockRuntime) {
    return;
  }

  const {
    initialMessage,
    initialMessageNoAutoSubmit,
    dir,
    resumeSessionId,
    viewType,
    recipeDeeplink,
    recipeId,
    scheduledJobId,
    recipeParameters,
  } = options;
  const settings = getSettings();

  let externalBackend: ExternalBackend | null;
  try {
    externalBackend = getActiveExternalBackend(settings);
  } catch (error) {
    log.error('External backend environment is invalid', formatErrorForLogging(error));
    dialog.showMessageBoxSync({
      type: 'error',
      title: 'External Backend Misconfigured',
      message: 'The external backend environment is invalid.',
      detail: 'Review the external backend configuration, then restart AccordLock.',
      buttons: ['Quit'],
    });
    app.quit();
    return;
  }

  if (app.isPackaged && externalBackend) {
    dialog.showMessageBoxSync({
      type: 'error',
      title: 'External Backend Disabled',
      message: 'AccordLock requires its bundled policy-enforced agent engine.',
      detail:
        'A packaged AccordLock distribution cannot attach to an external or unverified agent engine.',
      buttons: ['Quit'],
    });
    app.quit();
    return;
  }

  if (externalBackend?.certFingerprint) {
    const url = externalBackend.url;
    const usesHttps = (() => {
      try {
        return new URL(url).protocol === 'https:';
      } catch {
        return false;
      }
    })();

    if (!usesHttps) {
      const response = dialog.showMessageBoxSync({
        type: 'error',
        title: 'External Backend Misconfigured',
        message: 'Certificate fingerprint requires an HTTPS external backend URL.',
        detail: 'Use an https:// URL or remove the configured certificate fingerprint.',
        buttons: ['Disable External Backend & Retry', 'Quit'],
        defaultId: 0,
        cancelId: 1,
      });

      if (response === 0) {
        updateSettings((s) => {
          if (s.externalGoosed) {
            s.externalGoosed.enabled = false;
          }
        });
        return createChat(app, options);
      }

      app.quit();
      return;
    }
  }

  const serverSecret = externalBackend
    ? externalBackend.secret
    : crypto.randomBytes(32).toString('hex');
  const protectedWorkspaceRoots = [os.homedir(), app.getPath('userData'), accordLockEnginePathRoot];
  const defaultWorkspace = accordLockDefaultWorkspace(app.getPath('userData'));
  await fs.mkdir(defaultWorkspace, { recursive: true });
  const requestedWorkingDir = externalBackend?.workingDir?.trim() || dir;
  let workingDir = resolveAccordLockWorkspace(
    requestedWorkingDir,
    app.getPath('userData'),
    protectedWorkspaceRoots
  );
  if (requestedWorkingDir && path.resolve(requestedWorkingDir) !== workingDir) {
    log.warn('AccordLock refused an over-broad workspace and selected its isolated workspace');
  }
  let gooseServeLease: GooseServeLease | null = null;
  let backendBindingSecret: string | null = null;

  if (externalBackend) {
    let externalCertificateTrust: BackendCertificateTrustRegistration | null = null;

    try {
      const externalBaseUrl = normalizeAcpHttpBaseUrl(externalBackend.url);
      const externalBase = new URL(externalBaseUrl);
      if (externalBase.protocol === 'https:' && externalBackend.certFingerprint) {
        externalCertificateTrust = trustBackendCertificate(
          externalBase.origin,
          externalBackend.certFingerprint
        );
      }

      const externalBackendReady = await checkBackendStatus({
        baseUrl: externalBaseUrl,
        serverSecret,
        fetch: fetchFromAccordLockSession,
      });
      if (!externalBackendReady) {
        externalCertificateTrust?.release();
        const canDisableExternalBackend = externalBackend.source === 'settings';
        log.error(`External backend is unreachable: ${externalBaseUrl}`);
        const response = dialog.showMessageBoxSync({
          type: 'error',
          title: 'External Backend Unreachable',
          message: "AccordLock couldn't reach the configured external backend.",
          detail:
            'Check that the backend is running and that its access secret matches the configuration, then try again.',
          buttons: canDisableExternalBackend
            ? ['Disable External Backend & Retry', 'Quit']
            : ['Quit'],
          defaultId: 0,
          cancelId: canDisableExternalBackend ? 1 : 0,
        });

        if (canDisableExternalBackend && response === 0) {
          updateSettings((s) => {
            if (s.externalGoosed) {
              s.externalGoosed.enabled = false;
            }
          });
          return createChat(app, options);
        }

        app.quit();
        return;
      }

      const leaseCertificateTrust = externalCertificateTrust;
      externalCertificateTrust = null;
      gooseServeLease = gooseServeLeases.createExternal(
        acpWebSocketUrlFromHttpBase(externalBaseUrl, serverSecret),
        serverSecret,
        leaseCertificateTrust ? async () => leaseCertificateTrust.release() : undefined
      );
    } catch (error) {
      externalCertificateTrust?.release();
      log.error('External ACP backend is misconfigured', error);
      const canDisableExternalBackend = externalBackend.source === 'settings';
      const response = dialog.showMessageBoxSync({
        type: 'error',
        title: 'External Backend Misconfigured',
        message: 'The external backend URL is invalid.',
        detail: 'Use a valid HTTP or HTTPS base URL, then restart AccordLock.',
        buttons: canDisableExternalBackend
          ? ['Disable External Backend & Retry', 'Quit']
          : ['Quit'],
        defaultId: 0,
        cancelId: canDisableExternalBackend ? 1 : 0,
      });

      if (canDisableExternalBackend && response === 0) {
        updateSettings((s) => {
          if (s.externalGoosed) {
            s.externalGoosed.enabled = false;
          }
        });
        return createChat(app, options);
      }

      app.quit();
      return;
    }
  } else {
    const accordLockApprovalProxy = await requireAccordLockApprovalProxy();
    if (!accordLockApprovalProxy) {
      return;
    }
    backendBindingSecret = generateAccordLockBackendBindingSecret();
    const localCertificateIdentity = {
      registration: null as BackendCertificateTrustRegistration | null,
    };

    const loginShellPath = await getLoginShellPath(log);

    let gooseServeResult: Awaited<ReturnType<typeof startGooseServe>>;
    try {
      gooseServeResult = await startGooseServe({
        serverSecret,
        backendBindingSecret,
        dir: workingDir,
        tls: true,
        env: {
          GOOSE_PATH_ROOT: appConfig.GOOSE_PATH_ROOT as string | undefined,
          ...buildGoosePolicyEnvironment(
            accordLockApprovalProxy.baseUrl,
            accordLockApprovalProxy.bearer,
            (accordLockStartupNetworkPolicy?.allowed_domains.length ?? 0) > 0
          ),
        },
        loginShellPath,
        isPackaged: app.isPackaged,
        resourcesPath: app.isPackaged ? process.resourcesPath : undefined,
        expectedBinarySha256: app.isPackaged ? embeddedGooseBinarySha256() : undefined,
        logger: log,
        diagnosticsDir: STARTUP_LOGS_DIR,
        readinessFetch: fetchFromAccordLockSession,
        onTlsFingerprint: ({ fingerprint, origin }) => {
          if (localCertificateIdentity.registration) {
            throw new Error('goose serve emitted more than one TLS certificate identity');
          }
          const backendOrigin = new URL(origin);
          if (backendOrigin.protocol !== 'https:' || backendOrigin.hostname !== '127.0.0.1') {
            throw new Error('goose serve emitted a certificate for an unexpected origin');
          }
          localCertificateIdentity.registration = trustBackendCertificate(origin, fingerprint);
        },
      });
      if (!gooseServeResult.certFingerprint) {
        await gooseServeResult.cleanup();
        throw new Error(
          'goose serve started with TLS but did not return a certificate fingerprint'
        );
      }

      const localCertFingerprint = normalizeFingerprint(gooseServeResult.certFingerprint);
      if (!localCertificateIdentity.registration) {
        await gooseServeResult.cleanup();
        throw new Error('goose serve TLS certificate identity was not registered');
      }
      if (localCertificateIdentity.registration.trust.fingerprint !== localCertFingerprint) {
        await gooseServeResult.cleanup();
        throw new Error('goose serve TLS certificate fingerprint changed during startup');
      }
    } catch (error) {
      localCertificateIdentity.registration?.release();
      log.error('goose serve failed to start', error);
      dialog.showMessageBoxSync({
        type: 'error',
        title: 'AccordLock Failed to Start',
        message: 'The backend server failed to start.',
        detail:
          'Restart AccordLock. If the problem continues, reinstall the app or contact your administrator. No agent engine was launched.',
        buttons: ['OK'],
      });
      app.quit();
      return;
    }

    workingDir = gooseServeResult.workingDir;
    const registeredLocalCertificateTrust = localCertificateIdentity.registration;
    if (!registeredLocalCertificateTrust) {
      await gooseServeResult.cleanup();
      throw new Error('goose serve TLS certificate identity is unavailable');
    }
    const cleanupGooseServe = gooseServeResult.cleanup;
    gooseServeResult.cleanup = async () => {
      try {
        await cleanupGooseServe();
      } finally {
        registeredLocalCertificateTrust.release();
      }
    };
    gooseServeLease = gooseServeLeases.create(gooseServeResult, serverSecret);
  }

  const cleanupUnregisteredGooseServeLease = async () => {
    if (!gooseServeLease) {
      return;
    }

    const lease = gooseServeLease;
    gooseServeLease = null;
    await gooseServeLeases.cleanupLease(lease);
  };

  let mainWindowState: ReturnType<typeof windowStateKeeper>;
  let mainWindow: BrowserWindow;
  try {
    mainWindowState = windowStateKeeper({
      defaultWidth: 940,
      defaultHeight: 800,
    });

    const integratedWindowsTitleBar = process.platform === 'win32';
    const darkTitleBar = resolveAccordLockDarkTheme(settings);

    mainWindow = new BrowserWindow({
      show: false,
      title: 'AccordLock',
      titleBarStyle:
        process.platform === 'darwin' || integratedWindowsTitleBar ? 'hidden' : 'default',
      titleBarOverlay: integratedWindowsTitleBar
        ? accordLockTitleBarOverlay(darkTitleBar)
        : undefined,
      trafficLightPosition: process.platform === 'darwin' ? { x: 20, y: 16 } : undefined,
      vibrancy: process.platform === 'darwin' ? 'window' : undefined,
      frame: process.platform !== 'darwin',
      autoHideMenuBar: integratedWindowsTitleBar,
      backgroundColor: darkTitleBar ? '#1b1d21' : '#f5f5f3',
      // windowStateKeeper persists the outer window bounds (getBounds), so the
      // window must be restored by outer bounds too. With useContentSize the saved
      // outer height is reapplied as the content height, growing the window by the
      // frame height on every launch on framed platforms (#9363).
      x: mainWindowState.x,
      y: mainWindowState.y,
      width: mainWindowState.width,
      height: mainWindowState.height,
      minWidth: 480,
      minHeight: 400,
      resizable: true,
      icon: accordLockWindowIconPath,
      webPreferences: {
        spellcheck: settings.spellcheckEnabled ?? true,
        preload: path.join(__dirname, 'preload.js'),
        webSecurity: true,
        sandbox: true,
        nodeIntegration: false,
        contextIsolation: true,
        additionalArguments: [
          JSON.stringify({
            ...appConfig,
            GOOSE_WORKING_DIR: workingDir,
            REQUEST_DIR: dir,
            GOOSE_VERSION: version,
            recipeDeeplink: recipeDeeplink,
            recipeId: recipeId,
            recipeParameters: recipeParameters,
            scheduledJobId: scheduledJobId,
            SECURITY_ML_MODEL_MAPPING: process.env.SECURITY_ML_MODEL_MAPPING,
            SECURITY_PROMPT_ENABLED_OVERRIDE: process.env.SECURITY_PROMPT_ENABLED_OVERRIDE,
            SECURITY_COMMAND_CLASSIFIER_ENABLED_OVERRIDE:
              process.env.SECURITY_COMMAND_CLASSIFIER_ENABLED_OVERRIDE,
          }),
        ],
        partition: ACCORDLOCK_SESSION_PARTITION,
      },
    });
    if (integratedWindowsTitleBar) {
      mainWindow.setMenuBarVisibility(false);
    }
    mainWindow.on('page-title-updated', (event) => {
      event.preventDefault();
      mainWindow.setTitle('AccordLock');
    });
  } catch (error) {
    await cleanupUnregisteredGooseServeLease();
    throw error;
  }

  if (gooseServeLease) {
    const lease = gooseServeLease;
    mainWindow.once('closed', () => {
      void gooseServeLeases.releaseWindow(mainWindow.id);
    });
    gooseServeLeases.attachWindow(mainWindow.id, lease);
    gooseServeLease = null;
  }

  if (!app.isPackaged) {
    installExtension(REACT_DEVELOPER_TOOLS, {
      loadExtensionOptions: { allowFileAccess: true },
      session: mainWindow.webContents.session,
    })
      .then(() => log.info('added react dev tools'))
      .catch((err) => log.info('failed to install react dev tools:', err));
  }

  // Let windowStateKeeper manage the window
  mainWindowState.manage(mainWindow);

  mainWindow.webContents.session.setSpellCheckerLanguages(['en-US', 'en-GB']);
  mainWindow.webContents.on('context-menu', (_event, params) => {
    const menu = new Menu();
    const hasSpellingSuggestions = params.dictionarySuggestions.length > 0 || params.misspelledWord;

    if (hasSpellingSuggestions) {
      for (const suggestion of params.dictionarySuggestions) {
        menu.append(
          new MenuItem({
            label: suggestion,
            click: () => mainWindow.webContents.replaceMisspelling(suggestion),
          })
        );
      }

      if (params.misspelledWord) {
        menu.append(
          new MenuItem({
            label: 'Add to dictionary',
            click: () =>
              mainWindow.webContents.session.addWordToSpellCheckerDictionary(params.misspelledWord),
          })
        );
      }

      if (params.selectionText) {
        menu.append(new MenuItem({ type: 'separator' }));
      }
    }
    if (params.selectionText) {
      menu.append(
        new MenuItem({
          label: 'Cut',
          accelerator: 'CmdOrCtrl+X',
          role: 'cut',
        })
      );
      menu.append(
        new MenuItem({
          label: 'Copy',
          accelerator: 'CmdOrCtrl+C',
          role: 'copy',
        })
      );
    }

    // Only show paste in editable fields (text inputs)
    if (params.isEditable) {
      menu.append(
        new MenuItem({
          label: 'Paste',
          accelerator: 'CmdOrCtrl+V',
          role: 'paste',
        })
      );
    }

    if (menu.items.length > 0) {
      menu.popup();
    }
  });

  // Handle new window creation for links (fallback for any links not handled by onClick)
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (!isAccordLockExternalUrlAllowed(url)) {
      return { action: 'deny' };
    }

    shell.openExternal(url);
    return { action: 'deny' };
  });

  // Handle new-window events (alternative approach for external links)
  // Use type assertion for non-standard Electron event
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  mainWindow.webContents.on('new-window' as any, function (event: any, url: string) {
    event.preventDefault();
    if (!isAccordLockExternalUrlAllowed(url)) {
      return;
    }
    shell.openExternal(url);
  });

  const windowId = mainWindow.id;
  const url = getAppUrl();

  let appPath = '/';
  const routeMap: Record<string, string> = {
    chat: '/',
    pair: '/pair',
    settings: '/settings',
    sessions: '/sessions',
    schedules: '/schedules',
    recipes: '/recipes',
    skills: '/skills',
    permission: '/permission',
    ConfigureProviders: '/configure-providers',
  };

  if (viewType) {
    appPath = routeMap[viewType] || '/';
  }
  if (
    appPath === '/' &&
    (recipeDeeplink !== undefined || recipeId !== undefined || initialMessage)
  ) {
    appPath = '/pair';
  }

  let searchParams = new URLSearchParams();
  if (resumeSessionId) {
    searchParams.set('resumeSessionId', resumeSessionId);
    if (appPath === '/') {
      appPath = '/pair';
    }
  }

  // Goose's react app uses HashRouter, so the path + search params follow a #/
  url.hash = `${appPath}?${searchParams.toString()}`;
  let formattedUrl = formatUrl(url);
  log.info('Opening URL: ', formattedUrl);
  let mainWindowShown = false;
  const showMainWindow = () => {
    if (mainWindowShown) return;
    if (!mainWindow.isDestroyed()) {
      mainWindowShown = true;
      mainWindow.show();
    }
  };
  mainWindow.once('ready-to-show', showMainWindow);
  mainWindow.webContents.once('did-finish-load', showMainWindow);

  await desktopFileAccess.bindWindow(windowId, workingDir, protectedWorkspaceRoots);
  if (mainWindow.isDestroyed()) {
    desktopFileAccess.unbindWindow(windowId);
    return;
  }
  windowMap.set(windowId, mainWindow);
  if (backendBindingSecret) {
    accordLockBackendBindings.set(windowId, backendBindingSecret);
  }

  mainWindow.webContents.on('render-process-gone', (_event, details) => {
    accordLockNavigationAllowance.clear(windowId);
    if (shutdownState !== 'idle') return;
    log.warn(`AccordLock renderer ${windowId} exited (${details.reason}); retiring its tasks`);
    void revokeAccordLockWindowAuthorizations(
      windowId,
      accordLockTaskControl,
      accordLockRuntime
    ).catch((error) => {
      failClosedTaskRevocation(`window ${windowId} renderer exit`, error);
    });
  });

  let windowRevocationComplete = false;
  let windowRevocationPromise: Promise<void> | null = null;
  mainWindow.on('close', (event) => {
    if (windowRevocationComplete || shutdownState === 'complete') {
      return;
    }
    event.preventDefault();
    if (windowRevocationPromise) {
      return;
    }
    windowRevocationPromise = accordLockTaskControl
      .revokeWindowAuthorizations(windowId, accordLockRuntime)
      .then(() => {
        windowRevocationComplete = true;
        if (!mainWindow.isDestroyed()) {
          mainWindow.close();
        }
      })
      .catch((error) => {
        failClosedTaskRevocation(`window ${windowId} close`, error);
      })
      .finally(() => {
        windowRevocationPromise = null;
      });
  });

  // Final cleanup after the revocation-gated close completes.
  mainWindow.on('closed', () => {
    accordLockNavigationAllowance.clear(windowId);
    windowMap.delete(windowId);
    accordLockBackendBindings.delete(windowId);
    desktopFileAccess.unbindWindow(windowId);
    if (!windowRevocationComplete && shutdownState === 'idle') {
      failClosedTaskRevocation(
        `window ${windowId} destroyed before revocation`,
        new Error('Window closed without completing its task authorization revocation barrier')
      );
    }

    pendingInitialMessages.delete(windowId);
    pendingDeepLinks.delete(windowId);
    reactReadyWindows.delete(windowId);

    if (windowPowerSaveBlockers.has(windowId)) {
      const blockerId = windowPowerSaveBlockers.get(windowId)!;
      try {
        powerSaveBlocker.stop(blockerId);
        console.log(
          `[Main] Stopped power save blocker ${blockerId} for closing window ${windowId}`
        );
      } catch (error) {
        console.error(
          `[Main] Failed to stop power save blocker ${blockerId} for window ${windowId}:`,
          error
        );
      }
      windowPowerSaveBlockers.delete(windowId);
    }
  });

  const blockUnexpectedTopLevelNavigation = (
    event: Pick<Event, 'preventDefault'>,
    navigationUrl: string
  ) => {
    if (accordLockNavigationAllowance.consume(windowId, navigationUrl)) return;
    interceptUnexpectedAccordLockTopLevelNavigation(event, () =>
      requestAccordLockWindowReload(mainWindow, `window ${windowId} unexpected navigation`)
    );
  };
  mainWindow.webContents.on('will-navigate', blockUnexpectedTopLevelNavigation);
  mainWindow.webContents.on('will-redirect', blockUnexpectedTopLevelNavigation);
  mainWindow.webContents.on('did-finish-load', () => accordLockNavigationAllowance.clear(windowId));
  mainWindow.webContents.on('did-fail-load', () => accordLockNavigationAllowance.clear(windowId));

  accordLockNavigationAllowance.arm(windowId, formattedUrl);
  mainWindow.loadURL(formattedUrl);

  // If we have an initial message, store it to send after React is ready
  if (initialMessage) {
    pendingInitialMessages.set(mainWindow.id, initialMessage);
    if (initialMessageNoAutoSubmit) {
      pendingInitialMessageNoAutoSubmit.add(mainWindow.id);
    }
  }

  // Set up local keyboard shortcuts that only work when the window is focused
  mainWindow.webContents.on('before-input-event', (event, input) => {
    const key = input.key.toLowerCase();
    if ((key === 'r' && (input.meta || input.control)) || key === 'f5') {
      event.preventDefault();
      requestAccordLockWindowReload(mainWindow, `window ${windowId} keyboard reload`);
    }

    if (!app.isPackaged && input.key === 'i' && input.alt && input.meta) {
      mainWindow.webContents.openDevTools();
      event.preventDefault();
    }
  });

  mainWindow.on('app-command', (e, cmd) => {
    if (cmd === 'browser-backward') {
      mainWindow.webContents.send('mouse-back-button-clicked');
      e.preventDefault();
    }
  });

  const broadcastFullScreenState = () => {
    if (!mainWindow.isDestroyed()) {
      mainWindow.webContents.send('fullscreen-change', mainWindow.isFullScreen());
    }
  };
  mainWindow.on('enter-full-screen', broadcastFullScreenState);
  mainWindow.on('leave-full-screen', broadcastFullScreenState);

  // Handle mouse back button (button 3)
  // Use type assertion for non-standard Electron event
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  mainWindow.webContents.on('mouse-up' as any, function (_event: any, mouseButton: number) {
    // MouseButton 3 is the back button.
    if (mouseButton === 3) {
      mainWindow.webContents.send('mouse-back-button-clicked');
    }
  });

  return mainWindow;
};

let activeLauncherWindow: BrowserWindow | null = null;

const createLauncher = () => {
  if (activeLauncherWindow && !activeLauncherWindow.isDestroyed()) {
    activeLauncherWindow.focus();
    return activeLauncherWindow;
  }

  const launcherWorkspace = resolveAccordLockWorkspace(
    loadRecentDirs()[0],
    app.getPath('userData'),
    [os.homedir(), app.getPath('userData'), accordLockEnginePathRoot]
  );
  fsSync.mkdirSync(accordLockDefaultWorkspace(app.getPath('userData')), { recursive: true });
  const launcherWindow = new BrowserWindow({
    width: 680,
    height: 132,
    frame: false,
    transparent: process.platform === 'darwin',
    backgroundColor: process.platform === 'darwin' ? '#00000000' : '#ffffff',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      additionalArguments: [
        JSON.stringify({
          ...appConfig,
          ACCORDLOCK_LAUNCHER_WORKSPACE: launcherWorkspace,
        }),
      ],
      partition: ACCORDLOCK_SESSION_PARTITION,
    },
    skipTaskbar: true,
    alwaysOnTop: true,
    resizable: false,
    movable: true,
    minimizable: false,
    maximizable: false,
    fullscreenable: false,
    hasShadow: true,
    vibrancy: process.platform === 'darwin' ? 'window' : undefined,
  });

  // Center on screen
  const primaryDisplay = screen.getPrimaryDisplay();
  const { width, height } = primaryDisplay.workAreaSize;
  const windowBounds = launcherWindow.getBounds();

  launcherWindow.setPosition(
    Math.round(width / 2 - windowBounds.width / 2),
    Math.round(height / 3 - windowBounds.height / 2)
  );

  // Load launcher window content
  const url = getAppUrl();

  url.hash = '/launcher';
  launcherWindow.loadURL(formatUrl(url));
  activeLauncherWindow = launcherWindow;

  launcherWindow.on('closed', () => {
    reactReadyWindows.delete(launcherWindow.id);
    activeLauncherWindow = null;
  });

  // Destroy window when it loses focus
  launcherWindow.on('blur', () => {
    launcherWindow.destroy();
  });

  // Also destroy on escape key
  launcherWindow.webContents.on('before-input-event', (event, input) => {
    if (input.key === 'Escape') {
      launcherWindow.destroy();
      event.preventDefault();
    }
  });

  return launcherWindow;
};

// Track tray instance
let tray: Tray | null = null;

const destroyTray = () => {
  if (tray) {
    tray.destroy();
    tray = null;
  }
};

const disableTray = () => {
  updateSettings((s) => {
    s.showMenuBarIcon = false;
  });
};

const createTray = () => {
  destroyTray();

  const trayIconName = process.platform === 'darwin' ? 'iconTemplate.png' : 'iconTray.png';

  const possiblePaths = [
    path.join(process.resourcesPath, 'images', trayIconName),
    path.join(process.cwd(), 'src', 'images', trayIconName),
    path.join(__dirname, '..', 'images', trayIconName),
    path.join(__dirname, 'images', trayIconName),
    path.join(process.cwd(), 'images', trayIconName),
  ];

  const iconPath = possiblePaths.find((p) => fsSync.existsSync(p));

  if (!iconPath) {
    console.warn('[Main] Tray icon not found. App will continue without system tray.');
    disableTray();
    return;
  }

  try {
    tray = new Tray(iconPath);
    setTrayRef(tray);
    updateTrayMenu(getUpdateAvailable());

    if (process.platform === 'win32') {
      tray.on('click', showWindow);
    }
  } catch (error) {
    console.error('[Main] Tray creation failed. App will continue without system tray.', error);
    disableTray();
    tray = null;
  }
};

const showWindow = async () => {
  const windows = BrowserWindow.getAllWindows();

  if (windows.length === 0) {
    log.info('No windows are open, creating a new one...');
    const recentDirs = loadRecentDirs();
    const openDir = recentDirs.length > 0 ? recentDirs[0] : null;
    await createChat(app, { dir: openDir || undefined });
    return;
  }

  const initialOffsetX = 30;
  const initialOffsetY = 30;

  // Iterate over all windows
  windows.forEach((win, index) => {
    const currentBounds = win.getBounds();
    const newX = currentBounds.x + initialOffsetX * index;
    const newY = currentBounds.y + initialOffsetY * index;

    win.setBounds({
      x: newX,
      y: newY,
      width: currentBounds.width,
      height: currentBounds.height,
    });

    if (!win.isVisible()) {
      win.show();
    }

    win.focus();
  });
};

const buildRecentFilesMenu = () => {
  const recentDirs = loadRecentDirs();
  return recentDirs.map((dir) => ({
    label: dir,
    click: async () => {
      await createChat(app, { dir });
    },
  }));
};

const openDirectoryDialog = async (): Promise<OpenDialogReturnValue> => {
  // Get the current working directory from the focused window
  let defaultPath: string | undefined;
  const currentWindow = BrowserWindow.getFocusedWindow();

  if (currentWindow) {
    try {
      const currentWorkingDir = await currentWindow.webContents.executeJavaScript(
        `window.appConfig ? window.appConfig.get('GOOSE_WORKING_DIR') : null`
      );

      if (currentWorkingDir && typeof currentWorkingDir === 'string') {
        // Verify the directory exists before using it as default
        try {
          const stats = fsSync.lstatSync(currentWorkingDir);
          if (stats.isDirectory()) {
            defaultPath = currentWorkingDir;
          }
        } catch (error) {
          if (error && typeof error === 'object' && 'code' in error) {
            const fsError = error as { code?: string; message?: string };
            if (
              fsError.code === 'ENOENT' ||
              fsError.code === 'EACCES' ||
              fsError.code === 'EPERM'
            ) {
              console.warn(
                `Current working directory not accessible (${fsError.code}): ${currentWorkingDir}, falling back to home directory`
              );
              defaultPath = os.homedir();
            } else {
              console.warn(
                `Unexpected filesystem error (${fsError.code}) for directory ${currentWorkingDir}:`,
                fsError.message
              );
              defaultPath = os.homedir();
            }
          } else {
            console.warn(`Unexpected error checking directory ${currentWorkingDir}:`, error);
            defaultPath = os.homedir();
          }
        }
      }
    } catch (error) {
      console.warn('Failed to get current working directory from window:', error);
    }
  }

  if (!defaultPath) {
    defaultPath = os.homedir();
  }

  const result = (await dialog.showOpenDialog({
    properties: ['openFile', 'openDirectory', 'createDirectory'],
    defaultPath: defaultPath,
  })) as unknown as OpenDialogReturnValue;

  if (!result.canceled && result.filePaths.length > 0) {
    const selectedPath = result.filePaths[0];

    // If a file was selected, use its parent directory
    let dirToAdd = selectedPath;
    try {
      const stats = fsSync.lstatSync(selectedPath);

      // Reject symlinks for security
      if (stats.isSymbolicLink()) {
        console.warn(`Selected path is a symlink, using parent directory for security`);
        dirToAdd = path.dirname(selectedPath);
      } else if (stats.isFile()) {
        dirToAdd = path.dirname(selectedPath);
      }
    } catch {
      console.warn(`Could not stat selected path, using parent directory`);
      dirToAdd = path.dirname(selectedPath); // Fallback to parent directory
    }

    addRecentDir(dirToAdd);

    let deeplinkData: RecipeDeeplinkData | undefined = undefined;
    if (windowDeeplinkURL) {
      deeplinkData = parseRecipeDeeplink(windowDeeplinkURL);
    }
    await createChat(app, {
      dir: dirToAdd,
      recipeDeeplink: deeplinkData?.config,
      recipeParameters: deeplinkData?.parameters,
    });
  }
  return result;
};

interface RecipeDeeplinkData {
  config: string;
  parameters?: Record<string, string>;
}

function parseRecipeDeeplink(url: string): RecipeDeeplinkData | undefined {
  const parsedUrl = new URL(url);
  let recipeDeeplink = parsedUrl.searchParams.get('config');
  if (recipeDeeplink && !url.includes(recipeDeeplink)) {
    // URLSearchParams decodes + as space, which can break encoded configs
    // Parse raw query to preserve "+" characters in values like config
    const search = parsedUrl.search || '';
    const configMatch = search.match(/(?:[?&])config=([^&]*)/);
    let recipeDeeplinkTmp = configMatch ? configMatch[1] : null;
    if (recipeDeeplinkTmp) {
      try {
        recipeDeeplink = decodeURIComponent(recipeDeeplinkTmp);
      } catch (error) {
        console.error('[Main] parseRecipeDeeplink - Failed to decode:', errorMessage(error));
        return undefined;
      }
    }
  }
  if (!recipeDeeplink) {
    return undefined;
  }

  // Extract all query parameters except 'config' and 'scheduledJob' as recipe parameters
  // Use raw query string parsing to preserve '+' characters (consistent with config handling)
  const parameters: Record<string, string> = {};
  const search = parsedUrl.search || '';
  const paramMatches = search.matchAll(/[?&]([^=&]+)=([^&]*)/g);

  for (const match of paramMatches) {
    const key = match[1];
    const rawValue = match[2];

    if (key !== 'config' && key !== 'scheduledJob') {
      try {
        parameters[key] = decodeURIComponent(rawValue);
      } catch {
        // If decoding fails, use raw value
        parameters[key] = rawValue;
      }
    }
  }

  return {
    config: recipeDeeplink,
    parameters: Object.keys(parameters).length > 0 ? parameters : undefined,
  };
}

// Global error handler
const handleFatalError = (error: Error) => {
  log.error('Fatal main-process error', error);
  const windows = BrowserWindow.getAllWindows();
  windows.forEach((win) => {
    win.webContents.send(
      'fatal-error',
      'AccordLock stopped unexpectedly. Restart the app. If this happens again, contact support.'
    );
  });
};

let handlingFatalMainProcessError = false;

const failClosedOnMainProcessError = (kind: string, rawError: unknown) => {
  const error = rawError instanceof Error ? rawError : new Error(String(rawError));
  if (handlingFatalMainProcessError) {
    // Do not recurse forever if logging, notification, or revocation itself faults.
    app.exit(1);
    return;
  }

  handlingFatalMainProcessError = true;
  try {
    // `console.error` can itself throw when a detached Windows launcher closes its
    // stdio pipe. electron-log writes to the bounded application log instead.
    log.error(`${kind}: ${formatErrorForLogging(error)}`);
  } catch {
    // The security response must not depend on logging availability.
  }
  try {
    handleFatalError(error);
  } finally {
    // Enter the normal AccordLock revocation barrier. If it faults, the re-entrant
    // guard above terminates the process and closes inherited runtime authority.
    app.quit();
  }
};

process.on('uncaughtException', (error) => {
  failClosedOnMainProcessError('Uncaught Exception', error);
});

process.on('unhandledRejection', (error) => {
  failClosedOnMainProcessError('Unhandled Rejection', error);
});

ipcMain.on('react-ready', (event) => {
  log.info('React ready event received');

  // Get the window that sent the react-ready event
  const window = BrowserWindow.fromWebContents(event.sender);
  const windowId = window?.id;

  if (windowId !== undefined) {
    reactReadyWindows.add(windowId);
  }

  // Send any pending initial message for this window
  if (windowId && pendingInitialMessages.has(windowId)) {
    const initialMessage = pendingInitialMessages.get(windowId)!;
    const noAutoSubmit = pendingInitialMessageNoAutoSubmit.has(windowId);
    log.info('Sending pending initial message to window:', initialMessage);
    window.webContents.send('set-initial-message', initialMessage, { noAutoSubmit });
    pendingInitialMessages.delete(windowId);
    pendingInitialMessageNoAutoSubmit.delete(windowId);
  }

  if (windowId && pendingDeepLinks.has(windowId) && window) {
    const deepLinkUrl = pendingDeepLinks.get(windowId)!;
    pendingDeepLinks.delete(windowId);
    log.info('Processing pending deep link for window:', windowId);
    try {
      const parsedUrl = new URL(deepLinkUrl);
      if (parsedUrl.hostname === 'extension') {
        window.webContents.send('add-extension', deepLinkUrl);
      } else if (parsedUrl.hostname === 'sessions') {
        sendOpenSharedSession(window, deepLinkUrl);
      }
    } catch (error) {
      log.error('Error processing pending deep link:', error);
    }
  }
});

ipcMain.handle('open-external', async (event, url: string) => {
  requireRegularRendererWindow(event);
  if (!isAccordLockExternalUrlAllowed(url)) throw new Error('External URL is not permitted');
  await shell.openExternal(url);
});

async function selectNativeWorkspace(senderWindow: BrowserWindow) {
  return desktopFileAccess.selectWorkspaceWithNativeDialog(senderWindow.id, async (defaultPath) =>
    dialog.showOpenDialog(senderWindow, {
      properties: ['openDirectory', 'createDirectory'],
      defaultPath,
    })
  );
}

ipcMain.handle('accordlock:project-folder:select', async (event) => {
  const senderWindow = requireRegularRendererWindow(event);
  const selection = await selectNativeWorkspace(senderWindow);
  return selection.canceled ? null : (selection.directory ?? null);
});

ipcMain.handle('open-secure-workspace-window', async (event) => {
  const senderWindow = requireRegularRendererWindow(event);
  const selection = await selectNativeWorkspace(senderWindow);
  if (selection.canceled || !selection.directory) {
    return { opened: false, canceled: true };
  }
  if (senderWindow.isDestroyed() || windowMap.get(senderWindow.id) !== senderWindow) {
    throw new Error('The source window closed before the workspace could be opened');
  }
  addRecentDir(selection.directory);
  await createChat(app, { dir: selection.directory });
  return { opened: true, canceled: false };
});

ipcMain.handle('accordlock:terminal-program:add', async (event, alias: unknown) => {
  const senderWindow = requireRegularRendererWindow(event);
  const result = await pickAndPersistAccordLockTerminalProgram({
    alias,
    configurationPath: terminalProgramConfigurationPath(),
    selectExecutable: () =>
      dialog.showOpenDialog(senderWindow, {
        title: 'Choose a trusted native program for AccordLock',
        properties: ['openFile'],
        filters:
          process.platform === 'win32'
            ? [{ name: 'Native programs', extensions: ['exe'] }]
            : undefined,
      }),
    confirmBinding: async (binding) => {
      return showAccordLockSettingsConfirmationWindow(
        senderWindow,
        {
          title: 'Trust this native program?',
          message: `Allow the alias “${binding.alias}” to run this exact executable?`,
          detail: `${binding.executable_path}\n\n${binding.executable_sha256}\n\nPrograms require approval for each action, but are not sandboxed and may affect the system beyond the workspace.`,
          confirmLabel: 'Trust program',
          cancelLabel: 'Cancel',
          tone: 'warning',
          defaultButton: 'cancel',
          buttonOrder: 'confirm-first',
        },
        resolveAccordLockDarkTheme() ? 'dark' : 'light'
      );
    },
  });
  return {
    ...result,
    programs: loadAccordLockTerminalPrograms(terminalProgramConfigurationPath()),
  };
});

ipcMain.handle('accordlock:terminal-program:list', (event) => {
  requireRegularRendererWindow(event);
  return loadAccordLockTerminalPrograms(terminalProgramConfigurationPath());
});

ipcMain.handle('accordlock:terminal-program:remove', async (event, alias: unknown) => {
  const senderWindow = requireRegularRendererWindow(event);
  const trustedAlias = validateAccordLockTerminalProgramAlias(alias);
  const confirmed = await showAccordLockSettingsConfirmationWindow(
    senderWindow,
    {
      title: 'Remove trusted program?',
      message: `Remove the terminal alias “${trustedAlias}”?`,
      detail: 'The change is applied after AccordLock restarts.',
      confirmLabel: 'Remove',
      cancelLabel: 'Cancel',
      tone: 'warning',
      defaultButton: 'cancel',
      buttonOrder: 'confirm-first',
    },
    resolveAccordLockDarkTheme() ? 'dark' : 'light'
  );
  const removed = confirmed
    ? removeAccordLockTerminalProgram(trustedAlias, terminalProgramConfigurationPath())
    : false;
  return {
    removed,
    canceled: !confirmed,
    restartRequired: removed,
    programs: loadAccordLockTerminalPrograms(terminalProgramConfigurationPath()),
  };
});

ipcMain.handle('accordlock:network-policy:get', (event) => {
  requireRegularRendererWindow(event);
  const stored = loadAccordLockNetworkPolicy(accordLockNetworkPolicyPath);
  return {
    domains: stored?.allowed_domains ?? [],
    methods: ['GET', 'HEAD'],
    active:
      (stored?.configuration_digest ?? null) ===
      (accordLockStartupNetworkPolicy?.configuration_digest ?? null),
  };
});

ipcMain.handle('accordlock:network-policy:set', async (event, domains: unknown) => {
  const senderWindow = requireRegularRendererWindow(event);
  const previewDomains = normalizeAccordLockNetworkDomains(domains);
  const enabled = previewDomains.length > 0;
  const confirmed = await showAccordLockSettingsConfirmationWindow(
    senderWindow,
    {
      title: enabled ? 'Allow network access to these domains?' : 'Turn off network access?',
      message: enabled
        ? `Allow read-only HTTPS requests to ${previewDomains.length} exact ${previewDomains.length === 1 ? 'domain' : 'domains'}?`
        : 'Remove all governed network destinations?',
      detail: enabled
        ? `${previewDomains.join('\n')}\n\nOnly GET and HEAD are available. Every request requires single-use approval. Redirects, wildcard domains, ambient credentials, and proxies are blocked. The change applies after restart.`
        : 'The change applies after AccordLock restarts.',
      confirmLabel: enabled ? 'Save domains' : 'Turn off access',
      cancelLabel: 'Cancel',
      tone: enabled ? 'warning' : 'neutral',
      defaultButton: 'cancel',
      buttonOrder: 'confirm-first',
    },
    resolveAccordLockDarkTheme() ? 'dark' : 'light'
  );
  if (!confirmed) {
    const current = loadAccordLockNetworkPolicy(accordLockNetworkPolicyPath);
    return {
      saved: false,
      canceled: true,
      restartRequired: false,
      domains: current?.allowed_domains ?? [],
      methods: ['GET', 'HEAD'],
    };
  }
  const stored = writeAccordLockNetworkPolicy(accordLockNetworkPolicyPath, previewDomains);
  return {
    saved: true,
    canceled: false,
    restartRequired:
      stored.configuration_digest !== accordLockStartupNetworkPolicy?.configuration_digest,
    domains: stored.allowed_domains,
    methods: ['GET', 'HEAD'],
  };
});

ipcMain.handle('get-setting', (event, key: SettingKey) => {
  requireRegularRendererWindow(event);
  if (!validSettingKeys.has(key)) throw new Error('Setting is not exposed to the renderer');
  const settings = getSettings();
  return settings[key];
});

ipcMain.handle(ACCORDLOCK_APPROVAL_CHANNELS_LIST, async (event) => {
  requireRegularRendererWindow(event);
  return accordLockApprovalChannelStore.list();
});

ipcMain.handle(ACCORDLOCK_APPROVAL_CHANNELS_SAVE, async (event, configuration: unknown) => {
  requireRegularRendererWindow(event);
  return accordLockApprovalChannelStore.save(configuration);
});

ipcMain.handle(
  ACCORDLOCK_APPROVAL_CHANNELS_SET_ENABLED,
  async (event, channel: unknown, enabled: unknown) => {
    requireRegularRendererWindow(event);
    return accordLockApprovalChannelStore.setEnabled(channel, enabled);
  }
);

ipcMain.handle(ACCORDLOCK_APPROVAL_CHANNELS_REMOVE, async (event, channel: unknown) => {
  const senderWindow = requireRegularRendererWindow(event);
  if (!isChannelId(channel)) throw new Error('Approval channel is not supported');
  const confirmed = await showAccordLockSettingsConfirmationWindow(
    senderWindow,
    {
      title: 'Remove approval channel?',
      message: 'AccordLock will forget this channel’s credentials.',
      confirmLabel: 'Remove',
      cancelLabel: 'Cancel',
      tone: 'warning',
      defaultButton: 'cancel',
      buttonOrder: 'confirm-first',
    },
    resolveAccordLockDarkTheme() ? 'dark' : 'light'
  );
  if (!confirmed) return false;
  return accordLockApprovalChannelStore.remove(channel);
});

ipcMain.handle(ACCORDLOCK_APPROVAL_CHANNELS_TEST, async (event, channel: unknown) => {
  requireRegularRendererWindow(event);
  const bundle = await accordLockApprovalChannelStore.loadNotificationTestBundle(channel);
  return dispatchAccordLockConnectionTest({
    acceptDirtyDevelopmentMarker: acceptDirtyAccordLockRuntimeMarker(),
    binDirectory: runtimeBinDirectory(),
    bundle,
    expectedBinarySha256: app.isPackaged ? embeddedRuntimeBinarySha256() : undefined,
  });
});

ipcMain.handle(ACCORDLOCK_REMOTE_APPROVAL_ENROLLMENT_GET, async (event) => {
  requireRegularRendererWindow(event);
  return accordLockRemoteApprovalGatewayStore.getSummary();
});

ipcMain.handle(ACCORDLOCK_REMOTE_APPROVAL_ENROLLMENT_IMPORT, async (event) => {
  const senderWindow = requireRegularRendererWindow(event);
  const selection = await dialog.showOpenDialog(senderWindow, {
    title: 'Pair a remote approval gateway',
    properties: ['openFile'],
    filters: [{ name: 'Gateway enrollment', extensions: ['json'] }],
  });
  if (selection.canceled || selection.filePaths.length !== 1) return null;
  const document = await readBoundedRemoteApprovalDocument(selection.filePaths[0]);
  const now = Math.floor(Date.now() / 1_000);
  const preview = previewAccordLockRemoteGatewayEnrollment(document, now);
  const confirmed = await showAccordLockSettingsConfirmationWindow(
    senderWindow,
    {
      title: 'Trust this approval gateway?',
      message: preview.gatewayName,
      detail: [
        `Channels: ${preview.channels.join(', ')}`,
        `Key: ${preview.fingerprint}`,
        `Valid until: ${new Date(preview.validUntil * 1_000).toLocaleString()}`,
        '',
        'Only signed, exact, single-use decisions from this key will be accepted. Provider callbacks never enter the desktop app.',
      ].join('\n'),
      confirmLabel: 'Pair gateway',
      cancelLabel: 'Cancel',
      tone: 'warning',
      defaultButton: 'cancel',
      buttonOrder: 'confirm-first',
    },
    resolveAccordLockDarkTheme() ? 'dark' : 'light'
  );
  if (!confirmed) return null;
  return accordLockRemoteApprovalGatewayStore.enroll(document);
});

ipcMain.handle(
  ACCORDLOCK_REMOTE_APPROVAL_ENROLLMENT_REVOKE,
  async (event, enrollmentId: unknown) => {
    const senderWindow = requireRegularRendererWindow(event);
    const current = await accordLockRemoteApprovalGatewayStore.getSummary();
    if (!current || current.enrollmentId !== enrollmentId) {
      throw new Error('Remote approval gateway enrollment was not found');
    }
    const confirmed = await showAccordLockSettingsConfirmationWindow(
      senderWindow,
      {
        title: 'Revoke remote approvals?',
        message: `Stop accepting decisions from ${current.gatewayName}?`,
        detail:
          'New remote decisions will be refused immediately. Approval alerts can remain enabled.',
        confirmLabel: 'Revoke gateway',
        cancelLabel: 'Cancel',
        tone: 'warning',
        defaultButton: 'cancel',
        buttonOrder: 'confirm-first',
      },
      resolveAccordLockDarkTheme() ? 'dark' : 'light'
    );
    if (!confirmed) return current;
    return accordLockRemoteApprovalGatewayStore.revoke(enrollmentId);
  }
);

ipcMain.handle(ACCORDLOCK_REMOTE_APPROVAL_RECEIPT_IMPORT, async (event) => {
  const senderWindow = requireRegularRendererWindow(event);
  const selection = await dialog.showOpenDialog(senderWindow, {
    title: 'Import a signed remote decision',
    properties: ['openFile'],
    filters: [{ name: 'Verified decision receipt', extensions: ['json'] }],
  });
  if (selection.canceled || selection.filePaths.length !== 1) return null;
  const document = await readBoundedRemoteApprovalDocument(selection.filePaths[0]);
  return submitAccordLockVerifiedRemoteDecision(document);
});

ipcMain.handle(ACCORDLOCK_ENVIRONMENT_PROFILES_LIST, async (event) => {
  requireRegularRendererWindow(event);
  const profiles = await accordLockEnvironmentProfileStore.list();
  return Promise.all(profiles.map(accordLockEnvironmentView));
});

ipcMain.handle(ACCORDLOCK_ENVIRONMENT_PROFILES_SAVE, async (event, profile: unknown) => {
  const senderWindow = requireRegularRendererWindow(event);
  const prepared = await accordLockEnvironmentProfileStore.resolveAwsCredential(profile);
  const assertPinnedRoute = async () => {
    if (!prepared.input.id) return;
    const trust = await accordLockPreflightTrustStore.getCiAuthorityStatus(prepared.input.id);
    if (trust.status === 'ENROLLED') {
      assertPinnedCiRouteUnchanged(
        await accordLockEnvironmentProfileStore.loadExecutionBundle(prepared.input.id),
        prepared.input
      );
    }
  };
  await assertPinnedRoute();
  if (!prepared.needsDiscovery && prepared.existingEndpoint) {
    await assertPinnedRoute();
    return accordLockEnvironmentView(
      await accordLockEnvironmentProfileStore.save(profile, prepared.existingEndpoint)
    );
  }
  const controller = new AbortController();
  const abortHandler = () => controller.abort();
  senderWindow.once('closed', abortHandler);
  try {
    const discovered = await accordLockBundledPreflightRunner.discoverEks(
      {
        accountId: prepared.input.aws.accountId,
        region: prepared.input.aws.region,
        clusterName: prepared.input.kubernetes.clusterName,
        awsCredential: prepared.material,
      },
      controller.signal
    );
    if (senderWindow.isDestroyed()) throw new Error('ACCORDLOCK_EKS_CONNECTION_CANCELLED');
    const confirmed = await showAccordLockSettingsConfirmationWindow(
      senderWindow,
      {
        title: 'Connect this EKS cluster?',
        message: prepared.input.kubernetes.clusterName,
        detail: [
          `Cluster: ${discovered.clusterArn}`,
          `Endpoint: ${discovered.endpoint}`,
          `CA fingerprint: ${discovered.clusterCaHash}`,
        ].join('\n'),
        confirmLabel: 'Connect',
        cancelLabel: 'Cancel',
        tone: 'info',
        defaultButton: 'confirm',
        buttonOrder: 'confirm-first',
      },
      resolveAccordLockDarkTheme() ? 'dark' : 'light'
    );
    if (!confirmed) throw new Error('ACCORDLOCK_EKS_CONNECTION_CANCELLED');
    await assertPinnedRoute();
    return accordLockEnvironmentView(
      await accordLockEnvironmentProfileStore.save(profile, discovered.endpoint)
    );
  } finally {
    senderWindow.removeListener('closed', abortHandler);
  }
});

ipcMain.handle(ACCORDLOCK_ENVIRONMENT_PROFILES_REMOVE, async (event, profileId: unknown) => {
  const senderWindow = requireRegularRendererWindow(event);
  if (!isAccordLockEnvironmentProfileId(profileId)) {
    throw new Error('Environment profile identifier is invalid');
  }
  const confirmed = await showAccordLockSettingsConfirmationWindow(
    senderWindow,
    {
      title: 'Remove environment?',
      message: 'AccordLock will forget this environment and its protected credentials.',
      confirmLabel: 'Remove',
      cancelLabel: 'Cancel',
      tone: 'warning',
      defaultButton: 'cancel',
      buttonOrder: 'confirm-first',
    },
    resolveAccordLockDarkTheme() ? 'dark' : 'light'
  );
  if (!confirmed) return false;
  await accordLockPreflightTrustStore.remove(profileId);
  return accordLockEnvironmentProfileStore.remove(profileId);
});

ipcMain.handle(ACCORDLOCK_DEPLOYMENT_PREFLIGHT_RUN, async (event, input: unknown) => {
  requireRegularRendererWindow(event);
  return accordLockEnvironmentPreflight.run(input);
});

ipcMain.handle(
  ACCORDLOCK_DEPLOYMENT_PREFLIGHT_CI_EVIDENCE_IMPORT,
  async (event, input: unknown) => {
    const senderWindow = requireRegularRendererWindow(event);
    const parsed = deploymentPreflightCiEvidenceImportInputSchema.parse(input);
    const selection = await dialog.showOpenDialog(senderWindow, {
      title: 'Import build proof',
      properties: ['openFile'],
      filters: [{ name: 'JSON', extensions: ['json'] }],
    });
    if (selection.canceled || selection.filePaths.length !== 1) {
      return { status: 'CANCELED', environmentId: parsed.environmentId } as const;
    }
    const rawBundle = await readBoundedCiEvidence(selection.filePaths[0]);
    return accordLockCiEvidenceEnrollment.importForEnvironment(parsed.environmentId, rawBundle, {
      confirm: async (preview) => {
        if (senderWindow.isDestroyed()) return false;
        return showAccordLockSettingsConfirmationWindow(
          senderWindow,
          {
            title: 'Trust this CI source?',
            message: `${preview.repository} · run ${preview.runId}`,
            detail: ciEvidenceConfirmationDetail(preview),
            confirmLabel: 'Trust and import',
            cancelLabel: 'Cancel',
            tone: 'warning',
            defaultButton: 'cancel',
            buttonOrder: 'cancel-first',
          },
          resolveAccordLockDarkTheme() ? 'dark' : 'light'
        );
      },
    });
  }
);

ipcMain.handle(ACCORDLOCK_DEPLOYMENT_PREFLIGHT_HISTORY_LIST, async (event, input: unknown) => {
  requireRegularRendererWindow(event);
  const parsed = deploymentPreflightHistoryListInputSchema.parse(input);
  return accordLockDeploymentPreflightReceiptArchive.listSummaries({
    environmentId: parsed.environmentId,
    limit: parsed.limit,
  });
});

ipcMain.handle(ACCORDLOCK_DEPLOYMENT_PREFLIGHT_HISTORY_EXPORT, async (event, input: unknown) => {
  const senderWindow = requireRegularRendererWindow(event);
  const parsed = deploymentPreflightHistoryExportInputSchema.parse(input);
  const exported = await accordLockDeploymentPreflightReceiptArchive.exportPackage(
    parsed.receiptHash
  );
  const selection = await dialog.showSaveDialog(senderWindow, {
    title: 'Export check receipt',
    defaultPath: exported.fileName,
    filters: [{ name: 'JSON', extensions: ['json'] }],
  });
  if (selection.canceled || !selection.filePath) {
    return {
      saved: false,
      canceled: true,
      fileName: null,
      packageDigest: null,
    };
  }
  await fs.writeFile(selection.filePath, exported.contents);
  return {
    saved: true,
    canceled: false,
    fileName: path.basename(selection.filePath),
    packageDigest: exported.packageDigest,
  };
});

// Valid setting keys for runtime validation
const validSettingKeys: Set<string> = new Set([
  'showMenuBarIcon',
  'showDockIcon',
  'enableWakelock',
  'enableNotifications',
  'spellcheckEnabled',
  'globalShortcut',
  'keyboardShortcuts',
  'theme',
  'useSystemTheme',
  'responseStyle',
  'showPricing',
  'seenAnnouncementIds',
  'disableAutoDownload',
  'recentModels',
]);

ipcMain.handle('set-setting', (event, key: SettingKey, value: unknown) => {
  requireRegularRendererWindow(event);
  // Validate key at runtime to prevent prototype pollution
  if (!validSettingKeys.has(key)) {
    console.error(`Invalid setting key rejected: ${key}`);
    return;
  }

  const settings = getSettings();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (settings as any)[key] = value;
  fsSync.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2));

  // Re-register shortcuts if keyboard shortcuts changed
  if (key === 'keyboardShortcuts') {
    registerGlobalShortcuts();
  }

  if (key === 'disableAutoDownload') {
    setAutoDownloadDisabled(value as boolean);
  }
});

ipcMain.handle('get-secret-key', (event) => {
  const windowId = requireRegularRendererWindow(event).id;
  return gooseServeLeases.getSecretKey(windowId) ?? null;
});

ipcMain.handle('get-acp-url', async (event) => {
  const windowId = requireRegularRendererWindow(event).id;
  return gooseServeLeases.getAcpUrl(windowId) ?? null;
});

// Handle menu bar icon visibility
ipcMain.handle('set-menu-bar-icon', async (_event, show: boolean) => {
  updateSettings((s) => {
    s.showMenuBarIcon = show;
  });

  if (show) {
    createTray();
  } else {
    destroyTray();
  }
  return true;
});

ipcMain.handle('get-menu-bar-icon-state', () => {
  try {
    const settings = getSettings();
    return settings.showMenuBarIcon ?? true;
  } catch (error) {
    console.error('Error getting menu bar icon state:', error);
    return true;
  }
});

// Handle dock icon visibility (macOS only)
ipcMain.handle('set-dock-icon', async (_event, show: boolean) => {
  if (process.platform !== 'darwin') return false;

  const settings = getSettings();
  updateSettings((s) => {
    s.showDockIcon = show;
  });

  if (show) {
    app.dock?.show();
  } else {
    // Only hide the dock if we have a menu bar icon to maintain accessibility
    if (settings.showMenuBarIcon) {
      app.dock?.hide();
      setTimeout(() => {
        focusWindow();
      }, 50);
    }
  }
  return true;
});

ipcMain.handle('get-dock-icon-state', () => {
  try {
    if (process.platform !== 'darwin') return true;
    const settings = getSettings();
    return settings.showDockIcon ?? true;
  } catch (error) {
    console.error('Error getting dock icon state:', error);
    return true;
  }
});

// Handle opening system notifications preferences
ipcMain.handle('open-notifications-settings', async () => {
  try {
    if (process.platform === 'darwin') {
      spawn('open', ['x-apple.systempreferences:com.apple.preference.notifications']);
      return true;
    } else if (process.platform === 'win32') {
      // Windows: Open notification settings in Settings app
      spawn('ms-settings:notifications', { shell: true });
      return true;
    } else if (process.platform === 'linux') {
      // Linux: Try different desktop environments
      function canSpawn(cmd: string): boolean {
        try {
          execFileSync('which', [cmd], { stdio: 'ignore' });
          return true;
        } catch {
          return false;
        }
      }

      // GNOME
      if (canSpawn('gnome-control-center')) {
        spawn('gnome-control-center', ['notifications']);
        return true;
      }

      // KDE Plasma
      if (canSpawn('systemsettings5')) {
        spawn('systemsettings5', ['kcm_notifications']);
        return true;
      }

      // XFCE
      if (canSpawn('xfce4-settings-manager')) {
        spawn('xfce4-settings-manager', ['--socket-id=notifications']);
        return true;
      }

      console.warn('Could not find a suitable settings application for Linux');
      return false;
    } else {
      console.warn(
        `Opening notification settings is not supported on platform: ${process.platform}`
      );
      return false;
    }
  } catch (error) {
    console.error('Error opening notification settings:', error);
    return false;
  }
});

// Handle wakelock setting
ipcMain.handle('set-wakelock', async (_event, enable: boolean) => {
  updateSettings((s) => {
    s.enableWakelock = enable;
  });

  // Stop all existing power save blockers when disabling the setting
  if (!enable) {
    for (const [windowId, blockerId] of windowPowerSaveBlockers.entries()) {
      try {
        powerSaveBlocker.stop(blockerId);
        console.log(
          `[Main] Stopped power save blocker ${blockerId} for window ${windowId} due to wakelock setting disabled`
        );
      } catch (error) {
        console.error(
          `[Main] Failed to stop power save blocker ${blockerId} for window ${windowId}:`,
          error
        );
      }
    }
    windowPowerSaveBlockers.clear();
  }

  return true;
});

ipcMain.handle('get-wakelock-state', () => {
  try {
    const settings = getSettings();
    return settings.enableWakelock ?? false;
  } catch (error) {
    console.error('Error getting wakelock state:', error);
    return false;
  }
});

ipcMain.handle('set-spellcheck', async (_event, enable: boolean) => {
  updateSettings((s) => {
    s.spellcheckEnabled = enable;
  });
  return true;
});

ipcMain.handle('get-spellcheck-state', () => {
  try {
    const settings = getSettings();
    return settings.spellcheckEnabled ?? true;
  } catch (error) {
    console.error('Error getting spellcheck state:', error);
    return true;
  }
});

ipcMain.handle('is-any-window-focused', () => {
  return BrowserWindow.getFocusedWindow() !== null;
});

ipcMain.handle('get-is-fullscreen', (event) => {
  const win = BrowserWindow.fromWebContents(event.sender);
  return win?.isFullScreen() ?? false;
});

// Add file/directory selection handler
ipcMain.handle('select-file-or-directory', async (_event, defaultPath?: string) => {
  const dialogOptions: OpenDialogOptions = {
    properties: process.platform === 'darwin' ? ['openFile', 'openDirectory'] : ['openFile'],
  };

  // Set default path if provided
  if (defaultPath) {
    // Expand tilde to home directory
    const expandedPath = expandTilde(defaultPath);

    // Check if the path exists
    try {
      const stats = await fs.stat(expandedPath);
      if (stats.isDirectory()) {
        dialogOptions.defaultPath = expandedPath;
      } else {
        dialogOptions.defaultPath = path.dirname(expandedPath);
      }
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
    } catch (error) {
      // If path doesn't exist, fall back to home directory and log error
      console.error(`Default path does not exist: ${expandedPath}, falling back to home directory`);
      dialogOptions.defaultPath = os.homedir();
    }
  }

  const result = (await dialog.showOpenDialog(dialogOptions)) as unknown as OpenDialogReturnValue;

  if (!result.canceled && result.filePaths.length > 0) {
    return result.filePaths[0];
  }
  return null;
});

ipcMain.handle('select-recipe-file', async (event) => {
  const senderWindow = requireRegularRendererWindow(event);
  const pathRoot = appConfig.GOOSE_PATH_ROOT as string | undefined;
  const recipeDirectory = pathRoot
    ? path.join(pathRoot, 'config', 'recipes')
    : path.join(os.homedir(), '.config', 'goose', 'recipes');
  let defaultPath = os.homedir();
  try {
    if ((await fs.stat(recipeDirectory)).isDirectory()) {
      defaultPath = recipeDirectory;
    }
  } catch {
    // The recipe directory is optional; the native picker falls back to the home directory.
  }

  const result = await dialog.showOpenDialog(senderWindow, {
    title: 'Select a recipe',
    defaultPath,
    properties: ['openFile'],
    filters: [{ name: 'YAML recipes', extensions: ['yaml', 'yml'] }],
  });
  if (result.canceled || result.filePaths.length === 0) {
    return null;
  }
  return readSelectedRecipe(result.filePaths[0]);
});

ipcMain.handle('read-goosehints', async (event) => {
  const senderWindow = requireRegularRendererWindow(event);
  return desktopFileAccess.readGoosehints(senderWindow.id);
});

ipcMain.handle('write-goosehints', async (event, content) => {
  const senderWindow = requireRegularRendererWindow(event);
  return desktopFileAccess.writeGoosehints(senderWindow.id, content);
});

ipcMain.handle(ACCORDLOCK_APPROVAL_INBOX_GET_PENDING, (event) => {
  const senderWindow = requireRegularRendererWindow(event);
  return pendingAccordLockApprovalsForWindow(senderWindow.id);
});

ipcMain.handle(ACCORDLOCK_APPROVAL_INBOX_DECIDE, (event, rawDecision) => {
  const senderWindow = requireRegularRendererWindow(event);
  const decision = parseApprovalCenterDecision(rawDecision);
  const pending = accordLockPendingActionApprovals.get(decision.itemId);
  if (!pending) {
    throw new Error('Approval request is no longer pending');
  }
  return pending.gate.submit(decision, senderWindow.id, Math.floor(Date.now() / 1_000));
});

ipcMain.handle(ACCORDLOCK_TASK_AUTHORIZATION_GET_PENDING, (event) => {
  const senderWindow = requireRegularRendererWindow(event);
  return accordLockTaskControl.pendingAuthorizationsForWindow(senderWindow.id);
});

ipcMain.handle(ACCORDLOCK_TASK_AUTHORIZATION_PREPARE, async (event, request) => {
  const senderWindow = requireRegularRendererWindow(event);
  const parsedRequest = parseTaskRequest(request);
  const backendBindingSecret = accordLockBackendBindings.get(senderWindow.id);
  if (!backendBindingSecret) {
    throw new Error('Trusted AccordLock backend binding is unavailable');
  }
  const workspaceRoot = await desktopFileAccess.authorizedWorkingDirectory(senderWindow.id);
  const trustedRunId = deriveAccordLockBackendRunId(backendBindingSecret, parsedRequest.session_id);
  return accordLockTaskControl.prepareTask(
    senderWindow.id,
    parsedRequest,
    workspaceRoot,
    trustedRunId
  );
});

ipcMain.handle(ACCORDLOCK_TASK_AUTHORIZATION_DECIDE, async (event, request) => {
  const senderWindow = requireRegularRendererWindow(event);
  const taskDecision = accordLockTaskControl.authorizationForDecision(senderWindow.id, request);
  // The runtime may have committed this exact decision even if its IPC reply
  // never reached the renderer. Recover that acknowledgement without opening
  // another confirmation window or attempting to reconfigure settled access.
  if (taskDecision.acknowledgement) {
    return taskDecision.acknowledgement;
  }
  return accordLockTaskDecisionSingleFlight.run(
    taskDecision.authorization.authorization_id,
    taskDecision.request.decision,
    async () => {
      let effectiveRequest = taskDecision.request;
      if (taskDecision.request.decision === 'APPROVE') {
        const approvalResult = await showAccordLockTaskApprovalWindow(
          senderWindow,
          taskDecision.authorization,
          resolveAccordLockDarkTheme() ? 'dark' : 'light',
          (accordLockStartupNetworkPolicy?.allowed_domains.length ?? 0) > 0
        );
        if (approvalResult.status === 'FAILED') {
          throw new Error('Trusted task confirmation could not be completed');
        }
        if (approvalResult.status === 'CANCELLED') {
          effectiveRequest = { ...taskDecision.request, decision: 'REJECT' };
        } else {
          effectiveRequest = accordLockTaskControl.configurePendingTaskAccess(
            senderWindow.id,
            taskDecision.request,
            approvalResult.access
          );
        }
      }
      const runtime = await requireAccordLockRuntime();
      if (!runtime) {
        throw new Error('AccordLock trusted runtime is unavailable');
      }
      return accordLockTaskControl.decideTaskAuthorization(
        senderWindow.id,
        effectiveRequest,
        runtime
      );
    }
  );
});

ipcMain.handle(ACCORDLOCK_TASK_AUTHORIZATION_REVOKE, async (event, rawRequest) => {
  const senderWindow = requireRegularRendererWindow(event);
  const request = parseTaskAuthorizationRevokeRequest(rawRequest);
  for (const pending of accordLockPendingActionApprovals.values()) {
    if (
      pending.windowId === senderWindow.id &&
      pending.item.binding.sessionId === request.session_id
    ) {
      pending.gate.cancel();
    }
  }
  const pendingActionTail = accordLockActionApprovalTails.get(request.session_id);
  if (pendingActionTail) await pendingActionTail;
  const runtime = await requireAccordLockRuntime();
  if (!runtime) {
    throw new Error('AccordLock trusted runtime is unavailable');
  }
  try {
    return await accordLockTaskControl.revokeSessionAuthorization(
      senderWindow.id,
      request,
      runtime
    );
  } catch (error) {
    failClosedTaskRevocation(`session ${request.session_id} deletion`, error);
    throw error;
  }
});

ipcMain.handle(ACCORDLOCK_TASK_RESTORE, async (event, rawRequest) => {
  const senderWindow = requireRegularRendererWindow(event);
  const request = parseTaskRestoreRequest(rawRequest);
  return runAccordLockFileRestoreOnce(
    senderWindow.id,
    request.session_id,
    request.recovery_id,
    () => restoreAccordLockDeletedFile(senderWindow, request.session_id, request.recovery_id)
  );
});

ipcMain.handle(
  ACCORDLOCK_TASK_AUDIT,
  async (event, rawRequest): Promise<AccordLockTaskAuditAck> => {
    const senderWindow = requireRegularRendererWindow(event);
    const request = parseTaskAuditRequest(rawRequest);
    const trustedWorkspace = await desktopFileAccess.authorizedWorkingDirectory(senderWindow.id);
    const binding = accordLockTaskControl.auditBindingForSession(
      senderWindow.id,
      request.session_id,
      accordLockAuditWorkspaceId(trustedWorkspace)
    );
    let page: AccordLockSessionAuditPage;
    if (binding.source === 'CURRENT_PROCESS') {
      if (binding.ledgerId !== accordLockRuntimeLedgerId) {
        throw new Error('Current task audit locator is invalid');
      }
      const runtime = await requireAccordLockRuntime();
      if (!runtime) throw new Error('AccordLock trusted runtime is unavailable');
      page = await runtime.getSessionAudit(
        request.session_id,
        request.offset,
        request.limit,
        request.snapshot_revision
      );
    } else {
      if (binding.ledgerId === accordLockRuntimeLedgerId) {
        throw new Error('Historical task audit locator is ambiguous');
      }
      const historicalDataDirectory = await resolveAccordLockHistoricalLedgerDirectory(
        accordLockRuntimeRunsDirectory,
        binding.ledgerId
      );
      page = await readAccordLockHistoricalAuditPage({
        binDirectory: runtimeBinDirectory(),
        dataDirectory: historicalDataDirectory,
        expectedTaskId: binding.taskId,
        expectedSessionId: binding.sessionId,
        expectedRunId: binding.runId,
        offset: request.offset,
        limit: request.limit,
        snapshotRevision: request.snapshot_revision,
        logger: log,
        platform: process.platform,
        acceptDirtyDevelopmentMarker: acceptDirtyAccordLockRuntimeMarker(),
        expectedBinarySha256: app.isPackaged ? embeddedRuntimeBinarySha256() : undefined,
      });
    }
    if (
      page.task_id !== binding.taskId ||
      page.session_id !== binding.sessionId ||
      page.run_id !== binding.runId
    ) {
      throw new Error('The runtime audit does not match the task');
    }
    return {
      protocol: ACCORDLOCK_CONTROL_PROTOCOL,
      schema_version: 2,
      session_id: request.session_id,
      page,
    };
  }
);

// Native picker tailored for session imports: shows hidden files (so users can
// reach `~/.claude/projects/...` or `~/.pi/agent/sessions/...`), filters for
// .json/.jsonl, and returns the file's contents inline so the renderer doesn't
// need a separate read step.
ipcMain.handle('select-import-session-file', async () => {
  const result = (await dialog.showOpenDialog({
    title: 'Import session',
    defaultPath: os.homedir(),
    properties: ['openFile', 'showHiddenFiles'],
    filters: [
      { name: 'Session files', extensions: ['json', 'jsonl'] },
      { name: 'All files', extensions: ['*'] },
    ],
  })) as unknown as OpenDialogReturnValue;

  if (result.canceled || result.filePaths.length === 0) {
    return null;
  }
  const filePath = result.filePaths[0];
  try {
    const contents = await fs.readFile(filePath, 'utf8');
    return { filePath, contents };
  } catch (err) {
    log.error('AccordLock could not open the selected file', formatErrorForLogging(err));
    return {
      filePath,
      contents: '',
      error:
        "AccordLock couldn't open this file. Check that it still exists and that you have permission to read it, then try again.",
    };
  }
});

ipcMain.handle('check-ollama', async () => {
  try {
    return new Promise((resolve) => {
      // Run `ps` and filter for "ollama"
      const ps = spawn('ps', ['aux']);
      const grep = spawn('grep', ['-iw', '[o]llama']);

      let output = '';
      let errorOutput = '';

      // Pipe ps output to grep
      ps.stdout.pipe(grep.stdin);

      grep.stdout.on('data', (data) => {
        output += data.toString();
      });

      grep.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });

      grep.on('close', (code) => {
        if (code !== null && code !== 0 && code !== 1) {
          // grep returns 1 when no matches found
          console.error('Error executing grep command:', errorOutput);
          return resolve(false);
        }

        const trimmedOutput = output.trim();

        const isRunning = trimmedOutput.length > 0;
        resolve(isRunning);
      });

      ps.on('error', (error) => {
        console.error('Error executing ps command:', error);
        resolve(false);
      });

      grep.on('error', (error) => {
        console.error('Error executing grep command:', error);
        resolve(false);
      });

      // Close ps stdin when done
      ps.stdout.on('end', () => {
        grep.stdin.end();
      });
    });
  } catch (err) {
    console.error('Error checking for Ollama:', err);
    return false;
  }
});

ipcMain.handle('list-files', async (event, dirPath: unknown, extension?: unknown) => {
  const senderWindow = requireRegularRendererWindow(event);
  return desktopFileAccess.listFiles(senderWindow.id, dirPath, extension);
});

ipcMain.handle('show-message-box', async (_event, options) => {
  return dialog.showMessageBox(options);
});

ipcMain.handle('save-recipe-file', async (event, request: unknown) => {
  const senderWindow = requireRegularRendererWindow(event);
  return desktopFileAccess.saveRecipeWithNativeDialog(
    senderWindow.id,
    request,
    async (suggestedName) => {
      const result = await dialog.showSaveDialog(senderWindow, {
        title: 'Export recipe',
        defaultPath: suggestedName,
        filters: [
          { name: 'YAML files', extensions: ['yaml', 'yml'] },
          { name: 'All files', extensions: ['*'] },
        ],
        properties: ['showOverwriteConfirmation', 'createDirectory'],
      });
      return { canceled: result.canceled, filePath: result.filePath };
    }
  );
});

ipcMain.handle('save-audit-file', async (event, request: unknown) => {
  const senderWindow = requireRegularRendererWindow(event);
  return desktopFileAccess.saveAuditWithNativeDialog(
    senderWindow.id,
    request,
    async (suggestedName) => {
      const result = await dialog.showSaveDialog(senderWindow, {
        title: 'Export activity record',
        defaultPath: suggestedName,
        filters: [
          { name: 'JSON files', extensions: ['json'] },
          { name: 'All files', extensions: ['*'] },
        ],
        properties: ['showOverwriteConfirmation', 'createDirectory'],
      });
      return { canceled: result.canceled, filePath: result.filePath };
    }
  );
});

ipcMain.handle('get-allowed-extensions', async () => {
  return await getAllowList();
});

const createNewWindow = async (app: App, dir?: string | null) => {
  const recentDirs = loadRecentDirs();
  const openDir = dir || (recentDirs.length > 0 ? recentDirs[0] : undefined);
  return await createChat(app, { dir: openDir });
};

const focusWindow = () => {
  const windows = BrowserWindow.getAllWindows();
  if (windows.length > 0) {
    windows.forEach((win) => {
      win.show();
    });
    windows[windows.length - 1].webContents.send('focus-input');
  } else {
    createNewWindow(app);
  }
};

const registerGlobalShortcuts = () => {
  globalShortcut.unregisterAll();

  const settings = getSettings();
  const shortcuts = getKeyboardShortcuts(settings);

  if (shortcuts.focusWindow) {
    try {
      globalShortcut.register(shortcuts.focusWindow, () => {
        focusWindow();
      });
    } catch (e) {
      console.error('Error registering focus window hotkey:', e);
    }
  }

  if (shortcuts.quickLauncher) {
    try {
      globalShortcut.register(shortcuts.quickLauncher, () => {
        createLauncher();
      });
    } catch (e) {
      console.error('Error registering launcher hotkey:', e);
    }
  }
};

async function appMain() {
  const handleNativeThemeUpdated = () => {
    const settings = getSettings();
    if (settings.useSystemTheme) {
      updateAccordLockTitleBarOverlays(resolveAccordLockDarkTheme(settings));
    }
  };
  nativeTheme.on('updated', handleNativeThemeUpdated);
  app.once('will-quit', () => nativeTheme.removeListener('updated', handleNativeThemeUpdated));

  powerMonitor.on('resume', () => {
    for (const window of BrowserWindow.getAllWindows()) {
      if (!window.isDestroyed()) {
        window.webContents.send('system-resume');
      }
    }
  });

  await configureProxy();

  // Ensure Windows shims are available before any MCP processes are spawned
  await ensureWinShims();

  if (shouldSetupUpdater()) {
    registerUpdateIpcHandlers();
  }

  const accordLockSession = getAccordLockElectronSession();
  const hasRegularWindowAuthority = (webContents: WebContents): boolean => {
    const owner = BrowserWindow.fromWebContents(webContents);
    return Boolean(owner && windowMap.get(owner.id) === owner);
  };
  accordLockSession.setPermissionCheckHandler(
    (webContents, permission, requestingOrigin, details) =>
      Boolean(
        webContents &&
        hasRegularWindowAuthority(webContents) &&
        shouldGrantAccordLockMicrophoneCheck({
          permission,
          currentUrl: webContents.getURL(),
          requestingOrigin,
          requestingUrl: details.requestingUrl,
          securityOrigin: details.securityOrigin,
          isMainFrame: details.isMainFrame,
          mediaType: details.mediaType,
        })
      )
  );
  accordLockSession.setPermissionRequestHandler((webContents, permission, callback, details) => {
    const mediaDetails = details as {
      requestingUrl?: string;
      securityOrigin?: string;
      isMainFrame?: boolean;
      mediaTypes?: string[];
    };
    callback(
      hasRegularWindowAuthority(webContents) &&
        shouldGrantAccordLockMicrophoneRequest({
          permission,
          currentUrl: webContents.getURL(),
          requestingUrl: mediaDetails.requestingUrl,
          securityOrigin: mediaDetails.securityOrigin,
          isMainFrame: mediaDetails.isMainFrame,
          mediaTypes: mediaDetails.mediaTypes,
        })
    );
  });

  // Add CSP headers to all sessions, recomputed on every response so external
  // backend settings take effect without restarting the app.
  accordLockSession.webRequest.onHeadersReceived((details, callback) => {
    const currentSettings = getSettings();
    const owner = [...windowMap.values()].find(
      (candidate) => !candidate.isDestroyed() && candidate.webContents.id === details.webContentsId
    );
    const exactOrigins: string[] = [];
    const lease = owner ? gooseServeLeases.get(owner.id) : null;
    if (lease) {
      const acpOrigin = new URL(lease.acpUrl);
      exactOrigins.push(acpOrigin.origin);
      acpOrigin.protocol = acpOrigin.protocol === 'wss:' ? 'https:' : 'http:';
      exactOrigins.push(acpOrigin.origin);
    }
    if (!app.isPackaged && MAIN_WINDOW_VITE_DEV_SERVER_URL) {
      const rendererOrigin = new URL(MAIN_WINDOW_VITE_DEV_SERVER_URL);
      exactOrigins.push(rendererOrigin.origin);
      rendererOrigin.protocol = rendererOrigin.protocol === 'https:' ? 'wss:' : 'ws:';
      exactOrigins.push(rendererOrigin.origin);
    }
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': buildCSP(
          getExternalBackendForCsp(currentSettings),
          exactOrigins
        ),
      },
    });
  });

  // Migrate old settings format if needed (one-time migration)
  const settings = getSettings();
  if (!settings.keyboardShortcuts && settings.globalShortcut !== undefined) {
    updateSettings((s) => {
      s.keyboardShortcuts = getKeyboardShortcuts(s);
      delete s.globalShortcut;
    });
  }

  // Register global shortcuts based on settings
  registerGlobalShortcuts();

  accordLockSession.webRequest.onBeforeSendHeaders((details, callback) => {
    details.requestHeaders['Origin'] = 'http://localhost:5173';
    callback({ cancel: false, requestHeaders: details.requestHeaders });
  });

  if (settings.showMenuBarIcon) {
    createTray();
  }

  if (process.platform === 'darwin' && !settings.showDockIcon && settings.showMenuBarIcon) {
    app.dock?.hide();
  }

  const { dirPath } = parseArgs();

  if (!openUrlHandledLaunch) {
    await createNewWindow(app, dirPath);
  } else {
    log.info('[Main] Skipping window creation in appMain - open-url already handled launch');
  }

  // Setup auto-updater AFTER window is created and displayed (with delay to avoid blocking)
  setTimeout(() => {
    if (shouldSetupUpdater()) {
      log.info('Setting up auto-updater after window creation...');
      try {
        const settings = getSettings();
        if (settings.disableAutoDownload) {
          setAutoDownloadDisabled(true);
        }
        setupAutoUpdater();
      } catch (error) {
        log.error('Error setting up auto-updater:', error);
      }
    }
  }, 2000);

  if (process.platform === 'darwin') {
    const dockMenu = Menu.buildFromTemplate([
      {
        label: 'New Window',
        click: () => {
          createNewWindow(app);
        },
      },
    ]);
    app.dock?.setMenu(dockMenu);
  }

  const menu = Menu.getApplicationMenu();

  const shortcuts = getKeyboardShortcuts(settings);

  const appMenu = menu?.items.find((item) => item.label === app.name);
  if (appMenu?.submenu) {
    appMenu.submenu.insert(1, new MenuItem({ type: 'separator' }));
    if (shortcuts.settings) {
      appMenu.submenu.insert(
        1,
        new MenuItem({
          label: 'Settings',
          accelerator: shortcuts.settings,
          click() {
            const focusedWindow = BrowserWindow.getFocusedWindow();
            if (focusedWindow) focusedWindow.webContents.send('set-view', 'settings');
          },
        })
      );
    }
    appMenu.submenu.insert(1, new MenuItem({ type: 'separator' }));
  }

  const editMenu = menu?.items.find((item) => item.label === 'Edit');
  if (editMenu?.submenu) {
    const selectAllIndex = editMenu.submenu.items.findIndex((item) => item.label === 'Select All');

    const findSubmenu = Menu.buildFromTemplate([
      {
        label: 'Find…',
        accelerator: shortcuts.find || undefined,
        click() {
          const focusedWindow = BrowserWindow.getFocusedWindow();
          if (focusedWindow) focusedWindow.webContents.send('find-command');
        },
      },
      {
        label: 'Find Next',
        accelerator: shortcuts.findNext || undefined,
        click() {
          const focusedWindow = BrowserWindow.getFocusedWindow();
          if (focusedWindow) focusedWindow.webContents.send('find-next');
        },
      },
      {
        label: 'Find Previous',
        accelerator: shortcuts.findPrevious || undefined,
        click() {
          const focusedWindow = BrowserWindow.getFocusedWindow();
          if (focusedWindow) focusedWindow.webContents.send('find-previous');
        },
      },
      {
        label: 'Use Selection for Find',
        accelerator: process.platform === 'darwin' ? 'Command+E' : undefined,
        click() {
          const focusedWindow = BrowserWindow.getFocusedWindow();
          if (focusedWindow) focusedWindow.webContents.send('use-selection-find');
        },
        visible: process.platform === 'darwin', // Only show on Mac
      },
    ]);

    editMenu.submenu.insert(
      selectAllIndex + 1,
      new MenuItem({
        label: 'Find',
        submenu: findSubmenu,
      })
    );
  }

  const fileMenu = menu?.items.find((item) => item.label === 'File');

  if (fileMenu?.submenu) {
    // Use a counter to track the actual insertion index
    let menuIndex = 0;

    if (shortcuts.newChat) {
      fileMenu.submenu.insert(
        menuIndex++,
        new MenuItem({
          label: 'New Task',
          accelerator: shortcuts.newChat,
          click() {
            const focusedWindow = BrowserWindow.getFocusedWindow();
            if (focusedWindow) focusedWindow.webContents.send('set-view', '');
          },
        })
      );
    }

    if (shortcuts.newChatWindow) {
      fileMenu.submenu.insert(
        menuIndex++,
        new MenuItem({
          label: 'New Task Window',
          accelerator: shortcuts.newChatWindow,
          click() {
            ipcMain.emit('create-chat-window');
          },
        })
      );
    }

    if (shortcuts.openDirectory) {
      fileMenu.submenu.insert(
        menuIndex++,
        new MenuItem({
          label: 'Open Directory...',
          accelerator: shortcuts.openDirectory,
          click: () => openDirectoryDialog(),
        })
      );
    }

    const recentFilesSubmenu = buildRecentFilesMenu();
    if (recentFilesSubmenu.length > 0) {
      fileMenu.submenu.insert(
        menuIndex++,
        new MenuItem({
          label: 'Recent Directories',
          submenu: recentFilesSubmenu,
        })
      );
    }

    fileMenu.submenu.insert(menuIndex++, new MenuItem({ type: 'separator' }));

    if (shortcuts.focusWindow) {
      fileMenu.submenu.append(
        new MenuItem({
          label: 'Focus AccordLock Window',
          accelerator: shortcuts.focusWindow,
          click() {
            focusWindow();
          },
        })
      );
    }

    if (shortcuts.quickLauncher) {
      fileMenu.submenu.append(
        new MenuItem({
          label: 'Quick Launcher',
          accelerator: shortcuts.quickLauncher,
          click() {
            createLauncher();
          },
        })
      );
    }
  }

  if (menu) {
    let windowMenu = menu.items.find((item) => item.label === 'Window');

    if (!windowMenu) {
      windowMenu = new MenuItem({
        label: 'Window',
        submenu: Menu.buildFromTemplate([]),
      });

      const helpMenuIndex = menu.items.findIndex((item) => item.label === 'Help');
      if (helpMenuIndex >= 0) {
        menu.items.splice(helpMenuIndex, 0, windowMenu);
      } else {
        menu.items.push(windowMenu);
      }
    }

    if (windowMenu.submenu) {
      if (shortcuts.alwaysOnTop) {
        windowMenu.submenu.append(
          new MenuItem({
            label: 'Always on Top',
            type: 'checkbox',
            accelerator: shortcuts.alwaysOnTop,
            click(menuItem) {
              const focusedWindow = BrowserWindow.getFocusedWindow();
              if (focusedWindow) {
                const isAlwaysOnTop = menuItem.checked;

                if (process.platform === 'darwin') {
                  focusedWindow.setAlwaysOnTop(isAlwaysOnTop, 'floating');
                } else {
                  focusedWindow.setAlwaysOnTop(isAlwaysOnTop);
                }

                console.log(
                  `[Main] Set always-on-top to ${isAlwaysOnTop} for window ${focusedWindow.id}`
                );
              }
            },
          })
        );
      }
    }

    const viewMenu = menu.items.find((item) => item.label === 'View');
    if (app.isPackaged && viewMenu?.submenu) {
      for (const item of viewMenu.submenu.items) {
        if (isAccordLockUnsafeViewMenuRole(item.role)) {
          item.enabled = false;
          item.visible = false;
          item.registerAccelerator = false;
        }
      }
    }
    if (viewMenu?.submenu && shortcuts.toggleNavigation) {
      viewMenu.submenu.append(new MenuItem({ type: 'separator' }));
      viewMenu.submenu.append(
        new MenuItem({
          label: 'Toggle Navigation',
          accelerator: shortcuts.toggleNavigation,
          click() {
            const focusedWindow = BrowserWindow.getFocusedWindow();
            if (focusedWindow) {
              focusedWindow.webContents.send('toggle-navigation');
            }
          },
        })
      );
    }
  }

  // on macOS, the topbar is hidden
  if (menu && process.platform !== 'darwin') {
    let helpMenu = menu.items.find((item) => item.label === 'Help');

    // If Help menu doesn't exist, create it and add it to the menu
    if (!helpMenu) {
      helpMenu = new MenuItem({
        label: 'Help',
        submenu: Menu.buildFromTemplate([]), // Start with an empty submenu
      });
      // Find a reasonable place to insert the Help menu, usually near the end
      const insertIndex = menu.items.length > 0 ? menu.items.length - 1 : 0;
      menu.items.splice(insertIndex, 0, helpMenu);
    }

    // Ensure the Help menu has a submenu before appending
    if (helpMenu.submenu) {
      // Add a separator before the About item if the submenu is not empty
      if (helpMenu.submenu.items.length > 0) {
        helpMenu.submenu.append(new MenuItem({ type: 'separator' }));
      }

      // Create the About AccordLock menu item with a submenu
      const aboutAccordLockMenuItem = new MenuItem({
        label: 'About AccordLock',
        submenu: Menu.buildFromTemplate([]), // Start with an empty submenu for About
      });

      // Add the Version menu item (display only) to the About AccordLock submenu
      if (aboutAccordLockMenuItem.submenu) {
        aboutAccordLockMenuItem.submenu.append(
          new MenuItem({
            label: `Version ${version || app.getVersion()}`,
            enabled: false,
          })
        );
      }

      helpMenu.submenu.append(aboutAccordLockMenuItem);
    }
  }

  if (menu) {
    // Translate labels (including Electron's default top-level entries
    // File/Edit/View/Window/Help and submenu items populated by roles) before
    // installing the menu. Called last so the lookups above that match on the
    // English labels still succeed.
    Menu.setApplicationMenu(menu);
  }

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createNewWindow(app);
    }
  });

  ipcMain.on('create-chat-window', (event: IpcMainEvent | undefined, options = {}) => {
    void (async () => {
      const safeOptions =
        typeof options === 'object' && options !== null ? (options as Record<string, unknown>) : {};
      const query = typeof safeOptions.query === 'string' ? safeOptions.query : undefined;
      const resumeSessionId =
        typeof safeOptions.resumeSessionId === 'string' ? safeOptions.resumeSessionId : undefined;
      const viewType = typeof safeOptions.viewType === 'string' ? safeOptions.viewType : undefined;
      const recipeId = typeof safeOptions.recipeId === 'string' ? safeOptions.recipeId : undefined;

      const senderWindow = event?.sender ? BrowserWindow.fromWebContents(event.sender) : undefined;
      const isFromLauncher =
        !!query &&
        !resumeSessionId &&
        !viewType &&
        !recipeId &&
        !!senderWindow &&
        senderWindow === activeLauncherWindow &&
        !!event?.senderFrame &&
        isAuthorizedFileAccessRequest(
          {
            isRegisteredWindow: true,
            isMainFrame: event.senderFrame === event.sender.mainFrame,
            rendererUrl: event.senderFrame.url,
          },
          getAppUrl()
        );

      let resolvedDir: string | undefined;
      if (event?.sender && !isFromLauncher) {
        const authorizedWindow = requireRegularRendererWindow(event);
        resolvedDir = await desktopFileAccess.authorizedDesktopWorkingDirectory(
          authorizedWindow.id
        );
      } else {
        const recentDirs = loadRecentDirs();
        resolvedDir = recentDirs.length > 0 ? recentDirs[0] : undefined;
      }

      await createChat(app, {
        initialMessage: query,
        dir: resolvedDir,
        resumeSessionId,
        viewType,
        recipeId,
      });
    })().catch((error) => log.error('Secure new-window request failed', error));
  });

  ipcMain.on('close-window', (event) => {
    const window = BrowserWindow.fromWebContents(event.sender);
    if (window && !window.isDestroyed()) {
      window.close();
    }
  });

  ipcMain.on('notify', (event, data) => {
    try {
      const senderWindow = requireRegularRendererWindow(event);
      const parsed = parseAccordLockNotification(data);
      if (getSettings().enableNotifications !== true || BrowserWindow.getFocusedWindow() !== null) {
        return;
      }
      if (parsed.open.kind === 'APPROVAL') {
        const pending = accordLockPendingActionApprovals.get(parsed.open.approvalId);
        if (!pending || pending.windowId !== senderWindow.id) {
          throw new Error('Approval notification is no longer active');
        }
      } else {
        const task = accordLockTaskControl.authorizedContextForSession(parsed.open.sessionId);
        if (task.windowId !== senderWindow.id) {
          throw new Error('Task notification does not belong to this window');
        }
      }
      const presentation = notificationPresentationForRequest(parsed);
      const notification = new Notification({
        title: presentation.title,
        body: presentation.body,
      });
      const approvalId = parsed.open.kind === 'APPROVAL' ? parsed.open.approvalId : null;

      if (approvalId !== null) {
        accordLockApprovalNotifications.register(approvalId, notification);
        notification.on('close', () => {
          accordLockApprovalNotifications.release(approvalId, notification);
        });
      }

      notification.on('click', () => {
        if (approvalId !== null) {
          accordLockApprovalNotifications.dismiss(approvalId);
        }
        if (senderWindow.isDestroyed()) return;
        if (senderWindow.isMinimized()) {
          senderWindow.restore();
        }
        senderWindow.show();
        senderWindow.focus();
        if (!senderWindow.webContents.isDestroyed()) {
          senderWindow.webContents.send('accordlock:notification-open', parsed.open);
        }
      });

      notification.show();
    } catch {
      log.warn('Rejected invalid desktop notification request');
    }
  });

  ipcMain.on(ACCORDLOCK_APPROVAL_NOTIFICATION_DISMISS, (event, approvalId) => {
    try {
      requireRegularRendererWindow(event);
      accordLockApprovalNotifications.dismiss(parseApprovalNotificationId(approvalId));
    } catch {
      log.warn('Rejected invalid approval notification dismissal');
    }
  });

  ipcMain.on('logInfo', (_event, info) => {
    try {
      // Validate log info
      if (info === undefined || info === null) {
        console.error('Invalid log info: undefined or null');
        return;
      }

      // Convert to string if not already
      const logMessage = String(info);

      // Limit log message length
      const MAX_LENGTH = 10000; // 10KB limit
      if (logMessage.length > MAX_LENGTH) {
        console.error('Log message too long');
        return;
      }

      // Log the sanitized message
      log.info('from renderer:', logMessage);
    } catch (error) {
      console.error('Error logging info:', error);
    }
  });

  ipcMain.on('broadcast-theme-change', (event, themeData) => {
    const senderWindow = BrowserWindow.fromWebContents(event.sender);
    const allWindows = BrowserWindow.getAllWindows();

    if (
      process.platform === 'win32' &&
      typeof themeData === 'object' &&
      themeData !== null &&
      (themeData.mode === 'dark' || themeData.mode === 'light')
    ) {
      updateAccordLockTitleBarOverlays(themeData.mode === 'dark');
    }

    allWindows.forEach((window) => {
      if (window.id !== senderWindow?.id) {
        window.webContents.send('theme-changed', themeData);
      }
    });
  });

  ipcMain.on('reload-app', (event) => {
    try {
      const senderWindow = requireRegularRendererWindow(event);
      requestAccordLockWindowReload(senderWindow, `window ${senderWindow.id} renderer reload`);
    } catch (error) {
      log.warn('Rejected reload request from an unauthorized renderer', error);
    }
  });

  ipcMain.on('open-in-chrome', (event, url) => {
    try {
      requireRegularRendererWindow(event);
      if (typeof url !== 'string' || !isAccordLockExternalUrlAllowed(url)) {
        throw new Error('External URL is not permitted');
      }
      void shell.openExternal(url).catch((error) => {
        log.error('Error opening URL in the system browser', error);
      });
    } catch (error) {
      log.warn('Rejected system-browser request', error);
    }
  });

  // Handle app restart
  ipcMain.on('restart-app', (event) => {
    try {
      requireRegularRendererWindow(event);
      app.relaunch();
      // `quit` enters the AccordLock before-quit revocation barrier. `exit`
      // would terminate immediately and strand live task authorization.
      app.quit();
    } catch (error) {
      log.warn('Rejected restart request from an unauthorized renderer', error);
    }
  });

  // Handler for getting app version
  ipcMain.on('get-app-version', (event) => {
    event.returnValue = app.getVersion();
  });

  ipcMain.handle('open-directory-in-explorer', async (event) => {
    try {
      const senderWindow = requireRegularRendererWindow(event);
      const workspace = await desktopFileAccess.authorizedDesktopWorkingDirectory(senderWindow.id);
      return (await shell.openPath(workspace)) === '';
    } catch (error) {
      console.error('Error opening directory in explorer:', error);
      return false;
    }
  });
}

app.whenReady().then(async () => {
  try {
    const durableAuditAvailable = await accordLockTaskAuditIndex.initialize();
    if (!durableAuditAvailable) {
      log.warn(
        'Historical task audit is unavailable because protected local storage is unavailable'
      );
    }
    if (!(await requireAccordLockRuntime())) {
      app.quit();
      return;
    }
    await appMain();
  } catch (error) {
    log.error('AccordLock could not create the main window', formatErrorForLogging(error));
    dialog.showErrorBox(
      'AccordLock Could Not Open',
      'Restart AccordLock. If the problem continues, reinstall the app or contact your administrator.'
    );
    app.quit();
  }
});

async function getAllowList(): Promise<string[]> {
  if (!process.env.GOOSE_ALLOWLIST) {
    return [];
  }

  const response = await fetch(process.env.GOOSE_ALLOWLIST);

  if (!response.ok) {
    throw new Error(
      `Failed to fetch allowed extensions: ${response.status} ${response.statusText}`
    );
  }

  // Parse the YAML content
  const yamlContent = await response.text();
  const parsedYaml = yaml.parse(yamlContent);

  // Extract the commands from the extensions array
  if (parsedYaml && parsedYaml.extensions && Array.isArray(parsedYaml.extensions)) {
    const commands = parsedYaml.extensions.map(
      (ext: { id: string; command: string }) => ext.command
    );
    console.log(`Fetched ${commands.length} allowed extension commands`);
    return commands;
  } else {
    console.error('Invalid YAML structure:', parsedYaml);
    return [];
  }
}

app.on('before-quit', (event) => {
  if (shutdownState === 'complete') {
    return;
  }

  event.preventDefault();
  if (shutdownState === 'running') {
    return;
  }
  shutdownState = 'running';

  void (async () => {
    accordLockApprovalNotifications.clear();
    const gooseServeLeaseCount = gooseServeLeases.activeLeaseCount();
    if (gooseServeLeaseCount > 0) {
      log.info(`App quitting, cleaning up ${gooseServeLeaseCount} backend lease(s)`);
      await gooseServeLeases.cleanupAll();
    }

    if (accordLockApprovalProxyStart) {
      try {
        const approvalProxy = await accordLockApprovalProxyStart;
        await approvalProxy.cleanup();
      } catch (error) {
        log.error('AccordLock action-approval boundary cleanup failed', errorMessage(error));
      }
    }

    if (accordLockRuntimeStart) {
      try {
        const runtime = await accordLockRuntimeStart;
        for (const windowId of windowMap.keys()) {
          await accordLockTaskControl.revokeWindowAuthorizations(windowId, runtime);
        }
        await runtime.cleanup();
      } catch (error) {
        log.error('AccordLock shutdown could not durably revoke every task authorization', error);
        if (!accordLockRevocationFailureShown) {
          accordLockRevocationFailureShown = true;
          dialog.showErrorBox(
            'AccordLock Closed Its Security Runtime',
            'One or more task revocations could not be recorded. The runtime has been terminated so no authority remains usable.'
          );
        }
        try {
          const runtime = await accordLockRuntimeStart;
          await runtime.cleanup();
        } catch (cleanupError) {
          log.error('AccordLock runtime shutdown followed a failed startup', cleanupError);
        }
      }
    }

    for (const [windowId, blockerId] of windowPowerSaveBlockers.entries()) {
      try {
        powerSaveBlocker.stop(blockerId);
        console.log(
          `[Main] Stopped power save blocker ${blockerId} for window ${windowId} during app quit`
        );
      } catch (error) {
        console.error(
          `[Main] Failed to stop power save blocker ${blockerId} for window ${windowId}:`,
          error
        );
      }
    }
    windowPowerSaveBlockers.clear();
    globalShortcut.unregisterAll();
  })()
    .catch((error) => log.error('AccordLock shutdown cleanup failed', error))
    .finally(() => {
      shutdownState = 'complete';
      app.quit();
    });
});

app.on('window-all-closed', () => {
  // Only quit if we're not on macOS or don't have a tray icon
  if (process.platform !== 'darwin' || !tray) {
    app.quit();
  }
});
