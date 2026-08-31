import Electron, { contextBridge, ipcRenderer, webUtils } from 'electron';
import { Recipe } from './recipe';
import type { GooseApp } from './types/apps';
import type { Settings, SettingKey } from './utils/settings';
import { defaultSettings } from './utils/settings';
import type { AccordLockTerminalProgramBinding } from './accordlockTerminalPrograms';
import {
  ACCORDLOCK_APPROVAL_CHANNELS_LIST,
  ACCORDLOCK_APPROVAL_CHANNELS_REMOVE,
  ACCORDLOCK_APPROVAL_CHANNELS_SAVE,
  ACCORDLOCK_APPROVAL_CHANNELS_SET_ENABLED,
  ACCORDLOCK_APPROVAL_CHANNELS_TEST,
  type AccordLockApprovalChannelId,
  type AccordLockApprovalChannelInput,
  type AccordLockApprovalChannelSummary,
} from './accordlockApprovalChannels';
import type { AccordLockConnectionTestReport } from './accordlockApprovalNotificationDispatcher';
import {
  ACCORDLOCK_REMOTE_APPROVAL_ENROLLMENT_GET,
  ACCORDLOCK_REMOTE_APPROVAL_ENROLLMENT_IMPORT,
  ACCORDLOCK_REMOTE_APPROVAL_ENROLLMENT_REVOKE,
  ACCORDLOCK_REMOTE_APPROVAL_RECEIPT_IMPORT,
  type AccordLockRemoteGatewayEnrollmentSummary,
} from './accordlockRemoteApprovals';
import type { DeploymentPreflightResultView } from './components/accordlock/DeploymentPreflightResult';
import type { DeploymentPreflightInput } from './accordlock/deploymentPreflight';
import type { DeploymentPreflightReceiptArchiveSummary } from './accordlock/deploymentPreflightReceiptArchive';
import type { AccordLockEnvironmentProfileInput } from './accordlock/environmentProfiles';
import {
  ACCORDLOCK_DEPLOYMENT_PREFLIGHT_RUN,
  ACCORDLOCK_DEPLOYMENT_PREFLIGHT_HISTORY_EXPORT,
  ACCORDLOCK_DEPLOYMENT_PREFLIGHT_HISTORY_LIST,
  ACCORDLOCK_DEPLOYMENT_PREFLIGHT_CI_EVIDENCE_IMPORT,
  ACCORDLOCK_ENVIRONMENT_PROFILES_LIST,
  ACCORDLOCK_ENVIRONMENT_PROFILES_REMOVE,
  ACCORDLOCK_ENVIRONMENT_PROFILES_SAVE,
  type DeploymentPreflightHistoryExportResult,
  type DeploymentPreflightCiEvidenceImportResult,
  type AccordLockEnvironmentProfileView,
} from './accordlock/environmentProfileIpc';
import type { ApprovalCenterDecision } from './accordlock/approvalInbox';
import {
  ACCORDLOCK_APPROVAL_NOTIFICATION_DISMISS,
  type AccordLockNotificationRequest,
} from './accordlock/notificationNavigation';
import {
  ACCORDLOCK_APPROVAL_INBOX_DECIDE,
  ACCORDLOCK_APPROVAL_INBOX_GET_PENDING,
} from './accordlock/approvalInboxIpc';
import {
  ACCORDLOCK_TASK_AUTHORIZATION_DECIDE,
  ACCORDLOCK_TASK_AUTHORIZATION_GET_PENDING,
  ACCORDLOCK_TASK_AUTHORIZATION_PREPARE,
  ACCORDLOCK_TASK_AUTHORIZATION_REVOKE,
  ACCORDLOCK_TASK_AUDIT,
  ACCORDLOCK_TASK_RESTORE,
  type AccordLockTaskAuditRequest,
  type AccordLockTaskAuthorizationDecisionRequest,
  type AccordLockTaskAuthorizationRevokeRequest,
  type AccordLockTaskRequest,
  type AccordLockTaskRestoreRequest,
} from './accordlock/taskIpc';

// Mapping from settings keys to their old localStorage keys for lazy migration
const localStorageKeyMap: Partial<Record<SettingKey, string>> = {
  theme: 'theme',
  useSystemTheme: 'use_system_theme',
  responseStyle: 'response_style',
  showPricing: 'show_pricing',
  seenAnnouncementIds: 'seenAnnouncementIds',
};

// Parse localStorage value based on the setting key
function parseLocalStorageValue<K extends SettingKey>(
  key: K,
  rawValue: string
): Settings[K] | null {
  try {
    switch (key) {
      case 'theme':
        return (rawValue === 'dark' || rawValue === 'light' ? rawValue : null) as Settings[K];
      case 'useSystemTheme':
        return (rawValue === 'true') as unknown as Settings[K];
      case 'responseStyle':
        return rawValue as Settings[K];
      case 'showPricing':
        return (rawValue === 'true') as unknown as Settings[K];
      case 'seenAnnouncementIds':
        return JSON.parse(rawValue) as Settings[K];
      default:
        return null;
    }
  } catch {
    return null;
  }
}

interface MessageBoxOptions {
  type?: 'none' | 'info' | 'error' | 'question' | 'warning';
  buttons?: string[];
  defaultId?: number;
  title?: string;
  message: string;
  detail?: string;
}

interface MessageBoxResponse {
  response: number;
  checkboxChecked?: boolean;
}

interface NativeRecipeSaveResult {
  canceled: boolean;
  filePath?: string;
  saved: boolean;
}

interface FileResponse {
  file: string;
  filePath: string;
  error: string | null;
  found: boolean;
}

const config = JSON.parse(process.argv.find((arg) => arg.startsWith('{')) || '{}');

interface UpdaterEvent {
  event: string;
  data?: unknown;
}

export interface CreateChatWindowOptions {
  query?: string;
  version?: string;
  resumeSessionId?: string;
  viewType?: string;
  recipeId?: string;
}

// Define the API types in a single place
type ElectronAPI = {
  platform: string;
  arch: string;
  reactReady: () => void;
  getConfig: () => Record<string, unknown>;
  hideWindow: () => void;
  openSecureWorkspaceWindow: () => Promise<{ opened: boolean; canceled: boolean }>;
  selectProjectFolder: () => Promise<string | null>;
  createChatWindow: (options?: CreateChatWindowOptions) => void;
  logInfo: (txt: string) => void;
  showNotification: (data: AccordLockNotificationRequest) => void;
  dismissApprovalNotification: (approvalId: string) => void;
  showMessageBox: (options: MessageBoxOptions) => Promise<MessageBoxResponse>;
  saveRecipeFile: (suggestedName: string, content: string) => Promise<NativeRecipeSaveResult>;
  saveAuditFile: (suggestedName: string, content: string) => Promise<NativeRecipeSaveResult>;
  openInChrome: (url: string) => void;
  reloadApp: () => void;
  checkForOllama: () => Promise<boolean>;
  selectFileOrDirectory: (defaultPath?: string) => Promise<string | null>;
  selectImportSessionFile: () => Promise<{
    filePath: string;
    contents: string;
    error?: string;
  } | null>;
  getBinaryPath: (binaryName: string) => Promise<string>;
  selectRecipeFile: () => Promise<FileResponse | null>;
  readGoosehints: () => Promise<FileResponse>;
  writeGoosehints: (content: string) => Promise<boolean>;
  listFiles: (dirPath: string, extension?: string) => Promise<string[]>;
  getAllowedExtensions: () => Promise<string[]>;
  getPathForFile: (file: File) => string;
  setMenuBarIcon: (show: boolean) => Promise<boolean>;
  getMenuBarIconState: () => Promise<boolean>;
  setDockIcon: (show: boolean) => Promise<boolean>;
  getDockIconState: () => Promise<boolean>;
  getSetting: <K extends SettingKey>(key: K) => Promise<Settings[K]>;
  setSetting: <K extends SettingKey>(key: K, value: Settings[K]) => Promise<void>;
  getSecretKey: () => Promise<string | null>;
  getAcpUrl: () => Promise<string | null>;
  getPendingAccordLockActionApprovals: () => Promise<unknown>;
  submitAccordLockApprovalCenterDecision: (decision: ApprovalCenterDecision) => Promise<unknown>;
  getPendingAccordLockTaskAuthorizations: () => Promise<unknown>;
  requestAccordLockTaskAuthorization: (request: AccordLockTaskRequest) => Promise<unknown>;
  submitAccordLockTaskAuthorizationDecision: (
    request: AccordLockTaskAuthorizationDecisionRequest
  ) => Promise<unknown>;
  revokeAccordLockTaskAuthorization: (
    request: AccordLockTaskAuthorizationRevokeRequest
  ) => Promise<unknown>;
  restoreAccordLockDeletedFile: (request: AccordLockTaskRestoreRequest) => Promise<unknown>;
  getAccordLockTaskAudit: (request: AccordLockTaskAuditRequest) => Promise<unknown>;
  listAccordLockApprovalChannels: () => Promise<AccordLockApprovalChannelSummary[]>;
  saveAccordLockApprovalChannel: (
    configuration: AccordLockApprovalChannelInput
  ) => Promise<AccordLockApprovalChannelSummary>;
  removeAccordLockApprovalChannel: (channel: AccordLockApprovalChannelId) => Promise<boolean>;
  setAccordLockApprovalChannelEnabled: (
    channel: AccordLockApprovalChannelId,
    enabled: boolean
  ) => Promise<AccordLockApprovalChannelSummary>;
  testAccordLockApprovalChannel: (
    channel: AccordLockApprovalChannelId
  ) => Promise<AccordLockConnectionTestReport>;
  getAccordLockRemoteApprovalEnrollment: () => Promise<AccordLockRemoteGatewayEnrollmentSummary | null>;
  importAccordLockRemoteApprovalEnrollment: () => Promise<AccordLockRemoteGatewayEnrollmentSummary | null>;
  revokeAccordLockRemoteApprovalEnrollment: (
    enrollmentId: string
  ) => Promise<AccordLockRemoteGatewayEnrollmentSummary>;
  importAccordLockRemoteApprovalReceipt: () => Promise<{
    accepted: true;
    approvalId: string;
    intent: string;
  } | null>;
  listAccordLockEnvironmentProfiles: () => Promise<AccordLockEnvironmentProfileView[]>;
  saveAccordLockEnvironmentProfile: (
    profile: AccordLockEnvironmentProfileInput
  ) => Promise<AccordLockEnvironmentProfileView>;
  removeAccordLockEnvironmentProfile: (profileId: string) => Promise<boolean>;
  runAccordLockDeploymentPreflight: (
    input: DeploymentPreflightInput
  ) => Promise<DeploymentPreflightResultView>;
  listAccordLockDeploymentPreflightHistory: (
    environmentId: string
  ) => Promise<readonly DeploymentPreflightReceiptArchiveSummary[]>;
  exportAccordLockDeploymentPreflightReceipt: (
    receiptHash: string
  ) => Promise<DeploymentPreflightHistoryExportResult>;
  importAccordLockDeploymentPreflightCiEvidence: (
    environmentId: string
  ) => Promise<DeploymentPreflightCiEvidenceImportResult>;
  listAllowedTerminalPrograms: () => Promise<AccordLockTerminalProgramBinding[]>;
  addAllowedTerminalProgram: (alias: string) => Promise<{
    configured: boolean;
    canceled: boolean;
    restartRequired: boolean;
    programs: AccordLockTerminalProgramBinding[];
  }>;
  removeAllowedTerminalProgram: (alias: string) => Promise<{
    removed: boolean;
    canceled: boolean;
    restartRequired: boolean;
    programs: AccordLockTerminalProgramBinding[];
  }>;
  getGovernedNetworkPolicy: () => Promise<{
    domains: string[];
    methods: ['GET', 'HEAD'];
    active: boolean;
  }>;
  setGovernedNetworkDomains: (domains: string[]) => Promise<{
    saved: boolean;
    canceled: boolean;
    restartRequired: boolean;
    domains: string[];
    methods: ['GET', 'HEAD'];
  }>;
  setWakelock: (enable: boolean) => Promise<boolean>;
  getWakelockState: () => Promise<boolean>;
  setSpellcheck: (enable: boolean) => Promise<boolean>;
  getSpellcheckState: () => Promise<boolean>;
  openNotificationsSettings: () => Promise<boolean>;
  isAnyWindowFocused: () => Promise<boolean>;
  getIsFullScreen: () => Promise<boolean>;
  onMouseBackButtonClicked: (callback: () => void) => void;
  offMouseBackButtonClicked: (callback: () => void) => void;
  on: (
    channel: string,
    callback: (event: Electron.IpcRendererEvent, ...args: unknown[]) => void
  ) => void;
  off: (
    channel: string,
    callback: (event: Electron.IpcRendererEvent, ...args: unknown[]) => void
  ) => void;
  emit: (channel: string, ...args: unknown[]) => void;
  broadcastThemeChange: (themeData: {
    mode: string;
    useSystemTheme: boolean;
    theme: string;
    tokensUpdated?: boolean;
  }) => void;
  openExternal: (url: string) => Promise<void>;
  // Update-related functions
  getVersion: () => string;
  checkForUpdates: () => Promise<{ updateInfo: unknown; error: string | null }>;
  downloadUpdate: () => Promise<{ success: boolean; error: string | null }>;
  installUpdate: () => void;
  restartApp: () => void;
  onUpdaterEvent: (callback: (event: UpdaterEvent) => void) => void;
  getUpdateState: () => Promise<{ updateAvailable: boolean; latestVersion?: string } | null>;
  isUsingGitHubFallback: () => Promise<boolean>;
  getAutoDownloadDisabled: () => Promise<boolean>;
  // Recipe warning functions
  closeWindow: () => void;
  hasAcceptedRecipeBefore: (recipe: Recipe) => Promise<boolean>;
  recordRecipeHash: (recipe: Recipe) => Promise<boolean>;
  openDirectoryInExplorer: () => Promise<boolean>;
  launchApp: (app: GooseApp) => Promise<void>;
  refreshApp: (app: GooseApp) => Promise<void>;
  closeApp: (appName: string) => Promise<void>;
  getGitBranchInfo: () => Promise<{ branch: string } | null>;
  listGitBranches: () => Promise<string[]>;
  switchGitBranch: (
    branch: string
  ) => Promise<{ success: boolean; canceled?: boolean; error?: string }>;
};

type AppConfigAPI = {
  get: (key: string) => unknown;
  getAll: () => Record<string, unknown>;
};

const electronAPI: ElectronAPI = {
  platform: process.platform,
  arch: process.arch,
  reactReady: () => ipcRenderer.send('react-ready'),
  getConfig: () => {
    if (!config || Object.keys(config).length === 0) {
      console.warn(
        'No config provided by main process. This may indicate an initialization issue.'
      );
    }
    return config;
  },
  hideWindow: () => ipcRenderer.send('hide-window'),
  openSecureWorkspaceWindow: () => ipcRenderer.invoke('open-secure-workspace-window'),
  selectProjectFolder: () => ipcRenderer.invoke('accordlock:project-folder:select'),
  createChatWindow: (options?: CreateChatWindowOptions) =>
    ipcRenderer.send('create-chat-window', options || {}),
  logInfo: (txt: string) => ipcRenderer.send('logInfo', txt),
  showNotification: (data: AccordLockNotificationRequest) => ipcRenderer.send('notify', data),
  dismissApprovalNotification: (approvalId: string) =>
    ipcRenderer.send(ACCORDLOCK_APPROVAL_NOTIFICATION_DISMISS, approvalId),
  showMessageBox: (options: MessageBoxOptions) => ipcRenderer.invoke('show-message-box', options),
  saveRecipeFile: (suggestedName: string, content: string) =>
    ipcRenderer.invoke('save-recipe-file', { suggestedName, content }),
  saveAuditFile: (suggestedName: string, content: string) =>
    ipcRenderer.invoke('save-audit-file', { suggestedName, content }),
  openInChrome: (url: string) => ipcRenderer.send('open-in-chrome', url),
  reloadApp: () => ipcRenderer.send('reload-app'),
  checkForOllama: () => ipcRenderer.invoke('check-ollama'),

  selectFileOrDirectory: (defaultPath?: string) =>
    ipcRenderer.invoke('select-file-or-directory', defaultPath),
  selectImportSessionFile: () => ipcRenderer.invoke('select-import-session-file'),
  getBinaryPath: (binaryName: string) => ipcRenderer.invoke('get-binary-path', binaryName),
  selectRecipeFile: () => ipcRenderer.invoke('select-recipe-file'),
  readGoosehints: () => ipcRenderer.invoke('read-goosehints'),
  writeGoosehints: (content: string) => ipcRenderer.invoke('write-goosehints', content),
  listFiles: (dirPath: string, extension?: string) =>
    ipcRenderer.invoke('list-files', dirPath, extension),
  getPathForFile: (file: File) => webUtils.getPathForFile(file),
  getAllowedExtensions: () => ipcRenderer.invoke('get-allowed-extensions'),
  setMenuBarIcon: (show: boolean) => ipcRenderer.invoke('set-menu-bar-icon', show),
  getMenuBarIconState: () => ipcRenderer.invoke('get-menu-bar-icon-state'),
  setDockIcon: (show: boolean) => ipcRenderer.invoke('set-dock-icon', show),
  getDockIconState: () => ipcRenderer.invoke('get-dock-icon-state'),
  getSetting: async <K extends SettingKey>(key: K): Promise<Settings[K]> => {
    try {
      // Check for localStorage value first (lazy migration)
      const localStorageKey = localStorageKeyMap[key];
      if (localStorageKey) {
        const rawValue = localStorage.getItem(localStorageKey);
        if (rawValue !== null) {
          const parsed = parseLocalStorageValue(key, rawValue);
          if (parsed !== null) {
            return parsed;
          }
        }
      }
      return await ipcRenderer.invoke('get-setting', key);
    } catch (error) {
      console.error(`Failed to get setting '${key}', using default`, error);
      return defaultSettings[key];
    }
  },
  setSetting: async <K extends SettingKey>(key: K, value: Settings[K]): Promise<void> => {
    // Clear any localStorage version when writing
    const localStorageKey = localStorageKeyMap[key];
    if (localStorageKey) {
      localStorage.removeItem(localStorageKey);
    }
    return ipcRenderer.invoke('set-setting', key, value);
  },
  getSecretKey: () => ipcRenderer.invoke('get-secret-key'),
  getAcpUrl: () => ipcRenderer.invoke('get-acp-url'),
  getPendingAccordLockActionApprovals: () =>
    ipcRenderer.invoke(ACCORDLOCK_APPROVAL_INBOX_GET_PENDING),
  submitAccordLockApprovalCenterDecision: (decision: ApprovalCenterDecision) =>
    ipcRenderer.invoke(ACCORDLOCK_APPROVAL_INBOX_DECIDE, decision),
  getPendingAccordLockTaskAuthorizations: () =>
    ipcRenderer.invoke(ACCORDLOCK_TASK_AUTHORIZATION_GET_PENDING),
  requestAccordLockTaskAuthorization: (request: AccordLockTaskRequest) =>
    ipcRenderer.invoke(ACCORDLOCK_TASK_AUTHORIZATION_PREPARE, request),
  submitAccordLockTaskAuthorizationDecision: (
    request: AccordLockTaskAuthorizationDecisionRequest
  ) => ipcRenderer.invoke(ACCORDLOCK_TASK_AUTHORIZATION_DECIDE, request),
  revokeAccordLockTaskAuthorization: (request: AccordLockTaskAuthorizationRevokeRequest) =>
    ipcRenderer.invoke(ACCORDLOCK_TASK_AUTHORIZATION_REVOKE, request),
  restoreAccordLockDeletedFile: (request: AccordLockTaskRestoreRequest) =>
    ipcRenderer.invoke(ACCORDLOCK_TASK_RESTORE, {
      protocol: request.protocol,
      schema_version: request.schema_version,
      session_id: request.session_id,
      recovery_id: request.recovery_id,
    } satisfies AccordLockTaskRestoreRequest),
  getAccordLockTaskAudit: (request: AccordLockTaskAuditRequest) =>
    ipcRenderer.invoke(ACCORDLOCK_TASK_AUDIT, {
      protocol: request.protocol,
      schema_version: request.schema_version,
      session_id: request.session_id,
      offset: request.offset,
      limit: request.limit,
      snapshot_revision: request.snapshot_revision,
    } satisfies AccordLockTaskAuditRequest),
  listAccordLockApprovalChannels: () => ipcRenderer.invoke(ACCORDLOCK_APPROVAL_CHANNELS_LIST),
  saveAccordLockApprovalChannel: (configuration: AccordLockApprovalChannelInput) =>
    ipcRenderer.invoke(ACCORDLOCK_APPROVAL_CHANNELS_SAVE, configuration),
  removeAccordLockApprovalChannel: (channel: AccordLockApprovalChannelId) =>
    ipcRenderer.invoke(ACCORDLOCK_APPROVAL_CHANNELS_REMOVE, channel),
  setAccordLockApprovalChannelEnabled: (channel: AccordLockApprovalChannelId, enabled: boolean) =>
    ipcRenderer.invoke(ACCORDLOCK_APPROVAL_CHANNELS_SET_ENABLED, channel, enabled),
  testAccordLockApprovalChannel: (channel: AccordLockApprovalChannelId) =>
    ipcRenderer.invoke(ACCORDLOCK_APPROVAL_CHANNELS_TEST, channel),
  getAccordLockRemoteApprovalEnrollment: () =>
    ipcRenderer.invoke(ACCORDLOCK_REMOTE_APPROVAL_ENROLLMENT_GET),
  importAccordLockRemoteApprovalEnrollment: () =>
    ipcRenderer.invoke(ACCORDLOCK_REMOTE_APPROVAL_ENROLLMENT_IMPORT),
  revokeAccordLockRemoteApprovalEnrollment: (enrollmentId: string) =>
    ipcRenderer.invoke(ACCORDLOCK_REMOTE_APPROVAL_ENROLLMENT_REVOKE, enrollmentId),
  importAccordLockRemoteApprovalReceipt: () =>
    ipcRenderer.invoke(ACCORDLOCK_REMOTE_APPROVAL_RECEIPT_IMPORT),
  listAccordLockEnvironmentProfiles: () => ipcRenderer.invoke(ACCORDLOCK_ENVIRONMENT_PROFILES_LIST),
  saveAccordLockEnvironmentProfile: (profile: AccordLockEnvironmentProfileInput) =>
    ipcRenderer.invoke(ACCORDLOCK_ENVIRONMENT_PROFILES_SAVE, profile),
  removeAccordLockEnvironmentProfile: (profileId: string) =>
    ipcRenderer.invoke(ACCORDLOCK_ENVIRONMENT_PROFILES_REMOVE, profileId),
  importAccordLockDeploymentPreflightCiEvidence: (environmentId: string) =>
    ipcRenderer.invoke(ACCORDLOCK_DEPLOYMENT_PREFLIGHT_CI_EVIDENCE_IMPORT, {
      schemaVersion: 1,
      environmentId,
    }),
  runAccordLockDeploymentPreflight: (input: DeploymentPreflightInput) =>
    ipcRenderer.invoke(ACCORDLOCK_DEPLOYMENT_PREFLIGHT_RUN, input),
  listAccordLockDeploymentPreflightHistory: (environmentId: string) =>
    ipcRenderer.invoke(ACCORDLOCK_DEPLOYMENT_PREFLIGHT_HISTORY_LIST, {
      schemaVersion: 1,
      environmentId,
      limit: 50,
    }),
  exportAccordLockDeploymentPreflightReceipt: (receiptHash: string) =>
    ipcRenderer.invoke(ACCORDLOCK_DEPLOYMENT_PREFLIGHT_HISTORY_EXPORT, {
      schemaVersion: 1,
      receiptHash,
    }),
  listAllowedTerminalPrograms: () => ipcRenderer.invoke('accordlock:terminal-program:list'),
  addAllowedTerminalProgram: (alias: string) =>
    ipcRenderer.invoke('accordlock:terminal-program:add', alias),
  removeAllowedTerminalProgram: (alias: string) =>
    ipcRenderer.invoke('accordlock:terminal-program:remove', alias),
  getGovernedNetworkPolicy: () => ipcRenderer.invoke('accordlock:network-policy:get'),
  setGovernedNetworkDomains: (domains: string[]) =>
    ipcRenderer.invoke('accordlock:network-policy:set', domains),
  setWakelock: (enable: boolean) => ipcRenderer.invoke('set-wakelock', enable),
  getWakelockState: () => ipcRenderer.invoke('get-wakelock-state'),
  setSpellcheck: (enable: boolean) => ipcRenderer.invoke('set-spellcheck', enable),
  getSpellcheckState: () => ipcRenderer.invoke('get-spellcheck-state'),
  openNotificationsSettings: () => ipcRenderer.invoke('open-notifications-settings'),
  isAnyWindowFocused: () => ipcRenderer.invoke('is-any-window-focused'),
  getIsFullScreen: () => ipcRenderer.invoke('get-is-fullscreen'),
  onMouseBackButtonClicked: (callback: () => void) => {
    // Wrapper that ignores the event parameter.
    const wrappedCallback = (_event: Electron.IpcRendererEvent) => callback();
    ipcRenderer.on('mouse-back-button-clicked', wrappedCallback);
    return wrappedCallback;
  },
  offMouseBackButtonClicked: (callback: () => void) => {
    ipcRenderer.removeListener('mouse-back-button-clicked', callback);
  },
  on: (
    channel: string,
    callback: (event: Electron.IpcRendererEvent, ...args: unknown[]) => void
  ) => {
    ipcRenderer.on(channel, callback);
  },
  off: (
    channel: string,
    callback: (event: Electron.IpcRendererEvent, ...args: unknown[]) => void
  ) => {
    ipcRenderer.off(channel, callback);
  },
  emit: (channel: string, ...args: unknown[]) => {
    ipcRenderer.emit(channel, ...args);
  },
  broadcastThemeChange: (themeData: {
    mode: string;
    useSystemTheme: boolean;
    theme: string;
    tokensUpdated?: boolean;
  }) => {
    ipcRenderer.send('broadcast-theme-change', themeData);
  },
  openExternal: (url: string): Promise<void> => {
    return ipcRenderer.invoke('open-external', url);
  },
  getVersion: (): string => {
    return config.GOOSE_VERSION || ipcRenderer.sendSync('get-app-version') || '';
  },
  checkForUpdates: (): Promise<{ updateInfo: unknown; error: string | null }> => {
    return ipcRenderer.invoke('check-for-updates');
  },
  downloadUpdate: (): Promise<{ success: boolean; error: string | null }> => {
    return ipcRenderer.invoke('download-update');
  },
  installUpdate: (): void => {
    ipcRenderer.invoke('install-update');
  },
  restartApp: (): void => {
    ipcRenderer.send('restart-app');
  },
  onUpdaterEvent: (callback: (event: UpdaterEvent) => void): void => {
    ipcRenderer.on('updater-event', (_event, data) => callback(data));
  },
  getUpdateState: (): Promise<{ updateAvailable: boolean; latestVersion?: string } | null> => {
    return ipcRenderer.invoke('get-update-state');
  },
  isUsingGitHubFallback: (): Promise<boolean> => {
    return ipcRenderer.invoke('is-using-github-fallback');
  },
  getAutoDownloadDisabled: (): Promise<boolean> => {
    return ipcRenderer.invoke('get-auto-download-disabled');
  },
  closeWindow: () => ipcRenderer.send('close-window'),
  hasAcceptedRecipeBefore: (recipe: Recipe) =>
    ipcRenderer.invoke('has-accepted-recipe-before', recipe),
  recordRecipeHash: (recipe: Recipe) => ipcRenderer.invoke('record-recipe-hash', recipe),
  openDirectoryInExplorer: () => ipcRenderer.invoke('open-directory-in-explorer'),
  // MCP Apps are disabled in the policy-enforced distribution. Keep typed
  // renderer compatibility without exposing dormant window/reload authority over IPC.
  launchApp: async (_app: GooseApp) => {
    throw new Error('Apps are unavailable in the AccordLock secure profile.');
  },
  refreshApp: async (_app: GooseApp) => {
    throw new Error('Apps are unavailable in the AccordLock secure profile.');
  },
  closeApp: async (_appName: string) => {
    throw new Error('Apps are unavailable in the AccordLock secure profile.');
  },
  getGitBranchInfo: () => ipcRenderer.invoke('get-git-branch-info'),
  listGitBranches: () => ipcRenderer.invoke('list-git-branches'),
  switchGitBranch: (branch: string) => ipcRenderer.invoke('switch-git-branch', branch),
};

const appConfigAPI: AppConfigAPI = {
  get: (key: string) => config[key],
  getAll: () => ({ ...config }),
};

// Expose the APIs
contextBridge.exposeInMainWorld('electron', electronAPI);
contextBridge.exposeInMainWorld('appConfig', appConfigAPI);

// Type declaration for TypeScript
declare global {
  interface Window {
    electron: ElectronAPI;
    appConfig: AppConfigAPI;
  }
}
