/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * @vitest-environment jsdom
 */
import React from 'react';
import { screen, render, waitFor } from '@testing-library/react';
import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';
import { AppInner, PairRouteWrapper, resolveSessionInitialMessage } from './App';
import { IntlTestWrapper } from './i18n/test-utils';
import { FeaturesProvider } from './contexts/FeaturesContext';
import { reconnectAcpAfterSystemResume } from './acp/acpConnection';
import { createSession } from './sessions';
import { RecipeParameterScopesUnsupportedError } from './acp/errors';
import { acpDeleteSession, acpListSessions, type SessionListItem } from './acp/sessions';
import { AppEvents } from './constants/events';

const mockToastError = vi.hoisted(() => vi.fn());

// Set up globals for jsdom
Object.defineProperty(window, 'location', {
  value: {
    hash: '',
    search: '',
    href: 'http://localhost:3000',
    origin: 'http://localhost:3000',
    pathname: '/',
  },
  writable: true,
});

Object.defineProperty(window, 'history', {
  value: {
    replaceState: vi.fn(),
    state: null,
  },
  writable: true,
});

vi.mock('./utils/costDatabase', () => ({
  initializeCostDatabase: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('./acp/sessions', () => ({
  acpListSessions: vi.fn().mockResolvedValue({ sessions: [], nextCursor: null }),
  acpDeleteSession: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('./sessions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./sessions')>()),
  fetchSessionDetails: vi
    .fn()
    .mockResolvedValue({ sessionId: 'test', messages: [], metadata: { description: '' } }),
  generateSessionId: vi.fn(),
  createSession: vi.fn(),
}));

vi.mock('./acp/capabilities', () => ({
  getAcpFeatureCapabilities: vi.fn().mockResolvedValue({ localInference: true }),
}));

vi.mock('./acp/acpConnection', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./acp/acpConnection')>()),
  reconnectAcpAfterSystemResume: vi.fn(),
}));

// Mock the ACP providers module used by OnboardingGuard so it doesn't try to
// open a real ACP client connection during tests. Returning null defaults
// keeps the app in the "brand new" (no provider configured) onboarding state.
vi.mock('./acp/providers', () => ({
  acpReadDefaults: vi.fn().mockResolvedValue({ providerId: null, modelId: null }),
  acpSaveDefaults: vi.fn().mockResolvedValue(undefined),
  acpListProviderDetails: vi.fn().mockResolvedValue([]),
}));

// Mock the ConfigContext module
vi.mock('./components/ConfigContext', () => ({
  useConfig: () => ({
    read: vi.fn().mockResolvedValue(null),
    update: vi.fn(),
    getExtensions: vi.fn().mockReturnValue([]),
    addExtension: vi.fn(),
    updateExtension: vi.fn(),
    createProviderDefaults: vi.fn(),
  }),
  ConfigProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

// Mock other components to simplify testing
vi.mock('./components/ErrorBoundary', () => ({
  ErrorUI: ({ error }: { error: Error }) => <div>Error: {error.message}</div>,
}));

vi.mock('./components/ModelAndProviderContext', () => ({
  ModelAndProviderProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  useModelAndProvider: () => ({
    provider: null,
    model: null,
    getCurrentModelAndProvider: vi.fn(),
    getFallbackModelAndProvider: vi.fn().mockResolvedValue({ provider: '', model: '' }),
    refreshCurrentModelAndProvider: vi.fn().mockResolvedValue(undefined),
    setCurrentModelAndProvider: vi.fn(),
  }),
}));

vi.mock('./contexts/ChatContext', () => ({
  ChatProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  useChatContext: () => ({
    chat: {
      id: 'test-id',
      name: 'Test Chat',
      messages: [],
      recipe: null,
    },
    setChat: vi.fn(),
    setPairChat: vi.fn(), // Keep this from HEAD
    resetChat: vi.fn(),
    hasActiveSession: false,
    setRecipe: vi.fn(),
    clearRecipe: vi.fn(),
    contextKey: 'hub',
  }),
  DEFAULT_CHAT_TITLE: 'New Chat', // Keep this from HEAD
}));

vi.mock('./components/ui/ConfirmationModal', () => ({
  ConfirmationModal: () => null,
}));

vi.mock('react-toastify', () => ({
  ToastContainer: () => null,
  toast: {
    error: mockToastError,
  },
}));

vi.mock('./components/GoosehintsModal', () => ({
  GoosehintsModal: () => null,
}));

vi.mock('./components/AnnouncementModal', () => ({
  default: () => null,
}));

// Create mocks that we can track and configure per test
const mockNavigate = vi.fn();
const mockSearchParams = new URLSearchParams();
const mockSetSearchParams = vi.fn();

// Mock react-router to avoid HashRouter issues in tests
vi.mock('react-router', () => ({
  HashRouter: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  Routes: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  Route: ({ element }: { element: React.ReactNode }) => element,
  useNavigate: () => mockNavigate,
  useLocation: () => ({ state: null, pathname: '/' }),
  useSearchParams: () => [mockSearchParams, mockSetSearchParams],
  Outlet: () => null,
}));

// Mock electron API
const mockElectron = {
  getConfig: vi.fn().mockReturnValue({
    GOOSE_ALLOWLIST_WARNING: false,
    GOOSE_WORKING_DIR: '/test/dir',
  }),
  logInfo: vi.fn(),
  on: vi.fn(),
  off: vi.fn(),
  reactReady: vi.fn(),
  getAllowedExtensions: vi.fn().mockResolvedValue([]),
  platform: 'darwin',
  createChatWindow: vi.fn(),
  getSetting: vi.fn().mockResolvedValue(null),
  setSetting: vi.fn().mockResolvedValue(undefined),
  showNotification: vi.fn(),
  getPendingAccordLockActionApprovals: vi.fn().mockResolvedValue([]),
  submitAccordLockApprovalCenterDecision: vi.fn().mockRejectedValue(new Error('No test approval')),
  getPendingAccordLockTaskAuthorizations: vi.fn().mockResolvedValue([]),
  requestAccordLockTaskAuthorization: vi.fn().mockResolvedValue(null),
  submitAccordLockTaskAuthorizationDecision: vi
    .fn()
    .mockRejectedValue(new Error('No test runtime')),
  revokeAccordLockTaskAuthorization: vi.fn((request: { session_id: string }) =>
    Promise.resolve({
      protocol: 'accordlock.desktop.control/v2',
      schema_version: 2,
      session_id: request.session_id,
      task_id: null,
      run_id: null,
      status: 'REVOKED',
      reason_code: 'NO_SESSION_AUTHORIZATION',
      revocation_record: { request_id: null, revocation_digest: null },
    })
  ),
};

// Mock appConfig
const mockAppConfig = {
  get: vi.fn((key: string): string | null => {
    if (key === 'GOOSE_WORKING_DIR') return '/test/dir';
    return null;
  }),
};

// Attach mocks to window
(window as any).electron = mockElectron;
(window as any).appConfig = mockAppConfig;

// Mock matchMedia
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: vi.fn().mockImplementation((query) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(), // deprecated
    removeListener: vi.fn(), // deprecated
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
});

function AppInnerTestWrapper({ children }: { children: React.ReactNode }) {
  return (
    <IntlTestWrapper>
      <FeaturesProvider>{children}</FeaturesProvider>
    </IntlTestWrapper>
  );
}

describe('App Component - Brand New State', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockNavigate.mockClear();
    mockSetSearchParams.mockClear();
    mockAppConfig.get.mockImplementation((key: string): string | null => {
      if (key === 'GOOSE_WORKING_DIR') return '/test/dir';
      return null;
    });

    // Reset search params
    mockSearchParams.forEach((_, key) => {
      mockSearchParams.delete(key);
    });

    window.location.hash = '';
    window.location.search = '';
    window.location.pathname = '/';
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('should redirect to "/" when app is brand new (no provider configured)', async () => {
    // Mock no provider configured
    mockElectron.getConfig.mockReturnValue({
      GOOSE_DEFAULT_PROVIDER: null,
      GOOSE_DEFAULT_MODEL: null,
      GOOSE_ALLOWLIST_WARNING: false,
    });

    render(<AppInner />, { wrapper: AppInnerTestWrapper });

    // Wait for initialization
    await waitFor(() => {
      expect(mockElectron.reactReady).toHaveBeenCalled();
    });

    // The app should initialize without any navigation calls since we're already at "/"
    // No navigate calls should be made when no provider is configured
    expect(mockNavigate).not.toHaveBeenCalled();
  });

  it('should handle deep links correctly when app is brand new', async () => {
    // Mock no provider configured
    mockElectron.getConfig.mockReturnValue({
      GOOSE_DEFAULT_PROVIDER: null,
      GOOSE_DEFAULT_MODEL: null,
      GOOSE_ALLOWLIST_WARNING: false,
    });

    // Set up search params to simulate view=settings deep link
    mockSearchParams.set('view', 'settings');

    render(<AppInner />, { wrapper: AppInnerTestWrapper });

    // Wait for initialization
    await waitFor(() => {
      expect(mockElectron.reactReady).toHaveBeenCalled();
    });

    expect(
      await screen.findByText(/^Welcome to AccordLock/, {}, { timeout: 5000 })
    ).toBeInTheDocument();
  });

  it('should not redirect when provider is configured', async () => {
    // Mock provider configured
    mockElectron.getConfig.mockReturnValue({
      GOOSE_DEFAULT_PROVIDER: 'openai',
      GOOSE_DEFAULT_MODEL: 'gpt-4',
      GOOSE_ALLOWLIST_WARNING: false,
    });

    render(<AppInner />, { wrapper: AppInnerTestWrapper });

    // Wait for initialization
    await waitFor(() => {
      expect(mockElectron.reactReady).toHaveBeenCalled();
    });

    // Should not navigate anywhere since provider is configured and we're already at "/"
    expect(mockNavigate).not.toHaveBeenCalled();
  });

  it('shows the scoped-parameter incompatibility before returning home', async () => {
    mockAppConfig.get.mockImplementation((key: string): string | null => {
      if (key === 'GOOSE_WORKING_DIR') return '/test/dir';
      if (key === 'recipeDeeplink') return 'accordlock://recipe?url=example';
      return null;
    });
    vi.mocked(createSession).mockRejectedValueOnce(new RecipeParameterScopesUnsupportedError());

    render(<PairRouteWrapper activeSessions={[]} setActiveSessions={vi.fn()} />, {
      wrapper: AppInnerTestWrapper,
    });

    await waitFor(() => {
      expect(mockToastError).toHaveBeenCalledWith(
        'The connected agent backend does not support securely scoped recipe parameters. Update AccordLock or the backend and try again.'
      );
    });
    expect(mockNavigate).toHaveBeenCalledWith('/');
  });

  it('should navigate home when the main process emits new-chat', async () => {
    mockElectron.getConfig.mockReturnValue({
      GOOSE_DEFAULT_PROVIDER: 'openai',
      GOOSE_DEFAULT_MODEL: 'gpt-4',
      GOOSE_ALLOWLIST_WARNING: false,
    });

    render(<AppInner />, { wrapper: AppInnerTestWrapper });

    await waitFor(() => {
      expect(mockElectron.reactReady).toHaveBeenCalled();
    });

    const newChatHandler = mockElectron.on.mock.calls.find(
      ([channel]) => channel === 'new-chat'
    )?.[1];
    expect(newChatHandler).toBeDefined();

    newChatHandler?.({} as any);

    expect(mockNavigate).toHaveBeenCalledWith('/');
  });

  it('opens only a validated notification destination', async () => {
    render(<AppInner />, { wrapper: AppInnerTestWrapper });

    await waitFor(() => {
      expect(mockElectron.reactReady).toHaveBeenCalled();
    });

    const notificationHandler = mockElectron.on.mock.calls.find(
      ([channel]) => channel === 'accordlock:notification-open'
    )?.[1];
    expect(notificationHandler).toBeDefined();

    const approvalId = `action:sha256:${'a'.repeat(64)}`;
    notificationHandler?.({} as any, { kind: 'APPROVAL', approvalId });
    expect(mockNavigate).toHaveBeenCalledWith(`/approvals?item=${encodeURIComponent(approvalId)}`);

    mockNavigate.mockClear();
    notificationHandler?.({} as any, {
      kind: 'APPROVAL',
      approvalId: '../untrusted',
    });
    expect(mockNavigate).not.toHaveBeenCalled();
  });

  it('should reconnect ACP when the main process emits system-resume', async () => {
    render(<AppInner />, { wrapper: AppInnerTestWrapper });

    await waitFor(() => {
      expect(mockElectron.reactReady).toHaveBeenCalled();
    });

    const systemResumeHandler = mockElectron.on.mock.calls.find(
      ([channel]) => channel === 'system-resume'
    )?.[1];
    expect(systemResumeHandler).toBeDefined();

    systemResumeHandler?.({} as any);

    expect(reconnectAcpAfterSystemResume).toHaveBeenCalledOnce();
  });

  it('retires a phantom session before deleting it and announcing its deletion', async () => {
    const phantom: SessionListItem = {
      id: 'phantom-session',
      name: 'Untitled',
      workingDir: '/test/dir',
      updatedAt: '2026-08-24T00:00:00.000Z',
      messageCount: 0,
      createdAt: '2026-08-24T00:00:00.000Z',
      userSetName: false,
      hasRecipe: false,
    };
    vi.mocked(acpListSessions).mockResolvedValueOnce({ sessions: [phantom], nextCursor: null });
    const order: string[] = [];
    mockElectron.revokeAccordLockTaskAuthorization.mockImplementationOnce(async (request) => {
      order.push('retired');
      return {
        protocol: 'accordlock.desktop.control/v2',
        schema_version: 2,
        session_id: request.session_id,
        task_id: null,
        run_id: null,
        status: 'REVOKED',
        reason_code: 'NO_SESSION_AUTHORIZATION',
        revocation_record: { request_id: null, revocation_digest: null },
      };
    });
    vi.mocked(acpDeleteSession).mockImplementationOnce(async () => {
      order.push('deleted');
    });
    const deletedSessionIds: string[] = [];
    const onSessionDeleted = (event: Event) => {
      deletedSessionIds.push((event as CustomEvent<{ sessionId: string }>).detail.sessionId);
    };
    window.addEventListener(AppEvents.SESSION_DELETED, onSessionDeleted);

    try {
      render(<AppInner />, { wrapper: AppInnerTestWrapper });

      await waitFor(() => expect(acpDeleteSession).toHaveBeenCalledWith(phantom.id));
      expect(order).toEqual(['retired', 'deleted']);
      expect(deletedSessionIds).toEqual([phantom.id]);
    } finally {
      window.removeEventListener(AppEvents.SESSION_DELETED, onSessionDeleted);
    }
  });

  it('keeps a phantom session when runtime retirement cannot be proven', async () => {
    const phantom: SessionListItem = {
      id: 'phantom-session',
      name: 'Untitled',
      workingDir: '/test/dir',
      updatedAt: '2026-08-24T00:00:00.000Z',
      messageCount: 0,
      createdAt: '2026-08-24T00:00:00.000Z',
      userSetName: false,
      hasRecipe: false,
    };
    vi.mocked(acpListSessions).mockResolvedValueOnce({ sessions: [phantom], nextCursor: null });
    mockElectron.revokeAccordLockTaskAuthorization.mockRejectedValueOnce(
      new Error('trusted runtime unavailable')
    );
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined);

    render(<AppInner />, { wrapper: AppInnerTestWrapper });

    await waitFor(() =>
      expect(consoleError).toHaveBeenCalledWith(
        'Could not safely clean up an empty AccordLock session:',
        expect.objectContaining({ message: 'trusted runtime unavailable' })
      )
    );
    expect(acpDeleteSession).not.toHaveBeenCalled();
    consoleError.mockRestore();
  });

  it('should seed recipe sessions with the recipe prompt when no initial message is provided', () => {
    expect(
      resolveSessionInitialMessage(
        {
          recipe: {
            prompt: 'Write a release note for the latest change',
          },
        },
        undefined
      )
    ).toEqual({
      msg: 'Write a release note for the latest change',
      images: [],
    });
  });
});
