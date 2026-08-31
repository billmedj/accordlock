// Modified by AccordLock contributors; see UPSTREAM.md.
import { beforeEach, describe, expect, it, vi } from 'vitest';

describe('preload file access boundary', () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it('exposes only narrow file operations without renderer-supplied paths', async () => {
    const exposed: Record<string, unknown> = {};
    const invoke = vi.fn();
    vi.doMock('electron', () => ({
      default: {},
      contextBridge: {
        exposeInMainWorld: (name: string, api: unknown) => {
          exposed[name] = api;
        },
      },
      ipcRenderer: {
        emit: vi.fn(),
        invoke,
        off: vi.fn(),
        on: vi.fn(),
        removeListener: vi.fn(),
        send: vi.fn(),
        sendSync: vi.fn(),
      },
      webUtils: { getPathForFile: vi.fn() },
    }));

    await import('./preload');

    const electron = exposed.electron as Record<string, (...args: unknown[]) => unknown>;
    expect(electron).not.toHaveProperty('readFile');

    electron.selectRecipeFile('/etc/passwd');
    electron.selectProjectFolder('/etc/passwd');
    electron.readGoosehints('../secret');
    electron.writeGoosehints('project guidance', '../secret');

    expect(invoke).toHaveBeenNthCalledWith(1, 'select-recipe-file');
    expect(invoke).toHaveBeenNthCalledWith(2, 'accordlock:project-folder:select');
    expect(invoke).toHaveBeenNthCalledWith(3, 'read-goosehints');
    expect(invoke).toHaveBeenNthCalledWith(4, 'write-goosehints', 'project guidance');
  });

  it('exposes terminal provisioning by alias only and never accepts a renderer path', async () => {
    const exposed: Record<string, unknown> = {};
    const invoke = vi.fn();
    vi.doMock('electron', () => ({
      default: {},
      contextBridge: {
        exposeInMainWorld: (name: string, api: unknown) => {
          exposed[name] = api;
        },
      },
      ipcRenderer: {
        emit: vi.fn(),
        invoke,
        off: vi.fn(),
        on: vi.fn(),
        removeListener: vi.fn(),
        send: vi.fn(),
        sendSync: vi.fn(),
      },
      webUtils: { getPathForFile: vi.fn() },
    }));
    await import('./preload');
    const electron = exposed.electron as Record<string, (...args: unknown[]) => unknown>;

    electron.listAllowedTerminalPrograms();
    electron.addAllowedTerminalProgram('cargo');
    electron.removeAllowedTerminalProgram('cargo');

    expect(invoke).toHaveBeenNthCalledWith(1, 'accordlock:terminal-program:list');
    expect(invoke).toHaveBeenNthCalledWith(2, 'accordlock:terminal-program:add', 'cargo');
    expect(invoke).toHaveBeenNthCalledWith(3, 'accordlock:terminal-program:remove', 'cargo');
  });

  it('exposes only exact-domain network policy configuration', async () => {
    const exposed: Record<string, unknown> = {};
    const invoke = vi.fn();
    vi.doMock('electron', () => ({
      default: {},
      contextBridge: {
        exposeInMainWorld: (name: string, api: unknown) => {
          exposed[name] = api;
        },
      },
      ipcRenderer: {
        emit: vi.fn(),
        invoke,
        off: vi.fn(),
        on: vi.fn(),
        removeListener: vi.fn(),
        send: vi.fn(),
        sendSync: vi.fn(),
      },
      webUtils: { getPathForFile: vi.fn() },
    }));
    await import('./preload');
    const electron = exposed.electron as Record<string, (...args: unknown[]) => unknown>;

    electron.getGovernedNetworkPolicy();
    electron.setGovernedNetworkDomains(['api.example.com']);

    expect(invoke).toHaveBeenNthCalledWith(1, 'accordlock:network-policy:get');
    expect(invoke).toHaveBeenNthCalledWith(2, 'accordlock:network-policy:set', ['api.example.com']);
    expect(electron).not.toHaveProperty('httpsRequest');
    expect(electron).not.toHaveProperty('fetch');
  });

  it('never exposes provider callbacks, gateway keys, or signed receipts through renderer IPC', async () => {
    const exposed: Record<string, unknown> = {};
    const invoke = vi.fn();
    vi.doMock('electron', () => ({
      default: {},
      contextBridge: {
        exposeInMainWorld: (name: string, api: unknown) => {
          exposed[name] = api;
        },
      },
      ipcRenderer: {
        emit: vi.fn(),
        invoke,
        off: vi.fn(),
        on: vi.fn(),
        removeListener: vi.fn(),
        send: vi.fn(),
        sendSync: vi.fn(),
      },
      webUtils: { getPathForFile: vi.fn() },
    }));
    await import('./preload');
    const electron = exposed.electron as Record<string, (...args: unknown[]) => unknown>;

    electron.importAccordLockRemoteApprovalEnrollment({ publicKey: 'renderer-controlled' });
    electron.importAccordLockRemoteApprovalReceipt({ providerPayload: 'renderer-controlled' });

    expect(invoke).toHaveBeenNthCalledWith(1, 'accordlock:remote-approval-enrollment:import');
    expect(invoke).toHaveBeenNthCalledWith(2, 'accordlock:remote-approval-receipt:import');
    expect(electron).not.toHaveProperty('submitAccordLockRemoteProviderCallback');
    expect(electron).not.toHaveProperty('submitAccordLockVerifiedRemoteDecision');
  });

  it('strips renderer fields from a deleted-file restore request', async () => {
    const exposed: Record<string, unknown> = {};
    const invoke = vi.fn();
    vi.doMock('electron', () => ({
      default: {},
      contextBridge: {
        exposeInMainWorld: (name: string, api: unknown) => {
          exposed[name] = api;
        },
      },
      ipcRenderer: {
        emit: vi.fn(),
        invoke,
        off: vi.fn(),
        on: vi.fn(),
        removeListener: vi.fn(),
        send: vi.fn(),
        sendSync: vi.fn(),
      },
      webUtils: { getPathForFile: vi.fn() },
    }));
    await import('./preload');
    const electron = exposed.electron as Record<string, (...args: unknown[]) => unknown>;

    electron.restoreAccordLockDeletedFile({
      protocol: 'accordlock.desktop.control/v2',
      schema_version: 2,
      session_id: 'session-1',
      recovery_id: '33333333-3333-4333-8333-333333333333',
      relative_path: '../outside.txt',
      workspace_root: 'C:\\outside',
    });

    expect(invoke).toHaveBeenCalledWith('accordlock:control:recovery:restore', {
      protocol: 'accordlock.desktop.control/v2',
      schema_version: 2,
      session_id: 'session-1',
      recovery_id: '33333333-3333-4333-8333-333333333333',
    });
  });

  it('exposes only the bounded task-audit query fields', async () => {
    const exposed: Record<string, unknown> = {};
    const invoke = vi.fn();
    vi.doMock('electron', () => ({
      default: {},
      contextBridge: {
        exposeInMainWorld: (name: string, api: unknown) => {
          exposed[name] = api;
        },
      },
      ipcRenderer: {
        emit: vi.fn(),
        invoke,
        off: vi.fn(),
        on: vi.fn(),
        removeListener: vi.fn(),
        send: vi.fn(),
        sendSync: vi.fn(),
      },
      webUtils: { getPathForFile: vi.fn() },
    }));
    await import('./preload');
    const electron = exposed.electron as Record<string, (...args: unknown[]) => unknown>;

    electron.getAccordLockTaskAudit({
      protocol: 'accordlock.desktop.control/v2',
      schema_version: 2,
      session_id: 'session-1',
      offset: 0,
      limit: 100,
      include_arguments: true,
      include_output: true,
    });

    expect(invoke).toHaveBeenCalledWith('accordlock:control:audit:get', {
      protocol: 'accordlock.desktop.control/v2',
      schema_version: 2,
      session_id: 'session-1',
      offset: 0,
      limit: 100,
    });
  });

  it('exposes environment summaries and deployment preflight without main-process secrets', async () => {
    const exposed: Record<string, unknown> = {};
    const invoke = vi.fn();
    vi.doMock('electron', () => ({
      default: {},
      contextBridge: {
        exposeInMainWorld: (name: string, api: unknown) => {
          exposed[name] = api;
        },
      },
      ipcRenderer: {
        emit: vi.fn(),
        invoke,
        off: vi.fn(),
        on: vi.fn(),
        removeListener: vi.fn(),
        send: vi.fn(),
        sendSync: vi.fn(),
      },
      webUtils: { getPathForFile: vi.fn() },
    }));
    await import('./preload');
    const electron = exposed.electron as Record<string, (...args: unknown[]) => unknown>;
    const profile = { id: null, name: 'Production' };
    const input = {
      protocol: 'accordlock.deployment-preflight.v1',
      schemaVersion: 1,
      profileId: '33333333-3333-4333-8333-333333333333',
      pullRequestUrl: 'https://github.com/accordlock/product/pull/42',
      buildRunUrl: 'https://github.com/accordlock/product/actions/runs/987',
      imageDigest: `sha256:${'5'.repeat(64)}`,
    };

    electron.listAccordLockEnvironmentProfiles();
    electron.saveAccordLockEnvironmentProfile(profile);
    electron.removeAccordLockEnvironmentProfile(input.profileId);
    electron.runAccordLockDeploymentPreflight(input);
    electron.listAccordLockDeploymentPreflightHistory(input.profileId);
    electron.exportAccordLockDeploymentPreflightReceipt(input.imageDigest);

    expect(invoke).toHaveBeenNthCalledWith(1, 'accordlock:environment-profiles:list');
    expect(invoke).toHaveBeenNthCalledWith(2, 'accordlock:environment-profiles:save', profile);
    expect(invoke).toHaveBeenNthCalledWith(
      3,
      'accordlock:environment-profiles:remove',
      input.profileId
    );
    expect(invoke).toHaveBeenNthCalledWith(4, 'accordlock:deployment-preflight:run', input);
    expect(invoke).toHaveBeenNthCalledWith(5, 'accordlock:deployment-preflight:history:list', {
      schemaVersion: 1,
      environmentId: input.profileId,
      limit: 50,
    });
    expect(invoke).toHaveBeenNthCalledWith(6, 'accordlock:deployment-preflight:history:export', {
      schemaVersion: 1,
      receiptHash: input.imageDigest,
    });
    expect(electron).not.toHaveProperty('loadAccordLockEnvironmentProfileExecutionBundle');
    expect(electron).not.toHaveProperty('recordAccordLockEnvironmentProfileVerification');
    expect(electron).not.toHaveProperty('appendAccordLockDeploymentPreflightReceipt');
    expect(electron).not.toHaveProperty('loadAccordLockDeploymentPreflightReceiptPackage');
  });
});
