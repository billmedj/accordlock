import path from 'node:path';
import { beforeEach, describe, expect, it, vi } from 'vitest';

describe('AccordLock bootstrap', () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it('routes Electron and Chromium logs outside the application directory', async () => {
    const setName = vi.fn();
    const userDataDirectory = path.join('C:', 'Users', 'Ada', 'AppData', 'Roaming', 'AccordLock');
    const logsDirectory = path.join(userDataDirectory, 'logs');
    const getPath = vi.fn((name: string) => {
      if (name === 'userData') return userDataDirectory;
      if (name === 'logs') return logsDirectory;
      throw new Error(`Unexpected Electron path: ${name}`);
    });
    const setAppLogsPath = vi.fn();
    const appendSwitch = vi.fn();

    vi.doMock('electron', () => ({
      app: {
        setName,
        getPath,
        setAppLogsPath,
        commandLine: { appendSwitch },
      },
    }));

    await import('./accordlockBootstrap');

    expect(setName).toHaveBeenCalledOnce();
    expect(setName).toHaveBeenCalledWith('AccordLock');
    expect(getPath).toHaveBeenCalledTimes(2);
    expect(getPath).toHaveBeenNthCalledWith(1, 'userData');
    expect(getPath).toHaveBeenNthCalledWith(2, 'logs');
    expect(setAppLogsPath).toHaveBeenCalledOnce();
    expect(setAppLogsPath).toHaveBeenCalledWith(logsDirectory);
    expect(appendSwitch).toHaveBeenCalledOnce();
    expect(appendSwitch).toHaveBeenCalledWith('log-file', path.join(logsDirectory, 'chromium.log'));
    expect(setName.mock.invocationCallOrder[0]).toBeLessThan(getPath.mock.invocationCallOrder[0]);
    expect(setAppLogsPath.mock.invocationCallOrder[0]).toBeLessThan(
      getPath.mock.invocationCallOrder[1]
    );
    expect(setAppLogsPath.mock.invocationCallOrder[0]).toBeLessThan(
      appendSwitch.mock.invocationCallOrder[0]
    );
  });
});
