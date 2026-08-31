import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  loadAccordLockTerminalPrograms,
  pickAndPersistAccordLockTerminalProgram,
  removeAccordLockTerminalProgram,
  validateAccordLockTerminalProgramAlias,
} from './accordlockTerminalPrograms';

const temporaryDirectories: string[] = [];

const fixture = () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'accordlock-terminal-programs-'));
  temporaryDirectories.push(directory);
  const executable = path.join(directory, process.platform === 'win32' ? 'probe.exe' : 'probe');
  fs.writeFileSync(executable, 'native-probe-fixture');
  return {
    directory,
    executable,
    configuration: path.join(directory, 'programs.json'),
  };
};

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

describe('AccordLock trusted terminal program provisioning', () => {
  it('persists only the file returned by the native picker with a digest commitment', async () => {
    const paths = fixture();
    const result = await pickAndPersistAccordLockTerminalProgram({
      alias: 'test-probe',
      configurationPath: paths.configuration,
      selectExecutable: async () => ({ canceled: false, filePaths: [paths.executable] }),
    });

    expect(result).toEqual({ configured: true, canceled: false, restartRequired: true });
    expect(loadAccordLockTerminalPrograms(paths.configuration)).toEqual([
      {
        alias: 'test-probe',
        executable_path: fs.realpathSync.native(paths.executable),
        executable_sha256: expect.stringMatching(/^sha256:[0-9a-f]{64}$/u),
      },
    ]);
  });

  it('requires main-process confirmation over the exact inspected identity', async () => {
    const paths = fixture();
    const confirmBinding = vi.fn().mockResolvedValue(false);
    const result = await pickAndPersistAccordLockTerminalProgram({
      alias: 'test-probe',
      configurationPath: paths.configuration,
      selectExecutable: async () => ({ canceled: false, filePaths: [paths.executable] }),
      confirmBinding,
    });

    expect(confirmBinding).toHaveBeenCalledWith({
      alias: 'test-probe',
      executable_path: fs.realpathSync.native(paths.executable),
      executable_sha256: expect.stringMatching(/^sha256:[0-9a-f]{64}$/u),
    });
    expect(result).toEqual({ configured: false, canceled: true, restartRequired: false });
    expect(fs.existsSync(paths.configuration)).toBe(false);
  });

  it.each(['cmd', 'powershell', 'UPPER', '../escape', ''])(
    'rejects dangerous alias %j',
    (alias) => {
      expect(() => validateAccordLockTerminalProgramAlias(alias)).toThrow('non-shell profile');
    }
  );

  it('fails closed when the stored configuration commitment is substituted', async () => {
    const paths = fixture();
    await pickAndPersistAccordLockTerminalProgram({
      alias: 'test-probe',
      configurationPath: paths.configuration,
      selectExecutable: async () => ({ canceled: false, filePaths: [paths.executable] }),
    });
    const document = JSON.parse(fs.readFileSync(paths.configuration, 'utf8')) as Record<
      string,
      unknown
    >;
    document.configuration_digest = `sha256:${'0'.repeat(64)}`;
    fs.writeFileSync(paths.configuration, JSON.stringify(document));

    expect(() => loadAccordLockTerminalPrograms(paths.configuration)).toThrow('commitment');
  });

  it('fails closed when a selected executable changes on disk', async () => {
    const paths = fixture();
    await pickAndPersistAccordLockTerminalProgram({
      alias: 'test-probe',
      configurationPath: paths.configuration,
      selectExecutable: async () => ({ canceled: false, filePaths: [paths.executable] }),
    });
    fs.appendFileSync(paths.executable, 'tamper');

    expect(() => loadAccordLockTerminalPrograms(paths.configuration)).toThrow(
      'changed after it was selected'
    );
  });

  it('removes a binding atomically by validated alias', async () => {
    const paths = fixture();
    await pickAndPersistAccordLockTerminalProgram({
      alias: 'test-probe',
      configurationPath: paths.configuration,
      selectExecutable: async () => ({ canceled: false, filePaths: [paths.executable] }),
    });

    expect(removeAccordLockTerminalProgram('test-probe', paths.configuration)).toBe(true);
    expect(loadAccordLockTerminalPrograms(paths.configuration)).toEqual([]);
    expect(removeAccordLockTerminalProgram('test-probe', paths.configuration)).toBe(false);
  });
});
