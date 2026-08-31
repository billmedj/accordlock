import fs, { constants as fsConstants } from 'node:fs';
import fsPromises from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  DesktopFileAccess,
  MAX_DIRECTORY_ENTRIES,
  MAX_GOOSEHINTS_BYTES,
  MAX_NATIVE_SAVE_BYTES,
  isAppRendererUrl,
  isAuthorizedFileAccessRequest,
  readSelectedRecipe,
} from './desktopFileAccess';

const tempDirectories: string[] = [];

function makeTempDirectory(): string {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'goose-desktop-file-access-'));
  tempDirectories.push(directory);
  return directory;
}

afterEach(() => {
  vi.restoreAllMocks();
  while (tempDirectories.length > 0) {
    fs.rmSync(tempDirectories.pop()!, { recursive: true, force: true });
  }
});

describe('DesktopFileAccess', () => {
  it('reads .goosehints from the bound working directory', async () => {
    const workingDirectory = makeTempDirectory();
    fs.writeFileSync(path.join(workingDirectory, '.goosehints'), 'project guidance');
    const access = new DesktopFileAccess();
    await access.bindWindow(7, workingDirectory);
    const canonicalWorkingDirectory = fs.realpathSync(workingDirectory);

    await expect(access.readGoosehints(7)).resolves.toEqual({
      file: 'project guidance',
      filePath: path.join(canonicalWorkingDirectory, '.goosehints'),
      error: null,
      found: true,
    });
  });

  it('preserves missing-file behavior', async () => {
    const workingDirectory = makeTempDirectory();
    const access = new DesktopFileAccess();
    await access.bindWindow(7, workingDirectory);
    const canonicalWorkingDirectory = fs.realpathSync(workingDirectory);

    await expect(access.readGoosehints(7)).resolves.toEqual({
      file: '',
      filePath: path.join(canonicalWorkingDirectory, '.goosehints'),
      error: null,
      found: false,
    });
  });

  it('creates and updates .goosehints in the bound working directory', async () => {
    const workingDirectory = makeTempDirectory();
    const access = new DesktopFileAccess();
    await access.bindWindow(7, workingDirectory);
    const filePath = path.join(fs.realpathSync(workingDirectory), '.goosehints');

    await expect(access.writeGoosehints(7, 'first guidance')).resolves.toBe(true);
    expect(fs.readFileSync(filePath, 'utf8')).toBe('first guidance');

    await expect(access.writeGoosehints(7, 'updated guidance')).resolves.toBe(true);
    expect(fs.readFileSync(filePath, 'utf8')).toBe('updated guidance');
  });

  it('bounds .goosehints reads and writes to 256 KiB', async () => {
    const workingDirectory = makeTempDirectory();
    const access = new DesktopFileAccess();
    await access.bindWindow(7, workingDirectory);
    const filePath = path.join(workingDirectory, '.goosehints');
    const oversized = 'x'.repeat(MAX_GOOSEHINTS_BYTES + 1);

    await expect(access.writeGoosehints(7, oversized)).resolves.toBe(false);
    expect(fs.existsSync(filePath)).toBe(false);

    fs.writeFileSync(filePath, oversized);
    const result = await access.readGoosehints(7);
    expect(result.found).toBe(false);
    expect(result.error).toContain('size limit');
  });

  it('refuses a hard-linked .goosehints without modifying its other link', async () => {
    const root = makeTempDirectory();
    const workingDirectory = path.join(root, 'project');
    const outsideFile = path.join(root, 'outside-guidance');
    fs.mkdirSync(workingDirectory);
    fs.writeFileSync(outsideFile, 'outside guidance');
    fs.linkSync(outsideFile, path.join(workingDirectory, '.goosehints'));
    const access = new DesktopFileAccess();
    await access.bindWindow(7, workingDirectory);

    const result = await access.readGoosehints(7);
    await expect(access.writeGoosehints(7, 'replacement')).resolves.toBe(false);
    expect(result.found).toBe(false);
    expect(result.error).toContain('regular file');
    expect(fs.readFileSync(outsideFile, 'utf8')).toBe('outside guidance');
  });

  it.skipIf(process.platform === 'win32')('creates .goosehints with mode 0600', async () => {
    const workingDirectory = makeTempDirectory();
    const access = new DesktopFileAccess();
    await access.bindWindow(7, workingDirectory);
    const filePath = path.join(workingDirectory, '.goosehints');

    await expect(access.writeGoosehints(7, 'private guidance')).resolves.toBe(true);
    expect(fs.statSync(filePath).mode & 0o777).toBe(0o600);
  });

  it.skipIf(process.platform === 'win32')(
    'rejects a canonical working directory replaced by a symlink',
    async () => {
      const root = makeTempDirectory();
      const workingDirectory = path.join(root, 'project');
      const originalDirectory = path.join(root, 'original-project');
      const replacementDirectory = path.join(root, 'replacement-project');
      fs.mkdirSync(workingDirectory);
      fs.mkdirSync(replacementDirectory);
      fs.writeFileSync(path.join(workingDirectory, '.goosehints'), 'original guidance');
      fs.writeFileSync(path.join(replacementDirectory, '.goosehints'), 'replacement guidance');
      const access = new DesktopFileAccess();
      await access.bindWindow(7, workingDirectory);

      fs.renameSync(workingDirectory, originalDirectory);
      fs.symlinkSync(replacementDirectory, workingDirectory);

      const result = await access.readGoosehints(7);
      await expect(access.writeGoosehints(7, 'new guidance')).resolves.toBe(false);
      expect(result.found).toBe(false);
      expect(result.error).toContain('working directory changed');
      expect(fs.readFileSync(path.join(originalDirectory, '.goosehints'), 'utf8')).toBe(
        'original guidance'
      );
      expect(fs.readFileSync(path.join(replacementDirectory, '.goosehints'), 'utf8')).toBe(
        'replacement guidance'
      );
    }
  );

  it('rejects a canonical working directory replaced by another directory', async () => {
    const root = makeTempDirectory();
    const workingDirectory = path.join(root, 'project');
    const originalDirectory = path.join(root, 'original-project');
    fs.mkdirSync(workingDirectory);
    fs.writeFileSync(path.join(workingDirectory, '.goosehints'), 'original guidance');
    const access = new DesktopFileAccess();
    await access.bindWindow(7, workingDirectory);

    fs.renameSync(workingDirectory, originalDirectory);
    fs.mkdirSync(workingDirectory);
    fs.writeFileSync(path.join(workingDirectory, '.goosehints'), 'replacement guidance');

    const result = await access.readGoosehints(7);
    await expect(access.writeGoosehints(7, 'new guidance')).resolves.toBe(false);
    expect(result.found).toBe(false);
    expect(result.error).toContain('working directory changed');
    expect(fs.readFileSync(path.join(originalDirectory, '.goosehints'), 'utf8')).toBe(
      'original guidance'
    );
    expect(fs.readFileSync(path.join(workingDirectory, '.goosehints'), 'utf8')).toBe(
      'replacement guidance'
    );
  });

  it('rejects a bound working directory that was renamed away', async () => {
    const root = makeTempDirectory();
    const workingDirectory = path.join(root, 'project');
    const renamedDirectory = path.join(root, 'renamed-project');
    fs.mkdirSync(workingDirectory);
    fs.writeFileSync(path.join(workingDirectory, '.goosehints'), 'original guidance');
    const access = new DesktopFileAccess();
    await access.bindWindow(7, workingDirectory);

    fs.renameSync(workingDirectory, renamedDirectory);

    const result = await access.readGoosehints(7);
    await expect(access.writeGoosehints(7, 'new guidance')).resolves.toBe(false);
    expect(result.found).toBe(false);
    expect(result.error).toContain('working directory changed');
    expect(fs.readFileSync(path.join(renamedDirectory, '.goosehints'), 'utf8')).toBe(
      'original guidance'
    );
  });

  it.skipIf(process.platform === 'win32')(
    'rechecks the working directory before truncating an opened .goosehints',
    async () => {
      const root = makeTempDirectory();
      const workingDirectory = path.join(root, 'project');
      const renamedDirectory = path.join(root, 'renamed-project');
      const filePath = path.join(workingDirectory, '.goosehints');
      fs.mkdirSync(workingDirectory);
      fs.writeFileSync(filePath, 'original guidance');
      const access = new DesktopFileAccess();
      await access.bindWindow(7, workingDirectory);
      const open = fsPromises.open.bind(fsPromises);
      vi.spyOn(fsPromises, 'open').mockImplementationOnce(async (...args) => {
        fs.renameSync(workingDirectory, renamedDirectory);
        fs.mkdirSync(workingDirectory);
        fs.linkSync(
          path.join(renamedDirectory, '.goosehints'),
          path.join(workingDirectory, '.goosehints')
        );
        return open(...args);
      });

      await expect(access.writeGoosehints(7, 'new guidance')).resolves.toBe(false);
      expect(fs.readFileSync(path.join(renamedDirectory, '.goosehints'), 'utf8')).toBe(
        'original guidance'
      );
    }
  );

  it.skipIf(process.platform === 'win32')(
    'rechecks the working directory before reading an opened .goosehints',
    async () => {
      const root = makeTempDirectory();
      const workingDirectory = path.join(root, 'project');
      const renamedDirectory = path.join(root, 'renamed-project');
      const filePath = path.join(workingDirectory, '.goosehints');
      fs.mkdirSync(workingDirectory);
      fs.writeFileSync(filePath, 'original guidance');
      const access = new DesktopFileAccess();
      await access.bindWindow(7, workingDirectory);
      const open = fsPromises.open.bind(fsPromises);
      vi.spyOn(fsPromises, 'open').mockImplementationOnce(async (...args) => {
        fs.renameSync(workingDirectory, renamedDirectory);
        fs.mkdirSync(workingDirectory);
        fs.linkSync(
          path.join(renamedDirectory, '.goosehints'),
          path.join(workingDirectory, '.goosehints')
        );
        return open(...args);
      });

      const result = await access.readGoosehints(7);

      expect(result.found).toBe(false);
      expect(result.file).toBe('');
      expect(result.error).toContain('working directory changed');
    }
  );

  it('rechecks the working directory before creating a missing .goosehints', async () => {
    const root = makeTempDirectory();
    const workingDirectory = path.join(root, 'project');
    const renamedDirectory = path.join(root, 'renamed-project');
    fs.mkdirSync(workingDirectory);
    const access = new DesktopFileAccess();
    await access.bindWindow(7, workingDirectory);
    const lstat = fsPromises.lstat.bind(fsPromises);
    vi.spyOn(fsPromises, 'lstat').mockImplementation(async (...args) => {
      try {
        return await lstat(...args);
      } catch (error) {
        if (path.basename(args[0].toString()) === '.goosehints') {
          fs.renameSync(workingDirectory, renamedDirectory);
          fs.mkdirSync(workingDirectory);
        }
        throw error;
      }
    });
    const open = vi.spyOn(fsPromises, 'open');

    await expect(access.writeGoosehints(7, 'new guidance')).resolves.toBe(false);
    expect(open).not.toHaveBeenCalled();
    expect(fs.existsSync(path.join(workingDirectory, '.goosehints'))).toBe(false);
  });

  it('rejects a renderer without a bound working directory', async () => {
    const access = new DesktopFileAccess();

    await expect(access.readGoosehints(99)).rejects.toThrow('not authorized');
    await expect(access.writeGoosehints(99, 'project guidance')).rejects.toThrow('not authorized');
  });

  it('lists only directories inside the workspace bound to that window', async () => {
    const root = makeTempDirectory();
    const firstWorkspace = path.join(root, 'first');
    const secondWorkspace = path.join(root, 'second');
    fs.mkdirSync(path.join(firstWorkspace, 'src'), { recursive: true });
    fs.mkdirSync(secondWorkspace);
    fs.writeFileSync(path.join(firstWorkspace, 'src', 'inside.ts'), 'inside');
    fs.writeFileSync(path.join(secondWorkspace, 'secret.ts'), 'secret');
    const access = new DesktopFileAccess();
    await access.bindWindow(7, firstWorkspace);
    await access.bindWindow(8, secondWorkspace);

    await expect(access.listFiles(7, path.join(firstWorkspace, 'src'))).resolves.toEqual([
      'inside.ts',
    ]);
    await expect(access.listFiles(7, secondWorkspace)).rejects.toThrow('outside');
    await expect(access.listFiles(8, secondWorkspace)).resolves.toEqual(['secret.ts']);
  });

  it('rejects traversal outside the bound workspace', async () => {
    const root = makeTempDirectory();
    const workingDirectory = path.join(root, 'project');
    fs.mkdirSync(workingDirectory);
    const access = new DesktopFileAccess();
    await access.bindWindow(7, workingDirectory);

    await expect(access.listFiles(7, `${workingDirectory}${path.sep}..`)).rejects.toThrow();
    await expect(access.listFiles(7, '../project')).rejects.toThrow('invalid');
  });

  it('rejects a directory symlink that escapes the bound workspace', async () => {
    const root = makeTempDirectory();
    const workingDirectory = path.join(root, 'project');
    const outsideDirectory = path.join(root, 'outside');
    const linkedDirectory = path.join(workingDirectory, 'linked');
    fs.mkdirSync(workingDirectory);
    fs.mkdirSync(outsideDirectory);
    fs.writeFileSync(path.join(outsideDirectory, 'secret.txt'), 'secret');
    fs.symlinkSync(
      outsideDirectory,
      linkedDirectory,
      process.platform === 'win32' ? 'junction' : 'dir'
    );
    const access = new DesktopFileAccess();
    await access.bindWindow(7, workingDirectory);

    await expect(access.listFiles(7, linkedDirectory)).rejects.toThrow('symbolic-link');
  });

  it('fails closed when a directory exceeds the bounded entry count', async () => {
    const workingDirectory = makeTempDirectory();
    for (let index = 0; index <= MAX_DIRECTORY_ENTRIES; index += 1) {
      fs.writeFileSync(path.join(workingDirectory, `entry-${index}`), '');
    }
    const access = new DesktopFileAccess();
    await access.bindWindow(7, workingDirectory);

    await expect(access.listFiles(7, workingDirectory)).rejects.toThrow('entry limit');
  });

  it('atomically couples one native save selection to one bounded write', async () => {
    const workingDirectory = makeTempDirectory();
    const destination = path.join(workingDirectory, 'export.yaml');
    const access = new DesktopFileAccess();
    await access.bindWindow(7, workingDirectory);
    const showDialog = vi.fn().mockResolvedValue({ canceled: false, filePath: destination });

    await expect(
      access.saveRecipeWithNativeDialog(
        7,
        { suggestedName: 'export.yaml', content: 'title: Exported' },
        showDialog
      )
    ).resolves.toEqual({ canceled: false, filePath: destination, saved: true });
    expect(showDialog).toHaveBeenCalledOnce();
    expect(fs.readFileSync(destination, 'utf8')).toBe('title: Exported');
  });

  it('exports a bounded JSON audit through one native save selection', async () => {
    const workingDirectory = makeTempDirectory();
    const destination = path.join(workingDirectory, 'task.audit.json');
    const access = new DesktopFileAccess();
    await access.bindWindow(7, workingDirectory);
    const showDialog = vi.fn().mockResolvedValue({ canceled: false, filePath: destination });
    const content = '{"schemaVersion":1}\n';

    await expect(
      access.saveAuditWithNativeDialog(7, { suggestedName: 'task.audit.json', content }, showDialog)
    ).resolves.toEqual({ canceled: false, filePath: destination, saved: true });
    expect(fs.readFileSync(destination, 'utf8')).toBe(content);
  });

  it('exports a bounded Markdown task report through the same native save boundary', async () => {
    const workingDirectory = makeTempDirectory();
    const destination = path.join(workingDirectory, 'task-report.md');
    const access = new DesktopFileAccess();
    await access.bindWindow(7, workingDirectory);
    const showDialog = vi.fn().mockResolvedValue({ canceled: false, filePath: destination });
    const content = '# AccordLock task receipt\n';

    await expect(
      access.saveAuditWithNativeDialog(7, { suggestedName: 'task-report.md', content }, showDialog)
    ).resolves.toEqual({ canceled: false, filePath: destination, saved: true });
    expect(fs.readFileSync(destination, 'utf8')).toBe(content);
  });

  it('rejects an unsupported audit filename before opening the native dialog', async () => {
    const workingDirectory = makeTempDirectory();
    const access = new DesktopFileAccess();
    await access.bindWindow(7, workingDirectory);
    const showDialog = vi.fn();

    await expect(
      access.saveAuditWithNativeDialog(
        7,
        { suggestedName: '../task.txt', content: '{}' },
        showDialog
      )
    ).rejects.toThrow('filename');
    expect(showDialog).not.toHaveBeenCalled();
  });

  it('returns one canonical workspace selected by the trusted native dialog', async () => {
    const root = makeTempDirectory();
    const currentWorkspace = path.join(root, 'current');
    const nextWorkspace = path.join(root, 'next');
    fs.mkdirSync(currentWorkspace);
    fs.mkdirSync(nextWorkspace);
    const access = new DesktopFileAccess();
    await access.bindWindow(7, currentWorkspace);
    const showDialog = vi.fn().mockResolvedValue({
      canceled: false,
      filePaths: [nextWorkspace],
    });

    await expect(access.selectWorkspaceWithNativeDialog(7, showDialog)).resolves.toEqual({
      canceled: false,
      directory: fs.realpathSync(nextWorkspace),
    });
    expect(showDialog).toHaveBeenCalledWith(fs.realpathSync(currentWorkspace));
    expect(showDialog).toHaveBeenCalledOnce();
  });

  it('rejects a symlink workspace returned by the native dialog', async () => {
    const root = makeTempDirectory();
    const currentWorkspace = path.join(root, 'current');
    const targetWorkspace = path.join(root, 'target');
    const linkedWorkspace = path.join(root, 'linked');
    fs.mkdirSync(currentWorkspace);
    fs.mkdirSync(targetWorkspace);
    fs.symlinkSync(
      targetWorkspace,
      linkedWorkspace,
      process.platform === 'win32' ? 'junction' : 'dir'
    );
    const access = new DesktopFileAccess();
    await access.bindWindow(7, currentWorkspace);

    await expect(
      access.selectWorkspaceWithNativeDialog(7, async () => ({
        canceled: false,
        filePaths: [linkedWorkspace],
      }))
    ).rejects.toThrow('regular directory');
  });

  it('does not allow another window to initiate a save through this window binding', async () => {
    const workingDirectory = makeTempDirectory();
    const access = new DesktopFileAccess();
    await access.bindWindow(7, workingDirectory);
    const showDialog = vi.fn();

    await expect(
      access.saveRecipeWithNativeDialog(
        8,
        { suggestedName: 'export.yaml', content: 'title: Cross-window' },
        showDialog
      )
    ).rejects.toThrow('not authorized');
    expect(showDialog).not.toHaveBeenCalled();
  });

  it('rejects overlapping native saves instead of exposing a replayable write grant', async () => {
    const workingDirectory = makeTempDirectory();
    const destination = path.join(workingDirectory, 'export.yaml');
    const access = new DesktopFileAccess();
    await access.bindWindow(7, workingDirectory);
    let releaseSelection!: (selection: { canceled: boolean; filePath?: string }) => void;
    const pendingSelection = new Promise<{ canceled: boolean; filePath?: string }>((resolve) => {
      releaseSelection = resolve;
    });
    const firstSave = access.saveRecipeWithNativeDialog(
      7,
      { suggestedName: 'export.yaml', content: 'title: First' },
      () => pendingSelection
    );
    await vi.waitFor(() => expect((access as never) !== undefined).toBe(true));

    await expect(
      access.saveRecipeWithNativeDialog(
        7,
        { suggestedName: 'export.yaml', content: 'title: Replay' },
        async () => ({ canceled: false, filePath: destination })
      )
    ).rejects.toThrow('already active');

    releaseSelection({ canceled: false, filePath: destination });
    await expect(firstSave).resolves.toMatchObject({ saved: true });
    expect(fs.readFileSync(destination, 'utf8')).toBe('title: First');
  });

  it('rejects oversized native save content before showing a dialog', async () => {
    const workingDirectory = makeTempDirectory();
    const access = new DesktopFileAccess();
    await access.bindWindow(7, workingDirectory);
    const showDialog = vi.fn();

    await expect(
      access.saveRecipeWithNativeDialog(
        7,
        { suggestedName: 'export.yaml', content: 'x'.repeat(MAX_NATIVE_SAVE_BYTES + 1) },
        showDialog
      )
    ).rejects.toThrow('size limit');
    expect(showDialog).not.toHaveBeenCalled();
  });

  it.skipIf(process.platform === 'win32')(
    'refuses to overwrite a symlink selected by the native save dialog',
    async () => {
      const workingDirectory = makeTempDirectory();
      const target = path.join(workingDirectory, 'target.yaml');
      const selected = path.join(workingDirectory, 'export.yaml');
      fs.writeFileSync(target, 'title: Original');
      fs.symlinkSync(target, selected);
      const access = new DesktopFileAccess();
      await access.bindWindow(7, workingDirectory);

      await expect(
        access.saveRecipeWithNativeDialog(
          7,
          { suggestedName: 'export.yaml', content: 'title: Replacement' },
          async () => ({ canceled: false, filePath: selected })
        )
      ).rejects.toThrow('regular file');
      expect(fs.readFileSync(target, 'utf8')).toBe('title: Original');
    }
  );

  it('refuses to overwrite a hard-linked file selected by the native save dialog', async () => {
    const root = makeTempDirectory();
    const workingDirectory = path.join(root, 'project');
    const target = path.join(root, 'outside.yaml');
    const selected = path.join(workingDirectory, 'export.yaml');
    fs.mkdirSync(workingDirectory);
    fs.writeFileSync(target, 'title: Original');
    fs.linkSync(target, selected);
    const access = new DesktopFileAccess();
    await access.bindWindow(7, workingDirectory);

    await expect(
      access.saveRecipeWithNativeDialog(
        7,
        { suggestedName: 'export.yaml', content: 'title: Replacement' },
        async () => ({ canceled: false, filePath: selected })
      )
    ).rejects.toThrow('regular file');
    expect(fs.readFileSync(target, 'utf8')).toBe('title: Original');
  });

  it.skipIf(process.platform === 'win32')(
    'blocks a .goosehints symlink that escapes the working directory',
    async () => {
      const root = makeTempDirectory();
      const workingDirectory = path.join(root, 'project');
      const secretPath = path.join(root, 'secret');
      fs.mkdirSync(workingDirectory);
      fs.writeFileSync(secretPath, 'host secret');
      fs.symlinkSync('../secret', path.join(workingDirectory, '.goosehints'));
      const access = new DesktopFileAccess();
      await access.bindWindow(7, workingDirectory);

      const result = await access.readGoosehints(7);
      const saved = await access.writeGoosehints(7, 'replacement');

      expect(result.found).toBe(false);
      expect(result.file).toBe('');
      expect(result.error).toContain('symbolic link');
      expect(saved).toBe(false);
      expect(fs.readFileSync(secretPath, 'utf8')).toBe('host secret');
    }
  );

  it('does not truncate a replacement file opened after validation', async () => {
    const workingDirectory = makeTempDirectory();
    const filePath = path.join(workingDirectory, '.goosehints');
    const originalPath = path.join(workingDirectory, 'original.goosehints');
    fs.writeFileSync(filePath, 'original guidance');
    const access = new DesktopFileAccess();
    await access.bindWindow(7, workingDirectory);
    const open = fsPromises.open.bind(fsPromises);
    vi.spyOn(fsPromises, 'open').mockImplementationOnce(async (...args) => {
      fs.renameSync(filePath, originalPath);
      fs.writeFileSync(filePath, 'replacement guidance');
      return open(...args);
    });

    await expect(access.writeGoosehints(7, 'new guidance')).resolves.toBe(false);
    expect(fs.readFileSync(filePath, 'utf8')).toBe('replacement guidance');
    expect(fs.readFileSync(originalPath, 'utf8')).toBe('original guidance');
  });

  it.skipIf(process.platform === 'win32')(
    'keeps a symlinked working directory pinned to its bind-time target',
    async () => {
      const root = makeTempDirectory();
      const firstProject = path.join(root, 'first-project');
      const secondProject = path.join(root, 'second-project');
      const workingDirectory = path.join(root, 'current-project');
      fs.mkdirSync(firstProject);
      fs.mkdirSync(secondProject);
      fs.writeFileSync(path.join(firstProject, '.goosehints'), 'first guidance');
      fs.writeFileSync(path.join(secondProject, '.goosehints'), 'second guidance');
      fs.symlinkSync(firstProject, workingDirectory);
      const access = new DesktopFileAccess();
      await access.bindWindow(7, workingDirectory);
      const canonicalFirstProject = fs.realpathSync(firstProject);

      fs.unlinkSync(workingDirectory);
      fs.symlinkSync(secondProject, workingDirectory);

      await expect(access.readGoosehints(7)).resolves.toEqual({
        file: 'first guidance',
        filePath: path.join(canonicalFirstProject, '.goosehints'),
        error: null,
        found: true,
      });
      await expect(access.writeGoosehints(7, 'updated first guidance')).resolves.toBe(true);
      expect(fs.readFileSync(path.join(firstProject, '.goosehints'), 'utf8')).toBe(
        'updated first guidance'
      );
      expect(fs.readFileSync(path.join(secondProject, '.goosehints'), 'utf8')).toBe(
        'second guidance'
      );
    }
  );

  it.skipIf(process.platform === 'win32')(
    'rejects a non-regular .goosehints target without blocking',
    async () => {
      const workingDirectory = makeTempDirectory();
      execFileSync('mkfifo', [path.join(workingDirectory, '.goosehints')]);
      const access = new DesktopFileAccess();
      await access.bindWindow(7, workingDirectory);

      await expect(access.writeGoosehints(7, 'project guidance')).resolves.toBe(false);
    }
  );
});

describe('renderer provenance', () => {
  const devServerUrl = new URL('http://127.0.0.1:5173/');

  it('accepts legitimate hash-routed app URLs', () => {
    expect(isAppRendererUrl('http://127.0.0.1:5173/#/settings', devServerUrl)).toBe(true);
    expect(isAppRendererUrl('http://127.0.0.1:5173/#/schedules?tab=active', devServerUrl)).toBe(
      true
    );
    expect(
      isAppRendererUrl(
        'file:///Applications/Goose.app/Contents/Resources/renderer/main_window/index.html#/settings',
        new URL('file:///Applications/Goose.app/Contents/Resources/renderer/main_window/index.html')
      )
    ).toBe(true);
  });

  it('rejects sibling paths, foreign origins, and malformed URLs', () => {
    expect(isAppRendererUrl('http://127.0.0.1:5173/admin#/settings', devServerUrl)).toBe(false);
    expect(isAppRendererUrl('http://localhost:5173/#/settings', devServerUrl)).toBe(false);
    expect(isAppRendererUrl('https://attacker.example/#/settings', devServerUrl)).toBe(false);
    expect(
      isAppRendererUrl(
        'file://attacker/Applications/Goose.app/Contents/Resources/renderer/main_window/index.html',
        new URL('file:///Applications/Goose.app/Contents/Resources/renderer/main_window/index.html')
      )
    ).toBe(false);
    expect(isAppRendererUrl('not a URL', devServerUrl)).toBe(false);
  });

  it('requires a registered top-level Goose window', () => {
    const legitimateRequest = {
      isRegisteredWindow: true,
      isMainFrame: true,
      rendererUrl: 'http://127.0.0.1:5173/#/settings',
    };

    expect(isAuthorizedFileAccessRequest(legitimateRequest, devServerUrl)).toBe(true);
    expect(
      isAuthorizedFileAccessRequest(
        { ...legitimateRequest, isRegisteredWindow: false },
        devServerUrl
      )
    ).toBe(false);
    expect(
      isAuthorizedFileAccessRequest({ ...legitimateRequest, isMainFrame: false }, devServerUrl)
    ).toBe(false);
  });
});

describe('readSelectedRecipe', () => {
  it('reads a picker-selected YAML recipe', async () => {
    const directory = makeTempDirectory();
    const recipePath = path.join(directory, 'recipe.yaml');
    fs.writeFileSync(recipePath, 'title: Daily summary');

    await expect(readSelectedRecipe(recipePath)).resolves.toEqual({
      file: 'title: Daily summary',
      filePath: recipePath,
      error: null,
      found: true,
    });
  });

  it('does not read a selected non-recipe file', async () => {
    const directory = makeTempDirectory();
    const secretPath = path.join(directory, 'secret.txt');
    fs.writeFileSync(secretPath, 'host secret');

    const result = await readSelectedRecipe(secretPath);

    expect(result.found).toBe(false);
    expect(result.file).toBe('');
    expect(result.error).toContain('YAML');
  });

  it.skipIf(process.platform === 'win32')('allows a picker-selected YAML symlink', async () => {
    const directory = makeTempDirectory();
    const targetPath = path.join(directory, 'target.yaml');
    const recipePath = path.join(directory, 'recipe.yaml');
    fs.writeFileSync(targetPath, 'title: Linked recipe');
    fs.symlinkSync(targetPath, recipePath);

    await expect(readSelectedRecipe(recipePath)).resolves.toEqual({
      file: 'title: Linked recipe',
      filePath: recipePath,
      error: null,
      found: true,
    });
  });

  it.skipIf(process.platform === 'win32')(
    'reads from the opened recipe when a selected symlink is retargeted',
    async () => {
      const directory = makeTempDirectory();
      const firstTarget = path.join(directory, 'first.yaml');
      const secondTarget = path.join(directory, 'second.yaml');
      const recipePath = path.join(directory, 'recipe.yaml');
      fs.writeFileSync(firstTarget, 'title: First recipe');
      fs.writeFileSync(secondTarget, 'title: Second recipe');
      fs.symlinkSync(firstTarget, recipePath);
      const open = fsPromises.open.bind(fsPromises);
      const openSpy = vi.spyOn(fsPromises, 'open').mockImplementationOnce(async (...args) => {
        const handle = await open(...args);
        fs.unlinkSync(recipePath);
        fs.symlinkSync(secondTarget, recipePath);
        return handle;
      });

      await expect(readSelectedRecipe(recipePath)).resolves.toEqual({
        file: 'title: First recipe',
        filePath: recipePath,
        error: null,
        found: true,
      });
      expect(openSpy).toHaveBeenCalledOnce();
    }
  );

  it.skipIf(process.platform === 'win32')(
    'rejects a picker-selected FIFO without blocking',
    async () => {
      const directory = makeTempDirectory();
      const recipePath = path.join(directory, 'recipe.yaml');
      execFileSync('mkfifo', [recipePath]);
      const openSpy = vi.spyOn(fsPromises, 'open');

      const result = await readSelectedRecipe(recipePath);

      expect(result.found).toBe(false);
      expect(result.error).toContain('not a regular file');
      expect(openSpy).toHaveBeenCalledWith(
        recipePath,
        fsConstants.O_RDONLY | fsConstants.O_NONBLOCK
      );
    }
  );
});
