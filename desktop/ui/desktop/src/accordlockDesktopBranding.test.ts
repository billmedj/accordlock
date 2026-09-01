// Modified by AccordLock contributors; see UPSTREAM.md.
import { existsSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  accordLockWindowIconName,
  accordLockWindowsAppUserModelId,
  resolveAccordLockWindowIconPath,
} from './accordlockDesktopBranding';

describe('AccordLock desktop branding', () => {
  it.each([
    ['win32', 'icon.ico'],
    ['darwin', 'icon.icns'],
    ['linux', 'icon.png'],
  ] as const)('selects the native %s icon', (platform, expected) => {
    expect(accordLockWindowIconName(platform)).toBe(expected);
  });

  it.each(['win32', 'darwin', 'linux'] as const)(
    'ships the selected %s brand asset',
    (platform) => {
      const iconPath = resolveAccordLockWindowIconPath({
        appPath: process.cwd(),
        isPackaged: false,
        platform,
        resourcesPath: path.join(process.cwd(), 'resources'),
      });
      expect(existsSync(iconPath)).toBe(true);
    }
  );

  it('loads the checked-in brand asset while Electron Forge is running from source', () => {
    expect(
      resolveAccordLockWindowIconPath({
        appPath: path.join('work', 'desktop'),
        isPackaged: false,
        platform: 'win32',
        resourcesPath: path.join('ignored', 'resources'),
      })
    ).toBe(path.join('work', 'desktop', 'src', 'images', 'icon.ico'));
  });

  it('loads the extraResource brand asset from a packaged application', () => {
    expect(
      resolveAccordLockWindowIconPath({
        appPath: path.join('resources', 'app.asar'),
        isPackaged: true,
        platform: 'win32',
        resourcesPath: 'resources',
      })
    ).toBe(path.join('resources', 'images', 'icon.ico'));
  });

  it('matches the stable and development Squirrel shortcut identities', () => {
    expect(accordLockWindowsAppUserModelId(false)).toBe(
      'com.squirrel.accordlock_desktop.AccordLock'
    );
    expect(accordLockWindowsAppUserModelId(true)).toBe(
      'com.squirrel.accordlock_desktop_development.AccordLock'
    );
  });
});
