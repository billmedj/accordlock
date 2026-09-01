// Modified by AccordLock contributors; see UPSTREAM.md.
import path from 'node:path';

const ACCORDLOCK_SQUIRREL_PACKAGE = 'accordlock_desktop';
const ACCORDLOCK_DEVELOPMENT_SQUIRREL_PACKAGE = 'accordlock_desktop_development';

export interface AccordLockWindowIconLocation {
  appPath: string;
  isPackaged: boolean;
  platform: NodeJS.Platform;
  resourcesPath: string;
}

export function accordLockWindowIconName(platform: NodeJS.Platform): string {
  if (platform === 'darwin') return 'icon.icns';
  if (platform === 'win32') return 'icon.ico';
  return 'icon.png';
}

export function resolveAccordLockWindowIconPath({
  appPath,
  isPackaged,
  platform,
  resourcesPath,
}: AccordLockWindowIconLocation): string {
  const imageDirectory = isPackaged
    ? path.join(resourcesPath, 'images')
    : path.join(appPath, 'src', 'images');

  return path.join(imageDirectory, accordLockWindowIconName(platform));
}

export function accordLockWindowsAppUserModelId(isDevelopmentPackage: boolean): string {
  const squirrelPackage = isDevelopmentPackage
    ? ACCORDLOCK_DEVELOPMENT_SQUIRREL_PACKAGE
    : ACCORDLOCK_SQUIRREL_PACKAGE;
  return `com.squirrel.${squirrelPackage}.AccordLock`;
}
