import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  accordLockDefaultWorkspace,
  isAccordLockWorkspaceTooBroad,
  resolveAccordLockWorkspace,
} from './accordlockWorkspace';

describe('AccordLock workspace boundary', () => {
  const volume = path.parse(process.cwd()).root;
  const home = path.join(volume, 'Users', 'operator');
  const userData = path.join(home, 'AppData', 'Roaming', 'AccordLock');

  it('starts in an isolated empty workspace instead of the user home', () => {
    expect(resolveAccordLockWorkspace(undefined, userData, [home, userData])).toBe(
      accordLockDefaultWorkspace(userData)
    );
  });

  it('rejects filesystem roots, the home directory, and their ancestors', () => {
    expect(isAccordLockWorkspaceTooBroad(volume, [home, userData])).toBe(true);
    expect(isAccordLockWorkspaceTooBroad(home, [home, userData])).toBe(true);
    expect(isAccordLockWorkspaceTooBroad(path.dirname(home), [home, userData])).toBe(true);
  });

  it('allows a deliberately selected project below the home directory', () => {
    const project = path.join(home, 'Documents', 'acme-service');
    expect(resolveAccordLockWorkspace(project, userData, [home, userData])).toBe(
      path.resolve(project)
    );
  });
});
