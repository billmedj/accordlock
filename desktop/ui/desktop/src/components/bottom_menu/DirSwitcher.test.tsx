import type { ReactNode } from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { IntlTestWrapper } from '../../i18n/test-utils';
import { DirSwitcher, normalizeWorkspacePathForDisplay, splitDirPath } from './DirSwitcher';

vi.mock('../ui/dropdown-menu', () => ({
  DropdownMenu: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuContent: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuItem: ({ children, onSelect }: { children: ReactNode; onSelect?: () => void }) => (
    <button onClick={onSelect}>{children}</button>
  ),
  DropdownMenuLabel: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuSeparator: () => <hr />,
  DropdownMenuTrigger: ({ children }: { children: ReactNode }) => <div>{children}</div>,
}));

describe('DirSwitcher workspace navigation', () => {
  beforeEach(() => {
    window.electron.openSecureWorkspaceWindow = vi
      .fn()
      .mockResolvedValue({ opened: false, canceled: true });
    window.electron.openDirectoryInExplorer = vi.fn().mockResolvedValue(true);
  });

  it('opens a native, pathless new-window flow instead of mutating this window', async () => {
    render(<DirSwitcher className="" workingDir="C:\\trusted\\project" />, {
      wrapper: IntlTestWrapper,
    });

    await userEvent.click(screen.getByRole('button', { name: /open workspace in a new window/i }));

    expect(window.electron.openSecureWorkspaceWindow).toHaveBeenCalledOnce();
    expect(window.electron.openSecureWorkspaceWindow).toHaveBeenCalledWith();
    expect(screen.getAllByText(/project/i).length).toBeGreaterThan(0);
  });

  it('shows only the leaf folder in the trigger for Windows extended paths', () => {
    const extendedPath = '\\\\?\\C:\\Users\\Person\\Documents\\Acme workspace';

    render(<DirSwitcher className="" workingDir={extendedPath} />, {
      wrapper: IntlTestWrapper,
    });

    expect(screen.getByRole('button', { name: 'Acme workspace' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Acme workspace' })).toHaveClass(
      'h-8',
      'rounded-lg',
      'px-2'
    );
    expect(normalizeWorkspacePathForDisplay(extendedPath)).toBe(
      'C:\\Users\\Person\\Documents\\Acme workspace'
    );
    expect(splitDirPath(extendedPath)).toEqual({
      name: 'Acme workspace',
      parent: 'C:\\Users\\Person\\Documents',
    });
  });

  it('turns extended UNC paths into readable network paths', () => {
    expect(normalizeWorkspacePathForDisplay('\\\\?\\UNC\\server\\share\\project')).toBe(
      '\\\\server\\share\\project'
    );
  });
});
