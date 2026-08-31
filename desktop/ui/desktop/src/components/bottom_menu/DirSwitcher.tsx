// Modified by AccordLock contributors; see UPSTREAM.md.
import React, { useState } from 'react';
import { Check, FolderDot, FolderOpen, Plus } from 'lucide-react';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '../ui/Tooltip';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '../ui/dropdown-menu';
import { toast } from 'react-toastify';
import { defineMessages, useIntl } from '../../i18n';

const i18n = defineMessages({
  failedToOpenSecureWorkspace: {
    id: 'dirSwitcher.failedToOpenSecureWorkspace',
    defaultMessage: 'Failed to open the workspace in a new window',
  },
  currentDirectory: {
    id: 'dirSwitcher.currentDirectory',
    defaultMessage: 'Current directory',
  },
  openWorkspaceInNewWindow: {
    id: 'dirSwitcher.openWorkspaceInNewWindow',
    defaultMessage: 'Open workspace in a new window…',
  },
  openInFinder: {
    id: 'dirSwitcher.openInFinder',
    defaultMessage: 'Open in file manager',
  },
});

export const normalizeWorkspacePathForDisplay = (dir: string): string => {
  const trimmed = dir.replace(/[\\/]+$/, '');
  const extendedUncPrefix = '\\\\?\\UNC\\';
  const extendedPrefix = '\\\\?\\';

  if (trimmed.toLocaleLowerCase().startsWith(extendedUncPrefix.toLocaleLowerCase())) {
    return `\\\\${trimmed.slice(extendedUncPrefix.length)}`;
  }

  if (trimmed.startsWith(extendedPrefix)) {
    return trimmed.slice(extendedPrefix.length);
  }

  return trimmed;
};

export const splitDirPath = (dir: string): { name: string; parent: string } => {
  const normalized = normalizeWorkspacePathForDisplay(dir);
  const parts = normalized.split(/[\\/]/);
  const name = parts.pop() || dir;
  const parent = parts.join(normalized.includes('\\') ? '\\' : '/');
  return { name, parent };
};

const DirNameLabel: React.FC<{ dir: string }> = ({ dir }) => {
  const { name, parent } = splitDirPath(dir);
  return (
    <div className="flex flex-col min-w-0 flex-1">
      <span className="truncate text-sm text-text-primary">{name}</span>
      {parent && <span className="truncate text-xs text-text-secondary/70">{parent}</span>}
    </div>
  );
};

interface DirSwitcherProps {
  className: string;
  workingDir: string;
}

export const DirSwitcher: React.FC<DirSwitcherProps> = ({ className, workingDir }) => {
  const intl = useIntl();
  const [isTooltipOpen, setIsTooltipOpen] = useState(false);
  const [isDirectoryChooserOpen, setIsDirectoryChooserOpen] = useState(false);
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const displayPath = normalizeWorkspacePathForDisplay(workingDir);
  const workspaceName = splitDirPath(workingDir).name;

  const handleDirectoryChange = async () => {
    if (isDirectoryChooserOpen) return;
    setIsDirectoryChooserOpen(true);

    try {
      const result = await window.electron.openSecureWorkspaceWindow();
      if (!result.opened && !result.canceled) {
        toast.error(intl.formatMessage(i18n.failedToOpenSecureWorkspace));
      }
    } catch (error) {
      console.error('[DirSwitcher] Failed to select a workspace:', error);
      toast.error(intl.formatMessage(i18n.failedToOpenSecureWorkspace));
    } finally {
      setIsDirectoryChooserOpen(false);
    }
  };

  const handleDirectoryClick = async (event: React.MouseEvent) => {
    if (isDirectoryChooserOpen) {
      event.preventDefault();
      event.stopPropagation();
      return;
    }

    const isCmdOrCtrlClick = event.metaKey || event.ctrlKey;

    if (isCmdOrCtrlClick) {
      event.preventDefault();
      event.stopPropagation();
      await window.electron.openDirectoryInExplorer();
    }
  };

  return (
    <TooltipProvider>
      <Tooltip
        open={isTooltipOpen && !isDirectoryChooserOpen && !isMenuOpen}
        onOpenChange={(open) => {
          if (!isDirectoryChooserOpen && !isMenuOpen) setIsTooltipOpen(open);
        }}
      >
        <DropdownMenu open={isMenuOpen} onOpenChange={setIsMenuOpen}>
          <TooltipTrigger asChild>
            <DropdownMenuTrigger asChild>
              <button
                type="button"
                className={`z-[100] flex h-8 min-w-0 max-w-[220px] items-center overflow-hidden rounded-lg bg-background-secondary/55 px-2 text-xs text-text-primary/75 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-border-secondary [&>svg]:size-4 ${isDirectoryChooserOpen ? 'opacity-50' : 'hover:cursor-pointer hover:bg-background-tertiary hover:text-text-primary'} ${className}`}
                onClick={handleDirectoryClick}
                disabled={isDirectoryChooserOpen}
              >
                <FolderDot className="mr-1.5 shrink-0" size={16} />
                <div className="min-w-0 max-w-[200px] truncate">{workspaceName}</div>
              </button>
            </DropdownMenuTrigger>
          </TooltipTrigger>
          <DropdownMenuContent className="w-[28rem]" side="top" align="start">
            <DropdownMenuLabel>{intl.formatMessage(i18n.currentDirectory)}</DropdownMenuLabel>
            <DropdownMenuItem onSelect={() => void window.electron.openDirectoryInExplorer()}>
              <FolderOpen className="mr-2 h-4 w-4 flex-shrink-0" />
              <DirNameLabel dir={workingDir} />
              <Check className="ml-auto h-4 w-4 flex-shrink-0" />
            </DropdownMenuItem>

            <DropdownMenuSeparator />
            <DropdownMenuItem onSelect={() => void handleDirectoryChange()}>
              <Plus className="mr-2 h-4 w-4" />
              <span>{intl.formatMessage(i18n.openWorkspaceInNewWindow)}</span>
            </DropdownMenuItem>
            <DropdownMenuItem onSelect={() => void window.electron.openDirectoryInExplorer()}>
              <FolderOpen className="mr-2 h-4 w-4" />
              <span>{intl.formatMessage(i18n.openInFinder)}</span>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
        <TooltipContent side="top">{displayPath}</TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
};
