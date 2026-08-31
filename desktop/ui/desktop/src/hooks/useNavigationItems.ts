// Modified by AccordLock contributors; see UPSTREAM.md.
import {
  FileClock,
  FileText,
  FolderKanban,
  ListChecks,
  ListTodo,
  MessageSquarePlus,
  Settings,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { defineMessages, type IntlShape, type MessageDescriptor } from 'react-intl';

export interface NavItem {
  id: string;
  path: string;
  label: string;
  icon: LucideIcon;
  getTag?: () => string;
  tagAlign?: 'left' | 'right';
}

/** Top-level nav items (excluding Settings which is pinned to the bottom). */
export const NAV_ITEMS: NavItem[] = [
  { id: 'home', path: '/', label: 'New task', icon: MessageSquarePlus },
  { id: 'approvals', path: '/approvals', label: 'Approvals', icon: ListChecks },
  { id: 'projects', path: '/projects', label: 'Projects', icon: FolderKanban },
  { id: 'sessions', path: '/sessions', label: 'Tasks', icon: ListTodo },
  { id: 'audit', path: '/audit', label: 'Audit', icon: FileClock },
  { id: 'recipes', path: '/recipes', label: 'Playbooks', icon: FileText },
];

/** Settings is rendered separately, pinned to the bottom of the sidebar. */
export const SETTINGS_NAV_ITEM: NavItem = {
  id: 'settings',
  path: '/settings',
  label: 'Settings',
  icon: Settings,
};

// Translation descriptors for nav labels. Kept here next to NAV_ITEMS so the two
// stay in sync.
const navItemMessages = defineMessages({
  home: {
    id: 'navigation.itemHome',
    defaultMessage: 'New task',
  },
  approvals: {
    id: 'navigation.itemApprovals',
    defaultMessage: 'Approvals',
  },
  recipes: {
    id: 'navigation.itemRecipes',
    defaultMessage: 'Playbooks',
  },
  projects: {
    id: 'navigation.itemProjects',
    defaultMessage: 'Projects',
  },
  sessions: {
    id: 'navigation.itemSessions',
    defaultMessage: 'Tasks',
  },
  audit: {
    id: 'navigation.itemAudit',
    defaultMessage: 'Audit',
  },
  settings: {
    id: 'navigation.itemSettings',
    defaultMessage: 'Settings',
  },
});

const NAV_ITEM_MESSAGES: Record<string, MessageDescriptor> = navItemMessages;

/** Format a NavItem's label using the provided intl instance, falling back to `item.label`. */
export function getNavItemLabel(item: NavItem, intl: IntlShape): string {
  const descriptor = NAV_ITEM_MESSAGES[item.id];
  return descriptor ? intl.formatMessage(descriptor) : item.label;
}
