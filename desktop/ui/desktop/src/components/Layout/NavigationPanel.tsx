import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useLocation } from 'react-router';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { motion } from 'framer-motion';
import { useNavigationContext } from './NavigationContext';
import { useConfig } from '../ConfigContext';
import { useNavigationSessions } from '../../hooks/useNavigationSessions';
import {
  NAV_ITEMS,
  SETTINGS_NAV_ITEM,
  getNavItemLabel,
  type NavItem,
} from '../../hooks/useNavigationItems';
import { AppEvents } from '../../constants/events';
import { InlineEditText } from '../common/InlineEditText';
import { SessionIndicators } from '../SessionIndicators';
import { acpRenameSession, type SessionListItem } from '../../acp/sessions';
import { Tooltip, TooltipContent, TooltipTrigger } from '../ui/Tooltip';
import { formatMessageTimestamp } from '../../utils/timeUtils';
import { cn } from '../../utils';
import type { ProjectGroup } from '../../utils/projectSessions';
import { defineMessages, useIntl } from '../../i18n';
import { AccordLockWordmark } from '../accordlock/AccordLockBrand';
import { normalizeWorkspacePathForDisplay } from '../bottom_menu/DirSwitcher';
import { useApprovalInbox } from '../../accordlock/approvalInboxStore';

type StreamState = 'idle' | 'loading' | 'streaming' | 'error';

interface SessionStatus {
  streamState: StreamState;
  hasUnreadActivity: boolean;
}

const i18n = defineMessages({
  activity: {
    id: 'navigationPanel.activity',
    defaultMessage: 'Recent',
  },
  noActivity: {
    id: 'navigationPanel.noActivity',
    defaultMessage: 'No recent tasks yet',
  },
  untitledSession: {
    id: 'navigationPanel.untitledSession',
    defaultMessage: 'Untitled task',
  },
  metaModel: {
    id: 'navigationPanel.metaModel',
    defaultMessage: 'Model',
  },
  metaDirectory: {
    id: 'navigationPanel.metaDirectory',
    defaultMessage: 'Workspace',
  },
  metaStatus: {
    id: 'navigationPanel.metaStatus',
    defaultMessage: 'Status',
  },
  metaCreated: {
    id: 'navigationPanel.metaCreated',
    defaultMessage: 'Created',
  },
  metaUpdated: {
    id: 'navigationPanel.metaUpdated',
    defaultMessage: 'Updated',
  },
  statusStreaming: {
    id: 'navigationPanel.statusStreaming',
    defaultMessage: 'Working',
  },
  statusError: {
    id: 'navigationPanel.statusError',
    defaultMessage: 'Needs attention',
  },
  statusUnread: {
    id: 'navigationPanel.statusUnread',
    defaultMessage: 'Ready for review',
  },
  statusIdle: {
    id: 'navigationPanel.statusIdle',
    defaultMessage: 'Ready',
  },
});

const navItemClass = (active: boolean) =>
  cn(
    'flex flex-row items-center gap-3 outline-none no-drag w-full',
    'min-h-10 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
    active
      ? 'bg-background-tertiary text-text-primary'
      : 'text-text-secondary hover:bg-background-tertiary/60 hover:text-text-primary'
  );

interface NavRowProps {
  item: NavItem;
  active: boolean;
  onClick: () => void;
  tag?: string;
}

const NavRow: React.FC<NavRowProps> = ({ item, active, onClick, tag }) => {
  const intl = useIntl();
  const Icon = item.icon;
  const visibleTag = tag ?? item.getTag?.();
  return (
    <button onClick={onClick} className={navItemClass(active)}>
      <Icon className="w-5 h-5 flex-shrink-0 text-text-secondary" />
      <span className="text-left flex-1 truncate">{getNavItemLabel(item, intl)}</span>
      {visibleTag && (
        <span
          className="min-w-5 rounded-full bg-background-primary px-1.5 text-center text-[11px] font-medium text-text-secondary"
          aria-label={`${visibleTag} pending approval${visibleTag === '1' ? '' : 's'}`}
        >
          {visibleTag}
        </span>
      )}
    </button>
  );
};

interface SessionRowProps {
  session: SessionListItem;
  active: boolean;
  status: SessionStatus | undefined;
  onClick: () => void;
  onRenamed: () => void;
}

const formatTimestamp = (value?: string): string | null => {
  if (!value) return null;
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return null;
  return formatMessageTimestamp(parsed / 1000);
};

const MetaRow: React.FC<{ label: string; value: string }> = ({ label, value }) => (
  <div className="flex gap-2">
    <span className="text-text-inverse/60 flex-shrink-0">{label}</span>
    <span className="text-right ml-auto break-all">{value}</span>
  </div>
);

interface SessionTooltipContentProps {
  session: SessionListItem;
  statusLabel: string;
}

const SessionTooltipContent: React.FC<SessionTooltipContentProps> = ({ session, statusLabel }) => {
  const intl = useIntl();
  const model = session.modelId
    ? session.providerId
      ? `${session.modelId} (${session.providerId})`
      : session.modelId
    : session.providerId;
  const created = formatTimestamp(session.createdAt);
  const updated = formatTimestamp(session.lastMessageAt ?? session.updatedAt);

  return (
    <div className="flex flex-col gap-1 text-xs">
      <div className="font-medium break-words">
        {session.name || intl.formatMessage(i18n.untitledSession)}
      </div>
      <div className="flex flex-col gap-0.5">
        {model && <MetaRow label={intl.formatMessage(i18n.metaModel)} value={model} />}
        {session.workingDir && (
          <MetaRow
            label={intl.formatMessage(i18n.metaDirectory)}
            value={normalizeWorkspacePathForDisplay(session.workingDir)}
          />
        )}
        <MetaRow label={intl.formatMessage(i18n.metaStatus)} value={statusLabel} />
        {created && <MetaRow label={intl.formatMessage(i18n.metaCreated)} value={created} />}
        {updated && <MetaRow label={intl.formatMessage(i18n.metaUpdated)} value={updated} />}
      </div>
    </div>
  );
};

export const SessionRow: React.FC<SessionRowProps> = ({
  session,
  active,
  status,
  onClick,
  onRenamed,
}) => {
  const intl = useIntl();
  const [isEditing, setIsEditing] = useState(false);
  const [tooltipOpen, setTooltipOpen] = useState(false);
  const isStreaming = status?.streamState === 'streaming';
  const hasError = status?.streamState === 'error';
  const hasUnread = status?.hasUnreadActivity ?? false;

  const statusLabel = isStreaming
    ? intl.formatMessage(i18n.statusStreaming)
    : hasError
      ? intl.formatMessage(i18n.statusError)
      : hasUnread
        ? intl.formatMessage(i18n.statusUnread)
        : intl.formatMessage(i18n.statusIdle);

  const handleRowKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (isEditing || event.target !== event.currentTarget || event.repeat) return;
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      onClick();
    }
  };

  return (
    <Tooltip open={tooltipOpen && !isEditing} onOpenChange={setTooltipOpen} delayDuration={400}>
      <TooltipTrigger asChild>
        <div
          role={isEditing ? undefined : 'button'}
          tabIndex={isEditing ? -1 : 0}
          aria-current={!isEditing && active ? 'page' : undefined}
          onClick={() => !isEditing && onClick()}
          onKeyDown={handleRowKeyDown}
          className={cn(
            'group flex min-h-9 items-center gap-2 rounded-lg px-3 py-1.5 text-sm cursor-pointer',
            'outline-none transition-colors hover:bg-background-tertiary/60',
            'focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1',
            active && 'bg-background-tertiary'
          )}
        >
          <InlineEditText
            value={session.name}
            onSave={async (newName) => {
              await acpRenameSession(session.id, newName);
              window.dispatchEvent(
                new CustomEvent(AppEvents.SESSION_RENAMED, {
                  detail: { sessionId: session.id, newName, userInitiated: true },
                })
              );
              onRenamed();
            }}
            placeholder={intl.formatMessage(i18n.untitledSession)}
            disabled={isStreaming}
            singleClickEdit={false}
            className={cn(
              'flex-1 truncate !px-0 !py-0 hover:bg-transparent group-hover:text-text-primary',
              active ? 'text-text-primary' : 'text-text-secondary'
            )}
            editClassName="!text-sm"
            onEditStart={() => setIsEditing(true)}
            onEditEnd={() => setIsEditing(false)}
          />
          <SessionIndicators isStreaming={isStreaming} hasUnread={hasUnread} hasError={hasError} />
        </div>
      </TooltipTrigger>
      <TooltipContent side="right" align="start" className="max-w-xs text-left">
        <SessionTooltipContent session={session} statusLabel={statusLabel} />
      </TooltipContent>
    </Tooltip>
  );
};

export const Navigation: React.FC<{ className?: string }> = ({ className }) => {
  const intl = useIntl();
  const { isNavExpanded } = useNavigationContext();
  const location = useLocation();
  const { extensionsList } = useConfig();
  const approvalItems = useApprovalInbox();
  const pendingApprovalCount = approvalItems.filter((item) => item.status === 'PENDING').length;

  const appsExtensionEnabled = !!extensionsList?.find((ext) => ext.name === 'apps')?.enabled;

  const visibleItems = useMemo<NavItem[]>(() => {
    return NAV_ITEMS.filter((item) => {
      if (item.path === '/apps') return appsExtensionEnabled;
      return true;
    });
  }, [appsExtensionEnabled]);

  const isActive = useCallback((path: string) => location.pathname === path, [location.pathname]);

  const {
    recentSessions,
    recentSessionsByProject,
    activeSessionId,
    fetchSessions,
    handleNavClick,
    handleSessionClick,
  } = useNavigationSessions();

  const [sessionStatuses, setSessionStatuses] = useState<Map<string, SessionStatus>>(new Map());

  useEffect(() => {
    const handleStatusUpdate = (event: Event) => {
      const { sessionId, streamState } = (event as CustomEvent).detail;
      setSessionStatuses((prev) => {
        const existing = prev.get(sessionId);
        const shouldMarkUnread = existing?.streamState === 'streaming' && streamState === 'idle';
        const next = new Map(prev);
        next.set(sessionId, {
          streamState,
          hasUnreadActivity: existing?.hasUnreadActivity || shouldMarkUnread,
        });
        return next;
      });
    };

    window.addEventListener(AppEvents.SESSION_STATUS_UPDATE, handleStatusUpdate);
    return () => window.removeEventListener(AppEvents.SESSION_STATUS_UPDATE, handleStatusUpdate);
  }, []);

  const clearUnread = useCallback((sessionId: string) => {
    setSessionStatuses((prev) => {
      const status = prev.get(sessionId);
      if (status?.hasUnreadActivity) {
        const next = new Map(prev);
        next.set(sessionId, { ...status, hasUnreadActivity: false });
        return next;
      }
      return prev;
    });
  }, []);

  const navFocusRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (isNavExpanded) {
      fetchSessions();
      requestAnimationFrame(() => navFocusRef.current?.focus());
    }
  }, [isNavExpanded, fetchSessions]);

  const [collapsedProjects, setCollapsedProjects] = useState<Set<string>>(new Set());
  const showProjectGroups =
    recentSessionsByProject.length > 1 || recentSessions.some((session) => session.projectId);

  const toggleProjectCollapsed = useCallback((path: string) => {
    setCollapsedProjects((prev) => {
      const next = new Set(prev);
      if (next.has(path)) {
        next.delete(path);
      } else {
        next.add(path);
      }
      return next;
    });
  }, []);

  if (!isNavExpanded) return null;

  return (
    <motion.div
      ref={navFocusRef}
      tabIndex={-1}
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.15 }}
      className={cn('flex h-full flex-col bg-background-secondary outline-none', className)}
    >
      <div className="h-[48px] no-drag" />

      <div className="px-4 pb-5">
        <AccordLockWordmark />
      </div>

      <div className="px-2 flex flex-col gap-0.5">
        {visibleItems.map((item) => (
          <NavRow
            key={item.id}
            item={item}
            active={isActive(item.path)}
            onClick={() => handleNavClick(item.path)}
            tag={
              item.id === 'approvals' && pendingApprovalCount > 0
                ? pendingApprovalCount > 99
                  ? '99+'
                  : String(pendingApprovalCount)
                : undefined
            }
          />
        ))}
      </div>

      <div className="mt-4 flex min-h-0 flex-1 flex-col">
        <div className="px-4 pb-1.5 text-xs font-medium text-text-tertiary">
          {intl.formatMessage(i18n.activity)}
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto px-2 pb-2">
          {recentSessions.length === 0 ? (
            <div className="px-3 py-2 text-xs leading-5 text-text-tertiary">
              {intl.formatMessage(i18n.noActivity)}
            </div>
          ) : showProjectGroups ? (
            recentSessionsByProject.map((group: ProjectGroup) => {
              const isCollapsed = collapsedProjects.has(group.path);
              return (
                <React.Fragment key={group.path}>
                  <button
                    onClick={() => toggleProjectCollapsed(group.path)}
                    aria-expanded={!isCollapsed}
                    className="flex w-full items-center gap-1 px-3 pb-0.5 pt-2 text-[11px] font-medium text-text-tertiary transition-colors hover:text-text-secondary"
                    title={group.projectId ? group.label : group.path}
                  >
                    {isCollapsed ? (
                      <ChevronRight className="w-3 h-3 flex-shrink-0" />
                    ) : (
                      <ChevronDown className="w-3 h-3 flex-shrink-0" />
                    )}
                    <span className="truncate">{group.label}</span>
                  </button>
                  {!isCollapsed &&
                    group.sessions.map((session) => (
                      <SessionRow
                        key={session.id}
                        session={session}
                        active={session.id === activeSessionId}
                        status={sessionStatuses.get(session.id)}
                        onClick={() => {
                          clearUnread(session.id);
                          handleSessionClick(session.id);
                        }}
                        onRenamed={fetchSessions}
                      />
                    ))}
                </React.Fragment>
              );
            })
          ) : (
            recentSessions.map((session) => (
              <SessionRow
                key={session.id}
                session={session}
                active={session.id === activeSessionId}
                status={sessionStatuses.get(session.id)}
                onClick={() => {
                  clearUnread(session.id);
                  handleSessionClick(session.id);
                }}
                onRenamed={fetchSessions}
              />
            ))
          )}
        </div>
      </div>

      <div className="px-2 pt-2 pb-2 border-t border-border-secondary">
        <NavRow
          item={SETTINGS_NAV_ITEM}
          active={isActive(SETTINGS_NAV_ITEM.path)}
          onClick={() => handleNavClick(SETTINGS_NAV_ITEM.path)}
        />
      </div>
    </motion.div>
  );
};
