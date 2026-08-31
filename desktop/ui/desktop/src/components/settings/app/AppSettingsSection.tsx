// Modified by AccordLock contributors; see UPSTREAM.md.
import { useState, useEffect, useRef } from 'react';
import { defineMessages, useIntl } from '../../../i18n';
import { Switch } from '../../ui/switch';
import { Button } from '../../ui/button';
import { Settings } from 'lucide-react';
import UpdateSection from './UpdateSection';

import { COST_TRACKING_ENABLED, UPDATES_ENABLED } from '../../../updates';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../ui/card';
import ThemeSelector from '../../GooseSidebar/ThemeSelector';
import TelemetrySettings from './TelemetrySettings';
import { trackSettingToggled } from '../../../utils/analytics';
import { AccordLockWordmark } from '../../accordlock/AccordLockBrand';

const i18n = defineMessages({
  generalTitle: { id: 'settings.general.title', defaultMessage: 'General' },
  generalDesc: {
    id: 'settings.general.description',
    defaultMessage: 'Window and task behavior.',
  },
  notifications: { id: 'settings.notifications.title', defaultMessage: 'Notifications' },
  notificationsCardDesc: {
    id: 'settings.notifications.cardDescription',
    defaultMessage: 'Choose when AccordLock alerts you.',
  },
  notificationsDesc: {
    id: 'settings.notifications.description',
    defaultMessage: 'Allow AccordLock notifications in your system settings.',
  },
  notificationPermissions: {
    id: 'settings.notifications.permissions.title',
    defaultMessage: 'Notification permissions',
  },
  openSettings: { id: 'settings.notifications.openSettings', defaultMessage: 'Open Settings' },
  taskNotifications: {
    id: 'settings.notifications.task.title',
    defaultMessage: 'Task notifications',
  },
  taskNotificationsDesc: {
    id: 'settings.notifications.task.description',
    defaultMessage: 'Notify me when a task needs attention or finishes.',
  },
  menuBarIcon: { id: 'settings.menuBarIcon.title', defaultMessage: 'Background access' },
  menuBarIconDesc: {
    id: 'settings.menuBarIcon.description',
    defaultMessage: 'Keep AccordLock available from the system tray or menu bar.',
  },
  dockIcon: { id: 'settings.dockIcon.title', defaultMessage: 'Dock icon' },
  dockIconDesc: {
    id: 'settings.dockIcon.description',
    defaultMessage: 'Show AccordLock in the dock',
  },
  preventSleep: { id: 'settings.preventSleep.title', defaultMessage: 'Keep awake' },
  preventSleepDesc: {
    id: 'settings.preventSleep.description',
    defaultMessage: 'Keep the computer awake while a task runs.',
  },
  costTracking: { id: 'settings.costTracking.title', defaultMessage: 'Show costs' },
  costTrackingDesc: {
    id: 'settings.costTracking.description',
    defaultMessage: 'Show model usage costs.',
  },
  themeTitle: { id: 'settings.theme.title', defaultMessage: 'Theme' },
  themeDesc: {
    id: 'settings.theme.description',
    defaultMessage: 'Light, dark, or system theme.',
  },
  versionTitle: { id: 'settings.version.title', defaultMessage: 'Version' },
  updatesTitle: { id: 'settings.updates.title', defaultMessage: 'Updates' },
  updatesDesc: {
    id: 'settings.updates.description',
    defaultMessage: 'Check for and install AccordLock updates',
  },
});

interface AppSettingsSectionProps {
  scrollToSection?: string;
}

export default function AppSettingsSection({ scrollToSection }: AppSettingsSectionProps) {
  const [menuBarIconEnabled, setMenuBarIconEnabled] = useState(true);
  const [dockIconEnabled, setDockIconEnabled] = useState(true);
  const [wakelockEnabled, setWakelockEnabled] = useState(true);
  const [notificationsEnabled, setNotificationsEnabled] = useState(true);
  const [isMacOS, setIsMacOS] = useState(false);
  const [isDockSwitchDisabled, setIsDockSwitchDisabled] = useState(false);
  const [showPricing, setShowPricing] = useState(true);
  const updateSectionRef = useRef<HTMLDivElement>(null);
  const shouldShowUpdates = !window.appConfig.get('GOOSE_VERSION');

  useEffect(() => {
    setIsMacOS(window.electron.platform === 'darwin');
  }, []);

  useEffect(() => {
    window.electron.getSetting('showPricing').then(setShowPricing);
  }, []);

  useEffect(() => {
    if (scrollToSection === 'update' && updateSectionRef.current) {
      setTimeout(() => {
        updateSectionRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }, 100);
    }
  }, [scrollToSection]);

  useEffect(() => {
    window.electron.getMenuBarIconState().then((enabled) => {
      setMenuBarIconEnabled(enabled);
    });

    window.electron.getWakelockState().then((enabled) => {
      setWakelockEnabled(enabled);
    });

    window.electron.getSetting('enableNotifications').then((enabled) => {
      setNotificationsEnabled(enabled ?? true);
    });

    if (isMacOS) {
      window.electron.getDockIconState().then((enabled) => {
        setDockIconEnabled(enabled);
      });
    }
  }, [isMacOS]);

  const handleMenuBarIconToggle = async () => {
    const newState = !menuBarIconEnabled;
    // If we're turning off the menu bar icon and the dock icon is hidden,
    // we need to show the dock icon to maintain accessibility
    if (!newState && !dockIconEnabled && isMacOS) {
      const success = await window.electron.setDockIcon(true);
      if (success) {
        setDockIconEnabled(true);
      }
    }
    const success = await window.electron.setMenuBarIcon(newState);
    if (success) {
      setMenuBarIconEnabled(newState);
      trackSettingToggled('menu_bar_icon', newState);
    }
  };

  const handleDockIconToggle = async () => {
    const newState = !dockIconEnabled;
    // If we're turning off the dock icon and the menu bar icon is hidden,
    // we need to show the menu bar icon to maintain accessibility
    if (!newState && !menuBarIconEnabled) {
      const success = await window.electron.setMenuBarIcon(true);
      if (success) {
        setMenuBarIconEnabled(true);
      }
    }

    // Disable the switch to prevent rapid toggling
    setIsDockSwitchDisabled(true);
    setTimeout(() => {
      setIsDockSwitchDisabled(false);
    }, 1000);

    // Set the dock icon state
    const success = await window.electron.setDockIcon(newState);
    if (success) {
      setDockIconEnabled(newState);
      trackSettingToggled('dock_icon', newState);
    }
  };

  const handleWakelockToggle = async () => {
    const newState = !wakelockEnabled;
    const success = await window.electron.setWakelock(newState);
    if (success) {
      setWakelockEnabled(newState);
      trackSettingToggled('prevent_sleep', newState);
    }
  };

  const handleNotificationsToggle = async (checked: boolean) => {
    setNotificationsEnabled(checked);
    await window.electron.setSetting('enableNotifications', checked);
    trackSettingToggled('task_notifications', checked);
  };

  const handleShowPricingToggle = async (checked: boolean) => {
    setShowPricing(checked);
    await window.electron.setSetting('showPricing', checked);
    trackSettingToggled('cost_tracking', checked);
    // Trigger event for other components
    window.dispatchEvent(new CustomEvent('showPricingChanged'));
  };

  const intl = useIntl();

  return (
    <div className="space-y-4 pr-4 pb-8 mt-1">
      <Card className="rounded-lg">
        <CardHeader className="pb-0">
          <CardTitle>{intl.formatMessage(i18n.notifications)}</CardTitle>
          <CardDescription>{intl.formatMessage(i18n.notificationsCardDesc)}</CardDescription>
        </CardHeader>
        <CardContent className="pt-4 space-y-4 px-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-text-primary text-xs">
                {intl.formatMessage(i18n.notificationPermissions)}
              </h3>
              <p className="text-xs text-text-secondary max-w-md mt-[2px]">
                {intl.formatMessage(i18n.notificationsDesc)}
              </p>
            </div>
            <div className="flex items-center">
              <Button
                className="flex items-center gap-2 justify-center"
                variant="secondary"
                size="sm"
                onClick={async () => {
                  try {
                    await window.electron.openNotificationsSettings();
                  } catch (error) {
                    console.error('Failed to open notification settings:', error);
                  }
                }}
              >
                <Settings />
                {intl.formatMessage(i18n.openSettings)}
              </Button>
            </div>
          </div>

          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-text-primary text-xs">
                {intl.formatMessage(i18n.taskNotifications)}
              </h3>
              <p className="text-xs text-text-secondary max-w-md mt-[2px]">
                {intl.formatMessage(i18n.taskNotificationsDesc)}
              </p>
            </div>
            <div className="flex items-center">
              <Switch
                checked={notificationsEnabled}
                onCheckedChange={handleNotificationsToggle}
                variant="mono"
              />
            </div>
          </div>
        </CardContent>
      </Card>

      <Card className="rounded-lg">
        <CardHeader className="pb-0">
          <CardTitle>{intl.formatMessage(i18n.generalTitle)}</CardTitle>
          <CardDescription>{intl.formatMessage(i18n.generalDesc)}</CardDescription>
        </CardHeader>
        <CardContent className="pt-4 space-y-4 px-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-text-primary text-xs">{intl.formatMessage(i18n.menuBarIcon)}</h3>
              <p className="text-xs text-text-secondary max-w-md mt-[2px]">
                {intl.formatMessage(i18n.menuBarIconDesc)}
              </p>
            </div>
            <div className="flex items-center">
              <Switch
                checked={menuBarIconEnabled}
                onCheckedChange={handleMenuBarIconToggle}
                variant="mono"
              />
            </div>
          </div>

          {isMacOS && (
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-text-primary text-xs">{intl.formatMessage(i18n.dockIcon)}</h3>
                <p className="text-xs text-text-secondary max-w-md mt-[2px]">
                  {intl.formatMessage(i18n.dockIconDesc)}
                </p>
              </div>
              <div className="flex items-center">
                <Switch
                  disabled={isDockSwitchDisabled}
                  checked={dockIconEnabled}
                  onCheckedChange={handleDockIconToggle}
                  variant="mono"
                />
              </div>
            </div>
          )}

          {/* Keep awake */}
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-text-primary text-xs">{intl.formatMessage(i18n.preventSleep)}</h3>
              <p className="text-xs text-text-secondary max-w-md mt-[2px]">
                {intl.formatMessage(i18n.preventSleepDesc)}
              </p>
            </div>
            <div className="flex items-center">
              <Switch
                checked={wakelockEnabled}
                onCheckedChange={handleWakelockToggle}
                variant="mono"
              />
            </div>
          </div>

          {/* Show costs */}
          {COST_TRACKING_ENABLED && (
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-text-primary">{intl.formatMessage(i18n.costTracking)}</h3>
                <p className="text-xs text-text-secondary max-w-md mt-[2px]">
                  {intl.formatMessage(i18n.costTrackingDesc)}
                </p>
              </div>
              <div className="flex items-center">
                <Switch
                  checked={showPricing}
                  onCheckedChange={handleShowPricingToggle}
                  variant="mono"
                />
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <Card className="rounded-lg">
        <CardHeader className="pb-0">
          <CardTitle className="mb-1">{intl.formatMessage(i18n.themeTitle)}</CardTitle>
          <CardDescription>{intl.formatMessage(i18n.themeDesc)}</CardDescription>
        </CardHeader>
        <CardContent className="pt-4 px-4">
          <ThemeSelector className="w-auto" hideTitle horizontal />
        </CardContent>
      </Card>

      <TelemetrySettings />

      {/* Version Section - only show if GOOSE_VERSION is set */}
      {!shouldShowUpdates && (
        <Card className="rounded-lg">
          <CardHeader className="pb-0">
            <CardTitle className="mb-1">{intl.formatMessage(i18n.versionTitle)}</CardTitle>
          </CardHeader>
          <CardContent className="pt-4 px-4">
            <div className="flex items-center gap-3">
              <AccordLockWordmark subtitle="Desktop" />
              <span className="text-2xl font-mono text-black dark:text-white">
                {String(window.appConfig.get('GOOSE_VERSION') || 'Development')}
              </span>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Update Section - only show if GOOSE_VERSION is NOT set */}
      {UPDATES_ENABLED && shouldShowUpdates && (
        <div ref={updateSectionRef}>
          <Card className="rounded-lg">
            <CardHeader className="pb-0">
              <CardTitle className="mb-1">{intl.formatMessage(i18n.updatesTitle)}</CardTitle>
              <CardDescription>{intl.formatMessage(i18n.updatesDesc)}</CardDescription>
            </CardHeader>
            <CardContent className="px-4">
              <UpdateSection />
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
