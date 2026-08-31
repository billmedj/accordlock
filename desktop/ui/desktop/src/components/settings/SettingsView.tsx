// Modified by AccordLock contributors; see UPSTREAM.md.
import { ScrollArea } from '../ui/scroll-area';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../ui/tabs';
import { View, ViewOptions } from '../../utils/navigationUtils';
import ModelsSection from './models/ModelsSection';
import AppSettingsSection from './app/AppSettingsSection';
import TerminalProgramsSettings from './app/TerminalProgramsSettings';
import type { ExtensionConfig } from '../../types/extensions';
import { MainPanelLayout } from '../Layout/MainPanelLayout';
import {
  Bot,
  BellRing,
  ChevronDown,
  Globe2,
  Keyboard,
  PlugZap,
  ShieldCheck,
  Settings2,
  SquareTerminal,
} from 'lucide-react';
import { useState, useEffect, useRef } from 'react';
import ChatSettingsSection from './chat/ChatSettingsSection';
import KeyboardShortcutsSection from './keyboard/KeyboardShortcutsSection';
import AuthSettingsSection from './auth/AuthSettingsSection';
import LocalInferenceSection from './localInference/LocalInferenceSection';
import { trackSettingsTabViewed } from '../../utils/analytics';
import { useFeatures } from '../../contexts/FeaturesContext';
import { defineMessages, useIntl } from '../../i18n';
import { Card, CardContent } from '../ui/card';
import { Button } from '../ui/button';
import ApprovalChannelsSettings from './app/ApprovalChannelsSettings';
import EnvironmentConnectionsSettings from './connections/EnvironmentConnectionsSettings';
import NetworkAccessSettings from './app/NetworkAccessSettings';

const i18n = defineMessages({
  title: {
    id: 'settingsView.title',
    defaultMessage: 'Settings',
  },
  tabModels: {
    id: 'settingsView.tabModels',
    defaultMessage: 'Models',
  },
  tabNotifications: {
    id: 'settingsView.tabNotifications',
    defaultMessage: 'Notifications',
  },
  tabConnections: {
    id: 'settingsView.tabConnections',
    defaultMessage: 'Connections',
  },
  tabSecurity: {
    id: 'settingsView.tabSecurity',
    defaultMessage: 'Security',
  },
  tabApp: {
    id: 'settingsView.tabApp',
    defaultMessage: 'App',
  },
  keyboardShortcutsTitle: {
    id: 'settingsView.keyboardShortcutsTitle',
    defaultMessage: 'Keyboard shortcuts',
  },
  keyboardShortcutsDescription: {
    id: 'settingsView.keyboardShortcutsDescription',
    defaultMessage: 'Customize shortcuts for common actions.',
  },
  keyboardShortcutsShow: {
    id: 'settingsView.keyboardShortcutsShow',
    defaultMessage: 'Customize',
  },
  keyboardShortcutsHide: {
    id: 'settingsView.keyboardShortcutsHide',
    defaultMessage: 'Hide',
  },
  nativeProgramsTitle: {
    id: 'settingsView.nativeProgramsTitle',
    defaultMessage: 'Native programs',
  },
  nativeProgramsDescription: {
    id: 'settingsView.nativeProgramsDescription',
    defaultMessage: 'Allow specific local programs for terminal tasks.',
  },
  nativeProgramsShow: {
    id: 'settingsView.nativeProgramsShow',
    defaultMessage: 'Manage',
  },
  nativeProgramsHide: {
    id: 'settingsView.nativeProgramsHide',
    defaultMessage: 'Hide',
  },
  approvalAlertsTitle: {
    id: 'settingsView.approvalAlertsTitle',
    defaultMessage: 'Approval channels',
  },
  approvalAlertsDescription: {
    id: 'settingsView.approvalAlertsDescription',
    defaultMessage:
      'Send review alerts to Slack, Teams, Telegram, or WhatsApp. Pair a gateway below to approve remotely.',
  },
  networkTitle: {
    id: 'settingsView.networkTitle',
    defaultMessage: 'Network access',
  },
  networkDescription: {
    id: 'settingsView.networkDescription',
    defaultMessage:
      'Allow GET and HEAD requests to specific HTTPS domains. Each request needs approval.',
  },
  networkManage: { id: 'settingsView.networkManage', defaultMessage: 'Manage' },
  networkHide: { id: 'settingsView.networkHide', defaultMessage: 'Hide' },
});

export type SettingsViewOptions = {
  deepLinkConfig?: ExtensionConfig;
  showEnvVars?: boolean;
  section?: string;
};

export default function SettingsView({
  onClose,
  setView,
  viewOptions,
}: {
  onClose: () => void;
  setView: (view: View, viewOptions?: ViewOptions) => void;
  viewOptions: SettingsViewOptions;
}) {
  const [activeTab, setActiveTab] = useState('models');
  const [showKeyboardShortcuts, setShowKeyboardShortcuts] = useState(
    viewOptions.section === 'keyboard'
  );
  const [showNativePrograms, setShowNativePrograms] = useState(viewOptions.section === 'tools');
  const [showNetworkAccess, setShowNetworkAccess] = useState(viewOptions.section === 'network');
  const hasTrackedInitialTab = useRef(false);
  const { localInference } = useFeatures();
  const intl = useIntl();

  const handleTabChange = (tab: string) => {
    setActiveTab(tab);
    trackSettingsTabViewed(tab);
  };

  // Determine initial tab based on section prop
  useEffect(() => {
    if (viewOptions.section) {
      // Map section names to tab values
      const sectionToTab: Record<string, string> = {
        update: 'app',
        models: 'models',
        connections: 'connections',
        environments: 'connections',
        modes: 'app',
        styles: 'app',
        tools: 'security',
        network: 'security',
        app: 'app',
        chat: 'app',
        prompts: 'app',
        keyboard: 'app',
        auth: 'models',
        'local-inference': 'models',
      };

      const targetTab = sectionToTab[viewOptions.section];
      if (targetTab) {
        setActiveTab(targetTab);
      }
      if (viewOptions.section === 'keyboard') {
        setShowKeyboardShortcuts(true);
      }
      if (viewOptions.section === 'tools') {
        setShowNativePrograms(true);
      }
      if (viewOptions.section === 'network') {
        setShowNetworkAccess(true);
      }
    }
  }, [viewOptions.section]);

  useEffect(() => {
    if (!hasTrackedInitialTab.current) {
      trackSettingsTabViewed(activeTab);
      hasTrackedInitialTab.current = true;
    }
  }, [activeTab]);

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !event.defaultPrevented) {
        onClose();
      }
    };

    document.addEventListener('keydown', handleKeyDown);

    return () => {
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [onClose]);

  return (
    <>
      <MainPanelLayout>
        <div className="flex-1 flex flex-col min-h-0">
          <div className="bg-background-primary px-8 pb-8 pt-16">
            <div className="flex flex-col page-transition">
              <div className="flex justify-between items-center mb-1">
                <h1 className="text-4xl font-light">{intl.formatMessage(i18n.title)}</h1>
              </div>
            </div>
          </div>

          <div className="flex-1 min-h-0 relative px-6">
            <Tabs
              value={activeTab}
              onValueChange={handleTabChange}
              className="h-full flex flex-col"
            >
              <div className="px-1">
                <TabsList className="w-full mb-2 justify-start overflow-x-auto flex-nowrap">
                  <TabsTrigger
                    value="models"
                    className="flex gap-2"
                    data-testid="settings-models-tab"
                  >
                    <Bot className="h-4 w-4" />
                    {intl.formatMessage(i18n.tabModels)}
                  </TabsTrigger>
                  <TabsTrigger
                    value="connections"
                    className="flex gap-2"
                    data-testid="settings-connections-tab"
                  >
                    <PlugZap className="h-4 w-4" />
                    {intl.formatMessage(i18n.tabConnections)}
                  </TabsTrigger>
                  <TabsTrigger
                    value="notifications"
                    className="flex gap-2"
                    data-testid="settings-notifications-tab"
                  >
                    <BellRing className="h-4 w-4" />
                    {intl.formatMessage(i18n.tabNotifications)}
                  </TabsTrigger>
                  <TabsTrigger
                    value="security"
                    className="flex gap-2"
                    data-testid="settings-security-tab"
                  >
                    <ShieldCheck className="h-4 w-4" />
                    {intl.formatMessage(i18n.tabSecurity)}
                  </TabsTrigger>
                  <TabsTrigger value="app" className="flex gap-2" data-testid="settings-app-tab">
                    <Settings2 className="h-4 w-4" />
                    {intl.formatMessage(i18n.tabApp)}
                  </TabsTrigger>
                </TabsList>
              </div>

              <ScrollArea className="flex-1 px-2">
                <TabsContent
                  value="models"
                  className="mt-0 focus-visible:outline-none focus-visible:ring-0"
                >
                  <div className="space-y-8">
                    <ModelsSection setView={setView} />
                    <AuthSettingsSection onConnectProvider={() => setView('ConfigureProviders')} />
                    {localInference && <LocalInferenceSection />}
                  </div>
                </TabsContent>

                <TabsContent
                  value="connections"
                  className="mt-0 focus-visible:outline-none focus-visible:ring-0"
                >
                  <div className="space-y-4 pr-4 pb-8">
                    <EnvironmentConnectionsSettings />
                  </div>
                </TabsContent>

                <TabsContent
                  value="notifications"
                  className="mt-0 focus-visible:outline-none focus-visible:ring-0"
                >
                  <div className="space-y-4 pb-8">
                    <div className="space-y-4 pr-4">
                      <Card className="rounded-lg">
                        <CardContent className="px-4 py-4">
                          <div className="mb-3 flex items-start gap-3">
                            <BellRing
                              className="mt-0.5 h-4 w-4 shrink-0 text-text-secondary"
                              aria-hidden="true"
                            />
                            <div>
                              <h2 className="text-sm font-medium text-text-primary">
                                {intl.formatMessage(i18n.approvalAlertsTitle)}
                              </h2>
                              <p className="text-xs text-text-secondary">
                                {intl.formatMessage(i18n.approvalAlertsDescription)}
                              </p>
                            </div>
                          </div>
                          <ApprovalChannelsSettings />
                        </CardContent>
                      </Card>
                    </div>
                  </div>
                </TabsContent>

                <TabsContent
                  value="security"
                  className="mt-0 focus-visible:outline-none focus-visible:ring-0"
                >
                  <div className="space-y-4 pb-8">
                    <div className="space-y-4 pr-4">
                      <Card className="rounded-lg">
                        <CardContent className="flex items-center justify-between gap-4 px-4">
                          <div className="flex min-w-0 items-center gap-3">
                            <SquareTerminal
                              className="h-4 w-4 shrink-0 text-text-secondary"
                              aria-hidden="true"
                            />
                            <div className="min-w-0">
                              <h2 className="text-sm font-medium text-text-primary">
                                {intl.formatMessage(i18n.nativeProgramsTitle)}
                              </h2>
                              <p className="text-xs text-text-secondary">
                                {intl.formatMessage(i18n.nativeProgramsDescription)}
                              </p>
                            </div>
                          </div>
                          <Button
                            type="button"
                            variant="outline"
                            size="sm"
                            aria-expanded={showNativePrograms}
                            aria-label={`${intl.formatMessage(
                              showNativePrograms ? i18n.nativeProgramsHide : i18n.nativeProgramsShow
                            )} ${intl.formatMessage(i18n.nativeProgramsTitle)}`}
                            onClick={() => setShowNativePrograms((current) => !current)}
                          >
                            {intl.formatMessage(
                              showNativePrograms ? i18n.nativeProgramsHide : i18n.nativeProgramsShow
                            )}
                            <ChevronDown
                              className={`h-4 w-4 transition-transform ${showNativePrograms ? 'rotate-180' : ''}`}
                              aria-hidden="true"
                            />
                          </Button>
                        </CardContent>
                      </Card>
                      {showNativePrograms && <TerminalProgramsSettings />}
                      <Card className="rounded-lg">
                        <CardContent className="flex items-center justify-between gap-4 px-4">
                          <div className="flex min-w-0 items-center gap-3">
                            <Globe2
                              className="h-4 w-4 shrink-0 text-text-secondary"
                              aria-hidden="true"
                            />
                            <div className="min-w-0">
                              <h2 className="text-sm font-medium text-text-primary">
                                {intl.formatMessage(i18n.networkTitle)}
                              </h2>
                              <p className="text-xs text-text-secondary">
                                {intl.formatMessage(i18n.networkDescription)}
                              </p>
                            </div>
                          </div>
                          <Button
                            type="button"
                            variant="outline"
                            size="sm"
                            aria-expanded={showNetworkAccess}
                            aria-label={`${intl.formatMessage(
                              showNetworkAccess ? i18n.networkHide : i18n.networkManage
                            )} ${intl.formatMessage(i18n.networkTitle)}`}
                            onClick={() => setShowNetworkAccess((current) => !current)}
                          >
                            {intl.formatMessage(
                              showNetworkAccess ? i18n.networkHide : i18n.networkManage
                            )}
                            <ChevronDown
                              className={`h-4 w-4 transition-transform ${showNetworkAccess ? 'rotate-180' : ''}`}
                              aria-hidden="true"
                            />
                          </Button>
                        </CardContent>
                      </Card>
                      {showNetworkAccess && <NetworkAccessSettings />}
                    </div>
                  </div>
                </TabsContent>

                <TabsContent
                  value="app"
                  className="mt-0 focus-visible:outline-none focus-visible:ring-0"
                >
                  <div className="space-y-8">
                    <ChatSettingsSection />
                    <AppSettingsSection scrollToSection={viewOptions.section} />
                    <div className="space-y-4 pr-4 pb-8">
                      <Card className="rounded-lg">
                        <CardContent className="flex items-center justify-between gap-4 px-4">
                          <div className="flex min-w-0 items-center gap-3">
                            <Keyboard
                              className="h-4 w-4 shrink-0 text-text-secondary"
                              aria-hidden="true"
                            />
                            <div className="min-w-0">
                              <h2 className="text-sm font-medium text-text-primary">
                                {intl.formatMessage(i18n.keyboardShortcutsTitle)}
                              </h2>
                              <p className="text-xs text-text-secondary">
                                {intl.formatMessage(i18n.keyboardShortcutsDescription)}
                              </p>
                            </div>
                          </div>
                          <Button
                            type="button"
                            variant="outline"
                            size="sm"
                            aria-expanded={showKeyboardShortcuts}
                            onClick={() => setShowKeyboardShortcuts((current) => !current)}
                          >
                            {intl.formatMessage(
                              showKeyboardShortcuts
                                ? i18n.keyboardShortcutsHide
                                : i18n.keyboardShortcutsShow
                            )}
                            <ChevronDown
                              className={`h-4 w-4 transition-transform ${showKeyboardShortcuts ? 'rotate-180' : ''}`}
                              aria-hidden="true"
                            />
                          </Button>
                        </CardContent>
                      </Card>
                      {showKeyboardShortcuts && <KeyboardShortcutsSection />}
                    </div>
                  </div>
                </TabsContent>
              </ScrollArea>
            </Tabs>
          </div>
        </div>
      </MainPanelLayout>
    </>
  );
}
