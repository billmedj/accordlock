// AccordLock releases must never consume the upstream Goose update channel.
// Enable this only after the distribution owns a signed release repository.
export const UPDATES_ENABLED = false;
export const COST_TRACKING_ENABLED = true;
export const ANNOUNCEMENTS_ENABLED = false;
export const CONFIGURATION_ENABLED = true;
// Keep upstream analytics off until AccordLock has its own reviewed privacy
// policy, endpoint, consent text, retention rules, and release channel.
export const TELEMETRY_UI_ENABLED = false;
export const DICTATION_ALLOWED_PROVIDERS: string[] | null = null;
