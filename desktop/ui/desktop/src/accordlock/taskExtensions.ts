import type { FixedExtensionEntry } from '../components/ConfigContext';
import type { ExtensionConfig } from '../types/extensions';

const ACCORDLOCK_TASK_EXTENSION = 'developer';

/**
 * Protected tasks start with the single platform extension covered by the
 * task policy. Global extension toggles cannot widen a task authorization.
 */
export function selectAccordLockTaskExtensions(
  extensions: readonly FixedExtensionEntry[]
): ExtensionConfig[] {
  const developer = extensions.find((extension) => extension.name === ACCORDLOCK_TASK_EXTENSION);
  if (!developer) return [];

  const { enabled: _enabled, ...config } = developer;
  return [config as ExtensionConfig];
}
