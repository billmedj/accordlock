import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), 'utf8');
}

describe('user-facing error boundaries', () => {
  it('keeps raw startup errors out of Electron dialogs', () => {
    const main = source('../main.ts');

    expect(main).not.toMatch(/detail:\s*errorMessage\(/);
    expect(main).not.toContain('`Startup error:\\n${errorMessage(error)}`');
    expect(main).not.toContain('`Failed to create main window: ${error}`');
    expect(main).not.toContain('${details}`');
    expect(main).not.toMatch(/message:\s*`[^`]*\$\{externalBaseUrl\}/);
    expect(main).not.toMatch(/error:\s*errorMessage\(err\)/);
    expect(main).toContain(
      "AccordLock couldn't open this file. Check that it still exists and that you have permission to read it, then try again."
    );
    expect(main).toContain(
      "log.error('AccordLock could not open the selected file', formatErrorForLogging(err))"
    );
  });

  it.each([
    '../components/onboarding/ProviderConfigForm.tsx',
    '../components/settings/providers/modal/subcomponents/ProviderCatalogPicker.tsx',
    '../hooks/useChatSession.ts',
    '../components/McpApps/McpAppRenderer.tsx',
  ])('does not use diagnostic error text in %s', (relativePath) => {
    const contents = source(relativePath);

    expect(contents).not.toMatch(/\berrorMessage\s*\(/);
    expect(contents).not.toMatch(/\b(?:error|err)\.message\b/);
  });

  it('renders the crash recovery screen without passing diagnostic text', () => {
    const errorBoundary = source('../components/ErrorBoundary.tsx');

    expect(errorBoundary).not.toMatch(/<ErrorUI\s+error=/);
    expect(errorBoundary).not.toMatch(/\berrorMessage\s*\(/);
    expect(errorBoundary).toContain('formatErrorForLogging(event.reason)');
  });

  it('keeps turn failures out of rendered chat state and toast copy', () => {
    const hook = source('../hooks/useChatSession.ts');

    expect(hook).not.toMatch(/setLastRunError\(error\)/);
    expect(hook).not.toMatch(/msg:\s*error\b/);
  });
});
