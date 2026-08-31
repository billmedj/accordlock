import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  acpGetProviderTemplate,
  acpListProviderCatalogEntries,
} from '../../../../../acp/providers';
import { IntlTestWrapper } from '../../../../../i18n/test-utils';
import ProviderCatalogPicker from './ProviderCatalogPicker';

vi.mock('../../../../../acp/providers', () => ({
  acpGetProviderTemplate: vi.fn(),
  acpListProviderCatalogEntries: vi.fn(),
}));

vi.mock('../../../../ui/Select', () => ({ Select: () => null }));

const RAW_ERROR =
  'URL=https://raw-url.invalid/private?token=URL_SECRET ' +
  'PATH=C:\\Users\\PATH_SECRET\\provider.json ' +
  'PAYLOAD={"PAYLOAD_SECRET":"secret"}';

function expectNoDiagnostics(): void {
  const rendered = document.body.textContent ?? '';
  expect(rendered).not.toContain('raw-url.invalid');
  expect(rendered).not.toContain('PATH_SECRET');
  expect(rendered).not.toContain('PAYLOAD_SECRET');
}

describe('ProviderCatalogPicker', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('does not render provider-catalog diagnostics', async () => {
    vi.mocked(acpListProviderCatalogEntries).mockRejectedValue(new Error(RAW_ERROR));

    render(<ProviderCatalogPicker onSelect={vi.fn()} onCancel={vi.fn()} />, {
      wrapper: IntlTestWrapper,
    });

    expect(
      await screen.findByText(
        "Error: AccordLock couldn't load the provider catalog. Check your connection and try again."
      )
    ).toBeVisible();
    expectNoDiagnostics();
  });

  it('does not render provider-template diagnostics', async () => {
    vi.mocked(acpListProviderCatalogEntries).mockResolvedValue([
      {
        providerId: 'example',
        name: 'Example Provider',
        format: 'openai',
        apiUrl: 'https://api.example.invalid',
        modelCount: 1,
        docUrl: '',
        envVar: '',
      },
    ]);
    vi.mocked(acpGetProviderTemplate).mockRejectedValue(new Error(RAW_ERROR));

    render(<ProviderCatalogPicker onSelect={vi.fn()} onCancel={vi.fn()} />, {
      wrapper: IntlTestWrapper,
    });
    await userEvent.click(await screen.findByRole('button', { name: /Example Provider/ }));

    expect(
      await screen.findByText(
        "Error: AccordLock couldn't load this provider. Try again or choose another provider."
      )
    ).toBeVisible();
    expectNoDiagnostics();
  });
});
