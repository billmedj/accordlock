import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { acpAuthenticateProvider } from '../../acp/providers';
import { IntlTestWrapper } from '../../i18n/test-utils';
import type { ProviderDetails } from '../../types/providers';
import ProviderConfigForm from './ProviderConfigForm';

vi.mock('../../acp/providers', () => ({
  acpAuthenticateProvider: vi.fn(),
}));

vi.mock('../settings/providers/modal/subcomponents/forms/DefaultProviderSetupForm', () => ({
  default: () => null,
}));
vi.mock('../settings/providers/modal/subcomponents/handlers/DefaultSubmitHandler', () => ({
  providerConfigSubmitHandler: vi.fn(),
}));
vi.mock('../settings/providers/modal/subcomponents/ProviderLogo', () => ({
  default: () => null,
}));
vi.mock('../settings/providers/modal/subcomponents/SecureStorageNotice', () => ({
  SecureStorageNotice: () => null,
}));
vi.mock('../settings/providers/AcpReadinessPanel', () => ({ default: () => null }));

const RAW_ERROR =
  'URL=https://raw-url.invalid/private?token=URL_SECRET ' +
  'PATH=Z:\\private\\PATH_SECRET\\provider.json ' +
  'PAYLOAD={"PAYLOAD_SECRET":"secret"}';

const provider: ProviderDetails = {
  name: 'example-oauth',
  provider_type: 'Preferred',
  is_configured: false,
  is_available: true,
  visible_in_setup: true,
  deprecated: false,
  setup_category: 'model',
  uses_acp: false,
  metadata: {
    name: 'example-oauth',
    display_name: 'Example Provider',
    description: '',
    default_model: 'example-model',
    known_models: [],
    model_doc_link: '',
    config_keys: [
      {
        name: 'oauth',
        oauth_flow: true,
        required: true,
        secret: true,
      },
    ],
  },
};

describe('ProviderConfigForm', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('keeps provider diagnostics out of setup copy', async () => {
    vi.mocked(acpAuthenticateProvider).mockRejectedValue(new Error(RAW_ERROR));

    render(<ProviderConfigForm provider={provider} onConfigured={vi.fn()} />, {
      wrapper: IntlTestWrapper,
    });
    await userEvent.click(screen.getByRole('button', { name: 'Sign in with Example Provider' }));

    expect(
      await screen.findByText(
        "AccordLock couldn't connect to this provider. Check the provider settings and try again."
      )
    ).toBeVisible();

    const rendered = document.body.textContent ?? '';
    expect(rendered).not.toContain('raw-url.invalid');
    expect(rendered).not.toContain('PATH_SECRET');
    expect(rendered).not.toContain('PAYLOAD_SECRET');
  });
});
