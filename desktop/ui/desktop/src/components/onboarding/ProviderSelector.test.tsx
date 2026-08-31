import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { acpListSetupProviderDetails, acpSaveDefaults } from '../../acp/providers';
import { IntlTestWrapper } from '../../i18n/test-utils';
import type { ProviderDetails } from '../../types/providers';
import ProviderSelector from './ProviderSelector';

vi.mock('../../acp/providers', () => ({
  acpCreateCustomProviderFromRequest: vi.fn(),
  acpListSetupProviderDetails: vi.fn(),
  acpSaveDefaults: vi.fn(),
}));

vi.mock('../../contexts/FeaturesContext', () => ({
  useFeatures: () => ({ localInference: false, isLoading: false }),
}));

vi.mock('./ProviderConfigForm', () => ({
  default: ({ provider }: { provider: ProviderDetails }) => (
    <div data-testid="provider-config">Configure {provider.metadata.display_name}</div>
  ),
}));

vi.mock('./LocalModelPicker', () => ({ default: () => null }));
vi.mock('../settings/providers/modal/subcomponents/forms/CustomProviderForm', () => ({
  default: () => null,
}));

const provider = (name: string, displayName: string): ProviderDetails => ({
  name,
  provider_type: 'Preferred',
  is_configured: false,
  is_available: true,
  visible_in_setup: true,
  deprecated: false,
  metadata: {
    name,
    display_name: displayName,
    description: '',
    default_model: 'model',
    known_models: [],
    model_doc_link: '',
    config_keys: [],
  },
  setup_category: 'model',
  uses_acp: false,
});

const providers = [
  provider('anthropic', 'Anthropic'),
  provider('openai', 'OpenAI'),
  provider('opencode', 'OpenCode Zen'),
  provider('chatgpt_codex', 'ChatGPT Codex'),
  provider('google', 'Google Gemini (API Key)'),
  provider('mistral', 'Mistral'),
  provider('huggingface', 'Hugging Face'),
  provider('ollama', 'Ollama'),
  provider('deepseek', 'DeepSeek'),
];

describe('ProviderSelector', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(acpListSetupProviderDetails).mockResolvedValue(providers);
  });

  it('keeps the long provider catalog behind a deliberate advanced choice', async () => {
    render(<ProviderSelector onConfigured={vi.fn()} />, { wrapper: IntlTestWrapper });

    const connect = screen.getByRole('button', { name: /Connect a model/i });
    const explore = screen.getByRole('button', { name: /Explore first/i });
    expect(connect.compareDocumentPosition(explore)).toBe(Node.DOCUMENT_POSITION_FOLLOWING);
    expect(connect).toHaveAttribute('aria-pressed', 'false');
    await userEvent.click(connect);

    await waitFor(() => expect(screen.getByRole('button', { name: 'Anthropic' })).toBeVisible());
    expect(screen.getByRole('button', { name: 'OpenAI' })).toBeVisible();
    expect(screen.getByRole('button', { name: 'OpenCode Zen' })).toBeVisible();
    expect(screen.getByRole('button', { name: 'Mistral' })).toBeVisible();
    expect(screen.getByRole('button', { name: 'Hugging Face' })).toBeVisible();
    expect(screen.getByRole('button', { name: 'Ollama' })).toBeVisible();
    expect(screen.queryByRole('button', { name: 'ChatGPT Codex' })).not.toBeInTheDocument();
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'Browse all 9 providers' }));
    expect(screen.getByRole('combobox')).toBeVisible();
  });

  it('opens a recommended provider directly and lets the user change it', async () => {
    render(<ProviderSelector onConfigured={vi.fn()} />, { wrapper: IntlTestWrapper });
    await userEvent.click(screen.getByRole('button', { name: /Connect a model/i }));
    await userEvent.click(await screen.findByRole('button', { name: 'Anthropic' }));

    expect(screen.getByTestId('provider-config')).toHaveTextContent('Configure Anthropic');
    await userEvent.click(screen.getByRole('button', { name: 'Choose another provider' }));
    expect(screen.queryByTestId('provider-config')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Anthropic' })).toBeVisible();
  });

  it('offers a working retry instead of leaving a dead-end when providers fail to load', async () => {
    vi.mocked(acpListSetupProviderDetails)
      .mockRejectedValueOnce(new Error('runtime unavailable'))
      .mockResolvedValueOnce(providers);

    render(<ProviderSelector onConfigured={vi.fn()} />, { wrapper: IntlTestWrapper });
    await userEvent.click(screen.getByRole('button', { name: /Connect a model/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'AccordLock could not load model providers.'
    );
    await userEvent.click(screen.getByRole('button', { name: 'Try again' }));

    await waitFor(() => expect(screen.getByRole('button', { name: 'Anthropic' })).toBeVisible());
    expect(acpListSetupProviderDetails).toHaveBeenCalledTimes(2);
  });

  it('opens a truthful local product tour without configuring a provider or executing work', async () => {
    const onConfigured = vi.fn();
    render(<ProviderSelector onConfigured={onConfigured} />, { wrapper: IntlTestWrapper });

    await userEvent.click(screen.getByRole('button', { name: /Explore first/i }));

    const dialog = screen.getByRole('dialog', {
      name: /Try the approval flow/i,
    });
    expect(dialog).toBeVisible();
    expect(screen.getByText("This demo doesn't use a model or touch your files.")).toBeVisible();
    expect(
      screen.getByText('Can read files in this folder. Asks before changes and commands.')
    ).toBeVisible();
    expect(screen.getByText('Task access')).toBeVisible();
    expect(screen.getByText('Proposed change')).toBeVisible();
    expect(screen.getByText('Decision')).toBeVisible();
    expect(onConfigured).not.toHaveBeenCalled();
    expect(acpSaveDefaults).not.toHaveBeenCalled();

    const allowOnce = screen.getByRole('button', { name: 'Approve once' });
    await userEvent.click(allowOnce);
    expect(allowOnce).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByText('Approved once')).toBeVisible();
    expect(screen.getByText('Only the change shown above can run.')).toBeVisible();

    const keepLocked = screen.getByRole('button', { name: 'Keep locked' });
    await userEvent.click(keepLocked);
    expect(keepLocked).toHaveAttribute('aria-pressed', 'true');
    expect(allowOnce).toHaveAttribute('aria-pressed', 'false');
    expect(screen.getByText('Kept locked')).toBeVisible();
    expect(screen.getByText('The proposed change stays blocked.')).toBeVisible();

    await userEvent.click(screen.getByRole('button', { name: 'Back to provider selection' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(screen.getByRole('button', { name: /Explore first/i })).toBeVisible();
    expect(onConfigured).not.toHaveBeenCalled();
    expect(acpSaveDefaults).not.toHaveBeenCalled();
  });
});
