import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { IntlTestWrapper } from '../../../i18n/test-utils';
import ChatSettingsSection from './ChatSettingsSection';

vi.mock('./GoosehintsSection', () => ({
  GoosehintsSection: () => <div>Folder instructions</div>,
}));

vi.mock('../dictation/DictationSettings', () => ({
  DictationSettings: () => <div>Voice input setting</div>,
}));

vi.mock('./SpellcheckToggle', () => ({
  SpellcheckToggle: () => <div>Spell check setting</div>,
}));

vi.mock('../response_styles/ResponseStylesSection', () => ({
  ResponseStylesSection: () => <div>Response detail setting</div>,
}));

describe('ChatSettingsSection', () => {
  it('keeps the behavior surface focused on ordinary user preferences', () => {
    render(<ChatSettingsSection />, { wrapper: IntlTestWrapper });

    expect(screen.getByText('Folder instructions')).toBeVisible();
    expect(screen.getByRole('heading', { name: 'Input' })).toBeVisible();
    expect(screen.getByRole('heading', { name: 'Responses' })).toBeVisible();
    expect(screen.queryByText('Default Mode')).not.toBeInTheDocument();
    expect(screen.queryByText('Prompt injection')).not.toBeInTheDocument();
  });
});
