import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { IntlTestWrapper } from '../i18n/test-utils';
import { ErrorUI } from './ErrorBoundary';

const RAW_ERROR =
  'URL=https://raw-url.invalid/private?token=URL_SECRET ' +
  'PATH=C:\\Users\\PATH_SECRET\\provider.json ' +
  'PAYLOAD={"PAYLOAD_SECRET":"secret"}';

describe('ErrorUI', () => {
  it('shows calm recovery guidance without rendering diagnostic details', () => {
    render(<ErrorUI error={RAW_ERROR} />, { wrapper: IntlTestWrapper });

    expect(screen.getByText('AccordLock needs to restart')).toBeVisible();
    expect(screen.getByText('Your work is saved. Reload the app to continue.')).toBeVisible();

    const rendered = document.body.textContent ?? '';
    expect(rendered).not.toContain('raw-url.invalid');
    expect(rendered).not.toContain('PATH_SECRET');
    expect(rendered).not.toContain('PAYLOAD_SECRET');
  });
});
