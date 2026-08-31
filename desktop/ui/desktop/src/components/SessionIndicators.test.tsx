import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { IntlTestWrapper } from '../i18n/test-utils';
import { SessionIndicators } from './SessionIndicators';

function renderIndicators({
  isStreaming = false,
  hasUnread = false,
  hasError = false,
}: Partial<React.ComponentProps<typeof SessionIndicators>> = {}) {
  render(
    <IntlTestWrapper>
      <SessionIndicators isStreaming={isStreaming} hasUnread={hasUnread} hasError={hasError} />
    </IntlTestWrapper>
  );
}

describe('SessionIndicators', () => {
  it('describes active work consistently', () => {
    renderIndicators({ isStreaming: true });

    expect(screen.getByLabelText('Working')).toBeInTheDocument();
  });

  it('describes generic errors without implying a security block', () => {
    renderIndicators({ hasError: true });

    expect(screen.getByLabelText('Needs attention')).toBeInTheDocument();
    expect(screen.queryByLabelText('Blocked safely')).not.toBeInTheDocument();
  });

  it('keeps the readable unread badge', () => {
    renderIndicators({ hasUnread: true });

    expect(screen.getByText('New')).toHaveAccessibleName('Has new activity');
  });
});
