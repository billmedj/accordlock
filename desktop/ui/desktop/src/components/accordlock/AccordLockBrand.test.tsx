import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { AccordLockGlyph, AccordLockWordmark } from './AccordLockBrand';

describe('AccordLockBrand', () => {
  it('renders the proprietary verified-handoff mark', () => {
    const { container } = render(<AccordLockGlyph />);
    const mark = container.querySelector('[data-accordlock-mark="verified-handoff"]');

    expect(mark).not.toBeNull();
    expect(mark?.querySelectorAll('path')).toHaveLength(2);
    expect(mark?.querySelectorAll('rect')).toHaveLength(1);
  });

  it('keeps product identity separate from the active status indicator', () => {
    const { container, rerender } = render(<AccordLockGlyph />);

    expect(container.querySelector('[data-accordlock-status="active"]')).toBeNull();

    rerender(<AccordLockGlyph active />);

    expect(container.querySelector('[data-accordlock-status="active"]')).not.toBeNull();
  });

  it('animates only the transaction point while work is active', () => {
    const { container } = render(<AccordLockGlyph busy />);
    const mark = container.querySelector('[data-accordlock-mark="verified-handoff"]');
    const node = mark?.querySelector('rect');

    expect(mark).not.toHaveClass('animate-pulse');
    expect(node).toHaveClass('motion-safe:animate-pulse');
  });

  it('renders the wordmark and optional subtitle', () => {
    render(<AccordLockWordmark subtitle="Desktop" />);

    expect(screen.getByText('AccordLock')).toBeInTheDocument();
    expect(screen.getByText('Desktop')).toBeInTheDocument();
  });
});
