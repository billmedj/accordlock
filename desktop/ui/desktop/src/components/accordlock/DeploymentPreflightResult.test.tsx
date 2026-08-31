import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import {
  DeploymentPreflightResult,
  type DeploymentPreflightResultView,
  validateDeploymentPreflightResultView,
} from './DeploymentPreflightResult';

const digest = (character: string) => `sha256:${character.repeat(64)}`;

function result(
  overrides: Partial<DeploymentPreflightResultView> = {}
): DeploymentPreflightResultView {
  return {
    checkId: 'check-1',
    outcome: 'PASSED',
    completedAt: 1_800_000_000,
    validUntil: 1_800_000_060,
    environmentProfileHash: digest('1'),
    receiptHash: digest('2'),
    receiptJson: JSON.stringify({ receipt_hash: digest('2'), signature: 'test' }),
    reasonCodes: ['ALLOWED'],
    checks: [
      { kind: 'CODE_REVIEW', status: 'PASSED', summary: 'Approved commit matches' },
      { kind: 'BUILD', status: 'PASSED', summary: 'Successful run matches the commit' },
      { kind: 'IMAGE', status: 'PASSED', summary: 'Signed digest matches the build' },
      { kind: 'TARGET', status: 'PASSED', summary: 'Deployment state is unchanged' },
    ],
    ...overrides,
  };
}

describe('DeploymentPreflightResult', () => {
  it('shows one compact four-check result with an explicit zero-effect statement', () => {
    const onExport = vi.fn();
    render(<DeploymentPreflightResult result={result()} onExport={onExport} />);

    expect(screen.getByRole('heading', { name: 'Checks passed' })).toBeVisible();
    expect(screen.getByText('Code review')).toBeVisible();
    expect(screen.getByText('Build')).toBeVisible();
    expect(screen.getByText('Image')).toBeVisible();
    expect(screen.getByText('Target')).toBeVisible();
    expect(screen.getByText('No deployment was performed.')).toBeVisible();
    expect(screen.queryByRole('button', { name: /deploy/i })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Export receipt' }));
    expect(onExport).toHaveBeenCalledOnce();
  });

  it('offers retry only for an indeterminate result', () => {
    const onRetry = vi.fn();
    render(
      <DeploymentPreflightResult
        result={result({
          outcome: 'INDETERMINATE',
          validUntil: null,
          reasonCodes: ['PROVIDER_UNAVAILABLE'],
          checks: [
            { kind: 'CODE_REVIEW', status: 'INDETERMINATE', summary: 'GitHub unavailable' },
            { kind: 'BUILD', status: 'INDETERMINATE', summary: 'Not checked' },
            { kind: 'IMAGE', status: 'INDETERMINATE', summary: 'Not checked' },
            { kind: 'TARGET', status: 'INDETERMINATE', summary: 'Not checked' },
          ],
        })}
        onExport={vi.fn()}
        onRetry={onRetry}
      />
    );

    expect(screen.getByRole('heading', { name: "Couldn't verify" })).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(onRetry).toHaveBeenCalledOnce();
  });

  it('reports a failed read-only check without claiming it blocked a deployment', () => {
    render(
      <DeploymentPreflightResult
        result={result({
          outcome: 'BLOCKED',
          validUntil: null,
          reasonCodes: ['TARGET_STATE_MISMATCH'],
          checks: [
            { kind: 'CODE_REVIEW', status: 'PASSED', summary: 'Approved commit matches' },
            { kind: 'BUILD', status: 'PASSED', summary: 'Successful run matches the commit' },
            { kind: 'IMAGE', status: 'PASSED', summary: 'Signed digest matches the build' },
            { kind: 'TARGET', status: 'BLOCKED', summary: 'The deployment state changed' },
          ],
        })}
        onExport={vi.fn()}
      />
    );

    expect(screen.getByRole('heading', { name: 'Checks failed' })).toBeVisible();
    expect(screen.queryByText('Deployment blocked')).not.toBeInTheDocument();
    expect(screen.getByText('No deployment was performed.')).toBeVisible();
  });

  it('rejects partial passes and malformed check sets before rendering them', () => {
    const malformed = result({
      checks: [
        { kind: 'CODE_REVIEW', status: 'PASSED', summary: 'Approved' },
        { kind: 'BUILD', status: 'PASSED', summary: 'Built' },
        { kind: 'IMAGE', status: 'PASSED', summary: 'Signed' },
        { kind: 'TARGET', status: 'INDETERMINATE', summary: 'Unknown' },
      ],
    });

    expect(validateDeploymentPreflightResultView(malformed)).toBe(false);
    render(<DeploymentPreflightResult result={malformed} onExport={vi.fn()} />);
    expect(screen.getByRole('alert')).toHaveTextContent('Result unavailable');
  });
});
