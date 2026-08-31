import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { IntlTestWrapper } from '../../i18n/test-utils';
import { DeploymentPreflightDialog } from './DeploymentPreflightDialog';
import type { DeploymentPreflightResultView } from './DeploymentPreflightResult';

const digest = (character: string) => `sha256:${character.repeat(64)}`;

const environment = {
  id: '11111111-1111-4111-8111-111111111111',
  name: 'Production',
  repository: 'accordlock/product',
  workflow: 'release.yml',
  target: 'payments / production / api',
  status: 'SAVED' as const,
};

const passed: DeploymentPreflightResultView = {
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
};

describe('DeploymentPreflightDialog', () => {
  it('prefills the build identifiers already verified during import', () => {
    render(
      <DeploymentPreflightDialog
        open
        environment={environment}
        candidateDefaults={{
          buildRunUrl: 'https://github.com/accordlock/product/actions/runs/123',
          imageDigest: digest('a'),
        }}
        onOpenChange={vi.fn()}
        onRun={vi.fn()}
        onExport={vi.fn()}
      />,
      { wrapper: IntlTestWrapper }
    );

    expect(screen.getByLabelText('Build run')).toHaveValue(
      'https://github.com/accordlock/product/actions/runs/123'
    );
    expect(screen.getByLabelText('Image digest')).toHaveValue(digest('a'));
    expect(screen.getByLabelText('Pull request')).toHaveValue('');
  });

  it('runs one bounded check from three candidate fields', async () => {
    const user = userEvent.setup();
    const onRun = vi.fn().mockResolvedValue(passed);
    render(
      <DeploymentPreflightDialog
        open
        environment={environment}
        onOpenChange={vi.fn()}
        onRun={onRun}
        onExport={vi.fn()}
      />,
      { wrapper: IntlTestWrapper }
    );

    expect(screen.getByRole('heading', { name: 'Verify deployment' })).toBeVisible();
    expect(
      screen.getByText(
        'Read-only. Checks the code, build, image, and current target. Nothing is deployed.'
      )
    ).toBeVisible();
    expect(screen.getByText('Target · payments / production / api')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Run checks' })).toBeDisabled();

    await user.type(
      screen.getByLabelText('Pull request'),
      'https://github.com/accordlock/product/pull/42'
    );
    await user.type(
      screen.getByLabelText('Build run'),
      'https://github.com/accordlock/product/actions/runs/123'
    );
    await user.type(screen.getByLabelText('Image digest'), digest('a'));
    await user.click(screen.getByRole('button', { name: 'Run checks' }));

    await waitFor(() =>
      expect(onRun).toHaveBeenCalledWith({
        profileId: environment.id,
        pullRequestUrl: 'https://github.com/accordlock/product/pull/42',
        buildRunUrl: 'https://github.com/accordlock/product/actions/runs/123',
        imageDigest: digest('a'),
      })
    );
    expect(await screen.findByRole('heading', { name: 'Checks passed' })).toBeVisible();
    expect(screen.getByText('No deployment was performed.')).toBeVisible();
    expect(screen.queryByRole('button', { name: /deploy/i })).not.toBeInTheDocument();
  });

  it('keeps a runner error in the dialog without inventing a result', async () => {
    const user = userEvent.setup();
    const onRun = vi
      .fn()
      .mockRejectedValue(new Error('The build run belongs to another workflow.'));
    render(
      <DeploymentPreflightDialog
        open
        environment={environment}
        onOpenChange={vi.fn()}
        onRun={onRun}
        onExport={vi.fn()}
      />,
      { wrapper: IntlTestWrapper }
    );

    await user.type(
      screen.getByLabelText('Pull request'),
      'https://github.com/accordlock/product/pull/42'
    );
    await user.type(
      screen.getByLabelText('Build run'),
      'https://github.com/accordlock/product/actions/runs/123'
    );
    await user.type(screen.getByLabelText('Image digest'), digest('a'));
    await user.click(screen.getByRole('button', { name: 'Run checks' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The build run belongs to another workflow.'
    );
    expect(screen.queryByText('Checks passed')).not.toBeInTheDocument();
  });
});
