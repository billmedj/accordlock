import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AccordLockEnvironmentProfileSummary } from '../../../accordlock/environmentProfiles';
import type { AccordLockEnvironmentProfileView } from '../../../accordlock/environmentProfileIpc';
import type { DeploymentPreflightReceiptArchiveSummary } from '../../../accordlock/deploymentPreflightReceiptArchive';
import { IntlTestWrapper } from '../../../i18n/test-utils';
import type { DeploymentPreflightResultView } from '../../accordlock/DeploymentPreflightResult';
import EnvironmentConnectionsSettings from './EnvironmentConnectionsSettings';

const PROFILE_ID = '11111111-1111-4111-8111-111111111111';
const digest = (character: string) => `sha256:${character.repeat(64)}`;

function profile(
  overrides: Partial<AccordLockEnvironmentProfileSummary> = {}
): AccordLockEnvironmentProfileView {
  return {
    id: PROFILE_ID,
    name: 'Production',
    runner: { mode: 'LOCAL_BUNDLED' },
    github: {
      repository: 'accordlock/product',
      workflow: '.github/workflows/release.yml',
    },
    aws: {
      accountId: '123456789012',
      region: 'eu-west-1',
      ecrRepository: 'services/api',
    },
    kubernetes: {
      clusterName: 'production',
      namespace: 'production',
      deployment: 'api',
      container: 'api',
    },
    credentialsConfigured: { github: true, aws: true },
    status: 'SAVED',
    createdAt: 1_800_000_000,
    updatedAt: 1_800_000_000,
    verifiedAt: null,
    failedAt: null,
    failureCode: null,
    ciTrust: {
      status: 'ENROLLED',
      buildAuthorityFingerprint: digest('a'),
      artifactAuthorityFingerprint: digest('b'),
    },
    ...overrides,
  };
}

const passed: DeploymentPreflightResultView = {
  checkId: 'check-42',
  outcome: 'PASSED',
  completedAt: 1_800_000_000,
  validUntil: 1_800_000_060,
  environmentProfileHash: digest('1'),
  receiptHash: digest('2'),
  receiptJson: JSON.stringify({
    schema_version: 1,
    check_id: 'check-42',
    receipt_hash: digest('2'),
    signature: 'signed-receipt',
  }),
  reasonCodes: ['ALLOWED'],
  checks: [
    { kind: 'CODE_REVIEW', status: 'PASSED', summary: 'Approved commit matches' },
    { kind: 'BUILD', status: 'PASSED', summary: 'Successful run matches the commit' },
    { kind: 'IMAGE', status: 'PASSED', summary: 'Signed digest matches the build' },
    { kind: 'TARGET', status: 'PASSED', summary: 'Deployment state is unchanged' },
  ],
};

function installElectronMocks(profiles: readonly AccordLockEnvironmentProfileView[]) {
  const list = vi.fn().mockResolvedValue([...profiles]);
  const save = vi.fn().mockResolvedValue(profile());
  const remove = vi.fn().mockResolvedValue(true);
  const run = vi.fn().mockResolvedValue(passed);
  const listHistory = vi.fn().mockResolvedValue([]);
  const exportReceipt = vi.fn().mockResolvedValue({
    saved: true,
    canceled: false,
    fileName: 'receipt.json',
    packageDigest: digest('f'),
  });
  const importEvidence = vi
    .fn()
    .mockResolvedValue({ status: 'CANCELED', environmentId: PROFILE_ID });

  Object.assign(window.electron, {
    listAccordLockEnvironmentProfiles: list,
    saveAccordLockEnvironmentProfile: save,
    removeAccordLockEnvironmentProfile: remove,
    runAccordLockDeploymentPreflight: run,
    listAccordLockDeploymentPreflightHistory: listHistory,
    exportAccordLockDeploymentPreflightReceipt: exportReceipt,
    importAccordLockDeploymentPreflightCiEvidence: importEvidence,
  });

  return { list, save, remove, run, listHistory, exportReceipt, importEvidence };
}

async function openEditor(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('button', { name: 'Connect' }));
  expect(screen.getByRole('heading', { name: 'Connect environment' })).toBeVisible();
}

function setField(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

function expectEditorStep(step: number, title: string) {
  expect(screen.getByRole('progressbar', { name: 'Environment setup progress' })).toHaveAttribute(
    'aria-valuenow',
    String(step)
  );
  expect(screen.getByRole('heading', { level: 3, name: title })).toBeVisible();
}

async function fillNewEnvironment(user: ReturnType<typeof userEvent.setup>) {
  expectEditorStep(1, 'Environment');
  expect(screen.queryByLabelText('Repository')).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Save environment' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Continue' })).toBeDisabled();
  setField('Name', 'Production');
  await user.click(screen.getByRole('button', { name: 'Continue' }));

  expectEditorStep(2, 'Source & build');
  expect(screen.queryByLabelText('AWS account ID')).not.toBeInTheDocument();
  setField('Repository', 'accordlock/product');
  setField('Fine-grained GitHub token', 'github-secret');
  await user.click(screen.getByRole('button', { name: 'Continue' }));

  expectEditorStep(3, 'Image registry');
  expect(screen.queryByLabelText('Cluster name')).not.toBeInTheDocument();
  setField('AWS account ID', '123456789012');
  setField('Region', 'eu-west-1');
  setField('ECR repository', 'services/api');
  setField('Temporary access key ID', 'ASIAEXAMPLE');
  setField('Temporary secret access key', 'aws-secret');
  setField('Session token', 'aws-session-token');
  await user.click(screen.getByRole('button', { name: 'Continue' }));

  expectEditorStep(4, 'Deployment target');
  expect(screen.queryByRole('button', { name: 'Continue' })).not.toBeInTheDocument();
  setField('Cluster name', 'production');
  setField('Namespace', 'production');
  setField('Deployment', 'api');
  setField('Container', 'api');
}

describe('EnvironmentConnectionsSettings', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('shows a compact empty state without inventing a connected environment', async () => {
    installElectronMocks([]);

    render(<EnvironmentConnectionsSettings />, { wrapper: IntlTestWrapper });

    expect(await screen.findByText('No environments connected')).toBeVisible();
    expect(
      screen.getByText('Add one to verify code, builds, images, and deployment state.')
    ).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Verify' })).not.toBeInTheDocument();
  });

  it('creates a bounded profile and never renders submitted secrets in its summary', async () => {
    const user = userEvent.setup();
    const { save } = installElectronMocks([]);
    render(<EnvironmentConnectionsSettings />, { wrapper: IntlTestWrapper });
    await screen.findByText('No environments connected');

    await openEditor(user);
    await fillNewEnvironment(user);
    expect(screen.getByRole('button', { name: 'Save environment' })).toBeEnabled();
    await user.click(screen.getByRole('button', { name: 'Save environment' }));

    await waitFor(() => expect(save).toHaveBeenCalledOnce());
    expect(save).toHaveBeenCalledWith({
      id: null,
      name: 'Production',
      runner: { mode: 'LOCAL_BUNDLED' },
      github: {
        repository: 'accordlock/product',
        workflow: '.github/workflows/release.yml',
      },
      aws: {
        accountId: '123456789012',
        region: 'eu-west-1',
        ecrRepository: 'services/api',
      },
      kubernetes: {
        clusterName: 'production',
        namespace: 'production',
        deployment: 'api',
        container: 'api',
      },
      credentials: {
        github: { reference: 'desktop:github', material: { mode: 'SET', value: 'github-secret' } },
        aws: {
          reference: 'desktop:aws',
          material: {
            mode: 'SET',
            value: JSON.stringify({
              access_key_id: 'ASIAEXAMPLE',
              secret_access_key: 'aws-secret',
              session_token: 'aws-session-token',
            }),
          },
        },
      },
    });

    expect(await screen.findByText('Production')).toBeVisible();
    expect(screen.getByText('accordlock/product · eu-west-1 · production/api')).toBeVisible();
    expect(screen.queryByDisplayValue('github-secret')).not.toBeInTheDocument();
    expect(screen.queryByDisplayValue('aws-secret')).not.toBeInTheDocument();
  });

  it('starts at the first step with a clean form every time it opens', async () => {
    const user = userEvent.setup();
    installElectronMocks([]);
    render(<EnvironmentConnectionsSettings />, { wrapper: IntlTestWrapper });
    await screen.findByText('No environments connected');

    await openEditor(user);
    setField('Name', 'Discarded draft');
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    expectEditorStep(2, 'Source & build');
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    await waitFor(() =>
      expect(screen.queryByRole('heading', { name: 'Connect environment' })).not.toBeInTheDocument()
    );

    await openEditor(user);
    expectEditorStep(1, 'Environment');
    expect(screen.getByLabelText('Name')).toHaveValue('');
    expect(screen.queryByLabelText('Repository')).not.toBeInTheDocument();
  });

  it('keeps every stored credential when an edited secret field is left blank', async () => {
    const user = userEvent.setup();
    const savedProfile = profile();
    const { save } = installElectronMocks([savedProfile]);
    render(<EnvironmentConnectionsSettings />, { wrapper: IntlTestWrapper });
    await screen.findByText('Production');

    await user.click(screen.getByRole('button', { name: 'More actions for Production' }));
    await user.click(await screen.findByRole('menuitem', { name: 'Edit' }));
    expect(screen.getByRole('heading', { name: 'Edit environment' })).toBeVisible();

    const dialog = screen.getByRole('dialog');
    expectEditorStep(1, 'Environment');
    expect(within(dialog).queryByLabelText('Fine-grained GitHub token')).not.toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Continue' }));

    expectEditorStep(2, 'Source & build');
    expect(within(dialog).getByLabelText('Fine-grained GitHub token')).toHaveValue('');
    expect(within(dialog).getByRole('button', { name: 'Continue' })).toBeEnabled();
    await user.click(within(dialog).getByRole('button', { name: 'Continue' }));

    expectEditorStep(3, 'Image registry');
    expect(within(dialog).getByLabelText('Temporary access key ID')).toHaveValue('');
    expect(within(dialog).getByLabelText('Temporary secret access key')).toHaveValue('');
    expect(within(dialog).getByLabelText('Session token')).toHaveValue('');
    expect(within(dialog).getByRole('button', { name: 'Continue' })).toBeEnabled();
    await user.click(within(dialog).getByRole('button', { name: 'Continue' }));

    expectEditorStep(4, 'Deployment target');
    await user.click(within(dialog).getByRole('button', { name: 'Save environment' }));

    await waitFor(() => expect(save).toHaveBeenCalledOnce());
    expect(save.mock.calls[0]?.[0]).toMatchObject({
      id: PROFILE_ID,
      credentials: {
        github: { material: { mode: 'KEEP' } },
        aws: { material: { mode: 'KEEP' } },
      },
    });
    expect(JSON.stringify(save.mock.calls[0]?.[0])).not.toContain('undefined');
  });

  it('requires replacement credentials when an edited provider route changes', async () => {
    const user = userEvent.setup();
    const { save } = installElectronMocks([profile()]);
    render(<EnvironmentConnectionsSettings />, { wrapper: IntlTestWrapper });
    await screen.findByText('Production');

    await user.click(screen.getByRole('button', { name: 'More actions for Production' }));
    await user.click(await screen.findByRole('menuitem', { name: 'Edit' }));
    const dialog = screen.getByRole('dialog');
    await user.click(within(dialog).getByRole('button', { name: 'Continue' }));

    setField('Repository', 'accordlock/product-v2');
    expect(within(dialog).getByText('Enter a new token for this repository.')).toBeVisible();
    expect(within(dialog).getByRole('button', { name: 'Continue' })).toBeDisabled();
    setField('Fine-grained GitHub token', 'replacement-github-secret');
    await user.click(within(dialog).getByRole('button', { name: 'Continue' }));

    setField('ECR repository', 'services/api-v2');
    expect(
      within(dialog).getByText('Enter new temporary AWS credentials for this registry.')
    ).toBeVisible();
    expect(within(dialog).getByRole('button', { name: 'Continue' })).toBeDisabled();
    setField('Temporary access key ID', 'ASIAREPLACEMENT');
    setField('Temporary secret access key', 'replacement-aws-secret');
    expect(within(dialog).getByRole('button', { name: 'Continue' })).toBeDisabled();
    setField('Session token', 'replacement-session-token');
    await user.click(within(dialog).getByRole('button', { name: 'Continue' }));
    await user.click(within(dialog).getByRole('button', { name: 'Save environment' }));

    await waitFor(() => expect(save).toHaveBeenCalledOnce());
    expect(save.mock.calls[0]?.[0]).toMatchObject({
      id: PROFILE_ID,
      github: { repository: 'accordlock/product-v2' },
      aws: { ecrRepository: 'services/api-v2' },
      credentials: {
        github: { material: { mode: 'SET', value: 'replacement-github-secret' } },
        aws: { material: { mode: 'SET' } },
      },
    });
    expect(save.mock.calls[0]?.[0].credentials.aws.material).toEqual({
      mode: 'SET',
      value: JSON.stringify({
        access_key_id: 'ASIAREPLACEMENT',
        secret_access_key: 'replacement-aws-secret',
        session_token: 'replacement-session-token',
      }),
    });
  });

  it('refuses long-lived AWS key pairs without a session token', async () => {
    const user = userEvent.setup();
    installElectronMocks([]);
    render(<EnvironmentConnectionsSettings />, { wrapper: IntlTestWrapper });
    await screen.findByText('No environments connected');

    await openEditor(user);
    setField('Name', 'Production');
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    setField('Repository', 'accordlock/product');
    setField('Fine-grained GitHub token', 'github-secret');
    await user.click(screen.getByRole('button', { name: 'Continue' }));

    setField('AWS account ID', '123456789012');
    setField('Region', 'eu-west-1');
    setField('ECR repository', 'services/api');
    setField('Temporary access key ID', 'AKIALONGTERM');
    setField('Temporary secret access key', 'long-lived-secret');

    expect(
      screen.getByText(
        'Paste temporary credentials from AWS CLI or SSO. A session token is required.'
      )
    ).toBeVisible();
    expect(screen.getByRole('button', { name: 'Continue' })).toBeDisabled();
  });

  it('runs the versioned preflight and exports the exact verified receipt', async () => {
    const user = userEvent.setup();
    const { run, exportReceipt } = installElectronMocks([profile()]);
    render(<EnvironmentConnectionsSettings />, { wrapper: IntlTestWrapper });
    await screen.findByText('Production');

    await user.click(screen.getByRole('button', { name: 'Verify' }));
    expect(screen.getByRole('heading', { name: 'Verify deployment' })).toBeVisible();
    setField('Pull request', 'https://github.com/accordlock/product/pull/42');
    setField('Build run', 'https://github.com/accordlock/product/actions/runs/123');
    setField('Image digest', digest('a'));
    await user.click(screen.getByRole('button', { name: 'Run checks' }));

    await waitFor(() =>
      expect(run).toHaveBeenCalledWith({
        protocol: 'accordlock.deployment-preflight.v1',
        schemaVersion: 1,
        profileId: PROFILE_ID,
        pullRequestUrl: 'https://github.com/accordlock/product/pull/42',
        buildRunUrl: 'https://github.com/accordlock/product/actions/runs/123',
        imageDigest: digest('a'),
      })
    );
    expect(await screen.findByRole('heading', { name: 'Checks passed' })).toBeVisible();

    await user.click(screen.getByRole('button', { name: 'Export receipt' }));
    await waitFor(() => expect(exportReceipt).toHaveBeenCalledOnce());
    expect(exportReceipt).toHaveBeenCalledWith(passed.receiptHash);
  });

  it('opens one environment history and exports its portable package', async () => {
    const user = userEvent.setup();
    const { listHistory, exportReceipt } = installElectronMocks([profile()]);
    const archived: DeploymentPreflightReceiptArchiveSummary = {
      checkId: '33333333-3333-4333-8333-333333333333',
      receiptHash: digest('b'),
      packageDigest: digest('c'),
      environmentId: PROFILE_ID,
      outcome: 'PASSED',
      completedAt: 1_800_000_001,
      validUntil: 1_800_000_060,
      repository: 'accordlock/product',
      imageDigest: digest('5'),
      clusterIdentity: 'arn:aws:eks:eu-west-1:123456789012:cluster/production',
      namespace: 'production',
      deployment: 'api',
      archivedAt: 1_800_000_002,
    };
    listHistory.mockResolvedValue([archived]);
    render(<EnvironmentConnectionsSettings />, { wrapper: IntlTestWrapper });
    await screen.findByText('Production');

    await user.click(screen.getByRole('button', { name: 'More actions for Production' }));
    await user.click(await screen.findByRole('menuitem', { name: 'Check history' }));

    expect(await screen.findByRole('heading', { name: 'Check history' })).toBeVisible();
    expect(listHistory).toHaveBeenCalledWith(PROFILE_ID);
    const historyDialog = screen.getByRole('dialog');
    expect(within(historyDialog).getByText('accordlock/product')).toBeVisible();
    expect(within(historyDialog).getByText(/production\/api/)).toBeVisible();
    await user.click(within(historyDialog).getByRole('button', { name: 'Export' }));
    await waitFor(() => expect(exportReceipt).toHaveBeenCalledWith(archived.receiptHash));
  });
});
