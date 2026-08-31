import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AccordLockEnvironmentProfileView } from '../accordlock/environmentProfileIpc';
import type { AccordLockProject } from '../acp/projects';
import { IntlTestWrapper } from '../i18n/test-utils';
import Hub from './Hub';

const ENVIRONMENT_ID = '11111111-1111-4111-8111-111111111111';
const { listProjectsMock } = vi.hoisted(() => ({ listProjectsMock: vi.fn() }));

vi.mock('../acp/projects', async (importOriginal) => {
  const original = await importOriginal<typeof import('../acp/projects')>();
  return { ...original, listProjects: listProjectsMock };
});

vi.mock('../utils/workingDir', () => ({
  getInitialWorkingDir: () => 'C:\\Work\\Product',
}));

vi.mock('./ConfigContext', () => ({
  useConfig: () => ({ extensionsList: [] }),
}));

vi.mock('./ChatInput', () => ({
  default: () => <textarea aria-label="Task" />,
}));

vi.mock('./ChatInputCard', () => ({
  ChatInputCard: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

vi.mock('./projects/ProjectPicker', () => ({
  ProjectPicker: () => <span>Product project</span>,
}));

vi.mock('./accordlock/DeploymentPreflightDialog', () => ({
  DeploymentPreflightDialog: ({
    open,
    environment,
    candidateDefaults,
  }: {
    open: boolean;
    environment: { name: string; repository: string; target: string };
    candidateDefaults?: { buildRunUrl: string; imageDigest: string };
  }) =>
    open ? (
      <div role="dialog" aria-label="Deployment check">
        <span>{environment.name}</span>
        <span>{environment.repository}</span>
        <span>{environment.target}</span>
        {candidateDefaults ? <span>{candidateDefaults.buildRunUrl}</span> : null}
        {candidateDefaults ? <span>{candidateDefaults.imageDigest}</span> : null}
      </div>
    ) : null,
}));

function project(deploymentEnvironmentId?: string): AccordLockProject {
  return {
    id: 'product',
    title: 'Product',
    description: '',
    instructions: '',
    workingDirs: ['C:\\Work\\Product'],
    archived: false,
    ...(deploymentEnvironmentId ? { deploymentEnvironmentId } : {}),
    sourcePath: 'projects/product.md',
    writable: true,
    properties: {
      title: 'Product',
      workingDirs: ['C:\\Work\\Product'],
      ...(deploymentEnvironmentId ? { deploymentEnvironmentId } : {}),
    },
  };
}

function environment(enrolled = true): AccordLockEnvironmentProfileView {
  return {
    id: ENVIRONMENT_ID,
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
      clusterName: 'production-eks',
      namespace: 'production',
      deployment: 'api',
      container: 'api',
    },
    credentialsConfigured: { github: true, aws: true },
    status: 'VERIFIED',
    createdAt: 1_800_000_000,
    updatedAt: 1_800_000_000,
    verifiedAt: 1_800_000_000,
    failedAt: null,
    failureCode: null,
    ciTrust: enrolled
      ? {
          status: 'ENROLLED',
          buildAuthorityFingerprint: `sha256:${'1'.repeat(64)}`,
          artifactAuthorityFingerprint: `sha256:${'2'.repeat(64)}`,
        }
      : { status: 'UNENROLLED' },
  };
}

describe('Hub deployment preflight entry', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    Object.assign(window.electron, {
      listAccordLockEnvironmentProfiles: vi.fn().mockResolvedValue([environment()]),
    });
  });

  it('offers to connect an environment when the selected project has none', async () => {
    const user = userEvent.setup();
    const setView = vi.fn();
    listProjectsMock.mockResolvedValue([project()]);

    render(<Hub setView={setView} />, { wrapper: IntlTestWrapper });

    expect(await screen.findByText('Product project')).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Verify deployment' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Connect environment' }));
    expect(setView).toHaveBeenCalledWith('settings', { section: 'environments' });
  });

  it('opens the exact environment bound to the selected project', async () => {
    const user = userEvent.setup();
    listProjectsMock.mockResolvedValue([project(ENVIRONMENT_ID)]);

    render(<Hub setView={vi.fn()} />, { wrapper: IntlTestWrapper });

    await user.click(await screen.findByRole('button', { name: 'Verify deployment' }));
    const dialog = screen.getByRole('dialog', { name: 'Deployment check' });
    expect(dialog).toHaveTextContent('Production');
    expect(dialog).toHaveTextContent('accordlock/product');
    expect(dialog).toHaveTextContent('production-eks · production/api:api');
  });

  it('imports build proof before exposing deployment verification', async () => {
    const user = userEvent.setup();
    const importProof = vi.fn().mockResolvedValue({
      status: 'ENROLLED',
      environmentId: ENVIRONMENT_ID,
      repository: 'accordlock/product',
      workflow: '.github/workflows/release.yml',
      runId: 42,
      commit: 'a'.repeat(40),
      imageDigest: `sha256:${'b'.repeat(64)}`,
      buildAuthorityFingerprint: `sha256:${'1'.repeat(64)}`,
      artifactAuthorityFingerprint: `sha256:${'2'.repeat(64)}`,
    });
    const listProfiles = vi
      .fn()
      .mockResolvedValueOnce([environment(false)])
      .mockResolvedValueOnce([environment(true)]);
    Object.assign(window.electron, {
      importAccordLockDeploymentPreflightCiEvidence: importProof,
      listAccordLockEnvironmentProfiles: listProfiles,
    });
    listProjectsMock.mockResolvedValue([project(ENVIRONMENT_ID)]);

    render(<Hub setView={vi.fn()} />, { wrapper: IntlTestWrapper });

    await user.click(await screen.findByRole('button', { name: 'Add build proof' }));
    expect(importProof).toHaveBeenCalledWith(ENVIRONMENT_ID);
    expect(await screen.findByRole('button', { name: 'Verify deployment' })).toBeVisible();
    const dialog = screen.getByRole('dialog', { name: 'Deployment check' });
    expect(dialog).toHaveTextContent('https://github.com/accordlock/product/actions/runs/42');
    expect(dialog).toHaveTextContent(`sha256:${'b'.repeat(64)}`);
  });
});
