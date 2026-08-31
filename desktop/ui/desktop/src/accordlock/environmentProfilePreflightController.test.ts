import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  AccordLockEnvironmentProfileStore,
  type AccordLockEnvironmentProfileSafeStorage,
} from '../accordlockEnvironmentProfileStore';
import type {
  AccordLockEnvironmentProfileExecutionBundle,
  AccordLockEnvironmentProfileInput,
} from './environmentProfiles';
import {
  AccordLockEnvironmentProfilePreflightController,
  type AccordLockTrustedPreflightReceiptArchive,
  type AccordLockTrustedPreflightRunner,
} from './environmentProfilePreflightController';
import type { DeploymentPreflightReceiptArchiveSummary } from './deploymentPreflightReceiptArchive';
import {
  ACCORDLOCK_DEPLOYMENT_PREFLIGHT_PROTOCOL,
  type DeploymentPreflightInput,
  type DeploymentPreflightRunnerRequest,
} from './deploymentPreflight';

const directories: string[] = [];
const digest = (character: string) => `sha256:${character.repeat(64)}`;
const runnerMetadata = {
  receiptPublicKey: 'A'.repeat(43),
  receiptKeyId: 'preflight-receipts-v1',
  verificationProfile: { fixture: true },
} as const;

const safeStorage: AccordLockEnvironmentProfileSafeStorage = {
  isEncryptionAvailable: () => true,
  encryptString: (plaintext) => Buffer.from(plaintext, 'utf8').reverse(),
  decryptString: (ciphertext) => Buffer.from(ciphertext).reverse().toString('utf8'),
};

function profileInput(): AccordLockEnvironmentProfileInput {
  return {
    id: null,
    name: 'Production delivery',
    runner: { mode: 'LOCAL_BUNDLED' },
    github: { repository: 'accordlock/product', workflow: '.github/workflows/release.yml' },
    aws: { accountId: '123456789012', region: 'eu-west-3', ecrRepository: 'accordlock/app' },
    kubernetes: {
      clusterName: 'production',
      namespace: 'accordlock',
      deployment: 'desktop-api',
      container: 'api',
    },
    credentials: {
      github: { reference: 'github-production', material: { mode: 'SET', value: 'github-secret' } },
      aws: { reference: 'aws-production', material: { mode: 'SET', value: 'aws-secret' } },
    },
  };
}

function preflightInput(profileId: string): DeploymentPreflightInput {
  return {
    protocol: ACCORDLOCK_DEPLOYMENT_PREFLIGHT_PROTOCOL,
    schemaVersion: 1,
    profileId,
    pullRequestUrl: 'https://github.com/accordlock/product/pull/42',
    buildRunUrl: 'https://github.com/accordlock/product/actions/runs/987',
    imageDigest: digest('5'),
  };
}

function receipt(
  request: DeploymentPreflightRunnerRequest,
  bundle: AccordLockEnvironmentProfileExecutionBundle,
  outcome: 'PASSED' | 'INDETERMINATE' = 'PASSED'
): Record<string, unknown> {
  const determinate = outcome === 'PASSED';
  return {
    payload: {
      schema_version: 2,
      check_id: request.check_id,
      request_id: '22222222-2222-4222-8222-222222222222',
      environment_id: request.environment_id,
      environment_profile_hash: request.environment_profile_hash,
      runner_id: '44444444-4444-4444-8444-444444444444',
      runner_registration_hash: digest('2'),
      dispatch_hash: digest('3'),
      ...(determinate ? { policy_decision_hash: digest('4') } : {}),
      outcome,
      reason_codes: [determinate ? 'ALLOWED' : 'PROVIDER_UNAVAILABLE'],
      candidate: {
        repository: bundle.runnerProfile.github.repository,
        pull_number: request.pull_number,
        commit_sha: 'a'.repeat(40),
        workflow_ref: bundle.runnerProfile.github.workflow,
        actions_run_id: request.actions_run_id,
        ecr_repository: `${bundle.runnerProfile.aws.accountId}.dkr.ecr.${bundle.runnerProfile.aws.region}.amazonaws.com/${bundle.runnerProfile.aws.ecrRepository}`,
        image_digest: request.image_digest,
      },
      target: {
        cluster_identity: `arn:aws:eks:${bundle.runnerProfile.aws.region}:${bundle.runnerProfile.aws.accountId}:cluster/${bundle.runnerProfile.kubernetes.clusterName}`,
        cluster_endpoint: bundle.runnerProfile.kubernetes.expectedEndpoint,
        cluster_ca_hash: digest('d'),
        namespace: bundle.runnerProfile.kubernetes.namespace,
        deployment: bundle.runnerProfile.kubernetes.deployment,
        deployment_uid: '55555555-5555-4555-8555-555555555555',
        resource_version: '12345',
        observed_image_digest: request.image_digest,
        container: bundle.runnerProfile.kubernetes.container,
      },
      checks: ['CODE_REVIEW', 'BUILD', 'IMAGE', 'TARGET'].map((kind) => ({
        kind,
        status: outcome,
        summary: determinate ? 'Verified' : 'Provider unavailable',
        ...(!determinate ? { reason_code: 'PROVIDER_UNAVAILABLE' } : {}),
      })),
      ...(determinate
        ? {
            evidence_root: digest('a'),
            valid_until: 1_800_000_060,
            evaluation_attestation: { fixture: true },
          }
        : {}),
      started_at: 1_800_000_000,
      completed_at: 1_800_000_001,
      effect: 'NONE',
      deployment_performed: false,
    },
    receipt_hash: digest('b'),
    signer_key_id: 'preflight-receipts-v1',
    receipt_public_key_hash: digest('c'),
    signature: 'A'.repeat(86),
  };
}

function runnerWith(
  run: AccordLockTrustedPreflightRunner['run']
): AccordLockTrustedPreflightRunner {
  return {
    profileHash: async () => digest('9'),
    run,
  };
}

function archiveWith(
  appendVerified: AccordLockTrustedPreflightReceiptArchive['appendVerified'] = async () =>
    ({ receiptHash: digest('b') }) as DeploymentPreflightReceiptArchiveSummary
): AccordLockTrustedPreflightReceiptArchive {
  return { appendVerified };
}

async function fixture() {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'accordlock-preflight-'));
  directories.push(directory);
  const store = new AccordLockEnvironmentProfileStore({
    directory,
    safeStorage,
    nowSeconds: () => 1_800_000_010,
  });
  const saved = await store.save(profileInput(), 'https://api.production.eks.example.com');
  return { saved, store };
}

afterEach(async () => {
  vi.useRealTimers();
  await Promise.all(
    directories.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true }))
  );
});

describe('environment deployment preflight controller', () => {
  it('marks a profile VERIFIED only after a trusted, exact, four-check receipt', async () => {
    const { saved, store } = await fixture();
    const run = vi.fn<AccordLockTrustedPreflightRunner['run']>(async (request, bundle) => ({
      signatureVerified: true,
      receipt: receipt(request, bundle),
      ...runnerMetadata,
    }));
    const runner = runnerWith(run);
    const appendVerified = vi.fn<AccordLockTrustedPreflightReceiptArchive['appendVerified']>(
      async (input) => {
        expect((await store.list())[0]?.status).toBe('SAVED');
        expect(input).toMatchObject({
          signatureVerified: true,
          receiptKeyId: runnerMetadata.receiptKeyId,
        });
        return { receiptHash: digest('b') } as DeploymentPreflightReceiptArchiveSummary;
      }
    );
    const controller = new AccordLockEnvironmentProfilePreflightController(store, {
      runner,
      archive: archiveWith(appendVerified),
      nowSeconds: () => 1_800_000_010,
    });

    const result = await controller.run(preflightInput(saved.id));

    expect(result.outcome).toBe('PASSED');
    expect(result.checks).toHaveLength(4);
    expect(result.checks.every((check) => check.status === 'PASSED')).toBe(true);
    expect(run).toHaveBeenCalledOnce();
    expect(appendVerified).toHaveBeenCalledOnce();
    expect(run.mock.calls[0][0]).toMatchObject({
      environment_profile_hash: digest('9'),
      pull_number: 42,
      actions_run_id: 987,
    });
    expect(await store.list()).toMatchObject([{ status: 'VERIFIED', failureCode: null }]);
    expect(JSON.stringify(result)).not.toContain('secret');
  });

  it('records INDETERMINATE as FAILED and rejects a receipt bound to another profile', async () => {
    const { saved, store } = await fixture();
    const indeterminate = new AccordLockEnvironmentProfilePreflightController(store, {
      runner: runnerWith(async (request, bundle) => ({
        signatureVerified: true,
        receipt: receipt(request, bundle, 'INDETERMINATE'),
        ...runnerMetadata,
      })),
      archive: archiveWith(),
      nowSeconds: () => 1_800_000_010,
    });
    await expect(indeterminate.run(preflightInput(saved.id))).resolves.toMatchObject({
      outcome: 'INDETERMINATE',
    });
    expect(await store.list()).toMatchObject([
      { status: 'FAILED', failureCode: 'PREFLIGHT_INDETERMINATE' },
    ]);

    const mismatch = new AccordLockEnvironmentProfilePreflightController(store, {
      runner: runnerWith(async (request, bundle) => {
        const original = receipt(request, bundle);
        return {
          signatureVerified: true,
          ...runnerMetadata,
          receipt: {
            ...original,
            payload: {
              ...(original.payload as Record<string, unknown>),
              environment_profile_hash: digest('0'),
            },
          },
        };
      }),
      archive: archiveWith(),
      nowSeconds: () => 1_800_000_010,
    });
    await expect(mismatch.run(preflightInput(saved.id))).rejects.toThrow('could not be verified');
    expect(await store.list()).toMatchObject([
      { status: 'FAILED', failureCode: 'ATTESTATION_MISMATCH' },
    ]);
  });

  it('deduplicates identical work but rejects different selectors while it is running', async () => {
    const { saved, store } = await fixture();
    let releaseRunner: (() => void) | undefined;
    let startedRunner: (() => void) | undefined;
    const started = new Promise<void>((resolve) => {
      startedRunner = resolve;
    });
    const release = new Promise<void>((resolve) => {
      releaseRunner = resolve;
    });
    const runner = runnerWith(async (request, bundle) => {
      startedRunner?.();
      await release;
      return {
        signatureVerified: true,
        receipt: receipt(request, bundle),
        ...runnerMetadata,
      };
    });
    const controller = new AccordLockEnvironmentProfilePreflightController(store, {
      runner,
      archive: archiveWith(),
      nowSeconds: () => 1_800_000_010,
    });
    const first = controller.run(preflightInput(saved.id));
    await started;

    expect(controller.run(preflightInput(saved.id))).toBe(first);
    await expect(
      controller.run({
        ...preflightInput(saved.id),
        pullRequestUrl: 'https://github.com/accordlock/product/pull/43',
      })
    ).rejects.toThrow('different deployment preflight');

    releaseRunner?.();
    await expect(first).resolves.toMatchObject({ outcome: 'PASSED' });
  });

  it('fails closed and does not record success when receipt archiving fails', async () => {
    const { saved, store } = await fixture();
    const controller = new AccordLockEnvironmentProfilePreflightController(store, {
      runner: runnerWith(async (request, bundle) => ({
        signatureVerified: true,
        receipt: receipt(request, bundle),
        ...runnerMetadata,
      })),
      archive: archiveWith(async () => {
        throw new Error('archive unavailable');
      }),
      nowSeconds: () => 1_800_000_010,
    });

    await expect(controller.run(preflightInput(saved.id))).rejects.toThrow('could not be verified');
    expect(await store.list()).toMatchObject([
      { status: 'FAILED', failureCode: 'RUNNER_REJECTED' },
    ]);
  });
});
