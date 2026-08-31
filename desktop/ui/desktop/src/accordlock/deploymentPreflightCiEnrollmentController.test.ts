import { createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import type {
  AccordLockCiAuthorityEnrollment,
  AccordLockCiAuthorityStatus,
} from '../accordlockPreflightTrustStore';
import type { AccordLockEnvironmentProfileExecutionBundle } from './environmentProfiles';
import type { DeploymentPreflightCiEvidenceImportResult } from './deploymentPreflightCiEvidence';
import {
  AccordLockDeploymentPreflightCiEnrollmentController,
  type DeploymentPreflightCiEnrollmentControllerOptions,
  type DeploymentPreflightCiEnrollmentPreview,
} from './deploymentPreflightCiEnrollmentController';

const BUILD_DOMAIN = Buffer.from('accordlock:v1:build-trust-record\0', 'utf8');
const ARTIFACT_DOMAIN = Buffer.from('accordlock:v1:artifact-trust-record\0', 'utf8');
const ENVIRONMENT_ID = '44444444-4444-4444-8444-444444444444';

afterEach(() => {
  vi.useRealTimers();
});

function digest(seed: string): string {
  return `sha256:${createHash('sha256').update(seed, 'utf8').digest('hex')}`;
}

function authority(): Readonly<{ privateKey: KeyObject; publicKey: string }> {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const encoded = publicKey.export({ format: 'der', type: 'spki' });
  return {
    privateKey,
    publicKey: Buffer.from(encoded.subarray(encoded.length - 32)).toString('base64url'),
  };
}

function signRecord(domain: Buffer, payload: unknown, privateKey: KeyObject): string {
  const encoded = Buffer.from(JSON.stringify(payload), 'utf8');
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(encoded.length));
  const hash = createHash('sha256').update(domain).update(length).update(encoded).digest();
  return sign(null, hash, privateKey).toString('base64url');
}

function evidenceFixture(
  overrides: Readonly<{
    owner?: string;
    repository?: string;
    workflow?: string;
    accountId?: string;
    region?: string;
    ecrRepository?: string;
    runId?: number;
    commit?: string;
    imageDigest?: string;
  }> = {}
) {
  const owner = overrides.owner ?? 'accordlock';
  const repository = overrides.repository ?? 'product';
  const workflow = overrides.workflow ?? '.github/workflows/release.yml';
  const accountId = overrides.accountId ?? '123456789012';
  const region = overrides.region ?? 'eu-west-3';
  const ecrRepository = overrides.ecrRepository ?? 'product/api';
  const runId = overrides.runId ?? 987_654;
  const commit = overrides.commit ?? 'a'.repeat(40);
  const imageDigest = overrides.imageDigest ?? digest('image');
  const buildAuthority = authority();
  const artifactAuthority = authority();
  const buildPayload = {
    schema_version: 1,
    key_id: `build-${ENVIRONMENT_ID}`,
    repository: `${owner}/${repository}`,
    workflow_ref: workflow,
    run_id: runId,
    commit_sha: commit,
    input_manifest_root: digest('manifest'),
    output_digest: imageDigest,
    issued_at: 900,
    expires_at: 1_100,
  };
  const artifactPayload = {
    schema_version: 1,
    key_id: `artifact-${ENVIRONMENT_ID}`,
    registry_id: accountId,
    region,
    repository_name: ecrRepository,
    image_digest: imageDigest,
    source_repository: `${owner}/${repository}`,
    commit_sha: commit,
    source_run_id: runId,
    signature_valid: true,
    quarantined: false,
    issued_at: 900,
    expires_at: 1_100,
  };
  return {
    schema_version: 1,
    bundle_type: 'ACCORDLOCK_DEPLOYMENT_PREFLIGHT_CI_EVIDENCE',
    environment_id: ENVIRONMENT_ID,
    github: { owner, repository, workflow_ref: workflow },
    ecr: { registry_id: accountId, region, repository: ecrRepository },
    build_authority: {
      algorithm: 'Ed25519',
      key_id: `build-${ENVIRONMENT_ID}`,
      public_key: buildAuthority.publicKey,
    },
    artifact_authority: {
      algorithm: 'Ed25519',
      key_id: `artifact-${ENVIRONMENT_ID}`,
      public_key: artifactAuthority.publicKey,
    },
    build_record: {
      payload: buildPayload,
      signature: signRecord(BUILD_DOMAIN, buildPayload, buildAuthority.privateKey),
    },
    artifact_record: {
      payload: artifactPayload,
      signature: signRecord(ARTIFACT_DOMAIN, artifactPayload, artifactAuthority.privateKey),
    },
  };
}

function executionBundle(
  profileDigest = digest('profile'),
  overrides: Readonly<{
    repository?: string;
    workflow?: string;
    accountId?: string;
    region?: string;
    ecrRepository?: string;
  }> = {}
): AccordLockEnvironmentProfileExecutionBundle {
  return {
    runnerProfile: {
      schema_version: 1,
      profile_id: ENVIRONMENT_ID,
      profile_digest: profileDigest,
      credential_revision: '55555555-5555-4555-8555-555555555555',
      runner_mode: 'LOCAL_BUNDLED',
      github: {
        repository: overrides.repository ?? 'accordlock/product',
        workflow: overrides.workflow ?? '.github/workflows/release.yml',
        credential_source: 'github-production',
      },
      aws: {
        accountId: overrides.accountId ?? '123456789012',
        region: overrides.region ?? 'eu-west-3',
        ecrRepository: overrides.ecrRepository ?? 'product/api',
        credential_source: 'aws-production',
      },
      kubernetes: {
        clusterName: 'production',
        namespace: 'payments',
        deployment: 'api',
        container: 'api',
        expectedEndpoint: 'https://cluster.example.com',
      },
    },
    credentialMaterial: {
      github: 'TOP-SECRET-GITHUB',
      aws: 'TOP-SECRET-AWS',
    },
  };
}

function enrolledStatus(bundle: ReturnType<typeof evidenceFixture>): AccordLockCiAuthorityStatus {
  const buildPublic = bundle.build_authority.public_key;
  const artifactPublic = bundle.artifact_authority.public_key;
  return {
    status: 'ENROLLED',
    environmentId: ENVIRONMENT_ID,
    build: {
      keyId: bundle.build_authority.key_id,
      publicKey: buildPublic,
      publicKeyHash: `sha256:${createHash('sha256')
        .update(Buffer.from(buildPublic, 'base64url'))
        .digest('hex')}`,
    },
    artifact: {
      keyId: bundle.artifact_authority.key_id,
      publicKey: artifactPublic,
      publicKeyHash: `sha256:${createHash('sha256')
        .update(Buffer.from(artifactPublic, 'base64url'))
        .digest('hex')}`,
    },
  };
}

type Harness = Readonly<{
  controller: AccordLockDeploymentPreflightCiEnrollmentController;
  loadExecutionBundle: ReturnType<typeof vi.fn>;
  initialize: ReturnType<typeof vi.fn>;
  getStatus: ReturnType<typeof vi.fn>;
  enroll: ReturnType<typeof vi.fn>;
  importerFactory: ReturnType<typeof vi.fn>;
  importBundle: ReturnType<typeof vi.fn>;
  confirm: ReturnType<typeof vi.fn>;
}>;

function harness(
  options: Readonly<{
    load?: () => Promise<AccordLockEnvironmentProfileExecutionBundle>;
    confirm?: (preview: DeploymentPreflightCiEnrollmentPreview) => Promise<boolean>;
    status?: () => Promise<AccordLockCiAuthorityStatus>;
    enroll?: (environmentId: unknown, enrollment: unknown) => Promise<AccordLockCiAuthorityStatus>;
    importBundle?: (
      value: unknown,
      signal?: globalThis.AbortSignal
    ) => Promise<DeploymentPreflightCiEvidenceImportResult>;
    timeoutMilliseconds?: number;
    log?: string[];
  }> = {}
): Harness {
  const log = options.log;
  const loadExecutionBundle = vi.fn(async () => {
    log?.push('load');
    return options.load ? options.load() : executionBundle();
  });
  const initialize = vi.fn(async (_environmentId: string, _signal: globalThis.AbortSignal) => {
    log?.push('initialize');
  });
  const getStatus = vi.fn(async () => {
    log?.push('status');
    return options.status
      ? options.status()
      : ({ status: 'UNENROLLED', environmentId: ENVIRONMENT_ID } as const);
  });
  const enroll = vi.fn(async (environmentId: unknown, enrollment: unknown) => {
    log?.push('enroll');
    if (options.enroll) return options.enroll(environmentId, enrollment);
    const input = enrollment as AccordLockCiAuthorityEnrollment;
    return {
      status: 'ENROLLED',
      environmentId: environmentId as string,
      build: input.build,
      artifact: input.artifact,
    } as AccordLockCiAuthorityStatus;
  });
  const importBundle = vi.fn(
    async (
      value: unknown,
      signal?: globalThis.AbortSignal
    ): Promise<DeploymentPreflightCiEvidenceImportResult> => {
      log?.push('import');
      if (options.importBundle) return options.importBundle(value, signal);
      const input = value as ReturnType<typeof evidenceFixture>;
      const status = enrolledStatus(input);
      if (status.status !== 'ENROLLED') throw new Error('Test enrollment is unavailable');
      return {
        environmentId: ENVIRONMENT_ID,
        runId: input.build_record.payload.run_id,
        imageDigest: input.artifact_record.payload.image_digest,
        buildRecordPath: 'trusted/build.json',
        artifactRecordPath: 'trusted/artifact.json',
        enrollment: {
          environmentId: ENVIRONMENT_ID,
          build: status.build,
          artifact: status.artifact,
        },
      };
    }
  );
  const importerFactory = vi.fn(() => ({ importBundle }));
  const confirm = vi.fn(async (value: DeploymentPreflightCiEnrollmentPreview) => {
    log?.push('confirm');
    return options.confirm ? options.confirm(value) : true;
  });
  const controllerOptions: DeploymentPreflightCiEnrollmentControllerOptions = {
    environmentStore: { loadExecutionBundle },
    initializeEnvironmentTrust: initialize,
    trustStore: { getCiAuthorityStatus: getStatus, enrollCiAuthorities: enroll },
    trustedStateRoot: path.join(os.tmpdir(), 'accordlock-trusted-state'),
    importerFactory,
    confirm,
    timeoutMilliseconds: options.timeoutMilliseconds ?? 5_000,
    nowSeconds: () => 1_000,
  };
  return {
    controller: new AccordLockDeploymentPreflightCiEnrollmentController(controllerOptions),
    loadExecutionBundle,
    initialize,
    getStatus,
    enroll,
    importerFactory,
    importBundle,
    confirm,
  };
}

describe('Deployment Preflight CI enrollment controller', () => {
  it('returns CANCELED without initializing trust, importing records, or enrolling roots', async () => {
    const test = harness({ confirm: async () => false });
    await expect(
      test.controller.importForEnvironment(ENVIRONMENT_ID, evidenceFixture())
    ).resolves.toEqual({ status: 'CANCELED', environmentId: ENVIRONMENT_ID });
    expect(test.initialize).not.toHaveBeenCalled();
    expect(test.getStatus).not.toHaveBeenCalled();
    expect(test.importerFactory).not.toHaveBeenCalled();
    expect(test.importBundle).not.toHaveBeenCalled();
    expect(test.enroll).not.toHaveBeenCalled();
  });

  it('rejects a valid package whose routes substitute the saved environment', async () => {
    const test = harness();
    await expect(
      test.controller.importForEnvironment(
        ENVIRONMENT_ID,
        evidenceFixture({ owner: 'attacker', repository: 'replacement' })
      )
    ).rejects.toThrow('does not match');
    expect(test.confirm).not.toHaveBeenCalled();
    expect(test.initialize).not.toHaveBeenCalled();
  });

  it('rejects profile changes after confirmation and after record import', async () => {
    let calls = 0;
    const beforeMutation = harness({
      load: async () => executionBundle(++calls === 1 ? digest('profile-a') : digest('profile-b')),
    });
    await expect(
      beforeMutation.controller.importForEnvironment(ENVIRONMENT_ID, evidenceFixture())
    ).rejects.toThrow('Environment changed');
    expect(beforeMutation.initialize).not.toHaveBeenCalled();

    calls = 0;
    const afterImport = harness({
      load: async () => executionBundle(++calls < 4 ? digest('profile-a') : digest('profile-b')),
    });
    await expect(
      afterImport.controller.importForEnvironment(ENVIRONMENT_ID, evidenceFixture())
    ).rejects.toThrow('Environment changed');
    expect(afterImport.importBundle).toHaveBeenCalledOnce();
    expect(afterImport.enroll).not.toHaveBeenCalled();
  });

  it('leaves imported records untrusted when a concurrent authority rotation wins', async () => {
    const test = harness({
      enroll: async () => {
        throw new Error('CI authority rotation requires an explicit rotation workflow');
      },
    });
    await expect(
      test.controller.importForEnvironment(ENVIRONMENT_ID, evidenceFixture())
    ).rejects.toThrow('explicit rotation workflow');
    expect(test.importBundle).toHaveBeenCalledOnce();
    expect(test.enroll).toHaveBeenCalledOnce();
  });

  it('is retry-safe and single-flights an identical package per environment', async () => {
    const bundle = evidenceFixture();
    let status: AccordLockCiAuthorityStatus = {
      status: 'UNENROLLED',
      environmentId: ENVIRONMENT_ID,
    };
    const test = harness({
      status: async () => status,
      enroll: async (_environmentId, enrollment) => {
        const input = enrollment as AccordLockCiAuthorityEnrollment;
        status = { status: 'ENROLLED', ...input };
        return status;
      },
    });
    const first = await test.controller.importForEnvironment(ENVIRONMENT_ID, bundle);
    const second = await test.controller.importForEnvironment(ENVIRONMENT_ID, bundle);
    expect(second).toEqual(first);
    expect(test.importBundle).toHaveBeenCalledTimes(2);

    let release: ((value: boolean) => void) | undefined;
    const gated = harness({
      confirm: () => new Promise<boolean>((resolve) => (release = resolve)),
    });
    const concurrentA = gated.controller.importForEnvironment(ENVIRONMENT_ID, bundle);
    const concurrentB = gated.controller.importForEnvironment(ENVIRONMENT_ID, bundle);
    expect(concurrentB).toBe(concurrentA);
    await vi.waitFor(() => expect(gated.confirm).toHaveBeenCalledOnce());
    release?.(true);
    await expect(Promise.all([concurrentA, concurrentB])).resolves.toHaveLength(2);
    expect(gated.importBundle).toHaveBeenCalledOnce();
  });

  it('times out a stalled confirmation and performs no mutation', async () => {
    vi.useFakeTimers();
    const test = harness({
      confirm: () => new Promise<boolean>(() => undefined),
      timeoutMilliseconds: 100,
    });
    const operation = test.controller.importForEnvironment(ENVIRONMENT_ID, evidenceFixture());
    await vi.advanceTimersByTimeAsync(101);
    await expect(operation).rejects.toThrow('timed out');
    expect(test.initialize).not.toHaveBeenCalled();
    expect(test.importBundle).not.toHaveBeenCalled();
    expect(test.enroll).not.toHaveBeenCalled();
  });

  it('shows one concise public preview with exact provenance and fingerprints', async () => {
    const bundle = evidenceFixture();
    const status = enrolledStatus(bundle);
    let captured: DeploymentPreflightCiEnrollmentPreview | undefined;
    const test = harness({
      confirm: async (value) => {
        captured = value;
        return false;
      },
    });
    await test.controller.importForEnvironment(ENVIRONMENT_ID, bundle);
    expect(captured).toEqual({
      title: 'Trust this CI provenance?',
      environmentId: ENVIRONMENT_ID,
      repository: 'accordlock/product',
      workflow: '.github/workflows/release.yml',
      runId: 987_654,
      commit: 'a'.repeat(40),
      imageDigest: digest('image'),
      registry: '123456789012.dkr.ecr.eu-west-3.amazonaws.com/product/api',
      buildAuthorityFingerprint: status.status === 'ENROLLED' ? status.build.publicKeyHash : '',
      artifactAuthorityFingerprint:
        status.status === 'ENROLLED' ? status.artifact.publicKeyHash : '',
      note: 'Future key changes require an explicit rotation.',
    });
    expect(JSON.stringify(captured)).not.toContain('TOP-SECRET');
    expect(JSON.stringify(captured)).not.toContain('credential');
  });

  it('performs the successful mutation sequence with derived trusted paths', async () => {
    const log: string[] = [];
    const bundle = evidenceFixture();
    const test = harness({ log });
    const result = await test.controller.importForEnvironment(ENVIRONMENT_ID, bundle);
    expect(result).toMatchObject({
      status: 'ENROLLED',
      environmentId: ENVIRONMENT_ID,
      repository: 'accordlock/product',
      runId: 987_654,
      commit: 'a'.repeat(40),
      imageDigest: digest('image'),
    });
    expect(log).toEqual([
      'load',
      'confirm',
      'load',
      'initialize',
      'status',
      'load',
      'import',
      'load',
      'enroll',
      'load',
    ]);
    const importerOptions = test.importerFactory.mock.calls[0][0];
    expect(importerOptions.buildRecordsDirectory).toBe(
      path.join(
        os.tmpdir(),
        'accordlock-trusted-state',
        'environments',
        ENVIRONMENT_ID,
        'build-trust'
      )
    );
    expect(importerOptions.artifactRecordsDirectory).toBe(
      path.join(
        os.tmpdir(),
        'accordlock-trusted-state',
        'environments',
        ENVIRONMENT_ID,
        'artifact-trust'
      )
    );
    expect(test.importBundle.mock.calls[0][1]).toBeInstanceOf(globalThis.AbortSignal);
  });
});
