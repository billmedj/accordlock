import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import {
  parseAccordLockEnvironmentProfileInput,
  type AccordLockEnvironmentProfileInput,
} from './accordlock/environmentProfiles';
import {
  AccordLockEnvironmentProfileStore,
  type AccordLockEnvironmentProfileSafeStorage,
} from './accordlockEnvironmentProfileStore';

const directories: string[] = [];

const safeStorage: AccordLockEnvironmentProfileSafeStorage = {
  isEncryptionAvailable: () => true,
  encryptString: (plaintext) =>
    Buffer.from(`protected:${Buffer.from(plaintext, 'utf8').toString('base64')}`, 'utf8'),
  decryptString: (ciphertext) => {
    const encoded = ciphertext.toString('utf8');
    if (!encoded.startsWith('protected:')) throw new Error('invalid fixture ciphertext');
    return Buffer.from(encoded.slice('protected:'.length), 'base64').toString('utf8');
  },
};

function input(
  id: string | null = null,
  materialMode: 'SET' | 'KEEP' = 'SET'
): AccordLockEnvironmentProfileInput {
  const material = (value: string) =>
    materialMode === 'SET' ? ({ mode: 'SET', value } as const) : ({ mode: 'KEEP' } as const);
  return {
    id,
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
      github: {
        reference: 'github-production',
        material: material('github-secret-material'),
      },
      aws: { reference: 'aws-production', material: material('aws-secret-material') },
    },
  };
}

async function directory(): Promise<string> {
  const created = await fs.mkdtemp(path.join(os.tmpdir(), 'accordlock-environments-'));
  directories.push(created);
  return created;
}

afterEach(async () => {
  await Promise.all(directories.splice(0).map((entry) => fs.rm(entry, { recursive: true })));
});

describe('environment profile contract', () => {
  it('accepts fixed local-runner routes and rejects renderer-selected runner endpoints', () => {
    expect(parseAccordLockEnvironmentProfileInput(input())).toMatchObject({
      runner: { mode: 'LOCAL_BUNDLED' },
      github: { repository: 'accordlock/product' },
      aws: { accountId: '123456789012' },
      kubernetes: { namespace: 'accordlock' },
    });

    expect(() =>
      parseAccordLockEnvironmentProfileInput({
        ...input(),
        runner: { mode: 'REMOTE', endpoint: 'https://runner.example' },
      })
    ).toThrow('invalid');
    expect(() =>
      parseAccordLockEnvironmentProfileInput({
        ...input(),
        github: { repository: 'accordlock/product', workflow: '../steal.yml' },
      })
    ).toThrow('workflow');
    expect(() =>
      parseAccordLockEnvironmentProfileInput({
        ...input(),
        kubernetes: { ...input().kubernetes, clusterName: 'Production Cluster' },
      })
    ).toThrow('cluster name');
    for (const field of ['namespace', 'deployment', 'container'] as const) {
      expect(() =>
        parseAccordLockEnvironmentProfileInput({
          ...input(),
          kubernetes: { ...input().kubernetes, [field]: 'invalid.with-dot' },
        })
      ).toThrow(field);
    }
  });
});

describe('secure environment profile store', () => {
  it('atomically removes the obsolete Kubernetes credential during v1 migration', async () => {
    const root = await directory();
    const store = new AccordLockEnvironmentProfileStore({ directory: root, safeStorage });
    await store.save(input(), 'https://api.production.eks.example.com');
    const file = path.join(root, 'environment-profiles.v1.bin');
    const current = JSON.parse(safeStorage.decryptString(await fs.readFile(file))) as {
      schemaVersion: number;
      profiles: Array<Record<string, unknown>>;
    };
    const profile = current.profiles[0];
    const kubernetes = profile.kubernetes as Record<string, unknown>;
    const credentials = profile.credentials as Record<string, unknown>;
    current.schemaVersion = 1;
    profile.kubernetes = {
      clusterName: kubernetes.clusterName,
      serverIdentity: 'api.production.eks.example.com',
      namespace: kubernetes.namespace,
      deployment: kubernetes.deployment,
      container: kubernetes.container,
    };
    credentials.kubernetes = {
      reference: 'obsolete-service-account',
      material: 'obsolete-bearer-token',
    };
    await fs.writeFile(file, safeStorage.encryptString(JSON.stringify(current)));

    const restarted = new AccordLockEnvironmentProfileStore({ directory: root, safeStorage });
    await expect(restarted.list()).resolves.toHaveLength(1);
    const migrated = safeStorage.decryptString(await fs.readFile(file));
    expect(JSON.parse(migrated)).toMatchObject({ schemaVersion: 2 });
    expect(migrated).not.toContain('obsolete-bearer-token');
    expect(migrated).not.toContain('obsolete-service-account');
  });

  it('persists encrypted credentials while exposing only non-secret summaries', async () => {
    const root = await directory();
    const store = new AccordLockEnvironmentProfileStore({
      directory: root,
      safeStorage,
      nowSeconds: () => 1_000,
    });

    const saved = await store.save(input(), 'https://api.production.eks.example.com');
    expect(saved).toMatchObject({
      status: 'SAVED',
      credentialsConfigured: { github: true, aws: true },
      verifiedAt: null,
      failedAt: null,
    });
    const rendererProjection = JSON.stringify(saved);
    expect(Object.keys(saved.kubernetes).sort()).toEqual([
      'clusterName',
      'container',
      'deployment',
      'namespace',
    ]);
    expect(rendererProjection).not.toContain('api.production.eks.example.com');
    for (const hidden of [
      'github-production',
      'aws-production',
      'github-secret-material',
      'aws-secret-material',
    ]) {
      expect(rendererProjection).not.toContain(hidden);
    }

    const disk = await fs.readFile(path.join(root, 'environment-profiles.v1.bin'));
    expect(disk.toString('utf8')).not.toContain('github-secret-material');
    const restarted = new AccordLockEnvironmentProfileStore({
      directory: root,
      safeStorage,
      nowSeconds: () => 1_001,
    });
    await expect(restarted.list()).resolves.toHaveLength(1);
    const bundle = await restarted.loadExecutionBundle(saved.id);
    expect(bundle.runnerProfile.github.credential_source).toBe('github-production');
    expect(bundle.runnerProfile.kubernetes).toMatchObject({
      clusterName: 'production',
      expectedEndpoint: 'https://api.production.eks.example.com',
    });
    expect(bundle.credentialMaterial.github).toBe('github-secret-material');
    expect(rendererProjection).not.toContain(bundle.runnerProfile.credential_revision);
  });

  it('retains secret material only while its provider route is unchanged', async () => {
    const root = await directory();
    let now = 1_000;
    const store = new AccordLockEnvironmentProfileStore({
      directory: root,
      safeStorage,
      nowSeconds: () => now,
    });
    const created = await store.save(input(), 'https://api.production.eks.example.com');
    const firstBundle = await store.loadExecutionBundle(created.id);
    await expect(store.resolveAwsCredential(input(created.id, 'KEEP'))).resolves.toMatchObject({
      needsDiscovery: false,
      existingEndpoint: 'https://api.production.eks.example.com',
    });

    now = 1_010;
    const verified = await store.recordVerification(
      created.id,
      firstBundle.runnerProfile.profile_digest,
      {
        status: 'VERIFIED',
      }
    );
    expect(verified).toMatchObject({ status: 'VERIFIED', verifiedAt: 1_010 });

    now = 1_020;
    const updated = await store.save({
      ...input(created.id, 'KEEP'),
      name: 'Production delivery v2',
    });
    expect(updated).toMatchObject({
      status: 'SAVED',
      verifiedAt: null,
      failedAt: null,
      failureCode: null,
    });
    expect((await store.loadExecutionBundle(created.id)).credentialMaterial).toEqual(
      firstBundle.credentialMaterial
    );
    expect((await store.loadExecutionBundle(created.id)).runnerProfile.credential_revision).toBe(
      firstBundle.runnerProfile.credential_revision
    );
    await expect(
      store.save({
        ...input(created.id, 'KEEP'),
        github: {
          repository: 'attacker/product',
          workflow: '.github/workflows/release.yml',
        },
      })
    ).rejects.toThrow('github credentials must be re-entered');
  });

  it('invalidates an in-flight verification whenever credential material is replaced', async () => {
    const root = await directory();
    let now = 1_000;
    const store = new AccordLockEnvironmentProfileStore({
      directory: root,
      safeStorage,
      nowSeconds: () => now,
    });
    const created = await store.save(input(), 'https://api.production.eks.example.com');
    const beforeRotation = await store.loadExecutionBundle(created.id);

    now = 1_010;
    await store.save({
      ...input(created.id, 'SET'),
      credentials: {
        ...input(created.id, 'SET').credentials,
        github: {
          reference: 'github-production',
          material: { mode: 'SET', value: 'rotated-github-secret-material' },
        },
      },
    });
    const afterRotation = await store.loadExecutionBundle(created.id);

    expect(afterRotation.runnerProfile.credential_revision).not.toBe(
      beforeRotation.runnerProfile.credential_revision
    );
    expect(afterRotation.runnerProfile.profile_digest).not.toBe(
      beforeRotation.runnerProfile.profile_digest
    );
    await expect(
      store.recordVerification(created.id, beforeRotation.runnerProfile.profile_digest, {
        status: 'VERIFIED',
      })
    ).rejects.toThrow('changed during verification');
  });

  it('records indeterminate preflight results as FAILED and never infers VERIFIED from save', async () => {
    const root = await directory();
    let now = 1_000;
    const store = new AccordLockEnvironmentProfileStore({
      directory: root,
      safeStorage,
      nowSeconds: () => now,
    });
    const saved = await store.save(input(), 'https://api.production.eks.example.com');
    expect(saved.status).toBe('SAVED');
    const bundle = await store.loadExecutionBundle(saved.id);

    now = 1_010;
    const failed = await store.recordVerification(saved.id, bundle.runnerProfile.profile_digest, {
      status: 'FAILED',
      failureCode: 'PREFLIGHT_INDETERMINATE',
    });
    expect(failed).toMatchObject({
      status: 'FAILED',
      failedAt: 1_010,
      failureCode: 'PREFLIGHT_INDETERMINATE',
      verifiedAt: null,
    });
  });

  it('fails closed when secure storage is unavailable or Linux falls back to basic text', async () => {
    const root = await directory();
    const unavailable = new AccordLockEnvironmentProfileStore({
      directory: root,
      safeStorage: { ...safeStorage, isEncryptionAvailable: () => false },
    });
    await expect(unavailable.list()).rejects.toThrow('Secure credential storage');

    const insecureLinux = new AccordLockEnvironmentProfileStore({
      directory: root,
      platform: 'linux',
      safeStorage: {
        ...safeStorage,
        getSelectedStorageBackend: () => 'basic_text',
      },
    });
    await expect(insecureLinux.save(input())).rejects.toThrow('Secure credential storage');
  });
});
