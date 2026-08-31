import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import type { AccordLockEnvironmentProfileSafeStorage } from './accordlockEnvironmentProfileStore';
import {
  AccordLockPreflightTrustStore,
  type AccordLockCiAuthorityEnrollment,
  type AccordLockPreflightInstallationBootstrap,
} from './accordlockPreflightTrustStore';

const directories: string[] = [];
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_PREFIX_BYTES = 12;
const ENVIRONMENT_ID = '11111111-1111-4111-8111-111111111111';

const safeStorage: AccordLockEnvironmentProfileSafeStorage = {
  isEncryptionAvailable: () => true,
  encryptString: (plaintext) => Buffer.from(plaintext, 'utf8').reverse(),
  decryptString: (ciphertext) => Buffer.from(ciphertext).reverse().toString('utf8'),
};

function publicKey(seedByte: number): string {
  const seed = Buffer.alloc(32, seedByte);
  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const encodedPublic = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  return Buffer.from(encodedPublic).subarray(SPKI_PREFIX_BYTES).toString('base64url');
}

function fingerprint(encodedPublicKey: string): string {
  return `sha256:${createHash('sha256')
    .update(Buffer.from(encodedPublicKey, 'base64url'))
    .digest('hex')}`;
}

function bootstrap(seedByte: number): AccordLockPreflightInstallationBootstrap {
  const encodedPublicKey = publicKey(seedByte);
  return {
    runnerMasterSeed: Buffer.alloc(32, seedByte + 1).toString('base64url'),
    receiptSigningSeed: Buffer.alloc(32, seedByte).toString('base64url'),
    receiptKeyId: `accordlock-receipt-${seedByte}`,
    receiptPublicKey: encodedPublicKey,
    receiptPublicKeyHash: fingerprint(encodedPublicKey),
  };
}

function enrollment(
  buildSeed = 31,
  artifactSeed = 41,
  environmentId = ENVIRONMENT_ID
): AccordLockCiAuthorityEnrollment {
  const build = publicKey(buildSeed);
  const artifact = publicKey(artifactSeed);
  return {
    environmentId,
    build: {
      keyId: `build-${environmentId}`,
      publicKey: build,
      publicKeyHash: fingerprint(build),
    },
    artifact: {
      keyId: `artifact-${environmentId}`,
      publicKey: artifact,
      publicKeyHash: fingerprint(artifact),
    },
  };
}

async function directory(): Promise<string> {
  const created = await fs.mkdtemp(path.join(os.tmpdir(), 'accordlock-trust-'));
  directories.push(created);
  return created;
}

async function readPlaintext(directoryPath: string): Promise<Record<string, unknown>> {
  const ciphertext = await fs.readFile(path.join(directoryPath, 'preflight-trust.v1.bin'));
  return JSON.parse(safeStorage.decryptString(ciphertext)) as Record<string, unknown>;
}

async function writePlaintext(directoryPath: string, value: unknown): Promise<void> {
  await fs.writeFile(
    path.join(directoryPath, 'preflight-trust.v1.bin'),
    safeStorage.encryptString(JSON.stringify(value))
  );
}

function legacyDocument(environmentId = ENVIRONMENT_ID) {
  const installation = bootstrap(7);
  return {
    schemaVersion: 1,
    environments: [
      {
        environmentId,
        runnerMasterSeed: installation.runnerMasterSeed,
        receiptSigningSeed: installation.receiptSigningSeed,
        receiptPublicKey: installation.receiptPublicKey,
        receiptPublicKeyHash: installation.receiptPublicKeyHash,
        receiptKeyId: installation.receiptKeyId,
        buildTrustKeyId: `build-${environmentId}`,
        buildTrustPublicKey: publicKey(51),
        artifactTrustKeyId: `artifact-${environmentId}`,
        artifactTrustPublicKey: publicKey(61),
        createdAt: 1_800_000_000,
        expiresAt: 2_115_360_000,
      },
    ],
  };
}

afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((directoryPath) => fs.rm(directoryPath, { recursive: true, force: true }))
  );
});

describe('AccordLock preflight trust store', () => {
  it('creates only runner and receipt material and exposes CI as unenrolled', async () => {
    const directoryPath = await directory();
    const store = new AccordLockPreflightTrustStore({
      directory: directoryPath,
      safeStorage,
      nowSeconds: () => 1_800_000_000,
    });
    const initialize = vi.fn(async () => bootstrap(7));

    const first = await store.getOrCreate(ENVIRONMENT_ID, initialize);
    const second = await store.getOrCreate(ENVIRONMENT_ID, async () => bootstrap(9));
    expect(second).toEqual(first);
    expect(initialize).toHaveBeenCalledOnce();
    expect(first.ciAuthorities).toBeNull();
    await expect(store.getCiAuthorityStatus(ENVIRONMENT_ID)).resolves.toEqual({
      status: 'UNENROLLED',
      environmentId: ENVIRONMENT_ID,
    });
    const plaintext = JSON.stringify(await readPlaintext(directoryPath));
    expect(plaintext).toContain('"schemaVersion":2');
    expect(plaintext).toContain('"ciAuthorities":null');
    expect(plaintext).not.toContain('buildTrustPublicKey');
    expect(plaintext).not.toContain('artifactTrustPublicKey');
    const ciphertext = await fs.readFile(path.join(directoryPath, 'preflight-trust.v1.bin'));
    expect(ciphertext.toString('utf8')).not.toContain(first.receiptSigningSeed);
    expect(ciphertext.toString('utf8')).not.toContain(first.runnerMasterSeed);
  });

  it('migrates v1 without trusting old CI roots or changing installation keys', async () => {
    const directoryPath = await directory();
    const legacy = legacyDocument();
    await writePlaintext(directoryPath, legacy);
    const store = new AccordLockPreflightTrustStore({ directory: directoryPath, safeStorage });

    await expect(store.getCiAuthorityStatus(ENVIRONMENT_ID)).resolves.toEqual({
      status: 'UNENROLLED',
      environmentId: ENVIRONMENT_ID,
    });
    const initialize = vi.fn(async () => bootstrap(99));
    const migrated = await store.getOrCreate(ENVIRONMENT_ID, initialize);
    expect(initialize).not.toHaveBeenCalled();
    expect(migrated.runnerMasterSeed).toBe(legacy.environments[0].runnerMasterSeed);
    expect(migrated.receiptSigningSeed).toBe(legacy.environments[0].receiptSigningSeed);
    expect(migrated.receiptPublicKeyHash).toBe(legacy.environments[0].receiptPublicKeyHash);
    expect(migrated.ciAuthorities).toBeNull();
    const persisted = await readPlaintext(directoryPath);
    expect(persisted.schemaVersion).toBe(2);
    const serialized = JSON.stringify(persisted);
    expect(serialized).not.toContain(legacy.environments[0].buildTrustPublicKey);
    expect(serialized).not.toContain(legacy.environments[0].artifactTrustPublicKey);
  });

  it('enrolls public CI authorities once and makes an identical retry idempotent', async () => {
    const directoryPath = await directory();
    const store = new AccordLockPreflightTrustStore({ directory: directoryPath, safeStorage });
    await store.getOrCreate(ENVIRONMENT_ID, async () => bootstrap(7));
    const exact = enrollment();

    const first = await store.enrollCiAuthorities(ENVIRONMENT_ID, exact);
    const second = await store.enrollCiAuthorities(ENVIRONMENT_ID, exact);
    expect(second).toEqual(first);
    expect(first).toEqual({
      status: 'ENROLLED',
      environmentId: ENVIRONMENT_ID,
      build: exact.build,
      artifact: exact.artifact,
    });
    const material = await store.getOrCreate(ENVIRONMENT_ID, async () => bootstrap(9));
    expect(material.ciAuthorities).toEqual({ build: exact.build, artifact: exact.artifact });
    const serialized = JSON.stringify(await readPlaintext(directoryPath));
    expect(serialized).toContain(exact.build.publicKey);
    expect(serialized).toContain(exact.artifact.publicKey);
    expect(serialized).not.toContain('privateKey');
    expect(serialized).not.toContain('signingSeed');
  });

  it('rejects rotation, key reuse, wrong IDs, fingerprints, and environment binding', async () => {
    const directoryPath = await directory();
    const store = new AccordLockPreflightTrustStore({ directory: directoryPath, safeStorage });
    await store.getOrCreate(ENVIRONMENT_ID, async () => bootstrap(7));
    const exact = enrollment();
    await store.enrollCiAuthorities(ENVIRONMENT_ID, exact);

    await expect(store.enrollCiAuthorities(ENVIRONMENT_ID, enrollment(32, 42))).rejects.toThrow(
      'explicit rotation workflow'
    );
    await expect(
      store.enrollCiAuthorities(ENVIRONMENT_ID, {
        ...exact,
        artifact: {
          ...exact.artifact,
          publicKey: exact.build.publicKey,
          publicKeyHash: exact.build.publicKeyHash,
        },
      })
    ).rejects.toThrow('distinct keys');
    await expect(
      store.enrollCiAuthorities(ENVIRONMENT_ID, {
        ...exact,
        build: { ...exact.build, keyId: 'build-wrong' },
      })
    ).rejects.toThrow('Build CI authority');
    await expect(
      store.enrollCiAuthorities(ENVIRONMENT_ID, {
        ...exact,
        build: { ...exact.build, publicKeyHash: `sha256:${'0'.repeat(64)}` },
      })
    ).rejects.toThrow('fingerprint');
    await expect(
      store.enrollCiAuthorities(ENVIRONMENT_ID, {
        ...exact,
        environmentId: '22222222-2222-4222-8222-222222222222',
      })
    ).rejects.toThrow('does not match');
  });

  it('serializes concurrent initialization and enrollment races', async () => {
    const directoryPath = await directory();
    const store = new AccordLockPreflightTrustStore({ directory: directoryPath, safeStorage });
    const initialize = vi.fn(async () => bootstrap(7));
    const [first, second] = await Promise.all([
      store.getOrCreate(ENVIRONMENT_ID, initialize),
      store.getOrCreate(ENVIRONMENT_ID, initialize),
    ]);
    expect(first).toEqual(second);
    expect(initialize).toHaveBeenCalledOnce();

    const exact = enrollment();
    const statuses = await Promise.all([
      store.enrollCiAuthorities(ENVIRONMENT_ID, exact),
      store.enrollCiAuthorities(ENVIRONMENT_ID, exact),
    ]);
    expect(statuses[0]).toEqual(statuses[1]);
    const results = await Promise.allSettled([
      store.enrollCiAuthorities(ENVIRONMENT_ID, enrollment(32, 42)),
      store.enrollCiAuthorities(ENVIRONMENT_ID, exact),
    ]);
    expect(results.map((result) => result.status).sort()).toEqual(['fulfilled', 'rejected']);
    await expect(store.getCiAuthorityStatus(ENVIRONMENT_ID)).resolves.toMatchObject({
      status: 'ENROLLED',
      build: exact.build,
      artifact: exact.artifact,
    });
  });

  it('fails closed on v1 or v2 tampering and reports uninitialized environments', async () => {
    const directoryPath = await directory();
    const malformedLegacy = legacyDocument();
    malformedLegacy.environments[0].buildTrustKeyId = 'build-another-environment';
    await writePlaintext(directoryPath, malformedLegacy);
    const legacyStore = new AccordLockPreflightTrustStore({
      directory: directoryPath,
      safeStorage,
    });
    await expect(legacyStore.getCiAuthorityStatus(ENVIRONMENT_ID)).rejects.toThrow(
      'Legacy preflight trust material'
    );

    const secondDirectory = await directory();
    const store = new AccordLockPreflightTrustStore({ directory: secondDirectory, safeStorage });
    await expect(store.getCiAuthorityStatus(ENVIRONMENT_ID)).resolves.toEqual({
      status: 'NOT_INITIALIZED',
      environmentId: ENVIRONMENT_ID,
    });
    await store.getOrCreate(ENVIRONMENT_ID, async () => bootstrap(7));
    await store.enrollCiAuthorities(ENVIRONMENT_ID, enrollment());
    const tampered = await readPlaintext(secondDirectory);
    const environments = tampered.environments as Array<{
      ciAuthorities: { build: { publicKeyHash: string } };
    }>;
    environments[0].ciAuthorities.build.publicKeyHash = `sha256:${'f'.repeat(64)}`;
    await writePlaintext(secondDirectory, tampered);
    const reopened = new AccordLockPreflightTrustStore({
      directory: secondDirectory,
      safeStorage,
    });
    await expect(reopened.getCiAuthorityStatus(ENVIRONMENT_ID)).rejects.toThrow('fingerprint');
  });

  it('rejects a receipt seed that does not bind the runner-reported public key', async () => {
    const directoryPath = await directory();
    const store = new AccordLockPreflightTrustStore({ directory: directoryPath, safeStorage });
    const mismatched = { ...bootstrap(11), receiptPublicKey: bootstrap(12).receiptPublicKey };
    await expect(
      store.getOrCreate('22222222-2222-4222-8222-222222222222', async () => mismatched)
    ).rejects.toThrow('key binding');
  });
});
