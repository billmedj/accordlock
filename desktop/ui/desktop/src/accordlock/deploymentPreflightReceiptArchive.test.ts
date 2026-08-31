import { createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import {
  AccordLockDeploymentPreflightReceiptArchive,
  parseDeploymentPreflightReceiptExportPackage,
  type AppendVerifiedDeploymentPreflightReceiptInput,
} from './deploymentPreflightReceiptArchive';

const RECEIPT_HASH_DOMAIN = Buffer.from('accordlock:v1:deployment-preflight-receipt\0', 'utf8');
const RECEIPT_SIGNATURE_DOMAIN = Buffer.from(
  'accordlock:v1:deployment-preflight-receipt-signature\0',
  'utf8'
);
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => fs.rm(directory, { recursive: true, force: true }))
  );
});

async function temporaryDirectory(): Promise<string> {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'accordlock-receipts-'));
  temporaryDirectories.push(directory);
  return directory;
}

function digest(seed: string): string {
  return `sha256:${createHash('sha256').update(seed, 'utf8').digest('hex')}`;
}

function domainHash(encoded: Buffer): string {
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(encoded.length));
  return `sha256:${createHash('sha256')
    .update(RECEIPT_HASH_DOMAIN)
    .update(length)
    .update(encoded)
    .digest('hex')}`;
}

function keyMaterial(): Readonly<{
  privateKey: KeyObject;
  publicKey: string;
  publicKeyHash: string;
}> {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const raw = Buffer.from(spki.subarray(spki.length - 32));
  return {
    privateKey,
    publicKey: raw.toString('base64url'),
    publicKeyHash: `sha256:${createHash('sha256').update(raw).digest('hex')}`,
  };
}

function signedInput(
  keys: ReturnType<typeof keyMaterial>,
  overrides: Readonly<{
    checkId?: string;
    requestId?: string;
    profileId?: string;
    completedAt?: number;
  }> = {}
): AppendVerifiedDeploymentPreflightReceiptInput {
  const profileId = overrides.profileId ?? '44444444-4444-4444-8444-444444444444';
  const payload = {
    schema_version: 2,
    check_id: overrides.checkId ?? '11111111-1111-4111-8111-111111111111',
    request_id: overrides.requestId ?? '22222222-2222-4222-8222-222222222222',
    environment_id: profileId,
    environment_profile_hash: digest('profile'),
    runner_id: '33333333-3333-4333-8333-333333333333',
    runner_registration_hash: digest('runner'),
    dispatch_hash: digest('dispatch'),
    policy_decision_hash: null,
    outcome: 'INDETERMINATE',
    reason_codes: ['PROVIDER_UNAVAILABLE'],
    candidate: {
      repository: 'accordlock/product',
      pull_number: 42,
      commit_sha: 'a'.repeat(40),
      workflow_ref: '.github/workflows/release.yml',
      actions_run_id: 91,
      ecr_repository: '123456789012.dkr.ecr.eu-west-3.amazonaws.com/product',
      image_digest: digest('candidate-image'),
    },
    target: {
      cluster_identity: 'arn:aws:eks:eu-west-3:123456789012:cluster/production',
      cluster_endpoint: 'https://cluster.example.com',
      cluster_ca_hash: digest('cluster-ca'),
      namespace: 'payments',
      deployment: 'api',
      deployment_uid: 'deployment-uid',
      resource_version: '12891',
      container: 'api',
      observed_image_digest: digest('observed-image'),
    },
    checks: ['CODE_REVIEW', 'BUILD', 'IMAGE', 'TARGET'].map((kind) => ({
      kind,
      status: 'INDETERMINATE',
      summary: 'The provider could not be reached.',
      reason_code: 'PROVIDER_UNAVAILABLE',
      observed_at: null,
      freshness_seconds: null,
      evidence_reference: null,
    })),
    evidence_root: null,
    evaluation_attestation: null,
    started_at: 1_700_000_000,
    completed_at: overrides.completedAt ?? 1_700_000_001,
    valid_until: null,
    effect: 'NONE',
    deployment_performed: false,
  };
  const encoded = Buffer.from(JSON.stringify(payload), 'utf8');
  const receiptHash = domainHash(encoded);
  const receiptHashBytes = Buffer.from(receiptHash.slice('sha256:'.length), 'hex');
  const signature = sign(
    null,
    Buffer.concat([RECEIPT_SIGNATURE_DOMAIN, receiptHashBytes]),
    keys.privateKey
  ).toString('base64url');
  const receipt = {
    payload,
    receipt_hash: receiptHash,
    signer_key_id: 'receipt-installation-1',
    receipt_public_key_hash: keys.publicKeyHash,
    signature,
  };
  return {
    signatureVerified: true,
    receipt,
    receiptPublicKey: keys.publicKey,
    receiptKeyId: 'receipt-installation-1',
    verificationProfile: {
      schema_version: 2,
      profile_id: profileId,
      organization_id: 'accordlock',
      environment_id: profileId,
      executor_audience: 'accordlock://runner/deployment-preflight/v1',
      github: {
        authority: 'api.github.com',
        api_base_path: '/',
        owner: 'accordlock',
        repository: 'product',
        workflow_ref: '.github/workflows/release.yml',
        minimum_approvals: 1,
        maximum_response_bytes: 131_072,
      },
      ecr: {
        registry_id: '123456789012',
        region: 'eu-west-3',
        repository: 'product',
        maximum_response_bytes: 131_072,
      },
      eks_discovery: { maximum_response_bytes: 131_072 },
      kubernetes: {
        expected_endpoint: 'https://cluster.example.com',
        cluster_name: 'production',
        namespace: 'payments',
        deployment: 'api',
        container: 'api',
        maximum_response_bytes: 131_072,
      },
      build_trust: { key_id: 'build-key-1', public_key: keys.publicKey },
      artifact_trust: { key_id: 'artifact-key-1', public_key: keys.publicKey },
      receipt: {
        key_id: 'receipt-installation-1',
        public_key: keys.publicKey,
        public_key_hash: keys.publicKeyHash,
      },
      evidence_ttl_seconds: 120,
      maximum_source_age_seconds: 60,
      maximum_future_skew_seconds: 5,
      created_at: 1_699_999_000,
      expires_at: 2_015_359_000,
      environment_profile_hash: digest('profile'),
    },
  };
}

describe('AccordLock deployment preflight receipt archive', () => {
  it('persists an immutable public verification package that survives profile deletion', async () => {
    const directory = await temporaryDirectory();
    const keys = keyMaterial();
    const input = signedInput(keys);
    const archive = new AccordLockDeploymentPreflightReceiptArchive({
      directory,
      nowSeconds: () => 1_700_000_010,
    });

    const appended = await archive.appendVerified(input);
    expect(appended).toMatchObject({
      checkId: '11111111-1111-4111-8111-111111111111',
      outcome: 'INDETERMINATE',
      archivedAt: 1_700_000_010,
    });
    const reopened = new AccordLockDeploymentPreflightReceiptArchive({ directory });
    const loaded = await reopened.loadPackage(appended.receiptHash);
    const exported = await reopened.exportPackage(appended.receiptHash);

    expect(loaded.receipt_key).toEqual({
      algorithm: 'Ed25519',
      key_id: 'receipt-installation-1',
      public_key: keys.publicKey,
      public_key_hash: keys.publicKeyHash,
    });
    expect(loaded.verification_profile.build_trust.public_key).toBe(keys.publicKey);
    expect(exported.packageDigest).toBe(loaded.package_digest);
    expect(exported.fileName).toBe(
      'accordlock-deployment-preflight-11111111-1111-4111-8111-111111111111.json'
    );
    expect(JSON.parse(exported.contents.toString('utf8'))).toEqual(loaded);
    expect(
      parseDeploymentPreflightReceiptExportPackage(JSON.parse(exported.contents.toString('utf8')))
    ).toEqual(loaded);
    expect(await reopened.listSummaries()).toHaveLength(1);
  });

  it('exports deterministic bytes without credentials or local trust-record paths', async () => {
    const firstDirectory = await temporaryDirectory();
    const secondDirectory = await temporaryDirectory();
    const keys = keyMaterial();
    const input = signedInput(keys);
    const first = new AccordLockDeploymentPreflightReceiptArchive({
      directory: firstDirectory,
      nowSeconds: () => 1,
    });
    const second = new AccordLockDeploymentPreflightReceiptArchive({
      directory: secondDirectory,
      nowSeconds: () => 2,
    });
    const firstSummary = await first.appendVerified(input);
    const secondSummary = await second.appendVerified(input);
    const firstExport = await first.exportPackage(firstSummary.receiptHash);
    const secondExport = await second.exportPackage(secondSummary.receiptHash);

    expect(firstExport.contents.equals(secondExport.contents)).toBe(true);
    expect(firstExport.packageDigest).toBe(secondExport.packageDigest);
    const serialized = firstExport.contents.toString('utf8');
    expect(serialized).not.toContain('credential');
    expect(serialized).not.toContain('records_directory');
    expect(serialized).not.toContain('C:\\private');

    const unsafe = JSON.parse(JSON.stringify(input)) as {
      verificationProfile: { build_trust: Record<string, unknown> };
    };
    unsafe.verificationProfile.build_trust.records_directory = 'C:\\private\\build';
    await expect(
      first.appendVerified(unsafe as unknown as AppendVerifiedDeploymentPreflightReceiptInput)
    ).rejects.toThrow();
  });

  it('is idempotent for one exact receipt and rejects check-id or hash collisions', async () => {
    const directory = await temporaryDirectory();
    const keys = keyMaterial();
    const archive = new AccordLockDeploymentPreflightReceiptArchive({
      directory,
      nowSeconds: () => 1_700_000_010,
    });
    const firstInput = signedInput(keys);
    const first = await archive.appendVerified(firstInput);
    const repeated = await archive.appendVerified(firstInput);
    expect(repeated).toEqual(first);
    expect((await fs.readdir(directory)).filter((name) => name.endsWith('.json'))).toHaveLength(1);

    const reusedCheckId = signedInput(keys, {
      requestId: '55555555-5555-4555-8555-555555555555',
      completedAt: 1_700_000_002,
    });
    await expect(archive.appendVerified(reusedCheckId)).rejects.toThrow(
      'check identifier is already archived'
    );

    const differentProfile = JSON.parse(JSON.stringify(firstInput)) as {
      verificationProfile: { github: { repository: string } };
    };
    differentProfile.verificationProfile.github.repository = 'different';
    await expect(
      archive.appendVerified(
        differentProfile as unknown as AppendVerifiedDeploymentPreflightReceiptInput
      )
    ).rejects.toThrow('receipt hash is already archived differently');
  });

  it('fails closed on a tampered, corrupt, or incorrectly named committed record', async () => {
    const directory = await temporaryDirectory();
    const keys = keyMaterial();
    const archive = new AccordLockDeploymentPreflightReceiptArchive({ directory });
    const saved = await archive.appendVerified(signedInput(keys));
    const [recordName] = (await fs.readdir(directory)).filter((name) => name.endsWith('.json'));
    const recordPath = path.join(directory, recordName);
    const record = JSON.parse(await fs.readFile(recordPath, 'utf8')) as {
      package: { receipt: { payload: { candidate: { repository: string } } } };
    };
    record.package.receipt.payload.candidate.repository = 'attacker/repository';
    await fs.writeFile(recordPath, JSON.stringify(record));
    await expect(archive.loadPackage(saved.receiptHash)).rejects.toThrow();

    await fs.writeFile(recordPath, '{{');
    await expect(archive.listSummaries()).rejects.toThrow('record is corrupt');

    await fs.rm(recordPath);
    await fs.writeFile(path.join(directory, `${'f'.repeat(64)}.json`), '{}');
    await expect(archive.listSummaries()).rejects.toThrow();
  });

  it('validates key and profile bindings and bounds list access', async () => {
    const directory = await temporaryDirectory();
    const keys = keyMaterial();
    const archive = new AccordLockDeploymentPreflightReceiptArchive({ directory });
    const mismatch = { ...signedInput(keys), receiptKeyId: 'another-key' };
    await expect(archive.appendVerified(mismatch)).rejects.toThrow('binding is invalid');
    await expect(archive.listSummaries({ limit: 201 })).rejects.toThrow('list limit is invalid');
    await expect(archive.loadPackage(digest('missing'))).rejects.toThrow('was not found');
    expect(
      () =>
        new AccordLockDeploymentPreflightReceiptArchive({
          directory: 'relative/archive',
        })
    ).toThrow('must be absolute');
  });
});
