import { createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import {
  AccordLockDeploymentPreflightCiEvidenceImporter,
  verifyDeploymentPreflightCiEvidenceBundle,
} from './deploymentPreflightCiEvidence';

const BUILD_DOMAIN = Buffer.from('accordlock:v1:build-trust-record\0', 'utf8');
const ARTIFACT_DOMAIN = Buffer.from('accordlock:v1:artifact-trust-record\0', 'utf8');
const ENVIRONMENT_ID = '44444444-4444-4444-8444-444444444444';
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => fs.rm(directory, { recursive: true, force: true }))
  );
});

async function temporaryDirectory(): Promise<string> {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'accordlock-ci-evidence-'));
  temporaryDirectories.push(directory);
  return directory;
}

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

function fixture(
  overrides: Readonly<{
    buildAuthority?: ReturnType<typeof authority>;
    artifactAuthority?: ReturnType<typeof authority>;
    commitSha?: string;
    imageDigest?: string;
    runId?: number;
    issuedAt?: number;
    expiresAt?: number;
  }> = {}
) {
  const buildAuthority = overrides.buildAuthority ?? authority();
  const artifactAuthority = overrides.artifactAuthority ?? authority();
  const commitSha = overrides.commitSha ?? 'a'.repeat(40);
  const imageDigest = overrides.imageDigest ?? digest('image');
  const runId = overrides.runId ?? 987_654;
  const issuedAt = overrides.issuedAt ?? 900;
  const expiresAt = overrides.expiresAt ?? 1_100;
  const buildPayload = {
    schema_version: 1,
    key_id: `build-${ENVIRONMENT_ID}`,
    repository: 'accordlock/product',
    workflow_ref: '.github/workflows/release.yml',
    run_id: runId,
    commit_sha: commitSha,
    input_manifest_root: digest('manifest'),
    output_digest: imageDigest,
    issued_at: issuedAt,
    expires_at: expiresAt,
  };
  const artifactPayload = {
    schema_version: 1,
    key_id: `artifact-${ENVIRONMENT_ID}`,
    registry_id: '123456789012',
    region: 'eu-west-3',
    repository_name: 'product/api',
    image_digest: imageDigest,
    source_repository: 'accordlock/product',
    commit_sha: commitSha,
    source_run_id: runId,
    signature_valid: true,
    quarantined: false,
    issued_at: issuedAt,
    expires_at: expiresAt,
  };
  return {
    bundle: {
      schema_version: 1,
      bundle_type: 'ACCORDLOCK_DEPLOYMENT_PREFLIGHT_CI_EVIDENCE',
      environment_id: ENVIRONMENT_ID,
      github: {
        owner: 'accordlock',
        repository: 'product',
        workflow_ref: '.github/workflows/release.yml',
      },
      ecr: {
        registry_id: '123456789012',
        region: 'eu-west-3',
        repository: 'product/api',
      },
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
    },
    buildAuthority,
    artifactAuthority,
  };
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

describe('Deployment Preflight CI evidence', () => {
  it('verifies exact Rust records and returns public authority enrollment material', () => {
    const input = fixture();
    const verified = verifyDeploymentPreflightCiEvidenceBundle(input.bundle, {
      nowSeconds: 1_000,
    });

    expect(verified).toMatchObject({
      runId: 987_654,
      imageDigest: digest('image'),
      enrollment: {
        environmentId: ENVIRONMENT_ID,
        build: {
          keyId: `build-${ENVIRONMENT_ID}`,
          publicKey: input.buildAuthority.publicKey,
        },
        artifact: {
          keyId: `artifact-${ENVIRONMENT_ID}`,
          publicKey: input.artifactAuthority.publicKey,
        },
      },
    });
  });

  it('rejects inconsistent source, build, image, registry, run, and authority bindings', () => {
    const original = fixture().bundle;
    const mutations: Array<(bundle: ReturnType<typeof clone<typeof original>>) => void> = [
      (bundle) => {
        bundle.github.repository = 'other';
      },
      (bundle) => {
        bundle.github.workflow_ref = '.github/workflows/other.yml';
      },
      (bundle) => {
        bundle.ecr.registry_id = '999999999999';
      },
      (bundle) => {
        bundle.ecr.region = 'us-east-1';
      },
      (bundle) => {
        bundle.ecr.repository = 'other/image';
      },
      (bundle) => {
        bundle.artifact_record.payload.source_run_id += 1;
      },
      (bundle) => {
        bundle.artifact_record.payload.commit_sha = 'b'.repeat(40);
      },
      (bundle) => {
        bundle.artifact_record.payload.image_digest = digest('different');
      },
      (bundle) => {
        bundle.build_authority.key_id = 'build-another-environment';
      },
    ];

    for (const mutate of mutations) {
      const candidate = clone(original);
      mutate(candidate);
      expect(() =>
        verifyDeploymentPreflightCiEvidenceBundle(candidate, { nowSeconds: 1_000 })
      ).toThrow();
    }
  });

  it('rejects invalid signatures, unknown fields, oversized input, and invalid time windows', () => {
    const changedSignedField = clone(fixture().bundle);
    changedSignedField.build_record.payload.input_manifest_root = digest('attacker');
    expect(() =>
      verifyDeploymentPreflightCiEvidenceBundle(changedSignedField, { nowSeconds: 1_000 })
    ).toThrow('signature is invalid');

    const unknownField = clone(fixture().bundle) as typeof changedSignedField & {
      records_directory?: string;
    };
    unknownField.records_directory = 'C:\\private\\trust';
    expect(() =>
      verifyDeploymentPreflightCiEvidenceBundle(unknownField, { nowSeconds: 1_000 })
    ).toThrow();

    expect(() =>
      verifyDeploymentPreflightCiEvidenceBundle(
        { ...fixture().bundle, extra: 'x'.repeat(300 * 1_024) },
        { nowSeconds: 1_000 }
      )
    ).toThrow('size limit');
    expect(() =>
      verifyDeploymentPreflightCiEvidenceBundle(fixture({ issuedAt: 1_001 }).bundle, {
        nowSeconds: 1_000,
      })
    ).toThrow('not valid yet');
    expect(() =>
      verifyDeploymentPreflightCiEvidenceBundle(fixture({ expiresAt: 1_000 }).bundle, {
        nowSeconds: 1_000,
      })
    ).toThrow('has expired');
    expect(() =>
      verifyDeploymentPreflightCiEvidenceBundle(
        fixture({ issuedAt: 1_000, expiresAt: 1_000 }).bundle,
        { nowSeconds: 1_000 }
      )
    ).toThrow('validity window is invalid');
  });

  it('atomically imports only the exact Rust record filenames and is idempotent', async () => {
    const root = await temporaryDirectory();
    const buildDirectory = path.join(root, 'build');
    const artifactDirectory = path.join(root, 'artifact');
    const input = fixture();
    const importer = new AccordLockDeploymentPreflightCiEvidenceImporter({
      buildRecordsDirectory: buildDirectory,
      artifactRecordsDirectory: artifactDirectory,
      nowSeconds: () => 1_000,
    });

    const first = await importer.importBundle(input.bundle);
    const repeated = await importer.importBundle(input.bundle);
    expect(repeated).toEqual(first);
    expect(path.basename(first.buildRecordPath)).toBe('987654.json');
    expect(path.basename(first.artifactRecordPath)).toBe(
      `${digest('image').slice('sha256:'.length)}.json`
    );
    expect(JSON.parse(await fs.readFile(first.buildRecordPath, 'utf8'))).toEqual(
      input.bundle.build_record
    );
    expect(JSON.parse(await fs.readFile(first.artifactRecordPath, 'utf8'))).toEqual(
      input.bundle.artifact_record
    );
    expect(await fs.readdir(buildDirectory)).toEqual(['987654.json']);
    expect(await fs.readdir(artifactDirectory)).toEqual([
      `${digest('image').slice('sha256:'.length)}.json`,
    ]);
  });

  it('never overwrites different provenance and does not partially import a collision', async () => {
    const root = await temporaryDirectory();
    const buildDirectory = path.join(root, 'build');
    const artifactDirectory = path.join(root, 'artifact');
    const sharedBuildAuthority = authority();
    const sharedArtifactAuthority = authority();
    const first = fixture({
      buildAuthority: sharedBuildAuthority,
      artifactAuthority: sharedArtifactAuthority,
    });
    const importer = new AccordLockDeploymentPreflightCiEvidenceImporter({
      buildRecordsDirectory: buildDirectory,
      artifactRecordsDirectory: artifactDirectory,
      nowSeconds: () => 1_000,
    });
    await importer.importBundle(first.bundle);
    const changed = fixture({
      buildAuthority: sharedBuildAuthority,
      artifactAuthority: sharedArtifactAuthority,
      commitSha: 'b'.repeat(40),
    });
    await expect(importer.importBundle(changed.bundle)).rejects.toThrow('different content');
    expect(JSON.parse(await fs.readFile(path.join(buildDirectory, '987654.json'), 'utf8'))).toEqual(
      first.bundle.build_record
    );

    const secondRoot = await temporaryDirectory();
    const secondBuild = path.join(secondRoot, 'build');
    const secondArtifact = path.join(secondRoot, 'artifact');
    await fs.mkdir(secondArtifact, { recursive: true });
    await fs.writeFile(
      path.join(secondArtifact, `${digest('image').slice('sha256:'.length)}.json`),
      '{}\n'
    );
    const secondImporter = new AccordLockDeploymentPreflightCiEvidenceImporter({
      buildRecordsDirectory: secondBuild,
      artifactRecordsDirectory: secondArtifact,
      nowSeconds: () => 1_000,
    });
    await expect(secondImporter.importBundle(first.bundle)).rejects.toThrow('different content');
    await expect(fs.stat(path.join(secondBuild, '987654.json'))).rejects.toMatchObject({
      code: 'ENOENT',
    });
  });

  it('rejects relative, shared, and non-directory destinations', async () => {
    const root = await temporaryDirectory();
    expect(
      () =>
        new AccordLockDeploymentPreflightCiEvidenceImporter({
          buildRecordsDirectory: 'relative/build',
          artifactRecordsDirectory: path.join(root, 'artifact'),
        })
    ).toThrow('must be absolute');
    expect(
      () =>
        new AccordLockDeploymentPreflightCiEvidenceImporter({
          buildRecordsDirectory: root,
          artifactRecordsDirectory: root,
        })
    ).toThrow('must be distinct');

    const filePath = path.join(root, 'not-a-directory');
    await fs.writeFile(filePath, 'file');
    const importer = new AccordLockDeploymentPreflightCiEvidenceImporter({
      buildRecordsDirectory: filePath,
      artifactRecordsDirectory: path.join(root, 'artifact'),
      nowSeconds: () => 1_000,
    });
    await expect(importer.importBundle(fixture().bundle)).rejects.toThrow(
      'not a regular directory'
    );
  });
});
