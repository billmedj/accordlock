import { createHash, createPublicKey, randomUUID, verify as verifySignature } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

import { z } from 'zod';

const CI_EVIDENCE_SCHEMA_VERSION = 1 as const;
const CI_EVIDENCE_BUNDLE_TYPE = 'ACCORDLOCK_DEPLOYMENT_PREFLIGHT_CI_EVIDENCE' as const;
const BUILD_TRUST_DOMAIN = Buffer.from('accordlock:v1:build-trust-record\0', 'utf8');
const ARTIFACT_TRUST_DOMAIN = Buffer.from('accordlock:v1:artifact-trust-record\0', 'utf8');
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const MAX_BUNDLE_BYTES = 256 * 1_024;
const MAX_TRUST_RECORD_BYTES = 64 * 1_024;

function hasForbiddenTextCodePoint(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (
      codePoint === undefined ||
      codePoint <= 0x1f ||
      codePoint === 0x7f ||
      (codePoint >= 0x202a && codePoint <= 0x202e) ||
      (codePoint >= 0x2066 && codePoint <= 0x2069)
    ) {
      return true;
    }
  }
  return false;
}

const boundedText = (maximumBytes: number) =>
  z
    .string()
    .refine(
      (value) =>
        value.length > 0 &&
        value.trim() === value &&
        Buffer.byteLength(value, 'utf8') <= maximumBytes &&
        !hasForbiddenTextCodePoint(value),
      'text is invalid'
    );

const uuidSchema = z.string().uuid();
const safeTimestampSchema = z.number().int().nonnegative().safe();
const positiveSafeIntegerSchema = z.number().int().positive().safe();
const digestSchema = z
  .string()
  .regex(/^sha256:[0-9a-f]{64}$/u)
  .refine((value) => !/^sha256:0{64}$/u.test(value));
const commitSchema = z.string().regex(/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u);
const routeSegmentSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9._-]+$/u)
  .refine((value) => value !== '.' && value !== '..');
const workflowSchema = boundedText(256).refine(
  (value) =>
    !value.startsWith('/') &&
    !value.endsWith('/') &&
    !value.includes('\\') &&
    value.split('/').every((segment) => segment.length > 0 && segment !== '.' && segment !== '..'),
  'workflow reference is invalid'
);
const ecrRepositorySchema = z
  .string()
  .min(2)
  .max(256)
  .regex(/^[a-z0-9]+(?:[._/-][a-z0-9]+)*$/u);
const commercialAwsRegionSchema = z
  .string()
  .min(1)
  .max(32)
  .regex(/^[a-z]{2}(?:-[a-z0-9]+)+-\d$/u)
  .refine(
    (value) =>
      !['cn-', 'us-gov-', 'us-iso-', 'us-isob-', 'us-isof-', 'eu-isoe-'].some((prefix) =>
        value.startsWith(prefix)
      ),
    'AWS region is outside the supported commercial partition'
  );
const keyIdSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u);

function canonicalBase64Url(value: unknown, bytes: number): value is string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/u.test(value)) return false;
  const decoded = Buffer.from(value, 'base64url');
  return decoded.length === bytes && decoded.toString('base64url') === value;
}

const publicKeySchema = z.string().refine((value) => canonicalBase64Url(value, 32));
const signatureSchema = z.string().refine((value) => canonicalBase64Url(value, 64));

const githubRouteSchema = z
  .object({
    owner: routeSegmentSchema,
    repository: routeSegmentSchema,
    workflow_ref: workflowSchema,
  })
  .strict();

const ecrRouteSchema = z
  .object({
    registry_id: z.string().regex(/^\d{12}$/u),
    region: commercialAwsRegionSchema,
    repository: ecrRepositorySchema,
  })
  .strict();

const authoritySchema = z
  .object({
    algorithm: z.literal('Ed25519'),
    key_id: keyIdSchema,
    public_key: publicKeySchema,
  })
  .strict();

const buildTrustPayloadSchema = z
  .object({
    schema_version: z.literal(1),
    key_id: keyIdSchema,
    repository: boundedText(257),
    workflow_ref: workflowSchema,
    run_id: positiveSafeIntegerSchema,
    commit_sha: commitSchema,
    input_manifest_root: digestSchema,
    output_digest: digestSchema,
    issued_at: safeTimestampSchema,
    expires_at: safeTimestampSchema,
  })
  .strict();

const artifactTrustPayloadSchema = z
  .object({
    schema_version: z.literal(1),
    key_id: keyIdSchema,
    registry_id: z.string().regex(/^\d{12}$/u),
    region: commercialAwsRegionSchema,
    repository_name: ecrRepositorySchema,
    image_digest: digestSchema,
    source_repository: boundedText(257),
    commit_sha: commitSchema,
    source_run_id: positiveSafeIntegerSchema,
    signature_valid: z.boolean(),
    quarantined: z.boolean(),
    issued_at: safeTimestampSchema,
    expires_at: safeTimestampSchema,
  })
  .strict();

const signedBuildTrustRecordSchema = z
  .object({
    payload: buildTrustPayloadSchema,
    signature: signatureSchema,
  })
  .strict();

const signedArtifactTrustRecordSchema = z
  .object({
    payload: artifactTrustPayloadSchema,
    signature: signatureSchema,
  })
  .strict();

const ciEvidenceBundleSchema = z
  .object({
    schema_version: z.literal(CI_EVIDENCE_SCHEMA_VERSION),
    bundle_type: z.literal(CI_EVIDENCE_BUNDLE_TYPE),
    environment_id: uuidSchema,
    github: githubRouteSchema,
    ecr: ecrRouteSchema,
    build_authority: authoritySchema,
    artifact_authority: authoritySchema,
    build_record: signedBuildTrustRecordSchema,
    artifact_record: signedArtifactTrustRecordSchema,
  })
  .strict();

export type DeploymentPreflightCiEvidenceBundle = z.infer<typeof ciEvidenceBundleSchema>;
export type SignedBuildTrustRecord = z.infer<typeof signedBuildTrustRecordSchema>;
export type SignedArtifactTrustRecord = z.infer<typeof signedArtifactTrustRecordSchema>;

export type DeploymentPreflightCiAuthorityEnrollment = Readonly<{
  environmentId: string;
  build: Readonly<{ keyId: string; publicKey: string; publicKeyHash: string }>;
  artifact: Readonly<{ keyId: string; publicKey: string; publicKeyHash: string }>;
}>;

export type VerifiedDeploymentPreflightCiEvidence = Readonly<{
  bundle: DeploymentPreflightCiEvidenceBundle;
  enrollment: DeploymentPreflightCiAuthorityEnrollment;
  runId: number;
  imageDigest: string;
}>;

export type DeploymentPreflightCiEvidenceImporterOptions = Readonly<{
  buildRecordsDirectory: string;
  artifactRecordsDirectory: string;
  nowSeconds?: () => number;
}>;

export type DeploymentPreflightCiEvidenceImportResult = Readonly<{
  environmentId: string;
  runId: number;
  imageDigest: string;
  buildRecordPath: string;
  artifactRecordPath: string;
  enrollment: DeploymentPreflightCiAuthorityEnrollment;
}>;

function encodedJson(value: unknown, maximumBytes: number, label: string): Buffer {
  let encoded: string;
  try {
    encoded = JSON.stringify(value);
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
  const bytes = Buffer.from(encoded, 'utf8');
  if (bytes.length === 0 || bytes.length > maximumBytes) {
    throw new Error(`${label} exceeds its size limit`);
  }
  return bytes;
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function domainHash(domain: Buffer, encoded: Buffer): Buffer {
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(encoded.length));
  return createHash('sha256').update(domain).update(length).update(encoded).digest();
}

function orderedBuildPayload(
  payload: z.infer<typeof buildTrustPayloadSchema>
): z.infer<typeof buildTrustPayloadSchema> {
  return {
    schema_version: payload.schema_version,
    key_id: payload.key_id,
    repository: payload.repository,
    workflow_ref: payload.workflow_ref,
    run_id: payload.run_id,
    commit_sha: payload.commit_sha,
    input_manifest_root: payload.input_manifest_root,
    output_digest: payload.output_digest,
    issued_at: payload.issued_at,
    expires_at: payload.expires_at,
  };
}

function orderedArtifactPayload(
  payload: z.infer<typeof artifactTrustPayloadSchema>
): z.infer<typeof artifactTrustPayloadSchema> {
  return {
    schema_version: payload.schema_version,
    key_id: payload.key_id,
    registry_id: payload.registry_id,
    region: payload.region,
    repository_name: payload.repository_name,
    image_digest: payload.image_digest,
    source_repository: payload.source_repository,
    commit_sha: payload.commit_sha,
    source_run_id: payload.source_run_id,
    signature_valid: payload.signature_valid,
    quarantined: payload.quarantined,
    issued_at: payload.issued_at,
    expires_at: payload.expires_at,
  };
}

function verifyTrustRecordSignature(
  domain: Buffer,
  orderedPayload: unknown,
  encodedSignature: string,
  encodedPublicKey: string
): void {
  const payload = encodedJson(orderedPayload, MAX_TRUST_RECORD_BYTES, 'CI evidence record');
  const publicKey = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(encodedPublicKey, 'base64url')]),
    format: 'der',
    type: 'spki',
  });
  if (
    !verifySignature(
      null,
      domainHash(domain, payload),
      publicKey,
      Buffer.from(encodedSignature, 'base64url')
    )
  ) {
    throw new Error('CI evidence signature is invalid');
  }
}

function assertCurrentValidity(
  label: string,
  issuedAt: number,
  expiresAt: number,
  nowSeconds: number
): void {
  if (expiresAt <= issuedAt) throw new Error(`${label} validity window is invalid`);
  if (nowSeconds < issuedAt) throw new Error(`${label} is not valid yet`);
  if (nowSeconds >= expiresAt) throw new Error(`${label} has expired`);
}

function publicKeyHash(publicKey: string): string {
  return `sha256:${createHash('sha256').update(Buffer.from(publicKey, 'base64url')).digest('hex')}`;
}

function freezeVerified(
  bundle: DeploymentPreflightCiEvidenceBundle
): VerifiedDeploymentPreflightCiEvidence {
  const build = bundle.build_record.payload;
  const artifact = bundle.artifact_record.payload;
  return Object.freeze({
    bundle: Object.freeze(clone(bundle)),
    enrollment: Object.freeze({
      environmentId: bundle.environment_id,
      build: Object.freeze({
        keyId: bundle.build_authority.key_id,
        publicKey: bundle.build_authority.public_key,
        publicKeyHash: publicKeyHash(bundle.build_authority.public_key),
      }),
      artifact: Object.freeze({
        keyId: bundle.artifact_authority.key_id,
        publicKey: bundle.artifact_authority.public_key,
        publicKeyHash: publicKeyHash(bundle.artifact_authority.public_key),
      }),
    }),
    runId: build.run_id,
    imageDigest: artifact.image_digest,
  });
}

export function verifyDeploymentPreflightCiEvidenceBundle(
  value: unknown,
  options: Readonly<{ nowSeconds?: number }> = {}
): VerifiedDeploymentPreflightCiEvidence {
  encodedJson(value, MAX_BUNDLE_BYTES, 'CI evidence bundle');
  const bundle = ciEvidenceBundleSchema.parse(value);
  const nowSeconds = options.nowSeconds ?? Math.floor(Date.now() / 1_000);
  if (!Number.isSafeInteger(nowSeconds) || nowSeconds < 0) {
    throw new Error('CI evidence verification clock is invalid');
  }

  const expectedBuildKeyId = `build-${bundle.environment_id}`;
  const expectedArtifactKeyId = `artifact-${bundle.environment_id}`;
  const sourceRepository = `${bundle.github.owner}/${bundle.github.repository}`;
  const build = bundle.build_record.payload;
  const artifact = bundle.artifact_record.payload;
  if (
    bundle.build_authority.key_id !== expectedBuildKeyId ||
    build.key_id !== expectedBuildKeyId ||
    bundle.artifact_authority.key_id !== expectedArtifactKeyId ||
    artifact.key_id !== expectedArtifactKeyId
  ) {
    throw new Error('CI evidence authority does not match the environment');
  }
  if (
    build.repository !== sourceRepository ||
    build.workflow_ref !== bundle.github.workflow_ref ||
    artifact.source_repository !== sourceRepository ||
    artifact.registry_id !== bundle.ecr.registry_id ||
    artifact.region !== bundle.ecr.region ||
    artifact.repository_name !== bundle.ecr.repository ||
    artifact.source_run_id !== build.run_id ||
    artifact.commit_sha !== build.commit_sha ||
    artifact.image_digest !== build.output_digest
  ) {
    throw new Error('CI evidence records do not match the declared routes and provenance');
  }
  assertCurrentValidity('Build provenance', build.issued_at, build.expires_at, nowSeconds);
  assertCurrentValidity('Artifact provenance', artifact.issued_at, artifact.expires_at, nowSeconds);
  verifyTrustRecordSignature(
    BUILD_TRUST_DOMAIN,
    orderedBuildPayload(build),
    bundle.build_record.signature,
    bundle.build_authority.public_key
  );
  verifyTrustRecordSignature(
    ARTIFACT_TRUST_DOMAIN,
    orderedArtifactPayload(artifact),
    bundle.artifact_record.signature,
    bundle.artifact_authority.public_key
  );
  return freezeVerified(bundle);
}

function recordBytes(record: SignedBuildTrustRecord | SignedArtifactTrustRecord): Buffer {
  const bytes = Buffer.from(`${JSON.stringify(record)}\n`, 'utf8');
  if (bytes.length > MAX_TRUST_RECORD_BYTES) {
    throw new Error('CI evidence record exceeds its size limit');
  }
  return bytes;
}

async function ensureDirectoryWithoutSymlinks(directory: string): Promise<void> {
  const parsed = path.parse(directory);
  const segments = directory.slice(parsed.root.length).split(path.sep).filter(Boolean);
  let current = parsed.root;
  for (const segment of segments) {
    current = path.join(current, segment);
    try {
      const stat = await fs.lstat(current);
      if (stat.isSymbolicLink() || !stat.isDirectory()) {
        throw new Error('CI evidence directory path is not a regular directory');
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      await fs.mkdir(current, { mode: 0o700 });
      const created = await fs.lstat(current);
      if (created.isSymbolicLink() || !created.isDirectory()) {
        throw new Error('CI evidence directory path is not a regular directory');
      }
    }
  }
}

async function readExistingRegularFile(filePath: string): Promise<Buffer | null> {
  try {
    const stat = await fs.lstat(filePath);
    if (stat.isSymbolicLink() || !stat.isFile() || stat.size > MAX_TRUST_RECORD_BYTES) {
      throw new Error('CI evidence destination is not a regular bounded file');
    }
    return fs.readFile(filePath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw error;
  }
}

type StagedFile = {
  temporaryPath: string;
  finalPath: string;
  contents: Buffer;
};

async function stageFile(finalPath: string, contents: Buffer): Promise<StagedFile> {
  const temporaryPath = path.join(path.dirname(finalPath), `.ci-evidence.${randomUUID()}.tmp`);
  const handle = await fs.open(temporaryPath, 'wx', 0o600);
  try {
    await handle.writeFile(contents);
    await handle.sync();
  } catch (error) {
    await handle.close().catch(() => undefined);
    await fs.unlink(temporaryPath).catch(() => undefined);
    throw error;
  }
  await handle.close();
  return { temporaryPath, finalPath, contents };
}

async function commitStagedFile(staged: StagedFile): Promise<boolean> {
  const existing = await readExistingRegularFile(staged.finalPath);
  if (existing) {
    if (!existing.equals(staged.contents)) {
      throw new Error('CI evidence destination already contains different content');
    }
    return false;
  }
  await fs.link(staged.temporaryPath, staged.finalPath);
  return true;
}

async function rollbackCommittedFile(staged: StagedFile): Promise<void> {
  const current = await readExistingRegularFile(staged.finalPath).catch(() => null);
  if (current?.equals(staged.contents)) {
    await fs.unlink(staged.finalPath).catch(() => undefined);
  }
}

export class AccordLockDeploymentPreflightCiEvidenceImporter {
  private readonly artifactRecordsDirectory: string;
  private readonly buildRecordsDirectory: string;
  private readonly nowSeconds: () => number;
  private writeTail: Promise<void> = Promise.resolve();

  constructor(options: DeploymentPreflightCiEvidenceImporterOptions) {
    for (const directory of [options.buildRecordsDirectory, options.artifactRecordsDirectory]) {
      if (
        typeof directory !== 'string' ||
        !path.isAbsolute(directory) ||
        directory.includes('\0')
      ) {
        throw new Error('CI evidence directories must be absolute');
      }
    }
    this.buildRecordsDirectory = path.normalize(options.buildRecordsDirectory);
    this.artifactRecordsDirectory = path.normalize(options.artifactRecordsDirectory);
    const buildIdentity =
      process.platform === 'win32'
        ? this.buildRecordsDirectory.toLowerCase()
        : this.buildRecordsDirectory;
    const artifactIdentity =
      process.platform === 'win32'
        ? this.artifactRecordsDirectory.toLowerCase()
        : this.artifactRecordsDirectory;
    if (buildIdentity === artifactIdentity) {
      throw new Error('Build and artifact evidence directories must be distinct');
    }
    this.nowSeconds = options.nowSeconds ?? (() => Math.floor(Date.now() / 1_000));
  }

  async importBundle(value: unknown): Promise<DeploymentPreflightCiEvidenceImportResult> {
    const now = this.nowSeconds();
    const verified = verifyDeploymentPreflightCiEvidenceBundle(value, { nowSeconds: now });
    let result: DeploymentPreflightCiEvidenceImportResult | null = null;
    const operation = this.writeTail.then(async () => {
      const current = verifyDeploymentPreflightCiEvidenceBundle(verified.bundle, {
        nowSeconds: this.nowSeconds(),
      });
      await ensureDirectoryWithoutSymlinks(this.buildRecordsDirectory);
      await ensureDirectoryWithoutSymlinks(this.artifactRecordsDirectory);
      const buildPath = path.join(
        this.buildRecordsDirectory,
        `${current.bundle.build_record.payload.run_id}.json`
      );
      const artifactPath = path.join(
        this.artifactRecordsDirectory,
        `${current.bundle.artifact_record.payload.image_digest.slice('sha256:'.length)}.json`
      );
      const buildContents = recordBytes(current.bundle.build_record);
      const artifactContents = recordBytes(current.bundle.artifact_record);
      const [existingBuild, existingArtifact] = await Promise.all([
        readExistingRegularFile(buildPath),
        readExistingRegularFile(artifactPath),
      ]);
      if (existingBuild && !existingBuild.equals(buildContents)) {
        throw new Error('Build provenance already exists with different content');
      }
      if (existingArtifact && !existingArtifact.equals(artifactContents)) {
        throw new Error('Artifact provenance already exists with different content');
      }

      const staged: StagedFile[] = [];
      const committed: StagedFile[] = [];
      try {
        if (!existingBuild) staged.push(await stageFile(buildPath, buildContents));
        if (!existingArtifact) staged.push(await stageFile(artifactPath, artifactContents));
        for (const file of staged) {
          if (await commitStagedFile(file)) committed.push(file);
        }
      } catch (error) {
        await Promise.all(committed.map(rollbackCommittedFile));
        throw error;
      } finally {
        await Promise.all(
          staged.map((file) => fs.unlink(file.temporaryPath).catch(() => undefined))
        );
      }
      result = Object.freeze({
        environmentId: current.bundle.environment_id,
        runId: current.runId,
        imageDigest: current.imageDigest,
        buildRecordPath: buildPath,
        artifactRecordPath: artifactPath,
        enrollment: current.enrollment,
      });
    });
    this.writeTail = operation.then(
      () => undefined,
      () => undefined
    );
    await operation;
    if (!result) throw new Error('CI evidence import did not complete');
    return result;
  }
}
