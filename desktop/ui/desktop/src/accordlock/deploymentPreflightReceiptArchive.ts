import { createHash, createPublicKey, randomUUID, verify as verifySignature } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

import { z } from 'zod';

import {
  parseSignedDeploymentPreflightReceipt,
  type SignedDeploymentPreflightReceipt,
} from './deploymentPreflightReceipt';

const ARCHIVE_SCHEMA_VERSION = 1 as const;
const PACKAGE_SCHEMA_VERSION = 1 as const;
const PACKAGE_TYPE = 'ACCORDLOCK_DEPLOYMENT_PREFLIGHT_RECEIPT' as const;
const RECEIPT_HASH_DOMAIN = Buffer.from('accordlock:v1:deployment-preflight-receipt\0', 'utf8');
const RECEIPT_SIGNATURE_DOMAIN = Buffer.from(
  'accordlock:v1:deployment-preflight-receipt-signature\0',
  'utf8'
);
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const MAX_ARCHIVE_RECORDS = 4_096;
const MAX_RECORD_BYTES = 3 * 1_024 * 1_024;
const MAX_RECEIPT_BYTES = 2 * 1_024 * 1_024;
const MAX_LIST_LIMIT = 200;
const DEFAULT_LIST_LIMIT = 50;

const digestSchema = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const uuidSchema = z.string().uuid();
const safeTimestampSchema = z.number().int().nonnegative().safe();
const positiveSafeIntegerSchema = z.number().int().positive().safe();
const keyIdSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u);
const base64Url32Schema = z.string().refine((value) => canonicalBase64Url(value, 32));

type JsonRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

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

function canonicalBase64Url(value: unknown, bytes: number): value is string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/u.test(value)) return false;
  const decoded = Buffer.from(value, 'base64url');
  return decoded.length === bytes && decoded.toString('base64url') === value;
}

function canonicalJson(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isSafeInteger(value)) return String(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  }
  throw new Error('Deployment preflight archive contains non-canonical data');
}

function sha256(value: string | Buffer): string {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function immutableClone<T>(value: T): T {
  return JSON.parse(canonicalJson(value)) as T;
}

function jsonClone<T>(value: T): T {
  const encoded = JSON.stringify(value);
  if (Buffer.byteLength(encoded, 'utf8') > MAX_RECEIPT_BYTES) {
    throw new Error('Deployment preflight receipt is too large');
  }
  return JSON.parse(encoded) as T;
}

function normalizeRustOptionalNulls(value: unknown): unknown {
  if (!isRecord(value) || !isRecord(value.payload)) return value;
  const payload: JsonRecord = { ...value.payload };
  for (const key of [
    'policy_decision_hash',
    'evidence_root',
    'evaluation_attestation',
    'valid_until',
  ]) {
    if (payload[key] === null) delete payload[key];
  }
  if (Array.isArray(payload.checks)) {
    payload.checks = payload.checks.map((value) => {
      if (!isRecord(value)) return value;
      const check: JsonRecord = { ...value };
      for (const key of ['reason_code', 'observed_at', 'freshness_seconds', 'evidence_reference']) {
        if (check[key] === null) delete check[key];
      }
      return check;
    });
  }
  return { ...value, payload };
}

const publicTrustSchema = z
  .object({
    key_id: keyIdSchema,
    public_key: base64Url32Schema,
  })
  .strict();

const redactedVerificationProfileSchema = z
  .object({
    schema_version: z.literal(2),
    profile_id: uuidSchema,
    organization_id: boundedText(256),
    environment_id: boundedText(256),
    executor_audience: boundedText(512),
    github: z
      .object({
        authority: boundedText(253),
        api_base_path: boundedText(1_024),
        owner: boundedText(100),
        repository: boundedText(100),
        workflow_ref: boundedText(256),
        minimum_approvals: z.number().int().min(1).max(100).safe(),
        maximum_response_bytes: positiveSafeIntegerSchema.max(2 * 1_024 * 1_024),
      })
      .strict(),
    ecr: z
      .object({
        registry_id: z.string().regex(/^\d{12}$/u),
        region: z.string().regex(/^[a-z]{2}(?:-[a-z0-9]+)+-\d$/u),
        repository: boundedText(512),
        maximum_response_bytes: positiveSafeIntegerSchema.max(2 * 1_024 * 1_024),
      })
      .strict(),
    eks_discovery: z
      .object({
        maximum_response_bytes: positiveSafeIntegerSchema.max(2 * 1_024 * 1_024),
      })
      .strict(),
    kubernetes: z
      .object({
        expected_endpoint: boundedText(2_048),
        cluster_name: boundedText(253),
        namespace: boundedText(253),
        deployment: boundedText(253),
        container: boundedText(253),
        maximum_response_bytes: positiveSafeIntegerSchema.max(2 * 1_024 * 1_024),
      })
      .strict(),
    build_trust: publicTrustSchema,
    artifact_trust: publicTrustSchema,
    receipt: publicTrustSchema.extend({ public_key_hash: digestSchema }).strict(),
    evidence_ttl_seconds: positiveSafeIntegerSchema.max(86_400),
    maximum_source_age_seconds: positiveSafeIntegerSchema.max(86_400),
    maximum_future_skew_seconds: positiveSafeIntegerSchema.max(3_600),
    created_at: safeTimestampSchema,
    expires_at: safeTimestampSchema,
    environment_profile_hash: digestSchema,
  })
  .strict()
  .superRefine((profile, context) => {
    if (profile.expires_at <= profile.created_at) {
      context.addIssue({
        code: 'custom',
        path: ['expires_at'],
        message: 'must be after created_at',
      });
    }
    if (profile.environment_id !== profile.profile_id) {
      context.addIssue({
        code: 'custom',
        path: ['environment_id'],
        message: 'must match profile_id',
      });
    }
  });

export type DeploymentPreflightRedactedVerificationProfile = z.infer<
  typeof redactedVerificationProfileSchema
>;

const receiptKeySchema = z
  .object({
    algorithm: z.literal('Ed25519'),
    key_id: keyIdSchema,
    public_key: base64Url32Schema,
    public_key_hash: digestSchema,
  })
  .strict();

const packageBodySchema = z
  .object({
    schema_version: z.literal(PACKAGE_SCHEMA_VERSION),
    package_type: z.literal(PACKAGE_TYPE),
    receipt: z.unknown(),
    receipt_key: receiptKeySchema,
    verification_profile: redactedVerificationProfileSchema,
  })
  .strict();

const exportPackageSchema = packageBodySchema.extend({ package_digest: digestSchema }).strict();

export type DeploymentPreflightReceiptExportPackage = z.infer<typeof exportPackageSchema> & {
  receipt: SignedDeploymentPreflightReceipt;
};

const storedRecordSchema = z
  .object({
    schema_version: z.literal(ARCHIVE_SCHEMA_VERSION),
    archived_at: safeTimestampSchema,
    package: z.unknown(),
  })
  .strict();

export type DeploymentPreflightReceiptArchiveSummary = Readonly<{
  checkId: string;
  receiptHash: string;
  packageDigest: string;
  environmentId: string;
  outcome: 'PASSED' | 'BLOCKED' | 'INDETERMINATE';
  completedAt: number;
  validUntil: number | null;
  repository: string;
  imageDigest: string;
  clusterIdentity: string;
  namespace: string;
  deployment: string;
  archivedAt: number;
}>;

export type AppendVerifiedDeploymentPreflightReceiptInput = Readonly<{
  /** This capability is produced only by the trusted runner adapter. */
  signatureVerified: true;
  receipt: unknown;
  receiptPublicKey: string;
  receiptKeyId: string;
  verificationProfile: unknown;
}>;

export type DeploymentPreflightReceiptArchiveOptions = Readonly<{
  directory: string;
  nowSeconds?: () => number;
}>;

export type DeploymentPreflightReceiptExport = Readonly<{
  fileName: string;
  packageDigest: string;
  contents: Buffer;
}>;

type ParsedStoredRecord = Readonly<{
  archivedAt: number;
  package: DeploymentPreflightReceiptExportPackage;
}>;

const authorityDomainSchema = z
  .object({
    root: digestSchema,
    epoch: z.number().int().nonnegative().safe(),
    activation_id: uuidSchema,
  })
  .strict();

const authorityVectorSchema = z
  .object({
    policy: authorityDomainSchema,
    registry: authorityDomainSchema,
    revocation: authorityDomainSchema,
    connector: authorityDomainSchema,
    resource: authorityDomainSchema,
    signer: authorityDomainSchema,
    mediation: authorityDomainSchema,
    grant_registry: authorityDomainSchema,
    office_act_registry: authorityDomainSchema,
    principal_registry: authorityDomainSchema,
    workload_build_allowlist: authorityDomainSchema,
    kernel_configuration: authorityDomainSchema,
  })
  .strict();

const evaluationAttestationSchema = z
  .object({
    attestation: z
      .object({
        schema_version: z.literal(1),
        request_id: uuidSchema,
        evaluation_nonce: uuidSchema,
        tenant: boundedText(256),
        actor: boundedText(512),
        evaluated_at: safeTimestampSchema,
        outcome: z.enum(['ALLOW', 'DENY']),
        reasons: z.array(z.string().regex(/^[A-Z][A-Z0-9_]{1,127}$/u)).max(64),
        template_hash: digestSchema,
        evidence_root: digestSchema,
        principals: z.array(boundedText(512)).max(256),
        policy_root: digestSchema,
        authority: authorityVectorSchema,
        consume_before: safeTimestampSchema,
      })
      .strict(),
    cose_sign1: z.string().refine((value) => canonicalStandardBase64(value, 1_048_576)),
  })
  .strict();

function canonicalStandardBase64(value: unknown, maximumBytes: number): value is string {
  if (typeof value !== 'string' || value.length > Math.ceil(maximumBytes / 3) * 4) return false;
  const decoded = Buffer.from(value, 'base64');
  return decoded.length <= maximumBytes && decoded.toString('base64') === value;
}

function orderedAuthorityVector(value: z.infer<typeof authorityVectorSchema>): JsonRecord {
  return {
    policy: value.policy,
    registry: value.registry,
    revocation: value.revocation,
    connector: value.connector,
    resource: value.resource,
    signer: value.signer,
    mediation: value.mediation,
    grant_registry: value.grant_registry,
    office_act_registry: value.office_act_registry,
    principal_registry: value.principal_registry,
    workload_build_allowlist: value.workload_build_allowlist,
    kernel_configuration: value.kernel_configuration,
  };
}

function orderedEvaluationAttestation(value: unknown): JsonRecord | null {
  if (value === undefined || value === null) return null;
  const parsed = evaluationAttestationSchema.parse(value);
  const attestation = parsed.attestation;
  return {
    attestation: {
      schema_version: attestation.schema_version,
      request_id: attestation.request_id,
      evaluation_nonce: attestation.evaluation_nonce,
      tenant: attestation.tenant,
      actor: attestation.actor,
      evaluated_at: attestation.evaluated_at,
      outcome: attestation.outcome,
      reasons: attestation.reasons,
      template_hash: attestation.template_hash,
      evidence_root: attestation.evidence_root,
      principals: attestation.principals,
      policy_root: attestation.policy_root,
      authority: orderedAuthorityVector(attestation.authority),
      consume_before: attestation.consume_before,
    },
    cose_sign1: parsed.cose_sign1,
  };
}

/** Recreates the exact serde field order used by the trusted Rust runner. */
function rustReceiptPayload(receipt: SignedDeploymentPreflightReceipt): JsonRecord {
  const payload = receipt.payload;
  return {
    schema_version: payload.schema_version,
    check_id: payload.check_id,
    request_id: payload.request_id,
    environment_id: payload.environment_id,
    environment_profile_hash: payload.environment_profile_hash,
    runner_id: payload.runner_id,
    runner_registration_hash: payload.runner_registration_hash,
    dispatch_hash: payload.dispatch_hash,
    policy_decision_hash: payload.policy_decision_hash ?? null,
    outcome: payload.outcome,
    reason_codes: payload.reason_codes,
    candidate: {
      repository: payload.candidate.repository,
      pull_number: payload.candidate.pull_number,
      commit_sha: payload.candidate.commit_sha,
      workflow_ref: payload.candidate.workflow_ref,
      actions_run_id: payload.candidate.actions_run_id,
      ecr_repository: payload.candidate.ecr_repository,
      image_digest: payload.candidate.image_digest,
    },
    target: {
      cluster_identity: payload.target.cluster_identity,
      cluster_endpoint: payload.target.cluster_endpoint,
      cluster_ca_hash: payload.target.cluster_ca_hash,
      namespace: payload.target.namespace,
      deployment: payload.target.deployment,
      deployment_uid: payload.target.deployment_uid,
      resource_version: payload.target.resource_version,
      container: payload.target.container,
      observed_image_digest: payload.target.observed_image_digest,
    },
    checks: payload.checks.map((check) => ({
      kind: check.kind,
      status: check.status,
      summary: check.summary,
      reason_code: check.reason_code ?? null,
      observed_at: check.observed_at ?? null,
      freshness_seconds: check.freshness_seconds ?? null,
      evidence_reference: check.evidence_reference ?? null,
    })),
    evidence_root: payload.evidence_root ?? null,
    evaluation_attestation: orderedEvaluationAttestation(payload.evaluation_attestation),
    started_at: payload.started_at,
    completed_at: payload.completed_at,
    valid_until: payload.valid_until ?? null,
    effect: payload.effect,
    deployment_performed: payload.deployment_performed,
  };
}

function domainHash(domain: Buffer, encoded: Buffer): string {
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(encoded.length));
  return `sha256:${createHash('sha256')
    .update(domain)
    .update(length)
    .update(encoded)
    .digest('hex')}`;
}

function verifyReceiptCryptography(
  receipt: SignedDeploymentPreflightReceipt,
  receiptPublicKey: string
): void {
  const encodedPayload = Buffer.from(JSON.stringify(rustReceiptPayload(receipt)), 'utf8');
  if (domainHash(RECEIPT_HASH_DOMAIN, encodedPayload) !== receipt.receipt_hash) {
    throw new Error('Deployment preflight receipt payload hash is invalid');
  }

  const rawPublicKey = Buffer.from(receiptPublicKey, 'base64url');
  const rawReceiptHash = Buffer.from(receipt.receipt_hash.slice('sha256:'.length), 'hex');
  const signature = Buffer.from(receipt.signature, 'base64url');
  const message = Buffer.concat([RECEIPT_SIGNATURE_DOMAIN, rawReceiptHash]);
  const publicKey = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, rawPublicKey]),
    format: 'der',
    type: 'spki',
  });
  if (!verifySignature(null, message, publicKey, signature)) {
    throw new Error('Deployment preflight receipt signature is invalid');
  }
}

function bindAndVerifyPackage(value: unknown): DeploymentPreflightReceiptExportPackage {
  const parsed = exportPackageSchema.parse(value);
  const receipt = parseSignedDeploymentPreflightReceipt(parsed.receipt);
  const profile = parsed.verification_profile;
  const receiptKey = parsed.receipt_key;
  const packageBody = {
    schema_version: parsed.schema_version,
    package_type: parsed.package_type,
    receipt,
    receipt_key: receiptKey,
    verification_profile: profile,
  };
  if (sha256(canonicalJson(packageBody)) !== parsed.package_digest) {
    throw new Error('Deployment preflight export package digest is invalid');
  }
  if (
    receipt.signer_key_id !== receiptKey.key_id ||
    receipt.receipt_public_key_hash !== receiptKey.public_key_hash ||
    sha256(Buffer.from(receiptKey.public_key, 'base64url')) !== receiptKey.public_key_hash ||
    profile.receipt.key_id !== receiptKey.key_id ||
    profile.receipt.public_key !== receiptKey.public_key ||
    profile.receipt.public_key_hash !== receiptKey.public_key_hash ||
    profile.environment_id !== receipt.payload.environment_id ||
    profile.environment_profile_hash !== receipt.payload.environment_profile_hash
  ) {
    throw new Error('Deployment preflight export package binding is invalid');
  }
  verifyReceiptCryptography(receipt, receiptKey.public_key);
  return immutableClone({ ...packageBody, package_digest: parsed.package_digest });
}

function createPackage(
  input: AppendVerifiedDeploymentPreflightReceiptInput
): DeploymentPreflightReceiptExportPackage {
  if (input.signatureVerified !== true) {
    throw new Error('Deployment preflight receipt was not verified by the trusted runner');
  }
  const receipt = parseSignedDeploymentPreflightReceipt(normalizeRustOptionalNulls(input.receipt));
  const receiptForPackage = jsonClone(receipt);
  const profile = redactedVerificationProfileSchema.parse(input.verificationProfile);
  const receiptPublicKey = base64Url32Schema.parse(input.receiptPublicKey);
  const receiptKeyId = keyIdSchema.parse(input.receiptKeyId);
  const receiptKey = receiptKeySchema.parse({
    algorithm: 'Ed25519',
    key_id: receiptKeyId,
    public_key: receiptPublicKey,
    public_key_hash: sha256(Buffer.from(receiptPublicKey, 'base64url')),
  });
  const body = packageBodySchema.parse({
    schema_version: PACKAGE_SCHEMA_VERSION,
    package_type: PACKAGE_TYPE,
    receipt: receiptForPackage,
    receipt_key: receiptKey,
    verification_profile: profile,
  });
  return bindAndVerifyPackage({ ...body, package_digest: sha256(canonicalJson(body)) });
}

function recordFileName(receiptHash: string): string {
  return `${receiptHash.slice('sha256:'.length)}.json`;
}

function summary(record: ParsedStoredRecord): DeploymentPreflightReceiptArchiveSummary {
  const receipt = record.package.receipt;
  const payload = receipt.payload;
  return Object.freeze({
    checkId: payload.check_id,
    receiptHash: receipt.receipt_hash,
    packageDigest: record.package.package_digest,
    environmentId: payload.environment_id,
    outcome: payload.outcome,
    completedAt: payload.completed_at,
    validUntil: payload.valid_until ?? null,
    repository: payload.candidate.repository,
    imageDigest: payload.candidate.image_digest,
    clusterIdentity: payload.target.cluster_identity,
    namespace: payload.target.namespace,
    deployment: payload.target.deployment,
    archivedAt: record.archivedAt,
  });
}

async function writeAtomicExclusive(filePath: string, contents: Buffer): Promise<void> {
  const directory = path.dirname(filePath);
  const temporaryPath = path.join(directory, `.preflight-receipt.${randomUUID()}.tmp`);
  let handle: fs.FileHandle | null = null;
  try {
    handle = await fs.open(temporaryPath, 'wx', 0o600);
    await handle.writeFile(contents);
    await handle.sync();
    await handle.close();
    handle = null;
    await fs.link(temporaryPath, filePath);
    await fs.unlink(temporaryPath);
  } catch (error) {
    await handle?.close().catch(() => undefined);
    await fs.unlink(temporaryPath).catch(() => undefined);
    throw error;
  }
}

export class AccordLockDeploymentPreflightReceiptArchive {
  private readonly directory: string;
  private readonly nowSeconds: () => number;
  private writeTail: Promise<void> = Promise.resolve();

  constructor(options: DeploymentPreflightReceiptArchiveOptions) {
    if (
      typeof options.directory !== 'string' ||
      !path.isAbsolute(options.directory) ||
      options.directory.includes('\0')
    ) {
      throw new Error('Deployment preflight receipt archive directory must be absolute');
    }
    this.directory = path.normalize(options.directory);
    this.nowSeconds = options.nowSeconds ?? (() => Math.floor(Date.now() / 1_000));
  }

  /** Trusted-main-process ingestion. There is intentionally no raw mutation method or IPC here. */
  async appendVerified(
    input: AppendVerifiedDeploymentPreflightReceiptInput
  ): Promise<DeploymentPreflightReceiptArchiveSummary> {
    const exportPackage = createPackage(input);
    let result: DeploymentPreflightReceiptArchiveSummary | null = null;
    const operation = this.writeTail.then(async () => {
      const records = await this.readAll();
      const receipt = exportPackage.receipt;
      const sameHash = records.find(
        (record) => record.package.receipt.receipt_hash === receipt.receipt_hash
      );
      if (sameHash) {
        if (sameHash.package.package_digest !== exportPackage.package_digest) {
          throw new Error('Deployment preflight receipt hash is already archived differently');
        }
        result = summary(sameHash);
        return;
      }
      if (
        records.some(
          (record) => record.package.receipt.payload.check_id === receipt.payload.check_id
        )
      ) {
        throw new Error('Deployment preflight check identifier is already archived');
      }
      if (records.length >= MAX_ARCHIVE_RECORDS) {
        throw new Error('Deployment preflight receipt archive is full');
      }
      const archivedAt = this.nowSeconds();
      if (!Number.isSafeInteger(archivedAt) || archivedAt < 0) {
        throw new Error('Deployment preflight archive clock is invalid');
      }
      const stored = storedRecordSchema.parse({
        schema_version: ARCHIVE_SCHEMA_VERSION,
        archived_at: archivedAt,
        package: exportPackage,
      });
      const contents = Buffer.from(`${canonicalJson(stored)}\n`, 'utf8');
      if (contents.length > MAX_RECORD_BYTES) {
        throw new Error('Deployment preflight archive record is too large');
      }
      await fs.mkdir(this.directory, { recursive: true, mode: 0o700 });
      await writeAtomicExclusive(
        path.join(this.directory, recordFileName(receipt.receipt_hash)),
        contents
      );
      result = summary({ archivedAt, package: exportPackage });
    });
    this.writeTail = operation.then(
      () => undefined,
      () => undefined
    );
    await operation;
    if (!result) throw new Error('Deployment preflight receipt archive write failed');
    return result;
  }

  async listSummaries(
    options: {
      environmentId?: string;
      limit?: number;
    } = {}
  ): Promise<readonly DeploymentPreflightReceiptArchiveSummary[]> {
    await this.writeTail;
    const limit = options.limit ?? DEFAULT_LIST_LIMIT;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_LIST_LIMIT) {
      throw new Error('Deployment preflight receipt archive list limit is invalid');
    }
    const environmentId = options.environmentId;
    if (environmentId !== undefined) uuidSchema.parse(environmentId);
    return (await this.readAll())
      .filter(
        (record) =>
          environmentId === undefined ||
          record.package.receipt.payload.environment_id === environmentId
      )
      .map(summary)
      .sort(
        (left, right) =>
          right.completedAt - left.completedAt || left.checkId.localeCompare(right.checkId, 'en')
      )
      .slice(0, limit);
  }

  async loadPackage(receiptHash: unknown): Promise<DeploymentPreflightReceiptExportPackage> {
    await this.writeTail;
    const normalizedHash = digestSchema.parse(receiptHash);
    const records = await this.readAll();
    const record = records.find(
      (candidate) => candidate.package.receipt.receipt_hash === normalizedHash
    );
    if (!record) throw new Error('Deployment preflight receipt was not found');
    return immutableClone(record.package);
  }

  async exportPackage(receiptHash: unknown): Promise<DeploymentPreflightReceiptExport> {
    const exportPackage = await this.loadPackage(receiptHash);
    const checkId = exportPackage.receipt.payload.check_id;
    return Object.freeze({
      fileName: `accordlock-deployment-preflight-${checkId}.json`,
      packageDigest: exportPackage.package_digest,
      contents: Buffer.from(`${canonicalJson(exportPackage)}\n`, 'utf8'),
    });
  }

  private async readAll(): Promise<ParsedStoredRecord[]> {
    const entries = await fs
      .readdir(this.directory, { withFileTypes: true })
      .catch((error: NodeJS.ErrnoException) => {
        if (error.code === 'ENOENT') return null;
        throw error;
      });
    if (!entries) return [];
    const committed = entries.filter((entry) => entry.name.endsWith('.json'));
    if (committed.length > MAX_ARCHIVE_RECORDS) {
      throw new Error('Deployment preflight receipt archive exceeds its record limit');
    }
    const records: ParsedStoredRecord[] = [];
    for (const entry of committed) {
      if (!entry.isFile() || !/^[0-9a-f]{64}\.json$/u.test(entry.name)) {
        throw new Error('Deployment preflight receipt archive contains an invalid record');
      }
      const filePath = path.join(this.directory, entry.name);
      const stat = await fs.lstat(filePath);
      if (
        !stat.isFile() ||
        stat.isSymbolicLink() ||
        stat.size < 2 ||
        stat.size > MAX_RECORD_BYTES
      ) {
        throw new Error('Deployment preflight receipt archive record is invalid');
      }
      const raw = await fs.readFile(filePath);
      let decoded: unknown;
      try {
        decoded = JSON.parse(raw.toString('utf8'));
      } catch {
        throw new Error('Deployment preflight receipt archive record is corrupt');
      }
      const stored = storedRecordSchema.parse(decoded);
      const exportPackage = bindAndVerifyPackage(stored.package);
      if (entry.name !== recordFileName(exportPackage.receipt.receipt_hash)) {
        throw new Error('Deployment preflight receipt archive filename binding is invalid');
      }
      records.push({ archivedAt: stored.archived_at, package: exportPackage });
    }
    if (
      new Set(records.map((record) => record.package.receipt.receipt_hash)).size !==
        records.length ||
      new Set(records.map((record) => record.package.receipt.payload.check_id)).size !==
        records.length
    ) {
      throw new Error('Deployment preflight receipt archive contains duplicate records');
    }
    return records;
  }
}

export function parseDeploymentPreflightRedactedVerificationProfile(
  value: unknown
): DeploymentPreflightRedactedVerificationProfile {
  return redactedVerificationProfileSchema.parse(value);
}

/** Verifies a portable package without consulting the mutable environment store. */
export function parseDeploymentPreflightReceiptExportPackage(
  value: unknown
): DeploymentPreflightReceiptExportPackage {
  return bindAndVerifyPackage(value);
}
