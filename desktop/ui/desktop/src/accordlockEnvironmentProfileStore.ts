import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

import {
  ACCORDLOCK_ENVIRONMENT_PROFILE_SCHEMA_VERSION,
  isAccordLockEnvironmentProfileId,
  parseAccordLockEnvironmentProfileInput,
  type AccordLockEnvironmentProfileExecutionBundle,
  type AccordLockEnvironmentProfileStatus,
  type AccordLockEnvironmentProfileSummary,
  type AccordLockEnvironmentRunnerProfile,
  type AccordLockEnvironmentVerificationFailureCode,
  type AccordLockEnvironmentProvider,
} from './accordlock/environmentProfiles';

const STORE_SCHEMA_VERSION = 2 as const;
const MAX_STORE_BYTES = 512 * 1_024;
const SECURE_LINUX_BACKENDS = new Set(['gnome_libsecret', 'kwallet', 'kwallet5', 'kwallet6']);

type StoredCredential = {
  reference: string;
  material: string;
};

type StoredProfile = {
  id: string;
  name: string;
  runner: { mode: 'LOCAL_BUNDLED' };
  github: { repository: string; workflow: string };
  aws: { accountId: string; region: string; ecrRepository: string };
  kubernetes: {
    clusterName: string;
    expectedEndpoint: string;
    namespace: string;
    deployment: string;
    container: string;
  };
  credentials: Record<AccordLockEnvironmentProvider, StoredCredential>;
  credentialRevision: string;
  status: AccordLockEnvironmentProfileStatus;
  createdAt: number;
  updatedAt: number;
  verifiedAt: number | null;
  failedAt: number | null;
  failureCode: AccordLockEnvironmentVerificationFailureCode | null;
};

type StoredDocument = {
  schemaVersion: typeof STORE_SCHEMA_VERSION;
  profiles: StoredProfile[];
};

export type AccordLockTrustedEnvironmentVerification =
  | Readonly<{ status: 'VERIFIED' }>
  | Readonly<{
      status: 'FAILED';
      failureCode: AccordLockEnvironmentVerificationFailureCode;
    }>;

export interface AccordLockEnvironmentProfileSafeStorage {
  decryptString(ciphertext: Buffer): string;
  encryptString(plaintext: string): Buffer;
  getSelectedStorageBackend?(): string;
  isEncryptionAvailable(): boolean;
}

type StoreOptions = {
  directory: string;
  nowSeconds?: () => number;
  platform?: NodeJS.Platform;
  safeStorage: AccordLockEnvironmentProfileSafeStorage;
};

type JsonRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function exactKeys(value: JsonRecord, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function timestamp(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function nullableTimestamp(value: unknown): value is number | null {
  return value === null || timestamp(value);
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
  throw new Error('Environment profile contains non-canonical data');
}

function digest(value: unknown): string {
  return `sha256:${createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`;
}

function parseExpectedEksEndpoint(value: unknown): string {
  if (typeof value !== 'string' || value.length > 2_048 || value !== value.toLowerCase()) {
    throw new Error('Authenticated EKS endpoint is invalid');
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error('Authenticated EKS endpoint is invalid');
  }
  if (
    parsed.protocol !== 'https:' ||
    parsed.username ||
    parsed.password ||
    parsed.port ||
    parsed.search ||
    parsed.hash ||
    parsed.pathname !== '/' ||
    (value !== parsed.origin && value !== `${parsed.origin}/`)
  ) {
    throw new Error('Authenticated EKS endpoint is invalid');
  }
  return value;
}

function parseStoredCredential(value: unknown): StoredCredential {
  if (
    !isRecord(value) ||
    !exactKeys(value, ['reference', 'material']) ||
    typeof value.reference !== 'string' ||
    value.reference.length === 0 ||
    Buffer.byteLength(value.reference, 'utf8') > 512 ||
    typeof value.material !== 'string' ||
    value.material.length === 0 ||
    value.material.includes('\0') ||
    Buffer.byteLength(value.material, 'utf8') > 64 * 1_024
  ) {
    throw new Error('Stored environment credential is invalid');
  }
  return { reference: value.reference, material: value.material };
}

function parseStoredProfile(value: unknown): StoredProfile {
  if (
    !isRecord(value) ||
    !exactKeys(value, [
      'id',
      'name',
      'runner',
      'github',
      'aws',
      'kubernetes',
      'credentials',
      'credentialRevision',
      'status',
      'createdAt',
      'updatedAt',
      'verifiedAt',
      'failedAt',
      'failureCode',
    ]) ||
    !isAccordLockEnvironmentProfileId(value.id) ||
    !isAccordLockEnvironmentProfileId(value.credentialRevision) ||
    !timestamp(value.createdAt) ||
    !timestamp(value.updatedAt) ||
    value.updatedAt < value.createdAt ||
    !nullableTimestamp(value.verifiedAt) ||
    !nullableTimestamp(value.failedAt) ||
    !['SAVED', 'VERIFIED', 'FAILED'].includes(String(value.status)) ||
    !isRecord(value.credentials) ||
    !exactKeys(value.credentials, ['github', 'aws'])
  ) {
    throw new Error('Stored environment profile is invalid');
  }

  const failureCode = value.failureCode;
  const allowedFailureCodes: readonly AccordLockEnvironmentVerificationFailureCode[] = [
    'RUNNER_UNAVAILABLE',
    'RUNNER_TIMEOUT',
    'RUNNER_REJECTED',
    'PREFLIGHT_BLOCKED',
    'PREFLIGHT_INDETERMINATE',
    'ATTESTATION_MISMATCH',
    'PROFILE_CHANGED',
  ];
  if (
    (failureCode !== null &&
      !allowedFailureCodes.includes(failureCode as AccordLockEnvironmentVerificationFailureCode)) ||
    (value.status === 'SAVED' &&
      (value.verifiedAt !== null || value.failedAt !== null || failureCode !== null)) ||
    (value.status === 'VERIFIED' && (value.verifiedAt === null || failureCode !== null)) ||
    (value.status === 'FAILED' && (value.failedAt === null || failureCode === null))
  ) {
    throw new Error('Stored environment verification state is invalid');
  }

  const normalized = parseAccordLockEnvironmentProfileInput({
    id: value.id,
    name: value.name,
    runner: value.runner,
    github: value.github,
    aws: value.aws,
    kubernetes: isRecord(value.kubernetes)
      ? {
          clusterName: value.kubernetes.clusterName,
          namespace: value.kubernetes.namespace,
          deployment: value.kubernetes.deployment,
          container: value.kubernetes.container,
        }
      : value.kubernetes,
    credentials: {
      github: {
        reference: (value.credentials.github as JsonRecord | undefined)?.reference,
        material: {
          mode: 'SET',
          value: (value.credentials.github as JsonRecord | undefined)?.material,
        },
      },
      aws: {
        reference: (value.credentials.aws as JsonRecord | undefined)?.reference,
        material: {
          mode: 'SET',
          value: (value.credentials.aws as JsonRecord | undefined)?.material,
        },
      },
    },
  });
  const credentials = {
    github: parseStoredCredential(value.credentials.github),
    aws: parseStoredCredential(value.credentials.aws),
  };

  return {
    id: normalized.id!,
    name: normalized.name,
    runner: { mode: 'LOCAL_BUNDLED' },
    github: { ...normalized.github },
    aws: { ...normalized.aws },
    kubernetes: {
      ...normalized.kubernetes,
      expectedEndpoint: parseExpectedEksEndpoint(
        isRecord(value.kubernetes) ? value.kubernetes.expectedEndpoint : null
      ),
    },
    credentials,
    credentialRevision: value.credentialRevision,
    status: value.status as AccordLockEnvironmentProfileStatus,
    createdAt: value.createdAt,
    updatedAt: value.updatedAt,
    verifiedAt: value.verifiedAt,
    failedAt: value.failedAt,
    failureCode: failureCode as AccordLockEnvironmentVerificationFailureCode | null,
  };
}

function parseDocument(value: unknown): StoredDocument {
  if (isRecord(value) && value.schemaVersion === 1 && Array.isArray(value.profiles)) {
    value = {
      schemaVersion: 2,
      profiles: value.profiles.map((candidate) => {
        if (
          !isRecord(candidate) ||
          !isRecord(candidate.kubernetes) ||
          !isRecord(candidate.credentials)
        ) {
          throw new Error('Environment profile store is invalid');
        }
        const { serverIdentity, ...kubernetes } = candidate.kubernetes;
        const { kubernetes: _obsolete, ...credentials } = candidate.credentials;
        if (typeof serverIdentity !== 'string')
          throw new Error('Environment profile store is invalid');
        return {
          ...candidate,
          kubernetes: { ...kubernetes, expectedEndpoint: `https://${serverIdentity}` },
          credentials,
        };
      }),
    };
  }
  if (
    !isRecord(value) ||
    !exactKeys(value, ['schemaVersion', 'profiles']) ||
    value.schemaVersion !== STORE_SCHEMA_VERSION ||
    !Array.isArray(value.profiles) ||
    value.profiles.length > 64
  ) {
    throw new Error('Environment profile store is invalid');
  }
  const profiles = value.profiles.map(parseStoredProfile);
  if (new Set(profiles.map((profile) => profile.id)).size !== profiles.length) {
    throw new Error('Environment profile store contains duplicate identifiers');
  }
  return { schemaVersion: STORE_SCHEMA_VERSION, profiles };
}

function summary(profile: StoredProfile): AccordLockEnvironmentProfileSummary {
  return Object.freeze({
    id: profile.id,
    name: profile.name,
    runner: Object.freeze({ mode: profile.runner.mode }),
    github: Object.freeze({ ...profile.github }),
    aws: Object.freeze({ ...profile.aws }),
    kubernetes: Object.freeze({
      clusterName: profile.kubernetes.clusterName,
      namespace: profile.kubernetes.namespace,
      deployment: profile.kubernetes.deployment,
      container: profile.kubernetes.container,
    }),
    credentialsConfigured: Object.freeze({ github: true, aws: true }),
    status: profile.status,
    createdAt: profile.createdAt,
    updatedAt: profile.updatedAt,
    verifiedAt: profile.verifiedAt,
    failedAt: profile.failedAt,
    failureCode: profile.failureCode,
  });
}

function executionBundle(profile: StoredProfile): AccordLockEnvironmentProfileExecutionBundle {
  const runnerProfileWithoutDigest = {
    schema_version: ACCORDLOCK_ENVIRONMENT_PROFILE_SCHEMA_VERSION,
    profile_id: profile.id,
    credential_revision: profile.credentialRevision,
    runner_mode: profile.runner.mode,
    github: { ...profile.github, credential_source: profile.credentials.github.reference },
    aws: { ...profile.aws, credential_source: profile.credentials.aws.reference },
    kubernetes: {
      ...profile.kubernetes,
    },
  };
  const runnerProfile: AccordLockEnvironmentRunnerProfile = Object.freeze({
    ...runnerProfileWithoutDigest,
    profile_digest: digest(runnerProfileWithoutDigest),
    github: Object.freeze(runnerProfileWithoutDigest.github),
    aws: Object.freeze(runnerProfileWithoutDigest.aws),
    kubernetes: Object.freeze(runnerProfileWithoutDigest.kubernetes),
  });
  return Object.freeze({
    runnerProfile,
    credentialMaterial: Object.freeze({
      github: profile.credentials.github.material,
      aws: profile.credentials.aws.material,
    }),
  });
}

async function writeAtomic(filePath: string, contents: Buffer): Promise<void> {
  const directory = path.dirname(filePath);
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  const temporaryPath = path.join(directory, `.environment-profiles.${randomUUID()}.tmp`);
  let handle: fs.FileHandle | null = null;
  try {
    handle = await fs.open(temporaryPath, 'wx', 0o600);
    await handle.writeFile(contents);
    await handle.sync();
    await handle.close();
    handle = null;
    await fs.rename(temporaryPath, filePath);
  } catch (error) {
    await handle?.close().catch(() => undefined);
    await fs.unlink(temporaryPath).catch(() => undefined);
    throw error;
  }
}

export class AccordLockEnvironmentProfileStore {
  private readonly filePath: string;
  private readonly nowSeconds: () => number;
  private readonly platform: NodeJS.Platform;
  private readonly safeStorage: AccordLockEnvironmentProfileSafeStorage;
  private writeTail: Promise<void> = Promise.resolve();

  constructor(options: StoreOptions) {
    this.filePath = path.join(options.directory, 'environment-profiles.v1.bin');
    this.nowSeconds = options.nowSeconds ?? (() => Math.floor(Date.now() / 1_000));
    this.platform = options.platform ?? process.platform;
    this.safeStorage = options.safeStorage;
  }

  async list(): Promise<AccordLockEnvironmentProfileSummary[]> {
    await this.writeTail;
    return (await this.read()).profiles
      .map(summary)
      .sort(
        (left, right) => left.name.localeCompare(right.name) || left.id.localeCompare(right.id)
      );
  }

  /** Main-process-only. Resolves AWS material for authenticated discovery without persisting. */
  async resolveAwsCredential(value: unknown): Promise<
    Readonly<{
      input: ReturnType<typeof parseAccordLockEnvironmentProfileInput>;
      material: string;
      needsDiscovery: boolean;
      existingEndpoint: string | null;
    }>
  > {
    const input = parseAccordLockEnvironmentProfileInput(value);
    await this.writeTail;
    if (input.credentials.aws.material.mode === 'SET') {
      return Object.freeze({
        input,
        material: input.credentials.aws.material.value,
        needsDiscovery: true,
        existingEndpoint: null,
      });
    }
    if (!input.id) throw new Error('New environment AWS credentials must be provided');
    const existing = (await this.read()).profiles.find((profile) => profile.id === input.id);
    if (!existing) throw new Error('Environment profile does not exist');
    if (canonicalJson(existing.aws) !== canonicalJson(input.aws)) {
      throw new Error('AWS credentials must be re-entered when its route changes');
    }
    return Object.freeze({
      input,
      material: existing.credentials.aws.material,
      needsDiscovery:
        existing.aws.accountId !== input.aws.accountId ||
        existing.aws.region !== input.aws.region ||
        existing.kubernetes.clusterName !== input.kubernetes.clusterName,
      existingEndpoint: existing.kubernetes.expectedEndpoint,
    });
  }

  async save(
    value: unknown,
    expectedEndpoint?: string
  ): Promise<AccordLockEnvironmentProfileSummary> {
    const input = parseAccordLockEnvironmentProfileInput(value);
    let saved: AccordLockEnvironmentProfileSummary | null = null;
    const operation = this.writeTail.then(async () => {
      const document = await this.read();
      const now = this.nowSeconds();
      if (!timestamp(now)) throw new Error('Environment profile clock is unavailable');
      const existing =
        input.id === null
          ? undefined
          : document.profiles.find((profile) => profile.id === input.id);
      if (input.id !== null && !existing) throw new Error('Environment profile does not exist');
      const credentialsChanged = (['github', 'aws'] as const).some(
        (provider) => input.credentials[provider].material.mode === 'SET'
      );

      const routeChanged = (provider: AccordLockEnvironmentProvider): boolean => {
        if (!existing) return false;
        if (provider === 'github') {
          return canonicalJson(existing.github) !== canonicalJson(input.github);
        }
        if (provider === 'aws') return canonicalJson(existing.aws) !== canonicalJson(input.aws);
        return false;
      };

      const credential = (provider: AccordLockEnvironmentProvider): StoredCredential => {
        const candidate = input.credentials[provider];
        if (candidate.material.mode === 'KEEP') {
          const retained = existing?.credentials[provider];
          if (!retained) throw new Error('New environment credentials must be provided');
          if (routeChanged(provider)) {
            throw new Error(`${provider} credentials must be re-entered when its route changes`);
          }
          return { reference: candidate.reference, material: retained.material };
        }
        return { reference: candidate.reference, material: candidate.material.value };
      };

      const profile: StoredProfile = {
        id: existing?.id ?? randomUUID(),
        name: input.name,
        runner: { mode: 'LOCAL_BUNDLED' },
        github: { ...input.github },
        aws: { ...input.aws },
        kubernetes: {
          ...input.kubernetes,
          expectedEndpoint: (() => {
            const endpoint = expectedEndpoint ?? existing?.kubernetes.expectedEndpoint;
            if (!endpoint) {
              throw new Error('Authenticated EKS discovery is required');
            }
            return parseExpectedEksEndpoint(endpoint);
          })(),
        },
        credentials: {
          github: credential('github'),
          aws: credential('aws'),
        },
        credentialRevision:
          existing && !credentialsChanged ? existing.credentialRevision : randomUUID(),
        status: 'SAVED',
        createdAt: existing?.createdAt ?? now,
        updatedAt: now,
        verifiedAt: null,
        failedAt: null,
        failureCode: null,
      };
      document.profiles = [
        ...document.profiles.filter((candidate) => candidate.id !== profile.id),
        profile,
      ];
      await this.write(document);
      saved = summary(profile);
    });
    this.writeTail = operation.catch(() => undefined);
    await operation;
    if (!saved) throw new Error('Environment profile was not saved');
    return saved;
  }

  async remove(profileId: unknown): Promise<boolean> {
    if (!isAccordLockEnvironmentProfileId(profileId)) {
      throw new Error('Environment profile identifier is invalid');
    }
    let removed = false;
    const operation = this.writeTail.then(async () => {
      const document = await this.read();
      const profiles = document.profiles.filter((profile) => profile.id !== profileId);
      removed = profiles.length !== document.profiles.length;
      if (removed) await this.write({ schemaVersion: STORE_SCHEMA_VERSION, profiles });
    });
    this.writeTail = operation.catch(() => undefined);
    await operation;
    return removed;
  }

  /** Main-process-only. The preload bridge must never expose this method. */
  async loadExecutionBundle(
    profileId: unknown
  ): Promise<AccordLockEnvironmentProfileExecutionBundle> {
    if (!isAccordLockEnvironmentProfileId(profileId)) {
      throw new Error('Environment profile identifier is invalid');
    }
    await this.writeTail;
    const profile = (await this.read()).profiles.find((candidate) => candidate.id === profileId);
    if (!profile) throw new Error('Environment profile does not exist');
    return executionBundle(profile);
  }

  /**
   * Main-process-only status transition. Call this only after validating the
   * bundled preflight runner receipt for the supplied profile digest.
   */
  async recordVerification(
    profileId: unknown,
    expectedProfileDigest: unknown,
    result: AccordLockTrustedEnvironmentVerification
  ): Promise<AccordLockEnvironmentProfileSummary> {
    if (
      !isAccordLockEnvironmentProfileId(profileId) ||
      typeof expectedProfileDigest !== 'string' ||
      !/^sha256:[0-9a-f]{64}$/u.test(expectedProfileDigest) ||
      !isRecord(result) ||
      !['VERIFIED', 'FAILED'].includes(String(result.status))
    ) {
      throw new Error('Environment verification result is invalid');
    }
    let saved: AccordLockEnvironmentProfileSummary | null = null;
    const operation = this.writeTail.then(async () => {
      const document = await this.read();
      const profile = document.profiles.find((candidate) => candidate.id === profileId);
      if (!profile) throw new Error('Environment profile does not exist');
      if (executionBundle(profile).runnerProfile.profile_digest !== expectedProfileDigest) {
        throw new Error('Environment profile changed during verification');
      }
      const now = this.nowSeconds();
      if (!timestamp(now)) throw new Error('Environment profile clock is unavailable');

      if (result.status === 'VERIFIED') {
        if (!exactKeys(result, ['status'])) {
          throw new Error('Environment verification result is invalid');
        }
        profile.status = 'VERIFIED';
        profile.verifiedAt = now;
        profile.failedAt = null;
        profile.failureCode = null;
      } else {
        if (
          !exactKeys(result, ['status', 'failureCode']) ||
          ![
            'RUNNER_UNAVAILABLE',
            'RUNNER_TIMEOUT',
            'RUNNER_REJECTED',
            'PREFLIGHT_BLOCKED',
            'PREFLIGHT_INDETERMINATE',
            'ATTESTATION_MISMATCH',
            'PROFILE_CHANGED',
          ].includes(result.failureCode)
        ) {
          throw new Error('Environment verification result is invalid');
        }
        profile.status = 'FAILED';
        profile.failedAt = now;
        profile.failureCode = result.failureCode;
      }
      profile.updatedAt = now;
      await this.write(document);
      saved = summary(profile);
    });
    this.writeTail = operation.catch(() => undefined);
    await operation;
    if (!saved) throw new Error('Environment verification result was not recorded');
    return saved;
  }

  private requireSecureStorage(): void {
    if (!this.safeStorage.isEncryptionAvailable()) {
      throw new Error('Secure credential storage is unavailable');
    }
    if (this.platform === 'linux') {
      const backend = this.safeStorage.getSelectedStorageBackend?.();
      if (!backend || !SECURE_LINUX_BACKENDS.has(backend)) {
        throw new Error('Secure credential storage is unavailable');
      }
    }
  }

  private async read(): Promise<StoredDocument> {
    this.requireSecureStorage();
    let encrypted: Buffer;
    try {
      encrypted = await fs.readFile(this.filePath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return { schemaVersion: STORE_SCHEMA_VERSION, profiles: [] };
      }
      throw error;
    }
    if (encrypted.length === 0 || encrypted.length > MAX_STORE_BYTES) {
      throw new Error('Environment profile store is invalid');
    }
    const plaintext = this.safeStorage.decryptString(encrypted);
    if (Buffer.byteLength(plaintext, 'utf8') > MAX_STORE_BYTES) {
      throw new Error('Environment profile store is invalid');
    }
    const raw = JSON.parse(plaintext) as unknown;
    const migrated = isRecord(raw) && raw.schemaVersion === 1;
    const document = parseDocument(raw);
    if (migrated) {
      const migratedPlaintext = JSON.stringify(document);
      const protectedDocument = this.safeStorage.encryptString(migratedPlaintext);
      await writeAtomic(this.filePath, protectedDocument);
    }
    return document;
  }

  private async write(document: StoredDocument): Promise<void> {
    this.requireSecureStorage();
    const plaintext = JSON.stringify(parseDocument(document));
    if (Buffer.byteLength(plaintext, 'utf8') > MAX_STORE_BYTES) {
      throw new Error('Environment profile store is too large');
    }
    const encrypted = this.safeStorage.encryptString(plaintext);
    if (
      !Buffer.isBuffer(encrypted) ||
      encrypted.length === 0 ||
      encrypted.length > MAX_STORE_BYTES
    ) {
      throw new Error('Environment profile store protection failed');
    }
    await writeAtomic(this.filePath, encrypted);
  }
}
