import { createHash, createPrivateKey, createPublicKey, randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

import type { AccordLockEnvironmentProfileSafeStorage } from './accordlockEnvironmentProfileStore';
import { isAccordLockEnvironmentProfileId } from './accordlock/environmentProfiles';

const STORE_SCHEMA_VERSION = 2 as const;
const LEGACY_STORE_SCHEMA_VERSION = 1 as const;
const MAX_STORE_BYTES = 256 * 1_024;
const TEN_YEARS_SECONDS = 10 * 365 * 24 * 60 * 60;
const ED25519_PKCS8_SEED_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const SECURE_LINUX_BACKENDS = new Set(['gnome_libsecret', 'kwallet', 'kwallet5', 'kwallet6']);

export type AccordLockCiAuthority = Readonly<{
  keyId: string;
  publicKey: string;
  publicKeyHash: string;
}>;

export type AccordLockCiAuthorityPair = Readonly<{
  build: AccordLockCiAuthority;
  artifact: AccordLockCiAuthority;
}>;

export type AccordLockCiAuthorityEnrollment = Readonly<{
  environmentId: string;
  build: AccordLockCiAuthority;
  artifact: AccordLockCiAuthority;
}>;

type StoredTrustMaterial = {
  environmentId: string;
  runnerMasterSeed: string;
  receiptSigningSeed: string;
  receiptPublicKey: string;
  receiptPublicKeyHash: string;
  receiptKeyId: string;
  ciAuthorities: AccordLockCiAuthorityPair | null;
  createdAt: number;
  expiresAt: number;
};

type LegacyStoredTrustMaterial = Omit<StoredTrustMaterial, 'ciAuthorities'> & {
  buildTrustKeyId: string;
  buildTrustPublicKey: string;
  artifactTrustKeyId: string;
  artifactTrustPublicKey: string;
};

type StoredDocument = {
  schemaVersion: typeof STORE_SCHEMA_VERSION;
  environments: StoredTrustMaterial[];
};

type ParsedDocument = Readonly<{
  document: StoredDocument;
  migrated: boolean;
}>;

export type AccordLockPreflightTrustMaterial = Readonly<StoredTrustMaterial>;

export type AccordLockCiAuthorityStatus =
  | Readonly<{ status: 'NOT_INITIALIZED'; environmentId: string }>
  | Readonly<{ status: 'UNENROLLED'; environmentId: string }>
  | Readonly<{
      status: 'ENROLLED';
      environmentId: string;
      build: AccordLockCiAuthority;
      artifact: AccordLockCiAuthority;
    }>;

export type AccordLockPreflightInstallationBootstrap = Readonly<{
  runnerMasterSeed: string;
  receiptSigningSeed: string;
  receiptKeyId: string;
  receiptPublicKey: string;
  receiptPublicKeyHash: string;
}>;

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

function canonicalBase64Url(value: unknown, bytes: number): value is string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/u.test(value)) return false;
  const decoded = Buffer.from(value, 'base64url');
  try {
    return decoded.length === bytes && decoded.toString('base64url') === value;
  } finally {
    decoded.fill(0);
  }
}

function boundedKeyId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length >= 1 &&
    value.length <= 256 &&
    /^[A-Za-z0-9][A-Za-z0-9._:-]*$/u.test(value)
  );
}

function digestPublicKey(publicKey: Buffer): string {
  return `sha256:${createHash('sha256').update(publicKey).digest('hex')}`;
}

function deriveEd25519PublicKey(seed: Buffer): Buffer {
  if (seed.length !== 32) throw new Error('Preflight signing seed is invalid');
  const encodedPrivateKey = Buffer.concat([ED25519_PKCS8_SEED_PREFIX, seed]);
  let privateKey: ReturnType<typeof createPrivateKey>;
  try {
    privateKey = createPrivateKey({
      key: encodedPrivateKey,
      format: 'der',
      type: 'pkcs8',
    });
  } finally {
    encodedPrivateKey.fill(0);
  }
  const encoded = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  if (
    !Buffer.isBuffer(encoded) ||
    encoded.length !== ED25519_SPKI_PREFIX.length + 32 ||
    !encoded.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)
  ) {
    throw new Error('Preflight public key derivation failed');
  }
  return Buffer.from(encoded.subarray(ED25519_SPKI_PREFIX.length));
}

function parseCiAuthority(
  value: unknown,
  expectedKeyId: string,
  label: string
): AccordLockCiAuthority {
  if (
    !isRecord(value) ||
    !exactKeys(value, ['keyId', 'publicKey', 'publicKeyHash']) ||
    value.keyId !== expectedKeyId ||
    !boundedKeyId(value.keyId) ||
    !canonicalBase64Url(value.publicKey, 32) ||
    typeof value.publicKeyHash !== 'string' ||
    !/^sha256:[0-9a-f]{64}$/u.test(value.publicKeyHash)
  ) {
    throw new Error(`${label} CI authority is invalid`);
  }
  const publicKey = Buffer.from(value.publicKey, 'base64url');
  try {
    if (digestPublicKey(publicKey) !== value.publicKeyHash) {
      throw new Error(`${label} CI authority fingerprint is invalid`);
    }
    createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, publicKey]),
      format: 'der',
      type: 'spki',
    });
  } catch (error) {
    if (error instanceof Error && error.message.includes('fingerprint')) throw error;
    throw new Error(`${label} CI authority public key is invalid`);
  } finally {
    publicKey.fill(0);
  }
  return Object.freeze({
    keyId: value.keyId,
    publicKey: value.publicKey,
    publicKeyHash: value.publicKeyHash,
  });
}

function parseCiAuthorityPair(
  value: unknown,
  environmentId: string
): AccordLockCiAuthorityPair | null {
  if (value === null) return null;
  if (!isRecord(value) || !exactKeys(value, ['build', 'artifact'])) {
    throw new Error('CI authority enrollment is invalid');
  }
  const build = parseCiAuthority(value.build, `build-${environmentId}`, 'Build');
  const artifact = parseCiAuthority(value.artifact, `artifact-${environmentId}`, 'Artifact');
  if (build.publicKey === artifact.publicKey || build.publicKeyHash === artifact.publicKeyHash) {
    throw new Error('Build and artifact CI authorities must use distinct keys');
  }
  return Object.freeze({ build, artifact });
}

function parseCommonTrustMaterial(value: JsonRecord): Omit<StoredTrustMaterial, 'ciAuthorities'> {
  if (
    !isAccordLockEnvironmentProfileId(value.environmentId) ||
    !canonicalBase64Url(value.runnerMasterSeed, 32) ||
    !canonicalBase64Url(value.receiptSigningSeed, 32) ||
    !canonicalBase64Url(value.receiptPublicKey, 32) ||
    !boundedKeyId(value.receiptKeyId) ||
    typeof value.receiptPublicKeyHash !== 'string' ||
    !/^sha256:[0-9a-f]{64}$/u.test(value.receiptPublicKeyHash) ||
    !timestamp(value.createdAt) ||
    !timestamp(value.expiresAt) ||
    value.expiresAt <= value.createdAt
  ) {
    throw new Error('Preflight trust material is invalid');
  }
  const signingSeed = Buffer.from(value.receiptSigningSeed, 'base64url');
  let derivedPublic: Buffer;
  try {
    derivedPublic = deriveEd25519PublicKey(signingSeed);
  } finally {
    signingSeed.fill(0);
  }
  if (
    derivedPublic.toString('base64url') !== value.receiptPublicKey ||
    digestPublicKey(derivedPublic) !== value.receiptPublicKeyHash
  ) {
    throw new Error('Preflight receipt key binding is invalid');
  }
  return {
    environmentId: value.environmentId,
    runnerMasterSeed: value.runnerMasterSeed,
    receiptSigningSeed: value.receiptSigningSeed,
    receiptPublicKey: value.receiptPublicKey,
    receiptPublicKeyHash: value.receiptPublicKeyHash,
    receiptKeyId: value.receiptKeyId,
    createdAt: value.createdAt,
    expiresAt: value.expiresAt,
  };
}

function parseTrustMaterial(value: unknown): StoredTrustMaterial {
  const keys = [
    'environmentId',
    'runnerMasterSeed',
    'receiptSigningSeed',
    'receiptPublicKey',
    'receiptPublicKeyHash',
    'receiptKeyId',
    'ciAuthorities',
    'createdAt',
    'expiresAt',
  ];
  if (!isRecord(value) || !exactKeys(value, keys)) {
    throw new Error('Preflight trust material is invalid');
  }
  const common = parseCommonTrustMaterial(value);
  return {
    ...common,
    ciAuthorities: parseCiAuthorityPair(value.ciAuthorities, common.environmentId),
  };
}

function parseLegacyTrustMaterial(value: unknown): LegacyStoredTrustMaterial {
  const keys = [
    'environmentId',
    'runnerMasterSeed',
    'receiptSigningSeed',
    'receiptPublicKey',
    'receiptPublicKeyHash',
    'receiptKeyId',
    'buildTrustKeyId',
    'buildTrustPublicKey',
    'artifactTrustKeyId',
    'artifactTrustPublicKey',
    'createdAt',
    'expiresAt',
  ];
  if (
    !isRecord(value) ||
    !exactKeys(value, keys) ||
    !canonicalBase64Url(value.buildTrustPublicKey, 32) ||
    !canonicalBase64Url(value.artifactTrustPublicKey, 32)
  ) {
    throw new Error('Legacy preflight trust material is invalid');
  }
  const common = parseCommonTrustMaterial(value);
  if (
    value.buildTrustKeyId !== `build-${common.environmentId}` ||
    value.artifactTrustKeyId !== `artifact-${common.environmentId}`
  ) {
    throw new Error('Legacy preflight trust material is invalid');
  }
  return {
    ...common,
    buildTrustKeyId: value.buildTrustKeyId,
    buildTrustPublicKey: value.buildTrustPublicKey,
    artifactTrustKeyId: value.artifactTrustKeyId,
    artifactTrustPublicKey: value.artifactTrustPublicKey,
  };
}

function parseDocument(value: unknown): ParsedDocument {
  if (
    !isRecord(value) ||
    !exactKeys(value, ['schemaVersion', 'environments']) ||
    !Array.isArray(value.environments) ||
    value.environments.length > 64
  ) {
    throw new Error('Preflight trust store is invalid');
  }
  const migrated = value.schemaVersion === LEGACY_STORE_SCHEMA_VERSION;
  if (!migrated && value.schemaVersion !== STORE_SCHEMA_VERSION) {
    throw new Error('Preflight trust store is invalid');
  }
  const environments = migrated
    ? value.environments.map((entry) => {
        const legacy = parseLegacyTrustMaterial(entry);
        return {
          environmentId: legacy.environmentId,
          runnerMasterSeed: legacy.runnerMasterSeed,
          receiptSigningSeed: legacy.receiptSigningSeed,
          receiptPublicKey: legacy.receiptPublicKey,
          receiptPublicKeyHash: legacy.receiptPublicKeyHash,
          receiptKeyId: legacy.receiptKeyId,
          ciAuthorities: null,
          createdAt: legacy.createdAt,
          expiresAt: legacy.expiresAt,
        } satisfies StoredTrustMaterial;
      })
    : value.environments.map(parseTrustMaterial);
  if (new Set(environments.map((entry) => entry.environmentId)).size !== environments.length) {
    throw new Error('Preflight trust store contains duplicate environments');
  }
  return {
    document: { schemaVersion: STORE_SCHEMA_VERSION, environments },
    migrated,
  };
}

function authorityStatus(entry: StoredTrustMaterial): AccordLockCiAuthorityStatus {
  if (!entry.ciAuthorities) {
    return Object.freeze({ status: 'UNENROLLED', environmentId: entry.environmentId });
  }
  return Object.freeze({
    status: 'ENROLLED',
    environmentId: entry.environmentId,
    build: Object.freeze({ ...entry.ciAuthorities.build }),
    artifact: Object.freeze({ ...entry.ciAuthorities.artifact }),
  });
}

function trustMaterialView(entry: StoredTrustMaterial): AccordLockPreflightTrustMaterial {
  return Object.freeze({
    ...entry,
    ciAuthorities: entry.ciAuthorities
      ? Object.freeze({
          build: Object.freeze({ ...entry.ciAuthorities.build }),
          artifact: Object.freeze({ ...entry.ciAuthorities.artifact }),
        })
      : null,
  });
}

async function writeAtomic(filePath: string, contents: Buffer): Promise<void> {
  const directory = path.dirname(filePath);
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  const temporaryPath = path.join(directory, `.preflight-trust.${randomUUID()}.tmp`);
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

export class AccordLockPreflightTrustStore {
  private readonly filePath: string;
  private readonly nowSeconds: () => number;
  private readonly platform: NodeJS.Platform;
  private readonly safeStorage: AccordLockEnvironmentProfileSafeStorage;
  private writeTail: Promise<void> = Promise.resolve();

  constructor(options: StoreOptions) {
    this.filePath = path.join(options.directory, 'preflight-trust.v1.bin');
    this.nowSeconds = options.nowSeconds ?? (() => Math.floor(Date.now() / 1_000));
    this.platform = options.platform ?? process.platform;
    this.safeStorage = options.safeStorage;
  }

  async getOrCreate(
    environmentId: unknown,
    initialize: () => Promise<AccordLockPreflightInstallationBootstrap>
  ): Promise<AccordLockPreflightTrustMaterial> {
    if (!isAccordLockEnvironmentProfileId(environmentId)) {
      throw new Error('Environment profile identifier is invalid');
    }
    let result: StoredTrustMaterial | null = null;
    const operation = this.writeTail.then(async () => {
      const { document, migrated } = await this.read();
      const existing = document.environments.find((entry) => entry.environmentId === environmentId);
      if (existing) {
        if (migrated) await this.write(document);
        result = existing;
        return;
      }
      const createdAt = this.nowSeconds();
      if (!timestamp(createdAt) || createdAt > Number.MAX_SAFE_INTEGER - TEN_YEARS_SECONDS) {
        throw new Error('Preflight trust clock is unavailable');
      }
      const bootstrap = await initialize();
      if (
        !canonicalBase64Url(bootstrap.runnerMasterSeed, 32) ||
        !canonicalBase64Url(bootstrap.receiptSigningSeed, 32) ||
        !canonicalBase64Url(bootstrap.receiptPublicKey, 32) ||
        !boundedKeyId(bootstrap.receiptKeyId) ||
        !/^sha256:[0-9a-f]{64}$/u.test(bootstrap.receiptPublicKeyHash)
      ) {
        throw new Error('Preflight installation bootstrap is invalid');
      }
      const receiptSeed = Buffer.from(bootstrap.receiptSigningSeed, 'base64url');
      let receiptPublic: Buffer;
      try {
        receiptPublic = deriveEd25519PublicKey(receiptSeed);
      } finally {
        receiptSeed.fill(0);
      }
      if (
        receiptPublic.toString('base64url') !== bootstrap.receiptPublicKey ||
        digestPublicKey(receiptPublic) !== bootstrap.receiptPublicKeyHash
      ) {
        throw new Error('Preflight installation key binding is invalid');
      }
      const entry: StoredTrustMaterial = {
        environmentId,
        runnerMasterSeed: bootstrap.runnerMasterSeed,
        receiptSigningSeed: bootstrap.receiptSigningSeed,
        receiptPublicKey: bootstrap.receiptPublicKey,
        receiptPublicKeyHash: bootstrap.receiptPublicKeyHash,
        receiptKeyId: bootstrap.receiptKeyId,
        ciAuthorities: null,
        createdAt,
        expiresAt: createdAt + TEN_YEARS_SECONDS,
      };
      document.environments.push(entry);
      await this.write(document);
      result = entry;
    });
    this.writeTail = operation.catch(() => undefined);
    await operation;
    if (!result) throw new Error('Preflight trust material was not created');
    return trustMaterialView(result as StoredTrustMaterial);
  }

  async enrollCiAuthorities(
    environmentId: unknown,
    enrollment: unknown
  ): Promise<AccordLockCiAuthorityStatus> {
    if (!isAccordLockEnvironmentProfileId(environmentId)) {
      throw new Error('Environment profile identifier is invalid');
    }
    if (
      !isRecord(enrollment) ||
      !exactKeys(enrollment, ['environmentId', 'build', 'artifact']) ||
      enrollment.environmentId !== environmentId
    ) {
      throw new Error('CI authority enrollment does not match the environment');
    }
    const authorities = parseCiAuthorityPair(
      { build: enrollment.build, artifact: enrollment.artifact },
      environmentId
    );
    if (!authorities) throw new Error('CI authority enrollment is invalid');

    let status: AccordLockCiAuthorityStatus | null = null;
    const operation = this.writeTail.then(async () => {
      const { document, migrated } = await this.read();
      const entry = document.environments.find(
        (candidate) => candidate.environmentId === environmentId
      );
      if (!entry) throw new Error('Preflight environment has not been initialized');
      if (entry.ciAuthorities) {
        if (JSON.stringify(entry.ciAuthorities) !== JSON.stringify(authorities)) {
          throw new Error('CI authority rotation requires an explicit rotation workflow');
        }
        if (migrated) await this.write(document);
      } else {
        entry.ciAuthorities = authorities;
        await this.write(document);
      }
      status = authorityStatus(entry);
    });
    this.writeTail = operation.catch(() => undefined);
    await operation;
    if (!status) throw new Error('CI authority enrollment did not complete');
    return status;
  }

  async getCiAuthorityStatus(environmentId: unknown): Promise<AccordLockCiAuthorityStatus> {
    if (!isAccordLockEnvironmentProfileId(environmentId)) {
      throw new Error('Environment profile identifier is invalid');
    }
    let status: AccordLockCiAuthorityStatus | null = null;
    const operation = this.writeTail.then(async () => {
      const { document, migrated } = await this.read();
      const entry = document.environments.find(
        (candidate) => candidate.environmentId === environmentId
      );
      if (migrated) await this.write(document);
      status = entry
        ? authorityStatus(entry)
        : Object.freeze({ status: 'NOT_INITIALIZED', environmentId });
    });
    this.writeTail = operation.catch(() => undefined);
    await operation;
    if (!status) throw new Error('CI authority status is unavailable');
    return status;
  }

  async remove(environmentId: unknown): Promise<boolean> {
    if (!isAccordLockEnvironmentProfileId(environmentId)) {
      throw new Error('Environment profile identifier is invalid');
    }
    let removed = false;
    const operation = this.writeTail.then(async () => {
      const { document, migrated } = await this.read();
      const environments = document.environments.filter(
        (entry) => entry.environmentId !== environmentId
      );
      removed = environments.length !== document.environments.length;
      if (removed || migrated) {
        await this.write({ schemaVersion: STORE_SCHEMA_VERSION, environments });
      }
    });
    this.writeTail = operation.catch(() => undefined);
    await operation;
    return removed;
  }

  private requireSecureStorage(): void {
    if (!this.safeStorage.isEncryptionAvailable()) {
      throw new Error('Secure preflight trust storage is unavailable');
    }
    if (this.platform === 'linux') {
      const backend = this.safeStorage.getSelectedStorageBackend?.();
      if (!backend || !SECURE_LINUX_BACKENDS.has(backend)) {
        throw new Error('Secure preflight trust storage is unavailable');
      }
    }
  }

  private async read(): Promise<ParsedDocument> {
    this.requireSecureStorage();
    let ciphertext: Buffer;
    try {
      ciphertext = await fs.readFile(this.filePath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return {
          document: { schemaVersion: STORE_SCHEMA_VERSION, environments: [] },
          migrated: false,
        };
      }
      throw error;
    }
    if (ciphertext.length === 0 || ciphertext.length > MAX_STORE_BYTES) {
      throw new Error('Preflight trust store is invalid');
    }
    const plaintext = this.safeStorage.decryptString(ciphertext);
    if (Buffer.byteLength(plaintext, 'utf8') > MAX_STORE_BYTES) {
      throw new Error('Preflight trust store is invalid');
    }
    return parseDocument(JSON.parse(plaintext) as unknown);
  }

  private async write(document: StoredDocument): Promise<void> {
    this.requireSecureStorage();
    const parsed = parseDocument(document);
    if (parsed.migrated) throw new Error('Preflight trust store migration did not complete');
    const plaintext = JSON.stringify(parsed.document);
    if (Buffer.byteLength(plaintext, 'utf8') > MAX_STORE_BYTES) {
      throw new Error('Preflight trust store is too large');
    }
    const ciphertext = this.safeStorage.encryptString(plaintext);
    if (
      !Buffer.isBuffer(ciphertext) ||
      ciphertext.length === 0 ||
      ciphertext.length > MAX_STORE_BYTES
    ) {
      throw new Error('Preflight trust store protection failed');
    }
    await writeAtomic(this.filePath, ciphertext);
  }
}
