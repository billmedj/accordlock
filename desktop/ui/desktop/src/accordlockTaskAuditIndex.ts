import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

const INDEX_SCHEMA_VERSION = 3;
const ENTRY_SCHEMA_VERSION = 3;
const LEGACY_INDEX_SCHEMA_VERSION = 2;
const LEGACY_ENTRY_SCHEMA_VERSION = 2;
const COMMIT_SCHEMA_VERSION = 1;
const MAX_ENTRIES = 50_000;
const MAX_INDEX_BYTES = 64 * 1_024 * 1_024;
const MAX_PROTECTED_METADATA_BYTES = 16 * 1_024;
const AES_KEY_BYTES = 32;
const AES_NONCE_BYTES = 12;
const AES_TAG_BYTES = 16;
const INDEX_MAGIC = Buffer.from('ALI2', 'ascii');
const INDEX_AAD = Buffer.from('accordlock.task-audit-index.v2', 'utf8');
const SHA256_IDENTIFIER = /^sha256:[0-9a-f]{64}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SECURE_LINUX_BACKENDS = new Set(['gnome_libsecret', 'kwallet', 'kwallet5', 'kwallet6']);

type IndexSlot = 'a' | 'b';

export interface AccordLockSafeStorage {
  isEncryptionAvailable(): boolean;
  encryptString(plaintext: string): Buffer;
  decryptString(ciphertext: Buffer): string;
  getSelectedStorageBackend?(): string;
}

export interface AccordLockTaskAuditIndexEntry {
  schema_version: 3;
  ledger_id: string;
  task_id: string;
  session_id: string;
  run_id: string;
  workspace_id: string;
  approved_at: number;
  expires_at: number;
}

interface LegacyAccordLockTaskAuditIndexEntry {
  schema_version: 2;
  task_id: string;
  session_id: string;
  run_id: string;
  workspace_id: string;
  approved_at: number;
  expires_at: number;
}

type StoredAccordLockTaskAuditIndexEntry =
  | AccordLockTaskAuditIndexEntry
  | LegacyAccordLockTaskAuditIndexEntry;

interface AccordLockTaskAuditIndexDocument {
  schema_version: 2 | 3;
  generation: number;
  entries: StoredAccordLockTaskAuditIndexEntry[];
}

interface AccordLockTaskAuditIndexCommit {
  schema_version: 1;
  active_slot: IndexSlot;
  generation: number;
  index_digest: string;
}

interface AccordLockTaskAuditIndexOptions {
  directory: string;
  safeStorage: AccordLockSafeStorage;
  platform?: NodeJS.Platform;
  nowSeconds?: () => number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, expectedKeys: readonly string[]): boolean {
  const actualKeys = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  return (
    actualKeys.length === expected.length &&
    actualKeys.every((actualKey, index) => actualKey === expected[index])
  );
}

function boundedIdentifier(value: unknown, maximumBytes: number): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.trim() === value &&
    Buffer.byteLength(value, 'utf8') <= maximumBytes &&
    // eslint-disable-next-line no-control-regex
    !/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/u.test(value)
  );
}

function isTimestamp(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function sha256(value: Buffer): string {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

export function accordLockAuditWorkspaceId(workspaceRoot: string): string {
  if (!boundedIdentifier(workspaceRoot, 4_096)) {
    throw new Error('Trusted audit workspace binding is unavailable');
  }
  return sha256(Buffer.from(`accordlock.audit-workspace.v1\u0000${workspaceRoot}`, 'utf8'));
}

function validCommonEntryFields(value: Record<string, unknown>): boolean {
  return (
    typeof value.task_id === 'string' &&
    UUID.test(value.task_id) &&
    boundedIdentifier(value.session_id, 256) &&
    typeof value.run_id === 'string' &&
    SHA256_IDENTIFIER.test(value.run_id) &&
    typeof value.workspace_id === 'string' &&
    SHA256_IDENTIFIER.test(value.workspace_id) &&
    isTimestamp(value.approved_at) &&
    isTimestamp(value.expires_at) &&
    value.expires_at >= value.approved_at
  );
}

function parseEntry(value: unknown): AccordLockTaskAuditIndexEntry {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'schema_version',
      'ledger_id',
      'task_id',
      'session_id',
      'run_id',
      'workspace_id',
      'approved_at',
      'expires_at',
    ]) ||
    value.schema_version !== ENTRY_SCHEMA_VERSION ||
    typeof value.ledger_id !== 'string' ||
    !UUID.test(value.ledger_id) ||
    !validCommonEntryFields(value)
  ) {
    throw new Error('Task audit index entry is malformed');
  }
  return value as unknown as AccordLockTaskAuditIndexEntry;
}

function parseLegacyEntry(value: unknown): LegacyAccordLockTaskAuditIndexEntry {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'schema_version',
      'task_id',
      'session_id',
      'run_id',
      'workspace_id',
      'approved_at',
      'expires_at',
    ]) ||
    value.schema_version !== LEGACY_ENTRY_SCHEMA_VERSION ||
    !validCommonEntryFields(value)
  ) {
    throw new Error('Legacy task audit index entry is malformed');
  }
  return value as unknown as LegacyAccordLockTaskAuditIndexEntry;
}

function parseDocument(value: unknown): AccordLockTaskAuditIndexDocument {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ['schema_version', 'generation', 'entries']) ||
    (value.schema_version !== INDEX_SCHEMA_VERSION &&
      value.schema_version !== LEGACY_INDEX_SCHEMA_VERSION) ||
    !Number.isSafeInteger(value.generation) ||
    (value.generation as number) < 1 ||
    !Array.isArray(value.entries) ||
    value.entries.length > MAX_ENTRIES
  ) {
    throw new Error('Task audit index is malformed');
  }

  const entries = value.entries.map(
    value.schema_version === LEGACY_INDEX_SCHEMA_VERSION
      ? parseLegacyEntry
      : (entry) => {
          if (isRecord(entry) && entry.schema_version === LEGACY_ENTRY_SCHEMA_VERSION) {
            return parseLegacyEntry(entry);
          }
          return parseEntry(entry);
        }
  );
  const sessions = new Set<string>();
  const tasks = new Set<string>();
  for (const entry of entries) {
    if (sessions.has(entry.session_id) || tasks.has(entry.task_id)) {
      throw new Error('Task audit index contains duplicate bindings');
    }
    sessions.add(entry.session_id);
    tasks.add(entry.task_id);
  }
  return {
    schema_version: value.schema_version as 2 | 3,
    generation: value.generation as number,
    entries,
  };
}

function parseCommit(value: unknown): AccordLockTaskAuditIndexCommit {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ['schema_version', 'active_slot', 'generation', 'index_digest']) ||
    value.schema_version !== COMMIT_SCHEMA_VERSION ||
    (value.active_slot !== 'a' && value.active_slot !== 'b') ||
    !Number.isSafeInteger(value.generation) ||
    (value.generation as number) < 1 ||
    typeof value.index_digest !== 'string' ||
    !SHA256_IDENTIFIER.test(value.index_digest)
  ) {
    throw new Error('Task audit index commit is malformed');
  }
  return value as unknown as AccordLockTaskAuditIndexCommit;
}

function parseAesKey(value: string): Buffer {
  if (!/^[A-Za-z0-9_-]{43}$/u.test(value)) {
    throw new Error('Task audit index key is malformed');
  }
  const key = Buffer.from(value, 'base64url');
  if (key.length !== AES_KEY_BYTES) {
    throw new Error('Task audit index key is malformed');
  }
  return key;
}

function encryptDocument(document: AccordLockTaskAuditIndexDocument, key: Buffer): Buffer {
  const nonce = randomBytes(AES_NONCE_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(INDEX_AAD);
  const plaintext = Buffer.from(JSON.stringify(document), 'utf8');
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([INDEX_MAGIC, nonce, cipher.getAuthTag(), encrypted]);
}

function decryptDocument(encrypted: Buffer, key: Buffer): AccordLockTaskAuditIndexDocument {
  const headerBytes = INDEX_MAGIC.length + AES_NONCE_BYTES + AES_TAG_BYTES;
  if (
    encrypted.length <= headerBytes ||
    encrypted.length > MAX_INDEX_BYTES ||
    !encrypted.subarray(0, INDEX_MAGIC.length).equals(INDEX_MAGIC)
  ) {
    throw new Error('Task audit index ciphertext is malformed');
  }
  const nonceStart = INDEX_MAGIC.length;
  const tagStart = nonceStart + AES_NONCE_BYTES;
  const ciphertextStart = tagStart + AES_TAG_BYTES;
  const decipher = createDecipheriv('aes-256-gcm', key, encrypted.subarray(nonceStart, tagStart));
  decipher.setAAD(INDEX_AAD);
  decipher.setAuthTag(encrypted.subarray(tagStart, ciphertextStart));
  const plaintext = Buffer.concat([
    decipher.update(encrypted.subarray(ciphertextStart)),
    decipher.final(),
  ]);
  if (plaintext.length > MAX_INDEX_BYTES) {
    throw new Error('Task audit index plaintext is too large');
  }
  return parseDocument(JSON.parse(plaintext.toString('utf8')) as unknown);
}

async function readBoundedFile(filePath: string, maximumBytes: number): Promise<Buffer | null> {
  let handle: fs.FileHandle;
  try {
    handle = await fs.open(filePath, 'r');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw error;
  }

  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size <= 0 || stat.size > maximumBytes) {
      throw new Error('Task audit index file is invalid');
    }
    const result = Buffer.allocUnsafe(stat.size + 1);
    let total = 0;
    while (total < result.length) {
      const read = await handle.read(result, total, result.length - total, total);
      if (read.bytesRead === 0) break;
      total += read.bytesRead;
    }
    if (total <= 0 || total > maximumBytes) {
      throw new Error('Task audit index file changed while it was read');
    }
    return result.subarray(0, total);
  } finally {
    await handle.close();
  }
}

async function syncDirectory(directory: string): Promise<void> {
  if (process.platform === 'win32') return;
  const handle = await fs.open(directory, 'r');
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function writeAtomic(filePath: string, contents: Buffer): Promise<void> {
  const directory = path.dirname(filePath);
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  const temporaryPath = path.join(directory, `.${path.basename(filePath)}.${randomUUID()}.tmp`);
  let handle: fs.FileHandle | null = null;
  try {
    handle = await fs.open(temporaryPath, 'wx', 0o600);
    await handle.writeFile(contents);
    await handle.sync();
    await handle.close();
    handle = null;
    await fs.rename(temporaryPath, filePath);
    await syncDirectory(directory);
  } catch (error) {
    await handle?.close().catch(() => undefined);
    await fs.unlink(temporaryPath).catch(() => undefined);
    throw error;
  }
}

export class AccordLockTaskAuditIndex {
  private readonly keyPath: string;
  private readonly commitPath: string;
  private readonly slotPaths: Record<IndexSlot, string>;
  private readonly safeStorage: AccordLockSafeStorage;
  private readonly platform: NodeJS.Platform;
  private readonly nowSeconds: () => number;
  private entries = new Map<string, StoredAccordLockTaskAuditIndexEntry>();
  private key: Buffer | null = null;
  private activeSlot: IndexSlot | null = null;
  private generation = 0;
  private available = false;
  private initialized = false;
  private writeTail: Promise<void> = Promise.resolve();

  constructor(options: AccordLockTaskAuditIndexOptions) {
    this.keyPath = path.join(options.directory, 'task-audit-index.v2.key');
    this.commitPath = path.join(options.directory, 'task-audit-index.v2.commit');
    this.slotPaths = {
      a: path.join(options.directory, 'task-audit-index.v2.a'),
      b: path.join(options.directory, 'task-audit-index.v2.b'),
    };
    this.safeStorage = options.safeStorage;
    this.platform = options.platform ?? process.platform;
    this.nowSeconds = options.nowSeconds ?? (() => Math.floor(Date.now() / 1_000));
  }

  async initialize(): Promise<boolean> {
    if (this.initialized) return this.available;
    this.initialized = true;
    try {
      if (!this.safeStorage.isEncryptionAvailable()) return false;
      if (this.platform === 'linux') {
        const backend = this.safeStorage.getSelectedStorageBackend?.();
        if (!backend || !SECURE_LINUX_BACKENDS.has(backend)) return false;
      }

      const [wrappedKey, protectedCommit, slotA, slotB] = await Promise.all([
        readBoundedFile(this.keyPath, MAX_PROTECTED_METADATA_BYTES),
        readBoundedFile(this.commitPath, MAX_PROTECTED_METADATA_BYTES),
        readBoundedFile(this.slotPaths.a, MAX_INDEX_BYTES),
        readBoundedFile(this.slotPaths.b, MAX_INDEX_BYTES),
      ]);
      const allAbsent = !wrappedKey && !protectedCommit && !slotA && !slotB;
      if (allAbsent) {
        this.key = randomBytes(AES_KEY_BYTES);
        const protectedKey = this.safeStorage.encryptString(this.key.toString('base64url'));
        if (
          !Buffer.isBuffer(protectedKey) ||
          protectedKey.length === 0 ||
          protectedKey.length > MAX_PROTECTED_METADATA_BYTES
        ) {
          throw new Error('Task audit index key protection failed');
        }
        await writeAtomic(this.keyPath, protectedKey);
        this.available = true;
        await this.persist();
        return true;
      }
      if (!wrappedKey || !protectedCommit) {
        throw new Error('Task audit index store is incomplete');
      }

      this.key = parseAesKey(this.safeStorage.decryptString(wrappedKey));
      const commit = parseCommit(
        JSON.parse(this.safeStorage.decryptString(protectedCommit)) as unknown
      );
      const activeCiphertext = commit.active_slot === 'a' ? slotA : slotB;
      if (!activeCiphertext || sha256(activeCiphertext) !== commit.index_digest) {
        throw new Error('Task audit index commit does not match its active slot');
      }
      const document = decryptDocument(activeCiphertext, this.key);
      if (document.generation !== commit.generation) {
        throw new Error('Task audit index generation does not match its commit');
      }

      const ordered = this.order(document.entries);
      this.entries = new Map(ordered.map((entry) => [entry.session_id, entry]));
      this.activeSlot = commit.active_slot;
      this.generation = commit.generation;
      this.available = true;
      return true;
    } catch {
      this.retire();
      return false;
    }
  }

  isAvailable(): boolean {
    return this.available;
  }

  get(sessionId: string): AccordLockTaskAuditIndexEntry | null {
    if (!this.available || !boundedIdentifier(sessionId, 256)) return null;
    const entry = this.entries.get(sessionId);
    return entry?.schema_version === ENTRY_SCHEMA_VERSION
      ? globalThis.structuredClone(entry)
      : null;
  }

  async record(entry: AccordLockTaskAuditIndexEntry): Promise<boolean> {
    if (!this.available) return false;
    let parsed: AccordLockTaskAuditIndexEntry;
    try {
      parsed = parseEntry(entry);
    } catch {
      return false;
    }
    if (!isTimestamp(this.nowSeconds())) return false;

    const write = this.writeTail.then(async () => {
      const existing = this.entries.get(parsed.session_id);
      if (existing) {
        if (
          existing.schema_version !== ENTRY_SCHEMA_VERSION ||
          existing.ledger_id !== parsed.ledger_id ||
          existing.task_id !== parsed.task_id ||
          existing.run_id !== parsed.run_id ||
          existing.workspace_id !== parsed.workspace_id ||
          existing.approved_at !== parsed.approved_at ||
          existing.expires_at !== parsed.expires_at
        ) {
          throw new Error('Task audit binding substitution was rejected');
        }
        return;
      }
      if (
        [...this.entries.values()].some(
          (candidate) =>
            candidate.session_id !== parsed.session_id && candidate.task_id === parsed.task_id
        )
      ) {
        throw new Error('Task audit binding substitution was rejected');
      }
      this.entries.set(parsed.session_id, globalThis.structuredClone(parsed));
      this.entries = new Map(
        this.order([...this.entries.values()]).map((ordered) => [ordered.session_id, ordered])
      );
      if (this.entries.size > MAX_ENTRIES) {
        throw new Error('Task audit index reached its retention capacity');
      }
      await this.persist();
    });
    this.writeTail = write.catch(() => undefined);
    try {
      await write;
      return true;
    } catch {
      this.retire();
      return false;
    }
  }

  private order(
    entries: readonly StoredAccordLockTaskAuditIndexEntry[]
  ): StoredAccordLockTaskAuditIndexEntry[] {
    return [...entries].sort(
      (left, right) =>
        right.approved_at - left.approved_at || left.session_id.localeCompare(right.session_id)
    );
  }

  private async persist(): Promise<void> {
    if (!this.available || !this.key) {
      throw new Error('Task audit index storage is unavailable');
    }
    const generation = this.generation + 1;
    const nextSlot: IndexSlot = this.activeSlot === 'a' ? 'b' : 'a';
    const document: AccordLockTaskAuditIndexDocument = {
      schema_version: INDEX_SCHEMA_VERSION,
      generation,
      entries: [...this.entries.values()],
    };
    const encrypted = encryptDocument(document, this.key);
    if (encrypted.length > MAX_INDEX_BYTES) {
      throw new Error('Task audit index exceeds its storage bound');
    }
    await writeAtomic(this.slotPaths[nextSlot], encrypted);
    const commit: AccordLockTaskAuditIndexCommit = {
      schema_version: COMMIT_SCHEMA_VERSION,
      active_slot: nextSlot,
      generation,
      index_digest: sha256(encrypted),
    };
    const protectedCommit = this.safeStorage.encryptString(JSON.stringify(commit));
    if (
      !Buffer.isBuffer(protectedCommit) ||
      protectedCommit.length === 0 ||
      protectedCommit.length > MAX_PROTECTED_METADATA_BYTES
    ) {
      throw new Error('Task audit index commit protection failed');
    }
    await writeAtomic(this.commitPath, protectedCommit);
    this.activeSlot = nextSlot;
    this.generation = generation;
  }

  private retire(): void {
    this.key?.fill(0);
    this.key = null;
    this.entries.clear();
    this.activeSlot = null;
    this.generation = 0;
    this.available = false;
  }
}
