import fs from 'node:fs/promises';
import path from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';

const STORE_SCHEMA_VERSION = 1;
const MAX_STORE_BYTES = 128 * 1_024;
const SECURE_LINUX_BACKENDS = new Set(['gnome_libsecret', 'kwallet', 'kwallet5', 'kwallet6']);

export const ACCORDLOCK_APPROVAL_CHANNELS_LIST = 'accordlock:approval-channels:list';
export const ACCORDLOCK_APPROVAL_CHANNELS_SAVE = 'accordlock:approval-channels:save';
export const ACCORDLOCK_APPROVAL_CHANNELS_REMOVE = 'accordlock:approval-channels:remove';
export const ACCORDLOCK_APPROVAL_CHANNELS_SET_ENABLED = 'accordlock:approval-channels:set-enabled';
export const ACCORDLOCK_APPROVAL_CHANNELS_TEST = 'accordlock:approval-channels:test';

export type AccordLockApprovalChannelId = 'SLACK' | 'MICROSOFT_TEAMS' | 'TELEGRAM' | 'WHATSAPP';

type CommonInput = {
  enabled: boolean;
};

export type AccordLockApprovalChannelInput =
  | (CommonInput & {
      channel: 'SLACK';
      accessToken: string;
      destination: string;
    })
  | (CommonInput & {
      channel: 'MICROSOFT_TEAMS';
      accessToken: string;
      conversationId: string;
      serviceUrl: string;
    })
  | (CommonInput & {
      channel: 'TELEGRAM';
      botToken: string;
      chatId: string;
    })
  | (CommonInput & {
      channel: 'WHATSAPP';
      accessToken: string;
      phoneNumberId: string;
      recipient: string;
    });

export type AccordLockApprovalChannelSummary = {
  channel: AccordLockApprovalChannelId;
  configuredAt: number;
  destinationHint: string;
  enabled: boolean;
  updatedAt: number;
};

/** Main-process-only material. Never expose this through preload or renderer IPC. */
export type AccordLockApprovalChannelDispatchBundle = {
  channels: AccordLockApprovalChannelInput[];
  outboxKeyHex: string;
};

type StoredEntry = AccordLockApprovalChannelInput & {
  configuredAt: number;
  updatedAt: number;
};

type StoredDocument = {
  entries: StoredEntry[];
  schemaVersion: 1;
};

export interface AccordLockApprovalChannelSafeStorage {
  decryptString(ciphertext: Buffer): string;
  encryptString(plaintext: string): Buffer;
  getSelectedStorageBackend?(): string;
  isEncryptionAvailable(): boolean;
}

type StoreOptions = {
  directory: string;
  nowSeconds?: () => number;
  platform?: NodeJS.Platform;
  safeStorage: AccordLockApprovalChannelSafeStorage;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
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

function boundedText(value: unknown, maximumBytes: number): value is string {
  return (
    typeof value === 'string' &&
    value.trim() === value &&
    value.length > 0 &&
    Buffer.byteLength(value, 'utf8') <= maximumBytes &&
    !hasForbiddenTextCodePoint(value)
  );
}

function token(value: unknown, minimumBytes = 20, maximumBytes = 512): value is string {
  return (
    boundedText(value, maximumBytes) &&
    Buffer.byteLength(value, 'utf8') >= minimumBytes &&
    !/\s/u.test(value)
  );
}

function timestamp(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function parseTeamsServiceUrl(value: unknown): string {
  if (!boundedText(value, 512)) throw new Error('Microsoft Teams service URL is invalid');
  if (
    value.includes('\\') ||
    value.includes('%') ||
    value.includes('?') ||
    value.includes('#') ||
    value.includes('/../') ||
    value.includes('/./')
  ) {
    throw new Error('Microsoft Teams service URL is invalid');
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error('Microsoft Teams service URL is invalid');
  }
  if (
    parsed.protocol !== 'https:' ||
    parsed.username ||
    parsed.password ||
    parsed.hostname.toLocaleLowerCase('en-US') !== 'smba.trafficmanager.net' ||
    parsed.search ||
    parsed.hash ||
    parsed.port
  ) {
    throw new Error('Microsoft Teams service URL is not allowed');
  }
  const segments = parsed.pathname.split('/').filter(Boolean);
  if (
    segments.length === 0 ||
    segments.some(
      (segment) =>
        segment === '.' ||
        segment === '..' ||
        segment.length > 128 ||
        !/^[A-Za-z0-9._~-]+$/u.test(segment)
    )
  ) {
    throw new Error('Microsoft Teams service URL is invalid');
  }
  return `https://smba.trafficmanager.net/${segments.join('/')}/`;
}

export function parseAccordLockApprovalChannelInput(
  value: unknown
): AccordLockApprovalChannelInput {
  if (!isRecord(value) || typeof value.channel !== 'string' || typeof value.enabled !== 'boolean') {
    throw new Error('Approval channel configuration is invalid');
  }

  switch (value.channel) {
    case 'SLACK':
      if (
        !exactKeys(value, ['channel', 'enabled', 'accessToken', 'destination']) ||
        !token(value.accessToken) ||
        !boundedText(value.destination, 64) ||
        !/^[CDGU][A-Z0-9]{1,63}$/u.test(value.destination)
      ) {
        throw new Error('Slack configuration is invalid');
      }
      return {
        channel: 'SLACK',
        enabled: value.enabled,
        accessToken: value.accessToken,
        destination: value.destination,
      };
    case 'MICROSOFT_TEAMS':
      if (
        !exactKeys(value, ['channel', 'enabled', 'accessToken', 'conversationId', 'serviceUrl']) ||
        !token(value.accessToken) ||
        !boundedText(value.conversationId, 256)
      ) {
        throw new Error('Microsoft Teams configuration is invalid');
      }
      return {
        channel: 'MICROSOFT_TEAMS',
        enabled: value.enabled,
        accessToken: value.accessToken,
        conversationId: value.conversationId,
        serviceUrl: parseTeamsServiceUrl(value.serviceUrl),
      };
    case 'TELEGRAM':
      if (
        !exactKeys(value, ['channel', 'enabled', 'botToken', 'chatId']) ||
        !boundedText(value.botToken, 256) ||
        !/^\d{5,20}:[A-Za-z0-9_-]{30,128}$/u.test(value.botToken) ||
        !boundedText(value.chatId, 32) ||
        !/^-?\d{1,20}$/u.test(value.chatId)
      ) {
        throw new Error('Telegram configuration is invalid');
      }
      return {
        channel: 'TELEGRAM',
        enabled: value.enabled,
        botToken: value.botToken,
        chatId: value.chatId,
      };
    case 'WHATSAPP':
      if (
        !exactKeys(value, ['channel', 'enabled', 'accessToken', 'phoneNumberId', 'recipient']) ||
        !token(value.accessToken, 32, 1_024) ||
        !boundedText(value.phoneNumberId, 32) ||
        !/^\d{5,32}$/u.test(value.phoneNumberId) ||
        !boundedText(value.recipient, 24) ||
        !/^\+?\d{7,15}$/u.test(value.recipient)
      ) {
        throw new Error('WhatsApp configuration is invalid');
      }
      return {
        channel: 'WHATSAPP',
        enabled: value.enabled,
        accessToken: value.accessToken,
        phoneNumberId: value.phoneNumberId,
        recipient: value.recipient.replace(/^\+/u, ''),
      };
    default:
      throw new Error('Approval channel is not supported');
  }
}

function parseStoredEntry(value: unknown): StoredEntry {
  if (!isRecord(value) || !timestamp(value.configuredAt) || !timestamp(value.updatedAt)) {
    throw new Error('Stored approval channel configuration is invalid');
  }
  const { configuredAt, updatedAt, ...input } = value;
  if (updatedAt < configuredAt) {
    throw new Error('Stored approval channel configuration is invalid');
  }
  return { ...parseAccordLockApprovalChannelInput(input), configuredAt, updatedAt };
}

function parseDocument(value: unknown): StoredDocument {
  if (
    !isRecord(value) ||
    !exactKeys(value, ['schemaVersion', 'entries']) ||
    value.schemaVersion !== STORE_SCHEMA_VERSION ||
    !Array.isArray(value.entries) ||
    value.entries.length > 4
  ) {
    throw new Error('Approval channel store is invalid');
  }
  const entries = value.entries.map(parseStoredEntry);
  if (new Set(entries.map((entry) => entry.channel)).size !== entries.length) {
    throw new Error('Approval channel store contains duplicate entries');
  }
  return { schemaVersion: STORE_SCHEMA_VERSION, entries };
}

function destination(entry: StoredEntry): string {
  if (entry.channel === 'SLACK') return entry.destination;
  if (entry.channel === 'MICROSOFT_TEAMS') return entry.conversationId;
  if (entry.channel === 'TELEGRAM') return entry.chatId;
  return entry.recipient;
}

function hint(value: string): string {
  const visible = [...value].slice(-6).join('');
  return `${'•'.repeat(Math.min(4, Math.max(1, value.length - visible.length)))}${visible}`;
}

function summary(entry: StoredEntry): AccordLockApprovalChannelSummary {
  return {
    channel: entry.channel,
    configuredAt: entry.configuredAt,
    destinationHint: hint(destination(entry)),
    enabled: entry.enabled,
    updatedAt: entry.updatedAt,
  };
}

async function writeAtomic(filePath: string, contents: Buffer): Promise<void> {
  const directory = path.dirname(filePath);
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  const temporaryPath = path.join(directory, `.approval-channels.${randomUUID()}.tmp`);
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

export class AccordLockApprovalChannelStore {
  private readonly filePath: string;
  private readonly notificationKeyPath: string;
  private readonly nowSeconds: () => number;
  private readonly platform: NodeJS.Platform;
  private readonly safeStorage: AccordLockApprovalChannelSafeStorage;
  private writeTail: Promise<void> = Promise.resolve();
  private notificationKeyTail: Promise<string> | null = null;

  constructor(options: StoreOptions) {
    this.filePath = path.join(options.directory, 'approval-channels.v1.bin');
    this.notificationKeyPath = path.join(options.directory, 'approval-notifications-key.v1.bin');
    this.nowSeconds = options.nowSeconds ?? (() => Math.floor(Date.now() / 1_000));
    this.platform = options.platform ?? process.platform;
    this.safeStorage = options.safeStorage;
  }

  async list(): Promise<AccordLockApprovalChannelSummary[]> {
    await this.writeTail;
    return (await this.read()).entries
      .map(summary)
      .sort((left, right) => left.channel.localeCompare(right.channel));
  }

  /**
   * Loads enabled delivery material for the trusted main process only.
   * Stored credentials remain absent from every renderer-facing summary.
   */
  async loadNotificationDispatchBundle(): Promise<AccordLockApprovalChannelDispatchBundle | null> {
    await this.writeTail;
    const channels = (await this.read()).entries
      .filter((entry) => entry.enabled)
      .map(({ configuredAt: _configuredAt, updatedAt: _updatedAt, ...input }) => input)
      .sort((left, right) => left.channel.localeCompare(right.channel));
    if (channels.length === 0) return null;
    return {
      channels,
      outboxKeyHex: await this.loadOrCreateNotificationKey(),
    };
  }

  async loadNotificationTestBundle(
    channel: unknown
  ): Promise<AccordLockApprovalChannelDispatchBundle> {
    if (!isChannelId(channel)) throw new Error('Approval channel is not supported');
    await this.writeTail;
    const entry = (await this.read()).entries.find((candidate) => candidate.channel === channel);
    if (!entry) throw new Error('Approval channel is not configured');
    if (!entry.enabled) throw new Error('Approval channel is disabled');
    const { configuredAt: _configuredAt, updatedAt: _updatedAt, ...input } = entry;
    return {
      channels: [input],
      outboxKeyHex: await this.loadOrCreateNotificationKey(),
    };
  }

  async save(value: unknown): Promise<AccordLockApprovalChannelSummary> {
    const input = parseAccordLockApprovalChannelInput(value);
    let saved: AccordLockApprovalChannelSummary | null = null;
    const operation = this.writeTail.then(async () => {
      const document = await this.read();
      const now = this.nowSeconds();
      if (!timestamp(now)) throw new Error('Approval channel clock is unavailable');
      const existing = document.entries.find((entry) => entry.channel === input.channel);
      const entry: StoredEntry = {
        ...input,
        configuredAt: existing?.configuredAt ?? now,
        updatedAt: now,
      };
      document.entries = [
        ...document.entries.filter((candidate) => candidate.channel !== input.channel),
        entry,
      ];
      await this.write(document);
      saved = summary(entry);
    });
    this.writeTail = operation.catch(() => undefined);
    await operation;
    if (!saved) throw new Error('Approval channel configuration was not saved');
    return saved;
  }

  async remove(channel: unknown): Promise<boolean> {
    if (!isChannelId(channel)) throw new Error('Approval channel is not supported');
    let removed = false;
    const operation = this.writeTail.then(async () => {
      const document = await this.read();
      const entries = document.entries.filter((entry) => entry.channel !== channel);
      removed = entries.length !== document.entries.length;
      if (removed) await this.write({ schemaVersion: STORE_SCHEMA_VERSION, entries });
    });
    this.writeTail = operation.catch(() => undefined);
    await operation;
    return removed;
  }

  async setEnabled(channel: unknown, enabled: unknown): Promise<AccordLockApprovalChannelSummary> {
    if (!isChannelId(channel) || typeof enabled !== 'boolean') {
      throw new Error('Approval channel update is invalid');
    }
    let saved: AccordLockApprovalChannelSummary | null = null;
    const operation = this.writeTail.then(async () => {
      const document = await this.read();
      const entry = document.entries.find((candidate) => candidate.channel === channel);
      if (!entry) throw new Error('Approval channel is not configured');
      const now = this.nowSeconds();
      if (!timestamp(now)) throw new Error('Approval channel clock is unavailable');
      entry.enabled = enabled;
      entry.updatedAt = now;
      await this.write(document);
      saved = summary(entry);
    });
    this.writeTail = operation.catch(() => undefined);
    await operation;
    if (!saved) throw new Error('Approval channel configuration was not updated');
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

  private loadOrCreateNotificationKey(): Promise<string> {
    if (this.notificationKeyTail) return this.notificationKeyTail;
    const operation = this.readOrCreateNotificationKey();
    this.notificationKeyTail = operation;
    void operation.then(
      () => {
        if (this.notificationKeyTail === operation) this.notificationKeyTail = null;
      },
      () => {
        if (this.notificationKeyTail === operation) this.notificationKeyTail = null;
      }
    );
    return operation;
  }

  private async readOrCreateNotificationKey(): Promise<string> {
    this.requireSecureStorage();
    try {
      const encrypted = await fs.readFile(this.notificationKeyPath);
      if (encrypted.length === 0 || encrypted.length > 16 * 1_024) {
        throw new Error('Approval notification key is invalid');
      }
      const key = this.safeStorage.decryptString(encrypted);
      if (!/^[0-9a-f]{64}$/u.test(key) || /^0{64}$/u.test(key)) {
        throw new Error('Approval notification key is invalid');
      }
      return key;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }

    const key = randomBytes(32).toString('hex');
    const encrypted = this.safeStorage.encryptString(key);
    if (!Buffer.isBuffer(encrypted) || encrypted.length === 0 || encrypted.length > 16 * 1_024) {
      throw new Error('Approval notification key protection failed');
    }
    await writeAtomic(this.notificationKeyPath, encrypted);
    return key;
  }

  private async read(): Promise<StoredDocument> {
    this.requireSecureStorage();
    let encrypted: Buffer;
    try {
      encrypted = await fs.readFile(this.filePath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return { schemaVersion: STORE_SCHEMA_VERSION, entries: [] };
      }
      throw error;
    }
    if (encrypted.length === 0 || encrypted.length > MAX_STORE_BYTES) {
      throw new Error('Approval channel store is invalid');
    }
    const plaintext = this.safeStorage.decryptString(encrypted);
    if (Buffer.byteLength(plaintext, 'utf8') > MAX_STORE_BYTES) {
      throw new Error('Approval channel store is invalid');
    }
    return parseDocument(JSON.parse(plaintext) as unknown);
  }

  private async write(document: StoredDocument): Promise<void> {
    this.requireSecureStorage();
    const plaintext = JSON.stringify(parseDocument(document));
    if (Buffer.byteLength(plaintext, 'utf8') > MAX_STORE_BYTES) {
      throw new Error('Approval channel store is too large');
    }
    const encrypted = this.safeStorage.encryptString(plaintext);
    if (
      !Buffer.isBuffer(encrypted) ||
      encrypted.length === 0 ||
      encrypted.length > MAX_STORE_BYTES
    ) {
      throw new Error('Approval channel store protection failed');
    }
    await writeAtomic(this.filePath, encrypted);
  }
}

export function isChannelId(value: unknown): value is AccordLockApprovalChannelId {
  return (
    value === 'SLACK' || value === 'MICROSOFT_TEAMS' || value === 'TELEGRAM' || value === 'WHATSAPP'
  );
}
