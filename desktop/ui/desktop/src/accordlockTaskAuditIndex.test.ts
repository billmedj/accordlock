import { createCipheriv, createHash, randomBytes, randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  AccordLockTaskAuditIndex,
  accordLockAuditWorkspaceId,
  type AccordLockSafeStorage,
  type AccordLockTaskAuditIndexEntry,
} from './accordlockTaskAuditIndex';

class TestSafeStorage implements AccordLockSafeStorage {
  available = true;
  backend = 'dpapi';

  isEncryptionAvailable(): boolean {
    return this.available;
  }

  encryptString(plaintext: string): Buffer {
    return Buffer.from(`protected:${plaintext}`, 'utf8');
  }

  decryptString(ciphertext: Buffer): string {
    const protectedText = ciphertext.toString('utf8');
    if (!protectedText.startsWith('protected:')) throw new Error('vault rejected ciphertext');
    return protectedText.slice('protected:'.length);
  }

  getSelectedStorageBackend(): string {
    return this.backend;
  }
}

function entry(
  overrides: Partial<AccordLockTaskAuditIndexEntry> = {}
): AccordLockTaskAuditIndexEntry {
  return {
    schema_version: 3,
    ledger_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    task_id: randomUUID(),
    session_id: 'session-1',
    run_id: `sha256:${'1'.repeat(64)}`,
    workspace_id: accordLockAuditWorkspaceId('C:\\trusted\\workspace'),
    approved_at: 1_000,
    expires_at: 2_000,
    ...overrides,
  };
}

async function readCommit(directory: string, safeStorage: TestSafeStorage) {
  const protectedCommit = await fs.readFile(path.join(directory, 'task-audit-index.v2.commit'));
  return JSON.parse(safeStorage.decryptString(protectedCommit)) as {
    schema_version: 1;
    active_slot: 'a' | 'b';
    generation: number;
    index_digest: string;
  };
}

async function replaceCommittedDocument(
  directory: string,
  safeStorage: TestSafeStorage,
  document: unknown
): Promise<void> {
  const wrappedKey = await fs.readFile(path.join(directory, 'task-audit-index.v2.key'));
  const key = Buffer.from(safeStorage.decryptString(wrappedKey), 'base64url');
  const commit = await readCommit(directory, safeStorage);
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(Buffer.from('accordlock.task-audit-index.v2', 'utf8'));
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(document), 'utf8')),
    cipher.final(),
  ]);
  const encrypted = Buffer.concat([
    Buffer.from('ALI2', 'ascii'),
    nonce,
    cipher.getAuthTag(),
    ciphertext,
  ]);
  await fs.writeFile(path.join(directory, `task-audit-index.v2.${commit.active_slot}`), encrypted);
  await fs.writeFile(
    path.join(directory, 'task-audit-index.v2.commit'),
    safeStorage.encryptString(
      JSON.stringify({
        ...commit,
        index_digest: `sha256:${createHash('sha256').update(encrypted).digest('hex')}`,
      })
    )
  );
}

describe('durable task audit index', () => {
  let directory: string;
  let safeStorage: TestSafeStorage;

  beforeEach(async () => {
    directory = await fs.mkdtemp(path.join(os.tmpdir(), 'accordlock-audit-index-'));
    safeStorage = new TestSafeStorage();
  });

  afterEach(async () => {
    await fs.rm(directory, { recursive: true, force: true });
  });

  it('derives an opaque exact workspace entitlement', () => {
    const first = accordLockAuditWorkspaceId('C:\\trusted\\workspace');
    expect(first).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(accordLockAuditWorkspaceId('C:\\trusted\\workspace')).toBe(first);
    expect(accordLockAuditWorkspaceId('C:\\trusted\\other')).not.toBe(first);
    expect(first).not.toContain('trusted');
  });

  it('reopens an exact workspace-bound locator after a full process restart', async () => {
    const first = new AccordLockTaskAuditIndex({
      directory,
      safeStorage,
      nowSeconds: () => 1_500,
    });
    const binding = entry();

    expect(await first.initialize()).toBe(true);
    expect(await first.record(binding)).toBe(true);

    const restarted = new AccordLockTaskAuditIndex({
      directory,
      safeStorage,
      nowSeconds: () => 1_501,
    });
    expect(await restarted.initialize()).toBe(true);
    expect(restarted.get(binding.session_id)).toEqual(binding);
    expect(restarted.get(binding.session_id)).not.toBe(binding);

    const files = await fs.readdir(directory);
    expect(files.sort()).toEqual([
      'task-audit-index.v2.a',
      'task-audit-index.v2.b',
      'task-audit-index.v2.commit',
      'task-audit-index.v2.key',
    ]);
    for (const filename of files) {
      const protectedContents = await fs.readFile(path.join(directory, filename), 'utf8');
      expect(protectedContents).not.toContain(binding.session_id);
      expect(protectedContents).not.toContain(binding.task_id);
      expect(protectedContents).not.toContain(binding.run_id);
      expect(protectedContents).not.toContain(binding.ledger_id);
      expect(protectedContents).not.toContain('C:\\trusted\\workspace');
    }
  });

  it('opens a legacy index safely without treating its incomplete locators as usable', async () => {
    const seed = new AccordLockTaskAuditIndex({ directory, safeStorage });
    await seed.initialize();
    const commit = await readCommit(directory, safeStorage);
    const current = entry();
    const { ledger_id: _ledgerId, ...legacyFields } = current;
    await replaceCommittedDocument(directory, safeStorage, {
      schema_version: 2,
      generation: commit.generation,
      entries: [{ ...legacyFields, schema_version: 2 }],
    });

    const migrated = new AccordLockTaskAuditIndex({ directory, safeStorage });
    expect(await migrated.initialize()).toBe(true);
    expect(migrated.get(current.session_id)).toBeNull();

    const newBinding = entry({
      task_id: randomUUID(),
      session_id: 'session-2',
      run_id: `sha256:${'2'.repeat(64)}`,
      ledger_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    });
    expect(await migrated.record(newBinding)).toBe(true);
    const restarted = new AccordLockTaskAuditIndex({ directory, safeStorage });
    expect(await restarted.initialize()).toBe(true);
    expect(restarted.get(current.session_id)).toBeNull();
    expect(restarted.get(newBinding.session_id)).toEqual(newBinding);
  });

  it('commits an authenticated empty index during first initialization', async () => {
    const index = new AccordLockTaskAuditIndex({ directory, safeStorage });

    expect(await index.initialize()).toBe(true);
    expect((await fs.readdir(directory)).sort()).toEqual([
      'task-audit-index.v2.a',
      'task-audit-index.v2.commit',
      'task-audit-index.v2.key',
    ]);
    expect((await readCommit(directory, safeStorage)).generation).toBe(1);
  });

  it('keeps history unavailable when operating-system encryption is unavailable', async () => {
    safeStorage.available = false;
    const index = new AccordLockTaskAuditIndex({ directory, safeStorage });

    expect(await index.initialize()).toBe(false);
    expect(await index.record(entry())).toBe(false);
    expect(index.get('session-1')).toBeNull();
    await expect(fs.readdir(directory)).resolves.toEqual([]);
  });

  it('rejects insecure or unknown Linux secret-store backends', async () => {
    for (const backend of ['basic_text', 'unknown']) {
      safeStorage.backend = backend;
      const index = new AccordLockTaskAuditIndex({ directory, safeStorage, platform: 'linux' });
      expect(await index.initialize()).toBe(false);
    }
    await expect(fs.readdir(directory)).resolves.toEqual([]);
  });

  it('accepts an operating-system-backed Linux secret store', async () => {
    safeStorage.backend = 'gnome_libsecret';
    const index = new AccordLockTaskAuditIndex({ directory, safeStorage, platform: 'linux' });

    expect(await index.initialize()).toBe(true);
    expect(index.isAvailable()).toBe(true);
  });

  it('treats an operating-system protected-storage error as unavailable storage', async () => {
    vi.spyOn(safeStorage, 'isEncryptionAvailable').mockImplementation(() => {
      throw new Error('vault is locked');
    });
    const index = new AccordLockTaskAuditIndex({ directory, safeStorage });

    await expect(index.initialize()).resolves.toBe(false);
    expect(index.isAvailable()).toBe(false);
    await expect(fs.readdir(directory)).resolves.toEqual([]);
  });

  it('fails closed when the committed slot is corrupted or deleted', async () => {
    const first = new AccordLockTaskAuditIndex({ directory, safeStorage });
    await first.initialize();
    await first.record(entry());
    const commit = await readCommit(directory, safeStorage);
    const indexPath = path.join(directory, `task-audit-index.v2.${commit.active_slot}`);
    const corrupted = await fs.readFile(indexPath);
    corrupted[corrupted.length - 1] ^= 0xff;
    await fs.writeFile(indexPath, corrupted);

    const corruptedRestart = new AccordLockTaskAuditIndex({ directory, safeStorage });
    expect(await corruptedRestart.initialize()).toBe(false);
    expect(await fs.readFile(indexPath)).toEqual(corrupted);

    await fs.rm(indexPath);
    const deletedRestart = new AccordLockTaskAuditIndex({ directory, safeStorage });
    expect(await deletedRestart.initialize()).toBe(false);
  });

  it('ignores an uncommitted inactive generation after a simulated crash', async () => {
    const first = new AccordLockTaskAuditIndex({ directory, safeStorage });
    const binding = entry();
    await first.initialize();
    await first.record(binding);
    const commit = await readCommit(directory, safeStorage);
    const inactive = commit.active_slot === 'a' ? 'b' : 'a';
    await fs.writeFile(
      path.join(directory, `task-audit-index.v2.${inactive}`),
      Buffer.from('uncommitted-write')
    );

    const restarted = new AccordLockTaskAuditIndex({ directory, safeStorage });
    expect(await restarted.initialize()).toBe(true);
    expect(restarted.get(binding.session_id)).toEqual(binding);
  });

  it('rejects an authenticated document with an unexpected schema field', async () => {
    const first = new AccordLockTaskAuditIndex({ directory, safeStorage });
    await first.initialize();
    const commit = await readCommit(directory, safeStorage);
    await replaceCommittedDocument(directory, safeStorage, {
      schema_version: 2,
      generation: commit.generation,
      entries: [],
      bearer_token: 'must-never-be-accepted',
    });

    const restarted = new AccordLockTaskAuditIndex({ directory, safeStorage });
    expect(await restarted.initialize()).toBe(false);
  });

  it('rejects committed ciphertext protected by another local key', async () => {
    const otherDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'accordlock-audit-other-'));
    try {
      const first = new AccordLockTaskAuditIndex({ directory, safeStorage });
      const other = new AccordLockTaskAuditIndex({ directory: otherDirectory, safeStorage });
      await first.initialize();
      await other.initialize();
      await first.record(entry());
      await other.record(entry({ session_id: 'session-2', run_id: `sha256:${'2'.repeat(64)}` }));
      const otherCommit = await readCommit(otherDirectory, safeStorage);
      await fs.copyFile(
        path.join(otherDirectory, 'task-audit-index.v2.commit'),
        path.join(directory, 'task-audit-index.v2.commit')
      );
      await fs.copyFile(
        path.join(otherDirectory, `task-audit-index.v2.${otherCommit.active_slot}`),
        path.join(directory, `task-audit-index.v2.${otherCommit.active_slot}`)
      );

      const restarted = new AccordLockTaskAuditIndex({ directory, safeStorage });
      expect(await restarted.initialize()).toBe(false);
      expect(restarted.get('session-1')).toBeNull();
      expect(restarted.get('session-2')).toBeNull();
    } finally {
      await fs.rm(otherDirectory, { recursive: true, force: true });
    }
  });

  it('rejects run, workspace, and cross-session task substitutions', async () => {
    const substitutions: Array<
      (binding: AccordLockTaskAuditIndexEntry) => AccordLockTaskAuditIndexEntry
    > = [
      (binding) => ({
        ...binding,
        ledger_id: '99999999-9999-4999-8999-999999999999',
      }),
      (binding) => ({ ...binding, run_id: `sha256:${'9'.repeat(64)}` }),
      (binding) => ({ ...binding, workspace_id: `sha256:${'8'.repeat(64)}` }),
      (binding) => ({
        ...binding,
        task_id: '99999999-9999-4999-8999-999999999999',
        run_id: `sha256:${'7'.repeat(64)}`,
      }),
      (binding) => ({
        ...binding,
        session_id: 'session-2',
        run_id: `sha256:${'2'.repeat(64)}`,
      }),
    ];

    for (const substitute of substitutions) {
      const caseDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'accordlock-substitution-'));
      try {
        const index = new AccordLockTaskAuditIndex({
          directory: caseDirectory,
          safeStorage,
          nowSeconds: () => 1_500,
        });
        const binding = entry();
        await index.initialize();
        await index.record(binding);
        expect(
          await index.record({ ...substitute(binding), approved_at: binding.approved_at + 1 })
        ).toBe(false);
        expect(index.isAvailable()).toBe(false);
      } finally {
        await fs.rm(caseDirectory, { recursive: true, force: true });
      }
    }
  });

  it('treats only the complete immutable locator binding as an idempotent retry', async () => {
    const index = new AccordLockTaskAuditIndex({ directory, safeStorage });
    const binding = entry();
    await index.initialize();

    expect(await index.record(binding)).toBe(true);
    expect(await index.record(globalThis.structuredClone(binding))).toBe(true);
    expect(index.get(binding.session_id)).toEqual(binding);
  });

  it('does not delete committed locators after a forward wall-clock jump', async () => {
    const index = new AccordLockTaskAuditIndex({
      directory,
      safeStorage,
      nowSeconds: () => 1_500,
    });
    const binding = entry();
    await index.initialize();
    await index.record(binding);

    const restarted = new AccordLockTaskAuditIndex({
      directory,
      safeStorage,
      nowSeconds: () => 400 * 24 * 60 * 60,
    });
    expect(await restarted.initialize()).toBe(true);
    expect(restarted.get(binding.session_id)).toEqual(binding);
  });

  it('serializes concurrent generation commits without dropping locators', async () => {
    const index = new AccordLockTaskAuditIndex({
      directory,
      safeStorage,
      nowSeconds: () => 1_500,
    });
    await index.initialize();
    const first = entry();
    const second = entry({
      session_id: 'session-2',
      run_id: `sha256:${'2'.repeat(64)}`,
      approved_at: 1_001,
      expires_at: 2_001,
    });

    await expect(Promise.all([index.record(first), index.record(second)])).resolves.toEqual([
      true,
      true,
    ]);
    const restarted = new AccordLockTaskAuditIndex({
      directory,
      safeStorage,
      nowSeconds: () => 1_501,
    });
    await restarted.initialize();
    expect(restarted.get(first.session_id)).toEqual(first);
    expect(restarted.get(second.session_id)).toEqual(second);
    expect((await readCommit(directory, safeStorage)).generation).toBe(3);
  });

  it('never decrypts a partial store with no protected key', async () => {
    await fs.writeFile(
      path.join(directory, 'task-audit-index.v2.commit'),
      safeStorage.encryptString(
        JSON.stringify({
          schema_version: 1,
          active_slot: 'a',
          generation: 1,
          index_digest: `sha256:${'0'.repeat(64)}`,
        })
      )
    );
    await fs.writeFile(path.join(directory, 'task-audit-index.v2.a'), Buffer.from('ALI2evidence'));
    const decrypt = vi.spyOn(safeStorage, 'decryptString');
    const index = new AccordLockTaskAuditIndex({ directory, safeStorage });

    expect(await index.initialize()).toBe(false);
    expect(decrypt).not.toHaveBeenCalled();
  });
});
