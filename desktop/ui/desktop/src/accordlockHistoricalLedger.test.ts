import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  ACCORDLOCK_RUNTIME_DATABASE_FILENAME,
  createFreshAccordLockLedgerDirectory,
  resolveAccordLockHistoricalLedgerDirectory,
} from './accordlockHistoricalLedger';

const LEDGER_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

describe('historical ledger locator', () => {
  let root: string;
  let runs: string;

  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), 'accordlock-ledger-locator-'));
    runs = path.join(root, 'runs');
    await fs.mkdir(runs);
  });

  afterEach(async () => {
    await fs.rm(root, { recursive: true, force: true });
  });

  async function createLedger(ledgerId = LEDGER_ID): Promise<string> {
    const ledger = path.join(runs, ledgerId);
    await fs.mkdir(ledger);
    await fs.writeFile(path.join(ledger, ACCORDLOCK_RUNTIME_DATABASE_FILENAME), 'sqlite fixture');
    return ledger;
  }

  it('resolves one exact regular database beneath the trusted history root', async () => {
    const ledger = await createLedger();

    await expect(resolveAccordLockHistoricalLedgerDirectory(runs, LEDGER_ID)).resolves.toBe(
      await fs.realpath(ledger)
    );
  });

  it('reserves a fresh execution log exactly once', async () => {
    const directory = await createFreshAccordLockLedgerDirectory(runs, LEDGER_ID);

    expect(directory).toBe(await fs.realpath(path.join(runs, LEDGER_ID)));
    await expect(createFreshAccordLockLedgerDirectory(runs, LEDGER_ID)).rejects.toThrow(
      'Fresh execution log storage is unavailable'
    );
  });

  it('rejects path escape syntax before touching the filesystem', async () => {
    await createLedger();

    await expect(
      resolveAccordLockHistoricalLedgerDirectory(runs, '../aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')
    ).rejects.toThrow('locator is invalid');
    await expect(
      resolveAccordLockHistoricalLedgerDirectory(runs, LEDGER_ID.toUpperCase())
    ).rejects.toThrow('locator is invalid');
  });

  it('fails closed for an unknown locator or a non-file database', async () => {
    await expect(resolveAccordLockHistoricalLedgerDirectory(runs, LEDGER_ID)).rejects.toThrow(
      'ledger is unavailable'
    );
    const ledger = path.join(runs, LEDGER_ID);
    await fs.mkdir(path.join(ledger, ACCORDLOCK_RUNTIME_DATABASE_FILENAME), { recursive: true });
    await expect(resolveAccordLockHistoricalLedgerDirectory(runs, LEDGER_ID)).rejects.toThrow(
      'database is unavailable'
    );
  });

  it('rejects a linked ledger directory instead of following it outside the root', async () => {
    const outside = path.join(root, 'outside');
    await fs.mkdir(outside);
    await fs.writeFile(path.join(outside, ACCORDLOCK_RUNTIME_DATABASE_FILENAME), 'sqlite fixture');
    await fs.symlink(
      outside,
      path.join(runs, LEDGER_ID),
      process.platform === 'win32' ? 'junction' : 'dir'
    );

    await expect(resolveAccordLockHistoricalLedgerDirectory(runs, LEDGER_ID)).rejects.toThrow(
      'ledger is unavailable'
    );
  });
});
