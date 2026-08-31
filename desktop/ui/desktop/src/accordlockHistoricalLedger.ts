import fs from 'node:fs/promises';
import path from 'node:path';

export const ACCORDLOCK_RUNTIME_DATABASE_FILENAME = 'agent-runtime.sqlite3';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

async function requireRealDirectory(directory: string, message: string): Promise<string> {
  const metadata = await fs.lstat(directory).catch(() => null);
  if (!metadata?.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(message);
  }
  const canonical = await fs.realpath(directory).catch(() => null);
  if (!canonical) throw new Error(message);
  const canonicalMetadata = await fs.lstat(canonical).catch(() => null);
  if (!canonicalMetadata?.isDirectory() || canonicalMetadata.isSymbolicLink()) {
    throw new Error(message);
  }
  return canonical;
}

function validateLedgerLocator(runsDirectory: string, ledgerId: string): void {
  if (!path.isAbsolute(runsDirectory) || !UUID.test(ledgerId)) {
    throw new Error('Historical task audit locator is invalid');
  }
}

/**
 * Reserves one never-before-used directory for the current runtime. An
 * exclusive directory creation makes execution-authority isolation structural
 * rather than dependent on the negligible probability of a UUID collision.
 */
export async function createFreshAccordLockLedgerDirectory(
  runsDirectory: string,
  ledgerId: string
): Promise<string> {
  validateLedgerLocator(runsDirectory, ledgerId);
  await fs.mkdir(runsDirectory, { recursive: true, mode: 0o700 });
  const canonicalRoot = await requireRealDirectory(
    runsDirectory,
    'Execution log storage is unavailable'
  );
  const requested = path.join(canonicalRoot, ledgerId);
  try {
    await fs.mkdir(requested, { mode: 0o700 });
  } catch {
    throw new Error('Fresh execution log storage is unavailable');
  }
  const canonicalLedger = await requireRealDirectory(
    requested,
    'Fresh execution log storage is unavailable'
  );
  if (path.relative(canonicalRoot, canonicalLedger) !== ledgerId) {
    throw new Error('Fresh execution log escaped its storage boundary');
  }
  return canonicalLedger;
}

/**
 * Resolves one OS-protected ledger locator beneath the fixed runtime history
 * root. The locator is an opaque UUID rather than a path, and both the desktop
 * and the audit-only Rust process independently reject links and non-files.
 */
export async function resolveAccordLockHistoricalLedgerDirectory(
  runsDirectory: string,
  ledgerId: string
): Promise<string> {
  validateLedgerLocator(runsDirectory, ledgerId);
  const canonicalRoot = await requireRealDirectory(
    runsDirectory,
    'Historical task audit storage is unavailable'
  );
  const requested = path.join(canonicalRoot, ledgerId);
  const canonicalLedger = await requireRealDirectory(
    requested,
    'Historical task audit ledger is unavailable'
  );
  if (path.relative(canonicalRoot, canonicalLedger) !== ledgerId) {
    throw new Error('Historical task audit locator escaped its storage boundary');
  }

  const database = path.join(canonicalLedger, ACCORDLOCK_RUNTIME_DATABASE_FILENAME);
  const databaseMetadata = await fs.lstat(database).catch(() => null);
  if (!databaseMetadata?.isFile() || databaseMetadata.isSymbolicLink()) {
    throw new Error('Historical task audit database is unavailable');
  }
  return canonicalLedger;
}
