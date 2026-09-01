import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const CONFIG_SCHEMA_VERSION = 2;
const CONFIG_DIGEST_DOMAIN = 'accordlock:v2:terminal-program-configuration';
const MAX_CONFIG_BYTES = 64 * 1_024;
const ALIAS_PATTERN = /^[a-z0-9_-]{1,64}$/u;
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const BANNED_EXECUTABLE_STEMS = new Set([
  'bash',
  'cmd',
  'cscript',
  'dash',
  'fish',
  'mshta',
  'powershell',
  'pwsh',
  'regsvr32',
  'rundll32',
  'sh',
  'wscript',
  'wsl',
  'zsh',
]);

export interface AccordLockTerminalProgramBinding {
  alias: string;
  executable_path: string;
  executable_sha256: string;
}

interface AccordLockTerminalProgramConfiguration {
  schema_version: 1;
  programs: AccordLockTerminalProgramBinding[];
  configuration_digest: string;
}

export interface AccordLockNativeExecutableSelection {
  canceled: boolean;
  filePaths: string[];
}

const hasExactKeys = (value: Record<string, unknown>, keys: readonly string[]): boolean => {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const sameFileIdentity = (left: fs.BigIntStats, right: fs.BigIntStats): boolean =>
  left.dev === right.dev &&
  left.ino === right.ino &&
  (left.ino !== 0n ||
    (left.birthtimeMs === right.birthtimeMs &&
      left.size === right.size &&
      left.mode === right.mode));

const hashFile = (filePath: string): string => {
  const hash = createHash('sha256');
  const descriptor = fs.openSync(filePath, 'r');
  try {
    const buffer = Buffer.allocUnsafe(32 * 1_024);
    for (;;) {
      const count = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (count === 0) break;
      hash.update(buffer.subarray(0, count));
    }
  } finally {
    fs.closeSync(descriptor);
  }
  return `sha256:${hash.digest('hex')}`;
};

export const validateAccordLockTerminalProgramAlias = (alias: unknown): string => {
  if (
    typeof alias !== 'string' ||
    !ALIAS_PATTERN.test(alias) ||
    BANNED_EXECUTABLE_STEMS.has(alias)
  ) {
    throw new Error('AccordLock terminal alias is outside the strict non-shell profile');
  }
  return alias;
};

export const inspectAccordLockTerminalProgram = (
  alias: unknown,
  selectedPath: unknown,
  platform: NodeJS.Platform = process.platform
): AccordLockTerminalProgramBinding => {
  const trustedAlias = validateAccordLockTerminalProgramAlias(alias);
  if (typeof selectedPath !== 'string' || !path.isAbsolute(selectedPath)) {
    throw new Error('AccordLock terminal executable must be an absolute path');
  }
  const requested = path.resolve(selectedPath);
  const metadata = fs.lstatSync(requested, { bigint: true });
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error('AccordLock terminal executable must be a regular non-link file');
  }
  const canonical = fs.realpathSync.native(requested);
  const canonicalMetadata = fs.lstatSync(canonical, { bigint: true });
  if (
    !canonicalMetadata.isFile() ||
    canonicalMetadata.isSymbolicLink() ||
    !sameFileIdentity(metadata, canonicalMetadata)
  ) {
    throw new Error('AccordLock terminal executable changed while it was being inspected');
  }
  const stem = path.basename(canonical, path.extname(canonical)).toLowerCase();
  if (BANNED_EXECUTABLE_STEMS.has(stem)) {
    throw new Error('AccordLock does not provision shell or command interpreters');
  }
  if (platform === 'win32' && path.extname(canonical).toLowerCase() !== '.exe') {
    throw new Error('AccordLock Windows terminal programs must be native executables');
  }
  const executableSha256 = hashFile(canonical);
  const finalMetadata = fs.lstatSync(canonical, { bigint: true });
  if (!finalMetadata.isFile() || !sameFileIdentity(canonicalMetadata, finalMetadata)) {
    throw new Error('AccordLock terminal executable changed while it was being inspected');
  }
  return {
    alias: trustedAlias,
    executable_path: canonical,
    executable_sha256: executableSha256,
  };
};

const configurationPayload = (programs: readonly AccordLockTerminalProgramBinding[]) => ({
  schema_version: CONFIG_SCHEMA_VERSION as 1,
  programs: [...programs],
});

export const accordLockTerminalProgramConfigurationDigest = (
  programs: readonly AccordLockTerminalProgramBinding[]
): string => {
  const hash = createHash('sha256');
  hash.update(CONFIG_DIGEST_DOMAIN, 'utf8');
  hash.update('\0', 'utf8');
  hash.update(JSON.stringify(configurationPayload(programs)), 'utf8');
  return `sha256:${hash.digest('hex')}`;
};

const validateStoredBinding = (
  value: unknown,
  platform: NodeJS.Platform
): AccordLockTerminalProgramBinding => {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ['alias', 'executable_path', 'executable_sha256']) ||
    typeof value.executable_path !== 'string' ||
    typeof value.executable_sha256 !== 'string' ||
    !DIGEST_PATTERN.test(value.executable_sha256)
  ) {
    throw new Error('AccordLock terminal program configuration is malformed');
  }
  const inspected = inspectAccordLockTerminalProgram(value.alias, value.executable_path, platform);
  if (inspected.executable_sha256 !== value.executable_sha256) {
    throw new Error('AccordLock terminal executable changed after it was selected');
  }
  return inspected;
};

export const loadAccordLockTerminalPrograms = (
  configurationPath: string,
  platform: NodeJS.Platform = process.platform
): AccordLockTerminalProgramBinding[] => {
  if (!fs.existsSync(configurationPath)) return [];
  const metadata = fs.lstatSync(configurationPath);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > MAX_CONFIG_BYTES) {
    throw new Error('AccordLock terminal program configuration is not a trusted regular file');
  }
  const parsed: unknown = JSON.parse(fs.readFileSync(configurationPath, 'utf8'));
  if (
    !isRecord(parsed) ||
    !hasExactKeys(parsed, ['schema_version', 'programs', 'configuration_digest']) ||
    parsed.schema_version !== CONFIG_SCHEMA_VERSION ||
    !Array.isArray(parsed.programs) ||
    typeof parsed.configuration_digest !== 'string' ||
    !DIGEST_PATTERN.test(parsed.configuration_digest)
  ) {
    throw new Error('AccordLock terminal program configuration is malformed');
  }
  const programs = parsed.programs.map((program) => validateStoredBinding(program, platform));
  const aliases = programs.map(({ alias }) => alias);
  if (
    aliases.some((alias, index) => index > 0 && alias <= aliases[index - 1]) ||
    accordLockTerminalProgramConfigurationDigest(programs) !== parsed.configuration_digest
  ) {
    throw new Error('AccordLock terminal program configuration commitment is invalid');
  }
  return programs;
};

export const writeAccordLockTerminalPrograms = (
  configurationPath: string,
  programs: readonly AccordLockTerminalProgramBinding[],
  platform: NodeJS.Platform = process.platform
): void => {
  const validated = programs
    .map((program) => validateStoredBinding(program, platform))
    .sort((left, right) => left.alias.localeCompare(right.alias, 'en-US'));
  if (validated.some(({ alias }, index) => index > 0 && alias === validated[index - 1].alias)) {
    throw new Error('AccordLock terminal aliases must be unique');
  }
  const document: AccordLockTerminalProgramConfiguration = {
    ...configurationPayload(validated),
    configuration_digest: accordLockTerminalProgramConfigurationDigest(validated),
  };
  const directory = path.dirname(path.resolve(configurationPath));
  fs.mkdirSync(directory, { recursive: true });
  const directoryMetadata = fs.lstatSync(directory);
  if (!directoryMetadata.isDirectory() || directoryMetadata.isSymbolicLink()) {
    throw new Error('AccordLock terminal configuration directory is not trusted');
  }
  const temporaryPath = path.join(
    directory,
    `.${path.basename(configurationPath)}.${randomBytes(12).toString('hex')}.tmp`
  );
  let descriptor: number | undefined;
  try {
    descriptor = fs.openSync(temporaryPath, 'wx', 0o600);
    fs.writeFileSync(descriptor, `${JSON.stringify(document, null, 2)}\n`, 'utf8');
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    fs.renameSync(temporaryPath, path.resolve(configurationPath));
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    fs.rmSync(temporaryPath, { force: true });
  }
};

export const pickAndPersistAccordLockTerminalProgram = async ({
  alias,
  configurationPath,
  selectExecutable,
  confirmBinding,
  platform = process.platform,
}: {
  alias: unknown;
  configurationPath: string;
  selectExecutable: () => Promise<AccordLockNativeExecutableSelection>;
  confirmBinding?: (binding: AccordLockTerminalProgramBinding) => Promise<boolean>;
  platform?: NodeJS.Platform;
}): Promise<{ configured: boolean; canceled: boolean; restartRequired: boolean }> => {
  const trustedAlias = validateAccordLockTerminalProgramAlias(alias);
  const selection = await selectExecutable();
  if (selection.canceled || selection.filePaths.length === 0) {
    return { configured: false, canceled: true, restartRequired: false };
  }
  if (selection.filePaths.length !== 1) {
    throw new Error('AccordLock terminal provisioning requires exactly one native selection');
  }
  const program = inspectAccordLockTerminalProgram(trustedAlias, selection.filePaths[0], platform);
  if (confirmBinding && !(await confirmBinding(program))) {
    return { configured: false, canceled: true, restartRequired: false };
  }
  const existing = loadAccordLockTerminalPrograms(configurationPath, platform).filter(
    ({ alias: existingAlias }) => existingAlias !== trustedAlias
  );
  writeAccordLockTerminalPrograms(configurationPath, [...existing, program], platform);
  return { configured: true, canceled: false, restartRequired: true };
};

export const removeAccordLockTerminalProgram = (
  alias: unknown,
  configurationPath: string,
  platform: NodeJS.Platform = process.platform
): boolean => {
  const trustedAlias = validateAccordLockTerminalProgramAlias(alias);
  const programs = loadAccordLockTerminalPrograms(configurationPath, platform);
  const retained = programs.filter((program) => program.alias !== trustedAlias);
  if (retained.length === programs.length) return false;
  writeAccordLockTerminalPrograms(configurationPath, retained, platform);
  return true;
};
