import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const CONFIG_SCHEMA_VERSION = 1;
const CONFIG_DIGEST_DOMAIN = 'accordlock:v1:network-access-policy';
const MAX_CONFIG_BYTES = 64 * 1_024;
const MAX_DOMAINS = 64;

export interface AccordLockGovernedNetworkPolicy {
  schema_version: 1;
  allowed_domains: string[];
  allowed_methods: ['GET', 'HEAD'];
  configuration_digest: string;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const hasExactKeys = (value: Record<string, unknown>, expected: readonly string[]): boolean => {
  const actual = Object.keys(value).sort();
  const keys = [...expected].sort();
  return actual.length === keys.length && actual.every((key, index) => key === keys[index]);
};

export const validateAccordLockNetworkDomain = (value: unknown): string => {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > 253 ||
    value !== value.trim() ||
    value !== value.toLowerCase() ||
    value.endsWith('.') ||
    value === 'localhost' ||
    value.endsWith('.localhost') ||
    value.includes('*') ||
    value.includes('://') ||
    !value.includes('.')
  ) {
    throw new Error('Enter an exact lowercase public domain, such as api.example.com');
  }
  const labels = value.split('.');
  if (
    labels.some(
      (label) =>
        label.length === 0 ||
        label.length > 63 ||
        label.startsWith('-') ||
        label.endsWith('-') ||
        !/^[a-z0-9-]+$/u.test(label)
    ) ||
    /^\d{1,3}(?:\.\d{1,3}){3}$/u.test(value) ||
    value.includes(':')
  ) {
    throw new Error('Enter an exact lowercase public domain, such as api.example.com');
  }
  return value;
};

export const normalizeAccordLockNetworkDomains = (value: unknown): string[] => {
  if (!Array.isArray(value) || value.length > MAX_DOMAINS) {
    throw new Error(`Network access supports up to ${MAX_DOMAINS} exact domains`);
  }
  const domains = value
    .map(validateAccordLockNetworkDomain)
    .sort((left, right) => left.localeCompare(right, 'en-US'));
  if (domains.some((domain, index) => index > 0 && domain === domains[index - 1])) {
    throw new Error('Each network domain must be unique');
  }
  return domains;
};

const configurationPayload = (domains: readonly string[]) => ({
  schema_version: CONFIG_SCHEMA_VERSION as 1,
  allowed_domains: [...domains],
  allowed_methods: ['GET', 'HEAD'] as ['GET', 'HEAD'],
});

export const accordLockNetworkPolicyDigest = (domains: readonly string[]): string => {
  const hash = createHash('sha256');
  hash.update(CONFIG_DIGEST_DOMAIN, 'utf8');
  hash.update('\0', 'utf8');
  hash.update(JSON.stringify(configurationPayload(domains)), 'utf8');
  return `sha256:${hash.digest('hex')}`;
};

export const loadAccordLockNetworkPolicy = (
  configurationPath: string
): AccordLockGovernedNetworkPolicy | null => {
  if (!fs.existsSync(configurationPath)) return null;
  const metadata = fs.lstatSync(configurationPath);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > MAX_CONFIG_BYTES) {
    throw new Error('Network access policy is not a trusted regular file');
  }
  const parsed: unknown = JSON.parse(fs.readFileSync(configurationPath, 'utf8'));
  if (
    !isRecord(parsed) ||
    !hasExactKeys(parsed, [
      'schema_version',
      'allowed_domains',
      'allowed_methods',
      'configuration_digest',
    ]) ||
    parsed.schema_version !== CONFIG_SCHEMA_VERSION ||
    !Array.isArray(parsed.allowed_methods) ||
    parsed.allowed_methods.length !== 2 ||
    parsed.allowed_methods[0] !== 'GET' ||
    parsed.allowed_methods[1] !== 'HEAD' ||
    typeof parsed.configuration_digest !== 'string' ||
    !/^sha256:[0-9a-f]{64}$/u.test(parsed.configuration_digest)
  ) {
    throw new Error('Network access policy is malformed');
  }
  const domains = normalizeAccordLockNetworkDomains(parsed.allowed_domains);
  if (accordLockNetworkPolicyDigest(domains) !== parsed.configuration_digest) {
    throw new Error('Network access policy commitment is invalid');
  }
  return {
    ...configurationPayload(domains),
    configuration_digest: parsed.configuration_digest,
  };
};

export const writeAccordLockNetworkPolicy = (
  configurationPath: string,
  rawDomains: unknown
): AccordLockGovernedNetworkPolicy => {
  const domains = normalizeAccordLockNetworkDomains(rawDomains);
  const document: AccordLockGovernedNetworkPolicy = {
    ...configurationPayload(domains),
    configuration_digest: accordLockNetworkPolicyDigest(domains),
  };
  const directory = path.dirname(path.resolve(configurationPath));
  fs.mkdirSync(directory, { recursive: true });
  const directoryMetadata = fs.lstatSync(directory);
  if (!directoryMetadata.isDirectory() || directoryMetadata.isSymbolicLink()) {
    throw new Error('Network access policy directory is not trusted');
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
  return document;
};
