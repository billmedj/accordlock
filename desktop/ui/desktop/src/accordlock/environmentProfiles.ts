export const ACCORDLOCK_ENVIRONMENT_PROFILE_SCHEMA_VERSION = 1 as const;

export type AccordLockEnvironmentProfileStatus = 'SAVED' | 'VERIFIED' | 'FAILED';
export type AccordLockEnvironmentRunnerMode = 'LOCAL_BUNDLED';
export type AccordLockEnvironmentProvider = 'github' | 'aws';

export type AccordLockEnvironmentVerificationFailureCode =
  | 'RUNNER_UNAVAILABLE'
  | 'RUNNER_TIMEOUT'
  | 'RUNNER_REJECTED'
  | 'PREFLIGHT_BLOCKED'
  | 'PREFLIGHT_INDETERMINATE'
  | 'ATTESTATION_MISMATCH'
  | 'PROFILE_CHANGED';

export type AccordLockCredentialMaterialUpdate =
  | Readonly<{ mode: 'KEEP' }>
  | Readonly<{ mode: 'SET'; value: string }>;

export type AccordLockCredentialInput = Readonly<{
  /** Main-process-only source name. It is intentionally absent from summaries. */
  reference: string;
  /** Opaque provider credential material. It is encrypted before persistence. */
  material: AccordLockCredentialMaterialUpdate;
}>;

export type AccordLockGitHubRoute = Readonly<{
  repository: string;
  workflow: string;
}>;

export type AccordLockAwsRoute = Readonly<{
  accountId: string;
  region: string;
  ecrRepository: string;
}>;

export type AccordLockKubernetesRoute = Readonly<{
  clusterName: string;
  namespace: string;
  deployment: string;
  container: string;
}>;

export type AccordLockEnvironmentProfileInput = Readonly<{
  /** `null` creates a profile. An existing UUID updates that exact profile. */
  id: string | null;
  name: string;
  runner: Readonly<{ mode: AccordLockEnvironmentRunnerMode }>;
  github: AccordLockGitHubRoute;
  aws: AccordLockAwsRoute;
  kubernetes: AccordLockKubernetesRoute;
  credentials: Readonly<{
    github: AccordLockCredentialInput;
    aws: AccordLockCredentialInput;
  }>;
}>;

/** Renderer-safe projection. Credential material and source references are omitted. */
export type AccordLockEnvironmentProfileSummary = Readonly<{
  id: string;
  name: string;
  runner: Readonly<{ mode: AccordLockEnvironmentRunnerMode }>;
  github: AccordLockGitHubRoute;
  aws: AccordLockAwsRoute;
  kubernetes: AccordLockKubernetesRoute;
  credentialsConfigured: Readonly<Record<AccordLockEnvironmentProvider, boolean>>;
  status: AccordLockEnvironmentProfileStatus;
  createdAt: number;
  updatedAt: number;
  verifiedAt: number | null;
  failedAt: number | null;
  failureCode: AccordLockEnvironmentVerificationFailureCode | null;
}>;

export type AccordLockEnvironmentRunnerProfile = Readonly<{
  schema_version: typeof ACCORDLOCK_ENVIRONMENT_PROFILE_SCHEMA_VERSION;
  profile_id: string;
  profile_digest: string;
  credential_revision: string;
  runner_mode: AccordLockEnvironmentRunnerMode;
  github: AccordLockGitHubRoute & Readonly<{ credential_source: string }>;
  aws: AccordLockAwsRoute & Readonly<{ credential_source: string }>;
  kubernetes: AccordLockKubernetesRoute & Readonly<{ expectedEndpoint: string }>;
}>;

/** Trusted main-process bundle. Never return this object over IPC. */
export type AccordLockEnvironmentProfileExecutionBundle = Readonly<{
  runnerProfile: AccordLockEnvironmentRunnerProfile;
  credentialMaterial: Readonly<Record<AccordLockEnvironmentProvider, string>>;
}>;

type JsonRecord = Record<string, unknown>;

const PROFILE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const AWS_ACCOUNT_ID = /^\d{12}$/u;
const AWS_REGION = /^[a-z]{2}(?:-[a-z0-9]+)+-\d$/u;
const ECR_REPOSITORY = /^[a-z0-9]+(?:[._/-][a-z0-9]+)*$/u;
const GITHUB_COMPONENT = /^[A-Za-z0-9_.-]+$/u;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function exactKeys(value: JsonRecord, keys: readonly string[]): boolean {
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
    value.length > 0 &&
    value.trim() === value &&
    Buffer.byteLength(value, 'utf8') <= maximumBytes &&
    !hasForbiddenTextCodePoint(value)
  );
}

function parseRelativeSelector(value: unknown, maximumBytes: number, label: string): string {
  if (
    !boundedText(value, maximumBytes) ||
    value.includes('\\') ||
    value.startsWith('/') ||
    value.endsWith('/') ||
    value.split('/').some((part) => part.length === 0 || part === '.' || part === '..')
  ) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

function parseGitHubRoute(value: unknown): AccordLockGitHubRoute {
  if (!isRecord(value) || !exactKeys(value, ['repository', 'workflow'])) {
    throw new Error('GitHub route is invalid');
  }
  if (!boundedText(value.repository, 200)) throw new Error('GitHub repository is invalid');
  const repositoryParts = value.repository.split('/');
  if (
    repositoryParts.length !== 2 ||
    repositoryParts.some(
      (part) =>
        !GITHUB_COMPONENT.test(part) || part === '.' || part === '..' || part.endsWith('.git')
    )
  ) {
    throw new Error('GitHub repository is invalid');
  }
  return Object.freeze({
    repository: value.repository,
    workflow: parseRelativeSelector(value.workflow, 256, 'GitHub workflow'),
  });
}

function parseAwsRoute(value: unknown): AccordLockAwsRoute {
  if (!isRecord(value) || !exactKeys(value, ['accountId', 'region', 'ecrRepository'])) {
    throw new Error('AWS route is invalid');
  }
  if (!boundedText(value.accountId, 12) || !AWS_ACCOUNT_ID.test(value.accountId)) {
    throw new Error('AWS account is invalid');
  }
  if (!boundedText(value.region, 32) || !AWS_REGION.test(value.region)) {
    throw new Error('AWS region is invalid');
  }
  if (
    !boundedText(value.ecrRepository, 256) ||
    !ECR_REPOSITORY.test(value.ecrRepository) ||
    value.ecrRepository.includes('//')
  ) {
    throw new Error('ECR repository is invalid');
  }
  return Object.freeze({
    accountId: value.accountId,
    region: value.region,
    ecrRepository: value.ecrRepository,
  });
}

function parseDnsLabel(value: unknown, label: string): string {
  if (!boundedText(value, 63) || !DNS_LABEL.test(value) || value !== value.toLowerCase()) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

function parseKubernetesRoute(value: unknown): AccordLockKubernetesRoute {
  if (
    !isRecord(value) ||
    !exactKeys(value, ['clusterName', 'namespace', 'deployment', 'container'])
  ) {
    throw new Error('Kubernetes route is invalid');
  }
  return Object.freeze({
    clusterName: parseDnsLabel(value.clusterName, 'Kubernetes cluster name'),
    namespace: parseDnsLabel(value.namespace, 'Kubernetes namespace'),
    deployment: parseDnsLabel(value.deployment, 'Kubernetes deployment'),
    container: parseDnsLabel(value.container, 'Kubernetes container'),
  });
}

function parseCredentialMaterialUpdate(value: unknown): AccordLockCredentialMaterialUpdate {
  if (!isRecord(value) || typeof value.mode !== 'string') {
    throw new Error('Credential material is invalid');
  }
  if (value.mode === 'KEEP' && exactKeys(value, ['mode'])) {
    return Object.freeze({ mode: 'KEEP' });
  }
  if (
    value.mode === 'SET' &&
    exactKeys(value, ['mode', 'value']) &&
    typeof value.value === 'string' &&
    value.value.length > 0 &&
    !value.value.includes('\0') &&
    Buffer.byteLength(value.value, 'utf8') <= 64 * 1_024
  ) {
    return Object.freeze({ mode: 'SET', value: value.value });
  }
  throw new Error('Credential material is invalid');
}

function parseCredential(value: unknown): AccordLockCredentialInput {
  if (
    !isRecord(value) ||
    !exactKeys(value, ['reference', 'material']) ||
    !boundedText(value.reference, 512)
  ) {
    throw new Error('Credential source is invalid');
  }
  return Object.freeze({
    reference: value.reference,
    material: parseCredentialMaterialUpdate(value.material),
  });
}

export function parseAccordLockEnvironmentProfileInput(
  value: unknown
): AccordLockEnvironmentProfileInput {
  if (
    !isRecord(value) ||
    !exactKeys(value, ['id', 'name', 'runner', 'github', 'aws', 'kubernetes', 'credentials']) ||
    (value.id !== null && (typeof value.id !== 'string' || !PROFILE_ID.test(value.id))) ||
    !boundedText(value.name, 80) ||
    !isRecord(value.runner) ||
    !exactKeys(value.runner, ['mode']) ||
    value.runner.mode !== 'LOCAL_BUNDLED' ||
    !isRecord(value.credentials) ||
    !exactKeys(value.credentials, ['github', 'aws'])
  ) {
    throw new Error('Environment profile is invalid');
  }

  return Object.freeze({
    id: value.id,
    name: value.name,
    runner: Object.freeze({ mode: 'LOCAL_BUNDLED' as const }),
    github: parseGitHubRoute(value.github),
    aws: parseAwsRoute(value.aws),
    kubernetes: parseKubernetesRoute(value.kubernetes),
    credentials: Object.freeze({
      github: parseCredential(value.credentials.github),
      aws: parseCredential(value.credentials.aws),
    }),
  });
}

export function isAccordLockEnvironmentProfileId(value: unknown): value is string {
  return typeof value === 'string' && PROFILE_ID.test(value);
}
