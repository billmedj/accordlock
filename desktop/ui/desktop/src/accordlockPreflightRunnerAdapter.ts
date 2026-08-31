import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';

import type {
  AccordLockEnvironmentProfileExecutionBundle,
  AccordLockEnvironmentRunnerProfile,
} from './accordlock/environmentProfiles';
import type { DeploymentPreflightRunnerRequest } from './accordlock/deploymentPreflight';
import type {
  AccordLockTrustedPreflightRunner,
  AccordLockTrustedPreflightRunnerResponse,
} from './accordlock/environmentProfilePreflightController';
import {
  AccordLockPreflightTrustStore,
  type AccordLockPreflightInstallationBootstrap,
  type AccordLockPreflightTrustMaterial,
} from './accordlockPreflightTrustStore';

const MAX_MARKER_BYTES = 64 * 1_024;
const MAX_PROFILE_BYTES = 2 * 1_024 * 1_024;
const MAX_REQUEST_BYTES = 32 * 1_024;
const MAX_CREDENTIAL_BYTES = 128 * 1_024;
const MAX_RECEIPT_BYTES = 2 * 1_024 * 1_024;
const MAX_STDERR_BYTES = 64 * 1_024;
const MAX_BOOTSTRAP_BYTES = 8 * 1_024;
const PREFLIGHT_PROTOCOL_VERSION = 1;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;
const AWS_ACCESS_KEY = /^[\x21-\x7e]{8,256}$/u;
const AWS_SECRET = /^[\x21-\x7e]{16,4096}$/u;
const TOKEN = /^[\x20-\x7e]{8,65536}$/u;
const CLUSTER_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;

type JsonRecord = Record<string, unknown>;

type RunnerBuildMarker = Readonly<{
  schema_version: 1;
  component: 'accordlock-preflight-runner';
  protocol_version: 1;
  binary_sha256: string;
  source_commit: string;
  dirty: boolean;
}>;

export type AccordLockPreflightProcessInvocation = Readonly<{
  executable: string;
  args: readonly string[];
  stdin?: Buffer;
  sensitiveStdout?: boolean;
  maximumStdoutBytes: number;
  maximumStderrBytes: number;
  signal: globalThis.AbortSignal;
}>;

export type AccordLockPreflightProcessResult = Readonly<{
  stdout: Buffer;
}>;

export type AccordLockPreflightProcessExecutor = (
  invocation: AccordLockPreflightProcessInvocation
) => Promise<AccordLockPreflightProcessResult>;

type AdapterOptions = {
  binaryDirectory: string;
  stateDirectory: string;
  trustStore: AccordLockPreflightTrustStore;
  isPackaged: boolean;
  allowDirtyDevelopment: boolean;
  expectedBinarySha256?: string;
  expectedProtocolVersion?: number;
  platform?: NodeJS.Platform;
  executeProcess?: AccordLockPreflightProcessExecutor;
};

type PreparedProfile = Readonly<{
  profilePath: string;
  statePath: string;
  profile: ReturnType<typeof buildPublicProfile>;
  trust: AccordLockPreflightTrustMaterial;
}>;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function exactKeys(value: JsonRecord, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function parseJson(bytes: Buffer, label: string): unknown {
  try {
    return JSON.parse(bytes.toString('utf8')) as unknown;
  } catch {
    throw new Error(`${label} is invalid`);
  }
}

function parseDigest(value: unknown, label: string): string {
  if (typeof value !== 'string' || !DIGEST.test(value)) throw new Error(`${label} is invalid`);
  return value;
}

function parseRunnerBuildMarker(value: unknown): RunnerBuildMarker {
  const keys = [
    'schema_version',
    'component',
    'protocol_version',
    'binary_sha256',
    'source_commit',
    'dirty',
  ];
  if (
    !isRecord(value) ||
    !exactKeys(value, keys) ||
    value.schema_version !== 1 ||
    value.component !== 'accordlock-preflight-runner' ||
    value.protocol_version !== PREFLIGHT_PROTOCOL_VERSION ||
    typeof value.binary_sha256 !== 'string' ||
    !DIGEST.test(value.binary_sha256) ||
    typeof value.source_commit !== 'string' ||
    !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(value.source_commit) ||
    typeof value.dirty !== 'boolean' ||
    (/^0+$/u.test(value.source_commit) && !value.dirty)
  ) {
    throw new Error('Deployment preflight runner build marker is invalid');
  }
  return value as RunnerBuildMarker;
}

async function sha256File(filePath: string): Promise<string> {
  const hash = createHash('sha256');
  for await (const chunk of fsSync.createReadStream(filePath)) hash.update(chunk as Buffer);
  return `sha256:${hash.digest('hex')}`;
}

async function assertRegularFile(filePath: string, maximumBytes: number): Promise<void> {
  const stat = await fs.lstat(filePath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size <= 0 || stat.size > maximumBytes) {
    throw new Error('Deployment preflight runner file is invalid');
  }
}

async function writeAtomic(filePath: string, value: Buffer): Promise<void> {
  const directory = path.dirname(filePath);
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  const temporaryPath = path.join(directory, `.preflight-profile.${randomUUID()}.tmp`);
  let handle: fs.FileHandle | null = null;
  try {
    handle = await fs.open(temporaryPath, 'wx', 0o600);
    await handle.writeFile(value);
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

function collectBounded(
  stream: NodeJS.ReadableStream,
  maximumBytes: number,
  onOverflow: () => void,
  sensitive = false
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let length = 0;
    const erase = () => {
      if (sensitive) chunks.forEach((chunk) => chunk.fill(0));
    };
    stream.on('data', (chunk: Buffer | string) => {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      length += bytes.length;
      if (length > maximumBytes) {
        erase();
        if (sensitive) bytes.fill(0);
        onOverflow();
        reject(new Error('Deployment preflight runner output exceeded its limit'));
        return;
      }
      chunks.push(bytes);
    });
    stream.once('error', (error) => {
      erase();
      reject(error);
    });
    stream.once('end', () => {
      try {
        resolve(Buffer.concat(chunks, length));
      } finally {
        erase();
      }
    });
  });
}

export const executeAccordLockPreflightProcess: AccordLockPreflightProcessExecutor = async (
  invocation
) => {
  if (!path.isAbsolute(invocation.executable) || invocation.signal.aborted) {
    throw new Error('Deployment preflight runner invocation is invalid');
  }
  const child = spawn(invocation.executable, [...invocation.args], {
    env: {},
    shell: false,
    stdio: ['pipe', 'pipe', 'pipe'],
    windowsHide: true,
  });
  const abort = () => child.kill();
  invocation.signal.addEventListener('abort', abort, { once: true });
  try {
    const overflow = () => child.kill();
    if (!child.stdout || !child.stderr || !child.stdin) {
      child.kill();
      throw new Error('Deployment preflight runner streams are unavailable');
    }
    const stdoutPromise = collectBounded(
      child.stdout,
      invocation.maximumStdoutBytes,
      overflow,
      invocation.sensitiveStdout === true
    );
    const stderrPromise = collectBounded(child.stderr, invocation.maximumStderrBytes, overflow);
    const stdinPromise = new Promise<void>((resolve, reject) => {
      child.stdin!.once('error', reject);
      child.stdin!.end(invocation.stdin, resolve);
    });
    const closePromise = new Promise<number | null>((resolve, reject) => {
      child.once('error', reject);
      child.once('close', resolve);
    });
    const [exitCode, stdout, stderr] = await Promise.all([
      closePromise,
      stdoutPromise,
      stderrPromise,
      stdinPromise,
    ]);
    if (invocation.signal.aborted) {
      if (invocation.sensitiveStdout) stdout.fill(0);
      stderr.fill(0);
      throw new Error('Deployment preflight runner was cancelled');
    }
    if (exitCode !== 0) {
      if (invocation.sensitiveStdout) stdout.fill(0);
      stderr.fill(0);
      throw new Error('Deployment preflight runner rejected the request');
    }
    stderr.fill(0);
    return { stdout };
  } catch (error) {
    child.kill();
    throw error;
  } finally {
    invocation.signal.removeEventListener('abort', abort);
  }
};

function parseAwsCredentials(value: string): Readonly<{
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string | null;
}> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    throw new Error('AWS credentials must be strict JSON');
  }
  if (!isRecord(parsed)) throw new Error('AWS credentials are invalid');
  const keys = Object.keys(parsed).sort();
  const withoutSession = ['access_key_id', 'secret_access_key'];
  const withSession = ['access_key_id', 'secret_access_key', 'session_token'];
  if (
    JSON.stringify(keys) !== JSON.stringify(withoutSession) &&
    JSON.stringify(keys) !== JSON.stringify(withSession)
  ) {
    throw new Error('AWS credentials are invalid');
  }
  if (
    typeof parsed.access_key_id !== 'string' ||
    !AWS_ACCESS_KEY.test(parsed.access_key_id) ||
    typeof parsed.secret_access_key !== 'string' ||
    !AWS_SECRET.test(parsed.secret_access_key) ||
    (parsed.session_token !== undefined &&
      (typeof parsed.session_token !== 'string' || !TOKEN.test(parsed.session_token)))
  ) {
    throw new Error('AWS credentials are invalid');
  }
  return {
    accessKeyId: parsed.access_key_id,
    secretAccessKey: parsed.secret_access_key,
    sessionToken: parsed.session_token ?? null,
  };
}

function credentialBundle(
  bundle: AccordLockEnvironmentProfileExecutionBundle,
  trust: AccordLockPreflightTrustMaterial
): JsonRecord {
  const aws = parseAwsCredentials(bundle.credentialMaterial.aws);
  if (!TOKEN.test(bundle.credentialMaterial.github)) {
    throw new Error('Environment credentials are invalid');
  }
  const credentials = {
    schema_version: 1,
    github_token: bundle.credentialMaterial.github,
    aws_access_key_id: aws.accessKeyId,
    aws_secret_access_key: aws.secretAccessKey,
    aws_session_token: aws.sessionToken,
    runner_master_seed: trust.runnerMasterSeed,
    receipt_signing_seed: trust.receiptSigningSeed,
  };
  const encoded = Buffer.from(JSON.stringify(credentials), 'utf8');
  if (encoded.length === 0 || encoded.length > MAX_CREDENTIAL_BYTES) {
    encoded.fill(0);
    throw new Error('Environment credentials are too large');
  }
  encoded.fill(0);
  return credentials;
}

function splitRepository(repository: string): readonly [string, string] {
  const parts = repository.split('/');
  if (parts.length !== 2 || parts.some((part) => part.length === 0)) {
    throw new Error('Saved GitHub repository is invalid');
  }
  return [parts[0], parts[1]];
}

function assertRustCompatibleProfile(profile: AccordLockEnvironmentRunnerProfile): void {
  if (!CLUSTER_LABEL.test(profile.kubernetes.clusterName)) {
    throw new Error('Kubernetes cluster name must be one DNS label');
  }
  if (!profile.kubernetes.expectedEndpoint.startsWith('https://')) {
    throw new Error('Kubernetes API endpoint is invalid');
  }
}

function buildPublicProfile(
  bundle: AccordLockEnvironmentProfileExecutionBundle,
  trust: AccordLockPreflightTrustMaterial,
  directories: Readonly<{ build: string; artifact: string }>
) {
  const source = bundle.runnerProfile;
  if (trust.ciAuthorities === null) {
    throw new Error('CI authorities are not enrolled');
  }
  assertRustCompatibleProfile(source);
  const [owner, repository] = splitRepository(source.github.repository);
  return {
    schema_version: 2,
    profile_id: source.profile_id,
    organization_id: owner,
    environment_id: source.profile_id,
    actor_id: `accordlock://desktop/environment/${source.profile_id}/credentials/${source.credential_revision}`,
    executor_audience: 'accordlock://runner/deployment-preflight/v1',
    github: {
      authority: 'api.github.com',
      api_base_path: '/',
      socket_address: null,
      ca_certificates_der: [],
      owner,
      repository,
      workflow_ref: source.github.workflow,
      minimum_approvals: 1,
      maximum_response_bytes: 128 * 1_024,
    },
    ecr: {
      registry_id: source.aws.accountId,
      region: source.aws.region,
      repository: source.aws.ecrRepository,
      socket_address: null,
      ca_certificates_der: [],
      maximum_response_bytes: 128 * 1_024,
    },
    eks_discovery: {
      socket_address: null,
      ca_certificates_der: [],
      maximum_response_bytes: 128 * 1_024,
    },
    kubernetes: {
      expected_endpoint: source.kubernetes.expectedEndpoint,
      socket_address: null,
      cluster_name: source.kubernetes.clusterName,
      namespace: source.kubernetes.namespace,
      deployment: source.kubernetes.deployment,
      container: source.kubernetes.container,
      maximum_response_bytes: 128 * 1_024,
    },
    build_trust: {
      key_id: trust.ciAuthorities.build.keyId,
      public_key: trust.ciAuthorities.build.publicKey,
      records_directory: directories.build,
    },
    artifact_trust: {
      key_id: trust.ciAuthorities.artifact.keyId,
      public_key: trust.ciAuthorities.artifact.publicKey,
      records_directory: directories.artifact,
    },
    receipt: {
      key_id: trust.receiptKeyId,
      public_key: trust.receiptPublicKey,
      public_key_hash: trust.receiptPublicKeyHash,
    },
    evidence_ttl_seconds: 120,
    maximum_source_age_seconds: 60,
    maximum_future_skew_seconds: 5,
    created_at: trust.createdAt,
    expires_at: trust.expiresAt,
  };
}

function buildRedactedVerificationProfile(
  profile: ReturnType<typeof buildPublicProfile>,
  environmentProfileHash: string
): JsonRecord {
  return {
    schema_version: profile.schema_version,
    profile_id: profile.profile_id,
    organization_id: profile.organization_id,
    environment_id: profile.environment_id,
    executor_audience: profile.executor_audience,
    github: {
      authority: profile.github.authority,
      api_base_path: profile.github.api_base_path,
      owner: profile.github.owner,
      repository: profile.github.repository,
      workflow_ref: profile.github.workflow_ref,
      minimum_approvals: profile.github.minimum_approvals,
      maximum_response_bytes: profile.github.maximum_response_bytes,
    },
    ecr: {
      registry_id: profile.ecr.registry_id,
      region: profile.ecr.region,
      repository: profile.ecr.repository,
      maximum_response_bytes: profile.ecr.maximum_response_bytes,
    },
    eks_discovery: {
      maximum_response_bytes: profile.eks_discovery.maximum_response_bytes,
    },
    kubernetes: {
      expected_endpoint: profile.kubernetes.expected_endpoint,
      cluster_name: profile.kubernetes.cluster_name,
      namespace: profile.kubernetes.namespace,
      deployment: profile.kubernetes.deployment,
      container: profile.kubernetes.container,
      maximum_response_bytes: profile.kubernetes.maximum_response_bytes,
    },
    build_trust: {
      key_id: profile.build_trust.key_id,
      public_key: profile.build_trust.public_key,
    },
    artifact_trust: {
      key_id: profile.artifact_trust.key_id,
      public_key: profile.artifact_trust.public_key,
    },
    receipt: {
      key_id: profile.receipt.key_id,
      public_key: profile.receipt.public_key,
      public_key_hash: profile.receipt.public_key_hash,
    },
    evidence_ttl_seconds: profile.evidence_ttl_seconds,
    maximum_source_age_seconds: profile.maximum_source_age_seconds,
    maximum_future_skew_seconds: profile.maximum_future_skew_seconds,
    created_at: profile.created_at,
    expires_at: profile.expires_at,
    environment_profile_hash: environmentProfileHash,
  };
}

function parseInstallationBootstrap(bytes: Buffer): AccordLockPreflightInstallationBootstrap {
  try {
    const value = parseJson(bytes, 'Preflight installation bootstrap');
    if (
      !isRecord(value) ||
      !exactKeys(value, ['schema_version', 'public', 'secrets']) ||
      value.schema_version !== 1 ||
      !isRecord(value.public) ||
      !exactKeys(value.public, [
        'schema_version',
        'receipt_key_id',
        'receipt_public_key',
        'receipt_public_key_hash',
      ]) ||
      value.public.schema_version !== 1 ||
      typeof value.public.receipt_key_id !== 'string' ||
      !KEY_ID.test(value.public.receipt_key_id) ||
      typeof value.public.receipt_public_key !== 'string' ||
      typeof value.public.receipt_public_key_hash !== 'string' ||
      !DIGEST.test(value.public.receipt_public_key_hash) ||
      !isRecord(value.secrets) ||
      !exactKeys(value.secrets, ['schema_version', 'runner_master_seed', 'receipt_signing_seed']) ||
      value.secrets.schema_version !== 1 ||
      typeof value.secrets.runner_master_seed !== 'string' ||
      typeof value.secrets.receipt_signing_seed !== 'string'
    ) {
      throw new Error('Preflight installation bootstrap is invalid');
    }
    return {
      runnerMasterSeed: value.secrets.runner_master_seed,
      receiptSigningSeed: value.secrets.receipt_signing_seed,
      receiptKeyId: value.public.receipt_key_id,
      receiptPublicKey: value.public.receipt_public_key,
      receiptPublicKeyHash: value.public.receipt_public_key_hash,
    };
  } finally {
    bytes.fill(0);
  }
}

function parseProfileHash(bytes: Buffer, expectedReceiptKeyHash: string): string {
  const value = parseJson(bytes, 'Deployment preflight profile hash');
  if (
    !isRecord(value) ||
    !exactKeys(value, ['valid', 'environment_profile_hash', 'receipt_public_key_hash']) ||
    value.valid !== true ||
    value.receipt_public_key_hash !== expectedReceiptKeyHash
  ) {
    throw new Error('Deployment preflight profile hash is invalid');
  }
  return parseDigest(value.environment_profile_hash, 'Deployment preflight profile hash');
}

function parseReceiptEnvelope(value: unknown): Readonly<{
  receiptHash: string;
  receiptPublicKeyHash: string;
}> {
  if (
    !isRecord(value) ||
    typeof value.receipt_hash !== 'string' ||
    !DIGEST.test(value.receipt_hash) ||
    typeof value.receipt_public_key_hash !== 'string' ||
    !DIGEST.test(value.receipt_public_key_hash)
  ) {
    throw new Error('Deployment preflight receipt is invalid');
  }
  return {
    receiptHash: value.receipt_hash,
    receiptPublicKeyHash: value.receipt_public_key_hash,
  };
}

function parseVerification(
  bytes: Buffer,
  expectedReceiptHash: string,
  expectedReceiptKeyHash: string
): void {
  const value = parseJson(bytes, 'Deployment preflight receipt verification');
  if (
    !isRecord(value) ||
    !exactKeys(value, ['valid', 'receipt_hash', 'receipt_public_key_hash']) ||
    value.valid !== true ||
    value.receipt_hash !== expectedReceiptHash ||
    value.receipt_public_key_hash !== expectedReceiptKeyHash
  ) {
    throw new Error('Deployment preflight receipt verification failed');
  }
}

export class AccordLockBundledPreflightRunner implements AccordLockTrustedPreflightRunner {
  private readonly binaryDirectory: string;
  private readonly stateDirectory: string;
  private readonly trustStore: AccordLockPreflightTrustStore;
  private readonly platform: NodeJS.Platform;
  private readonly executeProcess: AccordLockPreflightProcessExecutor;
  private readonly isPackaged: boolean;
  private readonly allowDirtyDevelopment: boolean;
  private readonly expectedBinarySha256?: string;
  private readonly expectedProtocolVersion?: number;

  constructor(options: AdapterOptions) {
    if (!path.isAbsolute(options.binaryDirectory) || !path.isAbsolute(options.stateDirectory)) {
      throw new Error('Deployment preflight runner paths must be absolute');
    }
    this.binaryDirectory = path.resolve(options.binaryDirectory);
    this.stateDirectory = path.resolve(options.stateDirectory);
    this.trustStore = options.trustStore;
    this.platform = options.platform ?? process.platform;
    this.executeProcess = options.executeProcess ?? executeAccordLockPreflightProcess;
    this.isPackaged = options.isPackaged;
    this.allowDirtyDevelopment = options.allowDirtyDevelopment;
    this.expectedBinarySha256 = options.expectedBinarySha256;
    this.expectedProtocolVersion = options.expectedProtocolVersion;
  }

  async initializeEnvironmentTrust(
    environmentId: string,
    signal: globalThis.AbortSignal
  ): Promise<void> {
    const binary = await this.verifyRunnerInstallation();
    await this.trustStore.getOrCreate(environmentId, async () => {
      const result = await this.execute(binary, {
        args: ['init-installation-stdio'],
        sensitiveStdout: true,
        maximumStdoutBytes: MAX_BOOTSTRAP_BYTES,
        signal,
      });
      return parseInstallationBootstrap(result.stdout);
    });
  }

  async discoverEks(
    request: Readonly<{
      accountId: string;
      region: string;
      clusterName: string;
      awsCredential: string;
    }>,
    signal: globalThis.AbortSignal
  ): Promise<Readonly<{ clusterArn: string; endpoint: string; clusterCaHash: string }>> {
    const binary = await this.verifyRunnerInstallation();
    const aws = parseAwsCredentials(request.awsCredential);
    const input = Buffer.from(
      JSON.stringify({
        schema_version: 1,
        request: {
          account_id: request.accountId,
          region: request.region,
          cluster_name: request.clusterName,
        },
        credentials: {
          aws_access_key_id: aws.accessKeyId,
          aws_secret_access_key: aws.secretAccessKey,
          aws_session_token: aws.sessionToken,
        },
      }),
      'utf8'
    );
    if (input.length > 16 * 1_024) {
      input.fill(0);
      throw new Error('EKS discovery request is too large');
    }
    let stdout: Buffer;
    try {
      ({ stdout } = await this.execute(binary, {
        args: ['discover-eks-stdio'],
        stdin: input,
        maximumStdoutBytes: 2 * 1_024,
        signal,
      }));
    } finally {
      input.fill(0);
    }
    const value = parseJson(stdout, 'EKS discovery result');
    if (
      !isRecord(value) ||
      !exactKeys(value, ['schema_version', 'cluster_arn', 'endpoint', 'cluster_ca_hash']) ||
      value.schema_version !== 1 ||
      value.cluster_arn !==
        `arn:aws:eks:${request.region}:${request.accountId}:cluster/${request.clusterName}` ||
      typeof value.endpoint !== 'string' ||
      typeof value.cluster_ca_hash !== 'string' ||
      !DIGEST.test(value.cluster_ca_hash)
    ) {
      throw new Error('EKS discovery result is invalid');
    }
    let endpoint: URL;
    try {
      endpoint = new URL(value.endpoint);
    } catch {
      throw new Error('EKS discovery endpoint is invalid');
    }
    if (
      endpoint.protocol !== 'https:' ||
      endpoint.username ||
      endpoint.password ||
      endpoint.port ||
      endpoint.pathname !== '/' ||
      endpoint.search ||
      endpoint.hash ||
      (value.endpoint !== endpoint.origin && value.endpoint !== `${endpoint.origin}/`)
    ) {
      throw new Error('EKS discovery endpoint is invalid');
    }
    return Object.freeze({
      clusterArn: value.cluster_arn,
      endpoint: value.endpoint,
      clusterCaHash: value.cluster_ca_hash,
    });
  }

  async profileHash(
    bundle: AccordLockEnvironmentProfileExecutionBundle,
    signal: globalThis.AbortSignal
  ): Promise<string> {
    const binary = await this.verifyRunnerInstallation();
    const prepared = await this.prepareProfile(binary, bundle, signal);
    return this.profileHashFor(binary, prepared, signal);
  }

  async run(
    request: DeploymentPreflightRunnerRequest,
    bundle: AccordLockEnvironmentProfileExecutionBundle,
    signal: globalThis.AbortSignal
  ): Promise<AccordLockTrustedPreflightRunnerResponse> {
    const binary = await this.verifyRunnerInstallation();
    const prepared = await this.prepareProfile(binary, bundle, signal);
    const authoritativeHash = await this.profileHashFor(binary, prepared, signal);
    if (
      request.environment_id !== bundle.runnerProfile.profile_id ||
      request.environment_profile_hash !== authoritativeHash
    ) {
      throw new Error('Deployment preflight request does not match the trusted profile');
    }
    const requestBytes = Buffer.from(JSON.stringify(request), 'utf8');
    if (requestBytes.length === 0 || requestBytes.length > MAX_REQUEST_BYTES) {
      throw new Error('Deployment preflight request is too large');
    }
    const credentials = credentialBundle(bundle, prepared.trust);
    const localEnvelope = Buffer.from(
      JSON.stringify({ schema_version: 2, command: request, credentials }),
      'utf8'
    );
    if (localEnvelope.length > MAX_CREDENTIAL_BYTES + MAX_REQUEST_BYTES + 4 * 1_024) {
      localEnvelope.fill(0);
      throw new Error('Deployment preflight local request is too large');
    }
    let receiptBytes: Buffer;
    try {
      const result = await this.execute(binary, {
        args: ['check-stdio', '--profile', prepared.profilePath, '--state', prepared.statePath],
        stdin: localEnvelope,
        maximumStdoutBytes: MAX_RECEIPT_BYTES,
        signal,
      });
      receiptBytes = result.stdout;
    } finally {
      localEnvelope.fill(0);
    }
    const receipt = parseJson(receiptBytes, 'Deployment preflight receipt');
    const envelope = parseReceiptEnvelope(receipt);
    if (envelope.receiptPublicKeyHash !== prepared.trust.receiptPublicKeyHash) {
      throw new Error('Deployment preflight receipt key does not match the trusted profile');
    }
    const verification = await this.execute(binary, {
      args: ['verify', '--profile', prepared.profilePath],
      stdin: receiptBytes,
      maximumStdoutBytes: MAX_BOOTSTRAP_BYTES,
      signal,
    });
    parseVerification(
      verification.stdout,
      envelope.receiptHash,
      prepared.trust.receiptPublicKeyHash
    );
    return {
      signatureVerified: true,
      receipt,
      receiptPublicKey: prepared.trust.receiptPublicKey,
      receiptKeyId: prepared.trust.receiptKeyId,
      verificationProfile: buildRedactedVerificationProfile(prepared.profile, authoritativeHash),
    };
  }

  private async prepareProfile(
    binary: string,
    bundle: AccordLockEnvironmentProfileExecutionBundle,
    signal: globalThis.AbortSignal
  ): Promise<PreparedProfile> {
    const trust = await this.trustStore.getOrCreate(bundle.runnerProfile.profile_id, async () => {
      const result = await this.execute(binary, {
        args: ['init-installation-stdio'],
        sensitiveStdout: true,
        maximumStdoutBytes: MAX_BOOTSTRAP_BYTES,
        signal,
      });
      return parseInstallationBootstrap(result.stdout);
    });
    const environmentRoot = path.join(
      this.stateDirectory,
      'environments',
      bundle.runnerProfile.profile_id
    );
    const statePath = path.join(environmentRoot, 'runner-state');
    const buildPath = path.join(environmentRoot, 'build-trust');
    const artifactPath = path.join(environmentRoot, 'artifact-trust');
    await Promise.all(
      [statePath, buildPath, artifactPath].map((directory) =>
        fs.mkdir(directory, { recursive: true, mode: 0o700 })
      )
    );
    const profile = buildPublicProfile(bundle, trust, { build: buildPath, artifact: artifactPath });
    const encoded = Buffer.from(JSON.stringify(profile), 'utf8');
    if (encoded.length === 0 || encoded.length > MAX_PROFILE_BYTES) {
      throw new Error('Deployment preflight profile is too large');
    }
    const profilePath = path.join(environmentRoot, 'profile.v1.json');
    await writeAtomic(profilePath, encoded);
    return { profilePath, statePath, profile, trust };
  }

  private async profileHashFor(
    binary: string,
    prepared: PreparedProfile,
    signal: globalThis.AbortSignal
  ): Promise<string> {
    const result = await this.execute(binary, {
      args: ['profile-hash', '--profile', prepared.profilePath],
      maximumStdoutBytes: MAX_BOOTSTRAP_BYTES,
      signal,
    });
    return parseProfileHash(result.stdout, prepared.trust.receiptPublicKeyHash);
  }

  private async execute(
    executable: string,
    options: Omit<AccordLockPreflightProcessInvocation, 'executable' | 'maximumStderrBytes'>
  ): Promise<AccordLockPreflightProcessResult> {
    return this.executeProcess({
      executable,
      maximumStderrBytes: MAX_STDERR_BYTES,
      ...options,
    });
  }

  private async verifyRunnerInstallation(): Promise<string> {
    const binaryName =
      this.platform === 'win32' ? 'accordlock-preflight-runner.exe' : 'accordlock-preflight-runner';
    const binaryPath = path.join(this.binaryDirectory, binaryName);
    const markerPath = path.join(this.binaryDirectory, 'accordlock-preflight-runner-build.json');
    await assertRegularFile(markerPath, MAX_MARKER_BYTES);
    await assertRegularFile(binaryPath, 1_024 * 1_024 * 1_024);
    const marker = parseRunnerBuildMarker(
      parseJson(await fs.readFile(markerPath), 'Deployment preflight runner build marker')
    );
    if (marker.dirty && !this.allowDirtyDevelopment) {
      throw new Error('Dirty deployment preflight runner builds are not allowed');
    }
    if (this.isPackaged) {
      if (
        !this.expectedBinarySha256 ||
        !DIGEST.test(this.expectedBinarySha256) ||
        this.expectedProtocolVersion !== PREFLIGHT_PROTOCOL_VERSION
      ) {
        throw new Error('Packaged deployment preflight runner identity is missing');
      }
      if (
        marker.binary_sha256 !== this.expectedBinarySha256 ||
        marker.protocol_version !== this.expectedProtocolVersion
      ) {
        throw new Error('Packaged deployment preflight runner identity does not match');
      }
    }
    const actualDigest = await sha256File(binaryPath);
    if (actualDigest !== marker.binary_sha256) {
      throw new Error('Deployment preflight runner binary integrity check failed');
    }
    return binaryPath;
  }
}
